use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs},
    sync::Arc,
    time::Duration,
};

use super::{AdapterError, AdapterResult};

const ALLOWED_SCHEMES: &[&str] = &["http", "https"];
const CLOUD_METADATA_HOSTS: &[&str] = &[
    "169.254.169.254",
    "metadata.google.internal",
    "metadata.azure.com",
    "metadata.azure.internal",
];
const BLOCKED_HOSTNAMES: &[&str] = &["localhost", "0.0.0.0", "[::1]", "[::]"];
const INTERNAL_DOMAIN_SUFFIXES: &[&str] = &[".internal", ".local", ".localhost"];
const SENSITIVE_HEADER_NAMES: &[&str] = &[
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "www-authenticate",
    "proxy-authorization",
];

const DEFAULT_MAX_REDIRECT_HOPS: u32 = 3;
const DEFAULT_MAX_RESPONSE_SIZE: usize = 10 * 1024 * 1024;
const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 30;

/// Cap for the wall-clock time a single hostname resolution may take before
/// the guard treats it as unresolved (fail closed).
const DNS_RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);

/// Resolves a hostname to its addresses. The guard rejects the request if
/// any resolved address violates the IP policy, so resolvers must return the
/// full answer set (A and AAAA records) to keep DNS-rebinding-style SSRF out.
pub type DnsResolverFn = dyn Fn(&str) -> Vec<IpAddr> + Send + Sync;

/// Default resolver: the system getaddrinfo (same answer the underlying HTTP
/// stack observes) run under a wall-clock cap on a detached thread, so a slow
/// DNS server cannot stall a plugin worker indefinitely.
fn system_dns_resolve(host: &str) -> Vec<IpAddr> {
    let host = host.to_string();
    let (tx, rx) = std::sync::mpsc::channel();
    let _ = std::thread::Builder::new()
        .name("akivili-dns-resolve".to_string())
        .spawn(move || {
            let _ = tx.send(
                (host.as_str(), 0)
                    .to_socket_addrs()
                    .map(|addrs| addrs.map(|sa| sa.ip()).collect::<Vec<_>>())
                    .unwrap_or_default(),
            );
        });
    rx.recv_timeout(DNS_RESOLVE_TIMEOUT).unwrap_or_default()
}

#[derive(Debug, Clone)]
pub struct NetworkGuardPolicy {
    pub allowed_hosts: Option<HashSet<String>>,
    pub allow_private_ips: bool,
    pub allow_loopback: bool,
    pub allow_link_local: bool,
    pub allow_cloud_metadata: bool,
    pub allow_multicast: bool,
    pub max_redirect_hops: u32,
    pub max_response_size: usize,
    pub connect_timeout_secs: u64,
}

impl Default for NetworkGuardPolicy {
    fn default() -> Self {
        Self {
            allowed_hosts: None,
            allow_private_ips: false,
            allow_loopback: false,
            allow_link_local: false,
            allow_cloud_metadata: false,
            allow_multicast: false,
            max_redirect_hops: DEFAULT_MAX_REDIRECT_HOPS,
            max_response_size: DEFAULT_MAX_RESPONSE_SIZE,
            connect_timeout_secs: DEFAULT_CONNECT_TIMEOUT_SECS,
        }
    }
}

impl NetworkGuardPolicy {
    pub fn permissive() -> Self {
        Self {
            allowed_hosts: None,
            allow_private_ips: true,
            allow_loopback: true,
            allow_link_local: true,
            allow_cloud_metadata: false,
            allow_multicast: false,
            max_redirect_hops: DEFAULT_MAX_REDIRECT_HOPS,
            max_response_size: DEFAULT_MAX_RESPONSE_SIZE,
            connect_timeout_secs: DEFAULT_CONNECT_TIMEOUT_SECS,
        }
    }

    pub fn with_allowed_hosts(mut self, hosts: HashSet<String>) -> Self {
        self.allowed_hosts = Some(hosts);
        self
    }

    pub fn merge(&self, overlay: &NetworkGuardPolicy) -> NetworkGuardPolicy {
        NetworkGuardPolicy {
            allowed_hosts: overlay
                .allowed_hosts
                .clone()
                .or_else(|| self.allowed_hosts.clone()),
            allow_private_ips: overlay.allow_private_ips && self.allow_private_ips,
            allow_loopback: overlay.allow_loopback && self.allow_loopback,
            allow_link_local: overlay.allow_link_local && self.allow_link_local,
            allow_cloud_metadata: overlay.allow_cloud_metadata && self.allow_cloud_metadata,
            allow_multicast: overlay.allow_multicast && self.allow_multicast,
            max_redirect_hops: overlay.max_redirect_hops.min(self.max_redirect_hops),
            max_response_size: overlay.max_response_size.min(self.max_response_size),
            connect_timeout_secs: overlay.connect_timeout_secs.min(self.connect_timeout_secs),
        }
    }
}

#[derive(Clone)]
pub struct NetworkGuard {
    policy: NetworkGuardPolicy,
    resolve: Arc<DnsResolverFn>,
}

impl std::fmt::Debug for NetworkGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetworkGuard")
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

impl NetworkGuard {
    pub fn new(policy: NetworkGuardPolicy) -> Self {
        Self {
            policy,
            resolve: Arc::new(system_dns_resolve),
        }
    }

    /// Overrides the hostname resolver (tests inject canned answers).
    pub fn with_resolver(mut self, resolve: Arc<DnsResolverFn>) -> Self {
        self.resolve = resolve;
        self
    }

    pub fn with_default_policy() -> Self {
        Self::new(NetworkGuardPolicy::default())
    }

    pub fn policy(&self) -> &NetworkGuardPolicy {
        &self.policy
    }

    pub fn check_url(&self, url: &str) -> AdapterResult<url::Url> {
        let parsed = url::Url::parse(url)
            .map_err(|e| AdapterError::Security(format!("invalid URL: {}", e)))?;

        if !ALLOWED_SCHEMES.contains(&parsed.scheme()) {
            return Err(AdapterError::Security(format!(
                "scheme '{}' not allowed (only http/https)",
                parsed.scheme()
            )));
        }

        let host = parsed
            .host_str()
            .ok_or_else(|| AdapterError::Security("URL has no host".to_string()))?;

        if let Some(ref allowed) = self.policy.allowed_hosts
            && !allowed.contains(host)
        {
            return Err(AdapterError::Security(format!(
                "host '{}' not in allowed list",
                host
            )));
        }

        for &suffix in INTERNAL_DOMAIN_SUFFIXES {
            if host.ends_with(suffix) {
                return Err(AdapterError::Security(format!(
                    "internal domain suffix '{}' blocked: {}",
                    suffix, host
                )));
            }
        }

        let host_lower = host.to_ascii_lowercase();
        for &blocked in BLOCKED_HOSTNAMES {
            if host_lower == blocked {
                return Err(AdapterError::Security(format!(
                    "blocked hostname: {}",
                    host
                )));
            }
        }

        for &blocked in CLOUD_METADATA_HOSTS {
            if host == blocked && !self.policy.allow_cloud_metadata {
                return Err(AdapterError::Security(format!(
                    "cloud metadata endpoint blocked: {}",
                    host
                )));
            }
        }

        let ip_str = host.trim_start_matches('[').trim_end_matches(']');
        match ip_str.parse::<IpAddr>() {
            Ok(ip) => self.check_ip(ip)?,
            Err(_) => {
                // Hostname: resolve and validate every answer. Without this,
                // attacker-controlled DNS (a name resolving to 127.0.0.1, a
                // private subnet, the cloud metadata endpoint, or numeric
                // encodings like 2130706433) would bypass the guard — the
                // string checks alone cannot see where the name actually
                // points. Any blocked answer rejects the whole request.
                let resolved = (self.resolve)(host);
                if resolved.is_empty() {
                    return Err(AdapterError::Security(format!(
                        "hostname '{}' could not be resolved",
                        host
                    )));
                }
                for ip in resolved {
                    self.check_ip(ip).map_err(|e| {
                        AdapterError::Security(format!(
                            "hostname '{}' resolves to blocked address: {}",
                            host, e
                        ))
                    })?;
                }
            }
        }

        Ok(parsed)
    }

    fn check_ip(&self, ip: IpAddr) -> AdapterResult<()> {
        match ip {
            IpAddr::V4(ipv4) => self.check_ipv4(ipv4),
            IpAddr::V6(ipv6) => self.check_ipv6(ipv6),
        }
    }

    fn check_ipv4(&self, ip: Ipv4Addr) -> AdapterResult<()> {
        if ip.is_loopback() && !self.policy.allow_loopback {
            return Err(AdapterError::Security(format!(
                "loopback address blocked: {}",
                ip
            )));
        }

        if ip.is_private() && !self.policy.allow_private_ips {
            return Err(AdapterError::Security(format!(
                "private IP blocked: {}",
                ip
            )));
        }

        if ip.is_link_local() && !self.policy.allow_link_local {
            return Err(AdapterError::Security(format!(
                "link-local address blocked: {}",
                ip
            )));
        }

        if is_ipv4_multicast(&ip) && !self.policy.allow_multicast {
            return Err(AdapterError::Security(format!(
                "multicast address blocked: {}",
                ip
            )));
        }

        if is_cloud_metadata_ipv4(&ip) && !self.policy.allow_cloud_metadata {
            return Err(AdapterError::Security(format!(
                "cloud metadata address blocked: {}",
                ip
            )));
        }

        if ip == Ipv4Addr::new(0, 0, 0, 0) && !self.policy.allow_loopback {
            return Err(AdapterError::Security(format!(
                "unspecified address blocked: {}",
                ip
            )));
        }

        Ok(())
    }

    fn check_ipv6(&self, ip: Ipv6Addr) -> AdapterResult<()> {
        if ip.is_loopback() && !self.policy.allow_loopback {
            return Err(AdapterError::Security(format!(
                "loopback address blocked: {}",
                ip
            )));
        }

        if is_ipv6_unique_local(&ip) && !self.policy.allow_private_ips {
            return Err(AdapterError::Security(format!(
                "unique-local address blocked: {}",
                ip
            )));
        }

        if ip.is_multicast() && !self.policy.allow_multicast {
            return Err(AdapterError::Security(format!(
                "multicast address blocked: {}",
                ip
            )));
        }

        if is_ipv6_link_local(&ip) && !self.policy.allow_link_local {
            return Err(AdapterError::Security(format!(
                "link-local address blocked: {}",
                ip
            )));
        }

        if is_ipv4_mapped_loopback(&ip) && !self.policy.allow_loopback {
            return Err(AdapterError::Security(format!(
                "IPv4-mapped loopback blocked: {}",
                ip
            )));
        }

        if ip.is_unspecified() {
            return Err(AdapterError::Security(format!(
                "unspecified address blocked: {}",
                ip
            )));
        }

        Ok(())
    }

    pub fn should_strip_header_on_redirect(
        from_host: &str,
        to_host: &str,
        header_name: &str,
    ) -> bool {
        if from_host == to_host {
            return false;
        }
        let lower = header_name.to_ascii_lowercase();
        SENSITIVE_HEADER_NAMES.contains(&lower.as_str())
    }

    pub fn is_response_size_allowed(&self, size: usize) -> bool {
        size <= self.policy.max_response_size
    }

    pub fn max_redirect_hops(&self) -> u32 {
        self.policy.max_redirect_hops
    }
}

fn is_ipv4_multicast(ip: &Ipv4Addr) -> bool {
    let octets = ip.octets();
    (224..=239).contains(&octets[0])
}

fn is_cloud_metadata_ipv4(ip: &Ipv4Addr) -> bool {
    *ip == Ipv4Addr::new(169, 254, 169, 254)
}

fn is_ipv6_unique_local(ip: &Ipv6Addr) -> bool {
    let segments = ip.segments();
    (0xfc00..=0xfdff).contains(&segments[0])
}

fn is_ipv6_link_local(ip: &Ipv6Addr) -> bool {
    let segments = ip.segments();
    segments[0] == 0xfe80
}

fn is_ipv4_mapped_loopback(ip: &Ipv6Addr) -> bool {
    let octets = ip.octets();
    octets[0..12] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff]
        && octets[12..14] == [127, 0]
        && octets[14] == 0
        && octets[15] == 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;

    fn default_guard() -> NetworkGuard {
        NetworkGuard::with_default_policy()
    }

    fn public_dns() -> Arc<DnsResolverFn> {
        Arc::new(|_: &str| vec!["93.184.216.34".parse().unwrap()])
    }

    fn guard_with_dns(addrs: Vec<IpAddr>) -> NetworkGuard {
        NetworkGuard::new(NetworkGuardPolicy::default())
            .with_resolver(Arc::new(move |_: &str| addrs.clone()))
    }

    #[test]
    fn allows_https_url() -> Result<()> {
        let guard = default_guard().with_resolver(public_dns());
        let url = guard.check_url("https://example.com/path")?;
        assert_eq!(url.host_str(), Some("example.com"));
        Ok(())
    }

    #[test]
    fn allows_http_url() -> Result<()> {
        let guard = default_guard().with_resolver(public_dns());
        assert!(guard.check_url("http://example.com/").is_ok());
        Ok(())
    }

    #[test]
    fn rejects_ftp_scheme() -> Result<()> {
        let guard = default_guard();
        let result = guard.check_url("ftp://example.com/");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("scheme"));
        Ok(())
    }

    #[test]
    fn rejects_javascript_scheme() -> Result<()> {
        let guard = default_guard();
        assert!(guard.check_url("javascript:alert(1)").is_err());
        Ok(())
    }

    #[test]
    fn rejects_file_scheme() -> Result<()> {
        let guard = default_guard();
        assert!(guard.check_url("file:///etc/passwd").is_err());
        Ok(())
    }

    #[test]
    fn rejects_private_ipv4_10() -> Result<()> {
        let guard = default_guard();
        assert!(guard.check_url("http://10.0.0.1/").is_err());
        Ok(())
    }

    #[test]
    fn rejects_private_ipv4_172() -> Result<()> {
        let guard = default_guard();
        assert!(guard.check_url("http://172.16.0.1/").is_err());
        Ok(())
    }

    #[test]
    fn rejects_private_ipv4_192() -> Result<()> {
        let guard = default_guard();
        assert!(guard.check_url("http://192.168.1.1/").is_err());
        Ok(())
    }

    #[test]
    fn rejects_loopback_127() -> Result<()> {
        let guard = default_guard();
        assert!(guard.check_url("http://127.0.0.1/").is_err());
        Ok(())
    }

    #[test]
    fn rejects_localhost() -> Result<()> {
        let guard = default_guard();
        assert!(guard.check_url("http://localhost/").is_err());
        Ok(())
    }

    #[test]
    fn rejects_link_local() -> Result<()> {
        let guard = default_guard();
        assert!(guard.check_url("http://169.254.1.1/").is_err());
        Ok(())
    }

    #[test]
    fn rejects_cloud_metadata() -> Result<()> {
        let guard = default_guard();
        assert!(guard.check_url("http://169.254.169.254/").is_err());
        Ok(())
    }

    #[test]
    fn rejects_cloud_metadata_hostname() -> Result<()> {
        let guard = default_guard();
        assert!(guard.check_url("http://metadata.google.internal/").is_err());
        Ok(())
    }

    #[test]
    fn rejects_ipv6_loopback() -> Result<()> {
        let guard = default_guard();
        assert!(guard.check_url("http://[::1]/").is_err());
        Ok(())
    }

    #[test]
    fn rejects_ipv4_mapped_loopback() -> Result<()> {
        let guard = default_guard();
        assert!(guard.check_url("http://[::ffff:127.0.0.1]/").is_err());
        Ok(())
    }

    #[test]
    fn rejects_ipv6_unique_local() -> Result<()> {
        let guard = default_guard();
        assert!(guard.check_url("http://[fd00::1]/").is_err());
        Ok(())
    }

    #[test]
    fn rejects_multicast_ipv4() -> Result<()> {
        let guard = default_guard();
        assert!(guard.check_url("http://224.0.0.1/").is_err());
        Ok(())
    }

    #[test]
    fn rejects_multicast_ipv6() -> Result<()> {
        let guard = default_guard();
        assert!(guard.check_url("http://[ff00::1]/").is_err());
        Ok(())
    }

    #[test]
    fn rejects_zero_ip() -> Result<()> {
        let guard = default_guard();
        assert!(guard.check_url("http://0.0.0.0/").is_err());
        Ok(())
    }

    #[test]
    fn rejects_internal_domain_suffix() -> Result<()> {
        let guard = default_guard();
        assert!(guard.check_url("http://service.internal/").is_err());
        assert!(guard.check_url("http://service.local/").is_err());
        assert!(guard.check_url("http://service.localhost/").is_err());
        Ok(())
    }

    #[test]
    fn allows_public_ip() -> Result<()> {
        let guard = default_guard();
        assert!(guard.check_url("http://93.184.216.34/").is_ok());
        Ok(())
    }

    #[test]
    fn allowed_hosts_whitelist() -> Result<()> {
        let guard = NetworkGuard::new(
            NetworkGuardPolicy::default()
                .with_allowed_hosts(HashSet::from(["api.example.com".to_string()])),
        )
        .with_resolver(public_dns());
        assert!(guard.check_url("https://api.example.com/v1").is_ok());
        assert!(guard.check_url("https://other.example.com/v1").is_err());
        Ok(())
    }

    #[test]
    fn permissive_allows_private_and_loopback() -> Result<()> {
        let guard = NetworkGuard::new(NetworkGuardPolicy::permissive());
        assert!(guard.check_url("http://127.0.0.1/").is_ok());
        assert!(guard.check_url("http://10.0.0.1/").is_ok());
        assert!(guard.check_url("http://169.254.1.1/").is_ok());
        Ok(())
    }

    #[test]
    fn permissive_still_blocks_cloud_metadata() -> Result<()> {
        let guard = NetworkGuard::new(NetworkGuardPolicy::permissive());
        assert!(guard.check_url("http://169.254.169.254/").is_err());
        Ok(())
    }

    #[test]
    fn policy_merge_restrictive() -> Result<()> {
        let global = NetworkGuardPolicy::permissive();
        let agent = NetworkGuardPolicy::default();
        let merged = global.merge(&agent);
        assert!(!merged.allow_private_ips);
        assert!(!merged.allow_loopback);
        Ok(())
    }

    #[test]
    fn policy_merge_takes_stricter_redirect() -> Result<()> {
        let global = NetworkGuardPolicy {
            max_redirect_hops: 5,
            ..Default::default()
        };
        let agent = NetworkGuardPolicy {
            max_redirect_hops: 2,
            ..Default::default()
        };
        let merged = global.merge(&agent);
        assert_eq!(merged.max_redirect_hops, 2);
        Ok(())
    }

    #[test]
    fn policy_merge_takes_smaller_response_size() -> Result<()> {
        let global = NetworkGuardPolicy {
            max_response_size: 20 * 1024 * 1024,
            ..Default::default()
        };
        let agent = NetworkGuardPolicy {
            max_response_size: 1024,
            ..Default::default()
        };
        let merged = global.merge(&agent);
        assert_eq!(merged.max_response_size, 1024);
        Ok(())
    }

    #[test]
    fn strip_sensitive_header_on_cross_host_redirect() -> Result<()> {
        assert!(NetworkGuard::should_strip_header_on_redirect(
            "api.example.com",
            "other.com",
            "Authorization"
        ));
        assert!(NetworkGuard::should_strip_header_on_redirect(
            "api.example.com",
            "other.com",
            "Cookie"
        ));
        assert!(!NetworkGuard::should_strip_header_on_redirect(
            "api.example.com",
            "api.example.com",
            "Authorization"
        ));
        assert!(!NetworkGuard::should_strip_header_on_redirect(
            "api.example.com",
            "other.com",
            "Content-Type"
        ));
        Ok(())
    }

    #[test]
    fn response_size_limit() -> Result<()> {
        let guard = NetworkGuard::new(NetworkGuardPolicy {
            max_response_size: 100,
            ..Default::default()
        });
        assert!(guard.is_response_size_allowed(50));
        assert!(guard.is_response_size_allowed(100));
        assert!(!guard.is_response_size_allowed(101));
        Ok(())
    }

    #[test]
    fn rejects_hostname_resolving_to_loopback() -> Result<()> {
        let guard = guard_with_dns(vec!["127.0.0.1".parse().unwrap()]);
        let err = guard.check_url("http://rebind.example.com/").unwrap_err();
        assert!(err.to_string().contains("blocked"), "got: {}", err);
        Ok(())
    }

    #[test]
    fn rejects_hostname_resolving_to_private_ip() -> Result<()> {
        let guard = guard_with_dns(vec!["10.0.0.1".parse().unwrap()]);
        let err = guard
            .check_url("http://internal-rebind.example.com/")
            .unwrap_err();
        assert!(err.to_string().contains("blocked"), "got: {}", err);
        Ok(())
    }

    #[test]
    fn rejects_hostname_resolving_to_cloud_metadata() -> Result<()> {
        let guard = guard_with_dns(vec!["169.254.169.254".parse().unwrap()]);
        assert!(guard.check_url("http://rebind.example.com/").is_err());
        Ok(())
    }

    #[test]
    fn rejects_hostname_with_any_blocked_answer() -> Result<()> {
        let guard = guard_with_dns(vec![
            "93.184.216.34".parse().unwrap(),
            "192.168.1.1".parse().unwrap(),
        ]);
        let err = guard.check_url("http://mixed.example.com/").unwrap_err();
        assert!(err.to_string().contains("blocked"), "got: {}", err);
        Ok(())
    }

    #[test]
    fn allows_hostname_with_only_public_answers() -> Result<()> {
        let guard = guard_with_dns(vec![
            "93.184.216.34".parse().unwrap(),
            "8.8.8.8".parse().unwrap(),
        ]);
        assert!(guard.check_url("http://public.example.com/").is_ok());
        Ok(())
    }

    #[test]
    fn rejects_unresolvable_hostname() -> Result<()> {
        let guard = guard_with_dns(vec![]);
        let err = guard.check_url("http://nowhere.example.com/").unwrap_err();
        assert!(
            err.to_string().contains("could not be resolved"),
            "got: {}",
            err
        );
        Ok(())
    }

    #[test]
    fn rejects_numeric_encoded_loopback_via_dns() -> Result<()> {
        let guard = guard_with_dns(vec!["127.0.0.1".parse().unwrap()]);
        let err = guard
            .check_url("http://2130706433/")
            .expect_err("decimal-encoded loopback must be rejected");
        assert!(err.to_string().contains("blocked"), "got: {}", err);
        Ok(())
    }

    #[test]
    fn permissive_policy_accepts_hostname_resolving_to_private() -> Result<()> {
        let guard = NetworkGuard::new(NetworkGuardPolicy::permissive())
            .with_resolver(Arc::new(|_: &str| vec!["10.0.0.1".parse().unwrap()]));
        assert!(guard.check_url("http://internal.example.com/").is_ok());
        Ok(())
    }
}
