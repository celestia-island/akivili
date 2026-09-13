use anyhow::{Result, anyhow, bail};
use parking_lot::Mutex;
use serde_json::Value;
use std::{
    collections::HashMap,
    sync::{Arc, OnceLock},
};
use tokio::sync::RwLock;

use tracing::info;

use crate::guard::NetworkGuard;
use plana_domain_skills::{
    llm_subcall::LlmSubcallService,
    trigger_types::{TriggerPattern, TriggerSubscription},
};
use plana_infra_utils::pubsub::PubSubBus;
use plana_state_sync::ModelTier;

/// Installs the ring-based rustls crypto provider once per process.
///
/// The `rustls-no-provider` reqwest feature requires an explicit provider;
/// `install_default` fails only when the host application already installed
/// one, in which case the host's provider wins.
pub(crate) fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Maximum MCP tools a single plugin may register. Prevents one plugin from
/// dominating the shared tool surface (C8 amplification cap).
pub const MAX_TOOLS_PER_PLUGIN: usize = 32;

/// Maximum MCP tools across all plugins in the registry.
pub const MAX_MCP_TOOLS_GLOBAL: usize = 256;

/// Builds the plugin HTTP client with the egress guard applied: connection
/// timeout and a redirect policy capped at the guard's hop limit, re-checking
/// every hop URL against the guard allow-list (mirrors the legacy adapter's
/// `ReqwestHttpClient`). The client's DNS resolution runs through the guard
/// itself, so connect-time addresses are validated (no rebinding window).
fn build_http_client(guard: &NetworkGuard) -> reqwest::Client {
    let timeout = std::time::Duration::from_secs(guard.policy().connect_timeout_secs);
    let max_hops = guard.max_redirect_hops() as usize;
    let guard_clone = guard.clone();
    reqwest::Client::builder()
        .timeout(timeout)
        .dns_resolver(guard.clone())
        .redirect(reqwest::redirect::Policy::custom(move |attempt| {
            if attempt.previous().len() >= max_hops
                || guard_clone.check_url(attempt.url().as_str()).is_err()
            {
                attempt.stop()
            } else {
                attempt.follow()
            }
        }))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RegisteredMcpTool {
    pub tool_name: String,
    pub description: String,
    pub schema: String,
}

#[derive(serde::Serialize)]
struct HttpResp {
    status: u16,
    body: String,
}

struct PluginMcpRegistry {
    tools: Mutex<HashMap<String, Vec<RegisteredMcpTool>>>,
}

/// Enforces the MCP tool namespace policy: a plugin may only register tools
/// under its own `<plugin_name>.` prefix, and the local part must be a plain
/// identifier. This turns the shared tool surface into a per-plugin whitelist
/// (no cross-plugin impersonation, no global name squatting) and keeps the
/// registered name aligned with the `<agent>.<tool>` convention used by the
/// downstream namespace/`allowed_filter` machinery.
fn validate_tool_namespace(plugin_name: &str, tool_name: &str) -> Result<()> {
    if plugin_name.is_empty() {
        bail!("plugin name must not be empty");
    }

    if tool_name.is_empty() {
        bail!("tool name must not be empty");
    }

    if tool_name.contains(' ') || tool_name.contains('\n') || tool_name.contains('\t') {
        bail!("tool name '{}' contains whitespace", tool_name);
    }

    let prefix = format!("{}.", plugin_name);
    let local = tool_name.strip_prefix(&prefix).ok_or_else(|| {
        anyhow!(
            "tool name '{}' must be namespaced with the plugin prefix '{}…'",
            tool_name,
            prefix
        )
    })?;

    if local.is_empty() {
        bail!("tool name '{}' has an empty local part", tool_name);
    }

    if !local
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        bail!(
            "tool name '{}' local part contains invalid characters (only [A-Za-z0-9_-])",
            tool_name
        );
    }

    Ok(())
}

impl PluginMcpRegistry {
    fn new() -> Self {
        Self {
            tools: Mutex::new(HashMap::new()),
        }
    }
    fn register(&self, plugin_name: &str, tool: RegisteredMcpTool) {
        let mut guard = self.tools.lock();
        let tools = guard.entry(plugin_name.to_string()).or_default();
        if tools.iter().any(|t| t.tool_name == tool.tool_name) {
            return;
        }
        tools.push(tool);
    }

    fn all_tools(&self) -> Vec<(String, RegisteredMcpTool)> {
        let guard = self.tools.lock();
        let mut out = Vec::new();
        for (plugin, tools) in guard.iter() {
            for t in tools {
                out.push((plugin.clone(), t.clone()));
            }
        }
        out
    }

    fn tools_for_plugin(&self, plugin_name: &str) -> Vec<RegisteredMcpTool> {
        self.tools
            .lock()
            .get(plugin_name)
            .cloned()
            .unwrap_or_default()
    }
}

pub trait TriggerDispatcherHolder: Send + Sync {
    fn register_subscription(&self, sub: TriggerSubscription);
}

/// Host-side capabilities exposed to plugin scripts through the
/// `dispatch(...)` tool.
///
/// Implementations are invoked from plugin evaluation threads —
/// including the bare `TsPluginPool` workers, which run without any
/// ambient tokio runtime. Blocking implementations must bridge async
/// work through `HostFunctions::host_block_on` (or stay fully
/// synchronous) and must never call `Handle::current()` or
/// `block_in_place` directly.
pub trait HostApiProvider: Send + Sync + 'static {
    fn http_request(
        &self,
        method: String,
        url: String,
        headers: String,
        body: String,
    ) -> Result<String>;
    fn forward_event(&self, event_json: String) -> Result<()>;
    fn query_ai(&self, message: String, context: Option<String>) -> Result<String>;
    fn config_get(&self, key: String) -> Option<String>;
    fn register_mcp_tool(
        &self,
        plugin_name: &str,
        tool_name: String,
        description: String,
        schema: String,
    ) -> Result<()>;
    fn subscribe_trigger(&self, plugin_name: &str, topic_pattern: &str) -> Result<()>;
}

pub struct HostFunctions {
    kv_store: Arc<RwLock<HashMap<String, String>>>,
    config: Arc<RwLock<HashMap<String, String>>>,
    mcp_registry: Arc<PluginMcpRegistry>,
    http_client: reqwest::Client,
    network_guard: Arc<NetworkGuard>,
    pubsub_bus: Option<Arc<dyn PubSubBus>>,
    llm_service: Option<Arc<dyn LlmSubcallService>>,
    trigger_dispatcher: Option<Arc<dyn TriggerDispatcherHolder>>,
    /// Environment variables injected into every plugin sandbox. Holds the
    /// final merged set (registry-fed values layered under explicit caller
    /// configuration — see [`crate::sandbox_env`]). A `parking_lot` lock
    /// rather than tokio's because plugin contexts are created on plain
    /// worker threads (outside any async runtime).
    sandbox_env: Arc<parking_lot::RwLock<HashMap<String, String>>>,
    /// Dedicated async driver for blocking host-API calls made from bare
    /// plugin worker threads. Plugin contexts evaluate on plain
    /// `std::thread::Builder` pool workers (see
    /// [`crate::plugin_router::TsPluginPool`]) and on `spawn_blocking`
    /// loader threads. An ambient runtime, when one exists, is preferred
    /// (see [`HostFunctions::host_block_on`]); this lazily built
    /// current-thread runtime is the fallback for threads with no
    /// ambient runtime at all, where the former
    /// [`tokio::task::block_in_place`] + [`tokio::runtime::Handle::current`]
    /// pair panicked.
    host_rt: OnceLock<tokio::runtime::Runtime>,
}

impl Default for HostFunctions {
    fn default() -> Self {
        Self::new()
    }
}

impl HostFunctions {
    pub fn new() -> Self {
        install_crypto_provider();
        let guard = NetworkGuard::with_default_policy();
        let http_client = build_http_client(&guard);
        Self {
            kv_store: Arc::new(RwLock::new(HashMap::new())),
            config: Arc::new(RwLock::new(HashMap::new())),
            mcp_registry: Arc::new(PluginMcpRegistry::new()),
            http_client,
            network_guard: Arc::new(guard),
            pubsub_bus: None,
            llm_service: None,
            trigger_dispatcher: None,
            sandbox_env: Arc::new(parking_lot::RwLock::new(HashMap::new())),
            host_rt: OnceLock::new(),
        }
    }

    pub fn with_config(mut self, config: HashMap<String, String>) -> Self {
        self.config = Arc::new(RwLock::new(config));
        self
    }

    pub fn with_network_guard(mut self, guard: NetworkGuard) -> Self {
        // Rebuild the client so both the pre-request check and the redirect
        // policy use the new guard (the redirect closure captures it).
        self.http_client = build_http_client(&guard);
        self.network_guard = Arc::new(guard);
        self
    }

    pub fn with_pubsub_bus(mut self, bus: Arc<dyn PubSubBus>) -> Self {
        self.pubsub_bus = Some(bus);
        self
    }

    pub fn with_llm_service(mut self, service: Arc<dyn LlmSubcallService>) -> Self {
        self.llm_service = Some(service);
        self
    }

    pub fn with_trigger_dispatcher(mut self, dispatcher: Arc<dyn TriggerDispatcherHolder>) -> Self {
        self.trigger_dispatcher = Some(dispatcher);
        self
    }

    /// Sets the sandbox environment injected into every plugin sandbox
    /// (the `__sandbox_env` global and the `env-get` dispatch tool).
    ///
    /// This is the **explicit caller configuration** layer: host processes
    /// should pass the registry-fed set merged underneath their explicit
    /// values here ([`crate::sandbox_env::SandboxEnvFeed::merged_with`] —
    /// explicit configuration always wins over registry resources).
    pub fn with_sandbox_env(mut self, env: HashMap<String, String>) -> Self {
        self.sandbox_env = Arc::new(parking_lot::RwLock::new(env));
        self
    }

    /// A snapshot of the sandbox environment, taken when a plugin context
    /// is created (the `__sandbox_env` global's content).
    pub fn sandbox_env(&self) -> HashMap<String, String> {
        self.sandbox_env.read().clone()
    }

    /// Drives `fut` to completion for a blocking host-API call.
    ///
    /// Two regimes, so no calling context regresses versus the former
    /// `tokio::task::block_in_place` + `Handle::current().block_on`
    /// pair:
    ///
    /// - With an ambient runtime (async workers of a multi-thread
    ///   runtime, `spawn_blocking` threads) the legacy path is kept:
    ///   `block_in_place` legally parks such callers and the future
    ///   runs on the caller's own runtime.
    /// - On bare plugin worker threads — the `TsPluginPool` case, which
    ///   has no ambient runtime and where the legacy pair panicked — a
    ///   dedicated current-thread runtime is built on first use and
    ///   drives the future from the calling thread. `Runtime::block_on`
    ///   is legal on any thread that is not itself inside an async
    ///   execution context, and several bare threads sharing this
    ///   `HostFunctions` may enter it concurrently — tokio documents
    ///   concurrent `block_on` on the current-thread scheduler (the
    ///   first caller owns the IO/timer drivers, later ones hook into
    ///   them).
    ///
    /// Boundaries to respect when extending this:
    ///
    /// - Never call this from within a future it drives: the nested
    ///   call would see the fallback runtime via `try_current`, take
    ///   the `block_in_place` branch, and panic — that helper requires
    ///   a multi-thread runtime.
    /// - The fallback spawns no resident threads (the current-thread
    ///   flavor has no workers); only DNS resolution, which the guard
    ///   runs through `spawn_blocking`, creates transient pool threads
    ///   that tokio retires after their keep-alive.
    /// - The fallback runtime is dropped with the last `HostFunctions`
    ///   `Arc`, and tokio panics when a runtime is dropped inside an
    ///   async context — release the final `Arc` from synchronous code
    ///   (pool workers and process teardown do exactly that).
    pub(crate) fn host_block_on<F: std::future::Future>(&self, fut: F) -> F::Output {
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            return tokio::task::block_in_place(|| handle.block_on(fut));
        }
        let rt = self.host_rt.get_or_init(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("failed to build the plugin host runtime")
        });
        rt.block_on(fut)
    }

    /// Reads one sandbox environment variable — the `env-get` dispatch
    /// target, mirroring [`HostFunctions::config_get`]'s `config-get`.
    pub fn env_get(&self, key: &str) -> Option<String> {
        self.sandbox_env.read().get(key).cloned()
    }

    pub async fn kv_get(&self, key: &str) -> Option<String> {
        self.kv_store.read().await.get(key).cloned()
    }

    pub async fn kv_set(&self, key: &str, value: &str) {
        self.kv_store
            .write()
            .await
            .insert(key.to_string(), value.to_string());
    }

    pub fn all_mcp_tools(&self) -> Vec<(String, RegisteredMcpTool)> {
        self.mcp_registry.all_tools()
    }

    pub fn mcp_tools_for_plugin(&self, plugin_name: &str) -> Vec<RegisteredMcpTool> {
        self.mcp_registry.tools_for_plugin(plugin_name)
    }
}

impl HostApiProvider for HostFunctions {
    fn http_request(
        &self,
        method: String,
        url: String,
        headers: String,
        body: String,
    ) -> Result<String> {
        if let Err(e) = self.network_guard.check_url(&url) {
            bail!("URL blocked by NetworkGuard: {}", e);
        }

        let client = self.http_client.clone();
        self.host_block_on(async {
            let parsed_headers: HashMap<String, Value> =
                serde_json::from_str(&headers).unwrap_or_default();

            let mut req = match method.to_uppercase().as_str() {
                "GET" => client.get(&url),
                "POST" => client.post(&url),
                "PUT" => client.put(&url),
                "PATCH" => client.patch(&url),
                "DELETE" => client.delete(&url),
                other => client.request(
                    reqwest::Method::from_bytes(other.as_bytes()).unwrap_or(reqwest::Method::GET),
                    &url,
                ),
            };

            for (k, v) in parsed_headers {
                if let Some(s) = v.as_str() {
                    req = req.header(&k, s);
                }
            }

            if !body.is_empty() && !["GET", "HEAD"].contains(&method.to_uppercase().as_str()) {
                req = req.body(body);
            }

            let resp = req
                .send()
                .await
                .map_err(|e| anyhow!("HTTP request failed: {}", e))?;
            let status = resp.status().as_u16();
            let resp_body = resp
                .text()
                .await
                .map_err(|e| anyhow!("Failed to read response body: {}", e))?;

            Ok(serde_json::to_string(&HttpResp {
                status,
                body: resp_body,
            })
            .unwrap_or_default())
        })
    }

    fn forward_event(&self, event_json: String) -> Result<()> {
        if let Some(ref bus) = self.pubsub_bus {
            let parsed: serde_json::Value = serde_json::from_str(&event_json).unwrap_or_default();
            let topic = parsed
                .get("topic")
                .and_then(|v| v.as_str())
                .unwrap_or("plugin.event")
                .to_string();
            let payload = parsed.get("payload").cloned().unwrap_or(parsed.clone());

            let bus = bus.clone();
            self.host_block_on(async {
                bus.publish(&topic, payload).await;
            });
            info!(event = "plugin_forward_event", topic = %topic, "event forwarded to PubSubBus");
        } else {
            info!(event = "plugin_forward_event", "{}", event_json);
        }
        Ok(())
    }

    fn query_ai(&self, message: String, context: Option<String>) -> Result<String> {
        if let Some(ref llm) = self.llm_service {
            let llm = llm.clone();
            let result = self.host_block_on(async {
                llm.llm_chat(ModelTier::Basic, &message, context.as_deref(), None, None)
                    .await
            });
            if result.success {
                Ok(result.content)
            } else {
                bail!("AI query failed: {}", result.content)
            }
        } else {
            info!(
                event = "plugin_query_ai",
                has_context = context.is_some(),
                "query_ai: {:.100}",
                message
            );
            bail!("LLM service not configured")
        }
    }

    fn config_get(&self, key: String) -> Option<String> {
        let config = self.config.clone();
        self.host_block_on(async { config.read().await.get(&key).cloned() })
    }

    fn register_mcp_tool(
        &self,
        plugin_name: &str,
        tool_name: String,
        description: String,
        schema: String,
    ) -> Result<()> {
        validate_tool_namespace(plugin_name, &tool_name)?;

        {
            let all = self.mcp_registry.all_tools();
            if let Some((existing_plugin, _)) = all.iter().find(|(_, t)| t.tool_name == tool_name) {
                bail!(
                    "tool name '{}' already registered by plugin '{}'",
                    tool_name,
                    existing_plugin
                );
            }
        }

        if self.mcp_registry.tools_for_plugin(plugin_name).len() >= MAX_TOOLS_PER_PLUGIN {
            bail!(
                "plugin '{}' exceeds the per-plugin MCP tool cap of {}",
                plugin_name,
                MAX_TOOLS_PER_PLUGIN
            );
        }

        if self.mcp_registry.all_tools().len() >= MAX_MCP_TOOLS_GLOBAL {
            bail!(
                "MCP tool registry reached the global cap of {}",
                MAX_MCP_TOOLS_GLOBAL
            );
        }

        if !schema.is_empty()
            && let Err(e) = serde_json::from_str::<serde_json::Value>(&schema)
        {
            bail!("tool '{}' schema is not valid JSON: {}", tool_name, e);
        }

        info!(event = "plugin_register_mcp_tool", plugin = plugin_name, tool = %tool_name, "MCP tool registered");
        self.mcp_registry.register(
            plugin_name,
            RegisteredMcpTool {
                tool_name,
                description,
                schema,
            },
        );
        Ok(())
    }

    fn subscribe_trigger(&self, plugin_name: &str, topic_pattern: &str) -> Result<()> {
        if let Some(ref dispatcher) = self.trigger_dispatcher {
            let sub = TriggerSubscription {
                skill_name: plugin_name.to_string(),
                agent_type: "plugin".to_string(),
                topic_pattern: TriggerPattern::new(topic_pattern),
            };
            dispatcher.register_subscription(sub);
            info!(
                event = "plugin_subscribe_trigger",
                plugin = plugin_name,
                pattern = %topic_pattern,
                "trigger subscription registered"
            );
            Ok(())
        } else {
            bail!("trigger dispatcher not configured")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn register(api: &HostFunctions, plugin: &str, tool: &str) -> anyhow::Result<()> {
        api.register_mcp_tool(
            plugin,
            tool.to_string(),
            "desc".to_string(),
            "{}".to_string(),
        )
    }

    #[test]
    fn tool_name_must_be_namespaced() {
        let api = HostFunctions::new();
        assert!(register(&api, "tool-plugin", "my_tool").is_err());
        assert!(register(&api, "tool-plugin", "tool-plugin.my_tool").is_ok());
    }

    #[test]
    fn cross_plugin_tool_collision_is_rejected() {
        let api = HostFunctions::new();
        assert!(register(&api, "plugin-a", "plugin-a.shared_tool").is_ok());
        let err = register(&api, "plugin-b", "plugin-a.shared_tool").unwrap_err();
        assert!(
            err.to_string().contains("plugin-a"),
            "squatting another plugin's namespace must be rejected, got: {}",
            err
        );
    }

    #[test]
    fn tool_name_local_part_must_be_valid_identifier() {
        let api = HostFunctions::new();
        assert!(register(&api, "p", "p.").is_err());
        assert!(register(&api, "p", "p.sp ace").is_err());
        assert!(register(&api, "p", "p.dotted.name").is_err());
        assert!(register(&api, "p", "p.ok_name-1").is_ok());
    }

    #[test]
    fn per_plugin_registration_cap_is_enforced() {
        let api = HostFunctions::new();
        for i in 0..MAX_TOOLS_PER_PLUGIN {
            register(&api, "cap-plugin", &format!("cap-plugin.tool_{}", i)).unwrap();
        }
        let err = register(
            &api,
            "cap-plugin",
            &format!("cap-plugin.tool_{}", MAX_TOOLS_PER_PLUGIN),
        )
        .unwrap_err();
        assert!(err.to_string().contains("cap"), "got: {}", err);
    }

    #[test]
    fn global_registration_cap_is_enforced() {
        let api = HostFunctions::new();
        let mut plugin = 0usize;
        let mut tool = 0usize;
        let mut registered = 0usize;
        while registered < MAX_MCP_TOOLS_GLOBAL {
            register(
                &api,
                &format!("g{}", plugin),
                &format!("g{}.t{}", plugin, tool),
            )
            .unwrap();
            registered += 1;
            tool += 1;
            if tool >= MAX_TOOLS_PER_PLUGIN {
                tool = 0;
                plugin += 1;
            }
        }
        let err = register(
            &api,
            &format!("g{}", plugin),
            &format!("g{}.overflow", plugin),
        )
        .unwrap_err();
        assert!(err.to_string().contains("global cap"), "got: {}", err);
    }

    /// End-to-end pinning proof: the plugin HTTP client must connect through
    /// the guard's resolver. The hostname `local.test` does not resolve via
    /// the system DNS, so a successful request to it — mapped to 127.0.0.1
    /// by the injected resolver — can only happen if the connector used the
    /// guard-validated answer (IP pinning), not a second unguarded lookup.
    #[test]
    fn http_client_connects_through_guard_resolver() -> anyhow::Result<()> {
        use std::net::IpAddr;
        use std::sync::Arc;

        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        rt.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
            let addr = listener.local_addr()?;
            let server = tokio::task::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let (mut socket, _) = listener.accept().await?;
                let mut buf = [0u8; 4096];
                let _ = socket.read(&mut buf).await;
                socket
                    .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 4\r\n\r\npong")
                    .await?;
                Ok::<(), std::io::Error>(())
            });

            let guard =
                crate::guard::NetworkGuard::new(crate::guard::NetworkGuardPolicy::permissive())
                    .with_resolver(Arc::new(move |_: &str| {
                        vec![IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)]
                    }));
            let api = HostFunctions::new().with_network_guard(guard);
            let url = format!("http://local.test:{}/", addr.port());
            let resp = api.http_request("GET".into(), url, "{}".into(), String::new())?;
            assert!(resp.contains("pong"), "got: {}", resp);

            server.await??;
            Ok::<(), anyhow::Error>(())
        })?;
        Ok(())
    }
}
