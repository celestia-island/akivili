//! Sandbox environment feeding — the plugin host's registry adapter for
//! [`akivili_registry::kinds::SANDBOX_ENV`] resources.
//!
//! The sandbox a plugin executes in (its Boa context) can be handed
//! auxiliary environment variables ("from the VM's point of view, some
//! extra helping env vars") contributed by store plugins: the host opens
//! the registry with a [`SandboxEnvFeed`], and every enabled plugin that
//! declares a `sandbox.env` resource feeds variables into the merged set
//! the host then injects.
//!
//! # Payload contract
//!
//! A `sandbox.env` resource payload is an **inline JSON object of string
//! values**: `{"VAR_NAME": "value", ...}`. Anything else degrades per
//! entry, never poisoning the batch:
//!
//! - a value that is not a string skips that one variable (warn log);
//! - a payload that is not a JSON object, a `File` payload, or an empty
//!   variable name skips that resource/entry (warn log).
//!
//! # Precedence
//!
//! - Registry-fed values sit **below** explicit caller configuration:
//!   [`SandboxEnvFeed::merged_with`] layers an explicit map over the fed
//!   set, so explicitly configured variables always win.
//! - Within the registry itself, later-fed resources override earlier
//!   ones. Feed order is the registry's deterministic order (entry
//!   `order` ascending, ties by plugin id), so higher-`order` resources
//!   take precedence.
//!
//! # Host wiring (the consumption point)
//!
//! The env injection surface lives in this crate:
//! [`HostFunctions`](crate::plugin_state::HostFunctions) holds the merged
//! set ([`HostFunctions::with_sandbox_env`](crate::plugin_state::HostFunctions::with_sandbox_env)),
//! every Boa context is created with a `__sandbox_env` JSON snapshot
//! global (mirroring `__plugin_state`), and the `env-get` dispatch tool
//! reads it live (mirroring `config-get`). A host process wires the feed
//! like this:
//!
//! ```rust
//! # use std::collections::HashMap;
//! use akivili_plugin_host::{HostFunctions, SandboxEnvFeed};
//!
//! # let dir = tempfile::tempdir().unwrap();
//! # let plugin = dir.path().join("acmeenv");
//! # std::fs::create_dir_all(&plugin).unwrap();
//! # std::fs::write(plugin.join("akivili.plugin.toml"), r#"
//! # id = "acmeenv"
//! # version = "1.0.0"
//! # provider = "acme"
//! #
//! # [[resources]]
//! # kind = "sandbox.env"
//! # order = 1
//! #
//! # [resources.payload.Inline]
//! # AKIVILI_REGION = "eu"
//! # "#).unwrap();
//! // 1) open the feed against the plugin store (and its audit log).
//! let feed = SandboxEnvFeed::open(dir.path(), &dir.path().join("audit.jsonl")).unwrap();
//!
//! // 2) layer explicit configuration over the fed set — explicit wins.
//! let mut explicit = HashMap::new();
//! explicit.insert("AKIVILI_REGION".to_string(), "apac".to_string());
//! explicit.insert("AKIVILI_TOKEN".to_string(), "from-host-config".to_string());
//! let env = feed.merged_with(explicit);
//! assert_eq!(env["AKIVILI_REGION"], "apac");
//! assert_eq!(env["AKIVILI_TOKEN"], "from-host-config");
//!
//! // 3) hand the merged set to the host functions every plugin shares.
//! let host_api = HostFunctions::new().with_sandbox_env(env);
//! assert_eq!(host_api.env_get("AKIVILI_REGION").as_deref(), Some("apac"));
//! ```
//!
//! Keep the feed alive for as long as the host runs: it owns the loaded
//! resource handles (the audit anchor of the injection — dropping the
//! feed records `unloaded` events with `dropped: true`).
//!
//! # Missing store policy
//!
//! A store directory that does not exist degrades gracefully (empty env,
//! info log) — the same optional-facility convention as
//! [`PluginRouter::scan_and_load_dir`](crate::PluginRouter::scan_and_load_dir).
//! Any other open failure (unopenable audit log, unreadable store) is
//! fail-loud, per the registry's own semantics.

use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result};
use tracing::{info, warn};

use akivili_registry::{
    HostAcceptance, Registry, ResolvedPayload, ResourceHandle,
    kinds::{self, ResourceKind},
};

/// The host identity this adapter feeds as (lands in `fed` audit events).
pub const SANDBOX_ENV_HOST_ID: &str = "akivili-plugin-host";

/// The registry host adapter for sandbox environment variables.
///
/// Opens the plugin registry, feeds it the plugin host's acceptance
/// ([`SANDBOX_ENV`](akivili_registry::kinds::SANDBOX_ENV) only), loads
/// every fed resource (keeping the handles for the host's lifetime), and
/// exposes the merged `HashMap<String, String>` env set. See the
/// [module docs](self) for the payload contract and precedence rules.
#[derive(Debug)]
pub struct SandboxEnvFeed {
    registry: Option<Registry>,
    handles: Vec<ResourceHandle>,
    env: HashMap<String, String>,
}

impl SandboxEnvFeed {
    /// Opens the feed against a plugin store and its audit log.
    ///
    /// A missing store directory degrades to an empty feed (see the module
    /// docs); everything else fails loudly. Feeding and loading audit
    /// `fed`/`loaded` events into the JSONL log like any other host.
    pub fn open(store_dir: &Path, audit_path: &Path) -> Result<Self> {
        if !store_dir.exists() {
            info!(
                store = %store_dir.display(),
                "plugin store does not exist, sandbox env feed is empty"
            );
            return Ok(Self {
                registry: None,
                handles: Vec::new(),
                env: HashMap::new(),
            });
        }

        let registry = Registry::open(store_dir, audit_path)
            .with_context(|| format!("cannot open plugin registry at {}", store_dir.display()))?;
        let (handles, env) = Self::pull(&registry)?;
        Ok(Self {
            registry: Some(registry),
            handles,
            env,
        })
    }

    /// Feeds the acceptance, loads each fed resource (handles kept), and
    /// merges the inline payloads into the env set.
    fn pull(registry: &Registry) -> Result<(Vec<ResourceHandle>, HashMap<String, String>)> {
        let acceptance = HostAcceptance::new(
            SANDBOX_ENV_HOST_ID,
            vec![
                ResourceKind::new(kinds::SANDBOX_ENV)
                    .context("\"sandbox.env\" is a well-formed kind")?,
            ],
        );
        let fed = registry.feed(&acceptance)?;

        let mut handles = Vec::new();
        let mut env = HashMap::new();
        for item in fed.iter() {
            let handle = registry
                .load(&item.plugin_id, item.entry_index)
                .with_context(|| {
                    format!("cannot load sandbox env from plugin '{}'", item.plugin_id)
                })?;
            apply_payload(&mut env, &item.plugin_id, &item.resolved);
            handles.push(handle);
        }

        if fed.is_empty() {
            info!(
                host = SANDBOX_ENV_HOST_ID,
                "no sandbox env resources were fed"
            );
        } else {
            info!(
                host = SANDBOX_ENV_HOST_ID,
                resources = fed.len(),
                variables = env.len(),
                "sandbox env fed from the plugin registry"
            );
        }
        Ok((handles, env))
    }

    /// The registry-fed env set (explicit caller configuration not
    /// included — see [`SandboxEnvFeed::merged_with`]).
    pub fn env(&self) -> &HashMap<String, String> {
        &self.env
    }

    /// The open registry behind this feed, or `None` in the degraded
    /// missing-store case. Exposed read-only for hosts that want to
    /// inspect plugins or scan rejections alongside the feed.
    pub fn registry(&self) -> Option<&Registry> {
        self.registry.as_ref()
    }

    /// How many `sandbox.env` resources were fed and loaded — the live
    /// handles this feed keeps for the host's lifetime.
    pub fn resource_count(&self) -> usize {
        self.handles.len()
    }

    /// Layers `explicit` over the fed set: explicit caller configuration
    /// always wins over registry-fed values (registry < explicit).
    pub fn merged_with(&self, explicit: HashMap<String, String>) -> HashMap<String, String> {
        let mut merged = self.env.clone();
        merged.extend(explicit);
        merged
    }
}

/// Merges one resolved payload into the env set, skipping (with a log)
/// anything that violates the contract instead of poisoning the batch.
fn apply_payload(env: &mut HashMap<String, String>, plugin_id: &str, resolved: &ResolvedPayload) {
    let ResolvedPayload::Inline(value) = resolved else {
        warn!(
            plugin = plugin_id,
            "sandbox.env contract is inline JSON objects, skipping file payload"
        );
        return;
    };

    let Some(map) = value.as_object() else {
        warn!(
            plugin = plugin_id,
            "sandbox.env payload is not a JSON object, skipping resource"
        );
        return;
    };

    for (key, value) in map {
        if key.is_empty() {
            warn!(
                plugin = plugin_id,
                "sandbox.env variable with empty name, skipping"
            );
            continue;
        }
        match value.as_str() {
            Some(text) => {
                env.insert(key.clone(), text.to_string());
            }
            None => warn!(
                plugin = plugin_id,
                key, "sandbox.env value is not a string, skipping entry"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin_state::HostFunctions;
    use crate::ts_plugin::{TsLanguage, TsPlugin, TsPluginData};
    use std::sync::Arc;

    struct TestStore {
        root: tempfile::TempDir,
    }

    impl TestStore {
        fn new() -> Self {
            Self {
                root: tempfile::tempdir().unwrap(),
            }
        }

        fn store_dir(&self) -> &Path {
            self.root.path()
        }

        fn audit_path(&self) -> std::path::PathBuf {
            self.root.path().join("audit.jsonl")
        }

        fn add_plugin(&self, name: &str, manifest: &str) {
            let dir = self.root.path().join(name);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("akivili.plugin.toml"), manifest).unwrap();
        }

        fn disable(&self, plugin_id: &str) {
            std::fs::write(
                self.root.path().join("registry-state.json"),
                format!(r#"{{"plugins":{{"{plugin_id}":false}}}}"#),
            )
            .unwrap();
        }

        fn audit_json(&self) -> Vec<serde_json::Value> {
            let text = std::fs::read_to_string(self.audit_path()).unwrap();
            text.lines()
                .map(serde_json::from_str)
                .collect::<Result<_, _>>()
                .unwrap()
        }
    }

    /// beta: order 5 — feeds first, so alpha's order-10 value wins the tie.
    const BETA: &str = r#"
id = "beta"
version = "0.1.0"
provider = "test"

[[resources]]
kind = "sandbox.env"
order = 5

[resources.payload.Inline]
AKIVILI_REGION = "us"
AKIVILI_BETA_ONLY = "yes"
"#;

    /// alpha: order 10 — the later-fed resource, wins AKIVILI_REGION.
    const ALPHA: &str = r#"
id = "alpha"
version = "1.2.0"
provider = "test"

[[resources]]
kind = "sandbox.env"
order = 10

[resources.payload.Inline]
AKIVILI_REGION = "eu"
AKIVILI_TRACE = "off"
"#;

    /// gamma: one non-string value (skipped entry) next to a valid one.
    const GAMMA: &str = r#"
id = "gamma"
version = "1.0.0"
provider = "test"

[[resources]]
kind = "sandbox.env"
order = 20

[resources.payload.Inline]
AKIVILI_GAMMA_OK = "yes"
AKIVILI_COUNT = 3
"#;

    /// delta: payload is not a JSON object — the whole resource is skipped.
    const DELTA: &str = r#"
id = "delta"
version = "1.0.0"
provider = "test"

[[resources]]
kind = "sandbox.env"
order = 30

[resources.payload.Inline]
"not an object"
"#;

    /// epsilon: file payload — outside the sandbox.env contract, skipped.
    const EPSILON: &str = r#"
id = "epsilon"
version = "1.0.0"
provider = "test"

[[resources]]
kind = "sandbox.env"
order = 40

[resources.payload.File]
path = "env.json"
"#;

    #[test]
    fn multi_plugin_env_merges_with_feed_order_precedence() {
        let store = TestStore::new();
        store.add_plugin("alpha", ALPHA);
        store.add_plugin("beta", BETA);

        let feed = SandboxEnvFeed::open(store.store_dir(), &store.audit_path()).unwrap();
        let env = feed.env();
        assert_eq!(env.len(), 3, "all variables from both plugins: {env:?}");
        // alpha is fed later (order 10 > 5), so its AKIVILI_REGION wins.
        assert_eq!(env["AKIVILI_REGION"], "eu");
        assert_eq!(env["AKIVILI_TRACE"], "off");
        assert_eq!(env["AKIVILI_BETA_ONLY"], "yes");
    }

    #[test]
    fn invalid_entries_are_skipped_without_poisoning_the_batch() {
        let store = TestStore::new();
        store.add_plugin("alpha", ALPHA);
        store.add_plugin("gamma", GAMMA);
        store.add_plugin("delta", DELTA);
        store.add_plugin("epsilon", EPSILON);
        std::fs::write(
            store.root.path().join("epsilon").join("env.json"),
            r#"{"AKIVILI_EPSILON": "unused"}"#,
        )
        .unwrap();

        let feed = SandboxEnvFeed::open(store.store_dir(), &store.audit_path()).unwrap();
        let env = feed.env();
        assert_eq!(env["AKIVILI_GAMMA_OK"], "yes", "valid entry survives");
        assert!(
            !env.contains_key("AKIVILI_COUNT"),
            "non-string value must be skipped: {env:?}"
        );
        assert!(
            !env.contains_key("AKIVILI_EPSILON"),
            "file payload must be skipped: {env:?}"
        );
        assert_eq!(env.len(), 3, "alpha's two + gamma's one: {env:?}");
    }

    #[test]
    fn disabled_plugins_do_not_feed() {
        let store = TestStore::new();
        store.add_plugin("alpha", ALPHA);
        store.add_plugin("beta", BETA);
        store.disable("beta");

        let feed = SandboxEnvFeed::open(store.store_dir(), &store.audit_path()).unwrap();
        let env = feed.env();
        assert!(
            !env.contains_key("AKIVILI_BETA_ONLY"),
            "disabled plugin must not feed: {env:?}"
        );
        assert_eq!(env.len(), 2);

        let events = store.audit_json();
        assert!(
            !events
                .iter()
                .any(|e| e["event"] == "fed" && e["plugin_id"] == "beta"),
            "no fed event for the disabled plugin: {events:?}"
        );
    }

    #[test]
    fn explicit_values_beat_registry_values() {
        let store = TestStore::new();
        store.add_plugin("alpha", ALPHA);

        let feed = SandboxEnvFeed::open(store.store_dir(), &store.audit_path()).unwrap();
        let mut explicit = HashMap::new();
        explicit.insert("AKIVILI_REGION".to_string(), "apac".to_string());
        explicit.insert("AKIVILI_EXPLICIT_ONLY".to_string(), "yes".to_string());
        let merged = feed.merged_with(explicit);

        assert_eq!(merged["AKIVILI_REGION"], "apac", "explicit must win");
        assert_eq!(merged["AKIVILI_EXPLICIT_ONLY"], "yes");
        assert_eq!(
            merged["AKIVILI_TRACE"], "off",
            "non-overlapping registry values must survive"
        );
    }

    #[test]
    fn missing_store_dir_degrades_gracefully() {
        let store = TestStore::new();
        let missing = store.root.path().join("missing-store");

        let feed = SandboxEnvFeed::open(&missing, &store.audit_path()).unwrap();
        assert!(feed.env().is_empty(), "degraded feed must be empty");
        let merged = feed.merged_with(HashMap::from([("A".to_string(), "b".to_string())]));
        assert_eq!(
            merged["A"], "b",
            "the merge layer still works when degraded"
        );
    }

    #[test]
    fn audit_trail_records_fed_then_loaded_in_order() {
        let store = TestStore::new();
        store.add_plugin("alpha", ALPHA);
        store.add_plugin("beta", BETA);

        let feed = SandboxEnvFeed::open(store.store_dir(), &store.audit_path()).unwrap();
        let events = store.audit_json();
        let fed: Vec<&serde_json::Value> = events.iter().filter(|e| e["event"] == "fed").collect();
        let loaded: Vec<&serde_json::Value> =
            events.iter().filter(|e| e["event"] == "loaded").collect();

        assert_eq!(fed.len(), 2, "one fed event per resource: {events:?}");
        assert_eq!(loaded.len(), 2, "one loaded event per resource: {events:?}");
        // Feed order: beta (order 5) before alpha (order 10).
        assert_eq!(fed[0]["plugin_id"], "beta");
        assert_eq!(fed[1]["plugin_id"], "alpha");
        for e in &fed {
            assert_eq!(e["kind"], "sandbox.env");
            assert_eq!(e["host_id"], SANDBOX_ENV_HOST_ID);
        }
        // Every fed event precedes every loaded event (feed audits as a
        // batch, loads follow one by one).
        let last_fed = events.iter().rposition(|e| e["event"] == "fed").unwrap();
        let first_loaded = events.iter().position(|e| e["event"] == "loaded").unwrap();
        assert!(last_fed < first_loaded);
        let handle_count = loaded.len();

        // Dropping the feed releases the handles: dropped-time unloads at
        // the tail of the trail, one per loaded resource.
        drop(feed);
        let events = store.audit_json();
        let tail = &events[events.len() - handle_count..];
        assert!(
            tail.iter()
                .all(|e| e["event"] == "unloaded" && e["dropped"] == true),
            "trailing events must be dropped-unloads: {tail:?}"
        );
        assert_eq!(tail.len(), handle_count);
    }

    /// End-to-end wiring proof: the plugin's Boa context observes the
    /// merged set (explicit wins) through both surfaces — the
    /// `__sandbox_env` snapshot global and the `env-get` dispatch tool.
    #[test]
    fn ts_plugin_sees_the_merged_env() -> anyhow::Result<()> {
        let store = TestStore::new();
        store.add_plugin("alpha", ALPHA);

        let feed = SandboxEnvFeed::open(store.store_dir(), &store.audit_path())?;
        let mut explicit = HashMap::new();
        explicit.insert("AKIVILI_REGION".to_string(), "apac".to_string());
        let host_api = Arc::new(HostFunctions::new().with_sandbox_env(feed.merged_with(explicit)));

        let data = TsPluginData::new(
            "env-reader",
            r#"
var handleRequest = function(method, path, headers, body) {
    var snapshot = JSON.parse(__sandbox_env);
    return JSON.stringify({
        region: snapshot.AKIVILI_REGION,
        trace: snapshot.AKIVILI_TRACE,
        viaDispatch: dispatch("env-get", { key: "AKIVILI_TRACE" }).value,
        missing: dispatch("env-get", { key: "NO_SUCH_VAR" }).value
    });
};
"#,
            TsLanguage::JavaScript,
        );

        let rt = tokio::runtime::Runtime::new()?;
        rt.block_on(async {
            let api = host_api.clone();
            let output = tokio::task::spawn_blocking(move || {
                let mut plugin = TsPlugin::create_and_load(api, &data)?;
                plugin.handle_request("POST", "/env", "{}", "{}")
            })
            .await??;
            let parsed: serde_json::Value = serde_json::from_str(&output)?;
            assert_eq!(parsed["region"], "apac", "explicit value must win");
            assert_eq!(parsed["trace"], "off", "registry value must survive");
            assert_eq!(parsed["viaDispatch"], "off", "env-get reads the same set");
            assert!(parsed["missing"].is_null(), "unknown keys read as null");
            anyhow::Ok(())
        })?;
        Ok(())
    }
}
