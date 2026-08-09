use anyhow::{Result, anyhow, bail};
use parking_lot::Mutex;
use serde_json::Value;
use std::{collections::HashMap, sync::Arc};
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

/// Builds the plugin HTTP client with the egress guard applied: connection
/// timeout and a redirect policy capped at the guard's hop limit, re-checking
/// every hop URL against the guard allow-list (mirrors the legacy adapter's
/// `ReqwestHttpClient`).
fn build_http_client(guard: &NetworkGuard) -> reqwest::Client {
    let timeout = std::time::Duration::from_secs(guard.policy().connect_timeout_secs);
    let max_hops = guard.max_redirect_hops() as usize;
    let guard_clone = guard.clone();
    reqwest::Client::builder()
        .timeout(timeout)
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
        tokio::task::block_in_place(|| {
            let handle = tokio::runtime::Handle::current();
            handle.block_on(async {
                let parsed_headers: HashMap<String, Value> =
                    serde_json::from_str(&headers).unwrap_or_default();

                let mut req = match method.to_uppercase().as_str() {
                    "GET" => client.get(&url),
                    "POST" => client.post(&url),
                    "PUT" => client.put(&url),
                    "PATCH" => client.patch(&url),
                    "DELETE" => client.delete(&url),
                    other => client.request(
                        reqwest::Method::from_bytes(other.as_bytes())
                            .unwrap_or(reqwest::Method::GET),
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
            tokio::task::block_in_place(|| {
                let handle = tokio::runtime::Handle::current();
                handle.block_on(async {
                    bus.publish(&topic, payload).await;
                })
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
            let result = tokio::task::block_in_place(|| {
                let handle = tokio::runtime::Handle::current();
                handle.block_on(async {
                    llm.llm_chat(ModelTier::Basic, &message, context.as_deref(), None, None)
                        .await
                })
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
        tokio::task::block_in_place(|| {
            let handle = tokio::runtime::Handle::current();
            handle.block_on(async { config.read().await.get(&key).cloned() })
        })
    }

    fn register_mcp_tool(
        &self,
        plugin_name: &str,
        tool_name: String,
        description: String,
        schema: String,
    ) -> Result<()> {
        if tool_name.is_empty() {
            bail!("tool name must not be empty");
        }

        if tool_name.contains(' ') || tool_name.contains('\n') || tool_name.contains('\t') {
            bail!("tool name '{}' contains whitespace", tool_name);
        }

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
