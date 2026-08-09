use anyhow::{Error, Result, anyhow};
use parking_lot::Mutex;
use std::{collections::HashMap, sync::Arc};

use tokio::time::timeout;
use tracing::{debug, error, info};

use crate::{
    plugin_state::{HostFunctions, RegisteredMcpTool, install_crypto_provider},
    ts_plugin::{TsLanguage, TsPlugin, TsPluginData, plugin_compute_timeout},
};

/// A per-plugin execution worker owning the pooled Boa contexts. Boa 0.21
/// contexts must be dropped on the thread that created them, so every
/// instance lives and dies inside this worker's thread; dispatches arrive
/// over a channel and run strictly one at a time, preserving in-script
/// global state (`__plugin_state`, module-level vars) across requests.
/// A request that times out only drops the caller's reply channel: the
/// worker still finishes the run and keeps the (now idle) instance in the
/// pool, so a slow plugin never poisons the pool.
pub struct TsPluginPool {
    tx: std::sync::mpsc::Sender<PoolRequest>,
    data: TsPluginData,
}

enum PoolRequest {
    Webhook {
        method: String,
        path: String,
        headers: String,
        body: String,
        reply: tokio::sync::oneshot::Sender<Result<String>>,
    },
    BotMessage {
        platform: String,
        message: String,
        reply: tokio::sync::oneshot::Sender<Result<Option<String>>>,
    },
}

impl TsPluginPool {
    fn new(host_api: Arc<HostFunctions>, data: TsPluginData) -> Self {
        let (tx, rx) = std::sync::mpsc::channel();
        let worker_data = data.clone();
        std::thread::Builder::new()
            .name(format!("plugin-worker-{}", data.plugin_name()))
            .spawn(move || worker_loop(host_api, worker_data, rx))
            .expect("plugin worker thread spawn failed");
        Self { tx, data }
    }

    fn plugin_name(&self) -> &str {
        self.data.plugin_name()
    }
}

fn worker_loop(
    host_api: Arc<HostFunctions>,
    data: TsPluginData,
    rx: std::sync::mpsc::Receiver<PoolRequest>,
) {
    let mut idle: Vec<TsPlugin> = Vec::new();
    while let Ok(req) = rx.recv() {
        let mut plugin = match idle.pop() {
            Some(p) => p,
            None => match TsPlugin::create_and_load(host_api.clone(), &data) {
                Ok(p) => p,
                Err(e) => {
                    let err = anyhow!("plugin instance creation failed: {}", e);
                    match req {
                        PoolRequest::Webhook { reply, .. } => {
                            let _ = reply.send(Err(err));
                        }
                        PoolRequest::BotMessage { reply, .. } => {
                            let _ = reply.send(Err(err));
                        }
                    }
                    continue;
                }
            },
        };
        match req {
            PoolRequest::Webhook {
                method,
                path,
                headers,
                body,
                reply,
            } => {
                let r = plugin.handle_request(&method, &path, &headers, &body);
                let reusable = r.is_ok();
                let _ = reply.send(r);
                if reusable {
                    idle.push(plugin);
                }
            }
            PoolRequest::BotMessage {
                platform,
                message,
                reply,
            } => {
                let r = plugin.on_message(&platform, &message);
                let reusable = r.is_ok();
                let _ = reply.send(r);
                if reusable {
                    idle.push(plugin);
                }
            }
        }
    }
}

pub struct PluginRouter {
    plugins: Mutex<HashMap<String, Arc<TsPluginPool>>>,
    host_api: Arc<HostFunctions>,
}

impl PluginRouter {
    pub fn new(host_api: Arc<HostFunctions>) -> Self {
        install_crypto_provider();
        Self {
            plugins: Mutex::new(HashMap::new()),
            host_api,
        }
    }

    pub fn load_ts_plugin(&self, name: &str, code: &str, language: TsLanguage) -> Result<()> {
        let data = TsPluginData::new(name, code, language);

        let api = self.host_api.clone();
        let init_data = data.clone();
        let pname = name.to_string();
        tokio::task::block_in_place(|| {
            let handle = tokio::runtime::Handle::current();
            handle.block_on(async {
                let join_handle = tokio::task::spawn_blocking(move || {
                    let plugin = TsPlugin::create_and_load(api, &init_data)?;
                    let tools = plugin.take_mcp_tools();
                    debug!(plugin = %pname, tools = tools.len(), "TS plugin init complete");
                    Ok::<(), Error>(())
                });
                let output = timeout(plugin_compute_timeout(), join_handle)
                    .await
                    .map_err(|_| {
                        anyhow!("plugin load timed out after {:?}", plugin_compute_timeout())
                    })?;
                output.map_err(|e| anyhow!("plugin load task failed: {e}"))?
            })
        })?;

        let pool = Arc::new(TsPluginPool::new(self.host_api.clone(), data));
        self.plugins.lock().insert(name.to_string(), pool);

        info!(plugin = name, "TS plugin registered");
        Ok(())
    }

    pub fn load_ts_plugin_from_file(&self, path: &std::path::Path) -> Result<()> {
        let code = std::fs::read_to_string(path)?;
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        let language = match ext {
            "ts" => TsLanguage::TypeScript,
            _ => TsLanguage::JavaScript,
        };
        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();
        self.load_ts_plugin(&name, &code, language)
    }

    pub fn dispatch_webhook(
        &self,
        plugin_name: &str,
        method: &str,
        path: &str,
        headers: &str,
        body: &str,
    ) -> Result<String> {
        let pool = self
            .plugins
            .lock()
            .get(plugin_name)
            .cloned()
            .ok_or_else(|| anyhow!("plugin not found: {}", plugin_name))?;

        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        pool.tx
            .send(PoolRequest::Webhook {
                method: method.to_string(),
                path: path.to_string(),
                headers: headers.to_string(),
                body: body.to_string(),
                reply: reply_tx,
            })
            .map_err(|_| anyhow!("plugin worker stopped: {}", plugin_name))?;

        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(timeout(plugin_compute_timeout(), reply_rx))
        })
        .map_err(|_| {
            anyhow!(
                "plugin execution timed out after {:?}",
                plugin_compute_timeout()
            )
        })?
        .map_err(|e| anyhow!("plugin execution failed: {e}"))?
    }

    pub fn get_plugin_name(&self, plugin_name: &str) -> Result<String> {
        let pool = self
            .plugins
            .lock()
            .get(plugin_name)
            .cloned()
            .ok_or_else(|| anyhow!("plugin not found: {}", plugin_name))?;
        Ok(pool.plugin_name().to_string())
    }

    pub fn dispatch_bot_message(
        &self,
        plugin_name: &str,
        platform: &str,
        message: &str,
    ) -> Result<Option<String>> {
        let pool = self
            .plugins
            .lock()
            .get(plugin_name)
            .cloned()
            .ok_or_else(|| anyhow!("plugin not found: {}", plugin_name))?;

        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        pool.tx
            .send(PoolRequest::BotMessage {
                platform: platform.to_string(),
                message: message.to_string(),
                reply: reply_tx,
            })
            .map_err(|_| anyhow!("plugin worker stopped: {}", plugin_name))?;

        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(timeout(plugin_compute_timeout(), reply_rx))
        })
        .map_err(|_| {
            anyhow!(
                "plugin execution timed out after {:?}",
                plugin_compute_timeout()
            )
        })?
        .map_err(|e| anyhow!("plugin execution failed: {e}"))?
    }

    pub fn list_plugins(&self) -> Vec<String> {
        self.plugins.lock().keys().cloned().collect()
    }

    pub fn unload_plugin(&self, name: &str) {
        self.plugins.lock().remove(name);
        info!(plugin = name, "plugin unloaded");
    }

    pub fn all_mcp_tools(&self) -> Vec<(String, RegisteredMcpTool)> {
        self.host_api.all_mcp_tools()
    }

    pub fn scan_and_load_dir(&self, dir: &std::path::Path) -> Result<usize> {
        if !dir.exists() {
            info!(dir = %dir.display(), "plugin directory does not exist, skipping");
            return Ok(0);
        }
        let mut count = 0;
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");

            match ext {
                "ts" | "js" => match self.load_ts_plugin_from_file(&path) {
                    Ok(()) => count += 1,
                    Err(e) => {
                        let name = path.display();
                        error!(plugin = %name, error = %e, "failed to load TS/JS plugin");
                    }
                },
                _ => {}
            }
        }
        info!(dir = %dir.display(), loaded = count, "plugin scan complete");
        Ok(count)
    }

    pub fn scan_amphoreus_agents(&self, amphoreus_dir: &std::path::Path) -> Result<usize> {
        if !amphoreus_dir.exists() {
            info!(dir = %amphoreus_dir.display(), ".amphoreus directory does not exist, skipping");
            return Ok(0);
        }
        let mut count = 0;
        for entry in std::fs::read_dir(amphoreus_dir)? {
            let entry = entry?;
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let name = match path.file_name().and_then(|n| n.to_str()) {
                Some(n) if !n.starts_with('.') => n.to_string(),
                _ => continue,
            };
            if !path.join("agent.toml").exists() {
                continue;
            }
            for file_entry in std::fs::read_dir(&path)? {
                let file_entry = file_entry?;
                let file_path = file_entry.path();
                let ext = file_path.extension().and_then(|e| e.to_str()).unwrap_or("");
                if ext == "ts" {
                    match self.load_ts_plugin_from_file(&file_path) {
                        Ok(()) => count += 1,
                        Err(e) => {
                            error!(plugin = %name, error = %e, "failed to load .amphoreus TS plugin");
                        }
                    }
                }
            }
        }
        info!(dir = %amphoreus_dir.display(), loaded = count, ".amphoreus agent plugin scan complete");
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Context;

    fn make_host_api() -> Arc<HostFunctions> {
        Arc::new(HostFunctions::new())
    }

    #[test]
    fn load_ts_and_dispatch() -> Result<()> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        rt.block_on(async {
            let host_api = make_host_api();
            let router = PluginRouter::new(host_api);

            router.load_ts_plugin(
                "test-webhook",
                r#"
var handleRequest = function(method, path, headers, body) {
    return JSON.stringify({ method: method, received: true });
};
"#,
                TsLanguage::JavaScript,
            )?;

            let plugins = router.list_plugins();
            assert!(plugins.contains(&"test-webhook".to_string()));

            let response =
                router.dispatch_webhook("test-webhook", "POST", "/webhook/test", "{}", "{}")?;

            let parsed: serde_json::Value = serde_json::from_str(&response)?;
            assert_eq!(parsed["method"], "POST");
            assert_eq!(parsed["received"], true);
            Ok::<(), Error>(())
        })?;
        Ok(())
    }

    #[test]
    fn dispatch_unknown_plugin_errors() -> Result<()> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        rt.block_on(async {
            let host_api = make_host_api();
            let router = PluginRouter::new(host_api);

            let result = router.dispatch_webhook("nonexistent", "POST", "/", "{}", "{}");
            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("plugin not found"));
            Ok::<(), Error>(())
        })?;
        Ok(())
    }

    #[test]
    fn unload_removes_plugin() -> Result<()> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        rt.block_on(async {
            let host_api = make_host_api();
            let router = PluginRouter::new(host_api);

            router.load_ts_plugin(
                "temp-plugin",
                r#"var handleRequest = function(m,p,h,b) { return "{}"; };"#,
                TsLanguage::JavaScript,
            )?;

            assert!(router.list_plugins().contains(&"temp-plugin".to_string()));
            router.unload_plugin("temp-plugin");
            assert!(!router.list_plugins().contains(&"temp-plugin".to_string()));
            Ok::<(), Error>(())
        })?;
        Ok(())
    }

    #[test]
    fn scan_empty_dir_returns_zero() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let host_api = make_host_api();
        let router = PluginRouter::new(host_api);
        let count = router.scan_and_load_dir(dir.path())?;
        assert_eq!(count, 0);
        Ok(())
    }

    #[test]
    fn scan_nonexistent_dir_returns_zero() -> Result<()> {
        let host_api = make_host_api();
        let router = PluginRouter::new(host_api);
        let count = router.scan_and_load_dir(std::path::Path::new("/nonexistent/plugins/dir"))?;
        assert_eq!(count, 0);
        Ok(())
    }

    #[test]
    fn scan_loads_js_file() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let js_code =
            r#"var handleRequest = function(m,p,h,b) { return JSON.stringify({scanned: true}); };"#;
        std::fs::write(dir.path().join("my-plugin.js"), js_code)?;

        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        rt.block_on(async {
            let host_api = make_host_api();
            let router = PluginRouter::new(host_api);
            let count = router.scan_and_load_dir(dir.path())?;
            assert_eq!(count, 1);

            let response = router.dispatch_webhook("my-plugin", "POST", "/", "{}", "{}")?;
            let parsed: serde_json::Value = serde_json::from_str(&response)?;
            assert_eq!(parsed["scanned"], true);
            Ok::<(), Error>(())
        })?;
        Ok(())
    }

    /// Instances are pooled, so in-script state survives across dispatches:
    /// the second call must observe the counter mutated by the first.
    #[test]
    fn plugin_state_preserved_across_dispatches() -> Result<()> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        rt.block_on(async {
            let host_api = make_host_api();
            let router = PluginRouter::new(host_api);

            router.load_ts_plugin(
                "counter",
                r#"
var count = 0;
var handleRequest = function(m, p, h, b) {
    count = count + 1;
    return JSON.stringify({ count: count });
};
"#,
                TsLanguage::JavaScript,
            )?;

            let first = router.dispatch_webhook("counter", "POST", "/", "{}", "{}")?;
            let first_val: serde_json::Value = serde_json::from_str(&first)?;
            assert_eq!(first_val["count"], 1);

            let second = router.dispatch_webhook("counter", "POST", "/", "{}", "{}")?;
            let second_val: serde_json::Value = serde_json::from_str(&second)?;
            assert_eq!(second_val["count"], 2);
            Ok::<(), Error>(())
        })?;
        Ok(())
    }

    /// __plugin_state survives across dispatches via the pooled context.
    #[test]
    fn plugin_state_global_survives_dispatches() -> Result<()> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        rt.block_on(async {
            let host_api = make_host_api();
            let router = PluginRouter::new(host_api);

            router.load_ts_plugin(
                "stateful",
                r#"
var handleRequest = function(m, p, h, b) {
    var st = JSON.parse(__plugin_state);
    st.hits = (st.hits || 0) + 1;
    __plugin_state = JSON.stringify(st);
    return JSON.stringify(st);
};
"#,
                TsLanguage::JavaScript,
            )?;

            let first: serde_json::Value = serde_json::from_str(
                &router.dispatch_webhook("stateful", "POST", "/", "{}", "{}")?,
            )?;
            assert_eq!(first["hits"], 1);

            let second: serde_json::Value = serde_json::from_str(
                &router.dispatch_webhook("stateful", "POST", "/", "{}", "{}")?,
            )?;
            assert_eq!(second["hits"], 2);
            Ok::<(), Error>(())
        })?;
        Ok(())
    }

    /// The script body runs once per load, so MCP tools registered by the
    /// plugin must appear exactly once even after many dispatches.
    #[test]
    fn mcp_tools_registered_once() -> Result<()> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        rt.block_on(async {
            let host_api = make_host_api();
            let router = PluginRouter::new(host_api);

            router.load_ts_plugin(
                "tooler",
                r#"
registerMcpTool("echo", "Echoes input", "{}");
var handleRequest = function(m, p, h, b) { return "{}"; };
"#,
                TsLanguage::JavaScript,
            )?;

            for _ in 0..3 {
                router.dispatch_webhook("tooler", "POST", "/", "{}", "{}")?;
            }

            let all = router.all_mcp_tools();
            let mine: Vec<_> = all.iter().filter(|(p, _)| p == "tooler").collect();
            assert_eq!(mine.len(), 1, "tool must be registered exactly once");
            assert_eq!(mine[0].1.tool_name, "echo");
            Ok::<(), Error>(())
        })?;
        Ok(())
    }

    #[test]
    fn dispatch_bot_message_ts() -> Result<()> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        rt.block_on(async {
            let host_api = make_host_api();
            let router = PluginRouter::new(host_api);

            router.load_ts_plugin(
                "bot-plugin",
                r#"
var onMessage = function(platform, message) {
    return JSON.stringify({ platform: platform, text: message });
};
"#,
                TsLanguage::JavaScript,
            )?;

            let result = router.dispatch_bot_message("bot-plugin", "discord", "hi there")?;
            assert!(result.is_some());
            let parsed: serde_json::Value =
                serde_json::from_str(&result.context("no bot message returned")?)?;
            assert_eq!(parsed["platform"], "discord");
            assert_eq!(parsed["text"], "hi there");
            Ok::<(), Error>(())
        })?;
        Ok(())
    }

    /// C5: a dead-looping plugin handler must be cut off by a wall clock —
    /// the abandoned plugin instance is discarded and the router keeps
    /// serving other plugins with fresh instances.
    #[test]
    fn dispatch_infinite_loop_times_out() -> Result<()> {
        use std::time::{Duration, Instant};
        unsafe {
            std::env::set_var("CELESTIA_PLUGIN_COMPUTE_TIMEOUT_MS", "800");
        }
        let result = (|| -> Result<()> {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            rt.block_on(async {
                let host_api = make_host_api();
                let router = PluginRouter::new(host_api);

                router.load_ts_plugin(
                    "spinner",
                    r#"
var handleRequest = function(m, p, h, b) {
    var spin = function(){ for(var i=0;i<1000000;i++){} };
    var deadline = Date.now() + 3000;
    while (Date.now() < deadline) { spin(); }
    return "{}";
};
"#,
                    TsLanguage::JavaScript,
                )?;

                let started = Instant::now();
                let result = router.dispatch_webhook("spinner", "POST", "/", "{}", "{}");
                assert!(
                    result.is_err(),
                    "dead-looping plugin must time out on the wall clock"
                );
                assert!(
                    started.elapsed() < Duration::from_secs(10),
                    "plugin timeout must be enforced quickly, took {:?}",
                    started.elapsed()
                );

                router.load_ts_plugin(
                    "fine",
                    r#"var handleRequest = function(m,p,h,b) { return JSON.stringify({ ok: true }); };"#,
                    TsLanguage::JavaScript,
                )?;
                let ok = router.dispatch_webhook("fine", "POST", "/", "{}", "{}")?;
                let parsed: serde_json::Value = serde_json::from_str(&ok)?;
                assert_eq!(parsed["ok"], true);
                Ok::<(), Error>(())
            })
        })();
        unsafe {
            std::env::remove_var("CELESTIA_PLUGIN_COMPUTE_TIMEOUT_MS");
        }
        result
    }
}
