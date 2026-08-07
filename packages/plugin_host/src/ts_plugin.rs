use anyhow::{Result, anyhow};
use serde::Serialize;
use std::{
    cell::RefCell,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use boa_engine::{
    JsString, JsValue, Source, builtins::promise::Promise, js_string, object::builtins::JsPromise,
    property::Attribute,
};
use boa_runtime::Console;
use tracing::{debug, error, info, warn};

use crate::plugin_state::{HostApiProvider, HostFunctions, RegisteredMcpTool};

#[derive(Debug, Clone, Serialize)]
struct PluginResult {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    response: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl PluginResult {
    fn ok() -> serde_json::Value {
        serde_json::to_value(Self {
            success: true,
            response: None,
            value: None,
            error: None,
        })
        .unwrap_or_default()
    }
    fn with_response(resp: String) -> serde_json::Value {
        serde_json::to_value(Self {
            success: true,
            response: Some(resp),
            value: None,
            error: None,
        })
        .unwrap_or_default()
    }
    fn with_value(val: serde_json::Value) -> serde_json::Value {
        serde_json::to_value(Self {
            success: true,
            response: None,
            value: Some(val),
            error: None,
        })
        .unwrap_or_default()
    }
    fn err(msg: impl Into<String>) -> serde_json::Value {
        serde_json::to_value(Self {
            success: false,
            response: None,
            value: None,
            error: Some(msg.into()),
        })
        .unwrap_or_default()
    }
}

const COMPUTE_TIMEOUT: Duration = Duration::from_secs(120);
const ABSOLUTE_CEILING: Duration = Duration::from_secs(600);

/// Wall-clock budget for a single plugin evaluation (script load or handler
/// dispatch). The plugin instance runs inside a `spawn_blocking` task, so a
/// dead-looping plugin is abandoned when this budget elapses — the instance
/// is discarded and the next dispatch builds a fresh one. Overridable for
/// tests via `CELESTIA_PLUGIN_COMPUTE_TIMEOUT_MS`.
pub const PLUGIN_COMPUTE_TIMEOUT: Duration = Duration::from_secs(120);

pub fn plugin_compute_timeout() -> Duration {
    if let Some(ms) = std::env::var("CELESTIA_PLUGIN_COMPUTE_TIMEOUT_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        && ms > 0
    {
        return Duration::from_millis(ms);
    }
    PLUGIN_COMPUTE_TIMEOUT
}

thread_local! {
    static CURRENT_HOST_API: RefCell<Option<(Arc<HostFunctions>, String)>> = const { RefCell::new(None) };
}

fn native_dispatch_wrapper(
    _this: &JsValue,
    args: &[JsValue],
    _ctx: &mut boa_engine::Context,
) -> boa_engine::JsResult<JsValue> {
    let tool_name = args
        .get(1)
        .map(|v| match v.as_string() {
            Some(s) => s.to_std_string_escaped(),
            None => v.display().to_string(),
        })
        .unwrap_or_default();

    let params_json = args
        .get(2)
        .map(|v| match v.as_string() {
            Some(s) => s.to_std_string_escaped(),
            None => v.display().to_string(),
        })
        .unwrap_or_default();

    let params: serde_json::Value =
        serde_json::from_str(&params_json).unwrap_or(serde_json::Value::Object(Default::default()));

    let result = CURRENT_HOST_API.with(|cell| {
        cell.borrow()
            .as_ref()
            .map(|(api, pname)| dispatch_host_fn(api, pname, &tool_name, params))
    });

    match result {
        Some(val) => {
            let json =
                serde_json::to_string(&val).unwrap_or_else(|_| r#"{"success":false}"#.to_string());
            Ok(JsValue::from(js_string!(json)))
        }
        None => {
            let err: boa_engine::JsError = boa_engine::JsNativeError::range()
                .with_message("dispatch handler not initialized")
                .into();
            Err(err)
        }
    }
}

fn dispatch_host_fn(
    api: &Arc<HostFunctions>,
    plugin_name: &str,
    tool_name: &str,
    params: serde_json::Value,
) -> serde_json::Value {
    match tool_name {
        "http-request" => {
            let method = params["method"].as_str().unwrap_or("GET").to_string();
            let url = params["url"].as_str().unwrap_or("").to_string();
            let headers = params["headers"].as_str().unwrap_or("{}").to_string();
            let body = params["body"].as_str().unwrap_or("").to_string();
            match api.http_request(method, url, headers, body) {
                Ok(resp) => PluginResult::with_response(resp),
                Err(e) => PluginResult::err(e.to_string()),
            }
        }
        "forward-event" => {
            let event_str = if let Some(s) = params["event"].as_str() {
                s.to_string()
            } else if let Some(v) = params.get("event") {
                v.to_string()
            } else {
                "{}".to_string()
            };
            match api.forward_event(event_str) {
                Ok(()) => PluginResult::ok(),
                Err(e) => PluginResult::err(e.to_string()),
            }
        }
        "query-ai" => {
            let message = params["message"].as_str().unwrap_or("").to_string();
            let context = params["context"].as_str().map(|s| s.to_string());
            match api.query_ai(message, context) {
                Ok(resp) => PluginResult::with_response(resp),
                Err(e) => PluginResult::err(e.to_string()),
            }
        }
        "log" => {
            let level = params["level"].as_str().unwrap_or("info").to_string();
            let message = params["message"].as_str().unwrap_or("").to_string();
            match level.as_str() {
                "error" => error!(plugin = plugin_name, "{}", message),
                "warn" => warn!(plugin = plugin_name, "{}", message),
                "info" => info!(plugin = plugin_name, "{}", message),
                "debug" => debug!(plugin = plugin_name, "{}", message),
                _ => info!(plugin = plugin_name, "[{}] {}", level, message),
            }
            PluginResult::ok()
        }
        "config-get" => {
            let key = params["key"].as_str().unwrap_or("").to_string();
            match api.config_get(key) {
                Some(v) => PluginResult::with_value(serde_json::Value::String(v)),
                None => PluginResult::with_value(serde_json::Value::Null),
            }
        }
        "kv-get" => {
            let key = params["key"].as_str().unwrap_or("").to_string();
            let result = tokio::task::block_in_place(|| {
                let handle = tokio::runtime::Handle::current();
                handle.block_on(api.kv_get(&key))
            });
            match result {
                Some(v) => PluginResult::with_value(serde_json::Value::String(v)),
                None => PluginResult::with_value(serde_json::Value::Null),
            }
        }
        "kv-set" => {
            let key = params["key"].as_str().unwrap_or("").to_string();
            let value = params["value"].as_str().unwrap_or("").to_string();
            tokio::task::block_in_place(|| {
                let handle = tokio::runtime::Handle::current();
                handle.block_on(api.kv_set(&key, &value))
            });
            PluginResult::ok()
        }
        "register-mcp-tool" => {
            let tool_name = params["tool-name"]
                .as_str()
                .or_else(|| params["name"].as_str())
                .unwrap_or("")
                .to_string();
            let description = params["description"].as_str().unwrap_or("").to_string();
            let schema = params["schema"].as_str().unwrap_or("{}").to_string();
            match api.register_mcp_tool(plugin_name, tool_name, description, schema) {
                Ok(()) => PluginResult::ok(),
                Err(e) => PluginResult::err(e.to_string()),
            }
        }
        "subscribe-trigger" => {
            let topic_pattern = params["topicPattern"]
                .as_str()
                .or_else(|| params["topic_pattern"].as_str())
                .unwrap_or("")
                .to_string();
            match api.subscribe_trigger(plugin_name, &topic_pattern) {
                Ok(()) => PluginResult::ok(),
                Err(e) => PluginResult::err(e.to_string()),
            }
        }
        _ => {
            warn!(
                plugin = plugin_name,
                tool = tool_name,
                "unknown dispatch tool"
            );
            PluginResult::err(format!("unknown tool: {}", tool_name))
        }
    }
}

const PLUGIN_BOILERPLATE: &str = r#"
(function() {
    var _dispatch = globalThis.__plugin_dispatch;
    globalThis.dispatch = function(toolName, params) {
        var paramsJson = typeof params === 'string' ? params : JSON.stringify(params || {});
        var resultJson = _dispatch(null, toolName, paramsJson);
        try { return JSON.parse(resultJson); } catch(e) { return resultJson; }
    };
})();
"#;

const INIT_TOOL_REG: &str = r#"
globalThis.__registeredTools = [];
globalThis.registerMcpTool = function(name, description, schema) {
    var schemaJson = typeof schema === 'string' ? schema : JSON.stringify(schema || {});
    dispatch("register-mcp-tool", { "tool-name": name, "description": description, "schema": schemaJson });
    globalThis.__registeredTools.push({ name: name, description: description, schema: schemaJson });
};
"#;

#[derive(Debug)]
struct BufferedLogger {
    buffer: Arc<Mutex<String>>,
}

unsafe impl boa_gc::Trace for BufferedLogger {
    boa_gc::empty_trace!();
}

impl boa_gc::Finalize for BufferedLogger {}

impl boa_runtime::Logger for BufferedLogger {
    fn log(
        &self,
        msg: String,
        _: &boa_runtime::console::ConsoleState,
        _: &mut boa_engine::Context,
    ) -> boa_engine::JsResult<()> {
        if let Ok(mut buf) = self.buffer.lock() {
            buf.push_str(&msg);
            buf.push('\n');
        }
        Ok(())
    }

    fn info(
        &self,
        msg: String,
        state: &boa_runtime::console::ConsoleState,
        ctx: &mut boa_engine::Context,
    ) -> boa_engine::JsResult<()> {
        self.log(msg, state, ctx)
    }

    fn warn(
        &self,
        msg: String,
        state: &boa_runtime::console::ConsoleState,
        ctx: &mut boa_engine::Context,
    ) -> boa_engine::JsResult<()> {
        self.log(msg, state, ctx)
    }

    fn error(
        &self,
        msg: String,
        state: &boa_runtime::console::ConsoleState,
        ctx: &mut boa_engine::Context,
    ) -> boa_engine::JsResult<()> {
        self.log(msg, state, ctx)
    }
}

#[derive(Clone)]
pub enum TsLanguage {
    JavaScript,
    TypeScript,
}

#[derive(Clone)]
pub struct TsPluginData {
    pub code: String,
    pub language: TsLanguage,
    pub plugin_name: String,
    /// Lazily transpiled JS for TypeScript plugins; reused across dispatches
    /// so the SWC pipeline runs at most once per plugin. Arc so clones share
    /// the cache across dispatch threads.
    compiled_js: std::sync::Arc<std::sync::OnceLock<String>>,
}

impl TsPluginData {
    pub fn new(plugin_name: &str, code: &str, language: TsLanguage) -> Self {
        Self {
            code: code.to_string(),
            language,
            plugin_name: plugin_name.to_string(),
            compiled_js: std::sync::Arc::new(std::sync::OnceLock::new()),
        }
    }

    pub fn plugin_name(&self) -> &str {
        &self.plugin_name
    }

    fn transpiled_js(&self) -> Result<&str> {
        if let Some(cached) = self.compiled_js.get() {
            return Ok(cached);
        }
        let engine = akivili_iepl::IeplEngine::new();
        let transpiled = engine
            .transpile(&self.code)
            .map_err(|e| anyhow!("TS transpilation failed: {}", e))?;
        let _ = self.compiled_js.set(transpiled.js_code);
        Ok(self.compiled_js.get().expect("compiled js just set"))
    }
}

pub(crate) struct TsPlugin {
    context: boa_engine::Context,
    plugin_name: String,
    host_api: Arc<HostFunctions>,
    log_buffer: Arc<Mutex<String>>,
}

impl TsPlugin {
    pub(crate) fn create_and_load(
        host_api: Arc<HostFunctions>,
        data: &TsPluginData,
    ) -> Result<Self> {
        let mut plugin = Self::new_inner(host_api, &data.plugin_name)?;
        plugin.load_script(data)?;
        Ok(plugin)
    }

    fn new_inner(host_api: Arc<HostFunctions>, plugin_name: &str) -> Result<Self> {
        let mut context = boa_engine::Context::default();

        context.set_runtime_limits({
            let mut limits = boa_engine::vm::RuntimeLimits::default();
            limits.set_loop_iteration_limit(1_000_000);
            limits.set_recursion_limit(256);
            limits.set_stack_size_limit(1024);
            limits
        });

        let log_buffer = Arc::new(Mutex::new(String::new()));
        let logger = BufferedLogger {
            buffer: log_buffer.clone(),
        };
        Console::register_with_logger(logger, &mut context)
            .map_err(|e| anyhow!("failed to register console: {}", e))?;

        context
            .register_global_property(
                JsString::from("__plugin_state"),
                JsValue::from(js_string!("{}")),
                Attribute::WRITABLE | Attribute::CONFIGURABLE,
            )
            .map_err(|e| anyhow!("failed to register __plugin_state: {}", e))?;

        context
            .register_global_callable(
                js_string!("__plugin_dispatch"),
                3,
                boa_engine::NativeFunction::from_fn_ptr(native_dispatch_wrapper),
            )
            .map_err(|e| anyhow!("failed to register dispatch callable: {}", e))?;

        Ok(Self {
            context,
            plugin_name: plugin_name.to_string(),
            host_api,
            log_buffer,
        })
    }

    fn load_script(&mut self, data: &TsPluginData) -> Result<()> {
        set_dispatch(&self.host_api, &self.plugin_name);

        self.context
            .eval(Source::from_bytes(PLUGIN_BOILERPLATE))
            .map_err(|e| {
                clear_dispatch();
                anyhow!("plugin boilerplate eval failed: {}", e)
            })?;

        self.context
            .eval(Source::from_bytes(INIT_TOOL_REG))
            .map_err(|e| {
                clear_dispatch();
                anyhow!("tool registration init failed: {}", e)
            })?;

        let js_code = match &data.language {
            TsLanguage::TypeScript => {
                let js = data.transpiled_js().inspect_err(|_| clear_dispatch())?;
                Self::validate_js(js).inspect_err(|_| clear_dispatch())?;
                js.to_string()
            }
            TsLanguage::JavaScript => {
                Self::validate_js(&data.code).inspect_err(|_| clear_dispatch())?;
                data.code.clone()
            }
        };

        let result = self.eval_with_timeout(&js_code);
        clear_dispatch();
        result?;

        info!(plugin = %self.plugin_name, "TS plugin script loaded");
        Ok(())
    }

    /// Runs the AST security validator on JavaScript (raw for JS plugins,
    /// post-transpile output for TS plugins so swc lowering cannot smuggle
    /// forbidden constructs into the emitted code). Rejects on any violation.
    fn validate_js(code: &str) -> Result<()> {
        match akivili_iepl::ast_validator::validate_js_ast(code) {
            Ok(violations) if violations.is_empty() => Ok(()),
            Ok(violations) => {
                let details: Vec<String> = violations
                    .iter()
                    .map(|v| {
                        format!(
                            "[{}] {} (line {}, col {})",
                            v.kind, v.message, v.line, v.column
                        )
                    })
                    .collect();
                Err(anyhow!(
                    "plugin code rejected by AST security validation:\n{}",
                    details.join("\n")
                ))
            }
            Err(e) => Err(anyhow!("plugin code failed security validation: {}", e)),
        }
    }

    pub fn handle_request(
        &mut self,
        method: &str,
        path: &str,
        headers: &str,
        body: &str,
    ) -> Result<String> {
        if let Ok(mut buf) = self.log_buffer.lock() {
            buf.clear();
        }

        let handler_code = format!(
            r#"
(typeof globalThis.handleRequest === 'function')
    ? globalThis.handleRequest({}, {}, {}, {})
    : {{"error": "handleRequest not defined"}}
"#,
            serde_json::to_string(method).unwrap_or_else(|_| "\"\"".to_string()),
            serde_json::to_string(path).unwrap_or_else(|_| "\"\"".to_string()),
            serde_json::to_string(headers).unwrap_or_else(|_| "\"\"".to_string()),
            serde_json::to_string(body).unwrap_or_else(|_| "\"\"".to_string()),
        );

        set_dispatch(&self.host_api, &self.plugin_name);
        let result = self.eval_with_timeout(&handler_code);
        clear_dispatch();
        result
    }

    pub fn on_message(&mut self, platform: &str, message: &str) -> Result<Option<String>> {
        if let Ok(mut buf) = self.log_buffer.lock() {
            buf.clear();
        }

        let handler_code = format!(
            r#"
(typeof globalThis.onMessage === 'function')
    ? globalThis.onMessage({}, {})
    : null
"#,
            serde_json::to_string(platform).unwrap_or_else(|_| "\"\"".to_string()),
            serde_json::to_string(message).unwrap_or_else(|_| "\"\"".to_string()),
        );

        set_dispatch(&self.host_api, &self.plugin_name);
        let result = self.eval_with_timeout(&handler_code);
        clear_dispatch();
        let result = result?;
        if result.is_empty() || result == "null" || result == "undefined" {
            Ok(None)
        } else {
            Ok(Some(result))
        }
    }

    pub fn take_mcp_tools(&self) -> Vec<RegisteredMcpTool> {
        self.host_api.mcp_tools_for_plugin(&self.plugin_name)
    }

    fn eval_with_timeout(&mut self, code: &str) -> Result<String> {
        let result = self
            .context
            .eval(Source::from_bytes(code))
            .map_err(|e| anyhow!("JS eval error: {}", e))?;

        let resolved = if Self::is_promise(&result) {
            self.resolve_promise(&result)?
        } else {
            result
        };

        let mut output = self
            .log_buffer
            .lock()
            .map(|buf| buf.clone())
            .unwrap_or_default();

        if !resolved.is_undefined() {
            let display = match resolved.variant() {
                boa_engine::value::JsVariant::String(s) => s.to_std_string_escaped(),
                _ => resolved.display().to_string(),
            };
            if !output.is_empty() {
                output.push('\n');
            }
            output.push_str(&display);
        }

        Ok(output)
    }

    fn is_promise(value: &JsValue) -> bool {
        value.as_object().is_some_and(|obj| obj.is::<Promise>())
    }

    fn resolve_promise(&mut self, promise_value: &JsValue) -> Result<JsValue> {
        use boa_engine::builtins::promise::PromiseState;

        let Some(obj) = promise_value.as_object() else {
            return Ok(promise_value.clone());
        };
        let Ok(promise) = JsPromise::from_object(obj.clone()) else {
            return Ok(promise_value.clone());
        };

        let start = Instant::now();

        loop {
            let state: PromiseState = promise.state();
            match state {
                PromiseState::Pending => {}
                PromiseState::Fulfilled(v) => return Ok(v),
                PromiseState::Rejected(r) => {
                    return Err(anyhow!("promise rejected: {}", r.display()));
                }
            }

            if start.elapsed() >= COMPUTE_TIMEOUT {
                return Err(anyhow!("promise timeout after {:?}", COMPUTE_TIMEOUT));
            }

            if self.context.run_jobs().is_err() {
                let state2: PromiseState = promise.state();
                if !matches!(state2, PromiseState::Pending) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(1));
            }

            if start.elapsed() >= ABSOLUTE_CEILING {
                return Err(anyhow!(
                    "absolute ceiling exceeded after {:?}",
                    start.elapsed()
                ));
            }
        }

        let final_state: PromiseState = promise.state();
        match final_state {
            PromiseState::Fulfilled(v) => Ok(v),
            PromiseState::Rejected(r) => Err(anyhow!("promise rejected: {}", r.display())),
            _ => Err(anyhow!("promise timed out")),
        }
    }
}

impl Drop for TsPlugin {
    fn drop(&mut self) {
        clear_dispatch();
    }
}

fn set_dispatch(api: &Arc<HostFunctions>, plugin_name: &str) {
    CURRENT_HOST_API.with(|cell| {
        *cell.borrow_mut() = Some((api.clone(), plugin_name.to_string()));
    });
}

fn clear_dispatch() {
    CURRENT_HOST_API.with(|cell| {
        *cell.borrow_mut() = None;
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Context;
    use anyhow::{Error, Result};

    fn make_host_api() -> Arc<HostFunctions> {
        Arc::new(HostFunctions::new())
    }

    #[test]
    fn load_and_handle_request() -> Result<()> {
        let rt = tokio::runtime::Runtime::new()?;
        rt.block_on(async {
            let host_api = make_host_api();
            let data = TsPluginData::new(
                "test-plugin",
                r#"
var handleRequest = function(method, path, headers, body) {
    return JSON.stringify({ method: method, path: path, status: "ok" });
};
"#,
                TsLanguage::JavaScript,
            );
            let result = tokio::task::spawn_blocking(move || {
                let mut plugin = TsPlugin::create_and_load(host_api, &data)?;
                plugin.handle_request("POST", "/test", "{}", "{}")
            })
            .await??;
            let parsed: serde_json::Value = serde_json::from_str(&result)?;
            assert_eq!(parsed["method"], "POST");
            assert_eq!(parsed["path"], "/test");
            assert_eq!(parsed["status"], "ok");
            Ok::<(), Error>(())
        })?;
        Ok(())
    }

    #[test]
    fn ts_transpile_is_cached() -> Result<()> {
        let rt = tokio::runtime::Runtime::new()?;
        rt.block_on(async {
            let host_api = make_host_api();
            let data = TsPluginData::new(
                "cached-ts-plugin",
                r#"
const greeting: string = "hello";
function build(): string {
    return greeting;
}
build();
"#,
                TsLanguage::TypeScript,
            );
            let cloned = data.clone();
            tokio::task::spawn_blocking(move || {
                let plugin = TsPlugin::create_and_load(host_api, &cloned)?;
                drop(plugin);
                Ok::<_, Error>(())
            })
            .await??;
            assert!(
                data.compiled_js.get().is_some(),
                "transpile should be cached"
            );
            Ok::<(), Error>(())
        })?;
        Ok(())
    }

    #[test]
    fn dispatch_log() -> Result<()> {
        let rt = tokio::runtime::Runtime::new()?;
        rt.block_on(async {
            let host_api = make_host_api();
            let data = TsPluginData::new(
                "log-plugin",
                r#"
var handleRequest = function(method, path, headers, body) {
    dispatch("log", { level: "info", message: "hello from plugin" });
    return JSON.stringify({ logged: true });
};
"#,
                TsLanguage::JavaScript,
            );
            let result = tokio::task::spawn_blocking(move || {
                let mut plugin = TsPlugin::create_and_load(host_api, &data)?;
                plugin.handle_request("POST", "/test", "{}", "{}")
            })
            .await??;
            let parsed: serde_json::Value = serde_json::from_str(&result)?;
            assert_eq!(parsed["logged"], true);
            Ok::<(), Error>(())
        })?;
        Ok(())
    }

    #[test]
    fn dispatch_kv_roundtrip() -> Result<()> {
        let rt = tokio::runtime::Runtime::new()?;
        rt.block_on(async {
            let host_api = make_host_api();
            let data = TsPluginData::new(
                "kv-plugin",
                r#"
var handleRequest = function(method, path, headers, body) {
    dispatch("kv-set", { key: "k1", value: "v1" });
    var result = dispatch("kv-get", { key: "k1" });
    return JSON.stringify(result);
};
"#,
                TsLanguage::JavaScript,
            );
            let result = tokio::task::spawn_blocking(move || {
                let mut plugin = TsPlugin::create_and_load(host_api, &data)?;
                plugin.handle_request("POST", "/test", "{}", "{}")
            })
            .await??;
            let parsed: serde_json::Value = serde_json::from_str(&result)?;
            assert_eq!(parsed["success"], true);
            assert_eq!(parsed["value"], "v1");
            Ok::<(), Error>(())
        })?;
        Ok(())
    }

    #[test]
    fn register_mcp_tool() -> Result<()> {
        let rt = tokio::runtime::Runtime::new()?;
        rt.block_on(async {
            let host_api = make_host_api();
            let host_api_clone = host_api.clone();
            let data = TsPluginData::new(
                "tool-plugin",
                r#"
registerMcpTool("my_tool", "A test tool", '{"type":"object"}');
var handleRequest = function(m,p,h,b) {
    return JSON.stringify({ registered: true });
};
"#,
                TsLanguage::JavaScript,
            );
            let result = tokio::task::spawn_blocking(move || {
                let mut plugin = TsPlugin::create_and_load(host_api, &data)?;
                let response = plugin.handle_request("POST", "/test", "{}", "{}")?;
                let tools = plugin.take_mcp_tools();
                Ok::<_, Error>((response, tools))
            })
            .await??;
            let parsed: serde_json::Value = serde_json::from_str(&result.0)?;
            assert_eq!(parsed["registered"], true);
            assert_eq!(result.1.len(), 1);
            assert_eq!(result.1[0].tool_name, "my_tool");
            assert_eq!(result.1[0].description, "A test tool");
            let all = host_api_clone.all_mcp_tools();
            assert_eq!(all.len(), 1);
            assert_eq!(all[0].0, "tool-plugin");
            Ok::<(), Error>(())
        })?;
        Ok(())
    }

    #[test]
    fn handle_request_not_defined() -> Result<()> {
        let rt = tokio::runtime::Runtime::new()?;
        rt.block_on(async {
            let host_api = make_host_api();
            let data = TsPluginData::new("empty", r#"var x = 42;"#, TsLanguage::JavaScript);
            let result = tokio::task::spawn_blocking(move || {
                let mut plugin = TsPlugin::create_and_load(host_api, &data)?;
                plugin.handle_request("POST", "/test", "{}", "{}")
            })
            .await??;
            assert!(result.contains("handleRequest not defined"));
            Ok::<(), Error>(())
        })?;
        Ok(())
    }

    #[test]
    fn syntax_error_fails_load() -> Result<()> {
        let rt = tokio::runtime::Runtime::new()?;
        rt.block_on(async {
            let host_api = make_host_api();
            let data = TsPluginData::new("bad", r#"function foo( { "#, TsLanguage::JavaScript);
            let is_err = tokio::task::spawn_blocking(move || {
                TsPlugin::create_and_load(host_api, &data).is_err()
            })
            .await?;
            assert!(is_err);
            Ok::<(), Error>(())
        })?;
        Ok(())
    }

    #[test]
    fn js_plugin_with_eval_fails_load() -> Result<()> {
        let rt = tokio::runtime::Runtime::new()?;
        rt.block_on(async {
            let host_api = make_host_api();
            let data = TsPluginData::new(
                "evil",
                r#"var handleRequest = function() { return eval("1"); };"#,
                TsLanguage::JavaScript,
            );
            let err_msg = tokio::task::spawn_blocking(move || {
                match TsPlugin::create_and_load(host_api, &data) {
                    Ok(_) => None,
                    Err(e) => Some(e.to_string()),
                }
            })
            .await?;
            let err_msg = err_msg.expect("plugin with eval() should have been rejected");
            assert!(
                err_msg.contains("AST security validation"),
                "got: {}",
                err_msg
            );
            Ok::<(), Error>(())
        })?;
        Ok(())
    }

    #[test]
    fn on_message_handler() -> Result<()> {
        let rt = tokio::runtime::Runtime::new()?;
        rt.block_on(async {
            let host_api = make_host_api();
            let data = TsPluginData::new(
                "bot-plugin",
                r#"
var onMessage = function(platform, message) {
    return JSON.stringify({ platform: platform, echo: message });
};
"#,
                TsLanguage::JavaScript,
            );
            let result = tokio::task::spawn_blocking(move || {
                let mut plugin = TsPlugin::create_and_load(host_api, &data)?;
                plugin.on_message("discord", "hello")
            })
            .await??;
            assert!(result.is_some());
            let parsed: serde_json::Value =
                serde_json::from_str(&result.context("no message returned")?)?;
            assert_eq!(parsed["platform"], "discord");
            assert_eq!(parsed["echo"], "hello");
            Ok::<(), Error>(())
        })?;
        Ok(())
    }
}
