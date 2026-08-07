# akivili 架构 — 插件宿主与 TS 执行管线

## 1. 背景

插件 SDK 从 entelecheia 独立（PLAN.md §11，2026-08-07 立项）。entelecheia 保留
`.amphoreus/` 作为 agent 定义与插件代码的载体，akivili 提供插件装载与执行设施。

## 2. 插件契约

### 2.1 生效契约：TS 全局 API（实际执行）

插件源码通过 `globalThis` 导出三个函数：

```ts
function name(): string;                       // 插件名
function handleRequest(method, path, headers, body): string;  // webhook 处理
function onMessage(platform, message): string | null;         // bot 消息处理
```

宿主注入的全局能力（与遗留 WIT `host-api` 一一对应）：

| 全局函数 | 能力 |
|---|---|
| `dispatch(toolName, paramsJson)` | 调用宿主工具（log / http-request / query-ai / kv-* …） |
| `registerMcpTool(name, desc, schema)` | 注册 MCP 工具到宿主命名空间 |
| `__plugin_state` | 插件状态访问 |

### 2.2 遗留 WIT 契约（`wit/plugin.wit`）

WASM 时代的历史规格（world `amphoreus`：import `host-api`，export `webhook-handler`
与 `bot-handler`）。当前宿主是 TS 引擎，WIT 作为契约文档保留，代码中零引用。

## 3. 执行管线

```
plugin.ts ──► IeplEngine.transpile() (SWC TS→JS + AST 安全校验)
           ──► Boa Context (RuntimeLimits: 1M loop / 256 recursion / 1024 stack)
           ──► thread_local CURRENT_HOST_API ──► dispatch_host_fn ──► HostFunctions
```

- 引擎：boa_engine ^0.21；资源上限经 `RuntimeLimits` 强制。
- Promise 轮询：`context.run_jobs()`，120s 超时 / 600s 绝对上限（同步阻塞）。
- 注意：每次 dispatch 都重建 Boa 上下文（性能模型待优化，见 PLAN §11.3 阶段 5）。

## 4. 插件注册与分发链路

```
scepter PluginRouter (宿主装配)
   ├─ load_ts_plugin / scan_and_load_dir(PLUGIN_DIR)   注册
   ├─ scan_amphoreus_agents(.amphoreus)                .amphoreus/<agent>/plugin.ts 注册（scepter 启动激活）
   ├─ dispatch_webhook → HTTP POST /webhook/{name} → Boa handleRequest
   ├─ dispatch_bot_message → TriggerDispatcher → onMessage
   └─ all_mcp_tools → cosmos McpRouter 命名空间工具（未命中回退 webhook）
```

agent.toml 清单与预检审计在 plana `plana_custom_agent`（git 依赖引用），
akivili 只消费其 schema，不重复实现。

## 5. 订阅机制（社区 Layer3 agents）

`.amphoreus/subscribe.toml`：从 `official` / `github` 源订阅 Layer3 agents，
声明 `version` 约束、`trusted_sources`、`verify_signature`。

**已知缺口**：`verify_signature` / `trusted_sources` 当前仅解析未实施
（纸面安全）；akivili 独立后在 SDK 内实施真实签名验证（PLAN §11.3 阶段 5）。
