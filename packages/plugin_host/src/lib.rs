//! Agent plugin host — IEPL TypeScript runtime + tool router.
//!
//! Extracted from entelecheia `packages/shared/plugin_host` (PLAN.md §11).
//! Replaces the former WASM-based plugin system. Agent packages are composed
//! of IEPL TypeScript tool definitions, skill prompts, and optional binary
//! backends. This crate provides:
//!
//! - [`TsPlugin`]: Executes IEPL TypeScript tool code in the Boa JS sandbox.
//! - [`PluginRouter`]: Central registry that dispatches MCP tool calls to
//!   the correct agent package by tool name.
//! - [`PluginState`]: Host API surface exposed to TS tools.
//! - [`SandboxEnvFeed`]: Feeds sandbox environment variables from the plugin
//!   registry ([`akivili_registry`]) into the plugin sandboxes.
#![allow(clippy::type_complexity)]

pub use akivili_guard as guard;
pub mod plugin_router;
pub mod plugin_state;
pub mod sandbox_env;
pub mod ts_plugin;

pub use plugin_router::PluginRouter;
pub use plugin_state::{
    HostApiProvider, HostFunctions, RegisteredMcpTool, TriggerDispatcherHolder,
};
pub use sandbox_env::SandboxEnvFeed;
