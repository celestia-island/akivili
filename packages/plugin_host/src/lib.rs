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
#![allow(clippy::type_complexity)]

pub mod guard;
pub mod plugin_router;
pub mod plugin_state;
pub mod ts_plugin;

pub use plugin_router::PluginRouter;
pub use plugin_state::{
    HostApiProvider, HostFunctions, RegisteredMcpTool, TriggerDispatcherHolder,
};
