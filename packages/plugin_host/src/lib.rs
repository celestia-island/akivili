//! Agent plugin host — Boa TypeScript plugin runtime.
//!
//! This crate is the standalone home of the plugin host extracted from
//! entelecheia `packages/shared/plugin_host` (PLAN.md §11). The TS plugin
//! runtime, plugin router and host state will land here in the migration
//! wave; the workspace skeleton is bootstrapped first.

pub fn placeholder() -> &'static str {
    "akivili-plugin-host"
}
