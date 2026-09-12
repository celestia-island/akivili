//! Plugin registry — the central facility for plugin resources.
//!
//! The registry unifies the scattered extension mechanisms behind one model:
//! host runtimes declare *what plugin resources they accept*
//! ([`HostAcceptance`]), plugin management lives in the registry
//! ([`Registry`]), and hosts are *fed* ([`ResourceFeed`]) a series of
//! resources at startup which they load one by one ([`ResourceHandle`]).
//!
//! The facility is discoverable, easily uninstallable, and auditable:
//!
//! - **Discoverable** — a plugin store is a plain root directory with one
//!   subdirectory per plugin (an `akivili.plugin.toml` manifest plus payload
//!   files); [`store::scan`] enumerates and validates it, and the
//!   `akivili-plugin list` / `check` CLI mirrors the same view for humans.
//! - **Easily uninstallable** — a plugin is fully described by its own
//!   subdirectory (delete it and the plugin is gone); the enable/disable
//!   switch lives in a `registry-state.json` next to the store root, never
//!   inside the plugin directory, so [`Registry::set_enabled`] never mutates
//!   plugin-owned files.
//! - **Auditable** — every discovery, validation, rejection, enable/disable
//!   toggle, fed item, load, and unload lands in an append-only JSONL audit
//!   log ([`audit::AuditLog`]); opening the log is fail-loud.
//!
//! Resources are decoupled from service targets: the same registry feeds
//! webui styles/themes/modules ([`kinds::WEBUI_STYLE`] &c.), sandbox
//! environment variables ([`kinds::SANDBOX_ENV`]), and MCP tool
//! registrations ([`kinds::TOOL_MCP`]).
//!
//! Two registration modes are supported:
//!
//! 1. **Store plugins** — discovered from disk, filtered through host
//!    acceptance, and loaded via [`Registry::feed`] + [`Registry::load`].
//! 2. **Runtime-local resources** — registered in-process (never touching
//!    the disk store) via [`Registry::register_local`], the analogue of the
//!    plugin host's `registerMcpTool` family.
//!
//! The v1 API is synchronous (`std::fs`) on purpose: the IO volume is tiny
//! and avoiding tokio keeps the crate consumable from any runtime.

pub mod acceptance;
pub mod audit;
pub mod cli;
pub mod error;
pub mod feed;
pub mod handle;
pub mod kinds;
pub mod manifest;
pub mod registry;
pub mod store;

pub use acceptance::{HostAcceptance, KindFilter};
pub use audit::{AuditEvent, AuditLog};
pub use error::{RegistryError, RegistryResult};
pub use feed::{FeedItem, ResolvedPayload, ResourceFeed};
pub use handle::{LocalRegistration, ResourceHandle};
pub use kinds::ResourceKind;
pub use manifest::{Payload, PluginManifest, ResourceEntry};
pub use registry::Registry;
pub use store::{PluginRecord, Rejection, ScanResult};
