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
//! - **Path-confined** — file payloads are only ever read from inside the
//!   owning plugin's own directory: absolute paths, `..` walks, and
//!   symlink escapes are rejected at scan time and re-checked at
//!   feed/load time (see [`store::scan`]).
//! - **Size-capped** — every file payload is read under a configurable
//!   per-payload size cap
//!   ([`RegistryOptions::max_payload_bytes`], 8 MiB by default): an
//!   oversized payload rejects its plugin at scan time (the measured
//!   size lands in the `rejected` audit event) and fails loud at
//!   feed/load if it grew past the cap afterwards; the read itself is
//!   bounded, so a runaway payload can never dominate host memory.
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
//! The host's whole startup, in three steps — open, feed an acceptance,
//! then load each fed item and unload it when done:
//!
//! ```
//! use std::fs;
//! use akivili_registry::{HostAcceptance, Registry, ResourceKind};
//!
//! // A plugin store: one subdirectory per plugin, manifest inside.
//! let dir = tempfile::tempdir().unwrap();
//! let plugin = dir.path().join("acmestyle");
//! fs::create_dir_all(&plugin).unwrap();
//! fs::write(
//!     plugin.join("akivili.plugin.toml"),
//!     r#"
//! id = "acmestyle"
//! version = "1.0.0"
//! provider = "acme"
//!
//! [[resources]]
//! kind = "webui.style"
//! order = 1
//!
//! [resources.payload.Inline]
//! body = "serif"
//! "#,
//! )
//! .unwrap();
//!
//! // 1) open: scan the store and start the audit log (fail-loud).
//! let registry = Registry::open(dir.path(), &dir.path().join("audit.jsonl")).unwrap();
//! // 2) feed the host's acceptance: an ordered, resolved resource series.
//! let feed = registry
//!     .feed(&HostAcceptance::new(
//!         "webui",
//!         vec![ResourceKind::new("webui.style").unwrap()],
//!     ))
//!     .unwrap();
//! // 3) load each fed item, apply it, then unload.
//! for item in feed.iter() {
//!     let handle = registry.load(&item.plugin_id, item.entry_index).unwrap();
//!     // ... apply the resource in the host ...
//!     handle.unload().unwrap();
//! }
//! assert_eq!(feed.len(), 1);
//! ```
//!
//! The v1 API is synchronous (`std::fs`) on purpose: the IO volume is tiny
//! and avoiding tokio keeps the crate consumable from any runtime.

pub mod acceptance;
pub mod audit;
pub mod capabilities;
pub mod cli;
pub mod error;
pub mod feed;
pub mod forms;
pub mod handle;
pub mod kinds;
pub mod lanes;
pub mod manifest;
pub mod registry;
pub mod store;

pub use acceptance::{HostAcceptance, KindFilter};
pub use audit::{AuditEvent, AuditLog};
pub use capabilities::{Capability, VOCABULARY_V1};
pub use error::{RegistryError, RegistryResult};
pub use feed::{FeedItem, ResolvedPayload, ResourceFeed};
pub use forms::FormKind;
pub use handle::{LocalRegistration, ResourceHandle};
pub use kinds::ResourceKind;
pub use manifest::{
    ContractRef, MinTrust, Payload, PluginManifest, ResourceEntry, SCHEMA_V1, SCHEMA_V2,
    TrustSection,
};
pub use registry::{DEFAULT_MAX_PAYLOAD_BYTES, Registry, RegistryOptions};
pub use store::{PluginRecord, Rejection, ScanResult};
