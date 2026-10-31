//! `akivili` — the one-line dependency for the celestia-island plugin SDK.
//!
//! This crate is a facade: it re-exports the SDK's crates behind features so
//! a consumer opts into exactly the weight they need (the D9 weight
//! discipline — the default build pulls in the registry alone, never the SWC
//! transpiler or the network stack).
//!
//! | feature | module | what you get |
//! |---|---|---|
//! | `registry` (default) | [`registry`] | plugin discovery, manifests, host feeding, append-only audit |
//! | `guard` | [`guard`] | egress URL/IP policy enforcement with DNS-rebinding-safe resolution |
//! | `ptc` | [`ptc`] | sandboxed TypeScript → JavaScript execution pipeline (SWC transpile + AST safety validation) |
//! | `full` | all of the above | the whole SDK in one feature |
//!
//! ```toml
//! [dependencies]
//! akivili = "0.2"                          # registry only
//! akivili = { version = "0.2", features = ["full"] }   # everything
//! ```
//!
//! The dependent crates ([`akivili-plugin-host`], [`akivili-wasm-host`] and
//! [`akivili-loader`]) are not facaded here yet — they are still git-line
//! consumers of unpublished upstream crates and land on crates.io later.
//!
//! [`akivili-plugin-host`]: https://crates.io/crates/akivili-plugin-host
//! [`akivili-wasm-host`]: https://crates.io/crates/akivili-wasm-host
//! [`akivili-loader`]: https://crates.io/crates/akivili-loader

// ── registry (default) ──────────────────────────────────────────────────────
#[cfg(feature = "registry")]
pub use akivili_registry as registry;

// ── guard ───────────────────────────────────────────────────────────────────
#[cfg(feature = "guard")]
pub use akivili_guard as guard;

// ── ptc ─────────────────────────────────────────────────────────────────────
#[cfg(feature = "ptc")]
pub use akivili_ptc as ptc;

/// The SDK version, matching every published `akivili-*` crate.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
