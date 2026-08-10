//! Egress network guard extracted into a lightweight crate.
//!
//! Enforces a URL/IP policy on outbound HTTP requests ([`NetworkGuard`])
//! with DNS-rebinding-safe resolution: hostnames are resolved and every
//! answer validated against the policy before the connection is allowed
//! (connect-time pinning via [`reqwest::dns::Resolve`]).
//!
//! Deliberately dependency-light (url + thiserror + reqwest dns types) so
//! service crates can consume the hardened guard without pulling the Boa
//! plugin runtime into their build graph.

pub mod error;
pub mod network_guard;

pub use error::{AdapterError, AdapterResult};
pub use network_guard::{NetworkGuard, NetworkGuardPolicy};
