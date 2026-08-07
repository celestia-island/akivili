//! Egress network guard extracted from entelecheia `shared/adapter`.
//!
//! Enforces a URL allow-list policy on plugin HTTP requests
//! ([`NetworkGuard`]) with a shared error surface ([`AdapterError`]).

pub mod error;
pub mod network_guard;

pub use error::{AdapterError, AdapterResult};
pub use network_guard::{NetworkGuard, NetworkGuardPolicy};
