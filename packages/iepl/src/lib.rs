//! Sandboxed TypeScript→JavaScript transpilation engine for agent-authored scripts.
//!
//! Agents in the entelecheia system author automation logic in a restricted dialect of
//! TypeScript. This crate is responsible for converting that code into safe, runnable
//! JavaScript. It wraps [SWC](https://swc.rs) (the Rust-based JS/TS compiler) for
//! high-performance transpilation and adds a mandatory AST-level security validation pass.
//!
//! The design is centred on two concerns:
//! 1. **Transpilation** ([`IeplEngine`]) — strips TypeScript type annotations and downlevels
//!    modern syntax to a target JavaScript version suitable for embedding.
//! 2. **Security** ([`validate_ast`]) — walks the parsed AST to reject forbidden constructs
//!    (dynamic code execution, dangerous globals, etc.) before any code is emitted.
//!
//! The engine is intentionally *stateless* and synchronous — it consumes a source string
//! and returns a [`TranspileResult`] — so it can be embedded inside a sandboxed executor
//! without holding mutable state across calls.
#![allow(clippy::type_complexity)]

pub mod ast_validator;
pub mod engine;
pub mod security_constants;

pub use ast_validator::{AstViolation, validate_ast};
pub use engine::{IeplEngine, TranspileResult};
