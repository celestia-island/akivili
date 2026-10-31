//! Host ports — the small trait surface the plugin host borrows from its runtime.
//!
//! Deliberately plana-free: this crate ships on crates.io while the platform
//! crates it used to import (`plana_infra_utils::pubsub::PubSubBus`,
//! `plana_domain_skills::llm_subcall::LlmSubcallService`,
//! `plana_state_sync::ModelTier`) live on an unpublished git line. The
//! running host adapts its own services over these ports instead, so the
//! host crate keeps zero git dependencies and stays publishable.

use std::future::Future;
use std::pin::Pin;

use serde_json::Value;

/// Boxed future used by the port traits (dyn-compatible method returns).
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Model tier for sub-call routing; mirrors the platform tier vocabulary
/// (`Deep` / `Normal` / `Basic`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ModelTier {
    Deep,
    Normal,
    #[default]
    Basic,
}

/// Outcome of one LLM sub-call, mirroring the platform result fields the
/// host actually consumes.
#[derive(Debug, Clone)]
pub struct LlmReply {
    /// Whether the call succeeded.
    pub success: bool,
    /// Reply text (or the failure message when `success` is false).
    pub content: String,
}

/// Event-bus port: forward one plugin event onto the host bus.
pub trait PluginEventBus: Send + Sync {
    /// Publish `payload` on `topic`. Failure semantics belong to the host;
    /// the port has no error channel because forwarding is best-effort.
    fn publish<'a>(&'a self, topic: &'a str, payload: Value) -> BoxFuture<'a, ()>;
}

/// LLM sub-call port: what the host needs from an LLM-backed runtime.
pub trait PluginLlmService: Send + Sync {
    /// Run one sub-call at `tier`. `system_prompt`, `max_tokens` and
    /// `temperature` are optional host hints.
    fn llm_chat<'a>(
        &'a self,
        tier: ModelTier,
        prompt: &'a str,
        system_prompt: Option<&'a str>,
        max_tokens: Option<u32>,
        temperature: Option<f32>,
    ) -> BoxFuture<'a, LlmReply>;
}

/// Topic pattern a plugin subscription matches against (exact, `*` or `#`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TriggerPattern(String);

impl TriggerPattern {
    /// Wrap one pattern string.
    #[must_use]
    pub fn new(pattern: &str) -> Self {
        Self(pattern.to_string())
    }

    /// The wrapped pattern.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether this pattern is one of the wildcard sentinels.
    #[must_use]
    pub fn is_wildcard(&self) -> bool {
        self.0 == "*" || self.0 == "#"
    }
}

impl std::fmt::Display for TriggerPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// One plugin-declared trigger subscription, forwarded to the host dispatcher.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TriggerSubscription {
    /// Plugin (skill) name the subscription belongs to.
    pub skill_name: String,
    /// Agent type the subscription rides (plugins always use `plugin`).
    pub agent_type: String,
    /// Topic pattern to match.
    pub topic_pattern: TriggerPattern,
}
