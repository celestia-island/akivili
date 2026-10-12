//! Per-plugin capability grants (audit akivili-R1-1).
//!
//! The manifest's `capabilities` list is the only source of authority
//! for a plugin's host-tool calls: [`dispatch_host_fn`] consults the
//! [`GrantSet`] at its single entry point and refuses anything the
//! manifest does not declare. The set starts EMPTY (deny everything
//! except the always-granted `log` tool) — hosts feed the manifest's
//! list via [`HostFunctions::with_grants`].
//!
//! Parameterized capabilities match on `word:param` exactly:
//! `http.egress:api.github.com` covers outbound calls to that host
//! only; `mesh.subscribe:telemetry.usage` covers subscriptions to that
//! topic pattern.

use std::collections::BTreeSet;
use std::sync::OnceLock;

use akivili_registry::capabilities::{
    CAP_CONFIG_READ, CAP_EVENT_FORWARD, CAP_HTTP_EGRESS, CAP_KV_READ, CAP_KV_WRITE,
    CAP_MCP_REGISTER, CAP_MESH_SUBSCRIBE, CAP_TOOL_REGISTER, Capability,
};
use serde_json::Value;

/// Tool names mapped to the capability words that authorize them.
/// Parameterized tools take their parameter from the request params.
const TOOL_GRANTS: &[(&str, &str)] = &[
    ("http-request", CAP_HTTP_EGRESS),
    ("forward-event", CAP_EVENT_FORWARD),
    ("kv-get", CAP_KV_READ),
    ("kv-set", CAP_KV_WRITE),
    ("config-get", CAP_CONFIG_READ),
    ("register-tool", CAP_TOOL_REGISTER),
    ("register-mcp-tool", CAP_MCP_REGISTER),
    ("subscribe-trigger", CAP_MESH_SUBSCRIBE),
];

/// The declared capability set for one plugin, built from the
/// manifest's `capabilities` list (already vocabulary-validated by
/// [`Capability::new`] at parse time).
#[derive(Debug, Clone, Default)]
pub struct GrantSet {
    words: OnceLock<BTreeSet<String>>,
    raw: Vec<String>,
}

impl GrantSet {
    /// An empty set — deny everything except the always-granted tools.
    pub fn empty() -> Self {
        Self {
            words: OnceLock::new(),
            raw: Vec::new(),
        }
    }

    /// Build from the manifest's declared capability strings (raw
    /// `word` / `word:param` spellings).
    pub fn from_manifest(capabilities: &[Capability]) -> Self {
        Self {
            words: OnceLock::new(),
            raw: capabilities
                .iter()
                .map(|c| c.as_str().to_string())
                .collect(),
        }
    }

    /// Build from raw capability spellings (word / `word:param`) — the
    /// test-facing constructor; production callers go through
    /// [`Self::from_manifest`] with already-validated words.
    pub fn from_raw_words(words: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            words: OnceLock::new(),
            raw: words.into_iter().map(Into::into).collect(),
        }
    }

    /// The base-word set, built lazily (the grant set is shared behind
    /// an Arc; the index is built once on first check).
    fn words(&self) -> &BTreeSet<String> {
        self.words
            .get_or_init(|| self.raw.iter().cloned().collect())
    }

    /// Whether a capability `word:param` (or bare `word`) is granted.
    fn grants_word_param(&self, word: &str, param: Option<&str>) -> bool {
        match param {
            Some(p) => self.raw.iter().any(|c| {
                c == &format!("{word}:{p}")
                    // A bare `word` grant (no parameter) covers every
                    // parameterized use of that word.
                    || (c == word && !c.contains(':'))
            }),
            None => self.words().contains(word),
        }
    }

    /// Arbitrate one `dispatch(tool, params)` call.
    ///
    /// Returns `None` when the call is granted; `Some(reason)` carries
    /// the denial reason for the plugin-facing error and the host trace.
    pub fn check_dispatch(&self, tool: &str, params: &Value) -> Option<String> {
        // Always granted: structured logging is the plugin's observation
        // channel (the vocabulary lists it "for clarity", not as a gate).
        if tool == "log" {
            return None;
        }
        // `env-get` reads only the environment injected for THIS
        // plugin's sandbox (per-sandbox by construction, not shared) —
        // no capability gate needed. Every other gated tool goes
        // through TOOL_GRANTS below (audit R1 must-fix ②: `config-get`
        // rode this exemption while the config map is instance-level
        // and shared across plugins).
        if tool == "env-get" {
            return None;
        }

        let Some(word) = TOOL_GRANTS
            .iter()
            .find(|(t, _)| *t == tool)
            .map(|(_, w)| *w)
        else {
            // Not a gated dispatch tool (e.g. `query-ai`, whose LLM
            // subcall has no capability word in the closed v1
            // vocabulary — a documented gap, tracked in the registry
            // vocabulary's versioning process).
            return None;
        };

        let http_host: Option<String> = if word == CAP_HTTP_EGRESS {
            params["url"].as_str().and_then(host_of)
        } else {
            None
        };
        let param: Option<&str> = match word {
            CAP_HTTP_EGRESS => http_host.as_deref(),
            CAP_MESH_SUBSCRIBE => params["topicPattern"]
                .as_str()
                .or_else(|| params["topic_pattern"].as_str()),
            _ => None,
        };
        if !self.grants_word_param(word, param) {
            return Some(match param {
                Some(p) => format!("missing capability `{word}:{p}`"),
                None => format!("missing capability `{word}`"),
            });
        }
        None
    }
}

/// Extract the host from a URL string (audit R1 must-fix ①).
///
/// Parsed with the same WHATWG `url` crate the network guard uses — a
/// hand-rolled split diverges on backslashes (WHATWG treats `\\` as a
/// path separator for special schemes) and userinfo forms, and a
/// parser mismatch here becomes a parameterized-egress bypass
/// (`https://evil.com\\@api.github.com/` resolves to host `evil.com`).
fn host_of(url: &str) -> Option<String> {
    let host = url::Url::parse(url).ok()?.host_str()?.to_string();
    Some(host).filter(|h| !h.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn grants(list: &[&str]) -> GrantSet {
        let raw: Vec<String> = list.iter().map(|s| s.to_string()).collect();
        GrantSet {
            words: OnceLock::new(),
            raw,
        }
    }

    #[test]
    fn empty_set_denies_gated_tools() {
        let g = GrantSet::empty();
        assert!(g.check_dispatch("kv-get", &json!({"key": "k"})).is_some());
        assert!(
            g.check_dispatch("http-request", &json!({"url": "https://api.github.com/x"}))
                .is_some()
        );
        assert!(
            g.check_dispatch("subscribe-trigger", &json!({"topicPattern": "t"}))
                .is_some()
        );
        // Always-granted / plugin-scoped tools pass the empty set.
        assert!(g.check_dispatch("log", &json!({"message": "hi"})).is_none());
        assert!(g.check_dispatch("env-get", &json!({"key": "k"})).is_none());
        // config-get is now gated with config.read (audit R1 must-fix ②).
        assert!(
            g.check_dispatch("config-get", &json!({"key": "k"}))
                .is_some()
        );
    }

    #[test]
    fn plain_word_grants_admit_their_tools() {
        let g = grants(&["kv.read", "kv.write", "event.forward"]);
        assert!(g.check_dispatch("kv-get", &json!({"key": "k"})).is_none());
        assert!(
            g.check_dispatch("kv-set", &json!({"key": "k", "value": "v"}))
                .is_none()
        );
        assert!(
            g.check_dispatch("forward-event", &json!({"event": "{}"}))
                .is_none()
        );
        // Unrelated gated tool still denied.
        assert!(
            g.check_dispatch("http-request", &json!({"url": "https://api.github.com/x"}))
                .is_some()
        );
    }

    #[test]
    fn egress_host_parameter_must_match() {
        let g = grants(&["http.egress:api.github.com"]);
        assert!(
            g.check_dispatch(
                "http-request",
                &json!({"url": "https://api.github.com/repos/x"})
            )
            .is_none()
        );
        let denial = g
            .check_dispatch(
                "http-request",
                &json!({"url": "https://evil.example.com/x"}),
            )
            .expect("a different host must be denied");
        assert!(
            denial.contains("http.egress:evil.example.com"),
            "the denial must name the requested host: {denial}"
        );
        // Userinfo on a DIFFERENT host must not satisfy the grant.
        assert!(
            g.check_dispatch(
                "http-request",
                &json!({"url": "https://evil@api.example.com/x"})
            )
            .is_some()
        );
    }

    #[test]
    fn bare_word_grant_covers_parameterized_use() {
        let g = grants(&["http.egress"]);
        assert!(
            g.check_dispatch(
                "http-request",
                &json!({"url": "https://any.host.example/x"})
            )
            .is_none()
        );
    }

    #[test]
    fn subscribe_topic_pattern_must_match() {
        let g = grants(&["mesh.subscribe:telemetry.usage"]);
        assert!(
            g.check_dispatch(
                "subscribe-trigger",
                &json!({"topicPattern": "telemetry.usage"})
            )
            .is_none()
        );
        assert!(
            g.check_dispatch(
                "subscribe-trigger",
                &json!({"topic_pattern": "telemetry.other"})
            )
            .is_some()
        );
    }
}
