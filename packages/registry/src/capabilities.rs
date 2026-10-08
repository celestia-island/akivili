use serde::{Deserialize, Serialize, de::Deserializer};

use crate::error::{RegistryError, RegistryResult};

/// Capability word: structured logging (always granted, listed for clarity).
pub const CAP_LOG: &str = "log";
/// Capability word: read plugin-scoped key/value state.
pub const CAP_KV_READ: &str = "kv.read";
/// Capability word: write plugin-scoped key/value state.
pub const CAP_KV_WRITE: &str = "kv.write";
/// Capability word: read the plugin's own configuration section.
pub const CAP_CONFIG_READ: &str = "config.read";
/// Capability word: outbound HTTP to one host (parameterized: `http.egress:api.github.com`).
pub const CAP_HTTP_EGRESS: &str = "http.egress";
/// Capability word: forward structured events to the host event bus.
pub const CAP_EVENT_FORWARD: &str = "event.forward";
/// Capability word: register tools in the host tool namespace.
pub const CAP_TOOL_REGISTER: &str = "tool.register";
/// Capability word: register MCP tools into the host MCP router.
pub const CAP_MCP_REGISTER: &str = "mcp.register";
/// Capability word: read host-managed plugin state.
pub const CAP_STATE_READ: &str = "state.read";
/// Capability word: write host-managed plugin state.
pub const CAP_STATE_WRITE: &str = "state.write";
/// Capability word: scoped data-contract query (parameterized: `db.contract:usage.read`).
pub const CAP_DB_CONTRACT: &str = "db.contract";
/// Capability word: typed domain query (parameterized: `db.query:usage`).
pub const CAP_DB_QUERY: &str = "db.query";
/// Capability word: validated SQL dialect channel (first-party plugins only).
pub const CAP_DB_SQL: &str = "db.sql";
/// Capability word: direct per-plugin database role (first-party plugins only).
pub const CAP_DB_DIRECT: &str = "db.direct";
/// Capability word: request/response to another plugin over the topology
/// network (parameterized: `mesh.call:celestia-kanban`).
pub const CAP_MESH_CALL: &str = "mesh.call";
/// Capability word: fire-and-forget send to another plugin (parameterized target).
pub const CAP_MESH_SEND: &str = "mesh.send";
/// Capability word: subscribe to a topology topic (parameterized: `mesh.subscribe:telemetry.usage`).
pub const CAP_MESH_SUBSCRIBE: &str = "mesh.subscribe";

/// A declared capability from the closed v1 vocabulary.
///
/// A capability is either a plain word (`kv.read`) or a word with one
/// colon-separated parameter (`http.egress:api.github.com`,
/// `db.contract:usage.read`, `mesh.subscribe:telemetry.usage`). The base
/// word must come from the closed vocabulary below — this set is
/// deliberately **not** open (unlike resource kinds): extending it is a
/// versioned vocabulary change, mirroring the evernight capability-profile
/// discipline.
///
/// Validity is enforced at construction ([`Capability::new`]) and
/// deserialization routes through the same check, so a value of this type
/// is always vocabulary-clean.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Capability(String);

impl Capability {
    /// Validates `raw` against the closed vocabulary and returns the word.
    pub fn new(raw: &str) -> RegistryResult<Self> {
        if is_valid_capability(raw) {
            Ok(Self(raw.to_string()))
        } else {
            Err(RegistryError::InvalidCapability(raw.to_string()))
        }
    }

    /// The capability as a string slice (word plus parameter, if any).
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The base word (everything before the first `:`).
    pub fn base(&self) -> &str {
        self.0.split(':').next().unwrap_or(&self.0)
    }

    /// The parameter, if the word takes one.
    pub fn param(&self) -> Option<&str> {
        self.0.split_once(':').map(|(_, p)| p)
    }
}

/// The closed v1 vocabulary: `(word, takes_parameter)`.
pub const VOCABULARY_V1: &[(&str, bool)] = &[
    (CAP_LOG, false),
    (CAP_KV_READ, false),
    (CAP_KV_WRITE, false),
    (CAP_CONFIG_READ, false),
    (CAP_HTTP_EGRESS, true),
    (CAP_EVENT_FORWARD, false),
    (CAP_TOOL_REGISTER, false),
    (CAP_MCP_REGISTER, false),
    (CAP_STATE_READ, false),
    (CAP_STATE_WRITE, false),
    (CAP_DB_CONTRACT, true),
    (CAP_DB_QUERY, true),
    (CAP_DB_SQL, false),
    (CAP_DB_DIRECT, false),
    (CAP_MESH_CALL, true),
    (CAP_MESH_SEND, true),
    (CAP_MESH_SUBSCRIBE, true),
];

/// Validates one capability word against the closed vocabulary.
fn is_valid_capability(raw: &str) -> bool {
    let Some((base, param)) = raw.split_once(':') else {
        // Plain word: must be a parameter-less vocabulary entry.
        return VOCABULARY_V1
            .iter()
            .any(|(word, takes_param)| !takes_param && word == &raw);
    };
    let takes_param = VOCABULARY_V1
        .iter()
        .any(|(word, takes_param)| *takes_param && *word == base);
    if !takes_param || param.is_empty() {
        return false;
    }
    match base {
        // One lowercase hostname (no scheme, path, or wildcard in v1).
        CAP_HTTP_EGRESS => is_host(param),
        // `<domain>.<op>` — two kebab segments.
        CAP_DB_CONTRACT => match param.split_once('.') {
            Some((domain, op)) => is_kebab(domain) && is_kebab(op),
            None => false,
        },
        // One kebab domain segment.
        CAP_DB_QUERY => is_kebab(param),
        // One plugin-id/service-name target.
        CAP_MESH_CALL | CAP_MESH_SEND => is_target(param),
        // Dotted kebab topic segments.
        CAP_MESH_SUBSCRIBE => {
            !param.is_empty() && param.split('.').all(|seg| !seg.is_empty() && is_kebab(seg))
        }
        _ => false,
    }
}

/// `[a-z0-9-]+` (non-empty; used for domains, ops, worlds, topics).
fn is_kebab(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// `[a-z0-9][a-z0-9-]*` — plugin ids and mesh targets (must start alnum).
fn is_target(s: &str) -> bool {
    let mut bytes = s.bytes();
    match bytes.next() {
        Some(b) if b.is_ascii_lowercase() || b.is_ascii_digit() => {}
        _ => return false,
    }
    bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// A lowercase hostname: `[a-z0-9.-]` (labels may not be empty).
fn is_host(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
        && !s.starts_with('.')
        && !s.ends_with('.')
        && !s.contains("..")
}

impl std::fmt::Display for Capability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for Capability {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Capability {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Capability::new(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_every_plain_vocabulary_word() {
        for (word, takes_param) in VOCABULARY_V1 {
            if !takes_param {
                let cap = Capability::new(word).expect("plain words must validate");
                assert_eq!(cap.param(), None);
            }
        }
    }

    #[test]
    fn accepts_parameterized_words() {
        for raw in [
            "http.egress:api.github.com",
            "http.egress:hf-mirror.com",
            "db.contract:usage.read",
            "db.contract:usage.write",
            "db.query:usage",
            "mesh.call:celestia-kanban",
            "mesh.send:node-1",
            "mesh.subscribe:telemetry.usage",
        ] {
            let cap = Capability::new(raw).unwrap_or_else(|e| panic!("{raw}: {e}"));
            assert!(cap.param().is_some(), "{raw} must keep its parameter");
        }
    }

    #[test]
    fn rejects_unknown_base_words() {
        for raw in [
            "fs.read",
            "shell.exec",
            "kv",
            "http.ingress",
            "mesh",
            "db",
            "log.fine",
        ] {
            assert!(
                Capability::new(raw).is_err(),
                "'{raw}' is outside the closed vocabulary and must be rejected"
            );
        }
    }

    #[test]
    fn rejects_malformed_parameters() {
        for raw in [
            "http.egress:",           // empty param
            "http.egress:GitHub.com", // uppercase host
            "http.egress:https://x",  // scheme smuggled in
            "http.egress:api.github.com/path",
            "http.egress:*",     // no wildcards in v1
            "db.contract:usage", // missing .op
            "db.contract:usage.read.extra",
            "db.contract:.read",
            "db.query:", // empty domain
            "mesh.call:-leading-hyphen",
            "mesh.subscribe:telemetry..usage",
            "mesh.subscribe:", // empty topic
            "log:extra",       // plain word with a smuggled param
        ] {
            assert!(Capability::new(raw).is_err(), "'{raw}' must be rejected");
        }
    }

    #[test]
    fn deserialization_validates() {
        let value = serde_json::from_str::<Capability>("\"mesh.call:celestia-kanban\"").unwrap();
        assert_eq!(value.as_str(), "mesh.call:celestia-kanban");
        assert!(serde_json::from_str::<Capability>("\"fs.read\"").is_err());
    }

    #[test]
    fn serializes_transparently() {
        let cap = Capability::new(CAP_KV_READ).unwrap();
        assert_eq!(serde_json::to_string(&cap).unwrap(), "\"kv.read\"");
    }
}
