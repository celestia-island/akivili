use serde::{Deserialize, Serialize, de::Deserializer};

use crate::error::{RegistryError, RegistryResult};

/// Well-known resource kind: a webui stylesheet.
pub const WEBUI_STYLE: &str = "webui.style";
/// Well-known resource kind: a webui theme token bundle.
pub const WEBUI_THEME: &str = "webui.theme";
/// Well-known resource kind: a webui runtime module.
pub const WEBUI_MODULE: &str = "webui.module";
/// Well-known resource kind: environment variables injected into a sandbox.
pub const SANDBOX_ENV: &str = "sandbox.env";
/// Well-known resource kind: an MCP tool registration.
pub const TOOL_MCP: &str = "tool.mcp";
/// Well-known resource kind: a WASM component payload (plugin-fabric form F1).
pub const WASM_COMPONENT: &str = "wasm.component";
/// Well-known resource kind: a process-rpc plugin payload (form F2).
pub const PROCESS_RPC: &str = "process.rpc";
/// Well-known resource kind: a TypeScript script plugin payload (form F3).
pub const SCRIPT_TS: &str = "script.ts";
/// Well-known resource kind: a Vue3+TSX+SCSS webui module (form F4).
pub const WEB_VUE_MODULE: &str = "web.vue-module";

/// An open-set resource kind tag, e.g. `webui.style`.
///
/// The syntax is `^[a-z0-9-]+(\.[a-z0-9-]+)+$` — at least two dot-separated
/// segments of `[a-z0-9-]`. The set is deliberately open: services may
/// define their own kinds without touching this crate, while the well-known
/// constants ([`WEBUI_STYLE`] &c.) cover the launch set.
///
/// The validity invariant is enforced at construction: [`ResourceKind::new`]
/// validates, and deserialization routes through the same check, so a value
/// of this type is always syntactically valid.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ResourceKind(String);

impl ResourceKind {
    /// Validates `kind` against the kind syntax and returns the tag.
    pub fn new(kind: &str) -> RegistryResult<Self> {
        if is_valid_kind_syntax(kind) {
            Ok(Self(kind.to_string()))
        } else {
            Err(RegistryError::InvalidResourceKind(kind.to_string()))
        }
    }

    /// The kind as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Checks the `^[a-z0-9-]+(\.[a-z0-9-]+)+$` syntax without a regex engine.
fn is_valid_kind_syntax(kind: &str) -> bool {
    let mut segment_len = 0usize;
    let mut segment_count = 0usize;
    for ch in kind.chars() {
        match ch {
            '.' => {
                if segment_len == 0 {
                    return false; // empty segment (leading dot or "..")
                }
                segment_count += 1;
                segment_len = 0;
            }
            c if c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' => segment_len += 1,
            _ => return false,
        }
    }
    segment_count >= 1 && segment_len > 0 // at least 2 segments, none empty
}

impl std::fmt::Display for ResourceKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for ResourceKind {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ResourceKind {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        ResourceKind::new(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_well_formed_kinds() {
        for kind in [
            WEBUI_STYLE,
            WEBUI_THEME,
            WEBUI_MODULE,
            SANDBOX_ENV,
            TOOL_MCP,
            WASM_COMPONENT,
            PROCESS_RPC,
            SCRIPT_TS,
            WEB_VUE_MODULE,
        ] {
            let parsed = ResourceKind::new(kind).expect("well-known kinds must be valid");
            assert_eq!(parsed.as_str(), kind);
        }
        assert!(ResourceKind::new("a.b").is_ok());
        assert!(ResourceKind::new("webui.style.dark-accent").is_ok());
        assert!(ResourceKind::new("x-1.y-2").is_ok());
    }

    #[test]
    fn rejects_malformed_kinds() {
        // no dot, uppercase, empty segment, bad chars, empty, trailing dot
        for kind in [
            "webui",
            "Webui.Style",
            "webui..style",
            ".webui",
            "webui.",
            "",
        ] {
            assert!(
                ResourceKind::new(kind).is_err(),
                "kind '{kind}' must be rejected"
            );
        }
        assert!(ResourceKind::new("webui style").is_err());
        assert!(ResourceKind::new("webui.style\n").is_err());
    }

    #[test]
    fn deserialization_validates() {
        let value = serde_json::from_str::<ResourceKind>("\"webui.style\"").unwrap();
        assert_eq!(value.as_str(), "webui.style");
        assert!(serde_json::from_str::<ResourceKind>("\"webui\"").is_err());
    }

    #[test]
    fn serializes_transparently() {
        let kind = ResourceKind::new(WEBUI_THEME).unwrap();
        let json = serde_json::to_string(&kind).unwrap();
        assert_eq!(json, "\"webui.theme\"");
    }
}
