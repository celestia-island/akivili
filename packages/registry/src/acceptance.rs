use serde::{Deserialize, Serialize};

use crate::kinds::ResourceKind;

/// A host runtime's declaration of what plugin resources it accepts.
///
/// Feeding ([`crate::Registry::feed`]) filters store plugins against this:
/// an entry is fed only when its kind is listed here (and the plugin is
/// enabled). `constraints` are v1-recordal — they are kept and audited for
/// forward compatibility, but no semantic enforcement happens yet.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HostAcceptance {
    /// Identifies the declaring host runtime (lands in `fed` audit events).
    pub host_id: String,
    /// The kinds this host accepts.
    pub kinds: Vec<KindFilter>,
}

/// One accepted kind, plus optional recordal constraints.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KindFilter {
    /// The kind this filter accepts.
    pub kind: ResourceKind,
    /// v1: informational only (e.g. `{"names": ["dark"]}`), not enforced.
    #[serde(default)]
    pub constraints: Option<serde_json::Value>,
}

impl HostAcceptance {
    /// Builds an acceptance for `host_id` accepting exactly `kinds`.
    pub fn new(host_id: impl Into<String>, kinds: Vec<ResourceKind>) -> Self {
        Self {
            host_id: host_id.into(),
            kinds: kinds
                .into_iter()
                .map(|kind| KindFilter {
                    kind,
                    constraints: None,
                })
                .collect(),
        }
    }

    /// Whether `kind` is accepted by this host.
    pub fn accepts(&self, kind: &ResourceKind) -> bool {
        self.kinds.iter().any(|filter| &filter.kind == kind)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acceptance_filters_by_kind() {
        let acceptance = HostAcceptance::new(
            "webui",
            vec![
                ResourceKind::new(crate::kinds::WEBUI_STYLE).unwrap(),
                ResourceKind::new(crate::kinds::WEBUI_THEME).unwrap(),
            ],
        );
        assert_eq!(acceptance.host_id, "webui");
        assert!(acceptance.accepts(&ResourceKind::new("webui.style").unwrap()));
        assert!(acceptance.accepts(&ResourceKind::new("webui.theme").unwrap()));
        assert!(!acceptance.accepts(&ResourceKind::new("sandbox.env").unwrap()));
        assert!(!acceptance.accepts(&ResourceKind::new("tool.mcp").unwrap()));
    }

    #[test]
    fn round_trips_through_json_with_constraints() {
        let acceptance = HostAcceptance {
            host_id: "sandbox".into(),
            kinds: vec![KindFilter {
                kind: ResourceKind::new(crate::kinds::SANDBOX_ENV).unwrap(),
                constraints: Some(serde_json::json!({ "allow_prefix": "AKIVILI_" })),
            }],
        };
        let json = serde_json::to_string(&acceptance).unwrap();
        let back: HostAcceptance = serde_json::from_str(&json).unwrap();
        assert_eq!(back, acceptance);
        assert_eq!(
            back.kinds[0].constraints.as_ref().unwrap()["allow_prefix"],
            "AKIVILI_"
        );
    }
}
