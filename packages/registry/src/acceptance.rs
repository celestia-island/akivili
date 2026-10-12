use serde::{Deserialize, Serialize};

use crate::kinds::ResourceKind;
use crate::manifest::Surface;

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

/// A host runtime's declaration of which manifest ATTACHMENTS it accepts
/// (the `[[attachments]]` analogue of [`HostAcceptance`], fed through
/// [`Registry::feed_attachments`](crate::Registry::feed_attachments)).
///
/// `surfaces` is the primary filter (a host serves whole surfaces — the
/// engine host, the webui host, an edge node). `kinds` optionally narrows
/// within the accepted surfaces: when non-empty, only attachments that
/// DECLARE a matching kind are fed (an attachment with no kind cannot
/// match a kind filter — narrowing means "only these", not "these and
/// the undeclared").
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AttachmentAcceptance {
    /// Identifies the declaring host runtime (lands in `fed` audit events).
    pub host_id: String,
    /// The surfaces this host serves.
    pub surfaces: Vec<Surface>,
    /// Optional kind narrowing within the accepted surfaces (empty = all).
    #[serde(default)]
    pub kinds: Vec<ResourceKind>,
}

impl AttachmentAcceptance {
    /// Builds an acceptance for `host_id` serving exactly `surfaces`.
    pub fn new(host_id: impl Into<String>, surfaces: Vec<Surface>) -> Self {
        Self {
            host_id: host_id.into(),
            surfaces,
            kinds: Vec::new(),
        }
    }

    /// Narrows the acceptance to attachments declaring one of `kinds`.
    pub fn with_kinds(mut self, kinds: Vec<ResourceKind>) -> Self {
        self.kinds = kinds;
        self
    }

    /// Whether an attachment with this surface (and optional declared
    /// kind) is accepted by this host.
    pub fn accepts(&self, surface: &Surface, kind: Option<&ResourceKind>) -> bool {
        if !self.surfaces.contains(surface) {
            return false;
        }
        if self.kinds.is_empty() {
            return true;
        }
        kind.map(|kind| self.kinds.contains(kind)).unwrap_or(false)
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

    #[test]
    fn attachment_acceptance_filters_by_surface_then_kind() {
        let acceptance = AttachmentAcceptance::new("scepter-engine", vec![Surface::Engine]);
        assert!(acceptance.accepts(&Surface::Engine, None));
        assert!(!acceptance.accepts(&Surface::Webui, None));
        assert!(!acceptance.accepts(&Surface::Edge, None));

        // Kind narrowing: only declared kinds match; a kind-less
        // attachment cannot pass a kind filter.
        let agent = ResourceKind::new("engine.agent").unwrap();
        let narrowed = acceptance.with_kinds(vec![agent.clone()]);
        assert!(narrowed.accepts(&Surface::Engine, Some(&agent)));
        assert!(!narrowed.accepts(&Surface::Engine, None));
        assert!(!narrowed.accepts(
            &Surface::Engine,
            Some(&ResourceKind::new("engine.tool").unwrap())
        ));
        // Narrowing never widens the surface set.
        assert!(!narrowed.accepts(&Surface::Edge, Some(&agent)));
    }

    #[test]
    fn attachment_acceptance_round_trips_through_json() {
        let acceptance = AttachmentAcceptance::new("edge-node", vec![Surface::Edge])
            .with_kinds(vec![ResourceKind::new("edge.deploy").unwrap()]);
        let json = serde_json::to_string(&acceptance).unwrap();
        let back: AttachmentAcceptance = serde_json::from_str(&json).unwrap();
        assert_eq!(back, acceptance);
    }
}
