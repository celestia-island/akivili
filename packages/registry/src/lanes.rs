//! Capability lanes — named subsets of the closed vocabulary that a
//! host's admission surface can enforce (Celestia Plugin Fabric C3).
//!
//! The closed vocabulary (v1) is the WHOLE fabric's surface; a **lane**
//! is what a particular admission context allows. The protocol lane
//! (evernight #288's adjudication) admits `state.*` words only — an
//! external protocol plugin declaring `http.egress` passes the global
//! vocabulary check but must die at the LANE gate, before anything
//! loads. Lanes live in the registry (the vocabulary's authority
//! crate) so every consumer validates identically.

use crate::error::{RegistryError, RegistryResult};

use super::Capability;

/// A named lane: which base words the admission context allows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lane {
    name: &'static str,
    allowed: &'static [&'static str],
}

impl Lane {
    /// The protocol lane (evernight's builtin/external protocol
    /// plugins): read/write state only — network egress and mesh words
    /// belong to other lanes.
    pub const fn state_lane() -> Self {
        Self {
            name: "state",
            allowed: &["state.read", "state.write"],
        }
    }

    /// The lane's name (diagnostics).
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// Whether one capability's base word is lane-legal.
    pub fn admits(&self, capability: &Capability) -> bool {
        self.allowed.contains(&capability.base())
    }

    /// Validate a whole capability list against the lane — the first
    /// violation names the plugin and the word (loud, actionable).
    pub fn validate(&self, plugin_id: &str, capabilities: &[Capability]) -> RegistryResult<()> {
        for capability in capabilities {
            if !self.admits(capability) {
                return Err(RegistryError::InvalidManifest(format!(
                    "plugin '{plugin_id}' declares '{}' outside the {} lane (allowed: {})",
                    capability.as_str(),
                    self.name,
                    self.allowed.join(", ")
                )));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_state_lane_admits_its_words_and_rejects_others() {
        let lane = Lane::state_lane();
        for word in ["state.read", "state.write"] {
            assert!(lane.admits(&Capability::new(word).unwrap()), "{word}");
        }
        for word in ["log", "kv.read", "http.egress:example.com", "mesh.call:peer"] {
            assert!(!lane.admits(&Capability::new(word).unwrap()), "{word}");
        }
    }

    #[test]
    fn validation_names_the_plugin_and_the_word() {
        let lane = Lane::state_lane();
        let caps = ["state.read", "http.egress:evil.example"]
            .iter()
            .map(|w| Capability::new(w).unwrap())
            .collect::<Vec<_>>();
        let err = lane.validate("some-plugin", &caps).unwrap_err();
        let message = err.to_string();
        assert!(message.contains("some-plugin"), "{message}");
        assert!(message.contains("http.egress:evil.example"), "{message}");
        assert!(message.contains("state lane"), "{message}");
    }

    #[test]
    fn an_empty_list_is_trivially_valid() {
        assert!(Lane::state_lane().validate("p", &[]).is_ok());
    }
}
