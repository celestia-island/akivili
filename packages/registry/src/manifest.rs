use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::{RegistryError, RegistryResult};
use crate::kinds::ResourceKind;

/// The manifest file every plugin directory must contain.
pub const MANIFEST_FILE: &str = "akivili.plugin.toml";

/// A parsed plugin manifest (`akivili.plugin.toml`).
///
/// Field-level syntax (id, version, resource kinds) is checked by
/// [`PluginManifest::validate`]; structural completeness (fields present)
/// is enforced by deserialization itself — a manifest missing `id`,
/// `version`, or `provider` simply fails to parse.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PluginManifest {
    /// Plugin id, syntax `^[a-z0-9]+$`, unique within a store.
    pub id: String,
    /// Loose version: non-empty, dot-separated numeric segments (`1.0.3`).
    pub version: String,
    /// Who ships the plugin (free-form, e.g. an org or runtime id).
    pub provider: String,
    /// Optional human-readable description.
    #[serde(default)]
    pub description: Option<String>,
    /// The resources this plugin contributes.
    #[serde(default)]
    pub resources: Vec<ResourceEntry>,
}

/// One resource contributed by a plugin.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResourceEntry {
    /// What kind of resource this is (drives host acceptance filtering).
    pub kind: ResourceKind,
    /// Optional resource name, e.g. a theme name within `webui.theme`.
    #[serde(default)]
    pub name: Option<String>,
    /// Feed ordering hint: lower values are fed earlier. Ties are broken
    /// by plugin id, then by manifest position.
    #[serde(default)]
    pub order: i32,
    /// Where the resource content lives.
    pub payload: Payload,
}

/// The content of a resource entry.
///
/// Serialized with serde's default external enum tagging, so in TOML:
///
/// ```toml
/// [[resources]]
/// kind = "sandbox.env"
/// [resources.payload.Inline]
/// NO_PROXY = "127.0.0.1"
///
/// [[resources]]
/// kind = "webui.style"
/// [resources.payload.File]
/// path = "style.css"
/// sha256 = "…"
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Payload {
    /// Inlined JSON content (parsed from the manifest itself).
    Inline(serde_json::Value),
    /// A file inside the plugin directory (`path` is relative to it).
    File {
        path: PathBuf,
        /// Optional declared digest; when present it must match the file
        /// content at scan and feed time.
        sha256: Option<String>,
    },
}

impl PluginManifest {
    /// Validates id/version syntax after parsing.
    ///
    /// Kind syntax is already guaranteed by [`ResourceKind`]'s validating
    /// deserializer; file existence and digests are the store scanner's job
    /// (it knows the plugin directory).
    pub fn validate(&self) -> RegistryResult<()> {
        if !is_valid_id(&self.id) {
            return Err(RegistryError::InvalidManifest(format!(
                "id '{}' must match ^[a-z0-9]+$",
                self.id
            )));
        }
        if !is_valid_version(&self.version) {
            return Err(RegistryError::InvalidManifest(format!(
                "version '{}' must be non-empty dot-separated numeric segments",
                self.version
            )));
        }
        Ok(())
    }
}

/// Checks the `^[a-z0-9]+$` plugin id syntax.
fn is_valid_id(id: &str) -> bool {
    !id.is_empty()
        && id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
}

/// Loose version check: non-empty, every dot-separated segment a non-empty
/// digit run (e.g. `1`, `0.2.0`, `1.0.0-rc` is rejected — segments are
/// numeric only).
fn is_valid_version(version: &str) -> bool {
    !version.is_empty()
        && version
            .split('.')
            .all(|seg| !seg.is_empty() && seg.chars().all(|c| c.is_ascii_digit()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_full_manifest() {
        let raw = r##"
id = "acmetheme"
version = "0.2.1"
provider = "acme"
description = "Dark accent theme"

[[resources]]
kind = "webui.theme"
name = "dark-accent"
order = 10

[resources.payload.Inline]
primary = "#181825"

[[resources]]
kind = "webui.style"
order = 20

[resources.payload.File]
path = "style.css"
sha256 = "deadbeef"
"##;
        let manifest: PluginManifest = toml::from_str(raw).expect("manifest must parse");
        assert_eq!(manifest.id, "acmetheme");
        assert_eq!(manifest.version, "0.2.1");
        assert_eq!(manifest.provider, "acme");
        assert_eq!(manifest.description.as_deref(), Some("Dark accent theme"));
        assert_eq!(manifest.resources.len(), 2);

        let first = &manifest.resources[0];
        assert_eq!(first.kind.as_str(), "webui.theme");
        assert_eq!(first.name.as_deref(), Some("dark-accent"));
        assert_eq!(first.order, 10);
        match &first.payload {
            Payload::Inline(value) => assert_eq!(value["primary"], "#181825"),
            other => panic!("expected inline payload, got {other:?}"),
        }

        match &manifest.resources[1].payload {
            Payload::File { path, sha256 } => {
                assert_eq!(path, &PathBuf::from("style.css"));
                assert_eq!(sha256.as_deref(), Some("deadbeef"));
            }
            other => panic!("expected file payload, got {other:?}"),
        }

        manifest.validate().expect("manifest must validate");
    }

    #[test]
    fn missing_required_field_fails_to_parse() {
        let raw = r#"
id = "acmetheme"
version = "1.0"
"#;
        let err = toml::from_str::<PluginManifest>(raw).unwrap_err();
        assert!(err.to_string().contains("provider"), "got: {err}");
    }

    #[test]
    fn bad_kind_fails_to_parse() {
        let raw = r#"
id = "acme"
version = "1"
provider = "acme"
[[resources]]
kind = "WebUI"
[resources.payload.Inline]
value = 1
"#;
        assert!(toml::from_str::<PluginManifest>(raw).is_err());
    }

    #[test]
    fn validate_rejects_bad_ids_and_versions() {
        let mut manifest = PluginManifest {
            id: "Acme".into(),
            version: "1.0".into(),
            provider: "acme".into(),
            description: None,
            resources: Vec::new(),
        };
        assert!(manifest.validate().is_err());

        manifest.id = "acme".into();
        manifest.version = "1.0.0-rc.1".into();
        assert!(
            manifest.validate().is_err(),
            "non-numeric segment must fail"
        );

        manifest.version = "1".into();
        manifest.validate().expect("single numeric segment is fine");

        manifest.version = "1..0".into();
        assert!(manifest.validate().is_err());
    }
}
