use std::path::PathBuf;

use serde::{Deserialize, Serialize, de::Deserializer};

use crate::capabilities::Capability;
use crate::error::{RegistryError, RegistryResult};
use crate::forms::FormKind;
use crate::kinds::ResourceKind;

/// The manifest file every plugin directory must contain.
pub const MANIFEST_FILE: &str = "akivili.plugin.toml";

/// The schema generation a manifest declares (schema 2 adds the
/// plugin-fabric fields: `form`, `capabilities`, `requires-contract`,
/// `[trust]`).
pub const SCHEMA_V1: u32 = 1;
/// The plugin-fabric schema generation (form, capabilities, contracts, trust).
pub const SCHEMA_V2: u32 = 2;

fn default_schema() -> u32 {
    SCHEMA_V1
}

/// A parsed plugin manifest (`akivili.plugin.toml`).
///
/// Field-level syntax (id, version, capability vocabulary, contract refs)
/// is checked by [`PluginManifest::validate`] (plus the validating
/// deserializers of the field types); structural completeness (fields
/// present) is enforced by deserialization itself — a manifest missing
/// `id`, `version`, or `provider` simply fails to parse.
///
/// Schema generations gate the field set:
///
/// - **schema 1** (the default) keeps the launch contract: the
///   plugin-fabric fields must be absent, ids are `^[a-z0-9]+$`, and
///   versions are loose dot-separated numerics.
/// - **schema 2** adds `form` (required), `capabilities`,
///   `requires-contract`, and `[trust]`; ids relax to
///   `^[a-z0-9][a-z0-9-]*$` and versions are SemVer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PluginManifest {
    /// Manifest schema generation: `1` (the default when absent) or `2`.
    #[serde(default = "default_schema")]
    pub schema: u32,
    /// Plugin id. Schema 1: `^[a-z0-9]+$`; schema 2: `^[a-z0-9][a-z0-9-]*$`.
    /// Unique within a store.
    pub id: String,
    /// Schema 1: loose dot-separated numeric segments. Schema 2: SemVer
    /// (`MAJOR.MINOR.PATCH` with optional prerelease/build metadata).
    pub version: String,
    /// Who ships the plugin (free-form, e.g. an org or runtime id).
    pub provider: String,
    /// Optional human-readable description.
    #[serde(default)]
    pub description: Option<String>,
    /// The plugin form — how hosts load and run it (schema 2 only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub form: Option<FormKind>,
    /// Declared capabilities from the closed v1 vocabulary (schema 2 only).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<Capability>,
    /// Required contract worlds, e.g. `celestia:panel/host@0.1`
    /// (schema 2 only).
    #[serde(
        rename = "requires-contract",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub requires_contract: Vec<ContractRef>,
    /// Trust expectations for distribution (schema 2 only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust: Option<TrustSection>,
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

/// The `[trust]` section of a schema 2 manifest: what the plugin expects
/// from the distribution channel.
///
/// Unknown keys are rejected (`deny_unknown_fields`): a typo like
/// `min_trust` must fail loud, not silently downgrade to the `unsigned`
/// default — trust metadata is exactly where silent fallbacks hurt.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct TrustSection {
    /// Path of the signature file inside the plugin directory (relative),
    /// e.g. `agent.sig` — the Ed25519 signature over the plugin payload.
    #[serde(default)]
    pub signature: Option<String>,
    /// The minimum trust level the host must grant the plugin's source.
    #[serde(default)]
    pub min_trust: MinTrust,
}

/// Minimum trust levels for plugin sources. Absent `min-trust` in a
/// schema 2 `[trust]` section means [`MinTrust::Unsigned`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MinTrust {
    /// No signature required (local dev plugins).
    #[default]
    Unsigned,
    /// Must carry a valid signature from a known publisher key.
    Signed,
    /// Must come from a verified publisher (signature plus allowlisted
    /// identity).
    VerifiedPublisher,
}

/// A contract world reference: `celestia:<domain>/<world>@<major>.<minor>`.
///
/// References the WIT world a plugin requires (e.g. `celestia:panel/host@0.1`)
/// — the host's loader matches these against the worlds it provides at
/// install time. Validity is enforced at construction, so a value of this
/// type is always well-formed.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ContractRef(String);

impl ContractRef {
    /// Validates `raw` as a contract reference and returns it.
    pub fn new(raw: &str) -> RegistryResult<Self> {
        if is_valid_contract_ref(raw) {
            Ok(Self(raw.to_string()))
        } else {
            Err(RegistryError::InvalidContractRef(raw.to_string()))
        }
    }

    /// The reference as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Checks the `celestia:<domain>/<world>@<major>.<minor>` shape.
fn is_valid_contract_ref(raw: &str) -> bool {
    let Some(rest) = raw.strip_prefix("celestia:") else {
        return false;
    };
    let Some((path, world_ver)) = rest.split_once('/') else {
        return false;
    };
    if path.is_empty() || !path.split('.').all(|seg| !seg.is_empty() && is_kebab(seg)) {
        return false;
    }
    let Some((world, ver)) = world_ver.split_once('@') else {
        return false;
    };
    is_kebab(world) && is_dotted_two_digit_version(ver)
}

/// `major.minor` with no leading zeros (a WIT world version).
fn is_dotted_two_digit_version(ver: &str) -> bool {
    let Some((major, minor)) = ver.split_once('.') else {
        return false;
    };
    is_numeric_identifier(major) && is_numeric_identifier(minor)
}

fn is_kebab(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

impl std::fmt::Display for ContractRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for ContractRef {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ContractRef {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        ContractRef::new(&s).map_err(serde::de::Error::custom)
    }
}

impl Default for PluginManifest {
    /// The v1 baseline: every non-essential field empty, schema 1.
    ///
    /// This exists so downstream constructors (chest's store ops, tests)
    /// can use struct-update syntax (`..PluginManifest::default()`) and
    /// stay source-compatible when this crate grows additive fields —
    /// a bare literal pins every field and breaks on each addition.
    /// A default is **not** a valid manifest: `validate()` rejects the
    /// empty id/version/provider.
    fn default() -> Self {
        Self {
            schema: SCHEMA_V1,
            id: String::new(),
            version: String::new(),
            provider: String::new(),
            description: None,
            form: None,
            capabilities: Vec::new(),
            requires_contract: Vec::new(),
            trust: None,
            resources: Vec::new(),
        }
    }
}

impl PluginManifest {
    /// Validates the manifest against its schema generation.
    ///
    /// Kind syntax is already guaranteed by [`ResourceKind`]'s validating
    /// deserializer, capability vocabulary by [`Capability`]'s, contract
    /// ref shape by [`ContractRef`]'s. What remains here is the
    /// schema-level gating (v1 must not carry v2 fields, v2 must carry a
    /// form) and id/version syntax per schema. File existence and digests
    /// are the store scanner's job (it knows the plugin directory).
    pub fn validate(&self) -> RegistryResult<()> {
        match self.schema {
            SCHEMA_V1 => {
                if !is_valid_id_v1(&self.id) {
                    return Err(RegistryError::InvalidManifest(format!(
                        "id '{}' must match ^[a-z0-9]+$",
                        self.id
                    )));
                }
                if !is_valid_version_v1(&self.version) {
                    return Err(RegistryError::InvalidManifest(format!(
                        "version '{}' must be non-empty dot-separated numeric segments",
                        self.version
                    )));
                }
                self.reject_v2_fields()?;
            }
            SCHEMA_V2 => {
                if !is_valid_id_v2(&self.id) {
                    return Err(RegistryError::InvalidManifest(format!(
                        "id '{}' must match ^[a-z0-9][a-z0-9-]*$",
                        self.id
                    )));
                }
                if !is_valid_semver(&self.version) {
                    return Err(RegistryError::InvalidManifest(format!(
                        "version '{}' must be SemVer (MAJOR.MINOR.PATCH with optional prerelease/build)",
                        self.version
                    )));
                }
                if self.form.is_none() {
                    return Err(RegistryError::InvalidManifest(
                        "schema 2 requires a 'form' field (wasm.component / process.rpc / script.ts / web.vue-module / web.resource)"
                            .to_string(),
                    ));
                }
            }
            other => {
                return Err(RegistryError::InvalidManifest(format!(
                    "unsupported schema version {other} (expected 1 or 2)"
                )));
            }
        }
        Ok(())
    }

    /// The declared form, defaulting to the v1-era meaning (`web.resource`)
    /// for schema 1 manifests.
    pub fn form_or_default(&self) -> FormKind {
        self.form.unwrap_or(FormKind::WebResource)
    }

    fn reject_v2_fields(&self) -> RegistryResult<()> {
        if self.form.is_some() {
            return Err(RegistryError::InvalidManifest(
                "field 'form' requires schema = 2".to_string(),
            ));
        }
        if !self.capabilities.is_empty() {
            return Err(RegistryError::InvalidManifest(
                "field 'capabilities' requires schema = 2".to_string(),
            ));
        }
        if !self.requires_contract.is_empty() {
            return Err(RegistryError::InvalidManifest(
                "field 'requires-contract' requires schema = 2".to_string(),
            ));
        }
        if self.trust.is_some() {
            return Err(RegistryError::InvalidManifest(
                "field 'trust' requires schema = 2".to_string(),
            ));
        }
        Ok(())
    }
}

/// Checks the `^[a-z0-9]+$` plugin id syntax (schema 1).
fn is_valid_id_v1(id: &str) -> bool {
    !id.is_empty()
        && id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
}

/// Checks the `^[a-z0-9][a-z0-9-]*$` plugin id syntax (schema 2).
fn is_valid_id_v2(id: &str) -> bool {
    let mut chars = id.chars();
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() || c.is_ascii_digit() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// Loose version check (schema 1): non-empty, every dot-separated segment
/// a non-empty digit run (e.g. `1`, `0.2.0`; `1.0.0-rc` is rejected —
/// segments are numeric only).
fn is_valid_version_v1(version: &str) -> bool {
    !version.is_empty()
        && version
            .split('.')
            .all(|seg| !seg.is_empty() && seg.chars().all(|c| c.is_ascii_digit()))
}

/// Checks a SemVer string (schema 2): `MAJOR.MINOR.PATCH` with optional
/// `-prerelease` and `+build` metadata, per semver.org (numeric core
/// identifiers without leading zeros; alphanumeric prerelease/build
/// dot-segments; only purely-numeric prerelease segments forbid leading
/// zeros).
fn is_valid_semver(version: &str) -> bool {
    let (core_pre, build) = match version.split_once('+') {
        Some((head, tail)) => (head, Some(tail)),
        None => (version, None),
    };
    let (core, pre) = match core_pre.split_once('-') {
        Some((head, tail)) => (head, Some(tail)),
        None => (core_pre, None),
    };
    let mut core_count = 0usize;
    for segment in core.split('.') {
        core_count += 1;
        if !is_numeric_identifier(segment) {
            return false;
        }
    }
    if core_count != 3 {
        return false;
    }
    if let Some(pre) = pre {
        let valid_seg = |seg: &str| {
            !seg.is_empty()
                && seg.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && (seg.bytes().any(|b| !b.is_ascii_digit()) || is_numeric_identifier(seg))
        };
        if !pre.split('.').all(valid_seg) {
            return false;
        }
    }
    if let Some(build) = build {
        let valid_seg = |seg: &str| {
            !seg.is_empty() && seg.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        };
        if !build.split('.').all(valid_seg) {
            return false;
        }
    }
    true
}

/// A numeric SemVer identifier: non-empty digits, no leading zeros (`0`
/// itself is fine).
fn is_numeric_identifier(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) && (s.len() == 1 || !s.starts_with('0'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v1_manifest() -> PluginManifest {
        PluginManifest {
            schema: SCHEMA_V1,
            id: "acme".into(),
            version: "1".into(),
            provider: "acme".into(),
            description: None,
            form: None,
            capabilities: Vec::new(),
            requires_contract: Vec::new(),
            trust: None,
            resources: Vec::new(),
        }
    }

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
        assert_eq!(manifest.schema, SCHEMA_V1);
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
        let mut manifest = v1_manifest();
        manifest.id = "Acme".into();
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

    #[test]
    fn parses_a_full_schema_2_manifest() {
        let raw = r##"
schema = 2
id = "celestia-kanban"
version = "1.2.0"
provider = "official"
description = "Kanban board panel"
form = "web.vue-module"
capabilities = [
  "kv.read",
  "kv.write",
  "http.egress:api.github.com",
  "db.contract:usage.read",
  "mesh.call:celestia-reports",
]
requires-contract = ["celestia:panel/host@0.1"]

[trust]
signature = "agent.sig"
min-trust = "verified-publisher"

[[resources]]
kind = "webui.module"
order = 1

[resources.payload.File]
path = "module.toml"
"##;
        let manifest: PluginManifest = toml::from_str(raw).expect("schema 2 must parse");
        assert_eq!(manifest.schema, SCHEMA_V2);
        assert_eq!(manifest.id, "celestia-kanban");
        assert_eq!(manifest.version, "1.2.0");
        assert_eq!(manifest.form, Some(FormKind::WebVueModule));
        assert_eq!(manifest.capabilities.len(), 5);
        assert_eq!(
            manifest.capabilities[4].as_str(),
            "mesh.call:celestia-reports"
        );
        assert_eq!(
            manifest.requires_contract[0].as_str(),
            "celestia:panel/host@0.1"
        );
        let trust = manifest.trust.as_ref().expect("trust section");
        assert_eq!(trust.signature.as_deref(), Some("agent.sig"));
        assert_eq!(trust.min_trust, MinTrust::VerifiedPublisher);
        manifest.validate().expect("schema 2 must validate");
        assert_eq!(manifest.form_or_default(), FormKind::WebVueModule);
    }

    #[test]
    fn schema_2_round_trips_through_toml() {
        let raw = r#"
schema = 2
id = "grid-engine"
version = "0.1.0-rc.1"
provider = "official"
form = "wasm.component"
capabilities = ["mesh.subscribe:telemetry.usage"]
requires-contract = ["celestia:panel/host@0.1", "celestia:kv/host@0.2"]
"#;
        let manifest: PluginManifest = toml::from_str(raw).unwrap();
        manifest.validate().unwrap();
        let text = toml::to_string(&manifest).unwrap();
        let back: PluginManifest = toml::from_str(&text).unwrap();
        assert_eq!(back, manifest);
        back.validate().unwrap();
    }

    #[test]
    fn v1_rejects_every_v2_field() {
        let mut manifest = v1_manifest();
        manifest.form = Some(FormKind::ScriptTs);
        let err = manifest.validate().unwrap_err();
        assert!(err.to_string().contains("form"), "got: {err}");

        manifest.form = None;
        manifest.capabilities = vec![Capability::new("kv.read").unwrap()];
        let err = manifest.validate().unwrap_err();
        assert!(err.to_string().contains("capabilities"), "got: {err}");

        manifest.capabilities = Vec::new();
        manifest.requires_contract = vec![ContractRef::new("celestia:panel/host@0.1").unwrap()];
        let err = manifest.validate().unwrap_err();
        assert!(err.to_string().contains("requires-contract"), "got: {err}");

        manifest.requires_contract = Vec::new();
        manifest.trust = Some(TrustSection {
            signature: None,
            min_trust: MinTrust::Unsigned,
        });
        let err = manifest.validate().unwrap_err();
        assert!(err.to_string().contains("trust"), "got: {err}");
    }

    #[test]
    fn unsupported_schema_generation_is_rejected() {
        let mut manifest = v1_manifest();
        manifest.schema = 3;
        let err = manifest.validate().unwrap_err();
        assert!(err.to_string().contains("schema version 3"), "got: {err}");
        manifest.schema = 0;
        assert!(manifest.validate().is_err());
    }

    #[test]
    fn schema_2_relaxes_the_id_rule() {
        let mut manifest = v1_manifest();
        manifest.schema = SCHEMA_V2;
        manifest.version = "1.0.0".into();
        manifest.form = Some(FormKind::WebResource);

        manifest.id = "celestia-kanban".into();
        manifest
            .validate()
            .expect("hyphenated ids are schema 2 syntax");

        manifest.id = "-leading".into();
        assert!(manifest.validate().is_err(), "must start alphanumeric");

        manifest.id = "Upper".into();
        assert!(manifest.validate().is_err(), "uppercase stays rejected");
    }

    #[test]
    fn schema_2_requires_semver() {
        let mut manifest = v1_manifest();
        manifest.schema = SCHEMA_V2;
        manifest.id = "acme".into();
        manifest.form = Some(FormKind::WebResource);

        for good in [
            "1.2.3",
            "0.1.0",
            "10.20.30",
            "1.2.3-rc.1",
            "1.2.3-rc.1+build.5",
            "1.2.3-alpha-beta",
            "1.2.3+20260101",
            "1.2.3-0",
            "1.2.3-rc.01x",
        ] {
            manifest.version = good.into();
            manifest
                .validate()
                .unwrap_or_else(|e| panic!("'{good}' is valid SemVer: {e}"));
        }
        for bad in [
            "1.2",
            "1.2.3.4",
            "01.2.3",
            "1.02.3",
            "1.2.03",
            "1.2.3-",
            "1.2.3+",
            "1.2.3-01",
            "1.2.3-rc..1",
            "v1.2.3",
            "1.2.3-rc.1+build..5",
            "",
        ] {
            manifest.version = bad.into();
            assert!(
                manifest.validate().is_err(),
                "'{bad}' must fail SemVer validation"
            );
        }
    }

    #[test]
    fn schema_2_requires_a_form() {
        let mut manifest = v1_manifest();
        manifest.schema = SCHEMA_V2;
        manifest.version = "1.0.0".into();
        let err = manifest.validate().unwrap_err();
        assert!(err.to_string().contains("form"), "got: {err}");
    }

    #[test]
    fn v1_default_form_is_web_resource() {
        let manifest = v1_manifest();
        assert_eq!(manifest.form_or_default(), FormKind::WebResource);
    }

    #[test]
    fn default_is_the_v1_baseline_and_is_not_a_valid_manifest() {
        // Downstream struct-update constructors rely on the default being
        // the v1 baseline; validate() must still reject it loudly.
        let default = PluginManifest::default();
        assert_eq!(default.schema, SCHEMA_V1);
        assert!(default.form.is_none());
        assert!(default.capabilities.is_empty());
        assert!(default.requires_contract.is_empty());
        assert!(default.trust.is_none());
        assert!(default.resources.is_empty());
        assert!(default.validate().is_err(), "default must not validate");
    }

    #[test]
    fn struct_update_syntax_stays_v1_compatible() {
        // The exact construction shape chest's store ops will use after
        // this PR: fill the six v1 fields, inherit the rest.
        let manifest = PluginManifest {
            id: "acme".into(),
            version: "1".into(),
            provider: "acme".into(),
            description: None,
            resources: Vec::new(),
            ..PluginManifest::default()
        };
        assert_eq!(manifest.schema, SCHEMA_V1);
        manifest.validate().expect("v1 semantics preserved");
    }

    #[test]
    fn trust_section_rejects_unknown_keys_instead_of_downgrading() {
        // `min_trust` (snake_case typo) must fail the parse rather than
        // silently fall back to the unsigned default — pinned after the
        // kebab rename initially let this slide through as Unsigned.
        let raw = r#"
schema = 2
id = "acme"
version = "1.0.0"
provider = "acme"
form = "script.ts"

[trust]
signature = "agent.sig"
min_trust = "verified-publisher"
"#;
        assert!(toml::from_str::<PluginManifest>(raw).is_err());
    }

    #[test]
    fn contract_refs_validate_shape() {
        for good in [
            // The canonical fabric world (wasm_host wit/host.wit).
            "celestia:host/guest@0.1",
            "celestia:panel/host@0.1",
            "celestia:kv/host@1.0",
            "celestia:mesh/plugin@0.2",
            "celestia:panel.extended/host@0.1",
        ] {
            ContractRef::new(good).unwrap_or_else(|e| panic!("{good}: {e}"));
        }
        for bad in [
            "panel/host@0.1",            // missing celestia: prefix
            "celestia:host@0.1",         // missing world
            "celestia:panel@0.1",        // missing / separator
            "celestia:panel/host",       // missing version
            "celestia:panel/host@0",     // version needs major.minor
            "celestia:panel/host@0.1.2", // versions are major.minor only
            "celestia:Panel/host@0.1",   // uppercase domain
            "celestia:panel/HOST@0.1",   // uppercase world
            "celestia:panel/host@0.1 ",  // trailing space
            "celestia:panel/",           // empty world
            "kei:panel/host@0.1",        // wrong namespace
        ] {
            assert!(
                ContractRef::new(bad).is_err(),
                "'{bad}' must be rejected as a contract ref"
            );
        }
    }

    #[test]
    fn malformed_capabilities_fail_at_parse_time() {
        let raw = r#"
schema = 2
id = "acme"
version = "1.0.0"
provider = "acme"
form = "script.ts"
capabilities = ["fs.read"]
"#;
        let err = toml::from_str::<PluginManifest>(raw).unwrap_err();
        assert!(err.to_string().contains("fs.read"), "got: {err}");
    }

    #[test]
    fn malformed_contract_refs_fail_at_parse_time() {
        let raw = r#"
schema = 2
id = "acme"
version = "1.0.0"
provider = "acme"
form = "script.ts"
requires-contract = ["panel/host@0.1"]
"#;
        let err = toml::from_str::<PluginManifest>(raw).unwrap_err();
        assert!(err.to_string().contains("panel/host@0.1"), "got: {err}");
    }

    #[test]
    fn malformed_form_fails_at_parse_time() {
        let raw = r#"
schema = 2
id = "acme"
version = "1.0.0"
provider = "acme"
form = "web.esmodule"
"#;
        assert!(toml::from_str::<PluginManifest>(raw).is_err());
    }
}
