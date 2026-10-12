use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize, de::Deserializer};

use crate::capabilities::Capability;
use crate::error::{RegistryError, RegistryResult};
use crate::forms::FormKind;
use crate::kinds::ResourceKind;

/// The manifest file every plugin directory must contain.
pub const MANIFEST_FILE: &str = "akivili.plugin.toml";

/// The schema generation this crate speaks. The value is **1** — the
/// pre-release iterations consolidated the former schema-1/schema-2 split
/// into a single generation (nothing was ever released, so no compat
/// burden exists). Unknown values are rejected loudly by
/// [`PluginManifest::validate`], making the field a forward-compatibility
/// tripwire: when a real schema 2 is needed some day, old hosts will
/// refuse new manifests instead of silently ignoring fields they do not
/// know.
pub const SCHEMA: u32 = 1;

fn default_schema() -> u32 {
    SCHEMA
}

/// A parsed plugin manifest (`akivili.plugin.toml`).
///
/// Field-level syntax (id, version, capability vocabulary, contract refs)
/// is checked by [`PluginManifest::validate`] (plus the validating
/// deserializers of the field types); structural completeness (fields
/// present) is enforced by deserialization itself — a manifest missing
/// `id`, `version`, or `provider` simply fails to parse.
///
/// The unified rules (schema 1): ids are `^[a-z0-9][a-z0-9-]*$`,
/// versions are SemVer, `form` is required, and the plugin-fabric
/// sections (`[upgrade]`, `[[migrations]]`, `[config]`, `[system]`,
/// `[title_i18n]`/`[description_i18n]`) are optional.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PluginManifest {
    /// Manifest schema generation. Must be `1`; any other value is
    /// rejected (the forward-compat tripwire).
    #[serde(default = "default_schema")]
    pub schema: u32,
    /// Plugin id, `^[a-z0-9][a-z0-9-]*$`. Unique within a store.
    pub id: String,
    /// SemVer (`MAJOR.MINOR.PATCH` with optional prerelease/build
    /// metadata, per semver.org).
    pub version: String,
    /// Who ships the plugin (free-form, e.g. an org or runtime id).
    pub provider: String,
    /// Optional human-readable description (the un-localized fallback).
    #[serde(default)]
    pub description: Option<String>,
    /// The plugin form — how hosts load and run it. Required.
    pub form: Option<FormKind>,
    /// Optional classification for host/UI purposes (e.g. `"system"` for
    /// host binaries). When present and `"system"`, `form` must be
    /// `system.host` (and vice versa).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub class: Option<String>,
    /// Target platforms this plugin declares (e.g. `["web", "desktop"]`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub platforms: Vec<String>,
    /// Localized titles keyed by locale tag (e.g. `"zh-Hans"` → `"看板"`).
    /// The un-localized `title` (if any) lives in the first
    /// `webui.page-type` resource's inline payload; this map carries the
    /// translations for host-side resolution.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub title_i18n: BTreeMap<String, String>,
    /// Localized descriptions keyed by locale tag.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub description_i18n: BTreeMap<String, String>,
    /// Declared capabilities from the closed vocabulary.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<Capability>,
    /// Required contract worlds, e.g. `celestia:panel/host@0.1`.
    #[serde(
        rename = "requires-contract",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub requires_contract: Vec<ContractRef>,
    /// Trust expectations for distribution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust: Option<TrustSection>,
    /// Upgrade-strategy declaration (rolling / hot / cold and parameters).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upgrade: Option<UpgradeSection>,
    /// Database migrations this plugin ships (executed by the host).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub migrations: Vec<MigrationEntry>,
    /// Plugin configuration file declaration (hifumi versioned).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<ConfigSection>,
    /// System-host declaration (only for `class = "system"` plugins).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system: Option<SystemSection>,
    /// The resources this plugin contributes.
    #[serde(default)]
    pub resources: Vec<ResourceEntry>,
    /// Additional surfaces this plugin attaches to beyond its primary
    /// `form` (at most one entry per surface; see [`AttachmentEntry`]).
    /// The primary `form` stays the upgrade-semantics anchor; attachments
    /// carry their own scoped declaration instead.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attachments: Vec<AttachmentEntry>,
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

/// The surface an `[[attachments]]` entry serves — the additional host
/// beyond the plugin's primary `form` (2026-10-12 ruling: one plugin may
/// attach to several surfaces simultaneously — an engine agent plus a
/// webui module plus an edge deployment).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Surface {
    /// The compute-engine host (scepter): backend agents and tools.
    Engine,
    /// The web-UI host (chest-webui): embedded pages and resources.
    Webui,
    /// Edge nodes, deployed over the evernight topology lane.
    Edge,
}

impl Surface {
    /// The wire spelling of the surface.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Engine => "engine",
            Self::Webui => "webui",
            Self::Edge => "edge",
        }
    }
}

impl std::fmt::Display for Surface {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One `[[attachments]]` entry: an additional surface this plugin serves
/// beyond its primary `form`.
///
/// The entry is attachment-scoped: `form` says how the TARGET surface's
/// host loads and runs it, `kind` names the resource kind it registers
/// as there (open vocabulary — `engine.agent`, `webui.page-type`,
/// `edge.deploy`, …), and `capabilities` must be a SUBSET of the
/// plugin-level grant — an attachment narrows, never widens.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct AttachmentEntry {
    /// Which surface this attachment serves (at most one per surface).
    pub surface: Surface,
    /// How the target surface's host loads and runs this attachment.
    /// `system.host` is refused — the host binary itself never attaches.
    pub form: FormKind,
    /// The resource kind this attachment registers as on its surface
    /// (open vocabulary, syntax-validated by [`ResourceKind`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<ResourceKind>,
    /// Optional name within the kind (mirrors [`ResourceEntry::name`],
    /// e.g. the page-type class or the agent folder).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Attachment-scoped capabilities — every word must also appear in
    /// the plugin-level `capabilities` (narrowing only).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<Capability>,
    /// Attachment-scoped contract requirements.
    #[serde(
        rename = "requires-contract",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub requires_contract: Vec<ContractRef>,
    /// Attachment-scoped upgrade declaration, validated against THIS
    /// attachment's own `form` (same form×mode matrix as the plugin
    /// level). Absent = the plugin-level `[upgrade]` governs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upgrade: Option<UpgradeSection>,
    /// Attachment payload — an inline descriptor or a file inside the
    /// plugin directory. The consuming surface defines the inner shape.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Payload>,
}

/// The `[trust]` section of a manifest: what the plugin expects
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
/// `[trust]` section means [`MinTrust::Unsigned`].
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

impl TrustSection {
    /// Whether this section demands a signature at all.
    #[must_use]
    pub fn requires_signature(&self) -> bool {
        self.signature.is_some() || self.min_trust != MinTrust::Unsigned
    }
}

/// The distribution trust verdict for one plugin (C4): what the scan
/// surface computes from the manifest's `[trust]` section and the
/// plugin directory's bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustVerdict {
    /// No signature demanded — local-dev lane.
    UnsignedOk,
    /// Demanded and delivered: the signature file exists and verifies
    /// over the plugin payload under the publisher key.
    SignedOk { key_id: String },
    /// Demanded but the directory carries no usable signature.
    UnsignedButDemanded,
    /// A signature file is present but fails verification.
    SignatureMismatch { reason: String },
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
    /// The baseline: every non-essential field empty, schema 1.
    ///
    /// This exists so downstream constructors (chest's store ops, tests)
    /// can use struct-update syntax (`..PluginManifest::default()`) and
    /// stay source-compatible when this crate grows additive fields —
    /// a bare literal pins every field and breaks on each addition.
    /// A default is **not** a valid manifest: `validate()` rejects the
    /// empty id/version/provider and the missing form.
    fn default() -> Self {
        Self {
            schema: SCHEMA,
            id: String::new(),
            version: String::new(),
            provider: String::new(),
            description: None,
            form: None,
            class: None,
            platforms: Vec::new(),
            title_i18n: BTreeMap::new(),
            description_i18n: BTreeMap::new(),
            capabilities: Vec::new(),
            requires_contract: Vec::new(),
            trust: None,
            upgrade: None,
            migrations: Vec::new(),
            config: None,
            system: None,
            resources: Vec::new(),
            attachments: Vec::new(),
        }
    }
}

impl PluginManifest {
    /// Validates the manifest against the unified schema.
    ///
    /// Kind syntax is already guaranteed by [`ResourceKind`]'s validating
    /// deserializer, capability vocabulary by [`Capability`]'s, contract
    /// ref shape by [`ContractRef`]'s. What remains here is the
    /// schema-level gate (only `1` is accepted), id/version syntax, the
    /// required `form`, and cross-field invariants (`class = "system"` ⇔
    /// `form = system.host`). File existence and digests are the store
    /// scanner's job (it knows the plugin directory).
    pub fn validate(&self) -> RegistryResult<()> {
        if self.schema != SCHEMA {
            return Err(RegistryError::InvalidManifest(format!(
                "unsupported schema version {} (this host speaks schema {SCHEMA})",
                self.schema
            )));
        }
        if !is_valid_id(&self.id) {
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
        let Some(form) = self.form else {
            return Err(RegistryError::InvalidManifest(
                "a 'form' field is required (wasm.component / process.rpc / script.ts / web.vue-module / web.resource / system.host)"
                    .to_string(),
            ));
        };
        // class ⇔ system.host is a bidirectional binding: a system-host
        // binary must identify itself as such, and nothing else may claim
        // the system class.
        let is_system_class = self.class.as_deref() == Some("system");
        if is_system_class != (form == FormKind::SystemHost) {
            return Err(RegistryError::InvalidManifest(format!(
                "class {:?} and form {:?} disagree: class = \"system\" ⇔ form = system.host",
                self.class, form
            )));
        }
        if let Some(upgrade) = &self.upgrade {
            upgrade.validate(&form)?;
        }
        // Attachments: the primary form stays the upgrade anchor; each
        // entry is a second surface with its own scoped declaration.
        if !self.attachments.is_empty() {
            // The host binary itself never attaches elsewhere.
            if form == FormKind::SystemHost {
                return Err(RegistryError::InvalidManifest(
                    "system.host manifests may not declare [[attachments]]".to_string(),
                ));
            }
            let mut seen: Vec<Surface> = Vec::new();
            for attachment in &self.attachments {
                if attachment.form == FormKind::SystemHost {
                    return Err(RegistryError::InvalidManifest(format!(
                        "attachment to surface '{}' may not use form system.host",
                        attachment.surface
                    )));
                }
                if seen.contains(&attachment.surface) {
                    return Err(RegistryError::InvalidManifest(format!(
                        "duplicate [[attachments]] surface '{}' (at most one per surface)",
                        attachment.surface
                    )));
                }
                seen.push(attachment.surface);
                // Capabilities narrow the plugin-level grant, never widen.
                for word in &attachment.capabilities {
                    if !self.capabilities.contains(word) {
                        return Err(RegistryError::InvalidManifest(format!(
                            "attachment to surface '{}' declares capability '{}' not granted at plugin level",
                            attachment.surface, word
                        )));
                    }
                }
                if let Some(upgrade) = &attachment.upgrade {
                    upgrade.validate(&attachment.form)?;
                }
            }
        }
        for migration in &self.migrations {
            migration.validate()?;
        }
        Ok(())
    }
}

/// Checks the `^[a-z0-9][a-z0-9-]*$` plugin id syntax.
fn is_valid_id(id: &str) -> bool {
    let mut chars = id.chars();
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() || c.is_ascii_digit() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// Checks a SemVer string: `MAJOR.MINOR.PATCH` with optional
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

// ── upgrade-strategy declaration ─────────────────────────────────────────

/// The `[upgrade]` section: how this plugin may be upgraded.
///
/// The three modes and their form constraints:
///
/// - **hot** — the host swaps the plugin in place (container instance
///   swap, script re-instantiation, or a webui resource re-fetch). No
///   process restart. Default for `wasm.component`, `script.ts`,
///   `web.vue-module` and `web.resource`.
/// - **rolling** — new instances serve before old ones drain (blue-green
///   across a fleet, or a self-handover for hosts that can run two
///   copies). Default for `process.rpc` when the host has ≥2 instances.
/// - **cold** — the node (or the whole host) must restart. Required for
///   `system.host` (except evernight's self-handover).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct UpgradeSection {
    /// The upgrade mode: `rolling` | `hot` | `cold`.
    pub mode: UpgradeMode,
    /// The concrete mechanism: `blue-green` | `self-handover` |
    /// `installer-rerun` | `cold-restart` | `in-app-updater`.
    #[serde(default = "default_upgrade_strategy")]
    pub strategy: UpgradeStrategy,
    /// Failure policy: `auto` (rollback on failure) or `manual`.
    #[serde(default = "default_rollback_policy")]
    pub rollback: RollbackPolicy,
    /// Rolling: the longest an old instance may keep serving before a
    /// forced stop (e.g. `"30s"`).
    #[serde(
        rename = "drain-timeout",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub drain_timeout: Option<String>,
    /// Rolling: how many new instances must be ready before traffic
    /// switches.
    #[serde(rename = "min-ready", default, skip_serializing_if = "Option::is_none")]
    pub min_ready: Option<u32>,
    /// Cold: restart automatically when the node is idle.
    #[serde(
        rename = "idle-restart",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub idle_restart: Option<bool>,
    /// Cold: the window during which a forced restart is permitted
    /// (e.g. `"02:00-04:00"`).
    #[serde(
        rename = "force-window",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub force_window: Option<String>,
    /// How many previous generations to keep for rollback (N-1 by
    /// default; reserved for future expansion).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generations: Option<u32>,
}

fn default_upgrade_strategy() -> UpgradeStrategy {
    UpgradeStrategy::ColdRestart
}

fn default_rollback_policy() -> RollbackPolicy {
    RollbackPolicy::Auto
}

impl UpgradeSection {
    /// Cross-field validation against the plugin's form.
    fn validate(&self, form: &FormKind) -> RegistryResult<()> {
        use UpgradeMode as M;
        use UpgradeStrategy as S;
        // system.host: only cold (with cold-restart) or rolling (with
        // self-handover) — never hot.
        if *form == FormKind::SystemHost {
            if self.mode == M::Hot {
                return Err(RegistryError::InvalidManifest(
                    "system.host may not declare upgrade mode 'hot'".to_string(),
                ));
            }
            if self.mode == M::Rolling && self.strategy != S::SelfHandover {
                return Err(RegistryError::InvalidManifest(
                    "system.host rolling upgrades must use strategy 'self-handover'".to_string(),
                ));
            }
        }
        // Rolling-specific fields on non-rolling modes: reject rather than
        // silently ignore (a manifest that says hot but carries
        // drain-timeout is confused).
        if self.mode != M::Rolling && (self.drain_timeout.is_some() || self.min_ready.is_some()) {
            return Err(RegistryError::InvalidManifest(format!(
                "upgrade fields 'drain-timeout'/'min-ready' are rolling-only; mode is {:?}",
                self.mode
            )));
        }
        // Cold requires at least one restart path.
        if self.mode == M::Cold
            && self.idle_restart.is_none()
            && self.force_window.is_none()
            && self.strategy != S::InstallerRerun
            && self.strategy != S::InAppUpdater
        {
            return Err(RegistryError::InvalidManifest(
                "cold upgrades must declare 'idle-restart' or 'force-window' (or use an installer/updater strategy)".to_string(),
            ));
        }
        Ok(())
    }
}

/// The upgrade mode: what the host must do to move to a new version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UpgradeMode {
    /// Blue-green rolling: new instances serve before old ones drain.
    Rolling,
    /// In-place swap: no process restart (container instance, script
    /// context, or webui resource).
    Hot,
    /// The node (or the whole host) must restart.
    Cold,
}

/// The concrete upgrade mechanism.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UpgradeStrategy {
    /// Blue-green across a fleet: green (new) instances come up, traffic
    /// switches, blue (old) instances drain and are retired.
    BlueGreen,
    /// The host runs two copies briefly: new and old handshake, the new
    /// one takes over, the old one exits (e.g. evernight's self-rolling).
    SelfHandover,
    /// An external installer (e.g. shun) replaces the payload while the
    /// application is not running.
    InstallerRerun,
    /// The node restarts (soft = the service, hard = the OS).
    ColdRestart,
    /// The application updates itself in-app (e.g. Tauri updater).
    InAppUpdater,
}

/// Failure policy for an upgrade rollout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RollbackPolicy {
    /// Automatically roll back on failure.
    Auto,
    /// A human decides.
    Manual,
}

// ── database-migration declaration ───────────────────────────────────────

/// One `[[migrations]]` entry: a database migration this plugin ships,
/// executed by the host (the plugin never runs its own DDL).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct MigrationEntry {
    /// A unique (within this plugin) migration id, conventionally
    /// `NNNN_description`. Ids only grow — never edit or reuse one.
    pub id: String,
    /// How the host executes it: `sql` (raw SQL files, the only option
    /// for third-party plugins) or `sea-orm` (a first-party migration
    /// compiled into the host).
    pub engine: MigrationEngine,
    /// The up-migration file path (relative to the plugin directory).
    pub up: PathBuf,
    /// The optional down-migration file path (for explicit rollback).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub down: Option<PathBuf>,
    /// The sha256 of the up-migration file, hex-encoded (64 chars).
    /// Content-addressing prevents a same-id-different-content drift.
    pub sha256: String,
}

/// How a migration is executed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MigrationEngine {
    /// Raw SQL files executed by the host in a transaction.
    Sql,
    /// A `MigrationTrait` implementation compiled into the host binary
    /// (first-party plugins only).
    SeaOrm,
}

impl MigrationEntry {
    fn validate(&self) -> RegistryResult<()> {
        if self.id.is_empty() || self.id.len() > 128 {
            return Err(RegistryError::InvalidManifest(format!(
                "migration id {:?} must be 1..=128 chars",
                self.id
            )));
        }
        if self.up.as_os_str().is_empty() {
            return Err(RegistryError::InvalidManifest(format!(
                "migration {} must carry an 'up' path",
                self.id
            )));
        }
        if !is_sha256_hex(&self.sha256) {
            return Err(RegistryError::InvalidManifest(format!(
                "migration {} sha256 must be 64 lowercase hex chars",
                self.id
            )));
        }
        Ok(())
    }
}

/// Checks a 64-character lowercase hex string (a sha256 digest).
fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

// ── plugin-config declaration ────────────────────────────────────────────

/// The `[config]` section: the plugin's own configuration file and its
/// versioning policy (hifumi `#[version]`-style).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ConfigSection {
    /// The configuration file path (relative to the plugin directory).
    pub file: PathBuf,
    /// The hifumi `format-version` tag the plugin's current code reads.
    pub format_version: String,
    /// What to do when a config file carries an unknown version:
    /// `refuse` (the default — no silent fallback) or `default`
    /// (read as defaults, acknowledged loss).
    #[serde(default = "default_unknown_version_policy")]
    pub on_unknown_version: UnknownVersionPolicy,
}

fn default_unknown_version_policy() -> UnknownVersionPolicy {
    UnknownVersionPolicy::Refuse
}

/// What to do when a config file carries a version the plugin does not
/// know.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UnknownVersionPolicy {
    /// Reject the config file (the default — never silently fall back).
    Refuse,
    /// Read it as defaults (an acknowledged loss, for forward-tolerant
    /// configs only).
    Default,
}

// ── system-host declaration ──────────────────────────────────────────────

/// The `[system]` section: only for `class = "system"` plugins (the host
/// binaries that initialize the entire system).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct SystemSection {
    /// What this binary must be able to do on an empty host, in order
    /// (e.g. `["db-migrate", "seed", "setup"]`).
    pub bootstrap: Vec<String>,
    /// Who brings it back after a restart (e.g. `"systemd"`).
    pub supervisor: String,
    /// The content-addressed artifact name pattern
    /// (e.g. `"chest-{version}-{target}.tar.gz"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A valid baseline manifest (the minimum that passes validation).
    fn baseline() -> PluginManifest {
        PluginManifest {
            schema: SCHEMA,
            id: "acme".into(),
            version: "1.0.0".into(),
            provider: "acme".into(),
            description: None,
            form: Some(FormKind::WebResource),
            class: None,
            platforms: Vec::new(),
            title_i18n: BTreeMap::new(),
            description_i18n: BTreeMap::new(),
            capabilities: Vec::new(),
            requires_contract: Vec::new(),
            trust: None,
            upgrade: None,
            migrations: Vec::new(),
            config: None,
            system: None,
            resources: Vec::new(),
            attachments: Vec::new(),
        }
    }

    #[test]
    fn parses_a_full_manifest() {
        let raw = r##"
id = "acmetheme"
version = "0.2.1"
provider = "acme"
description = "Dark accent theme"
form = "web.resource"

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
        assert_eq!(manifest.schema, SCHEMA);
        assert_eq!(manifest.id, "acmetheme");
        assert_eq!(manifest.version, "0.2.1");
        assert_eq!(manifest.provider, "acme");
        assert_eq!(manifest.description.as_deref(), Some("Dark accent theme"));
        assert_eq!(manifest.form, Some(FormKind::WebResource));
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
version = "1.0.0"
"#;
        let err = toml::from_str::<PluginManifest>(raw).unwrap_err();
        assert!(err.to_string().contains("provider"), "got: {err}");
    }

    #[test]
    fn bad_kind_fails_to_parse() {
        let raw = r#"
id = "acme"
version = "1.0.0"
provider = "acme"
form = "web.resource"
[[resources]]
kind = "WebUI"
[resources.payload.Inline]
value = 1
"#;
        assert!(toml::from_str::<PluginManifest>(raw).is_err());
    }

    #[test]
    fn validate_rejects_bad_ids_and_versions() {
        let mut manifest = baseline();
        manifest.id = "Acme".into();
        assert!(manifest.validate().is_err());

        manifest.id = "acme".into();
        manifest.version = "1.0.0-rc.1".into();
        manifest.validate().expect("SemVer prerelease is valid");

        manifest.version = "1".into();
        assert!(
            manifest.validate().is_err(),
            "bare '1' is not SemVer (needs major.minor.patch)"
        );

        manifest.version = "1..0".into();
        assert!(manifest.validate().is_err());
    }

    #[test]
    fn parses_a_full_fabric_manifest() {
        let raw = r##"
schema = 1
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

[title_i18n]
en = "Kanban board"
"zh-Hans" = "看板"

[trust]
signature = "agent.sig"
min-trust = "verified-publisher"

[upgrade]
mode = "hot"
strategy = "in-app-updater"

[[resources]]
kind = "webui.module"
order = 1

[resources.payload.File]
path = "module.toml"
"##;
        let manifest: PluginManifest = toml::from_str(raw).expect("fabric manifest must parse");
        assert_eq!(manifest.schema, SCHEMA);
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
        assert_eq!(
            manifest.title_i18n.get("zh-Hans").map(String::as_str),
            Some("看板")
        );
        let trust = manifest.trust.as_ref().expect("trust section");
        assert_eq!(trust.signature.as_deref(), Some("agent.sig"));
        assert_eq!(trust.min_trust, MinTrust::VerifiedPublisher);
        let upgrade = manifest.upgrade.as_ref().expect("upgrade section");
        assert_eq!(upgrade.mode, UpgradeMode::Hot);
        assert_eq!(upgrade.strategy, UpgradeStrategy::InAppUpdater);
        manifest.validate().expect("fabric manifest must validate");
    }

    #[test]
    fn round_trips_through_toml() {
        let raw = r#"
schema = 1
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
    fn unsupported_schema_generation_is_rejected() {
        let mut manifest = baseline();
        manifest.schema = 3;
        let err = manifest.validate().unwrap_err();
        assert!(err.to_string().contains("schema version 3"), "got: {err}");
        manifest.schema = 0;
        assert!(manifest.validate().is_err());
        manifest.schema = 2;
        assert!(
            manifest.validate().is_err(),
            "the old schema-2 value is gone: only 1 is accepted"
        );
    }

    #[test]
    fn hyphenated_ids_are_valid() {
        let mut manifest = baseline();
        manifest.id = "celestia-kanban".into();
        manifest
            .validate()
            .expect("hyphenated ids are the unified rule");

        manifest.id = "-leading".into();
        assert!(manifest.validate().is_err(), "must start alphanumeric");

        manifest.id = "Upper".into();
        assert!(manifest.validate().is_err(), "uppercase stays rejected");
    }

    #[test]
    fn versions_must_be_semver() {
        let mut manifest = baseline();

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
    fn form_is_required() {
        let mut manifest = baseline();
        manifest.form = None;
        let err = manifest.validate().unwrap_err();
        assert!(err.to_string().contains("form"), "got: {err}");
    }

    #[test]
    fn default_is_the_baseline_and_is_not_a_valid_manifest() {
        let default = PluginManifest::default();
        assert_eq!(default.schema, SCHEMA);
        assert!(default.form.is_none());
        assert!(default.capabilities.is_empty());
        assert!(default.requires_contract.is_empty());
        assert!(default.trust.is_none());
        assert!(default.resources.is_empty());
        assert!(default.validate().is_err(), "default must not validate");
    }

    #[test]
    fn struct_update_syntax_stays_compatible() {
        let manifest = PluginManifest {
            id: "acme".into(),
            version: "1.0.0".into(),
            provider: "acme".into(),
            description: None,
            form: Some(FormKind::WebResource),
            resources: Vec::new(),
            attachments: Vec::new(),
            ..PluginManifest::default()
        };
        assert_eq!(manifest.schema, SCHEMA);
        manifest
            .validate()
            .expect("struct-update baseline validates");
    }

    #[test]
    fn trust_section_rejects_unknown_keys_instead_of_downgrading() {
        let raw = r#"
schema = 1
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
            "celestia:host/guest@0.1",
            "celestia:panel/host@0.1",
            "celestia:kv/host@1.0",
            "celestia:mesh/plugin@0.2",
            "celestia:panel.extended/host@0.1",
        ] {
            ContractRef::new(good).unwrap_or_else(|e| panic!("{good}: {e}"));
        }
        for bad in [
            "panel/host@0.1",
            "celestia:host@0.1",
            "celestia:panel@0.1",
            "celestia:panel/host",
            "celestia:panel/host@0",
            "celestia:panel/host@0.1.2",
            "celestia:Panel/host@0.1",
            "celestia:panel/HOST@0.1",
            "celestia:panel/host@0.1 ",
            "celestia:panel/",
            "kei:panel/host@0.1",
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
schema = 1
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
schema = 1
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
schema = 1
id = "acme"
version = "1.0.0"
provider = "acme"
form = "web.esmodule"
"#;
        assert!(toml::from_str::<PluginManifest>(raw).is_err());
    }

    // ── class ⇔ system.host binding ──────────────────────────────────

    #[test]
    fn system_host_requires_system_class_and_vice_versa() {
        let mut manifest = baseline();
        manifest.form = Some(FormKind::SystemHost);
        manifest.class = None;
        assert!(
            manifest.validate().is_err(),
            "system.host form without class = \"system\" must be rejected"
        );

        manifest.form = Some(FormKind::WebResource);
        manifest.class = Some("system".into());
        assert!(
            manifest.validate().is_err(),
            "class = \"system\" without system.host form must be rejected"
        );

        manifest.form = Some(FormKind::SystemHost);
        manifest.class = Some("system".into());
        manifest
            .validate()
            .expect("system.host + class = \"system\" is valid");

        manifest.class = Some("panel".into());
        assert!(
            manifest.validate().is_err(),
            "class = \"panel\" with system.host form must be rejected"
        );
    }

    // ── upgrade-section validation ───────────────────────────────────

    #[test]
    fn upgrade_rejects_hot_for_system_host() {
        let mut manifest = baseline();
        manifest.form = Some(FormKind::SystemHost);
        manifest.class = Some("system".into());
        manifest.upgrade = Some(UpgradeSection {
            mode: UpgradeMode::Hot,
            strategy: UpgradeStrategy::InAppUpdater,
            rollback: RollbackPolicy::Auto,
            drain_timeout: None,
            min_ready: None,
            idle_restart: None,
            force_window: None,
            generations: None,
        });
        let err = manifest.validate().unwrap_err();
        assert!(
            err.to_string().contains("system.host may not declare"),
            "got: {err}"
        );
    }

    #[test]
    fn upgrade_rejects_rolling_fields_on_non_rolling_modes() {
        let mut manifest = baseline();
        manifest.upgrade = Some(UpgradeSection {
            mode: UpgradeMode::Hot,
            strategy: UpgradeStrategy::InAppUpdater,
            rollback: RollbackPolicy::Auto,
            drain_timeout: Some("30s".into()),
            min_ready: None,
            idle_restart: None,
            force_window: None,
            generations: None,
        });
        let err = manifest.validate().unwrap_err();
        assert!(err.to_string().contains("rolling-only"), "got: {err}");
    }

    #[test]
    fn upgrade_cold_requires_a_restart_path() {
        let mut manifest = baseline();
        manifest.upgrade = Some(UpgradeSection {
            mode: UpgradeMode::Cold,
            strategy: UpgradeStrategy::ColdRestart,
            rollback: RollbackPolicy::Auto,
            drain_timeout: None,
            min_ready: None,
            idle_restart: None,
            force_window: None,
            generations: None,
        });
        assert!(
            manifest.validate().is_err(),
            "cold without idle-restart or force-window must be rejected"
        );

        manifest.upgrade.as_mut().unwrap().idle_restart = Some(true);
        manifest
            .validate()
            .expect("cold with idle-restart is valid");

        manifest.upgrade.as_mut().unwrap().idle_restart = None;
        manifest.upgrade.as_mut().unwrap().force_window = Some("02:00-04:00".into());
        manifest
            .validate()
            .expect("cold with force-window is valid");
    }

    // ── migration-section validation ─────────────────────────────────

    #[test]
    fn migration_entry_validates_id_up_and_sha256() {
        let mut manifest = baseline();
        manifest.migrations = vec![MigrationEntry {
            id: "0001-init".into(),
            engine: MigrationEngine::Sql,
            up: PathBuf::from("migrations/0001_init.up.sql"),
            down: Some(PathBuf::from("migrations/0001_init.down.sql")),
            sha256: "a".repeat(64),
        }];
        manifest
            .validate()
            .expect("a well-formed migration validates");

        // Bad sha256 (too short).
        manifest.migrations[0].sha256 = "abc".into();
        assert!(
            manifest.validate().is_err(),
            "short sha256 must be rejected"
        );

        // Bad sha256 (uppercase).
        manifest.migrations[0].sha256 = "A".repeat(64);
        assert!(
            manifest.validate().is_err(),
            "uppercase hex must be rejected"
        );

        // Missing up path.
        manifest.migrations[0].sha256 = "a".repeat(64);
        manifest.migrations[0].up = PathBuf::new();
        assert!(
            manifest.validate().is_err(),
            "empty up path must be rejected"
        );
    }

    // ── config-section parsing ───────────────────────────────────────

    #[test]
    fn config_section_parses_and_validates() {
        let raw = r#"
schema = 1
id = "acme"
version = "1.0.0"
provider = "acme"
form = "process.rpc"

[config]
file = "plugin.toml"
format-version = "0.2"
"#;
        let manifest: PluginManifest = toml::from_str(raw).expect("config section must parse");
        let config = manifest.config.as_ref().expect("config section");
        assert_eq!(config.file, PathBuf::from("plugin.toml"));
        assert_eq!(config.format_version, "0.2");
        assert_eq!(config.on_unknown_version, UnknownVersionPolicy::Refuse);
        manifest.validate().expect("must validate");
    }

    // ── system-section parsing ───────────────────────────────────────

    #[test]
    fn system_section_parses() {
        let raw = r#"
schema = 1
id = "celestia-chest"
version = "1.0.0"
provider = "official"
class = "system"
form = "system.host"

[system]
bootstrap = ["db-migrate", "seed", "setup"]
supervisor = "systemd"

[upgrade]
mode = "cold"
strategy = "cold-restart"
idle-restart = true
"#;
        let manifest: PluginManifest = toml::from_str(raw).expect("system section must parse");
        let system = manifest.system.as_ref().expect("system section");
        assert_eq!(system.bootstrap, vec!["db-migrate", "seed", "setup"]);
        assert_eq!(system.supervisor, "systemd");
        manifest.validate().expect("system host manifest validates");
    }

    // ── attachments (multi-surface declaration) ───────────────────────

    /// A helper attachment: engine surface, process.rpc form, agent kind.
    fn engine_attachment() -> AttachmentEntry {
        AttachmentEntry {
            surface: Surface::Engine,
            form: FormKind::ProcessRpc,
            kind: Some(ResourceKind::new("engine.agent").unwrap()),
            name: Some("industrial_iot".into()),
            capabilities: Vec::new(),
            requires_contract: Vec::new(),
            upgrade: None,
            payload: Some(Payload::Inline(serde_json::json!({
                "folder": "industrial_iot"
            }))),
        }
    }

    #[test]
    fn attachments_parse_validate_and_round_trip() {
        let raw = r#"
schema = 1
id = "acme-iot"
version = "1.2.0"
provider = "acme"
description = "IoT agent with a panel page"
form = "web.vue-module"
capabilities = ["mesh.call:evernight", "state.read"]

[[resources]]
kind = "webui.page-type"
name = "panel"
[resources.payload.Inline]
title = "IoT panel"

[[attachments]]
surface = "engine"
form = "process.rpc"
kind = "engine.agent"
name = "industrial_iot"
capabilities = ["mesh.call:evernight"]

[attachments.payload.Inline]
folder = "industrial_iot"

[attachments.upgrade]
mode = "cold"
strategy = "cold-restart"
idle-restart = true

[[attachments]]
surface = "edge"
form = "wasm.component"
kind = "edge.deploy"
"#;
        let manifest: PluginManifest = toml::from_str(raw).expect("attachments must parse");
        assert_eq!(manifest.attachments.len(), 2, "{manifest:?}");
        assert_eq!(manifest.attachments[0].surface, Surface::Engine);
        assert_eq!(manifest.attachments[1].surface, Surface::Edge);
        manifest
            .validate()
            .expect("multi-surface manifest validates");

        // Round trip: the serialized form parses back to the same value.
        let text = toml::to_string_pretty(&manifest).expect("serialize");
        let back: PluginManifest = toml::from_str(&text).expect("re-parse");
        assert_eq!(back, manifest, "round trip must be lossless");
    }

    #[test]
    fn attachments_reject_duplicate_surface() {
        let mut manifest = baseline();
        manifest.attachments = vec![engine_attachment(), engine_attachment()];
        let err = manifest.validate().unwrap_err().to_string();
        assert!(
            err.contains("duplicate [[attachments]] surface 'engine'"),
            "{err}"
        );
    }

    #[test]
    fn attachments_reject_system_host_form() {
        let mut manifest = baseline();
        let mut attachment = engine_attachment();
        attachment.form = FormKind::SystemHost;
        manifest.attachments = vec![attachment];
        let err = manifest.validate().unwrap_err().to_string();
        assert!(err.contains("may not use form system.host"), "{err}");
    }

    #[test]
    fn system_class_manifest_rejects_attachments() {
        let mut manifest = baseline();
        manifest.form = Some(FormKind::SystemHost);
        manifest.class = Some("system".into());
        manifest.attachments = vec![engine_attachment()];
        let err = manifest.validate().unwrap_err().to_string();
        assert!(
            err.contains("system.host manifests may not declare [[attachments]]"),
            "{err}"
        );
    }

    #[test]
    fn attachments_capabilities_must_narrow_plugin_grant() {
        let mut manifest = baseline();
        manifest.capabilities = vec![Capability::new("kv.read").unwrap()];
        let mut attachment = engine_attachment();
        attachment.capabilities = vec![Capability::new("mesh.call:evernight").unwrap()];
        manifest.attachments = vec![attachment];
        let err = manifest.validate().unwrap_err().to_string();
        assert!(err.contains("not granted at plugin level"), "{err}");

        // Narrowing to a granted word passes.
        manifest.attachments[0].capabilities = vec![Capability::new("kv.read").unwrap()];
        manifest.validate().expect("subset capability validates");
    }

    #[test]
    fn attachment_upgrade_validates_against_its_own_form() {
        let mut manifest = baseline();
        // Plugin level: hot on the webui primary form.
        manifest.upgrade = Some(UpgradeSection {
            mode: UpgradeMode::Hot,
            strategy: UpgradeStrategy::BlueGreen,
            rollback: RollbackPolicy::Auto,
            drain_timeout: None,
            min_ready: None,
            idle_restart: None,
            force_window: None,
            generations: None,
        });
        // Attachment level: cold without a restart path must fail against
        // the attachment's own form, independent of the plugin's hot.
        let mut attachment = engine_attachment();
        attachment.upgrade = Some(UpgradeSection {
            mode: UpgradeMode::Cold,
            strategy: UpgradeStrategy::ColdRestart,
            rollback: RollbackPolicy::Auto,
            drain_timeout: None,
            min_ready: None,
            idle_restart: None,
            force_window: None,
            generations: None,
        });
        manifest.attachments = vec![attachment];
        let err = manifest.validate().unwrap_err().to_string();
        assert!(err.contains("cold upgrades must declare"), "{err}");

        manifest.attachments[0]
            .upgrade
            .as_mut()
            .unwrap()
            .idle_restart = Some(true);
        manifest
            .validate()
            .expect("attachment cold with idle-restart validates");
    }

    #[test]
    fn attachments_reject_unknown_surface_spellings_and_keys() {
        let bad_surface = r#"
schema = 1
id = "acme"
version = "1.0.0"
provider = "acme"
form = "web.resource"

[[attachments]]
surface = "server"
form = "process.rpc"
"#;
        assert!(
            toml::from_str::<PluginManifest>(bad_surface).is_err(),
            "unknown surface spelling must fail to parse"
        );

        let typo_key = r#"
schema = 1
id = "acme"
version = "1.0.0"
provider = "acme"
form = "web.resource"

[[attachments]]
surface = "engine"
form = "process.rpc"
capabilitis = []
"#;
        assert!(
            toml::from_str::<PluginManifest>(typo_key).is_err(),
            "attachment entries deny unknown fields"
        );
    }
}
