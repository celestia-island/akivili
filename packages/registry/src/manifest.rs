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
    /// Domain agents this plugin carries — the 10-12 binding: built-in
    /// L2 agents move from the plana static registry into plugin
    /// manifests, so a plugin IS the authority for its agent's identity.
    /// Absent/empty = no agents (fully backward compatible).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub agents: Vec<AgentEntry>,
    /// Structured tool declarations (manifest `[[agent_tools]]`) — the
    /// lazy-visibility contract: the host can expose a tool's name,
    /// description and parameter schema from the manifest alone, before
    /// any MCP server is installed on a node.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub agent_tools: Vec<AgentToolEntry>,
    /// Install scripts (manifest `[[installs]]`) — the on-demand
    /// provisioning contract: plugin-owned TypeScript executed in the
    /// PTC sandbox when a bound tool is first invoked on a node that
    /// does not have its MCP entry yet.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub installs: Vec<InstallEntry>,
    /// MCP server entries (manifest `[[mcp_servers]]`) — servers this
    /// plugin installs on evernight nodes (never inside scepter or
    /// cosmos containers), each bound to one declared agent folder.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mcp_servers: Vec<McpServerEntry>,
}

/// Cap on one agent's declared `tools`/`skills` stems — mirrors the
/// scepter consumer's `MAX_CAPABILITY_STEMS` (the per-section doc cap
/// in `agent_config_service`), so a manifest cannot declare more
/// capability stems than the widest embedded agent.
pub const MAX_AGENT_CAPABILITY_STEMS: usize = 64;

/// One domain agent declared by a plugin (manifest `[[agents]]`).
///
/// `folder` follows plana's folder-name conventions so scepter's
/// prompt/tool paths resolve unchanged; the host merges declared agents
/// into the L2 roster beside the static registry (registry = fallback).
/// `tools`/`skills` stems are shape-gated by [`PluginManifest::validate`]
/// against the same vocabulary the scepter consumer enforces
/// (`is_capability_stem`: `^[a-z0-9_]+$`, 1..=64 chars, ≤ 64 per array)
/// — gating at the manifest layer keeps a bad stem from reaching the
/// consumer, where it cost the agent its whole roster row instead of
/// just the one stem (chest #1862 R2-P2-1).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentEntry {
    /// Agent folder name, `^[a-z][a-z0-9_]*$` (matches plana
    /// `AgentKind::folder_name` vocabulary — devops / office / …).
    pub folder: String,
    /// Un-localized friendly name (the roster's fallback label).
    pub name: String,
    /// Localized roster descriptions keyed by locale tag; `en` is
    /// required (the family's manifest i18n convention).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub description_i18n: BTreeMap<String, String>,
    /// Tool doc stems the agent exposes (resolved by the host from the
    /// plugin's res tree — the registry only carries the names).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<String>,
    /// Skill (recipe) doc stems the agent ships.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub skills: Vec<String>,
}

/// One structured tool declaration (manifest `[[agent_tools]]`).
///
/// The lazy-visibility half of the L2 plugin execution contract: the
/// host exposes name/description/schema from the manifest alone (before
/// any install has run), and `origin` tells the runtime where execution
/// lives once the install has provided it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentToolEntry {
    /// The `[[agents]]` folder this tool belongs to.
    pub agent: String,
    /// Tool name — the module export and the dispatch local part,
    /// `^[a-z0-9_]+$` (<= 64 chars), unique per agent.
    pub name: String,
    /// One-line description the prompt surface shows.
    pub description: String,
    /// Where the tool executes once provisioned:
    /// `"host"` — a built-in host capability the plugin binds;
    /// `"js"` — the plugin's in-PTC sandbox script;
    /// `"mcp:<server-id>"` — an `[[mcp_servers]]` entry of this plugin.
    pub origin: String,
    /// JSON Schema (object) for the tool's parameters; an empty object
    /// means "no schema enforced at the manifest layer".
    #[serde(default = "default_tool_schema")]
    pub schema: serde_json::Value,
}

fn default_tool_schema() -> serde_json::Value {
    serde_json::json!({})
}

/// One install script (manifest `[[installs]]`).
///
/// The on-demand provisioning contract: a plugin-owned TypeScript file
/// executed in the PTC sandbox when a bound tool is first invoked on a
/// node that does not have the MCP entry yet. The script drives Polemos
/// host tools (resource push / node exec / mcp registry upsert) to
/// install. All waiters — the initiating call included — wait at most
/// `timeout_ms` before receiving a retryable "installing" answer, and a
/// cancel is only honoured after at least one such timeout has elapsed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallEntry {
    /// Install id, `^[a-z0-9][a-z0-9-]*$`, unique within the manifest.
    pub id: String,
    /// Path of the TypeScript install script inside the plugin
    /// directory. Must be covered by a `[[resources]]` file payload so
    /// the bytes are hashed and signature-verified — an unsigned script
    /// is rejected at validation time.
    pub script: String,
    /// Tool names this install provides; `["*"]` (the default) means
    /// every declared tool. Each name must resolve to an
    /// `[[agent_tools]]` entry or an `[[agents]]` doc stem.
    #[serde(default = "default_install_tools")]
    pub tools: Vec<String>,
    /// How long callers wait for this install before receiving the
    /// retryable answer. Default 120 000 ms; clamped to 1 s ..= 1 h.
    #[serde(default = "default_install_timeout_ms")]
    pub timeout_ms: u64,
    /// Optional node affinity label (e.g. `"capability:office"`);
    /// resolved by the host against evernight node capabilities.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_selector: Option<String>,
}

fn default_install_tools() -> Vec<String> {
    vec!["*".to_string()]
}

const DEFAULT_INSTALL_TIMEOUT_MS: u64 = 120_000;

fn default_install_timeout_ms() -> u64 {
    DEFAULT_INSTALL_TIMEOUT_MS
}

/// One MCP server entry (manifest `[[mcp_servers]]`).
///
/// A server this plugin installs on evernight nodes — never inside
/// scepter or cosmos containers (the lateral-movement guard). Bound to
/// one L2 agent folder; after the install script has run, this is the
/// entry the node-side `mcpTools` registry carries.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpServerEntry {
    /// Server id, `^[a-z0-9][a-z0-9-]*$` (<= 64 chars), unique within
    /// the manifest; `[[agent_tools]]` origins reference it as
    /// `mcp:<id>`.
    pub id: String,
    /// Transport: `"stdio"` (the node spawns `command`) or `"http"` /
    /// `"sse"` (the node dials `url`).
    pub transport: String,
    /// The command to run for `stdio`, resolved inside the installed
    /// plugin directory. Empty for remote transports.
    #[serde(default)]
    pub command: String,
    /// argv for the stdio command.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    /// The endpoint URL for `http`/`sse`. Empty for stdio.
    #[serde(default)]
    pub url: String,
    /// The `[[agents]]` folder this server's tools belong to.
    pub agent: String,
    /// Platform/arch matrix the artifact set covers (e.g.
    /// `["linux-x64"]`); empty means platform-independent.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub platforms: Vec<String>,
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
            agents: Vec::new(),
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
            agent_tools: Vec::new(),
            installs: Vec::new(),
            mcp_servers: Vec::new(),
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
                // A kind rides exactly one channel (R1 finding): the
                // same kind declared both as a resource and as an
                // attachment would double-register on any host that
                // consumes both feeds.
                if let Some(kind) = &attachment.kind
                    && self.resources.iter().any(|entry| &entry.kind == kind)
                {
                    return Err(RegistryError::InvalidManifest(format!(
                        "kind '{}' is declared both as a resource and as an attachment",
                        kind
                    )));
                }
                // Capabilities narrow the plugin-level grant, never widen.
                for word in &attachment.capabilities {
                    if !self.capabilities.contains(word) {
                        return Err(RegistryError::InvalidManifest(format!(
                            "attachment to surface '{}' declares capability '{}' not granted at plugin level",
                            attachment.surface, word
                        )));
                    }
                }
                // The upgrade declaration is validated against THIS
                // attachment's form — explicitly declared, or inherited
                // from the plugin level (the inheritance re-check is
                // behavior-neutral under today's matrix and closes the
                // gap the moment the matrix grows form-specific rules).
                match &attachment.upgrade {
                    Some(upgrade) => upgrade.validate(&attachment.form)?,
                    None => {
                        if let Some(upgrade) = &self.upgrade {
                            upgrade.validate(&attachment.form)?;
                        }
                    }
                }
            }
        }
        // [[resources]] — list-level invariants. The webui host takes
        // a plugin's page-type class from its `webui.page-type`
        // resource, so a manifest declaring SEVERAL leaves the winner
        // to feed order — an ambiguity no consumer can resolve (each
        // host would silently first-win, the exact smell chest's
        // catalog surfaced). At most one may appear; validate/pack
        // rejects the ambiguity here, at the source (#1904 R2 and
        // chest #1893 R2, S3 closeout).
        {
            let mut seen_page_type = false;
            for (position, entry) in self.resources.iter().enumerate() {
                if entry.kind.as_str() == crate::kinds::WEBUI_PAGE_TYPE {
                    if seen_page_type {
                        return Err(RegistryError::InvalidManifest(format!(
                            "duplicate webui.page-type resource '{}' (manifest position {}): at most one webui.page-type resource per manifest — several leave the page class ambiguous",
                            entry.name.as_deref().unwrap_or("<unnamed>"),
                            position + 1,
                        )));
                    }
                    seen_page_type = true;
                }
            }
        }
        for migration in &self.migrations {
            migration.validate()?;
        }
        // [[agents]] — the 10-12 binding section. Folder names must
        // match plana's vocabulary shape and be unique within the
        // manifest; `en` description is required (the roster's
        // fallback label convention); tools/skills stems share the
        // scepter consumer's capability-stem vocabulary.
        {
            let mut seen_folders = std::collections::BTreeSet::new();
            for agent in &self.agents {
                let ok_folder = !agent.folder.is_empty()
                    && agent.folder.len() <= 48
                    && agent
                        .folder
                        .chars()
                        .next()
                        .is_some_and(|c| c.is_ascii_lowercase())
                    && agent
                        .folder
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
                if !ok_folder {
                    return Err(RegistryError::InvalidManifest(format!(
                        "agent folder '{}' must match ^[a-z][a-z0-9_]*$ (<= 48 chars)",
                        agent.folder
                    )));
                }
                if agent.name.trim().is_empty() {
                    return Err(RegistryError::InvalidManifest(format!(
                        "agent '{}' carries an empty name",
                        agent.folder
                    )));
                }
                if !agent.description_i18n.contains_key("en") {
                    return Err(RegistryError::InvalidManifest(format!(
                        "agent '{}' requires an \"en\" description_i18n entry",
                        agent.folder
                    )));
                }
                // Capability stems (tools/skills) — the SAME vocabulary
                // the scepter consumer enforces (`is_capability_stem` /
                // `MAX_CAPABILITY_STEMS` in agent_config_service):
                // `^[a-z0-9_]+$`, 1..=64 chars, ≤ 64 stems per array.
                // Gating here (pack/scan time) means a bad stem fails
                // loudly and early; on the consumer side it only
                // warn-dropped the whole roster row (chest #1862
                // R2-P2-1). One deliberate narrowing: duplicates are
                // refused here even though the consumer tolerates
                // repeats — a manifest naming the same stem twice is a
                // manifest smell, and the error says so explicitly.
                for (kind, stems) in [("tools", &agent.tools), ("skills", &agent.skills)] {
                    if stems.len() > MAX_AGENT_CAPABILITY_STEMS {
                        return Err(RegistryError::InvalidManifest(format!(
                            "agent '{}' declares {} {kind} stems (cap is {MAX_AGENT_CAPABILITY_STEMS}, mirroring the consumer's per-section doc cap)",
                            agent.folder,
                            stems.len()
                        )));
                    }
                    let mut seen_stems = std::collections::BTreeSet::new();
                    for stem in stems.iter() {
                        let ok_stem = !stem.is_empty()
                            && stem.len() <= 64
                            && stem
                                .chars()
                                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
                        if !ok_stem {
                            return Err(RegistryError::InvalidManifest(format!(
                                "agent '{}' declares {kind} stem '{stem}' outside the capability vocabulary ^[a-z0-9_]+$ (1..=64 chars)",
                                agent.folder
                            )));
                        }
                        if !seen_stems.insert(stem.as_str()) {
                            return Err(RegistryError::InvalidManifest(format!(
                                "agent '{}' declares duplicate {kind} stem '{stem}' — the consumer tolerates repeats but the manifest layer requires each stem once",
                                agent.folder
                            )));
                        }
                    }
                }
                if !seen_folders.insert(agent.folder.clone()) {
                    return Err(RegistryError::InvalidManifest(format!(
                        "duplicate [[agents]] folder '{}'",
                        agent.folder
                    )));
                }
            }
        }

        // [[agent_tools]] / [[mcp_servers]] / [[installs]] — the L2
        // plugin execution contract. Every cross-reference must resolve
        // within THIS manifest: agent bindings name a declared
        // [[agents]] folder, mcp origins name a declared server, every
        // install script is covered by a signed file resource, and
        // every install tool name resolves to a declared tool.
        {
            let agent_folders: std::collections::BTreeSet<&str> =
                self.agents.iter().map(|a| a.folder.as_str()).collect();
            let server_ids: std::collections::BTreeSet<&str> =
                self.mcp_servers.iter().map(|s| s.id.as_str()).collect();

            for server in &self.mcp_servers {
                if !is_valid_id(&server.id) || server.id.len() > 64 {
                    return Err(RegistryError::InvalidManifest(format!(
                        "mcp server id '{}' must match ^[a-z0-9][a-z0-9-]*$ (<= 64 chars)",
                        server.id
                    )));
                }
                match server.transport.as_str() {
                    "stdio" => {
                        if server.command.trim().is_empty() {
                            return Err(RegistryError::InvalidManifest(format!(
                                "mcp server '{}' (stdio) requires a command",
                                server.id
                            )));
                        }
                        // The command is resolved inside the installed
                        // plugin directory, so its path shape must stay
                        // relative and inside it (same rule as install
                        // scripts — no absolute paths, no `..` walks).
                        {
                            let command_path = PathBuf::from(&server.command);
                            if command_path.is_absolute()
                                || server.command.split(['/', '\\']).any(|seg| seg == "..")
                            {
                                return Err(RegistryError::InvalidManifest(format!(
                                    "mcp server '{}' (stdio) command '{}' must be a relative path inside the installed plugin directory",
                                    server.id, server.command
                                )));
                            }
                        }
                        // The url field is remote-transport-only; a stdio
                        // entry carrying one is a contradictory declaration.
                        if !server.url.is_empty() {
                            return Err(RegistryError::InvalidManifest(format!(
                                "mcp server '{}' (stdio) must not declare a url (remote-transport field)",
                                server.id
                            )));
                        }
                    }
                    "http" | "sse" => {
                        let scheme_len = if server.url.starts_with("https://") {
                            "https://".len()
                        } else if server.url.starts_with("http://") {
                            "http://".len()
                        } else {
                            return Err(RegistryError::InvalidManifest(format!(
                                "mcp server '{}' ({}) requires an http(s) url",
                                server.id, server.transport
                            )));
                        };
                        if server.url.len() == scheme_len {
                            return Err(RegistryError::InvalidManifest(format!(
                                "mcp server '{}' ({}) url is missing its host",
                                server.id, server.transport
                            )));
                        }
                        // The command field is stdio-only; a remote entry
                        // carrying one is a contradictory declaration.
                        if !server.command.is_empty() {
                            return Err(RegistryError::InvalidManifest(format!(
                                "mcp server '{}' ({}) must not declare a command (stdio field)",
                                server.id, server.transport
                            )));
                        }
                    }
                    other => {
                        return Err(RegistryError::InvalidManifest(format!(
                            "mcp server '{}' transport must be stdio|http|sse (got '{other}')",
                            server.id
                        )));
                    }
                }
                if !agent_folders.contains(server.agent.as_str()) {
                    return Err(RegistryError::InvalidManifest(format!(
                        "mcp server '{}' binds unknown agent folder '{}'",
                        server.id, server.agent
                    )));
                }
            }
            {
                let mut seen_ids = std::collections::BTreeSet::new();
                for server in &self.mcp_servers {
                    if !seen_ids.insert(server.id.clone()) {
                        return Err(RegistryError::InvalidManifest(format!(
                            "duplicate [[mcp_servers]] id '{}'",
                            server.id
                        )));
                    }
                }
            }

            {
                let mut seen: std::collections::BTreeSet<(String, String)> =
                    std::collections::BTreeSet::new();
                for tool in &self.agent_tools {
                    if !agent_folders.contains(tool.agent.as_str()) {
                        return Err(RegistryError::InvalidManifest(format!(
                            "agent tool '{}' binds unknown agent folder '{}'",
                            tool.name, tool.agent
                        )));
                    }
                    let ok_name = !tool.name.is_empty()
                        && tool.name.len() <= 64
                        && tool
                            .name
                            .chars()
                            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
                    if !ok_name {
                        return Err(RegistryError::InvalidManifest(format!(
                            "agent tool name '{}' must match ^[a-z0-9_]+$ (<= 64 chars)",
                            tool.name
                        )));
                    }
                    if tool.description.trim().is_empty() {
                        return Err(RegistryError::InvalidManifest(format!(
                            "agent tool '{}' carries an empty description",
                            tool.name
                        )));
                    }
                    match tool.origin.as_str() {
                        "host" | "js" => {}
                        origin if origin.starts_with("mcp:") => {
                            let server_id = &origin[4..];
                            if server_id.is_empty() || !server_ids.contains(server_id) {
                                return Err(RegistryError::InvalidManifest(format!(
                                    "agent tool '{}' origin '{origin}' does not name a declared [[mcp_servers]] id",
                                    tool.name
                                )));
                            }
                        }
                        other => {
                            return Err(RegistryError::InvalidManifest(format!(
                                "agent tool '{}' origin must be host|js|mcp:<server-id> (got '{other}')",
                                tool.name
                            )));
                        }
                    }
                    if !tool.schema.is_object() {
                        return Err(RegistryError::InvalidManifest(format!(
                            "agent tool '{}' schema must be a JSON object",
                            tool.name
                        )));
                    }
                    if !seen.insert((tool.agent.clone(), tool.name.clone())) {
                        return Err(RegistryError::InvalidManifest(format!(
                            "duplicate [[agent_tools]] name '{}' for agent '{}'",
                            tool.name, tool.agent
                        )));
                    }
                }
            }

            {
                // Tool name → the set of agent folders declaring it (an
                // [[agent_tools]] entry or an [[agents]] doc stem).
                // Installs name tools bare — no folder qualifier — so a
                // name bound to more than one agent is ambiguous: the
                // first-invocation trigger would fire for both, but the
                // script provisions only one of them.
                let mut tool_agents: std::collections::BTreeMap<
                    &str,
                    std::collections::BTreeSet<&str>,
                > = std::collections::BTreeMap::new();
                for tool in &self.agent_tools {
                    tool_agents
                        .entry(tool.name.as_str())
                        .or_default()
                        .insert(tool.agent.as_str());
                }
                for agent in &self.agents {
                    for stem in &agent.tools {
                        tool_agents
                            .entry(stem.as_str())
                            .or_default()
                            .insert(agent.folder.as_str());
                    }
                }
                let mut seen_ids = std::collections::BTreeSet::new();
                for install in &self.installs {
                    if !is_valid_id(&install.id) || install.id.len() > 64 {
                        return Err(RegistryError::InvalidManifest(format!(
                            "install id '{}' must match ^[a-z0-9][a-z0-9-]*$ (<= 64 chars)",
                            install.id
                        )));
                    }
                    if !seen_ids.insert(install.id.clone()) {
                        return Err(RegistryError::InvalidManifest(format!(
                            "duplicate [[installs]] id '{}'",
                            install.id
                        )));
                    }
                    if !(1_000..=3_600_000).contains(&install.timeout_ms) {
                        return Err(RegistryError::InvalidManifest(format!(
                            "install '{}' timeout_ms {} outside 1_000..=3_600_000",
                            install.id, install.timeout_ms
                        )));
                    }
                    let script_path = PathBuf::from(&install.script);
                    if install.script.trim().is_empty()
                        || script_path.is_absolute()
                        || install.script.split(['/', '\\']).any(|seg| seg == "..")
                    {
                        return Err(RegistryError::InvalidManifest(format!(
                            "install '{}' script '{}' must be a relative path inside the plugin directory",
                            install.id, install.script
                        )));
                    }
                    let covered = self.resources.iter().any(|r| match &r.payload {
                        Payload::File { path, .. } => *path == script_path,
                        Payload::Inline(_) => false,
                    });
                    if !covered {
                        return Err(RegistryError::InvalidManifest(format!(
                            "install '{}' script '{}' is not covered by a [[resources]] file payload (unsigned bytes)",
                            install.id, install.script
                        )));
                    }
                    if install.tools.is_empty() {
                        return Err(RegistryError::InvalidManifest(format!(
                            "install '{}' declares no tools",
                            install.id
                        )));
                    }
                    if install.tools.iter().any(|t| t == "*") && tool_agents.is_empty() {
                        return Err(RegistryError::InvalidManifest(format!(
                            "install '{}' declares tools = [\"*\"] but no [[agent_tools]] entry or [[agents]] doc stem exists — nothing could ever trigger it",
                            install.id
                        )));
                    }
                    for tool in &install.tools {
                        if tool == "*" {
                            continue;
                        }
                        let Some(agents) = tool_agents.get(tool.as_str()) else {
                            return Err(RegistryError::InvalidManifest(format!(
                                "install '{}' names tool '{tool}' which no [[agent_tools]] entry or [[agents]] doc stem declares",
                                install.id
                            )));
                        };
                        if agents.len() > 1 {
                            let folders: Vec<&str> = agents.iter().copied().collect();
                            return Err(RegistryError::InvalidManifest(format!(
                                "install '{}' names tool '{tool}' which is declared by more than one agent ({}) — a bare name cannot pick one",
                                install.id,
                                folders.join(", ")
                            )));
                        }
                    }
                }
            }
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
        for (label, path) in [("up", Some(&self.up)), ("down", self.down.as_ref())] {
            let Some(path) = path else { continue };
            if path.as_os_str().is_empty() {
                return Err(RegistryError::InvalidManifest(format!(
                    "migration {} must carry a non-empty '{label}' path",
                    self.id
                )));
            }
            if path.is_absolute()
                || path
                    .components()
                    .any(|c| !matches!(c, std::path::Component::Normal(_)))
            {
                return Err(RegistryError::InvalidManifest(format!(
                    "migration {} '{label}' path '{}' must be a relative path inside the plugin directory",
                    self.id,
                    path.display()
                )));
            }
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
            agents: Vec::new(),
            agent_tools: Vec::new(),
            installs: Vec::new(),
            mcp_servers: Vec::new(),
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

    /// A `webui.page-type` resource entry — the shape every page-class
    /// plugin carries exactly once.
    fn page_type_resource(name: &str) -> ResourceEntry {
        ResourceEntry {
            kind: ResourceKind::new(crate::kinds::WEBUI_PAGE_TYPE).expect("well-known kind"),
            name: Some(name.to_string()),
            order: 0,
            payload: Payload::Inline(serde_json::json!({ "title": name })),
        }
    }

    #[test]
    fn one_page_type_resource_validates() {
        // The legal shape: exactly one webui.page-type resource names
        // the plugin's page class — validate passes.
        let mut manifest = baseline();
        manifest.resources = vec![page_type_resource("panel")];
        manifest
            .validate()
            .expect("exactly one webui.page-type resource validates");
    }

    #[test]
    fn two_page_type_resources_are_refused_at_validate() {
        // The ambiguity the webui host cannot resolve: two page-type
        // resources leave the class winner feed-order-dependent. The
        // manifest layer refuses it loudly, naming the duplicate
        // resource and its manifest position.
        let mut manifest = baseline();
        manifest.resources = vec![page_type_resource("panel"), page_type_resource("shell")];
        let err = manifest.validate().unwrap_err().to_string();
        assert!(
            err.contains("duplicate webui.page-type resource 'shell' (manifest position 2)"),
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

    #[test]
    fn attachments_reject_kind_declared_as_resource() {
        let mut manifest = baseline();
        manifest.resources = vec![ResourceEntry {
            kind: ResourceKind::new("engine.agent").unwrap(),
            name: None,
            order: 0,
            payload: Payload::Inline(serde_json::json!({})),
        }];
        let mut attachment = engine_attachment();
        attachment.kind = Some(ResourceKind::new("engine.agent").unwrap());
        manifest.attachments = vec![attachment];
        let err = manifest.validate().unwrap_err().to_string();
        assert!(
            err.contains("declared both as a resource and as an attachment"),
            "{err}"
        );

        // A different kind on the attachment channel is fine.
        manifest.attachments[0].kind = Some(ResourceKind::new("engine.tool").unwrap());
        manifest.validate().expect("disjoint kinds validate");
    }

    #[test]
    fn attachment_upgrade_inherits_plugin_level_and_revalidates() {
        let mut manifest = baseline();
        // Plugin level: hot on the webui primary form — valid today.
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
        // Attachment with NO upgrade of its own: the plugin-level section
        // is inherited and re-validated against the attachment's form.
        // Today's matrix constrains only system.host (forbidden in
        // attachments), so this pins the lenient present AND the
        // inheritance path — the moment the matrix grows form-specific
        // rules, this guard is what catches an incompatible inheritance.
        manifest.attachments = vec![engine_attachment()];
        manifest
            .validate()
            .expect("inherited hot validates for a process.rpc attachment today");

        // An explicit attachment upgrade still wins over inheritance and
        // validates against the attachment's own form.
        let mut attachment = engine_attachment();
        attachment.upgrade = Some(UpgradeSection {
            mode: UpgradeMode::Cold,
            strategy: UpgradeStrategy::ColdRestart,
            rollback: RollbackPolicy::Auto,
            drain_timeout: None,
            min_ready: None,
            idle_restart: Some(true),
            force_window: None,
            generations: None,
        });
        manifest.attachments = vec![attachment];
        manifest
            .validate()
            .expect("explicit attachment upgrade validates");
    }

    #[test]
    fn attachments_round_trip_a_file_payload_with_upgrade() {
        let raw = r#"
schema = 1
id = "acme-edge"
version = "1.0.0"
provider = "acme"
form = "web.resource"

[[attachments]]
surface = "edge"
form = "wasm.component"
kind = "edge.deploy"

[attachments.payload.File]
path = "edge/module.wasm"

[attachments.upgrade]
mode = "rolling"
strategy = "blue-green"
drain-timeout = "30s"
min-ready = 1
"#;
        let manifest: PluginManifest = toml::from_str(raw).expect("file+upgrade must parse");
        manifest.validate().expect("file+upgrade validates");
        let text = toml::to_string_pretty(&manifest).expect("serialize");
        let back: PluginManifest = toml::from_str(&text).expect("re-parse");
        assert_eq!(back, manifest, "round trip must be lossless");
    }

    // ── agents (the 10-12 binding section) ───────────────────────────

    fn agent_section_raw() -> &'static str {
        r#"
schema = 1
id = "acme-devops"
version = "0.1.0"
provider = "acme"
form = "web.vue-module"

[[resources]]
kind = "webui.page-type"
name = "panel"
[resources.payload.Inline]
title = "DevOps"

[[agents]]
folder = "devops"
name = "DevOps"
tools = ["list_prs", "merge_pr"]
skills = ["release_flow"]

[agents.description_i18n]
en = "Source control, CI and CD operations"
zh-Hans = "源码管理、CI 与 CD 操作"
"#
    }

    #[test]
    fn agents_parse_validate_and_round_trip() {
        let manifest: PluginManifest =
            toml::from_str(agent_section_raw()).expect("agents section must parse");
        assert_eq!(manifest.agents.len(), 1);
        let agent = &manifest.agents[0];
        assert_eq!(agent.folder, "devops");
        assert_eq!(agent.name, "DevOps");
        assert_eq!(
            agent.description_i18n.get("en").map(String::as_str),
            Some("Source control, CI and CD operations")
        );
        assert_eq!(agent.tools, vec!["list_prs", "merge_pr"]);
        manifest.validate().expect("manifest with agents validates");
        // Round trip: serialize + reparse keeps the section intact.
        let again: PluginManifest =
            toml::from_str(&toml::to_string(&manifest).unwrap()).expect("round trip parses");
        assert_eq!(again.agents, manifest.agents);
    }

    #[test]
    fn agents_absent_is_backward_compatible() {
        let raw = r#"
schema = 1
id = "plain"
version = "1.0.0"
provider = "acme"
form = "web.vue-module"
"#;
        let manifest: PluginManifest = toml::from_str(raw).expect("no-agents manifest parses");
        assert!(manifest.agents.is_empty());
        manifest.validate().expect("validates without agents");
    }

    #[test]
    fn agents_reject_bad_folder_shape() {
        for bad in ["Devops", "dev-ops", "1devops", "", &"x".repeat(49)] {
            let raw = format!(
                r#"
schema = 1
id = "acme"
version = "1.0.0"
provider = "acme"
form = "web.vue-module"

[[agents]]
folder = "{bad}"
name = "X"

[agents.description_i18n]
en = "desc"
"#
            );
            let manifest: PluginManifest = toml::from_str(&raw).expect("parses");
            assert!(
                manifest.validate().is_err(),
                "folder {bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn agents_reject_missing_en_description_and_dup_folders() {
        let no_en = r#"
schema = 1
id = "acme"
version = "1.0.0"
provider = "acme"
form = "web.vue-module"

[[agents]]
folder = "devops"
name = "X"

[agents.description_i18n]
zh-Hans = "仅中文"
"#;
        let manifest: PluginManifest = toml::from_str(no_en).unwrap();
        assert!(manifest.validate().is_err(), "en description required");

        let dup = r#"
schema = 1
id = "acme"
version = "1.0.0"
provider = "acme"
form = "web.vue-module"

[[agents]]
folder = "devops"
name = "X"
[agents.description_i18n]
en = "a"

[[agents]]
folder = "devops"
name = "Y"
[agents.description_i18n]
en = "b"
"#;
        let manifest: PluginManifest = toml::from_str(dup).unwrap();
        assert!(manifest.validate().is_err(), "duplicate folders rejected");
    }

    /// Builds a one-agent manifest with literal TOML arrays for
    /// `tools`/`skills` (already quoted, e.g. `"a", "b"`; empty string
    /// = omit the key).
    fn agent_stems_raw(tools: &str, skills: &str) -> String {
        let tools = if tools.is_empty() {
            String::new()
        } else {
            format!("tools = [{tools}]")
        };
        let skills = if skills.is_empty() {
            String::new()
        } else {
            format!("skills = [{skills}]")
        };
        format!(
            r#"
schema = 1
id = "acme"
version = "1.0.0"
provider = "acme"
form = "web.vue-module"

[[agents]]
folder = "devops"
name = "DevOps"
{tools}
{skills}

[agents.description_i18n]
en = "desc"
"#
        )
    }

    #[test]
    fn agents_capability_stems_accept_official_shapes() {
        // Real stems from chest's official manifest pack (e.g.
        // celestia-kanban) — the positive reference shape.
        let manifest: PluginManifest = toml::from_str(&agent_stems_raw(
            r#""create_board", "move_card", "set_wip_limit""#,
            r#""run_standup", "unclog_lane""#,
        ))
        .expect("official-shaped stems parse");
        manifest.validate().expect("official-shaped stems validate");

        // Boundary values pass: exactly 64 chars, digits-only, a lone
        // underscore, and exactly 64 stems per array (the cap).
        let stem64 = "s".repeat(64);
        let manifest: PluginManifest =
            toml::from_str(&agent_stems_raw(&format!(r#""{stem64}", "007", "_""#), ""))
                .expect("boundary stems parse");
        manifest
            .validate()
            .expect("64-char stem at the cap validates");

        let many: Vec<String> = (0..MAX_AGENT_CAPABILITY_STEMS)
            .map(|i| format!("\"tool_{i}\""))
            .collect();
        let manifest: PluginManifest =
            toml::from_str(&agent_stems_raw(&many.join(", "), "")).expect("64 stems parse");
        manifest.validate().expect("exactly 64 stems validate");
    }

    #[test]
    fn agents_reject_bad_capability_stem_shapes() {
        // The scepter vocabulary is ^[a-z0-9_]+$ (1..=64 chars):
        // uppercase, dots, hyphens, empty and overlong stems are all
        // refused — each error names the agent folder and the stem.
        for bad in [
            "ListPrs",
            "list.prs",
            "list-prs",
            "",
            &"s".repeat(65),
            "看板",
        ] {
            for (kind, raw) in [
                (
                    "tools",
                    agent_stems_raw(&format!(r#""{bad}""#), r#""ok_skill""#),
                ),
                (
                    "skills",
                    agent_stems_raw(r#""ok_tool""#, &format!(r#""{bad}""#)),
                ),
            ] {
                let manifest: PluginManifest =
                    toml::from_str(&raw).unwrap_or_else(|e| panic!("parses: {e}"));
                let err = manifest.validate().unwrap_err().to_string();
                assert!(err.contains("devops"), "error names the folder: {err}");
                assert!(err.contains(kind), "error names the array: {err}");
                assert!(
                    err.contains(&format!("'{bad}'")),
                    "error quotes the bad stem verbatim: {err}"
                );
            }
        }
    }

    #[test]
    fn agents_reject_too_many_capability_stems() {
        let many: Vec<String> = (0..=MAX_AGENT_CAPABILITY_STEMS)
            .map(|i| format!("\"tool_{i}\""))
            .collect();
        let manifest: PluginManifest =
            toml::from_str(&agent_stems_raw(&many.join(", "), "")).expect("65 stems parse");
        let err = manifest.validate().unwrap_err().to_string();
        assert!(err.contains("devops"), "error names the folder: {err}");
        assert!(err.contains("tools"), "error names the array: {err}");
        assert!(
            err.contains("65") && err.contains("64"),
            "error reports the count and the cap: {err}"
        );
    }

    #[test]
    fn agents_reject_duplicate_capability_stems() {
        // Stricter than the scepter consumer (which tolerates repeats):
        // the manifest layer requires each stem once, and the error
        // says both halves explicitly.
        let manifest: PluginManifest = toml::from_str(&agent_stems_raw(
            r#""list_prs", "list_prs""#,
            r#""release_flow""#,
        ))
        .expect("parses");
        let err = manifest.validate().unwrap_err().to_string();
        assert!(err.contains("devops"), "error names the folder: {err}");
        assert!(
            err.contains("duplicate tools stem 'list_prs'"),
            "got: {err}"
        );

        let manifest: PluginManifest = toml::from_str(&agent_stems_raw(
            r#""list_prs""#,
            r#""release_flow", "release_flow""#,
        ))
        .expect("parses");
        let err = manifest.validate().unwrap_err().to_string();
        assert!(
            err.contains("duplicate skills stem 'release_flow'"),
            "got: {err}"
        );
    }

    // ── agent_tools / mcp_servers / installs (the L2 execution contract) ──

    fn l2_contract_raw() -> String {
        r#"
schema = 1
id = "acme-office"
version = "0.1.0"
provider = "acme"
form = "web.vue-module"

[[resources]]
kind = "webui.page-type"
name = "panel"
[resources.payload.Inline]
title = "Office"

[[resources]]
kind = "install.script"
[resources.payload.File]
path = "install/default.ts"

[[agents]]
folder = "office"
name = "Office"
[agents.description_i18n]
en = "Office documents"

[[agent_tools]]
agent = "office"
name = "deck_build"
description = "Compose a deck from a plan and template"
origin = "mcp:office-engine"
[agent_tools.schema]
type = "object"

[[agent_tools]]
agent = "office"
name = "deck_plan_validate"
description = "Validate a deck plan (pure logic)"
origin = "js"

[[mcp_servers]]
id = "office-engine"
transport = "stdio"
command = "office-mcp"
agent = "office"
platforms = ["linux-x64"]

[[installs]]
id = "default"
script = "install/default.ts"
tools = ["*"]
timeout_ms = 120000
node_selector = "capability:office"
"#
        .to_string()
    }

    fn parse_validated(raw: &str) -> PluginManifest {
        let manifest: PluginManifest = toml::from_str(raw).expect("must parse");
        manifest.validate().expect("must validate");
        manifest
    }

    #[test]
    fn l2_contract_sections_parse_validate_and_round_trip() {
        let manifest = parse_validated(&l2_contract_raw());
        assert_eq!(manifest.agent_tools.len(), 2);
        assert_eq!(manifest.installs.len(), 1);
        assert_eq!(manifest.mcp_servers.len(), 1);
        assert_eq!(manifest.installs[0].timeout_ms, 120_000);
        assert_eq!(
            manifest.installs[0].node_selector.as_deref(),
            Some("capability:office")
        );
        assert_eq!(manifest.agent_tools[0].origin, "mcp:office-engine");
        assert!(manifest.agent_tools[0].schema.is_object());
        assert_eq!(manifest.mcp_servers[0].agent, "office");

        let text = toml::to_string_pretty(&manifest).expect("serialize");
        let back: PluginManifest = toml::from_str(&text).expect("re-parse");
        assert_eq!(back, manifest, "round trip must be lossless");
    }

    #[test]
    fn l2_contract_defaults_apply_when_optional_keys_are_absent() {
        let raw = r#"
schema = 1
id = "acme-office"
version = "0.1.0"
provider = "acme"
form = "web.vue-module"

[[resources]]
kind = "install.script"
[resources.payload.File]
path = "install/default.ts"

[[agents]]
folder = "office"
name = "Office"
tools = ["seed_tool"]
[agents.description_i18n]
en = "Office"

[[installs]]
id = "default"
script = "install/default.ts"
"#;
        let manifest = parse_validated(raw);
        assert_eq!(manifest.installs[0].tools, vec!["*"]);
        assert_eq!(manifest.installs[0].timeout_ms, 120_000);
        assert!(manifest.installs[0].node_selector.is_none());
        // Agent tools absent = no lazy-visibility declarations; still valid
        // because the install's "*" resolves to the agent's doc stems.
        assert!(manifest.agent_tools.is_empty());
    }

    #[test]
    fn installs_with_wildcard_but_no_declared_tools_is_rejected() {
        // `tools = ["*"]` with zero declared tools can never be triggered
        // (installs fire on first tool invocation) — a dead declaration.
        let raw = r#"
schema = 1
id = "acme-office"
version = "0.1.0"
provider = "acme"
form = "web.vue-module"

[[resources]]
kind = "install.script"
[resources.payload.File]
path = "install/default.ts"

[[agents]]
folder = "office"
name = "Office"
[agents.description_i18n]
en = "Office"

[[installs]]
id = "default"
script = "install/default.ts"
"#;
        let manifest: PluginManifest = toml::from_str(raw).expect("must parse");
        let err = manifest.validate().unwrap_err().to_string();
        assert!(
            err.contains("tools = [\"*\"] but no [[agent_tools]] entry"),
            "{err}"
        );
    }

    #[test]
    fn installs_may_not_name_a_tool_ambiguous_across_agents() {
        // The bare name matches two agents' declarations: the trigger
        // would fire for both, but the script provisions only one.
        let raw = r#"
schema = 1
id = "acme"
version = "1.0.0"
provider = "acme"
form = "web.vue-module"

[[resources]]
kind = "install.script"
[resources.payload.File]
path = "install/default.ts"

[[agents]]
folder = "office"
name = "Office"
[agents.description_i18n]
en = "a"

[[agents]]
folder = "devops"
name = "DevOps"
[agents.description_i18n]
en = "b"

[[agent_tools]]
agent = "office"
name = "shared_name"
description = "d"
origin = "js"

[[agent_tools]]
agent = "devops"
name = "shared_name"
description = "d"
origin = "js"

[[installs]]
id = "default"
script = "install/default.ts"
tools = ["shared_name"]
"#;
        let manifest: PluginManifest = toml::from_str(raw).expect("must parse");
        let err = manifest.validate().unwrap_err().to_string();
        assert!(
            err.contains("declared by more than one agent (devops, office)"),
            "{err}"
        );
    }

    #[test]
    fn install_timeout_bounds_are_inclusive() {
        let mut manifest = parse_validated(&l2_contract_raw());
        for boundary in [1_000u64, 3_600_000] {
            manifest.installs[0].timeout_ms = boundary;
            manifest
                .validate()
                .unwrap_or_else(|e| panic!("boundary {boundary} must be legal: {e}"));
        }
        for outside in [999u64, 3_600_001] {
            manifest.installs[0].timeout_ms = outside;
            assert!(
                manifest.validate().is_err(),
                "{outside} must be rejected (1 s ..= 1 h)"
            );
        }
    }

    #[test]
    fn l2_sections_reject_unknown_keys_instead_of_silently_defaulting() {
        // The family spells multi-word keys in kebab-case elsewhere
        // (`drain-timeout`, `min-ready`, …); a `timeout-ms` typo here
        // must fail LOUDLY, not silently fall back to the 120 s default
        // in exactly the field that governs how long callers block.
        let typo = r#"
schema = 1
id = "acme"
version = "1.0.0"
provider = "acme"
form = "web.vue-module"

[[resources]]
kind = "install.script"
[resources.payload.File]
path = "install/default.ts"

[[agents]]
folder = "office"
name = "Office"
tools = ["seed_tool"]
[agents.description_i18n]
en = "a"

[[installs]]
id = "default"
script = "install/default.ts"
timeout-ms = 5000
"#;
        let err = toml::from_str::<PluginManifest>(typo)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("timeout-ms"),
            "the unknown key must be named in the error: {err}"
        );

        let server_typo = r#"
schema = 1
id = "acme"
version = "1.0.0"
provider = "acme"
form = "web.vue-module"

[[agents]]
folder = "office"
name = "Office"
[agents.description_i18n]
en = "a"

[[mcp_servers]]
id = "office-engine"
transport = "stdio"
command = "x"
agent = "office"
transport_mode = "stdio"
"#;
        assert!(
            toml::from_str::<PluginManifest>(server_typo).is_err(),
            "mcp_servers entries deny unknown fields"
        );
    }

    /// Mutate one aspect of the valid contract and assert validation
    /// refuses it. Every case names the rule it pins.
    #[test]
    fn l2_contract_rejects_broken_cross_references() {
        let cases: &[(&str, String)] = &[
            (
                "agent_tools binds unknown agent folder",
                r#"

[[agent_tools]]
agent = "ghost"
name = "deck_build"
description = "d"
origin = "js"
"#
                .to_string(),
            ),
            (
                "agent_tools origin names an undeclared mcp server",
                r#"

[[agent_tools]]
agent = "office"
name = "deck_render"
description = "d"
origin = "mcp:ghost-engine"
"#
                .to_string(),
            ),
            (
                "agent_tools names must be unique per agent",
                r#"

[[agent_tools]]
agent = "office"
name = "deck_build"
description = "d"
origin = "js"
"#
                .to_string(),
            ),
            (
                "agent_tools schema must be a JSON object",
                r#"

[[agent_tools]]
agent = "office"
name = "deck_outline"
description = "d"
origin = "js"
schema = "object"
"#
                .to_string(),
            ),
            (
                "agent_tools origin vocabulary is closed",
                r#"

[[agent_tools]]
agent = "office"
name = "deck_build"
description = "d"
origin = "wasm:office"
"#
                .to_string(),
            ),
            (
                "agent_tools name shape is enforced",
                r#"

[[agent_tools]]
agent = "office"
name = "DeckBuild"
description = "d"
origin = "js"
"#
                .to_string(),
            ),
            (
                "agent_tools description must not be empty",
                r#"

[[agent_tools]]
agent = "office"
name = "deck_build"
description = ""
origin = "js"
"#
                .to_string(),
            ),
            (
                "mcp_servers stdio requires a command",
                r#"

[[mcp_servers]]
id = "office-engine"
transport = "stdio"
agent = "office"
"#
                .to_string(),
            ),
            (
                "mcp_servers http requires an http(s) url",
                r#"

[[mcp_servers]]
id = "office-engine"
transport = "http"
url = "ftp://example.invalid"
agent = "office"
"#
                .to_string(),
            ),
            (
                "mcp_servers stdio must not carry a url",
                r#"

[[mcp_servers]]
id = "second-engine"
transport = "stdio"
command = "office-mcp"
url = "http://example.invalid"
agent = "office"
"#
                .to_string(),
            ),
            (
                "mcp_servers http must not carry a command",
                r#"

[[mcp_servers]]
id = "second-engine"
transport = "http"
url = "http://example.invalid"
command = "office-mcp"
agent = "office"
"#
                .to_string(),
            ),
            (
                "mcp_servers url must carry a host",
                r#"

[[mcp_servers]]
id = "second-engine"
transport = "sse"
url = "https://"
agent = "office"
"#
                .to_string(),
            ),
            (
                "mcp_servers transport vocabulary is closed",
                r#"

[[mcp_servers]]
id = "office-engine"
transport = "grpc"
command = "x"
agent = "office"
"#
                .to_string(),
            ),
            (
                "mcp_servers binds unknown agent folder",
                r#"

[[mcp_servers]]
id = "office-engine"
transport = "stdio"
command = "office-mcp"
agent = "ghost"
"#
                .to_string(),
            ),
            (
                "mcp_servers ids must be unique",
                r#"

[[mcp_servers]]
id = "office-engine"
transport = "stdio"
command = "a"
agent = "office"

[[mcp_servers]]
id = "office-engine"
transport = "stdio"
command = "b"
agent = "office"
"#
                .to_string(),
            ),
            (
                "installs script must be a signed file resource",
                r#"

[[installs]]
id = "rogue"
script = "install/not-declared.ts"
"#
                .to_string(),
            ),
            (
                "installs script must stay inside the plugin directory",
                r#"

[[installs]]
id = "rogue"
script = "../escape.ts"
"#
                .to_string(),
            ),
            (
                "installs names must resolve to declared tools",
                r#"

[[installs]]
id = "extra"
script = "install/default.ts"
tools = ["no_such_tool"]
"#
                .to_string(),
            ),
            (
                "installs timeout is clamped",
                r#"

[[installs]]
id = "extra"
script = "install/default.ts"
timeout_ms = 10
"#
                .to_string(),
            ),
            (
                "installs script must not be absolute",
                r#"

[[installs]]
id = "extra"
script = "/etc/evil.ts"
"#
                .to_string(),
            ),
            (
                "installs ids must be unique",
                r#"

[[installs]]
id = "default"
script = "install/default.ts"

[[installs]]
id = "default"
script = "install/default.ts"
"#
                .to_string(),
            ),
            (
                "stdio command must stay inside the plugin directory",
                r#"

[[mcp_servers]]
id = "office-engine-2"
transport = "stdio"
command = "/bin/bash"
agent = "office"
"#
                .to_string(),
            ),
            (
                "stdio command must not walk out with ..",
                r#"

[[mcp_servers]]
id = "office-engine-2"
transport = "stdio"
command = "../evil"
agent = "office"
"#
                .to_string(),
            ),
            (
                "install ids carry the same length cap as server ids",
                format!(
                    r#"

[[installs]]
id = "{}"
script = "install/default.ts"
"#,
                    "a".repeat(65)
                ),
            ),
        ];

        let template = l2_contract_raw();
        for (label, snippet) in cases {
            // Splice each mutation in just before the trailing quote of
            // the template: arrays-of-tables append, so every case adds
            // NEW entries. Each case MUST use an id/name that does not
            // collide with the template's own declarations — a colliding
            // entry gets rejected by an earlier duplicate check and never
            // reaches the gate it claims to pin (that masking is how
            // three gates silently lost coverage). The only exceptions
            // are the deliberate duplicate cases themselves.
            let mutated = format!("{}{}", &template[..template.len() - 1], snippet);
            let manifest: PluginManifest = match toml::from_str(&mutated) {
                Ok(m) => m,
                Err(e) => {
                    // A parse failure is also an acceptable rejection for
                    // shape-level cases (e.g. duplicate keys never parse).
                    let msg = e.to_string();
                    assert!(
                        msg.contains("duplicate") || msg.contains("invalid"),
                        "{label}: unexpected parse error: {msg}"
                    );
                    continue;
                }
            };
            assert!(
                manifest.validate().is_err(),
                "{label}: validation must reject"
            );
        }
    }

    #[test]
    fn agent_tools_per_agent_names_may_repeat_across_agents() {
        // Same tool name under two different agents is legal — the
        // dispatch name is folder-qualified at the host layer.
        let raw = r#"
schema = 1
id = "acme"
version = "1.0.0"
provider = "acme"
form = "web.vue-module"

[[agents]]
folder = "office"
name = "Office"
[agents.description_i18n]
en = "a"

[[agents]]
folder = "devops"
name = "DevOps"
[agents.description_i18n]
en = "b"

[[agent_tools]]
agent = "office"
name = "shared_name"
description = "d"
origin = "js"

[[agent_tools]]
agent = "devops"
name = "shared_name"
description = "d"
origin = "js"
"#;
        parse_validated(raw);
    }
}
