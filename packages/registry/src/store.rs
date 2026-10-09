use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{RegistryError, RegistryResult};
use crate::manifest::{MANIFEST_FILE, Payload, PluginManifest};

/// The enable/disable state file, stored at the store root (next to the
/// plugin subdirectories, never inside a plugin directory, so toggling a
/// plugin never mutates plugin-owned files).
pub const STATE_FILE: &str = "registry-state.json";

/// A validated plugin as discovered on disk.
#[derive(Debug, Clone, PartialEq)]
pub struct PluginRecord {
    pub manifest: PluginManifest,
    /// The plugin's own directory (manifest + payload files live here).
    pub dir: PathBuf,
    /// Effective enable state (defaults to `true` for unknown ids).
    pub enabled: bool,
}

/// Why a plugin source was rejected during a scan.
#[derive(Debug, Clone, PartialEq)]
pub struct Rejection {
    /// The directory that was rejected.
    pub dir: PathBuf,
    /// The plugin id, when the manifest parsed far enough to carry one.
    pub plugin_id: Option<String>,
    /// Human-readable rejection reason.
    pub reason: String,
}

/// The per-source outcome of a store scan, in scan (directory-name) order.
#[derive(Debug, Clone, PartialEq)]
pub enum ScanResult {
    /// Discovered and fully validated (syntax, payload existence, digests,
    /// unique id).
    Accepted(PluginRecord),
    /// Discovered but rejected; the store keeps scanning the rest.
    Rejected(Rejection),
}

/// The persisted enable/disable overrides.
///
/// Absent ids default to enabled; only explicit `false` entries (or `true`
/// re-enables) are recorded, so deleting a plugin directory leaves no
/// mandatory state cleanup behind.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct EnabledState {
    /// `plugin id -> enabled`. Missing = enabled.
    #[serde(default)]
    plugins: HashMap<String, bool>,
}

impl EnabledState {
    /// Loads the state file; a missing file yields the default (all
    /// enabled). A malformed file is a fail-loud error.
    pub fn load(path: &Path) -> RegistryResult<Self> {
        match fs::read_to_string(path) {
            Ok(text) => serde_json::from_str(&text)
                .map_err(|e| RegistryError::State(format!("cannot parse {}: {e}", path.display()))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(RegistryError::State(format!(
                "cannot read {}: {e}",
                path.display()
            ))),
        }
    }

    /// Persists the state file atomically (write to a temp sibling, rename
    /// over the target).
    pub fn save(&self, path: &Path) -> RegistryResult<()> {
        let tmp = path.with_extension("json.tmp");
        let text = serde_json::to_string_pretty(self)
            .map_err(|e| RegistryError::State(format!("cannot serialize state: {e}")))?;
        fs::write(&tmp, text)
            .map_err(|e| RegistryError::State(format!("cannot write {}: {e}", tmp.display())))?;
        fs::rename(&tmp, path)
            .map_err(|e| RegistryError::State(format!("cannot replace {}: {e}", path.display())))?;
        Ok(())
    }

    /// Effective enable flag for `plugin_id` (missing = enabled).
    pub fn get(&self, plugin_id: &str) -> bool {
        self.plugins.get(plugin_id).copied().unwrap_or(true)
    }

    /// Records an explicit override.
    pub fn set(&mut self, plugin_id: &str, enabled: bool) {
        self.plugins.insert(plugin_id.to_string(), enabled);
    }

    /// The recorded overrides, sorted by plugin id.
    pub fn overrides(&self) -> BTreeMap<&str, bool> {
        self.plugins.iter().map(|(k, v)| (k.as_str(), *v)).collect()
    }
}

/// Hex-encodes the SHA-256 digest of `bytes`.
pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Resolves a manifest-declared `File` payload path against the plugin's
/// own directory, enforcing the registry's path-confinement invariant:
/// after normalization the payload must live strictly inside `dir`.
///
/// `canonicalize` is used deliberately: it resolves `..` walks *and*
/// symlinks, so a payload path that hops over the plugin directory by
/// either mechanism is rejected. `canonicalize` requires the target to
/// exist, which is why this runs at the read sites (scan validation,
/// feed, load) — the exact places that would otherwise open the file.
/// Returns the canonical path to read; the reason strings are
/// channel-agnostic (scan wraps them in a `Rejection`, feed/load in a
/// `PayloadIntegrity` error).
///
/// Platform note: the supported and CI-exercised platform is Linux; the
/// post-scan symlink-swap tests are `#[cfg(unix)]` because they need
/// `symlink(2)`, while the `..`-walk, absolute-path, and nested-path
/// cases stay platform-independent. On Windows, `is_absolute()` reports
/// `false` for rooted-but-driveless (`\x`) and drive-relative (`C:x`)
/// paths, so the early rejection lets them through — but `join`
/// discards `dir` for both forms and the canonicalize + prefix check
/// still rejects them (escape when the target exists, missing
/// otherwise). Only the reason string can differ, never the verdict.
pub(crate) fn confined_payload_path(dir: &Path, path: &Path) -> Result<PathBuf, String> {
    if path.is_absolute() {
        return Err(format!(
            "payload path '{}' is absolute; file payloads must stay inside the plugin directory",
            path.display()
        ));
    }
    let full = dir.join(path);
    let canonical = match full.canonicalize() {
        Ok(canonical) => canonical,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(format!("payload file missing: {}: {e}", full.display()));
        }
        Err(e) => {
            return Err(format!("cannot resolve payload '{}': {e}", full.display()));
        }
    };
    let canonical_dir = dir
        .canonicalize()
        .map_err(|e| format!("cannot resolve plugin directory '{}': {e}", dir.display()))?;
    if !canonical.starts_with(&canonical_dir) {
        return Err(format!(
            "payload path '{}' escapes the plugin directory '{}'",
            path.display(),
            canonical_dir.display()
        ));
    }
    Ok(canonical)
}

/// Why a capped payload read failed (see [`read_capped`]).
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum ReadPayloadError {
    /// The payload exceeded the size cap; `size` is the measured size —
    /// always at least `cap + 1` bytes.
    TooLarge { size: u64, cap: u64 },
    /// The payload could not be opened or read (`io::Error` text).
    Io(String),
}

impl ReadPayloadError {
    /// The channel-agnostic reason string: scan wraps it in a
    /// [`Rejection`], feed/load in a registry error plus a `failed`
    /// audit event — the same convention as
    /// [`confined_payload_path`].
    pub(crate) fn reason(&self, full: &Path) -> String {
        match self {
            ReadPayloadError::TooLarge { size, cap } => format!(
                "payload_too_large: '{}' is {size} bytes, exceeding the cap of {cap} bytes",
                full.display()
            ),
            ReadPayloadError::Io(err) => format!("cannot read payload '{}': {err}", full.display()),
        }
    }
}

/// Reads a file payload under a hard size cap.
///
/// The read itself is bounded: the file is read through
/// `take(cap + 1)`, so a payload larger than the cap — or one that grows
/// past it mid-read — costs at most `cap + 1` bytes of memory, never its
/// full size. A payload at or under the cap reads in full; anything
/// strictly larger is [`ReadPayloadError::TooLarge`] with the measured
/// size for the audit trail.
pub(crate) fn read_capped(full: &Path, cap: u64) -> Result<Vec<u8>, ReadPayloadError> {
    use std::io::Read as _;

    let file = fs::File::open(full).map_err(|e| ReadPayloadError::Io(e.to_string()))?;
    let mut bytes = Vec::new();
    file.take(cap.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|e| ReadPayloadError::Io(e.to_string()))?;
    if bytes.len() as u64 > cap {
        // Best-effort true size for the audit record — the verdict is
        // already made, so a racing change cannot alter it; never report
        // less than the bounded read measured.
        let size = full
            .metadata()
            .map_or(bytes.len() as u64, |m| m.len().max(bytes.len() as u64));
        return Err(ReadPayloadError::TooLarge { size, cap });
    }
    Ok(bytes)
}

/// Scans a plugin store: one subdirectory per plugin under `root`, each
/// containing an `akivili.plugin.toml` plus payload files.
///
/// Validation per plugin directory (in order): manifest readable and
/// parseable, id/version syntax valid, every `File` payload present in —
/// and confined to — the plugin directory, at most `max_payload_bytes`
/// large, every declared `sha256` matching the actual file content, and
/// the plugin id not already taken by an earlier directory
/// (subdirectories are visited in name order, so the first **valid**
/// directory wins — see the duplicate check in `validate_dir`).
/// Any failure rejects that directory only — the scan always reports the
/// whole store.
pub fn scan(
    root: &Path,
    state: &EnabledState,
    max_payload_bytes: u64,
) -> RegistryResult<Vec<ScanResult>> {
    // The unsigned lane: no publisher keys configured, so a plugin
    // demanding a signature fails closed at the trust gate (C4-2).
    scan_with_keys(root, state, max_payload_bytes, &[])
}

/// [`scan`] with a publisher key list — the trust-gated lane: plugins
/// demanding a signature must verify under one of `keys` or the scan
/// rejects them (fail-closed, Celestia Plugin Fabric C4-2).
pub fn scan_with_keys(
    root: &Path,
    state: &EnabledState,
    max_payload_bytes: u64,
    publisher_keys: &[crate::trust::PublisherKey],
) -> RegistryResult<Vec<ScanResult>> {
    let entries = fs::read_dir(root).map_err(|e| {
        RegistryError::Io(std::io::Error::new(
            e.kind(),
            format!("cannot read plugin store {}: {e}", root.display()),
        ))
    })?;

    let mut dirs: Vec<PathBuf> = entries
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_type().is_ok_and(|t| t.is_dir()))
        .map(|entry| entry.path())
        .collect();
    dirs.sort();

    let mut results = Vec::new();
    let mut seen: HashMap<String, PathBuf> = HashMap::new();
    for dir in dirs {
        match validate_dir(&dir, &seen, max_payload_bytes, publisher_keys) {
            Ok(manifest) => {
                let record = PluginRecord {
                    enabled: state.get(&manifest.id),
                    dir,
                    manifest,
                };
                seen.insert(record.manifest.id.clone(), record.dir.clone());
                results.push(ScanResult::Accepted(record));
            }
            Err(rejection) => results.push(ScanResult::Rejected(rejection)),
        }
    }
    Ok(results)
}

/// Validates a single plugin directory, mapping every failure to a
/// [`Rejection`] instead of an error.
fn validate_dir(
    dir: &Path,
    seen: &HashMap<String, PathBuf>,
    max_payload_bytes: u64,
    publisher_keys: &[crate::trust::PublisherKey],
) -> Result<PluginManifest, Rejection> {
    let reject = |plugin_id: Option<String>, reason: String| Rejection {
        dir: dir.to_path_buf(),
        plugin_id,
        reason,
    };

    let manifest_path = dir.join(MANIFEST_FILE);
    let raw = match fs::read_to_string(&manifest_path) {
        Ok(raw) => raw,
        Err(e) => {
            return Err(reject(None, format!("cannot read {MANIFEST_FILE}: {e}")));
        }
    };

    let manifest: PluginManifest = match toml::from_str(&raw) {
        Ok(manifest) => manifest,
        Err(e) => {
            return Err(reject(None, format!("cannot parse {MANIFEST_FILE}: {e}")));
        }
    };

    if let Err(e) = manifest.validate() {
        return Err(reject(Some(manifest.id), e.to_string()));
    }

    // Duplicate-id rule: first **valid** wins. Only accepted directories
    // register their id in `seen` (see the insert in `scan`), so an
    // earlier directory rejected for its own faults never poisons the
    // id — a later valid directory may still claim it. A directory whose
    // id is already taken by a valid plugin is `Rejected`, with the
    // reason naming the winning directory.
    if let Some(first) = seen.get(&manifest.id) {
        return Err(reject(
            Some(manifest.id.clone()),
            format!(
                "duplicate plugin id '{}' (already provided by {})",
                manifest.id,
                first.display()
            ),
        ));
    }

    // The payload assembly for the trust gate: resource file bytes in
    // manifest order (the C4 concatenation contract).
    let mut payload_bytes: Vec<u8> = Vec::new();
    for entry in &manifest.resources {
        if let Payload::File { path, sha256 } = &entry.payload {
            let full = match confined_payload_path(dir, path) {
                Ok(full) => full,
                Err(reason) => {
                    return Err(reject(
                        Some(manifest.id.clone()),
                        format!("payload rejected for kind '{}': {reason}", entry.kind),
                    ));
                }
            };
            let bytes = match read_capped(&full, max_payload_bytes) {
                Ok(bytes) => bytes,
                Err(e) => {
                    return Err(reject(
                        Some(manifest.id.clone()),
                        format!(
                            "payload rejected for kind '{}': {}",
                            entry.kind,
                            e.reason(&full)
                        ),
                    ));
                }
            };
            if let Some(expected) = sha256 {
                let actual = sha256_hex(&bytes);
                if expected != &actual {
                    return Err(reject(
                        Some(manifest.id.clone()),
                        format!(
                            "sha256 mismatch for payload '{}' (kind '{}'): declared {expected}, actual {actual}",
                            path.display(),
                            entry.kind
                        ),
                    ));
                }
            }
            payload_bytes.extend_from_slice(&bytes);
        }
    }

    // The trust gate (C4-2): plugins demanding a signature must verify
    // under a listed publisher key — fail-closed on every failure shape.
    if let Some(trust) = &manifest.trust
        && trust.requires_signature()
    {
        let signature_bytes = trust.signature.as_ref().and_then(|sig_path| {
            let full = confined_payload_path(dir, std::path::Path::new(sig_path)).ok()?;
            read_capped(&full, max_payload_bytes)
                .ok()
                .map(|b| b.to_vec())
        });
        let verdict = match crate::trust::verify_plugin_signature(
            trust,
            signature_bytes.as_deref(),
            &payload_bytes,
            publisher_keys,
        ) {
            Ok(verdict) => verdict,
            Err(e) => {
                return Err(reject(
                    Some(manifest.id.clone()),
                    format!("trust gate: {e}"),
                ));
            }
        };
        match verdict {
            crate::manifest::TrustVerdict::UnsignedOk => {}
            crate::manifest::TrustVerdict::SignedOk { .. } => {}
            crate::manifest::TrustVerdict::UnsignedButDemanded => {
                return Err(reject(
                        Some(manifest.id.clone()),
                        "trust gate: a signature is demanded but the plugin directory carries no usable signature file".to_string(),
                    ));
            }
            crate::manifest::TrustVerdict::SignatureMismatch { reason } => {
                return Err(reject(
                    Some(manifest.id.clone()),
                    format!("trust gate: signature mismatch — {reason}"),
                ));
            }
        }
    }

    Ok(manifest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kinds::ResourceKind;

    /// (directory name, manifest content, [(file name, file content)])
    type DirSpec<'a> = (&'a str, &'a str, &'a [(&'a str, &'a str)]);

    /// Writes a plugin directory with the given manifest content and extra
    /// files; returns the store scan over a fresh temp root (default cap).
    fn scan_with(dirs: &[DirSpec<'_>]) -> RegistryResult<Vec<ScanResult>> {
        scan_with_cap(dirs, crate::registry::DEFAULT_MAX_PAYLOAD_BYTES)
    }

    /// [`scan_with`] under an explicit size cap.
    fn scan_with_cap(dirs: &[DirSpec<'_>], cap: u64) -> RegistryResult<Vec<ScanResult>> {
        let root = tempfile::tempdir().unwrap();
        for (name, manifest, files) in dirs {
            let dir = root.path().join(name);
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join(MANIFEST_FILE), manifest).unwrap();
            for (file_name, content) in *files {
                if let Some(parent) = Path::new(file_name).parent()
                    && !parent.as_os_str().is_empty()
                {
                    fs::create_dir_all(dir.join(parent)).unwrap();
                }
                fs::write(dir.join(file_name), content).unwrap();
            }
        }
        scan(root.path(), &EnabledState::default(), cap)
    }

    fn valid_manifest(id: &str) -> String {
        format!(
            r#"
id = "{id}"
version = "1.0.0"
provider = "test"

[[resources]]
kind = "webui.style"
order = 1

[resources.payload.File]
path = "style.css"
"#
        )
    }

    const STYLE_CSS: &str = "body { color: rebeccapurple; }\n";

    fn sha_of(content: &str) -> String {
        sha256_hex(content.as_bytes())
    }

    #[test]
    fn discovers_a_valid_plugin() {
        let results = scan_with(&[(
            "acmestyle",
            &valid_manifest("acmestyle"),
            &[("style.css", STYLE_CSS)],
        )])
        .unwrap();
        assert_eq!(results.len(), 1);
        match &results[0] {
            ScanResult::Accepted(record) => {
                assert_eq!(record.manifest.id, "acmestyle");
                assert_eq!(record.dir.file_name().unwrap(), "acmestyle");
                assert!(record.enabled, "absent state entry means enabled");
            }
            ScanResult::Rejected(rej) => panic!("unexpected rejection: {:?}", rej.reason),
        }
    }

    #[test]
    fn rejects_missing_manifest() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("empty");
        fs::create_dir_all(&dir).unwrap(); // a directory with no manifest at all
        let results = scan(
            root.path(),
            &EnabledState::default(),
            crate::registry::DEFAULT_MAX_PAYLOAD_BYTES,
        )
        .unwrap();
        match &results[0] {
            ScanResult::Rejected(rej) => {
                assert!(rej.reason.contains("cannot read"), "got: {}", rej.reason);
                assert_eq!(rej.plugin_id, None);
            }
            ScanResult::Accepted(_) => panic!("must be rejected"),
        }
    }

    #[test]
    fn rejects_missing_required_field() {
        let broken = r#"
id = "broken"
version = "1.0.0"
"#;
        let results = scan_with(&[("broken", broken, &[])]).unwrap();
        match &results[0] {
            ScanResult::Rejected(rej) => {
                assert!(rej.reason.contains("cannot parse"), "got: {}", rej.reason)
            }
            ScanResult::Accepted(_) => panic!("must be rejected"),
        }
    }

    #[test]
    fn rejects_bad_id_syntax() {
        let manifest = valid_manifest("Bad_Id");
        let results = scan_with(&[("bad-id", &manifest, &[])]).unwrap();
        match &results[0] {
            ScanResult::Rejected(rej) => {
                assert!(rej.reason.contains("id"), "got: {}", rej.reason);
                assert_eq!(rej.plugin_id.as_deref(), Some("Bad_Id"));
            }
            ScanResult::Accepted(_) => panic!("must be rejected"),
        }
    }

    #[test]
    fn rejects_bad_kind_syntax() {
        let manifest = r#"
id = "bad-kind"
version = "1.0.0"
provider = "test"
[[resources]]
kind = "WebUI"
[resources.payload.Inline]
value = 1
"#;
        let results = scan_with(&[("bad-kind", manifest, &[])]).unwrap();
        match &results[0] {
            ScanResult::Rejected(rej) => {
                assert!(rej.reason.contains("cannot parse"), "got: {}", rej.reason)
            }
            ScanResult::Accepted(_) => panic!("must be rejected"),
        }
    }

    #[test]
    fn rejects_missing_payload_file() {
        let results = scan_with(&[("ghost", &valid_manifest("ghost"), &[])]).unwrap();
        match &results[0] {
            ScanResult::Rejected(rej) => {
                assert!(rej.reason.contains("missing"), "got: {}", rej.reason);
                assert_eq!(rej.plugin_id.as_deref(), Some("ghost"));
            }
            ScanResult::Accepted(_) => panic!("must be rejected"),
        }
    }

    #[test]
    fn rejects_sha256_mismatch() {
        let mut manifest = valid_manifest("corrupt");
        manifest.push_str(&format!("sha256 = \"{}\"\n", "0".repeat(64)));
        let results = scan_with(&[("corrupt", &manifest, &[("style.css", STYLE_CSS)])]).unwrap();
        match &results[0] {
            ScanResult::Rejected(rej) => {
                assert!(rej.reason.contains("mismatch"), "got: {}", rej.reason)
            }
            ScanResult::Accepted(_) => panic!("must be rejected"),
        }
    }

    #[test]
    fn accepts_matching_sha256() {
        let mut manifest = valid_manifest("hashed");
        manifest.push_str(&format!("sha256 = \"{}\"\n", sha_of(STYLE_CSS)));
        let results = scan_with(&[("hashed", &manifest, &[("style.css", STYLE_CSS)])]).unwrap();
        assert!(matches!(results[0], ScanResult::Accepted(_)));
    }

    #[test]
    fn size_cap_accepts_exactly_at_cap_and_rejects_one_byte_over() {
        // Boundary: the cap is inclusive — a payload of exactly `cap`
        // bytes passes, `cap + 1` rejects the whole plugin.
        let at_cap = "x".repeat(64);
        let over_cap = "y".repeat(65);
        let results = scan_with_cap(
            &[
                ("atcap", &valid_manifest("atcap"), &[("style.css", &at_cap)]),
                ("over", &valid_manifest("over"), &[("style.css", &over_cap)]),
            ],
            64,
        )
        .unwrap();
        assert_eq!(results.len(), 2);
        assert!(matches!(results[0], ScanResult::Accepted(_)));
        match &results[1] {
            ScanResult::Rejected(rej) => {
                assert!(
                    rej.reason.contains("payload_too_large"),
                    "got: {}",
                    rej.reason
                );
                assert!(
                    rej.reason.contains("65 bytes") && rej.reason.contains("cap of 64 bytes"),
                    "the reason must record the measured size and the cap: {}",
                    rej.reason
                );
                assert_eq!(rej.plugin_id.as_deref(), Some("over"));
            }
            ScanResult::Accepted(_) => panic!("must be rejected"),
        }
    }

    #[test]
    fn rejects_payload_path_escaping_the_plugin_dir() {
        // `../escape.txt` points at a real file outside the plugin
        // directory (here: inside the store root). The scan must reject
        // the plugin, and the outside bytes must never be read.
        let root = tempfile::tempdir().unwrap();
        let secret = "outside-the-plugin-dir\n";
        fs::write(root.path().join("escape.txt"), secret).unwrap();
        let dir = root.path().join("escaper");
        fs::create_dir_all(&dir).unwrap();
        let manifest = valid_manifest("escaper").replace("style.css", "../escape.txt");
        fs::write(dir.join(MANIFEST_FILE), &manifest).unwrap();
        let results = scan(
            root.path(),
            &EnabledState::default(),
            crate::registry::DEFAULT_MAX_PAYLOAD_BYTES,
        )
        .unwrap();
        match &results[0] {
            ScanResult::Rejected(rej) => {
                assert!(rej.reason.contains("escapes"), "got: {}", rej.reason);
                assert_eq!(rej.plugin_id.as_deref(), Some("escaper"));
            }
            ScanResult::Accepted(_) => panic!("must be rejected"),
        }
    }

    #[test]
    fn rejects_absolute_payload_path() {
        // An absolute payload path discards the plugin directory in
        // `join` entirely; it is rejected even though the target exists.
        let root = tempfile::tempdir().unwrap();
        let outside = root.path().join("outside.css");
        fs::write(&outside, STYLE_CSS).unwrap();
        let dir = root.path().join("abspath");
        fs::create_dir_all(&dir).unwrap();
        let manifest = valid_manifest("abspath").replace("style.css", outside.to_str().unwrap());
        fs::write(dir.join(MANIFEST_FILE), &manifest).unwrap();
        let results = scan(
            root.path(),
            &EnabledState::default(),
            crate::registry::DEFAULT_MAX_PAYLOAD_BYTES,
        )
        .unwrap();
        match &results[0] {
            ScanResult::Rejected(rej) => {
                assert!(rej.reason.contains("absolute"), "got: {}", rej.reason);
                assert_eq!(rej.plugin_id.as_deref(), Some("abspath"));
            }
            ScanResult::Accepted(_) => panic!("must be rejected"),
        }
    }

    #[test]
    fn accepts_payload_in_nested_subdirectory() {
        // Confinement must not over-restrict: nested paths inside the
        // plugin directory normalize back inside it and are accepted.
        let manifest = valid_manifest("nested").replace("style.css", "assets/style.css");
        let results =
            scan_with(&[("nested", &manifest, &[("assets/style.css", STYLE_CSS)])]).unwrap();
        assert!(matches!(results[0], ScanResult::Accepted(_)));
    }

    #[test]
    fn duplicate_id_rejects_the_later_directory() {
        let results = scan_with(&[
            (
                "a-first",
                &valid_manifest("dup"),
                &[("style.css", STYLE_CSS)],
            ),
            (
                "b-second",
                &valid_manifest("dup"),
                &[("style.css", STYLE_CSS)],
            ),
        ])
        .unwrap();
        assert_eq!(results.len(), 2);
        assert!(matches!(results[0], ScanResult::Accepted(_)));
        match &results[1] {
            ScanResult::Rejected(rej) => {
                assert!(rej.reason.contains("duplicate"), "got: {}", rej.reason);
                assert!(
                    rej.reason.contains("a-first"),
                    "reason names the winner: {}",
                    rej.reason
                );
                assert_eq!(rej.plugin_id.as_deref(), Some("dup"));
            }
            ScanResult::Accepted(_) => panic!("must be rejected"),
        }
    }

    // ── The trust gate over real scans (C4-2) ──────────────────────

    fn trust_manifest(sig: Option<&str>) -> String {
        let sig_line = sig
            .map(|p| format!("signature = \"{p}\""))
            .unwrap_or_default();
        format!(
            r#"schema = 2
id = "signed-plugin"
version = "1.0.0"
provider = "official"
form = "web.vue-module"

[trust]
{sig_line}
min-trust = "signed"

[[resources]]
kind = "webui.style"
name = "main"

[resources.payload.Inline]
color = "red"
"#
        )
    }

    fn trust_scan_root(tag: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!(
            "akivili-trust-{tag}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(root.join("signed-plugin")).unwrap();
        root
    }

    /// A two-file schema-2 trust fixture: the payload is BOTH files'
    /// bytes in manifest order (the concatenation contract), so the
    /// signature covers a non-empty ordered body.
    fn two_file_trust_manifest() -> String {
        let alpha = b"alpha payload bytes".to_vec();
        let beta = b"beta payload bytes".to_vec();
        let sha = |b: &[u8]| sha256_hex(b);
        format!(
            r#"schema = 2
id = "signed-plugin"
version = "1.0.0"
provider = "official"
form = "web.vue-module"

[trust]
signature = "agent.sig"
min-trust = "signed"

[[resources]]
kind = "webui.style"
order = 1

[resources.payload.File]
path = "alpha.bin"
sha256 = "{sha_a}"

[[resources]]
kind = "webui.style"
order = 2

[resources.payload.File]
path = "beta.bin"
sha256 = "{sha_b}"
"#,
            sha_a = sha(&alpha),
            sha_b = sha(&beta),
        )
    }

    #[test]
    fn a_validly_signed_plugin_scans_in_under_its_key() {
        use ed25519_dalek::{Signer, SigningKey};
        use rand::rngs::OsRng;

        let signing = SigningKey::generate(&mut OsRng);
        // The payload is resource bytes in manifest order — alpha then
        // beta, a NON-empty ordered body.
        let signature = signing.sign(b"alpha payload bytesbeta payload bytes");
        let root = trust_scan_root("ok");
        std::fs::write(
            root.join("signed-plugin/akivili.plugin.toml"),
            two_file_trust_manifest(),
        )
        .unwrap();
        std::fs::write(root.join("signed-plugin/alpha.bin"), b"alpha payload bytes").unwrap();
        std::fs::write(root.join("signed-plugin/beta.bin"), b"beta payload bytes").unwrap();
        std::fs::write(root.join("signed-plugin/agent.sig"), signature.to_bytes()).unwrap();
        let keys = vec![crate::trust::PublisherKey {
            key_id: "scan-key".into(),
            bytes: signing.verifying_key().to_bytes(),
        }];
        let results = scan_with_keys(
            &root,
            &EnabledState::default(),
            crate::registry::DEFAULT_MAX_PAYLOAD_BYTES,
            &keys,
        )
        .expect("scan runs");
        let _ = std::fs::remove_dir_all(&root);
        assert!(
            matches!(results.first(), Some(ScanResult::Accepted(_))),
            "a validly signed plugin scans in, got {results:?}"
        );
    }

    /// The concatenation ORDER is load-bearing: a signature made over
    /// the reversed body must NOT verify (the m2 pin — the payload
    /// assembly follows manifest order, not filename or size).
    #[test]
    fn the_payload_concatenation_order_is_load_bearing() {
        use ed25519_dalek::{Signer, SigningKey};
        use rand::rngs::OsRng;

        let signing = SigningKey::generate(&mut OsRng);
        let signature = signing.sign(b"beta payload bytesalpha payload bytes");
        let root = trust_scan_root("order");
        std::fs::write(
            root.join("signed-plugin/akivili.plugin.toml"),
            two_file_trust_manifest(),
        )
        .unwrap();
        std::fs::write(root.join("signed-plugin/alpha.bin"), b"alpha payload bytes").unwrap();
        std::fs::write(root.join("signed-plugin/beta.bin"), b"beta payload bytes").unwrap();
        std::fs::write(root.join("signed-plugin/agent.sig"), signature.to_bytes()).unwrap();
        let keys = vec![crate::trust::PublisherKey {
            key_id: "order-key".into(),
            bytes: signing.verifying_key().to_bytes(),
        }];
        let results = scan_with_keys(
            &root,
            &EnabledState::default(),
            crate::registry::DEFAULT_MAX_PAYLOAD_BYTES,
            &keys,
        )
        .expect("scan runs");
        let _ = std::fs::remove_dir_all(&root);
        match results.first() {
            Some(ScanResult::Rejected(rejection)) => {
                assert!(
                    rejection.reason.contains("signature mismatch"),
                    "{}",
                    rejection.reason
                );
            }
            other => panic!("expected rejection for the reversed body, got {other:?}"),
        }
    }

    #[test]
    fn a_signature_demanding_plugin_fails_closed_without_keys() {
        let root = trust_scan_root("nokeys");
        std::fs::write(
            root.join("signed-plugin/akivili.plugin.toml"),
            trust_manifest(Some("agent.sig")),
        )
        .unwrap();
        let results = scan_with_keys(
            &root,
            &EnabledState::default(),
            crate::registry::DEFAULT_MAX_PAYLOAD_BYTES,
            &[],
        )
        .expect("scan runs");
        let _ = std::fs::remove_dir_all(&root);
        match results.first() {
            Some(ScanResult::Rejected(rejection)) => {
                assert!(
                    rejection.reason.contains("no usable signature file"),
                    "{}",
                    rejection.reason
                );
            }
            other => panic!("expected rejection, got {other:?}"),
        }
    }

    #[test]
    fn a_tampered_signature_is_rejected_with_the_reason() {
        use ed25519_dalek::{Signer, SigningKey};
        use rand::rngs::OsRng;

        let signing = SigningKey::generate(&mut OsRng);
        let other = SigningKey::generate(&mut OsRng);
        let signature = other.sign(&[]);
        let root = trust_scan_root("tamper");
        std::fs::write(
            root.join("signed-plugin/akivili.plugin.toml"),
            trust_manifest(Some("agent.sig")),
        )
        .unwrap();
        std::fs::write(root.join("signed-plugin/agent.sig"), signature.to_bytes()).unwrap();
        let keys = vec![crate::trust::PublisherKey {
            key_id: "real".into(),
            bytes: signing.verifying_key().to_bytes(),
        }];
        let results = scan_with_keys(
            &root,
            &EnabledState::default(),
            crate::registry::DEFAULT_MAX_PAYLOAD_BYTES,
            &keys,
        )
        .expect("scan runs");
        let _ = std::fs::remove_dir_all(&root);
        match results.first() {
            Some(ScanResult::Rejected(rejection)) => {
                assert!(
                    rejection.reason.contains("signature mismatch"),
                    "{}",
                    rejection.reason
                );
            }
            other => panic!("expected rejection, got {other:?}"),
        }
    }

    #[test]
    fn scan_errors_when_store_root_is_missing() {
        let root = tempfile::tempdir().unwrap();
        let missing = root.path().join("nope");
        let err = scan(
            &missing,
            &EnabledState::default(),
            crate::registry::DEFAULT_MAX_PAYLOAD_BYTES,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("cannot read plugin store"),
            "got: {err}"
        );
    }

    #[test]
    fn enabled_state_round_trip_and_defaults() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join(STATE_FILE);

        let mut state = EnabledState::load(&path).unwrap();
        assert!(state.get("anything"), "missing state file means enabled");

        state.set("acme", false);
        state.save(&path).unwrap();
        let mut reloaded = EnabledState::load(&path).unwrap();
        assert!(!reloaded.get("acme"));
        assert!(reloaded.get("other"));

        reloaded.set("acme", true);
        assert!(reloaded.get("acme"));
    }

    #[test]
    fn sha256_hex_matches_known_digest() {
        // sha256 of empty input
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        let kind = ResourceKind::new(crate::kinds::WEBUI_STYLE).unwrap();
        assert_eq!(kind.as_str(), "webui.style");
    }

    #[test]
    fn scan_accepts_schema_2_manifests_and_feeds_their_resources() {
        // End-to-end: a schema 2 plugin (form, capabilities, contract
        // ref) scans, validates, and feeds resources exactly like a v1
        // plugin — those fields are additive at the store level. The
        // [trust] section is NOT additive since C4-2: a demanding
        // section is enforced (see the trust-gate tests below), so this
        // fixture stays in the unsigned lane.
        let v2 = r##"
schema = 2
id = "celestia-kanban"
version = "1.2.0"
provider = "official"
form = "web.vue-module"
capabilities = ["kv.read", "mesh.call:celestia-reports"]
requires-contract = ["celestia:panel/host@0.1"]

[[resources]]
kind = "webui.module"
order = 1

[resources.payload.File]
path = "module.toml"
sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
"##;
        let results = scan_with(&[("celestia-kanban", v2, &[("module.toml", "")])]).unwrap();
        assert_eq!(results.len(), 1, "the schema 2 plugin must be accepted");
        match &results[0] {
            ScanResult::Accepted(record) => {
                assert_eq!(record.manifest.id, "celestia-kanban");
                assert_eq!(record.manifest.schema, 2);
                assert_eq!(record.manifest.resources.len(), 1);
            }
            other => panic!("expected an accepted scan, got {other:?}"),
        }
    }

    #[test]
    fn scan_rejects_v2_manifests_that_violate_the_schema_gates() {
        // v1 smuggling a v2 field must land in rejections, not panic.
        let smuggler = r#"
id = "smuggler"
version = "1"
provider = "acme"
capabilities = ["kv.read"]
"#;
        let results = scan_with(&[("smuggler", smuggler, &[])]).unwrap();
        match &results[0] {
            ScanResult::Rejected(rejection) => {
                assert!(
                    rejection.reason.contains("capabilities"),
                    "got: {}",
                    rejection.reason
                );
            }
            other => panic!("expected a rejection, got {other:?}"),
        }

        // schema 2 without a form is a rejection too.
        let formless = r#"
schema = 2
id = "formless"
version = "1.0.0"
provider = "acme"
"#;
        let results = scan_with(&[("formless", formless, &[])]).unwrap();
        match &results[0] {
            ScanResult::Rejected(rejection) => {
                assert!(
                    rejection.reason.contains("form"),
                    "got: {}",
                    rejection.reason
                );
            }
            other => panic!("expected a rejection, got {other:?}"),
        }
    }
}
