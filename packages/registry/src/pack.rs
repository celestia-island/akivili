//! The plugin bundle packer (W11 slice 2): turn a package directory into
//! a store-installable, signature-sealed bundle.
//!
//! Research pinned the distribution format before this module was
//! written — the installable unit is **a plugin directory** under the
//! store root (one `akivili.plugin.toml` plus payload files; the store
//! scan reads it, chest's RPC install writes it, scepter's L2 lanes open
//! it via [`crate::Registry`]). There is no archive to produce: the
//! bundle IS a directory, so the packer emits `<out>/<plugin-id>/`
//! containing:
//!
//! - the package's manifest, **sealed**: a `[trust]` section naming the
//!   signature file (a declared `trust.signature` path is honored;
//!   otherwise `<id>.sig` is injected with `min-trust = "signed"`), and
//!   a pinned `sha256` on every file payload that lacked one;
//! - every file of the package directory, copied verbatim (walked in
//!   sorted order; nothing is excluded except a stale file at the
//!   signature path — the signature output itself);
//! - the signature file: the raw 64-byte Ed25519 signature over
//!   **C4 v2** — the sealed manifest bytes, then resource file payload
//!   bytes in manifest order, then attachment file payload bytes in
//!   manifest order, then migration file bytes (`up`, then `down` per
//!   migration, in manifest order). [`crate::store::scan_with_keys`]
//!   assembles the exact same byte stream.
//!
//! The signing key comes from the `AKIVILI_SIGNING_KEY` environment
//! variable (64 hex chars — the 32-byte Ed25519 seed). Without it the
//! packer refuses with a setup hint; the `--insecure-dev-key` escape
//! hatch generates an ephemeral key pair for local store seeding and
//! marks every line of its output loudly.

use std::fs;
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use thiserror::Error;

use crate::manifest::{MANIFEST_FILE, MinTrust, Payload, PluginManifest, TrustSection};
use crate::registry::DEFAULT_MAX_PAYLOAD_BYTES;
use crate::store::{confined_payload_path, read_capped, sha256_hex};

/// The environment variable the signing key (hex seed) is read from.
pub const SIGNING_KEY_ENV: &str = "AKIVILI_SIGNING_KEY";

/// One file of the packed bundle, as reported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileDigest {
    /// Path relative to the bundle directory.
    pub path: PathBuf,
    /// SHA-256 of the file's bytes (64 lowercase hex chars).
    pub sha256: String,
    /// File size in bytes.
    pub bytes: u64,
}

/// What a successful [`pack`] produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackReport {
    /// The packed plugin's id.
    pub plugin_id: String,
    /// The packed plugin's version.
    pub version: String,
    /// The bundle directory written (`<out-dir>/<plugin-id>`), already in
    /// the store-installable shape — copying it into a store root is the
    /// whole install.
    pub bundle_dir: PathBuf,
    /// How many files the bundle carries (everything except the
    /// signature file).
    pub file_count: usize,
    /// Total bytes across those files.
    pub total_bytes: u64,
    /// Per-file digests, sorted by path.
    pub files: Vec<FileDigest>,
    /// The signature bytes, hex-encoded (64 raw bytes on disk).
    pub signature_hex: String,
    /// The verifying key that checks this signature, hex-encoded
    /// (32 bytes) — what a host's publisher-key list must carry.
    pub verifying_key_hex: String,
    /// A stable fingerprint of the verifying key (hex prefix of its
    /// SHA-256) — the `key_id` convention of [`crate::trust::PublisherKey`].
    pub key_id: String,
    /// Whether the signature was made with an ephemeral `--insecure-dev-key`.
    pub insecure_dev_key: bool,
}

impl PackReport {
    /// The exact install/verify instructions for the produced bundle.
    pub fn install_instructions(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "install: copy the bundle directory into a plugin store root\n  \
             cp -r {} <store-dir>/\n",
            self.bundle_dir.display()
        ));
        out.push_str(&format!(
            "verify: the host must carry the publisher key in its list\n  \
             verifying key (hex): {}\n  \
             key id: {}  (e.g. RegistryOptions::publisher_keys with\n  \
             PublisherKey {{ key_id, bytes }} from the hex above)\n",
            self.verifying_key_hex, self.key_id
        ));
        out.push_str(
            "note: chest's admin.plugins.install RPC is inline-only; file-payload\n  \
             bundles install by copying the directory into the store root\n",
        );
        out
    }

    /// The human-facing summary printed by the CLI.
    pub fn summary(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "packed plugin '{}' v{}\n",
            self.plugin_id, self.version
        ));
        out.push_str(&format!("bundle: {}\n", self.bundle_dir.display()));
        out.push_str(&format!(
            "files: {} ({} bytes total)\n",
            self.file_count, self.total_bytes
        ));
        for file in &self.files {
            out.push_str(&format!(
                "  sha256 {}  {:>9} B  {}\n",
                file.sha256,
                file.bytes,
                file.path.display()
            ));
        }
        out.push_str(&format!("signature: {}\n", self.signature_hex));
        out.push_str(&format!(
            "verifying key: {} (key id: {})\n",
            self.verifying_key_hex, self.key_id
        ));
        if self.insecure_dev_key {
            out.push_str(
                "!! INSECURE-DEV-KEY — EPHEMERAL KEY, LOCAL SEEDING ONLY, NEVER PRODUCTION !!\n",
            );
        }
        out.push_str(&self.install_instructions());
        out
    }
}

/// Why a pack failed. Every variant is fail-loud: the packer never
/// writes a bundle it could not fully seal.
#[derive(Debug, Error)]
pub enum PackError {
    /// The manifest is missing, unparseable, or fails `validate()`.
    #[error("invalid manifest: {0}")]
    InvalidManifest(String),
    /// No signing key was available (env var unset and no dev-key flag).
    #[error("no signing key: {0}")]
    MissingKey(String),
    /// The signing key could not be parsed.
    #[error("bad signing key: {0}")]
    BadKey(String),
    /// A file payload of the package failed its read-time verification
    /// (missing, escaping the directory, over the cap, or a declared
    /// digest mismatch) — the same refusal the store scan would make.
    #[error("payload rejected: {0}")]
    Payload(String),
    /// Filesystem failure while reading the package or writing the bundle.
    #[error("io: {0}")]
    Io(String),
    /// The target bundle directory already exists; the packer never
    /// clobbers a previous bundle silently.
    #[error("bundle directory already exists: {0}")]
    Exists(PathBuf),
}

/// A resolved signing key: the key plus how it was obtained.
#[derive(Debug)]
pub struct ResolvedKey {
    /// The Ed25519 signing key.
    pub key: SigningKey,
    /// Whether this is an ephemeral `--insecure-dev-key` key.
    pub insecure_dev: bool,
}

/// Parses a 64-hex-char signing key (the 32-byte Ed25519 seed), matching
/// the lowercase-hex convention the registry uses for digests.
pub fn parse_signing_key(hex: &str) -> Result<SigningKey, PackError> {
    let hex = hex.trim();
    if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(PackError::BadKey(format!(
            "expected 64 hex chars (32-byte Ed25519 seed), got {} char(s)",
            hex.len()
        )));
    }
    let mut seed = [0u8; 32];
    for (i, byte) in seed.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|e| PackError::BadKey(format!("hex decode: {e}")))?;
    }
    Ok(SigningKey::from_bytes(&seed))
}

/// Resolves the signing key the way the CLI does, as a pure function so
/// tests never touch process state: the env value wins; without one the
/// `--insecure-dev-key` lane generates an ephemeral key; otherwise this
/// is a [`PackError::MissingKey`] refusal carrying the setup hint.
pub fn resolve_signing_key(
    env_value: Option<&str>,
    allow_dev: bool,
) -> Result<ResolvedKey, PackError> {
    if let Some(hex) = env_value {
        return Ok(ResolvedKey {
            key: parse_signing_key(hex)?,
            insecure_dev: false,
        });
    }
    if allow_dev {
        return Ok(ResolvedKey {
            key: SigningKey::generate(&mut OsRng),
            insecure_dev: true,
        });
    }
    Err(PackError::MissingKey(format!(
        "set {SIGNING_KEY_ENV} to a 64-hex-char Ed25519 seed (hex-encode the 32 seed bytes), \
         or pass --insecure-dev-key for an ephemeral local-seeding key"
    )))
}

/// A stable fingerprint for a verifying key: the first 16 hex chars of
/// its SHA-256 — the `key_id` shape [`crate::trust::PublisherKey`]
/// diagnostics expect.
pub fn key_fingerprint(verifying: &[u8; 32]) -> String {
    sha256_hex(verifying)[..16].to_string()
}

/// Hex-encodes bytes (lowercase).
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Walks `dir` recursively and returns every regular file's relative
/// path, sorted for determinism. A symlink refuses the whole pack: file
/// payloads are confined to real files inside the plugin directory, and
/// a symlink hop is exactly what the store's confinement check rejects
/// — a bundle carrying one would install a plugin the scan refuses.
fn walk_files(dir: &Path) -> Result<Vec<PathBuf>, PackError> {
    fn visit(dir: &Path, prefix: &Path, out: &mut Vec<PathBuf>) -> Result<(), PackError> {
        let entries = fs::read_dir(dir)
            .map_err(|e| PackError::Io(format!("cannot read {}: {e}", dir.display())))?;
        for entry in entries {
            let entry = entry.map_err(|e| {
                PackError::Io(format!("cannot read entry in {}: {e}", dir.display()))
            })?;
            let name = entry.file_name();
            let rel = prefix.join(&name);
            let file_type = entry.file_type().map_err(|e| {
                PackError::Io(format!("cannot stat {}: {e}", entry.path().display()))
            })?;
            if file_type.is_dir() {
                visit(&entry.path(), &rel, out)?;
            } else if file_type.is_symlink() {
                return Err(PackError::Io(format!(
                    "symlink in package is not packable: {}",
                    entry.path().display()
                )));
            } else {
                out.push(rel);
            }
        }
        Ok(())
    }
    let mut files = Vec::new();
    visit(dir, Path::new(""), &mut files)?;
    files.sort();
    Ok(files)
}

/// Reads one file payload the way the store scan does (confined, capped)
/// and checks its declared digest, returning `(relative path, bytes)`.
fn read_payload_checked(
    package_dir: &Path,
    plugin_id: &str,
    path: &Path,
    declared: &Option<String>,
    label: &str,
) -> Result<Vec<u8>, PackError> {
    let full = confined_payload_path(package_dir, path).map_err(|reason| {
        PackError::Payload(format!(
            "plugin '{plugin_id}' {label} '{}': {reason}",
            path.display()
        ))
    })?;
    let bytes = read_capped(&full, DEFAULT_MAX_PAYLOAD_BYTES).map_err(|e| {
        PackError::Payload(format!(
            "plugin '{plugin_id}' {label} '{}': {}",
            path.display(),
            e.reason(&full)
        ))
    })?;
    if let Some(expected) = declared {
        let actual = sha256_hex(&bytes);
        if expected != &actual {
            return Err(PackError::Payload(format!(
                "plugin '{plugin_id}' {label} '{}': sha256 mismatch: declared {expected}, actual {actual}",
                path.display()
            )));
        }
    }
    Ok(bytes)
}

/// (payload path, digest) pairs in signing order — the pinning list.
type PayloadDigestList = Vec<(PathBuf, String)>;

/// Assembles the C4 payload concatenation from a parsed manifest —
/// resource file bytes in manifest order, then attachment file bytes in
/// manifest order, then migration file bytes (`up` then `down` per
/// migration, in manifest order) — reading each payload with the store's
/// own confinement, cap, and digest checks. The sealed manifest bytes
/// are prepended by the caller (C4 v2).
fn assemble_payload_concat(
    package_dir: &Path,
    manifest: &PluginManifest,
) -> Result<(Vec<u8>, PayloadDigestList), PackError> {
    let mut concat: Vec<u8> = Vec::new();
    // (payload path, digest) in signing order — also the pinning list.
    let mut payload_files: Vec<(PathBuf, String)> = Vec::new();

    let mut push =
        |path: &Path, declared: &Option<String>, label: String| -> Result<(), PackError> {
            let bytes = read_payload_checked(package_dir, &manifest.id, path, declared, &label)?;
            payload_files.push((path.to_path_buf(), sha256_hex(&bytes)));
            concat.extend_from_slice(&bytes);
            Ok(())
        };

    for entry in &manifest.resources {
        if let Payload::File { path, sha256 } = &entry.payload {
            push(path, sha256, format!("resource kind '{}'", entry.kind))?;
        }
    }
    for attachment in &manifest.attachments {
        if let Some(Payload::File { path, sha256 }) = &attachment.payload {
            let label = attachment
                .kind
                .as_ref()
                .map(|kind| format!("attachment kind '{kind}'"))
                .unwrap_or_else(|| format!("attachment surface '{}'", attachment.surface));
            push(path, sha256, label)?;
        }
    }
    for migration in &manifest.migrations {
        let up_sha = Some(migration.sha256.clone());
        push(
            &migration.up,
            &up_sha,
            format!("migration '{}' up", migration.id),
        )?;
        if let Some(down) = &migration.down {
            let no_digest: Option<String> = None;
            push(
                down,
                &no_digest,
                format!("migration '{}' down", migration.id),
            )?;
        }
    }
    Ok((concat, payload_files))
}

/// Seals the manifest for the bundle and serializes it (the same
/// `toml::to_string_pretty` chest's install path uses to write
/// manifests): honors or injects the `[trust]` section, pins `sha256`
/// (from `digests`) on every file payload that lacks one, and
/// re-validates the result. The manifest is outside the signed byte
/// range, so these edits never invalidate the signature.
fn seal_manifest(
    manifest: &PluginManifest,
    sig_rel: &Path,
    digests: &std::collections::HashMap<PathBuf, String>,
) -> Result<String, PackError> {
    let mut sealed = manifest.clone();

    let trust = sealed.trust.get_or_insert(TrustSection {
        signature: None,
        min_trust: MinTrust::Unsigned,
    });
    if trust.signature.is_none() {
        trust.signature = Some(sig_rel.display().to_string());
    }
    if trust.min_trust == MinTrust::Unsigned {
        trust.min_trust = MinTrust::Signed;
    }

    for entry in &mut sealed.resources {
        if let Payload::File { path, sha256 } = &mut entry.payload
            && sha256.is_none()
        {
            *sha256 = digests.get(path).cloned();
        }
    }
    for attachment in &mut sealed.attachments {
        if let Some(Payload::File { path, sha256 }) = &mut attachment.payload
            && sha256.is_none()
        {
            *sha256 = digests.get(path).cloned();
        }
    }

    sealed.validate().map_err(|e| {
        PackError::InvalidManifest(format!("sealed manifest no longer validates: {e}"))
    })?;
    toml::to_string_pretty(&sealed).map_err(|e| {
        PackError::InvalidManifest(format!("sealed manifest is not representable: {e}"))
    })
}

/// Writes the bundle directory: creates it fresh, copies every package
/// file verbatim (the signature path excluded — that is the packer's
/// output, never a copy), writes the sealed manifest over the copied
/// one, writes the raw 64-byte signature, then digests the bundle as
/// written. Returns the per-file digest list and byte total for the
/// report; the caller rolls the directory back on error.
fn write_bundle(
    bundle_dir: &Path,
    package_dir: &Path,
    package_files: &[PathBuf],
    sig_rel: &Path,
    sealed_text: &str,
    signature: &[u8; 64],
) -> Result<(Vec<FileDigest>, u64), PackError> {
    let write_err = |e: std::io::Error, target: &Path| {
        PackError::Io(format!("cannot write {}: {e}", target.display()))
    };
    fs::create_dir_all(bundle_dir)
        .map_err(|e| PackError::Io(format!("cannot create {}: {e}", bundle_dir.display())))?;
    for rel in package_files {
        if rel == sig_rel {
            continue; // the packer's own output, never copied from source
        }
        let target = bundle_dir.join(rel);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(|e| write_err(e, parent))?;
        }
        fs::copy(package_dir.join(rel), &target).map_err(|e| write_err(e, &target))?;
    }
    let sealed_manifest_path = bundle_dir.join(MANIFEST_FILE);
    fs::write(&sealed_manifest_path, sealed_text)
        .map_err(|e| write_err(e, &sealed_manifest_path))?;
    let sig_path = bundle_dir.join(sig_rel);
    if let Some(parent) = sig_path.parent() {
        fs::create_dir_all(parent).map_err(|e| write_err(e, parent))?;
    }
    fs::write(&sig_path, signature).map_err(|e| write_err(e, &sig_path))?;

    // The digest report reflects the bundle as written (the sealed
    // manifest differs from the source manifest, so digest the bundle).
    let mut files = Vec::with_capacity(package_files.len());
    let mut total_bytes = 0u64;
    for rel in package_files {
        if rel == sig_rel {
            continue;
        }
        let bytes = fs::read(bundle_dir.join(rel))
            .map_err(|e| PackError::Io(format!("cannot re-read bundled {rel:?}: {e}")))?;
        total_bytes += bytes.len() as u64;
        files.push(FileDigest {
            path: rel.clone(),
            sha256: sha256_hex(&bytes),
            bytes: bytes.len() as u64,
        });
    }
    Ok((files, total_bytes))
}

/// Packs `package_dir` into `<out_dir>/<plugin-id>/`, signing with `key`.
///
/// The output directory takes the store's shape directly: pointing
/// `out_dir` at a plugin store root and opening the registry with the
/// publisher key installed is the full roundtrip (see the tests).
pub fn pack(package_dir: &Path, out_dir: &Path, key: &SigningKey) -> Result<PackReport, PackError> {
    // 1) Parse and validate the manifest.
    let manifest_path = package_dir.join(MANIFEST_FILE);
    let raw = fs::read_to_string(&manifest_path).map_err(|e| {
        PackError::InvalidManifest(format!("cannot read {}: {e}", manifest_path.display()))
    })?;
    let manifest: PluginManifest = toml::from_str(&raw)
        .map_err(|e| PackError::InvalidManifest(format!("cannot parse {MANIFEST_FILE}: {e}")))?;
    manifest
        .validate()
        .map_err(|e| PackError::InvalidManifest(e.to_string()))?;

    // 2) Walk every file of the package (deterministic order).
    let package_files = walk_files(package_dir)?;

    // 3) The signature path: a declared `trust.signature` wins, else
    // `<id>.sig`. A stale file at that path is the one exclusion from
    // both the copy and the digest report — it is the packer's output.
    // The path must stay relative and inside the bundle (the store's
    // confinement rule for signature files) — an escaping declaration
    // must refuse, never write outside the bundle directory.
    let sig_rel = PathBuf::from(
        manifest
            .trust
            .as_ref()
            .and_then(|t| t.signature.clone())
            .unwrap_or_else(|| format!("{}.sig", manifest.id)),
    );
    if sig_rel.is_absolute()
        || sig_rel
            .components()
            .any(|c| !matches!(c, std::path::Component::Normal(_)))
    {
        return Err(PackError::InvalidManifest(format!(
            "trust.signature '{}' must be a relative path inside the plugin directory",
            sig_rel.display()
        )));
    }
    // The signature path is the packer's output, never a payload: a
    // collision would overwrite a declared file with 64 signature bytes
    // and produce a bundle the store rejects (or, worse, a payload
    // substitution). Refuse before writing anything.
    let mut declared_paths: Vec<&Path> = Vec::new();
    for resource in &manifest.resources {
        if let Payload::File { path, .. } = &resource.payload {
            declared_paths.push(path);
        }
    }
    for attachment in &manifest.attachments {
        if let Some(Payload::File { path, .. }) = &attachment.payload {
            declared_paths.push(path);
        }
    }
    for migration in &manifest.migrations {
        declared_paths.push(&migration.up);
        if let Some(down) = &migration.down {
            declared_paths.push(down);
        }
    }
    if sig_rel == Path::new(crate::manifest::MANIFEST_FILE)
        || declared_paths.contains(&sig_rel.as_path())
    {
        return Err(PackError::InvalidManifest(format!(
            "trust.signature '{}' collides with a declared payload path",
            sig_rel.display()
        )));
    }

    // 4) Assemble the C4 payload concat (resources, then attachments,
    // then migration files) with the store's own read-time checks.
    let (concat, payload_files) = assemble_payload_concat(package_dir, &manifest)?;

    // 5) Seal the manifest (trust + pinned digests) and re-validate.
    let digests: std::collections::HashMap<PathBuf, String> = payload_files.into_iter().collect();
    let sealed_text = seal_manifest(&manifest, &sig_rel, &digests)?;

    // 6) Sign C4 v2: the sealed manifest bytes first, then the payload
    // concat. Signing the manifest closes the "append a migration (or
    // rewrite agents/capabilities) after sealing" class.
    let mut signed_bytes = Vec::with_capacity(sealed_text.len() + concat.len());
    signed_bytes.extend_from_slice(sealed_text.as_bytes());
    signed_bytes.extend_from_slice(&concat);
    let signature = key.sign(&signed_bytes);

    // 6+7) Write the bundle (fresh directory, verbatim copies, sealed
    // manifest, signature last), then digest it as written. Any failure
    // rolls the partial bundle back — a half-written directory must not
    // block the retry via `PackError::Exists` (chest's install applies
    // the same rollback discipline).
    let bundle_dir = out_dir.join(&manifest.id);
    if bundle_dir.exists() {
        return Err(PackError::Exists(bundle_dir));
    }
    let written = match write_bundle(
        &bundle_dir,
        package_dir,
        &package_files,
        &sig_rel,
        &sealed_text,
        &signature.to_bytes(),
    ) {
        Ok(written) => written,
        Err(e) => {
            let _ = fs::remove_dir_all(&bundle_dir); // best-effort rollback
            return Err(e);
        }
    };
    let (files, total_bytes) = written;

    let verifying = key.verifying_key().to_bytes();
    Ok(PackReport {
        plugin_id: manifest.id.clone(),
        version: manifest.version.clone(),
        bundle_dir,
        file_count: files.len(),
        total_bytes,
        files,
        signature_hex: hex(&signature.to_bytes()),
        verifying_key_hex: hex(&verifying),
        key_id: key_fingerprint(&verifying),
        insecure_dev_key: false,
    })
}

/// [`pack`] with an ephemeral `--insecure-dev-key` key; the report (and
/// everything the CLI prints from it) is marked insecure. The signing
/// seed is returned so the caller can print it for local re-seeding.
pub fn pack_dev_key(
    package_dir: &Path,
    out_dir: &Path,
) -> Result<(PackReport, SigningKey), PackError> {
    let key = SigningKey::generate(&mut OsRng);
    let mut report = pack(package_dir, out_dir, &key)?;
    report.insecure_dev_key = true;
    Ok((report, key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::MANIFEST_FILE;
    use crate::registry::Registry;
    use crate::trust::PublisherKey;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    /// A fixture package: two file resources, one file attachment, one
    /// unreferenced docs file, and NO `[trust]` section — the packer
    /// must inject it.
    const FIXTURE_MANIFEST: &str = r#"schema = 1
id = "pack-fixture"
version = "1.0.0"
provider = "official"
form = "web.vue-module"

[[resources]]
kind = "webui.style"
[resources.payload.File]
path = "style.css"

[[resources]]
kind = "webui.theme"
[resources.payload.File]
path = "assets/theme.bin"

[[attachments]]
surface = "engine"
form = "process.rpc"
kind = "engine.agent"
[attachments.payload.File]
path = "agent.bin"
"#;

    /// Writes the fixture package under `<root>/<name>` and returns its
    /// path.
    fn fixture_package(root: &Path, name: &str) -> PathBuf {
        let pkg = root.join(name);
        fs::create_dir_all(pkg.join("assets")).unwrap();
        fs::create_dir_all(pkg.join("res")).unwrap();
        fs::write(pkg.join(MANIFEST_FILE), FIXTURE_MANIFEST).unwrap();
        fs::write(pkg.join("style.css"), b"RESOURCE-STYLE").unwrap();
        fs::write(pkg.join("assets/theme.bin"), b"RESOURCE-THEME").unwrap();
        fs::write(pkg.join("agent.bin"), b"ATTACHMENT-AGENT").unwrap();
        fs::write(pkg.join("res/notes.md"), b"unreferenced docs ride along").unwrap();
        pkg
    }

    fn publisher_key(key: &SigningKey, key_id: &str) -> Vec<PublisherKey> {
        vec![PublisherKey {
            key_id: key_id.to_string(),
            bytes: key.verifying_key().to_bytes(),
        }]
    }

    /// The bundle lands directly in a store root: `out` IS the store.
    fn open_store(out: &Path, key: &SigningKey, key_id: &str) -> Registry {
        Registry::options()
            .publisher_keys(publisher_key(key, key_id))
            .open(out, &out.join("audit.jsonl"))
            .expect("the keyed store opens")
    }

    #[test]
    fn pack_seals_and_the_store_scan_verifies_the_roundtrip() {
        let root = tempfile::tempdir().unwrap();
        let pkg = fixture_package(root.path(), "pkg");
        let key = SigningKey::generate(&mut OsRng);

        let report = pack(&pkg, &root.path().join("store"), &key).expect("packs");

        // Bundle shape: <out>/<id>/, store-installable.
        assert_eq!(report.plugin_id, "pack-fixture");
        assert_eq!(
            report.bundle_dir,
            root.path().join("store/pack-fixture"),
            "the bundle is a plugin directory named after the id"
        );
        assert!(report.bundle_dir.join(MANIFEST_FILE).exists());

        // The sealed manifest: injected trust naming the sig file, and a
        // pinned digest for every file payload.
        let sealed = fs::read_to_string(report.bundle_dir.join(MANIFEST_FILE)).unwrap();
        assert!(
            sealed.contains("signature = \"pack-fixture.sig\""),
            "trust.signature must be injected: {sealed}"
        );
        assert!(
            sealed.contains("min-trust = \"signed\""),
            "min-trust must be lifted to signed: {sealed}"
        );
        let style_sha = sha256_hex(b"RESOURCE-STYLE");
        assert!(
            sealed.contains(&style_sha),
            "the style.css digest must be pinned: {sealed}"
        );
        assert!(sealed.contains(&sha256_hex(b"ATTACHMENT-AGENT")));

        // The signature file: 64 raw bytes.
        let sig = fs::read(report.bundle_dir.join("pack-fixture.sig")).unwrap();
        assert_eq!(sig.len(), 64);

        // The digest report: every file except the signature itself.
        let mut reported: Vec<String> = report
            .files
            .iter()
            .map(|f| f.path.display().to_string())
            .collect();
        reported.sort();
        assert_eq!(
            reported,
            vec![
                "agent.bin",
                "akivili.plugin.toml",
                "assets/theme.bin",
                "res/notes.md",
                "style.css",
            ],
            "the report covers every file, unreferenced included, sig excluded"
        );
        assert_eq!(report.file_count, 5);
        assert!(report.total_bytes > 0);

        // THE ROUNDTRIP: the existing store machinery discovers and
        // verifies the bundle.
        let registry = open_store(&root.path().join("store"), &key, &report.key_id);
        let found = registry
            .plugins()
            .iter()
            .find(|r| r.manifest.id == "pack-fixture")
            .expect("the packed bundle must be discovered");
        assert_eq!(found.manifest.version, "1.0.0");
        assert!(
            registry.rejections().is_empty(),
            "no rejections: {:?}",
            registry.rejections()
        );

        // The summary carries the install instruction and key material.
        let text = report.summary();
        assert!(text.contains("packed plugin 'pack-fixture' v1.0.0"));
        assert!(text.contains("verifying key"));
        assert!(text.contains("cp -r"));
        assert!(
            !text.contains("INSECURE"),
            "an env-key pack is not dev-marked"
        );
    }

    #[test]
    fn a_tampered_payload_fails_the_digest_gate() {
        let root = tempfile::tempdir().unwrap();
        let pkg = fixture_package(root.path(), "pkg");
        let key = SigningKey::generate(&mut OsRng);
        let report = pack(&pkg, &root.path().join("store"), &key).unwrap();

        // Flip one byte in one payload file of the installed bundle.
        let style = report.bundle_dir.join("style.css");
        fs::write(&style, b"RESOURCE-STYLF").unwrap();

        let registry = open_store(&root.path().join("store"), &key, &report.key_id);
        assert!(
            registry
                .rejections()
                .iter()
                .any(|r| r.reason.contains("sha256 mismatch")),
            "the pinned digest must catch the flip: {:?}",
            registry.rejections()
        );
        assert!(
            registry
                .plugins()
                .iter()
                .all(|r| r.manifest.id != "pack-fixture")
        );
    }

    #[test]
    fn a_forged_digest_still_fails_the_signature_gate() {
        let root = tempfile::tempdir().unwrap();
        let pkg = fixture_package(root.path(), "pkg");
        let key = SigningKey::generate(&mut OsRng);
        let report = pack(&pkg, &root.path().join("store"), &key).unwrap();

        // Flip one byte AND forge the manifest digest over it: the
        // sha256 gate passes, the Ed25519 trust gate must not.
        fs::write(report.bundle_dir.join("style.css"), b"RESOURCE-STYLF").unwrap();
        let sealed = fs::read_to_string(report.bundle_dir.join(MANIFEST_FILE)).unwrap();
        let old = sha256_hex(b"RESOURCE-STYLE");
        let forged = sha256_hex(b"RESOURCE-STYLF");
        assert!(sealed.contains(&old), "the packer pinned the honest digest");
        fs::write(
            report.bundle_dir.join(MANIFEST_FILE),
            sealed.replace(&old, &forged),
        )
        .unwrap();

        let registry = open_store(&root.path().join("store"), &key, &report.key_id);
        assert!(
            registry
                .rejections()
                .iter()
                .any(|r| r.reason.contains("signature mismatch")),
            "the trust gate must catch what the digest gate cannot: {:?}",
            registry.rejections()
        );
        assert!(
            registry
                .plugins()
                .iter()
                .all(|r| r.manifest.id != "pack-fixture")
        );
    }

    #[test]
    fn a_stale_signature_file_is_replaced_not_copied() {
        let root = tempfile::tempdir().unwrap();
        let pkg = fixture_package(root.path(), "pkg");
        // A stale signature from an earlier pack: garbage bytes.
        fs::write(pkg.join("pack-fixture.sig"), [0u8; 64]).unwrap();
        let key = SigningKey::generate(&mut OsRng);

        let report = pack(&pkg, &root.path().join("store"), &key).expect("stale sig is replaced");

        let registry = open_store(&root.path().join("store"), &key, &report.key_id);
        assert!(
            registry
                .plugins()
                .iter()
                .any(|r| r.manifest.id == "pack-fixture"),
            "the fresh signature must verify, not the stale bytes: {:?}",
            registry.rejections()
        );
    }

    /// Ported from the superseded #65 lineage: the stale-replacement
    /// guarantee at a manifest-DECLARED signature path (the default-path
    /// case has its own test above).
    #[test]
    fn a_stale_signature_at_a_declared_path_is_replaced() {
        let root = tempfile::tempdir().unwrap();
        let pkg = fixture_package(root.path(), "pkg");
        let manifest = fs::read_to_string(pkg.join(MANIFEST_FILE)).unwrap();
        fs::write(
            pkg.join(MANIFEST_FILE),
            format!(
                "{manifest}\n[trust]\nsignature = \"sigs/agent.sig\"\nmin-trust = \"signed\"\n"
            ),
        )
        .unwrap();
        // A stale signature from an earlier pack sits at the DECLARED
        // path — the packer's own output location.
        fs::create_dir_all(pkg.join("sigs")).unwrap();
        fs::write(pkg.join("sigs/agent.sig"), [0u8; 64]).unwrap();

        let key = SigningKey::generate(&mut OsRng);
        let report = pack(&pkg, &root.path().join("store"), &key)
            .expect("a stale sig at the declared path is replaced, not copied");

        let sig = fs::read(report.bundle_dir.join("sigs/agent.sig")).unwrap();
        assert_eq!(sig.len(), 64);
        assert_ne!(
            sig,
            vec![0u8; 64],
            "the bundle carries the fresh signature, not the stale bytes"
        );
        let registry = open_store(&root.path().join("store"), &key, &report.key_id);
        assert!(
            registry
                .plugins()
                .iter()
                .any(|r| r.manifest.id == "pack-fixture"),
            "the fresh signature must verify: {:?}",
            registry.rejections()
        );
    }

    /// Ported from the superseded #65 lineage.
    #[test]
    fn two_resources_on_one_file_sign_and_store_the_doubled_concat() {
        let root = tempfile::tempdir().unwrap();
        let pkg = fixture_package(root.path(), "pkg");
        // Point the second resource at the SAME file as the first: the
        // C4 concat then carries style.css's bytes twice, and both the
        // signature and the store's re-assembly must agree on that.
        let manifest = fs::read_to_string(pkg.join(MANIFEST_FILE)).unwrap();
        fs::write(
            pkg.join(MANIFEST_FILE),
            manifest.replace("path = \"assets/theme.bin\"", "path = \"style.css\""),
        )
        .unwrap();

        let key = SigningKey::generate(&mut OsRng);
        let report =
            pack(&pkg, &root.path().join("store"), &key).expect("same-file resources pack");

        let registry = open_store(&root.path().join("store"), &key, &report.key_id);
        assert!(
            registry.rejections().is_empty(),
            "the doubled concat must verify consistently: {:?}",
            registry.rejections()
        );
        assert!(
            registry
                .plugins()
                .iter()
                .any(|r| r.manifest.id == "pack-fixture")
        );
        // The walk-based report counts the shared file once, and the
        // sealed manifest pins the same digest on both entries.
        assert_eq!(
            report
                .files
                .iter()
                .filter(|f| f.path == Path::new("style.css"))
                .count(),
            1
        );
        let sealed = fs::read_to_string(report.bundle_dir.join(MANIFEST_FILE)).unwrap();
        assert_eq!(
            sealed.matches(&sha256_hex(b"RESOURCE-STYLE")).count(),
            2,
            "both entries carry the same pin: {sealed}"
        );
    }

    /// Ported from the superseded #65 lineage, adapted to #67: hosts may
    /// now pin providers via [`crate::registry::RegistryOptions::require_signature_for`]
    /// so their plugins can never ride the unsigned lane at all. This
    /// test covers the (still-default) unpinned host: the signature
    /// backstop removed — sig file deleted, `[trust]` stripped from the
    /// sealed manifest (the manifest is outside the signed byte range by
    /// design, so an attacker who can rewrite an installed bundle can
    /// always do this) — and the store opened WITHOUT publisher keys.
    /// The pinned digests the packer injected are then the only gate
    /// left, so a one-byte payload tamper must still reject.
    #[test]
    fn pins_are_load_bearing_when_the_signature_lane_is_stripped() {
        let root = tempfile::tempdir().unwrap();
        let pkg = fixture_package(root.path(), "pkg");
        let key = SigningKey::generate(&mut OsRng);
        let report = pack(&pkg, &root.path().join("store"), &key).unwrap();

        fs::remove_file(report.bundle_dir.join("pack-fixture.sig")).unwrap();
        let sealed = fs::read_to_string(report.bundle_dir.join(MANIFEST_FILE)).unwrap();
        let mut value: toml::Value = toml::from_str(&sealed).unwrap();
        value.as_table_mut().unwrap().remove("trust");
        fs::write(
            report.bundle_dir.join(MANIFEST_FILE),
            toml::to_string_pretty(&value).unwrap(),
        )
        .unwrap();

        // Control: the stripped-but-honest bundle is still acceptable in
        // the unsigned lane (this is what an unsigned dev plugin looks
        // like) — the strip itself must not be what rejects.
        let store = root.path().join("store");
        let honest = Registry::open_quiet(&store, &root.path().join("audit-honest.jsonl")).unwrap();
        assert!(
            honest.rejections().is_empty(),
            "the control must be clean: {:?}",
            honest.rejections()
        );
        assert!(
            honest
                .plugins()
                .iter()
                .any(|r| r.manifest.id == "pack-fixture")
        );

        // Tamper one byte: no signature exists to catch it — the pin must.
        fs::write(report.bundle_dir.join("style.css"), b"RESOURCE-STYLF").unwrap();
        let tampered =
            Registry::open_quiet(&store, &root.path().join("audit-tampered.jsonl")).unwrap();
        assert!(
            tampered
                .rejections()
                .iter()
                .any(|r| r.reason.contains("sha256 mismatch")),
            "the pin layer is load-bearing without signatures: {:?}",
            tampered.rejections()
        );
        assert!(
            tampered
                .plugins()
                .iter()
                .all(|r| r.manifest.id != "pack-fixture")
        );
    }

    #[test]
    fn a_declared_trust_signature_path_is_honored() {
        let root = tempfile::tempdir().unwrap();
        let pkg = fixture_package(root.path(), "pkg");
        let manifest = fs::read_to_string(pkg.join(MANIFEST_FILE)).unwrap();
        fs::write(
            pkg.join(MANIFEST_FILE),
            format!(
                "{manifest}\n[trust]\nsignature = \"sigs/agent.sig\"\nmin-trust = \"signed\"\n"
            ),
        )
        .unwrap();

        let key = SigningKey::generate(&mut OsRng);
        let report = pack(&pkg, &root.path().join("store"), &key).expect("packs");

        assert!(
            report.bundle_dir.join("sigs/agent.sig").exists(),
            "the declared path is the signature output"
        );
        let registry = open_store(&root.path().join("store"), &key, &report.key_id);
        assert!(
            registry
                .plugins()
                .iter()
                .any(|r| r.manifest.id == "pack-fixture")
        );
    }

    #[test]
    fn an_invalid_manifest_refuses_before_writing_anything() {
        let root = tempfile::tempdir().unwrap();
        let pkg = root.path().join("pkg");
        fs::create_dir_all(&pkg).unwrap();
        fs::write(
            pkg.join(MANIFEST_FILE),
            FIXTURE_MANIFEST.replace("version = \"1.0.0\"", "version = \"1\""),
        )
        .unwrap();

        let key = SigningKey::generate(&mut OsRng);
        let err = pack(&pkg, &root.path().join("store"), &key).expect_err("non-SemVer refuses");
        assert!(matches!(err, PackError::InvalidManifest(_)), "{err}");
        assert!(
            !root.path().join("store").exists(),
            "no bundle may be written on refusal"
        );
    }

    #[test]
    fn a_declared_digest_mismatch_refuses() {
        let root = tempfile::tempdir().unwrap();
        let pkg = fixture_package(root.path(), "pkg");
        let manifest = fs::read_to_string(pkg.join(MANIFEST_FILE)).unwrap();
        fs::write(
            pkg.join(MANIFEST_FILE),
            manifest.replace(
                "path = \"style.css\"",
                &format!("path = \"style.css\"\nsha256 = \"{}\"", "0".repeat(64)),
            ),
        )
        .unwrap();

        let key = SigningKey::generate(&mut OsRng);
        let err = pack(&pkg, &root.path().join("store"), &key).expect_err("bad digest refuses");
        assert!(
            err.to_string().contains("sha256 mismatch"),
            "the packer applies the store's digest gate: {err}"
        );
    }

    #[test]
    fn a_missing_payload_file_refuses() {
        let root = tempfile::tempdir().unwrap();
        let pkg = fixture_package(root.path(), "pkg");
        fs::remove_file(pkg.join("agent.bin")).unwrap();

        let key = SigningKey::generate(&mut OsRng);
        let err =
            pack(&pkg, &root.path().join("store"), &key).expect_err("missing payload refuses");
        assert!(err.to_string().contains("payload file missing"), "{err}");
    }

    #[test]
    fn packing_twice_refuses_rather_than_clobbering() {
        let root = tempfile::tempdir().unwrap();
        let pkg = fixture_package(root.path(), "pkg");
        let key = SigningKey::generate(&mut OsRng);
        let out = root.path().join("store");
        pack(&pkg, &out, &key).expect("first pack");
        let err = pack(&pkg, &out, &key).expect_err("second pack refuses");
        assert!(matches!(err, PackError::Exists(_)), "{err}");
    }

    #[test]
    fn missing_key_refuses_with_the_setup_hint() {
        let err = resolve_signing_key(None, false).expect_err("no env, no flag");
        assert!(matches!(err, PackError::MissingKey(_)), "{err}");
        assert!(
            err.to_string().contains(SIGNING_KEY_ENV),
            "the hint names the env var: {err}"
        );
        assert!(err.to_string().contains("--insecure-dev-key"));
    }

    #[test]
    fn a_malformed_env_key_refuses() {
        for bad in ["", "xyz", &"g".repeat(64), &"0".repeat(63)] {
            let err = resolve_signing_key(Some(bad), false).expect_err("bad hex refuses");
            assert!(matches!(err, PackError::BadKey(_)), "{bad}: {err}");
        }
    }

    #[test]
    fn an_env_hex_seed_resolves_to_its_key() {
        let signing = SigningKey::generate(&mut OsRng);
        let hex_seed = hex(&signing.to_bytes());
        let resolved = resolve_signing_key(Some(&hex_seed), false).expect("hex resolves");
        assert!(!resolved.insecure_dev);
        assert_eq!(
            resolved.key.verifying_key().to_bytes(),
            signing.verifying_key().to_bytes(),
            "the seed must reconstruct the same key pair"
        );
    }

    #[test]
    fn the_dev_key_lane_signs_and_marks_loudly() {
        let root = tempfile::tempdir().unwrap();
        let pkg = fixture_package(root.path(), "pkg");

        let (report, dev_key) =
            pack_dev_key(&pkg, &root.path().join("store")).expect("the dev lane packs");

        assert!(report.insecure_dev_key);
        let text = report.summary();
        assert!(
            text.contains("INSECURE-DEV-KEY"),
            "the dev lane must be loud: {text}"
        );

        // And it still verifies against the ephemeral key.
        let registry = open_store(&root.path().join("store"), &dev_key, &report.key_id);
        assert!(
            registry
                .plugins()
                .iter()
                .any(|r| r.manifest.id == "pack-fixture")
        );
    }

    #[test]
    fn the_env_key_beats_the_dev_flag() {
        let signing = SigningKey::generate(&mut OsRng);
        let hex_seed = hex(&signing.to_bytes());
        let resolved = resolve_signing_key(Some(&hex_seed), true).expect("env wins over the flag");
        assert!(
            !resolved.insecure_dev,
            "an explicit key is never dev-marked"
        );
    }

    #[test]
    fn the_signature_covers_the_c4_concat_in_load_bearing_order() {
        // The packer signs resources‖attachments (manifest order). A
        // hand-made signature over any other order must fail closed in
        // the store — pinning the concatenation contract from the
        // packing side.
        let root = tempfile::tempdir().unwrap();
        let pkg = fixture_package(root.path(), "pkg");
        let key = SigningKey::generate(&mut OsRng);
        let report = pack(&pkg, &root.path().join("store"), &key).unwrap();

        // Wrong-order signature (attachments‖resources): replace the sig.
        let wrong = key.sign(b"ATTACHMENT-AGENTRESOURCE-STYLERESOURCE-THEME");
        fs::write(report.bundle_dir.join("pack-fixture.sig"), wrong.to_bytes()).unwrap();
        let registry = open_store(&root.path().join("store"), &key, &report.key_id);
        assert!(
            registry
                .plugins()
                .iter()
                .all(|r| r.manifest.id != "pack-fixture"),
            "a wrong-concat signature must fail closed: {:?}",
            registry.rejections()
        );
    }

    #[test]
    fn an_escaping_trust_signature_path_refuses() {
        let root = tempfile::tempdir().unwrap();
        let pkg = fixture_package(root.path(), "pkg");
        let manifest = fs::read_to_string(pkg.join(MANIFEST_FILE)).unwrap();
        // The trust section goes at the END: a `[trust]` header would
        // swallow every top-level key that follows it.
        fs::write(
            pkg.join(MANIFEST_FILE),
            format!("{manifest}\n[trust]\nsignature = \"../evil.sig\"\nmin-trust = \"signed\"\n"),
        )
        .unwrap();

        let key = SigningKey::generate(&mut OsRng);
        let err = pack(&pkg, &root.path().join("store"), &key)
            .expect_err("an escaping signature path must refuse");
        assert!(
            err.to_string().contains("inside the plugin directory"),
            "{err}"
        );
        assert!(
            !root.path().join("store").exists(),
            "nothing may be written on refusal"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_in_the_package_refuses() {
        let root = tempfile::tempdir().unwrap();
        let pkg = fixture_package(root.path(), "pkg");
        std::os::unix::fs::symlink(pkg.join("style.css"), pkg.join("link.css")).unwrap();

        let key = SigningKey::generate(&mut OsRng);
        let err = pack(&pkg, &root.path().join("store"), &key).expect_err("symlinks refuse");
        assert!(err.to_string().contains("symlink"), "{err}");
    }

    #[test]
    fn the_key_fingerprint_is_stable_and_short() {
        let key = SigningKey::generate(&mut OsRng);
        let fp = key_fingerprint(&key.verifying_key().to_bytes());
        assert_eq!(fp.len(), 16);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(fp, key_fingerprint(&key.verifying_key().to_bytes()));
    }

    /// P1 (R1 find): the C4 v2 stream leads with the sealed manifest, so
    /// appending `[[migrations]]` (or editing any manifest field) after
    /// the packer signed it must fail the store's trust gate. Before
    /// C4 v2 this attack scanned in with the migration attached.
    #[test]
    fn a_post_seal_manifest_edit_fails_the_trust_gate() {
        let root = tempfile::tempdir().unwrap();
        let pkg = fixture_package(root.path(), "pkg");
        let key = SigningKey::generate(&mut OsRng);
        let out = root.path().join("store");
        let report = pack(&pkg, &out, &key).expect("packs");

        // Append a migration the publisher never signed, plus its SQL.
        let sql = b"CREATE TABLE evil (id int);\n";
        fs::write(report.bundle_dir.join("evil.sql"), sql).unwrap();
        let manifest_path = report.bundle_dir.join(MANIFEST_FILE);
        let mut sealed = fs::read_to_string(&manifest_path).unwrap();
        sealed.push_str(&format!(
            "\n[[migrations]]\nid = \"0001-evil\"\nengine = \"sql\"\nup = \"evil.sql\"\nsha256 = \"{}\"\n",
            sha256_hex(sql)
        ));
        fs::write(&manifest_path, sealed).unwrap();

        let registry = open_store(&out, &key, "pack-key");
        assert!(
            registry
                .plugins()
                .iter()
                .all(|record| record.manifest.id != "pack-fixture"),
            "a post-seal manifest edit must be rejected by the trust gate"
        );
    }

    /// P2 (R1 find): a migration `up` file is part of the C4 v2 stream;
    /// changing its bytes after the pack makes the signed digest and the
    /// stream disagree, so the scan rejects (fail closed).
    #[test]
    fn a_tampered_migration_file_fails_the_trust_gate() {
        let root = tempfile::tempdir().unwrap();
        let pkg = root.path().join("pkg");
        fs::create_dir_all(pkg.join("migrations")).unwrap();
        let sql = b"CREATE TABLE t (id int);\n";
        let manifest = format!(
            "schema = 1\nid = \"migration-fixture\"\nversion = \"1.0.0\"\nprovider = \"official\"\nform = \"web.vue-module\"\n\n[[migrations]]\nid = \"0001-init\"\nengine = \"sql\"\nup = \"migrations/0001_init.up.sql\"\ndown = \"migrations/0001_init.down.sql\"\nsha256 = \"{}\"\n",
            sha256_hex(sql)
        );
        fs::write(pkg.join(MANIFEST_FILE), manifest).unwrap();
        fs::write(pkg.join("migrations/0001_init.up.sql"), sql).unwrap();
        fs::write(
            pkg.join("migrations/0001_init.down.sql"),
            b"DROP TABLE t;\n",
        )
        .unwrap();

        let key = SigningKey::generate(&mut OsRng);
        let out = root.path().join("store");
        let report = pack(&pkg, &out, &key).expect("packs a migration-bearing package");
        // The migration-bearing bundle scans in as sealed.
        let registry = open_store(&out, &key, "migration-key");
        assert!(
            registry
                .plugins()
                .iter()
                .any(|record| record.manifest.id == "migration-fixture"),
            "the sealed migration bundle must scan in"
        );

        // Tamper the bundled migration file; the signed stream and the
        // declared sha256 both disagree with it.
        fs::write(
            report.bundle_dir.join("migrations/0001_init.up.sql"),
            b"DROP TABLE t;\n",
        )
        .unwrap();
        let tampered = open_store(&out, &key, "migration-key");
        assert!(
            tampered
                .plugins()
                .iter()
                .all(|record| record.manifest.id != "migration-fixture"),
            "a tampered migration file must fail closed"
        );

        // Restore the up file and tamper the DOWN file instead: down
        // bytes are in the C4 v2 stream (no declared digest, so the
        // signature is the only guard) and must be load-bearing.
        fs::write(report.bundle_dir.join("migrations/0001_init.up.sql"), sql).unwrap();
        fs::write(
            report.bundle_dir.join("migrations/0001_init.down.sql"),
            b"DROP TABLE t; -- tampered\n",
        )
        .unwrap();
        let down_tampered = open_store(&out, &key, "migration-key");
        assert!(
            down_tampered
                .plugins()
                .iter()
                .all(|record| record.manifest.id != "migration-fixture"),
            "a tampered down-migration file must fail closed"
        );
    }

    /// P2 (R1 find): an absolute migration path must be refused as
    /// well (the `..` case has its own test).
    #[test]
    fn an_absolute_migration_path_refuses() {
        let root = tempfile::tempdir().unwrap();
        let pkg = root.path().join("pkg");
        fs::create_dir_all(&pkg).unwrap();
        let manifest = r#"schema = 1
id = "absolute-fixture"
version = "1.0.0"
provider = "official"
form = "web.vue-module"

[[migrations]]
id = "0001-init"
engine = "sql"
up = "/etc/passwd"
sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
"#;
        fs::write(pkg.join(MANIFEST_FILE), manifest).unwrap();
        let key = SigningKey::generate(&mut OsRng);
        let err = pack(&pkg, &root.path().join("store"), &key)
            .expect_err("an absolute migration path must refuse");
        assert!(err.to_string().contains("relative path"), "{err}");
    }

    /// P2 (R1 find): a migration path may not escape the package.
    #[test]
    fn a_migration_path_escape_refuses() {
        let root = tempfile::tempdir().unwrap();
        let pkg = root.path().join("pkg");
        fs::create_dir_all(&pkg).unwrap();
        let manifest = r#"schema = 1
id = "escape-fixture"
version = "1.0.0"
provider = "official"
form = "web.vue-module"

[[migrations]]
id = "0001-init"
engine = "sql"
up = "../etc/passwd"
sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
"#;
        fs::write(pkg.join(MANIFEST_FILE), manifest).unwrap();
        let key = SigningKey::generate(&mut OsRng);
        let err = pack(&pkg, &root.path().join("store"), &key)
            .expect_err("a migration path escape must refuse");
        assert!(err.to_string().contains("relative path"), "{err}");
        assert!(
            !root.path().join("store").exists(),
            "nothing may be written on refusal"
        );
    }

    /// P2 (R1 find): the signature output path must not collide with a
    /// declared payload (that would overwrite the payload with 64
    /// signature bytes and produce a bundle the store rejects).
    #[test]
    fn a_signature_path_collision_refuses() {
        let root = tempfile::tempdir().unwrap();
        let pkg = fixture_package(root.path(), "pkg");
        let manifest = fs::read_to_string(pkg.join(MANIFEST_FILE)).unwrap();
        fs::write(
            pkg.join(MANIFEST_FILE),
            format!("{manifest}\n[trust]\nsignature = \"style.css\"\nmin-trust = \"signed\"\n"),
        )
        .unwrap();
        let key = SigningKey::generate(&mut OsRng);
        let err = pack(&pkg, &root.path().join("store"), &key)
            .expect_err("a signature/payload collision must refuse");
        assert!(err.to_string().contains("collides"), "{err}");
    }

    /// P2 (R1 find): a declared `verified-publisher` trust level must be
    /// preserved by sealing; a silent downgrade is a trust regression.
    #[test]
    fn sealing_preserves_a_declared_verified_publisher_level() {
        let root = tempfile::tempdir().unwrap();
        let pkg = fixture_package(root.path(), "pkg");
        let manifest = fs::read_to_string(pkg.join(MANIFEST_FILE)).unwrap();
        fs::write(
            pkg.join(MANIFEST_FILE),
            format!("{manifest}\n[trust]\nsignature = \"pack-fixture.sig\"\nmin-trust = \"verified-publisher\"\n"),
        )
        .unwrap();
        let key = SigningKey::generate(&mut OsRng);
        let report = pack(&pkg, &root.path().join("store"), &key).expect("packs");
        let sealed = fs::read_to_string(report.bundle_dir.join(MANIFEST_FILE)).unwrap();
        let parsed: PluginManifest = toml::from_str(&sealed).expect("sealed manifest parses");
        assert_eq!(
            parsed.trust.expect("trust is present").min_trust,
            crate::manifest::MinTrust::VerifiedPublisher,
            "sealing must not downgrade verified-publisher"
        );
    }
}
