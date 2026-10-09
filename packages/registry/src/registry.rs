use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::acceptance::HostAcceptance;
use crate::audit::{AuditEvent, AuditLog, unix_secs};
use crate::error::{RegistryError, RegistryResult};
use crate::feed::{FeedItem, ResolvedPayload, ResourceFeed};
use crate::handle::{HandleInfo, LocalRegistration, RegistryInner, ResourceHandle};
use crate::manifest::{Payload, ResourceEntry};
use crate::store::{
    self, EnabledState, PluginRecord, ReadPayloadError, Rejection, STATE_FILE, ScanResult,
    sha256_hex,
};

/// The default per-payload size cap: 8 MiB — deliberately generous for
/// the resource vocabulary the registry feeds today (styles, themes,
/// modules, icons, fonts), while keeping one runaway payload from
/// dominating host memory. Hosts may raise or lower it via
/// [`RegistryOptions::max_payload_bytes`].
pub const DEFAULT_MAX_PAYLOAD_BYTES: u64 = 8 * 1024 * 1024;

/// Open-time options for a [`Registry`] — the builder behind
/// [`Registry::options`].
///
/// The defaults reproduce [`Registry::open`]: the scan replay is audited
/// and file payloads are capped at [`DEFAULT_MAX_PAYLOAD_BYTES`].
#[derive(Debug, Clone)]
pub struct RegistryOptions {
    pub(crate) audit_scan_replay: bool,
    pub(crate) max_payload_bytes: u64,
    /// Publisher keys for the distribution trust gate (C4): when
    /// non-empty the scan runs `scan_with_keys` — signature-demanding
    /// plugins must verify under one of these or the scan rejects them
    /// (fail-closed). Empty (the default) keeps the unsigned lane:
    /// demanding plugins are rejected regardless, unsigned ones load.
    pub(crate) publisher_keys: Vec<crate::trust::PublisherKey>,
}

impl Default for RegistryOptions {
    fn default() -> Self {
        Self {
            audit_scan_replay: true,
            max_payload_bytes: DEFAULT_MAX_PAYLOAD_BYTES,
            publisher_keys: Vec::new(),
        }
    }
}

impl RegistryOptions {
    /// The default options (equivalent to [`Registry::open`]).
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the publisher keys for the distribution trust gate (C4).
    pub fn publisher_keys(mut self, keys: Vec<crate::trust::PublisherKey>) -> Self {
        self.publisher_keys = keys;
        self
    }

    /// Skips replaying the scan into the audit log at open — the quiet
    /// semantics of [`Registry::open_quiet`] — so read-only opens append
    /// nothing. Composable with [`Self::max_payload_bytes`] for a quiet
    /// open under a custom cap.
    pub fn quiet(mut self, quiet: bool) -> Self {
        self.audit_scan_replay = !quiet;
        self
    }

    /// Sets the per-file-payload size cap (bytes), enforced at **every**
    /// payload read: scan validation at open (an oversized payload
    /// rejects its plugin, audited as `rejected` with the measured
    /// size), feed, and load (fail-loud `failed` events if the file grew
    /// past the cap after the scan). The reads themselves are bounded,
    /// so an oversized payload never dominates host memory — the feed
    /// snapshot guarantee (hosts load exactly the audited bytes) is
    /// untouched. Default: [`DEFAULT_MAX_PAYLOAD_BYTES`].
    ///
    /// A cap of `u64::MAX` is effectively "no cap": the bounded read
    /// (`take(cap + 1)`) saturates instead of overflowing and no file
    /// can exceed `u64::MAX` bytes, so nothing is ever rejected — the
    /// trade-off being that reads are then bounded only by the file's
    /// actual size, not by the cap.
    pub fn max_payload_bytes(mut self, max: u64) -> Self {
        self.max_payload_bytes = max;
        self
    }

    /// Opens the registry against a plugin store and an audit log with
    /// these options; anything left at its default behaves exactly like
    /// [`Registry::open`].
    pub fn open(self, store_dir: &Path, audit_path: &Path) -> RegistryResult<Registry> {
        Registry::open_impl(store_dir, audit_path, self)
    }
}

/// The registry facade: plugin management, host feeding, and runtime
/// registration, all audited.
///
/// Synchronous by design (v1): the plugin-store IO volume is tiny, and
/// staying off tokio keeps the crate consumable from any runtime.
///
/// ```no_run
/// use akivili_registry::{HostAcceptance, Registry, ResourceKind};
/// use std::path::Path;
/// # fn main() -> Result<(), akivili_registry::RegistryError> {
/// let registry = Registry::open(
///     Path::new("/var/lib/akivili/plugins"),
///     Path::new("/var/lib/akivili/audit.jsonl"),
/// )?;
/// let feed = registry.feed(&HostAcceptance::new(
///     "webui",
///     vec![ResourceKind::new("webui.style")?],
/// ))?;
/// for item in feed.iter() {
///     let handle = registry.load(&item.plugin_id, item.entry_index)?;
///     // ... apply the resource in the host ...
///     handle.unload()?;
/// }
/// # Ok(())
/// # }
/// ```
pub struct Registry {
    inner: Arc<RegistryInner>,
    store_dir: PathBuf,
    state_path: PathBuf,
    state: EnabledState,
    records: Vec<PluginRecord>,
    rejections: Vec<Rejection>,
    max_payload_bytes: u64,
}

impl std::fmt::Debug for Registry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Registry")
            .field("store_dir", &self.store_dir)
            .field(
                "plugins",
                &self
                    .records
                    .iter()
                    .map(|r| r.manifest.id.as_str())
                    .collect::<Vec<_>>(),
            )
            .field("max_payload_bytes", &self.max_payload_bytes)
            .finish_non_exhaustive()
    }
}

impl Registry {
    /// Opens the registry against a plugin store and an audit log.
    ///
    /// Scans the store, replays the full scan into the audit log
    /// (`discovered` + `validated`/`rejected` per source), and applies the
    /// persisted enable/disable state. Fail-loud: an unopenable audit log
    /// or an unreadable store root is an error, never a silent empty
    /// registry.
    ///
    /// The scan replay is the right default for host processes, which
    /// open once: the replay leaves a trace of every scan that fed the
    /// process. Read-only lookups that may run repeatedly (the CLI's
    /// `list`) should prefer [`Registry::open_quiet`] so they do not
    /// grow the audit log on every invocation.
    ///
    /// Opens with the default options; [`Registry::options`] is the
    /// builder for the knobs (quiet open, per-payload size cap).
    pub fn open(store_dir: &Path, audit_path: &Path) -> RegistryResult<Self> {
        RegistryOptions::new().open(store_dir, audit_path)
    }

    /// Opens the registry quietly: the same scan, the same persisted
    /// enable/disable state, and the same fail-loud errors as
    /// [`Registry::open`] — but the scan is **not** replayed into the
    /// audit log, so a read-only open appends nothing.
    ///
    /// Everything the returned registry does afterwards (toggle, feed,
    /// load, unload, failures) audits exactly as with `open`; only the
    /// open-time `discovered`/`validated`/`rejected` replay is skipped.
    pub fn open_quiet(store_dir: &Path, audit_path: &Path) -> RegistryResult<Self> {
        RegistryOptions::new()
            .quiet(true)
            .open(store_dir, audit_path)
    }

    /// The open-time options surface: a builder for every registry knob
    /// (quiet open, per-payload size cap), starting from the
    /// [`Registry::open`] defaults.
    pub fn options() -> RegistryOptions {
        RegistryOptions::new()
    }

    fn open_impl(
        store_dir: &Path,
        audit_path: &Path,
        options: RegistryOptions,
    ) -> RegistryResult<Self> {
        let audit = AuditLog::open(audit_path)?;
        let inner = Arc::new(RegistryInner::from_audit(audit));

        let state_path = store_dir.join(STATE_FILE);
        let state = EnabledState::load(&state_path)?;
        let scan = if options.publisher_keys.is_empty() {
            store::scan(store_dir, &state, options.max_payload_bytes)?
        } else {
            store::scan_with_keys(
                store_dir,
                &state,
                options.max_payload_bytes,
                &options.publisher_keys,
            )?
        };

        let mut records = Vec::new();
        let mut rejections = Vec::new();
        for result in scan {
            match result {
                ScanResult::Accepted(record) => {
                    if options.audit_scan_replay {
                        inner.append_audit(AuditEvent::Discovered {
                            ts: unix_secs(),
                            source: record.dir.display().to_string(),
                            plugin_id: Some(record.manifest.id.clone()),
                        })?;
                        inner.append_audit(AuditEvent::Validated {
                            ts: unix_secs(),
                            plugin_id: record.manifest.id.clone(),
                            version: Some(record.manifest.version.clone()),
                            resources: record.manifest.resources.len(),
                        })?;
                    }
                    records.push(record);
                }
                ScanResult::Rejected(rejection) => {
                    if options.audit_scan_replay {
                        inner.append_audit(AuditEvent::Discovered {
                            ts: unix_secs(),
                            source: rejection.dir.display().to_string(),
                            plugin_id: rejection.plugin_id.clone(),
                        })?;
                        inner.append_audit(AuditEvent::Rejected {
                            ts: unix_secs(),
                            source: rejection.dir.display().to_string(),
                            plugin_id: rejection.plugin_id.clone(),
                            reason: rejection.reason.clone(),
                        })?;
                    }
                    rejections.push(rejection);
                }
            }
        }

        Ok(Self {
            inner,
            store_dir: store_dir.to_path_buf(),
            state_path,
            state,
            records,
            rejections,
            max_payload_bytes: options.max_payload_bytes,
        })
    }

    /// The discovered (validated) plugins. This is the discoverability
    /// surface: everything here is also visible to `akivili-plugin list`.
    pub fn plugins(&self) -> &[PluginRecord] {
        &self.records
    }

    /// The sources rejected by the last scan, with reasons.
    pub fn rejections(&self) -> &[Rejection] {
        &self.rejections
    }

    /// The plugin store root this registry was opened against.
    pub fn store_dir(&self) -> &Path {
        &self.store_dir
    }

    /// The per-payload size cap this registry enforces at scan, feed,
    /// and load (see [`RegistryOptions::max_payload_bytes`]).
    pub fn max_payload_bytes(&self) -> u64 {
        self.max_payload_bytes
    }

    /// Toggles a plugin: persists the override to the state file next to
    /// the store root (never inside the plugin directory — the
    /// uninstallability guarantee) and audits `enabled`/`disabled`.
    pub fn set_enabled(&mut self, plugin_id: &str, enabled: bool) -> RegistryResult<()> {
        let record = self
            .records
            .iter_mut()
            .find(|record| record.manifest.id == plugin_id)
            .ok_or_else(|| RegistryError::UnknownPlugin(plugin_id.to_string()))?;

        record.enabled = enabled;
        self.state.set(plugin_id, enabled);
        self.state.save(&self.state_path)?;

        self.inner.append_audit(if enabled {
            AuditEvent::Enabled {
                ts: unix_secs(),
                plugin_id: plugin_id.to_string(),
            }
        } else {
            AuditEvent::Disabled {
                ts: unix_secs(),
                plugin_id: plugin_id.to_string(),
            }
        })
    }

    /// Registers a runtime-local resource: an in-process dynamic entry
    /// that never touches the disk store — the second registration mode,
    /// the analogue of the plugin host's `registerMcpTool` family.
    ///
    /// Only inline payloads are accepted (a `File` payload has no plugin
    /// directory to resolve against). The returned [`LocalRegistration`]
    /// is handed back to [`Registry::load_local`] when the host declares
    /// the resource loaded. Local resources do not participate in
    /// [`Registry::feed`]; they are pushed by their provider, not pulled
    /// by host acceptance.
    pub fn register_local(
        &self,
        entry: ResourceEntry,
        provider: &str,
    ) -> RegistryResult<LocalRegistration> {
        if let Payload::File { path, .. } = &entry.payload {
            self.inner.append_audit(AuditEvent::Failed {
                ts: unix_secs(),
                stage: "register_local".into(),
                plugin_id: Some(provider.to_string()),
                reason: format!(
                    "file payload '{}' has no plugin directory in local mode",
                    path.display()
                ),
            })?;
            return Err(RegistryError::UnsupportedLocalPayload(format!(
                "file payload '{}' has no plugin directory in local mode",
                path.display()
            )));
        }

        self.inner.append_audit(AuditEvent::Discovered {
            ts: unix_secs(),
            source: "local".into(),
            plugin_id: Some(provider.to_string()),
        })?;
        self.inner.append_audit(AuditEvent::Validated {
            ts: unix_secs(),
            plugin_id: provider.to_string(),
            version: None,
            resources: 1,
        })?;

        Ok(LocalRegistration {
            provider: provider.to_string(),
            entry,
        })
    }

    /// Declares a runtime-local resource loaded: audits `loaded` and
    /// returns a [`ResourceHandle`]. Loading the same registration twice
    /// produces two audited handles (the registry does not deduplicate —
    /// the audit trail reflects every declaration).
    pub fn load_local(&self, registration: &LocalRegistration) -> RegistryResult<ResourceHandle> {
        let id = self.inner.allocate_handle_id();
        self.inner.append_audit(AuditEvent::Loaded {
            ts: unix_secs(),
            plugin_id: registration.provider.clone(),
            kind: registration.entry.kind.to_string(),
            handle: id,
            sha256: None,
        })?;
        Ok(ResourceHandle::new(
            self.inner.clone(),
            HandleInfo {
                id,
                plugin_id: registration.provider.clone(),
                kind: registration.entry.kind.clone(),
            },
        ))
    }

    /// Feeds a host: filters enabled store plugins by the acceptance's
    /// declared kinds, resolves payloads (file bytes are read — under
    /// the registry's size cap, see [`RegistryOptions::max_payload_bytes`]
    /// — and digested now), orders the result (entry `order` ascending,
    /// ties by plugin id, then manifest position), and audits one `fed`
    /// event per item.
    ///
    /// Local registrations are intentionally not fed (see
    /// [`Registry::register_local`]).
    pub fn feed(&self, acceptance: &HostAcceptance) -> RegistryResult<ResourceFeed> {
        let mut items = Vec::new();
        for record in &self.records {
            if !record.enabled {
                continue;
            }
            for (entry_index, entry) in record.manifest.resources.iter().enumerate() {
                if !acceptance.accepts(&entry.kind) {
                    continue;
                }
                let resolved = self.resolve_payload(record, entry)?;
                items.push(FeedItem {
                    plugin_id: record.manifest.id.clone(),
                    plugin_version: record.manifest.version.clone(),
                    entry_index,
                    entry: entry.clone(),
                    resolved,
                });
            }
        }

        items.sort_by(|a, b| (&a.entry.order, &a.plugin_id).cmp(&(&b.entry.order, &b.plugin_id)));

        for item in &items {
            self.inner.append_audit(AuditEvent::Fed {
                ts: unix_secs(),
                plugin_id: item.plugin_id.clone(),
                kind: item.entry.kind.to_string(),
                host_id: acceptance.host_id.clone(),
                order: item.entry.order,
                name: item.entry.name.clone(),
                sha256: item.resolved.sha256().map(str::to_string),
            })?;
        }

        Ok(ResourceFeed { items })
    }

    /// Declares a resource loaded: the host's "I loaded this" statement.
    ///
    /// Looks the entry up in the plugin's manifest, re-verifies file
    /// payloads (path confinement first, then the size cap, then their
    /// declared digests — the file may have changed since the scan),
    /// audits `loaded`, and returns a handle. Loading from a disabled
    /// plugin is an error — `set_enabled(false)` is the store-level off
    /// switch.
    pub fn load(&self, plugin_id: &str, entry_index: usize) -> RegistryResult<ResourceHandle> {
        let fail = |reason: String| {
            self.inner.append_audit(AuditEvent::Failed {
                ts: unix_secs(),
                stage: "load".into(),
                plugin_id: Some(plugin_id.to_string()),
                reason: reason.clone(),
            })
        };

        let record = self
            .records
            .iter()
            .find(|record| record.manifest.id == plugin_id)
            .ok_or_else(|| RegistryError::UnknownPlugin(plugin_id.to_string()));
        let record = match record {
            Ok(record) => record,
            Err(e) => {
                fail(e.to_string())?;
                return Err(e);
            }
        };

        if !record.enabled {
            let e = RegistryError::PluginDisabled(plugin_id.to_string());
            fail(e.to_string())?;
            return Err(e);
        }

        let entry = record.manifest.resources.get(entry_index);
        let entry = match entry {
            Some(entry) => entry,
            None => {
                let e = RegistryError::EntryIndexOutOfBounds {
                    plugin_id: plugin_id.to_string(),
                    index: entry_index,
                };
                fail(e.to_string())?;
                return Err(e);
            }
        };

        let sha256 = match &entry.payload {
            Payload::Inline(_) => None,
            Payload::File { path, sha256 } => {
                let full = match store::confined_payload_path(&record.dir, path) {
                    Ok(full) => full,
                    Err(reason) => {
                        let err = RegistryError::PayloadIntegrity {
                            plugin_id: plugin_id.to_string(),
                            reason,
                        };
                        fail(err.to_string())?;
                        return Err(err);
                    }
                };
                let bytes = match store::read_capped(&full, self.max_payload_bytes) {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        let reason = e.reason(&full);
                        let err = match e {
                            ReadPayloadError::TooLarge { size, cap } => {
                                RegistryError::PayloadTooLarge {
                                    plugin_id: plugin_id.to_string(),
                                    path: path.display().to_string(),
                                    size,
                                    cap,
                                }
                            }
                            ReadPayloadError::Io(_) => RegistryError::PayloadIntegrity {
                                plugin_id: plugin_id.to_string(),
                                reason,
                            },
                        };
                        fail(err.to_string())?;
                        return Err(err);
                    }
                };
                let actual = sha256_hex(&bytes);
                if let Some(expected) = sha256
                    && expected != &actual
                {
                    let err = RegistryError::PayloadIntegrity {
                        plugin_id: plugin_id.to_string(),
                        reason: format!(
                            "sha256 mismatch for payload '{}': declared {expected}, actual {actual}",
                            path.display()
                        ),
                    };
                    fail(err.to_string())?;
                    return Err(err);
                }
                Some(actual)
            }
        };

        let id = self.inner.allocate_handle_id();
        self.inner.append_audit(AuditEvent::Loaded {
            ts: unix_secs(),
            plugin_id: plugin_id.to_string(),
            kind: entry.kind.to_string(),
            handle: id,
            sha256,
        })?;
        Ok(ResourceHandle::new(
            self.inner.clone(),
            HandleInfo {
                id,
                plugin_id: plugin_id.to_string(),
                kind: entry.kind.clone(),
            },
        ))
    }

    /// Resolves one entry's payload at feed time, verifying declared
    /// digests, confining file reads to the plugin's own directory, and
    /// reading under the registry's size cap; failures audit `failed`
    /// and bubble up (feed is fail-loud — one corrupted or oversized
    /// payload surfaces rather than being silently skipped).
    fn resolve_payload(
        &self,
        record: &PluginRecord,
        entry: &ResourceEntry,
    ) -> RegistryResult<ResolvedPayload> {
        match &entry.payload {
            Payload::Inline(value) => Ok(ResolvedPayload::Inline(value.clone())),
            Payload::File { path, sha256 } => {
                let full = match store::confined_payload_path(&record.dir, path) {
                    Ok(full) => full,
                    Err(reason) => {
                        let err = RegistryError::PayloadIntegrity {
                            plugin_id: record.manifest.id.clone(),
                            reason,
                        };
                        self.feed_failure(record, &err)?;
                        return Err(err);
                    }
                };
                let bytes = match store::read_capped(&full, self.max_payload_bytes) {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        let reason = e.reason(&full);
                        let err = match e {
                            ReadPayloadError::TooLarge { size, cap } => {
                                RegistryError::PayloadTooLarge {
                                    plugin_id: record.manifest.id.clone(),
                                    path: path.display().to_string(),
                                    size,
                                    cap,
                                }
                            }
                            ReadPayloadError::Io(_) => RegistryError::PayloadIntegrity {
                                plugin_id: record.manifest.id.clone(),
                                reason,
                            },
                        };
                        self.feed_failure(record, &err)?;
                        return Err(err);
                    }
                };
                let actual = sha256_hex(&bytes);
                if let Some(expected) = sha256
                    && expected != &actual
                {
                    let err = RegistryError::PayloadIntegrity {
                        plugin_id: record.manifest.id.clone(),
                        reason: format!(
                            "sha256 mismatch for payload '{}': declared {expected}, actual {actual}",
                            path.display()
                        ),
                    };
                    self.feed_failure(record, &err)?;
                    return Err(err);
                }
                Ok(ResolvedPayload::File {
                    bytes,
                    sha256: actual,
                })
            }
        }
    }

    fn feed_failure(&self, record: &PluginRecord, err: &RegistryError) -> RegistryResult<()> {
        self.inner.append_audit(AuditEvent::Failed {
            ts: unix_secs(),
            stage: "feed".into(),
            plugin_id: Some(record.manifest.id.clone()),
            reason: err.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kinds::ResourceKind;
    use crate::manifest::MANIFEST_FILE;

    struct TestStore {
        root: tempfile::TempDir,
    }

    impl TestStore {
        fn new() -> Self {
            Self {
                root: tempfile::tempdir().unwrap(),
            }
        }

        fn store_dir(&self) -> &Path {
            self.root.path()
        }

        fn audit_path(&self) -> PathBuf {
            self.root.path().join("audit.jsonl")
        }

        fn add_plugin(&self, name: &str, manifest: &str, files: &[(&str, &str)]) {
            let dir = self.root.path().join(name);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join(MANIFEST_FILE), manifest).unwrap();
            for (file, content) in files {
                if let Some(parent) = Path::new(file).parent()
                    && !parent.as_os_str().is_empty()
                {
                    std::fs::create_dir_all(dir.join(parent)).unwrap();
                }
                std::fs::write(dir.join(file), content).unwrap();
            }
        }

        fn open(&self) -> Registry {
            Registry::open(self.store_dir(), &self.audit_path()).unwrap()
        }

        fn open_with(&self, options: RegistryOptions) -> Registry {
            options.open(self.store_dir(), &self.audit_path()).unwrap()
        }

        fn audit_events(&self) -> Vec<AuditEvent> {
            let text = std::fs::read_to_string(self.audit_path()).unwrap();
            text.lines()
                .map(serde_json::from_str)
                .collect::<Result<_, _>>()
                .unwrap()
        }
    }

    /// alpha: theme(order 10, inline) + style(order 10, file)
    const ALPHA: &str = r##"
id = "alpha"
version = "1.2.0"
provider = "test"

[[resources]]
kind = "webui.theme"
name = "dark"
order = 10

[resources.payload.Inline]
primary = "#181825"

[[resources]]
kind = "webui.style"
order = 10

[resources.payload.File]
path = "style.css"

[[resources]]
kind = "sandbox.env"
order = 99

[resources.payload.Inline]
HTTP_PROXY = "http://192.0.2.1:7890"
"##;

    /// beta: one style, order 5 (must feed before alpha's order-10 style)
    const BETA: &str = r#"
id = "beta"
version = "0.1.0"
provider = "test"

[[resources]]
kind = "webui.style"
order = 5

[resources.payload.Inline]
body = "serif"
"#;

    /// gamma: one style, order 10 (ties with alpha; alpha wins by plugin id)
    const GAMMA: &str = r#"
id = "gamma"
version = "2.0.0"
provider = "other"

[[resources]]
kind = "webui.style"
order = 10

[resources.payload.Inline]
body = "monospace"
"#;

    fn style_style() -> Vec<ResourceKind> {
        vec![ResourceKind::new(crate::kinds::WEBUI_STYLE).unwrap()]
    }

    /// A one-resource manifest whose style payload is a file at `path`
    /// (relative to the plugin directory, or not — the escape tests
    /// deliberately declare paths that leave it).
    fn file_manifest(id: &str, path: &str) -> String {
        format!(
            r#"
id = "{id}"
version = "0.1.0"
provider = "test"

[[resources]]
kind = "webui.style"
order = 5

[resources.payload.File]
path = "{path}"
"#
        )
    }

    #[test]
    fn open_discovers_and_audits_plugins() {
        let store = TestStore::new();
        store.add_plugin("alpha", ALPHA, &[("style.css", "body{}\n")]);
        store.add_plugin("beta", BETA, &[]);

        let registry = store.open();
        let ids: Vec<&str> = registry
            .plugins()
            .iter()
            .map(|r| r.manifest.id.as_str())
            .collect();
        assert_eq!(ids, ["alpha", "beta"]);
        assert!(registry.plugins().iter().all(|r| r.enabled));

        let events = store.audit_events();
        // 2 events per accepted plugin: discovered + validated
        assert_eq!(events.len(), 4);
        assert!(
            matches!(&events[0], AuditEvent::Discovered { plugin_id, .. } if plugin_id.as_deref() == Some("alpha"))
        );
        assert!(
            matches!(&events[1], AuditEvent::Validated { plugin_id, version, resources, .. } if
            plugin_id == "alpha" && version.as_deref() == Some("1.2.0") && *resources == 3)
        );
        assert!(
            matches!(&events[3], AuditEvent::Validated { plugin_id, .. } if plugin_id == "beta")
        );
    }

    #[test]
    fn open_audits_rejections_alongside_acceptances() {
        let store = TestStore::new();
        store.add_plugin("good", BETA, &[]);
        store.add_plugin(
            "bad",
            "id = \"Bad\"\nversion = \"1\"\nprovider = \"x\"\n",
            &[],
        );

        let registry = store.open();
        assert_eq!(registry.plugins().len(), 1);
        assert_eq!(registry.rejections().len(), 1);
        assert!(registry.rejections()[0].reason.contains("id"));

        // Directories scan in name order: bad (discovered+rejected), then
        // good (discovered+validated).
        let events = store.audit_events();
        assert_eq!(events.len(), 4);
        assert!(
            matches!(&events[0], AuditEvent::Discovered { source, .. } if source.ends_with("bad"))
        );
        assert!(matches!(&events[1], AuditEvent::Rejected { reason, .. } if reason.contains("id")));
        assert!(
            matches!(&events[3], AuditEvent::Validated { plugin_id, .. } if plugin_id == "beta")
        );
    }

    #[test]
    fn quiet_open_skips_the_scan_replay_but_still_scans() {
        let store = TestStore::new();
        store.add_plugin("alpha", ALPHA, &[("style.css", "body{}\n")]);
        store.add_plugin("bad", "not = \"a manifest\"\n", &[]);

        let registry = Registry::open_quiet(store.store_dir(), &store.audit_path()).unwrap();
        // The scan itself still ran, rejections included.
        assert_eq!(registry.plugins().len(), 1);
        assert_eq!(registry.rejections().len(), 1);

        // But the audit log carries no discovered/validated/rejected
        // events for this open — nothing at all, in fact.
        let events = store.audit_events();
        assert!(
            !events.iter().any(|e| matches!(
                e,
                AuditEvent::Discovered { .. }
                    | AuditEvent::Validated { .. }
                    | AuditEvent::Rejected { .. }
            )),
            "quiet open must not replay the scan: {events:?}"
        );
        assert!(events.is_empty(), "quiet open writes nothing: {events:?}");

        // Later operations still audit as usual.
        registry
            .feed(&HostAcceptance::new("webui", style_style()))
            .unwrap();
        assert!(
            store
                .audit_events()
                .iter()
                .any(|e| matches!(e, AuditEvent::Fed { .. })),
            "post-open operations must still audit"
        );
    }

    #[test]
    fn quiet_open_still_fails_loud_on_missing_store() {
        let store = TestStore::new();
        let missing = store.root.path().join("missing-store");
        let err = Registry::open_quiet(&missing, &store.audit_path()).unwrap_err();
        assert!(
            err.to_string().contains("cannot read plugin store"),
            "got: {err}"
        );
    }

    #[test]
    fn feed_filters_by_accepted_kind() {
        let store = TestStore::new();
        store.add_plugin("alpha", ALPHA, &[("style.css", "body{}\n")]);

        let registry = store.open();
        let feed = registry
            .feed(&HostAcceptance::new("sandbox", style_style()))
            .unwrap();
        assert_eq!(feed.len(), 1, "only the style entry feeds: {feed:?}");
        assert_eq!(feed.iter().next().unwrap().plugin_id, "alpha");
        assert_eq!(
            feed.iter().next().unwrap().entry.kind.as_str(),
            "webui.style"
        );

        // A kind no plugin provides feeds nothing.
        let feed = registry
            .feed(&HostAcceptance::new(
                "mcp",
                vec![ResourceKind::new(crate::kinds::TOOL_MCP).unwrap()],
            ))
            .unwrap();
        assert!(feed.is_empty());
    }

    #[test]
    fn feed_resolves_file_payloads_with_digest() {
        let store = TestStore::new();
        let css = "body { color: rebeccapurple; }\n";
        store.add_plugin("alpha", ALPHA, &[("style.css", css)]);

        let registry = store.open();
        let feed = registry
            .feed(&HostAcceptance::new("webui", style_style()))
            .unwrap();
        let item = feed.iter().next().unwrap();
        match &item.resolved {
            ResolvedPayload::File { bytes, sha256 } => {
                assert_eq!(bytes, css.as_bytes());
                assert_eq!(sha256, &sha256_hex(css.as_bytes()));
            }
            other => panic!("expected file payload, got {other:?}"),
        }
        assert_eq!(item.entry_index, 1, "style is alpha's second resource");
        assert_eq!(item.plugin_version, "1.2.0");

        // The fed event carries the digest.
        let events = store.audit_events();
        let fed = events
            .iter()
            .find(|e| matches!(e, AuditEvent::Fed { .. }))
            .expect("fed event must exist");
        assert!(matches!(fed,
            AuditEvent::Fed { plugin_id, kind, host_id, sha256, .. }
            if plugin_id == "alpha" && kind == "webui.style" && host_id == "webui"
                && sha256.as_deref() == Some(sha256_hex(css.as_bytes()).as_str())));
    }

    #[test]
    fn feed_orders_by_order_then_plugin_id() {
        let store = TestStore::new();
        store.add_plugin("gamma", GAMMA, &[]);
        store.add_plugin("alpha", ALPHA, &[("style.css", "body{}\n")]);
        store.add_plugin("beta", BETA, &[]);

        let registry = store.open();
        let feed = registry
            .feed(&HostAcceptance::new("webui", style_style()))
            .unwrap();
        let order: Vec<(&str, i32)> = feed
            .iter()
            .map(|i| (i.plugin_id.as_str(), i.entry.order))
            .collect();
        // beta order 5, then alpha & gamma order 10 with alpha first (id tie-break)
        assert_eq!(order, [("beta", 5), ("alpha", 10), ("gamma", 10)]);
    }

    #[test]
    fn feed_tie_break_uses_plugin_id_not_directory_order() {
        // Directory names deliberately sort opposite to plugin ids, so the
        // scan order of records differs from id order. A stable sort alone
        // (no id tie-break) would keep the scan order and fail this test.
        let store = TestStore::new();
        let zzz = BETA.replace(r#"id = "beta""#, r#"id = "zzz""#);
        let aaa = BETA.replace(r#"id = "beta""#, r#"id = "aaa""#);
        store.add_plugin("a-first-dir", &zzz, &[]);
        store.add_plugin("b-second-dir", &aaa, &[]);

        let registry = store.open();
        let scan_order: Vec<&str> = registry
            .plugins()
            .iter()
            .map(|r| r.manifest.id.as_str())
            .collect();
        assert_eq!(scan_order, ["zzz", "aaa"], "scan order follows dir names");

        let feed = registry
            .feed(&HostAcceptance::new("webui", style_style()))
            .unwrap();
        let fed_order: Vec<&str> = feed.iter().map(|i| i.plugin_id.as_str()).collect();
        assert_eq!(
            fed_order,
            ["aaa", "zzz"],
            "equal orders tie-break by plugin id"
        );
    }

    #[test]
    fn disabled_plugins_do_not_feed() {
        let store = TestStore::new();
        store.add_plugin("beta", BETA, &[]);

        let mut registry = store.open();
        registry.set_enabled("beta", false).unwrap();

        let feed = registry
            .feed(&HostAcceptance::new("webui", style_style()))
            .unwrap();
        assert!(feed.is_empty(), "disabled plugin must not feed");

        // No fed events; one disabled event.
        let events = store.audit_events();
        assert!(!events.iter().any(|e| matches!(e, AuditEvent::Fed { .. })));
        assert!(matches!(
            events.last(),
            Some(AuditEvent::Disabled { plugin_id, .. }) if plugin_id == "beta"
        ));

        // Re-enabling feeds again.
        registry.set_enabled("beta", true).unwrap();
        let feed = registry
            .feed(&HostAcceptance::new("webui", style_style()))
            .unwrap();
        assert_eq!(feed.len(), 1);
    }

    #[test]
    fn set_enabled_persists_across_reopen() {
        let store = TestStore::new();
        store.add_plugin("beta", BETA, &[]);

        {
            let mut registry = store.open();
            registry.set_enabled("beta", false).unwrap();
        }

        let registry = store.open();
        assert!(
            !registry
                .plugins()
                .iter()
                .find(|r| r.manifest.id == "beta")
                .unwrap()
                .enabled,
            "disable must survive a reopen"
        );

        // state file exists at store root, not inside the plugin dir
        assert!(store.store_dir().join(STATE_FILE).is_file());
        assert!(!store.store_dir().join("beta").join(STATE_FILE).exists());
    }

    #[test]
    fn set_enabled_unknown_plugin_fails() {
        let store = TestStore::new();
        let mut registry = store.open();
        let err = registry.set_enabled("ghost", true).unwrap_err();
        assert!(matches!(err, RegistryError::UnknownPlugin(_)));
    }

    #[test]
    fn payload_exactly_at_the_cap_feeds() {
        // Boundary: the cap is inclusive — a payload of exactly `cap`
        // bytes is at the limit, not over it.
        let store = TestStore::new();
        let exactly = "x".repeat(8);
        store.add_plugin(
            "beta",
            &file_manifest("beta", "style.css"),
            &[("style.css", &exactly)],
        );

        let registry = store.open_with(Registry::options().max_payload_bytes(8));
        assert_eq!(registry.max_payload_bytes(), 8);
        let feed = registry
            .feed(&HostAcceptance::new("webui", style_style()))
            .unwrap();
        assert_eq!(feed.len(), 1, "an exactly-at-cap payload must feed");
        match &feed.iter().next().unwrap().resolved {
            ResolvedPayload::File { bytes, sha256 } => {
                assert_eq!(bytes.as_slice(), b"xxxxxxxx");
                assert_eq!(sha256, &sha256_hex(b"xxxxxxxx"));
            }
            other => panic!("expected file payload, got {other:?}"),
        }
    }

    #[test]
    fn oversized_payloads_reject_the_plugin_at_scan_with_audited_sizes() {
        let store = TestStore::new();
        let oversized = "x".repeat(9);
        store.add_plugin(
            "beta",
            &file_manifest("beta", "style.css"),
            &[("style.css", &oversized)],
        );

        let registry = store.open_with(Registry::options().max_payload_bytes(8));
        assert!(
            registry.plugins().is_empty(),
            "an oversized payload must not validate: {:?}",
            registry.plugins()
        );
        assert_eq!(registry.rejections().len(), 1);
        let reason = &registry.rejections()[0].reason;
        assert!(
            reason.contains("payload_too_large"),
            "the reason must carry the machine token: {reason}"
        );
        assert!(
            reason.contains("9 bytes") && reason.contains("cap of 8 bytes"),
            "the reason must record the measured size and the cap: {reason}"
        );

        let events = store.audit_events();
        assert!(
            events.iter().any(|e| matches!(e,
                AuditEvent::Rejected { reason, plugin_id, .. }
                if reason.contains("payload_too_large") && reason.contains("9 bytes")
                    && plugin_id.as_deref() == Some("beta"))),
            "the oversize must be audited with its measured size: {events:?}"
        );
        assert!(!events.iter().any(|e| matches!(e,
            AuditEvent::Validated { plugin_id, .. } if plugin_id == "beta")));
        assert!(!events.iter().any(|e| matches!(e, AuditEvent::Fed { .. })));
    }

    #[test]
    fn default_cap_is_8_mib_with_the_exact_boundary_accepted() {
        let store = TestStore::new();
        let at_cap = "x".repeat(DEFAULT_MAX_PAYLOAD_BYTES as usize);
        let over_cap = "y".repeat(DEFAULT_MAX_PAYLOAD_BYTES as usize + 1);
        store.add_plugin(
            "atcap",
            &file_manifest("atcap", "style.css"),
            &[("style.css", &at_cap)],
        );
        store.add_plugin(
            "over",
            &file_manifest("over", "style.css"),
            &[("style.css", &over_cap)],
        );

        let registry = store.open();
        assert_eq!(registry.max_payload_bytes(), 8 * 1024 * 1024);
        let ids: Vec<&str> = registry
            .plugins()
            .iter()
            .map(|r| r.manifest.id.as_str())
            .collect();
        assert_eq!(ids, ["atcap"], "exactly-at-cap passes, one-over rejects");

        let feed = registry
            .feed(&HostAcceptance::new("webui", style_style()))
            .unwrap();
        assert_eq!(feed.len(), 1);
        assert_eq!(feed.iter().next().unwrap().plugin_id, "atcap");
    }

    #[test]
    fn feed_fails_loud_when_a_payload_grows_past_the_cap_after_the_scan() {
        // TOCTOU backstop: the scan accepted a 4-byte payload; the file
        // then grows past the cap. Only the feed-time capped read can
        // catch it — and it must fail loud, never feed the oversized
        // bytes (the feed snapshot stays byte-exact).
        let store = TestStore::new();
        store.add_plugin(
            "beta",
            &file_manifest("beta", "style.css"),
            &[("style.css", "tiny")],
        );
        let registry = store.open_with(Registry::options().max_payload_bytes(8));

        let grown = "x".repeat(20);
        std::fs::write(store.root.path().join("beta").join("style.css"), &grown).unwrap();
        let err = registry
            .feed(&HostAcceptance::new("webui", style_style()))
            .unwrap_err();
        assert!(
            matches!(
                err,
                RegistryError::PayloadTooLarge {
                    size: 20,
                    cap: 8,
                    ..
                }
            ),
            "got: {err}"
        );

        let events = store.audit_events();
        assert!(
            events.iter().any(|e| matches!(e,
                AuditEvent::Failed { stage, reason, .. }
                if stage == "feed" && reason.contains("payload_too_large")
                    && reason.contains("20 bytes"))),
            "the oversize must be audited as a feed failure with the size: {events:?}"
        );
        assert!(!events.iter().any(|e| matches!(e, AuditEvent::Fed { .. })));
    }

    #[test]
    fn load_fails_loud_when_a_payload_grows_past_the_cap_after_the_scan() {
        let store = TestStore::new();
        store.add_plugin(
            "beta",
            &file_manifest("beta", "style.css"),
            &[("style.css", "tiny")],
        );
        let registry = store.open_with(Registry::options().max_payload_bytes(8));

        std::fs::write(
            store.root.path().join("beta").join("style.css"),
            "x".repeat(20),
        )
        .unwrap();
        let err = registry.load("beta", 0).unwrap_err();
        assert!(
            matches!(
                err,
                RegistryError::PayloadTooLarge {
                    size: 20,
                    cap: 8,
                    ..
                }
            ),
            "got: {err}"
        );
        assert!(
            store.audit_events().iter().any(|e| matches!(e,
                AuditEvent::Failed { stage, .. } if stage == "load")),
            "the oversize must be audited as a load failure"
        );
    }

    #[test]
    fn quiet_opens_compose_with_a_custom_cap() {
        let store = TestStore::new();
        let oversized = "x".repeat(9);
        store.add_plugin(
            "beta",
            &file_manifest("beta", "style.css"),
            &[("style.css", &oversized)],
        );

        let registry = store.open_with(Registry::options().quiet(true).max_payload_bytes(8));
        assert!(
            registry.plugins().is_empty(),
            "the cap applies on quiet opens"
        );
        assert!(
            store.audit_events().is_empty(),
            "quiet open writes nothing, rejection included"
        );
    }

    #[test]
    fn feed_sha_mismatch_fails_loud() {
        // The declared digest is correct at scan time; the file is then
        // tampered with, so only the feed-time re-verification can catch it.
        let store = TestStore::new();
        let css = "body { color: rebeccapurple; }\n";
        let manifest = format!(
            r#"
id = "beta"
version = "0.1.0"
provider = "test"

[[resources]]
kind = "webui.style"
order = 5

[resources.payload.File]
path = "style.css"
sha256 = "{}"
"#,
            sha256_hex(css.as_bytes())
        );
        store.add_plugin("beta", &manifest, &[("style.css", css)]);

        let registry = store.open();
        assert_eq!(registry.plugins().len(), 1, "scan must accept the plugin");

        std::fs::write(
            store.root.path().join("beta").join("style.css"),
            "tampered {}",
        )
        .unwrap();
        let err = registry
            .feed(&HostAcceptance::new("webui", style_style()))
            .unwrap_err();
        assert!(
            matches!(err, RegistryError::PayloadIntegrity { .. }),
            "got: {err}"
        );

        let events = store.audit_events();
        assert!(
            events.iter().any(|e| matches!(e,
                AuditEvent::Failed { stage, reason, .. }
                if stage == "feed" && reason.contains("mismatch"))),
            "mismatch must be audited as a feed failure: {events:?}"
        );
        assert!(
            !events.iter().any(|e| matches!(e, AuditEvent::Fed { .. })),
            "nothing may be fed from a corrupted payload"
        );
    }

    #[test]
    fn declared_escape_paths_are_rejected_at_scan_and_never_feed() {
        // The manifest declares `../escape.txt`, which points at a real
        // file outside the plugin directory (but inside the store root —
        // escaping the *plugin* directory is already a violation).
        let store = TestStore::new();
        let secret = "store-root-secret-bytes\n";
        std::fs::write(store.root.path().join("escape.txt"), secret).unwrap();
        store.add_plugin("evil", &file_manifest("evil", "../escape.txt"), &[]);

        let registry = store.open();
        assert!(
            registry.plugins().is_empty(),
            "an escaping payload must not be accepted: {:?}",
            registry.plugins()
        );
        assert_eq!(registry.rejections().len(), 1);
        assert!(
            registry.rejections()[0].reason.contains("escapes"),
            "got: {}",
            registry.rejections()[0].reason
        );

        // Nothing feeds, so the outside bytes are never handed to a host.
        let feed = registry
            .feed(&HostAcceptance::new("webui", style_style()))
            .unwrap();
        assert!(feed.is_empty(), "nothing may be fed: {feed:?}");

        let events = store.audit_events();
        assert!(
            events.iter().any(|e| matches!(e,
                AuditEvent::Rejected { reason, .. } if reason.contains("escapes"))),
            "the escape must be audited as a rejection: {events:?}"
        );
        assert!(
            !events.iter().any(|e| matches!(e,
                AuditEvent::Validated { plugin_id, .. } if plugin_id == "evil")),
            "the escaping plugin must never validate"
        );
        assert!(!events.iter().any(|e| matches!(e, AuditEvent::Fed { .. })));
        // And the secret content never lands in the audit log either.
        let audit_text = std::fs::read_to_string(store.audit_path()).unwrap();
        assert!(!audit_text.contains(secret), "content must not leak");
    }

    #[test]
    fn absolute_payload_paths_are_rejected() {
        // An absolute path would replace the plugin directory entirely in
        // `join`; it is rejected as a confinement violation even though
        // the target file exists.
        let store = TestStore::new();
        let outside = store.root.path().join("outside.css");
        std::fs::write(&outside, "body { color: red; }\n").unwrap();
        store.add_plugin("abs", &file_manifest("abs", outside.to_str().unwrap()), &[]);

        let registry = store.open();
        assert!(registry.plugins().is_empty());
        assert_eq!(registry.rejections().len(), 1);
        assert!(
            registry.rejections()[0].reason.contains("absolute"),
            "got: {}",
            registry.rejections()[0].reason
        );

        let feed = registry
            .feed(&HostAcceptance::new("webui", style_style()))
            .unwrap();
        assert!(feed.is_empty());
        assert!(
            store.audit_events().iter().any(|e| matches!(e,
                AuditEvent::Rejected { reason, .. } if reason.contains("absolute"))),
            "the rejection must be audited"
        );
    }

    #[test]
    #[cfg(unix)] // requires symlink(2)
    fn feed_rejects_payload_swapped_for_an_escape_after_the_scan() {
        // The scan accepted a confined payload; the file is then swapped
        // for a symlink pointing outside the plugin directory. Only the
        // feed-time confinement check (canonicalize resolves symlinks)
        // can catch it — the mandatory runtime defense.
        let store = TestStore::new();
        let secret = "classified-payload-bytes\n";
        std::fs::write(store.root.path().join("secret.txt"), secret).unwrap();
        store.add_plugin(
            "beta",
            &file_manifest("beta", "style.css"),
            &[("style.css", "body{}\n")],
        );

        let registry = store.open();
        assert_eq!(registry.plugins().len(), 1, "scan must accept the plugin");

        let css = store.root.path().join("beta").join("style.css");
        std::fs::remove_file(&css).unwrap();
        std::os::unix::fs::symlink(store.root.path().join("secret.txt"), &css).unwrap();

        let err = registry
            .feed(&HostAcceptance::new("webui", style_style()))
            .unwrap_err();
        assert!(
            matches!(err, RegistryError::PayloadIntegrity { .. }),
            "got: {err}"
        );
        assert!(err.to_string().contains("escapes"), "got: {err}");
        assert!(!err.to_string().contains(secret), "content must not leak");

        let events = store.audit_events();
        assert!(
            events.iter().any(|e| matches!(e,
                AuditEvent::Failed { stage, reason, .. }
                if stage == "feed" && reason.contains("escapes"))),
            "the escape must be audited as a feed failure: {events:?}"
        );
        assert!(
            !events.iter().any(|e| matches!(e, AuditEvent::Fed { .. })),
            "nothing may be fed through a symlink escape"
        );
    }

    #[test]
    #[cfg(unix)] // requires symlink(2)
    fn load_rejects_payload_swapped_for_an_escape_after_the_scan() {
        // The load-time read re-runs the same confinement check, so a
        // symlink planted between feed and load is caught too.
        let store = TestStore::new();
        std::fs::write(store.root.path().join("secret.txt"), "classified\n").unwrap();
        store.add_plugin(
            "beta",
            &file_manifest("beta", "style.css"),
            &[("style.css", "body{}\n")],
        );

        let registry = store.open();
        let css = store.root.path().join("beta").join("style.css");
        std::fs::remove_file(&css).unwrap();
        std::os::unix::fs::symlink(store.root.path().join("secret.txt"), &css).unwrap();

        let err = registry.load("beta", 0).unwrap_err();
        assert!(
            matches!(err, RegistryError::PayloadIntegrity { .. }),
            "got: {err}"
        );
        assert!(err.to_string().contains("escapes"), "got: {err}");

        assert!(
            store.audit_events().iter().any(|e| matches!(e,
                AuditEvent::Failed { stage, reason, .. }
                if stage == "load" && reason.contains("escapes"))),
            "the escape must be audited as a load failure"
        );
    }

    #[test]
    fn feed_resolves_file_payloads_in_nested_subdirectories() {
        // Confinement must not over-restrict: a payload in a nested
        // subdirectory of the plugin directory is legitimate.
        let store = TestStore::new();
        let css = "body { font: serif; }\n";
        store.add_plugin(
            "beta",
            &file_manifest("beta", "assets/style.css"),
            &[("assets/style.css", css)],
        );

        let registry = store.open();
        assert_eq!(registry.plugins().len(), 1);
        let feed = registry
            .feed(&HostAcceptance::new("webui", style_style()))
            .unwrap();
        assert_eq!(feed.len(), 1);
        match &feed.iter().next().unwrap().resolved {
            ResolvedPayload::File { bytes, sha256 } => {
                assert_eq!(bytes, css.as_bytes());
                assert_eq!(sha256, &sha256_hex(css.as_bytes()));
            }
            other => panic!("expected file payload, got {other:?}"),
        }
    }

    #[test]
    fn load_and_explicit_unload_audited_end_to_end() {
        let store = TestStore::new();
        store.add_plugin("beta", BETA, &[]);

        let registry = store.open();
        let feed = registry
            .feed(&HostAcceptance::new("webui", style_style()))
            .unwrap();
        let item = feed.iter().next().unwrap().clone();
        let handle = registry.load(&item.plugin_id, item.entry_index).unwrap();
        let handle_id = handle.id().expect("live handle carries its id");
        handle.unload().unwrap();

        let events = store.audit_events();
        let loaded = events
            .iter()
            .find(|e| matches!(e, AuditEvent::Loaded { .. }))
            .expect("loaded event");
        assert!(matches!(loaded,
            AuditEvent::Loaded { plugin_id, kind, handle, .. }
            if plugin_id == "beta" && kind == "webui.style" && *handle == handle_id));
        assert!(matches!(
            events.last(),
            Some(AuditEvent::Unloaded { handle, dropped, .. }) if *handle == handle_id && !*dropped
        ));
    }

    #[test]
    fn load_then_drop_audits_dropped_unload() {
        let store = TestStore::new();
        store.add_plugin("beta", BETA, &[]);

        let registry = store.open();
        let handle = registry.load("beta", 0).unwrap();
        let handle_id = handle.id().expect("live handle carries its id");
        drop(handle);

        let events = store.audit_events();
        assert!(matches!(
            events.last(),
            Some(AuditEvent::Unloaded { handle, dropped, .. }) if *handle == handle_id && *dropped
        ));
    }

    #[test]
    fn load_rejects_unknown_disabled_and_out_of_bounds() {
        let store = TestStore::new();
        store.add_plugin("beta", BETA, &[]);

        let mut registry = store.open();
        assert!(matches!(
            registry.load("ghost", 0).unwrap_err(),
            RegistryError::UnknownPlugin(_)
        ));
        assert!(matches!(
            registry.load("beta", 9).unwrap_err(),
            RegistryError::EntryIndexOutOfBounds { .. }
        ));

        registry.set_enabled("beta", false).unwrap();
        assert!(matches!(
            registry.load("beta", 0).unwrap_err(),
            RegistryError::PluginDisabled(_)
        ));

        // every failed load is audited as a `failed` event
        let events = store.audit_events();
        let failed: Vec<&AuditEvent> = events
            .iter()
            .filter(|e| matches!(e, AuditEvent::Failed { .. }))
            .collect();
        assert_eq!(failed.len(), 3, "failed loads must be audited: {events:?}");
    }

    #[test]
    fn register_local_to_unload_audit_sequence_is_complete() {
        let store = TestStore::new();

        let registry = store.open();
        let registration = registry
            .register_local(
                ResourceEntry {
                    kind: ResourceKind::new(crate::kinds::TOOL_MCP).unwrap(),
                    name: Some("acme.lookup".into()),
                    order: 0,
                    payload: Payload::Inline(serde_json::json!({
                        "description": "Look things up",
                        "schema": {}
                    })),
                },
                "plugin-host",
            )
            .unwrap();

        let handle = registry.load_local(&registration).unwrap();
        handle.unload().unwrap();

        let events = store.audit_events();
        let kinds: Vec<String> = events
            .iter()
            .map(|e| {
                serde_json::to_value(e)
                    .unwrap()
                    .get("event")
                    .and_then(|v| v.as_str())
                    .unwrap()
                    .to_string()
            })
            .collect();
        assert_eq!(
            kinds,
            ["discovered", "validated", "loaded", "unloaded"],
            "the full register->handle->unload sequence must be audited"
        );
        assert!(matches!(&events[0],
            AuditEvent::Discovered { source, plugin_id, .. }
            if source == "local" && plugin_id.as_deref() == Some("plugin-host")));
        assert!(matches!(&events[1],
            AuditEvent::Validated { plugin_id, version, resources, .. }
            if plugin_id == "plugin-host" && version.is_none() && *resources == 1));
        assert!(matches!(&events[3],
            AuditEvent::Unloaded { plugin_id, kind, dropped, .. }
            if plugin_id == "plugin-host" && kind == "tool.mcp" && !*dropped));
    }

    #[test]
    fn register_local_rejects_file_payloads() {
        let store = TestStore::new();
        let registry = store.open();
        let err = registry
            .register_local(
                ResourceEntry {
                    kind: ResourceKind::new(crate::kinds::WEBUI_STYLE).unwrap(),
                    name: None,
                    order: 0,
                    payload: Payload::File {
                        path: "style.css".into(),
                        sha256: None,
                    },
                },
                "plugin-host",
            )
            .unwrap_err();
        assert!(matches!(err, RegistryError::UnsupportedLocalPayload(_)));
        assert!(
            store.audit_events().iter().any(|e| matches!(e,
                AuditEvent::Failed { stage, .. } if stage == "register_local")),
            "the rejection must be audited"
        );
    }

    #[test]
    fn audit_log_is_valid_jsonl_throughout() {
        let store = TestStore::new();
        store.add_plugin("alpha", ALPHA, &[("style.css", "body{}\n")]);
        store.add_plugin("bad", "not = \"a manifest\"\n", &[]);

        let mut registry = store.open();
        registry.set_enabled("alpha", false).unwrap();
        registry.set_enabled("alpha", true).unwrap();
        let feed = registry
            .feed(&HostAcceptance::new(
                "webui",
                vec![
                    ResourceKind::new(crate::kinds::WEBUI_STYLE).unwrap(),
                    ResourceKind::new(crate::kinds::WEBUI_THEME).unwrap(),
                ],
            ))
            .unwrap();
        for item in feed.iter() {
            let handle = registry.load(&item.plugin_id, item.entry_index).unwrap();
            handle.unload().unwrap();
        }
        let registration = registry
            .register_local(
                ResourceEntry {
                    kind: ResourceKind::new(crate::kinds::SANDBOX_ENV).unwrap(),
                    name: None,
                    order: 0,
                    payload: Payload::Inline(serde_json::json!({ "LANG": "C" })),
                },
                "sandbox",
            )
            .unwrap();
        drop(registry.load_local(&registration).unwrap());

        // Every line parses back into an AuditEvent (JSONL validity).
        let events = store.audit_events();
        assert!(
            events.len() >= 15,
            "a busy registry must leave a rich trail: {}",
            events.len()
        );
        let text = std::fs::read_to_string(store.audit_path()).unwrap();
        assert_eq!(text.lines().count(), events.len());
        assert!(
            text.ends_with('\n'),
            "each event is one newline-terminated line"
        );
    }

    #[test]
    fn open_fails_loud_on_bad_audit_path() {
        let store = TestStore::new();
        let blocker = store.root.path().join("blocked.jsonl");
        std::fs::create_dir(&blocker).unwrap();
        let err = Registry::open(store.store_dir(), &blocker).unwrap_err();
        assert!(matches!(err, RegistryError::Audit(_)), "got: {err}");
    }

    #[test]
    fn open_fails_loud_on_missing_store() {
        let store = TestStore::new();
        let missing = store.root.path().join("missing-store");
        let err = Registry::open(&missing, &store.audit_path()).unwrap_err();
        assert!(
            err.to_string().contains("cannot read plugin store"),
            "got: {err}"
        );
    }
    // ── The publisher-keys builder option (C4-3) ───────────────────

    #[test]
    fn the_builder_keys_switch_the_scan_into_the_trust_lane() {
        use crate::trust::PublisherKey;
        use ed25519_dalek::{Signer, SigningKey};
        use rand::rngs::OsRng;

        let root = std::env::temp_dir().join(format!(
            "akivili-reg-keys-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let plugin = root.join("plugins/signed-plugin");
        std::fs::create_dir_all(&plugin).unwrap();
        std::fs::write(
            plugin.join("akivili.plugin.toml"),
            r#"schema = 2
id = "signed-plugin"
version = "1.0.0"
provider = "official"
form = "web.vue-module"

[trust]
signature = "agent.sig"
min-trust = "signed"
"#,
        )
        .unwrap();
        let signing = SigningKey::generate(&mut OsRng);
        let signature = signing.sign(b"");
        std::fs::write(plugin.join("agent.sig"), signature.to_bytes()).unwrap();
        let audit = root.join("audit.jsonl");

        // With the key: the plugin scans in.
        let registry = Registry::options()
            .publisher_keys(vec![PublisherKey {
                key_id: "builder-key".into(),
                bytes: signing.verifying_key().to_bytes(),
            }])
            .open(&root.join("plugins"), &audit);
        match registry {
            Ok(registry) => {
                let record = registry
                    .plugins()
                    .iter()
                    .find(|r| r.manifest.id == "signed-plugin")
                    .expect("present");
                assert_eq!(record.manifest.id, "signed-plugin");
            }
            Err(e) => panic!("the keyed lane must accept a validly signed plugin: {e}"),
        }

        // Without the key (plain open): the same plugin fails closed.
        match Registry::open(&root.join("plugins"), &audit) {
            Ok(_) => panic!("the unsigned lane must reject the demanding plugin"),
            Err(_) => {}
        }
        let _ = std::fs::remove_dir_all(&root);
    }
}
