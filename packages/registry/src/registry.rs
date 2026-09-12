use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::acceptance::HostAcceptance;
use crate::audit::{AuditEvent, AuditLog, unix_secs};
use crate::error::{RegistryError, RegistryResult};
use crate::feed::{FeedItem, ResolvedPayload, ResourceFeed};
use crate::handle::{HandleInfo, LocalRegistration, RegistryInner, ResourceHandle};
use crate::manifest::{Payload, ResourceEntry};
use crate::store::{
    self, EnabledState, PluginRecord, Rejection, STATE_FILE, ScanResult, sha256_hex,
};

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
    pub fn open(store_dir: &Path, audit_path: &Path) -> RegistryResult<Self> {
        Self::open_impl(store_dir, audit_path, true)
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
        Self::open_impl(store_dir, audit_path, false)
    }

    fn open_impl(
        store_dir: &Path,
        audit_path: &Path,
        audit_scan_replay: bool,
    ) -> RegistryResult<Self> {
        let audit = AuditLog::open(audit_path)?;
        let inner = Arc::new(RegistryInner::from_audit(audit));

        let state_path = store_dir.join(STATE_FILE);
        let state = EnabledState::load(&state_path)?;
        let scan = store::scan(store_dir, &state)?;

        let mut records = Vec::new();
        let mut rejections = Vec::new();
        for result in scan {
            match result {
                ScanResult::Accepted(record) => {
                    if audit_scan_replay {
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
                    if audit_scan_replay {
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
    /// declared kinds, resolves payloads (file bytes are read and digested
    /// now), orders the result (entry `order` ascending, ties by plugin
    /// id, then manifest position), and audits one `fed` event per item.
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
    /// payloads against their declared digests (the file may have changed
    /// since the scan), audits `loaded`, and returns a handle. Loading
    /// from a disabled plugin is an error — `set_enabled(false)` is the
    /// store-level off switch.
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
                let bytes = match std::fs::read(record.dir.join(path)) {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        let err = RegistryError::PayloadIntegrity {
                            plugin_id: plugin_id.to_string(),
                            reason: format!("cannot read payload '{}': {e}", path.display()),
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
    /// digests; failures audit `failed` and bubble up (feed is fail-loud —
    /// one corrupted payload surfaces rather than being silently skipped).
    fn resolve_payload(
        &self,
        record: &PluginRecord,
        entry: &ResourceEntry,
    ) -> RegistryResult<ResolvedPayload> {
        match &entry.payload {
            Payload::Inline(value) => Ok(ResolvedPayload::Inline(value.clone())),
            Payload::File { path, sha256 } => {
                let full = record.dir.join(path);
                let bytes = match std::fs::read(&full) {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        let err = RegistryError::PayloadIntegrity {
                            plugin_id: record.manifest.id.clone(),
                            reason: format!("cannot read payload '{}': {e}", full.display()),
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
                std::fs::write(dir.join(file), content).unwrap();
            }
        }

        fn open(&self) -> Registry {
            Registry::open(self.store_dir(), &self.audit_path()).unwrap()
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
}
