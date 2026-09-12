use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU64, Ordering},
};

use crate::audit::{AuditEvent, AuditLog, unix_secs};
use crate::error::{RegistryError, RegistryResult};
use crate::kinds::ResourceKind;
use crate::manifest::ResourceEntry;

/// Registry state shared with handles (the audit log and the handle-id
/// allocator); kept alive by [`crate::Registry`] and every live handle.
#[derive(Debug)]
pub(crate) struct RegistryInner {
    pub(crate) audit: Mutex<AuditLog>,
    pub(crate) next_handle_id: AtomicU64,
}

impl RegistryInner {
    pub(crate) fn from_audit(audit: AuditLog) -> Self {
        Self {
            audit: Mutex::new(audit),
            next_handle_id: AtomicU64::new(0),
        }
    }

    pub(crate) fn allocate_handle_id(&self) -> u64 {
        self.next_handle_id.fetch_add(1, Ordering::Relaxed) + 1
    }

    pub(crate) fn append_audit(&self, event: AuditEvent) -> RegistryResult<()> {
        self.audit
            .lock()
            .map_err(|_| RegistryError::Audit("audit log mutex poisoned".into()))?
            .append(&event)
    }
}

/// The identity half of a [`ResourceHandle`], taken on unload.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct HandleInfo {
    pub(crate) id: u64,
    pub(crate) plugin_id: String,
    pub(crate) kind: ResourceKind,
}

/// A loaded resource, returned by [`crate::Registry::load`] and
/// [`crate::Registry::load_local`].
///
/// The handle is the host's statement "I have loaded this resource"; it is
/// the audit anchor for the resource's lifetime. Release it explicitly with
/// [`ResourceHandle::unload`]; dropping an un-released handle still records
/// an `unloaded` audit event, marked `dropped: true`, so a lost handle is
/// visible in the trail rather than silent.
#[derive(Debug)]
pub struct ResourceHandle {
    info: Option<HandleInfo>,
    inner: Arc<RegistryInner>,
}

impl ResourceHandle {
    pub(crate) fn new(inner: Arc<RegistryInner>, info: HandleInfo) -> Self {
        Self {
            info: Some(info),
            inner,
        }
    }

    /// The handle's registry-unique id (monotonic, never reused), or
    /// `None` once the handle has been unloaded or dropped — the
    /// identity is taken on release, and a spent handle reports no
    /// dummy values.
    pub fn id(&self) -> Option<u64> {
        self.info.as_ref().map(|i| i.id)
    }

    /// The plugin (or runtime provider) the resource belongs to, or
    /// `None` once the handle has been unloaded or dropped.
    pub fn plugin_id(&self) -> Option<&str> {
        self.info.as_ref().map(|i| i.plugin_id.as_str())
    }

    /// The resource kind, or `None` once the handle has been unloaded
    /// or dropped.
    pub fn kind(&self) -> Option<&ResourceKind> {
        self.info.as_ref().map(|i| &i.kind)
    }

    /// Explicitly unloads the resource: records an `unloaded` audit event
    /// (`dropped: false`) and consumes the handle.
    pub fn unload(mut self) -> RegistryResult<()> {
        // `take()` (not a move out of `self`): `ResourceHandle` implements
        // Drop, so fields cannot be moved out; Drop then sees `None` and
        // stays silent — exactly one unload event per handle.
        let Some(info) = self.info.take() else {
            return Ok(());
        };
        self.inner.append_audit(AuditEvent::Unloaded {
            ts: unix_secs(),
            plugin_id: info.plugin_id,
            kind: info.kind.to_string(),
            handle: info.id,
            dropped: false,
        })
    }
}

impl Drop for ResourceHandle {
    fn drop(&mut self) {
        if let Some(info) = self.info.take() {
            let event = AuditEvent::Unloaded {
                ts: unix_secs(),
                plugin_id: info.plugin_id,
                kind: info.kind.to_string(),
                handle: info.id,
                dropped: true,
            };
            // Drop cannot propagate errors; a failed final audit line is
            // reported on stderr so it is at least visible.
            if let Err(e) = self.inner.append_audit(event) {
                eprintln!("akivili_registry: drop-time audit failed: {e}");
            }
        }
    }
}

/// The source returned by [`crate::Registry::register_local`]: an
/// in-process resource registration that never touches the disk store.
///
/// Cloneable and shareable; pass it back to [`crate::Registry::load_local`]
/// when the host actually declares the resource loaded.
#[derive(Debug, Clone, PartialEq)]
pub struct LocalRegistration {
    /// The registering provider (fills the `plugin_id` audit fields for
    /// this resource).
    pub provider: String,
    /// The registered entry; always an inline payload.
    pub entry: ResourceEntry,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::Payload;

    fn inner_with_log(path: &std::path::Path) -> Arc<RegistryInner> {
        let log = AuditLog::open(path).unwrap();
        Arc::new(RegistryInner {
            audit: Mutex::new(log),
            next_handle_id: AtomicU64::new(0),
        })
    }

    fn read_events(path: &std::path::Path) -> Vec<AuditEvent> {
        let text = std::fs::read_to_string(path).unwrap();
        text.lines()
            .map(serde_json::from_str)
            .collect::<Result<_, _>>()
            .unwrap()
    }

    fn sample_info(id: u64) -> HandleInfo {
        HandleInfo {
            id,
            plugin_id: "acme".into(),
            kind: ResourceKind::new(crate::kinds::WEBUI_STYLE).unwrap(),
        }
    }

    #[test]
    fn handle_ids_are_unique_and_monotonic() {
        let dir = tempfile::tempdir().unwrap();
        let inner = inner_with_log(&dir.path().join("a.jsonl"));
        assert_eq!(inner.allocate_handle_id(), 1);
        assert_eq!(inner.allocate_handle_id(), 2);
        assert_eq!(inner.allocate_handle_id(), 3);
    }

    #[test]
    fn explicit_unload_audits_once_not_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.jsonl");
        let inner = inner_with_log(&path);

        let handle = ResourceHandle::new(inner.clone(), sample_info(1));
        assert_eq!(handle.id(), Some(1));
        assert_eq!(handle.plugin_id(), Some("acme"));
        assert_eq!(
            handle.kind(),
            Some(&ResourceKind::new(crate::kinds::WEBUI_STYLE).unwrap())
        );
        handle.unload().unwrap();

        let events = read_events(&path);
        assert_eq!(events.len(), 1, "exactly one unload event: {events:?}");
        match &events[0] {
            AuditEvent::Unloaded {
                plugin_id,
                kind,
                handle,
                dropped,
                ..
            } => {
                assert_eq!(plugin_id, "acme");
                assert_eq!(kind, "webui.style");
                assert_eq!(*handle, 1);
                assert!(!*dropped);
            }
            other => panic!("expected Unloaded, got {other:?}"),
        }
    }

    #[test]
    fn drop_fallback_audits_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.jsonl");
        let inner = inner_with_log(&path);

        {
            let _handle = ResourceHandle::new(inner.clone(), sample_info(2));
        } // dropped without unload

        let events = read_events(&path);
        assert_eq!(events.len(), 1);
        match &events[0] {
            AuditEvent::Unloaded {
                dropped, handle, ..
            } => {
                assert!(*dropped);
                assert_eq!(*handle, 2);
            }
            other => panic!("expected Unloaded, got {other:?}"),
        }
    }

    #[test]
    fn spent_handle_accessors_report_none() {
        // The exact state `unload`/`Drop` leave behind: the identity
        // taken, the shell still dropping silently. A spent handle must
        // not fabricate dummy values, and its final drop must not audit
        // a second unload event.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.jsonl");
        let inner = inner_with_log(&path);

        let spent = ResourceHandle {
            info: None,
            inner: inner.clone(),
        };
        assert_eq!(spent.id(), None);
        assert_eq!(spent.plugin_id(), None);
        assert!(spent.kind().is_none());
        drop(spent);

        let events = read_events(&path);
        assert!(
            events.is_empty(),
            "dropping a spent handle must not audit: {events:?}"
        );
    }

    #[test]
    fn local_registration_carries_inline_payload() {
        let entry = ResourceEntry {
            kind: ResourceKind::new(crate::kinds::SANDBOX_ENV).unwrap(),
            name: Some("proxy".into()),
            order: 0,
            payload: Payload::Inline(serde_json::json!({ "HTTP_PROXY": "http://192.0.2.1:7890" })),
        };
        let reg = LocalRegistration {
            provider: "plugin-host".into(),
            entry: entry.clone(),
        };
        assert_eq!(reg.clone(), reg);
        assert_eq!(reg.provider, "plugin-host");
        assert_eq!(reg.entry.name.as_deref(), Some("proxy"));
    }

    #[test]
    fn audit_writer_flushes_per_append() {
        // An append must be durable immediately: write via a fresh handle,
        // then read back through the file (not the writer). Reopening in
        // append mode must also preserve pre-existing content.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.jsonl");
        let mut log = AuditLog::open(&path).unwrap();
        log.append(&AuditEvent::Enabled {
            ts: 42,
            plugin_id: "p".into(),
        })
        .unwrap();
        drop(log);

        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.lines().count(), 1, "append must flush: {text}");

        let mut log = AuditLog::open(&path).unwrap();
        log.append(&AuditEvent::Disabled {
            ts: 43,
            plugin_id: "p".into(),
        })
        .unwrap();
        drop(log);
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.lines().count(), 2);
    }
}
