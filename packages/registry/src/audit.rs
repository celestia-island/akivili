use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::error::{RegistryError, RegistryResult};

/// Seconds since the Unix epoch, the audit timestamp unit.
pub(crate) fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// One line of the append-only audit trail.
///
/// Serialized as a single JSON object tagged with `"event": "…"`, one JSON
/// object per line (JSONL). `ts` is Unix-epoch seconds; `plugin_id`,
/// `kind`, `host_id`, `reason`, and payload digests appear on the variants
/// where they apply.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum AuditEvent {
    /// A plugin source entered the scan: `source` is the plugin directory
    /// (or `"local"` for runtime registrations); `plugin_id` is known only
    /// when the manifest parsed far enough to read it.
    Discovered {
        ts: u64,
        source: String,
        plugin_id: Option<String>,
    },
    /// A plugin passed validation and joined the registry.
    Validated {
        ts: u64,
        plugin_id: String,
        version: Option<String>,
        resources: usize,
    },
    /// A plugin source was rejected, with the reason.
    Rejected {
        ts: u64,
        source: String,
        plugin_id: Option<String>,
        reason: String,
    },
    Enabled {
        ts: u64,
        plugin_id: String,
    },
    Disabled {
        ts: u64,
        plugin_id: String,
    },
    /// One resource entry was fed to a host.
    Fed {
        ts: u64,
        plugin_id: String,
        kind: String,
        host_id: String,
        order: i32,
        name: Option<String>,
        sha256: Option<String>,
    },
    /// A host declared a resource loaded; `handle` identifies the returned
    /// resource handle.
    Loaded {
        ts: u64,
        plugin_id: String,
        kind: String,
        handle: u64,
        sha256: Option<String>,
    },
    /// A resource handle was released; `dropped: true` marks the Drop
    /// fallback (the host never called unload explicitly).
    Unloaded {
        ts: u64,
        plugin_id: String,
        kind: String,
        handle: u64,
        dropped: bool,
    },
    /// An operation failed loudly (feed resolution, load preconditions,
    /// runtime registration); the reason is recorded.
    Failed {
        ts: u64,
        stage: String,
        plugin_id: Option<String>,
        reason: String,
    },
}

impl AuditEvent {
    /// The event's Unix-epoch-seconds timestamp, regardless of variant.
    pub fn ts(&self) -> u64 {
        match self {
            AuditEvent::Discovered { ts, .. }
            | AuditEvent::Validated { ts, .. }
            | AuditEvent::Rejected { ts, .. }
            | AuditEvent::Enabled { ts, .. }
            | AuditEvent::Disabled { ts, .. }
            | AuditEvent::Fed { ts, .. }
            | AuditEvent::Loaded { ts, .. }
            | AuditEvent::Unloaded { ts, .. }
            | AuditEvent::Failed { ts, .. } => *ts,
        }
    }
}

/// An append-only JSONL audit log.
///
/// Opening is fail-loud: an unopenable audit path is an error, never a
/// silent skip. Every append is flushed before returning so a crash cannot
/// lose the tail of the trail.
pub struct AuditLog {
    writer: BufWriter<File>,
}

impl std::fmt::Debug for AuditLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditLog").finish_non_exhaustive()
    }
}

impl AuditLog {
    /// Opens (creating if needed) the audit log in append mode.
    pub fn open(path: &Path) -> RegistryResult<Self> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)
                .map_err(|e| RegistryError::Audit(format!("cannot create audit dir: {e}")))?;
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| RegistryError::Audit(format!("cannot open audit log: {e}")))?;
        Ok(Self {
            writer: BufWriter::new(file),
        })
    }

    /// Appends one event as a JSON line and flushes.
    pub fn append(&mut self, event: &AuditEvent) -> RegistryResult<()> {
        let mut line = serde_json::to_string(event)
            .map_err(|e| RegistryError::Audit(format!("cannot serialize audit event: {e}")))?;
        line.push('\n');
        self.writer
            .write_all(line.as_bytes())
            .and_then(|()| self.writer.flush())
            .map_err(|e| RegistryError::Audit(format!("cannot write audit log: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn events_serialize_as_tagged_jsonl_objects() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("audit.jsonl");
        let mut log = AuditLog::open(&path)?;

        log.append(&AuditEvent::Discovered {
            ts: 1,
            source: "/store/acme".into(),
            plugin_id: Some("acme".into()),
        })?;
        log.append(&AuditEvent::Fed {
            ts: 2,
            plugin_id: "acme".into(),
            kind: "webui.style".into(),
            host_id: "webui".into(),
            order: 5,
            name: Some("dark".into()),
            sha256: Some("abc123".into()),
        })?;
        log.append(&AuditEvent::Unloaded {
            ts: 3,
            plugin_id: "acme".into(),
            kind: "webui.style".into(),
            handle: 7,
            dropped: true,
        })?;
        drop(log);

        let text = std::fs::read_to_string(&path)?;
        let events: Vec<AuditEvent> = text
            .lines()
            .map(serde_json::from_str)
            .collect::<Result<_, _>>()?;
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].ts(), 1);
        assert_eq!(
            events[1],
            AuditEvent::Fed {
                ts: 2,
                plugin_id: "acme".into(),
                kind: "webui.style".into(),
                host_id: "webui".into(),
                order: 5,
                name: Some("dark".into()),
                sha256: Some("abc123".into()),
            }
        );
        assert!(text.contains("\"event\":\"fed\""));
        assert!(text.contains("\"dropped\":true"));
        Ok(())
    }

    #[test]
    fn open_fails_loud_on_unopenable_path() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        // A directory where the log file should be cannot be opened for append.
        let blocker = dir.path().join("audit.jsonl");
        std::fs::create_dir(&blocker)?;
        assert!(AuditLog::open(&blocker).is_err());
        Ok(())
    }
}
