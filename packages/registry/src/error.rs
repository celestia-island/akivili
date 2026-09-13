use thiserror::Error;

/// Errors raised by the registry crate.
///
/// Per-plugin validation failures during a store scan are *not* errors of
/// this type: they are recorded as [`crate::store::Rejection`]s (and audited
/// as `rejected` events) so one broken plugin directory never hides the
/// rest of the store. This type covers the fail-loud paths: audit-log and
/// state-file IO, unknown or disabled plugins, and payload integrity
/// failures at feed/load time.
#[derive(Debug, Error)]
pub enum RegistryError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("audit log error: {0}")]
    Audit(String),

    #[error("registry state file error: {0}")]
    State(String),

    #[error("invalid resource kind '{0}': must match ^[a-z0-9-]+(\\.[a-z0-9-]+)+$")]
    InvalidResourceKind(String),

    #[error("invalid plugin manifest: {0}")]
    InvalidManifest(String),

    #[error("unknown plugin id '{0}'")]
    UnknownPlugin(String),

    #[error("plugin '{0}' is disabled")]
    PluginDisabled(String),

    #[error("entry index {index} out of bounds for plugin '{plugin_id}'")]
    EntryIndexOutOfBounds { plugin_id: String, index: usize },

    /// A file payload failed its read-time verification: unreadable,
    /// declared-digest mismatch, or a declared path that escapes the
    /// owning plugin directory (absolute, `..` walk, or symlink hop).
    #[error("payload integrity failure for plugin '{plugin_id}': {reason}")]
    PayloadIntegrity { plugin_id: String, reason: String },

    #[error("local registrations only support inline payloads: {0}")]
    UnsupportedLocalPayload(String),
}

pub type RegistryResult<T> = Result<T, RegistryError>;
