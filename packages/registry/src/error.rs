use thiserror::Error;

/// Errors raised by the registry crate.
///
/// Per-plugin validation failures during a store scan are *not* errors of
/// this type: they are recorded as [`crate::store::Rejection`]s (and audited
/// as `rejected` events) so one broken plugin directory never hides the
/// rest of the store. This type covers the fail-loud paths: audit-log and
/// state-file IO, unknown or disabled plugins, payload integrity failures
/// at feed/load time, and payloads exceeding the configured size cap at
/// any payload read (see
/// [`RegistryOptions::max_payload_bytes`](crate::RegistryOptions::max_payload_bytes)).
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

    #[error(
        "invalid capability '{0}': must come from the closed v1 vocabulary (optionally as word:parameter, e.g. http.egress:api.github.com)"
    )]
    InvalidCapability(String),

    #[error(
        "invalid contract reference '{0}': expected celestia:<domain>/<world>@<major>.<minor> (e.g. celestia:panel/host@0.1)"
    )]
    InvalidContractRef(String),

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

    /// A file payload exceeded the configured per-payload size cap at
    /// read time (scan validation, feed, or load). `size` is the measured
    /// size — always at least `cap + 1` bytes; `path` is the
    /// manifest-declared payload path.
    #[error("payload_too_large: '{path}' is {size} bytes, exceeding the cap of {cap} bytes")]
    PayloadTooLarge {
        plugin_id: String,
        path: String,
        size: u64,
        cap: u64,
    },

    #[error("local registrations only support inline payloads: {0}")]
    UnsupportedLocalPayload(String),
}

pub type RegistryResult<T> = Result<T, RegistryError>;
