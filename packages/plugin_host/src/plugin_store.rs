//! Plugin persistent state — the P1 state contract of the plugin hot-swap
//! project (design `_plan-archive/workspace/20261109-entelecheia-plugin-hotswap-design.md`).
//!
//! Scope: kv persistence per plugin (data directory separated from the
//! package directory), an explicit [`PluginState`] contract with a monotonic
//! [`PluginState::state_version`] (0 is illegal), fail-closed version
//! matching, and a pure-function migration runner with idempotent stepping
//! and loss-free rollback. The lifecycle state machine, wasm wiring and the
//! hot-swap sequence are P2/P3 and intentionally not here.
//!
//! Naming discipline (design §4.3): a *state migration* (this module, future
//! manifest key `[[state_migrations]]`) moves plugin kv data between
//! `state_version`s and is unrelated to the existing *database* `[[migrations]]`
//! in `akivili_registry::manifest`, which the host executes against domain
//! databases. Never reuse the two names for each other.
//!
//! hifumi's load-bearing seam: Rust-side typed state steps. A
//! `#[hifumi::version]`-annotated struct carries a `$version` tag in its JSON
//! form and auto-migrates old payloads on deserialization; [`typed_state_step`]
//! wraps that chain as one migration step over a kv entry, so compile-time
//! typed plugin state migrates through the same runner as dynamic state.
//!
//! Concurrency invariant: one writer per `(plugin_id, state_version)` at a
//! time. P1 ships no call sites and the host is single-process, so nothing
//! can race today; P2's hot-swap deliberately overlaps draining (old
//! instance) with loading (new instance) of the same plugin, and MUST add a
//! per-plugin lock or drain barrier around `save`/`migrate` before that
//! overlap exists.

use std::{collections::BTreeMap, fs, path::PathBuf, sync::Arc};

use anyhow::{Context as _, Result, anyhow};
use serde::{Deserialize, Serialize};

/// Smallest legal `state_version`. The contract is monotonic and starts at 1;
/// 0 is illegal everywhere (save, load and migration alike reject it).
pub const MIN_STATE_VERSION: u32 = 1;

/// The persisted plugin state contract (design §4.1).
///
/// `kv` is the persistent form of the in-memory plugin kv: plugin-owned
/// string-to-string pairs. Host-managed metadata (updated_at, schema digest)
/// stays outside the plugin-visible surface and is therefore not modeled in
/// P1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginState {
    /// Data schema version, self-declared by the plugin, monotonically
    /// increasing. 0 is illegal ([`MIN_STATE_VERSION`]).
    pub state_version: u32,
    /// Plugin-owned key-value pairs.
    #[serde(default)]
    pub kv: BTreeMap<String, String>,
}

impl PluginState {
    /// A fresh state at `version` with empty kv. Rejects versions below
    /// [`MIN_STATE_VERSION`].
    pub fn empty_at(version: u32) -> Result<Self> {
        if version < MIN_STATE_VERSION {
            anyhow::bail!("state_version {version} below minimum {MIN_STATE_VERSION}");
        }
        Ok(Self {
            state_version: version,
            kv: BTreeMap::new(),
        })
    }
}

/// Fail-closed store errors with machine-readable codes (design §6: every
/// error class carries a code; no swallowed degradation).
#[derive(Debug, thiserror::Error)]
pub enum PluginStoreError {
    /// A state file exists whose `state_version` does not equal the version
    /// the caller expects. Covers both stale (found < expected) and downgrade
    /// (found > expected) reads — the contract never silently converts,
    /// guesses, or downgrades.
    #[error("plugin {plugin_id}: state version mismatch: found {found}, expected {expected}")]
    VersionMismatch {
        plugin_id: String,
        found: u32,
        expected: u32,
    },

    /// A `state_version` below [`MIN_STATE_VERSION`] appeared (save, load, or
    /// migration target).
    #[error("plugin {plugin_id}: illegal state_version {found} (minimum {MIN_STATE_VERSION})")]
    InvalidStateVersion { plugin_id: String, found: u32 },

    /// The `plugin_id` is not a legal id (`[a-z0-9][a-z0-9-]*`). Ids become
    /// path segments under the data root, so traversal-shaped ids (`..`,
    /// `/`, absolute) are rejected fail-closed instead of escaping the root
    /// (design §4.2: no silent fallback).
    #[error("invalid plugin id {plugin_id:?}: expected [a-z0-9][a-z0-9-]*")]
    InvalidPluginId { plugin_id: String },

    /// The state file exists but cannot be parsed as a [`PluginState`].
    #[error("plugin {plugin_id}: corrupt state file {path}: {source}")]
    CorruptState {
        plugin_id: String,
        path: PathBuf,
        source: anyhow::Error,
    },

    /// A migration step failed. Disk keeps the last successfully persisted
    /// version, so the plugin stays runnable at that version (loss-free
    /// rollback = reload the snapshot still on disk).
    #[error(
        "plugin {plugin_id}: state migration step {from} -> {to} failed: {source} \
         (state on disk remains at {from})"
    )]
    MigrationFailed {
        plugin_id: String,
        from: u32,
        to: u32,
        source: anyhow::Error,
    },

    /// The migration table has a gap between the current and target version.
    /// Fail-closed: gaps never skip silently, and the check runs *before* any
    /// step executes (a misconfigured table never does partial work).
    #[error("plugin {plugin_id}: no migration step from {from} (table gap before target {target})")]
    MissingStep {
        plugin_id: String,
        from: u32,
        target: u32,
    },

    /// The migration table registered two steps for the same `from` version.
    /// An ambiguous table is a programming error, never silently overwritten.
    #[error("migration table conflict: duplicate step from {from}")]
    TableConflict { from: u32 },

    /// Filesystem failure while reading or writing state.
    #[error("plugin {plugin_id}: state io at {path}: {source}")]
    Io {
        plugin_id: String,
        path: PathBuf,
        source: std::io::Error,
    },
}

impl PluginStoreError {
    /// Machine-readable error code (wire-stable, kebab-case).
    pub fn code(&self) -> &'static str {
        match self {
            Self::VersionMismatch { .. } => "version-mismatch",
            Self::InvalidStateVersion { .. } => "invalid-state-version",
            Self::InvalidPluginId { .. } => "invalid-plugin-id",
            Self::CorruptState { .. } => "corrupt-state",
            Self::MigrationFailed { .. } => "migration-failed",
            Self::MissingStep { .. } => "missing-step",
            Self::TableConflict { .. } => "table-conflict",
            Self::Io { .. } => "state-io",
        }
    }
}

/// Validates a `state_version` for `plugin_id` against [`MIN_STATE_VERSION`].
fn check_version(plugin_id: &str, version: u32) -> std::result::Result<(), PluginStoreError> {
    if version < MIN_STATE_VERSION {
        return Err(PluginStoreError::InvalidStateVersion {
            plugin_id: plugin_id.to_string(),
            found: version,
        });
    }
    Ok(())
}

/// Validates `plugin_id` against the registry id charset (`[a-z0-9][a-z0-9-]*`,
/// mirroring `akivili_registry`'s manifest id rule). Ids become path segments
/// under the data root, so traversal-shaped ids (`..`, `/`, absolute) are
/// rejected fail-closed instead of escaping the root.
fn check_plugin_id(plugin_id: &str) -> std::result::Result<(), PluginStoreError> {
    let mut chars = plugin_id.chars();
    let valid = matches!(chars.next(), Some(c) if c.is_ascii_lowercase() || c.is_ascii_digit())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    if valid {
        Ok(())
    } else {
        Err(PluginStoreError::InvalidPluginId {
            plugin_id: plugin_id.to_string(),
        })
    }
}

/// Per-plugin data store rooted at a host-chosen plugin data root (design
/// §4.1: `<plugin-data-root>/<plugin_id>/<state_version>/state.json`).
///
/// The data directory is deliberately separate from the plugin *package*
/// directory managed by the registry store: uninstalling a package must never
/// delete plugin data (data disposal is the explicit P2 uninstall policy,
/// not a side effect of file layout).
#[derive(Debug, Clone)]
pub struct PluginDataStore {
    root: PathBuf,
}

impl PluginDataStore {
    /// Creates a store over `root`; the directory is created lazily on first
    /// save.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Path of the state file for `plugin_id` at `version`.
    pub fn state_path(&self, plugin_id: &str, version: u32) -> PathBuf {
        self.root
            .join(plugin_id)
            .join(version.to_string())
            .join("state.json")
    }

    /// The highest `state_version` directory that holds a persisted
    /// `state.json` for `plugin_id` (`None` when the plugin has no
    /// persisted state yet — fresh install).
    ///
    /// Fail-closed (design §4.2): only `NotFound` on the plugin directory
    /// maps to "no state yet"; any other IO error — and any unreadable
    /// directory entry — surfaces as [`PluginStoreError::Io`] instead of
    /// being silently read as empty or stale state. Non-numeric entries
    /// are foreign and ignored; a numeric entry without `state.json`
    /// (e.g. a crash leftover from an interrupted save) is not a persisted
    /// version and cannot hijack discovery.
    pub fn latest_version(
        &self,
        plugin_id: &str,
    ) -> std::result::Result<Option<u32>, PluginStoreError> {
        check_plugin_id(plugin_id)?;
        let dir = self.root.join(plugin_id);
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            // Only "nothing here yet" may read as a fresh install; every
            // other error (EACCES, ENOTDIR, …) fails loud.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                return Err(PluginStoreError::Io {
                    plugin_id: plugin_id.to_string(),
                    path: dir,
                    source: e,
                });
            }
        };
        let mut latest = None;
        for entry in entries {
            let entry = entry.map_err(|e| PluginStoreError::Io {
                plugin_id: plugin_id.to_string(),
                path: dir.clone(),
                source: e,
            })?;
            let Some(version) = entry
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<u32>().ok())
            else {
                continue; // foreign entry, ignored by design
            };
            if version < MIN_STATE_VERSION {
                continue;
            }
            // A version directory without a loadable state.json is not a
            // persisted version (e.g. an interrupted-save leftover).
            match fs::metadata(entry.path().join("state.json")) {
                Ok(m) if m.is_file() => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => {
                    return Err(PluginStoreError::Io {
                        plugin_id: plugin_id.to_string(),
                        path: entry.path(),
                        source: e,
                    });
                }
                Ok(_) => continue,
            }
            latest = Some(latest.map_or(version, |max: u32| max.max(version)));
        }
        Ok(latest)
    }

    /// Loads the state of `plugin_id` as the plugin expects it at `expected`.
    ///
    /// Discovers the latest persisted version first, then compares:
    /// - No persisted state (fresh install): empty state at `expected`.
    /// - Latest persisted `state_version != expected` (stale *or* downgrade):
    ///   [`PluginStoreError::VersionMismatch`] — migration is always an
    ///   explicit host action, never a silent conversion.
    /// - Latest file unparsable or declaring 0:
    ///   [`PluginStoreError::CorruptState`] / [`PluginStoreError::InvalidStateVersion`].
    pub fn load(
        &self,
        plugin_id: &str,
        expected: u32,
    ) -> std::result::Result<PluginState, PluginStoreError> {
        check_plugin_id(plugin_id)?;
        check_version(plugin_id, expected)?;
        match self.latest_version(plugin_id)? {
            None => {
                // Fresh install: `expected` was validated against
                // MIN_STATE_VERSION two lines up, so constructing directly
                // (instead of routing through `empty_at`) keeps this branch
                // free of an unmappable error.
                Ok(PluginState {
                    state_version: expected,
                    kv: BTreeMap::new(),
                })
            }
            Some(found) => {
                let state = self.load_version(plugin_id, found)?;
                if state.state_version != expected {
                    return Err(PluginStoreError::VersionMismatch {
                        plugin_id: plugin_id.to_string(),
                        found: state.state_version,
                        expected,
                    });
                }
                Ok(state)
            }
        }
    }

    /// Reads exactly the snapshot at `version` (missing file =
    /// [`PluginStoreError::Io`] with `NotFound`). The precise-read channel for
    /// rollback verification and history inspection; plugin-facing reads go
    /// through [`Self::load`].
    pub fn load_version(
        &self,
        plugin_id: &str,
        version: u32,
    ) -> std::result::Result<PluginState, PluginStoreError> {
        check_plugin_id(plugin_id)?;
        check_version(plugin_id, version)?;
        let path = self.state_path(plugin_id, version);
        let text = fs::read_to_string(&path).map_err(|e| PluginStoreError::Io {
            plugin_id: plugin_id.to_string(),
            path: path.clone(),
            source: e,
        })?;
        let state: PluginState = serde_json::from_str(&text).map_err(|e| {
            let source = anyhow!(e);
            PluginStoreError::CorruptState {
                plugin_id: plugin_id.to_string(),
                path: path.clone(),
                source,
            }
        })?;
        check_version(plugin_id, state.state_version)?;
        Ok(state)
    }

    /// Persists `state` atomically (temp sibling + rename, mirroring the
    /// registry `registry-state.json` convention). Versioned directories
    /// accumulate: older versions stay readable as migration snapshots until
    /// an explicit uninstall policy removes them.
    ///
    /// The tmp sibling is pid-unique, so concurrent host processes never
    /// share one tmp file. The store otherwise assumes a single writer per
    /// `(plugin_id, state_version)` (see the module docs): P2's hot-swap
    /// wiring must serialize draining/loading instances before that
    /// invariant is relaxed.
    pub fn save(
        &self,
        plugin_id: &str,
        state: &PluginState,
    ) -> std::result::Result<(), PluginStoreError> {
        check_plugin_id(plugin_id)?;
        check_version(plugin_id, state.state_version)?;
        let path = self.state_path(plugin_id, state.state_version);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| PluginStoreError::Io {
                plugin_id: plugin_id.to_string(),
                path: parent.to_path_buf(),
                source: e,
            })?;
        }
        // Pid-unique tmp sibling in the same version directory (same
        // filesystem → rename stays atomic); a crash may leave the tmp
        // behind, which is inert for discovery.
        let tmp = path.with_extension(format!("json.{}.tmp", std::process::id()));
        let text = serde_json::to_string_pretty(state).map_err(|e| {
            let source = anyhow!(e);
            PluginStoreError::CorruptState {
                plugin_id: plugin_id.to_string(),
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&tmp, text).map_err(|e| PluginStoreError::Io {
            plugin_id: plugin_id.to_string(),
            path: tmp.clone(),
            source: e,
        })?;
        fs::rename(&tmp, &path).map_err(|e| PluginStoreError::Io {
            plugin_id: plugin_id.to_string(),
            path: path.clone(),
            source: e,
        })?;
        Ok(())
    }
}

/// One state migration step: a pure function over the in-memory state.
///
/// Pure means no IO inside the step — no network, no DB, no files. The host
/// persists after each successful step. If a migration genuinely needs
/// external data, the host injects it into `kv` *before* migration and the
/// step stays pure (design §4.3).
pub type StateMigrationFn = Arc<dyn Fn(&mut PluginState) -> Result<()> + Send + Sync>;

/// The ordered state migration table for one plugin: the step registered at
/// `from` migrates state from `from` to `from + 1` (version-stepped, each
/// step independently replayable — the idempotence contract).
///
/// TS/Boa-line plugins declare their steps in package manifests and execute
/// them inside the Boa sandbox at the same execution site (no privileges);
/// that adapter lands with the P2 lifecycle work. Rust-side typed steps are
/// built with [`typed_state_step`] today.
#[derive(Clone, Default)]
pub struct StateMigrationTable {
    steps: BTreeMap<u32, StateMigrationFn>,
}

impl std::fmt::Debug for StateMigrationTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Function bodies have no meaningful Debug; the step ranges are the
        // useful identity of a table.
        f.debug_struct("StateMigrationTable")
            .field(
                "steps",
                &self
                    .steps
                    .keys()
                    .map(|from| (*from, *from + 1))
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl StateMigrationTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers the step `from` -> `from + 1`. Registering another step for
    /// the same `from` fails closed (ambiguous table is a programming error,
    /// not something to silently overwrite).
    pub fn step(
        &mut self,
        from: u32,
        f: StateMigrationFn,
    ) -> std::result::Result<&mut Self, PluginStoreError> {
        if from < MIN_STATE_VERSION {
            return Err(PluginStoreError::InvalidStateVersion {
                plugin_id: String::new(),
                found: from,
            });
        }
        if self.steps.insert(from, f).is_some() {
            return Err(PluginStoreError::TableConflict { from });
        }
        Ok(self)
    }

    pub fn step_at(&self, from: u32) -> Option<&StateMigrationFn> {
        self.steps.get(&from)
    }
}

/// Runs state migrations version-step by version-step (design §4.3).
#[derive(Debug, Clone, Copy, Default)]
pub struct MigrationRunner;

impl MigrationRunner {
    /// Migrates `state` (at `state.state_version`) up to `target`.
    ///
    /// Semantics:
    /// - `state.state_version == target`: no-op success (idempotent rerun,
    ///   zero IO).
    /// - `state.state_version > target`: [`PluginStoreError::VersionMismatch`]
    ///   — the contract never downgrades.
    /// - Missing intermediate step: [`PluginStoreError::MissingStep`],
    ///   detected *before* any step runs (and before the snapshot below) —
    ///   a misconfigured table never does partial work.
    /// - Step failure: [`PluginStoreError::MigrationFailed`]; the last
    ///   successfully persisted version stays loadable on disk.
    ///
    /// Before the first step runs, the runner persists the input state at
    /// its *own* version (pre-migration snapshot, design §4.3) — even when
    /// the caller never saved it — so a failure always leaves a concrete
    /// on-disk rollback point instead of dropping the only in-memory copy.
    /// Re-saving an already-persisted snapshot is idempotent
    /// (byte-identical).
    ///
    /// Each successful step is persisted at its new version before the next
    /// step runs, so a crash mid-chain leaves the last good version loadable.
    pub fn migrate(
        &self,
        store: &PluginDataStore,
        table: &StateMigrationTable,
        plugin_id: &str,
        state: PluginState,
        target: u32,
    ) -> std::result::Result<PluginState, PluginStoreError> {
        check_plugin_id(plugin_id)?;
        if target < MIN_STATE_VERSION || state.state_version < MIN_STATE_VERSION {
            return Err(PluginStoreError::InvalidStateVersion {
                plugin_id: plugin_id.to_string(),
                found: target.min(state.state_version),
            });
        }
        if state.state_version == target {
            // Already at target: idempotent no-op, zero IO.
            return Ok(state);
        }
        if state.state_version > target {
            return Err(PluginStoreError::VersionMismatch {
                plugin_id: plugin_id.to_string(),
                found: state.state_version,
                expected: target,
            });
        }
        // Upfront gap check: every step current..target must exist before any
        // step executes, so a broken table does zero partial work.
        for from in state.state_version..target {
            if table.step_at(from).is_none() {
                return Err(PluginStoreError::MissingStep {
                    plugin_id: plugin_id.to_string(),
                    from,
                    target,
                });
            }
        }
        let mut working = state;
        // Pre-migration snapshot (design §4.3): persist the input at its own
        // version before any step runs, so failure always leaves a concrete
        // on-disk rollback point even when the caller never saved the state.
        // For an already-persisted snapshot this rewrite is byte-identical.
        store.save(plugin_id, &working)?;
        while working.state_version < target {
            let from = working.state_version;
            let to = from + 1;
            // Upfront check above guarantees presence; a None here would be a
            // logic bug worth a panic-free fail-closed path anyway.
            let Some(step) = table.step_at(from) else {
                return Err(PluginStoreError::MissingStep {
                    plugin_id: plugin_id.to_string(),
                    from,
                    target,
                });
            };
            // The step mutates a clone: on failure the caller's state and the
            // last persisted version are both untouched.
            let mut next = working.clone();
            if let Err(source) = step(&mut next) {
                return Err(PluginStoreError::MigrationFailed {
                    plugin_id: plugin_id.to_string(),
                    from,
                    to,
                    source,
                });
            }
            next.state_version = to;
            store.save(plugin_id, &next)?;
            tracing::info!(
                plugin = plugin_id,
                from,
                to,
                "plugin state migration step applied"
            );
            working = next;
        }
        Ok(working)
    }
}

/// A typed state step over one kv entry, powered by the hifumi version chain.
///
/// The plugin keeps a typed document (a `#[hifumi::version]`-annotated struct
/// serialized as JSON) under `key`. hifumi tags the payload with `$version`
/// and its macro-generated `From` chain migrates old payloads during
/// deserialization, so this step is: deserialize as `T` (auto-migrating),
/// re-serialize, write back. This is the load-bearing hifumi seam of the
/// runner — dynamic (closure) steps need no types and need no hifumi.
///
/// Version alignment: this step migrates the kv *document's* `$version` to
/// `T`'s current schema version (possibly several chain hops in one runner
/// step), while the runner advances `state_version` by exactly one. The two
/// version families are deliberately decoupled — the typed document is
/// plugin-internal — so register `T` at the step where its `$version` chain
/// matches the plugin's intent. hifumi fail-closes on unknown/future
/// `$version`s (the hidden version enum has no such variant → deserialize
/// error → `MigrationFailed`), never silently guessing.
pub fn typed_state_step<T>(key: &str) -> StateMigrationFn
where
    T: Serialize + serde::de::DeserializeOwned + 'static,
{
    let key = key.to_string();
    Arc::new(move |state: &mut PluginState| {
        let raw = state
            .kv
            .get(&key)
            .ok_or_else(|| anyhow!("typed state step: kv key {key:?} missing"))?;
        // hifumi auto-migrates any older $version payload into T here.
        let parsed: T = serde_json::from_str(raw)
            .with_context(|| format!("typed state step: deserialize {key:?} as the new schema"))?;
        state
            .kv
            .insert(key.clone(), serde_json::to_string(&parsed)?);
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_store() -> (tempfile::TempDir, PluginDataStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = PluginDataStore::new(dir.path());
        (dir, store)
    }

    fn raw_step(
        f: impl Fn(&mut PluginState) -> Result<()> + Send + Sync + 'static,
    ) -> StateMigrationFn {
        Arc::new(f)
    }

    // ---- class 1: normal path ----

    #[test]
    fn fresh_install_yields_empty_state_at_expected_version() {
        let (dir, store) = tmp_store();
        // Plugin directory already exists but holds no persisted version
        // (crash leftover, foreign files): still a fresh install, not an
        // error, and junk entries never surface.
        fs::create_dir_all(dir.path().join("p1").join("not-a-version")).unwrap();
        let state = store.load("p1", 1).unwrap();
        assert_eq!(state.state_version, 1);
        assert!(state.kv.is_empty());
        assert!(!store.state_path("p1", 1).exists());
    }

    #[test]
    fn save_then_load_roundtrips() {
        let (_dir, store) = tmp_store();
        let mut state = PluginState::empty_at(1).unwrap();
        state.kv.insert("theme".into(), "dark".into());
        store.save("p1", &state).unwrap();

        let loaded = store.load("p1", 1).unwrap();
        assert_eq!(loaded, state);
    }

    #[test]
    fn hifumi_typed_chain_migrates_kv_document() {
        // A plugin-side typed schema: v2 renamed `display_name` to `label`.
        // hifumi's macro generates the v1 payload -> v2 struct conversion at
        // deserialization time ($version tag).
        #[hifumi::version("2")]
        #[derive(Debug, Clone, PartialEq)]
        #[migration("1" => "2" {
            display_name => label: String
        })]
        struct Cfg {
            greeting: String,
            label: String,
        }

        let (_dir, store) = tmp_store();
        let mut state = PluginState::empty_at(1).unwrap();
        state.kv.insert(
            "cfg".into(),
            r#"{"$version":"1","greeting":"hi","display_name":"demo"}"#.into(),
        );
        store.save("p1", &state).unwrap();

        let mut table = StateMigrationTable::new();
        table.step(1, typed_state_step::<Cfg>("cfg")).unwrap();
        let migrated = MigrationRunner::default()
            .migrate(&store, &table, "p1", store.load("p1", 1).unwrap(), 2)
            .unwrap();

        assert_eq!(migrated.state_version, 2);
        // Pin the hifumi write-back seam on the RAW persisted JSON: the
        // payload must carry T's CURRENT $version and the migrated field
        // name. Deserializing as `Cfg` alone proves nothing here — hifumi
        // auto-migrates any older payload at read time, which would mask a
        // missing/neutralized write-back.
        let raw: serde_json::Value = serde_json::from_str(&migrated.kv["cfg"]).unwrap();
        assert_eq!(raw["$version"], serde_json::json!("2"));
        assert!(raw.get("label").is_some());
        assert!(raw.get("display_name").is_none());
        let cfg: Cfg = serde_json::from_str(&migrated.kv["cfg"]).unwrap();
        assert_eq!(
            cfg,
            Cfg {
                greeting: "hi".into(),
                label: "demo".into()
            }
        );
        // Reload at the new version matches (persisted, not just in memory).
        assert_eq!(store.load("p1", 2).unwrap(), migrated);
    }

    // ---- class 2: failures are explicit and closed ----

    #[test]
    fn version_mismatch_is_refused_not_converted() {
        let (_dir, store) = tmp_store();
        let mut state = PluginState::empty_at(1).unwrap();
        state.kv.insert("k".into(), "v".into());
        store.save("p1", &state).unwrap();

        // Stale read: plugin expects schema 2, disk's latest says 1.
        let err = store.load("p1", 2).unwrap_err();
        assert!(matches!(
            err,
            PluginStoreError::VersionMismatch {
                found: 1,
                expected: 2,
                ..
            }
        ));
        assert_eq!(err.code(), "version-mismatch");

        // Downgrade read: plugin was rolled back to schema 1, disk says 2.
        // Same explicit refusal — the contract never downgrades silently.
        let v2 = PluginState::empty_at(2).unwrap();
        store.save("p1", &v2).unwrap();
        let err = store.load("p1", 1).unwrap_err();
        assert!(matches!(
            err,
            PluginStoreError::VersionMismatch {
                found: 2,
                expected: 1,
                ..
            }
        ));
    }

    #[test]
    fn corrupt_state_fails_loud() {
        let (_dir, store) = tmp_store();
        let path = store.state_path("p1", 1);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, "not json").unwrap();

        let err = store.load("p1", 1).unwrap_err();
        assert!(matches!(err, PluginStoreError::CorruptState { .. }));
        assert_eq!(err.code(), "corrupt-state");
    }

    #[test]
    fn unreadable_plugin_dir_fails_loud_not_fresh() {
        // Any IO error other than NotFound on the plugin directory must
        // surface as Io — never silently read as a fresh (empty) install
        // (design §4.2 fail-closed). ENOTDIR repro: a file sits where the
        // plugin directory should be.
        let (dir, store) = tmp_store();
        fs::write(dir.path().join("p1"), "not a directory").unwrap();

        let err = store.load("p1", 1).unwrap_err();
        assert!(matches!(err, PluginStoreError::Io { .. }));
        assert_eq!(err.code(), "state-io");
    }

    #[test]
    fn crash_leftover_version_dir_does_not_hijack_discovery() {
        // An interrupted save can leave an empty <version> directory; that
        // is not a persisted version and must not shadow older, loadable
        // state (no stale read, no misleading NotFound).
        let (_dir, store) = tmp_store();
        let mut state = PluginState::empty_at(2).unwrap();
        state.kv.insert("k".into(), "v".into());
        store.save("p1", &state).unwrap();

        fs::create_dir_all(store.state_path("p1", 9).parent().unwrap()).unwrap();
        assert_eq!(store.latest_version("p1").unwrap(), Some(2));
        assert_eq!(store.load("p1", 2).unwrap().kv["k"], "v");
    }

    #[test]
    fn zero_version_is_illegal_everywhere() {
        let (_dir, store) = tmp_store();
        assert!(matches!(PluginState::empty_at(0), Err(_)));
        assert!(matches!(
            store.load("p1", 0),
            Err(PluginStoreError::InvalidStateVersion { found: 0, .. })
        ));
        let bad = PluginState {
            state_version: 0,
            kv: BTreeMap::new(),
        };
        assert!(matches!(
            store.save("p1", &bad),
            Err(PluginStoreError::InvalidStateVersion { found: 0, .. })
        ));
        // Migration: zero input version and zero target both refused.
        let table = StateMigrationTable::new();
        assert!(matches!(
            MigrationRunner::default().migrate(&store, &table, "p1", bad, 2),
            Err(PluginStoreError::InvalidStateVersion { found: 0, .. })
        ));
        assert!(matches!(
            MigrationRunner::default().migrate(
                &store,
                &table,
                "p1",
                PluginState::empty_at(1).unwrap(),
                0
            ),
            Err(PluginStoreError::InvalidStateVersion { found: 0, .. })
        ));
        // Exact-read channel and table registration reject 0 too.
        assert!(matches!(
            store.load_version("p1", 0),
            Err(PluginStoreError::InvalidStateVersion { found: 0, .. })
        ));
        let mut table = StateMigrationTable::new();
        assert!(matches!(
            table.step(0, raw_step(|_| Ok(()))),
            Err(PluginStoreError::InvalidStateVersion { found: 0, .. })
        ));
        // A file that parses but declares state_version 0 is refused the
        // same way — no silent acceptance anywhere.
        let path = store.state_path("p1", 1);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, r#"{"state_version":0,"kv":{}}"#).unwrap();
        assert!(matches!(
            store.load("p1", 1),
            Err(PluginStoreError::InvalidStateVersion { found: 0, .. })
        ));
    }

    #[test]
    fn traversal_shaped_plugin_ids_are_rejected() {
        // Ids become path segments under the data root: `..`, `/`, absolute
        // and otherwise illegal ids fail closed instead of escaping the
        // root (registry charset [a-z0-9][a-z0-9-]*).
        let (_dir, store) = tmp_store();
        for bad in ["../evil", "a/b", "", "-x", "UPPER", "spa ce", "."] {
            assert!(
                matches!(
                    store.save(bad, &PluginState::empty_at(1).unwrap()),
                    Err(PluginStoreError::InvalidPluginId { .. })
                ),
                "save accepted illegal id {bad:?}"
            );
            assert!(
                matches!(
                    store.load(bad, 1),
                    Err(PluginStoreError::InvalidPluginId { .. })
                ),
                "load accepted illegal id {bad:?}"
            );
        }
        // Nothing escaped the data root.
        assert_eq!(fs::read_dir(_dir.path()).unwrap().count(), 0);
    }

    #[test]
    fn failing_step_keeps_disk_at_last_good_version() {
        let (_dir, store) = tmp_store();
        let mut state = PluginState::empty_at(1).unwrap();
        state.kv.insert("step".into(), "1".into());
        store.save("p1", &state).unwrap();

        let mut table = StateMigrationTable::new();
        table
            .step(
                1,
                raw_step(|s| {
                    s.kv.insert("step".into(), "2".into());
                    Ok(())
                }),
            )
            .unwrap();
        table
            .step(
                2,
                raw_step(|s| {
                    let _ = s;
                    anyhow::bail!("boom: bad data");
                }),
            )
            .unwrap();

        let err = MigrationRunner::default()
            .migrate(&store, &table, "p1", store.load("p1", 1).unwrap(), 3)
            .unwrap_err();
        assert!(matches!(
            &err,
            PluginStoreError::MigrationFailed { from: 2, to: 3, .. }
        ));
        assert_eq!(err.code(), "migration-failed");

        // Disk stopped at the last good version and that version is the
        // state after step 1 — runnable, loadable, uncorrupted.
        let v2 = store.load("p1", 2).unwrap();
        assert_eq!(v2.kv["step"], "2");
        // v1 snapshot still intact (nothing deleted, nothing overwritten);
        // exact-read because discovery would (correctly) find v2 as latest.
        let v1 = store.load_version("p1", 1).unwrap();
        assert_eq!(v1.kv["step"], "1");
        // v3 was never written.
        assert!(!store.state_path("p1", 3).exists());
    }

    #[test]
    fn table_gap_fails_closed() {
        let (_dir, store) = tmp_store();
        let state = PluginState::empty_at(1).unwrap();
        store.save("p1", &state).unwrap();

        // Only step 1 registered, target 3: gap at 2 — detected upfront, so
        // not even step 1 runs and no v2 file appears.
        let mut table = StateMigrationTable::new();
        table.step(1, raw_step(|_| Ok(()))).unwrap();
        let err = MigrationRunner::default()
            .migrate(&store, &table, "p1", state, 3)
            .unwrap_err();
        assert!(matches!(
            err,
            PluginStoreError::MissingStep {
                from: 2,
                target: 3,
                ..
            }
        ));
        assert_eq!(err.code(), "missing-step");
        assert!(!store.state_path("p1", 2).exists());
    }

    // ---- class 3: idempotence ----

    #[test]
    fn migrate_to_current_version_is_a_no_op() {
        let (_dir, store) = tmp_store();
        let mut state = PluginState::empty_at(2).unwrap();
        state.kv.insert("k".into(), "v".into());
        store.save("p1", &state).unwrap();
        let before = fs::read_to_string(store.state_path("p1", 2)).unwrap();

        let table = StateMigrationTable::new();
        let out = MigrationRunner::default()
            .migrate(&store, &table, "p1", state, 2)
            .unwrap();
        assert_eq!(out.state_version, 2);
        assert_eq!(out.kv["k"], "v");
        // File untouched, byte for byte.
        assert_eq!(
            fs::read_to_string(store.state_path("p1", 2)).unwrap(),
            before
        );
    }

    #[test]
    fn replaying_a_completed_migration_is_a_byte_identical_noop() {
        // True replay: migrate v1 -> v2 once with the typed step, then run
        // the SAME table against the loaded v2 state again. The second run
        // must be a no-op — no double-apply, disk byte-identical.
        #[hifumi::version("2")]
        #[derive(Debug, Clone, PartialEq)]
        #[migration("1" => "2" {
            display_name => label: String
        })]
        struct Cfg {
            greeting: String,
            label: String,
        }

        let (_dir, store) = tmp_store();
        let mut state = PluginState::empty_at(1).unwrap();
        state.kv.insert(
            "cfg".into(),
            r#"{"$version":"1","greeting":"hi","display_name":"demo"}"#.into(),
        );
        store.save("p1", &state).unwrap();

        let mut table = StateMigrationTable::new();
        table.step(1, typed_state_step::<Cfg>("cfg")).unwrap();
        MigrationRunner::default()
            .migrate(&store, &table, "p1", store.load("p1", 1).unwrap(), 2)
            .unwrap();
        let before = fs::read_to_string(store.state_path("p1", 2)).unwrap();

        // Replay: same (from -> to) registered, state already migrated.
        let replayed = MigrationRunner::default()
            .migrate(&store, &table, "p1", store.load("p1", 2).unwrap(), 2)
            .unwrap();
        assert_eq!(replayed.state_version, 2);
        assert_eq!(
            fs::read_to_string(store.state_path("p1", 2)).unwrap(),
            before
        );
        let raw: serde_json::Value = serde_json::from_str(&replayed.kv["cfg"]).unwrap();
        assert_eq!(raw["$version"], serde_json::json!("2"));
    }

    // ---- class 4: rollback is loss-free ----

    #[test]
    fn migrate_snapshots_unsaved_input_before_stepping() {
        // The runner persists the input state at its own version before the
        // first step (pre-migration snapshot, design §4.3): a failure with
        // an input the caller never saved still leaves a concrete on-disk
        // rollback point — the kv is not silently dropped with the moved
        // input.
        let (_dir, store) = tmp_store();
        let mut state = PluginState::empty_at(1).unwrap();
        state.kv.insert("keep".into(), "1".into());
        // NOT saved before migrate.

        let mut table = StateMigrationTable::new();
        table
            .step(1, raw_step(|_| anyhow::bail!("boom: bad data")))
            .unwrap();
        let err = MigrationRunner::default()
            .migrate(&store, &table, "p1", state, 2)
            .unwrap_err();
        assert!(matches!(
            &err,
            PluginStoreError::MigrationFailed { from: 1, to: 2, .. }
        ));
        // The pre-migration snapshot exists on disk and carries the kv.
        assert_eq!(store.load_version("p1", 1).unwrap().kv["keep"], "1");
        assert!(!store.state_path("p1", 2).exists());
    }

    #[test]
    fn future_kv_version_fails_closed_through_typed_step() {
        // A kv document declaring a $version beyond the compiled chain must
        // fail the step — hifumi's hidden version enum has no such variant,
        // so deserialization errors and the runner reports MigrationFailed
        // (never a silent guess, design §4.2).
        #[hifumi::version("2")]
        #[derive(Debug, Clone, PartialEq)]
        #[migration("1" => "2" {
            display_name => label: String
        })]
        struct Cfg {
            greeting: String,
            label: String,
        }

        let (_dir, store) = tmp_store();
        let payload = r#"{"$version":"3","greeting":"hi","label":"demo"}"#;
        let mut state = PluginState::empty_at(1).unwrap();
        state.kv.insert("cfg".into(), payload.into());
        store.save("p1", &state).unwrap();

        let mut table = StateMigrationTable::new();
        table.step(1, typed_state_step::<Cfg>("cfg")).unwrap();
        let err = MigrationRunner::default()
            .migrate(&store, &table, "p1", store.load("p1", 1).unwrap(), 2)
            .unwrap_err();
        assert!(matches!(
            &err,
            PluginStoreError::MigrationFailed { from: 1, to: 2, .. }
        ));
        assert_eq!(err.code(), "migration-failed");
        // Disk keeps the pre-migration snapshot, payload untouched.
        assert_eq!(store.load_version("p1", 1).unwrap().kv["cfg"], payload);
    }

    #[test]
    fn failed_migration_rolls_back_to_runnable_snapshot() {
        let (_dir, store) = tmp_store();
        let mut state = PluginState::empty_at(1).unwrap();
        state.kv.insert("data".into(), "keep".into());
        store.save("p1", &state).unwrap();

        let mut table = StateMigrationTable::new();
        table
            .step(
                1,
                raw_step(|s| {
                    s.kv.insert("data".into(), "mangled".into());
                    anyhow::bail!("simulated bad transform")
                }),
            )
            .unwrap();

        let err = MigrationRunner::default()
            .migrate(&store, &table, "p1", state.clone(), 2)
            .unwrap_err();
        assert!(matches!(
            err,
            PluginStoreError::MigrationFailed { from: 1, to: 2, .. }
        ));

        // Rollback = reload the on-disk snapshot: the old version is intact
        // and runnable ("keep" survived the failed transform).
        let restored = store.load("p1", 1).unwrap();
        assert_eq!(restored, state);
        assert!(!store.state_path("p1", 2).exists());
    }

    #[test]
    fn downgrade_target_is_refused() {
        let (_dir, store) = tmp_store();
        let state = PluginState::empty_at(2).unwrap();
        store.save("p1", &state).unwrap();

        let err = MigrationRunner::default()
            .migrate(&store, &StateMigrationTable::new(), "p1", state, 1)
            .unwrap_err();
        assert!(matches!(
            err,
            PluginStoreError::VersionMismatch {
                found: 2,
                expected: 1,
                ..
            }
        ));
    }

    #[test]
    fn duplicate_step_registration_is_refused() {
        let mut table = StateMigrationTable::new();
        assert!(table.step(1, raw_step(|_| Ok(()))).is_ok());
        assert!(matches!(
            table.step(1, raw_step(|_| Ok(()))),
            Err(PluginStoreError::TableConflict { from: 1 })
        ));
    }
}
