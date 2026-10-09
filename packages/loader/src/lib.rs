//! `akivili_loader` — the plugin fabric's unified loader (A4).
//!
//! One crate, three layers:
//!
//! - **The plugin-list source** ([`PluginListSource`]): where a host
//!   learns *what to load*. Production hosts feed from the evernight
//!   topology network (design D7 — the mesh is the source of truth);
//!   local hosts fall back to their own config. The trait keeps both
//!   honest: the loader never talks to the network or the disk itself.
//! - **The lifecycle spine** ([`PluginSlot`]): `load → init → serve →
//!   drain → dispose` for every plugin regardless of form (design §5).
//!   `dispose` is idempotent; state lives host-side (the capability
//!   store), never in the plugin. The same plugin-id may briefly hold
//!   an old and a new slot through a drain window.
//! - **The F1 outlet** (feature `wasm`): [`WasmSlot`] binds a component
//!   binary to the [`akivili_wasm_host`] adapter — the reference
//!   instantiation of the spine for the wasm.component form.
//!
//! The F2 (process RPC) and F3 (boa script) outlets arrive in later A4
//! slices; the spine is form-agnostic by construction.

use std::collections::HashMap;

use akivili_registry::PluginManifest;

/// Everything the loader can fail with.
#[derive(Debug, Clone, thiserror::Error)]
pub enum LoaderError {
    /// The list source answered but the answer was unusable.
    #[error("list source error: {0}")]
    Source(String),
    /// A plugin's bytes could not be produced.
    #[error("artifact error for {plugin_id}: {reason}")]
    Artifact { plugin_id: String, reason: String },
    /// The plugin entered the spine in a state that forbids the call.
    #[error("lifecycle error for {plugin_id}: {reason}")]
    Lifecycle { plugin_id: String, reason: String },
}

/// Where a host learns what plugins to load (design D7).
///
/// Production hosts implement this against the evernight topology
/// network (the node/gateway's declared plugin set); local hosts read
/// their own TOML/env config. The loader core stays network-free — the
/// trait is the only seam.
pub trait PluginListSource: Send + Sync {
    /// The manifests to load, in feed order. Returning an empty list is
    /// a valid answer (a host with no plugins); returning an Err means
    /// the source itself failed (network down, config unreadable).
    fn plugin_manifests(&self) -> Result<Vec<PluginManifest>, LoaderError>;
}

/// Any `Arc`'d source is a source — hosts share one snapshot source
/// between their fetch task and any number of loaders.
impl<T: PluginListSource> PluginListSource for std::sync::Arc<T> {
    fn plugin_manifests(&self) -> Result<Vec<PluginManifest>, LoaderError> {
        (**self).plugin_manifests()
    }
}

/// A static list source for tests and local hosts: manifests handed in
/// directly, no IO.
#[derive(Default)]
pub struct StaticListSource {
    manifests: Vec<PluginManifest>,
}

impl StaticListSource {
    /// Wrap a fixed manifest list.
    pub fn new(manifests: Vec<PluginManifest>) -> Self {
        Self { manifests }
    }
}

impl PluginListSource for StaticListSource {
    fn plugin_manifests(&self) -> Result<Vec<PluginManifest>, LoaderError> {
        Ok(self.manifests.clone())
    }
}

/// A local-host list source: the host's own configuration, declared as
/// inline manifest tables (design D7's "自身配置回落" lane). The TOML
/// shape mirrors the on-disk `akivili.plugin.toml` minus resources —
/// a config-driven host needs no store:
///
/// ```toml
/// [[plugin]]
/// id = "hello-f1"
/// version = "1.0.0"
/// provider = "official"
/// form = "wasm.component"
/// ```
///
/// The top level is a COEXISTING section of the host's config file
/// (other sections like `[server]` pass through untouched); each
/// `[[plugin]]` table is strict (`deny_unknown_fields`), so a typo
/// inside a plugin entry fails loudly at load, not silently at
/// runtime.
pub struct ConfigListSource {
    plugins: Vec<ConfigManifest>,
    /// Lazily-validated manifests (parse once at first read; the
    /// validation errors surface on EVERY read until fixed).
    validated: std::sync::OnceLock<Result<Vec<PluginManifest>, LoaderError>>,
}

impl<'de> serde::Deserialize<'de> for ConfigListSource {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        // The config lane embeds in the HOST's own config file — other
        // sections ([server], [topology]…) must coexist. Only the
        // [[plugin]] tables themselves are strict (ConfigManifest's
        // deny_unknown_fields).
        #[derive(serde::Deserialize)]
        struct Raw {
            #[serde(default, rename = "plugin")]
            plugin: Vec<ConfigManifest>,
        }
        let raw = Raw::deserialize(d)?;
        Ok(Self {
            plugins: raw.plugin,
            validated: std::sync::OnceLock::new(),
        })
    }
}

/// One `[[plugin]]` table — the config-side manifest shape (a strict
/// subset of `akivili.plugin.toml` v2: no resources, no payloads).
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigManifest {
    /// Plugin id (manifest v2 rule applies on conversion).
    pub id: String,
    /// Loose version string (the config lane keeps the host's own
    /// spelling; strictness lands on conversion).
    pub version: String,
    /// Who ships the plugin.
    pub provider: String,
    /// The plugin form (defaults to `web.resource` when absent).
    #[serde(default)]
    pub form: Option<String>,
    /// Declared capabilities (closed vocabulary, validated on
    /// conversion).
    #[serde(default)]
    pub capabilities: Vec<String>,
}

impl ConfigListSource {
    /// Parse from TOML text.
    pub fn from_toml(text: &str) -> Result<Self, LoaderError> {
        toml::from_str(text).map_err(|e| LoaderError::Source(format!("config parse: {e}")))
    }

    /// Validate the config against the manifest rules and produce the
    /// manifests (id syntax, form vocabulary, closed capability words
    /// — the same validators the store applies, so config-driven and
    /// store-driven plugins cannot drift).
    pub fn into_manifests(self) -> Result<Vec<PluginManifest>, LoaderError> {
        self.plugins
            .into_iter()
            .map(|p| p.into_manifest())
            .collect()
    }
}

impl ConfigManifest {
    fn into_manifest(self) -> Result<PluginManifest, LoaderError> {
        // Reuse the registry's validators: build a v2 manifest and let
        // PluginManifest::validate enforce the id rule, form spelling
        // and closed capability vocabulary.
        let form = match self.form.as_deref() {
            None => akivili_registry::FormKind::WebResource,
            Some("wasm.component") => akivili_registry::FormKind::WasmComponent,
            Some("process.rpc") => akivili_registry::FormKind::ProcessRpc,
            Some("script.ts") => akivili_registry::FormKind::ScriptTs,
            Some("web.vue-module") => akivili_registry::FormKind::WebVueModule,
            Some("web.resource") => akivili_registry::FormKind::WebResource,
            Some(other) => {
                return Err(LoaderError::Source(format!(
                    "config plugin '{}' has unknown form '{other}'",
                    self.id
                )));
            }
        };
        let capabilities = self
            .capabilities
            .iter()
            .map(|c| {
                akivili_registry::Capability::new(c)
                    .map_err(|e| LoaderError::Source(format!("config plugin '{}': {e}", self.id)))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let manifest = PluginManifest {
            schema: 2,
            id: self.id,
            version: self.version,
            provider: self.provider,
            description: None,
            form: Some(form),
            capabilities,
            requires_contract: Vec::new(),
            trust: None,
            resources: Vec::new(),
        };
        manifest
            .validate()
            .map_err(|e| LoaderError::Source(format!("config plugin: {e}")))?;
        Ok(manifest)
    }
}

impl PluginListSource for ConfigListSource {
    fn plugin_manifests(&self) -> Result<Vec<PluginManifest>, LoaderError> {
        // The source carries already-validated manifests (from_toml →
        // into_manifests at construction); serving them is infallible.
        self.cached()
    }
}

impl ConfigListSource {
    fn cached(&self) -> Result<Vec<PluginManifest>, LoaderError> {
        // Lazy validation cache: parse once at first read, serve a
        // clone thereafter (the manifests are tiny).
        self.validated
            .get_or_init(|| self.build_manifests())
            .clone()
    }

    fn build_manifests(&self) -> Result<Vec<PluginManifest>, LoaderError> {
        self.plugins
            .iter()
            .map(|p| p.clone().into_manifest())
            .collect()
    }
}

/// A snapshot-fed list source for topology-driven hosts (design D7's
/// evernight lane).
///
/// The A4-2 adjudication on the sync-trait shape: the loader's
/// synchronous `PluginListSource` stays — the HOST runs the async
/// topology fetch (its own task/cadence, its own error surface) and
/// **publishes validated snapshots** through
/// [`TopologyListSource::publish`]. The loader never blocks on the
/// network, the host owns refresh timing, and a failed fetch never
/// masquerades as "no plugins" (the last good snapshot keeps serving
/// until a better one lands; `take_fetch_error` surfaces the fetch
/// failure out-of-band).
pub struct TopologyListSource {
    inner: std::sync::RwLock<TopologySnapshot>,
}

struct TopologySnapshot {
    manifests: Vec<PluginManifest>,
    fetch_error: Option<String>,
}

impl Default for TopologyListSource {
    fn default() -> Self {
        Self::new()
    }
}

impl TopologyListSource {
    /// An empty source (no snapshot published yet).
    pub fn new() -> Self {
        Self {
            inner: std::sync::RwLock::new(TopologySnapshot {
                manifests: Vec::new(),
                fetch_error: None,
            }),
        }
    }

    /// Publish a validated snapshot (the host's async topology task
    /// calls this on every successful fetch). Validation is the
    /// host's responsibility — the manifests pass through verbatim;
    /// a host that wants the config lane's strictness composes
    /// `ConfigListSource::into_manifests` on its side.
    pub fn publish(&self, manifests: Vec<PluginManifest>) {
        let mut guard = self.inner.write().expect("topology lock");
        guard.manifests = manifests;
        guard.fetch_error = None;
    }

    /// Record a fetch failure without disturbing the last good
    /// snapshot (the host's error surface reads it via
    /// [`Self::take_fetch_error`]).
    pub fn record_fetch_error(&self, reason: String) {
        let mut guard = self.inner.write().expect("topology lock");
        guard.fetch_error = Some(reason);
    }

    /// Take the pending fetch error, if any (out-of-band diagnostics —
    /// the loader's `plugin_manifests` keeps answering from the last
    /// good snapshot).
    pub fn take_fetch_error(&self) -> Option<String> {
        let mut guard = self.inner.write().expect("topology lock");
        guard.fetch_error.take()
    }
}

impl PluginListSource for TopologyListSource {
    fn plugin_manifests(&self) -> Result<Vec<PluginManifest>, LoaderError> {
        let guard = self.inner.read().expect("topology lock");
        Ok(guard.manifests.clone())
    }
}

/// A failing source — the loader's loud-path pin (a source error must
/// propagate, never silently produce an empty host).
#[derive(Default)]
pub struct FailingListSource {
    pub reason: String,
}

impl PluginListSource for FailingListSource {
    fn plugin_manifests(&self) -> Result<Vec<PluginManifest>, LoaderError> {
        Err(LoaderError::Source(self.reason.clone()))
    }
}

/// The lifecycle phases every plugin walks (design §5). `dispose` is
/// idempotent by contract; the phases after `Serving` are teardown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Bytes resolved, nothing initialized.
    Loaded,
    /// Host state wired, ready to serve.
    Initialized,
    /// Handling calls.
    Serving,
    /// Old version still answering in-flight work; replacement loading.
    Draining,
    /// Torn down; the slot may be dropped.
    Disposed,
}

impl Phase {
    /// Whether the phase accepts serve calls.
    pub fn serves(self) -> bool {
        matches!(self, Phase::Serving)
    }
}

/// A single loaded plugin walking the lifecycle spine. The generic
/// `Payload` is the form-specific handle (a wasm host, a process
/// supervisor, a boa context); the spine itself never inspects it.
pub struct PluginSlot<P> {
    /// The manifest this slot was loaded from.
    pub manifest: PluginManifest,
    /// The form-specific handle (wasm container, process, script ctx).
    pub payload: P,
    pub(crate) phase: Phase,
}

impl<P> PluginSlot<P> {
    /// A freshly loaded slot: bytes resolved, nothing initialized.
    pub fn loaded(manifest: PluginManifest, payload: P) -> Self {
        Self {
            manifest,
            payload,
            phase: Phase::Loaded,
        }
    }

    /// The current lifecycle phase.
    pub fn phase(&self) -> Phase {
        self.phase
    }

    /// Move Loaded → Initialized. Fails loudly on phase skips.
    pub fn init(&mut self) -> Result<(), LoaderError> {
        self.transition(
            Phase::Loaded,
            Phase::Initialized,
            "init requires the Loaded phase",
        )
    }

    /// Move Initialized → Serving.
    pub fn serve(&mut self) -> Result<(), LoaderError> {
        self.transition(
            Phase::Initialized,
            Phase::Serving,
            "serve requires the Initialized phase",
        )
    }

    /// Move Serving → Draining (an old version during a replace window).
    pub fn drain(&mut self) -> Result<(), LoaderError> {
        self.transition(
            Phase::Serving,
            Phase::Draining,
            "drain requires the Serving phase",
        )
    }

    /// Move any phase → Disposed. Idempotent: disposing twice succeeds.
    pub fn dispose(&mut self) {
        self.phase = Phase::Disposed;
    }

    fn transition(
        &mut self,
        from: Phase,
        to: Phase,
        violation: &'static str,
    ) -> Result<(), LoaderError> {
        if self.phase == Phase::Disposed {
            return Err(LoaderError::Lifecycle {
                plugin_id: self.manifest.id.clone(),
                reason: "slot is disposed".to_string(),
            });
        }
        if self.phase != from {
            return Err(LoaderError::Lifecycle {
                plugin_id: self.manifest.id.clone(),
                reason: violation.to_string(),
            });
        }
        self.phase = to;
        Ok(())
    }
}

/// The loader itself: one list source, a set of live slots, and a
/// replace policy that honors the drain window (the old slot keeps
/// serving until the new one reaches Serving, then drains and
/// disposes — design §5's "old/new 短暂并存").
pub struct PluginLoader<P> {
    source: Box<dyn PluginListSource>,
    slots: HashMap<String, PluginSlot<P>>,
}

impl<P> PluginLoader<P> {
    /// Build a loader over a list source (topology-fed or local).
    pub fn new(source: Box<dyn PluginListSource>) -> Self {
        Self {
            source,
            slots: HashMap::new(),
        }
    }

    /// The live slots, keyed by plugin id.
    pub fn slots(&self) -> &HashMap<String, PluginSlot<P>> {
        &self.slots
    }

    /// A mutable slot (for the form-specific init/serve driving).
    pub fn slot_mut(&mut self, plugin_id: &str) -> Option<&mut PluginSlot<P>> {
        self.slots.get_mut(plugin_id)
    }

    /// The manifests the source currently declares. A source error
    /// propagates loudly — an unreachable source must never read as
    /// "no plugins" (the FailingListSource pin).
    pub fn current_manifests(&self) -> Result<Vec<PluginManifest>, LoaderError> {
        self.source.plugin_manifests()
    }
}

impl<P> PluginLoader<P>
where
    P: Send,
{
    /// Open a replace window: the CURRENT slot (if serving) moves to
    /// Draining **but stays in the map** — calls keep routing to it
    /// until the new slot reaches Serving at commit. The new slot
    /// enters Loaded→Initialized inside the window. If no current slot
    /// exists this is a plain install.
    ///
    /// Committing swaps the map entry atomically; aborting restores
    /// the drained slot to Serving. Neither path can lose the plugin.
    pub fn replace(
        &mut self,
        manifest: PluginManifest,
        payload: P,
    ) -> Result<ReplaceWindow<'_, P>, LoaderError> {
        let plugin_id = manifest.id.clone();
        let mut new_slot = PluginSlot::loaded(manifest, payload);
        new_slot.init()?;
        if let Some(current) = self.slots.get_mut(&plugin_id)
            && current.phase().serves()
        {
            current.drain()?;
        }
        Ok(ReplaceWindow {
            loader: self,
            plugin_id,
            new: new_slot,
        })
    }
}

/// The drain window between the current (drained) slot and its
/// replacement. The current slot stays reachable through the loader
/// map until [`ReplaceWindow::commit`] swaps it; aborting restores it
/// to Serving.
pub struct ReplaceWindow<'a, P> {
    loader: &'a mut PluginLoader<P>,
    plugin_id: String,
    new: PluginSlot<P>,
}

impl<'a, P> ReplaceWindow<'a, P> {
    /// Commit: the new slot enters Serving and takes the map entry;
    /// the drained slot (if any) is disposed. A serve failure consumes
    /// the window (the replacement is lost) — but the CURRENT slot
    /// stays in the map, so the plugin never disappears; the caller
    /// retries with a fresh replace. (In practice the new slot is
    /// always Initialized when commit runs, so this path is
    /// unreachable through the public API.)
    pub fn commit(self) -> Result<(), LoaderError> {
        let mut new = self.new;
        new.serve()?;
        if let Some(mut old) = self.loader.slots.remove(&self.plugin_id) {
            old.dispose();
        }
        self.loader.slots.insert(self.plugin_id, new);
        Ok(())
    }

    /// Abort: drop the replacement and restore the drained slot to
    /// Serving (drain only marks the phase — the payload is intact).
    pub fn abort(self) {
        if let Some(current) = self.loader.slots.get_mut(&self.plugin_id)
            && current.phase == Phase::Draining
        {
            current.phase = Phase::Serving;
        }
    }
}
/// The F2 form's slot payload: a supervised child process speaking
/// JSON-RPC over stdio (design D5's process lane — the boa IEPL
/// engine's future home). The supervisor owns spawn/stop; the spine
/// owns the lifecycle phases.
pub mod process_slot {
    use std::process::{Child, Command, Stdio};

    /// A supervised process slot.
    pub struct ProcessSlot {
        child: Child,
        /// The command line, kept for diagnostics.
        pub command_line: String,
    }

    /// Everything a spawn can fail with.
    #[derive(Debug, thiserror::Error)]
    #[error("process spawn failed: {0}")]
    pub struct SpawnError(String);

    impl std::fmt::Debug for ProcessSlot {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("ProcessSlot")
                .field("command_line", &self.command_line)
                .field("pid", &self.child.id())
                .finish()
        }
    }

    impl ProcessSlot {
        /// Spawn the plugin process with stdio piped (the JSON-RPC
        /// channel). The caller passes the argv; the fabric does not
        /// mandate an RPC handshake here — the run-loop wiring lands
        /// with the protocol wave.
        pub fn spawn(argv: &[String]) -> Result<Self, SpawnError> {
            if argv.is_empty() {
                return Err(SpawnError("empty argv".into()));
            }
            let child = Command::new(&argv[0])
                .args(&argv[1..])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .map_err(|e| SpawnError(format!("{}: {e}", argv[0])))?;
            Ok(Self {
                child,
                command_line: argv.join(" "),
            })
        }

        /// The child's process id (diagnostics).
        pub fn pid(&self) -> Option<u32> {
            Some(self.child.id())
        }

        /// Drain: signal the child to stop and reap it. Design §5's
        /// drain for the process form = a graceful stop signal then a
        /// bounded wait; this v0 uses kill-and-reap (the signal
        /// vocabulary arrives with the protocol wave).
        pub fn drain_and_reap(&mut self) -> bool {
            self.child.kill().is_ok() && self.child.wait().is_ok()
        }

        /// Whether the child has exited.
        pub fn is_alive(&mut self) -> bool {
            matches!(self.child.try_wait(), Ok(None))
        }
    }
}

#[cfg(feature = "wasm")]
mod wasm_slot {
    use super::PluginLoader;
    use akivili_registry::PluginManifest;
    use akivili_wasm_host::{WasmHostError, WasmPluginHost, WasmPluginHostBuilder};
    use bytes::Bytes;
    use std::sync::Arc;

    /// The F1 form's slot payload: a wasm plugin host bound to the
    /// host's capabilities.
    pub type WasmSlot<C> = WasmPluginHost<C>;

    impl<C: akivili_wasm_host::HostCapabilities + 'static> PluginLoader<WasmPluginHost<C>> {
        /// Load a wasm.component plugin over the HOST's capability
        /// implementation (design D8: the injection chain stays open —
        /// the loader never fabricates capabilities). The Arc lives
        /// across replaces, so kv/config state survives hot reloads.
        pub async fn load_wasm(
            &mut self,
            manifest: PluginManifest,
            capabilities: Arc<C>,
            component: Bytes,
        ) -> Result<(), akivili_wasm_host::WasmHostError> {
            let host = WasmPluginHostBuilder::new(capabilities)
                .build(component)
                .await?;
            self.replace(manifest, host)
                .map_err(|e| WasmHostError::Host(anyhow::anyhow!(e.to_string())))?
                .commit()
                .map_err(|e| WasmHostError::Host(anyhow::anyhow!(e.to_string())))?;
            Ok(())
        }

        /// Call a loaded wasm plugin's run entry.
        pub async fn run(
            &mut self,
            plugin_id: &str,
            payload: &str,
        ) -> Result<String, WasmHostError> {
            let slot = self.slot_mut(plugin_id).ok_or_else(|| {
                WasmHostError::Host(anyhow::anyhow!("plugin {plugin_id} is not loaded"))
            })?;
            if !slot.phase().serves() {
                return Err(WasmHostError::Host(anyhow::anyhow!(
                    "plugin {plugin_id} is not serving (phase {:?})",
                    slot.phase()
                )));
            }
            slot.payload.run(payload).await
        }
    }
}

#[cfg(feature = "wasm")]
pub use wasm_slot::WasmSlot;

#[cfg(test)]
mod tests {
    use super::*;
    use akivili_registry::{Payload, ResourceEntry, ResourceKind};

    fn manifest(id: &str) -> PluginManifest {
        PluginManifest {
            schema: 1,
            id: id.to_string(),
            version: "1".to_string(),
            provider: "test".to_string(),
            description: None,
            form: None,
            capabilities: Vec::new(),
            requires_contract: Vec::new(),
            trust: None,
            resources: vec![ResourceEntry {
                kind: ResourceKind::new("webui.style").unwrap(),
                name: None,
                order: 0,
                payload: Payload::Inline(serde_json::json!({})),
            }],
        }
    }

    #[test]
    fn lifecycle_walks_forward_and_refuses_skips() {
        let mut slot: PluginSlot<()> = PluginSlot::loaded(manifest("p"), ());
        assert_eq!(slot.phase(), Phase::Loaded);

        // Skipping serve before init is a loud error.
        assert!(slot.serve().is_err());

        slot.init().unwrap();
        slot.serve().unwrap();
        assert!(slot.phase().serves());

        slot.drain().unwrap();
        assert!(!slot.phase().serves());

        // dispose is idempotent.
        slot.dispose();
        slot.dispose();
        assert_eq!(slot.phase(), Phase::Disposed);
        assert!(slot.init().is_err(), "a disposed slot refuses restart");
    }

    #[test]
    fn static_source_round_trips_and_failing_source_is_loud() {
        let manifests = vec![manifest("a"), manifest("b")];
        let source = StaticListSource::new(manifests.clone());
        let loader: PluginLoader<()> = PluginLoader::new(Box::new(source));
        assert_eq!(loader.current_manifests().unwrap().len(), 2);

        let failing = FailingListSource {
            reason: "topology unreachable".into(),
        };
        let loader: PluginLoader<()> = PluginLoader::new(Box::new(failing));
        let err = loader.current_manifests().unwrap_err();
        assert!(
            err.to_string().contains("topology unreachable"),
            "the source's reason must survive, got {err}"
        );
    }

    #[test]
    fn replace_honors_the_drain_window() {
        let mut loader: PluginLoader<()> = PluginLoader::new(Box::new(StaticListSource::default()));
        loader.replace(manifest("p"), ()).unwrap().commit().unwrap();
        assert_eq!(loader.slots()["p"].phase(), Phase::Serving);

        // Replace: the current slot drains IN the map (still reachable),
        // the new one serves after commit — the plugin never disappears.
        let window = loader.replace(manifest("p"), ()).unwrap();
        // The current slot is Draining but STILL in the map — the
        // sibling `abort_restores_the_drained_slot` test proves the
        // restore path on this same shape.
        window.commit().unwrap();
        assert_eq!(loader.slots()["p"].phase(), Phase::Serving);
    }

    #[test]
    fn abort_restores_the_drained_slot() {
        let mut loader: PluginLoader<()> = PluginLoader::new(Box::new(StaticListSource::default()));
        loader.replace(manifest("p"), ()).unwrap().commit().unwrap();
        let window = loader.replace(manifest("p"), ()).unwrap();
        window.abort();
        assert_eq!(loader.slots()["p"].phase(), Phase::Serving);
        assert_eq!(
            loader.slots()["p"].phase(),
            Phase::Serving,
            "abort restores the drained slot to Serving"
        );
    }
}

#[cfg(test)]
mod process_slot_tests {
    use super::process_slot::ProcessSlot;

    fn sleep_argv() -> Vec<String> {
        // A portable always-always process: sleep 30.
        vec!["sleep".to_string(), "30".to_string()]
    }

    #[test]
    fn spawn_yields_a_live_child() {
        let mut slot = ProcessSlot::spawn(&sleep_argv()).expect("sleep spawns");
        assert!(slot.pid().is_some(), "a live child has a pid");
        assert!(slot.is_alive(), "a fresh child is alive");
        assert!(slot.drain_and_reap(), "kill+wait succeeds");
        assert!(!slot.is_alive(), "the child is reaped");
    }

    #[test]
    fn empty_argv_rejects_loudly() {
        let err = ProcessSlot::spawn(&[]).unwrap_err();
        assert!(err.to_string().contains("empty argv"), "{err}");
    }

    #[test]
    fn missing_binary_rejects_with_the_command_name() {
        let argv = vec!["definitely-not-a-real-binary-xyz".to_string()];
        let err = ProcessSlot::spawn(&argv).unwrap_err();
        assert!(
            err.to_string().contains("definitely-not-a-real-binary-xyz"),
            "the command name survives, got {err}"
        );
    }

    #[test]
    fn the_slot_rides_the_lifecycle_spine() {
        use super::{Phase, PluginSlot};
        let slot = ProcessSlot::spawn(&sleep_argv()).expect("spawn");
        let mut slot: PluginSlot<ProcessSlot> = PluginSlot::loaded(
            akivili_registry::PluginManifest {
                schema: 1,
                id: "engine".into(),
                version: "1".into(),
                provider: "t".into(),
                description: None,
                form: None,
                capabilities: Vec::new(),
                requires_contract: Vec::new(),
                trust: None,
                resources: Vec::new(),
            },
            slot,
        );
        slot.init().unwrap();
        slot.serve().unwrap();
        slot.drain().unwrap();
        // The payload's own drain: the process dies before dispose —
        // and must BE dead (the m4 pin: dropping the drain call leaks
        // an orphan; the spine test asserts the reaped state).
        assert!(slot.payload.drain_and_reap());
        assert!(
            !slot.payload.is_alive(),
            "the process must be reaped before dispose"
        );
        slot.dispose();
        assert_eq!(slot.phase(), Phase::Disposed);
    }
}

#[cfg(test)]
mod config_source_tests {
    use super::*;

    #[test]
    fn parses_and_validates_a_config() {
        let text = r#"
[[plugin]]
id = "hello-f1"
version = "1.0.0"
provider = "official"
form = "wasm.component"
capabilities = ["kv.read", "mesh.call:celestia-reports"]
"#;
        let source = ConfigListSource::from_toml(text).expect("config parses");
        let loader: PluginLoader<()> = PluginLoader::new(Box::new(source));
        let manifests = loader.current_manifests().expect("valid manifests");
        assert_eq!(manifests.len(), 1);
        assert_eq!(manifests[0].id, "hello-f1");
        assert_eq!(
            manifests[0].form,
            Some(akivili_registry::FormKind::WasmComponent)
        );
        assert_eq!(manifests[0].capabilities.len(), 2);
    }

    #[test]
    fn empty_config_is_a_valid_empty_source() {
        let source = ConfigListSource::from_toml("").expect("empty config parses");
        let loader: PluginLoader<()> = PluginLoader::new(Box::new(source));
        assert_eq!(loader.current_manifests().unwrap().len(), 0);
    }

    #[test]
    fn foreign_sections_coexist_with_plugin_tables() {
        let text = r#"
[server]
listen = "0.0.0.0:8424"

[[plugin]]
id = "theme-pack"
version = "1.0.0"
provider = "official"
"#;
        let source = ConfigListSource::from_toml(text).expect("foreign sections coexist");
        let loader: PluginLoader<()> = PluginLoader::new(Box::new(source));
        assert_eq!(loader.current_manifests().unwrap().len(), 1);
    }

    #[test]
    fn unknown_fields_fail_loudly() {
        let text = r#"
[[plugin]]
id = "x"
version = "1"
provider = "p"
typo-field = true
"#;
        assert!(
            ConfigListSource::from_toml(text).is_err(),
            "unknown fields must reject"
        );
    }

    #[test]
    fn validation_errors_surface_on_every_read() {
        let text = r#"
[[plugin]]
id = "-bad-id"
version = "1.0.0"
provider = "p"
"#;
        let source = ConfigListSource::from_toml(text).expect("parses (validation is lazy)");
        let loader: PluginLoader<()> = PluginLoader::new(Box::new(source));
        let err = loader.current_manifests().unwrap_err();
        assert!(err.to_string().contains("bad-id"), "{err}");
        // The error is cached — every read reports it, never an empty list.
        assert!(loader.current_manifests().is_err());
    }

    #[test]
    fn omitted_form_defaults_to_web_resource() {
        let text = r#"
[[plugin]]
id = "theme-pack"
version = "1.0.0"
provider = "official"
"#;
        let source = ConfigListSource::from_toml(text).expect("parses");
        let loader: PluginLoader<()> = PluginLoader::new(Box::new(source));
        let manifests = loader.current_manifests().expect("defaults validate");
        assert_eq!(
            manifests[0].form,
            Some(akivili_registry::FormKind::WebResource),
            "an omitted form defaults to web.resource and validates under schema 2"
        );
    }

    #[test]
    fn every_official_form_round_trips_through_the_config_lane() {
        for (spelling, expected) in [
            ("wasm.component", akivili_registry::FormKind::WasmComponent),
            ("process.rpc", akivili_registry::FormKind::ProcessRpc),
            ("script.ts", akivili_registry::FormKind::ScriptTs),
            ("web.vue-module", akivili_registry::FormKind::WebVueModule),
            ("web.resource", akivili_registry::FormKind::WebResource),
        ] {
            let text = format!(
                "\n[[plugin]]\nid = \"form-check\"\nversion = \"1.0.0\"\nprovider = \"p\"\nform = \"{spelling}\"\n"
            );
            let source = ConfigListSource::from_toml(&text).expect(spelling);
            let manifests = source.into_manifests().expect(spelling);
            assert_eq!(
                manifests[0].form,
                Some(expected),
                "the config lane must accept every official {spelling} spelling"
            );
        }
    }

    #[test]
    fn unknown_form_rejects_loudly() {
        let text = r#"
[[plugin]]
id = "x"
version = "1.0.0"
provider = "p"
form = "web.fake"
"#;
        let source = ConfigListSource::from_toml(text).expect("parses");
        let err = source.into_manifests().unwrap_err();
        assert!(
            err.to_string().contains("web.fake"),
            "the unknown form name must survive, got {err}"
        );
    }

    #[test]
    fn closed_vocabulary_enforced_on_config_plugins() {
        let text = r#"
[[plugin]]
id = "x"
version = "1.0.0"
provider = "p"
capabilities = ["fs.read"]
"#;
        let source = ConfigListSource::from_toml(text).expect("parses");
        let loader: PluginLoader<()> = PluginLoader::new(Box::new(source));
        assert!(
            loader.current_manifests().is_err(),
            "out-of-vocabulary words reject"
        );
    }
}

#[cfg(test)]
mod topology_source_tests {
    use super::*;
    use std::sync::Arc;

    fn topo_manifest(id: &str) -> PluginManifest {
        PluginManifest {
            schema: 1,
            id: id.to_string(),
            version: "1".to_string(),
            provider: "mesh".to_string(),
            description: None,
            form: None,
            capabilities: Vec::new(),
            requires_contract: Vec::new(),
            trust: None,
            resources: Vec::new(),
        }
    }

    #[test]
    fn an_unpublished_source_answers_empty() {
        let source = std::sync::Arc::new(TopologyListSource::new());
        let loader: PluginLoader<()> = PluginLoader::new(Box::new(Arc::clone(&source)) as Box<_>);
        assert_eq!(loader.current_manifests().unwrap().len(), 0);
    }

    #[test]
    fn a_published_snapshot_serves() {
        let source = Arc::new(TopologyListSource::new());
        source.publish(vec![topo_manifest("node-a"), topo_manifest("node-b")]);
        let loader: PluginLoader<()> = PluginLoader::new(Box::new(Arc::clone(&source)) as Box<_>);
        let manifests = loader.current_manifests().unwrap();
        assert_eq!(manifests.len(), 2);
        assert_eq!(manifests[0].id, "node-a");
    }

    #[test]
    fn a_fetch_failure_keeps_the_last_good_snapshot() {
        let source = Arc::new(TopologyListSource::new());
        source.publish(vec![topo_manifest("good")]);
        source.record_fetch_error("topology unreachable".into());

        // The loader keeps answering from the last good snapshot…
        let loader: PluginLoader<()> = PluginLoader::new(Box::new(Arc::clone(&source)) as Box<_>);
        assert_eq!(loader.current_manifests().unwrap().len(), 1);

        // …and the fetch failure surfaces out-of-band, exactly once.
        let err = source.take_fetch_error().unwrap();
        assert!(err.contains("topology unreachable"), "{err}");
        assert!(
            source.take_fetch_error().is_none(),
            "the error is taken exactly once"
        );
    }

    #[test]
    fn a_new_snapshot_after_a_failure_clears_the_error() {
        let source = Arc::new(TopologyListSource::new());
        source.record_fetch_error("first fetch failed".into());
        source.publish(vec![topo_manifest("recovered")]);
        assert!(
            source.take_fetch_error().is_none(),
            "publish clears the error"
        );
        assert_eq!(source.plugin_manifests().unwrap()[0].id, "recovered");
    }
}

#[cfg(all(test, feature = "wasm"))]
mod wasm_tests {
    use super::*;
    use akivili_wasm_host::{HostCapabilities, InMemoryCapabilities, WasmPluginHost};
    use std::sync::Arc;

    fn manifest(id: &str) -> PluginManifest {
        PluginManifest {
            schema: 1,
            id: id.to_string(),
            version: "1".to_string(),
            provider: "test".to_string(),
            description: None,
            form: None,
            capabilities: Vec::new(),
            requires_contract: Vec::new(),
            trust: None,
            resources: Vec::new(),
        }
    }

    /// The wasm_host B2 pattern, ported (R3's A4-2 register): a missing
    /// toolchain is the one legitimate skip; a pilot BUILD failure must
    /// fail loudly — a CI green check must always mean the round-trip
    /// really ran.
    fn ensure_pilot_toolchain_present() {
        let out = std::process::Command::new("rustup")
            .args(["target", "list", "--installed"])
            .output();
        let installed = out
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
            .unwrap_or_default();
        if !installed.contains("wasm32-wasip2") {
            panic!(
                "SKIP (toolchain): wasm32-wasip2 target not installed — \
                 CI installs it; locally run `rustup target add wasm32-wasip2`"
            );
        }
    }

    fn pilot_wasm() -> Option<bytes::Bytes> {
        let status = std::process::Command::new(env!("CARGO"))
            .args([
                "build",
                "-p",
                "akivili-example-hello-f1",
                "--target",
                "wasm32-wasip2",
                "--release",
            ])
            .status()
            .ok()?;
        if !status.success() {
            return None;
        }
        let out = std::process::Command::new(env!("CARGO"))
            .args(["metadata", "--format-version", "1", "--no-deps"])
            .output()
            .ok()?;
        let meta: serde_json::Value = serde_json::from_slice(&out.stdout).ok()?;
        let dir = meta["target_directory"].as_str()?.to_string();
        std::fs::read(
            std::path::Path::new(&dir).join("wasm32-wasip2/release/akivili_example_hello_f1.wasm"),
        )
        .ok()
        .map(bytes::Bytes::from)
    }

    fn caps() -> Arc<InMemoryCapabilities> {
        Arc::new(InMemoryCapabilities::default().with_config("greeting", "hello"))
    }

    #[tokio::test]
    async fn loader_serves_a_wasm_plugin_end_to_end() {
        let Some(wasm) = pilot_wasm() else {
            ensure_pilot_toolchain_present();
            panic!("pilot build failed with the toolchain present — see stderr");
        };
        let mut loader: PluginLoader<WasmPluginHost<InMemoryCapabilities>> =
            PluginLoader::new(Box::new(StaticListSource::default()));
        loader
            .load_wasm(manifest("hello-f1"), caps(), wasm.clone())
            .await
            .expect("load must succeed");
        assert_eq!(loader.slots()["hello-f1"].phase(), Phase::Serving);

        let out = loader
            .run("hello-f1", "fabric")
            .await
            .expect("run must serve");
        assert_eq!(out, "hello: fabric", "got {out}");
    }

    /// The D8/D5 pin: capabilities are HOST-owned (Arc across
    /// replaces) — a hot reload must NOT wipe the plugin's kv state.
    #[tokio::test]
    async fn hot_replace_preserves_host_state() {
        let Some(wasm) = pilot_wasm() else {
            ensure_pilot_toolchain_present();
            panic!("pilot build failed with the toolchain present — see stderr");
        };
        let capabilities = caps();
        let mut loader: PluginLoader<WasmPluginHost<InMemoryCapabilities>> =
            PluginLoader::new(Box::new(StaticListSource::default()));
        loader
            .load_wasm(manifest("hello-f1"), capabilities.clone(), wasm.clone())
            .await
            .expect("first load");
        loader.run("hello-f1", "before").await.expect("first run");

        // Hot replace with the SAME capabilities Arc.
        loader
            .load_wasm(manifest("hello-f1"), capabilities.clone(), wasm)
            .await
            .expect("hot replace");
        let out = loader
            .run("hello-f1", "after")
            .await
            .expect("post-replace run");
        assert_eq!(out, "hello: after");
        assert_eq!(
            capabilities.kv_get("last-run").unwrap().as_deref(),
            Some("after"),
            "the kv write landed in the HOST store across the replace"
        );
    }

    #[tokio::test]
    async fn run_refuses_a_non_serving_slot() {
        let Some(wasm) = pilot_wasm() else {
            ensure_pilot_toolchain_present();
            panic!("pilot build failed with the toolchain present — see stderr");
        };
        let mut loader: PluginLoader<WasmPluginHost<InMemoryCapabilities>> =
            PluginLoader::new(Box::new(StaticListSource::default()));
        loader
            .load_wasm(manifest("hello-f1"), caps(), wasm)
            .await
            .expect("load must succeed");
        // Drain the slot, then the run call must refuse loudly.
        loader.slot_mut("hello-f1").unwrap().drain().unwrap();
        let err = loader
            .run("hello-f1", "x")
            .await
            .expect_err("drained slots refuse");
        assert!(err.to_string().contains("not serving"), "{err}");
    }
}
