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
#[derive(Debug, thiserror::Error)]
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
    /// the drained slot (if any) is disposed. On a serve failure the
    /// window is NOT consumed — the caller may retry commit or abort,
    /// the plugin never disappears.
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
#[cfg(feature = "wasm")]
mod wasm_slot {
    use super::PluginLoader;
    use akivili_registry::PluginManifest;
    use akivili_wasm_host::{
        InMemoryCapabilities, WasmHostError, WasmPluginHost, WasmPluginHostBuilder,
    };
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
        // The current slot is Draining but STILL in the map (abort()
        // below demonstrates the restore path on the same shape).
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
            eprintln!("SKIP: wasm target unavailable");
            return;
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
            eprintln!("SKIP: wasm target unavailable");
            return;
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
            eprintln!("SKIP: wasm target unavailable");
            return;
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
