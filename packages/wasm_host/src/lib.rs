//! `akivili_wasm_host` — the plugin fabric's F1 adapter (B1).
//!
//! One crate, two layers:
//!
//! - **Runtime-agnostic core** (always compiled): the
//!   [`HostCapabilities`] trait — the D8 capability-injection SPI. A
//!   host implements it once (log / kv / config today, the rest of the
//!   closed vocabulary as the fabric grows); every runtime outlet —
//!   this crate's wasm adapter, the boa plugin host, the F2 process
//!   RPC lane — dispatches through the same trait object, gated by the
//!   grant ceiling.
//! - **The tairitsu adapter** (feature `tairitsu`):
//!   [`WasmPluginHost`] builds a wasmtime [`AsyncContainer`] over a
//!   component binary, registers the `celestia:host/guest` imports
//!   against the host's [`HostCapabilities`] implementation, and
//!   exposes a `run` call surface. The weight discipline (design D9):
//!   nothing in akivili's other crates pulls wasmtime; consumers opt
//!   into the feature.
//!
//! The WIT contract lives in [`wit/host.wit`](https://github.com/celestia-island/akivili/blob/master/packages/wasm_host/wit/host.wit)
//! (world `celestia:host/guest`); guests bind with
//! `wit_bindgen::generate!`.

/// The capability-injection SPI (design D8) — runtime-agnostic.
///
/// Implement this once per host; the wasm adapter (and future runtime
/// outlets) call through it. The v0 surface covers the vocabulary
/// words `log`, `kv.read`, `kv.write` and `config.read`; the data
/// methods are fallible so a host can enforce its grant ceiling
/// (deny = error, never a silent default). `log` is infallible by
/// design — a denied log is a dropped log, not a guest trap.
pub trait HostCapabilities: Send + Sync {
    /// Vocabulary word `log` — structured logging through the host.
    fn log(&self, level: &str, message: &str);

    /// Vocabulary word `kv.read` — plugin-scoped key/value state.
    fn kv_get(&self, key: &str) -> anyhow::Result<Option<String>>;

    /// Vocabulary word `kv.write` — plugin-scoped key/value state.
    fn kv_set(&self, key: &str, value: &str) -> anyhow::Result<()>;

    /// Vocabulary word `config.read` — the plugin's own config section.
    fn config_get(&self, key: &str) -> anyhow::Result<Option<String>>;
}

/// A minimal in-memory [`HostCapabilities`] for tests and examples:
/// kv in a map, config in a map, log a no-op.
#[derive(Default)]
pub struct InMemoryCapabilities {
    kv: std::sync::Mutex<std::collections::HashMap<String, String>>,
    config: std::collections::HashMap<String, String>,
}

impl InMemoryCapabilities {
    /// Seed a config entry.
    pub fn with_config(mut self, key: &str, value: &str) -> Self {
        self.config.insert(key.to_string(), value.to_string());
        self
    }
}

impl HostCapabilities for InMemoryCapabilities {
    fn log(&self, level: &str, message: &str) {
        // The example sink; real hosts route through tracing.
        eprintln!("[wasm-host:{level}] {message}");
    }

    fn kv_get(&self, key: &str) -> anyhow::Result<Option<String>> {
        Ok(self.kv.lock().expect("kv lock").get(key).cloned())
    }

    fn kv_set(&self, key: &str, value: &str) -> anyhow::Result<()> {
        self.kv
            .lock()
            .expect("kv lock")
            .insert(key.to_string(), value.to_string());
        Ok(())
    }

    fn config_get(&self, key: &str) -> anyhow::Result<Option<String>> {
        Ok(self.config.get(key).cloned())
    }
}

/// Everything a wasm plugin call can fail with.
#[derive(Debug, thiserror::Error)]
pub enum WasmHostError {
    /// The guest returned an error result from its `run` export.
    #[error("guest error: {0}")]
    Guest(String),
    /// The host machinery failed (build, instantiate, call, ABI).
    #[error("host error: {0}")]
    Host(#[from] anyhow::Error),
}

#[cfg(feature = "tairitsu")]
mod adapter {
    use super::{HostCapabilities, WasmHostError};
    use bytes::Bytes;
    use std::sync::Arc;
    use tairitsu::{AsyncContainer, Container, Image};

    /// Unwraps the dynamic-path RON for a `result<string, string>` return:
    /// tairitsu serializes both variants as the Ok-side RON string
    /// (`Ok("value")` / `Err("boom")`), so the guest's declared error must
    /// be re-classified here — the Ok arm strips the wrapper, the Err arm
    /// becomes [`WasmHostError::Guest`].
    pub(super) fn parse_run_result(raw: &str) -> Result<String, WasmHostError> {
        let trimmed = raw.trim();
        if let Some(inner) = trimmed
            .strip_prefix("Ok(")
            .and_then(|rest| rest.strip_suffix(')'))
        {
            Ok(inner.trim().trim_matches('"').to_string())
        } else if let Some(inner) = trimmed
            .strip_prefix("Err(")
            .and_then(|rest| rest.strip_suffix(')'))
        {
            Err(WasmHostError::Guest(
                inner.trim().trim_matches('"').to_string(),
            ))
        } else {
            // A bare string (no result wrapper): treat as the payload.
            Ok(trimmed.trim_matches('"').to_string())
        }
    }

    /// One loaded F1 plugin: a tairitsu [`AsyncContainer`] wired to the
    /// host's [`HostCapabilities`] through the `guest` world imports.
    ///
    /// Built from a component binary (wasm32-wasip2). Fuel/epoch limits
    /// ride the builder before [`WasmPluginHost::build`].
    pub struct WasmPluginHost<C: HostCapabilities> {
        capabilities: Arc<C>,
        container: AsyncContainer<tairitsu::HostState>,
    }

    /// Builder for [`WasmPluginHost`].
    pub struct WasmPluginHostBuilder<C: HostCapabilities> {
        capabilities: Arc<C>,
        fuel_limit: Option<u64>,
        epoch_deadline: Option<u64>,
    }

    impl<C: HostCapabilities + 'static> WasmPluginHostBuilder<C> {
        /// Start from the host's capability implementation.
        pub fn new(capabilities: Arc<C>) -> Self {
            Self {
                capabilities,
                fuel_limit: None,
                epoch_deadline: None,
            }
        }

        /// Fuel budget per store (requires the image-side
        /// `consume_fuel(true)` config — enforced by the build error
        /// if missing, same as tairitsu).
        pub fn with_fuel_limit(mut self, limit: u64) -> Self {
            self.fuel_limit = Some(limit);
            self
        }

        /// Epoch deadline for cooperative interruption.
        pub fn with_epoch_deadline(mut self, deadline: u64) -> Self {
            self.epoch_deadline = Some(deadline);
            self
        }

        /// Build the host over a component binary: registers the
        /// `guest` world imports against the capabilities and instantiates
        /// the component async.
        ///
        /// The registration itself uses sync host closures — wasmtime's
        /// async ABI (`wasm_component_model_async`) is a later wave; a
        /// sync-registered host function still runs on the container's
        /// async call path without blocking a second thread (the fiber
        /// carries it).
        pub async fn build(self, component: Bytes) -> anyhow::Result<WasmPluginHost<C>> {
            let image = Image::from_component(component)?;
            let capabilities = self.capabilities.clone();

            let mut builder = Container::builder(image)
                .with_host_state(tairitsu::HostState::new()?)
                .with_host_linker(move |linker| {
                    let mut root = linker.root();
                    let caps = capabilities.clone();

                    root.func_wrap("log", move |_store, (level, message): (String, String)| {
                        caps.log(&level, &message);
                        Ok(())
                    })?;

                    let caps = capabilities.clone();
                    root.func_wrap("kv-get", move |_store, (key,): (String,)| {
                        Ok((caps
                            .kv_get(&key)
                            .map_err(|e| wasmtime::format_err!(e.to_string()))?,))
                    })?;

                    let caps = capabilities.clone();
                    root.func_wrap("kv-set", move |_store, (key, value): (String, String)| {
                        // A failed write traps the guest run (harder
                        // than `log`, whose denials merely drop) — the
                        // v0 world has no per-call error channel for
                        // writes, and the trap's original cause is
                        // reduced to the wasm backtrace at the ABI
                        // boundary.
                        caps.kv_set(&key, &value)
                            .map_err(|e| wasmtime::format_err!(e.to_string()))
                    })?;

                    let caps = capabilities.clone();
                    root.func_wrap("config-get", move |_store, (key,): (String,)| {
                        Ok((caps
                            .config_get(&key)
                            .map_err(|e| wasmtime::format_err!(e.to_string()))?,))
                    })?;

                    Ok(())
                });

            if let Some(fuel) = self.fuel_limit {
                builder = builder.with_fuel_limit(fuel);
            }
            if let Some(deadline) = self.epoch_deadline {
                builder = builder.with_epoch_deadline(deadline);
            }

            let container = builder.build_async().await?;
            Ok(WasmPluginHost {
                capabilities: self.capabilities,
                container,
            })
        }
    }

    impl<C: HostCapabilities> WasmPluginHost<C> {
        /// The host's capability implementation (for the host's own
        /// bookkeeping; the guest never sees it).
        pub fn capabilities(&self) -> &C {
            &self.capabilities
        }

        /// Call the guest's `run` export with a string payload —
        /// the world-v0 entry point. The RON quoting matches a
        /// wit-bindgen guest's string ABI (B2 pilots bind against
        /// `wit/host.wit`).
        pub async fn run(&mut self, payload: &str) -> Result<String, WasmHostError> {
            let out = self
                .container
                .call_guest_raw_desc_async("run", &format!("{payload:?}"))
                .await?;
            parse_run_result(&out)
        }

        /// The dynamic call surface — any export, any RON payload.
        /// Guests not built with wit-bindgen (hand-written components,
        /// numeric test fixtures) use this directly.
        pub async fn call_raw(
            &mut self,
            function: &str,
            payload: &str,
        ) -> Result<String, WasmHostError> {
            Ok(self
                .container
                .call_guest_raw_desc_async(function, payload)
                .await?)
        }

        /// Stop the underlying container (refuses further calls).
        pub fn stop(&mut self) {
            self.container.stop();
        }
    }
}

#[cfg(feature = "tairitsu")]
pub use adapter::{WasmPluginHost, WasmPluginHostBuilder};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_memory_capabilities_round_trip() {
        let caps = InMemoryCapabilities::default().with_config("greeting", "hello");
        caps.log("info", "capability smoke");
        assert_eq!(caps.kv_get("k").unwrap(), None);
        caps.kv_set("k", "v").unwrap();
        assert_eq!(caps.kv_get("k").unwrap(), Some("v".to_string()));
        assert_eq!(caps.config_get("greeting").unwrap(), Some("hello".into()));
        assert_eq!(caps.config_get("missing").unwrap(), None);
    }

    #[test]
    fn error_display_distinguishes_guest_and_host() {
        let guest = WasmHostError::Guest("boom".into());
        let host = WasmHostError::Host(anyhow::anyhow!("io"));
        assert!(guest.to_string().starts_with("guest error:"));
        assert!(host.to_string().starts_with("host error:"));
    }
}

#[cfg(all(test, feature = "tairitsu"))]
mod adapter_tests {
    use super::adapter::parse_run_result;
    use super::*;

    #[test]
    fn run_result_ron_unwrapping_classifies_guest_errors() {
        assert_eq!(
            parse_run_result("Ok(\"hello\")").unwrap(),
            "hello",
            "the Ok wrapper strips, the inner string survives"
        );
        let guest_err = parse_run_result("Err(\"boom\")").unwrap_err();
        assert!(
            matches!(&guest_err, crate::WasmHostError::Guest(msg) if msg == "boom"),
            "the Err arm becomes a Guest error, got {guest_err}"
        );
        assert_eq!(
            parse_run_result("\"bare\"").unwrap(),
            "bare",
            "a bare string falls back to the payload"
        );
    }
    use std::sync::Arc;

    /// A compute-only guest (no imports — the host-api imports stay
    /// unexercised here; string-ABI guest round-trips land with the
    /// B2 wit-bindgen pilot). The component exports `run` echoing a
    /// counted payload.
    fn echo_component_wasm() -> bytes::Bytes {
        let wat = r#"
            (component
              (core module $m
                (memory (export "mem") 1)
                (func (export "run") (param i32) (result i32)
                  local.get 0))
              (core instance $i (instantiate $m))
              (func (export "run") (param "x" s32) (result s32)
                (canon lift (core func $i "run"))))
        "#;
        bytes::Bytes::from(wat::parse_str(wat).expect("WAT must parse"))
    }

    #[tokio::test]
    async fn builds_and_calls_a_compute_guest() {
        let caps = Arc::new(InMemoryCapabilities::default());
        let mut host = WasmPluginHostBuilder::new(caps)
            .build(echo_component_wasm())
            .await
            .expect("host must build over a compute guest");
        let out = host
            .call_raw("run", "7")
            .await
            .expect("run must round-trip");
        assert_eq!(out, "7", "the echo guest returns its payload, got {out}");
    }

    #[tokio::test]
    async fn fuel_limit_poisons_a_runaway_guest() {
        // A spinning guest under a tiny fuel budget: the host call
        // surfaces the trap and the container is poisoned.
        let wat = r#"
            (component
              (core module $m
                (memory (export "mem") 1)
                (func (export "run") (param i32) (result i32)
                  (loop $l br $l)
                  (i32.const 0)))
              (core instance $i (instantiate $m))
              (func (export "run") (param "x" s32) (result s32)
                (canon lift (core func $i "run"))))
        "#;
        let wasm = bytes::Bytes::from(wat::parse_str(wat).expect("WAT must parse"));

        let caps = Arc::new(InMemoryCapabilities::default());
        // Fuel needs the engine-side config; the adapter exposes the
        // store-side budget — without the image-side switch the build
        // itself must fail loudly (the tairitsu contract).
        let host = WasmPluginHostBuilder::new(caps)
            .with_fuel_limit(1_000)
            .build(wasm)
            .await;
        // Without consume_fuel in the image config, tairitsu errors on
        // set_fuel — the loud path. (The fuel-enforced happy path rides
        // the B2 pilot with a properly configured image.)
        assert!(host.is_err(), "fuel without engine config must fail loud");
    }
    /// Panics with a dedicated message when the wasm32-wasip2 target is
    /// missing (the one legitimate skip condition).
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

    /// Builds the F1 pilot plugin (examples/hello-f1) for wasm32-wasip2
    /// and returns its component binary. The pilot is the world's
    /// reference guest: string ABI, every host import exercised.
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
        // CARGO_TARGET_DIR may be external; ask cargo where it puts
        // artifacts by locating via the manifest metadata.
        let out = std::process::Command::new(env!("CARGO"))
            .args(["metadata", "--format-version", "1", "--no-deps"])
            .output()
            .ok()?;
        let meta: serde_json::Value = serde_json::from_slice(&out.stdout).ok()?;
        let target_dir = meta["target_directory"].as_str()?.to_string();
        let wasm = std::path::Path::new(&target_dir)
            .join("wasm32-wasip2/release/akivili_example_hello_f1.wasm");
        std::fs::read(wasm).ok().map(bytes::Bytes::from)
    }

    /// The B2 headline: the FIRST full-round-trip through a real
    /// wit-bindgen guest — host string → guest `run` → every host
    /// import (kv-set, kv-get, config-get, log) dispatched into the
    /// host's capability implementation → guest answer → host result
    /// classification. Skip (not fail) when the wasm target is absent.
    #[tokio::test]
    async fn f1_pilot_full_round_trip() {
        let Some(wasm) = pilot_wasm() else {
            // A missing wasm32-wasip2 toolchain is the one legitimate
            // skip; a pilot BUILD failure must fail loudly (CI installs
            // the target, so the green check always means the round-trip
            // really ran).
            ensure_pilot_toolchain_present();
            panic!("pilot build failed with the toolchain present — see stderr");
        };
        let caps = Arc::new(InMemoryCapabilities::default().with_config("greeting", "hello"));
        let mut host = WasmPluginHostBuilder::new(caps.clone())
            .build(wasm)
            .await
            .expect("host must build over the pilot");

        let out = host.run("fabric").await.expect("pilot run must succeed");
        assert_eq!(out, "hello: fabric", "greeting + kv echo, got {out}");

        // The guest's kv-set must have landed in the HOST's capability
        // store — the injection chain is real, not mocked.
        assert_eq!(
            caps.kv_get("last-run").unwrap().as_deref(),
            Some("fabric"),
            "the pilot's kv-set must land host-side"
        );
    }

    /// A guest's declared error (Err variant of run) must surface as
    /// [`WasmHostError::Guest`], not a host failure — the parse_run_result
    /// classification proven against a real bindgen guest's ABI.
    #[tokio::test]
    async fn f1_pilot_guest_error_classification() {
        let Some(wasm) = pilot_wasm() else {
            ensure_pilot_toolchain_present();
            panic!("pilot build failed with the toolchain present — see stderr");
        };
        // No greeting configured → the pilot returns Err("config-get:
        // greeting missing").
        let caps = Arc::new(InMemoryCapabilities::default());
        let mut host = WasmPluginHostBuilder::new(caps)
            .build(wasm)
            .await
            .expect("host must build over the pilot");

        let err = host.run("x").await.expect_err("missing config must fail");
        match err {
            crate::WasmHostError::Guest(msg) => {
                assert!(
                    msg.contains("greeting"),
                    "guest error carries its message: {msg}"
                );
            }
            other => panic!("expected Guest error, got {other}"),
        }
    }
}

/// The WIT contract gate: `wit/host.wit` must parse and carry the
/// world-v0 shape (four host imports, one guest export). Syntax or
/// shape drift fails here in CI instead of at B2 bind time.
#[cfg(test)]
mod wit_contract {

    /// The WIT contract gate: `wit/host.wit` must parse and carry the
    /// world-v0 shape (four host imports, one guest export). Syntax or
    /// shape drift fails here in CI instead of at B2 bind time.
    #[test]
    fn parses_and_pins_the_world_shape() {
        let source = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/wit/host.wit"))
            .expect("wit/host.wit must ship in-tree");
        let unresolved = wit_parser::UnresolvedPackageGroup::parse("wit/host.wit", &source)
            .unwrap_or_else(|e| panic!("host.wit must parse: {e:?}"));
        let mut resolver = wit_parser::Resolve::new();
        resolver
            .push_group(unresolved)
            .unwrap_or_else(|e| panic!("host.wit must resolve: {e:?}"));

        // Resolve.worlds is an Arena<World>: iterate (Id, &World) pairs.
        let world = resolver
            .worlds
            .iter()
            .find(|(_, world)| world.name == "guest")
            .map(|(_, world)| world)
            .expect("world guest must exist");
        let import_names: Vec<String> = world
            .imports
            .iter()
            .filter_map(|(_, item)| extern_name(item))
            .collect();
        for expected in ["log", "kv-get", "kv-set", "config-get"] {
            assert!(
                import_names.iter().any(|n| n == expected),
                "world must import {expected}, got {import_names:?}"
            );
        }
        let export_names: Vec<String> = world
            .exports
            .iter()
            .filter_map(|(_, item)| extern_name(item))
            .collect();
        assert!(
            export_names.iter().any(|n| n == "run"),
            "world must export run, got {export_names:?}"
        );
    }

    fn extern_name(item: &wit_parser::WorldItem) -> Option<String> {
        match item {
            wit_parser::WorldItem::Function(f) => Some(f.name.clone()),
            _ => None,
        }
    }
}
