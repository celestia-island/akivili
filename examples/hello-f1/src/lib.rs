//! The first F1 pilot plugin (Celestia Plugin Fabric B2).
//!
//! Binds the `celestia:host/host-v0` world (packages/wasm_host/wit/
//! host.wit) and exercises EVERY host import on each `run`: writes a
//! kv entry, reads it back, reads a config key, and logs the summary.
//! The run answer is the plugin's report — the adapter tests assert
//! its exact shape, so the full string-ABI round-trip (host → guest →
//! host capabilities → guest → host) is machine-checked.

wit_bindgen::generate!({
    path: "../../packages/wasm_host/wit",
    world: "guest",
});

struct HelloF1;

impl Guest for HelloF1 {
    fn run(payload: String) -> Result<String, String> {
        // kv-set: persist the payload under the run key.
        kv_set("last-run", &payload);

        // kv-get: read it back — proves the write landed host-side.
        let echo = kv_get("last-run").ok_or("kv-get returned none")?;
        if echo != payload {
            return Err(format!("kv round-trip mismatch: {echo:?} != {payload:?}"));
        }

        // config-get: read the plugin's own config section.
        let greeting = config_get("greeting").ok_or("config-get: greeting missing")?;

        // log: structured logging through the host.
        log("info", &format!("hello-f1 ran with payload {payload:?}"));

        Ok(format!("{greeting}: {echo}"))
    }
}

export!(HelloF1);
