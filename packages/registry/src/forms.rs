use serde::{Deserialize, Serialize};

/// The plugin **form**: how a host loads and runs the plugin (schema 2).
///
/// The forms follow the plugin-fabric shape taxonomy:
///
/// - [`FormKind::WasmComponent`] — F1, a WASM component payload. Hosts run
///   it on the tairitsu runtime stack (wasmtime server-side, the browser
///   glue on the webui side); hot reload is container-instance swap.
/// - [`FormKind::ProcessRpc`] — F2, an external process speaking JSON-RPC
///   over UDS/stdio/WS. Native core components (e.g. the boa IEPL engine)
///   take this form; hot reload is supervisor restart plus drain.
/// - [`FormKind::ScriptTs`] — F3, a TypeScript script plugin executed in
///   the boa sandbox (the akivili plugin host's existing form).
/// - [`FormKind::WebVueModule`] — F4, a Vue3 + TSX + SCSS webui module.
/// - [`FormKind::WebResource`] — F4, a declarative web resource
///   (style/theme/token payloads; never executes code).
///
/// Serialization is the wire spelling (`wasm.component` &c.), so TOML
/// manifests and JSON descriptors agree; unknown spellings fail to
/// deserialize.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FormKind {
    #[serde(rename = "wasm.component")]
    WasmComponent,
    #[serde(rename = "process.rpc")]
    ProcessRpc,
    #[serde(rename = "script.ts")]
    ScriptTs,
    #[serde(rename = "web.vue-module")]
    WebVueModule,
    #[serde(rename = "web.resource")]
    WebResource,
}

impl FormKind {
    /// The wire spelling of the form.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::WasmComponent => "wasm.component",
            Self::ProcessRpc => "process.rpc",
            Self::ScriptTs => "script.ts",
            Self::WebVueModule => "web.vue-module",
            Self::WebResource => "web.resource",
        }
    }
}

impl std::fmt::Display for FormKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_serializes_every_form() {
        for (wire, form) in [
            ("wasm.component", FormKind::WasmComponent),
            ("process.rpc", FormKind::ProcessRpc),
            ("script.ts", FormKind::ScriptTs),
            ("web.vue-module", FormKind::WebVueModule),
            ("web.resource", FormKind::WebResource),
        ] {
            let parsed: FormKind = serde_json::from_str(&format!("\"{wire}\"")).expect(wire);
            assert_eq!(parsed, form);
            assert_eq!(parsed.as_str(), wire);
            assert_eq!(
                serde_json::to_string(&parsed).unwrap(),
                format!("\"{wire}\"")
            );
        }
    }

    #[test]
    fn rejects_unknown_spellings() {
        for wire in [
            "wasm",
            "Wasm.Component",
            "web.esmodule",
            "process",
            "plugin",
        ] {
            assert!(
                serde_json::from_str::<FormKind>(&format!("\"{wire}\"")).is_err(),
                "'{wire}' must not parse as a form"
            );
        }
    }

    #[test]
    fn toml_round_trips() {
        #[derive(Serialize, Deserialize)]
        struct Wrapper {
            form: FormKind,
        }
        let text = toml::to_string(&Wrapper {
            form: FormKind::WasmComponent,
        })
        .unwrap();
        assert!(text.contains("wasm.component"), "{text}");
        let back: Wrapper = toml::from_str(&text).unwrap();
        assert_eq!(back.form, FormKind::WasmComponent);
    }
}
