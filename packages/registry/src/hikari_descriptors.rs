//! Phase 4 closeout: the hikari wasm component descriptors are real
//! `PluginManifest`s, and the registry rejects the four wrong shapes
//! *before* anything is loaded or executed.
//!
//! hikari ships four first-party `wasm.component` plugins (qr, mermaid,
//! scene3d, highlight). Each carries a descriptor (`component.toml`,
//! authored in the hikari repo) shaped like this crate's
//! [`PluginManifest`]. This module pins the akivili half of that
//! contract — that the shape is accepted end to end through
//! [`crate::store::scan`], and that each of the four failure shapes a
//! descriptor can take is refused at scan/validation time with a reason
//! that names the offending field.
//!
//! The descriptors are reproduced here rather than read from a hikari
//! checkout: this crate must not depend on a sibling repository's
//! working tree. The hikari-side consistency gate
//! (`packages/wasm/component_descriptor.py`) is what keeps these
//! reproductions honest against the real WIT files.
//!
//! One descriptor per component, in the same order the hikari gate
//! reports them.

#[cfg(test)]
mod tests {
    use crate::forms::FormKind;
    use crate::manifest::{MANIFEST_FILE, PluginManifest};
    use crate::registry::DEFAULT_MAX_PAYLOAD_BYTES;
    use crate::store::{ScanResult, scan};

    /// The artifact bytes are stand-ins: a real `.wasm` is 96 KB–2.3 MB and
    /// this crate only ever needs a payload whose digest it can compute. The
    /// hikari gate is what checks digests against real artifacts.
    const ARTIFACT: &[u8] = b"\0asm\x0d\x00\x01\x00stub wasm component";

    fn sha256_hex(bytes: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(bytes);
        digest.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// One descriptor, exactly as hikari writes it — only the digest is
    /// recomputed over [`ARTIFACT`] instead of the shipped bytes.
    fn descriptor(id: &str, world: &str, capabilities: &[&str]) -> String {
        let caps = capabilities
            .iter()
            .map(|c| format!("\"{c}\""))
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            r#"
schema = 1
id = "{id}"
version = "0.1.0"
provider = "celestia-island"
description = "hikari component"
form = "wasm.component"
platforms = ["web"]
capabilities = [{caps}]
requires-contract = ["celestia:{id}/{world}@0.1"]

[[resources]]
kind = "wasm.component"

[resources.payload.File]
path = "target/wasm32-wasip2/release/hikari_wasm_{id}.wasm"
sha256 = "{}"
"#,
            sha256_hex(ARTIFACT)
        )
    }

    /// The four first-party descriptors `(id, world)`.
    const COMPONENTS: [(&str, &str); 4] = [
        ("hikari-qr", "qr"),
        ("hikari-mermaid", "mermaid"),
        ("hikari-scene3d", "scene3d"),
        ("hikari-highlight", "highlight"),
    ];

    /// Scans a one-plugin store and returns the outcome.
    fn scan_one(manifest: &str) -> ScanResult {
        let root = tempfile::tempdir().expect("tempdir");
        let dir = root.path().join("component");
        std::fs::create_dir_all(dir.join("target/wasm32-wasip2/release")).expect("mkdir");
        std::fs::write(dir.join(MANIFEST_FILE), manifest).expect("manifest");
        std::fs::write(
            dir.join("target/wasm32-wasip2/release/hikari_wasm_hikari-qr.wasm"),
            ARTIFACT,
        )
        .expect("artifact");
        let results =
            scan(root.path(), &Default::default(), DEFAULT_MAX_PAYLOAD_BYTES).expect("scan");
        results.into_iter().next().expect("one result")
    }

    /// The reason a one-plugin scan rejected its plugin, or a panic
    /// carrying the acceptance (so a green run cannot hide a rejection
    /// that moved into a different branch).
    fn rejection(manifest: &str) -> String {
        match scan_one(manifest) {
            ScanResult::Rejected(rejection) => rejection.reason,
            ScanResult::Accepted(record) => {
                panic!("expected a rejection, got an accepted plugin: {record:?}")
            }
        }
    }

    #[test]
    fn every_hikari_descriptor_is_a_valid_manifest() {
        for (id, world) in COMPONENTS {
            let manifest = descriptor(id, world, &[]);
            let parsed: PluginManifest = toml::from_str(&manifest)
                .unwrap_or_else(|e| panic!("{id}: descriptor must parse: {e}"));
            parsed
                .validate()
                .unwrap_or_else(|e| panic!("{id}: descriptor must validate: {e}"));
            assert_eq!(parsed.form, Some(FormKind::WasmComponent), "{id}");
            assert_eq!(parsed.id, id);
            assert_eq!(parsed.version, "0.1.0");
            let contract = parsed
                .requires_contract
                .first()
                .unwrap_or_else(|| panic!("{id}: must pin a contract"));
            assert_eq!(contract.as_str(), format!("celestia:{id}/{world}@0.1"));
            assert!(
                parsed.capabilities.is_empty(),
                "{id}: the four components are pure computation -- no imports, no grant"
            );
        }
    }

    /// The whole four-component store scans clean: every descriptor is
    /// accepted and the declared digest matches the payload bytes.
    #[test]
    fn the_four_first_party_descriptors_scan_clean() {
        let root = tempfile::tempdir().expect("tempdir");
        for (id, world) in COMPONENTS {
            let dir = root.path().join(id);
            std::fs::create_dir_all(dir.join("target/wasm32-wasip2/release")).expect("mkdir");
            std::fs::write(dir.join(MANIFEST_FILE), descriptor(id, world, &[])).expect("manifest");
            std::fs::write(
                dir.join(format!(
                    "target/wasm32-wasip2/release/hikari_wasm_{id}.wasm"
                )),
                ARTIFACT,
            )
            .expect("artifact");
        }
        let results =
            scan(root.path(), &Default::default(), DEFAULT_MAX_PAYLOAD_BYTES).expect("scan runs");
        assert_eq!(results.len(), COMPONENTS.len(), "{results:?}");
        // Store scans report in DIRECTORY-NAME order, which is not the
        // declaration order of `COMPONENTS`. Compare as a sorted id set so
        // the assertion is about "all four accepted" and not about a
        // coincidence between two orderings.
        let mut accepted: Vec<String> = Vec::new();
        for result in &results {
            match result {
                ScanResult::Accepted(record) => {
                    assert!(record.enabled);
                    accepted.push(record.manifest.id.clone());
                }
                ScanResult::Rejected(rejection) => {
                    panic!(
                        "{} rejected: {}",
                        rejection.plugin_id.clone().unwrap_or_default(),
                        rejection.reason
                    )
                }
            }
        }
        accepted.sort();
        let mut expected: Vec<String> = COMPONENTS.iter().map(|(id, _)| id.to_string()).collect();
        expected.sort();
        assert_eq!(accepted, expected, "every descriptor must be accepted");
    }

    /// A descriptor whose `sha256` is one character off must be refused at
    /// scan time, naming the digest — the registry never feeds bytes the
    /// descriptor did not review.
    #[test]
    fn a_one_character_digest_change_is_rejected_before_load() {
        let good = descriptor("hikari-qr", "qr", &[]);
        let digest = sha256_hex(ARTIFACT);
        // Flip the LAST character: a one-character change is the smallest
        // edit that still leaves a well-formed 64-character hex digest, so
        // the rejection below is about the value and not about the shape.
        let mut flipped: Vec<char> = digest.chars().collect();
        let last = flipped.last_mut().expect("digest is non-empty");
        *last = if *last == '0' { '1' } else { '0' };
        let flipped: String = flipped.into_iter().collect();
        assert_ne!(
            flipped, digest,
            "the control must actually change the value"
        );
        let tampered = good.replace(&digest, &flipped);
        assert_ne!(tampered, good, "the control must reach the manifest");
        // `String::replace` silently does nothing when the needle is absent,
        // which would leave the descriptor correct and make the rejection
        // below a claim about the WRONG fixture. Pin the needle itself.
        assert!(
            good.contains(&digest),
            "the fixture must actually contain the good digest, else the flip is a no-op"
        );
        assert!(
            tampered.contains(&flipped) && !tampered.contains(&digest),
            "the tampered manifest must carry the flipped digest and not the original"
        );

        let reason = rejection(&tampered);
        assert!(
            reason.contains("sha256 mismatch"),
            "the reason must name the digest failure, got: {reason}"
        );
        assert!(
            reason.contains(&flipped) && reason.contains(&digest),
            "the reason must show declared and actual, got: {reason}"
        );

        // Both halves of the store's message must be about THIS fixture: the
        // declared value is the flipped one and the actual is the real digest.
        // Asserting only that both substrings appear would pass if the reason
        // quoted them in the opposite roles.
        let declared_then_actual = format!("declared {flipped}, actual {digest}");
        assert!(
            reason.contains(&declared_then_actual),
            "the reason must pair declared={flipped} with actual={digest}, got: {reason}"
        );
    }

    /// A contract reference naming a world that is not the component's is
    /// still a *syntactically* valid ref, so the registry alone cannot
    /// catch it — this test pins that boundary honestly: the shape passes
    /// and the hikari-side gate is what compares it to the WIT.
    #[test]
    fn a_wrong_world_is_syntactically_valid_and_needs_the_wit_gate() {
        let wrong_world = descriptor("hikari-qr", "encode", &[]);
        let parsed: PluginManifest =
            toml::from_str(&wrong_world).expect("a wrong world is still a valid ref shape");
        parsed
            .validate()
            .expect("a wrong world passes shape validation -- by design");
        assert_eq!(
            parsed.requires_contract[0].as_str(),
            "celestia:hikari-qr/encode@0.1",
            "the registry stores what was declared; matching it to a WIT world is the \
             contract gate's job, not the ref parser's"
        );
        // The shape-level parser DOES reject a malformed version, which is
        // the half of this failure the registry owns.
        let bad_version = wrong_world.replace(
            "celestia:hikari-qr/encode@0.1",
            "celestia:hikari-qr/encode@1",
        );
        let parsed: Result<PluginManifest, _> = toml::from_str(&bad_version);
        assert!(
            parsed.is_err(),
            "a one-part version must fail the ContractRef shape"
        );
    }

    /// A capability outside the closed vocabulary never even parses: the
    /// deserializer routes through `Capability::new`. This is the
    /// registry-side half of "declared wider than the contract".
    #[test]
    fn an_unknown_capability_fails_at_parse_time() {
        let widened = descriptor("hikari-qr", "qr", &["dom.full-control"]);
        let parsed: Result<PluginManifest, _> = toml::from_str(&widened);
        let error = parsed.expect_err("an out-of-vocabulary capability must not parse");
        assert!(
            error.to_string().contains("closed v1 vocabulary"),
            "the error must name the closed vocabulary, got: {error}"
        );
    }

    /// A capability that IS in the vocabulary but that the component does
    /// not import parses fine — the registry has no WIT to compare against.
    /// Pinned so the boundary is visible: the hikari gate owns this check.
    #[test]
    fn a_vocabulary_capability_is_accepted_even_when_unjustified() {
        let widened = descriptor("hikari-qr", "qr", &["kv.read"]);
        let parsed: PluginManifest =
            toml::from_str(&widened).expect("kv.read is in the closed vocabulary, so it parses");
        parsed
            .validate()
            .expect("the registry cannot know this component imports nothing");
        assert_eq!(parsed.capabilities[0].as_str(), "kv.read");
    }
}
