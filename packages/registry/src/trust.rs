//! Ed25519 signature verification for plugin distribution (C4).
//!
//! The `[trust]` section's `signature` names a signature file inside
//! the plugin directory; the signature is Ed25519 over the plugin's
//! PAYLOAD — every resource file's bytes in manifest order (the
//! content-addressed digest chain the store already computes per
//! file). A plugin demanding trust (`min-trust` above unsigned, or an
//! explicit signature path) fails closed: missing file, malformed
//! bytes, or a key mismatch all refuse the load.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

use crate::error::{RegistryError, RegistryResult};
use crate::manifest::{MinTrust, TrustSection, TrustVerdict};

/// One publisher key's material, identified for verdict diagnostics.
pub struct PublisherKey {
    /// A stable key id (e.g. a fingerprint prefix) for diagnostics.
    pub key_id: String,
    /// The raw Ed25519 verifying key (32 bytes).
    pub bytes: [u8; 32],
}

/// Verify a plugin's declared signature over its payload bytes.
///
/// `signature_file` is the signature file's content; `payload` is the
/// concatenation the distribution format defines (v0: the resource
/// files' bytes in manifest order — the store hands it in already
/// assembled).
pub fn verify_plugin_signature(
    trust: &TrustSection,
    signature_file: Option<&[u8]>,
    payload: &[u8],
    keys: &[PublisherKey],
) -> RegistryResult<TrustVerdict> {
    if !trust.requires_signature() {
        return Ok(TrustVerdict::UnsignedOk);
    }
    let Some(bytes) = signature_file else {
        return Ok(TrustVerdict::UnsignedButDemanded);
    };
    let signature = Signature::from_slice(bytes)
        .map_err(|e| RegistryError::InvalidManifest(format!("malformed signature file: {e}")))?;
    for key in keys {
        let verifying = VerifyingKey::from_bytes(&key.bytes)
            .map_err(|e| RegistryError::InvalidManifest(format!("publisher key: {e}")))?;
        if verifying.verify(payload, &signature).is_ok() {
            if trust.min_trust == MinTrust::VerifiedPublisher {
                // v0: every key in the list counts as a verified
                // publisher; the allowlist split (known vs verified)
                // arrives with the registry's publisher directory.
                return Ok(TrustVerdict::SignedOk {
                    key_id: key.key_id.clone(),
                });
            }
            return Ok(TrustVerdict::SignedOk {
                key_id: key.key_id.clone(),
            });
        }
    }
    Ok(TrustVerdict::SignatureMismatch {
        reason: "no listed publisher key verifies the payload".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn section(signature: Option<&str>, min_trust: MinTrust) -> TrustSection {
        TrustSection {
            signature: signature.map(str::to_string),
            min_trust,
        }
    }

    #[test]
    fn an_unsigned_demand_answers_unsigned_ok() {
        let trust = section(None, MinTrust::Unsigned);
        let verdict =
            verify_plugin_signature(&trust, None, b"payload", &[]).expect("unsigned lane");
        assert_eq!(verdict, TrustVerdict::UnsignedOk);
    }

    #[test]
    fn a_demanded_but_missing_signature_fails_closed() {
        let trust = section(Some("agent.sig".into()), MinTrust::Signed);
        let verdict =
            verify_plugin_signature(&trust, None, b"payload", &[]).expect("verdict computes");
        assert_eq!(verdict, TrustVerdict::UnsignedButDemanded);
    }

    #[test]
    fn a_valid_signature_verifies_under_its_key() {
        let signing = SigningKey::generate(&mut rand::rngs::OsRng);
        let payload = b"the plugin payload bytes";
        let signature = signing.sign(payload);
        let keys = vec![PublisherKey {
            key_id: "test-key".into(),
            bytes: signing.verifying_key().to_bytes(),
        }];
        let trust = section(Some("agent.sig".into()), MinTrust::Signed);
        let verdict = verify_plugin_signature(&trust, Some(&signature.to_bytes()), payload, &keys)
            .expect("verdict computes");
        assert_eq!(
            verdict,
            TrustVerdict::SignedOk {
                key_id: "test-key".into()
            }
        );
    }

    #[test]
    fn a_foreign_signature_reports_a_mismatch() {
        let other = SigningKey::generate(&mut rand::rngs::OsRng);
        let signature = other.sign(b"tampered payload");
        let signing = SigningKey::generate(&mut rand::rngs::OsRng);
        let keys = vec![PublisherKey {
            key_id: "real-key".into(),
            bytes: signing.verifying_key().to_bytes(),
        }];
        let trust = section(Some("agent.sig".into()), MinTrust::Signed);
        let verdict = verify_plugin_signature(
            &trust,
            Some(&signature.to_bytes()),
            b"different payload",
            &keys,
        )
        .expect("verdict computes");
        assert!(matches!(verdict, TrustVerdict::SignatureMismatch { .. }));
    }

    #[test]
    fn malformed_signature_bytes_are_a_loud_error() {
        let trust = section(Some("agent.sig".into()), MinTrust::Signed);
        let err = verify_plugin_signature(&trust, Some(&[1u8; 8]), b"p", &[])
            .expect_err("garbage bytes must not verify");
        assert!(err.to_string().contains("malformed signature"), "{err}");
    }
}
