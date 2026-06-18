//! Client side of server discovery: verify a `/.well-known/hearth-discovery`
//! response and decide trust (TOFU). The server side is `hearth::discovery`;
//! see `design/hub.md` + `docs/dev/hub-discovery.md` in the workspace.
//!
//! This module is **pure** — it verifies an already-fetched response. The HTTP
//! fetch + TLS land with the gRPC transport in the next sub-phase; keeping the
//! security-critical verification independent makes it exhaustively testable.

use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;

/// The signed-payload layout this client understands. Must match the server's
/// `PAYLOAD_VERSION`; a newer version is refused rather than mis-verified.
const PAYLOAD_VERSION: u32 = 1;

/// Domain-separation tag — identical to the server's, byte for byte.
const DOMAIN: &[u8] = b"sylva.hearth.discovery.v1";

#[derive(Debug, thiserror::Error)]
pub enum DiscoveryError {
    #[error("unsupported discovery payload version {0}")]
    UnsupportedVersion(u32),
    #[error("nonce mismatch — the response did not echo our challenge (possible replay)")]
    NonceMismatch,
    #[error("malformed discovery field: {0}")]
    Malformed(&'static str),
    #[error("discovery signature verification failed")]
    BadSignature,
}

type Result<T> = std::result::Result<T, DiscoveryError>;

/// The raw discovery response as returned by the server (hex-encoded key +
/// signature).
#[derive(Debug, Clone, Deserialize)]
pub struct DiscoveryResponse {
    pub name: String,
    pub server_version: String,
    pub grpc_port: u16,
    /// Hex-encoded Ed25519 public key.
    pub server_identity_public: String,
    /// The nonce echoed back from our request.
    pub nonce: String,
    /// Hex-encoded Ed25519 signature over the canonical payload.
    pub signature: String,
    pub payload_version: u32,
}

/// A discovery response whose signature checked out against the identity key it
/// carries. The caller still has to make the **trust** decision ([`check_pin`]).
#[derive(Debug, Clone)]
pub struct VerifiedServer {
    pub identity_public: [u8; 32],
    pub name: String,
    pub server_version: String,
    pub grpc_port: u16,
}

/// Verify a discovery response end to end: payload version, that the server
/// echoed *our* `expected_nonce` (freshness / anti-replay), and the Ed25519
/// signature over the canonical bytes — using the key the response carries.
///
/// A pass means "this response was signed *now* by whoever holds this identity
/// key." Whether that key is the one we trust is the separate [`check_pin`].
pub fn verify_discovery(resp: &DiscoveryResponse, expected_nonce: &str) -> Result<VerifiedServer> {
    if resp.payload_version != PAYLOAD_VERSION {
        return Err(DiscoveryError::UnsupportedVersion(resp.payload_version));
    }
    if resp.nonce != expected_nonce {
        return Err(DiscoveryError::NonceMismatch);
    }

    let identity_public = decode_hex_array::<32>(&resp.server_identity_public)
        .ok_or(DiscoveryError::Malformed("server_identity_public"))?;
    let signature_bytes =
        decode_hex_array::<64>(&resp.signature).ok_or(DiscoveryError::Malformed("signature"))?;

    let verifying_key =
        VerifyingKey::from_bytes(&identity_public).map_err(|_| DiscoveryError::Malformed("identity key"))?;
    let signature = Signature::from_bytes(&signature_bytes);
    let message = canonical_bytes(&resp.nonce, &identity_public, resp.grpc_port, &resp.name);
    verifying_key
        .verify_strict(&message, &signature)
        .map_err(|_| DiscoveryError::BadSignature)?;

    Ok(VerifiedServer {
        identity_public,
        name: resp.name.clone(),
        server_version: resp.server_version.clone(),
        grpc_port: resp.grpc_port,
    })
}

/// The trust-on-first-use outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustDecision {
    /// No pin yet — first contact. The caller pins `identity_public`.
    FirstContact,
    /// The verified identity matches the stored pin. Proceed.
    Matches,
    /// The verified identity differs from the pin — refuse + warn (reinstall or
    /// attack).
    Mismatch,
}

/// TOFU: compare a freshly [`verify_discovery`]-ed identity against the pin we
/// stored on first contact (`None` if we've never seen this server).
pub fn check_pin(verified: &VerifiedServer, pinned: Option<&[u8; 32]>) -> TrustDecision {
    match pinned {
        None => TrustDecision::FirstContact,
        Some(pin) if pin == &verified.identity_public => TrustDecision::Matches,
        Some(_) => TrustDecision::Mismatch,
    }
}

/// The exact bytes the server signed — domain-separated and length-prefixed per
/// field. MUST stay byte-for-byte identical to `hearth::discovery::canonical_bytes`.
fn canonical_bytes(nonce: &str, public: &[u8; 32], grpc_port: u16, name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    push_field(&mut out, DOMAIN);
    push_field(&mut out, &PAYLOAD_VERSION.to_be_bytes());
    push_field(&mut out, nonce.as_bytes());
    push_field(&mut out, public);
    push_field(&mut out, &grpc_port.to_be_bytes());
    push_field(&mut out, name.as_bytes());
    out
}

fn push_field(out: &mut Vec<u8>, field: &[u8]) {
    out.extend_from_slice(&(field.len() as u32).to_be_bytes());
    out.extend_from_slice(field);
}

/// Decode a hex string into a fixed `N`-byte array, or `None` if it isn't
/// exactly `2N` hex digits.
fn decode_hex_array<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != N * 2 {
        return None;
    }
    let mut out = [0u8; N];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn hex_encode(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push(HEX[(b >> 4) as usize] as char);
            s.push(HEX[(b & 0x0f) as usize] as char);
        }
        s
    }

    /// Build a discovery response signed exactly the way the server does — the
    /// cross-implementation contract for the canonical format.
    fn signed_response(
        key: &SigningKey,
        nonce: &str,
        name: &str,
        grpc_port: u16,
    ) -> DiscoveryResponse {
        let public = key.verifying_key().to_bytes();
        let signature = key.sign(&canonical_bytes(nonce, &public, grpc_port, name));
        DiscoveryResponse {
            name: name.to_string(),
            server_version: "0.0.1".to_string(),
            grpc_port,
            server_identity_public: hex_encode(&public),
            nonce: nonce.to_string(),
            signature: hex_encode(&signature.to_bytes()),
            payload_version: PAYLOAD_VERSION,
        }
    }

    #[test]
    fn verifies_a_well_formed_response() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let resp = signed_response(&key, "abc123", "My Hearth", 50051);
        let verified = verify_discovery(&resp, "abc123").unwrap();
        assert_eq!(verified.identity_public, key.verifying_key().to_bytes());
        assert_eq!(verified.name, "My Hearth");
        assert_eq!(verified.grpc_port, 50051);
    }

    #[test]
    fn rejects_a_replayed_or_mismatched_nonce() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let resp = signed_response(&key, "server-said", "H", 50051);
        assert!(matches!(
            verify_discovery(&resp, "we-asked-for-other"),
            Err(DiscoveryError::NonceMismatch)
        ));
    }

    #[test]
    fn rejects_unsupported_payload_version() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let mut resp = signed_response(&key, "n", "H", 50051);
        resp.payload_version = 2;
        assert!(matches!(
            verify_discovery(&resp, "n"),
            Err(DiscoveryError::UnsupportedVersion(2))
        ));
    }

    #[test]
    fn rejects_tampered_fields() {
        let key = SigningKey::from_bytes(&[7u8; 32]);

        // Name changed after signing → signature no longer covers it.
        let mut resp = signed_response(&key, "n", "Real", 50051);
        resp.name = "Evil".to_string();
        assert!(matches!(verify_discovery(&resp, "n"), Err(DiscoveryError::BadSignature)));

        // Port changed after signing.
        let mut resp = signed_response(&key, "n", "Real", 50051);
        resp.grpc_port = 1;
        assert!(matches!(verify_discovery(&resp, "n"), Err(DiscoveryError::BadSignature)));
    }

    #[test]
    fn rejects_a_substituted_identity_key() {
        // An attacker re-signs the payload with their own key but can't change
        // the advertised key to match without us noticing at the pin step; even
        // self-consistent, a different key simply isn't the pinned one.
        let attacker = SigningKey::from_bytes(&[9u8; 32]);
        let resp = signed_response(&attacker, "n", "H", 50051);
        // It self-verifies (attacker signed their own key)...
        let verified = verify_discovery(&resp, "n").unwrap();
        // ...but TOFU catches the swap.
        let real = SigningKey::from_bytes(&[7u8; 32]).verifying_key().to_bytes();
        assert_eq!(check_pin(&verified, Some(&real)), TrustDecision::Mismatch);
    }

    #[test]
    fn rejects_malformed_hex() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let mut resp = signed_response(&key, "n", "H", 50051);
        resp.server_identity_public = "not-hex".to_string();
        assert!(matches!(verify_discovery(&resp, "n"), Err(DiscoveryError::Malformed(_))));

        let mut resp = signed_response(&key, "n", "H", 50051);
        resp.signature = "abcd".to_string(); // wrong length
        assert!(matches!(verify_discovery(&resp, "n"), Err(DiscoveryError::Malformed(_))));
    }

    #[test]
    fn empty_nonce_round_trips() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let resp = signed_response(&key, "", "H", 50051);
        assert!(verify_discovery(&resp, "").is_ok());
    }

    #[test]
    fn tofu_decisions() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let resp = signed_response(&key, "n", "H", 50051);
        let verified = verify_discovery(&resp, "n").unwrap();
        let pin = key.verifying_key().to_bytes();

        assert_eq!(check_pin(&verified, None), TrustDecision::FirstContact);
        assert_eq!(check_pin(&verified, Some(&pin)), TrustDecision::Matches);
        assert_eq!(check_pin(&verified, Some(&[0u8; 32])), TrustDecision::Mismatch);
    }
}
