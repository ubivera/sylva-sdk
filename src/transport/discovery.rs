//! Client side of server discovery: verify a `/.well-known/sylva-discovery`
//! response and decide trust (TOFU). The server side is `server::discovery`;
//! see `design/hub.md` + `docs/dev/hub-discovery.md` in the workspace.
//!
//! This module is **pure** — it verifies an already-fetched response. The HTTP
//! fetch + TLS land with the gRPC transport in the next sub-phase; keeping the
//! security-critical verification independent makes it exhaustively testable.

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

/// The signed-payload layout this client understands. Must match the server's
/// `PAYLOAD_VERSION`; a newer version is refused rather than mis-verified.
const PAYLOAD_VERSION: u32 = 1;

/// Domain-separation tag — identical to the server's, byte for byte.
const DOMAIN: &[u8] = b"sylva.discovery.v1";

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
    #[error("discovery request failed")]
    Fetch,
}

type Result<T> = std::result::Result<T, DiscoveryError>;

/// The raw discovery response as returned by the server (hex-encoded key +
/// signature). `Serialize` is for tests; in production the SDK only deserializes.
#[derive(Debug, Clone, Serialize, Deserialize)]
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

/// Parse a discovery JSON body and verify it against `expected_nonce`. The pure
/// half of [`fetch_and_verify`], split out so the parse + verify pipeline is
/// testable without a network.
pub fn parse_and_verify(body: &[u8], expected_nonce: &str) -> Result<VerifiedServer> {
    let response: DiscoveryResponse =
        serde_json::from_slice(body).map_err(|_| DiscoveryError::Malformed("response body"))?;
    verify_discovery(&response, expected_nonce)
}

/// Fetch + verify discovery from a base server URL (e.g. `http://host:port`):
/// generate a fresh nonce, `GET /.well-known/sylva-discovery`, and verify the
/// signed response. The caller still decides *trust* via [`check_pin`].
///
/// Connection is plain HTTP for now (dev); HTTPS arrives with the TLS work. The
/// signature + identity pin are the trust anchor regardless.
pub async fn fetch_and_verify(base_url: &str) -> Result<VerifiedServer> {
    let nonce = random_nonce();
    let url = discovery_url(base_url, &nonce);
    let response = reqwest::get(&url).await.map_err(|_| DiscoveryError::Fetch)?;
    if !response.status().is_success() {
        return Err(DiscoveryError::Fetch);
    }
    let body = response.bytes().await.map_err(|_| DiscoveryError::Fetch)?;
    parse_and_verify(&body, &nonce)
}

/// `{base}/.well-known/sylva-discovery?nonce={nonce}` (a trailing slash on
/// `base` is tolerated).
fn discovery_url(base_url: &str, nonce: &str) -> String {
    format!(
        "{}/.well-known/sylva-discovery?nonce={}",
        base_url.trim_end_matches('/'),
        nonce
    )
}

/// A fresh 128-bit random discovery nonce, hex-encoded.
fn random_nonce() -> String {
    let mut bytes = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
    encode_hex(&bytes)
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// The exact bytes the server signed — domain-separated and length-prefixed per
/// field. MUST stay byte-for-byte identical to `server::discovery::canonical_bytes`.
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

    #[test]
    fn parse_and_verify_round_trips_through_json() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let resp = signed_response(&key, "nonce-1", "My Hearth", 50051);
        let json = serde_json::to_vec(&resp).unwrap();
        let verified = parse_and_verify(&json, "nonce-1").unwrap();
        assert_eq!(verified.identity_public, key.verifying_key().to_bytes());
        assert_eq!(verified.grpc_port, 50051);
    }

    #[test]
    fn parse_and_verify_accepts_the_server_json_shape() {
        // A hand-written body with the server's exact field names + a valid
        // signature — locks the wire format the SDK must parse.
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let resp = signed_response(&key, "nonce-xyz", "H", 50051);
        let json = format!(
            r#"{{"name":"{}","server_version":"{}","grpc_port":{},"server_identity_public":"{}","nonce":"{}","signature":"{}","payload_version":{}}}"#,
            resp.name,
            resp.server_version,
            resp.grpc_port,
            resp.server_identity_public,
            resp.nonce,
            resp.signature,
            resp.payload_version
        );
        assert!(parse_and_verify(json.as_bytes(), "nonce-xyz").is_ok());
    }

    #[test]
    fn parse_and_verify_rejects_malformed_json_and_bad_nonce() {
        assert!(matches!(
            parse_and_verify(b"not json", "n"),
            Err(DiscoveryError::Malformed(_))
        ));
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let json = serde_json::to_vec(&signed_response(&key, "good", "H", 50051)).unwrap();
        assert!(matches!(
            parse_and_verify(&json, "wrong"),
            Err(DiscoveryError::NonceMismatch)
        ));
    }

    #[test]
    fn discovery_url_builds_correctly() {
        assert_eq!(
            discovery_url("http://host:8443", "abc"),
            "http://host:8443/.well-known/sylva-discovery?nonce=abc"
        );
        // A trailing slash on the base is tolerated (no doubled slash).
        assert_eq!(
            discovery_url("http://host:8443/", "abc"),
            "http://host:8443/.well-known/sylva-discovery?nonce=abc"
        );
    }

    #[test]
    fn random_nonce_is_unique_hex() {
        let a = random_nonce();
        let b = random_nonce();
        assert_eq!(a.len(), 32);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b, "nonces must be fresh per call");
    }
}
