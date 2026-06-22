//! Transport: finding a Sylva Server and anchoring trust in it.
//!
//! So far: the **discovery** verification + TOFU pinning (the client half of the
//! `/.well-known/sylva-discovery` handshake). The HTTP fetch, endpoint-list
//! failover, TLS (self-signed, anchored on the identity key), and the gRPC
//! channel land with the gRPC client stubs in the next sub-phase.

pub mod client;
pub mod discovery;

pub use client::{AccountSession, ClientError, bootstrap, connect, login};
pub use discovery::{
    DiscoveryError, DiscoveryResponse, TrustDecision, VerifiedServer, check_pin, fetch_and_verify,
    parse_and_verify, verify_discovery,
};

use tonic::transport::Channel;

#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
    #[error(transparent)]
    Discovery(#[from] DiscoveryError),
    #[error(transparent)]
    Connect(#[from] ClientError),
    #[error("the server's identity does not match the pinned key (possible MITM or reinstall)")]
    IdentityMismatch,
}

/// One-shot: discover + verify a server, apply the TOFU pin check, then connect
/// its advertised gRPC port. `host` + `discovery_port` are what the user
/// entered; `pinned` is the previously-stored identity key (`None` on first
/// contact). Returns the connected channel, the verified server, and the trust
/// decision — the caller **pins** `verified.identity_public` on `FirstContact`.
///
/// Refuses outright on `Mismatch` (a changed identity). gRPC connects to the
/// same `host` at the discovered `grpc_port`.
pub async fn discover_and_connect(
    host: &str,
    discovery_port: u16,
    pinned: Option<&[u8; 32]>,
) -> Result<(Channel, VerifiedServer, TrustDecision), ConnectError> {
    let verified = discovery::fetch_and_verify(&format!("http://{host}:{discovery_port}")).await?;
    let decision = discovery::check_pin(&verified, pinned);
    if decision == TrustDecision::Mismatch {
        return Err(ConnectError::IdentityMismatch);
    }
    let channel = client::connect(&[format!("{host}:{}", verified.grpc_port)]).await?;
    Ok((channel, verified, decision))
}
