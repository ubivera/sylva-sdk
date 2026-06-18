//! Transport: finding a Hearth server and anchoring trust in it.
//!
//! So far: the **discovery** verification + TOFU pinning (the client half of the
//! `/.well-known/hearth-discovery` handshake). The HTTP fetch, endpoint-list
//! failover, TLS (self-signed, anchored on the identity key), and the gRPC
//! channel land with the gRPC client stubs in the next sub-phase.

pub mod discovery;

pub use discovery::{
    DiscoveryError, DiscoveryResponse, TrustDecision, VerifiedServer, check_pin, verify_discovery,
};
