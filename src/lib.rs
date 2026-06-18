//! # Sylva SDK
//!
//! The shared Rust client core every Sylva client (Sylva Hub first) builds on
//! to talk to a Hearth server. See `design/hub.md` + `docs/dev/hub-build-spec.md`
//! in the workspace for the full picture.
//!
//! **Scope so far:**
//! - [`crypto`] (Phase 3a) — the client-side **end-to-end crypto**: the
//!   1Password-style two-secret key derivation (2SKD), master-key wrap/unwrap,
//!   and user/device keypair generation. The security root the whole system
//!   rests on; built and tested in isolation before any network code. The server
//!   stores only the ciphertext it produces — never the password, Secret Key,
//!   master key, or any private key.
//! - [`transport`] (Phase 3b) — finding a server and anchoring trust:
//!   **discovery** response verification + TOFU identity pinning. The HTTP fetch,
//!   endpoint failover, TLS, and the enrollment flows follow.
//! - [`proto`] (Phase 3b) — generated gRPC client stubs for `sylva.account.v1` +
//!   `sylva.platform.v1`, from the vendored `proto/` (synced from sylva-hearth).

pub mod crypto;
pub mod proto;
pub mod transport;
