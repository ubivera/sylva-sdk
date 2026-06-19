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
//!   `sylva.platform.v1`, from the vendored `proto/` (synced from sylva-server).
//! - [`flows`] (Phase 3b) — the enrollment flows that compose the above into the
//!   user operations: create the first owner, sign in (+ unlock), manage devices.
//! - [`storage`] (Phase 3.4) — per-OS-user keychain persistence of the enrollment
//!   secrets + server profile, so a device stays enrolled across launches.
//! - [`client`] (Phase 3.6) — the high-level [`client::SylvaClient`] facade the
//!   native shell drives: a stateful handle composing transport + flows +
//!   storage into connect / create-owner / sign-in / device-management calls.
//!   (The `uniffi` boundary + a blocking wrapper expose it to C# next.)

pub mod client;
pub mod crypto;
pub mod flows;
pub mod proto;
pub mod storage;
pub mod transport;

#[cfg(feature = "ffi")]
pub mod ffi;

// uniffi proc-macro scaffolding for the FFI boundary (feature-gated). C# bindings
// are generated from this by `uniffi-bindgen-cs` in Phase 4.
#[cfg(feature = "ffi")]
uniffi::setup_scaffolding!();
