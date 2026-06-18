//! # Sylva SDK
//!
//! The shared Rust client core every Sylva client (Sylva Hub first) builds on
//! to talk to a Hearth server. See `design/hub.md` + `docs/dev/hub-build-spec.md`
//! in the workspace for the full picture.
//!
//! **Current scope (Phase 3a):** the client-side **end-to-end crypto** — the
//! 1Password-style two-secret key derivation (2SKD), master-key wrap/unwrap, and
//! user/device keypair generation. This is the security root the whole system
//! rests on, so it's built and tested first, in isolation, before any network
//! code. Transport (discovery + gRPC), the enrollment flows, OS-keychain
//! storage, and the `uniffi` boundary land in later phases.
//!
//! The server stores only the *ciphertext* this module produces (the wrapped
//! master key + salt/params, the master-key-wrapped private keys, the public
//! keys); it never sees the password, the Secret Key, the master key, or any
//! private key.

pub mod crypto;
