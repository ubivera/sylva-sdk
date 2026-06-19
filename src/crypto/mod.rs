//! Client-side end-to-end crypto: the 1Password-style **two-secret key
//! derivation** (2SKD), master-key wrap/unwrap, and user/device keypair
//! generation. See `design/hub.md` §"How the keys work" + `design/auth.md`.
//!
//! ## The key hierarchy
//!
//! - A random **master key** (32 bytes) is the root of the user's E2E
//!   encryption. The user's X25519 + Ed25519 **private keys** are wrapped under
//!   it (XChaCha20-Poly1305).
//! - The master key itself is wrapped under a **KEK** derived from *both* the
//!   password and the **Secret Key** — neither alone is ever sufficient.
//!
//! ## The 2SKD construction (`derive_kek`)
//!
//! Two independent derivations over the same per-user salt, combined by XOR —
//! the 1Password approach, so a weakness in one factor can't undermine the
//! other:
//!
//! ```text
//! password_leg  = Argon2id(password, salt, m=64MiB, t=3, p=4)   // 32 bytes
//! secretkey_leg = HKDF-SHA256(ikm = secret_key, salt, info)      // 32 bytes
//! KEK           = password_leg XOR secretkey_leg                 // 32 bytes
//! ```
//!
//! The server stores only `master_key_wrapped` + the salt/params + the
//! master-key-wrapped private keys + the public keys. It never sees the
//! password (it keeps a *separate*, server-computed Argon2id verifier), the
//! Secret Key, the master key, or any private key.

mod secret_key;

pub use secret_key::SecretKey;

use zeroize::{Zeroize, Zeroizing};

/// Domain-separation label for the Secret Key's HKDF leg.
const HKDF_INFO: &[u8] = b"sylva.2skd.v1";
/// Per-user KDF salt size (matches `auth.md`).
const SALT_LEN: usize = 16;
/// Symmetric key size for the master key + all AEAD wraps.
const KEY_LEN: usize = 32;
/// XChaCha20-Poly1305 nonce size (prepended to each wrap).
const NONCE_LEN: usize = 24;

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("key derivation failed")]
    Kdf,
    /// Wrong password / Secret Key, or corrupted/tampered ciphertext — callers
    /// must not distinguish these.
    #[error("decryption failed")]
    Decrypt,
    #[error("malformed input: {0}")]
    Malformed(&'static str),
    #[error("invalid secret key: {0}")]
    SecretKey(&'static str),
}

pub type Result<T> = std::result::Result<T, CryptoError>;

/// Argon2id parameters for the password leg of the 2SKD. Serialized into the
/// server's opaque `kdf_params` so any enrolled device re-derives identically.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct KdfParams {
    /// Memory cost, KiB (`m`). Default 65536 = 64 MiB.
    #[serde(rename = "m")]
    pub m_cost_kib: u32,
    /// Time cost / iterations (`t`).
    #[serde(rename = "t")]
    pub t_cost: u32,
    /// Parallelism / lanes (`p`).
    #[serde(rename = "p")]
    pub p_cost: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            m_cost_kib: 65536,
            t_cost: 3,
            p_cost: 4,
        }
    }
}

impl KdfParams {
    fn to_json(self) -> Result<String> {
        serde_json::to_string(&self).map_err(|_| CryptoError::Kdf)
    }

    fn from_json(s: &str) -> Result<Self> {
        serde_json::from_str(s).map_err(|_| CryptoError::Malformed("kdf_params"))
    }
}

/// The user's root master key (32 bytes). Zeroized on drop.
#[derive(Clone, Zeroize, zeroize::ZeroizeOnDrop)]
pub struct MasterKey([u8; KEY_LEN]);

impl MasterKey {
    fn random() -> Self {
        let mut bytes = [0u8; KEY_LEN];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
        Self(bytes)
    }

    /// Reconstruct from raw bytes (e.g. rehydrating from the OS keychain).
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The raw key bytes (for caching in the OS keychain / re-wrapping).
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl std::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MasterKey(<redacted>)")
    }
}

/// The wrapped key bundle the server stores (ciphertext + public keys only).
/// Maps 1:1 onto the gRPC `KeyMaterial` message (wired in a later phase).
#[derive(Debug, Clone)]
pub struct KeyBundle {
    pub x25519_public: Vec<u8>,
    pub ed25519_public: Vec<u8>,
    pub x25519_private_wrapped: Vec<u8>,
    pub ed25519_private_wrapped: Vec<u8>,
    pub master_key_wrapped: Vec<u8>,
    pub kdf_salt: Vec<u8>,
    pub kdf_params: String,
}

/// The unlocked secrets a signed-in device holds in memory (and caches in the
/// OS keychain). All private material is zeroized on drop.
pub struct UnlockedIdentity {
    pub master_key: MasterKey,
    /// User X25519 static secret (receives wrapped content keys).
    pub user_x25519_secret: Zeroizing<[u8; KEY_LEN]>,
    /// User Ed25519 signing seed (signs content).
    pub user_ed25519_secret: Zeroizing<[u8; KEY_LEN]>,
}

/// Everything produced by first-owner bootstrap: the ciphertext bundle for the
/// server, the Secret Key for the user to write down, and the unlocked secrets
/// the bootstrapping device keeps.
pub struct BootstrapOutput {
    pub bundle: KeyBundle,
    pub secret_key: SecretKey,
    pub identity: UnlockedIdentity,
}

/// A per-device X25519 keypair. The public key is registered server-side; the
/// secret stays in this device's OS keychain (and is the Slice-2 propagation
/// target).
pub struct DeviceKeypair {
    pub public: [u8; KEY_LEN],
    pub secret: Zeroizing<[u8; KEY_LEN]>,
}

/// Generate a fresh device X25519 keypair.
pub fn generate_device_keypair() -> DeviceKeypair {
    let secret = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
    let public = x25519_dalek::PublicKey::from(&secret);
    DeviceKeypair {
        public: public.to_bytes(),
        secret: Zeroizing::new(secret.to_bytes()),
    }
}

/// Bootstrap a brand-new owner identity with the default KDF params.
pub fn bootstrap_identity(password: &str) -> Result<BootstrapOutput> {
    bootstrap_identity_with_params(password, KdfParams::default())
}

/// Bootstrap with explicit KDF params (tests / param upgrades). Generates the
/// Secret Key, master key, and user keypairs; wraps everything; returns both the
/// server bundle and the unlocked secrets.
pub fn bootstrap_identity_with_params(
    password: &str,
    params: KdfParams,
) -> Result<BootstrapOutput> {
    let mut rng = rand::rngs::OsRng;

    let secret_key = SecretKey::generate();
    let master_key = MasterKey::random();

    let user_x_secret = x25519_dalek::StaticSecret::random_from_rng(rng);
    let user_x_public = x25519_dalek::PublicKey::from(&user_x_secret);
    let user_ed = ed25519_dalek::SigningKey::generate(&mut rng);
    let user_ed_public = user_ed.verifying_key();

    let mut salt = [0u8; SALT_LEN];
    rand::RngCore::fill_bytes(&mut rng, &mut salt);

    let kek = derive_kek(password.as_bytes(), &secret_key, &salt, params)?;
    let master_key_wrapped = seal(&kek, master_key.as_bytes())?;

    // Private keys wrapped under the master key.
    let x_secret_bytes = Zeroizing::new(user_x_secret.to_bytes());
    let ed_secret_bytes = Zeroizing::new(user_ed.to_bytes());
    let x25519_private_wrapped = seal(master_key.as_bytes(), x_secret_bytes.as_ref())?;
    let ed25519_private_wrapped = seal(master_key.as_bytes(), ed_secret_bytes.as_ref())?;

    let bundle = KeyBundle {
        x25519_public: user_x_public.to_bytes().to_vec(),
        ed25519_public: user_ed_public.to_bytes().to_vec(),
        x25519_private_wrapped,
        ed25519_private_wrapped,
        master_key_wrapped,
        kdf_salt: salt.to_vec(),
        kdf_params: params.to_json()?,
    };

    Ok(BootstrapOutput {
        identity: UnlockedIdentity {
            master_key,
            user_x25519_secret: x_secret_bytes,
            user_ed25519_secret: ed_secret_bytes,
        },
        bundle,
        secret_key,
    })
}

/// Unlock a stored bundle with the password + Secret Key — the login /
/// re-enroll path. Returns the master key and the user's private keys, or
/// [`CryptoError::Decrypt`] if either factor is wrong.
pub fn unlock_identity(
    bundle: &KeyBundle,
    password: &str,
    secret_key: &SecretKey,
) -> Result<UnlockedIdentity> {
    let params = KdfParams::from_json(&bundle.kdf_params)?;
    let kek = derive_kek(password.as_bytes(), secret_key, &bundle.kdf_salt, params)?;
    let master_key = MasterKey::from_bytes(open_array(&kek, &bundle.master_key_wrapped)?);

    let user_x25519_secret = Zeroizing::new(open_array(master_key.as_bytes(), &bundle.x25519_private_wrapped)?);
    let user_ed25519_secret = Zeroizing::new(open_array(master_key.as_bytes(), &bundle.ed25519_private_wrapped)?);

    Ok(UnlockedIdentity {
        master_key,
        user_x25519_secret,
        user_ed25519_secret,
    })
}

/// The 2SKD KEK: `Argon2id(password, salt) XOR HKDF-SHA256(secret_key, salt)`.
fn derive_kek(
    password: &[u8],
    secret_key: &SecretKey,
    salt: &[u8],
    params: KdfParams,
) -> Result<[u8; KEY_LEN]> {
    let mut password_leg = argon2_leg(password, salt, params)?;
    let mut secretkey_leg = secret_key_leg(secret_key, salt)?;
    let mut kek = [0u8; KEY_LEN];
    for (dst, (a, b)) in kek
        .iter_mut()
        .zip(password_leg.iter().zip(secretkey_leg.iter()))
    {
        *dst = a ^ b;
    }
    password_leg.zeroize();
    secretkey_leg.zeroize();
    Ok(kek)
}

fn argon2_leg(password: &[u8], salt: &[u8], params: KdfParams) -> Result<[u8; KEY_LEN]> {
    let p = argon2::Params::new(params.m_cost_kib, params.t_cost, params.p_cost, Some(KEY_LEN))
        .map_err(|_| CryptoError::Kdf)?;
    let argon = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, p);
    let mut out = [0u8; KEY_LEN];
    argon
        .hash_password_into(password, salt, &mut out)
        .map_err(|_| CryptoError::Kdf)?;
    Ok(out)
}

fn secret_key_leg(secret_key: &SecretKey, salt: &[u8]) -> Result<[u8; KEY_LEN]> {
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(salt), secret_key.as_bytes());
    let mut out = [0u8; KEY_LEN];
    hk.expand(HKDF_INFO, &mut out).map_err(|_| CryptoError::Kdf)?;
    Ok(out)
}

/// XChaCha20-Poly1305 seal: `nonce(24) || ciphertext+tag`. Matches the server's
/// `auth::secretbox` framing. Fallible only in theory (plaintext-length
/// overflow), but propagated rather than swallowed.
fn seal(key: &[u8; KEY_LEN], plaintext: &[u8]) -> Result<Vec<u8>> {
    use chacha20poly1305::{
        Key, XChaCha20Poly1305,
        aead::{Aead, AeadCore, KeyInit, OsRng},
    };
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| CryptoError::Malformed("plaintext too large to encrypt"))?;
    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(nonce.as_slice());
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

fn open(key: &[u8; KEY_LEN], blob: &[u8]) -> Result<Vec<u8>> {
    use chacha20poly1305::{
        Key, XChaCha20Poly1305, XNonce,
        aead::{Aead, KeyInit},
    };
    if blob.len() < NONCE_LEN {
        return Err(CryptoError::Decrypt);
    }
    let (nonce, ciphertext) = blob.split_at(NONCE_LEN);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(XNonce::from_slice(nonce), ciphertext)
        .map_err(|_| CryptoError::Decrypt)
}

/// [`open`] a blob that must decrypt to exactly 32 bytes (a key).
fn open_array(key: &[u8; KEY_LEN], blob: &[u8]) -> Result<[u8; KEY_LEN]> {
    open(key, blob)?
        .try_into()
        .map_err(|_| CryptoError::Malformed("expected a 32-byte key"))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    // Fast params keep the Argon2 legs cheap in tests (the construction, not the
    // cost factor, is what's under test).
    fn fast() -> KdfParams {
        KdfParams {
            m_cost_kib: 64,
            t_cost: 1,
            p_cost: 1,
        }
    }

    #[test]
    fn kdf_params_json_shape_round_trips() {
        let json = KdfParams::default().to_json().unwrap();
        assert_eq!(json, r#"{"m":65536,"t":3,"p":4}"#);
        assert_eq!(KdfParams::from_json(&json).unwrap(), KdfParams::default());
    }

    #[test]
    fn kek_is_deterministic() {
        let sk = SecretKey::generate();
        let salt = [9u8; SALT_LEN];
        let a = derive_kek(b"pw", &sk, &salt, fast()).unwrap();
        let b = derive_kek(b"pw", &sk, &salt, fast()).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn kek_depends_on_every_input() {
        let sk = SecretKey::generate();
        let other_sk = SecretKey::generate();
        let salt = [9u8; SALT_LEN];
        let base = derive_kek(b"pw", &sk, &salt, fast()).unwrap();
        assert_ne!(base, derive_kek(b"PW", &sk, &salt, fast()).unwrap(), "password");
        assert_ne!(base, derive_kek(b"pw", &other_sk, &salt, fast()).unwrap(), "secret key");
        assert_ne!(base, derive_kek(b"pw", &sk, &[1u8; SALT_LEN], fast()).unwrap(), "salt");
    }

    #[test]
    fn seal_open_round_trips_and_detects_tampering() {
        let key = [3u8; KEY_LEN];
        let blob = seal(&key, b"secret payload").unwrap();
        assert_eq!(open(&key, &blob).unwrap(), b"secret payload");

        // Wrong key.
        assert!(open(&[4u8; KEY_LEN], &blob).is_err());
        // Tampered ciphertext.
        let mut bad = blob.clone();
        let last = bad.len() - 1;
        bad[last] ^= 0x01;
        assert!(open(&key, &bad).is_err());
        // Truncated.
        assert!(open(&key, b"short").is_err());
    }

    #[test]
    fn bootstrap_then_unlock_recovers_master_key_and_private_keys() {
        let out = bootstrap_identity_with_params("hunter2", fast()).unwrap();
        let unlocked = unlock_identity(&out.bundle, "hunter2", &out.secret_key).unwrap();

        assert_eq!(unlocked.master_key.as_bytes(), out.identity.master_key.as_bytes());

        // The recovered X25519 secret re-derives the bundle's public key.
        let x = x25519_dalek::StaticSecret::from(*unlocked.user_x25519_secret);
        assert_eq!(
            x25519_dalek::PublicKey::from(&x).to_bytes().to_vec(),
            out.bundle.x25519_public
        );
        // The recovered Ed25519 seed re-derives the bundle's verifying key.
        let ed = ed25519_dalek::SigningKey::from_bytes(&unlocked.user_ed25519_secret);
        assert_eq!(
            ed.verifying_key().to_bytes().to_vec(),
            out.bundle.ed25519_public
        );
    }

    #[test]
    fn unlock_fails_with_wrong_password_or_secret_key() {
        let out = bootstrap_identity_with_params("right", fast()).unwrap();
        assert!(matches!(
            unlock_identity(&out.bundle, "wrong", &out.secret_key),
            Err(CryptoError::Decrypt)
        ));
        assert!(matches!(
            unlock_identity(&out.bundle, "right", &SecretKey::generate()),
            Err(CryptoError::Decrypt)
        ));
    }

    #[test]
    fn bundle_has_expected_field_shapes() {
        let out = bootstrap_identity_with_params("pw", fast()).unwrap();
        assert_eq!(out.bundle.x25519_public.len(), 32);
        assert_eq!(out.bundle.ed25519_public.len(), 32);
        assert_eq!(out.bundle.kdf_salt.len(), SALT_LEN);
        // wrapped = nonce(24) + 32 + tag(16) = 72.
        assert_eq!(out.bundle.master_key_wrapped.len(), NONCE_LEN + 32 + 16);
        assert!(KdfParams::from_json(&out.bundle.kdf_params).is_ok());
    }

    #[test]
    fn each_bootstrap_is_unique() {
        let a = bootstrap_identity_with_params("pw", fast()).unwrap();
        let b = bootstrap_identity_with_params("pw", fast()).unwrap();
        assert_ne!(a.bundle.master_key_wrapped, b.bundle.master_key_wrapped);
        assert_ne!(a.secret_key.as_bytes(), b.secret_key.as_bytes());
        assert_ne!(a.bundle.kdf_salt, b.bundle.kdf_salt);
    }

    #[test]
    fn device_keypair_public_matches_secret() {
        let kp = generate_device_keypair();
        let secret = x25519_dalek::StaticSecret::from(*kp.secret);
        assert_eq!(x25519_dalek::PublicKey::from(&secret).to_bytes(), kp.public);
    }
}
