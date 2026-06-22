//! Per-OS-user persistent storage for this device's enrollment secrets + the
//! server profile, so it stays enrolled across launches. Abstracted behind
//! [`SecretStore`]: production uses the OS keychain ([`OsKeychain`]); tests use
//! [`MemoryStore`]. See `design/hub.md` ("Stored in the OS keychain (this
//! device, this OS user): the unwrapped master key, the cached Secret Key, the
//! device private key, the session token, the server profile").

use serde::{Deserialize, Serialize};

use crate::crypto::{MasterKey, SecretKey};

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("keychain backend error")]
    Backend,
    #[error("a stored value is malformed")]
    Malformed,
}

pub type Result<T> = std::result::Result<T, StoreError>;

/// A flat `key → bytes` secret store — one OS-keychain entry per key.
pub trait SecretStore {
    fn set(&self, key: &str, value: &[u8]) -> Result<()>;
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>>;
    fn delete(&self, key: &str) -> Result<()>;
}

/// Lets a boxed, type-erased store be used where a `SecretStore` is expected
/// (so [`Vault`] can hold either the OS keychain or an in-memory store chosen at
/// runtime — e.g. the high-level client picking prod vs. test storage).
impl SecretStore for Box<dyn SecretStore + Send + Sync> {
    fn set(&self, key: &str, value: &[u8]) -> Result<()> {
        (**self).set(key, value)
    }
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        (**self).get(key)
    }
    fn delete(&self, key: &str) -> Result<()> {
        (**self).delete(key)
    }
}

// Entry keys (one keychain credential each).
const MASTER_KEY: &str = "master_key";
const SECRET_KEY: &str = "secret_key";
const DEVICE_SECRET: &str = "device_secret";
const SESSION_TOKEN: &str = "session_token";
const SERVER_PROFILE: &str = "server_profile";

/// The persisted record of an enrolled server: where to reach it + the pinned
/// identity to re-verify on every reconnect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerProfile {
    /// Ordered discovery endpoints (`host:port`), tried in order — the LAN / VPN
    /// / public failover from the design.
    pub endpoints: Vec<String>,
    /// The TOFU-pinned server identity public key (Ed25519).
    pub identity_public: [u8; 32],
    /// The signed-in user's id on this server.
    pub user_id: String,
}

/// Typed accessors over a [`SecretStore`] for this device's enrollment state.
/// Secrets round-trip as raw bytes; the server profile as JSON.
pub struct Vault<S: SecretStore> {
    store: S,
}

impl<S: SecretStore> Vault<S> {
    pub fn new(store: S) -> Self {
        Self { store }
    }

    pub fn set_session_token(&self, token: &str) -> Result<()> {
        self.store.set(SESSION_TOKEN, token.as_bytes())
    }

    pub fn session_token(&self) -> Result<Option<String>> {
        match self.store.get(SESSION_TOKEN)? {
            Some(bytes) => Ok(Some(String::from_utf8(bytes).map_err(|_| StoreError::Malformed)?)),
            None => Ok(None),
        }
    }

    pub fn set_master_key(&self, key: &MasterKey) -> Result<()> {
        self.store.set(MASTER_KEY, key.as_bytes())
    }

    pub fn master_key(&self) -> Result<Option<MasterKey>> {
        match self.store.get(MASTER_KEY)? {
            Some(bytes) => {
                let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| StoreError::Malformed)?;
                Ok(Some(MasterKey::from_bytes(arr)))
            }
            None => Ok(None),
        }
    }

    pub fn set_secret_key(&self, secret_key: &SecretKey) -> Result<()> {
        self.store.set(SECRET_KEY, secret_key.as_bytes())
    }

    pub fn secret_key(&self) -> Result<Option<SecretKey>> {
        match self.store.get(SECRET_KEY)? {
            Some(bytes) => Ok(Some(SecretKey::from_bytes(&bytes).map_err(|_| StoreError::Malformed)?)),
            None => Ok(None),
        }
    }

    pub fn set_device_secret(&self, secret: &[u8; 32]) -> Result<()> {
        self.store.set(DEVICE_SECRET, secret)
    }

    pub fn device_secret(&self) -> Result<Option<[u8; 32]>> {
        match self.store.get(DEVICE_SECRET)? {
            Some(bytes) => Ok(Some(bytes.as_slice().try_into().map_err(|_| StoreError::Malformed)?)),
            None => Ok(None),
        }
    }

    pub fn set_server_profile(&self, profile: &ServerProfile) -> Result<()> {
        let json = serde_json::to_vec(profile).map_err(|_| StoreError::Malformed)?;
        self.store.set(SERVER_PROFILE, &json)
    }

    pub fn server_profile(&self) -> Result<Option<ServerProfile>> {
        match self.store.get(SERVER_PROFILE)? {
            Some(bytes) => Ok(Some(serde_json::from_slice(&bytes).map_err(|_| StoreError::Malformed)?)),
            None => Ok(None),
        }
    }

    /// Wipe all stored secrets + the profile (forget-this-server / device revoke).
    pub fn clear(&self) -> Result<()> {
        for key in [MASTER_KEY, SECRET_KEY, DEVICE_SECRET, SESSION_TOKEN, SERVER_PROFILE] {
            self.store.delete(key)?;
        }
        Ok(())
    }

    /// Clear just the active session: the session token + the unwrapped master
    /// key. Keeps the Secret Key, device key, and server profile, so the device
    /// stays enrolled and a return needs only the password ([`clear`](Self::clear)
    /// is the full forget-this-server wipe).
    pub fn clear_session(&self) -> Result<()> {
        self.store.delete(SESSION_TOKEN)?;
        self.store.delete(MASTER_KEY)?;
        Ok(())
    }
}

/// The production [`SecretStore`]: the per-OS-user OS keychain (Windows
/// Credential Manager / macOS Keychain / Linux secret-service, via `keyring`).
/// Entries are namespaced by a service name (e.g. `"sylva-client"`).
pub struct OsKeychain {
    service: String,
}

impl OsKeychain {
    pub fn new(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
        }
    }

    fn entry(&self, key: &str) -> Result<keyring::Entry> {
        keyring::Entry::new(&self.service, key).map_err(|_| StoreError::Backend)
    }
}

impl SecretStore for OsKeychain {
    fn set(&self, key: &str, value: &[u8]) -> Result<()> {
        self.entry(key)?
            .set_secret(value)
            .map_err(|_| StoreError::Backend)
    }

    fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        match self.entry(key)?.get_secret() {
            Ok(value) => Ok(Some(value)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(_) => Err(StoreError::Backend),
        }
    }

    fn delete(&self, key: &str) -> Result<()> {
        match self.entry(key)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(_) => Err(StoreError::Backend),
        }
    }
}

/// An in-memory [`SecretStore`] for tests + non-persistent use.
#[derive(Default)]
pub struct MemoryStore {
    map: std::sync::Mutex<std::collections::HashMap<String, Vec<u8>>>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, std::collections::HashMap<String, Vec<u8>>> {
        self.map.lock().unwrap_or_else(|poison| poison.into_inner())
    }
}

impl SecretStore for MemoryStore {
    fn set(&self, key: &str, value: &[u8]) -> Result<()> {
        self.lock().insert(key.to_string(), value.to_vec());
        Ok(())
    }

    fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.lock().get(key).cloned())
    }

    fn delete(&self, key: &str) -> Result<()> {
        self.lock().remove(key);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use crate::crypto;

    fn fast() -> crypto::KdfParams {
        crypto::KdfParams {
            m_cost_kib: 64,
            t_cost: 1,
            p_cost: 1,
        }
    }

    #[test]
    fn vault_round_trips_all_items() {
        let vault = Vault::new(MemoryStore::new());

        // Nothing stored yet.
        assert!(vault.master_key().unwrap().is_none());
        assert!(vault.session_token().unwrap().is_none());
        assert!(vault.server_profile().unwrap().is_none());

        let boot = crypto::bootstrap_identity_with_params("pw", fast()).unwrap();
        let device = crypto::generate_device_keypair();
        let profile = ServerProfile {
            endpoints: vec!["192.168.1.5:8443".to_string(), "vpn.example:8443".to_string()],
            identity_public: [9u8; 32],
            user_id: "u-1".to_string(),
        };

        vault.set_master_key(&boot.identity.master_key).unwrap();
        vault.set_secret_key(&boot.secret_key).unwrap();
        vault.set_device_secret(&device.secret).unwrap();
        vault.set_session_token("tok-xyz").unwrap();
        vault.set_server_profile(&profile).unwrap();

        assert_eq!(
            vault.master_key().unwrap().unwrap().as_bytes(),
            boot.identity.master_key.as_bytes()
        );
        assert_eq!(
            vault.secret_key().unwrap().unwrap().as_bytes(),
            boot.secret_key.as_bytes()
        );
        assert_eq!(vault.device_secret().unwrap().unwrap(), *device.secret);
        assert_eq!(vault.session_token().unwrap().unwrap(), "tok-xyz");
        assert_eq!(vault.server_profile().unwrap().unwrap(), profile);
    }

    #[test]
    fn clear_wipes_everything() {
        let vault = Vault::new(MemoryStore::new());
        vault.set_session_token("t").unwrap();
        vault.set_device_secret(&[1u8; 32]).unwrap();
        vault.clear().unwrap();
        assert!(vault.session_token().unwrap().is_none());
        assert!(vault.device_secret().unwrap().is_none());
    }

    #[test]
    fn clear_session_keeps_the_device_enrolled() {
        let vault = Vault::new(MemoryStore::new());
        let boot = crypto::bootstrap_identity_with_params("pw", fast()).unwrap();
        vault.set_master_key(&boot.identity.master_key).unwrap();
        vault.set_secret_key(&boot.secret_key).unwrap();
        vault.set_session_token("t").unwrap();
        vault.set_device_secret(&[1u8; 32]).unwrap();
        vault
            .set_server_profile(&ServerProfile {
                endpoints: vec!["h:1".to_string()],
                identity_public: [9u8; 32],
                user_id: "u".to_string(),
            })
            .unwrap();

        vault.clear_session().unwrap();

        // Session is gone...
        assert!(vault.session_token().unwrap().is_none());
        assert!(vault.master_key().unwrap().is_none());
        // ...but the device stays enrolled (return needs only the password).
        assert!(vault.secret_key().unwrap().is_some());
        assert!(vault.device_secret().unwrap().is_some());
        assert!(vault.server_profile().unwrap().is_some());
    }

    #[test]
    fn malformed_value_is_an_error() {
        let store = MemoryStore::new();
        store.set("master_key", b"too short").unwrap();
        let vault = Vault::new(store);
        assert!(matches!(vault.master_key(), Err(StoreError::Malformed)));
    }

    #[test]
    #[ignore = "writes to the real OS keychain; run manually with --ignored"]
    fn os_keychain_round_trips() {
        let store = OsKeychain::new("sylva-sdk-test-delete-me");
        store.set("smoke", b"value").unwrap();
        assert_eq!(store.get("smoke").unwrap().as_deref(), Some(b"value".as_slice()));
        store.delete("smoke").unwrap();
        assert!(store.get("smoke").unwrap().is_none());
    }
}
