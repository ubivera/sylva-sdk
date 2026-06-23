//! [`Client`] — the high-level client facade the native shell drives. A
//! single stateful handle that composes the [transport](crate::transport),
//! [flows](crate::flows), and [storage](crate::storage) into the operations the
//! Connect → Create-owner / Sign-in → Name-device → My-devices screens need.
//!
//! Methods are `async` here (cleanly testable). The `uniffi` boundary + a thin
//! blocking wrapper that exposes a synchronous C# API land in 3.6b — see
//! `docs/dev/hub-build-spec.md`.

use tokio::sync::Mutex;
use tonic::transport::Channel;

use crate::crypto::{self, KdfParams, MasterKey, SecretKey, UnlockedIdentity};
use crate::flows::{self, NewOwner};
use crate::proto::account::v1 as pb;
use crate::storage::{OsKeychain, SecretStore, ServerProfile, Vault};
use crate::transport::{self, AccountSession, ConnectError, TrustDecision, VerifiedServer};

/// Errors surfaced to the shell — deliberately coarse (details go to logs, not
/// the UI). Flat variants so the `uniffi::Error` mapping in 3.6b is clean.
#[derive(Debug, thiserror::Error)]
#[cfg_attr(feature = "ffi", derive(uniffi::Error))]
pub enum ClientError {
    #[error("not connected to a server")]
    NotConnected,
    #[error("not signed in")]
    NotSignedIn,
    #[error("could not reach the server")]
    Connect,
    #[error("the server identity does not match the pinned key (possible MITM or reinstall)")]
    IdentityMismatch,
    #[error("wrong password or Secret Key")]
    Crypto,
    #[error("a Secret Key is required to sign in on this device")]
    SecretKeyRequired,
    #[error("secure storage error")]
    Storage,
    #[error("server error")]
    Server,
}

type Result<T> = std::result::Result<T, ClientError>;

/// Whether this is the first time we've seen a server (pin it) or it matches the
/// stored pin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum TrustStatus {
    FirstContact,
    Trusted,
}

/// What [`Client::connect`] learned, for the Connect screen's confirm step.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct ConnectInfo {
    pub server_name: String,
    /// Hex of the server identity public key (the shell formats it for display).
    pub identity_fingerprint: String,
    pub grpc_port: u16,
    pub trust: TrustStatus,
}

/// The result of creating the first owner. `secret_key` MUST be shown to the
/// user once for write-down — it is not recoverable.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct Enrollment {
    pub user_id: String,
    pub secret_key: String,
}

/// A device row for "My devices".
#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct DeviceInfo {
    pub device_id: String,
    pub label: String,
    pub platform: String,
    pub created_at: String,
    pub revoked: bool,
}

/// The signed-in user's profile, for the account-settings screen.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct Profile {
    pub user_id: String,
    pub email: String,
    pub display_name: String,
    /// `owner` | `admin` | `member`.
    pub instance_role: String,
}

/// The outcome of a sign-in attempt.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum SignInOutcome {
    Success { user_id: String },
    /// The account has a second factor; the shell must complete MFA (not yet
    /// supported by this client — slice 1).
    MfaRequired,
}

/// In-memory connection + session state. All `Option` so `Default` is derivable
/// despite the inner types not being `Default`.
#[derive(Default)]
struct Inner {
    channel: Option<Channel>,
    verified: Option<VerifiedServer>,
    endpoints: Vec<String>,
    session: Option<AccountSession>,
    identity: Option<UnlockedIdentity>,
    secret_key: Option<SecretKey>,
}

/// The stateful client handle the shell holds for the lifetime of the app.
pub struct Client {
    inner: Mutex<Inner>,
    vault: Vault<Box<dyn SecretStore + Send + Sync>>,
}

impl Client {
    /// Production constructor: secrets live in the OS keychain under `service`
    /// (e.g. `"sylva-client"`), scoped to the current OS user.
    pub fn new(service: impl Into<String>) -> Self {
        Self::with_store(Box::new(OsKeychain::new(service)))
    }

    /// Construct over a caller-chosen secret store (tests pass a `MemoryStore`).
    pub fn with_store(store: Box<dyn SecretStore + Send + Sync>) -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
            vault: Vault::new(store),
        }
    }

    /// Discover + verify a server, apply the TOFU pin check, and connect its gRPC
    /// port. `host` + `discovery_port` are what the user entered. On first
    /// contact the returned `trust` is `FirstContact` (the shell shows the
    /// fingerprint to confirm); a changed identity is [`ClientError::IdentityMismatch`].
    pub async fn connect(&self, host: &str, discovery_port: u16) -> Result<ConnectInfo> {
        let pinned = self
            .vault
            .server_profile()
            .map_err(|_| ClientError::Storage)?
            .map(|p| p.identity_public);
        let (channel, verified, decision) =
            transport::discover_and_connect(host, discovery_port, pinned.as_ref())
                .await
                .map_err(map_connect_err)?;

        let info = ConnectInfo {
            server_name: verified.name.clone(),
            identity_fingerprint: hex(&verified.identity_public),
            grpc_port: verified.grpc_port,
            trust: match decision {
                TrustDecision::FirstContact => TrustStatus::FirstContact,
                _ => TrustStatus::Trusted,
            },
        };

        let mut inner = self.inner.lock().await;
        inner.endpoints = vec![format!("{host}:{discovery_port}")];
        inner.verified = Some(verified);
        inner.channel = Some(channel);
        Ok(info)
    }

    /// Create the first owner: generate all key material client-side, enroll, and
    /// cache everything in the keychain. Returns the user id + the Secret Key to
    /// display once.
    pub async fn create_owner(
        &self,
        email: &str,
        display_name: &str,
        password: &str,
        device_label: &str,
    ) -> Result<Enrollment> {
        let mut inner = self.inner.lock().await;
        let channel = inner.channel.clone().ok_or(ClientError::NotConnected)?;
        let identity_public = inner
            .verified
            .as_ref()
            .ok_or(ClientError::NotConnected)?
            .identity_public;

        let enrolled = flows::enroll_new_owner(
            channel,
            NewOwner {
                email,
                display_name,
                password,
                device_label,
                platform: std::env::consts::OS,
                machine_label: device_label,
            },
        )
        .await
        .map_err(map_enroll_err)?;

        self.persist(ToCache {
            identity_public,
            user_id: &enrolled.user_id,
            token: enrolled.account.token(),
            master_key: &enrolled.identity.master_key,
            secret_key: &enrolled.secret_key,
            device_secret: Some(&enrolled.device_secret),
            endpoints: inner.endpoints.clone(),
        })?;

        let result = Enrollment {
            user_id: enrolled.user_id.clone(),
            secret_key: enrolled.secret_key.display(),
        };
        inner.session = Some(enrolled.account);
        inner.identity = Some(enrolled.identity);
        inner.secret_key = Some(enrolled.secret_key);
        Ok(result)
    }

    /// Sign in: authenticate, fetch the wrapped key material, and unlock it with
    /// the password + Secret Key. `secret_key` is the user-entered value on a new
    /// device, or `None` to use the one cached in the keychain on a returning
    /// device.
    pub async fn sign_in(
        &self,
        email: &str,
        password: &str,
        secret_key: Option<&str>,
    ) -> Result<SignInOutcome> {
        let resolved = match secret_key {
            Some(s) => SecretKey::parse(s).map_err(|_| ClientError::Crypto)?,
            None => self
                .vault
                .secret_key()
                .map_err(|_| ClientError::Storage)?
                .ok_or(ClientError::SecretKeyRequired)?,
        };

        let mut inner = self.inner.lock().await;
        let channel = inner.channel.clone().ok_or(ClientError::NotConnected)?;
        let identity_public = inner
            .verified
            .as_ref()
            .ok_or(ClientError::NotConnected)?
            .identity_public;

        match flows::login(channel, email, password, &resolved).await {
            Ok(logged_in) => {
                self.persist(ToCache {
                    identity_public,
                    user_id: &logged_in.user_id,
                    token: logged_in.account.token(),
                    master_key: &logged_in.identity.master_key,
                    secret_key: &resolved,
                    device_secret: None,
                    endpoints: inner.endpoints.clone(),
                })?;
                let outcome = SignInOutcome::Success {
                    user_id: logged_in.user_id.clone(),
                };
                inner.session = Some(logged_in.account);
                inner.identity = Some(logged_in.identity);
                inner.secret_key = Some(resolved);
                Ok(outcome)
            }
            Err(flows::EnrollError::MfaRequired) => Ok(SignInOutcome::MfaRequired),
            Err(flows::EnrollError::Crypto(_)) => Err(ClientError::Crypto),
            Err(other) => Err(map_enroll_err(other)),
        }
    }

    /// Enroll *this* device into the signed-in account (the "Name this device"
    /// step when joining an existing account from a new machine).
    pub async fn enroll_this_device(&self, label: &str) -> Result<DeviceInfo> {
        let mut inner = self.inner.lock().await;
        let session = inner.session.as_mut().ok_or(ClientError::NotSignedIn)?;
        let device = crypto::generate_device_keypair();
        let enrolled = session
            .register_device(pb::DeviceEnrollment {
                device_label: label.to_string(),
                platform: std::env::consts::OS.to_string(),
                device_public_key: device.public.to_vec(),
                machine_label: label.to_string(),
            })
            .await
            .map_err(|_| ClientError::Server)?;
        self.vault
            .set_device_secret(&device.secret)
            .map_err(|_| ClientError::Storage)?;
        Ok(device_info(enrolled))
    }

    /// This account's active devices.
    pub async fn list_devices(&self) -> Result<Vec<DeviceInfo>> {
        let mut inner = self.inner.lock().await;
        let session = inner.session.as_mut().ok_or(ClientError::NotSignedIn)?;
        let devices = session.list_devices().await.map_err(|_| ClientError::Server)?;
        Ok(devices.into_iter().map(device_info).collect())
    }

    /// Revoke one of this account's devices.
    pub async fn revoke_device(&self, device_id: &str) -> Result<()> {
        let mut inner = self.inner.lock().await;
        let session = inner.session.as_mut().ok_or(ClientError::NotSignedIn)?;
        session
            .revoke_device(device_id.to_string())
            .await
            .map_err(|_| ClientError::Server)?;
        Ok(())
    }

    /// This account's profile (for the account-settings screen).
    pub async fn get_profile(&self) -> Result<Profile> {
        let mut inner = self.inner.lock().await;
        let session = inner.session.as_mut().ok_or(ClientError::NotSignedIn)?;
        let profile = session.get_profile().await.map_err(|_| ClientError::Server)?;
        Ok(profile_info(profile))
    }

    /// Change this account's display name; returns the updated profile.
    pub async fn update_display_name(&self, display_name: &str) -> Result<Profile> {
        let mut inner = self.inner.lock().await;
        let session = inner.session.as_mut().ok_or(ClientError::NotSignedIn)?;
        let profile = session
            .update_display_name(display_name.to_string())
            .await
            .map_err(|_| ClientError::Server)?;
        Ok(profile_info(profile))
    }

    /// Change this account's email (re-auth: current password); returns the
    /// updated profile.
    pub async fn update_email(&self, new_email: &str, current_password: &str) -> Result<Profile> {
        let mut inner = self.inner.lock().await;
        let session = inner.session.as_mut().ok_or(ClientError::NotSignedIn)?;
        let profile = session
            .update_email(new_email.to_string(), current_password.to_string())
            .await
            .map_err(|_| ClientError::Server)?;
        Ok(profile_info(profile))
    }

    /// Change this account's password. Fetches the current wrapped bundle,
    /// unlocks it with the *current* password + the cached Secret Key (this is
    /// the local check of the old password), re-wraps the master key under the
    /// new password, and hands the server the new verifier + re-wrap. The master
    /// key and Secret Key are unchanged, so nothing in the vault needs rewriting.
    pub async fn change_password(&self, current_password: &str, new_password: &str) -> Result<()> {
        // The cached Secret Key is the unchanged second 2SKD factor.
        let secret_key = self
            .vault
            .secret_key()
            .map_err(|_| ClientError::Storage)?
            .ok_or(ClientError::SecretKeyRequired)?;

        let mut inner = self.inner.lock().await;
        let session = inner.session.as_mut().ok_or(ClientError::NotSignedIn)?;

        // Fetch the current bundle and unlock with the *current* password — this
        // verifies the old password locally (wrong password → Crypto).
        let material = session.key_material().await.map_err(|_| ClientError::Server)?;
        let bundle = key_material_to_bundle(material);
        let unlocked = crypto::unlock_identity(&bundle, current_password, &secret_key)
            .map_err(|_| ClientError::Crypto)?;

        // Re-wrap the (unchanged) master key under the new password.
        let rewrapped =
            crypto::rewrap_master_key(&unlocked.master_key, &secret_key, new_password, KdfParams::default())
                .map_err(|_| ClientError::Crypto)?;

        session
            .change_password(pb::ChangePasswordRequest {
                current_password: current_password.to_string(),
                new_password: new_password.to_string(),
                new_master_key_wrapped: rewrapped.master_key_wrapped,
                new_kdf_salt: rewrapped.kdf_salt,
                new_kdf_params: rewrapped.kdf_params,
            })
            .await
            .map_err(map_change_password_err)?;
        Ok(())
    }

    /// Sign out of the active session but keep this device enrolled: drops the
    /// in-memory state, the cached session token, and the unwrapped master key, so
    /// a return needs only the password (the Secret Key, device key, and pinned
    /// server stay cached). Use [`forget_server`](Self::forget_server) for a full wipe.
    pub async fn sign_out(&self) -> Result<()> {
        self.vault.clear_session().map_err(|_| ClientError::Storage)?;
        let mut inner = self.inner.lock().await;
        *inner = Inner::default();
        Ok(())
    }

    /// Forget this server entirely: wipe every cached secret + the pinned identity
    /// and drop in-memory state. The device must re-enroll (Secret Key) to return.
    /// This is also the reset for a changed server identity (clears the stale pin).
    pub async fn forget_server(&self) -> Result<()> {
        self.vault.clear().map_err(|_| ClientError::Storage)?;
        let mut inner = self.inner.lock().await;
        *inner = Inner::default();
        Ok(())
    }

    /// Auto-resume a prior session on launch. If this OS user's keychain holds an
    /// enrollment, reconnect to the pinned server and rebuild the authenticated
    /// session from the cached token — no password needed. Returns the user id, or
    /// `None` if there's nothing to resume or the server can't be reached/verified
    /// (the shell then shows Connect, which re-surfaces a real identity mismatch).
    ///
    /// ponytail: rebuilds only the gRPC session (enough for device management); the
    /// unlocked identity for data decryption is NOT restored — add when a screen
    /// needs to decrypt without a fresh sign-in. The resume path needs a live
    /// discovery server (cross-stack e2e / manual); the unit test covers the
    /// nothing-to-resume branch.
    pub async fn restore(&self) -> Result<Option<String>> {
        let profile = match self.vault.server_profile().map_err(|_| ClientError::Storage)? {
            Some(p) => p,
            None => return Ok(None),
        };
        let token = match self.vault.session_token().map_err(|_| ClientError::Storage)? {
            Some(t) => t,
            None => return Ok(None),
        };

        // The cached endpoint is "host:discovery_port" (see connect()).
        let endpoint = match profile.endpoints.first() {
            Some(e) => e.clone(),
            None => return Ok(None),
        };
        let Some((host, port)) = endpoint.rsplit_once(':') else {
            return Ok(None);
        };
        let Ok(discovery_port) = port.parse::<u16>() else {
            return Ok(None);
        };

        // Re-verify the pin on reconnect; any failure (offline, changed identity)
        // means we can't auto-resume — fall back to Connect rather than erroring.
        let (channel, verified, _decision) = match transport::discover_and_connect(
            host,
            discovery_port,
            Some(&profile.identity_public),
        )
        .await
        {
            Ok(t) => t,
            Err(_) => return Ok(None),
        };

        let mut inner = self.inner.lock().await;
        inner.endpoints = profile.endpoints.clone();
        inner.session = Some(AccountSession::new(channel.clone(), token));
        inner.verified = Some(verified);
        inner.channel = Some(channel);
        Ok(Some(profile.user_id))
    }

    /// Cache the post-auth state in the keychain.
    fn persist(&self, data: ToCache<'_>) -> Result<()> {
        self.vault.set_master_key(data.master_key).map_err(|_| ClientError::Storage)?;
        self.vault.set_secret_key(data.secret_key).map_err(|_| ClientError::Storage)?;
        self.vault.set_session_token(data.token).map_err(|_| ClientError::Storage)?;
        if let Some(secret) = data.device_secret {
            self.vault.set_device_secret(secret).map_err(|_| ClientError::Storage)?;
        }
        self.vault
            .set_server_profile(&ServerProfile {
                endpoints: data.endpoints,
                identity_public: data.identity_public,
                user_id: data.user_id.to_string(),
            })
            .map_err(|_| ClientError::Storage)?;
        Ok(())
    }
}

/// The post-auth state to cache (bundled to keep [`Client::persist`] tidy).
/// `device_secret` is `Some` only when the call enrolled a device (bootstrap).
struct ToCache<'a> {
    identity_public: [u8; 32],
    user_id: &'a str,
    token: &'a str,
    master_key: &'a MasterKey,
    secret_key: &'a SecretKey,
    device_secret: Option<&'a [u8; 32]>,
    endpoints: Vec<String>,
}

fn map_connect_err(err: ConnectError) -> ClientError {
    match err {
        ConnectError::IdentityMismatch => ClientError::IdentityMismatch,
        ConnectError::Discovery(_) | ConnectError::Connect(_) => ClientError::Connect,
    }
}

fn map_enroll_err(err: flows::EnrollError) -> ClientError {
    match err {
        flows::EnrollError::Crypto(_) => ClientError::Crypto,
        flows::EnrollError::Transport(_) | flows::EnrollError::EmptyLogin => ClientError::Server,
        flows::EnrollError::MfaRequired => ClientError::Server, // handled as an outcome in sign_in
    }
}

fn device_info(d: pb::Device) -> DeviceInfo {
    DeviceInfo {
        device_id: d.device_id,
        label: d.device_label,
        platform: d.platform,
        created_at: d.created_at,
        revoked: !d.revoked_at.is_empty(),
    }
}

fn profile_info(p: pb::Profile) -> Profile {
    Profile {
        user_id: p.user_id,
        email: p.email,
        display_name: p.display_name,
        instance_role: p.instance_role,
    }
}

/// The wire `KeyMaterial` → local `KeyBundle` (the facade's copy of the bridge in
/// [`crate::flows`]; only the `change_password` re-wrap needs it here).
fn key_material_to_bundle(m: pb::KeyMaterial) -> crypto::KeyBundle {
    crypto::KeyBundle {
        x25519_public: m.x25519_public,
        ed25519_public: m.ed25519_public,
        x25519_private_wrapped: m.x25519_private_wrapped,
        ed25519_private_wrapped: m.ed25519_private_wrapped,
        master_key_wrapped: m.master_key_wrapped,
        kdf_salt: m.kdf_salt,
        kdf_params: m.kdf_params,
    }
}

/// Map a `ChangePassword` RPC failure: the server rejects a wrong *current*
/// password with `unauthenticated` (surfaced as `Crypto`, consistent with the
/// local unlock failure); anything else is a coarse `Server` error.
fn map_change_password_err(err: crate::transport::ClientError) -> ClientError {
    match err {
        crate::transport::ClientError::Rpc(status)
            if status.code() == tonic::Code::Unauthenticated =>
        {
            ClientError::Crypto
        }
        _ => ClientError::Server,
    }
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use crate::proto::account::v1::account_server::{Account, AccountServer};
    use crate::storage::MemoryStore;
    use tonic::{Request, Response, Status};

    const TOKEN: &str = "tok-facade";

    fn require_token<T>(req: &Request<T>) -> std::result::Result<(), Status> {
        let ok = req
            .metadata()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .map(|v| v == format!("Bearer {TOKEN}"))
            .unwrap_or(false);
        if ok {
            Ok(())
        } else {
            Err(Status::unauthenticated("bad token"))
        }
    }

    /// Mock Account server serving a real wrapped bundle (so unlock succeeds) +
    /// canned devices.
    struct Mock {
        key_material: pb::KeyMaterial,
    }

    #[tonic::async_trait]
    impl Account for Mock {
        async fn bootstrap(
            &self,
            _req: Request<pb::BootstrapRequest>,
        ) -> std::result::Result<Response<pb::Session>, Status> {
            Ok(Response::new(pb::Session {
                token: TOKEN.to_string(),
                user_id: "u-1".to_string(),
                expires_at: "2030".to_string(),
            }))
        }
        async fn login(
            &self,
            _req: Request<pb::LoginRequest>,
        ) -> std::result::Result<Response<pb::LoginResponse>, Status> {
            Ok(Response::new(pb::LoginResponse {
                outcome: Some(pb::login_response::Outcome::Session(pb::Session {
                    token: TOKEN.to_string(),
                    user_id: "u-1".to_string(),
                    expires_at: "2030".to_string(),
                })),
            }))
        }
        async fn get_key_material(
            &self,
            req: Request<pb::Empty>,
        ) -> std::result::Result<Response<pb::GetKeyMaterialResponse>, Status> {
            require_token(&req)?;
            Ok(Response::new(pb::GetKeyMaterialResponse {
                key_material: Some(self.key_material.clone()),
            }))
        }
        async fn register_device(
            &self,
            req: Request<pb::RegisterDeviceRequest>,
        ) -> std::result::Result<Response<pb::Device>, Status> {
            require_token(&req)?;
            let dev = req.into_inner().device.unwrap_or_default();
            Ok(Response::new(pb::Device {
                device_id: "dev-2".to_string(),
                device_label: dev.device_label,
                platform: dev.platform,
                machine_id: "m".to_string(),
                created_at: "2026".to_string(),
                last_seen_at: String::new(),
                revoked_at: String::new(),
            }))
        }
        async fn list_my_devices(
            &self,
            req: Request<pb::Empty>,
        ) -> std::result::Result<Response<pb::ListMyDevicesResponse>, Status> {
            require_token(&req)?;
            Ok(Response::new(pb::ListMyDevicesResponse {
                devices: vec![pb::Device {
                    device_id: "dev-1".to_string(),
                    device_label: "Olivia's PC".to_string(),
                    platform: "windows".to_string(),
                    machine_id: "m".to_string(),
                    created_at: "2026".to_string(),
                    last_seen_at: String::new(),
                    revoked_at: String::new(),
                }],
            }))
        }
        async fn revoke_device(
            &self,
            req: Request<pb::DeviceId>,
        ) -> std::result::Result<Response<pb::Empty>, Status> {
            require_token(&req)?;
            Ok(Response::new(pb::Empty {}))
        }
        async fn verify_mfa(
            &self,
            _req: Request<pb::VerifyMfaRequest>,
        ) -> std::result::Result<Response<pb::Session>, Status> {
            Err(Status::unimplemented("mock"))
        }
        async fn get_profile(
            &self,
            req: Request<pb::Empty>,
        ) -> std::result::Result<Response<pb::Profile>, Status> {
            require_token(&req)?;
            Ok(Response::new(pb::Profile {
                user_id: "u-1".to_string(),
                email: "o@x".to_string(),
                display_name: "Olivia".to_string(),
                instance_role: "owner".to_string(),
            }))
        }
        async fn update_display_name(
            &self,
            req: Request<pb::UpdateDisplayNameRequest>,
        ) -> std::result::Result<Response<pb::Profile>, Status> {
            require_token(&req)?;
            Ok(Response::new(pb::Profile {
                user_id: "u-1".to_string(),
                email: "o@x".to_string(),
                display_name: req.into_inner().display_name,
                instance_role: "owner".to_string(),
            }))
        }
        async fn update_email(
            &self,
            req: Request<pb::UpdateEmailRequest>,
        ) -> std::result::Result<Response<pb::Profile>, Status> {
            require_token(&req)?;
            Ok(Response::new(pb::Profile {
                user_id: "u-1".to_string(),
                email: req.into_inner().new_email,
                display_name: "Olivia".to_string(),
                instance_role: "owner".to_string(),
            }))
        }
        async fn change_password(
            &self,
            req: Request<pb::ChangePasswordRequest>,
        ) -> std::result::Result<Response<pb::Empty>, Status> {
            require_token(&req)?;
            // The client must hand back a non-empty 2SKD re-wrap of the master key.
            let r = req.into_inner();
            if r.new_master_key_wrapped.is_empty() || r.new_kdf_salt.is_empty() {
                return Err(Status::invalid_argument("missing re-wrap"));
            }
            Ok(Response::new(pb::Empty {}))
        }
    }

    async fn spawn(key_material: pb::KeyMaterial) -> (String, tokio::sync::oneshot::Sender<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(AccountServer::new(Mock { key_material }))
                .serve_with_incoming_shutdown(
                    tokio_stream::wrappers::TcpListenerStream::new(listener),
                    async {
                        let _ = rx.await;
                    },
                )
                .await
                .unwrap();
        });
        (addr.to_string(), tx)
    }

    fn fast() -> crypto::KdfParams {
        crypto::KdfParams {
            m_cost_kib: 64,
            t_cost: 1,
            p_cost: 1,
        }
    }

    /// Inject a connected channel + a verified server, bypassing discovery (which
    /// needs an HTTP server; covered by the cross-stack e2e). Lets the facade's
    /// post-connect flows be tested against a mock gRPC server.
    async fn inject(client: &Client, addr: &str) {
        let channel = transport::connect(&[addr.to_string()]).await.unwrap();
        let mut inner = client.inner.lock().await;
        inner.channel = Some(channel);
        inner.verified = Some(VerifiedServer {
            identity_public: [7u8; 32],
            name: "Mock".to_string(),
            server_version: "0".to_string(),
            grpc_port: 50051,
        });
        inner.endpoints = vec![addr.to_string()];
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn create_owner_caches_state_and_manages_devices() {
        let (addr, shutdown) = spawn(pb::KeyMaterial::default()).await;
        let client = Client::with_store(Box::new(MemoryStore::new()));
        inject(&client, &addr).await;

        let enrollment = client
            .create_owner("o@x", "Olivia", "pw", "Olivia's PC")
            .await
            .unwrap();
        assert_eq!(enrollment.user_id, "u-1");
        assert_eq!(enrollment.secret_key.split('-').count(), 8);

        // Everything got cached in the keychain.
        assert!(client.vault.master_key().unwrap().is_some());
        assert!(client.vault.secret_key().unwrap().is_some());
        assert!(client.vault.device_secret().unwrap().is_some());
        assert_eq!(client.vault.session_token().unwrap().as_deref(), Some(TOKEN));
        assert!(client.vault.server_profile().unwrap().is_some());

        // Device management round-trips against the mock.
        let devices = client.list_devices().await.unwrap();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].label, "Olivia's PC");
        let added = client.enroll_this_device("Laptop").await.unwrap();
        assert_eq!(added.label, "Laptop");
        client.revoke_device("dev-1").await.unwrap();

        // Light sign-out drops the session + master key but keeps the device
        // enrolled (Secret Key + server profile stay) — a return needs only the password.
        client.sign_out().await.unwrap();
        assert!(client.vault.master_key().unwrap().is_none());
        assert!(client.vault.session_token().unwrap().is_none());
        assert!(client.vault.secret_key().unwrap().is_some());
        assert!(client.vault.server_profile().unwrap().is_some());

        // Forget-server is the full wipe.
        client.forget_server().await.unwrap();
        assert!(client.vault.secret_key().unwrap().is_none());
        assert!(client.vault.server_profile().unwrap().is_none());

        let _ = shutdown.send(());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn sign_in_unlocks_and_caches() {
        // A real bundle the mock serves as this account's key material.
        let boot = crypto::bootstrap_identity_with_params("pw", fast()).unwrap();
        let secret_key_str = boot.secret_key.display();
        let (addr, shutdown) = spawn(key_material(&boot.bundle)).await;
        let client = Client::with_store(Box::new(MemoryStore::new()));
        inject(&client, &addr).await;

        // New-device sign-in: the user supplies the Secret Key.
        let outcome = client
            .sign_in("o@x", "pw", Some(&secret_key_str))
            .await
            .unwrap();
        assert!(matches!(outcome, SignInOutcome::Success { .. }));
        // The cached Secret Key now lets a returning sign-in omit it.
        assert!(client.vault.secret_key().unwrap().is_some());
        assert_eq!(client.vault.session_token().unwrap().as_deref(), Some(TOKEN));

        let _ = shutdown.send(());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn change_password_rewraps_and_calls_the_server() {
        // Sign in first so the Secret Key + session are cached, then change the
        // password. The mock serves a real bundle, so the local unlock (old
        // password check) and re-wrap both run for real.
        let boot = crypto::bootstrap_identity_with_params("pw", fast()).unwrap();
        let secret_key_str = boot.secret_key.display();
        let (addr, shutdown) = spawn(key_material(&boot.bundle)).await;
        let client = Client::with_store(Box::new(MemoryStore::new()));
        inject(&client, &addr).await;

        client
            .sign_in("o@x", "pw", Some(&secret_key_str))
            .await
            .unwrap();

        // Right current password → succeeds (the mock asserts a non-empty re-wrap).
        client.change_password("pw", "new-pw").await.unwrap();

        // Wrong current password → the local unlock fails → Crypto (no server call).
        let err = client.change_password("wrong", "new-pw").await.unwrap_err();
        assert!(matches!(err, ClientError::Crypto));

        let _ = shutdown.send(());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn sign_in_wrong_secret_key_fails() {
        let boot = crypto::bootstrap_identity_with_params("pw", fast()).unwrap();
        let (addr, shutdown) = spawn(key_material(&boot.bundle)).await;
        let client = Client::with_store(Box::new(MemoryStore::new()));
        inject(&client, &addr).await;

        let wrong = SecretKey::generate().display();
        let result = client.sign_in("o@x", "pw", Some(&wrong)).await;
        assert!(matches!(result, Err(ClientError::Crypto)));

        let _ = shutdown.send(());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn restore_without_enrollment_is_none() {
        let client = Client::with_store(Box::new(MemoryStore::new()));
        assert!(client.restore().await.unwrap().is_none());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn calls_before_connect_or_signin_are_rejected() {
        let client = Client::with_store(Box::new(MemoryStore::new()));
        assert!(matches!(
            client.create_owner("o@x", "O", "pw", "PC").await,
            Err(ClientError::NotConnected)
        ));
        assert!(matches!(
            client.list_devices().await,
            Err(ClientError::NotSignedIn)
        ));
    }

    fn key_material(bundle: &crypto::KeyBundle) -> pb::KeyMaterial {
        pb::KeyMaterial {
            x25519_public: bundle.x25519_public.clone(),
            ed25519_public: bundle.ed25519_public.clone(),
            x25519_private_wrapped: bundle.x25519_private_wrapped.clone(),
            ed25519_private_wrapped: bundle.ed25519_private_wrapped.clone(),
            master_key_wrapped: bundle.master_key_wrapped.clone(),
            kdf_salt: bundle.kdf_salt.clone(),
            kdf_params: bundle.kdf_params.clone(),
        }
    }
}
