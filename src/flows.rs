//! The slice-1 enrollment flows — the orchestration layer that composes the
//! [crypto core](crate::crypto) with the [gRPC transport](crate::transport) into
//! the user-facing operations: create the first owner, sign in (+ unlock), and
//! manage this account's devices. (These realize the `auth` + `enroll` surfaces
//! sketched in `design/repos.md`; they live in one module for slice 1.)
//!
//! The crypto↔proto bridge lives here — the only place the wire `KeyMaterial`
//! and the local `KeyBundle` meet.

use tonic::transport::Channel;
use zeroize::Zeroizing;

use crate::crypto::{self, KeyBundle, SecretKey, UnlockedIdentity};
use crate::proto::account::v1 as pb;
use crate::transport::client::{self, AccountSession, ClientError};

#[derive(Debug, thiserror::Error)]
pub enum EnrollError {
    #[error(transparent)]
    Transport(#[from] ClientError),
    #[error(transparent)]
    Crypto(#[from] crypto::CryptoError),
    #[error("multi-factor authentication is required but this client can't complete it yet")]
    MfaRequired,
    #[error("the server's login response was empty")]
    EmptyLogin,
}

pub type Result<T> = std::result::Result<T, EnrollError>;

/// Identifying details for the first owner.
pub struct NewOwner<'a> {
    pub email: &'a str,
    pub display_name: &'a str,
    pub password: &'a str,
    pub device_label: &'a str,
    pub platform: &'a str,
    pub machine_label: &'a str,
}

/// The result of a successful owner-bootstrap. The caller MUST surface
/// `secret_key` to the user for one-time write-down, and cache `identity` +
/// `device_secret` in the OS keychain (a later phase). `account` is an authed
/// session ready for further calls.
pub struct EnrolledOwner {
    pub account: AccountSession,
    pub user_id: String,
    pub secret_key: SecretKey,
    pub identity: UnlockedIdentity,
    pub device_public: [u8; 32],
    pub device_secret: Zeroizing<[u8; 32]>,
}

/// The result of a successful sign-in: a live authed session + the unlocked
/// identity (master key + private keys).
pub struct LoggedIn {
    pub account: AccountSession,
    pub user_id: String,
    pub identity: UnlockedIdentity,
}

/// Create the first owner on a connected (and identity-verified) server, with
/// the default KDF cost.
pub async fn enroll_new_owner(channel: Channel, owner: NewOwner<'_>) -> Result<EnrolledOwner> {
    enroll_new_owner_with_params(channel, owner, crypto::KdfParams::default()).await
}

/// As [`enroll_new_owner`] but with explicit KDF params (param upgrades / tests).
pub async fn enroll_new_owner_with_params(
    channel: Channel,
    owner: NewOwner<'_>,
    params: crypto::KdfParams,
) -> Result<EnrolledOwner> {
    // Generate all key material client-side; the server only ever sees ciphertext.
    let boot = crypto::bootstrap_identity_with_params(owner.password, params)?;
    let device = crypto::generate_device_keypair();

    let request = pb::BootstrapRequest {
        email: owner.email.to_string(),
        display_name: owner.display_name.to_string(),
        // Sent over TLS for the server's Argon2id verifier — distinct from the
        // client-side 2SKD that wrapped the master key in `boot.bundle`.
        password: owner.password.to_string(),
        key_material: Some(bundle_to_key_material(boot.bundle)),
        device: Some(pb::DeviceEnrollment {
            device_label: owner.device_label.to_string(),
            platform: owner.platform.to_string(),
            device_public_key: device.public.to_vec(),
            machine_label: owner.machine_label.to_string(),
        }),
    };

    let session = client::bootstrap(channel.clone(), request).await?;
    Ok(EnrolledOwner {
        account: AccountSession::new(channel, session.token),
        user_id: session.user_id,
        secret_key: boot.secret_key,
        identity: boot.identity,
        device_public: device.public,
        device_secret: device.secret,
    })
}

/// Sign in: authenticate, fetch the wrapped key material, and unlock it locally
/// with the password + Secret Key. Returns an authed session for device ops and
/// the unlocked identity. `MfaRequired` if the account has a second factor (not
/// completable by this client yet); `Crypto` if the password / Secret Key is wrong.
pub async fn login(
    channel: Channel,
    email: &str,
    password: &str,
    secret_key: &SecretKey,
) -> Result<LoggedIn> {
    let response = client::login(
        channel.clone(),
        pb::LoginRequest {
            email: email.to_string(),
            password: password.to_string(),
            mfa_challenge_token: String::new(),
            mfa_response: Vec::new(),
        },
    )
    .await?;

    let session = match response.outcome {
        Some(pb::login_response::Outcome::Session(session)) => session,
        Some(pb::login_response::Outcome::MfaRequired(_)) => return Err(EnrollError::MfaRequired),
        None => return Err(EnrollError::EmptyLogin),
    };

    let mut account = AccountSession::new(channel, session.token);
    let key_material = account.key_material().await?;
    let bundle = key_material_to_bundle(key_material);
    let identity = crypto::unlock_identity(&bundle, password, secret_key)?;

    Ok(LoggedIn {
        account,
        user_id: session.user_id,
        identity,
    })
}

// ── the crypto ↔ proto bridge ──────────────────────────────────────────────

fn bundle_to_key_material(bundle: KeyBundle) -> pb::KeyMaterial {
    pb::KeyMaterial {
        x25519_public: bundle.x25519_public,
        ed25519_public: bundle.ed25519_public,
        x25519_private_wrapped: bundle.x25519_private_wrapped,
        ed25519_private_wrapped: bundle.ed25519_private_wrapped,
        master_key_wrapped: bundle.master_key_wrapped,
        kdf_salt: bundle.kdf_salt,
        kdf_params: bundle.kdf_params,
    }
}

fn key_material_to_bundle(material: pb::KeyMaterial) -> KeyBundle {
    KeyBundle {
        x25519_public: material.x25519_public,
        ed25519_public: material.ed25519_public,
        x25519_private_wrapped: material.x25519_private_wrapped,
        ed25519_private_wrapped: material.ed25519_private_wrapped,
        master_key_wrapped: material.master_key_wrapped,
        kdf_salt: material.kdf_salt,
        kdf_params: material.kdf_params,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use crate::proto::account::v1::account_server::{Account, AccountServer};
    use tonic::{Request, Response, Status};

    fn fast_params() -> crypto::KdfParams {
        crypto::KdfParams {
            m_cost_kib: 64,
            t_cost: 1,
            p_cost: 1,
        }
    }

    /// A mock Account service for the flow tests. Returns a configurable
    /// `key_material` (a *real* wrapped bundle, so `unlock_identity` succeeds)
    /// and can be told to demand MFA.
    #[derive(Clone)]
    struct FlowMock {
        token: String,
        key_material: pb::KeyMaterial,
        require_mfa: bool,
    }

    #[tonic::async_trait]
    impl Account for FlowMock {
        async fn bootstrap(
            &self,
            req: Request<pb::BootstrapRequest>,
        ) -> std::result::Result<Response<pb::Session>, Status> {
            let r = req.into_inner();
            // The flow must have attached client-generated key material + a device.
            assert!(r.key_material.is_some(), "bootstrap missing key_material");
            assert!(r.device.is_some(), "bootstrap missing device");
            assert!(!r.password.is_empty(), "bootstrap missing password");
            Ok(Response::new(pb::Session {
                token: self.token.clone(),
                user_id: "u-1".to_string(),
                expires_at: "2030-01-01T00:00:00Z".to_string(),
            }))
        }

        async fn login(
            &self,
            _req: Request<pb::LoginRequest>,
        ) -> std::result::Result<Response<pb::LoginResponse>, Status> {
            let outcome = if self.require_mfa {
                pb::login_response::Outcome::MfaRequired(pb::MfaRequired {
                    mfa_challenge_token: "challenge".to_string(),
                    methods: vec!["totp".to_string()],
                })
            } else {
                pb::login_response::Outcome::Session(pb::Session {
                    token: self.token.clone(),
                    user_id: "u-1".to_string(),
                    expires_at: "2030-01-01T00:00:00Z".to_string(),
                })
            };
            Ok(Response::new(pb::LoginResponse {
                outcome: Some(outcome),
            }))
        }

        async fn get_key_material(
            &self,
            req: Request<pb::Empty>,
        ) -> std::result::Result<Response<pb::GetKeyMaterialResponse>, Status> {
            // Must carry the session token the mock just issued.
            let auth = req
                .metadata()
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default();
            if auth != format!("Bearer {}", self.token) {
                return Err(Status::unauthenticated("bad token"));
            }
            Ok(Response::new(pb::GetKeyMaterialResponse {
                key_material: Some(self.key_material.clone()),
            }))
        }

        async fn verify_mfa(
            &self,
            _req: Request<pb::VerifyMfaRequest>,
        ) -> std::result::Result<Response<pb::Session>, Status> {
            Err(Status::unimplemented("mock"))
        }
        async fn register_device(
            &self,
            _req: Request<pb::RegisterDeviceRequest>,
        ) -> std::result::Result<Response<pb::Device>, Status> {
            Err(Status::unimplemented("mock"))
        }
        async fn list_my_devices(
            &self,
            _req: Request<pb::Empty>,
        ) -> std::result::Result<Response<pb::ListMyDevicesResponse>, Status> {
            Err(Status::unimplemented("mock"))
        }
        async fn revoke_device(
            &self,
            _req: Request<pb::DeviceId>,
        ) -> std::result::Result<Response<pb::Empty>, Status> {
            Err(Status::unimplemented("mock"))
        }
        async fn get_profile(
            &self,
            _req: Request<pb::Empty>,
        ) -> std::result::Result<Response<pb::Profile>, Status> {
            Err(Status::unimplemented("mock"))
        }
        async fn update_display_name(
            &self,
            _req: Request<pb::UpdateDisplayNameRequest>,
        ) -> std::result::Result<Response<pb::Profile>, Status> {
            Err(Status::unimplemented("mock"))
        }
        async fn update_email(
            &self,
            _req: Request<pb::UpdateEmailRequest>,
        ) -> std::result::Result<Response<pb::Profile>, Status> {
            Err(Status::unimplemented("mock"))
        }
        async fn change_password(
            &self,
            _req: Request<pb::ChangePasswordRequest>,
        ) -> std::result::Result<Response<pb::Empty>, Status> {
            Err(Status::unimplemented("mock"))
        }
    }

    async fn spawn(mock: FlowMock) -> (Channel, tokio::sync::oneshot::Sender<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(AccountServer::new(mock))
                .serve_with_incoming_shutdown(
                    tokio_stream::wrappers::TcpListenerStream::new(listener),
                    async {
                        let _ = rx.await;
                    },
                )
                .await
                .unwrap();
        });
        let channel = client::connect(&[addr.to_string()]).await.unwrap();
        (channel, tx)
    }

    fn dummy_key_material() -> pb::KeyMaterial {
        pb::KeyMaterial {
            x25519_public: vec![0u8; 32],
            ed25519_public: vec![0u8; 32],
            x25519_private_wrapped: vec![0u8; 48],
            ed25519_private_wrapped: vec![0u8; 48],
            master_key_wrapped: vec![0u8; 72],
            kdf_salt: vec![0u8; 16],
            kdf_params: r#"{"m":64,"t":1,"p":1}"#.to_string(),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn enroll_new_owner_generates_material_and_returns_secret_key() {
        let mock = FlowMock {
            token: "tok-1".to_string(),
            key_material: dummy_key_material(),
            require_mfa: false,
        };
        let (channel, shutdown) = spawn(mock).await;

        let enrolled = enroll_new_owner_with_params(
            channel,
            NewOwner {
                email: "owner@example.com",
                display_name: "Olivia",
                password: "correct horse",
                device_label: "Olivia's PC",
                platform: "windows",
                machine_label: "Family-PC",
            },
            fast_params(),
        )
        .await
        .unwrap();

        assert_eq!(enrolled.user_id, "u-1");
        // A Secret Key was generated for the user to write down.
        assert_eq!(enrolled.secret_key.display().split('-').count(), 8);
        // A device keypair was generated (public is non-zero).
        assert_ne!(enrolled.device_public, [0u8; 32]);

        let _ = shutdown.send(());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn login_unlocks_the_master_key() {
        // A real bundle the mock will serve as this account's key material.
        let boot = crypto::bootstrap_identity_with_params("hunter2", fast_params()).unwrap();
        let expected_master = *boot.identity.master_key.as_bytes();
        let mock = FlowMock {
            token: "tok-2".to_string(),
            key_material: bundle_to_key_material(boot.bundle.clone()),
            require_mfa: false,
        };
        let (channel, shutdown) = spawn(mock).await;

        let logged_in = login(channel, "owner@example.com", "hunter2", &boot.secret_key)
            .await
            .unwrap();
        assert_eq!(logged_in.user_id, "u-1");
        assert_eq!(*logged_in.identity.master_key.as_bytes(), expected_master);

        let _ = shutdown.send(());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn login_with_wrong_secret_key_fails_to_unlock() {
        let boot = crypto::bootstrap_identity_with_params("pw", fast_params()).unwrap();
        let mock = FlowMock {
            token: "tok-3".to_string(),
            key_material: bundle_to_key_material(boot.bundle),
            require_mfa: false,
        };
        let (channel, shutdown) = spawn(mock).await;

        // Right password, wrong Secret Key → local unlock fails (server auth passed).
        let result = login(channel, "owner@example.com", "pw", &SecretKey::generate()).await;
        assert!(matches!(result, Err(EnrollError::Crypto(_))));

        let _ = shutdown.send(());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn login_surfaces_mfa_required() {
        let mock = FlowMock {
            token: "tok-4".to_string(),
            key_material: dummy_key_material(),
            require_mfa: true,
        };
        let (channel, shutdown) = spawn(mock).await;

        let result = login(channel, "owner@example.com", "pw", &SecretKey::generate()).await;
        assert!(matches!(result, Err(EnrollError::MfaRequired)));

        let _ = shutdown.send(());
    }
}
