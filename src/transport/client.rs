//! The gRPC transport to a Sylva Server `Account` service: ordered-endpoint failover
//! connect + an authenticated client wrapper that attaches the session token.
//!
//! Connection is **h2c** (plaintext HTTP/2) for now — Sylva Server serves gRPC without
//! TLS at this layer (a reverse proxy terminates TLS in production). The
//! self-signed-TLS-anchored-on-the-identity-key path (design `hub.md`) lands when
//! TLS termination moves in; the discovery identity pin is the trust anchor
//! regardless (see [`super::discovery`]).
//!
//! This layer deals in raw proto types; the crypto-composing enrollment *flows*
//! (generate keys → `Bootstrap`; `Login` → `GetKeyMaterial` → unlock) sit above
//! it in a later sub-phase.

use tonic::transport::{Channel, Endpoint};

use crate::proto::account::v1 as pb;
use pb::account_client::AccountClient;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("no endpoints to try")]
    NoEndpoints,
    #[error("could not connect to any endpoint")]
    AllEndpointsFailed,
    #[error("invalid endpoint (must be host:port)")]
    BadEndpoint,
    #[error("transport error")]
    Transport(#[from] tonic::transport::Error),
    #[error("rpc failed: {0}")]
    Rpc(#[from] tonic::Status),
    #[error("server response was missing an expected field")]
    EmptyResponse,
}

pub type Result<T> = std::result::Result<T, ClientError>;

/// Connect to the first reachable endpoint, tried in order — the LAN / VPN /
/// public failover from the design. Each `endpoint` is a `host:port`; connection
/// is plaintext h2c (`http://…`).
pub async fn connect(endpoints: &[String]) -> Result<Channel> {
    if endpoints.is_empty() {
        return Err(ClientError::NoEndpoints);
    }
    let mut last: Option<ClientError> = None;
    for endpoint in endpoints {
        let endpoint = match Endpoint::from_shared(format!("http://{endpoint}")) {
            Ok(endpoint) => endpoint,
            Err(_) => {
                last = Some(ClientError::BadEndpoint);
                continue;
            }
        };
        match endpoint.connect().await {
            Ok(channel) => return Ok(channel),
            Err(err) => last = Some(ClientError::Transport(err)),
        }
    }
    Err(last.unwrap_or(ClientError::AllEndpointsFailed))
}

/// Unauthenticated: create the first owner from client-generated key material.
/// Returns the session (token + user id + expiry).
pub async fn bootstrap(channel: Channel, request: pb::BootstrapRequest) -> Result<pb::Session> {
    let mut client = AccountClient::new(channel);
    Ok(client.bootstrap(tonic::Request::new(request)).await?.into_inner())
}

/// Unauthenticated: sign in. Returns the outcome (a session, or `mfa_required`).
pub async fn login(channel: Channel, request: pb::LoginRequest) -> Result<pb::LoginResponse> {
    let mut client = AccountClient::new(channel);
    Ok(client.login(tonic::Request::new(request)).await?.into_inner())
}

/// An authenticated `Account` client: a connected channel plus the session
/// token, which it attaches as `authorization: Bearer <token>` on every call.
pub struct AccountSession {
    client: AccountClient<Channel>,
    token: String,
}

impl AccountSession {
    pub fn new(channel: Channel, token: impl Into<String>) -> Self {
        Self {
            client: AccountClient::new(channel),
            token: token.into(),
        }
    }

    /// The session token this client authenticates with (for caching).
    pub fn token(&self) -> &str {
        &self.token
    }

    /// Wrap a message in a request bearing the session token.
    fn authed<T>(&self, message: T) -> tonic::Request<T> {
        let mut request = tonic::Request::new(message);
        if let Ok(value) = format!("Bearer {}", self.token).parse() {
            request.metadata_mut().insert("authorization", value);
        }
        request
    }

    /// The caller's wrapped key bundle (the client then unlocks it with
    /// password + Secret Key).
    pub async fn key_material(&mut self) -> Result<pb::KeyMaterial> {
        let response = self.client.get_key_material(self.authed(pb::Empty {})).await?;
        response.into_inner().key_material.ok_or(ClientError::EmptyResponse)
    }

    /// Enroll an additional device; returns the server's device record.
    pub async fn register_device(&mut self, device: pb::DeviceEnrollment) -> Result<pb::Device> {
        let request = self.authed(pb::RegisterDeviceRequest {
            device: Some(device),
        });
        Ok(self.client.register_device(request).await?.into_inner())
    }

    /// The caller's active (non-revoked) devices, oldest first.
    pub async fn list_devices(&mut self) -> Result<Vec<pb::Device>> {
        let response = self.client.list_my_devices(self.authed(pb::Empty {})).await?;
        Ok(response.into_inner().devices)
    }

    /// Revoke one of the caller's devices.
    pub async fn revoke_device(&mut self, device_id: impl Into<String>) -> Result<()> {
        let request = self.authed(pb::DeviceId {
            device_id: device_id.into(),
        });
        self.client.revoke_device(request).await?;
        Ok(())
    }

    /// The caller's profile (public identity fields only).
    pub async fn get_profile(&mut self) -> Result<pb::Profile> {
        Ok(self.client.get_profile(self.authed(pb::Empty {})).await?.into_inner())
    }

    /// Change the caller's display name; returns the updated profile.
    pub async fn update_display_name(&mut self, display_name: impl Into<String>) -> Result<pb::Profile> {
        let request = self.authed(pb::UpdateDisplayNameRequest {
            display_name: display_name.into(),
        });
        Ok(self.client.update_display_name(request).await?.into_inner())
    }

    /// Change the caller's email (re-auth: current password); returns the
    /// updated profile.
    pub async fn update_email(
        &mut self,
        new_email: impl Into<String>,
        current_password: impl Into<String>,
    ) -> Result<pb::Profile> {
        let request = self.authed(pb::UpdateEmailRequest {
            new_email: new_email.into(),
            current_password: current_password.into(),
        });
        Ok(self.client.update_email(request).await?.into_inner())
    }

    /// Change the caller's password: the server recomputes its verifier from
    /// `new_password` and stores the client's 2SKD re-wrap of the master key.
    pub async fn change_password(&mut self, request: pb::ChangePasswordRequest) -> Result<()> {
        self.client.change_password(self.authed(request)).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use crate::proto::account::v1::account_server::{Account, AccountServer};
    use tonic::{Request, Response, Status};

    const TOKEN: &str = "tok-abc-123";

    /// Pull the bearer token out of a request's metadata, or reject.
    fn bearer<T>(req: &Request<T>) -> std::result::Result<String, Status> {
        let raw = req
            .metadata()
            .get("authorization")
            .ok_or_else(|| Status::unauthenticated("missing authorization"))?
            .to_str()
            .map_err(|_| Status::unauthenticated("bad authorization"))?;
        raw.strip_prefix("Bearer ")
            .map(str::to_string)
            .ok_or_else(|| Status::unauthenticated("not a bearer token"))
    }

    /// Reject unless the request carries the expected bearer token. Returns
    /// `unauthenticated` (not a panic) so the client's error path is exercised.
    fn require_token<T>(req: &Request<T>) -> std::result::Result<(), Status> {
        if bearer(req)? == TOKEN {
            Ok(())
        } else {
            Err(Status::unauthenticated("wrong token"))
        }
    }

    /// A mock Account service: `Bootstrap` issues a fixed token; the authed RPCs
    /// assert the bearer token is present + correct before returning canned data.
    #[derive(Default)]
    struct MockAccount;

    #[tonic::async_trait]
    impl Account for MockAccount {
        async fn bootstrap(
            &self,
            _req: Request<pb::BootstrapRequest>,
        ) -> std::result::Result<Response<pb::Session>, Status> {
            Ok(Response::new(pb::Session {
                token: TOKEN.to_string(),
                user_id: "11111111-1111-1111-1111-111111111111".to_string(),
                expires_at: "2030-01-01T00:00:00Z".to_string(),
            }))
        }

        async fn login(
            &self,
            _req: Request<pb::LoginRequest>,
        ) -> std::result::Result<Response<pb::LoginResponse>, Status> {
            Ok(Response::new(pb::LoginResponse {
                outcome: Some(pb::login_response::Outcome::Session(pb::Session {
                    token: TOKEN.to_string(),
                    user_id: "11111111-1111-1111-1111-111111111111".to_string(),
                    expires_at: "2030-01-01T00:00:00Z".to_string(),
                })),
            }))
        }

        async fn verify_mfa(
            &self,
            _req: Request<pb::VerifyMfaRequest>,
        ) -> std::result::Result<Response<pb::Session>, Status> {
            Err(Status::unimplemented("mock"))
        }

        async fn get_key_material(
            &self,
            req: Request<pb::Empty>,
        ) -> std::result::Result<Response<pb::GetKeyMaterialResponse>, Status> {
            require_token(&req)?;
            Ok(Response::new(pb::GetKeyMaterialResponse {
                key_material: Some(pb::KeyMaterial {
                    x25519_public: vec![1u8; 32],
                    ed25519_public: vec![2u8; 32],
                    x25519_private_wrapped: vec![3u8; 48],
                    ed25519_private_wrapped: vec![4u8; 48],
                    master_key_wrapped: vec![5u8; 72],
                    kdf_salt: vec![6u8; 16],
                    kdf_params: r#"{"m":65536,"t":3,"p":4}"#.to_string(),
                }),
            }))
        }

        async fn register_device(
            &self,
            req: Request<pb::RegisterDeviceRequest>,
        ) -> std::result::Result<Response<pb::Device>, Status> {
            require_token(&req)?;
            let dev = req.into_inner().device.unwrap_or_default();
            Ok(Response::new(pb::Device {
                device_id: "dev-1".to_string(),
                device_label: dev.device_label,
                platform: dev.platform,
                machine_id: "mac-1".to_string(),
                created_at: "2026-01-01T00:00:00Z".to_string(),
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
                    machine_id: "mac-1".to_string(),
                    created_at: "2026-01-01T00:00:00Z".to_string(),
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

        async fn get_profile(
            &self,
            req: Request<pb::Empty>,
        ) -> std::result::Result<Response<pb::Profile>, Status> {
            require_token(&req)?;
            Ok(Response::new(pb::Profile {
                user_id: "11111111-1111-1111-1111-111111111111".to_string(),
                email: "olivia@test.local".to_string(),
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
                user_id: "11111111-1111-1111-1111-111111111111".to_string(),
                email: "olivia@test.local".to_string(),
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
                user_id: "11111111-1111-1111-1111-111111111111".to_string(),
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
            Ok(Response::new(pb::Empty {}))
        }
    }

    /// Spin up the mock on an ephemeral port; returns its `host:port` + a
    /// shutdown sender.
    async fn spawn_mock() -> (String, tokio::sync::oneshot::Sender<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(AccountServer::new(MockAccount))
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

    #[tokio::test(flavor = "multi_thread")]
    async fn connect_fails_over_then_bootstrap_and_authed_round_trips() {
        let (addr, shutdown) = spawn_mock().await;

        // First endpoint is dead; failover reaches the live mock second.
        let channel = connect(&["127.0.0.1:1".to_string(), addr]).await.unwrap();

        // Unauthenticated bootstrap yields a token.
        let session = bootstrap(channel.clone(), pb::BootstrapRequest::default())
            .await
            .unwrap();
        assert_eq!(session.token, TOKEN);

        // The authed client attaches the bearer token (mock asserts it) and the
        // typed wrappers unwrap the responses.
        let mut account = AccountSession::new(channel, session.token);
        let km = account.key_material().await.unwrap();
        assert_eq!(km.master_key_wrapped, vec![5u8; 72]);

        let devices = account.list_devices().await.unwrap();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].device_label, "Olivia's PC");

        let enrolled = account
            .register_device(pb::DeviceEnrollment {
                device_label: "Laptop".to_string(),
                platform: "windows".to_string(),
                device_public_key: vec![7u8; 32],
                machine_label: "Family-PC".to_string(),
            })
            .await
            .unwrap();
        assert_eq!(enrolled.device_label, "Laptop");

        account.revoke_device("dev-1").await.unwrap();

        // Account self-service round-trips: read the profile, update name + email,
        // and change the password (all authed; the mock asserts the bearer token).
        let profile = account.get_profile().await.unwrap();
        assert_eq!(profile.display_name, "Olivia");
        assert_eq!(profile.instance_role, "owner");
        let renamed = account.update_display_name("Liv").await.unwrap();
        assert_eq!(renamed.display_name, "Liv");
        let remailed = account.update_email("liv@x", "pw").await.unwrap();
        assert_eq!(remailed.email, "liv@x");
        account
            .change_password(pb::ChangePasswordRequest {
                current_password: "pw".to_string(),
                new_password: "pw2".to_string(),
                new_master_key_wrapped: vec![9u8; 72],
                new_kdf_salt: vec![8u8; 16],
                new_kdf_params: r#"{"m":65536,"t":3,"p":4}"#.to_string(),
            })
            .await
            .unwrap();

        let _ = shutdown.send(());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn missing_token_is_rejected_by_the_server() {
        let (addr, shutdown) = spawn_mock().await;
        let channel = connect(&[addr]).await.unwrap();
        // An empty token → no usable bearer → the mock rejects with unauthenticated.
        let mut account = AccountSession::new(channel, "");
        let err = account.list_devices().await.unwrap_err();
        assert!(matches!(err, ClientError::Rpc(status) if status.code() == tonic::Code::Unauthenticated));
        let _ = shutdown.send(());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn connect_with_no_endpoints_errors() {
        assert!(matches!(connect(&[]).await, Err(ClientError::NoEndpoints)));
    }
}
