//! The uniffi boundary for native shells (Sylva Hub) — feature `ffi`.
//!
//! [`SylvaHub`] is the opaque object the shell binds to. It wraps the async
//! [`SylvaClient`] facade behind a **blocking** API (it owns a tokio runtime and
//! `block_on`s each call), because the chosen C# binding generator
//! (`uniffi-bindgen-cs`) handles synchronous calls most reliably. The shell
//! invokes these off its UI thread.
//!
//! C# bindings are generated from this scaffolding by `uniffi-bindgen-cs` in
//! Phase 4 (the `uniffi` crate version here must match that tool's supported
//! version).

use std::sync::Arc;

use tokio::runtime::Runtime;

use crate::client::{
    ClientError, ConnectInfo, DeviceInfo, Enrollment, SignInOutcome, SylvaClient,
};

/// The shell-facing handle: a blocking wrapper over [`SylvaClient`] with its own
/// runtime. Held for the app's lifetime.
#[derive(uniffi::Object)]
pub struct SylvaHub {
    runtime: Runtime,
    client: SylvaClient,
}

#[uniffi::export]
impl SylvaHub {
    /// Create a hub whose secrets live in the OS keychain under `service`
    /// (e.g. `"sylva-client"`), scoped to the current OS user.
    #[uniffi::constructor]
    pub fn new(service: String) -> Result<Arc<Self>, ClientError> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|_| ClientError::Server)?;
        Ok(Arc::new(Self {
            runtime,
            client: SylvaClient::new(service),
        }))
    }

    /// Discover + verify + connect a server (TOFU). See [`SylvaClient::connect`].
    pub fn connect(&self, host: String, discovery_port: u16) -> Result<ConnectInfo, ClientError> {
        self.runtime
            .block_on(self.client.connect(&host, discovery_port))
    }

    /// Create the first owner. Returns the Secret Key to show once.
    pub fn create_owner(
        &self,
        email: String,
        display_name: String,
        password: String,
        device_label: String,
    ) -> Result<Enrollment, ClientError> {
        self.runtime.block_on(self.client.create_owner(
            &email,
            &display_name,
            &password,
            &device_label,
        ))
    }

    /// Sign in (+ unlock). `secret_key` is the user-entered value on a new
    /// device, or empty/absent to use the keychain-cached one.
    pub fn sign_in(
        &self,
        email: String,
        password: String,
        secret_key: Option<String>,
    ) -> Result<SignInOutcome, ClientError> {
        self.runtime
            .block_on(self.client.sign_in(&email, &password, secret_key.as_deref()))
    }

    /// Enroll this device into the signed-in account.
    pub fn enroll_this_device(&self, label: String) -> Result<DeviceInfo, ClientError> {
        self.runtime
            .block_on(self.client.enroll_this_device(&label))
    }

    /// This account's active devices.
    pub fn list_devices(&self) -> Result<Vec<DeviceInfo>, ClientError> {
        self.runtime.block_on(self.client.list_devices())
    }

    /// Revoke one of this account's devices.
    pub fn revoke_device(&self, device_id: String) -> Result<(), ClientError> {
        self.runtime
            .block_on(self.client.revoke_device(&device_id))
    }

    /// Sign out: wipe the keychain + drop in-memory secrets.
    pub fn sign_out(&self) -> Result<(), ClientError> {
        self.runtime.block_on(self.client.sign_out())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn hub_constructs_and_guards_before_connect() {
        let hub = SylvaHub::new("sylva-sdk-ffi-test".to_string()).unwrap();
        // A call before connecting drives the async facade to completion (via the
        // internal runtime) and surfaces the guard error — proving the blocking
        // wrapper + delegation work end to end.
        let err = hub
            .create_owner(
                "o@x".to_string(),
                "O".to_string(),
                "pw".to_string(),
                "PC".to_string(),
            )
            .unwrap_err();
        assert!(matches!(err, ClientError::NotConnected));
    }
}
