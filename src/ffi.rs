//! The uniffi boundary for the native client shells — feature `ffi`.
//!
//! [`SylvaClient`] is the opaque object the shell binds to. It wraps the async
//! [`Client`] facade behind a **blocking** API (it owns a tokio runtime and
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
    Client, ClientError, ConnectInfo, DeviceInfo, Enrollment, Profile, SignInOutcome,
    TotpEnrollment, TotpFactor,
};

/// The shell-facing handle: a blocking wrapper over the async [`Client`] facade
/// with its own runtime. Held for the app's lifetime.
#[derive(uniffi::Object)]
pub struct SylvaClient {
    runtime: Runtime,
    client: Client,
}

#[uniffi::export]
impl SylvaClient {
    /// Create a client whose secrets live in the OS keychain under `service`
    /// (e.g. `"sylva-client"`), scoped to the current OS user.
    #[uniffi::constructor]
    pub fn new(service: String) -> Result<Arc<Self>, ClientError> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|_| ClientError::Server)?;
        Ok(Arc::new(Self {
            runtime,
            client: Client::new(service),
        }))
    }

    /// Discover + verify + connect a server (TOFU). See [`Client::connect`].
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

    /// Complete a sign-in that returned `MfaRequired` by submitting the user's
    /// TOTP `code`. A wrong code returns `InvalidCode` and the pending sign-in is
    /// kept so the user can retry.
    pub fn submit_mfa(&self, code: String) -> Result<SignInOutcome, ClientError> {
        self.runtime.block_on(self.client.submit_mfa(&code))
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

    /// This account's profile (for the account-settings screen).
    pub fn get_profile(&self) -> Result<Profile, ClientError> {
        self.runtime.block_on(self.client.get_profile())
    }

    /// Change this account's display name; returns the updated profile.
    pub fn update_display_name(&self, display_name: String) -> Result<Profile, ClientError> {
        self.runtime
            .block_on(self.client.update_display_name(&display_name))
    }

    /// Change this account's email (re-auth: current password); returns the
    /// updated profile.
    pub fn update_email(
        &self,
        new_email: String,
        current_password: String,
    ) -> Result<Profile, ClientError> {
        self.runtime
            .block_on(self.client.update_email(&new_email, &current_password))
    }

    /// Change this account's password (local re-wrap + server verifier update).
    pub fn change_password(
        &self,
        current_password: String,
        new_password: String,
    ) -> Result<(), ClientError> {
        self.runtime
            .block_on(self.client.change_password(&current_password, &new_password))
    }

    /// Begin enrolling a TOTP authenticator. Returns the id + base32 secret +
    /// `otpauth://` URI (render as a QR code); confirm a code to activate it.
    pub fn enroll_totp(&self) -> Result<TotpEnrollment, ClientError> {
        self.runtime.block_on(self.client.enroll_totp())
    }

    /// Confirm a pending TOTP enrollment with a current code. A wrong code maps
    /// to `InvalidCode`; an empty `label` defaults server-side.
    pub fn confirm_totp(
        &self,
        totp_id: String,
        code: String,
        label: String,
    ) -> Result<(), ClientError> {
        self.runtime
            .block_on(self.client.confirm_totp(&totp_id, &code, &label))
    }

    /// This account's verified TOTP authenticators (for the security screen).
    pub fn list_totp(&self) -> Result<Vec<TotpFactor>, ClientError> {
        self.runtime.block_on(self.client.list_totp())
    }

    /// Remove one of this account's TOTP authenticators.
    pub fn remove_totp(&self, totp_id: String) -> Result<(), ClientError> {
        self.runtime.block_on(self.client.remove_totp(&totp_id))
    }

    /// This account's avatar (decrypted), or `None` if unset. Needs the cached
    /// master key. `Option<Vec<u8>>` maps to a nullable C# `byte[]`.
    pub fn get_avatar(&self) -> Result<Option<Vec<u8>>, ClientError> {
        self.runtime.block_on(self.client.get_avatar())
    }

    /// Seal a PNG under the master key and store it server-side (overwrites any
    /// prior). `Vec<u8>` maps to a C# `byte[]`.
    pub fn set_avatar(&self, avatar: Vec<u8>) -> Result<(), ClientError> {
        self.runtime.block_on(self.client.set_avatar(avatar))
    }

    /// Sign out of the active session, keeping this device enrolled (see
    /// [`Client::sign_out`]). A return needs only the password.
    pub fn sign_out(&self) -> Result<(), ClientError> {
        self.runtime.block_on(self.client.sign_out())
    }

    /// Forget this server entirely — full wipe; re-enroll (Secret Key) to return
    /// (see [`Client::forget_server`]).
    pub fn forget_server(&self) -> Result<(), ClientError> {
        self.runtime.block_on(self.client.forget_server())
    }

    /// Auto-resume a prior session on launch (see [`Client::restore`]). Returns the
    /// user id if resumed, else `None` (the shell then shows Connect).
    pub fn restore(&self) -> Result<Option<String>, ClientError> {
        self.runtime.block_on(self.client.restore())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn client_constructs_and_guards_before_connect() {
        let client = SylvaClient::new("sylva-sdk-ffi-test".to_string()).unwrap();
        // A call before connecting drives the async facade to completion (via the
        // internal runtime) and surfaces the guard error — proving the blocking
        // wrapper + delegation work end to end.
        let err = client
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
