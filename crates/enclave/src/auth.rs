// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

use crate::error::{Error, Result};
use crate::types::BackendKind;

/// Capabilities of the current platform's authentication subsystem.
#[derive(Debug, Clone)]
pub struct AuthCapabilities {
    /// Biometric authenticator available (Touch ID, Windows Hello fingerprint).
    pub biometric_available: bool,
    /// Password/PIN fallback available in the same auth flow.
    pub password_available: bool,
    /// Presence prompts can be cached across ops within a TTL (macOS LAContext only).
    pub presence_caching: bool,
    /// Human-readable authenticator name, if known.
    pub authenticator_name: Option<String>,
}

/// Handle to the platform authentication subsystem.
/// Obtained from `create_auth()`.
#[derive(Debug)]
pub struct AuthHandle {
    backend_kind: BackendKind,
}

impl AuthHandle {
    pub(crate) fn new(backend_kind: BackendKind) -> Self {
        Self { backend_kind }
    }

    pub fn capabilities(&self) -> AuthCapabilities {
        platform_auth_capabilities()
    }

    /// Request user-presence verification. Returns Ok(()) if granted.
    /// `reason` is shown in the OS prompt.
    ///
    /// Note: in the current implementation, presence is enforced per-operation
    /// via sign_with_presence(). Standalone presence acquisition will be
    /// fully implemented in Phase 2.
    pub fn request_presence(&self, _reason: &str) -> Result<()> {
        if !self.capabilities().biometric_available {
            return Err(Error::PresenceNotAvailable);
        }
        // Phase 2: integrate LAContext/UserConsentVerifier standalone flow.
        Ok(())
    }

    /// Evict any cached presence token. No-op on platforms without caching.
    pub fn evict_presence_cache(&self) {
        // No-op until Phase 2 integrates standalone LAContext management.
    }

    pub fn backend_kind(&self) -> BackendKind {
        self.backend_kind
    }
}

/// Standalone helper — no handle required.
#[allow(clippy::needless_return, unreachable_code)]
pub fn platform_auth_capabilities() -> AuthCapabilities {
    #[cfg(target_os = "macos")]
    let available = enclaveapp_apple::touch_id_available();

    #[cfg(target_os = "macos")]
    return AuthCapabilities {
        biometric_available: available,
        password_available: true,
        presence_caching: true,
        authenticator_name: Some("Touch ID".into()),
    };

    #[cfg(target_os = "windows")]
    return AuthCapabilities {
        biometric_available: true,
        password_available: true,
        presence_caching: false,
        authenticator_name: Some("Windows Hello".into()),
    };

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    AuthCapabilities {
        biometric_available: false,
        password_available: false,
        presence_caching: false,
        authenticator_name: None,
    }
}
