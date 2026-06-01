// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

use enclaveapp_app_storage::{AppSigningBackend, BackendKind};

use enclaveapp_core::types::{AccessPolicy, KeyType};

use crate::error::{Error, Result};
use crate::types::{KeyInfo, PresenceOptions};

/// Handle to a signing backend. Obtained from `create_signer()`.
///
/// Multi-key: each method takes a `label` parameter. The factory
/// initializes the backend and ensures the `default_key_label` exists.
pub struct SignerHandle {
    backend: AppSigningBackend,
    backend_kind: BackendKind,
}

impl std::fmt::Debug for SignerHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignerHandle")
            .field("backend_kind", &self.backend_kind)
            .finish()
    }
}

impl SignerHandle {
    pub(crate) fn new(backend: AppSigningBackend, backend_kind: BackendKind) -> Self {
        Self {
            backend,
            backend_kind,
        }
    }

    /// Generate a new P-256 signing key. Returns uncompressed SEC1 public key.
    pub fn generate_key(&self, label: &str, policy: AccessPolicy) -> Result<Vec<u8>> {
        // BiometricOnly / PasswordOnly are only hardware-enforceable on macOS.
        if !cfg!(target_os = "macos") {
            match policy {
                AccessPolicy::BiometricOnly | AccessPolicy::PasswordOnly => {
                    return Err(Error::PolicyNotSupported {
                        policy: format!("{policy:?}"),
                    });
                }
                AccessPolicy::None | AccessPolicy::Any => {}
            }
        }
        self.backend
            .key_manager()
            .generate(label, KeyType::Signing, policy)
            .map_err(Error::from)
    }

    /// Return the uncompressed SEC1 public key for an existing key.
    pub fn public_key(&self, label: &str) -> Result<Vec<u8>> {
        self.backend
            .key_manager()
            .public_key(label)
            .map_err(Error::from)
    }

    /// Sign `data` (SHA-256 applied internally). Returns DER-encoded ECDSA signature.
    pub fn sign(&self, label: &str, data: &[u8]) -> Result<Vec<u8>> {
        self.backend.signer().sign(label, data).map_err(Error::from)
    }

    /// Sign with optional user-presence prompt.
    ///
    /// - `PresenceMode::Strict` on a platform where `presence_available()` is false
    ///   returns `Error::PresenceNotAvailable`.
    /// - `PresenceMode::Cached` or `PresenceMode::None` always falls through to a
    ///   plain sign on non-macOS platforms (no error).
    pub fn sign_with_presence(
        &self,
        label: &str,
        data: &[u8],
        opts: &PresenceOptions,
    ) -> Result<Vec<u8>> {
        use enclaveapp_core::types::PresenceMode;
        if opts.mode == PresenceMode::Strict && !self.presence_available() {
            return Err(Error::PresenceNotAvailable);
        }
        self.backend
            .signer()
            .sign_with_presence(label, data, opts.mode, opts.cache_ttl_secs, &opts.reason)
            .map_err(Error::from)
    }

    /// True when the current platform supports presence prompting.
    pub fn presence_available(&self) -> bool {
        #[cfg(target_os = "macos")]
        return enclaveapp_apple::touch_id_available();
        #[cfg(not(target_os = "macos"))]
        false
    }

    pub fn list_keys(&self) -> Result<Vec<KeyInfo>> {
        let labels = self
            .backend
            .key_manager()
            .list_keys()
            .map_err(Error::from)?;
        let mut infos = Vec::with_capacity(labels.len());
        for label in labels {
            if let Ok(pub_key) = self.backend.key_manager().public_key(&label) {
                infos.push(KeyInfo {
                    label,
                    key_type: KeyType::Signing,
                    access_policy: AccessPolicy::None,
                    public_key: pub_key,
                });
            }
        }
        Ok(infos)
    }

    pub fn delete_key(&self, label: &str) -> Result<()> {
        self.backend
            .key_manager()
            .delete_key(label)
            .map_err(Error::from)
    }

    pub fn key_exists(&self, label: &str) -> Result<bool> {
        self.backend
            .key_manager()
            .key_exists(label)
            .map_err(Error::from)
    }

    pub fn rename_key(&self, old_label: &str, new_label: &str) -> Result<()> {
        self.backend
            .key_manager()
            .rename_key(old_label, new_label)
            .map_err(Error::from)
    }

    pub fn evict_presence_cache(&self, label: &str) {
        self.backend.signer().evict_wrapping_key_cache(label);
    }

    pub fn backend_kind(&self) -> BackendKind {
        self.backend_kind
    }
}
