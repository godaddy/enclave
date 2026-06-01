// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

use enclaveapp_app_storage::{BackendKind, EncryptionStorage};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// Handle to an encryption backend. Single-key for Phase 1.
/// Obtained from `create_encryptor()`.
pub struct EncryptorHandle {
    inner: Box<dyn EncryptionStorage>,
    backend_kind: BackendKind,
}

impl std::fmt::Debug for EncryptorHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptorHandle")
            .field("backend_kind", &self.backend_kind)
            .finish()
    }
}

impl EncryptorHandle {
    pub(crate) fn new(inner: Box<dyn EncryptionStorage>, backend_kind: BackendKind) -> Self {
        Self {
            inner,
            backend_kind,
        }
    }

    /// ECIES encrypt. Wire format: [0x01 version][65B pubkey][12B nonce][ciphertext][16B tag].
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.inner.encrypt(plaintext).map_err(Error::from)
    }

    /// ECIES decrypt. Returns plaintext in a Zeroizing wrapper.
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let plaintext = self.inner.decrypt(ciphertext).map_err(Error::from)?;
        Ok(Zeroizing::new(plaintext))
    }

    pub fn backend_kind(&self) -> BackendKind {
        self.backend_kind
    }
}
