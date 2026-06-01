// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

use std::path::Path;

use enclaveapp_core::metadata::{atomic_write, compute_meta_hmac_bytes};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// Result of a verification check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyOutcome {
    /// File matches its trust anchor.
    Match,
    /// HMAC mismatch — file has been modified outside the API.
    Tamper,
    /// No trust anchor exists yet (pre-migration or new path).
    Legacy,
    /// File does not exist.
    NotFound,
    /// Secure store is unreachable; verification was skipped (fail-open).
    StoreUnavailable,
}

/// Handle to the tamper-evident file subsystem for one app.
/// HMAC key loaded from platform secure store on construction.
pub struct TamperEvidentHandle {
    app_name: String,
    hmac_key: Option<Zeroizing<Vec<u8>>>,
}

impl std::fmt::Debug for TamperEvidentHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TamperEvidentHandle")
            .field("app_name", &self.app_name)
            .field("hmac_key_loaded", &self.hmac_key.is_some())
            .finish()
    }
}

impl TamperEvidentHandle {
    pub(crate) fn new(app_name: String) -> Self {
        let hmac_key = enclaveapp_app_storage::platform::meta_hmac_key(&app_name);
        Self { app_name, hmac_key }
    }

    /// Write `content` to `path` atomically and update the HMAC sidecar.
    pub fn write(&self, path: &Path, content: &[u8]) -> Result<()> {
        atomic_write(path, content).map_err(Error::from)?;

        if let Some(key) = &self.hmac_key {
            let tag = compute_meta_hmac_bytes(key.as_slice(), content);
            let hex = bytes_to_hex(&tag);
            let sidecar = sidecar_path(path);
            atomic_write(&sidecar, hex.as_bytes()).map_err(Error::from)?;
        }
        Ok(())
    }

    /// Read `path` and verify its HMAC sidecar.
    /// Returns `Error::TamperDetected` if the HMAC doesn't match.
    pub fn read(&self, path: &Path) -> Result<Vec<u8>> {
        if !path.exists() {
            return Err(Error::KeyNotFound {
                label: path.display().to_string(),
            });
        }
        let outcome = self.verify(path)?;
        match outcome {
            VerifyOutcome::Match | VerifyOutcome::Legacy | VerifyOutcome::StoreUnavailable => {}
            VerifyOutcome::Tamper => {
                return Err(Error::TamperDetected {
                    path: path.display().to_string(),
                });
            }
            VerifyOutcome::NotFound => {
                return Err(Error::KeyNotFound {
                    label: path.display().to_string(),
                });
            }
        }
        std::fs::read(path).map_err(Error::Io)
    }

    /// Verify `path` without reading content.
    pub fn verify(&self, path: &Path) -> Result<VerifyOutcome> {
        if !path.exists() {
            return Ok(VerifyOutcome::NotFound);
        }
        let key = match &self.hmac_key {
            Some(k) => k,
            None => return Ok(VerifyOutcome::StoreUnavailable),
        };
        let sidecar = sidecar_path(path);
        if !sidecar.exists() {
            return Ok(VerifyOutcome::Legacy);
        }
        let content = std::fs::read(path).map_err(Error::Io)?;
        let stored_hex = std::fs::read_to_string(&sidecar).map_err(Error::Io)?;
        let stored_hex = stored_hex.trim();

        let computed = compute_meta_hmac_bytes(key.as_slice(), &content);
        let computed_hex = bytes_to_hex(&computed);

        // Constant-time comparison.
        if stored_hex.len() != computed_hex.len() {
            return Ok(VerifyOutcome::Tamper);
        }
        let mut diff: u8 = 0;
        for (a, b) in stored_hex.bytes().zip(computed_hex.bytes()) {
            diff |= a ^ b;
        }
        if diff == 0 {
            Ok(VerifyOutcome::Match)
        } else {
            Ok(VerifyOutcome::Tamper)
        }
    }

    /// Write HMAC sidecar for an existing file (idempotent).
    pub fn migrate(&self, path: &Path) -> Result<()> {
        if !path.exists() {
            return Err(Error::KeyNotFound {
                label: path.display().to_string(),
            });
        }
        let key = match &self.hmac_key {
            Some(k) => k,
            None => return Ok(()), // Can't migrate without a key; fail-open.
        };
        let content = std::fs::read(path).map_err(Error::Io)?;
        let tag = compute_meta_hmac_bytes(key.as_slice(), &content);
        let hex = bytes_to_hex(&tag);
        let sidecar = sidecar_path(path);
        atomic_write(&sidecar, hex.as_bytes()).map_err(Error::from)
    }

    /// Delete the HMAC sidecar for `path`. Does not delete the file itself.
    pub fn remove_integrity_data(&self, path: &Path) -> Result<()> {
        let sidecar = sidecar_path(path);
        if sidecar.exists() {
            std::fs::remove_file(&sidecar).map_err(Error::Io)?;
        }
        Ok(())
    }

    /// App name this handle was created for.
    pub fn app_name(&self) -> &str {
        &self.app_name
    }
}

fn sidecar_path(path: &Path) -> std::path::PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".hmac");
    std::path::PathBuf::from(s)
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let hi = (b >> 4) as usize;
        let lo = (b & 0xf) as usize;
        const HEX: &[u8] = b"0123456789abcdef";
        s.push(HEX[hi] as char);
        s.push(HEX[lo] as char);
    }
    s
}
