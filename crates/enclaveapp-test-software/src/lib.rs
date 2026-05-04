// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

// The p256/elliptic-curve ecosystem uses deprecated generic-array APIs
// during the 0.14 -> 1.0 transition. Allow until upstream resolves this.
#![allow(deprecated)]

//! **Test-only** software P-256 key backend.
//!
//! This crate provides the same `EnclaveKeyManager`, `EnclaveSigner`, and
//! `EnclaveEncryptor` trait implementations as the hardware backends, but
//! stores private keys as plaintext files on disk. It exists solely for
//! testing without hardware security modules.
//!
//! **Do NOT use this crate in production.** Production code should use:
//! - `enclaveapp-apple` (macOS Secure Enclave)
//! - `enclaveapp-windows` (Windows TPM 2.0)
//! - `enclaveapp-linux-tpm` (Linux TPM 2.0)
//! - `enclaveapp-keyring` (Linux keyring fallback)

mod key_storage;

#[cfg(feature = "signing")]
mod sign;

#[cfg(feature = "encryption")]
mod encrypt;

#[cfg(feature = "signing")]
pub use sign::SoftwareSigner;

#[cfg(feature = "encryption")]
pub use encrypt::SoftwareEncryptor;

pub use key_storage::is_available;
