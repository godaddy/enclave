// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Error types for application-level storage operations.

use thiserror::Error;

/// Errors from application storage initialization and operations.
#[derive(Error, Debug)]
pub enum StorageError {
    #[error("hardware security module not available")]
    NotAvailable,
    #[error("encryption failed: {0}")]
    EncryptionFailed(String),
    #[error("decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("signing failed: {0}")]
    SigningFailed(String),
    #[error("key initialization failed: {0}")]
    KeyInitFailed(String),
    #[error("key not found: {0}")]
    KeyNotFound(String),
    #[error("key policy mismatch: {0}")]
    PolicyMismatch(String),
    #[error("platform error: {0}")]
    PlatformError(String),
}

pub type Result<T> = std::result::Result<T, StorageError>;
