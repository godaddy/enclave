// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Error types for hardware key operations.

use thiserror::Error;

/// Core error type shared across enclaveapp crates.
#[derive(Debug, Error)]
pub enum Error {
    #[error("hardware security module not available")]
    NotAvailable,

    #[error("key generation failed: {detail}")]
    GenerateFailed { detail: String },

    #[error("key not found: {label}")]
    KeyNotFound { label: String },

    #[error("duplicate key label: {label}")]
    DuplicateLabel { label: String },

    #[error("invalid key label: {reason}")]
    InvalidLabel { reason: String },

    #[error("signing failed: {detail}")]
    SignFailed { detail: String },

    #[error("encryption failed: {detail}")]
    EncryptFailed { detail: String },

    #[error("decryption failed: {detail}")]
    DecryptFailed { detail: String },

    #[error("key operation failed: {operation}: {detail}")]
    KeyOperation { operation: String, detail: String },

    #[error("config error: {0}")]
    Config(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serialization(String),
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Serialization(e.to_string())
    }
}

impl From<toml::de::Error> for Error {
    fn from(e: toml::de::Error) -> Self {
        Error::Serialization(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn display_not_available() {
        let e = Error::NotAvailable;
        assert!(e.to_string().contains("not available"));
    }

    #[test]
    fn display_generate_failed() {
        let e = Error::GenerateFailed {
            detail: "timeout".into(),
        };
        assert!(e.to_string().contains("timeout"));
    }

    #[test]
    fn display_key_not_found() {
        let e = Error::KeyNotFound {
            label: "mykey".into(),
        };
        assert!(e.to_string().contains("mykey"));
    }

    #[test]
    fn display_duplicate_label() {
        let e = Error::DuplicateLabel {
            label: "dup".into(),
        };
        assert!(e.to_string().contains("dup"));
    }

    #[test]
    fn display_invalid_label() {
        let e = Error::InvalidLabel {
            reason: "empty".into(),
        };
        assert!(e.to_string().contains("empty"));
    }

    #[test]
    fn display_sign_failed() {
        let e = Error::SignFailed {
            detail: "hw error".into(),
        };
        assert!(e.to_string().contains("hw error"));
    }

    #[test]
    fn display_encrypt_failed() {
        let e = Error::EncryptFailed {
            detail: "bad key".into(),
        };
        assert!(e.to_string().contains("bad key"));
    }

    #[test]
    fn display_decrypt_failed() {
        let e = Error::DecryptFailed {
            detail: "corrupt".into(),
        };
        assert!(e.to_string().contains("corrupt"));
    }

    #[test]
    fn display_key_operation() {
        let e = Error::KeyOperation {
            operation: "export".into(),
            detail: "not supported".into(),
        };
        let msg = e.to_string();
        assert!(msg.contains("export"));
        assert!(msg.contains("not supported"));
    }

    #[test]
    fn display_config() {
        let e = Error::Config("missing field".into());
        assert!(e.to_string().contains("missing field"));
    }

    #[test]
    fn display_serialization() {
        let e = Error::Serialization("bad json".into());
        assert!(e.to_string().contains("bad json"));
    }

    #[test]
    fn from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file missing");
        let e: Error = io_err.into();
        match &e {
            Error::Io(_) => {}
            other => panic!("expected Error::Io, got: {other}"),
        }
        assert!(e.to_string().contains("file missing"));
    }

    #[test]
    fn from_serde_json_error() {
        let json_err = serde_json::from_str::<serde_json::Value>("not json").unwrap_err();
        let e: Error = json_err.into();
        match &e {
            Error::Serialization(_) => {}
            other => panic!("expected Error::Serialization, got: {other}"),
        }
    }

    #[test]
    fn from_toml_de_error() {
        let toml_err = toml::from_str::<toml::Value>("= invalid").unwrap_err();
        let e: Error = toml_err.into();
        match &e {
            Error::Serialization(_) => {}
            other => panic!("expected Error::Serialization, got: {other}"),
        }
    }
}
