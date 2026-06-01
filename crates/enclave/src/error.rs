// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("hardware security module not available")]
    NotAvailable,
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
    #[error("authentication denied for '{label}'")]
    AuthDenied { label: String },
    #[error("authentication required for '{label}': {detail}")]
    AuthRequired { label: String, detail: String },
    #[error("user cancelled authentication for '{label}'")]
    UserCancelled { label: String },
    #[error("key operation failed — {operation}: {detail}")]
    KeyOperation { operation: String, detail: String },
    #[error("tamper detected: {path}")]
    TamperDetected { path: String },
    /// Returned from factory construction (not first use) when a config option
    /// requires a code-signed binary with the named entitlement/feature.
    #[error("feature '{feature}' requires a code-signed binary")]
    RequiresSigning { feature: String },
    /// Returned from generate_key() when the backend cannot enforce the
    /// requested AccessPolicy (e.g. BiometricOnly on Linux keyring/TPM).
    #[error("access policy '{policy}' is not supported by the current backend")]
    PolicyNotSupported { policy: String },
    /// Returned from sign_with_presence() when PresenceMode::Strict is
    /// requested but the platform has no user-presence support.
    #[error("user presence is not available on this platform")]
    PresenceNotAvailable,
    #[error("config error: {0}")]
    Config(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("memory error: {0}")]
    Memory(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl From<enclaveapp_core::Error> for Error {
    fn from(e: enclaveapp_core::Error) -> Self {
        use enclaveapp_core::Error as CE;
        match e {
            CE::NotAvailable => Error::NotAvailable,
            CE::KeyNotFound { label } => Error::KeyNotFound { label },
            CE::DuplicateLabel { label } => Error::DuplicateLabel { label },
            CE::InvalidLabel { reason } => Error::InvalidLabel { reason },
            CE::SignFailed { detail } => Error::SignFailed { detail },
            CE::EncryptFailed { detail } => Error::EncryptFailed { detail },
            CE::DecryptFailed { detail } => Error::DecryptFailed { detail },
            CE::KeychainAuthDenied { label } => Error::AuthDenied { label },
            CE::KeychainInteractionRequired { label } => Error::AuthRequired {
                label,
                detail: "screen may be locked; unlock and retry".into(),
            },
            CE::KeychainNoWindowServer { label } => Error::AuthRequired {
                label,
                detail: "no GUI session; restart agent via launchd".into(),
            },
            CE::UserCancelled { label } => Error::UserCancelled { label },
            CE::KeyOperation { operation, detail } => Error::KeyOperation { operation, detail },
            CE::GenerateFailed { detail } => Error::KeyOperation {
                operation: "generate".into(),
                detail,
            },
            CE::Config(s) | CE::Serialization(s) => Error::Config(s),
            CE::Io(e) => Error::Io(e),
        }
    }
}

impl From<enclaveapp_app_storage::StorageError> for Error {
    fn from(e: enclaveapp_app_storage::StorageError) -> Self {
        use enclaveapp_app_storage::StorageError as SE;
        match e {
            SE::NotAvailable => Error::NotAvailable,
            SE::EncryptionFailed(s) => Error::EncryptFailed { detail: s },
            SE::DecryptionFailed(s) => Error::DecryptFailed { detail: s },
            SE::SigningFailed(s) => Error::SignFailed { detail: s },
            SE::KeyInitFailed(s) => Error::KeyOperation {
                operation: "init".into(),
                detail: s,
            },
            SE::KeyNotFound(s) => Error::KeyNotFound { label: s },
            SE::PolicyMismatch(s) => Error::KeyOperation {
                operation: "policy_check".into(),
                detail: s,
            },
            SE::PlatformError(s) => Error::KeyOperation {
                operation: "platform".into(),
                detail: s,
            },
        }
    }
}
