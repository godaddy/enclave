// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Hardware-enforced Windows Hello consent via the Win32 WebAuthn
//! platform authenticator.
//!
//! ## Why this crate exists
//!
//! `enclaveapp-windows::hello` calls `UserConsentVerifier`, which is
//! a *user-mode UI* gate -- a `Verified` return is just a Boolean
//! that an attacker with code execution as the user can hook and
//! overwrite. The TPM key on the Microsoft Platform Crypto Provider
//! has no hardware UI gate when Hello is enrolled (we drop
//! `NCRYPT_UI_PROTECT_KEY_FLAG` to avoid the legacy CryptUI password
//! dialog), so the only thing keeping a malicious local process from
//! signing is the agent's own check of that Boolean.
//!
//! This crate provides the *hardware-enforced* path. The Win32
//! `WebAuthn.dll` platform authenticator generates and stores
//! ECDSA P-256 keypairs *inside the TPM* via the same NGC infra
//! that backs Windows Hello for Business, and `GetAssertion` won't
//! produce a signature without the OS-mediated Hello gesture
//! actually firing. There is no user-mode "fake yes" that yields
//! a valid signature.
//!
//! ## What this is NOT
//!
//! This is not a passkey manager. The credentials we produce are
//! addressed by `credential_id` (opaque blob the TPM emits), not by
//! "the user's passkey for example.com" -- although Windows still
//! shows the "save your passkey" UX once at make-time because that's
//! the canonical platform-authenticator enrollment flow.
//!
//! ## SSH-SK wire format
//!
//! Output is shaped to feed `sk-ecdsa-sha2-nistp256@openssh.com`,
//! the OpenSSH 8.2+ FIDO2-SK key type. The signed payload is
//! `authenticator_data || SHA-256(client_data)`; the SSH verifier
//! reconstructs the same shape. Caller passes the raw SSH-side
//! sign payload as `client_data`; Win32 hashes it with SHA-256 and
//! signs the result. See `PROTOCOL.u2f` in OpenSSH for the full
//! verification rules.
//!
//! ## Cross-platform
//!
//! This crate compiles to no-op stubs on non-Windows targets so
//! workspace-wide builds don't break. Calls return `NotAvailable`.

#[cfg(target_os = "windows")]
mod windows_impl;

#[cfg(target_os = "windows")]
pub use windows_impl::{
    delete_platform_credential, get_assertion, is_platform_authenticator_available,
    make_credential, GetAssertionParams, MakeCredentialParams,
};

#[cfg(not(target_os = "windows"))]
mod stub;

#[cfg(not(target_os = "windows"))]
pub use stub::{
    delete_platform_credential, get_assertion, is_platform_authenticator_available,
    make_credential, GetAssertionParams, MakeCredentialParams,
};

/// Result of a successful `make_credential` call.
#[derive(Debug, Clone)]
pub struct WebAuthnCredential {
    /// Opaque credential identifier returned by the platform
    /// authenticator. The TPM uses this to address the wrapped key
    /// material; we store it alongside the SSH key metadata.
    pub credential_id: Vec<u8>,
    /// Uncompressed X coordinate of the ECDSA P-256 public key.
    pub public_key_x: [u8; 32],
    /// Uncompressed Y coordinate of the ECDSA P-256 public key.
    pub public_key_y: [u8; 32],
    /// Raw `authenticator_data` from the make-credential response.
    /// Caller may discard once `credential_id` and pubkey are
    /// extracted; retained here for diagnostic / audit use.
    pub authenticator_data: Vec<u8>,
    /// True if the authenticator created a *resident* credential
    /// (passkey-style; OS holds the credential metadata in addition
    /// to the wrapped private key). Windows Hello platform
    /// authenticator typically creates resident credentials
    /// regardless of the `prefer_resident_key` hint.
    pub resident: bool,
}

/// Result of a successful `get_assertion` call.
#[derive(Debug, Clone)]
pub struct WebAuthnAssertion {
    /// DER-encoded ECDSA signature (`SEQUENCE { INTEGER r, INTEGER s }`).
    /// Convert to the OpenSSH SK signature format
    /// (`mpint r, mpint s`) before emitting on the SSH wire.
    pub signature_der: Vec<u8>,
    /// Authenticator data the TPM signed alongside the client-data
    /// hash. Includes the rpIdHash (32 bytes), flags byte, and
    /// 4-byte big-endian counter the SK signature blob requires.
    pub authenticator_data: Vec<u8>,
    /// `authenticator_data[32]`. Bit 0 = User Present,
    /// bit 2 = User Verified, bit 6 = Attested Credential Data.
    pub flags: u8,
    /// Big-endian u32 from `authenticator_data[33..37]`. The TPM
    /// increments this on every assertion; ssh verifiers can
    /// (optionally) check monotonicity for replay detection.
    pub counter: u32,
}

/// Errors from the WebAuthn platform-authenticator path.
#[derive(Debug, thiserror::Error)]
pub enum WebAuthnError {
    /// Platform authenticator (Hello) is not available on this host.
    /// Either Hello is not enrolled or webauthn.dll is missing
    /// (very old Windows 10 builds).
    #[error("Windows Hello platform authenticator is not available")]
    NotAvailable,

    /// User canceled the Hello prompt or the OS dismissed it.
    /// Callers should treat this as a soft failure -- the user
    /// declined consent for this specific operation.
    #[error("user canceled the Windows Hello prompt")]
    UserCanceled,

    /// Hello prompt timed out waiting for the user.
    #[error("Windows Hello prompt timed out")]
    Timeout,

    /// Underlying WebAuthn API returned an error we don't have a
    /// more specific variant for.
    #[error("WebAuthn API error 0x{hr:08x}: {name}")]
    Backend { hr: u32, name: String },

    /// Response from WebAuthn was structurally invalid (missing
    /// fields, malformed CBOR, etc.). Indicates an API contract
    /// drift -- either we're misusing it or Microsoft changed
    /// something.
    #[error("invalid WebAuthn response: {0}")]
    InvalidResponse(String),
}

/// Result alias used throughout the crate.
pub type Result<T> = core::result::Result<T, WebAuthnError>;
