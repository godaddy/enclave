// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

// The p256/elliptic-curve ecosystem uses deprecated generic-array APIs.
// The TPM FFI modules also need unseparated literal suffixes (tss-esapi constants)
// and eprintln for user-facing warnings.
#![allow(deprecated, clippy::unseparated_literal_suffix, clippy::print_stderr)]

//! Linux TPM 2.0 backend via tss-esapi.
//!
//! Uses the kernel TPM resource manager (`/dev/tpmrm0`) or `tpm2-abrmd`.
//! Keys are stored as TPM-wrapped blobs -- the private portion is encrypted
//! by the TPM and useless without the same physical hardware.
//!
//! On musl/Alpine, tss-esapi is not available and this crate compiles as
//! empty stubs (`is_available()` returns `false`).

// tss-esapi requires glibc. On musl, everything compiles as stubs.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
mod tpm;

#[cfg(all(target_os = "linux", target_env = "gnu", feature = "signing"))]
mod sign;

#[cfg(all(target_os = "linux", target_env = "gnu", feature = "encryption"))]
mod encrypt;

#[cfg(all(target_os = "linux", target_env = "gnu", feature = "signing"))]
pub use sign::LinuxTpmSigner;

#[cfg(all(target_os = "linux", target_env = "gnu", feature = "encryption"))]
pub use encrypt::LinuxTpmEncryptor;

/// Check if a Linux TPM is available.
pub fn is_available() -> bool {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    {
        tpm::is_available()
    }
    #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    #[test]
    #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
    fn is_available_returns_false_on_non_linux() {
        assert!(!super::is_available());
    }

    #[test]
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    fn is_available_returns_bool_on_linux() {
        // Just verify it doesn't panic — actual TPM may or may not be present
        let _ = super::is_available();
    }
}
