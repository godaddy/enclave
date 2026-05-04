// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Platform detection and backend identification.

#[allow(unused_imports)]
use std::path::PathBuf;

/// Which hardware/software backend is in use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendKind {
    /// macOS Secure Enclave via CryptoKit.
    SecureEnclave,
    /// Windows TPM 2.0 via CNG.
    Tpm,
    /// WSL bridge to Windows TPM.
    TpmBridge,
    /// Keyring-backed P-256 keys (Linux without TPM).
    Keyring,
}

impl std::fmt::Display for BackendKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BackendKind::SecureEnclave => write!(f, "Secure Enclave"),
            BackendKind::Tpm => write!(f, "TPM 2.0"),
            BackendKind::TpmBridge => write!(f, "TPM 2.0 (WSL Bridge)"),
            BackendKind::Keyring => write!(f, "Keyring"),
        }
    }
}

/// Search for a WSL TPM bridge executable.
///
/// Tries in order:
/// 1. `enclaveapp_bridge::find_bridge(app_name)` (standard libenclaveapp discovery)
/// 2. Auto-derived paths: `/mnt/c/Program Files/{app_name}/{app_name}-tpm-bridge.exe`
///    and `/mnt/c/ProgramData/{app_name}/{app_name}-tpm-bridge.exe`
/// 3. Any absolute extra paths provided by the caller as explicit overrides
#[cfg(target_os = "linux")]
pub fn find_bridge_executable(app_name: &str, extra_paths: &[String]) -> Option<PathBuf> {
    // Standard libenclaveapp discovery.
    if let Some(path) = enclaveapp_bridge::find_bridge(app_name) {
        return Some(path);
    }

    // Auto-derived paths.
    let auto_paths = [
        format!("/mnt/c/Program Files/{app_name}/{app_name}-tpm-bridge.exe"),
        format!("/mnt/c/ProgramData/{app_name}/{app_name}-tpm-bridge.exe"),
    ];

    for path_str in &auto_paths {
        let path = std::path::Path::new(path_str);
        if path.exists() {
            return Some(path.to_path_buf());
        }
    }

    for path_str in extra_paths {
        let path = std::path::Path::new(path_str);
        if path.is_absolute() && path.exists() {
            return Some(path.to_path_buf());
        }
    }

    None
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn backend_kind_display() {
        assert_eq!(BackendKind::SecureEnclave.to_string(), "Secure Enclave");
        assert_eq!(BackendKind::Tpm.to_string(), "TPM 2.0");
        assert_eq!(BackendKind::TpmBridge.to_string(), "TPM 2.0 (WSL Bridge)");
        assert_eq!(BackendKind::Keyring.to_string(), "Keyring");
    }

    #[test]
    fn backend_kind_eq() {
        assert_eq!(BackendKind::SecureEnclave, BackendKind::SecureEnclave);
        assert_ne!(BackendKind::SecureEnclave, BackendKind::Tpm);
    }

    #[test]
    fn backend_kind_clone() {
        let kind = BackendKind::Tpm;
        let cloned = kind;
        assert_eq!(kind, cloned);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn find_bridge_executable_returns_none_on_dev_machine() {
        // Should return None on most dev machines (not WSL with bridge installed).
        drop(find_bridge_executable("test-app", &[]));
    }
}
