// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use crate::types::{AccessPolicy, BackendKind};

pub use enclaveapp_core::signing::is_binary_signed;

/// True iff the running binary has the named keychain-access-groups entitlement.
/// On macOS, runs `codesign -d --entitlements -` and checks for the group string.
/// On other platforms, always returns false.
/// Result is cached per group string.
pub fn has_keychain_entitlement(group: &str) -> bool {
    #[cfg(target_os = "macos")]
    {
        static CACHE: OnceLock<Mutex<HashMap<String, bool>>> = OnceLock::new();
        let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
        let mut guard = cache.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(&result) = guard.get(group) {
            return result;
        }
        let result = check_entitlement_macos(group);
        guard.insert(group.to_string(), result);
        result
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = group;
        false
    }
}

#[cfg(target_os = "macos")]
fn check_entitlement_macos(group: &str) -> bool {
    let exe = match std::env::current_exe() {
        Ok(e) => e,
        Err(_) => return false,
    };
    // codesign -d --entitlements - writes the plist to stderr on older macOS.
    let output = std::process::Command::new("codesign")
        .args(["-d", "--entitlements", "-", "--xml"])
        .arg(&exe)
        .output();
    match output {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            let stderr = String::from_utf8_lossy(&o.stderr);
            stdout.contains(group) || stderr.contains(group)
        }
        Err(_) => false,
    }
}

/// Full description of the security tier available to the current binary on the current platform.
#[derive(Debug, Clone)]
pub struct SecurityCapabilities {
    /// Binary is code-signed. When false, app_name has `-unsigned` appended.
    pub binary_signed: bool,
    /// Hardware security backend detected.
    pub backend: BackendKind,
    /// Effective keychain access group, if any.
    pub effective_keychain_group: Option<String>,
    /// Keychain items are bound to this binary's code signature.
    pub code_signature_binding: bool,
    /// User-presence gates the keychain wrapping key.
    pub keychain_user_presence: bool,
    /// Platform can enforce user-presence at hardware/OS level.
    pub hardware_presence: bool,
    /// Presence prompts can be cached across operations within a TTL.
    pub presence_caching: bool,
    /// Effective app_name after -unsigned suffix applied (if applicable).
    pub effective_app_name: String,
    /// Features requested that were silently downgraded.
    pub downgraded_features: Vec<String>,
    /// Recommended AccessPolicy for new keys given the current security tier.
    pub recommended_access_policy: AccessPolicy,
}

/// Query capabilities without creating any handles.
pub fn security_capabilities(app_name: &str) -> SecurityCapabilities {
    let signed = is_binary_signed();
    let effective_app_name = enclaveapp_core::signing::ensure_safe_app_name(app_name);
    let backend = detect_backend();

    #[cfg(target_os = "macos")]
    let hardware_presence = enclaveapp_apple::touch_id_available();
    #[cfg(target_os = "windows")]
    let hardware_presence = true;
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    let hardware_presence = false;

    let presence_caching = cfg!(target_os = "macos");

    let recommended_access_policy = if signed {
        AccessPolicy::None
    } else {
        AccessPolicy::Any
    };

    SecurityCapabilities {
        binary_signed: signed,
        backend,
        effective_keychain_group: None,
        code_signature_binding: false,
        keychain_user_presence: false,
        hardware_presence,
        presence_caching,
        effective_app_name,
        downgraded_features: Vec::new(),
        recommended_access_policy,
    }
}

#[allow(clippy::needless_return, unreachable_code)]
fn detect_backend() -> BackendKind {
    #[cfg(target_os = "macos")]
    {
        return BackendKind::SecureEnclave;
    }
    #[cfg(target_os = "windows")]
    {
        return BackendKind::Tpm;
    }
    #[cfg(target_os = "linux")]
    {
        if enclaveapp_wsl::is_wsl() {
            return BackendKind::TpmBridge;
        }
        return BackendKind::Keyring;
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    BackendKind::Keyring
}
