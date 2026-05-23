// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Cross-platform binary signing detection and app_name enforcement.
//!
//! Ensures unsigned (development/test) binaries can never use the same
//! identifiers as signed release binaries for ANY storage operation —
//! keychain, file paths, backend markers, keys directories, etc.

use std::sync::OnceLock;

const UNSIGNED_SUFFIX: &str = "-unsigned";

/// Returns true iff the current binary is considered "signed" for
/// identity purposes.
///
/// Detection logic:
/// 1. If the exe path contains `/target/` or `\target\`, it's a cargo
///    build → unsigned.
/// 2. On macOS: runs `codesign --verify --no-strict` — exit 0 means signed.
/// 3. On other platforms: if not in `/target/`, assumed signed (there's
///    no platform-equivalent ACL coupling concern on Windows/Linux, but
///    we still separate namespaces for development builds).
///
/// Result is cached for the process lifetime.
pub fn is_binary_signed() -> bool {
    static RESULT: OnceLock<bool> = OnceLock::new();
    *RESULT.get_or_init(|| {
        let Ok(exe) = std::env::current_exe() else {
            return false;
        };
        let path = exe.to_string_lossy();
        if path.contains("/target/") || path.contains("\\target\\") {
            return false;
        }
        is_codesigned(&exe)
    })
}

#[cfg(target_os = "macos")]
fn is_codesigned(exe: &std::path::Path) -> bool {
    std::process::Command::new("codesign")
        .args(["--verify", "--no-strict"])
        .arg(exe)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[cfg(not(target_os = "macos"))]
fn is_codesigned(_exe: &std::path::Path) -> bool {
    true
}

/// Ensures the app_name is safe for the current binary's signing state.
///
/// - **Unsigned binary**: forcibly appends `-unsigned` if not already present.
/// - **Signed binary**: returns as-is.
///
/// This function is idempotent — calling it multiple times will never
/// double-suffix.
pub fn ensure_safe_app_name(app_name: &str) -> String {
    if is_binary_signed() || app_name.ends_with(UNSIGNED_SUFFIX) {
        app_name.to_string()
    } else {
        format!("{app_name}{UNSIGNED_SUFFIX}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsigned_binary_gets_suffix() {
        assert_eq!(ensure_safe_app_name("gocode-dev"), "gocode-dev-unsigned");
        assert_eq!(ensure_safe_app_name("sshenc"), "sshenc-unsigned");
    }

    #[test]
    fn already_suffixed_not_doubled() {
        assert_eq!(
            ensure_safe_app_name("gocode-dev-unsigned"),
            "gocode-dev-unsigned"
        );
    }

    #[test]
    fn is_binary_signed_false_in_tests() {
        assert!(!is_binary_signed());
    }
}
