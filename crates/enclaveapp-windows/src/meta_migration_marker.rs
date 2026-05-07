// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Windows Credential-Manager-backed marker indicating that the
//! one-time meta-integrity migration has completed for this install.
//!
//! See `docs/design-meta-hmac-trust-anchor.md`. This is the Windows
//! analogue of `enclaveapp-apple::meta_migration_marker`.
//!
//! ## Why Credential Manager, not a file
//!
//! The marker exists to distinguish "first time after upgrade" from
//! "second time, this is suspicious." A free-floating file in
//! `%APPDATA%` is trivially `del`-able by a same-UID attacker —
//! exactly the deletion primitive that re-opens the auto-migrate hole
//! the trust anchor closes. Credential Manager binds the entry to the
//! current user's profile via DPAPI under the hood: writes go through
//! `CredWriteW` (no UI prompt), reads through `CredReadW`, and the
//! same-user attacker without code that goes through the Credential
//! Manager API surface cannot rewrite the marker by `del` alone.
//!
//! Target name: `com.godaddy.<app>.migrate-marker` — symmetric with
//! the macOS service name.
//! Type: `CRED_TYPE_GENERIC`.
//! Persistence: `CRED_PERSIST_LOCAL_MACHINE` so the marker survives
//! logoff/logon but does not roam.

// This module wraps Win32 Credential Manager APIs which require unsafe
// FFI calls.
#![allow(unsafe_code, clippy::ptr_as_ptr, unused_qualifications)]

use enclaveapp_core::{Error, Result};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{ERROR_NOT_FOUND, FILETIME};
use windows::Win32::Security::Credentials::{
    CredDeleteW, CredFree, CredReadW, CredWriteW, CREDENTIALW, CRED_PERSIST_LOCAL_MACHINE,
    CRED_TYPE_GENERIC,
};

/// Sentinel payload — presence/absence is the only signal we read,
/// the body just exists because Credential Manager rejects empty
/// blobs. Versioned so a future schema bump can be detected.
const MARKER_PAYLOAD: &[u8] = b"v1";

/// Build the wide-string target name for the marker.
fn target_name_wide(app_name: &str) -> Vec<u16> {
    format!("com.godaddy.{app_name}.migrate-marker")
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect()
}

/// Returns whether the migration marker is set for `app_name`.
///
/// `Ok(true)` — marker is present in Credential Manager.
/// `Ok(false)` — marker explicitly absent (`ERROR_NOT_FOUND`).
/// `Err(_)` — every other Credential Manager failure (corrupt
///   profile, FFI error). Callers that want to fail-open should map
///   the error to `false`; callers that want to fail-closed (the
///   CLI's "are we already migrated?" check) should bail with a clear
///   message so the user knows the recommendation can't be trusted.
pub fn is_set(app_name: &str) -> Result<bool> {
    let target = target_name_wide(app_name);
    let mut cred_ptr: *mut CREDENTIALW = std::ptr::null_mut();
    // SAFETY: `target` outlives the call; `cred_ptr` is uninitialised
    // input that CredReadW will fill on success. On failure it is not
    // dereferenced.
    let result = unsafe { CredReadW(PCWSTR(target.as_ptr()), CRED_TYPE_GENERIC, 0, &mut cred_ptr) };
    match result {
        Ok(()) => {
            // Free the LSA-allocated buffer immediately — we don't
            // need the body, presence is the signal.
            if !cred_ptr.is_null() {
                // SAFETY: pointer was just returned by CredReadW; the
                // documented free path is CredFree.
                unsafe { CredFree(cred_ptr as *const _) };
            }
            Ok(true)
        }
        Err(e) => {
            if e.code() == ERROR_NOT_FOUND.to_hresult() {
                Ok(false)
            } else {
                Err(Error::KeyOperation {
                    operation: "migrate_marker_load".into(),
                    detail: format!("CredReadW: {e}"),
                })
            }
        }
    }
}

/// Set the migration marker for `app_name`. Idempotent: replacing an
/// existing marker is fine — `CredWriteW` is upsert.
pub fn set(app_name: &str) -> Result<()> {
    let mut target = target_name_wide(app_name);
    let mut blob = MARKER_PAYLOAD.to_vec();
    let blob_size = u32::try_from(blob.len()).map_err(|_| Error::KeyOperation {
        operation: "migrate_marker_set".into(),
        detail: "payload too large".into(),
    })?;

    let credential = CREDENTIALW {
        Flags: windows::Win32::Security::Credentials::CRED_FLAGS(0),
        Type: CRED_TYPE_GENERIC,
        TargetName: windows::core::PWSTR(target.as_mut_ptr()),
        Comment: windows::core::PWSTR::null(),
        LastWritten: FILETIME::default(),
        CredentialBlobSize: blob_size,
        CredentialBlob: blob.as_mut_ptr(),
        Persist: CRED_PERSIST_LOCAL_MACHINE,
        AttributeCount: 0,
        Attributes: std::ptr::null_mut(),
        TargetAlias: windows::core::PWSTR::null(),
        UserName: windows::core::PWSTR::null(),
    };

    // SAFETY: every pointer field of `credential` either points into
    // a buffer that outlives the call (`target`, `blob`) or is null.
    // CredWriteW copies the data; nothing is retained past return.
    let result = unsafe { CredWriteW(&credential, 0) };
    // Drop the borrow projection so the buffers stay alive across the
    // unsafe call boundary.
    let _ = (&mut target, &mut blob);

    result.map_err(|e| Error::KeyOperation {
        operation: "migrate_marker_set".into(),
        detail: format!("CredWriteW: {e}"),
    })
}

/// Clear the migration marker for `app_name`. Idempotent: a missing
/// entry is reported as success.
pub fn clear(app_name: &str) -> Result<()> {
    let target = target_name_wide(app_name);
    // SAFETY: `target` outlives the call.
    let result = unsafe { CredDeleteW(PCWSTR(target.as_ptr()), CRED_TYPE_GENERIC, 0) };
    match result {
        Ok(()) => Ok(()),
        Err(e) if e.code() == ERROR_NOT_FOUND.to_hresult() => Ok(()),
        Err(e) => Err(Error::KeyOperation {
            operation: "migrate_marker_clear".into(),
            detail: format!("CredDeleteW: {e}"),
        }),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, let_underscore_drop)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn unique_app() -> String {
        format!(
            "enclaveapp-windows-migrate-marker-test-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst),
        )
    }

    #[test]
    fn target_name_format() {
        let wide = target_name_wide("sshenc");
        assert_eq!(wide.last(), Some(&0));
        let recovered = String::from_utf16(&wide[..wide.len() - 1]).unwrap();
        assert_eq!(recovered, "com.godaddy.sshenc.migrate-marker");

        let wide = target_name_wide("awsenc");
        let recovered = String::from_utf16(&wide[..wide.len() - 1]).unwrap();
        assert_eq!(recovered, "com.godaddy.awsenc.migrate-marker");
    }

    /// Real Credential Manager round-trip. Persists state in the
    /// user's credential vault under a unique app name so concurrent
    /// runs don't collide. `#[ignore]`d on default `cargo test`
    /// because it requires the user-mode Credential Manager service;
    /// stock `windows-latest` GitHub runners have it enabled, but we
    /// keep this opt-in to match the meta_hmac roundtrip pattern.
    #[test]
    #[ignore = "hits real Windows Credential Manager; run on the matrix or locally"]
    fn set_clear_roundtrip() {
        let app = unique_app();
        clear(&app).expect("clear is idempotent");
        assert!(matches!(is_set(&app), Ok(false)));

        set(&app).expect("set succeeds");
        assert!(matches!(is_set(&app), Ok(true)));

        // Replace semantics — second set still leaves marker present.
        set(&app).expect("repeat set");
        assert!(matches!(is_set(&app), Ok(true)));

        clear(&app).expect("clear succeeds");
        assert!(matches!(is_set(&app), Ok(false)));
    }
}
