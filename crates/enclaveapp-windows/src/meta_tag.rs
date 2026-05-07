// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Per-key meta-integrity tag stored in Windows Credential Manager.
//!
//! See `docs/design-meta-hmac-trust-anchor.md` for the rationale; this
//! is the Windows analogue of `enclaveapp-apple::meta_tag`.
//!
//! ## Mechanism
//!
//! The first attempt at this module used a custom CNG property
//! (`NCryptSetProperty(handle, L"sshenc-meta-tag", …)`) on the
//! persisted Microsoft Platform Crypto Provider key. That FFI returns
//! `NTE_NOT_SUPPORTED (0x80090029)` on real Windows 11 + Hello-enrolled
//! hosts: the TPM-backed provider only accepts a fixed allowlist of
//! property names (`NCRYPT_UI_POLICY`, `NCRYPT_LENGTH_PROPERTY`, etc.)
//! and rejects custom names regardless of the buffer payload. The
//! porting doc anticipated this — Credential Manager is the documented
//! fallback.
//!
//! For each key `<label>`, we persist a 32-byte HMAC-SHA256 tag of the
//! key's `<label>.meta` JSON contents as a `CRED_TYPE_GENERIC` /
//! `CRED_PERSIST_LOCAL_MACHINE` Credential Manager entry under target
//! name `com.godaddy.<app>.meta-tag.<label>`. The entry is bound to
//! the current Windows user (Credential Manager applies DPAPI under
//! the hood), persists across logoff/logon, and does not roam.
//!
//! At every per-op load (sign / public_key) we recompute the HMAC of
//! the on-disk `.meta` and compare it (constant-time) against the
//! Credential-Manager-stored tag. Mismatch is **tamper**; missing
//! entry on an existing key is **legacy_meta** (user must run
//! `sshenc migrate-meta`); both refuse the operation.
//!
//! The on-disk `<label>.meta.hmac` sidecar is a derivable cache: it
//! continues to be written for crash-resilience and forensic
//! comparison, but it is **not** the trust anchor. Deleting the
//! sidecar does not change the verification outcome — the Credential
//! Manager tag is the authority. This closes the auto-migrate hole
//! where a same-UID attacker could `del` the sidecar to force a
//! re-bless of tampered meta JSON.
//!
//! ## Trust domain
//!
//! Reading or writing the entry uses `CredReadW` / `CredWriteW` /
//! `CredDeleteW`. The store is per-user; an attacker without the
//! current user's Windows credentials cannot decrypt or rewrite. A
//! same-UID attacker process *can* call CredDelete to remove the
//! entry (the deletion-primitive analogue), but this still surfaces
//! as `VerifyOutcome::Legacy` — and after `migrate-meta` runs once,
//! the migration marker switches the `legacy_meta` error to its
//! strong-tamper variant. So the deletion primitive is observable,
//! not silently exploitable.
//!
//! Same trust domain as the existing `.meta-hmac.dpapi` blob and the
//! migration marker.

// This module wraps Win32 Credential Manager APIs which require unsafe
// FFI calls.
#![allow(unsafe_code, clippy::ptr_as_ptr, unused_qualifications)]

use enclaveapp_core::{Error, Result};
use std::path::Path;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{ERROR_NOT_FOUND, FILETIME};
use windows::Win32::Security::Credentials::{
    CredDeleteW, CredFree, CredReadW, CredWriteW, CREDENTIALW, CRED_FLAGS,
    CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC,
};
use zeroize::Zeroize;

/// Length of the meta-integrity tag in bytes (HMAC-SHA256 output).
pub const META_TAG_LEN: usize = 32;

/// Outcome of a meta-integrity verification against the on-disk
/// `.meta` file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyOutcome {
    /// Entry has a tag and it matches the recomputed HMAC of the
    /// on-disk `.meta`. Caller proceeds with the operation.
    Match,
    /// Entry has a tag but it does not match the on-disk `.meta`.
    /// Caller MUST refuse the operation (tamper).
    Tamper,
    /// No entry for this label — pre-trust-anchor key, or the entry
    /// was removed out of band. Caller MUST refuse the operation and
    /// surface the legacy-meta error message that points at
    /// `sshenc migrate-meta`.
    Legacy,
    /// On-disk `.meta` does not exist. Caller's "key not found" flow
    /// applies; no verification was needed. Distinct from `Legacy` so
    /// the caller can distinguish "no key" from "untagged key".
    NoMeta,
    /// Credential Manager unreachable. Verification could not run.
    /// Caller decides whether this is fatal or fail-open; current
    /// consumers treat it as fail-open to match the existing
    /// wrapping-key load behavior.
    KeychainUnavailable,
}

/// Build the per-key Credential Manager target name.
fn target_name_wide(app_name: &str, label: &str) -> Vec<u16> {
    format!("com.godaddy.{app_name}.meta-tag.{label}")
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect()
}

/// Persist or replace the meta-integrity tag for `(app_name, label)`.
/// Idempotent: an existing tag for the same key is overwritten.
/// `CredWriteW` is upsert.
pub fn store(app_name: &str, label: &str, tag: &[u8]) -> Result<()> {
    if tag.len() != META_TAG_LEN {
        return Err(Error::KeyOperation {
            operation: "meta_tag_store".into(),
            detail: format!("tag must be {META_TAG_LEN} bytes, got {}", tag.len()),
        });
    }
    let mut target = target_name_wide(app_name, label);
    let mut blob = tag.to_vec();
    let blob_size = u32::try_from(blob.len()).map_err(|_| Error::KeyOperation {
        operation: "meta_tag_store".into(),
        detail: "tag too large".into(),
    })?;

    let credential = CREDENTIALW {
        Flags: CRED_FLAGS(0),
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

    // SAFETY: every pointer field of `credential` either points into a
    // buffer that outlives the call (`target`, `blob`) or is null.
    // CredWriteW copies the data; nothing is retained past return.
    let result = unsafe { CredWriteW(&credential, 0) };
    let _ = (&mut target, &mut blob);

    blob.zeroize();
    result.map_err(|e| Error::KeyOperation {
        operation: "meta_tag_store".into(),
        detail: format!("CredWriteW: {e}"),
    })
}

/// Load the meta-integrity tag for `(app_name, label)`. Returns:
///
/// - `Ok(Some(tag))` on a successful Credential Manager read.
/// - `Ok(None)` for the explicit not-found case (`ERROR_NOT_FOUND`,
///   1168). Surfaces as `Legacy` from `verify`.
/// - `Err` for every other failure. [`verify`] maps these to
///   `KeychainUnavailable` (fail-open) so a transient store hiccup
///   doesn't brick access.
pub fn load(app_name: &str, label: &str) -> Result<Option<[u8; META_TAG_LEN]>> {
    let target = target_name_wide(app_name, label);
    let mut cred_ptr: *mut CREDENTIALW = std::ptr::null_mut();
    // SAFETY: `target` outlives the call; `cred_ptr` is uninitialised
    // input that CredReadW fills on success. On failure it is not
    // dereferenced.
    let result = unsafe { CredReadW(PCWSTR(target.as_ptr()), CRED_TYPE_GENERIC, 0, &mut cred_ptr) };
    match result {
        Ok(()) => {
            if cred_ptr.is_null() {
                return Err(Error::KeyOperation {
                    operation: "meta_tag_load".into(),
                    detail: "CredReadW returned success with null pointer".into(),
                });
            }
            // SAFETY: CredReadW returned success with a non-null
            // pointer; the LSA-allocated CREDENTIALW outlives this
            // borrow and we copy its blob bytes into a local array
            // before calling CredFree.
            let cred = unsafe { &*cred_ptr };
            let len = cred.CredentialBlobSize as usize;
            if len != META_TAG_LEN {
                // SAFETY: pointer was returned by CredReadW.
                unsafe { CredFree(cred_ptr as *const _) };
                return Err(Error::KeyOperation {
                    operation: "meta_tag_load".into(),
                    detail: format!(
                        "loaded meta tag has unexpected length {len}, expected {META_TAG_LEN}"
                    ),
                });
            }
            let mut out = [0_u8; META_TAG_LEN];
            // SAFETY: CredentialBlob points to `len` bytes (we just
            // checked it equals META_TAG_LEN). Source and dest do not
            // overlap.
            unsafe {
                std::ptr::copy_nonoverlapping(cred.CredentialBlob, out.as_mut_ptr(), META_TAG_LEN);
            }
            // SAFETY: pointer was returned by CredReadW; documented
            // free path is CredFree.
            unsafe { CredFree(cred_ptr as *const _) };
            Ok(Some(out))
        }
        Err(e) => {
            if e.code() == ERROR_NOT_FOUND.to_hresult() {
                Ok(None)
            } else {
                tracing::debug!(label = %label, error = %e, "meta_tag_load: CredReadW failed");
                Err(Error::KeyOperation {
                    operation: "meta_tag_load".into(),
                    detail: format!("CredReadW: {e}"),
                })
            }
        }
    }
}

/// Delete the meta-integrity tag for `(app_name, label)`. Idempotent:
/// missing entry is success.
pub fn delete(app_name: &str, label: &str) -> Result<()> {
    let target = target_name_wide(app_name, label);
    // SAFETY: `target` outlives the call.
    let result = unsafe { CredDeleteW(PCWSTR(target.as_ptr()), CRED_TYPE_GENERIC, 0) };
    match result {
        Ok(()) => Ok(()),
        Err(e) if e.code() == ERROR_NOT_FOUND.to_hresult() => Ok(()),
        Err(e) => Err(Error::KeyOperation {
            operation: "meta_tag_delete".into(),
            detail: format!("CredDeleteW: {e}"),
        }),
    }
}

/// Recompute and store the meta-integrity tag for `(app_name, label)`
/// from the current on-disk `<label>.meta` content.
///
/// Used at the end of the higher-level keygen flow after every meta-
/// mutating step (the `app_specific` fields the sshenc CLI / agent
/// layer adds — `comment`, `pub_file_path`, `presence_mode` — land
/// AFTER the platform backend's `generate` returns, so a tag stamped
/// inline in the platform backend is invalidated by the time keygen
/// completes). Calling `stamp_from_disk` once at the end stamps the
/// authoritative final meta. Idempotent with the inline stamp; the
/// CredWriteW call upserts.
pub fn stamp_from_disk(
    app_name: &str,
    label: &str,
    keys_dir: &Path,
    meta_hmac_key: &[u8],
) -> Result<()> {
    let meta_path = keys_dir.join(format!("{label}.meta"));
    let meta_bytes = std::fs::read(&meta_path).map_err(|e| Error::KeyOperation {
        operation: "meta_tag_stamp".into(),
        detail: format!("read {}: {e}", meta_path.display()),
    })?;
    let tag = enclaveapp_core::metadata::compute_meta_hmac_bytes(meta_hmac_key, &meta_bytes);
    store(app_name, label, &tag)
}

/// Move the meta-integrity tag from `old_label` to `new_label`.
/// Idempotent on the source: a missing source tag is treated as
/// "nothing to move" and returns Ok. The destination is overwritten
/// if a tag already exists there.
///
/// Note: the Windows TPM backend currently refuses key-rename outright
/// (CNG keys are immutable by name), so this function is here for API
/// parity with macOS but is not exercised by the agent today.
pub fn rename(app_name: &str, old_label: &str, new_label: &str) -> Result<()> {
    if let Some(tag) = load(app_name, old_label)? {
        store(app_name, new_label, &tag)?;
        delete(app_name, old_label)?;
    }
    Ok(())
}

/// Verify the on-disk `<label>.meta` against the Credential-Manager-
/// stored integrity tag for `(app_name, label)`.
///
/// This is the per-op trust-anchor check. The caller passes the
/// process-loaded meta-HMAC key (from [`crate::meta_hmac`]) so this
/// function does not perform a second secure-store round-trip on
/// every call. The meta-HMAC key is loaded once at agent startup and
/// cached; the per-key tag is the only thing read here.
pub fn verify(
    app_name: &str,
    label: &str,
    keys_dir: &Path,
    meta_hmac_key: &[u8],
) -> Result<VerifyOutcome> {
    let meta_path = keys_dir.join(format!("{label}.meta"));
    if !meta_path.exists() {
        return Ok(VerifyOutcome::NoMeta);
    }
    let stored = match load(app_name, label) {
        Ok(Some(tag)) => tag,
        Ok(None) => return Ok(VerifyOutcome::Legacy),
        Err(_) => return Ok(VerifyOutcome::KeychainUnavailable),
    };

    let meta_bytes = std::fs::read(&meta_path).map_err(|e| Error::KeyOperation {
        operation: "meta_tag_verify".into(),
        detail: format!("read {}: {e}", meta_path.display()),
    })?;
    let actual = enclaveapp_core::metadata::compute_meta_hmac_bytes(meta_hmac_key, &meta_bytes);

    let mut diff: u8 = 0;
    for i in 0..META_TAG_LEN {
        diff |= stored[i] ^ actual[i];
    }
    if diff == 0 {
        Ok(VerifyOutcome::Match)
    } else {
        Ok(VerifyOutcome::Tamper)
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
            "enclaveapp-windows-meta-tag-test-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst),
        )
    }

    #[test]
    fn target_name_format() {
        let wide = target_name_wide("sshenc", "default");
        assert_eq!(wide.last(), Some(&0));
        let recovered = String::from_utf16(&wide[..wide.len() - 1]).unwrap();
        assert_eq!(recovered, "com.godaddy.sshenc.meta-tag.default");

        let wide = target_name_wide("awsenc", "prod-key");
        let recovered = String::from_utf16(&wide[..wide.len() - 1]).unwrap();
        assert_eq!(recovered, "com.godaddy.awsenc.meta-tag.prod-key");
    }

    #[test]
    fn verify_no_meta_when_file_missing() {
        let dir = std::env::temp_dir().join(format!(
            "meta-tag-test-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let outcome = verify(&unique_app(), "missing-label", &dir, &[0_u8; 32]).unwrap();
        assert_eq!(outcome, VerifyOutcome::NoMeta);
        drop(std::fs::remove_dir_all(&dir));
    }

    #[test]
    fn store_rejects_wrong_length_tag() {
        let result = store(&unique_app(), "label", &[0_u8; 16]);
        assert!(result.is_err());
        let result = store(&unique_app(), "label", &[0_u8; 33]);
        assert!(result.is_err());
    }

    /// Real Credential Manager round-trip — store, load, verify-match,
    /// tamper, verify-tamper, delete, verify-legacy. Persists state in
    /// the user's credential vault under a unique app name so
    /// concurrent test runs don't collide. `#[ignore]`d by default
    /// because it persists state outside the workspace; opt-in via
    /// `cargo test -- --ignored` on the matrix-test laptop.
    #[test]
    #[ignore = "hits real Windows Credential Manager; run on the matrix or locally"]
    fn end_to_end_roundtrip() {
        let app = unique_app();
        let label = "roundtrip-key";
        let dir = std::env::temp_dir().join(format!(
            "meta-tag-test-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let meta_path = dir.join(format!("{label}.meta"));
        let meta_content = b"{\"label\":\"roundtrip-key\",\"presence_mode\":\"strict\"}";
        std::fs::write(&meta_path, meta_content).unwrap();

        let hmac_key = [0x55_u8; 32];
        let tag = enclaveapp_core::metadata::compute_meta_hmac_bytes(&hmac_key, meta_content);

        store(&app, label, &tag).expect("store");
        let outcome = verify(&app, label, &dir, &hmac_key).expect("verify match");
        assert_eq!(outcome, VerifyOutcome::Match);

        std::fs::write(
            &meta_path,
            b"{\"label\":\"roundtrip-key\",\"presence_mode\":\"none\"}",
        )
        .unwrap();
        let outcome = verify(&app, label, &dir, &hmac_key).expect("verify tamper");
        assert_eq!(outcome, VerifyOutcome::Tamper);

        delete(&app, label).expect("delete");
        let outcome = verify(&app, label, &dir, &hmac_key).expect("verify legacy");
        assert_eq!(outcome, VerifyOutcome::Legacy);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
