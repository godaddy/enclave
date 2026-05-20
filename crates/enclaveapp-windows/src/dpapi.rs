// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Small DPAPI helpers shared by Windows software fallback code.

#![allow(unsafe_code, unused_qualifications)]

use enclaveapp_core::{Error, Result};
use windows::Win32::Foundation::{LocalFree, HLOCAL};
use windows::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
};

/// Protect bytes with per-user DPAPI and no UI.
pub fn protect(plaintext: &[u8], operation: &'static str) -> Result<Vec<u8>> {
    let mut input = CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(plaintext.len()).map_err(|_| Error::KeyOperation {
            operation: operation.into(),
            detail: "plaintext too large".into(),
        })?,
        pbData: plaintext.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB::default();

    // SAFETY: `input` points at the borrowed plaintext for the
    // duration of the call. On success DPAPI owns `output.pbData`
    // until we copy and free it with `LocalFree`.
    let result = unsafe {
        CryptProtectData(
            &input,
            windows::core::PCWSTR::null(),
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    let _ = &mut input;

    result.map_err(|e| Error::KeyOperation {
        operation: operation.into(),
        detail: format!("CryptProtectData: {e}"),
    })?;

    copy_and_free_blob(&output, operation)
}

/// Unprotect a per-user DPAPI blob with no UI.
pub fn unprotect(blob: &[u8], operation: &'static str) -> Result<Vec<u8>> {
    let mut input = CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(blob.len()).map_err(|_| Error::KeyOperation {
            operation: operation.into(),
            detail: "blob too large".into(),
        })?,
        pbData: blob.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB::default();

    // SAFETY: same shape as `protect`; DPAPI fills `output` on
    // success, and we immediately copy and free the owned buffer.
    let result = unsafe {
        CryptUnprotectData(
            &input,
            None,
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    let _ = &mut input;

    result.map_err(|e| Error::KeyOperation {
        operation: operation.into(),
        detail: format!("CryptUnprotectData: {e}"),
    })?;

    copy_and_free_blob(&output, operation)
}

fn copy_and_free_blob(blob: &CRYPT_INTEGER_BLOB, operation: &'static str) -> Result<Vec<u8>> {
    if blob.cbData == 0 || blob.pbData.is_null() {
        return Err(Error::KeyOperation {
            operation: operation.into(),
            detail: "DPAPI returned an empty or null blob".into(),
        });
    }

    // SAFETY: DPAPI guarantees `pbData` is valid for `cbData` bytes.
    let bytes = unsafe { std::slice::from_raw_parts(blob.pbData, blob.cbData as usize) }.to_vec();
    // SAFETY: `pbData` was allocated by DPAPI with LocalAlloc.
    let freed = unsafe { LocalFree(HLOCAL(blob.pbData.cast())) };
    if !freed.is_invalid() {
        return Err(Error::KeyOperation {
            operation: operation.into(),
            detail: "LocalFree failed for DPAPI output".into(),
        });
    }
    Ok(bytes)
}
