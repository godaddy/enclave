// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Public key export from NCrypt key handles.

// This module wraps NCrypt C APIs which require unsafe FFI calls.
#![allow(unsafe_code, unused_qualifications)]

use crate::convert::eccpublic_blob_to_sec1;
use crate::provider::NcryptHandle;
use windows::core::PCWSTR;
use windows::Win32::Security::Cryptography::*;

/// Export a public key from an NCrypt key handle.
///
/// Calls `NCryptExportKey` with `ECCPUBLICBLOB` and converts from the
/// `BCRYPT_ECCKEY_BLOB` layout to a 65-byte SEC1 uncompressed point.
pub fn export_public_key(key_handle: &NcryptHandle) -> enclaveapp_core::Result<Vec<u8>> {
    let blob_type: Vec<u16> = "ECCPUBLICBLOB"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut blob_size: u32 = 0;

    // Query required size.
    unsafe {
        NCryptExportKey(
            key_handle.as_key(),
            NCRYPT_KEY_HANDLE::default(),
            PCWSTR(blob_type.as_ptr()),
            None,
            None,
            &mut blob_size,
            NCRYPT_FLAGS::default(),
        )
        .map_err(|e| enclaveapp_core::Error::KeyOperation {
            operation: "export_public_key (size)".into(),
            detail: e.to_string(),
        })?;
    }

    // Export the blob.
    let mut blob = vec![0_u8; blob_size as usize];
    unsafe {
        NCryptExportKey(
            key_handle.as_key(),
            NCRYPT_KEY_HANDLE::default(),
            PCWSTR(blob_type.as_ptr()),
            None,
            Some(&mut blob),
            &mut blob_size,
            NCRYPT_FLAGS::default(),
        )
        .map_err(|e| enclaveapp_core::Error::KeyOperation {
            operation: "export_public_key".into(),
            detail: e.to_string(),
        })?;
    }
    blob.truncate(blob_size as usize);

    eccpublic_blob_to_sec1(&blob)
}
