// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Format conversion helpers: P1363 <-> DER signatures, ECCPUBLIC_BLOB parsing,
//! and key name generation.
//!
//! These are pure logic with no Windows API dependency, so they compile and test
//! on every platform.

use enclaveapp_core::Error;

/// Build the CNG key name from an application name and label.
///
/// All keys managed by this crate are named `{app_name}-{label}` inside the
/// Microsoft Platform Crypto Provider.
pub fn key_name(app_name: &str, label: &str) -> String {
    format!("{app_name}-{label}")
}

/// Convert an IEEE P1363 signature (r || s, 64 bytes) to a DER-encoded
/// ECDSA-Sig-Value `SEQUENCE { INTEGER r, INTEGER s }`.
pub fn p1363_to_der(sig: &[u8]) -> Vec<u8> {
    assert!(sig.len() == 64, "P1363 signature must be 64 bytes");
    let r = &sig[0..32];
    let s = &sig[32..64];

    let r_der = int_to_der(r);
    let s_der = int_to_der(s);

    let inner_len = r_der.len() + s_der.len();
    let mut der = Vec::with_capacity(2 + inner_len);
    der.push(0x30); // SEQUENCE
    der.push(inner_len as u8);
    der.extend_from_slice(&r_der);
    der.extend_from_slice(&s_der);
    der
}

/// Convert a DER-encoded ECDSA-Sig-Value to IEEE P1363 format (r || s, 64 bytes).
pub fn der_to_p1363(der: &[u8]) -> enclaveapp_core::Result<Vec<u8>> {
    if der.len() < 6 {
        return Err(Error::KeyOperation {
            operation: "der_to_p1363".into(),
            detail: "DER too short".into(),
        });
    }
    if der[0] != 0x30 {
        return Err(Error::KeyOperation {
            operation: "der_to_p1363".into(),
            detail: format!("expected SEQUENCE tag 0x30, got 0x{:02x}", der[0]),
        });
    }
    let seq_len = der[1] as usize;
    if der.len() < 2 + seq_len {
        return Err(Error::KeyOperation {
            operation: "der_to_p1363".into(),
            detail: "DER truncated".into(),
        });
    }

    let (r, r_end) = parse_der_integer(&der[2..])?;
    let (s, _) = parse_der_integer(&der[2 + r_end..])?;

    let mut out = vec![0_u8; 64];
    copy_integer_padded(&r, &mut out[0..32]);
    copy_integer_padded(&s, &mut out[32..64]);
    Ok(out)
}

/// Parse `BCRYPT_ECCKEY_BLOB` format into a 65-byte uncompressed SEC1 point.
///
/// The blob layout is: `{ magic: u32, cbKey: u32, X: [u8; cbKey], Y: [u8; cbKey] }`.
/// Output: `0x04 || X || Y`.
pub fn eccpublic_blob_to_sec1(blob: &[u8]) -> enclaveapp_core::Result<Vec<u8>> {
    if blob.len() < 8 {
        return Err(Error::KeyOperation {
            operation: "export_public_key".into(),
            detail: "blob too short".into(),
        });
    }
    let cb_key = u32::from_le_bytes([blob[4], blob[5], blob[6], blob[7]]) as usize;
    if blob.len() < 8 + cb_key * 2 {
        return Err(Error::KeyOperation {
            operation: "export_public_key".into(),
            detail: "blob truncated".into(),
        });
    }

    let mut point = Vec::with_capacity(1 + cb_key * 2);
    point.push(0x04);
    point.extend_from_slice(&blob[8..8 + cb_key]);
    point.extend_from_slice(&blob[8 + cb_key..8 + cb_key * 2]);

    if point.len() != 65 {
        return Err(Error::KeyOperation {
            operation: "export_public_key".into(),
            detail: format!("unexpected point size: {} (expected 65)", point.len()),
        });
    }
    Ok(point)
}

/// Build a `BCRYPT_ECCKEY_BLOB` from a 65-byte SEC1 uncompressed point.
///
/// `magic` should be the appropriate BCRYPT_ECDH_PUBLIC_P256_MAGIC or
/// BCRYPT_ECDSA_PUBLIC_P256_MAGIC value.
#[cfg_attr(not(feature = "encryption"), allow(dead_code))]
pub fn sec1_to_eccpublic_blob(point: &[u8], magic: u32) -> enclaveapp_core::Result<Vec<u8>> {
    if point.len() != 65 || point[0] != 0x04 {
        return Err(Error::KeyOperation {
            operation: "sec1_to_eccpublic_blob".into(),
            detail: "expected 65-byte uncompressed SEC1 point".into(),
        });
    }
    let cb_key: u32 = 32;
    let mut blob = Vec::with_capacity(8 + 64);
    blob.extend_from_slice(&magic.to_le_bytes());
    blob.extend_from_slice(&cb_key.to_le_bytes());
    blob.extend_from_slice(&point[1..33]); // X
    blob.extend_from_slice(&point[33..65]); // Y
    Ok(blob)
}

// ─── Internal helpers ───────────────────────────────────────────

/// Encode a big-endian unsigned integer as a DER INTEGER.
fn int_to_der(val: &[u8]) -> Vec<u8> {
    // Strip leading zeros (but keep at least one byte)
    let mut start = 0;
    while start < val.len() - 1 && val[start] == 0 {
        start += 1;
    }
    let stripped = &val[start..];

    // If the high bit is set, prepend 0x00 to keep the integer positive.
    let needs_pad = stripped[0] & 0x80 != 0;
    let len = stripped.len() + usize::from(needs_pad);

    let mut der = Vec::with_capacity(2 + len);
    der.push(0x02); // INTEGER
    der.push(len as u8);
    if needs_pad {
        der.push(0x00);
    }
    der.extend_from_slice(stripped);
    der
}

/// Parse one DER INTEGER, returning (value bytes, total consumed bytes).
fn parse_der_integer(data: &[u8]) -> enclaveapp_core::Result<(Vec<u8>, usize)> {
    if data.len() < 2 {
        return Err(Error::KeyOperation {
            operation: "parse_der_integer".into(),
            detail: "too short for INTEGER tag+length".into(),
        });
    }
    if data[0] != 0x02 {
        return Err(Error::KeyOperation {
            operation: "parse_der_integer".into(),
            detail: format!("expected INTEGER tag 0x02, got 0x{:02x}", data[0]),
        });
    }
    let len = data[1] as usize;
    if data.len() < 2 + len {
        return Err(Error::KeyOperation {
            operation: "parse_der_integer".into(),
            detail: "INTEGER truncated".into(),
        });
    }
    let value = data[2..2 + len].to_vec();
    Ok((value, 2 + len))
}

/// Copy a variable-length big-endian integer into a fixed-width buffer,
/// right-aligned with zero-padding. Strips a leading 0x00 pad if present.
fn copy_integer_padded(src: &[u8], dst: &mut [u8]) {
    // Strip the leading 0x00 padding byte if present
    let stripped = if src.len() > dst.len() && src[0] == 0x00 {
        &src[1..]
    } else {
        src
    };
    let offset = dst.len().saturating_sub(stripped.len());
    dst[offset..].copy_from_slice(stripped);
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    // ─── key_name ───────────────────────────────────────────────

    #[test]
    fn key_name_sshenc_default() {
        assert_eq!(key_name("sshenc", "default"), "sshenc-default");
    }

    #[test]
    fn key_name_awsenc_my_key() {
        assert_eq!(key_name("awsenc", "my-key"), "awsenc-my-key");
    }

    #[test]
    fn key_name_empty_parts() {
        assert_eq!(key_name("", ""), "-");
    }

    // ─── p1363_to_der ───────────────────────────────────────────

    #[test]
    fn p1363_to_der_simple() {
        let mut sig = vec![0_u8; 64];
        sig[31] = 1; // r = 1
        sig[63] = 2; // s = 2
        let der = p1363_to_der(&sig);
        assert_eq!(der[0], 0x30); // SEQUENCE
        assert_eq!(der[2], 0x02); // INTEGER (r)
        assert_eq!(der[3], 0x01); // length 1
        assert_eq!(der[4], 1); // r = 1
        assert_eq!(der[5], 0x02); // INTEGER (s)
        assert_eq!(der[6], 0x01); // length 1
        assert_eq!(der[7], 2); // s = 2
    }

    #[test]
    fn p1363_to_der_high_bit_needs_padding() {
        let mut sig = vec![0_u8; 64];
        sig[0] = 0x80;
        sig[31] = 1;
        sig[32] = 0x80;
        sig[63] = 2;
        let der = p1363_to_der(&sig);
        // r: starts with 0x80 => needs 0x00 pad => 33 bytes content + 2 header = 35
        assert_eq!(der[2], 0x02);
        assert_eq!(der[4], 0x00); // padding byte
        assert_eq!(der[5], 0x80);
    }

    #[test]
    fn p1363_to_der_all_zeros() {
        let sig = vec![0_u8; 64];
        let der = p1363_to_der(&sig);
        // r = 0, s = 0 => each is INTEGER 0x02 0x01 0x00
        assert_eq!(der, vec![0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00]);
    }

    #[test]
    fn p1363_to_der_max_values() {
        let sig = vec![0xFF; 64];
        let der = p1363_to_der(&sig);
        // Both r and s have high bit set and no leading zeros to strip,
        // so each gets a 0x00 pad: 0x02 0x21 0x00 0xFF*32 = 35 bytes each
        assert_eq!(der[0], 0x30);
        assert_eq!(der[1], 70); // 35 + 35
        assert_eq!(der[2], 0x02);
        assert_eq!(der[3], 33); // 1 pad + 32 data
        assert_eq!(der[4], 0x00); // pad
        assert_eq!(der[5], 0xFF);
    }

    #[test]
    fn p1363_to_der_leading_zeros_stripped() {
        let mut sig = vec![0_u8; 64];
        // r = 0x00 0x00 ... 0x00 0x42 (leading zeros stripped)
        sig[31] = 0x42;
        // s = 0x00 ... 0x00 0x7F (no pad needed, high bit clear)
        sig[63] = 0x7F;
        let der = p1363_to_der(&sig);
        // r: INTEGER 0x02 0x01 0x42
        assert_eq!(&der[2..5], &[0x02, 0x01, 0x42]);
        // s: INTEGER 0x02 0x01 0x7F
        assert_eq!(&der[5..8], &[0x02, 0x01, 0x7F]);
    }

    // ─── der_to_p1363 ──────────────────────────────────────────

    #[test]
    fn der_to_p1363_simple_roundtrip() {
        let mut sig = vec![0_u8; 64];
        sig[31] = 1;
        sig[63] = 2;
        let der = p1363_to_der(&sig);
        let p1363 = der_to_p1363(&der).unwrap();
        assert_eq!(p1363, sig);
    }

    #[test]
    fn der_to_p1363_high_bit_roundtrip() {
        let mut sig = vec![0_u8; 64];
        sig[0] = 0x80;
        sig[31] = 0x01;
        sig[32] = 0xFF;
        sig[63] = 0xFE;
        let der = p1363_to_der(&sig);
        let p1363 = der_to_p1363(&der).unwrap();
        assert_eq!(p1363, sig);
    }

    #[test]
    fn der_to_p1363_max_values_roundtrip() {
        let sig = vec![0xFF; 64];
        let der = p1363_to_der(&sig);
        let p1363 = der_to_p1363(&der).unwrap();
        assert_eq!(p1363, sig);
    }

    #[test]
    fn der_to_p1363_all_zeros_roundtrip() {
        let sig = vec![0_u8; 64];
        let der = p1363_to_der(&sig);
        let p1363 = der_to_p1363(&der).unwrap();
        assert_eq!(p1363, sig);
    }

    #[test]
    fn der_to_p1363_rejects_short() {
        assert!(der_to_p1363(&[0x30, 0x02, 0x02, 0x01]).is_err());
    }

    #[test]
    fn der_to_p1363_rejects_bad_tag() {
        assert!(der_to_p1363(&[0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02]).is_err());
    }

    #[test]
    fn der_to_p1363_rejects_truncated() {
        assert!(der_to_p1363(&[0x30, 0xFF, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02]).is_err());
    }

    // ─── eccpublic_blob_to_sec1 ────────────────────────────────

    #[test]
    fn eccpublic_blob_to_sec1_valid() {
        // BCRYPT_ECDSA_PUBLIC_P256_MAGIC = 0x31534345
        let magic: u32 = 0x3153_4345;
        let cb_key: u32 = 32;
        let mut blob = Vec::new();
        blob.extend_from_slice(&magic.to_le_bytes());
        blob.extend_from_slice(&cb_key.to_le_bytes());
        blob.extend_from_slice(&[0xAA; 32]); // X
        blob.extend_from_slice(&[0xBB; 32]); // Y
        let sec1 = eccpublic_blob_to_sec1(&blob).unwrap();
        assert_eq!(sec1.len(), 65);
        assert_eq!(sec1[0], 0x04);
        assert_eq!(&sec1[1..33], &[0xAA; 32]);
        assert_eq!(&sec1[33..65], &[0xBB; 32]);
    }

    #[test]
    fn eccpublic_blob_to_sec1_too_short() {
        assert!(eccpublic_blob_to_sec1(&[0; 7]).is_err());
    }

    #[test]
    fn eccpublic_blob_to_sec1_truncated_data() {
        let mut blob = Vec::new();
        blob.extend_from_slice(&0_u32.to_le_bytes()); // magic
        blob.extend_from_slice(&32_u32.to_le_bytes()); // cbKey = 32
        blob.extend_from_slice(&[0; 32]); // X only, missing Y
        assert!(eccpublic_blob_to_sec1(&blob).is_err());
    }

    #[test]
    fn eccpublic_blob_to_sec1_wrong_key_size() {
        let mut blob = Vec::new();
        blob.extend_from_slice(&0_u32.to_le_bytes());
        blob.extend_from_slice(&16_u32.to_le_bytes()); // cbKey = 16, not 32
        blob.extend_from_slice(&[0; 32]); // X(16) + Y(16) = 32 bytes
        let result = eccpublic_blob_to_sec1(&blob);
        // 1 + 16*2 = 33 != 65
        assert!(result.is_err());
    }

    // ─── sec1_to_eccpublic_blob ────────────────────────────────

    #[test]
    fn sec1_to_eccpublic_blob_roundtrip() {
        let magic: u32 = 0x3153_4345;
        let mut point = vec![0x04];
        point.extend_from_slice(&[0xAA; 32]);
        point.extend_from_slice(&[0xBB; 32]);

        let blob = sec1_to_eccpublic_blob(&point, magic).unwrap();
        let sec1 = eccpublic_blob_to_sec1(&blob).unwrap();
        assert_eq!(sec1, point);
    }

    #[test]
    fn sec1_to_eccpublic_blob_rejects_wrong_length() {
        assert!(sec1_to_eccpublic_blob(&[0x04; 33], 0).is_err());
    }

    #[test]
    fn sec1_to_eccpublic_blob_rejects_wrong_prefix() {
        let mut point = vec![0x02]; // compressed, not uncompressed
        point.extend_from_slice(&[0; 64]);
        assert!(sec1_to_eccpublic_blob(&point, 0).is_err());
    }

    // ─── int_to_der ────────────────────────────────────────────

    #[test]
    fn int_to_der_simple() {
        assert_eq!(int_to_der(&[0, 0, 1]), vec![0x02, 0x01, 0x01]);
    }

    #[test]
    fn int_to_der_high_bit_padded() {
        assert_eq!(int_to_der(&[0x80]), vec![0x02, 0x02, 0x00, 0x80]);
    }

    #[test]
    fn int_to_der_zero() {
        assert_eq!(int_to_der(&[0]), vec![0x02, 0x01, 0x00]);
    }

    #[test]
    fn int_to_der_strips_leading_zeros() {
        assert_eq!(int_to_der(&[0, 0, 0, 0x42]), vec![0x02, 0x01, 0x42]);
    }

    #[test]
    fn int_to_der_full_32_bytes_high_bit() {
        let mut val = vec![0xFF; 32];
        val[0] = 0xFF;
        let der = int_to_der(&val);
        assert_eq!(der[0], 0x02);
        assert_eq!(der[1], 33); // 0x00 + 32 bytes
        assert_eq!(der[2], 0x00);
        assert_eq!(&der[3..], &[0xFF; 32]);
    }

    // ─── Additional edge-case tests ────────────────────────────────

    #[test]
    fn p1363_to_der_asymmetric_r_s() {
        // r = 1 (tiny), s = full 32-byte value with high bit set
        let mut sig = vec![0_u8; 64];
        sig[31] = 0x01; // r = 1
                        // s = 0xFF repeated (high bit set, needs padding)
        sig[32..64].fill(0xFF);
        let der = p1363_to_der(&sig);
        // r: INTEGER 0x02 0x01 0x01 (3 bytes)
        assert_eq!(&der[2..5], &[0x02, 0x01, 0x01]);
        // s: INTEGER 0x02 0x21 0x00 0xFF*32 (35 bytes)
        assert_eq!(der[5], 0x02);
        assert_eq!(der[6], 33); // 1 pad + 32 data
        assert_eq!(der[7], 0x00); // padding
        assert_eq!(&der[8..40], &[0xFF; 32]);
        // Total sequence length = 3 + 35 = 38
        assert_eq!(der[1], 38);
        // Roundtrip
        let rt = der_to_p1363(&der).unwrap();
        assert_eq!(rt, sig);
    }

    #[test]
    fn der_to_p1363_leading_zero_edge_case() {
        // Build a DER signature where r has a leading zero pad (because
        // the original value has high bit set), and s is small.
        // r = 0x00 0x80 0x00 ... 0x01 (padded 32-byte value starting with 0x80)
        let mut sig = vec![0_u8; 64];
        sig[0] = 0x80;
        sig[31] = 0x01;
        sig[63] = 0x42; // s = 0x42
        let der = p1363_to_der(&sig);
        // The DER encoding of r should have a 0x00 leading pad
        assert_eq!(der[2], 0x02); // INTEGER tag
        assert_eq!(der[4], 0x00); // leading pad
        assert_eq!(der[5], 0x80); // actual first byte of r
                                  // Roundtrip should recover exact P1363 bytes
        let rt = der_to_p1363(&der).unwrap();
        assert_eq!(rt, sig);
    }

    #[test]
    fn eccpublic_blob_to_sec1_realistic_p256_key() {
        // Use a known NIST P-256 test vector (the generator point G).
        // G.x = 6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
        // G.y = 4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
        let x = [
            0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47, 0xF8, 0xBC, 0xE6, 0xE5, 0x63, 0xA4,
            0x40, 0xF2, 0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0, 0xF4, 0xA1, 0x39, 0x45,
            0xD8, 0x98, 0xC2, 0x96,
        ];
        let y = [
            0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B, 0x8E, 0xE7, 0xEB, 0x4A, 0x7C, 0x0F,
            0x9E, 0x16, 0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, 0xCE, 0xCB, 0xB6, 0x40, 0x68,
            0x37, 0xBF, 0x51, 0xF5,
        ];
        let magic: u32 = 0x3153_4345; // BCRYPT_ECDSA_PUBLIC_P256_MAGIC
        let cb_key: u32 = 32;
        let mut blob = Vec::new();
        blob.extend_from_slice(&magic.to_le_bytes());
        blob.extend_from_slice(&cb_key.to_le_bytes());
        blob.extend_from_slice(&x);
        blob.extend_from_slice(&y);

        let sec1 = eccpublic_blob_to_sec1(&blob).unwrap();
        assert_eq!(sec1.len(), 65);
        assert_eq!(sec1[0], 0x04);
        assert_eq!(&sec1[1..33], &x);
        assert_eq!(&sec1[33..65], &y);
    }

    #[test]
    fn sec1_to_eccpublic_blob_roundtrip_random_looking_data() {
        // Use bytes that look like a real P-256 public key (random-ish data)
        let mut point = vec![0x04_u8];
        // X coordinate: mix of byte values
        let x: [u8; 32] = [
            0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC,
            0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x99, 0xAA, 0xBB, 0xCC,
        ];
        // Y coordinate: different mix
        let y: [u8; 32] = [
            0xCA, 0xFE, 0xBA, 0xBE, 0xF0, 0x0D, 0xCA, 0xFE, 0xDE, 0xAD, 0xC0, 0xDE, 0xBA, 0xAD,
            0xF0, 0x0D, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x01, 0x02, 0x03, 0x04,
            0x05, 0x06, 0x07, 0x08,
        ];
        point.extend_from_slice(&x);
        point.extend_from_slice(&y);

        // BCRYPT_ECDH_PUBLIC_P256_MAGIC = 0x314B4345
        let magic: u32 = 0x314B_4345;
        let blob = sec1_to_eccpublic_blob(&point, magic).unwrap();

        // Verify blob structure
        assert_eq!(blob.len(), 72); // 8 header + 64 data
        assert_eq!(
            u32::from_le_bytes([blob[0], blob[1], blob[2], blob[3]]),
            magic
        );
        assert_eq!(u32::from_le_bytes([blob[4], blob[5], blob[6], blob[7]]), 32);

        // Roundtrip back to SEC1
        let sec1 = eccpublic_blob_to_sec1(&blob).unwrap();
        assert_eq!(sec1, point);
    }
}
