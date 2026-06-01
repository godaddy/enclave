// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

// aes-gcm's Nonce::from_slice still works but triggers a deprecation on
// the underlying generic_array usage in some versions.
#![allow(deprecated)]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use rand::TryRngCore;

use super::coffer::master_key;
use super::secure_buffer::SecureBuffer;
use crate::error::{Error, Result};

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

static NONCE_PREFIX: OnceLock<[u8; 4]> = OnceLock::new();
static NONCE_COUNTER: AtomicU64 = AtomicU64::new(0);

fn nonce_prefix() -> &'static [u8; 4] {
    NONCE_PREFIX.get_or_init(|| {
        let mut prefix = [0_u8; 4];
        if rand::rngs::OsRng.try_fill_bytes(&mut prefix).is_err() {
            // Fallback: mix PID into a deterministic value.
            // This is not cryptographically ideal but avoids a panic.
            let pid = std::process::id();
            prefix[0] = (pid & 0xFF) as u8;
            prefix[1] = ((pid >> 8) & 0xFF) as u8;
            prefix[2] = ((pid >> 16) & 0xFF) as u8;
            prefix[3] = ((pid >> 24) & 0xFF) as u8;
        }
        prefix
    })
}

fn next_nonce() -> [u8; NONCE_LEN] {
    let counter = NONCE_COUNTER.fetch_add(1, Ordering::SeqCst);
    let mut nonce = [0_u8; NONCE_LEN];
    nonce[..4].copy_from_slice(nonce_prefix());
    nonce[4..].copy_from_slice(&counter.to_le_bytes());
    nonce
}

/// An in-memory AES-256-GCM sealed secret.
///
/// Plaintext is encrypted under the process-global Coffer master key
/// (stored XOR-split in locked memory). The ciphertext lives in a
/// regular heap `Vec<u8>`; the plaintext is only exposed briefly during
/// `open()`, inside a `SecureBuffer` (guard pages + mlock).
///
/// This defends against heap-scraping attacks on long-lived processes:
/// even if an attacker reads process memory between `seal()` and `open()`,
/// they see ciphertext rather than the secret.
pub struct MemoryEnclave {
    id: u64,
    /// [nonce (12 bytes)] [ciphertext] [GCM tag (16 bytes)]
    ciphertext: Vec<u8>,
    plaintext_len: usize,
}

impl std::fmt::Debug for MemoryEnclave {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoryEnclave")
            .field("id", &self.id)
            .field("plaintext_len", &self.plaintext_len)
            .finish()
    }
}

static SEAL_ID: AtomicU64 = AtomicU64::new(1);

impl MemoryEnclave {
    /// Seal `plaintext` under the process Coffer key. Returns a `MemoryEnclave`
    /// holding only ciphertext. The caller is responsible for zeroizing `plaintext`
    /// after calling this (use `Zeroizing` or a `SecureBuffer`).
    pub fn seal(plaintext: &[u8]) -> Result<Self> {
        let key = master_key()?;
        let nonce_bytes = next_nonce();
        let nonce = Nonce::from_slice(&nonce_bytes);

        let cipher = Aes256Gcm::new_from_slice(key.as_ref())
            .map_err(|e| Error::Memory(format!("MemoryEnclave::seal cipher init: {e}")))?;

        let mut ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| Error::Memory(format!("MemoryEnclave::seal encrypt: {e}")))?;

        // Prepend nonce so open() is self-contained.
        let mut blob = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        blob.extend_from_slice(&nonce_bytes);
        blob.append(&mut ciphertext);

        let id = SEAL_ID.fetch_add(1, Ordering::Relaxed);

        Ok(Self {
            id,
            ciphertext: blob,
            plaintext_len: plaintext.len(),
        })
    }

    /// Seal a `SecureBuffer`'s contents. Equivalent to `seal(buf.as_slice())`.
    pub fn seal_buffer(buf: &mut SecureBuffer) -> Result<Self> {
        buf.melt()?;
        let result = Self::seal(buf.as_slice());
        // Re-freeze regardless of seal outcome.
        drop(buf.freeze());
        result
    }

    /// Decrypt and return the plaintext in a `SecureBuffer` (guard pages + mlock).
    pub fn open(&self) -> Result<SecureBuffer> {
        if self.ciphertext.len() < NONCE_LEN + TAG_LEN {
            return Err(Error::Memory(
                "MemoryEnclave::open: ciphertext too short".into(),
            ));
        }

        let key = master_key()?;
        let nonce = Nonce::from_slice(&self.ciphertext[..NONCE_LEN]);

        let cipher = Aes256Gcm::new_from_slice(key.as_ref())
            .map_err(|e| Error::Memory(format!("MemoryEnclave::open cipher init: {e}")))?;

        let plaintext = cipher
            .decrypt(nonce, &self.ciphertext[NONCE_LEN..])
            .map_err(|_| Error::DecryptFailed {
                detail: "MemoryEnclave::open: authentication failed".into(),
            })?;

        let mut buf = SecureBuffer::new(plaintext.len())?;
        buf.bytes().copy_from_slice(&plaintext);
        buf.freeze()?;
        Ok(buf)
    }

    /// Length of the original plaintext.
    pub fn plaintext_len(&self) -> usize {
        self.plaintext_len
    }

    /// Unique per-process identifier for this sealed secret.
    pub fn id(&self) -> u64 {
        self.id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip() {
        let plaintext = b"super secret value";
        let enc = MemoryEnclave::seal(plaintext).expect("seal failed");
        assert_eq!(enc.plaintext_len(), plaintext.len());
        let buf = enc.open().expect("open failed");
        assert_eq!(buf.as_slice(), plaintext);
    }

    #[test]
    fn seal_open_empty() {
        let enc = MemoryEnclave::seal(b"").expect("seal empty failed");
        assert_eq!(enc.plaintext_len(), 0);
        let buf = enc.open().expect("open empty failed");
        assert_eq!(buf.as_slice(), b"");
    }

    #[test]
    fn seal_open_large() {
        let plaintext = vec![0xAB_u8; 4096];
        let enc = MemoryEnclave::seal(&plaintext).expect("seal large failed");
        let buf = enc.open().expect("open large failed");
        assert_eq!(buf.as_slice(), plaintext.as_slice());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let plaintext = b"tamper test";
        let mut enc = MemoryEnclave::seal(plaintext).expect("seal failed");
        // Flip a byte in the ciphertext (after the nonce).
        enc.ciphertext[NONCE_LEN] ^= 0xFF;
        let result = enc.open();
        assert!(
            matches!(result, Err(Error::DecryptFailed { .. })),
            "expected DecryptFailed, got {result:?}"
        );
    }

    #[test]
    fn truncated_ciphertext_fails() {
        let enc = MemoryEnclave::seal(b"short").expect("seal failed");
        // Create a version with a too-short ciphertext blob.
        let truncated = MemoryEnclave {
            id: enc.id,
            ciphertext: vec![0_u8; NONCE_LEN + TAG_LEN - 1],
            plaintext_len: 5,
        };
        let result = truncated.open();
        assert!(
            matches!(result, Err(Error::Memory(_))),
            "expected Memory error, got {result:?}"
        );
    }

    #[test]
    fn unique_ids() {
        let a = MemoryEnclave::seal(b"a").expect("seal a");
        let b = MemoryEnclave::seal(b"b").expect("seal b");
        assert_ne!(a.id(), b.id());
    }

    #[test]
    fn multiple_opens_identical() {
        let plaintext = b"open me twice";
        let enc = MemoryEnclave::seal(plaintext).expect("seal failed");
        let buf1 = enc.open().expect("open 1");
        let buf2 = enc.open().expect("open 2");
        assert_eq!(buf1.as_slice(), buf2.as_slice());
    }

    #[test]
    fn seal_buffer_roundtrip() {
        let secret = b"buffered secret";
        let mut sbuf = SecureBuffer::new(secret.len()).expect("sbuf alloc");
        sbuf.bytes().copy_from_slice(secret);
        let enc = MemoryEnclave::seal_buffer(&mut sbuf).expect("seal_buffer");
        // sbuf should be re-frozen after seal_buffer.
        assert!(sbuf.is_alive());
        let out = enc.open().expect("open after seal_buffer");
        assert_eq!(out.as_slice(), secret);
    }

    #[test]
    fn debug_does_not_leak_plaintext() {
        let enc = MemoryEnclave::seal(b"top secret").expect("seal");
        let debug = format!("{enc:?}");
        assert!(!debug.contains("top secret"));
        assert!(debug.contains("MemoryEnclave"));
    }

    #[test]
    fn different_plaintexts_different_ciphertexts() {
        let a = MemoryEnclave::seal(b"aaa").expect("seal a");
        let b = MemoryEnclave::seal(b"bbb").expect("seal b");
        assert_ne!(a.ciphertext, b.ciphertext);
    }

    #[test]
    fn same_plaintext_different_nonces() {
        // Due to counter-based nonces, sealing the same plaintext twice
        // must produce different ciphertexts (different nonces).
        let a = MemoryEnclave::seal(b"same").expect("seal a");
        let b = MemoryEnclave::seal(b"same").expect("seal b");
        assert_ne!(a.ciphertext, b.ciphertext);
    }
}
