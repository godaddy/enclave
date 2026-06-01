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
use zeroize::Zeroizing;

use super::coffer::master_key;
use super::pool::{hot_cache_evict, hot_cache_get, hot_cache_insert, pool_acquire, PoolSlot};
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
/// Plaintext is encrypted under the process-global Coffer master key.
/// `open()` returns the plaintext in a `PoolSlot` (slab-backed if ≤ slot_size,
/// otherwise standalone `SecureBuffer`). A hot cache avoids decryption when
/// the same `MemoryEnclave` is opened multiple times in quick succession.
///
/// When dropped, the hot cache entry for this enclave is evicted.
pub struct MemoryEnclave {
    id: u64,
    /// [nonce (12 bytes)] [ciphertext + GCM tag]
    ciphertext: Vec<u8>,
    plaintext_len: usize,
}

static SEAL_ID: AtomicU64 = AtomicU64::new(1);

impl std::fmt::Debug for MemoryEnclave {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoryEnclave")
            .field("id", &self.id)
            .field("plaintext_len", &self.plaintext_len)
            .finish()
    }
}

impl MemoryEnclave {
    fn do_seal(plaintext: &[u8]) -> Result<Self> {
        let key = master_key()?;
        let nonce_bytes = next_nonce();
        let nonce = Nonce::from_slice(&nonce_bytes);

        let cipher = Aes256Gcm::new_from_slice(key.as_ref())
            .map_err(|e| Error::Memory(format!("MemoryEnclave::seal cipher init: {e}")))?;

        let ct = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| Error::Memory(format!("MemoryEnclave::seal encrypt: {e}")))?;

        let mut blob = Vec::with_capacity(NONCE_LEN + ct.len());
        blob.extend_from_slice(&nonce_bytes);
        blob.extend_from_slice(&ct);

        let id = SEAL_ID.fetch_add(1, Ordering::Relaxed);
        Ok(Self {
            id,
            ciphertext: blob,
            plaintext_len: plaintext.len(),
        })
    }

    /// Seal `plaintext` under the Coffer key.
    pub fn seal(plaintext: &[u8]) -> Result<Self> {
        Self::do_seal(plaintext)
    }

    /// Seal a `SecureBuffer`'s contents (melt → read → re-freeze).
    pub fn seal_buffer(buf: &mut SecureBuffer) -> Result<Self> {
        buf.melt()?;
        let result = Self::do_seal(buf.as_slice());
        drop(buf.freeze());
        result
    }

    /// Seal a `PoolSlot`'s contents.
    /// The caller is responsible for dropping the slot (which zeroizes it).
    pub fn seal_slot(slot: &PoolSlot) -> Result<Self> {
        Self::do_seal(slot.as_slice())
    }

    /// Decrypt and return the plaintext in a `PoolSlot`.
    ///
    /// Hot cache fast path: if this enclave was recently opened, the plaintext
    /// is copied from the cache into a new `PoolSlot` without AES-GCM decryption.
    /// The cached copy lives in regular heap memory and should not be held longer
    /// than necessary.
    pub fn open(&self) -> Result<PoolSlot> {
        // Hot cache lookup.
        if let Some(cached) = hot_cache_get(self.id) {
            let mut slot = pool_acquire(cached.len())?;
            let len = cached.len().min(slot.size());
            slot.bytes()[..len].copy_from_slice(&cached[..len]);
            return Ok(slot);
        }

        // Cold path: decrypt.
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

        // Populate hot cache before copying into slot.
        hot_cache_insert(self.id, Zeroizing::new(plaintext.clone()));

        let mut slot = pool_acquire(plaintext.len())?;
        let len = plaintext.len().min(slot.size());
        slot.bytes()[..len].copy_from_slice(&plaintext[..len]);
        Ok(slot)
    }

    pub fn plaintext_len(&self) -> usize {
        self.plaintext_len
    }

    pub fn id(&self) -> u64 {
        self.id
    }
}

impl Drop for MemoryEnclave {
    fn drop(&mut self) {
        hot_cache_evict(self.id);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::memory::pool::coffer_view;

    #[test]
    fn seal_and_open_roundtrip() {
        let secret = b"my secret data 1234";
        let enc = MemoryEnclave::seal(secret).unwrap();
        let slot = enc.open().unwrap();
        assert_eq!(&slot.as_slice()[..secret.len()], secret.as_ref());
    }

    #[test]
    fn open_twice_uses_hot_cache() {
        let secret = b"cached secret";
        let enc = MemoryEnclave::seal(secret).unwrap();
        let s1 = enc.open().unwrap();
        let s2 = enc.open().unwrap();
        assert_eq!(&s1.as_slice()[..secret.len()], secret.as_ref());
        assert_eq!(&s2.as_slice()[..secret.len()], secret.as_ref());
    }

    #[test]
    fn drop_evicts_hot_cache() {
        let secret = b"evicted secret";
        let id = {
            let enc = MemoryEnclave::seal(secret).unwrap();
            let _slot = enc.open().unwrap(); // populate cache
            enc.id()
        }; // enc dropped here — should evict
        assert!(hot_cache_get(id).is_none());
    }

    #[test]
    fn different_enclaves_are_independent() {
        let enc1 = MemoryEnclave::seal(b"secret one").unwrap();
        let enc2 = MemoryEnclave::seal(b"secret two").unwrap();
        assert_ne!(enc1.id(), enc2.id());
        let s1 = enc1.open().unwrap();
        let s2 = enc2.open().unwrap();
        assert_eq!(&s1.as_slice()[..10], b"secret one");
        assert_eq!(&s2.as_slice()[..10], b"secret two");
    }

    #[test]
    fn seal_empty_slice() {
        let enc = MemoryEnclave::seal(b"").unwrap();
        assert_eq!(enc.plaintext_len(), 0);
        let slot = enc.open().unwrap();
        drop(slot);
    }

    #[test]
    fn coffer_view_returns_key_sized_slot() {
        let slot = coffer_view().unwrap();
        assert_eq!(slot.size(), 32);
    }

    #[test]
    fn pool_acquire_small_uses_slab() {
        use crate::memory::pool::pool_acquire;
        let slot = pool_acquire(16).unwrap();
        assert!(slot.slab_index().is_some());
    }

    #[test]
    fn pool_acquire_large_uses_standalone() {
        use crate::memory::pool::pool_acquire;
        let slot = pool_acquire(8192).unwrap();
        assert!(slot.slab_index().is_none());
    }

    #[test]
    fn seal_open_large() {
        let plaintext = vec![0xAB_u8; 4096];
        let enc = MemoryEnclave::seal(&plaintext).unwrap();
        let slot = enc.open().unwrap();
        assert_eq!(&slot.as_slice()[..4096], plaintext.as_slice());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let plaintext = b"tamper test";
        let mut enc = MemoryEnclave::seal(plaintext).unwrap();
        enc.ciphertext[NONCE_LEN] ^= 0xFF;
        let result = enc.open();
        assert!(
            matches!(result, Err(Error::DecryptFailed { .. })),
            "expected DecryptFailed, got {result:?}"
        );
    }

    #[test]
    fn truncated_ciphertext_fails() {
        let enc = MemoryEnclave::seal(b"short").unwrap();
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
        let a = MemoryEnclave::seal(b"a").unwrap();
        let b = MemoryEnclave::seal(b"b").unwrap();
        assert_ne!(a.id(), b.id());
    }

    #[test]
    fn seal_buffer_roundtrip() {
        let secret = b"buffered secret";
        let mut sbuf = SecureBuffer::new(secret.len()).unwrap();
        sbuf.bytes().copy_from_slice(secret);
        let enc = MemoryEnclave::seal_buffer(&mut sbuf).unwrap();
        assert!(sbuf.is_alive());
        let slot = enc.open().unwrap();
        assert_eq!(&slot.as_slice()[..secret.len()], secret);
    }

    #[test]
    fn seal_slot_roundtrip() {
        let secret = b"slot secret data";
        let mut slot = pool_acquire(secret.len()).unwrap();
        // slot.size() may be larger than secret.len() (slab slot is DEFAULT_SLOT_SIZE).
        slot.bytes()[..secret.len()].copy_from_slice(secret);
        // seal_slot seals the full slot (slot.size() bytes), so open returns
        // at least secret.len() bytes.
        let enc = MemoryEnclave::seal_slot(&slot).unwrap();
        drop(slot);
        let out = enc.open().unwrap();
        assert_eq!(&out.as_slice()[..secret.len()], secret);
    }

    #[test]
    fn debug_does_not_leak_plaintext() {
        let enc = MemoryEnclave::seal(b"top secret").unwrap();
        let debug = format!("{enc:?}");
        assert!(!debug.contains("top secret"));
        assert!(debug.contains("MemoryEnclave"));
    }

    #[test]
    fn same_plaintext_different_nonces() {
        let a = MemoryEnclave::seal(b"same").unwrap();
        let b = MemoryEnclave::seal(b"same").unwrap();
        assert_ne!(a.ciphertext, b.ciphertext);
    }
}
