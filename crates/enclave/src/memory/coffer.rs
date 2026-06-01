// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

use std::sync::{Mutex, OnceLock};

use rand::TryRngCore;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::secure_buffer::SecureBuffer;

const KEY_LEN: usize = 32;

struct CofferInner {
    /// Stores: master_key XOR SHA-256(right)
    left: SecureBuffer,
    /// Stores: random right half
    right: SecureBuffer,
}

impl CofferInner {
    fn generate() -> crate::error::Result<Self> {
        // Generate random master key and right half.
        let mut master_key = Zeroizing::new([0_u8; KEY_LEN]);
        let mut right_bytes = [0_u8; KEY_LEN];
        rand::rngs::OsRng
            .try_fill_bytes(master_key.as_mut())
            .map_err(|e| crate::error::Error::Memory(format!("coffer keygen OsRng: {e}")))?;
        rand::rngs::OsRng
            .try_fill_bytes(&mut right_bytes)
            .map_err(|e| crate::error::Error::Memory(format!("coffer right OsRng: {e}")))?;

        // Compute SHA-256(right).
        let right_hash: [u8; 32] = Sha256::digest(right_bytes).into();

        // left_stored = master_key XOR SHA-256(right)
        let mut left_stored = [0_u8; KEY_LEN];
        for i in 0..KEY_LEN {
            left_stored[i] = master_key[i] ^ right_hash[i];
        }

        let mut left_buf = SecureBuffer::new(KEY_LEN)?;
        left_buf.bytes().copy_from_slice(&left_stored);
        left_buf.freeze()?;

        let mut right_buf = SecureBuffer::new(KEY_LEN)?;
        right_buf.bytes().copy_from_slice(&right_bytes);
        right_buf.freeze()?;

        Ok(Self {
            left: left_buf,
            right: right_buf,
        })
    }

    /// Reconstruct the master key. Returns a Zeroizing array.
    fn master_key(&mut self) -> crate::error::Result<Zeroizing<[u8; KEY_LEN]>> {
        self.left.melt()?;
        self.right.melt()?;

        let right_hash: [u8; 32] = Sha256::digest(self.right.as_slice()).into();

        let mut key = Zeroizing::new([0_u8; KEY_LEN]);
        for i in 0..KEY_LEN {
            key[i] = self.left.as_slice()[i] ^ right_hash[i];
        }

        self.left.freeze()?;
        self.right.freeze()?;

        Ok(key)
    }
}

static COFFER: OnceLock<Mutex<CofferInner>> = OnceLock::new();

fn coffer() -> &'static Mutex<CofferInner> {
    COFFER.get_or_init(|| {
        Mutex::new(
            CofferInner::generate()
                .expect("MemoryEnclave: coffer key generation failed — OsRng unavailable"),
        )
    })
}

/// Reconstruct and return the process master key.
/// The returned `Zeroizing` array is zeroed when dropped.
pub(super) fn master_key() -> crate::error::Result<Zeroizing<[u8; KEY_LEN]>> {
    let mut guard = coffer().lock().unwrap_or_else(|e| e.into_inner());
    guard.master_key()
}
