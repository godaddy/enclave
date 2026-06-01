// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

#![allow(unsafe_code)]

use std::collections::VecDeque;
use std::sync::{Mutex, OnceLock};

use zeroize::Zeroizing;

use super::secure_buffer::SecureBuffer;
use super::slab::{SecureSlab, DEFAULT_SLOT_SIZE};
use crate::error::{Error, Result};

/// Maximum number of recently-decrypted MemoryEnclaves kept in the hot cache.
const HOT_CACHE_MAX: usize = 8;

// ── Pool slot origin ────────────────────────────────────────────────

enum PoolSlotOrigin {
    /// Slot lives in the global slab. Index is the slot number.
    Slab { index: usize },
    /// Slot owns a standalone guard-paged buffer (size > slab slot_size, or slab exhausted).
    Standalone(SecureBuffer),
}

/// A handle to a locked memory region containing secret data.
///
/// The slot is either backed by a slab slot (mlock'd single-page pool) or a
/// standalone `SecureBuffer` (guard pages + mlock, for larger allocations).
///
/// `PoolSlot` is `Send` but NOT `Sync`; exclusive reference semantics prevent
/// concurrent mutation.
///
/// # Safety of the slab pointer
///
/// When origin is `Slab`, `ptr` points into the global `SecureSlab` which lives
/// in a `OnceLock<Mutex<Pool>>` and is never dropped for the process lifetime.
/// The pointer therefore cannot dangle as long as the process is alive.
pub struct PoolSlot {
    ptr: *mut u8,
    len: usize,
    origin: PoolSlotOrigin,
}

unsafe impl Send for PoolSlot {}

impl std::fmt::Debug for PoolSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PoolSlot").field("len", &self.len).finish()
    }
}

impl PoolSlot {
    fn from_slab(ptr: *mut u8, len: usize, index: usize) -> Self {
        Self {
            ptr,
            len,
            origin: PoolSlotOrigin::Slab { index },
        }
    }

    fn from_standalone(mut buf: SecureBuffer) -> Self {
        // buf starts Mutable (freshly allocated); melt is a no-op if already mutable.
        drop(buf.melt());
        let ptr = buf.bytes().as_mut_ptr();
        let len = buf.size();
        Self {
            ptr,
            len,
            origin: PoolSlotOrigin::Standalone(buf),
        }
    }

    /// Mutable access to the slot's bytes.
    pub fn bytes(&mut self) -> &mut [u8] {
        // Safety: ptr is valid for len bytes (either in global slab or standalone buf).
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) }
    }

    /// Read-only access to the slot's bytes.
    pub fn as_slice(&self) -> &[u8] {
        // Safety: ptr is valid for len bytes; no aliased mutable reference exists
        // because PoolSlot is not Sync.
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }

    /// Total capacity of this slot in bytes.
    pub fn size(&self) -> usize {
        self.len
    }

    /// Returns the slab slot index if this slot is backed by the global slab.
    #[allow(dead_code)]
    pub(crate) fn slab_index(&self) -> Option<usize> {
        match &self.origin {
            PoolSlotOrigin::Slab { index } => Some(*index),
            PoolSlotOrigin::Standalone(_) => None,
        }
    }
}

impl Drop for PoolSlot {
    fn drop(&mut self) {
        match &mut self.origin {
            PoolSlotOrigin::Slab { index } => {
                // Zeroize here before acquiring the pool lock, so the memory is
                // clean even if the lock is contended.
                // Safety: ptr points into the global slab page which is alive.
                unsafe {
                    let s = std::slice::from_raw_parts_mut(self.ptr, self.len);
                    use zeroize::Zeroize;
                    s.zeroize();
                }
                // Return slot to slab (slab.release also zeroizes, which is redundant
                // but harmless).
                if let Ok(mut guard) = global_pool().lock() {
                    guard.slab.release(*index);
                }
            }
            PoolSlotOrigin::Standalone(buf) => {
                // Zeroize before buf's own drop, which also zeroizes.
                drop(buf.melt());
                // Safety: ptr points into buf's inner region which is still alive.
                unsafe {
                    let s = std::slice::from_raw_parts_mut(self.ptr, self.len);
                    use zeroize::Zeroize;
                    s.zeroize();
                }
                // buf drops here: zeroizes again + unmaps.
            }
        }
    }
}

// ── Hot cache ─────────────────────────────────────────────────────

/// Entry in the hot cache: (enclave_id, plaintext_copy).
/// Stored as `Zeroizing<Vec<u8>>` so evicted entries are zeroed automatically.
struct HotEntry {
    id: u64,
    plaintext: Zeroizing<Vec<u8>>,
}

struct HotCache {
    /// Front = LRU (oldest), back = MRU (newest).
    entries: VecDeque<HotEntry>,
}

impl HotCache {
    fn new() -> Self {
        Self {
            entries: VecDeque::with_capacity(HOT_CACHE_MAX),
        }
    }

    /// Look up and return a copy of the plaintext. Promotes the entry to MRU.
    ///
    /// The returned copy lives in regular heap memory; it should be consumed
    /// promptly and not stored long-term, as it is not mlock'd.
    fn get(&mut self, id: u64) -> Option<Zeroizing<Vec<u8>>> {
        let pos = self.entries.iter().position(|e| e.id == id)?;
        let entry = self.entries.remove(pos)?;
        let copy = Zeroizing::new((*entry.plaintext).clone());
        self.entries.push_back(HotEntry {
            id: entry.id,
            plaintext: entry.plaintext,
        });
        Some(copy)
    }

    /// Insert plaintext for `id`. Evicts LRU if at capacity.
    fn insert(&mut self, id: u64, plaintext: Zeroizing<Vec<u8>>) {
        // Remove existing entry for same id if present.
        self.entries.retain(|e| e.id != id);
        // Evict LRU if full.
        if self.entries.len() >= HOT_CACHE_MAX {
            drop(self.entries.pop_front()); // Zeroizing drop zeroes the plaintext.
        }
        self.entries.push_back(HotEntry { id, plaintext });
    }

    /// Evict the entry for `id` if present.
    fn evict(&mut self, id: u64) {
        self.entries.retain(|e| e.id != id);
    }
}

// ── Global pool ───────────────────────────────────────────────────

struct Pool {
    slab: SecureSlab,
    hot_cache: HotCache,
}

fn global_pool() -> &'static Mutex<Pool> {
    static POOL: OnceLock<Mutex<Pool>> = OnceLock::new();
    POOL.get_or_init(|| {
        let slab = SecureSlab::new(DEFAULT_SLOT_SIZE)
            .expect("enclave: global pool SecureSlab init failed");
        Mutex::new(Pool {
            slab,
            hot_cache: HotCache::new(),
        })
    })
}

/// Acquire a pool slot for `size` bytes.
///
/// - If `size <= slab.slot_size()`: attempts to acquire a slab slot.
///   Waits up to 30 s for one to become available, then falls back to
///   a standalone buffer.
/// - If `size > slab.slot_size()`: immediately allocates a standalone
///   guard-paged `SecureBuffer`.
pub fn pool_acquire(size: usize) -> Result<PoolSlot> {
    let slot_size = {
        global_pool()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .slab
            .slot_size()
    };

    if size <= slot_size {
        // Try slab first with spin-wait up to 30 s.
        let deadline = std::time::Instant::now() + super::slab::SLOT_WAIT_TIMEOUT;
        loop {
            {
                let mut guard = global_pool().lock().unwrap_or_else(|e| e.into_inner());
                if let Some(index) = guard.slab.find_free_slot() {
                    guard
                        .slab
                        .checkout(index)
                        .map_err(|e| Error::Memory(format!("pool_acquire checkout: {e}")))?;
                    let (ptr, len) = guard.slab.slot_raw(index);
                    return Ok(PoolSlot::from_slab(ptr, len, index));
                }
            }
            if std::time::Instant::now() >= deadline {
                tracing::warn!(
                    size,
                    "pool_acquire: slab exhausted after 30 s; \
                     falling back to standalone SecureBuffer"
                );
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    // Standalone fallback (or size > slot_size).
    let buf = SecureBuffer::new(size)?;
    Ok(PoolSlot::from_standalone(buf))
}

/// Release a pool slot. The slot's contents are zeroized.
/// Prefer dropping the `PoolSlot` directly; this is provided for explicit release.
pub fn pool_release(slot: PoolSlot) {
    drop(slot);
}

/// Get a `PoolSlot` containing the Coffer master key.
/// Release promptly after use; holding it blocks coffer key rotation.
pub fn coffer_view() -> Result<PoolSlot> {
    let key = super::coffer::master_key()?;
    let mut slot = pool_acquire(key.len())?;
    slot.bytes().copy_from_slice(key.as_ref());
    Ok(slot)
}

/// Insert plaintext into the hot cache for `id`.
pub(super) fn hot_cache_insert(id: u64, plaintext: Zeroizing<Vec<u8>>) {
    if let Ok(mut guard) = global_pool().lock() {
        guard.hot_cache.insert(id, plaintext);
    }
}

/// Look up plaintext from the hot cache.
pub(super) fn hot_cache_get(id: u64) -> Option<Zeroizing<Vec<u8>>> {
    global_pool()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .hot_cache
        .get(id)
}

/// Evict an entry from the hot cache.
pub(super) fn hot_cache_evict(id: u64) {
    if let Ok(mut guard) = global_pool().lock() {
        guard.hot_cache.evict(id);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn pool_acquire_small_uses_slab() {
        let slot = pool_acquire(16).unwrap();
        assert!(slot.slab_index().is_some());
        assert_eq!(slot.size(), DEFAULT_SLOT_SIZE);
    }

    #[test]
    fn pool_acquire_large_uses_standalone() {
        let slot = pool_acquire(8192).unwrap();
        assert!(slot.slab_index().is_none());
        assert_eq!(slot.size(), 8192);
    }

    #[test]
    fn pool_acquire_zero_uses_slab() {
        // size 0 <= slot_size, so it should use the slab.
        let slot = pool_acquire(0).unwrap();
        assert!(slot.slab_index().is_some());
    }

    #[test]
    fn pool_slot_write_and_read() {
        let mut slot = pool_acquire(16).unwrap();
        let data = b"test data 12345!";
        // slot.size() may be larger than 16 (slab slot size is DEFAULT_SLOT_SIZE).
        slot.bytes()[..data.len()].copy_from_slice(data);
        assert_eq!(&slot.as_slice()[..data.len()], data);
    }

    #[test]
    fn hot_cache_insert_get_evict() {
        let plaintext = Zeroizing::new(b"cached secret".to_vec());
        hot_cache_insert(9999, plaintext.clone());
        let got = hot_cache_get(9999).unwrap();
        assert_eq!(*got, *plaintext);
        hot_cache_evict(9999);
        assert!(hot_cache_get(9999).is_none());
    }

    #[test]
    fn hot_cache_eviction_at_capacity() {
        // Insert HOT_CACHE_MAX + 1 entries; the first should be evicted.
        for i in 0_u64..=(HOT_CACHE_MAX as u64) {
            let pt = Zeroizing::new(vec![i as u8; 4]);
            hot_cache_insert(10000 + i, pt);
        }
        // Entry 0 should have been evicted (LRU).
        assert!(hot_cache_get(10000).is_none());
        // Entry HOT_CACHE_MAX should still be present.
        assert!(hot_cache_get(10000 + HOT_CACHE_MAX as u64).is_some());
        // Clean up.
        for i in 1_u64..=(HOT_CACHE_MAX as u64) {
            hot_cache_evict(10000 + i);
        }
    }

    #[test]
    fn coffer_view_returns_key_sized_slot() {
        let slot = coffer_view().unwrap();
        assert_eq!(slot.size(), 32);
        assert!(slot.slab_index().is_some());
    }
}
