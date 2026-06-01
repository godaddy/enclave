// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

#![allow(unsafe_code)]

//! Single mlock'd page subdivided into fixed-size slots.
//!
//! The slab occupies exactly one OS page (typically 4 KiB), mlock'd to
//! prevent swap-out. It is subdivided into `floor(page_size / slot_size)`
//! equal slots. This fits within the typical per-process mlock limit.
//!
//! Slots 0 and 1 are permanently reserved for the Coffer (master key halves).
//! Remaining slots are shared between the hot cache and transient pool use.

use std::collections::HashSet;
use std::ptr::NonNull;
use std::time::Duration;

use super::memcall::{os_lock, os_protect, os_unlock, page_size, Protection};
use crate::error::{Error, Result};

/// Default slot size in bytes (AES-256 key size, matching asherah-ffi).
pub const DEFAULT_SLOT_SIZE: usize = 32;

/// Maximum time to wait for a slot to become available.
pub(crate) const SLOT_WAIT_TIMEOUT: Duration = Duration::from_secs(30);

/// A single mlock'd page subdivided into fixed-size slots.
pub struct SecureSlab {
    ptr: NonNull<u8>,
    page_size: usize,
    slot_size: usize,
    total_slots: usize,
    /// Slots currently checked out (by index). Prevents double-release.
    transient: HashSet<usize>,
}

// Safety: exclusive ownership of the allocation; all access is through &mut or Mutex.
unsafe impl Send for SecureSlab {}

impl std::fmt::Debug for SecureSlab {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecureSlab")
            .field("slot_size", &self.slot_size)
            .field("total_slots", &self.total_slots)
            .field("checked_out", &self.transient.len())
            .finish()
    }
}

impl SecureSlab {
    /// Allocate and mlock a single page, subdivided into `slot_size`-byte slots.
    /// Slots 0 and 1 are reserved for the Coffer.
    pub fn new(slot_size: usize) -> Result<Self> {
        let ps = page_size();
        if slot_size == 0 || slot_size > ps / 4 {
            return Err(Error::Memory(format!(
                "SecureSlab: slot_size {slot_size} is invalid (must be 1..={})",
                ps / 4
            )));
        }
        let total_slots = ps / slot_size;
        if total_slots < 3 {
            return Err(Error::Memory(
                "SecureSlab: page too small for at least 3 slots (2 coffer + 1 usable)".into(),
            ));
        }

        let ptr = unsafe { super::memcall::os_alloc(ps) }
            .map_err(|e| Error::Memory(format!("SecureSlab alloc: {e}")))?;

        // mlock the entire page.
        if let Err(e) = unsafe { os_lock(ptr.as_ptr(), ps) } {
            drop(unsafe { super::memcall::os_free(ptr.as_ptr(), ps) });
            return Err(Error::Memory(format!("SecureSlab mlock: {e}")));
        }

        Ok(Self {
            ptr,
            page_size: ps,
            slot_size,
            total_slots,
            transient: HashSet::new(),
        })
    }

    fn slot_ptr(&self, index: usize) -> *mut u8 {
        // Safety: index is validated in checkout(); ptr is valid for page_size bytes
        // for the process lifetime (stored in OnceLock in the global pool).
        unsafe { self.ptr.as_ptr().add(index * self.slot_size) }
    }

    /// Raw pointer + length for slot `index`. Only valid while `self` is alive.
    pub fn slot_raw(&self, index: usize) -> (*mut u8, usize) {
        (self.slot_ptr(index), self.slot_size)
    }

    /// Mark slot as checked out. Returns error if already checked out.
    pub fn checkout(&mut self, index: usize) -> Result<()> {
        if index >= self.total_slots {
            return Err(Error::Memory(format!(
                "SecureSlab: slot {index} out of range"
            )));
        }
        if !self.transient.insert(index) {
            return Err(Error::Memory(format!(
                "SecureSlab: slot {index} is already checked out (double-acquire)"
            )));
        }
        Ok(())
    }

    /// Return slot to the slab and zeroize its contents.
    pub fn release(&mut self, index: usize) {
        if self.transient.remove(&index) {
            let ptr = self.slot_ptr(index);
            // Safety: ptr points into our mlock'd page; slot_size bytes are valid and writable.
            unsafe {
                let s = std::slice::from_raw_parts_mut(ptr, self.slot_size);
                use zeroize::Zeroize;
                s.zeroize();
            }
        }
    }

    /// Find an available slot (not coffer-reserved, not checked out).
    /// Coffer slots are 0 and 1.
    pub fn find_free_slot(&self) -> Option<usize> {
        (2..self.total_slots).find(|i| !self.transient.contains(i))
    }

    pub fn slot_size(&self) -> usize {
        self.slot_size
    }

    #[allow(dead_code)]
    pub fn total_slots(&self) -> usize {
        self.total_slots
    }

    #[allow(dead_code)]
    pub fn usable_slots(&self) -> usize {
        self.total_slots.saturating_sub(2) // subtract 2 coffer slots
    }
}

impl Drop for SecureSlab {
    fn drop(&mut self) {
        // Zeroize entire page before releasing.
        // Safety: ptr is valid for page_size bytes; we restore write access first.
        unsafe {
            drop(os_protect(
                self.ptr.as_ptr(),
                self.page_size,
                Protection::ReadWrite,
            ));
            let s = std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.page_size);
            use zeroize::Zeroize;
            s.zeroize();
            drop(os_unlock(self.ptr.as_ptr(), self.page_size));
            drop(super::memcall::os_free(self.ptr.as_ptr(), self.page_size));
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn new_default_slot_size() {
        let slab = SecureSlab::new(DEFAULT_SLOT_SIZE).unwrap();
        assert_eq!(slab.slot_size(), DEFAULT_SLOT_SIZE);
        assert!(slab.total_slots() >= 3);
        assert_eq!(slab.usable_slots(), slab.total_slots() - 2);
    }

    #[test]
    fn slot_size_zero_rejected() {
        assert!(SecureSlab::new(0).is_err());
    }

    #[test]
    fn slot_size_too_large_rejected() {
        let ps = page_size();
        assert!(SecureSlab::new(ps / 4 + 1).is_err());
    }

    #[test]
    fn checkout_and_release() {
        let mut slab = SecureSlab::new(DEFAULT_SLOT_SIZE).unwrap();
        let free = slab.find_free_slot().unwrap();
        assert!(free >= 2, "coffer slots must not be returned");
        slab.checkout(free).unwrap();
        // Double-checkout must fail.
        assert!(slab.checkout(free).is_err());
        slab.release(free);
        // After release, slot is available again.
        let free2 = slab.find_free_slot().unwrap();
        assert_eq!(free, free2);
    }

    #[test]
    fn out_of_range_checkout_fails() {
        let mut slab = SecureSlab::new(DEFAULT_SLOT_SIZE).unwrap();
        assert!(slab.checkout(slab.total_slots()).is_err());
    }

    #[test]
    fn release_nonexistent_is_noop() {
        let mut slab = SecureSlab::new(DEFAULT_SLOT_SIZE).unwrap();
        // Releasing a slot that was never checked out must not panic or corrupt state.
        slab.release(5);
    }

    #[test]
    fn slot_raw_valid_offset() {
        let slab = SecureSlab::new(DEFAULT_SLOT_SIZE).unwrap();
        let (p0, _) = slab.slot_raw(0);
        let (p1, _) = slab.slot_raw(1);
        assert_eq!(unsafe { p1.offset_from(p0) } as usize, DEFAULT_SLOT_SIZE);
    }
}
