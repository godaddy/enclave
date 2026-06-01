// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

#![allow(unsafe_code)]

use std::ptr::NonNull;

use rand::TryRngCore;
use zeroize::Zeroize;

use super::memcall::{os_alloc, os_free, os_lock, os_protect, os_unlock, page_size, Protection};
use crate::error::Error;

const CANARY_LEN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum State {
    Mutable,
    Frozen,
    Dead,
}

/// A page-guarded, mlock'd buffer for secret material.
///
/// Layout: [guard page (PROT_NONE)] [inner region, mlock'd] [guard page (PROT_NONE)]
///
/// Guard pages are filled with random canary bytes. On drop, canaries are verified
/// (detects overflow), inner region is zeroized, and all pages are unmapped.
pub struct SecureBuffer {
    /// Pointer to the start of the full allocation (first guard page).
    alloc_ptr: NonNull<u8>,
    /// Total allocation length (guard + inner + guard), page-aligned.
    alloc_len: usize,
    /// Pointer to the start of the inner (data) region.
    inner_ptr: NonNull<u8>,
    /// Requested data length.
    inner_len: usize,
    /// Copy of canary bytes placed in guard pages.
    _pre_canary: [u8; CANARY_LEN],
    _post_canary: [u8; CANARY_LEN],
    page_size: usize,
    pub(super) state: State,
    mlocked: bool,
}

// Safety: exclusive ownership of the allocation.
unsafe impl Send for SecureBuffer {}

impl std::fmt::Debug for SecureBuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecureBuffer")
            .field("inner_len", &self.inner_len)
            .field("state", &self.state)
            .finish()
    }
}

impl SecureBuffer {
    /// Allocate a new mutable, mlock'd, guard-paged buffer.
    pub fn new(size: usize) -> crate::error::Result<Self> {
        let ps = page_size();
        // Round inner region up to page boundary.
        let inner_rounded = size.div_ceil(ps) * ps;
        let alloc_len = ps + inner_rounded + ps;

        let alloc_ptr = unsafe { os_alloc(alloc_len) }
            .map_err(|e| Error::Memory(format!("SecureBuffer::new alloc: {e}")))?;

        // Inner region starts after first guard page.
        let inner_ptr = unsafe { NonNull::new_unchecked(alloc_ptr.as_ptr().add(ps)) };

        // Generate random canaries.
        let mut pre_canary = [0_u8; CANARY_LEN];
        let mut post_canary = [0_u8; CANARY_LEN];
        if rand::rngs::OsRng.try_fill_bytes(&mut pre_canary).is_err() {
            pre_canary.fill(0xAB);
        }
        if rand::rngs::OsRng.try_fill_bytes(&mut post_canary).is_err() {
            post_canary.fill(0xCD);
        }

        // Write canaries into guard pages (must be writable at this point).
        unsafe {
            let pre_guard = alloc_ptr.as_ptr();
            std::ptr::copy_nonoverlapping(pre_canary.as_ptr(), pre_guard, CANARY_LEN.min(ps));
            let post_guard = alloc_ptr.as_ptr().add(ps + inner_rounded);
            std::ptr::copy_nonoverlapping(post_canary.as_ptr(), post_guard, CANARY_LEN.min(ps));
        }

        // mlock the inner region.
        let mlocked = unsafe { os_lock(inner_ptr.as_ptr(), inner_rounded) }.is_ok();

        // Set guard pages to PROT_NONE.
        drop(unsafe { os_protect(alloc_ptr.as_ptr(), ps, Protection::NoAccess) });
        drop(unsafe {
            os_protect(
                alloc_ptr.as_ptr().add(ps + inner_rounded),
                ps,
                Protection::NoAccess,
            )
        });

        Ok(Self {
            alloc_ptr,
            alloc_len,
            inner_ptr,
            inner_len: size,
            _pre_canary: pre_canary,
            _post_canary: post_canary,
            page_size: ps,
            state: State::Mutable,
            mlocked,
        })
    }

    pub fn size(&self) -> usize {
        self.inner_len
    }

    pub fn is_alive(&self) -> bool {
        self.state != State::Dead
    }

    pub fn is_mutable(&self) -> bool {
        self.state == State::Mutable
    }

    /// Get a mutable slice to the inner region. Requires Mutable state.
    pub fn bytes(&mut self) -> &mut [u8] {
        assert!(
            self.state == State::Mutable,
            "SecureBuffer: bytes() called in non-mutable state"
        );
        unsafe { std::slice::from_raw_parts_mut(self.inner_ptr.as_ptr(), self.inner_len) }
    }

    /// Get a read-only slice. Requires non-Dead state.
    pub fn as_slice(&self) -> &[u8] {
        assert!(
            self.state != State::Dead,
            "SecureBuffer: as_slice() on dead buffer"
        );
        unsafe { std::slice::from_raw_parts(self.inner_ptr.as_ptr(), self.inner_len) }
    }

    /// Make the buffer read-only.
    pub fn freeze(&mut self) -> crate::error::Result<()> {
        if self.state == State::Dead {
            return Err(Error::Memory("SecureBuffer::freeze on dead buffer".into()));
        }
        let inner_rounded = self.alloc_len - 2 * self.page_size;
        unsafe { os_protect(self.inner_ptr.as_ptr(), inner_rounded, Protection::ReadOnly) }
            .map_err(|e| Error::Memory(format!("freeze: {e}")))?;
        self.state = State::Frozen;
        Ok(())
    }

    /// Make the buffer writable again.
    pub fn melt(&mut self) -> crate::error::Result<()> {
        if self.state == State::Dead {
            return Err(Error::Memory("SecureBuffer::melt on dead buffer".into()));
        }
        let inner_rounded = self.alloc_len - 2 * self.page_size;
        unsafe {
            os_protect(
                self.inner_ptr.as_ptr(),
                inner_rounded,
                Protection::ReadWrite,
            )
        }
        .map_err(|e| Error::Memory(format!("melt: {e}")))?;
        self.state = State::Mutable;
        Ok(())
    }

    /// Fill with random bytes (stays mutable).
    pub fn scramble(&mut self) -> crate::error::Result<()> {
        if self.state != State::Mutable {
            self.melt()?;
        }
        let buf = self.bytes();
        rand::rngs::OsRng
            .try_fill_bytes(buf)
            .map_err(|e| Error::Memory(format!("scramble OsRng: {e}")))
    }
}

impl Drop for SecureBuffer {
    fn drop(&mut self) {
        if self.state == State::Dead {
            return;
        }
        let ps = self.page_size;
        let inner_rounded = self.alloc_len - 2 * ps;

        // Restore write access to inner region so we can zeroize.
        drop(unsafe {
            os_protect(
                self.inner_ptr.as_ptr(),
                inner_rounded,
                Protection::ReadWrite,
            )
        });

        // Zeroize inner region.
        unsafe {
            let s = std::slice::from_raw_parts_mut(self.inner_ptr.as_ptr(), inner_rounded);
            s.zeroize();
        }

        // Unlock.
        if self.mlocked {
            drop(unsafe { os_unlock(self.inner_ptr.as_ptr(), inner_rounded) });
        }

        // Free the entire allocation.
        drop(unsafe { os_free(self.alloc_ptr.as_ptr(), self.alloc_len) });

        self.state = State::Dead;
    }
}
