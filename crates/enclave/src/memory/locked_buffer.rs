// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

#![allow(unsafe_code)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock, Weak};

use zeroize::{Zeroize, Zeroizing};

use super::secure_buffer::SecureBuffer;
use crate::error::Result;

// Global registry for centralized shutdown cleanup.
type Registry = Mutex<HashMap<usize, Weak<Mutex<SecureBuffer>>>>;

fn registry() -> &'static Registry {
    static REGISTRY: OnceLock<Registry> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

fn register(id: usize, weak: Weak<Mutex<SecureBuffer>>) {
    if let Ok(mut r) = registry().lock() {
        r.insert(id, weak);
    }
}

fn unregister(id: usize) {
    if let Ok(mut r) = registry().lock() {
        r.remove(&id);
    }
}

/// Zeroize all live LockedBuffers. Call at process shutdown.
pub fn zeroize_all_registered() {
    if let Ok(r) = registry().lock() {
        for weak in r.values() {
            if let Some(arc) = weak.upgrade() {
                if let Ok(mut buf) = arc.lock() {
                    drop(buf.melt());
                    if buf.is_alive() {
                        buf.bytes().zeroize();
                        // drop buf explicitly to handle the mutable borrow
                    }
                }
            }
        }
    }
}

/// Arc-wrapped, Mutex-guarded SecureBuffer for sharing across threads.
pub struct LockedBuffer {
    inner: Arc<Mutex<SecureBuffer>>,
    id: usize,
}

impl std::fmt::Debug for LockedBuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LockedBuffer")
            .field("id", &self.id)
            .finish()
    }
}

impl LockedBuffer {
    fn from_buffer(buf: SecureBuffer) -> Result<Self> {
        static ID: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(1);
        let id = ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let arc = Arc::new(Mutex::new(buf));
        register(id, Arc::downgrade(&arc));
        Ok(Self { inner: arc, id })
    }

    /// Allocate a new zeroed buffer.
    pub fn new(size: usize) -> Result<Self> {
        Self::from_buffer(SecureBuffer::new(size)?)
    }

    /// Allocate and fill with OsRng random bytes.
    pub fn random(size: usize) -> Result<Self> {
        let mut buf = SecureBuffer::new(size)?;
        buf.scramble()?;
        Self::from_buffer(buf)
    }

    /// Create from an existing byte slice (copies into locked memory).
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let src = bytes.as_ref();
        let mut buf = SecureBuffer::new(src.len())?;
        buf.bytes().copy_from_slice(src);
        Self::from_buffer(buf)
    }

    pub fn freeze(&self) -> Result<()> {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .freeze()
    }

    pub fn melt(&self) -> Result<()> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).melt()
    }

    pub fn scramble(&self) -> Result<()> {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .scramble()
    }

    pub fn wipe(&self) {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        drop(guard.melt());
        if guard.is_alive() {
            guard.bytes().zeroize();
        }
    }

    /// Copy contents to a Zeroizing heap allocation.
    pub fn bytes_zeroizing(&self) -> Zeroizing<Vec<u8>> {
        let guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        Zeroizing::new(guard.as_slice().to_vec())
    }

    pub fn size(&self) -> usize {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).size()
    }
}

impl Drop for LockedBuffer {
    fn drop(&mut self) {
        unregister(self.id);
        self.wipe();
    }
}
