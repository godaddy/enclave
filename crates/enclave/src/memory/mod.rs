// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Page-guarded, mlock'd memory buffers for secret material.

mod coffer;
mod locked_buffer;
mod memcall;
mod memory_enclave;
mod secure_buffer;

pub use locked_buffer::LockedBuffer;
pub use memory_enclave::MemoryEnclave;
pub use secure_buffer::SecureBuffer;

/// Zeroize and remove all registered LockedBuffers. Call at shutdown.
pub fn zeroize_all() {
    locked_buffer::zeroize_all_registered();
}
