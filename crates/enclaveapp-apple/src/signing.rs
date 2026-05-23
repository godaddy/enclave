// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Re-exports signing detection from enclaveapp-core for macOS keychain use.
//!
//! The canonical implementation lives in `enclaveapp_core::signing` so it's
//! available on all platforms. This module re-exports it for use by the
//! macOS-specific keychain code within this crate.

pub use enclaveapp_core::signing::{ensure_safe_app_name, is_binary_signed};
