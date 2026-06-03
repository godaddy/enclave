// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Filesystem helpers for atomic writes and permission management.
//!
//! These utilities are used by consuming apps to safely persist configuration,
//! key metadata, and credential caches. Writes are atomic (write-to-temp then
//! rename) and file permissions are locked down to owner-only.

pub use crate::internal::core::metadata::{
    atomic_write, config_dir, ensure_dir, keys_dir, read_no_follow, read_to_string_no_follow,
    restrict_file_permissions,
};
