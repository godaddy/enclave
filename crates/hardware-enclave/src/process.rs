// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Process hardening, trusted binary discovery, and timeout utilities.
//!
//! Any binary that handles hardware-backed secret material should call
//! [`harden_process`] as the **first line of `main()`** — before argument
//! parsing, environment inspection, or decryption.
//!
//! [`find_trusted_binary`] locates sibling binaries (agent, bridge, etc.)
//! in platform-appropriate install directories, deliberately excluding
//! `PATH` and `~/.cargo/bin` to prevent attacker-controlled PATH entries
//! from hijacking daemon launches.

// Process hardening
pub use crate::internal::core::process::harden_process;

// Trusted binary discovery
pub use crate::internal::core::bin_discovery::{
    find_trusted_binary, find_trusted_binary_with_context, BinaryDiscoveryContext,
};

// Subprocess timeout utilities
pub use crate::internal::core::timeout::{
    run_status_with_timeout, run_with_timeout, wait_with_timeout, TimeoutResult,
};
