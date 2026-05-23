// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Platform-agnostic types, traits, and utilities for hardware-backed key management.
//!
//! This crate provides the core abstractions shared across macOS Secure Enclave,
//! Windows TPM 2.0, and WSL bridge implementations.

pub mod bin_discovery;
pub mod config;
pub mod config_block;
pub mod daemon;
pub mod error;
pub mod metadata;
pub mod platform;
pub mod process;
pub mod quoting;
pub mod signing;
pub mod timeout;
pub mod traits;
pub mod types;

pub use error::{Error, Result};
pub use metadata::KeyMeta;
pub use traits::{EnclaveEncryptor, EnclaveKeyManager, EnclaveSigner};
pub use types::{AccessPolicy, KeyType, PresenceMode};
