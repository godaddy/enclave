// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Shell config block injection and path/value quoting.
//!
//! [`BlockMarkers`] + the `install_block_in_file` / `remove_block_from_file`
//! functions handle adding and removing managed blocks from `.bashrc`,
//! `.zshrc`, SSH config, and similar files.
//!
//! The quoting functions produce correctly-escaped strings for embedding
//! paths and values into config files.

// Config block management
pub use crate::internal::core::config_block::{
    build_block, find_block, has_block, install_block_in_file, read_config_file, remove_block,
    remove_block_from_file, upsert_block, write_config_file, BlockInstallResult, BlockMarkers,
    BlockRemoveResult,
};

// Path and value quoting for config files
pub use crate::internal::core::quoting::quote_config_value;

/// Quote a filesystem path for embedding in a config file.
///
/// On Windows, backslashes are converted to forward slashes (required by
/// OpenSSH and many other config parsers). Paths containing spaces are
/// wrapped in double quotes.
///
/// Use this wherever you write a path into a generated config file —
/// SSH `IdentityFile`, `ProxyCommand`, Git credential helper entries, etc.
pub fn quote_path_for_config(path: &std::path::Path) -> String {
    crate::internal::core::quoting::quote_ssh_path(path)
}

/// Quote a path for the `credential_process` directive in AWS config.
///
/// Same as [`quote_path_for_config`] but uses INI-style escaping
/// (`\"` and `\\`) instead of forward-slash normalization.
pub use crate::internal::core::quoting::quote_credential_process_arg;
