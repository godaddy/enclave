// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! WSL environment detection and shell integration for Windows-hosted apps.
//!
//! Consuming apps that support WSL2 use this module to:
//! - Detect whether the current process is running inside WSL ([`is_wsl`])
//! - Enumerate installed distros ([`detect_distros`], [`WslDistro`])
//! - Install/remove shell integration blocks across all distros
//!   ([`configure_all_distros`], [`unconfigure_all_distros`], [`WslInstallConfig`])
//! - Specify a Linux release binary to auto-install into each distro
//!   ([`LinuxReleaseSpec`])

// Environment detection (re-exported at crate::internal::wsl via pub use detect::*)
pub use crate::internal::wsl::{decode_wsl_output, detect_distros, is_wsl, WslDistro};

// Installation orchestration
pub use crate::internal::wsl::install::{
    configure_all_distros, find_wsl_home, unconfigure_all_distros, DistroResult, LinuxReleaseSpec,
    WslInstallConfig,
};

// Per-distro shell config management (re-exported at crate::internal::wsl via pub use shell_config::*)
pub use crate::internal::wsl::{
    install_block, is_installed, shell_config_paths, uninstall_block, validate_shell_syntax,
    InstallResult, ShellBlockConfig, UninstallResult,
};
