// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Shared build.rs helpers for enclave apps.
//!
//! # Usage
//!
//! In your crate's `build.rs`:
//!
//! ```rust,ignore
//! fn main() {
//!     enclaveapp_build_support::compile_windows_resource();
//! }
//! ```

/// Compile the Windows PE version resource from Cargo.toml metadata.
///
/// On non-Windows platforms, this is a no-op. On Windows, it uses the
/// `winresource` crate to embed version information (FileVersion,
/// ProductVersion, etc.) from Cargo.toml into the executable.
///
/// # Panics
///
/// Panics if the Windows resource compilation fails (build.rs convention).
#[allow(clippy::missing_panics_doc)]
pub fn compile_windows_resource() {
    #[cfg(target_os = "windows")]
    {
        winresource::WindowsResource::new()
            .compile()
            .expect("Failed to compile Windows resource");
    }
}
