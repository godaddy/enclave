// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! TPM bridge for WSL (JSON-RPC over stdin/stdout).
//!
//! On Windows, a bridge server reads JSON-RPC requests from stdin and writes
//! responses to stdout. On Linux/WSL, the client spawns the Windows bridge
//! binary and communicates via the same protocol.

mod client;
mod protocol;

pub use client::*;
pub use protocol::*;
