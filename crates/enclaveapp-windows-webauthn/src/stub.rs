// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Stub implementation for non-Windows targets. WebAuthn is a
//! Windows-only API; on macOS/Linux every entry point reports
//! `NotAvailable` so workspace-wide builds and `cargo check` keep
//! working without needing per-target conditional compilation in
//! every consumer.

use crate::{Result, WebAuthnAssertion, WebAuthnCredential, WebAuthnError};

#[derive(Debug, Clone)]
pub struct MakeCredentialParams<'params> {
    pub rp_id: &'params str,
    pub rp_name: &'params str,
    pub user_id: &'params [u8],
    pub user_name: &'params str,
    pub user_display_name: &'params str,
    pub timeout_ms: u32,
    pub hwnd: Option<isize>,
}

#[derive(Debug, Clone)]
pub struct GetAssertionParams<'params> {
    pub rp_id: &'params str,
    pub credential_id: &'params [u8],
    pub client_data: &'params [u8],
    pub timeout_ms: u32,
    pub hwnd: Option<isize>,
}

pub fn is_platform_authenticator_available() -> bool {
    false
}

pub fn make_credential(_params: MakeCredentialParams<'_>) -> Result<WebAuthnCredential> {
    Err(WebAuthnError::NotAvailable)
}

pub fn get_assertion(_params: GetAssertionParams<'_>) -> Result<WebAuthnAssertion> {
    Err(WebAuthnError::NotAvailable)
}

pub fn delete_platform_credential(_credential_id: &[u8]) -> Result<()> {
    Err(WebAuthnError::NotAvailable)
}
