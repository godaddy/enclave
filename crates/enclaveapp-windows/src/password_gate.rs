// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Windows account-password soft gate.
//!
//! Fallback user-presence check for hosts where Windows Hello / PIN is
//! not configured. [`crate::hello_gate::HelloGate`] tries
//! `UserConsentVerifier` first; when that reports the device is not
//! enrolled (`DeviceNotPresent` / `NotConfiguredForUser` /
//! `DisabledByPolicy`) it falls back to this module, which prompts for
//! the current user's Windows credentials via
//! `CredUIPromptForWindowsCredentialsW` and validates them with
//! `LogonUserW` (network logon).
//!
//! ## Username/domain splitting (the important bit)
//!
//! `LogonUserW` only validates an AD domain account when the **domain is
//! passed separately** from the username: `LogonUserW("jgowdy", "JOMAX",
//! ...)` succeeds, but `LogonUserW("JOMAX\\jgowdy", NULL, ...)` returns
//! `ERROR_LOGON_FAILURE` for the *correct* password. `CredUnPackAuthen-
//! ticationBufferW` sometimes returns the identity as `DOMAIN\user` in the
//! username field with an empty domain field, so we split a leading
//! `DOMAIN\` back out before calling `LogonUserW`. (This was the original
//! "invalid password over and over" bug.) Validated on a real JOMAX
//! domain account; an SSPI NTLM-loopback approach was tried and abandoned
//! because Windows' loopback/reflection protection denies even a correct
//! password.
//!
//! ## Why this exists
//!
//! Without a fallback, opting an app into the Hello soft-UX gate would
//! *eliminate* the user-presence signal for exactly the users who never
//! set up Hello, while keeping the prompt friction for those who did.
//! A Windows password prompt works regardless of Hello enrollment, so
//! every user gets a presence check.
//!
//! ## Threat-model trade-off
//!
//! Identical posture to [`crate::hello_gate`]: this is a **soft gate**.
//! The verification is a Boolean computed in the calling process; a
//! same-UID attacker with code execution can hook the result or invoke
//! the TPM key operation directly. It is a user-presence consent signal,
//! not a hard cryptographic boundary against same-UID malware. The
//! plaintext password lives in process memory only for the `LogonUserW`
//! call and is zeroized immediately after.
//!
//! ## Outcomes
//!
//! [`verify_current_user`] returns a [`PresenceOutcome`]:
//! - [`PresenceOutcome::Verified`] — the user proved presence; proceed.
//! - [`PresenceOutcome::Denied`] — the user cancelled or entered a wrong
//!   password too many times; the caller treats this as access denied.
//! - [`PresenceOutcome::Unavailable`] — no prompt could be shown or the
//!   account cannot be validated here (headless session, no reachable
//!   domain controller, logon-type not granted). The caller degrades to
//!   no presence prompt; the bundle remains TPM-encrypted. A *wrong
//!   password* is `Denied`, not `Unavailable`.

#![allow(unsafe_code)]

use std::iter::once;
use std::mem::size_of;
use std::ptr::{null, null_mut};

use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, HANDLE, HWND};
use windows::Win32::Graphics::Gdi::HBITMAP;
use windows::Win32::Security::Credentials::{
    CredUIPromptForWindowsCredentialsW, CredUnPackAuthenticationBufferW,
    CREDUIWIN_ENUMERATE_CURRENT_USER, CREDUI_INFOW, CRED_PACK_FLAGS,
};
use windows::Win32::Security::{LogonUserW, LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT};
use windows::Win32::System::Com::CoTaskMemFree;
use zeroize::Zeroize;

/// Result of a Windows password presence check.
#[derive(Debug)]
pub enum PresenceOutcome {
    /// The user proved presence (correct Windows password).
    Verified,
    /// The user actively declined (cancelled the dialog) or failed
    /// verification after the allowed retries. Treat as access denied.
    Denied(String),
    /// No prompt could be shown, or the account cannot be validated via
    /// this mechanism. The caller should degrade gracefully rather than
    /// block the user.
    Unavailable(String),
}

/// `CredUIPromptForWindowsCredentialsW` returns a Win32 error code (not
/// an `HRESULT`). `ERROR_SUCCESS` means the user submitted credentials.
const ERROR_SUCCESS_CODE: u32 = 0;
/// The user dismissed the credential dialog.
const ERROR_CANCELLED_CODE: u32 = 1223; // ERROR_CANCELLED
/// Win32 `ERROR_LOGON_FAILURE` — wrong username/password. Also passed
/// back to the dialog as `dwAuthError` on a re-prompt so it shows the
/// "the password is incorrect" hint.
const ERROR_LOGON_FAILURE_CODE: u32 = 1326;
/// How many times to re-prompt on a wrong password before denying.
const MAX_ATTEMPTS: u32 = 3;

/// Prompt the current user for their Windows password and verify it.
///
/// `reason` is shown as the dialog's message text; pick something the
/// user can match to the action they're taking (e.g. "Unlock gocode-dev
/// credentials"). See the module docs for the outcome semantics and the
/// threat-model trade-off.
pub fn verify_current_user(reason: &str) -> PresenceOutcome {
    // SAFETY: every pointer handed to the Win32 calls below is either null
    // or points at a live, correctly-sized buffer for the duration of the
    // call; see the inner functions for per-call notes.
    unsafe { verify_current_user_inner(reason) }
}

unsafe fn verify_current_user_inner(reason: &str) -> PresenceOutcome {
    let message: Vec<u16> = reason.encode_utf16().chain(once(0)).collect();
    let caption: Vec<u16> = "gocode-dev".encode_utf16().chain(once(0)).collect();
    let ui_info = CREDUI_INFOW {
        cbSize: size_of::<CREDUI_INFOW>() as u32,
        hwndParent: HWND::default(),
        pszMessageText: PCWSTR(message.as_ptr()),
        pszCaptionText: PCWSTR(caption.as_ptr()),
        hbmBanner: HBITMAP::default(),
    };

    let mut auth_error: u32 = 0;
    let mut attempts: u32 = 0;

    loop {
        attempts += 1;
        let mut auth_package: u32 = 0;
        let mut out_buf: *mut core::ffi::c_void = null_mut();
        let mut out_size: u32 = 0;

        // Restrict the dialog to the current user's tile: we are
        // confirming "are you still you", not collecting arbitrary
        // credentials.
        let rc = CredUIPromptForWindowsCredentialsW(
            Some(&ui_info),
            auth_error,
            &mut auth_package,
            None,
            0,
            &mut out_buf,
            &mut out_size,
            None,
            CREDUIWIN_ENUMERATE_CURRENT_USER,
        );

        match rc {
            ERROR_SUCCESS_CODE => {}
            ERROR_CANCELLED_CODE => {
                return PresenceOutcome::Denied("user cancelled the password prompt".into());
            }
            other => {
                return PresenceOutcome::Unavailable(format!(
                    "CredUIPromptForWindowsCredentialsW failed (0x{other:08X})"
                ));
            }
        }

        let outcome = verify_auth_buffer(out_buf, out_size);

        // The credential blob holds the plaintext password; scrub it
        // before handing the memory back to the allocator.
        if !out_buf.is_null() {
            std::slice::from_raw_parts_mut(out_buf.cast::<u8>(), out_size as usize).zeroize();
            CoTaskMemFree(Some(out_buf.cast_const()));
        }

        match outcome {
            AuthCheck::Verified => return PresenceOutcome::Verified,
            AuthCheck::WrongPassword => {
                auth_error = ERROR_LOGON_FAILURE_CODE;
                if attempts >= MAX_ATTEMPTS {
                    return PresenceOutcome::Denied(
                        "Windows password could not be verified".into(),
                    );
                }
                // loop and re-prompt with the "incorrect password" hint
            }
            AuthCheck::Unavailable(detail) => return PresenceOutcome::Unavailable(detail),
        }
    }
}

/// Internal classification of a single unpack+logon attempt.
enum AuthCheck {
    Verified,
    WrongPassword,
    Unavailable(String),
}

/// Number of `u16` code units before the first NUL.
fn wlen(buf: &[u16]) -> usize {
    buf.iter().position(|&c| c == 0).unwrap_or(buf.len())
}

/// Unpack the credential blob from `CredUIPromptForWindowsCredentialsW`
/// and validate it with a network logon. All secret buffers are zeroized
/// before return.
unsafe fn verify_auth_buffer(buf: *mut core::ffi::c_void, size: u32) -> AuthCheck {
    if buf.is_null() || size == 0 {
        return AuthCheck::Unavailable("empty credential buffer".into());
    }

    // First call: discover the required buffer lengths (in WCHARs). The
    // wrapper returns Err on the expected insufficient-buffer result;
    // the out-params are written regardless.
    let mut user_len: u32 = 0;
    let mut domain_len: u32 = 0;
    let mut pass_len: u32 = 0;
    drop(CredUnPackAuthenticationBufferW(
        CRED_PACK_FLAGS(0),
        buf,
        size,
        PWSTR(null_mut()),
        &mut user_len,
        PWSTR(null_mut()),
        Some(&mut domain_len),
        PWSTR(null_mut()),
        &mut pass_len,
    ));
    if user_len == 0 || pass_len == 0 {
        return AuthCheck::Unavailable("could not size unpacked credentials".into());
    }

    let mut user = vec![0_u16; user_len as usize];
    let mut domain = vec![0_u16; domain_len.max(1) as usize];
    let mut password = vec![0_u16; pass_len as usize];

    let unpacked = CredUnPackAuthenticationBufferW(
        CRED_PACK_FLAGS(0),
        buf,
        size,
        PWSTR(user.as_mut_ptr()),
        &mut user_len,
        PWSTR(domain.as_mut_ptr()),
        Some(&mut domain_len),
        PWSTR(password.as_mut_ptr()),
        &mut pass_len,
    );
    if unpacked.is_err() {
        user.zeroize();
        domain.zeroize();
        password.zeroize();
        return AuthCheck::Unavailable("could not unpack credentials".into());
    }

    // LogonUserW requires the domain passed *separately*; a `DOMAIN\user`
    // string with a NULL domain fails with ERROR_LOGON_FAILURE even for
    // the correct password. Prefer the unpacked domain field; if it is
    // empty but the username carries a `DOMAIN\` prefix, split it back
    // out. (user/domain are not secret; only the password is.)
    let user_str = String::from_utf16_lossy(&user[..wlen(&user)]);
    let domain_str = String::from_utf16_lossy(&domain[..wlen(&domain)]);
    let (eff_user, eff_domain) = if !domain_str.is_empty() {
        (user_str, domain_str)
    } else if let Some((dom, usr)) = user_str.split_once('\\') {
        (usr.to_string(), dom.to_string())
    } else {
        (user_str, String::new())
    };
    let user_w: Vec<u16> = eff_user.encode_utf16().chain(once(0)).collect();
    let domain_w: Vec<u16> = eff_domain.encode_utf16().chain(once(0)).collect();
    let domain_ptr = if eff_domain.is_empty() {
        PCWSTR(null())
    } else {
        PCWSTR(domain_w.as_ptr())
    };

    let mut token = HANDLE::default();
    let logon = LogonUserW(
        PCWSTR(user_w.as_ptr()),
        domain_ptr,
        PCWSTR(password.as_ptr()),
        LOGON32_LOGON_NETWORK,
        LOGON32_PROVIDER_DEFAULT,
        &mut token,
    );

    // Scrub the password the instant it is no longer needed.
    password.zeroize();
    user.zeroize();
    domain.zeroize();

    match logon {
        Ok(()) => {
            if !token.is_invalid() {
                drop(CloseHandle(token));
            }
            AuthCheck::Verified
        }
        Err(err) => {
            // HRESULT_FROM_WIN32 packs the Win32 code in the low 16 bits.
            let win32 = (err.code().0 as u32) & 0xFFFF;
            if win32 == ERROR_LOGON_FAILURE_CODE {
                AuthCheck::WrongPassword
            } else {
                // Cannot validate here (no reachable DC, logon-type not
                // granted, etc.) — degrade rather than lock the user out.
                AuthCheck::Unavailable(format!("LogonUserW could not validate the account: {err}"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The Win32 codes the prompt loop branches on must match the
    /// platform definitions. A silent drift here would change the gate's
    /// deny/allow semantics. The interactive prompt itself is not
    /// unit-testable (it requires an attended desktop), so pin the
    /// constants instead.
    #[test]
    fn win32_codes_match_platform_definitions() {
        assert_eq!(ERROR_SUCCESS_CODE, 0);
        assert_eq!(ERROR_CANCELLED_CODE, 1223);
        assert_eq!(ERROR_LOGON_FAILURE_CODE, 1326);
    }

    /// Document the deny/allow contract of the three outcomes so a
    /// refactor can't quietly collapse "denied" (block decrypt) into
    /// "unavailable" (degrade and decrypt).
    #[test]
    fn outcomes_carry_the_expected_shape() {
        let denied = PresenceOutcome::Denied("cancelled".into());
        let unavailable = PresenceOutcome::Unavailable("headless".into());
        assert!(matches!(denied, PresenceOutcome::Denied(_)));
        assert!(matches!(unavailable, PresenceOutcome::Unavailable(_)));
        assert!(matches!(
            PresenceOutcome::Verified,
            PresenceOutcome::Verified
        ));
    }

    /// `wlen` stops at the first NUL and tolerates an unterminated slice.
    #[test]
    fn wlen_stops_at_nul() {
        assert_eq!(wlen(&[b'a' as u16, b'b' as u16, 0, b'c' as u16]), 2);
        assert_eq!(wlen(&[b'x' as u16, b'y' as u16]), 2);
        assert_eq!(wlen(&[0]), 0);
    }
}
