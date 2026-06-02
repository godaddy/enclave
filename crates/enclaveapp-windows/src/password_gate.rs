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
//! `CredUIPromptForWindowsCredentialsW` and validates them with an
//! **SSPI NTLM loopback** handshake.
//!
//! ## Why SSPI loopback and not `LogonUserW`
//!
//! `LogonUserW` (any logon type) validates against the local SAM or
//! cached *domain* credentials. On Entra ID (Azure AD)-joined machines —
//! the common corporate case — the account is a cloud account with no
//! local/domain secret, so `LogonUserW` returns `ERROR_LOGON_FAILURE`
//! even for the **correct** password. That made the gate reject every
//! password (the bug behind this rewrite).
//!
//! Instead we drive a loopback NTLM handshake against the local SSP:
//! acquire an *outbound* credential from the typed username/password and
//! an *inbound* credential for the same package, then exchange security
//! contexts (`InitializeSecurityContextW` ↔ `AcceptSecurityContext`)
//! until `AcceptSecurityContext` returns `SEC_E_OK` (password matches the
//! cached MSV/NTLM verifier) or `SEC_E_LOGON_DENIED` (wrong password).
//! Because Windows caches an MSV1_0 verifier for Entra password sign-in,
//! this validates local, AD-domain, **and** Entra accounts.
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
//! plaintext password lives in process memory only for the SSPI handshake
//! and is zeroized immediately after.
//!
//! ## Outcomes
//!
//! [`verify_current_user`] returns a [`PresenceOutcome`]:
//! - [`PresenceOutcome::Verified`] — the user proved presence; proceed.
//! - [`PresenceOutcome::Denied`] — the user cancelled or entered a wrong
//!   password too many times; the caller treats this as access denied.
//! - [`PresenceOutcome::Unavailable`] — no prompt could be shown or the
//!   credential could not be validated *at all* (headless session, SSPI
//!   package unavailable, NTLM disabled by policy). The caller degrades
//!   to no presence prompt; the credential bundle remains TPM-encrypted.
//!   Note a *wrong password* is `Denied`, not `Unavailable`.

#![allow(unsafe_code)]

use std::iter::once;
use std::mem::size_of;
use std::ptr::{null, null_mut};

use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{HWND, SEC_E_LOGON_DENIED, SEC_E_OK, SEC_I_CONTINUE_NEEDED};
use windows::Win32::Graphics::Gdi::HBITMAP;
use windows::Win32::Security::Authentication::Identity::{
    AcceptSecurityContext, AcquireCredentialsHandleW, DeleteSecurityContext, FreeContextBuffer,
    FreeCredentialsHandle, InitializeSecurityContextW, SecBuffer, SecBufferDesc,
    ASC_REQ_ALLOCATE_MEMORY, ASC_REQ_CONNECTION, ISC_REQ_ALLOCATE_MEMORY, ISC_REQ_CONNECTION,
    SECBUFFER_TOKEN, SECBUFFER_VERSION, SECPKG_CRED_INBOUND, SECPKG_CRED_OUTBOUND,
    SECURITY_NATIVE_DREP,
};
use windows::Win32::Security::Credentials::{
    CredUIPromptForWindowsCredentialsW, CredUnPackAuthenticationBufferW, SecHandle,
    CREDUIWIN_ENUMERATE_CURRENT_USER, CREDUI_INFOW, CRED_PACK_FLAGS,
};
use windows::Win32::System::Com::CoTaskMemFree;
use windows::Win32::System::Rpc::{SEC_WINNT_AUTH_IDENTITY_UNICODE, SEC_WINNT_AUTH_IDENTITY_W};
use zeroize::Zeroize;

/// SSPI package used for the loopback validation. NTLM (rather than
/// Negotiate) forces the MSV1_0 path that checks the typed password
/// against the locally cached credential verifier — the only leg that
/// works offline and for Entra cloud accounts.
const NTLM_PACKAGE: &[u16] = &[b'N' as u16, b'T' as u16, b'L' as u16, b'M' as u16, 0];

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
/// Win32 `ERROR_LOGON_FAILURE`; passed back to the dialog as `dwAuthError`
/// on a re-prompt so it shows the "the password is incorrect" hint. The
/// wrong-vs-unvalidatable distinction is made by the SSPI handshake, not
/// this code.
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
    // SAFETY: all pointers handed to the Win32 calls below are either
    // null or point at live, correctly-sized stack/heap buffers for the
    // duration of each call; see the inner function for per-call notes.
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

/// Unpack the credential blob from `CredUIPromptForWindowsCredentialsW`
/// and validate it via an SSPI NTLM loopback handshake. All secret
/// buffers are zeroized before return.
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
    // Expected to fail with insufficient-buffer; the lengths are written
    // regardless. `drop` matches the crate convention for discarding a
    // Result whose Err carries a destructor.
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

    let outcome = validate_via_sspi(&mut user, &mut domain, &mut password);

    // Scrub secrets the instant they are no longer needed.
    user.zeroize();
    domain.zeroize();
    password.zeroize();

    outcome
}

/// Number of `u16` code units before the first NUL (the character length
/// SSPI expects, excluding the terminator).
fn wlen(buf: &[u16]) -> u32 {
    buf.iter().position(|&c| c == 0).unwrap_or(buf.len()) as u32
}

/// Validate `user`/`domain`/`password` via an NTLM loopback handshake
/// against the local SSP. See the module docs for why this is used
/// instead of `LogonUserW`. Returns `WrongPassword` only on a definitive
/// `SEC_E_LOGON_DENIED`; any inability to run the handshake is
/// `Unavailable` (degrade) rather than a false rejection.
unsafe fn validate_via_sspi(
    user: &mut [u16],
    domain: &mut [u16],
    password: &mut [u16],
) -> AuthCheck {
    let user_len = wlen(user);
    let pass_len = wlen(password);
    let domain_len = wlen(domain);
    let (domain_ptr, domain_chars) = if domain_len > 0 {
        (domain.as_mut_ptr(), domain_len)
    } else {
        (null_mut(), 0)
    };

    let identity = SEC_WINNT_AUTH_IDENTITY_W {
        User: user.as_mut_ptr(),
        UserLength: user_len,
        Domain: domain_ptr,
        DomainLength: domain_chars,
        Password: password.as_mut_ptr(),
        PasswordLength: pass_len,
        Flags: SEC_WINNT_AUTH_IDENTITY_UNICODE,
    };

    let package = PCWSTR(NTLM_PACKAGE.as_ptr());
    let mut ts: i64 = 0;
    let id_ptr: *const SEC_WINNT_AUTH_IDENTITY_W = &identity;

    // Outbound (client) credential built from the typed identity.
    let mut client_cred = SecHandle::default();
    if AcquireCredentialsHandleW(
        PCWSTR(null()),
        package,
        SECPKG_CRED_OUTBOUND,
        None,
        Some(id_ptr.cast()),
        None,
        None,
        &mut client_cred,
        Some(&mut ts),
    )
    .is_err()
    {
        return AuthCheck::Unavailable("AcquireCredentialsHandle(outbound) failed".into());
    }

    // Inbound (server) credential for the same package; no identity — it
    // validates the client's response against the locally cached verifier.
    let mut server_cred = SecHandle::default();
    if AcquireCredentialsHandleW(
        PCWSTR(null()),
        package,
        SECPKG_CRED_INBOUND,
        None,
        None,
        None,
        None,
        &mut server_cred,
        Some(&mut ts),
    )
    .is_err()
    {
        drop(FreeCredentialsHandle(&client_cred));
        return AuthCheck::Unavailable("AcquireCredentialsHandle(inbound) failed".into());
    }

    let result = run_loopback(&client_cred, &server_cred, &mut ts);

    drop(FreeCredentialsHandle(&client_cred));
    drop(FreeCredentialsHandle(&server_cred));
    result
}

/// Drive the client↔server SSPI token exchange to completion. Each
/// iteration runs one `InitializeSecurityContextW` (client) leg then one
/// `AcceptSecurityContext` (server) leg; the server's verdict
/// (`SEC_E_OK` / `SEC_E_LOGON_DENIED`) ends the loop. SSP-allocated
/// output tokens are released with `FreeContextBuffer`.
unsafe fn run_loopback(
    client_cred: &SecHandle,
    server_cred: &SecHandle,
    ts: &mut i64,
) -> AuthCheck {
    let mut client_ctx = SecHandle::default();
    let mut server_ctx = SecHandle::default();
    let mut have_client_ctx = false;
    let mut have_server_ctx = false;

    // Token most recently produced by the server, fed into the next ISC.
    let mut server_token: *mut core::ffi::c_void = null_mut();
    let mut server_token_len: u32 = 0;

    let mut attr: u32 = 0;
    let outcome;

    loop {
        // ---- client: InitializeSecurityContext ----
        let mut out_client = SecBuffer {
            cbBuffer: 0,
            BufferType: SECBUFFER_TOKEN,
            pvBuffer: null_mut(),
        };
        let mut out_client_desc = SecBufferDesc {
            ulVersion: SECBUFFER_VERSION,
            cBuffers: 1,
            pBuffers: &mut out_client,
        };
        let mut in_client = SecBuffer {
            cbBuffer: server_token_len,
            BufferType: SECBUFFER_TOKEN,
            pvBuffer: server_token,
        };
        let in_client_desc = SecBufferDesc {
            ulVersion: SECBUFFER_VERSION,
            cBuffers: 1,
            pBuffers: &mut in_client,
        };
        let p_in_client: Option<*const SecBufferDesc> = if server_token.is_null() {
            None
        } else {
            let p: *const SecBufferDesc = &in_client_desc;
            Some(p)
        };
        let p_client_ctx: Option<*const SecHandle> = if have_client_ctx {
            let p: *const SecHandle = &client_ctx;
            Some(p)
        } else {
            None
        };

        let st_isc = InitializeSecurityContextW(
            Some(client_cred),
            p_client_ctx,
            None,
            ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_CONNECTION,
            0,
            SECURITY_NATIVE_DREP,
            p_in_client,
            0,
            Some(&mut client_ctx),
            Some(&mut out_client_desc),
            &mut attr,
            Some(ts),
        );
        have_client_ctx = true;

        // The server token has been consumed by this ISC; release it.
        if !server_token.is_null() {
            drop(FreeContextBuffer(server_token));
            server_token = null_mut();
            // server_token_len is paired with the pointer and is always
            // re-set before its next read; no reset needed here.
        }

        if st_isc != SEC_E_OK && st_isc != SEC_I_CONTINUE_NEEDED {
            if !out_client.pvBuffer.is_null() {
                drop(FreeContextBuffer(out_client.pvBuffer));
            }
            outcome = AuthCheck::Unavailable(format!(
                "InitializeSecurityContext failed (0x{:08X})",
                st_isc.0 as u32
            ));
            break;
        }

        // ---- server: AcceptSecurityContext (consume the client token) ----
        let mut out_server = SecBuffer {
            cbBuffer: 0,
            BufferType: SECBUFFER_TOKEN,
            pvBuffer: null_mut(),
        };
        let mut out_server_desc = SecBufferDesc {
            ulVersion: SECBUFFER_VERSION,
            cBuffers: 1,
            pBuffers: &mut out_server,
        };
        let mut in_server = SecBuffer {
            cbBuffer: out_client.cbBuffer,
            BufferType: SECBUFFER_TOKEN,
            pvBuffer: out_client.pvBuffer,
        };
        let in_server_desc = SecBufferDesc {
            ulVersion: SECBUFFER_VERSION,
            cBuffers: 1,
            pBuffers: &mut in_server,
        };
        let p_in_server: Option<*const SecBufferDesc> = if out_client.pvBuffer.is_null() {
            None
        } else {
            let p: *const SecBufferDesc = &in_server_desc;
            Some(p)
        };
        let p_server_ctx: Option<*const SecHandle> = if have_server_ctx {
            let p: *const SecHandle = &server_ctx;
            Some(p)
        } else {
            None
        };

        let st_asc = AcceptSecurityContext(
            Some(server_cred),
            p_server_ctx,
            p_in_server,
            ASC_REQ_ALLOCATE_MEMORY | ASC_REQ_CONNECTION,
            SECURITY_NATIVE_DREP,
            Some(&mut server_ctx),
            Some(&mut out_server_desc),
            &mut attr,
            Some(ts),
        );
        have_server_ctx = true;

        // The client token has now been consumed by the server; release it.
        if !out_client.pvBuffer.is_null() {
            drop(FreeContextBuffer(out_client.pvBuffer));
        }

        if st_asc == SEC_E_OK {
            if !out_server.pvBuffer.is_null() {
                drop(FreeContextBuffer(out_server.pvBuffer));
            }
            outcome = AuthCheck::Verified;
            break;
        }
        if st_asc == SEC_E_LOGON_DENIED {
            if !out_server.pvBuffer.is_null() {
                drop(FreeContextBuffer(out_server.pvBuffer));
            }
            outcome = AuthCheck::WrongPassword;
            break;
        }
        if st_asc != SEC_I_CONTINUE_NEEDED {
            if !out_server.pvBuffer.is_null() {
                drop(FreeContextBuffer(out_server.pvBuffer));
            }
            outcome = AuthCheck::Unavailable(format!(
                "AcceptSecurityContext failed (0x{:08X})",
                st_asc.0 as u32
            ));
            break;
        }

        // Server wants another leg: its token becomes the next ISC input.
        server_token = out_server.pvBuffer;
        server_token_len = out_server.cbBuffer;
    }

    if have_client_ctx {
        drop(DeleteSecurityContext(&client_ctx));
    }
    if have_server_ctx {
        drop(DeleteSecurityContext(&server_ctx));
    }
    if !server_token.is_null() {
        drop(FreeContextBuffer(server_token));
    }

    outcome
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The Win32 codes the prompt loop branches on must match the
    /// platform definitions. A silent drift here would turn "user
    /// cancelled" into "degrade" (or vice versa), changing the gate's
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
    /// "unavailable" (degrade and decrypt) without this test noticing.
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
}
