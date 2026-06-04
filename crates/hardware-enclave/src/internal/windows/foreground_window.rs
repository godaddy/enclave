// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! A transient, top-most, invisible owner window used solely to give the
//! Windows Hello consent dialog a foreground parent.
//!
//! The secret agent that decrypts credentials is a windowless, detached
//! background process. `UserConsentVerifier::RequestVerificationAsync` (no
//! HWND) therefore shows the Hello / "Windows Security" dialog *behind* the
//! user's active window, so the user has to find and click it before they can
//! authenticate. By creating a throwaway top-most window, bringing it to the
//! foreground, and passing its HWND to
//! `IUserConsentVerifierInterop::RequestVerificationForWindowAsync`, the dialog
//! inherits foreground activation by construction.
//!
//! The window is never painted to and lives only for the duration of one
//! prompt: created, foregrounded, used as the dialog's owner, then destroyed by
//! `Drop`. It does not pump messages — the consent UI is hosted out-of-process,
//! so the owner HWND is only needed for activation / z-order, not as a message
//! host.
#![allow(unsafe_code)]

use std::mem::size_of;

use windows::core::{w, PCWSTR};
use windows::Foundation::{AsyncStatus, IAsyncOperation};
use windows::Security::Credentials::UI::UserConsentVerificationResult;
use windows::Win32::Foundation::{FALSE, HWND, LPARAM, LRESULT, TRUE, WPARAM};
use windows::Win32::System::Threading::{AttachThreadInput, GetCurrentThreadId};
use windows::Win32::UI::WindowsAndMessaging::{
    BringWindowToTop, CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW,
    GetForegroundWindow, GetWindowThreadProcessId, MsgWaitForMultipleObjectsEx, PeekMessageW,
    RegisterClassExW, SetForegroundWindow, ShowWindow, TranslateMessage, UnregisterClassW,
    CW_USEDEFAULT, MSG, MWMO_INPUTAVAILABLE, PM_REMOVE, QS_ALLINPUT, SW_SHOW, WNDCLASSEXW,
    WS_EX_TOOLWINDOW, WS_EX_TOPMOST, WS_POPUP,
};

const CLASS_NAME: PCWSTR = w!("EnclaveAppHelloOwnerWindow");

/// Minimal window procedure — we never handle anything ourselves.
unsafe extern "system" fn wnd_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    DefWindowProcW(hwnd, msg, wparam, lparam)
}

/// RAII owner window. `create()` registers the class (idempotently) and makes
/// the window; `Drop` destroys it and unregisters the class.
pub(crate) struct ForegroundOwner {
    hwnd: HWND,
}

impl ForegroundOwner {
    /// Create the transient owner window. Returns `Err` if the window could
    /// not be created, so the caller can fall back to the windowless prompt.
    pub(crate) fn create() -> windows::core::Result<Self> {
        // SAFETY: `wc` is fully initialized for the duration of the call and
        // `wnd_proc` is a valid `extern "system"` fn. RegisterClassExW returning
        // 0 (e.g. ERROR_CLASS_ALREADY_EXISTS from a prior prompt) is tolerated —
        // CreateWindowExW will still succeed against the existing class.
        let hwnd = unsafe {
            let wc = WNDCLASSEXW {
                cbSize: size_of::<WNDCLASSEXW>() as u32,
                lpfnWndProc: Some(wnd_proc),
                lpszClassName: CLASS_NAME,
                ..Default::default()
            };
            let _ = RegisterClassExW(&wc);
            CreateWindowExW(
                WS_EX_TOOLWINDOW | WS_EX_TOPMOST,
                CLASS_NAME,
                w!(""),
                WS_POPUP,
                CW_USEDEFAULT,
                CW_USEDEFAULT,
                1,
                1,
                None,
                None,
                None,
                None,
            )?
        };
        Ok(Self { hwnd })
    }

    /// The owner window handle to hand to `RequestVerificationForWindowAsync`.
    pub(crate) fn hwnd(&self) -> HWND {
        self.hwnd
    }

    /// Bring the owner window to the foreground so the consent dialog inherits
    /// activation. Uses the `AttachThreadInput` trick to defeat Windows'
    /// foreground lock (which otherwise makes `SetForegroundWindow` a silent
    /// no-op from a background process). Best-effort: a failure here just leaves
    /// the dialog where it would have been anyway.
    pub(crate) fn foreground(&self) {
        // SAFETY: all handles/thread ids are obtained immediately before use;
        // AttachThreadInput is balanced (attach then detach) when it succeeds.
        unsafe {
            let _ = ShowWindow(self.hwnd, SW_SHOW);
            let fg = GetForegroundWindow();
            let our_tid = GetCurrentThreadId();
            let fg_tid = GetWindowThreadProcessId(fg, None);
            let attached = fg_tid != 0
                && fg_tid != our_tid
                && AttachThreadInput(our_tid, fg_tid, TRUE).as_bool();
            BringWindowToTop(self.hwnd).ok();
            let _ = SetForegroundWindow(self.hwnd);
            if attached {
                let _ = AttachThreadInput(our_tid, fg_tid, FALSE);
            }
        }
    }
}

/// Wait for `op` to complete while pumping this thread's message queue.
///
/// The HWND-aware consent dialog is modal to our owner window, so the thread
/// that owns that window MUST pump messages for the dialog to appear and
/// proceed. A blocking `IAsyncOperation::get()` on this same thread would
/// deadlock — the window would never pump — which is exactly the freeze
/// observed with the naive approach. Polling `Status()` every 10ms while
/// draining messages is cheap at human-prompt timescales.
pub(crate) fn pump_until_complete(
    op: &IAsyncOperation<UserConsentVerificationResult>,
) -> windows::core::Result<UserConsentVerificationResult> {
    loop {
        if op.Status()? != AsyncStatus::Started {
            break;
        }
        // SAFETY: `msg` is a valid out-param; we only translate/dispatch
        // messages destined for this thread's own windows, then block until the
        // next message arrives (so the modal dialog's handshake is pumped the
        // instant it needs it) or 100ms elapses (to re-check completion).
        unsafe {
            let mut msg = MSG::default();
            while PeekMessageW(&mut msg, None, 0, 0, PM_REMOVE).as_bool() {
                let _ = TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
            let _ = MsgWaitForMultipleObjectsEx(None, 100, QS_ALLINPUT, MWMO_INPUTAVAILABLE);
        }
    }
    op.GetResults()
}

impl Drop for ForegroundOwner {
    fn drop(&mut self) {
        // SAFETY: `self.hwnd` was created by us and is destroyed exactly once.
        unsafe {
            DestroyWindow(self.hwnd).ok();
            UnregisterClassW(CLASS_NAME, None).ok();
        }
    }
}
