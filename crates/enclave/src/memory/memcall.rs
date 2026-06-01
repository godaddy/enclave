// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

#![allow(unsafe_code)]

use std::ptr::NonNull;

#[derive(Debug)]
pub enum MemError {
    Alloc(String),
    Lock(String),
    Unlock(String),
    Protect(String),
    Free(String),
}

impl std::fmt::Display for MemError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MemError::Alloc(s) => write!(f, "alloc: {s}"),
            MemError::Lock(s) => write!(f, "lock: {s}"),
            MemError::Unlock(s) => write!(f, "unlock: {s}"),
            MemError::Protect(s) => write!(f, "protect: {s}"),
            MemError::Free(s) => write!(f, "free: {s}"),
        }
    }
}

#[derive(Clone, Copy)]
pub enum Protection {
    NoAccess,
    ReadOnly,
    ReadWrite,
}

#[cfg(unix)]
pub fn page_size() -> usize {
    unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize }
}

#[cfg(windows)]
pub fn page_size() -> usize {
    use windows::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};
    unsafe {
        let mut info = SYSTEM_INFO::default();
        GetSystemInfo(&mut info);
        info.dwPageSize as usize
    }
}

#[cfg(not(any(unix, windows)))]
pub fn page_size() -> usize {
    4096
}

// ── Unix implementation ───────────────────────────────────────────────────────

#[cfg(unix)]
pub unsafe fn os_alloc(len: usize) -> Result<NonNull<u8>, MemError> {
    let ptr = libc::mmap(
        std::ptr::null_mut(),
        len,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_PRIVATE | libc::MAP_ANON,
        -1,
        0,
    );
    if ptr == libc::MAP_FAILED {
        return Err(MemError::Alloc(std::io::Error::last_os_error().to_string()));
    }
    Ok(NonNull::new(ptr.cast::<u8>()).expect("mmap returned null that is not MAP_FAILED"))
}

#[cfg(unix)]
pub unsafe fn os_lock(ptr: *mut u8, len: usize) -> Result<(), MemError> {
    // Best-effort: exclude from core dumps.
    #[cfg(target_os = "linux")]
    let _ = libc::madvise(ptr.cast(), len, libc::MADV_DONTDUMP);
    // macOS: no MADV_NOCORE; use MADV_ZERO_WIRED_PAGES as a best-effort hint.
    #[cfg(target_os = "macos")]
    let _ = libc::madvise(ptr.cast(), len, libc::MADV_ZERO_WIRED_PAGES);

    if libc::mlock(ptr.cast(), len) != 0 {
        return Err(MemError::Lock(std::io::Error::last_os_error().to_string()));
    }
    Ok(())
}

#[cfg(unix)]
pub unsafe fn os_unlock(ptr: *mut u8, len: usize) -> Result<(), MemError> {
    if libc::munlock(ptr.cast(), len) != 0 {
        return Err(MemError::Unlock(
            std::io::Error::last_os_error().to_string(),
        ));
    }
    Ok(())
}

#[cfg(unix)]
pub unsafe fn os_protect(ptr: *mut u8, len: usize, prot: Protection) -> Result<(), MemError> {
    let flags = match prot {
        Protection::NoAccess => libc::PROT_NONE,
        Protection::ReadOnly => libc::PROT_READ,
        Protection::ReadWrite => libc::PROT_READ | libc::PROT_WRITE,
    };
    if libc::mprotect(ptr.cast(), len, flags) != 0 {
        return Err(MemError::Protect(
            std::io::Error::last_os_error().to_string(),
        ));
    }
    Ok(())
}

#[cfg(unix)]
pub unsafe fn os_free(ptr: *mut u8, len: usize) -> Result<(), MemError> {
    if libc::munmap(ptr.cast(), len) != 0 {
        return Err(MemError::Free(std::io::Error::last_os_error().to_string()));
    }
    Ok(())
}

// ── Windows implementation ────────────────────────────────────────────────────

#[cfg(windows)]
pub unsafe fn os_alloc(len: usize) -> Result<NonNull<u8>, MemError> {
    use windows::Win32::System::Memory::{VirtualAlloc, MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE};
    let ptr = VirtualAlloc(None, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    NonNull::new(ptr.cast::<u8>())
        .ok_or_else(|| MemError::Alloc(std::io::Error::last_os_error().to_string()))
}

#[cfg(windows)]
pub unsafe fn os_lock(ptr: *mut u8, len: usize) -> Result<(), MemError> {
    use windows::Win32::System::Memory::VirtualLock;
    VirtualLock(ptr.cast(), len).map_err(|e| MemError::Lock(e.to_string()))
}

#[cfg(windows)]
pub unsafe fn os_unlock(ptr: *mut u8, len: usize) -> Result<(), MemError> {
    use windows::Win32::System::Memory::VirtualUnlock;
    VirtualUnlock(ptr.cast(), len).map_err(|e| MemError::Unlock(e.to_string()))
}

#[cfg(windows)]
pub unsafe fn os_protect(ptr: *mut u8, len: usize, prot: Protection) -> Result<(), MemError> {
    use windows::Win32::System::Memory::{
        VirtualProtect, PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE,
    };
    let flags = match prot {
        Protection::NoAccess => PAGE_NOACCESS,
        Protection::ReadOnly => PAGE_READONLY,
        Protection::ReadWrite => PAGE_READWRITE,
    };
    let mut old = windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS(0);
    VirtualProtect(ptr.cast(), len, flags, &mut old).map_err(|e| MemError::Protect(e.to_string()))
}

#[cfg(windows)]
pub unsafe fn os_free(ptr: *mut u8, len: usize) -> Result<(), MemError> {
    use windows::Win32::System::Memory::{VirtualFree, MEM_RELEASE};
    let _ = len;
    VirtualFree(ptr.cast(), 0, MEM_RELEASE).map_err(|e| MemError::Free(e.to_string()))
}

// ── Stub for other platforms ──────────────────────────────────────────────────

#[cfg(not(any(unix, windows)))]
pub unsafe fn os_alloc(len: usize) -> Result<NonNull<u8>, MemError> {
    use std::alloc::{alloc_zeroed, Layout};
    let layout = Layout::from_size_align(len, 1).map_err(|e| MemError::Alloc(e.to_string()))?;
    let ptr = alloc_zeroed(layout);
    NonNull::new(ptr).ok_or_else(|| MemError::Alloc("allocation failed".into()))
}

#[cfg(not(any(unix, windows)))]
pub unsafe fn os_lock(_ptr: *mut u8, _len: usize) -> Result<(), MemError> {
    Ok(())
}
#[cfg(not(any(unix, windows)))]
pub unsafe fn os_unlock(_ptr: *mut u8, _len: usize) -> Result<(), MemError> {
    Ok(())
}
#[cfg(not(any(unix, windows)))]
pub unsafe fn os_protect(_ptr: *mut u8, _len: usize, _prot: Protection) -> Result<(), MemError> {
    Ok(())
}
#[cfg(not(any(unix, windows)))]
pub unsafe fn os_free(ptr: *mut u8, len: usize) -> Result<(), MemError> {
    use std::alloc::{dealloc, Layout};
    let layout = Layout::from_size_align(len, 1).map_err(|e| MemError::Free(e.to_string()))?;
    dealloc(ptr, layout);
    Ok(())
}
