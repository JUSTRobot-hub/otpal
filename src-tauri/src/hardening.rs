//! Windows-only protections for the running process.
//!
//! - The window is excluded from screenshots and screen recording (it shows black to them).
//! - Other programs running as the same user cannot read or write this process's memory, start
//!   threads in it, or change its permissions. Administrators and debuggers holding the debug
//!   privilege can still get around that, and it does not cover the browser helper processes.
//! - The vault locks when Windows locks, the PC sleeps, or the window is minimized.

use crate::vault;
use std::{ffi::c_void, ptr, sync::OnceLock};
use tauri::{AppHandle, Manager};
use windows_sys::Win32::{
    Foundation::{LocalFree, HWND, LPARAM, LRESULT, WPARAM},
    Security::{
        Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1},
        SetKernelObjectSecurity, DACL_SECURITY_INFORMATION,
    },
    System::{
        RemoteDesktop::{WTSRegisterSessionNotification, NOTIFY_FOR_THIS_SESSION},
        Threading::GetCurrentProcess,
    },
    UI::{
        Shell::{DefSubclassProc, SetWindowSubclass},
        WindowsAndMessaging::{
            SetWindowDisplayAffinity, PBT_APMSUSPEND, SIZE_MINIMIZED, WDA_EXCLUDEFROMCAPTURE, WM_POWERBROADCAST,
            WM_SIZE, WM_WTSSESSION_CHANGE,
        },
    },
};

/// WTS_SESSION_LOCK: the workstation was locked (Win+L, or the lock screen came up).
const WTS_SESSION_LOCK: u32 = 0x7;

static APP: OnceLock<AppHandle> = OnceLock::new();

pub fn apply(app: &tauri::App) {
    let _ = APP.set(app.handle().clone());
    // Debug builds keep these off so a debugger can attach while developing.
    if !cfg!(debug_assertions) {
        protect_process_memory();
    }
    if let Some(window) = app.get_webview_window("main") {
        if let Ok(hwnd) = window.hwnd() {
            let hwnd = hwnd.0 as HWND;
            // SAFETY: `hwnd` is this app's live top-level window and setup runs on its thread.
            unsafe {
                if !cfg!(debug_assertions) {
                    SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE);
                }
                WTSRegisterSessionNotification(hwnd, NOTIFY_FOR_THIS_SESSION);
                SetWindowSubclass(hwnd, Some(lock_triggers), 1, 0);
            }
        }
    }
}

/// Runs on the window's thread for every message, so it only does the cheap part.
unsafe extern "system" fn lock_triggers(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM, _id: usize, _data: usize) -> LRESULT {
    let lock_now = match msg {
        WM_WTSSESSION_CHANGE => wparam as u32 == WTS_SESSION_LOCK,
        WM_POWERBROADCAST => wparam as u32 == PBT_APMSUSPEND,
        WM_SIZE => wparam as u32 == SIZE_MINIMIZED,
        _ => false,
    };
    if lock_now {
        if let Some(app) = APP.get() {
            vault::lock(app);
        }
    }
    DefSubclassProc(hwnd, msg, wparam, lparam)
}

/// Denies other processes the rights needed to read or write this process's memory, create
/// threads in it, or edit this very permission list. Everyone else keeps ordinary access, so
/// Task Manager and the browser helper processes keep working.
fn protect_process_memory() {
    // Deny: create thread 0x2, VM operation 0x8, VM read 0x10, VM write 0x20, write DAC 0x40000,
    // write owner 0x80000. Owner rights are cut to "read permissions" so the owner cannot
    // quietly grant themselves access back.
    let sddl: Vec<u16> = "D:(D;;0x000C003A;;;WD)(A;;GA;;;WD)(A;;0x20000;;;OW)\0".encode_utf16().collect();
    let mut descriptor: *mut c_void = ptr::null_mut();
    // SAFETY: `sddl` is NUL-terminated; Windows allocates `descriptor`, which is freed below.
    unsafe {
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), SDDL_REVISION_1, &mut descriptor, ptr::null_mut()) != 0 {
            SetKernelObjectSecurity(GetCurrentProcess(), DACL_SECURITY_INFORMATION, descriptor);
            LocalFree(descriptor);
        }
    }
}
