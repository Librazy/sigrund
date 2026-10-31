//! Keep a verified directory FD in SQLite filenames. The bundled Unix VFS
//! already uses O_NOFOLLOW on database/WAL/SHM files; only its pathname
//! canonicalizer must be replaced so it does not dereference /proc/self/fd.
use crate::{CoreError, Result};
use rusqlite::ffi;
use std::{ffi::CStr, sync::OnceLock};

pub(crate) fn register() -> Result<()> {
    static REGISTERED: OnceLock<std::result::Result<(), String>> = OnceLock::new();
    REGISTERED
        .get_or_init(|| {
            // Initialize SQLite before accessing its process-lifetime VFS table.
            if unsafe { ffi::sqlite3_initialize() } != ffi::SQLITE_OK {
                return Err("SQLite initialization failed".into());
            }
            let base = unsafe { ffi::sqlite3_vfs_find(c"unix".as_ptr()) };
            if base.is_null() {
                return Err("Unix SQLite VFS unavailable".into());
            }
            // All remaining callbacks and their application data belong to the
            // built-in Unix VFS, whose lifetime is the entire process. This copy
            // is registered once, never unregistered, and never made the default.
            let mut vfs = Box::new(unsafe { std::ptr::read(base) });
            vfs.zName = c"sigrund-pinned-v1".as_ptr();
            vfs.pNext = std::ptr::null_mut();
            vfs.xFullPathname = Some(full_pathname);
            let raw = Box::into_raw(vfs);
            if unsafe { ffi::sqlite3_vfs_register(raw, 0) } != ffi::SQLITE_OK {
                unsafe {
                    drop(Box::from_raw(raw));
                }
                return Err("SQLite pinned VFS registration failed".into());
            }
            Ok(())
        })
        .clone()
        .map_err(CoreError::Database)
}

unsafe extern "C" fn full_pathname(
    _vfs: *mut ffi::sqlite3_vfs,
    input: *const std::ffi::c_char,
    capacity: std::ffi::c_int,
    output: *mut std::ffi::c_char,
) -> std::ffi::c_int {
    if input.is_null() || output.is_null() || capacity <= 0 {
        return ffi::SQLITE_CANTOPEN;
    }
    // Inputs/outputs and capacity are SQLite-owned buffers for this callback.
    let bytes = unsafe { CStr::from_ptr(input) }.to_bytes();
    let Some(relative) = bytes.strip_prefix(b"/proc/self/fd/") else {
        return ffi::SQLITE_CANTOPEN;
    };
    let Some(number) = relative.strip_suffix(b"/state.sqlite") else {
        return ffi::SQLITE_CANTOPEN;
    };
    if number.is_empty()
        || !number.iter().all(u8::is_ascii_digit)
        || bytes.len() >= capacity as usize
    {
        return ffi::SQLITE_CANTOPEN;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(input, output, bytes.len() + 1);
    }
    ffi::SQLITE_OK
}
