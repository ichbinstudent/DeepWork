//! Windows helpers shared by the service and its clients.

use std::fs::File;
use std::os::windows::io::AsRawHandle;
use std::ptr::null_mut;

use windows_sys::Win32::Foundation::{HANDLE, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, GetSecurityInfo, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    IsWellKnownSid, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    WinBuiltinAdministratorsSid, WinLocalSystemSid,
};

/// Whether administrators or SYSTEM own the object (a file, folder or named
/// pipe; the handle needs `READ_CONTROL`). Others can't make them its owner:
/// an object's owner is always one of its creator's own groups.
pub fn owned_by_admins(file: &File) -> bool {
    owner_is(file, is_admins)
}

/// Whether Windows itself (TrustedInstaller, who owns its programs),
/// administrators or SYSTEM own a file.
pub fn owned_by_system(file: &File) -> bool {
    const TRUSTED_INSTALLER: &str =
        "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
    // SAFETY: the owner is a valid SID.
    owner_is(file, |sid| unsafe {
        is_admins(sid) || sid_string(sid).is_some_and(|s| s == TRUSTED_INSTALLER)
    })
}

fn is_admins(sid: PSID) -> bool {
    // SAFETY: a valid SID from the system.
    unsafe {
        IsWellKnownSid(sid, WinBuiltinAdministratorsSid) != 0
            || IsWellKnownSid(sid, WinLocalSystemSid) != 0
    }
}

/// A SID as text (`S-1-5-…`).
///
/// # Safety
/// `sid` must point to a valid SID.
pub unsafe fn sid_string(sid: PSID) -> Option<String> {
    let mut text: *mut u16 = null_mut();
    // SAFETY: the system fills in a NUL-terminated string, freed here.
    unsafe {
        if ConvertSidToStringSidW(sid, &mut text) == 0 || text.is_null() {
            return None;
        }
        let len = (0..).take_while(|&i| *text.add(i) != 0).count();
        let s = String::from_utf16_lossy(std::slice::from_raw_parts(text, len));
        LocalFree(text.cast());
        Some(s)
    }
}

fn owner_is(file: &File, matches: impl Fn(PSID) -> bool) -> bool {
    let mut owner: PSID = null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: valid handle and out pointers; the descriptor is freed below
    // and `owner` points into it.
    unsafe {
        let err = GetSecurityInfo(
            file.as_raw_handle() as HANDLE,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            null_mut(),
            null_mut(),
            &mut sd,
        );
        if err != 0 {
            return false;
        }
        let ok = matches(owner);
        LocalFree(sd);
        ok
    }
}
