//! The named pipe (`\\.\pipe\deepwork`) that the app and `deepworkctl` use.

use std::ffi::c_void;
use std::fs::File;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::path::Path;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use windows_sys::Win32::Foundation::{
    ERROR_PIPE_CONNECTED, GetLastError, HANDLE, INVALID_HANDLE_VALUE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, IsWellKnownSid, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
    TOKEN_ELEVATION, TOKEN_QUERY, TOKEN_USER, TokenElevation, TokenUser, WinLocalSystemSid,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_FLAG_FIRST_PIPE_INSTANCE, FlushFileBuffers, PIPE_ACCESS_DUPLEX,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
    PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES,
    PIPE_WAIT,
};
use windows_sys::Win32::System::Threading::{
    OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
};

use deepwork_core::client::is_service_pipe;
use deepwork_core::windows::owned_by_admins;

use crate::server::{Caller, Slot, UserId, handle_conn, permitted};
use crate::state::Daemon;

/// SYSTEM and administrators get full access. Other signed-in users may read
/// and write (`FILE_GENERIC_READ | FILE_WRITE_DATA`), but not create pipe
/// instances, so nobody can pose as the service.
const SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x0012008b;;;AU)";

/// Refusals not yet read by clients that may not control DeepWork. They
/// have places of their own, so leaving refusals unread can't use up the
/// connections of the users who may.
const MAX_REFUSALS: usize = 8;
static REFUSALS: AtomicUsize = AtomicUsize::new(0);

/// One of the [`MAX_REFUSALS`]; freed when dropped.
struct Refusal(());

impl Refusal {
    fn take() -> Option<Refusal> {
        if REFUSALS.fetch_add(1, Ordering::SeqCst) >= MAX_REFUSALS {
            REFUSALS.fetch_sub(1, Ordering::SeqCst);
            return None;
        }
        Some(Refusal(()))
    }
}

impl Drop for Refusal {
    fn drop(&mut self) {
        REFUSALS.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Answer one client, then wait until it has read everything (for a client
/// that never reads, as long as the process lives) and disconnect.
fn serve_one(pipe: File, daemon: Arc<Mutex<Daemon>>, permitted: bool) {
    handle_conn(&pipe, &pipe, daemon, permitted);
    let h = pipe.as_raw_handle() as HANDLE;
    // SAFETY: `pipe` still owns the handle.
    unsafe {
        FlushFileBuffers(h);
        DisconnectNamedPipe(h);
    }
}

/// Serve clients on the pipe at `path` until the process ends.
pub fn serve(
    path: &Path,
    daemon: Arc<Mutex<Daemon>>,
    allowed: Option<Vec<UserId>>,
) -> io::Result<()> {
    let name: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
    let sddl: Vec<u16> = SDDL.encode_utf16().chain([0]).collect();
    let mut sd: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: valid NUL-terminated string and out pointer. The descriptor is
    // used for every pipe instance and lives as long as the process.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut sd,
            null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let sa = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd,
        bInheritHandle: 0,
    };

    let mut first = true;
    let mut squatted = false;
    loop {
        // The first instance must be ours: fail if someone else holds the name.
        let open_mode = PIPE_ACCESS_DUPLEX
            | if first {
                FILE_FLAG_FIRST_PIPE_INSTANCE
            } else {
                0
            };
        // SAFETY: valid name and security attributes.
        let h = unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                open_mode,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                PIPE_UNLIMITED_INSTANCES,
                64 * 1024,
                64 * 1024,
                0,
                &sa,
            )
        };
        if h == INVALID_HANDLE_VALUE {
            let err = io::Error::last_os_error();
            // Another program took the service's name while it wasn't
            // running. Clients won't talk to it (see `Client`), and blocks
            // keep being enforced meanwhile; the name is ours once it's gone.
            if first && is_service_pipe(&path.to_string_lossy()) && !held_by_admins(path) {
                if !squatted {
                    eprintln!(
                        "deepwork: another program holds {}, so the app can't reach the \
                         service until that program ends",
                        path.display()
                    );
                    squatted = true;
                }
                std::thread::sleep(Duration::from_secs(5));
                continue;
            }
            return Err(err);
        }
        if squatted {
            eprintln!("deepwork: {} is the service's again", path.display());
            squatted = false;
        }
        first = false;
        // SAFETY: `h` is a fresh handle that we own from here on.
        let pipe = unsafe { File::from_raw_handle(h as RawHandle) };
        // SAFETY: valid pipe handle, synchronous mode.
        let connected = unsafe { ConnectNamedPipe(h, null_mut()) } != 0
            || unsafe { GetLastError() } == ERROR_PIPE_CONNECTED;
        if !connected {
            continue;
        }
        let daemon = daemon.clone();
        let caller = client(&pipe);
        if let Some(caller) = caller.filter(|c| permitted(Some(c), allowed.as_deref())) {
            let Some(slot) = Slot::take(&caller) else {
                // SAFETY: `pipe` still owns the handle.
                unsafe { DisconnectNamedPipe(h) };
                continue;
            };
            std::thread::spawn(move || {
                let _slot = slot;
                serve_one(pipe, daemon, true);
            });
        } else {
            let Some(refusal) = Refusal::take() else {
                // SAFETY: `pipe` still owns the handle.
                unsafe { DisconnectNamedPipe(h) };
                continue;
            };
            std::thread::spawn(move || {
                let _refusal = refusal;
                serve_one(pipe, daemon, false);
            });
        }
    }
}

/// Whether the existing pipe at `path` is that of another copy of the
/// service (or something else of the administrators'). Their pipes let
/// SYSTEM and administrators in; one that doesn't, or that belongs to
/// someone else, isn't theirs.
fn held_by_admins(path: &Path) -> bool {
    use std::os::windows::fs::OpenOptionsExt;
    // READ_CONTROL: enough to see the owner, without writing to the pipe.
    const READ_CONTROL: u32 = 0x0002_0000;
    std::fs::OpenOptions::new()
        .access_mode(READ_CONTROL)
        .open(path)
        .is_ok_and(|f| owned_by_admins(&f))
}

/// The caller: an administrator for SYSTEM and elevated administrators,
/// otherwise their user SID.
fn client(pipe: &File) -> Option<Caller> {
    // SAFETY: plain Win32 calls with valid out pointers; every handle we open
    // is wrapped in an `OwnedHandle` so it gets closed.
    unsafe {
        let mut pid = 0u32;
        if GetNamedPipeClientProcessId(pipe.as_raw_handle() as HANDLE, &mut pid) == 0 {
            return None;
        }
        let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if process.is_null() {
            return None;
        }
        let process = OwnedHandle::from_raw_handle(process as RawHandle);
        let mut token: HANDLE = null_mut();
        if OpenProcessToken(process.as_raw_handle() as HANDLE, TOKEN_QUERY, &mut token) == 0 {
            return None;
        }
        let token = OwnedHandle::from_raw_handle(token as RawHandle);
        let token = token.as_raw_handle() as HANDLE;

        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut len = 0u32;
        if GetTokenInformation(
            token,
            TokenElevation,
            &mut elevation as *mut _ as *mut c_void,
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut len,
        ) != 0
            && elevation.TokenIsElevated != 0
        {
            return Some(Caller::Admin);
        }

        // TOKEN_USER plus the SID it points to; u64s keep it aligned.
        let mut buf = [0u64; 64];
        if GetTokenInformation(
            token,
            TokenUser,
            buf.as_mut_ptr() as *mut c_void,
            size_of_val(&buf) as u32,
            &mut len,
        ) == 0
        {
            return None;
        }
        let sid = (*(buf.as_ptr() as *const TOKEN_USER)).User.Sid;
        if IsWellKnownSid(sid, WinLocalSystemSid) != 0 {
            return Some(Caller::Admin);
        }
        let mut text: *mut u16 = null_mut();
        if ConvertSidToStringSidW(sid, &mut text) == 0 || text.is_null() {
            return None;
        }
        let len = (0..).take_while(|&i| *text.add(i) != 0).count();
        let s = String::from_utf16_lossy(std::slice::from_raw_parts(text, len));
        LocalFree(text.cast());
        Some(Caller::Sid(s))
    }
}

#[cfg(test)]
mod tests;
