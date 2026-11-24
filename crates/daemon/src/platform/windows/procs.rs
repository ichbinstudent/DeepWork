//! Listing and closing people's processes.
//!
//! Programs that were open before are asked to close first, the way a click
//! on their close button does, so they can save. The service can't reach
//! windows from its own session, so it starts itself in the person's session
//! for that ([`CLOSE_WINDOWS`]).

use std::collections::{HashMap, HashSet};
use std::ffi::c_void;
use std::fs::File;
use std::mem::{size_of, zeroed};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::ptr::{null, null_mut};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use windows_sys::Wdk::System::Threading::{
    NtQueryInformationProcess, ProcessCommandLineInformation,
};
use windows_sys::Win32::Foundation::{
    ERROR_INSUFFICIENT_BUFFER, FILETIME, HANDLE, HWND, INVALID_HANDLE_VALUE, LPARAM,
    UNICODE_STRING, WAIT_OBJECT_0,
};
use windows_sys::Win32::Security::{
    DuplicateTokenEx, GetTokenInformation, SECURITY_MAX_SID_SIZE, SecurityImpersonation,
    TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_ELEVATION, TOKEN_QUERY, TOKEN_USER,
    TokenElevation, TokenPrimary, TokenUser,
};
use windows_sys::Win32::Storage::Packaging::Appx::GetPackageFamilyName;
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::RemoteDesktop::{ProcessIdToSessionId, WTSQueryUserToken};
use windows_sys::Win32::System::SystemInformation::GetSystemTimeAsFileTime;
use windows_sys::Win32::System::Threading::{
    CREATE_NO_WINDOW, CreateProcessAsUserW, GetCurrentProcessId, GetExitCodeProcess,
    GetProcessTimes, OpenProcess, OpenProcessToken, PROCESS_INFORMATION, PROCESS_NAME_WIN32,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE, QueryFullProcessImageNameW, STARTUPINFOW,
    TerminateProcess, WaitForSingleObject,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    EnumChildWindows, EnumWindows, GetWindowThreadProcessId, IsWindowVisible, PostMessageW,
    WM_CLOSE,
};

use deepwork_core::model::is_protected_process;
use deepwork_core::windows::{owned_by_system, sid_string};

use crate::platform::ProcessTable;
use crate::procs::Proc;

/// `deepwork-daemon --close-windows PID,PID…`: ask these processes to close
/// their windows.
pub const CLOSE_WINDOWS: &str = "--close-windows";

/// A program younger than this (in 100 ns, as in FILETIME) has nothing to
/// save yet and is closed right away.
const YOUNG: u64 = 10 * 10_000_000;

const GRACE: Duration = Duration::from_secs(10);

/// The processes seen last time (pid to what it is), so only new ones are
/// looked at closely.
#[derive(Default)]
pub struct Processes {
    known: Mutex<HashMap<u32, Proc>>,
}

impl ProcessTable for Processes {
    fn list(&self) -> Vec<Proc> {
        let mut known = self.known.lock().unwrap_or_else(|e| e.into_inner());
        let mut now = HashMap::new();
        for (pid, name) in snapshot() {
            let Some(process) = open(pid, PROCESS_QUERY_LIMITED_INFORMATION) else {
                continue;
            };
            let Some(start) = started(&process) else {
                continue;
            };
            let p = known
                .remove(&pid)
                .filter(|p| p.start_time == start)
                .unwrap_or_else(|| describe(&process, pid, name, start));
            now.insert(pid, p);
        }
        *known = now;
        known.values().cloned().collect()
    }

    /// Enough to answer "save changes?".
    fn grace(&self) -> Duration {
        GRACE
    }

    fn terminate(&self, processes: &[Proc], force: bool) {
        let now = now();
        // By session, and whether they run elevated.
        let mut ask: HashMap<(u32, bool), (Vec<u32>, Option<OwnedHandle>)> = HashMap::new();
        for p in processes {
            // Keeps the pid from being reused meanwhile.
            let Some(handle) = open(p.pid, PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION)
            else {
                continue;
            };
            if started(&handle) != Some(p.start_time) {
                continue;
            }
            if !force
                && now.saturating_sub(p.start_time) > YOUNG
                && let Some(session) = session_of(p.pid)
            {
                let token = elevated_token(&handle);
                let (pids, with) = ask.entry((session, token.is_some())).or_default();
                pids.push(p.pid);
                *with = with.take().or(token);
                continue;
            }
            // SAFETY: a process handle with the right to terminate it.
            unsafe { TerminateProcess(handle.as_raw_handle() as HANDLE, 1) };
        }
        for ((session, _), (pids, token)) in ask {
            close_windows_in(session, &pids, token);
        }
    }
}

/// Every process's id and file name.
fn snapshot() -> Vec<(u32, String)> {
    let mut list = vec![];
    // SAFETY: the snapshot handle is checked and closed; the entry is
    // initialised with its size as documented.
    unsafe {
        let h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if h == INVALID_HANDLE_VALUE {
            return list;
        }
        let h = OwnedHandle::from_raw_handle(h as RawHandle);
        let mut e: PROCESSENTRY32W = zeroed();
        e.dwSize = size_of::<PROCESSENTRY32W>() as u32;
        let mut more = Process32FirstW(h.as_raw_handle() as HANDLE, &mut e) != 0;
        while more {
            list.push((e.th32ProcessID, text(&e.szExeFile)));
            more = Process32NextW(h.as_raw_handle() as HANDLE, &mut e) != 0;
        }
    }
    list
}

/// A UTF-16 string up to its NUL.
fn text(s: &[u16]) -> String {
    let end = s.iter().position(|c| *c == 0).unwrap_or(s.len());
    String::from_utf16_lossy(&s[..end])
}

fn open(pid: u32, access: u32) -> Option<OwnedHandle> {
    // SAFETY: plain call; a handle we get is ours.
    unsafe {
        let h = OpenProcess(access, 0, pid);
        (!h.is_null()).then(|| OwnedHandle::from_raw_handle(h as RawHandle))
    }
}

fn filetime(t: FILETIME) -> u64 {
    (u64::from(t.dwHighDateTime) << 32) | u64::from(t.dwLowDateTime)
}

fn now() -> u64 {
    // SAFETY: valid out pointer.
    unsafe {
        let mut t: FILETIME = zeroed();
        GetSystemTimeAsFileTime(&mut t);
        filetime(t)
    }
}

/// When the process started.
fn started(process: &OwnedHandle) -> Option<u64> {
    // SAFETY: valid handle and out pointers.
    unsafe {
        let [mut start, mut exit, mut kernel, mut user]: [FILETIME; 4] = zeroed();
        (GetProcessTimes(
            process.as_raw_handle() as HANDLE,
            &mut start,
            &mut exit,
            &mut kernel,
            &mut user,
        ) != 0)
            .then(|| filetime(start))
    }
}

/// The session a process runs in; `None` for session 0, where services run.
fn session_of(pid: u32) -> Option<u32> {
    let mut session = 0;
    // SAFETY: valid out pointer.
    let ok = unsafe { ProcessIdToSessionId(pid, &mut session) } != 0;
    (ok && session != 0).then_some(session)
}

/// Whether a SID is a person's account (of this computer, a domain, or
/// Entra ID), not SYSTEM, a service or the window manager.
fn is_person(sid: &str) -> bool {
    sid.starts_with("S-1-5-21-") || sid.starts_with("S-1-12-1-")
}

fn describe(process: &OwnedHandle, pid: u32, name: String, start: u64) -> Proc {
    let person = session_of(pid).is_some() && user(process).is_some_and(|sid| is_person(&sid));
    if !person {
        return Proc {
            pid,
            privileged: true,
            comm: name,
            start_time: start,
            ..Default::default()
        };
    }
    let exe = exe(process).unwrap_or_default();
    let cmdline = cmdline(process).unwrap_or_default();
    // Only matters for names that are protected.
    let file = exe.rsplit('\\').next().unwrap_or_default();
    let package = package_family(process);
    let protected =
        is_protected_process(file) || package.as_deref().is_some_and(is_protected_process);
    let system_exe = protected && belongs_to_system(&exe);
    Proc {
        pid,
        privileged: false,
        comm: name,
        system_exe,
        argv0: first_argument(&cmdline).to_string(),
        cmdline,
        app_id: package,
        start_time: start,
        exe,
    }
}

/// The SID of the user a process runs as.
fn user(process: &OwnedHandle) -> Option<String> {
    // SAFETY: valid handles and out pointers; the buffer is aligned and big
    // enough for TOKEN_USER and any SID.
    unsafe {
        let mut token: HANDLE = null_mut();
        if OpenProcessToken(process.as_raw_handle() as HANDLE, TOKEN_QUERY, &mut token) == 0 {
            return None;
        }
        let token = OwnedHandle::from_raw_handle(token as RawHandle);
        let mut buf = [0u64; (size_of::<TOKEN_USER>() + SECURITY_MAX_SID_SIZE as usize) / 8 + 1];
        let mut len = 0;
        if GetTokenInformation(
            token.as_raw_handle() as HANDLE,
            TokenUser,
            buf.as_mut_ptr().cast(),
            size_of_val(&buf) as u32,
            &mut len,
        ) == 0
        {
            return None;
        }
        sid_string((*buf.as_ptr().cast::<TOKEN_USER>()).User.Sid)
    }
}

/// The program's file, as the kernel knows it.
fn exe(process: &OwnedHandle) -> Option<String> {
    let mut buf = vec![0u16; 32 * 1024];
    let mut len = buf.len() as u32;
    // SAFETY: the buffer holds `len` characters.
    let ok = unsafe {
        QueryFullProcessImageNameW(
            process.as_raw_handle() as HANDLE,
            PROCESS_NAME_WIN32,
            buf.as_mut_ptr(),
            &mut len,
        )
    };
    (ok != 0).then(|| String::from_utf16_lossy(&buf[..len as usize]))
}

fn cmdline(process: &OwnedHandle) -> Option<String> {
    let mut len = 0u32;
    // SAFETY: a size query, then a buffer of that size (u64s keep it
    // aligned). The kernel fills in a UNICODE_STRING that points into the
    // same buffer; both are checked against it.
    unsafe {
        let h = process.as_raw_handle() as HANDLE;
        NtQueryInformationProcess(h, ProcessCommandLineInformation, null_mut(), 0, &mut len);
        if len == 0 || len > 1 << 20 {
            return None;
        }
        let mut buf = vec![0u64; len as usize / 8 + 1];
        let size = (buf.len() * 8) as u32;
        if NtQueryInformationProcess(
            h,
            ProcessCommandLineInformation,
            buf.as_mut_ptr().cast(),
            size,
            &mut len,
        ) < 0
        {
            return None;
        }
        let s = &*buf.as_ptr().cast::<UNICODE_STRING>();
        let base = buf.as_ptr() as usize;
        let start = (s.Buffer as usize).checked_sub(base)?;
        if start + s.Length as usize > size as usize || !start.is_multiple_of(2) {
            return None;
        }
        let chars = std::slice::from_raw_parts(s.Buffer, s.Length as usize / 2);
        Some(String::from_utf16_lossy(chars))
    }
}

/// The first argument of a command line, without quotes.
fn first_argument(cmdline: &str) -> &str {
    let s = cmdline.trim_start();
    match s.strip_prefix('"') {
        Some(rest) => rest.split('"').next().unwrap_or(rest),
        None => s.split_whitespace().next().unwrap_or(s),
    }
}

/// The package family name of a Store app (`SpotifyAB.SpotifyMusic_…`).
fn package_family(process: &OwnedHandle) -> Option<String> {
    let mut buf = [0u16; 256];
    let mut len = buf.len() as u32;
    // SAFETY: the buffer holds `len` characters.
    let code = unsafe {
        GetPackageFamilyName(
            process.as_raw_handle() as HANDLE,
            &mut len,
            buf.as_mut_ptr(),
        )
    };
    debug_assert_ne!(code, ERROR_INSUFFICIENT_BUFFER);
    (code == 0).then(|| text(&buf))
}

/// Whether a program file belongs to Windows or the administrators.
fn belongs_to_system(exe: &str) -> bool {
    // Enough to see who owns it.
    const READ_CONTROL: u32 = 0x0002_0000;
    std::fs::OpenOptions::new()
        .access_mode(READ_CONTROL)
        .open(exe)
        .is_ok_and(|f: File| owned_by_system(&f))
}

// ------------------------------------------------------------------ closing windows

/// A copy of an elevated process's token, `None` if it isn't elevated.
fn elevated_token(process: &OwnedHandle) -> Option<OwnedHandle> {
    // SAFETY: valid handles and out pointers; every handle is closed.
    unsafe {
        let mut token: HANDLE = null_mut();
        if OpenProcessToken(
            process.as_raw_handle() as HANDLE,
            TOKEN_QUERY | TOKEN_DUPLICATE,
            &mut token,
        ) == 0
        {
            return None;
        }
        let token = OwnedHandle::from_raw_handle(token as RawHandle);
        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut len = 0;
        if GetTokenInformation(
            token.as_raw_handle() as HANDLE,
            TokenElevation,
            (&raw mut elevation).cast(),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut len,
        ) == 0
            || elevation.TokenIsElevated == 0
        {
            return None;
        }
        let mut copy: HANDLE = null_mut();
        (DuplicateTokenEx(
            token.as_raw_handle() as HANDLE,
            TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY,
            null(),
            SecurityImpersonation,
            TokenPrimary,
            &mut copy,
        ) != 0)
            .then(|| OwnedHandle::from_raw_handle(copy as RawHandle))
    }
}

/// Ask processes of a session to close, in that session: with the rights of
/// `token` (elevated programs' windows only take messages from elevated
/// programs), otherwise those of the person signed in there.
fn close_windows_in(session: u32, pids: &[u32], token: Option<OwnedHandle>) {
    // SAFETY: no preconditions.
    if session_of(unsafe { GetCurrentProcessId() }) == Some(session) {
        close_windows(pids);
        return;
    }
    let Ok(me) = std::env::current_exe() else {
        return;
    };
    let pids: Vec<String> = pids.iter().map(u32::to_string).collect();
    let wide = |s: &str| s.encode_utf16().chain([0]).collect::<Vec<u16>>();
    let exe = wide(&me.to_string_lossy());
    let mut line = wide(&format!(
        "\"{}\" {CLOSE_WINDOWS} {}",
        me.display(),
        pids.join(",")
    ));
    let mut desktop = wide(r"winsta0\default");
    // SAFETY: valid NUL-terminated strings and out pointers, all alive
    // during the calls; every handle is closed.
    unsafe {
        let token = match token {
            Some(token) => token,
            None => {
                let mut token: HANDLE = null_mut();
                // Needs SYSTEM. Without it, programs are closed without asking.
                if WTSQueryUserToken(session, &mut token) == 0 {
                    eprintln!(
                        "deepwork: cannot ask programs in session {session} to close: {}",
                        std::io::Error::last_os_error()
                    );
                    return;
                }
                OwnedHandle::from_raw_handle(token as RawHandle)
            }
        };
        let mut startup: STARTUPINFOW = zeroed();
        startup.cb = size_of::<STARTUPINFOW>() as u32;
        startup.lpDesktop = desktop.as_mut_ptr();
        let mut info: PROCESS_INFORMATION = zeroed();
        if CreateProcessAsUserW(
            token.as_raw_handle() as HANDLE,
            exe.as_ptr(),
            line.as_mut_ptr(),
            null(),
            null(),
            0,
            CREATE_NO_WINDOW,
            null(),
            null(),
            &startup,
            &mut info,
        ) == 0
        {
            eprintln!(
                "deepwork: cannot ask programs to close: {}",
                std::io::Error::last_os_error()
            );
            return;
        }
        drop(OwnedHandle::from_raw_handle(info.hThread as RawHandle));
        let helper = OwnedHandle::from_raw_handle(info.hProcess as RawHandle);
        std::thread::spawn(move || watch(&helper));
    }
}

/// Report it when asking programs to close fails, or takes so long that they
/// don't get much time for it.
fn watch(helper: &OwnedHandle) {
    let asked = Instant::now();
    let h = helper.as_raw_handle() as HANDLE;
    // SAFETY: a valid process handle and out pointer.
    let (done, code) = unsafe {
        let done = WaitForSingleObject(h, GRACE.as_millis() as u32) == WAIT_OBJECT_0;
        let mut code = 0;
        GetExitCodeProcess(h, &mut code);
        (done, code)
    };
    let took = asked.elapsed().as_secs_f64();
    if !done {
        eprintln!("deepwork: asking programs to close takes more than {took:.1} s");
    } else if code != 0 || took > 2.0 {
        eprintln!("deepwork: asking programs to close took {took:.1} s (exit code {code:#x})");
    }
}

/// The [`CLOSE_WINDOWS`] command.
pub fn close_windows_command(pids: Option<String>) {
    let pids: Vec<u32> = pids
        .unwrap_or_default()
        .split(',')
        .filter_map(|p| p.parse().ok())
        .collect();
    println!("asked {} windows to close", close_windows(&pids));
}

/// Ask every window of these processes to close, like a click on its close
/// button. Returns how many were asked.
fn close_windows(pids: &[u32]) -> usize {
    struct Asked {
        pids: HashSet<u32>,
        windows: usize,
    }
    unsafe extern "system" fn each(window: HWND, asked: LPARAM) -> i32 {
        // SAFETY: the pointer passed to EnumWindows below.
        let Asked { pids, windows } = unsafe { &mut *(asked as *mut Asked) };
        // SAFETY: windows may be gone by now, which these calls handle.
        unsafe {
            if IsWindowVisible(window) != 0 && (belongs(window, pids) || hosts(window, pids)) {
                *windows += usize::from(PostMessageW(window, WM_CLOSE, 0, 0) != 0);
            }
        }
        1
    }
    let mut asked = Asked {
        pids: pids.iter().copied().collect(),
        windows: 0,
    };
    // SAFETY: the callback only uses the pointer during the call.
    unsafe { EnumWindows(Some(each), &raw mut asked as LPARAM) };
    asked.windows
}

fn belongs(window: HWND, pids: &HashSet<u32>) -> bool {
    let mut pid = 0;
    // SAFETY: valid out pointer; a window that is gone has no process.
    unsafe { GetWindowThreadProcessId(window, &mut pid) };
    pids.contains(&pid)
}

/// Whether a window frames one of theirs: Store apps' windows belong to
/// ApplicationFrameHost.
fn hosts(window: HWND, pids: &HashSet<u32>) -> bool {
    struct Search<'a> {
        pids: &'a HashSet<u32>,
        found: bool,
    }
    unsafe extern "system" fn each(window: HWND, search: LPARAM) -> i32 {
        // SAFETY: the pointer passed to EnumChildWindows below.
        let search = unsafe { &mut *(search as *mut Search) };
        search.found = belongs(window, search.pids);
        i32::from(!search.found)
    }
    let mut search = Search { pids, found: false };
    // SAFETY: the callback only uses the pointer during the call.
    unsafe {
        EnumChildWindows(
            window,
            Some(each),
            (&raw mut search).cast::<c_void>() as LPARAM,
        )
    };
    search.found
}

#[cfg(test)]
mod tests;
