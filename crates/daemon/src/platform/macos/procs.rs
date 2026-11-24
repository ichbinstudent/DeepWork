//! Listing and closing people's processes (libproc, `sysctl`). Apps are
//! known by their bundle id, from the `Info.plist` of the app they run from.

use std::collections::HashMap;
use std::ffi::{CStr, c_int};
use std::fs;
use std::io::Read;
use std::mem::{MaybeUninit, size_of};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::ptr::null_mut;
use std::sync::Mutex;

use deepwork_core::model::is_protected_process;

use crate::platform::ProcessTable;
use crate::procs::Proc;

pub struct Processes {
    /// Lowest uid of a person's account.
    uid_min: u32,
    /// Bundle ids by app folder.
    bundles: Mutex<HashMap<PathBuf, Option<String>>>,
}

/// Whether `uid` belongs to a person rather than to root, a service, or
/// nobody (-2) and the ids next to it.
fn is_user_account(uid: u32, uid_min: u32) -> bool {
    uid != 0 && uid >= uid_min && uid < u32::MAX - 100
}

impl Processes {
    pub fn new(uid_min: u32) -> Processes {
        Processes {
            uid_min,
            bundles: Mutex::new(HashMap::new()),
        }
    }

    fn describe(&self, pid: c_int, args: &mut [u8]) -> Option<Proc> {
        let info = bsd_info(pid)?;
        let mut p = Proc {
            pid: pid.cast_unsigned(),
            privileged: !is_user_account(info.pbi_uid, self.uid_min),
            start_time: start_time(&info),
            ..Default::default()
        };
        if p.privileged {
            return Some(p);
        }
        let (exec, argv) = arguments(pid, args).unwrap_or_default();
        // The kernel's path of the running file. It has none once the file
        // is deleted; then the one the program was started with has to do.
        let path = path_of(pid);
        p.exe = path.clone().unwrap_or(exec);
        let file = p.exe.rsplit('/').next().unwrap_or_default();
        p.comm = if file.is_empty() {
            c_string(&info.pbi_name)
        } else {
            file.to_string()
        };
        p.system_exe = is_protected_process(file) && path.is_some_and(|path| is_system(&path));
        p.argv0 = argv.first().cloned().unwrap_or_default();
        p.cmdline = argv.join(" ");
        p.app_id = bundle_of(&p.exe).and_then(|b| self.bundle_id(b));
        Some(p)
    }

    fn bundle_id(&self, bundle: PathBuf) -> Option<String> {
        let mut bundles = self.bundles.lock().unwrap_or_else(|e| e.into_inner());
        if bundles.len() > 4096 {
            bundles.clear();
        }
        bundles
            .entry(bundle)
            .or_insert_with_key(|b| read_bundle_id(b))
            .clone()
    }
}

impl ProcessTable for Processes {
    fn list(&self) -> Vec<Proc> {
        let mut args = vec![0u8; 1 << 20]; // kern.argmax
        pids()
            .into_iter()
            .filter_map(|pid| self.describe(pid, &mut args))
            .collect()
    }

    fn terminate(&self, processes: &[Proc], force: bool) {
        let sig = if force { libc::SIGKILL } else { libc::SIGTERM };
        for p in processes {
            let pid = p.pid.cast_signed();
            if bsd_info(pid).is_some_and(|i| start_time(&i) == p.start_time) {
                // SAFETY: plain system call.
                unsafe { libc::kill(pid, sig) };
            }
        }
    }
}

fn pids() -> Vec<c_int> {
    // SAFETY: a count query, then a buffer of the size given.
    unsafe {
        let n = libc::proc_listallpids(null_mut(), 0);
        // Room for processes started in the meantime.
        let mut pids = vec![0; usize::try_from(n).unwrap_or(0) + 64];
        let n = libc::proc_listallpids(
            pids.as_mut_ptr().cast(),
            (pids.len() * size_of::<c_int>()) as c_int,
        );
        pids.truncate(usize::try_from(n).unwrap_or(0));
        pids.retain(|p| *p > 0);
        pids
    }
}

fn bsd_info(pid: c_int) -> Option<libc::proc_bsdinfo> {
    let mut info = MaybeUninit::<libc::proc_bsdinfo>::zeroed();
    let size = size_of::<libc::proc_bsdinfo>() as c_int;
    // SAFETY: the buffer has the size given; plain integers, valid when
    // zeroed.
    unsafe {
        let n = libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            size,
        );
        (n == size).then(|| info.assume_init())
    }
}

fn start_time(info: &libc::proc_bsdinfo) -> u64 {
    info.pbi_start_tvsec * 1_000_000 + info.pbi_start_tvusec
}

fn c_string(s: &[libc::c_char]) -> String {
    let bytes: Vec<u8> = s.iter().map(|c| c.cast_unsigned()).collect();
    let text = CStr::from_bytes_until_nul(&bytes).map(CStr::to_string_lossy);
    text.unwrap_or_default().into_owned()
}

fn path_of(pid: c_int) -> Option<String> {
    let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    // SAFETY: the buffer has the size given.
    let n = unsafe { libc::proc_pidpath(pid, buf.as_mut_ptr().cast(), buf.len() as u32) };
    let n = usize::try_from(n).ok().filter(|n| *n > 0)?;
    Some(String::from_utf8_lossy(&buf[..n]).into_owned())
}

/// The file a process was started from, and its arguments.
fn arguments(pid: c_int, buf: &mut [u8]) -> Option<(String, Vec<String>)> {
    let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid];
    let mut len = buf.len();
    // SAFETY: the buffer has the size given; `len` is set to what was written.
    let rc = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as u32,
            buf.as_mut_ptr().cast(),
            &mut len,
            null_mut(),
            0,
        )
    };
    (rc == 0).then(|| parse_arguments(buf.get(..len)?))?
}

/// `KERN_PROCARGS2`: the number of arguments, the file, NULs up to a word
/// boundary, the arguments, the environment.
fn parse_arguments(data: &[u8]) -> Option<(String, Vec<String>)> {
    let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
    let (argc, rest) = data.split_first_chunk::<4>()?;
    let argc = usize::try_from(i32::from_ne_bytes(*argc)).ok()?;
    let end = rest.iter().position(|b| *b == 0)?;
    let (exec, rest) = rest.split_at(end);
    let start = rest.iter().position(|b| *b != 0).unwrap_or(rest.len());
    let args = rest[start..].split(|b| *b == 0).take(argc).map(text);
    Some((text(exec), args.collect()))
}

/// Whether a program file belongs to the system: root's, in a folder only
/// administrators can change.
fn is_system(path: &str) -> bool {
    let path = Path::new(path);
    fs::symlink_metadata(path).is_ok_and(|m| m.is_file() && m.uid() == 0)
        && path.parent().is_some_and(crate::admin_only)
}

/// The app folder a program runs from: the outermost, so an app's helpers
/// count as the app.
fn bundle_of(exe: &str) -> Option<PathBuf> {
    let end = exe.to_ascii_lowercase().find(".app/")?;
    Some(PathBuf::from(exe.get(..end + 4)?))
}

fn read_bundle_id(bundle: &Path) -> Option<String> {
    const MAX: u64 = 1 << 20;
    // Anyone may make an app folder: no waiting on what isn't a plain file.
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(bundle.join("Contents/Info.plist"))
        .ok()?;
    let meta = file.metadata().ok()?;
    if !meta.is_file() || meta.len() > MAX {
        return None;
    }
    let mut data = vec![];
    file.take(MAX).read_to_end(&mut data).ok()?;
    let info = plist::Value::from_reader(std::io::Cursor::new(data)).ok()?;
    let id = info.as_dictionary()?.get("CFBundleIdentifier")?;
    let id = id.as_string()?.trim();
    (!id.is_empty()).then(|| id.to_string())
}

#[cfg(test)]
mod tests;
