//! Unix socket transport (Linux, macOS). Callers are identified by the
//! kernel (`SO_PEERCRED` / `getpeereid`), not by anything they send.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::server::{Caller, Slot, UserId, handle_conn, permitted};
use crate::state::Daemon;

#[cfg(target_os = "linux")]
fn peer_uid(stream: &UnixStream) -> Option<u32> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    (rc == 0).then_some(cred.uid)
}

#[cfg(not(target_os = "linux"))]
fn peer_uid(stream: &UnixStream) -> Option<u32> {
    let (mut uid, mut gid) = (0, 0);
    let rc = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
    (rc == 0).then_some(uid)
}

pub fn serve(
    path: &Path,
    daemon: Arc<Mutex<Daemon>>,
    allowed: Option<Vec<UserId>>,
) -> std::io::Result<()> {
    let _ = fs::remove_file(path);
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let listener = UnixListener::bind(path)?;
    // Anyone may connect; each connection is checked by its peer uid.
    fs::set_permissions(path, fs::Permissions::from_mode(0o666))?;
    let allowed = Arc::new(allowed);
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let Some(caller) = peer_uid(&stream).map(|uid| match uid {
            0 => Caller::Admin,
            uid => Caller::Uid(uid),
        }) else {
            continue;
        };
        let Some(slot) = Slot::take(&caller) else {
            continue;
        };
        let daemon = daemon.clone();
        let allowed = allowed.clone();
        std::thread::spawn(move || {
            let _slot = slot;
            let ok = permitted(Some(&caller), allowed.as_deref());
            stream.set_read_timeout(Some(Duration::from_secs(60))).ok();
            let Ok(writer) = stream.try_clone() else {
                return;
            };
            handle_conn(stream, writer, daemon, ok);
        });
    }
    Ok(())
}
