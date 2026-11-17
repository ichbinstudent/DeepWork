//! Windows: website blocking and Firefox policies so far.
//!
//! Still to do, roughly in order:
//! - IPC ([`serve`]): a named pipe (`\\.\pipe\deepwork`) with the caller
//!   identified by `GetNamedPipeClientProcessId` and its token's user SID.
//!   Until then the service can't be controlled, so this comes first.
//! - running as a Windows service (the `windows-service` crate).
//! - apps ([`ProcessTable`](super::ProcessTable)): Toolhelp32 snapshots,
//!   `QueryFullProcessImageNameW`, `TerminateProcess`; Store apps by
//!   package family name.
//! - browsers: Chromium-based browsers read policies from the registry
//!   (`HKLM\SOFTWARE\Policies\Google\Chrome\URLBlocklist`, Edge, Brave…).
//! - freeze: `LockWorkStation` from a helper in the user's session.
//! - boot id: `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters\BootId`.
//! - network ([`NetGuard`](super::NetGuard)): Windows Filtering Platform for
//!   encrypted DNS and tunnels; the web filter can drop connections by SNI
//!   with the WinDivert driver.
//! - hardcore ([`AdminLockout`](super::AdminLockout)): removing users from
//!   Administrators only takes effect at the next sign-in, so it is weak.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use super::{Options, Paths, Platform, System, spawn_quiet};
use crate::browser::Layout;
use crate::state::Daemon;

fn env_dir(var: &str, default: &str) -> PathBuf {
    std::env::var_os(var)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(default))
}

pub fn paths() -> Paths {
    let base = env_dir("ProgramData", r"C:\ProgramData").join("DeepWork");
    Paths {
        state_dir: base.join("state"),
        config: base.join("config.json"),
    }
}

pub fn hosts_path() -> PathBuf {
    env_dir("SystemRoot", r"C:\Windows").join(r"System32\drivers\etc\hosts")
}

pub fn platform(opts: &Options) -> Platform {
    let hosts = if opts.sandbox {
        opts.root.join("etc").join("hosts")
    } else {
        hosts_path()
    };
    Platform {
        os: "Windows",
        system: Box::new(WindowsSystem {
            hosts,
            run: !opts.sandbox,
        }),
        browsers: Some(Layout {
            chromium: &[],
            firefox: Some((
                r"C:\Program Files\Mozilla Firefox\distribution\policies.json",
                &[r"C:\Program Files\Mozilla Firefox\firefox.exe"],
            )),
        }),
        processes: None,
        net: None,
        admin: None,
    }
}

struct WindowsSystem {
    hosts: PathBuf,
    run: bool,
}

impl System for WindowsSystem {
    fn hosts_file(&self) -> Option<PathBuf> {
        Some(self.hosts.clone())
    }

    fn flush_dns(&self) {
        if self.run {
            spawn_quiet("ipconfig", &["/flushdns"]);
        }
    }
}

pub fn serve(
    _path: &Path,
    _daemon: Arc<Mutex<Daemon>>,
    _allowed: Option<Vec<u32>>,
) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "the named pipe server isn't implemented yet",
    ))
}
