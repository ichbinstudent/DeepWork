//! Windows: website blocking through the hosts file and
//! browser policies (Chrome, Edge, Brave and Chromium in the registry,
//! Firefox's `policies.json`), closing open connections to blocked sites,
//! closing apps ([`procs`]), and the named pipe the app and `deepworkctl` talk to. It runs as the
//! `DeepWork` Windows service ([`service`]), installed by `windows/deepwork.iss`.
//!
//! Still to do, roughly in order:
//! - freeze: `LockWorkStation` from a helper in the user's session.
//! - boot id: `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters\BootId`.
//! - network ([`NetGuard`](super::NetGuard)): Windows Filtering Platform for
//!   encrypted DNS and tunnels; the web filter can drop connections by SNI
//!   with the WinDivert driver.
//! - hardcore ([`AdminLockout`](super::AdminLockout)): removing users from
//!   Administrators only takes effect at the next sign-in, so it is weak.

use std::path::{Path, PathBuf};

use super::{Options, Paths, Platform, System, spawn_quiet};
use crate::browser::{Layout, PolicyStore};

mod acl;
mod chromium;
mod pipe;
pub mod procs;
pub mod service;
mod tcp;
pub use pipe::serve;

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
        if let Some(base) = opts.state_dir.parent() {
            log_to_file(&base.join(LOG));
        }
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
            chromium_store: (!opts.sandbox).then(|| {
                Box::new(chromium::RegistryPolicies {
                    hive: chromium::Hive::Machine,
                    keys: chromium::BROWSER_KEYS
                        .iter()
                        .map(|k| k.to_string())
                        .collect(),
                    backup: opts.state_dir.join("chromium-registry.orig.json"),
                }) as Box<dyn PolicyStore>
            }),
            firefox: Some((
                r"C:\Program Files\Mozilla Firefox\distribution\policies.json",
                &[r"C:\Program Files\Mozilla Firefox\firefox.exe"],
            )),
        }),
        processes: Some(Box::new(procs::Processes::default())),
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

    fn cut_connections(&self, ips: &[std::net::IpAddr]) {
        if self.run {
            tcp::cut(ips);
        }
    }
}

const LOG: &str = "deepwork.log";

/// Make the data folder (the parent of `state_dir`) belong to
/// administrators, before anything in it is read or written: only they may
/// change it, and only they may read the state and the log. See [`acl`].
pub fn prepare_data_dir(state_dir: &Path) -> std::io::Result<()> {
    let (Some(base), Some(state)) = (state_dir.parent(), state_dir.file_name()) else {
        return Ok(());
    };
    acl::secure_data_dir(base, &[&state.to_string_lossy()], &[LOG])
}

/// Send the service's messages (stderr) to a log file, since it runs
/// without a console. The log starts over once it passes 1 MB.
fn log_to_file(path: &Path) {
    use std::os::windows::io::IntoRawHandle;
    use windows_sys::Win32::System::Console::{STD_ERROR_HANDLE, SetStdHandle};

    let full = std::fs::metadata(path).is_ok_and(|m| m.len() > 1 << 20);
    let mut opts = std::fs::OpenOptions::new();
    if full {
        opts.write(true).truncate(true);
    } else {
        opts.append(true);
    }
    let Ok(file) = opts.create(true).open(path) else {
        return;
    };
    let _ = acl::make_private(path);
    // SAFETY: the handle is handed over to the process for good.
    unsafe { SetStdHandle(STD_ERROR_HANDLE, file.into_raw_handle()) };
    eprintln!(
        "--- service started (Unix time {:.0})",
        deepwork_core::now()
    );
}
