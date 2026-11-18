//! Windows: website blocking through the hosts file and
//! browser policies (Chrome, Edge, Brave and Chromium in the registry,
//! Firefox's `policies.json`), closing open connections to blocked sites,
//! and the named pipe the app and `deepworkctl` talk to. It runs as the
//! `DeepWork` Windows service ([`service`]), installed by `windows/deepwork.iss`.
//!
//! Still to do, roughly in order:
//! - a tray icon for the app.
//! - apps ([`ProcessTable`](super::ProcessTable)): Toolhelp32 snapshots,
//!   `QueryFullProcessImageNameW`, `TerminateProcess`; Store apps by
//!   package family name.
//! - freeze: `LockWorkStation` from a helper in the user's session.
//! - boot id: `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters\BootId`.
//! - network ([`NetGuard`](super::NetGuard)): Windows Filtering Platform for
//!   encrypted DNS and tunnels; the web filter can drop connections by SNI
//!   with the WinDivert driver.
//! - hardcore ([`AdminLockout`](super::AdminLockout)): removing users from
//!   Administrators only takes effect at the next sign-in, so it is weak.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use super::{Options, Paths, Platform, System, spawn_quiet};
use crate::browser::{Layout, PolicyStore};

mod chromium;
mod pipe;
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
            restrict_to_admins(base);
            log_to_file(&base.join("deepwork.log"));
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

    fn cut_connections(&self, ips: &[std::net::IpAddr]) {
        if self.run {
            tcp::cut(ips);
        }
    }
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
    // SAFETY: the handle is handed over to the process for good.
    unsafe { SetStdHandle(STD_ERROR_HANDLE, file.into_raw_handle()) };
    eprintln!(
        "--- service started (Unix time {:.0})",
        deepwork_core::now()
    );
}

/// Let only SYSTEM and administrators change `dir` (state and config), and
/// make administrators its owner, so nobody else can edit the blocks or the
/// list of allowed users. Normal users may still read it.
fn restrict_to_admins(dir: &Path) {
    let icacls = |target: &Path, args: &[&str]| {
        Command::new("icacls")
            .arg(target)
            .args(args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    };
    // Well-known SIDs, so this works in every language: SYSTEM,
    // Administrators, Users. The rules go on the folder only; everything
    // inside is reset to inherit them (folder rules on a file would leave
    // the file with no access at all).
    let ok = icacls(dir, &["/setowner", "*S-1-5-32-544", "/T", "/C", "/Q"])
        && icacls(
            dir,
            &[
                "/inheritance:r",
                "/grant:r",
                "*S-1-5-18:(OI)(CI)F",
                "*S-1-5-32-544:(OI)(CI)F",
                "*S-1-5-32-545:(OI)(CI)RX",
                "/C",
                "/Q",
            ],
        );
    if !ok {
        eprintln!("deepwork: cannot restrict access to {}", dir.display());
    }
    // Fails harmlessly when the folder is still empty.
    icacls(&dir.join("*"), &["/reset", "/T", "/C", "/Q"]);
}
