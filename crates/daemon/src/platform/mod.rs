//! Everything that depends on the operating system.
//!
//! The rest of the daemon (rules, state, scheduling, the hosts file format,
//! browser policy contents, process matching, the request protocol) is
//! portable. Each OS module builds a [`Platform`] from the pieces it can
//! provide; a missing piece (`None`) means the feature isn't available there.
//! [`Platform::capabilities`] reports that to the app, which hides or
//! disables those features, and the service refuses them.
//!
//! To port DeepWork to a new OS, implement the traits below in a new module
//! and add it to [`native`]. Start with [`System`] and [`ProcessTable`];
//! the rest can stay `None` until it's ready.

use std::collections::HashSet;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use deepwork_core::protocol::{Capabilities, NetStatus};

use crate::browser::Layout;
use crate::procs::Proc;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(unix)]
pub mod unix_ipc;
#[cfg(windows)]
pub mod windows;

/// How the daemon was started.
#[derive(Debug, Clone)]
pub struct Options {
    /// Prefix for every system file. `/` normally, a directory in the sandbox.
    pub root: PathBuf,
    pub state_dir: PathBuf,
    /// Keep all files under `root` and don't run system commands (testing).
    pub sandbox: bool,
    /// Use the network protections even in the sandbox (test namespaces).
    pub force_net: bool,
    /// Lowest uid of a person's account (not on Windows). Only their processes are
    /// network-filtered or closed by app blocks; root and system accounts
    /// (services) never are.
    pub filter_uid_min: u32,
    /// Ports of the local HTTPS and HTTP filter.
    pub filter_ports: (u16, u16),
}

/// Default locations on this OS.
pub struct Paths {
    pub state_dir: PathBuf,
    pub config: PathBuf,
}

/// Small, stateless OS services.
pub trait System: Send {
    /// The hosts file, if websites can be blocked through it.
    fn hosts_file(&self) -> Option<PathBuf>;
    /// Make the OS forget cached DNS answers after the hosts file changed.
    fn flush_dns(&self) {}
    /// Close open connections to websites (port 443 or 80) at these
    /// addresses, so browsers reconnect and hit the block. Only outgoing
    /// connections, and on Linux only people's own, never root's or a
    /// service's.
    fn cut_connections(&self, _ips: &[IpAddr]) {}
    /// Whether [`System::lock_screen`] works (needed by Freeze).
    fn can_lock_screen(&self) -> bool {
        false
    }
    /// Lock every user session.
    fn lock_screen(&self) {}
    /// An id that changes with every boot (needed by the "Until restart" lock).
    fn boot_id(&self) -> Option<String> {
        None
    }
}

/// Listing and closing processes. Matching them against block rules is
/// portable (see [`crate::procs`]).
pub trait ProcessTable: Send {
    fn list(&self) -> Vec<Proc>;
    /// How long a process gets between being asked and being killed.
    fn grace(&self) -> Duration {
        Duration::from_secs(3)
    }
    /// Ask processes (as [`ProcessTable::list`] gave them) to quit
    /// (`force = false`) or kill them (`force = true`).
    fn terminate(&self, processes: &[Proc], force: bool);
}

/// Which network protections a [`NetGuard`] wants or supports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NetWant {
    /// Refuse connections to well-known encrypted DNS servers.
    pub doh: bool,
    /// Check the site name of every web connection.
    pub filter: bool,
    /// Refuse traffic that would leave through a VPN tunnel.
    pub tunnels: bool,
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))] // used by the Linux backend
impl NetWant {
    pub fn any(&self) -> bool {
        self.doh || self.filter || self.tunnels
    }

    /// Only what `supported` allows.
    pub fn and(self, supported: NetWant) -> NetWant {
        NetWant {
            doh: self.doh && supported.doh,
            filter: self.filter && supported.filter,
            tunnels: self.tunnels && supported.tunnels,
        }
    }
}

/// Firewall-level protections: encrypted DNS, the web filter and tunnels.
pub trait NetGuard: Send {
    fn supported(&self) -> NetWant;
    /// Called every tick; should be cheap when nothing changed.
    fn apply(&mut self, want: NetWant);
    /// Domains the web filter refuses (with all their subdomains).
    fn set_blocked(&mut self, domains: HashSet<String>);
    fn status(&self) -> NetStatus;
    /// Remove every rule (service stopping or uninstalling).
    fn cleanup(&mut self);
}

/// Taking administrator rights away while a hardcore block runs.
pub trait AdminLockout: Send {
    /// Keep rights away until `until`, or give them back when it is 0.
    fn apply(&mut self, until: f64);
    fn release(&mut self);
    /// Ways in that couldn't be closed.
    fn warnings(&self) -> Vec<String>;
}

/// Everything the daemon needs from the OS. `None` = not supported.
pub struct Platform {
    pub os: &'static str,
    pub system: Box<dyn System>,
    /// Where browser policies live on this OS.
    pub browsers: Option<Layout>,
    pub processes: Option<Box<dyn ProcessTable>>,
    pub net: Option<Box<dyn NetGuard>>,
    pub admin: Option<Box<dyn AdminLockout>>,
}

impl Platform {
    pub fn capabilities(&self) -> Capabilities {
        let net = self.net.as_ref().map(|n| n.supported()).unwrap_or_default();
        Capabilities {
            os: self.os.into(),
            websites: self.system.hosts_file().is_some(),
            browser_policies: self.browsers.is_some(),
            apps: self.processes.is_some(),
            encrypted_dns: net.doh,
            https_filter: net.filter,
            tunnels: net.tunnels,
            freeze: self.system.can_lock_screen(),
            restart_lock: self.system.boot_id().is_some(),
            hardcore: self.admin.is_some(),
        }
    }
}

/// The platform for the OS this binary was built for.
pub fn native(opts: &Options) -> Platform {
    #[cfg(target_os = "linux")]
    return linux::platform(opts);
    #[cfg(target_os = "macos")]
    return macos::platform(opts);
    #[cfg(windows)]
    return windows::platform(opts);
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    return unsupported(opts);
}

/// The real hosts file of this OS.
pub fn system_hosts_file() -> PathBuf {
    #[cfg(windows)]
    return windows::hosts_path();
    #[cfg(target_os = "macos")]
    return PathBuf::from("/private/etc/hosts");
    #[cfg(not(any(windows, target_os = "macos")))]
    return PathBuf::from("/etc/hosts");
}

/// Default file locations for this OS.
pub fn default_paths() -> Paths {
    #[cfg(target_os = "linux")]
    return linux::paths();
    #[cfg(target_os = "macos")]
    return macos::paths();
    #[cfg(windows)]
    return windows::paths();
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    return Paths {
        state_dir: "/var/lib/deepwork".into(),
        config: "/etc/deepwork/config.json".into(),
    };
}

/// Lowest uid of a person's account, unless told otherwise.
pub const DEFAULT_UID_MIN: u32 = if cfg!(target_os = "macos") { 500 } else { 1000 };

/// Listen for clients at `path` and serve them until the process ends.
pub fn serve(
    path: &std::path::Path,
    daemon: std::sync::Arc<std::sync::Mutex<crate::state::Daemon>>,
    allowed: Option<Vec<crate::server::UserId>>,
) -> std::io::Result<()> {
    #[cfg(unix)]
    return unix_ipc::serve(path, daemon, allowed);
    #[cfg(windows)]
    return windows::serve(path, daemon, allowed);
    #[cfg(not(any(unix, windows)))]
    return Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "no IPC transport for this OS",
    ));
}

/// Whether the daemon runs with full privileges (root / SYSTEM).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))] // used by the Linux backend
pub fn is_privileged() -> bool {
    #[cfg(unix)]
    return unsafe { libc::geteuid() } == 0;
    #[cfg(not(unix))]
    return false;
}

/// A platform with nothing but a hosts file under `root`.
#[allow(dead_code)]
pub fn unsupported(opts: &Options) -> Platform {
    struct HostsOnly(PathBuf);
    impl System for HostsOnly {
        fn hosts_file(&self) -> Option<PathBuf> {
            Some(self.0.clone())
        }
    }
    Platform {
        os: std::env::consts::OS,
        system: Box::new(HostsOnly(opts.root.join("etc/hosts"))),
        browsers: None,
        processes: None,
        net: None,
        admin: None,
    }
}

/// Run a command without waiting for it.
#[allow(dead_code)]
pub fn spawn_quiet(cmd: &str, args: &[&str]) {
    use std::process::{Command, Stdio};
    let child = Command::new(cmd)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    if let Ok(mut child) = child {
        std::thread::spawn(move || child.wait());
    }
}

#[cfg(test)]
mod tests;
