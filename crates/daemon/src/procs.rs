//! Matching processes against block rules and closing them. Listing and
//! signalling processes is the platform's job ([`ProcessTable`]).

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use deepwork_core::model::{CMD_PREFIX, is_protected_process};

use crate::platform::ProcessTable;

#[derive(Debug, Clone, Default)]
pub struct Proc {
    pub pid: u32,
    /// Runs as root / SYSTEM or a system account (a service), not as a
    /// person's user account. Such processes are never closed.
    pub privileged: bool,
    /// Short process name. A process can change its own, so it is only used
    /// to find matches, never to spare a process.
    pub comm: String,
    pub exe: String,
    /// The executable file belongs to an administrator (it was installed,
    /// not put there by a user). Only then does a protected name such as
    /// `bash` or `systemd` spare the process.
    pub system_exe: bool,
    pub argv0: String,
    /// Full command line, arguments separated by spaces.
    pub cmdline: String,
    /// Desktop app id: the systemd scope on Linux (flatpak, GNOME, KDE
    /// launchers), the bundle id on macOS, the package family on Windows.
    pub app_id: Option<String>,
    /// Tells a reused pid apart from the original process.
    pub start_time: u64,
}

/// Last path component, for `/` and `\` paths.
fn basename(s: &str) -> &str {
    s.rsplit(['/', '\\']).next().unwrap_or(s)
}

/// Process names compare without case and without a Windows `.exe`.
fn same_name(a: &str, b: &str) -> bool {
    let strip = |s: &str| {
        let s = s.to_lowercase();
        s.strip_suffix(".exe").map(str::to_string).unwrap_or(s)
    };
    strip(a) == strip(b)
}

/// Windows paths (`C:\...`) and macOS's don't care about case.
fn same_path(a: &str, b: &str) -> bool {
    if b.starts_with('/') && !cfg!(target_os = "macos") {
        a == b
    } else {
        a.to_lowercase() == b.to_lowercase()
    }
}

fn is_path(rule: &str) -> bool {
    rule.starts_with('/') || rule.get(1..3) == Some(":\\")
}

pub fn matches(rule: &str, p: &Proc) -> bool {
    if let Some(needle) = rule.strip_prefix(CMD_PREFIX) {
        return !needle.is_empty() && p.cmdline.to_lowercase().contains(&needle.to_lowercase());
    }
    if is_path(rule) {
        return [&p.exe, &p.argv0].iter().any(|path| same_path(path, rule));
    }
    let r = rule.to_lowercase();
    let comm = p.comm.to_lowercase();
    // Linux truncates command names to 15 characters.
    if same_name(&comm, &r) || (comm.len() == 15 && r.len() > 15 && r.starts_with(&comm)) {
        return true;
    }
    [basename(&p.exe), basename(&p.argv0)]
        .iter()
        .any(|n| same_name(n, &r))
        || p.app_id.as_deref().is_some_and(|id| id.to_lowercase() == r)
}

/// Closes matching processes: politely first, forcefully if they linger.
pub struct Killer {
    table: Box<dyn ProcessTable>,
    own_pid: u32,
    pending: HashMap<u32, (Instant, u64)>,
    last_report: HashMap<String, Instant>,
}

impl Killer {
    pub fn new(table: Box<dyn ProcessTable>) -> Self {
        Self {
            table,
            own_pid: std::process::id(),
            pending: HashMap::new(),
            last_report: HashMap::new(),
        }
    }

    /// Returns newly blocked `(app, block)` pairs worth reporting.
    pub fn enforce(&mut self, rules: &[(String, String)]) -> Vec<(String, String)> {
        if rules.is_empty() {
            self.pending.clear();
            return vec![];
        }
        let mut seen = HashSet::new();
        let mut report = Vec::new();
        let (mut quit, mut kill) = (vec![], vec![]);
        for p in self.table.list() {
            if p.pid <= 1 || p.pid == self.own_pid || p.privileged {
                continue;
            }
            // Elsewhere users choose the app id themselves.
            let package = if cfg!(windows) {
                p.app_id.as_deref()
            } else {
                None
            };
            if p.system_exe
                && (is_protected_process(basename(&p.exe))
                    || package.is_some_and(is_protected_process))
            {
                continue;
            }
            let Some((rule, block)) = rules.iter().find(|(r, _)| matches(r, &p)) else {
                continue;
            };
            seen.insert(p.pid);
            match self.pending.get(&p.pid) {
                Some((at, st)) if *st == p.start_time => {
                    if at.elapsed() > Duration::from_secs(3) {
                        kill.push(p);
                    }
                }
                _ => {
                    self.pending.insert(p.pid, (Instant::now(), p.start_time));
                    let key = rule.to_lowercase();
                    let recent = self
                        .last_report
                        .get(&key)
                        .is_some_and(|t| t.elapsed() < Duration::from_secs(10));
                    if !recent {
                        self.last_report.insert(key, Instant::now());
                        report.push((display_name(rule, &p), block.clone()));
                    }
                    quit.push(p);
                }
            }
        }
        for (processes, force) in [(quit, false), (kill, true)] {
            if !processes.is_empty() {
                self.table.terminate(&processes, force);
            }
        }
        self.pending.retain(|pid, _| seen.contains(pid));
        report
    }
}

fn display_name(rule: &str, p: &Proc) -> String {
    if let Some(needle) = rule.strip_prefix(CMD_PREFIX) {
        format!("{} ({needle})", p.comm)
    } else if is_path(rule) {
        basename(rule).to_string()
    } else if p
        .app_id
        .as_deref()
        .is_some_and(|id| id.eq_ignore_ascii_case(rule))
    {
        rule.rsplit('.').next().unwrap_or(rule).to_string()
    } else {
        rule.to_string()
    }
}

#[cfg(test)]
mod tests;
