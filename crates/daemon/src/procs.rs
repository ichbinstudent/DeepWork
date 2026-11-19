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

fn is_path(rule: &str) -> bool {
    rule.starts_with('/') || rule.get(1..3) == Some(":\\")
}

pub fn matches(rule: &str, p: &Proc) -> bool {
    if let Some(needle) = rule.strip_prefix(CMD_PREFIX) {
        return !needle.is_empty() && p.cmdline.to_lowercase().contains(&needle.to_lowercase());
    }
    if is_path(rule) {
        return p.exe == rule || p.argv0 == rule;
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
        for p in self.table.list() {
            if p.pid <= 1 || p.pid == self.own_pid || p.privileged {
                continue;
            }
            if p.system_exe && is_protected_process(basename(&p.exe)) {
                continue;
            }
            let Some((rule, block)) = rules.iter().find(|(r, _)| matches(r, &p)) else {
                continue;
            };
            seen.insert(p.pid);
            match self.pending.get(&p.pid) {
                Some((at, st)) if *st == p.start_time => {
                    if at.elapsed() > Duration::from_secs(3) {
                        self.table.terminate(p.pid, true);
                    }
                }
                _ => {
                    self.table.terminate(p.pid, false);
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
                }
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
mod tests {
    use super::*;

    #[test]
    fn rule_matching() {
        let p = Proc {
            pid: 42,
            comm: "Discord".into(),
            exe: "/opt/discord/Discord".into(),
            argv0: "/opt/discord/Discord".into(),
            app_id: Some("com.discordapp.Discord".into()),
            ..Default::default()
        };
        assert!(matches("discord", &p));
        assert!(matches("com.discordapp.discord", &p));
        assert!(matches("/opt/discord/Discord", &p));
        assert!(!matches("disc", &p));
        let java = Proc {
            comm: "java".into(),
            cmdline: "/usr/bin/java -Xmx4G -cp a.jar net.minecraft.client.main.Main --username x"
                .into(),
            ..Default::default()
        };
        assert!(matches("cmd:net.minecraft.client.main.Main", &java));
        assert!(matches("cmd:NET.MINECRAFT.client", &java));
        assert!(!matches("cmd:net.fabricmc.loader", &java));
        assert!(!matches("java.minecraft", &java));
        let long = Proc {
            comm: "steamwebhelper_".into(),
            ..Default::default()
        };
        assert!(matches("steamwebhelper_long", &long));
        let win = Proc {
            comm: "Discord.exe".into(),
            exe: r"C:\Users\a\AppData\Local\Discord\app-1.0\Discord.exe".into(),
            ..Default::default()
        };
        assert!(matches("discord", &win));
        assert!(matches(
            r"C:\Users\a\AppData\Local\Discord\app-1.0\Discord.exe",
            &win
        ));
        assert!(!matches("discord.ex", &win));
    }

    /// A fake process table that records what was closed.
    struct Fake(
        Vec<Proc>,
        std::sync::Arc<std::sync::Mutex<Vec<(u32, bool)>>>,
    );
    impl ProcessTable for Fake {
        fn list(&self) -> Vec<Proc> {
            self.0.clone()
        }
        fn terminate(&self, pid: u32, force: bool) {
            self.1.lock().unwrap().push((pid, force));
        }
    }

    #[test]
    fn killer_spares_privileged_and_protected() {
        let p = |pid, comm: &str, privileged| Proc {
            pid,
            comm: comm.into(),
            exe: format!("/usr/bin/{comm}"),
            system_exe: true,
            privileged,
            start_time: 1,
            ..Default::default()
        };
        let log = std::sync::Arc::new(std::sync::Mutex::new(vec![]));
        let table = Fake(
            vec![
                p(10, "steam", false),
                p(11, "steam", true),
                p(12, "gnome-shell", false),
            ],
            log.clone(),
        );
        let mut k = Killer::new(Box::new(table));
        let rules = [
            ("steam".to_string(), "Games".to_string()),
            ("gnome-shell".to_string(), "X".to_string()),
        ];
        let reported = k.enforce(&rules);
        assert_eq!(reported, vec![("steam".to_string(), "Games".to_string())]);
        assert_eq!(*log.lock().unwrap(), vec![(10, false)]);
    }

    /// A blocked program can't hide behind a protected name: the name it
    /// gives itself doesn't count, and neither does a protected file name
    /// on a copy a user made.
    #[test]
    fn protected_names_cant_be_borrowed() {
        let p = |pid, comm: &str, exe: &str, system_exe| Proc {
            pid,
            comm: comm.into(),
            exe: exe.into(),
            system_exe,
            cmdline: format!("{exe} net.minecraft.client.main.Main"),
            start_time: 1,
            ..Default::default()
        };
        let log = std::sync::Arc::new(std::sync::Mutex::new(vec![]));
        let table = Fake(
            vec![
                // renamed itself with prctl(PR_SET_NAME)
                p(20, "bash", "/usr/lib/jvm/bin/java", true),
                // a copy of the game named like a shell
                p(21, "bash", "/home/a/.local/bin/bash", false),
                // a real shell whose command line happens to match
                p(22, "bash", "/usr/bin/bash", true),
            ],
            log.clone(),
        );
        let mut k = Killer::new(Box::new(table));
        let rules = [(
            "cmd:net.minecraft.client.main.Main".to_string(),
            "Games".to_string(),
        )];
        k.enforce(&rules);
        assert_eq!(*log.lock().unwrap(), vec![(20, false), (21, false)]);
    }
}
