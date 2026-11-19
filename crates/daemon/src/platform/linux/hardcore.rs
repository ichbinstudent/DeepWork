//! Hardcore mode: while a hardcore block runs, nobody gets administrator
//! rights, so nobody can stop the service, edit `/etc/hosts` or flush the
//! firewall.
//!
//! - sudo: a sudoers drop-in that sorts last denies every command to
//!   everyone but root (the last matching rule wins).
//! - doas: a `deny` section at the end of `/etc/doas.conf`, if it exists.
//! - polkit (pkexec, run0, systemctl, GNOME Software…): administrator
//!   authentication needs root's password, and the dangerous actions are
//!   refused outright, even where a distribution allows them for admins.
//! - su and root logins: root's password is locked (if it was set) and
//!   unlocked again afterwards.
//!
//! Everything is undone when the block ends. A systemd timer with a release
//! script is the safety net in case the service itself can't do that: it
//! gives the rights back shortly after the deadline even if this binary is
//! broken or gone.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::platform::AdminLockout;
use crate::write_atomic;

const SUDOERS_NAME: &str = "zz-deepwork-hardcore";
const POLKIT_NAME: &str = "00-deepwork-hardcore.rules";
const UNIT: &str = "deepwork-hardcore-release";
const DOAS_BEGIN: &str = "# BEGIN deepwork hardcore";
const DOAS_END: &str = "# END deepwork hardcore";
/// The safety net waits this long after the end, so the service normally
/// gets there first.
const RELEASE_GRACE: f64 = 60.0;

pub struct Paths {
    pub sudoers: PathBuf,
    pub sudoers_d: PathBuf,
    pub doas: PathBuf,
    pub polkit_dir: PathBuf,
    pub units: PathBuf,
    /// Marker: root's password was locked by us.
    pub root_marker: PathBuf,
    pub script: PathBuf,
    pub passwd: PathBuf,
    pub shadow: PathBuf,
}

impl Paths {
    pub fn new(root: &Path, state_dir: &Path) -> Self {
        Paths {
            sudoers: root.join("etc/sudoers"),
            sudoers_d: root.join("etc/sudoers.d"),
            doas: root.join("etc/doas.conf"),
            polkit_dir: root.join("etc/polkit-1"),
            units: root.join("etc/systemd/system"),
            root_marker: state_dir.join("hardcore-root-locked"),
            script: state_dir.join("hardcore-release.sh"),
            passwd: root.join("etc/passwd"),
            shadow: root.join("etc/shadow"),
        }
    }

    fn sudoers_file(&self) -> PathBuf {
        self.sudoers_d.join(SUDOERS_NAME)
    }

    fn polkit_file(&self) -> PathBuf {
        self.polkit_dir.join("rules.d").join(POLKIT_NAME)
    }

    fn unit(&self, ext: &str) -> PathBuf {
        self.units.join(format!("{UNIT}.{ext}"))
    }
}

pub struct Hardcore {
    paths: Paths,
    /// Run system commands (usermod, systemctl, visudo). Off in the sandbox.
    system: bool,
    /// Deadline currently in force; `None` until the first apply.
    applied: Option<f64>,
    last_check: Instant,
    warnings: Vec<String>,
}

impl AdminLockout for Hardcore {
    fn apply(&mut self, until: f64) {
        Hardcore::apply(self, until)
    }

    fn release(&mut self) {
        Hardcore::release(self)
    }

    fn warnings(&self) -> Vec<String> {
        self.warnings.clone()
    }
}

impl Hardcore {
    pub fn new(paths: Paths, system: bool) -> Self {
        Hardcore {
            paths,
            system,
            applied: None,
            last_check: Instant::now(),
            warnings: vec![],
        }
    }

    /// Keep administrator rights away until `until`, or give them back when
    /// it is 0.
    pub fn apply(&mut self, until: f64) {
        if until > 0.0 {
            let recheck = self.last_check.elapsed() > Duration::from_secs(30);
            if self.applied != Some(until) || recheck {
                self.last_check = Instant::now();
                self.engage(until);
                self.applied = Some(until);
            }
        } else if self.applied != Some(0.0) {
            // Also runs once at start-up, to clean up after a crash.
            self.release();
            self.applied = Some(0.0);
        }
    }

    fn engage(&mut self, until: f64) {
        let mut warnings = vec![];
        if let Err(e) = self.lock_sudo() {
            warnings.push(format!("sudo: {e}"));
        }
        if let Err(e) = self.lock_doas() {
            warnings.push(format!("doas: {e}"));
        }
        if let Err(e) = self.lock_polkit() {
            warnings.push(format!("polkit: {e}"));
        }
        if let Err(e) = self.lock_root() {
            warnings.push(format!("su: {e}"));
        }
        if let Err(e) = self.arm_safety_net(until) {
            warnings.push(format!("safety net: {e}"));
        }
        for w in &warnings {
            if !self.warnings.contains(w) {
                eprintln!("deepwork: hardcore mode: {w}");
            }
        }
        self.warnings = warnings;
    }

    /// Give administrator rights back.
    pub fn release(&mut self) {
        let p = &self.paths;
        for f in [p.sudoers_file(), p.polkit_file()] {
            if f.exists()
                && let Err(e) = fs::remove_file(&f)
            {
                eprintln!("deepwork: cannot remove {}: {e}", f.display());
            }
        }
        if let Ok(text) = fs::read_to_string(&p.doas) {
            let cleaned = strip_section(&text);
            if cleaned != text
                && let Err(e) = write_atomic(&p.doas, cleaned.as_bytes(), 0o600)
            {
                eprintln!("deepwork: cannot update {}: {e}", p.doas.display());
            }
        }
        if p.root_marker.exists() {
            match if self.system {
                run("usermod", &["-U", "root"])
            } else {
                Ok(())
            } {
                Ok(()) => {
                    let _ = fs::remove_file(&p.root_marker);
                }
                // Kept, so the next start (or the safety net) tries again.
                Err(e) => eprintln!("deepwork: cannot unlock root's password: {e}"),
            }
        }
        if p.unit("timer").exists() {
            if self.system {
                let _ = run("systemctl", &["disable", "--now", &format!("{UNIT}.timer")]);
            }
            let _ = fs::remove_file(p.unit("timer"));
            let _ = fs::remove_file(p.unit("service"));
            if self.system {
                let _ = run("systemctl", &["daemon-reload"]);
            }
        }
        let _ = fs::remove_file(&p.script);
        self.warnings.clear();
    }

    fn lock_sudo(&self) -> Result<(), String> {
        let p = &self.paths;
        if !p.sudoers.exists() && !p.sudoers_d.exists() {
            return Ok(()); // sudo isn't installed
        }
        if !p.sudoers_d.is_dir() {
            return Err(format!("{} is missing", p.sudoers_d.display()));
        }
        if let Ok(main) = fs::read_to_string(&p.sudoers)
            && !main.lines().any(|l| {
                let l = l.trim_start();
                (l.starts_with("#includedir") || l.starts_with("@includedir"))
                    && l.contains("sudoers.d")
            })
        {
            return Err(format!(
                "{} doesn't include {}",
                p.sudoers.display(),
                p.sudoers_d.display()
            ));
        }
        let file = p.sudoers_file();
        if fs::read_to_string(&file).is_ok_and(|c| c == SUDOERS) {
            return Ok(());
        }
        if self.system {
            // Never install a file that would break sudo's parser.
            let check = p.script.with_file_name("sudoers.check");
            write_atomic(&check, SUDOERS.as_bytes(), 0o440).map_err(|e| e.to_string())?;
            let ok = run("visudo", &["-cqf", &check.to_string_lossy()]);
            let _ = fs::remove_file(&check);
            if let Err(e) = ok {
                return Err(format!("the rule was rejected by visudo: {e}"));
            }
        }
        write_atomic(&file, SUDOERS.as_bytes(), 0o440).map_err(|e| e.to_string())
    }

    fn lock_doas(&self) -> Result<(), String> {
        let p = &self.paths;
        let Ok(text) = fs::read_to_string(&p.doas) else {
            return Ok(()); // doas isn't set up
        };
        let users = regular_users(&p.passwd);
        let wanted = format!("{}{}", strip_section(&text), doas_section(&users));
        if wanted == text {
            return Ok(());
        }
        write_atomic(&p.doas, wanted.as_bytes(), 0o600).map_err(|e| e.to_string())
    }

    fn lock_polkit(&self) -> Result<(), String> {
        let p = &self.paths;
        if !p.polkit_dir.is_dir() {
            return Ok(()); // polkit isn't installed
        }
        let file = p.polkit_file();
        if fs::read_to_string(&file).is_ok_and(|c| c == POLKIT_RULES) {
            return Ok(());
        }
        fs::create_dir_all(file.parent().unwrap()).map_err(|e| e.to_string())?;
        write_atomic(&file, POLKIT_RULES.as_bytes(), 0o644).map_err(|e| e.to_string())
    }

    /// Lock root's password so `su` and root logins fail. Only if it has one
    /// and we haven't already; the marker records that we must unlock it.
    fn lock_root(&self) -> Result<(), String> {
        let p = &self.paths;
        if p.root_marker.exists() || !self.system {
            return Ok(());
        }
        let shadow = fs::read_to_string(&p.shadow).map_err(|e| e.to_string())?;
        match root_password(&shadow) {
            RootPassword::Set => {}
            RootPassword::Locked => return Ok(()),
            // usermod can't unlock an empty password again, so leave it.
            RootPassword::Empty => {
                return Err("root has no password, so anyone can become root with su. \
                            Lock it with `sudo passwd -l root`."
                    .into());
            }
        }
        // Write the marker first: if we crash in between, the release
        // runs `usermod -U`, which is harmless on an unlocked account.
        fs::write(&p.root_marker, b"").map_err(|e| e.to_string())?;
        run("usermod", &["-L", "root"]).inspect_err(|_| {
            let _ = fs::remove_file(&p.root_marker);
        })
    }

    fn arm_safety_net(&self, until: f64) -> Result<(), String> {
        let p = &self.paths;
        let deadline = (until + RELEASE_GRACE).ceil() as i64;
        let script = release_script(p, deadline);
        if fs::read_to_string(&p.script).ok().as_deref() != Some(script.as_str()) {
            write_atomic(&p.script, script.as_bytes(), 0o700).map_err(|e| e.to_string())?;
        }
        let service = release_service(&p.script);
        let new_units = fs::read_to_string(p.unit("service")).ok().as_deref()
            != Some(service.as_str())
            || fs::read_to_string(p.unit("timer")).ok().as_deref() != Some(RELEASE_TIMER);
        if new_units {
            fs::create_dir_all(&p.units).map_err(|e| e.to_string())?;
            write_atomic(&p.unit("service"), service.as_bytes(), 0o644)
                .map_err(|e| e.to_string())?;
            write_atomic(&p.unit("timer"), RELEASE_TIMER.as_bytes(), 0o644)
                .map_err(|e| e.to_string())?;
        }
        if self.system {
            if new_units {
                run("systemctl", &["daemon-reload"])?;
            }
            let timer = format!("{UNIT}.timer");
            if new_units || run("systemctl", &["is-active", "--quiet", &timer]).is_err() {
                run("systemctl", &["enable", "--now", &timer])?;
            }
        }
        Ok(())
    }
}

const SUDOERS: &str = "\
# Written by DeepWork while a hardcore block runs, and removed when it ends.
# Until then nobody but root may use sudo: the last matching rule wins.
ALL, !root ALL=(ALL:ALL) !ALL
";

const POLKIT_RULES: &str = r#"// Written by DeepWork while a hardcore block runs, and removed when it ends.

// Administrator authentication needs root's password, which is locked.
polkit.addAdminRule(function (action, subject) {
    return ["unix-user:0"];
});

// Refuse what could stop DeepWork outright, even where the distribution
// lets administrators do it without a password.
polkit.addRule(function (action, subject) {
    if (subject.user == "root") {
        return polkit.Result.NOT_HANDLED;
    }
    var denied = [
        "org.freedesktop.policykit.exec",
        "org.freedesktop.systemd1.",
        "org.freedesktop.packagekit.",
        "org.freedesktop.machine1.",
        "org.freedesktop.import1.",
        "org.freedesktop.portable1.",
        "org.freedesktop.sysupdate1.",
        "org.freedesktop.accounts.user-administration",
        "org.freedesktop.timedate1.set-time",
        "org.freedesktop.timedate1.set-ntp",
        "org.freedesktop.timedate1.set-local-rtc"
    ];
    for (var i = 0; i < denied.length; i++) {
        var d = denied[i];
        var prefix = d.charAt(d.length - 1) == ".";
        if (action.id == d || (prefix && action.id.indexOf(d) == 0)) {
            return polkit.Result.NO;
        }
    }
    return polkit.Result.NOT_HANDLED;
});
"#;

const RELEASE_TIMER: &str = "\
[Unit]
Description=Safety net for DeepWork hardcore mode

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
AccuracySec=30s

[Install]
WantedBy=timers.target
";

fn release_service(script: &Path) -> String {
    format!(
        "[Unit]\n\
         Description=Give administrator rights back after DeepWork hardcore mode\n\n\
         [Service]\n\
         Type=oneshot\n\
         ExecStart=/bin/sh {}\n",
        script.display()
    )
}

/// Shell script that undoes everything once the deadline has passed. It
/// doesn't depend on the DeepWork binaries.
fn release_script(p: &Paths, deadline: i64) -> String {
    let q = |path: PathBuf| format!("'{}'", path.display());
    format!(
        "#!/bin/sh\n\
         # DeepWork hardcore mode safety net: gives administrator rights back\n\
         # after the deadline in case the DeepWork service couldn't.\n\
         [ \"$(date +%s)\" -ge {deadline} ] || exit 0\n\
         rm -f {sudoers} {polkit}\n\
         if [ -f {doas} ]; then sed -i '/^{begin}$/,/^{end}$/d' {doas}; fi\n\
         if [ -e {marker} ]; then usermod -U root && rm -f {marker}; fi\n\
         systemctl disable --now {UNIT}.timer\n",
        sudoers = q(p.sudoers_file()),
        polkit = q(p.polkit_file()),
        doas = q(p.doas.clone()),
        marker = q(p.root_marker.clone()),
        begin = DOAS_BEGIN,
        end = DOAS_END,
    )
}

fn doas_section(users: &[String]) -> String {
    let mut s = format!("{DOAS_BEGIN}\n");
    s.push_str("# Nobody may use doas until DeepWork's hardcore block ends.\n");
    s.push_str("deny :wheel\n");
    for u in users {
        s.push_str(&format!("deny {u}\n"));
    }
    s.push_str(&format!("{DOAS_END}\n"));
    s
}

fn strip_section(text: &str) -> String {
    let mut out = String::new();
    let mut inside = false;
    for line in text.lines() {
        if line == DOAS_BEGIN {
            inside = true;
        } else if line == DOAS_END {
            inside = false;
        } else if !inside {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

/// Login names of regular users (uid 1000–59999).
fn regular_users(passwd: &Path) -> Vec<String> {
    fs::read_to_string(passwd)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| {
            let mut f = l.split(':');
            let name = f.next()?;
            let uid: u32 = f.nth(1)?.parse().ok()?;
            ((1000..60000).contains(&uid) && !name.is_empty()).then(|| name.to_string())
        })
        .collect()
}

#[derive(Debug, PartialEq)]
enum RootPassword {
    Set,
    Empty,
    /// Locked, disabled or missing.
    Locked,
}

fn root_password(shadow: &str) -> RootPassword {
    let hash = shadow
        .lines()
        .find_map(|l| l.strip_prefix("root:"))
        .and_then(|rest| rest.split(':').next());
    match hash {
        Some("") => RootPassword::Empty,
        Some(h) if !h.starts_with('!') && !h.starts_with('*') => RootPassword::Set,
        _ => RootPassword::Locked,
    }
}

fn run(cmd: &str, args: &[&str]) -> Result<(), String> {
    let out = Command::new(cmd)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("cannot run {cmd}: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
        Err(if err.is_empty() {
            format!("{cmd} failed ({})", out.status)
        } else {
            err
        })
    }
}

#[cfg(test)]
mod tests;
