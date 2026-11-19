//! Reading processes from `/proc`.

use std::fs;
use std::os::unix::fs::MetadataExt;

use deepwork_core::procinfo::app_id_from_cgroup;

use crate::platform::ProcessTable;
use crate::procs::Proc;

/// Lists processes from `/proc`. Only processes of people's user accounts
/// count as closable; root and system accounts (services such as databases,
/// web servers or systemd-resolved) are never closed, whatever a block says.
pub struct ProcFs {
    /// Lowest uid of a person's account (`UID_MIN` in `/etc/login.defs`).
    pub uid_min: u32,
}

/// Whether `uid` belongs to a person rather than to root or a service.
pub fn is_user_account(uid: u32, uid_min: u32) -> bool {
    // systemd's DynamicUser= range, nobody, and the 16-bit "no user" id.
    const SYSTEM_RANGES: [std::ops::RangeInclusive<u32>; 2] = [61184..=65519, 65534..=65535];
    uid != 0 && uid >= uid_min && !SYSTEM_RANGES.iter().any(|r| r.contains(&uid))
}

impl ProcessTable for ProcFs {
    fn list(&self) -> Vec<Proc> {
        let Ok(dir) = fs::read_dir("/proc") else {
            return vec![];
        };
        dir.filter_map(|e| e.ok()?.file_name().to_str()?.parse::<u32>().ok())
            .filter_map(|pid| read_proc(pid, self.uid_min))
            .collect()
    }

    fn terminate(&self, pid: u32, force: bool) {
        let sig = if force { libc::SIGKILL } else { libc::SIGTERM };
        unsafe { libc::kill(pid as libc::pid_t, sig) };
    }
}

pub fn read_proc(pid: u32, uid_min: u32) -> Option<Proc> {
    let base = format!("/proc/{pid}");
    let uid = fs::metadata(&base).ok()?.uid();
    let exe = fs::read_link(format!("{base}/exe"))
        .ok()?
        .to_string_lossy()
        .trim_end_matches(" (deleted)")
        .to_string();
    // The kernel's link to the running file, so a rename or a replaced file
    // can't lie about who owns it.
    let system_exe = fs::metadata(format!("{base}/exe")).is_ok_and(|m| m.uid() == 0);
    let comm = fs::read_to_string(format!("{base}/comm"))
        .ok()?
        .trim_end()
        .to_string();
    let cmdline = fs::read(format!("{base}/cmdline")).unwrap_or_default();
    let argv0 =
        String::from_utf8_lossy(cmdline.split(|b| *b == 0).next().unwrap_or_default()).to_string();
    let cgroup = fs::read_to_string(format!("{base}/cgroup")).unwrap_or_default();
    let stat = fs::read_to_string(format!("{base}/stat")).unwrap_or_default();
    let start_time = stat
        .rsplit_once(')')
        .and_then(|(_, rest)| rest.split_whitespace().nth(19))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    Some(Proc {
        pid,
        privileged: !is_user_account(uid, uid_min),
        comm,
        exe,
        system_exe,
        argv0,
        cmdline: String::from_utf8_lossy(&cmdline)
            .split('\0')
            .filter(|a| !a.is_empty())
            .collect::<Vec<_>>()
            .join(" "),
        app_id: app_id_from_cgroup(&cgroup),
        start_time,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_own_process() {
        let me = read_proc(std::process::id(), 1000).unwrap();
        assert!(!me.comm.is_empty() && me.start_time > 0);
        assert!(
            ProcFs { uid_min: 1000 }
                .list()
                .iter()
                .any(|p| p.pid == me.pid)
        );
    }

    #[test]
    fn only_peoples_accounts_are_closable() {
        assert!(is_user_account(1000, 1000));
        assert!(is_user_account(60_001, 1000)); // systemd-homed
        assert!(is_user_account(1_234_567, 1000)); // directory services
        for service in [0, 33, 999, 61_184, 65_534, 65_535] {
            assert!(!is_user_account(service, 1000), "{service}");
        }
        // Tests that filter every user still never touch root.
        assert!(is_user_account(5, 0) && !is_user_account(0, 0));
    }
}
