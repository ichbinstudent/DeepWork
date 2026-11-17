//! Reading processes from `/proc`.

use std::fs;
use std::os::unix::fs::MetadataExt;

use deepwork_core::procinfo::app_id_from_cgroup;

use crate::platform::ProcessTable;
use crate::procs::Proc;

pub struct ProcFs;

impl ProcessTable for ProcFs {
    fn list(&self) -> Vec<Proc> {
        let Ok(dir) = fs::read_dir("/proc") else {
            return vec![];
        };
        dir.filter_map(|e| e.ok()?.file_name().to_str()?.parse::<u32>().ok())
            .filter_map(read_proc)
            .collect()
    }

    fn terminate(&self, pid: u32, force: bool) {
        let sig = if force { libc::SIGKILL } else { libc::SIGTERM };
        unsafe { libc::kill(pid as libc::pid_t, sig) };
    }
}

pub fn read_proc(pid: u32) -> Option<Proc> {
    let base = format!("/proc/{pid}");
    let uid = fs::metadata(&base).ok()?.uid();
    let exe = fs::read_link(format!("{base}/exe"))
        .ok()?
        .to_string_lossy()
        .trim_end_matches(" (deleted)")
        .to_string();
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
        privileged: uid == 0,
        comm,
        exe,
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
        let me = read_proc(std::process::id()).unwrap();
        assert!(!me.comm.is_empty() && me.start_time > 0);
        assert!(ProcFs.list().iter().any(|p| p.pid == me.pid));
    }
}
