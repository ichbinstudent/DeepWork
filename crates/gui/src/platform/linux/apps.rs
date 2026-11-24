//! Linux: desktop ids plus the real ELF binary, running apps from `/proc`
//! and their systemd scopes.

use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use adw::prelude::*;
use deepwork_core::model::is_protected_process;
use deepwork_core::procinfo::app_id_from_cgroup;
use gtk::gio;

use crate::apps::AppEntry;

fn is_elf(path: &Path) -> bool {
    let mut buf = [0u8; 4];
    fs::File::open(path)
        .and_then(|mut f| f.read_exact(&mut buf))
        .is_ok()
        && buf == *b"\x7fELF"
}

fn which(cmd: &Path) -> Option<PathBuf> {
    if cmd.is_absolute() {
        return cmd.exists().then(|| cmd.to_path_buf());
    }
    std::env::var_os("PATH")?
        .to_str()?
        .split(':')
        .map(|d| Path::new(d).join(cmd))
        .find(|p| p.exists())
}

pub fn installed() -> Vec<AppEntry> {
    crate::platform::gio_apps::installed(rules_for)
}

fn rules_for(info: &gio::AppInfo) -> Vec<String> {
    let mut rules = vec![];
    if let Some(id) = info.id() {
        rules.push(id.trim_end_matches(".desktop").to_string());
    }
    // Also match the real binary so the app is caught when started from a terminal.
    let Some(exe) = info.executable() else {
        return rules;
    };
    let base = exe
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    if !base.is_empty()
        && !matches!(base.as_str(), "flatpak" | "env" | "sh" | "bash" | "snap")
        && let Some(real) = which(&exe).and_then(|p| fs::canonicalize(p).ok())
        && is_elf(&real)
    {
        let name = real.file_name().unwrap().to_string_lossy().to_string();
        if !is_protected_process(&name) && !rules.iter().any(|r| r.eq_ignore_ascii_case(&name)) {
            rules.push(name);
        }
    }
    rules
}

/// Graphical apps the current user is running right now.
pub fn running(installed: &[AppEntry]) -> Vec<AppEntry> {
    let me = unsafe { libc_getuid() };
    let mut seen = BTreeMap::new();
    let Ok(dir) = fs::read_dir("/proc") else {
        return vec![];
    };
    for entry in dir.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<u32>().ok())
        else {
            continue;
        };
        let base = format!("/proc/{pid}");
        if fs::metadata(&base).map(|m| m.uid()).ok() != Some(me) {
            continue;
        }
        let Ok(cgroup) = fs::read_to_string(format!("{base}/cgroup")) else {
            continue;
        };
        let Some(app_id) = app_id_from_cgroup(&cgroup) else {
            continue;
        };
        let comm = fs::read_to_string(format!("{base}/comm"))
            .unwrap_or_default()
            .trim()
            .to_string();
        if comm.is_empty()
            || is_protected_process(&comm)
            || app_id.starts_with("io.github.ichbinstudent")
        {
            continue;
        }
        seen.entry(app_id.clone()).or_insert_with(|| {
            let known = installed
                .iter()
                .find(|a| a.rules[0].eq_ignore_ascii_case(&app_id));
            match known {
                Some(a) => a.clone(),
                None => AppEntry {
                    name: comm.clone(),
                    icon: None,
                    rules: vec![comm.clone()],
                    detail: format!("process “{comm}”"),
                },
            }
        });
    }
    let mut v: Vec<AppEntry> = seen.into_values().collect();
    v.sort_by_key(|a| a.name.to_lowercase());
    v.dedup_by(|a, b| a.rules == b.rules);
    v
}

unsafe extern "C" {
    #[link_name = "getuid"]
    fn libc_getuid() -> u32;
}
