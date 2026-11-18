//! DeepWork daemon: runs with full privileges and enforces blocks.
//!
//! Everything OS-specific lives in [`platform`]; the rest is portable.

mod browser;
mod enforcer;
mod hosts;
mod platform;
mod procs;
mod server;
mod state;
mod webfilter;

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use deepwork_core::protocol::DEFAULT_SOCKET;
use serde::Deserialize;

use crate::enforcer::Enforcer;
use crate::platform::Options;
use crate::state::{Daemon, Persisted};

/// Write a file atomically (temp file + rename) with the given Unix mode
/// (ignored elsewhere). Symlinked targets are written in place so the link
/// survives.
pub fn write_atomic(path: &Path, data: &[u8], mode: u32) -> std::io::Result<()> {
    if fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
        return fs::write(path, data);
    }
    let dir = path.parent().unwrap_or(Path::new("."));
    let tmp = dir.join(format!(
        ".{}.deepwork-tmp",
        path.file_name().unwrap_or_default().to_string_lossy()
    ));
    {
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut opts, mode);
        let mut f = opts.open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    set_mode(&tmp, mode)?;
    fs::rename(&tmp, path)
}

/// Set Unix permissions (no-op on other systems).
pub fn set_mode(path: &Path, mode: u32) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
        Ok(())
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct Config {
    /// Who may control the service besides administrators: Unix user ids,
    /// or Windows SIDs. Empty = everyone.
    allowed_users: Vec<server::UserId>,
}

/// The users allowed to control the service (`None`: everyone). A config
/// file that can't be read leaves only administrators in, never everyone.
fn allowed_users(path: &Path) -> Option<Vec<server::UserId>> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => {
            eprintln!(
                "deepwork: cannot read {} ({e}); only administrators may control DeepWork",
                path.display()
            );
            return Some(vec![]);
        }
    };
    match serde_json::from_str::<Config>(&text) {
        Ok(c) => (!c.allowed_users.is_empty()).then_some(c.allowed_users),
        Err(e) => {
            eprintln!(
                "deepwork: {} is invalid ({e}); only administrators may control DeepWork until it is fixed",
                path.display()
            );
            Some(vec![])
        }
    }
}

fn usage() -> ! {
    eprintln!(
        "usage: deepwork-daemon [--sandbox DIR] [--socket PATH] [--net] [--filter-uid-min N]\n                       \
         [--proxy-ports TLS,HTTP] [--cleanup] [--allow-user ID]\n\n  \
         --sandbox DIR         keep all files under DIR and don't touch the system (for testing)\n  \
         --socket PATH         listen on PATH instead of the default socket\n  \
         --net                 manage the firewall and HTTPS filter even in the sandbox\n  \
         --filter-uid-min N    only filter processes of users with uid >= N (default 1000)\n  \
         --proxy-ports T,H     ports of the HTTPS and HTTP filter (default 41443,41080)\n  \
         --cleanup             remove blocks from the hosts file, browser policies and the firewall,\n                        \
       and give administrator rights back (hardcore mode), then exit\n  \
         --allow-user ID       let a user control DeepWork (a uid, or a SID on Windows), then exit"
    );
    std::process::exit(2)
}

fn main() {
    // Started by the Windows service control manager.
    #[cfg(windows)]
    if std::env::args().nth(1).as_deref() == Some("--service") {
        if let Err(e) = platform::windows::service::run(run) {
            eprintln!("deepwork: cannot run as a service: {e}");
            std::process::exit(1);
        }
        return;
    }
    run();
}

/// Add a user to `allowed_users` in the config file, keeping its other
/// settings. On Windows, entries from before full SIDs (bare numbers) are
/// dropped: they could match the wrong account.
fn allow_user(path: &Path, id: &str) -> std::io::Result<()> {
    let user: server::UserId = match id.parse::<u32>() {
        Ok(uid) if !cfg!(windows) => server::UserId::Uid(uid),
        _ if cfg!(windows) && !id.to_ascii_uppercase().starts_with("S-1-") => {
            return Err(std::io::Error::other(format!("{id} is not a SID")));
        }
        _ => server::UserId::Sid(id.to_string()),
    };
    let mut config: serde_json::Value = fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .filter(serde_json::Value::is_object)
        .unwrap_or_else(|| serde_json::json!({}));
    let mut list: Vec<serde_json::Value> = config
        .get("allowed_users")
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default();
    if cfg!(windows) {
        list.retain(|v| v.is_string());
    }
    let new = match &user {
        server::UserId::Uid(uid) => serde_json::json!(uid),
        server::UserId::Sid(sid) => serde_json::json!(sid),
    };
    let known = list.iter().any(|v| match (v, &new) {
        (serde_json::Value::String(a), serde_json::Value::String(b)) => a.eq_ignore_ascii_case(b),
        (a, b) => a == b,
    });
    if !known {
        list.push(new);
    }
    config["allowed_users"] = serde_json::Value::Array(list);
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let text = serde_json::to_string_pretty(&config).unwrap_or_default();
    write_atomic(path, text.as_bytes(), 0o644)
}

fn run() {
    let defaults = platform::default_paths();
    let mut opts = Options {
        root: PathBuf::from("/"),
        state_dir: defaults.state_dir,
        sandbox: false,
        force_net: false,
        filter_uid_min: 1000,
        filter_ports: (41443, 41080),
    };
    let mut config_path = defaults.config;
    let mut socket: Option<PathBuf> = None;
    let mut cleanup = false;
    let mut allow: Option<String> = None;
    let mut args = std::env::args().skip(1).filter(|a| a != "--service");
    while let Some(a) = args.next() {
        match a.as_str() {
            "--allow-user" => allow = Some(args.next().unwrap_or_else(|| usage())),
            "--sandbox" => {
                let dir = PathBuf::from(args.next().unwrap_or_else(|| usage()));
                opts.state_dir = dir.join("state");
                config_path = dir.join("config.json");
                socket.get_or_insert_with(|| dir.join("deepwork.sock"));
                opts.root = dir;
                opts.sandbox = true;
            }
            "--socket" => socket = Some(args.next().unwrap_or_else(|| usage()).into()),
            "--cleanup" => cleanup = true,
            "--net" => opts.force_net = true,
            "--filter-uid-min" => {
                opts.filter_uid_min = args
                    .next()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or_else(|| usage())
            }
            "--proxy-ports" => {
                let v = args.next().unwrap_or_else(|| usage());
                let (t, h) = v.split_once(',').unwrap_or_else(|| usage());
                opts.filter_ports = (
                    t.parse().unwrap_or_else(|_| usage()),
                    h.parse().unwrap_or_else(|_| usage()),
                );
            }
            "--version" => {
                println!("deepwork-daemon {}", deepwork_core::VERSION);
                return;
            }
            _ => usage(),
        }
    }
    let socket = socket.unwrap_or_else(|| DEFAULT_SOCKET.into());
    if let Some(id) = allow {
        match allow_user(&config_path, &id) {
            Ok(()) => println!("{id} may now control DeepWork (restart the service to apply)."),
            Err(e) => {
                eprintln!("deepwork: cannot update {}: {e}", config_path.display());
                std::process::exit(1);
            }
        }
        return;
    }

    if let Err(e) = fs::create_dir_all(&opts.state_dir) {
        eprintln!("deepwork: cannot create {}: {e}", opts.state_dir.display());
        std::process::exit(1);
    }
    let _ = set_mode(&opts.state_dir, 0o700);

    let platform = platform::native(&opts);
    // The sandbox starts from a copy of the real hosts file.
    if opts.sandbox
        && let Some(hosts) = platform.system.hosts_file()
        && !hosts.exists()
    {
        let _ = fs::create_dir_all(hosts.parent().unwrap());
        let _ = fs::copy(platform::system_hosts_file(), &hosts);
    }
    let mut enforcer = Enforcer::new(platform, &opts);
    if cleanup {
        match enforcer.cleanup() {
            Ok(()) => println!("DeepWork blocks removed from the system."),
            Err(e) => {
                eprintln!("deepwork: cleanup failed: {e}");
                std::process::exit(1)
            }
        }
        return;
    }

    let state_file = opts.state_dir.join("state.json");
    let persisted: Persisted = match fs::read_to_string(&state_file) {
        Ok(s) => serde_json::from_str(&s).unwrap_or_else(|e| {
            eprintln!("deepwork: state file is corrupt ({e}); keeping a copy and starting fresh");
            let _ = fs::copy(&state_file, opts.state_dir.join("state.json.corrupt"));
            Persisted::default()
        }),
        Err(_) => Persisted::default(),
    };
    let allowed = allowed_users(&config_path);

    let caps = enforcer.capabilities();
    let daemon = Arc::new(Mutex::new(Daemon::new(
        persisted,
        enforcer.boot_id(),
        caps.clone(),
    )));

    {
        let daemon = daemon.clone();
        let socket = socket.clone();
        std::thread::spawn(move || {
            if let Err(e) = platform::serve(&socket, daemon, allowed) {
                eprintln!("deepwork: socket {} failed: {e}", socket.display());
                std::process::exit(1);
            }
        });
    }
    let missing: Vec<&str> = [
        ("apps", caps.apps),
        ("browser policies", caps.browser_policies),
        ("encrypted DNS blocking", caps.encrypted_dns),
        ("HTTPS filter", caps.https_filter),
        ("freeze", caps.freeze),
        ("hardcore", caps.hardcore),
    ]
    .iter()
    .filter(|(_, ok)| !ok)
    .map(|(name, _)| *name)
    .collect();
    eprintln!(
        "deepwork: daemon {} running on {}, socket {}{}",
        deepwork_core::VERSION,
        caps.os,
        socket.display(),
        if missing.is_empty() {
            String::new()
        } else {
            format!(" (not available here: {})", missing.join(", "))
        }
    );

    let mut last_wall = deepwork_core::now();
    let mut last_mono = Instant::now();
    let mut last_save = Instant::now();
    loop {
        std::thread::sleep(Duration::from_millis(1000));
        let wall = deepwork_core::now();
        let mono = Instant::now();
        let mono_dt = mono.duration_since(last_mono).as_secs_f64();
        let plan =
            daemon
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .tick(wall, wall - last_wall, mono_dt);
        last_wall = wall;
        last_mono = mono;

        let kills = enforcer.apply(&plan);

        let snapshot = {
            let mut d = daemon.lock().unwrap_or_else(|e| e.into_inner());
            if !kills.is_empty() {
                d.record_kills(wall, kills);
            }
            d.net = enforcer.net_status();
            d.hardcore = enforcer.hardcore_status();
            if d.dirty || last_save.elapsed() > Duration::from_secs(30) {
                d.dirty = false;
                serde_json::to_vec_pretty(&d.p).ok()
            } else {
                None
            }
        };
        if let Some(data) = snapshot {
            last_save = Instant::now();
            if let Err(e) = write_atomic(&state_file, &data, 0o600) {
                eprintln!("deepwork: cannot save state: {e}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_user_keeps_other_settings() {
        let dir = std::env::temp_dir().join(format!("dw-allow-{}", std::process::id()));
        let path = dir.join("config.json");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(&path, r#"{"allowed_users": [1000], "other": true}"#).unwrap();
        let me = if cfg!(windows) {
            "S-1-5-21-1-2-3-1001"
        } else {
            "1001"
        };
        allow_user(&path, me).unwrap();
        allow_user(&path, me).unwrap(); // only once
        let v: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(v["other"], true);
        let list = v["allowed_users"].as_array().unwrap();
        if cfg!(windows) {
            // Bare numbers (old style) are dropped on Windows.
            assert_eq!(list, &[serde_json::json!(me)]);
            assert!(allow_user(&path, "1001").is_err());
        } else {
            assert_eq!(list, &[serde_json::json!(1000), serde_json::json!(1001)]);
        }
        assert_eq!(allowed_users(&path).map(|l| l.len()), Some(list.len()));
        // A broken file lets only administrators in.
        fs::write(&path, "{ nope").unwrap();
        assert_eq!(allowed_users(&path), Some(vec![]));
        let _ = fs::remove_dir_all(&dir);
    }
}
