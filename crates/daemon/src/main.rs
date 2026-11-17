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
    /// User ids allowed to talk to the daemon (root always is). Empty = everyone.
    allowed_users: Vec<u32>,
}

fn usage() -> ! {
    eprintln!(
        "usage: deepwork-daemon [--sandbox DIR] [--socket PATH] [--net] [--filter-uid-min N]\n                       \
         [--proxy-ports TLS,HTTP] [--cleanup]\n\n  \
         --sandbox DIR         keep all files under DIR and don't touch the system (for testing)\n  \
         --socket PATH         listen on PATH instead of the default socket\n  \
         --net                 manage the firewall and HTTPS filter even in the sandbox\n  \
         --filter-uid-min N    only filter processes of users with uid >= N (default 1000)\n  \
         --proxy-ports T,H     ports of the HTTPS and HTTP filter (default 41443,41080)\n  \
         --cleanup             remove blocks from the hosts file, browser policies and the firewall,\n                        \
       and give administrator rights back (hardcore mode), then exit"
    );
    std::process::exit(2)
}

fn main() {
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
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
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
    let config: Config = fs::read_to_string(&config_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    let allowed = (!config.allowed_users.is_empty()).then_some(config.allowed_users);

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
