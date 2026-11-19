//! DeepWork daemon: runs with full privileges and enforces blocks.
//!
//! Everything OS-specific lives in [`platform`]; the rest is portable.

mod browser;
mod enforcer;
mod hosts;
mod persist;
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
use crate::state::Daemon;

/// Write a file atomically (temp file + rename) with the given Unix mode
/// (ignored elsewhere).
///
/// The service runs as root, so it never follows a link that somebody else
/// could have put there: a symlinked target is written in place (keeping the
/// link) only when its directory belongs to administrators, and is replaced
/// otherwise. The temporary file is always created new, never opened through
/// an existing link.
pub fn write_atomic(path: &Path, data: &[u8], mode: u32) -> std::io::Result<()> {
    let dir = path.parent().unwrap_or(Path::new("."));
    if fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) && admin_only(dir) {
        return fs::write(path, data);
    }
    let tmp = dir.join(format!(
        ".{}.deepwork-tmp",
        path.file_name().unwrap_or_default().to_string_lossy()
    ));
    let _ = fs::remove_file(&tmp);
    {
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut opts, mode);
        let mut f = opts.open(&tmp)?;
        f.write_all(data)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(fs::Permissions::from_mode(mode))?;
        }
        #[cfg(not(unix))]
        let _ = mode;
        f.sync_all()?;
    }
    fs::rename(&tmp, path).or_else(|e| {
        // Some files can't be replaced, only rewritten: a mount point (e.g.
        // /etc/hosts in containers), or a file another program holds open.
        let _ = fs::remove_file(&tmp);
        rewrite_in_place(path, data).map_err(|_| e)
    })
}

/// Overwrite an existing file without following a symlink at `path`.
fn rewrite_in_place(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(&mut opts, libc::O_NOFOLLOW);
    opts.open(path)?.write_all(data)
}

/// Read a file the service manages, following a symlink at `path` only when
/// [`write_atomic`] would follow it too: a link elsewhere could point the
/// service at any file on the system.
pub fn read_managed(path: &Path) -> std::io::Result<String> {
    if fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink())
        && !path.parent().is_some_and(admin_only)
    {
        return Err(std::io::Error::other(format!(
            "{} is a link in a folder that non-administrators can change",
            path.display()
        )));
    }
    fs::read_to_string(path)
}

/// Whether only administrators can decide what `dir` is and what's in it:
/// every folder looked at on the way there, through links too, belongs to
/// root and nobody else may change it (on macOS, members of `admin` may: they
/// can get root anyway). Folders that don't exist yet count as safe, since
/// the service creates them. Elsewhere the service's own folders are made
/// admin-only by the platform module, so this is assumed.
pub fn admin_only(dir: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let admin_gid = if cfg!(target_os = "macos") { 80 } else { 0 };
        let safe = |d: &Path| {
            fs::metadata(d).is_ok_and(|m| {
                m.uid() == 0
                    && m.mode() & 0o002 == 0
                    && (m.mode() & 0o020 == 0 || m.gid() == 0 || m.gid() == admin_gid)
            })
        };
        let Ok(dir) = std::path::absolute(dir) else {
            return false;
        };
        let mut prefix = PathBuf::new();
        for part in dir.components() {
            prefix.push(part);
            match fs::canonicalize(&prefix) {
                Ok(real) if real.ancestors().all(safe) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return true,
                _ => return false,
            }
        }
        true
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        true
    }
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
    /// or Windows SIDs.
    allowed_users: Vec<server::UserId>,
}

/// The users allowed to control the service besides administrators. A
/// config file that is missing, can't be read or lists nobody leaves only
/// administrators in, never everyone.
fn allowed_users(path: &Path) -> Vec<server::UserId> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) => {
            eprintln!(
                "deepwork: cannot read {} ({e}); only administrators may control DeepWork \
                 (add users with deepwork-daemon --allow-user)",
                path.display()
            );
            return vec![];
        }
    };
    match serde_json::from_str::<Config>(&text) {
        Ok(c) => {
            if c.allowed_users.is_empty() {
                eprintln!(
                    "deepwork: {} lists no users; only administrators may control DeepWork",
                    path.display()
                );
            }
            c.allowed_users
        }
        Err(e) => {
            eprintln!(
                "deepwork: {} is invalid ({e}); only administrators may control DeepWork until it is fixed",
                path.display()
            );
            vec![]
        }
    }
}

/// Allow more open files than the usual 1024: the web filter needs two per
/// connection it relays.
#[cfg(unix)]
fn raise_open_files_limit() {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: valid pointer to an rlimit.
    unsafe {
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) == 0 && limit.rlim_cur < limit.rlim_max
        {
            limit.rlim_cur = limit.rlim_max.min(65_536);
            libc::setrlimit(libc::RLIMIT_NOFILE, &limit);
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
         --filter-uid-min N    lowest uid of a person's account: only their processes are\n                        \
       network-filtered or closed by app blocks (default 1000)\n  \
         --proxy-ports T,H     ports of the HTTPS and HTTP filter (default: any free ports)\n  \
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
        filter_ports: (0, 0),
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
    // Windows: the data folder must belong to administrators before
    // anything in it is trusted or written (any user may create folders in
    // C:\ProgramData, so it might be theirs).
    #[cfg(windows)]
    if !opts.sandbox
        && let Err(e) = platform::windows::prepare_data_dir(&opts.state_dir)
    {
        eprintln!(
            "deepwork: cannot make {} safe: {e}",
            opts.state_dir.parent().unwrap_or(&opts.state_dir).display()
        );
        std::process::exit(1);
    }
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
    #[cfg(unix)]
    raise_open_files_limit();

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
    let persisted = persist::load(&state_file).unwrap_or_else(|e| {
        eprintln!("deepwork: {e}");
        std::process::exit(1);
    });
    // A sandbox without a config file is a developer's test: anyone may use it.
    let allowed = if opts.sandbox && !config_path.exists() {
        None
    } else {
        Some(allowed_users(&config_path))
    };

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
mod tests;
