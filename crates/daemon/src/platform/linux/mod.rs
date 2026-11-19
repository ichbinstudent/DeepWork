//! Linux: the reference platform, with every feature.
//!
//! - websites: `/etc/hosts` + systemd-resolved cache flush
//! - browsers: JSON policy files for Chromium-based browsers and Firefox
//! - apps: `/proc`, with app ids from systemd scopes
//! - network: nftables + a transparent SNI/Host filter
//! - freeze: `loginctl lock-sessions`
//! - hardcore: sudoers, doas, polkit and root's password

mod hardcore;
mod net;
mod netfilter;
mod procs;
mod proxy;

use std::collections::HashSet;
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::process::{Command, Stdio};

use super::{Options, Paths, Platform, System, spawn_quiet};
use crate::browser::{ChromiumFlavor, Layout};

pub fn paths() -> Paths {
    Paths {
        state_dir: "/var/lib/deepwork".into(),
        config: "/etc/deepwork/config.json".into(),
    }
}

pub fn platform(opts: &Options) -> Platform {
    let run = !opts.sandbox;
    let net = if (opts.force_net || (run && super::is_privileged())) && netfilter::available() {
        Some(Box::new(net::LinuxNet::new(opts)) as Box<dyn super::NetGuard>)
    } else {
        if run {
            eprintln!(
                "deepwork: nft not available or not root; encrypted DNS blocking and HTTPS \
                 filtering are off"
            );
        }
        None
    };
    Platform {
        os: "Linux",
        system: Box::new(LinuxSystem {
            hosts: opts.root.join("etc/hosts"),
            run,
            uid_min: opts.filter_uid_min,
        }),
        browsers: Some(Layout {
            chromium: CHROMIUM_FLAVORS,
            chromium_store: None,
            firefox: Some((FIREFOX_POLICY, FIREFOX_MARKERS)),
        }),
        processes: Some(Box::new(procs::ProcFs {
            uid_min: opts.filter_uid_min,
        })),
        net,
        admin: Some(Box::new(hardcore::Hardcore::new(
            hardcore::Paths::new(&opts.root, &opts.state_dir),
            run,
        ))),
    }
}

struct LinuxSystem {
    hosts: PathBuf,
    /// Run system commands (off in the sandbox).
    run: bool,
    /// Lowest uid of a person's account: only their connections are cut.
    uid_min: u32,
}

/// `ss` filter for connections to websites.
const WEB_PORTS: &str = "( dport = :443 or dport = :80 )";

/// The connections in `ss -tnHe state established` output that may be cut:
/// to a website (port 443 or 80) at one of `ips`, made by a person's
/// account. Root's and services' connections, and connections coming in
/// (SSH, say), stay up whatever address a website is given. Returns each
/// one's local and remote address the way `ss` writes them.
fn web_connections(listing: &str, ips: &HashSet<IpAddr>, uid_min: u32) -> Vec<(String, String)> {
    listing
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let (local, peer) = (*fields.get(2)?, *fields.get(3)?);
            let remote: SocketAddr = peer.parse().ok()?;
            // ss leaves the uid out for root's connections.
            let uid = fields.iter().find_map(|f| f.strip_prefix("uid:"))?;
            let person = procs::is_user_account(uid.parse().ok()?, uid_min);
            (person
                && matches!(remote.port(), 443 | 80)
                && ips.contains(&remote.ip().to_canonical()))
            .then(|| (local.to_string(), peer.to_string()))
        })
        .collect()
}

impl System for LinuxSystem {
    fn hosts_file(&self) -> Option<PathBuf> {
        Some(self.hosts.clone())
    }

    fn flush_dns(&self) {
        if self.run {
            spawn_quiet("resolvectl", &["flush-caches"]);
        }
    }

    fn cut_connections(&self, ips: &[IpAddr]) {
        if !self.run || ips.is_empty() {
            return;
        }
        let Ok(out) = Command::new("ss")
            .args(["-tnHe", "state", "established", WEB_PORTS])
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
        else {
            return;
        };
        let ips: HashSet<IpAddr> = ips.iter().map(IpAddr::to_canonical).collect();
        let listing = String::from_utf8_lossy(&out.stdout);
        for chunk in web_connections(&listing, &ips, self.uid_min).chunks(16) {
            let filter = chunk
                .iter()
                .map(|(local, peer)| format!("( src {local} dst {peer} )"))
                .collect::<Vec<_>>()
                .join(" or ");
            spawn_quiet("ss", &["-K", "-tn", "state", "established", &filter]);
        }
    }

    fn can_lock_screen(&self) -> bool {
        true
    }

    fn lock_screen(&self) {
        if self.run {
            spawn_quiet("loginctl", &["lock-sessions"]);
        }
    }

    fn boot_id(&self) -> Option<String> {
        fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    }
}

/// Policy directories and the files whose presence means the browser is installed.
const CHROMIUM_FLAVORS: &[ChromiumFlavor] = &[
    ChromiumFlavor {
        dir: "/etc/opt/chrome/policies/managed",
        markers: &[
            "/opt/google/chrome",
            "/usr/bin/google-chrome-stable",
            "/usr/bin/google-chrome",
        ],
    },
    ChromiumFlavor {
        dir: "/etc/chromium/policies/managed",
        markers: &[
            "/usr/bin/chromium",
            "/usr/bin/chromium-browser",
            "/usr/lib/chromium",
        ],
    },
    ChromiumFlavor {
        dir: "/etc/brave/policies/managed",
        markers: &[
            "/opt/brave.com",
            "/opt/brave-bin",
            "/usr/bin/brave",
            "/usr/bin/brave-browser",
        ],
    },
    ChromiumFlavor {
        dir: "/etc/opt/edge/policies/managed",
        markers: &[
            "/opt/microsoft/msedge",
            "/usr/bin/microsoft-edge-stable",
            "/usr/bin/microsoft-edge",
        ],
    },
    ChromiumFlavor {
        dir: "/etc/opt/vivaldi/policies/managed",
        markers: &[
            "/opt/vivaldi",
            "/usr/bin/vivaldi-stable",
            "/usr/bin/vivaldi",
        ],
    },
];

const FIREFOX_POLICY: &str = "/etc/firefox/policies/policies.json";
const FIREFOX_MARKERS: &[&str] = &[
    "/usr/lib/firefox",
    "/usr/lib64/firefox",
    "/opt/firefox",
    "/usr/bin/firefox",
];

#[cfg(test)]
mod tests;
