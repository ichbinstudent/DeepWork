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

use std::fs;
use std::net::IpAddr;
use std::path::PathBuf;

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
        }),
        browsers: Some(Layout {
            chromium: CHROMIUM_FLAVORS,
            chromium_store: None,
            firefox: Some((FIREFOX_POLICY, FIREFOX_MARKERS)),
        }),
        processes: Some(Box::new(procs::ProcFs)),
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
        if !self.run {
            return;
        }
        for chunk in ips.chunks(16) {
            let mut args = vec!["-K".to_string()];
            for (i, ip) in chunk.iter().enumerate() {
                if i > 0 {
                    args.push("or".into());
                }
                args.push("dst".into());
                args.push(ip.to_string());
            }
            let refs: Vec<&str> = args.iter().map(String::as_str).collect();
            spawn_quiet("ss", &refs);
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
