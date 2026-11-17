//! macOS: website blocking and Firefox policies so far.
//!
//! Still to do, roughly in order:
//! - apps ([`ProcessTable`](super::ProcessTable)): `proc_listpids` /
//!   `proc_pidpath` from libproc, bundle ids from the executable's
//!   `Info.plist`, `kill(2)` to close.
//! - browsers: Chromium-based browsers read managed preferences
//!   (`/Library/Managed Preferences/<bundle id>.plist`), not JSON files.
//! - freeze: needs an agent in the user's session (`CGSession -suspend`).
//! - network ([`NetGuard`](super::NetGuard)): `pf` anchors for encrypted DNS
//!   and tunnels; the web filter needs a Network Extension content filter.
//! - hardcore ([`AdminLockout`](super::AdminLockout)): a sudoers drop-in
//!   works as on Linux; admin rights also come from the `admin` group and
//!   the authorization database (`security authorizationdb`).
//!
//! The daemon would run as a LaunchDaemon (`/Library/LaunchDaemons`).

use std::path::PathBuf;
use std::process::Command;

use super::{Options, Paths, Platform, System, spawn_quiet};
use crate::browser::Layout;

pub fn paths() -> Paths {
    let base = PathBuf::from("/Library/Application Support/DeepWork");
    Paths {
        state_dir: base.join("state"),
        config: base.join("config.json"),
    }
}

pub fn platform(opts: &Options) -> Platform {
    Platform {
        os: "macOS",
        system: Box::new(MacSystem {
            // /etc is a link to /private/etc.
            hosts: opts.root.join("private/etc/hosts"),
            run: !opts.sandbox,
        }),
        browsers: Some(Layout {
            chromium: &[],
            firefox: Some((
                "/Applications/Firefox.app/Contents/Resources/distribution/policies.json",
                &["/Applications/Firefox.app"],
            )),
        }),
        processes: None,
        net: None,
        admin: None,
    }
}

struct MacSystem {
    hosts: PathBuf,
    run: bool,
}

impl System for MacSystem {
    fn hosts_file(&self) -> Option<PathBuf> {
        Some(self.hosts.clone())
    }

    fn flush_dns(&self) {
        if self.run {
            spawn_quiet("dscacheutil", &["-flushcache"]);
            spawn_quiet("killall", &["-HUP", "mDNSResponder"]);
        }
    }

    fn boot_id(&self) -> Option<String> {
        let out = Command::new("sysctl")
            .args(["-n", "kern.bootsessionuuid"])
            .output()
            .ok()?;
        let id = String::from_utf8_lossy(&out.stdout).trim().to_string();
        (out.status.success() && !id.is_empty()).then_some(id)
    }
}
