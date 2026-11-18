//! Applies a [`Plan`] to the system through the [`Platform`]. Features the
//! platform doesn't have are skipped.

use std::collections::{BTreeSet, HashSet};
use std::fs;
use std::net::{IpAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use deepwork_core::doh::DOH_HOSTS;
use deepwork_core::protocol::{Capabilities, HardcoreStatus, NetStatus};

use crate::browser::Policies;
use crate::hosts;
use crate::platform::{NetWant, Options, Platform};
use crate::procs::Killer;
use crate::state::Plan;

pub struct Enforcer {
    platform: Platform,
    hosts_path: Option<PathBuf>,
    policies: Option<Policies>,
    killer: Option<Killer>,
    last_domains: Option<BTreeSet<String>>,
    last_doh: bool,
    last_hosts_check: Instant,
    last_lock: Option<Instant>,
    hardcore_until: f64,
    /// Addresses of newly blocked sites whose connections are being cut,
    /// since when, and how many of [`CUT_AT`] are done.
    cutting: Option<(BTreeSet<IpAddr>, Instant, usize)>,
}

/// When open connections to newly blocked sites are cut (seconds after the
/// block started). A page that reconnects right away may still reach the
/// site while DNS caches catch up with the hosts file, so it is repeated a
/// few times. Not more often: the addresses can be shared with other sites.
const CUT_AT: [u64; 6] = [0, 2, 5, 15, 30, 60];

impl Enforcer {
    pub fn new(mut platform: Platform, opts: &Options) -> Self {
        let policies = platform.browsers.take().map(|layout| Policies {
            layout,
            root: opts.root.clone(),
            state_dir: opts.state_dir.clone(),
            sandbox: opts.sandbox,
        });
        let killer = platform.processes.take().map(Killer::new);
        Self {
            hosts_path: platform.system.hosts_file(),
            platform,
            policies,
            killer,
            last_domains: None,
            last_doh: false,
            last_hosts_check: Instant::now(),
            last_lock: None,
            hardcore_until: 0.0,
            cutting: None,
        }
    }

    /// What this platform supports (taken before the pieces were moved in).
    pub fn capabilities(&self) -> Capabilities {
        let mut caps = self.platform.capabilities();
        caps.browser_policies = self.policies.is_some();
        caps.apps = self.killer.is_some();
        caps
    }

    pub fn boot_id(&self) -> String {
        self.platform.system.boot_id().unwrap_or_default()
    }

    /// Returns `(app, block)` pairs that were just closed.
    pub fn apply(&mut self, plan: &Plan) -> Vec<(String, String)> {
        let changed =
            self.last_domains.as_ref() != Some(&plan.domains) || self.last_doh != plan.block_doh;
        let exact: BTreeSet<String> = if plan.block_doh {
            DOH_HOSTS.iter().map(|h| h.to_string()).collect()
        } else {
            BTreeSet::new()
        };
        if changed || self.last_hosts_check.elapsed() > Duration::from_secs(5) {
            self.last_hosts_check = Instant::now();
            let added: BTreeSet<String> = match &self.last_domains {
                Some(old) => plan.domains.difference(old).cloned().collect(),
                None => plan.domains.clone(),
            };
            // Resolve before the hosts file hides the real addresses, so open
            // connections to those sites can be cut afterwards.
            let ips = if changed && !added.is_empty() {
                resolve(&added)
            } else {
                vec![]
            };
            match self.sync_hosts(&plan.domains, &exact) {
                Ok(true) => self.platform.system.flush_dns(),
                Ok(false) => {}
                Err(e) => eprintln!("deepwork: cannot update the hosts file: {e}"),
            }
            if changed {
                if let Some(p) = &self.policies
                    && let Err(e) = p.apply(&plan.domains)
                {
                    eprintln!("deepwork: cannot update browser policies: {e}");
                }
                // Stop cutting once a site is unblocked again.
                if self
                    .last_domains
                    .as_ref()
                    .is_some_and(|old| !old.is_subset(&plan.domains))
                {
                    self.cutting = None;
                }
                if !ips.is_empty() {
                    let mut set = self.cutting.take().map(|c| c.0).unwrap_or_default();
                    set.extend(ips);
                    self.cutting = Some((set, Instant::now(), 0));
                }
                self.last_domains = Some(plan.domains.clone());
                self.last_doh = plan.block_doh;
                if let Some(net) = self.platform.net.as_mut() {
                    let mut set: HashSet<String> = plan.domains.iter().cloned().collect();
                    set.extend(exact.iter().cloned());
                    net.set_blocked(set);
                }
            }
        }
        if let Some((ips, since, done)) = &mut self.cutting
            && since.elapsed() >= Duration::from_secs(CUT_AT[*done])
        {
            let ips: Vec<IpAddr> = ips.iter().copied().collect();
            self.platform.system.cut_connections(&ips);
            *done += 1;
            if *done == CUT_AT.len() {
                self.cutting = None;
            }
        }
        if let Some(net) = self.platform.net.as_mut() {
            net.apply(NetWant {
                doh: plan.block_doh,
                filter: plan.https_filter,
                tunnels: plan.block_tunnels,
            });
        }
        if let Some(admin) = self.platform.admin.as_mut() {
            admin.apply(plan.hardcore_until);
        }
        self.hardcore_until = plan.hardcore_until;

        if plan.frozen
            && self
                .last_lock
                .is_none_or(|t| t.elapsed() >= Duration::from_secs(2))
        {
            self.last_lock = Some(Instant::now());
            self.platform.system.lock_screen();
        }

        match self.killer.as_mut() {
            Some(k) => k.enforce(&plan.apps),
            None => vec![],
        }
    }

    pub fn net_status(&self) -> NetStatus {
        self.platform
            .net
            .as_ref()
            .map(|n| n.status())
            .unwrap_or_default()
    }

    pub fn hardcore_status(&self) -> HardcoreStatus {
        HardcoreStatus {
            until: self.hardcore_until,
            warnings: self
                .platform
                .admin
                .as_ref()
                .map(|a| a.warnings())
                .unwrap_or_default(),
        }
    }

    /// Returns whether the file was rewritten.
    fn sync_hosts(
        &self,
        domains: &BTreeSet<String>,
        exact: &BTreeSet<String>,
    ) -> std::io::Result<bool> {
        let Some(path) = &self.hosts_path else {
            return Ok(false);
        };
        let current = fs::read_to_string(path).unwrap_or_default();
        let wanted = hosts::render(&current, domains, exact);
        if wanted == current {
            return Ok(false);
        }
        crate::write_atomic(path, wanted.as_bytes(), 0o644)?;
        Ok(true)
    }

    /// Undo everything (service uninstall).
    pub fn cleanup(&mut self) -> std::io::Result<()> {
        if let Some(admin) = self.platform.admin.as_mut() {
            admin.release();
        }
        self.sync_hosts(&BTreeSet::new(), &BTreeSet::new())?;
        if let Some(net) = self.platform.net.as_mut() {
            net.cleanup();
        }
        match &self.policies {
            Some(p) => p.cleanup(),
            None => Ok(()),
        }
    }
}

fn resolve(domains: &BTreeSet<String>) -> Vec<IpAddr> {
    let (tx, rx) = mpsc::channel();
    let hosts: Vec<String> = domains
        .iter()
        .flat_map(|d| [d.clone(), format!("www.{d}")])
        .collect();
    std::thread::spawn(move || {
        let mut ips = BTreeSet::new();
        for h in hosts {
            if let Ok(addrs) = (h.as_str(), 443).to_socket_addrs() {
                ips.extend(
                    addrs
                        .map(|a| a.ip())
                        .filter(|ip| !ip.is_loopback() && !ip.is_unspecified()),
                );
            }
        }
        let _ = tx.send(ips.into_iter().collect());
    });
    rx.recv_timeout(Duration::from_secs(3)).unwrap_or_default()
}
