//! nftables rules plus the transparent filter, as a [`NetGuard`].

use std::collections::HashSet;
use std::time::{Duration, Instant};

use deepwork_core::protocol::NetStatus;

use super::netfilter;
use super::proxy::Proxy;
use crate::platform::{NetGuard, NetWant, Options};

pub struct LinuxNet {
    cfg: netfilter::Config,
    proxy: Option<Proxy>,
    applied: NetWant,
    last_check: Instant,
    error: Option<String>,
}

impl LinuxNet {
    pub fn new(opts: &Options) -> Self {
        // A table left behind by a crash would send traffic to a dead port.
        netfilter::remove();
        let (tls, http) = opts.filter_ports;
        let (proxy, error) = match Proxy::start(tls, http) {
            Ok(p) => (Some(p), None),
            Err(e) => (None, Some(format!("HTTPS filter unavailable: {e}"))),
        };
        LinuxNet {
            cfg: netfilter::Config {
                uid_min: opts.filter_uid_min,
                tls_port: tls,
                http_port: http,
            },
            proxy,
            applied: NetWant::default(),
            last_check: Instant::now(),
            error,
        }
    }
}

impl NetGuard for LinuxNet {
    fn supported(&self) -> NetWant {
        NetWant {
            doh: true,
            filter: self.proxy.is_some(),
            tunnels: true,
        }
    }

    fn apply(&mut self, want: NetWant) {
        let want = want.and(self.supported());
        // Somebody may have flushed the ruleset; check now and then.
        let recheck = want.any() && self.last_check.elapsed() > Duration::from_secs(10);
        if want == self.applied && !recheck {
            return;
        }
        self.last_check = Instant::now();
        if want == self.applied && netfilter::present() {
            return;
        }
        match netfilter::apply(&self.cfg, want) {
            Ok(()) => {
                self.applied = want;
                if self
                    .error
                    .as_deref()
                    .is_some_and(|e| e.starts_with("Firewall"))
                {
                    self.error = None;
                }
            }
            Err(e) => {
                eprintln!("deepwork: firewall update failed: {e}");
                self.error = Some(format!("Firewall rules could not be applied: {e}"));
                self.applied = NetWant::default();
            }
        }
    }

    fn set_blocked(&mut self, domains: HashSet<String>) {
        if let Some(p) = &self.proxy {
            p.set_blocked(domains);
        }
    }

    fn status(&self) -> NetStatus {
        NetStatus {
            firewall_available: true,
            doh_blocked: self.applied.doh,
            filtering: self.applied.filter,
            tunnels_blocked: self.applied.tunnels,
            filtered_connections: self.proxy.as_ref().map(|p| p.refused()).unwrap_or(0),
            error: self.error.clone(),
        }
    }

    fn cleanup(&mut self) {
        netfilter::remove();
        self.applied = NetWant::default();
    }
}
