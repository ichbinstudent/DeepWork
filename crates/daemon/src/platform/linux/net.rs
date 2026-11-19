//! nftables rules plus the transparent filter, as a [`NetGuard`].

use std::collections::HashSet;
use std::time::{Duration, Instant};

use deepwork_core::protocol::NetStatus;

use super::netfilter::{self, FilterPorts};
use super::proxy::Proxy;
use crate::platform::{NetGuard, NetWant, Options};

pub struct LinuxNet {
    uid_min: u32,
    /// Ports asked for on the command line (0: any free port).
    requested_ports: (u16, u16),
    proxy: Option<Proxy>,
    /// Why the web filter isn't running.
    proxy_error: Option<String>,
    last_proxy_try: Instant,
    blocked: HashSet<String>,
    applied: NetWant,
    applied_ports: Option<FilterPorts>,
    last_check: Instant,
    firewall_error: Option<String>,
}

impl LinuxNet {
    pub fn new(opts: &Options) -> Self {
        // A table left behind by a crash would send traffic to a dead port.
        netfilter::remove();
        let mut net = LinuxNet {
            uid_min: opts.filter_uid_min,
            requested_ports: opts.filter_ports,
            proxy: None,
            proxy_error: None,
            last_proxy_try: Instant::now(),
            blocked: HashSet::new(),
            applied: NetWant::default(),
            applied_ports: None,
            last_check: Instant::now(),
            firewall_error: None,
        };
        net.start_proxy();
        net
    }

    fn start_proxy(&mut self) {
        self.last_proxy_try = Instant::now();
        let (tls, http) = self.requested_ports;
        match Proxy::start(tls, http) {
            Ok(p) => {
                p.set_blocked(self.blocked.clone());
                self.proxy = Some(p);
                self.proxy_error = None;
            }
            Err(e) => {
                eprintln!("deepwork: HTTPS filter unavailable: {e}");
                self.proxy_error = Some(format!(
                    "HTTPS filter unavailable ({e}); web traffic is refused while it should be \
                     filtered"
                ));
            }
        }
    }
}

impl NetGuard for LinuxNet {
    fn supported(&self) -> NetWant {
        // The web filter is retried if it couldn't start; until it runs,
        // the traffic it should check is refused.
        NetWant {
            doh: true,
            filter: true,
            tunnels: true,
        }
    }

    fn apply(&mut self, want: NetWant) {
        let want = want.and(self.supported());
        if want.filter
            && self.proxy.is_none()
            && self.last_proxy_try.elapsed() > Duration::from_secs(10)
        {
            self.start_proxy();
        }
        let ports = self.proxy.as_ref().map(Proxy::ports);
        // Somebody may have flushed the ruleset; check now and then.
        let recheck = want.any() && self.last_check.elapsed() > Duration::from_secs(10);
        let same = want == self.applied && (!want.filter || ports == self.applied_ports);
        if same && !recheck {
            return;
        }
        self.last_check = Instant::now();
        if same && netfilter::present() {
            return;
        }
        let cfg = netfilter::Config {
            uid_min: self.uid_min,
            filter: ports,
        };
        match netfilter::apply(&cfg, want) {
            Ok(()) => {
                self.applied = want;
                self.applied_ports = ports;
                self.firewall_error = None;
            }
            Err(e) => {
                eprintln!("deepwork: firewall update failed: {e}");
                self.firewall_error = Some(format!("Firewall rules could not be applied: {e}"));
                self.applied = NetWant::default();
            }
        }
    }

    fn set_blocked(&mut self, domains: HashSet<String>) {
        if let Some(p) = &self.proxy {
            p.set_blocked(domains.clone());
        }
        self.blocked = domains;
    }

    fn status(&self) -> NetStatus {
        NetStatus {
            firewall_available: true,
            doh_blocked: self.applied.doh,
            filtering: self.applied.filter,
            tunnels_blocked: self.applied.tunnels,
            filtered_connections: self.proxy.as_ref().map(|p| p.refused()).unwrap_or(0),
            error: self
                .firewall_error
                .clone()
                .or_else(|| self.proxy_error.clone()),
        }
    }

    fn cleanup(&mut self) {
        netfilter::remove();
        self.applied = NetWant::default();
    }
}
