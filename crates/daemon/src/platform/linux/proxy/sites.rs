//! Whether a site name leads where a connection goes.
//!
//! The filter only sees the name a client gives, so it also checks that the
//! name leads to the address the client connects to. Otherwise an allowed
//! name could carry a request to a blocked site's server, which picks the
//! site from the encrypted (HTTPS) or ignored (HTTP) name instead.

use std::collections::HashMap;
use std::net::{IpAddr, ToSocketAddrs};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// An address stays a name's this long after it was last among the name's
/// answers: browsers keep answers for a while too.
const KEEP: Duration = Duration::from_secs(10 * 60);
/// A name whose known addresses don't have the one asked for is looked up
/// again, at most this often.
const RETRY: Duration = Duration::from_secs(2);
/// Site names remembered at most; past that the list starts over.
const MAX_NAMES: usize = 1024;

struct Lookup {
    /// When the name was last looked up.
    at: Instant,
    /// Its addresses, and when each was last among the answers.
    ips: HashMap<IpAddr, Instant>,
}

/// The addresses of site names, as the system's resolver gives them (the
/// same answers browsers get: DeepWork turns their own encrypted DNS off).
#[derive(Default)]
pub struct Names {
    names: Mutex<HashMap<String, Lookup>>,
}

impl Names {
    /// Whether `ip` is one of `host`'s addresses.
    pub fn has(&self, host: &str, ip: IpAddr) -> bool {
        self.has_with(host, ip, resolve)
    }

    pub(super) fn has_with(
        &self,
        host: &str,
        ip: IpAddr,
        resolve: impl Fn(&str) -> Vec<IpAddr>,
    ) -> bool {
        let ip = ip.to_canonical();
        let names = || self.names.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(known) = names().get(host) {
            if known.ips.get(&ip).is_some_and(|t| t.elapsed() < KEEP) {
                return true;
            }
            if known.at.elapsed() < RETRY {
                return false;
            }
        }
        let found = resolve(host);
        let now = Instant::now();
        let mut names = names();
        if names.len() >= MAX_NAMES && !names.contains_key(host) {
            names.clear();
        }
        let known = names.entry(host.to_string()).or_insert(Lookup {
            at: now,
            ips: HashMap::new(),
        });
        known.at = now;
        known.ips.extend(found.into_iter().map(|a| (a, now)));
        known.ips.retain(|_, t| t.elapsed() < KEEP);
        known.ips.contains_key(&ip)
    }
}

fn resolve(host: &str) -> Vec<IpAddr> {
    (host, 0)
        .to_socket_addrs()
        .map(|addrs| {
            addrs
                .map(|a| a.ip().to_canonical())
                .filter(|ip| !ip.is_unspecified())
                .collect()
        })
        .unwrap_or_default()
}

/// The address a site name is, if it is one: `192.0.2.1`, `[2001:db8::1]`.
pub fn ip_literal(host: &str) -> Option<IpAddr> {
    let bare = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    bare.parse().ok()
}

/// Whether `host` is an ordinary host name. Resolvers also take addresses in
/// other spellings (`16843009`, `0x1010101` and `1.65793` are 1.1.1.1,
/// `fe80::1%eth0` has a scope) and "resolve" them, so they would count as
/// names leading to any server. As in browsers, a name whose last label is a
/// number is an address.
pub fn is_name(host: &str) -> bool {
    let host = host.strip_suffix('.').unwrap_or(host);
    let last = host.rsplit('.').next().unwrap_or(host);
    let hex = last.strip_prefix("0x").or(last.strip_prefix("0X"));
    let number = last.bytes().all(|b| b.is_ascii_digit())
        || hex.is_some_and(|h| h.bytes().all(|b| b.is_ascii_hexdigit()));
    !number
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}

/// An address on a local network (private, link-local, or carrier-grade
/// NAT as VPNs like Tailscale use): a router's or a printer's page, reached
/// by address, and never a website's.
pub fn local_network(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            v4.is_private() || v4.is_link_local() || (a == 100 && (64..128).contains(&b))
        }
        IpAddr::V6(v6) => {
            let first = v6.segments()[0];
            first & 0xfe00 == 0xfc00 || first & 0xffc0 == 0xfe80
        }
    }
}
