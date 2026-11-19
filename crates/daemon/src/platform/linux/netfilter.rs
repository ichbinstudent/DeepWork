//! nftables rules for encrypted-DNS blocking and HTTPS filtering.
//!
//! Everything lives in one table, `inet deepwork`, which is replaced
//! atomically and deleted when nothing needs it. Only processes of regular
//! users (uid >= `uid_min`) are affected, so system services such as
//! systemd-resolved (including DNS over TLS configured there) keep working.

use std::io::Write;
use std::process::{Command, Stdio};

use deepwork_core::doh::{DOH_IPV4, DOH_IPV6};

use super::proxy::MARK;
use crate::platform::NetWant;

pub const TABLE: &str = "deepwork";

/// Interface types of VPN and tunnel devices: `none` (0xfffe) covers tun
/// devices (OpenVPN, Tailscale, most VPN apps) and WireGuard; the others are
/// IP-in-IP and GRE tunnels. Ethernet, Wi-Fi, PPP and loopback stay open.
const TUNNEL_TYPES: &str = "0xfffe, ipip, ipip6, ipgre, sit";

#[derive(Debug, Clone)]
pub struct Config {
    pub uid_min: u32,
    /// Where the web filter listens. `None`: it isn't running, so web
    /// traffic that should be filtered is refused instead of let through.
    pub filter: Option<FilterPorts>,
}

/// Ports of the web filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FilterPorts {
    /// HTTPS and HTTP on 127.0.0.1.
    pub v4: (u16, u16),
    /// HTTPS and HTTP on ::1; `None` without IPv6, and then IPv6 web
    /// traffic is refused while filtering.
    pub v6: Option<(u16, u16)>,
}

pub fn ruleset(cfg: &Config, want: NetWant) -> String {
    let skip_system = if cfg.uid_min > 0 {
        format!("        meta skuid < {} return\n", cfg.uid_min)
    } else {
        String::new()
    };
    let mut s = String::new();
    // Create-then-delete makes the replacement atomic and idempotent.
    s.push_str(&format!(
        "table inet {TABLE} {{}}\ndelete table inet {TABLE}\ntable inet {TABLE} {{\n"
    ));
    if want.doh {
        s.push_str(&format!(
            "    set doh4 {{\n        type ipv4_addr; flags interval\n        elements = {{ {} }}\n    }}\n",
            DOH_IPV4.join(", ")
        ));
        s.push_str(&format!(
            "    set doh6 {{\n        type ipv6_addr; flags interval\n        elements = {{ {} }}\n    }}\n",
            DOH_IPV6.join(", ")
        ));
    }
    // Runs before NAT (priority -150 < dstnat -100) so it sees the real destination.
    s.push_str(
        "    chain guard {\n        type filter hook output priority -150; policy accept;\n",
    );
    s.push_str(&format!("        meta mark {MARK:#x} return\n"));
    s.push_str(&skip_system);
    if want.tunnels {
        s.push_str(&format!(
            "        meta oiftype {{ {TUNNEL_TYPES} }} reject\n"
        ));
    }
    if want.doh {
        s.push_str(
            "        ip daddr @doh4 meta l4proto { tcp, udp } th dport { 443, 853 } reject\n",
        );
        s.push_str(
            "        ip6 daddr @doh6 meta l4proto { tcp, udp } th dport { 443, 853 } reject\n",
        );
    }
    if want.filter {
        // HTTP/3 can't be filtered by name here; browsers fall back to TCP.
        s.push_str("        udp dport 443 reject\n");
        // Web traffic the filter can't take is refused, never let through.
        let refuse4 =
            "        ip daddr != 127.0.0.0/8 tcp dport { 80, 443 } reject with tcp reset\n";
        let refuse6 = "        ip6 daddr != ::1 tcp dport { 80, 443 } reject with tcp reset\n";
        match cfg.filter {
            None => {
                s.push_str(refuse4);
                s.push_str(refuse6);
            }
            Some(FilterPorts { v6: None, .. }) => s.push_str(refuse6),
            Some(_) => {}
        }
    }
    s.push_str("    }\n");
    if want.filter
        && let Some(ports) = cfg.filter
    {
        s.push_str("    chain web_redirect {\n        type nat hook output priority dstnat; policy accept;\n");
        s.push_str(&format!("        meta mark {MARK:#x} return\n"));
        s.push_str(&skip_system);
        s.push_str("        ip daddr 127.0.0.0/8 return\n        ip6 daddr ::1 return\n");
        let families = [("ipv4", Some(ports.v4)), ("ipv6", ports.v6)];
        for (family, ports) in families {
            if let Some((tls, http)) = ports {
                s.push_str(&format!(
                    "        meta nfproto {family} tcp dport 443 redirect to :{tls}\n"
                ));
                s.push_str(&format!(
                    "        meta nfproto {family} tcp dport 80 redirect to :{http}\n"
                ));
            }
        }
        s.push_str("    }\n");
    }
    s.push_str("}\n");
    s
}

fn nft(input: Option<&str>, args: &[&str]) -> Result<(), String> {
    let mut child = Command::new("nft")
        .args(args)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("cannot run nft: {e}"))?;
    if let (Some(text), Some(mut stdin)) = (input, child.stdin.take()) {
        stdin
            .write_all(text.as_bytes())
            .map_err(|e| e.to_string())?;
    }
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

pub fn available() -> bool {
    nft(None, &["--version"]).is_ok()
}

pub fn apply(cfg: &Config, want: NetWant) -> Result<(), String> {
    if want.any() {
        nft(Some(&ruleset(cfg, want)), &["-f", "-"])
    } else {
        remove();
        Ok(())
    }
}

pub fn remove() {
    let _ = nft(None, &["delete", "table", "inet", TABLE]);
}

/// Whether our table is still loaded (somebody may have flushed the ruleset).
pub fn present() -> bool {
    nft(None, &["list", "table", "inet", TABLE]).is_ok()
}

#[cfg(test)]
mod tests;
