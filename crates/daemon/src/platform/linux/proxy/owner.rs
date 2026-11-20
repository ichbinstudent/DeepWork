//! Whose a connection to the filter is, so one user can't take all of its
//! connections.

use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// The user whose socket connects from `local` to `remote` (the client's
/// own view: the firewall's redirect to the filter doesn't show there).
pub fn owner(local: SocketAddr, remote: SocketAddr) -> Option<u32> {
    ["/proc/net/tcp", "/proc/net/tcp6"]
        .iter()
        .find_map(|t| owner_in(&fs::read_to_string(t).ok()?, local, remote))
}

/// [`owner`] in the text of `/proc/net/tcp` or `/proc/net/tcp6`.
pub fn owner_in(table: &str, local: SocketAddr, remote: SocketAddr) -> Option<u32> {
    let canonical = |a: SocketAddr| (a.ip().to_canonical(), a.port());
    let (local, remote) = (canonical(local), canonical(remote));
    table.lines().skip(1).find_map(|line| {
        let f: Vec<&str> = line.split_whitespace().collect();
        let here = canonical(parse_addr(f.get(1)?)?);
        let there = canonical(parse_addr(f.get(2)?)?);
        (here == local && there == remote).then(|| f.get(7)?.parse().ok())?
    })
}

/// An address as the kernel writes it there: `0100007F:0050`, the address
/// in 32-bit words of host byte order.
fn parse_addr(s: &str) -> Option<SocketAddr> {
    let (addr, port) = s.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let words = (0..addr.len() / 8)
        .map(|i| u32::from_str_radix(addr.get(i * 8..i * 8 + 8)?, 16).ok())
        .collect::<Option<Vec<u32>>>()?;
    if addr.len() != words.len() * 8 {
        return None;
    }
    let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_ne_bytes()).collect();
    let ip = match bytes.len() {
        4 => IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(bytes).ok()?)),
        16 => IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(bytes).ok()?)),
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}
