//! Transparent HTTPS/HTTP filter (Linux).
//!
//! nftables redirects user web traffic (TCP 443/80) to these listeners,
//! which find the original destination with `SO_ORIGINAL_DST`. The site name
//! is read by [`crate::webfilter`]. Nothing is decrypted. Blocked
//! connections are closed (HTTPS) or answered with a small block page
//! (HTTP); everything else is connected to the original destination and
//! relayed unchanged.

use std::collections::HashSet;
use std::io::{self, Write};
use std::mem::MaybeUninit;
use std::net::{
    Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, SocketAddrV4, SocketAddrV6, TcpListener, TcpStream,
};
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use crate::webfilter::{block_page, is_blocked, read_client_hello, read_http_head};

/// Mark set on the proxy's own outgoing connections so the firewall never
/// redirects them back to the proxy.
pub const MARK: u32 = 0x4457;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    Tls,
    Http,
}

struct Shared {
    blocked: RwLock<Arc<HashSet<String>>>,
    refused: AtomicU64,
    ports: (u16, u16),
}

#[derive(Clone)]
pub struct Proxy {
    shared: Arc<Shared>,
}

impl Proxy {
    /// Bind the listeners on 127.0.0.1 and ::1 and start accepting.
    pub fn start(tls_port: u16, http_port: u16) -> io::Result<Proxy> {
        let shared = Arc::new(Shared {
            blocked: RwLock::new(Arc::new(HashSet::new())),
            refused: AtomicU64::new(0),
            ports: (tls_port, http_port),
        });
        for (port, kind) in [(tls_port, Kind::Tls), (http_port, Kind::Http)] {
            let v4 = TcpListener::bind((Ipv4Addr::LOCALHOST, port))?;
            spawn_acceptor(v4, kind, shared.clone());
            // IPv6 may be disabled; that's fine.
            if let Ok(v6) = TcpListener::bind((Ipv6Addr::LOCALHOST, port)) {
                spawn_acceptor(v6, kind, shared.clone());
            }
        }
        Ok(Proxy { shared })
    }

    pub fn set_blocked(&self, domains: HashSet<String>) {
        *self
            .shared
            .blocked
            .write()
            .unwrap_or_else(|e| e.into_inner()) = Arc::new(domains);
    }

    pub fn refused(&self) -> u64 {
        self.shared.refused.load(Ordering::Relaxed)
    }
}

fn spawn_acceptor(listener: TcpListener, kind: Kind, shared: Arc<Shared>) {
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(conn) = conn else { continue };
            let shared = shared.clone();
            let _ = std::thread::Builder::new()
                .stack_size(256 * 1024)
                .spawn(move || {
                    let _ = handle(conn, kind, &shared);
                });
        }
    });
}

fn handle(mut client: TcpStream, kind: Kind, shared: &Shared) -> io::Result<()> {
    client.set_read_timeout(Some(Duration::from_secs(10)))?;
    client.set_nodelay(true).ok();
    let dst = original_dst(&client)?;
    if dst.ip().is_loopback() && (dst.port() == shared.ports.0 || dst.port() == shared.ports.1) {
        return Ok(()); // someone connected to the proxy directly
    }
    let (head, host) = match kind {
        Kind::Tls => read_client_hello(&mut client)?,
        Kind::Http => read_http_head(&mut client)?,
    };
    let blocked = shared
        .blocked
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    if let Some(host) = host.as_deref().filter(|h| is_blocked(h, &blocked)) {
        shared.refused.fetch_add(1, Ordering::Relaxed);
        if kind == Kind::Http {
            let _ = client.write_all(block_page(host).as_bytes());
        }
        let _ = client.shutdown(Shutdown::Both);
        return Ok(());
    }

    let mut upstream = connect_marked(dst)?;
    upstream.write_all(&head)?;
    client.set_read_timeout(None)?;
    relay(client, upstream);
    Ok(())
}

fn relay(client: TcpStream, upstream: TcpStream) {
    let (Ok(mut c2), Ok(mut u2)) = (client.try_clone(), upstream.try_clone()) else {
        return;
    };
    let t = std::thread::Builder::new()
        .stack_size(128 * 1024)
        .spawn(move || {
            let _ = io::copy(&mut u2, &mut c2);
            let _ = c2.shutdown(Shutdown::Write);
        });
    let (mut c, mut u) = (client, upstream);
    let _ = io::copy(&mut c, &mut u);
    let _ = u.shutdown(Shutdown::Write);
    if let Ok(t) = t {
        let _ = t.join();
    }
}

fn connect_marked(dst: SocketAddr) -> io::Result<TcpStream> {
    let socket = Socket::new(Domain::for_address(dst), Type::STREAM, Some(Protocol::TCP))?;
    // Needs CAP_NET_ADMIN; without it (e.g. unprivileged tests) the uid rule
    // is what keeps the connection from being redirected again.
    let _ = socket.set_mark(MARK);
    socket.connect_timeout(&SockAddr::from(dst), Duration::from_secs(10))?;
    let s: TcpStream = socket.into();
    s.set_nodelay(true).ok();
    Ok(s)
}

/// Where the client was originally connecting to before the redirect.
fn original_dst(s: &TcpStream) -> io::Result<SocketAddr> {
    const SO_ORIGINAL_DST: libc::c_int = 80; // same value for IPv4 and IPv6
    let fd = s.as_raw_fd();
    if s.local_addr()?.is_ipv4() {
        let mut addr = MaybeUninit::<libc::sockaddr_in>::zeroed();
        let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_IP,
                SO_ORIGINAL_DST,
                addr.as_mut_ptr().cast(),
                &mut len,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        let a = unsafe { addr.assume_init() };
        Ok(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::from(u32::from_be(a.sin_addr.s_addr)),
            u16::from_be(a.sin_port),
        )))
    } else {
        let mut addr = MaybeUninit::<libc::sockaddr_in6>::zeroed();
        let mut len = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_IPV6,
                SO_ORIGINAL_DST,
                addr.as_mut_ptr().cast(),
                &mut len,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        let a = unsafe { addr.assume_init() };
        Ok(SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::from(a.sin6_addr.s6_addr),
            u16::from_be(a.sin6_port),
            a.sin6_flowinfo,
            a.sin6_scope_id,
        )))
    }
}
