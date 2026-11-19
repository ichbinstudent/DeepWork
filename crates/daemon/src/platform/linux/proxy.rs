//! Transparent HTTPS/HTTP filter (Linux).
//!
//! nftables redirects user web traffic (TCP 443/80) to these listeners,
//! which find the original destination with `SO_ORIGINAL_DST`. The site name
//! is read by [`crate::webfilter`]. Nothing is decrypted. Blocked
//! connections are closed (HTTPS) or answered with a small block page
//! (HTTP); everything else is connected and relayed. Plain HTTP is checked
//! request by request, and goes to the original destination. HTTPS goes
//! where its site name leads: the name is all the filter sees, so an
//! allowed name sent to a blocked site's address reaches the allowed site.
//!
//! The filter fails closed: a connection that doesn't name its site (TLS
//! without SNI, e.g. to a bare IP address), a request it can't read, and
//! connections beyond its limit are refused, never passed on unchecked.

use std::collections::{HashMap, HashSet};
use std::io::{self, Read, Write};
use std::mem::MaybeUninit;
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, SocketAddrV4, SocketAddrV6, TcpListener,
    TcpStream, ToSocketAddrs,
};
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock, mpsc};
use std::time::{Duration, Instant};

use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use super::netfilter::FilterPorts;
use crate::webfilter::{HttpGate, Stop, block_page, is_blocked, read_client_hello};

/// Mark set on the proxy's own outgoing connections so the firewall never
/// redirects them back to the proxy.
pub const MARK: u32 = 0x4457;

/// Time a client gets to say which site it wants.
const HANDSHAKE: Duration = Duration::from_secs(10);
/// A connection with no traffic either way for this long is closed.
const IDLE: Duration = Duration::from_secs(10 * 60);
/// How often a waiting relay checks whether its connection went idle.
const POLL: Duration = Duration::from_secs(30);
/// How long the addresses of a site name are reused.
const NAME_TTL: Duration = Duration::from_secs(60);
/// Site names remembered at most; past that the list starts over.
const NAMES_MAX: usize = 1024;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    Tls,
    Http,
}

struct Shared {
    blocked: RwLock<Arc<HashSet<String>>>,
    refused: AtomicU64,
    /// Our own listening ports (connections to them aren't relayed).
    ports: Vec<u16>,
    /// Connections being handled, and how many may be.
    active: AtomicUsize,
    max: usize,
    names: Mutex<HashMap<String, Lookup>>,
}

/// When a site name was looked up, and its addresses.
type Lookup = (Instant, Arc<[IpAddr]>);

impl Shared {
    fn blocked(&self) -> Arc<HashSet<String>> {
        self.blocked
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

#[derive(Clone)]
pub struct Proxy {
    shared: Arc<Shared>,
    ports: FilterPorts,
}

/// Whether binding failed because this system has no IPv6 loopback.
fn no_ipv6(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::AddrNotAvailable || e.raw_os_error() == Some(libc::EAFNOSUPPORT)
}

/// How many connections may be relayed at once: each takes two open files
/// and two threads. Leaves room for the service's other files.
fn max_connections() -> usize {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: valid pointer to an rlimit.
    let files = if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } == 0 {
        usize::try_from(limit.rlim_cur).unwrap_or(usize::MAX)
    } else {
        1024
    };
    (files.saturating_sub(256) / 2).clamp(32, 4096)
}

impl Proxy {
    /// Bind the listeners on 127.0.0.1 and ::1 and start accepting. Port 0
    /// (the default) takes any free port, so no other user can occupy the
    /// filter's ports beforehand.
    pub fn start(tls_port: u16, http_port: u16) -> io::Result<Proxy> {
        let mut listeners = vec![];
        let mut v4 = [0u16; 2];
        let mut v6 = Some([0u16; 2]);
        for (i, (port, kind)) in [(tls_port, Kind::Tls), (http_port, Kind::Http)]
            .into_iter()
            .enumerate()
        {
            let l = TcpListener::bind((Ipv4Addr::LOCALHOST, port))?;
            v4[i] = l.local_addr()?.port();
            listeners.push((l, kind));
            match TcpListener::bind((Ipv6Addr::LOCALHOST, port)) {
                Ok(l) => {
                    if let Some(v6) = &mut v6 {
                        v6[i] = l.local_addr()?.port();
                    }
                    listeners.push((l, kind));
                }
                // No IPv6 here: the firewall refuses IPv6 web traffic instead.
                Err(e) if no_ipv6(&e) => v6 = None,
                Err(e) => return Err(e),
            }
        }
        let ports = FilterPorts {
            v4: (v4[0], v4[1]),
            v6: v6.map(|p| (p[0], p[1])),
        };
        let shared = Arc::new(Shared {
            blocked: RwLock::new(Arc::new(HashSet::new())),
            refused: AtomicU64::new(0),
            ports: listeners
                .iter()
                .filter_map(|(l, _)| l.local_addr().ok())
                .map(|a| a.port())
                .collect(),
            active: AtomicUsize::new(0),
            max: max_connections(),
            names: Mutex::new(HashMap::new()),
        });
        for (l, kind) in listeners {
            spawn_acceptor(l, kind, shared.clone());
        }
        Ok(Proxy { shared, ports })
    }

    /// Where the filter listens, for the firewall's redirect.
    pub fn ports(&self) -> FilterPorts {
        self.ports
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

/// One of the [`Shared::max`] connections; freed when dropped.
struct Slot(Arc<Shared>);

impl Slot {
    fn take(shared: &Arc<Shared>) -> Option<Slot> {
        if shared.active.fetch_add(1, Ordering::SeqCst) >= shared.max {
            shared.active.fetch_sub(1, Ordering::SeqCst);
            return None;
        }
        Some(Slot(shared.clone()))
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::SeqCst);
    }
}

fn spawn_acceptor(listener: TcpListener, kind: Kind, shared: Arc<Shared>) {
    std::thread::spawn(move || {
        let mut warned = false;
        for conn in listener.incoming() {
            let Ok(conn) = conn else {
                // Out of files or memory: don't spin.
                std::thread::sleep(Duration::from_millis(50));
                continue;
            };
            // Over the limit, the connection is closed: refused, not let through.
            let Some(slot) = Slot::take(&shared) else {
                if !warned {
                    eprintln!(
                        "deepwork: web filter busy ({} connections), refusing new ones",
                        shared.max
                    );
                    warned = true;
                }
                continue;
            };
            warned = false;
            let _ = std::thread::Builder::new()
                .stack_size(256 * 1024)
                .spawn(move || {
                    let shared = slot.0.clone();
                    let _ = handle(conn, kind, &shared);
                    drop(slot);
                });
        }
    });
}

/// Reads from a socket until `until`, then fails.
struct Deadline<'a> {
    socket: &'a TcpStream,
    until: Instant,
}

impl Read for Deadline<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let left = self
            .until
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or(io::ErrorKind::TimedOut)?;
        self.socket.set_read_timeout(Some(left))?;
        (&*self.socket).read(buf)
    }
}

fn refuse(client: &TcpStream, shared: &Shared, page: Option<&str>) {
    shared.refused.fetch_add(1, Ordering::Relaxed);
    if let Some(host) = page {
        let _ = (&*client).write_all(block_page(host).as_bytes());
    }
    let _ = client.shutdown(Shutdown::Both);
}

fn handle(client: TcpStream, kind: Kind, shared: &Shared) -> io::Result<()> {
    client.set_nodelay(true).ok();
    let dst = original_dst(&client)?;
    if dst.ip().is_loopback() && shared.ports.contains(&dst.port()) {
        return Ok(()); // someone connected to the proxy directly
    }
    let mut hello = Deadline {
        socket: &client,
        until: Instant::now() + HANDSHAKE,
    };
    match kind {
        Kind::Tls => {
            let (head, host) = read_client_hello(&mut hello)?;
            // Without a site name the filter can't tell which site this is.
            let blocked = shared.blocked();
            let Some(host) = host.filter(|h| !is_blocked(h, &blocked)) else {
                refuse(&client, shared, None);
                return Ok(());
            };
            let Some(target) = upstream(dst, &addresses(shared, &host, dst.port())) else {
                refuse(&client, shared, None);
                return Ok(());
            };
            let upstream = connect_marked(target)?;
            (&upstream).write_all(&head)?;
            relay(client, upstream, None, shared);
        }
        Kind::Http => {
            // The first request decides before anything is connected, so a
            // blocked site gets a block page instead.
            let mut gate = HttpGate::default();
            let mut out = vec![];
            let mut buf = [0u8; 4096];
            while !gate.started() {
                let n = hello.read(&mut buf)?;
                if n == 0 {
                    return Ok(());
                }
                match gate.feed(&buf[..n], &shared.blocked(), &mut out) {
                    Ok(()) => {}
                    Err(Stop::Blocked(host)) => {
                        refuse(&client, shared, Some(&host));
                        return Ok(());
                    }
                    Err(Stop::Invalid) => {
                        refuse(&client, shared, None);
                        return Ok(());
                    }
                }
            }
            let upstream = connect_marked(dst)?;
            (&upstream).write_all(&out)?;
            relay(client, upstream, Some(gate), shared);
        }
    }
    Ok(())
}

/// The addresses `host` has (looked up again after [`NAME_TTL`]).
fn addresses(shared: &Shared, host: &str, port: u16) -> Arc<[IpAddr]> {
    let names = || shared.names.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((at, ips)) = names().get(host)
        && at.elapsed() < NAME_TTL
    {
        return ips.clone();
    }
    let ips: Arc<[IpAddr]> = (host, port)
        .to_socket_addrs()
        .map(|addrs| {
            addrs
                .map(|a| a.ip().to_canonical())
                .filter(|ip| !ip.is_unspecified())
                .collect()
        })
        .unwrap_or_default();
    if !ips.is_empty() {
        let mut names = names();
        if names.len() >= NAMES_MAX {
            names.clear();
        }
        names.insert(host.to_string(), (Instant::now(), ips.clone()));
    }
    ips
}

/// Where an HTTPS connection for a site with addresses `ips` goes: where the
/// client sent it if that is one of them, otherwise to one of them (of the
/// same IP version if it has one). None: the name has no address.
fn upstream(dst: SocketAddr, ips: &[IpAddr]) -> Option<SocketAddr> {
    if ips.contains(&dst.ip().to_canonical()) {
        return Some(dst);
    }
    ips.iter()
        .find(|ip| ip.is_ipv4() == dst.is_ipv4())
        .or(ips.first())
        .map(|ip| SocketAddr::new(*ip, dst.port()))
}

/// When either direction of a connection last carried data.
struct Activity {
    start: Instant,
    last_ms: AtomicU64,
}

impl Activity {
    fn touch(&self) {
        let ms = self.start.elapsed().as_millis() as u64;
        self.last_ms.store(ms, Ordering::Relaxed);
    }

    fn idle(&self) -> bool {
        let ms = self.start.elapsed().as_millis() as u64;
        ms.saturating_sub(self.last_ms.load(Ordering::Relaxed)) > IDLE.as_millis() as u64
    }
}

/// Read some bytes, waking up now and then to see whether the whole
/// connection has gone idle. `Ok(0)`: the other side is done.
fn read_some(from: &TcpStream, buf: &mut [u8], activity: &Activity) -> io::Result<usize> {
    loop {
        match (&*from).read(buf) {
            Ok(n) => {
                activity.touch();
                return Ok(n);
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) =>
            {
                if activity.idle() {
                    return Err(io::ErrorKind::TimedOut.into());
                }
            }
            Err(e) => return Err(e),
        }
    }
}

/// Copy `from` to `to`. With `upgrade`, report whether the first answer
/// is `101 Switching Protocols`.
fn pump(
    from: &TcpStream,
    to: &TcpStream,
    activity: &Activity,
    mut upgrade: Option<mpsc::Sender<bool>>,
) -> io::Result<()> {
    let mut buf = vec![0u8; 16 * 1024];
    let mut first = Vec::new();
    loop {
        let n = read_some(from, &mut buf, activity)?;
        if n == 0 {
            return Ok(());
        }
        if let Some(tx) = &upgrade {
            first.extend_from_slice(&buf[..n.min(16)]);
            if first.len() >= 12 {
                let _ = tx
                    .send(first.starts_with(b"HTTP/1.1 101") || first.starts_with(b"HTTP/1.0 101"));
                upgrade = None;
            }
        }
        (&*to).write_all(&buf[..n])?;
    }
}

/// Copy the client's requests to the server through the gate.
fn pump_http(
    client: &TcpStream,
    upstream: &TcpStream,
    activity: &Activity,
    gate: &mut HttpGate,
    upgrade: Option<mpsc::Receiver<bool>>,
    shared: &Shared,
) -> io::Result<()> {
    let mut buf = vec![0u8; 16 * 1024];
    let mut out = Vec::new();
    loop {
        out.clear();
        let result = if gate.awaiting_upgrade() {
            let switched = upgrade
                .as_ref()
                .and_then(|rx| rx.recv_timeout(IDLE).ok())
                .ok_or(io::ErrorKind::TimedOut)?;
            gate.upgrade_answered(switched, &shared.blocked(), &mut out)
        } else {
            let n = read_some(client, &mut buf, activity)?;
            if n == 0 {
                return Ok(());
            }
            gate.feed(&buf[..n], &shared.blocked(), &mut out)
        };
        (&*upstream).write_all(&out)?;
        if let Err(stop) = result {
            // The client retries on a new connection, where it gets the
            // block page.
            if let Stop::Blocked(_) = stop {
                shared.refused.fetch_add(1, Ordering::Relaxed);
            }
            return Err(io::ErrorKind::PermissionDenied.into());
        }
    }
}

fn relay(client: TcpStream, upstream: TcpStream, gate: Option<HttpGate>, shared: &Shared) {
    for s in [&client, &upstream] {
        let _ = s.set_read_timeout(Some(POLL));
        // A peer that stops reading can't hold the connection forever.
        let _ = s.set_write_timeout(Some(IDLE));
    }
    let activity = Arc::new(Activity {
        start: Instant::now(),
        last_ms: AtomicU64::new(0),
    });
    let (tx, rx) = mpsc::channel();
    let watch = gate.as_ref().is_some_and(HttpGate::awaiting_upgrade);
    let (Ok(c2), Ok(u2)) = (client.try_clone(), upstream.try_clone()) else {
        return;
    };
    let act = activity.clone();
    let back = std::thread::Builder::new()
        .stack_size(128 * 1024)
        .spawn(move || {
            let result = pump(&u2, &c2, &act, watch.then_some(tx));
            match result {
                Ok(()) => {
                    let _ = c2.shutdown(Shutdown::Write);
                }
                Err(_) => {
                    let _ = c2.shutdown(Shutdown::Both);
                    let _ = u2.shutdown(Shutdown::Both);
                }
            }
        });
    if back.is_err() {
        return;
    }
    let result = match gate {
        Some(mut gate) => pump_http(&client, &upstream, &activity, &mut gate, Some(rx), shared),
        None => pump(&client, &upstream, &activity, None),
    };
    match result {
        Ok(()) => {
            let _ = upstream.shutdown(Shutdown::Write);
        }
        Err(_) => {
            let _ = client.shutdown(Shutdown::Both);
            let _ = upstream.shutdown(Shutdown::Both);
        }
    }
    if let Ok(t) = back {
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

#[cfg(test)]
mod tests;
