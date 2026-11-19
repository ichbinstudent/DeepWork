use super::*;

fn shared() -> Arc<Shared> {
    Arc::new(Shared {
        blocked: RwLock::new(Arc::new(["reddit.com".to_string()].into())),
        refused: AtomicU64::new(0),
        ports: vec![],
        active: AtomicUsize::new(0),
        max: 2,
        names: Mutex::new(HashMap::new()),
    })
}

/// A connected pair of sockets.
fn pair() -> (TcpStream, TcpStream) {
    let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let a = TcpStream::connect(l.local_addr().unwrap()).unwrap();
    (a, l.accept().unwrap().0)
}

/// Everything `s` receives until the other side closes or goes quiet.
fn drain(s: &TcpStream) -> Vec<u8> {
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut all = vec![];
    let _ = (&*s).read_to_end(&mut all);
    all
}

/// Relay a plain-HTTP connection whose first request (`first`) went
/// through; returns the browser's socket and the server's.
fn http_relay(first: &str) -> (TcpStream, TcpStream, Arc<Shared>) {
    let shared = shared();
    let (browser, client) = pair();
    let (upstream, server) = pair();
    let mut gate = HttpGate::default();
    let mut out = vec![];
    gate.feed(first.as_bytes(), &shared.blocked(), &mut out)
        .unwrap();
    (&upstream).write_all(&out).unwrap();
    let s = shared.clone();
    std::thread::spawn(move || relay(client, upstream, Some(gate), &s));
    (browser, server, shared)
}

#[test]
fn later_requests_on_a_connection_are_checked() {
    let ok = "GET / HTTP/1.1\r\nHost: example.org\r\n\r\n";
    let (browser, server, shared) = http_relay(ok);
    (&browser)
        .write_all(b"GET / HTTP/1.1\r\nHost: old.reddit.com\r\n\r\n")
        .unwrap();
    assert_eq!(drain(&server), ok.as_bytes(), "only the allowed request");
    assert_eq!(shared.refused.load(Ordering::Relaxed), 1);
}

#[test]
fn websocket_follows_the_servers_answer() {
    let ws = "GET /chat HTTP/1.1\r\nHost: example.org\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n";
    // Accepted: frames pass both ways.
    let (browser, server, _) = http_relay(ws);
    (&server)
        .write_all(b"HTTP/1.1 101 Switching Protocols\r\n\r\n")
        .unwrap();
    (&browser).write_all(b"\x01frame").unwrap();
    let mut buf = [0u8; 64];
    server
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut got = vec![];
    while got.len() < ws.len() + 6 {
        let n = (&server).read(&mut buf).unwrap();
        assert!(n > 0);
        got.extend_from_slice(&buf[..n]);
    }
    assert_eq!(got, format!("{ws}\x01frame").as_bytes());

    // Refused: what follows must be checked requests again.
    let (browser, server, _) = http_relay(ws);
    (&browser)
        .write_all(b"GET / HTTP/1.1\r\nHost: reddit.com\r\n\r\n")
        .unwrap();
    (&server).write_all(b"HTTP/1.1 400 Nope\r\n\r\n").unwrap();
    assert_eq!(drain(&server), ws.as_bytes());
}

#[test]
fn connections_beyond_the_limit_are_refused() {
    let shared = shared();
    let a = Slot::take(&shared).unwrap();
    let _b = Slot::take(&shared).unwrap();
    assert!(Slot::take(&shared).is_none());
    drop(a);
    assert!(Slot::take(&shared).is_some());
}

#[test]
fn listens_on_free_ports() {
    let p = Proxy::start(0, 0).unwrap();
    let ports = p.ports();
    assert_ne!(ports.v4.0, 0);
    assert_ne!(ports.v4.0, ports.v4.1);
    // Another program can't take them, and can't have taken them before.
    assert!(TcpListener::bind((Ipv4Addr::LOCALHOST, ports.v4.0)).is_err());
    if let Some((tls, _)) = ports.v6 {
        assert!(TcpListener::bind((Ipv6Addr::LOCALHOST, tls)).is_err());
    }
    // An occupied port is an error, not a filter quietly missing.
    let taken = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = taken.local_addr().unwrap().port();
    assert!(Proxy::start(port, 0).is_err());
}

/// The site name is all the filter sees, so an allowed name sent to some
/// other address (a blocked site's) goes to the allowed site instead.
#[test]
fn https_goes_where_the_name_leads() {
    let addr = |s: &str| s.parse::<SocketAddr>().unwrap();
    let ip = |s: &str| s.parse::<IpAddr>().unwrap();
    let site = [ip("192.0.2.1"), ip("192.0.2.2"), ip("2001:db8::1")];
    // Sent to one of the name's addresses: kept.
    assert_eq!(
        upstream(addr("192.0.2.2:443"), &site),
        Some(addr("192.0.2.2:443"))
    );
    assert_eq!(
        upstream(addr("[2001:db8::1]:443"), &site),
        Some(addr("[2001:db8::1]:443"))
    );
    // Sent elsewhere: to the name's own address, same IP version first.
    assert_eq!(
        upstream(addr("198.51.100.9:443"), &site),
        Some(addr("192.0.2.1:443"))
    );
    assert_eq!(
        upstream(addr("[2001:db8::99]:8443"), &site),
        Some(addr("[2001:db8::1]:8443"))
    );
    assert_eq!(
        upstream(addr("198.51.100.9:443"), &[ip("2001:db8::1")]),
        Some(addr("[2001:db8::1]:443"))
    );
    // A name without an address is refused.
    assert_eq!(upstream(addr("198.51.100.9:443"), &[]), None);
}

#[test]
fn looks_names_up() {
    let shared = shared();
    let ips = addresses(&shared, "localhost", 443);
    assert!(ips.iter().all(IpAddr::is_loopback) && !ips.is_empty());
    assert!(addresses(&shared, "no-such-name.invalid", 443).is_empty());
    assert_eq!(shared.names.lock().unwrap().len(), 1);
}
