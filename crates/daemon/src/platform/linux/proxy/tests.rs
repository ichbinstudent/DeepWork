use super::*;

const LOCAL: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

fn shared() -> Arc<Shared> {
    let shared = Shared::new(vec![], 4);
    *shared.blocked.write().unwrap() = Arc::new(["reddit.com".to_string()].into());
    Arc::new(shared)
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
    gate.feed(first.as_bytes(), &*shared.blocked(), &mut out)
        .unwrap();
    (&upstream).write_all(&out).unwrap();
    let s = shared.clone();
    let hosts = gate.first_hosts().to_vec();
    // example.org's requests may go to 127.0.0.1 here.
    s.names.has_with("example.org", LOCAL, |_| vec![LOCAL]);
    std::thread::spawn(move || relay(client, upstream, Some(gate), LOCAL, hosts, &s));
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
    // One user gets 3 of the 4: never all of them.
    let a = Slot::take(&shared, 1000).unwrap();
    let _b = Slot::take(&shared, 1000).unwrap();
    let _c = Slot::take(&shared, 1000).unwrap();
    assert!(Slot::take(&shared, 1000).is_none());
    let _d = Slot::take(&shared, 1001).unwrap();
    assert!(Slot::take(&shared, 1001).is_none());
    drop(a);
    assert!(Slot::take(&shared, 1000).is_some());
}

#[test]
fn finds_whose_a_connection_is() {
    let table = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0277 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1
   1: 0500000A:CB38 0100A8C0:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 2 1
";
    let from: SocketAddr = "10.0.0.5:52024".parse().unwrap();
    let to: SocketAddr = "192.168.0.1:443".parse().unwrap();
    let other: SocketAddr = "192.168.0.2:443".parse().unwrap();
    if cfg!(target_endian = "little") {
        assert_eq!(owner::owner_in(table, from, to), Some(1000));
        assert_eq!(owner::owner_in(table, from, other), None);
    }

    // A real connection, over IPv4 and IPv6.
    let me = unsafe { libc::getuid() };
    for at in ["127.0.0.1:0", "[::1]:0"] {
        let Ok(l) = TcpListener::bind(at) else {
            continue;
        };
        let c = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let found = owner::owner(c.local_addr().unwrap(), c.peer_addr().unwrap());
        assert_eq!(found, Some(me), "{at}");
    }
}

#[test]
fn names_must_lead_to_the_address() {
    let names = Names::default();
    let ip = |s: &str| s.parse::<IpAddr>().unwrap();
    let lookups = std::cell::Cell::new(0);
    let resolve = |_: &str| {
        lookups.set(lookups.get() + 1);
        vec![ip("192.0.2.1"), ip("2001:db8::1")]
    };
    assert!(names.has_with("example.org", ip("192.0.2.1"), resolve));
    assert!(names.has_with("example.org", ip("::ffff:192.0.2.1"), resolve));
    assert!(names.has_with("example.org", ip("2001:db8::1"), resolve));
    assert_eq!(lookups.get(), 1);
    // Another address: looked up again, but not over and over.
    assert!(!names.has_with("example.org", ip("198.51.100.7"), resolve));
    assert!(!names.has_with("example.org", ip("198.51.100.7"), resolve));
    assert_eq!(lookups.get(), 1);

    let shared = shared();
    // The system's resolver.
    assert!(shared.leads_to("localhost", LOCAL, false));
    assert!(!shared.leads_to("localhost", ip("192.0.2.1"), false));
    assert!(!shared.leads_to("no-such-name.invalid", ip("192.0.2.1"), false));
    // Addresses as names: HTTPS never, plain HTTP on a local network only.
    assert!(!shared.leads_to("192.168.1.1", ip("192.168.1.1"), false));
    assert!(shared.leads_to("192.168.1.1", ip("192.168.1.1"), true));
    assert!(shared.leads_to("[fe80::1]", ip("fe80::1"), true));
    assert!(!shared.leads_to("192.168.1.1", ip("192.168.1.2"), true));
    assert!(!shared.leads_to("203.0.113.9", ip("203.0.113.9"), true));
    // Nor in the other spellings the system's resolver takes.
    for other in ["2130706433", "0x7f000001", "127.1", "0177.0.0.1"] {
        for by_address in [false, true] {
            assert!(!shared.leads_to(other, LOCAL, by_address), "{other}");
        }
    }
}

#[test]
fn host_names_and_addresses() {
    for name in [
        "example.com",
        "example.com.",
        "localhost",
        "a_b.example.com",
        "xn--bcher-kva.example",
        "1.example",
        "4chan.org",
        "0xabc.example",
        "1e100.net",
    ] {
        assert!(sites::is_name(name), "{name}");
    }
    for address in [
        "",
        ".",
        "16843009",
        "0x1010101",
        "0x",
        "1.65793",
        "example.1",
        "1.1.1.1.",
        "fe80::1%eth0",
        "[fe80::1%25eth0]",
        "a b.example",
    ] {
        assert!(!sites::is_name(address), "{address}");
    }
}

#[test]
fn local_networks() {
    for local in [
        "10.1.2.3",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.0.1",
        "100.100.1.1",
        "fd00::1",
        "fe80::1",
    ] {
        assert!(sites::local_network(local.parse().unwrap()), "{local}");
    }
    for public in ["8.8.8.8", "100.128.0.1", "2001:4860::8888", "203.0.113.9"] {
        assert!(!sites::local_network(public.parse().unwrap()), "{public}");
    }
}

/// A connection is closed when its site gets blocked, wherever it goes.
#[test]
fn relays_end_when_their_site_is_blocked() {
    let shared = shared();
    let (browser, client) = pair();
    let (upstream, server) = pair();
    let s = shared.clone();
    let done = std::thread::spawn(move || {
        relay(
            client,
            upstream,
            None,
            LOCAL,
            vec!["news.example".into()],
            &s,
        )
    });
    (&browser).write_all(b"hello").unwrap();
    let mut buf = [0u8; 5];
    (&server).read_exact(&mut buf).unwrap();
    let proxy = Proxy {
        shared: shared.clone(),
        ports: FilterPorts {
            v4: (0, 0),
            v6: None,
        },
    };
    proxy.set_blocked(["reddit.com".into(), "example".into()].into());
    done.join().unwrap();
    assert!(drain(&browser).is_empty());
    assert!(shared.relays().is_empty());
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
