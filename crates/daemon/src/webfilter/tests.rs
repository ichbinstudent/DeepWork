use super::*;

/// Minimal but well-formed ClientHello with an SNI extension.
pub fn client_hello(sni: &str) -> Vec<u8> {
    let mut ext = Vec::new();
    // some unrelated extension first (supported_groups)
    ext.extend_from_slice(&[0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x1d]);
    let name = sni.as_bytes();
    let mut sn = Vec::new();
    sn.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
    sn.push(0);
    sn.extend_from_slice(&(name.len() as u16).to_be_bytes());
    sn.extend_from_slice(name);
    ext.extend_from_slice(&[0x00, 0x00]);
    ext.extend_from_slice(&(sn.len() as u16).to_be_bytes());
    ext.extend_from_slice(&sn);

    let mut body = vec![0x03, 0x03];
    body.extend_from_slice(&[7u8; 32]);
    body.push(32);
    body.extend_from_slice(&[9u8; 32]);
    body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
    body.extend_from_slice(&[0x01, 0x00]);
    body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext);

    let mut hs = vec![0x01];
    hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    hs.extend_from_slice(&body);
    let mut rec = vec![0x16, 0x03, 0x01];
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

#[test]
fn reads_sni() {
    let hello = client_hello("Www.Reddit.com");
    let (raw, sni) = read_client_hello(&mut hello.as_slice()).unwrap();
    assert_eq!(raw, hello);
    assert_eq!(sni.as_deref(), Some("www.reddit.com"));
}

#[test]
fn reads_fragmented_hello() {
    // split the handshake across two TLS records
    let hello = client_hello("example.org");
    let hs = &hello[5..];
    let (a, b) = hs.split_at(20);
    let mut two = vec![0x16, 0x03, 0x01];
    two.extend_from_slice(&(a.len() as u16).to_be_bytes());
    two.extend_from_slice(a);
    two.extend_from_slice(&[0x16, 0x03, 0x01]);
    two.extend_from_slice(&(b.len() as u16).to_be_bytes());
    two.extend_from_slice(b);
    let (raw, sni) = read_client_hello(&mut two.as_slice()).unwrap();
    assert_eq!(raw, two);
    assert_eq!(sni.as_deref(), Some("example.org"));
}

#[test]
fn garbage_is_not_a_hello() {
    let (_, sni) = read_client_hello(&mut &b"GET / HTTP/1.1\r\n\r\n"[..]).unwrap();
    assert_eq!(sni, None);
    assert_eq!(parse_sni(&[1, 0, 0, 3, 3, 3]), None);
}

fn blocked() -> HashSet<String> {
    ["reddit.com".to_string()].into()
}

/// Feed `input` in pieces of `step` bytes; returns what went through
/// and how it ended.
fn gate(input: &[u8], step: usize) -> (Vec<u8>, Result<(), Stop>) {
    let mut g = HttpGate::default();
    let mut out = vec![];
    for piece in input.chunks(step.max(1)) {
        if let Err(e) = g.feed(piece, &blocked(), &mut out) {
            return (out, Err(e));
        }
    }
    (out, Ok(()))
}

#[test]
fn reads_http_host() {
    let req = b"GET /r/rust HTTP/1.1\r\nUser-Agent: x\r\nHOST: Reddit.com:8080\r\n\r\n";
    assert_eq!(gate(req, 100).1, Err(Stop::Blocked("reddit.com".into())));
    let ok = b"GET / HTTP/1.1\r\nHost: example.org:8080\r\n\r\n";
    assert_eq!(gate(ok, 100), (ok.to_vec(), Ok(())));
}

/// Every request on a connection is checked, however the bytes arrive.
#[test]
fn every_request_is_checked() {
    let allowed = "GET / HTTP/1.1\r\nHost: example.org\r\n\r\n";
    let post = "POST /f HTTP/1.1\r\nHost: example.org\r\nContent-Length: 5\r\n\r\nhello";
    let chunked = "POST /c HTTP/1.1\r\nHost: example.org\r\nTransfer-Encoding: chunked\r\n\r\n\
                   5;x=1\r\nhello\r\n0\r\nX-T: 1\r\n\r\n";
    let evil = "GET / HTTP/1.1\r\nHost: old.reddit.com\r\n\r\n";
    for step in [1, 3, 7, 1000] {
        let fine = format!("{allowed}{post}{chunked}{allowed}");
        assert_eq!(
            gate(fine.as_bytes(), step),
            (fine.clone().into_bytes(), Ok(()))
        );
        let (out, end) = gate(format!("{allowed}{post}{evil}{allowed}").as_bytes(), step);
        assert_eq!(end, Err(Stop::Blocked("old.reddit.com".into())));
        assert_eq!(out, format!("{allowed}{post}").into_bytes());
        // After a chunked body, the next request is checked too.
        let (_, end) = gate(format!("{chunked}{evil}").as_bytes(), step);
        assert_eq!(end, Err(Stop::Blocked("old.reddit.com".into())), "{step}");
    }
    // The absolute form names the site too.
    let proxy = "GET http://www.reddit.com/ HTTP/1.1\r\nHost: example.org\r\n\r\n";
    assert_eq!(
        gate(proxy.as_bytes(), 9).1,
        Err(Stop::Blocked("www.reddit.com".into()))
    );
}

/// Requests a server might read differently from the filter are refused.
#[test]
fn ambiguous_requests_are_refused() {
    for bad in [
        "GET / HTTP/1.1\r\n\r\n",                                     // no site
        "GET / HTTP/1.1\r\nHost: a.org\r\nHost: reddit.com\r\n\r\n",  // two
        "GET / HTTP/1.1\r\nHost: a.org\r\n Host: reddit.com\r\n\r\n", // folded
        "GET / HTTP/1.1\r\nHost : a.org\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: a.org\nHost: reddit.com\r\n\r\n", // bare LF
        "POST / HTTP/1.1\r\nHost: a.org\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n",
        "POST / HTTP/1.1\r\nHost: a.org\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\n",
        "POST / HTTP/1.1\r\nHost: a.org\r\nContent-Length: +3\r\n\r\n",
        "POST / HTTP/1.1\r\nHost: a.org\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
        "POST / HTTP/1.1\r\nHost: a.org\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n",
        "CONNECT reddit.com:443 HTTP/1.1\r\nHost: a.org\r\n\r\n",
        "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
        "\x16\x03\x01\x00\x05hello\r\n\r\n",
    ] {
        assert_eq!(gate(bad.as_bytes(), 1000).1, Err(Stop::Invalid), "{bad:?}");
    }
    // A head that never ends.
    let long = format!("GET / HTTP/1.1\r\nX: {}", "a".repeat(MAX_HTTP_HEAD + 10));
    assert_eq!(gate(long.as_bytes(), 1000).1, Err(Stop::Invalid));
}

/// WebSocket is followed only when the server agrees; other upgrades
/// (h2c) are taken out of the request.
#[test]
fn upgrades() {
    let ws = "GET /chat HTTP/1.1\r\nHost: example.org\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n";
    let evil = "GET / HTTP/1.1\r\nHost: reddit.com\r\n\r\n";
    let mut g = HttpGate::default();
    let mut out = vec![];
    g.feed(format!("{ws}{evil}").as_bytes(), &blocked(), &mut out)
        .unwrap();
    assert_eq!(out, ws.as_bytes());
    assert!(g.awaiting_upgrade());
    // Refused by the server: the next request is checked.
    let mut more = vec![];
    let end = g.upgrade_answered(false, &blocked(), &mut more);
    assert_eq!(end, Err(Stop::Blocked("reddit.com".into())));
    assert!(more.is_empty());
    // Accepted: what follows is WebSocket data.
    let mut g = HttpGate::default();
    let mut out = vec![];
    g.feed(
        format!("{ws}\x01\x05hello").as_bytes(),
        &blocked(),
        &mut out,
    )
    .unwrap();
    g.upgrade_answered(true, &blocked(), &mut out).unwrap();
    assert_eq!(out, format!("{ws}\x01\x05hello").as_bytes());
    // Not on a connection that was used already.
    let first = "GET / HTTP/1.1\r\nHost: example.org\r\n\r\n";
    assert_eq!(
        gate(format!("{first}{ws}").as_bytes(), 1000).1,
        Err(Stop::Invalid)
    );
    // h2c is dropped from the request.
    let h2c = "GET / HTTP/1.1\r\nHost: example.org\r\nConnection: Upgrade, HTTP2-Settings\r\n\
               Upgrade: h2c\r\nHTTP2-Settings: AAMAAABkAAQAAP__\r\n\r\n";
    let (out, end) = gate(h2c.as_bytes(), 1000);
    assert_eq!(end, Ok(()));
    let out = String::from_utf8(out).unwrap();
    assert!(!out.contains("h2c") && !out.contains("AAMA") && out.ends_with("\r\n\r\n"));
}

#[test]
fn suffix_matching() {
    let set: HashSet<String> = ["reddit.com".to_string()].into();
    assert!(is_blocked("reddit.com", &set));
    assert!(is_blocked("old.reddit.com.", &set));
    assert!(!is_blocked("notreddit.com", &set));
    assert!(!is_blocked("com", &set));
}

/// A request whose site doesn't lead where the connection goes is refused,
/// on later requests too.
#[test]
fn requests_must_reach_their_site() {
    struct OnlyExample;
    impl Sites for OnlyExample {
        fn blocked(&self, host: &str) -> bool {
            host == "reddit.com"
        }
        fn reaches(&self, host: &str) -> bool {
            host == "example.org"
        }
    }
    let ok = "GET / HTTP/1.1\r\nHost: example.org\r\n\r\n";
    let elsewhere = "GET / HTTP/1.1\r\nHost: other.example\r\n\r\n";
    let mut g = HttpGate::default();
    let mut out = vec![];
    g.feed(ok.as_bytes(), &OnlyExample, &mut out).unwrap();
    assert_eq!(g.first_hosts(), ["example.org"]);
    let end = g.feed(elsewhere.as_bytes(), &OnlyExample, &mut out);
    assert_eq!(end, Err(Stop::Invalid));
    assert_eq!(out, ok.as_bytes());
    // Absolute form counts too.
    let mut g = HttpGate::default();
    let sneaky = "GET http://other.example/ HTTP/1.1\r\nHost: example.org\r\n\r\n";
    assert_eq!(
        g.feed(sneaky.as_bytes(), &OnlyExample, &mut vec![]),
        Err(Stop::Invalid)
    );
}
