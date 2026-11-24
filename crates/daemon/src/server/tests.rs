use super::*;

#[test]
fn who_may_connect() {
    let uid = |u| Some(Caller::Uid(u));
    assert!(permitted(Some(&Caller::Admin), Some(&[])));
    assert!(permitted(uid(1000).as_ref(), Some(&[UserId::Uid(1000)])));
    assert!(!permitted(uid(1001).as_ref(), Some(&[UserId::Uid(1000)])));
    assert!(permitted(uid(1001).as_ref(), None));
    assert!(!permitted(None, None));

    // Windows: the whole SID counts, not just its last number.
    let me = "S-1-5-21-1-2-3-1001";
    let allowed: Vec<UserId> = serde_json::from_str(&format!("[\"{me}\", 1000]")).unwrap();
    assert!(permitted(
        Some(&Caller::Sid(me.to_lowercase())),
        Some(&allowed)
    ));
    assert!(!permitted(
        Some(&Caller::Sid("S-1-5-21-9-9-9-1001".into())),
        Some(&allowed)
    ));
    assert!(!permitted(
        Some(&Caller::Sid("S-1-5-21-1-2-3-1000".into())),
        Some(&allowed)
    ));
}

/// Garbage and mangled requests get answers, never a crash, and the
/// service keeps working.
#[test]
fn survives_garbage_and_mangled_requests() {
    use deepwork_core::protocol::Capabilities;
    let daemon = Arc::new(Mutex::new(Daemon::new(
        crate::state::Persisted::default(),
        String::new(),
        Capabilities::all("test"),
    )));
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut next = move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let samples = [
        r#"{"cmd":"create_block","config":{"name":"x","websites":["a.com"],"lock":"strict"},"password":null}"#,
        r#"{"cmd":"update_block","id":"x","config":{"name":"y","apps":["firefox"]},"password":"p"}"#,
        r#"{"cmd":"start_block","id":"x","minutes":5}"#,
        r#"{"cmd":"unlock","id":"x","response":"abc"}"#,
        r#"{"cmd":"take_break","id":"x","minutes":4294967295}"#,
        r#"{"cmd":"set_settings","settings":{}}"#,
        r#"{"cmd":"freeze","minutes":1}"#,
        r#"{"cmd":"events","since":0}"#,
        r#"{"cmd":"stats","days":4000000000}"#,
    ];
    let junk = b"{}[]\":,0123456789-.eE ntrufalsxyz\\\x00\xff\n";
    for i in 0..3_000 {
        let mut req: Vec<u8> = if i % 3 == 0 {
            (0..next() % 120).map(|_| (next() % 256) as u8).collect()
        } else {
            let mut r = samples[(next() % samples.len() as u64) as usize]
                .as_bytes()
                .to_vec();
            for _ in 0..1 + next() % 4 {
                let at = (next() % r.len() as u64) as usize;
                r[at] = junk[(next() % junk.len() as u64) as usize];
            }
            r
        };
        req.push(b'\n');
        let mut out = Vec::new();
        handle_conn(&req[..], &mut out, daemon.clone(), true);
    }
    // Real requests with silly values are answered too.
    for s in samples {
        let mut out = Vec::new();
        handle_conn(format!("{s}\n").as_bytes(), &mut out, daemon.clone(), true);
        assert!(!out.is_empty(), "{s}");
    }
    let mut out = Vec::new();
    handle_conn(&b"{\"cmd\":\"status\"}\n"[..], &mut out, daemon, true);
    assert!(String::from_utf8_lossy(&out).contains("\"ok\":true"));
}

#[test]
fn refuses_strangers_and_huge_requests() {
    use deepwork_core::protocol::Capabilities;
    let daemon = Arc::new(Mutex::new(Daemon::new(
        crate::state::Persisted::default(),
        String::new(),
        Capabilities::all("test"),
    )));
    // Not permitted: one refusal, without waiting for a request.
    let mut out = Vec::new();
    handle_conn(std::io::empty(), &mut out, daemon.clone(), false);
    assert!(String::from_utf8_lossy(&out).contains("not allowed"));

    let mut out = Vec::new();
    let huge = vec![b'x'; MAX_REQUEST + 10];
    handle_conn(&huge[..], &mut out, daemon.clone(), true);
    assert!(String::from_utf8_lossy(&out).contains("too large"));

    let mut out = Vec::new();
    handle_conn(&b"{\"cmd\":\"ping\"}\n"[..], &mut out, daemon, true);
    assert!(String::from_utf8_lossy(&out).contains("\"ok\":true"));
}

/// One user can't keep other users out, and users can't keep administrators
/// out.
#[test]
fn connections_are_shared_fairly() {
    let slots: &'static Slots = Box::leak(Box::new(Slots::new()));
    let take = |caller: &Caller| slots.take(caller);
    let mut held = vec![];
    for _ in 0..MAX_PER_USER {
        held.push(take(&Caller::Uid(1)).unwrap());
    }
    assert!(take(&Caller::Uid(1)).is_none());
    assert!(take(&Caller::Sid("S-1-5-21-1".into())).is_some());
    held.pop();
    held.push(take(&Caller::Uid(1)).unwrap());

    let mut uid = 2;
    while let Some(slot) = take(&Caller::Uid(uid)) {
        held.push(slot);
        uid += 1;
    }
    assert_eq!(held.len(), MAX_CONNECTIONS - KEPT_FOR_ADMINS);
    for _ in 0..KEPT_FOR_ADMINS {
        held.push(take(&Caller::Admin).unwrap());
    }
    assert!(take(&Caller::Admin).is_none());
    drop(held);
    assert!(slots.0.lock().unwrap().is_empty());
}
