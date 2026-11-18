//! Request handling for one client connection. The transport (Unix socket,
//! named pipe) comes from the platform, see [`crate::platform::serve`].

use std::io::{BufRead, BufReader, Read, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use deepwork_core::protocol::{Request, Response};
use serde::Deserialize;

use crate::state::Daemon;

/// An entry of `allowed_users` in config.json: a Unix user id, or on
/// Windows a full SID ("S-1-5-21-...").
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
pub enum UserId {
    Uid(u32),
    Sid(String),
}

/// Who is connecting, as the operating system reports it (never taken from
/// anything the client sends).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Caller {
    /// root, SYSTEM or an elevated administrator.
    Admin,
    #[cfg_attr(windows, allow(dead_code))]
    Uid(u32),
    #[cfg_attr(not(windows), allow(dead_code))]
    Sid(String),
}

/// Whether `caller` may control the service. Administrators always may;
/// `allowed = None` lets everyone in.
pub fn permitted(caller: Option<&Caller>, allowed: Option<&[UserId]>) -> bool {
    match (caller, allowed) {
        (None, _) => false,
        (Some(Caller::Admin), _) => true,
        (Some(_), None) => true,
        (Some(Caller::Uid(uid)), Some(list)) => list.contains(&UserId::Uid(*uid)),
        (Some(Caller::Sid(sid)), Some(list)) => list
            .iter()
            .any(|a| matches!(a, UserId::Sid(s) if s.eq_ignore_ascii_case(sid))),
    }
}

/// Requests longer than this are refused (blocks with thousands of sites
/// stay far below it).
const MAX_REQUEST: usize = 4 << 20;
/// Connections served at the same time; more are closed right away.
const MAX_CONNECTIONS: usize = 64;
static CONNECTIONS: AtomicUsize = AtomicUsize::new(0);

/// A place among the [`MAX_CONNECTIONS`]; freed when dropped.
pub struct Slot(());

impl Slot {
    pub fn take() -> Option<Slot> {
        let n = CONNECTIONS.fetch_add(1, Ordering::SeqCst);
        if n >= MAX_CONNECTIONS {
            CONNECTIONS.fetch_sub(1, Ordering::SeqCst);
            eprintln!("deepwork: too many connections, refusing one");
            return None;
        }
        Some(Slot(()))
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        CONNECTIONS.fetch_sub(1, Ordering::SeqCst);
    }
}

fn send(writer: &mut impl Write, resp: &Response) -> bool {
    let mut out = serde_json::to_vec(resp).unwrap_or_default();
    out.push(b'\n');
    writer.write_all(&out).is_ok()
}

/// Answer newline-delimited JSON requests until the client disconnects.
/// Callers that aren't permitted get one refusal and are disconnected.
pub fn handle_conn(
    reader: impl Read,
    mut writer: impl Write,
    daemon: Arc<Mutex<Daemon>>,
    permitted: bool,
) {
    if !permitted {
        send(
            &mut writer,
            &Response::err("You are not allowed to control DeepWork on this computer"),
        );
        return;
    }
    let mut reader = BufReader::new(reader);
    let mut line = Vec::new();
    loop {
        line.clear();
        match (&mut reader)
            .take(MAX_REQUEST as u64 + 1)
            .read_until(b'\n', &mut line)
        {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        if line.len() > MAX_REQUEST {
            send(&mut writer, &Response::err("Request too large"));
            break;
        }
        let Ok(text) = std::str::from_utf8(&line) else {
            send(&mut writer, &Response::err("Bad request: not UTF-8"));
            break;
        };
        if text.trim().is_empty() {
            continue;
        }
        let resp = match serde_json::from_str::<Request>(text) {
            Ok(req) => {
                let now = deepwork_core::now();
                daemon
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .handle(req, now)
            }
            Err(e) => Response::err(format!("Bad request: {e}")),
        };
        if !send(&mut writer, &resp) {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
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
}
