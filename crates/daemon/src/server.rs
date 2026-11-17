//! Request handling for one client connection. The transport (Unix socket,
//! named pipe) comes from the platform, see [`crate::platform::serve`].

use std::io::{BufRead, BufReader, Read, Write};
use std::sync::{Arc, Mutex};

use deepwork_core::protocol::{Request, Response};

use crate::state::Daemon;

/// Whether a caller with this user id may control the daemon. Root always
/// may; `allowed = None` lets everyone in.
pub fn permitted(uid: Option<u32>, allowed: Option<&[u32]>) -> bool {
    match (uid, allowed) {
        (Some(0), _) => true,
        (Some(uid), Some(list)) => list.contains(&uid),
        (Some(_), None) => true,
        (None, _) => false,
    }
}

/// Answer newline-delimited JSON requests until the client disconnects.
pub fn handle_conn(
    reader: impl Read,
    mut writer: impl Write,
    daemon: Arc<Mutex<Daemon>>,
    permitted: bool,
) {
    for line in BufReader::new(reader).lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        let resp = if !permitted {
            Response::err("You are not allowed to control DeepWork on this computer")
        } else {
            match serde_json::from_str::<Request>(&line) {
                Ok(req) => {
                    let now = deepwork_core::now();
                    daemon
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .handle(req, now)
                }
                Err(e) => Response::err(format!("Bad request: {e}")),
            }
        };
        let mut out = serde_json::to_vec(&resp).unwrap_or_default();
        out.push(b'\n');
        if writer.write_all(&out).is_err() {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn who_may_connect() {
        assert!(permitted(Some(0), Some(&[])));
        assert!(permitted(Some(1000), Some(&[1000])));
        assert!(!permitted(Some(1001), Some(&[1000])));
        assert!(permitted(Some(1001), None));
        assert!(!permitted(None, None));
    }
}
