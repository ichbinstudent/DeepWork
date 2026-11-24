//! Request handling for one client connection. The transport (Unix socket,
//! named pipe) comes from the platform, see [`crate::platform::serve`].

use std::io::{BufRead, BufReader, Read, Write};
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
/// `allowed = None` lets everyone in (only for a sandbox without a config
/// file; a missing config file on a real system leaves only administrators
/// in).
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
/// How many of them one user may have (the app needs a few), so that a user
/// can't keep the others out.
const MAX_PER_USER: usize = 16;
/// How many are kept for administrators, however many users there are.
const KEPT_FOR_ADMINS: usize = 8;

/// The connections being served, by caller.
pub struct Slots(Mutex<Vec<Caller>>);

static SLOTS: Slots = Slots::new();

/// A place among the [`MAX_CONNECTIONS`]; freed when dropped.
pub struct Slot {
    slots: &'static Slots,
    caller: Caller,
}

impl Slot {
    pub fn take(caller: &Caller) -> Option<Slot> {
        SLOTS.take(caller)
    }
}

impl Slots {
    const fn new() -> Slots {
        Slots(Mutex::new(Vec::new()))
    }

    fn take(&'static self, caller: &Caller) -> Option<Slot> {
        let mut taken = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let mut free = taken.len() < MAX_CONNECTIONS;
        if *caller != Caller::Admin {
            let users = taken.iter().filter(|c| **c != Caller::Admin).count();
            let mine = taken.iter().filter(|c| *c == caller).count();
            free &= mine < MAX_PER_USER && users < MAX_CONNECTIONS - KEPT_FOR_ADMINS;
        }
        if !free {
            eprintln!("deepwork: too many connections, refusing one");
            return None;
        }
        taken.push(caller.clone());
        Some(Slot {
            slots: self,
            caller: caller.clone(),
        })
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        let mut taken = self.slots.0.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(i) = taken.iter().position(|c| *c == self.caller) {
            taken.swap_remove(i);
        }
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
mod tests;
