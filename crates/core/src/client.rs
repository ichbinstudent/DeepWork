//! Blocking client for the daemon socket.

use std::io::{BufRead, BufReader, Write};

use serde::de::DeserializeOwned;

use crate::model::BlockConfig;
use crate::protocol::{Event, Request, Response, Stats, Status, socket_path};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientError {
    /// The daemon isn't running or the socket isn't accessible.
    Unavailable(String),
    /// The daemon refused the request.
    Refused(String),
    Protocol(String),
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::Unavailable(e) => write!(f, "DeepWork service unavailable: {e}"),
            ClientError::Refused(e) => f.write_str(e),
            ClientError::Protocol(e) => write!(f, "Protocol error: {e}"),
        }
    }
}

impl std::error::Error for ClientError {}

pub type Result<T> = std::result::Result<T, ClientError>;

#[derive(Debug, Clone)]
pub struct Client {
    path: String,
}

impl Default for Client {
    fn default() -> Self {
        Self {
            path: socket_path(),
        }
    }
}

/// Explain why the service can't be reached in words a user can act on.
fn unreachable(e: std::io::Error) -> ClientError {
    use std::io::ErrorKind;
    let msg = match e.kind() {
        ErrorKind::NotFound | ErrorKind::ConnectionRefused => {
            "the service isn't running. Is DeepWork installed?".to_string()
        }
        ErrorKind::PermissionDenied => "you aren't allowed to connect to it".to_string(),
        _ => e.to_string(),
    };
    ClientError::Unavailable(msg)
}

/// Open a connection to the daemon (Unix socket).
#[cfg(unix)]
fn connect(path: &str) -> Result<std::os::unix::net::UnixStream> {
    let stream = std::os::unix::net::UnixStream::connect(path).map_err(unreachable)?;
    use std::time::Duration;
    stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(5))).ok();
    Ok(stream)
}

/// Open a connection to the daemon (named pipe).
#[cfg(windows)]
fn connect(path: &str) -> Result<std::fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    use std::time::{Duration, Instant};
    // Read and write data, nothing more: that is all the service's pipe
    // grants to normal users (FILE_GENERIC_READ | FILE_WRITE_DATA).
    const ACCESS: u32 = 0x0012_008b;
    // All pipe instances are taken; the service is about to create another.
    const ERROR_PIPE_BUSY: i32 = 231;
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match std::fs::OpenOptions::new().access_mode(ACCESS).open(path) {
            // Any program may create a pipe of that name while the service
            // isn't running. The service's belongs to SYSTEM (or the
            // administrators), which nobody else can pose as; anyone else
            // doesn't get to see passwords.
            Ok(f) if is_service_pipe(path) && !crate::windows::owned_by_admins(&f) => {
                return Err(ClientError::Unavailable(
                    "another program is posing as it. Restart the computer, and if that \
                     doesn't help, ask an administrator to look for it."
                        .into(),
                ));
            }
            Ok(f) => return Ok(f),
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) && Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(20))
            }
            Err(e) => return Err(unreachable(e)),
        }
    }
}

/// Whether `path` names the service's own pipe (not one of a sandbox or a
/// test, whose servers are ordinary programs).
#[cfg(windows)]
pub fn is_service_pipe(path: &str) -> bool {
    path.eq_ignore_ascii_case(crate::protocol::DEFAULT_SOCKET)
}

impl Client {
    pub fn new(path: impl Into<String>) -> Self {
        Self { path: path.into() }
    }

    pub fn call_raw(&self, req: &Request) -> Result<serde_json::Value> {
        let mut stream = connect(&self.path)?;
        let mut line = serde_json::to_vec(req).map_err(|e| ClientError::Protocol(e.to_string()))?;
        line.push(b'\n');
        stream
            .write_all(&line)
            .map_err(|e| ClientError::Unavailable(e.to_string()))?;
        let mut reader = BufReader::new(stream);
        let mut buf = String::new();
        reader
            .read_line(&mut buf)
            .map_err(|e| ClientError::Unavailable(e.to_string()))?;
        if buf.is_empty() {
            return Err(ClientError::Unavailable("connection closed".into()));
        }
        let resp: Response =
            serde_json::from_str(&buf).map_err(|e| ClientError::Protocol(e.to_string()))?;
        if resp.ok {
            Ok(resp.data)
        } else {
            Err(ClientError::Refused(
                resp.error.unwrap_or_else(|| "request refused".into()),
            ))
        }
    }

    pub fn call<T: DeserializeOwned>(&self, req: &Request) -> Result<T> {
        let v = self.call_raw(req)?;
        serde_json::from_value(v).map_err(|e| ClientError::Protocol(e.to_string()))
    }

    pub fn status(&self) -> Result<Status> {
        self.call(&Request::Status)
    }
    pub fn events(&self, since: u64) -> Result<Vec<Event>> {
        self.call(&Request::Events { since })
    }
    pub fn stats(&self, days: u32) -> Result<Stats> {
        self.call(&Request::Stats { days })
    }
    pub fn create_block(&self, config: BlockConfig, password: Option<String>) -> Result<String> {
        self.call(&Request::CreateBlock { config, password })
    }
    pub fn update_block(
        &self,
        id: &str,
        config: BlockConfig,
        password: Option<String>,
    ) -> Result<()> {
        self.call_raw(&Request::UpdateBlock {
            id: id.into(),
            config,
            password,
        })
        .map(|_| ())
    }
    pub fn delete_block(&self, id: &str) -> Result<()> {
        self.call_raw(&Request::DeleteBlock { id: id.into() })
            .map(|_| ())
    }
    pub fn start_block(&self, id: &str, minutes: u32) -> Result<()> {
        self.call_raw(&Request::StartBlock {
            id: id.into(),
            minutes,
        })
        .map(|_| ())
    }
    pub fn stop_block(&self, id: &str) -> Result<()> {
        self.call_raw(&Request::StopBlock { id: id.into() })
            .map(|_| ())
    }
    pub fn unlock_challenge(&self, id: &str) -> Result<String> {
        self.call(&Request::UnlockChallenge { id: id.into() })
    }
    pub fn unlock(&self, id: &str, response: &str) -> Result<()> {
        self.call_raw(&Request::Unlock {
            id: id.into(),
            response: response.into(),
        })
        .map(|_| ())
    }
    pub fn take_break(&self, id: &str, minutes: u32) -> Result<()> {
        self.call_raw(&Request::TakeBreak {
            id: id.into(),
            minutes,
        })
        .map(|_| ())
    }
    pub fn end_break(&self, id: &str) -> Result<()> {
        self.call_raw(&Request::EndBreak { id: id.into() })
            .map(|_| ())
    }
    pub fn set_settings(&self, settings: crate::model::Settings) -> Result<()> {
        self.call_raw(&Request::SetSettings { settings })
            .map(|_| ())
    }
    pub fn freeze(&self, minutes: u32) -> Result<()> {
        self.call_raw(&Request::Freeze { minutes }).map(|_| ())
    }
}
