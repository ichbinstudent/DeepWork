//! Wire protocol between the GUI/CLI and the daemon.
//!
//! One JSON object per line over a local socket (a Unix socket on Linux and
//! macOS, a named pipe on Windows). Each request gets exactly one response
//! line: `{"ok": true, "data": ...}` or `{"ok": false, "error": "..."}`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::model::{BlockConfig, LockKind, Settings};

#[cfg(target_os = "linux")]
pub const DEFAULT_SOCKET: &str = "/run/deepwork/deepwork.sock";
#[cfg(target_os = "macos")]
pub const DEFAULT_SOCKET: &str = "/var/run/deepwork.sock";
#[cfg(windows)]
pub const DEFAULT_SOCKET: &str = r"\\.\pipe\deepwork";
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
pub const DEFAULT_SOCKET: &str = "/var/run/deepwork.sock";

pub fn socket_path() -> String {
    std::env::var("DEEPWORK_SOCKET").unwrap_or_else(|_| DEFAULT_SOCKET.to_string())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    Ping,
    Status,
    Events {
        since: u64,
    },
    Stats {
        days: u32,
    },
    CreateBlock {
        config: BlockConfig,
        password: Option<String>,
    },
    UpdateBlock {
        id: String,
        config: BlockConfig,
        password: Option<String>,
    },
    DeleteBlock {
        id: String,
    },
    StartBlock {
        id: String,
        minutes: u32,
    },
    StopBlock {
        id: String,
    },
    UnlockChallenge {
        id: String,
    },
    Unlock {
        id: String,
        response: String,
    },
    TakeBreak {
        id: String,
        minutes: u32,
    },
    EndBreak {
        id: String,
    },
    Freeze {
        minutes: u32,
    },
    SetSettings {
        settings: Settings,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default)]
    pub data: serde_json::Value,
}

impl Response {
    pub fn ok(data: impl Serialize) -> Self {
        Self {
            ok: true,
            error: None,
            data: serde_json::to_value(data).unwrap_or_default(),
        }
    }
    pub fn err(msg: impl Into<String>) -> Self {
        Self {
            ok: false,
            error: Some(msg.into()),
            data: serde_json::Value::Null,
        }
    }
}

/// What a client gets to see about a block (never the password hash).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlockStatus {
    pub id: String,
    pub config: BlockConfig,
    pub has_password: bool,
    /// In a manual session or scheduled window (even during a break).
    pub active: bool,
    /// Actively blocking right now.
    pub enforcing: bool,
    pub locked: bool,
    pub on_break: bool,
    pub paused: bool,
    pub session_until: f64,
    pub window_start: Option<f64>,
    pub window_end: Option<f64>,
    pub pause_until: f64,
    /// `(on_break, seconds_until_switch)` for pomodoro blocks.
    pub pomodoro: Option<(bool, f64)>,
    pub allowance_left: f64,
    /// Why the lock is held, e.g. "random" or "protected".
    pub lock_reason: Option<LockKind>,
    pub protected: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Status {
    pub version: String,
    pub now: f64,
    pub frozen_until: f64,
    pub blocks: Vec<BlockStatus>,
    #[serde(default)]
    pub settings: Settings,
    #[serde(default)]
    pub net: NetStatus,
    #[serde(default)]
    pub hardcore: HardcoreStatus,
    #[serde(default)]
    pub capabilities: Capabilities,
}

/// What the service can do on this operating system. Features that are
/// missing are refused by the service and hidden or disabled in the app.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Capabilities {
    /// "Linux", "macOS", "Windows"…
    pub os: String,
    /// Block websites through the hosts file.
    pub websites: bool,
    /// Browser policies (URL blocklists, DNS over HTTPS off).
    pub browser_policies: bool,
    /// Close blocked applications.
    pub apps: bool,
    /// Block encrypted DNS servers.
    pub encrypted_dns: bool,
    /// Check the site name of every web connection.
    pub https_filter: bool,
    /// Refuse traffic through VPN tunnels.
    pub tunnels: bool,
    /// Lock the screen for a while.
    pub freeze: bool,
    /// Tell reboots apart (needed by the "Until restart" lock).
    pub restart_lock: bool,
    /// Take administrator rights away (needed by the "Hardcore" lock).
    pub hardcore: bool,
}

impl Capabilities {
    /// Everything supported (for tests and tools).
    pub fn all(os: &str) -> Self {
        Capabilities {
            os: os.into(),
            websites: true,
            browser_policies: true,
            apps: true,
            encrypted_dns: true,
            https_filter: true,
            tunnels: true,
            freeze: true,
            restart_lock: true,
            hardcore: true,
        }
    }

    pub fn supports_lock(&self, lock: LockKind) -> bool {
        match lock {
            LockKind::Restart => self.restart_lock,
            LockKind::Hardcore => self.hardcore,
            _ => true,
        }
    }
}

/// Hardcore mode: administrator rights are taken away while a hardcore
/// block runs.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct HardcoreStatus {
    /// Administrator rights are blocked until this time (0 = not now).
    pub until: f64,
    /// Ways in that couldn't be closed, e.g. "sudo: /etc/sudoers.d is missing".
    pub warnings: Vec<String>,
}

/// State of the network-level protections.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct NetStatus {
    /// The firewall (nftables) can be used.
    pub firewall_available: bool,
    /// Encrypted DNS servers are being blocked right now.
    pub doh_blocked: bool,
    /// Web traffic is going through the HTTPS filter right now.
    pub filtering: bool,
    /// Traffic through VPN tunnels is refused right now (hardcore mode).
    pub tunnels_blocked: bool,
    /// Connections refused by the HTTPS filter since the service started.
    pub filtered_connections: u64,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Event {
    pub seq: u64,
    pub ts: f64,
    /// "app_blocked", "block_started", "block_ended", "frozen", ...
    pub kind: String,
    pub title: String,
    pub body: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct DayStats {
    pub focus_seconds: f64,
    pub blocked_apps: u32,
    pub apps: BTreeMap<String, u32>,
}

/// date (YYYY-MM-DD) -> stats
pub type Stats = BTreeMap<String, DayStats>;
