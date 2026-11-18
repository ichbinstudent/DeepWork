//! OS-specific parts of the app. Everything else is plain GTK and runs
//! wherever GTK 4 and libadwaita do.
//!
//! - [`tray`]: the top-bar / system-tray indicator (what it shows is in
//!   [`tray_menu`])
//! - [`apps`]: turning installed apps into block rules, and listing the
//!   apps that are running
//!
//! Features the service can't provide on an OS are reported in
//! `Status::capabilities`; pages hide or disable them.

pub mod tray_menu;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{apps, tray};

#[cfg(windows)]
pub mod windows;
#[cfg(windows)]
pub use fallback::apps;
#[cfg(windows)]
pub use windows::tray;

#[cfg(not(target_os = "linux"))]
#[cfg_attr(windows, allow(dead_code))] // only its apps part on Windows
mod fallback;
#[cfg(not(any(target_os = "linux", windows)))]
pub use fallback::{apps, tray};

// Compile the fallbacks in Linux test builds too, so they don't rot.
#[cfg(all(test, target_os = "linux"))]
#[allow(dead_code)]
mod fallback;

/// Something the user picked in the tray menu (no tray on some systems).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    Open(Option<&'static str>),
    Start(String, u32),
    StartCustom(String),
    AddTime(String, u32),
    Stop(String),
    Unlock(String),
    Break(String),
    EndBreak(String),
    ToggleTimer,
    Quit,
}
