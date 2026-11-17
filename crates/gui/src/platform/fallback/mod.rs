//! Systems without a native implementation yet: no tray icon, installed
//! apps from GIO only, no list of running apps.
//!
//! - macOS tray: `NSStatusItem` (e.g. through the `tray-icon` crate).
//! - Windows tray: `Shell_NotifyIconW`; running apps from the service.

pub mod apps;
pub mod tray;
