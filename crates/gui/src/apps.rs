//! Discovering installed and running applications. How an app maps to
//! block rules and which apps are running is up to the platform.

use gtk::gio;

use crate::platform;

#[derive(Clone)]
pub struct AppEntry {
    pub name: String,
    pub icon: Option<gio::Icon>,
    /// Rules to add to a block for this app.
    pub rules: Vec<String>,
    pub detail: String,
}

/// The installed applications, by name.
pub fn installed() -> Vec<AppEntry> {
    let mut v = platform::apps::installed();
    v.sort_by_key(|a| a.name.to_lowercase());
    v
}

/// Graphical apps the current user is running right now.
pub fn running() -> Vec<AppEntry> {
    platform::apps::running(&installed())
}

/// Friendly name and icon for a rule stored in a block.
pub fn describe_rule(rule: &str, installed: &[AppEntry]) -> (String, Option<gio::Icon>) {
    if let Some(needle) = rule.strip_prefix(deepwork_core::model::CMD_PREFIX) {
        return (format!("Command line contains “{needle}”"), None);
    }
    installed
        .iter()
        .find(|a| a.rules.iter().any(|r| r.eq_ignore_ascii_case(rule)))
        .map(|a| (a.name.clone(), a.icon.clone()))
        .unwrap_or_else(|| (rule.to_string(), None))
}
