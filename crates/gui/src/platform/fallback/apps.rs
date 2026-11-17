//! App discovery without OS-specific knowledge.

use adw::prelude::*;
use gtk::gio;

use crate::apps::AppEntry;

/// The app id plus the executable's name (without `.exe`).
pub fn rules_for(info: &gio::AppInfo) -> Vec<String> {
    let mut rules = vec![];
    if let Some(id) = info.id() {
        rules.push(id.trim_end_matches(".desktop").to_string());
    }
    if let Some(name) = info
        .executable()
        .and_then(|e| e.file_stem().map(|n| n.to_string_lossy().to_string()))
        .filter(|n| !n.is_empty() && !rules.iter().any(|r| r.eq_ignore_ascii_case(n)))
    {
        rules.push(name);
    }
    rules
}

pub fn running(_installed: &[AppEntry]) -> Vec<AppEntry> {
    vec![]
}
