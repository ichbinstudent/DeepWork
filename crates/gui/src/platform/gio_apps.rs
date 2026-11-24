//! Installed apps as GIO knows them (desktop files, app bundles).

use std::collections::BTreeMap;

use adw::prelude::*;
use gtk::gio;

use crate::apps::AppEntry;

/// The installed apps, with the block rules `rules_for` gives each one.
pub fn installed(rules_for: impl Fn(&gio::AppInfo) -> Vec<String>) -> Vec<AppEntry> {
    let mut by_id = BTreeMap::new();
    for info in gio::AppInfo::all() {
        if !info.should_show() {
            continue;
        }
        let rules = rules_for(&info);
        if rules.is_empty()
            || rules
                .iter()
                .any(|r| r.starts_with("io.github.ichbinstudent"))
        {
            continue;
        }
        let name = info.display_name().to_string();
        by_id.entry(rules[0].clone()).or_insert(AppEntry {
            detail: rules.join(", "),
            name,
            icon: info.icon(),
            rules,
        });
    }
    by_id.into_values().collect()
}
