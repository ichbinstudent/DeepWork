//! Windows: the Start menu's apps (programs and Store apps), and those with
//! an open window.

use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock};

use adw::prelude::*;
use deepwork_core::procinfo::start_menu_rules;
use gtk::{gdk, gio, glib};

use super::start_apps::{self, ICON, StartApp};
use crate::apps::AppEntry;

/// The last list. Reading it takes a moment, so it is read in the background
/// ahead of time, and again whenever it was used.
static APPS: OnceLock<Mutex<Vec<StartApp>>> = OnceLock::new();

/// Start reading the installed apps.
pub fn preload() {
    std::thread::spawn(|| {
        let apps = start_apps::installed();
        match APPS.get() {
            Some(list) => *list.lock().unwrap_or_else(|e| e.into_inner()) = apps,
            None => {
                let _ = APPS.set(Mutex::new(apps));
            }
        }
    });
}

pub fn installed() -> Vec<AppEntry> {
    let list = APPS.get_or_init(|| Mutex::new(start_apps::installed()));
    let mut by_rule = BTreeMap::new();
    for app in list.lock().unwrap_or_else(|e| e.into_inner()).iter() {
        by_rule
            .entry(app.rules[0].to_lowercase())
            .or_insert_with(|| AppEntry {
                name: app.name.clone(),
                icon: app.icon.as_deref().map(icon),
                rules: app.rules.clone(),
                detail: app.rules.join(", "),
            });
    }
    preload();
    by_rule.into_values().collect()
}

fn icon(pixels: &[u8]) -> gio::Icon {
    gdk::MemoryTexture::new(
        ICON as i32,
        ICON as i32,
        gdk::MemoryFormat::B8g8r8a8Premultiplied,
        &glib::Bytes::from(pixels),
        ICON * 4,
    )
    .upcast()
}

/// Programs with an open window.
pub fn running(installed: &[AppEntry]) -> Vec<AppEntry> {
    let mut apps = BTreeMap::new();
    for open in start_apps::open() {
        let store = open.package.is_some();
        let rules = match open.package {
            Some(family) => vec![family],
            None => match start_menu_rules(&open.exe, "", "") {
                Some(rules) => rules,
                None => continue,
            },
        };
        let known = installed
            .iter()
            .find(|a| a.rules.iter().any(|r| r.eq_ignore_ascii_case(&rules[0])));
        // Store apps that aren't in the Start menu are parts of Windows.
        if known.is_none() && store {
            continue;
        }
        let entry = known.cloned().unwrap_or_else(|| AppEntry {
            name: rules[0]
                .rsplit('\\')
                .next()
                .unwrap_or(&rules[0])
                .to_string(),
            icon: None,
            detail: format!("process “{}”", rules[0]),
            rules,
        });
        apps.insert(entry.rules[0].to_lowercase(), entry);
    }
    let mut v: Vec<AppEntry> = apps.into_values().collect();
    v.sort_by_key(|a| a.name.to_lowercase());
    v
}
