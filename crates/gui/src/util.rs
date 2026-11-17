//! Small widget helpers.

use adw::prelude::*;
use deepwork_core::model::BlockConfig;
use deepwork_core::protocol::BlockStatus;
use deepwork_core::{describe_schedule, format_clock, format_time};
use gtk::gdk;

pub fn color_rgba(name: &str) -> gdk::RGBA {
    let hex = match name {
        "teal" => "#2190a4",
        "green" => "#2ec27e",
        "yellow" => "#e5a50a",
        "orange" => "#ff7800",
        "red" => "#e01b24",
        "pink" => "#e64b9d",
        "purple" => "#9141ac",
        _ => "#3584e4",
    };
    gdk::RGBA::parse(hex).unwrap_or(gdk::RGBA::BLUE)
}

pub fn dot(color: &str) -> gtk::Box {
    let d = gtk::Box::builder()
        .valign(gtk::Align::Center)
        .halign(gtk::Align::Center)
        .build();
    d.add_css_class("dot");
    d.add_css_class(color);
    d
}

pub fn pill(text: &str, class: &str) -> gtk::Label {
    let l = gtk::Label::builder()
        .label(text)
        .valign(gtk::Align::Center)
        .build();
    l.add_css_class("pill-label");
    if !class.is_empty() {
        l.add_css_class(class);
    }
    l
}

/// Compact duration for tiles and the ring: "0m", "45m", "2h 05m".
pub fn short_duration(secs: f64) -> String {
    if secs < 60.0 {
        return "0m".into();
    }
    deepwork_core::format_duration(secs)
        .replace(" min", "m")
        .replace(" h ", "h ")
        .replace(" d ", "d ")
}

pub fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

pub fn clear_listbox(list: &gtk::ListBox) {
    while let Some(child) = list.first_child() {
        list.remove(&child);
    }
}

/// "22 websites · 4 apps" for a filter list.
pub fn list_summary(l: &deepwork_core::lists::FilterList) -> String {
    let mut parts = vec![];
    if !l.websites.is_empty() {
        parts.push(plural(l.websites.len(), "website", "websites"));
    }
    if !l.apps.is_empty() {
        parts.push(plural(l.apps.len(), "app", "apps"));
    }
    parts.join(" · ")
}

/// "2 lists · 46 websites · 22 apps · Weekdays 09:00–17:00"
pub fn block_summary(cfg: &BlockConfig) -> String {
    let mut parts = vec![];
    if !cfg.lists.is_empty() {
        parts.push(plural(cfg.lists.len(), "list", "lists"));
    }
    let (sites, apps) = (cfg.effective_websites().len(), cfg.effective_apps().len());
    if sites > 0 {
        parts.push(plural(sites, "website", "websites"));
    }
    if apps > 0 {
        parts.push(plural(apps, "app", "apps"));
    }
    if parts.is_empty() {
        parts.push("Empty".into());
    }
    if cfg.schedule_enabled && !cfg.schedule.is_empty() {
        parts.push(describe_schedule(&cfg.schedule));
    }
    parts.join(" · ")
}

/// One-line live state for an active block.
pub fn live_line(b: &BlockStatus, now: f64) -> String {
    if b.paused {
        return format!("On a break · back in {}", format_clock(b.pause_until - now));
    }
    if let Some((true, left)) = b.pomodoro {
        return format!("Pomodoro break · back in {}", format_clock(left));
    }
    let mut s = match b.window_end {
        Some(end) => format!(
            "{} left · until {}",
            format_clock(end - now),
            format_time(end)
        ),
        None => "Off".into(),
    };
    if let Some((false, left)) = b.pomodoro {
        s.push_str(&format!(" · break in {}", format_clock(left)));
    }
    s
}

/// Badge for a block: (text, css class).
pub fn badge(b: &BlockStatus) -> (&'static str, &'static str) {
    if b.on_break {
        ("Break", "break")
    } else if b.active && b.locked && b.config.lock == deepwork_core::model::LockKind::Hardcore {
        ("Hardcore", "locked")
    } else if b.active && b.locked {
        ("Locked", "locked")
    } else if b.active {
        ("Active", "active")
    } else if b.protected {
        ("Protected", "locked")
    } else if b.config.schedule_enabled && !b.config.schedule.is_empty() {
        ("Scheduled", "")
    } else {
        ("Off", "")
    }
}

pub fn icon_button(icon: &str, tooltip: &str) -> gtk::Button {
    let b = gtk::Button::builder()
        .icon_name(icon)
        .tooltip_text(tooltip)
        .valign(gtk::Align::Center)
        .build();
    b.add_css_class("flat");
    b
}

pub fn text_button(label: &str, classes: &[&str]) -> gtk::Button {
    let b = gtk::Button::builder()
        .label(label)
        .valign(gtk::Align::Center)
        .build();
    for c in classes {
        b.add_css_class(c);
    }
    b
}

/// Signature used to decide whether a list needs rebuilding.
pub fn signature<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_string(v).unwrap_or_default()
}

/// Groups of the current user that give root-equivalent access (e.g.
/// `docker`), which hardcore mode can't take away.
pub fn root_equivalent_groups() -> Vec<String> {
    const RISKY: &[&str] = &["docker", "lxd", "incus-admin", "disk"];
    let read = |p: &str| std::fs::read_to_string(p).unwrap_or_default();
    let Some(uid) = read("/proc/self/status").lines().find_map(|l| {
        l.strip_prefix("Uid:")
            .and_then(|v| v.split_whitespace().next().map(str::to_string))
    }) else {
        return vec![];
    };
    let passwd = read("/etc/passwd");
    let Some((name, gid)) = passwd.lines().find_map(|l| {
        let f: Vec<&str> = l.split(':').collect();
        (f.len() > 3 && f[2] == uid).then(|| (f[0].to_string(), f[3].to_string()))
    }) else {
        return vec![];
    };
    read("/etc/group")
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            if f.len() < 4 || !RISKY.contains(&f[0]) {
                return None;
            }
            let member = f[2] == gid || f[3].split(',').any(|m| m == name);
            member.then(|| f[0].to_string())
        })
        .collect()
}
