//! What the tray shows, independent of how the OS displays it: the icon,
//! tooltip, countdown and menu for a status.

use deepwork_core::model::LockKind;
use deepwork_core::protocol::{BlockStatus, Status};
use deepwork_core::{format_duration, format_time};
use gtk::{gio, glib};
use std::path::PathBuf;

use crate::platform::Action;

/// The tray icons, one per state (`resources/tray/deepwork-<name>-symbolic.svg`).
pub const ICONS: &[&str] = &["idle", "active", "locked", "break", "frozen", "offline"];

#[derive(Debug, Clone, PartialEq)]
pub struct Item {
    pub label: String,
    pub enabled: bool,
    pub separator: bool,
    pub toggle: Option<bool>,
    pub action: Option<Action>,
    pub children: Vec<Item>,
    /// A symbolic icon from the icon theme, drawn in the menu's text color
    /// (where the tray shows menu icons).
    pub icon: Option<&'static str>,
}

/// Marks locked blocks (flat and single-colored, unlike an emoji).
pub const LOCK_ICON: &str = "changes-prevent-symbolic";

impl Item {
    pub fn new(label: impl Into<String>, action: Action) -> Self {
        Self {
            label: label.into(),
            enabled: true,
            separator: false,
            toggle: None,
            action: Some(action),
            children: vec![],
            icon: None,
        }
    }
    pub fn info(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            enabled: false,
            separator: false,
            toggle: None,
            action: None,
            children: vec![],
            icon: None,
        }
    }
    pub fn submenu(label: impl Into<String>, children: Vec<Item>) -> Self {
        Self {
            label: label.into(),
            enabled: true,
            separator: false,
            toggle: None,
            action: None,
            children,
            icon: None,
        }
    }
    pub fn with_icon(mut self, icon: Option<&'static str>) -> Self {
        self.icon = icon;
        self
    }
    pub fn separator() -> Self {
        Self {
            label: String::new(),
            enabled: true,
            separator: true,
            toggle: None,
            action: None,
            children: vec![],
            icon: None,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Look {
    pub icon: &'static str,
    pub title: String,
    /// The countdown shown next to the icon (empty when hidden).
    pub label: String,
    pub tooltip: String,
}

fn settings_path() -> PathBuf {
    glib::user_config_dir()
        .join("deepwork")
        .join("settings.json")
}

#[cfg_attr(windows, allow(dead_code))] // no timer next to the icon there
pub fn load_show_timer() -> bool {
    std::fs::read_to_string(settings_path())
        .ok()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        .and_then(|v| v.get("show_timer").and_then(|b| b.as_bool()))
        .unwrap_or(true)
}

#[cfg_attr(windows, allow(dead_code))]
pub fn save_show_timer(on: bool) {
    let p = settings_path();
    if let Some(dir) = p.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::fs::write(p, serde_json::json!({ "show_timer": on }).to_string());
}

pub fn icon_svg(name: &str) -> Option<glib::Bytes> {
    gio::resources_lookup_data(
        &format!("/io/github/ichbinstudent/DeepWork/tray/deepwork-{name}-symbolic.svg"),
        gio::ResourceLookupFlags::NONE,
    )
    .ok()
}

/// An icon at `size` pixels with its glyph in `color` (e.g. `#ffffff`).
pub fn render(name: &str, size: i32, color: &str) -> Option<gtk::gdk_pixbuf::Pixbuf> {
    let svg = icon_svg(name)?;
    let svg = String::from_utf8_lossy(&svg).replace("#222", color);
    let stream = gio::MemoryInputStream::from_bytes(&glib::Bytes::from(svg.as_bytes()));
    let pb = gtk::gdk_pixbuf::Pixbuf::from_stream_at_scale(
        &stream,
        size,
        size,
        true,
        gio::Cancellable::NONE,
    )
    .ok()?;
    if pb.has_alpha() {
        Some(pb)
    } else {
        pb.add_alpha(false, 0, 0, 0).ok()
    }
}

/// "1h 05m", "42m", "<1m"
fn short_clock(secs: f64) -> String {
    let m = (secs / 60.0).ceil() as u64;
    if m >= 60 {
        format!("{}h {:02}m", m / 60, m % 60)
    } else {
        format!("{m}m")
    }
}

fn block_left(b: &BlockStatus, now: f64) -> String {
    match b.window_end {
        Some(end) => format!(
            "{} left",
            format_duration(((end - now) / 60.0).ceil() * 60.0)
        ),
        None => String::new(),
    }
}

// ----------------------------------------------------------------------------- state -> look/menu

/// The tray's look and menu for a status. `show_timer` is the "show timer"
/// menu toggle, where the tray can show text next to the icon (`None`: it
/// can't, and the countdown goes in [`Look::label`] for the tooltip).
pub fn compute(status: Option<&Status>, now: f64, show_timer: Option<bool>) -> (Look, Vec<Item>) {
    let mut items = vec![];
    let Some(s) = status else {
        let look = Look {
            icon: "offline",
            title: "DeepWork".into(),
            label: String::new(),
            tooltip: "The DeepWork service isn't running".into(),
        };
        items.push(Item::info("Service isn't running"));
        items.push(Item::separator());
        items.push(Item::new("Open DeepWork", Action::Open(None)));
        items.push(Item::new("Quit", Action::Quit));
        return (look, items);
    };

    let active: Vec<&BlockStatus> = s.blocks.iter().filter(|b| b.active).collect();
    let idle: Vec<&BlockStatus> = s.blocks.iter().filter(|b| !b.active).collect();
    let frozen = s.frozen_until > now;
    let enforcing = active.iter().any(|b| b.enforcing);
    let end = active
        .iter()
        .filter_map(|b| b.window_end)
        .fold(0.0, f64::max);

    let (icon, headline, label) = if frozen {
        (
            "frozen",
            format!("Frozen until {}", format_time(s.frozen_until)),
            short_clock(s.frozen_until - now),
        )
    } else if !active.is_empty() && !enforcing {
        let back = active
            .iter()
            .map(|b| {
                if b.paused {
                    b.pause_until
                } else {
                    now + b.pomodoro.map(|p| p.1).unwrap_or(0.0)
                }
            })
            .fold(f64::MAX, f64::min);
        (
            "break",
            format!("On a break until {}", format_time(back)),
            short_clock(back - now),
        )
    } else if enforcing {
        let locked = active.iter().any(|b| b.locked);
        (
            if locked { "locked" } else { "active" },
            format!(
                "Blocking until {}{}",
                format_time(end),
                if locked { " · locked" } else { "" }
            ),
            short_clock(end - now),
        )
    } else {
        ("idle", "Not blocking anything".to_string(), String::new())
    };

    items.push(Item::info(headline.clone()));

    if !active.is_empty() {
        items.push(Item::separator());
        for b in &active {
            let mut sub = vec![
                Item::new("Add 15 minutes", Action::AddTime(b.id.clone(), 15)),
                Item::new("Add 1 hour", Action::AddTime(b.id.clone(), 60)),
            ];
            if b.paused {
                sub.push(Item::new("End break", Action::EndBreak(b.id.clone())));
            } else if b.config.allowance_minutes > 0 && b.allowance_left >= 60.0 {
                sub.push(Item::new(
                    format!(
                        "Take a break… ({} left today)",
                        format_duration(b.allowance_left)
                    ),
                    Action::Break(b.id.clone()),
                ));
            }
            sub.push(Item::separator());
            if !b.locked {
                sub.push(Item::new("Stop", Action::Stop(b.id.clone())));
            } else if !b.protected && matches!(b.config.lock, LockKind::Random | LockKind::Password)
            {
                sub.push(Item::new("Unlock…", Action::Unlock(b.id.clone())));
            } else {
                sub.push(Item::info(match b.config.lock {
                    LockKind::Restart => "Locked until restart",
                    _ => "Locked until it ends",
                }));
            }
            let state = if b.on_break {
                "on a break".to_string()
            } else {
                block_left(b, now)
            };
            items.push(
                Item::submenu(format!("{} — {state}", b.config.name), sub)
                    .with_icon(b.locked.then_some(LOCK_ICON)),
            );
        }
    }

    items.push(Item::separator());
    if !idle.is_empty() {
        let blocks = idle
            .iter()
            .map(|b| {
                let mut durations: Vec<Item> = [
                    (25, "25 minutes"),
                    (60, "1 hour"),
                    (120, "2 hours"),
                    (240, "4 hours"),
                ]
                .iter()
                .map(|(m, l)| Item::new(*l, Action::Start(b.id.clone(), *m)))
                .collect();
                durations.push(Item::new(
                    "Other duration…",
                    Action::StartCustom(b.id.clone()),
                ));
                Item::submenu(b.config.name.clone(), durations)
                    .with_icon((b.config.lock != LockKind::None).then_some(LOCK_ICON))
            })
            .collect();
        items.push(Item::submenu("Start a block", blocks));
    } else if s.blocks.is_empty() {
        items.push(Item::new("Create a block…", Action::Open(Some("blocks"))));
    }
    if !frozen {
        items.push(Item::new("Freeze computer…", Action::Open(Some("freeze"))));
    }
    items.push(Item::separator());
    if let Some(on) = show_timer {
        let mut timer = Item::new("Show timer in top bar", Action::ToggleTimer);
        timer.toggle = Some(on);
        items.push(timer);
    }
    items.push(Item::new("Open DeepWork", Action::Open(None)));
    items.push(Item::new("Quit", Action::Quit));

    let look = Look {
        icon,
        title: "DeepWork".into(),
        label: if show_timer != Some(false) {
            label
        } else {
            String::new()
        },
        tooltip: headline,
    };
    (look, items)
}

#[cfg(test)]
pub mod test_util {
    use super::*;
    use deepwork_core::model::BlockConfig;

    pub fn block(active: bool, locked: bool) -> BlockStatus {
        BlockStatus {
            id: "b1".into(),
            config: BlockConfig {
                name: "Social".into(),
                lock: LockKind::Random,
                ..Default::default()
            },
            has_password: false,
            active,
            enforcing: active,
            locked,
            on_break: false,
            paused: false,
            session_until: 0.0,
            window_start: active.then_some(0.0),
            window_end: active.then_some(3900.0),
            pause_until: 0.0,
            pomodoro: None,
            allowance_left: 0.0,
            lock_reason: None,
            protected: false,
        }
    }

    pub fn status(blocks: Vec<BlockStatus>) -> Status {
        Status {
            version: "x".into(),
            now: 0.0,
            frozen_until: 0.0,
            blocks,
            settings: Default::default(),
            net: Default::default(),
            hardcore: Default::default(),
            capabilities: Default::default(),
        }
    }
}

#[cfg(test)]
mod tests;
