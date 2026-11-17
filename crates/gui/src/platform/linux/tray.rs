//! Top-bar / system-tray indicator.
//!
//! Implements the StatusNotifierItem and com.canonical.dbusmenu D-Bus
//! interfaces directly with GIO, so everything runs on the GTK main loop.
//! GNOME shows it through the AppIndicator extension; KDE and most other
//! desktops support it natively. The non-standard `XAyatanaLabel` property
//! puts a countdown next to the icon where the host supports it.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::path::PathBuf;
use std::rc::Rc;

use deepwork_core::model::LockKind;
use deepwork_core::protocol::{BlockStatus, Status};
use deepwork_core::{format_duration, format_time};
use gtk::gio;
use gtk::glib::{self, Variant};
use gtk::prelude::*;

use crate::platform::Action;
use crate::store::Store;

const ITEM_PATH: &str = "/StatusNotifierItem";
const MENU_PATH: &str = "/MenuBar";
const ITEM_IFACE: &str = "org.kde.StatusNotifierItem";
const MENU_IFACE: &str = "com.canonical.dbusmenu";
const ICONS: &[&str] = &["idle", "active", "locked", "break", "frozen", "offline"];

const XML: &str = r#"<node>
<interface name="org.kde.StatusNotifierItem">
  <property name="Category" type="s" access="read"/>
  <property name="Id" type="s" access="read"/>
  <property name="Title" type="s" access="read"/>
  <property name="Status" type="s" access="read"/>
  <property name="WindowId" type="i" access="read"/>
  <property name="IconThemePath" type="s" access="read"/>
  <property name="IconName" type="s" access="read"/>
  <property name="IconPixmap" type="a(iiay)" access="read"/>
  <property name="OverlayIconName" type="s" access="read"/>
  <property name="OverlayIconPixmap" type="a(iiay)" access="read"/>
  <property name="AttentionIconName" type="s" access="read"/>
  <property name="AttentionIconPixmap" type="a(iiay)" access="read"/>
  <property name="AttentionMovieName" type="s" access="read"/>
  <property name="ToolTip" type="(sa(iiay)ss)" access="read"/>
  <property name="ItemIsMenu" type="b" access="read"/>
  <property name="Menu" type="o" access="read"/>
  <property name="XAyatanaLabel" type="s" access="read"/>
  <property name="XAyatanaLabelGuide" type="s" access="read"/>
  <method name="ContextMenu"><arg name="x" type="i" direction="in"/><arg name="y" type="i" direction="in"/></method>
  <method name="Activate"><arg name="x" type="i" direction="in"/><arg name="y" type="i" direction="in"/></method>
  <method name="SecondaryActivate"><arg name="x" type="i" direction="in"/><arg name="y" type="i" direction="in"/></method>
  <method name="Scroll"><arg name="delta" type="i" direction="in"/><arg name="orientation" type="s" direction="in"/></method>
  <signal name="NewTitle"/>
  <signal name="NewIcon"/>
  <signal name="NewAttentionIcon"/>
  <signal name="NewOverlayIcon"/>
  <signal name="NewToolTip"/>
  <signal name="NewStatus"><arg name="status" type="s"/></signal>
  <signal name="XAyatanaNewLabel"><arg name="label" type="s"/><arg name="guide" type="s"/></signal>
</interface>
<interface name="com.canonical.dbusmenu">
  <property name="Version" type="u" access="read"/>
  <property name="TextDirection" type="s" access="read"/>
  <property name="Status" type="s" access="read"/>
  <property name="IconThemePath" type="as" access="read"/>
  <method name="GetLayout">
    <arg type="i" name="parentId" direction="in"/>
    <arg type="i" name="recursionDepth" direction="in"/>
    <arg type="as" name="propertyNames" direction="in"/>
    <arg type="u" name="revision" direction="out"/>
    <arg type="(ia{sv}av)" name="layout" direction="out"/>
  </method>
  <method name="GetGroupProperties">
    <arg type="ai" name="ids" direction="in"/>
    <arg type="as" name="propertyNames" direction="in"/>
    <arg type="a(ia{sv})" name="properties" direction="out"/>
  </method>
  <method name="GetProperty">
    <arg type="i" name="id" direction="in"/>
    <arg type="s" name="name" direction="in"/>
    <arg type="v" name="value" direction="out"/>
  </method>
  <method name="Event">
    <arg type="i" name="id" direction="in"/>
    <arg type="s" name="eventId" direction="in"/>
    <arg type="v" name="data" direction="in"/>
    <arg type="u" name="timestamp" direction="in"/>
  </method>
  <method name="EventGroup">
    <arg type="a(isvu)" name="events" direction="in"/>
    <arg type="ai" name="idErrors" direction="out"/>
  </method>
  <method name="AboutToShow">
    <arg type="i" name="id" direction="in"/>
    <arg type="b" name="needUpdate" direction="out"/>
  </method>
  <method name="AboutToShowGroup">
    <arg type="ai" name="ids" direction="in"/>
    <arg type="ai" name="updatesNeeded" direction="out"/>
    <arg type="ai" name="idErrors" direction="out"/>
  </method>
  <signal name="ItemsPropertiesUpdated">
    <arg type="a(ia{sv})" name="updatedProps"/>
    <arg type="a(ias)" name="removedProps"/>
  </signal>
  <signal name="LayoutUpdated">
    <arg type="u" name="revision"/>
    <arg type="i" name="parent"/>
  </signal>
  <signal name="ItemActivationRequested">
    <arg type="i" name="id"/>
    <arg type="u" name="timestamp"/>
  </signal>
</interface>
</node>"#;

#[derive(Debug, Clone, PartialEq)]
struct Item {
    label: String,
    enabled: bool,
    separator: bool,
    toggle: Option<bool>,
    action: Option<Action>,
    children: Vec<Item>,
}

impl Item {
    fn new(label: impl Into<String>, action: Action) -> Self {
        Self {
            label: label.into(),
            enabled: true,
            separator: false,
            toggle: None,
            action: Some(action),
            children: vec![],
        }
    }
    fn info(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            enabled: false,
            separator: false,
            toggle: None,
            action: None,
            children: vec![],
        }
    }
    fn submenu(label: impl Into<String>, children: Vec<Item>) -> Self {
        Self {
            label: label.into(),
            enabled: true,
            separator: false,
            toggle: None,
            action: None,
            children,
        }
    }
    fn separator() -> Self {
        Self {
            label: String::new(),
            enabled: true,
            separator: true,
            toggle: None,
            action: None,
            children: vec![],
        }
    }
}

/// Menu items flattened with stable ids (0 is the root).
#[derive(Default)]
struct Menu {
    items: Vec<(i32, Item, Vec<i32>)>,
}

impl Menu {
    fn build(root: Vec<Item>) -> Self {
        let mut m = Menu::default();
        let root_item = Item::submenu("", root);
        m.add(root_item);
        m
    }

    fn add(&mut self, item: Item) -> i32 {
        let id = self.items.len() as i32;
        self.items.push((id, item.clone(), vec![]));
        let children: Vec<i32> = item.children.into_iter().map(|c| self.add(c)).collect();
        self.items[id as usize].2 = children;
        id
    }

    fn get(&self, id: i32) -> Option<&(i32, Item, Vec<i32>)> {
        self.items.get(usize::try_from(id).ok()?)
    }

    fn props(&self, id: i32) -> HashMap<String, Variant> {
        let mut p = HashMap::new();
        let Some((_, item, children)) = self.get(id) else {
            return p;
        };
        if item.separator {
            p.insert("type".into(), "separator".to_variant());
            return p;
        }
        if id != 0 {
            p.insert("label".into(), item.label.replace('_', "__").to_variant());
            p.insert("enabled".into(), item.enabled.to_variant());
        }
        if !children.is_empty() {
            p.insert("children-display".into(), "submenu".to_variant());
        }
        if let Some(on) = item.toggle {
            p.insert("toggle-type".into(), "checkmark".to_variant());
            p.insert("toggle-state".into(), (on as i32).to_variant());
        }
        p
    }

    fn layout(&self, id: i32, depth: i32) -> (i32, HashMap<String, Variant>, Vec<Variant>) {
        let children = match self.get(id) {
            Some((_, _, kids)) if depth != 0 => kids
                .iter()
                .map(|c| self.layout(*c, depth - 1).to_variant())
                .collect(),
            _ => vec![],
        };
        (id, self.props(id), children)
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
struct Look {
    icon: &'static str,
    title: String,
    label: String,
    tooltip: String,
}

/// Icon pixmap as sent over D-Bus: width, height, ARGB32 bytes.
type Pixmap = (i32, i32, Vec<u8>);

pub struct Tray {
    conn: gio::DBusConnection,
    bus_name: String,
    icon_dir: PathBuf,
    look: RefCell<Look>,
    menu: RefCell<Menu>,
    menu_sig: RefCell<String>,
    revision: Cell<u32>,
    pixmaps: HashMap<&'static str, Vec<Pixmap>>,
    show_timer: Cell<bool>,
    registered: Cell<bool>,
    on_action: Box<dyn Fn(Action)>,
    on_registered: Box<dyn Fn()>,
}

// ----------------------------------------------------------------------------- helpers

fn settings_path() -> PathBuf {
    glib::user_config_dir()
        .join("deepwork")
        .join("settings.json")
}

fn load_show_timer() -> bool {
    std::fs::read_to_string(settings_path())
        .ok()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        .and_then(|v| v.get("show_timer").and_then(|b| b.as_bool()))
        .unwrap_or(true)
}

fn save_show_timer(on: bool) {
    let p = settings_path();
    if let Some(dir) = p.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::fs::write(p, serde_json::json!({ "show_timer": on }).to_string());
}

fn icon_svg(name: &str) -> Option<glib::Bytes> {
    gio::resources_lookup_data(
        &format!("/io/github/ichbinstudent/DeepWork/tray/deepwork-{name}-symbolic.svg"),
        gio::ResourceLookupFlags::NONE,
    )
    .ok()
}

/// Write the icons where the tray host can find them by name.
fn install_icons() -> PathBuf {
    let dir = glib::user_runtime_dir().join("deepwork").join("tray-icons");
    let themed = dir.join("hicolor").join("scalable").join("status");
    let _ = std::fs::create_dir_all(&themed);
    let _ = std::fs::write(
        dir.join("hicolor").join("index.theme"),
        "[Icon Theme]\nName=Hicolor\nDirectories=scalable/status\n\n[scalable/status]\nSize=16\nMinSize=8\nMaxSize=512\nType=Scalable\n",
    );
    for name in ICONS {
        if let Some(svg) = icon_svg(name) {
            let file = format!("deepwork-{name}-symbolic.svg");
            let _ = std::fs::write(dir.join(&file), &svg[..]);
            let _ = std::fs::write(themed.join(&file), &svg[..]);
        }
    }
    dir
}

/// Bitmap fallback for hosts that can't load icons by name: white glyphs,
/// ARGB32 in network byte order as the spec requires.
fn render_pixmaps(name: &str) -> Vec<Pixmap> {
    let Some(svg) = icon_svg(name) else {
        return vec![];
    };
    let white = String::from_utf8_lossy(&svg).replace("#222", "#ffffff");
    let mut out = vec![];
    for size in [22, 32, 48] {
        let stream = gio::MemoryInputStream::from_bytes(&glib::Bytes::from(white.as_bytes()));
        let Ok(pb) = gtk::gdk_pixbuf::Pixbuf::from_stream_at_scale(
            &stream,
            size,
            size,
            true,
            gio::Cancellable::NONE,
        ) else {
            continue;
        };
        let Ok(pb) = (if pb.has_alpha() {
            Ok(pb)
        } else {
            pb.add_alpha(false, 0, 0, 0)
        }) else {
            continue;
        };
        let (w, h, stride, n) = (
            pb.width(),
            pb.height(),
            pb.rowstride() as usize,
            pb.n_channels() as usize,
        );
        let bytes = pb.read_pixel_bytes();
        let mut data = Vec::with_capacity((w * h * 4) as usize);
        for y in 0..h as usize {
            for x in 0..w as usize {
                let i = y * stride + x * n;
                data.extend_from_slice(&[bytes[i + 3], bytes[i], bytes[i + 1], bytes[i + 2]]);
            }
        }
        out.push((w, h, data));
    }
    out
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

fn compute(status: Option<&Status>, now: f64, show_timer: bool) -> (Look, Vec<Item>) {
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
            format!("☕ {}", short_clock(back - now)),
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
            let lock = if b.locked { "🔒 " } else { "" };
            items.push(Item::submenu(
                format!("{lock}{} — {state}", b.config.name),
                sub,
            ));
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
                let lock = if b.config.lock != LockKind::None {
                    " 🔒"
                } else {
                    ""
                };
                Item::submenu(format!("{}{lock}", b.config.name), durations)
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
    let mut timer = Item::new("Show timer in top bar", Action::ToggleTimer);
    timer.toggle = Some(show_timer);
    items.push(timer);
    items.push(Item::new("Open DeepWork", Action::Open(None)));
    items.push(Item::new("Quit", Action::Quit));

    let look = Look {
        icon,
        title: "DeepWork".into(),
        label: if show_timer { label } else { String::new() },
        tooltip: headline,
    };
    (look, items)
}

// ----------------------------------------------------------------------------- D-Bus plumbing

impl Tray {
    pub fn start(
        conn: gio::DBusConnection,
        on_action: impl Fn(Action) + 'static,
        on_registered: impl Fn() + 'static,
    ) -> Result<Rc<Self>, glib::Error> {
        let node = gio::DBusNodeInfo::for_xml(XML)?;
        let bus_name = format!("org.kde.StatusNotifierItem-{}-1", std::process::id());
        let tray = Rc::new(Tray {
            conn: conn.clone(),
            bus_name: bus_name.clone(),
            icon_dir: install_icons(),
            look: RefCell::new(Look {
                icon: "offline",
                title: "DeepWork".into(),
                ..Default::default()
            }),
            menu: RefCell::new(Menu::build(vec![])),
            menu_sig: RefCell::new(String::new()),
            revision: Cell::new(1),
            pixmaps: ICONS.iter().map(|n| (*n, render_pixmaps(n))).collect(),
            show_timer: Cell::new(load_show_timer()),
            registered: Cell::new(false),
            on_action: Box::new(on_action),
            on_registered: Box::new(on_registered),
        });

        let item_iface = node.lookup_interface(ITEM_IFACE).expect("item interface");
        let menu_iface = node.lookup_interface(MENU_IFACE).expect("menu interface");
        let weak = Rc::downgrade(&tray);
        let weak2 = weak.clone();
        conn.register_object(ITEM_PATH, &item_iface)
            .method_call(move |_, _, _, _, method, _params, inv| {
                if method == "Activate"
                    && let Some(t) = weak.upgrade()
                {
                    (t.on_action)(Action::Open(None));
                }
                inv.return_value(None);
            })
            .property(move |_, _, _, _, prop| match weak2.upgrade() {
                Some(t) => t.item_property(prop),
                None => "".to_variant(),
            })
            .build()?;

        let weak = Rc::downgrade(&tray);
        let weak2 = weak.clone();
        conn.register_object(MENU_PATH, &menu_iface)
            .method_call(
                move |_, _, _, _, method, params, inv| match weak.upgrade() {
                    Some(t) => t.menu_call(method, &params, inv),
                    None => inv.return_value(None),
                },
            )
            .property(move |_, _, _, _, prop| match (weak2.upgrade(), prop) {
                (_, "Version") => 3u32.to_variant(),
                (_, "TextDirection") => "ltr".to_variant(),
                (_, "Status") => "normal".to_variant(),
                _ => Vec::<String>::new().to_variant(),
            })
            .build()?;

        // Own a well-known name and (re-)register whenever a watcher shows up,
        // e.g. after GNOME Shell restarts.
        // The ids are plain handles; ownership and watching last until unowned/unwatched.
        let _ = gio::bus_own_name_on_connection(
            &conn,
            &bus_name,
            gio::BusNameOwnerFlags::NONE,
            |_, _| {},
            |_, _| {},
        );
        let weak = Rc::downgrade(&tray);
        let _ = gio::bus_watch_name_on_connection(
            &conn,
            "org.kde.StatusNotifierWatcher",
            gio::BusNameWatcherFlags::NONE,
            move |_, _, _| {
                if let Some(t) = weak.upgrade() {
                    t.register();
                }
            },
            |_, _| {},
        );
        Ok(tray)
    }

    fn register(self: &Rc<Self>) {
        let weak = Rc::downgrade(self);
        self.conn.call(
            Some("org.kde.StatusNotifierWatcher"),
            "/StatusNotifierWatcher",
            "org.kde.StatusNotifierWatcher",
            "RegisterStatusNotifierItem",
            Some(&(self.bus_name.as_str(),).to_variant()),
            None,
            gio::DBusCallFlags::NONE,
            5000,
            gio::Cancellable::NONE,
            move |res| {
                let Some(t) = weak.upgrade() else { return };
                match res {
                    Ok(_) => {
                        if !t.registered.replace(true) {
                            (t.on_registered)();
                        }
                    }
                    Err(e) => eprintln!("deepwork: tray registration failed: {e}"),
                }
            },
        );
    }

    fn item_property(&self, prop: &str) -> Variant {
        let look = self.look.borrow();
        match prop {
            "Category" => "ApplicationStatus".to_variant(),
            "Id" => "deepwork".to_variant(),
            "Title" => look.title.to_variant(),
            "Status" => "Active".to_variant(),
            "WindowId" => 0i32.to_variant(),
            "IconThemePath" => self.icon_dir.to_string_lossy().to_string().to_variant(),
            "IconName" => format!("deepwork-{}-symbolic", look.icon).to_variant(),
            "IconPixmap" => self
                .pixmaps
                .get(look.icon)
                .cloned()
                .unwrap_or_default()
                .to_variant(),
            "OverlayIconPixmap" | "AttentionIconPixmap" => Vec::<Pixmap>::new().to_variant(),
            "ToolTip" => (
                "",
                Vec::<Pixmap>::new(),
                look.title.as_str(),
                look.tooltip.as_str(),
            )
                .to_variant(),
            "ItemIsMenu" => false.to_variant(),
            "Menu" => glib::variant::ObjectPath::try_from(MENU_PATH)
                .unwrap()
                .to_variant(),
            "XAyatanaLabel" => look.label.to_variant(),
            "XAyatanaLabelGuide" => "00h 00m".to_variant(),
            _ => "".to_variant(),
        }
    }

    fn menu_call(self: &Rc<Self>, method: &str, params: &Variant, inv: gio::DBusMethodInvocation) {
        let menu = self.menu.borrow();
        match method {
            "GetLayout" => {
                let (parent, depth, _): (i32, i32, Vec<String>) =
                    params.get().unwrap_or((0, -1, vec![]));
                inv.return_value(Some(
                    &(self.revision.get(), menu.layout(parent, depth)).to_variant(),
                ));
            }
            "GetGroupProperties" => {
                let (ids, _): (Vec<i32>, Vec<String>) = params.get().unwrap_or_default();
                let ids: Vec<i32> = if ids.is_empty() {
                    menu.items.iter().map(|i| i.0).collect()
                } else {
                    ids
                };
                let props: Vec<(i32, HashMap<String, Variant>)> = ids
                    .into_iter()
                    .filter(|id| menu.get(*id).is_some())
                    .map(|id| (id, menu.props(id)))
                    .collect();
                inv.return_value(Some(&(props,).to_variant()));
            }
            "GetProperty" => {
                let (id, name): (i32, String) = params.get().unwrap_or_default();
                let v = menu
                    .props(id)
                    .remove(&name)
                    .unwrap_or_else(|| "".to_variant());
                inv.return_value(Some(&(v,).to_variant()));
            }
            "Event" => {
                let id = params.child_value(0).get::<i32>().unwrap_or(-1);
                let event = params.child_value(1).get::<String>().unwrap_or_default();
                if event == "clicked" {
                    self.dispatch(&menu, id);
                }
                inv.return_value(None);
            }
            "EventGroup" => {
                let events = params.child_value(0);
                for i in 0..events.n_children() {
                    let e = events.child_value(i);
                    let id = e.child_value(0).get::<i32>().unwrap_or(-1);
                    if e.child_value(1).get::<String>().as_deref() == Some("clicked") {
                        self.dispatch(&menu, id);
                    }
                }
                inv.return_value(Some(&(Vec::<i32>::new(),).to_variant()));
            }
            "AboutToShow" => inv.return_value(Some(&(false,).to_variant())),
            "AboutToShowGroup" => {
                inv.return_value(Some(&(Vec::<i32>::new(), Vec::<i32>::new()).to_variant()))
            }
            _ => inv.return_value(None),
        }
    }

    fn dispatch(self: &Rc<Self>, menu: &Menu, id: i32) {
        let Some(action) = menu.get(id).and_then(|i| i.1.action.clone()) else {
            return;
        };
        if action == Action::ToggleTimer {
            let on = !self.show_timer.get();
            self.show_timer.set(on);
            save_show_timer(on);
        }
        // Run after the D-Bus reply so dialogs and window changes don't block it.
        let t = self.clone();
        glib::idle_add_local_once(move || (t.on_action)(action));
    }

    /// Recompute icon, label and menu from the latest status.
    pub fn update(&self, store: &Store) {
        let status = store.status();
        let (look, items) = compute(status.as_ref(), deepwork_core::now(), self.show_timer.get());
        let old = self.look.replace(look.clone());
        if old.icon != look.icon {
            self.emit_item("NewIcon", None);
        }
        if old.tooltip != look.tooltip || old.title != look.title {
            self.emit_item("NewToolTip", None);
            self.emit_item("NewTitle", None);
        }
        if old.label != look.label {
            self.emit_item(
                "XAyatanaNewLabel",
                Some((look.label.as_str(), "00h 00m").to_variant()),
            );
        }

        let sig = format!("{items:?}");
        if *self.menu_sig.borrow() != sig {
            *self.menu_sig.borrow_mut() = sig;
            *self.menu.borrow_mut() = Menu::build(items);
            self.revision.set(self.revision.get() + 1);
            let _ = self.conn.emit_signal(
                None,
                MENU_PATH,
                MENU_IFACE,
                "LayoutUpdated",
                Some(&(self.revision.get(), 0i32).to_variant()),
            );
        }
    }

    fn emit_item(&self, signal: &str, args: Option<Variant>) {
        let _ = self
            .conn
            .emit_signal(None, ITEM_PATH, ITEM_IFACE, signal, args.as_ref());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use deepwork_core::model::BlockConfig;

    fn block(active: bool, locked: bool) -> BlockStatus {
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

    fn status(blocks: Vec<BlockStatus>) -> Status {
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

    #[test]
    fn idle_and_offline() {
        let (look, items) = compute(None, 0.0, true);
        assert_eq!(look.icon, "offline");
        assert!(items.iter().any(|i| i.action == Some(Action::Quit)));
        let (look, items) = compute(Some(&status(vec![block(false, false)])), 0.0, true);
        assert_eq!(look.icon, "idle");
        assert_eq!(look.label, "");
        assert!(items.iter().any(|i| i.label == "Start a block"));
    }

    #[test]
    fn locked_block_shows_timer_and_unlock() {
        let (look, items) = compute(Some(&status(vec![block(true, true)])), 0.0, true);
        assert_eq!(look.icon, "locked");
        assert_eq!(look.label, "1h 05m");
        let sub = items.iter().find(|i| i.label.contains("Social")).unwrap();
        assert!(
            sub.children
                .iter()
                .any(|c| c.action == Some(Action::Unlock("b1".into())))
        );
        assert!(
            !sub.children
                .iter()
                .any(|c| c.action == Some(Action::Stop("b1".into())))
        );
        let (look, _) = compute(Some(&status(vec![block(true, true)])), 0.0, false);
        assert_eq!(look.label, "");
    }

    #[test]
    fn menu_layout_ids() {
        let (_, items) = compute(Some(&status(vec![block(true, false)])), 0.0, true);
        let m = Menu::build(items);
        let (id, _, children) = m.layout(0, -1);
        assert_eq!(id, 0);
        assert!(!children.is_empty());
        let v = (1u32, m.layout(0, -1)).to_variant();
        assert_eq!(v.type_().as_str(), "(u(ia{sv}av))");
        // every id resolves
        for (id, _, kids) in &m.items {
            assert!(m.get(*id).is_some());
            for k in kids {
                assert!(m.get(*k).is_some());
            }
        }
    }
}
