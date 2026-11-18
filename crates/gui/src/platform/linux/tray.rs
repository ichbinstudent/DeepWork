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

use gtk::gio;
use gtk::glib::{self, Variant};
use gtk::prelude::*;

use crate::platform::Action;
use crate::platform::tray_menu::{
    ICONS, Item, Look, compute, icon_svg, load_show_timer, render, save_show_timer,
};
use crate::store::Store;

const ITEM_PATH: &str = "/StatusNotifierItem";
const MENU_PATH: &str = "/MenuBar";
const ITEM_IFACE: &str = "org.kde.StatusNotifierItem";
const MENU_IFACE: &str = "com.canonical.dbusmenu";

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
        if let Some(icon) = item.icon {
            p.insert("icon-name".into(), icon.to_variant());
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
    let mut out = vec![];
    for size in [22, 32, 48] {
        let Some(pb) = render(name, size, "#ffffff") else {
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

// ----------------------------------------------------------------------------- D-Bus plumbing

impl Tray {
    pub fn start(
        app: &adw::Application,
        on_action: impl Fn(Action) + 'static,
        on_registered: impl Fn() + 'static,
    ) -> Result<Rc<Self>, glib::Error> {
        let conn = app.dbus_connection().ok_or_else(|| {
            glib::Error::new(gio::IOErrorEnum::NotConnected, "no D-Bus session bus")
        })?;
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
        let (look, items) = compute(
            status.as_ref(),
            deepwork_core::now(),
            Some(self.show_timer.get()),
        );
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
    use crate::platform::tray_menu::test_util::*;

    #[test]
    fn menu_layout_ids() {
        let (_, items) = compute(Some(&status(vec![block(true, false)])), 0.0, Some(true));
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
