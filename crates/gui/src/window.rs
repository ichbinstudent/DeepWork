//! Main window: sidebar navigation, pages, toasts and the offline screen.

use std::cell::RefCell;
use std::rc::Rc;

use adw::prelude::*;
use deepwork_core::client;
use gtk::gio;

use crate::pages;
use crate::store::Store;

type GoTo = Box<dyn Fn(&str)>;

/// Everything pages need to talk to each other.
pub struct Ctx {
    pub store: Rc<Store>,
    pub window: adw::ApplicationWindow,
    pub toasts: adw::ToastOverlay,
    /// Navigation stack of the "Blocks" page (the editor is pushed here).
    pub blocks_nav: adw::NavigationView,
    /// Fires when the window gets narrow, so pages can adapt.
    pub narrow: adw::Breakpoint,
    go_to: RefCell<Option<GoTo>>,
}

impl Ctx {
    pub fn toast(&self, msg: &str) {
        let t = adw::Toast::new(msg);
        t.set_timeout(4);
        self.toasts.add_toast(t);
    }

    /// Show an error as a toast; refresh state on success.
    pub fn act<T>(&self, r: client::Result<T>) -> Option<T> {
        match r {
            Ok(v) => {
                self.store.refresh();
                Some(v)
            }
            Err(e) => {
                self.toast(&e.to_string());
                self.store.refresh();
                None
            }
        }
    }

    /// Switch to a sidebar page by name.
    pub fn go(&self, page: &str) {
        if let Some(f) = self.go_to.borrow().as_ref() {
            f(page);
        }
    }
}

struct NavItem {
    name: &'static str,
    title: &'static str,
    icon: &'static str,
}

const NAV: &[NavItem] = &[
    NavItem {
        name: "focus",
        title: "Focus",
        icon: "dw-focus-symbolic",
    },
    NavItem {
        name: "blocks",
        title: "Blocks",
        icon: "dw-shield-symbolic",
    },
    NavItem {
        name: "freeze",
        title: "Freeze",
        icon: "weather-snow-symbolic",
    },
    NavItem {
        name: "stats",
        title: "Statistics",
        icon: "dw-chart-symbolic",
    },
    NavItem {
        name: "settings",
        title: "Settings",
        icon: "emblem-system-symbolic",
    },
];

fn sidebar_row(item: &NavItem) -> gtk::ListBoxRow {
    let b = gtk::Box::builder()
        .spacing(12)
        .margin_top(2)
        .margin_bottom(2)
        .build();
    b.append(&gtk::Image::from_icon_name(item.icon));
    b.append(&gtk::Label::builder().label(item.title).xalign(0.0).build());
    gtk::ListBoxRow::builder().child(&b).name(item.name).build()
}

fn offline_page(store: &Rc<Store>) -> gtk::Widget {
    let retry = gtk::Button::builder()
        .label("Try again")
        .halign(gtk::Align::Center)
        .build();
    retry.add_css_class("pill");
    retry.add_css_class("suggested-action");
    let cmd = gtk::Label::builder()
        .label("sudo systemctl enable --now deepwork")
        .selectable(true)
        .css_classes(["monospace", "card"])
        .margin_bottom(12)
        .build();
    cmd.set_margin_start(8);
    let inner = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(12)
        .halign(gtk::Align::Center)
        .build();
    inner.append(&cmd);
    inner.append(&retry);
    let status = adw::StatusPage::builder()
        .icon_name("dw-shield-symbolic")
        .title("The DeepWork service isn't running")
        .description(
            "Blocking is done by a small background service that runs with administrator rights. \
             Install it with <b>sudo ./install.sh</b> from the source folder, or start it with:",
        )
        .child(&inner)
        .vexpand(true)
        .build();
    let s = store.clone();
    retry.connect_clicked(move |_| s.refresh());
    let tv = adw::ToolbarView::new();
    tv.add_top_bar(&adw::HeaderBar::new());
    tv.set_content(Some(&status));
    tv.upcast()
}

/// Build the main window. When `keep_running` is true, closing the window only
/// hides it (the app lives on in the tray).
pub fn build(
    app: &adw::Application,
    store: Rc<Store>,
    keep_running: Rc<std::cell::Cell<bool>>,
) -> Rc<Ctx> {
    let window = adw::ApplicationWindow::builder()
        .application(app)
        .title("DeepWork")
        .default_width(1060)
        .default_height(760)
        .width_request(360)
        .height_request(480)
        .build();
    let toasts = adw::ToastOverlay::new();
    let narrow = adw::Breakpoint::new(
        adw::BreakpointCondition::parse("max-width: 720sp").expect("condition"),
    );
    window.add_breakpoint(narrow.clone());

    let ctx = Rc::new(Ctx {
        store: store.clone(),
        window: window.clone(),
        toasts: toasts.clone(),
        blocks_nav: adw::NavigationView::new(),
        narrow: narrow.clone(),
        go_to: RefCell::new(None),
    });

    // ---------------------------------------------------------------- content
    // Not homogeneous: the window's minimum size follows the visible page only.
    let stack = gtk::Stack::builder()
        .transition_type(gtk::StackTransitionType::Crossfade)
        .hhomogeneous(false)
        .vhomogeneous(false)
        .build();
    stack.add_named(&pages::dashboard::build(&ctx), Some("focus"));
    stack.add_named(&pages::blocks::build(&ctx), Some("blocks"));
    stack.add_named(&pages::freeze::build(&ctx), Some("freeze"));
    stack.add_named(&pages::stats::build(&ctx), Some("stats"));
    stack.add_named(&pages::settings::build(&ctx), Some("settings"));
    let content = adw::NavigationPage::builder()
        .title("Focus")
        .child(&stack)
        .build();

    // ---------------------------------------------------------------- sidebar
    let list = gtk::ListBox::new();
    list.add_css_class("navigation-sidebar");
    for item in NAV {
        list.append(&sidebar_row(item));
    }
    let service_dot = gtk::Box::builder().valign(gtk::Align::Center).build();
    service_dot.add_css_class("status-dot");
    let service_label = gtk::Label::builder().xalign(0.0).wrap(true).build();
    let service = gtk::Box::builder().spacing(10).build();
    service.add_css_class("service-status");
    service.append(&service_dot);
    service.append(&service_label);

    let menu = gio::Menu::new();
    menu.append(Some("About DeepWork"), Some("app.about"));
    menu.append(Some("Quit"), Some("app.quit"));
    let menu_btn = gtk::MenuButton::builder()
        .icon_name("open-menu-symbolic")
        .menu_model(&menu)
        .primary(true)
        .build();
    let side_header = adw::HeaderBar::new();
    side_header.pack_end(&menu_btn);
    let side_box = gtk::Box::new(gtk::Orientation::Vertical, 0);
    let scroller = gtk::ScrolledWindow::builder()
        .vexpand(true)
        .child(&list)
        .hscrollbar_policy(gtk::PolicyType::Never)
        .build();
    side_box.append(&scroller);
    side_box.append(&service);
    let side_tv = adw::ToolbarView::new();
    side_tv.add_top_bar(&side_header);
    side_tv.set_content(Some(&side_box));
    let sidebar = adw::NavigationPage::builder()
        .title("DeepWork")
        .child(&side_tv)
        .build();

    let split = adw::NavigationSplitView::builder()
        .sidebar(&sidebar)
        .content(&content)
        .min_sidebar_width(200.0)
        .max_sidebar_width(260.0)
        .build();
    narrow.add_setter(&split, "collapsed", Some(&true.to_value()));

    {
        let stack = stack.clone();
        let content = content.clone();
        let split = split.clone();
        list.connect_row_selected(move |_, row| {
            let Some(row) = row else { return };
            let name = row.widget_name();
            if let Some(item) = NAV.iter().find(|i| i.name == name.as_str()) {
                stack.set_visible_child_name(item.name);
                content.set_title(item.title);
                split.set_show_content(true);
            }
        });
    }
    {
        let list = list.clone();
        *ctx.go_to.borrow_mut() = Some(Box::new(move |name: &str| {
            let mut i = 0;
            while let Some(row) = list.row_at_index(i) {
                if row.widget_name() == name {
                    list.select_row(Some(&row));
                }
                i += 1;
            }
        }));
    }
    list.select_row(list.row_at_index(0).as_ref());

    // ---------------------------------------------------------------- online / offline
    let top = gtk::Stack::builder()
        .transition_type(gtk::StackTransitionType::Crossfade)
        .build();
    top.add_named(&split, Some("main"));
    top.add_named(&offline_page(&store), Some("offline"));
    toasts.set_child(Some(&top));
    window.set_content(Some(&toasts));

    let update = {
        let store = store.clone();
        let top = top.clone();
        move || {
            let online = store.online();
            top.set_visible_child_name(if online { "main" } else { "offline" });
            if online {
                let s = store.status().unwrap();
                let now = deepwork_core::now();
                let n = s.blocks.iter().filter(|b| b.enforcing).count();
                service_dot.remove_css_class("offline");
                service_label.set_label(&if s.frozen_until > now {
                    "Frozen".to_string()
                } else if n > 0 {
                    format!(
                        "Protecting you · {}",
                        crate::util::plural(n, "block", "blocks")
                    )
                } else {
                    "Service running".to_string()
                });
            } else {
                service_dot.add_css_class("offline");
                service_label.set_label("Service offline");
            }
        }
    };
    update();
    store.subscribe(update);

    #[cfg(debug_assertions)]
    debug_hooks(&ctx);

    window.connect_close_request(move |w| {
        if keep_running.get() {
            w.set_visible(false);
            gtk::glib::Propagation::Stop
        } else {
            gtk::glib::Propagation::Proceed
        }
    });
    ctx
}

/// Development aid: `DEEPWORK_DEBUG_PAGE=stats`, `DEEPWORK_DEBUG_OPEN=edit|start|unlock|apps|new`
/// and `DEEPWORK_DEBUG_SHOT=/path.png` render the window to a PNG and quit.
#[cfg(debug_assertions)]
fn debug_hooks(ctx: &Rc<Ctx>) {
    use gtk::glib;
    if let Some((w, h)) = std::env::var("DEEPWORK_DEBUG_SIZE").ok().and_then(|s| {
        let (w, h) = s.split_once('x')?;
        Some((w.parse().ok()?, h.parse().ok()?))
    }) {
        ctx.window.set_default_size(w, h);
    }
    if let Ok(page) = std::env::var("DEEPWORK_DEBUG_PAGE") {
        ctx.go(&page);
    }
    let ctx2 = ctx.clone();
    glib::timeout_add_local_once(std::time::Duration::from_millis(600), move || {
        let first = ctx2.store.status().and_then(|s| s.blocks.first().cloned());
        match (std::env::var("DEEPWORK_DEBUG_OPEN").as_deref(), first) {
            (Ok("new"), _) => crate::editor::open(&ctx2, None),
            (Ok("edit"), Some(b)) => crate::editor::open(&ctx2, Some(&b)),
            (Ok("start"), Some(b)) => crate::dialogs::start(&ctx2, &b),
            (Ok("unlock"), Some(b)) => crate::dialogs::unlock(&ctx2, &b),
            (Ok("apps"), _) => crate::dialogs::choose_app(&ctx2, |_| {}),
            (Ok("lists"), Some(b)) => {
                crate::dialogs::choose_lists(&ctx2, b.config.lists.clone(), vec![], |_| {})
            }
            _ => {}
        }
    });
    if let Some(frac) = std::env::var("DEEPWORK_DEBUG_SCROLL")
        .ok()
        .and_then(|s| s.parse::<f64>().ok())
    {
        let win = ctx.window.clone();
        glib::timeout_add_local_once(std::time::Duration::from_millis(1800), move || {
            fn walk(w: &gtk::Widget, frac: f64) {
                if let Some(sw) = w.downcast_ref::<gtk::ScrolledWindow>()
                    && sw.is_mapped()
                {
                    let a = sw.vadjustment();
                    a.set_value((a.upper() - a.page_size()) * frac);
                }
                let mut c = w.first_child();
                while let Some(ch) = c {
                    walk(&ch, frac);
                    c = ch.next_sibling();
                }
            }
            walk(win.upcast_ref(), frac);
        });
    }
    let Ok(path) = std::env::var("DEEPWORK_DEBUG_SHOT") else {
        return;
    };
    // Headless backends don't tick the frame clock, so animations would never finish.
    if let Some(settings) = gtk::Settings::default() {
        settings.set_gtk_enable_animations(false);
    }
    let win = ctx.window.clone();
    glib::timeout_add_local_once(std::time::Duration::from_millis(2500), move || {
        let target: gtk::Widget = win.clone().upcast();
        let (w, h) = (target.width(), target.height());
        eprintln!("debug shot: {} {w}x{h}", target.type_().name());
        let paintable = gtk::WidgetPaintable::new(Some(&target));
        let snap = gtk::Snapshot::new();
        paintable.snapshot(&snap, w as f64, h as f64);
        match (snap.to_node(), win.renderer()) {
            (Some(node), Some(renderer)) => {
                let tex = renderer.render_texture(&node, None);
                if let Err(e) = tex.save_to_png(&path) {
                    eprintln!("debug shot: save failed: {e}");
                }
            }
            (n, r) => eprintln!("debug shot: node={} renderer={}", n.is_some(), r.is_some()),
        }
        if let Some(app) = win.application() {
            app.quit();
        }
    });
}
