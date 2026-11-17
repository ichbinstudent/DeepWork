//! DeepWork — GTK4/libadwaita front-end.

mod apps;
mod dialogs;
mod editor;
mod pages;
mod platform;
mod store;
mod util;
mod widgets;
mod window;

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use adw::prelude::*;
use gtk::{gdk, gio, glib};

use crate::platform::Action;
use crate::platform::tray::Tray;
use crate::store::Store;
use crate::window::Ctx;

pub const APP_ID: &str = "io.github.ichbinstudent.DeepWork";
const RESOURCE_PREFIX: &str = "/io/github/ichbinstudent/DeepWork";

fn load_style() {
    let Some(display) = gdk::Display::default() else {
        return;
    };
    let provider = gtk::CssProvider::new();
    provider.load_from_resource(&format!("{RESOURCE_PREFIX}/style.css"));
    gtk::style_context_add_provider_for_display(
        &display,
        &provider,
        gtk::STYLE_PROVIDER_PRIORITY_APPLICATION,
    );
    gtk::IconTheme::for_display(&display).add_resource_path(&format!("{RESOURCE_PREFIX}/icons"));
}

fn send(app: &adw::Application, id: &str, title: &str, body: &str) {
    let n = gio::Notification::new(title);
    n.set_body(Some(body));
    n.set_icon(&gio::ThemedIcon::new(APP_ID));
    app.send_notification(Some(id), &n);
}

fn notify(app: &adw::Application, store: &Store) {
    for ev in store.new_events() {
        if matches!(
            ev.kind.as_str(),
            "app_blocked" | "block_started" | "block_ended" | "frozen" | "thawed" | "clock"
        ) {
            // One id per kind so repeated "app blocked" messages replace each other.
            send(app, &format!("deepwork-{}", ev.kind), &ev.title, &ev.body);
        }
    }
}

/// Everything the app-level callbacks share.
struct App {
    app: adw::Application,
    store: Rc<Store>,
    ui: RefCell<Option<Rc<Ctx>>>,
    /// Hide instead of quitting when the window closes (tray or background mode).
    keep_running: Rc<Cell<bool>>,
}

impl App {
    fn show(&self, page: Option<&str>) -> Rc<Ctx> {
        let ctx = self
            .ui
            .borrow_mut()
            .get_or_insert_with(|| {
                window::build(&self.app, self.store.clone(), self.keep_running.clone())
            })
            .clone();
        ctx.window.present();
        if let Some(p) = page {
            ctx.go(p);
        }
        ctx
    }

    /// Run a daemon request from the tray; errors become notifications.
    fn report<T>(&self, r: deepwork_core::client::Result<T>) {
        if let Err(e) = r {
            send(&self.app, "deepwork-error", "DeepWork", &e.to_string());
        }
        self.store.refresh();
    }

    fn handle(&self, action: Action) {
        let client = &self.store.client;
        let with_block = |id: &str, f: &dyn Fn(&Rc<Ctx>, &deepwork_core::protocol::BlockStatus)| {
            if let Some(b) = self.store.block(id) {
                f(&self.show(Some("focus")), &b);
            }
        };
        match action {
            Action::Open(page) => {
                self.show(page);
            }
            Action::Start(id, m) => self.report(client.start_block(&id, m)),
            Action::AddTime(id, m) => {
                let m = self
                    .store
                    .block(&id)
                    .map(|b| dialogs::effective_minutes(&b, m))
                    .unwrap_or(m);
                self.report(client.start_block(&id, m));
            }
            Action::Stop(id) => self.report(client.stop_block(&id)),
            Action::EndBreak(id) => self.report(client.end_break(&id)),
            Action::StartCustom(id) => with_block(&id, &|ctx, b| dialogs::start(ctx, b)),
            Action::Unlock(id) => with_block(&id, &|ctx, b| dialogs::unlock(ctx, b)),
            Action::Break(id) => with_block(&id, &|ctx, b| dialogs::take_break(ctx, b)),
            Action::ToggleTimer => self.store.refresh(),
            Action::Quit => self.app.quit(),
        }
    }
}

fn main() -> glib::ExitCode {
    gio::resources_register_include!("deepwork.gresource").expect("embedded resources");

    let background = std::env::args().any(|a| a == "--background");
    let adw_app = adw::Application::builder().application_id(APP_ID).build();
    let app = Rc::new(App {
        app: adw_app.clone(),
        store: Rc::new(Store::new()),
        ui: RefCell::new(None),
        keep_running: Rc::new(Cell::new(background)),
    });
    let skip_first_window = Rc::new(Cell::new(background));

    {
        let app = app.clone();
        adw_app.connect_startup(move |gapp| {
            load_style();
            gtk::Window::set_default_icon_name(APP_ID);
            if background {
                // Keep running without a window for the tray and notifications.
                std::mem::forget(gapp.hold());
            }

            let about = gio::ActionEntry::builder("about")
                .activate(|gapp: &adw::Application, _, _| {
                    let dialog = adw::AboutDialog::builder()
                        .application_name("DeepWork")
                        .application_icon(APP_ID)
                        .version(deepwork_core::VERSION)
                        .developer_name("DeepWork contributors")
                        .license_type(gtk::License::Gpl30)
                        .comments("Block distracting websites and apps, on a schedule or on demand, with locks you can't easily talk your way out of.")
                        .build();
                    dialog.present(gapp.active_window().as_ref());
                })
                .build();
            let quit = gio::ActionEntry::builder("quit")
                .activate(|gapp: &adw::Application, _, _| gapp.quit())
                .build();
            gapp.add_action_entries([about, quit]);
            gapp.set_accels_for_action("app.quit", &["<Control>q"]);
            gapp.set_accels_for_action("window.close", &["<Control>w"]);

            let store = app.store.clone();
            store.refresh();
            store.refresh_stats();
            let _ = store.new_events();

            // Top-bar indicator.
            if let Some(conn) = gapp.dbus_connection() {
                let (a1, a2) = (Rc::downgrade(&app), Rc::downgrade(&app));
                let tray = Tray::start(
                    conn,
                    move |action| {
                        if let Some(app) = a1.upgrade() {
                            app.handle(action);
                        }
                    },
                    move || {
                        // With a tray icon there is always a way back to the window.
                        if let Some(app) = a2.upgrade() {
                            app.keep_running.set(true);
                            std::mem::forget(app.app.hold());
                        }
                    },
                );
                match tray {
                    Ok(tray) => {
                        tray.update(&store);
                        let s = store.clone();
                        store.subscribe(move || tray.update(&s));
                    }
                    Err(e) => eprintln!("deepwork: no tray icon: {e}"),
                }
            }

            let s = store.clone();
            glib::timeout_add_seconds_local(1, move || {
                s.refresh();
                glib::ControlFlow::Continue
            });
            let s = store.clone();
            let weak_app = gapp.downgrade();
            glib::timeout_add_seconds_local(2, move || {
                if let Some(gapp) = weak_app.upgrade()
                    && s.online()
                {
                    notify(&gapp, &s);
                }
                glib::ControlFlow::Continue
            });
            let s = store.clone();
            glib::timeout_add_seconds_local(30, move || {
                s.refresh_stats();
                glib::ControlFlow::Continue
            });
        });
    }

    {
        let app = app.clone();
        adw_app.connect_activate(move |_| {
            if skip_first_window.replace(false) {
                return;
            }
            app.show(None);
        });
    }

    // GTK doesn't know our flags; keep only the program name.
    adw_app.run_with_args(&["deepwork"])
}
