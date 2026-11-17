//! No tray icon on this system yet. Without one, closing the window quits
//! the app (blocking carries on in the service).

use std::rc::Rc;

use gtk::{gio, glib};

use crate::platform::Action;
use crate::store::Store;

pub struct Tray;

impl Tray {
    pub fn start(
        _conn: gio::DBusConnection,
        _on_action: impl Fn(Action) + 'static,
        _on_registered: impl Fn() + 'static,
    ) -> Result<Rc<Self>, glib::Error> {
        Err(glib::Error::new(
            gio::IOErrorEnum::NotSupported,
            "no tray icon on this system yet",
        ))
    }

    pub fn update(&self, _store: &Store) {}
}
