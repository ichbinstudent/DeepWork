//! "Freeze" page: lock the whole computer for a while.

use std::cell::Cell;
use std::rc::Rc;

use adw::prelude::*;
use deepwork_core::{format_clock, format_duration, format_time};

use crate::window::Ctx;

const CHOICES: &[(u32, &str)] = &[
    (15, "15 min"),
    (30, "30 min"),
    (60, "1 hour"),
    (120, "2 hours"),
    (240, "4 hours"),
];

const DESCRIPTION: &str = "Lock your whole computer for a while. The screen locks right away and \
     locks again every time it's unlocked, until the timer runs out. There's no way to end it early.";

pub fn build(ctx: &Rc<Ctx>) -> gtk::Widget {
    let header = adw::HeaderBar::new();
    let minutes = Rc::new(Cell::new(30u32));

    let toggles = adw::ToggleGroup::builder()
        .halign(gtk::Align::Center)
        .build();
    toggles.add_css_class("round");
    for (m, label) in CHOICES {
        toggles.add(
            adw::Toggle::builder()
                .label(*label)
                .name(m.to_string())
                .build(),
        );
    }
    toggles.set_active_name(Some("30"));
    let custom = adw::SpinRow::with_range(1.0, 720.0, 5.0);
    custom.set_title("Minutes");
    custom.set_value(30.0);
    let group = adw::PreferencesGroup::new();
    group.add(&custom);

    let go = gtk::Button::builder()
        .label("Freeze for 30 min")
        .halign(gtk::Align::Center)
        .build();
    go.add_css_class("pill");
    go.add_css_class("destructive-action");

    let controls = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(18)
        .build();
    controls.append(&toggles);
    controls.append(&group);
    controls.append(&go);

    let countdown = gtk::Label::builder()
        .css_classes(["duration-big"])
        .visible(false)
        .build();
    let inner = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(18)
        .build();
    inner.append(&countdown);
    inner.append(&controls);
    let clamp = adw::Clamp::builder()
        .maximum_size(480)
        .child(&inner)
        .build();

    let status = adw::StatusPage::builder()
        .icon_name("weather-snow-symbolic")
        .title("Freeze")
        .description(DESCRIPTION)
        .child(&clamp)
        .vexpand(true)
        .build();

    let set_minutes = {
        let (minutes, go) = (minutes.clone(), go.clone());
        move |m: u32| {
            minutes.set(m);
            go.set_label(&format!("Freeze for {}", format_duration(m as f64 * 60.0)));
        }
    };
    {
        let (set_minutes, custom) = (set_minutes.clone(), custom.clone());
        toggles.connect_active_name_notify(move |t| {
            if let Some(m) = t.active_name().and_then(|n| n.parse::<u32>().ok()) {
                custom.set_value(m as f64);
                set_minutes(m);
            }
        });
    }
    {
        let toggles = toggles.clone();
        custom.connect_value_notify(move |c| {
            let m = c.value() as u32;
            set_minutes(m);
            match CHOICES.iter().find(|(x, _)| *x == m) {
                Some((x, _)) => toggles.set_active_name(Some(&x.to_string())),
                None => toggles.set_active(gtk::INVALID_LIST_POSITION),
            }
        });
    }
    {
        let ctx = ctx.clone();
        go.connect_clicked(move |_| {
            let m = minutes.get();
            let until = format_time(deepwork_core::now() + m as f64 * 60.0);
            let d = adw::AlertDialog::new(
                Some(&format!("Freeze for {}?", format_duration(m as f64 * 60.0))),
                Some(&format!(
                    "Save your work first. Your screen will lock now and keep locking until {until}. This can't be cancelled."
                )),
            );
            d.add_response("cancel", "Cancel");
            d.add_response("freeze", "Freeze");
            d.set_response_appearance("freeze", adw::ResponseAppearance::Destructive);
            d.set_default_response(Some("cancel"));
            let ctx2 = ctx.clone();
            d.connect_response(None, move |_, r| {
                if r == "freeze" {
                    ctx2.act(ctx2.store.client.freeze(m));
                }
            });
            d.present(Some(&ctx.window));
        });
    }

    let update = {
        let ctx = ctx.clone();
        let status = status.clone();
        move || {
            let Some(s) = ctx.store.status() else { return };
            let now = deepwork_core::now();
            let frozen = s.frozen_until > now;
            let caps = ctx.store.capabilities();
            controls.set_sensitive(caps.freeze);
            status.set_description(Some(&if caps.freeze {
                DESCRIPTION.to_string()
            } else {
                format!("Freeze isn't available on {} yet.", caps.os)
            }));
            controls.set_visible(!frozen);
            countdown.set_visible(frozen);
            if frozen {
                status.set_title(&format!("Frozen until {}", format_time(s.frozen_until)));
                countdown.set_label(&format_clock(s.frozen_until - now));
            } else {
                status.set_title("Freeze");
            }
        }
    };
    update();
    ctx.store.subscribe(update);

    let tv = adw::ToolbarView::new();
    tv.add_top_bar(&header);
    tv.set_content(Some(&status));
    tv.upcast()
}
