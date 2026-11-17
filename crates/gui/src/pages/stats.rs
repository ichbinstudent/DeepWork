//! "Statistics" page.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use adw::prelude::*;
use deepwork_core::DAY_NAMES;
use deepwork_core::model::{DAY, today_key};
use deepwork_core::protocol::Stats;

use crate::util::{clear_listbox, pill, short_duration, signature};
use crate::widgets::chart::{Bar, BarChart};
use crate::window::Ctx;

struct Tile {
    value: gtk::Label,
}

fn tile(label: &str) -> (gtk::Box, Tile) {
    let b = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(4)
        .build();
    b.add_css_class("stat-tile");
    let value = gtk::Label::builder()
        .xalign(0.0)
        .css_classes(["stat-value"])
        .build();
    let l = gtk::Label::builder()
        .label(label)
        .xalign(0.0)
        .wrap(true)
        .css_classes(["stat-label"])
        .build();
    b.append(&l);
    b.append(&value);
    (b, Tile { value })
}

fn day_key(offset: i64, now: f64) -> String {
    today_key(now - offset as f64 * DAY)
}

pub fn build(ctx: &Rc<Ctx>) -> gtk::Widget {
    let header = adw::HeaderBar::new();
    let refresh = gtk::Button::builder()
        .icon_name("view-refresh-symbolic")
        .tooltip_text("Refresh")
        .build();
    header.pack_end(&refresh);

    let content = gtk::Box::new(gtk::Orientation::Vertical, 24);

    // Four tiles in a row; two rows of two when the window is narrow.
    let tiles = gtk::Box::builder().spacing(12).homogeneous(true).build();
    let (t1, today) = tile("FOCUSED TODAY");
    let (t2, week) = tile("LAST 7 DAYS");
    let (t3, streak) = tile("DAY STREAK");
    let (t4, blocked) = tile("STOPPED THIS WEEK");
    for pair in [[t1, t2], [t3, t4]] {
        let row = gtk::Box::builder().spacing(12).homogeneous(true).build();
        for t in pair {
            row.append(&t);
        }
        tiles.append(&row);
    }
    ctx.narrow.add_setter(
        &tiles,
        "orientation",
        Some(&gtk::Orientation::Vertical.to_value()),
    );
    content.append(&tiles);

    let chart = BarChart::new();
    let chart_card = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(12)
        .build();
    chart_card.add_css_class("chart-card");
    chart_card.append(
        &gtk::Label::builder()
            .label("Focus time, last 14 days")
            .xalign(0.0)
            .css_classes(["heading"])
            .build(),
    );
    chart_card.append(&chart.area);
    content.append(&chart_card);

    let top = adw::PreferencesGroup::builder()
        .title("Most blocked apps")
        .description("Times an app was closed in the last 30 days")
        .build();
    let top_list = gtk::ListBox::builder()
        .selection_mode(gtk::SelectionMode::None)
        .build();
    top_list.add_css_class("boxed-list");
    top.add(&top_list);
    content.append(&top);

    let sig = Rc::new(RefCell::new(String::new()));
    let update = {
        let ctx = ctx.clone();
        move || {
            let stats: Stats = ctx.store.stats();
            let s = signature(&stats);
            if *sig.borrow() == s {
                return;
            }
            *sig.borrow_mut() = s;
            let now = deepwork_core::now();
            let get = |k: &str| stats.get(k).cloned().unwrap_or_default();

            today
                .value
                .set_label(&short_duration(get(&day_key(0, now)).focus_seconds));
            let last7: Vec<_> = (0..7).map(|i| get(&day_key(i, now))).collect();
            week.value
                .set_label(&short_duration(last7.iter().map(|d| d.focus_seconds).sum()));
            blocked.value.set_label(
                &last7
                    .iter()
                    .map(|d| d.blocked_apps)
                    .sum::<u32>()
                    .to_string(),
            );
            // Streak: consecutive days with at least 10 minutes of focus (today counts if reached).
            let mut n = 0;
            for i in 0..365 {
                let f = get(&day_key(i, now)).focus_seconds;
                if f >= 600.0 {
                    n += 1;
                } else if i > 0 {
                    break;
                }
            }
            streak.value.set_label(&n.to_string());

            let bars = (0..14)
                .rev()
                .map(|i| {
                    let ts = now - i as f64 * DAY;
                    let wd = deepwork_core::model::minute_of_week(ts) as usize / 1440;
                    Bar {
                        label: if i == 0 {
                            "Today".into()
                        } else {
                            DAY_NAMES[wd.min(6)].into()
                        },
                        value: get(&day_key(i, now)).focus_seconds / 3600.0,
                        highlight: i == 0,
                    }
                })
                .collect();
            chart.set(bars);

            let mut apps: BTreeMap<String, u32> = BTreeMap::new();
            for i in 0..30 {
                for (app, n) in get(&day_key(i, now)).apps {
                    *apps.entry(app).or_default() += n;
                }
            }
            let mut apps: Vec<_> = apps.into_iter().collect();
            apps.sort_by_key(|&(_, n)| std::cmp::Reverse(n));
            clear_listbox(&top_list);
            for (app, n) in apps.iter().take(8) {
                let row = adw::ActionRow::builder()
                    .title(gtk::glib::markup_escape_text(app).as_str())
                    .build();
                row.add_suffix(&pill(&n.to_string(), ""));
                top_list.append(&row);
            }
            top.set_visible(!apps.is_empty());
        }
    };
    update();
    ctx.store.subscribe(update.clone());
    {
        let ctx = ctx.clone();
        refresh.connect_clicked(move |_| {
            ctx.store.refresh_stats();
            update();
        });
    }

    crate::pages::page_shell(&content, &header).upcast()
}
