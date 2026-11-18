//! "Focus" page: what's running now and a quick way to start something.

use std::cell::RefCell;
use std::rc::Rc;

use adw::prelude::*;
use deepwork_core::model::LockKind;
use deepwork_core::protocol::{BlockStatus, Status};
use deepwork_core::{format_clock, format_duration, format_time, model::today_key};

use crate::dialogs;
use crate::editor;
use crate::util::{
    badge, block_summary, clear_listbox, color_rgba, dot, live_line, pill, plural, short_duration,
    signature, text_button,
};
use crate::widgets::ring::Ring;
use crate::window::Ctx;

fn active_row(ctx: &Rc<Ctx>, b: &BlockStatus) -> (adw::ActionRow, BlockStatus) {
    let row = adw::ActionRow::builder()
        .title(glib_escape(&b.config.name))
        .build();
    row.set_subtitle(&live_line(b, deepwork_core::now()));
    row.add_prefix(&dot(&b.config.color));

    let (text, class) = badge(b);
    row.add_suffix(&pill(text, class));

    if b.paused {
        let btn = text_button("End Break", &["flat"]);
        let (ctx, id) = (ctx.clone(), b.id.clone());
        btn.connect_clicked(move |_| {
            ctx.act(ctx.store.client.end_break(&id));
        });
        row.add_suffix(&btn);
    } else if b.config.allowance_minutes > 0 && b.allowance_left >= 60.0 {
        let btn = gtk::Button::builder()
            .icon_name("dw-coffee-symbolic")
            .tooltip_text(format!(
                "Take a break ({} left today)",
                format_duration(b.allowance_left)
            ))
            .valign(gtk::Align::Center)
            .build();
        btn.add_css_class("flat");
        let (ctx, b2) = (ctx.clone(), b.clone());
        btn.connect_clicked(move |_| dialogs::take_break(&ctx, &b2));
        row.add_suffix(&btn);
    }

    let more = gtk::Button::builder()
        .icon_name("list-add-symbolic")
        .tooltip_text("Add time")
        .valign(gtk::Align::Center)
        .build();
    more.add_css_class("flat");
    {
        let (ctx, id) = (ctx.clone(), b.id.clone());
        more.connect_clicked(move |_| {
            if let Some(b) = ctx.store.block(&id) {
                dialogs::start(&ctx, &b);
            }
        });
    }
    row.add_suffix(&more);

    if b.locked {
        let unlockable =
            !b.protected && matches!(b.config.lock, LockKind::Random | LockKind::Password);
        let btn = gtk::Button::builder()
            .icon_name("changes-prevent-symbolic")
            .tooltip_text(if unlockable { "Unlock" } else { "Locked" })
            .valign(gtk::Align::Center)
            .build();
        btn.add_css_class("flat");
        let (ctx, id) = (ctx.clone(), b.id.clone());
        btn.connect_clicked(move |_| {
            if let Some(b) = ctx.store.block(&id) {
                dialogs::unlock(&ctx, &b);
            }
        });
        row.add_suffix(&btn);
    } else {
        let stop = text_button("Stop", &["flat", "error"]);
        let (ctx, id) = (ctx.clone(), b.id.clone());
        stop.connect_clicked(move |_| {
            ctx.act(ctx.store.client.stop_block(&id));
        });
        row.add_suffix(&stop);
    }
    (row, b.clone())
}

fn idle_row(ctx: &Rc<Ctx>, b: &BlockStatus) -> adw::ActionRow {
    let row = adw::ActionRow::builder()
        .title(glib_escape(&b.config.name))
        .subtitle(glib_escape(&block_summary(&b.config)))
        .activatable(true)
        .build();
    row.add_prefix(&dot(&b.config.color));
    if b.config.lock != LockKind::None {
        let img = gtk::Image::from_icon_name("changes-prevent-symbolic");
        img.set_tooltip_text(Some(b.config.lock.label()));
        img.add_css_class("dim-label");
        row.add_suffix(&img);
    }
    let start = text_button("Start", &[]);
    {
        let (ctx, b) = (ctx.clone(), b.clone());
        start.connect_clicked(move |_| dialogs::start(&ctx, &b));
    }
    row.add_suffix(&start);
    let (ctx, b) = (ctx.clone(), b.clone());
    row.connect_activated(move |_| editor::open(&ctx, Some(&b)));
    row
}

fn glib_escape(s: &str) -> String {
    gtk::glib::markup_escape_text(s).to_string()
}

pub fn build(ctx: &Rc<Ctx>) -> gtk::Widget {
    let header = adw::HeaderBar::new();
    let new_btn = gtk::Button::builder()
        .icon_name("list-add-symbolic")
        .tooltip_text("New block")
        .build();
    {
        let ctx = ctx.clone();
        new_btn.connect_clicked(move |_| editor::open(&ctx, None));
    }
    header.pack_start(&new_btn);

    let content = gtk::Box::new(gtk::Orientation::Vertical, 28);

    // ---------------------------------------------------------------- hero
    let hero = gtk::Box::builder().spacing(32).build();
    hero.add_css_class("hero");
    let ring = Ring::new(176);
    hero.append(&ring.widget);
    let info = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(6)
        .valign(gtk::Align::Center)
        .hexpand(true)
        .build();
    let title = gtk::Label::builder()
        .xalign(0.0)
        .wrap(true)
        .css_classes(["hero-title"])
        .build();
    let subtitle = gtk::Label::builder()
        .xalign(0.0)
        .wrap(true)
        .css_classes(["hero-subtitle"])
        .build();
    info.append(&title);
    info.append(&subtitle);

    let quick = gtk::Box::builder().spacing(8).margin_top(14).build();
    let choices = gtk::StringList::new(&[]);
    let dropdown = gtk::DropDown::builder()
        .model(&choices)
        .valign(gtk::Align::Center)
        .build();
    let start_btn = text_button("Start…", &["pill", "suggested-action"]);
    let create_btn = text_button("Create Your First Block", &["pill", "suggested-action"]);
    quick.append(&dropdown);
    quick.append(&start_btn);
    quick.append(&create_btn);
    info.append(&quick);
    hero.append(&info);
    ctx.narrow.add_setter(
        &hero,
        "orientation",
        Some(&gtk::Orientation::Vertical.to_value()),
    );
    content.append(&hero);

    let choice_ids: Rc<RefCell<Vec<String>>> = Rc::default();
    {
        let (ctx, ids, dd) = (ctx.clone(), choice_ids.clone(), dropdown.clone());
        start_btn.connect_clicked(move |_| {
            let id = ids.borrow().get(dd.selected() as usize).cloned();
            if let Some(b) = id.and_then(|id| ctx.store.block(&id)) {
                dialogs::start(&ctx, &b);
            }
        });
    }
    {
        let ctx = ctx.clone();
        create_btn.connect_clicked(move |_| editor::open(&ctx, None));
    }

    // ---------------------------------------------------------------- lists
    let running = adw::PreferencesGroup::builder()
        .title("Running now")
        .build();
    let running_list = gtk::ListBox::builder()
        .selection_mode(gtk::SelectionMode::None)
        .build();
    running_list.add_css_class("boxed-list");
    running.add(&running_list);
    content.append(&running);

    let others = adw::PreferencesGroup::builder()
        .title("Your blocks")
        .build();
    let others_list = gtk::ListBox::builder()
        .selection_mode(gtk::SelectionMode::None)
        .build();
    others_list.add_css_class("boxed-list");
    others.add(&others_list);
    content.append(&others);

    // ---------------------------------------------------------------- updates
    let sig = Rc::new(RefCell::new(String::new()));
    let live_rows: Rc<RefCell<Vec<(adw::ActionRow, String)>>> = Rc::default();
    let update = {
        let ctx = ctx.clone();
        move || {
            let Some(s): Option<Status> = ctx.store.status() else {
                return;
            };
            let now = deepwork_core::now();
            let active: Vec<&BlockStatus> = s.blocks.iter().filter(|b| b.active).collect();
            let idle: Vec<&BlockStatus> = s.blocks.iter().filter(|b| !b.active).collect();

            // Rebuild lists only when something structural changed.
            let new_sig = signature(
                &s.blocks
                    .iter()
                    .map(|b| {
                        (
                            &b.id,
                            &b.config,
                            b.active,
                            b.locked,
                            b.on_break,
                            b.paused,
                            b.allowance_left >= 60.0,
                            b.protected,
                        )
                    })
                    .collect::<Vec<_>>(),
            );
            if *sig.borrow() != new_sig {
                *sig.borrow_mut() = new_sig;
                clear_listbox(&running_list);
                clear_listbox(&others_list);
                live_rows.borrow_mut().clear();
                for b in &active {
                    let (row, b) = active_row(&ctx, b);
                    running_list.append(&row);
                    live_rows.borrow_mut().push((row, b.id));
                }
                for b in &idle {
                    others_list.append(&idle_row(&ctx, b));
                }
                running.set_visible(!active.is_empty());
                others.set_visible(!idle.is_empty());

                let selected = choice_ids
                    .borrow()
                    .get(dropdown.selected() as usize)
                    .cloned();
                let ids: Vec<String> = idle.iter().map(|b| b.id.clone()).collect();
                let names: Vec<&str> = idle.iter().map(|b| b.config.name.as_str()).collect();
                choices.splice(0, choices.n_items(), &names);
                if let Some(pos) = selected.and_then(|id| ids.iter().position(|i| *i == id)) {
                    dropdown.set_selected(pos as u32);
                }
                *choice_ids.borrow_mut() = ids;
                dropdown.set_visible(!idle.is_empty());
                start_btn.set_visible(!idle.is_empty());
                create_btn.set_visible(s.blocks.is_empty());
            }
            for (row, id) in live_rows.borrow().iter() {
                if let Some(b) = s.blocks.iter().find(|b| b.id == *id) {
                    row.set_subtitle(&live_line(b, now));
                }
            }

            // Hero
            // Only touch the classes when they change: every change restyles
            // the whole hero.
            let frozen = s.frozen_until > now;
            for (class, on) in [
                ("frozen", frozen),
                ("active", !frozen && !active.is_empty()),
            ] {
                if hero.has_css_class(class) != on {
                    if on {
                        hero.add_css_class(class);
                    } else {
                        hero.remove_css_class(class);
                    }
                }
            }
            let enforcing: Vec<&&BlockStatus> = active.iter().filter(|b| b.enforcing).collect();
            if frozen {
                title.set_label("Frozen");
                subtitle.set_label(&format!(
                    "Your computer stays locked until {}.",
                    format_time(s.frozen_until)
                ));
                ring.set(
                    1.0,
                    gtk::gdk::RGBA::parse("#3584e4").unwrap(),
                    &format_clock(s.frozen_until - now),
                    "FROZEN",
                );
            } else if let Some(primary) = active.iter().max_by(|a, b| {
                a.window_end
                    .unwrap_or(0.0)
                    .total_cmp(&b.window_end.unwrap_or(0.0))
            }) {
                let sites: std::collections::BTreeSet<String> = enforcing
                    .iter()
                    .flat_map(|b| b.config.effective_websites())
                    .collect();
                let apps: std::collections::BTreeSet<String> = enforcing
                    .iter()
                    .flat_map(|b| b.config.effective_apps())
                    .collect();
                let end = primary.window_end.unwrap_or(now);
                let start = primary.window_start.unwrap_or(now);
                if enforcing.is_empty() {
                    title.set_label("On a break");
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
                    subtitle.set_label(&format!(
                        "Everything is unblocked until {}. Enjoy it.",
                        format_time(back)
                    ));
                    ring.set(
                        ((back - now) / 300.0).clamp(0.0, 1.0),
                        color_rgba("green"),
                        &format_clock(back - now),
                        "BREAK",
                    );
                } else {
                    title.set_label("Focus mode is on");
                    let mut what = vec![];
                    if !sites.is_empty() {
                        what.push(plural(sites.len(), "website", "websites"));
                    }
                    if !apps.is_empty() {
                        what.push(plural(apps.len(), "app", "apps"));
                    }
                    let locked = active.iter().any(|b| b.locked);
                    subtitle.set_label(&format!(
                        "Blocking {} until {}{}",
                        what.join(" and "),
                        format_time(end),
                        if s.hardcore.until > now {
                            " · hardcore"
                        } else if locked {
                            " · locked"
                        } else {
                            ""
                        }
                    ));
                    let frac = ((end - now) / (end - start).max(1.0)).clamp(0.0, 1.0);
                    ring.set(
                        frac,
                        color_rgba(&primary.config.color),
                        &format_clock(end - now),
                        "REMAINING",
                    );
                }
            } else {
                title.set_label(if s.blocks.is_empty() {
                    "Welcome to DeepWork"
                } else {
                    "Ready to focus?"
                });
                subtitle.set_label(if s.blocks.is_empty() {
                    "Make a block of the sites and apps that pull you away, then switch it on when you need to concentrate."
                } else {
                    "Pick a block and choose how long it should run."
                });
                let today = ctx
                    .store
                    .stats()
                    .get(&today_key(now))
                    .map(|d| d.focus_seconds)
                    .unwrap_or(0.0);
                ring.set(
                    0.0,
                    crate::widgets::accent(),
                    &short_duration(today),
                    "FOCUSED TODAY",
                );
            }
        }
    };
    update();
    ctx.store.subscribe(update);

    crate::pages::page_shell(&content, &header).upcast()
}
