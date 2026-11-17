//! Dialogs: start a block, unlock it, take a break, choose an app.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use adw::prelude::*;
use deepwork_core::model::LockKind;
use deepwork_core::protocol::BlockStatus;
use deepwork_core::{format_duration, format_time};

use crate::apps::{self, AppEntry};
use crate::window::Ctx;

fn dialog_shell(title: &str, width: i32, content: &impl IsA<gtk::Widget>) -> adw::Dialog {
    let tv = adw::ToolbarView::new();
    tv.add_top_bar(&adw::HeaderBar::new());
    tv.set_content(Some(content));
    adw::Dialog::builder()
        .title(title)
        .content_width(width)
        .child(&tv)
        .build()
}

fn vbox(spacing: i32) -> gtk::Box {
    gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(spacing)
        .margin_top(12)
        .margin_bottom(24)
        .margin_start(24)
        .margin_end(24)
        .build()
}

fn big_button(label: &str, class: &str) -> gtk::Button {
    let b = gtk::Button::builder()
        .label(label)
        .halign(gtk::Align::Center)
        .margin_top(6)
        .build();
    b.add_css_class("pill");
    b.add_css_class(class);
    b
}

// --------------------------------------------------------------------------- start

const PRESETS: &[(u32, &str)] = &[
    (15, "15m"),
    (25, "25m"),
    (45, "45m"),
    (60, "1h"),
    (120, "2h"),
    (240, "4h"),
    (480, "8h"),
];

/// Minutes from now so that "add time" extends a running session by `m`.
pub fn effective_minutes(block: &BlockStatus, m: u32) -> u32 {
    let left = block.session_until - deepwork_core::now();
    if left > 0.0 {
        (left / 60.0).ceil() as u32 + m
    } else {
        m
    }
}

pub fn start(ctx: &Rc<Ctx>, block: &BlockStatus) {
    let extending = block.active;
    let title = if extending { "Add time" } else { "Start block" };
    let content = vbox(18);

    let heading = gtk::Label::builder()
        .label(if extending {
            format!("Keep “{}” on for longer", block.config.name)
        } else {
            format!("How long should “{}” run?", block.config.name)
        })
        .wrap(true)
        .css_classes(["title-4"])
        .build();
    content.append(&heading);

    let big = gtk::Label::builder().css_classes(["duration-big"]).build();
    let ends = gtk::Label::builder().css_classes(["dim-label"]).build();
    let big_box = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .build();
    big_box.append(&big);
    big_box.append(&ends);
    content.append(&big_box);

    let toggles = adw::ToggleGroup::builder()
        .halign(gtk::Align::Center)
        .build();
    toggles.add_css_class("round");
    for (m, label) in PRESETS {
        toggles.add(
            adw::Toggle::builder()
                .label(*label)
                .name(m.to_string())
                .build(),
        );
    }
    content.append(&toggles);

    let hours = adw::SpinRow::with_range(0.0, 24.0 * 30.0, 1.0);
    hours.set_title("Hours");
    let minutes = adw::SpinRow::with_range(0.0, 59.0, 5.0);
    minutes.set_title("Minutes");
    let group = adw::PreferencesGroup::new();
    group.add(&hours);
    group.add(&minutes);
    content.append(&group);

    let lock = block.config.lock;
    let lock_row = adw::ActionRow::builder()
        .title(lock.label())
        .subtitle(if lock == LockKind::None {
            "No lock: you can stop this block whenever you want. Pick a lock in the block's settings."
        } else {
            lock.description()
        })
        .build();
    lock_row.add_prefix(&gtk::Image::from_icon_name(if lock == LockKind::None {
        "changes-allow-symbolic"
    } else {
        "changes-prevent-symbolic"
    }));
    let lock_group = adw::PreferencesGroup::new();
    lock_group.add(&lock_row);
    if extending {
        lock_group.set_description(Some(
            "Time can be added to a running block but never taken away.",
        ));
    }
    content.append(&lock_group);

    let go = big_button(
        if extending {
            "Add time"
        } else {
            "Start blocking"
        },
        "suggested-action",
    );
    content.append(&go);

    let dialog = dialog_shell(title, 460, &content);

    let total = Rc::new(Cell::new(60u32));
    let updating = Rc::new(Cell::new(false));
    let refresh = {
        let (big, ends, total, go, block) = (
            big.clone(),
            ends.clone(),
            total.clone(),
            go.clone(),
            block.clone(),
        );
        move || {
            let m = total.get();
            big.set_label(&format_duration(m as f64 * 60.0));
            // The block may stay on longer anyway because of its schedule.
            let end = (deepwork_core::now() + effective_minutes(&block, m) as f64 * 60.0)
                .max(block.window_end.unwrap_or(0.0));
            ends.set_label(&format!("until {}", format_time(end)));
            go.set_sensitive(m > 0);
        }
    };
    let set_total = {
        let (hours, minutes, toggles, total, updating, refresh) = (
            hours.clone(),
            minutes.clone(),
            toggles.clone(),
            total.clone(),
            updating.clone(),
            refresh.clone(),
        );
        move |m: u32, from_toggle: bool| {
            total.set(m);
            updating.set(true);
            hours.set_value((m / 60) as f64);
            minutes.set_value((m % 60) as f64);
            if !from_toggle {
                match PRESETS.iter().find(|(p, _)| *p == m) {
                    Some((p, _)) => toggles.set_active_name(Some(&p.to_string())),
                    None => toggles.set_active(gtk::INVALID_LIST_POSITION),
                }
            }
            updating.set(false);
            refresh();
        }
    };
    {
        let set_total = set_total.clone();
        toggles.connect_active_name_notify(move |t| {
            if let Some(m) = t.active_name().and_then(|n| n.parse().ok()) {
                set_total(m, true);
            }
        });
    }
    for row in [&hours, &minutes] {
        let (hours, minutes, updating, set_total) = (
            hours.clone(),
            minutes.clone(),
            updating.clone(),
            set_total.clone(),
        );
        row.connect_value_notify(move |_| {
            if !updating.get() {
                set_total(hours.value() as u32 * 60 + minutes.value() as u32, false);
            }
        });
    }
    set_total(60, false);

    {
        let (ctx, dialog, id, name, total) = (
            ctx.clone(),
            dialog.clone(),
            block.id.clone(),
            block.config.name.clone(),
            total.clone(),
        );
        go.connect_clicked(move |_| {
            let minutes = ctx
                .store
                .block(&id)
                .map(|b| effective_minutes(&b, total.get()))
                .unwrap_or(total.get());
            if ctx
                .act(ctx.store.client.start_block(&id, minutes))
                .is_some()
            {
                dialog.close();
                let until = ctx
                    .store
                    .block(&id)
                    .and_then(|b| b.window_end)
                    .map(format_time)
                    .unwrap_or_default();
                ctx.toast(&format!("“{name}” is on until {until}"));
            }
        });
    }
    dialog.present(Some(&ctx.window));
}

// --------------------------------------------------------------------------- unlock

fn explain(ctx: &Rc<Ctx>, heading: &str, body: &str) {
    let d = adw::AlertDialog::new(Some(heading), Some(body));
    d.add_response("ok", "OK");
    d.present(Some(&ctx.window));
}

fn after_unlock(ctx: &Rc<Ctx>, id: &str, name: &str) {
    if !ctx.store.block(id).is_some_and(|b| b.active) {
        // Only the protection date was holding it.
        return explain(
            ctx,
            "Unlocked for 15 minutes",
            &format!(
                "You can now change or delete “{name}”, or remove its protection date. \
                 If you leave it as it is, the protection comes back on its own."
            ),
        );
    }
    let d = adw::AlertDialog::new(
        Some("Unlocked"),
        Some(&format!(
            "“{name}” is unlocked for the rest of this session. You can stop it or change its settings."
        )),
    );
    d.add_response("keep", "Keep It Running");
    d.add_response("stop", "Stop Block");
    d.set_response_appearance("stop", adw::ResponseAppearance::Destructive);
    d.set_default_response(Some("keep"));
    let (ctx2, id) = (ctx.clone(), id.to_string());
    d.connect_response(None, move |_, resp| {
        if resp == "stop" {
            ctx2.act(ctx2.store.client.stop_block(&id));
        }
    });
    d.present(Some(&ctx.window));
}

/// Find the `GtkText` inside an entry so we can intercept pastes.
fn block_paste(entry: &impl IsA<gtk::Widget>) {
    let mut child = entry.first_child();
    while let Some(c) = child {
        if let Ok(text) = c.clone().downcast::<gtk::Text>() {
            text.connect_paste_clipboard(|t| t.stop_signal_emission_by_name("paste-clipboard"));
        } else {
            block_paste(&c);
        }
        child = c.next_sibling();
    }
}

pub fn unlock(ctx: &Rc<Ctx>, block: &BlockStatus) {
    unlock_then(ctx, block, Rc::new(|| {}));
}

/// Unlock a running block or lift its protection date, the way its lock
/// type allows. `then` runs after a successful unlock.
pub fn unlock_then(ctx: &Rc<Ctx>, block: &BlockStatus, then: Rc<dyn Fn()>) {
    let name = block.config.name.clone();
    let protected_only = block.protected && !block.active;
    let until = format_time(block.config.protect_until);
    match block.config.lock {
        LockKind::Strict | LockKind::Hardcore => explain(
            ctx,
            if block.config.lock == LockKind::Hardcore {
                "Hardcore lock"
            } else {
                "Strict lock"
            },
            &if protected_only {
                format!("“{name}” is strict, so its settings stay protected until {until}.")
            } else {
                format!("“{name}” can't be unlocked. It ends on its own when the time is up.")
            },
        ),
        LockKind::Restart => explain(
            ctx,
            "Unlocks after a restart",
            &if protected_only {
                format!(
                    "“{name}” stays protected until you restart your computer (or until {until})."
                )
            } else {
                format!(
                    "“{name}” unlocks after you restart your computer. Blocking stays on until then."
                )
            },
        ),
        LockKind::Random => unlock_random(ctx, block, then),
        LockKind::Password => unlock_password(ctx, block, then),
        LockKind::None if block.protected => explain(
            ctx,
            "Settings are protected",
            &format!("“{name}” is protected until {until}."),
        ),
        LockKind::None => {}
    }
}

fn unlock_random(ctx: &Rc<Ctx>, block: &BlockStatus, then: Rc<dyn Fn()>) {
    let Some(challenge) = ctx.act(ctx.store.client.unlock_challenge(&block.id)) else {
        return;
    };
    let content = vbox(14);
    content.append(
        &gtk::Label::builder()
            .label("To unlock, type the characters below exactly as shown. Pasting is turned off.")
            .wrap(true)
            .xalign(0.0)
            .build(),
    );
    let shown = gtk::Label::builder()
        .label(&challenge)
        .wrap(true)
        .wrap_mode(gtk::pango::WrapMode::Char)
        .selectable(false)
        .xalign(0.0)
        .css_classes(["challenge"])
        .build();
    // Line breaks must not add hyphens that look like part of the text.
    let attrs = gtk::pango::AttrList::new();
    attrs.insert(gtk::pango::AttrInt::new_insert_hyphens(false));
    shown.set_attributes(Some(&attrs));
    content.append(&shown);
    let entry = gtk::Entry::builder().placeholder_text("Type here…").build();
    entry.add_css_class("monospace");
    block_paste(&entry);
    content.append(&entry);
    let progress = gtk::Label::builder()
        .xalign(1.0)
        .css_classes(["dim-label", "numeric", "caption"])
        .build();
    content.append(&progress);
    let go = big_button("Unlock", "destructive-action");
    go.set_sensitive(false);
    content.append(&go);
    let dialog = dialog_shell("Unlock", 520, &content);

    progress.set_label(&format!("0 / {} correct", challenge.chars().count()));
    let last = Rc::new(RefCell::new(String::new()));
    let guard = Rc::new(Cell::new(false));
    {
        let (challenge, go, progress, last, guard) = (
            challenge.clone(),
            go.clone(),
            progress.clone(),
            last.clone(),
            guard.clone(),
        );
        entry.connect_changed(move |e| {
            if guard.get() {
                return;
            }
            let text = e.text().to_string();
            // Typing adds one character at a time; anything bigger is a paste or drop.
            if text.chars().count() > last.borrow().chars().count() + 1 {
                guard.set(true);
                e.set_text(&last.borrow());
                e.set_position(-1);
                guard.set(false);
                e.error_bell();
                return;
            }
            *last.borrow_mut() = text.clone();
            let correct = challenge
                .chars()
                .zip(text.chars())
                .take_while(|(a, b)| a == b)
                .count();
            progress.set_label(&format!(
                "{correct} / {} correct",
                challenge.chars().count()
            ));
            if text.len() > correct {
                e.add_css_class("error");
            } else {
                e.remove_css_class("error");
            }
            go.set_sensitive(text == challenge);
        });
    }
    let submit = {
        let (ctx, dialog, entry, id, name) = (
            ctx.clone(),
            dialog.clone(),
            entry.clone(),
            block.id.clone(),
            block.config.name.clone(),
        );
        move || {
            if ctx
                .act(ctx.store.client.unlock(&id, &entry.text()))
                .is_some()
            {
                dialog.close();
                then();
                after_unlock(&ctx, &id, &name);
            }
        }
    };
    {
        let submit = submit.clone();
        go.connect_clicked(move |_| submit());
    }
    {
        let go = go.clone();
        entry.connect_activate(move |_| {
            if go.is_sensitive() {
                submit();
            }
        });
    }
    dialog.present(Some(&ctx.window));
    entry.grab_focus();
}

fn unlock_password(ctx: &Rc<Ctx>, block: &BlockStatus, then: Rc<dyn Fn()>) {
    let content = vbox(14);
    content.append(
        &gtk::Label::builder()
            .label(format!(
                "“{}” is protected by a password. Ask the person who set it.",
                block.config.name
            ))
            .wrap(true)
            .xalign(0.0)
            .build(),
    );
    let pw = adw::PasswordEntryRow::builder().title("Password").build();
    let group = adw::PreferencesGroup::new();
    group.add(&pw);
    content.append(&group);
    let go = big_button("Unlock", "destructive-action");
    content.append(&go);
    let dialog = dialog_shell("Unlock", 420, &content);
    let submit = {
        let (ctx, dialog, pw, id, name) = (
            ctx.clone(),
            dialog.clone(),
            pw.clone(),
            block.id.clone(),
            block.config.name.clone(),
        );
        move || {
            if ctx.act(ctx.store.client.unlock(&id, &pw.text())).is_some() {
                dialog.close();
                then();
                after_unlock(&ctx, &id, &name);
            } else {
                pw.add_css_class("error");
            }
        }
    };
    {
        let submit = submit.clone();
        go.connect_clicked(move |_| submit());
    }
    pw.connect_entry_activated(move |_| submit());
    dialog.present(Some(&ctx.window));
    pw.grab_focus();
}

// --------------------------------------------------------------------------- break

pub fn take_break(ctx: &Rc<Ctx>, block: &BlockStatus) {
    let left_min = (block.allowance_left / 60.0).floor() as u32;
    if left_min == 0 {
        return explain(
            ctx,
            "No breaks left",
            "You've used today's break allowance for this block. It resets tomorrow.",
        );
    }
    let content = vbox(14);
    content.append(
        &gtk::Label::builder()
            .label(format!(
                "You have {} of break time left today for “{}”. Everything it blocks is available during the break.",
                format_duration(block.allowance_left),
                block.config.name
            ))
            .wrap(true)
            .xalign(0.0)
            .build(),
    );
    let mins = adw::SpinRow::with_range(1.0, left_min as f64, 1.0);
    mins.set_title("Break length (minutes)");
    mins.set_value(left_min.min(5) as f64);
    let group = adw::PreferencesGroup::new();
    group.add(&mins);
    content.append(&group);
    let go = big_button("Start Break", "suggested-action");
    content.append(&go);
    let dialog = dialog_shell("Take a break", 420, &content);
    let (ctx2, d2, id) = (ctx.clone(), dialog.clone(), block.id.clone());
    go.connect_clicked(move |_| {
        if ctx2
            .act(ctx2.store.client.take_break(&id, mins.value() as u32))
            .is_some()
        {
            d2.close();
        }
    });
    dialog.present(Some(&ctx.window));
}

// --------------------------------------------------------------------------- app chooser

fn app_list(
    entries: &[AppEntry],
    on_pick: Rc<dyn Fn(&AppEntry)>,
    search: &gtk::SearchEntry,
) -> gtk::Widget {
    let list = gtk::ListBox::builder()
        .selection_mode(gtk::SelectionMode::None)
        .valign(gtk::Align::Start)
        .build();
    list.add_css_class("boxed-list");
    let names: Rc<Vec<String>> = Rc::new(
        entries
            .iter()
            .map(|e| format!("{} {}", e.name, e.detail).to_lowercase())
            .collect(),
    );
    for e in entries {
        let row = adw::ActionRow::builder()
            .title(glib_escape(&e.name))
            .subtitle(glib_escape(&e.detail))
            .activatable(true)
            .build();
        let img = match &e.icon {
            Some(icon) => gtk::Image::from_gicon(icon),
            None => gtk::Image::from_icon_name("application-x-executable-symbolic"),
        };
        img.set_pixel_size(32);
        row.add_prefix(&img);
        row.add_suffix(&gtk::Image::from_icon_name("list-add-symbolic"));
        let (e, f) = (e.clone(), on_pick.clone());
        row.connect_activated(move |_| f(&e));
        list.append(&row);
    }
    if entries.is_empty() {
        list.set_placeholder(Some(
            &gtk::Label::builder()
                .label("Nothing here")
                .margin_top(24)
                .margin_bottom(24)
                .css_classes(["dim-label"])
                .build(),
        ));
    }
    let query = Rc::new(RefCell::new(String::new()));
    {
        let (q, names) = (query.clone(), names.clone());
        list.set_filter_func(move |row| {
            let q = q.borrow();
            q.is_empty()
                || names
                    .get(row.index() as usize)
                    .is_some_and(|n| n.contains(q.as_str()))
        });
    }
    {
        let list = list.clone();
        search.connect_search_changed(move |s| {
            *query.borrow_mut() = s.text().to_lowercase();
            list.invalidate_filter();
        });
    }
    let clamp = adw::Clamp::builder()
        .child(&list)
        .margin_top(12)
        .margin_bottom(24)
        .margin_start(12)
        .margin_end(12)
        .build();
    gtk::ScrolledWindow::builder()
        .child(&clamp)
        .vexpand(true)
        .hscrollbar_policy(gtk::PolicyType::Never)
        .build()
        .upcast()
}

fn glib_escape(s: &str) -> String {
    gtk::glib::markup_escape_text(s).to_string()
}

pub fn choose_app(ctx: &Rc<Ctx>, on_pick: impl Fn(&AppEntry) + 'static) {
    let search = gtk::SearchEntry::builder()
        .placeholder_text("Search apps")
        .hexpand(true)
        .build();
    let stack = adw::ViewStack::new();
    let dialog = adw::Dialog::builder()
        .title("Choose an app")
        .content_width(520)
        .content_height(640)
        .build();
    let pick: Rc<dyn Fn(&AppEntry)> = {
        let dialog = dialog.clone();
        Rc::new(move |e: &AppEntry| {
            on_pick(e);
            dialog.close();
        })
    };
    let installed = apps::installed();
    let running = apps::running();
    stack.add_titled_with_icon(
        &app_list(&installed, pick.clone(), &search),
        Some("installed"),
        "Installed",
        "view-app-grid-symbolic",
    );
    stack.add_titled_with_icon(
        &app_list(&running, pick, &search),
        Some("running"),
        "Running",
        "media-playback-start-symbolic",
    );

    let switcher = adw::ViewSwitcher::builder()
        .stack(&stack)
        .policy(adw::ViewSwitcherPolicy::Wide)
        .build();
    let header = adw::HeaderBar::builder().title_widget(&switcher).build();
    let search_box = gtk::Box::builder()
        .margin_start(12)
        .margin_end(12)
        .margin_top(6)
        .build();
    search_box.append(&search);
    let tv = adw::ToolbarView::new();
    tv.add_top_bar(&header);
    tv.add_top_bar(&search_box);
    tv.set_content(Some(&stack));
    dialog.set_child(Some(&tv));
    dialog.present(Some(&ctx.window));
    search.grab_focus();
}

// --------------------------------------------------------------------------- filter lists

/// Pick built-in filter lists. `fixed` ones are shown checked and can't be
/// unchecked (the block is locked).
pub fn choose_lists(
    ctx: &Rc<Ctx>,
    selected: Vec<String>,
    fixed: Vec<String>,
    on_change: impl Fn(Vec<String>) + 'static,
) {
    use deepwork_core::lists::LISTS;
    let chosen: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(selected));
    let on_change = Rc::new(on_change);
    let list = gtk::ListBox::builder()
        .selection_mode(gtk::SelectionMode::None)
        .valign(gtk::Align::Start)
        .build();
    list.add_css_class("boxed-list");
    for l in LISTS {
        let row = adw::ActionRow::builder()
            .title(glib_escape(l.name))
            .subtitle(glib_escape(&format!(
                "{} · {}",
                l.description,
                crate::util::list_summary(l)
            )))
            .activatable(true)
            .build();
        row.add_prefix(&gtk::Image::from_icon_name(l.icon));
        let check = gtk::CheckButton::builder()
            .active(chosen.borrow().iter().any(|c| c == l.id))
            .valign(gtk::Align::Center)
            .build();
        if fixed.iter().any(|f| f == l.id) {
            check.set_sensitive(false);
            row.set_tooltip_text(Some("The block is locked, so this list can't be removed"));
        }
        row.add_suffix(&check);
        row.set_activatable_widget(Some(&check));
        let (chosen, on_change, id) = (chosen.clone(), on_change.clone(), l.id);
        check.connect_toggled(move |c| {
            let mut set: Vec<String> = chosen.borrow().clone();
            set.retain(|x| x != id);
            if c.is_active() {
                set.push(id.to_string());
            }
            // Keep the built-in order.
            let ordered: Vec<String> = LISTS
                .iter()
                .filter(|l| set.iter().any(|s| s == l.id))
                .map(|l| l.id.to_string())
                .collect();
            *chosen.borrow_mut() = ordered.clone();
            on_change(ordered);
        });
        list.append(&row);
    }
    let content = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(12)
        .margin_top(6)
        .margin_bottom(24)
        .margin_start(12)
        .margin_end(12)
        .build();
    content.append(
        &gtk::Label::builder()
            .label("Everything in a list is blocked along with the block's own websites and apps. Lists are updated with new versions of DeepWork.")
            .wrap(true)
            .xalign(0.0)
            .css_classes(["dim-label"])
            .build(),
    );
    content.append(&list);
    let clamp = adw::Clamp::builder().child(&content).build();
    let scroller = gtk::ScrolledWindow::builder()
        .child(&clamp)
        .vexpand(true)
        .hscrollbar_policy(gtk::PolicyType::Never)
        .build();
    let tv = adw::ToolbarView::new();
    tv.add_top_bar(&adw::HeaderBar::new());
    tv.set_content(Some(&scroller));
    let dialog = adw::Dialog::builder()
        .title("Filter lists")
        .content_width(560)
        .content_height(680)
        .child(&tv)
        .build();
    dialog.present(Some(&ctx.window));
}
