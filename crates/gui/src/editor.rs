//! Create / edit a block.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use adw::prelude::*;
use deepwork_core::lists;
use deepwork_core::model::MAX_WEBSITES;
use deepwork_core::model::{BlockConfig, COLORS, LockKind, normalize_app, normalize_domain};
use deepwork_core::protocol::BlockStatus;
use deepwork_core::{describe_schedule, format_time};
use gtk::{gio, glib};

use crate::apps::{self, AppEntry};
use crate::dialogs;
use crate::util::{clear_listbox, dot, icon_button, list_summary, plural};
use crate::widgets::schedule::ScheduleGrid;
use crate::window::Ctx;

struct Editor {
    ctx: Rc<Ctx>,
    id: Option<String>,
    orig: BlockConfig,
    cfg: RefCell<BlockConfig>,
    locked: bool,
    sites: gtk::ListBox,
    apps: gtk::ListBox,
    sites_group: adw::PreferencesGroup,
    apps_group: adw::PreferencesGroup,
    lists: gtk::ListBox,
    lists_group: adw::PreferencesGroup,
    installed: Vec<AppEntry>,
}

impl Editor {
    /// Locked blocks can't lose items they already had.
    fn removable_site(&self, s: &str) -> bool {
        !self.locked || !self.orig.websites.iter().any(|w| w == s)
    }

    fn removable_app(&self, a: &str) -> bool {
        !self.locked || !self.orig.apps.iter().any(|x| x.eq_ignore_ascii_case(a))
    }
}

fn render_sites(ed: &Rc<Editor>) {
    const MAX_ROWS: usize = 100;
    clear_listbox(&ed.sites);
    let sites = ed.cfg.borrow().websites.clone();
    ed.sites.set_visible(!sites.is_empty());
    ed.sites_group.set_title(&if sites.is_empty() {
        "Websites".to_string()
    } else {
        format!("Websites ({})", sites.len())
    });
    for site in sites.iter().rev().take(MAX_ROWS) {
        let row = adw::ActionRow::builder().title(site.as_str()).build();
        row.add_prefix(&gtk::Image::from_icon_name("dw-globe-symbolic"));
        let rm = icon_button("user-trash-symbolic", "Remove");
        rm.set_sensitive(ed.removable_site(site));
        let (ed2, site) = (ed.clone(), site.clone());
        rm.connect_clicked(move |_| {
            ed2.cfg.borrow_mut().websites.retain(|w| *w != site);
            render_sites(&ed2);
        });
        row.add_suffix(&rm);
        ed.sites.append(&row);
    }
    if sites.len() > MAX_ROWS {
        let more = adw::ActionRow::builder()
            .title(format!("…and {} more", sites.len() - MAX_ROWS))
            .build();
        more.add_css_class("dim-label");
        ed.sites.append(&more);
    }
    if sites.len() > 10 && !ed.locked {
        let clear = adw::ButtonRow::builder()
            .title("Remove All Websites")
            .start_icon_name("edit-clear-all-symbolic")
            .build();
        clear.add_css_class("destructive-action");
        let ed2 = ed.clone();
        clear.connect_activated(move |_| {
            ed2.cfg.borrow_mut().websites.clear();
            render_sites(&ed2);
        });
        ed.sites.append(&clear);
    }
}

/// Hardcore takes administrator rights away, so make sure that's wanted.
/// Cancelling switches the lock row back to the `previous` position.
fn confirm_hardcore(ed: &Rc<Editor>, row: &adw::ComboRow, previous: u32) {
    let name = ed.cfg.borrow().name.clone();
    let mut body = format!(
        "While “{name}” runs, nobody on this computer gets administrator rights:\n\n\
         • sudo, su, pkexec and run0 are refused, and admin passwords stop working\n\
         • software can't be installed, updated or removed\n\
         • the clock can't be changed\n\
         • VPN apps, Tor and web proxies are blocked\n\n\
         There is no way to end it early, not even by restarting. If something needs \
         administrator rights, it has to wait until the block is over."
    );
    let groups = crate::util::root_equivalent_groups();
    if !groups.is_empty() {
        body.push_str(&format!(
            "\n\nYou're in the {} group, which can still get administrator rights. Leave it \
             if you want no way around the block.",
            groups.join(" and ")
        ));
    }
    let d = adw::AlertDialog::new(Some("Use hardcore mode?"), Some(&body));
    d.add_response("cancel", "Cancel");
    d.add_response("hardcore", "Use Hardcore");
    d.set_response_appearance("hardcore", adw::ResponseAppearance::Destructive);
    d.set_default_response(Some("cancel"));
    d.set_close_response("cancel");
    let row = row.clone();
    d.connect_response(None, move |_, r| {
        if r != "hardcore" {
            row.set_selected(previous);
        }
    });
    d.present(Some(&ed.ctx.window));
}

fn render_lists(ed: &Rc<Editor>) {
    clear_listbox(&ed.lists);
    let ids = ed.cfg.borrow().lists.clone();
    ed.lists_group.set_title(&if ids.is_empty() {
        "Filter lists".to_string()
    } else {
        format!("Filter lists ({})", ids.len())
    });
    for id in &ids {
        let Some(l) = lists::get(id) else { continue };
        let row = adw::ExpanderRow::builder()
            .title(glib::markup_escape_text(l.name).as_str())
            .subtitle(list_summary(l))
            .build();
        row.add_prefix(&gtk::Image::from_icon_name(l.icon));
        let rm = icon_button("user-trash-symbolic", "Remove list");
        rm.set_sensitive(!ed.locked || !ed.orig.lists.contains(id));
        let (ed2, id2) = (ed.clone(), id.clone());
        rm.connect_clicked(move |_| {
            ed2.cfg.borrow_mut().lists.retain(|x| *x != id2);
            render_lists(&ed2);
        });
        row.add_suffix(&rm);
        if !l.websites.is_empty() {
            let r = adw::ActionRow::builder()
                .title("Websites")
                .subtitle(l.websites.join(", "))
                .subtitle_selectable(true)
                .build();
            row.add_row(&r);
        }
        if !l.apps.is_empty() {
            let names: Vec<String> = l
                .apps
                .iter()
                .map(|a| apps::describe_rule(a, &ed.installed).0)
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect();
            let r = adw::ActionRow::builder()
                .title("Applications")
                .subtitle(glib::markup_escape_text(&names.join(", ")).as_str())
                .subtitle_selectable(true)
                .build();
            row.add_row(&r);
        }
        ed.lists.append(&row);
    }
}

fn import_sites(ed: &Rc<Editor>) {
    let lists_filter = gtk::FileFilter::new();
    lists_filter.set_name(Some("Domain lists"));
    lists_filter.add_mime_type("text/plain");
    lists_filter.add_pattern("hosts*");
    lists_filter.add_pattern("*.txt");
    lists_filter.add_pattern("*.list");
    let all = gtk::FileFilter::new();
    all.set_name(Some("All files"));
    all.add_pattern("*");
    let filters = gio::ListStore::new::<gtk::FileFilter>();
    filters.append(&lists_filter);
    filters.append(&all);
    let dialog = gtk::FileDialog::builder()
        .title("Import Websites")
        .modal(true)
        .filters(&filters)
        .build();
    let ed = ed.clone();
    dialog.open(
        Some(&ed.ctx.window.clone()),
        gio::Cancellable::NONE,
        move |res| {
            let Ok(file) = res else { return };
            let bytes = match file.load_contents(gio::Cancellable::NONE) {
                Ok((bytes, _)) => bytes,
                Err(e) => return ed.ctx.toast(&format!("Couldn't read the file: {e}")),
            };
            let (domains, skipped) = lists::parse_domain_list(&String::from_utf8_lossy(&bytes));
            let added = {
                let mut cfg = ed.cfg.borrow_mut();
                let mut have: std::collections::HashSet<String> =
                    cfg.websites.iter().cloned().collect();
                let room = MAX_WEBSITES.saturating_sub(cfg.websites.len());
                let new: Vec<String> = domains
                    .into_iter()
                    .filter(|d| have.insert(d.clone()))
                    .collect();
                let take = new.len().min(room);
                let dropped = new.len() - take;
                cfg.websites.extend(new.into_iter().take(take));
                (take, dropped)
            };
            render_sites(&ed);
            let mut msg = format!("Imported {}", plural(added.0, "website", "websites"));
            if added.1 > 0 {
                msg.push_str(&format!(", {} over the limit of {MAX_WEBSITES}", added.1));
            }
            if skipped > 0 {
                msg.push_str(&format!(", skipped {}", plural(skipped, "line", "lines")));
            }
            msg.push_str(". Save to apply.");
            ed.ctx.toast(&msg);
        },
    );
}

fn render_apps(ed: &Rc<Editor>) {
    clear_listbox(&ed.apps);
    let list = ed.cfg.borrow().apps.clone();
    ed.apps.set_visible(!list.is_empty());
    ed.apps_group.set_title(&if list.is_empty() {
        "Applications".to_string()
    } else {
        format!("Applications ({})", list.len())
    });
    for rule in list.iter().rev() {
        let (name, icon) = apps::describe_rule(rule, &ed.installed);
        let row = adw::ActionRow::builder()
            .title(glib::markup_escape_text(&name).as_str())
            .build();
        if name != *rule {
            row.set_subtitle(&glib::markup_escape_text(rule));
        }
        let img = match icon {
            Some(i) => gtk::Image::from_gicon(&i),
            None => gtk::Image::from_icon_name("application-x-executable-symbolic"),
        };
        img.set_pixel_size(24);
        row.add_prefix(&img);
        let rm = icon_button("user-trash-symbolic", "Remove");
        rm.set_sensitive(ed.removable_app(rule));
        let (ed2, rule) = (ed.clone(), rule.clone());
        rm.connect_clicked(move |_| {
            ed2.cfg.borrow_mut().apps.retain(|a| *a != rule);
            render_apps(&ed2);
        });
        row.add_suffix(&rm);
        ed.apps.append(&row);
    }
}

fn add_sites(ed: &Rc<Editor>, input: &str) -> Result<usize, String> {
    let mut added = 0;
    let parts: Vec<&str> = input
        .split(|c: char| c.is_whitespace() || c == ',' || c == ';')
        .filter(|s| !s.is_empty())
        .collect();
    let normalized = parts
        .iter()
        .map(|p| normalize_domain(p).map_err(|e| e.0))
        .collect::<Result<Vec<_>, _>>()?;
    let mut cfg = ed.cfg.borrow_mut();
    for d in normalized {
        if !cfg.websites.contains(&d) {
            cfg.websites.push(d);
            added += 1;
        }
    }
    Ok(added)
}

fn add_apps(ed: &Rc<Editor>, rules: &[String]) -> Result<usize, String> {
    let normalized = rules
        .iter()
        .map(|r| normalize_app(r).map_err(|e| e.0))
        .collect::<Result<Vec<_>, _>>()?;
    let mut added = 0;
    let mut cfg = ed.cfg.borrow_mut();
    for r in normalized {
        if !cfg.apps.iter().any(|a| a.eq_ignore_ascii_case(&r)) {
            cfg.apps.push(r);
            added += 1;
        }
    }
    Ok(added)
}

fn group(title: &str, description: &str) -> adw::PreferencesGroup {
    let g = adw::PreferencesGroup::builder().title(title).build();
    if !description.is_empty() {
        g.set_description(Some(description));
    }
    g
}

fn boxed_list() -> gtk::ListBox {
    let l = gtk::ListBox::builder()
        .selection_mode(gtk::SelectionMode::None)
        .margin_top(12)
        .build();
    l.add_css_class("boxed-list");
    l
}

fn end_of_day(date: &glib::DateTime) -> f64 {
    glib::DateTime::from_local(date.year(), date.month(), date.day_of_month(), 23, 59, 59.0)
        .map(|d| d.to_unix() as f64)
        .unwrap_or(0.0)
}

pub fn open(ctx: &Rc<Ctx>, existing: Option<&BlockStatus>) {
    let cfg = existing.map(|b| b.config.clone()).unwrap_or_default();
    let locked = existing.is_some_and(|b| b.locked);
    let has_password = existing.is_some_and(|b| b.has_password);
    let ed = Rc::new(Editor {
        ctx: ctx.clone(),
        id: existing.map(|b| b.id.clone()),
        orig: cfg.clone(),
        cfg: RefCell::new(cfg.clone()),
        locked,
        sites: boxed_list(),
        apps: boxed_list(),
        lists: boxed_list(),
        lists_group: group(
            "Filter lists",
            "Ready-made collections of websites and apps, kept up to date with DeepWork.",
        ),
        sites_group: group(
            "Websites",
            "Blocked in every browser. Subdomains are included.",
        ),
        apps_group: group(
            "Applications",
            "Closed as soon as they start while the block is on.",
        ),
        installed: apps::installed(),
    });
    // Features the service can't provide on this OS.
    let caps = ctx.store.capabilities();
    for (group, ok, what) in [
        (&ed.sites_group, caps.websites, "Blocking websites"),
        (&ed.apps_group, caps.apps, "Blocking applications"),
    ] {
        if !ok {
            group.set_description(Some(&format!("{what} isn't available on {} yet.", caps.os)));
            group.set_sensitive(false);
        }
    }

    let page_box = gtk::Box::new(gtk::Orientation::Vertical, 0);
    let banner = adw::Banner::new(&match existing {
        Some(b) if b.locked && !b.active && b.protected => format!(
            "Protected until {}. You can add lists, websites, apps and times, but not remove anything.",
            format_time(b.config.protect_until)
        ),
        _ => "This block is locked. You can add lists, websites, apps and times, but not remove anything."
            .to_string(),
    });
    banner.set_revealed(locked);
    if let Some(b) = existing
        .filter(|b| b.locked && matches!(b.config.lock, LockKind::Random | LockKind::Password))
    {
        banner.set_button_label(Some("Unlock…"));
        let (ctx, b) = (ctx.clone(), b.clone());
        banner.connect_button_clicked(move |_| {
            let ctx2 = ctx.clone();
            let id = b.id.clone();
            // Reopen the editor so it reflects the unlocked state.
            let reopen: Rc<dyn Fn()> = Rc::new(move || {
                ctx2.blocks_nav.pop();
                if let Some(fresh) = ctx2.store.block(&id) {
                    open(&ctx2, Some(&fresh));
                }
            });
            dialogs::unlock_then(&ctx, &b, reopen);
        });
    }
    page_box.append(&banner);
    let prefs = adw::PreferencesPage::new();
    prefs.set_vexpand(true);
    page_box.append(&prefs);

    // ------------------------------------------------------------- general
    let general = group("", "");
    let name = adw::EntryRow::builder()
        .title("Name")
        .text(&cfg.name)
        .build();
    {
        let ed = ed.clone();
        name.connect_changed(move |e| ed.cfg.borrow_mut().name = e.text().to_string());
    }
    general.add(&name);
    let color_row = adw::ActionRow::builder().title("Color").build();
    let colors = gtk::Box::builder()
        .spacing(4)
        .valign(gtk::Align::Center)
        .build();
    let mut first: Option<gtk::ToggleButton> = None;
    for c in COLORS {
        let b = gtk::ToggleButton::builder()
            .child(&dot(c))
            .tooltip_text(*c)
            .build();
        b.add_css_class("color-choice");
        if let Some(f) = &first {
            b.set_group(Some(f));
        } else {
            first = Some(b.clone());
        }
        b.set_active(cfg.color == *c);
        let (ed, c) = (ed.clone(), c.to_string());
        b.connect_toggled(move |b| {
            if b.is_active() {
                ed.cfg.borrow_mut().color = c.clone();
            }
        });
        colors.append(&b);
    }
    color_row.add_suffix(&colors);
    general.add(&color_row);
    prefs.add(&general);

    // ------------------------------------------------------------- filter lists
    let add_lists = gtk::Button::builder()
        .child(
            &adw::ButtonContent::builder()
                .label("Add lists")
                .icon_name("view-list-symbolic")
                .build(),
        )
        .build();
    add_lists.add_css_class("flat");
    {
        let ed = ed.clone();
        add_lists.connect_clicked(move |_| {
            let fixed = if ed.locked {
                ed.orig.lists.clone()
            } else {
                vec![]
            };
            let ed2 = ed.clone();
            dialogs::choose_lists(
                &ed.ctx,
                ed.cfg.borrow().lists.clone(),
                fixed,
                move |chosen| {
                    ed2.cfg.borrow_mut().lists = chosen;
                    render_lists(&ed2);
                },
            );
        });
    }
    ed.lists_group.set_header_suffix(Some(&add_lists));
    ed.lists.set_placeholder(Some(
        &gtk::Label::builder()
            .label("Add ready-made lists like social media, chat apps or games.")
            .wrap(true)
            .margin_top(18)
            .margin_bottom(18)
            .margin_start(12)
            .margin_end(12)
            .css_classes(["dim-label"])
            .build(),
    ));
    ed.lists.set_margin_top(0);
    ed.lists_group.add(&ed.lists);
    prefs.add(&ed.lists_group);

    // ------------------------------------------------------------- websites
    let add_site = adw::EntryRow::builder()
        .title("Add website, e.g. reddit.com")
        .show_apply_button(true)
        .build();
    let import = gtk::Button::builder()
        .child(
            &adw::ButtonContent::builder()
                .label("Import…")
                .icon_name("document-open-symbolic")
                .build(),
        )
        .tooltip_text("Import websites from a text, hosts or adblock list")
        .build();
    import.add_css_class("flat");
    {
        let ed = ed.clone();
        import.connect_clicked(move |_| import_sites(&ed));
    }
    ed.sites_group.set_header_suffix(Some(&import));
    let on_add_site = {
        let ed = ed.clone();
        move |row: &adw::EntryRow| {
            let text = row.text().to_string();
            if text.trim().is_empty() {
                return;
            }
            match add_sites(&ed, &text) {
                Ok(_) => {
                    row.set_text("");
                    row.remove_css_class("error");
                    render_sites(&ed);
                }
                Err(e) => {
                    row.add_css_class("error");
                    ed.ctx.toast(&e);
                }
            }
        }
    };
    {
        let f = on_add_site.clone();
        add_site.connect_apply(move |r| f(r));
    }
    add_site.connect_entry_activated(move |r| on_add_site(r));
    ed.sites_group.add(&add_site);
    ed.sites_group.add(&ed.sites);
    prefs.add(&ed.sites_group);

    // ------------------------------------------------------------- apps
    let choose = gtk::Button::builder()
        .child(
            &adw::ButtonContent::builder()
                .label("Choose app")
                .icon_name("view-app-grid-symbolic")
                .build(),
        )
        .build();
    choose.add_css_class("flat");
    {
        let ed = ed.clone();
        choose.connect_clicked(move |_| {
            let ed2 = ed.clone();
            dialogs::choose_app(&ed.ctx, move |entry| match add_apps(&ed2, &entry.rules) {
                Ok(_) => render_apps(&ed2),
                Err(e) => ed2.ctx.toast(&e),
            });
        });
    }
    ed.apps_group.set_header_suffix(Some(&choose));
    let add_app = adw::EntryRow::builder()
        .title("Add by process name, e.g. steam")
        .show_apply_button(true)
        .build();
    let on_add_app = {
        let ed = ed.clone();
        move |row: &adw::EntryRow| {
            let text = row.text().trim().to_string();
            if text.is_empty() {
                return;
            }
            match add_apps(&ed, &[text]) {
                Ok(_) => {
                    row.set_text("");
                    row.remove_css_class("error");
                    render_apps(&ed);
                }
                Err(e) => {
                    row.add_css_class("error");
                    ed.ctx.toast(&e);
                }
            }
        }
    };
    {
        let f = on_add_app.clone();
        add_app.connect_apply(move |r| f(r));
    }
    add_app.connect_entry_activated(move |r| on_add_app(r));
    ed.apps_group.add(&add_app);
    ed.apps_group.add(&ed.apps);
    prefs.add(&ed.apps_group);

    // ------------------------------------------------------------- schedule
    let sched_group = group(
        "Schedule",
        "Turn the block on automatically. Drag across the grid to pick times.",
    );
    let sched_switch = adw::SwitchRow::builder()
        .title("Block on a schedule")
        .subtitle(describe_schedule(&cfg.schedule))
        .active(cfg.schedule_enabled)
        .build();
    sched_group.add(&sched_switch);
    // Point out that an unlocked schedule can be switched off mid-block.
    let sched_hint = adw::ActionRow::builder()
        .title("Can be switched off at any time")
        .subtitle(
            "Without a lock, this schedule can be turned off even while it's blocking. Choose a \
             lock below to keep it on until each scheduled time is over.",
        )
        .build();
    sched_hint.add_prefix(&gtk::Image::from_icon_name("dialog-information-symbolic"));
    sched_hint.set_visible(cfg.schedule_enabled && cfg.lock == LockKind::None);
    sched_group.add(&sched_hint);
    if locked && cfg.schedule_enabled {
        // The daemon refuses turning a locked schedule off, so don't offer it.
        sched_switch.set_sensitive(false);
        sched_switch.set_subtitle(&format!(
            "{} · locked until the block is off",
            describe_schedule(&cfg.schedule)
        ));
    }
    let grid = ScheduleGrid::new();
    grid.set_ranges(&cfg.schedule);
    if locked && cfg.schedule_enabled {
        grid.set_fixed(&cfg.schedule);
    }
    let grid_card = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(12)
        .margin_top(12)
        .build();
    grid_card.add_css_class("schedule-card");
    grid_card.append(&grid.widget);
    let preset_row = gtk::Box::builder()
        .spacing(6)
        .halign(gtk::Align::Center)
        .build();
    let day = |d: u32, a: u32, b: u32| [d * 1440 + a, d * 1440 + b];
    let schedule_presets: Vec<(&str, Vec<[u32; 2]>)> = vec![
        ("Workdays 9–5", (0..5).map(|d| day(d, 540, 1020)).collect()),
        ("Evenings", (0..7).map(|d| day(d, 1200, 1440)).collect()),
        ("Mornings", (0..7).map(|d| day(d, 360, 720)).collect()),
        ("Clear", vec![]),
    ];
    {
        let ed = ed.clone();
        let sub = sched_switch.clone();
        grid.connect_changed(move |ranges| {
            sub.set_subtitle(&describe_schedule(&ranges));
            ed.cfg.borrow_mut().schedule = ranges;
        });
    }
    for (label, ranges) in schedule_presets {
        let b = gtk::Button::builder().label(label).build();
        b.add_css_class("flat");
        let (ed, grid, sub) = (ed.clone(), grid.clone(), sched_switch.clone());
        b.connect_clicked(move |_| {
            let mut merged = if label == "Clear" {
                vec![]
            } else {
                ed.cfg.borrow().schedule.clone()
            };
            merged.extend(ranges.iter().copied());
            let merged = deepwork_core::model::normalize_schedule(&merged);
            let merged = if ed.locked && ed.orig.schedule_enabled {
                // Can't clear locked time; keep the original ranges.
                let mut m = merged;
                m.extend(ed.orig.schedule.iter().copied());
                deepwork_core::model::normalize_schedule(&m)
            } else {
                merged
            };
            grid.set_ranges(&merged);
            sub.set_subtitle(&describe_schedule(&merged));
            ed.cfg.borrow_mut().schedule = merged;
        });
        preset_row.append(&b);
    }
    grid_card.append(&preset_row);
    sched_group.add(&grid_card);
    {
        let ed = ed.clone();
        let card = grid_card.clone();
        card.set_sensitive(cfg.schedule_enabled);
        let hint = sched_hint.clone();
        sched_switch.connect_active_notify(move |s| {
            ed.cfg.borrow_mut().schedule_enabled = s.is_active();
            card.set_sensitive(s.is_active());
            hint.set_visible(s.is_active() && ed.cfg.borrow().lock == LockKind::None);
        });
    }
    prefs.add(&sched_group);

    // ------------------------------------------------------------- lock
    let lock_group = group(
        "Lock",
        "Make it hard to give up early. While the block is on, in a session or during its \
         scheduled times, a locked block can't be stopped, deleted or weakened, and its \
         schedule can't be turned off. Once it's off, you can change anything.",
    );
    // Only the locks this OS supports (plus the block's current one).
    let kinds: Rc<Vec<LockKind>> = Rc::new(
        LockKind::ALL
            .into_iter()
            .filter(|k| caps.supports_lock(*k) || *k == cfg.lock)
            .collect(),
    );
    let model = gtk::StringList::new(&kinds.iter().map(|l| l.label()).collect::<Vec<_>>());
    let lock_row = adw::ComboRow::builder()
        .title("Lock type")
        .model(&model)
        .build();
    lock_row.set_selected(kinds.iter().position(|l| *l == cfg.lock).unwrap_or(0) as u32);
    lock_row.set_subtitle(cfg.lock.description());
    let random_len = adw::SpinRow::with_range(8.0, 500.0, 8.0);
    random_len.set_title("Characters to type");
    random_len.set_subtitle("Longer is harder to get through on a whim");
    random_len.set_value(cfg.random_length as f64);
    let password = adw::PasswordEntryRow::builder()
        .title(if has_password {
            "New password (leave empty to keep)"
        } else {
            "Password"
        })
        .build();
    let sync_lock_rows = {
        let (random_len, password) = (random_len.clone(), password.clone());
        move |k: LockKind| {
            random_len.set_visible(k == LockKind::Random);
            password.set_visible(k == LockKind::Password);
        }
    };
    let hardcore_row = adw::ActionRow::builder()
        .title("Hardcore mode")
        .subtitle(
            "While the block runs, nobody on this computer gets administrator rights: no sudo, \
             su, pkexec or admin passwords, no installing software and no changing the clock. \
             VPN apps, Tor and web proxies are blocked, and encrypted DNS blocking and HTTPS \
             filtering are always on. Restarting doesn't end it. At most 7 days in a row, \
             counting every hardcore block.",
        )
        .build();
    hardcore_row.add_prefix(&gtk::Image::from_icon_name("dialog-warning-symbolic"));
    hardcore_row.add_css_class("warning");
    let sync_lock_rows = {
        let hardcore_row = hardcore_row.clone();
        move |k: LockKind| {
            sync_lock_rows(k);
            hardcore_row.set_visible(k == LockKind::Hardcore);
        }
    };
    sync_lock_rows(cfg.lock);
    // protect until a date
    let protect_row = adw::ActionRow::builder()
        .title("Protect settings until")
        .build();
    let set_protect_subtitle = {
        let (row, ed) = (protect_row.clone(), ed.clone());
        move |ts: f64| {
            let lock = ed.cfg.borrow().lock;
            let how = match lock {
                LockKind::Random => "Typing the random text lifts it early.",
                LockKind::Password => "The password lifts it early.",
                LockKind::Restart => "Restarting the computer lifts it early.",
                LockKind::Strict | LockKind::Hardcore | LockKind::None => "Nothing lifts it early.",
            };
            row.set_subtitle(&if lock == LockKind::None {
                "Choose a lock type above to use this".to_string()
            } else if ts > deepwork_core::now() {
                format!(
                    "{}: no stopping, deleting or weakening, even while it's off. {how}",
                    format_time(ts)
                )
            } else {
                format!("Off. {how}")
            });
        }
    };
    set_protect_subtitle(cfg.protect_until);
    let cal = gtk::Calendar::new();
    let clear = gtk::Button::builder().label("Turn Off").build();
    clear.add_css_class("flat");
    clear.set_sensitive(!locked);
    let pop_box = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(6)
        .build();
    pop_box.append(&cal);
    pop_box.append(&clear);
    let pop = gtk::Popover::builder().child(&pop_box).build();
    let date_btn = gtk::MenuButton::builder()
        .icon_name("x-office-calendar-symbolic")
        .popover(&pop)
        .valign(gtk::Align::Center)
        .build();
    date_btn.add_css_class("flat");
    date_btn.set_sensitive(cfg.lock != LockKind::None);
    protect_row.add_suffix(&date_btn);
    {
        let (ed, set_sub, pop) = (ed.clone(), set_protect_subtitle.clone(), pop.clone());
        cal.connect_day_selected(move |c| {
            let ts = end_of_day(&c.date());
            if ts <= deepwork_core::now() {
                ed.ctx.toast("Pick a date in the future");
                return;
            }
            if ed.cfg.borrow().lock == LockKind::None {
                ed.ctx.toast("Choose a lock type first");
                return;
            }
            ed.cfg.borrow_mut().protect_until = ts;
            set_sub(ts);
            pop.popdown();
        });
    }
    {
        let (ed, set_sub) = (ed.clone(), set_protect_subtitle.clone());
        clear.connect_clicked(move |_| {
            ed.cfg.borrow_mut().protect_until = 0.0;
            set_sub(0.0);
            pop.popdown();
        });
    }
    {
        let ed = ed.clone();
        let hint = sched_hint.clone();
        let (date_btn, protect_sub) = (date_btn.clone(), set_protect_subtitle.clone());
        let prev = Rc::new(Cell::new(lock_row.selected()));
        let kinds = kinds.clone();
        lock_row.connect_selected_notify(move |row| {
            let k = kinds[row.selected() as usize];
            let old = prev.replace(row.selected());
            if k == LockKind::Hardcore && kinds[old as usize] != LockKind::Hardcore {
                confirm_hardcore(&ed, row, old);
            }
            row.set_subtitle(k.description());
            ed.cfg.borrow_mut().lock = k;
            sync_lock_rows(k);
            hint.set_visible(ed.cfg.borrow().schedule_enabled && k == LockKind::None);
            // A protection date follows the lock type, so it needs one.
            if k == LockKind::None {
                ed.cfg.borrow_mut().protect_until = 0.0;
            }
            date_btn.set_sensitive(k != LockKind::None);
            let ts = ed.cfg.borrow().protect_until;
            protect_sub(ts);
        });
    }
    {
        let ed = ed.clone();
        random_len
            .connect_value_notify(move |r| ed.cfg.borrow_mut().random_length = r.value() as u32);
    }
    if locked {
        // Mirror the daemon's rules so the form only offers allowed changes.
        lock_row.set_sensitive(false);
        password.set_sensitive(false);
        random_len.adjustment().set_lower(cfg.random_length as f64);
    }
    lock_group.add(&lock_row);
    lock_group.add(&hardcore_row);
    lock_group.add(&random_len);
    lock_group.add(&password);

    lock_group.add(&protect_row);
    prefs.add(&lock_group);

    // ------------------------------------------------------------- breaks
    let breaks = group("Breaks", "");
    let allowance = adw::SpinRow::with_range(0.0, 240.0, 5.0);
    allowance.set_title("Daily break allowance");
    allowance.set_subtitle("Minutes per day you may pause this block, even when it's locked");
    allowance.set_value(cfg.allowance_minutes as f64);
    {
        let ed = ed.clone();
        allowance.connect_value_notify(move |r| {
            ed.cfg.borrow_mut().allowance_minutes = r.value() as u32
        });
    }
    breaks.add(&allowance);
    let pomo = adw::ExpanderRow::builder()
        .title("Pomodoro breaks")
        .subtitle("Unblock everything for a short break at regular intervals")
        .show_enable_switch(true)
        .enable_expansion(cfg.break_every > 0 && cfg.break_length > 0)
        .build();
    let every = adw::SpinRow::with_range(5.0, 240.0, 5.0);
    every.set_title("Focus for (minutes)");
    every.set_value(if cfg.break_every > 0 {
        cfg.break_every
    } else {
        25
    } as f64);
    let length = adw::SpinRow::with_range(1.0, 60.0, 1.0);
    length.set_title("Then take a break of (minutes)");
    length.set_value(if cfg.break_length > 0 {
        cfg.break_length
    } else {
        5
    } as f64);
    pomo.add_row(&every);
    pomo.add_row(&length);
    let sync_pomo = {
        let (ed, pomo, every, length) = (ed.clone(), pomo.clone(), every.clone(), length.clone());
        move || {
            let mut c = ed.cfg.borrow_mut();
            if pomo.enables_expansion() {
                c.break_every = every.value() as u32;
                c.break_length = length.value() as u32;
            } else {
                c.break_every = 0;
                c.break_length = 0;
            }
        }
    };
    {
        let f = sync_pomo.clone();
        pomo.connect_enable_expansion_notify(move |_| f());
    }
    {
        let f = sync_pomo.clone();
        every.connect_value_notify(move |_| f());
    }
    length.connect_value_notify(move |_| sync_pomo());
    if locked {
        allowance
            .adjustment()
            .set_upper(cfg.allowance_minutes as f64);
        pomo.set_sensitive(false);
    }
    breaks.add(&pomo);
    prefs.add(&breaks);

    // ------------------------------------------------------------- delete
    if existing.is_some() {
        let danger = group("", "");
        let del = adw::ButtonRow::builder()
            .title("Delete Block")
            .start_icon_name("user-trash-symbolic")
            .build();
        del.add_css_class("destructive-action");
        del.set_sensitive(!locked);
        let ed = ed.clone();
        del.connect_activated(move |_| {
            let d = adw::AlertDialog::new(
                Some("Delete this block?"),
                Some(&format!(
                    "“{}” and its settings will be removed.",
                    ed.orig.name
                )),
            );
            d.add_response("cancel", "Cancel");
            d.add_response("delete", "Delete");
            d.set_response_appearance("delete", adw::ResponseAppearance::Destructive);
            let ed2 = ed.clone();
            d.connect_response(None, move |_, r| {
                if r == "delete"
                    && let Some(id) = &ed2.id
                    && ed2.ctx.act(ed2.ctx.store.client.delete_block(id)).is_some()
                {
                    ed2.ctx.blocks_nav.pop();
                    ed2.ctx.toast("Block deleted");
                }
            });
            d.present(Some(&ed.ctx.window));
        });
        danger.add(&del);
        prefs.add(&danger);
    }

    render_lists(&ed);
    render_sites(&ed);
    render_apps(&ed);

    // ------------------------------------------------------------- header + save
    let save = gtk::Button::builder()
        .label(if existing.is_some() { "Save" } else { "Create" })
        .build();
    save.add_css_class("suggested-action");
    let header = adw::HeaderBar::new();
    header.pack_end(&save);
    let tv = adw::ToolbarView::new();
    tv.add_top_bar(&header);
    tv.set_content(Some(&page_box));
    let title = if existing.is_some() {
        cfg.name.clone()
    } else {
        "New block".into()
    };
    let page = adw::NavigationPage::builder()
        .title(&title)
        .child(&tv)
        .build();
    {
        let ed = ed.clone();
        save.connect_clicked(move |_| {
            let cfg = ed.cfg.borrow().clone();
            if cfg.lock == LockKind::Password && password.text().is_empty() && !has_password {
                ed.ctx.toast("Enter a password for the password lock");
                password.grab_focus();
                return;
            }
            let pw = Some(password.text().to_string()).filter(|p| !p.is_empty());
            let client = &ed.ctx.store.client;
            let res = match &ed.id {
                Some(id) => client.update_block(id, cfg, pw).map(|_| ()),
                None => client.create_block(cfg, pw).map(|_| ()),
            };
            if ed.ctx.act(res).is_some() {
                ed.ctx.blocks_nav.pop();
                ed.ctx.toast(if ed.id.is_some() {
                    "Saved"
                } else {
                    "Block created"
                });
            }
        });
    }
    ctx.go("blocks");
    ctx.blocks_nav.push(&page);
}
