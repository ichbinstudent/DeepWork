//! "Blocks" page: list of all blocks; the editor is pushed on top.

use std::cell::RefCell;
use std::rc::Rc;

use adw::prelude::*;
use deepwork_core::model::LockKind;

use crate::editor;
use crate::util::{badge, block_summary, clear_listbox, dot, pill, signature};
use crate::window::Ctx;

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

    let content = gtk::Box::new(gtk::Orientation::Vertical, 24);
    let group = adw::PreferencesGroup::builder()
        .title("Blocks")
        .description("Each block is a set of websites and apps, with its own schedule and lock.")
        .build();
    let list = gtk::ListBox::builder()
        .selection_mode(gtk::SelectionMode::None)
        .build();
    list.add_css_class("boxed-list");
    group.add(&list);
    content.append(&group);

    let empty_btn = gtk::Button::builder()
        .label("New Block")
        .halign(gtk::Align::Center)
        .build();
    empty_btn.add_css_class("pill");
    empty_btn.add_css_class("suggested-action");
    {
        let ctx = ctx.clone();
        empty_btn.connect_clicked(move |_| editor::open(&ctx, None));
    }
    let empty = adw::StatusPage::builder()
        .icon_name("dw-shield-symbolic")
        .title("No blocks yet")
        .description("Create a block, add the websites and apps that distract you, then start it or give it a schedule.")
        .child(&empty_btn)
        .build();
    content.append(&empty);

    let sig = Rc::new(RefCell::new(String::new()));
    let update = {
        let ctx = ctx.clone();
        move || {
            let Some(s) = ctx.store.status() else { return };
            let new_sig = signature(
                &s.blocks
                    .iter()
                    .map(|b| (&b.id, &b.config, badge(b)))
                    .collect::<Vec<_>>(),
            );
            if *sig.borrow() == new_sig {
                return;
            }
            *sig.borrow_mut() = new_sig;
            clear_listbox(&list);
            for b in &s.blocks {
                let row = adw::ActionRow::builder()
                    .title(gtk::glib::markup_escape_text(&b.config.name).as_str())
                    .subtitle(gtk::glib::markup_escape_text(&block_summary(&b.config)).as_str())
                    .activatable(true)
                    .build();
                row.add_prefix(&dot(&b.config.color));
                if b.config.lock != LockKind::None {
                    let img = gtk::Image::from_icon_name("changes-prevent-symbolic");
                    img.set_tooltip_text(Some(&format!("Lock: {}", b.config.lock.label())));
                    img.add_css_class("dim-label");
                    row.add_suffix(&img);
                }
                let (text, class) = badge(b);
                row.add_suffix(&pill(text, class));
                row.add_suffix(&gtk::Image::from_icon_name("go-next-symbolic"));
                let (ctx, id) = (ctx.clone(), b.id.clone());
                row.connect_activated(move |_| {
                    if let Some(b) = ctx.store.block(&id) {
                        editor::open(&ctx, Some(&b));
                    }
                });
                list.append(&row);
            }
            group.set_visible(!s.blocks.is_empty());
            empty.set_visible(s.blocks.is_empty());
        }
    };
    update();
    ctx.store.subscribe(update);

    let shell = crate::pages::page_shell(&content, &header);
    let root = adw::NavigationPage::builder()
        .title("Blocks")
        .tag("list")
        .child(&shell)
        .build();
    ctx.blocks_nav.add(&root);
    ctx.blocks_nav.clone().upcast()
}
