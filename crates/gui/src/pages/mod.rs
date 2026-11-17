pub mod blocks;
pub mod dashboard;
pub mod freeze;
pub mod settings;
pub mod stats;

use adw::prelude::*;

/// Header bar + scrollable, width-clamped content.
pub fn page_shell(content: &impl IsA<gtk::Widget>, header: &adw::HeaderBar) -> adw::ToolbarView {
    let clamp = adw::Clamp::builder()
        .maximum_size(880)
        .tightening_threshold(600)
        .child(content)
        .margin_top(24)
        .margin_bottom(32)
        .margin_start(16)
        .margin_end(16)
        .build();
    let scroller = gtk::ScrolledWindow::builder()
        .child(&clamp)
        .vexpand(true)
        .hscrollbar_policy(gtk::PolicyType::Never)
        .build();
    let tv = adw::ToolbarView::new();
    tv.add_top_bar(header);
    tv.set_content(Some(&scroller));
    tv
}
