pub mod chart;
pub mod ring;
pub mod schedule;

use gtk::prelude::*;
use gtk::{cairo, gdk, pango};

pub fn set_source(cr: &cairo::Context, c: &gdk::RGBA, alpha: f64) {
    cr.set_source_rgba(
        c.red() as f64,
        c.green() as f64,
        c.blue() as f64,
        c.alpha() as f64 * alpha,
    );
}

pub fn rounded_rect(cr: &cairo::Context, x: f64, y: f64, w: f64, h: f64, r: f64) {
    let r = r.min(w / 2.0).min(h / 2.0).max(0.0);
    let pi = std::f64::consts::PI;
    cr.new_sub_path();
    cr.arc(x + w - r, y + r, r, -pi / 2.0, 0.0);
    cr.arc(x + w - r, y + h - r, r, 0.0, pi / 2.0);
    cr.arc(x + r, y + h - r, r, pi / 2.0, pi);
    cr.arc(x + r, y + r, r, pi, 1.5 * pi);
    cr.close_path();
}

/// Draw text with the widget's font. `align`: 0 = left, 0.5 = centre, 1 = right
/// relative to `x`; `y` is the top edge.
#[allow(clippy::too_many_arguments)]
pub fn text(
    widget: &impl IsA<gtk::Widget>,
    cr: &cairo::Context,
    s: &str,
    x: f64,
    y: f64,
    align: f64,
    size_pt: f64,
    bold: bool,
) -> (f64, f64) {
    let layout = widget.create_pango_layout(Some(s));
    let mut fd = layout.context().font_description().unwrap_or_default();
    fd.set_size((size_pt * pango::SCALE as f64) as i32);
    if bold {
        fd.set_weight(pango::Weight::Bold);
    }
    layout.set_font_description(Some(&fd));
    let (w, h) = layout.pixel_size();
    cr.move_to(x - w as f64 * align, y);
    pangocairo::functions::show_layout(cr, &layout);
    (w as f64, h as f64)
}

pub fn accent() -> gdk::RGBA {
    adw::StyleManager::default().accent_color_rgba()
}
