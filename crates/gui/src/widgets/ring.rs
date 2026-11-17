//! Circular progress ring with a label in the middle.

use std::cell::RefCell;
use std::f64::consts::PI;
use std::rc::Rc;

use gtk::gdk;
use gtk::prelude::*;

use super::set_source;

#[derive(Clone)]
pub struct Ring {
    pub widget: gtk::Overlay,
    area: gtk::DrawingArea,
    state: Rc<RefCell<(f64, gdk::RGBA)>>,
    pub time: gtk::Label,
    pub caption: gtk::Label,
}

impl Ring {
    pub fn new(size: i32) -> Self {
        let area = gtk::DrawingArea::builder()
            .content_width(size)
            .content_height(size)
            .build();
        let state = Rc::new(RefCell::new((0.0, super::accent())));
        let st = state.clone();
        area.set_draw_func(move |area, cr, w, h| {
            let (frac, color): (f64, gdk::RGBA) = *st.borrow();
            let fg = area.color();
            let line = 12.0;
            let r = (w.min(h) as f64 - line) / 2.0;
            let (cx, cy) = (w as f64 / 2.0, h as f64 / 2.0);
            cr.set_line_width(line);
            cr.set_line_cap(gtk::cairo::LineCap::Round);
            set_source(cr, &fg, 0.08);
            cr.arc(cx, cy, r, 0.0, 2.0 * PI);
            let _ = cr.stroke();
            if frac > 0.0 {
                set_source(cr, &color, 1.0);
                let start = -PI / 2.0;
                cr.arc(cx, cy, r, start, start + 2.0 * PI * frac.clamp(0.002, 1.0));
                let _ = cr.stroke();
            }
        });
        let time = gtk::Label::builder().css_classes(["ring-time"]).build();
        let caption = gtk::Label::builder().css_classes(["ring-caption"]).build();
        let center = gtk::Box::builder()
            .orientation(gtk::Orientation::Vertical)
            .halign(gtk::Align::Center)
            .valign(gtk::Align::Center)
            .build();
        center.append(&time);
        center.append(&caption);
        let widget = gtk::Overlay::builder()
            .child(&area)
            .halign(gtk::Align::Center)
            .valign(gtk::Align::Center)
            .build();
        widget.add_overlay(&center);
        Self {
            widget,
            area,
            state,
            time,
            caption,
        }
    }

    pub fn set(&self, fraction: f64, color: gdk::RGBA, time: &str, caption: &str) {
        let changed = {
            let s = self.state.borrow();
            (s.0 - fraction).abs() > 1e-4 || s.1 != color
        };
        if changed {
            *self.state.borrow_mut() = (fraction, color);
            self.area.queue_draw();
        }
        self.time.set_label(time);
        self.caption.set_label(caption);
    }
}
