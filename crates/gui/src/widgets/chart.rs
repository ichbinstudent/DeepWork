//! A small bar chart of focus hours per day.

use std::cell::RefCell;
use std::rc::Rc;

use gtk::prelude::*;

use super::{accent, rounded_rect, set_source, text};

#[derive(Clone, Default)]
pub struct Bar {
    pub label: String,
    pub value: f64,
    pub highlight: bool,
}

#[derive(Clone)]
pub struct BarChart {
    pub area: gtk::DrawingArea,
    data: Rc<RefCell<Vec<Bar>>>,
}

fn nice_max(v: f64) -> f64 {
    for step in [0.5, 1.0, 2.0, 4.0, 6.0, 8.0, 12.0, 16.0, 24.0] {
        if v <= step {
            return step;
        }
    }
    v.ceil()
}

impl BarChart {
    pub fn new() -> Self {
        let area = gtk::DrawingArea::builder()
            .content_height(220)
            .hexpand(true)
            .build();
        let data: Rc<RefCell<Vec<Bar>>> = Rc::default();
        let d = data.clone();
        area.set_draw_func(move |area, cr, w, h| {
            let bars = d.borrow();
            if bars.is_empty() {
                return;
            }
            let fg = area.color();
            let acc = accent();
            let (w, h) = (w as f64, h as f64);
            let (left, bottom, top) = (36.0, 24.0, 8.0);
            let plot_h = h - bottom - top;
            let max = nice_max(bars.iter().map(|b| b.value).fold(0.0, f64::max).max(0.5));

            // grid lines + y labels
            for i in 0..=4 {
                let v = max * i as f64 / 4.0;
                let y = top + plot_h - plot_h * i as f64 / 4.0;
                set_source(cr, &fg, if i == 0 { 0.18 } else { 0.07 });
                cr.set_line_width(1.0);
                cr.move_to(left, y.round() + 0.5);
                cr.line_to(w, y.round() + 0.5);
                let _ = cr.stroke();
                set_source(cr, &fg, 0.5);
                let label = if v.fract() == 0.0 {
                    format!("{v:.0}h")
                } else {
                    format!("{v:.1}h")
                };
                text(area, cr, &label, left - 8.0, y - 7.0, 1.0, 7.5, false);
            }

            let slot = (w - left) / bars.len() as f64;
            let bar_w = (slot * 0.56).min(36.0);
            for (i, b) in bars.iter().enumerate() {
                let x = left + slot * i as f64 + (slot - bar_w) / 2.0;
                let bh = (b.value / max * plot_h).max(if b.value > 0.0 { 3.0 } else { 0.0 });
                if bh > 0.0 {
                    set_source(cr, &acc, if b.highlight { 1.0 } else { 0.55 });
                    rounded_rect(
                        cr,
                        x,
                        top + plot_h - bh,
                        bar_w,
                        bh,
                        6.0_f64.min(bar_w / 2.0),
                    );
                    let _ = cr.fill();
                }
                set_source(cr, &fg, if b.highlight { 0.9 } else { 0.5 });
                text(
                    area,
                    cr,
                    &b.label,
                    x + bar_w / 2.0,
                    top + plot_h + 6.0,
                    0.5,
                    7.5,
                    b.highlight,
                );
            }
        });
        Self { area, data }
    }

    pub fn set(&self, bars: Vec<Bar>) {
        *self.data.borrow_mut() = bars;
        self.area.queue_draw();
    }
}
