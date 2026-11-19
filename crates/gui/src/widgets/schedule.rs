//! Weekly schedule painter: drag across the grid to select times.
//!
//! Rows are days (Mon–Sun), columns are half hours. Dragging paints a
//! rectangle; starting on a filled cell erases instead.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use deepwork_core::DAY_NAMES;
use deepwork_core::model::minute_of_week;
use gtk::prelude::*;

use super::{accent, rounded_rect, set_source, text};

pub const SLOT_MIN: u32 = 30;
pub const SLOTS_PER_DAY: usize = (24 * 60 / SLOT_MIN) as usize;
pub const SLOTS: usize = 7 * SLOTS_PER_DAY;

const LEFT: f64 = 40.0;
const TOP: f64 = 20.0;
const ROW_H: f64 = 26.0;
const GAP: f64 = 2.0;

pub type Slots = [bool; SLOTS];

pub fn slots_from_ranges(ranges: &[[u32; 2]]) -> Slots {
    let mut s = [false; SLOTS];
    for r in ranges {
        for (i, slot) in s.iter_mut().enumerate() {
            let (a, b) = (i as u32 * SLOT_MIN, (i as u32 + 1) * SLOT_MIN);
            if a < r[1] && b > r[0] {
                *slot = true;
            }
        }
    }
    s
}

pub fn ranges_from_slots(s: &Slots) -> Vec<[u32; 2]> {
    let mut out: Vec<[u32; 2]> = vec![];
    for (i, on) in s.iter().enumerate() {
        if !on {
            continue;
        }
        let (a, b) = (i as u32 * SLOT_MIN, (i as u32 + 1) * SLOT_MIN);
        match out.last_mut() {
            Some(last) if last[1] == a => last[1] = b,
            _ => out.push([a, b]),
        }
    }
    out
}

#[derive(Clone, Copy)]
struct Drag {
    start: (usize, usize),
    current: (usize, usize),
    paint: bool,
}

type ChangeFn = Box<dyn Fn(Vec<[u32; 2]>)>;

#[derive(Clone)]
pub struct ScheduleGrid {
    pub widget: gtk::DrawingArea,
    slots: Rc<RefCell<Slots>>,
    /// Slots that can't be removed (block is locked).
    fixed: Rc<RefCell<Slots>>,
    drag: Rc<Cell<Option<Drag>>>,
    on_change: Rc<RefCell<Option<ChangeFn>>>,
}

fn cell_at(w: f64, x: f64, y: f64) -> (usize, usize) {
    let cw = (w - LEFT) / SLOTS_PER_DAY as f64;
    let col = ((x - LEFT) / cw)
        .floor()
        .clamp(0.0, SLOTS_PER_DAY as f64 - 1.0) as usize;
    let row = ((y - TOP) / (ROW_H + GAP)).floor().clamp(0.0, 6.0) as usize;
    (row, col)
}

fn in_rect(d: &Drag, row: usize, col: usize) -> bool {
    let (r0, r1) = (d.start.0.min(d.current.0), d.start.0.max(d.current.0));
    let (c0, c1) = (d.start.1.min(d.current.1), d.start.1.max(d.current.1));
    (r0..=r1).contains(&row) && (c0..=c1).contains(&col)
}

impl ScheduleGrid {
    pub fn new() -> Self {
        let widget = gtk::DrawingArea::builder()
            .content_height((TOP + 7.0 * (ROW_H + GAP)) as i32)
            .hexpand(true)
            .cursor(&gtk::gdk::Cursor::from_name("crosshair", None).unwrap())
            .build();
        let grid = Self {
            widget,
            slots: Rc::new(RefCell::new([false; SLOTS])),
            fixed: Rc::new(RefCell::new([false; SLOTS])),
            drag: Rc::new(Cell::new(None)),
            on_change: Rc::default(),
        };
        grid.setup_draw();
        grid.setup_drag();
        grid
    }

    pub fn set_ranges(&self, ranges: &[[u32; 2]]) {
        *self.slots.borrow_mut() = slots_from_ranges(ranges);
        self.widget.queue_draw();
    }

    pub fn set_fixed(&self, ranges: &[[u32; 2]]) {
        *self.fixed.borrow_mut() = slots_from_ranges(ranges);
    }

    pub fn connect_changed(&self, f: impl Fn(Vec<[u32; 2]>) + 'static) {
        *self.on_change.borrow_mut() = Some(Box::new(f));
    }

    fn setup_draw(&self) {
        let slots = self.slots.clone();
        let drag = self.drag.clone();
        self.widget.set_draw_func(move |area, cr, w, _h| {
            let w = w as f64;
            let fg = area.color();
            let acc = accent();
            let cw = (w - LEFT) / SLOTS_PER_DAY as f64;
            let slots = slots.borrow();
            let drag = drag.get();
            let now_mow = minute_of_week(deepwork_core::now());
            let today = (now_mow / 1440.0) as usize;

            // hour labels
            for h in (0..24).step_by(3) {
                let x = LEFT + (h * 2) as f64 * cw;
                set_source(cr, &fg, 0.5);
                text(area, cr, &format!("{h:02}"), x, 0.0, 0.0, 7.5, false);
            }
            for (d, name) in DAY_NAMES.iter().enumerate() {
                let y = TOP + d as f64 * (ROW_H + GAP);
                set_source(cr, &fg, if d == today { 0.95 } else { 0.55 });
                text(
                    area,
                    cr,
                    name,
                    0.0,
                    y + ROW_H / 2.0 - 8.0,
                    0.0,
                    8.5,
                    d == today,
                );
                for c in 0..SLOTS_PER_DAY {
                    let mut on = slots[d * SLOTS_PER_DAY + c];
                    let mut preview = false;
                    if let Some(dr) = drag.filter(|dr| in_rect(dr, d, c)) {
                        preview = on != dr.paint;
                        on = dr.paint;
                    }
                    // extra gap between hours for readability
                    let x = LEFT + c as f64 * cw + if c % 2 == 0 { 1.0 } else { 0.0 };
                    let cell_w = cw - 1.5;
                    if on {
                        set_source(cr, &acc, if preview { 0.6 } else { 0.9 });
                    } else {
                        set_source(cr, &fg, if preview { 0.14 } else { 0.06 });
                    }
                    rounded_rect(cr, x, y, cell_w.max(1.0), ROW_H, 3.0);
                    let _ = cr.fill();
                }
            }
            // "now" marker
            let y = TOP + today as f64 * (ROW_H + GAP);
            let x = LEFT + (now_mow % 1440.0) / SLOT_MIN as f64 * cw;
            cr.set_source_rgba(0.88, 0.11, 0.14, 0.9);
            cr.set_line_width(2.0);
            cr.move_to(x, y - 2.0);
            cr.line_to(x, y + ROW_H + 2.0);
            let _ = cr.stroke();
        });
    }

    fn setup_drag(&self) {
        let gesture = gtk::GestureDrag::new();
        let origin = Rc::new(Cell::new((0.0, 0.0)));
        {
            let (slots, drag, origin, area) = (
                self.slots.clone(),
                self.drag.clone(),
                origin.clone(),
                self.widget.clone(),
            );
            gesture.connect_drag_begin(move |_, x, y| {
                origin.set((x, y));
                let cell = cell_at(area.width() as f64, x, y);
                let paint = !slots.borrow()[cell.0 * SLOTS_PER_DAY + cell.1];
                drag.set(Some(Drag {
                    start: cell,
                    current: cell,
                    paint,
                }));
                area.queue_draw();
            });
        }
        {
            let (drag, origin, area) = (self.drag.clone(), origin.clone(), self.widget.clone());
            gesture.connect_drag_update(move |_, dx, dy| {
                if let Some(mut d) = drag.get() {
                    let (x, y) = origin.get();
                    d.current = cell_at(area.width() as f64, x + dx, y + dy);
                    drag.set(Some(d));
                    area.queue_draw();
                }
            });
        }
        {
            let (slots, fixed, drag, area, cb) = (
                self.slots.clone(),
                self.fixed.clone(),
                self.drag.clone(),
                self.widget.clone(),
                self.on_change.clone(),
            );
            gesture.connect_drag_end(move |_, _, _| {
                let Some(d) = drag.take() else { return };
                {
                    let mut s = slots.borrow_mut();
                    let fixed = fixed.borrow();
                    for row in 0..7 {
                        for col in 0..SLOTS_PER_DAY {
                            if in_rect(&d, row, col) {
                                let i = row * SLOTS_PER_DAY + col;
                                s[i] = d.paint || fixed[i];
                            }
                        }
                    }
                }
                area.queue_draw();
                let ranges = ranges_from_slots(&slots.borrow());
                if let Some(f) = cb.borrow().as_ref() {
                    f(ranges);
                }
            });
        }
        self.widget.add_controller(gesture);
    }
}

#[cfg(test)]
mod tests;
