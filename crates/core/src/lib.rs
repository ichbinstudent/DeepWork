//! Shared model, rules and protocol for DeepWork.

pub mod client;
pub mod doh;
pub mod lists;
pub mod model;
pub mod procinfo;
pub mod protocol;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Current wall-clock time in unix seconds.
pub fn now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// "1 h 05 min", "12 min", "45 s"
pub fn format_duration(secs: f64) -> String {
    let s = secs.max(0.0).round() as u64;
    let (d, h, m) = (s / 86_400, (s % 86_400) / 3600, (s % 3600) / 60);
    if d > 0 {
        format!("{d} d {h} h")
    } else if h > 0 {
        format!("{h} h {m:02} min")
    } else if m > 0 {
        format!("{m} min")
    } else {
        format!("{s} s")
    }
}

/// "1:05:09" or "05:09"
pub fn format_clock(secs: f64) -> String {
    let s = secs.max(0.0).ceil() as u64;
    let (h, m, sec) = (s / 3600, (s % 3600) / 60, s % 60);
    if h > 0 {
        format!("{h}:{m:02}:{sec:02}")
    } else {
        format!("{m:02}:{sec:02}")
    }
}

/// "17:30" today, "Tue 09:00" within a week, "24 Dec 09:00" otherwise.
pub fn format_time(ts: f64) -> String {
    let Some(t) = model::local_time(ts) else {
        return String::new();
    };
    let today = jiff::ZonedDateTime::now();
    let days_apart = (t.timestamp().as_second() - today.timestamp().as_second()).abs() / 86_400;
    if t.date() == today.date() {
        t.strftime("%H:%M").to_string()
    } else if days_apart < 6 {
        t.strftime("%a %H:%M").to_string()
    } else {
        t.strftime("%-d %b %H:%M").to_string()
    }
}

pub const DAY_NAMES: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];

fn hm(m: u32) -> String {
    format!("{:02}:{:02}", m / 60, m % 60)
}

/// Human summary of a weekly schedule, e.g. "Weekdays 09:00–17:00".
pub fn describe_schedule(ranges: &[[u32; 2]]) -> String {
    if ranges.is_empty() {
        return "No times selected".into();
    }
    // Split into per-day intra-day ranges.
    let mut days: [Vec<[u32; 2]>; 7] = Default::default();
    for r in ranges {
        let mut a = r[0];
        while a < r[1] {
            let d = (a / 1440) as usize;
            let end = r[1].min((d as u32 + 1) * 1440);
            days[d].push([a - d as u32 * 1440, end - d as u32 * 1440]);
            a = end;
        }
    }
    let active: Vec<usize> = (0..7).filter(|d| !days[*d].is_empty()).collect();
    let first = &days[active[0]];
    if active.iter().all(|d| &days[*d] == first) {
        let which = match active.as_slice() {
            [0, 1, 2, 3, 4, 5, 6] => "Every day".to_string(),
            [0, 1, 2, 3, 4] => "Weekdays".to_string(),
            [5, 6] => "Weekends".to_string(),
            ds => ds
                .iter()
                .map(|d| DAY_NAMES[*d])
                .collect::<Vec<_>>()
                .join(", "),
        };
        let times = if first == &vec![[0, 1440]] {
            "all day".to_string()
        } else {
            first
                .iter()
                .map(|r| format!("{}–{}", hm(r[0]), hm(r[1])))
                .collect::<Vec<_>>()
                .join(", ")
        };
        return format!("{which} {times}");
    }
    let total: u32 = ranges.iter().map(|r| r[1] - r[0]).sum();
    format!("{} h per week", (total as f64 / 60.0).round())
}

#[cfg(test)]
mod tests;
