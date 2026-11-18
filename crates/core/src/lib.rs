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
mod tests {
    use super::*;

    #[test]
    fn times() {
        let shape = |s: &str| -> String {
            s.chars()
                .map(|c| {
                    if c.is_ascii_digit() {
                        '9'
                    } else if c.is_alphabetic() {
                        'a'
                    } else {
                        c
                    }
                })
                .collect()
        };
        assert_eq!(shape(&format_time(now())), "99:99");
        assert_eq!(shape(&format_time(now() + 3.0 * 86_400.0)), "aaa 99:99");
        let later = format_time(now() + 40.0 * 86_400.0);
        assert!(
            matches!(shape(&later).as_str(), "9 aaa 99:99" | "99 aaa 99:99"),
            "{later}"
        );
        assert_eq!(format_time(f64::MAX), "");
    }

    #[test]
    fn schedule_descriptions() {
        let weekdays: Vec<[u32; 2]> = (0..5).map(|d| [d * 1440 + 540, d * 1440 + 1020]).collect();
        assert_eq!(describe_schedule(&weekdays), "Weekdays 09:00–17:00");
        assert_eq!(describe_schedule(&[[0, 7 * 1440]]), "Every day all day");
        assert_eq!(
            describe_schedule(&[[5 * 1440 + 600, 5 * 1440 + 720]]),
            "Sat 10:00–12:00"
        );
        assert_eq!(describe_schedule(&[[0, 60], [1440, 1560]]), "3 h per week");
    }

    #[test]
    fn durations() {
        assert_eq!(format_duration(3900.0), "1 h 05 min");
        assert_eq!(format_duration(59.0), "59 s");
        assert_eq!(format_clock(3725.0), "1:02:05");
        assert_eq!(format_clock(65.0), "01:05");
    }
}
