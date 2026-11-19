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
