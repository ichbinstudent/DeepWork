use super::*;

/// Local timestamp for a given date and time.
fn ts(y: i32, m: u32, d: u32, h: u32, min: u32) -> f64 {
    jiff::civil::date(y as i16, m as i8, d as i8)
        .at(h as i8, min as i8, 0, 0)
        .to_zoned_datetime(jiff::tz::TimeZone::system())
        .unwrap()
        .timestamp()
        .as_second() as f64
}

// 2026-11-16 is a Monday.
const MON: u32 = 16;

fn block(cfg: BlockConfig) -> Block {
    Block::new(validate_config(cfg).unwrap())
}

/// Whatever is accepted as a website or app can't break out of the
/// hosts file, a policy file or the registry.
#[test]
fn accepted_rules_are_safe() {
    let mut x: u64 = 0x2545_f491_4f6c_dd1d;
    let mut next = move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let pieces = [
        "a",
        "Z",
        "0",
        "-",
        ".",
        "*.",
        "www.",
        "https://",
        "/",
        "?",
        "#",
        "@",
        ":",
        " ",
        "\n",
        "\r",
        "\t",
        "\0",
        "\"",
        "'",
        "\\",
        "<",
        "&",
        "%",
        "ü",
        "é",
        "例",
        "😀",
        "com",
        "x--",
        "localhost",
        "127.0.0.1",
        "::1",
    ];
    for _ in 0..20_000 {
        let n = next() % 12;
        let raw: String = (0..n)
            .map(|_| pieces[(next() % pieces.len() as u64) as usize])
            .collect();
        if let Ok(d) = normalize_domain(&raw) {
            assert!(
                d.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-'),
                "{raw:?} -> {d:?}"
            );
        }
        if let Ok(a) = normalize_app(&raw) {
            assert!(!a.contains('\n') && !a.contains('\0'), "{raw:?} -> {a:?}");
        }
    }
}

#[test]
fn domains_are_normalized() {
    assert_eq!(
        normalize_domain("https://www.Reddit.com/r/rust?x=1").unwrap(),
        "reddit.com"
    );
    assert_eq!(normalize_domain("*.youtube.com").unwrap(), "youtube.com");
    assert_eq!(
        normalize_domain("news.ycombinator.com:443").unwrap(),
        "news.ycombinator.com"
    );
    assert_eq!(normalize_domain("www.co").unwrap(), "www.co");
    assert!(normalize_domain("localhost").is_err());
    assert!(normalize_domain("bad_domain.com").is_err());
    assert!(normalize_domain("1.2.3.4").is_err());
}

#[test]
fn cmd_rules() {
    assert_eq!(
        normalize_app(" cmd: net.minecraft ").unwrap(),
        "cmd:net.minecraft"
    );
    assert!(normalize_app("cmd:java").is_err());
    assert_eq!(
        normalize_app("cmd:/opt/game/run.sh").unwrap(),
        "cmd:/opt/game/run.sh"
    );
}

#[test]
fn protected_apps_are_rejected() {
    assert!(normalize_app("bash").is_err());
    assert!(normalize_app("/usr/bin/gnome-shell").is_err());
    assert!(normalize_app("dir/thing").is_err());
    assert_eq!(normalize_app(" Discord ").unwrap(), "Discord");
}

#[test]
fn schedule_is_merged() {
    assert_eq!(
        normalize_schedule(&[[60, 120], [0, 60], [100, 200], [300, 300]]),
        vec![[0, 200]]
    );
    assert_eq!(
        normalize_schedule(&[[10_000, 99_999]]),
        vec![[10_000, WEEK_MINUTES]]
    );
}

#[test]
fn schedule_window_simple() {
    // Monday 09:00-17:00
    let sched = [[9 * 60, 17 * 60]];
    let now = ts(2026, 11, MON, 10, 0);
    let (s, e) = schedule_window(&sched, now).unwrap();
    assert_eq!(s, ts(2026, 11, MON, 9, 0));
    assert_eq!(e, ts(2026, 11, MON, 17, 0));
    assert!(schedule_window(&sched, ts(2026, 11, MON, 17, 0)).is_none());
    assert!(schedule_window(&sched, ts(2026, 11, MON + 1, 10, 0)).is_none());
}

#[test]
fn schedule_window_wraps_week() {
    // Sunday 22:00 → Monday 02:00
    let sched = [[6 * 1440 + 22 * 60, WEEK_MINUTES], [0, 120]];
    let now = ts(2026, 11, MON, 1, 0);
    let (s, e) = schedule_window(&sched, now).unwrap();
    assert_eq!(s, ts(2026, 11, MON - 1, 22, 0));
    assert_eq!(e, ts(2026, 11, MON, 2, 0));
}

#[test]
fn full_week_schedule_has_finite_end() {
    let now = ts(2026, 11, MON, 1, 0);
    let (_, e) = schedule_window(&[[0, WEEK_MINUTES]], now).unwrap();
    assert!(e.is_finite() && e > now);
}

#[test]
fn manual_session_and_locks() {
    let mut b = block(BlockConfig {
        lock: LockKind::Random,
        ..Default::default()
    });
    let now = 1_000_000.0;
    assert!(!b.locked(now, "boot"));
    b.rt.session_start = now;
    b.rt.session_until = now + 3600.0;
    assert!(b.enforcing(now) && b.locked(now, "boot"));
    b.rt.unlocked_until = now + 3600.0;
    assert!(!b.locked(now, "boot"));
    assert!(!b.locked(now + 4000.0, "boot"));
    assert!(!b.enforcing(now + 4000.0));
}

#[test]
fn restart_lock_releases_after_reboot() {
    let mut b = block(BlockConfig {
        lock: LockKind::Restart,
        ..Default::default()
    });
    b.rt.session_until = 2000.0;
    b.rt.lock_boot_id = "boot-a".into();
    assert!(b.locked(1000.0, "boot-a"));
    assert!(!b.locked(1000.0, "boot-b"));
}

#[test]
fn protection_locks_outside_window() {
    let mut b = block(BlockConfig {
        protect_until: 5000.0,
        lock: LockKind::Random,
        ..Default::default()
    });
    assert!(b.locked(1000.0, "x"));
    assert!(!b.locked(6000.0, "x"));
    // an unlock lifts the protection for a while
    b.rt.unlocked_until = 2000.0;
    assert!(!b.locked(1500.0, "x"));
    assert!(b.locked(2500.0, "x"));
}

#[test]
fn restart_lock_lifts_protection_after_reboot() {
    let mut b = block(BlockConfig {
        protect_until: 5000.0,
        lock: LockKind::Restart,
        ..Default::default()
    });
    b.rt.protect_boot_id = "boot-a".into();
    assert!(b.locked(1000.0, "boot-a"));
    assert!(!b.protection_active(1000.0, "boot-b"));
    assert!(!b.locked(1000.0, "boot-b"));
}

#[test]
fn skip_suppresses_schedule() {
    let mut b = block(BlockConfig {
        schedule: vec![[0, WEEK_MINUTES]],
        schedule_enabled: true,
        ..Default::default()
    });
    let now = ts(2026, 11, MON, 12, 0);
    assert!(b.enforcing(now));
    b.rt.skip_until = now + 60.0;
    assert!(!b.enforcing(now));
    assert!(b.enforcing(now + 61.0));
}

#[test]
fn pomodoro_cycles() {
    let mut b = block(BlockConfig {
        break_every: 25,
        break_length: 5,
        ..Default::default()
    });
    b.rt.session_start = 0.0 + 1.0;
    b.rt.session_until = 1.0 + 7200.0;
    assert_eq!(b.pomodoro(1.0 + 60.0), Some((false, 24.0 * 60.0)));
    assert!(b.on_break(1.0 + 26.0 * 60.0));
    assert!(!b.enforcing(1.0 + 26.0 * 60.0));
    assert!(b.enforcing(1.0 + 31.0 * 60.0));
}

#[test]
fn allowance_accounting() {
    let mut b = block(BlockConfig {
        allowance_minutes: 10,
        ..Default::default()
    });
    let now = ts(2026, 11, MON, 12, 0);
    assert_eq!(b.allowance_left(now), 600.0);
    b.rt.allowance_used.insert(today_key(now), 540.0);
    assert_eq!(b.allowance_left(now), 60.0);
    assert_eq!(b.allowance_left(now + DAY), 600.0);
}

#[test]
fn weakening_detection() {
    let old = validate_config(BlockConfig {
        websites: vec!["a.com".into(), "b.com".into()],
        apps: vec!["Discord".into()],
        schedule: vec![[0, 600]],
        schedule_enabled: true,
        lock: LockKind::Random,
        random_length: 40,
        allowance_minutes: 5,
        ..Default::default()
    })
    .unwrap();
    // Strengthening is fine.
    let mut stronger = old.clone();
    stronger.websites.push("c.com".into());
    stronger.apps = vec!["discord".into(), "steam".into()];
    stronger.schedule = vec![[0, 900]];
    stronger.random_length = 60;
    stronger.allowance_minutes = 2;
    stronger.name = "renamed".into();
    assert!(weakening_reasons(&old, &validate_config(stronger).unwrap(), false).is_empty());

    let mut w = old.clone();
    w.websites.pop();
    assert_eq!(weakening_reasons(&old, &w, false), vec!["remove websites"]);
    let mut w = old.clone();
    w.schedule = vec![[60, 600]];
    assert_eq!(
        weakening_reasons(&old, &w, false),
        vec!["shrink the schedule"]
    );
    let mut w = old.clone();
    w.schedule_enabled = false;
    assert_eq!(
        weakening_reasons(&old, &w, false),
        vec!["turn off the schedule"]
    );
    let mut w = old.clone();
    w.lock = LockKind::None;
    assert_eq!(
        weakening_reasons(&old, &w, false),
        vec!["change the lock type"]
    );
    let mut w = old.clone();
    w.allowance_minutes = 30;
    w.break_every = 25;
    w.break_length = 5;
    assert_eq!(
        weakening_reasons(&old, &w, false),
        vec!["increase the allowance", "add or lengthen breaks"]
    );
}

#[test]
fn filter_lists() {
    let base = validate_config(BlockConfig {
        websites: vec!["reddit.com".into(), "example.org".into()],
        lists: vec!["social".into()],
        ..Default::default()
    })
    .unwrap();
    assert!(base.effective_websites().contains("instagram.com"));
    assert!(base.effective_websites().contains("example.org"));
    assert!(!base.blocks_nothing());
    assert!(
        validate_config(BlockConfig {
            lists: vec!["nope".into()],
            ..Default::default()
        })
        .is_err()
    );
    // reddit.com is still covered by the social list, so dropping it is fine
    let mut w = base.clone();
    w.websites = vec!["example.org".into()];
    assert!(weakening_reasons(&base, &w, false).is_empty());
    // dropping the list is not
    let mut w = base.clone();
    w.lists.clear();
    assert_eq!(
        weakening_reasons(&base, &w, false),
        vec!["remove websites", "remove applications"]
    );
    // adding one is
    let mut w = base.clone();
    w.lists.push("games".into());
    assert!(weakening_reasons(&base, &w, false).is_empty());
    assert!(w.effective_apps().iter().any(|a| a == "steam"));
}

#[test]
fn passwords_roundtrip() {
    // Generated, so no password is written into the code.
    let password = random_text(12);
    let other = password[1..].to_string();
    let h = hash_password(&password);
    assert!(verify_password(&password, &h));
    assert!(!verify_password(&other, &h));
    assert!(!verify_password(&password, "garbage"));
}

#[test]
fn schedules_in_other_time_zones() {
    let sched = vec![[9 * 60, 17 * 60]]; // Monday 9:00 to 17:00
    let now = ts(2026, 11, MON, 10, 0);
    let here = system_zone();
    assert_eq!(
        schedule_window_in(&sched, now, &here),
        schedule_window(&sched, now)
    );
    // Eight hours further east it's 18:00 there: the window is over.
    let east = fixed_zone(utc_offset(&here, now) + 8 * 3600);
    assert!(zones_differ(&here, &east, now));
    assert!(!zones_differ(&here, &here.clone(), now));
    assert!(schedule_window_in(&sched, now, &east).is_none());
    assert_eq!(minute_of_week_in(now, &east), 18.0 * 60.0);
}

#[test]
fn random_text_uses_alphabet() {
    let t = random_text(50);
    assert_eq!(t.len(), 50);
    assert!(t.bytes().all(|c| RANDOM_ALPHABET.contains(&c)));
}
