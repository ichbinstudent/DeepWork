use super::*;

const T: f64 = 1_800_000_000.0;

fn daemon_with(cfg: BlockConfig, password: Option<&str>) -> (Daemon, String) {
    let mut d = Daemon::new(
        Persisted::default(),
        "boot-1".into(),
        Capabilities::all("test"),
    );
    let r = d.handle(
        Request::CreateBlock {
            config: cfg,
            password: password.map(Into::into),
        },
        T,
    );
    assert!(r.ok, "{:?}", r.error);
    let id = r.data.as_str().unwrap().to_string();
    (d, id)
}

/// A password and a wrong guess, generated so that no password is
/// written into the code.
fn test_password() -> (String, String) {
    let password = random_text(12);
    let wrong = password[1..].to_string();
    (password, wrong)
}

fn sites() -> BlockConfig {
    BlockConfig {
        name: "Social".into(),
        websites: vec!["reddit.com".into()],
        ..Default::default()
    }
}

#[test]
fn start_tick_and_plan() {
    let (mut d, id) = daemon_with(
        BlockConfig {
            apps: vec!["steam".into()],
            ..sites()
        },
        None,
    );
    assert!(d.tick(T, 1.0, 1.0).domains.is_empty());
    assert!(
        d.handle(
            Request::StartBlock {
                id: id.clone(),
                minutes: 30
            },
            T
        )
        .ok
    );
    let plan = d.tick(T + 1.0, 1.0, 1.0);
    assert!(plan.domains.contains("reddit.com"));
    assert_eq!(plan.apps, vec![("steam".to_string(), "Social".to_string())]);
    assert!(d.tick(T + 31.0 * 60.0, 1.0, 1.0).domains.is_empty());
    // session cleared after it ended
    assert_eq!(d.p.blocks[0].rt.session_until, 0.0);
}

#[test]
fn filter_lists_are_enforced() {
    let cfg = BlockConfig {
        lists: vec!["games".into()],
        ..Default::default()
    };
    let (mut d, id) = daemon_with(cfg, None);
    assert!(
        d.handle(Request::StartBlock { id, minutes: 10 }, T).ok,
        "a list alone is enough to start"
    );
    let plan = d.tick(T + 1.0, 1.0, 1.0);
    assert!(plan.domains.contains("store.steampowered.com"));
    assert!(plan.apps.iter().any(|(a, _)| a == "steam"));
}

#[test]
fn network_settings() {
    let (mut d, id) = daemon_with(
        BlockConfig {
            lock: LockKind::Strict,
            ..sites()
        },
        None,
    );
    assert!(
        d.p.settings.block_doh,
        "encrypted DNS blocking is on by default"
    );
    // nothing running: no network measures
    let plan = d.tick(T, 1.0, 1.0);
    assert!(!plan.block_doh && !plan.https_filter);
    let on = Settings {
        block_doh: true,
        https_filter: true,
    };
    assert!(d.handle(Request::SetSettings { settings: on }, T).ok);
    d.handle(Request::StartBlock { id, minutes: 30 }, T);
    let plan = d.tick(T + 1.0, 1.0, 1.0);
    assert!(plan.block_doh && plan.https_filter);
    // locked: can't relax
    let off = Settings {
        block_doh: false,
        https_filter: false,
    };
    let r = d.handle(Request::SetSettings { settings: off }, T + 2.0);
    assert!(!r.ok);
    assert!(
        r.error
            .unwrap()
            .contains("turn off encrypted DNS blocking or turn off HTTPS filtering")
    );
    assert!(d.status(T + 2.0).settings.https_filter);
}

#[test]
fn hardcore_blocks() {
    let hardcore = BlockConfig {
        lock: LockKind::Hardcore,
        apps: vec!["steam".into()],
        ..Default::default()
    };
    let (mut d, id) = daemon_with(hardcore.clone(), None);
    let off = Settings {
        block_doh: false,
        https_filter: false,
    };
    assert!(d.handle(Request::SetSettings { settings: off }, T).ok);
    assert_eq!(d.tick(T, 1.0, 1.0).hardcore_until, 0.0);

    // At most 7 days in one go.
    let start = |d: &mut Daemon, minutes, now| {
        d.handle(
            Request::StartBlock {
                id: id.clone(),
                minutes,
            },
            now,
        )
    };
    assert!(!start(&mut d, 7 * 24 * 60 + 1, T).ok);
    assert!(start(&mut d, 120, T).ok);
    assert!(
        !start(&mut d, 7 * 24 * 60, T + 60.0).ok,
        "extending counts too"
    );

    let plan = d.tick(T + 1.0, 1.0, 1.0);
    assert_eq!(plan.hardcore_until, T + 120.0 * 60.0);
    assert!(plan.block_tunnels);
    // The VPN list comes with it, and the network protections are on
    // even though the settings say otherwise.
    assert!(plan.domains.contains("torproject.org"));
    assert!(plan.apps.iter().any(|(a, _)| a == "openvpn"));
    assert!(plan.block_doh && plan.https_filter);

    // Strict: no stopping, no unlocking, no changing the lock.
    assert!(!d.handle(Request::StopBlock { id: id.clone() }, T + 2.0).ok);
    assert!(
        !d.handle(Request::UnlockChallenge { id: id.clone() }, T + 2.0)
            .ok
    );
    let r = d.handle(
        Request::UpdateBlock {
            id: id.clone(),
            config: BlockConfig {
                lock: LockKind::Strict,
                ..hardcore.clone()
            },
            password: None,
        },
        T + 2.0,
    );
    assert!(!r.ok);

    // A break unblocks, but administrator rights stay away.
    let mut b = d.p.blocks[0].clone();
    b.rt.pause_until = T + 600.0;
    d.p.blocks[0] = b;
    let plan = d.tick(T + 3.0, 1.0, 1.0);
    assert_eq!(plan.hardcore_until, T + 120.0 * 60.0);
    assert!(!plan.block_tunnels && plan.domains.is_empty());

    // Over: everything comes back.
    let plan = d.tick(T + 121.0 * 60.0, 1.0, 1.0);
    assert_eq!(plan.hardcore_until, 0.0);
    assert!(!plan.block_tunnels);
}

/// Tick every half hour from `from` to `to`, like the service does
/// every second; returns the last plan.
fn tick_through(d: &mut Daemon, from: f64, to: f64) -> Plan {
    let mut t = from;
    let mut plan = d.tick(t, 1.0, 1.0);
    while t < to {
        t = (t + 1800.0).min(to);
        plan = d.tick(t, 1.0, 1.0);
    }
    plan
}

#[test]
fn hardcore_blocks_together_stop_after_7_days() {
    let hardcore = |name: &str| BlockConfig {
        name: name.into(),
        lock: LockKind::Hardcore,
        apps: vec!["steam".into()],
        ..Default::default()
    };
    let mut d = Daemon::new(
        Persisted::default(),
        "boot-1".into(),
        Capabilities::all("test"),
    );
    let mut ids = vec![];
    for name in ["A", "B", "C"] {
        let r = d.handle(
            Request::CreateBlock {
                config: hardcore(name),
                password: None,
            },
            T,
        );
        ids.push(r.data.as_str().unwrap().to_string());
    }
    let start = |d: &mut Daemon, i: usize, minutes, now| {
        d.handle(
            Request::StartBlock {
                id: ids[i].clone(),
                minutes,
            },
            now,
        )
    };
    let day = 24 * 60;
    assert!(start(&mut d, 0, 6 * day, T).ok);
    tick_through(&mut d, T, T + 5.0 * DAY);
    // A second hardcore block continues the stretch: 7 days from T.
    let r = start(&mut d, 1, 3 * day, T + 5.0 * DAY);
    assert!(!r.ok);
    assert!(r.error.unwrap().contains("at most 7 days"));
    assert!(start(&mut d, 1, 2 * day, T + 5.0 * DAY).ok);
    let plan = tick_through(&mut d, T + 5.0 * DAY, T + 7.0 * DAY - 60.0);
    assert_eq!(plan.hardcore_until, T + 7.0 * DAY);
    let plan = tick_through(&mut d, T + 7.0 * DAY - 60.0, T + 7.0 * DAY + 600.0);
    assert_eq!(plan.hardcore_until, 0.0);

    // Right after, a third one can't take the rights away again...
    let r = start(&mut d, 2, day, T + 7.0 * DAY + 600.0);
    assert!(!r.ok);
    assert!(r.error.unwrap().contains("back for an hour"));
    // ...but once they've been back for an hour, it can.
    let later = T + 7.0 * DAY + 600.0 + HARDCORE_BREAK;
    tick_through(&mut d, T + 7.0 * DAY + 600.0, later);
    assert!(start(&mut d, 2, day, later).ok);
    assert_eq!(d.tick(later + 1.0, 1.0, 1.0).hardcore_until, later + DAY);
}

/// However hardcore windows are chained (here: a session longer than
/// allowed, as a schedule could make it), rights come back after 7 days.
#[test]
fn hardcore_rights_come_back_after_7_days() {
    let (mut d, _) = daemon_with(
        BlockConfig {
            lock: LockKind::Hardcore,
            apps: vec!["steam".into()],
            ..Default::default()
        },
        None,
    );
    d.p.blocks[0].rt.session_start = T;
    d.p.blocks[0].rt.session_until = T + 10.0 * DAY;
    let plan = tick_through(&mut d, T, T + 6.0 * DAY);
    assert_eq!(plan.hardcore_until, T + 7.0 * DAY);
    let plan = tick_through(&mut d, T + 6.0 * DAY, T + 7.0 * DAY + 60.0);
    assert_eq!(plan.hardcore_until, 0.0, "rights are back");
    assert!(plan.block_tunnels, "the block itself goes on");
    assert!(
        d.events
            .iter()
            .any(|e| e.kind == "hardcore_break" && e.ts >= T + 7.0 * DAY)
    );
    let plan = tick_through(&mut d, T + 7.0 * DAY + 60.0, T + 7.0 * DAY + 3000.0);
    assert_eq!(plan.hardcore_until, 0.0, "for an hour");
    let back = T + 7.0 * DAY + 60.0 + HARDCORE_BREAK;
    let plan = tick_through(&mut d, T + 7.0 * DAY + 3000.0, back);
    assert_eq!(plan.hardcore_until, T + 10.0 * DAY, "then hardcore again");
    // The stretch survives a restart of the service.
    let json = serde_json::to_string(&d.p).unwrap();
    let mut d2 = Daemon::new(
        serde_json::from_str(&json).unwrap(),
        "boot-1".into(),
        Capabilities::all("test"),
    );
    assert_eq!(
        d2.tick(back + 60.0, 1.0, 1.0).hardcore_until,
        T + 10.0 * DAY
    );
    assert_eq!(d2.p.hardcore_since, d.p.hardcore_since);
}

/// An unlocked block running for 30 days can't be made hardcore: that
/// would keep administrator rights away for longer than 7 days.
#[test]
fn long_sessions_cant_become_hardcore() {
    let (mut d, id) = daemon_with(
        BlockConfig {
            apps: vec!["steam".into()],
            ..Default::default()
        },
        None,
    );
    let hardcore = BlockConfig {
        lock: LockKind::Hardcore,
        ..d.p.blocks[0].config.clone()
    };
    let update = |d: &mut Daemon, now| {
        d.handle(
            Request::UpdateBlock {
                id: id.clone(),
                config: hardcore.clone(),
                password: None,
            },
            now,
        )
    };
    assert!(
        d.handle(
            Request::StartBlock {
                id: id.clone(),
                minutes: 30 * 24 * 60
            },
            T
        )
        .ok
    );
    let r = update(&mut d, T + 60.0);
    assert!(!r.ok);
    assert!(r.error.unwrap().contains("at most 7 days"));
    assert_ne!(d.p.blocks[0].config.lock, LockKind::Hardcore);

    assert!(
        d.handle(Request::StopBlock { id: id.clone() }, T + 120.0)
            .ok
    );
    assert!(
        d.handle(
            Request::StartBlock {
                id: id.clone(),
                minutes: 120
            },
            T + 180.0
        )
        .ok
    );
    assert!(update(&mut d, T + 240.0).ok, "a short one may");
    // Once hardcore, adding to it is fine.
    let mut more = d.p.blocks[0].config.clone();
    more.apps.push("lutris".into());
    let r = d.handle(
        Request::UpdateBlock {
            id: id.clone(),
            config: more,
            password: None,
        },
        T + 300.0,
    );
    assert!(r.ok, "{:?}", r.error);
}

#[test]
fn hardcore_schedules_leave_time_free() {
    let week = |ranges: Vec<[u32; 2]>| BlockConfig {
        lock: LockKind::Hardcore,
        websites: vec!["reddit.com".into()],
        schedule: ranges,
        schedule_enabled: true,
        ..Default::default()
    };
    let mut d = Daemon::new(
        Persisted::default(),
        "boot-1".into(),
        Capabilities::all("test"),
    );
    let create = |d: &mut Daemon, cfg| {
        d.handle(
            Request::CreateBlock {
                config: cfg,
                password: None,
            },
            T,
        )
    };
    let r = create(&mut d, week(vec![[0, WEEK_MINUTES]]));
    assert!(!r.ok);
    assert!(r.error.unwrap().contains("leave some time free"));
    // Fine alone, but not together with a block covering the rest.
    assert!(create(&mut d, week(vec![[0, 5000]])).ok);
    assert!(!create(&mut d, week(vec![[5000, WEEK_MINUTES]])).ok);
    assert!(create(&mut d, week(vec![[5000, WEEK_MINUTES - 30]])).ok);
    // Strict blocks may cover the whole week.
    let strict = BlockConfig {
        lock: LockKind::Strict,
        ..week(vec![[0, WEEK_MINUTES]])
    };
    assert!(create(&mut d, strict).ok);
}

#[test]
fn protection_date_follows_the_lock_type() {
    let protect = |lock| BlockConfig {
        lock,
        protect_until: T + 7.0 * DAY,
        ..sites()
    };
    let off = |d: &Daemon| {
        let mut c = d.p.blocks[0].config.clone();
        c.protect_until = 0.0;
        c
    };

    // A date needs a lock.
    let mut d = Daemon::new(
        Persisted::default(),
        "boot-1".into(),
        Capabilities::all("test"),
    );
    let r = d.handle(
        Request::CreateBlock {
            config: protect(LockKind::None),
            password: None,
        },
        T,
    );
    assert!(!r.ok);

    // Random text: protected even while off, until the text is typed.
    let (mut d, id) = daemon_with(protect(LockKind::Random), None);
    assert!(d.status(T).blocks[0].locked && d.status(T).blocks[0].protected);
    let upd = |c: BlockConfig| Request::UpdateBlock {
        id: id.clone(),
        config: c,
        password: None,
    };
    assert!(!d.handle(upd(off(&d)), T).ok);
    assert!(!d.handle(Request::DeleteBlock { id: id.clone() }, T).ok);
    let text = d
        .handle(Request::UnlockChallenge { id: id.clone() }, T)
        .data
        .as_str()
        .unwrap()
        .to_string();
    assert!(
        d.handle(
            Request::Unlock {
                id: id.clone(),
                response: text
            },
            T + 1.0
        )
        .ok
    );
    d.tick(T + 2.0, 1.0, 1.0); // the unlock survives a tick outside any window
    assert!(
        d.handle(upd(off(&d)), T + 3.0).ok,
        "can remove the date after unlocking"
    );

    // Unlocking without changing anything: protection comes back.
    let (mut d, id) = daemon_with(protect(LockKind::Random), None);
    let text = d
        .handle(Request::UnlockChallenge { id: id.clone() }, T)
        .data
        .as_str()
        .unwrap()
        .to_string();
    d.handle(
        Request::Unlock {
            id: id.clone(),
            response: text,
        },
        T,
    );
    assert!(!d.status(T + 60.0).blocks[0].locked);
    d.tick(T + 16.0 * 60.0, 1.0, 1.0);
    assert!(d.status(T + 16.0 * 60.0).blocks[0].locked);

    // Password.
    let (password, wrong) = test_password();
    let (mut d, id) = daemon_with(protect(LockKind::Password), Some(&password));
    assert!(
        !d.handle(
            Request::Unlock {
                id: id.clone(),
                response: wrong
            },
            T
        )
        .ok
    );
    assert!(
        d.handle(
            Request::Unlock {
                id: id.clone(),
                response: password
            },
            T
        )
        .ok
    );
    assert!(!d.status(T + 1.0).blocks[0].locked);

    // Strict: no way out until the date.
    let (mut d, id) = daemon_with(protect(LockKind::Strict), None);
    let r = d.handle(Request::UnlockChallenge { id: id.clone() }, T);
    assert!(!r.ok && r.error.unwrap().contains("protected until"));
    assert!(d.status(T + 7.0 * DAY - 1.0).blocks[0].locked);
    assert!(!d.status(T + 7.0 * DAY + 1.0).blocks[0].locked);

    // Until restart: lifts after a reboot.
    let (d, _) = daemon_with(protect(LockKind::Restart), None);
    assert!(d.status(T).blocks[0].locked);
    let json = serde_json::to_string(&d.p).unwrap();
    let d2 = Daemon::new(
        serde_json::from_str(&json).unwrap(),
        "boot-2".into(),
        Capabilities::all("test"),
    );
    assert!(!d2.status(T).blocks[0].locked);
}

#[test]
fn settings_follow_the_lock_type() {
    let on = Settings {
        block_doh: true,
        https_filter: true,
    };
    let off = Settings {
        block_doh: false,
        https_filter: false,
    };
    let set =
        |d: &mut Daemon, s: Settings, t: f64| d.handle(Request::SetSettings { settings: s }, t).ok;

    // No lock: protections can be turned off while blocking.
    let (mut d, id) = daemon_with(sites(), None);
    set(&mut d, on, T);
    d.handle(Request::StartBlock { id, minutes: 30 }, T);
    assert!(set(&mut d, off, T + 1.0));

    // Random text: locked until unlocked, then free.
    let (mut d, id) = daemon_with(
        BlockConfig {
            lock: LockKind::Random,
            random_length: 8,
            ..sites()
        },
        None,
    );
    set(&mut d, on, T);
    d.handle(
        Request::StartBlock {
            id: id.clone(),
            minutes: 30,
        },
        T,
    );
    assert!(!set(&mut d, off, T + 1.0));
    assert!(
        set(&mut d, on, T + 1.0),
        "turning things on is always allowed"
    );
    let text = d
        .handle(Request::UnlockChallenge { id: id.clone() }, T + 2.0)
        .data
        .as_str()
        .unwrap()
        .to_string();
    assert!(d.handle(Request::Unlock { id, response: text }, T + 3.0).ok);
    assert!(set(&mut d, off, T + 4.0));

    // Strict: locked until the block is over.
    let (mut d, id) = daemon_with(
        BlockConfig {
            lock: LockKind::Strict,
            ..sites()
        },
        None,
    );
    set(&mut d, on, T);
    d.handle(Request::StartBlock { id, minutes: 30 }, T);
    assert!(!set(&mut d, off, T + 60.0));
    d.tick(T + 1801.0, 1.0, 1.0);
    assert!(set(&mut d, off, T + 1801.0));
}

/// A schedule window from one hour before `T` to one hour after.
fn window_around_t() -> Vec<[u32; 2]> {
    let m = deepwork_core::model::minute_of_week(T) as u32;
    assert!(m >= 60 && m + 60 <= deepwork_core::model::WEEK_MINUTES);
    vec![[m - 60, m + 60]]
}

#[test]
fn locked_schedule_can_only_change_when_off() {
    let cfg = BlockConfig {
        schedule: window_around_t(),
        schedule_enabled: true,
        lock: LockKind::Strict,
        ..sites()
    };
    let (mut d, id) = daemon_with(cfg, None);
    d.tick(T, 1.0, 1.0);
    let mut off = d.p.blocks[0].config.clone();
    off.schedule_enabled = false;
    let upd = |off: &BlockConfig| Request::UpdateBlock {
        id: id.clone(),
        config: off.clone(),
        password: None,
    };
    // during the window: no turning off, stopping or deleting
    assert!(!d.handle(upd(&off), T).ok);
    assert!(!d.handle(Request::StopBlock { id: id.clone() }, T).ok);
    assert!(!d.handle(Request::DeleteBlock { id: id.clone() }, T).ok);
    let mut shorter = d.p.blocks[0].config.clone();
    shorter.schedule[0][1] -= 30;
    assert!(!d.handle(upd(&shorter), T).ok);
    // after the window: anything goes
    let after = T + 3601.0;
    d.tick(after, 3601.0, 3601.0);
    assert!(d.handle(upd(&off), after).ok);
    assert!(!d.p.blocks[0].config.schedule_enabled);
}

#[test]
fn clock_jump_does_not_end_a_scheduled_window() {
    let cfg = BlockConfig {
        schedule: window_around_t(),
        schedule_enabled: true,
        lock: LockKind::Strict,
        ..sites()
    };
    let (mut d, id) = daemon_with(cfg, None);
    assert!(!d.tick(T, 1.0, 1.0).domains.is_empty());
    // wall clock jumps 3 hours ahead (past the window's end) in one tick
    let jumped = T + 1.0 + 3.0 * 3600.0;
    let plan = d.tick(jumped, 3.0 * 3600.0 + 1.0, 1.0);
    assert!(
        plan.domains.contains("reddit.com"),
        "still blocking after the jump"
    );
    assert!(
        !d.handle(Request::StopBlock { id: id.clone() }, jumped).ok,
        "still locked"
    );
    // it ends after the hour that was left
    assert!(!d.tick(jumped + 3500.0, 1.0, 1.0).domains.is_empty());
    assert!(d.tick(jumped + 3700.0, 1.0, 1.0).domains.is_empty());
}

/// Moving the system to another time zone (any Windows user may) doesn't
/// end a running scheduled block early.
#[test]
fn time_zone_change_does_not_end_a_scheduled_window() {
    // A schedule that runs around T in a zone 5 hours east of the
    // system's, so it isn't running in the system's own zone.
    use deepwork_core::model::{fixed_zone, utc_offset};
    let east = fixed_zone(utc_offset(&system_zone(), T) + 5 * 3600);
    let m = deepwork_core::model::minute_of_week_in(T, &east) as u32;
    assert!(m >= 60 && m + 60 <= WEEK_MINUTES);
    let cfg = BlockConfig {
        schedule: vec![[m - 60, m + 60]],
        schedule_enabled: true,
        lock: LockKind::Strict,
        ..sites()
    };
    let (mut d, id) = daemon_with(cfg, None);
    assert!(d.p.blocks[0].sched_window_in(T, &east).is_some());
    assert!(d.p.blocks[0].sched_window(T).is_none());

    // The service last saw the eastern zone; now the system's is back.
    d.zone = Some(east);
    let plan = d.tick(T, 1.0, 1.0);
    assert!(plan.domains.contains("reddit.com"), "still blocking");
    assert!(
        !d.handle(Request::StopBlock { id }, T + 1.0).ok,
        "still locked"
    );
    assert!(d.events.iter().any(|e| e.title.contains("Time zone")));
    // It ends when the window would have ended.
    assert!(!d.tick(T + 3500.0, 1.0, 1.0).domains.is_empty());
    assert!(d.tick(T + 3700.0, 1.0, 1.0).domains.is_empty());
    // No change, nothing happens.
    let events = d.events.len();
    d.tick(T + 3701.0, 1.0, 1.0);
    assert_eq!(d.events.len(), events);
}

/// Websites added to a locked block, which is allowed, go behind the
/// ones it already blocked, so they can't push those out of the hosts
/// file's subdomains or Chromium's 1000-entry blocklist.
#[test]
fn websites_of_locked_blocks_come_first() {
    // A big unlocked block from before.
    let many: Vec<String> = (0..3000).map(|i| format!("a{i:04}.example")).collect();
    let (mut d, big) = daemon_with(
        BlockConfig {
            name: "Imported".into(),
            websites: many.clone(),
            ..Default::default()
        },
        None,
    );
    let r = d.handle(
        Request::CreateBlock {
            config: BlockConfig {
                lock: LockKind::Strict,
                ..sites()
            },
            password: None,
        },
        T,
    );
    let locked = r.data.as_str().unwrap().to_string();
    for id in [&big, &locked] {
        d.handle(
            Request::StartBlock {
                id: id.clone(),
                minutes: 60,
            },
            T,
        );
    }
    let plan = d.tick(T, 1.0, 1.0);
    assert_eq!(plan.priority[0], "reddit.com");
    assert_eq!(plan.priority.len(), plan.domains.len());

    // Add thousands of sites that sort before it to the locked block.
    let mut cfg = d.p.blocks[1].config.clone();
    cfg.websites
        .extend((0..3000).map(|i| format!("a{i:04}.earlier")));
    assert!(
        d.handle(
            Request::UpdateBlock {
                id: locked.clone(),
                config: cfg,
                password: None,
            },
            T + 1.0
        )
        .ok
    );
    let plan = d.tick(T + 2.0, 1.0, 1.0);
    assert_eq!(plan.priority[0], "reddit.com");
    assert!(plan.priority[1].ends_with(".earlier"));
    assert!(plan.priority[3001].ends_with(".example"));
    // Kept through a restart, forgotten once the lock is over.
    let json = serde_json::to_string(&d.p).unwrap();
    let mut d = Daemon::new(
        serde_json::from_str(&json).unwrap(),
        "boot-1".into(),
        Capabilities::all("test"),
    );
    assert_eq!(d.tick(T + 3.0, 1.0, 1.0).priority[0], "reddit.com");
    d.tick(T + 3601.0, 1.0, 1.0);
    assert!(d.p.lock_order.is_empty());
}

/// A block protected until a date is locked while it isn't running too, so
/// websites added then (or right after it was made) still go behind the
/// ones it had once it runs.
#[test]
fn websites_of_protected_blocks_keep_their_place() {
    let (mut d, id) = daemon_with(
        BlockConfig {
            lock: LockKind::Strict,
            protect_until: T + 7.0 * DAY,
            ..sites()
        },
        None,
    );
    let mut cfg = d.p.blocks[0].config.clone();
    cfg.websites
        .extend((0..3000).map(|i| format!("a{i:04}.earlier")));
    let update = Request::UpdateBlock {
        id: id.clone(),
        config: cfg,
        password: None,
    };
    assert!(d.handle(update, T).ok);
    d.tick(T + 1.0, 1.0, 1.0);
    assert!(d.p.lock_order.contains_key("reddit.com"));

    let start = Request::StartBlock { id, minutes: 60 };
    assert!(d.handle(start, T + DAY).ok);
    let plan = d.tick(T + DAY, 1.0, 1.0);
    assert_eq!(plan.priority[0], "reddit.com");
    assert!(plan.priority[1].ends_with(".earlier"));
}

#[test]
fn empty_block_cannot_start() {
    let (mut d, id) = daemon_with(BlockConfig::default(), None);
    assert!(!d.handle(Request::StartBlock { id, minutes: 30 }, T).ok);
}

#[test]
fn random_lock_flow() {
    let (mut d, id) = daemon_with(
        BlockConfig {
            lock: LockKind::Random,
            random_length: 10,
            ..sites()
        },
        None,
    );
    d.handle(
        Request::StartBlock {
            id: id.clone(),
            minutes: 60,
        },
        T,
    );
    d.tick(T, 1.0, 1.0);
    let r = d.handle(Request::StopBlock { id: id.clone() }, T + 5.0);
    assert!(!r.ok);
    assert!(
        !d.handle(Request::DeleteBlock { id: id.clone() }, T + 5.0)
            .ok
    );
    // weakening edit refused, strengthening accepted
    let mut cfg = d.p.blocks[0].config.clone();
    cfg.websites.clear();
    assert!(
        !d.handle(
            Request::UpdateBlock {
                id: id.clone(),
                config: cfg,
                password: None
            },
            T + 5.0
        )
        .ok
    );
    let mut cfg = d.p.blocks[0].config.clone();
    cfg.websites.push("youtube.com".into());
    assert!(
        d.handle(
            Request::UpdateBlock {
                id: id.clone(),
                config: cfg,
                password: None
            },
            T + 5.0
        )
        .ok
    );

    let text = d
        .handle(Request::UnlockChallenge { id: id.clone() }, T + 6.0)
        .data
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(text.len(), 10);
    assert!(
        !d.handle(
            Request::Unlock {
                id: id.clone(),
                response: text[1..].to_string()
            },
            T + 7.0
        )
        .ok
    );
    assert!(
        d.handle(
            Request::Unlock {
                id: id.clone(),
                response: text
            },
            T + 8.0
        )
        .ok
    );
    assert!(d.handle(Request::StopBlock { id: id.clone() }, T + 9.0).ok);
    assert!(d.tick(T + 10.0, 1.0, 1.0).domains.is_empty());
}

#[test]
fn password_lock_flow() {
    let (password, wrong) = test_password();
    let (mut d, id) = daemon_with(
        BlockConfig {
            lock: LockKind::Password,
            ..sites()
        },
        Some(&password),
    );
    d.handle(
        Request::StartBlock {
            id: id.clone(),
            minutes: 60,
        },
        T,
    );
    assert!(
        !d.handle(
            Request::Unlock {
                id: id.clone(),
                response: wrong
            },
            T + 1.0
        )
        .ok
    );
    assert!(
        d.handle(
            Request::Unlock {
                id: id.clone(),
                response: password
            },
            T + 1.0
        )
        .ok
    );
    assert!(!d.status(T + 2.0).blocks[0].locked);
}

#[test]
fn password_lock_requires_password() {
    let mut d = Daemon::new(Persisted::default(), "b".into(), Capabilities::all("test"));
    let r = d.handle(
        Request::CreateBlock {
            config: BlockConfig {
                lock: LockKind::Password,
                ..sites()
            },
            password: None,
        },
        T,
    );
    assert!(!r.ok);
}

#[test]
fn strict_cannot_be_unlocked() {
    let (mut d, id) = daemon_with(
        BlockConfig {
            lock: LockKind::Strict,
            ..sites()
        },
        None,
    );
    d.handle(
        Request::StartBlock {
            id: id.clone(),
            minutes: 60,
        },
        T,
    );
    assert!(
        !d.handle(Request::UnlockChallenge { id: id.clone() }, T + 1.0)
            .ok
    );
    assert!(
        !d.handle(
            Request::Unlock {
                id: id.clone(),
                response: String::new()
            },
            T + 1.0
        )
        .ok
    );
    assert!(d.handle(Request::StopBlock { id }, T + 3601.0).ok);
}

#[test]
fn restart_lock_survives_until_new_boot() {
    let (mut d, id) = daemon_with(
        BlockConfig {
            lock: LockKind::Restart,
            ..sites()
        },
        None,
    );
    d.handle(
        Request::StartBlock {
            id: id.clone(),
            minutes: 60,
        },
        T,
    );
    assert!(!d.handle(Request::StopBlock { id: id.clone() }, T + 1.0).ok);
    // simulate reboot: reload persisted state with a new boot id
    let json = serde_json::to_string(&d.p).unwrap();
    let mut d2 = Daemon::new(
        serde_json::from_str(&json).unwrap(),
        "boot-2".into(),
        Capabilities::all("test"),
    );
    d2.tick(T + 100.0, 1.0, 1.0);
    assert!(d2.handle(Request::StopBlock { id }, T + 101.0).ok);
}

#[test]
fn allowance_breaks() {
    let (mut d, id) = daemon_with(
        BlockConfig {
            allowance_minutes: 10,
            lock: LockKind::Strict,
            ..sites()
        },
        None,
    );
    assert!(
        !d.handle(
            Request::TakeBreak {
                id: id.clone(),
                minutes: 5
            },
            T
        )
        .ok,
        "not running"
    );
    d.handle(
        Request::StartBlock {
            id: id.clone(),
            minutes: 120,
        },
        T,
    );
    assert!(
        d.handle(
            Request::TakeBreak {
                id: id.clone(),
                minutes: 15
            },
            T + 1.0
        )
        .ok
    );
    assert!(d.tick(T + 2.0, 1.0, 1.0).domains.is_empty(), "paused");
    assert!(
        !d.tick(T + 1.0 + 601.0, 1.0, 1.0).domains.is_empty(),
        "allowance used up"
    );
    assert!(
        !d.handle(
            Request::TakeBreak {
                id: id.clone(),
                minutes: 1
            },
            T + 700.0
        )
        .ok
    );
}

#[test]
fn end_break_refunds() {
    let (mut d, id) = daemon_with(
        BlockConfig {
            allowance_minutes: 10,
            ..sites()
        },
        None,
    );
    d.handle(
        Request::StartBlock {
            id: id.clone(),
            minutes: 120,
        },
        T,
    );
    d.handle(
        Request::TakeBreak {
            id: id.clone(),
            minutes: 10,
        },
        T,
    );
    d.handle(Request::EndBreak { id: id.clone() }, T + 60.0);
    assert!((d.p.blocks[0].allowance_left(T + 60.0) - 540.0).abs() < 1e-6);
}

#[test]
fn clock_jump_preserves_remaining_time() {
    let (mut d, id) = daemon_with(sites(), None);
    d.handle(Request::StartBlock { id, minutes: 60 }, T);
    d.tick(T + 1.0, 1.0, 1.0);
    // wall clock jumps two hours ahead within one tick
    let jumped = T + 2.0 + 7200.0;
    let plan = d.tick(jumped, 7201.0, 1.0);
    assert!(plan.domains.contains("reddit.com"));
    assert!((d.p.blocks[0].rt.session_until - (T + 3600.0 + 7200.0)).abs() < 1.0);
}

#[test]
fn kills_are_counted() {
    let mut d = Daemon::new(Persisted::default(), "b".into(), Capabilities::all("test"));
    d.record_kills(
        T,
        vec![
            ("steam".into(), "Games".into()),
            ("steam".into(), "Games".into()),
        ],
    );
    let day = &d.p.stats[&today_key(T)];
    assert_eq!(day.blocked_apps, 2);
    assert_eq!(day.apps["steam"], 2);
    let ev: Vec<Event> =
        serde_json::from_value(d.handle(Request::Events { since: 1 }, T).data).unwrap();
    assert_eq!(ev.len(), 1);
}

#[test]
fn unsupported_features_are_refused() {
    let caps = Capabilities {
        os: "Plan 9".into(),
        websites: true,
        ..Default::default()
    };
    let mut d = Daemon::new(Persisted::default(), "b".into(), caps);
    let create = |d: &mut Daemon, cfg| {
        d.handle(
            Request::CreateBlock {
                config: cfg,
                password: None,
            },
            T,
        )
    };
    let r = create(
        &mut d,
        BlockConfig {
            lock: LockKind::Hardcore,
            ..sites()
        },
    );
    assert_eq!(
        r.error.as_deref(),
        Some("The “Hardcore” lock isn't available on Plan 9 yet")
    );
    assert!(
        !create(
            &mut d,
            BlockConfig {
                lock: LockKind::Restart,
                ..sites()
            }
        )
        .ok
    );
    assert!(
        !create(
            &mut d,
            BlockConfig {
                apps: vec!["steam".into()],
                ..sites()
            }
        )
        .ok
    );
    assert!(
        create(
            &mut d,
            BlockConfig {
                lock: LockKind::Strict,
                ..sites()
            }
        )
        .ok
    );
    assert!(!d.handle(Request::Freeze { minutes: 5 }, T).ok);
    assert_eq!(d.status(T).capabilities.os, "Plan 9");
}

#[test]
fn freeze_limits() {
    let mut d = Daemon::new(Persisted::default(), "b".into(), Capabilities::all("test"));
    assert!(!d.handle(Request::Freeze { minutes: 0 }, T).ok);
    assert!(!d.handle(Request::Freeze { minutes: 13 * 60 }, T).ok);
    assert!(d.handle(Request::Freeze { minutes: 5 }, T).ok);
    assert!(d.tick(T + 1.0, 1.0, 1.0).frozen);
    assert!(!d.tick(T + 301.0, 1.0, 1.0).frozen);
}

#[test]
fn stopping_scheduled_block_skips_window() {
    let cfg = BlockConfig {
        schedule: vec![[0, deepwork_core::model::WEEK_MINUTES]],
        schedule_enabled: true,
        ..sites()
    };
    let (mut d, id) = daemon_with(cfg, None);
    assert!(!d.tick(T, 1.0, 1.0).domains.is_empty());
    assert!(d.handle(Request::StopBlock { id }, T).ok);
    assert!(d.tick(T + 1.0, 1.0, 1.0).domains.is_empty());
    assert!(!d.tick(T + DAY + 1.0, 1.0, 1.0).domains.is_empty());
}

/// A request right after a time zone change, before the next tick, sees
/// the window that was running too: it can't delete or turn off the block.
#[test]
fn time_zone_change_is_noticed_by_requests() {
    use deepwork_core::model::{fixed_zone, utc_offset};
    let east = fixed_zone(utc_offset(&system_zone(), T) + 5 * 3600);
    let m = deepwork_core::model::minute_of_week_in(T, &east) as u32;
    assert!(m >= 60 && m + 60 <= WEEK_MINUTES);
    let cfg = BlockConfig {
        schedule: vec![[m - 60, m + 60]],
        schedule_enabled: true,
        lock: LockKind::Strict,
        ..sites()
    };
    let (mut d, id) = daemon_with(cfg, None);
    d.zone = Some(east);
    let mut off = d.p.blocks[0].config.clone();
    off.schedule_enabled = false;
    let r = d.handle(
        Request::UpdateBlock {
            id: id.clone(),
            config: off,
            password: None,
        },
        T,
    );
    assert!(!r.ok, "the schedule can't be turned off");
    assert!(!d.handle(Request::DeleteBlock { id }, T).ok, "nor deleted");
    assert!(d.tick(T + 1.0, 1.0, 1.0).domains.contains("reddit.com"));
}

fn pomodoro_block(cfg: BlockConfig) -> BlockConfig {
    BlockConfig {
        break_every: 25,
        break_length: 5,
        lock: LockKind::Strict,
        ..cfg
    }
}

/// Fewer or shorter breaks are allowed while locked. The new rhythm starts
/// with focus, instead of counting from the window's start, where minute 33
/// of 30 + 5 would be a break.
#[test]
fn a_new_break_rhythm_starts_with_focus() {
    let (mut d, id) = daemon_with(pomodoro_block(sites()), None);
    assert!(
        d.handle(
            Request::StartBlock {
                id: id.clone(),
                minutes: 120
            },
            T
        )
        .ok
    );
    d.tick(T + 1.0, 1.0, 1.0);
    let t = T + 33.0 * 60.0;
    d.tick(t, 1.0, 1.0);
    assert!(d.p.blocks[0].enforcing(t));
    for (every, length) in [(30, 5), (30, 1)] {
        let mut cfg = d.p.blocks[0].config.clone();
        (cfg.break_every, cfg.break_length) = (every, length);
        let r = d.handle(
            Request::UpdateBlock {
                id: id.clone(),
                config: cfg,
                password: None,
            },
            t,
        );
        assert!(r.ok, "{:?}", r.error);
        assert_eq!(
            d.p.blocks[0].pomodoro(t + 60.0),
            Some((false, (every as f64 - 1.0) * 60.0))
        );
        d.tick(t + 60.0, 1.0, 1.0);
        assert!(d.p.blocks[0].enforcing(t + 60.0));
    }
}

/// Adding schedule time before a running window (allowed while locked)
/// moves the window's start, but not the rhythm of its breaks.
#[test]
fn earlier_schedule_time_keeps_the_break_rhythm() {
    let m = deepwork_core::model::minute_of_week(T) as u32;
    assert!(m >= 60 && m + 60 <= WEEK_MINUTES);
    // 33 minutes into the window: focus.
    let cfg = pomodoro_block(BlockConfig {
        schedule: vec![[m - 33, m + 60]],
        schedule_enabled: true,
        ..sites()
    });
    for tick_first in [true, false] {
        let (mut d, id) = daemon_with(cfg.clone(), None);
        if tick_first {
            d.tick(T, 1.0, 1.0);
        }
        assert!(d.p.blocks[0].enforcing(T));
        // 25 more minutes before it: the window has run for 58 minutes, which
        // counted from its new start would be a break.
        let mut earlier = cfg.clone();
        earlier.schedule = vec![[m - 58, m + 60]];
        let r = d.handle(
            Request::UpdateBlock {
                id,
                config: earlier,
                password: None,
            },
            T,
        );
        assert!(r.ok, "{:?}", r.error);
        d.tick(T + 1.0, 1.0, 1.0);
        assert!(d.p.blocks[0].enforcing(T + 1.0), "tick first: {tick_first}");
    }
}

/// Wrong passwords: a few are free, then everyone waits longer and longer
/// between guesses, up to five minutes.
#[test]
fn guessing_passwords_gets_slow() {
    let (password, wrong) = test_password();
    let cfg = BlockConfig {
        lock: LockKind::Password,
        ..sites()
    };
    let (mut d, id) = daemon_with(cfg, Some(&password));
    let start = Request::StartBlock {
        id: id.clone(),
        minutes: 600,
    };
    assert!(d.handle(start, T).ok);
    let unlock = |d: &mut Daemon, response: &str, t: f64| {
        d.handle(
            Request::Unlock {
                id: id.clone(),
                response: response.into(),
            },
            t,
        )
        .error
        .unwrap_or_default()
    };
    for _ in 0..4 {
        assert_eq!(unlock(&mut d, &wrong, T), "Wrong password");
    }
    assert_eq!(
        unlock(&mut d, &wrong, T),
        "Wrong password. Try again in 5 seconds."
    );
    assert_eq!(
        unlock(&mut d, &password, T + 4.0),
        "Too many wrong passwords. Try again in 1 second.",
        "not even the right one"
    );
    assert_eq!(
        unlock(&mut d, &wrong, T + 5.0),
        "Wrong password. Try again in 10 seconds."
    );
    // Many guesses later, the wait stops growing.
    d.guesses.insert(id.clone(), (40, 0.0));
    assert_eq!(
        unlock(&mut d, &wrong, T + 15.0),
        "Wrong password. Try again in 5 minutes."
    );
    // After the wait the right password works, and the count starts over.
    assert_eq!(unlock(&mut d, &password, T + 315.0), "");
    assert!(d.guesses.is_empty());
}
