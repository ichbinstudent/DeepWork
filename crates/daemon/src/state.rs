//! Daemon state machine: request handling and per-tick bookkeeping.
//!
//! No I/O happens here; `tick` returns a [`Plan`] that the enforcer applies.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};

use deepwork_core::format_time;
use deepwork_core::model::{
    Block, BlockConfig, DAY, HARDCORE_BREAK, LockKind, MAX_HARDCORE_SECONDS, Settings, TimeZone,
    WEEK_MINUTES, hash_password, random_text, schedule_minutes, settings_weakening, system_zone,
    today_key, validate_config, verify_password, weakening_reasons, zones_differ,
};
use deepwork_core::protocol::{
    BlockStatus, Capabilities, DayStats, Event, HardcoreStatus, NetStatus, Request, Response,
    Stats, Status,
};
use serde::{Deserialize, Serialize};

const MAX_SESSION_MINUTES: u32 = 60 * 24 * 30;
const MAX_FREEZE_MINUTES: u32 = 60 * 12;
const MAX_EVENTS: usize = 200;
/// More blocks than anyone needs; keeps the state file bounded.
const MAX_BLOCKS: usize = 500;
/// How long an unlock lasts for a block that isn't running (protected only).
const UNLOCK_GRACE: f64 = 15.0 * 60.0;

fn check_protection(cfg: &BlockConfig, now: f64) -> R<()> {
    if cfg.protect_until > now && cfg.lock == LockKind::None {
        return Err("Choose a lock type to protect the settings until a date".into());
    }
    Ok(())
}

/// Version of the state file's format. Bump it only for changes older
/// releases can't read; every release must keep loading all earlier
/// formats (tested with the files in `tests/data`).
pub const STATE_FORMAT: u32 = 1;

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Persisted {
    /// [`STATE_FORMAT`] of the release that wrote it (0: written before
    /// formats were numbered, same as 1).
    pub format: u32,
    pub blocks: Vec<Block>,
    pub frozen_until: f64,
    pub stats: Stats,
    pub settings: Settings,
    /// Start of the current stretch of hardcore mode: administrator rights
    /// kept away without a break of [`HARDCORE_BREAK`] or more (0: none).
    pub hardcore_since: f64,
    /// When administrator rights were last kept away.
    pub hardcore_last: f64,
    /// Websites of locked blocks, numbered in the order they were first
    /// locked (see [`Plan::priority`]).
    pub lock_order: BTreeMap<String, u64>,
    pub next_lock_order: u64,
}

/// What the enforcer should do right now.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Plan {
    pub domains: BTreeSet<String>,
    /// `domains`, most important first: websites of locked blocks in the
    /// order they were locked, then the rest. Where only some fit (subdomains
    /// in the hosts file, Chromium's 1000-entry blocklist) the first ones
    /// win, so adding websites to a locked block, which is allowed, can't
    /// push out ones it already blocked.
    pub priority: Vec<String>,
    /// (rule, block name)
    pub apps: Vec<(String, String)>,
    pub frozen: bool,
    /// Block encrypted DNS servers (only while websites are blocked).
    pub block_doh: bool,
    /// Send web traffic through the HTTPS filter (only while websites are blocked).
    pub https_filter: bool,
    /// Refuse traffic through VPN tunnels (a hardcore block is blocking).
    pub block_tunnels: bool,
    /// Keep administrator rights away until this time (0 = not now).
    pub hardcore_until: f64,
}

pub struct Daemon {
    pub p: Persisted,
    pub boot_id: String,
    pub dirty: bool,
    challenges: HashMap<String, String>,
    events: VecDeque<Event>,
    next_seq: u64,
    was_enforcing: HashSet<String>,
    was_frozen: bool,
    was_hardcore: bool,
    /// The time zone of the last tick; schedules follow the system's.
    zone: Option<TimeZone>,
    /// Reported by the enforcer after each tick.
    pub net: NetStatus,
    pub hardcore: HardcoreStatus,
    /// What this OS supports; requests for anything else are refused.
    pub caps: Capabilities,
}

type R<T> = Result<T, String>;

impl Daemon {
    pub fn new(mut p: Persisted, boot_id: String, caps: Capabilities) -> Self {
        p.format = STATE_FORMAT;
        Self {
            p,
            boot_id,
            dirty: false,
            challenges: HashMap::new(),
            events: VecDeque::new(),
            next_seq: 1,
            was_enforcing: HashSet::new(),
            was_frozen: false,
            was_hardcore: false,
            zone: None,
            net: NetStatus::default(),
            hardcore: HardcoreStatus::default(),
            caps,
        }
    }

    pub fn push_event(&mut self, now: f64, kind: &str, title: String, body: String) {
        self.events.push_back(Event {
            seq: self.next_seq,
            ts: now,
            kind: kind.into(),
            title,
            body,
        });
        self.next_seq += 1;
        while self.events.len() > MAX_EVENTS {
            self.events.pop_front();
        }
    }

    fn day(&mut self, now: f64) -> &mut DayStats {
        self.p.stats.entry(today_key(now)).or_default()
    }

    fn block_mut(&mut self, id: &str) -> R<&mut Block> {
        self.p
            .blocks
            .iter_mut()
            .find(|b| b.id == id)
            .ok_or_else(|| "No such block".to_string())
    }

    // ------------------------------------------------------------------ tick

    /// Advance bookkeeping. `wall_dt`/`mono_dt` are the seconds elapsed since
    /// the last tick according to the wall clock and the monotonic clock.
    pub fn tick(&mut self, now: f64, wall_dt: f64, mono_dt: f64) -> Plan {
        // Clock tamper protection: if the wall clock jumped, shift every
        // timer so the remaining durations stay the same.
        let skew = wall_dt - mono_dt;
        if skew.abs() > 30.0 {
            let shift = |t: &mut f64| {
                if *t > now - skew {
                    *t += skew;
                }
            };
            let prev = now - wall_dt;
            for b in &mut self.p.blocks {
                // Schedules follow the wall clock, so a jump forward could
                // skip the rest of a scheduled window. Keep it running for
                // the time it had left by turning it into a session.
                let window = if skew > 0.0 {
                    b.sched_window(prev)
                } else {
                    None
                };
                shift(&mut b.rt.session_until);
                shift(&mut b.rt.session_start);
                shift(&mut b.rt.pause_until);
                shift(&mut b.rt.unlocked_until);
                shift(&mut b.config.protect_until);
                if let Some((start, end)) = window {
                    let real_now = prev + mono_dt;
                    let remaining = end - real_now;
                    if remaining > 0.0 {
                        if !b.session_active(now) {
                            b.rt.session_start = now - (real_now - start);
                        }
                        b.rt.session_until = b.rt.session_until.max(now + remaining);
                    }
                }
            }
            shift(&mut self.p.frozen_until);
            // How long hardcore mode has been on stays the same.
            for t in [&mut self.p.hardcore_since, &mut self.p.hardcore_last] {
                if *t != 0.0 {
                    *t += skew;
                }
            }
            self.dirty = true;
            self.push_event(
                now,
                "clock",
                "Clock change detected".into(),
                "Timers were adjusted so the clock change doesn't end any blocks early.".into(),
            );
        }
        let zone = system_zone();
        if let Some(old) = self.zone.replace(zone.clone())
            && zones_differ(&old, &zone, now)
        {
            self.zone_changed(&old, now);
        }

        let boot = self.boot_id.clone();
        let mut plan = Plan::default();
        let mut enforcing_now = HashSet::new();
        let mut transitions = Vec::new();
        let mut hardcore_wanted: f64 = 0.0;
        let mut locked_sites = BTreeSet::new();
        for b in &mut self.p.blocks {
            if b.in_window(now) {
                if b.rt.lock_boot_id.is_empty() {
                    b.rt.lock_boot_id = boot.clone();
                    self.dirty = true;
                }
            } else {
                // An unlock of a protected block outside its window runs on
                // its own timer, so only clear it once it has expired.
                let stale_unlock = b.rt.unlocked_until != 0.0 && b.rt.unlocked_until <= now;
                if !b.rt.lock_boot_id.is_empty() || b.rt.session_until != 0.0 || stale_unlock {
                    b.rt.lock_boot_id.clear();
                    b.rt.session_until = 0.0;
                    b.rt.session_start = 0.0;
                    if stale_unlock {
                        b.rt.unlocked_until = 0.0;
                    }
                    self.dirty = true;
                }
            }
            if b.rt.pause_until != 0.0 && b.rt.pause_until <= now {
                b.rt.pause_until = 0.0;
                self.dirty = true;
            }
            let cutoff = today_key(now - 8.0 * DAY);
            b.rt.allowance_used.retain(|k, _| *k > cutoff);

            if let Some(until) = b.hardcore_until(now) {
                hardcore_wanted = hardcore_wanted.max(until);
            }
            let locked = b.in_window(now) && b.locked(now, &boot);
            let enforcing = b.enforcing(now);
            let sites = if locked || enforcing {
                b.config.effective_websites()
            } else {
                BTreeSet::new()
            };
            if locked {
                for site in &sites {
                    if !self.p.lock_order.contains_key(site) {
                        self.p
                            .lock_order
                            .insert(site.clone(), self.p.next_lock_order);
                        self.p.next_lock_order += 1;
                        self.dirty = true;
                    }
                }
                locked_sites.extend(sites.iter().cloned());
            }
            if enforcing {
                if b.config.lock == LockKind::Hardcore {
                    plan.block_tunnels = true;
                }
                enforcing_now.insert(b.id.clone());
                plan.domains.extend(sites);
                plan.apps.extend(
                    b.config
                        .effective_apps()
                        .into_iter()
                        .map(|a| (a, b.config.name.clone())),
                );
                if !self.was_enforcing.contains(&b.id) {
                    transitions.push((true, b.config.name.clone()));
                }
            } else if self.was_enforcing.contains(&b.id) {
                transitions.push((false, b.config.name.clone()));
            }
        }
        for (started, name) in transitions {
            if started {
                self.push_event(
                    now,
                    "block_started",
                    format!("{name} is on"),
                    "Time to focus.".into(),
                );
            } else {
                self.push_event(
                    now,
                    "block_ended",
                    format!("{name} is off"),
                    "Distractions are unblocked.".into(),
                );
            }
        }
        let focusing = !enforcing_now.is_empty();
        self.was_enforcing = enforcing_now;

        let before = self.p.lock_order.len();
        self.p
            .lock_order
            .retain(|site, _| locked_sites.contains(site));
        if self.p.lock_order.len() != before {
            self.dirty = true;
        }
        if self.p.lock_order.is_empty() {
            self.p.next_lock_order = 0;
        }
        plan.priority = plan.domains.iter().cloned().collect();
        // Stable: the rest stays in alphabetical order.
        plan.priority
            .sort_by_key(|site| self.p.lock_order.get(site).copied().unwrap_or(u64::MAX));
        plan.hardcore_until = self.hardcore_cap(now, hardcore_wanted);

        plan.frozen = self.p.frozen_until > now;
        // Hardcore blocks always get the network protections.
        let websites = !plan.domains.is_empty();
        plan.block_doh = (self.p.settings.block_doh || plan.block_tunnels) && websites;
        plan.https_filter = (self.p.settings.https_filter || plan.block_tunnels) && websites;
        if self.was_frozen && !plan.frozen {
            self.push_event(
                now,
                "thawed",
                "Freeze is over".into(),
                "Your computer is unlocked again.".into(),
            );
        }
        self.was_frozen = plan.frozen;

        if focusing || plan.frozen {
            self.day(now).focus_seconds += mono_dt.clamp(0.0, 5.0);
        }
        if self.p.stats.len() > 400 {
            let cutoff = today_key(now - 400.0 * DAY);
            self.p.stats.retain(|k, _| *k > cutoff);
        }
        plan
    }

    pub fn record_kills(&mut self, now: f64, kills: Vec<(String, String)>) {
        for (app, block) in kills {
            let day = self.day(now);
            day.blocked_apps += 1;
            *day.apps.entry(app.clone()).or_default() += 1;
            self.push_event(
                now,
                "app_blocked",
                format!("{app} is blocked"),
                format!("Blocked by “{block}”"),
            );
            self.dirty = true;
        }
    }

    /// Until when administrator rights stay away (0: give them back now),
    /// given that hardcore blocks want them away until `wanted`.
    ///
    /// All hardcore blocks together keep them away for at most
    /// [`MAX_HARDCORE_SECONDS`] in one stretch; a gap shorter than
    /// [`HARDCORE_BREAK`] doesn't end a stretch, and after a full one the
    /// rights come back for that long, however the blocks were chained.
    fn hardcore_cap(&mut self, now: f64, wanted: f64) -> f64 {
        let recent = self.hardcore_stretch(now).is_some();
        if wanted <= now {
            if self.p.hardcore_since != 0.0 && !recent {
                self.p.hardcore_since = 0.0;
                self.p.hardcore_last = 0.0;
                self.dirty = true;
            }
            self.was_hardcore = false;
            return 0.0;
        }
        if !recent {
            self.p.hardcore_since = now;
            self.dirty = true;
        }
        let end = self.p.hardcore_since + MAX_HARDCORE_SECONDS;
        if now >= end {
            // The rights came back at `end`, and stay back for a while.
            self.p.hardcore_last = self.p.hardcore_last.max(end);
            if self.was_hardcore {
                self.was_hardcore = false;
                self.push_event(
                    now,
                    "hardcore_break",
                    "Administrator rights are back for an hour".into(),
                    format!(
                        "Hardcore blocks kept them away for 7 days in a row. Blocking goes on; \
                         hardcore mode resumes after {}.",
                        format_time(self.p.hardcore_last + HARDCORE_BREAK)
                    ),
                );
            }
            return 0.0;
        }
        self.was_hardcore = true;
        self.p.hardcore_last = now;
        wanted.min(end)
    }

    /// Start of the running stretch of hardcore mode, or of one that ended
    /// less than [`HARDCORE_BREAK`] ago (a new hardcore block continues it).
    fn hardcore_stretch(&self, now: f64) -> Option<f64> {
        (self.p.hardcore_since != 0.0 && now - self.p.hardcore_last < HARDCORE_BREAK)
            .then_some(self.p.hardcore_since)
    }

    /// Refuse to keep administrator rights away from `start` to `end` for
    /// longer than [`MAX_HARDCORE_SECONDS`] (`start`: the beginning of the
    /// block's window, or of the stretch of hardcore mode it continues).
    fn check_hardcore_length(&self, name: &str, start: f64, end: f64, now: f64) -> R<()> {
        let start = start.min(self.hardcore_stretch(now).unwrap_or(start));
        let limit = start + MAX_HARDCORE_SECONDS;
        if end <= limit {
            return Ok(());
        }
        if limit <= now {
            return Err(format!(
                "Hardcore blocks have kept administrator rights away for 7 days in a row, so \
                 they are back for an hour. “{name}” can be hardcore again after {}.",
                format_time(self.p.hardcore_last.max(limit) + HARDCORE_BREAK)
            ));
        }
        Err(format!(
            "“{name}” is hardcore, so it can run for at most 7 days in one go (together with \
             hardcore blocks before it that ended less than an hour earlier), here until {}. \
             Administrator rights must come back now and then, e.g. for updates.",
            format_time(limit)
        ))
    }

    /// The system's time zone changed, which Windows lets every user do.
    /// Scheduled windows that were running in the old zone keep running, as
    /// sessions, for the time they had left, so the change can't end a block
    /// early. Later windows follow the new zone.
    fn zone_changed(&mut self, old: &TimeZone, now: f64) {
        let mut kept = false;
        for b in &mut self.p.blocks {
            if let Some((start, end)) = b.sched_window_in(now, old)
                && end > now
            {
                if !b.session_active(now) {
                    b.rt.session_start = start;
                }
                b.rt.session_until = b.rt.session_until.max(end);
                kept = true;
            }
        }
        if kept {
            self.dirty = true;
            self.push_event(
                now,
                "clock",
                "Time zone change detected".into(),
                "Scheduled blocks that were on keep running for the time they had left.".into(),
            );
        }
    }

    // ------------------------------------------------------------------ status

    pub fn block_status(&self, b: &Block, now: f64) -> BlockStatus {
        let window = b.window(now);
        let locked = b.locked(now, &self.boot_id);
        let protected = b.protection_active(now, &self.boot_id);
        BlockStatus {
            id: b.id.clone(),
            config: b.config.clone(),
            has_password: !b.password_hash.is_empty(),
            active: window.is_some(),
            enforcing: b.enforcing(now),
            locked,
            on_break: b.on_break(now),
            paused: b.paused(now),
            session_until: if b.session_active(now) {
                b.rt.session_until
            } else {
                0.0
            },
            window_start: window.map(|w| w.0),
            window_end: window.map(|w| w.1),
            pause_until: if b.paused(now) { b.rt.pause_until } else { 0.0 },
            pomodoro: b.pomodoro(now),
            allowance_left: b.allowance_left(now),
            lock_reason: locked.then_some(b.config.lock),
            protected,
        }
    }

    pub fn status(&self, now: f64) -> Status {
        Status {
            version: deepwork_core::VERSION.into(),
            now,
            frozen_until: if self.p.frozen_until > now {
                self.p.frozen_until
            } else {
                0.0
            },
            blocks: self
                .p
                .blocks
                .iter()
                .map(|b| self.block_status(b, now))
                .collect(),
            settings: self.p.settings,
            net: self.net.clone(),
            hardcore: self.hardcore.clone(),
            capabilities: self.caps.clone(),
        }
    }

    // ------------------------------------------------------------------ requests

    pub fn handle(&mut self, req: Request, now: f64) -> Response {
        let mutating = !matches!(
            req,
            Request::Ping | Request::Status | Request::Events { .. } | Request::Stats { .. }
        );
        let res = self.dispatch(req, now);
        if mutating && res.ok {
            self.dirty = true;
        }
        res
    }

    fn dispatch(&mut self, req: Request, now: f64) -> Response {
        fn wrap<T: Serialize>(r: R<T>) -> Response {
            match r {
                Ok(v) => Response::ok(v),
                Err(e) => Response::err(e),
            }
        }
        match req {
            Request::Ping => Response::ok(deepwork_core::VERSION),
            Request::Status => Response::ok(self.status(now)),
            Request::Events { since } => Response::ok(
                self.events
                    .iter()
                    .filter(|e| e.seq > since)
                    .cloned()
                    .collect::<Vec<_>>(),
            ),
            Request::Stats { days } => {
                let cutoff = today_key(now - days.min(400) as f64 * DAY);
                Response::ok(
                    self.p
                        .stats
                        .iter()
                        .filter(|(k, _)| **k > cutoff)
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect::<Stats>(),
                )
            }
            Request::CreateBlock { config, password } => wrap(self.create(config, password, now)),
            Request::UpdateBlock {
                id,
                config,
                password,
            } => wrap(self.update(&id, config, password, now)),
            Request::DeleteBlock { id } => wrap(self.delete(&id, now)),
            Request::StartBlock { id, minutes } => wrap(self.start(&id, minutes, now)),
            Request::StopBlock { id } => wrap(self.stop(&id, now)),
            Request::UnlockChallenge { id } => wrap(self.challenge(&id, now)),
            Request::Unlock { id, response } => wrap(self.unlock(&id, &response, now)),
            Request::TakeBreak { id, minutes } => wrap(self.take_break(&id, minutes, now)),
            Request::EndBreak { id } => wrap(self.end_break(&id, now)),
            Request::Freeze { minutes } => wrap(self.freeze(minutes, now)),
            Request::SetSettings { settings } => wrap(self.set_settings(settings, now)),
        }
    }

    /// Refuse what this OS can't enforce. A block keeps a lock it already
    /// had (e.g. state copied from another machine).
    fn check_supported(&self, cfg: &BlockConfig, old_lock: Option<LockKind>) -> R<()> {
        if !self.caps.supports_lock(cfg.lock) && old_lock != Some(cfg.lock) {
            return Err(format!(
                "The “{}” lock isn't available on {} yet",
                cfg.lock.label(),
                self.caps.os
            ));
        }
        if !cfg.apps.is_empty() && !self.caps.apps {
            return Err(format!(
                "Blocking applications isn't available on {} yet",
                self.caps.os
            ));
        }
        if !cfg.websites.is_empty() && !self.caps.websites {
            return Err(format!(
                "Blocking websites isn't available on {} yet",
                self.caps.os
            ));
        }
        Ok(())
    }

    /// Hardcore blocks take administrator rights away while they run, so
    /// their schedules (together) must leave time free every week.
    fn check_hardcore(&self, id: Option<&str>, cfg: &BlockConfig) -> R<()> {
        if cfg.lock != LockKind::Hardcore || !cfg.schedule_enabled {
            return Ok(());
        }
        let mut minutes = schedule_minutes(&cfg.schedule);
        for b in &self.p.blocks {
            if Some(b.id.as_str()) != id
                && b.config.lock == LockKind::Hardcore
                && b.config.schedule_enabled
            {
                minutes.extend(schedule_minutes(&b.config.schedule));
            }
        }
        if minutes.len() >= WEEK_MINUTES as usize {
            return Err(
                "Hardcore schedules must leave some time free every week, so \
                        administrator rights come back now and then (e.g. for updates)"
                    .into(),
            );
        }
        Ok(())
    }

    fn create(&mut self, config: BlockConfig, password: Option<String>, now: f64) -> R<String> {
        if self.p.blocks.len() >= MAX_BLOCKS {
            return Err(format!("There can be at most {MAX_BLOCKS} blocks"));
        }
        let config = validate_config(config).map_err(|e| e.0)?;
        check_protection(&config, now)?;
        self.check_supported(&config, None)?;
        self.check_hardcore(None, &config)?;
        let mut b = Block::new(config);
        if let Some((start, end)) = b.hardcore_until(now).and_then(|_| b.window(now)) {
            self.check_hardcore_length(&b.config.name, start, end, now)?;
        }
        if b.config.protect_until > now {
            b.rt.protect_boot_id = self.boot_id.clone();
        }
        match password.filter(|p| !p.is_empty()) {
            Some(p) => b.password_hash = hash_password(&p),
            None if b.config.lock == LockKind::Password => {
                return Err("A password lock needs a password".into());
            }
            None => {}
        }
        let id = b.id.clone();
        self.p.blocks.push(b);
        Ok(id)
    }

    fn update(
        &mut self,
        id: &str,
        config: BlockConfig,
        password: Option<String>,
        now: f64,
    ) -> R<()> {
        let boot = self.boot_id.clone();
        let new = validate_config(config).map_err(|e| e.0)?;
        check_protection(&new, now)?;
        let old_lock = self
            .p
            .blocks
            .iter()
            .find(|b| b.id == id)
            .map(|b| b.config.lock);
        self.check_supported(&new, old_lock)?;
        self.check_hardcore(Some(id), &new)?;
        // Turning a running block hardcore, or making its window longer,
        // must stay within the hardcore limit too.
        if new.lock == LockKind::Hardcore
            && let Some(old) = self.p.blocks.iter().find(|b| b.id == id)
        {
            let mut probe = old.clone();
            probe.config = new.clone();
            if let Some((start, end)) = probe.window(now)
                && end > old.hardcore_until(now).unwrap_or(0.0)
            {
                self.check_hardcore_length(&new.name, start, end, now)?;
            }
        }
        let b = self.block_mut(id)?;
        let password = password.filter(|p| !p.is_empty());
        if b.locked(now, &boot) {
            let reasons = weakening_reasons(&b.config, &new, password.is_some());
            if !reasons.is_empty() {
                return Err(format!(
                    "“{}” is locked, so you can't {}. You can still add websites, apps or schedule time.",
                    b.config.name,
                    join_human(&reasons)
                ));
            }
        }
        if new.lock == LockKind::Password && password.is_none() && b.password_hash.is_empty() {
            return Err("A password lock needs a password".into());
        }
        if let Some(p) = password {
            b.password_hash = hash_password(&p);
        }
        if new.lock != LockKind::Password {
            b.password_hash.clear();
        }
        // (Re)starting or extending a protection ties a restart lock to this boot.
        if new.protect_until > now && new.protect_until != b.config.protect_until {
            b.rt.protect_boot_id = boot;
        }
        b.config = new;
        Ok(())
    }

    fn delete(&mut self, id: &str, now: f64) -> R<()> {
        let boot = self.boot_id.clone();
        let b = self.block_mut(id)?;
        if b.locked(now, &boot) {
            return Err(format!(
                "“{}” is locked and can't be deleted right now",
                b.config.name
            ));
        }
        self.p.blocks.retain(|b| b.id != id);
        self.challenges.remove(id);
        Ok(())
    }

    fn start(&mut self, id: &str, minutes: u32, now: f64) -> R<()> {
        if minutes == 0 || minutes > MAX_SESSION_MINUTES {
            return Err("Pick a duration between 1 minute and 30 days".into());
        }
        let boot = self.boot_id.clone();
        let b = self
            .p
            .blocks
            .iter()
            .find(|b| b.id == id)
            .ok_or("No such block")?;
        if b.config.lock == LockKind::Hardcore {
            let start = b.window(now).map_or(now, |w| w.0);
            let end = now + minutes as f64 * 60.0;
            self.check_hardcore_length(&b.config.name, start, end, now)?;
        }
        let b = self.block_mut(id)?;
        if b.config.blocks_nothing() {
            return Err(format!(
                "“{}” has nothing to block yet. Add a website or an app first.",
                b.config.name
            ));
        }
        if !b.session_active(now) {
            b.rt.session_start = now;
        }
        b.rt.session_until = b.rt.session_until.max(now + minutes as f64 * 60.0);
        b.rt.unlocked_until = 0.0;
        b.rt.skip_until = 0.0;
        if b.rt.lock_boot_id.is_empty() {
            b.rt.lock_boot_id = boot;
        }
        Ok(())
    }

    fn stop(&mut self, id: &str, now: f64) -> R<()> {
        let boot = self.boot_id.clone();
        let b = self.block_mut(id)?;
        if b.locked(now, &boot) {
            return Err(format!("“{}” is locked. Unlock it first.", b.config.name));
        }
        if let Some((_, end)) = b.sched_window(now) {
            b.rt.skip_until = end.min(now + DAY);
        }
        b.rt.session_until = 0.0;
        b.rt.session_start = 0.0;
        b.rt.unlocked_until = 0.0;
        b.rt.pause_until = 0.0;
        Ok(())
    }

    fn challenge(&mut self, id: &str, now: f64) -> R<String> {
        let boot = self.boot_id.clone();
        let b = self.block_mut(id)?;
        if !b.locked(now, &boot) {
            return Err("This block isn't locked".into());
        }
        let protected_only = !b.in_window(now);
        let until = deepwork_core::format_time(b.config.protect_until);
        let text = match b.config.lock {
            LockKind::Random => random_text(b.config.random_length as usize),
            LockKind::Password => String::new(),
            LockKind::Restart => {
                return Err("This block unlocks after you restart your computer".into());
            }
            LockKind::Strict | LockKind::Hardcore if protected_only => {
                return Err(format!(
                    "This block is strict. Its settings stay protected until {until}."
                ));
            }
            LockKind::Strict | LockKind::Hardcore => {
                return Err("This block is strict. It ends when the time is up.".into());
            }
            // Only possible for protections set before a lock was required.
            LockKind::None => {
                return Err(format!("The settings are protected until {until}."));
            }
        };
        self.challenges.insert(id.to_string(), text.clone());
        Ok(text)
    }

    fn unlock(&mut self, id: &str, response: &str, now: f64) -> R<()> {
        let boot = self.boot_id.clone();
        let challenge = self.challenges.get(id).cloned();
        let b = self.block_mut(id)?;
        if !b.locked(now, &boot) {
            return Ok(());
        }
        let ok = match b.config.lock {
            LockKind::Random => challenge.is_some_and(|c| !c.is_empty() && c == response),
            LockKind::Password => verify_password(response, &b.password_hash),
            _ => return Err("This block can't be unlocked".into()),
        };
        if !ok {
            return Err(match b.config.lock {
                LockKind::Password => "Wrong password".into(),
                _ => "The text doesn't match. Type it exactly as shown.".into(),
            });
        }
        // Unlocked for the rest of the running window, and at least a few
        // minutes so a protected block that isn't running can be edited.
        let window_end = b.window(now).map(|w| w.1).unwrap_or(now);
        b.rt.unlocked_until = window_end.max(now + UNLOCK_GRACE);
        self.challenges.remove(id);
        Ok(())
    }

    fn take_break(&mut self, id: &str, minutes: u32, now: f64) -> R<f64> {
        let b = self.block_mut(id)?;
        if b.config.allowance_minutes == 0 {
            return Err("This block has no break allowance".into());
        }
        if !b.in_window(now) {
            return Err("This block isn't running".into());
        }
        if b.paused(now) {
            return Err("You're already on a break".into());
        }
        let left = b.allowance_left(now);
        if left < 1.0 {
            return Err("You've used today's allowance".into());
        }
        let grant = (minutes.max(1) as f64 * 60.0).min(left);
        b.rt.pause_until = now + grant;
        *b.rt.allowance_used.entry(today_key(now)).or_default() += grant;
        Ok(grant)
    }

    fn end_break(&mut self, id: &str, now: f64) -> R<()> {
        let b = self.block_mut(id)?;
        if b.paused(now) {
            let refund = b.rt.pause_until - now;
            let used = b.rt.allowance_used.entry(today_key(now)).or_default();
            *used = (*used - refund).max(0.0);
            b.rt.pause_until = 0.0;
        }
        Ok(())
    }

    fn set_settings(&mut self, settings: Settings, now: f64) -> R<()> {
        let boot = self.boot_id.clone();
        if let Some(b) = self.p.blocks.iter().find(|b| b.locked(now, &boot)) {
            let reasons = settings_weakening(&self.p.settings, &settings);
            if !reasons.is_empty() {
                return Err(format!(
                    "“{}” is locked, so you can't {} right now.",
                    b.config.name,
                    join_human(&reasons)
                ));
            }
        }
        if self.p.frozen_until > now && !settings_weakening(&self.p.settings, &settings).is_empty()
        {
            return Err("Settings can't be relaxed during a freeze".into());
        }
        self.p.settings = settings;
        Ok(())
    }

    fn freeze(&mut self, minutes: u32, now: f64) -> R<()> {
        if !self.caps.freeze {
            return Err(format!("Freeze isn't available on {} yet", self.caps.os));
        }
        if minutes == 0 || minutes > MAX_FREEZE_MINUTES {
            return Err("Freeze for between 1 minute and 12 hours".into());
        }
        self.p.frozen_until = self.p.frozen_until.max(now + minutes as f64 * 60.0);
        self.push_event(
            now,
            "frozen",
            "Frozen".into(),
            "Your computer will stay locked until the timer ends.".into(),
        );
        Ok(())
    }
}

fn join_human(items: &[&str]) -> String {
    match items {
        [] => String::new(),
        [a] => a.to_string(),
        [rest @ .., last] => format!("{} or {}", rest.join(", "), last),
    }
}

#[cfg(test)]
mod tests {
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
        let set = |d: &mut Daemon, s: Settings, t: f64| {
            d.handle(Request::SetSettings { settings: s }, t).ok
        };

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
}
