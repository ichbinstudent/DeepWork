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
mod tests;
