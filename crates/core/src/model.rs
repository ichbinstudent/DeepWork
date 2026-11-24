//! Data model and pure blocking logic.
//!
//! Everything here is side-effect free and takes `now` (unix seconds)
//! explicitly so it can be unit-tested. The daemon owns the only mutable copy
//! of the state; the GUI only ever sees [`crate::protocol::BlockStatus`].

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

pub const WEEK_MINUTES: u32 = 7 * 24 * 60;
pub const DAY: f64 = 86_400.0;

/// Process names that must never be killed, no matter what a user enters.
pub const PROTECTED_PROCESSES: &[&str] = &[
    "systemd",
    "init",
    "dbus-daemon",
    "dbus-broker",
    "gnome-shell",
    "gnome-session-binary",
    "kwin_wayland",
    "kwin_x11",
    "plasmashell",
    "xorg",
    "xwayland",
    "gdm",
    "sddm",
    "lightdm",
    "sshd",
    "login",
    "sudo",
    "su",
    "pkexec",
    "polkitd",
    "bash",
    "zsh",
    "fish",
    "sh",
    "dash",
    "pipewire",
    "wireplumber",
    "pulseaudio",
    "networkmanager",
    "deepwork",
    "deepwork-daemon",
    "mutter",
    "loginctl",
    "systemctl",
    "kworker",
    "xdg-desktop-portal",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationError(pub String);

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ValidationError {}

fn invalid<T>(msg: impl Into<String>) -> Result<T, ValidationError> {
    Err(ValidationError(msg.into()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LockKind {
    /// Can be stopped at any time.
    #[default]
    None,
    /// Type a string of random characters to unlock.
    Random,
    /// Somebody else's password unlocks it.
    Password,
    /// Unlocks only after the computer restarts.
    Restart,
    /// Cannot be unlocked until the block ends.
    Strict,
    /// Strict, and while the block runs nobody gets administrator rights
    /// (sudo, su, pkexec, polkit), VPN tunnels are refused and the network
    /// protections are always on.
    Hardcore,
}

impl LockKind {
    pub const ALL: [LockKind; 6] = [
        LockKind::None,
        LockKind::Random,
        LockKind::Password,
        LockKind::Restart,
        LockKind::Strict,
        LockKind::Hardcore,
    ];

    pub fn label(self) -> &'static str {
        match self {
            LockKind::None => "No lock",
            LockKind::Random => "Random text",
            LockKind::Password => "Password",
            LockKind::Restart => "Until restart",
            LockKind::Strict => "Strict",
            LockKind::Hardcore => "Hardcore",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            LockKind::None => "Stop the block whenever you like",
            LockKind::Random => "Type a string of random characters to unlock",
            LockKind::Password => "Unlock with a password somebody else keeps",
            LockKind::Restart => "Unlock only after restarting the computer",
            LockKind::Strict => "No way out until the time is up",
            LockKind::Hardcore => "Strict, and nobody gets admin rights until the time is up",
        }
    }

    /// Can only be waited out.
    pub fn is_strict(self) -> bool {
        matches!(self, LockKind::Strict | LockKind::Hardcore)
    }
}

/// Filter list every hardcore block includes, so tunnels can't get around it.
pub const HARDCORE_LIST: &str = "vpn";
/// Longest time hardcore blocks may keep administrator rights away in one
/// go, all hardcore blocks together.
pub const MAX_HARDCORE_SECONDS: f64 = 7.0 * DAY;
/// How long administrator rights must be back before hardcore blocks may
/// take them away again: shorter gaps between hardcore blocks count as one
/// stretch for [`MAX_HARDCORE_SECONDS`], and after that long a stretch the
/// rights come back for at least this long.
pub const HARDCORE_BREAK: f64 = 3600.0;

/// User-editable settings of a block.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct BlockConfig {
    pub name: String,
    pub color: String,
    pub websites: Vec<String>,
    pub apps: Vec<String>,
    /// Ids of built-in filter lists (see [`crate::lists`]).
    pub lists: Vec<String>,
    /// `[start, end)` ranges in minutes of the week, Monday 00:00 = 0.
    pub schedule: Vec<[u32; 2]>,
    pub schedule_enabled: bool,
    pub lock: LockKind,
    pub random_length: u32,
    /// Minutes per day the block may be paused.
    pub allowance_minutes: u32,
    /// Pomodoro: focus minutes before a break (0 = off).
    pub break_every: u32,
    /// Pomodoro: break minutes.
    pub break_length: u32,
    /// Settings cannot be weakened before this timestamp.
    pub protect_until: f64,
}

impl Default for BlockConfig {
    fn default() -> Self {
        Self {
            name: "New block".into(),
            color: "blue".into(),
            websites: vec![],
            apps: vec![],
            lists: vec![],
            schedule: vec![],
            schedule_enabled: false,
            lock: LockKind::None,
            random_length: 32,
            allowance_minutes: 0,
            break_every: 0,
            break_length: 0,
            protect_until: 0.0,
        }
    }
}

impl BlockConfig {
    /// Own websites plus those of every included filter list.
    pub fn effective_websites(&self) -> BTreeSet<String> {
        let mut out: BTreeSet<String> = self.websites.iter().cloned().collect();
        for l in self.effective_lists() {
            out.extend(l.websites.iter().map(|w| w.to_string()));
        }
        out
    }

    /// Own app rules plus those of every included filter list (deduplicated,
    /// ignoring case).
    pub fn effective_apps(&self) -> Vec<String> {
        let mut seen = BTreeSet::new();
        let lists = self.effective_lists().into_iter();
        self.apps
            .iter()
            .cloned()
            .chain(lists.flat_map(|l| l.apps.iter().map(|a| a.to_string())))
            .filter(|a| seen.insert(a.to_lowercase()))
            .collect()
    }

    /// Included filter lists, plus the VPN list for hardcore blocks.
    pub fn effective_lists(&self) -> Vec<&'static crate::lists::FilterList> {
        let mut ids: Vec<&str> = self.lists.iter().map(String::as_str).collect();
        if self.lock == LockKind::Hardcore && !ids.contains(&HARDCORE_LIST) {
            ids.push(HARDCORE_LIST);
        }
        ids.into_iter().filter_map(crate::lists::get).collect()
    }

    pub fn blocks_nothing(&self) -> bool {
        self.effective_websites().is_empty() && self.effective_apps().is_empty()
    }
}

/// Global switches that make website blocking harder to get around.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// While websites are blocked, stop apps from using encrypted DNS
    /// (DNS over HTTPS / TLS) servers that would bypass `/etc/hosts`.
    pub block_doh: bool,
    /// While websites are blocked, route user web traffic through a local
    /// filter that checks the site name (TLS SNI / HTTP Host).
    pub https_filter: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            block_doh: true,
            https_filter: false,
        }
    }
}

/// Changes that make blocking easier to bypass (refused while locked).
pub fn settings_weakening(old: &Settings, new: &Settings) -> Vec<&'static str> {
    let mut r = vec![];
    if old.block_doh && !new.block_doh {
        r.push("turn off encrypted DNS blocking");
    }
    if old.https_filter && !new.https_filter {
        r.push("turn off HTTPS filtering");
    }
    r
}

/// Upper limit for a block's own websites (imports can be large).
pub const MAX_WEBSITES: usize = 20_000;
pub const MAX_APPS: usize = 2_000;

pub const COLORS: &[&str] = &[
    "blue", "teal", "green", "yellow", "orange", "red", "pink", "purple",
];

/// State that only the daemon writes.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct BlockRuntime {
    pub session_start: f64,
    pub session_until: f64,
    /// A scheduled window was stopped early; ignore the schedule until then.
    pub skip_until: f64,
    /// Unlocked for the rest of the current window.
    pub unlocked_until: f64,
    /// Allowance break.
    pub pause_until: f64,
    /// Where the pomodoro rhythm of the current window started: its start,
    /// or when the rhythm last changed. Moving the window's start (more
    /// schedule time, a time zone change) doesn't move the rhythm, so it
    /// can't jump into a break. Ignored when it's before the window.
    pub cycle_start: f64,
    /// Boot in which the current window was locked (restart lock).
    pub lock_boot_id: String,
    /// Boot in which the "protect until" date was set (restart lock).
    pub protect_boot_id: String,
    /// date (YYYY-MM-DD) -> seconds of allowance used.
    pub allowance_used: BTreeMap<String, f64>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Block {
    pub id: String,
    pub config: BlockConfig,
    pub password_hash: String,
    pub rt: BlockRuntime,
}

// --------------------------------------------------------------------------- validation

pub fn normalize_domain(raw: &str) -> Result<String, ValidationError> {
    let mut s = raw.trim().to_lowercase();
    if let Some(i) = s.find("://") {
        s = s[i + 3..].to_string();
    }
    for sep in ['/', '?', '#'] {
        if let Some(i) = s.find(sep) {
            s.truncate(i);
        }
    }
    if let Some(i) = s.rfind('@') {
        s = s[i + 1..].to_string();
    }
    if let Some(i) = s.find(':') {
        s.truncate(i);
    }
    let mut s = s.trim_matches('.').to_string();
    while let Some(rest) = s.strip_prefix("*.") {
        s = rest.to_string();
    }
    if s.starts_with("www.") && s.matches('.').count() >= 2 {
        s = s[4..].to_string();
    }
    let labels: Vec<&str> = s.split('.').collect();
    let label_ok = |l: &&str| {
        !l.is_empty()
            && l.len() <= 63
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    };
    let tld_ok = labels
        .last()
        .is_some_and(|t| t.len() >= 2 && !t.chars().all(|c| c.is_ascii_digit()));
    if s.len() > 253 || labels.len() < 2 || !labels.iter().all(label_ok) || !tld_ok {
        return invalid(format!("“{}” is not a valid website", raw.trim()));
    }
    Ok(s)
}

pub fn is_protected_process(name: &str) -> bool {
    let n = name.to_lowercase();
    PROTECTED_PROCESSES.contains(&n.as_str())
}

/// Prefix for rules that match a substring of a process's full command line,
/// e.g. `cmd:net.minecraft.client.main.Main` for a Java game.
pub const CMD_PREFIX: &str = "cmd:";

pub fn normalize_app(raw: &str) -> Result<String, ValidationError> {
    let s = raw.trim();
    if let Some(needle) = s.strip_prefix(CMD_PREFIX) {
        let needle = needle.trim();
        // Short substrings would match far too much.
        if needle.chars().count() < 6 || needle.contains('\0') || needle.contains('\n') {
            return invalid(format!(
                "“{s}”: a command-line rule needs at least 6 characters after “cmd:”"
            ));
        }
        return Ok(format!("{CMD_PREFIX}{needle}"));
    }
    if s.is_empty() || s.len() > 4096 || s.contains('\0') || s.contains('\n') {
        return invalid(format!("“{s}” is not a valid application"));
    }
    if !s.starts_with('/') && s.contains('/') {
        return invalid(format!("“{s}” is not a valid application name"));
    }
    let base = s.rsplit('/').next().unwrap_or(s);
    if is_protected_process(base) {
        return invalid(format!("“{s}” is a system process and cannot be blocked"));
    }
    Ok(s.to_string())
}

pub fn normalize_schedule(ranges: &[[u32; 2]]) -> Vec<[u32; 2]> {
    let mut clean: Vec<[u32; 2]> = ranges
        .iter()
        .map(|r| [r[0].min(WEEK_MINUTES), r[1].min(WEEK_MINUTES)])
        .filter(|r| r[1] > r[0])
        .collect();
    clean.sort();
    let mut merged: Vec<[u32; 2]> = Vec::new();
    for r in clean {
        match merged.last_mut() {
            Some(last) if r[0] <= last[1] => last[1] = last[1].max(r[1]),
            _ => merged.push(r),
        }
    }
    merged
}

pub fn schedule_minutes(ranges: &[[u32; 2]]) -> BTreeSet<u32> {
    ranges.iter().flat_map(|r| r[0]..r[1]).collect()
}

/// Validate and normalize a config coming from a client.
pub fn validate_config(mut c: BlockConfig) -> Result<BlockConfig, ValidationError> {
    c.name = c.name.trim().chars().take(80).collect();
    if c.name.is_empty() {
        c.name = "Untitled block".into();
    }
    if !COLORS.contains(&c.color.as_str()) {
        c.color = "blue".into();
    }
    let mut seen = BTreeSet::new();
    c.websites = c
        .websites
        .iter()
        .filter(|w| !w.trim().is_empty())
        .map(|w| normalize_domain(w))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|w| seen.insert(w.clone()))
        .collect();
    let mut seen = BTreeSet::new();
    c.apps = c
        .apps
        .iter()
        .filter(|a| !a.trim().is_empty())
        .map(|a| normalize_app(a))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|a| seen.insert(a.to_lowercase()))
        .collect();
    if c.websites.len() > MAX_WEBSITES {
        return invalid(format!(
            "A block can hold at most {MAX_WEBSITES} websites (this one has {})",
            c.websites.len()
        ));
    }
    if c.apps.len() > MAX_APPS {
        return invalid(format!(
            "A block can hold at most {MAX_APPS} apps (this one has {})",
            c.apps.len()
        ));
    }
    let mut seen = BTreeSet::new();
    for id in &c.lists {
        if crate::lists::get(id).is_none() {
            return invalid(format!("Unknown filter list “{id}”"));
        }
    }
    c.lists.retain(|id| seen.insert(id.clone()));
    c.schedule = normalize_schedule(&c.schedule);
    c.random_length = c.random_length.clamp(8, 500);
    c.allowance_minutes = c.allowance_minutes.min(24 * 60);
    c.break_every = c.break_every.min(24 * 60);
    c.break_length = c.break_length.min(24 * 60);
    if !c.protect_until.is_finite() || c.protect_until < 0.0 {
        c.protect_until = 0.0;
    }
    Ok(c)
}

/// Explain why replacing `old` with `new` would make a block less strict.
///
/// Adding websites/apps/schedule time, lengthening the random text or
/// extending the protection date are all allowed while a block is locked;
/// nothing else is. `new` must already be validated.
pub fn weakening_reasons(
    old: &BlockConfig,
    new: &BlockConfig,
    password_change: bool,
) -> Vec<&'static str> {
    let mut reasons = Vec::new();
    // Compare what actually gets blocked, so moving a site from the block's
    // own list into a filter list (or the other way round) is fine.
    if !old
        .effective_websites()
        .is_subset(&new.effective_websites())
    {
        reasons.push("remove websites");
    }
    let new_apps: BTreeSet<_> = new
        .effective_apps()
        .iter()
        .map(|a| a.to_lowercase())
        .collect();
    if old
        .effective_apps()
        .iter()
        .any(|a| !new_apps.contains(&a.to_lowercase()))
    {
        reasons.push("remove applications");
    }
    if old.schedule_enabled {
        if !new.schedule_enabled {
            reasons.push("turn off the schedule");
        } else if !schedule_minutes(&old.schedule).is_subset(&schedule_minutes(&new.schedule)) {
            reasons.push("shrink the schedule");
        }
    }
    if new.lock != old.lock {
        reasons.push("change the lock type");
    }
    if new.random_length < old.random_length {
        reasons.push("shorten the unlock text");
    }
    if new.allowance_minutes > old.allowance_minutes {
        reasons.push("increase the allowance");
    }
    let old_breaks = old.break_every > 0 && old.break_length > 0;
    let new_breaks = new.break_every > 0 && new.break_length > 0;
    if new_breaks
        && (!old_breaks || new.break_every < old.break_every || new.break_length > old.break_length)
    {
        reasons.push("add or lengthen breaks");
    }
    if new.protect_until < old.protect_until {
        reasons.push("shorten the protection period");
    }
    if password_change && old.lock == LockKind::Password {
        reasons.push("change the password");
    }
    reasons
}

// --------------------------------------------------------------------------- time

pub use jiff::tz::TimeZone;

/// The system's time zone, as it is now.
pub fn system_zone() -> TimeZone {
    TimeZone::system()
}

thread_local! {
    static PINNED_ZONE: RefCell<Option<TimeZone>> = const { RefCell::new(None) };
}

/// Make this thread use `zone` for schedules and dates from now on. The
/// system's zone can change between two looks at it, so the service looks
/// once and decides everything about a request in that zone.
pub fn pin_zone(zone: TimeZone) {
    PINNED_ZONE.set(Some(zone));
}

/// The time zone schedules follow: the one pinned on this thread, otherwise
/// the system's.
fn current_zone() -> TimeZone {
    PINNED_ZONE
        .with_borrow(Clone::clone)
        .unwrap_or_else(system_zone)
}

/// How many seconds `zone` is ahead of UTC at `ts`.
pub fn utc_offset(zone: &TimeZone, ts: f64) -> i32 {
    jiff::Timestamp::from_second(ts.floor() as i64).map_or(0, |t| zone.to_offset(t).seconds())
}

/// A time zone that is always `seconds` ahead of UTC (within ±25 hours).
pub fn fixed_zone(seconds: i32) -> TimeZone {
    jiff::tz::Offset::from_seconds(seconds).map_or(TimeZone::UTC, TimeZone::fixed)
}

/// Whether the clocks of two time zones show different times at `ts`
/// (daylight saving time doesn't make a zone differ from itself).
pub fn zones_differ(a: &TimeZone, b: &TimeZone, ts: f64) -> bool {
    utc_offset(a, ts) != utc_offset(b, ts)
}

/// A Unix timestamp in the time zone schedules follow.
pub fn local_time(ts: f64) -> Option<jiff::ZonedDateTime> {
    local_time_in(ts, &current_zone())
}

fn local_time_in(ts: f64, zone: &TimeZone) -> Option<jiff::ZonedDateTime> {
    let t = jiff::Timestamp::from_second(ts.floor() as i64).ok()?;
    Some(t.to_zoned_datetime(zone.clone()))
}

pub fn minute_of_week(ts: f64) -> f64 {
    minute_of_week_in(ts, &current_zone())
}

pub fn minute_of_week_in(ts: f64, zone: &TimeZone) -> f64 {
    let d = local_time_in(ts, zone).unwrap_or_else(jiff::ZonedDateTime::now);
    d.weekday().to_monday_zero_offset() as f64 * 1440.0
        + d.hour() as f64 * 60.0
        + d.minute() as f64
        + (d.second() as f64 + ts.fract()) / 60.0
}

pub fn today_key(ts: f64) -> String {
    local_time(ts)
        .unwrap_or_else(jiff::ZonedDateTime::now)
        .strftime("%Y-%m-%d")
        .to_string()
}

/// `(start, end)` timestamps of the scheduled window containing `now`.
///
/// Ranges that touch across the Sunday→Monday wrap count as one window. A
/// schedule covering the whole week reports a rolling one-week horizon.
pub fn schedule_window(ranges: &[[u32; 2]], now: f64) -> Option<(f64, f64)> {
    schedule_window_in(ranges, now, &current_zone())
}

/// [`schedule_window`] in the given time zone.
pub fn schedule_window_in(ranges: &[[u32; 2]], now: f64, zone: &TimeZone) -> Option<(f64, f64)> {
    if ranges.is_empty() {
        return None;
    }
    let mow = minute_of_week_in(now, zone);
    let mut unrolled: Vec<[f64; 2]> = (0..3)
        .flat_map(|k| {
            ranges.iter().map(move |r| {
                let off = (k * WEEK_MINUTES) as f64;
                [r[0] as f64 + off, r[1] as f64 + off]
            })
        })
        .collect();
    unrolled.sort_by(|a, b| a[0].total_cmp(&b[0]));
    let mut merged: Vec<[f64; 2]> = Vec::new();
    for r in unrolled {
        match merged.last_mut() {
            Some(last) if r[0] <= last[1] => last[1] = last[1].max(r[1]),
            _ => merged.push(r),
        }
    }
    let pos = mow + WEEK_MINUTES as f64;
    let w = merged.iter().find(|r| r[0] <= pos && pos < r[1])?;
    if w[1] - w[0] >= (3 * WEEK_MINUTES) as f64 {
        return Some((now - DAY, now + 7.0 * DAY));
    }
    Some((now - (pos - w[0]) * 60.0, now + (w[1] - pos) * 60.0))
}

// --------------------------------------------------------------------------- secrets

const PBKDF2_ROUNDS: u32 = 200_000;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

fn derive(password: &str, salt: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, PBKDF2_ROUNDS, &mut out);
    out
}

pub fn hash_password(password: &str) -> String {
    let salt: [u8; 16] = rand::thread_rng().r#gen();
    format!("pbkdf2${}${}", hex(&salt), hex(&derive(password, &salt)))
}

pub fn verify_password(password: &str, stored: &str) -> bool {
    let mut parts = stored.split('$');
    let (Some("pbkdf2"), Some(salt), Some(digest), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    let (Some(salt), Some(digest)) = (unhex(salt), unhex(digest)) else {
        return false;
    };
    let got = derive(password, &salt);
    // constant-time comparison
    got.len() == digest.len()
        && got
            .iter()
            .zip(&digest)
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0
}

pub const RANDOM_ALPHABET: &[u8] = b"abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";

pub fn random_text(len: usize) -> String {
    let mut rng = rand::thread_rng();
    (0..len)
        .map(|_| RANDOM_ALPHABET[rng.gen_range(0..RANDOM_ALPHABET.len())] as char)
        .collect()
}

// --------------------------------------------------------------------------- block logic

impl Block {
    pub fn new(config: BlockConfig) -> Self {
        let id: String = random_text(12).to_lowercase();
        Self {
            id,
            config,
            ..Default::default()
        }
    }

    pub fn session_active(&self, now: f64) -> bool {
        self.rt.session_until > now
    }

    pub fn sched_window(&self, now: f64) -> Option<(f64, f64)> {
        self.sched_window_in(now, &current_zone())
    }

    /// [`Block::sched_window`] as if the system were in another time zone.
    pub fn sched_window_in(&self, now: f64, zone: &TimeZone) -> Option<(f64, f64)> {
        if !self.config.schedule_enabled || self.rt.skip_until > now {
            return None;
        }
        schedule_window_in(&self.config.schedule, now, zone)
    }

    /// The enforcement window `(start, end)` covering `now`, if any.
    pub fn window(&self, now: f64) -> Option<(f64, f64)> {
        let session = self.session_active(now).then_some((
            if self.rt.session_start > 0.0 {
                self.rt.session_start
            } else {
                now
            },
            self.rt.session_until,
        ));
        match (session, self.sched_window(now)) {
            (Some(a), Some(b)) => Some((a.0.min(b.0), a.1.max(b.1))),
            (a, b) => a.or(b),
        }
    }

    pub fn in_window(&self, now: f64) -> bool {
        self.window(now).is_some()
    }

    /// `(on_break, seconds_until_switch)` when pomodoro breaks are configured.
    pub fn pomodoro(&self, now: f64) -> Option<(bool, f64)> {
        let (every, length) = (
            self.config.break_every as f64 * 60.0,
            self.config.break_length as f64 * 60.0,
        );
        if every <= 0.0 || length <= 0.0 {
            return None;
        }
        let (start, _) = self.window(now)?;
        // A rhythm pinned earlier in this window wins over the window's start.
        let start = if (start..=now).contains(&self.rt.cycle_start) {
            self.rt.cycle_start
        } else {
            start
        };
        let pos = (now - start).rem_euclid(every + length);
        Some(if pos < every {
            (false, every - pos)
        } else {
            (true, every + length - pos)
        })
    }

    pub fn paused(&self, now: f64) -> bool {
        self.rt.pause_until > now
    }

    pub fn on_break(&self, now: f64) -> bool {
        self.paused(now) || self.pomodoro(now).is_some_and(|p| p.0)
    }

    pub fn enforcing(&self, now: f64) -> bool {
        self.in_window(now) && !self.on_break(now)
    }

    /// The "protect settings until" date is in force. It follows the lock
    /// type: a restart lock lifts it after a reboot; random text and password
    /// locks can lift it early through [`Block::locked`]'s unlock window.
    pub fn protection_active(&self, now: f64, boot_id: &str) -> bool {
        if self.config.protect_until <= now {
            return false;
        }
        match self.config.lock {
            LockKind::Restart => {
                self.rt.protect_boot_id.is_empty() || self.rt.protect_boot_id == boot_id
            }
            _ => true,
        }
    }

    /// Whether the block may NOT be stopped, deleted or weakened right now:
    /// it is running with a lock, or its settings are protected until a date,
    /// and it hasn't been unlocked.
    pub fn locked(&self, now: f64, boot_id: &str) -> bool {
        let running_locked = self.in_window(now)
            && match self.config.lock {
                LockKind::None => false,
                LockKind::Restart => {
                    self.rt.lock_boot_id.is_empty() || self.rt.lock_boot_id == boot_id
                }
                _ => true,
            };
        (running_locked || self.protection_active(now, boot_id)) && self.rt.unlocked_until <= now
    }

    /// End of the current hardcore window: while it runs, nobody gets
    /// administrator rights. Breaks don't count as an end.
    pub fn hardcore_until(&self, now: f64) -> Option<f64> {
        if self.config.lock != LockKind::Hardcore {
            return None;
        }
        self.window(now).map(|w| w.1)
    }

    pub fn allowance_left(&self, now: f64) -> f64 {
        if self.config.allowance_minutes == 0 {
            return 0.0;
        }
        let used = self
            .rt
            .allowance_used
            .get(&today_key(now))
            .copied()
            .unwrap_or(0.0);
        (self.config.allowance_minutes as f64 * 60.0 - used).max(0.0)
    }
}

#[cfg(test)]
mod tests;
