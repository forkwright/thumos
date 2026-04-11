//! Heorte: calendar, alarm, timer, and stopwatch engine.
//!
//! ἑορτή = "feast day, appointed time" — holds times marked for human attention.
//!
//! This module provides the data model and logic for:
//! - **Calendar events**: time-bounded entries with title and metadata
//! - **Alarms**: recurring or one-shot time-of-day alerts
//! - **Timer**: single countdown from a set duration
//! - **Stopwatch**: count-up with lap recording
//!
//! The calendar is a local cache; authoritative state lives in aletheia.
//! Alarms, timer, and stopwatch are fully local.
//!
//! ## Design decisions
//!
//! - Fixed-size title/label buffers avoid heap allocation for small strings.
//! - `Vec` used for event/alarm lists and stopwatch laps (kernel has an allocator).
//! - No `unwrap()`/`expect()` in any code path.
//! - Tick-based timing: callers pass the current kernel tick count; the engine
//!   computes elapsed time from deltas rather than polling a clock.

// WHY: heorte module created in Phase 07 Wave 7, kinit wiring pending.
#![expect(dead_code, reason = "Heorte created in Phase 07 Wave 7, kinit wiring pending")]

extern crate alloc;
use alloc::vec::Vec;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum title length for calendar events (bytes).
const MAX_TITLE_LEN: usize = 64;

/// Maximum label length for alarms (bytes).
const MAX_LABEL_LEN: usize = 32;

/// Maximum number of stopwatch laps stored. Oldest evicted beyond this.
const MAX_LAPS: usize = 50;

/// Seconds per minute.
const SECS_PER_MIN: u64 = 60;

/// Seconds per hour.
const SECS_PER_HOUR: u64 = 3600;

/// Seconds per day.
const SECS_PER_DAY: u64 = 86400;

// ---------------------------------------------------------------------------
// Calendar event
// ---------------------------------------------------------------------------

/// A calendar event with fixed-size title buffer.
///
/// Events are sorted by `start_epoch` for agenda display. The `id` is
/// locally unique and auto-incremented by [`HeorteManager`].
#[derive(Debug, Clone)]
pub struct CalendarEvent {
    /// Locally unique event identifier, auto-incremented.
    pub id: u32,
    /// Event title stored as raw bytes (UTF-8).
    pub title: [u8; MAX_TITLE_LEN],
    /// Number of valid bytes in `title`.
    pub title_len: u8,
    /// Start time as Unix epoch seconds.
    pub start_epoch: u64,
    /// Duration in minutes (0 for instantaneous events).
    pub duration_min: u16,
    /// Whether this is an all-day event (time portion ignored for display).
    pub all_day: bool,
}

impl CalendarEvent {
    /// Create a new calendar event.
    ///
    /// `title_bytes` is truncated to [`MAX_TITLE_LEN`] if longer.
    #[must_use]
    pub fn new(id: u32, title_bytes: &[u8], start_epoch: u64, duration_min: u16, all_day: bool) -> Self {
        let mut title = [0u8; MAX_TITLE_LEN];
        let len = title_bytes.len().min(MAX_TITLE_LEN);
        title[..len].copy_from_slice(&title_bytes[..len]);
        Self {
            id,
            title,
            title_len: len as u8,
            start_epoch,
            duration_min,
            all_day,
        }
    }

    /// Return the title as a `&str`, or an empty string if not valid UTF-8.
    pub fn title_str(&self) -> &str {
        core::str::from_utf8(&self.title[..self.title_len as usize]).unwrap_or("")
    }

    /// End epoch (start + duration). Returns `start_epoch` if duration is 0.
    pub fn end_epoch(&self) -> u64 {
        self.start_epoch + u64::from(self.duration_min) * SECS_PER_MIN
    }

    /// Whether this event is active (happening now) at the given epoch.
    pub fn is_active(&self, current_epoch: u64) -> bool {
        current_epoch >= self.start_epoch && current_epoch < self.end_epoch()
    }

    /// Extract the day (as days since Unix epoch) for grouping.
    pub fn day_index(&self) -> u32 {
        (self.start_epoch / SECS_PER_DAY) as u32
    }
}

impl core::fmt::Display for CalendarEvent {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.title_str())
    }
}

// ---------------------------------------------------------------------------
// Alarm
// ---------------------------------------------------------------------------

/// Day-of-week bitmask constants for alarm repeat scheduling.
pub mod day_mask {
    /// Sunday (bit 0).
    pub const SUN: u8 = 1 << 0;
    /// Monday (bit 1).
    pub const MON: u8 = 1 << 1;
    /// Tuesday (bit 2).
    pub const TUE: u8 = 1 << 2;
    /// Wednesday (bit 3).
    pub const WED: u8 = 1 << 3;
    /// Thursday (bit 4).
    pub const THU: u8 = 1 << 4;
    /// Friday (bit 5).
    pub const FRI: u8 = 1 << 5;
    /// Saturday (bit 6).
    pub const SAT: u8 = 1 << 6;
    /// All weekdays (Mon-Fri).
    pub const WEEKDAYS: u8 = MON | TUE | WED | THU | FRI;
    /// Every day.
    pub const DAILY: u8 = SUN | MON | TUE | WED | THU | FRI | SAT;
}

/// An alarm set to fire at a specific time of day.
///
/// `repeat_days` is a bitmask where bit 0 = Sunday through bit 6 = Saturday.
/// A value of 0 means the alarm fires once and then auto-disables.
#[derive(Debug, Clone)]
pub struct Alarm {
    /// Locally unique alarm identifier, auto-incremented.
    pub id: u32,
    /// Hour of day (0-23).
    pub hour: u8,
    /// Minute of hour (0-59).
    pub minute: u8,
    /// Alarm label stored as raw bytes (UTF-8).
    pub label: [u8; MAX_LABEL_LEN],
    /// Number of valid bytes in `label`.
    pub label_len: u8,
    /// Whether this alarm is armed.
    pub enabled: bool,
    /// Day-of-week repeat bitmask. 0 = one-shot, auto-disables after firing.
    pub repeat_days: u8,
}

impl Alarm {
    /// Create a new alarm.
    ///
    /// `label_bytes` is truncated to [`MAX_LABEL_LEN`] if longer.
    #[must_use]
    pub fn new(
        id: u32,
        hour: u8,
        minute: u8,
        label_bytes: &[u8],
        enabled: bool,
        repeat_days: u8,
    ) -> Self {
        let mut label = [0u8; MAX_LABEL_LEN];
        let len = label_bytes.len().min(MAX_LABEL_LEN);
        label[..len].copy_from_slice(&label_bytes[..len]);
        Self {
            id,
            hour: hour.min(23),
            minute: minute.min(59),
            label,
            label_len: len as u8,
            enabled,
            repeat_days,
        }
    }

    /// Return the label as a `&str`, or an empty string if not valid UTF-8.
    #[must_use]
    pub fn label_str(&self) -> &str {
        core::str::from_utf8(&self.label[..self.label_len as usize]).unwrap_or("")
    }

    /// Check whether this alarm should fire at the given epoch.
    ///
    /// Returns `true` if the alarm is enabled and the current time-of-day
    /// matches the alarm's hour:minute. If `repeat_days` is non-zero,
    /// also checks whether the current day-of-week is in the bitmask.
    pub fn should_fire(&self, current_epoch: u64) -> bool {
        if !self.enabled {
            return false;
        }

        let day_secs = current_epoch % SECS_PER_DAY;
        let current_hour = (day_secs / SECS_PER_HOUR) as u8;
        let current_minute = ((day_secs % SECS_PER_HOUR) / SECS_PER_MIN) as u8;

        if current_hour != self.hour || current_minute != self.minute {
            return false;
        }

        // If no repeat mask, alarm fires on any day (one-shot).
        if self.repeat_days == 0 {
            return true;
        }

        // Check day-of-week against repeat mask.
        let dow = day_of_week(current_epoch);
        (self.repeat_days & (1 << dow)) != 0
    }

    /// Human-readable repeat description.
    #[must_use]
    pub fn repeat_label(&self) -> &'static str {
        match self.repeat_days {
            0 => "Once",
            d if d == day_mask::DAILY => "Daily",
            d if d == day_mask::WEEKDAYS => "Weekdays",
            _ => "Custom",
        }
    }
}

impl core::fmt::Display for Alarm {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:02}:{:02} {}", self.hour, self.minute, self.label_str())
    }
}

/// Compute day of week from Unix epoch seconds.
///
/// Returns 0 = Sunday, 1 = Monday, ..., 6 = Saturday.
/// Unix epoch (1970-01-01) was a Thursday (day 4).
fn day_of_week(epoch: u64) -> u8 {
    let days = epoch / SECS_PER_DAY;
    ((days + 4) % 7) as u8 // +4 because 1970-01-01 was Thursday
}

// ---------------------------------------------------------------------------
// Timer
// ---------------------------------------------------------------------------

/// Countdown timer.
///
/// Tracks a set duration and computes remaining time based on the kernel
/// tick count (milliseconds). The timer can be started, paused, and reset.
#[derive(Debug, Clone)]
pub struct Timer {
    /// Total duration in seconds.
    pub duration_secs: u32,
    /// Remaining seconds (computed on query, cached for display).
    pub remaining_secs: u32,
    /// Whether the timer is actively counting down.
    pub running: bool,
    /// Kernel tick (ms) when the timer was last started or resumed.
    pub started_tick: u64,
}

impl Timer {
    /// Create a new timer with zero duration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            duration_secs: 0,
            remaining_secs: 0,
            running: false,
            started_tick: 0,
        }
    }

    /// Set the timer duration and reset state.
    pub fn set_duration(&mut self, secs: u32) {
        self.duration_secs = secs;
        self.remaining_secs = secs;
        self.running = false;
        self.started_tick = 0;
    }

    /// Start or resume the countdown from the current tick.
    pub fn start(&mut self, current_tick: u64) {
        if !self.running && self.remaining_secs > 0 {
            self.running = true;
            self.started_tick = current_tick;
        }
    }

    /// Pause the countdown, preserving remaining time.
    pub fn pause(&mut self, current_tick: u64) {
        if self.running {
            self.update(current_tick);
            self.running = false;
        }
    }

    /// Reset the timer to its original duration.
    pub fn reset(&mut self) {
        self.remaining_secs = self.duration_secs;
        self.running = false;
        self.started_tick = 0;
    }

    /// Update remaining seconds from the current tick.
    ///
    /// Called each render cycle (or on query) to recompute remaining time.
    /// Returns `true` if the timer has expired (reached zero).
    pub fn update(&mut self, current_tick: u64) -> bool {
        if !self.running {
            return self.remaining_secs == 0 && self.duration_secs > 0;
        }

        let elapsed_ms = current_tick.saturating_sub(self.started_tick);
        let elapsed_secs = (elapsed_ms / 1000) as u32;

        if elapsed_secs >= self.remaining_secs {
            self.remaining_secs = 0;
            self.running = false;
            return true;
        }

        self.remaining_secs = self.remaining_secs.saturating_sub(elapsed_secs);
        self.started_tick = current_tick;
        false
    }

    /// Whether the timer has expired.
    pub fn expired(&self) -> bool {
        self.duration_secs > 0 && self.remaining_secs == 0 && !self.running
    }

    /// Format remaining time as `MM:SS`.
    pub fn format_remaining(&self) -> [u8; 5] {
        let m = (self.remaining_secs / 60).min(99);
        let s = self.remaining_secs % 60;
        [
            b'0' + (m / 10) as u8,
            b'0' + (m % 10) as u8,
            b':',
            b'0' + (s / 10) as u8,
            b'0' + (s % 10) as u8,
        ]
    }
}

impl core::fmt::Display for Timer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let buf = self.format_remaining();
        let s = core::str::from_utf8(&buf).unwrap_or("??:??");
        write!(f, "{s}")
    }
}

// ---------------------------------------------------------------------------
// Stopwatch
// ---------------------------------------------------------------------------

/// Count-up stopwatch with lap recording.
///
/// Elapsed time is tracked in milliseconds. Laps record cumulative split
/// times; the display shows per-lap deltas. Maximum [`MAX_LAPS`] laps;
/// oldest is evicted when full.
#[derive(Debug, Clone)]
pub struct Stopwatch {
    /// Total elapsed milliseconds (accumulated across start/stop cycles).
    pub elapsed_ms: u64,
    /// Whether the stopwatch is currently running.
    pub running: bool,
    /// Kernel tick (ms) when the stopwatch was last started or resumed.
    pub started_tick: u64,
    /// Cumulative lap split times in milliseconds.
    pub laps: Vec<u64>,
}

impl Stopwatch {
    /// Create a new stopwatch in the stopped state.
    #[must_use]
    pub fn new() -> Self {
        Self {
            elapsed_ms: 0,
            running: false,
            started_tick: 0,
            laps: Vec::new(),
        }
    }

    /// Start or resume the stopwatch.
    pub fn start(&mut self, current_tick: u64) {
        if !self.running {
            self.running = true;
            self.started_tick = current_tick;
        }
    }

    /// Stop the stopwatch, preserving elapsed time.
    pub fn stop(&mut self, current_tick: u64) {
        if self.running {
            self.elapsed_ms += current_tick.saturating_sub(self.started_tick);
            self.running = false;
        }
    }

    /// Reset the stopwatch to zero.
    pub fn reset(&mut self) {
        self.elapsed_ms = 0;
        self.running = false;
        self.started_tick = 0;
        self.laps.clear();
    }

    /// Record a lap at the current tick.
    ///
    /// Stores the cumulative elapsed time as a lap marker. If the lap
    /// list exceeds [`MAX_LAPS`], the oldest lap is removed.
    pub fn lap(&mut self, current_tick: u64) {
        if !self.running {
            return;
        }

        let current_elapsed = self.elapsed_ms + current_tick.saturating_sub(self.started_tick);
        if self.laps.len() >= MAX_LAPS {
            self.laps.remove(0);
        }
        self.laps.push(current_elapsed);
    }

    /// Get the current total elapsed time in milliseconds.
    pub fn current_elapsed(&self, current_tick: u64) -> u64 {
        if self.running {
            self.elapsed_ms + current_tick.saturating_sub(self.started_tick)
        } else {
            self.elapsed_ms
        }
    }

    /// Get per-lap duration (delta between consecutive laps) in milliseconds.
    ///
    /// Returns an iterator of `(lap_number, duration_ms)` pairs, 1-indexed.
    pub fn lap_durations(&self) -> Vec<(usize, u64)> {
        let mut result = Vec::with_capacity(self.laps.len());
        let mut prev = 0u64;
        for (i, &cumulative) in self.laps.iter().enumerate() {
            result.push((i + 1, cumulative.saturating_sub(prev)));
            prev = cumulative;
        }
        result
    }

    /// Format elapsed time as `HH:MM:SS.mmm`.
    ///
    /// Returns a 12-byte buffer. Caller should convert to `&str` via
    /// `core::str::from_utf8`.
    pub fn format_elapsed(&self, current_tick: u64) -> [u8; 12] {
        format_elapsed_ms(self.current_elapsed(current_tick))
    }
}

impl core::fmt::Display for Stopwatch {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let ms = self.elapsed_ms;
        let secs = ms / 1000;
        write!(f, "{:02}:{:02}", secs / 60, secs % 60)
    }
}

/// Format milliseconds as `HH:MM:SS.mmm`.
fn format_elapsed_ms(ms: u64) -> [u8; 12] {
    let total_secs = ms / 1000;
    let millis = (ms % 1000) as u16;
    let hours = (total_secs / 3600).min(99);
    let minutes = (total_secs % 3600) / 60;
    let seconds = total_secs % 60;

    [
        b'0' + (hours / 10) as u8,
        b'0' + (hours % 10) as u8,
        b':',
        b'0' + (minutes / 10) as u8,
        b'0' + (minutes % 10) as u8,
        b':',
        b'0' + (seconds / 10) as u8,
        b'0' + (seconds % 10) as u8,
        b'.',
        b'0' + (millis / 100) as u8,
        b'0' + ((millis / 10) % 10) as u8,
        b'0' + (millis % 10) as u8,
    ]
}

/// Format milliseconds as `MM:SS.mmm` (compact, for lap display).
fn format_lap_ms(ms: u64) -> [u8; 9] {
    let total_secs = ms / 1000;
    let millis = (ms % 1000) as u16;
    let minutes = (total_secs / 60).min(99);
    let seconds = total_secs % 60;

    [
        b'0' + (minutes / 10) as u8,
        b'0' + (minutes % 10) as u8,
        b':',
        b'0' + (seconds / 10) as u8,
        b'0' + (seconds % 10) as u8,
        b'.',
        b'0' + (millis / 100) as u8,
        b'0' + ((millis / 10) % 10) as u8,
        b'0' + (millis % 10) as u8,
    ]
}

// ---------------------------------------------------------------------------
// Heorte manager
// ---------------------------------------------------------------------------

/// Central manager for calendar events, alarms, timer, and stopwatch.
///
/// Owns all heorte state and provides a unified API for the UI screens.
/// Event and alarm IDs are auto-incremented and never reused within a
/// session (persistence across reboots is handled by the storage layer).
pub struct HeorteManager {
    /// Calendar events, sorted by `start_epoch`.
    events: Vec<CalendarEvent>,
    /// Alarm definitions.
    alarms: Vec<Alarm>,
    /// Countdown timer.
    timer: Timer,
    /// Stopwatch.
    stopwatch: Stopwatch,
    /// Next event ID to assign.
    next_event_id: u32,
    /// Next alarm ID to assign.
    next_alarm_id: u32,
}

impl HeorteManager {
    /// Create a new empty heorte manager.
    #[must_use]
    pub fn new() -> Self {
        Self {
            events: Vec::new(),
            alarms: Vec::new(),
            timer: Timer::new(),
            stopwatch: Stopwatch::new(),
            next_event_id: 1,
            next_alarm_id: 1,
        }
    }

    // -- Calendar events --

    /// Add a calendar event. Returns the assigned event ID.
    pub fn add_event(
        &mut self,
        title: &[u8],
        start_epoch: u64,
        duration_min: u16,
        all_day: bool,
    ) -> u32 {
        let id = self.next_event_id;
        self.next_event_id += 1;
        let event = CalendarEvent::new(id, title, start_epoch, duration_min, all_day);
        self.events.push(event);
        self.sort_events();
        id
    }

    /// Remove an event by ID. Returns `true` if found and removed.
    pub fn remove_event(&mut self, id: u32) -> bool {
        let before = self.events.len();
        self.events.retain(|e| e.id != id);
        self.events.len() < before
    }

    /// List all events, sorted by start time.
    pub fn events(&self) -> &[CalendarEvent] {
        &self.events
    }

    /// List events occurring on or after the given epoch, sorted by start time.
    pub fn upcoming_events(&self, from_epoch: u64) -> Vec<&CalendarEvent> {
        self.events
            .iter()
            .filter(|e| e.end_epoch() > from_epoch || e.start_epoch >= from_epoch)
            .collect()
    }

    /// Find an event by ID.
    pub fn find_event(&self, id: u32) -> Option<&CalendarEvent> {
        self.events.iter().find(|e| e.id == id)
    }

    /// Sort events by `start_epoch` (stable sort preserves insertion order for ties).
    fn sort_events(&mut self) {
        self.events.sort_by_key(|e| e.start_epoch);
    }

    // -- Alarms --

    /// Add an alarm. Returns the assigned alarm ID.
    pub fn add_alarm(
        &mut self,
        hour: u8,
        minute: u8,
        label: &[u8],
        enabled: bool,
        repeat_days: u8,
    ) -> u32 {
        let id = self.next_alarm_id;
        self.next_alarm_id += 1;
        let alarm = Alarm::new(id, hour, minute, label, enabled, repeat_days);
        self.alarms.push(alarm);
        id
    }

    /// Remove an alarm by ID. Returns `true` if found and removed.
    pub fn remove_alarm(&mut self, id: u32) -> bool {
        let before = self.alarms.len();
        self.alarms.retain(|a| a.id != id);
        self.alarms.len() < before
    }

    /// Toggle an alarm's enabled state by ID. Returns the new state, or
    /// `None` if the alarm was not found.
    pub fn toggle_alarm(&mut self, id: u32) -> Option<bool> {
        for alarm in &mut self.alarms {
            if alarm.id == id {
                alarm.enabled = !alarm.enabled;
                return Some(alarm.enabled);
            }
        }
        None
    }

    /// List all alarms.
    pub fn alarms(&self) -> &[Alarm] {
        &self.alarms
    }

    /// Check which alarms should fire at the given epoch.
    ///
    /// Returns a list of alarm IDs that match. One-shot alarms (`repeat_days` == 0)
    /// are auto-disabled after firing.
    pub fn check_alarms(&mut self, current_epoch: u64) -> Vec<u32> {
        let mut firing = Vec::new();
        for alarm in &mut self.alarms {
            if alarm.should_fire(current_epoch) {
                firing.push(alarm.id);
                // Auto-disable one-shot alarms.
                if alarm.repeat_days == 0 {
                    alarm.enabled = false;
                }
            }
        }
        firing
    }

    // -- Timer --

    /// Mutable access to the timer.
    pub fn timer_mut(&mut self) -> &mut Timer {
        &mut self.timer
    }

    /// Immutable access to the timer.
    pub fn timer(&self) -> &Timer {
        &self.timer
    }

    // -- Stopwatch --

    /// Mutable access to the stopwatch.
    pub fn stopwatch_mut(&mut self) -> &mut Stopwatch {
        &mut self.stopwatch
    }

    /// Immutable access to the stopwatch.
    pub fn stopwatch(&self) -> &Stopwatch {
        &self.stopwatch
    }
}

// ---------------------------------------------------------------------------
// Epoch decomposition utilities (shared with screen modules)
// ---------------------------------------------------------------------------

/// Decompose Unix epoch seconds into `(hour, minute, year, month, day)`.
///
/// Uses a simplified algorithm sufficient for display purposes.
pub fn decompose_epoch(epoch: u64) -> (u8, u8, u16, u8, u8) {
    if epoch == 0 {
        return (0, 0, 0, 0, 0);
    }

    let day_secs = epoch % SECS_PER_DAY;
    let hour = (day_secs / SECS_PER_HOUR) as u8;
    let minute = ((day_secs % SECS_PER_HOUR) / SECS_PER_MIN) as u8;

    let mut days = (epoch / SECS_PER_DAY) as u32;
    let mut year: u16 = 1970;
    loop {
        let days_in_year = if is_leap_year(year) { 366 } else { 365 };
        if days < days_in_year {
            break;
        }
        days -= days_in_year;
        year += 1;
    }

    let leap = is_leap_year(year);
    let month_days: [u32; 12] = [
        31,
        if leap { 29 } else { 28 },
        31, 30, 31, 30, 31, 31, 30, 31, 30, 31,
    ];
    let mut month: u8 = 1;
    for &md in &month_days {
        if days < md {
            break;
        }
        days -= md;
        month += 1;
    }

    let day = (days + 1) as u8;
    (hour, minute, year, month, day)
}

/// Check if a year is a leap year.
const fn is_leap_year(year: u16) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

/// Format date as "YYYY-MM-DD" into a fixed buffer.
pub fn format_date(year: u16, month: u8, day: u8) -> [u8; 10] {
    [
        b'0' + (year / 1000) as u8,
        b'0' + ((year / 100) % 10) as u8,
        b'0' + ((year / 10) % 10) as u8,
        b'0' + (year % 10) as u8,
        b'-',
        b'0' + month / 10,
        b'0' + month % 10,
        b'-',
        b'0' + day / 10,
        b'0' + day % 10,
    ]
}

/// Format time as "HH:MM" into a fixed buffer.
pub fn format_time_hhmm(hour: u8, minute: u8) -> [u8; 5] {
    [
        b'0' + hour / 10,
        b'0' + hour % 10,
        b':',
        b'0' + minute / 10,
        b'0' + minute % 10,
    ]
}

/// Compute a day label relative to a reference epoch.
///
/// Returns "TODAY", "TOMORROW", or "YYYY-MM-DD" for other days.
pub fn day_label(event_epoch: u64, current_epoch: u64) -> DayLabel {
    let event_day = event_epoch / SECS_PER_DAY;
    let current_day = current_epoch / SECS_PER_DAY;

    if event_day == current_day {
        DayLabel::Today
    } else if event_day == current_day + 1 {
        DayLabel::Tomorrow
    } else {
        let (_, _, y, m, d) = decompose_epoch(event_epoch);
        DayLabel::Date(format_date(y, m, d))
    }
}

/// Day label for agenda grouping.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum DayLabel {
    /// Same day as reference epoch.
    Today,
    /// Day after reference epoch.
    Tomorrow,
    /// Formatted date for other days.
    Date([u8; 10]),
}

impl core::fmt::Display for DayLabel {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl DayLabel {
    /// Return a displayable string.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Today => "TODAY",
            Self::Tomorrow => "TOMORROW",
            Self::Date(buf) => core::str::from_utf8(buf).unwrap_or("????-??-??"),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_event_increments_id() {
        let mut mgr = HeorteManager::new();
        let id1 = mgr.add_event(b"Meeting", 1_000_000, 60, false);
        let id2 = mgr.add_event(b"Lunch", 2_000_000, 30, false);
        assert_eq!(id1, 1, "first event ID must be 1");
        assert_eq!(id2, 2, "second event ID must be 2");
        assert_eq!(mgr.events().len(), 2, "must have 2 events");
    }

    #[test]
    fn events_sorted_by_start_time() {
        let mut mgr = HeorteManager::new();
        mgr.add_event(b"Later", 2_000_000, 60, false);
        mgr.add_event(b"Earlier", 1_000_000, 30, false);
        let events = mgr.events();
        assert!(
            events[0].start_epoch < events[1].start_epoch,
            "events must be sorted by start_epoch"
        );
        assert_eq!(events[0].title_str(), "Earlier");
        assert_eq!(events[1].title_str(), "Later");
    }

    #[test]
    fn remove_event_works() {
        let mut mgr = HeorteManager::new();
        let id = mgr.add_event(b"Delete me", 1_000_000, 60, false);
        assert!(mgr.remove_event(id), "must remove existing event");
        assert!(mgr.events().is_empty(), "events must be empty after removal");
        assert!(!mgr.remove_event(id), "removing again must return false");
    }

    #[test]
    fn event_title_truncation() {
        let long_title = [b'A'; 100];
        let event = CalendarEvent::new(1, &long_title, 0, 0, false);
        assert_eq!(event.title_len as usize, MAX_TITLE_LEN, "title must be truncated");
    }

    #[test]
    fn event_is_active() {
        let event = CalendarEvent::new(1, b"Test", 1000, 60, false);
        // 60 min = 3600 sec, so active range is [1000, 4600).
        assert!(event.is_active(1000), "must be active at start");
        assert!(event.is_active(3000), "must be active during event");
        assert!(!event.is_active(4600), "must not be active at end");
        assert!(!event.is_active(999), "must not be active before start");
    }

    #[test]
    fn timer_countdown_updates() {
        let mut timer = Timer::new();
        timer.set_duration(300); // 5 minutes
        assert_eq!(timer.remaining_secs, 300);

        timer.start(1000); // start at tick 1000ms
        assert!(timer.running);

        // Advance 60 seconds (60000ms).
        let expired = timer.update(61_000);
        assert!(!expired, "timer must not be expired yet");
        assert_eq!(timer.remaining_secs, 240, "must have 240s remaining after 60s");
    }

    #[test]
    fn timer_expires() {
        let mut timer = Timer::new();
        timer.set_duration(10);
        timer.start(0);

        let expired = timer.update(10_000); // 10 seconds
        assert!(expired, "timer must expire after full duration");
        assert_eq!(timer.remaining_secs, 0);
        assert!(!timer.running, "timer must stop when expired");
    }

    #[test]
    fn timer_pause_resume() {
        let mut timer = Timer::new();
        timer.set_duration(60);
        timer.start(0);
        timer.pause(5_000); // pause after 5 seconds
        assert!(!timer.running);
        assert_eq!(timer.remaining_secs, 55);

        timer.start(10_000); // resume at tick 10000
        let expired = timer.update(20_000); // 10 more seconds
        assert!(!expired);
        assert_eq!(timer.remaining_secs, 45);
    }

    #[test]
    fn timer_reset_clears() {
        let mut timer = Timer::new();
        timer.set_duration(120);
        timer.start(0);
        timer.update(30_000); // advance 30 seconds
        timer.reset();
        assert_eq!(timer.remaining_secs, 120, "reset must restore full duration");
        assert!(!timer.running, "reset must stop timer");
    }

    #[test]
    fn timer_format_remaining() {
        let mut timer = Timer::new();
        timer.set_duration(332); // 5:32
        let buf = timer.format_remaining();
        assert_eq!(&buf, b"05:32", "must format as MM:SS");

        timer.set_duration(0);
        let buf = timer.format_remaining();
        assert_eq!(&buf, b"00:00");
    }

    #[test]
    fn stopwatch_lap_records() {
        let mut sw = Stopwatch::new();
        sw.start(0);
        sw.lap(3_000); // lap 1 at 3s
        sw.lap(7_000); // lap 2 at 7s
        sw.lap(10_000); // lap 3 at 10s

        assert_eq!(sw.laps.len(), 3, "must have 3 laps");
        let durations = sw.lap_durations();
        assert_eq!(durations.len(), 3);
        assert_eq!(durations[0], (1, 3_000), "lap 1 must be 3s");
        assert_eq!(durations[1], (2, 4_000), "lap 2 must be 4s");
        assert_eq!(durations[2], (3, 3_000), "lap 3 must be 3s");
    }

    #[test]
    fn stopwatch_elapsed_accumulates() {
        let mut sw = Stopwatch::new();
        sw.start(0);
        sw.stop(5_000); // 5 seconds
        assert_eq!(sw.elapsed_ms, 5_000);

        sw.start(10_000);
        sw.stop(13_000); // 3 more seconds
        assert_eq!(sw.elapsed_ms, 8_000, "elapsed must accumulate across stop/start");
    }

    #[test]
    fn stopwatch_reset() {
        let mut sw = Stopwatch::new();
        sw.start(0);
        sw.lap(1_000);
        sw.stop(2_000);
        sw.reset();
        assert_eq!(sw.elapsed_ms, 0, "reset must clear elapsed");
        assert!(sw.laps.is_empty(), "reset must clear laps");
        assert!(!sw.running, "reset must stop stopwatch");
    }

    #[test]
    fn stopwatch_max_laps() {
        let mut sw = Stopwatch::new();
        sw.start(0);
        for i in 1..=55 {
            sw.lap(i * 1000);
        }
        assert_eq!(sw.laps.len(), MAX_LAPS, "must cap at MAX_LAPS");
    }

    #[test]
    fn stopwatch_lap_while_stopped() {
        let mut sw = Stopwatch::new();
        sw.lap(1_000); // should be a no-op
        assert!(sw.laps.is_empty(), "lap while stopped must be ignored");
    }

    #[test]
    fn alarm_fires_at_correct_time() {
        // Alarm at 06:30, no repeat (one-shot).
        let alarm = Alarm::new(1, 6, 30, b"Wake up", true, 0);

        // 06:30:00 UTC on any day: epoch where time-of-day = 6*3600 + 30*60 = 23400
        let epoch_630 = 23400;
        assert!(alarm.should_fire(epoch_630), "alarm must fire at 06:30");

        // 06:31:00 UTC
        let epoch_631 = 23460;
        assert!(!alarm.should_fire(epoch_631), "alarm must not fire at 06:31");
    }

    #[test]
    fn alarm_disabled_does_not_fire() {
        let alarm = Alarm::new(1, 6, 30, b"Wake up", false, 0);
        let epoch_630 = 23400;
        assert!(!alarm.should_fire(epoch_630), "disabled alarm must not fire");
    }

    #[test]
    fn alarm_repeat_mask_works() {
        use day_mask::*;
        // Alarm at 08:00, weekdays only.
        let alarm = Alarm::new(1, 8, 0, b"Work", true, WEEKDAYS);

        // 1970-01-01 was a Thursday (day 4). 08:00 that day = 28800.
        let thursday_0800 = 28800u64;
        assert!(alarm.should_fire(thursday_0800), "Thursday must fire for weekday alarm");

        // 1970-01-03 was a Saturday. 08:00 = 2*86400 + 28800 = 201600.
        let saturday_0800 = 2 * SECS_PER_DAY + 28800;
        assert!(!alarm.should_fire(saturday_0800), "Saturday must not fire for weekday alarm");

        // 1970-01-04 was a Sunday. 08:00 = 3*86400 + 28800 = 288000.
        let sunday_0800 = 3 * SECS_PER_DAY + 28800;
        assert!(!alarm.should_fire(sunday_0800), "Sunday must not fire for weekday alarm");
    }

    #[test]
    fn check_alarms_auto_disables_oneshot() {
        let mut mgr = HeorteManager::new();
        mgr.add_alarm(6, 30, b"Once", true, 0);

        let firing = mgr.check_alarms(23400); // 06:30
        assert_eq!(firing.len(), 1, "one alarm must fire");

        // After firing, the one-shot alarm must be disabled.
        assert!(!mgr.alarms()[0].enabled, "one-shot alarm must auto-disable");

        // Checking again must not fire.
        let firing2 = mgr.check_alarms(23400);
        assert!(firing2.is_empty(), "disabled alarm must not fire again");
    }

    #[test]
    fn toggle_alarm_works() {
        let mut mgr = HeorteManager::new();
        let id = mgr.add_alarm(7, 0, b"Test", true, 0);
        let new_state = mgr.toggle_alarm(id);
        assert_eq!(new_state, Some(false), "toggle must disable");

        let new_state2 = mgr.toggle_alarm(id);
        assert_eq!(new_state2, Some(true), "toggle again must enable");

        let missing = mgr.toggle_alarm(999);
        assert_eq!(missing, None, "toggle non-existent must return None");
    }

    #[test]
    fn alarm_repeat_labels() {
        assert_eq!(Alarm::new(1, 0, 0, b"", true, 0).repeat_label(), "Once");
        assert_eq!(Alarm::new(1, 0, 0, b"", true, day_mask::DAILY).repeat_label(), "Daily");
        assert_eq!(Alarm::new(1, 0, 0, b"", true, day_mask::WEEKDAYS).repeat_label(), "Weekdays");
        assert_eq!(Alarm::new(1, 0, 0, b"", true, day_mask::MON | day_mask::WED).repeat_label(), "Custom");
    }

    #[test]
    fn day_of_week_known_dates() {
        // 1970-01-01 = Thursday = 4
        assert_eq!(day_of_week(0), 4, "1970-01-01 must be Thursday");
        // 1970-01-04 = Sunday = 0
        assert_eq!(day_of_week(3 * SECS_PER_DAY), 0, "1970-01-04 must be Sunday");
    }

    #[test]
    fn format_elapsed_ms_works() {
        // 12 min 34 sec 567 ms
        let ms = 12 * 60 * 1000 + 34 * 1000 + 567;
        let buf = format_elapsed_ms(ms);
        let s = core::str::from_utf8(&buf).unwrap_or("");
        assert_eq!(s, "00:12:34.567");
    }

    #[test]
    fn format_lap_ms_works() {
        let ms = 3 * 60 * 1000 + 21 * 1000 + 443;
        let buf = format_lap_ms(ms);
        let s = core::str::from_utf8(&buf).unwrap_or("");
        assert_eq!(s, "03:21.443");
    }

    #[test]
    fn decompose_epoch_known() {
        // 2026-01-01 00:00:00 UTC = 1767225600
        let (h, m, y, mo, d) = decompose_epoch(1_767_225_600);
        assert_eq!((y, mo, d, h, m), (2026, 1, 1, 0, 0));
    }

    #[test]
    fn day_label_today_tomorrow() {
        let current = 86400 * 10; // day 10
        let today_event = 86400 * 10 + 3600;
        let tomorrow_event = 86400 * 11 + 7200;
        let other_event = 86400 * 15;

        assert!(matches!(day_label(today_event, current), DayLabel::Today));
        assert!(matches!(day_label(tomorrow_event, current), DayLabel::Tomorrow));
        assert!(matches!(day_label(other_event, current), DayLabel::Date(_)));
    }

    #[test]
    fn find_event_works() {
        let mut mgr = HeorteManager::new();
        let id = mgr.add_event(b"Find me", 1_000_000, 60, false);
        assert!(mgr.find_event(id).is_some(), "must find existing event");
        assert_eq!(mgr.find_event(id).map(|e| e.title_str()), Some("Find me"));
        assert!(mgr.find_event(999).is_none(), "must not find non-existent");
    }

    #[test]
    fn upcoming_events_filters() {
        let mut mgr = HeorteManager::new();
        mgr.add_event(b"Past", 1000, 10, false); // ends at 1600
        mgr.add_event(b"Active", 5000, 60, false); // ends at 8600
        mgr.add_event(b"Future", 10000, 30, false);

        let upcoming = mgr.upcoming_events(6000);
        assert_eq!(upcoming.len(), 2, "must include active and future events");
        assert_eq!(upcoming[0].title_str(), "Active");
        assert_eq!(upcoming[1].title_str(), "Future");
    }
}
