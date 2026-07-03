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
//! ## Module structure
//!
//! Alarm logic is in [`crate::heorte_alarm`].
//! Timer and stopwatch are in [`crate::heorte_timer`].
//!
//! ## Design decisions
//!
//! - Fixed-size title/label buffers avoid heap allocation for small strings.
//! - `Vec` used for event/alarm lists and stopwatch laps (kernel has an allocator).
//! - No `unwrap()`/`expect()` in any code path.
//! - Tick-based timing: callers pass the current kernel tick count; the engine
//!   computes elapsed time from deltas rather than polling a clock.

// WHY: the engine is compiled and tested but no boot-time runtime manager
// owns calendar/alarm/timer state yet.
#![expect(dead_code, reason = "Heorte runtime manager is not wired into kinit")]

extern crate alloc;
use alloc::vec::Vec;

// Re-export alarm, timer, and stopwatch types so callers can still use crate::heorte::*.
pub(crate) use crate::heorte_alarm::*;
pub(crate) use crate::heorte_timer::*;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum title length for calendar events (bytes).
const MAX_TITLE_LEN: usize = 64;

/// Seconds per minute.
pub(crate) const SECS_PER_MIN: u64 = 60;

/// Seconds per hour.
pub(crate) const SECS_PER_HOUR: u64 = 3600;

/// Seconds per day.
pub(crate) const SECS_PER_DAY: u64 = 86400;

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

/// Return the largest prefix length of `bytes` (capped at `max_len`) that
/// ends on a valid UTF-8 char boundary, so truncating to it never splits a
/// multi-byte codepoint (#359).
pub(crate) fn utf8_truncate_len(bytes: &[u8], max_len: usize) -> usize {
    let mut len = bytes.len().min(max_len);
    if len == bytes.len() {
        return len;
    }
    // UTF-8 continuation bytes are `10xxxxxx` (0x80..=0xBF); back off from
    // a mid-codepoint cut to the start of that codepoint.
    while len > 0 && (bytes[len] & 0xC0) == 0x80 {
        len -= 1;
    }
    len
}

impl CalendarEvent {
    /// Create a new calendar event.
    ///
    /// `title_bytes` is truncated to [`MAX_TITLE_LEN`] if longer, backing
    /// off to the last full codepoint so truncation never splits one
    /// (#359).
    #[must_use]
    pub(crate) fn new(
        id: u32,
        title_bytes: &[u8],
        start_epoch: u64,
        duration_min: u16,
        all_day: bool,
    ) -> Self {
        let mut title = [0u8; MAX_TITLE_LEN];
        let len = utf8_truncate_len(title_bytes, MAX_TITLE_LEN);
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
    pub(crate) fn title_str(&self) -> &str {
        core::str::from_utf8(&self.title[..self.title_len as usize]).unwrap_or("")
    }

    /// End epoch (start + duration). Returns `start_epoch` if duration is 0.
    pub(crate) fn end_epoch(&self) -> u64 {
        self.start_epoch + u64::from(self.duration_min) * SECS_PER_MIN
    }

    /// Whether this event is active (happening now) at the given epoch.
    pub(crate) fn is_active(&self, current_epoch: u64) -> bool {
        current_epoch >= self.start_epoch && current_epoch < self.end_epoch()
    }

    /// Extract the day (as days since Unix epoch) for grouping.
    pub(crate) fn day_index(&self) -> u32 {
        (self.start_epoch / SECS_PER_DAY) as u32
    }
}

impl core::fmt::Display for CalendarEvent {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.title_str())
    }
}

// ---------------------------------------------------------------------------
// Heorte manager
// ---------------------------------------------------------------------------

/// Central manager for calendar events, alarms, timer, and stopwatch.
///
/// Owns all heorte state and provides a unified API for the UI screens.
/// Event and alarm IDs are auto-incremented and never reused within a
/// session (persistence across reboots is handled by the storage layer).
pub(crate) struct HeorteManager {
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
    pub(crate) fn new() -> Self {
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
    pub(crate) fn add_event(
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
    pub(crate) fn remove_event(&mut self, id: u32) -> bool {
        let before = self.events.len();
        self.events.retain(|e| e.id != id);
        self.events.len() < before
    }

    /// List all events, sorted by start time.
    pub(crate) fn events(&self) -> &[CalendarEvent] {
        &self.events
    }

    /// List events occurring on or after the given epoch, sorted by start time.
    pub(crate) fn upcoming_events(&self, from_epoch: u64) -> Vec<&CalendarEvent> {
        self.events
            .iter()
            .filter(|e| e.end_epoch() > from_epoch || e.start_epoch >= from_epoch)
            .collect()
    }

    /// Find an event by ID.
    pub(crate) fn find_event(&self, id: u32) -> Option<&CalendarEvent> {
        self.events.iter().find(|e| e.id == id)
    }

    /// Sort events by `start_epoch` (stable sort preserves insertion order for ties).
    fn sort_events(&mut self) {
        self.events.sort_by_key(|e| e.start_epoch);
    }

    // -- Alarms --

    /// Add an alarm. Returns the assigned alarm ID.
    pub(crate) fn add_alarm(
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
    pub(crate) fn remove_alarm(&mut self, id: u32) -> bool {
        let before = self.alarms.len();
        self.alarms.retain(|a| a.id != id);
        self.alarms.len() < before
    }

    /// Toggle an alarm's enabled state by ID. Returns the new state, or
    /// `None` if the alarm was not found.
    pub(crate) fn toggle_alarm(&mut self, id: u32) -> Option<bool> {
        for alarm in &mut self.alarms {
            if alarm.id == id {
                alarm.enabled = !alarm.enabled;
                return Some(alarm.enabled);
            }
        }
        None
    }

    /// List all alarms.
    pub(crate) fn alarms(&self) -> &[Alarm] {
        &self.alarms
    }

    /// Check which alarms should fire at the given epoch.
    ///
    /// Returns a list of alarm IDs that match. One-shot alarms (`repeat_days` == 0)
    /// are auto-disabled after firing.
    pub(crate) fn check_alarms(&mut self, current_epoch: u64) -> Vec<u32> {
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
    pub(crate) fn timer_mut(&mut self) -> &mut Timer {
        &mut self.timer
    }

    /// Immutable access to the timer.
    pub(crate) fn timer(&self) -> &Timer {
        &self.timer
    }

    // -- Stopwatch --

    /// Mutable access to the stopwatch.
    pub(crate) fn stopwatch_mut(&mut self) -> &mut Stopwatch {
        &mut self.stopwatch
    }

    /// Immutable access to the stopwatch.
    pub(crate) fn stopwatch(&self) -> &Stopwatch {
        &self.stopwatch
    }
}

// ---------------------------------------------------------------------------
// Epoch decomposition utilities (shared with screen modules)
// ---------------------------------------------------------------------------

/// Decompose Unix epoch seconds into `(hour, minute, year, month, day)`.
///
/// Uses a closed-form Gregorian calendar calculation (O(1) regardless of
/// epoch magnitude) sufficient for display purposes. `year` saturates to
/// `u16::MAX` for dates beyond the display range rather than overflowing
/// or iterating (#366).
pub(crate) fn decompose_epoch(epoch: u64) -> (u8, u8, u16, u8, u8) {
    if epoch == 0 {
        return (0, 0, 0, 0, 0);
    }

    let day_secs = epoch % SECS_PER_DAY;
    let hour = (day_secs / SECS_PER_HOUR) as u8;
    let minute = ((day_secs % SECS_PER_HOUR) / SECS_PER_MIN) as u8;

    let days = epoch / SECS_PER_DAY;
    let (year, month, day) = civil_from_days(days);
    (hour, minute, year, month, day)
}

/// Convert days-since-Unix-epoch to a `(year, month, day)` civil date in
/// O(1), replacing the year-by-year iteration that made `decompose_epoch`
/// an O(years) DoS surface for an adversarial epoch -- up to ~11.7M
/// iterations for a large `days` value (#366).
///
/// Closed-form Gregorian calendar algorithm (Howard Hinnant's
/// `civil_from_days`, <https://howardhinnant.github.io/date_algorithms.html>).
/// `days` is always non-negative here (`epoch / SECS_PER_DAY`), so the
/// `i64` intermediate arithmetic never loses range for any `u64` epoch.
/// `year` saturates to `u16::MAX` rather than overflowing for dates far
/// beyond the display range.
fn civil_from_days(days: u64) -> (u16, u8, u8) {
    let z = (days as i64).saturating_add(719_468);
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let y = if m <= 2 { y + 1 } else { y };

    let year = u16::try_from(y).unwrap_or(u16::MAX);
    (year, m as u8, d as u8)
}

/// Format date as "YYYY-MM-DD" into a fixed buffer.
pub(crate) fn format_date(year: u16, month: u8, day: u8) -> [u8; 10] {
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
pub(crate) fn format_time_hhmm(hour: u8, minute: u8) -> [u8; 5] {
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
pub(crate) fn day_label(event_epoch: u64, current_epoch: u64) -> DayLabel {
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
    pub(crate) fn as_str(&self) -> &str {
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
        assert!(
            mgr.events().is_empty(),
            "events must be empty after removal"
        );
        assert!(!mgr.remove_event(id), "removing again must return false");
    }

    #[test]
    fn event_title_truncation() {
        let long_title = [b'A'; 100];
        let event = CalendarEvent::new(1, &long_title, 0, 0, false);
        assert_eq!(
            event.title_len as usize, MAX_TITLE_LEN,
            "title must be truncated"
        );
    }

    #[test]
    fn event_title_truncation_preserves_valid_utf8_prefix() {
        // 63 ASCII bytes + a 2-byte codepoint straddling MAX_TITLE_LEN (64):
        // pre-fix, a byte-count truncation would cut mid-codepoint and
        // title_str() would silently return "" instead of the 63 valid
        // 'A' characters (#359).
        let mut long_title = alloc::vec![b'A'; 63];
        long_title.extend_from_slice("é".as_bytes());
        let event = CalendarEvent::new(1, &long_title, 0, 0, false);
        assert_eq!(
            event.title_len as usize, 63,
            "truncation must back off to the last full codepoint, not split it"
        );
        assert_eq!(event.title_str().len(), 63);
        assert!(event.title_str().chars().all(|c| c == 'A'));
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
    fn decompose_epoch_known() {
        // 2026-01-01 00:00:00 UTC = 1767225600
        let (h, m, y, mo, d) = decompose_epoch(1_767_225_600);
        assert_eq!((y, mo, d, h, m), (2026, 1, 1, 0, 0));
    }

    #[test]
    fn decompose_epoch_large_value_completes_in_o1() {
        // #366: an adversarial epoch near u64::MAX previously drove the
        // year-by-year loop through millions of iterations. The closed-form
        // civil_from_days() calculation returns in O(1) regardless of
        // magnitude -- this test would hang under the old implementation
        // and returns instantly under the fix.
        let (_, _, year, month, day) = decompose_epoch(u64::MAX / 2);
        assert_eq!(
            year,
            u16::MAX,
            "year must saturate rather than wrap or panic"
        );
        assert!((1..=12).contains(&month), "month must stay in valid range");
        assert!((1..=31).contains(&day), "day must stay in valid range");
    }

    #[test]
    fn day_label_today_tomorrow() {
        let current = 86400 * 10; // day 10
        let today_event = 86400 * 10 + 3600;
        let tomorrow_event = 86400 * 11 + 7200;
        let other_event = 86400 * 15;

        assert!(matches!(day_label(today_event, current), DayLabel::Today));
        assert!(matches!(
            day_label(tomorrow_event, current),
            DayLabel::Tomorrow
        ));
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
