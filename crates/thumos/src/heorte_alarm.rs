//! Alarm subsystem for the Heorte engine.
//!
//! Provides [`Alarm`] with day-of-week repeat scheduling, fire-at-time checking,
//! and the [`day_mask`] constants for building repeat bitmasks.

// Items in this module are re-exported from heorte.rs.

use crate::heorte::{utf8_truncate_len, SECS_PER_DAY, SECS_PER_HOUR, SECS_PER_MIN};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum label length for alarms (bytes).
const MAX_LABEL_LEN: usize = 32;

// ---------------------------------------------------------------------------
// Day-of-week bitmask
// ---------------------------------------------------------------------------

/// Day-of-week bitmask constants for alarm repeat scheduling.
pub(crate) mod day_mask {
    /// Sunday (bit 0).
    pub(crate) const SUN: u8 = 1 << 0;
    /// Monday (bit 1).
    pub(crate) const MON: u8 = 1 << 1;
    /// Tuesday (bit 2).
    pub(crate) const TUE: u8 = 1 << 2;
    /// Wednesday (bit 3).
    pub(crate) const WED: u8 = 1 << 3;
    /// Thursday (bit 4).
    pub(crate) const THU: u8 = 1 << 4;
    /// Friday (bit 5).
    pub(crate) const FRI: u8 = 1 << 5;
    /// Saturday (bit 6).
    pub(crate) const SAT: u8 = 1 << 6;
    /// All weekdays (Mon-Fri).
    pub(crate) const WEEKDAYS: u8 = MON | TUE | WED | THU | FRI;
    /// Every day.
    pub(crate) const DAILY: u8 = SUN | MON | TUE | WED | THU | FRI | SAT;
}

// ---------------------------------------------------------------------------
// Alarm
// ---------------------------------------------------------------------------

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
    pub(crate) fn new(
        id: u32,
        hour: u8,
        minute: u8,
        label_bytes: &[u8],
        enabled: bool,
        repeat_days: u8,
    ) -> Self {
        let mut label = [0u8; MAX_LABEL_LEN];
        let len = utf8_truncate_len(label_bytes, MAX_LABEL_LEN);
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
    pub(crate) fn label_str(&self) -> &str {
        core::str::from_utf8(&self.label[..self.label_len as usize]).unwrap_or("")
    }

    /// Check whether this alarm should fire at the given epoch.
    ///
    /// Returns `true` if the alarm is enabled and the current time-of-day
    /// matches the alarm's hour:minute. If `repeat_days` is non-zero,
    /// also checks whether the current day-of-week is in the bitmask.
    pub(crate) fn should_fire(&self, current_epoch: u64) -> bool {
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
    pub(crate) fn repeat_label(&self) -> &'static str {
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
pub(crate) fn day_of_week(epoch: u64) -> u8 {
    let days = epoch / SECS_PER_DAY;
    ((days + 4) % 7) as u8 // +4 because 1970-01-01 was Thursday
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

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
    fn alarm_label_truncation_preserves_valid_utf8_prefix() {
        // 31 ASCII bytes + a 2-byte codepoint straddling MAX_LABEL_LEN (32):
        // pre-fix, a byte-count truncation would cut mid-codepoint and
        // label_str() would silently return "" instead of the 31 valid
        // 'A' characters (#359).
        let mut long_label = alloc::vec![b'A'; 31];
        long_label.extend_from_slice("é".as_bytes());
        let alarm = Alarm::new(1, 6, 30, &long_label, true, 0);
        assert_eq!(
            alarm.label_len as usize, 31,
            "truncation must back off to the last full codepoint, not split it"
        );
        assert_eq!(alarm.label_str().len(), 31);
        assert!(alarm.label_str().chars().all(|c| c == 'A'));
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
}
