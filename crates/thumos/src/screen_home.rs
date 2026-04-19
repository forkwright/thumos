//! Home (idle) screen for the thumos kernel UI.
//!
//! Displays:
//! - Large centered time in 24-hour format (`HH:MM`)
//! - ISO date below (`YYYY-MM-DD`)
//! - Carrier name or "No service"
//! - Mode indicator (`DAILY` / `SENTINEL` / `PANIC`)
//! - Unread message count (if any)
//! - Softkeys: LSK = "MSGS", RSK = "SEARCH"
//!
//! Time is sourced from the clock module's `ClockManager`. The screen
//! accepts a snapshot of the current state to avoid holding references
//! to kernel globals across the render boundary.

// WHY: home screen is created in Phase 07 Wave 1, not yet wired to kinit.
#![expect(dead_code, reason = "Home screen created in Phase 07 Wave 1, kinit wiring pending")]

use crate::ui::{
    self, color, Key, Screen, ScreenAction, ScreenId,
    CHAR_HEIGHT, CHAR_WIDTH, CONTENT_HEIGHT, SCREEN_WIDTH,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Y offset for the large time display, roughly 1/4 down the content area.
const TIME_Y: u16 = 60;

/// Y offset for the date line, below the time.
const DATE_Y: u16 = TIME_Y + CHAR_HEIGHT * 2 + 8;

/// Y offset for the carrier/service line.
const CARRIER_Y: u16 = DATE_Y + CHAR_HEIGHT + 8;

/// Y offset for the mode indicator.
const MODE_Y: u16 = CARRIER_Y + CHAR_HEIGHT + 4;

/// Y offset for the unread count line.
const UNREAD_Y: u16 = MODE_Y + CHAR_HEIGHT + 4;

/// Scale factor for the large time digits.
///
/// Time is rendered at 2x the base font size (16x32 pixels per character).
const TIME_SCALE: u16 = 2;

/// Width of a scaled character.
const SCALED_CHAR_WIDTH: u16 = CHAR_WIDTH * TIME_SCALE;

/// Height of a scaled character.
const SCALED_CHAR_HEIGHT: u16 = CHAR_HEIGHT * TIME_SCALE;

// ---------------------------------------------------------------------------
// Operating mode
// ---------------------------------------------------------------------------

/// Phone operating mode, displayed on the home screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum OperatingMode {
    /// Normal daily use.
    #[default]
    Daily,
    /// Heightened awareness mode.
    Sentinel,
    /// Emergency mode.
    Panic,
}

impl OperatingMode {
    /// Display label for this mode.
    const fn label(self) -> &'static str {
        match self {
            Self::Daily => "DAILY",
            Self::Sentinel => "SENTINEL",
            Self::Panic => "PANIC",
        }
    }

    /// Color for the mode indicator.
    const fn color(self) -> u16 {
        match self {
            Self::Daily => color::WHITE,
            Self::Sentinel => color::YELLOW,
            Self::Panic => color::RED,
        }
    }
}

// ---------------------------------------------------------------------------
// Home screen state
// ---------------------------------------------------------------------------

/// Snapshot of the state needed to render the home screen.
///
/// Updated each render cycle from kernel globals. The home screen does not
/// own the clock or telephony state; it receives a snapshot to avoid
/// lifetime issues with kernel statics.
pub(crate) struct HomeScreenState {
    /// Wall clock time as Unix epoch seconds (0 = no time source).
    pub epoch_secs: u64,
    /// Carrier name (empty = no SIM / no service).
    pub carrier: &'static str,
    /// Current operating mode.
    pub mode: OperatingMode,
    /// Number of unread messages.
    pub unread_count: u16,
}

impl Default for HomeScreenState {
    fn default() -> Self {
        Self {
            epoch_secs: 0,
            carrier: "",
            mode: OperatingMode::Daily,
            unread_count: 0,
        }
    }
}

/// Home screen implementation.
pub(crate) struct HomeScreen {
    /// Current state snapshot, updated before each render.
    pub state: HomeScreenState,
}

impl HomeScreen {
    /// Create a new home screen with default state.
    pub(crate) fn new() -> Self {
        Self {
            state: HomeScreenState::default(),
        }
    }

    /// Update the state snapshot. Called each render cycle.
    pub(crate) fn update_state(&mut self, state: HomeScreenState) {
        self.state = state;
    }
}

impl Screen for HomeScreen {
    fn draw(&self, fb: &mut [u16]) {
        let w = SCREEN_WIDTH;
        let h = CONTENT_HEIGHT;

        // Clear content area to black.
        ui::fill_rect(fb, w, h, 0, 0, w, h, color::BLACK);

        // Extract HH:MM and YYYY-MM-DD from epoch seconds.
        let (hour, minute, year, month, day) = decompose_epoch(self.state.epoch_secs);

        // Large centered time (2x scale).
        let time_buf = format_time(hour, minute);
        ui::draw_scaled_str_centered(fb, w, TIME_Y, &time_buf, color::WHITE, color::BLACK, TIME_SCALE);

        // ISO date.
        let date_buf = format_date(year, month, day);
        let date_str = core::str::from_utf8(&date_buf).unwrap_or("----/--/--");
        ui::draw_str_centered(fb, w, 0, w, DATE_Y, date_str, color::WHITE, color::BLACK);

        // Carrier or "No service".
        let carrier_text = if self.state.carrier.is_empty() {
            "No service"
        } else {
            self.state.carrier
        };
        ui::draw_str_centered(
            fb, w, 0, w, CARRIER_Y, carrier_text, color::DARK_GREY, color::BLACK,
        );

        // Mode indicator.
        let mode_label = self.state.mode.label();
        let mode_color = self.state.mode.color();
        ui::draw_str_centered(fb, w, 0, w, MODE_Y, mode_label, mode_color, color::BLACK);

        // Unread count (only if > 0).
        if self.state.unread_count > 0 {
            let unread_buf = format_unread(self.state.unread_count);
            ui::draw_str_centered(
                fb, w, 0, w, UNREAD_Y, unread_buf.as_str(), color::YELLOW, color::BLACK,
            );
        }
    }

    fn on_key(&mut self, key: Key) -> ScreenAction {
        match key {
            Key::Lsk => ScreenAction::Navigate(ScreenId::Messages),
            Key::Rsk => ScreenAction::Navigate(ScreenId::Search),
            Key::Call => ScreenAction::Navigate(ScreenId::Dialer),
            Key::Ok => ScreenAction::Navigate(ScreenId::Settings),
            _ => ScreenAction::None,
        }
    }

    fn softkey_left(&self) -> &'static str {
        "MSGS"
    }

    fn softkey_right(&self) -> &'static str {
        "SEARCH"
    }

    fn title(&self) -> &'static str {
        ""
    }
}

// ---------------------------------------------------------------------------
// Time/date decomposition
// ---------------------------------------------------------------------------

/// Decompose Unix epoch seconds into `(hour, minute, year, month, day)`.
///
/// Uses a simplified algorithm sufficient for display purposes. Not a
/// full calendar implementation -- no leap-second handling, approximate
/// leap-year handling.
fn decompose_epoch(epoch: u64) -> (u8, u8, u16, u8, u8) {
    if epoch == 0 {
        return (0, 0, 0, 0, 0);
    }

    // Time of day.
    let day_secs = epoch % 86400;
    let hour = (day_secs / 3600) as u8;
    let minute = ((day_secs % 3600) / 60) as u8;

    // Days since Unix epoch.
    let mut days = (epoch / 86400) as u32;

    // Year calculation (accounting for leap years).
    let mut year: u16 = 1970;
    loop {
        let days_in_year = if is_leap_year(year) { 366 } else { 365 };
        if days < days_in_year {
            break;
        }
        days -= days_in_year;
        year += 1;
    }

    // Month calculation.
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

    let day = (days + 1) as u8; // 1-indexed

    (hour, minute, year, month, day)
}

/// Check if a year is a leap year.
const fn is_leap_year(year: u16) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

// ---------------------------------------------------------------------------
// String formatting (no_std, no alloc for small buffers)
// ---------------------------------------------------------------------------

/// Format time as "HH:MM" into a fixed buffer.
fn format_time(hour: u8, minute: u8) -> [u8; 5] {
    [
        b'0' + hour / 10,
        b'0' + hour % 10,
        b':',
        b'0' + minute / 10,
        b'0' + minute % 10,
    ]
}

/// Format date as "YYYY-MM-DD" into a fixed buffer.
fn format_date(year: u16, month: u8, day: u8) -> [u8; 10] {
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

/// Format unread count as a display string.
///
/// Returns a fixed buffer like "3 UNREAD" or "99+ UNREAD" for large counts.
fn format_unread(count: u16) -> FormatBuf {
    let mut buf = FormatBuf::new();
    if count >= 100 {
        buf.push(b'9');
        buf.push(b'9');
        buf.push(b'+');
    } else if count >= 10 {
        buf.push(b'0' + (count / 10) as u8);
        buf.push(b'0' + (count % 10) as u8);
    } else {
        buf.push(b'0' + count as u8);
    }
    buf.push(b' ');
    for &b in b"UNREAD" {
        buf.push(b);
    }
    buf
}

/// Small fixed-capacity string buffer for `no_std` formatting.
///
/// Avoids heap allocation for short UI strings.
struct FormatBuf {
    data: [u8; 16],
    len: usize,
}

impl FormatBuf {
    const fn new() -> Self {
        Self {
            data: [0; 16],
            len: 0,
        }
    }

    fn push(&mut self, b: u8) {
        if self.len < self.data.len() {
            self.data[self.len] = b;
            self.len += 1;
        }
    }

    fn as_str(&self) -> &str {
        // All bytes pushed are ASCII, so this is always valid UTF-8.
        // SAFETY: we only push ASCII bytes (0x20..0x7E range) from format
        // functions above.
        core::str::from_utf8(&self.data[..self.len]).unwrap_or("")
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::CONTENT_PIXELS;

    #[test]
    fn home_screen_softkeys_correct() {
        let screen = HomeScreen::new();
        assert_eq!(
            screen.softkey_left(),
            "MSGS",
            "home screen left softkey must be 'MSGS'"
        );
        assert_eq!(
            screen.softkey_right(),
            "SEARCH",
            "home screen right softkey must be 'SEARCH'"
        );
    }

    #[test]
    fn home_screen_draws_without_panic() {
        let screen = HomeScreen::new();
        let mut fb = [0u16; CONTENT_PIXELS];
        screen.draw(&mut fb);
        // Should have rendered at least the "No service" text and mode indicator.
        let any_set = fb.iter().any(|&px| px != 0);
        assert!(
            any_set,
            "home screen must render visible content even with default state"
        );
    }

    #[test]
    fn home_screen_draws_with_time() {
        let mut screen = HomeScreen::new();
        // 2026-04-09 14:30:00 UTC (approximate epoch).
        screen.update_state(HomeScreenState {
            epoch_secs: 1_775_924_600,
            carrier: "Thumos",
            mode: OperatingMode::Daily,
            unread_count: 3,
        });
        let mut fb = [0u16; CONTENT_PIXELS];
        screen.draw(&mut fb);
        let any_set = fb.iter().any(|&px| px != 0);
        assert!(any_set, "home screen with time must render visible content");
    }

    #[test]
    fn home_screen_lsk_navigates_to_messages() {
        let mut screen = HomeScreen::new();
        let action = screen.on_key(Key::Lsk);
        assert_eq!(
            action,
            ScreenAction::Navigate(ScreenId::Messages),
            "LSK must navigate to Messages"
        );
    }

    #[test]
    fn home_screen_rsk_navigates_to_search() {
        let mut screen = HomeScreen::new();
        let action = screen.on_key(Key::Rsk);
        assert_eq!(
            action,
            ScreenAction::Navigate(ScreenId::Search),
            "RSK must navigate to Search"
        );
    }

    #[test]
    fn home_screen_call_navigates_to_dialer() {
        let mut screen = HomeScreen::new();
        let action = screen.on_key(Key::Call);
        assert_eq!(
            action,
            ScreenAction::Navigate(ScreenId::Dialer),
            "Call key must navigate to Dialer"
        );
    }

    #[test]
    fn decompose_epoch_zero_returns_zeroes() {
        let (h, m, y, mo, d) = decompose_epoch(0);
        assert_eq!((h, m, y, mo, d), (0, 0, 0, 0, 0), "epoch 0 must return all zeros");
    }

    #[test]
    fn decompose_epoch_known_date() {
        // 2026-01-01 00:00:00 UTC = 1767225600
        let (h, m, y, mo, d) = decompose_epoch(1_767_225_600);
        assert_eq!(y, 2026, "year must be 2026");
        assert_eq!(mo, 1, "month must be January");
        assert_eq!(d, 1, "day must be 1");
        assert_eq!(h, 0, "hour must be 0");
        assert_eq!(m, 0, "minute must be 0");
    }

    #[test]
    fn decompose_epoch_with_time() {
        // 2026-01-01 14:30:00 UTC = 1767225600 + 14*3600 + 30*60
        let epoch = 1_767_225_600 + 14 * 3600 + 30 * 60;
        let (h, m, _y, _mo, _d) = decompose_epoch(epoch);
        assert_eq!(h, 14, "hour must be 14");
        assert_eq!(m, 30, "minute must be 30");
    }

    #[test]
    fn format_time_produces_correct_output() {
        let buf = format_time(14, 5);
        assert_eq!(&buf, b"14:05", "format_time(14, 5) must produce '14:05'");

        let buf = format_time(0, 0);
        assert_eq!(&buf, b"00:00", "format_time(0, 0) must produce '00:00'");

        let buf = format_time(23, 59);
        assert_eq!(&buf, b"23:59", "format_time(23, 59) must produce '23:59'");
    }

    #[test]
    fn format_date_produces_correct_output() {
        let buf = format_date(2026, 4, 9);
        assert_eq!(&buf, b"2026-04-09", "format_date must produce '2026-04-09'");
    }

    #[test]
    fn format_unread_single_digit() {
        let buf = format_unread(3);
        assert_eq!(buf.as_str(), "3 UNREAD", "single digit unread");
    }

    #[test]
    fn format_unread_double_digit() {
        let buf = format_unread(42);
        assert_eq!(buf.as_str(), "42 UNREAD", "double digit unread");
    }

    #[test]
    fn format_unread_overflow() {
        let buf = format_unread(200);
        assert_eq!(buf.as_str(), "99+ UNREAD", "overflow must show 99+");
    }

    #[test]
    fn is_leap_year_correct() {
        assert!(is_leap_year(2000), "2000 is a leap year (div by 400)");
        assert!(!is_leap_year(1900), "1900 is not a leap year (div by 100)");
        assert!(is_leap_year(2024), "2024 is a leap year (div by 4)");
        assert!(!is_leap_year(2025), "2025 is not a leap year");
    }

    #[test]
    fn operating_mode_labels_correct() {
        assert_eq!(OperatingMode::Daily.label(), "DAILY");
        assert_eq!(OperatingMode::Sentinel.label(), "SENTINEL");
        assert_eq!(OperatingMode::Panic.label(), "PANIC");
    }

    #[test]
    fn operating_mode_colors_distinct() {
        let d = OperatingMode::Daily.color();
        let s = OperatingMode::Sentinel.color();
        let p = OperatingMode::Panic.color();
        assert_ne!(d, s, "Daily and Sentinel colors must differ");
        assert_ne!(s, p, "Sentinel and Panic colors must differ");
        assert_ne!(d, p, "Daily and Panic colors must differ");
    }

    #[test]
    fn scaled_char_draws_without_panic() {
        let mut fb = [0u16; 240 * 50];
        ui::draw_char_scaled(&mut fb, 240, 0, 0, '1', color::WHITE, color::BLACK, TIME_SCALE);
        let any_set = fb.iter().any(|&px| px != 0);
        assert!(any_set, "scaled character must produce visible pixels");
    }

    #[test]
    fn scaled_str_centered_draws_without_panic() {
        let mut fb = [0u16; 240 * 50];
        let time = format_time(12, 34);
        ui::draw_scaled_str_centered(&mut fb, 240, 0, &time, color::WHITE, color::BLACK, TIME_SCALE);
        let any_set = fb.iter().any(|&px| px != 0);
        assert!(any_set, "scaled time string must produce visible pixels");
    }
}
