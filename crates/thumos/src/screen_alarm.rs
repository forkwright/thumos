//! Alarm, timer, and stopwatch screens for the thumos kernel UI.
//!
//! Combined screen with three tabs navigable via Left/Right:
//!
//! - **Tab 1 (Alarms)**: list of alarms with enabled/disabled toggle
//! - **Tab 2 (Timer)**: countdown timer with set duration, start/stop/reset
//! - **Tab 3 (Stopwatch)**: elapsed time with lap recording
//!
//! Timer displays as large `MM:SS` countdown. Stopwatch displays as
//! large `HH:MM:SS.mmm`. Both use the kernel tick count passed via
//! state updates.

// WHY: renderable screen exists, but kinit currently renders only the home
// frame and has no alarm/timer route/input path.
#![expect(
    dead_code,
    reason = "Alarm screen is not wired into the service-loop UI route (#753)"
)]

extern crate alloc;
use alloc::vec::Vec;

use crate::heorte::{self, HeorteManager};
use crate::ui::{
    self, CHAR_HEIGHT, CHAR_WIDTH, CONTENT_HEIGHT, Key, SCREEN_WIDTH, Screen, ScreenAction, color,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Left padding for content.
const PADDING_X: u16 = 8;

/// Y offset where tab content begins (below tab bar).
const CONTENT_START_Y: u16 = 28;

/// Height of the tab indicator bar.
const TAB_BAR_HEIGHT: u16 = 22;

/// Height of each alarm list row.
const ALARM_ROW_HEIGHT: u16 = CHAR_HEIGHT + 8;

/// Y offset for the large timer/stopwatch display.
const BIG_DISPLAY_Y: u16 = 70;

/// Y offset for status text below the large display.
const STATUS_Y: u16 = BIG_DISPLAY_Y + CHAR_HEIGHT * 2 + 12;

/// Y offset for the "set:" label on the timer tab.
const SET_LABEL_Y: u16 = STATUS_Y + CHAR_HEIGHT + 8;

/// Y offset for the "LAPS" header on the stopwatch tab.
const LAPS_HEADER_Y: u16 = STATUS_Y + CHAR_HEIGHT + 8;

/// Y offset for the first lap entry.
const LAPS_START_Y: u16 = LAPS_HEADER_Y + CHAR_HEIGHT + 4;

/// Maximum visible alarm rows.
const MAX_ALARM_ROWS: usize = 10;

/// Maximum visible lap rows.
const MAX_LAP_ROWS: usize = 5;

/// Scale factor for large timer/stopwatch display.
const BIG_SCALE: u16 = 2;

/// Tab labels.
const TAB_LABELS: [&str; 3] = ["ALARMS", "TIMER", "STOPWCH"];

// ---------------------------------------------------------------------------
// Tab state
// ---------------------------------------------------------------------------

/// Active tab index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tab {
    Alarms = 0,
    Timer = 1,
    Stopwatch = 2,
}

impl Tab {
    /// Cycle to the next tab (wrapping).
    fn next(self) -> Self {
        match self {
            Self::Alarms => Self::Timer,
            Self::Timer => Self::Stopwatch,
            Self::Stopwatch => Self::Alarms,
        }
    }

    /// Cycle to the previous tab (wrapping).
    fn prev(self) -> Self {
        match self {
            Self::Alarms => Self::Stopwatch,
            Self::Timer => Self::Alarms,
            Self::Stopwatch => Self::Timer,
        }
    }
}

// ---------------------------------------------------------------------------
// Alarm screen snapshot
// ---------------------------------------------------------------------------

/// Snapshot of a single alarm for display.
#[derive(Debug, Clone)]
struct AlarmEntry {
    /// Alarm ID.
    id: u32,
    /// Formatted time "HH:MM".
    time: [u8; 5],
    /// Label string.
    label: [u8; 32],
    /// Valid bytes in label.
    label_len: u8,
    /// Whether the alarm is enabled.
    enabled: bool,
    /// Repeat description.
    repeat_label: &'static str,
}

// ---------------------------------------------------------------------------
// Alarm screen
// ---------------------------------------------------------------------------

/// Combined alarm/timer/stopwatch screen.
pub(crate) struct AlarmScreen {
    // kanon:ignore RUST/struct-too-many-fields -- three sub-modes (alarm/timer/stopwatch) share one screen; splitting would require three parallel screens + a dispatcher
    /// Active tab.
    tab: Tab,
    /// Alarm entries snapshot.
    alarm_entries: Vec<AlarmEntry>,
    /// Cursor position within the alarm list.
    alarm_cursor: usize,
    /// Scroll offset for the alarm list.
    alarm_scroll: usize,
    /// Current kernel tick (ms) for timer/stopwatch computation.
    current_tick: u64,
    /// Cached timer remaining display.
    timer_display: [u8; 5],
    /// Whether timer is running.
    timer_running: bool,
    /// Whether timer has expired.
    timer_expired: bool,
    /// Timer set duration display.
    timer_set_display: [u8; 5],
    /// Cached stopwatch elapsed display.
    stopwatch_display: [u8; 12],
    /// Whether stopwatch is running.
    stopwatch_running: bool,
    /// Cached lap display data.
    lap_entries: Vec<(usize, [u8; 9])>,
    /// Scroll offset for lap list.
    lap_scroll: usize,
}

impl AlarmScreen {
    /// Create a new alarm screen.
    pub(crate) fn new() -> Self {
        Self {
            tab: Tab::Alarms,
            alarm_entries: Vec::new(),
            alarm_cursor: 0,
            alarm_scroll: 0,
            current_tick: 0,
            timer_display: *b"00:00",
            timer_running: false,
            timer_expired: false,
            timer_set_display: *b"00:00",
            stopwatch_display: *b"00:00:00.000",
            stopwatch_running: false,
            lap_entries: Vec::new(),
            lap_scroll: 0,
        }
    }

    /// Update the screen state from the heorte manager.
    ///
    /// Called each render cycle to refresh alarm list, timer state,
    /// and stopwatch state.
    pub(crate) fn update(&mut self, manager: &HeorteManager, current_tick: u64) {
        self.current_tick = current_tick;

        // Refresh alarm entries.
        self.alarm_entries.clear();
        for alarm in manager.alarms() {
            self.alarm_entries.push(AlarmEntry {
                id: alarm.id,
                time: heorte::format_time_hhmm(alarm.hour, alarm.minute),
                label: alarm.label,
                label_len: alarm.label_len,
                enabled: alarm.enabled,
                repeat_label: alarm.repeat_label(),
            });
        }
        if self.alarm_cursor >= self.alarm_entries.len() {
            self.alarm_cursor = self.alarm_entries.len().saturating_sub(1);
        }

        // Refresh timer display.
        let timer = manager.timer();
        self.timer_display = timer.format_remaining();
        self.timer_running = timer.running;
        self.timer_expired = timer.expired();
        // Set duration display.
        let set_m = (timer.duration_secs / 60).min(99);
        let set_s = timer.duration_secs % 60;
        self.timer_set_display = [
            b'0' + (set_m / 10) as u8,
            b'0' + (set_m % 10) as u8,
            b':',
            b'0' + (set_s / 10) as u8,
            b'0' + (set_s % 10) as u8,
        ];

        // Refresh stopwatch display.
        let sw = manager.stopwatch();
        self.stopwatch_display = sw.format_elapsed(current_tick);
        self.stopwatch_running = sw.running;

        // Refresh lap entries.
        self.lap_entries.clear();
        for (num, dur_ms) in sw.lap_durations() {
            let formatted = format_lap_compact(dur_ms);
            self.lap_entries.push((num, formatted));
        }
    }

    /// Adjust alarm list scroll offset.
    fn adjust_alarm_scroll(&mut self) {
        if self.alarm_cursor < self.alarm_scroll {
            self.alarm_scroll = self.alarm_cursor;
        } else if self.alarm_cursor >= self.alarm_scroll + MAX_ALARM_ROWS {
            self.alarm_scroll = self.alarm_cursor + 1 - MAX_ALARM_ROWS;
        }
    }

    /// Draw the tab bar at the top of the content area.
    fn draw_tab_bar(&self, fb: &mut [u16]) {
        let w = SCREEN_WIDTH;
        let h = CONTENT_HEIGHT;

        // Background for tab bar.
        ui::fill_rect(fb, w, h, 0, 0, w, TAB_BAR_HEIGHT, color::BLACK);

        // Draw each tab label.
        let tab_width = w / 3;
        for (i, &label) in TAB_LABELS.iter().enumerate() {
            let x = i as u16 * tab_width;
            let is_active = i == self.tab as usize;

            let (fg, bg) = if is_active {
                (color::BLACK, color::WHITE)
            } else {
                (color::DARK_GREY, color::BLACK)
            };

            if is_active {
                ui::fill_rect(fb, w, h, x, 0, tab_width, TAB_BAR_HEIGHT, color::WHITE);
            }

            // Center label within tab segment.
            let label_w = label.len() as u16 * CHAR_WIDTH;
            let label_x = x + (tab_width.saturating_sub(label_w)) / 2;
            ui::draw_str(fb, w, label_x, 3, label, fg, bg);
        }
    }

    /// Draw the alarms tab content.
    fn draw_alarms(&self, fb: &mut [u16]) {
        let w = SCREEN_WIDTH;
        let h = CONTENT_HEIGHT;

        if self.alarm_entries.is_empty() {
            ui::draw_str_centered(
                fb,
                w,
                0,
                w,
                CONTENT_START_Y + 40,
                "No alarms set",
                color::DARK_GREY,
                color::BLACK,
            );
            return;
        }

        let visible_end = (self.alarm_scroll + MAX_ALARM_ROWS).min(self.alarm_entries.len());
        for (vi, ai) in (self.alarm_scroll..visible_end).enumerate() {
            let entry = &self.alarm_entries[ai];
            let row_y = CONTENT_START_Y + (vi as u16) * ALARM_ROW_HEIGHT;
            let is_selected = ai == self.alarm_cursor;

            let (fg, bg) = if is_selected {
                (color::BLACK, color::WHITE)
            } else {
                (color::WHITE, color::BLACK)
            };

            if is_selected {
                ui::fill_rect(fb, w, h, 0, row_y, w, ALARM_ROW_HEIGHT, color::WHITE);
            }

            let mut x = PADDING_X;

            // Enabled indicator.
            let indicator = if entry.enabled { '*' } else { ' ' };
            let indicator_color = if entry.enabled {
                if is_selected {
                    color::from_rgb(0, 160, 0)
                } else {
                    color::GREEN
                }
            } else {
                fg
            };
            ui::draw_char(fb, w, x, row_y + 4, indicator, indicator_color, bg);
            x += CHAR_WIDTH + 2;

            // Time.
            let time_str = core::str::from_utf8(&entry.time).unwrap_or("??:??");
            ui::draw_str(fb, w, x, row_y + 4, time_str, fg, bg);
            x += 6 * CHAR_WIDTH;

            // Repeat label.
            ui::draw_str(fb, w, x, row_y + 4, entry.repeat_label, fg, bg);
        }
    }

    /// Draw the timer tab content.
    fn draw_timer(&self, fb: &mut [u16]) {
        let w = SCREEN_WIDTH;

        // Large countdown display (centered, scaled text).
        ui::draw_scaled_str_centered(
            fb,
            w,
            BIG_DISPLAY_Y,
            &self.timer_display,
            color::WHITE,
            color::BLACK,
            BIG_SCALE,
        );

        // Status text.
        let status = if self.timer_expired {
            "EXPIRED"
        } else if self.timer_running {
            "RUNNING"
        } else if self.timer_display == *b"00:00" {
            "SET TIME"
        } else {
            "PAUSED"
        };
        let status_color = if self.timer_expired {
            color::RED
        } else if self.timer_running {
            color::GREEN
        } else {
            color::DARK_GREY
        };
        ui::draw_str_centered(fb, w, 0, w, STATUS_Y, status, status_color, color::BLACK);

        // Set duration label.
        let set_str = core::str::from_utf8(&self.timer_set_display).unwrap_or("??:??");
        ui::draw_str(
            fb,
            w,
            PADDING_X,
            SET_LABEL_Y,
            "set: ",
            color::DARK_GREY,
            color::BLACK,
        );
        ui::draw_str(
            fb,
            w,
            PADDING_X + 5 * CHAR_WIDTH,
            SET_LABEL_Y,
            set_str,
            color::WHITE,
            color::BLACK,
        );
    }

    /// Draw the stopwatch tab content.
    fn draw_stopwatch(&self, fb: &mut [u16]) {
        let w = SCREEN_WIDTH;

        // Large elapsed display (centered, scaled text).
        ui::draw_scaled_str_centered(
            fb,
            w,
            BIG_DISPLAY_Y,
            &self.stopwatch_display,
            color::WHITE,
            color::BLACK,
            BIG_SCALE,
        );

        // Status.
        let status = if self.stopwatch_running {
            "RUNNING"
        } else {
            "STOPPED"
        };
        let status_color = if self.stopwatch_running {
            color::GREEN
        } else {
            color::DARK_GREY
        };
        ui::draw_str_centered(fb, w, 0, w, STATUS_Y, status, status_color, color::BLACK);

        // Laps header.
        if !self.lap_entries.is_empty() {
            ui::draw_str(
                fb,
                w,
                PADDING_X,
                LAPS_HEADER_Y,
                "LAPS",
                color::YELLOW,
                color::BLACK,
            );

            let visible_end = (self.lap_scroll + MAX_LAP_ROWS).min(self.lap_entries.len());
            for (vi, li) in (self.lap_scroll..visible_end).enumerate() {
                let (num, ref formatted) = self.lap_entries[li];
                let row_y = LAPS_START_Y + (vi as u16) * (CHAR_HEIGHT + 2);

                // Lap number.
                let mut num_buf = [0u8; 4];
                let num_len = format_u16_into(num as u16, &mut num_buf);
                let num_str = core::str::from_utf8(&num_buf[..num_len]).unwrap_or("?");
                ui::draw_str(
                    fb,
                    w,
                    PADDING_X,
                    row_y,
                    num_str,
                    color::DARK_GREY,
                    color::BLACK,
                );

                // Lap duration.
                let dur_str = core::str::from_utf8(formatted).unwrap_or("??:??.???");
                ui::draw_str(
                    fb,
                    w,
                    PADDING_X + 4 * CHAR_WIDTH,
                    row_y,
                    dur_str,
                    color::WHITE,
                    color::BLACK,
                );
            }
        }
    }
}

impl Screen for AlarmScreen {
    fn draw(&self, fb: &mut [u16]) {
        let w = SCREEN_WIDTH;
        let h = CONTENT_HEIGHT;

        // Clear entire content area.
        ui::fill_rect(fb, w, h, 0, 0, w, h, color::BLACK);

        // Tab bar.
        self.draw_tab_bar(fb);

        // Tab content.
        match self.tab {
            Tab::Alarms => self.draw_alarms(fb),
            Tab::Timer => self.draw_timer(fb),
            Tab::Stopwatch => self.draw_stopwatch(fb),
        }
    }

    fn on_key(&mut self, key: Key) -> ScreenAction {
        match key {
            // Tab navigation.
            Key::Left => {
                self.tab = self.tab.prev();
                ScreenAction::None
            }
            Key::Right => {
                self.tab = self.tab.next();
                ScreenAction::None
            }
            // Tab-specific key handling.
            Key::Up => {
                match self.tab {
                    Tab::Alarms => {
                        if self.alarm_cursor > 0 {
                            self.alarm_cursor -= 1;
                            self.adjust_alarm_scroll();
                        }
                    }
                    Tab::Stopwatch => {
                        if self.lap_scroll > 0 {
                            self.lap_scroll -= 1;
                        }
                    }
                    Tab::Timer => {}
                }
                ScreenAction::None
            }
            Key::Down => {
                match self.tab {
                    Tab::Alarms => {
                        if self.alarm_cursor < self.alarm_entries.len().saturating_sub(1) {
                            self.alarm_cursor += 1;
                            self.adjust_alarm_scroll();
                        }
                    }
                    Tab::Stopwatch => {
                        if self.lap_scroll + MAX_LAP_ROWS < self.lap_entries.len() {
                            self.lap_scroll += 1;
                        }
                    }
                    Tab::Timer => {}
                }
                ScreenAction::None
            }
            Key::Ok => {
                // Context-dependent:
                // Alarms: toggle selected alarm (handled by caller via selected_alarm_id)
                // Timer: start/pause toggle (handled by caller)
                // Stopwatch: lap (handled by caller)
                ScreenAction::None
            }
            Key::Lsk => {
                // Context-dependent:
                // Alarms: ADD (future wave)
                // Timer: RESET (handled by caller)
                // Stopwatch: RESET (handled by caller)
                ScreenAction::None
            }
            Key::Rsk | Key::End => ScreenAction::Back,
            _ => ScreenAction::None,
        }
    }

    fn softkey_left(&self) -> &'static str {
        match self.tab {
            Tab::Alarms => "ADD",
            Tab::Timer | Tab::Stopwatch => "RESET",
        }
    }

    fn softkey_right(&self) -> &'static str {
        "BACK"
    }

    fn title(&self) -> &'static str {
        ""
    }
}

/// Public accessors for caller integration.
impl AlarmScreen {
    /// Get the active tab.
    pub(crate) fn active_tab_index(&self) -> usize {
        self.tab as usize
    }

    /// Get the alarm ID at the current cursor (if on Alarms tab).
    pub(crate) fn selected_alarm_id(&self) -> Option<u32> {
        if self.tab != Tab::Alarms {
            return None;
        }
        self.alarm_entries.get(self.alarm_cursor).map(|e| e.id)
    }

    /// Whether the timer tab is active.
    pub(crate) fn is_timer_tab(&self) -> bool {
        self.tab == Tab::Timer
    }

    /// Whether the stopwatch tab is active.
    pub(crate) fn is_stopwatch_tab(&self) -> bool {
        self.tab == Tab::Stopwatch
    }
}

// ---------------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------------

/// Format milliseconds as compact `MM:SS.mmm` for lap display.
fn format_lap_compact(ms: u64) -> [u8; 9] {
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

/// Format a u16 into a byte buffer. Returns the number of bytes written.
fn format_u16_into(val: u16, buf: &mut [u8; 4]) -> usize {
    if val >= 1000 {
        buf[0] = b'0' + (val / 1000) as u8;
        buf[1] = b'0' + ((val / 100) % 10) as u8;
        buf[2] = b'0' + ((val / 10) % 10) as u8;
        buf[3] = b'0' + (val % 10) as u8;
        4
    } else if val >= 100 {
        buf[0] = b'0' + (val / 100) as u8;
        buf[1] = b'0' + ((val / 10) % 10) as u8;
        buf[2] = b'0' + (val % 10) as u8;
        3
    } else if val >= 10 {
        buf[0] = b'0' + (val / 10) as u8;
        buf[1] = b'0' + (val % 10) as u8;
        2
    } else {
        buf[0] = b'0' + val as u8;
        1
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heorte::day_mask;

    fn make_manager_with_alarms() -> HeorteManager {
        let mut mgr = HeorteManager::new();
        mgr.add_alarm(6, 30, b"Wake up", true, day_mask::WEEKDAYS);
        mgr.add_alarm(22, 0, b"Medication", true, day_mask::DAILY);
        mgr.add_alarm(14, 30, b"Meeting", false, 0);
        mgr
    }

    #[test]
    fn tab_navigation_works() {
        let mut screen = AlarmScreen::new();
        assert_eq!(screen.tab, Tab::Alarms, "initial tab must be Alarms");

        screen.on_key(Key::Right);
        assert_eq!(screen.tab, Tab::Timer, "Right must go to Timer");

        screen.on_key(Key::Right);
        assert_eq!(screen.tab, Tab::Stopwatch, "Right must go to Stopwatch");

        screen.on_key(Key::Right);
        assert_eq!(screen.tab, Tab::Alarms, "Right must wrap to Alarms");

        screen.on_key(Key::Left);
        assert_eq!(screen.tab, Tab::Stopwatch, "Left must wrap to Stopwatch");
    }

    #[test]
    fn timer_display_formats_mmss() {
        let mut mgr = HeorteManager::new();
        mgr.timer_mut().set_duration(332); // 5:32
        let mut screen = AlarmScreen::new();
        screen.tab = Tab::Timer;
        screen.update(&mgr, 0);

        assert_eq!(&screen.timer_display, b"05:32", "timer must show 05:32");
        assert_eq!(
            &screen.timer_set_display, b"05:32",
            "set display must show 05:32"
        );
    }

    #[test]
    fn timer_display_running() {
        let mut mgr = HeorteManager::new();
        mgr.timer_mut().set_duration(60);
        mgr.timer_mut().start(0);
        mgr.timer_mut().update(10_000); // 10 seconds elapsed

        let mut screen = AlarmScreen::new();
        screen.tab = Tab::Timer;
        screen.update(&mgr, 10_000);

        assert!(screen.timer_running, "timer must be running");
        assert_eq!(
            &screen.timer_display, b"00:50",
            "must show 50 seconds remaining"
        );
    }

    #[test]
    fn stopwatch_display_formats() {
        let mut mgr = HeorteManager::new();
        mgr.stopwatch_mut().start(0);
        mgr.stopwatch_mut().stop(754_567); // 12 min 34 sec 567 ms

        let mut screen = AlarmScreen::new();
        screen.tab = Tab::Stopwatch;
        screen.update(&mgr, 754_567);

        let s = core::str::from_utf8(&screen.stopwatch_display).unwrap_or("");
        assert_eq!(s, "00:12:34.567", "stopwatch must show elapsed time");
    }

    #[test]
    fn alarm_list_renders() {
        let mgr = make_manager_with_alarms();
        let mut screen = AlarmScreen::new();
        screen.update(&mgr, 0);

        assert_eq!(screen.alarm_entries.len(), 3, "must have 3 alarm entries");

        let mut fb = alloc::vec![0u16; SCREEN_WIDTH as usize * CONTENT_HEIGHT as usize];
        screen.draw(&mut fb);
        let any_set = fb.iter().any(|&px| px != 0);
        assert!(any_set, "alarm list must render visible content");
    }

    #[test]
    fn alarm_cursor_navigation() {
        let mgr = make_manager_with_alarms();
        let mut screen = AlarmScreen::new();
        screen.update(&mgr, 0);

        assert_eq!(screen.alarm_cursor, 0);
        screen.on_key(Key::Down);
        assert_eq!(screen.alarm_cursor, 1, "Down must advance alarm cursor");
        screen.on_key(Key::Down);
        assert_eq!(screen.alarm_cursor, 2);
        screen.on_key(Key::Down); // at last item, should stay
        assert_eq!(screen.alarm_cursor, 2, "cursor must not go past last");
        screen.on_key(Key::Up);
        assert_eq!(screen.alarm_cursor, 1, "Up must go back");
    }

    #[test]
    fn softkeys_per_tab() {
        let mut screen = AlarmScreen::new();

        screen.tab = Tab::Alarms;
        assert_eq!(screen.softkey_left(), "ADD");
        assert_eq!(screen.softkey_right(), "BACK");

        screen.tab = Tab::Timer;
        assert_eq!(screen.softkey_left(), "RESET");

        screen.tab = Tab::Stopwatch;
        assert_eq!(screen.softkey_left(), "RESET");
    }

    #[test]
    fn rsk_goes_back() {
        let mut screen = AlarmScreen::new();
        let action = screen.on_key(Key::Rsk);
        assert_eq!(action, ScreenAction::Back, "RSK must go back");
    }

    #[test]
    fn end_goes_back() {
        let mut screen = AlarmScreen::new();
        let action = screen.on_key(Key::End);
        assert_eq!(action, ScreenAction::Back, "End key must go back");
    }

    #[test]
    fn timer_tab_draws() {
        let mut mgr = HeorteManager::new();
        mgr.timer_mut().set_duration(300);

        let mut screen = AlarmScreen::new();
        screen.tab = Tab::Timer;
        screen.update(&mgr, 0);

        let mut fb = alloc::vec![0u16; SCREEN_WIDTH as usize * CONTENT_HEIGHT as usize];
        screen.draw(&mut fb);
        let any_set = fb.iter().any(|&px| px != 0);
        assert!(any_set, "timer tab must render visible content");
    }

    #[test]
    fn stopwatch_tab_draws() {
        let mut screen = AlarmScreen::new();
        screen.tab = Tab::Stopwatch;

        let mut fb = alloc::vec![0u16; SCREEN_WIDTH as usize * CONTENT_HEIGHT as usize];
        screen.draw(&mut fb);
        let any_set = fb.iter().any(|&px| px != 0);
        assert!(any_set, "stopwatch tab must render visible content");
    }

    #[test]
    fn stopwatch_laps_display() {
        let mut mgr = HeorteManager::new();
        mgr.stopwatch_mut().start(0);
        mgr.stopwatch_mut().lap(3_000);
        mgr.stopwatch_mut().lap(7_000);
        mgr.stopwatch_mut().stop(10_000);

        let mut screen = AlarmScreen::new();
        screen.tab = Tab::Stopwatch;
        screen.update(&mgr, 10_000);

        assert_eq!(screen.lap_entries.len(), 2, "must have 2 lap entries");
        // Lap 1: 3000ms = 00:03.000
        let lap1_str = core::str::from_utf8(&screen.lap_entries[0].1).unwrap_or("");
        assert_eq!(lap1_str, "00:03.000");
    }

    #[test]
    fn format_u16_into_works() {
        let mut buf = [0u8; 4];
        assert_eq!(format_u16_into(0, &mut buf), 1);
        assert_eq!(&buf[..1], b"0");

        assert_eq!(format_u16_into(42, &mut buf), 2);
        assert_eq!(&buf[..2], b"42");

        assert_eq!(format_u16_into(999, &mut buf), 3);
        assert_eq!(&buf[..3], b"999");

        assert_eq!(format_u16_into(1234, &mut buf), 4);
        assert_eq!(&buf[..4], b"1234");
    }

    #[test]
    fn format_lap_compact_works() {
        let buf = format_lap_compact(3 * 60 * 1000 + 21 * 1000 + 443);
        let s = core::str::from_utf8(&buf).unwrap_or("");
        assert_eq!(s, "03:21.443");
    }

    #[test]
    fn empty_alarm_list_draws() {
        let mgr = HeorteManager::new();
        let mut screen = AlarmScreen::new();
        screen.update(&mgr, 0);

        let mut fb = alloc::vec![0u16; SCREEN_WIDTH as usize * CONTENT_HEIGHT as usize];
        screen.draw(&mut fb);
        let any_set = fb.iter().any(|&px| px != 0);
        assert!(any_set, "empty alarm list must render placeholder text");
    }

    #[test]
    fn selected_alarm_id_works() {
        let mgr = make_manager_with_alarms();
        let mut screen = AlarmScreen::new();
        screen.update(&mgr, 0);

        // On alarms tab, cursor at 0.
        let id = screen.selected_alarm_id();
        assert!(id.is_some(), "must have selected alarm ID");

        // Switch to timer tab.
        screen.tab = Tab::Timer;
        let id = screen.selected_alarm_id();
        assert!(id.is_none(), "timer tab must not return alarm ID");
    }
}
