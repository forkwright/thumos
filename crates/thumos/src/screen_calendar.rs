//! Calendar agenda screen for the thumos kernel UI.
//!
//! Displays upcoming calendar events sorted by start time and grouped by
//! day. Each day group shows a header ("TODAY 2026-04-11", "TOMORROW ...",
//! or the ISO date) followed by event entries with time and title.
//!
//! Active events (happening now) are marked with a bullet indicator.
//! The event list scrolls vertically with D-pad Up/Down. OK opens
//! event detail (future wave), LSK = "ADD" (future wave), RSK = "BACK".
//!
//! ## State model
//!
//! The screen receives a snapshot of calendar events and the current epoch
//! before each render cycle, avoiding references to kernel globals across
//! the render boundary.

// WHY: calendar screen created in Phase 07 Wave 7, kinit wiring pending.
#![expect(dead_code, reason = "Calendar screen created in Phase 07 Wave 7, kinit wiring pending")]

extern crate alloc;
use alloc::vec::Vec;

use crate::heorte::{self, HeorteManager};
use crate::ui::{
    self, color, Key, Screen, ScreenAction,
    CHAR_HEIGHT, CHAR_WIDTH, CONTENT_HEIGHT, SCREEN_WIDTH,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Left padding for all content.
const PADDING_X: u16 = 8;

/// Y offset for the first line of content.
const START_Y: u16 = 4;

/// Height of a day header row.
const HEADER_HEIGHT: u16 = CHAR_HEIGHT + 6;

/// Height of an event row (time + title on one line).
const EVENT_ROW_HEIGHT: u16 = CHAR_HEIGHT + 4;

/// Maximum visible rows in the content area.
const MAX_VISIBLE_ROWS: usize = 12;

/// Bullet character for active events.
const ACTIVE_BULLET: char = '*';

/// Separator line character.
const SEPARATOR_CHAR: u8 = b'-';

/// Number of separator characters across the display.
const SEPARATOR_LEN: usize = 28;

// ---------------------------------------------------------------------------
// Agenda row model
// ---------------------------------------------------------------------------

/// A row in the agenda view. Either a day header or an event entry.
#[derive(Debug, Clone)]
enum AgendaRow {
    /// Day group header (e.g., "TODAY 2026-04-11").
    DayHeader {
        /// Display label ("TODAY", "TOMORROW", or ISO date).
        label: heorte::DayLabel,
        /// ISO date string for display after the label.
        date: [u8; 10],
    },
    /// An event entry.
    Event {
        /// Event ID for selection.
        id: u32,
        /// Start time formatted as "HH:MM".
        time: [u8; 5],
        /// Title (first 24 chars to fit display).
        title: [u8; 24],
        /// Valid bytes in title.
        title_len: u8,
        /// Whether this event is currently active.
        active: bool,
    },
}

// ---------------------------------------------------------------------------
// Calendar screen
// ---------------------------------------------------------------------------

/// Agenda-view calendar screen.
pub struct CalendarScreen {
    /// Pre-built row list from the most recent event snapshot.
    rows: Vec<AgendaRow>,
    /// Currently highlighted row index.
    cursor: usize,
    /// Scroll offset for the visible window.
    scroll_offset: usize,
    /// Current epoch (for active-event detection and day labeling).
    current_epoch: u64,
}

impl CalendarScreen {
    /// Create a new calendar screen with no events.
    pub fn new() -> Self {
        Self {
            rows: Vec::new(),
            cursor: 0,
            scroll_offset: 0,
            current_epoch: 0,
        }
    }

    /// Update the screen with a fresh set of events and the current epoch.
    ///
    /// Rebuilds the agenda row list. Called each render cycle or when
    /// the event list changes.
    pub fn update(&mut self, manager: &HeorteManager, current_epoch: u64) {
        self.current_epoch = current_epoch;
        self.rows.clear();

        let upcoming = manager.upcoming_events(current_epoch);
        if upcoming.is_empty() {
            return;
        }

        let mut last_day_index: Option<u32> = None;

        for event in &upcoming {
            let day_idx = event.day_index();

            // Insert a day header if this event is in a new day group.
            if last_day_index != Some(day_idx) {
                last_day_index = Some(day_idx);
                let label = heorte::day_label(event.start_epoch, current_epoch);
                let (_, _, y, m, d) = heorte::decompose_epoch(event.start_epoch);
                let date = heorte::format_date(y, m, d);
                self.rows.push(AgendaRow::DayHeader { label, date });
            }

            // Build the event row.
            let (hour, minute, _, _, _) = heorte::decompose_epoch(event.start_epoch);
            let time = heorte::format_time_hhmm(hour, minute);

            let mut title = [0u8; 24];
            let tlen = (event.title_len as usize).min(24);
            title[..tlen].copy_from_slice(&event.title[..tlen]);

            self.rows.push(AgendaRow::Event {
                id: event.id,
                time,
                title,
                title_len: tlen as u8,
                active: event.is_active(current_epoch),
            });
        }

        // Clamp cursor and scroll.
        if self.cursor >= self.rows.len() {
            self.cursor = self.rows.len().saturating_sub(1);
        }
        self.adjust_scroll();
    }

    /// Adjust scroll offset so the cursor is visible.
    fn adjust_scroll(&mut self) {
        if self.cursor < self.scroll_offset {
            self.scroll_offset = self.cursor;
        } else if self.cursor >= self.scroll_offset + MAX_VISIBLE_ROWS {
            self.scroll_offset = self.cursor + 1 - MAX_VISIBLE_ROWS;
        }
    }

    /// Get the event ID at the current cursor position, if it points to an event row.
    fn selected_event_id(&self) -> Option<u32> {
        match self.rows.get(self.cursor) {
            Some(AgendaRow::Event { id, .. }) => Some(*id),
            _ => None,
        }
    }
}

impl Screen for CalendarScreen {
    fn draw(&self, fb: &mut [u16]) {
        let w = SCREEN_WIDTH;
        let h = CONTENT_HEIGHT;

        // Clear content area.
        ui::fill_rect(fb, w, h, 0, 0, w, h, color::BLACK);

        if self.rows.is_empty() {
            // Show empty state message.
            ui::draw_str_centered(
                fb, w, 0, w, h / 2 - CHAR_HEIGHT / 2,
                "No upcoming events",
                color::DARK_GREY, color::BLACK,
            );
            return;
        }

        let visible_end = (self.scroll_offset + MAX_VISIBLE_ROWS).min(self.rows.len());
        let mut y = START_Y;

        for vi in self.scroll_offset..visible_end {
            let is_selected = vi == self.cursor;

            match &self.rows[vi] {
                AgendaRow::DayHeader { label, date } => {
                    // Draw separator line before header (except first row).
                    if vi > 0 && y > START_Y {
                        let sep = [SEPARATOR_CHAR; SEPARATOR_LEN];
                        let sep_str = core::str::from_utf8(&sep).unwrap_or("");
                        ui::draw_str(fb, w, PADDING_X, y, sep_str, color::DARK_GREY, color::BLACK);
                        y += CHAR_HEIGHT + 2;
                    }

                    // Day label + date.
                    let label_str = label.as_str();
                    let date_str = core::str::from_utf8(date).unwrap_or("????-??-??");

                    let fg = color::YELLOW;
                    ui::draw_str(fb, w, PADDING_X, y, label_str, fg, color::BLACK);

                    // Show date after label if label is not already a date.
                    if matches!(label, heorte::DayLabel::Today | heorte::DayLabel::Tomorrow) {
                        let label_width = label_str.len() as u16 * CHAR_WIDTH;
                        ui::draw_str(
                            fb, w,
                            PADDING_X + label_width + CHAR_WIDTH,
                            y,
                            date_str,
                            color::DARK_GREY, color::BLACK,
                        );
                    }

                    y += HEADER_HEIGHT;
                }
                AgendaRow::Event { time, title, title_len, active, .. } => {
                    let (fg, bg) = if is_selected {
                        (color::BLACK, color::WHITE)
                    } else {
                        (color::WHITE, color::BLACK)
                    };

                    // Draw highlight background for selected row.
                    if is_selected {
                        ui::fill_rect(fb, w, h, 0, y, w, EVENT_ROW_HEIGHT, color::WHITE);
                    }

                    let mut x = PADDING_X;

                    // Active bullet.
                    if *active {
                        ui::draw_char(fb, w, x, y + 2, ACTIVE_BULLET, color::GREEN, bg);
                    }
                    x += CHAR_WIDTH + 2;

                    // Time.
                    let time_str = core::str::from_utf8(time).unwrap_or("??:??");
                    ui::draw_str(fb, w, x, y + 2, time_str, fg, bg);
                    x += 5 * CHAR_WIDTH + CHAR_WIDTH;

                    // Title.
                    let title_str = core::str::from_utf8(&title[..*title_len as usize])
                        .unwrap_or("");
                    ui::draw_str(fb, w, x, y + 2, title_str, fg, bg);

                    y += EVENT_ROW_HEIGHT;
                }
            }

            // Stop drawing if we've gone past the content area.
            if y >= h {
                break;
            }
        }
    }

    fn on_key(&mut self, key: Key) -> ScreenAction {
        match key {
            Key::Up => {
                if self.cursor > 0 {
                    self.cursor -= 1;
                    // Skip day headers when navigating.
                    while self.cursor > 0 && matches!(self.rows.get(self.cursor), Some(AgendaRow::DayHeader { .. })) {
                        self.cursor -= 1;
                    }
                    self.adjust_scroll();
                }
                ScreenAction::None
            }
            Key::Down => {
                if self.cursor < self.rows.len().saturating_sub(1) {
                    self.cursor += 1;
                    // Skip day headers when navigating.
                    while self.cursor < self.rows.len().saturating_sub(1)
                        && matches!(self.rows.get(self.cursor), Some(AgendaRow::DayHeader { .. }))
                    {
                        self.cursor += 1;
                    }
                    self.adjust_scroll();
                }
                ScreenAction::None
            }
            Key::Ok => {
                // Open event detail (future wave — for now, no-op).
                ScreenAction::None
            }
            Key::Lsk => {
                // ADD (future wave — for now, no-op).
                ScreenAction::None
            }
            Key::Rsk | Key::End => ScreenAction::Back,
            _ => ScreenAction::None,
        }
    }

    fn softkey_left(&self) -> &'static str {
        "ADD"
    }

    fn softkey_right(&self) -> &'static str {
        "BACK"
    }

    fn title(&self) -> &'static str {
        "Calendar"
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_manager_with_events() -> HeorteManager {
        let mut mgr = HeorteManager::new();
        // Events at different times. Using epoch values where day boundaries are clear.
        // Day 100 = epoch 8640000
        let day100 = 100 * 86400u64;
        mgr.add_event(b"Lunch", day100 + 12 * 3600, 60, false);
        mgr.add_event(b"Standup", day100 + 10 * 3600, 30, false);
        // Day 101 = epoch 8726400
        let day101 = 101 * 86400u64;
        mgr.add_event(b"Dentist", day101 + 9 * 3600, 60, false);
        mgr
    }

    #[test]
    fn agenda_sorts_by_time() {
        let mgr = make_manager_with_events();
        let mut screen = CalendarScreen::new();
        let current = 100 * 86400u64; // start of day 100
        screen.update(&mgr, current);

        // Should have rows: DayHeader(day100), Event(Standup), Event(Lunch),
        // DayHeader(day101), Event(Dentist)
        assert_eq!(screen.rows.len(), 5, "must have 5 rows (2 headers + 3 events)");

        // First event after day header should be Standup (10:00), not Lunch (12:00).
        match &screen.rows[1] {
            AgendaRow::Event { title, title_len, .. } => {
                let name = core::str::from_utf8(&title[..*title_len as usize]).unwrap_or("");
                assert_eq!(name, "Standup", "first event must be Standup (earlier time)");
            }
            _ => panic!("row 1 must be an event"),
        }
    }

    #[test]
    fn softkeys_correct() {
        let screen = CalendarScreen::new();
        assert_eq!(screen.softkey_left(), "ADD", "LSK must be ADD");
        assert_eq!(screen.softkey_right(), "BACK", "RSK must be BACK");
        assert_eq!(screen.title(), "Calendar", "title must be Calendar");
    }

    #[test]
    fn rsk_goes_back() {
        let mut screen = CalendarScreen::new();
        let action = screen.on_key(Key::Rsk);
        assert_eq!(action, ScreenAction::Back, "RSK must go back");
    }

    #[test]
    fn end_goes_back() {
        let mut screen = CalendarScreen::new();
        let action = screen.on_key(Key::End);
        assert_eq!(action, ScreenAction::Back, "End key must go back");
    }

    #[test]
    fn empty_state_draws() {
        let screen = CalendarScreen::new();
        let mut fb = [0u16; SCREEN_WIDTH as usize * CONTENT_HEIGHT as usize];
        screen.draw(&mut fb);
        // Should render the "No upcoming events" message.
        let any_set = fb.iter().any(|&px| px != 0);
        assert!(any_set, "empty calendar must render placeholder text");
    }

    #[test]
    fn cursor_navigation_skips_headers() {
        let mgr = make_manager_with_events();
        let mut screen = CalendarScreen::new();
        let current = 100 * 86400u64;
        screen.update(&mgr, current);

        // Initial cursor should be at 0 (day header).
        // Navigate down — should skip header and land on first event.
        screen.on_key(Key::Down);
        assert!(
            matches!(screen.rows.get(screen.cursor), Some(AgendaRow::Event { .. })),
            "cursor must skip to event row"
        );
    }

    #[test]
    fn draw_with_events_does_not_panic() {
        let mgr = make_manager_with_events();
        let mut screen = CalendarScreen::new();
        let current = 100 * 86400u64 + 10 * 3600 + 900; // during standup
        screen.update(&mgr, current);

        let mut fb = [0u16; SCREEN_WIDTH as usize * CONTENT_HEIGHT as usize];
        screen.draw(&mut fb);
        let any_set = fb.iter().any(|&px| px != 0);
        assert!(any_set, "calendar with events must render visible content");
    }

    #[test]
    fn active_event_detected() {
        let mgr = make_manager_with_events();
        let mut screen = CalendarScreen::new();
        // During standup (10:00 + 15min)
        let current = 100 * 86400u64 + 10 * 3600 + 900;
        screen.update(&mgr, current);

        // Find the standup event row and check active flag.
        let has_active = screen.rows.iter().any(|r| matches!(r, AgendaRow::Event { active: true, .. }));
        assert!(has_active, "standup event must be marked active");
    }
}
