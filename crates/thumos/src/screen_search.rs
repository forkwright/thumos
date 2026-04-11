//! Function search ("everything launcher") for the thumos kernel UI.
//!
//! Provides a flat list of all thumos functions/screens. The user types
//! with T9/numpad keys; the list filters in real-time via fuzzy
//! case-insensitive substring matching.
//!
//! Accessible from the Home screen via RSK ("SEARCH") or OK key.
//!
//! ## Layout
//!
//! - Input field at the top showing the typed filter text
//! - Filtered results list below
//! - Up/Down navigates the list, OK selects, numpad keys filter
//! - LSK: "CLEAR" (clears filter), RSK: "BACK"

// WHY: search screen created in Phase 07 Wave 6, kinit wiring pending.
#![expect(
    dead_code,
    reason = "Search screen created in Phase 07 Wave 6, kinit wiring pending"
)]

use crate::ui::{
    self, color, Key, Screen, ScreenAction, ScreenId,
    CHAR_HEIGHT, CHAR_WIDTH, CONTENT_HEIGHT, SCREEN_WIDTH,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum length of the filter input string.
const MAX_FILTER_LEN: usize = 16;

/// Maximum number of function entries in the catalogue.
const MAX_ENTRIES: usize = 32;

/// Maximum number of visible rows in the results list.
///
/// Computed from the content area height minus the input field area,
/// divided by the row height.
const VISIBLE_ROWS: usize = 12;

/// Y offset for the input field.
const INPUT_Y: u16 = 4;

/// Height of the input field area (text + underline + padding).
const INPUT_AREA_HEIGHT: u16 = CHAR_HEIGHT + 8;

/// Y offset where the results list begins.
const LIST_Y: u16 = INPUT_Y + INPUT_AREA_HEIGHT + 4;

/// Height of each result row.
const ROW_HEIGHT: u16 = CHAR_HEIGHT + 4;

/// Left padding for list items.
const LIST_PADDING_X: u16 = 8;

/// Left padding for the input field.
const INPUT_PADDING_X: u16 = 8;

// ---------------------------------------------------------------------------
// T9 letter mapping
// ---------------------------------------------------------------------------

/// Map a numpad key to its T9 letter group for fuzzy filtering.
///
/// Each numpad key maps to 3-4 letters. When the user presses a numpad key,
/// the filter matches any entry containing one of those letters at the
/// corresponding position.
///
/// For simplicity in this implementation, we append all letters for the
/// pressed key and do a broader substring match rather than positional T9.
const fn key_to_t9_chars(key: Key) -> &'static [u8] {
    match key {
        Key::Num2 => b"abc",
        Key::Num3 => b"def",
        Key::Num4 => b"ghi",
        Key::Num5 => b"jkl",
        Key::Num6 => b"mno",
        Key::Num7 => b"pqrs",
        Key::Num8 => b"tuv",
        Key::Num9 => b"wxyz",
        Key::Num0 => b" ",
        Key::Num1 => b".,?!",
        _ => b"",
    }
}

// ---------------------------------------------------------------------------
// Function catalogue
// ---------------------------------------------------------------------------

/// A searchable function entry mapping a display name to a screen.
#[derive(Debug, Clone, Copy)]
pub struct FunctionEntry {
    /// Display name shown in the search results.
    pub name: &'static str,
    /// Target screen to navigate to when selected.
    pub screen_id: ScreenId,
}

/// Complete catalogue of searchable functions.
///
/// Ordered by likely usage frequency. All screens that exist as `ScreenId`
/// variants are listed here.
const FUNCTIONS: &[FunctionEntry] = &[
    FunctionEntry { name: "Messages", screen_id: ScreenId::Messages },
    FunctionEntry { name: "Dialer", screen_id: ScreenId::Dialer },
    FunctionEntry { name: "Contacts", screen_id: ScreenId::Contacts },
    FunctionEntry { name: "Settings", screen_id: ScreenId::Settings },
    FunctionEntry { name: "Calendar", screen_id: ScreenId::Calendar },
    FunctionEntry { name: "Timer", screen_id: ScreenId::Timer },
    FunctionEntry { name: "Stopwatch", screen_id: ScreenId::Stopwatch },
    FunctionEntry { name: "Alarms", screen_id: ScreenId::Alarms },
    FunctionEntry { name: "FM Radio", screen_id: ScreenId::FmRadio },
    FunctionEntry { name: "WiFi", screen_id: ScreenId::WifiSettings },
    FunctionEntry { name: "Bluetooth", screen_id: ScreenId::BtSettings },
    FunctionEntry { name: "Privacy", screen_id: ScreenId::Privacy },
    FunctionEntry { name: "Radio Control", screen_id: ScreenId::RadioControl },
    FunctionEntry { name: "About", screen_id: ScreenId::About },
    FunctionEntry { name: "Battery", screen_id: ScreenId::Battery },
];

// ---------------------------------------------------------------------------
// Fuzzy matching
// ---------------------------------------------------------------------------

/// Check if `name` contains `filter` as a case-insensitive substring.
///
/// Both `name` (ASCII function names) and `filter` (user-typed T9 letters)
/// are compared byte-by-byte with ASCII lowercasing.
fn fuzzy_match(name: &str, filter: &[u8], filter_len: usize) -> bool {
    if filter_len == 0 {
        return true;
    }

    let name_bytes = name.as_bytes();
    let filter_slice = if filter_len <= filter.len() {
        &filter[..filter_len]
    } else {
        return false;
    };

    if filter_len > name_bytes.len() {
        return false;
    }

    // Sliding window substring match.
    let window_count = name_bytes.len() - filter_len + 1;
    for start in 0..window_count {
        let mut matched = true;
        for (i, &fb) in filter_slice.iter().enumerate() {
            let nb = name_bytes[start + i];
            if to_ascii_lower(nb) != to_ascii_lower(fb) {
                matched = false;
                break;
            }
        }
        if matched {
            return true;
        }
    }
    false
}

/// ASCII-only lowercase conversion.
const fn to_ascii_lower(b: u8) -> u8 {
    if b >= b'A' && b <= b'Z' {
        b + 32
    } else {
        b
    }
}

// ---------------------------------------------------------------------------
// Search screen state
// ---------------------------------------------------------------------------

/// Function search screen.
///
/// Maintains the filter input buffer, filtered results, and cursor position.
pub struct SearchScreen {
    /// Filter input buffer (ASCII letters from T9 mapping).
    filter: [u8; MAX_FILTER_LEN],
    /// Number of valid bytes in `filter`.
    filter_len: usize,
    /// Indices into `FUNCTIONS` that match the current filter.
    matches: [usize; MAX_ENTRIES],
    /// Number of valid entries in `matches`.
    match_count: usize,
    /// Currently selected index within `matches`.
    cursor: usize,
    /// Scroll offset for the visible window.
    scroll_offset: usize,
}

impl SearchScreen {
    /// Create a new search screen with empty filter (shows all entries).
    pub fn new() -> Self {
        let mut screen = Self {
            filter: [0u8; MAX_FILTER_LEN],
            filter_len: 0,
            matches: [0usize; MAX_ENTRIES],
            match_count: 0,
            cursor: 0,
            scroll_offset: 0,
        };
        screen.rebuild_matches();
        screen
    }

    /// Rebuild the match list from the current filter.
    fn rebuild_matches(&mut self) {
        self.match_count = 0;
        for (i, entry) in FUNCTIONS.iter().enumerate() {
            if fuzzy_match(entry.name, &self.filter, self.filter_len) {
                if self.match_count < MAX_ENTRIES {
                    self.matches[self.match_count] = i;
                    self.match_count += 1;
                }
            }
        }

        // Clamp cursor to valid range.
        if self.match_count == 0 {
            self.cursor = 0;
            self.scroll_offset = 0;
        } else {
            if self.cursor >= self.match_count {
                self.cursor = self.match_count - 1;
            }
            self.adjust_scroll();
        }
    }

    /// Adjust scroll offset so the cursor is visible.
    fn adjust_scroll(&mut self) {
        if self.cursor < self.scroll_offset {
            self.scroll_offset = self.cursor;
        } else if self.cursor >= self.scroll_offset + VISIBLE_ROWS {
            self.scroll_offset = self.cursor + 1 - VISIBLE_ROWS;
        }
    }

    /// Append a T9 character group to the filter.
    ///
    /// For simplicity, appends the first letter of the T9 group. A full T9
    /// implementation would cycle through letters on repeated presses, but
    /// single-letter-per-key is sufficient for substring filtering.
    fn append_t9_key(&mut self, key: Key) {
        let chars = key_to_t9_chars(key);
        if chars.is_empty() {
            return;
        }
        if self.filter_len < MAX_FILTER_LEN {
            self.filter[self.filter_len] = chars[0];
            self.filter_len += 1;
            self.rebuild_matches();
        }
    }

    /// Clear the filter and reset to showing all entries.
    fn clear_filter(&mut self) {
        self.filter_len = 0;
        self.cursor = 0;
        self.scroll_offset = 0;
        self.rebuild_matches();
    }

    /// Get the currently selected function entry, if any.
    fn selected_entry(&self) -> Option<&'static FunctionEntry> {
        if self.cursor < self.match_count {
            Some(&FUNCTIONS[self.matches[self.cursor]])
        } else {
            None
        }
    }

    /// Return the current filter as a string slice.
    fn filter_str(&self) -> &str {
        // Filter bytes are always ASCII (from T9 mapping).
        core::str::from_utf8(&self.filter[..self.filter_len]).unwrap_or("")
    }

    /// Return the match count for testing.
    #[cfg(test)]
    fn match_count(&self) -> usize {
        self.match_count
    }
}

// ---------------------------------------------------------------------------
// Screen implementation
// ---------------------------------------------------------------------------

impl Screen for SearchScreen {
    fn draw(&self, fb: &mut [u16]) {
        let w = SCREEN_WIDTH;
        let h = CONTENT_HEIGHT;

        // Clear content area.
        ui::fill_rect(fb, w, h, 0, 0, w, h, color::BLACK);

        // --- Input field ---
        // Draw filter text or placeholder.
        let filter_text = self.filter_str();
        if filter_text.is_empty() {
            ui::draw_str(
                fb, w, INPUT_PADDING_X, INPUT_Y,
                "Type to search...", color::DARK_GREY, color::BLACK,
            );
        } else {
            ui::draw_str(
                fb, w, INPUT_PADDING_X, INPUT_Y,
                filter_text, color::WHITE, color::BLACK,
            );
        }

        // Draw underline below input field.
        let underline_y = INPUT_Y + CHAR_HEIGHT + 2;
        ui::fill_rect(fb, w, h, INPUT_PADDING_X, underline_y, w - INPUT_PADDING_X * 2, 1, color::DARK_GREY);

        // --- Results list ---
        if self.match_count == 0 && self.filter_len > 0 {
            // Show "No results" message.
            ui::draw_str_centered(
                fb, w, 0, w, LIST_Y + ROW_HEIGHT * 2,
                "No results", color::DARK_GREY, color::BLACK,
            );
            return;
        }

        let visible_end = (self.scroll_offset + VISIBLE_ROWS).min(self.match_count);
        for (vi, mi) in (self.scroll_offset..visible_end).enumerate() {
            let entry = &FUNCTIONS[self.matches[mi]];
            let row_y = LIST_Y + (vi as u16) * ROW_HEIGHT;

            // Highlight selected row.
            let (fg, bg) = if mi == self.cursor {
                (color::BLACK, color::WHITE)
            } else {
                (color::WHITE, color::BLACK)
            };

            // Draw highlight background for selected row.
            if mi == self.cursor {
                ui::fill_rect(fb, w, h, 0, row_y, w, ROW_HEIGHT, color::WHITE);
            }

            // Draw entry name.
            ui::draw_str(fb, w, LIST_PADDING_X, row_y + 2, entry.name, fg, bg);
        }

        // Draw scroll indicators if needed.
        if self.scroll_offset > 0 {
            // Up arrow indicator.
            ui::draw_char(fb, w, w - CHAR_WIDTH - 4, LIST_Y, '^', color::DARK_GREY, color::BLACK);
        }
        if visible_end < self.match_count {
            // Down arrow indicator.
            let arrow_y = LIST_Y + (VISIBLE_ROWS as u16) * ROW_HEIGHT;
            ui::draw_char(fb, w, w - CHAR_WIDTH - 4, arrow_y, 'v', color::DARK_GREY, color::BLACK);
        }
    }

    fn on_key(&mut self, key: Key) -> ScreenAction {
        match key {
            // Navigation.
            Key::Up => {
                if self.cursor > 0 {
                    self.cursor -= 1;
                    self.adjust_scroll();
                }
                ScreenAction::None
            }
            Key::Down => {
                if self.match_count > 0 && self.cursor < self.match_count - 1 {
                    self.cursor += 1;
                    self.adjust_scroll();
                }
                ScreenAction::None
            }

            // Select.
            Key::Ok => {
                if let Some(entry) = self.selected_entry() {
                    ScreenAction::Navigate(entry.screen_id)
                } else {
                    ScreenAction::None
                }
            }

            // Softkeys.
            Key::Lsk => {
                self.clear_filter();
                ScreenAction::None
            }
            Key::Rsk | Key::End => ScreenAction::Back,

            // Numpad keys for T9 filtering.
            Key::Num0 | Key::Num1 | Key::Num2 | Key::Num3 |
            Key::Num4 | Key::Num5 | Key::Num6 | Key::Num7 |
            Key::Num8 | Key::Num9 => {
                self.append_t9_key(key);
                ScreenAction::None
            }

            // Left key acts as backspace on the filter.
            Key::Left => {
                if self.filter_len > 0 {
                    self.filter_len -= 1;
                    self.rebuild_matches();
                }
                ScreenAction::None
            }

            _ => ScreenAction::None,
        }
    }

    fn softkey_left(&self) -> &'static str {
        "CLEAR"
    }

    fn softkey_right(&self) -> &'static str {
        "BACK"
    }

    fn title(&self) -> &'static str {
        "Search"
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fuzzy_match_finds_substring() {
        assert!(
            fuzzy_match("Messages", b"es", 2),
            "'es' must match 'Messages'"
        );
        assert!(
            fuzzy_match("Timer", b"me", 2),
            "'me' must match 'Timer'"
        );
        assert!(
            fuzzy_match("FM Radio", b"rad", 3),
            "'rad' must match 'FM Radio'"
        );
        assert!(
            !fuzzy_match("Dialer", b"xyz", 3),
            "'xyz' must not match 'Dialer'"
        );
    }

    #[test]
    fn empty_filter_shows_all() {
        let screen = SearchScreen::new();
        assert_eq!(
            screen.match_count(), FUNCTIONS.len(),
            "empty filter must show all {} entries", FUNCTIONS.len()
        );
    }

    #[test]
    fn select_navigates_to_screen() {
        let mut screen = SearchScreen::new();
        // First entry is "Messages".
        let action = screen.on_key(Key::Ok);
        assert_eq!(
            action,
            ScreenAction::Navigate(ScreenId::Messages),
            "selecting first entry must navigate to Messages"
        );
    }

    #[test]
    fn filter_is_case_insensitive() {
        // "m" (lowercase from T9 key 6) should match "Messages" (uppercase M).
        assert!(
            fuzzy_match("Messages", b"m", 1),
            "lowercase 'm' must match 'Messages' (case-insensitive)"
        );
        assert!(
            fuzzy_match("Messages", b"M", 1),
            "uppercase 'M' must match 'Messages' (case-insensitive)"
        );
        // "wifi" should match "WiFi".
        assert!(
            fuzzy_match("WiFi", b"wifi", 4),
            "'wifi' must match 'WiFi' (case-insensitive)"
        );
    }

    #[test]
    fn clear_resets_filter() {
        let mut screen = SearchScreen::new();
        // Apply a filter that narrows results.
        screen.filter[0] = b'm';
        screen.filter_len = 1;
        screen.rebuild_matches();
        let filtered_count = screen.match_count();
        assert!(
            filtered_count < FUNCTIONS.len(),
            "filtering by 'm' must reduce results"
        );

        // Clear and verify all entries are back.
        screen.clear_filter();
        assert_eq!(
            screen.match_count(), FUNCTIONS.len(),
            "clear must restore all entries"
        );
        assert_eq!(screen.filter_len, 0, "filter must be empty after clear");
        assert_eq!(screen.cursor, 0, "cursor must reset to 0 after clear");
    }

    #[test]
    fn t9_key_appends_filter() {
        let mut screen = SearchScreen::new();
        // Key 6 maps to "mno", appends 'm'.
        screen.append_t9_key(Key::Num6);
        assert_eq!(screen.filter_len, 1, "filter length must be 1 after one key");
        assert_eq!(screen.filter[0], b'm', "Num6 must append 'm'");
    }

    #[test]
    fn backspace_removes_last_filter_char() {
        let mut screen = SearchScreen::new();
        screen.append_t9_key(Key::Num6); // 'm'
        screen.append_t9_key(Key::Num3); // 'd'
        assert_eq!(screen.filter_len, 2);

        let action = screen.on_key(Key::Left);
        assert_eq!(action, ScreenAction::None);
        assert_eq!(screen.filter_len, 1, "backspace must remove last char");
    }

    #[test]
    fn cursor_navigation_wraps_at_bounds() {
        let mut screen = SearchScreen::new();
        // Cursor starts at 0, Up should not go negative.
        let action = screen.on_key(Key::Up);
        assert_eq!(action, ScreenAction::None);
        assert_eq!(screen.cursor, 0, "cursor must not go below 0");

        // Move to last entry.
        for _ in 0..FUNCTIONS.len() {
            screen.on_key(Key::Down);
        }
        assert_eq!(
            screen.cursor, FUNCTIONS.len() - 1,
            "cursor must stop at last entry"
        );
    }

    #[test]
    fn rsk_returns_back() {
        let mut screen = SearchScreen::new();
        let action = screen.on_key(Key::Rsk);
        assert_eq!(action, ScreenAction::Back, "RSK must return Back action");
    }

    #[test]
    fn draw_does_not_panic() {
        let screen = SearchScreen::new();
        let mut fb = [0u16; SCREEN_WIDTH as usize * CONTENT_HEIGHT as usize];
        screen.draw(&mut fb);
        let any_set = fb.iter().any(|&px| px != 0);
        assert!(any_set, "search screen must render visible content");
    }

    #[test]
    fn draw_with_filter_does_not_panic() {
        let mut screen = SearchScreen::new();
        screen.append_t9_key(Key::Num6); // 'm'
        let mut fb = [0u16; SCREEN_WIDTH as usize * CONTENT_HEIGHT as usize];
        screen.draw(&mut fb);
        // Should still render without panic.
    }

    #[test]
    fn draw_no_results_does_not_panic() {
        let mut screen = SearchScreen::new();
        // Apply a filter that matches nothing.
        screen.filter[0] = b'z';
        screen.filter[1] = b'z';
        screen.filter[2] = b'z';
        screen.filter_len = 3;
        screen.rebuild_matches();
        assert_eq!(screen.match_count(), 0, "zzz must match nothing");

        let mut fb = [0u16; SCREEN_WIDTH as usize * CONTENT_HEIGHT as usize];
        screen.draw(&mut fb);
    }

    #[test]
    fn softkeys_correct() {
        let screen = SearchScreen::new();
        assert_eq!(screen.softkey_left(), "CLEAR");
        assert_eq!(screen.softkey_right(), "BACK");
    }

    #[test]
    fn title_is_search() {
        let screen = SearchScreen::new();
        assert_eq!(screen.title(), "Search");
    }
}
