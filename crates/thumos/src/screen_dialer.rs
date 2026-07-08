//! Phone dialer screen for the thumos kernel UI.
//!
//! Implements the [`Screen`] trait to provide a T9-style phone dialer:
//! - Number entry with large centered digits
//! - Numpad keys (0-9, *, #) append to the number buffer
//! - Call key initiates a voice call via the telephony subsystem
//! - End key clears the number (or navigates back if empty)
//! - Left key acts as backspace (deletes last digit)
//! - Softkeys: LSK = "CONTACTS", RSK = "CALL"
//!
//! Rendering approach ported from `crates/eidolon/src/widgets/dialer.rs`,
//! adapted for the kernel's `u16` RGB565 framebuffer format.

use crate::ui::{
    self, CHAR_HEIGHT, CHAR_WIDTH, CONTENT_HEIGHT, Key, SCREEN_WIDTH, Screen, ScreenAction,
    ScreenId, color,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of digits in the entry buffer.
const MAX_DIGITS: usize = 20;

/// Y offset for the entered number display.
const NUMBER_Y: u16 = 20;

/// Height of the number display area.
const NUMBER_AREA_HEIGHT: u16 = CHAR_HEIGHT * 2 + 16;

/// Scale factor for the number display digits.
const DIGIT_SCALE: u16 = 2;

/// Width of a scaled digit character.
const SCALED_CHAR_WIDTH: u16 = CHAR_WIDTH * DIGIT_SCALE;

/// Height of a scaled digit character.
const SCALED_CHAR_HEIGHT: u16 = CHAR_HEIGHT * DIGIT_SCALE;

/// Y offset for the keypad grid, below the number display.
const KEYPAD_Y: u16 = NUMBER_Y + NUMBER_AREA_HEIGHT + 8;

/// Height of each keypad row.
const KEY_ROW_H: u16 = 30;

/// Number of keypad columns.
const KEY_COLS: u16 = 3;

/// Keypad cell width.
const KEY_CELL_W: u16 = SCREEN_WIDTH / KEY_COLS;

// ---------------------------------------------------------------------------
// Digit key mapping
// ---------------------------------------------------------------------------

/// Map a numeric [`Key`] to its ASCII digit character.
const fn key_to_digit(key: Key) -> Option<char> {
    match key {
        Key::Num0 => Some('0'),
        Key::Num1 => Some('1'),
        Key::Num2 => Some('2'),
        Key::Num3 => Some('3'),
        Key::Num4 => Some('4'),
        Key::Num5 => Some('5'),
        Key::Num6 => Some('6'),
        Key::Num7 => Some('7'),
        Key::Num8 => Some('8'),
        Key::Num9 => Some('9'),
        Key::Star => Some('*'),
        Key::Hash => Some('#'),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Number formatting
// ---------------------------------------------------------------------------

/// Format a digit string with hyphens for readability.
///
/// Produces `NXX-NXX-XXXX` for 10-digit numbers, `NXX-XXXX` for 7-digit.
/// Other lengths are returned as-is.
fn format_number(digits: &[u8], len: usize) -> ([u8; 24], usize) {
    let mut buf = [0u8; 24];
    match len {
        10 => {
            // Format as NXX-NXX-XXXX (12 chars).
            buf[0..3].copy_from_slice(&digits[0..3]);
            buf[3] = b'-';
            buf[4..7].copy_from_slice(&digits[3..6]);
            buf[7] = b'-';
            buf[8..12].copy_from_slice(&digits[6..10]);
            (buf, 12)
        }
        7 => {
            // Format as NXX-XXXX (8 chars).
            buf[0..3].copy_from_slice(&digits[0..3]);
            buf[3] = b'-';
            buf[4..8].copy_from_slice(&digits[3..7]);
            (buf, 8)
        }
        _ => {
            let copy_len = len.min(24);
            buf[..copy_len].copy_from_slice(&digits[..copy_len]);
            (buf, copy_len)
        }
    }
}

// ---------------------------------------------------------------------------
// Dialer screen
// ---------------------------------------------------------------------------

/// Phone dialer screen.
///
/// Tracks the entered digit sequence and provides Call/End/Backspace
/// key handling. The caller is responsible for wiring the
/// `ScreenAction::Navigate(ScreenId::InCall)` result to the telephony
/// subsystem's `dial()` method.
pub(crate) struct DialerScreen {
    /// Entered digit sequence (no formatting separators).
    digits: [u8; MAX_DIGITS],
    /// Number of valid digits in the buffer.
    digit_count: usize,
}

impl DialerScreen {
    /// Create a new dialer screen with an empty number buffer.
    pub(crate) fn new() -> Self {
        Self {
            digits: [0u8; MAX_DIGITS],
            digit_count: 0,
        }
    }

    /// Return the current digit string as a byte slice.
    #[must_use]
    pub(crate) fn digits(&self) -> &[u8] {
        &self.digits[..self.digit_count]
    }

    /// Return the number of entered digits.
    #[must_use]
    pub(crate) fn digit_count(&self) -> usize {
        self.digit_count
    }

    /// Append a digit character to the buffer.
    fn push_digit(&mut self, ch: char) {
        if self.digit_count < MAX_DIGITS {
            self.digits[self.digit_count] = ch as u8;
            self.digit_count += 1;
        }
    }

    /// Remove the last digit (backspace).
    fn backspace(&mut self) {
        if self.digit_count > 0 {
            self.digit_count -= 1;
        }
    }

    /// Clear all entered digits.
    fn clear(&mut self) {
        self.digit_count = 0;
    }
}

impl Screen for DialerScreen {
    fn draw(&self, fb: &mut [u16]) {
        let w = SCREEN_WIDTH;
        let h = CONTENT_HEIGHT;

        // Clear content area to black.
        ui::fill_rect(fb, w, h, 0, 0, w, h, color::BLACK);

        // Title.
        ui::draw_str_centered(fb, w, 0, w, 4, "PHONE", color::WHITE, color::BLACK);

        // Number display: large centered digits.
        if self.digit_count > 0 {
            let (formatted, fmt_len) = format_number(&self.digits, self.digit_count);
            let display_str = core::str::from_utf8(&formatted[..fmt_len]).unwrap_or("");
            ui::draw_scaled_str_centered(
                fb,
                w,
                NUMBER_Y,
                display_str.as_bytes(),
                color::WHITE,
                color::BLACK,
                DIGIT_SCALE,
            );
        } else {
            // Placeholder text.
            ui::draw_str_centered(
                fb,
                w,
                0,
                w,
                NUMBER_Y + CHAR_HEIGHT / 2,
                "Enter number",
                color::DARK_GREY,
                color::BLACK,
            );
        }

        // Keypad grid.
        let keypad_labels = [
            ["1", "2", "3"],
            ["4", "5", "6"],
            ["7", "8", "9"],
            ["*", "0", "#"],
        ];

        for (row, labels) in keypad_labels.iter().enumerate() {
            let row_y = KEYPAD_Y + (row as u16) * KEY_ROW_H;
            for (col, label) in labels.iter().enumerate() {
                let cell_x = (col as u16) * KEY_CELL_W;
                // Cell background.
                ui::fill_rect(
                    fb,
                    w,
                    h,
                    cell_x + 1,
                    row_y + 1,
                    KEY_CELL_W - 2,
                    KEY_ROW_H - 2,
                    color::from_rgb(30, 30, 60),
                );
                // Cell label (centered).
                let label_x = cell_x + KEY_CELL_W / 2 - CHAR_WIDTH / 2;
                let label_y = row_y + KEY_ROW_H / 2 - CHAR_HEIGHT / 2;
                ui::draw_str(
                    fb,
                    w,
                    label_x,
                    label_y,
                    label,
                    color::WHITE,
                    color::from_rgb(30, 30, 60),
                );
            }
        }
    }

    fn on_key(&mut self, key: Key) -> ScreenAction {
        // Digit keys: append to number.
        if let Some(ch) = key_to_digit(key) {
            self.push_digit(ch);
            return ScreenAction::None;
        }

        match key {
            Key::Left => {
                self.backspace();
                ScreenAction::None
            }
            Key::Call | Key::Rsk => {
                // Initiate call if digits are entered.
                if self.digit_count > 0 {
                    ScreenAction::Navigate(ScreenId::InCall)
                } else {
                    ScreenAction::None
                }
            }
            Key::End => {
                if self.digit_count > 0 {
                    self.clear();
                    ScreenAction::None
                } else {
                    ScreenAction::Back
                }
            }
            Key::Lsk => ScreenAction::Navigate(ScreenId::Contacts),
            _ => ScreenAction::None,
        }
    }

    fn softkey_left(&self) -> &'static str {
        "CONTACTS"
    }

    fn softkey_right(&self) -> &'static str {
        "CALL"
    }

    fn title(&self) -> &'static str {
        "Phone"
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digit_key_appends_to_number() {
        let mut screen = DialerScreen::new();
        screen.on_key(Key::Num1);
        screen.on_key(Key::Num2);
        screen.on_key(Key::Num3);
        assert_eq!(screen.digit_count(), 3, "must have 3 digits");
        assert_eq!(screen.digits(), b"123", "digits must be 1, 2, 3");
    }

    #[test]
    fn end_key_clears_number() {
        let mut screen = DialerScreen::new();
        screen.on_key(Key::Num5);
        screen.on_key(Key::Num6);
        assert_eq!(screen.digit_count(), 2);

        let action = screen.on_key(Key::End);
        assert_eq!(
            action,
            ScreenAction::None,
            "End with digits must clear, not navigate"
        );
        assert_eq!(screen.digit_count(), 0, "digits must be cleared");
    }

    #[test]
    fn end_key_navigates_back_when_empty() {
        let mut screen = DialerScreen::new();
        let action = screen.on_key(Key::End);
        assert_eq!(
            action,
            ScreenAction::Back,
            "End with empty number must navigate back"
        );
    }

    #[test]
    fn call_key_returns_navigate_to_call() {
        let mut screen = DialerScreen::new();
        screen.on_key(Key::Num1);
        let action = screen.on_key(Key::Call);
        assert_eq!(
            action,
            ScreenAction::Navigate(ScreenId::InCall),
            "Call with digits must navigate to InCall screen"
        );
    }

    #[test]
    fn call_key_no_op_when_empty() {
        let mut screen = DialerScreen::new();
        let action = screen.on_key(Key::Call);
        assert_eq!(
            action,
            ScreenAction::None,
            "Call with no digits must be no-op"
        );
    }

    #[test]
    fn softkeys_correct() {
        let screen = DialerScreen::new();
        assert_eq!(screen.softkey_left(), "CONTACTS", "LSK must be CONTACTS");
        assert_eq!(screen.softkey_right(), "CALL", "RSK must be CALL");
    }

    #[test]
    fn left_key_acts_as_backspace() {
        let mut screen = DialerScreen::new();
        screen.on_key(Key::Num4);
        screen.on_key(Key::Num5);
        screen.on_key(Key::Left);
        assert_eq!(screen.digit_count(), 1);
        assert_eq!(screen.digits(), b"4", "Left must delete last digit");
    }

    #[test]
    fn max_digits_capped() {
        let mut screen = DialerScreen::new();
        for _ in 0..MAX_DIGITS + 5 {
            screen.on_key(Key::Num1);
        }
        assert_eq!(
            screen.digit_count(),
            MAX_DIGITS,
            "digits must be capped at MAX_DIGITS"
        );
    }

    #[test]
    fn format_number_10_digits() {
        let digits = b"1234567890";
        let (buf, len) = format_number(digits, 10);
        let s = core::str::from_utf8(&buf[..len]).unwrap_or("");
        assert_eq!(
            s, "123-456-7890",
            "10-digit number must format as NXX-NXX-XXXX"
        );
    }

    #[test]
    fn format_number_7_digits() {
        let digits = b"5551234";
        let (buf, len) = format_number(digits, 7);
        let s = core::str::from_utf8(&buf[..len]).unwrap_or("");
        assert_eq!(s, "555-1234", "7-digit number must format as NXX-XXXX");
    }

    #[test]
    fn rsk_also_initiates_call() {
        let mut screen = DialerScreen::new();
        screen.on_key(Key::Num9);
        let action = screen.on_key(Key::Rsk);
        assert_eq!(
            action,
            ScreenAction::Navigate(ScreenId::InCall),
            "RSK with digits must navigate to InCall"
        );
    }

    #[test]
    fn lsk_navigates_to_contacts() {
        let mut screen = DialerScreen::new();
        let action = screen.on_key(Key::Lsk);
        assert_eq!(
            action,
            ScreenAction::Navigate(ScreenId::Contacts),
            "LSK must navigate to Contacts"
        );
    }

    #[test]
    fn star_and_hash_append() {
        let mut screen = DialerScreen::new();
        screen.on_key(Key::Star);
        screen.on_key(Key::Hash);
        assert_eq!(screen.digits(), b"*#", "Star and Hash must append");
    }

    #[test]
    fn draw_does_not_panic() {
        let screen = DialerScreen::new();
        let mut fb = [0u16; SCREEN_WIDTH as usize * CONTENT_HEIGHT as usize];
        screen.draw(&mut fb);
        let any_set = fb.iter().any(|&px| px != 0);
        assert!(any_set, "dialer screen must render visible content");
    }
}
