//! Phone dialer widget.
//!
//! [`PhoneDialer`] renders a number display, a 3×4 keypad grid, and
//! Call/End action buttons. Digit entry via [`Key`] events; backspace
//! on the Left key; Call/End on the corresponding physical keys.

use thumos_haphe::input::{Key, TouchPoint};

use crate::color::Rgb565;
use crate::font::{CHAR_HEIGHT, CHAR_WIDTH, draw_str};
use crate::framebuffer::Framebuffer;
use crate::widget::{Focusable, Widget};

/// Maximum number of digits in a phone number.
const MAX_DIGITS: usize = 20;

/// Height of the number display area.
const DISPLAY_HEIGHT: u32 = CHAR_HEIGHT + 8;

/// Height of a keypad row.
const KEY_ROW_H: u32 = CHAR_HEIGHT + 10;

/// Number of keypad rows (0-9, *, #).
const KEY_ROWS: u32 = 4;

/// Number of keypad columns.
const KEY_COLS: u32 = 3;

/// Height of the Call/End button row.
const ACTION_BTN_H: u32 = CHAR_HEIGHT + 8;

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

/// Format a digit string with hyphens for readability.
///
/// Produces patterns like `123-456-7890` for 10-digit numbers.
/// Shorter or longer strings are returned as-is.
#[must_use]
pub fn format_number(digits: &str) -> String {
    match digits.len() {
        10 => {
            let (area, rest) = digits.split_at(3);
            let (prefix, line) = rest.split_at(3);
            format!("{area}-{prefix}-{line}")
        }
        7 => {
            let (prefix, line) = digits.split_at(3);
            format!("{prefix}-{line}")
        }
        _ => digits.to_owned(),
    }
}

/// Phone dialer widget.
///
/// After each input cycle, check [`PhoneDialer::is_call_pressed`] and
/// [`PhoneDialer::is_end_pressed`] to react to action buttons, then call
/// [`PhoneDialer::clear_actions`].
#[derive(Debug)]
pub struct PhoneDialer {
    /// Entered digit sequence (no formatting).
    digits: String,
    call_pressed: bool,
    end_pressed: bool,
    focused: bool,
    width: u32,
}

impl PhoneDialer {
    /// Create a new dialer with the given pixel width.
    #[must_use]
    pub const fn new(width: u32) -> Self {
        Self {
            digits: String::new(),
            call_pressed: false,
            end_pressed: false,
            focused: false,
            width,
        }
    }

    /// Current raw digit string (no formatting separators).
    #[must_use]
    pub fn digits(&self) -> &str {
        &self.digits
    }

    /// Formatted display number (e.g., `123-456-7890`).
    #[must_use]
    pub fn formatted(&self) -> String {
        format_number(&self.digits)
    }

    /// Whether the Call button was pressed since the last [`clear_actions`](Self::clear_actions).
    #[must_use]
    pub const fn is_call_pressed(&self) -> bool {
        self.call_pressed
    }

    /// Whether the End button was pressed since the last [`clear_actions`](Self::clear_actions).
    #[must_use]
    pub const fn is_end_pressed(&self) -> bool {
        self.end_pressed
    }

    /// Clear Call/End action flags.
    pub const fn clear_actions(&mut self) {
        self.call_pressed = false;
        self.end_pressed = false;
    }

    /// Append a digit/char if within [`MAX_DIGITS`].
    fn push_digit(&mut self, ch: char) {
        if self.digits.len() < MAX_DIGITS {
            self.digits.push(ch);
        }
    }

    /// Remove the last digit (backspace).
    fn backspace(&mut self) {
        self.digits.pop();
    }

    /// Keypad cell width.
    const fn cell_width(&self) -> u32 {
        self.width / KEY_COLS
    }
}

impl Widget for PhoneDialer {
    fn draw(&self, fb: &mut Framebuffer, x: u32, y: u32) {
        // Number display row.
        fb.fill_rect(x, y, self.width, DISPLAY_HEIGHT, Rgb565::BLACK);
        let display = self.formatted();
        let display_str: &str = display
            .get(
                ..display
                    .char_indices()
                    .nth(usize::try_from(self.width / CHAR_WIDTH).unwrap_or(0))
                    .map_or(display.len(), |(i, _)| i),
            )
            .unwrap_or(display.as_str());
        draw_str(fb, x + 4, y + 4, display_str, Rgb565::WHITE, Rgb565::BLACK);

        // Keypad grid: rows 1-9, then *, 0, #.
        let keypad_labels = [
            ["1", "2", "3"],
            ["4", "5", "6"],
            ["7", "8", "9"],
            ["*", "0", "#"],
        ];
        let cell_w = self.cell_width();
        let kpad_y = y + DISPLAY_HEIGHT;
        for (row, labels) in keypad_labels.iter().enumerate() {
            let row_y = kpad_y + u32::try_from(row).unwrap_or(0) * KEY_ROW_H;
            for (col, label) in labels.iter().enumerate() {
                let cell_x = x + u32::try_from(col).unwrap_or(0) * cell_w;
                fb.fill_rect(
                    cell_x,
                    row_y,
                    cell_w.saturating_sub(1),
                    KEY_ROW_H.saturating_sub(1),
                    Rgb565::from_rgb(30, 30, 60),
                );
                draw_str(
                    fb,
                    cell_x + cell_w / 2 - CHAR_WIDTH / 2,
                    row_y + KEY_ROW_H / 2 - CHAR_HEIGHT / 2,
                    label,
                    Rgb565::WHITE,
                    Rgb565::from_rgb(30, 30, 60),
                );
            }
        }

        // Call / End buttons.
        let btn_y = y + DISPLAY_HEIGHT + KEY_ROWS * KEY_ROW_H;
        let half_w = self.width / 2;
        fb.fill_rect(
            x,
            btn_y,
            half_w.saturating_sub(1),
            ACTION_BTN_H,
            Rgb565::GREEN,
        );
        draw_str(fb, x + 4, btn_y + 4, "Call", Rgb565::BLACK, Rgb565::GREEN);
        fb.fill_rect(
            x + half_w,
            btn_y,
            half_w.saturating_sub(1),
            ACTION_BTN_H,
            Rgb565::RED,
        );
        draw_str(
            fb,
            x + half_w + 4,
            btn_y + 4,
            "End",
            Rgb565::WHITE,
            Rgb565::RED,
        );
    }

    fn width(&self) -> u32 {
        self.width
    }

    fn height(&self) -> u32 {
        DISPLAY_HEIGHT + KEY_ROWS * KEY_ROW_H + ACTION_BTN_H
    }
}

impl Focusable for PhoneDialer {
    fn on_key(&mut self, key: Key) -> bool {
        if let Some(ch) = key_to_digit(key) {
            self.push_digit(ch);
            return true;
        }
        match key {
            Key::Left => {
                // Backspace: delete last digit.
                self.backspace();
                true
            }
            Key::Call => {
                self.call_pressed = true;
                true
            }
            Key::End => {
                self.end_pressed = true;
                true
            }
            _ => false,
        }
    }

    fn on_touch(&mut self, point: TouchPoint) -> bool {
        let cell_w = self.cell_width();
        if cell_w == 0 {
            return false;
        }
        let rel_y = u32::from(point.y);
        let rel_x = u32::from(point.x);

        // Determine if the touch hit the keypad area.
        let kpad_start = DISPLAY_HEIGHT;
        let kpad_end = kpad_start + KEY_ROWS * KEY_ROW_H;
        if rel_y >= kpad_start && rel_y < kpad_end {
            let row = usize::try_from((rel_y - kpad_start) / KEY_ROW_H).unwrap_or(0);
            let col = usize::try_from(rel_x / cell_w).unwrap_or(0);
            let keypad_chars = [
                ['1', '2', '3'],
                ['4', '5', '6'],
                ['7', '8', '9'],
                ['*', '0', '#'],
            ];
            if let Some(row_chars) = keypad_chars.get(row)
                && let Some(&ch) = row_chars.get(col)
            {
                self.push_digit(ch);
                return true;
            }
        }

        // Call / End buttons.
        let btn_start = kpad_end;
        let btn_end = btn_start + ACTION_BTN_H;
        if rel_y >= btn_start && rel_y < btn_end {
            let half_w = self.width / 2;
            if rel_x < half_w {
                self.call_pressed = true;
            } else {
                self.end_pressed = true;
            }
            return true;
        }

        false
    }

    fn is_focused(&self) -> bool {
        self.focused
    }

    fn set_focused(&mut self, focused: bool) {
        self.focused = focused;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizing_is_correct() {
        let d = PhoneDialer::new(240);
        assert_eq!(d.width(), 240, "width must match constructor arg");
        let expected_h = DISPLAY_HEIGHT + KEY_ROWS * KEY_ROW_H + ACTION_BTN_H;
        assert_eq!(
            d.height(),
            expected_h,
            "height must equal sum of display + keypad + action rows"
        );
    }

    #[test]
    fn digit_keys_append_to_number() {
        let mut d = PhoneDialer::new(240);
        d.on_key(Key::Num1);
        d.on_key(Key::Num2);
        d.on_key(Key::Num3);
        assert_eq!(d.digits(), "123", "digits must be appended in order");
    }

    #[test]
    fn star_and_hash_appended() {
        let mut d = PhoneDialer::new(240);
        d.on_key(Key::Star);
        d.on_key(Key::Hash);
        assert_eq!(d.digits(), "*#", "Star and Hash must be appended");
    }

    #[test]
    fn backspace_removes_last_digit() {
        let mut d = PhoneDialer::new(240);
        d.on_key(Key::Num5);
        d.on_key(Key::Num6);
        d.on_key(Key::Left); // backspace
        assert_eq!(d.digits(), "5", "Left key must remove last digit");
    }

    #[test]
    fn backspace_on_empty_is_no_op() {
        let mut d = PhoneDialer::new(240);
        d.on_key(Key::Left);
        assert_eq!(d.digits(), "", "backspace on empty must not panic or error");
    }

    #[test]
    fn call_key_sets_call_pressed() {
        let mut d = PhoneDialer::new(240);
        d.on_key(Key::Call);
        assert!(d.is_call_pressed(), "Call key must set call_pressed");
    }

    #[test]
    fn end_key_sets_end_pressed() {
        let mut d = PhoneDialer::new(240);
        d.on_key(Key::End);
        assert!(d.is_end_pressed(), "End key must set end_pressed");
    }

    #[test]
    fn clear_actions_resets_flags() {
        let mut d = PhoneDialer::new(240);
        d.on_key(Key::Call);
        d.on_key(Key::End);
        d.clear_actions();
        assert!(
            !d.is_call_pressed(),
            "clear_actions must reset call_pressed"
        );
        assert!(!d.is_end_pressed(), "clear_actions must reset end_pressed");
    }

    #[test]
    fn format_number_10_digits() {
        let formatted = format_number("1234567890");
        assert_eq!(
            formatted, "123-456-7890",
            "10 digit number must format as NXX-NXX-XXXX"
        );
    }

    #[test]
    fn format_number_7_digits() {
        let formatted = format_number("5551234");
        assert_eq!(
            formatted, "555-1234",
            "7 digit number must format as NXX-XXXX"
        );
    }

    #[test]
    fn format_number_other_len_unchanged() {
        let formatted = format_number("123");
        assert_eq!(
            formatted, "123",
            "numbers of other lengths must pass through unchanged"
        );
    }

    #[test]
    fn max_digits_capped() {
        let mut d = PhoneDialer::new(240);
        for _ in 0..=MAX_DIGITS + 5 {
            d.on_key(Key::Num1);
        }
        assert_eq!(
            d.digits().len(),
            MAX_DIGITS,
            "digits must be capped at MAX_DIGITS"
        );
    }

    #[test]
    fn draw_does_not_panic() {
        let mut d = PhoneDialer::new(240);
        d.on_key(Key::Num1);
        d.on_key(Key::Num2);
        let mut fb = Framebuffer::new(240, 320);
        // NOTE: should complete without panic
        d.draw(&mut fb, 0, 0);
    }

    #[test]
    fn focus_set_and_cleared() {
        let mut d = PhoneDialer::new(240);
        assert!(!d.is_focused(), "dialer must start unfocused");
        d.set_focused(true);
        assert!(d.is_focused(), "must be focused after set_focused(true)");
    }
}
