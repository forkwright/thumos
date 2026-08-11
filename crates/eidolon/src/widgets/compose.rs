//! Compose text-buffer widget.
//!
//! [`ComposeField`] is the growable multi-character body with a cursor that
//! nothing else in eidolon manages -- [`crate::widgets::PhoneDialer`] only
//! ever holds a fixed-purpose digit string. It owns insert/backspace/cursor
//! movement and renders a scrolling preview that keeps the cursor visible
//! when the buffer outgrows the strip.
//!
//! WHY 42px tall (#458): the full-screen keyboard layout budgets
//! status(20) + preview(42) + 4 key rows(57 each=228) + softkey(30) = 320,
//! the panel's exact height. 42 divides evenly by 2 lines (21px each),
//! itself taller than the 16px glyph it centers -- a deliberate touch
//! target for the tap-to-place-cursor affordance below.
//!
//! ## Dual input
//!
//! - Touch: tapping inside the preview places the cursor at the tapped
//!   character position. This is the case the operator named for touch as a
//!   modal accelerator over the keypad -- jumping the cursor to an arbitrary
//!   point in already-typed text has no comfortable keypad equivalent
//!   (repeated Left/Right presses), so touch clearly beats it here.
//! - Keypad: [`Key::Left`]/[`Key::Right`] step the cursor one character at a
//!   time, clamped at the buffer's ends -- the same reach as touch, just
//!   slower, since every touch affordance still needs a keypad path.
//!
//! Character insertion and backspace are NOT driven through [`Key`] events:
//! the physical keypad has no letter keys ([`haphe::input::Key`] is digits,
//! `*`/`#`, and d-pad/action buttons only), so the only sources of
//! characters are the [`crate::widgets::Keyboard`] widget's [`take_event`]
//! and T9 (kernel-side, out of scope here). Whatever assembles the compose
//! screen calls [`ComposeField::insert_char`] / [`ComposeField::backspace`]
//! with the drained events; this widget does not know or care where a
//! character came from.
//!
//! ## Coverage cost
//!
//! [`insert_char`] silently drops any character outside [`crate::font`]'s
//! `0x20`-`0x7E` range: no accented characters, no emoji, no box-drawing
//! glyphs can enter the buffer, because nothing on this panel can render
//! them.
//!
//! [`take_event`]: crate::widgets::Keyboard::take_event
//! [`insert_char`]: ComposeField::insert_char

use alloc::string::String;

use haphe::input::{Key, TouchPoint};

use crate::color::Rgb565;
use crate::font::{CHAR_HEIGHT, CHAR_WIDTH, draw_char};
use crate::framebuffer::Framebuffer;
use crate::widget::{Focusable, Widget};

/// Total pixel height of the preview strip.
const PREVIEW_HEIGHT: u32 = 42;

/// Number of text lines shown in the preview.
const PREVIEW_LINES: u32 = 2;

/// Pixel height of each line's touch/render band (evenly divides `PREVIEW_HEIGHT`).
const LINE_BAND_H: u32 = PREVIEW_HEIGHT / PREVIEW_LINES;

/// Pixel width of the caret indicator.
const CARET_WIDTH: u32 = 2;

/// Lowest character this widget will insert (matches [`crate::font`]'s range).
const FONT_MIN: char = ' ';

/// Highest character this widget will insert (matches [`crate::font`]'s range).
const FONT_MAX: char = '~';

/// Byte offset of the `char_idx`-th character in `s`, or `s.len()` if
/// `char_idx` is at or past the end.
fn byte_index(s: &str, char_idx: usize) -> usize {
    s.char_indices().nth(char_idx).map_or(s.len(), |(i, _)| i)
}

/// First visible character index for a buffer of `total` characters,
/// a cursor at `cursor`, and a window of `capacity` characters.
///
/// Positions before `capacity` always show from the start (`0`). Once
/// `total` exceeds `capacity`, the window is pinned to keep `cursor` inside
/// `[start, start + capacity]`, preferring the buffer's tail.
const fn window_start(cursor: usize, total: usize, capacity: usize) -> usize {
    if capacity == 0 {
        return 0;
    }
    let max_start = total.saturating_sub(capacity);
    let by_cursor = cursor.saturating_sub(capacity);
    if by_cursor < max_start {
        by_cursor
    } else {
        max_start
    }
}

/// Compose text buffer with cursor and a 2-line scrolling preview.
///
/// Call [`ComposeField::insert_char`] / [`ComposeField::backspace`] to
/// mutate the buffer (see the module docs for why these are plain methods
/// rather than [`Key`]-driven); [`Focusable::on_key`] only moves the cursor.
#[derive(Debug)]
pub struct ComposeField {
    buffer: String,
    /// Cursor position, in characters (not bytes).
    cursor: usize,
    width: u32,
    focused: bool,
}

impl ComposeField {
    /// Create an empty compose field with the given pixel width (240 on the real panel).
    #[must_use]
    pub(crate) const fn new(width: u32) -> Self {
        Self {
            buffer: String::new(),
            cursor: 0,
            width,
            focused: false,
        }
    }

    /// The composed text so far.
    #[must_use]
    pub(crate) fn buffer(&self) -> &str {
        &self.buffer
    }

    /// Cursor position, in characters from the start of the buffer.
    #[must_use]
    pub(crate) const fn cursor(&self) -> usize {
        self.cursor
    }

    /// Insert `ch` at the cursor and advance the cursor past it.
    ///
    /// Silently ignored if `ch` falls outside the font's renderable range
    /// (see the module docs).
    pub(crate) fn insert_char(&mut self, ch: char) {
        if !(FONT_MIN..=FONT_MAX).contains(&ch) {
            return;
        }
        let idx = byte_index(&self.buffer, self.cursor);
        self.buffer.insert(idx, ch);
        self.cursor += 1;
    }

    /// Delete the character before the cursor. No-op at the start of the buffer.
    pub(crate) fn backspace(&mut self) {
        if self.cursor == 0 {
            return;
        }
        let start = byte_index(&self.buffer, self.cursor - 1);
        self.buffer.remove(start);
        self.cursor -= 1;
    }

    /// Move the cursor left one character, clamping at the start.
    const fn cursor_left(&mut self) {
        self.cursor = self.cursor.saturating_sub(1);
    }

    /// Move the cursor right one character, clamping at the end.
    fn cursor_right(&mut self) {
        let len = self.buffer.chars().count();
        if self.cursor < len {
            self.cursor += 1;
        }
    }

    /// Characters shown per line.
    fn cols_per_line(&self) -> usize {
        usize::try_from(self.width / CHAR_WIDTH).unwrap_or(0)
    }

    /// Total characters visible in the preview window.
    fn capacity(&self) -> usize {
        self.cols_per_line()
            .saturating_mul(usize::try_from(PREVIEW_LINES).unwrap_or(2))
    }
}

impl Widget for ComposeField {
    fn draw(&self, fb: &mut Framebuffer, x: u32, y: u32) {
        fb.fill_rect(x, y, self.width, PREVIEW_HEIGHT, Rgb565::BLACK);

        let cols = self.cols_per_line();
        if cols == 0 {
            return;
        }
        let capacity = self.capacity();
        let total = self.buffer.chars().count();
        let start = window_start(self.cursor, total, capacity);
        let end = (start + capacity).min(total);
        let start_byte = byte_index(&self.buffer, start);
        let end_byte = byte_index(&self.buffer, end);
        let visible = self.buffer.get(start_byte..end_byte).unwrap_or("");

        let lines_usize = usize::try_from(PREVIEW_LINES).unwrap_or(2);
        for (i, ch) in visible.chars().enumerate() {
            let line = i / cols;
            if line >= lines_usize {
                break;
            }
            let col = i % cols;
            let glyph_x = x + u32::try_from(col).unwrap_or(0) * CHAR_WIDTH;
            let glyph_y = y
                + u32::try_from(line).unwrap_or(0) * LINE_BAND_H
                + (LINE_BAND_H.saturating_sub(CHAR_HEIGHT)) / 2;
            draw_char(fb, glyph_x, glyph_y, ch, Rgb565::WHITE, Rgb565::BLACK);
        }

        if self.focused {
            let rel = self
                .cursor
                .saturating_sub(start)
                .min(capacity.saturating_sub(1));
            let line = rel / cols;
            let col = rel % cols;
            let caret_x = x + u32::try_from(col).unwrap_or(0) * CHAR_WIDTH;
            let caret_y = y
                + u32::try_from(line).unwrap_or(0) * LINE_BAND_H
                + (LINE_BAND_H.saturating_sub(CHAR_HEIGHT)) / 2;
            fb.fill_rect(caret_x, caret_y, CARET_WIDTH, CHAR_HEIGHT, Rgb565::YELLOW);
        }
    }

    fn width(&self) -> u32 {
        self.width
    }

    fn height(&self) -> u32 {
        PREVIEW_HEIGHT
    }
}

impl Focusable for ComposeField {
    fn on_key(&mut self, key: Key) -> bool {
        match key {
            Key::Left => {
                self.cursor_left();
                true
            }
            Key::Right => {
                self.cursor_right();
                true
            }
            _ => false,
        }
    }

    fn on_touch(&mut self, point: TouchPoint) -> bool {
        let x = u32::from(point.x);
        let y = u32::from(point.y);
        if x >= self.width || y >= PREVIEW_HEIGHT {
            return false;
        }
        let cols = self.cols_per_line();
        if cols == 0 {
            return false;
        }
        let line = usize::try_from(y / LINE_BAND_H).unwrap_or(0);
        let col = usize::try_from(x / CHAR_WIDTH)
            .unwrap_or(0)
            .min(cols.saturating_sub(1));
        let total = self.buffer.chars().count();
        let capacity = self.capacity();
        let start = window_start(self.cursor, total, capacity);
        let idx_in_window = line.saturating_mul(cols) + col;
        self.cursor = (start + idx_in_window).min(total);
        true
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
        let c = ComposeField::new(240);
        assert_eq!(c.width(), 240, "width must match constructor arg");
        assert_eq!(
            c.height(),
            42,
            "height must be the fixed 42px preview budget"
        );
    }

    #[test]
    fn new_is_empty() {
        let c = ComposeField::new(240);
        assert_eq!(c.buffer(), "", "new field must start with an empty buffer");
        assert_eq!(c.cursor(), 0, "new field must start with cursor at 0");
    }

    #[test]
    fn insert_char_appends_in_order() {
        let mut c = ComposeField::new(240);
        c.insert_char('h');
        c.insert_char('i');
        assert_eq!(c.buffer(), "hi", "characters must insert in press order");
        assert_eq!(c.cursor(), 2, "cursor must advance past each insert");
    }

    #[test]
    fn insert_char_rejects_out_of_font_range() {
        let mut c = ComposeField::new(240);
        c.insert_char('e');
        c.insert_char('\u{E9}'); // outside 0x20-0x7E
        c.insert_char('\n'); // below 0x20
        c.insert_char('\u{7F}'); // one past 0x7E
        assert_eq!(
            c.buffer(),
            "e",
            "characters outside the font's ASCII range must be silently dropped"
        );
    }

    #[test]
    fn insert_char_accepts_font_boundary_chars() {
        let mut c = ComposeField::new(240);
        c.insert_char(' '); // 0x20, lowest renderable
        c.insert_char('~'); // 0x7E, highest renderable
        assert_eq!(
            c.buffer(),
            " ~",
            "the font's own min/max characters must be accepted"
        );
    }

    #[test]
    fn backspace_removes_preceding_char() {
        let mut c = ComposeField::new(240);
        c.insert_char('a');
        c.insert_char('b');
        c.backspace();
        assert_eq!(
            c.buffer(),
            "a",
            "backspace must remove the char before the cursor"
        );
        assert_eq!(c.cursor(), 1, "cursor must retreat with the removed char");
    }

    #[test]
    fn backspace_on_empty_is_noop() {
        let mut c = ComposeField::new(240);
        c.backspace();
        assert_eq!(
            c.buffer(),
            "",
            "backspace on empty buffer must not panic or error"
        );
        assert_eq!(c.cursor(), 0);
    }

    #[test]
    fn cursor_left_right_clamp_at_bounds() {
        let mut c = ComposeField::new(240);
        c.insert_char('a');
        c.insert_char('b');
        assert!(c.on_key(Key::Left), "Left must be consumed");
        assert_eq!(c.cursor(), 1);
        c.on_key(Key::Left);
        c.on_key(Key::Left); // already at 0, must clamp
        assert_eq!(c.cursor(), 0, "cursor must clamp at 0, not go negative");
        c.on_key(Key::Right);
        c.on_key(Key::Right);
        c.on_key(Key::Right); // already at len, must clamp
        assert_eq!(c.cursor(), 2, "cursor must clamp at buffer length");
    }

    #[test]
    fn insert_at_mid_cursor_position() {
        let mut c = ComposeField::new(240);
        c.insert_char('a');
        c.insert_char('c');
        c.on_key(Key::Left); // cursor between 'a' and 'c'
        c.insert_char('b');
        assert_eq!(
            c.buffer(),
            "abc",
            "insert must land at the cursor, not always append"
        );
        assert_eq!(c.cursor(), 2);
    }

    #[test]
    fn backspace_at_mid_cursor_position() {
        let mut c = ComposeField::new(240);
        c.insert_char('a');
        c.insert_char('b');
        c.insert_char('c');
        c.on_key(Key::Left); // cursor between 'b' and 'c'
        c.backspace();
        assert_eq!(
            c.buffer(),
            "ac",
            "backspace must remove the char before the cursor, not the last char"
        );
        assert_eq!(c.cursor(), 1);
    }

    #[test]
    fn unrelated_key_not_consumed() {
        let mut c = ComposeField::new(240);
        assert!(
            !c.on_key(Key::Select),
            "Select has no meaning on the compose field"
        );
    }

    // --- window_start boundary math ---

    #[test]
    fn window_start_shows_from_zero_when_buffer_fits() {
        assert_eq!(window_start(0, 0, 60), 0);
        assert_eq!(
            window_start(10, 20, 60),
            0,
            "total under capacity must show from 0"
        );
    }

    #[test]
    fn window_start_pins_to_tail_when_cursor_at_end() {
        assert_eq!(
            window_start(60, 60, 60),
            0,
            "exactly-full window with cursor at the end must still start at 0"
        );
        assert_eq!(
            window_start(100, 100, 60),
            40,
            "cursor at the very end of an overflowing buffer must pin the tail"
        );
    }

    #[test]
    fn window_start_scrolls_minimally_past_capacity() {
        assert_eq!(
            window_start(70, 100, 60),
            10,
            "cursor just past the first page must shift the window by exactly the overrun"
        );
    }

    #[test]
    fn window_start_early_cursor_shows_from_start_even_in_long_buffer() {
        assert_eq!(
            window_start(50, 200, 60),
            0,
            "a cursor still within the first page must not scroll early"
        );
    }

    // --- overflow rendering ---

    #[test]
    fn draw_does_not_panic_with_overflowing_buffer() {
        let mut c = ComposeField::new(240);
        for _ in 0..100 {
            c.insert_char('x');
        }
        c.set_focused(true);
        let mut fb = Framebuffer::new(240, 42);
        fb.clear(Rgb565::WHITE);
        c.draw(&mut fb, 0, 0);
        assert!(
            fb.as_bytes().iter().any(|&b| b != 0xFF),
            "overflowing buffer must still render visible pixels"
        );
    }

    #[test]
    fn draw_does_not_panic_when_empty() {
        let c = ComposeField::new(240);
        let mut fb = Framebuffer::new(240, 42);
        fb.clear(Rgb565::WHITE);
        c.draw(&mut fb, 0, 0);
        // Background fill alone must produce non-background pixels (black fill on white bg).
        assert!(
            fb.as_bytes().iter().any(|&b| b != 0xFF),
            "an empty field must still paint its background"
        );
    }

    // --- touch cursor placement ---

    #[test]
    fn touch_places_cursor_at_column_edges_on_line_zero() {
        let mut c = ComposeField::new(240);
        for _ in 0..40 {
            c.insert_char('x');
        }
        c.on_touch(TouchPoint::new(0, 0, 100, 0));
        assert_eq!(
            c.cursor(),
            0,
            "tapping the first cell must place the cursor at 0"
        );
        c.on_touch(TouchPoint::new(7, 0, 100, 0));
        assert_eq!(c.cursor(), 0, "x=7 is still inside column 0 (8px wide)");
        c.on_touch(TouchPoint::new(8, 0, 100, 0));
        assert_eq!(c.cursor(), 1, "x=8 is the first pixel of column 1");
    }

    #[test]
    fn touch_places_cursor_on_line_boundary() {
        let mut c = ComposeField::new(240);
        for _ in 0..40 {
            c.insert_char('x');
        }
        c.on_touch(TouchPoint::new(0, 20, 100, 0));
        assert_eq!(
            c.cursor(),
            0,
            "y=20 is the last pixel of line 0 (21px band)"
        );
        c.on_touch(TouchPoint::new(0, 21, 100, 0));
        assert_eq!(
            c.cursor(),
            30,
            "y=21 is the first pixel of line 1, which starts at window index 30 (cols_per_line)"
        );
    }

    #[test]
    fn touch_out_of_bounds_not_consumed() {
        let mut c = ComposeField::new(240);
        assert!(
            !c.on_touch(TouchPoint::new(240, 0, 100, 0)),
            "x == width is off-widget and must not be consumed"
        );
        assert!(
            !c.on_touch(TouchPoint::new(0, 42, 100, 0)),
            "y == height is off-widget and must not be consumed"
        );
    }

    #[test]
    fn focus_set_and_cleared() {
        let mut c = ComposeField::new(240);
        assert!(!c.is_focused(), "field must start unfocused");
        c.set_focused(true);
        assert!(c.is_focused(), "must be focused after set_focused(true)");
        c.set_focused(false);
        assert!(
            !c.is_focused(),
            "must be unfocused after set_focused(false)"
        );
    }
}
