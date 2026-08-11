//! On-screen QWERTY keyboard widget.
//!
//! [`Keyboard`] renders a touch QWERTY grid over a fixed-pitch 10-unit column
//! system (24px per unit at the 240px panel width) so hit-testing and keypad
//! navigation share the same geometry. Layout (#458), top to bottom:
//!
//! - Row 0: `q w e r t y u i o p` (10 letters, 1 unit each)
//! - Row 1: `a s d f g h j k l` (9 letters) + `DEL` (1 unit)
//! - Row 2: `Shift` (1 unit) + `z x c v b n m` (7 letters) + `,` + `.`
//! - Row 3: a single `SPACE` key spanning the full width
//! - Softkey bar: `T9` (switch to multi-tap fallback) + `DONE` (5 units each)
//!
//! WHY these row heights (#458): the full-screen layout budgets
//! status(20) + compose-preview(42) + 4x`KEY_ROW_H`(57) + softkey(30) = 320,
//! the panel's exact height. 57px is 97% of the 59px comfortable finger
//! target derived for this panel (2.4in/240x320 -> 166.7 PPI -> 9mm contact);
//! the 30px softkey row and the 24px unit width both undershoot that target
//! deliberately -- width is the permanent constraint on this panel, and the
//! softkey bar carries secondary, infrequent actions.
//!
//! ## Dual input
//!
//! Every key is reachable both ways:
//! - Touch: tapping a key's rect presses it directly.
//! - Keypad: [`Key::Up`]/[`Key::Down`]/[`Key::Left`]/[`Key::Right`] move a
//!   highlighted-key cursor; [`Key::Select`] presses whatever is
//!   highlighted. Vertical movement preserves horizontal pixel position by
//!   re-resolving the nearest key under the previous key's center in the
//!   target row, so moving between rows of different key counts (e.g. the
//!   10-key letter rows and the single full-width `SPACE` row) lands
//!   somewhere sensible rather than on a fixed column index.
//!
//! `Shift` is a sticky toggle (not one-shot): no widget in this crate has a
//! time source, so "revert after one letter" is not implementable without
//! one. Pressing `Shift` again reverts it.
//!
//! ## Coverage cost
//!
//! [`crate::font`] only covers ASCII `0x20`-`0x7E`. This grid exposes `,`
//! and `.` directly and nothing else beyond letters/space/backspace --
//! apostrophe and other ASCII punctuation are reachable through neither
//! touch nor the keypad cursor on this grid. `T9` is one softkey away as
//! the accuracy/coverage fallback.

use haphe::input::{Key, TouchPoint};

use crate::color::Rgb565;
use crate::font::{CHAR_HEIGHT, draw_str, str_pixel_width};
use crate::framebuffer::Framebuffer;
use crate::widget::{Focusable, Widget};

/// Grid columns per full-width row (10 QWERTY keys at 24px each on a 240px panel).
const GRID_UNITS: u32 = 10;

/// Height of each of the four main key rows.
const KEY_ROW_H: u32 = 57;

/// Height of the softkey bar.
const SOFTKEY_ROW_H: u32 = 30;

/// Number of main (non-softkey) rows.
const MAIN_ROW_COUNT: usize = 4;

/// Total number of rows, including the softkey bar.
const NUM_ROWS: usize = MAIN_ROW_COUNT + 1;

/// Total pixel height of the widget: four 57px rows plus the 30px softkey bar.
const KEYBOARD_HEIGHT: u32 = KEY_ROW_H * MAIN_ROW_COUNT as u32 + SOFTKEY_ROW_H;

/// Background color for an unhighlighted key (matches [`crate::widgets::PhoneDialer`]'s keypad).
const KEY_BG: Rgb565 = Rgb565::from_rgb(30, 30, 60);

/// What a key does when pressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyAction {
    /// Lowercase letter; display and emission respect `shift_active`.
    Letter(char),
    /// Fixed punctuation; unaffected by shift.
    Symbol(char),
    /// Inserts a literal space.
    Space,
    /// Deletes the character before the cursor in the compose buffer.
    Backspace,
    /// Toggles `shift_active`.
    Shift,
    /// Requests a switch to T9 multi-tap input (the accuracy fallback).
    SwitchToT9,
    /// Requests the keyboard be dismissed / composition committed.
    Done,
}

/// One key's action, grid width, and (for non-letter keys) fixed label.
#[derive(Debug, Clone, Copy)]
struct KeyDef {
    action: KeyAction,
    /// Width in grid units (24px each at the 240px panel width).
    units: u32,
    /// Fixed label for non-letter/symbol keys; `None` means the display
    /// character is derived from `action` at draw time (case-sensitive to shift).
    label: Option<&'static str>,
}

impl KeyDef {
    /// A single-unit lowercase letter key.
    const fn letter(ch: char) -> Self {
        Self {
            action: KeyAction::Letter(ch),
            units: 1,
            label: None,
        }
    }

    /// A single-unit fixed-symbol key, unaffected by shift.
    const fn symbol(ch: char) -> Self {
        Self {
            action: KeyAction::Symbol(ch),
            units: 1,
            label: None,
        }
    }

    /// A key with a fixed multi-character label spanning `units` grid columns.
    const fn special(action: KeyAction, units: u32, label: &'static str) -> Self {
        Self {
            action,
            units,
            label: Some(label),
        }
    }
}

/// Row 0: `q w e r t y u i o p`.
const ROW0: [KeyDef; 10] = [
    KeyDef::letter('q'),
    KeyDef::letter('w'),
    KeyDef::letter('e'),
    KeyDef::letter('r'),
    KeyDef::letter('t'),
    KeyDef::letter('y'),
    KeyDef::letter('u'),
    KeyDef::letter('i'),
    KeyDef::letter('o'),
    KeyDef::letter('p'),
];

/// Row 1: `a s d f g h j k l` + backspace.
const ROW1: [KeyDef; 10] = [
    KeyDef::letter('a'),
    KeyDef::letter('s'),
    KeyDef::letter('d'),
    KeyDef::letter('f'),
    KeyDef::letter('g'),
    KeyDef::letter('h'),
    KeyDef::letter('j'),
    KeyDef::letter('k'),
    KeyDef::letter('l'),
    KeyDef::special(KeyAction::Backspace, 1, "DEL"),
];

/// Row 2: shift + `z x c v b n m` + `,` + `.`.
const ROW2: [KeyDef; 10] = [
    KeyDef::special(KeyAction::Shift, 1, "^"),
    KeyDef::letter('z'),
    KeyDef::letter('x'),
    KeyDef::letter('c'),
    KeyDef::letter('v'),
    KeyDef::letter('b'),
    KeyDef::letter('n'),
    KeyDef::letter('m'),
    KeyDef::symbol(','),
    KeyDef::symbol('.'),
];

/// Row 3: a single full-width space bar.
const ROW3: [KeyDef; 1] = [KeyDef::special(KeyAction::Space, GRID_UNITS, "SPACE")];

/// Softkey bar: T9 fallback + Done.
const SOFTKEY_ROW: [KeyDef; 2] = [
    KeyDef::special(KeyAction::SwitchToT9, 5, "T9"),
    KeyDef::special(KeyAction::Done, 5, "DONE"),
];

/// All rows, top to bottom, including the softkey bar as the final row.
const ROWS: [&[KeyDef]; NUM_ROWS] = [&ROW0, &ROW1, &ROW2, &ROW3, &SOFTKEY_ROW];

/// Pixel width of one grid unit at the given widget width.
const fn unit_width(width: u32) -> u32 {
    width / GRID_UNITS
}

/// X offset of `col` within `row`, in pixels, relative to the row's start.
fn key_x_start(row: &[KeyDef], uw: u32, col: usize) -> u32 {
    let units: u32 = row.iter().take(col).map(|k| k.units).sum();
    units * uw
}

/// Pixel width of `col` within `row`; zero if `col` is out of range.
fn key_width_px(row: &[KeyDef], uw: u32, col: usize) -> u32 {
    row.get(col).map_or(0, |k| k.units * uw)
}

/// Which key in `row` contains pixel offset `x` (relative to the row's start).
///
/// Clamps to the last key if `x` falls past the row's end.
fn key_at_x(row: &[KeyDef], uw: u32, x: u32) -> usize {
    let mut start = 0u32;
    for (i, k) in row.iter().enumerate() {
        let end = start + k.units * uw;
        if x < end {
            return i;
        }
        start = end;
    }
    row.len().saturating_sub(1)
}

/// Y offset of `row` from the widget's top.
const fn row_y(row: usize) -> u32 {
    if row >= MAIN_ROW_COUNT {
        KEY_ROW_H * MAIN_ROW_COUNT as u32
    } else {
        KEY_ROW_H * row as u32
    }
}

/// Pixel height of `row` (the softkey bar is shorter than the main rows).
const fn row_height(row: usize) -> u32 {
    if row >= MAIN_ROW_COUNT {
        SOFTKEY_ROW_H
    } else {
        KEY_ROW_H
    }
}

/// Which row a Y offset (relative to the widget's top) falls in.
///
/// Clamps to the last row (the softkey bar) for `y` past the grid's bottom.
fn row_at_y(y: u32) -> usize {
    let mut start = 0u32;
    for row in 0..NUM_ROWS {
        let end = start + row_height(row);
        if y < end {
            return row;
        }
        start = end;
    }
    NUM_ROWS.saturating_sub(1)
}

/// Rectangle of a single key on the panel, in absolute framebuffer pixels.
#[derive(Debug, Clone, Copy)]
struct Rect {
    x: u32,
    y: u32,
    w: u32,
    h: u32,
}

/// Result of pressing a key: what the caller (the compose screen, not built
/// here) should do to the text buffer or input mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyboardEvent {
    /// Insert this character (already case-resolved against shift) into the
    /// compose buffer.
    Char(char),
    /// Delete the character before the cursor.
    Backspace,
    /// Switch input to T9 multi-tap -- the accuracy fallback one softkey away.
    SwitchToT9,
    /// Composition is finished (send/save/close is the caller's call).
    Done,
}

/// On-screen QWERTY keyboard: a fixed-pitch touch grid with a keypad-cursor
/// equivalent for every key. See the module docs for the row layout and the
/// dual-input mapping.
///
/// Call [`Keyboard::take_event`] after each input cycle to drain a pending
/// key press.
#[derive(Debug)]
pub struct Keyboard {
    cursor_row: usize,
    cursor_col: usize,
    shift_active: bool,
    pending: Option<KeyboardEvent>,
    focused: bool,
    width: u32,
}

impl Keyboard {
    /// Create a keyboard with the given pixel width (240 on the real panel).
    #[must_use]
    pub(crate) const fn new(width: u32) -> Self {
        Self {
            cursor_row: 0,
            cursor_col: 0,
            shift_active: false,
            pending: None,
            focused: false,
            width,
        }
    }

    /// Return and clear the pending key event, if any.
    pub(crate) const fn take_event(&mut self) -> Option<KeyboardEvent> {
        self.pending.take()
    }

    /// Whether shift is currently toggled on (affects letter case).
    #[must_use]
    pub(crate) const fn is_shift_active(&self) -> bool {
        self.shift_active
    }

    /// Move the highlighted-key cursor up a row, preserving horizontal position.
    fn move_up(&mut self) {
        if self.cursor_row == 0 {
            return;
        }
        self.move_row(self.cursor_row - 1);
    }

    /// Move the highlighted-key cursor down a row, preserving horizontal position.
    fn move_down(&mut self) {
        if self.cursor_row + 1 >= NUM_ROWS {
            return;
        }
        self.move_row(self.cursor_row + 1);
    }

    /// Re-target the cursor at `new_row`, resolving the column nearest the
    /// current key's horizontal center.
    fn move_row(&mut self, new_row: usize) {
        let uw = unit_width(self.width);
        let Some(cur_row) = ROWS.get(self.cursor_row) else {
            return;
        };
        let center = key_x_start(cur_row, uw, self.cursor_col)
            + key_width_px(cur_row, uw, self.cursor_col) / 2;
        let Some(target_row) = ROWS.get(new_row) else {
            return;
        };
        self.cursor_row = new_row;
        self.cursor_col = key_at_x(target_row, uw, center);
    }

    /// Move the highlighted-key cursor left within the current row, clamping at 0.
    const fn move_left(&mut self) {
        if self.cursor_col > 0 {
            self.cursor_col -= 1;
        }
    }

    /// Move the highlighted-key cursor right within the current row, clamping at the end.
    fn move_right(&mut self) {
        let Some(row) = ROWS.get(self.cursor_row) else {
            return;
        };
        if self.cursor_col + 1 < row.len() {
            self.cursor_col += 1;
        }
    }

    /// Press whatever key is currently highlighted.
    fn activate(&mut self) {
        let Some(row) = ROWS.get(self.cursor_row) else {
            return;
        };
        let Some(key) = row.get(self.cursor_col) else {
            return;
        };
        match key.action {
            KeyAction::Letter(ch) => {
                let out = if self.shift_active {
                    ch.to_ascii_uppercase()
                } else {
                    ch
                };
                self.pending = Some(KeyboardEvent::Char(out));
            }
            KeyAction::Symbol(ch) => self.pending = Some(KeyboardEvent::Char(ch)),
            KeyAction::Space => self.pending = Some(KeyboardEvent::Char(' ')),
            KeyAction::Backspace => self.pending = Some(KeyboardEvent::Backspace),
            KeyAction::Shift => self.shift_active = !self.shift_active,
            KeyAction::SwitchToT9 => self.pending = Some(KeyboardEvent::SwitchToT9),
            KeyAction::Done => self.pending = Some(KeyboardEvent::Done),
        }
    }

    /// Background/foreground color for a cell: cursor highlight takes
    /// priority over the shift-active indicator, which takes priority over
    /// the default key color.
    fn cell_colors(&self, row: usize, col: usize, action: KeyAction) -> (Rgb565, Rgb565) {
        if self.focused && row == self.cursor_row && col == self.cursor_col {
            (Rgb565::BLUE, Rgb565::WHITE)
        } else if action == KeyAction::Shift && self.shift_active {
            (Rgb565::CYAN, Rgb565::BLACK)
        } else {
            (KEY_BG, Rgb565::WHITE)
        }
    }

    /// Draw a single key's label, centered in `rect`.
    fn draw_label(&self, fb: &mut Framebuffer, rect: Rect, key: &KeyDef, fg: Rgb565, bg: Rgb565) {
        match key.action {
            KeyAction::Letter(ch) => {
                let disp = if self.shift_active {
                    ch.to_ascii_uppercase()
                } else {
                    ch
                };
                let mut buf = [0u8; 4];
                let s = disp.encode_utf8(&mut buf);
                Self::draw_centered(fb, rect, s, fg, bg);
            }
            KeyAction::Symbol(ch) => {
                let mut buf = [0u8; 4];
                let s = ch.encode_utf8(&mut buf);
                Self::draw_centered(fb, rect, s, fg, bg);
            }
            _ => {
                Self::draw_centered(fb, rect, key.label.unwrap_or(""), fg, bg);
            }
        }
    }

    /// Draw `s` horizontally and vertically centered within `rect`.
    fn draw_centered(fb: &mut Framebuffer, rect: Rect, s: &str, fg: Rgb565, bg: Rgb565) {
        let text_w = str_pixel_width(s);
        let lx = rect.x + rect.w.saturating_sub(text_w) / 2;
        let ly = rect.y + rect.h.saturating_sub(CHAR_HEIGHT) / 2;
        draw_str(fb, lx, ly, s, fg, bg);
    }
}

impl Widget for Keyboard {
    fn draw(&self, fb: &mut Framebuffer, x: u32, y: u32) {
        let uw = unit_width(self.width);
        for (row_idx, row) in ROWS.iter().enumerate() {
            let ry = row_y(row_idx);
            let rh = row_height(row_idx);
            for (col_idx, key) in row.iter().enumerate() {
                let kx = key_x_start(row, uw, col_idx);
                let kw = key.units * uw;
                let rect = Rect {
                    x: x + kx,
                    y: y + ry,
                    w: kw,
                    h: rh,
                };
                let (bg, fg) = self.cell_colors(row_idx, col_idx, key.action);
                fb.fill_rect(
                    rect.x,
                    rect.y,
                    rect.w.saturating_sub(1),
                    rect.h.saturating_sub(1),
                    bg,
                );
                self.draw_label(fb, rect, key, fg, bg);
            }
        }
    }

    fn width(&self) -> u32 {
        self.width
    }

    fn height(&self) -> u32 {
        KEYBOARD_HEIGHT
    }
}

impl Focusable for Keyboard {
    fn on_key(&mut self, key: Key) -> bool {
        match key {
            Key::Up => {
                self.move_up();
                true
            }
            Key::Down => {
                self.move_down();
                true
            }
            Key::Left => {
                self.move_left();
                true
            }
            Key::Right => {
                self.move_right();
                true
            }
            Key::Select => {
                self.activate();
                true
            }
            _ => false,
        }
    }

    fn on_touch(&mut self, point: TouchPoint) -> bool {
        let x = u32::from(point.x);
        let y = u32::from(point.y);
        if x >= self.width || y >= KEYBOARD_HEIGHT {
            return false;
        }
        let row_idx = row_at_y(y);
        let Some(row) = ROWS.get(row_idx) else {
            return false;
        };
        let uw = unit_width(self.width);
        self.cursor_row = row_idx;
        self.cursor_col = key_at_x(row, uw, x);
        self.activate();
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
        let k = Keyboard::new(240);
        assert_eq!(k.width(), 240, "width must match constructor arg");
        assert_eq!(
            k.height(),
            258,
            "height must be 4*57 (main rows) + 30 (softkey bar)"
        );
    }

    #[test]
    fn keypad_reaches_every_key_in_row0() {
        let mut k = Keyboard::new(240);
        k.set_focused(true);
        let expected = "qwertyuiop";
        for (i, ch) in expected.chars().enumerate() {
            k.on_key(Key::Select);
            assert_eq!(
                k.take_event(),
                Some(KeyboardEvent::Char(ch)),
                "column {i} of row 0 must press '{ch}'"
            );
            k.on_key(Key::Right);
        }
    }

    #[test]
    fn keypad_reaches_backspace_at_end_of_row1() {
        let mut k = Keyboard::new(240);
        k.set_focused(true);
        k.on_key(Key::Down); // row 1, col 0 ('a')
        for _ in 0..9 {
            k.on_key(Key::Right);
        }
        k.on_key(Key::Select);
        assert_eq!(
            k.take_event(),
            Some(KeyboardEvent::Backspace),
            "row 1's 10th key must be backspace"
        );
    }

    #[test]
    fn keypad_reaches_shift_comma_period_in_row2() {
        let mut k = Keyboard::new(240);
        k.set_focused(true);
        k.on_key(Key::Down);
        k.on_key(Key::Down); // row 2, col 0 (shift)
        k.on_key(Key::Select);
        assert!(k.is_shift_active(), "row 2 col 0 must be shift, toggled on");
        for _ in 0..8 {
            k.on_key(Key::Right);
        }
        k.on_key(Key::Select);
        assert_eq!(
            k.take_event(),
            Some(KeyboardEvent::Char(',')),
            "row 2 col 8 must be comma"
        );
        k.on_key(Key::Right);
        k.on_key(Key::Select);
        assert_eq!(
            k.take_event(),
            Some(KeyboardEvent::Char('.')),
            "row 2 col 9 must be period"
        );
    }

    #[test]
    fn shift_uppercases_letters_until_toggled_off() {
        let mut k = Keyboard::new(240);
        k.set_focused(true);
        k.on_key(Key::Down);
        k.on_key(Key::Down);
        k.on_key(Key::Select); // toggle shift on
        k.on_key(Key::Left); // no-op, already at col 0
        k.on_key(Key::Right); // col 1: 'z'
        k.on_key(Key::Select);
        assert_eq!(
            k.take_event(),
            Some(KeyboardEvent::Char('Z')),
            "letter pressed while shift is active must be uppercase"
        );
        // Toggle shift back off.
        k.on_key(Key::Left);
        k.on_key(Key::Select);
        assert!(!k.is_shift_active(), "second shift press must toggle off");
        k.on_key(Key::Right);
        k.on_key(Key::Select);
        assert_eq!(
            k.take_event(),
            Some(KeyboardEvent::Char('z')),
            "letter pressed after shift toggles off must be lowercase"
        );
    }

    #[test]
    fn shift_does_not_affect_symbols() {
        let mut k = Keyboard::new(240);
        k.set_focused(true);
        k.on_key(Key::Down);
        k.on_key(Key::Down);
        k.on_key(Key::Select); // shift on
        for _ in 0..8 {
            k.on_key(Key::Right);
        }
        k.on_key(Key::Select);
        assert_eq!(
            k.take_event(),
            Some(KeyboardEvent::Char(',')),
            "comma must be unaffected by an active shift"
        );
    }

    #[test]
    fn keypad_reaches_space_in_row3() {
        let mut k = Keyboard::new(240);
        k.set_focused(true);
        for _ in 0..3 {
            k.on_key(Key::Down);
        }
        k.on_key(Key::Select);
        assert_eq!(
            k.take_event(),
            Some(KeyboardEvent::Char(' ')),
            "row 3 must be a single full-width space key"
        );
    }

    #[test]
    fn keypad_reaches_softkeys() {
        let mut k = Keyboard::new(240);
        k.set_focused(true);
        for _ in 0..4 {
            k.on_key(Key::Down);
        }
        // Descending from column 0 each row preserves a center of x=12,
        // which lands in row 3's single space key, whose own center (x=120)
        // sits exactly on the T9/Done boundary; the half-open interval
        // convention resolves a boundary to the right-hand key (Done).
        k.on_key(Key::Select);
        assert_eq!(
            k.take_event(),
            Some(KeyboardEvent::Done),
            "center x=120 resolves to Done, the boundary's right-hand key"
        );
        k.on_key(Key::Left);
        k.on_key(Key::Select);
        assert_eq!(
            k.take_event(),
            Some(KeyboardEvent::SwitchToT9),
            "softkey col 0 must be T9"
        );
    }

    #[test]
    fn vertical_navigation_preserves_horizontal_position_across_uniform_rows() {
        let mut k = Keyboard::new(240);
        k.set_focused(true);
        // Row 0 col 9 ('p') is centered at x=228 (216..240).
        for _ in 0..9 {
            k.on_key(Key::Right);
        }
        // Row 1 is also 10 uniform 1-unit keys: same center falls in col 9 (backspace).
        k.on_key(Key::Down);
        k.on_key(Key::Select);
        assert_eq!(
            k.take_event(),
            Some(KeyboardEvent::Backspace),
            "preserved column 9 in row 1 must be backspace"
        );
        // Row 2 is likewise 10 uniform 1-unit keys: same center falls in col 9 (period).
        k.on_key(Key::Down);
        k.on_key(Key::Select);
        assert_eq!(
            k.take_event(),
            Some(KeyboardEvent::Char('.')),
            "preserved column 9 in row 2 must be period"
        );
    }

    #[test]
    fn space_row_collapses_and_recenters_from_its_own_width() {
        let mut k = Keyboard::new(240);
        k.set_focused(true);
        // Row 0 col 9 -> row 1 col 9 -> row 2 col 9 (period) -> row 3: the
        // single full-width key absorbs every incoming column.
        for _ in 0..9 {
            k.on_key(Key::Right);
        }
        k.on_key(Key::Down);
        k.on_key(Key::Down);
        k.on_key(Key::Down);
        k.on_key(Key::Select);
        assert_eq!(
            k.take_event(),
            Some(KeyboardEvent::Char(' ')),
            "any column landing in row 3 must hit its one full-width key"
        );
        // Leaving that single wide key, the preserved "position" is its OWN
        // center (x=120, the panel's midpoint) rather than wherever the
        // cursor entered from -- there is no other position to remember once
        // a row collapses to one key. x=120 falls in row 2's column 5 ('b').
        k.on_key(Key::Up);
        k.on_key(Key::Select);
        assert_eq!(
            k.take_event(),
            Some(KeyboardEvent::Char('b')),
            "leaving the space key must re-resolve from its own center, not the prior column"
        );
    }

    #[test]
    fn left_right_clamp_at_row_bounds() {
        let mut k = Keyboard::new(240);
        k.set_focused(true);
        k.on_key(Key::Left);
        k.on_key(Key::Select);
        assert_eq!(
            k.take_event(),
            Some(KeyboardEvent::Char('q')),
            "Left at column 0 must clamp, not wrap"
        );
        for _ in 0..20 {
            k.on_key(Key::Right);
        }
        k.on_key(Key::Select);
        assert_eq!(
            k.take_event(),
            Some(KeyboardEvent::Char('p')),
            "Right past the last column must clamp at the last key"
        );
    }

    #[test]
    fn up_down_clamp_at_grid_bounds() {
        let mut k = Keyboard::new(240);
        k.set_focused(true);
        k.on_key(Key::Up); // already at row 0
        k.on_key(Key::Select);
        assert_eq!(
            k.take_event(),
            Some(KeyboardEvent::Char('q')),
            "Up at row 0 must clamp, not wrap"
        );
        for _ in 0..10 {
            k.on_key(Key::Down);
        }
        k.on_key(Key::Select);
        assert_eq!(
            k.take_event(),
            Some(KeyboardEvent::Done),
            "Down past the last row must clamp at the softkey row, not wrap or panic"
        );
    }

    #[test]
    fn touch_hits_row0_column_edges() {
        let mut k = Keyboard::new(240);
        k.on_touch(TouchPoint::new(0, 0, 100, 0));
        assert_eq!(k.take_event(), Some(KeyboardEvent::Char('q')));
        k.on_touch(TouchPoint::new(23, 0, 100, 0));
        assert_eq!(
            k.take_event(),
            Some(KeyboardEvent::Char('q')),
            "x=23 is the last pixel of column 0 (24px wide)"
        );
        k.on_touch(TouchPoint::new(24, 0, 100, 0));
        assert_eq!(
            k.take_event(),
            Some(KeyboardEvent::Char('w')),
            "x=24 is the first pixel of column 1"
        );
        k.on_touch(TouchPoint::new(239, 0, 100, 0));
        assert_eq!(
            k.take_event(),
            Some(KeyboardEvent::Char('p')),
            "x=239 is the last pixel on the panel, still column 9"
        );
    }

    #[test]
    fn touch_hits_row_boundaries() {
        let mut k = Keyboard::new(240);
        k.on_touch(TouchPoint::new(0, 56, 100, 0));
        assert_eq!(
            k.take_event(),
            Some(KeyboardEvent::Char('q')),
            "y=56 is the last pixel of row 0 (57px tall)"
        );
        k.on_touch(TouchPoint::new(0, 57, 100, 0));
        assert_eq!(
            k.take_event(),
            Some(KeyboardEvent::Char('a')),
            "y=57 is the first pixel of row 1"
        );
        k.on_touch(TouchPoint::new(0, 227, 100, 0));
        assert_eq!(
            k.take_event(),
            Some(KeyboardEvent::Char(' ')),
            "y=227 is the last pixel of row 3 (the space row)"
        );
        k.on_touch(TouchPoint::new(0, 228, 100, 0));
        assert_eq!(
            k.take_event(),
            Some(KeyboardEvent::SwitchToT9),
            "y=228 is the first pixel of the softkey row"
        );
    }

    #[test]
    fn touch_hits_softkey_boundary() {
        let mut k = Keyboard::new(240);
        k.on_touch(TouchPoint::new(119, 228, 100, 0));
        assert_eq!(
            k.take_event(),
            Some(KeyboardEvent::SwitchToT9),
            "x=119 is the last pixel of the T9 softkey (0..120)"
        );
        k.on_touch(TouchPoint::new(120, 228, 100, 0));
        assert_eq!(
            k.take_event(),
            Some(KeyboardEvent::Done),
            "x=120 is the first pixel of the Done softkey"
        );
        k.on_touch(TouchPoint::new(239, 257, 100, 0));
        assert_eq!(
            k.take_event(),
            Some(KeyboardEvent::Done),
            "the panel's last pixel must still hit Done"
        );
    }

    #[test]
    fn touch_out_of_bounds_not_consumed() {
        let mut k = Keyboard::new(240);
        assert!(
            !k.on_touch(TouchPoint::new(240, 0, 100, 0)),
            "x == width is off-widget and must not be consumed"
        );
        assert!(
            !k.on_touch(TouchPoint::new(0, 258, 100, 0)),
            "y == height is off-widget and must not be consumed"
        );
        assert!(
            k.take_event().is_none(),
            "an unconsumed touch must not queue an event"
        );
    }

    #[test]
    fn take_event_drains_pending() {
        let mut k = Keyboard::new(240);
        k.on_touch(TouchPoint::new(0, 0, 100, 0));
        let first = k.take_event();
        let second = k.take_event();
        assert!(first.is_some(), "first take_event must return the press");
        assert!(second.is_none(), "second take_event must be None");
    }

    #[test]
    fn unrelated_key_not_consumed() {
        let mut k = Keyboard::new(240);
        assert!(
            !k.on_key(Key::Call),
            "Call has no meaning on the keyboard grid and must not be consumed"
        );
    }

    #[test]
    fn focus_set_and_cleared() {
        let mut k = Keyboard::new(240);
        assert!(!k.is_focused(), "keyboard must start unfocused");
        k.set_focused(true);
        assert!(k.is_focused(), "must be focused after set_focused(true)");
        k.set_focused(false);
        assert!(
            !k.is_focused(),
            "must be unfocused after set_focused(false)"
        );
    }

    #[test]
    fn draw_does_not_panic() {
        let k = Keyboard::new(240);
        let mut fb = Framebuffer::new(240, 320);
        fb.clear(Rgb565::WHITE);
        k.draw(&mut fb, 0, 62); // below a 20px status + 42px preview
        assert!(
            fb.as_bytes().iter().any(|&b| b != 0xFF),
            "keyboard must write at least one pixel"
        );
    }
}
