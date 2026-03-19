//! Scrollable text list widget with selection highlight.
//!
//! [`TextList`] renders a bounded list of text items and tracks which item
//! is selected. Navigation is via Up/Down keys or touch tap.

use thumos_haphe::input::{Key, TouchPoint};

use crate::color::Rgb565;
use crate::font::{CHAR_HEIGHT, CHAR_WIDTH, draw_str};
use crate::framebuffer::Framebuffer;
use crate::widget::{Focusable, Widget};

/// Default item height in pixels (matches font character height).
const DEFAULT_ITEM_HEIGHT: u32 = CHAR_HEIGHT;

/// Horizontal text padding in pixels.
const TEXT_PAD_X: u32 = 2;

/// Configuration for a [`TextList`].
#[derive(Debug, Clone)]
pub struct TextListConfig {
    /// Pixel width of the list widget.
    pub width: u32,
    /// Maximum number of items visible at once (determines widget height).
    pub visible_rows: usize,
    /// Height of each row in pixels.
    pub item_height: u32,
    /// Background color for selected item.
    pub selected_bg: Rgb565,
    /// Text color for selected item.
    pub selected_fg: Rgb565,
    /// Normal text color.
    pub text_color: Rgb565,
    /// Normal background color.
    pub bg_color: Rgb565,
}

impl Default for TextListConfig {
    fn default() -> Self {
        Self {
            width: 240,
            visible_rows: 10,
            item_height: DEFAULT_ITEM_HEIGHT,
            selected_bg: Rgb565::BLUE,
            selected_fg: Rgb565::WHITE,
            text_color: Rgb565::WHITE,
            bg_color: Rgb565::BLACK,
        }
    }
}

/// Scrollable list of text items with selection highlight.
///
/// Navigation: Up/Down keys move selection; touch tap selects the tapped row.
/// The list scrolls automatically to keep the selected item in view.
#[derive(Debug)]
pub struct TextList {
    items: Vec<String>,
    /// Index of the selected item.
    selected: usize,
    /// Index of the first visible item.
    scroll_offset: usize,
    config: TextListConfig,
    focused: bool,
}

impl TextList {
    /// Create a new, empty list with the given configuration.
    #[must_use]
    pub const fn new(config: TextListConfig) -> Self {
        Self {
            items: Vec::new(),
            selected: 0,
            scroll_offset: 0,
            config,
            focused: false,
        }
    }

    /// Create a new list with default configuration and given pixel width.
    #[must_use]
    pub fn with_width(width: u32) -> Self {
        Self::new(TextListConfig {
            width,
            ..TextListConfig::default()
        })
    }

    /// Append an item to the list.
    pub fn push(&mut self, item: impl Into<String>) {
        self.items.push(item.into());
    }

    /// Return the currently selected item text, if any items exist.
    #[must_use]
    pub fn selected_item(&self) -> Option<&str> {
        self.items.get(self.selected).map(String::as_str)
    }

    /// Return the selected item index.
    #[must_use]
    pub const fn selected_index(&self) -> usize {
        self.selected
    }

    /// Number of items in the list.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.items.len()
    }

    /// Whether the list is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Move selection up by one, clamping at the top.
    const fn move_up(&mut self) {
        if self.selected > 0 {
            self.selected -= 1;
            self.clamp_scroll();
        }
    }

    /// Move selection down by one, clamping at the bottom.
    const fn move_down(&mut self) {
        if self.selected + 1 < self.items.len() {
            self.selected += 1;
            self.clamp_scroll();
        }
    }

    /// Ensure the selected item is within the visible window.
    const fn clamp_scroll(&mut self) {
        // Scroll up if selected is above the visible window.
        if self.selected < self.scroll_offset {
            self.scroll_offset = self.selected;
        }
        // Scroll down if selected is below the visible window.
        let last_visible = self.scroll_offset + self.config.visible_rows;
        if self.selected >= last_visible {
            self.scroll_offset = self.selected + 1 - self.config.visible_rows;
        }
    }

    /// Return the list item index for a touch y-coordinate relative to widget origin.
    fn row_at_y(&self, rel_y: u32) -> Option<usize> {
        let row = usize::try_from(rel_y / self.config.item_height).ok()?;
        if row < self.config.visible_rows {
            let idx = self.scroll_offset + row;
            if idx < self.items.len() {
                return Some(idx);
            }
        }
        None
    }
}

impl Widget for TextList {
    fn draw(&self, fb: &mut Framebuffer, x: u32, y: u32) {
        for row in 0..self.config.visible_rows {
            let idx = self.scroll_offset + row;
            let row_y = y + u32::try_from(row).unwrap_or(0) * self.config.item_height;
            let (bg, fg) = if idx == self.selected && !self.items.is_empty() {
                (self.config.selected_bg, self.config.selected_fg)
            } else {
                (self.config.bg_color, self.config.text_color)
            };

            // Draw row background.
            fb.fill_rect(x, row_y, self.config.width, self.config.item_height, bg);

            // Draw item text if the index is in range.
            if let Some(text) = self.items.get(idx) {
                let max_chars = usize::try_from(
                    (self.config.width.saturating_sub(TEXT_PAD_X * 2)) / CHAR_WIDTH,
                )
                .unwrap_or(0);
                let display: &str = text
                    .get(
                        ..text
                            .char_indices()
                            .nth(max_chars)
                            .map_or(text.len(), |(i, _)| i),
                    )
                    .unwrap_or(text.as_str());
                draw_str(fb, x + TEXT_PAD_X, row_y, display, fg, bg);
            }
        }
    }

    fn width(&self) -> u32 {
        self.config.width
    }

    fn height(&self) -> u32 {
        u32::try_from(self.config.visible_rows).unwrap_or(0) * self.config.item_height
    }
}

impl Focusable for TextList {
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
            _ => false,
        }
    }

    fn on_touch(&mut self, point: TouchPoint) -> bool {
        // NOTE: caller must translate absolute coordinates to widget-relative.
        if let Some(idx) = self.row_at_y(u32::from(point.y)) {
            self.selected = idx;
            self.clamp_scroll();
            true
        } else {
            false
        }
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

    fn make_list(items: &[&str]) -> TextList {
        let mut list = TextList::with_width(240);
        for item in items {
            list.push(*item);
        }
        list
    }

    #[test]
    fn sizing_matches_config() {
        let list = TextList::new(TextListConfig {
            width: 200,
            visible_rows: 5,
            item_height: 20,
            ..TextListConfig::default()
        });
        assert_eq!(list.width(), 200, "width must match config");
        assert_eq!(
            list.height(),
            100,
            "height must be visible_rows * item_height"
        );
    }

    #[test]
    fn push_increases_len() {
        let mut list = TextList::with_width(240);
        assert_eq!(list.len(), 0, "new list must be empty");
        list.push("alpha");
        list.push("beta");
        assert_eq!(list.len(), 2, "len must equal number of pushed items");
    }

    #[test]
    fn initial_selection_is_zero() {
        let list = make_list(&["a", "b", "c"]);
        assert_eq!(list.selected_index(), 0, "initial selection must be item 0");
        assert_eq!(
            list.selected_item(),
            Some("a"),
            "selected item must match first item"
        );
    }

    #[test]
    fn down_key_advances_selection() {
        let mut list = make_list(&["a", "b", "c"]);
        let consumed = list.on_key(Key::Down);
        assert!(consumed, "Down key must be consumed by list");
        assert_eq!(
            list.selected_index(),
            1,
            "selection must advance after Down"
        );
    }

    #[test]
    fn up_key_at_top_clamps() {
        let mut list = make_list(&["a", "b"]);
        let consumed = list.on_key(Key::Up);
        assert!(consumed, "Up key must be consumed even at top");
        assert_eq!(
            list.selected_index(),
            0,
            "selection must stay at 0 when already at top"
        );
    }

    #[test]
    fn down_key_at_bottom_clamps() {
        let mut list = make_list(&["a", "b"]);
        list.on_key(Key::Down);
        list.on_key(Key::Down); // try to go past end
        assert_eq!(
            list.selected_index(),
            1,
            "selection must clamp at last item"
        );
    }

    #[test]
    fn scroll_offset_tracks_selection() {
        let mut list = TextList::new(TextListConfig {
            width: 240,
            visible_rows: 3,
            item_height: 16,
            ..TextListConfig::default()
        });
        for i in 0..10u8 {
            list.push(i.to_string());
        }
        // Navigate down past the visible window.
        for _ in 0..5 {
            list.on_key(Key::Down);
        }
        assert_eq!(list.selected_index(), 5, "selection must be at index 5");
        assert!(
            list.scroll_offset <= list.selected_index(),
            "scroll_offset must not exceed selected index"
        );
        assert!(
            list.scroll_offset + list.config.visible_rows > list.selected_index(),
            "selected item must be within visible window"
        );
    }

    #[test]
    fn touch_selects_row() {
        let mut list = TextList::new(TextListConfig {
            width: 240,
            visible_rows: 5,
            item_height: 20,
            ..TextListConfig::default()
        });
        for ch in ["a", "b", "c", "d", "e"] {
            list.push(ch);
        }
        let touch = TouchPoint {
            x: 10,
            y: 42, // row 2 (y=42 / item_height=20 => row 2)
            pressure: 100,
            tracking_id: 0,
        };
        let consumed = list.on_touch(touch);
        assert!(consumed, "touch within list must be consumed");
        assert_eq!(
            list.selected_index(),
            2,
            "touch at row 2 must select index 2"
        );
    }

    #[test]
    fn unrelated_key_not_consumed() {
        let mut list = make_list(&["a"]);
        let consumed = list.on_key(Key::Select);
        assert!(!consumed, "Select key must not be consumed by TextList");
    }

    #[test]
    fn focus_set_and_cleared() {
        let mut list = make_list(&["a"]);
        assert!(!list.is_focused(), "list must start unfocused");
        list.set_focused(true);
        assert!(
            list.is_focused(),
            "list must report focused after set_focused(true)"
        );
        list.set_focused(false);
        assert!(
            !list.is_focused(),
            "list must report unfocused after set_focused(false)"
        );
    }

    #[test]
    fn draw_does_not_panic_on_empty_list() {
        let list = TextList::with_width(240);
        let mut fb = Framebuffer::new(240, 320);
        // NOTE: should complete without panic or index error
        list.draw(&mut fb, 0, 0);
    }
}
