//! Nested menu system for the 240×320 display.
//!
//! [`Menu`] supports a main menu and arbitrarily deep submenus. Each item
//! carries a label, an optional single-character icon, and an action ID that
//! the caller uses to dispatch work. Navigation is by Up/Down/Select; the
//! Left key (or a back-button item) pops the navigation stack.

use alloc::string::String;
use alloc::vec::Vec;

use haphe::input::{Key, TouchPoint};

use crate::color::Rgb565;
use crate::font::{CHAR_HEIGHT, CHAR_WIDTH, draw_str};
use crate::framebuffer::Framebuffer;
use crate::widget::{Focusable, Widget};

/// Height of a single menu row in pixels.
const ROW_HEIGHT: u32 = CHAR_HEIGHT + 4;

/// Horizontal text padding.
const PAD_X: u32 = 4;

/// Sentinel action ID meaning "no action taken yet / still navigating".
pub const ACTION_NONE: u32 = u32::MAX;

/// A single item in a [`Menu`].
#[derive(Debug, Clone)]
#[expect(clippy::use_self, reason = "Self cannot be used in struct field types")]
pub struct MenuItem {
    /// Display label.
    pub(crate) label: String,
    /// Optional single-character icon rendered before the label.
    pub(crate) icon: Option<char>,
    /// Action ID returned to the caller when this item is selected.
    /// Use [`ACTION_NONE`] for items that only open a submenu.
    pub(crate) action_id: u32,
    /// Optional submenu opened when this item is selected.
    pub(crate) submenu: Option<Vec<MenuItem>>,
}

impl MenuItem {
    /// Create a leaf item with no submenu.
    #[must_use]
    pub(crate) fn leaf(label: impl Into<String>, action_id: u32) -> Self {
        Self {
            label: label.into(),
            icon: None,
            action_id,
            submenu: None,
        }
    }

    /// Create a leaf item with an icon.
    #[must_use]
    pub(crate) fn with_icon(label: impl Into<String>, icon: char, action_id: u32) -> Self {
        Self {
            label: label.into(),
            icon: Some(icon),
            action_id,
            submenu: None,
        }
    }

    /// Create a folder item that opens a submenu. `action_id` is [`ACTION_NONE`].
    #[must_use]
    #[expect(
        clippy::use_self,
        reason = "Self cannot be used in function parameter types"
    )]
    pub(crate) fn folder(label: impl Into<String>, children: Vec<MenuItem>) -> Self {
        Self {
            label: label.into(),
            icon: None,
            action_id: ACTION_NONE,
            submenu: Some(children),
        }
    }
}

/// Navigation stack frame: saved items and cursor position.
#[derive(Debug, Clone)]
struct NavFrame {
    items: Vec<MenuItem>,
    cursor: usize,
}

/// Nested menu widget.
///
/// Call [`Menu::take_action`] after each input cycle to retrieve a pending
/// action ID, then call [`Menu::clear_action`] to reset it.
#[derive(Debug)]
pub struct Menu {
    /// Currently displayed items.
    current: Vec<MenuItem>,
    /// Cursor within current items.
    cursor: usize,
    /// Navigation stack for Back support.
    nav_stack: Vec<NavFrame>,
    /// Pending action set when an item is activated.
    pending_action: Option<u32>,
    width: u32,
    visible_rows: usize,
    focused: bool,
}

impl Menu {
    /// Create a new menu with the given root items and pixel width.
    ///
    /// Time: O(1) — takes ownership of the already-built `items` `Vec` by
    /// move; it is not iterated or copied.
    /// Space: O(1) auxiliary — `nav_stack` starts as an empty `Vec::new()`,
    /// which performs no allocation (the memory backing `items` was already
    /// allocated by the caller and is only moved, not duplicated).
    #[must_use]
    pub(crate) const fn new(items: Vec<MenuItem>, width: u32) -> Self {
        Self {
            current: items,
            cursor: 0,
            nav_stack: Vec::new(),
            pending_action: None,
            width,
            visible_rows: 10,
            focused: false,
        }
    }

    /// Set the number of rows visible at once (controls widget height).
    #[must_use]
    pub(crate) const fn with_visible_rows(mut self, rows: usize) -> Self {
        self.visible_rows = rows;
        self
    }

    /// Return and clear the pending action, if any.
    pub(crate) const fn take_action(&mut self) -> Option<u32> {
        self.pending_action.take()
    }

    /// Whether the menu has navigated into a submenu (i.e., Back is possible).
    #[must_use]
    pub(crate) const fn can_go_back(&self) -> bool {
        !self.nav_stack.is_empty()
    }

    /// Activate the currently selected item: push submenu or set action.
    fn activate(&mut self) {
        let Some(item) = self.current.get(self.cursor) else {
            return;
        };
        if let Some(sub) = item.submenu.clone() {
            // Push current level onto stack and descend.
            self.nav_stack.push(NavFrame {
                items: self.current.clone(),
                cursor: self.cursor,
            });
            self.current = sub;
            self.cursor = 0;
        } else {
            self.pending_action = Some(item.action_id);
        }
    }

    /// Pop the navigation stack (go back to the parent menu).
    fn go_back(&mut self) {
        if let Some(frame) = self.nav_stack.pop() {
            self.current = frame.items;
            self.cursor = frame.cursor;
        }
    }

    /// Scroll offset for the visible window.
    const fn scroll_offset(&self) -> usize {
        if self.cursor >= self.visible_rows {
            self.cursor + 1 - self.visible_rows
        } else {
            0
        }
    }
}

impl Widget for Menu {
    fn draw(&self, fb: &mut Framebuffer, x: u32, y: u32) {
        let offset = self.scroll_offset();
        for row in 0..self.visible_rows {
            let idx = offset + row;
            let row_y = y + u32::try_from(row).unwrap_or(0) * ROW_HEIGHT;
            let (bg, fg) = if idx == self.cursor {
                (Rgb565::BLUE, Rgb565::WHITE)
            } else {
                (Rgb565::BLACK, Rgb565::WHITE)
            };
            fb.fill_rect(x, row_y, self.width, ROW_HEIGHT, bg);

            let Some(item) = self.current.get(idx) else {
                continue;
            };

            let mut text_x = x + PAD_X;

            // Render icon prefix if present.
            if let Some(icon) = item.icon {
                let mut buf = [0u8; 4];
                let icon_str = icon.encode_utf8(&mut buf);
                draw_str(fb, text_x, row_y + 2, icon_str, fg, bg);
                text_x += CHAR_WIDTH + 2;
            }

            // Render label, truncated to fit.
            let available_px = self.width.saturating_sub(text_x - x);
            let max_chars = usize::try_from(available_px / CHAR_WIDTH).unwrap_or(0);
            let display: &str = item
                .label
                .get(
                    ..item
                        .label
                        .char_indices()
                        .nth(max_chars)
                        .map_or(item.label.len(), |(i, _)| i),
                )
                .unwrap_or(item.label.as_str());
            draw_str(fb, text_x, row_y + 2, display, fg, bg);

            // Draw submenu indicator.
            if item.submenu.is_some() {
                let indicator_x = x + self.width.saturating_sub(CHAR_WIDTH + PAD_X);
                draw_str(fb, indicator_x, row_y + 2, ">", fg, bg);
            }
        }
    }

    fn width(&self) -> u32 {
        self.width
    }

    fn height(&self) -> u32 {
        u32::try_from(self.visible_rows).unwrap_or(0) * ROW_HEIGHT
    }
}

impl Focusable for Menu {
    fn on_key(&mut self, key: Key) -> bool {
        match key {
            Key::Up => {
                if self.cursor > 0 {
                    self.cursor -= 1;
                }
                true
            }
            Key::Down => {
                if self.cursor + 1 < self.current.len() {
                    self.cursor += 1;
                }
                true
            }
            Key::Select | Key::Right => {
                self.activate();
                true
            }
            Key::Left => {
                self.go_back();
                true
            }
            _ => false,
        }
    }

    fn on_touch(&mut self, point: TouchPoint) -> bool {
        let row = usize::try_from(u32::from(point.y) / ROW_HEIGHT).unwrap_or(0);
        let idx = self.scroll_offset() + row;
        if idx < self.current.len() {
            if self.cursor == idx {
                // Tap already-selected item: activate.
                self.activate();
            } else {
                self.cursor = idx;
            }
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
    use alloc::vec;

    use super::*;

    fn root_items() -> Vec<MenuItem> {
        vec![
            MenuItem::leaf("Calls", 1),
            MenuItem::leaf("Messages", 2),
            MenuItem::folder(
                "Settings",
                vec![MenuItem::leaf("Display", 10), MenuItem::leaf("Sound", 11)],
            ),
        ]
    }

    #[test]
    fn sizing_matches_visible_rows() {
        let menu = Menu::new(root_items(), 240).with_visible_rows(5);
        assert_eq!(menu.width(), 240, "width must match constructor arg");
        assert_eq!(
            menu.height(),
            5 * ROW_HEIGHT,
            "height must equal visible_rows * ROW_HEIGHT"
        );
    }

    #[test]
    fn down_up_navigation() {
        let mut menu = Menu::new(root_items(), 240);
        assert_eq!(menu.cursor, 0, "cursor must start at 0");
        menu.on_key(Key::Down);
        assert_eq!(menu.cursor, 1, "Down must advance cursor");
        menu.on_key(Key::Up);
        assert_eq!(menu.cursor, 0, "Up must retreat cursor");
    }

    #[test]
    fn down_clamps_at_last_item() {
        let mut menu = Menu::new(root_items(), 240);
        for _ in 0..10 {
            menu.on_key(Key::Down);
        }
        assert_eq!(
            menu.cursor,
            root_items().len() - 1,
            "cursor must clamp at last item"
        );
    }

    #[test]
    fn select_leaf_sets_pending_action() {
        let mut menu = Menu::new(root_items(), 240);
        menu.on_key(Key::Select);
        assert_eq!(
            menu.take_action(),
            Some(1),
            "activating leaf must SET action_id 1"
        );
    }

    #[test]
    fn select_folder_descends_submenu() {
        let mut menu = Menu::new(root_items(), 240);
        // Navigate to Settings (index 2).
        menu.on_key(Key::Down);
        menu.on_key(Key::Down);
        menu.on_key(Key::Select);
        assert_eq!(
            menu.current.len(),
            2,
            "must be inside Settings submenu with 2 items"
        );
        assert!(
            menu.can_go_back(),
            "can_go_back must be true inside submenu"
        );
    }

    #[test]
    fn back_returns_to_parent() {
        let mut menu = Menu::new(root_items(), 240);
        // Go into Settings.
        menu.on_key(Key::Down);
        menu.on_key(Key::Down);
        menu.on_key(Key::Select);
        // Go back.
        menu.on_key(Key::Left);
        assert_eq!(
            menu.current.len(),
            root_items().len(),
            "after Back must be at root with 3 items"
        );
        assert!(!menu.can_go_back(), "can_go_back must be false at root");
    }

    #[test]
    fn back_at_root_is_no_op() {
        let mut menu = Menu::new(root_items(), 240);
        let consumed = menu.on_key(Key::Left);
        assert!(consumed, "Left must be consumed even at root");
        assert_eq!(
            menu.cursor, 0,
            "cursor must be unchanged at root after Left"
        );
    }

    #[test]
    fn take_action_clears_pending() {
        let mut menu = Menu::new(root_items(), 240);
        menu.on_key(Key::Select);
        let first = menu.take_action();
        let second = menu.take_action();
        assert!(first.is_some(), "first take_action must return the action");
        assert!(
            second.is_none(),
            "second take_action must return None after clearing"
        );
    }
}
