//! Modal dialog widget with configurable button set.
//!
//! [`Dialog`] renders a centered title, a message body, and a row of
//! buttons (OK, Cancel, Yes, No) at the bottom. The caller queries
//! [`Dialog::take_result`] to learn which button was activated.

use haphe::input::{Key, TouchPoint};

use crate::color::Rgb565;
use crate::font::{CHAR_HEIGHT, CHAR_WIDTH, draw_str};
use crate::framebuffer::Framebuffer;
use crate::widget::{Focusable, Widget};

/// Pixel padding inside the dialog border.
const PAD: u32 = 4;

/// Height of the button row in pixels.
const BTN_ROW_HEIGHT: u32 = CHAR_HEIGHT + 8;

/// Minimum number of text rows for the message area.
const MIN_MSG_ROWS: u32 = 2;

/// A button available in a [`Dialog`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DialogButton {
    /// Confirm action.
    Ok,
    /// Cancel action.
    Cancel,
    /// Affirmative response.
    Yes,
    /// Negative response.
    No,
}

impl DialogButton {
    /// Short label rendered on the button.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Ok => "OK",
            Self::Cancel => "Cancel",
            Self::Yes => "Yes",
            Self::No => "No",
        }
    }
}

/// Modal dialog widget.
///
/// Navigate buttons with Left/Right, confirm with Select. The dialog
/// stores at most one pending result; call [`Dialog::take_result`] after
/// each input cycle to drain it.
#[derive(Debug)]
pub struct Dialog {
    title: String,
    message: String,
    buttons: Vec<DialogButton>,
    /// Index of the currently highlighted button.
    selected_btn: usize,
    /// Pending button result after activation.
    pending: Option<DialogButton>,
    width: u32,
    focused: bool,
}

impl Dialog {
    /// Create a dialog with the given title, message, and button set.
    ///
    /// # Panics (dev only)
    ///
    /// Panics in debug builds if `buttons` is empty.
    #[must_use]
    pub fn new(
        title: impl Into<String>,
        message: impl Into<String>,
        buttons: Vec<DialogButton>,
    ) -> Self {
        debug_assert!(!buttons.is_empty(), "dialog must have at least one button");
        Self {
            title: title.into(),
            message: message.into(),
            buttons,
            selected_btn: 0,
            pending: None,
            width: 200,
            focused: false,
        }
    }

    /// Create a simple OK dialog.
    #[must_use]
    pub fn ok(title: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(title, message, vec![DialogButton::Ok])
    }

    /// Create a Yes/No confirmation dialog.
    #[must_use]
    pub fn confirm(title: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(title, message, vec![DialogButton::Yes, DialogButton::No])
    }

    /// Set the pixel width of the dialog box.
    #[must_use]
    pub const fn with_width(mut self, width: u32) -> Self {
        self.width = width;
        self
    }

    /// Return and clear the pending button selection, if any.
    pub const fn take_result(&mut self) -> Option<DialogButton> {
        self.pending.take()
    }

    /// Confirm the currently highlighted button.
    fn confirm_selected(&mut self) {
        if let Some(&btn) = self.buttons.get(self.selected_btn) {
            self.pending = Some(btn);
        }
    }

    /// Number of pixel rows needed for the title bar.
    const fn title_height() -> u32 {
        CHAR_HEIGHT + PAD * 2
    }

    /// Number of pixel rows needed for the message area.
    fn msg_height(&self) -> u32 {
        let cols = usize::try_from(self.usable_width() / CHAR_WIDTH)
            .unwrap_or(1)
            .max(1);
        let lines = self.message.len().div_ceil(cols);
        let lines = lines.max(usize::try_from(MIN_MSG_ROWS).unwrap_or(2));
        u32::try_from(lines).unwrap_or(MIN_MSG_ROWS) * CHAR_HEIGHT + PAD * 2
    }

    /// Width available for text inside the dialog (excludes padding).
    const fn usable_width(&self) -> u32 {
        self.width.saturating_sub(PAD * 2)
    }

    /// Width allocated per button.
    fn btn_width(&self) -> u32 {
        let n = u32::try_from(self.buttons.len().max(1)).unwrap_or(1);
        self.usable_width() / n
    }
}

impl Widget for Dialog {
    fn draw(&self, fb: &mut Framebuffer, x: u32, y: u32) {
        let h = self.height();
        // Dialog background.
        fb.fill_rect(x, y, self.width, h, Rgb565::from_rgb(30, 30, 80));

        // Title bar.
        fb.fill_rect(x, y, self.width, Self::title_height(), Rgb565::BLUE);
        let title_display: &str = self
            .title
            .get(
                ..self
                    .title
                    .char_indices()
                    .nth(usize::try_from(self.usable_width() / CHAR_WIDTH).unwrap_or(0))
                    .map_or(self.title.len(), |(i, _)| i),
            )
            .unwrap_or(self.title.as_str());
        draw_str(
            fb,
            x + PAD,
            y + PAD,
            title_display,
            Rgb565::WHITE,
            Rgb565::BLUE,
        );

        // Message text.
        let msg_y = y + Self::title_height();
        draw_str(
            fb,
            x + PAD,
            msg_y + PAD,
            &self.message,
            Rgb565::WHITE,
            Rgb565::from_rgb(30, 30, 80),
        );

        // Button row.
        let btn_y = y + h - BTN_ROW_HEIGHT;
        let btn_w = self.btn_width();
        for (i, btn) in self.buttons.iter().enumerate() {
            let btn_x = x + PAD + u32::try_from(i).unwrap_or(0) * btn_w;
            let (bg, fg) = if i == self.selected_btn {
                (Rgb565::WHITE, Rgb565::from_rgb(30, 30, 80))
            } else {
                (Rgb565::from_rgb(60, 60, 120), Rgb565::WHITE)
            };
            fb.fill_rect(btn_x, btn_y, btn_w.saturating_sub(2), BTN_ROW_HEIGHT, bg);
            draw_str(fb, btn_x + 2, btn_y + 4, btn.label(), fg, bg);
        }
    }

    fn width(&self) -> u32 {
        self.width
    }

    fn height(&self) -> u32 {
        Self::title_height() + self.msg_height() + BTN_ROW_HEIGHT
    }
}

impl Focusable for Dialog {
    fn on_key(&mut self, key: Key) -> bool {
        match key {
            Key::Left => {
                if self.selected_btn > 0 {
                    self.selected_btn -= 1;
                }
                true
            }
            Key::Right => {
                if self.selected_btn + 1 < self.buttons.len() {
                    self.selected_btn += 1;
                }
                true
            }
            Key::Select => {
                self.confirm_selected();
                true
            }
            _ => false,
        }
    }

    fn on_touch(&mut self, point: TouchPoint) -> bool {
        let btn_w = self.btn_width();
        if btn_w == 0 {
            return false;
        }
        let rel_x = u32::from(point.x).saturating_sub(PAD);
        let btn_idx = usize::try_from(rel_x / btn_w).unwrap_or(0);
        if btn_idx < self.buttons.len() {
            self.selected_btn = btn_idx;
            self.confirm_selected();
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

    #[test]
    fn ok_dialog_sizing() {
        let d = Dialog::ok("Alert", "Something happened").with_width(200);
        assert_eq!(d.width(), 200, "width must match constructor");
        assert!(d.height() > 0, "height must be positive");
    }

    #[test]
    fn select_ok_returns_ok_button() {
        let mut d = Dialog::ok("Title", "Message");
        d.on_key(Key::Select);
        assert_eq!(
            d.take_result(),
            Some(DialogButton::Ok),
            "Select must yield Ok button"
        );
    }

    #[test]
    fn confirm_dialog_right_then_select_returns_no() {
        let mut d = Dialog::confirm("Question", "Are you sure?");
        d.on_key(Key::Right); // move to No
        d.on_key(Key::Select);
        assert_eq!(
            d.take_result(),
            Some(DialogButton::No),
            "Right + Select must yield No button"
        );
    }

    #[test]
    fn left_at_first_button_clamps() {
        let mut d = Dialog::confirm("Q", "M");
        d.on_key(Key::Left); // already at index 0
        assert_eq!(d.selected_btn, 0, "Left at index 0 must clamp at 0");
    }

    #[test]
    fn take_result_clears_pending() {
        let mut d = Dialog::ok("T", "M");
        d.on_key(Key::Select);
        let first = d.take_result();
        let second = d.take_result();
        assert!(first.is_some(), "first take_result must return the result");
        assert!(second.is_none(), "second take_result must be None");
    }

    #[test]
    fn focus_set_and_cleared() {
        let mut d = Dialog::ok("T", "M");
        assert!(!d.is_focused(), "dialog must start unfocused");
        d.set_focused(true);
        assert!(d.is_focused(), "must be focused after set_focused(true)");
        d.set_focused(false);
        assert!(
            !d.is_focused(),
            "must be unfocused after set_focused(false)"
        );
    }

    #[test]
    fn draw_does_not_panic() {
        let d = Dialog::confirm("Alert", "Delete everything?");
        let mut fb = Framebuffer::new(240, 320);
        // NOTE: should not panic
        d.draw(&mut fb, 20, 100);
    }
}
