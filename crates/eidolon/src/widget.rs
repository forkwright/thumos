//! Widget and focusable traits for the 240×320 framebuffer UI.
//!
//! All UI components implement [`Widget`] for rendering and optionally
//! [`Focusable`] for interactive input handling.

use haphe::input::{Key, TouchPoint};

use crate::framebuffer::Framebuffer;

/// Renderable UI component.
///
/// Every widget knows its own size and can draw itself at an arbitrary
/// position in the framebuffer. Layout is caller-managed; widgets clip
/// to the framebuffer bounds automatically through [`Framebuffer`] primitives.
pub trait Widget {
    /// Draw the widget at pixel position `(x, y)`.
    fn draw(&self, fb: &mut Framebuffer, x: u32, y: u32);

    /// Width of the widget in pixels.
    fn width(&self) -> u32;

    /// Height of the widget in pixels.
    fn height(&self) -> u32;
}

/// Interactive widget that can receive keyboard and touch input.
///
/// Widgets that can hold focus implement this trait in addition to
/// [`Widget`]. Returning `true` from an input handler means the event
/// was consumed and should not propagate further.
pub trait Focusable {
    /// Handle a key press event.
    ///
    /// Returns `true` if the widget consumed the key.
    fn on_key(&mut self, key: Key) -> bool;

    /// Handle a touch event.
    ///
    /// Returns `true` if the widget consumed the touch.
    fn on_touch(&mut self, point: TouchPoint) -> bool;

    /// Whether this widget currently holds focus.
    fn is_focused(&self) -> bool;

    /// Set or clear focus on this widget.
    fn set_focused(&mut self, focused: bool);
}
