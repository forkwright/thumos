//! User interface for the 240×320 framebuffer display. Widget system, keypad navigation, T9 text input, status bar.
//!
//! # Modules
//!
//! - [`framebuffer`]: in-memory `RGB565` pixel buffer with primitive drawing operations.
//! - [`color`]: [`color::Rgb565`] type with named constants and 24-bit conversion.
//! - [`font`]: 8×16 bitmap font with character and string rendering.
//! - [`status_bar`]: top status strip (signal, time, battery).

pub mod color;
pub mod font;
pub mod framebuffer;
pub mod status_bar;

pub use color::Rgb565;
pub use font::{CHAR_HEIGHT, CHAR_WIDTH, draw_char, draw_str};
pub use framebuffer::Framebuffer;
pub use status_bar::StatusBar;
