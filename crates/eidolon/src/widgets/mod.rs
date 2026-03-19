//! Concrete widget implementations.
//!
//! All widgets implement [`crate::widget::Widget`] for rendering and
//! optionally [`crate::widget::Focusable`] for input handling.

pub mod dialer;
pub mod dialog;
pub mod list;
pub mod menu;

pub use dialer::PhoneDialer;
pub use dialog::{Dialog, DialogButton};
pub use list::{TextList, TextListConfig};
pub use menu::{ACTION_NONE, Menu, MenuItem};
