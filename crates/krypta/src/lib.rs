//! End-to-end encrypted communication. Signal protocol key exchange and message encryption, peer-to-peer messaging over `WiFi` Direct and Bluetooth.

pub mod error;
pub mod identity;
pub mod ratchet;
pub mod session;
pub mod x3dh;

pub use error::{Error, Result};
