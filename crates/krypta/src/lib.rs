#![deny(missing_docs)]
#![expect(
    dead_code,
    reason = "public API surface for future kernel binary integration (#126)"
)]
#![allow(unfulfilled_lint_expectations)]
//! End-to-end encrypted communication. Signal protocol key exchange and message encryption, peer-to-peer messaging over `WiFi` Direct and Bluetooth.

pub mod error;
pub mod identity;
pub mod ratchet;
pub mod session;
pub mod x3dh;

pub use error::{Error, Result};
