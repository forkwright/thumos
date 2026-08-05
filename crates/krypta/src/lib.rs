#![deny(missing_docs)]
#![expect(
    dead_code,
    reason = "public API surface for future kernel binary integration (#126)"
)]
#![allow(unfulfilled_lint_expectations)]
//! End-to-end encrypted communication: X3DH key exchange plus message
//! encryption via directional symmetric chain ratchets (one HMAC chain per
//! direction, forward secrecy per message). Peer-to-peer messaging over
//! `WiFi` Direct and Bluetooth.
//!
//! NOT the Signal Double Ratchet: there is no DH ratchet or root chain here
//! (#543). X3DH is implemented per spec; the ratchet is a simpler symmetric
//! chain and is named that way everywhere in this crate. The surface is
//! non-production and unreachable from the kernel until the declared
//! protocol is mechanically verified end-to-end.

pub mod error;
pub mod identity;
pub mod ratchet;
pub mod session;
pub mod x3dh;

pub use error::{Error, Result};
