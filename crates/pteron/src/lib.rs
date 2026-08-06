#![deny(missing_docs)]
#![expect(
    dead_code,
    reason = "API surface pending convergence — tracked in docs/convergence.toml (#545)"
)]
#![allow(unfulfilled_lint_expectations)]
//! Bluetooth driver: HCI transport over STP, BLE scanning and device discovery, classic pairing.
//!
//! # LE Privacy
//!
//! All LE HCI commands use `Own_Address_Type = 0x01` (Random).  The
//! [`transport`] module manages address rotation at 15-minute intervals.

pub mod ble;
pub mod config;
pub mod device;
pub mod hci;
pub mod smp;
pub mod transport;
