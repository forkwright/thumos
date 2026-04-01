//! Bluetooth driver: HCI transport over STP, BLE scanning and device discovery, classic pairing.
//!
//! # LE Privacy
//!
//! All LE HCI commands use `Own_Address_Type = 0x01` (Random).  The
//! [`transport`] module manages address rotation at 15-minute intervals.

pub mod ble;
pub mod device;
pub mod hci;
pub mod transport;
