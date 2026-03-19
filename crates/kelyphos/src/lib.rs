//! WMT (Wireless Management Task) connectivity manager for the MT6739 combo chip.
//!
//! Manages firmware loading, power control, and STP framing for the integrated
//! `WiFi`/`BT`/`GPS`/FM combo chip. All radio subsystems communicate through
//! the WMT layer via STP (Serial Transport Protocol).

pub mod stp;
