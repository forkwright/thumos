#![deny(missing_docs)]
#![expect(
    dead_code,
    reason = "public API surface for future kernel binary integration (#126)"
)]
#![allow(unfulfilled_lint_expectations)]
//! WMT (Wireless Management Task) connectivity manager for the MT6739 combo chip.
//!
//! Manages firmware loading, power control, and STP framing for the integrated
//! `WiFi`/`BT`/`GPS`/FM combo chip. All radio subsystems communicate through
//! the WMT layer via STP (Serial Transport Protocol).

pub mod config;
pub mod stp;
pub mod transport;
pub mod wmt;
