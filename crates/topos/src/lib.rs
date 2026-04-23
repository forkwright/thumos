#![deny(missing_docs)]
#![expect(
    dead_code,
    reason = "public API surface for future kernel binary integration (#126)"
)]
#![allow(unfulfilled_lint_expectations)]
//! GPS driver and position service for the MT6739 combo chip.
//!
//! `NMEA` sentence parsing, coordinate logging, geofence evaluation,
//! track recording. GPS data arrives via `CCCI` channel or UART.

pub mod error;
pub mod nmea;
pub mod position;
