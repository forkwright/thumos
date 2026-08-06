#![deny(missing_docs)]
#![expect(
    dead_code,
    reason = "API surface pending convergence — tracked in docs/convergence.toml (#545)"
)]
#![allow(unfulfilled_lint_expectations)]
//! GPS driver and position service for the MT6739 combo chip.
//!
//! `NMEA` sentence parsing, coordinate logging, geofence evaluation,
//! track recording. GPS data arrives via `CCCI` channel or UART.

pub mod error;
pub mod nmea;
pub mod position;
