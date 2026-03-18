//! GPS driver and position service for the MT6739 combo chip.
//!
//! `NMEA` sentence parsing, coordinate logging, geofence evaluation,
//! track recording. GPS data arrives via `CCCI` channel or UART.

pub mod error;
pub mod nmea;
pub mod position;
