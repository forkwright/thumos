#![deny(missing_docs)]
#![expect(
    dead_code,
    reason = "API surface pending convergence — tracked in docs/convergence.toml (#545)"
)]
#![allow(unfulfilled_lint_expectations)]
//! Radio analysis tools. `WiFi` AP scanning, `BT` device enumeration, cell tower logging, `IMSI` catcher detection via tower behavior analysis.

pub mod cell;
pub mod config;
pub mod eval;
pub mod wifi;
pub mod wifi_analysis;
