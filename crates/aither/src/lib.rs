#![deny(missing_docs)]
#![expect(
    dead_code,
    reason = "API surface pending convergence — tracked in docs/convergence.toml (#545)"
)]
#![allow(unfulfilled_lint_expectations)]
//! `WiFi` MAC driver and `WPA2`/`WPA3` supplicant. Scanning, association, EAPOL 4-way handshake, SAE key exchange.

pub mod eapol;
pub(crate) mod mac;
pub mod network;
pub mod wpa;
