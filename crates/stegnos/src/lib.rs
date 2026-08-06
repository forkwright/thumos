#![deny(missing_docs)]
#![expect(
    dead_code,
    reason = "API surface pending convergence — tracked in docs/convergence.toml (#545)"
)]
#![allow(unfulfilled_lint_expectations)]
//! Encrypted block device management. `dm-crypt` setup, LUKS key derivation, `TPM` `PCR` sealing, secure key storage.

pub mod cipher;
pub mod config;
pub mod erase;
pub mod keys;
