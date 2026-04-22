#![deny(missing_docs)]
#![expect(dead_code, reason = "public API surface for future kernel binary integration (#126)")]
#![allow(unfulfilled_lint_expectations)]
//! Encrypted block device management. `dm-crypt` setup, LUKS key derivation, `TPM` `PCR` sealing, secure key storage.

pub mod cipher;
pub mod config;
pub mod erase;
pub mod keys;
