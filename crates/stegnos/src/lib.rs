//! Encrypted block device management. `dm-crypt` setup, LUKS key derivation, `TPM` `PCR` sealing, secure key storage.

pub mod cipher;
pub mod erase;
pub mod keys;
