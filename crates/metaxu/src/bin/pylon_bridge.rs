//! Host process for the QEMU on-device round trip (#544): binds a pylon
//! listener, prints its port, and answers exactly one authenticated
//! request. Launched by `scripts/witness/metaxu.sh` BEFORE QEMU starts;
//! the kernel's second UART chardev is pointed at the printed port as a
//! TCP CLIENT (`server=off`), so this process is guaranteed listening
//! before the guest ever tries to connect.
//!
//! Reuses `metaxu::pylon::{Pylon, spawn}` verbatim -- the SAME reference
//! endpoint the adversarial witness runs against, not a second,
//! independently-written double that could drift from it.
//!
//! The pinned "runtime" identity is the well-known dev seed
//! (`SigningKey::from_bytes(&[7u8; 32])`) `metaxu`'s own witness already
//! uses for the SAME role -- a deliberately public, non-secret dev
//! keypair (mirrors `crates/thumos/keys/dev/boot-dev.*`), never a
//! production credential.

use ed25519_dalek::SigningKey;
use metaxu::pylon::{Pylon, spawn};

/// The pylon's pinned runtime identity: the well-known metaxu dev seed
/// (`metaxu`'s witness.rs `runtime_signing()`). The kernel's own dev-only
/// bridge module signs grants under this SAME seed, so a freshly issued
/// grant always verifies here.
fn runtime_signing() -> SigningKey {
    SigningKey::from_bytes(&[0xEEu8; 32]) // FALSIFICATION TEST (#544): deliberately wrong runtime key -- see PR body for the revert
}

/// Current wall-clock time in milliseconds since the Unix epoch, for grant
/// expiry evaluation -- comparable to the kernel's own real wall clock
/// (kardia's `ClockManager`), so expiry is a genuine temporal check, not a
/// vacuous one.
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

fn main() {
    let pylon = Pylon::new(runtime_signing().verifying_key(), now_ms());
    let (port, handle) = spawn(pylon, 1);
    // WHY this exact line shape: scripts/witness/metaxu.sh greps stdout for
    // it to learn the port before launching qemu -- the orchestration
    // contract between the two, kept in one place.
    println!("PYLON_PORT={port}");
    let _ = handle.join(); // kanon:ignore RUST/no-silent-result-swallow -- a panicked pylon thread has nothing further for this process to report; the witness script observes the outcome via the kernel's own boot log, not this process's exit path
}
