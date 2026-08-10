//! Host process for the QEMU on-device round trip (#544): binds a pylon
//! listener, prints its port, and answers exactly one authenticated
//! request. Launched by `scripts/witness/metaxu.sh` BEFORE QEMU starts;
//! the kernel's second UART chardev is pointed at the printed port as a
//! TCP CLIENT (`server=off`), so this process is guaranteed listening
//! before the guest ever tries to connect.
//!
//! Reuses `metaxu::pylon::{Pylon, spawn_with_response_transform}` verbatim
//! -- the SAME reference endpoint the adversarial witness runs against, not
//! a second, independently-written double that could drift from it.
//!
//! The pinned "runtime" identity is the well-known dev seed
//! (`SigningKey::from_bytes(&[7u8; 32])`) `metaxu`'s own witness already
//! uses for the SAME role -- a deliberately public, non-secret dev
//! keypair (mirrors `crates/thumos/keys/dev/boot-dev.*`), never a
//! production credential.
//!
//! `--tamper-mac` (#544 negative-case witness): corrupts every outgoing
//! response's MAC before it reaches the wire, so the on-device client must
//! observe a typed MAC failure rather than a silent accept. This binary is
//! CI test tooling -- a host process the QEMU witness launches, never
//! compiled into the kernel image -- so it carries none of
//! `metaxu_bridge.rs`'s production-exclusion constraints; the flag is
//! simply absent unless a caller passes it.

use ed25519_dalek::SigningKey;
use metaxu::pylon::{Pylon, spawn_with_response_transform};

/// The pylon's pinned runtime identity: the well-known metaxu dev seed
/// (`metaxu`'s witness.rs `runtime_signing()`). The kernel's own dev-only
/// bridge module signs grants under this SAME seed, so a freshly issued
/// grant always verifies here.
fn runtime_signing() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
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
    let tamper_mac = std::env::args().any(|a| a == "--tamper-mac");
    let pylon = Pylon::new(runtime_signing().verifying_key(), now_ms());
    let (port, handle) = spawn_with_response_transform(pylon, 1, move |response| {
        // WHY this exact line shape: scripts/witness/metaxu-negative.sh
        // greps stdout for it as the positive proof that a frame reached
        // this process -- the transform only runs once `Pylon::handle` has
        // already verified + answered a fully-read request frame, so its
        // presence is exactly "the host bridge received a frame" and its
        // absence is exactly "nothing was transmitted" (#544).
        println!("PYLON: frame received and answered");
        if tamper_mac {
            tamper_response_mac(response)
        } else {
            response
        }
    });
    // WHY this exact line shape: scripts/witness/metaxu.sh (and
    // metaxu-negative.sh) grep stdout for it to learn the port before
    // launching qemu -- the orchestration contract between the two, kept
    // in one place.
    println!("PYLON_PORT={port}");
    let _ = handle.join(); // kanon:ignore RUST/no-silent-result-swallow -- a panicked pylon thread has nothing further for this process to report; the witness script observes the outcome via the kernel's own boot log, not this process's exit path
}

/// Flip the response frame's LAST byte (#544 negative case).
///
/// The envelope wraps a postcard-encoded `AuthenticatedResponse {
/// response, mac: [u8; 32] }`; postcard encodes a fixed-size byte array
/// as raw bytes with no length prefix, so `mac` is always the frame's
/// trailing 32 bytes -- corrupting the last one breaks
/// `AuthenticatedResponse::verify` while leaving the envelope header and
/// the `response` payload exactly as `Envelope::decode` and
/// `postcard::from_bytes` expect, so decode still succeeds and only the
/// MAC comparison fails.
fn tamper_response_mac(mut frame: Vec<u8>) -> Vec<u8> {
    if let Some(last) = frame.last_mut() {
        *last ^= 0xFF;
    }
    frame
}
