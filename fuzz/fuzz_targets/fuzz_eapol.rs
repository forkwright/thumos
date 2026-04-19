//! Fuzz target: EAPOL frame parsing and encode/parse round-trip.
//!
//! Exercises `aither::eapol::parse` against arbitrary byte inputs to find
//! panics, infinite loops, or incorrect error handling. When `parse` succeeds,
//! feeds the result through `encode` → `parse` to verify the round-trip
//! invariant holds.
//!
//! # Running
//!
//! ```text
//! cargo fuzz run fuzz_eapol -- -max_total_time=60
//! cargo fuzz run fuzz_eapol corpus/fuzz_eapol -- -max_total_time=60
//! ```
#![no_main]
use libfuzzer_sys::fuzz_target;

use aither::eapol;

fuzz_target!(|data: &[u8]| {
    // ── Phase 1: parse ───────────────────────────────────────────────────────
    // Must never panic regardless of input. Errors are expected and OK.
    let Ok(frame) = eapol::parse(data) else {
        return;
    };

    // ── Phase 2: round-trip ──────────────────────────────────────────────────
    // If we parsed successfully, encoding and re-parsing must succeed and
    // produce the identical frame. Any deviation is a bug.
    let encoded = eapol::encode(&frame);
    let reparsed = eapol::parse(&encoded).expect("re-parse EAPOL round-trip must succeed"); // kanon:ignore RUST/expect -- fuzz targets must panic on invariant violations so libFuzzer reports the bug; round-trip is guaranteed by construction
    assert_eq!(
        frame, reparsed,
        "EAPOL round-trip must be lossless: parse → encode → parse must yield identical frames",
    );
});
