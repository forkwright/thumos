//! Fuzz target: CCCI frame codec (header + payload).
//!
//! Exercises `klesis::ccci::CcciMessage::from_bytes` against arbitrary byte
//! inputs — every modem control-channel frame crosses this codec. The decoder
//! must never panic, never loop, and never allocate beyond the declared MTU;
//! a successful decode must re-encode and re-decode losslessly.
//!
//! # Running
//!
//! ```text
//! cargo fuzz run fuzz_ccci -- -max_total_time=60
//! cargo fuzz run fuzz_ccci corpus/fuzz_ccci -- -max_total_time=60
//! ```
#![no_main]
use libfuzzer_sys::fuzz_target;

use klesis::ccci::CcciMessage;

fuzz_target!(|data: &[u8]| {
    // ── Phase 1: decode ──────────────────────────────────────────────────────
    // Must never panic regardless of input. Errors are expected and OK.
    let Ok(msg) = CcciMessage::from_bytes(data) else {
        return;
    };

    // ── Phase 2: round-trip ──────────────────────────────────────────────────
    // A decoded message must re-encode and re-decode to the identical message.
    let encoded = msg.to_bytes();
    let reparsed = CcciMessage::from_bytes(&encoded).expect("CCCI round-trip must re-parse"); // kanon:ignore RUST/expect -- fuzz targets must panic on invariant violations so libFuzzer reports the bug; round-trip is guaranteed by construction
    assert_eq!(
        msg.header.data, reparsed.header.data,
        "CCCI round-trip must preserve header words",
    );
    assert_eq!(
        msg.header.channel, reparsed.header.channel,
        "CCCI round-trip must preserve channel",
    );
    assert_eq!(
        msg.payload, reparsed.payload,
        "CCCI round-trip must preserve payload",
    );
});
