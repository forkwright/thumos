//! Fuzz target: 3GPP TS 27.007 AT response/URC parsers.
//!
//! Exercises the klesis AT parsers against arbitrary bytes — the modem's every
//! response, error, and unsolicited result code crosses this surface. All
//! parsers must return an Err (or a partial nom parse) for malformed input,
//! never panic, never loop, and never allocate unboundedly.
//!
//! # Running
//!
//! ```text
//! cargo fuzz run fuzz_at -- -max_total_time=60
//! cargo fuzz run fuzz_at corpus/fuzz_at -- -max_total_time=60
//! ```
#![no_main]
use libfuzzer_sys::fuzz_target;

use klesis::at;

fuzz_target!(|data: &[u8]| {
    // Parsers consume &str; lossy conversion keeps every byte exercised while
    // skipping only the (uninteresting) invalid-UTF8 rejection path.
    let text = String::from_utf8_lossy(data);
    let line = text.trim_end_matches(['\r', '\n']);

    // ── Phase 1: final-result parser ────────────────────────────────────────
    // OK / ERROR / +CME ERROR / +CMS ERROR. Must never panic.
    let _ = at::parse_final_result(line);

    // ── Phase 2: URC parsers ────────────────────────────────────────────────
    // +CSQ signal, +CREG registration, RING, +CMTI SMS arrival. Prefixed as
    // the modem would send them, with the fuzz bytes as the payload.
    let csq = format!("+CSQ: {line}");
    let _ = at::parse_csq(&csq);
    let creg = format!("+CREG: {line}");
    let _ = at::parse_creg(&creg);
    let ring = format!("RING{line}");
    let _ = at::parse_ring(&ring);
    let cmti = format!("+CMTI: {line}");
    let _ = at::parse_cmti(&cmti);
});
