//! Fuzz target: packet parse + filter evaluation + rules.
//!
//! Exercises the asphaleia packet-filter surface — every IP byte the device
//! sees crosses it. Header parsers must never panic or misreport lengths; the
//! filter must evaluate arbitrary packets in both directions without panic.
//!
//! # Running
//!
//! ```text
//! cargo fuzz run fuzz_packet -- -max_total_time=60
//! cargo fuzz run fuzz_packet corpus/fuzz_packet -- -max_total_time=60
//! ```
#![no_main]
use libfuzzer_sys::fuzz_target;

use asphaleia::filter::Filter;
use asphaleia::packet::{IpHeader, UdpHeader};
use asphaleia::rules::Direction;

fuzz_target!(|data: &[u8]| {
    // ── Phase 1: header parsers ──────────────────────────────────────────────
    // Must never panic. Errors are expected and OK.
    if let Ok(ip) = IpHeader::parse(data) {
        let hl = ip.header_len();
        assert!(hl >= 20, "parsed IPv4 header_len must be >= the 20-byte minimum (got {hl})");
        // UDP parse over the remaining bytes past the declared header.
        if data.len() > hl {
            let _ = UdpHeader::parse(&data[hl..]);
        }
    }

    // ── Phase 2: filter evaluation, both directions ──────────────────────────
    // A default-deny posture must still evaluate without panic; verdict type
    // is not asserted (policy, not parser), only that evaluation terminates.
    let mut filter = Filter::new();
    let _ = filter.evaluate(data, Direction::In);
    let _ = filter.evaluate(data, Direction::Out);
});
