//! Fuzz target: DNS query domain extraction and blocklist evaluation.
//!
//! Exercises `asphaleia::dns` against arbitrary byte inputs to find panics,
//! infinite loops, or unbounded memory allocations in the DNS QNAME parser.
//!
//! Attack surface:
//! - `extract_query_domain`: parses raw DNS message bytes into a domain string
//! - `DnsBlocklist::blocks_dns_payload`: combines parse + blocklist lookup
//!
//! Both functions must handle arbitrary untrusted UDP payloads without panicking.
//!
//! # Running
//!
//! ```text
//! cargo fuzz run fuzz_dns -- -max_total_time=60
//! cargo fuzz run fuzz_dns corpus/fuzz_dns -- -max_total_time=60
//! ```
#![no_main]
use libfuzzer_sys::fuzz_target;

use asphaleia::DnsBlocklist;

fuzz_target!(|data: &[u8]| {
    // ── Phase 1: raw domain extraction ──────────────────────────────────────
    // Must never panic. Returns None for malformed input.
    //
    // WHY: extract_query_domain is pub(crate) in asphaleia; we exercise it
    // indirectly through the public DnsBlocklist::blocks_dns_payload API which
    // calls extract_query_domain internally. This covers the same code paths.
    let bl = DnsBlocklist::with_surveillance_defaults();

    // blocks_dns_payload calls extract_query_domain → is_blocked.
    // Any panic here is a bug.
    let _ = bl.blocks_dns_payload(data); // WHY: fuzz target — only contract is no panic; Ok/Err are both valid outcomes

    // ── Phase 2: blocklist matching on extracted domain ──────────────────────
    // Also test is_blocked directly with the raw bytes interpreted as a string
    // to exercise the pattern matching paths independently of DNS parsing.
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = bl.is_blocked(s); // WHY: fuzz target — only contract is no panic; Ok/Err are both valid outcomes
    }
});
