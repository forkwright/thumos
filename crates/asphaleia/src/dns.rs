//! DNS query parsing and domain blocklist for surveillance domain filtering.
//!
//! Parses the queried domain name FROM a raw DNS query message and matches it
//! against a configurable blocklist. The default blocklist covers domains
//! identified in the Adups FOTA surveillance audit (`docs/SURVEILLANCE-AUDIT.md`).

use std::str;

// Constants

/// DNS message header length in bytes.
const DNS_HEADER_LEN: usize = 12;

/// DNS port number.
pub const DNS_PORT: u16 = 53;

/// Maximum number of labels we will follow when decoding a QNAME.
/// Prevents unbounded iteration on malformed packets.
const MAX_LABELS: usize = 128;

// Type definitions

/// A SET of domain patterns that should be blocked.
///
/// Each entry is either:
/// - An **exact** domain name (`"app-measurement.com"`)
/// - A **wildcard** prefix that matches any subdomain (`"*.doubleclick.net"`)
///
/// Matching is case-insensitive.
#[derive(Debug, Default)]
pub struct DnsBlocklist {
    /// Patterns stored in lower-case for case-insensitive comparison.
    patterns: Vec<String>,
}

// Impl blocks

impl DnsBlocklist {
    /// Create an empty blocklist.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a blocklist pre-populated with the surveillance domains identified
    /// in `docs/SURVEILLANCE-AUDIT.md` (Adups FOTA analysis).
    #[must_use]
    pub fn with_surveillance_defaults() -> Self {
        let mut bl = Self::new();
        for domain in [
            "app-measurement.com",
            "googleads.g.doubleclick.net",
            "ad.doubleclick.net",
            "googlesyndication.com",
            "analytics.google.com",
            "firebaselogging.googleapis.com",
        ] {
            bl.add(domain);
        }
        bl
    }

    /// Add a domain pattern to the blocklist.
    ///
    /// Patterns are lower-cased on insertion. A pattern beginning with `*.`
    /// will match any subdomain of the suffix (e.g. `"*.doubleclick.net"`
    /// matches `"ad.doubleclick.net"` and `"googleads.g.doubleclick.net"`).
    pub fn add(&mut self, pattern: &str) {
        self.patterns.push(pattern.to_ascii_lowercase());
    }

    /// Returns `true` if `domain` matches any pattern in this blocklist.
    ///
    /// `domain` is compared case-insensitively.
    #[must_use]
    pub fn is_blocked(&self, domain: &str) -> bool {
        let lower = domain.to_ascii_lowercase();
        self.patterns.iter().any(|pat| pattern_matches(pat, &lower))
    }

    /// Extract the queried domain FROM a raw DNS message and check it against
    /// the blocklist.
    ///
    /// `data` must be the DNS message payload (not the IP/UDP framing).
    /// Returns `true` if the query should be blocked, including when the
    /// message cannot be decoded (non-UTF-8 label, compression pointer,
    /// truncated, malformed QDCOUNT) — this matches the crate's
    /// parse-failure-denies default (see `filter.rs`).
    #[must_use]
    pub fn blocks_dns_payload(&self, data: &[u8]) -> bool {
        // WHY: fail CLOSED. An undecodable query must not bypass the
        // blocklist — a malicious app could otherwise evade domain
        // blocking with a deliberately malformed query.
        extract_query_domain(data)
            .as_deref()
            .is_none_or(|d| self.is_blocked(d))
    }
}

// Free functions

/// Extract the QNAME FROM the first question in a DNS query message.
///
/// Returns `None` if the message is malformed, truncated, or contains a
/// compression pointer (which should not appear in query QNAMEs but can appear
/// in malformed or spoofed packets).
#[must_use]
pub fn extract_query_domain(data: &[u8]) -> Option<String> {
    if data.len() < DNS_HEADER_LEN {
        return None;
    }

    // QDCOUNT must be at least 1.
    let qdcount = u16::from_be_bytes([
        data.get(4).copied().unwrap_or_default(),
        data.get(5).copied().unwrap_or_default(),
    ]);
    if qdcount == 0 {
        return None;
    }

    let mut pos = DNS_HEADER_LEN;
    let mut domain = String::new();
    let mut label_count = 0usize;

    loop {
        let len_byte = *data.get(pos)?;
        pos = pos.checked_add(1)?;

        if len_byte == 0 {
            // Root label  -  end of QNAME.
            break;
        }

        // Reject compression pointers (top two bits SET). They should not
        // appear in query QNAMEs and indicate malformed or spoofed packets.
        if len_byte & 0xC0 == 0xC0 {
            return None;
        }

        label_count = label_count.checked_add(1)?;
        if label_count > MAX_LABELS {
            return None;
        }

        let label_len = usize::from(len_byte);
        let label_end = pos.checked_add(label_len)?;
        let label_bytes = data.get(pos..label_end)?;
        let label = str::from_utf8(label_bytes).ok()?;

        if !domain.is_empty() {
            domain.push('.');
        }
        domain.push_str(label);

        pos = label_end;
    }

    if domain.is_empty() {
        None
    } else {
        Some(domain)
    }
}

fn pattern_matches(pattern: &str, domain: &str) -> bool {
    pattern
        .strip_prefix("*.")
        .map_or_else(|| domain == pattern, |suffix| subdomain_of(domain, suffix))
}

// Returns true if `domain` is a direct or nested subdomain of `suffix`.
// The bare suffix itself does not match (only `sub.suffix` and deeper do).
fn subdomain_of(domain: &str, suffix: &str) -> bool {
    domain
        .strip_suffix(suffix)
        .is_some_and(|rest| rest.ends_with('.'))
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal DNS query message for `domain`.
    fn make_dns_query(domain: &str) -> Vec<u8> {
        let mut msg = Vec::new();
        // Header
        msg.extend_from_slice(&[0x12, 0x34]); // ID
        msg.extend_from_slice(&[0x01, 0x00]); // QR=0, OPCODE=0, RD=1
        msg.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1
        msg.extend_from_slice(&[0x00, 0x00]); // ANCOUNT = 0
        msg.extend_from_slice(&[0x00, 0x00]); // NSCOUNT = 0
        msg.extend_from_slice(&[0x00, 0x00]); // ARCOUNT = 0

        // QNAME
        for label in domain.split('.') {
            let bytes = label.as_bytes();
            msg.push(u8::try_from(bytes.len()).unwrap_or(u8::MAX));
            msg.extend_from_slice(bytes);
        }
        msg.push(0x00); // Root label

        // QTYPE = A (1), QCLASS = IN (1)
        msg.extend_from_slice(&[0x00, 0x01]);
        msg.extend_from_slice(&[0x00, 0x01]);

        msg
    }

    #[test]
    fn extracts_simple_domain_name() {
        let msg = make_dns_query("example.com");
        let domain = extract_query_domain(&msg);
        assert_eq!(
            domain.as_deref(),
            Some("example.com"),
            "must extract 'example.com'"
        );
    }

    #[test]
    fn extracts_multi_label_domain() {
        let msg = make_dns_query("analytics.google.com");
        let domain = extract_query_domain(&msg);
        assert_eq!(
            domain.as_deref(),
            Some("analytics.google.com"),
            "must extract multi-label domain"
        );
    }

    #[test]
    fn returns_none_for_truncated_message() {
        let short = [0u8; 6];
        assert_eq!(
            extract_query_domain(&short),
            None,
            "truncated DNS message must return None"
        );
    }

    #[test]
    fn returns_none_for_zero_qdcount() {
        let mut msg = make_dns_query("example.com");
        // Set QDCOUNT to 0
        msg[4] = 0;
        msg[5] = 0;
        assert_eq!(
            extract_query_domain(&msg),
            None,
            "zero QDCOUNT must return None"
        );
    }

    #[test]
    fn rejects_compression_pointer_in_qname() {
        let mut msg = make_dns_query("example.com");
        // Overwrite the first QNAME label-length byte with a compression
        // pointer (top two bits SET) — the anti-spoof guard must reject it.
        msg[DNS_HEADER_LEN] = 0xC0;
        assert_eq!(
            extract_query_domain(&msg),
            None,
            "QNAME starting with a compression pointer must return None"
        );
    }

    #[test]
    fn blocklist_exact_match_blocks_domain() {
        let bl = DnsBlocklist::with_surveillance_defaults();
        assert!(
            bl.is_blocked("app-measurement.com"),
            "app-measurement.com must be blocked"
        );
        assert!(
            bl.is_blocked("analytics.google.com"),
            "analytics.google.com must be blocked"
        );
    }

    #[test]
    fn blocklist_exact_match_does_not_block_unrelated_domain() {
        let bl = DnsBlocklist::with_surveillance_defaults();
        assert!(
            !bl.is_blocked("example.com"),
            "example.com must not be blocked"
        );
        assert!(
            !bl.is_blocked("google.com"),
            "google.com must not be blocked (only specific subdomains are)"
        );
    }

    #[test]
    fn blocklist_wildcard_matches_subdomains() {
        let mut bl = DnsBlocklist::new();
        bl.add("*.example.com");
        assert!(
            bl.is_blocked("sub.example.com"),
            "sub.example.com must match *.example.com"
        );
        assert!(
            bl.is_blocked("a.b.example.com"),
            "a.b.example.com must match *.example.com"
        );
        assert!(
            !bl.is_blocked("example.com"),
            "example.com itself must not match *.example.com"
        );
        assert!(
            !bl.is_blocked("notexample.com"),
            "notexample.com must not match *.example.com"
        );
    }

    #[test]
    fn blocklist_is_case_insensitive() {
        let mut bl = DnsBlocklist::new();
        bl.add("App-Measurement.COM");
        assert!(
            bl.is_blocked("app-measurement.com"),
            "lowercase query must match case-insensitive pattern"
        );
        assert!(
            bl.is_blocked("APP-MEASUREMENT.COM"),
            "uppercase query must match case-insensitive pattern"
        );
    }

    #[test]
    fn blocks_dns_payload_returns_true_for_blocked_query() {
        let bl = DnsBlocklist::with_surveillance_defaults();
        let msg = make_dns_query("firebaselogging.googleapis.com");
        assert!(
            bl.blocks_dns_payload(&msg),
            "firebaselogging.googleapis.com DNS query must be blocked"
        );
    }

    #[test]
    fn blocks_dns_payload_returns_false_for_allowed_query() {
        let bl = DnsBlocklist::with_surveillance_defaults();
        let msg = make_dns_query("example.com");
        assert!(
            !bl.blocks_dns_payload(&msg),
            "example.com DNS query must not be blocked"
        );
    }

    #[test]
    fn blocks_dns_payload_fails_closed_on_non_utf8_label() {
        let bl = DnsBlocklist::with_surveillance_defaults();
        let mut msg = vec![
            0x12, 0x34, // ID
            0x01, 0x00, // QR=0, OPCODE=0, RD=1
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x00, // ANCOUNT = 0
            0x00, 0x00, // NSCOUNT = 0
            0x00, 0x00, // ARCOUNT = 0
        ];
        msg.push(3); // label length
        msg.extend_from_slice(&[0xFF, 0xFE, 0xFD]); // invalid UTF-8 label bytes
        msg.push(0x00); // root label
        msg.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // QTYPE/QCLASS
        assert!(
            bl.blocks_dns_payload(&msg),
            "an undecodable query (non-UTF-8 label) must fail closed, not bypass the blocklist"
        );
    }
}
