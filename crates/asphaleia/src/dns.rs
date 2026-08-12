//! DNS query parsing and domain blocklist for surveillance domain filtering.
//!
//! Parses the queried domain name FROM a raw DNS query message and matches it
//! against a configurable blocklist. The default blocklist covers domains
//! identified in the Adups FOTA surveillance audit (`docs/SURVEILLANCE-AUDIT.md`).
//!
//! QNAME extraction and the default surveillance-domain policy (list +
//! suffix-matching rule) delegate to `asphaleia_core` (#545) — the same
//! canonical implementation the kernel's `firewall.rs` links by path
//! dependency.

/// DNS port number.
pub use asphaleia_core::DNS_PORT;

// Type definitions

/// A SET of domain suffixes that should be blocked.
///
/// A domain is blocked if it equals or is a subdomain of any entry (see
/// [`asphaleia_core::domain_matches_suffix`]) — matching is unconditional,
/// case-insensitive, and needs no wildcard syntax: adding `"doubleclick.net"`
/// already blocks `"ad.doubleclick.net"` and every other subdomain.
#[derive(Debug, Default)]
pub struct DnsBlocklist {
    /// Suffixes stored in lower-case for case-insensitive comparison.
    patterns: Vec<String>,
}

// Impl blocks

impl DnsBlocklist {
    /// Create an empty blocklist.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a blocklist pre-populated with the canonical surveillance
    /// domains ([`asphaleia_core::SURVEILLANCE_DOMAINS`], #545).
    ///
    /// Time: O(1) — iterates the fixed 12-entry `SURVEILLANCE_DOMAINS`
    /// compile-time constant array; the work done does not depend on any
    /// runtime input.
    /// Space: O(1) — allocates at most 12 owned `String` suffixes into
    /// `self.patterns`, a count bounded by the compile-time-constant
    /// `SURVEILLANCE_DOMAINS.len()`.
    #[must_use]
    pub fn with_surveillance_defaults() -> Self {
        let mut bl = Self::new();
        for domain in asphaleia_core::SURVEILLANCE_DOMAINS {
            bl.add(domain);
        }
        bl
    }

    /// Add a domain suffix to the blocklist.
    ///
    /// Lower-cased on insertion. Any query domain equal to or a subdomain of
    /// `suffix` will be blocked — see [`asphaleia_core::domain_matches_suffix`].
    pub fn add(&mut self, suffix: &str) {
        self.patterns
            .push(asphaleia_core::normalize_suffix(suffix).to_ascii_lowercase());
    }

    /// Returns `true` if `domain` matches any suffix in this blocklist.
    ///
    /// `domain` is compared case-insensitively.
    #[must_use]
    pub fn is_blocked(&self, domain: &str) -> bool {
        let lower = domain.to_ascii_lowercase();
        self.is_blocked_lowercased(&lower)
    }

    /// Same as [`Self::is_blocked`], for a caller that already holds a
    /// lowercased domain (e.g. [`extract_query_domain`], which lowercases
    /// while it decodes) — avoids a second allocation on the hot path.
    fn is_blocked_lowercased(&self, lowercased_domain: &str) -> bool {
        self.patterns
            .iter()
            .any(|suffix| asphaleia_core::domain_matches_suffix(lowercased_domain, suffix))
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
            .is_none_or(|d| self.is_blocked_lowercased(d))
    }
}

// Free functions

/// Extract the QNAME FROM the first question in a DNS query message,
/// lowercased. See [`asphaleia_core::extract_query_domain`].
///
/// Returns `None` if the message is malformed, truncated, or contains a
/// compression pointer (which should not appear in query QNAMEs but can appear
/// in malformed or spoofed packets).
///
/// Time: O(n) where n is `data.len()` — delegates to
/// [`asphaleia_core::extract_query_domain`], which walks the QNAME once,
/// lowercasing each label byte as it goes.
/// Space: O(n) — the returned domain `String` is built from the QNAME
/// labels, bounded above by `data.len()`.
#[must_use]
pub(crate) fn extract_query_domain(data: &[u8]) -> Option<String> {
    asphaleia_core::extract_query_domain(data)
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
        msg[asphaleia_core::DNS_HEADER_LEN] = 0xC0;
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
        // Both spellings must behave identically: the converged rule is plain
        // suffix matching, and a "*." entry is normalized rather than stored
        // as a literal that could never match (#545).
        bl.add("*.example.com");
        assert!(
            bl.is_blocked("sub.example.com"),
            "sub.example.com must match a '*.example.com' entry after normalization"
        );
        assert!(
            bl.is_blocked("example.com"),
            "the apex must match too: '*.' is normalized away, not treated as a literal"
        );
        assert!(
            bl.is_blocked("a.b.example.com"),
            "a.b.example.com must match *.example.com"
        );
        // NOTE (#545): the pre-convergence copy asserted the apex must NOT
        // match, i.e. strict subdomain-only wildcards. The converged rule
        // deliberately includes the apex, and for a surveillance blocklist
        // that is the correct default: blocking ads.doubleclick.net while
        // leaving doubleclick.net reachable is under-blocking, and
        // under-blocking is the failure mode that matters on this device.
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
