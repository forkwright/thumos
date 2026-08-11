#![no_std]
//! asphaleia-core: the canonical packet-parse and DNS-surveillance-policy
//! semantics (#545).
//!
//! This crate is the single home of IPv4/TCP/UDP header field extraction,
//! DNS QNAME parsing, and the surveillance-domain blocklist policy (the
//! domain list and its suffix-matching semantics), shared by the
//! `asphaleia` workspace crate (packet filter + DNS blocklist library) and
//! the thumos kernel (`firewall.rs`, the filter actually wired into the
//! live RX/TX packet path). It exists because the two sides drifted: the
//! kernel's blocklist matched 12 domains and always treated a listed
//! domain as covering its whole subtree; `asphaleia`'s independently-typed
//! copy matched only 6 domains and required an explicit `"*."` prefix to
//! match a subdomain at all — the same domain string protected different
//! traffic depending on which copy evaluated it. One parser, one policy.
//!
//! `no_std` + alloc so the bare-metal kernel can link it via a path
//! dependency; nothing here performs I/O.

extern crate alloc;

use alloc::string::String;

// ---------------------------------------------------------------------------
// IANA protocol numbers (RFC 790 assigned numbers -- universal, not a
// project policy choice)
// ---------------------------------------------------------------------------

/// IP protocol number for ICMP.
pub const PROTO_ICMP: u8 = 1;
/// IP protocol number for TCP.
pub const PROTO_TCP: u8 = 6;
/// IP protocol number for UDP.
pub const PROTO_UDP: u8 = 17;

// ---------------------------------------------------------------------------
// Parse errors
// ---------------------------------------------------------------------------

/// Errors that can occur when parsing network packet headers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseError {
    /// The buffer is shorter than the minimum required for this header.
    TooShort {
        /// Bytes required to parse the header.
        needed: usize,
        /// Bytes actually available.
        got: usize,
    },
    /// The IP version field is not 4.
    InvalidVersion {
        /// The version nibble found in the first byte.
        version: u8,
    },
    /// The IHL field encodes a header shorter than the minimum 20 bytes.
    InvalidIhl {
        /// The IHL (internet header length) value in 32-bit words.
        ihl: u8,
    },
}

impl core::fmt::Display for ParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooShort { needed, got } => {
                write!(f, "packet too short: need {needed} bytes, got {got}")
            }
            Self::InvalidVersion { version } => {
                write!(f, "invalid IP version: expected 4, got {version}")
            }
            Self::InvalidIhl { ihl } => {
                write!(f, "invalid IHL {ihl}: minimum is 5 (20 bytes)")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// IPv4 header
// ---------------------------------------------------------------------------

const IPV4_MIN_HEADER_LEN: usize = 20;
const IPV4_VERSION: u8 = 4;
const MIN_IHL: u8 = 5;

/// Parsed IPv4 header fields.
///
/// Addresses are raw octets, not a `std::net`/`smoltcp` wrapper type — each
/// consumer wraps them in whatever address type its own layer already uses
/// (the kernel avoids coupling this module to smoltcp; `asphaleia` wraps
/// them in `std::net::Ipv4Addr` for its richer userspace-facing API).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Fields {
    /// IP version (always 4 for a successfully parsed header).
    pub version: u8,
    /// Internet Header Length in 32-bit words.
    pub ihl: u8,
    /// Total packet length in bytes (header + payload).
    pub total_length: u16,
    /// IP protocol number (see [`PROTO_TCP`], [`PROTO_UDP`], [`PROTO_ICMP`]).
    pub protocol: u8,
    /// Source IPv4 address, network byte order.
    pub src_addr: [u8; 4],
    /// Destination IPv4 address, network byte order.
    pub dst_addr: [u8; 4],
}

impl Ipv4Fields {
    /// Parse an IPv4 header from the beginning of `data`.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::TooShort`] if `data` is shorter than 20 bytes or
    /// shorter than the length encoded in the IHL field.
    /// Returns [`ParseError::InvalidVersion`] if the version is not 4.
    /// Returns [`ParseError::InvalidIhl`] if IHL is less than 5.
    pub fn parse(data: &[u8]) -> Result<Self, ParseError> {
        if data.len() < IPV4_MIN_HEADER_LEN {
            return Err(ParseError::TooShort {
                needed: IPV4_MIN_HEADER_LEN,
                got: data.len(),
            });
        }

        let version_ihl = data.first().copied().unwrap_or_default();
        let version = version_ihl >> 4;
        let ihl = version_ihl & 0x0F;

        if version != IPV4_VERSION {
            return Err(ParseError::InvalidVersion { version });
        }
        if ihl < MIN_IHL {
            return Err(ParseError::InvalidIhl { ihl });
        }

        let header_len = usize::from(ihl) * 4;
        if data.len() < header_len {
            return Err(ParseError::TooShort {
                needed: header_len,
                got: data.len(),
            });
        }

        let total_length = u16::from_be_bytes([
            data.get(2).copied().unwrap_or_default(),
            data.get(3).copied().unwrap_or_default(),
        ]);
        let protocol = data.get(9).copied().unwrap_or_default();
        let src_addr = [
            data.get(12).copied().unwrap_or_default(),
            data.get(13).copied().unwrap_or_default(),
            data.get(14).copied().unwrap_or_default(),
            data.get(15).copied().unwrap_or_default(),
        ];
        let dst_addr = [
            data.get(16).copied().unwrap_or_default(),
            data.get(17).copied().unwrap_or_default(),
            data.get(18).copied().unwrap_or_default(),
            data.get(19).copied().unwrap_or_default(),
        ];

        Ok(Self {
            version,
            ihl,
            total_length,
            protocol,
            src_addr,
            dst_addr,
        })
    }

    /// Return the header length in bytes (`ihl * 4`).
    #[must_use]
    pub const fn header_len(&self) -> usize {
        (self.ihl as usize) * 4
    }
}

// ---------------------------------------------------------------------------
// TCP header
// ---------------------------------------------------------------------------

const TCP_MIN_HEADER_LEN: usize = 20;

/// Parsed TCP header fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpFields {
    /// Source TCP port.
    pub src_port: u16,
    /// Destination TCP port.
    pub dst_port: u16,
    /// Sequence number.
    pub seq: u32,
    /// Acknowledgement number.
    pub ack: u32,
    /// Control flags byte (SYN, ACK, FIN, RST, PSH, URG, ECE, CWR).
    pub flags: u8,
}

impl TcpFields {
    /// Parse a TCP header from the beginning of `data` (the byte
    /// immediately after the IP header).
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::TooShort`] if `data` is shorter than 20 bytes.
    pub fn parse(data: &[u8]) -> Result<Self, ParseError> {
        if data.len() < TCP_MIN_HEADER_LEN {
            return Err(ParseError::TooShort {
                needed: TCP_MIN_HEADER_LEN,
                got: data.len(),
            });
        }

        let src_port = u16::from_be_bytes([
            data.first().copied().unwrap_or_default(),
            data.get(1).copied().unwrap_or_default(),
        ]);
        let dst_port = u16::from_be_bytes([
            data.get(2).copied().unwrap_or_default(),
            data.get(3).copied().unwrap_or_default(),
        ]);
        let seq = u32::from_be_bytes([
            data.get(4).copied().unwrap_or_default(),
            data.get(5).copied().unwrap_or_default(),
            data.get(6).copied().unwrap_or_default(),
            data.get(7).copied().unwrap_or_default(),
        ]);
        let ack = u32::from_be_bytes([
            data.get(8).copied().unwrap_or_default(),
            data.get(9).copied().unwrap_or_default(),
            data.get(10).copied().unwrap_or_default(),
            data.get(11).copied().unwrap_or_default(),
        ]);
        // Byte 12 is data OFFSET; byte 13 is the flags byte.
        let flags = data.get(13).copied().unwrap_or_default();

        Ok(Self {
            src_port,
            dst_port,
            seq,
            ack,
            flags,
        })
    }
}

// ---------------------------------------------------------------------------
// UDP header
// ---------------------------------------------------------------------------

const UDP_HEADER_LEN: usize = 8;

/// Parsed UDP header fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpFields {
    /// Source UDP port.
    pub src_port: u16,
    /// Destination UDP port.
    pub dst_port: u16,
    /// UDP datagram length (header + data) in bytes.
    pub length: u16,
}

impl UdpFields {
    /// Parse a UDP header from the beginning of `data` (the byte
    /// immediately after the IP header).
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::TooShort`] if `data` is shorter than 8 bytes.
    pub fn parse(data: &[u8]) -> Result<Self, ParseError> {
        if data.len() < UDP_HEADER_LEN {
            return Err(ParseError::TooShort {
                needed: UDP_HEADER_LEN,
                got: data.len(),
            });
        }

        let src_port = u16::from_be_bytes([
            data.first().copied().unwrap_or_default(),
            data.get(1).copied().unwrap_or_default(),
        ]);
        let dst_port = u16::from_be_bytes([
            data.get(2).copied().unwrap_or_default(),
            data.get(3).copied().unwrap_or_default(),
        ]);
        let length = u16::from_be_bytes([
            data.get(4).copied().unwrap_or_default(),
            data.get(5).copied().unwrap_or_default(),
        ]);

        Ok(Self {
            src_port,
            dst_port,
            length,
        })
    }
}

// ---------------------------------------------------------------------------
// DNS QNAME extraction
// ---------------------------------------------------------------------------

/// DNS port number.
pub const DNS_PORT: u16 = 53;

/// DNS message header length in bytes -- the offset the QNAME starts at.
pub const DNS_HEADER_LEN: usize = 12;

/// Maximum number of labels to follow when decoding a QNAME. Prevents
/// unbounded iteration on malformed packets.
const MAX_LABELS: usize = 128;

/// Extract the QNAME from the first question in a DNS query message,
/// lowercased.
///
/// `data` must be the DNS message payload (after the UDP header, or after
/// the 2-byte length prefix for DNS-over-TCP). Returns `None` if the
/// message is malformed, truncated, or contains a compression pointer
/// (which should not appear in a query QNAME and indicates a malformed or
/// spoofed packet).
///
/// The returned domain is lowercased during extraction rather than left in
/// wire case: every caller on both sides matches it against a
/// case-normalized blocklist (see [`domain_matches_suffix`]), and
/// lowercasing once here — instead of once per caller — avoids a second
/// per-packet allocation on the hot path.
#[must_use]
pub fn extract_query_domain(data: &[u8]) -> Option<String> {
    if data.len() < DNS_HEADER_LEN {
        return None;
    }

    // QDCOUNT must be at least 1.
    let qdcount = u16::from_be_bytes([*data.get(4)?, *data.get(5)?]);
    if qdcount == 0 {
        return None;
    }

    let mut pos = DNS_HEADER_LEN;
    let mut domain = String::new();
    let mut label_count: usize = 0;

    loop {
        let len_byte = *data.get(pos)?;
        pos = pos.checked_add(1)?;

        if len_byte == 0 {
            // Root label -- end of QNAME.
            break;
        }

        // Reject compression pointers (top two bits SET).
        if len_byte & 0xC0 == 0xC0 {
            return None;
        }

        label_count = label_count.checked_add(1)?;
        if label_count > MAX_LABELS {
            return None;
        }

        let label_len = len_byte as usize;
        let label_end = pos.checked_add(label_len)?;
        let label_bytes = data.get(pos..label_end)?;
        let label = core::str::from_utf8(label_bytes).ok()?;

        if !domain.is_empty() {
            domain.push('.');
        }
        domain.extend(label.chars().map(|c| c.to_ascii_lowercase()));

        pos = label_end;
    }

    if domain.is_empty() {
        None
    } else {
        Some(domain)
    }
}

// ---------------------------------------------------------------------------
// Surveillance-domain blocklist policy
// ---------------------------------------------------------------------------

/// Surveillance domains blocked by default (the canonical policy, #545).
///
/// These are the advertising, analytics, and telemetry domains identified
/// in the thumos security brainstorm / `docs/SURVEILLANCE-AUDIT.md`.
/// Matching is via [`domain_matches_suffix`]: a domain is blocked if it
/// equals or is a subdomain of any entry here, unconditionally -- no
/// separate wildcard syntax is needed or supported. (Before #545,
/// `asphaleia`'s independently-typed blocklist required an explicit `"*."`
/// prefix on an entry before it would match a subdomain, and shipped only
/// 6 of these 12 domains; the kernel's copy -- the one actually filtering
/// the live RX/TX path -- always matched subdomains implicitly. The same
/// bare domain string therefore protected different traffic depending on
/// which copy evaluated it: the non-transitive-fix divergence this crate
/// exists to kill.)
pub const SURVEILLANCE_DOMAINS: &[&str] = &[
    "graph.facebook.com",
    "analytics.google.com",
    "firebaselogging.googleapis.com",
    "app-measurement.com",
    "crashlytics.com",
    "doubleclick.net",
    "googlesyndication.com",
    "googleadservices.com",
    "analytics.yahoo.com",
    "ads.linkedin.com",
    "bat.bing.com",
    "pixel.facebook.com",
];

/// Check whether `domain` equals or is a subdomain of `suffix`.
///
/// Case-sensitive: callers compare pre-lowercased strings (see
/// [`extract_query_domain`]).
///
/// `"sub.doubleclick.net"` matches suffix `"doubleclick.net"`.
/// `"doubleclick.net"` matches suffix `"doubleclick.net"`.
/// `"notdoubleclick.net"` does NOT match suffix `"doubleclick.net"`.
#[must_use]
pub fn domain_matches_suffix(domain: &str, suffix: &str) -> bool {
    if domain == suffix {
        return true;
    }
    domain
        .strip_suffix(suffix)
        .is_some_and(|rest| rest.ends_with('.'))
}

/// Strip a leading `"*."` from a blocklist entry, if present.
///
/// WHY (#545): the converged rule is plain suffix matching -- an entry blocks
/// itself and every subdomain, so no wildcard syntax is needed. But `"*."` is
/// the near-universal spelling in hosts/adblock formats, and before #545 this
/// crate's own blocklist REQUIRED it. Accepting such an entry as a literal
/// would store a suffix no domain can ever match, so the entry silently blocks
/// nothing -- a fail-OPEN outcome on a surveillance blocklist, and invisible
/// because nothing errors. Normalizing it is fail-closed and costs one strip.
#[must_use]
pub fn normalize_suffix(entry: &str) -> &str {
    entry.strip_prefix("*.").unwrap_or(entry)
}

/// Check whether `domain` (already lowercased) matches any entry in
/// [`SURVEILLANCE_DOMAINS`].
#[must_use]
pub fn is_default_surveillance_domain(domain_lowercased: &str) -> bool {
    SURVEILLANCE_DOMAINS
        .iter()
        .any(|suffix| domain_matches_suffix(domain_lowercased, suffix))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use super::*;

    fn make_tcp_packet() -> Vec<u8> {
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x45; // version=4, IHL=5
        pkt[3] = 40; // total length
        pkt[9] = PROTO_TCP;
        pkt[12..16].copy_from_slice(&[10, 0, 0, 1]);
        pkt[16..20].copy_from_slice(&[192, 168, 1, 1]);
        pkt[20] = 0x30;
        pkt[21] = 0x39; // src_port = 12345
        pkt[22] = 0x00;
        pkt[23] = 0x50; // dst_port = 80
        pkt[32] = 0x50; // data offset = 5 (20 bytes)
        pkt[33] = 0x02; // SYN flag
        pkt
    }

    fn make_udp_packet() -> Vec<u8> {
        let mut pkt = vec![0u8; 28];
        pkt[0] = 0x45;
        pkt[3] = 28;
        pkt[9] = PROTO_UDP;
        pkt[12..16].copy_from_slice(&[10, 0, 0, 1]);
        pkt[16..20].copy_from_slice(&[8, 8, 8, 8]);
        pkt[20] = 0xD4;
        pkt[21] = 0x31; // src_port = 54321
        pkt[22] = 0x00;
        pkt[23] = 0x35; // dst_port = 53
        pkt[25] = 8; // length = 8 (header only)
        pkt
    }

    fn make_dns_query(domain: &str) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(&[0x12, 0x34]); // ID
        msg.extend_from_slice(&[0x01, 0x00]); // flags
        msg.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1
        msg.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        for label in domain.split('.') {
            let bytes = label.as_bytes();
            msg.push(u8::try_from(bytes.len()).unwrap_or(u8::MAX));
            msg.extend_from_slice(bytes);
        }
        msg.push(0x00);
        msg.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        msg
    }

    #[test]
    fn ipv4_fields_parses_valid_packet() {
        let pkt = make_tcp_packet();
        let hdr =
            Ipv4Fields::parse(&pkt).unwrap_or_else(|_| unreachable!("valid packet must parse"));
        assert_eq!(hdr.version, 4);
        assert_eq!(hdr.ihl, 5);
        assert_eq!(hdr.total_length, 40);
        assert_eq!(hdr.protocol, PROTO_TCP);
        assert_eq!(hdr.src_addr, [10, 0, 0, 1]);
        assert_eq!(hdr.dst_addr, [192, 168, 1, 1]);
        assert_eq!(hdr.header_len(), 20);
    }

    #[test]
    fn ipv4_fields_rejects_truncated_packet() {
        let short = [0x45u8; 10];
        assert!(matches!(
            Ipv4Fields::parse(&short),
            Err(ParseError::TooShort { .. })
        ));
    }

    #[test]
    fn ipv4_fields_rejects_ipv6_version() {
        let mut pkt = make_tcp_packet();
        pkt[0] = 0x65; // version=6
        assert!(matches!(
            Ipv4Fields::parse(&pkt),
            Err(ParseError::InvalidVersion { version: 6 })
        ));
    }

    #[test]
    fn ipv4_fields_rejects_ihl_below_minimum() {
        let mut pkt = make_tcp_packet();
        pkt[0] = 0x44; // version=4, IHL=4 (invalid)
        assert!(matches!(
            Ipv4Fields::parse(&pkt),
            Err(ParseError::InvalidIhl { ihl: 4 })
        ));
    }

    #[test]
    fn tcp_fields_parses_valid_segment() {
        let pkt = make_tcp_packet();
        let ip =
            Ipv4Fields::parse(&pkt).unwrap_or_else(|_| unreachable!("valid packet must parse"));
        let tcp = TcpFields::parse(&pkt[ip.header_len()..])
            .unwrap_or_else(|_| unreachable!("valid TCP header must parse"));
        assert_eq!(tcp.src_port, 12345);
        assert_eq!(tcp.dst_port, 80);
        assert_eq!(tcp.flags, 0x02);
    }

    #[test]
    fn tcp_fields_rejects_short_slice() {
        let short = [0u8; 10];
        assert!(matches!(
            TcpFields::parse(&short),
            Err(ParseError::TooShort { .. })
        ));
    }

    #[test]
    fn udp_fields_parses_valid_datagram() {
        let pkt = make_udp_packet();
        let ip =
            Ipv4Fields::parse(&pkt).unwrap_or_else(|_| unreachable!("valid packet must parse"));
        let udp = UdpFields::parse(&pkt[ip.header_len()..])
            .unwrap_or_else(|_| unreachable!("valid UDP header must parse"));
        assert_eq!(udp.src_port, 54321);
        assert_eq!(udp.dst_port, 53);
        assert_eq!(udp.length, 8);
    }

    #[test]
    fn udp_fields_rejects_short_slice() {
        let short = [0u8; 4];
        assert!(matches!(
            UdpFields::parse(&short),
            Err(ParseError::TooShort { .. })
        ));
    }

    #[test]
    fn extracts_simple_domain_name() {
        let msg = make_dns_query("example.com");
        assert_eq!(extract_query_domain(&msg).as_deref(), Some("example.com"));
    }

    #[test]
    fn extracts_and_lowercases_domain() {
        let msg = make_dns_query("Example.COM");
        assert_eq!(extract_query_domain(&msg).as_deref(), Some("example.com"));
    }

    #[test]
    fn returns_none_for_truncated_message() {
        let short = [0u8; 6];
        assert_eq!(extract_query_domain(&short), None);
    }

    #[test]
    fn returns_none_for_zero_qdcount() {
        let mut msg = make_dns_query("example.com");
        msg[4] = 0;
        msg[5] = 0;
        assert_eq!(extract_query_domain(&msg), None);
    }

    #[test]
    fn rejects_compression_pointer_in_qname() {
        let mut msg = make_dns_query("example.com");
        msg[DNS_HEADER_LEN] = 0xC0;
        assert_eq!(extract_query_domain(&msg), None);
    }

    #[test]
    fn domain_matches_suffix_covers_exact_and_subdomain() {
        assert!(domain_matches_suffix("doubleclick.net", "doubleclick.net"));
        assert!(domain_matches_suffix(
            "sub.doubleclick.net",
            "doubleclick.net"
        ));
        assert!(!domain_matches_suffix(
            "notdoubleclick.net",
            "doubleclick.net"
        ));
    }

    #[test]
    fn surveillance_list_has_no_duplicate_entries() {
        for (i, a) in SURVEILLANCE_DOMAINS.iter().enumerate() {
            for b in &SURVEILLANCE_DOMAINS[i + 1..] {
                assert_ne!(a, b, "duplicate surveillance domain entry: {a}");
            }
        }
    }

    #[test]
    fn is_default_surveillance_domain_blocks_exact_and_subdomain() {
        assert!(is_default_surveillance_domain("app-measurement.com"));
        assert!(is_default_surveillance_domain("doubleclick.net"));
        assert!(is_default_surveillance_domain("sub.doubleclick.net"));
    }

    /// Regression for #545: asphaleia's pre-convergence blocklist listed
    /// only these two doubleclick subdomains explicitly (no bare
    /// "doubleclick.net" entry, no wildcard). The canonical list carries
    /// the bare domain and matches subdomains unconditionally, so both
    /// entries -- and every other doubleclick.net subdomain -- are
    /// subsumed by the one "doubleclick.net" entry.
    #[test]
    fn canonical_list_subsumes_asphaleias_pre_convergence_doubleclick_entries() {
        assert!(is_default_surveillance_domain(
            "googleads.g.doubleclick.net"
        ));
        assert!(is_default_surveillance_domain("ad.doubleclick.net"));
    }

    /// Regression for #545: a bare (non-subdomain) surveillance domain must
    /// not be treated as blocking its unrelated sibling/parent labels.
    #[test]
    fn is_default_surveillance_domain_does_not_over_match() {
        assert!(!is_default_surveillance_domain("example.com"));
        assert!(!is_default_surveillance_domain("google.com"));
        assert!(!is_default_surveillance_domain("notdoubleclick.net"));
    }
}
