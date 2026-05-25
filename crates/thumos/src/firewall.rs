//! Packet filter and DNS blocklist.
//!
//! Provides a stateless packet filter that evaluates raw IPv4 packets against
//! an ordered rule set. DNS queries to surveillance domains are blocked before
//! rule evaluation. The filter is designed to sit between the network device
//! and smoltcp's interface — callers invoke [`Firewall::evaluate_rx`] on
//! inbound packets and [`Firewall::evaluate_tx`] on outbound packets.
//!
//! # Architecture
//!
//! Rules are evaluated in insertion order (first match wins). If no rule
//! matches, the direction-specific default policy applies: deny all inbound,
//! allow all outbound. Parse failures are fail-closed (denied).
//!
//! The DNS blocklist checks outbound UDP port 53 queries against a hardcoded
//! set of surveillance domain suffixes. A match causes the packet to be
//! denied before rule evaluation.
//!
//! # Integration
//!
//! `net.rs` wires this filter through a device wrapper that evaluates RX
//! packets before smoltcp sees them and TX packets before the driver sends
//! them. Callers can still use [`Firewall::evaluate_rx`] and
//! [`Firewall::evaluate_tx`] at other packet interception points.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use crate::audit::{AuditEventType, AuditLog};
use crate::security::KEY_SIZE;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// IPv4 minimum header length in bytes (IHL = 5).
const IPV4_MIN_HEADER_LEN: usize = 20;

/// IPv4 version number.
const IPV4_VERSION: u8 = 4;

/// Minimum IHL value (5 = 20 bytes).
const MIN_IHL: u8 = 5;

/// TCP minimum header length in bytes.
const TCP_MIN_HEADER_LEN: usize = 20;

/// UDP header length in bytes.
const UDP_HEADER_LEN: usize = 8;

/// IP protocol number for ICMP.
const PROTO_ICMP: u8 = 1;

/// IP protocol number for TCP.
const PROTO_TCP: u8 = 6;

/// IP protocol number for UDP.
const PROTO_UDP: u8 = 17;

/// DNS port number.
const DNS_PORT: u16 = 53;

/// DNS message header length in bytes.
const DNS_HEADER_LEN: usize = 12;

/// Maximum number of labels to follow when decoding a DNS QNAME.
const MAX_LABELS: usize = 128;

/// Surveillance domains blocked by default.
///
/// These are the advertising, analytics, and telemetry domains identified
/// in the thumos security brainstorm. Matching is by suffix: a domain is
/// blocked if it equals or is a subdomain of any entry.
const SURVEILLANCE_DOMAINS: &[&str] = &[
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

// ---------------------------------------------------------------------------
// Type definitions
// ---------------------------------------------------------------------------

/// Action to take on a packet after rule evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Action {
    /// Forward the packet.
    Allow,
    /// Drop the packet.
    Deny,
    /// Forward the packet and log the event.
    #[expect(dead_code, reason = "log action reserved for audit-policy rules")]
    Log,
}

/// Traffic direction relative to the device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Direction {
    /// Traffic arriving from an external interface.
    Inbound,
    /// Traffic leaving toward an external interface.
    Outbound,
}

/// Layer-4 protocol selector for a [`FilterRule`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Protocol {
    /// Match TCP segments.
    Tcp,
    /// Match UDP datagrams.
    Udp,
    /// Match ICMP messages.
    Icmp,
}

impl core::fmt::Display for Action {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Allow => write!(f, "allow"),
            Self::Deny => write!(f, "deny"),
            Self::Log => write!(f, "log"),
        }
    }
}

impl core::fmt::Display for Direction {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Inbound => write!(f, "inbound"),
            Self::Outbound => write!(f, "outbound"),
        }
    }
}

/// An IPv4 address represented as four octets.
///
/// Equivalent to `smoltcp::wire::Ipv4Address` but kept local to avoid
/// coupling the firewall module to smoltcp directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Address(pub [u8; 4]);

/// A single firewall rule.
///
/// All specified fields must match for the rule to fire. `None` fields are
/// treated as wildcards (match any value).
#[derive(Debug, Clone)]
pub struct FilterRule {
    /// Which direction this rule applies to.
    pub direction: Direction,
    /// Protocol constraint. `None` matches any protocol.
    pub protocol: Option<Protocol>,
    /// Source IPv4 address constraint.
    pub src_addr: Option<Ipv4Address>,
    /// Destination IPv4 address constraint.
    pub dst_addr: Option<Ipv4Address>,
    /// Destination port constraint.
    pub dst_port: Option<u16>,
    /// Action to take when this rule matches.
    pub action: Action,
}

impl core::fmt::Display for FilterRule {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} {}", self.direction, self.action)?;
        if let Some(proto) = self.protocol {
            write!(f, " {proto:?}")?;
        }
        if let Some(port) = self.dst_port {
            write!(f, " port {port}")?;
        }
        Ok(())
    }
}

/// Packet statistics tracked by the firewall.
#[derive(Debug, Clone, Default)]
pub struct FirewallStats {
    /// Total packets that resulted in [`Action::Allow`] or [`Action::Log`].
    pub packets_allowed: u64,
    /// Total packets that resulted in [`Action::Deny`].
    pub packets_denied: u64,
    /// Total DNS queries blocked by the domain blocklist.
    pub dns_blocked: u64,
}

impl core::fmt::Display for FirewallStats {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "allowed={}, denied={}, dns_blocked={}",
            self.packets_allowed, self.packets_denied, self.dns_blocked,
        )
    }
}

/// Packet filter combining an ordered rule set, a DNS domain blocklist,
/// direction-specific default policies, and per-action statistics.
pub(crate) struct Firewall {
    /// Ordered list of filter rules. First match wins.
    rules: Vec<FilterRule>,
    /// Domain suffixes to block in DNS queries.
    dns_blocklist: Vec<String>,
    /// Packet statistics.
    stats: FirewallStats,
    /// Default action for inbound packets when no rule matches.
    default_inbound: Action,
    /// Default action for outbound packets when no rule matches.
    default_outbound: Action,
}

/// Extracted packet header fields used for rule matching.
struct PacketInfo {
    protocol: Protocol,
    src_addr: Ipv4Address,
    dst_addr: Ipv4Address,
    dst_port: Option<u16>,
}

// ---------------------------------------------------------------------------
// Impl blocks
// ---------------------------------------------------------------------------

impl Firewall {
    /// Create a firewall with default policies: deny all inbound, allow all
    /// outbound. No rules or DNS blocklist entries are configured.
    pub(crate) fn new() -> Self {
        Self {
            rules: Vec::new(),
            dns_blocklist: Vec::new(),
            stats: FirewallStats::default(),
            default_inbound: Action::Deny,
            default_outbound: Action::Allow,
        }
    }

    /// Prepend a rule to the rule list.
    ///
    /// Rules are evaluated in order and the first match wins, so prepending
    /// gives the new rule highest priority.
    #[expect(dead_code, reason = "dynamic firewall rules await policy wiring")]
    pub(crate) fn add_rule(&mut self, rule: FilterRule) {
        self.rules.insert(0, rule);
    }

    /// Add a domain suffix to the DNS blocklist.
    ///
    /// Any DNS query whose queried domain equals or is a subdomain of
    /// `suffix` will be denied. Matching is case-insensitive.
    pub(crate) fn add_dns_block(&mut self, suffix: &str) {
        self.dns_blocklist.push(suffix.to_ascii_lowercase());
    }

    /// Evaluate an inbound (RX) packet against the firewall rules.
    ///
    /// Parses the raw IPv4 packet, checks DNS blocklist for outbound DNS
    /// queries, then evaluates rules in order. If no rule matches, the
    /// default inbound policy (deny) applies. Parse failures are denied
    /// (fail-closed).
    pub(crate) fn evaluate_rx(&mut self, packet: &[u8]) -> Action {
        let action = self.classify(packet, Direction::Inbound);
        self.record(action);
        action
    }

    /// Evaluate an outbound (TX) packet against the firewall rules.
    ///
    /// DNS queries to blocked domains are denied before rule evaluation.
    /// If no rule matches, the default outbound policy (allow) applies.
    /// Parse failures are denied (fail-closed).
    pub(crate) fn evaluate_tx(&mut self, packet: &[u8]) -> Action {
        let action = self.classify(packet, Direction::Outbound);
        self.record(action);
        action
    }

    /// Check whether a hostname matches any entry in the DNS blocklist.
    ///
    /// A hostname is blocked if it equals a blocklist entry or is a
    /// subdomain of one (e.g., `"sub.doubleclick.net"` matches
    /// `"doubleclick.net"`). Matching is case-insensitive.
    pub(crate) fn is_dns_blocked(&self, hostname: &str) -> bool {
        let lower = hostname.to_ascii_lowercase();
        self.dns_blocklist
            .iter()
            .any(|suffix| domain_matches_suffix(&lower, suffix))
    }

    /// Return a reference to the firewall statistics.
    #[cfg_attr(not(test), expect(dead_code, reason = "runtime firewall metrics UI pending"))]
    pub(crate) fn stats(&self) -> &FirewallStats {
        &self.stats
    }

    /// Populate the DNS blocklist with the default surveillance domains.
    ///
    /// Appends [`SURVEILLANCE_DOMAINS`] to any existing blocklist entries.
    pub(crate) fn load_default_blocklist(&mut self) {
        for domain in SURVEILLANCE_DOMAINS {
            self.add_dns_block(domain);
        }
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /// Parse the packet and classify it against rules and blocklist.
    fn classify(&mut self, packet: &[u8], direction: Direction) -> Action {
        let info = match parse_packet(packet) {
            Some(info) => info,
            None => return Action::Deny,
        };

        // Check DNS blocklist for UDP port 53 queries (both directions).
        if info.protocol == Protocol::Udp
            && info.dst_port == Some(DNS_PORT)
            && self
                .check_dns_blocklist(packet, &info)
                .is_some_and(|blocked| blocked)
        {
            self.stats.dns_blocked += 1;
            return Action::Deny;
        }

        // Evaluate rules in order (first match wins).
        for rule in &self.rules {
            if rule_matches(rule, direction, &info) {
                return rule.action;
            }
        }

        // Apply direction-specific default.
        match direction {
            Direction::Inbound => self.default_inbound,
            Direction::Outbound => self.default_outbound,
        }
    }

    /// Extract the DNS payload from a UDP packet and check the blocklist.
    ///
    /// Returns `Some(true)` if blocked, `Some(false)` if not blocked,
    /// `None` if the DNS payload could not be extracted.
    fn check_dns_blocklist(&self, packet: &[u8], info: &PacketInfo) -> Option<bool> {
        if self.dns_blocklist.is_empty() {
            return Some(false);
        }

        // IP header length.
        let ihl = (packet.first()? & 0x0F) as usize * 4;
        // UDP payload starts after IP header + 8-byte UDP header.
        let dns_start = ihl.checked_add(UDP_HEADER_LEN)?;
        let dns_payload = packet.get(dns_start..)?;

        let _ = info; // info already used for protocol/port check above
        let domain = extract_query_domain(dns_payload)?;
        Some(self.is_dns_blocked(&domain))
    }

    /// Update statistics based on the action taken.
    fn record(&mut self, action: Action) {
        match action {
            Action::Allow | Action::Log => self.stats.packets_allowed += 1,
            Action::Deny => self.stats.packets_denied += 1,
        }
    }
}

// ---------------------------------------------------------------------------
// Audit integration
// ---------------------------------------------------------------------------

/// Log a firewall packet deny event to the audit log.
///
/// Called when [`Firewall::evaluate_rx`] or [`Firewall::evaluate_tx`]
/// denies a packet. The `direction` indicates whether the packet was
/// inbound or outbound.
#[expect(dead_code, reason = "audit key plumbing is not available at net device hook yet")]
pub(crate) fn log_packet_deny(
    direction: Direction,
    audit_log: &mut AuditLog,
    audit_key: &[u8; KEY_SIZE],
    timestamp: u64,
) {
    let detail = match direction {
        Direction::Inbound => b"inbound packet denied" as &[u8],
        Direction::Outbound => b"outbound packet denied",
    };
    let _ = audit_log.log_event(
        AuditEventType::PacketDeny,
        0,
        detail,
        timestamp,
        audit_key,
    );
}

// ---------------------------------------------------------------------------
// Packet parsing (ported from asphaleia::packet for no_std)
// ---------------------------------------------------------------------------

/// Parse an IPv4 packet and extract the fields needed for rule matching.
///
/// Returns `None` if the packet is malformed or too short.
fn parse_packet(packet: &[u8]) -> Option<PacketInfo> {
    if packet.len() < IPV4_MIN_HEADER_LEN {
        return None;
    }

    let version_ihl = *packet.first()?;
    let version = version_ihl >> 4;
    let ihl = version_ihl & 0x0F;

    if version != IPV4_VERSION {
        return None;
    }
    if ihl < MIN_IHL {
        return None;
    }

    let header_len = (ihl as usize) * 4;
    if packet.len() < header_len {
        return None;
    }

    let proto_byte = *packet.get(9)?;
    let src_addr = Ipv4Address([
        *packet.get(12)?,
        *packet.get(13)?,
        *packet.get(14)?,
        *packet.get(15)?,
    ]);
    let dst_addr = Ipv4Address([
        *packet.get(16)?,
        *packet.get(17)?,
        *packet.get(18)?,
        *packet.get(19)?,
    ]);

    let payload = packet.get(header_len..)?;

    match proto_byte {
        PROTO_TCP => {
            if payload.len() < TCP_MIN_HEADER_LEN {
                return None;
            }
            let dst_port = u16::from_be_bytes([*payload.get(2)?, *payload.get(3)?]);
            Some(PacketInfo {
                protocol: Protocol::Tcp,
                src_addr,
                dst_addr,
                dst_port: Some(dst_port),
            })
        }
        PROTO_UDP => {
            if payload.len() < UDP_HEADER_LEN {
                return None;
            }
            let dst_port = u16::from_be_bytes([*payload.get(2)?, *payload.get(3)?]);
            Some(PacketInfo {
                protocol: Protocol::Udp,
                src_addr,
                dst_addr,
                dst_port: Some(dst_port),
            })
        }
        PROTO_ICMP => Some(PacketInfo {
            protocol: Protocol::Icmp,
            src_addr,
            dst_addr,
            dst_port: None,
        }),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// DNS query domain extraction (ported from asphaleia::dns for no_std)
// ---------------------------------------------------------------------------

/// Extract the QNAME from the first question in a DNS query message.
///
/// `data` must be the DNS message payload (after the UDP header).
/// Returns `None` if the message is malformed, truncated, or uses
/// compression pointers.
fn extract_query_domain(data: &[u8]) -> Option<String> {
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
            break;
        }

        // Reject compression pointers.
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
        domain.push_str(label);

        pos = label_end;
    }

    if domain.is_empty() {
        None
    } else {
        Some(domain)
    }
}

// ---------------------------------------------------------------------------
// Rule matching
// ---------------------------------------------------------------------------

/// Check whether a single rule matches the given direction and packet info.
fn rule_matches(rule: &FilterRule, direction: Direction, info: &PacketInfo) -> bool {
    if rule.direction != direction {
        return false;
    }

    if let Some(proto) = rule.protocol
        && proto != info.protocol
    {
        return false;
    }

    if let Some(src) = rule.src_addr
        && src != info.src_addr
    {
        return false;
    }

    if let Some(dst) = rule.dst_addr
        && dst != info.dst_addr
    {
        return false;
    }

    if let Some(rule_port) = rule.dst_port {
        match info.dst_port {
            Some(pkt_port) => {
                if rule_port != pkt_port {
                    return false;
                }
            }
            None => return false,
        }
    }

    true
}

/// Check whether a domain equals or is a subdomain of a blocklist suffix.
///
/// `"sub.doubleclick.net"` matches suffix `"doubleclick.net"`.
/// `"doubleclick.net"` matches suffix `"doubleclick.net"`.
/// `"notdoubleclick.net"` does NOT match suffix `"doubleclick.net"`.
fn domain_matches_suffix(domain: &str, suffix: &str) -> bool {
    if domain == suffix {
        return true;
    }
    // Check if domain ends with ".suffix" (genuine subdomain).
    domain
        .strip_suffix(suffix)
        .is_some_and(|rest| rest.ends_with('.'))
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/// Build a minimal IPv4/TCP packet for testing.
#[cfg(test)]
fn make_ip_tcp(
    src: [u8; 4],
    dst: [u8; 4],
    src_port: u16,
    dst_port: u16,
) -> alloc::vec::Vec<u8> {
    let mut pkt = alloc::vec![0u8; 40];
    pkt[0] = 0x45; // version=4, IHL=5
    pkt[2] = 0x00;
    pkt[3] = 40; // total length
    pkt[9] = PROTO_TCP;
    pkt[12..16].copy_from_slice(&src);
    pkt[16..20].copy_from_slice(&dst);
    let sp = src_port.to_be_bytes();
    let dp = dst_port.to_be_bytes();
    pkt[20] = sp[0];
    pkt[21] = sp[1];
    pkt[22] = dp[0];
    pkt[23] = dp[1];
    pkt[32] = 0x50; // data offset = 5 (20 bytes)
    pkt
}

/// Build a minimal IPv4/UDP packet for testing.
#[cfg(test)]
fn make_ip_udp(
    src: [u8; 4],
    dst: [u8; 4],
    src_port: u16,
    dst_port: u16,
    udp_payload: &[u8],
) -> alloc::vec::Vec<u8> {
    let total = 20 + 8 + udp_payload.len();
    let mut pkt = alloc::vec![0u8; total];
    pkt[0] = 0x45; // version=4, IHL=5
    let tl = (total as u16).to_be_bytes();
    pkt[2] = tl[0];
    pkt[3] = tl[1];
    pkt[9] = PROTO_UDP;
    pkt[12..16].copy_from_slice(&src);
    pkt[16..20].copy_from_slice(&dst);
    let sp = src_port.to_be_bytes();
    let dp = dst_port.to_be_bytes();
    pkt[20] = sp[0];
    pkt[21] = sp[1];
    pkt[22] = dp[0];
    pkt[23] = dp[1];
    let ul = ((8 + udp_payload.len()) as u16).to_be_bytes();
    pkt[24] = ul[0];
    pkt[25] = ul[1];
    if !udp_payload.is_empty() {
        pkt[28..].copy_from_slice(udp_payload);
    }
    pkt
}

/// Build a minimal DNS query message for a given domain.
#[cfg(test)]
fn make_dns_query(domain: &str) -> alloc::vec::Vec<u8> {
    let mut msg = alloc::vec::Vec::new();
    // DNS header: ID=0x0001, flags=standard query, QDCOUNT=1
    msg.extend_from_slice(&[
        0x00, 0x01, // ID
        0x01, 0x00, // flags: standard query, RD=1
        0x00, 0x01, // QDCOUNT = 1
        0x00, 0x00, // ANCOUNT = 0
        0x00, 0x00, // NSCOUNT = 0
        0x00, 0x00, // ARCOUNT = 0
    ]);
    // QNAME: length-prefixed labels
    for label in domain.split('.') {
        let b = label.as_bytes();
        msg.push(b.len() as u8);
        msg.extend_from_slice(b);
    }
    msg.push(0x00); // root label
    // QTYPE = A (1), QCLASS = IN (1)
    msg.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
    msg
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_denies_inbound() {
        let mut fw = Firewall::new();
        let pkt = make_ip_tcp([1, 2, 3, 4], [10, 0, 0, 1], 54321, 80);
        assert_eq!(
            fw.evaluate_rx(&pkt),
            Action::Deny,
            "default inbound policy must deny all packets"
        );
    }

    #[test]
    fn default_allows_outbound() {
        let mut fw = Firewall::new();
        let pkt = make_ip_tcp([10, 0, 0, 1], [1, 2, 3, 4], 54321, 80);
        assert_eq!(
            fw.evaluate_tx(&pkt),
            Action::Allow,
            "default outbound policy must allow all packets"
        );
    }

    #[test]
    fn custom_rule_allows_specific_inbound_port() {
        let mut fw = Firewall::new();
        fw.add_rule(FilterRule {
            direction: Direction::Inbound,
            protocol: Some(Protocol::Tcp),
            src_addr: None,
            dst_addr: None,
            dst_port: Some(443),
            action: Action::Allow,
        });

        let allowed = make_ip_tcp([1, 2, 3, 4], [10, 0, 0, 1], 54321, 443);
        assert_eq!(
            fw.evaluate_rx(&allowed),
            Action::Allow,
            "rule allowing TCP port 443 inbound must permit matching packet"
        );

        let denied = make_ip_tcp([1, 2, 3, 4], [10, 0, 0, 1], 54321, 80);
        assert_eq!(
            fw.evaluate_rx(&denied),
            Action::Deny,
            "no rule for port 80 — default deny must apply"
        );
    }

    #[test]
    fn first_matching_rule_wins() {
        let mut fw = Firewall::new();

        // Add deny-all first (will be prepended, so it goes to position 0).
        fw.add_rule(FilterRule {
            direction: Direction::Inbound,
            protocol: None,
            src_addr: None,
            dst_addr: None,
            dst_port: None,
            action: Action::Deny,
        });

        // Add allow-all second (prepended, so it goes to position 0, pushing deny to 1).
        fw.add_rule(FilterRule {
            direction: Direction::Inbound,
            protocol: None,
            src_addr: None,
            dst_addr: None,
            dst_port: None,
            action: Action::Allow,
        });

        let pkt = make_ip_tcp([1, 2, 3, 4], [10, 0, 0, 1], 54321, 80);
        assert_eq!(
            fw.evaluate_rx(&pkt),
            Action::Allow,
            "later-added allow rule was prepended and must win over earlier deny"
        );
    }

    #[test]
    fn dns_blocklist_blocks_surveillance_domain() {
        let mut fw = Firewall::new();
        fw.load_default_blocklist();

        assert!(
            fw.is_dns_blocked("app-measurement.com"),
            "exact surveillance domain must be blocked"
        );
        assert!(
            fw.is_dns_blocked("sub.doubleclick.net"),
            "subdomain of surveillance domain must be blocked"
        );
        assert!(
            fw.is_dns_blocked("analytics.google.com"),
            "analytics.google.com must be blocked"
        );
    }

    #[test]
    fn dns_blocklist_allows_clean_domain() {
        let mut fw = Firewall::new();
        fw.load_default_blocklist();

        assert!(
            !fw.is_dns_blocked("example.com"),
            "example.com must not be blocked"
        );
        assert!(
            !fw.is_dns_blocked("google.com"),
            "google.com itself must not be blocked"
        );
        assert!(
            !fw.is_dns_blocked("notdoubleclick.net"),
            "notdoubleclick.net must not match doubleclick.net suffix"
        );
    }

    #[test]
    fn stats_track_allowed_and_denied() {
        let mut fw = Firewall::new();

        // Outbound defaults to allow.
        let out_pkt = make_ip_tcp([10, 0, 0, 1], [1, 2, 3, 4], 54321, 80);
        fw.evaluate_tx(&out_pkt);
        fw.evaluate_tx(&out_pkt);

        // Inbound defaults to deny.
        let in_pkt = make_ip_tcp([1, 2, 3, 4], [10, 0, 0, 1], 54321, 80);
        fw.evaluate_rx(&in_pkt);

        assert_eq!(
            fw.stats().packets_allowed, 2,
            "two outbound packets must be counted as allowed"
        );
        assert_eq!(
            fw.stats().packets_denied, 1,
            "one inbound packet must be counted as denied"
        );
    }

    #[test]
    fn evaluate_rx_parses_tcp_packet() {
        let mut fw = Firewall::new();
        fw.add_rule(FilterRule {
            direction: Direction::Inbound,
            protocol: Some(Protocol::Tcp),
            src_addr: Some(Ipv4Address([10, 0, 0, 2])),
            dst_addr: None,
            dst_port: Some(443),
            action: Action::Allow,
        });

        let pkt = make_ip_tcp([10, 0, 0, 2], [10, 0, 0, 1], 54321, 443);
        assert_eq!(
            fw.evaluate_rx(&pkt),
            Action::Allow,
            "TCP packet from 10.0.0.2 to port 443 must match allow rule"
        );

        // Different source — should not match.
        let pkt2 = make_ip_tcp([10, 0, 0, 3], [10, 0, 0, 1], 54321, 443);
        assert_eq!(
            fw.evaluate_rx(&pkt2),
            Action::Deny,
            "TCP packet from 10.0.0.3 must not match rule for 10.0.0.2"
        );
    }

    #[test]
    fn evaluate_rx_parses_udp_packet() {
        let mut fw = Firewall::new();
        fw.add_rule(FilterRule {
            direction: Direction::Inbound,
            protocol: Some(Protocol::Udp),
            src_addr: None,
            dst_addr: None,
            dst_port: Some(5353),
            action: Action::Allow,
        });

        let pkt = make_ip_udp([10, 0, 0, 2], [10, 0, 0, 1], 54321, 5353, &[]);
        assert_eq!(
            fw.evaluate_rx(&pkt),
            Action::Allow,
            "UDP packet to port 5353 must match allow rule"
        );

        let pkt2 = make_ip_udp([10, 0, 0, 2], [10, 0, 0, 1], 54321, 5354, &[]);
        assert_eq!(
            fw.evaluate_rx(&pkt2),
            Action::Deny,
            "UDP packet to port 5354 must not match rule for 5353"
        );
    }

    #[test]
    fn load_default_blocklist_populates_entries() {
        let mut fw = Firewall::new();
        assert!(
            fw.dns_blocklist.is_empty(),
            "blocklist must start empty"
        );

        fw.load_default_blocklist();
        assert_eq!(
            fw.dns_blocklist.len(),
            SURVEILLANCE_DOMAINS.len(),
            "blocklist must contain all surveillance domains after loading defaults"
        );

        // Verify each surveillance domain is blocked.
        for domain in SURVEILLANCE_DOMAINS {
            assert!(
                fw.is_dns_blocked(domain),
                "{domain} must be blocked after loading default blocklist"
            );
        }
    }

    #[test]
    fn dns_blocklist_denies_outbound_dns_query() {
        let mut fw = Firewall::new();
        fw.load_default_blocklist();

        let dns_payload = make_dns_query("app-measurement.com");
        let pkt = make_ip_udp([10, 0, 0, 1], [8, 8, 8, 8], 54321, DNS_PORT, &dns_payload);
        assert_eq!(
            fw.evaluate_tx(&pkt),
            Action::Deny,
            "outbound DNS query for surveillance domain must be denied"
        );
        assert_eq!(
            fw.stats().dns_blocked, 1,
            "dns_blocked counter must increment for blocked DNS query"
        );
    }

    #[test]
    fn dns_blocklist_allows_clean_dns_query() {
        let mut fw = Firewall::new();
        fw.load_default_blocklist();

        let dns_payload = make_dns_query("example.com");
        let pkt = make_ip_udp([10, 0, 0, 1], [8, 8, 8, 8], 54321, DNS_PORT, &dns_payload);
        assert_eq!(
            fw.evaluate_tx(&pkt),
            Action::Allow,
            "outbound DNS query for clean domain must be allowed"
        );
        assert_eq!(
            fw.stats().dns_blocked, 0,
            "dns_blocked counter must not increment for clean domain"
        );
    }

    #[test]
    fn malformed_packet_denied() {
        let mut fw = Firewall::new();
        // Even with allow-all outbound default, garbage packets should be denied.
        let garbage = [0xFF_u8; 5];
        assert_eq!(
            fw.evaluate_tx(&garbage),
            Action::Deny,
            "malformed packet must be denied (fail-closed)"
        );
    }

    #[test]
    fn log_action_counts_as_allowed() {
        let mut fw = Firewall::new();
        fw.add_rule(FilterRule {
            direction: Direction::Inbound,
            protocol: None,
            src_addr: None,
            dst_addr: None,
            dst_port: None,
            action: Action::Log,
        });

        let pkt = make_ip_tcp([1, 2, 3, 4], [10, 0, 0, 1], 54321, 80);
        let action = fw.evaluate_rx(&pkt);
        assert_eq!(action, Action::Log, "Log rule must return Log action");
        assert_eq!(
            fw.stats().packets_allowed, 1,
            "Log action must count as allowed"
        );
    }

    #[test]
    fn dns_blocklist_case_insensitive() {
        let mut fw = Firewall::new();
        fw.add_dns_block("Example.COM");

        assert!(
            fw.is_dns_blocked("example.com"),
            "lowercase query must match mixed-case blocklist entry"
        );
        assert!(
            fw.is_dns_blocked("EXAMPLE.COM"),
            "uppercase query must match mixed-case blocklist entry"
        );
    }
}
