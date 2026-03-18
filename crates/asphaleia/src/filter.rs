//! Packet filter engine.
//!
//! [`Filter`] combines a [`RuleSet`] with an optional [`DnsBlocklist`] to
//! evaluate raw IP packets. DNS queries to blocked domains are denied before
//! rule evaluation. Parse failures default to deny.

use crate::dns::{DNS_PORT, DnsBlocklist};
use crate::packet::{IpHeader, PROTO_ICMP, PROTO_TCP, PROTO_UDP, TcpHeader, UdpHeader};
use crate::rules::{Action, Direction, PacketInfo, Protocol, RuleSet};

// Type definitions

/// Packet filter combining a rule set, an optional DNS blocklist, and
/// per-action statistics counters.
#[derive(Debug, Default)]
pub struct Filter {
    ruleset: RuleSet,
    blocklist: Option<DnsBlocklist>,
    /// Total packets that resulted in [`Action::Allow`] or [`Action::LogAndAllow`].
    pub packets_allowed: u64,
    /// Total packets that resulted in [`Action::Deny`] or [`Action::LogAndDeny`].
    pub packets_denied: u64,
    /// Total packets that produced a log entry (either `LogAndAllow` or `LogAndDeny`).
    pub packets_logged: u64,
}

// Impl blocks

impl Filter {
    /// Create a filter with an empty rule set and no DNS blocklist.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a filter with a pre-populated rule set.
    #[must_use]
    pub fn with_ruleset(ruleset: RuleSet) -> Self {
        Self {
            ruleset,
            ..Self::default()
        }
    }

    /// Attach a DNS blocklist. DNS queries matching the blocklist are denied
    /// before any rules are evaluated.
    pub fn set_blocklist(&mut self, blocklist: DnsBlocklist) {
        self.blocklist = Some(blocklist);
    }

    /// Provide mutable access to the rule set.
    pub const fn ruleset_mut(&mut self) -> &mut RuleSet {
        &mut self.ruleset
    }

    /// Evaluate a raw IPv4 packet and return the action to take.
    ///
    /// All packets from the modem are treated as inbound (`Direction::In`).
    /// Packets that fail to parse are denied (fail-closed).
    pub fn evaluate(&mut self, packet: &[u8]) -> Action {
        let action = self.classify(packet);
        self.record(action);
        action
    }

    // Private helpers

    fn classify(&self, packet: &[u8]) -> Action {
        let Ok(ip) = IpHeader::parse(packet) else {
            return Action::Deny;
        };

        let Some(payload) = packet.get(ip.header_len()..) else {
            return Action::Deny;
        };

        let (protocol, src_port, dst_port) = match ip.protocol {
            PROTO_TCP => {
                let Ok(tcp) = TcpHeader::parse(payload) else {
                    return Action::Deny;
                };
                (Protocol::Tcp, Some(tcp.src_port), Some(tcp.dst_port))
            }
            PROTO_UDP => {
                let Ok(udp) = UdpHeader::parse(payload) else {
                    return Action::Deny;
                };

                // Check DNS blocklist before rule evaluation.
                if udp.dst_port == DNS_PORT
                    && let Some(bl) = &self.blocklist
                {
                    let dns_payload = payload.get(8..).unwrap_or(&[]);
                    if bl.blocks_dns_payload(dns_payload) {
                        return Action::Deny;
                    }
                }

                (Protocol::Udp, Some(udp.src_port), Some(udp.dst_port))
            }
            PROTO_ICMP => (Protocol::Icmp, None, None),
            _ => (Protocol::Any, None, None),
        };

        let info = PacketInfo {
            direction: Direction::In,
            protocol,
            src_addr: ip.src_addr,
            dst_addr: ip.dst_addr,
            src_port,
            dst_port,
        };

        self.ruleset.evaluate(&info)
    }

    const fn record(&mut self, action: Action) {
        if action.is_allow() {
            self.packets_allowed += 1;
        } else {
            self.packets_denied += 1;
        }
        if action.is_logged() {
            self.packets_logged += 1;
        }
    }
}

// Tests

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::rules::{AddressMatch, PortMatch, Rule};

    fn make_ip_tcp(src: [u8; 4], dst: [u8; 4], src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x45;
        pkt[2] = 0x00;
        pkt[3] = 40;
        pkt[9] = PROTO_TCP;
        pkt[12..16].copy_from_slice(&src);
        pkt[16..20].copy_from_slice(&dst);
        let sp = src_port.to_be_bytes();
        let dp = dst_port.to_be_bytes();
        pkt[20] = sp[0];
        pkt[21] = sp[1];
        pkt[22] = dp[0];
        pkt[23] = dp[1];
        pkt[32] = 0x50; // data offset
        pkt
    }

    fn make_ip_udp(
        src: [u8; 4],
        dst: [u8; 4],
        src_port: u16,
        dst_port: u16,
        udp_payload: &[u8],
    ) -> Vec<u8> {
        let total = 20 + 8 + udp_payload.len();
        let mut pkt = vec![0u8; total];
        pkt[0] = 0x45;
        let tl = u16::try_from(total).unwrap_or(u16::MAX);
        let tl_bytes = tl.to_be_bytes();
        pkt[2] = tl_bytes[0];
        pkt[3] = tl_bytes[1];
        pkt[9] = PROTO_UDP;
        pkt[12..16].copy_from_slice(&src);
        pkt[16..20].copy_from_slice(&dst);
        let sp = src_port.to_be_bytes();
        let dp = dst_port.to_be_bytes();
        pkt[20] = sp[0];
        pkt[21] = sp[1];
        pkt[22] = dp[0];
        pkt[23] = dp[1];
        let ul = u16::try_from(8 + udp_payload.len()).unwrap_or(u16::MAX);
        let ul_bytes = ul.to_be_bytes();
        pkt[24] = ul_bytes[0];
        pkt[25] = ul_bytes[1];
        pkt[28..].copy_from_slice(udp_payload);
        pkt
    }

    fn make_dns_query_bytes(domain: &str) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(&[
            0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);
        for label in domain.split('.') {
            let b = label.as_bytes();
            msg.push(b.len() as u8);
            msg.extend_from_slice(b);
        }
        msg.push(0x00);
        msg.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        msg
    }

    #[test]
    fn empty_filter_denies_all_packets() {
        let mut f = Filter::new();
        let pkt = make_ip_tcp([1, 2, 3, 4], [10, 0, 0, 1], 54321, 80);
        assert_eq!(
            f.evaluate(&pkt),
            Action::Deny,
            "empty filter must deny all packets"
        );
    }

    #[test]
    fn allow_rule_permits_matching_packet() {
        let mut f = Filter::new();
        f.ruleset_mut().add_rule(Rule {
            direction: Direction::In,
            protocol: Protocol::Tcp,
            src_addr: AddressMatch::any(),
            dst_addr: AddressMatch::any(),
            src_port: PortMatch::Any,
            dst_port: PortMatch::Single(80),
            action: Action::Allow,
        });
        let pkt = make_ip_tcp([1, 2, 3, 4], [10, 0, 0, 1], 54321, 80);
        assert_eq!(
            f.evaluate(&pkt),
            Action::Allow,
            "matching allow rule must permit packet to port 80"
        );
    }

    #[test]
    fn malformed_packet_is_denied() {
        let mut f = Filter::new();
        f.ruleset_mut().add_rule(Rule {
            direction: Direction::In,
            protocol: Protocol::Any,
            src_addr: AddressMatch::any(),
            dst_addr: AddressMatch::any(),
            src_port: PortMatch::Any,
            dst_port: PortMatch::Any,
            action: Action::Allow,
        });
        let garbage = [0xFFu8; 5];
        assert_eq!(
            f.evaluate(&garbage),
            Action::Deny,
            "unparseable packet must be denied even with allow-all rule"
        );
    }

    #[test]
    fn statistics_count_allowed_and_denied() {
        let mut f = Filter::new();
        f.ruleset_mut().add_rule(Rule {
            direction: Direction::In,
            protocol: Protocol::Tcp,
            src_addr: AddressMatch::host(Ipv4Addr::new(10, 0, 0, 2)),
            dst_addr: AddressMatch::any(),
            src_port: PortMatch::Any,
            dst_port: PortMatch::Any,
            action: Action::Allow,
        });

        let allowed = make_ip_tcp([10, 0, 0, 2], [10, 0, 0, 1], 1234, 443);
        let denied = make_ip_tcp([10, 0, 0, 3], [10, 0, 0, 1], 1234, 443);

        f.evaluate(&allowed);
        f.evaluate(&allowed);
        f.evaluate(&denied);

        assert_eq!(f.packets_allowed, 2, "two allowed packets must be counted");
        assert_eq!(f.packets_denied, 1, "one denied packet must be counted");
        assert_eq!(
            f.packets_logged, 0,
            "no logged packets for plain allow/deny"
        );
    }

    #[test]
    fn log_and_deny_increments_both_denied_and_logged() {
        let mut f = Filter::new();
        f.ruleset_mut().add_rule(Rule {
            direction: Direction::In,
            protocol: Protocol::Any,
            src_addr: AddressMatch::any(),
            dst_addr: AddressMatch::any(),
            src_port: PortMatch::Any,
            dst_port: PortMatch::Any,
            action: Action::LogAndDeny,
        });

        let pkt = make_ip_tcp([1, 2, 3, 4], [10, 0, 0, 1], 12345, 80);
        f.evaluate(&pkt);

        assert_eq!(
            f.packets_denied, 1,
            "LogAndDeny must increment denied count"
        );
        assert_eq!(
            f.packets_logged, 1,
            "LogAndDeny must increment logged count"
        );
        assert_eq!(
            f.packets_allowed, 0,
            "LogAndDeny must not increment allowed count"
        );
    }

    #[test]
    fn dns_blocklist_blocks_surveillance_domain() {
        let mut f = Filter::new();
        // Allow all traffic so we can isolate the DNS blocklist effect.
        f.ruleset_mut().add_rule(Rule {
            direction: Direction::In,
            protocol: Protocol::Any,
            src_addr: AddressMatch::any(),
            dst_addr: AddressMatch::any(),
            src_port: PortMatch::Any,
            dst_port: PortMatch::Any,
            action: Action::Allow,
        });
        f.set_blocklist(DnsBlocklist::with_surveillance_defaults());

        let dns_payload = make_dns_query_bytes("app-measurement.com");
        let pkt = make_ip_udp([10, 0, 0, 2], [8, 8, 8, 8], 54321, DNS_PORT, &dns_payload);
        assert_eq!(
            f.evaluate(&pkt),
            Action::Deny,
            "DNS query for app-measurement.com must be denied by blocklist"
        );
    }

    #[test]
    fn dns_blocklist_allows_safe_domain() {
        let mut f = Filter::new();
        f.ruleset_mut().add_rule(Rule {
            direction: Direction::In,
            protocol: Protocol::Any,
            src_addr: AddressMatch::any(),
            dst_addr: AddressMatch::any(),
            src_port: PortMatch::Any,
            dst_port: PortMatch::Any,
            action: Action::Allow,
        });
        f.set_blocklist(DnsBlocklist::with_surveillance_defaults());

        let dns_payload = make_dns_query_bytes("example.com");
        let pkt = make_ip_udp([10, 0, 0, 2], [8, 8, 8, 8], 54321, DNS_PORT, &dns_payload);
        assert_eq!(
            f.evaluate(&pkt),
            Action::Allow,
            "DNS query for example.com must pass the blocklist"
        );
    }
}
