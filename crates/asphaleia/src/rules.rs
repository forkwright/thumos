//! Packet filter rule types.
//!
//! Rules are evaluated in order; the first match determines the action. If no
//! rule matches, the [`RuleSet`] default policy applies (deny-all).

use std::net::Ipv4Addr;

// Type definitions

/// Traffic direction relative to the protected system.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Direction {
    /// Traffic arriving from an external interface (e.g. the modem).
    In,
    /// Traffic leaving toward an external interface.
    Out,
}

/// Layer-4 protocol selector for a [`Rule`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Protocol {
    /// Match TCP packets only.
    Tcp,
    /// Match UDP packets only.
    Udp,
    /// Match ICMP packets only.
    Icmp,
    /// Match packets of any protocol.
    Any,
}

/// Action taken when a rule matches a packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Action {
    /// Forward the packet without logging.
    Allow,
    /// Drop the packet without logging.
    Deny,
    /// Log the packet and then forward it.
    LogAndAllow,
    /// Log the packet and then drop it.
    LogAndDeny,
}

/// An IPv4 address with a subnet mask, used to match address ranges.
///
/// A mask of `255.255.255.255` performs an exact host match. A mask of
/// `0.0.0.0` matches any address.
#[derive(Debug, Clone, Copy)]
pub struct AddressMatch {
    /// The reference address.
    pub addr: Ipv4Addr,
    /// The subnet mask (host-byte order).
    pub mask: Ipv4Addr,
}

/// Port selector for a [`Rule`].
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum PortMatch {
    /// Match any port number.
    Any,
    /// Match exactly one port.
    Single(u16),
    /// Match an inclusive port range `[start, end]`.
    Range(u16, u16),
}

/// A single firewall rule.
///
/// All fields must match for the rule to fire. Use [`AddressMatch::any`] and
/// [`PortMatch::Any`] for fields that should be unconstrained.
#[derive(Debug, Clone)]
pub struct Rule {
    /// Which direction of traffic this rule applies to.
    pub direction: Direction,
    /// Which protocol this rule applies to.
    pub protocol: Protocol,
    /// Source address constraint.
    pub src_addr: AddressMatch,
    /// Destination address constraint.
    pub dst_addr: AddressMatch,
    /// Source port constraint. Ignored for ICMP.
    pub src_port: PortMatch,
    /// Destination port constraint. Ignored for ICMP.
    pub dst_port: PortMatch,
    /// Action to take when this rule matches.
    pub action: Action,
}

/// A packet's layer-3/4 attributes, extracted for rule evaluation.
#[derive(Debug, Clone, Copy)]
pub(crate) struct PacketInfo {
    pub(crate) direction: Direction,
    pub(crate) protocol: Protocol,
    pub(crate) src_addr: Ipv4Addr,
    pub(crate) dst_addr: Ipv4Addr,
    /// `None` for protocols that have no port concept (ICMP).
    pub(crate) src_port: Option<u16>,
    /// `None` for protocols that have no port concept (ICMP).
    pub(crate) dst_port: Option<u16>,
}

/// An ordered list of [`Rule`]s with a deny-all default policy.
///
/// Rules are evaluated in insertion order. The first matching rule's
/// [`Action`] is returned. If no rule matches, [`Action::Deny`] is returned.
#[derive(Debug, Default)]
pub struct RuleSet {
    rules: Vec<Rule>,
}

// Impl blocks

impl Action {
    /// Returns `true` if this action results in the packet being forwarded.
    #[must_use]
    pub const fn is_allow(self) -> bool {
        matches!(self, Self::Allow | Self::LogAndAllow)
    }

    /// Returns `true` if this action results in the packet being dropped.
    #[must_use]
    pub const fn is_deny(self) -> bool {
        matches!(self, Self::Deny | Self::LogAndDeny)
    }

    /// Returns `true` if this action produces a log entry.
    #[must_use]
    pub const fn is_logged(self) -> bool {
        matches!(self, Self::LogAndAllow | Self::LogAndDeny)
    }
}

impl AddressMatch {
    /// Match any source or destination address (mask = `0.0.0.0`).
    #[must_use]
    pub const fn any() -> Self {
        Self {
            addr: Ipv4Addr::UNSPECIFIED,
            mask: Ipv4Addr::UNSPECIFIED,
        }
    }

    /// Match exactly one host (mask = `255.255.255.255`).
    #[must_use]
    pub const fn host(addr: Ipv4Addr) -> Self {
        Self {
            addr,
            mask: Ipv4Addr::BROADCAST,
        }
    }

    /// Match a CIDR subnet. `prefix_len` must be in `0..=32`.
    ///
    /// # Panics
    ///
    /// Panics if `prefix_len` is greater than 32.
    #[must_use]
    pub fn subnet(addr: Ipv4Addr, prefix_len: u8) -> Self {
        assert!(
            prefix_len <= 32,
            "prefix_len must be 0..=32, got {prefix_len}"
        );
        let mask_bits: u32 = if prefix_len == 0 {
            0
        } else {
            u32::MAX << (32 - prefix_len)
        };
        Self {
            addr,
            mask: Ipv4Addr::from(mask_bits),
        }
    }

    /// Returns `true` if `addr` falls within this address/mask range.
    #[must_use]
    pub fn matches(self, addr: Ipv4Addr) -> bool {
        let mask = u32::from(self.mask);
        u32::from(addr) & mask == u32::from(self.addr) & mask
    }
}

impl PortMatch {
    /// Returns `true` if `port` satisfies this selector.
    #[must_use]
    pub const fn matches(self, port: u16) -> bool {
        match self {
            Self::Any => true,
            Self::Single(p) => port == p,
            Self::Range(lo, hi) => port >= lo && port <= hi,
        }
    }
}

impl RuleSet {
    /// Create an empty rule set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a rule. Rules are evaluated in insertion order.
    pub fn add_rule(&mut self, rule: Rule) {
        self.rules.push(rule);
    }

    /// Evaluate all rules against `info`. Returns the first matching rule's
    /// action, or [`Action::Deny`] if no rule matches (default-deny policy).
    #[must_use]
    pub(crate) fn evaluate(&self, info: &PacketInfo) -> Action {
        for rule in &self.rules {
            if rule_matches(rule, info) {
                return rule.action;
            }
        }
        // Default policy: deny all.
        Action::Deny
    }
}

// Free functions

fn rule_matches(rule: &Rule, info: &PacketInfo) -> bool {
    if rule.direction != info.direction {
        return false;
    }

    if !protocol_matches(rule.protocol, info.protocol) {
        return false;
    }

    if !rule.src_addr.matches(info.src_addr) {
        return false;
    }

    if !rule.dst_addr.matches(info.dst_addr) {
        return false;
    }

    // Port constraints are only checked when the packet carries port numbers.
    let src_ok = info
        .src_port
        .map_or(matches!(rule.src_port, PortMatch::Any), |p| {
            rule.src_port.matches(p)
        });
    if !src_ok {
        return false;
    }

    info.dst_port
        .map_or(matches!(rule.dst_port, PortMatch::Any), |p| {
            rule.dst_port.matches(p)
        })
}

fn protocol_matches(rule_proto: Protocol, pkt_proto: Protocol) -> bool {
    matches!(rule_proto, Protocol::Any) || rule_proto == pkt_proto
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;

    fn allow_all_in() -> Rule {
        Rule {
            direction: Direction::In,
            protocol: Protocol::Any,
            src_addr: AddressMatch::any(),
            dst_addr: AddressMatch::any(),
            src_port: PortMatch::Any,
            dst_port: PortMatch::Any,
            action: Action::Allow,
        }
    }

    #[test]
    fn empty_ruleset_denies_all() {
        let rs = RuleSet::new();
        let info = PacketInfo {
            direction: Direction::In,
            protocol: Protocol::Tcp,
            src_addr: Ipv4Addr::new(1, 2, 3, 4),
            dst_addr: Ipv4Addr::new(10, 0, 0, 1),
            src_port: Some(54321),
            dst_port: Some(80),
        };
        assert_eq!(
            rs.evaluate(&info),
            Action::Deny,
            "empty ruleset must deny by default"
        );
    }

    #[test]
    fn first_matching_rule_wins() {
        let mut rs = RuleSet::new();
        rs.add_rule(allow_all_in());
        rs.add_rule(Rule {
            direction: Direction::In,
            protocol: Protocol::Any,
            src_addr: AddressMatch::any(),
            dst_addr: AddressMatch::any(),
            src_port: PortMatch::Any,
            dst_port: PortMatch::Any,
            action: Action::Deny,
        });

        let info = PacketInfo {
            direction: Direction::In,
            protocol: Protocol::Tcp,
            src_addr: Ipv4Addr::new(1, 2, 3, 4),
            dst_addr: Ipv4Addr::new(10, 0, 0, 1),
            src_port: Some(12345),
            dst_port: Some(443),
        };
        assert_eq!(
            rs.evaluate(&info),
            Action::Allow,
            "first rule (Allow) must win over later Deny"
        );
    }

    #[test]
    fn exact_ip_match_allows_matching_host() {
        let mut rs = RuleSet::new();
        rs.add_rule(Rule {
            direction: Direction::In,
            protocol: Protocol::Any,
            src_addr: AddressMatch::host(Ipv4Addr::new(10, 0, 0, 2)),
            dst_addr: AddressMatch::any(),
            src_port: PortMatch::Any,
            dst_port: PortMatch::Any,
            action: Action::Allow,
        });

        let matching = PacketInfo {
            direction: Direction::In,
            protocol: Protocol::Udp,
            src_addr: Ipv4Addr::new(10, 0, 0, 2),
            dst_addr: Ipv4Addr::new(10, 0, 0, 1),
            src_port: Some(1234),
            dst_port: Some(5678),
        };
        assert_eq!(
            rs.evaluate(&matching),
            Action::Allow,
            "exact host rule must match"
        );

        let non_matching = PacketInfo {
            src_addr: Ipv4Addr::new(10, 0, 0, 3),
            ..matching
        };
        assert_eq!(
            rs.evaluate(&non_matching),
            Action::Deny,
            "different source must not match exact host rule"
        );
    }

    #[test]
    fn subnet_match_covers_all_hosts_in_range() {
        let mut rs = RuleSet::new();
        rs.add_rule(Rule {
            direction: Direction::In,
            protocol: Protocol::Any,
            src_addr: AddressMatch::subnet(Ipv4Addr::new(192, 168, 0, 0), 24),
            dst_addr: AddressMatch::any(),
            src_port: PortMatch::Any,
            dst_port: PortMatch::Any,
            action: Action::Allow,
        });

        for host in [1u8, 100, 254] {
            let info = PacketInfo {
                direction: Direction::In,
                protocol: Protocol::Tcp,
                src_addr: Ipv4Addr::new(192, 168, 0, host),
                dst_addr: Ipv4Addr::new(10, 0, 0, 1),
                src_port: Some(1024),
                dst_port: Some(80),
            };
            assert_eq!(
                rs.evaluate(&info),
                Action::Allow,
                "host 192.168.0.{host} must be covered by /24 subnet rule"
            );
        }

        let outside = PacketInfo {
            direction: Direction::In,
            protocol: Protocol::Tcp,
            src_addr: Ipv4Addr::new(192, 168, 1, 1),
            dst_addr: Ipv4Addr::new(10, 0, 0, 1),
            src_port: Some(1024),
            dst_port: Some(80),
        };
        assert_eq!(
            rs.evaluate(&outside),
            Action::Deny,
            "192.168.1.1 is outside /24 and must not match"
        );
    }

    #[test]
    fn port_range_match_works_at_boundaries() {
        let mut rs = RuleSet::new();
        rs.add_rule(Rule {
            direction: Direction::In,
            protocol: Protocol::Tcp,
            src_addr: AddressMatch::any(),
            dst_addr: AddressMatch::any(),
            src_port: PortMatch::Any,
            dst_port: PortMatch::Range(8000, 8080),
            action: Action::Allow,
        });

        for port in [8000u16, 8040, 8080] {
            let info = PacketInfo {
                direction: Direction::In,
                protocol: Protocol::Tcp,
                src_addr: Ipv4Addr::new(1, 2, 3, 4),
                dst_addr: Ipv4Addr::new(10, 0, 0, 1),
                src_port: Some(50000),
                dst_port: Some(port),
            };
            assert_eq!(
                rs.evaluate(&info),
                Action::Allow,
                "port {port} must be within 8000-8080 range"
            );
        }

        for port in [7999u16, 8081] {
            let info = PacketInfo {
                direction: Direction::In,
                protocol: Protocol::Tcp,
                src_addr: Ipv4Addr::new(1, 2, 3, 4),
                dst_addr: Ipv4Addr::new(10, 0, 0, 1),
                src_port: Some(50000),
                dst_port: Some(port),
            };
            assert_eq!(
                rs.evaluate(&info),
                Action::Deny,
                "port {port} must be outside 8000-8080 range"
            );
        }
    }

    #[test]
    fn protocol_rule_does_not_match_wrong_protocol() {
        let mut rs = RuleSet::new();
        rs.add_rule(Rule {
            direction: Direction::In,
            protocol: Protocol::Tcp,
            src_addr: AddressMatch::any(),
            dst_addr: AddressMatch::any(),
            src_port: PortMatch::Any,
            dst_port: PortMatch::Any,
            action: Action::Allow,
        });

        let udp_info = PacketInfo {
            direction: Direction::In,
            protocol: Protocol::Udp,
            src_addr: Ipv4Addr::new(1, 2, 3, 4),
            dst_addr: Ipv4Addr::new(10, 0, 0, 1),
            src_port: Some(5000),
            dst_port: Some(5001),
        };
        assert_eq!(
            rs.evaluate(&udp_info),
            Action::Deny,
            "TCP-only rule must not match UDP packet"
        );
    }

    #[test]
    fn direction_rule_does_not_match_wrong_direction() {
        let mut rs = RuleSet::new();
        rs.add_rule(allow_all_in());

        let out_info = PacketInfo {
            direction: Direction::Out,
            protocol: Protocol::Tcp,
            src_addr: Ipv4Addr::new(10, 0, 0, 1),
            dst_addr: Ipv4Addr::new(1, 2, 3, 4),
            src_port: Some(80),
            dst_port: Some(54321),
        };
        assert_eq!(
            rs.evaluate(&out_info),
            Action::Deny,
            "inbound rule must not match outbound packet"
        );
    }

    #[test]
    fn action_helpers_are_consistent() {
        assert!(Action::Allow.is_allow(), "Allow must be allow");
        assert!(!Action::Allow.is_deny(), "Allow must not be deny");
        assert!(!Action::Allow.is_logged(), "Allow must not be logged");

        assert!(Action::Deny.is_deny(), "Deny must be deny");
        assert!(!Action::Deny.is_allow(), "Deny must not be allow");

        assert!(Action::LogAndAllow.is_allow(), "LogAndAllow must be allow");
        assert!(
            Action::LogAndAllow.is_logged(),
            "LogAndAllow must be logged"
        );

        assert!(Action::LogAndDeny.is_deny(), "LogAndDeny must be deny");
        assert!(Action::LogAndDeny.is_logged(), "LogAndDeny must be logged");
    }
}
