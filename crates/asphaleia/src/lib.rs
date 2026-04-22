#![deny(missing_docs)]
#![expect(dead_code, reason = "public API surface for future kernel binary integration (#126)")]
#![allow(unfulfilled_lint_expectations)]
//! Security policy enforcement. Packet filtering, DNS-over-TLS, telemetry domain blocking, capability-based access control.

pub mod dns;
pub mod filter;
pub mod rules;

pub(crate) mod packet;

pub use dns::DnsBlocklist;
pub use filter::Filter;
pub use rules::{Action, AddressMatch, Direction, PortMatch, Protocol, Rule, RuleSet};
