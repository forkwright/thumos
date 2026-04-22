#![deny(missing_docs)]
#![expect(dead_code, reason = "public API surface for future kernel binary integration (#126)")]
#![allow(unfulfilled_lint_expectations)]
//! Telephony daemon for the MT6739 modem.
//!
//! Direct `CCCI` channel access, AT command parser, call state machine,
//! SMS PDU encoding/decoding. No Android RIL dependency.

pub mod at;
pub mod ccci;
pub mod cldma;
pub mod error;
pub mod gsm7;
pub mod pdu;
pub mod transport;
