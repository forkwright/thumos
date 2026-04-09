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
