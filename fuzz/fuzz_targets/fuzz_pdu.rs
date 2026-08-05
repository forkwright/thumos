//! Fuzz target: SMS PDU full surface (DELIVER decode + SUBMIT encode, UCS-2
//! and GSM-7, validity-period and WAP-Push rejection paths).
//!
//! Broader sibling of fuzz_gsm7: drives `klesis::pdu` with hex-framed
//! arbitrary bytes on the decode path and with structured message variants on
//! the encode path. The decoder must never panic or allocate beyond its
//! declared maximum; the encoder must produce structurally valid hex.
//!
//! # Running
//!
//! ```text
//! cargo fuzz run fuzz_pdu -- -max_total_time=60
//! cargo fuzz run fuzz_pdu corpus/fuzz_pdu -- -max_total_time=60
//! ```
#![no_main]
use libfuzzer_sys::fuzz_target;

use klesis::pdu::{Address, AddressType, DataEncoding, SmsSubmit, UserData, decode_deliver, encode_submit};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // ── Phase 1: DELIVER decode on hexified input ───────────────────────────
    // As with fuzz_gsm7, hexify the raw bytes to reach the byte-level PDU
    // parser (type bytes, address BCD, DCS, UDH, OMA-CP/WAP-Push rejection).
    let hex_pdu: String = data.iter().map(|b| format!("{b:02X}")).collect();
    // Errors are expected and fine; the contract is no panic.
    let _ = decode_deliver(&hex_pdu); // WHY: fuzz target — only contract is no panic; Ok/Err are both valid outcomes

    // ── Phase 2: SUBMIT encode with fuzz-driven variants ────────────────────
    // Bytes 0/1 pick encoding + address type; a later byte drives the optional
    // validity period; the remainder is the text payload as lossy UTF-8.
    if data.len() < 4 {
        return;
    }
    let encoding = if data[0] & 1 == 0 { DataEncoding::Gsm7Bit } else { DataEncoding::Ucs2 };
    let addr_type = if data[1] & 1 == 0 { AddressType::International } else { AddressType::National };
    let validity_period = if data[2] & 1 == 0 { None } else { Some(data[3]) };
    let text = String::from_utf8_lossy(&data[4..]);
    let msg = SmsSubmit {
        destination: Address {
            number: "+1234567890".to_owned(),
            type_of_address: addr_type,
        },
        user_data: UserData {
            encoding,
            text: text.into_owned(),
        },
        validity_period,
    };
    if let Ok(hex) = encode_submit(&msg) {
        assert!(!hex.is_empty(), "encoded SUBMIT PDU must be non-empty");
        assert!(
            hex.chars().all(|c| c.is_ascii_hexdigit()),
            "encoded SUBMIT PDU must be valid hex",
        );
    }
});
