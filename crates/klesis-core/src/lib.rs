#![no_std]
#![deny(missing_docs)]
//! klesis-core: the canonical GSM-7, SMS-PDU, and AT-response semantics
//! (#545, #662, #685).
//!
//! This crate is the single home of the GSM 7-bit alphabet codec, the PDU
//! byte primitives (hex, BCD address, cursor), the surveillance
//! classification of an incoming message — silent SMS by PID, and WAP
//! Push by UDH application port — and the AT command final-result/URC
//! token classification shared by both sides' modem response parsers. It
//! is shared by the `klesis` workspace crate (telephony daemon) and the
//! thumos kernel (`sms.rs` and `telephony_parser.rs`, the paths actually
//! reached on the device).
//!
//! It exists because the two sides were independent hand-ports and had
//! already diverged (#662, #685):
//!
//! - the kernel read the PID and discarded it (`// PID (ignored).`), so a
//!   silent SMS — the standard covert location-ping, specified as neither
//!   displayed nor stored — was filed to the inbox as an ordinary message,
//!   while `klesis` rejected it. The detection existed only in the layer
//!   that never runs on the phone.
//! - the kernel accepted GSM-7 data ending in a dangling ESC septet and
//!   returned the truncated text; `klesis` rejected it. The same modem
//!   bytes produced a message on one side and an error on the other.
//! - the workspace AT parser matched a final result code (`OK`, `ERROR`,
//!   `RING`) by prefix; the kernel compared whole lines. A modem line
//!   merely beginning with a matched token (`"OKAY"`, `"RINGING"`) would
//!   have parsed as success on one side and been correctly rejected on
//!   the other.
//!
//! Neither drift could be caught, because nothing tested the two against
//! each other. One codec, one classification, one token grammar.
//!
//! `no_std` + alloc so the bare-metal kernel can link it via a path
//! dependency; nothing here performs I/O, and nothing here decides policy
//! — a caller is told *what a message is* and chooses what to do about it.
//! That split is deliberate: `klesis` drops a silent SMS, while the kernel
//! must keep and surface it, because an alert the user never sees is
//! indistinguishable from no detection at all. The AT-response section
//! (below) is entirely allocation-free byte-slice parsing -- text lines
//! are pure ASCII, so a `&[u8]` view loses nothing a `&str` caller needs.
//!
//! # Module map
//!
//! The domains below were previously one undifferentiated file; each is
//! now a module owning one seam, re-exported here so every
//! `klesis_core::Thing` path a caller already uses keeps resolving
//! unchanged:
//!
//! - [`gsm7`] -- the GSM 7-bit alphabet codec.
//! - [`hex`] -- ASCII hex encode/decode.
//! - [`bcd_address`] -- BCD-packed SMS address encode/decode.
//! - [`cursor`] -- the bounds-checked PDU byte reader.
//! - [`udh`] -- UDH parsing and silent-SMS/WAP-Push classification.
//! - [`at_response`] -- AT command response parsing.

extern crate alloc;

mod at_response;
mod bcd_address;
mod cursor;
mod gsm7;
mod hex;
mod udh;

pub use at_response::{
    FinalResult, RegStatus, SimPinState, dbm_to_bars, is_ring, is_valid_dial_byte, parse_cpin,
    parse_csq, parse_final_result, rssi_to_dbm,
};
pub use bcd_address::{
    MAX_ADDRESS_DIGITS, TOA_INTERNATIONAL, decode_bcd_address, encode_bcd_address, pack_bcd_digits,
};
pub use cursor::Cursor;
pub use gsm7::{
    ESC_SEPTET, EXT_TABLE, GSM_TO_UNICODE, char_to_septet, count_septets, decode, decode_from,
    encode,
};
pub use hex::{hex_decode, hex_encode, hex_nibble};
pub use udh::{
    MAX_PDU_HEX_LEN, MessageClass, PID_SIM_TOOLKIT_UPPER, PID_TYPE_0_SMS, UDH_IEI_APP_PORT_16BIT,
    UDHI_BIT, UdhPorts, WAP_PUSH_PORT_ALT, WAP_PUSH_PORT_OMA_CP, classify, gsm7_udh_septets,
    has_udh, is_silent_sms_pid, is_wap_push_port, parse_udh_ports, udh_octet_len,
};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// A failure decoding or encoding SMS wire data.
///
/// Deliberately `Copy` and allocation-free: every variant carries only the
/// position or value needed to locate the fault, so the kernel can surface
/// one without a heap allocation on an error path fed by a hostile modem.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CoreError {
    /// A character has no GSM-7 representation.
    Gsm7Encode {
        /// Unicode scalar value that could not be encoded.
        codepoint: u32,
    },
    /// Packed GSM-7 data ran out before the declared septet count.
    Gsm7Truncated {
        /// Septet index at which the data ended.
        septet: usize,
    },
    /// GSM-7 data ends with an ESC that has no following extension code.
    Gsm7DanglingEscape,
    /// A BCD nibble was not a decimal digit (and not the 0xF filler).
    BcdInvalidDigit {
        /// The offending nibble.
        nibble: u8,
    },
    /// An address exceeded the maximum digit count.
    AddressTooLong {
        /// Digit count supplied.
        digits: usize,
    },
    /// A hex string had odd length or a non-hex character.
    HexInvalid {
        /// Byte offset of the fault.
        offset: usize,
    },
    /// A read ran past the end of the buffer.
    Truncated {
        /// Byte offset at which the read was attempted.
        offset: usize,
    },
}

/// Result alias for this crate.
pub type Result<T> = core::result::Result<T, CoreError>;

/// Unwrap a [`Result`] in a test, panicking with the error's `Debug` output.
///
/// WHY crate-visible rather than duplicated per module: several of the
/// split-out test modules (gsm7, hex, bcd_address, cursor) need this exact
/// helper; defining it once here keeps every module's tests identical in
/// failure-message shape rather than drifting copy to copy.
#[cfg(test)]
pub(crate) fn ok<T>(r: Result<T>) -> T {
    match r {
        Ok(v) => v,
        Err(e) => unreachable!("expected Ok, got {e:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // WHY this test stays here rather than moving into `gsm7` or `udh`:
    // it exercises the seam BETWEEN them -- `decode_from` (gsm7) reading
    // from a septet offset that `gsm7_udh_septets`/`udh_octet_len` (udh)
    // computed -- so it belongs to neither module alone.
    #[test]
    fn decode_from_reads_text_at_a_septet_offset_not_an_octet_one() {
        // A real UDH-bearing user-data field: 6 header octets, then "Hello".
        // 6 octets = 48 bits; ceil(48/7) = 7 septets = 49 bits, so one fill
        // bit separates them and the text starts at BIT 49.
        let ud = [
            0x05, 0x00, 0x03, 0xAB, 0x02, 0x01, // UDH
            0x90, 0x65, 0x36, 0xFB, 0x0D, // "Hello" from bit 49
        ];
        let udh_septets = gsm7_udh_septets(udh_octet_len(&ud));
        assert_eq!(udh_septets, 7, "6 header octets fold into 7 septets");

        assert_eq!(
            ok(decode_from(&ud, udh_septets, 5)),
            "Hello",
            "text must be read from the septet boundary after the header"
        );

        // The bug this replaced: skipping the header by OCTET and decoding
        // from bit 0 of the remainder. It is off by the single fill bit and
        // produces confident garbage rather than an error, which is why it
        // survived in both the kernel and klesis.
        assert_eq!(
            ok(decode(&ud[6..], 5)),
            "\u{394}KYY\u{a7}",
            "slicing at the octet boundary must be demonstrably wrong -- if \
             this ever equals \"Hello\", the fixture stopped exercising the \
             misalignment and the test above proves nothing"
        );
    }
}
