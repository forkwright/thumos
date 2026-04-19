//! AT response parsing for the telephony subsystem.
//!
//! Pure functions for parsing modem AT responses: final result codes,
//! +CSQ signal quality, +CREG registration status, +COPS operator name,
//! +CLIP caller ID, +CPIN SIM status, and unsolicited result codes (URCs).
//!
//! These parsers operate on raw byte slices (`&[u8]`) with zero allocation,
//! suitable for `#![no_std]` kernel use.

// Items in this module are re-exported from telephony.rs.

use crate::telephony::{AtResponse, RegStatus, Urc, MAX_NUMBER_LEN};

// ---------------------------------------------------------------------------
// AT response parsing (no_std, no nom)
// ---------------------------------------------------------------------------

/// Parse a final result code from an AT response line.
///
/// Handles: "OK", "ERROR", "+CME ERROR: <code>"
pub(crate) fn parse_final_result(line: &[u8]) -> Option<AtResponse> {
    if line == b"OK" {
        return Some(AtResponse::Ok);
    }
    if line == b"ERROR" {
        return Some(AtResponse::Error);
    }
    if let Some(rest) = strip_prefix(line, b"+CME ERROR: ") {
        if let Some(code) = parse_u32(rest) {
            return Some(AtResponse::CmeError(code));
        }
    }
    None
}

/// Parse a +CSQ response line: "+CSQ: <rssi>,<ber>"
///
/// Returns (rssi_raw, ber) where rssi_raw is 0-31 or 99 (unknown).
pub(crate) fn parse_csq_response(line: &[u8]) -> Option<(u8, u8)> {
    let rest = strip_prefix(line, b"+CSQ: ")?;
    let comma = memchr(b',', rest)?;
    let rssi = parse_u8(&rest[..comma])?;
    let ber = parse_u8(&rest[comma + 1..])?;
    Some((rssi, ber))
}

/// Parse a +CREG response/URC line: "+CREG: <stat>[,<lac>,<ci>]"
///
/// We only extract the stat field for telephony purposes.
pub(crate) fn parse_creg_response(line: &[u8]) -> Option<RegStatus> {
    let rest = strip_prefix(line, b"+CREG: ")?;
    // stat is the first field, possibly followed by comma and more fields.
    let end = memchr(b',', rest).unwrap_or(rest.len());
    let stat = parse_u8(&rest[..end])?;
    Some(RegStatus::from(stat))
}

/// Parse a +COPS? response line: "+COPS: <mode>,<format>,\"<operator>\""
///
/// Extracts the operator name string.
pub(crate) fn parse_cops_response(line: &[u8], name_buf: &mut [u8; MAX_OPERATOR_LEN]) -> Option<u8> {
    let rest = strip_prefix(line, b"+COPS: ")?;
    // Find the quoted operator name.
    let quote_start = memchr(b'"', rest)?;
    let after_quote = &rest[quote_start + 1..];
    let quote_end = memchr(b'"', after_quote)?;
    let name = &after_quote[..quote_end];
    let len = name.len().min(MAX_OPERATOR_LEN);
    name_buf[..len].copy_from_slice(&name[..len]);
    Some(len as u8)
}

/// Parse a +CLIP URC line: "+CLIP: \"<number>\",<type>..."
///
/// Extracts the caller phone number.
pub(crate) fn parse_clip_response(line: &[u8], number_buf: &mut [u8; MAX_NUMBER_LEN]) -> Option<u8> {
    let rest = strip_prefix(line, b"+CLIP: ")?;
    // Number is in quotes.
    let quote_start = memchr(b'"', rest)?;
    let after_quote = &rest[quote_start + 1..];
    let quote_end = memchr(b'"', after_quote)?;
    let number = &after_quote[..quote_end];
    let len = number.len().min(MAX_NUMBER_LEN);
    number_buf[..len].copy_from_slice(&number[..len]);
    Some(len as u8)
}

/// Parse a +CPIN? response line: "+CPIN: <status>"
///
/// Returns true if the SIM is ready (no PIN required).
pub(crate) fn parse_cpin_response(line: &[u8]) -> Option<bool> {
    let rest = strip_prefix(line, b"+CPIN: ")?;
    if rest == b"READY" {
        Some(true)
    } else if starts_with(rest, b"SIM PIN") {
        Some(false)
    } else {
        // Other states (SIM PUK, etc.) — treat as not ready.
        Some(false)
    }
}

/// Check if a line is a RING URC.
pub(crate) fn is_ring(line: &[u8]) -> bool {
    line == b"RING"
}

/// Check if a line is a NO CARRIER URC.
pub(crate) fn is_no_carrier(line: &[u8]) -> bool {
    line == b"NO CARRIER"
}

/// Check if a line is a BUSY URC.
pub(crate) fn is_busy(line: &[u8]) -> bool {
    line == b"BUSY"
}

/// Try to parse a line as any known URC.
pub(crate) fn parse_urc(line: &[u8]) -> Option<Urc> {
    if is_ring(line) {
        return Some(Urc::Ring);
    }
    if is_no_carrier(line) {
        return Some(Urc::NoCarrier);
    }
    if is_busy(line) {
        return Some(Urc::Busy);
    }
    if let Some((rssi, ber)) = parse_csq_response(line) {
        return Some(Urc::Csq { rssi, ber });
    }
    if let Some(stat) = parse_creg_response(line) {
        return Some(Urc::Creg { stat });
    }
    if starts_with(line, b"+CLIP: ") {
        let mut number = [0u8; MAX_NUMBER_LEN];
        if let Some(len) = parse_clip_response(line, &mut number) {
            return Some(Urc::Clip {
                number,
                number_len: len,
            });
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Byte-level parsing helpers (no_std, no alloc)
// ---------------------------------------------------------------------------

/// Strip a prefix from a byte slice. Returns `None` if the prefix doesn't match.
pub(crate) fn strip_prefix<'a>(input: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    if input.len() >= prefix.len() && &input[..prefix.len()] == prefix {
        Some(&input[prefix.len()..])
    } else {
        None
    }
}

/// Check if `input` starts with `prefix`.
fn starts_with(input: &[u8], prefix: &[u8]) -> bool {
    input.len() >= prefix.len() && &input[..prefix.len()] == prefix
}

/// Find the position of a byte in a slice.
fn memchr(needle: u8, haystack: &[u8]) -> Option<usize> {
    haystack.iter().position(|&b| b == needle)
}

/// Parse a byte slice as a decimal u8.
fn parse_u8(input: &[u8]) -> Option<u8> {
    if input.is_empty() {
        return None;
    }
    let mut result: u8 = 0;
    for &b in input {
        if !b.is_ascii_digit() {
            return None;
        }
        result = result.checked_mul(10)?.checked_add(b - b'0')?;
    }
    Some(result)
}

/// Parse a byte slice as a decimal u32.
fn parse_u32(input: &[u8]) -> Option<u32> {
    if input.is_empty() {
        return None;
    }
    let mut result: u32 = 0;
    for &b in input {
        if !b.is_ascii_digit() {
            return None;
        }
        result = result.checked_mul(10)?.checked_add(u32::from(b - b'0'))?;
    }
    Some(result)
}

/// Convert raw AT+CSQ RSSI value (0-31, 99=unknown) to dBm.
///
/// Formula: dBm = -113 + (rssi * 2), per 3GPP TS 27.007.
pub(crate) fn rssi_to_dbm(rssi: u8) -> i16 {
    if rssi == 99 {
        return -999; // unknown sentinel
    }
    -113 + (i16::from(rssi) * 2)
}

/// Map signal strength in dBm to bars (0-4).
///
/// Thresholds based on the spec's dBm mapping:
/// - >= -70 dBm -> 4 bars (excellent)
/// - >= -85 dBm -> 3 bars (good)
/// - >= -100 dBm -> 2 bars (fair)
/// - >= -110 dBm -> 1 bar  (poor)
/// - <  -110 dBm -> 0 bars (no signal)
pub(crate) fn dbm_to_bars(dbm: i16) -> u8 {
    if dbm >= -70 {
        4
    } else if dbm >= -85 {
        3
    } else if dbm >= -100 {
        2
    } else if dbm >= -110 {
        1
    } else {
        0
    }
}

/// Maximum operator name length in bytes.
pub(crate) const MAX_OPERATOR_LEN: usize = 32;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signal_strength_maps_to_correct_bars() {
        // Test the dBm-to-bars mapping at boundary values.
        assert_eq!(dbm_to_bars(-70), 4, "-70 dBm must be 4 bars");
        assert_eq!(dbm_to_bars(-69), 4, "-69 dBm must be 4 bars");
        assert_eq!(dbm_to_bars(-71), 3, "-71 dBm must be 3 bars");
        assert_eq!(dbm_to_bars(-85), 3, "-85 dBm must be 3 bars");
        assert_eq!(dbm_to_bars(-86), 2, "-86 dBm must be 2 bars");
        assert_eq!(dbm_to_bars(-100), 2, "-100 dBm must be 2 bars");
        assert_eq!(dbm_to_bars(-101), 1, "-101 dBm must be 1 bar");
        assert_eq!(dbm_to_bars(-110), 1, "-110 dBm must be 1 bar");
        assert_eq!(dbm_to_bars(-111), 0, "-111 dBm must be 0 bars");
        assert_eq!(dbm_to_bars(-999), 0, "unknown signal must be 0 bars");
    }

    #[test]
    fn parse_csq_response_extracts_rssi() {
        let line = b"+CSQ: 18,99";
        let result = parse_csq_response(line);
        assert_eq!(
            result,
            Some((18, 99)),
            "CSQ response must extract rssi=18 and ber=99"
        );

        // Verify dBm conversion: RSSI 18 => -113 + (18*2) = -77 dBm.
        let dbm = rssi_to_dbm(18);
        assert_eq!(dbm, -77, "RSSI 18 must convert to -77 dBm");
    }

    #[test]
    fn parse_cops_response_extracts_operator() {
        let line = b"+COPS: 0,0,\"T-Mobile\"";
        let mut name = [0u8; MAX_OPERATOR_LEN];
        let len = parse_cops_response(line, &mut name);
        assert_eq!(len, Some(8), "operator name length must be 8");
        assert_eq!(
            &name[..8],
            b"T-Mobile",
            "operator name must be T-Mobile"
        );
    }

    #[test]
    fn parse_clip_response_extracts_number() {
        let line = b"+CLIP: \"+15551234567\",145";
        let mut number = [0u8; MAX_NUMBER_LEN];
        let len = parse_clip_response(line, &mut number);
        assert_eq!(len, Some(12), "number length must be 12");
        assert_eq!(
            &number[..12],
            b"+15551234567",
            "caller ID number must be +15551234567"
        );
    }
}
