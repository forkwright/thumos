//! AT response parsing for the telephony subsystem.
//!
//! Pure functions for parsing modem AT responses: final result codes,
//! +CSQ signal quality, +CREG registration status, +COPS operator name,
//! +CLIP caller ID, +CPIN SIM status, and unsolicited result codes (URCs).
//!
//! These parsers operate on raw byte slices (`&[u8]`) with zero allocation,
//! suitable for `#![no_std]` kernel use.

// Items in this module are re-exported from telephony.rs.

use crate::telephony::{AtResponse, MAX_NUMBER_LEN, RegStatus, Urc};

// ---------------------------------------------------------------------------
// AT response parsing (no_std, no nom)
// ---------------------------------------------------------------------------

/// Parse a final result code from an AT response line.
///
/// Handles: "OK", "ERROR", "+CME ERROR: <code>", "+CMS ERROR: <code>"
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
    if let Some(rest) = strip_prefix(line, b"+CMS ERROR: ") {
        if let Some(code) = parse_u32(rest) {
            return Some(AtResponse::CmsError(code));
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
pub(crate) fn parse_cops_response(
    line: &[u8],
    name_buf: &mut [u8; MAX_OPERATOR_LEN],
) -> Option<u8> {
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

/// Return whether `b` is a legal byte in a GSM AT dial-string.
///
/// SECURITY: gates every byte that reaches an `ATD<number>;` command
/// buffer -- directly in [`crate::telephony::Telephony::dial`], and here
/// so a forged `+CLIP` caller-ID number can never be stored in the first
/// place. Allowed set: ASCII digits `0`-`9`, `+`, `*`, `#`, and `A`-`D`
/// (3GPP TS 27.007 dial-string charset). CR/LF and `;` are deliberately
/// excluded: either would let attacker-controlled bytes terminate an ATD
/// command early and inject a follow-on AT command once relayed into
/// `dial`.
pub(crate) const fn is_valid_dial_byte(b: u8) -> bool {
    matches!(b, b'0'..=b'9' | b'+' | b'*' | b'#' | b'A'..=b'D')
}

/// Parse a +CLIP URC line: "+CLIP: \"<number>\",<type>..."
///
/// Extracts the caller phone number.
///
/// SECURITY: rejects (returns `None` for) a caller ID containing any byte
/// outside [`is_valid_dial_byte`]. The modem/network is untrusted; without
/// this check a forged `+CLIP` URC could carry AT-injection bytes into
/// `number_buf`, which a UI callback re-dialing this caller would then
/// pass straight to `Telephony::dial`.
pub(crate) fn parse_clip_response(
    line: &[u8],
    number_buf: &mut [u8; MAX_NUMBER_LEN],
) -> Option<u8> {
    let rest = strip_prefix(line, b"+CLIP: ")?;
    // Number is in quotes.
    let quote_start = memchr(b'"', rest)?;
    let after_quote = &rest[quote_start + 1..];
    let quote_end = memchr(b'"', after_quote)?;
    let number = &after_quote[..quote_end];
    if !number.iter().all(|&b| is_valid_dial_byte(b)) {
        return None;
    }
    let len = number.len().min(MAX_NUMBER_LEN);
    number_buf[..len].copy_from_slice(&number[..len]);
    Some(len as u8)
}

/// SIM card PIN/PUK lock state, parsed from a `+CPIN?` response.
///
/// The +CPIN status vocabulary distinguishes many states (3GPP TS 27.007
/// §8.3); this enum keeps the practically actionable distinction a caller
/// needs to route to the correct unlock flow -- entering a PUK as if it
/// were a PIN (or vice versa) burns limited unlock attempts and can
/// permanently lock the SIM (issue #282 finding 17).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub(crate) enum SimPinState {
    /// SIM ready, no PIN required.
    Ready,
    /// SIM PIN required.
    PinRequired,
    /// SIM PUK required (after too many wrong PIN attempts).
    PukRequired,
    /// A recognized but distinct lock state (e.g. PH-SIM PIN, PH-NET PUK) --
    /// not READY, and not a plain SIM PIN/PUK unlock flow.
    Other,
}

/// Parse a +CPIN? response line: "+CPIN: <status>"
///
/// Distinguishes SIM PIN vs SIM PUK vs other lock states (issue #282
/// finding 17) -- the old boolean collapsed every non-READY state to a
/// single "not ready" flag, which cannot tell a caller whether to prompt
/// for a 4-digit PIN or an 8-digit PUK.
pub(crate) fn parse_cpin_response(line: &[u8]) -> Option<SimPinState> {
    let rest = strip_prefix(line, b"+CPIN: ")?;
    if rest == b"READY" {
        Some(SimPinState::Ready)
    } else if starts_with(rest, b"SIM PUK") {
        Some(SimPinState::PukRequired)
    } else if starts_with(rest, b"SIM PIN") {
        Some(SimPinState::PinRequired)
    } else {
        Some(SimPinState::Other)
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
    fn parse_cpin_response_distinguishes_pin_from_puk() {
        // Distinguishes SIM PIN vs SIM PUK vs READY (issue #282 finding 17)
        // -- routing a PUK-locked SIM through a PIN-entry UI flow burns
        // limited PUK attempts and can permanently lock the SIM.
        assert_eq!(
            parse_cpin_response(b"+CPIN: READY"),
            Some(SimPinState::Ready)
        );
        assert_eq!(
            parse_cpin_response(b"+CPIN: SIM PIN"),
            Some(SimPinState::PinRequired)
        );
        assert_eq!(
            parse_cpin_response(b"+CPIN: SIM PUK"),
            Some(SimPinState::PukRequired),
            "SIM PUK must not collapse to the same state as SIM PIN"
        );
        assert_eq!(
            parse_cpin_response(b"+CPIN: PH-NET PIN"),
            Some(SimPinState::Other)
        );
        assert_eq!(parse_cpin_response(b"garbage"), None);
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
    fn parse_creg_response_extracts_stat_ignoring_trailing_fields() {
        assert_eq!(
            parse_creg_response(b"+CREG: 5"),
            Some(RegStatus::RegisteredRoaming),
            "stat=5 must parse as RegisteredRoaming"
        );
        assert_eq!(
            parse_creg_response(b"+CREG: 2,\"1FFE\",\"CE12\""),
            Some(RegStatus::Searching),
            "stat must be extracted from the leading field even with trailing lac/ci fields present"
        );
        assert_eq!(
            parse_creg_response(b"+CREG: 9"),
            Some(RegStatus::Unknown),
            "an unrecognized stat code must map to RegStatus::Unknown rather than None"
        );
        assert_eq!(
            parse_creg_response(b"+CSQ: 1"),
            None,
            "a line without the +CREG prefix must not parse"
        );
    }

    #[test]
    fn parse_cops_response_extracts_operator() {
        let line = b"+COPS: 0,0,\"T-Mobile\"";
        let mut name = [0u8; MAX_OPERATOR_LEN];
        let len = parse_cops_response(line, &mut name);
        assert_eq!(len, Some(8), "operator name length must be 8");
        assert_eq!(&name[..8], b"T-Mobile", "operator name must be T-Mobile");
    }

    #[test]
    fn parse_final_result_recognizes_cms_error() {
        assert_eq!(
            parse_final_result(b"+CMS ERROR: 302"),
            Some(AtResponse::CmsError(302)),
            "+CMS ERROR must be recognized as a final result, not fall through as informational"
        );
    }

    #[test]
    fn parse_final_result_ok() {
        assert_eq!(
            parse_final_result(b"OK"),
            Some(AtResponse::Ok),
            "a bare OK line must classify as AtResponse::Ok"
        );
    }

    #[test]
    fn parse_final_result_error() {
        assert_eq!(
            parse_final_result(b"ERROR"),
            Some(AtResponse::Error),
            "a bare ERROR line must classify as AtResponse::Error"
        );
    }

    #[test]
    fn parse_final_result_recognizes_cme_error() {
        assert_eq!(
            parse_final_result(b"+CME ERROR: 10"),
            Some(AtResponse::CmeError(10)),
            "+CME ERROR must extract its numeric code into AtResponse::CmeError"
        );
    }

    #[test]
    fn parse_final_result_malformed_cme_code_returns_none() {
        assert_eq!(
            parse_final_result(b"+CME ERROR: x"),
            None,
            "a non-numeric CME error code must not classify as any final result"
        );
    }

    #[test]
    fn parse_final_result_unrecognized_line_returns_none() {
        assert_eq!(
            parse_final_result(b"OKK"),
            None,
            "a near-miss line must not be classified as OK by prefix/substring confusion"
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

    #[test]
    fn parse_clip_response_rejects_invalid_charset() {
        let line = b"+CLIP: \"AT+CFUN=0\",145";
        let mut number = [0u8; MAX_NUMBER_LEN];
        let len = parse_clip_response(line, &mut number);
        assert_eq!(
            len, None,
            "a caller ID containing AT-command bytes outside the dial charset must be rejected, not stored"
        );
    }

    #[test]
    fn parse_urc_dispatches_line_to_matching_urc_variant() {
        assert_eq!(
            parse_urc(b"RING"),
            Some(Urc::Ring),
            "RING must dispatch to Urc::Ring"
        );
        assert_eq!(
            parse_urc(b"NO CARRIER"),
            Some(Urc::NoCarrier),
            "NO CARRIER must dispatch to Urc::NoCarrier"
        );
        assert_eq!(
            parse_urc(b"BUSY"),
            Some(Urc::Busy),
            "BUSY must dispatch to Urc::Busy"
        );
        assert_eq!(
            parse_urc(b"+CSQ: 18,99"),
            Some(Urc::Csq { rssi: 18, ber: 99 }),
            "+CSQ line must dispatch to Urc::Csq carrying the parsed rssi/ber"
        );
        assert_eq!(
            parse_urc(b"+CREG: 1"),
            Some(Urc::Creg {
                stat: RegStatus::RegisteredHome
            }),
            "+CREG line must dispatch to Urc::Creg carrying the parsed stat"
        );
        let mut number = [0u8; MAX_NUMBER_LEN];
        number[..12].copy_from_slice(b"+15551234567");
        assert_eq!(
            parse_urc(b"+CLIP: \"+15551234567\",145"),
            Some(Urc::Clip {
                number,
                number_len: 12
            }),
            "+CLIP line must dispatch to Urc::Clip carrying the parsed number"
        );
        assert_eq!(
            parse_urc(b"+CLIP: \"AT+CFUN=0\",145"),
            None,
            "a +CLIP line whose number fails charset validation must dispatch to None, not a partial Urc::Clip"
        );
        assert_eq!(
            parse_urc(b"+CGATT: 1"),
            None,
            "a line matching no known URC prefix must dispatch to None"
        );
    }
}
