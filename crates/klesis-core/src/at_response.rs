//! AT command response parsing (3GPP TS 27.007), the byte-slice grammar
//! genuinely identical on both `klesis` and the kernel: final-result
//! exactness, `+CSQ` field extraction, the registration-status code table,
//! the `+CPIN` SIM lock-state vocabulary, and the dial-string charset.
//! Allocation-free -- text lines are pure ASCII, so a `&[u8]` view loses
//! nothing a `&str` caller needs.

/// Network registration status (3GPP TS 27.007 +CREG).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RegStatus {
    /// Not registered, not searching.
    NotRegistered,
    /// Registered on home network.
    RegisteredHome,
    /// Searching for network.
    Searching,
    /// Registration denied.
    Denied,
    /// Status unknown.
    Unknown,
    /// Registered, roaming.
    RegisteredRoaming,
}

impl From<u8> for RegStatus {
    fn from(val: u8) -> Self {
        match val {
            0 => Self::NotRegistered,
            1 => Self::RegisteredHome,
            2 => Self::Searching,
            3 => Self::Denied,
            5 => Self::RegisteredRoaming,
            _ => Self::Unknown,
        }
    }
}

impl core::fmt::Display for RegStatus {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotRegistered => write!(f, "not registered"),
            Self::RegisteredHome => write!(f, "registered (home)"),
            Self::Searching => write!(f, "searching"),
            Self::Denied => write!(f, "denied"),
            Self::Unknown => write!(f, "unknown"),
            Self::RegisteredRoaming => write!(f, "registered (roaming)"),
        }
    }
}

/// A parsed AT final result code (OK / ERROR / +CME ERROR / +CMS ERROR).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum FinalResult {
    /// Command succeeded.
    #[default]
    Ok,
    /// Generic error -- no code, or a non-numeric (verbose) CME/CMS body.
    Error,
    /// Command failed with a CME error code.
    CmeError(u32),
    /// Command failed with a CMS error code (SMS-specific, 3GPP TS 27.005).
    CmsError(u32),
}

/// Parse a final result code from an AT response line.
///
/// Handles `"OK"`, `"ERROR"`, `"+CME ERROR: <code>"`, `"+CMS ERROR:
/// <code>"`.
///
/// SECURITY: 3GPP TS 27.007 final result codes are complete lines, not
/// prefixes -- `OK` and `ERROR` terminate the response with no further
/// bytes. A byte-equality check enforces that exactly: a prefix match
/// would also accept `"OKAY"`, an unsolicited line, or trailing framing
/// debris the transport failed to strip, letting a caller record a modem
/// command as having succeeded when it did not (#685). `+CME ERROR: `/
/// `+CMS ERROR: ` remain legitimate prefixes -- they carry a numeric code
/// after the tag.
///
/// WHY the non-numeric fallback: a modem in verbose CME error mode
/// (`AT+CMEE=2`, 3GPP TS 27.007 §9.2) reports a text message here instead
/// of a numeric code (e.g. `"+CME ERROR: SIM not inserted"`), and a
/// digit-run followed by trailing garbage is symptomatically the same
/// thing -- neither is a clean code. Falling through unclassified leaves
/// a response loop treating the line as informational and eventually
/// timing out, hiding a real modem-reported error behind a misleading
/// timeout; classifying it as a generic [`FinalResult::Error`] surfaces
/// the failure immediately instead.
#[must_use]
pub fn parse_final_result(line: &[u8]) -> Option<FinalResult> {
    if line == b"OK" {
        return Some(FinalResult::Ok);
    }
    if line == b"ERROR" {
        return Some(FinalResult::Error);
    }
    if let Some(rest) = strip_prefix(line, b"+CME ERROR: ") {
        return Some(parse_decimal_u32(rest).map_or(FinalResult::Error, FinalResult::CmeError));
    }
    if let Some(rest) = strip_prefix(line, b"+CMS ERROR: ") {
        return Some(parse_decimal_u32(rest).map_or(FinalResult::Error, FinalResult::CmsError));
    }
    None
}

/// Check whether `line` is a RING URC.
///
/// SECURITY: same prefix-vs-exact hazard as [`parse_final_result`] --
/// `RING` is a bare literal with no trailing payload (3GPP TS 27.007), so
/// a plain prefix match would also accept `"RINGING"` (#685).
#[must_use]
pub fn is_ring(line: &[u8]) -> bool {
    line == b"RING"
}

/// SIM card PIN/PUK lock state, parsed from a `+CPIN?` response (3GPP TS
/// 27.007 §8.3).
///
/// The `+CPIN?` status vocabulary distinguishes many values; this enum keeps
/// the practically actionable distinction a caller needs to route to the
/// correct unlock flow -- entering a PUK as if it were a PIN (or vice versa)
/// burns limited unlock attempts and can permanently lock the SIM (#282
/// finding 17). `SIM PIN2`/`SIM PUK2` are kept distinct from the primary
/// `SIM PIN`/`SIM PUK` states: they gate the FDN/fixed-dialling secondary
/// credential, not the primary SIM lock, and conflating them routes a PIN2
/// lock through the primary unlock flow (#696).
///
/// WHY deliberately NOT `#[non_exhaustive]`: this type drives which
/// credential an unlock flow prompts for, and a PUK has a small (~10)
/// lifetime attempt limit with no carrier reset -- a caller that dispatches
/// on this must decide what every value means. A downstream `_` arm would
/// fold any future enumerated value into whatever the wildcard's neighbor
/// happens to be, silently misrouting it the same way the pre-#696 prefix
/// match misrouted `SIM PUK2`. Adding a variant here must break every
/// consumer that routes on this type (same reasoning as [`crate::MessageClass`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SimPinState {
    /// SIM ready, no PIN required.
    Ready,
    /// Primary SIM PIN required.
    PinRequired,
    /// Primary SIM PUK required (after too many wrong PIN attempts).
    PukRequired,
    /// PIN2 required -- gates the FDN/fixed-dialling secondary credential,
    /// not the primary SIM lock.
    Pin2Required,
    /// PUK2 required -- gates PIN2 unlock (too many wrong PIN2 attempts),
    /// not the primary SIM lock.
    Puk2Required,
    /// A recognized but distinct lock state (e.g. `PH-SIM PIN`, `PH-NET
    /// PUK`), or a value this parser does not recognize -- not READY, and
    /// not a primary or secondary PIN/PUK unlock flow.
    Other,
}

/// Parse a `+CPIN?` response line: `"+CPIN: <status>"`.
///
/// SECURITY (#696): matches the 3GPP TS 27.007 §8.3 enumerated values by
/// exact equality, not prefix -- the prior implementation matched `SIM
/// PIN`/`SIM PUK` by prefix, so `+CPIN: SIM PUK2` (a PIN2/FDN lock, a
/// distinct enumerated value) took the `SIM PUK` arm and reported the
/// primary-SIM PUK state. A SIM PUK has a small lifetime attempt limit and
/// no carrier reset; an unlock flow built on that misclassification prompts
/// for the SIM PUK and validates every entry against the wrong credential,
/// burning attempts toward the permanent-block limit. Exact equality has no
/// shadowing order to get wrong: `SIM PUK2` cannot be mistaken for `SIM
/// PUK` because the two byte strings are never equal.
///
/// A value outside this vocabulary -- including a truncated or malformed
/// one -- classifies as [`SimPinState::Other`] rather than `None`, so a
/// caller that dispatches on the lock state never mistakes "this parser
/// doesn't recognize the value" for "the query itself failed", and never
/// drives a credential prompt from a guess.
#[must_use]
pub fn parse_cpin(line: &[u8]) -> Option<SimPinState> {
    let rest = strip_prefix(line, b"+CPIN: ")?;
    Some(if rest == b"READY" {
        SimPinState::Ready
    } else if rest == b"SIM PIN2" {
        SimPinState::Pin2Required
    } else if rest == b"SIM PUK2" {
        SimPinState::Puk2Required
    } else if rest == b"SIM PIN" {
        SimPinState::PinRequired
    } else if rest == b"SIM PUK" {
        SimPinState::PukRequired
    } else {
        SimPinState::Other
    })
}

/// Parse a +CSQ response line: `"+CSQ: <rssi>,<ber>"`.
///
/// Returns `(rssi_raw, ber)` where `rssi_raw` is 0-31 or 99 (unknown).
///
/// Time: O(n) where n is `line.len()` -- one linear scan FOR the comma
/// separator, then two [`parse_decimal_u8`] passes over the two fields;
/// together these touch each byte of `line` a constant number of times.
/// Space: O(1) -- no allocation; returns a fixed-size tuple.
#[must_use]
pub fn parse_csq(line: &[u8]) -> Option<(u8, u8)> {
    let rest = strip_prefix(line, b"+CSQ: ")?;
    let comma = rest.iter().position(|&b| b == b',')?;
    let rssi = parse_decimal_u8(&rest[..comma])?;
    let ber = parse_decimal_u8(&rest[comma + 1..])?;
    Some((rssi, ber))
}

/// Return whether `b` is a legal byte in a GSM AT dial-string.
///
/// SECURITY: gates every byte that reaches an `ATD<number>;` command --
/// the modem and cellular network are untrusted, and an unfiltered byte
/// could carry CR/LF (splits the string into multiple AT command lines),
/// `"` (closes a quoted field early in `AT+CMGS="..."`), or `;` (ends a
/// dial command early and starts a second one), letting an
/// attacker-influenced number smuggle a command past the modem. Allowed
/// set: ASCII digits `0`-`9`, `+`, `*`, `#`, and `A`-`D` (3GPP TS 27.007
/// dial-string charset).
#[must_use]
pub const fn is_valid_dial_byte(b: u8) -> bool {
    matches!(b, b'0'..=b'9' | b'+' | b'*' | b'#' | b'A'..=b'D')
}

/// Largest RSSI index 3GPP TS 27.007 defines for `+CSQ`. 31 maps to -51 dBm;
/// 99 is the separate "not known or not detectable" value.
const CSQ_RSSI_MAX: u8 = 31;

/// dBm value reported when the RSSI is unknown or outside its defined domain.
pub const RSSI_DBM_UNKNOWN: i16 = -999;

/// Convert a raw AT+CSQ RSSI value (0-31, 99=unknown) to dBm.
///
/// Formula: dBm = -113 + (rssi * 2), per 3GPP TS 27.007.
///
/// WHY anything outside 0-31 returns the unknown sentinel rather than the
/// formula's output: the formula is only defined on that domain, and applying
/// it to, say, 200 yields +287 dBm -- which [`dbm_to_bars`] then classifies as
/// four bars. A malformed or hostile modem line would report *excellent*
/// signal, and a wrong answer delivered confidently is worse than the absence
/// this sentinel already exists to express.
#[must_use]
pub fn rssi_to_dbm(rssi: u8) -> i16 {
    if rssi > CSQ_RSSI_MAX {
        return RSSI_DBM_UNKNOWN;
    }
    -113 + (i16::from(rssi) * 2)
}

/// Map signal strength in dBm to bars (0-4).
///
/// Thresholds:
/// - `>= -70` dBm -> 4 bars (excellent)
/// - `>= -85` dBm -> 3 bars (good)
/// - `>= -100` dBm -> 2 bars (fair)
/// - `>= -110` dBm -> 1 bar (poor)
/// - `< -110` dBm -> 0 bars (no signal)
#[must_use]
pub fn dbm_to_bars(dbm: i16) -> u8 {
    if dbm >= -70 {
        4
    } else if dbm >= -85 {
        3
    } else if dbm >= -100 {
        2
    } else {
        u8::from(dbm >= -110)
    }
}

/// Strip `prefix` from `input`. Returns `None` if `input` does not start
/// with `prefix`.
fn strip_prefix<'a>(input: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    if input.len() >= prefix.len() && &input[..prefix.len()] == prefix {
        Some(&input[prefix.len()..])
    } else {
        None
    }
}

/// Parse a byte slice as a decimal `u8`. Every byte must be an ASCII digit.
fn parse_decimal_u8(input: &[u8]) -> Option<u8> {
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

/// Parse a byte slice as a decimal `u32`. Every byte must be an ASCII digit.
fn parse_decimal_u32(input: &[u8]) -> Option<u32> {
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

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::*;

    #[test]
    fn reg_status_maps_known_codes() {
        assert_eq!(RegStatus::from(0), RegStatus::NotRegistered);
        assert_eq!(RegStatus::from(1), RegStatus::RegisteredHome);
        assert_eq!(RegStatus::from(2), RegStatus::Searching);
        assert_eq!(RegStatus::from(3), RegStatus::Denied);
        assert_eq!(
            RegStatus::from(4),
            RegStatus::Unknown,
            "code 4 has no defined meaning and must map to Unknown, not a neighboring code"
        );
        assert_eq!(RegStatus::from(5), RegStatus::RegisteredRoaming);
        assert_eq!(
            RegStatus::from(99),
            RegStatus::Unknown,
            "an out-of-range code must map to Unknown rather than panic or wrap"
        );
    }

    #[test]
    fn reg_status_display_is_human_readable() {
        assert_eq!(RegStatus::RegisteredHome.to_string(), "registered (home)");
    }

    #[test]
    fn parse_final_result_ok() {
        assert_eq!(
            parse_final_result(b"OK"),
            Some(FinalResult::Ok),
            "a bare OK line must classify as FinalResult::Ok"
        );
    }

    #[test]
    fn parse_final_result_rejects_okay_as_success() {
        // SECURITY (#685): a modem line beginning "OK" but carrying more
        // bytes must not be accepted as command success. A plain prefix
        // match would accept "OKAY" as OK with "AY" silently discarded.
        assert_eq!(
            parse_final_result(b"OKAY"),
            None,
            "'OKAY' must not parse as a successful final result"
        );
    }

    #[test]
    fn parse_final_result_rejects_okk_prefix_collision() {
        // SECURITY (#685): the issue's exact near-miss case.
        assert_eq!(
            parse_final_result(b"OKK"),
            None,
            "'OKK' must not be classified as FinalResult::Ok by prefix match"
        );
    }

    #[test]
    fn parse_final_result_rejects_ok_embedded_mid_string() {
        // SECURITY (#685): a final result code is the whole line; "OK"
        // occurring anywhere other than as the complete line must not
        // classify as success.
        assert_eq!(parse_final_result(b"PREFIX OK"), None);
        assert_eq!(parse_final_result(b"NOKIA"), None);
    }

    #[test]
    fn parse_final_result_bare_error() {
        assert_eq!(
            parse_final_result(b"ERROR"),
            Some(FinalResult::Error),
            "bare 'ERROR' must parse to FinalResult::Error"
        );
    }

    #[test]
    fn parse_final_result_rejects_error_prefix_collision() {
        // SECURITY (#685): same exactness requirement as OK -- ERROR is
        // also a bare, no-payload final result code.
        assert_eq!(
            parse_final_result(b"ERRORX"),
            None,
            "'ERRORX' must not be classified as FinalResult::Error by prefix match"
        );
    }

    #[test]
    fn parse_final_result_recognizes_cme_error() {
        assert_eq!(
            parse_final_result(b"+CME ERROR: 10"),
            Some(FinalResult::CmeError(10)),
            "CME error code 10 must be extracted"
        );
    }

    #[test]
    fn parse_final_result_recognizes_cms_error() {
        assert_eq!(
            parse_final_result(b"+CMS ERROR: 321"),
            Some(FinalResult::CmsError(321)),
            "+CMS ERROR must be recognized as a final result, not fall through as informational"
        );
    }

    #[test]
    fn parse_final_result_verbose_or_malformed_cme_error_classifies_as_generic_error() {
        // WHY: a modem in verbose CME error mode (AT+CMEE=2, 3GPP TS
        // 27.007 section 9.2) reports a text message here instead of a
        // numeric code. Falling through unclassified leaves a response
        // loop treating the line as informational and eventually timing
        // out, hiding a real modem-reported error behind a misleading
        // Timeout -- classifying as a generic error surfaces the failure
        // immediately. Digits-then-garbage ("10x") is symptomatically the
        // same case: it is not a clean numeric code, so it takes the same
        // fallback rather than truncating to CmeError(10) with the "x"
        // silently dropped.
        assert_eq!(
            parse_final_result(b"+CME ERROR: x"),
            Some(FinalResult::Error),
            "a non-numeric CME error code must classify as a generic Error, not fall through to None"
        );
        assert_eq!(
            parse_final_result(b"+CME ERROR: SIM not inserted"),
            Some(FinalResult::Error),
            "a verbose CME ERROR message must classify as a generic Error, not time out unclassified"
        );
        assert_eq!(
            parse_final_result(b"+CME ERROR: 10x"),
            Some(FinalResult::Error),
            "trailing bytes after a CME error code must classify as a generic error, not truncate to CmeError(10)"
        );
        assert_eq!(
            parse_final_result(b"+CMS ERROR: SMS storage full"),
            Some(FinalResult::Error),
            "a verbose CMS ERROR message must classify as a generic Error, not time out unclassified"
        );
    }

    #[test]
    fn parse_final_result_unrecognized_line_returns_none() {
        assert_eq!(
            parse_final_result(b"garbage"),
            None,
            "a line matching no known final-result grammar must classify as None"
        );
    }

    #[test]
    fn parse_final_result_cme_error_code_rejects_u32_overflow() {
        // WHY: the CME/CMS error code is decimal-parsed with a
        // checked_mul/checked_add guard, not a wrapping accumulator -- a
        // code exceeding u32::MAX must fall back to a generic Error
        // (the same fallback a verbose/malformed body takes) rather than
        // silently wrap to a smaller, wrong code.
        assert_eq!(
            parse_final_result(b"+CME ERROR: 4294967296"),
            Some(FinalResult::Error),
            "a CME error code exceeding u32::MAX must classify as a generic error, not wrap"
        );
        assert_eq!(
            parse_final_result(b"+CME ERROR: 99999999999999999999"),
            Some(FinalResult::Error),
            "a value far exceeding u32::MAX must classify as a generic error, not wrap"
        );
    }

    #[test]
    fn is_ring_requires_exact_match() {
        assert!(is_ring(b"RING"), "RING must be recognized");
        // SECURITY (#685, same class): RING is a bare no-payload URC
        // token, just like OK/ERROR. A prefix match would also accept
        // "RINGING".
        assert!(
            !is_ring(b"RINGING"),
            "'RINGING' must not be classified as RING by prefix match"
        );
    }

    #[test]
    fn parse_cpin_recognizes_ready() {
        assert_eq!(parse_cpin(b"+CPIN: READY"), Some(SimPinState::Ready));
    }

    #[test]
    fn parse_cpin_recognizes_primary_pin() {
        assert_eq!(
            parse_cpin(b"+CPIN: SIM PIN"),
            Some(SimPinState::PinRequired)
        );
    }

    #[test]
    fn parse_cpin_recognizes_primary_puk() {
        assert_eq!(
            parse_cpin(b"+CPIN: SIM PUK"),
            Some(SimPinState::PukRequired),
            "SIM PUK must not collapse to the same state as SIM PIN"
        );
    }

    #[test]
    fn parse_cpin_recognizes_pin2_distinct_from_pin() {
        // SECURITY (#696): the exact case the prior prefix matcher got
        // wrong for the milder half of the pair -- SIM PIN2 gates the
        // FDN/PIN2 secondary credential, not the primary SIM lock.
        assert_eq!(
            parse_cpin(b"+CPIN: SIM PIN2"),
            Some(SimPinState::Pin2Required),
            "SIM PIN2 must not classify as the primary SimPinState::PinRequired"
        );
    }

    #[test]
    fn parse_cpin_recognizes_puk2_distinct_from_puk() {
        // SECURITY (#696): the damaging case -- a prefix matcher testing
        // "SIM PUK" before "SIM PIN" takes SIM PUK2 into the PUK arm and
        // reports the primary-SIM PUK state. A PUK has a small lifetime
        // attempt limit with no carrier reset; an unlock flow driven by
        // this misclassification prompts for the SIM PUK and burns
        // attempts against the wrong credential.
        assert_eq!(
            parse_cpin(b"+CPIN: SIM PUK2"),
            Some(SimPinState::Puk2Required),
            "SIM PUK2 must not classify as the primary SimPinState::PukRequired"
        );
    }

    #[test]
    fn parse_cpin_recognizes_ph_lock_as_other() {
        assert_eq!(
            parse_cpin(b"+CPIN: PH-NET PIN"),
            Some(SimPinState::Other),
            "a recognized-but-distinct lock state must classify as Other, not a guess"
        );
    }

    #[test]
    fn parse_cpin_unrecognized_value_is_other_not_none() {
        // WHY Other rather than None: a caller that dispatches on the lock
        // state must never conflate "this parser doesn't recognize the
        // value" (Other) with "the query itself failed to parse" (None) --
        // conflating the two risks a fallback path guessing a lock state
        // for a value nobody has classified.
        assert_eq!(
            parse_cpin(b"+CPIN: SOMETHING UNKNOWN"),
            Some(SimPinState::Other)
        );
        assert_eq!(
            parse_cpin(b"garbage"),
            None,
            "a line without the +CPIN: prefix must not parse at all"
        );
    }

    #[test]
    fn parse_csq_extracts_rssi_and_ber() {
        assert_eq!(
            parse_csq(b"+CSQ: 18,99"),
            Some((18, 99)),
            "CSQ response must extract rssi=18 and ber=99"
        );
        assert_eq!(
            parse_csq(b"+CREG: 1"),
            None,
            "a line without the +CSQ prefix must not parse"
        );
    }

    #[test]
    fn parse_csq_rejects_overflowing_rssi_field() {
        assert_eq!(
            parse_csq(b"+CSQ: 999,0"),
            None,
            "an out-of-range rssi field must reject the whole +CSQ line rather than wrap"
        );
    }

    #[test]
    fn is_valid_dial_byte_allows_only_the_dial_string_charset() {
        for b in b'0'..=b'9' {
            assert!(is_valid_dial_byte(b));
        }
        for b in [b'+', b'*', b'#', b'A', b'B', b'C', b'D'] {
            assert!(is_valid_dial_byte(b));
        }
        for b in [b'\r', b'\n', b'"', b';', b' ', b'E'] {
            assert!(
                !is_valid_dial_byte(b),
                "byte {b:?} must be rejected -- CR/LF/quote/semicolon can smuggle a second AT command"
            );
        }
    }

    #[test]
    fn signal_strength_conversion_matches_3gpp_formula() {
        assert_eq!(rssi_to_dbm(18), -77, "RSSI 18 must convert to -77 dBm");
        assert_eq!(rssi_to_dbm(0), -113, "RSSI 0 must be -113 dBm");
        assert_eq!(rssi_to_dbm(31), -51, "RSSI 31 must be -51 dBm");
        assert_eq!(
            rssi_to_dbm(99),
            -999,
            "RSSI 99 (unknown sentinel) must convert to -999 dBm"
        );
    }

    #[test]
    fn dbm_to_bars_maps_boundary_values() {
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
    fn rssi_outside_its_defined_domain_is_unknown_not_a_strong_signal() {
        // #833: the TS 27.007 formula is defined on 0-31. Applied to a value
        // above that it produces a POSITIVE dBm, which `dbm_to_bars` then
        // classifies as four bars -- so a malformed or hostile modem line
        // reported excellent signal.
        for rssi in [32u8, 98, 100, 200, 255] {
            assert_eq!(
                rssi_to_dbm(rssi),
                RSSI_DBM_UNKNOWN,
                "RSSI {rssi} is outside 0-31 and must read as unknown"
            );
            assert_eq!(
                dbm_to_bars(rssi_to_dbm(rssi)),
                0,
                "an unknown RSSI must render as no signal, not full bars"
            );
        }
    }

    #[test]
    fn rssi_domain_boundaries_still_convert() {
        // The bound is inclusive at both ends, and 99 keeps its own meaning.
        assert_eq!(rssi_to_dbm(0), -113, "0 is the weakest defined reading");
        assert_eq!(rssi_to_dbm(31), -51, "31 is the strongest defined reading");
        assert_eq!(
            rssi_to_dbm(99),
            RSSI_DBM_UNKNOWN,
            "99 is the standard's own unknown value"
        );
    }
}
