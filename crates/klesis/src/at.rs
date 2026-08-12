//! AT command parser and builder for the MT6739 modem.
//!
//! Handles standard 3GPP TS 27.007 AT commands used for voice calls,
//! SMS, network registration, and signal monitoring.

use nom::IResult;
use nom::Parser;
use nom::bytes::complete::{tag, take_until, take_while1};
use nom::character::complete::{char, digit1};
use nom::combinator::{map, map_res, opt, verify};
use nom::sequence::{delimited, preceded};

use crate::error::{Error, Result};

/// Network registration status (3GPP TS 27.007 +CREG).
///
/// Canonical definition: [`klesis_core::RegStatus`] (#545) -- re-exported
/// here so existing `at::RegStatus` call sites are unaffected.
pub use klesis_core::RegStatus;

/// Raw AT response FROM the modem.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum Response {
    /// Command succeeded.
    #[default]
    Ok,
    /// Command failed with CME error code.
    CmeError(u32),
    /// Command failed with CMS error code (SMS-specific).
    CmsError(u32),
    /// Generic error (no code).
    Error,
    /// Informational text line.
    Info(String),
    /// Unsolicited result code (URC).
    Urc(Urc),
}

/// Unsolicited result codes FROM the modem.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum Urc {
    /// Incoming call.
    #[default]
    Ring,
    /// Caller ID: number and type.
    Clip {
        /// Caller phone number.
        number: String,
        /// Numbering plan type.
        num_type: u8,
    },
    /// Network registration status changed.
    Creg {
        /// Registration status code.
        stat: RegStatus,
        /// Location area code.
        lac: Option<u16>,
        /// Cell ID.
        ci: Option<u32>,
    },
    /// Signal quality report.
    Csq {
        /// Raw RSSI value (0-31, 99=unknown).
        rssi: u8,
        /// Bit error rate.
        ber: u8,
    },
    /// Incoming SMS notification.
    Cmti {
        /// Storage location name.
        storage: String,
        /// Message index.
        index: u16,
    },
    /// SMS delivery report.
    Cds(String),
    /// Call ended.
    NoCarrier,
    /// Line busy.
    Busy,
    /// No answer.
    NoAnswer,
}

/// Signal strength in dBm, converted FROM AT+CSQ RSSI value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignalStrength {
    /// Raw AT+CSQ RSSI value (0-31, 99=unknown).
    pub(crate) rssi_raw: u8,
    /// Signal strength in dBm.
    pub(crate) dbm: i16,
    /// Signal bar count (0-5).
    pub(crate) bars: u8,
}

impl From<u8> for SignalStrength {
    fn from(rssi: u8) -> Self {
        // WHY: dBm conversion and bar thresholds are
        // [`klesis_core::rssi_to_dbm`]/[`klesis_core::dbm_to_bars`] (#545)
        // -- the canonical 3GPP-derived mapping shared with the kernel, so
        // klesis and the kernel cannot silently disagree on how many bars
        // a given dBm value reports.
        let dbm = klesis_core::rssi_to_dbm(rssi);
        let bars = klesis_core::dbm_to_bars(dbm);
        Self {
            rssi_raw: rssi,
            dbm,
            bars,
        }
    }
}

// WHY: AT commands are line-oriented text protocol. nom gives us composable,
// zero-copy parsing that handles the messy reality of modem responses
// (variable whitespace, optional fields, interleaved URCs) for the URCs
// that still differ between klesis and the kernel (+CREG's `<lac>`/`<ci>`,
// +CMTI). The token-exactness parsers below have no such variability left
// to parse -- they delegate entirely to [`klesis_core`] (#545).

/// Parse a final result code (OK, ERROR, +CME ERROR, +CMS ERROR).
///
/// SECURITY: 3GPP TS 27.007 final result codes are complete lines, not
/// prefixes -- delegates to [`klesis_core::parse_final_result`], the
/// byte-slice classifier shared with the kernel, which enforces that
/// exactly (#685). AT response text is pure ASCII, so the `&str` -> `&[u8]`
/// view loses nothing.
///
/// Time: O(n) where n is `input.len()` -- the `"OK"`/`"ERROR"` and
/// `"+CME ERROR: "`/`"+CMS ERROR: "` prefix checks are O(1) fixed-length
/// comparisons, but a matched CME/CMS prefix scans the remaining digit run
/// once via `parse_decimal_u32`.
/// Space: O(1) -- no allocation; returns an enum by value.
#[must_use]
pub fn parse_final_result(input: &str) -> Option<Response> {
    match klesis_core::parse_final_result(input.as_bytes())? {
        klesis_core::FinalResult::Ok => Some(Response::Ok),
        klesis_core::FinalResult::Error => Some(Response::Error),
        klesis_core::FinalResult::CmeError(code) => Some(Response::CmeError(code)),
        klesis_core::FinalResult::CmsError(code) => Some(Response::CmsError(code)),
        // WHY: klesis_core::FinalResult is #[non_exhaustive] -- a future
        // variant added there without a matching Response counterpart
        // must not be misclassified as one of the above.
        _ => None,
    }
}

/// Parse a +CSQ response: +CSQ: <rssi>,<ber>
///
/// Time: O(n) where n is `input.len()` -- `klesis_core::parse_csq` scans FOR
/// the comma separator and then parses each of the two decimal fields,
/// together touching each byte of `input` a constant number of times.
/// Space: O(1) -- no allocation; returns a fixed-size tuple.
#[must_use]
pub fn parse_csq(input: &str) -> Option<(u8, u8)> {
    klesis_core::parse_csq(input.as_bytes())
}

/// Parse a +CREG URC: +CREG: <stat>[,<lac>,<ci>]
pub fn parse_creg(input: &str) -> IResult<&str, Urc> {
    let (input, _) = tag("+CREG: ").parse(input)?;
    let (input, stat) = map_res(digit1, str::parse::<u8>).parse(input)?;
    let (input, lac_ci) = opt((
        preceded(
            char(','),
            map_res(take_while1(|c: char| c.is_ascii_hexdigit()), |s: &str| {
                u16::from_str_radix(s, 16)
            }),
        ),
        preceded(
            char(','),
            map_res(take_while1(|c: char| c.is_ascii_hexdigit()), |s: &str| {
                u32::from_str_radix(s, 16)
            }),
        ),
    ))
    .parse(input)?;

    let (lac, ci) = match lac_ci {
        Some((l, c)) => (Some(l), Some(c)),
        None => (None, None),
    };

    Ok((
        input,
        Urc::Creg {
            stat: RegStatus::from(stat),
            lac,
            ci,
        },
    ))
}

/// Parse a RING URC.
///
/// SECURITY: same prefix-vs-exact hazard as [`parse_final_result`] -- `RING`
/// is a bare literal with no trailing payload (3GPP TS 27.007), so a plain
/// prefix match would also accept `"RINGING"` or any other line merely
/// beginning with it. Delegates to [`klesis_core::is_ring`], the exact-match
/// check shared with the kernel's `is_ring`.
#[must_use]
pub fn parse_ring(input: &str) -> Option<Urc> {
    klesis_core::is_ring(input.as_bytes()).then_some(Urc::Ring)
}

/// Maximum length accepted for a `+CMTI` storage-location name.
///
/// SECURITY: `storage` is a modem-controlled field; without a bound,
/// `take_until` allocates a `String` proportional to whatever a
/// malicious/malfunctioning modem sends before the next `"`. Real storage
/// identifiers (`"SM"`, `"ME"`, `"MT"`, `"SR"`) are 2-3 chars; this stays
/// generous while removing the unbounded allocation.
const MAX_CMTI_STORAGE_LEN: usize = 16;

/// Parse a +CMTI URC: +CMTI: "<storage>",<index>
pub fn parse_cmti(input: &str) -> IResult<&str, Urc> {
    let (input, _) = tag("+CMTI: ").parse(input)?;
    let (input, storage) = delimited(
        char('"'),
        verify(map(take_until("\""), String::from), |s: &String| {
            s.len() <= MAX_CMTI_STORAGE_LEN
        }),
        char('"'),
    )
    .parse(input)?;
    let (input, _) = char(',').parse(input)?;
    let (input, index) = map_res(digit1, str::parse::<u16>).parse(input)?;
    Ok((input, Urc::Cmti { storage, index }))
}

/// Build an AT command string with proper CR/LF termination.
pub(crate) fn build_cmd(cmd: &str) -> String {
    format!("{cmd}\r\n")
}

/// Validate that `s` contains only characters legal in a GSM AT dial-string.
///
/// SECURITY: gates every phone number before it is interpolated into an AT
/// command string. The modem and cellular network are untrusted; an
/// unfiltered number could carry CR/LF (splits the string into multiple AT
/// command lines) or `"` (closes a quoted field early in
/// `AT+CMGS="..."`), letting an attacker-influenced number smuggle a
/// second AT command past the modem.
///
/// Allowed set: ASCII digits `0`-`9`, `+`, `*`, `#`, and `A`-`D`
/// (3GPP TS 27.007 dial-string charset) -- the charset itself is
/// [`klesis_core::is_valid_dial_byte`] (#545), shared with the kernel's
/// `+CLIP` caller-ID validation.
///
/// Time: O(n) where n is `s.len()` -- `.all()` scans until the first
/// invalid byte or the end of the string.
/// Space: O(1) on the accepted path (returns a borrowed `&str`); the
/// rejection path allocates an O(n) `String` echoing the invalid number
/// into the error message.
pub(crate) fn validate_phone_number(s: &str) -> Result<&str> {
    if !s.bytes().all(klesis_core::is_valid_dial_byte) {
        return Err(Error::Parse {
            message: format!("invalid phone number: {s:?}"),
        });
    }
    Ok(s)
}

/// Common AT commands.
pub(crate) mod cmd {
    use super::{Result, validate_phone_number};

    /// Check modem is alive.
    pub(crate) const AT: &str = "AT";
    /// Request manufacturer identification.
    pub(crate) const CGMI: &str = "AT+CGMI";
    /// Request model identification.
    pub(crate) const CGMM: &str = "AT+CGMM";
    /// Request IMEI.
    pub(crate) const CGSN: &str = "AT+CGSN";
    /// Request signal quality.
    pub(crate) const CSQ: &str = "AT+CSQ";
    /// Enable network registration URCs.
    pub(crate) const CREG_ENABLE: &str = "AT+CREG=2";
    /// Query network registration.
    pub(crate) const CREG_QUERY: &str = "AT+CREG?";
    /// Enable caller ID.
    pub(crate) const CLIP_ENABLE: &str = "AT+CLIP=1";
    /// Dial a number.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::Error::Parse`] if `number` contains any byte
    /// outside the GSM dial-string charset (see
    /// [`super::validate_phone_number`]).
    pub(crate) fn dial(number: &str) -> Result<String> {
        let number = validate_phone_number(number)?;
        Ok(format!("ATD{number};"))
    }
    /// Answer incoming call.
    pub(crate) const ATA: &str = "ATA";
    /// Hang up.
    pub(crate) const ATH: &str = "ATH";
    /// Set SMS text mode.
    pub(crate) const CMGF_TEXT: &str = "AT+CMGF=1";
    /// Set SMS PDU mode.
    pub(crate) const CMGF_PDU: &str = "AT+CMGF=0";
    /// Send SMS (text mode). Returns prompt ">" for message body.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::Error::Parse`] if `number` contains any byte
    /// outside the GSM dial-string charset (see
    /// [`super::validate_phone_number`]), including `"` (would close the
    /// quoted destination field early).
    pub(crate) fn cmgs(number: &str) -> Result<String> {
        let number = validate_phone_number(number)?;
        Ok(format!("AT+CMGS=\"{number}\""))
    }
    /// Read SMS at index.
    pub(crate) fn cmgr(index: u16) -> String {
        format!("AT+CMGR={index}")
    }
    /// Delete SMS at index.
    pub(crate) fn cmgd(index: u16) -> String {
        format!("AT+CMGD={index}")
    }
    /// Query operator name.
    pub(crate) const COPS_QUERY: &str = "AT+COPS?";
    /// Enable extended error reporting.
    pub(crate) const CMEE_ENABLE: &str = "AT+CMEE=1";
    /// Query SIM status.
    pub(crate) const CPIN_QUERY: &str = "AT+CPIN?";
    /// Power off radio (airplane mode).
    pub(crate) const CFUN_OFF: &str = "AT+CFUN=0";
    /// Power on radio (full functionality).
    pub(crate) const CFUN_ON: &str = "AT+CFUN=1";
    /// Restrict network selection to LTE only (refuse 2G/3G).
    ///
    /// `AT+COPS=0,,,7` sets automatic operator selection with access technology
    /// restricted to E-UTRAN (LTE). This prevents the modem from registering on
    /// GSM or UMTS networks, blocking downgrade attacks used by IMSI catchers.
    ///
    /// 3GPP TS 27.007 § 7.3: the fourth parameter is the access technology:
    /// 0=GSM, 2=UTRAN, 7=E-UTRAN (LTE).
    pub(crate) const COPS_LTE_ONLY: &str = "AT+COPS=0,,,7";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ok() {
        let resp = parse_final_result("OK").unwrap_or_default();
        assert_eq!(resp, Response::Ok, "parsing 'OK' must produce Response::Ok");
    }

    #[test]
    fn parse_final_result_rejects_okay_as_success() {
        // SECURITY (#685): a modem line beginning "OK" but carrying more
        // bytes must not be accepted as command success -- a prefix match
        // would accept "OKAY" as OK with "AY" silently discarded.
        assert_eq!(
            parse_final_result("OKAY"),
            None,
            "'OKAY' must not parse as a successful final result"
        );
    }

    #[test]
    fn parse_final_result_rejects_okk_prefix_collision() {
        // SECURITY (#685): issue's exact near-miss case.
        assert_eq!(
            parse_final_result("OKK"),
            None,
            "'OKK' must not be classified as Response::Ok by prefix match"
        );
    }

    #[test]
    fn parse_final_result_rejects_ok_embedded_mid_string() {
        // SECURITY (#685): a final result code is the whole line; "OK"
        // occurring anywhere other than as the complete line must not
        // classify as success.
        assert_eq!(
            parse_final_result("PREFIX OK"),
            None,
            "a line with OK embedded mid-string must not parse as a final result"
        );
        assert_eq!(
            parse_final_result("NOKIA"),
            None,
            "a line merely containing the substring OK must not parse as a final result"
        );
    }

    #[test]
    fn parse_final_result_bare_error() {
        let resp = parse_final_result("ERROR").unwrap_or_default();
        assert_eq!(
            resp,
            Response::Error,
            "bare 'ERROR' must parse to Response::Error"
        );
    }

    #[test]
    fn parse_final_result_rejects_error_prefix_collision() {
        // SECURITY (#685): same exactness requirement as OK -- ERROR is
        // also a bare, no-payload final result code.
        assert_eq!(
            parse_final_result("ERRORX"),
            None,
            "'ERRORX' must not be classified as Response::Error by prefix match"
        );
    }

    #[test]
    fn parse_cme_error() {
        let resp = parse_final_result("+CME ERROR: 10").unwrap_or_default();
        assert_eq!(
            resp,
            Response::CmeError(10),
            "CME error code 10 must be extracted"
        );
    }

    #[test]
    fn parse_cme_error_verbose_or_trailing_garbage_classifies_as_generic_error() {
        // WHY (#545 convergence): converged onto the kernel's finding-13
        // behavior -- a CME/CMS error body that is not cleanly numeric (a
        // verbose AT+CMEE=2 message, or trailing bytes after a digit run)
        // classifies as a generic Response::Error rather than falling
        // through unparsed. The prior klesis-only behavior rejected
        // "+CME ERROR: 10x" outright; that left a caller's response loop
        // treating the line as informational and looping for a final
        // result that would never arrive -- the same silent-timeout
        // hazard finding 13 fixed on the kernel side. It never risks
        // truncating to CmeError(10) with the "x" silently dropped: the
        // whole remainder must be digits, or the fallback applies.
        assert_eq!(
            parse_final_result("+CME ERROR: 10x"),
            Some(Response::Error),
            "trailing bytes after a CME error code must classify as a generic error, not be silently dropped or left unparsed"
        );
        assert_eq!(
            parse_final_result("+CME ERROR: SIM not inserted"),
            Some(Response::Error),
            "a verbose CME ERROR message must classify as a generic Error, not time out unclassified"
        );
    }

    #[test]
    fn parse_cms_error() {
        let resp = parse_final_result("+CMS ERROR: 321").unwrap_or_default();
        assert_eq!(
            resp,
            Response::CmsError(321),
            "CMS error code 321 must be extracted"
        );
    }

    #[test]
    fn parse_csq_response() {
        let (rssi, ber) = parse_csq("+CSQ: 18,99").unwrap_or_default();
        assert_eq!(rssi, 18, "RSSI must be 18");
        assert_eq!(ber, 99, "BER must be 99");
    }

    #[test]
    fn signal_strength_conversion() {
        let sig = SignalStrength::from(18u8);
        assert_eq!(
            sig.dbm, -77,
            "RSSI 18 must convert to -77 dBm per AT+CSQ formula"
        );
        assert_eq!(sig.bars, 3, "RSSI 18 (-77 dBm) must be 3 bars");
    }

    #[test]
    fn signal_strength_bars_match_telephony_parser_thresholds() {
        // WHY: locks bar thresholds to klesis_core::dbm_to_bars's boundary
        // values -- the single implementation the kernel's
        // telephony_parser also links (#545) -- so a future edit cannot
        // silently diverge the two again.
        // rssi=21 -> dbm = -113 + 21*2 = -71 dBm (just below -70)
        assert_eq!(SignalStrength::from(21u8).bars, 3, "-71 dBm must be 3 bars");
        // rssi=22 -> dbm = -113 + 22*2 = -69 dBm (at/above -70)
        assert_eq!(SignalStrength::from(22u8).bars, 4, "-69 dBm must be 4 bars");
    }

    #[test]
    fn signal_strength_unknown() {
        let sig = SignalStrength::from(99u8);
        assert_eq!(
            sig.dbm, -999,
            "RSSI 99 must map to -999 dBm (unknown sentinel)"
        );
        assert_eq!(sig.bars, 0, "unknown signal strength must report 0 bars");
    }

    #[test]
    fn parse_creg_registered_home() {
        let (_, urc) = parse_creg("+CREG: 1").unwrap_or_default();
        assert_eq!(
            urc,
            Urc::Creg {
                stat: RegStatus::RegisteredHome,
                lac: None,
                ci: None,
            },
            "CREG stat=1 without LAC/CI must parse as RegisteredHome with no location"
        );
    }

    #[test]
    fn parse_creg_with_location() {
        let (_, urc) = parse_creg("+CREG: 1,1A2B,0000FFEE").unwrap_or_default();
        assert_eq!(
            urc,
            Urc::Creg {
                stat: RegStatus::RegisteredHome,
                lac: Some(0x1A2B),
                ci: Some(0x0000_FFEE),
            },
            "CREG with LAC/CI must parse all three fields correctly"
        );
    }

    #[test]
    fn parse_ring_urc() {
        let urc = parse_ring("RING").unwrap_or_default();
        assert_eq!(urc, Urc::Ring, "RING must parse to Urc::Ring");
    }

    #[test]
    fn parse_ring_rejects_prefix_collision() {
        // SECURITY (#685, same class): RING is a bare no-payload URC token,
        // just like OK/ERROR. The kernel's `is_ring` already compares the
        // whole line; klesis must not diverge by accepting a mere prefix.
        assert_eq!(
            parse_ring("RINGING"),
            None,
            "'RINGING' must not be classified as Urc::Ring by prefix match"
        );
    }

    #[test]
    fn parse_cmti_urc() {
        let (_, urc) = parse_cmti("+CMTI: \"SM\",3").unwrap_or_default();
        assert_eq!(
            urc,
            Urc::Cmti {
                storage: "SM".to_owned(),
                index: 3,
            },
            "CMTI URC must parse storage and index correctly"
        );
    }

    #[test]
    fn parse_cmti_rejects_oversized_storage() {
        let long_storage = "X".repeat(MAX_CMTI_STORAGE_LEN + 1);
        let input = format!("+CMTI: \"{long_storage}\",3");
        let result = parse_cmti(&input);
        assert!(
            result.is_err(),
            "storage field longer than MAX_CMTI_STORAGE_LEN must be rejected"
        );
    }

    #[test]
    fn build_dial_command() {
        assert_eq!(
            cmd::dial("+15551234567").unwrap_or_default(),
            "ATD+15551234567;",
            "dial command must be formatted as ATD<number>;"
        );
    }

    #[test]
    fn build_dial_command_rejects_crlf_injection() {
        let result = cmd::dial("+1\r\nAT+CFUN=0");
        assert!(
            result.is_err(),
            "CR/LF in dial number must be rejected, not formatted"
        );
    }

    #[test]
    fn build_sms_command() {
        assert_eq!(
            cmd::cmgs("+15551234567").unwrap_or_default(),
            "AT+CMGS=\"+15551234567\"",
            "CMGS command must wrap number in quotes"
        );
    }

    #[test]
    fn build_sms_command_rejects_quote_injection() {
        let result = cmd::cmgs("+1\"\r\nATH");
        assert!(
            result.is_err(),
            "quote/CR/LF in CMGS destination must be rejected, not formatted"
        );
    }
}
