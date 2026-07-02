//! AT command parser and builder for the MT6739 modem.
//!
//! Handles standard 3GPP TS 27.007 AT commands used for voice calls,
//! SMS, network registration, and signal monitoring.

use nom::IResult;
use nom::Parser;
use nom::branch::alt;
use nom::bytes::complete::{tag, take_until, take_while1};
use nom::character::complete::{char, digit1};
use nom::combinator::{map, map_res, opt, value};
use nom::sequence::{delimited, preceded};

use crate::error::{Error, Result};

/// Raw AT response FROM the modem.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub(crate) enum Response {
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
pub(crate) enum Urc {
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

/// Network registration status (3GPP TS 27.007 +CREG).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub(crate) enum RegStatus {
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

/// Signal strength in dBm, converted FROM AT+CSQ RSSI value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SignalStrength {
    /// Raw AT+CSQ RSSI value (0-31, 99=unknown).
    pub(crate) rssi_raw: u8,
    /// Signal strength in dBm.
    pub(crate) dbm: i16,
    /// Signal bar count (0-5).
    pub(crate) bars: u8,
}

impl From<u8> for SignalStrength {
    fn from(rssi: u8) -> Self {
        let dbm = if rssi == 99 {
            -999 // NOTE: unknown
        } else {
            -113 + (i16::from(rssi) * 2)
        };
        let bars = match dbm {
            ..=-100 => 0,
            -99..=-85 => 1,
            -84..=-70 => 2,
            -69..=-55 => 3,
            _ => 4,
        };
        Self {
            rssi_raw: rssi,
            dbm,
            bars,
        }
    }
}

// WHY: AT commands are line-oriented text protocol. nom gives us composable,
// zero-copy parsing that handles the messy reality of modem responses
// (variable whitespace, optional fields, interleaved URCs).

/// Parse a final result code (OK, ERROR, +CME ERROR, +CMS ERROR).
pub(crate) fn parse_final_result(input: &str) -> IResult<&str, Response> {
    alt((
        value(Response::Ok, tag("OK")),
        value(Response::Error, tag("ERROR")),
        map(
            preceded(tag("+CME ERROR: "), map_res(digit1, str::parse::<u32>)),
            Response::CmeError,
        ),
        map(
            preceded(tag("+CMS ERROR: "), map_res(digit1, str::parse::<u32>)),
            Response::CmsError,
        ),
    ))
    .parse(input)
}

/// Parse a +CSQ response: +CSQ: <rssi>,<ber>
pub(crate) fn parse_csq(input: &str) -> IResult<&str, (u8, u8)> {
    preceded(
        tag("+CSQ: "),
        (
            map_res(digit1, str::parse::<u8>),
            preceded(char(','), map_res(digit1, str::parse::<u8>)),
        ),
    )
    .parse(input)
}

/// Parse a +CREG URC: +CREG: <stat>[,<lac>,<ci>]
pub(crate) fn parse_creg(input: &str) -> IResult<&str, Urc> {
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
pub(crate) fn parse_ring(input: &str) -> IResult<&str, Urc> {
    value(Urc::Ring, tag("RING")).parse(input)
}

/// Parse a +CMTI URC: +CMTI: "<storage>",<index>
pub(crate) fn parse_cmti(input: &str) -> IResult<&str, Urc> {
    let (input, _) = tag("+CMTI: ").parse(input)?;
    let (input, storage) =
        delimited(char('"'), map(take_until("\""), String::from), char('"')).parse(input)?;
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
/// (3GPP TS 27.007 dial-string charset).
pub(crate) fn validate_phone_number(s: &str) -> Result<&str> {
    if !s
        .bytes()
        .all(|b| matches!(b, b'0'..=b'9' | b'+' | b'*' | b'#' | b'A'..=b'D'))
    {
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
        let (remaining, resp) = parse_final_result("OK").unwrap_or_default();
        assert_eq!(resp, Response::Ok, "parsing 'OK' must produce Response::Ok");
        assert!(remaining.is_empty(), "expected empty rest");
    }

    #[test]
    fn parse_cme_error() {
        let (_, resp) = parse_final_result("+CME ERROR: 10").unwrap_or_default();
        assert_eq!(
            resp,
            Response::CmeError(10),
            "CME error code 10 must be extracted"
        );
    }

    #[test]
    fn parse_cms_error() {
        let (_, resp) = parse_final_result("+CMS ERROR: 321").unwrap_or_default();
        assert_eq!(
            resp,
            Response::CmsError(321),
            "CMS error code 321 must be extracted"
        );
    }

    #[test]
    fn parse_csq_response() {
        let (_, (rssi, ber)) = parse_csq("+CSQ: 18,99").unwrap_or_default();
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
        assert_eq!(sig.bars, 2, "RSSI 18 (-77 dBm) must be 2 bars");
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
        let (_, urc) = parse_ring("RING").unwrap_or_default();
        assert_eq!(urc, Urc::Ring, "RING must parse to Urc::Ring");
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
