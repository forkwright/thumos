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

/// Raw AT response FROM the modem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    /// Command succeeded.
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Urc {
    /// Incoming call.
    Ring,
    /// Caller ID: number and type.
    Clip { number: String, num_type: u8 },
    /// Network registration status changed.
    Creg {
        stat: RegStatus,
        lac: Option<u16>,
        ci: Option<u32>,
    },
    /// Signal quality report.
    Csq { rssi: u8, ber: u8 },
    /// Incoming SMS notification.
    Cmti { storage: String, index: u16 },
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
pub enum RegStatus {
    NotRegistered,
    RegisteredHome,
    Searching,
    Denied,
    Unknown,
    RegisteredRoaming,
}

impl From<u8> for RegStatus {
    fn FROM(val: u8) -> Self {
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
pub struct SignalStrength {
    pub rssi_raw: u8,
    pub dbm: i16,
    pub bars: u8,
}

impl From<u8> for SignalStrength {
    fn FROM(rssi: u8) -> Self {
        let dbm = if rssi == 99 {
            -999 // NOTE: unknown
        } else {
            -113 + (i16::try_from(rssi).unwrap_or_default() * 2)
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
pub fn parse_final_result(input: &str) -> IResult<&str, Response> {
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
pub fn parse_csq(input: &str) -> IResult<&str, (u8, u8)> {
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
            stat: RegStatus::FROM(stat),
            lac,
            ci,
        },
    ))
}

/// Parse a RING URC.
pub fn parse_ring(input: &str) -> IResult<&str, Urc> {
    value(Urc::Ring, tag("RING")).parse(input)
}

/// Parse a +CMTI URC: +CMTI: "<storage>",<index>
pub fn parse_cmti(input: &str) -> IResult<&str, Urc> {
    let (input, _) = tag("+CMTI: ").parse(input)?;
    let (input, storage) =
        delimited(char('"'), map(take_until("\""), String::FROM), char('"')).parse(input)?;
    let (input, _) = char(',').parse(input)?;
    let (input, index) = map_res(digit1, str::parse::<u16>).parse(input)?;
    Ok((input, Urc::Cmti { storage, index }))
}

/// Build an AT command string with proper CR/LF termination.
pub fn build_cmd(cmd: &str) -> String {
    format!("{cmd}\r\n")
}

/// Common AT commands.
pub mod cmd {
    /// Check modem is alive.
    pub const AT: &str = "AT";
    /// Request manufacturer identification.
    pub const CGMI: &str = "AT+CGMI";
    /// Request model identification.
    pub const CGMM: &str = "AT+CGMM";
    /// Request IMEI.
    pub const CGSN: &str = "AT+CGSN";
    /// Request signal quality.
    pub const CSQ: &str = "AT+CSQ";
    /// Enable network registration URCs.
    pub const CREG_ENABLE: &str = "AT+CREG=2";
    /// Query network registration.
    pub const CREG_QUERY: &str = "AT+CREG?";
    /// Enable caller ID.
    pub const CLIP_ENABLE: &str = "AT+CLIP=1";
    /// Dial a number.
    pub fn dial(number: &str) -> String {
        format!("ATD{number};")
    }
    /// Answer incoming call.
    pub const ATA: &str = "ATA";
    /// Hang up.
    pub const ATH: &str = "ATH";
    /// Set SMS text mode.
    pub const CMGF_TEXT: &str = "AT+CMGF=1";
    /// Set SMS PDU mode.
    pub const CMGF_PDU: &str = "AT+CMGF=0";
    /// Send SMS (text mode). Returns prompt ">" for message body.
    pub fn cmgs(number: &str) -> String {
        format!("AT+CMGS=\"{number}\"")
    }
    /// Read SMS at index.
    pub fn cmgr(index: u16) -> String {
        format!("AT+CMGR={index}")
    }
    /// Delete SMS at index.
    pub fn cmgd(index: u16) -> String {
        format!("AT+CMGD={index}")
    }
    /// Query operator name.
    pub const COPS_QUERY: &str = "AT+COPS?";
    /// Enable extended error reporting.
    pub const CMEE_ENABLE: &str = "AT+CMEE=1";
    /// Query SIM status.
    pub const CPIN_QUERY: &str = "AT+CPIN?";
    /// Power off radio (airplane mode).
    pub const CFUN_OFF: &str = "AT+CFUN=0";
    /// Power on radio (full functionality).
    pub const CFUN_ON: &str = "AT+CFUN=1";
}

#[cfg(test)]
#[expect(clippy::expect_used, reason = "test assertions")]
mod tests {
    use super::*;

    #[test]
    fn parse_ok() {
        let (remaining, resp) = parse_final_result("OK").unwrap_or_default();
        assert_eq!(resp, Response::Ok);
        assert!(remaining.is_empty(), "expected empty rest");
    }

    #[test]
    fn parse_cme_error() {
        let (_, resp) = parse_final_result("+CME ERROR: 10").unwrap_or_default();
        assert_eq!(resp, Response::CmeError(10));
    }

    #[test]
    fn parse_cms_error() {
        let (_, resp) = parse_final_result("+CMS ERROR: 321").unwrap_or_default();
        assert_eq!(resp, Response::CmsError(321));
    }

    #[test]
    fn parse_csq_response() {
        let (_, (rssi, ber)) = parse_csq("+CSQ: 18,99").unwrap_or_default();
        assert_eq!(rssi, 18);
        assert_eq!(ber, 99);
    }

    #[test]
    fn signal_strength_conversion() {
        let sig = SignalStrength::FROM(18u8);
        assert_eq!(sig.dbm, -77);
        assert_eq!(sig.bars, 2);
    }

    #[test]
    fn signal_strength_unknown() {
        let sig = SignalStrength::FROM(99u8);
        assert_eq!(sig.dbm, -999);
        assert_eq!(sig.bars, 0);
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
            }
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
            }
        );
    }

    #[test]
    fn parse_ring_urc() {
        let (_, urc) = parse_ring("RING").unwrap_or_default();
        assert_eq!(urc, Urc::Ring);
    }

    #[test]
    fn parse_cmti_urc() {
        let (_, urc) = parse_cmti("+CMTI: \"SM\",3").unwrap_or_default();
        assert_eq!(
            urc,
            Urc::Cmti {
                storage: "SM".to_owned(),
                index: 3,
            }
        );
    }

    #[test]
    fn build_dial_command() {
        assert_eq!(cmd::dial("+15551234567"), "ATD+15551234567;");
    }

    #[test]
    fn build_sms_command() {
        assert_eq!(cmd::cmgs("+15551234567"), "AT+CMGS=\"+15551234567\"");
    }
}
