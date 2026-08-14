//! UDH parsing and covert-message classification.
//!
//! User Data Header parsing (application-port addressing IE, 3GPP TS
//! 23.040 § 9.2.3.24) and the surveillance classification built on it:
//! silent SMS by PID, and WAP Push / OMA-CP by UDH destination port.

/// PID for Type 0 SMS: no display, no storage (3GPP TS 23.040 § 9.2.3.9).
pub const PID_TYPE_0_SMS: u8 = 0x40;

/// Exclusive upper bound of the SIM-toolkit replace-short-message PID range
/// (`0x41`-`0x47`).
pub const PID_SIM_TOOLKIT_UPPER: u8 = 0x48;

/// OMA-CP WAP Push destination port (3GPP TS 23.040 / OMA WAP-259).
pub const WAP_PUSH_PORT_OMA_CP: u16 = 2948;

/// Alternative WAP Push destination port used by some implementations.
pub const WAP_PUSH_PORT_ALT: u16 = 49999;

/// UDH Information Element Identifier for 16-bit application port
/// addressing (3GPP TS 23.040 § 9.2.3.24.4).
pub const UDH_IEI_APP_PORT_16BIT: u8 = 0x05;

/// Bit 6 of the first TPDU octet: User Data Header Indicator.
pub const UDHI_BIT: u8 = 0x40;

/// Maximum accepted hex length for a single SMS-DELIVER PDU.
///
/// SECURITY: the hex string originates from modem-controlled storage and is
/// otherwise unbounded. A single SMS-DELIVER TPDU stays well under 200
/// octets; this cap is generous headroom against a malfunctioning or
/// hostile modem flooding the decoder.
pub const MAX_PDU_HEX_LEN: usize = 1024;

/// A parsed UDH application-port addressing element.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdhPorts {
    /// Destination port from the UDH IE.
    pub destination: u16,
    /// Source port from the UDH IE.
    pub source: u16,
}

/// What an incoming message is, beyond its text.
///
/// Returned rather than acted upon: `klesis` rejects a flagged message,
/// while the kernel keeps and marks it. Encoding that choice here would
/// force one of those two to be wrong.
/// WHY deliberately NOT `#[non_exhaustive]`: a downstream `_` arm would map
/// any future covert class to "ordinary message", which is fail-open on the
/// exact axis this type exists to guard. Adding a variant must break every
/// consumer that classifies, so each one decides what the new class means.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MessageClass {
    /// An ordinary user-visible message.
    #[default]
    Normal,
    /// A silent / Type 0 message: specified as neither displayed nor
    /// stored, and the standard covert location-ping.
    Silent {
        /// The PID that triggered the classification.
        pid: u8,
    },
    /// A WAP Push / OMA-CP message, the usual carrier for silent
    /// provisioning changes.
    WapPush {
        /// UDH destination port.
        destination_port: u16,
        /// UDH source port.
        source_port: u16,
    },
}

impl MessageClass {
    /// Whether this classification describes a surveillance-relevant
    /// message that the user would otherwise never see.
    #[must_use]
    pub const fn is_covert(self) -> bool {
        !matches!(self, Self::Normal)
    }
}

/// Whether a PID marks a silent / surveillance message.
///
/// Covers `0x40` (Type 0) through `0x47` (SIM-toolkit replace types).
#[must_use]
pub const fn is_silent_sms_pid(pid: u8) -> bool {
    pid >= PID_TYPE_0_SMS && pid < PID_SIM_TOOLKIT_UPPER
}

/// Whether a UDH destination port marks a WAP Push / OMA-CP message.
#[must_use]
pub const fn is_wap_push_port(port: u16) -> bool {
    port == WAP_PUSH_PORT_OMA_CP || port == WAP_PUSH_PORT_ALT
}

/// Whether the first TPDU octet has the User Data Header Indicator set.
#[must_use]
pub const fn has_udh(first_octet: u8) -> bool {
    first_octet & UDHI_BIT != 0
}

/// Parse a User Data Header from the start of the user-data bytes.
///
/// Scans information elements for 16-bit application port addressing
/// (IEI `0x05`), returning the port pair when present.
#[must_use]
pub fn parse_udh_ports(ud_bytes: &[u8]) -> Option<UdhPorts> {
    let udhl = usize::from(*ud_bytes.first()?);
    // UDH content starts at byte 1 and runs for `udhl` bytes.
    if ud_bytes.len() < udhl + 1 {
        return None;
    }
    let udh = ud_bytes.get(1..=udhl)?;

    let mut pos = 0;
    while pos < udh.len() {
        let iei = *udh.get(pos)?;
        let ie_len = usize::from(*udh.get(pos + 1)?);
        let ie_data_start = pos + 2;
        let ie_data_end = ie_data_start + ie_len;
        if ie_data_end > udh.len() {
            break;
        }
        if iei == UDH_IEI_APP_PORT_16BIT && ie_len == 4 {
            let dest_hi = *udh.get(ie_data_start)?;
            let dest_lo = *udh.get(ie_data_start + 1)?;
            let src_hi = *udh.get(ie_data_start + 2)?;
            let src_lo = *udh.get(ie_data_start + 3)?;
            return Some(UdhPorts {
                destination: u16::from_be_bytes([dest_hi, dest_lo]),
                source: u16::from_be_bytes([src_hi, src_lo]),
            });
        }
        pos = ie_data_end;
    }
    None
}

/// Total octets the UDH occupies, including its own length byte.
///
/// Returns 0 when `ud_bytes` is empty. The result is clamped to the buffer
/// so a hostile UDHL cannot push a later slice past the end.
#[must_use]
pub fn udh_octet_len(ud_bytes: &[u8]) -> usize {
    let udhl = usize::from(ud_bytes.first().copied().unwrap_or(0));
    (udhl + 1).min(ud_bytes.len())
}

/// Septets consumed by `udh_octets` raw UDH bytes once folded into the
/// septet stream.
///
/// 3GPP TS 23.040 § 9.2.3.24: the UDH is stored as whole octets, and fill
/// bits pad it to the next septet boundary before the text begins.
#[must_use]
pub const fn gsm7_udh_septets(udh_octets: usize) -> usize {
    (udh_octets * 8).div_ceil(7)
}

/// Classify an incoming SMS-DELIVER from its PID and user-data bytes.
///
/// `first_octet` is the first TPDU octet (for the UDHI bit), `pid` the
/// protocol identifier, and `ud_bytes` the raw user data — the UDH, when
/// present, is at its head.
///
/// A silent PID takes precedence over a WAP Push port: both describe a
/// message the user never sees, and the PID is the stronger signal because
/// it is what makes the message invisible in the first place.
#[must_use]
pub fn classify(first_octet: u8, pid: u8, ud_bytes: &[u8]) -> MessageClass {
    if is_silent_sms_pid(pid) {
        return MessageClass::Silent { pid };
    }
    if has_udh(first_octet)
        && let Some(ports) = parse_udh_ports(ud_bytes)
        && is_wap_push_port(ports.destination)
    {
        return MessageClass::WapPush {
            destination_port: ports.destination,
            source_port: ports.source,
        };
    }
    MessageClass::Normal
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gsm7_udh_septets_matches_the_spec_rounding() {
        // ceil(octets * 8 / 7). The two boundaries coincide only when the
        // octet count is a multiple of 7 -- which is why the 7-octet WAP
        // Push header looked correct while the 6-octet concatenation
        // header did not.
        assert_eq!(gsm7_udh_septets(6), 7, "6 octets (48 bits) -> 7 septets");
        assert_eq!(
            gsm7_udh_septets(7),
            8,
            "7 octets (56 bits) -> 8 septets exactly, no fill bits"
        );
        assert_eq!(gsm7_udh_septets(0), 0);
    }

    #[test]
    fn silent_pid_range_matches_spec() {
        assert!(is_silent_sms_pid(0x40), "PID 0x40 is Type 0 SMS");
        assert!(is_silent_sms_pid(0x41), "PID 0x41 is a replace type");
        assert!(is_silent_sms_pid(0x47), "PID 0x47 is a replace type");
        assert!(!is_silent_sms_pid(0x48), "PID 0x48 is outside the range");
        assert!(!is_silent_sms_pid(0x00), "PID 0x00 is an ordinary message");
        assert!(!is_silent_sms_pid(0x3F), "PID 0x3F is below the range");
    }

    #[test]
    fn wap_push_ports_match_spec() {
        assert!(is_wap_push_port(WAP_PUSH_PORT_OMA_CP));
        assert!(is_wap_push_port(WAP_PUSH_PORT_ALT));
        assert!(!is_wap_push_port(80), "port 80 is not WAP Push");
    }

    #[test]
    fn udh_ports_parse_from_port_ie() {
        // UDHL=6, IEI=0x05, len=4, dest=2948 (0x0B84), src=0 (0x0000).
        let ud = [0x06, 0x05, 0x04, 0x0B, 0x84, 0x00, 0x00];
        let ports = parse_udh_ports(&ud);
        assert_eq!(
            ports,
            Some(UdhPorts {
                destination: 2948,
                source: 0
            })
        );
    }

    #[test]
    fn udh_ports_absent_when_no_port_ie() {
        // UDHL=5, IEI=0x00 (concatenation), len=3.
        let ud = [0x05, 0x00, 0x03, 0x01, 0x02, 0x03];
        assert_eq!(
            parse_udh_ports(&ud),
            None,
            "a concatenation IE carries no ports"
        );
        assert_eq!(parse_udh_ports(&[]), None, "empty user data has no UDH");
    }

    #[test]
    fn udh_length_is_clamped_to_the_buffer() {
        // A hostile UDHL claiming 200 octets in a 3-byte buffer.
        assert_eq!(
            udh_octet_len(&[200, 0x01, 0x02]),
            3,
            "an over-long UDHL must clamp, so no later slice runs past the end"
        );
    }

    #[test]
    fn classify_flags_silent_sms() {
        assert_eq!(
            classify(0x00, PID_TYPE_0_SMS, &[]),
            MessageClass::Silent {
                pid: PID_TYPE_0_SMS
            },
            "a Type 0 PID must classify as silent"
        );
    }

    #[test]
    fn classify_flags_wap_push_only_when_udhi_set() {
        let ud = [0x06, 0x05, 0x04, 0x0B, 0x84, 0x00, 0x00];
        assert_eq!(
            classify(UDHI_BIT, 0x00, &ud),
            MessageClass::WapPush {
                destination_port: 2948,
                source_port: 0
            },
            "UDHI set plus an OMA-CP port must classify as WAP Push"
        );
        // WHY: without the UDHI bit those same bytes are ordinary message
        // text that merely happens to look like a header. Classifying on
        // content alone would let any sender forge the flag by typing it.
        assert_eq!(
            classify(0x00, 0x00, &ud),
            MessageClass::Normal,
            "identical bytes without UDHI are message text, not a header"
        );
    }

    #[test]
    fn classify_prefers_silent_over_wap_push() {
        let ud = [0x06, 0x05, 0x04, 0x0B, 0x84, 0x00, 0x00];
        assert_eq!(
            classify(UDHI_BIT, PID_TYPE_0_SMS, &ud),
            MessageClass::Silent {
                pid: PID_TYPE_0_SMS
            },
            "the silent PID is the stronger signal and must win"
        );
    }

    #[test]
    fn normal_message_is_not_covert() {
        assert!(!MessageClass::Normal.is_covert());
        assert!(MessageClass::Silent { pid: 0x40 }.is_covert());
        assert!(
            MessageClass::WapPush {
                destination_port: 2948,
                source_port: 0
            }
            .is_covert()
        );
    }
}
