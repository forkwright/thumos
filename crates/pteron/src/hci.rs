//! HCI command/event types, Bluetooth device address, and H4-framed packet encoding/decoding.

use std::fmt;
use std::str::FromStr;

use snafu::Snafu;

// ── Constants ──────────────────────────────────────────────────────────────────

const BD_ADDR_LEN: usize = 6;

const H4_COMMAND_TYPE: u8 = 0x01;
const H4_EVENT_TYPE: u8 = 0x04;

// OGF (Opcode Group Field)
const OGF_LINK_CONTROL: u16 = 0x01;
const OGF_CONTROLLER_BASEBAND: u16 = 0x03;
const OGF_INFORMATIONAL: u16 = 0x04;
const OGF_LE_CONTROLLER: u16 = 0x08;

// OCF (Opcode Command Field)  -  Link Control
const OCF_INQUIRY: u16 = 0x0001;
const OCF_INQUIRY_CANCEL: u16 = 0x0002;

// OCF  -  Controller & Baseband
const OCF_SET_EVENT_MASK: u16 = 0x0001;
const OCF_RESET: u16 = 0x0003;

// OCF  -  Informational Parameters
const OCF_READ_BD_ADDR: u16 = 0x0009;

// OCF  -  LE Controller
const OCF_LE_SET_RANDOM_ADDRESS: u16 = 0x0005;
const OCF_LE_SET_SCAN_PARAMETERS: u16 = 0x000B;
const OCF_LE_SET_SCAN_ENABLE: u16 = 0x000C;

// HCI event codes
const EVT_INQUIRY_COMPLETE: u8 = 0x01;
const EVT_INQUIRY_RESULT: u8 = 0x02;
const EVT_COMMAND_COMPLETE: u8 = 0x0E;
const EVT_COMMAND_STATUS: u8 = 0x0F;
const EVT_LE_META: u8 = 0x3E;

// LE Meta subevent codes
const LE_SUBEVENT_ADVERTISING_REPORT: u8 = 0x02;

// InquiryResult response entry size:
//   BD_ADDR(6) + PSR_Mode(1) + Reserved(2) + Class_of_Device(3) + Clock_Offset(2) = 14
const INQUIRY_ENTRY_SIZE: usize = 14;
const INQUIRY_ENTRY_COD_OFFSET: usize = 9;
const INQUIRY_ENTRY_CLOCK_OFFSET: usize = 12;

// Minimum sizes
const MIN_EVENT_PACKET: usize = 3; // H4 type + event_code + param_length

// ── Error type ─────────────────────────────────────────────────────────────────

/// Errors FROM HCI address parsing and event decoding.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum Error {
    /// Input does not have exactly six colon-separated hex segments.
    #[snafu(display("invalid BD address format: expected AA:BB:CC:DD:EE:FF, got '{input}'"))]
    InvalidAddrFormat {
        /// The full input string that failed to parse.
        input: String,
    },

    /// A single byte segment is not valid hexadecimal.
    #[snafu(display("invalid BD address byte: '{byte}' is not valid hex"))]
    InvalidAddrByte {
        /// The byte segment that failed.
        byte: String,
    },

    /// The packet is shorter than the minimum required length.
    #[snafu(display("HCI packet too short: need at least {min} bytes, got {actual}"))]
    PacketTooShort {
        /// Minimum number of bytes required.
        min: usize,
        /// Actual number of bytes in the packet.
        actual: usize,
    },

    /// The H4 framing byte is not the expected event type (`0x04`).
    #[snafu(display("unexpected H4 type: expected 0x{expected:02X}, got 0x{actual:02X}"))]
    UnexpectedPacketType {
        /// Expected H4 type byte.
        expected: u8,
        /// Actual H4 type byte.
        actual: u8,
    },

    /// The event code is not recognised.
    #[snafu(display("unknown HCI event code: 0x{code:02X}"))]
    UnknownEventCode {
        /// The unknown event code.
        code: u8,
    },

    /// Event parameters are truncated or structurally invalid.
    #[snafu(display("malformed HCI event: {detail}"))]
    MalformedEvent {
        /// Human-readable description of the problem.
        detail: &'static str,
    },
}

/// Result alias for this module.
pub type Result<T> = std::result::Result<T, Error>;

// ── Types ──────────────────────────────────────────────────────────────────────

/// Six-byte Bluetooth device address.
///
/// Stored in display ORDER (most-significant byte first), matching the
/// `"AA:BB:CC:DD:EE:FF"` colon-separated notation.  When constructing
/// FROM raw HCI packet bytes (which are transmitted LSB-first), reverse
/// the byte array before calling [`BdAddr::from_bytes`].
#[derive(Clone, Default, PartialEq, Eq, Hash)]
pub struct BdAddr([u8; BD_ADDR_LEN]);

/// HCI command to send to the controller.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum HciCommand {
    /// Reset the controller to its default state.
    Reset,

    /// Initiate a classic Bluetooth inquiry scan.
    Inquiry {
        /// Lower Address Part (LAP) for the inquiry access code.
        /// Use `[0x33, 0x8B, 0x9E]` for general inquiry.
        lap: [u8; 3],
        /// Duration in units of 1.28 s (1–48).
        inquiry_length: u8,
        /// Maximum number of responses; `0` means unlimited.
        num_responses: u8,
    },

    /// Cancel an in-progress inquiry.
    InquiryCancel,

    /// Read the controller's public `BD_ADDR`.
    ReadBdAddr,

    /// Set the HCI event mask, controlling which events are forwarded.
    SetEventMask {
        /// Eight-byte event mask bitmask.
        mask: [u8; 8],
    },

    /// Configure LE scan parameters before enabling scanning.
    LESetScanParameters {
        /// Scan type: `0x00` = passive, `0x01` = active.
        scan_type: u8,
        /// Scan interval in 0.625 ms units (0x0004–0x4000).
        scan_interval: u16,
        /// Scan window in 0.625 ms units (0x0004–0x4000).
        scan_window: u16,
        /// Own address type: `0x00` = public, `0x01` = random.
        own_address_type: u8,
        /// Scanning filter policy.
        filter_policy: u8,
    },

    /// Enable or disable LE scanning.
    LESetScanEnable {
        /// `true` to enable scanning, `false` to disable.
        enable: bool,
        /// `true` to suppress duplicate advertising reports.
        filter_duplicates: bool,
    },

    /// Set the LE random device address (OGF=0x08, OCF=0x0005).
    ///
    /// Must be called before enabling advertising or scanning with
    /// `Own_Address_Type = 0x01` (Random).  The address must be a valid
    /// static random, non-resolvable private, or resolvable private address.
    LESetRandomAddress {
        /// Six-byte random address in display ORDER (MSB first).
        /// The command encoder reverses to LSB-first for HCI transmission.
        address: BdAddr,
    },
}

/// A device discovered during a classic Bluetooth inquiry.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct InquiryDevice {
    /// Bluetooth device address.
    pub address: BdAddr,
    /// 24-bit Class of Device field, packed INTO the low three bytes.
    pub class_of_device: u32,
    /// Raw clock OFFSET value FROM the inquiry result.
    pub clock_offset: u16,
}

/// A single LE advertising report within a [`HciEvent::LEAdvertisingReport`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct LeAdvReport {
    /// Advertising event type (PDU type flags).
    pub event_type: u8,
    /// Address type: `0` = public, `1` = random.
    pub address_type: u8,
    /// Advertiser device address.
    pub address: BdAddr,
    /// Raw advertising data payload.
    pub data: Vec<u8>,
    /// Received signal strength in dBm.
    pub rssi: i8,
}

/// Decoded HCI event packet.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum HciEvent {
    /// A previously-issued command has completed.
    CommandComplete {
        /// Number of HCI command packets the host may now send.
        num_packets: u8,
        /// Opcode of the completed command.
        opcode: u16,
        /// Raw return parameter bytes.
        return_params: Vec<u8>,
    },

    /// Status notification for a pending command.
    CommandStatus {
        /// Status code (`0x00` = pending/accepted).
        status: u8,
        /// Number of HCI command packets the host may now send.
        num_packets: u8,
        /// Opcode of the command this status relates to.
        opcode: u16,
    },

    /// One or more classic Bluetooth devices found during inquiry.
    InquiryResult {
        /// Discovered devices.
        devices: Vec<InquiryDevice>,
    },

    /// Classic Bluetooth inquiry scan has finished.
    InquiryComplete {
        /// Status code (`0x00` = success).
        status: u8,
    },

    /// One or more LE advertising reports received by the controller.
    LEAdvertisingReport {
        /// Individual advertising reports.
        reports: Vec<LeAdvReport>,
    },
}

// ── BdAddr impl ────────────────────────────────────────────────────────────────

impl BdAddr {
    /// Construct a `BdAddr` FROM a raw byte array in display ORDER (MSB first).
    ///
    /// When reading FROM an HCI packet (WHERE bytes are LSB-first), reverse
    /// the array before calling this function.
    pub const fn from_bytes(bytes: [u8; BD_ADDR_LEN]) -> Self {
        Self(bytes)
    }

    /// Parse a `BD_ADDR` FROM a colon-separated hex string (e.g. `"AA:BB:CC:DD:EE:FF"`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidAddrFormat`] if the string does not have exactly
    /// six colon-separated segments.
    ///
    /// Returns [`Error::InvalidAddrByte`] if any segment is not valid hex.
    ///
    /// # Examples
    ///
    /// ```
    /// use pteron::hci::BdAddr;
    ///
    /// let addr = BdAddr::parse("AA:BB:CC:DD:EE:FF").unwrap();
    /// assert_eq!(addr.to_string(), "AA:BB:CC:DD:EE:FF");
    /// ```
    pub fn parse(s: &str) -> Result<Self> {
        s.parse()
    }

    /// Return the raw bytes in display ORDER (MSB first).
    pub const fn as_bytes(&self) -> &[u8; BD_ADDR_LEN] {
        &self.0
    }
}

impl FromStr for BdAddr {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != BD_ADDR_LEN {
            return Err(Error::InvalidAddrFormat {
                input: s.to_owned(),
            });
        }
        let mut bytes = [0u8; BD_ADDR_LEN];
        for (byte, part) in bytes.iter_mut().zip(parts.iter()) {
            *byte = u8::from_str_radix(part, 16).map_err(|_| Error::InvalidAddrByte {
                byte: (*part).to_owned(),
            })?;
        }
        Ok(Self(bytes))
    }
}

impl fmt::Display for BdAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [b0, b1, b2, b3, b4, b5] = self.0;
        write!(f, "{b0:02X}:{b1:02X}:{b2:02X}:{b3:02X}:{b4:02X}:{b5:02X}")
    }
}

impl fmt::Debug for BdAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BdAddr({self})")
    }
}

// ── Packet encoding ────────────────────────────────────────────────────────────

/// Encode an [`HciCommand`] INTO an H4-framed byte buffer ready to write to
/// the HCI UART transport.
///
/// The buffer layout is:
/// `[0x01, opcode_lo, opcode_hi, param_len, ...params]`
pub fn encode_command(cmd: &HciCommand) -> Vec<u8> {
    let (opcode, params) = build_command_parts(cmd);
    let opcode_bytes = opcode.to_le_bytes();
    // INVARIANT: HCI parameter total is bounded by spec at 255 bytes; always fits in u8.
    let param_len = u8::try_from(params.len()).unwrap_or_default();

    let mut packet = Vec::with_capacity(4 + params.len());
    packet.push(H4_COMMAND_TYPE);
    packet.push(opcode_bytes[0]);
    packet.push(opcode_bytes[1]);
    packet.push(param_len);
    packet.extend_from_slice(&params);
    packet
}

fn build_command_parts(cmd: &HciCommand) -> (u16, Vec<u8>) {
    match cmd {
        HciCommand::Reset => {
            let opcode = (OGF_CONTROLLER_BASEBAND << 10) | OCF_RESET;
            (opcode, vec![])
        }
        HciCommand::Inquiry {
            lap,
            inquiry_length,
            num_responses,
        } => {
            let opcode = (OGF_LINK_CONTROL << 10) | OCF_INQUIRY;
            let params = vec![lap[0], lap[1], lap[2], *inquiry_length, *num_responses];
            (opcode, params)
        }
        HciCommand::InquiryCancel => {
            let opcode = (OGF_LINK_CONTROL << 10) | OCF_INQUIRY_CANCEL;
            (opcode, vec![])
        }
        HciCommand::ReadBdAddr => {
            let opcode = (OGF_INFORMATIONAL << 10) | OCF_READ_BD_ADDR;
            (opcode, vec![])
        }
        HciCommand::SetEventMask { mask } => {
            let opcode = (OGF_CONTROLLER_BASEBAND << 10) | OCF_SET_EVENT_MASK;
            (opcode, mask.to_vec())
        }
        HciCommand::LESetScanParameters {
            scan_type,
            scan_interval,
            scan_window,
            own_address_type,
            filter_policy,
        } => {
            let opcode = (OGF_LE_CONTROLLER << 10) | OCF_LE_SET_SCAN_PARAMETERS;
            let iv = scan_interval.to_le_bytes();
            let wv = scan_window.to_le_bytes();
            let params = vec![
                *scan_type,
                iv.first().copied().unwrap_or_default(),
                iv.get(1).copied().unwrap_or_default(),
                wv.first().copied().unwrap_or_default(),
                wv.get(1).copied().unwrap_or_default(),
                *own_address_type,
                *filter_policy,
            ];
            (opcode, params)
        }
        HciCommand::LESetScanEnable {
            enable,
            filter_duplicates,
        } => {
            let opcode = (OGF_LE_CONTROLLER << 10) | OCF_LE_SET_SCAN_ENABLE;
            let params = vec![u8::from(*enable), u8::from(*filter_duplicates)];
            (opcode, params)
        }
        HciCommand::LESetRandomAddress { address } => {
            let opcode = (OGF_LE_CONTROLLER << 10) | OCF_LE_SET_RANDOM_ADDRESS;
            // WHY: HCI spec §7.8.4 transmits BD_ADDR LSB-first; BdAddr stores
            // MSB-first for display, so we reverse when encoding.
            let a = address.as_bytes();
            let params = vec![a[5], a[4], a[3], a[2], a[1], a[0]];
            (opcode, params)
        }
    }
}

// ── Packet decoding ────────────────────────────────────────────────────────────

/// Decode an H4-framed HCI event packet.
///
/// # Errors
///
/// Returns [`Error::PacketTooShort`] if `data` has fewer than 3 bytes.
///
/// Returns [`Error::UnexpectedPacketType`] if the first byte is not `0x04`.
///
/// Returns [`Error::UnknownEventCode`] for unrecognised event codes.
///
/// Returns [`Error::MalformedEvent`] if parameters are truncated or invalid.
pub fn decode_event(data: &[u8]) -> Result<HciEvent> {
    if data.len() < MIN_EVENT_PACKET {
        return Err(Error::PacketTooShort {
            min: MIN_EVENT_PACKET,
            actual: data.len(),
        });
    }

    let h4_type = data.first().copied().unwrap_or_default();
    if h4_type != H4_EVENT_TYPE {
        return Err(Error::UnexpectedPacketType {
            expected: H4_EVENT_TYPE,
            actual: h4_type,
        });
    }

    let event_code = data.get(1).copied().unwrap_or_default();
    // params start at byte 3 (after H4 type, event code, param_length)
    let params = data.get(3..).unwrap_or(&[]);

    match event_code {
        EVT_COMMAND_COMPLETE => decode_command_complete(params),
        EVT_COMMAND_STATUS => decode_command_status(params),
        EVT_INQUIRY_RESULT => decode_inquiry_result(params),
        EVT_INQUIRY_COMPLETE => decode_inquiry_complete(params),
        EVT_LE_META => decode_le_meta(params),
        code => Err(Error::UnknownEventCode { code }),
    }
}

fn decode_command_complete(params: &[u8]) -> Result<HciEvent> {
    let mut cur = Cursor::new(params);
    let num_packets = cur.read_u8().ok_or(Error::MalformedEvent {
        detail: "CommandComplete: missing num_packets",
    })?;
    let opcode = cur.read_u16_le().ok_or(Error::MalformedEvent {
        detail: "CommandComplete: missing opcode",
    })?;
    let return_params = cur.remaining().to_vec();
    Ok(HciEvent::CommandComplete {
        num_packets,
        opcode,
        return_params,
    })
}

fn decode_command_status(params: &[u8]) -> Result<HciEvent> {
    let mut cur = Cursor::new(params);
    let status = cur.read_u8().ok_or(Error::MalformedEvent {
        detail: "CommandStatus: missing status",
    })?;
    let num_packets = cur.read_u8().ok_or(Error::MalformedEvent {
        detail: "CommandStatus: missing num_packets",
    })?;
    let opcode = cur.read_u16_le().ok_or(Error::MalformedEvent {
        detail: "CommandStatus: missing opcode",
    })?;
    Ok(HciEvent::CommandStatus {
        status,
        num_packets,
        opcode,
    })
}

fn decode_inquiry_complete(params: &[u8]) -> Result<HciEvent> {
    let status = params.first().copied().ok_or(Error::MalformedEvent {
        detail: "InquiryComplete: missing status",
    })?;
    Ok(HciEvent::InquiryComplete { status })
}

fn decode_inquiry_result(params: &[u8]) -> Result<HciEvent> {
    let num_responses = params.first().copied().ok_or(Error::MalformedEvent {
        detail: "InquiryResult: missing num_responses",
    })?;

    let num = usize::from(num_responses);
    let required = 1 + num * INQUIRY_ENTRY_SIZE;
    if params.len() < required {
        return Err(Error::MalformedEvent {
            detail: "InquiryResult: parameters truncated",
        });
    }

    let mut devices = Vec::with_capacity(num);
    for i in 0..num {
        let base = 1 + i * INQUIRY_ENTRY_SIZE;
        // BD_ADDR: 6 bytes, transmitted LSB-first; store MSB-first for display
        let addr_bytes = params.get(base..base + 6).ok_or(Error::MalformedEvent {
            detail: "InquiryResult: BD_ADDR truncated",
        })?;
        let address = BdAddr::from_bytes([
            addr_bytes.get(5).copied().unwrap_or_default(),
            addr_bytes.get(4).copied().unwrap_or_default(),
            addr_bytes.get(3).copied().unwrap_or_default(),
            addr_bytes.get(2).copied().unwrap_or_default(),
            addr_bytes.get(1).copied().unwrap_or_default(),
            addr_bytes.first().copied().unwrap_or_default(),
        ]);

        // Class of Device: 3 bytes at OFFSET 9, little-endian
        let cod_base = base + INQUIRY_ENTRY_COD_OFFSET;
        let cod = params
            .get(cod_base..cod_base + 3)
            .ok_or(Error::MalformedEvent {
                detail: "InquiryResult: CoD truncated",
            })?;
        let class_of_device = u32::from(cod.first().copied().unwrap_or_default())
            | (u32::from(cod.get(1).copied().unwrap_or_default()) << 8)
            | (u32::from(cod.get(2).copied().unwrap_or_default()) << 16);

        // Clock Offset: 2 bytes at OFFSET 12, little-endian
        let clk_base = base + INQUIRY_ENTRY_CLOCK_OFFSET;
        let clk = params
            .get(clk_base..clk_base + 2)
            .ok_or(Error::MalformedEvent {
                detail: "InquiryResult: clock_offset truncated",
            })?;
        let clock_offset = u16::from(clk.first().copied().unwrap_or_default())
            | (u16::from(clk.get(1).copied().unwrap_or_default()) << 8);

        devices.push(InquiryDevice {
            address,
            class_of_device,
            clock_offset,
        });
    }

    Ok(HciEvent::InquiryResult { devices })
}

fn decode_le_meta(params: &[u8]) -> Result<HciEvent> {
    let subevent = params.first().copied().ok_or(Error::MalformedEvent {
        detail: "LE Meta: missing subevent code",
    })?;

    match subevent {
        LE_SUBEVENT_ADVERTISING_REPORT => {
            decode_le_advertising_report(params.get(1..).unwrap_or(&[]))
        }
        _ => Err(Error::MalformedEvent {
            detail: "LE Meta: unsupported subevent",
        }),
    }
}

fn decode_le_advertising_report(params: &[u8]) -> Result<HciEvent> {
    let mut cur = Cursor::new(params);
    let num_reports = cur.read_u8().ok_or(Error::MalformedEvent {
        detail: "LEAdvReport: missing num_reports",
    })?;

    let mut reports = Vec::with_capacity(usize::from(num_reports));
    for _ in 0..num_reports {
        let event_type = cur.read_u8().ok_or(Error::MalformedEvent {
            detail: "LEAdvReport: missing event_type",
        })?;
        let address_type = cur.read_u8().ok_or(Error::MalformedEvent {
            detail: "LEAdvReport: missing address_type",
        })?;
        let address = cur.read_bdaddr().ok_or(Error::MalformedEvent {
            detail: "LEAdvReport: missing address",
        })?;
        let data_len = usize::from(cur.read_u8().ok_or(Error::MalformedEvent {
            detail: "LEAdvReport: missing data_length",
        })?);
        let data = cur
            .read_bytes(data_len)
            .ok_or(Error::MalformedEvent {
                detail: "LEAdvReport: data truncated",
            })?
            .to_vec();
        let rssi_raw = cur.read_u8().ok_or(Error::MalformedEvent {
            detail: "LEAdvReport: missing RSSI",
        })?;
        let rssi = rssi_raw.cast_signed();

        reports.push(LeAdvReport {
            event_type,
            address_type,
            address,
            data,
            rssi,
        });
    }

    Ok(HciEvent::LEAdvertisingReport { reports })
}

// ── Cursor helper ──────────────────────────────────────────────────────────────

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    const fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn read_u8(&mut self) -> Option<u8> {
        let b = *self.data.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }

    fn read_u16_le(&mut self) -> Option<u16> {
        let lo = self.read_u8()?;
        let hi = self.read_u8()?;
        Some(u16::from_le_bytes([lo, hi]))
    }

    fn read_bytes(&mut self, n: usize) -> Option<&[u8]> {
        let slice = self.data.get(self.pos..self.pos + n)?;
        self.pos += n;
        Some(slice)
    }

    /// Read a 6-byte `BD_ADDR` (HCI LSB-first ORDER) and return as display-ORDER [`BdAddr`].
    fn read_bdaddr(&mut self) -> Option<BdAddr> {
        let b0 = self.read_u8()?;
        let b1 = self.read_u8()?;
        let b2 = self.read_u8()?;
        let b3 = self.read_u8()?;
        let b4 = self.read_u8()?;
        let b5 = self.read_u8()?;
        // HCI sends BD_ADDR LSB first; invert to get display ORDER (MSB first)
        Some(BdAddr::from_bytes([b5, b4, b3, b2, b1, b0]))
    }

    fn remaining(&self) -> &[u8] {
        self.data.get(self.pos..).unwrap_or(&[])
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── BdAddr ──

    #[test]
    fn bdaddr_parses_valid_uppercase() -> Result<()> {
        let addr = BdAddr::parse("AA:BB:CC:DD:EE:FF")?;
        assert_eq!(
            addr.as_bytes(),
            &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            "bytes should match the input segments"
        );
        Ok(())
    }

    #[test]
    fn bdaddr_parses_valid_lowercase() -> Result<()> {
        let addr = BdAddr::parse("aa:bb:cc:dd:ee:ff")?;
        assert_eq!(
            addr.as_bytes(),
            &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            "lowercase should produce the same bytes as uppercase"
        );
        Ok(())
    }

    #[test]
    fn bdaddr_display_roundtrip() -> Result<()> {
        let original = "DE:AD:BE:EF:00:01";
        let addr: BdAddr = original.parse()?;
        assert_eq!(
            addr.to_string(),
            original,
            "Display should reproduce the original uppercase colon-separated string"
        );
        Ok(())
    }

    #[test]
    fn bdaddr_rejects_too_few_segments() {
        let result = BdAddr::parse("AA:BB:CC:DD:EE");
        assert!(
            result.is_err(),
            "address with only 5 segments should be rejected"
        );
    }

    #[test]
    fn bdaddr_rejects_too_many_segments() {
        let result = BdAddr::parse("AA:BB:CC:DD:EE:FF:00");
        assert!(
            result.is_err(),
            "address with 7 segments should be rejected"
        );
    }

    #[test]
    fn bdaddr_rejects_invalid_hex_byte() {
        let result = BdAddr::parse("ZZ:BB:CC:DD:EE:FF");
        assert!(result.is_err(), "non-hex segment 'ZZ' should be rejected");
    }

    // ── encode_command ──

    #[test]
    fn encode_reset_produces_correct_bytes() {
        // Reset: opcode = (0x03 << 10) | 0x0003 = 0x0C03, no params
        let bytes = encode_command(&HciCommand::Reset);
        assert_eq!(
            bytes,
            &[0x01, 0x03, 0x0C, 0x00],
            "Reset should encode to H4 type + opcode 0x0C03 LE + zero param_len"
        );
    }

    #[test]
    fn encode_inquiry_produces_correct_bytes() {
        // Inquiry: opcode = (0x01 << 10) | 0x0001 = 0x0401
        let cmd = HciCommand::Inquiry {
            lap: [0x33, 0x8B, 0x9E],
            inquiry_length: 0x08,
            num_responses: 0x00,
        };
        let bytes = encode_command(&cmd);
        assert_eq!(
            bytes,
            &[0x01, 0x01, 0x04, 0x05, 0x33, 0x8B, 0x9E, 0x08, 0x00],
            "Inquiry should encode opcode 0x0401 LE + 5 param bytes"
        );
    }

    #[test]
    fn encode_le_set_scan_enable_produces_correct_bytes() {
        // LESetScanEnable: opcode = (0x08 << 10) | 0x000C = 0x200C
        let cmd = HciCommand::LESetScanEnable {
            enable: true,
            filter_duplicates: false,
        };
        let bytes = encode_command(&cmd);
        assert_eq!(
            bytes,
            &[0x01, 0x0C, 0x20, 0x02, 0x01, 0x00],
            "LESetScanEnable should encode opcode 0x200C LE + enable/filter bytes"
        );
    }

    // ── decode_event ──

    #[test]
    fn decode_command_complete_event() -> Result<()> {
        // H4=0x04, evt=0x0E, param_len=4, num_packets=1, opcode=0x0C03(LE), status=0x00
        let data = [0x04, 0x0E, 0x04, 0x01, 0x03, 0x0C, 0x00];
        let evt = decode_event(&data)?;
        assert!(
            matches!(
                evt,
                HciEvent::CommandComplete {
                    num_packets: 1,
                    opcode: 0x0C03,
                    ..
                }
            ),
            "should decode as CommandComplete with num_packets=1, opcode=0x0C03"
        );
        Ok(())
    }

    #[test]
    fn decode_inquiry_complete_event() -> Result<()> {
        let data = [0x04, 0x01, 0x01, 0x00];
        let evt = decode_event(&data)?;
        assert!(
            matches!(evt, HciEvent::InquiryComplete { status: 0 }),
            "should decode as InquiryComplete with status=0"
        );
        Ok(())
    }

    #[test]
    fn decode_inquiry_result_event() -> Result<()> {
        // 1 response: BD_ADDR=01:02:03:04:05:06 (LSB first in packet), PSR=0, reserved=0,0,
        // CoD=0x240408, ClkOffset=0x0000
        #[rustfmt::skip]
        let data = [
            0x04, 0x02, 0x0F,        // H4 + event code + param_len=15
            0x01,                     // num_responses=1
            0x06, 0x05, 0x04, 0x03, 0x02, 0x01, // BD_ADDR LSB-first
            0x00,                     // PSR_Mode
            0x00, 0x00,               // Reserved
            0x08, 0x04, 0x24,         // Class_of_Device (0x240408)
            0x00, 0x00,               // Clock_Offset
        ];
        let evt = decode_event(&data)?;
        let HciEvent::InquiryResult { devices } = evt else {
            unreachable!("expected InquiryResult variant");
        };
        assert_eq!(devices.len(), 1, "should have exactly one inquiry device");
        assert_eq!(
            devices
                .first()
                .cloned()
                .unwrap_or_default()
                .address
                .to_string(),
            "01:02:03:04:05:06",
            "address should be in display ORDER (MSB first)"
        );
        assert_eq!(
            devices.first().cloned().unwrap_or_default().class_of_device,
            0x00_24_04_08,
            "CoD should be decoded FROM little-endian bytes"
        );
        Ok(())
    }

    #[test]
    fn decode_rejects_packet_too_short() {
        let data = [0x04, 0x0E]; // only 2 bytes
        let result = decode_event(&data);
        assert!(
            result.is_err(),
            "a 2-byte packet should be rejected as too short"
        );
        assert!(
            matches!(result, Err(Error::PacketTooShort { .. })),
            "error should be PacketTooShort"
        );
    }

    #[test]
    fn decode_rejects_unknown_event_code() {
        let data = [0x04, 0xFF, 0x00]; // event code 0xFF is not defined
        let result = decode_event(&data);
        assert!(
            matches!(result, Err(Error::UnknownEventCode { code: 0xFF })),
            "unknown event code should produce UnknownEventCode error"
        );
    }

    #[test]
    fn decode_rejects_wrong_h4_type() {
        let data = [0x02, 0x0E, 0x04, 0x01, 0x03, 0x0C, 0x00]; // 0x02 = ACL, not event
        let result = decode_event(&data);
        assert!(
            matches!(result, Err(Error::UnexpectedPacketType { .. })),
            "non-event H4 type should produce UnexpectedPacketType error"
        );
    }
}
