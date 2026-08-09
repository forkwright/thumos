//! HCI command/event types, Bluetooth device address, and H4-framed packet encoding/decoding.

use std::fmt;
use std::str::FromStr;

use snafu::Snafu;

// ── Constants ──────────────────────────────────────────────────────────────────

const BD_ADDR_LEN: usize = 6;

const H4_COMMAND_TYPE: u8 = 0x01;
/// H4 packet type for HCI ACL Data (Vol 4 Part E §5.4.2). `pub(crate)` so
/// `transport.rs`'s RX loop can dispatch on it without re-decoding.
pub(crate) const H4_ACL_TYPE: u8 = 0x02;
/// `pub(crate)` so `transport.rs`'s RX loop can dispatch on it without
/// re-decoding (#635).
pub(crate) const H4_EVENT_TYPE: u8 = 0x04;

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
// H4 type(1) + Connection_Handle/PB/BC(2) + Data_Total_Length(2)
const MIN_ACL_PACKET: usize = 5;

// ── Error type ─────────────────────────────────────────────────────────────────

/// Errors FROM HCI address parsing and event decoding.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub(crate) enum Error {
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

    /// ACL Data packet fields are truncated or structurally invalid (#635).
    #[snafu(display("malformed HCI ACL packet: {detail}"))]
    MalformedAclPacket {
        /// Human-readable description of the problem.
        detail: &'static str,
    },
}

/// Result alias for this module.
pub(crate) type Result<T> = std::result::Result<T, Error>;

// ── Types ──────────────────────────────────────────────────────────────────────

/// Six-byte Bluetooth device address.
///
/// Stored in display ORDER (most-significant byte first), matching the
/// `"AA:BB:CC:DD:EE:FF"` colon-separated notation.  When constructing
/// FROM raw HCI packet bytes (which are transmitted LSB-first), reverse
/// the byte array before calling [`BdAddr::from_bytes`].
#[derive(Clone, Default, PartialEq, Eq, Hash)]
pub(crate) struct BdAddr([u8; BD_ADDR_LEN]);

/// HCI command to send to the controller.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub(crate) enum HciCommand {
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
pub(crate) struct InquiryDevice {
    /// Bluetooth device address.
    pub(crate) address: BdAddr,
    /// 24-bit Class of Device field, packed INTO the low three bytes.
    pub(crate) class_of_device: u32,
    /// Raw clock OFFSET value FROM the inquiry result.
    pub(crate) clock_offset: u16,
}

/// A single LE advertising report within a [`HciEvent::LEAdvertisingReport`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub(crate) struct LeAdvReport {
    /// Advertising event type (PDU type flags).
    pub(crate) event_type: u8,
    /// Address type: `0` = public, `1` = random.
    pub(crate) address_type: u8,
    /// Advertiser device address.
    pub(crate) address: BdAddr,
    /// Raw advertising data payload.
    pub(crate) data: Vec<u8>,
    /// Received signal strength in dBm.
    pub(crate) rssi: i8,
}

/// Decoded HCI event packet.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub(crate) enum HciEvent {
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

/// `Packet_Boundary_Flag` values on an HCI ACL Data packet (Vol 4 Part E
/// §5.4.2, Table 5.1) — where in an L2CAP PDU's fragmentation sequence this
/// ACL packet falls (#635).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub(crate) enum PbFlag {
    /// `0b00` — first fragment of a message, not automatically flushable.
    FirstNonFlushable,
    /// `0b01` — a continuing fragment of a higher-layer message.
    Continuation,
    /// `0b10` — first fragment of a message, automatically flushable.
    FirstFlushable,
    /// `0b11` — a complete L2CAP PDU, automatically flushable
    /// (Controller-to-Host only).
    CompleteFlushable,
}

impl PbFlag {
    /// Decode the two-bit `Packet_Boundary_Flag` field.
    const fn from_bits(bits: u8) -> Self {
        match bits & 0b11 {
            0b00 => Self::FirstNonFlushable,
            0b01 => Self::Continuation,
            0b10 => Self::FirstFlushable,
            _ => Self::CompleteFlushable,
        }
    }

    /// Encode back to the two-bit wire value — the inverse of [`Self::from_bits`].
    const fn to_bits(self) -> u8 {
        match self {
            Self::FirstNonFlushable => 0b00,
            Self::Continuation => 0b01,
            Self::FirstFlushable => 0b10,
            Self::CompleteFlushable => 0b11,
        }
    }
}

/// A decoded HCI ACL Data packet (H4 type `0x02`, Vol 4 Part E §5.4.2).
///
/// `data` borrows FROM the input buffer — every variant of
/// [`Packet_Boundary_Flag`](PbFlag) still needs its bytes copied exactly
/// once by the L2CAP reassembler (`l2cap.rs`, #635), so this decode step
/// does not pay for a second copy first.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub(crate) struct AclDataPacket<'a> {
    /// `Connection_Handle` (12 bits).
    pub(crate) handle: u16,
    /// `Packet_Boundary_Flag` (2 bits).
    pub(crate) pb_flag: PbFlag,
    /// `Broadcast_Flag` (2 bits). Always `0b00` (point-to-point) on LE-U;
    /// classic BR/EDR broadcast values are decoded but unused by this driver.
    pub(crate) bc_flag: u8,
    /// The packet's `Data` field — one fragment of an L2CAP PDU.
    pub(crate) data: &'a [u8],
}

// ── BdAddr impl ────────────────────────────────────────────────────────────────

impl BdAddr {
    /// Construct a `BdAddr` FROM a raw byte array in display ORDER (MSB first).
    ///
    /// When reading FROM an HCI packet (WHERE bytes are LSB-first), reverse
    /// the array before calling this function.
    pub(crate) const fn from_bytes(bytes: [u8; BD_ADDR_LEN]) -> Self {
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
    /// Internal callers use this parser for display-order addresses such as
    /// `AA:BB:CC:DD:EE:FF`.
    pub(crate) fn parse(s: &str) -> Result<Self> {
        s.parse()
    }

    /// Return the raw bytes in display ORDER (MSB first).
    pub(crate) const fn as_bytes(&self) -> &[u8; BD_ADDR_LEN] {
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
pub(crate) fn encode_command(cmd: &HciCommand) -> Vec<u8> {
    let (opcode, params) = build_command_parts(cmd);
    let [op_lo, op_hi] = opcode.to_le_bytes();
    // INVARIANT: HCI parameter total is bounded by spec at 255 bytes; always fits in u8.
    let param_len = u8::try_from(params.len()).map_or(u8::MAX, |len| len);

    let mut packet = Vec::with_capacity(4 + params.len());
    packet.push(H4_COMMAND_TYPE);
    packet.push(op_lo);
    packet.push(op_hi);
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
            let [l0, l1, l2] = *lap;
            let params = vec![l0, l1, l2, *inquiry_length, *num_responses];
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
            let [iv_lo, iv_hi] = scan_interval.to_le_bytes();
            let [wv_lo, wv_hi] = scan_window.to_le_bytes();
            let params = vec![
                *scan_type,
                iv_lo,
                iv_hi,
                wv_lo,
                wv_hi,
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
            let [a0, a1, a2, a3, a4, a5] = *address.as_bytes();
            let params = vec![a5, a4, a3, a2, a1, a0];
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
pub(crate) fn decode_event(data: &[u8]) -> Result<HciEvent> {
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
    let param_length = usize::from(data.get(2).copied().unwrap_or_default());
    // WHY: params must be bounded to the declared param_length, not every
    // trailing byte in `data` — otherwise bytes past the real event boundary
    // would be folded into params (e.g. CommandComplete's return_params).
    let params = data.get(3..).unwrap_or(&[]);
    let params = params.get(..param_length).ok_or(Error::MalformedEvent {
        detail: "event: param_length exceeds available bytes",
    })?;

    match event_code {
        EVT_COMMAND_COMPLETE => decode_command_complete(params),
        EVT_COMMAND_STATUS => decode_command_status(params),
        EVT_INQUIRY_RESULT => decode_inquiry_result(params),
        EVT_INQUIRY_COMPLETE => decode_inquiry_complete(params),
        EVT_LE_META => decode_le_meta(params),
        code => Err(Error::UnknownEventCode { code }),
    }
}

/// Decode an H4-framed HCI ACL Data packet (H4 type `0x02`, Vol 4 Part E
/// §5.4.2).
///
/// Layout: `[0x02, handle_lo, handle_hi|pb|bc, data_len_lo, data_len_hi, data...]`
/// — `Connection_Handle` (12 bits) and `PB_Flag`/`BC_Flag` (2 bits each)
/// share a little-endian `u16`; `Data_Total_Length` is a second
/// little-endian `u16` bounding the `Data` field that follows.
///
/// # Errors
///
/// Returns [`Error::PacketTooShort`] if `data` has fewer than 5 bytes.
///
/// Returns [`Error::UnexpectedPacketType`] if the first byte is not `0x02`.
///
/// Returns [`Error::MalformedAclPacket`] if `Data_Total_Length` exceeds the
/// bytes actually present — mirrors [`decode_event`]'s `param_length` bound,
/// so a truncated ACL packet is rejected rather than silently short-read.
pub(crate) fn decode_acl_data(data: &[u8]) -> Result<AclDataPacket<'_>> {
    if data.len() < MIN_ACL_PACKET {
        return Err(Error::PacketTooShort {
            min: MIN_ACL_PACKET,
            actual: data.len(),
        });
    }

    let h4_type = data.first().copied().unwrap_or_default();
    if h4_type != H4_ACL_TYPE {
        return Err(Error::UnexpectedPacketType {
            expected: H4_ACL_TYPE,
            actual: h4_type,
        });
    }

    let mut cur = Cursor::new(data.get(1..).unwrap_or(&[]));
    let handle_and_flags = cur.read_u16_le().ok_or(Error::MalformedAclPacket {
        detail: "ACL: missing Connection_Handle/PB/BC field",
    })?;
    let handle = handle_and_flags & 0x0FFF;
    // WHY: PB_Flag occupies bits [13:12] and BC_Flag bits [15:14] of the
    // combined field (Table 5.1) — both above the 12-bit handle. Each is
    // masked to 2 bits before the u16->u8 narrowing, so the cast never
    // truncates a live bit (workspace lint cast_possible_truncation = allow).
    let pb_flag = PbFlag::from_bits(((handle_and_flags >> 12) & 0b11) as u8);
    let bc_flag = ((handle_and_flags >> 14) & 0b11) as u8;

    let data_total_length = cur.read_u16_le().ok_or(Error::MalformedAclPacket {
        detail: "ACL: missing Data_Total_Length field",
    })?;
    // WHY the slice comes from `data` and not from `cur`: the returned packet
    // borrows for the caller's lifetime, and `cur` is local — reading the
    // payload through the cursor would return a reference into a value dropped
    // at the end of this function. The header is fixed-width (H4 type, then the
    // handle/flags and length u16s), so the payload offset is known without it.
    let payload_start = 1 + 2 + 2;
    let payload = data
        .get(payload_start..)
        .and_then(|rest| rest.get(..usize::from(data_total_length)))
        .ok_or(Error::MalformedAclPacket {
            detail: "ACL: Data_Total_Length exceeds available bytes",
        })?;

    Ok(AclDataPacket {
        handle,
        pb_flag,
        bc_flag,
        data: payload,
    })
}

/// Encode an H4-framed HCI ACL Data packet (H4 type `0x02`) — the inverse
/// of [`decode_acl_data`]: `[0x02, handle_lo, handle_hi|pb|bc, data_len_lo,
/// data_len_hi, data...]`.
///
/// `handle` is masked to its 12 protocol bits and `bc_flag` to its 2 (Vol
/// 4 Part E §5.4.2) — an out-of-range caller value is truncated rather
/// than panicking, matching [`decode_acl_data`]'s own tolerance for the
/// field's bit width.
pub(crate) fn encode_acl_data(handle: u16, pb_flag: PbFlag, bc_flag: u8, data: &[u8]) -> Vec<u8> {
    let handle_and_flags = (handle & 0x0FFF)
        | (u16::from(pb_flag.to_bits()) << 12)
        | (u16::from(bc_flag & 0b11) << 14);
    let data_len = u16::try_from(data.len()).unwrap_or(u16::MAX);
    let mut packet = Vec::with_capacity(5 + data.len());
    packet.push(H4_ACL_TYPE);
    packet.extend_from_slice(&handle_and_flags.to_le_bytes());
    packet.extend_from_slice(&data_len.to_le_bytes());
    packet.extend_from_slice(data);
    packet
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
    fn decode_command_complete_ignores_trailing_bytes_past_param_length() -> Result<()> {
        // H4=0x04, evt=0x0E, param_len=4 (num_packets + opcode + 1-byte status),
        // followed by 2 extra trailing bytes that are not part of this event and
        // must not leak into return_params.
        let data = [0x04, 0x0E, 0x04, 0x01, 0x03, 0x0C, 0x00, 0xAA, 0xBB];
        let evt = decode_event(&data)?;
        let HciEvent::CommandComplete { return_params, .. } = evt else {
            unreachable!("expected CommandComplete variant");
        };
        assert_eq!(
            return_params,
            vec![0x00],
            "return_params must be bounded to the declared param_length, excluding trailing bytes"
        );
        Ok(())
    }

    #[test]
    fn decode_rejects_param_length_exceeding_available_bytes() {
        // H4=0x04, evt=0x0E, param_len declares 10 bytes but only 4 follow.
        let data = [0x04, 0x0E, 0x0A, 0x01, 0x03, 0x0C, 0x00];
        let result = decode_event(&data);
        assert!(
            matches!(result, Err(Error::MalformedEvent { .. })),
            "a param_length exceeding the actual buffer must be rejected, not silently truncated"
        );
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

    // ── decode_acl_data (#635) ──

    #[test]
    fn decode_acl_data_extracts_handle_flags_and_payload() -> Result<()> {
        // handle=0x0040, PB=0b10 (FirstFlushable), BC=0b00 -> handle_and_flags
        // = 0x0040 | (0b10 << 12) = 0x2040, LE bytes [0x40, 0x20].
        // data_total_length=3, payload=[0xAA, 0xBB, 0xCC].
        let data = [0x02, 0x40, 0x20, 0x03, 0x00, 0xAA, 0xBB, 0xCC];
        let pkt = decode_acl_data(&data)?;
        assert_eq!(pkt.handle, 0x0040, "handle should be the low 12 bits");
        assert_eq!(
            pkt.pb_flag,
            PbFlag::FirstFlushable,
            "PB bits 0b10 should decode to FirstFlushable"
        );
        assert_eq!(pkt.bc_flag, 0b00, "BC bits should be 0b00 (point-to-point)");
        assert_eq!(
            pkt.data,
            &[0xAA, 0xBB, 0xCC],
            "payload should match Data field"
        );
        Ok(())
    }

    #[test]
    fn decode_acl_data_decodes_continuation_pb_flag() -> Result<()> {
        // handle=0x0001, PB=0b01 (Continuation) -> 0x0001 | (0b01 << 12) = 0x1001.
        let data = [0x02, 0x01, 0x10, 0x01, 0x00, 0xFF];
        let pkt = decode_acl_data(&data)?;
        assert_eq!(
            pkt.pb_flag,
            PbFlag::Continuation,
            "PB bits 0b01 should decode to Continuation"
        );
        Ok(())
    }

    #[test]
    fn decode_acl_data_masks_handle_to_twelve_bits() -> Result<()> {
        // handle field bits set beyond 12 must not leak into the handle:
        // handle_and_flags = 0xFFFF -> handle = 0x0FFF, PB=0b11, BC=0b11.
        let data = [0x02, 0xFF, 0xFF, 0x00, 0x00];
        let pkt = decode_acl_data(&data)?;
        assert_eq!(pkt.handle, 0x0FFF, "handle must be masked to 12 bits");
        assert_eq!(pkt.pb_flag, PbFlag::CompleteFlushable, "PB bits 0b11");
        assert_eq!(pkt.bc_flag, 0b11, "BC bits 0b11");
        Ok(())
    }

    #[test]
    fn decode_acl_data_rejects_wrong_h4_type() {
        // 0x04 = Event, not ACL.
        let data = [0x04, 0x40, 0x00, 0x01, 0x00, 0xAA];
        let result = decode_acl_data(&data);
        assert!(
            matches!(
                result,
                Err(Error::UnexpectedPacketType {
                    expected: H4_ACL_TYPE,
                    ..
                })
            ),
            "non-ACL H4 type should produce UnexpectedPacketType error"
        );
    }

    #[test]
    fn decode_acl_data_rejects_packet_too_short() {
        let data = [0x02, 0x40, 0x00, 0x00]; // only 4 bytes, need 5
        let result = decode_acl_data(&data);
        assert!(
            matches!(
                result,
                Err(Error::PacketTooShort {
                    min: MIN_ACL_PACKET,
                    actual: 4
                })
            ),
            "a 4-byte ACL packet should be rejected as too short"
        );
    }

    #[test]
    fn decode_acl_data_rejects_data_total_length_exceeding_available_bytes() {
        // data_total_length declares 10 bytes but only 2 follow.
        let data = [0x02, 0x40, 0x00, 0x0A, 0x00, 0xAA, 0xBB];
        let result = decode_acl_data(&data);
        assert!(
            matches!(result, Err(Error::MalformedAclPacket { .. })),
            "Data_Total_Length exceeding the actual buffer must be rejected, not silently truncated"
        );
    }

    #[test]
    fn decode_acl_data_accepts_empty_payload() -> Result<()> {
        // data_total_length=0 is a valid (if unusual) ACL packet.
        let data = [0x02, 0x40, 0x00, 0x00, 0x00];
        let pkt = decode_acl_data(&data)?;
        assert!(
            pkt.data.is_empty(),
            "zero-length Data field should decode to an empty slice"
        );
        Ok(())
    }

    // ── PbFlag::from_bits / to_bits ──

    #[test]
    fn pb_flag_from_bits_covers_all_four_values() {
        assert_eq!(PbFlag::from_bits(0b00), PbFlag::FirstNonFlushable);
        assert_eq!(PbFlag::from_bits(0b01), PbFlag::Continuation);
        assert_eq!(PbFlag::from_bits(0b10), PbFlag::FirstFlushable);
        assert_eq!(PbFlag::from_bits(0b11), PbFlag::CompleteFlushable);
    }

    #[test]
    fn pb_flag_to_bits_is_the_inverse_of_from_bits() {
        for bits in 0b00..=0b11 {
            assert_eq!(
                PbFlag::from_bits(bits).to_bits(),
                bits,
                "to_bits must invert from_bits for every two-bit value"
            );
        }
    }

    // ── encode_acl_data (#635/#455 stage 3 composition) ──

    #[test]
    fn encode_acl_data_round_trips_through_decode() -> Result<()> {
        let encoded = encode_acl_data(0x0040, PbFlag::FirstFlushable, 0b00, &[0xAA, 0xBB, 0xCC]);
        let pkt = decode_acl_data(&encoded)?;
        assert_eq!(pkt.handle, 0x0040, "handle must round-trip");
        assert_eq!(
            pkt.pb_flag,
            PbFlag::FirstFlushable,
            "pb_flag must round-trip"
        );
        assert_eq!(pkt.bc_flag, 0b00, "bc_flag must round-trip");
        assert_eq!(pkt.data, &[0xAA, 0xBB, 0xCC], "payload must round-trip");
        Ok(())
    }

    #[test]
    fn encode_acl_data_masks_handle_and_bc_flag_to_their_protocol_widths() -> Result<()> {
        let encoded = encode_acl_data(0xFFFF, PbFlag::Continuation, 0xFF, &[]);
        let pkt = decode_acl_data(&encoded)?;
        assert_eq!(pkt.handle, 0x0FFF, "handle must be masked to 12 bits");
        assert_eq!(pkt.bc_flag, 0b11, "bc_flag must be masked to 2 bits");
        Ok(())
    }
}
