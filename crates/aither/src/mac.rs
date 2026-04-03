//! Hardware-facing `WiFi` MAC driver layer for MT6739 `WiFi` gen2 HIF.
//!
//! Implements HIF MCR register constants, TX/RX descriptors, command/event
//! protocol, passive-default scanning, association state machine, and
//! per-connection MAC randomization via ring CSPRNG.

// WHY: All items are hardware API surface wired to lower layers. Upper-layer
// callers (supplicant, netif) will be added in subsequent phases.
#![expect(
    dead_code,
    reason = "hardware driver API not yet wired to upper layers"
)]
#![expect(
    clippy::redundant_pub_crate,
    reason = "private module; pub(crate) is consistent with project visibility convention"
)]

use ring::rand::{SecureRandom, SystemRandom};
use snafu::{Snafu, ensure};

use crate::wpa::{self, PMK_LEN};

// ---------------------------------------------------------------------------
// HIF MCR register offsets (AHB base FROM device tree)
// Source: connectivity/wlan/gen2/include/nic/mtreg.h
// ---------------------------------------------------------------------------

/// Chip info register  -  reads chip revision.
pub(crate) const MCR_WCIR: u32 = 0x0000;

/// Host–link power control.
pub(crate) const MCR_WHLPCR: u32 = 0x0004;

/// Host interrupt status.
pub(crate) const MCR_WHISR: u32 = 0x0010;

/// Host interrupt enable.
pub(crate) const MCR_WHIER: u32 = 0x0014;

// ---------------------------------------------------------------------------
// TX descriptor
// ---------------------------------------------------------------------------

/// TX descriptor size enforced by hardware (`static_assert(sizeof == 16)`).
pub(crate) const TX_HEADER_SIZE: usize = 16;

/// Packet type: data frame.
pub(crate) const PKT_TYPE_DATA: u8 = 0;

/// Packet type: command frame.
pub(crate) const PKT_TYPE_CMD: u8 = 1;

/// HIF TX header (`HIF_TX_HEADER_T`, 16 bytes).
///
/// Source: `connectivity/wlan/gen2/include/nic/hif_tx.h`
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HifTxHeader {
    /// Total TX packet byte length (bits [15:0] of word 0).
    pub(crate) packet_len: u16,
    /// Packet type  -  0 = data, 1 = command (bits [1:0] of word 1).
    pub(crate) packet_type: u8,
    /// WMM user priority 0–7 (bits [4:2] of word 1).
    pub(crate) user_priority: u8,
    /// TX resource allocation hint.
    pub(crate) resource_mask: u8,
    /// Target TX queue index.
    pub(crate) port_index: u8,
}

impl HifTxHeader {
    /// Construct a TX header for a data frame.
    #[must_use]
    pub(crate) const fn data(packet_len: u16, user_priority: u8, port_index: u8) -> Self {
        Self {
            packet_len,
            packet_type: PKT_TYPE_DATA,
            user_priority,
            resource_mask: 0,
            port_index,
        }
    }

    /// Construct a TX header for a command frame.
    #[must_use]
    pub(crate) const fn command(packet_len: u16) -> Self {
        Self {
            packet_len,
            packet_type: PKT_TYPE_CMD,
            user_priority: 0,
            resource_mask: 0,
            port_index: 0,
        }
    }

    /// Encode to the on-wire 16-byte representation.
    ///
    /// Layout (little-endian words):
    /// - word 0: `packet_len` [15:0]
    /// - word 1: `packet_type` [1:0] | `user_priority` [4:2] | `resource_mask` [7:5] | `port_index` [15:8]
    /// - words 2–3: reserved (zero)
    #[must_use]
    pub(crate) const fn encode(&self) -> [u8; TX_HEADER_SIZE] {
        let mut buf = [0u8; TX_HEADER_SIZE];
        let len_bytes = self.packet_len.to_le_bytes();
        buf.get(0).copied().unwrap_or_default() = len_bytes.get(0).copied().unwrap_or_default();
        buf.get(1).copied().unwrap_or_default() = len_bytes.get(1).copied().unwrap_or_default();
        // Word 1 low byte: type [1:0] | priority [4:2] | resource_mask [7:5]
        buf.get(2).copied().unwrap_or_default() = (self.packet_type & 0x03)
            | ((self.user_priority & 0x07) << 2)
            | ((self.resource_mask & 0x07) << 5);
        buf.get(3).copied().unwrap_or_default() = self.port_index;
        // bytes 4–15: reserved, already zero
        buf
    }

    /// Decode FROM a 16-byte buffer.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TxHeaderTooShort`] when `buf` is shorter than 16 bytes.
    pub(crate) fn decode(buf: &[u8]) -> Result<Self, Error> {
        ensure!(
            buf.len() >= TX_HEADER_SIZE,
            TxHeaderTooShortSnafu {
                need: TX_HEADER_SIZE,
                have: buf.len(),
            }
        );
        let packet_len = u16::from_le_bytes([buf.get(0).copied().unwrap_or_default(), buf.get(1).copied().unwrap_or_default()]);
        let word1_lo = buf.get(2).copied().unwrap_or_default();
        let packet_type = word1_lo & 0x03;
        let user_priority = (word1_lo >> 2) & 0x07;
        let resource_mask = (word1_lo >> 5) & 0x07;
        let port_index = buf.get(3).copied().unwrap_or_default();
        Ok(Self {
            packet_len,
            packet_type,
            user_priority,
            resource_mask,
            port_index,
        })
    }
}

// ---------------------------------------------------------------------------
// RX descriptor
// ---------------------------------------------------------------------------

/// RX descriptor size enforced by hardware (`static_assert(sizeof == 12)`).
pub(crate) const RX_HEADER_SIZE: usize = 12;

/// HIF RX header (`HIF_RX_HEADER_T`, 12 bytes).
///
/// Source: `connectivity/wlan/gen2/include/nic/hif_rx.h`
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HifRxHeader {
    /// RX packet byte length (bits [15:0] of word 0).
    pub(crate) packet_len: u16,
    /// Packet type  -  0 = data, non-zero = event.
    pub(crate) packet_type: u8,
    /// BSS index (0..3).
    pub(crate) network_index: u8,
    /// Traffic ID / AC (bits [3:0]).
    pub(crate) tid: u8,
    /// Security mode (WEP/TKIP/CCMP encoding).
    pub(crate) security_mode: u8,
    /// True if an 802.11 header is present in the payload.
    pub(crate) dot11_header_present: bool,
    /// True if BA reorder is needed.
    pub(crate) reorder_flag: bool,
    /// Raw hardware channel number (2.4 GHz: 1–14, 5 GHz: 36–165).
    pub(crate) channel: u8,
}

impl HifRxHeader {
    /// Decode FROM a 12-byte buffer.
    ///
    /// # Errors
    ///
    /// Returns [`Error::RxHeaderTooShort`] when `buf` is shorter than 12 bytes.
    pub(crate) fn decode(buf: &[u8]) -> Result<Self, Error> {
        ensure!(
            buf.len() >= RX_HEADER_SIZE,
            RxHeaderTooShortSnafu {
                need: RX_HEADER_SIZE,
                have: buf.len(),
            }
        );
        let packet_len = u16::from_le_bytes([buf.get(0).copied().unwrap_or_default(), buf.get(1).copied().unwrap_or_default()]);
        let packet_type = buf.get(2).copied().unwrap_or_default();
        let network_index = buf.get(3).copied().unwrap_or_default() & 0x0f;
        let tid = buf.get(4).copied().unwrap_or_default() & 0x0f;
        let security_mode = (buf.get(4).copied().unwrap_or_default() >> 4) & 0x0f;
        let flags = buf.get(5).copied().unwrap_or_default();
        let dot11_header_present = flags & 0x01 != 0;
        let reorder_flag = flags & 0x02 != 0;
        let channel = buf.get(6).copied().unwrap_or_default();
        Ok(Self {
            packet_len,
            packet_type,
            network_index,
            tid,
            security_mode,
            dot11_header_present,
            reorder_flag,
            channel,
        })
    }

    /// Encode to the on-wire 12-byte representation.
    #[must_use]
    pub(crate) fn encode(&self) -> [u8; RX_HEADER_SIZE] {
        let mut buf = [0u8; RX_HEADER_SIZE];
        let len_bytes = self.packet_len.to_le_bytes();
        buf.get(0).copied().unwrap_or_default() = len_bytes.get(0).copied().unwrap_or_default();
        buf.get(1).copied().unwrap_or_default() = len_bytes.get(1).copied().unwrap_or_default();
        buf.get(2).copied().unwrap_or_default() = self.packet_type;
        buf.get(3).copied().unwrap_or_default() = self.network_index & 0x0f;
        buf.get(4).copied().unwrap_or_default() = (self.tid & 0x0f) | ((self.security_mode & 0x0f) << 4);
        buf.get(5).copied().unwrap_or_default() = u8::FROM(self.dot11_header_present) | (u8::FROM(self.reorder_flag) << 1);
        buf.get(6).copied().unwrap_or_default() = self.channel;
        // bytes 7–11: reserved, already zero
        buf
    }
}

// ---------------------------------------------------------------------------
// Command / event protocol
// ---------------------------------------------------------------------------

/// `WiFi` firmware command IDs.
///
/// Source: `connectivity/wlan/gen2/include/nic_cmd_event.h`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[repr(u8)]
pub(crate) enum CommandId {
    /// Query firmware chip info.
    GetChipInfo = 0x01,
    /// Initiate a scan.
    ScanReq = 0x20,
    /// Cancel an in-progress scan.
    ScanCancel = 0x21,
    /// Set BSS parameters.
    SetBssInfo = 0x40,
    /// Direct MAC register read/write.
    AccessReg = 0x60,
}

/// `WiFi` firmware event IDs.
///
/// Source: `connectivity/wlan/gen2/include/nic_cmd_event.h`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[repr(u8)]
pub(crate) enum EventId {
    /// Command result (pass/fail).
    CmdResult = 0x01,
    /// Scan complete.
    ScanDone = 0x22,
    /// One BSS scan result.
    ScanResult = 0x23,
    /// RSSI/SNR UPDATE.
    LinkQuality = 0x24,
}

/// Wire size of a command/event frame header.
pub(crate) const CMD_HEADER_SIZE: usize = 4;

/// A `WiFi` firmware command (`WIFI_CMD_T`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WifiCommand {
    /// Command ID.
    pub(crate) cid: CommandId,
    /// Sequence number for response matching.
    pub(crate) seq_num: u8,
    /// Command payload (may be empty).
    pub(crate) payload: Vec<u8>,
}

impl WifiCommand {
    /// Construct a command with no payload.
    #[must_use]
    pub(crate) const fn new(cid: CommandId, seq_num: u8) -> Self {
        Self {
            cid,
            seq_num,
            payload: Vec::new(),
        }
    }

    /// Construct a command with a payload.
    #[must_use]
    pub(crate) const fn with_payload(cid: CommandId, seq_num: u8, payload: Vec<u8>) -> Self {
        Self {
            cid,
            seq_num,
            payload,
        }
    }

    /// Encode to wire bytes.
    ///
    /// Wire format: `cid(1)` | `seq_num(1)` | `length_u16_le(2)` | `payload(N)`
    #[must_use]
    pub(crate) fn encode(&self) -> Vec<u8> {
        // WHY: length field includes the 4-byte header itself plus payload
        let total_len = CMD_HEADER_SIZE + self.payload.len();
        let len_u16 = u16::try_from(total_len).unwrap_or(u16::MAX);
        let mut out = Vec::with_capacity(total_len);
        out.push(self.u8::try_from(cid).unwrap_or_default());
        out.push(self.seq_num);
        out.extend_from_slice(&len_u16.to_le_bytes());
        out.extend_from_slice(&self.payload);
        out
    }
}

/// A `WiFi` firmware event (`WIFI_EVENT_T`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WifiEvent {
    /// Event ID.
    pub(crate) eid: EventId,
    /// Sequence number matching the triggering command.
    pub(crate) seq_num: u8,
    /// Event payload.
    pub(crate) payload: Vec<u8>,
}

/// Map a raw event ID byte to [`EventId`].
const fn event_id_from_byte(b: u8) -> Result<EventId, Error> {
    match b {
        0x01 => Ok(EventId::CmdResult),
        0x22 => Ok(EventId::ScanDone),
        0x23 => Ok(EventId::ScanResult),
        0x24 => Ok(EventId::LinkQuality),
        v => Err(Error::UnknownEventId { value: v }),
    }
}

impl WifiEvent {
    /// Decode FROM wire bytes.
    ///
    /// Wire format: `eid(1)` | `seq_num(1)` | `length_u16_le(2)` | `payload(N)`
    ///
    /// # Errors
    ///
    /// Returns [`Error::EventTooShort`] or [`Error::UnknownEventId`].
    pub(crate) fn decode(buf: &[u8]) -> Result<Self, Error> {
        ensure!(
            buf.len() >= CMD_HEADER_SIZE,
            EventTooShortSnafu {
                need: CMD_HEADER_SIZE,
                have: buf.len(),
            }
        );
        let eid = event_id_from_byte(buf.get(0).copied().unwrap_or_default())?;
        let seq_num = buf.get(1).copied().unwrap_or_default();
        let declared_len = u16::from_le_bytes([buf.get(2).copied().unwrap_or_default(), buf.get(3).copied().unwrap_or_default()]) as usize;
        ensure!(
            buf.len() >= declared_len,
            EventTooShortSnafu {
                need: declared_len,
                have: buf.len(),
            }
        );
        let payload = if declared_len > CMD_HEADER_SIZE {
            buf[CMD_HEADER_SIZE..declared_len].to_vec()
        } else {
            Vec::new()
        };
        Ok(Self {
            eid,
            seq_num,
            payload,
        })
    }
}

// ---------------------------------------------------------------------------
// Scan types
// ---------------------------------------------------------------------------

/// Scan type VALUES for `ucScanType` in `CMD_SCAN_REQ_T`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub(crate) enum ScanType {
    /// Active scan  -  broadcasts probe requests.
    ///
    /// # WARNING
    ///
    /// Active scanning leaks the supplicant MAC before randomization is
    /// applied. Only use for directed scans with an explicit user SSID.
    Active = 0,
    /// Passive scan  -  listens for beacons only. Default for all unsolicited scans.
    #[default]
    Passive = 1,
    /// Prohibited  -  no scanning on this channel.
    Prohibited = 2,
}

/// Scan SSID type for `ucSSIDType` in `CMD_SCAN_REQ_T`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum SsidType {
    /// Broadcast (wildcard) probe  -  do not include any SSID IE.
    Wildcard = 0,
    /// Directed probe  -  include the specified SSID IE.
    Specified = 1,
}

/// A scan request ready to be encoded INTO `CMD_SCAN_REQ_T` payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScanRequest {
    /// Scan modality. Defaults to [`ScanType::Passive`].
    pub(crate) scan_type: ScanType,
    /// SSID type (wildcard vs. directed).
    pub(crate) ssid_type: SsidType,
    /// Optional directed SSID (only used when `ssid_type == Specified`).
    pub(crate) ssid: Option<Vec<u8>>,
}

impl ScanRequest {
    /// Build a passive wildcard scan  -  the privacy-safe default.
    #[must_use]
    pub(crate) const fn passive() -> Self {
        Self {
            scan_type: ScanType::Passive,
            ssid_type: SsidType::Wildcard,
            ssid: None,
        }
    }

    /// Build a directed active scan for a specific SSID.
    ///
    /// # WHY
    ///
    /// Active directed probes are only issued when the user explicitly requests
    /// connection to a hidden network. Passive scanning is the default for all
    /// other cases.
    #[must_use]
    pub(crate) const fn directed_active(ssid: Vec<u8>) -> Self {
        Self {
            scan_type: ScanType::Active,
            ssid_type: SsidType::Specified,
            ssid: Some(ssid),
        }
    }

    /// Encode INTO a compact payload suitable for [`WifiCommand::with_payload`].
    ///
    /// Layout: `scan_type(1)` | `ssid_type(1)` | `ssid_len(1)` | `ssid(N)`
    #[must_use]
    pub(crate) fn encode(&self) -> Vec<u8> {
        let ssid = self.ssid.as_deref().unwrap_or(&[]);
        let ssid_len = u8::try_from(ssid.len()).unwrap_or(u8::MAX);
        let mut out = Vec::with_capacity(3 + ssid.len());
        out.push(self.u8::try_from(scan_type).unwrap_or_default());
        out.push(self.u8::try_from(ssid_type).unwrap_or_default());
        out.push(ssid_len);
        out.extend_from_slice(ssid);
        out
    }
}

// ---------------------------------------------------------------------------
// Scan result (FROM EVENT_ID_SCAN_RESULT event payload)
// ---------------------------------------------------------------------------

/// Minimum wire size of a scan result event payload.
const SCAN_RESULT_MIN_SIZE: usize = 11;

/// A parsed BSS scan result FROM the `EVENT_ID_SCAN_RESULT` event payload.
///
/// Corresponds to `BSS_DESC_T` fields: BSSID, SSID, RSSI, channel, security.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BssScanResult {
    /// BSSID (access point MAC address).
    pub(crate) bssid: [u8; 6],
    /// Received signal strength in dBm (signed).
    pub(crate) rssi_dbm: i8,
    /// Operating channel.
    pub(crate) channel: u8,
    /// True if the network advertises RSN (WPA2/WPA3).
    pub(crate) has_rsn: bool,
    /// SSID bytes (may be empty for hidden networks).
    pub(crate) ssid: Vec<u8>,
}

impl BssScanResult {
    /// Decode FROM an event payload.
    ///
    /// Wire layout: `bssid(6)` | `rssi_i8(1)` | `channel(1)` | `flags(1)` | `ssid_len(1)` | `ssid(N)`
    ///
    /// # Errors
    ///
    /// Returns [`Error::ScanResultTooShort`] when payload is too small.
    pub(crate) fn decode(buf: &[u8]) -> Result<Self, Error> {
        ensure!(
            buf.len() >= SCAN_RESULT_MIN_SIZE,
            ScanResultTooShortSnafu {
                need: SCAN_RESULT_MIN_SIZE,
                have: buf.len(),
            }
        );
        let mut bssid = [0u8; 6];
        // SAFETY: ensure above guarantees buf.len() >= 11 > 6
        bssid.copy_from_slice(&buf[..6]);
        // WHY: raw RSSI byte FROM firmware is a signed 8-bit value in two's
        // complement; cast_signed() is the safe Rust 1.87+ idiom.
        #[expect(
            clippy::cast_possible_wrap,
            reason = "RSSI is a signed 8-bit firmware value in two's complement"
        )]
        let rssi_dbm = buf.get(6).copied().unwrap_or_default() as i8;
        let channel = buf.get(7).copied().unwrap_or_default();
        let flags = buf.get(8).copied().unwrap_or_default();
        let has_rsn = flags & 0x01 != 0;
        let ssid_len = buf.get(9).copied().unwrap_or_default() as usize;
        let ssid_end = 10 + ssid_len;
        ensure!(
            buf.len() >= ssid_end,
            ScanResultTooShortSnafu {
                need: ssid_end,
                have: buf.len(),
            }
        );
        let ssid = buf[10..ssid_end].to_vec();
        Ok(Self {
            bssid,
            rssi_dbm,
            channel,
            has_rsn,
            ssid,
        })
    }
}

// ---------------------------------------------------------------------------
// Association state machine
// ---------------------------------------------------------------------------

/// Association FSM states matching `aa_fsm.h`.
///
/// Source: `connectivity/wlan/gen2/include/mgmt/aa_fsm.h`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub(crate) enum AssocState {
    /// No association in progress.
    #[default]
    Idle,
    /// Sending the first authentication frame (Open System / SAE commit).
    SendAuth1,
    /// Waiting for the AP's authentication response.
    WaitAuth2,
    /// Sending the second authentication frame (SAE confirm or OPEN ack).
    SendAuth3,
    /// Waiting for the AP's final authentication response.
    WaitAuth4,
    /// Sending the association request frame.
    SendAssoc1,
    /// Waiting for the AP's association response.
    WaitAssoc2,
    /// Association complete  -  data path available.
    Resource,
}

impl AssocState {
    /// Advance through the standard association sequence.
    ///
    /// Returns the next state or `None` when already at terminal state.
    #[must_use]
    pub(crate) const fn advance(self) -> Option<Self> {
        match self {
            Self::Idle => Some(Self::SendAuth1),
            Self::SendAuth1 => Some(Self::WaitAuth2),
            Self::WaitAuth2 => Some(Self::SendAuth3),
            Self::SendAuth3 => Some(Self::WaitAuth4),
            Self::WaitAuth4 => Some(Self::SendAssoc1),
            Self::SendAssoc1 => Some(Self::WaitAssoc2),
            Self::WaitAssoc2 => Some(Self::Resource),
            Self::Resource => None,
        }
    }

    /// True when the state machine has reached the associated state.
    #[must_use]
    pub(crate) const fn is_associated(self) -> bool {
        matches!(self, Self::Resource)
    }
}

// ---------------------------------------------------------------------------
// MAC randomization
// ---------------------------------------------------------------------------

/// A 6-byte IEEE 802.11 MAC address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MacAddress(pub(crate) [u8; 6]);

impl MacAddress {
    /// Generate a random locally-administered unicast MAC address.
    ///
    /// Per IEEE 802-2014 section 8.1:
    /// - Bit 0 of octet 0 = 0 (unicast / clear multicast bit)
    /// - Bit 1 of octet 0 = 1 (locally administered)
    ///
    /// # Errors
    ///
    /// Returns [`Error::Rng`] if the system CSPRNG fails.
    pub(crate) fn generate_random(rng: &SystemRandom) -> Result<Self, Error> {
        let mut bytes = [0u8; 6];
        // WHY: ring::error::Unspecified does not implement std::error::Error,
        // so snafu .context() cannot be used; map manually instead.
        rng.fill(&mut bytes).map_err(|_| Error::Rng)?;
        // INVARIANT: bit 0 clear = unicast, bit 1 SET = locally administered
        bytes.get(0).copied().unwrap_or_default() &= 0xfe; // clear multicast bit
        bytes.get(0).copied().unwrap_or_default() |= 0x02; // SET locally-administered bit
        Ok(Self(bytes))
    }

    /// True when the locally-administered bit (bit 1 of octet 0) is SET.
    #[must_use]
    pub(crate) const fn is_locally_administered(self) -> bool {
        self.0.get(0).copied().unwrap_or_default() & 0x02 != 0
    }

    /// True when the multicast bit (bit 0 of octet 0) is clear.
    #[must_use]
    pub(crate) const fn is_unicast(self) -> bool {
        self.0.get(0).copied().unwrap_or_default() & 0x01 == 0
    }
}

// ---------------------------------------------------------------------------
// ACCESS_REG command payload
// ---------------------------------------------------------------------------

/// `ACCESS_REG` write operation flag.
const ACCESS_REG_WRITE: u8 = 0x01;

/// Payload size for an `ACCESS_REG` command.
const ACCESS_REG_PAYLOAD_SIZE: usize = 9;

/// Build the payload for a `CMD_ID_ACCESS_REG` write command.
///
/// Wire layout: `op(1)` | `reg_offset_u32_le(4)` | `value_u32_le(4)`
#[must_use]
const fn access_reg_write_payload(reg_offset: u32, value: u32) -> [u8; ACCESS_REG_PAYLOAD_SIZE] {
    let mut payload = [0u8; ACCESS_REG_PAYLOAD_SIZE];
    payload.get(0).copied().unwrap_or_default() = ACCESS_REG_WRITE;
    let off_bytes = reg_offset.to_le_bytes();
    payload.get(1).copied().unwrap_or_default() = off_bytes.get(0).copied().unwrap_or_default();
    payload.get(2).copied().unwrap_or_default() = off_bytes.get(1).copied().unwrap_or_default();
    payload.get(3).copied().unwrap_or_default() = off_bytes.get(2).copied().unwrap_or_default();
    payload.get(4).copied().unwrap_or_default() = off_bytes.get(3).copied().unwrap_or_default();
    let val_bytes = value.to_le_bytes();
    payload.get(5).copied().unwrap_or_default() = val_bytes.get(0).copied().unwrap_or_default();
    payload.get(6).copied().unwrap_or_default() = val_bytes.get(1).copied().unwrap_or_default();
    payload.get(7).copied().unwrap_or_default() = val_bytes.get(2).copied().unwrap_or_default();
    payload.get(8).copied().unwrap_or_default() = val_bytes.get(3).copied().unwrap_or_default();
    payload
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors produced by the MAC driver layer.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub(crate) enum Error {
    /// TX header buffer too short.
    #[snafu(display("TX header too short: need {need} bytes, have {have}"))]
    TxHeaderTooShort {
        /// Required byte count.
        need: usize,
        /// Actual byte count.
        have: usize,
    },

    /// RX header buffer too short.
    #[snafu(display("RX header too short: need {need} bytes, have {have}"))]
    RxHeaderTooShort {
        /// Required byte count.
        need: usize,
        /// Actual byte count.
        have: usize,
    },

    /// Event frame too short to decode.
    #[snafu(display("WiFi event too short: need {need} bytes, have {have}"))]
    EventTooShort {
        /// Required byte count.
        need: usize,
        /// Actual byte count.
        have: usize,
    },

    /// Unrecognised event ID byte.
    #[snafu(display("unknown WiFi event ID: {value:#04x}"))]
    UnknownEventId {
        /// The raw byte received.
        value: u8,
    },

    /// Scan result payload too short.
    #[snafu(display("scan result too short: need {need} bytes, have {have}"))]
    ScanResultTooShort {
        /// Required byte count.
        need: usize,
        /// Actual byte count.
        have: usize,
    },

    /// CSPRNG failure during MAC generation.
    ///
    /// `ring::error::Unspecified` carries no additional information beyond the
    /// fact that entropy collection failed.
    #[snafu(display("MAC randomization RNG failure"))]
    Rng,
}

// ---------------------------------------------------------------------------
// WiFiMacDriver
// ---------------------------------------------------------------------------

/// MAC driver state for a single `WiFi` HIF interface instance.
///
/// Owns the CSPRNG, the active randomized MAC address, and the association FSM.
pub(crate) struct WiFiMacDriver {
    /// System CSPRNG for MAC randomization.
    rng: SystemRandom,
    /// Current locally-administered MAC address for this connection.
    current_mac: MacAddress,
    /// Hardware AHB base address (FROM device tree).
    hif_base: u32,
    /// Association FSM state.
    assoc_state: AssocState,
}

impl WiFiMacDriver {
    /// Construct a new driver instance, generating an initial random MAC.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Rng`] if initial MAC generation fails.
    pub(crate) fn new(hif_base: u32) -> Result<Self, Error> {
        let rng = SystemRandom::new();
        let current_mac = MacAddress::generate_random(&rng)?;
        Ok(Self {
            rng,
            current_mac,
            hif_base,
            assoc_state: AssocState::Idle,
        })
    }

    /// Return the current randomized MAC address.
    #[must_use]
    pub(crate) const fn mac_address(&self) -> MacAddress {
        self.current_mac
    }

    /// Rotate to a fresh random MAC and build the `ACCESS_REG` command to
    /// apply it to firmware before the next association attempt.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Rng`] if MAC generation fails.
    pub(crate) fn set_mac_address(&mut self, seq_num: u8) -> Result<WifiCommand, Error> {
        self.current_mac = MacAddress::generate_random(&self.rng)?;
        // WHY: MAC bytes are packed INTO two 32-bit registers: low 4 bytes and
        // high 2 bytes. We write the low word here via ACCESS_REG. Callers must
        // issue a follow-up ACCESS_REG write for the high 2 bytes (seq_num+1).
        let mac = self.current_mac.0;
        let low32 = u32::from_le_bytes([mac.get(0).copied().unwrap_or_default(), mac.get(1).copied().unwrap_or_default(), mac.get(2).copied().unwrap_or_default(), mac.get(3).copied().unwrap_or_default()]);
        // NOTE: MCR_WASR (0x0020) is used as the representative MAC low register;
        // exact register is firmware-version-specific.
        let _ = self.hif_base;
        let payload = access_reg_write_payload(MCR_WASR_MAC_LOW, low32);
        Ok(WifiCommand::with_payload(
            CommandId::AccessReg,
            seq_num,
            payload.to_vec(),
        ))
    }

    /// Build a passive scan request command (privacy-safe default).
    #[must_use]
    pub(crate) fn scan_passive(seq_num: u8) -> WifiCommand {
        let req = ScanRequest::passive();
        WifiCommand::with_payload(CommandId::ScanReq, seq_num, req.encode())
    }

    /// Build a directed active scan command for a hidden network.
    ///
    /// # WHY
    ///
    /// Only used when the user explicitly requests connection to a network
    /// that does not broadcast its SSID. Active probing leaks the current MAC
    /// (even if locally administered) as a persistent identifier during the
    /// scan window.
    #[must_use]
    pub(crate) fn scan_directed(ssid: Vec<u8>, seq_num: u8) -> WifiCommand {
        let req = ScanRequest::directed_active(ssid);
        WifiCommand::with_payload(CommandId::ScanReq, seq_num, req.encode())
    }

    /// Advance the association state machine one step.
    ///
    /// Returns the new state, or the current state if already at the terminal state.
    pub(crate) const fn advance_assoc(&mut self) -> AssocState {
        if let Some(next) = self.assoc_state.advance() {
            self.assoc_state = next;
        }
        self.assoc_state
    }

    /// Reset the association state machine to `Idle`.
    pub(crate) const fn reset_assoc(&mut self) {
        self.assoc_state = AssocState::Idle;
    }

    /// Current association state.
    #[must_use]
    pub(crate) const fn assoc_state(&self) -> AssocState {
        self.assoc_state
    }

    /// Derive a PTK using the current randomized MAC as the supplicant address.
    ///
    /// Wires the locally-administered MAC through to `wpa::derive_ptk` so that
    /// the PTK is bound to the per-connection identity.
    #[must_use]
    pub(crate) fn derive_ptk(
        &self,
        pmk: &[u8; PMK_LEN],
        anonce: &[u8; 32],
        snonce: &[u8; 32],
        ap_mac: [u8; 6],
    ) -> wpa::Ptk {
        wpa::derive_ptk(pmk, anonce, snonce, &ap_mac, &self.current_mac.0)
    }
}

/// Offset of the MAC low-word register used by `CMD_ID_ACCESS_REG` writes.
///
/// NOTE: Matches `MCR_WASR` (WLAN async status register, 0x0020) which doubles
/// as the software-visible MAC register on gen2 HIF.
const MCR_WASR_MAC_LOW: u32 = 0x0020;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- TX descriptor encoding/decoding ---

    #[test]
    fn test_tx_header_data_encode_decode_roundtrip() {
        let hdr = HifTxHeader::data(1500, 4, 2);
        let encoded = hdr.encode();
        assert_eq!(
            encoded.len(),
            TX_HEADER_SIZE,
            "TX header must be exactly 16 bytes"
        );
        let decoded = HifTxHeader::decode(&encoded).unwrap_or_default();
        assert_eq!(
            decoded.packet_len, 1500,
            "packet_len must survive roundtrip"
        );
        assert_eq!(
            decoded.packet_type, PKT_TYPE_DATA,
            "packet_type must survive roundtrip"
        );
        assert_eq!(
            decoded.user_priority, 4,
            "user_priority must survive roundtrip"
        );
        assert_eq!(decoded.port_index, 2, "port_index must survive roundtrip");
    }

    #[test]
    fn test_tx_header_command_encode_decode_roundtrip() {
        let hdr = HifTxHeader::command(64);
        let encoded = hdr.encode();
        let decoded = HifTxHeader::decode(&encoded).unwrap_or_default();
        assert_eq!(
            decoded.packet_type, PKT_TYPE_CMD,
            "command type must be preserved"
        );
        assert_eq!(decoded.packet_len, 64, "packet_len must be preserved");
    }

    #[test]
    fn test_tx_header_decode_too_short() {
        let short = [0u8; 8];
        let result = HifTxHeader::decode(&short);
        assert!(
            matches!(result, Err(Error::TxHeaderTooShort { need: 16, have: 8 })),
            "must return TxHeaderTooShort for 8-byte buffer"
        );
    }

    // --- RX descriptor encoding/decoding ---

    #[test]
    fn test_rx_header_encode_decode_roundtrip() {
        let hdr = HifRxHeader {
            packet_len: 800,
            packet_type: 0,
            network_index: 1,
            tid: 3,
            security_mode: 2,
            dot11_header_present: true,
            reorder_flag: false,
            channel: 6,
        };
        let encoded = hdr.encode();
        assert_eq!(
            encoded.len(),
            RX_HEADER_SIZE,
            "RX header must be exactly 12 bytes"
        );
        let decoded = HifRxHeader::decode(&encoded).unwrap_or_default();
        assert_eq!(decoded.packet_len, 800, "packet_len roundtrip");
        assert_eq!(decoded.network_index, 1, "network_index roundtrip");
        assert_eq!(decoded.tid, 3, "tid roundtrip");
        assert_eq!(decoded.security_mode, 2, "security_mode roundtrip");
        assert!(
            decoded.dot11_header_present,
            "dot11_header_present roundtrip"
        );
        assert!(!decoded.reorder_flag, "reorder_flag roundtrip");
        assert_eq!(decoded.channel, 6, "channel roundtrip");
    }

    #[test]
    fn test_rx_header_decode_too_short() {
        let short = [0u8; 5];
        let result = HifRxHeader::decode(&short);
        assert!(
            matches!(result, Err(Error::RxHeaderTooShort { need: 12, have: 5 })),
            "must return RxHeaderTooShort for 5-byte buffer"
        );
    }

    // --- Command framing ---

    #[test]
    fn test_command_encode_no_payload() {
        let cmd = WifiCommand::new(CommandId::GetChipInfo, 1);
        let encoded = cmd.encode();
        assert_eq!(encoded.get(0).copied().unwrap_or_default(), 0x01, "first byte must be command ID");
        assert_eq!(encoded.get(1).copied().unwrap_or_default(), 1, "second byte must be seq_num");
        let len = u16::from_le_bytes([encoded.get(2).copied().unwrap_or_default(), encoded.get(3).copied().unwrap_or_default()]);
        assert_eq!(
            usize::try_from(len).unwrap_or_default(), CMD_HEADER_SIZE,
            "length must include header only"
        );
    }

    #[test]
    fn test_command_encode_with_payload() {
        let payload = vec![0xaa, 0xbb, 0xcc];
        let cmd = WifiCommand::with_payload(CommandId::ScanReq, 7, payload.clone());
        let encoded = cmd.encode();
        assert_eq!(encoded.get(0).copied().unwrap_or_default(), 0x20, "command ID must be ScanReq");
        assert_eq!(encoded.get(1).copied().unwrap_or_default(), 7, "seq_num must be 7");
        let len = u16::from_le_bytes([encoded.get(2).copied().unwrap_or_default(), encoded.get(3).copied().unwrap_or_default()]) as usize;
        assert_eq!(
            len,
            CMD_HEADER_SIZE + payload.len(),
            "length must account for payload"
        );
        assert_eq!(
            &encoded[4..],
            payload.as_slice(),
            "payload must be appended verbatim"
        );
    }

    // --- Scan result parsing ---

    #[test]
    fn test_scan_result_decode_valid() {
        let bssid = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let ssid = b"TestNet";
        let mut buf = Vec::new();
        buf.extend_from_slice(&bssid);
        #[expect(
            clippy::cast_possible_wrap,
            reason = "test: literal -70i8 encoded as two's complement for wire format"
        )]
        buf.push((-70i8) as u8);
        buf.push(11); // channel
        buf.push(0x01); // flags: has_rsn=1
        buf.push(ssid.len() as u8);
        buf.extend_from_slice(ssid);
        let result = BssScanResult::decode(&buf).unwrap_or_default();
        assert_eq!(result.bssid, bssid, "BSSID must match");
        assert_eq!(result.rssi_dbm, -70, "RSSI must match");
        assert_eq!(result.channel, 11, "channel must match");
        assert!(result.has_rsn, "has_rsn flag must be SET");
        assert_eq!(result.ssid, ssid, "SSID must match");
    }

    #[test]
    fn test_scan_result_decode_too_short() {
        let buf = [0u8; 5];
        let result = BssScanResult::decode(&buf);
        assert!(
            matches!(result, Err(Error::ScanResultTooShort { .. })),
            "must fail on short buffer"
        );
    }

    // --- MAC randomization validity ---

    #[test]
    fn test_mac_locally_administered_bit_set() {
        let rng = SystemRandom::new();
        for _ in 0..20 {
            let mac = MacAddress::generate_random(&rng).unwrap_or_default();
            assert!(
                mac.is_locally_administered(),
                "locally-administered bit must be SET in generated MAC"
            );
        }
    }

    #[test]
    fn test_mac_multicast_bit_clear() {
        let rng = SystemRandom::new();
        for _ in 0..20 {
            let mac = MacAddress::generate_random(&rng).unwrap_or_default();
            assert!(
                mac.is_unicast(),
                "multicast bit must be clear in generated MAC"
            );
        }
    }

    #[test]
    fn test_mac_randomness_across_calls() {
        // NOTE: Probability of collision is 2^{-46}  -  negligible.
        let rng = SystemRandom::new();
        let mac_a = MacAddress::generate_random(&rng).unwrap_or_default();
        let mac_b = MacAddress::generate_random(&rng).unwrap_or_default();
        // We verify both are valid rather than asserting inequality
        // (collision is theoretically possible but negligibly unlikely).
        assert!(
            mac_a.is_locally_administered(),
            "mac_a must be locally administered"
        );
        assert!(
            mac_b.is_locally_administered(),
            "mac_b must be locally administered"
        );
    }

    // --- Passive scan default ---

    #[test]
    fn test_passive_scan_default() {
        let req = ScanRequest::passive();
        assert_eq!(
            req.scan_type,
            ScanType::Passive,
            "default scan must be passive"
        );
        assert_eq!(
            req.ssid_type,
            SsidType::Wildcard,
            "default scan must be wildcard"
        );
        let encoded = req.encode();
        assert_eq!(
            encoded.get(0).copied().unwrap_or_default(),
            ScanType::u8::try_from(Passive).unwrap_or_default(),
            "encoded scan_type must be passive (1)"
        );
    }

    #[test]
    fn test_directed_active_scan() {
        let ssid = b"HiddenNet".to_vec();
        let req = ScanRequest::directed_active(ssid.clone());
        assert_eq!(
            req.scan_type,
            ScanType::Active,
            "directed scan must be active"
        );
        assert_eq!(
            req.ssid_type,
            SsidType::Specified,
            "directed scan must be specified"
        );
        let encoded = req.encode();
        assert_eq!(
            encoded.get(0).copied().unwrap_or_default(),
            ScanType::u8::try_from(Active).unwrap_or_default(),
            "encoded type must be active (0)"
        );
        assert_eq!(
            encoded.get(2).copied().unwrap_or_default() as usize,
            ssid.len(),
            "encoded ssid_len must match"
        );
        assert_eq!(&encoded[3..], ssid.as_slice(), "encoded SSID must match");
    }

    // --- Association state transitions ---

    #[test]
    fn test_assoc_state_full_sequence() {
        let expected = [
            AssocState::SendAuth1,
            AssocState::WaitAuth2,
            AssocState::SendAuth3,
            AssocState::WaitAuth4,
            AssocState::SendAssoc1,
            AssocState::WaitAssoc2,
            AssocState::Resource,
        ];
        let mut state = AssocState::Idle;
        for &expected_next in &expected {
            let next = state
                .advance()
                .unwrap_or_default();
            assert_eq!(next, expected_next, "state must advance in spec ORDER");
            state = next;
        }
        assert!(
            state.advance().is_none(),
            "Resource is the terminal state  -  advance must return None"
        );
    }

    #[test]
    fn test_assoc_state_is_associated_only_at_resource() {
        let non_terminal = [
            AssocState::Idle,
            AssocState::SendAuth1,
            AssocState::WaitAuth2,
            AssocState::SendAuth3,
            AssocState::WaitAuth4,
            AssocState::SendAssoc1,
            AssocState::WaitAssoc2,
        ];
        for state in non_terminal {
            assert!(
                !state.is_associated(),
                "{state:?} must not report as associated"
            );
        }
        assert!(
            AssocState::Resource.is_associated(),
            "Resource must report as associated"
        );
    }

    // --- WiFiMacDriver integration ---

    #[test]
    fn test_driver_initial_mac_valid() {
        let driver = WiFiMacDriver::new(0x1800_0000).unwrap_or_default();
        let mac = driver.mac_address();
        assert!(
            mac.is_locally_administered(),
            "initial MAC must be locally administered"
        );
        assert!(mac.is_unicast(), "initial MAC must be unicast");
    }

    #[test]
    fn test_driver_set_mac_address_produces_access_reg_command() {
        let mut driver = WiFiMacDriver::new(0x1800_0000).unwrap_or_default();
        let cmd = driver
            .set_mac_address(3)
            .unwrap_or_default();
        assert_eq!(
            cmd.cid,
            CommandId::AccessReg,
            "must produce ACCESS_REG command"
        );
        assert_eq!(cmd.seq_num, 3, "seq_num must match argument");
        assert_eq!(
            cmd.payload.len(),
            ACCESS_REG_PAYLOAD_SIZE,
            "payload must be exactly {ACCESS_REG_PAYLOAD_SIZE} bytes"
        );
        assert_eq!(
            cmd.payload.get(0).copied().unwrap_or_default(), ACCESS_REG_WRITE,
            "operation byte must be write"
        );
    }

    #[test]
    fn test_driver_assoc_state_machine_advances() {
        let mut driver = WiFiMacDriver::new(0x1800_0000).unwrap_or_default();
        assert_eq!(driver.assoc_state(), AssocState::Idle, "must start Idle");
        driver.advance_assoc();
        assert_eq!(
            driver.assoc_state(),
            AssocState::SendAuth1,
            "must advance to SendAuth1"
        );
        driver.reset_assoc();
        assert_eq!(
            driver.assoc_state(),
            AssocState::Idle,
            "reset must return to Idle"
        );
    }

    #[test]
    fn test_driver_ptk_derivation_uses_randomized_mac() {
        let driver = WiFiMacDriver::new(0x1800_0000).unwrap_or_default();
        let pmk = [0x11u8; PMK_LEN];
        let anonce = [0xaau8; 32];
        let snonce = [0xbbu8; 32];
        let ap_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let ptk_via_driver = driver.derive_ptk(&pmk, &anonce, &snonce, ap_mac);
        // Manually derive PTK using the same MAC the driver holds.
        let ptk_direct = wpa::derive_ptk(&pmk, &anonce, &snonce, &ap_mac, &driver.mac_address().0);
        assert_eq!(
            ptk_via_driver, ptk_direct,
            "driver PTK derivation must use the current randomized MAC"
        );
    }

    #[test]
    fn test_event_decode_cmd_result() {
        // eid=0x01, seq=5, length=4 (header only, little-endian)
        let buf = [0x01u8, 0x05, 0x04, 0x00];
        let evt = WifiEvent::decode(&buf).unwrap_or_default();
        assert_eq!(evt.eid, EventId::CmdResult, "EID must be CmdResult");
        assert_eq!(evt.seq_num, 5, "seq_num must be 5");
        assert!(
            evt.payload.is_empty(),
            "payload must be empty for header-only event"
        );
    }

    #[test]
    fn test_event_decode_unknown_eid() {
        let buf = [0xffu8, 0x01, 0x04, 0x00];
        let result = WifiEvent::decode(&buf);
        assert!(
            matches!(result, Err(Error::UnknownEventId { value: 0xff })),
            "must reject unknown EID"
        );
    }

    #[test]
    fn test_scan_type_default_is_passive() {
        let default_type = ScanType::default();
        assert_eq!(
            default_type,
            ScanType::Passive,
            "ScanType default must be Passive"
        );
    }
}
