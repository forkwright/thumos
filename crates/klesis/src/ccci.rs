//! CCCI (Cross-Core Communication Interface) channel types and message format.
//!
//! The CCCI manages the AP↔modem link on the MT6739 (modem: MD 6293, a
//! separate ARM core). All CCCI messages share a 16-byte header. Two physical
//! transports exist: CLDMA (ring-buffer DMA) and CCIF (mailbox). This module
//! covers the logical channel layer that sits above both.
//!
//! Source: `eccci/inc/ccci_core.h`, `eccci/mt6739/ccci_config.h`,
//! `docs/DRIVER-INTERFACES.md §1.6–1.7`

use snafu::ensure;

use crate::error::{ParseSnafu, Result};

// ─── Constants ────────────────────────────────────────────────────────────────

/// Maximum CCCI message payload size (bytes).
///
/// Source: `eccci/mt6739/ccci_config.h`
pub(crate) const CCCI_MTU: usize = 3456;

/// Magic value placed in `data[0]` to mark an internal control message.
///
/// Source: `eccci/inc/ccci_core.h:33`
pub(crate) const CCCI_MAGIC_NUM: u32 = 0xFFFF_FFFF;

/// Wire size of a [`CcciHeader`] in bytes.
pub(crate) const HEADER_SIZE: usize = 16;

// ─── Types ────────────────────────────────────────────────────────────────────

/// Logical CCCI channel identifiers.
///
/// Maps directly to the kernel `CCCI_*_RX/TX` enum defined in
/// `eccci/inc/ccci_core.h:46`. Each value equals the raw channel number
/// placed in the header's `channel` field.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub(crate) enum CcciChannel {
    /// Modem control handshake, AP-receive direction.
    #[default]
    ControlRx,
    /// Modem control handshake, AP-transmit direction.
    ControlTx,
    /// System messages, AP-receive.
    SystemRx,
    /// System messages, AP-transmit.
    SystemTx,
    /// PCM audio, AP-receive.
    PcmRx,
    /// PCM audio, AP-transmit.
    PcmTx,
    /// AT command / RILD  -  META UART, AP-receive.
    Uart1Rx,
    /// AT command / RILD  -  META UART, AP-transmit.
    Uart1Tx,
    /// MUX UART, AP-receive.
    Uart2Rx,
    /// MUX UART, AP-transmit.
    Uart2Tx,
    /// File-system proxy, AP-receive.
    FsRx,
    /// File-system proxy, AP-transmit.
    FsTx,
    /// PMIC proxy, AP-receive.
    PmicRx,
    /// PMIC proxy, AP-transmit.
    PmicTx,
    /// Network data channel 1, AP-receive.
    Ccmni1Rx,
    /// Network data channel 1, AP-transmit.
    Ccmni1Tx,
    /// Network data channel 2, AP-receive.
    Ccmni2Rx,
    /// Network data channel 2, AP-transmit.
    Ccmni2Tx,
    /// Network data channel 3, AP-receive.
    Ccmni3Rx,
    /// Network data channel 3, AP-transmit.
    Ccmni3Tx,
    /// Inter-processor call, AP-receive.
    IpcRx,
    /// Inter-processor call, AP-transmit.
    IpcTx,
    /// Modem log, AP-receive.
    MdLogRx,
    /// Modem log, AP-transmit.
    MdLogTx,
}

impl CcciChannel {
    /// Raw channel number placed in the CCCI header `channel` field.
    #[must_use]
    pub(crate) const fn id(self) -> u32 {
        match self {
            Self::ControlRx => 0,
            Self::ControlTx => 1,
            Self::SystemRx => 2,
            Self::SystemTx => 3,
            Self::PcmRx => 4,
            Self::PcmTx => 5,
            Self::Uart1Rx => 6,
            Self::Uart1Tx => 8,
            Self::Uart2Rx => 10,
            Self::Uart2Tx => 12,
            Self::FsRx => 14,
            Self::FsTx => 15,
            Self::PmicRx => 16,
            Self::PmicTx => 17,
            Self::Ccmni1Rx => 20,
            Self::Ccmni1Tx => 22,
            Self::Ccmni2Rx => 24,
            Self::Ccmni2Tx => 26,
            Self::Ccmni3Rx => 28,
            Self::Ccmni3Tx => 30,
            Self::IpcRx => 34,
            Self::IpcTx => 36,
            Self::MdLogRx => 42,
            Self::MdLogTx => 43,
        }
    }
}

impl TryFrom<u32> for CcciChannel {
    type Error = crate::error::Error;

    /// # Errors
    ///
    /// Returns [`crate::error::Error::Parse`] for any unrecognised channel ID.
    fn try_from(id: u32) -> Result<Self> {
        match id {
            0 => Ok(Self::ControlRx),
            1 => Ok(Self::ControlTx),
            2 => Ok(Self::SystemRx),
            3 => Ok(Self::SystemTx),
            4 => Ok(Self::PcmRx),
            5 => Ok(Self::PcmTx),
            6 => Ok(Self::Uart1Rx),
            8 => Ok(Self::Uart1Tx),
            10 => Ok(Self::Uart2Rx),
            12 => Ok(Self::Uart2Tx),
            14 => Ok(Self::FsRx),
            15 => Ok(Self::FsTx),
            16 => Ok(Self::PmicRx),
            17 => Ok(Self::PmicTx),
            20 => Ok(Self::Ccmni1Rx),
            22 => Ok(Self::Ccmni1Tx),
            24 => Ok(Self::Ccmni2Rx),
            26 => Ok(Self::Ccmni2Tx),
            28 => Ok(Self::Ccmni3Rx),
            30 => Ok(Self::Ccmni3Tx),
            34 => Ok(Self::IpcRx),
            36 => Ok(Self::IpcTx),
            42 => Ok(Self::MdLogRx),
            43 => Ok(Self::MdLogTx),
            _ => ParseSnafu {
                message: format!("unknown CCCI channel ID: {id}"),
            }
            .fail(),
        }
    }
}

/// 16-byte CCCI message header shared by all channels.
///
/// Wire layout (little-endian):
///
/// ```text
/// bytes  0– 3  data[0]    channel-specific payload word 0
/// bytes  4– 7  data[1]    channel-specific payload word 1
/// bytes  8–11  channel    logical channel ID (see CcciChannel)
/// bytes 12–15  reserved   sequence number / flags / C2K ctrl
/// ```
///
/// When `data[0] == CCCI_MAGIC_NUM` the message is an internal control
/// message, not user data.
///
/// Source: `eccci/inc/ccci_core.h:33`, `docs/DRIVER-INTERFACES.md §1.6`
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct CcciHeader {
    /// Channel-specific words. `data[0] == CCCI_MAGIC_NUM` signals a control
    /// message; for data channels `data[0]` carries the packet length.
    pub(crate) data: [u32; 2],
    /// Logical channel number (see [`CcciChannel::id`]).
    pub(crate) channel: u32,
    /// Sequence number, flags, or C2K control word depending on channel.
    pub(crate) reserved: u32,
}

impl CcciHeader {
    /// Construct a header FROM its four words.
    #[must_use]
    pub(crate) const fn new(data0: u32, data1: u32, channel: u32, reserved: u32) -> Self {
        Self {
            data: [data0, data1],
            channel,
            reserved,
        }
    }

    /// Encode to the 16-byte little-endian wire format.
    #[must_use]
    pub(crate) const fn to_bytes(self) -> [u8; HEADER_SIZE] {
        let [data0, data1] = self.data;
        let [d00, d01, d02, d03] = data0.to_le_bytes();
        let [d10, d11, d12, d13] = data1.to_le_bytes();
        let [c0, c1, c2, c3] = self.channel.to_le_bytes();
        let [r0, r1, r2, r3] = self.reserved.to_le_bytes();
        [
            d00, d01, d02, d03, d10, d11, d12, d13, c0, c1, c2, c3, r0, r1, r2, r3,
        ]
    }

    /// Decode FROM the 16-byte little-endian wire format.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::Error::Parse`] when `buf` is shorter than
    /// [`HEADER_SIZE`].
    pub(crate) fn from_bytes(buf: &[u8]) -> Result<Self> {
        ensure!(
            buf.len() >= HEADER_SIZE,
            ParseSnafu {
                message: format!(
                    "CCCI header requires {HEADER_SIZE} bytes, got {}",
                    buf.len()
                ),
            }
        );
        // WHY: ensure! above guarantees buf.len() >= HEADER_SIZE (16), so these
        // fixed wire-format byte reads are in bounds.
        let data0 = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let data1 = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let channel = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
        let reserved = u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]);
        Ok(Self {
            data: [data0, data1],
            channel,
            reserved,
        })
    }

    /// Returns `true` when `data[0]` holds the internal-control magic value.
    #[must_use]
    pub(crate) const fn is_internal(&self) -> bool {
        let [d0, _] = self.data;
        d0 == CCCI_MAGIC_NUM
    }
}

/// A complete CCCI message: 16-byte header plus variable-length payload.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct CcciMessage {
    /// Parsed header.
    pub(crate) header: CcciHeader,
    /// Raw payload bytes (up to [`CCCI_MTU`] bytes).
    pub(crate) payload: Vec<u8>,
}

impl CcciMessage {
    /// Create a message FROM a header and payload.
    #[must_use]
    pub(crate) const fn new(header: CcciHeader, payload: Vec<u8>) -> Self {
        Self { header, payload }
    }

    /// Encode header followed by payload INTO a single byte buffer.
    #[must_use]
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_SIZE + self.payload.len());
        out.extend_from_slice(&self.header.to_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    /// Decode a message: first [`HEADER_SIZE`] bytes are the header, the rest
    /// is the payload.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::Error::Parse`] when `buf` is shorter than
    /// [`HEADER_SIZE`].
    pub(crate) fn from_bytes(buf: &[u8]) -> Result<Self> {
        let header = CcciHeader::from_bytes(buf)?;
        let payload = buf.get(HEADER_SIZE..).unwrap_or(&[]).to_vec();
        Ok(Self { header, payload })
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_encode_little_endian() {
        let hdr = CcciHeader::new(0x0000_0010, 0x0000_0000, 8, 0);
        let bytes = hdr.to_bytes();
        assert_eq!(
            bytes.get(0..4).unwrap_or_default(),
            &[0x10, 0x00, 0x00, 0x00],
            "data.get(0).copied().unwrap_or_default() must be little-endian"
        );
        assert_eq!(
            bytes.get(8..12).unwrap_or_default(),
            &[0x08, 0x00, 0x00, 0x00],
            "channel must be little-endian"
        );
    }

    #[test]
    fn header_decode_roundtrip() {
        let original = CcciHeader::new(0xDEAD_BEEF, 0x1234_5678, 6, 0x0000_0042);
        let decoded = CcciHeader::from_bytes(&original.to_bytes()).unwrap_or_default();
        assert_eq!(original, decoded, "header roundtrip must be lossless");
    }

    #[test]
    fn header_decode_rejects_short_buffer() {
        let result = CcciHeader::from_bytes(&[0u8; 8]);
        assert!(result.is_err(), "must reject buffers shorter than 16 bytes");
    }

    #[test]
    fn header_is_internal_magic() {
        let ctrl = CcciHeader::new(CCCI_MAGIC_NUM, 0, 0, 0);
        assert!(
            ctrl.is_internal(),
            "magic data.get(0).copied().unwrap_or_default() must be detected as internal"
        );

        let data = CcciHeader::new(0x0000_0010, 0, 8, 0);
        assert!(!data.is_internal(), "non-magic header must not be internal");
    }

    #[test]
    fn message_roundtrip_with_payload() {
        let hdr = CcciHeader::new(0x14, 0, CcciChannel::Uart1Tx.id(), 1);
        let payload = b"AT+CSQ\r\n".to_vec();
        let msg = CcciMessage::new(hdr, payload);
        let decoded = CcciMessage::from_bytes(&msg.to_bytes()).unwrap_or_default();
        assert_eq!(msg, decoded, "message roundtrip must be lossless");
    }

    #[test]
    fn channel_id_roundtrip() {
        let ch = CcciChannel::Uart1Tx;
        let id = ch.id();
        let recovered = CcciChannel::try_from(id).unwrap_or_default();
        assert_eq!(
            ch, recovered,
            "channel roundtrip via id() / try_from must be lossless"
        );
    }

    #[test]
    fn channel_try_from_rejects_unknown() {
        let result = CcciChannel::try_from(0xFF);
        assert!(result.is_err(), "unknown channel ID 0xFF must be rejected");
    }
}
