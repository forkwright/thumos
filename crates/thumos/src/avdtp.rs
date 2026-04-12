//! AVDTP (Audio/Video Distribution Transport Protocol) signaling message builder.
//!
//! Builds AVDTP signaling messages for A2DP session setup and teardown.
//! These messages are encapsulated in L2CAP frames over the AVDTP PSM (0x0019).
//!
//! ## AVDTP signaling sequence
//!
//! 1. **Discover** -- enumerate remote stream endpoints (SEPs)
//! 2. **`GetCapabilities`** -- query codec capabilities of each SEP
//! 3. **`SetConfiguration`** -- negotiate SBC parameters
//! 4. **Open** -- open the transport channel
//! 5. **Start** -- begin streaming
//!
//! ## Message format
//!
//! Single-packet format:
//! ```text
//! Byte 0: [transaction_label:4][packet_type:2][message_type:2]
//! Byte 1: Signal identifier
//! Byte 2+: Signal-specific parameters
//! ```

// WHY: A2DP profile not yet wired to audio session manager (Wave 8, kinit pending).
#![expect(
    dead_code,
    reason = "A2DP profile created in Phase 07 Wave 8, audio manager wiring pending"
)]

extern crate alloc;
use alloc::vec::Vec;

use crate::sbc::{SbcFrameHeader, SBC_MIN_BITPOOL};

// ---------------------------------------------------------------------------
// AVDTP constants (Bluetooth A2DP Spec v1.3.2, AVDTP Spec v1.3)
// ---------------------------------------------------------------------------

/// AVDTP message type: command.
const AVDTP_MSG_TYPE_COMMAND: u8 = 0x00;

/// AVDTP packet type: single packet.
const AVDTP_PACKET_TYPE_SINGLE: u8 = 0x00;

/// AVDTP signal identifier: Discover.
pub(crate) const AVDTP_SIGNAL_DISCOVER: u8 = 0x01;

/// AVDTP signal identifier: Get Capabilities.
pub(crate) const AVDTP_SIGNAL_GET_CAPABILITIES: u8 = 0x02;

/// AVDTP signal identifier: Set Configuration.
pub(crate) const AVDTP_SIGNAL_SET_CONFIGURATION: u8 = 0x03;

/// AVDTP signal identifier: Open.
pub(crate) const AVDTP_SIGNAL_OPEN: u8 = 0x06;

/// AVDTP signal identifier: Start.
pub(crate) const AVDTP_SIGNAL_START: u8 = 0x07;

/// AVDTP signal identifier: Close.
pub(crate) const AVDTP_SIGNAL_CLOSE: u8 = 0x08;

/// AVDTP signal identifier: Suspend.
pub(crate) const AVDTP_SIGNAL_SUSPEND: u8 = 0x09;

/// AVDTP signal identifier: Abort.
pub(crate) const AVDTP_SIGNAL_ABORT: u8 = 0x0A;

/// Maximum AVDTP transaction label (4 bits).
pub(crate) const AVDTP_MAX_TRANSACTION_LABEL: u8 = 0x0F;

// ---------------------------------------------------------------------------
// AVDTP signaling message builder
// ---------------------------------------------------------------------------

/// Build an AVDTP signaling message.
///
/// AVDTP messages are encapsulated in L2CAP frames over the AVDTP PSM (0x0019).
pub(crate) struct AvdtpMessage;

impl AvdtpMessage {
    /// Build the first byte of an AVDTP signaling message.
    pub(crate) const fn header_byte(transaction_label: u8, msg_type: u8) -> u8 {
        ((transaction_label & 0x0F) << 4)
            | ((AVDTP_PACKET_TYPE_SINGLE & 0x03) << 2)
            | (msg_type & 0x03)
    }

    /// Build a Discover command.
    pub(crate) fn discover(transaction_label: u8) -> [u8; 2] {
        [
            Self::header_byte(transaction_label, AVDTP_MSG_TYPE_COMMAND),
            AVDTP_SIGNAL_DISCOVER,
        ]
    }

    /// Build a Get Capabilities command for the given SEID.
    pub(crate) fn get_capabilities(transaction_label: u8, seid: u8) -> [u8; 3] {
        [
            Self::header_byte(transaction_label, AVDTP_MSG_TYPE_COMMAND),
            AVDTP_SIGNAL_GET_CAPABILITIES,
            (seid & 0x3F) << 2, // SEID in bits 7:2, bits 1:0 reserved
        ]
    }

    /// Build a Set Configuration command.
    ///
    /// Configures the remote SEP with SBC codec parameters.
    pub(crate) fn set_configuration(
        transaction_label: u8,
        acp_seid: u8,
        int_seid: u8,
        header: &SbcFrameHeader,
    ) -> Vec<u8> {
        let mut msg = Vec::with_capacity(12);
        msg.push(Self::header_byte(transaction_label, AVDTP_MSG_TYPE_COMMAND));
        msg.push(AVDTP_SIGNAL_SET_CONFIGURATION);
        msg.push((acp_seid & 0x3F) << 2); // ACP SEID
        msg.push((int_seid & 0x3F) << 2); // INT SEID

        // Media transport capability (category 1, length 0).
        msg.push(0x01); // category: media transport
        msg.push(0x00); // length: 0

        // Media codec capability (category 7).
        msg.push(0x07); // category: media codec
        msg.push(0x06); // length: 6 bytes of codec info

        // Media type: audio (0x00), codec type: SBC (0x00).
        msg.push(0x00); // media type (audio) << 4
        msg.push(0x00); // codec type (SBC)

        // SBC codec specific information element (4 bytes).
        // Byte 0: [sampling_freq:4][channel_mode:4]
        let freq_bits = match header.sampling_freq {
            0 => 0x10, // 48000
            1 => 0x20, // 44100
            2 => 0x40, // 32000
            _ => 0x80, // 16000
        };
        let mode_bits = match header.channel_mode {
            0 => 0x08, // mono
            1 => 0x04, // dual
            2 => 0x02, // stereo
            _ => 0x01, // joint stereo
        };
        msg.push(freq_bits | mode_bits);

        // Byte 1: [blocks:4][subbands:2][alloc:2]
        let block_bits = match header.blocks {
            0 => 0x80, // 4
            1 => 0x40, // 8
            2 => 0x20, // 12
            _ => 0x10, // 16
        };
        let sub_bits = if header.subbands == 0 { 0x08 } else { 0x04 };
        let alloc_bits = if header.alloc_method == 0 { 0x02 } else { 0x01 };
        msg.push(block_bits | sub_bits | alloc_bits);

        // Byte 2: min bitpool
        msg.push(SBC_MIN_BITPOOL);

        // Byte 3: max bitpool
        msg.push(header.bitpool);

        msg
    }

    /// Build an Open command for the given SEID.
    pub(crate) fn open(transaction_label: u8, seid: u8) -> [u8; 3] {
        [
            Self::header_byte(transaction_label, AVDTP_MSG_TYPE_COMMAND),
            AVDTP_SIGNAL_OPEN,
            (seid & 0x3F) << 2,
        ]
    }

    /// Build a Start command for the given SEID.
    pub(crate) fn start(transaction_label: u8, seid: u8) -> [u8; 3] {
        [
            Self::header_byte(transaction_label, AVDTP_MSG_TYPE_COMMAND),
            AVDTP_SIGNAL_START,
            (seid & 0x3F) << 2,
        ]
    }

    /// Build a Close command for the given SEID.
    pub(crate) fn close(transaction_label: u8, seid: u8) -> [u8; 3] {
        [
            Self::header_byte(transaction_label, AVDTP_MSG_TYPE_COMMAND),
            AVDTP_SIGNAL_CLOSE,
            (seid & 0x3F) << 2,
        ]
    }

    /// Build a Suspend command for the given SEID.
    pub(crate) fn suspend(transaction_label: u8, seid: u8) -> [u8; 3] {
        [
            Self::header_byte(transaction_label, AVDTP_MSG_TYPE_COMMAND),
            AVDTP_SIGNAL_SUSPEND,
            (seid & 0x3F) << 2,
        ]
    }

    /// Build an Abort command for the given SEID.
    pub(crate) fn abort(transaction_label: u8, seid: u8) -> [u8; 3] {
        [
            Self::header_byte(transaction_label, AVDTP_MSG_TYPE_COMMAND),
            AVDTP_SIGNAL_ABORT,
            (seid & 0x3F) << 2,
        ]
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn avdtp_discover_message_format() {
        let msg = AvdtpMessage::discover(3);
        // Byte 0: label=3 (bits 7:4=0011), packet_type=single (bits 3:2=00),
        //         msg_type=command (bits 1:0=00) => 0x30
        assert_eq!(msg[0], 0x30, "header byte must encode label and types");
        assert_eq!(msg[1], AVDTP_SIGNAL_DISCOVER, "signal must be Discover");
    }
}
