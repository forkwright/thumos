//! Bluetooth A2DP audio source profile.
//!
//! Implements the A2DP (Advanced Audio Distribution Profile) source role for
//! streaming audio to Bluetooth headphones and speakers.  Builds on the HCI
//! layer in `bluetooth.rs`.
//!
//! ## Protocol stack
//!
//! ```text
//! Application (PCM audio)
//!        |
//!   SBC encoder  (sub-band coding, mandatory A2DP codec)
//!        |
//!   AVDTP        (Audio/Video Distribution Transport Protocol)
//!        |
//!   L2CAP        (encapsulated in HCI ACL packets)
//!        |
//!   HCI          (bluetooth.rs)
//! ```
//!
//! ## AVDTP signaling
//!
//! A2DP session setup follows the AVDTP signaling sequence:
//!
//! 1. **Discover** -- enumerate remote stream endpoints (SEPs)
//! 2. **`GetCapabilities`** -- query codec capabilities of each SEP
//! 3. **`SetConfiguration`** -- negotiate SBC parameters
//! 4. **Open** -- open the transport channel
//! 5. **Start** -- begin streaming
//!
//! ## SBC codec
//!
//! SBC (Sub-Band Coding) is the mandatory A2DP codec.  This module implements
//! the SBC frame header structure and a stub encoder that produces valid SBC
//! frame headers with zeroed audio data.  Full audio encoding (analysis
//! filterbank, bit allocation, quantization) is future work.
//!
//! ## Integration
//!
//! Used by the audio session manager (`audio.rs`) when the output route is
//! `AudioRoute::BluetoothA2dp`.  Connects to the BT adapter via `bluetooth.rs`.

// WHY: A2DP profile not yet wired to audio session manager (Wave 8, kinit pending).
#![expect(
    dead_code,
    reason = "A2DP profile created in Phase 07 Wave 8, audio manager wiring pending"
)]

extern crate alloc;
use alloc::vec::Vec;

use crate::bluetooth::{BtError, BtHwOps};

// ---------------------------------------------------------------------------
// AVDTP constants (Bluetooth A2DP Spec v1.3.2, AVDTP Spec v1.3)
// ---------------------------------------------------------------------------

/// L2CAP PSM for AVDTP signaling.
const AVDTP_PSM: u16 = 0x0019;

/// AVDTP message type: command.
const AVDTP_MSG_TYPE_COMMAND: u8 = 0x00;

/// AVDTP message type: general reject.
const AVDTP_MSG_TYPE_GENERAL_REJECT: u8 = 0x01;

/// AVDTP message type: response accept.
const AVDTP_MSG_TYPE_RESPONSE_ACCEPT: u8 = 0x02;

/// AVDTP message type: response reject.
const AVDTP_MSG_TYPE_RESPONSE_REJECT: u8 = 0x03;

/// AVDTP packet type: single packet.
const AVDTP_PACKET_TYPE_SINGLE: u8 = 0x00;

/// AVDTP signal identifier: Discover.
const AVDTP_SIGNAL_DISCOVER: u8 = 0x01;

/// AVDTP signal identifier: Get Capabilities.
const AVDTP_SIGNAL_GET_CAPABILITIES: u8 = 0x02;

/// AVDTP signal identifier: Set Configuration.
const AVDTP_SIGNAL_SET_CONFIGURATION: u8 = 0x03;

/// AVDTP signal identifier: Open.
const AVDTP_SIGNAL_OPEN: u8 = 0x06;

/// AVDTP signal identifier: Start.
const AVDTP_SIGNAL_START: u8 = 0x07;

/// AVDTP signal identifier: Close.
const AVDTP_SIGNAL_CLOSE: u8 = 0x08;

/// AVDTP signal identifier: Suspend.
const AVDTP_SIGNAL_SUSPEND: u8 = 0x09;

/// AVDTP signal identifier: Abort.
const AVDTP_SIGNAL_ABORT: u8 = 0x0A;

/// Maximum AVDTP transaction label (4 bits).
const AVDTP_MAX_TRANSACTION_LABEL: u8 = 0x0F;

// ---------------------------------------------------------------------------
// SBC constants (A2DP Spec Appendix B / Bluetooth SIG SBC specification)
// ---------------------------------------------------------------------------

/// SBC syncword (first byte of every SBC frame).
const SBC_SYNCWORD: u8 = 0x9C;

/// SBC sampling frequency: 44100 Hz (index 1).
const SBC_FREQ_44100: u8 = 0x01;

/// SBC sampling frequency: 48000 Hz (index 0).
const SBC_FREQ_48000: u8 = 0x00;

/// SBC channel mode: mono (index 0).
const SBC_CHANNEL_MONO: u8 = 0x00;

/// SBC channel mode: joint stereo (index 3).
const SBC_CHANNEL_JOINT_STEREO: u8 = 0x03;

/// SBC block length: 16 blocks.
const SBC_BLOCKS_16: u8 = 0x03;

/// SBC subbands: 8 subbands.
const SBC_SUBBANDS_8: u8 = 0x01;

/// SBC allocation method: loudness.
const SBC_ALLOC_LOUDNESS: u8 = 0x01;

/// Default SBC bitpool value for high quality stereo (A2DP recommended).
///
/// Bitpool 53 gives ~328 kbps for joint stereo 44.1 kHz, which is the
/// standard "high quality" setting for A2DP.
const SBC_DEFAULT_BITPOOL: u8 = 53;

/// Minimum allowed SBC bitpool (per spec).
const SBC_MIN_BITPOOL: u8 = 2;

/// Maximum allowed SBC bitpool (per spec).
const SBC_MAX_BITPOOL: u8 = 250;

/// Number of subbands in the analysis filterbank.
const SBC_NUM_SUBBANDS: usize = 8;

/// Number of blocks per SBC frame.
const SBC_NUM_BLOCKS: usize = 16;

/// SBC frame header size in bytes.
const SBC_HEADER_SIZE: usize = 4;

/// Maximum SBC frame size in bytes (header + scale factors + audio data).
///
/// For 16 blocks, 8 subbands, joint stereo, bitpool 53:
/// `frame_length` = 4 + (4 * 8 * 2 / 8) + ceil(16 * 53 / 8) = 4 + 8 + 106 = 118
/// We use a generous upper bound for any configuration.
const SBC_MAX_FRAME_SIZE: usize = 512;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Bluetooth audio (A2DP) errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BtAudioError {
    /// The A2DP profile is not in a valid state for this operation.
    InvalidState,
    /// Bluetooth HCI layer error.
    HciError(BtError),
    /// AVDTP signaling failed or was rejected by the remote peer.
    AvdtpError,
    /// SBC encoding error (e.g., invalid parameters).
    SbcError,
    /// The peer does not support SBC (mandatory codec).
    CodecNotSupported,
    /// Buffer too small for the encoded output.
    BufferTooSmall,
    /// No peer device configured.
    NoPeer,
}

impl core::fmt::Display for BtAudioError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidState => write!(f, "A2DP invalid state"),
            Self::HciError(e) => write!(f, "A2DP HCI error: {e}"),
            Self::AvdtpError => write!(f, "AVDTP signaling error"),
            Self::SbcError => write!(f, "SBC encoding error"),
            Self::CodecNotSupported => write!(f, "SBC codec not supported by peer"),
            Self::BufferTooSmall => write!(f, "output buffer too small"),
            Self::NoPeer => write!(f, "no peer device configured"),
        }
    }
}

impl From<BtError> for BtAudioError {
    fn from(e: BtError) -> Self {
        Self::HciError(e)
    }
}

// ---------------------------------------------------------------------------
// A2DP state machine
// ---------------------------------------------------------------------------

/// A2DP source profile connection state.
///
/// Follows the AVDTP signaling lifecycle:
/// `Disconnected -> Connecting -> Connected -> Streaming`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum A2dpState {
    /// No active A2DP connection.
    #[default]
    Disconnected,
    /// AVDTP signaling in progress (Discover -> `SetConfiguration` -> Open).
    Connecting,
    /// AVDTP stream is configured and open, ready to start.
    Connected,
    /// Audio is actively streaming to the remote sink.
    Streaming,
    /// An error occurred during signaling or streaming.
    Error(BtAudioError),
}

impl core::fmt::Display for A2dpState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Disconnected => write!(f, "disconnected"),
            Self::Connecting => write!(f, "connecting"),
            Self::Connected => write!(f, "connected"),
            Self::Streaming => write!(f, "streaming"),
            Self::Error(e) => write!(f, "error: {e}"),
        }
    }
}

// ---------------------------------------------------------------------------
// SBC frame header
// ---------------------------------------------------------------------------

/// SBC frame header (4 bytes).
///
/// Per the SBC specification (A2DP Appendix B):
///
/// ```text
/// Byte 0: Syncword (0x9C)
/// Byte 1: [sampling_freq:2][blocks:2][channel_mode:2][alloc_method:1][subbands:1]
/// Byte 2: Bitpool value
/// Byte 3: CRC-8 of bytes 1-2 (and channel data for joint stereo)
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SbcFrameHeader {
    /// Sampling frequency index (0=48kHz, 1=44.1kHz, 2=32kHz, 3=16kHz).
    pub sampling_freq: u8,
    /// Block count index (0=4, 1=8, 2=12, 3=16).
    pub blocks: u8,
    /// Channel mode (0=mono, 1=dual, 2=stereo, 3=joint stereo).
    pub channel_mode: u8,
    /// Allocation method (0=SNR, 1=loudness).
    pub alloc_method: u8,
    /// Subbands (0=4, 1=8).
    pub subbands: u8,
    /// Bitpool value (2-250).
    pub bitpool: u8,
}

impl SbcFrameHeader {
    /// Create a default SBC frame header for A2DP high-quality stereo.
    ///
    /// 44100 Hz, 16 blocks, joint stereo, 8 subbands, loudness allocation,
    /// bitpool 53.
    #[must_use]
    pub const fn default_a2dp() -> Self {
        Self {
            sampling_freq: SBC_FREQ_44100,
            blocks: SBC_BLOCKS_16,
            channel_mode: SBC_CHANNEL_JOINT_STEREO,
            alloc_method: SBC_ALLOC_LOUDNESS,
            subbands: SBC_SUBBANDS_8,
            bitpool: SBC_DEFAULT_BITPOOL,
        }
    }

    /// Create a mono SBC frame header for low-bandwidth use.
    #[must_use]
    pub const fn mono(sample_rate: u32) -> Self {
        let freq = if sample_rate == 48000 {
            SBC_FREQ_48000
        } else {
            SBC_FREQ_44100
        };
        Self {
            sampling_freq: freq,
            blocks: SBC_BLOCKS_16,
            channel_mode: SBC_CHANNEL_MONO,
            alloc_method: SBC_ALLOC_LOUDNESS,
            subbands: SBC_SUBBANDS_8,
            bitpool: SBC_DEFAULT_BITPOOL,
        }
    }

    /// Encode this header into 4 bytes.
    ///
    /// Returns `[syncword, config_byte, bitpool, crc]`.
    #[must_use]
    pub fn encode(&self) -> [u8; SBC_HEADER_SIZE] {
        let config = (self.sampling_freq << 6)
            | (self.blocks << 4)
            | (self.channel_mode << 2)
            | (self.alloc_method << 1)
            | self.subbands;
        let crc = sbc_crc8(config, self.bitpool);
        [SBC_SYNCWORD, config, self.bitpool, crc]
    }

    /// Calculate the expected frame length in bytes.
    ///
    /// Per the SBC specification, frame length depends on channel mode,
    /// subbands, blocks, and bitpool.
    #[must_use]
    pub const fn frame_length(&self) -> usize {
        let nrof_subbands: usize = if self.subbands == SBC_SUBBANDS_8 { 8 } else { 4 };
        let nrof_blocks: usize = match self.blocks {
            0 => 4,
            1 => 8,
            2 => 12,
            _ => 16,
        };

        let join = if self.channel_mode == SBC_CHANNEL_JOINT_STEREO { 1 } else { 0 };
        let nrof_channels: usize = if self.channel_mode == SBC_CHANNEL_MONO { 1 } else { 2 };

        // frame_length = 4 + (4 * nrof_subbands * nrof_channels) / 8
        //              + ceil(nrof_blocks * bitpool * nrof_channels / 8) (mono/dual)
        //     or        + ceil(nrof_blocks * bitpool / 8) (stereo/joint + join bits)
        //
        // Simplified per spec section 12.9:
        let scale_factors_bytes = (4 * nrof_subbands * nrof_channels) / 8;
        let audio_bits = if self.channel_mode == SBC_CHANNEL_MONO
            || self.channel_mode == 0x01 // dual channel
        {
            nrof_blocks * self.bitpool as usize * nrof_channels
        } else {
            // stereo or joint stereo
            join * nrof_subbands + nrof_blocks * self.bitpool as usize
        };
        let audio_bytes = audio_bits.div_ceil(8);

        SBC_HEADER_SIZE + scale_factors_bytes + audio_bytes
    }

    /// Validate that the header parameters are within spec bounds.
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.sampling_freq <= 3
            && self.blocks <= 3
            && self.channel_mode <= 3
            && self.alloc_method <= 1
            && self.subbands <= 1
            && self.bitpool >= SBC_MIN_BITPOOL
            && self.bitpool <= SBC_MAX_BITPOOL
    }
}

/// Compute the SBC CRC-8 checksum over the config byte and bitpool.
///
/// Uses the polynomial x^8 + x^4 + x^3 + x^2 + 1 (0x1D) as specified
/// in the SBC specification section 12.6.
fn sbc_crc8(config: u8, bitpool: u8) -> u8 {
    let data = [config, bitpool];
    let mut crc: u8 = 0x0F; // initial value per SBC spec
    for &byte in &data {
        for bit in (0..8).rev() {
            let do_xor = (crc ^ (byte >> bit)) & 0x01;
            crc >>= 1;
            if do_xor != 0 {
                crc ^= 0x8D; // reversed polynomial 0x1D
            }
        }
    }
    crc
}

// ---------------------------------------------------------------------------
// SBC encoder trait
// ---------------------------------------------------------------------------

/// SBC encoder trait for audio encoding.
///
/// Implementations take PCM audio samples and produce SBC-encoded frames.
pub trait SbcEncoder {
    /// Encode PCM samples into an SBC frame.
    ///
    /// `pcm` contains interleaved 16-bit PCM samples (L,R,L,R... for stereo).
    /// `output` receives the encoded SBC frame data.
    ///
    /// Returns the number of bytes written to `output`.
    fn encode(&mut self, pcm: &[i16], output: &mut [u8]) -> Result<usize, BtAudioError>;
}

// ---------------------------------------------------------------------------
// Stub SBC encoder
// ---------------------------------------------------------------------------

/// Stub SBC encoder that produces valid frame headers with zeroed audio data.
///
/// This encoder generates structurally valid SBC frames that can be parsed by
/// any A2DP sink, but the audio payload is silence (all zeros).  This is
/// sufficient for testing the A2DP state machine and AVDTP signaling without
/// implementing the full SBC analysis filterbank.
///
/// ## Future work
///
/// Replace with a real SBC encoder that implements:
/// 1. Analysis filterbank (8 subbands, polyphase)
/// 2. Scale factor calculation
/// 3. Bit allocation (loudness or SNR method)
/// 4. Quantization and bitstream packing
pub struct StubSbcEncoder {
    /// Frame header configuration.
    header: SbcFrameHeader,
}

impl StubSbcEncoder {
    /// Create a new stub encoder with the given header configuration.
    #[must_use]
    pub const fn new(header: SbcFrameHeader) -> Self {
        Self { header }
    }

    /// Create a stub encoder with default A2DP high-quality settings.
    #[must_use]
    pub const fn default_a2dp() -> Self {
        Self::new(SbcFrameHeader::default_a2dp())
    }

    /// Return the configured frame header.
    #[must_use]
    pub const fn header(&self) -> &SbcFrameHeader {
        &self.header
    }
}

impl SbcEncoder for StubSbcEncoder {
    fn encode(&mut self, _pcm: &[i16], output: &mut [u8]) -> Result<usize, BtAudioError> {
        let frame_len = self.header.frame_length();
        if output.len() < frame_len {
            return Err(BtAudioError::BufferTooSmall);
        }

        // Write the 4-byte header.
        let hdr = self.header.encode();
        output[..SBC_HEADER_SIZE].copy_from_slice(&hdr);

        // Zero the audio payload (silence).
        for byte in &mut output[SBC_HEADER_SIZE..frame_len] {
            *byte = 0;
        }

        Ok(frame_len)
    }
}

// ---------------------------------------------------------------------------
// AVDTP signaling message builder
// ---------------------------------------------------------------------------

/// Build an AVDTP signaling message.
///
/// AVDTP messages are encapsulated in L2CAP frames over the AVDTP PSM (0x0019).
///
/// Single-packet format:
/// ```text
/// Byte 0: [transaction_label:4][packet_type:2][message_type:2]
/// Byte 1: Signal identifier
/// Byte 2+: Signal-specific parameters
/// ```
struct AvdtpMessage;

impl AvdtpMessage {
    /// Build the first byte of an AVDTP signaling message.
    const fn header_byte(transaction_label: u8, msg_type: u8) -> u8 {
        ((transaction_label & 0x0F) << 4)
            | ((AVDTP_PACKET_TYPE_SINGLE & 0x03) << 2)
            | (msg_type & 0x03)
    }

    /// Build a Discover command.
    fn discover(transaction_label: u8) -> [u8; 2] {
        [
            Self::header_byte(transaction_label, AVDTP_MSG_TYPE_COMMAND),
            AVDTP_SIGNAL_DISCOVER,
        ]
    }

    /// Build a Get Capabilities command for the given SEID.
    fn get_capabilities(transaction_label: u8, seid: u8) -> [u8; 3] {
        [
            Self::header_byte(transaction_label, AVDTP_MSG_TYPE_COMMAND),
            AVDTP_SIGNAL_GET_CAPABILITIES,
            (seid & 0x3F) << 2, // SEID in bits 7:2, bits 1:0 reserved
        ]
    }

    /// Build a Set Configuration command.
    ///
    /// Configures the remote SEP with SBC codec parameters.
    fn set_configuration(
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
    fn open(transaction_label: u8, seid: u8) -> [u8; 3] {
        [
            Self::header_byte(transaction_label, AVDTP_MSG_TYPE_COMMAND),
            AVDTP_SIGNAL_OPEN,
            (seid & 0x3F) << 2,
        ]
    }

    /// Build a Start command for the given SEID.
    fn start(transaction_label: u8, seid: u8) -> [u8; 3] {
        [
            Self::header_byte(transaction_label, AVDTP_MSG_TYPE_COMMAND),
            AVDTP_SIGNAL_START,
            (seid & 0x3F) << 2,
        ]
    }

    /// Build a Close command for the given SEID.
    fn close(transaction_label: u8, seid: u8) -> [u8; 3] {
        [
            Self::header_byte(transaction_label, AVDTP_MSG_TYPE_COMMAND),
            AVDTP_SIGNAL_CLOSE,
            (seid & 0x3F) << 2,
        ]
    }

    /// Build a Suspend command for the given SEID.
    fn suspend(transaction_label: u8, seid: u8) -> [u8; 3] {
        [
            Self::header_byte(transaction_label, AVDTP_MSG_TYPE_COMMAND),
            AVDTP_SIGNAL_SUSPEND,
            (seid & 0x3F) << 2,
        ]
    }

    /// Build an Abort command for the given SEID.
    fn abort(transaction_label: u8, seid: u8) -> [u8; 3] {
        [
            Self::header_byte(transaction_label, AVDTP_MSG_TYPE_COMMAND),
            AVDTP_SIGNAL_ABORT,
            (seid & 0x3F) << 2,
        ]
    }
}

// ---------------------------------------------------------------------------
// A2DP profile
// ---------------------------------------------------------------------------

/// A2DP source profile.
///
/// Manages the A2DP connection lifecycle and AVDTP signaling for streaming
/// audio to a Bluetooth sink (headphones, speaker).
///
/// Generic over the BT hardware backend (`H: BtHwOps`) for testability.
pub struct A2dpProfile<H: BtHwOps> {
    /// Current A2DP state.
    state: A2dpState,
    /// Bluetooth device address of the peer sink.
    peer_addr: Option<[u8; 6]>,
    /// Configured sample rate (44100 or 48000 Hz).
    sample_rate: u32,
    /// Number of audio channels (1 = mono, 2 = stereo).
    channels: u8,
    /// SBC encoder for audio framing.
    encoder: StubSbcEncoder,
    /// AVDTP transaction label counter (0-15, wraps).
    transaction_label: u8,
    /// Remote stream endpoint ID discovered during signaling.
    remote_seid: u8,
    /// Local stream endpoint ID.
    local_seid: u8,
    /// Bluetooth hardware backend.
    hw: H,
}

impl<H: BtHwOps> A2dpProfile<H> {
    /// Create a new A2DP source profile with default settings.
    ///
    /// Default: 44100 Hz, stereo, SBC high-quality.
    #[must_use]
    pub fn new(hw: H) -> Self {
        Self {
            state: A2dpState::Disconnected,
            peer_addr: None,
            sample_rate: 44100,
            channels: 2,
            encoder: StubSbcEncoder::default_a2dp(),
            transaction_label: 0,
            remote_seid: 0,
            local_seid: 1,
            hw,
        }
    }

    /// Return the current A2DP state.
    #[must_use]
    pub fn state(&self) -> A2dpState {
        self.state
    }

    /// Return the peer device address, if set.
    #[must_use]
    pub fn peer_addr(&self) -> Option<&[u8; 6]> {
        self.peer_addr.as_ref()
    }

    /// Return the configured sample rate.
    #[must_use]
    pub fn sample_rate(&self) -> u32 {
        self.sample_rate
    }

    /// Return the configured channel count.
    #[must_use]
    pub fn channels(&self) -> u8 {
        self.channels
    }

    /// Set the peer device address for A2DP connection.
    pub fn set_peer(&mut self, addr: [u8; 6]) {
        self.peer_addr = Some(addr);
    }

    /// Configure the audio parameters.
    ///
    /// Must be called before `connect()`. Only 44100 and 48000 Hz are
    /// supported; other values default to 44100.
    pub fn configure(&mut self, sample_rate: u32, channels: u8) {
        self.sample_rate = if sample_rate == 48000 { 48000 } else { 44100 };
        self.channels = if channels >= 2 { 2 } else { 1 };

        let header = if self.channels == 1 {
            SbcFrameHeader::mono(self.sample_rate)
        } else {
            let freq = if self.sample_rate == 48000 {
                SBC_FREQ_48000
            } else {
                SBC_FREQ_44100
            };
            SbcFrameHeader {
                sampling_freq: freq,
                ..SbcFrameHeader::default_a2dp()
            }
        };
        self.encoder = StubSbcEncoder::new(header);
    }

    /// Initiate A2DP connection to the configured peer.
    ///
    /// Sends the AVDTP Discover command to begin the signaling sequence.
    /// The full sequence (Discover -> `GetCapabilities` -> `SetConfiguration` ->
    /// Open -> Start) is driven by calling `process_signaling()` after each
    /// response.
    ///
    /// # Errors
    ///
    /// - [`BtAudioError::InvalidState`] -- not in Disconnected state.
    /// - [`BtAudioError::NoPeer`] -- no peer address configured.
    /// - [`BtAudioError::HciError`] -- HCI send failed.
    #[must_use]
    pub fn connect(&mut self) -> Result<(), BtAudioError> {
        if self.state != A2dpState::Disconnected {
            return Err(BtAudioError::InvalidState);
        }
        if self.peer_addr.is_none() {
            return Err(BtAudioError::NoPeer);
        }

        self.state = A2dpState::Connecting;

        // Send AVDTP Discover command.
        let label = self.next_transaction_label();
        let discover = AvdtpMessage::discover(label);
        self.hw.send_command(&discover).map_err(BtAudioError::from)?;

        Ok(())
    }

    /// Advance the AVDTP signaling state machine.
    ///
    /// Called when an AVDTP response is received from the peer.
    /// Drives the signaling sequence to completion:
    ///
    /// 1. After Discover response: send `GetCapabilities`
    /// 2. After `GetCapabilities` response: send `SetConfiguration`
    /// 3. After `SetConfiguration` response: send Open
    /// 4. After Open response: send Start
    /// 5. After Start response: transition to Streaming
    ///
    /// # Errors
    ///
    /// - [`BtAudioError::InvalidState`] -- not in Connecting state.
    /// - [`BtAudioError::AvdtpError`] -- unknown or unexpected signal ID.
    /// - [`BtAudioError::HciError`] -- HCI send failed.
    #[must_use]
    pub fn advance_signaling(&mut self, signal: u8) -> Result<(), BtAudioError> {
        if self.state != A2dpState::Connecting {
            return Err(BtAudioError::InvalidState);
        }

        match signal {
            AVDTP_SIGNAL_DISCOVER => {
                // Received Discover response -- send GetCapabilities.
                let label = self.next_transaction_label();
                let msg = AvdtpMessage::get_capabilities(label, self.remote_seid);
                self.hw.send_command(&msg).map_err(BtAudioError::from)?;
            }
            AVDTP_SIGNAL_GET_CAPABILITIES => {
                // Received GetCapabilities response -- send SetConfiguration.
                let label = self.next_transaction_label();
                let header = *self.encoder.header();
                let msg = AvdtpMessage::set_configuration(
                    label,
                    self.remote_seid,
                    self.local_seid,
                    &header,
                );
                self.hw.send_command(&msg).map_err(BtAudioError::from)?;
            }
            AVDTP_SIGNAL_SET_CONFIGURATION => {
                // Received SetConfiguration response -- send Open.
                let label = self.next_transaction_label();
                let msg = AvdtpMessage::open(label, self.remote_seid);
                self.hw.send_command(&msg).map_err(BtAudioError::from)?;
            }
            AVDTP_SIGNAL_OPEN => {
                // Received Open response -- send Start.
                let label = self.next_transaction_label();
                let msg = AvdtpMessage::start(label, self.remote_seid);
                self.hw.send_command(&msg).map_err(BtAudioError::from)?;
            }
            AVDTP_SIGNAL_START => {
                // Received Start response -- streaming is active.
                self.state = A2dpState::Streaming;
            }
            _ => {
                // Unknown or unexpected signal.
                self.state = A2dpState::Error(BtAudioError::AvdtpError);
                return Err(BtAudioError::AvdtpError);
            }
        }

        Ok(())
    }

    /// Send an SBC-encoded audio frame.
    ///
    /// Encodes the PCM data using the stub encoder and sends it via HCI.
    ///
    /// # Errors
    ///
    /// - [`BtAudioError::InvalidState`] -- not in Streaming state.
    /// - [`BtAudioError::SbcError`] -- SBC encoding failed.
    /// - [`BtAudioError::BufferTooSmall`] -- internal frame buffer too small.
    /// - [`BtAudioError::HciError`] -- HCI send failed.
    #[must_use]
    pub fn send_audio(&mut self, pcm: &[i16]) -> Result<usize, BtAudioError> {
        if self.state != A2dpState::Streaming {
            return Err(BtAudioError::InvalidState);
        }

        let mut frame_buf = [0u8; SBC_MAX_FRAME_SIZE];
        let frame_len = self.encoder.encode(pcm, &mut frame_buf)?;

        self.hw
            .send_command(&frame_buf[..frame_len])
            .map_err(BtAudioError::from)?;

        Ok(frame_len)
    }

    /// Suspend the active audio stream.
    ///
    /// Transitions from Streaming to Connected (stream is open but paused).
    ///
    /// # Errors
    ///
    /// - [`BtAudioError::InvalidState`] -- not in Streaming state.
    /// - [`BtAudioError::HciError`] -- HCI send failed.
    #[must_use]
    pub fn suspend(&mut self) -> Result<(), BtAudioError> {
        if self.state != A2dpState::Streaming {
            return Err(BtAudioError::InvalidState);
        }

        let label = self.next_transaction_label();
        let msg = AvdtpMessage::suspend(label, self.remote_seid);
        self.hw.send_command(&msg).map_err(BtAudioError::from)?;

        self.state = A2dpState::Connected;
        Ok(())
    }

    /// Resume a suspended audio stream.
    ///
    /// Transitions from Connected back to Streaming.
    ///
    /// # Errors
    ///
    /// - [`BtAudioError::InvalidState`] -- not in Connected state.
    /// - [`BtAudioError::HciError`] -- HCI send failed.
    #[must_use]
    pub fn resume(&mut self) -> Result<(), BtAudioError> {
        if self.state != A2dpState::Connected {
            return Err(BtAudioError::InvalidState);
        }

        let label = self.next_transaction_label();
        let msg = AvdtpMessage::start(label, self.remote_seid);
        self.hw.send_command(&msg).map_err(BtAudioError::from)?;

        self.state = A2dpState::Streaming;
        Ok(())
    }

    /// Disconnect the A2DP session.
    ///
    /// Sends AVDTP Close (if connected/streaming) and cleans up state.
    ///
    /// # Errors
    ///
    /// Currently infallible but returns `Result` for API consistency.
    #[must_use]
    #[expect(clippy::unnecessary_wraps, reason = "returns Result for API consistency with other lifecycle methods")]
    pub fn disconnect(&mut self) -> Result<(), BtAudioError> {
        match self.state {
            A2dpState::Streaming => {
                // Suspend first, then close.
                let label = self.next_transaction_label();
                let suspend_msg = AvdtpMessage::suspend(label, self.remote_seid);
                // Best-effort suspend; continue to close even if it fails.
                let _ = self.hw.send_command(&suspend_msg);

                let label = self.next_transaction_label();
                let close_msg = AvdtpMessage::close(label, self.remote_seid);
                let _ = self.hw.send_command(&close_msg);
            }
            A2dpState::Connected | A2dpState::Connecting => {
                let label = self.next_transaction_label();
                let close_msg = AvdtpMessage::close(label, self.remote_seid);
                let _ = self.hw.send_command(&close_msg);
            }
            A2dpState::Disconnected | A2dpState::Error(_) => {
                // Already disconnected or errored, nothing to send.
            }
        }

        self.state = A2dpState::Disconnected;
        self.remote_seid = 0;
        Ok(())
    }

    /// Set the remote stream endpoint ID (normally discovered via AVDTP).
    pub fn set_remote_seid(&mut self, seid: u8) {
        self.remote_seid = seid;
    }

    /// Get the next AVDTP transaction label (0-15, wrapping).
    fn next_transaction_label(&mut self) -> u8 {
        let label = self.transaction_label;
        self.transaction_label = (self.transaction_label + 1) & AVDTP_MAX_TRANSACTION_LABEL;
        label
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bluetooth::MockBtHw;

    /// Helper: create a fresh A2DP profile with a mock BT backend.
    fn make_a2dp() -> A2dpProfile<MockBtHw> {
        A2dpProfile::new(MockBtHw::new())
    }

    #[test]
    fn a2dp_starts_disconnected() {
        let profile = make_a2dp();
        assert_eq!(
            profile.state(),
            A2dpState::Disconnected,
            "new A2DP profile must start in Disconnected state"
        );
        assert!(
            profile.peer_addr().is_none(),
            "peer address must be None initially"
        );
    }

    #[test]
    fn connect_transitions_state() {
        let mut profile = make_a2dp();
        let peer = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        profile.set_peer(peer);

        let result = profile.connect();
        assert!(result.is_ok(), "connect must succeed with peer set");
        assert_eq!(
            profile.state(),
            A2dpState::Connecting,
            "state must be Connecting after connect()"
        );
    }

    #[test]
    fn connect_without_peer_returns_error() {
        let mut profile = make_a2dp();
        let result = profile.connect();
        assert_eq!(
            result,
            Err(BtAudioError::NoPeer),
            "connect without peer must return NoPeer error"
        );
        assert_eq!(
            profile.state(),
            A2dpState::Disconnected,
            "state must remain Disconnected"
        );
    }

    #[test]
    fn sbc_frame_header_valid() {
        let header = SbcFrameHeader::default_a2dp();
        assert!(header.is_valid(), "default A2DP header must be valid");

        let encoded = header.encode();
        assert_eq!(
            encoded[0], SBC_SYNCWORD,
            "first byte must be the SBC syncword 0x9C"
        );
        assert_eq!(
            encoded[2], SBC_DEFAULT_BITPOOL,
            "bitpool byte must match the configured value"
        );

        // Verify the config byte encoding.
        let expected_config = (SBC_FREQ_44100 << 6)
            | (SBC_BLOCKS_16 << 4)
            | (SBC_CHANNEL_JOINT_STEREO << 2)
            | (SBC_ALLOC_LOUDNESS << 1)
            | SBC_SUBBANDS_8;
        assert_eq!(
            encoded[1], expected_config,
            "config byte must encode frequency, blocks, channel mode, alloc, subbands"
        );
    }

    #[test]
    fn sbc_mono_header_valid() {
        let header = SbcFrameHeader::mono(48000);
        assert!(header.is_valid(), "mono header must be valid");
        assert_eq!(
            header.sampling_freq, SBC_FREQ_48000,
            "48kHz must map to frequency index 0"
        );
        assert_eq!(
            header.channel_mode, SBC_CHANNEL_MONO,
            "channel mode must be mono"
        );
    }

    #[test]
    fn sbc_frame_length_calculated() {
        let header = SbcFrameHeader::default_a2dp();
        let len = header.frame_length();
        // 44.1kHz, joint stereo, 16 blocks, 8 subbands, bitpool 53:
        // 4 + (4*8*2)/8 + ceil(1*8 + 16*53)/8 = 4 + 8 + ceil(856)/8 = 4+8+107 = 119
        assert!(
            len > SBC_HEADER_SIZE,
            "frame length must be greater than header size ({len})"
        );
        assert!(
            len < SBC_MAX_FRAME_SIZE,
            "frame length must be within max frame size ({len})"
        );
    }

    #[test]
    fn sbc_invalid_header_detected() {
        let header = SbcFrameHeader {
            sampling_freq: 5, // invalid: max is 3
            blocks: SBC_BLOCKS_16,
            channel_mode: SBC_CHANNEL_JOINT_STEREO,
            alloc_method: SBC_ALLOC_LOUDNESS,
            subbands: SBC_SUBBANDS_8,
            bitpool: SBC_DEFAULT_BITPOOL,
        };
        assert!(
            !header.is_valid(),
            "header with invalid sampling_freq must not validate"
        );
    }

    #[test]
    fn stub_encoder_produces_valid_frame() {
        let mut encoder = StubSbcEncoder::default_a2dp();
        let pcm = [0i16; 256];
        let mut output = [0u8; SBC_MAX_FRAME_SIZE];

        let result = encoder.encode(&pcm, &mut output);
        assert!(result.is_ok(), "stub encoder must succeed");

        let frame_len = result.unwrap_or(0);
        assert!(frame_len > 0, "frame length must be > 0");
        assert_eq!(
            output[0], SBC_SYNCWORD,
            "encoded frame must start with SBC syncword"
        );
    }

    #[test]
    fn stub_encoder_buffer_too_small() {
        let mut encoder = StubSbcEncoder::default_a2dp();
        let pcm = [0i16; 256];
        let mut output = [0u8; 2]; // way too small

        let result = encoder.encode(&pcm, &mut output);
        assert_eq!(
            result,
            Err(BtAudioError::BufferTooSmall),
            "encoding into too-small buffer must return BufferTooSmall"
        );
    }

    #[test]
    fn disconnect_cleans_up() {
        let mut profile = make_a2dp();
        let peer = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        profile.set_peer(peer);
        profile.connect().ok();

        // Walk through signaling to Streaming.
        profile.set_remote_seid(1);
        profile.advance_signaling(AVDTP_SIGNAL_DISCOVER).ok();
        profile.advance_signaling(AVDTP_SIGNAL_GET_CAPABILITIES).ok();
        profile.advance_signaling(AVDTP_SIGNAL_SET_CONFIGURATION).ok();
        profile.advance_signaling(AVDTP_SIGNAL_OPEN).ok();
        profile.advance_signaling(AVDTP_SIGNAL_START).ok();
        assert_eq!(profile.state(), A2dpState::Streaming);

        // Disconnect.
        let result = profile.disconnect();
        assert!(result.is_ok(), "disconnect must succeed");
        assert_eq!(
            profile.state(),
            A2dpState::Disconnected,
            "state must be Disconnected after disconnect"
        );
    }

    #[test]
    fn full_signaling_sequence_reaches_streaming() {
        let mut profile = make_a2dp();
        let peer = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE];
        profile.set_peer(peer);
        profile.set_remote_seid(2);
        profile.connect().ok();

        assert_eq!(profile.state(), A2dpState::Connecting);

        // Drive the full signaling sequence.
        profile.advance_signaling(AVDTP_SIGNAL_DISCOVER).ok();
        assert_eq!(profile.state(), A2dpState::Connecting, "still connecting after discover");

        profile.advance_signaling(AVDTP_SIGNAL_GET_CAPABILITIES).ok();
        assert_eq!(profile.state(), A2dpState::Connecting, "still connecting after get_caps");

        profile.advance_signaling(AVDTP_SIGNAL_SET_CONFIGURATION).ok();
        assert_eq!(profile.state(), A2dpState::Connecting, "still connecting after set_config");

        profile.advance_signaling(AVDTP_SIGNAL_OPEN).ok();
        assert_eq!(profile.state(), A2dpState::Connecting, "still connecting after open");

        profile.advance_signaling(AVDTP_SIGNAL_START).ok();
        assert_eq!(
            profile.state(),
            A2dpState::Streaming,
            "must be Streaming after Start response"
        );
    }

    #[test]
    fn suspend_and_resume() {
        let mut profile = make_a2dp();
        let peer = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        profile.set_peer(peer);
        profile.set_remote_seid(1);
        profile.connect().ok();
        profile.advance_signaling(AVDTP_SIGNAL_DISCOVER).ok();
        profile.advance_signaling(AVDTP_SIGNAL_GET_CAPABILITIES).ok();
        profile.advance_signaling(AVDTP_SIGNAL_SET_CONFIGURATION).ok();
        profile.advance_signaling(AVDTP_SIGNAL_OPEN).ok();
        profile.advance_signaling(AVDTP_SIGNAL_START).ok();

        // Suspend.
        let result = profile.suspend();
        assert!(result.is_ok(), "suspend must succeed");
        assert_eq!(profile.state(), A2dpState::Connected);

        // Resume.
        let result = profile.resume();
        assert!(result.is_ok(), "resume must succeed");
        assert_eq!(profile.state(), A2dpState::Streaming);
    }

    #[test]
    fn send_audio_requires_streaming() {
        let mut profile = make_a2dp();
        let pcm = [0i16; 128];
        let result = profile.send_audio(&pcm);
        assert_eq!(
            result,
            Err(BtAudioError::InvalidState),
            "send_audio in Disconnected state must return InvalidState"
        );
    }

    #[test]
    fn configure_clamps_parameters() {
        let mut profile = make_a2dp();
        profile.configure(96000, 5);
        assert_eq!(
            profile.sample_rate(),
            44100,
            "invalid sample rate must default to 44100"
        );
        assert_eq!(
            profile.channels(),
            2,
            "channels > 2 must clamp to 2"
        );

        profile.configure(48000, 1);
        assert_eq!(profile.sample_rate(), 48000);
        assert_eq!(profile.channels(), 1);
    }

    #[test]
    fn connect_in_wrong_state_returns_error() {
        let mut profile = make_a2dp();
        let peer = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        profile.set_peer(peer);
        profile.connect().ok();

        // Already connecting -- second connect must fail.
        let result = profile.connect();
        assert_eq!(
            result,
            Err(BtAudioError::InvalidState),
            "connect while Connecting must return InvalidState"
        );
    }

    #[test]
    fn avdtp_discover_message_format() {
        let msg = AvdtpMessage::discover(3);
        // Byte 0: label=3 (bits 7:4=0011), packet_type=single (bits 3:2=00),
        //         msg_type=command (bits 1:0=00) => 0x30
        assert_eq!(msg[0], 0x30, "header byte must encode label and types");
        assert_eq!(msg[1], AVDTP_SIGNAL_DISCOVER, "signal must be Discover");
    }

    #[test]
    fn transaction_label_wraps() {
        let mut profile = make_a2dp();
        for _ in 0..20 {
            let label = profile.next_transaction_label();
            assert!(
                label <= AVDTP_MAX_TRANSACTION_LABEL,
                "transaction label {label} must be <= {AVDTP_MAX_TRANSACTION_LABEL}"
            );
        }
    }

    #[test]
    fn disconnect_from_disconnected_is_ok() {
        let mut profile = make_a2dp();
        let result = profile.disconnect();
        assert!(
            result.is_ok(),
            "disconnect from Disconnected must succeed (no-op)"
        );
    }

    #[test]
    fn sbc_crc8_deterministic() {
        let header = SbcFrameHeader::default_a2dp();
        let encoded1 = header.encode();
        let encoded2 = header.encode();
        assert_eq!(
            encoded1[3], encoded2[3],
            "CRC must be deterministic for same input"
        );
    }

    // -- Phase 07 audit: error variant coverage --

    #[test]
    fn sbc_error_on_buffer_too_small() {
        let mut encoder = StubSbcEncoder::default_a2dp();
        let pcm = [0i16; 128];
        let mut tiny_buf = [0u8; 2]; // way too small for any SBC frame
        let result = encoder.encode(&pcm, &mut tiny_buf);
        assert_eq!(
            result,
            Err(BtAudioError::BufferTooSmall),
            "encoding into too-small buffer must return BufferTooSmall"
        );
    }

    #[test]
    fn codec_not_supported_error_display() {
        // BtAudioError::CodecNotSupported is returned during AVDTP capability
        // negotiation when the remote sink does not support SBC. This requires
        // a real BT peer, so we verify the variant is constructable and displays.
        let err = BtAudioError::CodecNotSupported;
        let msg = alloc::format!("{err}");
        assert_eq!(msg, "SBC codec not supported by peer");
    }

    #[test]
    fn sbc_error_variant_display() {
        let err = BtAudioError::SbcError;
        let msg = alloc::format!("{err}");
        assert_eq!(msg, "SBC encoding error");
    }
}
