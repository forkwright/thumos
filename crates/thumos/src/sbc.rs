//! SBC (Sub-Band Coding) codec for Bluetooth A2DP.
//!
//! SBC is the mandatory codec for A2DP audio streaming. This module implements
//! the SBC frame header structure, CRC-8 checksum, encoder trait, and a stub
//! encoder that produces valid frame headers with zeroed audio data.
//!
//! ## Frame format
//!
//! ```text
//! Byte 0: Syncword (0x9C)
//! Byte 1: [sampling_freq:2][blocks:2][channel_mode:2][alloc_method:1][subbands:1]
//! Byte 2: Bitpool value
//! Byte 3: CRC-8 of bytes 1-2 (and channel data for joint stereo)
//! ```
//!
//! ## Future work
//!
//! Replace the stub encoder with a real SBC encoder that implements the
//! analysis filterbank (8 subbands, polyphase), scale factor calculation,
//! bit allocation, quantization, and bitstream packing.

// WHY: A2DP profile not yet wired to audio session manager (Wave 8, kinit pending).
// cfg_attr(not(test), ...): the module's own tests now exercise its full
// surface, so nothing is dead in the test build -- expecting dead_code there
// makes the expectation unfulfilled. Production reachability is unchanged;
// the expectation is scoped to the build where it is still real.
#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "A2DP profile exists; audio manager wiring pending (#753; tier in docs/capability-inventory.toml)"
    )
)]

use crate::bt_audio::BtAudioError;

// ---------------------------------------------------------------------------
// SBC constants (A2DP Spec Appendix B / Bluetooth SIG SBC specification)
// ---------------------------------------------------------------------------

/// SBC syncword (first byte of every SBC frame).
pub(crate) const SBC_SYNCWORD: u8 = 0x9C;

/// SBC sampling frequency: 44100 Hz (index 1).
pub(crate) const SBC_FREQ_44100: u8 = 0x01;

/// SBC sampling frequency: 48000 Hz (index 0).
pub(crate) const SBC_FREQ_48000: u8 = 0x00;

/// SBC channel mode: mono (index 0).
pub(crate) const SBC_CHANNEL_MONO: u8 = 0x00;

/// SBC channel mode: joint stereo (index 3).
pub(crate) const SBC_CHANNEL_JOINT_STEREO: u8 = 0x03;

/// SBC block length: 16 blocks.
pub(crate) const SBC_BLOCKS_16: u8 = 0x03;

/// SBC subbands: 8 subbands.
pub(crate) const SBC_SUBBANDS_8: u8 = 0x01;

/// SBC allocation method: loudness.
pub(crate) const SBC_ALLOC_LOUDNESS: u8 = 0x01;

/// Default SBC bitpool value for high quality stereo (A2DP recommended).
///
/// Bitpool 53 gives ~328 kbps for joint stereo 44.1 kHz, which is the
/// standard "high quality" setting for A2DP.
pub(crate) const SBC_DEFAULT_BITPOOL: u8 = 53;

/// Minimum allowed SBC bitpool (per spec).
pub(crate) const SBC_MIN_BITPOOL: u8 = 2;

/// Maximum allowed SBC bitpool (per spec).
pub(crate) const SBC_MAX_BITPOOL: u8 = 250;

/// SBC frame header size in bytes.
pub(crate) const SBC_HEADER_SIZE: usize = 4;

/// Maximum SBC frame size in bytes (header + scale factors + audio data).
///
/// For 16 blocks, 8 subbands, joint stereo, bitpool 53:
/// `frame_length` = 4 + (4 * 8 * 2 / 8) + ceil(16 * 53 / 8) = 4 + 8 + 106 = 118
/// We use a generous upper bound for any configuration.
pub(crate) const SBC_MAX_FRAME_SIZE: usize = 512;

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
    pub(crate) const fn default_a2dp() -> Self {
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
    pub(crate) const fn mono(sample_rate: u32) -> Self {
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
    pub(crate) fn encode(&self) -> [u8; SBC_HEADER_SIZE] {
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
    pub(crate) const fn frame_length(&self) -> usize {
        let nrof_subbands: usize = if self.subbands == SBC_SUBBANDS_8 {
            8
        } else {
            4
        };
        let nrof_blocks: usize = match self.blocks {
            0 => 4,
            1 => 8,
            2 => 12,
            _ => 16,
        };

        let join = if self.channel_mode == SBC_CHANNEL_JOINT_STEREO {
            1
        } else {
            0
        };
        let nrof_channels: usize = if self.channel_mode == SBC_CHANNEL_MONO {
            1
        } else {
            2
        };

        // frame_length = 4 + (4 * nrof_subbands * nrof_channels) / 8
        //              + ceil(nrof_blocks * bitpool * nrof_channels / 8) (mono/dual)
        //     or        + ceil(nrof_blocks * bitpool / 8) (stereo/joint + join bits)
        //
        // Simplified per spec section 12.9:
        let scale_factors_bytes = (4 * nrof_subbands * nrof_channels) / 8;
        let audio_bits = if self.channel_mode == SBC_CHANNEL_MONO || self.channel_mode == 0x01
        // dual channel
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
    pub(crate) const fn is_valid(&self) -> bool {
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
pub(crate) fn sbc_crc8(config: u8, bitpool: u8) -> u8 {
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
pub(crate) trait SbcEncoder {
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
pub(crate) struct StubSbcEncoder {
    /// Frame header configuration.
    header: SbcFrameHeader,
}

impl StubSbcEncoder {
    /// Create a new stub encoder with the given header configuration.
    #[must_use]
    pub(crate) const fn new(header: SbcFrameHeader) -> Self {
        Self { header }
    }

    /// Create a stub encoder with default A2DP high-quality settings.
    #[must_use]
    pub(crate) const fn default_a2dp() -> Self {
        Self::new(SbcFrameHeader::default_a2dp())
    }

    /// Return the configured frame header.
    #[must_use]
    pub(crate) const fn header(&self) -> &SbcFrameHeader {
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
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

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
    fn sbc_error_variant_display() {
        let err = BtAudioError::SbcError;
        let msg = alloc::format!("{err}");
        assert_eq!(msg, "SBC encoding error");
    }
}
