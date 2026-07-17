//! Ekphrasis: voice-to-text via aletheia STT.
//!
//! ἔκφρασις = "speaking-out-of, bringing into words." Classical rhetoric
//! term for vivid verbal description. For thumos: captures voice audio,
//! streams it to aletheia's STT endpoint over WebSocket, and returns
//! transcribed text.
//!
//! # Architecture
//!
//! Pure transcription only — no local command parsing. When Cody wants
//! to execute actions via voice, he speaks to nous. Nous interprets
//! intent and proposes actions via structured JSON blocks in Matrix
//! messages. The [`ActionProposal`] parser handles that path.
//!
//! Audio capture uses the Phase 07 audio subsystem (via `audio.rs`).
//! Network transport builds HTTP upgrade + WebSocket frames for the
//! caller to send via smoltcp TCP sockets — same pattern as
//! [`crate::http_client`] and [`crate::harmostes`].
//!
//! # WebSocket framing
//!
//! Implements a minimal RFC 6455 frame parser/builder sufficient for
//! streaming binary audio to aletheia and receiving text transcriptions
//! back. Client-to-server frames are masked (per spec); server-to-client
//! frames are unmasked.
//!
//! # Offline behaviour
//!
//! When aletheia is unreachable, voice input is unavailable and the
//! state machine reports [`EkphrasisState::Idle`] with
//! [`Ekphrasis::is_available`] returning false. T9 fallback for typing.
//!
//! # Action proposals from nous
//!
//! Nous can propose thumos actions via structured JSON fence blocks in
//! Matrix messages. [`parse_action_proposal`] detects and parses these
//! blocks into [`ActionProposal`] structs for the confirmation UI
//! (full rendering is Wave 8).

// WHY: ekphrasis created in Phase 09 Wave 6, audio pipeline integration pending.
#![expect(
    dead_code,
    reason = "Ekphrasis created in Phase 09 Wave 6, audio pipeline integration pending (#145)"
)]

extern crate alloc;

use core::fmt;

use alloc::string::String;
use alloc::vec::Vec;

use crate::http_client::{HttpMethod, HttpRequest};
use crate::json_mini::{JsonError, JsonParser, JsonValue};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default STT endpoint path for the WebSocket upgrade.
const STT_WS_PATH: &str = "/stt/stream";

/// WebSocket protocol version (RFC 6455).
const WS_VERSION: &str = "13";

/// Maximum length of partial transcription text held in memory.
/// Prevents unbounded growth from a misbehaving server.
const MAX_PARTIAL_TEXT_LEN: usize = 4096;

/// Maximum length of final transcription text.
const MAX_FINAL_TEXT_LEN: usize = 16_384;

/// Maximum WebSocket frame payload size we will accept (64 KiB).
/// Transcription text frames should be small; this is a safety limit.
const MAX_WS_FRAME_PAYLOAD: usize = 65_536;

/// Maximum number of key-value params in an action proposal.
const MAX_ACTION_PARAMS: usize = 32;

/// Maximum length of the action string in a proposal.
const MAX_ACTION_LEN: usize = 128;

/// Maximum length of the description string in a proposal.
const MAX_DESCRIPTION_LEN: usize = 512;

/// WebSocket magic GUID for the Sec-WebSocket-Accept handshake (RFC 6455
/// §1.3).
const WS_MAGIC_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Audio sample rate for STT (16 kHz mono, per design doc).
const AUDIO_SAMPLE_RATE_HZ: u32 = 16_000;

/// Audio channels for STT capture.
const AUDIO_CHANNELS: u8 = 1;

/// Maximum buffered audio bytes accumulated by `feed_audio` before the
/// buffer is drained via `take_audio_frame`. At the 16 kHz mono 16-bit STT
/// capture rate (32 KB/s), 256 KiB is 8 seconds of un-drained audio —
/// generous headroom for a slow drain cycle on a 1 GB device without
/// leaving the slab allocator exposed to unbounded growth from a stuck
/// audio callback (#363).
const MAX_AUDIO_BUFFER_BYTES: usize = 256 * 1024;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors from ekphrasis voice-to-text operations.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
#[non_exhaustive]
pub enum EkphrasisError {
    /// The aletheia STT endpoint is not reachable.
    EndpointUnreachable,
    /// WebSocket handshake failed or was rejected by the server.
    HandshakeFailed,
    /// The `host` or `ws_key` passed to [`build_ws_upgrade`] contains a
    /// control character (CR, LF, NUL, or other C0/DEL byte) that could
    /// corrupt the HTTP request line or inject additional headers.
    InvalidUpgradeParam,
    /// A WebSocket frame was malformed or violated protocol constraints.
    InvalidFrame,
    /// The frame payload exceeds [`MAX_WS_FRAME_PAYLOAD`].
    PayloadTooLarge,
    /// The transcription text exceeds the maximum length.
    TextTooLong,
    /// Audio capture failed: mic power/codec error, or the buffered audio
    /// reached [`MAX_AUDIO_BUFFER_BYTES`] before being drained (#363).
    AudioCaptureFailed,
    /// The ekphrasis state machine is in an invalid state for the operation.
    InvalidState {
        /// The operation that was attempted.
        operation: &'static str,
        /// The current state (as a string for Display).
        current: &'static str,
    },
    /// JSON parsing error from an action proposal or server response.
    Json(JsonError),
    /// The WebSocket connection was closed by the server.
    ConnectionClosed,
    /// An incomplete frame was received — need more bytes.
    Incomplete,
}

impl fmt::Display for EkphrasisError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EndpointUnreachable => write!(f, "aletheia STT endpoint unreachable"),
            Self::HandshakeFailed => write!(f, "WebSocket handshake failed"),
            Self::InvalidUpgradeParam => write!(f, "invalid WebSocket upgrade parameter"),
            Self::InvalidFrame => write!(f, "invalid WebSocket frame"),
            Self::PayloadTooLarge => write!(f, "WebSocket payload too large"),
            Self::TextTooLong => write!(f, "transcription text exceeds limit"),
            Self::AudioCaptureFailed => write!(f, "audio capture failed"),
            Self::InvalidState { operation, current } => {
                write!(f, "cannot {operation} in state {current}")
            }
            Self::Json(e) => write!(f, "JSON error: {e}"),
            Self::ConnectionClosed => write!(f, "WebSocket connection closed"),
            Self::Incomplete => write!(f, "incomplete WebSocket frame"),
        }
    }
}

impl From<JsonError> for EkphrasisError {
    fn from(e: JsonError) -> Self {
        Self::Json(e)
    }
}

// ---------------------------------------------------------------------------
// WebSocket frame types
// ---------------------------------------------------------------------------

/// WebSocket opcode (RFC 6455 section 5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum WsOpcode {
    /// UTF-8 text frame (opcode 0x1).
    Text,
    /// Binary data frame (opcode 0x2).
    Binary,
    /// Connection close (opcode 0x8).
    Close,
    /// Ping (opcode 0x9).
    Ping,
    /// Pong (opcode 0xA).
    Pong,
}

impl WsOpcode {
    /// Convert a raw opcode byte to `WsOpcode`.
    fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x1 => Some(Self::Text),
            0x2 => Some(Self::Binary),
            0x8 => Some(Self::Close),
            0x9 => Some(Self::Ping),
            0xA => Some(Self::Pong),
            _ => None,
        }
    }

    /// Return the raw opcode byte value.
    const fn as_byte(self) -> u8 {
        match self {
            Self::Text => 0x1,
            Self::Binary => 0x2,
            Self::Close => 0x8,
            Self::Ping => 0x9,
            Self::Pong => 0xA,
        }
    }
}

impl fmt::Display for WsOpcode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Text => write!(f, "text"),
            Self::Binary => write!(f, "binary"),
            Self::Close => write!(f, "close"),
            Self::Ping => write!(f, "ping"),
            Self::Pong => write!(f, "pong"),
        }
    }
}

/// A parsed WebSocket frame.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
#[non_exhaustive]
pub struct WsFrame {
    /// The frame opcode indicating the type of data.
    pub opcode: WsOpcode,
    /// The frame payload bytes.
    pub payload: Vec<u8>,
}

impl WsFrame {
    /// Create a new frame with the given opcode and payload.
    #[must_use]
    pub(crate) fn new(opcode: WsOpcode, payload: Vec<u8>) -> Self {
        Self { opcode, payload }
    }
}

impl fmt::Display for WsFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "WsFrame({}, {} bytes)", self.opcode, self.payload.len())
    }
}

// ---------------------------------------------------------------------------
// WebSocket frame parsing (RFC 6455)
// ---------------------------------------------------------------------------

/// Parse a single WebSocket frame from the given data buffer.
///
/// Returns the parsed frame and the number of bytes consumed from the input.
/// Server-to-client frames are expected to be unmasked (per RFC 6455).
///
/// # Errors
///
/// - [`EkphrasisError::Incomplete`] if the buffer doesn't contain a full frame.
/// - [`EkphrasisError::InvalidFrame`] if the opcode is unknown.
/// - [`EkphrasisError::PayloadTooLarge`] if the payload exceeds the limit.
#[must_use]
pub(crate) fn parse_ws_frame(data: &[u8]) -> Result<(WsFrame, usize), EkphrasisError> {
    // Minimum frame size: 2 bytes (FIN+opcode, MASK+payload-len).
    if data.len() < 2 {
        return Err(EkphrasisError::Incomplete);
    }

    let byte0 = data[0];
    let byte1 = data[1];

    // RFC 6455 §5.2: RSV1-3 (bits 4-6 of byte 0) are reserved for
    // extensions thumos does not negotiate. A nonzero value means either
    // an unsupported extension or a malformed/adversarial frame; reject
    // rather than silently ignore.
    if byte0 & 0x70 != 0 {
        return Err(EkphrasisError::InvalidFrame);
    }

    // FIN bit (bit 7). thumos implements no continuation-frame reassembly
    // state machine (opcode 0x0 "continuation" is not a WsOpcode variant),
    // so a fragmented message (FIN=0) is rejected cleanly here instead of
    // being silently parsed as if it were a complete frame.
    if byte0 & 0x80 == 0 {
        return Err(EkphrasisError::InvalidFrame);
    }

    // Extract opcode from lower 4 bits of byte 0.
    let opcode_raw = byte0 & 0x0F;
    let opcode = WsOpcode::from_byte(opcode_raw).ok_or(EkphrasisError::InvalidFrame)?;

    // Mask bit and initial payload length from byte 1.
    let masked = (byte1 & 0x80) != 0;
    let len_indicator = byte1 & 0x7F;

    // Determine actual payload length and header size.
    let (payload_len, header_size) = if len_indicator < 126 {
        (len_indicator as usize, 2_usize)
    } else if len_indicator == 126 {
        // Next 2 bytes are the length (big-endian u16).
        if data.len() < 4 {
            return Err(EkphrasisError::Incomplete);
        }
        let len = u16::from_be_bytes([data[2], data[3]]) as usize;
        (len, 4_usize)
    } else {
        // len_indicator == 127: next 8 bytes are the length (big-endian u64).
        if data.len() < 10 {
            return Err(EkphrasisError::Incomplete);
        }
        let len = u64::from_be_bytes([
            data[2], data[3], data[4], data[5], data[6], data[7], data[8], data[9],
        ]) as usize;
        (len, 10_usize)
    };

    if payload_len > MAX_WS_FRAME_PAYLOAD {
        return Err(EkphrasisError::PayloadTooLarge);
    }

    // Account for masking key (4 bytes) if mask bit is set.
    let mask_size = if masked { 4 } else { 0 };
    let total_frame_size = header_size + mask_size + payload_len;

    if data.len() < total_frame_size {
        return Err(EkphrasisError::Incomplete);
    }

    // Extract and unmask payload.
    let payload_start = header_size + mask_size;
    let mut payload = data[payload_start..payload_start + payload_len].to_vec();

    if masked {
        let mask_key = &data[header_size..header_size + 4];
        for (i, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask_key[i % 4];
        }
    }

    Ok((WsFrame::new(opcode, payload), total_frame_size))
}

/// Build a WebSocket frame with client-to-server masking.
///
/// Per RFC 6455, all client-to-server frames MUST be masked. The mask key
/// is provided by the caller (should be random per frame in production;
/// a fixed key is acceptable for testing).
///
/// Returns the complete frame bytes ready to send over the wire.
#[must_use]
pub(crate) fn build_ws_frame(opcode: WsOpcode, payload: &[u8], mask_key: [u8; 4]) -> Vec<u8> {
    let payload_len = payload.len();

    // Calculate frame size: 2 (header) + extended length + 4 (mask) + payload.
    let extended_len_size = if payload_len < 126 {
        0
    } else if payload_len <= 0xFFFF {
        2
    } else {
        8
    };
    let frame_size = 2 + extended_len_size + 4 + payload_len;
    let mut frame = Vec::with_capacity(frame_size);

    // Byte 0: FIN bit (1) + opcode.
    frame.push(0x80 | opcode.as_byte());

    // Byte 1: MASK bit (1) + payload length.
    if payload_len < 126 {
        frame.push(0x80 | (payload_len as u8));
    } else if payload_len <= 0xFFFF {
        frame.push(0x80 | 126);
        frame.extend_from_slice(&(payload_len as u16).to_be_bytes());
    } else {
        frame.push(0x80 | 127);
        frame.extend_from_slice(&(payload_len as u64).to_be_bytes());
    }

    // Masking key (4 bytes).
    frame.extend_from_slice(&mask_key);

    // Masked payload.
    for (i, &byte) in payload.iter().enumerate() {
        frame.push(byte ^ mask_key[i % 4]);
    }

    frame
}

// ---------------------------------------------------------------------------
// WebSocket upgrade request
// ---------------------------------------------------------------------------

/// Return true if `s` contains a byte that could corrupt an HTTP header
/// or request line if written verbatim: a C0 control byte (including CR,
/// LF, NUL) or DEL.
fn contains_control_byte(s: &str) -> bool {
    s.bytes().any(|b| b < 0x20 || b == 0x7F)
}

/// Build an HTTP/1.1 WebSocket upgrade request for the aletheia STT endpoint.
///
/// The `ws_key` should be a base64-encoded 16-byte random value (per
/// RFC 6455 section 4.1). The caller is responsible for generating it
/// from the kernel CSPRNG.
///
/// Returns an [`HttpRequest`] that can be serialized with `build_raw()`
/// and sent over a TCP socket.
///
/// # Errors
///
/// Returns [`EkphrasisError::InvalidUpgradeParam`] if `host` or `ws_key`
/// contains a control character (CR, LF, NUL, etc.) that could corrupt
/// the HTTP request line or inject additional headers.
#[must_use]
pub(crate) fn build_ws_upgrade(
    host: &str,
    path: &str,
    ws_key: &str,
) -> Result<HttpRequest, EkphrasisError> {
    if contains_control_byte(host) || contains_control_byte(ws_key) {
        return Err(EkphrasisError::InvalidUpgradeParam);
    }

    let mut req = HttpRequest::new(HttpMethod::Get, String::from(host), String::from(path));

    req.add_header(String::from("Upgrade"), String::from("websocket"));
    req.add_header(String::from("Connection"), String::from("Upgrade"));
    req.add_header(String::from("Sec-WebSocket-Key"), String::from(ws_key));
    req.add_header(
        String::from("Sec-WebSocket-Version"),
        String::from(WS_VERSION),
    );
    // Request binary subprotocol for audio streaming.
    req.add_header(
        String::from("Sec-WebSocket-Protocol"),
        String::from("stt-audio"),
    );

    Ok(req)
}

/// Verify a server's `Sec-WebSocket-Accept` header value against the
/// client key sent in the upgrade request (RFC 6455 §4.1 / §4.2.2):
/// `base64(SHA-1(client_key + WS_MAGIC_GUID))`.
///
/// Fails closed: any mismatch -- including a missing or malformed header --
/// is rejected. Without this check, ANY HTTP 101 response would be accepted
/// as a valid WebSocket upgrade regardless of which server produced it,
/// since `WS_MAGIC_GUID` was previously dead code with no verification path
/// wired to it.
///
/// # Errors
///
/// Returns [`EkphrasisError::HandshakeFailed`] if `server_accept` does not
/// match the value computed from `client_key`.
pub(crate) fn verify_ws_accept(
    client_key: &str,
    server_accept: &str,
) -> Result<(), EkphrasisError> {
    if compute_ws_accept(client_key) == server_accept {
        Ok(())
    } else {
        Err(EkphrasisError::HandshakeFailed)
    }
}

/// Compute the expected `Sec-WebSocket-Accept` value for `client_key`.
#[must_use]
pub(crate) fn compute_ws_accept(client_key: &str) -> String {
    let mut input = Vec::with_capacity(client_key.len() + WS_MAGIC_GUID.len());
    input.extend_from_slice(client_key.as_bytes());
    input.extend_from_slice(WS_MAGIC_GUID.as_bytes());
    base64_encode(&crate::security::sha1(&input))
}

/// Encode bytes as standard padded base64 (RFC 4648 §4).
fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied();
        let b2 = chunk.get(2).copied();

        out.push(ALPHABET[(b0 >> 2) as usize] as char);
        out.push(ALPHABET[(((b0 & 0x03) << 4) | (b1.unwrap_or(0) >> 4)) as usize] as char);
        out.push(match b1 {
            Some(b1) => ALPHABET[(((b1 & 0x0F) << 2) | (b2.unwrap_or(0) >> 6)) as usize] as char,
            None => '=',
        });
        out.push(match b2 {
            Some(b2) => ALPHABET[(b2 & 0x3F) as usize] as char,
            None => '=',
        });
    }
    out
}

// ---------------------------------------------------------------------------
// Ekphrasis state machine
// ---------------------------------------------------------------------------

/// State of the ekphrasis voice-to-text subsystem.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
#[non_exhaustive]
pub enum EkphrasisState {
    /// No recording in progress, ready for input.
    Idle,
    /// Mic capture is active, audio is being buffered.
    Recording,
    /// Audio is being streamed to aletheia over WebSocket.
    Streaming,
    /// Waiting for partial or final transcription from aletheia.
    Transcribing,
    /// An error occurred; the error is preserved for inspection.
    Error(EkphrasisError),
}

impl EkphrasisState {
    /// Return a static string label for the current state.
    fn label(&self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Recording => "recording",
            Self::Streaming => "streaming",
            Self::Transcribing => "transcribing",
            Self::Error(_) => "error",
        }
    }
}

impl fmt::Display for EkphrasisState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Error(e) => write!(f, "error: {e}"),
            other => f.write_str(other.label()),
        }
    }
}

// ---------------------------------------------------------------------------
// Audio configuration (for audio subsystem integration)
// ---------------------------------------------------------------------------

/// Audio capture configuration for STT streaming.
///
/// Passed to the audio subsystem when requesting mic capture.
/// Values match the aletheia whisper endpoint expectations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub struct AudioCaptureConfig {
    /// Sample rate in Hz (16 kHz for STT).
    pub sample_rate_hz: u32,
    /// Number of audio channels (1 = mono).
    pub channels: u8,
    /// Bits per sample (16-bit PCM).
    pub bits_per_sample: u8,
}

impl AudioCaptureConfig {
    /// Configuration for STT audio capture (16 kHz, mono, 16-bit PCM).
    #[must_use]
    pub(crate) const fn stt_default() -> Self {
        Self {
            sample_rate_hz: AUDIO_SAMPLE_RATE_HZ,
            channels: AUDIO_CHANNELS,
            bits_per_sample: 16,
        }
    }
}

impl fmt::Display for AudioCaptureConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}Hz {}ch {}bit",
            self.sample_rate_hz, self.channels, self.bits_per_sample
        )
    }
}

// ---------------------------------------------------------------------------
// Ekphrasis core struct
// ---------------------------------------------------------------------------

/// Voice-to-text subsystem that streams audio to aletheia for transcription.
///
/// `Ekphrasis` is a state machine that manages the lifecycle of a voice
/// recording session: start capture, stream audio over WebSocket to
/// aletheia's STT endpoint, receive partial/final transcriptions, and
/// deliver the result to the active text field.
///
/// # Integration
///
/// - Audio capture: requests mic power via the Phase 07 audio subsystem
/// - Network: builds HTTP upgrade + WebSocket frames for the caller to
///   send via smoltcp TCP sockets
/// - UI: provides partial/final text for the active text field
pub(crate) struct Ekphrasis {
    /// Current state of the voice-to-text pipeline.
    state: EkphrasisState,
    /// Aletheia STT endpoint hostname (e.g., "stt.example.lan" or Tailscale IP).
    aletheia_host: String,
    /// Aletheia STT endpoint port.
    aletheia_port: u16,
    /// Partial transcription text as it arrives (word by word).
    partial_text: String,
    /// Completed transcription after recording stops.
    final_text: String,
    /// Audio capture configuration.
    capture_config: AudioCaptureConfig,
    /// Whether the aletheia endpoint has been confirmed reachable.
    endpoint_reachable: bool,
    /// Audio buffer for captured samples before streaming.
    audio_buffer: Vec<u8>,
}

impl Ekphrasis {
    /// Create a new ekphrasis instance targeting the given aletheia host.
    ///
    /// Starts in [`EkphrasisState::Idle`] with empty transcription buffers.
    #[must_use]
    pub(crate) fn new(host: &str, port: u16) -> Self {
        Self {
            state: EkphrasisState::Idle,
            aletheia_host: String::from(host),
            aletheia_port: port,
            partial_text: String::new(),
            final_text: String::new(),
            capture_config: AudioCaptureConfig::stt_default(),
            endpoint_reachable: false,
            audio_buffer: Vec::new(),
        }
    }

    /// Begin voice recording for STT.
    ///
    /// Transitions from `Idle` to `Recording`. The caller should then:
    /// 1. Power up the mic via the audio subsystem
    /// 2. Open a TCP connection to `aletheia_host:aletheia_port`
    /// 3. Send the WebSocket upgrade request from [`Self::ws_upgrade_request`]
    /// 4. Begin feeding audio data via [`Self::feed_audio`]
    ///
    /// # Errors
    ///
    /// Returns [`EkphrasisError::InvalidState`] if not in `Idle` state.
    /// Returns [`EkphrasisError::EndpointUnreachable`] if the endpoint
    /// has not been marked reachable.
    pub(crate) fn start_recording(&mut self) -> Result<(), EkphrasisError> {
        if !self.endpoint_reachable {
            return Err(EkphrasisError::EndpointUnreachable);
        }

        match &self.state {
            EkphrasisState::Idle => {
                self.partial_text.clear();
                self.final_text.clear();
                self.audio_buffer.clear();
                self.state = EkphrasisState::Recording;
                Ok(())
            }
            other => Err(EkphrasisError::InvalidState {
                operation: "start_recording",
                current: other.label(),
            }),
        }
    }

    /// Transition from `Recording` to `Streaming`.
    ///
    /// Called after the WebSocket connection is established. Audio data
    /// fed via [`Self::feed_audio`] will be framed for transmission.
    ///
    /// # Errors
    ///
    /// Returns [`EkphrasisError::InvalidState`] if not in `Recording` state.
    pub(crate) fn begin_streaming(&mut self) -> Result<(), EkphrasisError> {
        match &self.state {
            EkphrasisState::Recording => {
                self.state = EkphrasisState::Streaming;
                Ok(())
            }
            other => Err(EkphrasisError::InvalidState {
                operation: "begin_streaming",
                current: other.label(),
            }),
        }
    }

    /// Feed captured audio data into the buffer.
    ///
    /// Called by the audio capture callback with raw PCM samples.
    /// In `Streaming` state, the data is available for framing via
    /// [`Self::take_audio_frame`].
    ///
    /// # Errors
    ///
    /// Returns [`EkphrasisError::InvalidState`] if not in `Recording`
    /// or `Streaming` state. Returns [`EkphrasisError::AudioCaptureFailed`]
    /// if appending `data` would exceed [`MAX_AUDIO_BUFFER_BYTES`] — the
    /// caller should stop capture (#363).
    pub(crate) fn feed_audio(&mut self, data: &[u8]) -> Result<(), EkphrasisError> {
        match &self.state {
            EkphrasisState::Recording | EkphrasisState::Streaming => {
                if self.audio_buffer.len().saturating_add(data.len()) > MAX_AUDIO_BUFFER_BYTES {
                    return Err(EkphrasisError::AudioCaptureFailed);
                }
                self.audio_buffer.extend_from_slice(data);
                Ok(())
            }
            other => Err(EkphrasisError::InvalidState {
                operation: "feed_audio",
                current: other.label(),
            }),
        }
    }

    /// Take buffered audio data as a WebSocket binary frame.
    ///
    /// Drains the audio buffer and returns a masked WebSocket frame
    /// ready to send. Returns `None` if the buffer is empty.
    ///
    /// The `mask_key` should be a 4-byte random value from the CSPRNG.
    #[must_use]
    pub(crate) fn take_audio_frame(&mut self, mask_key: [u8; 4]) -> Option<Vec<u8>> {
        if self.audio_buffer.is_empty() {
            return None;
        }

        let payload: Vec<u8> = core::mem::take(&mut self.audio_buffer);
        Some(build_ws_frame(WsOpcode::Binary, &payload, mask_key))
    }

    /// Process a received WebSocket frame from aletheia.
    ///
    /// Text frames contain transcription results (partial or final).
    /// The caller should parse received TCP data with [`parse_ws_frame`]
    /// and pass the resulting frames here.
    ///
    /// # Errors
    ///
    /// Returns an error if the frame contains invalid JSON or if the
    /// transcription text exceeds the length limit.
    pub(crate) fn handle_server_frame(&mut self, frame: &WsFrame) -> Result<(), EkphrasisError> {
        // WHY: without this guard, a frame arriving while Idle (no session
        // active) or already Error (needs an explicit reset()) was processed
        // exactly like a frame arriving mid-session -- silently transitioning
        // the state machine OUT of Error on a stray frame.
        if matches!(self.state, EkphrasisState::Idle | EkphrasisState::Error(_)) {
            return Err(EkphrasisError::InvalidState {
                operation: "handle_server_frame",
                current: self.state.label(),
            });
        }

        match frame.opcode {
            WsOpcode::Text => {
                // Parse the text payload as a transcription response.
                let result = core::str::from_utf8(&frame.payload)
                    .map_err(|_| EkphrasisError::InvalidFrame)
                    .and_then(|text| self.process_transcription(text));
                if let Err(ref err) = result {
                    // WHY: a malformed/corrupt server response (bad UTF-8,
                    // invalid JSON, missing "text" field, oversized text)
                    // leaves the stream untrustworthy -- move to Error so
                    // the caller must call reset() explicitly instead of
                    // silently retrying on the next frame. This is the
                    // transition the Idle|Error guard above assumes exists.
                    self.state = EkphrasisState::Error(err.clone());
                }
                result
            }
            WsOpcode::Close => {
                self.state = EkphrasisState::Idle;
                Err(EkphrasisError::ConnectionClosed)
            }
            WsOpcode::Ping => {
                // Pong is handled by the caller at the transport level.
                Ok(())
            }
            WsOpcode::Pong | WsOpcode::Binary => Ok(()),
        }
    }

    /// Process a transcription text response from aletheia.
    ///
    /// The response is expected to be JSON with at least a "text" field
    /// and an optional "final" boolean:
    ///
    /// ```json
    /// {"text": "hello world", "final": false}
    /// ```
    fn process_transcription(&mut self, text: &str) -> Result<(), EkphrasisError> {
        let value = JsonParser::parse(text.as_bytes())?;

        // WHY: a missing/non-string "text" field previously fell back to ""
        // silently -- indistinguishable from the server legitimately sending
        // an empty transcript. Error instead so a malformed response is
        // surfaced rather than swallowed.
        let transcript = value
            .get("text")
            .and_then(JsonValue::as_str)
            .ok_or(EkphrasisError::InvalidFrame)?;

        let is_final = value
            .get("final")
            .and_then(JsonValue::as_bool)
            .unwrap_or(false);

        if is_final {
            if transcript.len() > MAX_FINAL_TEXT_LEN {
                return Err(EkphrasisError::TextTooLong);
            }
            self.final_text.clear();
            self.final_text.push_str(transcript);
            self.state = EkphrasisState::Idle;
        } else {
            if transcript.len() > MAX_PARTIAL_TEXT_LEN {
                return Err(EkphrasisError::TextTooLong);
            }
            self.partial_text.clear();
            self.partial_text.push_str(transcript);
            // Remain in streaming/transcribing state.
            if self.state == EkphrasisState::Streaming {
                self.state = EkphrasisState::Transcribing;
            }
        }

        Ok(())
    }

    /// Stop recording and return the final transcription.
    ///
    /// Sends a close frame (returned for the caller to transmit) and
    /// transitions to `Idle`. Returns the final transcription text
    /// accumulated so far.
    ///
    /// # Errors
    ///
    /// Returns [`EkphrasisError::InvalidState`] if not in a recording,
    /// streaming, or transcribing state.
    pub(crate) fn stop_recording(&mut self) -> Result<String, EkphrasisError> {
        match &self.state {
            EkphrasisState::Recording
            | EkphrasisState::Streaming
            | EkphrasisState::Transcribing => {
                self.audio_buffer.clear();
                self.state = EkphrasisState::Idle;

                // Return final text if available, otherwise partial.
                let result = if !self.final_text.is_empty() {
                    self.final_text.clone()
                } else {
                    self.partial_text.clone()
                };

                Ok(result)
            }
            other => Err(EkphrasisError::InvalidState {
                operation: "stop_recording",
                current: other.label(),
            }),
        }
    }

    /// Return the current partial transcription text.
    #[must_use]
    pub(crate) fn partial_text(&self) -> &str {
        &self.partial_text
    }

    /// Return the completed final transcription text.
    #[must_use]
    pub(crate) fn final_text(&self) -> &str {
        &self.final_text
    }

    /// Return true if a recording is currently in progress.
    #[must_use]
    pub(crate) fn is_recording(&self) -> bool {
        matches!(
            self.state,
            EkphrasisState::Recording | EkphrasisState::Streaming | EkphrasisState::Transcribing
        )
    }

    /// Return true if the aletheia STT endpoint is considered reachable.
    ///
    /// This reflects the last known reachability state. The caller is
    /// responsible for probing the endpoint (e.g., TCP connect attempt)
    /// and calling [`Self::set_endpoint_reachable`] to update.
    #[must_use]
    pub(crate) fn is_available(&self) -> bool {
        self.endpoint_reachable
    }

    /// Update the endpoint reachability status.
    ///
    /// Called by the network layer after probing the aletheia STT
    /// endpoint (TCP connect or health check).
    pub(crate) fn set_endpoint_reachable(&mut self, reachable: bool) {
        self.endpoint_reachable = reachable;
    }

    /// Return a reference to the current state.
    #[must_use]
    pub(crate) fn state(&self) -> &EkphrasisState {
        &self.state
    }

    /// Return the aletheia host.
    #[must_use]
    pub(crate) fn host(&self) -> &str {
        &self.aletheia_host
    }

    /// Return the aletheia port.
    #[must_use]
    pub(crate) fn port(&self) -> u16 {
        self.aletheia_port
    }

    /// Return the audio capture configuration.
    #[must_use]
    pub(crate) fn capture_config(&self) -> AudioCaptureConfig {
        self.capture_config
    }

    /// Build a WebSocket upgrade request for the STT endpoint.
    ///
    /// The `ws_key` should be a base64-encoded 16-byte random value.
    ///
    /// # Errors
    ///
    /// Returns [`EkphrasisError::InvalidUpgradeParam`] if the configured
    /// host or `ws_key` contains a control character.
    pub(crate) fn ws_upgrade_request(&self, ws_key: &str) -> Result<HttpRequest, EkphrasisError> {
        build_ws_upgrade(&self.aletheia_host, STT_WS_PATH, ws_key)
    }

    /// Build a WebSocket close frame for clean shutdown.
    ///
    /// The `mask_key` should be a 4-byte random value from the CSPRNG.
    #[must_use]
    pub(crate) fn build_close_frame(mask_key: [u8; 4]) -> Vec<u8> {
        // Close frame with empty payload (normal closure, no status code).
        build_ws_frame(WsOpcode::Close, &[], mask_key)
    }

    /// Reset the state machine to idle, clearing all buffers.
    ///
    /// Used for error recovery when the state machine gets stuck.
    pub(crate) fn reset(&mut self) {
        self.state = EkphrasisState::Idle;
        self.partial_text.clear();
        self.final_text.clear();
        self.audio_buffer.clear();
    }
}

impl fmt::Display for Ekphrasis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ekphrasis({}:{}, state={})",
            self.aletheia_host, self.aletheia_port, self.state
        )
    }
}

// ---------------------------------------------------------------------------
// Action proposal types
// ---------------------------------------------------------------------------

/// A proposed thumos action from a nous entity.
///
/// When a user speaks to nous and expresses intent (e.g., "call Maria"),
/// nous responds with a structured JSON block that thumos can parse into
/// an action proposal. The user is shown a confirmation card before
/// execution.
///
/// # Format
///
/// The JSON block appears inside a fenced code block in the Matrix
/// message body:
///
/// ```text
/// ~~~thumos-action
/// {
///   "thumos_action": "open_dialer",
///   "params": {"contact_name": "Maria", "number": "+1555..."},
///   "description": "Call Maria"
/// }
/// ~~~
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
#[non_exhaustive]
pub struct ActionProposal {
    /// The action identifier (e.g., "open_dialer", "draft_sms").
    pub action: String,
    /// Key-value parameters for the action.
    pub params: Vec<(String, String)>,
    /// Human-readable description shown in the confirmation card.
    pub description: String,
}

impl ActionProposal {
    /// Create a new action proposal.
    #[must_use]
    pub(crate) fn new(action: String, params: Vec<(String, String)>, description: String) -> Self {
        Self {
            action,
            params,
            description,
        }
    }

    /// Look up a parameter value by key.
    #[must_use]
    pub(crate) fn param(&self, key: &str) -> Option<&str> {
        self.params
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }
}

impl fmt::Display for ActionProposal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "action({}): {}", self.action, self.description)
    }
}

// ---------------------------------------------------------------------------
// Known action types (thumos-defined vocabulary)
// ---------------------------------------------------------------------------

/// Known action types that nous can propose.
///
/// The parser accepts any action string, but these constants define the
/// vocabulary thumos recognizes for dispatch.
pub(crate) mod action_types {
    /// Open the dialer with a contact/number pre-populated.
    pub(crate) const OPEN_DIALER: &str = "open_dialer";
    /// Draft an SMS with recipient and body.
    pub(crate) const DRAFT_SMS: &str = "draft_sms";
    /// Draft a Matrix message with recipient and body.
    pub(crate) const DRAFT_MATRIX_MESSAGE: &str = "draft_matrix_message";
    /// Start a timer with a duration.
    pub(crate) const START_TIMER: &str = "start_timer";
    /// Set an alarm with time and label.
    pub(crate) const SET_ALARM: &str = "set_alarm";
    /// Add a calendar event.
    pub(crate) const ADD_CALENDAR_EVENT: &str = "add_calendar_event";
    /// Toggle security mode (Sentinel, Covert, etc.).
    pub(crate) const TOGGLE_MODE: &str = "toggle_mode";
    /// Toggle a specific radio (WiFi, cellular, Bluetooth).
    pub(crate) const TOGGLE_RADIO: &str = "toggle_radio";
    /// Navigate to a thumos function/screen.
    pub(crate) const OPEN_FEATURE: &str = "open_feature";
    /// Initiate a security scan (Phase 10).
    pub(crate) const SCAN_START: &str = "scan_start";
    /// Add the current WiFi network to safe networks.
    pub(crate) const ADD_SAFE_NETWORK: &str = "add_safe_network";

    /// All known action type strings, for validation.
    pub(crate) const ALL: &[&str] = &[
        OPEN_DIALER,
        DRAFT_SMS,
        DRAFT_MATRIX_MESSAGE,
        START_TIMER,
        SET_ALARM,
        ADD_CALENDAR_EVENT,
        TOGGLE_MODE,
        TOGGLE_RADIO,
        OPEN_FEATURE,
        SCAN_START,
        ADD_SAFE_NETWORK,
    ];

    /// Check whether an action string is a known type.
    pub(crate) fn is_known(action: &str) -> bool {
        ALL.contains(&action)
    }
}

// ---------------------------------------------------------------------------
// Action proposal parsing
// ---------------------------------------------------------------------------

/// Fence block delimiters for action proposals in Matrix messages.
const FENCE_START: &str = "```thumos-action\n";
const FENCE_START_ALT: &str = "~~~thumos-action\n";
const FENCE_END: &str = "\n```";
const FENCE_END_ALT: &str = "\n~~~";

/// Parse an action proposal from a Matrix message body.
///
/// Detects a fenced JSON block with the `thumos-action` language tag
/// and parses the enclosed JSON into an [`ActionProposal`].
///
/// Returns `None` if no action proposal block is found in the message.
/// Returns `Some(Err(...))` if a block is found but the JSON is invalid.
///
/// # Format
///
/// ```text
/// Some conversational text from nous...
///
/// ```thumos-action
/// {
///   "thumos_action": "open_dialer",
///   "params": {"contact_name": "Maria"},
///   "description": "Call Maria"
/// }
/// ```
/// ```
#[must_use]
pub(crate) fn parse_action_proposal(
    message_body: &str,
) -> Option<Result<ActionProposal, EkphrasisError>> {
    // Try both fence styles.
    let (json_str, _) = find_fenced_block(message_body)?;

    Some(parse_proposal_json(json_str))
}

/// Find a thumos-action fenced block in the message and return its contents.
///
/// Returns the JSON string and the byte offset past the closing fence.
fn find_fenced_block(message: &str) -> Option<(&str, usize)> {
    // Try ``` style first, then ~~~ style.
    if let Some(result) = try_find_fence(message, FENCE_START, FENCE_END) {
        return Some(result);
    }
    try_find_fence(message, FENCE_START_ALT, FENCE_END_ALT)
}

/// Try to find a fenced block with the given delimiters. `end_marker` must
/// already include its leading newline (see FENCE_END / FENCE_END_ALT).
fn try_find_fence<'a>(
    message: &'a str,
    start_marker: &str,
    end_marker: &str,
) -> Option<(&'a str, usize)> {
    let start_pos = message.find(start_marker)?;
    let content_start = start_pos + start_marker.len();
    let remaining = &message[content_start..];

    // Find the closing fence. end_marker already carries the leading
    // newline (FENCE_END / FENCE_END_ALT), so the closing fence must be on
    // its own line -- with no per-parse heap allocation to build the
    // pattern (previously alloc::format!("\n{end_marker}") ran once per
    // parse call).
    let end_pos = remaining.find(end_marker)?;

    let json_str = &remaining[..end_pos];
    let total_consumed = content_start + end_pos + end_marker.len();

    Some((json_str, total_consumed))
}

/// Parse the JSON contents of an action proposal block.
fn parse_proposal_json(json_str: &str) -> Result<ActionProposal, EkphrasisError> {
    let value = JsonParser::parse(json_str.trim().as_bytes())?;

    // Extract required "thumos_action" field.
    let action = value
        .get("thumos_action")
        .and_then(JsonValue::as_str)
        .ok_or(EkphrasisError::InvalidFrame)?;

    if action.len() > MAX_ACTION_LEN {
        return Err(EkphrasisError::TextTooLong);
    }

    // Extract required "description" field.
    let description = value
        .get("description")
        .and_then(JsonValue::as_str)
        .ok_or(EkphrasisError::InvalidFrame)?;

    if description.len() > MAX_DESCRIPTION_LEN {
        return Err(EkphrasisError::TextTooLong);
    }

    // Extract optional "params" object — flatten to key-value pairs.
    let mut params = Vec::new();
    if let Some(params_obj) = value.get("params").and_then(JsonValue::as_object) {
        if params_obj.len() > MAX_ACTION_PARAMS {
            return Err(EkphrasisError::TextTooLong);
        }
        for (key, val) in params_obj {
            // Convert all param values to strings for the flat representation.
            let val_str = match val {
                JsonValue::String(s) => s.clone(),
                JsonValue::Number(n) => {
                    let mut buf = String::new();
                    fmt::write(&mut buf, format_args!("{n}")).ok();
                    buf
                }
                JsonValue::Bool(b) => {
                    let mut buf = String::new();
                    fmt::write(&mut buf, format_args!("{b}")).ok();
                    buf
                }
                JsonValue::Null => String::from("null"),
                // Arrays and objects are not expected as param values.
                _ => continue,
            };
            params.push((key.clone(), val_str));
        }
    }

    Ok(ActionProposal::new(
        String::from(action),
        params,
        String::from(description),
    ))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use alloc::string::ToString;
    use alloc::vec;

    use super::*;

    // -----------------------------------------------------------------------
    // WebSocket frame round-trip tests
    // -----------------------------------------------------------------------

    #[test]
    fn ws_frame_roundtrip_text() {
        let payload = b"hello world";
        let mask_key = [0x12, 0x34, 0x56, 0x78];

        let frame_bytes = build_ws_frame(WsOpcode::Text, payload, mask_key);
        let (parsed, consumed) = parse_ws_frame(&frame_bytes).ok().flatten_pair();

        // The frame is masked (client-to-server), so parse should unmask it.
        assert_eq!(consumed, frame_bytes.len());
        assert_eq!(parsed.opcode, WsOpcode::Text);
        assert_eq!(parsed.payload, payload);
    }

    #[test]
    fn ws_frame_roundtrip_binary() {
        let payload: Vec<u8> = (0..256).map(|i| i as u8).collect();
        let mask_key = [0xAA, 0xBB, 0xCC, 0xDD];

        let frame_bytes = build_ws_frame(WsOpcode::Binary, &payload, mask_key);
        let (parsed, consumed) = parse_ws_frame(&frame_bytes).ok().flatten_pair();

        assert_eq!(consumed, frame_bytes.len());
        assert_eq!(parsed.opcode, WsOpcode::Binary);
        assert_eq!(parsed.payload, payload);
    }

    #[test]
    fn ws_frame_roundtrip_empty_payload() {
        let mask_key = [0x01, 0x02, 0x03, 0x04];
        let frame_bytes = build_ws_frame(WsOpcode::Close, &[], mask_key);
        let (parsed, consumed) = parse_ws_frame(&frame_bytes).ok().flatten_pair();

        assert_eq!(consumed, frame_bytes.len());
        assert_eq!(parsed.opcode, WsOpcode::Close);
        assert!(parsed.payload.is_empty());
    }

    #[test]
    fn ws_frame_roundtrip_medium_payload() {
        // 200 bytes — uses 7-bit length (< 126).
        let payload = vec![0x42; 100];
        let mask_key = [0x11, 0x22, 0x33, 0x44];

        let frame_bytes = build_ws_frame(WsOpcode::Binary, &payload, mask_key);
        let (parsed, consumed) = parse_ws_frame(&frame_bytes).ok().flatten_pair();

        assert_eq!(consumed, frame_bytes.len());
        assert_eq!(parsed.payload, payload);
    }

    #[test]
    fn ws_frame_roundtrip_extended_16bit_length() {
        // 300 bytes — uses 16-bit extended length (126..65535).
        let payload = vec![0x55; 300];
        let mask_key = [0xDE, 0xAD, 0xBE, 0xEF];

        let frame_bytes = build_ws_frame(WsOpcode::Binary, &payload, mask_key);
        let (parsed, consumed) = parse_ws_frame(&frame_bytes).ok().flatten_pair();

        assert_eq!(consumed, frame_bytes.len());
        assert_eq!(parsed.payload.len(), 300);
        assert_eq!(parsed.payload, payload);
    }

    #[test]
    fn ws_frame_roundtrip_extended_64bit_length() {
        // Exactly MAX_WS_FRAME_PAYLOAD (65536) bytes — payload_len > 0xFFFF
        // forces the 64-bit extended length header (len_indicator == 127).
        let payload = vec![0x99; MAX_WS_FRAME_PAYLOAD];
        let mask_key = [0xAA, 0xBB, 0xCC, 0xDD];

        let frame_bytes = build_ws_frame(WsOpcode::Binary, &payload, mask_key);
        let (parsed, consumed) = parse_ws_frame(&frame_bytes).ok().flatten_pair();

        assert_eq!(consumed, frame_bytes.len());
        assert_eq!(parsed.payload.len(), MAX_WS_FRAME_PAYLOAD);
        assert_eq!(parsed.payload, payload);
    }

    #[test]
    fn ws_frame_parse_unmasked_server_frame() {
        // Server-to-client frames are unmasked.
        // Build manually: FIN + Text, len=5, "hello".
        let data = [
            0x81, // FIN + opcode 1 (text)
            0x05, // no mask, length 5
            b'h', b'e', b'l', b'l', b'o',
        ];

        let (parsed, consumed) = parse_ws_frame(&data).ok().flatten_pair();

        assert_eq!(consumed, 7);
        assert_eq!(parsed.opcode, WsOpcode::Text);
        assert_eq!(parsed.payload, b"hello");
    }

    #[test]
    fn ws_frame_parse_incomplete() {
        // Only 1 byte — not enough for a frame header.
        let data = [0x81];
        let result = parse_ws_frame(&data);
        assert_eq!(result, Err(EkphrasisError::Incomplete));
    }

    #[test]
    fn ws_frame_parse_incomplete_payload() {
        // Header says 5 bytes, but only 3 available.
        let data = [0x81, 0x05, b'h', b'e', b'l'];
        let result = parse_ws_frame(&data);
        assert_eq!(result, Err(EkphrasisError::Incomplete));
    }

    #[test]
    fn ws_frame_parse_unknown_opcode() {
        // Opcode 0x0F is reserved/unknown.
        let data = [0x8F, 0x00];
        let result = parse_ws_frame(&data);
        assert_eq!(result, Err(EkphrasisError::InvalidFrame));
    }

    #[test]
    fn ws_frame_rejects_nonzero_rsv_bits() {
        // FIN(1) + RSV1(1) + text opcode(0x1): byte0 = 1000_0001 | 0100_0000 = 0xC1.
        let data = [0xC1, 0x00];
        let result = parse_ws_frame(&data);
        assert_eq!(result, Err(EkphrasisError::InvalidFrame));
    }

    #[test]
    fn ws_frame_rejects_fin_zero_fragmentation() {
        // FIN=0, text opcode(0x1), no mask, zero length: byte0 = 0x01.
        let data = [0x01, 0x00];
        let result = parse_ws_frame(&data);
        assert_eq!(result, Err(EkphrasisError::InvalidFrame));
    }

    #[test]
    fn ws_frame_ping_pong() {
        let mask_key = [0x01, 0x02, 0x03, 0x04];
        let ping_frame = build_ws_frame(WsOpcode::Ping, b"ping", mask_key);
        let (parsed, _) = parse_ws_frame(&ping_frame).ok().flatten_pair();
        assert_eq!(parsed.opcode, WsOpcode::Ping);
        assert_eq!(parsed.payload, b"ping");

        let pong_frame = build_ws_frame(WsOpcode::Pong, b"pong", mask_key);
        let (parsed, _) = parse_ws_frame(&pong_frame).ok().flatten_pair();
        assert_eq!(parsed.opcode, WsOpcode::Pong);
        assert_eq!(parsed.payload, b"pong");
    }

    // -----------------------------------------------------------------------
    // Helper trait for test ergonomics
    // -----------------------------------------------------------------------

    trait FlattenPair {
        type Output;
        fn flatten_pair(self) -> Self::Output;
    }

    impl<T, U> FlattenPair for Option<(T, U)> {
        type Output = (T, U);
        fn flatten_pair(self) -> (T, U) {
            match self {
                Some(pair) => pair,
                None => panic!("expected Some, got None"),
            }
        }
    }

    // -----------------------------------------------------------------------
    // Action proposal parsing tests
    // -----------------------------------------------------------------------

    #[test]
    fn parse_action_proposal_basic() {
        let message = r#"Sure, I'll call Maria for you.

```thumos-action
{
  "thumos_action": "open_dialer",
  "params": {"contact_name": "Maria", "number": "+15550100"},
  "description": "Call Maria"
}
```

Let me know if you need anything else."#;

        let result = parse_action_proposal(message);
        assert!(result.is_some());
        let proposal = result.as_ref().map(|r| r.as_ref().ok()).flatten();
        assert!(proposal.is_some());
        let proposal = proposal.map(|p| p.clone());
        let p = proposal.as_ref().map(|p| p);
        assert!(p.is_some());
        let p = p.map(|p| p).flatten_ref();

        assert_eq!(p.action, "open_dialer");
        assert_eq!(p.description, "Call Maria");
        assert_eq!(p.param("contact_name"), Some("Maria"));
        assert_eq!(p.param("number"), Some("+15550100"));
    }

    #[test]
    fn find_fenced_block_reports_correct_consumed_offset() {
        // Regression test for the alloc-free refactor: the old code built
        // its search pattern (and its total_consumed offset) from two
        // separate pieces (a runtime-formatted "\n" + end_marker, plus a
        // manual "+1"); the new code uses the single pre-built FENCE_END
        // constant. Both the extracted content and the exact byte offset
        // past the closing fence must still be correct.
        let message = "before\n```thumos-action\ncontent\n```\nafter";
        let (json_str, consumed) = find_fenced_block(message).expect("fence must be found");
        assert_eq!(json_str, "content");
        assert_eq!(
            &message[consumed..],
            "\nafter",
            "consumed offset must land exactly after the closing fence"
        );
    }

    #[test]
    fn parse_action_proposal_tilde_fence() {
        let message = "Here's the timer:\n\n~~~thumos-action\n{\"thumos_action\": \"start_timer\", \"params\": {\"duration\": \"300\"}, \"description\": \"5 minute timer\"}\n~~~\n";

        let result = parse_action_proposal(message);
        assert!(result.is_some());
        let p = result.and_then(|r| r.ok());
        assert!(p.is_some());
        let p = p.as_ref().map(|p| p);
        assert!(p.is_some());
        let p = p.map(|p| p).flatten_ref();

        assert_eq!(p.action, "start_timer");
        assert_eq!(p.description, "5 minute timer");
        assert_eq!(p.param("duration"), Some("300"));
    }

    #[test]
    fn parse_action_proposal_no_params() {
        let message = "```thumos-action\n{\"thumos_action\": \"scan_start\", \"description\": \"Start security scan\"}\n```";

        let result = parse_action_proposal(message);
        assert!(result.is_some());
        let p = result.and_then(|r| r.ok());
        assert!(p.is_some());
        let p = p.as_ref().map(|p| p).flatten_ref();

        assert_eq!(p.action, "scan_start");
        assert!(p.params.is_empty());
    }

    #[test]
    fn parse_action_proposal_none_when_no_fence() {
        let message = "Just a regular message with no action block.";
        assert!(parse_action_proposal(message).is_none());
    }

    #[test]
    fn parse_action_proposal_none_when_wrong_language() {
        let message = "```json\n{\"thumos_action\": \"open_dialer\"}\n```";
        assert!(parse_action_proposal(message).is_none());
    }

    #[test]
    fn parse_action_proposal_missing_action_field() {
        let message = "```thumos-action\n{\"description\": \"Call Maria\"}\n```";
        let result = parse_action_proposal(message);
        assert!(result.is_some());
        let err = result.and_then(|r| r.err());
        assert!(err.is_some());
    }

    #[test]
    fn parse_action_proposal_missing_description() {
        let message = "```thumos-action\n{\"thumos_action\": \"open_dialer\"}\n```";
        let result = parse_action_proposal(message);
        assert!(result.is_some());
        let err = result.and_then(|r| r.err());
        assert!(err.is_some());
    }

    #[test]
    fn parse_action_proposal_invalid_json() {
        let message = "```thumos-action\nnot valid json at all\n```";
        let result = parse_action_proposal(message);
        assert!(result.is_some());
        let err = result.and_then(|r| r.err());
        assert!(err.is_some());
    }

    #[test]
    fn parse_action_proposal_numeric_params() {
        let message = "```thumos-action\n{\"thumos_action\": \"set_alarm\", \"params\": {\"hour\": 7, \"minute\": 30}, \"description\": \"Wake up alarm\"}\n```";
        let result = parse_action_proposal(message);
        let p = result.and_then(|r| r.ok());
        assert!(p.is_some());
        let p = p.as_ref().map(|p| p).flatten_ref();

        assert_eq!(p.action, "set_alarm");
        assert_eq!(p.param("hour"), Some("7"));
        assert_eq!(p.param("minute"), Some("30"));
    }

    #[test]
    fn action_types_known() {
        assert!(action_types::is_known("open_dialer"));
        assert!(action_types::is_known("draft_sms"));
        assert!(action_types::is_known("toggle_mode"));
        assert!(!action_types::is_known("unknown_action"));
        assert!(!action_types::is_known(""));
    }

    // -----------------------------------------------------------------------
    // State machine transition tests
    // -----------------------------------------------------------------------

    #[test]
    fn state_idle_to_recording() {
        let mut ek = Ekphrasis::new("stt.example.lan", 8080);
        ek.set_endpoint_reachable(true);

        assert_eq!(*ek.state(), EkphrasisState::Idle);
        assert!(!ek.is_recording());

        let result = ek.start_recording();
        assert!(result.is_ok());
        assert_eq!(*ek.state(), EkphrasisState::Recording);
        assert!(ek.is_recording());
    }

    #[test]
    fn state_recording_to_streaming() {
        let mut ek = Ekphrasis::new("stt.example.lan", 8080);
        ek.set_endpoint_reachable(true);
        let _ = ek.start_recording();

        let result = ek.begin_streaming();
        assert!(result.is_ok());
        assert_eq!(*ek.state(), EkphrasisState::Streaming);
        assert!(ek.is_recording());
    }

    #[test]
    fn state_cannot_record_when_unreachable() {
        let mut ek = Ekphrasis::new("stt.example.lan", 8080);
        // Not reachable by default.
        assert!(!ek.is_available());

        let result = ek.start_recording();
        assert_eq!(result, Err(EkphrasisError::EndpointUnreachable));
    }

    #[test]
    fn state_cannot_record_when_already_recording() {
        let mut ek = Ekphrasis::new("stt.example.lan", 8080);
        ek.set_endpoint_reachable(true);
        let _ = ek.start_recording();

        let result = ek.start_recording();
        assert!(result.is_err());
        match result {
            Err(EkphrasisError::InvalidState { operation, current }) => {
                assert_eq!(operation, "start_recording");
                assert_eq!(current, "recording");
            }
            _ => panic!("expected InvalidState"),
        }
    }

    #[test]
    fn state_cannot_stream_from_idle() {
        let mut ek = Ekphrasis::new("stt.example.lan", 8080);
        let result = ek.begin_streaming();
        assert!(result.is_err());
    }

    #[test]
    fn state_stop_from_recording() {
        let mut ek = Ekphrasis::new("stt.example.lan", 8080);
        ek.set_endpoint_reachable(true);
        let _ = ek.start_recording();

        let result = ek.stop_recording();
        assert!(result.is_ok());
        assert_eq!(*ek.state(), EkphrasisState::Idle);
        assert!(!ek.is_recording());
    }

    #[test]
    fn stop_recording_returns_partial_text_when_no_final() {
        let mut ek = Ekphrasis::new("stt.example.lan", 8080);
        ek.set_endpoint_reachable(true);
        let _ = ek.start_recording();
        let _ = ek.begin_streaming();

        let partial_frame = WsFrame::new(
            WsOpcode::Text,
            b"{\"text\": \"partial only\", \"final\": false}".to_vec(),
        );
        let _ = ek.handle_server_frame(&partial_frame);
        assert!(ek.final_text().is_empty());
        assert_eq!(ek.partial_text(), "partial only");

        let result = ek.stop_recording();
        assert_eq!(result, Ok(String::from("partial only")));
    }

    #[test]
    fn state_stop_from_idle_fails() {
        let mut ek = Ekphrasis::new("stt.example.lan", 8080);
        let result = ek.stop_recording();
        assert!(result.is_err());
    }

    #[test]
    fn state_feed_audio_while_recording() {
        let mut ek = Ekphrasis::new("stt.example.lan", 8080);
        ek.set_endpoint_reachable(true);
        let _ = ek.start_recording();

        let result = ek.feed_audio(&[0x01, 0x02, 0x03]);
        assert!(result.is_ok());
    }

    #[test]
    fn state_feed_audio_while_idle_fails() {
        let mut ek = Ekphrasis::new("stt.example.lan", 8080);
        let result = ek.feed_audio(&[0x01]);
        assert!(result.is_err());
    }

    #[test]
    fn feed_audio_rejects_beyond_max_buffer() {
        let mut ek = Ekphrasis::new("stt.example.lan", 8080);
        ek.set_endpoint_reachable(true);
        let _ = ek.start_recording();

        // Fill exactly to the cap.
        let chunk = alloc::vec![0u8; MAX_AUDIO_BUFFER_BYTES];
        assert!(
            ek.feed_audio(&chunk).is_ok(),
            "filling to the cap must succeed"
        );
        assert_eq!(ek.audio_buffer.len(), MAX_AUDIO_BUFFER_BYTES);

        // One more byte must be rejected, and the buffer must not grow further.
        let result = ek.feed_audio(&[0x01]);
        assert_eq!(result, Err(EkphrasisError::AudioCaptureFailed));
        assert_eq!(
            ek.audio_buffer.len(),
            MAX_AUDIO_BUFFER_BYTES,
            "rejected feed must not grow the buffer past the cap"
        );
    }

    #[test]
    fn state_take_audio_frame() {
        let mut ek = Ekphrasis::new("stt.example.lan", 8080);
        ek.set_endpoint_reachable(true);
        let _ = ek.start_recording();
        let _ = ek.begin_streaming();

        // No data yet.
        assert!(ek.take_audio_frame([0; 4]).is_none());

        // Feed some data.
        let _ = ek.feed_audio(&[0xAA; 10]);
        let frame = ek.take_audio_frame([0x01, 0x02, 0x03, 0x04]);
        assert!(frame.is_some());

        // Buffer drained — next take returns None.
        assert!(ek.take_audio_frame([0; 4]).is_none());
    }

    #[test]
    fn state_transcription_flow() {
        let mut ek = Ekphrasis::new("stt.example.lan", 8080);
        ek.set_endpoint_reachable(true);
        let _ = ek.start_recording();
        let _ = ek.begin_streaming();

        // Receive partial transcription.
        let partial_frame = WsFrame::new(
            WsOpcode::Text,
            b"{\"text\": \"hello\", \"final\": false}".to_vec(),
        );
        let result = ek.handle_server_frame(&partial_frame);
        assert!(result.is_ok());
        assert_eq!(ek.partial_text(), "hello");
        assert_eq!(*ek.state(), EkphrasisState::Transcribing);

        // Receive final transcription.
        let final_frame = WsFrame::new(
            WsOpcode::Text,
            b"{\"text\": \"hello world\", \"final\": true}".to_vec(),
        );
        let result = ek.handle_server_frame(&final_frame);
        assert!(result.is_ok());
        assert_eq!(ek.final_text(), "hello world");
        assert_eq!(*ek.state(), EkphrasisState::Idle);
    }

    #[test]
    fn state_server_close_frame() {
        let mut ek = Ekphrasis::new("stt.example.lan", 8080);
        ek.set_endpoint_reachable(true);
        let _ = ek.start_recording();
        let _ = ek.begin_streaming();

        let close_frame = WsFrame::new(WsOpcode::Close, Vec::new());
        let result = ek.handle_server_frame(&close_frame);
        assert_eq!(result, Err(EkphrasisError::ConnectionClosed));
        assert_eq!(*ek.state(), EkphrasisState::Idle);
    }

    #[test]
    fn handle_server_frame_rejects_when_idle() {
        let mut ek = Ekphrasis::new("stt.example.lan", 8080);
        let frame = WsFrame::new(WsOpcode::Text, b"{\"text\": \"hi\"}".to_vec());
        let result = ek.handle_server_frame(&frame);
        assert!(
            matches!(
                result,
                Err(EkphrasisError::InvalidState {
                    operation: "handle_server_frame",
                    ..
                })
            ),
            "a frame arriving in Idle state must be rejected, not processed"
        );
    }

    #[test]
    fn handle_server_frame_rejects_and_stays_in_error_state() {
        let mut ek = Ekphrasis::new("stt.example.lan", 8080);
        ek.set_endpoint_reachable(true);
        let _ = ek.start_recording();
        let _ = ek.begin_streaming();
        ek.state = EkphrasisState::Error(EkphrasisError::ConnectionClosed);

        let frame = WsFrame::new(WsOpcode::Text, b"{\"text\": \"hi\"}".to_vec());
        let result = ek.handle_server_frame(&frame);
        assert!(
            matches!(result, Err(EkphrasisError::InvalidState { .. })),
            "a frame arriving while in Error state must not silently transition out of Error"
        );
        assert!(
            matches!(ek.state(), EkphrasisState::Error(_)),
            "state must remain Error, not be overwritten by a stray frame"
        );
    }

    #[test]
    fn process_transcription_errors_on_missing_text_field() {
        let mut ek = Ekphrasis::new("stt.example.lan", 8080);
        ek.set_endpoint_reachable(true);
        let _ = ek.start_recording();
        let _ = ek.begin_streaming();

        let frame = WsFrame::new(WsOpcode::Text, b"{\"final\": false}".to_vec());
        let result = ek.handle_server_frame(&frame);
        assert_eq!(
            result,
            Err(EkphrasisError::InvalidFrame),
            "a transcription response missing \"text\" must error, not silently substitute empty string"
        );
    }

    #[test]
    fn handle_server_frame_transitions_to_error_on_malformed_response() {
        let mut ek = Ekphrasis::new("stt.example.lan", 8080);
        ek.set_endpoint_reachable(true);
        let _ = ek.start_recording();
        let _ = ek.begin_streaming();

        let frame = WsFrame::new(WsOpcode::Text, b"{\"final\": false}".to_vec());
        let result = ek.handle_server_frame(&frame);
        assert!(result.is_err());
        assert!(
            matches!(ek.state(), EkphrasisState::Error(_)),
            "a malformed transcription response must move the state machine to Error, requiring an explicit reset()"
        );
    }

    #[test]
    fn state_reset_clears_everything() {
        let mut ek = Ekphrasis::new("stt.example.lan", 8080);
        ek.set_endpoint_reachable(true);
        let _ = ek.start_recording();
        let _ = ek.feed_audio(&[0xFF; 100]);

        ek.reset();
        assert_eq!(*ek.state(), EkphrasisState::Idle);
        assert!(ek.partial_text().is_empty());
        assert!(ek.final_text().is_empty());
        assert!(!ek.is_recording());
    }

    // -----------------------------------------------------------------------
    // Accessors and Display
    // -----------------------------------------------------------------------

    #[test]
    fn ekphrasis_accessors() {
        let ek = Ekphrasis::new("198.51.100.1", 9000);
        assert_eq!(ek.host(), "198.51.100.1");
        assert_eq!(ek.port(), 9000);
        assert!(!ek.is_available());

        let config = ek.capture_config();
        assert_eq!(config.sample_rate_hz, 16_000);
        assert_eq!(config.channels, 1);
        assert_eq!(config.bits_per_sample, 16);
    }

    #[test]
    fn ekphrasis_display() {
        let ek = Ekphrasis::new("stt.example.lan", 8080);
        let display = alloc::format!("{ek}");
        assert!(display.contains("stt.example.lan"));
        assert!(display.contains("8080"));
        assert!(display.contains("idle"));
    }

    #[test]
    fn ekphrasis_ws_upgrade_request() {
        let ek = Ekphrasis::new("stt.example.lan", 8080);
        let req = ek
            .ws_upgrade_request("dGVzdC1rZXk=")
            .expect("a control-char-free host/key must build a request");

        assert_eq!(req.host, "stt.example.lan");
        assert_eq!(req.path, "/stt/stream");
        assert!(
            req.headers
                .iter()
                .any(|(k, v)| k == "Upgrade" && v == "websocket")
        );
        assert!(
            req.headers
                .iter()
                .any(|(k, v)| k == "Sec-WebSocket-Key" && v == "dGVzdC1rZXk=")
        );
    }

    #[test]
    fn ws_upgrade_rejects_crlf_in_host() {
        let ek = Ekphrasis::new("stt.example.lan\r\nX-Injected: evil", 8080);
        let result = ek.ws_upgrade_request("dGVzdC1rZXk=");
        assert!(matches!(result, Err(EkphrasisError::InvalidUpgradeParam)));
    }

    #[test]
    fn ws_upgrade_rejects_nul_in_key() {
        let ek = Ekphrasis::new("stt.example.lan", 8080);
        let result = ek.ws_upgrade_request("dGVz\0dC1rZXk=");
        assert!(matches!(result, Err(EkphrasisError::InvalidUpgradeParam)));
    }

    #[test]
    fn ekphrasis_close_frame_builds() {
        let frame = Ekphrasis::build_close_frame([0x01, 0x02, 0x03, 0x04]);
        let (parsed, _) = parse_ws_frame(&frame).ok().flatten_pair();
        assert_eq!(parsed.opcode, WsOpcode::Close);
        assert!(parsed.payload.is_empty());
    }

    #[test]
    fn compute_ws_accept_matches_rfc6455_example() {
        // RFC 6455 §1.3 worked example.
        let accept = compute_ws_accept("dGhlIHNhbXBsZSBub25jZQ==");
        assert_eq!(accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[test]
    fn verify_ws_accept_accepts_matching_key() {
        let result = verify_ws_accept("dGhlIHNhbXBsZSBub25jZQ==", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
        assert!(result.is_ok());
    }

    #[test]
    fn verify_ws_accept_rejects_mismatched_key() {
        let result = verify_ws_accept("dGhlIHNhbXBsZSBub25jZQ==", "not-the-right-value=");
        assert_eq!(result, Err(EkphrasisError::HandshakeFailed));
    }

    #[test]
    fn verify_ws_accept_fails_closed_on_empty_server_value() {
        let result = verify_ws_accept("dGhlIHNhbXBsZSBub25jZQ==", "");
        assert_eq!(result, Err(EkphrasisError::HandshakeFailed));
    }

    // -----------------------------------------------------------------------
    // Error Display coverage
    // -----------------------------------------------------------------------

    #[test]
    fn error_display() {
        let errors = [
            EkphrasisError::EndpointUnreachable,
            EkphrasisError::HandshakeFailed,
            EkphrasisError::InvalidUpgradeParam,
            EkphrasisError::InvalidFrame,
            EkphrasisError::PayloadTooLarge,
            EkphrasisError::TextTooLong,
            EkphrasisError::AudioCaptureFailed,
            EkphrasisError::InvalidState {
                operation: "start",
                current: "recording",
            },
            EkphrasisError::Json(JsonError::Empty),
            EkphrasisError::ConnectionClosed,
            EkphrasisError::Incomplete,
        ];

        for e in &errors {
            let s = alloc::format!("{e}");
            assert!(!s.is_empty());
        }
    }

    #[test]
    fn state_display() {
        let states = [
            EkphrasisState::Idle,
            EkphrasisState::Recording,
            EkphrasisState::Streaming,
            EkphrasisState::Transcribing,
            EkphrasisState::Error(EkphrasisError::EndpointUnreachable),
        ];

        for s in &states {
            let display = alloc::format!("{s}");
            assert!(!display.is_empty());
        }
    }

    #[test]
    fn action_proposal_display() {
        let p = ActionProposal::new(
            String::from("open_dialer"),
            Vec::new(),
            String::from("Call Maria"),
        );
        let display = alloc::format!("{p}");
        assert!(display.contains("open_dialer"));
        assert!(display.contains("Call Maria"));
    }

    #[test]
    fn ws_opcode_display() {
        assert_eq!(WsOpcode::Text.to_string(), "text");
        assert_eq!(WsOpcode::Binary.to_string(), "binary");
        assert_eq!(WsOpcode::Close.to_string(), "close");
    }

    #[test]
    fn ws_frame_display() {
        let frame = WsFrame::new(WsOpcode::Text, b"hello".to_vec());
        let display = alloc::format!("{frame}");
        assert!(display.contains("text"));
        assert!(display.contains("5 bytes"));
    }

    #[test]
    fn audio_capture_config_display() {
        let config = AudioCaptureConfig::stt_default();
        let display = alloc::format!("{config}");
        assert!(display.contains("16000Hz"));
        assert!(display.contains("1ch"));
        assert!(display.contains("16bit"));
    }

    // -----------------------------------------------------------------------
    // Trait coverage for non_exhaustive / flatten_ref helper
    // -----------------------------------------------------------------------

    trait FlattenRef<'a, T> {
        fn flatten_ref(self) -> &'a T;
    }

    impl<'a, T> FlattenRef<'a, T> for Option<&'a T> {
        fn flatten_ref(self) -> &'a T {
            match self {
                Some(v) => v,
                None => panic!("expected Some, got None"),
            }
        }
    }
}
