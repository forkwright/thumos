//! UART transport layer connecting STP framing to the WMT subsystem.
//!
//! Provides a sliding-window TX queue and byte-stream RX assembler for
//! delivering [`StpFrame`](crate::stp::StpFrame) payloads over the BTIF UART
//! to the MT6739 CONSYS combo chip.
//!
//! Protocol parameters (FROM `stp_core.h`):
//! - Sliding window: [`WINDOW_SIZE`] = 7 frames max in-flight
//! - TX timeout: [`TX_TIMEOUT_MS`] = 180 ms before retransmit
//! - Retry LIMIT: [`RETRY_LIMIT`] = 10 retransmissions before link failure

use snafu::Snafu;

use crate::config::{Config, DEFAULT_RETRY_LIMIT, DEFAULT_TX_TIMEOUT_MS};
use crate::stp::{MAX_PAYLOAD, StpFrame};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Maximum in-flight unacknowledged TX frames (`MTKSTP_WINSIZE`).
///
/// Remains `const` — this is a protocol invariant fixed by the STP spec and
/// is used as the size of the sliding-window array. Changing it at runtime
/// would require reallocating the window.
pub const WINDOW_SIZE: usize = 7;

/// Default TX timeout in milliseconds before a frame is assumed lost and
/// retransmitted.
///
/// Preserved as a `pub const` alias of [`DEFAULT_TX_TIMEOUT_MS`] for backward
/// compatibility. The runtime-tunable entry point is
/// [`Config::tx_timeout_ms`].
pub const TX_TIMEOUT_MS: u32 = DEFAULT_TX_TIMEOUT_MS;

/// Default maximum retransmissions per frame before the link is declared dead.
///
/// Preserved as a `pub const` alias of [`DEFAULT_RETRY_LIMIT`] for backward
/// compatibility. The runtime-tunable entry point is
/// [`Config::retry_limit`].
pub const RETRY_LIMIT: u8 = DEFAULT_RETRY_LIMIT;

/// Maximum encoded STP frame size: SOF(1) + header(4) + payload + CRC(2).
pub const TX_FRAME_MAX_ENCODED: usize = 1 + 4 + MAX_PAYLOAD + 2;

/// STP Start of Frame byte  -  used by RX parser to synchronise.
const STP_SOF: u8 = 0x80;

// ── Error types ───────────────────────────────────────────────────────────────

/// Errors produced by the STP transport layer.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum TransportError {
    /// TX sliding window is full  -  caller must wait for acknowledgements.
    #[snafu(display(
        "TX window is full ({WINDOW_SIZE} frames in flight); wait for acknowledgements"
    ))]
    WindowFull,

    /// Frame retry count exceeded the configured [`Config::retry_limit`];
    /// link is dead.
    #[snafu(display("frame seq={seq} exceeded retry LIMIT ({limit}); link declared dead"))]
    RetryLimitExceeded {
        /// Sequence number of the frame that exceeded the retry LIMIT.
        seq: u8,
        /// The retry limit that was exceeded (as configured at transport
        /// construction).
        limit: u8,
    },

    /// Acknowledgement sequence number is outside the current window.
    #[snafu(display("ack seq={seq} is outside the current TX window"))]
    StaleAck {
        /// Acknowledged sequence number that was not found in the window.
        seq: u8,
    },
}

// ── TX window ─────────────────────────────────────────────────────────────────

/// A queued TX frame awaiting acknowledgement.
pub struct TxEntry {
    /// Encoded STP frame bytes ready to write to UART.
    data: [u8; TX_FRAME_MAX_ENCODED],
    /// Number of valid bytes in [`data`](Self::data).
    pub(crate) len: usize,
    /// STP sequence number for this frame.
    pub(crate) seq: u8,
    /// Retransmission count  -  incremented each time the frame is resent.
    pub(crate) retries: u8,
}

impl TxEntry {
    /// Encode `frame` INTO a new entry.
    fn from_frame(frame: &StpFrame) -> Self {
        let mut entry = Self {
            data: [0u8; TX_FRAME_MAX_ENCODED],
            len: 0,
            seq: frame.header.seq,
            retries: 0,
        };
        entry.len = frame.encode(&mut entry.data);
        entry
    }

    /// Raw encoded bytes slice.
    pub fn as_bytes(&self) -> &[u8] {
        // WHY: len is SET by encode() which returns exact byte count; safe slice.
        &self.data[..self.len]
    }
}

// ── RX parser ────────────────────────────────────────────────────────────────

/// State of the RX byte-stream parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RxState {
    /// Waiting for the SOF byte (0x80).
    WaitSof,
    /// Collecting 4-byte header; `collected` bytes received so far.
    Header { collected: u8 },
    /// Collecting payload bytes; `remaining` bytes LEFT.
    Payload { remaining: u16 },
    /// Collecting 2-byte CRC; `collected` bytes received so far.
    Crc { collected: u8 },
}

/// Byte-stream RX parser that reassembles raw bytes INTO complete STP frames.
pub struct RxParser {
    state: RxState,
    /// Raw accumulation buffer.
    buf: [u8; TX_FRAME_MAX_ENCODED],
    pos: usize,
    /// Payload length decoded FROM the header (SET during [`Header`](RxState::Header) phase).
    payload_len: u16,
}

impl Default for RxParser {
    fn default() -> Self {
        Self::new()
    }
}

impl RxParser {
    /// Create a new parser in the initial [`WaitSof`](RxState::WaitSof) state.
    pub const fn new() -> Self {
        Self {
            state: RxState::WaitSof,
            buf: [0u8; TX_FRAME_MAX_ENCODED],
            pos: 0,
            payload_len: 0,
        }
    }

    /// Feed one byte INTO the parser.
    ///
    /// Returns `true` when a complete frame has been assembled and is
    /// readable via [`take_raw`](Self::take_raw).
    pub fn push_byte(&mut self, byte: u8) -> bool {
        match self.state {
            RxState::WaitSof => {
                if byte == STP_SOF {
                    self.pos = 0;
                    self.buf[self.pos] = byte;
                    self.pos += 1;
                    self.state = RxState::Header { collected: 0 };
                }
                false
            }

            RxState::Header { collected } => {
                if self.pos < TX_FRAME_MAX_ENCODED {
                    self.buf[self.pos] = byte;
                    self.pos += 1;
                }
                let collected = collected + 1;
                if collected == 4 {
                    // Decode payload length FROM header bytes 1 and 2 (after SOF).
                    // header[1] bits [6:0] = length bits [11:5]
                    // header[2] bits [7:3] = length bits [4:0]
                    let h1 = self.buf.get(2).copied().unwrap_or_default(); // buf index 0 = SOF, index 1 = h0, index 2 = h1
                    let h2 = self.buf.get(3).copied().unwrap_or_default();
                    let len = (u16::from(h1 & 0x7F) << 5) | (u16::from(h2 >> 3));
                    self.payload_len = len;
                    if len == 0 {
                        self.state = RxState::Crc { collected: 0 };
                    } else {
                        self.state = RxState::Payload { remaining: len };
                    }
                } else {
                    self.state = RxState::Header { collected };
                }
                false
            }

            RxState::Payload { remaining } => {
                if self.pos < TX_FRAME_MAX_ENCODED {
                    self.buf[self.pos] = byte;
                    self.pos += 1;
                }
                if remaining == 1 {
                    self.state = RxState::Crc { collected: 0 };
                } else {
                    self.state = RxState::Payload {
                        remaining: remaining - 1,
                    };
                }
                false
            }

            RxState::Crc { collected } => {
                if self.pos < TX_FRAME_MAX_ENCODED {
                    self.buf[self.pos] = byte;
                    self.pos += 1;
                }
                if collected == 1 {
                    // Both CRC bytes received  -  frame is complete.
                    self.state = RxState::WaitSof;
                    true
                } else {
                    self.state = RxState::Crc { collected: 1 };
                    false
                }
            }
        }
    }

    /// Return the raw accumulated bytes of the last complete frame.
    ///
    /// Only valid immediately after [`push_byte`](Self::push_byte) returns `true`.
    pub fn take_raw(&self) -> &[u8] {
        &self.buf[..self.pos]
    }

    /// Payload length decoded FROM the most recently completed frame header.
    pub const fn last_payload_len(&self) -> u16 {
        self.payload_len
    }
}

// ── StpTransport ──────────────────────────────────────────────────────────────

/// STP UART transport with sliding-window TX and byte-stream RX.
///
/// The transport encodes outgoing [`StpFrame`]s INTO the TX window and
/// advances the window as ACKs arrive. The RX side assembles raw bytes
/// FROM UART INTO complete frames via [`RxParser`].
pub struct StpTransport {
    /// Sliding window of in-flight TX frames.
    tx_window: [Option<TxEntry>; WINDOW_SIZE],
    /// Sequence number for the next transmitted frame (mod 8).
    tx_seq: u8,
    /// RX byte-stream parser.
    rx_parser: RxParser,
    /// Retry budget in effect for this transport, captured from [`Config`].
    retry_limit: u8,
    /// TX timeout in milliseconds for this transport, captured from [`Config`].
    ///
    /// WHY: stored for caller-visible timing policy — the transport itself
    /// does not drive time, but exposes [`tx_timeout_ms`](Self::tx_timeout_ms)
    /// so the retransmit scheduler picks up the configured value.
    tx_timeout_ms: u32,
}

impl Default for StpTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl StpTransport {
    /// Create a new transport in the idle state using [`Config::default`].
    #[must_use]
    pub fn new() -> Self {
        Self::new_with_config(&Config::default())
    }

    /// Create a new transport with an explicit [`Config`].
    ///
    /// The retry budget and TX-timeout values are captured from `config` at
    /// construction time and propagated through [`retransmit`](Self::retransmit)
    /// and [`tx_timeout_ms`](Self::tx_timeout_ms).
    #[expect(
        clippy::large_stack_arrays,
        reason = "no_std kernel context  -  heap allocation is unavailable; 7-slot window is the spec-mandated size"
    )]
    #[must_use]
    pub fn new_with_config(config: &Config) -> Self {
        // WHY: Option<TxEntry> is not Copy because TxEntry has a large array,
        // so we cannot use array repeat syntax [None; N]. Build manually.
        Self {
            tx_window: [None, None, None, None, None, None, None],
            tx_seq: 0,
            rx_parser: RxParser::new(),
            retry_limit: config.retry_limit(),
            tx_timeout_ms: config.tx_timeout_ms(),
        }
    }

    /// Retry limit this transport was constructed with.
    #[must_use]
    pub const fn retry_limit(&self) -> u8 {
        self.retry_limit
    }

    /// TX timeout in milliseconds this transport was constructed with.
    #[must_use]
    pub const fn tx_timeout_ms(&self) -> u32 {
        self.tx_timeout_ms
    }

    /// Enqueue `frame` in the TX sliding window.
    ///
    /// Returns the slot index on success, or [`TransportError::WindowFull`]
    /// when all [`WINDOW_SIZE`] slots are occupied.
    #[must_use = "enqueue failure must be handled"]
    pub fn enqueue(&mut self, frame: &StpFrame) -> Result<usize, TransportError> {
        for (idx, slot) in self.tx_window.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(TxEntry::from_frame(frame));
                self.tx_seq = (self.tx_seq + 1) & 0x07;
                return Ok(idx);
            }
        }
        Err(TransportError::WindowFull)
    }

    /// Acknowledge receipt of the frame with sequence number `seq`.
    ///
    /// Frees the corresponding window slot. Returns [`TransportError::StaleAck`]
    /// if `seq` is not present in the current window.
    #[must_use = "ack failure must be handled"]
    pub fn acknowledge(&mut self, seq: u8) -> Result<(), TransportError> {
        for slot in &mut self.tx_window {
            if let Some(entry) = slot
                && entry.seq == seq
            {
                *slot = None;
                return Ok(());
            }
        }
        Err(TransportError::StaleAck { seq })
    }

    /// Mark the frame with sequence number `seq` for retransmission.
    ///
    /// Increments its retry counter. Returns [`TransportError::RetryLimitExceeded`]
    /// when the counter reaches the configured [`Config::retry_limit`], or
    /// [`TransportError::StaleAck`] if `seq` is not in the window.
    #[must_use = "retransmit failure must be handled"]
    pub fn retransmit(&mut self, seq: u8) -> Result<&[u8], TransportError> {
        for slot in &mut self.tx_window {
            if let Some(entry) = slot
                && entry.seq == seq
            {
                if entry.retries >= self.retry_limit {
                    return Err(TransportError::RetryLimitExceeded {
                        seq,
                        limit: self.retry_limit,
                    });
                }
                entry.retries += 1;
                return Ok(entry.as_bytes());
            }
        }
        Err(TransportError::StaleAck { seq })
    }

    /// Feed one received byte INTO the RX parser.
    ///
    /// Returns `Some(&[u8])` with the raw frame bytes when a complete frame
    /// has been assembled, or `None` if more bytes are needed.
    pub fn receive_byte(&mut self, byte: u8) -> Option<&[u8]> {
        if self.rx_parser.push_byte(byte) {
            Some(self.rx_parser.take_raw())
        } else {
            None
        }
    }

    /// Number of in-flight frames currently occupying window slots.
    pub fn in_flight(&self) -> usize {
        self.tx_window.iter().filter(|s| s.is_some()).count()
    }

    /// Next TX sequence number (0–7).
    pub const fn next_seq(&self) -> u8 {
        self.tx_seq
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[expect(
    clippy::expect_used,
    clippy::panic,
    reason = "test code — panics and expect are intentional for assertion failures"
)]
mod tests {
    use super::*;
    use crate::stp::{FrameType, StpFrame};

    fn make_frame(seq: u8, payload: &[u8]) -> StpFrame {
        StpFrame::data(seq, payload)
    }

    #[test]
    fn enqueue_single_frame_occupies_one_slot() {
        let mut t = StpTransport::new();
        let frame = make_frame(0, b"hello");
        let slot = t.enqueue(&frame).unwrap_or_default();
        assert_eq!(
            t.in_flight(),
            1,
            "window must contain exactly 1 frame after one enqueue"
        );
        assert!(
            slot < WINDOW_SIZE,
            "returned slot index must be within window bounds"
        );
    }

    #[test]
    fn enqueue_fills_window_to_limit() {
        let mut t = StpTransport::new();
        for i in 0..WINDOW_SIZE {
            let frame = make_frame(u8::try_from(i).unwrap_or_default() & 0x07, b"x");
            t.enqueue(&frame)
                .unwrap_or_else(|_| panic!("enqueue {i} must succeed when window not full"));
        }
        assert_eq!(
            t.in_flight(),
            WINDOW_SIZE,
            "window must be full after WINDOW_SIZE enqueues"
        );
    }

    #[test]
    fn enqueue_beyond_window_returns_window_full() {
        let mut t = StpTransport::new();
        for i in 0..WINDOW_SIZE {
            let frame = make_frame(u8::try_from(i).unwrap_or_default() & 0x07, b"x");
            t.enqueue(&frame)
                .unwrap_or_else(|_| panic!("enqueue {i} must succeed"));
        }
        let overflow = make_frame(0, b"overflow");
        let err = t
            .enqueue(&overflow)
            .expect_err("enqueue past window size must return WindowFull");
        assert!(
            matches!(err, TransportError::WindowFull),
            "error must be WindowFull, got {err:?}"
        );
    }

    #[test]
    fn acknowledge_frees_window_slot() {
        let mut t = StpTransport::new();
        let frame = make_frame(3, b"ack-me");
        t.enqueue(&frame).unwrap_or_default();
        assert_eq!(t.in_flight(), 1, "one frame in flight before ack");
        t.acknowledge(3).unwrap_or_default();
        assert_eq!(t.in_flight(), 0, "window must be empty after ack");
    }

    #[test]
    fn acknowledge_unknown_seq_returns_stale_ack() {
        let mut t = StpTransport::new();
        let err = t
            .acknowledge(5)
            .expect_err("acking a seq not in window must fail");
        assert!(
            matches!(err, TransportError::StaleAck { seq: 5 }),
            "error must be StaleAck(5), got {err:?}"
        );
    }

    #[test]
    fn retransmit_increments_retry_count() {
        let mut t = StpTransport::new();
        let frame = make_frame(1, b"retry");
        t.enqueue(&frame).unwrap_or_default();
        t.retransmit(1).unwrap_or_default();
        // Inspect retry count via a second retransmit call.
        t.retransmit(1).unwrap_or_default();
        // Two retransmits  -  still below RETRY_LIMIT.
        assert_eq!(
            t.in_flight(),
            1,
            "frame must still be in window after retransmits below LIMIT"
        );
    }

    #[test]
    fn retransmit_limit_exceeded_returns_error() {
        let mut t = StpTransport::new();
        let frame = make_frame(2, b"exhaust");
        t.enqueue(&frame).unwrap_or_default();
        // Drive retry count to the LIMIT.
        for i in 0..RETRY_LIMIT {
            t.retransmit(2)
                .unwrap_or_else(|_| panic!("retransmit {i} must succeed before LIMIT"));
        }
        let err = t
            .retransmit(2)
            .expect_err("retransmit past RETRY_LIMIT must return RetryLimitExceeded");
        assert!(
            matches!(
                err,
                TransportError::RetryLimitExceeded {
                    seq: 2,
                    limit: RETRY_LIMIT
                }
            ),
            "error must be RetryLimitExceeded(seq=2, limit=RETRY_LIMIT), got {err:?}"
        );
    }

    #[test]
    fn custom_config_changes_retry_budget() {
        // WHY: prove Config.retry_limit flows through to retransmit. A 2-retry
        // budget must reject on the 3rd call where default (10) would accept.
        let cfg = Config {
            retry_limit: 2,
            ..Config::default()
        };
        let mut t = StpTransport::new_with_config(&cfg);
        let frame = make_frame(7, b"tight");
        t.enqueue(&frame).unwrap_or_default();
        t.retransmit(7).expect("retry 1 within budget");
        t.retransmit(7).expect("retry 2 within budget");
        let err = t
            .retransmit(7)
            .expect_err("retry 3 must exceed the 2-retry budget");
        assert!(
            matches!(err, TransportError::RetryLimitExceeded { seq: 7, limit: 2 }),
            "error must report the configured limit of 2, got {err:?}"
        );
    }

    #[test]
    fn default_tx_timeout_matches_historical_const() {
        let t = StpTransport::new();
        assert_eq!(t.tx_timeout_ms(), TX_TIMEOUT_MS);
        assert_eq!(t.retry_limit(), RETRY_LIMIT);
    }

    #[test]
    fn stp_frame_round_trips_through_tx_entry() {
        let frame = make_frame(5, b"round-trip");
        let entry = TxEntry::from_frame(&frame);
        assert!(entry.len > 0, "encoded TxEntry must have non-zero length");
        assert_eq!(
            entry.as_bytes()[0],
            0x80,
            "first byte of encoded entry must be STP SOF (0x80)"
        );
        assert_eq!(entry.seq, 5, "TxEntry seq must match the frame seq");
        assert_eq!(entry.retries, 0, "TxEntry retries must start at 0");
    }

    #[test]
    fn rx_parser_assembles_encoded_frame() {
        let frame = make_frame(0, b"abc");
        let mut encoded = [0u8; TX_FRAME_MAX_ENCODED];
        let len = frame.encode(&mut encoded);

        let mut t = StpTransport::new();
        let mut complete = None;
        for &byte in encoded.iter().take(len) {
            if let Some(raw) = t.receive_byte(byte) {
                complete = Some(raw.to_vec());
            }
        }
        let raw = complete.unwrap_or_default();
        assert_eq!(
            raw.first().copied(),
            Some(0x80),
            "reassembled frame must start with SOF"
        );
        assert_eq!(
            raw.len(),
            len,
            "reassembled frame length must match original encoded length"
        );
    }

    #[test]
    fn transport_window_constants() {
        assert_eq!(WINDOW_SIZE, 7, "WINDOW_SIZE must be 7 per STP spec");
        assert_eq!(TX_TIMEOUT_MS, 180, "TX_TIMEOUT_MS must be 180 per STP spec");
        assert_eq!(RETRY_LIMIT, 10, "RETRY_LIMIT must be 10 per STP spec");
    }

    #[test]
    fn next_seq_advances_after_enqueue() {
        let mut t = StpTransport::new();
        assert_eq!(t.next_seq(), 0, "initial seq must be 0");
        let frame = make_frame(0, b"seq-test");
        t.enqueue(&frame).unwrap_or_default();
        assert_eq!(t.next_seq(), 1, "seq must advance to 1 after first enqueue");
    }

    #[test]
    fn frame_type_mgmt_encoded_in_tx_entry() {
        // Verify the transport correctly handles ACK frames (zero payload).
        let ack = StpFrame::ack(4);
        let entry = TxEntry::from_frame(&ack);
        // ACK frame: SOF(1) + header(4) + payload(0) + CRC(2) = 7 bytes.
        assert_eq!(
            entry.len, 7,
            "ACK frame must encode to exactly 7 bytes (no payload)"
        );
        assert_eq!(entry.seq, 4, "ACK TxEntry seq must match frame seq");
    }

    #[test]
    fn subsystem_frame_type_values() {
        // Verify the FrameType discriminants used for STP subsystem routing.
        // as u8 on repr(u8) enum in test code: discriminant always fits in u8, no truncation.
        assert_eq!(FrameType::Data as u8, 0, "Data frame type must be 0");
        assert_eq!(FrameType::Ack as u8, 2, "Ack frame type must be 2");
        assert_eq!(
            FrameType::FwDownload as u8,
            3,
            "FwDownload frame type must be 3"
        );
    }
}
