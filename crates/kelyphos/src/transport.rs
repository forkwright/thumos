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
use crate::stp::{MAX_PAYLOAD, StpFrame, compute_crc_over};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Maximum in-flight unacknowledged TX frames (`MTKSTP_WINSIZE`).
///
/// Remains `const` — this is a protocol invariant fixed by the STP spec and
/// is used as the size of the sliding-window array. Changing it at runtime
/// would require reallocating the window.
pub(crate) const WINDOW_SIZE: usize = 7;

/// Default TX timeout in milliseconds before a frame is assumed lost and
/// retransmitted.
///
/// Preserved as a `pub(crate) const` alias of [`DEFAULT_TX_TIMEOUT_MS`] for backward
/// compatibility. The runtime-tunable entry point is
/// [`Config::tx_timeout_ms`].
pub(crate) const TX_TIMEOUT_MS: u32 = DEFAULT_TX_TIMEOUT_MS;

/// Default maximum retransmissions per frame before the link is declared dead.
///
/// Preserved as a `pub(crate) const` alias of [`DEFAULT_RETRY_LIMIT`] for backward
/// compatibility. The runtime-tunable entry point is
/// [`Config::retry_limit`].
pub(crate) const RETRY_LIMIT: u8 = DEFAULT_RETRY_LIMIT;

/// Maximum encoded STP frame size: SOF(1) + header(4) + payload + CRC(2).
pub(crate) const TX_FRAME_MAX_ENCODED: usize = 1 + 4 + MAX_PAYLOAD + 2;

/// STP Start of Frame byte  -  used by RX parser to synchronise.
const STP_SOF: u8 = 0x80;

// ── Error types ───────────────────────────────────────────────────────────────

/// Errors produced by the STP transport layer.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub(crate) enum TransportError {
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
pub(crate) struct TxEntry {
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
    pub(crate) fn as_bytes(&self) -> &[u8] {
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
pub(crate) struct RxParser {
    state: RxState,
    /// Raw accumulation buffer.
    buf: [u8; TX_FRAME_MAX_ENCODED],
    pos: usize,
    /// Payload length decoded FROM the header (SET during [`Header`](RxState::Header) phase).
    payload_len: u16,
    /// Count of frames discarded because the received CRC-16 CCITT did not
    /// match the recomputed value over the received header + payload bytes.
    crc_errors: u32,
}

impl Default for RxParser {
    fn default() -> Self {
        Self::new()
    }
}

impl RxParser {
    /// Create a new parser in the initial [`WaitSof`](RxState::WaitSof) state.
    pub(crate) const fn new() -> Self {
        Self {
            state: RxState::WaitSof,
            buf: [0u8; TX_FRAME_MAX_ENCODED],
            pos: 0,
            payload_len: 0,
            crc_errors: 0,
        }
    }

    /// Feed one byte INTO the parser.
    ///
    /// Returns `true` when a complete frame has been assembled and is
    /// readable via [`take_raw`](Self::take_raw).
    pub(crate) fn push_byte(&mut self, byte: u8) -> bool {
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
                if self.pos >= TX_FRAME_MAX_ENCODED {
                    // WARNING: header phase cannot overflow the buffer under
                    // the current 12-bit length field / TX_FRAME_MAX_ENCODED
                    // sizing, but bail rather than silently drop the byte and
                    // let a corrupt/truncated header decode as if intact.
                    self.state = RxState::WaitSof;
                    self.pos = 0;
                    return false;
                }
                self.buf[self.pos] = byte;
                self.pos += 1;
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
                if self.pos >= TX_FRAME_MAX_ENCODED {
                    // WARNING: declared payload length would overflow the RX
                    // buffer  -  abandon the frame instead of silently
                    // truncating it and presenting a short frame as complete.
                    self.state = RxState::WaitSof;
                    self.pos = 0;
                    return false;
                }
                self.buf[self.pos] = byte;
                self.pos += 1;
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
                    // Both CRC bytes received  -  verify integrity before
                    // surfacing the frame as complete.
                    self.state = RxState::WaitSof;
                    // INVARIANT: Crc state is only reached after Header fully
                    // decodes (pos >= 5), so pos - 2 and pos - 1 are always
                    // valid indices into buf here.
                    let received_crc =
                        u16::from_be_bytes([self.buf[self.pos - 2], self.buf[self.pos - 1]]);
                    let header_bytes = &self.buf[1..4];
                    let payload_bytes = &self.buf[5..self.pos - 2];
                    let computed_crc = compute_crc_over(header_bytes, payload_bytes);
                    if received_crc == computed_crc {
                        true
                    } else {
                        self.crc_errors += 1;
                        false
                    }
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
    pub(crate) fn take_raw(&self) -> &[u8] {
        &self.buf[..self.pos]
    }

    /// Payload length decoded FROM the most recently completed frame header.
    pub(crate) const fn last_payload_len(&self) -> u16 {
        self.payload_len
    }

    /// Count of frames discarded due to a CRC-16 CCITT mismatch on RX.
    pub(crate) const fn crc_errors(&self) -> u32 {
        self.crc_errors
    }
}

// ── StpTransport ──────────────────────────────────────────────────────────────

/// STP UART transport with sliding-window TX and byte-stream RX.
///
/// The transport encodes outgoing [`StpFrame`]s INTO the TX window and
/// advances the window as ACKs arrive. The RX side assembles raw bytes
/// FROM UART INTO complete frames via [`RxParser`].
pub(crate) struct StpTransport {
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
    pub(crate) fn new() -> Self {
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
    pub(crate) fn new_with_config(config: &Config) -> Self {
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
    pub(crate) const fn retry_limit(&self) -> u8 {
        self.retry_limit
    }

    /// TX timeout in milliseconds this transport was constructed with.
    #[must_use]
    pub(crate) const fn tx_timeout_ms(&self) -> u32 {
        self.tx_timeout_ms
    }

    /// Enqueue `frame` in the TX sliding window.
    ///
    /// Returns the slot index on success, or [`TransportError::WindowFull`]
    /// when all [`WINDOW_SIZE`] slots are occupied.
    ///
    /// Time: O(1) — scans the fixed [`WINDOW_SIZE`] (7)-slot array for a free
    /// slot; `WINDOW_SIZE` is a compile-time protocol constant, not a
    /// function of runtime input.
    /// Space: O(1) — writes into an existing array slot; no allocation.
    #[must_use = "enqueue failure must be handled"]
    pub(crate) fn enqueue(&mut self, frame: &StpFrame) -> Result<usize, TransportError> {
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
    ///
    /// Time: O(1) — scans the fixed [`WINDOW_SIZE`] (7)-slot array;
    /// `WINDOW_SIZE` is a compile-time protocol constant.
    /// Space: O(1) — no allocation.
    #[must_use = "ack failure must be handled"]
    pub(crate) fn acknowledge(&mut self, seq: u8) -> Result<(), TransportError> {
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
    ///
    /// Time: O(1) — `position()` scans the fixed [`WINDOW_SIZE`] (7)-slot
    /// array; `WINDOW_SIZE` is a compile-time protocol constant.
    /// Space: O(1) — no allocation; returns a borrow of the existing
    /// [`TxEntry`] buffer.
    #[must_use = "retransmit failure must be handled"]
    pub(crate) fn retransmit(&mut self, seq: u8) -> Result<&[u8], TransportError> {
        let limit = self.retry_limit;
        // Locate the window slot holding this seq (read-only borrow, released
        // before any mutation below so the terminal-failure clear and the
        // success-path reborrow do not overlap — see #351).
        let Some(idx) = self
            .tx_window
            .iter()
            .position(|slot| slot.as_ref().is_some_and(|e| e.seq == seq))
        else {
            return Err(TransportError::StaleAck { seq });
        };

        // Terminal failure: free the slot on retry exhaustion, mirroring
        // acknowledge()'s cleanup  -  otherwise a link-declared-dead frame
        // occupies its window slot forever (no ACK will ever arrive for it),
        // and enough exhausted slots permanently write-locks the transport.
        if self.tx_window[idx]
            .as_ref()
            .is_some_and(|e| e.retries >= limit)
        {
            self.tx_window[idx] = None;
            return Err(TransportError::RetryLimitExceeded { seq, limit });
        }

        // Otherwise bump the retry count and hand back the encoded bytes.
        let Some(entry) = self.tx_window[idx].as_mut() else {
            return Err(TransportError::StaleAck { seq });
        };
        entry.retries += 1;
        Ok(entry.as_bytes())
    }

    /// Feed one received byte INTO the RX parser.
    ///
    /// Returns `Some(&[u8])` with the raw frame bytes when a complete frame
    /// has been assembled, or `None` if more bytes are needed.
    pub(crate) fn receive_byte(&mut self, byte: u8) -> Option<&[u8]> {
        if self.rx_parser.push_byte(byte) {
            Some(self.rx_parser.take_raw())
        } else {
            None
        }
    }

    /// Number of in-flight frames currently occupying window slots.
    ///
    /// Time: O(1) — counts occupied slots in the fixed [`WINDOW_SIZE`]
    /// (7)-slot array; `WINDOW_SIZE` is a compile-time protocol constant.
    /// Space: O(1) — no allocation.
    pub(crate) fn in_flight(&self) -> usize {
        self.tx_window.iter().filter(|s| s.is_some()).count()
    }

    /// Next TX sequence number (0–7).
    pub(crate) const fn next_seq(&self) -> u8 {
        self.tx_seq
    }

    /// Count of received frames discarded due to a CRC-16 CCITT mismatch.
    ///
    /// Time: O(1) — returns the RX parser's stored counter; no iteration.
    /// Space: O(1) — no allocation.
    pub(crate) const fn crc_errors(&self) -> u32 {
        self.rx_parser.crc_errors()
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
    fn retransmit_limit_exceeded_frees_window_slot_for_reuse() {
        let mut t = StpTransport::new();
        // Fill every window slot and drive each to RetryLimitExceeded.
        for i in 0..WINDOW_SIZE {
            let seq = u8::try_from(i).unwrap_or_default() & 0x07;
            let frame = make_frame(seq, b"exhaust");
            t.enqueue(&frame)
                .unwrap_or_else(|_| panic!("enqueue {i} must succeed when window not full"));
        }
        for i in 0..WINDOW_SIZE {
            let seq = u8::try_from(i).unwrap_or_default() & 0x07;
            for _ in 0..RETRY_LIMIT {
                t.retransmit(seq).unwrap_or_default();
            }
            let err = t.retransmit(seq);
            assert!(
                matches!(err, Err(TransportError::RetryLimitExceeded { .. })),
                "slot {i} must report RetryLimitExceeded once retries are exhausted"
            );
        }

        assert_eq!(
            t.in_flight(),
            0,
            "every exhausted slot must be freed, not permanently occupied"
        );

        // The transport must accept new traffic instead of staying write-locked.
        let next = make_frame(0, b"fresh");
        assert!(
            t.enqueue(&next).is_ok(),
            "enqueue must succeed after all slots are freed by retry exhaustion"
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
    fn rx_parser_rejects_frame_with_corrupted_payload_byte() {
        let frame = make_frame(0, b"integrity-check");
        let mut encoded = [0u8; TX_FRAME_MAX_ENCODED];
        let len = frame.encode(&mut encoded);

        // Flip one payload byte after encoding (payload starts at index 5);
        // the trailing CRC bytes are left untouched, simulating line
        // corruption/injection after the sender computed the CRC.
        encoded[5] ^= 0xFF;

        let mut t = StpTransport::new();
        let mut saw_complete = false;
        for &byte in encoded.iter().take(len) {
            if t.receive_byte(byte).is_some() {
                saw_complete = true;
            }
        }
        assert!(
            !saw_complete,
            "a frame with a corrupted payload byte must never be surfaced as complete"
        );
        assert_eq!(
            t.crc_errors(),
            1,
            "crc_errors must increment exactly once for the corrupted frame"
        );
    }

    #[test]
    fn rx_parser_accepts_intact_frame_and_leaves_crc_errors_at_zero() {
        let frame = make_frame(1, b"clean");
        let mut encoded = [0u8; TX_FRAME_MAX_ENCODED];
        let len = frame.encode(&mut encoded);

        let mut t = StpTransport::new();
        let mut complete = None;
        for &byte in encoded.iter().take(len) {
            if let Some(raw) = t.receive_byte(byte) {
                complete = Some(raw.to_vec());
            }
        }
        assert!(complete.is_some(), "an intact frame must complete");
        assert_eq!(
            t.crc_errors(),
            0,
            "an intact frame must not count as a CRC error"
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

    #[test]
    fn rx_parser_reassembles_max_payload_frame_without_truncation() {
        // WHY: proves TX_FRAME_MAX_ENCODED exactly accommodates the largest
        // legitimately-decodable frame (12-bit length field, max 4095 ==
        // MAX_PAYLOAD) with zero loss, i.e. the overflow-bail path above is
        // never hit on a real frame.
        let payload = [0xABu8; MAX_PAYLOAD];
        let frame = make_frame(0, &payload);
        let mut encoded = [0u8; TX_FRAME_MAX_ENCODED];
        let len = frame.encode(&mut encoded);
        assert_eq!(
            len, TX_FRAME_MAX_ENCODED,
            "max-payload frame must fill the encode buffer exactly"
        );

        let mut t = StpTransport::new();
        let mut complete = None;
        for &byte in encoded.iter().take(len) {
            if let Some(raw) = t.receive_byte(byte) {
                complete = Some(raw.to_vec());
            }
        }
        let raw = complete.unwrap_or_default();
        assert_eq!(
            raw.len(),
            TX_FRAME_MAX_ENCODED,
            "a max-size frame must be reassembled at full length, never silently truncated"
        );
    }

    #[test]
    fn rx_parser_assembles_back_to_back_frames() {
        // WHY: the RX parser resets to WaitSof immediately after every
        // completed frame (match or mismatch), so a second frame arriving
        // with no gap after the first must not be lost or merged into the
        // first frame's tail.
        let frame_a = make_frame(0, b"first");
        let frame_b = make_frame(1, b"second");
        let mut encoded_a = [0u8; TX_FRAME_MAX_ENCODED];
        let mut encoded_b = [0u8; TX_FRAME_MAX_ENCODED];
        let len_a = frame_a.encode(&mut encoded_a);
        let len_b = frame_b.encode(&mut encoded_b);

        let mut t = StpTransport::new();
        let mut completed: Vec<Vec<u8>> = Vec::new();
        for &byte in encoded_a
            .iter()
            .take(len_a)
            .chain(encoded_b.iter().take(len_b))
        {
            if let Some(raw) = t.receive_byte(byte) {
                completed.push(raw.to_vec());
            }
        }

        assert_eq!(
            completed.len(),
            2,
            "both back-to-back frames must be surfaced as complete, got {completed:?}"
        );
        assert_eq!(
            completed[0].len(),
            len_a,
            "first frame length must match its own encoding, not bleed into the second"
        );
        assert_eq!(
            completed[1].len(),
            len_b,
            "second frame length must match its own encoding"
        );
        assert_eq!(
            t.crc_errors(),
            0,
            "two intact back-to-back frames must not register any CRC errors"
        );
    }

    #[test]
    fn rx_parser_resyncs_after_truncated_frame_precedes_valid_frame() {
        // WHY: simulates a truncated/corrupted transmission  -  an SOF
        // followed by an all-zero header (decodes to a zero-length payload)
        // and a garbage CRC, mirroring a dropped/re-established UART link.
        // The bogus mini-frame is fully consumed and rejected without
        // wedging the state machine, so the parser must resynchronize
        // cleanly on the SOF of the frame that follows.
        let truncated_then_garbage = [0x80u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

        let frame = make_frame(2, b"resynced");
        let mut encoded = [0u8; TX_FRAME_MAX_ENCODED];
        let len = frame.encode(&mut encoded);

        let mut t = StpTransport::new();
        for &byte in &truncated_then_garbage {
            let _ = t.receive_byte(byte);
        }
        let crc_errors_before_valid_frame = t.crc_errors();

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
            "the valid frame following the truncated/garbage prefix must start with SOF"
        );
        assert_eq!(
            raw.len(),
            len,
            "the valid frame following the truncated/garbage prefix must be fully reassembled"
        );
        assert_eq!(
            t.crc_errors(),
            crc_errors_before_valid_frame,
            "the valid frame itself must not register a new CRC error"
        );
    }
}
