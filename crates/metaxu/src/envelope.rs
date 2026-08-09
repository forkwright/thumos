//! The versioned wire envelope: the ONE shared Aletheia-facing contract
//! (#553).
//!
//! Every Aletheia-facing frame — task request, task response, STT event —
//! travels inside this envelope. It exists so two repositories (thumos and
//! aletheia) never ship separate assumptions: magic + schema identity,
//! major/minor version, message kind, correlation ID, and declared length
//! are checked BEFORE any allocation or payload decode, and decoding is
//! exact (a frame is the header plus exactly `payload_len` bytes, no more,
//! no less).
//!
//! # Layout (22-byte fixed header, little-endian)
//!
//! ```text
//! [0..4)   magic: u32 = MAGIC ("MTX1" bytes 4D 54 58 31)
//! [4..6)   schema: u16 = SCHEMA_ID (1)
//! [6]      major: u8   = MAJOR (1)
//! [7]      minor: u8   = MINOR (0)
//! [8..10)  kind: u16   = MessageKind
//! [10..18) correlation_id: u64 (request/response/event correlation)
//! [18..22) payload_len: u32 (declared; ceiling-checked BEFORE allocation)
//! [22..)   payload (postcard bytes for the kind's payload type)
//! ```
//!
//! # Compatibility rules
//!
//! - Wrong magic or schema: reject (`BadMagic` / `UnsupportedSchema`) —
//!   never a silent misdecode.
//! - `major` mismatch: reject (`IncompatibleVersion`). A major bump is
//!   never negotiated silently.
//! - `minor` NEWER than ours: accepted ONLY if `kind` is known and the
//!   payload decodes exactly — minor bumps may ADD kinds or optional
//!   fields within a kind, never change an existing kind's payload shape.
//!   An unknown kind always rejects (`UnknownKind`).
//! - `minor` older than ours: accepted (symmetric rule).
//! - `payload_len` above the kind's ceiling: reject (`FrameTooLarge`)
//!   BEFORE allocating — a 1 GB device never allocates on a peer's say-so.
//! - Actual bytes != 22 + `payload_len`: reject (`TruncatedFrame` /
//!   `TrailingBytes`) — exact decoding, always.
//!
//! Golden vectors live in `vectors.rs`; both repositories must decode them
//! identically (#544 proves both endpoints against them).

use compact_str::CompactString;
use serde::{Deserialize, Serialize};
use snafu::Snafu;

/// Envelope magic bytes: "MTX1" as a u32 LE (4D 54 58 31 on the wire).
pub(crate) const MAGIC: u32 = 0x3158_544D;

/// Schema family identifier (bump only for a new envelope family).
pub(crate) const SCHEMA_ID: u16 = 1;

/// Major version: incompatible changes only.
pub(crate) const MAJOR: u8 = 1;

/// Minor version: additive changes within [`MAJOR`]. MINOR 1 adds the
/// authenticated kinds (4, 5) per the #553 compat rule (#544).
pub(crate) const MINOR: u8 = 1;

/// Fixed header length in bytes.
pub(crate) const HEADER_LEN: usize = 22;

/// Per-kind payload ceilings (v1). Derived from content classes:
/// - STT text is one utterance: 4 KiB.
/// - Task requests/responses carry summaries, drafts, small batches: 32 KiB.
pub(crate) const MAX_STT_PAYLOAD: u32 = 4 * 1024;
/// Task request payload ceiling.
pub(crate) const MAX_TASK_REQUEST_PAYLOAD: u32 = 32 * 1024;
/// Task response payload ceiling.
pub(crate) const MAX_TASK_RESPONSE_PAYLOAD: u32 = 32 * 1024;

/// Authenticated request payload ceiling: the task ceiling plus room for
/// the grant wrapper (~256 B) (#544).
pub(crate) const MAX_AUTH_REQUEST_PAYLOAD: u32 = 34 * 1024;

/// Authenticated response payload ceiling (response + 32 B MAC) (#544).
pub(crate) const MAX_AUTH_RESPONSE_PAYLOAD: u32 = 33 * 1024;

/// The message kinds this envelope version knows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[must_use]
#[non_exhaustive]
#[repr(u16)]
pub enum MessageKind {
    /// A task request (device action proposal).
    TaskRequest = 1,
    /// A task response (accepted/rejected).
    TaskResponse = 2,
    /// An STT event (partial/final/error).
    SttEvent = 3,
    /// An authenticated task request (grant + task) — MINOR 1 (#544).
    AuthenticatedRequest = 4,
    /// An authenticated task response (response + MAC) — MINOR 1 (#544).
    AuthenticatedResponse = 5,
}

impl MessageKind {
    /// Parse a wire kind value.
    const fn from_u16(v: u16) -> Option<Self> {
        match v {
            1 => Some(Self::TaskRequest),
            2 => Some(Self::TaskResponse),
            3 => Some(Self::SttEvent),
            4 => Some(Self::AuthenticatedRequest),
            5 => Some(Self::AuthenticatedResponse),
            _ => None,
        }
    }

    /// This kind's wire value (the inverse of [`Self::from_u16`]).
    const fn to_u16(self) -> u16 {
        match self {
            Self::TaskRequest => 1,
            Self::TaskResponse => 2,
            Self::SttEvent => 3,
            Self::AuthenticatedRequest => 4,
            Self::AuthenticatedResponse => 5,
        }
    }

    /// This kind's payload ceiling.
    const fn payload_ceiling(self) -> u32 {
        match self {
            Self::TaskRequest => MAX_TASK_REQUEST_PAYLOAD,
            Self::TaskResponse => MAX_TASK_RESPONSE_PAYLOAD,
            Self::SttEvent => MAX_STT_PAYLOAD,
            Self::AuthenticatedRequest => MAX_AUTH_REQUEST_PAYLOAD,
            Self::AuthenticatedResponse => MAX_AUTH_RESPONSE_PAYLOAD,
        }
    }
}

/// Envelope errors: every reject is explicit and named (#553).
#[derive(Debug, Clone, PartialEq, Eq, Snafu)]
#[snafu(visibility(pub(crate)))]
#[must_use]
#[non_exhaustive]
pub enum EnvelopeError {
    /// Magic bytes did not match.
    #[snafu(display("bad envelope magic"))]
    BadMagic,
    /// Schema family is not supported.
    #[snafu(display("unsupported schema {schema}"))]
    UnsupportedSchema {
        /// The frame's schema ID.
        schema: u16,
    },
    /// Major version mismatch — never silently negotiated.
    #[snafu(display("incompatible major version (ours {ours}, theirs {theirs})"))]
    IncompatibleVersion {
        /// Our major.
        ours: u8,
        /// The frame's major.
        theirs: u8,
    },
    /// The kind value is not known at this version.
    #[snafu(display("unknown message kind {kind}"))]
    UnknownKind {
        /// The frame's kind field.
        kind: u16,
    },
    /// A decoder was handed a frame of a different kind than it expects.
    #[snafu(display("unexpected kind: expected {expected:?}, got {got:?}"))]
    UnexpectedKind {
        /// The kind the caller asked for.
        expected: MessageKind,
        /// The kind the frame carries.
        got: MessageKind,
    },
    /// Declared payload length exceeds the kind's ceiling.
    #[snafu(display("frame too large for {kind:?}: declared {declared} > ceiling {ceiling}"))]
    FrameTooLarge {
        /// The kind.
        kind: MessageKind,
        /// The declared length.
        declared: u32,
        /// The ceiling.
        ceiling: u32,
    },
    /// Fewer bytes than 22 + `payload_len` arrived.
    #[snafu(display("truncated frame: expected {expected} bytes, have {present}"))]
    TruncatedFrame {
        /// Bytes expected.
        expected: usize,
        /// Bytes present.
        present: usize,
    },
    /// More bytes than 22 + `payload_len` arrived (exact decoding).
    #[snafu(display("{extra} trailing bytes after frame"))]
    TrailingBytes {
        /// Extra byte count.
        extra: usize,
    },
}

/// A parsed envelope header (validated; the payload is checked separately).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EnvelopeHeader {
    /// Message kind.
    pub(crate) kind: MessageKind,
    /// Correlation ID.
    pub(crate) correlation_id: u64,
    /// Declared payload length (ceiling-checked already).
    pub(crate) payload_len: u32,
    /// The frame's minor version.
    pub(crate) minor: u8,
}

impl EnvelopeHeader {
    /// Encode the header bytes for an outgoing frame.
    fn encode(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[0..4].copy_from_slice(&MAGIC.to_le_bytes());
        out[4..6].copy_from_slice(&SCHEMA_ID.to_le_bytes());
        out[6] = MAJOR;
        out[7] = MINOR;
        out[8..10].copy_from_slice(&self.kind.to_u16().to_le_bytes());
        out[10..18].copy_from_slice(&self.correlation_id.to_le_bytes());
        out[18..22].copy_from_slice(&self.payload_len.to_le_bytes());
        out
    }

    /// Parse + validate a header from the front of `bytes`.
    ///
    /// Checks magic, schema, major compat, kind, and the payload ceiling —
    /// everything BEFORE the caller allocates for a payload (#553).
    fn parse(bytes: &[u8]) -> Result<Self, EnvelopeError> {
        if bytes.len() < HEADER_LEN {
            return Err(EnvelopeError::TruncatedFrame {
                expected: HEADER_LEN,
                present: bytes.len(),
            });
        }
        let magic = u32::from_le_bytes(
            bytes[0..4]
                .try_into()
                .map_err(|_| EnvelopeError::BadMagic)?,
        );
        if magic != MAGIC {
            return Err(EnvelopeError::BadMagic);
        }
        let schema = u16::from_le_bytes(
            bytes[4..6]
                .try_into()
                .map_err(|_| EnvelopeError::UnsupportedSchema { schema: 0 })?,
        );
        if schema != SCHEMA_ID {
            return Err(EnvelopeError::UnsupportedSchema { schema });
        }
        let major = bytes[6];
        if major != MAJOR {
            return Err(EnvelopeError::IncompatibleVersion {
                ours: MAJOR,
                theirs: major,
            });
        }
        let minor = bytes[7];
        let kind_raw = u16::from_le_bytes(
            bytes[8..10]
                .try_into()
                .map_err(|_| EnvelopeError::UnknownKind { kind: 0 })?,
        );
        let kind =
            MessageKind::from_u16(kind_raw).ok_or(EnvelopeError::UnknownKind { kind: kind_raw })?;
        let correlation_id = u64::from_le_bytes(
            bytes[10..18]
                .try_into()
                .map_err(|_| EnvelopeError::BadMagic)?,
        );
        let payload_len = u32::from_le_bytes(
            bytes[18..22]
                .try_into()
                .map_err(|_| EnvelopeError::BadMagic)?,
        );
        let ceiling = kind.payload_ceiling();
        if payload_len > ceiling {
            return Err(EnvelopeError::FrameTooLarge {
                kind,
                declared: payload_len,
                ceiling,
            });
        }
        Ok(Self {
            kind,
            correlation_id,
            payload_len,
            minor,
        })
    }
}

/// An owned, fully-validated frame (header + exact payload).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Envelope {
    /// The validated header.
    pub(crate) header: EnvelopeHeader,
    /// The payload bytes (exactly `header.payload_len` long).
    pub(crate) payload: Vec<u8>,
}

impl Envelope {
    /// Build an outgoing frame from kind/correlation/payload.
    ///
    /// # Errors
    ///
    /// [`EnvelopeError::FrameTooLarge`] if the payload exceeds the kind's
    /// ceiling (outgoing frames obey the same bound as incoming).
    pub(crate) fn build(
        kind: MessageKind,
        correlation_id: u64,
        payload: Vec<u8>,
    ) -> Result<Self, EnvelopeError> {
        let payload_len =
            u32::try_from(payload.len()).map_err(|_| EnvelopeError::FrameTooLarge {
                kind,
                declared: u32::MAX,
                ceiling: kind.payload_ceiling(),
            })?;
        let ceiling = kind.payload_ceiling();
        if payload_len > ceiling {
            return Err(EnvelopeError::FrameTooLarge {
                kind,
                declared: payload_len,
                ceiling,
            });
        }
        Ok(Self {
            header: EnvelopeHeader {
                kind,
                correlation_id,
                payload_len,
                minor: MINOR,
            },
            payload,
        })
    }

    /// Serialize the frame (header + payload).
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.payload.len());
        out.extend_from_slice(&self.header.encode());
        out.extend_from_slice(&self.payload);
        out
    }

    /// Parse a frame, enforcing exact decoding: the input must be EXACTLY
    /// one frame (no truncation, no trailing bytes), and the payload length
    /// is ceiling-checked BEFORE the payload is copied (#553).
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, EnvelopeError> {
        let header = EnvelopeHeader::parse(bytes)?;
        let payload_len =
            usize::try_from(header.payload_len).map_err(|_| EnvelopeError::FrameTooLarge {
                kind: header.kind,
                declared: header.payload_len,
                ceiling: header.kind.payload_ceiling(),
            })?;
        let expected = HEADER_LEN + payload_len;
        if bytes.len() < expected {
            return Err(EnvelopeError::TruncatedFrame {
                expected,
                present: bytes.len(),
            });
        }
        if bytes.len() > expected {
            return Err(EnvelopeError::TrailingBytes {
                extra: bytes.len() - expected,
            });
        }
        Ok(Self {
            header,
            payload: bytes[HEADER_LEN..expected].to_vec(),
        })
    }
}

// ---------------------------------------------------------------------------
// Typed STT events (#553): partial/final/error with sequence + provenance
// ---------------------------------------------------------------------------

/// A typed STT event — the payload of a [`MessageKind::SttEvent`] frame.
///
/// Replaces the ad hoc `{"text", "final"}` convention: every event carries
/// a session-correlated sequence number and, for finals, provenance
/// (language, model, audio duration) so a transcript is auditable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[must_use]
#[non_exhaustive]
pub enum SttEvent {
    /// An in-progress partial result (seq is monotonic within a session).
    Partial {
        /// Sequence number within the session (monotonic).
        seq: u32,
        /// Partial transcript text (bounded by the frame ceiling).
        text: CompactString,
        /// Recognizer confidence, per-mille when known (0 = unknown).
        confidence_milli: u16,
    },
    /// The session's final transcript, with provenance.
    Final {
        /// Sequence number (greater than every partial's).
        seq: u32,
        /// Final transcript text.
        text: CompactString,
        /// BCP-47 language tag actually recognized.
        language: CompactString,
        /// Model identifier that produced the transcript.
        model: CompactString,
        /// Audio duration processed, milliseconds.
        duration_ms: u32,
    },
    /// A terminal error event.
    Error {
        /// Sequence number.
        seq: u32,
        /// Typed error code.
        code: SttErrorCode,
    },
}

/// Typed STT error codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[must_use]
#[non_exhaustive]
pub enum SttErrorCode {
    /// The recognizer is overloaded/unavailable.
    ModelOverloaded,
    /// The audio stream was malformed or unsupported.
    BadAudio,
    /// The session was cancelled by the service.
    Cancelled,
}

impl SttEvent {
    /// The event's sequence number.
    pub const fn seq(&self) -> u32 {
        match self {
            Self::Partial { seq, .. } | Self::Final { seq, .. } | Self::Error { seq, .. } => *seq,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_payload(kind: MessageKind) -> Vec<u8> {
        match kind {
            MessageKind::TaskRequest => b"task-payload".to_vec(),
            MessageKind::TaskResponse => b"response-payload".to_vec(),
            MessageKind::SttEvent => b"stt".to_vec(),
            MessageKind::AuthenticatedRequest => b"auth-request".to_vec(),
            MessageKind::AuthenticatedResponse => b"auth-response".to_vec(),
        }
    }

    #[test]
    fn round_trip_preserves_frame() {
        for kind in [
            MessageKind::TaskRequest,
            MessageKind::TaskResponse,
            MessageKind::SttEvent,
            MessageKind::AuthenticatedRequest,
            MessageKind::AuthenticatedResponse,
        ] {
            let frame = Envelope::build(kind, 0xA5A5_1234, sample_payload(kind)).ok();
            assert!(frame.is_some());
            let frame = frame.unwrap_or_else(|| unreachable!());
            let bytes = frame.encode();
            let back = Envelope::decode(&bytes);
            assert_eq!(back, Ok(frame), "{kind:?} must round-trip exactly");
        }
    }

    #[test]
    fn header_layout_is_exact() {
        let frame = Envelope::build(MessageKind::TaskRequest, 7, vec![1, 2, 3])
            .unwrap_or_else(|_| unreachable!());
        let bytes = frame.encode();
        assert_eq!(bytes.len(), HEADER_LEN + 3);
        assert_eq!(&bytes[0..4], &MAGIC.to_le_bytes(), "magic at [0..4)");
        assert_eq!(&bytes[4..6], &SCHEMA_ID.to_le_bytes(), "schema at [4..6)");
        assert_eq!(bytes[6], MAJOR, "major at [6]");
        assert_eq!(bytes[7], MINOR, "minor at [7]");
        assert_eq!(&bytes[8..10], &1u16.to_le_bytes(), "kind at [8..10)");
        assert_eq!(
            &bytes[10..18],
            &7u64.to_le_bytes(),
            "correlation at [10..18)"
        );
        assert_eq!(
            &bytes[18..22],
            &3u32.to_le_bytes(),
            "payload_len at [18..22)"
        );
        assert_eq!(&bytes[22..], &[1, 2, 3], "payload follows");
    }

    #[test]
    fn bad_magic_rejects() {
        let mut bytes = Envelope::build(MessageKind::TaskRequest, 1, vec![0])
            .unwrap_or_else(|_| unreachable!())
            .encode();
        bytes[0] ^= 0xFF;
        assert_eq!(Envelope::decode(&bytes), Err(EnvelopeError::BadMagic));
    }

    #[test]
    fn major_mismatch_rejects_explicitly() {
        let mut bytes = Envelope::build(MessageKind::TaskRequest, 1, vec![0])
            .unwrap_or_else(|_| unreachable!())
            .encode();
        bytes[6] = MAJOR + 1;
        assert_eq!(
            Envelope::decode(&bytes),
            Err(EnvelopeError::IncompatibleVersion {
                ours: MAJOR,
                theirs: MAJOR + 1,
            }),
            "a major bump is an explicit error, never a silent downgrade"
        );
    }

    #[test]
    fn unknown_kind_rejects() {
        let mut bytes = Envelope::build(MessageKind::TaskRequest, 1, vec![0])
            .unwrap_or_else(|_| unreachable!())
            .encode();
        bytes[8..10].copy_from_slice(&99u16.to_le_bytes());
        assert_eq!(
            Envelope::decode(&bytes),
            Err(EnvelopeError::UnknownKind { kind: 99 })
        );
    }

    #[test]
    fn oversized_payload_rejects_before_allocation() {
        let mut bytes = Envelope::build(MessageKind::SttEvent, 1, vec![0])
            .unwrap_or_else(|_| unreachable!())
            .encode();
        // Declare a payload one byte over the STT ceiling.
        bytes[18..22].copy_from_slice(&(MAX_STT_PAYLOAD + 1).to_le_bytes());
        assert_eq!(
            Envelope::decode(&bytes),
            Err(EnvelopeError::FrameTooLarge {
                kind: MessageKind::SttEvent,
                declared: MAX_STT_PAYLOAD + 1,
                ceiling: MAX_STT_PAYLOAD,
            }),
            "the ceiling check fires on the DECLARED length, before any payload copy"
        );
    }

    #[test]
    fn truncated_and_trailing_reject() {
        let frame = Envelope::build(MessageKind::TaskRequest, 1, b"abc".to_vec())
            .unwrap_or_else(|_| unreachable!());
        let bytes = frame.encode();
        let truncated = &bytes[..bytes.len() - 1];
        assert!(matches!(
            Envelope::decode(truncated),
            Err(EnvelopeError::TruncatedFrame { .. })
        ));
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(
            Envelope::decode(&trailing),
            Err(EnvelopeError::TrailingBytes { extra: 1 }),
            "exact decoding: extra bytes are a protocol error"
        );
    }

    #[test]
    fn newer_minor_with_known_kind_accepted() {
        // Compat rule: a newer minor is accepted when kind is known and the
        // payload decodes exactly (minor bumps are additive only).
        let mut bytes = Envelope::build(MessageKind::TaskRequest, 1, vec![0])
            .unwrap_or_else(|_| unreachable!())
            .encode();
        bytes[7] = MINOR + 1;
        let back = Envelope::decode(&bytes);
        assert!(back.is_ok(), "newer minor + known kind must accept");
        assert_eq!(
            back.ok().map(|f| f.header.minor),
            Some(MINOR + 1),
            "the frame's minor is preserved for the caller's semantics"
        );
    }

    #[test]
    fn build_rejects_over_ceiling_payload() {
        let too_big = vec![0u8; MAX_STT_PAYLOAD as usize + 1];
        assert!(matches!(
            Envelope::build(MessageKind::SttEvent, 1, too_big),
            Err(EnvelopeError::FrameTooLarge { .. })
        ));
    }

    #[test]
    fn stt_event_seq_accessor() {
        let p = SttEvent::Partial {
            seq: 3,
            text: "hello".into(),
            confidence_milli: 800,
        };
        assert_eq!(p.seq(), 3);
        let f = SttEvent::Final {
            seq: 7,
            text: "hello world".into(),
            language: "en".into(),
            model: "whisper-small".into(),
            duration_ms: 1200,
        };
        assert_eq!(f.seq(), 7);
        let e = SttEvent::Error {
            seq: 8,
            code: SttErrorCode::Cancelled,
        };
        assert_eq!(e.seq(), 8);
    }
}
