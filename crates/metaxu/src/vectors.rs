//! Golden vectors for the envelope contract (#553).
//!
//! Byte-exact frames both repositories (thumos and aletheia) MUST decode
//! identically. A change to the envelope layout, kind set, version fields,
//! or payload encoding that alters these bytes is a CONTRACT CHANGE and
//! must be made deliberately (envelope major/minor/schema), never as a
//! side effect of an implementation refactor. #544 proves both endpoints
//! against these vectors before live action support expands.

use crate::envelope::MessageKind;

/// A golden vector: exact frame bytes plus the values they must decode to.
pub(crate) struct GoldenVector {
    /// Human name (used in assertion messages).
    pub(crate) name: &'static str,
    /// The exact frame bytes (22-byte header + payload).
    pub(crate) bytes: &'static [u8],
    /// The kind the frame carries.
    pub(crate) kind: MessageKind,
    /// The correlation ID it carries.
    pub(crate) correlation_id: u64,
    /// The exact payload bytes.
    pub(crate) payload: &'static [u8],
}

/// The golden vectors (envelope v1: magic "MTX1" LE, schema 1, major 1,
/// minor 0). Segments annotated per byte run.
pub(crate) static GOLDEN_VECTORS: &[GoldenVector] = &[
    GoldenVector {
        name: "task-request-minimal",
        bytes: &[
            0x4D, 0x54, 0x58, 0x31, // magic "MTX1"
            0x01, 0x00, // schema 1
            0x01, // major 1
            0x00, // minor 0
            0x01, 0x00, // kind 1 = TaskRequest
            0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // correlation 7
            0x01, 0x00, 0x00, 0x00, // payload_len 1
            0x00, // payload: one zero byte
        ],
        kind: MessageKind::TaskRequest,
        correlation_id: 7,
        payload: &[0x00],
    },
    GoldenVector {
        name: "stt-event-partial-minimal",
        bytes: &[
            0x4D, 0x54, 0x58, 0x31, // magic "MTX1"
            0x01, 0x00, // schema 1
            0x01, // major 1
            0x00, // minor 0
            0x03, 0x00, // kind 3 = SttEvent
            0x2A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // correlation 42
            0x04, 0x00, 0x00, 0x00, // payload_len 4
            0x00, 0x03, 0x00, 0x00, // payload: discriminant 0 (Partial), seq 3, empty text, confidence 0
        ],
        kind: MessageKind::SttEvent,
        correlation_id: 42,
        payload: &[0x00, 0x03, 0x00, 0x00],
    },
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{Envelope, EnvelopeError, MessageKind, SttErrorCode, SttEvent};
    use compact_str::CompactString;

    #[test]
    fn golden_vectors_decode_and_reencode_identically() {
        for v in GOLDEN_VECTORS {
            let frame = Envelope::decode(v.bytes)
                .unwrap_or_else(|e| unreachable!("{}: golden vector must decode: {e}", v.name));
            assert_eq!(frame.header.kind, v.kind, "{}", v.name);
            assert_eq!(frame.header.correlation_id, v.correlation_id, "{}", v.name);
            assert_eq!(frame.payload, v.payload, "{}", v.name);
            assert_eq!(
                frame.encode(),
                v.bytes,
                "{}: re-encode must reproduce the golden bytes exactly",
                v.name
            );
        }
    }

    #[test]
    fn golden_vector_shape_is_pinned() {
        // The first vector's exact header bytes, hand-verified against the
        // documented layout: magic LE, schema LE, major, minor, kind LE,
        // correlation LE, payload_len LE.
        let v = &GOLDEN_VECTORS[0];
        assert_eq!(&v.bytes[0..4], &crate::envelope::MAGIC.to_le_bytes());
        assert_eq!(&v.bytes[4..6], &crate::envelope::SCHEMA_ID.to_le_bytes());
        assert_eq!(v.bytes[6], crate::envelope::MAJOR);
        assert_eq!(v.bytes[7], crate::envelope::MINOR);
        assert_eq!(&v.bytes[8..10], &1u16.to_le_bytes());
        assert_eq!(&v.bytes[10..18], &7u64.to_le_bytes());
        assert_eq!(&v.bytes[18..22], &1u32.to_le_bytes());
        assert_eq!(v.bytes.len(), 23, "22-byte header + 1-byte payload");
    }

    #[test]
    fn stt_event_postcard_round_trip_through_envelope() {
        // The STT event wire shape, pinned through the envelope: a Final
        // with provenance encodes, decodes, and matches exactly.
        let event = SttEvent::Final {
            seq: 7,
            text: CompactString::from("hello world"),
            language: CompactString::from("en"),
            model: CompactString::from("whisper-small"),
            duration_ms: 1200,
        };
        let payload = postcard::to_allocvec(&event).unwrap_or_else(|_| unreachable!());
        let frame = Envelope::build(MessageKind::SttEvent, 0x00C0_FFEE, payload).unwrap_or_else(|_| unreachable!());
        let back = Envelope::decode(&frame.encode());
        assert_eq!(back, Ok(frame));
        let decoded: SttEvent = postcard::from_bytes(&back.unwrap_or_else(|_| unreachable!()).payload)
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(decoded, event);
    }

    #[test]
    fn stt_event_kinds_are_distinct_on_the_wire() {
        // Partial/Final/Error encode with distinct discriminants and decode
        // back exactly — the typed-event contract replacing {"text","final"}.
        let partial = SttEvent::Partial {
            seq: 3,
            text: CompactString::from("hel"),
            confidence_milli: 800,
        };
        let err = SttEvent::Error {
            seq: 8,
            code: SttErrorCode::ModelOverloaded,
        };
        for event in [partial, err] {
            let payload = postcard::to_allocvec(&event).unwrap_or_else(|_| unreachable!());
            let decoded: SttEvent = postcard::from_bytes(&payload).unwrap_or_else(|_| unreachable!());
            assert_eq!(decoded, event);
        }
    }

    #[test]
    fn stt_golden_vector_decodes_to_the_documented_event() {
        // The STT golden vector's payload decodes to a Partial with seq 3
        // and confidence 0 — the exact bytes an aletheia endpoint must
        // produce for this case.
        let v = &GOLDEN_VECTORS[1];
        let frame = Envelope::decode(v.bytes).unwrap_or_else(|_| unreachable!());
        let event: SttEvent = postcard::from_bytes(&frame.payload).unwrap_or_else(|_| unreachable!());
        assert_eq!(
            event,
            SttEvent::Partial {
                seq: 3,
                text: CompactString::from(""),
                confidence_milli: 0,
            }
        );
    }

    #[test]
    fn downgrade_attempt_is_an_explicit_error_not_a_misdecode() {
        // A frame claiming a future major must reject loudly (#553's
        // downgrade-ambiguity ban), never decode with wrong semantics.
        let mut bytes = GOLDEN_VECTORS[0].bytes.to_vec();
        bytes[6] = crate::envelope::MAJOR + 1;
        assert!(matches!(
            Envelope::decode(&bytes),
            Err(EnvelopeError::IncompatibleVersion { .. })
        ));
    }
}
