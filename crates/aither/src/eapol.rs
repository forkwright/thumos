//! EAPOL (Extensible Authentication Protocol over LAN) frame parsing and
//! encoding.
//!
//! Implements IEEE 802.1X-2020 framing used during the WPA2/WPA3 4-way
//! handshake. The frame types, parser, and encoder live in
//! [`aither_core::eapol`], shared with the thumos kernel (#545, #819) so the
//! two cannot drift; this module re-exports them directly rather than
//! wrapping them in a second, redundant type.

pub use aither_core::eapol::{
    DESCRIPTOR_TYPE_RSN, DESCRIPTOR_TYPE_WPA, EapolFrame, EapolKeyFrame, EapolType, Error, IV_LEN,
    KeyInfo, MIC_LEN, NONCE_LEN, encode, parse,
};

#[cfg(test)]
mod tests {
    use super::*;

    fn make_key_frame() -> EapolKeyFrame {
        EapolKeyFrame {
            descriptor_type: DESCRIPTOR_TYPE_RSN,
            key_info: KeyInfo(0x008a), // version=2, pairwise, ack
            key_length: 16,
            replay_counter: 1,
            nonce: [0xaa; NONCE_LEN],
            iv: [0u8; IV_LEN],
            rsc: 0,
            mic: [0u8; MIC_LEN],
            key_data: vec![0x01, 0x02, 0x03, 0x04],
        }
    }

    // WHY: adapter-boundary coverage only -- `aither_core::eapol` carries
    // the exhaustive parse/encode/descriptor-gate/truncation test suite.
    // This confirms the re-export resolves to a working parser, not the
    // parser's own correctness.
    #[test]
    fn key_frame_roundtrips_through_the_shared_codec() -> Result<(), Error> {
        let kf = make_key_frame();
        let frame = EapolFrame {
            version: 2,
            packet_type: EapolType::Key,
            key_frame: Some(kf.clone()),
            raw_body: Vec::new(),
        };
        let encoded = encode(&frame);
        let parsed = parse(&encoded)?;
        assert_eq!(
            parsed.key_frame,
            Some(kf),
            "key frame must survive encode/parse roundtrip through the shared codec"
        );
        Ok(())
    }

    #[test]
    fn errors_surface_through_the_re_exported_error_type() {
        let data = [0x02, 0x01, 0x00]; // truncated header
        assert!(
            matches!(parse(&data), Err(Error::TooShort { need: 4, have: 3 })),
            "a core parse failure must surface as this crate's re-exported Error"
        );
    }
}
