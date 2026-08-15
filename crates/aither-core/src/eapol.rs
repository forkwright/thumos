//! EAPOL (Extensible Authentication Protocol over LAN) frame parsing and encoding.
//!
//! Implements IEEE 802.1X-2020 framing and the EAPOL-Key body it carries
//! during the WPA2/WPA3 4-way handshake (IEEE 802.11-2020, section 12.7.2).

use alloc::vec::Vec;
use core::fmt;

/// Size of the EAPOL common header (version + type + length).
const EAPOL_HEADER_LEN: usize = 4;

/// Size of the fixed portion of an EAPOL-Key body (before variable key data).
///
/// Fields: `descriptor_type(1)` + `key_info(2)` + `key_length(2)` +
/// `replay_counter(8)` + nonce(32) + iv(16) + rsc(8) + reserved(8) + mic(16)
/// + `key_data_length(2)` = 95
const EAPOL_KEY_FIXED_LEN: usize = 95;

/// Length of the MIC field.
pub const MIC_LEN: usize = 16;

/// Length of the nonce field.
pub const NONCE_LEN: usize = 32;

/// Length of the IV field.
pub const IV_LEN: usize = 16;

/// RSN key descriptor type (WPA2/WPA3).
pub const DESCRIPTOR_TYPE_RSN: u8 = 0x02;

/// WPA (legacy) key descriptor type. Never accepted by [`parse`] -- kept
/// only so callers (tests, fuzzing) can name the rejected value instead of
/// a bare literal.
pub const DESCRIPTOR_TYPE_WPA: u8 = 0xFE;

/// A failure parsing an EAPOL frame.
///
/// Deliberately `Copy` and allocation-free: every variant carries only the
/// value or position needed to locate the fault, so the kernel can surface
/// one without a heap allocation on an error path fed by a hostile peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Buffer is too short to contain required fields.
    TooShort {
        /// Minimum required bytes.
        need: usize,
        /// Actual buffer length.
        have: usize,
    },
    /// Unrecognised EAPOL packet type byte.
    UnknownEapolType {
        /// The unrecognised type byte.
        value: u8,
    },
    /// EAPOL-Key frame descriptor type is not RSN ([`DESCRIPTOR_TYPE_RSN`]).
    /// A non-RSN or malformed descriptor must never be parsed and trusted
    /// as a WPA2 handshake frame.
    UnknownKeyDescriptorType {
        /// The unexpected descriptor type byte.
        value: u8,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort { need, have } => {
                write!(f, "frame too short: need {need} bytes, have {have}")
            }
            Self::UnknownEapolType { value } => {
                write!(f, "unknown EAPOL packet type: {value:#04x}")
            }
            Self::UnknownKeyDescriptorType { value } => {
                write!(f, "unknown EAPOL-Key descriptor type: {value:#04x}")
            }
        }
    }
}

/// EAPOL packet type discriminant (IEEE 802.1X-2020, table 11-3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EapolType {
    /// EAP authentication message.
    EapPacket,
    /// Supplicant requests authentication start.
    Start,
    /// Supplicant ends the authenticated session.
    Logoff,
    /// Key negotiation message (4-way handshake).
    Key,
}

impl EapolType {
    /// Parse from wire byte.
    const fn from_byte(b: u8) -> Result<Self, Error> {
        match b {
            0x00 => Ok(Self::EapPacket),
            0x01 => Ok(Self::Start),
            0x02 => Ok(Self::Logoff),
            0x03 => Ok(Self::Key),
            v => Err(Error::UnknownEapolType { value: v }),
        }
    }

    /// Encode to wire byte.
    const fn to_byte(self) -> u8 {
        match self {
            Self::EapPacket => 0x00,
            Self::Start => 0x01,
            Self::Logoff => 0x02,
            Self::Key => 0x03,
        }
    }
}

/// Packed key-information field (IEEE 802.11-2020, section 12.7.2, figure 12-33).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct KeyInfo(pub u16);

impl KeyInfo {
    /// Key descriptor version (bits 0-2).
    #[must_use]
    #[expect(
        clippy::as_conversions,
        reason = "masked to 3 bits (0x0007), result is always 0-7; fits u8 without truncation"
    )]
    pub const fn descriptor_version(self) -> u8 {
        (self.0 & 0x0007) as u8
    }

    /// True if pairwise (unicast) key; false for group/broadcast key.
    #[must_use]
    pub const fn pairwise(self) -> bool {
        self.0 & 0x0008 != 0
    }

    /// Key index for group keys (bits 4-5).
    #[must_use]
    #[expect(
        clippy::as_conversions,
        reason = "masked to 2 bits (0x03), result is always 0-3; fits u8 without truncation"
    )]
    pub const fn key_index(self) -> u8 {
        ((self.0 >> 4) & 0x03) as u8
    }

    /// True if supplicant shall install the key.
    #[must_use]
    pub const fn install(self) -> bool {
        self.0 & 0x0040 != 0
    }

    /// True if message requires an acknowledgement.
    #[must_use]
    pub const fn ack(self) -> bool {
        self.0 & 0x0080 != 0
    }

    /// True if a MIC is present in this frame.
    #[must_use]
    pub const fn mic(self) -> bool {
        self.0 & 0x0100 != 0
    }

    /// True if the RSNA has been established.
    #[must_use]
    pub const fn secure(self) -> bool {
        self.0 & 0x0200 != 0
    }

    /// True if key data is encrypted (AES-KEYWRAP).
    #[must_use]
    pub const fn encrypted_key_data(self) -> bool {
        self.0 & 0x1000 != 0
    }
}

/// EAPOL-Key frame body (IEEE 802.11-2020, section 12.7.2).
///
/// Deliberately NOT `#[non_exhaustive]`: this type has exactly two
/// consumers, both in this repository (`aither`, the kernel), both of which
/// construct it via struct literal -- test fixtures and
/// `wpa::WpaHandshake::build_response`. `non_exhaustive`'s purpose is
/// protecting a crate from consumers OUTSIDE it that cannot yet be
/// enumerated; there is no such consumer here, and the attribute would only
/// force every construction site through a builder for no safety gained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EapolKeyFrame {
    /// Key descriptor type (0x02 = RSN, 0xFE = WPA legacy).
    pub descriptor_type: u8,
    /// Key information flags.
    pub key_info: KeyInfo,
    /// Length of the pairwise temporal key in octets.
    pub key_length: u16,
    /// Strictly monotonic replay counter.
    pub replay_counter: u64,
    /// Authenticator or supplicant nonce (`ANonce` / `SNonce`).
    pub nonce: [u8; NONCE_LEN],
    /// Key IV (all-zero for CCMP; used by TKIP).
    pub iv: [u8; IV_LEN],
    /// RSC / GTK sequence counter.
    pub rsc: u64,
    /// Message Integrity Code (MIC field zeroed before MIC computation).
    pub mic: [u8; MIC_LEN],
    /// Optional key material (wrapped GTK or RSNE IE).
    pub key_data: Vec<u8>,
}

/// Top-level EAPOL frame.
///
/// See [`EapolKeyFrame`]'s doc comment for why this is not `#[non_exhaustive]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EapolFrame {
    /// Protocol version (1 = 802.1X-2001, 2 = 802.1X-2004, 3 = 802.1X-2010).
    pub version: u8,
    /// Packet type discriminant.
    pub packet_type: EapolType,
    /// Key frame (present only when `packet_type == EapolType::Key`).
    pub key_frame: Option<EapolKeyFrame>,
    /// Raw body bytes (for EAP-Packet, Start, and Logoff).
    pub raw_body: Vec<u8>,
}

/// Parse an EAPOL frame from a byte slice.
///
/// # Errors
///
/// Returns [`Error::TooShort`] when the slice cannot satisfy the declared
/// packet length, [`Error::UnknownEapolType`] for unrecognised packet type
/// bytes, and [`Error::UnknownKeyDescriptorType`] when an EAPOL-Key frame's
/// descriptor type is not RSN ([`DESCRIPTOR_TYPE_RSN`]).
pub fn parse(data: &[u8]) -> Result<EapolFrame, Error> {
    if data.len() < EAPOL_HEADER_LEN {
        return Err(Error::TooShort {
            need: EAPOL_HEADER_LEN,
            have: data.len(),
        });
    }

    let version = data[0];
    let packet_type = EapolType::from_byte(data[1])?;
    let body_len = usize::from(u16::from_be_bytes([data[2], data[3]]));
    let total = EAPOL_HEADER_LEN + body_len;

    if data.len() < total {
        return Err(Error::TooShort {
            need: total,
            have: data.len(),
        });
    }

    let body = &data[EAPOL_HEADER_LEN..total];

    if packet_type == EapolType::Key {
        let key_frame = parse_key_frame(body)?;
        Ok(EapolFrame {
            version,
            packet_type,
            key_frame: Some(key_frame),
            raw_body: Vec::new(),
        })
    } else {
        Ok(EapolFrame {
            version,
            packet_type,
            key_frame: None,
            raw_body: body.to_vec(),
        })
    }
}

/// Parse the body of an EAPOL-Key frame.
///
/// # Errors
///
/// As [`parse`].
fn parse_key_frame(body: &[u8]) -> Result<EapolKeyFrame, Error> {
    if body.len() < EAPOL_KEY_FIXED_LEN {
        return Err(Error::TooShort {
            need: EAPOL_KEY_FIXED_LEN,
            have: body.len(),
        });
    }

    // WHY (#819): the kernel required exactly this -- a non-RSN or malformed
    // descriptor must never be parsed and trusted as a WPA2 handshake frame.
    // `aither`'s pre-convergence parser accepted any byte here unchecked.
    let descriptor_type = body[0];
    if descriptor_type != DESCRIPTOR_TYPE_RSN {
        return Err(Error::UnknownKeyDescriptorType {
            value: descriptor_type,
        });
    }
    let key_info = KeyInfo(u16::from_be_bytes([body[1], body[2]]));
    let key_length = u16::from_be_bytes([body[3], body[4]]);

    let mut replay_buf = [0u8; 8];
    replay_buf.copy_from_slice(&body[5..13]);
    let replay_counter = u64::from_be_bytes(replay_buf);

    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&body[13..45]);

    let mut iv = [0u8; IV_LEN];
    iv.copy_from_slice(&body[45..61]);

    let mut rsc_buf = [0u8; 8];
    rsc_buf.copy_from_slice(&body[61..69]);
    let rsc = u64::from_be_bytes(rsc_buf);
    // body[69..77] is reserved; skip.

    let mut mic = [0u8; MIC_LEN];
    mic.copy_from_slice(&body[77..93]);

    let key_data_len = usize::from(u16::from_be_bytes([body[93], body[94]]));
    let key_data_end = EAPOL_KEY_FIXED_LEN + key_data_len;

    if body.len() < key_data_end {
        return Err(Error::TooShort {
            need: key_data_end,
            have: body.len(),
        });
    }

    let key_data = body[EAPOL_KEY_FIXED_LEN..key_data_end].to_vec();

    Ok(EapolKeyFrame {
        descriptor_type,
        key_info,
        key_length,
        replay_counter,
        nonce,
        iv,
        rsc,
        mic,
        key_data,
    })
}

/// Encode an EAPOL frame into a byte vector.
#[must_use]
pub fn encode(frame: &EapolFrame) -> Vec<u8> {
    let body = frame
        .key_frame
        .as_ref()
        .map_or_else(|| frame.raw_body.clone(), encode_key_frame);

    // WHY: body length is capped at u16::MAX to match the 2-byte length
    // field in the EAPOL header. Frames exceeding this are malformed;
    // truncating the body is the least-bad option in a no_std context
    // without Result overhead -- but the truncation must apply to the BYTES
    // WRITTEN, not just the length field, or the declared length and the
    // actual frame body diverge (kernel audit #282 finding 5: the
    // pre-convergence `aither::eapol::encode` capped only `body_len` and
    // then unconditionally wrote the full untruncated `body`, corrupting
    // any frame whose body exceeded u16::MAX).
    let body_len = u16::try_from(body.len()).unwrap_or(u16::MAX);
    let truncated_body = &body[..usize::from(body_len)];

    let mut out = Vec::with_capacity(EAPOL_HEADER_LEN + truncated_body.len());
    out.push(frame.version);
    out.push(frame.packet_type.to_byte());
    out.extend_from_slice(&body_len.to_be_bytes());
    out.extend_from_slice(truncated_body);
    out
}

/// Encode an EAPOL-Key frame body.
fn encode_key_frame(kf: &EapolKeyFrame) -> Vec<u8> {
    // WHY: same u16::MAX cap and WRITTEN-bytes truncation fix as `encode`,
    // applied to the key_data_length field (kernel audit #282 finding 5).
    let key_data_len = u16::try_from(kf.key_data.len()).unwrap_or(u16::MAX);
    let truncated_key_data = &kf.key_data[..usize::from(key_data_len)];
    let mut out = Vec::with_capacity(EAPOL_KEY_FIXED_LEN + truncated_key_data.len());

    out.push(kf.descriptor_type);
    out.extend_from_slice(&kf.key_info.0.to_be_bytes());
    out.extend_from_slice(&kf.key_length.to_be_bytes());
    out.extend_from_slice(&kf.replay_counter.to_be_bytes());
    out.extend_from_slice(&kf.nonce);
    out.extend_from_slice(&kf.iv);
    out.extend_from_slice(&kf.rsc.to_be_bytes());
    out.extend_from_slice(&[0u8; 8]); // reserved
    out.extend_from_slice(&kf.mic);
    out.extend_from_slice(&key_data_len.to_be_bytes());
    out.extend_from_slice(truncated_key_data);
    out
}

#[cfg(test)]
mod tests {
    use alloc::vec;

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

    #[test]
    fn parses_start_frame() -> Result<(), Error> {
        // version=2, type=Start(0x01), length=0
        let data = [0x02, 0x01, 0x00, 0x00];
        let frame = parse(&data)?;
        assert_eq!(frame.version, 2, "version byte must be 2");
        assert_eq!(
            frame.packet_type,
            EapolType::Start,
            "packet type must be Start"
        );
        assert!(
            frame.key_frame.is_none(),
            "Start frame must have no key frame"
        );
        assert!(frame.raw_body.is_empty(), "Start frame body must be empty");
        Ok(())
    }

    #[test]
    fn parses_logoff_frame() -> Result<(), Error> {
        let data = [0x01, 0x02, 0x00, 0x00];
        let frame = parse(&data)?;
        assert_eq!(
            frame.packet_type,
            EapolType::Logoff,
            "packet type must be Logoff"
        );
        Ok(())
    }

    #[test]
    fn key_frame_roundtrips_through_encode_parse() -> Result<(), Error> {
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
            parsed.version, 2,
            "version must survive encode/parse roundtrip"
        );
        assert_eq!(
            parsed.packet_type,
            EapolType::Key,
            "packet type must survive encode/parse roundtrip"
        );
        assert_eq!(
            parsed.key_frame,
            Some(kf),
            "key frame fields must be identical after roundtrip"
        );
        Ok(())
    }

    #[test]
    fn raw_body_roundtrips_through_encode_parse() -> Result<(), Error> {
        let body = vec![0xde, 0xad, 0xbe, 0xef];
        let frame = EapolFrame {
            version: 1,
            packet_type: EapolType::EapPacket,
            key_frame: None,
            raw_body: body.clone(),
        };
        let encoded = encode(&frame);
        let decoded = parse(&encoded)?;
        assert_eq!(
            decoded.raw_body, body,
            "raw body must survive encode/parse roundtrip"
        );
        Ok(())
    }

    #[test]
    fn key_frame_with_key_data_roundtrips() -> Result<(), Error> {
        let key_data = vec![0x30, 0x14, 0x01, 0x00]; // start of RSNE IE
        let kf = EapolKeyFrame {
            key_data: key_data.clone(),
            ..make_key_frame()
        };
        let frame = EapolFrame {
            version: 2,
            packet_type: EapolType::Key,
            key_frame: Some(kf),
            raw_body: Vec::new(),
        };
        let encoded = encode(&frame);
        let parsed = parse(&encoded)?;
        assert_eq!(
            parsed.key_frame.map(|kf| kf.key_data),
            Some(key_data),
            "key data must survive encode/parse roundtrip"
        );
        Ok(())
    }

    #[test]
    fn rejects_header_shorter_than_four_bytes() {
        let data = [0x02, 0x01, 0x00]; // only 3 bytes
        let result = parse(&data);
        assert!(
            matches!(result, Err(Error::TooShort { need: 4, have: 3 })),
            "must return TooShort when header is truncated"
        );
    }

    #[test]
    fn rejects_body_shorter_than_declared_length() {
        // Claims 10-byte body but only has 2 extra bytes.
        let data = [0x02, 0x01, 0x00, 0x0a, 0xff, 0xff];
        let result = parse(&data);
        assert!(
            matches!(result, Err(Error::TooShort { .. })),
            "must return TooShort when body is truncated"
        );
    }

    #[test]
    fn rejects_unknown_packet_type_byte() {
        let data = [0x01, 0xff, 0x00, 0x00];
        let result = parse(&data);
        assert!(
            matches!(result, Err(Error::UnknownEapolType { value: 0xff })),
            "must return UnknownEapolType for unrecognised packet type byte"
        );
    }

    // WHY (#819): the load-bearing regression proving the merge converged
    // onto the KERNEL's descriptor-type gate, not `aither`'s pre-convergence
    // parser (which accepted any descriptor byte unchecked).
    #[test]
    fn rejects_non_rsn_key_descriptor_type() {
        let kf = EapolKeyFrame {
            descriptor_type: DESCRIPTOR_TYPE_WPA, // WPA legacy, not RSN
            ..make_key_frame()
        };
        let frame = EapolFrame {
            version: 2,
            packet_type: EapolType::Key,
            key_frame: Some(kf),
            raw_body: Vec::new(),
        };
        let encoded = encode(&frame);
        let result = parse(&encoded);
        assert!(
            matches!(
                result,
                Err(Error::UnknownKeyDescriptorType {
                    value: DESCRIPTOR_TYPE_WPA
                })
            ),
            "must return UnknownKeyDescriptorType for a non-RSN descriptor"
        );
    }

    #[test]
    fn parse_key_frame_rejects_key_data_length_exceeding_buffer() {
        let kf = EapolKeyFrame {
            key_data: vec![0x01, 0x02, 0x03],
            ..make_key_frame()
        };
        let frame = EapolFrame {
            version: 2,
            packet_type: EapolType::Key,
            key_frame: Some(kf),
            raw_body: Vec::new(),
        };
        let mut encoded = encode(&frame);

        // WHY: corrupt key_data_length to claim more bytes than actually
        // follow it, without touching the outer EAPOL body_len field or the
        // buffer length -- the last two bytes of the fixed key-frame
        // portion, at offset EAPOL_HEADER_LEN + EAPOL_KEY_FIXED_LEN - 2.
        let key_data_len_offset = EAPOL_HEADER_LEN + EAPOL_KEY_FIXED_LEN - 2;
        encoded[key_data_len_offset..key_data_len_offset + 2].copy_from_slice(&50u16.to_be_bytes());

        let result = parse(&encoded);
        assert!(
            matches!(
                result,
                Err(Error::TooShort {
                    need,
                    have,
                }) if need == EAPOL_KEY_FIXED_LEN + 50 && have == EAPOL_KEY_FIXED_LEN + 3
            ),
            "must return TooShort when key_data_length exceeds the remaining body"
        );
    }

    // WHY (#819, #282 finding 5): proves `encode`'s outer body-length
    // truncation matches the declared length field, not just caps it.
    #[test]
    fn encode_truncates_raw_body_bytes_to_match_declared_length_field() {
        let oversized_len = usize::from(u16::MAX) + 100;
        let frame = EapolFrame {
            version: 2,
            packet_type: EapolType::Start,
            key_frame: None,
            raw_body: vec![0xAB; oversized_len],
        };
        let encoded = encode(&frame);
        let declared_len = u16::from_be_bytes([encoded[2], encoded[3]]);
        assert_eq!(declared_len, u16::MAX, "length field must be capped");
        assert_eq!(
            encoded.len(),
            EAPOL_HEADER_LEN + usize::from(u16::MAX),
            "encoded frame length must match the declared length field, not the untruncated body"
        );
    }

    // WHY (#819, #282 finding 5): `aither`'s pre-convergence
    // `encode_key_frame` capped ONLY the `key_data_length` field and then
    // unconditionally wrote the full untruncated `key_data` -- the same
    // class of bug as the outer body-length test above, at the inner
    // key-data-length field. This is the regression for THAT specific site.
    //
    // WHY this calls `encode_key_frame` directly, not the public `encode`:
    // the fixed 95-byte key-frame header plus a key_data clamped to
    // u16::MAX (65535) is itself 65630 bytes -- already past u16::MAX, so
    // going through `encode`'s OWN outer body_len clamp would truncate a
    // SECOND time and no longer isolate the inner fix this test exists to
    // pin. `encode_key_frame` is private but reachable here: `tests` is a
    // submodule of `eapol`.
    #[test]
    fn encode_key_frame_truncates_key_data_bytes_to_match_declared_length_field() {
        let oversized_len = usize::from(u16::MAX) + 100;
        let kf = EapolKeyFrame {
            key_data: vec![0xCD; oversized_len],
            ..make_key_frame()
        };
        let encoded_key_frame = encode_key_frame(&kf);
        let key_data_len_offset = EAPOL_KEY_FIXED_LEN - 2;
        let declared_len = u16::from_be_bytes([
            encoded_key_frame[key_data_len_offset],
            encoded_key_frame[key_data_len_offset + 1],
        ]);
        assert_eq!(
            declared_len,
            u16::MAX,
            "key_data_length field must be capped"
        );
        assert_eq!(
            encoded_key_frame.len(),
            EAPOL_KEY_FIXED_LEN + usize::from(u16::MAX),
            "encoded key-frame body length must match the declared key_data_length field, \
             not the untruncated key_data"
        );
    }

    #[test]
    fn key_info_flags_decode_correctly() {
        // 0x008a = pairwise(bit3) | ack(bit7) | key_descriptor_version=2
        let ki = KeyInfo(0x008a);
        assert_eq!(
            ki.descriptor_version(),
            2,
            "descriptor version must be 2 for 0x008a"
        );
        assert!(ki.pairwise(), "pairwise bit must be set for 0x008a");
        assert!(ki.ack(), "ack bit must be set for 0x008a");
        assert!(!ki.install(), "install bit must be clear for 0x008a");
        assert!(!ki.mic(), "MIC bit must be clear for 0x008a");
    }

    #[test]
    fn key_info_key_index_decodes_group_key_index_bits() {
        // bits 4-5 = 0b10 (2), rest clear.
        let ki = KeyInfo(0x0020);
        assert_eq!(ki.key_index(), 2, "key_index must read bits 4-5");
    }
}
