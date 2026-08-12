//! EAPOL (Extensible Authentication Protocol over LAN) frame parsing and encoding.
//!
//! Implements IEEE 802.1X-2020 framing used during WPA2/WPA3 4-way handshake.

use snafu::{Snafu, ensure};

/// Size of the EAPOL common header (version + type + length).
const EAPOL_HEADER_LEN: usize = 4;

/// Size of the fixed portion of an EAPOL-Key body (before variable key data).
///
/// Fields: descriptor\_type(1) + key\_info(2) + key\_length(2) + replay\_counter(8)
/// + nonce(32) + iv(16) + rsc(8) + reserved(8) + mic(16) + key\_data\_length(2) = 95
const EAPOL_KEY_FIXED_LEN: usize = 95;

/// Length of the MIC field.
pub(crate) const MIC_LEN: usize = 16;

/// Length of the nonce field.
pub(crate) const NONCE_LEN: usize = 32;

/// Length of the IV field.
pub(crate) const IV_LEN: usize = 16;

/// RSN key descriptor type (WPA2/WPA3).
pub(crate) const DESCRIPTOR_TYPE_RSN: u8 = 0x02;

/// WPA (legacy) key descriptor type.
pub(crate) const DESCRIPTOR_TYPE_WPA: u8 = 0xFE;

/// Errors produced by EAPOL parsing.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum Error {
    /// Buffer is too short to contain required fields.
    #[snafu(display("frame too short: need {need} bytes, have {have}"))]
    TooShort {
        /// Minimum required bytes.
        need: usize,
        /// Actual buffer length.
        have: usize,
    },

    /// Unrecognised EAPOL packet type byte.
    #[snafu(display("unknown EAPOL packet type: {value:#04x}"))]
    UnknownType {
        /// The unrecognised type byte.
        value: u8,
    },
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
    const fn from_byte(b: u8) -> Result<Self, Error> {
        match b {
            0x00 => Ok(Self::EapPacket),
            0x01 => Ok(Self::Start),
            0x02 => Ok(Self::Logoff),
            0x03 => Ok(Self::Key),
            v => Err(Error::UnknownType { value: v }),
        }
    }

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
    /// Key descriptor version (bits 0–2).
    #[must_use]
    #[expect(
        clippy::as_conversions,
        reason = "masked to 3 bits (0x0007), result is always 0-7; fits u8 without truncation"
    )]
    pub(crate) const fn descriptor_version(self) -> u8 {
        (self.0 & 0x0007) as u8
    }

    /// True if pairwise (unicast) key; false for GROUP/broadcast key.
    #[must_use]
    pub(crate) const fn pairwise(self) -> bool {
        self.0 & 0x0008 != 0
    }

    /// Key index for GROUP keys (bits 4–5).
    #[must_use]
    #[expect(
        clippy::as_conversions,
        reason = "masked to 2 bits (0x03), result is always 0-3; fits u8 without truncation"
    )]
    pub(crate) const fn key_index(self) -> u8 {
        ((self.0 >> 4) & 0x03) as u8
    }

    /// True if supplicant shall install the key.
    #[must_use]
    pub(crate) const fn install(self) -> bool {
        self.0 & 0x0040 != 0
    }

    /// True if message requires an acknowledgement.
    #[must_use]
    pub(crate) const fn ack(self) -> bool {
        self.0 & 0x0080 != 0
    }

    /// True if a MIC is present in this frame.
    #[must_use]
    pub(crate) const fn mic(self) -> bool {
        self.0 & 0x0100 != 0
    }

    /// True if the RSNA has been established.
    #[must_use]
    pub(crate) const fn secure(self) -> bool {
        self.0 & 0x0200 != 0
    }

    /// True if key data is encrypted (AESKEYWRAP).
    #[must_use]
    pub(crate) const fn encrypted_key_data(self) -> bool {
        self.0 & 0x1000 != 0
    }
}

/// EAPOL-Key frame body (IEEE 802.11-2020, section 12.7.2).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
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
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
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

/// Parse an EAPOL frame FROM a byte slice.
///
/// # Errors
///
/// Returns [`Error::TooShort`] when the slice cannot satisfy the declared packet
/// length, and [`Error::UnknownType`] for unrecognised packet type bytes.
pub fn parse(data: &[u8]) -> Result<EapolFrame, Error> {
    ensure!(
        data.len() >= EAPOL_HEADER_LEN,
        TooShortSnafu {
            need: EAPOL_HEADER_LEN,
            have: data.len()
        }
    );

    let version = data.first().copied().unwrap_or_default();
    let packet_type = EapolType::from_byte(data.get(1).copied().unwrap_or_default())?;
    let body_len = usize::from(u16::from_be_bytes([
        data.get(2).copied().unwrap_or_default(),
        data.get(3).copied().unwrap_or_default(),
    ]));
    let total = EAPOL_HEADER_LEN + body_len;

    ensure!(
        data.len() >= total,
        TooShortSnafu {
            need: total,
            have: data.len()
        }
    );

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

fn parse_key_frame(body: &[u8]) -> Result<EapolKeyFrame, Error> {
    ensure!(
        body.len() >= EAPOL_KEY_FIXED_LEN,
        TooShortSnafu {
            need: EAPOL_KEY_FIXED_LEN,
            have: body.len()
        }
    );

    // Safe: all offsets guaranteed by the ensure above.
    let descriptor_type = body.first().copied().unwrap_or_default();
    let key_info = KeyInfo(u16::from_be_bytes([
        body.get(1).copied().unwrap_or_default(),
        body.get(2).copied().unwrap_or_default(),
    ]));
    let key_length = u16::from_be_bytes([
        body.get(3).copied().unwrap_or_default(),
        body.get(4).copied().unwrap_or_default(),
    ]);

    let mut replay_buf = [0u8; 8];
    replay_buf.copy_from_slice(body.get(5..13).unwrap_or_default());
    let replay_counter = u64::from_be_bytes(replay_buf);

    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(body.get(13..45).unwrap_or_default());

    let mut iv = [0u8; IV_LEN];
    iv.copy_from_slice(body.get(45..61).unwrap_or_default());

    let mut seq_buf = [0u8; 8];
    seq_buf.copy_from_slice(body.get(61..69).unwrap_or_default());
    let rsc = u64::from_be_bytes(seq_buf);
    // body[69..77] is reserved; skip.

    let mut mic = [0u8; MIC_LEN];
    mic.copy_from_slice(body.get(77..93).unwrap_or_default());

    let key_data_len = usize::from(u16::from_be_bytes([
        body.get(93).copied().unwrap_or_default(),
        body.get(94).copied().unwrap_or_default(),
    ]));
    let key_data_end = EAPOL_KEY_FIXED_LEN + key_data_len;

    ensure!(
        body.len() >= key_data_end,
        TooShortSnafu {
            need: key_data_end,
            have: body.len()
        }
    );

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

/// Encode an EAPOL frame INTO a byte vector.
#[must_use]
pub fn encode(frame: &EapolFrame) -> Vec<u8> {
    let body = frame
        .key_frame
        .as_ref()
        .map_or_else(|| frame.raw_body.clone(), encode_key_frame);

    let body_len = u16::try_from(body.len()).unwrap_or(u16::MAX);
    let mut out = Vec::with_capacity(EAPOL_HEADER_LEN + body.len());
    out.push(frame.version);
    out.push(frame.packet_type.to_byte());
    out.extend_from_slice(&body_len.to_be_bytes());
    out.extend_from_slice(&body);
    out
}

fn encode_key_frame(kf: &EapolKeyFrame) -> Vec<u8> {
    let key_data_len = u16::try_from(kf.key_data.len()).unwrap_or(u16::MAX);
    let mut out = Vec::with_capacity(EAPOL_KEY_FIXED_LEN + kf.key_data.len());

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
    out.extend_from_slice(&kf.key_data);
    out
}

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
        assert!(
            parsed.key_frame.is_some(),
            "key frame must be present after roundtrip"
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
            matches!(result, Err(Error::UnknownType { value: 0xff })),
            "must return UnknownType for unrecognised packet type byte"
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
        assert!(
            parsed.key_frame.is_some(),
            "key frame must be present after roundtrip"
        );
        if let Some(pkf) = parsed.key_frame {
            assert_eq!(
                pkf.key_data, key_data,
                "key data must survive encode/parse roundtrip"
            );
        }
        Ok(())
    }
}
