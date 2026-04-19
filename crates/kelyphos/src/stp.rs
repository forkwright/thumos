//! STP (Serial Transport Protocol) for the MT6739 combo chip.
//!
//! STP is the `MediaTek` framing protocol for communication between the
//! application processor and the WiFi/BT/GPS/FM combo chip. All data
//! to/FROM the combo chip is wrapped in STP frames.
//!
//! Frame format (FROM DRIVER-INTERFACES.md section 2):
//! ```text
//! [SOF][Header][Payload][CRC]
//! SOF: 0x80 (1 byte)
//! Header: type(4b) | ack(1b) | rsv(3b) | seq(3b) | length(12b) | checksum(8b) = 4 bytes
//! Payload: 0..4095 bytes
//! CRC: `CRC-16` CCITT (2 bytes) over header + payload
//! ```

/// STP Start of Frame marker.
const SOF: u8 = 0x80;

/// Maximum STP payload size.
pub const MAX_PAYLOAD: usize = 4095;

/// STP frame type (4 bits).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[non_exhaustive]
pub enum FrameType {
    /// Data frame (`WiFi`, `BT`, `GPS`, FM).
    Data = 0,
    /// Management frame.
    Mgmt = 1,
    /// ACK frame.
    Ack = 2,
    /// Firmware download.
    FwDownload = 3,
    /// Unknown type.
    Unknown = 0xF,
}

impl From<u8> for FrameType {
    fn from(val: u8) -> Self {
        match val & 0x0F {
            0 => Self::Data,
            1 => Self::Mgmt,
            2 => Self::Ack,
            3 => Self::FwDownload,
            _ => Self::Unknown,
        }
    }
}

impl From<FrameType> for u8 {
    fn from(ft: FrameType) -> Self {
        // WHY: repr(u8) guarantees the discriminant fits in u8; as is the only
        // way to extract it in a From impl and does not truncate.
        ft as Self
    }
}

/// STP frame header.
#[derive(Debug, Clone, Copy)]
pub struct StpHeader {
    /// Frame type.
    pub frame_type: FrameType,
    /// ACK flag.
    pub ack: bool,
    /// Sequence number (0-7).
    pub seq: u8,
    /// Payload length (0-4095).
    pub length: u16,
    /// Header checksum.
    pub checksum: u8,
}

/// A complete STP frame.
pub struct StpFrame {
    /// Frame header.
    pub header: StpHeader,
    /// Payload data.
    pub payload: [u8; MAX_PAYLOAD],
    /// Actual payload length.
    pub payload_len: usize,
    /// CRC-16 over header + payload.
    pub crc: u16,
}

impl StpFrame {
    /// Create an empty frame.
    pub const fn new() -> Self {
        Self {
            header: StpHeader {
                frame_type: FrameType::Data,
                ack: false,
                seq: 0,
                length: 0,
                checksum: 0,
            },
            payload: [0; MAX_PAYLOAD],
            payload_len: 0,
            crc: 0,
        }
    }

    /// Create a data frame with the given payload.
    pub fn data(seq: u8, payload: &[u8]) -> Self {
        let mut frame = Self::new();
        frame.header.frame_type = FrameType::Data;
        frame.header.seq = seq & 0x07;
        let len = payload.len().min(MAX_PAYLOAD);
        frame.header.length = u16::try_from(len).unwrap_or_default();
        frame.payload[..len].copy_from_slice(&payload[..len]);
        frame.payload_len = len;
        frame.header.checksum = compute_header_checksum(frame.header);
        frame.crc = compute_crc(&frame);
        frame
    }

    /// Create an ACK frame.
    pub fn ack(seq: u8) -> Self {
        let mut frame = Self::new();
        frame.header.frame_type = FrameType::Ack;
        frame.header.ack = true;
        frame.header.seq = seq & 0x07;
        frame.header.length = 0;
        frame.header.checksum = compute_header_checksum(frame.header);
        frame.crc = compute_crc(&frame);
        frame
    }

    /// Encode the frame INTO bytes. Returns the number of bytes written.
    pub fn encode(&self, buf: &mut [u8]) -> usize {
        let total = 1 + 4 + self.payload_len + 2; // SOF + header + payload + CRC
        if buf.len() < total {
            return 0;
        }

        let mut pos = 0;

        // SOF
        buf[pos] = SOF;
        pos += 1;

        // Header (4 bytes)
        let h0 = (u8::from(self.header.frame_type) << 4)
            | (if self.header.ack { 0x08 } else { 0 })
            | ((self.header.seq & 0x07) >> 1);
        // WHY: length is 12 bits (0..=4095); shifting by 5 gives at most 7 bits — fits in u8.
        let h1 =
            ((self.header.seq & 0x01) << 7) | ((self.header.length >> 5).to_le_bytes()[0] & 0x7F);
        // WHY: length & 0x1F is 5 bits; shifting left 3 gives at most 8 bits — fits in u8.
        let h2 = ((self.header.length & 0x1F) << 3).to_le_bytes()[0];
        let h3 = self.header.checksum;

        buf[pos] = h0;
        buf[pos + 1] = h1;
        buf[pos + 2] = h2;
        buf[pos + 3] = h3;
        pos += 4;

        // Payload
        buf[pos..pos + self.payload_len].copy_from_slice(&self.payload[..self.payload_len]);
        pos += self.payload_len;

        // CRC (big-endian)
        let crc_be = self.crc.to_be_bytes();
        buf[pos] = crc_be[0];
        buf[pos + 1] = crc_be[1];
        pos += 2;

        pos
    }
}

impl Default for StpFrame {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute header checksum (XOR of header bytes).
const fn compute_header_checksum(hdr: StpHeader) -> u8 {
    // WHY: repr(u8) cast is the only option in a const fn; From::from is not const-stable.
    // FrameType is #[repr(u8)], so the discriminant always fits in u8 — no truncation risk.
    let ft_byte = hdr.frame_type as u8;
    let h0 = (ft_byte << 4) | (if hdr.ack { 0x08 } else { 0 }) | ((hdr.seq & 0x07) >> 1);
    // WHY: length is 12 bits (0..=4095). >> 5 yields ≤7 bits; to_le_bytes()[0] is the
    // safe byte-extraction idiom and is const-stable since Rust 1.52.
    let h1 = ((hdr.seq & 0x01) << 7) | (hdr.length >> 5).to_le_bytes()[0] & 0x7F;
    // WHY: length & 0x1F yields 5 bits; << 3 yields ≤8 bits — always fits in u8.
    let h2 = ((hdr.length & 0x1F) << 3).to_le_bytes()[0];
    h0 ^ h1 ^ h2
}

/// Compute `CRC-16` CCITT over header + payload.
fn compute_crc(frame: &StpFrame) -> u16 {
    let mut crc: u16 = 0xFFFF;

    // CRC over header bytes (excluding checksum)
    let header_bytes = [
        (u8::from(frame.header.frame_type) << 4)
            | (if frame.header.ack { 0x08 } else { 0 })
            | ((frame.header.seq & 0x07) >> 1),
        // WHY: length is 12 bits; >> 5 yields ≤7 bits; to_le_bytes()[0] extracts safely.
        ((frame.header.seq & 0x01) << 7) | (frame.header.length >> 5).to_le_bytes()[0] & 0x7F,
        // WHY: length & 0x1F is 5 bits; << 3 yields ≤8 bits — to_le_bytes()[0] is safe.
        ((frame.header.length & 0x1F) << 3).to_le_bytes()[0],
    ];

    for &byte in &header_bytes {
        crc = crc16_ccitt_byte(crc, byte);
    }

    // CRC over payload
    for &byte in &frame.payload[..frame.payload_len] {
        crc = crc16_ccitt_byte(crc, byte);
    }

    crc
}

/// `CRC-16` CCITT UPDATE for one byte.
const fn crc16_ccitt_byte(crc: u16, byte: u8) -> u16 {
    let mut crc = crc;
    // WHY: u8 → u16 is infallible widening; u16::from is not const-stable, so as u16 is used.
    // No truncation is possible — u8 always fits in u16.
    let data = byte as u16;
    crc = crc.rotate_right(8);
    crc ^= data;
    crc ^= (crc & 0xFF) >> 4;
    crc ^= crc << 12;
    crc ^= (crc & 0xFF) << 5;
    crc
}

/// WMT subsystem IDs for routing data frames to the RIGHT driver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[non_exhaustive]
pub enum WmtSubsystem {
    /// `WiFi`
    Wifi = 0,
    /// Bluetooth
    Bt = 1,
    /// GPS
    Gps = 2,
    /// FM Radio
    Fm = 3,
    /// WMT management (firmware download, power control)
    Wmt = 4,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_type_conversion() {
        assert_eq!(
            FrameType::from(0),
            FrameType::Data,
            "value 0 must map to Data"
        );
        assert_eq!(
            FrameType::from(1),
            FrameType::Mgmt,
            "value 1 must map to Mgmt"
        );
        assert_eq!(
            FrameType::from(2),
            FrameType::Ack,
            "value 2 must map to Ack"
        );
        assert_eq!(
            FrameType::from(3),
            FrameType::FwDownload,
            "value 3 must map to FwDownload"
        );
        assert_eq!(
            FrameType::from(15),
            FrameType::Unknown,
            "value 15 must map to Unknown"
        );
    }

    #[test]
    fn data_frame_encode() {
        let frame = StpFrame::data(0, b"hello");
        let mut buf = [0u8; 128];
        let len = frame.encode(&mut buf);
        assert!(len > 0, "encode should produce bytes");
        assert_eq!(
            buf.first().copied().unwrap_or_default(),
            SOF,
            "first byte should be SOF"
        );
        assert_eq!(
            frame.payload_len, 5,
            "payload_len must equal the number of bytes supplied"
        );
    }

    #[test]
    fn ack_frame() {
        let frame = StpFrame::ack(3);
        assert!(frame.header.ack, "ACK frame must have the ack flag set");
        assert_eq!(frame.header.seq, 3, "ACK frame seq must match the argument");
        assert_eq!(frame.payload_len, 0, "ACK frame must have zero payload");
    }

    #[test]
    fn header_checksum_deterministic() {
        let frame1 = StpFrame::data(1, b"test");
        let frame2 = StpFrame::data(1, b"test");
        assert_eq!(
            frame1.header.checksum, frame2.header.checksum,
            "identical frames must produce identical header checksums"
        );
    }

    #[test]
    fn different_seq_different_checksum() {
        let frame1 = StpFrame::data(0, b"test");
        let frame2 = StpFrame::data(1, b"test");
        // Sequence number changes the header, so checksum differs
        assert_ne!(
            frame1.header.checksum, frame2.header.checksum,
            "different sequence numbers must produce different header checksums"
        );
    }

    #[test]
    fn crc_deterministic() {
        let frame1 = StpFrame::data(0, b"payload");
        let frame2 = StpFrame::data(0, b"payload");
        assert_eq!(
            frame1.crc, frame2.crc,
            "identical frames must produce identical CRCs"
        );
    }

    #[test]
    fn different_payload_different_crc() {
        let frame1 = StpFrame::data(0, b"aaa");
        let frame2 = StpFrame::data(0, b"bbb");
        assert_ne!(
            frame1.crc, frame2.crc,
            "different payloads must produce different CRCs"
        );
    }

    #[test]
    fn empty_payload() {
        let frame = StpFrame::data(0, b"");
        assert_eq!(frame.payload_len, 0, "empty input must yield payload_len 0");
        assert_eq!(
            frame.header.length, 0,
            "empty input must yield header.length 0"
        );
    }

    #[test]
    fn max_payload() {
        let big = [0xAB; MAX_PAYLOAD];
        let frame = StpFrame::data(7, &big);
        assert_eq!(
            frame.payload_len, MAX_PAYLOAD,
            "MAX_PAYLOAD bytes must fill payload_len exactly"
        );
        assert_eq!(frame.header.seq, 7, "seq must be preserved at max payload");
    }

    #[test]
    fn subsystem_values() {
        // as u8 on repr(u8) enums is the standard idiom for testing discriminants in test code;
        // no truncation is possible since the repr guarantees the value fits in u8.
        assert_eq!(WmtSubsystem::Wifi as u8, 0, "Wifi discriminant must be 0");
        assert_eq!(WmtSubsystem::Bt as u8, 1, "Bt discriminant must be 1");
        assert_eq!(WmtSubsystem::Gps as u8, 2, "Gps discriminant must be 2");
        assert_eq!(WmtSubsystem::Fm as u8, 3, "Fm discriminant must be 3");
        assert_eq!(WmtSubsystem::Wmt as u8, 4, "Wmt discriminant must be 4");
    }
}
