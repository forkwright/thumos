//! IPv4, TCP, and UDP header parsing FROM raw byte slices.
//!
//! All parsing is zero-copy: header fields are extracted by value FROM the
//! provided slice without allocating. The caller retains ownership of the
//! underlying bytes.

use std::net::Ipv4Addr;

use snafu::Snafu;

// Constants

const IPV4_VERSION: u8 = 4;
const IPV4_MIN_HEADER_LEN: usize = 20;
const MIN_IHL: u8 = 5;
const TCP_MIN_HEADER_LEN: usize = 20;
const UDP_HEADER_LEN: usize = 8;

pub const PROTO_ICMP: u8 = 1;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

// Type definitions

/// Errors that can occur when parsing network packet headers.
#[derive(Debug, Snafu)]
pub enum ParseError {
    /// The buffer is shorter than the minimum required for this header.
    #[snafu(display("packet too short: need {needed} bytes, got {got}"))]
    TooShort { needed: usize, got: usize },

    /// The IP version field is not 4.
    #[snafu(display("invalid IP version: expected 4, got {version}"))]
    InvalidVersion { version: u8 },

    /// The IHL field encodes a header shorter than the minimum 20 bytes.
    #[snafu(display("invalid IHL {ihl}: minimum is 5 (20 bytes)"))]
    InvalidIhl { ihl: u8 },
}

/// Parsed IPv4 header fields.
#[derive(Debug, Clone)]
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "public API — version and total_length are unused in this crate but available to downstream consumers"
    )
)]
pub struct IpHeader {
    /// IP version (always 4 for a successfully parsed header).
    pub version: u8,
    /// Internet Header Length in 32-bit words.
    pub ihl: u8,
    /// Total packet length in bytes (header + payload).
    pub total_length: u16,
    /// IP protocol number (e.g. `PROTO_TCP`, `PROTO_UDP`, `PROTO_ICMP`).
    pub protocol: u8,
    /// Source IPv4 address.
    pub src_addr: Ipv4Addr,
    /// Destination IPv4 address.
    pub dst_addr: Ipv4Addr,
}

/// Parsed TCP header fields.
#[derive(Debug, Clone)]
#[expect(
    dead_code,
    reason = "public API — seq and ack are unused in this crate but available to downstream consumers"
)]
pub struct TcpHeader {
    /// Source TCP port.
    pub src_port: u16,
    /// Destination TCP port.
    pub dst_port: u16,
    /// Sequence number.
    pub seq: u32,
    /// Acknowledgement number.
    pub ack: u32,
    /// Control flags byte (SYN, ACK, FIN, RST, PSH, URG, ECE, CWR).
    pub flags: u8,
}

/// Parsed UDP header fields.
#[derive(Debug, Clone)]
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "public API — length is unused in this crate but available to downstream consumers"
    )
)]
pub struct UdpHeader {
    /// Source UDP port.
    pub src_port: u16,
    /// Destination UDP port.
    pub dst_port: u16,
    /// UDP datagram length (header + data) in bytes.
    pub length: u16,
}

// Impl blocks

impl IpHeader {
    /// Parse an IPv4 header FROM the beginning of `data`.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::TooShort`] if `data` is shorter than 20 bytes or
    /// shorter than the length encoded in the IHL field.
    /// Returns [`ParseError::InvalidVersion`] if the version is not 4.
    /// Returns [`ParseError::InvalidIhl`] if IHL is less than 5.
    pub fn parse(data: &[u8]) -> Result<Self, ParseError> {
        if data.len() < IPV4_MIN_HEADER_LEN {
            return Err(ParseError::TooShort {
                needed: IPV4_MIN_HEADER_LEN,
                got: data.len(),
            });
        }

        let version_ihl = data.first().copied().unwrap_or_default();
        let version = version_ihl >> 4;
        let ihl = version_ihl & 0x0F;

        if version != IPV4_VERSION {
            return Err(ParseError::InvalidVersion { version });
        }

        if ihl < MIN_IHL {
            return Err(ParseError::InvalidIhl { ihl });
        }

        let header_len = usize::from(ihl) * 4;
        if data.len() < header_len {
            return Err(ParseError::TooShort {
                needed: header_len,
                got: data.len(),
            });
        }

        let total_length = u16::from_be_bytes([
            data.get(2).copied().unwrap_or_default(),
            data.get(3).copied().unwrap_or_default(),
        ]);
        let protocol = data.get(9).copied().unwrap_or_default();
        let src_addr = Ipv4Addr::new(
            data.get(12).copied().unwrap_or_default(),
            data.get(13).copied().unwrap_or_default(),
            data.get(14).copied().unwrap_or_default(),
            data.get(15).copied().unwrap_or_default(),
        );
        let dst_addr = Ipv4Addr::new(
            data.get(16).copied().unwrap_or_default(),
            data.get(17).copied().unwrap_or_default(),
            data.get(18).copied().unwrap_or_default(),
            data.get(19).copied().unwrap_or_default(),
        );

        Ok(Self {
            version,
            ihl,
            total_length,
            protocol,
            src_addr,
            dst_addr,
        })
    }

    /// Return the header length in bytes (`ihl * 4`).
    pub fn header_len(&self) -> usize {
        usize::from(self.ihl) * 4
    }
}

impl TcpHeader {
    /// Parse a TCP header FROM the beginning of `data`.
    ///
    /// `data` should point to the start of the TCP header, i.e. the byte
    /// immediately after the IP header.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::TooShort`] if `data` is shorter than 20 bytes.
    pub fn parse(data: &[u8]) -> Result<Self, ParseError> {
        if data.len() < TCP_MIN_HEADER_LEN {
            return Err(ParseError::TooShort {
                needed: TCP_MIN_HEADER_LEN,
                got: data.len(),
            });
        }

        let src_port = u16::from_be_bytes([
            data.first().copied().unwrap_or_default(),
            data.get(1).copied().unwrap_or_default(),
        ]);
        let dst_port = u16::from_be_bytes([
            data.get(2).copied().unwrap_or_default(),
            data.get(3).copied().unwrap_or_default(),
        ]);
        let seq = u32::from_be_bytes([
            data.get(4).copied().unwrap_or_default(),
            data.get(5).copied().unwrap_or_default(),
            data.get(6).copied().unwrap_or_default(),
            data.get(7).copied().unwrap_or_default(),
        ]);
        let ack = u32::from_be_bytes([
            data.get(8).copied().unwrap_or_default(),
            data.get(9).copied().unwrap_or_default(),
            data.get(10).copied().unwrap_or_default(),
            data.get(11).copied().unwrap_or_default(),
        ]);
        // Byte 12 is data OFFSET; byte 13 is the flags byte.
        let flags = data.get(13).copied().unwrap_or_default();

        Ok(Self {
            src_port,
            dst_port,
            seq,
            ack,
            flags,
        })
    }
}

impl UdpHeader {
    /// Parse a UDP header FROM the beginning of `data`.
    ///
    /// `data` should point to the start of the UDP header, i.e. the byte
    /// immediately after the IP header.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::TooShort`] if `data` is shorter than 8 bytes.
    pub fn parse(data: &[u8]) -> Result<Self, ParseError> {
        if data.len() < UDP_HEADER_LEN {
            return Err(ParseError::TooShort {
                needed: UDP_HEADER_LEN,
                got: data.len(),
            });
        }

        let src_port = u16::from_be_bytes([
            data.first().copied().unwrap_or_default(),
            data.get(1).copied().unwrap_or_default(),
        ]);
        let dst_port = u16::from_be_bytes([
            data.get(2).copied().unwrap_or_default(),
            data.get(3).copied().unwrap_or_default(),
        ]);
        let length = u16::from_be_bytes([
            data.get(4).copied().unwrap_or_default(),
            data.get(5).copied().unwrap_or_default(),
        ]);

        Ok(Self {
            src_port,
            dst_port,
            length,
        })
    }
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;

    // A minimal valid IPv4/TCP packet (no payload).
    // IP: src=10.0.0.1, dst=192.168.1.1, proto=TCP, IHL=5
    // TCP: src_port=12345, dst_port=80, SYN flag
    fn make_tcp_packet() -> Vec<u8> {
        let mut pkt = vec![0u8; 40];
        // IP header
        pkt[0] = 0x45; // version=4, IHL=5
        pkt[2] = 0x00;
        pkt[3] = 40; // total length
        pkt[9] = PROTO_TCP;
        pkt[12] = 10;
        pkt[13] = 0;
        pkt[14] = 0;
        pkt[15] = 1; // src = 10.0.0.1
        pkt[16] = 192;
        pkt[17] = 168;
        pkt[18] = 1;
        pkt[19] = 1; // dst = 192.168.1.1
        // TCP header
        pkt[20] = 0x30;
        pkt[21] = 0x39; // src_port = 12345
        pkt[22] = 0x00;
        pkt[23] = 0x50; // dst_port = 80
        pkt[32] = 0x50; // data OFFSET = 5 (20 bytes)
        pkt[33] = 0x02; // SYN flag
        pkt
    }

    // A minimal valid IPv4/UDP packet.
    // IP: src=10.0.0.1, dst=8.8.8.8, proto=UDP
    // UDP: src_port=54321, dst_port=53
    fn make_udp_packet() -> Vec<u8> {
        let mut pkt = vec![0u8; 28];
        pkt[0] = 0x45;
        pkt[2] = 0x00;
        pkt[3] = 28;
        pkt[9] = PROTO_UDP;
        pkt[12] = 10;
        pkt[13] = 0;
        pkt[14] = 0;
        pkt[15] = 1;
        pkt[16] = 8;
        pkt[17] = 8;
        pkt[18] = 8;
        pkt[19] = 8;
        // UDP header
        pkt[20] = 0xD4;
        pkt[21] = 0x31; // src_port = 54321
        pkt[22] = 0x00;
        pkt[23] = 0x35; // dst_port = 53
        pkt[24] = 0x00;
        pkt[25] = 8; // length = 8 (header only)
        pkt
    }

    #[test]
    fn ip_header_parses_valid_packet() -> Result<(), ParseError> {
        let pkt = make_tcp_packet();
        let hdr = IpHeader::parse(&pkt)?;
        assert_eq!(hdr.version, 4, "IPv4 version must be 4");
        assert_eq!(hdr.ihl, 5, "standard IHL is 5");
        assert_eq!(hdr.total_length, 40, "total length should be 40");
        assert_eq!(hdr.protocol, PROTO_TCP, "protocol must be TCP");
        assert_eq!(
            hdr.src_addr,
            Ipv4Addr::new(10, 0, 0, 1),
            "source address mismatch"
        );
        assert_eq!(
            hdr.dst_addr,
            Ipv4Addr::new(192, 168, 1, 1),
            "destination address mismatch"
        );
        assert_eq!(hdr.header_len(), 20, "IHL=5 means 20 byte header");
        Ok(())
    }

    #[test]
    fn ip_header_rejects_truncated_packet() {
        let short = [0x45u8; 10];
        let err = IpHeader::parse(&short);
        assert!(
            matches!(err, Err(ParseError::TooShort { .. })),
            "truncated packet must return TooShort"
        );
    }

    #[test]
    fn ip_header_rejects_ipv6_version() {
        let mut pkt = make_tcp_packet();
        pkt[0] = 0x65; // version=6
        let err = IpHeader::parse(&pkt);
        assert!(
            matches!(err, Err(ParseError::InvalidVersion { version: 6 })),
            "IPv6 version byte must return InvalidVersion"
        );
    }

    #[test]
    fn ip_header_rejects_ihl_below_minimum() {
        let mut pkt = make_tcp_packet();
        pkt[0] = 0x44; // version=4, IHL=4 (invalid)
        let err = IpHeader::parse(&pkt);
        assert!(
            matches!(err, Err(ParseError::InvalidIhl { ihl: 4 })),
            "IHL=4 must return InvalidIhl"
        );
    }

    #[test]
    fn tcp_header_parses_valid_segment() -> Result<(), ParseError> {
        let pkt = make_tcp_packet();
        let ip = IpHeader::parse(&pkt)?;
        let tcp = TcpHeader::parse(&pkt[ip.header_len()..])?;
        assert_eq!(tcp.src_port, 12345, "source port mismatch");
        assert_eq!(tcp.dst_port, 80, "destination port mismatch");
        assert_eq!(tcp.flags, 0x02, "SYN flag should be SET");
        Ok(())
    }

    #[test]
    fn tcp_header_rejects_short_slice() {
        let short = [0u8; 10];
        let err = TcpHeader::parse(&short);
        assert!(
            matches!(err, Err(ParseError::TooShort { .. })),
            "short TCP slice must return TooShort"
        );
    }

    #[test]
    fn udp_header_parses_valid_datagram() -> Result<(), ParseError> {
        let pkt = make_udp_packet();
        let ip = IpHeader::parse(&pkt)?;
        let udp = UdpHeader::parse(&pkt[ip.header_len()..])?;
        assert_eq!(udp.src_port, 54321, "source port mismatch");
        assert_eq!(udp.dst_port, 53, "destination port mismatch");
        assert_eq!(udp.length, 8, "length mismatch");
        Ok(())
    }

    #[test]
    fn udp_header_rejects_short_slice() {
        let short = [0u8; 4];
        let err = UdpHeader::parse(&short);
        assert!(
            matches!(err, Err(ParseError::TooShort { .. })),
            "short UDP slice must return TooShort"
        );
    }
}
