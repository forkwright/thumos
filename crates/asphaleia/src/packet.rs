//! IPv4, TCP, and UDP header parsing FROM raw byte slices.
//!
//! All parsing is zero-copy: header fields are extracted by value FROM the
//! provided slice without allocating. The caller retains ownership of the
//! underlying bytes.
//!
//! The actual header-field arithmetic (version/IHL validation, byte-offset
//! extraction) is `asphaleia_core`'s (#545) — the same canonical
//! implementation the kernel's `firewall.rs` links by path dependency. This
//! module wraps the raw `[u8; 4]` addresses `asphaleia_core` returns in
//! `std::net::Ipv4Addr` for this crate's userspace-facing API and keeps this
//! crate's own [`ParseError`] shape (re-exported, not redefined).

use std::net::Ipv4Addr;

pub use asphaleia_core::{PROTO_ICMP, PROTO_TCP, PROTO_UDP, ParseError};

/// Parsed IPv4 header fields.
#[derive(Debug, Clone)]
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "public API — version and total_length are unused in this crate but held for downstream consumers"
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
    reason = "public API — seq and ack are unused in this crate but held for downstream consumers"
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
        reason = "public API — length is unused in this crate but held for downstream consumers"
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
    /// Delegates the field arithmetic to [`asphaleia_core::Ipv4Fields`] and
    /// wraps the raw octet addresses in [`Ipv4Addr`] for this crate's API.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::TooShort`] if `data` is shorter than 20 bytes or
    /// shorter than the length encoded in the IHL field.
    /// Returns [`ParseError::InvalidVersion`] if the version is not 4.
    /// Returns [`ParseError::InvalidIhl`] if IHL is less than 5.
    pub fn parse(data: &[u8]) -> Result<Self, ParseError> {
        let fields = asphaleia_core::Ipv4Fields::parse(data)?;
        Ok(Self {
            version: fields.version,
            ihl: fields.ihl,
            total_length: fields.total_length,
            protocol: fields.protocol,
            src_addr: Ipv4Addr::from(fields.src_addr),
            dst_addr: Ipv4Addr::from(fields.dst_addr),
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
    /// immediately after the IP header. Delegates to
    /// [`asphaleia_core::TcpFields`].
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::TooShort`] if `data` is shorter than 20 bytes.
    pub fn parse(data: &[u8]) -> Result<Self, ParseError> {
        let fields = asphaleia_core::TcpFields::parse(data)?;
        Ok(Self {
            src_port: fields.src_port,
            dst_port: fields.dst_port,
            seq: fields.seq,
            ack: fields.ack,
            flags: fields.flags,
        })
    }
}

impl UdpHeader {
    /// Parse a UDP header FROM the beginning of `data`.
    ///
    /// `data` should point to the start of the UDP header, i.e. the byte
    /// immediately after the IP header. Delegates to
    /// [`asphaleia_core::UdpFields`].
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::TooShort`] if `data` is shorter than 8 bytes.
    pub fn parse(data: &[u8]) -> Result<Self, ParseError> {
        let fields = asphaleia_core::UdpFields::parse(data)?;
        Ok(Self {
            src_port: fields.src_port,
            dst_port: fields.dst_port,
            length: fields.length,
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
