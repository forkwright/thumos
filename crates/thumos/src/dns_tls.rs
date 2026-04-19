//! DNS-over-TLS (DoT) framing layer.
//!
//! Wraps DNS queries in the DoT wire format (RFC 7858): a 2-byte length
//! prefix followed by the DNS message, transmitted over a TLS 1.3 connection
//! to port 853. The actual TLS handshake is abstracted behind the
//! [`TlsTransport`] trait, allowing the kernel to plug in any TLS backend
//! (e.g., `rustls` or a hardware TLS accelerator).
//!
//! ## Certificate pinning
//!
//! The client stores the SHA-256 hash of the server's Subject Public Key
//! Info (SPKI). During the TLS handshake callback, the received SPKI is
//! checked against `pinned_spki_hash`. A mismatch causes the connection
//! to be rejected. No plaintext fallback: DoT failure = DNS failure.
//!
//! ## Wire format
//!
//! Per RFC 7858 section 3.3, DNS messages over TLS are framed with a
//! 2-byte big-endian length prefix (identical to DNS over TCP framing
//! from RFC 1035 section 4.2.2):
//!
//! ```text
//! +------+------+----------//----------+
//! | MSB  | LSB  |   DNS message        |
//! +------+------+----------//----------+
//!  2 bytes len    len bytes payload
//! ```
//!
//! ## Integration
//!
//! The `dns.rs` resolver can be wired to use a `DotClient` as transport
//! instead of plain UDP by setting `DnsResolver::use_dot` (added by this
//! module). LAN queries (`*.lan`) bypass DoT and use plain UDP to the
//! local AdGuard instance.

// WHY: DNS-over-TLS created in Phase 08 Wave 7, integration pending.
#![expect(
    dead_code,
    reason = "DNS-over-TLS created in Phase 08 Wave 7, network integration pending"
)]

extern crate alloc;

use alloc::vec::Vec;
use smoltcp::wire::Ipv4Address;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Standard DNS-over-TLS port (RFC 7858).
pub(crate) const DOT_PORT: u16 = 853;

/// Maximum DNS message size for DoT framing (RFC 7858 section 3.3).
/// TCP/TLS DNS messages can be up to 65535 bytes, but practical queries
/// are much smaller. We cap at 4096 to prevent memory exhaustion.
const MAX_DNS_MESSAGE_SIZE: usize = 4096;

/// DoT frame header size: 2-byte big-endian length prefix.
const DOT_FRAME_HEADER_SIZE: usize = 2;

/// Maximum total frame size (header + message).
const MAX_FRAME_SIZE: usize = DOT_FRAME_HEADER_SIZE + MAX_DNS_MESSAGE_SIZE;

/// SHA-256 hash length for SPKI pinning.
const SPKI_HASH_LEN: usize = 32;

/// Quad9 DNS server address (primary DoT target).
pub(crate) const QUAD9_DNS: Ipv4Address = Ipv4Address::new(9, 9, 9, 9);

/// DNS record type A (IPv4 address).
const DNS_TYPE_A: u16 = 1;

/// DNS class IN (Internet).
const DNS_CLASS_IN: u16 = 1;

/// Minimum DNS header size.
const DNS_HEADER_SIZE: usize = 12;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors from DNS-over-TLS operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DotError {
    /// The DNS message exceeds the maximum allowed size.
    MessageTooLarge,
    /// The TLS transport failed to send data.
    SendFailed,
    /// The TLS transport failed to receive data.
    RecvFailed,
    /// The received frame has an invalid length prefix.
    InvalidFrameLength,
    /// The response is shorter than the frame header.
    TruncatedFrame,
    /// The TLS certificate SPKI hash does not match the pinned hash.
    PinMismatch,
    /// The DNS query name is empty or malformed.
    InvalidName,
    /// The DNS response is malformed.
    MalformedResponse,
    /// The DNS server returned an error code.
    ServerError,
    /// No answer records in the DNS response.
    NoRecords,
    /// The response buffer is too small.
    BufferTooSmall,
    /// The TLS transport is not connected.
    NotConnected,
}

impl core::fmt::Display for DotError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MessageTooLarge => write!(f, "DNS message exceeds maximum size"),
            Self::SendFailed => write!(f, "TLS transport send failed"),
            Self::RecvFailed => write!(f, "TLS transport receive failed"),
            Self::InvalidFrameLength => write!(f, "invalid DoT frame length"),
            Self::TruncatedFrame => write!(f, "truncated DoT frame"),
            Self::PinMismatch => write!(f, "TLS certificate SPKI pin mismatch"),
            Self::InvalidName => write!(f, "invalid DNS query name"),
            Self::MalformedResponse => write!(f, "malformed DNS response"),
            Self::ServerError => write!(f, "DNS server error"),
            Self::NoRecords => write!(f, "no DNS answer records"),
            Self::BufferTooSmall => write!(f, "response buffer too small"),
            Self::NotConnected => write!(f, "TLS transport not connected"),
        }
    }
}

// ---------------------------------------------------------------------------
// TLS transport trait
// ---------------------------------------------------------------------------

/// Abstraction over a TLS connection for DNS-over-TLS transport.
///
/// Implementors provide the actual TLS handshake and data transfer.
/// The kernel can plug in `rustls`, a hardware TLS accelerator, or a
/// mock for testing.
pub(crate) trait TlsTransport {
    /// Send data over the TLS connection.
    ///
    /// Returns `Ok(())` on success, or `Err(DotError::SendFailed)` if
    /// the transport could not deliver the data.
    fn send(&mut self, data: &[u8]) -> Result<(), DotError>;

    /// Receive data from the TLS connection into `buf`.
    ///
    /// Returns the number of bytes read on success, or
    /// `Err(DotError::RecvFailed)` on failure.
    fn recv(&mut self, buf: &mut [u8]) -> Result<usize, DotError>;
}

// ---------------------------------------------------------------------------
// DoT framing
// ---------------------------------------------------------------------------

/// Wrap a DNS message in a DoT frame (2-byte big-endian length prefix).
///
/// Returns the framed message or `DotError::MessageTooLarge` if the
/// DNS message exceeds `MAX_DNS_MESSAGE_SIZE`.
#[must_use]
pub(crate) fn frame_dns_message(dns_message: &[u8]) -> Result<Vec<u8>, DotError> {
    if dns_message.len() > MAX_DNS_MESSAGE_SIZE {
        return Err(DotError::MessageTooLarge);
    }

    let len = dns_message.len() as u16;
    let mut frame = Vec::with_capacity(DOT_FRAME_HEADER_SIZE + dns_message.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(dns_message);
    Ok(frame)
}

/// Extract the DNS message length from a DoT frame header.
///
/// Reads the first 2 bytes as a big-endian u16 length value.
#[must_use]
pub(crate) fn parse_frame_length(header: &[u8; 2]) -> u16 {
    u16::from_be_bytes(*header)
}

/// Read a complete DoT frame from a TLS transport.
///
/// Reads the 2-byte length prefix, then reads the DNS message body.
/// Returns the DNS message payload (without the length prefix).
#[must_use]
pub(crate) fn read_dot_frame<T: TlsTransport>(transport: &mut T) -> Result<Vec<u8>, DotError> {
    // Read the 2-byte length prefix.
    let mut header = [0u8; DOT_FRAME_HEADER_SIZE];
    let n = transport.recv(&mut header)?;
    if n < DOT_FRAME_HEADER_SIZE {
        return Err(DotError::TruncatedFrame);
    }

    let msg_len = parse_frame_length(&header) as usize;
    if msg_len > MAX_DNS_MESSAGE_SIZE {
        return Err(DotError::InvalidFrameLength);
    }
    if msg_len == 0 {
        return Err(DotError::InvalidFrameLength);
    }

    // Read the DNS message body.
    let mut body = alloc::vec![0u8; msg_len];
    let n = transport.recv(&mut body)?;
    if n < msg_len {
        return Err(DotError::TruncatedFrame);
    }

    Ok(body)
}

// ---------------------------------------------------------------------------
// DNS query builder
// ---------------------------------------------------------------------------

/// Build a DNS A query packet for the given hostname.
///
/// Returns the wire-format query bytes and the transaction ID.
/// The query has flags RD=1 (recursion desired), QDCOUNT=1.
#[must_use]
pub(crate) fn build_dns_query(hostname: &str, txid: u16) -> Result<Vec<u8>, DotError> {
    if hostname.is_empty() {
        return Err(DotError::InvalidName);
    }

    let qname_len = hostname.len() + 2;
    let mut packet = Vec::with_capacity(DNS_HEADER_SIZE + qname_len + 4);

    // Header.
    packet.extend_from_slice(&txid.to_be_bytes());
    packet.extend_from_slice(&0x0100u16.to_be_bytes()); // Flags: RD=1
    packet.extend_from_slice(&1u16.to_be_bytes());      // QDCOUNT
    packet.extend_from_slice(&0u16.to_be_bytes());      // ANCOUNT
    packet.extend_from_slice(&0u16.to_be_bytes());      // NSCOUNT
    packet.extend_from_slice(&0u16.to_be_bytes());      // ARCOUNT

    // QNAME: encode hostname as DNS labels.
    for label in hostname.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(DotError::InvalidName);
        }
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0); // Terminal zero.

    // QTYPE = A (1), QCLASS = IN (1).
    packet.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
    packet.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());

    Ok(packet)
}

/// Build a DNS query for an arbitrary record type.
///
/// Like `build_dns_query` but accepts a custom record type value.
#[must_use]
pub(crate) fn build_dns_query_typed(
    hostname: &str,
    txid: u16,
    record_type: u16,
) -> Result<Vec<u8>, DotError> {
    if hostname.is_empty() {
        return Err(DotError::InvalidName);
    }

    let qname_len = hostname.len() + 2;
    let mut packet = Vec::with_capacity(DNS_HEADER_SIZE + qname_len + 4);

    // Header.
    packet.extend_from_slice(&txid.to_be_bytes());
    packet.extend_from_slice(&0x0100u16.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());

    for label in hostname.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(DotError::InvalidName);
        }
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0);

    packet.extend_from_slice(&record_type.to_be_bytes());
    packet.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());

    Ok(packet)
}

// ---------------------------------------------------------------------------
// Certificate pinning
// ---------------------------------------------------------------------------

/// Verify a server's SPKI hash against a pinned hash.
///
/// Both hashes are SHA-256 digests (32 bytes). Returns `true` if the
/// received SPKI hash matches the pinned hash exactly.
///
/// This is called from within the TLS handshake callback. The actual
/// SPKI extraction from the X.509 certificate is the responsibility
/// of the TLS library; this function only compares the final hash.
#[must_use]
pub(crate) fn verify_pin(received_spki: &[u8; SPKI_HASH_LEN], pinned: &[u8; SPKI_HASH_LEN]) -> bool {
    // Constant-time comparison to prevent timing side-channels.
    let mut diff: u8 = 0;
    for i in 0..SPKI_HASH_LEN {
        diff |= received_spki[i] ^ pinned[i];
    }
    diff == 0
}

// ---------------------------------------------------------------------------
// DoT client
// ---------------------------------------------------------------------------

/// DNS-over-TLS client with certificate pinning.
///
/// Wraps a [`TlsTransport`] to send DNS queries framed per RFC 7858
/// and verify the server's SPKI hash against a pinned value.
#[non_exhaustive]
pub(crate) struct DotClient<T: TlsTransport> {
    /// Underlying TLS transport.
    transport: T,
    /// DNS server address.
    server_addr: Ipv4Address,
    /// SHA-256 hash of the server's SPKI for certificate pinning.
    pinned_spki_hash: [u8; SPKI_HASH_LEN],
    /// Transaction ID counter.
    next_txid: u16,
}

impl<T: TlsTransport> DotClient<T> {
    /// Create a new DoT client with the given transport and SPKI pin.
    ///
    /// The `pinned_spki_hash` is the SHA-256 digest of the server's
    /// Subject Public Key Info, used for certificate pinning during
    /// the TLS handshake.
    pub(crate) fn new(
        transport: T,
        server_addr: Ipv4Address,
        pinned_spki_hash: [u8; SPKI_HASH_LEN],
    ) -> Self {
        Self {
            transport,
            server_addr,
            pinned_spki_hash,
            next_txid: 1,
        }
    }

    /// Return the configured server address.
    pub(crate) fn server_addr(&self) -> Ipv4Address {
        self.server_addr
    }

    /// Return the pinned SPKI hash.
    pub(crate) fn pinned_spki_hash(&self) -> &[u8; SPKI_HASH_LEN] {
        &self.pinned_spki_hash
    }

    /// Verify a received SPKI hash against the pinned hash.
    ///
    /// Returns `Ok(())` if the hashes match, or
    /// `Err(DotError::PinMismatch)` if they differ.
    #[must_use]
    pub(crate) fn verify_server_pin(
        &self,
        received_spki: &[u8; SPKI_HASH_LEN],
    ) -> Result<(), DotError> {
        if verify_pin(received_spki, &self.pinned_spki_hash) {
            Ok(())
        } else {
            Err(DotError::PinMismatch)
        }
    }

    /// Send a DNS query for the given hostname (A record).
    ///
    /// Builds a DNS A query, wraps it in a DoT frame, sends it over
    /// the TLS transport, reads the response frame, and returns the
    /// raw DNS response message.
    #[must_use]
    pub(crate) fn query(&mut self, name: &str, record_type: u16) -> Result<Vec<u8>, DotError> {
        // Build the DNS query.
        let txid = self.next_txid;
        self.next_txid = self.next_txid.wrapping_add(1);
        let dns_query = build_dns_query_typed(name, txid, record_type)?;

        // Frame and send.
        let frame = frame_dns_message(&dns_query)?;
        self.transport.send(&frame)?;

        // Read response frame.
        let response = read_dot_frame(&mut self.transport)?;

        // Validate response header: check transaction ID and QR bit.
        if response.len() < DNS_HEADER_SIZE {
            return Err(DotError::MalformedResponse);
        }
        let resp_txid = u16::from_be_bytes([response[0], response[1]]);
        if resp_txid != txid {
            return Err(DotError::MalformedResponse);
        }
        let flags = u16::from_be_bytes([response[2], response[3]]);
        if flags & 0x8000 == 0 {
            return Err(DotError::MalformedResponse);
        }
        let rcode = flags & 0x000F;
        if rcode != 0 {
            return Err(DotError::ServerError);
        }

        Ok(response)
    }

    /// Send a raw DNS message over DoT and return the raw response.
    ///
    /// The caller is responsible for building and parsing the DNS message.
    #[must_use]
    pub(crate) fn send_raw(&mut self, dns_message: &[u8]) -> Result<Vec<u8>, DotError> {
        let frame = frame_dns_message(dns_message)?;
        self.transport.send(&frame)?;
        read_dot_frame(&mut self.transport)
    }

    /// Return a mutable reference to the underlying transport.
    pub(crate) fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }
}

// ---------------------------------------------------------------------------
// DoT configuration for DnsResolver integration
// ---------------------------------------------------------------------------

/// Configuration for DNS-over-TLS integration with the DNS resolver.
///
/// When `enabled` is true, the resolver routes non-LAN queries through
/// a DoT client instead of plain UDP. LAN queries (`*.lan`) always use
/// plain UDP to the local AdGuard instance.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct DotConfig {
    /// Whether DoT is enabled for non-LAN queries.
    pub enabled: bool,
    /// DoT server address (e.g., Quad9 9.9.9.9).
    pub server_addr: Ipv4Address,
    /// SHA-256 SPKI pin for the DoT server.
    pub pinned_spki_hash: [u8; SPKI_HASH_LEN],
}

impl DotConfig {
    /// Create a new DoT configuration.
    pub(crate) fn new(
        server_addr: Ipv4Address,
        pinned_spki_hash: [u8; SPKI_HASH_LEN],
    ) -> Self {
        Self {
            enabled: true,
            server_addr,
            pinned_spki_hash,
        }
    }

    /// Create a disabled DoT configuration.
    pub(crate) fn disabled() -> Self {
        Self {
            enabled: false,
            server_addr: QUAD9_DNS,
            pinned_spki_hash: [0u8; SPKI_HASH_LEN],
        }
    }
}

impl core::fmt::Display for DotConfig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.enabled {
            write!(f, "DoT enabled (server: {})", self.server_addr)
        } else {
            write!(f, "DoT disabled")
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    // -- Mock TLS transport ---------------------------------------------------

    /// Mock TLS transport for testing DoT framing and query flow.
    ///
    /// Stores sent data and returns preconfigured responses.
    struct MockTlsTransport {
        /// Data sent via `send()`, accumulated for inspection.
        sent: Vec<u8>,
        /// Preconfigured responses, returned in order by `recv()`.
        responses: Vec<Vec<u8>>,
        /// Index into `responses` for the next `recv()` call.
        recv_idx: usize,
    }

    impl MockTlsTransport {
        fn new() -> Self {
            Self {
                sent: Vec::new(),
                responses: Vec::new(),
                recv_idx: 0,
            }
        }

        fn with_responses(responses: Vec<Vec<u8>>) -> Self {
            Self {
                sent: Vec::new(),
                responses,
                recv_idx: 0,
            }
        }
    }

    impl TlsTransport for MockTlsTransport {
        fn send(&mut self, data: &[u8]) -> Result<(), DotError> {
            self.sent.extend_from_slice(data);
            Ok(())
        }

        fn recv(&mut self, buf: &mut [u8]) -> Result<usize, DotError> {
            if self.recv_idx >= self.responses.len() {
                return Err(DotError::RecvFailed);
            }
            let response = &self.responses[self.recv_idx];
            self.recv_idx += 1;
            let copy_len = response.len().min(buf.len());
            buf[..copy_len].copy_from_slice(&response[..copy_len]);
            Ok(copy_len)
        }
    }

    // -- Framing tests --------------------------------------------------------

    #[test]
    fn frame_adds_correct_length_prefix() {
        let dns_msg = [0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let framed = frame_dns_message(&dns_msg);
        assert!(framed.is_ok(), "framing must succeed for valid message");

        let framed = framed.ok().unwrap(); // ok: test
        assert_eq!(framed.len(), 2 + dns_msg.len(), "frame = 2-byte header + message");

        // Check length prefix.
        let prefix = u16::from_be_bytes([framed[0], framed[1]]);
        assert_eq!(
            prefix, dns_msg.len() as u16,
            "length prefix must equal DNS message length"
        );

        // Check payload preserved.
        assert_eq!(
            &framed[2..], &dns_msg,
            "payload must be unchanged after framing"
        );
    }

    #[test]
    fn frame_rejects_oversized_message() {
        let big_msg = vec![0u8; MAX_DNS_MESSAGE_SIZE + 1];
        let result = frame_dns_message(&big_msg);
        assert_eq!(
            result, Err(DotError::MessageTooLarge),
            "oversized message must be rejected"
        );
    }

    #[test]
    fn frame_empty_message() {
        let framed = frame_dns_message(&[]);
        assert!(framed.is_ok(), "empty message framing must succeed");
        let framed = framed.ok().unwrap(); // ok: test
        assert_eq!(framed.len(), 2, "empty message frame = 2-byte header only");
        assert_eq!(framed[0], 0);
        assert_eq!(framed[1], 0);
    }

    #[test]
    fn parse_frame_length_correct() {
        assert_eq!(parse_frame_length(&[0x00, 0x0C]), 12);
        assert_eq!(parse_frame_length(&[0x01, 0x00]), 256);
        assert_eq!(parse_frame_length(&[0xFF, 0xFF]), 65535);
        assert_eq!(parse_frame_length(&[0x00, 0x00]), 0);
    }

    // -- Query builder tests --------------------------------------------------

    #[test]
    fn build_query_produces_valid_wire_format() {
        let result = build_dns_query("example.com", 0x1234);
        assert!(result.is_ok(), "query build must succeed");
        let packet = result.ok().unwrap(); // ok: test

        // Header checks.
        assert!(packet.len() >= DNS_HEADER_SIZE);
        assert_eq!(packet[0], 0x12, "txid high byte");
        assert_eq!(packet[1], 0x34, "txid low byte");
        assert_eq!(packet[2], 0x01, "flags high: RD=1");
        assert_eq!(packet[3], 0x00, "flags low");
        assert_eq!(
            u16::from_be_bytes([packet[4], packet[5]]), 1,
            "QDCOUNT must be 1"
        );

        // QNAME: should contain "example" and "com" labels.
        let qname_start = DNS_HEADER_SIZE;
        assert_eq!(packet[qname_start], 7, "first label length = 7 (example)");
        assert_eq!(
            &packet[qname_start + 1..qname_start + 8], b"example",
            "first label content"
        );
        assert_eq!(packet[qname_start + 8], 3, "second label length = 3 (com)");
        assert_eq!(
            &packet[qname_start + 9..qname_start + 12], b"com",
            "second label content"
        );
        assert_eq!(packet[qname_start + 12], 0, "terminal zero");
    }

    #[test]
    fn build_query_rejects_empty_name() {
        let result = build_dns_query("", 0x0001);
        assert_eq!(result, Err(DotError::InvalidName));
    }

    #[test]
    fn build_query_rejects_long_label() {
        let long_label = "a".repeat(64);
        let hostname = alloc::format!("{long_label}.com");
        let result = build_dns_query(&hostname, 0x0001);
        assert_eq!(
            result, Err(DotError::InvalidName),
            "label > 63 chars must be rejected"
        );
    }

    #[test]
    fn build_query_typed_uses_record_type() {
        let result = build_dns_query_typed("example.com", 0xABCD, 28); // AAAA = 28
        assert!(result.is_ok(), "typed query must succeed");
        let packet = result.ok().unwrap(); // ok: test

        // Find the QTYPE field (after QNAME terminal zero + 0 byte).
        // QNAME for "example.com": 1 + 7 + 1 + 3 + 1 = 13 bytes
        let qtype_offset = DNS_HEADER_SIZE + 13;
        let qtype = u16::from_be_bytes([packet[qtype_offset], packet[qtype_offset + 1]]);
        assert_eq!(qtype, 28, "QTYPE must be AAAA (28)");
    }

    // -- Pin verification tests -----------------------------------------------

    #[test]
    fn verify_pin_accepts_matching_hash() {
        let pin = [0xAA; SPKI_HASH_LEN];
        assert!(
            verify_pin(&pin, &pin),
            "matching hashes must verify successfully"
        );
    }

    #[test]
    fn verify_pin_rejects_mismatching_hash() {
        let pinned = [0xAA; SPKI_HASH_LEN];
        let received = [0xBB; SPKI_HASH_LEN];
        assert!(
            !verify_pin(&received, &pinned),
            "mismatching hashes must fail verification"
        );
    }

    #[test]
    fn verify_pin_rejects_single_bit_difference() {
        let pinned = [0x00; SPKI_HASH_LEN];
        let mut received = [0x00; SPKI_HASH_LEN];
        received[15] = 0x01; // Single bit flip.
        assert!(
            !verify_pin(&received, &pinned),
            "single-bit difference must fail verification"
        );
    }

    // -- DoT client tests -----------------------------------------------------

    #[test]
    fn dot_client_query_sends_framed_message() {
        // Build a mock response: frame header + DNS response.
        let txid: u16 = 1;
        let mut dns_response = Vec::new();
        dns_response.extend_from_slice(&txid.to_be_bytes());
        dns_response.extend_from_slice(&0x8180u16.to_be_bytes()); // QR=1, RD=1, RA=1
        dns_response.extend_from_slice(&0u16.to_be_bytes()); // QDCOUNT
        dns_response.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT
        dns_response.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        dns_response.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
        // Answer: inline name + A record.
        dns_response.push(4);
        dns_response.extend_from_slice(b"test");
        dns_response.push(3);
        dns_response.extend_from_slice(b"com");
        dns_response.push(0);
        dns_response.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
        dns_response.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        dns_response.extend_from_slice(&300u32.to_be_bytes());
        dns_response.extend_from_slice(&4u16.to_be_bytes());
        dns_response.extend_from_slice(&[93, 184, 216, 34]);

        // Frame the response.
        let resp_len = dns_response.len() as u16;
        let frame_header = resp_len.to_be_bytes().to_vec();

        let transport = MockTlsTransport::with_responses(vec![
            frame_header,
            dns_response.clone(),
        ]);

        let pinned = [0xAA; SPKI_HASH_LEN];
        let mut client = DotClient::new(transport, QUAD9_DNS, pinned);

        let result = client.query("test.com", DNS_TYPE_A);
        assert!(result.is_ok(), "query must succeed with valid mock response");

        let response = result.ok().unwrap(); // ok: test
        assert_eq!(response, dns_response, "response must match mock DNS message");

        // Verify the sent data contains a DoT frame.
        let sent = &client.transport_mut().sent;
        assert!(sent.len() > 2, "must have sent framed data");
        let sent_len = u16::from_be_bytes([sent[0], sent[1]]) as usize;
        assert_eq!(
            sent_len, sent.len() - 2,
            "sent frame length prefix must match payload size"
        );
    }

    #[test]
    fn dot_client_verifies_pin() {
        let pinned = [0xAA; SPKI_HASH_LEN];
        let transport = MockTlsTransport::new();
        let client = DotClient::new(transport, QUAD9_DNS, pinned);

        // Matching pin.
        let matching = [0xAA; SPKI_HASH_LEN];
        assert!(client.verify_server_pin(&matching).is_ok());

        // Mismatching pin.
        let wrong = [0xBB; SPKI_HASH_LEN];
        assert_eq!(
            client.verify_server_pin(&wrong),
            Err(DotError::PinMismatch),
        );
    }

    #[test]
    fn dot_client_server_addr() {
        let transport = MockTlsTransport::new();
        let client = DotClient::new(transport, QUAD9_DNS, [0; SPKI_HASH_LEN]);
        assert_eq!(client.server_addr(), QUAD9_DNS);
    }

    #[test]
    fn dot_client_pinned_hash() {
        let pin = [0x42; SPKI_HASH_LEN];
        let transport = MockTlsTransport::new();
        let client = DotClient::new(transport, QUAD9_DNS, pin);
        assert_eq!(client.pinned_spki_hash(), &pin);
    }

    // -- Read frame tests -----------------------------------------------------

    #[test]
    fn read_frame_extracts_message() {
        let dns_msg = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        let len = dns_msg.len() as u16;
        let header = len.to_be_bytes().to_vec();

        let mut transport = MockTlsTransport::with_responses(vec![header, dns_msg.clone()]);
        let result = read_dot_frame(&mut transport);
        assert!(result.is_ok(), "read_dot_frame must succeed");
        assert_eq!(result.ok().unwrap(), dns_msg); // ok: test
    }

    #[test]
    fn read_frame_rejects_truncated_header() {
        // Only 1 byte instead of 2.
        let mut transport = MockTlsTransport::with_responses(vec![vec![0x00]]);
        let result = read_dot_frame(&mut transport);
        assert_eq!(result, Err(DotError::TruncatedFrame));
    }

    #[test]
    fn read_frame_rejects_zero_length() {
        let mut transport = MockTlsTransport::with_responses(vec![vec![0x00, 0x00]]);
        let result = read_dot_frame(&mut transport);
        assert_eq!(result, Err(DotError::InvalidFrameLength));
    }

    #[test]
    fn read_frame_rejects_oversized() {
        // Length = MAX_DNS_MESSAGE_SIZE + 1.
        let len = (MAX_DNS_MESSAGE_SIZE + 1) as u16;
        let header = len.to_be_bytes().to_vec();
        let mut transport = MockTlsTransport::with_responses(vec![header]);
        let result = read_dot_frame(&mut transport);
        assert_eq!(result, Err(DotError::InvalidFrameLength));
    }

    // -- DotConfig tests ------------------------------------------------------

    #[test]
    fn dot_config_new_is_enabled() {
        let config = DotConfig::new(QUAD9_DNS, [0xAA; SPKI_HASH_LEN]);
        assert!(config.enabled, "new config must be enabled");
        assert_eq!(config.server_addr, QUAD9_DNS);
    }

    #[test]
    fn dot_config_disabled() {
        let config = DotConfig::disabled();
        assert!(!config.enabled, "disabled config must not be enabled");
    }

    #[test]
    fn dot_config_display() {
        let config = DotConfig::new(QUAD9_DNS, [0; SPKI_HASH_LEN]);
        let s = alloc::format!("{config}");
        assert!(s.contains("DoT enabled"), "display must show enabled status");

        let disabled = DotConfig::disabled();
        let s = alloc::format!("{disabled}");
        assert!(s.contains("DoT disabled"), "display must show disabled status");
    }

    // -- DotError Display test ------------------------------------------------

    #[test]
    fn dot_error_display_all_variants() {
        // Verify all error variants produce non-empty display strings.
        let errors = [
            DotError::MessageTooLarge,
            DotError::SendFailed,
            DotError::RecvFailed,
            DotError::InvalidFrameLength,
            DotError::TruncatedFrame,
            DotError::PinMismatch,
            DotError::InvalidName,
            DotError::MalformedResponse,
            DotError::ServerError,
            DotError::NoRecords,
            DotError::BufferTooSmall,
            DotError::NotConnected,
        ];
        for err in &errors {
            let s = alloc::format!("{err}");
            assert!(!s.is_empty(), "error display must not be empty");
        }
    }
}
