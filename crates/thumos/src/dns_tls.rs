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
    reason = "DNS-over-TLS created in Phase 08 Wave 7, network integration pending (#442)"
)]

extern crate alloc;

use alloc::vec::Vec;
use smoltcp::wire::Ipv4Address;

use crate::csprng;

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
    /// The receive deadline passed before the frame completed (#442) — a
    /// peer that stops answering mid-frame no longer hangs the resolver.
    Timeout,
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
            Self::Timeout => write!(f, "DoT receive deadline exceeded"),
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

    /// Receive data from the TLS connection into `buf`, bounded by a real
    /// deadline (#442). Returns the number of bytes read on success;
    /// `Err(DotError::Timeout)` if the transport cannot complete the read
    /// before `deadline_ms` on its own clock; `Err(DotError::RecvFailed)`
    /// on any other failure. The deadline is an absolute tick-ms value
    /// supplied by the caller, so the resolver never hangs on a silent peer.
    fn recv(&mut self, buf: &mut [u8], deadline_ms: u64) -> Result<usize, DotError>;
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
pub(crate) fn read_dot_frame<T: TlsTransport>(
    transport: &mut T,
    deadline_ms: u64,
) -> Result<Vec<u8>, DotError> {
    // Read the 2-byte length prefix. WHY: DoT runs over a TCP-backed TLS
    // stream; a single recv() call is not guaranteed to return all
    // requested bytes even for a 2-byte header — loop until the header
    // is fully read, treating n == 0 as a closed connection.
    let mut header = [0u8; DOT_FRAME_HEADER_SIZE];
    let mut received = 0;
    while received < DOT_FRAME_HEADER_SIZE {
        let n = transport.recv(&mut header[received..], deadline_ms)?;
        if n == 0 {
            return Err(DotError::TruncatedFrame);
        }
        received += n;
    }

    let msg_len = parse_frame_length(&header) as usize;
    if msg_len > MAX_DNS_MESSAGE_SIZE {
        return Err(DotError::InvalidFrameLength);
    }
    if msg_len == 0 {
        return Err(DotError::InvalidFrameLength);
    }

    // Read the DNS message body. WHY: a DNS message routinely spans
    // multiple TCP segments (multiple answer records, DNSSEC RRSIGs); a
    // single recv() call only returns what's immediately buffered, so
    // accumulate until msg_len bytes are received (issue #285).
    let mut body = alloc::vec![0u8; msg_len];
    let mut received = 0;
    while received < msg_len {
        let n = transport.recv(&mut body[received..], deadline_ms)?;
        if n == 0 {
            return Err(DotError::TruncatedFrame);
        }
        received += n;
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
    packet.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    packet.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    packet.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    packet.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

    // QNAME: encode hostname as DNS labels. RFC 1035 section 3.1 caps the
    // total encoded name -- every length-prefix octet plus every label
    // octet plus the terminating zero -- at 255 octets; the per-label
    // <= 63 check alone does not bound the SUM across many short labels
    // (mirrors dns.rs's build_dns_query, fixed in an earlier batch).
    const DNS_MAX_NAME_LEN: usize = 255;
    let mut qname_len: usize = 0;
    for label in hostname.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(DotError::InvalidName);
        }
        qname_len = qname_len
            .checked_add(1 + label.len())
            .ok_or(DotError::InvalidName)?;
        if qname_len >= DNS_MAX_NAME_LEN {
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

    // RFC 1035 section 3.1: total encoded QNAME (length-prefix octets +
    // label octets + terminating zero) is capped at 255 octets; the
    // per-label <= 63 check alone does not bound the sum (mirrors
    // build_dns_query above).
    const DNS_MAX_NAME_LEN: usize = 255;
    let mut qname_len: usize = 0;
    for label in hostname.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(DotError::InvalidName);
        }
        qname_len = qname_len
            .checked_add(1 + label.len())
            .ok_or(DotError::InvalidName)?;
        if qname_len >= DNS_MAX_NAME_LEN {
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
pub(crate) fn verify_pin(
    received_spki: &[u8; SPKI_HASH_LEN],
    pinned: &[u8; SPKI_HASH_LEN],
) -> bool {
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
}

/// Generate a DNS transaction ID from the kernel CSPRNG.
///
/// WHY: a sequential/predictable transaction ID lets an on-path or
/// off-path attacker predict the next query's TXID and race a spoofed
/// response ahead of the real DNS server (CWE-330, DNS cache
/// poisoning, issue #288). Each query must draw independent entropy
/// rather than incrementing a counter.
fn random_txid() -> u16 {
    let mut buf = [0u8; 2];
    // NOTE(#284): the fail-closed CSPRNG returns Err only before seeding,
    // which cannot occur here — DNS resolution runs after `csprng::init()`
    // completes during kinit. On that unreachable path `buf` stays zeroed,
    // never key material.
    let _ = csprng::kernel_random_bytes(&mut buf); // kanon:ignore RUST/no-silent-result-swallow -- fail-closed CSPRNG Err path is unreachable post-init (see NOTE above); zeroed buf on that path yields a valid (if predictable) TXID, not key material
    u16::from_le_bytes(buf)
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
    pub(crate) fn query(
        &mut self,
        name: &str,
        record_type: u16,
        now_ms: u64,
        timeout_ms: u64,
    ) -> Result<Vec<u8>, DotError> {
        let deadline_ms = now_ms.saturating_add(timeout_ms);
        // Build the DNS query. WHY: draw the transaction ID from the
        // kernel CSPRNG rather than a sequential counter — a predictable
        // TXID lets an attacker race a spoofed response (CWE-330, #288).
        let txid = random_txid();
        let dns_query = build_dns_query_typed(name, txid, record_type)?;

        // Frame and send.
        let frame = frame_dns_message(&dns_query)?;
        self.transport.send(&frame)?;

        // Read response frame.
        let response = read_dot_frame(&mut self.transport, deadline_ms)?;

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
    pub(crate) fn send_raw(
        &mut self,
        dns_message: &[u8],
        now_ms: u64,
        timeout_ms: u64,
    ) -> Result<Vec<u8>, DotError> {
        let frame = frame_dns_message(dns_message)?;
        self.transport.send(&frame)?;
        read_dot_frame(&mut self.transport, now_ms.saturating_add(timeout_ms))
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
    pub(crate) fn new(server_addr: Ipv4Address, pinned_spki_hash: [u8; SPKI_HASH_LEN]) -> Self {
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
    use alloc::vec;

    use super::*;

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
        /// Scriptable clock (#442): advanced by `advance_per_recv` on each
        /// `recv()`; a recv that lands after the deadline returns Timeout.
        now_ms: u64,
        /// Tick-ms added to `now_ms` per `recv()` call (0 = instant transport).
        advance_per_recv: u64,
    }

    impl MockTlsTransport {
        fn new() -> Self {
            Self {
                sent: Vec::new(),
                responses: Vec::new(),
                recv_idx: 0,
                now_ms: 0,
                advance_per_recv: 0,
            }
        }

        fn with_responses(responses: Vec<Vec<u8>>) -> Self {
            Self {
                sent: Vec::new(),
                responses,
                recv_idx: 0,
                now_ms: 0,
                advance_per_recv: 0,
            }
        }

        /// Script a transport whose clock advances `per_recv` tick-ms on
        /// every recv (#442): a recv that lands after the deadline must
        /// return DotError::Timeout.
        fn with_clock_advance(responses: Vec<Vec<u8>>, per_recv: u64) -> Self {
            Self {
                sent: Vec::new(),
                responses,
                recv_idx: 0,
                now_ms: 0,
                advance_per_recv: per_recv,
            }
        }
    }

    impl TlsTransport for MockTlsTransport {
        fn send(&mut self, data: &[u8]) -> Result<(), DotError> {
            self.sent.extend_from_slice(data);
            Ok(())
        }

        fn recv(&mut self, buf: &mut [u8], deadline_ms: u64) -> Result<usize, DotError> {
            self.now_ms += self.advance_per_recv;
            if self.now_ms > deadline_ms {
                return Err(DotError::Timeout);
            }
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
        let dns_msg = [
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let framed = frame_dns_message(&dns_msg);
        assert!(framed.is_ok(), "framing must succeed for valid message");

        let framed = framed.ok().unwrap(); // ok: test
        assert_eq!(
            framed.len(),
            2 + dns_msg.len(),
            "frame = 2-byte header + message"
        );

        // Check length prefix.
        let prefix = u16::from_be_bytes([framed[0], framed[1]]);
        assert_eq!(
            prefix,
            dns_msg.len() as u16,
            "length prefix must equal DNS message length"
        );

        // Check payload preserved.
        assert_eq!(
            &framed[2..],
            &dns_msg,
            "payload must be unchanged after framing"
        );
    }

    #[test]
    fn frame_rejects_oversized_message() {
        let big_msg = vec![0u8; MAX_DNS_MESSAGE_SIZE + 1];
        let result = frame_dns_message(&big_msg);
        assert_eq!(
            result,
            Err(DotError::MessageTooLarge),
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
            u16::from_be_bytes([packet[4], packet[5]]),
            1,
            "QDCOUNT must be 1"
        );

        // QNAME: should contain "example" and "com" labels.
        let qname_start = DNS_HEADER_SIZE;
        assert_eq!(packet[qname_start], 7, "first label length = 7 (example)");
        assert_eq!(
            &packet[qname_start + 1..qname_start + 8],
            b"example",
            "first label content"
        );
        assert_eq!(packet[qname_start + 8], 3, "second label length = 3 (com)");
        assert_eq!(
            &packet[qname_start + 9..qname_start + 12],
            b"com",
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
            result,
            Err(DotError::InvalidName),
            "label > 63 chars must be rejected"
        );
    }

    #[test]
    fn build_query_rejects_oversized_total_name() {
        // Five 63-byte labels: each individually legal (<= 63 bytes), but
        // the total encoded QNAME (5 * (1 + 63) + 1 = 321 bytes) blows
        // past the RFC 1035 section 3.1 255-byte ceiling. Only the
        // per-label check existed before; this must be caught too.
        let label = "a".repeat(63);
        let hostname = alloc::format!("{label}.{label}.{label}.{label}.{label}");
        let result = build_dns_query(&hostname, 0x0001);
        assert_eq!(
            result,
            Err(DotError::InvalidName),
            "a total QNAME over 255 bytes must return InvalidName even when every label is individually legal"
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

    #[test]
    fn build_query_typed_rejects_oversized_total_name() {
        let label = "a".repeat(63);
        let hostname = alloc::format!("{label}.{label}.{label}.{label}.{label}");
        let result = build_dns_query_typed(&hostname, 0x0001, 28);
        assert_eq!(
            result,
            Err(DotError::InvalidName),
            "build_dns_query_typed must enforce the same 255-byte QNAME ceiling as build_dns_query"
        );
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
        // txids are now CSPRNG-derived (issue #288), not a predictable
        // counter, so the test can't hardcode the expected value. Seed
        // the CSPRNG deterministically, predict the draw query() will
        // make, then reseed to the same starting state so the client's
        // internal draw matches the prediction — this lets the mock
        // response stage the correct txid ahead of time.
        let key = [
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
            0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b,
            0x2c, 0x2d, 0x2e, 0x2f,
        ];
        csprng::seed_for_test(&key, &[0u8; 8], 0);
        let mut predicted = [0u8; 2];
        csprng::kernel_random_bytes(&mut predicted).expect("test csprng seeded");
        let txid = u16::from_le_bytes(predicted);
        csprng::seed_for_test(&key, &[0u8; 8], 0);

        // Build a mock response: frame header + DNS response.
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

        let transport = MockTlsTransport::with_responses(vec![frame_header, dns_response.clone()]);

        let pinned = [0xAA; SPKI_HASH_LEN];
        let mut client = DotClient::new(transport, QUAD9_DNS, pinned);

        let result = client.query("test.com", DNS_TYPE_A, 0, 1000);
        assert!(
            result.is_ok(),
            "query must succeed with valid mock response"
        );

        let response = result.ok().unwrap(); // ok: test
        assert_eq!(
            response, dns_response,
            "response must match mock DNS message"
        );

        // Verify the sent data contains a DoT frame carrying the
        // CSPRNG-predicted txid, not a hardcoded/predictable one.
        let sent = &client.transport_mut().sent;
        assert!(sent.len() > 2, "must have sent framed data");
        let sent_len = u16::from_be_bytes([sent[0], sent[1]]) as usize;
        assert_eq!(
            sent_len,
            sent.len() - 2,
            "sent frame length prefix must match payload size"
        );
        assert_eq!(
            &sent[2..4],
            &txid.to_be_bytes(),
            "client must send the CSPRNG-derived txid"
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
        assert_eq!(client.verify_server_pin(&wrong), Err(DotError::PinMismatch),);
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

    #[test]
    fn random_txid_is_not_sequential() {
        let key = [
            0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d,
            0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b,
            0x4c, 0x4d, 0x4e, 0x4f,
        ];
        csprng::seed_for_test(&key, &[0u8; 8], 0);

        let txids: Vec<u16> = (0..16).map(|_| random_txid()).collect();

        let all_sequential = txids.windows(2).all(|w| w[1] == w[0].wrapping_add(1));
        assert!(
            !all_sequential,
            "txids must not be a sequential counter: {txids:?}"
        );

        let monotonic = txids.windows(2).all(|w| w[1] > w[0]);
        assert!(
            !monotonic,
            "txids must not be monotonically increasing: {txids:?}"
        );
    }

    // -- Read frame tests -----------------------------------------------------

    #[test]
    fn read_frame_extracts_message() {
        let dns_msg = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        let len = dns_msg.len() as u16;
        let header = len.to_be_bytes().to_vec();

        let mut transport = MockTlsTransport::with_responses(vec![header, dns_msg.clone()]);
        let result = read_dot_frame(&mut transport, 1000);
        assert!(result.is_ok(), "read_dot_frame must succeed");
        assert_eq!(result.ok().unwrap(), dns_msg); // ok: test
    }

    #[test]
    fn read_frame_accumulates_partial_body_recv() {
        // Regression test for issue #285: DoT runs over a TCP-backed TLS
        // stream, so a DNS message body routinely arrives split across
        // multiple recv() calls. A single-shot recv must not be treated
        // as fatal truncation.
        let dns_msg = vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let len = dns_msg.len() as u16;
        let header = len.to_be_bytes().to_vec();
        let mid = dns_msg.len() / 2;

        let mut transport = MockTlsTransport::with_responses(vec![
            header,
            dns_msg[..mid].to_vec(),
            dns_msg[mid..].to_vec(),
        ]);
        let result = read_dot_frame(&mut transport, 1000);
        assert_eq!(
            result,
            Ok(dns_msg),
            "read_dot_frame must accumulate a body split across multiple recv() calls"
        );
    }

    #[test]
    fn read_frame_accumulates_partial_header_recv() {
        // The 2-byte length prefix itself can also arrive split across
        // recv() calls.
        let dns_msg = vec![0x01, 0x02, 0x03];
        let len = dns_msg.len() as u16;
        let header_bytes = len.to_be_bytes();

        let mut transport = MockTlsTransport::with_responses(vec![
            vec![header_bytes[0]],
            vec![header_bytes[1]],
            dns_msg.clone(),
        ]);
        let result = read_dot_frame(&mut transport, 1000);
        assert_eq!(
            result,
            Ok(dns_msg),
            "read_dot_frame must accumulate a length prefix split across multiple recv() calls"
        );
    }

    #[test]
    fn read_frame_rejects_truncated_header() {
        // WHY the trailing empty response (issue #285 regression): 1 byte
        // instead of 2, then the connection closes. read_dot_frame now
        // loops until DOT_FRAME_HEADER_SIZE bytes are accumulated, so an
        // empty recv() (n == 0, the real-world "orderly close" signal) is
        // what must produce TruncatedFrame here — exhausting
        // MockTlsTransport's staged responses instead produces
        // Err(RecvFailed), a distinct "transport failed" scenario, not a
        // truncated frame.
        let mut transport = MockTlsTransport::with_responses(vec![vec![0x00], vec![]]);
        let result = read_dot_frame(&mut transport, 1000);
        assert_eq!(result, Err(DotError::TruncatedFrame));
    }

    #[test]
    fn read_frame_rejects_zero_length() {
        let mut transport = MockTlsTransport::with_responses(vec![vec![0x00, 0x00]]);
        let result = read_dot_frame(&mut transport, 1000);
        assert_eq!(result, Err(DotError::InvalidFrameLength));
    }

    #[test]
    fn read_frame_rejects_oversized() {
        // Length = MAX_DNS_MESSAGE_SIZE + 1.
        let len = (MAX_DNS_MESSAGE_SIZE + 1) as u16;
        let header = len.to_be_bytes().to_vec();
        let mut transport = MockTlsTransport::with_responses(vec![header]);
        let result = read_dot_frame(&mut transport, 1000);
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
        assert!(
            s.contains("DoT enabled"),
            "display must show enabled status"
        );

        let disabled = DotConfig::disabled();
        let s = alloc::format!("{disabled}");
        assert!(
            s.contains("DoT disabled"),
            "display must show disabled status"
        );
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
            DotError::Timeout,
        ];
        for err in &errors {
            let s = alloc::format!("{err}");
            assert!(!s.is_empty(), "error display must not be empty");
        }
    }

    // -- #442 bounded deadline tests -----------------------------------------

    #[test]
    fn recv_past_deadline_returns_timeout_not_hang() {
        // A transport whose clock advances 500 ms per recv can never complete
        // within a 100 ms deadline: the timeout must surface as an error,
        // not a hang.
        let mut transport = MockTlsTransport::with_clock_advance(Vec::new(), 500);
        let mut buf = [0u8; 16];
        let result = transport.recv(&mut buf, 100);
        assert_eq!(result, Err(DotError::Timeout));
    }

    #[test]
    fn recv_within_deadline_succeeds() {
        let mut transport = MockTlsTransport::with_clock_advance(Vec::new(), 500);
        let mut buf = [0u8; 16];
        // Deadline of exactly one advance: the first recv lands at the edge.
        transport.responses.push(b"ok".to_vec());
        let result = transport.recv(&mut buf, 500);
        assert_eq!(result, Result::Ok(2));
    }

    #[test]
    fn read_dot_frame_times_out_mid_frame() {
        // Header arrives (at t=500), then the peer goes silent and the next
        // recv lands at t=1000 — past the 900 ms deadline: the frame reader
        // must return Timeout, never spin.
        let mut transport = MockTlsTransport::with_clock_advance(vec![b"\x00\x05".to_vec()], 500);
        let result = read_dot_frame(&mut transport, 900);
        assert_eq!(result, Err(DotError::Timeout));
    }

    #[test]
    fn query_passes_its_deadline_through() {
        // The same scripted frame as the success test, but with a deadline
        // the advancing mock cannot meet: query must return Timeout,
        // proving the deadline threads query -> read_dot_frame -> recv.
        let dns_response = alloc::vec![0x12, 0x34, 0x81, 0x80, 0x00, 0x01];
        let resp_len = dns_response.len() as u16;
        let frame_header = resp_len.to_be_bytes().to_vec();
        let transport =
            MockTlsTransport::with_clock_advance(vec![frame_header, dns_response], 500);
        let pinned = [0xAA; SPKI_HASH_LEN];
        let mut client = DotClient::new(transport, QUAD9_DNS, pinned);
        let result = client.query("test.com", DNS_TYPE_A, 0, 100);
        assert_eq!(result, Err(DotError::Timeout));
    }
}
