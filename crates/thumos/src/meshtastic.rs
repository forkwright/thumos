//! Meshtastic `LoRa` mesh transport stub.
//!
//! `LoRa` mesh messaging via a paired Meshtastic device (T-Echo or T-Deck
//! connected via Bluetooth serial or USB). The actual `LoRa` protocol is
//! handled by the Meshtastic firmware on the companion device — thumos
//! communicates using the Meshtastic serial protocol (protobuf over
//! SLIP-framed serial).
//!
//! # Architecture
//!
//! `MeshtasticTransport` is a state machine that manages the serial
//! connection to a paired Meshtastic node, routes outbound messages,
//! and buffers inbound mesh messages. Methods return
//! [`MeshError::TransportNotReady`] for operations that require the
//! serial link, which will be wired via akroasis kerykeion in a future
//! phase.
//!
//! # `LoRa` mesh properties
//!
//! - Long range (1-10+ km line of sight), low bandwidth (~200 bps)
//! - Multi-hop mesh: messages relay through intermediate nodes
//! - No cellular infrastructure required — works off-grid
//! - Each node has a 32-bit ID and operates on a configured channel
//! - Messages include hop count for mesh topology awareness
//!
//! # Integration
//!
//! Inbound messages are surfaced through the unified inbox via
//! [`MessageTransport::Meshtastic`](crate::screen_messages::MessageTransport::Meshtastic).
//! The `from_node` field maps to the contact system when a node ID
//! is associated with a known contact.

// WHY: Meshtastic transport stub created in Phase 09 Wave 7, serial
// protocol implementation via akroasis kerykeion pending.
#![expect(
    dead_code,
    reason = "Meshtastic transport stub created in Phase 09 Wave 7, serial protocol pending"
)]

extern crate alloc;

use core::fmt;

use alloc::string::String;
use alloc::vec::Vec;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of mesh messages buffered before oldest are dropped.
const MAX_INBOX_MESSAGES: usize = 256;

/// Maximum message body length in bytes.
///
/// Meshtastic messages are limited by `LoRa` payload size. The protocol
/// supports up to ~237 bytes per packet; longer messages are fragmented.
/// We buffer the reassembled payload up to this limit.
const MAX_MESSAGE_BODY_LEN: usize = 512;

/// Maximum number of hops a message can traverse in the mesh.
///
/// Meshtastic defaults to 3 hops; this is the validation ceiling.
const MAX_HOP_COUNT: u8 = 7;

/// Default `LoRa` channel index (0 = primary channel).
const DEFAULT_CHANNEL: u8 = 0;

/// Broadcast destination node ID (all nodes on the channel).
const BROADCAST_NODE_ID: u32 = 0xFFFF_FFFF;

/// Maximum number of known nodes tracked by the transport.
const MAX_KNOWN_NODES: usize = 128;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors from Meshtastic transport operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
#[non_exhaustive]
pub enum MeshError {
    /// The serial transport to the Meshtastic device is not connected.
    TransportNotReady,
    /// The message body exceeds [`MAX_MESSAGE_BODY_LEN`].
    MessageTooLong,
    /// The hop count exceeds [`MAX_HOP_COUNT`].
    InvalidHopCount,
    /// The transport is in an invalid state for the requested operation.
    InvalidState {
        /// The operation that was attempted.
        operation: &'static str,
        /// The current state label.
        current: &'static str,
    },
    /// The serial connection to the Meshtastic device was lost.
    ConnectionLost,
    /// The inbox buffer has reached capacity (oldest was dropped).
    InboxOverflow,
    /// The serial protocol returned malformed data.
    ProtocolError,
    /// The node ID is not valid (e.g., zero).
    InvalidNodeId,
}

impl fmt::Display for MeshError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TransportNotReady => write!(f, "Meshtastic transport not ready"),
            Self::MessageTooLong => write!(f, "message body too long for LoRa"),
            Self::InvalidHopCount => write!(f, "hop count exceeds maximum"),
            Self::InvalidState { operation, current } => {
                write!(f, "cannot {operation} in state {current}")
            }
            Self::ConnectionLost => write!(f, "serial connection lost"),
            Self::InboxOverflow => write!(f, "inbox overflow, oldest message dropped"),
            Self::ProtocolError => write!(f, "serial protocol error"),
            Self::InvalidNodeId => write!(f, "invalid node ID"),
        }
    }
}

// ---------------------------------------------------------------------------
// State machine
// ---------------------------------------------------------------------------

/// Meshtastic transport lifecycle state.
///
/// Tracks the serial connection state to the paired Meshtastic device.
/// In the current stub, the transport never leaves
/// [`MeshState::Disconnected`] since the serial protocol is not yet wired.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum MeshState {
    /// No Meshtastic device is connected.
    #[default]
    Disconnected,
    /// Serial connection to the device is active and ready.
    Connected,
    /// A fatal error occurred on the serial link.
    Error(MeshError),
}

impl fmt::Display for MeshState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Disconnected => write!(f, "disconnected"),
            Self::Connected => write!(f, "connected"),
            Self::Error(e) => write!(f, "error: {e}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Node info
// ---------------------------------------------------------------------------

/// Information about a known mesh node.
///
/// Populated from Meshtastic node info packets. Tracks node identity
/// and last-seen metadata for mesh topology awareness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshNode {
    /// Unique 32-bit node ID assigned by the Meshtastic firmware.
    pub node_id: u32,
    /// Short name (up to 4 characters, as configured on the device).
    pub short_name: [u8; 4],
    /// Number of valid bytes in `short_name`.
    pub short_name_len: u8,
    /// Unix timestamp (seconds) when this node was last heard.
    pub last_seen: u64,
    /// Last known hop distance from this node.
    pub last_hop_count: u8,
}

impl MeshNode {
    /// Create a new node entry.
    #[must_use]
    pub(crate) const fn new(node_id: u32) -> Self {
        Self {
            node_id,
            short_name: [0u8; 4],
            short_name_len: 0,
            last_seen: 0,
            last_hop_count: 0,
        }
    }

    /// Return the short name as a byte slice.
    #[must_use]
    pub(crate) fn short_name(&self) -> &[u8] {
        &self.short_name[..self.short_name_len as usize]
    }

    /// Set the short name from a byte slice (truncated to 4 bytes).
    pub(crate) fn set_short_name(&mut self, name: &[u8]) {
        let len = name.len().min(4);
        self.short_name[..len].copy_from_slice(&name[..len]);
        self.short_name_len = len as u8;
    }
}

impl fmt::Display for MeshNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "!{:08x}", self.node_id)?;
        let name = self.short_name();
        if !name.is_empty() {
            write!(f, " (")?;
            for &b in name {
                let c = if b.is_ascii_graphic() || b == b' ' {
                    b as char
                } else {
                    '?'
                };
                write!(f, "{c}")?;
            }
            write!(f, ")")?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Message
// ---------------------------------------------------------------------------

/// An inbound Meshtastic mesh message.
///
/// Contains the decrypted message payload after `LoRa` demodulation and
/// Meshtastic protocol decoding. The `hop_count` field indicates how
/// many mesh relays the message traversed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshMessage {
    /// Source node ID (32-bit Meshtastic node identifier).
    pub from_node: u32,
    /// Destination node ID (our node or broadcast).
    pub to_node: u32,
    /// Decrypted message body (UTF-8 plaintext).
    pub body: String,
    /// Unix timestamp (seconds since epoch) when the message was received.
    pub timestamp: u64,
    /// Number of mesh hops this message traversed.
    pub hop_count: u8,
    /// Channel index the message was received on.
    pub channel: u8,
}

impl MeshMessage {
    /// Create a new mesh message with validation.
    ///
    /// # Errors
    ///
    /// - [`MeshError::MessageTooLong`] if `body` exceeds the limit
    /// - [`MeshError::InvalidHopCount`] if `hop_count` exceeds maximum
    /// - [`MeshError::InvalidNodeId`] if `from_node` is zero
    pub(crate) fn new(
        from_node: u32,
        to_node: u32,
        body: String,
        timestamp: u64,
        hop_count: u8,
        channel: u8,
    ) -> Result<Self, MeshError> {
        if from_node == 0 {
            return Err(MeshError::InvalidNodeId);
        }
        if body.len() > MAX_MESSAGE_BODY_LEN {
            return Err(MeshError::MessageTooLong);
        }
        if hop_count > MAX_HOP_COUNT {
            return Err(MeshError::InvalidHopCount);
        }
        Ok(Self {
            from_node,
            to_node,
            body,
            timestamp,
            hop_count,
            channel,
        })
    }

    /// Whether this message was a broadcast to all nodes on the channel.
    #[must_use]
    pub(crate) const fn is_broadcast(&self) -> bool {
        self.to_node == BROADCAST_NODE_ID
    }
}

impl fmt::Display for MeshMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "!{:08x}->!{:08x} ({}h, ch{}): ",
            self.from_node, self.to_node, self.hop_count, self.channel,
        )?;
        // WHY: byte-index 64 can land inside a multi-byte UTF-8 sequence in
        // an adversary-crafted body; walk char boundaries instead of
        // slicing at a fixed byte offset.
        let preview_len = self
            .body
            .char_indices()
            .map(|(i, c)| i + c.len_utf8())
            .take_while(|&end| end <= 64)
            .last()
            .unwrap_or(0);
        write!(f, "{}", &self.body[..preview_len])?;
        if self.body.len() > preview_len {
            write!(f, "...")?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

/// Meshtastic `LoRa` mesh transport.
///
/// Manages the serial connection to a paired Meshtastic device, routes
/// outbound messages, and buffers inbound mesh messages. In this stub,
/// `send_message()` always returns [`MeshError::TransportNotReady`]
/// and `poll_messages()` returns an empty slice.
///
/// # Integration point
///
/// When the serial protocol is implemented (via akroasis kerykeion):
/// 1. `connect(node_id)` establishes serial link and configures the node
/// 2. `send_message()` encodes and transmits via SLIP-framed serial
/// 3. `poll_messages()` drains the inbound buffer
/// 4. Received messages feed into the unified inbox
pub(crate) struct MeshtasticTransport {
    /// Current transport state.
    state: MeshState,
    /// Our node ID (set during connect).
    node_id: u32,
    /// Active `LoRa` channel index.
    channel: u8,
    /// Inbound message buffer.
    inbox: Vec<MeshMessage>,
    /// Known mesh nodes discovered via node info packets.
    known_nodes: Vec<MeshNode>,
}

impl MeshtasticTransport {
    /// Create a new Meshtastic transport in the
    /// [`MeshState::Disconnected`] state.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            state: MeshState::Disconnected,
            node_id: 0,
            channel: DEFAULT_CHANNEL,
            inbox: Vec::new(),
            known_nodes: Vec::new(),
        }
    }

    /// Return the current transport state.
    #[must_use]
    pub(crate) fn state(&self) -> MeshState {
        self.state
    }

    /// Return our node ID (zero if not connected).
    #[must_use]
    pub(crate) fn node_id(&self) -> u32 {
        self.node_id
    }

    /// Return the active `LoRa` channel index.
    #[must_use]
    pub(crate) fn channel(&self) -> u8 {
        self.channel
    }

    /// Return the current inbox contents.
    #[must_use]
    pub(crate) fn inbox(&self) -> &[MeshMessage] {
        &self.inbox
    }

    /// Return the number of buffered messages.
    #[must_use]
    pub(crate) fn inbox_count(&self) -> usize {
        self.inbox.len()
    }

    /// Return the list of known mesh nodes.
    #[must_use]
    pub(crate) fn known_nodes(&self) -> &[MeshNode] {
        &self.known_nodes
    }

    /// Connect to a Meshtastic device with the given node ID.
    ///
    /// In this stub, sets the node ID and channel but does not actually
    /// establish a serial connection — the state remains
    /// [`MeshState::Disconnected`] until the serial protocol is wired.
    ///
    /// # Errors
    ///
    /// - [`MeshError::InvalidNodeId`] if `node_id` is zero
    pub(crate) fn connect(&mut self, node_id: u32) -> Result<(), MeshError> {
        if node_id == 0 {
            return Err(MeshError::InvalidNodeId);
        }
        self.node_id = node_id;
        // WHY: actual serial connection establishment will be wired
        // via akroasis kerykeion. For now we record the node ID but
        // stay in Disconnected state to indicate the transport layer
        // is not functional.
        //
        // When wired, this will:
        // 1. Open the BT serial or USB serial port
        // 2. Send a SLIP-framed config request to the device
        // 3. Transition to Connected on successful handshake
        Ok(())
    }

    /// Set the active `LoRa` channel.
    pub(crate) fn set_channel(&mut self, channel: u8) {
        self.channel = channel;
    }

    /// Send a message to a destination node (or broadcast).
    ///
    /// In this stub implementation, always returns
    /// [`MeshError::TransportNotReady`]. When the serial protocol is
    /// wired, this will encode the message as a Meshtastic protobuf
    /// and transmit it via SLIP-framed serial to the paired device.
    ///
    /// Use `dest_node = 0xFFFF_FFFF` for broadcast.
    ///
    /// # Errors
    ///
    /// - [`MeshError::TransportNotReady`] (always, in stub)
    /// - [`MeshError::MessageTooLong`] if `body` exceeds the limit
    // WHY: &self is the correct signature for when the serial protocol is
    // wired (will access self.state, self.channel, etc.). Stub doesn't use it.
    #[expect(
        clippy::unused_self,
        reason = "&self is the correct signature for when the serial protocol is wired"
    )]
    pub(crate) fn send_message(&self, dest_node: u32, body: &str) -> Result<(), MeshError> {
        if body.len() > MAX_MESSAGE_BODY_LEN {
            return Err(MeshError::MessageTooLong);
        }
        // WHY: serial protocol not yet wired. This is the integration
        // point where Meshtastic protobuf encoding and SLIP framing
        // will be implemented via akroasis kerykeion.
        let _ = dest_node;
        Err(MeshError::TransportNotReady)
    }

    /// Poll for inbound mesh messages.
    ///
    /// In the stub implementation, this always returns an empty slice.
    /// When the serial protocol is wired, this will drain messages
    /// received from the paired Meshtastic device since the last call.
    #[must_use]
    pub(crate) fn poll_messages(&self) -> &[MeshMessage] {
        // WHY: no serial transport to receive from. The inbox buffer
        // will be populated by the serial receive loop in a future phase.
        &self.inbox
    }

    /// Push a message into the inbox buffer.
    ///
    /// Used internally by the serial receive loop (future) and for
    /// testing. Drops the oldest message if the buffer is full.
    pub(crate) fn push_inbox(&mut self, message: MeshMessage) {
        if self.inbox.len() >= MAX_INBOX_MESSAGES {
            // Drop oldest message to make room.
            self.inbox.remove(0);
        }
        self.inbox.push(message);
    }

    /// Clear all buffered inbox messages.
    pub(crate) fn clear_inbox(&mut self) {
        self.inbox.clear();
    }

    /// Record or update a known mesh node.
    ///
    /// If the node ID already exists, updates the entry. Otherwise
    /// adds a new entry (up to [`MAX_KNOWN_NODES`], oldest evicted).
    pub(crate) fn update_node(&mut self, node: MeshNode) {
        // Update existing entry if present.
        for existing in &mut self.known_nodes {
            if existing.node_id == node.node_id {
                existing.short_name = node.short_name;
                existing.short_name_len = node.short_name_len;
                existing.last_seen = node.last_seen;
                existing.last_hop_count = node.last_hop_count;
                return;
            }
        }
        // New node: evict oldest if at capacity.
        if self.known_nodes.len() >= MAX_KNOWN_NODES {
            // Evict the node with the oldest last_seen timestamp.
            let oldest_idx = self
                .known_nodes
                .iter()
                .enumerate()
                .min_by_key(|(_, n)| n.last_seen)
                .map(|(i, _)| i);
            if let Some(idx) = oldest_idx {
                self.known_nodes.swap_remove(idx);
            }
        }
        self.known_nodes.push(node);
    }

    /// Look up a known node by ID.
    #[must_use]
    pub(crate) fn find_node(&self, node_id: u32) -> Option<&MeshNode> {
        self.known_nodes.iter().find(|n| n.node_id == node_id)
    }
}

impl fmt::Display for MeshtasticTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Meshtastic({}, node !{:08x}, ch{}, {} msgs, {} nodes)",
            self.state,
            self.node_id,
            self.channel,
            self.inbox.len(),
            self.known_nodes.len(),
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::*;

    // --- State tests ---

    #[test]
    fn transport_starts_disconnected() {
        let transport = MeshtasticTransport::new();
        assert_eq!(
            transport.state(),
            MeshState::Disconnected,
            "new transport must start in Disconnected state"
        );
    }

    #[test]
    fn transport_starts_with_zero_node_id() {
        let transport = MeshtasticTransport::new();
        assert_eq!(
            transport.node_id(),
            0,
            "new transport must have zero node ID"
        );
    }

    #[test]
    fn transport_starts_with_default_channel() {
        let transport = MeshtasticTransport::new();
        assert_eq!(
            transport.channel(),
            DEFAULT_CHANNEL,
            "new transport must use default channel"
        );
    }

    #[test]
    fn transport_starts_with_empty_inbox() {
        let transport = MeshtasticTransport::new();
        assert!(
            transport.inbox().is_empty(),
            "new transport must have no messages"
        );
        assert_eq!(transport.inbox_count(), 0);
    }

    #[test]
    fn transport_starts_with_no_known_nodes() {
        let transport = MeshtasticTransport::new();
        assert!(
            transport.known_nodes().is_empty(),
            "new transport must have no known nodes"
        );
    }

    #[test]
    fn display_does_not_panic_on_multibyte_char_straddling_preview_boundary() {
        let mut body = "a".repeat(62);
        body.push('\u{1F600}'); // 4-byte UTF-8 emoji starting at byte offset 62, spanning 62..66
        let msg = MeshMessage::new(1, BROADCAST_NODE_ID, body, 0, 0, 0)
            .unwrap_or_else(|_| unreachable!("valid message"));
        let rendered = msg.to_string();
        assert!(
            rendered.contains('a'),
            "preview must contain the leading ASCII content without panicking"
        );
    }

    // --- Connect tests ---

    #[test]
    fn connect_sets_node_id() {
        let mut transport = MeshtasticTransport::new();
        let result = transport.connect(0x1234_5678);
        assert!(result.is_ok(), "connect with valid node ID must succeed");
        assert_eq!(transport.node_id(), 0x1234_5678);
    }

    #[test]
    fn connect_zero_node_id_fails() {
        let mut transport = MeshtasticTransport::new();
        let result = transport.connect(0);
        assert_eq!(
            result,
            Err(MeshError::InvalidNodeId),
            "connect with zero node ID must fail"
        );
    }

    #[test]
    fn set_channel_updates_channel() {
        let mut transport = MeshtasticTransport::new();
        transport.set_channel(3);
        assert_eq!(transport.channel(), 3);
    }

    // --- Message creation tests ---

    #[test]
    fn message_creation_succeeds() {
        let msg = MeshMessage::new(0x1234, 0x5678, "hello mesh".to_string(), 1_000_000, 2, 0);
        assert!(msg.is_ok(), "valid message creation must succeed");
        let msg = msg.unwrap_or_else(|_| unreachable!());
        assert_eq!(msg.from_node, 0x1234);
        assert_eq!(msg.to_node, 0x5678);
        assert_eq!(msg.body, "hello mesh");
        assert_eq!(msg.timestamp, 1_000_000);
        assert_eq!(msg.hop_count, 2);
        assert_eq!(msg.channel, 0);
    }

    #[test]
    fn message_zero_from_node_fails() {
        let result = MeshMessage::new(0, 0x5678, "hello".to_string(), 0, 0, 0);
        assert_eq!(
            result,
            Err(MeshError::InvalidNodeId),
            "message from node 0 must fail"
        );
    }

    #[test]
    fn message_too_long_fails() {
        let long_body = "X".repeat(MAX_MESSAGE_BODY_LEN + 1);
        let result = MeshMessage::new(0x1234, 0x5678, long_body, 0, 0, 0);
        assert_eq!(
            result,
            Err(MeshError::MessageTooLong),
            "oversized message must be rejected"
        );
    }

    #[test]
    fn message_max_body_succeeds() {
        let max_body = "X".repeat(MAX_MESSAGE_BODY_LEN);
        let result = MeshMessage::new(0x1234, 0x5678, max_body, 0, 0, 0);
        assert!(
            result.is_ok(),
            "message at exactly MAX_MESSAGE_BODY_LEN must succeed"
        );
    }

    #[test]
    fn message_hop_count_too_high_fails() {
        let result = MeshMessage::new(0x1234, 0x5678, "hello".to_string(), 0, MAX_HOP_COUNT + 1, 0);
        assert_eq!(
            result,
            Err(MeshError::InvalidHopCount),
            "hop count exceeding MAX_HOP_COUNT must be rejected"
        );
    }

    #[test]
    fn message_max_hop_count_succeeds() {
        let result = MeshMessage::new(0x1234, 0x5678, "hello".to_string(), 0, MAX_HOP_COUNT, 0);
        assert!(
            result.is_ok(),
            "message at exactly MAX_HOP_COUNT must succeed"
        );
    }

    #[test]
    fn broadcast_message_detection() {
        let msg = MeshMessage::new(0x1234, BROADCAST_NODE_ID, "broadcast".to_string(), 0, 0, 0)
            .unwrap_or_else(|_| unreachable!());
        assert!(
            msg.is_broadcast(),
            "message to BROADCAST_NODE_ID must be broadcast"
        );

        let msg = MeshMessage::new(0x1234, 0x5678, "direct".to_string(), 0, 0, 0)
            .unwrap_or_else(|_| unreachable!());
        assert!(
            !msg.is_broadcast(),
            "message to specific node must not be broadcast"
        );
    }

    // --- Send tests ---

    #[test]
    fn send_returns_transport_not_ready() {
        let transport = MeshtasticTransport::new();
        let result = transport.send_message(0x5678, "hello");
        assert_eq!(
            result,
            Err(MeshError::TransportNotReady),
            "send must return TransportNotReady in stub"
        );
    }

    #[test]
    fn send_oversized_message_fails() {
        let transport = MeshtasticTransport::new();
        let long_body = "X".repeat(MAX_MESSAGE_BODY_LEN + 1);
        let result = transport.send_message(0x5678, &long_body);
        assert_eq!(
            result,
            Err(MeshError::MessageTooLong),
            "oversized message must be rejected before transport check"
        );
    }

    #[test]
    fn send_broadcast_returns_not_ready() {
        let transport = MeshtasticTransport::new();
        let result = transport.send_message(BROADCAST_NODE_ID, "broadcast");
        assert_eq!(
            result,
            Err(MeshError::TransportNotReady),
            "broadcast send must still return TransportNotReady in stub"
        );
    }

    // --- Poll tests ---

    #[test]
    fn poll_returns_empty_in_stub() {
        let transport = MeshtasticTransport::new();
        assert!(
            transport.poll_messages().is_empty(),
            "stub poll must return empty slice"
        );
    }

    // --- Inbox buffer tests ---

    #[test]
    fn push_inbox_adds_message() {
        let mut transport = MeshtasticTransport::new();
        let msg = MeshMessage::new(0x1234, 0x5678, "hello".to_string(), 1000, 1, 0)
            .unwrap_or_else(|_| unreachable!());
        transport.push_inbox(msg);
        assert_eq!(transport.inbox_count(), 1);
        assert_eq!(transport.inbox()[0].body, "hello");
    }

    #[test]
    fn clear_inbox_empties_buffer() {
        let mut transport = MeshtasticTransport::new();
        let msg = MeshMessage::new(0x1234, 0x5678, "hello".to_string(), 1000, 1, 0)
            .unwrap_or_else(|_| unreachable!());
        transport.push_inbox(msg);
        assert_eq!(transport.inbox_count(), 1);

        transport.clear_inbox();
        assert_eq!(transport.inbox_count(), 0);
    }

    // --- Node tracking tests ---

    #[test]
    fn update_node_adds_new_node() {
        let mut transport = MeshtasticTransport::new();
        let mut node = MeshNode::new(0x1234);
        node.set_short_name(b"AB");
        node.last_seen = 1000;
        transport.update_node(node);

        assert_eq!(transport.known_nodes().len(), 1);
        let found = transport.find_node(0x1234);
        assert!(found.is_some(), "must find added node");
        let found = found.unwrap_or_else(|| unreachable!());
        assert_eq!(found.short_name(), b"AB");
    }

    #[test]
    fn update_node_updates_existing() {
        let mut transport = MeshtasticTransport::new();

        let mut node1 = MeshNode::new(0x1234);
        node1.set_short_name(b"AB");
        node1.last_seen = 1000;
        transport.update_node(node1);

        let mut node2 = MeshNode::new(0x1234);
        node2.set_short_name(b"CD");
        node2.last_seen = 2000;
        transport.update_node(node2);

        assert_eq!(
            transport.known_nodes().len(),
            1,
            "duplicate node ID must update, not duplicate"
        );
        let found = transport
            .find_node(0x1234)
            .unwrap_or_else(|| unreachable!());
        assert_eq!(found.short_name(), b"CD");
        assert_eq!(found.last_seen, 2000);
    }

    #[test]
    fn find_unknown_node_returns_none() {
        let transport = MeshtasticTransport::new();
        assert!(
            transport.find_node(0xDEAD).is_none(),
            "unknown node must return None"
        );
    }

    #[test]
    fn node_short_name_truncated_to_4() {
        let mut node = MeshNode::new(0x1234);
        node.set_short_name(b"ABCDEF");
        assert_eq!(
            node.short_name(),
            b"ABCD",
            "short name must be truncated to 4 bytes"
        );
        assert_eq!(node.short_name_len, 4);
    }

    #[test]
    fn node_empty_short_name() {
        let node = MeshNode::new(0x1234);
        assert!(node.short_name().is_empty());
        assert_eq!(node.short_name_len, 0);
    }

    // --- Display tests ---

    #[test]
    fn state_display() {
        assert_eq!(MeshState::Disconnected.to_string(), "disconnected");
        assert_eq!(MeshState::Connected.to_string(), "connected");
        assert_eq!(
            MeshState::Error(MeshError::ConnectionLost).to_string(),
            "error: serial connection lost"
        );
    }

    #[test]
    fn error_display() {
        assert_eq!(
            MeshError::TransportNotReady.to_string(),
            "Meshtastic transport not ready"
        );
        assert_eq!(
            MeshError::MessageTooLong.to_string(),
            "message body too long for LoRa"
        );
        assert_eq!(
            MeshError::InvalidHopCount.to_string(),
            "hop count exceeds maximum"
        );
        assert_eq!(
            MeshError::InvalidState {
                operation: "send",
                current: "disconnected"
            }
            .to_string(),
            "cannot send in state disconnected"
        );
        assert_eq!(MeshError::InvalidNodeId.to_string(), "invalid node ID");
    }

    #[test]
    fn node_display_with_name() {
        let mut node = MeshNode::new(0x1234_5678);
        node.set_short_name(b"AB");
        let display = node.to_string();
        assert_eq!(display, "!12345678 (AB)");
    }

    #[test]
    fn node_display_without_name() {
        let node = MeshNode::new(0x0000_00FF);
        let display = node.to_string();
        assert_eq!(display, "!000000ff");
    }

    #[test]
    fn message_display() {
        let msg = MeshMessage::new(
            0x1234,
            0x5678,
            "Hello mesh!".to_string(),
            1_700_000_000,
            2,
            1,
        )
        .unwrap_or_else(|_| unreachable!());
        let display = msg.to_string();
        assert!(
            display.contains("!00001234->!00005678"),
            "message display must contain node IDs: {display}"
        );
        assert!(
            display.contains("2h"),
            "message display must contain hop count: {display}"
        );
        assert!(
            display.contains("ch1"),
            "message display must contain channel: {display}"
        );
        assert!(
            display.contains("Hello mesh!"),
            "message display must contain body: {display}"
        );
    }

    #[test]
    fn transport_display() {
        let transport = MeshtasticTransport::new();
        let display = transport.to_string();
        assert!(
            display.contains("Meshtastic(disconnected"),
            "transport display must show state: {display}"
        );
        assert!(
            display.contains("node !00000000"),
            "transport display must show node ID: {display}"
        );
    }

    // --- Default state tests ---

    #[test]
    fn mesh_state_default_is_disconnected() {
        let state: MeshState = Default::default();
        assert_eq!(
            state,
            MeshState::Disconnected,
            "default MeshState must be Disconnected"
        );
    }
}
