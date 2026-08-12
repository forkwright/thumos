//! Briar peer-to-peer transport stub.
//!
//! Metadata-minimized messaging protocol. The full Briar implementation
//! is complex (BTP protocol over Tor, Bluetooth, and `WiFi` Direct) —
//! this module provides the integration scaffold so that when Briar is
//! implemented, messages flow into the unified inbox via
//! [`MessageTransport::Briar`](crate::screen_messages::MessageTransport::Briar).
//!
//! # Architecture
//!
//! `BriarTransport` is a state machine with contact management and an
//! inbound message buffer. Methods return [`BriarError::TransportNotReady`]
//! for operations that require the actual BTP transport layer, which
//! will be wired in a future phase.
//!
//! # Privacy model
//!
//! Briar's design eliminates metadata at the transport layer:
//! - No central server — direct device-to-device over Tor or local radios
//! - Contacts exchange public keys out-of-band (QR code or link)
//! - Messages are end-to-end encrypted and forward-secret
//! - No phone number, email, or account required
//!
//! # Integration
//!
//! The `BriarContact.id` field (32-byte public key hash) maps to the
//! contact system via [`crate::contacts`]. Inbound messages are surfaced
//! through the unified inbox in [`crate::screen_messages`].

// WHY: Briar transport stub created in Phase 09 Wave 7, full BTP
// implementation pending.
#![expect(
    dead_code,
    reason = "Briar transport stub exists; BTP implementation pending (tier in docs/capability-inventory.toml)"
)]

extern crate alloc;

use core::fmt;

use alloc::string::String;
use alloc::vec::Vec;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of Briar contacts held in memory.
const MAX_CONTACTS: usize = 256;

/// Maximum number of inbound messages buffered before oldest are dropped.
const MAX_INBOX_MESSAGES: usize = 512;

/// Maximum message body length in bytes (Briar's own limit is ~32 KiB).
const MAX_MESSAGE_BODY_LEN: usize = 32_768;

/// Maximum contact name length in bytes.
const MAX_CONTACT_NAME_LEN: usize = 64;

/// Briar contact ID length (SHA-256 of the public key).
const CONTACT_ID_LEN: usize = 32;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors from Briar transport operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
#[non_exhaustive]
pub enum BriarError {
    /// The BTP transport layer is not yet implemented.
    TransportNotReady,
    /// The contact list has reached capacity.
    ContactCapacityReached,
    /// A contact with this ID already exists.
    DuplicateContact,
    /// The referenced contact was not found.
    ContactNotFound,
    /// The message body exceeds [`MAX_MESSAGE_BODY_LEN`].
    MessageTooLong,
    /// The contact name exceeds [`MAX_CONTACT_NAME_LEN`].
    NameTooLong,
    /// The transport is in an invalid state for the requested operation.
    InvalidState {
        /// The operation that was attempted.
        operation: &'static str,
        /// The current state label.
        current: &'static str,
    },
    /// The inbox buffer has reached capacity.
    InboxFull,
}

impl fmt::Display for BriarError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TransportNotReady => write!(f, "Briar transport not ready"),
            Self::ContactCapacityReached => write!(f, "contact list at capacity"),
            Self::DuplicateContact => write!(f, "duplicate contact ID"),
            Self::ContactNotFound => write!(f, "contact not found"),
            Self::MessageTooLong => write!(f, "message body too long"),
            Self::NameTooLong => write!(f, "contact name too long"),
            Self::InvalidState { operation, current } => {
                write!(f, "cannot {operation} in state {current}")
            }
            Self::InboxFull => write!(f, "inbox buffer full"),
        }
    }
}

// ---------------------------------------------------------------------------
// State machine
// ---------------------------------------------------------------------------

/// Briar transport lifecycle state.
///
/// Tracks the connection state of the BTP transport layer. In the
/// current stub, the transport never leaves [`BriarState::Offline`]
/// since the actual protocol is not yet implemented.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum BriarState {
    /// Transport is not running.
    #[default]
    Offline,
    /// Establishing BTP connections (Tor bootstrap or local radio scan).
    Connecting,
    /// Transport is active and can send/receive messages.
    Online,
    /// A fatal error occurred.
    Error(BriarError),
}

impl fmt::Display for BriarState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Offline => write!(f, "offline"),
            Self::Connecting => write!(f, "connecting"),
            Self::Online => write!(f, "online"),
            Self::Error(e) => write!(f, "error: {e}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Contact
// ---------------------------------------------------------------------------

/// A Briar contact identified by a 32-byte public key hash.
///
/// Contacts are exchanged out-of-band (QR code or Briar link). The
/// `id` field is the SHA-256 hash of the contact's public signing key,
/// used as a stable identifier across transport sessions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BriarContact {
    /// SHA-256 of the contact's public signing key.
    pub id: [u8; CONTACT_ID_LEN],
    /// UTF-8 encoded display name (padded with zeros).
    pub name: [u8; MAX_CONTACT_NAME_LEN],
    /// Number of valid bytes in `name`.
    pub name_len: u8,
}

impl BriarContact {
    /// Create a new contact with the given ID and name.
    ///
    /// Returns [`BriarError::NameTooLong`] if `name` exceeds
    /// [`MAX_CONTACT_NAME_LEN`] bytes.
    pub(crate) fn new(id: [u8; CONTACT_ID_LEN], name: &[u8]) -> Result<Self, BriarError> {
        if name.len() > MAX_CONTACT_NAME_LEN {
            return Err(BriarError::NameTooLong);
        }
        let mut buf = [0u8; MAX_CONTACT_NAME_LEN];
        buf[..name.len()].copy_from_slice(name);
        Ok(Self {
            id,
            name: buf,
            name_len: name.len() as u8,
        })
    }

    /// Return the contact name as a byte slice.
    #[must_use]
    pub(crate) fn name(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }
}

impl fmt::Display for BriarContact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Display first 8 bytes of ID as hex, then name.
        for b in &self.id[..4] {
            write!(f, "{b:02x}")?;
        }
        write!(f, "..")?;
        let name = self.name();
        if name.is_empty() {
            write!(f, " (unnamed)")
        } else {
            write!(f, " ")?;
            for &b in name {
                let c = if b.is_ascii_graphic() || b == b' ' {
                    b as char
                } else {
                    '?'
                };
                write!(f, "{c}")?;
            }
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// Message
// ---------------------------------------------------------------------------

/// An inbound Briar message.
///
/// Messages are end-to-end encrypted over BTP; this struct holds the
/// decrypted plaintext after transport-layer processing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BriarMessage {
    /// SHA-256 of the sender's public key (matches a `BriarContact.id`).
    pub sender_id: [u8; CONTACT_ID_LEN],
    /// Decrypted message body (UTF-8 plaintext).
    pub body: String,
    /// Unix timestamp (seconds since epoch) when the message was sent.
    pub timestamp: u64,
}

impl BriarMessage {
    /// Create a new message with validation.
    ///
    /// Returns [`BriarError::MessageTooLong`] if `body` exceeds
    /// [`MAX_MESSAGE_BODY_LEN`] bytes.
    pub(crate) fn new(
        sender_id: [u8; CONTACT_ID_LEN],
        body: String,
        timestamp: u64,
    ) -> Result<Self, BriarError> {
        if body.len() > MAX_MESSAGE_BODY_LEN {
            return Err(BriarError::MessageTooLong);
        }
        Ok(Self {
            sender_id,
            body,
            timestamp,
        })
    }
}

impl fmt::Display for BriarMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Show sender ID prefix and truncated body.
        for b in &self.sender_id[..4] {
            write!(f, "{b:02x}")?;
        }
        write!(f, ".. @ {}: ", self.timestamp)?;
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

/// Briar peer-to-peer transport.
///
/// Manages contacts, inbound message buffering, and transport state.
/// In this stub implementation, `send_message()` always returns
/// [`BriarError::TransportNotReady`] and `receive_messages()` returns
/// an empty slice — the actual BTP protocol layer will be implemented
/// in a future phase.
///
/// # Integration point
///
/// When BTP is implemented:
/// 1. `connect()` bootstraps Tor or scans for local Bluetooth/WiFi peers
/// 2. `send_message()` encrypts and routes via BTP
/// 3. A poll loop calls `receive_messages()` to drain the inbound buffer
/// 4. Received messages are pushed into the unified inbox
pub(crate) struct BriarTransport {
    /// Current transport state.
    state: BriarState,
    /// Known contacts (exchanged out-of-band).
    contacts: Vec<BriarContact>,
    /// Inbound message buffer.
    inbox: Vec<BriarMessage>,
}

impl BriarTransport {
    /// Create a new Briar transport in the [`BriarState::Offline`] state.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            state: BriarState::Offline,
            contacts: Vec::new(),
            inbox: Vec::new(),
        }
    }

    /// Return the current transport state.
    #[must_use]
    pub(crate) fn state(&self) -> BriarState {
        self.state
    }

    /// Return the current contact list.
    #[must_use]
    pub(crate) fn contacts(&self) -> &[BriarContact] {
        &self.contacts
    }

    /// Return the current inbox contents.
    #[must_use]
    pub(crate) fn inbox(&self) -> &[BriarMessage] {
        &self.inbox
    }

    /// Return the number of contacts.
    #[must_use]
    pub(crate) fn contact_count(&self) -> usize {
        self.contacts.len()
    }

    /// Return the number of buffered messages.
    #[must_use]
    pub(crate) fn inbox_count(&self) -> usize {
        self.inbox.len()
    }

    /// Add a contact to the local contact list.
    ///
    /// Contacts are exchanged out-of-band. This does not require the
    /// transport to be online — contacts can be added before connecting.
    ///
    /// # Errors
    ///
    /// - [`BriarError::ContactCapacityReached`] if the list is full
    /// - [`BriarError::DuplicateContact`] if the ID already exists
    pub(crate) fn add_contact(&mut self, contact: BriarContact) -> Result<(), BriarError> {
        if self.contacts.len() >= MAX_CONTACTS {
            return Err(BriarError::ContactCapacityReached);
        }
        if self.contacts.iter().any(|c| c.id == contact.id) {
            return Err(BriarError::DuplicateContact);
        }
        self.contacts.push(contact);
        Ok(())
    }

    /// Remove a contact by ID.
    ///
    /// Returns the removed contact, or [`BriarError::ContactNotFound`].
    pub(crate) fn remove_contact(
        &mut self,
        id: &[u8; CONTACT_ID_LEN],
    ) -> Result<BriarContact, BriarError> {
        let pos = self
            .contacts
            .iter()
            .position(|c| &c.id == id)
            .ok_or(BriarError::ContactNotFound)?;
        Ok(self.contacts.swap_remove(pos))
    }

    /// Look up a contact by ID.
    #[must_use]
    pub(crate) fn find_contact(&self, id: &[u8; CONTACT_ID_LEN]) -> Option<&BriarContact> {
        self.contacts.iter().find(|c| &c.id == id)
    }

    /// Send a message to a contact.
    ///
    /// In this stub implementation, always returns
    /// [`BriarError::TransportNotReady`]. When BTP is implemented,
    /// this will encrypt and route the message via Tor or local radio.
    ///
    /// # Errors
    ///
    /// - [`BriarError::TransportNotReady`] (always, in stub)
    /// - [`BriarError::ContactNotFound`] if `dest_id` is not in contacts
    /// - [`BriarError::MessageTooLong`] if `body` exceeds the limit
    pub(crate) fn send_message(
        &self,
        dest_id: &[u8; CONTACT_ID_LEN],
        body: &str,
    ) -> Result<(), BriarError> {
        // Validate contact exists.
        if !self.contacts.iter().any(|c| &c.id == dest_id) {
            return Err(BriarError::ContactNotFound);
        }
        // Validate message length.
        if body.len() > MAX_MESSAGE_BODY_LEN {
            return Err(BriarError::MessageTooLong);
        }
        // WHY: BTP transport is not yet implemented. This is the
        // integration point where encrypted message framing and
        // routing (Tor/BT/WiFi Direct) will be wired.
        Err(BriarError::TransportNotReady)
    }

    /// Return buffered inbound messages.
    ///
    /// In the stub implementation, this always returns an empty slice.
    /// When BTP is implemented, this will drain messages received since
    /// the last call.
    #[must_use]
    pub(crate) fn receive_messages(&self) -> &[BriarMessage] {
        // WHY: no BTP transport to receive from. The inbox buffer will
        // be populated by the BTP receive loop in a future phase.
        &self.inbox
    }

    /// Push a message into the inbox buffer.
    ///
    /// Used internally by the BTP receive loop (future) and for testing.
    /// Drops the oldest message if the buffer is full.
    ///
    /// # Errors
    ///
    /// - [`BriarError::ContactNotFound`] if the sender is not in contacts
    pub(crate) fn push_inbox(&mut self, message: BriarMessage) -> Result<(), BriarError> {
        if !self.contacts.iter().any(|c| c.id == message.sender_id) {
            return Err(BriarError::ContactNotFound);
        }
        if self.inbox.len() >= MAX_INBOX_MESSAGES {
            // Drop oldest message to make room.
            self.inbox.remove(0);
        }
        self.inbox.push(message);
        Ok(())
    }

    /// Clear all buffered inbox messages.
    pub(crate) fn clear_inbox(&mut self) {
        self.inbox.clear();
    }
}

impl fmt::Display for BriarTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Briar({}, {} contacts, {} messages)",
            self.state,
            self.contacts.len(),
            self.inbox.len(),
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
    fn transport_starts_offline() {
        let transport = BriarTransport::new();
        assert_eq!(
            transport.state(),
            BriarState::Offline,
            "new transport must start in Offline state"
        );
    }

    #[test]
    fn transport_starts_with_empty_contacts() {
        let transport = BriarTransport::new();
        assert!(
            transport.contacts().is_empty(),
            "new transport must have no contacts"
        );
        assert_eq!(transport.contact_count(), 0);
    }

    #[test]
    fn transport_starts_with_empty_inbox() {
        let transport = BriarTransport::new();
        assert!(
            transport.inbox().is_empty(),
            "new transport must have no messages"
        );
        assert_eq!(transport.inbox_count(), 0);
    }

    #[test]
    fn display_does_not_panic_on_multibyte_char_straddling_preview_boundary() {
        let mut body = "a".repeat(62);
        body.push('\u{20AC}'); // 3-byte UTF-8 '\u{20ac}' starting at byte offset 62, spanning 62..65
        let msg = BriarMessage::new([0x11; CONTACT_ID_LEN], body, 0)
            .unwrap_or_else(|_| unreachable!("valid message"));
        let rendered = msg.to_string();
        assert!(
            rendered.contains('a'),
            "preview must contain the leading ASCII content without panicking"
        );
    }

    // --- Contact tests ---

    #[test]
    fn add_contact_succeeds() {
        let mut transport = BriarTransport::new();
        let contact = BriarContact::new([0x01; 32], b"Alice").ok();
        assert!(contact.is_some(), "contact creation must succeed");
        let contact = contact.unwrap_or_else(|| unreachable!());
        let result = transport.add_contact(contact);
        assert!(result.is_ok(), "adding first contact must succeed");
        assert_eq!(transport.contact_count(), 1);
    }

    #[test]
    fn add_duplicate_contact_fails() {
        let mut transport = BriarTransport::new();
        let c1 = BriarContact::new([0x01; 32], b"Alice");
        let c2 = BriarContact::new([0x01; 32], b"Alice Copy");
        assert!(c1.is_ok());
        assert!(c2.is_ok());
        let c1 = c1.unwrap_or_else(|_| unreachable!());
        let c2 = c2.unwrap_or_else(|_| unreachable!());
        transport.add_contact(c1).ok();
        let result = transport.add_contact(c2);
        assert_eq!(
            result,
            Err(BriarError::DuplicateContact),
            "duplicate contact ID must be rejected"
        );
    }

    #[test]
    fn remove_contact_succeeds() {
        let mut transport = BriarTransport::new();
        let id = [0x02; 32];
        let contact = BriarContact::new(id, b"Bob").unwrap_or_else(|_| unreachable!());
        transport.add_contact(contact).ok();
        let result = transport.remove_contact(&id);
        assert!(result.is_ok(), "removing existing contact must succeed");
        assert_eq!(transport.contact_count(), 0);
    }

    #[test]
    fn remove_nonexistent_contact_fails() {
        let mut transport = BriarTransport::new();
        let result = transport.remove_contact(&[0xFF; 32]);
        assert_eq!(
            result,
            Err(BriarError::ContactNotFound),
            "removing nonexistent contact must return ContactNotFound"
        );
    }

    #[test]
    fn find_contact_by_id() {
        let mut transport = BriarTransport::new();
        let id = [0x03; 32];
        let contact = BriarContact::new(id, b"Carol").unwrap_or_else(|_| unreachable!());
        transport.add_contact(contact).ok();
        let found = transport.find_contact(&id);
        assert!(found.is_some(), "must find contact by ID");
        let found = found.unwrap_or_else(|| unreachable!());
        assert_eq!(found.name(), b"Carol");
    }

    #[test]
    fn find_missing_contact_returns_none() {
        let transport = BriarTransport::new();
        assert!(
            transport.find_contact(&[0xFF; 32]).is_none(),
            "missing contact must return None"
        );
    }

    #[test]
    fn contact_name_too_long_fails() {
        let long_name = [b'X'; MAX_CONTACT_NAME_LEN + 1];
        let result = BriarContact::new([0x04; 32], &long_name);
        assert_eq!(
            result,
            Err(BriarError::NameTooLong),
            "name exceeding MAX_CONTACT_NAME_LEN must be rejected"
        );
    }

    #[test]
    fn contact_max_name_succeeds() {
        let max_name = [b'A'; MAX_CONTACT_NAME_LEN];
        let result = BriarContact::new([0x05; 32], &max_name);
        assert!(
            result.is_ok(),
            "name at exactly MAX_CONTACT_NAME_LEN must succeed"
        );
        let contact = result.unwrap_or_else(|_| unreachable!());
        assert_eq!(contact.name_len, MAX_CONTACT_NAME_LEN as u8);
        assert_eq!(contact.name(), &max_name[..]);
    }

    #[test]
    fn contact_empty_name_succeeds() {
        let result = BriarContact::new([0x06; 32], b"");
        assert!(result.is_ok(), "empty name must succeed");
        let contact = result.unwrap_or_else(|_| unreachable!());
        assert_eq!(contact.name_len, 0);
        assert!(contact.name().is_empty());
    }

    // --- Message tests ---

    #[test]
    fn message_creation_succeeds() {
        let msg = BriarMessage::new([0x01; 32], "hello".to_string(), 1_000_000);
        assert!(msg.is_ok(), "message creation must succeed");
        let msg = msg.unwrap_or_else(|_| unreachable!());
        assert_eq!(msg.body, "hello");
        assert_eq!(msg.timestamp, 1_000_000);
    }

    #[test]
    fn message_too_long_fails() {
        let long_body = "X".repeat(MAX_MESSAGE_BODY_LEN + 1);
        let result = BriarMessage::new([0x01; 32], long_body, 0);
        assert_eq!(
            result,
            Err(BriarError::MessageTooLong),
            "message exceeding MAX_MESSAGE_BODY_LEN must be rejected"
        );
    }

    // --- Send tests ---

    #[test]
    fn send_returns_transport_not_ready() {
        let mut transport = BriarTransport::new();
        let id = [0x01; 32];
        let contact = BriarContact::new(id, b"Alice").unwrap_or_else(|_| unreachable!());
        transport.add_contact(contact).ok();

        let result = transport.send_message(&id, "hello");
        assert_eq!(
            result,
            Err(BriarError::TransportNotReady),
            "send must return TransportNotReady in stub"
        );
    }

    #[test]
    fn send_to_unknown_contact_fails() {
        let transport = BriarTransport::new();
        let result = transport.send_message(&[0xFF; 32], "hello");
        assert_eq!(
            result,
            Err(BriarError::ContactNotFound),
            "send to unknown contact must return ContactNotFound"
        );
    }

    #[test]
    fn send_oversized_message_fails() {
        let mut transport = BriarTransport::new();
        let id = [0x01; 32];
        let contact = BriarContact::new(id, b"Alice").unwrap_or_else(|_| unreachable!());
        transport.add_contact(contact).ok();

        let long_body = "X".repeat(MAX_MESSAGE_BODY_LEN + 1);
        let result = transport.send_message(&id, &long_body);
        assert_eq!(
            result,
            Err(BriarError::MessageTooLong),
            "oversized message must be rejected"
        );
    }

    // --- Receive tests ---

    #[test]
    fn receive_returns_empty_in_stub() {
        let transport = BriarTransport::new();
        assert!(
            transport.receive_messages().is_empty(),
            "stub receive must return empty slice"
        );
    }

    // --- Inbox buffer tests ---

    #[test]
    fn push_inbox_succeeds_for_known_contact() {
        let mut transport = BriarTransport::new();
        let id = [0x01; 32];
        let contact = BriarContact::new(id, b"Alice").unwrap_or_else(|_| unreachable!());
        transport.add_contact(contact).ok();

        let msg =
            BriarMessage::new(id, "hello".to_string(), 1000).unwrap_or_else(|_| unreachable!());
        let result = transport.push_inbox(msg);
        assert!(result.is_ok(), "push from known contact must succeed");
        assert_eq!(transport.inbox_count(), 1);
    }

    #[test]
    fn push_inbox_rejects_unknown_sender() {
        let mut transport = BriarTransport::new();
        let msg =
            BriarMessage::new([0xFF; 32], "spam".to_string(), 0).unwrap_or_else(|_| unreachable!());
        let result = transport.push_inbox(msg);
        assert_eq!(
            result,
            Err(BriarError::ContactNotFound),
            "message from unknown sender must be rejected"
        );
    }

    #[test]
    fn push_inbox_drops_oldest_when_full() {
        let mut transport = BriarTransport::new();
        let id = [0x01; 32];
        let contact = BriarContact::new(id, b"Alice").unwrap_or_else(|_| unreachable!());
        transport.add_contact(contact).ok();

        for i in 0..MAX_INBOX_MESSAGES {
            let msg =
                BriarMessage::new(id, "m".to_string(), i as u64).unwrap_or_else(|_| unreachable!());
            transport.push_inbox(msg).ok();
        }
        assert_eq!(transport.inbox_count(), MAX_INBOX_MESSAGES);

        // One more push over capacity must drop the oldest (timestamp 0),
        // not silently grow past MAX_INBOX_MESSAGES or drop the newest.
        let overflow_msg = BriarMessage::new(id, "overflow".to_string(), MAX_INBOX_MESSAGES as u64)
            .unwrap_or_else(|_| unreachable!());
        transport.push_inbox(overflow_msg).ok();

        assert_eq!(
            transport.inbox_count(),
            MAX_INBOX_MESSAGES,
            "inbox must stay capped at MAX_INBOX_MESSAGES after overflow"
        );
        assert_eq!(
            transport.inbox()[0].timestamp,
            1,
            "the oldest message (timestamp 0) must have been dropped, not the newest"
        );
        assert_eq!(
            transport.inbox().last().map(|m| m.timestamp),
            Some(MAX_INBOX_MESSAGES as u64),
            "the newly pushed message must be present at the newest end"
        );
    }

    #[test]
    fn clear_inbox_empties_buffer() {
        let mut transport = BriarTransport::new();
        let id = [0x01; 32];
        let contact = BriarContact::new(id, b"Alice").unwrap_or_else(|_| unreachable!());
        transport.add_contact(contact).ok();

        let msg =
            BriarMessage::new(id, "hello".to_string(), 1000).unwrap_or_else(|_| unreachable!());
        transport.push_inbox(msg).ok();
        assert_eq!(transport.inbox_count(), 1);

        transport.clear_inbox();
        assert_eq!(transport.inbox_count(), 0);
    }

    // --- Display tests ---

    #[test]
    fn state_display() {
        assert_eq!(BriarState::Offline.to_string(), "offline");
        assert_eq!(BriarState::Connecting.to_string(), "connecting");
        assert_eq!(BriarState::Online.to_string(), "online");
        assert_eq!(
            BriarState::Error(BriarError::TransportNotReady).to_string(),
            "error: Briar transport not ready"
        );
    }

    #[test]
    fn error_display() {
        assert_eq!(
            BriarError::TransportNotReady.to_string(),
            "Briar transport not ready"
        );
        assert_eq!(
            BriarError::ContactCapacityReached.to_string(),
            "contact list at capacity"
        );
        assert_eq!(
            BriarError::DuplicateContact.to_string(),
            "duplicate contact ID"
        );
        assert_eq!(
            BriarError::InvalidState {
                operation: "send",
                current: "offline"
            }
            .to_string(),
            "cannot send in state offline"
        );
    }

    #[test]
    fn contact_display_with_name() {
        let contact = BriarContact::new([0xAB; 32], b"Alice").unwrap_or_else(|_| unreachable!());
        let display = contact.to_string();
        assert!(
            display.contains("abababab.."),
            "display must contain hex prefix of ID: {display}"
        );
        assert!(
            display.contains("Alice"),
            "display must contain contact name: {display}"
        );
    }

    #[test]
    fn contact_display_unnamed() {
        let contact = BriarContact::new([0xCD; 32], b"").unwrap_or_else(|_| unreachable!());
        let display = contact.to_string();
        assert!(
            display.contains("(unnamed)"),
            "display must show (unnamed) for empty name: {display}"
        );
    }

    #[test]
    fn transport_display() {
        let mut transport = BriarTransport::new();
        let display = transport.to_string();
        assert!(
            display.contains("Briar(offline, 0 contacts, 0 messages)"),
            "transport display must show state summary: {display}"
        );

        let contact = BriarContact::new([0x01; 32], b"Alice").unwrap_or_else(|_| unreachable!());
        transport.add_contact(contact).ok();
        let display = transport.to_string();
        assert!(
            display.contains("1 contacts"),
            "transport display must reflect contact count: {display}"
        );
    }

    #[test]
    fn message_display() {
        let msg = BriarMessage::new([0xAB; 32], "Hello, world!".to_string(), 1_700_000_000)
            .unwrap_or_else(|_| unreachable!());
        let display = msg.to_string();
        assert!(
            display.contains("abababab.."),
            "message display must contain sender ID prefix: {display}"
        );
        assert!(
            display.contains("1700000000"),
            "message display must contain timestamp: {display}"
        );
        assert!(
            display.contains("Hello, world!"),
            "message display must contain body preview: {display}"
        );
    }

    // --- Default state tests ---

    #[test]
    fn briar_state_default_is_offline() {
        let state: BriarState = BriarState::default();
        assert_eq!(
            state,
            BriarState::Offline,
            "default BriarState must be Offline"
        );
    }
}
