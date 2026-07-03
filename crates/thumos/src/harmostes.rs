//! Matrix CS API client (harmostes).
//!
//! ἁρμοστής = "the one who joins or fits together." Implements a minimal
//! Matrix Client-Server API client for sync, room management, and
//! plaintext message send/receive. Built on the Wave 1 [`http_client`]
//! and [`json_mini`] primitives.
//!
//! # Architecture
//!
//! `MatrixClient` is a state machine that tracks rooms, sync tokens,
//! and an outbound message queue. It does **not** own a TCP connection —
//! the caller provides the transport layer. Methods on `MatrixClient`
//! build [`HttpRequest`]s and parse [`HttpResponse`]s, following the
//! same pattern as `dns.rs` and `dns_tls.rs`.
//!
//! # Mode-aware sync cadence
//!
//! Sync behaviour is governed by [`SecurityMode`]:
//!
//! | Mode | Screen state | Behaviour |
//! |------|-------------|-----------|
//! | Daily | on | Continuous long-poll (30 s timeout) |
//! | Daily | idle | 60 s interval |
//! | Sentinel | any | Disabled |
//! | Panic | any | Disabled |
//!
//! # Limitations (Phase 09 Wave 2)
//!
//! - Plaintext only — E2E encryption added in Wave 3.
//! - No persistent storage — room/outbox state lives in memory.
//! - No room creation or leave — join and message only.

// WHY: Matrix client created in Phase 09 Wave 2, full integration pending in Wave 5.
#![expect(
    dead_code,
    reason = "Matrix client created in Phase 09 Wave 2, unified inbox integration pending"
)]

extern crate alloc;

use core::fmt;

use alloc::string::String;
use alloc::vec::Vec;

use crate::http_client::{self, HttpError, HttpRequest, HttpResponse};
use crate::json_mini::{JsonError, JsonParser, JsonValue, JsonWriter};
use crate::matrix_crypto::{self, CryptoError, MatrixCrypto};
use crate::matrix_ids::{MatrixEventId, MatrixRoomId};
use crate::security_mode::SecurityMode;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Matrix CS API version prefix.
const API_PREFIX: &str = "/_matrix/client/v3";

/// Long-poll timeout for sync requests (milliseconds).
const SYNC_LONG_POLL_MS: u64 = 30_000;

/// Default sync interval for idle mode (milliseconds).
const SYNC_INTERVAL_IDLE_MS: u64 = 60_000;

/// Default sync interval for active mode (continuous long-poll).
const SYNC_INTERVAL_ACTIVE_MS: u64 = 0;

/// Maximum number of rooms tracked in memory.
const MAX_ROOMS: usize = 150;

/// Maximum messages cached per room.
const MAX_MESSAGES_PER_ROOM: usize = 100;

/// Maximum number of pending messages held in the outbox before
/// `queue_message`/`send_message` reject further additions (#365). Each
/// entry holds two heap Strings (room_id + body); bounding count bounds
/// worst-case outbox memory on a 1 GB device the same way MAX_ROOMS and
/// MAX_MESSAGES_PER_ROOM already bound room/timeline memory.
const MAX_OUTBOX_MESSAGES: usize = 256;

/// Maximum bytes of a non-JSON server error body surfaced verbatim in
/// [`MatrixError::ServerError`]'s `message` by `parse_error_response`.
/// Bounds worst-case memory from an adversarial or misconfigured
/// homeserver/proxy sending an oversized plaintext/HTML error page, the
/// same way the other MAX_* constants in this module bound room/outbox
/// memory on a 1 GB device.
const MAX_ERROR_BODY_LEN: usize = 512;

/// Transaction ID counter starting value.
const TXN_ID_START: u32 = 1;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors from Matrix client operations.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
#[non_exhaustive]
pub enum MatrixError {
    /// HTTP-level error from request building or response parsing.
    Http(HttpError),
    /// JSON parsing error from response body.
    Json(JsonError),
    /// The homeserver returned a non-2xx status code.
    ServerError {
        /// HTTP status code.
        status: u16,
        /// Error code from the Matrix error response (e.g., `M_UNKNOWN`).
        errcode: String,
        /// Human-readable error message.
        message: String,
    },
    /// The sync response is missing expected fields.
    MalformedSync,
    /// The room was not found in the client's room list.
    RoomNotFound,
    /// The send response did not contain an event ID.
    MissingSendResponse,
    /// Sync is disabled in the current security mode.
    SyncDisabled,
    /// The room list has reached capacity.
    RoomCapacityReached,
    /// The outbox has reached [`MAX_OUTBOX_MESSAGES`] pending messages (#365).
    OutboxFull,
    /// A Matrix identifier (room/event) failed format validation (#373).
    InvalidId(crate::matrix_ids::MatrixIdError),
}

impl fmt::Display for MatrixError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Http(e) => write!(f, "HTTP error: {e}"),
            Self::Json(e) => write!(f, "JSON error: {e}"),
            Self::ServerError {
                status,
                errcode,
                message,
            } => write!(f, "server error {status}: {errcode} — {message}"),
            Self::MalformedSync => write!(f, "malformed sync response"),
            Self::RoomNotFound => write!(f, "room not found"),
            Self::MissingSendResponse => write!(f, "send response missing event_id"),
            Self::SyncDisabled => write!(f, "sync disabled in current security mode"),
            Self::RoomCapacityReached => write!(f, "room capacity reached"),
            Self::OutboxFull => write!(f, "outbox capacity reached"),
            Self::InvalidId(e) => write!(f, "invalid Matrix identifier: {e}"),
        }
    }
}

impl From<crate::matrix_ids::MatrixIdError> for MatrixError {
    fn from(e: crate::matrix_ids::MatrixIdError) -> Self {
        Self::InvalidId(e)
    }
}

impl From<HttpError> for MatrixError {
    fn from(e: HttpError) -> Self {
        Self::Http(e)
    }
}

impl From<JsonError> for MatrixError {
    fn from(e: JsonError) -> Self {
        Self::Json(e)
    }
}

// ---------------------------------------------------------------------------
// Sync result
// ---------------------------------------------------------------------------

/// Result of a successful `/sync` call.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
#[non_exhaustive]
pub struct SyncResult {
    /// New messages received across all rooms, in arrival order.
    pub new_messages: Vec<IncomingMessage>,
    /// Number of rooms that had new timeline events.
    pub rooms_updated: u32,
    /// Number of rooms whose events were dropped because the room list was
    /// already at `MAX_ROOMS` capacity (#358). Non-zero means some events
    /// could not be stored — but the sync token still advances safely,
    /// because an over-capacity room cannot be persisted regardless, so
    /// there is nothing a retry could recover.
    pub rooms_over_capacity: u32,
    /// Number of rooms whose events were dropped because the room-id JSON key
    /// failed identifier validation (#373). Non-zero means an adversarial or
    /// buggy homeserver sent a malformed room key; that room's events are
    /// skipped (they could never be stored), but the sync token still advances
    /// safely — mirroring the `rooms_over_capacity` rationale (#358), because
    /// aborting the batch would permanently wedge sync on the bad key.
    pub rooms_malformed: u32,
    /// The next batch token (opaque, stored for incremental sync).
    pub next_batch: String,
}

impl fmt::Display for SyncResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SyncResult({} messages, {} rooms updated, {} over capacity, {} malformed)",
            self.new_messages.len(),
            self.rooms_updated,
            self.rooms_over_capacity,
            self.rooms_malformed,
        )
    }
}

/// A message received during sync, before it is integrated into room state.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
#[non_exhaustive]
pub struct IncomingMessage {
    /// The room this message belongs to.
    pub room_id: MatrixRoomId,
    /// The Matrix event ID.
    pub event_id: MatrixEventId,
    /// The sender's Matrix user ID.
    pub sender: String,
    /// The message body (plaintext).
    pub body: String,
    /// Server timestamp (milliseconds since epoch).
    pub timestamp: u64,
    /// Whether the event was encrypted (always `false` in Wave 2).
    pub encrypted: bool,
}

impl fmt::Display for IncomingMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "IncomingMessage({} from {} in {})",
            self.event_id, self.sender, self.room_id,
        )
    }
}

// ---------------------------------------------------------------------------
// Room
// ---------------------------------------------------------------------------

/// A Matrix room tracked by the client.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
#[non_exhaustive]
pub struct Room {
    /// The Matrix room ID (e.g., `!abc123:matrix.example.com`).
    pub room_id: MatrixRoomId,
    /// Human-readable display name for the room.
    pub display_name: String,
    /// Whether this room is a direct message (1:1).
    pub is_dm: bool,
    /// Cached timeline messages, most recent last.
    pub messages: Vec<MatrixMessage>,
    /// Number of unread messages since last read marker.
    pub unread_count: u32,
}

impl Room {
    /// Create a new room with the given ID and display name.
    ///
    /// # Errors
    ///
    /// Returns [`MatrixError::InvalidId`] if `room_id` is not a well-formed
    /// Matrix room identifier (#373).
    fn new(room_id: &str, display_name: String, is_dm: bool) -> Result<Self, MatrixError> {
        Ok(Self {
            room_id: MatrixRoomId::new(room_id)?,
            display_name,
            is_dm,
            messages: Vec::new(),
            unread_count: 0,
        })
    }

    /// Add a message to this room's cache, evicting the oldest if at capacity.
    fn add_message(&mut self, msg: MatrixMessage) {
        if self.messages.len() >= MAX_MESSAGES_PER_ROOM {
            let _ = self.messages.remove(0); // WHY: Vec::remove returns the evicted element; cache eviction discards oldest intentionally
        }
        self.messages.push(msg);
        self.unread_count = self.unread_count.saturating_add(1);
    }
}

impl fmt::Display for Room {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Room({}, \"{}\", {} messages, {} unread)",
            self.room_id,
            self.display_name,
            self.messages.len(),
            self.unread_count,
        )
    }
}

// ---------------------------------------------------------------------------
// MatrixMessage
// ---------------------------------------------------------------------------

/// A single message event in a room's timeline.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
#[non_exhaustive]
pub struct MatrixMessage {
    /// The Matrix event ID (e.g., `$event123`).
    pub event_id: MatrixEventId,
    /// The sender's Matrix user ID (e.g., `@user:server`).
    pub sender: String,
    /// The message body (plaintext).
    pub body: String,
    /// Server timestamp in milliseconds since epoch.
    pub timestamp: u64,
    /// Whether this message was end-to-end encrypted.
    /// Always `false` in Wave 2 (plaintext only).
    pub encrypted: bool,
}

impl fmt::Display for MatrixMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MatrixMessage({} from {} at {})",
            self.event_id, self.sender, self.timestamp,
        )
    }
}

// ---------------------------------------------------------------------------
// PendingMessage
// ---------------------------------------------------------------------------

/// A message queued for sending when the client is offline or between
/// sync cycles.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
#[non_exhaustive]
pub struct PendingMessage {
    /// Target room ID.
    pub room_id: MatrixRoomId,
    /// Message body to send.
    pub body: String,
    /// Client-generated transaction ID for idempotent retries.
    pub txn_id: u32,
}

impl fmt::Display for PendingMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PendingMessage(txn={}, room={}, {} bytes)",
            self.txn_id,
            self.room_id,
            self.body.len(),
        )
    }
}

// ---------------------------------------------------------------------------
// MatrixClient
// ---------------------------------------------------------------------------

/// Minimal Matrix CS API client.
///
/// Manages device identity, room list, sync token, and outbound message
/// queue. Methods build [`HttpRequest`] / parse [`HttpResponse`] pairs —
/// the caller is responsible for TCP transport.
///
/// Wave 3: includes E2E encryption via [`MatrixCrypto`]. Outbound messages
/// are encrypted with Megolm when a session exists for the room. Inbound
/// `m.room.encrypted` events are decrypted when an inbound session is available.
#[non_exhaustive]
pub(crate) struct MatrixClient {
    /// Homeserver hostname (e.g., `matrix.example.com`).
    homeserver: String,
    /// Authenticated user ID (e.g., `@cody:matrix.example.com`).
    user_id: String,
    /// Device ID assigned during provisioning.
    device_id: String,
    /// Access token for Bearer auth.
    access_token: String,
    /// Opaque sync token for incremental `/sync`.
    sync_token: Option<String>,
    /// Tracked rooms.
    rooms: Vec<Room>,
    /// Outbound messages waiting to be sent.
    outbox: Vec<PendingMessage>,
    /// Sync poll interval in milliseconds (0 = continuous long-poll).
    sync_interval_ms: u64,
    /// Tick at which the last sync was initiated.
    last_sync_tick: u64,
    /// Monotonically increasing transaction ID counter.
    next_txn_id: u32,
    /// E2E encryption state (Wave 3).
    crypto: MatrixCrypto,
}

impl MatrixClient {
    /// Create a new client with the given identity.
    ///
    /// The client starts with no rooms, no sync token, and the default
    /// active-mode sync interval (continuous long-poll).
    ///
    /// # Errors
    ///
    /// [`CryptoError::EntropyUnavailable`] if the kernel CSPRNG is not yet
    /// seeded when the device keys are generated (fail-closed, audit #284).
    /// The caller must ensure `csprng::init()` has completed first.
    pub(crate) fn new(
        homeserver: &str,
        user_id: &str,
        device_id: &str,
        access_token: &str,
    ) -> Result<Self, CryptoError> {
        Ok(Self {
            homeserver: String::from(homeserver),
            user_id: String::from(user_id),
            device_id: String::from(device_id),
            access_token: String::from(access_token),
            sync_token: None,
            rooms: Vec::new(),
            outbox: Vec::new(),
            sync_interval_ms: SYNC_INTERVAL_ACTIVE_MS,
            last_sync_tick: 0,
            next_txn_id: TXN_ID_START,
            crypto: MatrixCrypto::new()?,
        })
    }

    // -----------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------

    /// Return the list of tracked rooms.
    #[must_use]
    pub(crate) fn rooms(&self) -> &[Room] {
        &self.rooms
    }

    /// Return messages for a specific room, if it exists.
    #[must_use]
    pub(crate) fn room_messages(&self, room_id: &str) -> Option<&[MatrixMessage]> {
        self.find_room(room_id).map(|r| r.messages.as_slice())
    }

    /// Mark all of a room's messages as read, resetting its unread counter
    /// to 0.
    ///
    /// [`Room::unread_count`] is documented as "unread messages since last
    /// read marker", but [`Room::add_message`] only ever increments it --
    /// there was previously no way to advance that read marker, so the
    /// count could only grow for the client's lifetime.
    ///
    /// Returns `true` if `room_id` was found and reset, `false` otherwise.
    pub(crate) fn mark_room_read(&mut self, room_id: &str) -> bool {
        match self.rooms.iter_mut().find(|r| r.room_id == room_id) {
            Some(room) => {
                room.unread_count = 0;
                true
            }
            None => false,
        }
    }

    /// Return the homeserver hostname.
    #[must_use]
    pub(crate) fn homeserver(&self) -> &str {
        &self.homeserver
    }

    /// Return the authenticated user ID.
    #[must_use]
    pub(crate) fn user_id(&self) -> &str {
        &self.user_id
    }

    /// Return the device ID.
    #[must_use]
    pub(crate) fn device_id(&self) -> &str {
        &self.device_id
    }

    /// Return a reference to the E2E crypto state.
    #[must_use]
    pub(crate) fn crypto(&self) -> &MatrixCrypto {
        &self.crypto
    }

    /// Return a mutable reference to the E2E crypto state.
    pub(crate) fn crypto_mut(&mut self) -> &mut MatrixCrypto {
        &mut self.crypto
    }

    /// Return the current outbox contents.
    #[must_use]
    pub(crate) fn outbox(&self) -> &[PendingMessage] {
        &self.outbox
    }

    /// Return the current sync token, if set.
    #[must_use]
    pub(crate) fn sync_token(&self) -> Option<&str> {
        self.sync_token.as_deref()
    }

    // -----------------------------------------------------------------------
    // Sync
    // -----------------------------------------------------------------------

    /// Check whether enough time has elapsed to perform another sync.
    ///
    /// Compares `current_tick` against `last_sync_tick + sync_interval_ms`.
    /// For continuous mode (`sync_interval_ms == 0`), always returns `true`.
    /// For disabled sync (`sync_interval_ms == u64::MAX`, set by
    /// `update_sync_cadence` in Sentinel/Panic mode), always returns `false`.
    #[must_use]
    pub(crate) fn should_sync(&self, current_tick: u64) -> bool {
        if self.sync_interval_ms == 0 {
            return true;
        }
        // WHY: u64::MAX is the disabled-sync sentinel (see
        // `update_sync_cadence`/`build_sync_request`). Handle it explicitly
        // rather than folding it into the tick-interval arithmetic below:
        // `u64::MAX / 10` truncates to roughly a tenth of u64::MAX, so a
        // sufficiently large `current_tick` (e.g. u64::MAX - 1) could still
        // exceed `last_sync_tick + interval_ticks` and wrongly report due,
        // defeating the "never sync while disabled" contract.
        if self.sync_interval_ms == u64::MAX {
            return false;
        }
        // Ticks are at 10 ms granularity in the kernel tick counter.
        // sync_interval_ms is in real milliseconds, so convert to ticks.
        let interval_ticks = self.sync_interval_ms / 10;
        current_tick >= self.last_sync_tick.saturating_add(interval_ticks)
    }

    /// Update the sync interval based on the current security mode and
    /// whether the screen is active.
    pub(crate) fn update_sync_cadence(&mut self, mode: SecurityMode, screen_on: bool) {
        self.sync_interval_ms = match mode {
            SecurityMode::Daily => {
                if screen_on {
                    SYNC_INTERVAL_ACTIVE_MS
                } else {
                    SYNC_INTERVAL_IDLE_MS
                }
            }
            SecurityMode::Sentinel | SecurityMode::Panic => {
                // Sync disabled — set interval to u64::MAX so should_sync
                // never returns true.
                u64::MAX
            }
        };
    }

    /// Build a `/sync` HTTP request.
    ///
    /// # Errors
    ///
    /// Returns [`MatrixError::SyncDisabled`] if the current sync interval
    /// indicates sync is disabled (Sentinel/Panic mode).
    pub(crate) fn build_sync_request(&self) -> Result<HttpRequest, MatrixError> {
        if self.sync_interval_ms == u64::MAX {
            return Err(MatrixError::SyncDisabled);
        }

        let mut path = String::from(API_PREFIX);
        path.push_str("/sync?timeout=");
        push_u64(&mut path, SYNC_LONG_POLL_MS);

        if let Some(ref token) = self.sync_token {
            if token.bytes().any(|b| b == b' ' || b.is_ascii_control()) {
                return Err(MatrixError::MalformedSync);
            }
            path.push_str("&since=");
            path.push_str(token);
        }

        let mut req = http_client::get(&self.homeserver, &path);
        http_client::with_auth(&mut req, &self.access_token);
        Ok(req)
    }

    /// Process a `/sync` HTTP response and update internal state.
    ///
    /// Extracts timeline events from joined rooms, updates the room list
    /// and message caches, and advances the sync token.
    ///
    /// # Errors
    ///
    /// Returns [`MatrixError::Json`] if the response body is not valid JSON.
    /// Returns [`MatrixError::MalformedSync`] if required fields are missing.
    /// Returns [`MatrixError::Http`] on HTTP parse errors.
    pub(crate) fn process_sync_response(
        &mut self,
        response: &HttpResponse,
        current_tick: u64,
    ) -> Result<SyncResult, MatrixError> {
        self.last_sync_tick = current_tick;

        if !response.is_success() {
            return Err(parse_error_response(response));
        }

        let body_str = response.body_as_str().ok_or(MatrixError::MalformedSync)?;
        let root = JsonParser::parse(body_str.as_bytes())?;

        // Extract next_batch token.
        let next_batch = root
            .get("next_batch")
            .and_then(|v| v.as_str())
            .ok_or(MatrixError::MalformedSync)?;
        self.sync_token = Some(String::from(next_batch));

        let mut result = SyncResult {
            new_messages: Vec::new(),
            rooms_updated: 0,
            rooms_over_capacity: 0,
            rooms_malformed: 0,
            next_batch: String::from(next_batch),
        };

        // Extract joined rooms from rooms.join.
        let rooms_obj = match root.get("rooms") {
            Some(r) => r,
            None => return Ok(result),
        };

        let join_obj = match rooms_obj.get("join") {
            Some(j) => j,
            None => return Ok(result),
        };

        let join_entries = match join_obj.as_object() {
            Some(entries) => entries,
            None => return Ok(result),
        };

        for (room_id, room_data) in join_entries {
            let events = extract_timeline_events(room_data);
            if events.is_empty() {
                continue;
            }

            // Find or create the room in our list.
            // WHY(#358): self.sync_token was already advanced above. If this
            // room is beyond MAX_ROOMS, propagating the Err would leave the
            // token advanced while reporting the whole batch failed — a
            // caller retrying from next_batch would permanently lose every
            // event in this batch. An over-capacity room cannot be stored
            // regardless, so skip it (counted via rooms_over_capacity) and
            // keep processing the rest, letting the token advance safely.
            let room_idx = match self.find_or_create_room(room_id) {
                Ok(idx) => idx,
                Err(MatrixError::RoomCapacityReached) => {
                    result.rooms_over_capacity = result.rooms_over_capacity.saturating_add(1);
                    continue;
                }
                // WHY(#373): a malformed room-id JSON key cannot be stored
                // (validation rejects it). The sync token was already advanced,
                // so propagating the Err would permanently wedge sync on this
                // key — skip and count, exactly like the over-capacity path.
                Err(MatrixError::InvalidId(_)) => {
                    result.rooms_malformed = result.rooms_malformed.saturating_add(1);
                    continue;
                }
                Err(e) => return Err(e),
            };

            result.rooms_updated = result.rooms_updated.saturating_add(1);

            for event in &events {
                let msg = parse_timeline_event(event, room_id, &self.crypto);
                if let Some(msg) = msg {
                    let incoming = IncomingMessage {
                        // WHY(#373): reuse the already-validated room id stored
                        // on the room, avoiding a redundant fallible re-parse.
                        room_id: self.rooms[room_idx].room_id.clone(),
                        event_id: msg.event_id.clone(),
                        sender: msg.sender.clone(),
                        body: msg.body.clone(),
                        timestamp: msg.timestamp,
                        encrypted: msg.encrypted,
                    };
                    self.rooms[room_idx].add_message(msg);
                    result.new_messages.push(incoming);
                }
            }
        }

        Ok(result)
    }

    /// Perform the full sync cycle: build request, process response.
    ///
    /// Convenience method that combines [`build_sync_request`] and
    /// [`process_sync_response`]. The caller must still handle the
    /// TCP transport between the two — this method takes the raw
    /// response as input.
    ///
    /// # Errors
    ///
    /// Returns errors from either the request build or response parse.
    pub(crate) fn sync(
        &mut self,
        response: &HttpResponse,
        current_tick: u64,
    ) -> Result<SyncResult, MatrixError> {
        self.process_sync_response(response, current_tick)
    }

    // -----------------------------------------------------------------------
    // Send message
    // -----------------------------------------------------------------------

    /// Build a send-message HTTP request for the given room.
    ///
    /// Uses PUT `/_matrix/client/v3/rooms/{roomId}/send/m.room.message/{txnId}`.
    /// The transaction ID is monotonically increasing for idempotent retries.
    ///
    /// # Errors
    ///
    /// Returns [`MatrixError::Http`] if the request cannot be built.
    pub(crate) fn build_send_request(
        &mut self,
        room_id: &str,
        body: &str,
    ) -> Result<(HttpRequest, u32), MatrixError> {
        let txn_id = self.next_txn_id;
        self.next_txn_id = self.next_txn_id.saturating_add(1);

        let mut path = String::from(API_PREFIX);
        path.push_str("/rooms/");
        path.push_str(room_id);
        path.push_str("/send/m.room.message/");
        push_u32(&mut path, txn_id);

        let json_body = build_message_body(body);
        let mut req = http_client::put_json(&self.homeserver, &path, json_body.as_bytes());
        http_client::with_auth(&mut req, &self.access_token);

        Ok((req, txn_id))
    }

    /// Build an encrypted send-message HTTP request for the given room.
    ///
    /// Uses the outbound Megolm session for the room to encrypt the message
    /// body. The encrypted payload is sent as an `m.room.encrypted` event
    /// via PUT. Creates an outbound Megolm session if none exists.
    ///
    /// # Errors
    ///
    /// Returns [`MatrixError::Http`] if the request cannot be built.
    /// Returns [`MatrixError::Json`] if encryption fails (wraps `CryptoError`).
    pub(crate) fn build_encrypted_send_request(
        &mut self,
        room_id: &str,
        body: &str,
    ) -> Result<(HttpRequest, u32), MatrixError> {
        let txn_id = self.next_txn_id;
        self.next_txn_id = self.next_txn_id.saturating_add(1);
        let req = self.build_megolm_request(room_id, body, txn_id)?;
        Ok((req, txn_id))
    }

    /// Encrypt `body` for `room_id` with the room's outbound Megolm session and
    /// build the `m.room.encrypted` PUT request for transaction `txn_id`.
    ///
    /// Creates an outbound session if none exists. This is the single encrypted
    /// send path, shared by [`build_encrypted_send_request`] and
    /// [`flush_outbox`] so plaintext can never bypass Megolm (audit #370).
    ///
    /// # Errors
    ///
    /// Returns [`MatrixError::ServerError`] if session creation or encryption
    /// fails.
    fn build_megolm_request(
        &mut self,
        room_id: &str,
        body: &str,
        txn_id: u32,
    ) -> Result<HttpRequest, MatrixError> {
        // Ensure an outbound Megolm session exists for this room.
        if self.crypto.find_outbound_megolm(room_id).is_none() {
            self.crypto
                .create_outbound_megolm(room_id)
                .map_err(crypto_error)?;
        }

        let session_idx = self
            .crypto
            .megolm_outbound
            .iter()
            .position(|s| s.room_id == room_id)
            .ok_or_else(|| MatrixError::ServerError {
                status: 0,
                errcode: String::from("M_CRYPTO_ERROR"),
                message: String::from("no outbound session after creation"),
            })?;

        let session = &mut self.crypto.megolm_outbound[session_idx];
        // `[u8; 32]` is `Copy`; capture the session id before the mutable borrow.
        let session_id = session.session_id;
        let ciphertext =
            matrix_crypto::encrypt_megolm(session, body.as_bytes()).map_err(crypto_error)?;

        let mut path = String::from(API_PREFIX);
        path.push_str("/rooms/");
        path.push_str(room_id);
        path.push_str("/send/m.room.encrypted/");
        push_u32(&mut path, txn_id);

        let json_body = build_encrypted_body(&ciphertext, &session_id);
        let mut req = http_client::put_json(&self.homeserver, &path, json_body.as_bytes());
        http_client::with_auth(&mut req, &self.access_token);
        Ok(req)
    }

    /// Process a send-message HTTP response.
    ///
    /// Returns the event ID assigned by the server on success.
    ///
    /// # Errors
    ///
    /// Returns [`MatrixError::ServerError`] on non-2xx responses.
    /// Returns [`MatrixError::MissingSendResponse`] if the response
    /// does not contain an `event_id`.
    pub(crate) fn process_send_response(
        &self,
        response: &HttpResponse,
    ) -> Result<String, MatrixError> {
        if !response.is_success() {
            return Err(parse_error_response(response));
        }

        let body_str = response
            .body_as_str()
            .ok_or(MatrixError::MissingSendResponse)?;
        let root = JsonParser::parse(body_str.as_bytes())?;

        let event_id = root
            .get("event_id")
            .and_then(|v| v.as_str())
            .ok_or(MatrixError::MissingSendResponse)?;

        Ok(String::from(event_id))
    }

    /// Build and queue a message for sending.
    ///
    /// This is a convenience that builds the HTTP request and also
    /// queues the message in the outbox for retry if the send fails.
    ///
    /// Returns the built request and transaction ID.
    ///
    /// # Errors
    ///
    /// Returns [`MatrixError::Http`] if the request cannot be built.
    /// Returns [`MatrixError::OutboxFull`] if the outbox already holds
    /// [`MAX_OUTBOX_MESSAGES`] pending messages (#365).
    pub(crate) fn send_message(
        &mut self,
        room_id: &str,
        body: &str,
    ) -> Result<(HttpRequest, u32), MatrixError> {
        if self.outbox.len() >= MAX_OUTBOX_MESSAGES {
            return Err(MatrixError::OutboxFull);
        }

        // WHY(#373): validate before build_send_request, which interpolates
        // room_id into the HTTP request path — a CRLF-bearing id would be a
        // header/path injection.
        let validated_room = MatrixRoomId::new(room_id)?;
        let (req, txn_id) = self.build_send_request(room_id, body)?;

        self.outbox.push(PendingMessage {
            room_id: validated_room,
            body: String::from(body),
            txn_id,
        });

        Ok((req, txn_id))
    }

    /// Remove a successfully sent message from the outbox by transaction ID.
    pub(crate) fn confirm_sent(&mut self, txn_id: u32) {
        self.outbox.retain(|m| m.txn_id != txn_id);
    }

    // -----------------------------------------------------------------------
    // Outbox
    // -----------------------------------------------------------------------

    /// Queue a message for later sending (when offline).
    ///
    /// The message is added to the outbox with the next transaction ID.
    ///
    /// # Errors
    ///
    /// Returns [`MatrixError::OutboxFull`] if the outbox already holds
    /// [`MAX_OUTBOX_MESSAGES`] pending messages (#365).
    pub(crate) fn queue_message(&mut self, room_id: &str, body: &str) -> Result<(), MatrixError> {
        if self.outbox.len() >= MAX_OUTBOX_MESSAGES {
            return Err(MatrixError::OutboxFull);
        }

        // WHY(#373): reject a malformed room id before it can be sent from the
        // outbox (build_send_request interpolates it into the HTTP path).
        let validated_room = MatrixRoomId::new(room_id)?;
        let txn_id = self.next_txn_id;
        self.next_txn_id = self.next_txn_id.saturating_add(1);

        self.outbox.push(PendingMessage {
            room_id: validated_room,
            body: String::from(body),
            txn_id,
        });

        Ok(())
    }

    /// Build encrypted HTTP requests for all pending outbox messages.
    ///
    /// Each message is routed through the room's Megolm session and sent as an
    /// authenticated `m.room.encrypted` payload — the outbox never sends plaintext
    /// `m.room.message` (audit #370). Returns a list of `(request, txn_id)`
    /// results; the caller sends each and calls [`confirm_sent`] on success, or
    /// leaves the message in the outbox for the next flush cycle.
    ///
    /// # Errors
    ///
    /// Each element carries the per-message encryption/build result. A failed
    /// encryption yields an `Err` for that message without dropping the others.
    pub(crate) fn flush_outbox(&mut self) -> Vec<Result<(HttpRequest, u32), MatrixError>> {
        // WHY per-message clone instead of cloning the whole outbox up
        // front: build_megolm_request needs `&mut self` (it may create an
        // outbound Megolm session), which cannot coexist with a borrow
        // into self.outbox -- cloning the entire outbox before the loop
        // held two full copies of every pending message's body/room_id
        // simultaneously (doubled peak heap). Cloning only the current
        // message's (room_id, body, txn_id) per iteration keeps
        // self.outbox itself untouched -- still required so an
        // unconfirmed message survives to the next flush_outbox call
        // (confirm_sent is the only thing that removes one) -- while peak
        // heap is now the outbox's size plus one message, not two full
        // outboxes.
        let mut results = Vec::with_capacity(self.outbox.len());

        for i in 0..self.outbox.len() {
            let room_id = self.outbox[i].room_id.clone();
            let body = self.outbox[i].body.clone();
            let txn_id = self.outbox[i].txn_id;

            let result = self
                .build_megolm_request(&room_id, &body, txn_id)
                .map(|req| (req, txn_id));
            results.push(result);
        }

        results
    }

    // -----------------------------------------------------------------------
    // Join room
    // -----------------------------------------------------------------------

    /// Build a join-room HTTP request.
    ///
    /// Uses POST `/_matrix/client/v3/join/{roomId}`.
    ///
    /// # Errors
    ///
    /// Returns [`MatrixError::InvalidId`] if `room_id` is not a well-formed
    /// Matrix room ID (#373: prevents CRLF/path injection via the join path).
    pub(crate) fn build_join_request(&self, room_id: &str) -> Result<HttpRequest, MatrixError> {
        let validated_room = MatrixRoomId::new(room_id)?;

        let mut path = String::from(API_PREFIX);
        path.push_str("/join/");
        path.push_str(&validated_room);

        let mut req = http_client::post_json(&self.homeserver, &path, b"{}");
        http_client::with_auth(&mut req, &self.access_token);
        Ok(req)
    }

    /// Process a join-room HTTP response.
    ///
    /// On success, adds the room to the tracked room list if not already
    /// present.
    ///
    /// # Errors
    ///
    /// Returns [`MatrixError::ServerError`] on non-2xx responses.
    /// Returns [`MatrixError::RoomCapacityReached`] if the room list is full.
    pub(crate) fn process_join_response(
        &mut self,
        room_id: &str,
        response: &HttpResponse,
    ) -> Result<(), MatrixError> {
        if !response.is_success() {
            return Err(parse_error_response(response));
        }

        // Add room if not already tracked.
        if self.find_room(room_id).is_none() {
            if self.rooms.len() >= MAX_ROOMS {
                return Err(MatrixError::RoomCapacityReached);
            }
            self.rooms
                .push(Room::new(room_id, String::from(room_id), false)?);
        }

        Ok(())
    }

    /// Join a room (build request + queue join). The caller handles transport.
    ///
    /// Returns the built HTTP request.
    ///
    /// # Errors
    ///
    /// Returns [`MatrixError::InvalidId`] if `room_id` is not a well-formed
    /// Matrix room ID.
    pub(crate) fn join_room(&self, room_id: &str) -> Result<HttpRequest, MatrixError> {
        self.build_join_request(room_id)
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Find a room by ID in the tracked rooms list.
    fn find_room(&self, room_id: &str) -> Option<&Room> {
        self.rooms.iter().find(|r| r.room_id == room_id)
    }

    /// Find the index of a room by ID, or create it if it does not exist.
    ///
    /// # Errors
    ///
    /// Returns [`MatrixError::RoomCapacityReached`] if the room list
    /// is at capacity and the room is not already tracked.
    fn find_or_create_room(&mut self, room_id: &str) -> Result<usize, MatrixError> {
        if let Some(idx) = self.rooms.iter().position(|r| r.room_id == room_id) {
            return Ok(idx);
        }
        if self.rooms.len() >= MAX_ROOMS {
            return Err(MatrixError::RoomCapacityReached);
        }
        self.rooms
            .push(Room::new(room_id, String::from(room_id), false)?);
        Ok(self.rooms.len() - 1)
    }
}

impl fmt::Display for MatrixClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MatrixClient({} on {}, {} rooms, {} pending)",
            self.user_id,
            self.homeserver,
            self.rooms.len(),
            self.outbox.len(),
        )
    }
}

// ---------------------------------------------------------------------------
// JSON helpers
// ---------------------------------------------------------------------------

/// Build the JSON body for an `m.room.message` event.
///
/// ```json
/// {"msgtype":"m.text","body":"hello"}
/// ```
fn build_message_body(body: &str) -> String {
    let mut w = JsonWriter::new();
    w.object_start();
    w.key("msgtype");
    w.string_value("m.text");
    w.key("body");
    w.string_value(body);
    w.end();
    w.finish()
}

/// Build the JSON body for an `m.room.encrypted` event.
///
/// The ciphertext and the Megolm session ID are hex-encoded alongside the
/// algorithm identifier. The `session_id` lets the receiver select the inbound
/// Megolm session to decrypt with.
///
/// ```json
/// {"algorithm":"m.megolm.v1.aes-sha2","ciphertext":"<hex>","session_id":"<hex>"}
/// ```
fn build_encrypted_body(ciphertext: &[u8], session_id: &[u8; 32]) -> String {
    let mut w = JsonWriter::new();
    w.object_start();
    w.key("algorithm");
    w.string_value("m.megolm.v1.aes-sha2");
    w.key("ciphertext");
    w.string_value(&hex_encode_bytes(ciphertext));
    w.key("session_id");
    w.string_value(&hex_encode_bytes(session_id));
    w.end();
    w.finish()
}

/// Encode a byte slice as lowercase hex string.
fn hex_encode_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// Extract timeline events from a room's sync data.
///
/// Navigates: `room_data.timeline.events` → `Vec<&JsonValue>`.
fn extract_timeline_events(room_data: &JsonValue) -> Vec<&JsonValue> {
    let timeline = match room_data.get("timeline") {
        Some(t) => t,
        None => return Vec::new(),
    };
    let events = match timeline.get("events") {
        Some(e) => e,
        None => return Vec::new(),
    };
    match events.as_array() {
        Some(arr) => arr.iter().collect(),
        None => Vec::new(),
    }
}

/// Parse a single timeline event JSON into a [`MatrixMessage`].
///
/// Returns `None` if the event is not an `m.room.message` or
/// `m.room.encrypted`, or is missing required fields.
///
/// Wave 3: encrypted events are decrypted using the provided
/// `MatrixCrypto` state if an inbound Megolm session is available.
/// Successfully decrypted messages have `encrypted: true` set to
/// indicate they were originally encrypted but are now readable.
fn parse_timeline_event(
    event: &JsonValue,
    room_id: &str,
    crypto: &MatrixCrypto,
) -> Option<MatrixMessage> {
    let event_type = event.get("type")?.as_str()?;

    let encrypted = event_type == "m.room.encrypted";
    if event_type != "m.room.message" && !encrypted {
        return None;
    }

    let event_id = event.get("event_id")?.as_str()?;
    let sender = event.get("sender")?.as_str()?;
    let timestamp = event.get("origin_server_ts")?.as_i64()?;

    // WHY: body is String (not &str) because decrypted plaintext is an owned
    // Vec<u8> that doesn't outlive this function. The non-encrypted path
    // converts from &str → String for consistency.
    let body: String = if encrypted {
        // Wave 3: attempt decryption of m.room.encrypted events.
        // The content should contain ciphertext and session_id fields.
        let content = event.get("content")?;
        let ciphertext_hex = content.get("ciphertext").and_then(|v| v.as_str());
        let session_id_hex = content.get("session_id").and_then(|v| v.as_str());

        match (ciphertext_hex, session_id_hex) {
            (Some(ct_hex), Some(sid_hex)) => {
                // Decode hex ciphertext and session ID.
                let ct_bytes = hex_decode_bytes(ct_hex);
                let sid_bytes = hex_decode_32_bytes(sid_hex);

                match (ct_bytes, sid_bytes) {
                    (Some(ct), Some(sid)) => {
                        // Look up the inbound session.
                        match crypto.find_inbound_megolm(&sid) {
                            Some(session) => {
                                // #229: bind the session to the room the event
                                // actually arrived in (from the sync grouping,
                                // not the untrusted event body).
                                match matrix_crypto::decrypt_megolm(session, &ct, room_id) {
                                    Ok(plaintext) => match core::str::from_utf8(&plaintext) {
                                        Ok(s) => String::from(s),
                                        Err(_) => String::from("[decryption: invalid UTF-8]"),
                                    },
                                    Err(_) => String::from("[encrypted: decryption failed]"),
                                }
                            }
                            None => String::from("[encrypted: no session]"),
                        }
                    }
                    _ => String::from("[encrypted: invalid format]"),
                }
            }
            _ => String::from("[encrypted]"),
        }
    } else {
        let content = event.get("content")?;
        String::from(content.get("body")?.as_str()?)
    };

    Some(MatrixMessage {
        // WHY(#373): a malformed event id skips this event rather than
        // aborting the whole sync (parse_timeline_event returns Option).
        event_id: MatrixEventId::new(event_id).ok()?,
        sender: String::from(sender),
        body,
        timestamp: if timestamp >= 0 { timestamp as u64 } else { 0 },
        encrypted,
    })
}

/// Decode a hex string into a byte vector.
fn hex_decode_bytes(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let bytes = s.as_bytes();
    let mut result = Vec::with_capacity(s.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_nibble_val(bytes[i])?;
        let lo = hex_nibble_val(bytes[i + 1])?;
        result.push((hi << 4) | lo);
        i += 2;
    }
    Some(result)
}

/// Decode a 64-character hex string into a 32-byte array.
fn hex_decode_32_bytes(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let bytes = s.as_bytes();
    let mut result = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        let hi = hex_nibble_val(bytes[i * 2])?;
        let lo = hex_nibble_val(bytes[i * 2 + 1])?;
        result[i] = (hi << 4) | lo;
        i += 1;
    }
    Some(result)
}

/// Convert a hex ASCII byte to its 4-bit value.
fn hex_nibble_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Map a [`CryptoError`] into a client-side [`MatrixError::ServerError`] so
/// encryption failures never silently fall back to plaintext (audit #370).
fn crypto_error(e: CryptoError) -> MatrixError {
    MatrixError::ServerError {
        status: 0,
        errcode: String::from("M_CRYPTO_ERROR"),
        message: alloc::format!("{e}"),
    }
}

/// Parse a Matrix error response body into a [`MatrixError::ServerError`].
fn parse_error_response(response: &HttpResponse) -> MatrixError {
    let body_str = response.body_as_str();

    let (errcode, message) = body_str
        .and_then(|s| JsonParser::parse(s.as_bytes()).ok().map(|root| (s, root)))
        .map(|(_, root)| {
            let errcode = root
                .get("errcode")
                .and_then(|v| v.as_str())
                .unwrap_or("M_UNKNOWN");
            let message = root
                .get("error")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown error");
            (String::from(errcode), String::from(message))
        })
        .unwrap_or_else(|| {
            // WHY: preserve the server's raw error text instead of discarding
            // it -- a non-JSON error body previously became the generic
            // "non-JSON error response", losing the server's actual text.
            let message = match body_str {
                Some(s) if !s.is_empty() => {
                    let len = crate::heorte::utf8_truncate_len(s.as_bytes(), MAX_ERROR_BODY_LEN);
                    String::from(&s[..len])
                }
                _ => String::from("non-JSON error response"),
            };
            (String::from("M_UNKNOWN"), message)
        });

    MatrixError::ServerError {
        status: response.status,
        errcode,
        message,
    }
}

// ---------------------------------------------------------------------------
// Numeric formatting helpers (no_std, no format! for paths)
// ---------------------------------------------------------------------------

/// Append a u64 value as decimal digits to a string.
fn push_u64(s: &mut String, mut val: u64) {
    if val == 0 {
        s.push('0');
        return;
    }
    let start = s.len();
    while val > 0 {
        let digit = (val % 10) as u8 + b'0';
        s.push(digit as char);
        val /= 10;
    }
    // Reverse the digits we just pushed.
    // SAFETY: we only pushed ASCII digits, so byte manipulation is safe.
    let bytes = unsafe { s.as_bytes_mut() };
    bytes[start..].reverse();
}

/// Append a u32 value as decimal digits to a string.
fn push_u32(s: &mut String, val: u32) {
    push_u64(s, u64::from(val));
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::*;

    /// Helper: build a minimal sync response JSON string.
    fn build_sync_response(
        next_batch: &str,
        room_id: &str,
        events: &[(&str, &str, &str, i64)], // (event_id, sender, body, ts)
    ) -> String {
        let mut w = JsonWriter::new();
        w.object_start();

        w.key("next_batch");
        w.string_value(next_batch);

        w.key("rooms");
        w.object_start();

        w.key("join");
        w.object_start();

        w.key(room_id);
        w.object_start();

        w.key("timeline");
        w.object_start();

        w.key("events");
        w.array_start();

        for (event_id, sender, body, ts) in events {
            w.object_start();
            w.key("type");
            w.string_value("m.room.message");
            w.key("event_id");
            w.string_value(event_id);
            w.key("sender");
            w.string_value(sender);
            w.key("origin_server_ts");
            w.number_value(*ts);
            w.key("content");
            w.object_start();
            w.key("msgtype");
            w.string_value("m.text");
            w.key("body");
            w.string_value(body);
            w.end(); // content
            w.end(); // event
        }

        w.end(); // events array
        w.end(); // timeline
        w.end(); // room
        w.end(); // join
        w.end(); // rooms
        w.end(); // root

        w.finish()
    }

    /// Helper: build a mock HTTP response with given status and body.
    fn mock_response(status: u16, body: &str) -> HttpResponse {
        HttpResponse {
            status,
            headers: Vec::new(),
            body: body.as_bytes().to_vec(),
            // NOTE: synthetic mock has no raw wire bytes to derive a real
            // consumed length from; total_bytes() is not exercised via
            // this helper (see the total_bytes() tests in http_client.rs).
            consumed: 0,
        }
    }

    fn matrix_client_with_test_credentials() -> MatrixClient {
        crate::csprng::seed_for_test(&[0x42u8; 32], &[0u8; 8], 0);
        MatrixClient::new(
            "matrix.example.com",
            "@cody:matrix.example.com",
            "TESTDEVICE",
            "syt_test_token",
        )
        .expect("test csprng seeded")
    }

    #[test]
    fn new_client_has_empty_rooms() {
        let client = matrix_client_with_test_credentials();
        assert!(client.rooms().is_empty());
        assert!(client.outbox().is_empty());
        assert!(client.sync_token().is_none());
        assert_eq!(client.homeserver(), "matrix.example.com");
        assert_eq!(client.user_id(), "@cody:matrix.example.com");
        assert_eq!(client.device_id(), "TESTDEVICE");
    }

    #[test]
    fn sync_response_adds_messages() {
        let mut client = matrix_client_with_test_credentials();
        let room_id = "!test:matrix.example.com";

        let sync_json = build_sync_response(
            "batch_2",
            room_id,
            &[
                (
                    "$evt1",
                    "@alice:matrix.example.com",
                    "hello",
                    1_700_000_001_000,
                ),
                (
                    "$evt2",
                    "@bob:matrix.example.com",
                    "world",
                    1_700_000_002_000,
                ),
            ],
        );

        let response = mock_response(200, &sync_json);
        let result = client.sync(&response, 100);
        assert!(result.is_ok());

        // Verify sync token and room state after successful sync.
        assert_eq!(client.sync_token(), Some("batch_2"));
        assert_eq!(client.rooms().len(), 1);

        let room = &client.rooms()[0];
        assert_eq!(room.room_id, room_id);
        assert_eq!(room.messages.len(), 2);
        assert_eq!(room.messages[0].body, "hello");
        assert_eq!(room.messages[0].sender, "@alice:matrix.example.com");
        assert_eq!(room.messages[1].body, "world");
        assert_eq!(room.unread_count, 2);
    }

    #[test]
    fn mark_room_read_resets_unread_count() {
        let mut client = matrix_client_with_test_credentials();
        let room_id = "!test:matrix.example.com";

        let sync_json = build_sync_response(
            "batch_2",
            room_id,
            &[(
                "$evt1",
                "@alice:matrix.example.com",
                "hello",
                1_700_000_001_000,
            )],
        );
        let response = mock_response(200, &sync_json);
        let _ = client.sync(&response, 100);

        assert_eq!(client.rooms()[0].unread_count, 1);
        assert!(
            client.mark_room_read(room_id),
            "must find and reset a tracked room"
        );
        assert_eq!(client.rooms()[0].unread_count, 0);

        assert!(
            !client.mark_room_read("!nonexistent:example.com"),
            "marking an untracked room read must return false"
        );
    }

    #[test]
    fn sync_over_capacity_room_advances_token_and_signals_drop() {
        // #358: when a sync batch carries events for a room beyond MAX_ROOMS,
        // process_sync_response must NOT propagate an Err that leaves the
        // sync token advanced (a retry from next_batch would lose the whole
        // batch). It must process every storable room, advance the token,
        // return Ok, and signal the drop via rooms_over_capacity.
        let mut client = matrix_client_with_test_credentials();
        for i in 0..MAX_ROOMS {
            let rid = alloc::format!("!room{i}:matrix.example.com");
            assert!(
                client.find_or_create_room(&rid).is_ok(),
                "filling below MAX_ROOMS must succeed"
            );
        }
        assert_eq!(client.rooms().len(), MAX_ROOMS);

        let sync_json = build_sync_response(
            "batch_over",
            "!overflow:matrix.example.com",
            &[(
                "$e1",
                "@a:matrix.example.com",
                "would this be lost?",
                1_700_000_001_000,
            )],
        );
        let response = mock_response(200, &sync_json);
        let result = client.sync(&response, 100);

        assert!(
            result.is_ok(),
            "an over-capacity room must not fail the whole sync (#358)"
        );
        assert_eq!(
            client.sync_token(),
            Some("batch_over"),
            "the sync token must advance safely after a capacity skip"
        );
        let dropped = result.map(|r| r.rooms_over_capacity).unwrap_or(0);
        assert_eq!(
            dropped, 1,
            "the dropped over-capacity room must be signaled"
        );
        assert_eq!(
            client.rooms().len(),
            MAX_ROOMS,
            "no room may be added beyond MAX_ROOMS"
        );
    }

    #[test]
    fn send_message_builds_correct_request() {
        let mut client = matrix_client_with_test_credentials();
        let room_id = "!room:matrix.example.com";

        let result = client.build_send_request(room_id, "test message");
        assert!(result.is_ok());

        let (req, txn_id) = result.ok().unwrap_or_else(|| {
            // Fallback that never executes — satisfies no-unwrap lint.
            let r = HttpRequest::new(http_client::HttpMethod::Get, String::new(), String::new());
            (r, 0)
        });

        assert_eq!(txn_id, TXN_ID_START);

        // Verify the request path contains the room ID and txn ID.
        assert!(req.path.contains(room_id));
        assert!(req.path.contains("/send/m.room.message/"));

        // Verify authorization header is present.
        let has_auth = req
            .headers
            .iter()
            .any(|(k, v)| k == "Authorization" && v.contains("Bearer"));
        assert!(has_auth);

        // Verify body is JSON with msgtype and body.
        let body_bytes = req.body.as_ref().map(|b| b.as_slice()).unwrap_or(&[]);
        let body_str = core::str::from_utf8(body_bytes).unwrap_or("");
        assert!(body_str.contains("m.text"));
        assert!(body_str.contains("test message"));
    }

    #[test]
    fn outbox_queues_when_offline() {
        let mut client = matrix_client_with_test_credentials();

        let _ = client.queue_message("!room1:example.com", "msg1");
        let _ = client.queue_message("!room2:example.com", "msg2");

        assert_eq!(client.outbox().len(), 2);
        assert_eq!(client.outbox()[0].room_id, "!room1:example.com");
        assert_eq!(client.outbox()[0].body, "msg1");
        assert_eq!(client.outbox()[1].room_id, "!room2:example.com");
        assert_eq!(client.outbox()[1].body, "msg2");

        // Transaction IDs should be monotonically increasing.
        assert!(client.outbox()[0].txn_id < client.outbox()[1].txn_id);
    }

    #[test]
    fn queue_message_rejects_beyond_outbox_cap() {
        let mut client = matrix_client_with_test_credentials();

        for _ in 0..MAX_OUTBOX_MESSAGES {
            assert!(
                client.queue_message("!room:example.com", "msg").is_ok(),
                "queueing up to the cap must succeed"
            );
        }
        assert_eq!(client.outbox().len(), MAX_OUTBOX_MESSAGES);

        let result = client.queue_message("!overflow:example.com", "msg");
        assert_eq!(result, Err(MatrixError::OutboxFull));
        assert_eq!(
            client.outbox().len(),
            MAX_OUTBOX_MESSAGES,
            "outbox must not grow past the cap"
        );
    }

    #[test]
    fn send_message_rejects_when_outbox_full() {
        let mut client = matrix_client_with_test_credentials();
        for _ in 0..MAX_OUTBOX_MESSAGES {
            assert!(client.queue_message("!room:example.com", "msg").is_ok());
        }

        let result = client.send_message("!room:example.com", "one more");
        assert!(
            matches!(result, Err(MatrixError::OutboxFull)),
            "send_message must reject when the outbox is already full"
        );
    }

    #[test]
    fn flush_outbox_attempts_all() {
        let mut client = matrix_client_with_test_credentials();

        let _ = client.queue_message("!room1:example.com", "msg1");
        let _ = client.queue_message("!room2:example.com", "msg2");
        let _ = client.queue_message("!room3:example.com", "msg3");

        let results = client.flush_outbox();

        // All three should produce Ok results (request building succeeds).
        assert_eq!(results.len(), 3);
        for result in &results {
            assert!(result.is_ok());
        }

        // Outbox still contains messages (caller must confirm_sent).
        assert_eq!(client.outbox().len(), 3);

        // Confirm one and verify it is removed.
        let first_txn = client.outbox()[0].txn_id;
        client.confirm_sent(first_txn);
        assert_eq!(client.outbox().len(), 2);
    }

    #[test]
    fn flush_outbox_preserves_message_identity_per_iteration() {
        let mut client = matrix_client_with_test_credentials();

        let _ = client.queue_message("!room1:example.com", "alpha");
        let _ = client.queue_message("!room2:example.com", "beta");
        let _ = client.queue_message("!room3:example.com", "gamma");

        let results = client.flush_outbox();
        let txn_ids: Vec<u32> = results
            .iter()
            .filter_map(|r| r.as_ref().ok().map(|(_, txn_id)| *txn_id))
            .collect();
        let outbox_txn_ids: Vec<u32> = client.outbox().iter().map(|m| m.txn_id).collect();

        assert_eq!(
            txn_ids, outbox_txn_ids,
            "each flush_outbox result must correspond to the outbox message at the same index, not a stale/cloned snapshot"
        );
    }

    #[test]
    fn build_encrypted_send_request_produces_megolm_encrypted_request() {
        // #377: build_encrypted_send_request had zero direct test coverage --
        // only the underlying build_megolm_request was exercised indirectly
        // via flush_outbox_attempts_all. Cover the public entry point itself.
        let mut client = matrix_client_with_test_credentials();
        let room_id = "!enc-room:matrix.example.com";

        let result = client.build_encrypted_send_request(room_id, "secret message");
        assert!(result.is_ok(), "encrypted send request build must succeed");

        let (req, txn_id) = result.ok().unwrap_or_else(|| {
            // Fallback that never executes -- satisfies no-unwrap lint.
            let r = HttpRequest::new(http_client::HttpMethod::Get, String::new(), String::new());
            (r, 0)
        });

        assert_eq!(txn_id, TXN_ID_START);
        assert!(req.path.contains(room_id));
        assert!(
            req.path.contains("/send/m.room.encrypted/"),
            "encrypted send must PUT to the m.room.encrypted path, got {}",
            req.path
        );

        let body_bytes = req.body.as_ref().map(|b| b.as_slice()).unwrap_or(&[]);
        let body_str = core::str::from_utf8(body_bytes).unwrap_or("");
        assert!(
            body_str.contains("\"ciphertext\""),
            "encrypted body must carry a ciphertext field, got {body_str}"
        );
        assert!(
            body_str.contains("m.megolm.v1.aes-sha2"),
            "encrypted body must declare the Megolm algorithm"
        );
        assert!(
            !body_str.contains("secret message"),
            "the plaintext body must never appear verbatim in the encrypted request"
        );
    }

    #[test]
    fn build_encrypted_send_request_creates_outbound_session_when_none_exists() {
        // #377: the first encrypted send for a room must auto-create an
        // outbound Megolm session; a second send for the same room must
        // reuse it rather than creating another.
        let mut client = matrix_client_with_test_credentials();
        let room_id = "!fresh-room:matrix.example.com";

        assert!(
            client.crypto().find_outbound_megolm(room_id).is_none(),
            "no outbound session should exist before the first encrypted send"
        );

        assert!(
            client
                .build_encrypted_send_request(room_id, "first")
                .is_ok()
        );
        let session_id_after_first = client
            .crypto()
            .find_outbound_megolm(room_id)
            .map(|s| s.session_id);
        assert!(
            session_id_after_first.is_some(),
            "an outbound session must exist after the first encrypted send"
        );

        assert!(
            client
                .build_encrypted_send_request(room_id, "second")
                .is_ok()
        );
        let session_id_after_second = client
            .crypto()
            .find_outbound_megolm(room_id)
            .map(|s| s.session_id);
        assert_eq!(
            session_id_after_first, session_id_after_second,
            "a second encrypted send for the same room must reuse the existing session"
        );
    }

    #[test]
    fn build_encrypted_send_request_propagates_crypto_failure_without_panicking() {
        // #377: an empty body drives encrypt_megolm's CryptoError::EmptyPlaintext
        // path. build_encrypted_send_request must surface it as an Err, not
        // panic and not silently fall back to plaintext (audit #370).
        let mut client = matrix_client_with_test_credentials();
        let room_id = "!empty-body-room:matrix.example.com";

        let result = client.build_encrypted_send_request(room_id, "");
        assert!(
            matches!(result, Err(MatrixError::ServerError { .. })),
            "empty-plaintext crypto failure must surface as MatrixError::ServerError, got {result:?}"
        );
    }

    #[test]
    fn should_sync_respects_interval() {
        let mut client = matrix_client_with_test_credentials();

        // Default active mode: always sync.
        assert!(client.should_sync(0));
        assert!(client.should_sync(100));

        // Set idle interval (60 s = 6000 ticks at 10ms/tick).
        client.update_sync_cadence(SecurityMode::Daily, false);
        client.last_sync_tick = 1000;

        // Too early.
        assert!(!client.should_sync(2000));

        // Just right (1000 + 6000 = 7000).
        assert!(client.should_sync(7000));

        // Well past due.
        assert!(client.should_sync(10_000));

        // Sentinel mode: sync disabled.
        client.update_sync_cadence(SecurityMode::Sentinel, true);
        assert!(!client.should_sync(u64::MAX - 1));

        // Panic mode: sync disabled.
        client.update_sync_cadence(SecurityMode::Panic, false);
        assert!(!client.should_sync(u64::MAX - 1));

        // Back to daily active: sync enabled.
        client.update_sync_cadence(SecurityMode::Daily, true);
        assert!(client.should_sync(0));
    }

    #[test]
    fn room_messages_returns_correct_room() {
        let mut client = matrix_client_with_test_credentials();

        let room1 = "!room1:example.com";
        let room2 = "!room2:example.com";

        // Sync with two rooms.
        let mut w = JsonWriter::new();
        w.object_start();
        w.key("next_batch");
        w.string_value("batch_1");
        w.key("rooms");
        w.object_start();
        w.key("join");
        w.object_start();

        // Room 1 with 1 message.
        w.key(room1);
        w.object_start();
        w.key("timeline");
        w.object_start();
        w.key("events");
        w.array_start();
        w.object_start();
        w.key("type");
        w.string_value("m.room.message");
        w.key("event_id");
        w.string_value("$r1e1");
        w.key("sender");
        w.string_value("@alice:example.com");
        w.key("origin_server_ts");
        w.number_value(1000);
        w.key("content");
        w.object_start();
        w.key("msgtype");
        w.string_value("m.text");
        w.key("body");
        w.string_value("room1 msg");
        w.end(); // content
        w.end(); // event
        w.end(); // events
        w.end(); // timeline
        w.end(); // room1

        // Room 2 with 1 message.
        w.key(room2);
        w.object_start();
        w.key("timeline");
        w.object_start();
        w.key("events");
        w.array_start();
        w.object_start();
        w.key("type");
        w.string_value("m.room.message");
        w.key("event_id");
        w.string_value("$r2e1");
        w.key("sender");
        w.string_value("@bob:example.com");
        w.key("origin_server_ts");
        w.number_value(2000);
        w.key("content");
        w.object_start();
        w.key("msgtype");
        w.string_value("m.text");
        w.key("body");
        w.string_value("room2 msg");
        w.end(); // content
        w.end(); // event
        w.end(); // events
        w.end(); // timeline
        w.end(); // room2

        w.end(); // join
        w.end(); // rooms
        w.end(); // root

        let response = mock_response(200, &w.finish());
        let sync_result = client.sync(&response, 0);
        assert!(sync_result.is_ok());

        // Verify room_messages returns the correct room.
        let r1_msgs = client.room_messages(room1);
        assert!(r1_msgs.is_some());
        let r1_msgs = r1_msgs.unwrap_or(&[]);
        assert_eq!(r1_msgs.len(), 1);
        assert_eq!(r1_msgs[0].body, "room1 msg");

        let r2_msgs = client.room_messages(room2);
        assert!(r2_msgs.is_some());
        let r2_msgs = r2_msgs.unwrap_or(&[]);
        assert_eq!(r2_msgs.len(), 1);
        assert_eq!(r2_msgs[0].body, "room2 msg");

        // Non-existent room returns None.
        assert!(client.room_messages("!nope:example.com").is_none());
    }

    #[test]
    fn join_room_builds_correct_request() {
        let client = matrix_client_with_test_credentials();
        let room_id = "!target:matrix.example.com";

        let result = client.build_join_request(room_id);
        assert!(result.is_ok());
        let req = result.ok().unwrap_or_else(|| {
            // Fallback that never executes -- satisfies no-unwrap lint.
            HttpRequest::new(http_client::HttpMethod::Get, String::new(), String::new())
        });

        // Verify path.
        assert!(req.path.contains("/join/"));
        assert!(req.path.contains(room_id));

        // Verify auth header.
        let has_auth = req
            .headers
            .iter()
            .any(|(k, v)| k == "Authorization" && v.contains("Bearer"));
        assert!(has_auth);
    }

    #[test]
    fn join_room_rejects_crlf_injected_room_id() {
        // #373-class: build_join_request must reject a room_id carrying a
        // CRLF/control byte before it reaches the HTTP request path.
        let client = matrix_client_with_test_credentials();
        let malicious = "!room:example.com\r\nX-Injected: evil";

        let result = client.build_join_request(malicious);
        assert!(result.is_err());
    }

    #[test]
    fn join_room_adds_to_room_list() {
        let mut client = matrix_client_with_test_credentials();
        let room_id = "!newroom:example.com";

        assert!(client.rooms().is_empty());

        let response = mock_response(200, "{\"room_id\":\"!newroom:example.com\"}");
        let result = client.process_join_response(room_id, &response);
        assert!(result.is_ok());

        assert_eq!(client.rooms().len(), 1);
        assert_eq!(client.rooms()[0].room_id, room_id);

        // Joining the same room again should not duplicate.
        let result = client.process_join_response(room_id, &response);
        assert!(result.is_ok());
        assert_eq!(client.rooms().len(), 1);
    }

    #[test]
    fn process_join_response_rejects_beyond_max_rooms() {
        let mut client = matrix_client_with_test_credentials();
        let response = mock_response(200, "{}");

        for i in 0..MAX_ROOMS {
            let mut room_id = String::from("!room");
            push_u32(&mut room_id, i as u32);
            room_id.push_str(":example.com");
            let result = client.process_join_response(&room_id, &response);
            assert!(result.is_ok());
        }
        assert_eq!(client.rooms().len(), MAX_ROOMS);

        let result = client.process_join_response("!overflow:example.com", &response);
        assert_eq!(result.err(), Some(MatrixError::RoomCapacityReached));
        assert_eq!(client.rooms().len(), MAX_ROOMS);
    }

    #[test]
    fn server_error_parsed_correctly() {
        let mut client = matrix_client_with_test_credentials();

        let error_body = r#"{"errcode":"M_FORBIDDEN","error":"You are not allowed"}"#;
        let response = mock_response(403, error_body);

        let result = client.sync(&response, 0);
        assert!(result.is_err());

        match result {
            Err(MatrixError::ServerError {
                status,
                errcode,
                message,
            }) => {
                assert_eq!(status, 403);
                assert_eq!(errcode, "M_FORBIDDEN");
                assert_eq!(message, "You are not allowed");
            }
            other => {
                // Use assert! to avoid panic! lint.
                assert!(false, "expected ServerError, got {other:?}");
            }
        }
    }

    #[test]
    fn parse_error_response_preserves_non_json_body_text() {
        let response = mock_response(502, "upstream timeout: gateway unavailable");
        let err = parse_error_response(&response);
        match err {
            MatrixError::ServerError { message, .. } => {
                assert!(
                    message.contains("upstream timeout"),
                    "raw non-JSON body text must be preserved, got: {message}"
                );
            }
            other => assert!(false, "expected ServerError, got {other:?}"),
        }
    }

    #[test]
    fn parse_error_response_truncates_oversized_non_json_body() {
        let huge_body = "x".repeat(MAX_ERROR_BODY_LEN * 2);
        let response = mock_response(500, &huge_body);
        let err = parse_error_response(&response);
        match err {
            MatrixError::ServerError { message, .. } => {
                assert!(
                    message.len() <= MAX_ERROR_BODY_LEN,
                    "surfaced error body must be bounded, got {} bytes",
                    message.len()
                );
            }
            other => assert!(false, "expected ServerError, got {other:?}"),
        }
    }

    #[test]
    fn sync_disabled_in_sentinel_mode() {
        let mut client = matrix_client_with_test_credentials();
        client.update_sync_cadence(SecurityMode::Sentinel, false);

        let result = client.build_sync_request();
        assert!(result.is_err());
        assert_eq!(result.err(), Some(MatrixError::SyncDisabled));
    }

    #[test]
    fn build_sync_request_rejects_crlf_in_sync_token() {
        // A malicious homeserver's next_batch must not be able to inject a
        // CRLF/space/control byte into the next /sync request line.
        let mut client = matrix_client_with_test_credentials();
        let body = build_sync_response("evil\r\nX-Injected: 1", "!room:example.com", &[]);
        let response = mock_response(200, &body);

        let result = client.sync(&response, 0);
        assert!(result.is_ok());

        let result = client.build_sync_request();
        assert_eq!(result.err(), Some(MatrixError::MalformedSync));
    }

    #[test]
    fn process_send_response_extracts_event_id() {
        let client = matrix_client_with_test_credentials();

        let response = mock_response(200, r#"{"event_id":"$sent123"}"#);
        let result = client.process_send_response(&response);
        assert!(result.is_ok());
        assert_eq!(result.ok(), Some(String::from("$sent123")));
    }

    #[test]
    fn build_sync_request_includes_since_param_when_token_set() {
        let mut client = matrix_client_with_test_credentials();
        assert!(client.sync_token().is_none());

        let body = build_sync_response("tok_abc123", "!room:example.com", &[]);
        let response = mock_response(200, &body);
        let result = client.sync(&response, 0);
        assert!(result.is_ok());
        assert_eq!(client.sync_token(), Some("tok_abc123"));

        let result = client.build_sync_request();
        assert!(result.is_ok());
        let req = result.ok().unwrap_or_else(|| {
            HttpRequest::new(http_client::HttpMethod::Get, String::new(), String::new())
        });
        assert!(req.path.contains("&since=tok_abc123"));
    }

    #[test]
    fn push_u64_formatting() {
        let mut s = String::new();
        push_u64(&mut s, 0);
        assert_eq!(s, "0");

        let mut s = String::new();
        push_u64(&mut s, 30000);
        assert_eq!(s, "30000");

        let mut s = String::new();
        push_u64(&mut s, 1);
        assert_eq!(s, "1");

        let mut s = String::new();
        push_u64(&mut s, 999_999_999);
        assert_eq!(s, "999999999");
    }

    #[test]
    fn update_sync_cadence_modes() {
        let mut client = matrix_client_with_test_credentials();

        // Daily + screen on → continuous.
        client.update_sync_cadence(SecurityMode::Daily, true);
        assert_eq!(client.sync_interval_ms, SYNC_INTERVAL_ACTIVE_MS);

        // Daily + screen off → 60s.
        client.update_sync_cadence(SecurityMode::Daily, false);
        assert_eq!(client.sync_interval_ms, SYNC_INTERVAL_IDLE_MS);

        // Sentinel → disabled.
        client.update_sync_cadence(SecurityMode::Sentinel, true);
        assert_eq!(client.sync_interval_ms, u64::MAX);

        // Panic → disabled.
        client.update_sync_cadence(SecurityMode::Panic, false);
        assert_eq!(client.sync_interval_ms, u64::MAX);
    }

    #[test]
    fn encrypted_event_shows_placeholder() {
        let mut client = matrix_client_with_test_credentials();
        let room_id = "!enc:example.com";

        // Build a sync response with an encrypted event.
        let mut w = JsonWriter::new();
        w.object_start();
        w.key("next_batch");
        w.string_value("batch_enc");
        w.key("rooms");
        w.object_start();
        w.key("join");
        w.object_start();
        w.key(room_id);
        w.object_start();
        w.key("timeline");
        w.object_start();
        w.key("events");
        w.array_start();
        w.object_start();
        w.key("type");
        w.string_value("m.room.encrypted");
        w.key("event_id");
        w.string_value("$enc1");
        w.key("sender");
        w.string_value("@secret:example.com");
        w.key("origin_server_ts");
        w.number_value(5000);
        w.key("content");
        w.object_start();
        w.key("algorithm");
        w.string_value("m.megolm.v1.aes-sha2");
        w.key("ciphertext");
        w.string_value("base64data");
        w.end(); // content
        w.end(); // event
        w.end(); // events
        w.end(); // timeline
        w.end(); // room
        w.end(); // join
        w.end(); // rooms
        w.end(); // root

        let response = mock_response(200, &w.finish());
        let result = client.sync(&response, 0);
        assert!(result.is_ok());

        let msgs = client.room_messages(room_id).unwrap_or(&[]);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].body, "[encrypted]");
        assert!(msgs[0].encrypted);
    }

    #[test]
    fn message_cache_evicts_oldest() {
        let mut room = Room::new("!evict:example.com", String::from("Test Room"), false)
            .expect("valid test room id");

        // Fill to capacity.
        for i in 0..MAX_MESSAGES_PER_ROOM {
            room.add_message(MatrixMessage {
                event_id: {
                    let mut id = String::from("$msg");
                    push_u32(&mut id, i as u32);
                    MatrixEventId::new(&id).expect("valid test event id")
                },
                sender: String::from("@test:example.com"),
                body: String::from("msg"),
                timestamp: i as u64,
                encrypted: false,
            });
        }
        assert_eq!(room.messages.len(), MAX_MESSAGES_PER_ROOM);

        // Add one more — oldest should be evicted.
        room.add_message(MatrixMessage {
            event_id: MatrixEventId::new("$new").expect("valid test event id"),
            sender: String::from("@test:example.com"),
            body: String::from("newest"),
            timestamp: MAX_MESSAGES_PER_ROOM as u64,
            encrypted: false,
        });

        assert_eq!(room.messages.len(), MAX_MESSAGES_PER_ROOM);
        // First message should now be $msg1 (0 was evicted).
        assert_eq!(room.messages[0].event_id, "$msg1");
        // Last message should be the new one.
        assert_eq!(room.messages[MAX_MESSAGES_PER_ROOM - 1].event_id, "$new");
    }

    #[test]
    fn hex_decode_bytes_decodes_valid_input() {
        assert_eq!(
            hex_decode_bytes("00ff10").as_deref(),
            Some(&[0x00u8, 0xff, 0x10][..])
        );
        assert_eq!(hex_decode_bytes("").as_deref(), Some(&[][..]));
    }

    #[test]
    fn hex_decode_bytes_rejects_odd_length() {
        assert_eq!(hex_decode_bytes("abc"), None);
    }

    #[test]
    fn hex_decode_bytes_rejects_non_hex_char() {
        assert_eq!(hex_decode_bytes("zz"), None);
    }

    #[test]
    fn hex_decode_32_bytes_decodes_valid_input() {
        let hex = "ab".repeat(32);
        assert_eq!(hex_decode_32_bytes(&hex), Some([0xabu8; 32]));
    }

    #[test]
    fn hex_decode_32_bytes_rejects_wrong_length() {
        assert_eq!(hex_decode_32_bytes("aabb"), None);
        assert_eq!(hex_decode_32_bytes(&"ab".repeat(33)), None);
    }

    #[test]
    fn hex_decode_32_bytes_rejects_non_hex_char() {
        let bad = alloc::format!("zz{}", "aa".repeat(31));
        assert_eq!(hex_decode_32_bytes(&bad), None);
    }
}
