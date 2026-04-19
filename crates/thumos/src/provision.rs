//! Matrix device provisioning via USB serial.
//!
//! Receives a [`ProvisionBundle`] from the host workstation over the USB ACM
//! serial gadget (see [`usb`]), deserializes it with postcard, verifies a
//! SHA-256 checksum, and provides the credentials for [`MatrixClient`]
//! initialization.
//!
//! ## Wire format
//!
//! ```text
//! [4-byte magic "THMS"][4-byte LE length][postcard-serialized ProvisionBundle][32-byte SHA-256]
//! ```
//!
//! The `length` field covers only the postcard payload (not magic, length, or
//! checksum). The SHA-256 covers magic + length + payload (everything before
//! the checksum).
//!
//! ## Provisioning flow
//!
//! 1. Device shows "WAITING FOR PROVISIONING" screen.
//! 2. menos-side tool pushes bundle over USB serial.
//! 3. Device receives, deserializes, verifies (SHA-256 checksum).
//! 4. Stores credentials to `/data/harmostes/` via LFS.
//! 5. Initializes [`MatrixClient`] with the provisioned credentials.
//! 6. Shows "PROVISIONED: @user:server" confirmation.
//!
//! [`usb`]: crate::usb
//! [`MatrixClient`]: crate::harmostes::MatrixClient

// WHY: Provisioning module created in Phase 09 Wave 4, full integration with
// MatrixClient pending in Wave 5.
#![expect(
    dead_code,
    reason = "Provisioning module created in Phase 09 Wave 4, MatrixClient integration pending"
)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use serde::{Deserialize, Serialize};

use crate::security;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Magic header identifying a Thumos provisioning bundle.
const PROVISION_MAGIC: [u8; 4] = *b"THMS";

/// Size of the fixed header: 4-byte magic + 4-byte length.
const HEADER_SIZE: usize = 8;

/// SHA-256 digest length (bytes).
const SHA256_LEN: usize = 32;

/// Maximum payload size (64 KiB). Prevents unbounded allocation from
/// malformed length fields.
const MAX_PAYLOAD_SIZE: usize = 65_536;

/// Receive buffer capacity. Must hold header + max payload + checksum.
const RECV_BUF_CAPACITY: usize = HEADER_SIZE + MAX_PAYLOAD_SIZE + SHA256_LEN;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors during provisioning.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
#[non_exhaustive]
pub enum ProvisionError {
    /// The magic header does not match "THMS".
    InvalidMagic,
    /// The payload length exceeds [`MAX_PAYLOAD_SIZE`].
    PayloadTooLarge,
    /// The SHA-256 checksum did not match.
    ChecksumMismatch,
    /// Postcard deserialization failed.
    DeserializeError,
    /// Not enough data received yet (still accumulating).
    Incomplete,
    /// The provisioner is in an error state and must be reset.
    PreviousError,
}

impl fmt::Display for ProvisionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMagic => write!(f, "invalid provision magic header"),
            Self::PayloadTooLarge => write!(f, "provision payload exceeds maximum size"),
            Self::ChecksumMismatch => write!(f, "provision checksum mismatch"),
            Self::DeserializeError => write!(f, "provision bundle deserialization failed"),
            Self::Incomplete => write!(f, "provision data incomplete"),
            Self::PreviousError => write!(f, "provisioner in error state, reset required"),
        }
    }
}

// ---------------------------------------------------------------------------
// Provision state
// ---------------------------------------------------------------------------

/// Current state of the provisioning state machine.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
#[non_exhaustive]
pub enum ProvisionState {
    /// Listening for USB data.
    Waiting,
    /// Accumulating incoming bytes.
    Receiving,
    /// Checking signature/integrity.
    Verifying,
    /// Provisioning completed successfully.
    Complete,
    /// An error occurred.
    Error(ProvisionError),
}

impl fmt::Display for ProvisionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Waiting => write!(f, "waiting for provisioning data"),
            Self::Receiving => write!(f, "receiving provisioning data"),
            Self::Verifying => write!(f, "verifying provisioning bundle"),
            Self::Complete => write!(f, "provisioning complete"),
            Self::Error(e) => write!(f, "provisioning error: {e}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Provision bundle
// ---------------------------------------------------------------------------

/// Matrix device credentials received during USB provisioning.
///
/// Serialized with postcard (serde) for compact binary transport over
/// the USB serial link.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[must_use]
#[non_exhaustive]
pub struct ProvisionBundle {
    /// Matrix user ID (e.g., `@cody:matrix.example.com`).
    pub user_id: String,
    /// Device ID assigned during registration.
    pub device_id: String,
    /// Access token for Bearer auth.
    pub access_token: String,
    /// Homeserver hostname (e.g., `matrix.example.com`).
    pub homeserver: String,
    /// Ed25519 device signing key (32 bytes).
    pub ed25519_key: [u8; 32],
    /// Curve25519 device key exchange key (32 bytes).
    pub curve25519_key: [u8; 32],
    /// Cross-signing master key, if available.
    pub cross_signing_master: Option<[u8; 32]>,
}

impl fmt::Display for ProvisionBundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ProvisionBundle({} on {})",
            self.user_id, self.homeserver,
        )
    }
}

// ---------------------------------------------------------------------------
// Provisioner
// ---------------------------------------------------------------------------

/// USB provisioning receiver and verifier.
///
/// Accumulates bytes received from the USB serial gadget, then deserializes
/// and verifies the integrity of a [`ProvisionBundle`].
///
/// # Usage
///
/// ```ignore
/// let mut prov = Provisioner::new();
/// loop {
///     let chunk = usb.read_serial(&mut buf);
///     prov.receive_chunk(&buf[..chunk]);
///     if prov.is_complete() {
///         let bundle = prov.finalize().unwrap();
///         break;
///     }
/// }
/// ```
#[non_exhaustive]
pub(crate) struct Provisioner {
    /// Current state machine state.
    state: ProvisionState,
    /// Accumulated receive buffer.
    buffer: Vec<u8>,
    /// Parsed payload length from the header (set after header received).
    payload_len: Option<usize>,
    /// Successfully deserialized bundle (set after finalize).
    bundle: Option<ProvisionBundle>,
}

impl Provisioner {
    /// Create a new provisioner in the [`ProvisionState::Waiting`] state.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            state: ProvisionState::Waiting,
            buffer: Vec::new(),
            payload_len: None,
            bundle: None,
        }
    }

    /// Current provisioning state.
    #[must_use]
    pub(crate) fn state(&self) -> &ProvisionState {
        &self.state
    }

    /// Whether provisioning completed successfully.
    #[must_use]
    pub(crate) fn is_complete(&self) -> bool {
        self.state == ProvisionState::Complete
    }

    /// Reference to the provisioned bundle, if available.
    #[must_use]
    pub(crate) fn bundle(&self) -> Option<&ProvisionBundle> {
        self.bundle.as_ref()
    }

    /// Feed a chunk of data received from the USB serial interface.
    ///
    /// Returns the new state after processing. The caller should keep
    /// feeding data until the state is [`ProvisionState::Complete`] or
    /// [`ProvisionState::Error`].
    #[must_use]
    pub(crate) fn receive_chunk(&mut self, data: &[u8]) -> &ProvisionState {
        // Don't accept data in terminal states.
        match &self.state {
            ProvisionState::Complete | ProvisionState::Error(_) => return &self.state,
            _ => {}
        }

        // Transition from Waiting to Receiving on first data.
        if self.state == ProvisionState::Waiting && !data.is_empty() {
            self.state = ProvisionState::Receiving;
        }

        self.buffer.extend_from_slice(data);

        // Try to parse the header if we haven't yet.
        if self.payload_len.is_none() && self.buffer.len() >= HEADER_SIZE {
            // Validate magic.
            if self.buffer[..4] != PROVISION_MAGIC {
                self.state = ProvisionState::Error(ProvisionError::InvalidMagic);
                return &self.state;
            }

            // Parse payload length (little-endian u32).
            let len_bytes: [u8; 4] = [
                self.buffer[4],
                self.buffer[5],
                self.buffer[6],
                self.buffer[7],
            ];
            let payload_len = u32::from_le_bytes(len_bytes) as usize;

            if payload_len > MAX_PAYLOAD_SIZE {
                self.state = ProvisionState::Error(ProvisionError::PayloadTooLarge);
                return &self.state;
            }

            self.payload_len = Some(payload_len);
        }

        // Check if we have the complete message (header + payload + checksum).
        if let Some(payload_len) = self.payload_len {
            let total_len = HEADER_SIZE + payload_len + SHA256_LEN;
            if self.buffer.len() >= total_len {
                self.state = ProvisionState::Verifying;
                // Attempt finalization inline.
                match self.try_finalize(payload_len) {
                    Ok(bundle) => {
                        self.bundle = Some(bundle);
                        self.state = ProvisionState::Complete;
                    }
                    Err(e) => {
                        self.state = ProvisionState::Error(e);
                    }
                }
            }
        }

        &self.state
    }

    /// Finalize the provisioning: deserialize and verify the bundle.
    ///
    /// Returns the bundle if provisioning completed successfully. If the
    /// provisioner is not in the [`ProvisionState::Complete`] state, returns
    /// the appropriate error.
    pub(crate) fn finalize(&mut self) -> Result<ProvisionBundle, ProvisionError> {
        match &self.state {
            ProvisionState::Complete => {
                self.bundle.clone().ok_or(ProvisionError::Incomplete)
            }
            ProvisionState::Error(e) => Err(e.clone()),
            ProvisionState::Waiting | ProvisionState::Receiving => {
                Err(ProvisionError::Incomplete)
            }
            ProvisionState::Verifying => {
                // Should not happen — Verifying is transient and resolves in
                // receive_chunk. If we somehow get here, treat as incomplete.
                Err(ProvisionError::Incomplete)
            }
        }
    }

    /// Internal: attempt to deserialize and verify the accumulated buffer.
    fn try_finalize(&self, payload_len: usize) -> Result<ProvisionBundle, ProvisionError> {
        let checksum_start = HEADER_SIZE + payload_len;
        let data_region = &self.buffer[..checksum_start];
        let received_checksum = &self.buffer[checksum_start..checksum_start + SHA256_LEN];

        // Verify SHA-256 checksum over magic + length + payload.
        let computed = security::sha256(data_region);
        if computed != received_checksum {
            return Err(ProvisionError::ChecksumMismatch);
        }

        // Deserialize the postcard payload.
        let payload = &self.buffer[HEADER_SIZE..checksum_start];
        postcard::from_bytes(payload).map_err(|_| ProvisionError::DeserializeError)
    }

    /// Reset the provisioner to accept a new bundle.
    ///
    /// Clears all accumulated data and returns to the
    /// [`ProvisionState::Waiting`] state.
    pub(crate) fn reset(&mut self) {
        self.state = ProvisionState::Waiting;
        self.buffer.clear();
        self.payload_len = None;
        self.bundle = None;
    }
}

impl fmt::Display for Provisioner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Provisioner(state={}, buffered={} bytes)",
            self.state,
            self.buffer.len(),
        )
    }
}

// ---------------------------------------------------------------------------
// Bundle encoding (for test and menos-side tooling)
// ---------------------------------------------------------------------------

/// Encode a [`ProvisionBundle`] into the wire format for transmission.
///
/// Returns the complete byte sequence: magic + length + postcard payload +
/// SHA-256 checksum. Used by the menos-side provisioning tool and in tests.
pub(crate) fn encode_bundle(bundle: &ProvisionBundle) -> Result<Vec<u8>, ProvisionError> {
    let payload = postcard::to_allocvec(bundle).map_err(|_| ProvisionError::DeserializeError)?;

    if payload.len() > MAX_PAYLOAD_SIZE {
        return Err(ProvisionError::PayloadTooLarge);
    }

    let payload_len = payload.len() as u32;
    let mut wire = Vec::with_capacity(HEADER_SIZE + payload.len() + SHA256_LEN);

    // Magic.
    wire.extend_from_slice(&PROVISION_MAGIC);
    // Length (little-endian).
    wire.extend_from_slice(&payload_len.to_le_bytes());
    // Payload.
    wire.extend_from_slice(&payload);

    // SHA-256 checksum over everything so far.
    let checksum = security::sha256(&wire);
    wire.extend_from_slice(&checksum);

    Ok(wire)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a test bundle with deterministic data.
    fn provision_bundle_with_cross_signing() -> ProvisionBundle {
        ProvisionBundle {
            user_id: String::from("@cody:matrix.example.com"),
            device_id: String::from("THMSTESTDEV01"),
            access_token: String::from("syt_test_provision_token_1234"),
            homeserver: String::from("matrix.example.com"),
            ed25519_key: [0xAA; 32],
            curve25519_key: [0xBB; 32],
            cross_signing_master: Some([0xCC; 32]),
        }
    }

    /// Create a test bundle without cross-signing key.
    fn provision_bundle_without_cross_signing() -> ProvisionBundle {
        ProvisionBundle {
            user_id: String::from("@test:example.org"),
            device_id: String::from("DEVNOCSIGN"),
            access_token: String::from("syt_no_cross_sign"),
            homeserver: String::from("example.org"),
            ed25519_key: [0x11; 32],
            curve25519_key: [0x22; 32],
            cross_signing_master: None,
        }
    }

    // -----------------------------------------------------------------------
    // Serialization round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn bundle_round_trip() {
        let bundle = provision_bundle_with_cross_signing();
        let wire = encode_bundle(&bundle).ok();
        assert!(wire.is_some());
        let wire = wire.as_ref().map(Vec::as_slice).unwrap_or_default();

        let mut prov = Provisioner::new();
        let state = prov.receive_chunk(wire);
        assert_eq!(*state, ProvisionState::Complete);

        let result = prov.finalize();
        assert!(result.is_ok());
        let decoded = result.unwrap_or_else(|_| provision_bundle_with_cross_signing());
        assert_eq!(decoded, bundle);
    }

    #[test]
    fn bundle_round_trip_no_cross_signing() {
        let bundle = provision_bundle_without_cross_signing();
        let wire = encode_bundle(&bundle).ok();
        assert!(wire.is_some());
        let wire = wire.as_ref().map(Vec::as_slice).unwrap_or_default();

        let mut prov = Provisioner::new();
        prov.receive_chunk(wire);
        assert!(prov.is_complete());

        let decoded = prov.finalize().unwrap_or_else(|_| provision_bundle_with_cross_signing());
        assert_eq!(decoded, bundle);
    }

    // -----------------------------------------------------------------------
    // Magic header validation
    // -----------------------------------------------------------------------

    #[test]
    fn invalid_magic_rejected() {
        let mut wire = encode_bundle(&provision_bundle_with_cross_signing())
            .unwrap_or_else(|_| Vec::new());
        assert!(!wire.is_empty());
        // Corrupt magic.
        wire[0] = b'X';

        let mut prov = Provisioner::new();
        let state = prov.receive_chunk(&wire);
        assert_eq!(*state, ProvisionState::Error(ProvisionError::InvalidMagic));
    }

    #[test]
    fn wrong_magic_bytes_rejected() {
        let mut data = Vec::new();
        data.extend_from_slice(b"NOPE");
        data.extend_from_slice(&10u32.to_le_bytes());
        data.extend_from_slice(&[0u8; 10]);
        data.extend_from_slice(&[0u8; 32]);

        let mut prov = Provisioner::new();
        let state = prov.receive_chunk(&data);
        assert_eq!(*state, ProvisionState::Error(ProvisionError::InvalidMagic));
    }

    // -----------------------------------------------------------------------
    // Checksum verification
    // -----------------------------------------------------------------------

    #[test]
    fn checksum_mismatch_rejected() {
        let mut wire = encode_bundle(&provision_bundle_with_cross_signing())
            .unwrap_or_else(|_| Vec::new());
        assert!(!wire.is_empty());
        // Corrupt last byte of checksum.
        let last = wire.len() - 1;
        wire[last] ^= 0xFF;

        let mut prov = Provisioner::new();
        let state = prov.receive_chunk(&wire);
        assert_eq!(
            *state,
            ProvisionState::Error(ProvisionError::ChecksumMismatch)
        );
    }

    #[test]
    fn corrupted_payload_fails_checksum() {
        let mut wire = encode_bundle(&provision_bundle_with_cross_signing())
            .unwrap_or_else(|_| Vec::new());
        assert!(!wire.is_empty());
        // Corrupt a byte in the payload region.
        if wire.len() > HEADER_SIZE + 5 {
            wire[HEADER_SIZE + 5] ^= 0xFF;
        }

        let mut prov = Provisioner::new();
        let state = prov.receive_chunk(&wire);
        // Should be either ChecksumMismatch or DeserializeError depending on
        // whether the checksum is checked first.
        assert!(matches!(
            state,
            ProvisionState::Error(ProvisionError::ChecksumMismatch)
                | ProvisionState::Error(ProvisionError::DeserializeError)
        ));
    }

    // -----------------------------------------------------------------------
    // Corrupt data rejected
    // -----------------------------------------------------------------------

    #[test]
    fn truncated_data_stays_receiving() {
        let wire = encode_bundle(&provision_bundle_with_cross_signing()).ok();
        assert!(wire.is_some());
        let wire = wire.as_ref().map(Vec::as_slice).unwrap_or_default();
        // Send only half the data.
        let half = wire.len() / 2;

        let mut prov = Provisioner::new();
        let state = prov.receive_chunk(&wire[..half]);
        assert_eq!(*state, ProvisionState::Receiving);

        // Finalize should fail with Incomplete.
        let result = prov.finalize();
        assert_eq!(result, Err(ProvisionError::Incomplete));
    }

    #[test]
    fn payload_too_large_rejected() {
        let mut data = Vec::new();
        data.extend_from_slice(&PROVISION_MAGIC);
        // Length exceeding MAX_PAYLOAD_SIZE.
        let oversized = (MAX_PAYLOAD_SIZE as u32) + 1;
        data.extend_from_slice(&oversized.to_le_bytes());

        let mut prov = Provisioner::new();
        let state = prov.receive_chunk(&data);
        assert_eq!(
            *state,
            ProvisionState::Error(ProvisionError::PayloadTooLarge)
        );
    }

    #[test]
    fn empty_data_stays_waiting() {
        let mut prov = Provisioner::new();
        let state = prov.receive_chunk(&[]);
        assert_eq!(*state, ProvisionState::Waiting);
    }

    // -----------------------------------------------------------------------
    // Chunk accumulation
    // -----------------------------------------------------------------------

    #[test]
    fn multi_chunk_accumulation() {
        let wire = encode_bundle(&provision_bundle_with_cross_signing()).ok();
        assert!(wire.is_some());
        let wire = wire.as_ref().map(Vec::as_slice).unwrap_or_default();

        let mut prov = Provisioner::new();

        // Feed one byte at a time for the first 20 bytes.
        let chunk_boundary = 20.min(wire.len());
        for &byte in &wire[..chunk_boundary] {
            prov.receive_chunk(&[byte]);
        }

        // Feed the rest in larger chunks.
        let remaining = &wire[chunk_boundary..];
        let mid = remaining.len() / 2;
        if mid > 0 {
            let state = prov.receive_chunk(&remaining[..mid]);
            // Should still be Receiving (not yet complete).
            assert!(
                *state == ProvisionState::Receiving || *state == ProvisionState::Complete,
                "unexpected state after partial data: {state}"
            );
        }

        if mid < remaining.len() {
            prov.receive_chunk(&remaining[mid..]);
        }

        assert!(prov.is_complete());
        let decoded = prov.finalize().unwrap_or_else(|_| provision_bundle_without_cross_signing());
        assert_eq!(decoded, provision_bundle_with_cross_signing());
    }

    #[test]
    fn byte_at_a_time_accumulation() {
        let wire = encode_bundle(&provision_bundle_with_cross_signing()).ok();
        assert!(wire.is_some());
        let wire = wire.as_ref().map(Vec::as_slice).unwrap_or_default();

        let mut prov = Provisioner::new();

        // Feed every single byte individually.
        for &byte in wire {
            prov.receive_chunk(&[byte]);
        }

        assert!(prov.is_complete());
        let decoded = prov.finalize().unwrap_or_else(|_| provision_bundle_without_cross_signing());
        assert_eq!(decoded, provision_bundle_with_cross_signing());
    }

    // -----------------------------------------------------------------------
    // State transitions
    // -----------------------------------------------------------------------

    #[test]
    fn state_transitions_waiting_to_receiving() {
        let mut prov = Provisioner::new();
        assert_eq!(*prov.state(), ProvisionState::Waiting);

        prov.receive_chunk(&[0x01]);
        // Not valid magic, but should transition to Receiving first, then
        // remain Receiving until header is complete.
        assert!(
            *prov.state() == ProvisionState::Receiving
                || matches!(prov.state(), ProvisionState::Error(_))
        );
    }

    #[test]
    fn complete_state_ignores_further_data() {
        let wire = encode_bundle(&provision_bundle_with_cross_signing()).ok();
        assert!(wire.is_some());
        let wire = wire.as_ref().map(Vec::as_slice).unwrap_or_default();

        let mut prov = Provisioner::new();
        prov.receive_chunk(wire);
        assert!(prov.is_complete());

        // Sending more data should not change state.
        let state = prov.receive_chunk(b"extra garbage");
        assert_eq!(*state, ProvisionState::Complete);
    }

    #[test]
    fn error_state_ignores_further_data() {
        let mut prov = Provisioner::new();
        prov.receive_chunk(b"BAD_MAGIC_HEADER_DATA_PLUS_PADDING__");
        assert!(matches!(prov.state(), ProvisionState::Error(_)));

        // Sending more data should not change state.
        let state = prov.receive_chunk(b"more data");
        assert!(matches!(state, ProvisionState::Error(_)));
    }

    // -----------------------------------------------------------------------
    // Reset
    // -----------------------------------------------------------------------

    #[test]
    fn reset_clears_state() {
        let wire = encode_bundle(&provision_bundle_with_cross_signing()).ok();
        assert!(wire.is_some());
        let wire = wire.as_ref().map(Vec::as_slice).unwrap_or_default();

        let mut prov = Provisioner::new();
        prov.receive_chunk(wire);
        assert!(prov.is_complete());

        prov.reset();
        assert_eq!(*prov.state(), ProvisionState::Waiting);
        assert!(prov.bundle().is_none());
        assert!(!prov.is_complete());
    }

    #[test]
    fn reset_after_error_allows_retry() {
        let mut prov = Provisioner::new();
        prov.receive_chunk(b"BAD_MAGIC_HEADER_DATA_PLUS_PADDING__");
        assert!(matches!(prov.state(), ProvisionState::Error(_)));

        prov.reset();
        assert_eq!(*prov.state(), ProvisionState::Waiting);

        // Now send valid data.
        let wire = encode_bundle(&provision_bundle_with_cross_signing()).ok();
        assert!(wire.is_some());
        let wire = wire.as_ref().map(Vec::as_slice).unwrap_or_default();
        prov.receive_chunk(wire);
        assert!(prov.is_complete());
    }

    // -----------------------------------------------------------------------
    // Display impls
    // -----------------------------------------------------------------------

    #[test]
    fn display_provision_error() {
        let err = ProvisionError::InvalidMagic;
        let s = alloc::format!("{err}");
        assert!(s.contains("magic"));
    }

    #[test]
    fn display_provision_state() {
        let state = ProvisionState::Waiting;
        let s = alloc::format!("{state}");
        assert!(s.contains("waiting"));
    }

    #[test]
    fn display_provision_bundle() {
        let bundle = provision_bundle_with_cross_signing();
        let s = alloc::format!("{bundle}");
        assert!(s.contains("@cody:matrix.example.com"));
        assert!(s.contains("matrix.example.com"));
    }

    #[test]
    fn display_provisioner() {
        let prov = Provisioner::new();
        let s = alloc::format!("{prov}");
        assert!(s.contains("Provisioner"));
        assert!(s.contains("0 bytes"));
    }

    // -----------------------------------------------------------------------
    // Encode edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn encode_bundle_produces_correct_structure() {
        let bundle = provision_bundle_with_cross_signing();
        let wire = encode_bundle(&bundle).ok();
        assert!(wire.is_some());
        let wire = wire.as_ref().unwrap();

        // Check magic.
        assert_eq!(&wire[..4], b"THMS");

        // Check length field.
        let payload_len =
            u32::from_le_bytes([wire[4], wire[5], wire[6], wire[7]]) as usize;

        // Total wire length should be header + payload + checksum.
        assert_eq!(wire.len(), HEADER_SIZE + payload_len + SHA256_LEN);

        // Verify the checksum independently.
        let checksum_start = HEADER_SIZE + payload_len;
        let computed = security::sha256(&wire[..checksum_start]);
        assert_eq!(&wire[checksum_start..], &computed[..]);
    }

    #[test]
    fn encoded_payload_deserializes_independently() {
        let bundle = provision_bundle_with_cross_signing();
        let wire = encode_bundle(&bundle).ok();
        assert!(wire.is_some());
        let wire = wire.as_ref().unwrap();

        let payload_len =
            u32::from_le_bytes([wire[4], wire[5], wire[6], wire[7]]) as usize;
        let payload = &wire[HEADER_SIZE..HEADER_SIZE + payload_len];

        let decoded: Result<ProvisionBundle, _> = postcard::from_bytes(payload);
        assert!(decoded.is_ok());
        assert_eq!(decoded.unwrap_or_else(|_| provision_bundle_without_cross_signing()), bundle);
    }
}
