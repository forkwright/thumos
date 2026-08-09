//! Matrix device provisioning via USB serial.
//!
//! Receives a [`ProvisionBundle`] from the host workstation over the USB ACM
//! serial gadget (see [`usb`]), deserializes it with postcard, verifies a
//! SHA-256 integrity checksum and an Ed25519 authenticity signature, and
//! provides the credentials for [`MatrixClient`] initialization.
//!
//! ## Wire format
//!
//! ```text
//! [4-byte magic "THMS"][4-byte LE length][postcard-serialized ProvisionBundle][32-byte SHA-256][64-byte Ed25519 signature]
//! ```
//!
//! The `length` field covers only the postcard payload (not magic, length,
//! checksum, or signature). The SHA-256 covers magic + length + payload
//! (everything before the checksum) and is integrity-only: it travels inside
//! the same untrusted bundle it protects, so it catches corruption but proves
//! nothing about origin. The Ed25519 signature covers the same magic + length
//! + payload region and is the sole authenticity guarantee — verified against
//!   [`PROVISION_PUBLIC_KEY`], a compile-time-embedded public key whose
//!   corresponding private key is held offline by the operator, mirroring the
//!   secure-boot Ed25519 key custody model (see [`secure_boot`]).
//!
//! ## Provisioning flow
//!
//! 1. Device shows "WAITING FOR PROVISIONING" screen.
//! 2. menos-side tool pushes an operator-signed bundle over USB serial.
//! 3. Device receives, deserializes, verifies (SHA-256 checksum, then
//!    Ed25519 signature).
//! 4. Stores credentials to `/data/harmostes/` via LFS.
//! 5. Initializes [`MatrixClient`] with the provisioned credentials.
//! 6. Shows "PROVISIONED: @user:server" confirmation.
//!
//! [`usb`]: crate::usb
//! [`MatrixClient`]: crate::harmostes::MatrixClient
//! [`secure_boot`]: crate::secure_boot

// WHY: Provisioning module created in Phase 09 Wave 4, full integration with
// MatrixClient pending in Wave 5.
#![expect(
    dead_code,
    reason = "Provisioning module created in Phase 09 Wave 4, MatrixClient integration pending"
)]

extern crate alloc;

use core::fmt;

use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::matrix_ids::{MatrixDeviceId, MatrixUserId};
use crate::secure_boot;
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

/// Ed25519 signature length (bytes). Mirrors [`secure_boot::SIGNATURE_LEN`].
const SIGNATURE_LEN: usize = secure_boot::SIGNATURE_LEN;

/// Maximum payload size (64 KiB). Prevents unbounded allocation from
/// malformed length fields.
const MAX_PAYLOAD_SIZE: usize = 65_536;

/// Receive buffer capacity. Must hold header + max payload + checksum +
/// signature.
const RECV_BUF_CAPACITY: usize = HEADER_SIZE + MAX_PAYLOAD_SIZE + SHA256_LEN + SIGNATURE_LEN;

/// Embedded Ed25519 public key for provisioning bundle authenticity.
///
/// TODO(#270)[deliberate-prudent]: this is the RFC 8032 section 7.1 Test 2
/// public key, NOT a real trust anchor. It must be replaced with the
/// production provisioning key injected by the offline signing
/// infrastructure before any release build. The corresponding private key
/// is held offline by the operator (same custody model as
/// [`secure_boot`]'s boot key) and used by the menos-side provisioning
/// tool to sign bundles — it never touches this crate's compiled artifact.
/// Deliberately a distinct key from the boot key: provisioning-bundle
/// authenticity and kernel-image authenticity are separate trust domains.
const PROVISION_PUBLIC_KEY: [u8; secure_boot::PUBLIC_KEY_LEN] = [
    0x3d, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89, 0x5a, 0x92, 0xb7, 0x0a, 0xa7, 0x4d, 0x1b, 0x7e, 0xbc,
    0x9c, 0x98, 0x2c, 0xcf, 0x2e, 0xc4, 0x96, 0x8c, 0xc0, 0xcd, 0x55, 0xf1, 0x2a, 0xf4, 0x66, 0x0c,
];

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
    /// The Ed25519 signature did not verify against [`PROVISION_PUBLIC_KEY`].
    SignatureInvalid,
    /// Postcard deserialization failed.
    DeserializeError,
    /// Postcard serialization failed while encoding a [`ProvisionBundle`]
    /// into the wire format. Carries the underlying [`postcard::Error`] as
    /// cause (distinct from [`Self::DeserializeError`] -- encoding and
    /// decoding are different failure modes).
    SerializeError(postcard::Error),
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
            Self::SignatureInvalid => write!(f, "provision bundle signature invalid"),
            Self::DeserializeError => write!(f, "provision bundle deserialization failed"),
            Self::SerializeError(cause) => {
                write!(f, "provision bundle serialization failed: {cause}")
            }
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
    pub user_id: MatrixUserId,
    /// Device ID assigned during registration.
    pub device_id: MatrixDeviceId,
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
    /// Ed25519 public key used to verify bundle signatures. Always
    /// `PROVISION_PUBLIC_KEY` outside tests; test-injectable via
    /// [`Provisioner::new_with_key`] to exercise verification against a
    /// locally generated keypair.
    provision_public_key: [u8; secure_boot::PUBLIC_KEY_LEN],
}

impl Provisioner {
    /// Create a new provisioner in the [`ProvisionState::Waiting`] state.
    ///
    /// Verifies bundle signatures against [`PROVISION_PUBLIC_KEY`].
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            state: ProvisionState::Waiting,
            buffer: Vec::new(),
            payload_len: None,
            bundle: None,
            provision_public_key: PROVISION_PUBLIC_KEY,
        }
    }

    /// Create a new provisioner that verifies bundle signatures against a
    /// caller-supplied public key instead of [`PROVISION_PUBLIC_KEY`].
    ///
    /// Test-only: lets tests exercise the verification path against a
    /// locally generated Ed25519 keypair without needing a signature
    /// pre-computed under the production placeholder key.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn new_with_key(provision_public_key: [u8; secure_boot::PUBLIC_KEY_LEN]) -> Self {
        Self {
            state: ProvisionState::Waiting,
            buffer: Vec::new(),
            payload_len: None,
            bundle: None,
            provision_public_key,
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
            _ => {} // WHY: non-terminal states (Waiting/Receiving) continue processing below
        }

        // Transition from Waiting to Receiving on first data.
        if self.state == ProvisionState::Waiting && !data.is_empty() {
            self.state = ProvisionState::Receiving;
        }

        // Reject growth beyond the maximum possible message size (header +
        // max payload + checksum + signature) BEFORE extending the
        // buffer, not after -- RECV_BUF_CAPACITY exists precisely to cap
        // this but was never wired in, leaving the buffer to grow without
        // bound if a caller ever hands receive_chunk() a chunk (or a run
        // of chunks) larger than any well-formed bundle could need.
        if self.buffer.len().saturating_add(data.len()) > RECV_BUF_CAPACITY {
            self.state = ProvisionState::Error(ProvisionError::PayloadTooLarge);
            return &self.state;
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

        // Check if we have the complete message (header + payload + checksum
        // + signature).
        if let Some(payload_len) = self.payload_len {
            let total_len = HEADER_SIZE + payload_len + SHA256_LEN + SIGNATURE_LEN;
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
            ProvisionState::Complete => self.bundle.clone().ok_or(ProvisionError::Incomplete),
            ProvisionState::Error(e) => Err(e.clone()),
            ProvisionState::Waiting | ProvisionState::Receiving => Err(ProvisionError::Incomplete),
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
        let signature_start = checksum_start + SHA256_LEN;
        let data_region = &self.buffer[..checksum_start];
        let received_checksum = &self.buffer[checksum_start..signature_start];

        // Verify SHA-256 checksum over magic + length + payload. Integrity
        // only: the checksum travels inside the same untrusted bundle it
        // covers, so a mismatch proves corruption but a match proves
        // nothing about origin — PROVISION_PUBLIC_KEY below is the actual
        // authenticity check.
        let computed = security::sha256(data_region);
        if computed != received_checksum {
            return Err(ProvisionError::ChecksumMismatch);
        }

        // Verify the Ed25519 signature over the same region. This is the
        // sole authenticity guarantee: only a host holding the offline
        // provisioning private key can produce a signature
        // provision_public_key accepts, closing the "any host can inject
        // credentials" gap the checksum alone left open (#270).
        let mut signature = [0u8; SIGNATURE_LEN];
        signature.copy_from_slice(&self.buffer[signature_start..signature_start + SIGNATURE_LEN]);
        secure_boot::verify_message_signature(data_region, &signature, &self.provision_public_key)
            .map_err(|_| ProvisionError::SignatureInvalid)?;

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
/// SHA-256 checksum + Ed25519 signature. `signature` must be computed by
/// the caller over the magic + length + payload bytes (the same region
/// [`Provisioner::try_finalize`] verifies) under the provisioning private
/// key held offline by the operator. This function never touches
/// signing-key material itself — it only appends a caller-supplied
/// signature — so the menos-side provisioning tool (or a test, via a
/// locally generated keypair) computes the signature with its own crypto
/// stack and passes the result in.
///
/// # Errors
///
/// Returns [`ProvisionError::PayloadTooLarge`] if the serialized payload
/// exceeds [`MAX_PAYLOAD_SIZE`], or [`ProvisionError::SerializeError`] if
/// postcard serialization fails.
pub(crate) fn encode_bundle(
    bundle: &ProvisionBundle,
    signature: &[u8; SIGNATURE_LEN],
) -> Result<Vec<u8>, ProvisionError> {
    let payload = postcard::to_allocvec(bundle).map_err(ProvisionError::SerializeError)?;

    if payload.len() > MAX_PAYLOAD_SIZE {
        return Err(ProvisionError::PayloadTooLarge);
    }

    let payload_len = payload.len() as u32;
    let mut wire = Vec::with_capacity(HEADER_SIZE + payload.len() + SHA256_LEN + SIGNATURE_LEN);

    // Magic.
    wire.extend_from_slice(&PROVISION_MAGIC);
    // Length (little-endian).
    wire.extend_from_slice(&payload_len.to_le_bytes());
    // Payload.
    wire.extend_from_slice(&payload);

    // SHA-256 checksum over everything so far (integrity only).
    let checksum = security::sha256(&wire);
    wire.extend_from_slice(&checksum);

    // Ed25519 signature over magic + length + payload (authenticity).
    wire.extend_from_slice(signature);

    Ok(wire)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};

    use super::*;

    /// Fixed, deterministic Ed25519 signing key for provisioning tests.
    ///
    /// Its public half is injected into [`harness_provisioner`] via
    /// [`Provisioner::new_with_key`], so a locally computed signature verifies
    /// without the offline production key behind [`PROVISION_PUBLIC_KEY`].
    fn harness_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[0x42; 32])
    }

    /// A provisioner that trusts [`harness_signing_key`]'s public key instead of
    /// the production [`PROVISION_PUBLIC_KEY`], so test-signed bundles verify.
    fn harness_provisioner() -> Provisioner {
        Provisioner::new_with_key(harness_signing_key().verifying_key().to_bytes())
    }

    /// The exact wire region [`encode_bundle`] signs over: magic + length +
    /// payload — everything BEFORE the SHA-256 checksum, and the SAME region
    /// [`Provisioner::try_finalize`] verifies the signature against.
    fn signed_region(bundle: &ProvisionBundle) -> Vec<u8> {
        let payload = postcard::to_allocvec(bundle).expect("serialize provision bundle");
        let payload_len = payload.len() as u32;
        let mut region = Vec::with_capacity(HEADER_SIZE + payload.len());
        region.extend_from_slice(&PROVISION_MAGIC);
        region.extend_from_slice(&payload_len.to_le_bytes());
        region.extend_from_slice(&payload);
        region
    }

    /// Encode `bundle`, signing the magic+length+payload region with
    /// `signing_key`. [`encode_bundle`] computes the SHA-256 checksum itself
    /// and appends this caller-supplied signature.
    fn encode_bundle_with(bundle: &ProvisionBundle, signing_key: &SigningKey) -> Vec<u8> {
        let signature: [u8; SIGNATURE_LEN] = signing_key.sign(&signed_region(bundle)).to_bytes();
        encode_bundle(bundle, &signature).expect("encode provision bundle")
    }

    /// Encode `bundle` signed by the trusted [`harness_signing_key`] — the happy
    /// path a [`harness_provisioner`] accepts.
    fn encode_bundle_signed(bundle: &ProvisionBundle) -> Vec<u8> {
        encode_bundle_with(bundle, &harness_signing_key())
    }

    /// Create a test bundle with deterministic data.
    fn provision_bundle_with_cross_signing() -> ProvisionBundle {
        ProvisionBundle {
            user_id: MatrixUserId::new("@cody:matrix.example.com").expect("valid test user id"),
            device_id: MatrixDeviceId::new("THMSTESTDEV01").expect("valid test device id"),
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
            user_id: MatrixUserId::new("@test:example.org").expect("valid test user id"),
            device_id: MatrixDeviceId::new("DEVNOCSIGN").expect("valid test device id"),
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
        let wire = encode_bundle_signed(&bundle);

        let mut prov = harness_provisioner();
        let state = prov.receive_chunk(&wire);
        assert_eq!(*state, ProvisionState::Complete);

        let result = prov.finalize();
        assert!(result.is_ok());
        let decoded = result.unwrap_or_else(|_| provision_bundle_with_cross_signing());
        assert_eq!(decoded, bundle);
    }

    #[test]
    fn bundle_round_trip_no_cross_signing() {
        let bundle = provision_bundle_without_cross_signing();
        let wire = encode_bundle_signed(&bundle);

        let mut prov = harness_provisioner();
        prov.receive_chunk(&wire);
        assert!(prov.is_complete());

        let decoded = prov
            .finalize()
            .unwrap_or_else(|_| provision_bundle_with_cross_signing());
        assert_eq!(decoded, bundle);
    }

    // -----------------------------------------------------------------------
    // Magic header validation
    // -----------------------------------------------------------------------

    #[test]
    fn invalid_magic_rejected() {
        let mut wire = encode_bundle_signed(&provision_bundle_with_cross_signing());
        assert!(!wire.is_empty());
        // Corrupt magic.
        wire[0] = b'X';

        let mut prov = harness_provisioner();
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
        let mut wire = encode_bundle_signed(&provision_bundle_with_cross_signing());
        assert!(!wire.is_empty());
        // Corrupt a byte INSIDE the SHA-256 checksum region. The trailing
        // bytes are now the Ed25519 signature, so corrupting the tail would
        // surface as SignatureInvalid instead (see signature_invalid_rejected).
        let payload_len = u32::from_le_bytes([wire[4], wire[5], wire[6], wire[7]]) as usize;
        let checksum_start = HEADER_SIZE + payload_len;
        wire[checksum_start + SHA256_LEN - 1] ^= 0xFF;

        let mut prov = harness_provisioner();
        let state = prov.receive_chunk(&wire);
        assert_eq!(
            *state,
            ProvisionState::Error(ProvisionError::ChecksumMismatch)
        );
    }

    #[test]
    fn corrupted_payload_fails_checksum() {
        let mut wire = encode_bundle_signed(&provision_bundle_with_cross_signing());
        assert!(!wire.is_empty());
        // Corrupt a byte in the payload region.
        if wire.len() > HEADER_SIZE + 5 {
            wire[HEADER_SIZE + 5] ^= 0xFF;
        }

        let mut prov = harness_provisioner();
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
        let wire = encode_bundle_signed(&provision_bundle_with_cross_signing());
        // Send only half the data.
        let half = wire.len() / 2;

        let mut prov = harness_provisioner();
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
    fn receive_chunk_rejects_growth_beyond_recv_buf_capacity() {
        // A single over-sized chunk, larger than any well-formed bundle
        // could ever need (RECV_BUF_CAPACITY = header + max payload +
        // checksum + signature). Content is irrelevant -- the cap must
        // reject growth BEFORE parsing a header, not rely on the
        // payload_len check (which only fires once a header is present).
        let mut oversized = Vec::new();
        oversized.resize(RECV_BUF_CAPACITY + 1, 0u8);

        let mut prov = Provisioner::new();
        let state = prov.receive_chunk(&oversized);
        assert_eq!(
            *state,
            ProvisionState::Error(ProvisionError::PayloadTooLarge),
            "a chunk larger than RECV_BUF_CAPACITY must be rejected before buffering"
        );
        assert!(
            prov.buffer.is_empty(),
            "the oversized chunk must never be appended to the receive buffer"
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
        let wire = encode_bundle_signed(&provision_bundle_with_cross_signing());

        let mut prov = harness_provisioner();

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
        let decoded = prov
            .finalize()
            .unwrap_or_else(|_| provision_bundle_without_cross_signing());
        assert_eq!(decoded, provision_bundle_with_cross_signing());
    }

    #[test]
    fn byte_at_a_time_accumulation() {
        let wire = encode_bundle_signed(&provision_bundle_with_cross_signing());

        let mut prov = harness_provisioner();

        // Feed every single byte individually.
        for &byte in &wire {
            prov.receive_chunk(&[byte]);
        }

        assert!(prov.is_complete());
        let decoded = prov
            .finalize()
            .unwrap_or_else(|_| provision_bundle_without_cross_signing());
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
        let wire = encode_bundle_signed(&provision_bundle_with_cross_signing());

        let mut prov = harness_provisioner();
        prov.receive_chunk(&wire);
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

    #[test]
    fn finalize_in_error_state_returns_the_stored_error() {
        let mut prov = Provisioner::new();
        let state = prov.receive_chunk(b"BAD_MAGIC_HEADER_DATA_PLUS_PADDING__");
        assert_eq!(*state, ProvisionState::Error(ProvisionError::InvalidMagic));

        let result = prov.finalize();
        assert_eq!(
            result,
            Err(ProvisionError::InvalidMagic),
            "finalize() in the Error state must return the exact stored error, \
             not Incomplete or a different variant"
        );
    }

    // -----------------------------------------------------------------------
    // Reset
    // -----------------------------------------------------------------------

    #[test]
    fn reset_clears_state() {
        let wire = encode_bundle_signed(&provision_bundle_with_cross_signing());

        let mut prov = harness_provisioner();
        prov.receive_chunk(&wire);
        assert!(prov.is_complete());

        prov.reset();
        assert_eq!(*prov.state(), ProvisionState::Waiting);
        assert!(prov.bundle().is_none());
        assert!(!prov.is_complete());
    }

    #[test]
    fn reset_after_error_allows_retry() {
        let mut prov = harness_provisioner();
        prov.receive_chunk(b"BAD_MAGIC_HEADER_DATA_PLUS_PADDING__");
        assert!(matches!(prov.state(), ProvisionState::Error(_)));

        prov.reset();
        assert_eq!(*prov.state(), ProvisionState::Waiting);

        // Now send valid data.
        let wire = encode_bundle_signed(&provision_bundle_with_cross_signing());
        prov.receive_chunk(&wire);
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
    fn display_provision_error_serialize_error_includes_cause() {
        // WHY: encode_bundle previously mapped a postcard::to_allocvec
        // failure onto ProvisionError::DeserializeError (wrong variant --
        // encode failure is not deserialize failure) and discarded the
        // underlying postcard::Error. SerializeError carries the cause and
        // renders it in Display, and is a distinct variant from
        // DeserializeError.
        let err = ProvisionError::SerializeError(postcard::Error::SerializeBufferFull);
        let s = alloc::format!("{err}");
        assert!(s.contains("serialization"));
        assert_ne!(
            err,
            ProvisionError::DeserializeError,
            "a serialize failure must not be indistinguishable from a deserialize failure"
        );
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
        let wire = encode_bundle_signed(&bundle);

        // Check magic.
        assert_eq!(&wire[..4], b"THMS");

        // Check length field.
        let payload_len = u32::from_le_bytes([wire[4], wire[5], wire[6], wire[7]]) as usize;

        // Total wire length = header + payload + checksum + signature.
        assert_eq!(
            wire.len(),
            HEADER_SIZE + payload_len + SHA256_LEN + SIGNATURE_LEN
        );

        // Verify the checksum independently. It occupies the 32 bytes after
        // the payload; the Ed25519 signature follows it.
        let checksum_start = HEADER_SIZE + payload_len;
        let computed = security::sha256(&wire[..checksum_start]);
        assert_eq!(
            &wire[checksum_start..checksum_start + SHA256_LEN],
            &computed[..]
        );
    }

    #[test]
    fn encoded_payload_deserializes_independently() {
        let bundle = provision_bundle_with_cross_signing();
        let wire = encode_bundle_signed(&bundle);

        let payload_len = u32::from_le_bytes([wire[4], wire[5], wire[6], wire[7]]) as usize;
        let payload = &wire[HEADER_SIZE..HEADER_SIZE + payload_len];

        let decoded: Result<ProvisionBundle, _> = postcard::from_bytes(payload);
        assert!(decoded.is_ok());
        assert_eq!(
            decoded.unwrap_or_else(|_| provision_bundle_without_cross_signing()),
            bundle
        );
    }

    // -----------------------------------------------------------------------
    // Signature authenticity (#270)
    // -----------------------------------------------------------------------

    #[test]
    fn valid_signature_accepted() {
        // A bundle signed by the trusted provisioning key round-trips to Ok.
        let bundle = provision_bundle_with_cross_signing();
        let wire = encode_bundle_signed(&bundle);

        let mut prov = harness_provisioner();
        let state = prov.receive_chunk(&wire);
        assert_eq!(*state, ProvisionState::Complete);

        let result = prov.finalize();
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap_or_else(|_| provision_bundle_without_cross_signing()),
            bundle
        );
    }

    #[test]
    fn signature_invalid_rejected() {
        // Valid checksum, corrupted trailing Ed25519 signature: the SHA-256
        // integrity check passes but signature verification fails.
        let mut wire = encode_bundle_signed(&provision_bundle_with_cross_signing());
        assert!(!wire.is_empty());
        let last = wire.len() - 1;
        wire[last] ^= 0xFF;

        let mut prov = harness_provisioner();
        let state = prov.receive_chunk(&wire);
        assert_eq!(
            *state,
            ProvisionState::Error(ProvisionError::SignatureInvalid)
        );
    }

    #[test]
    fn hash_only_forgery_rejected() {
        // The core #270 property: an attacker who does NOT hold the trusted
        // provisioning key signs the bundle with a DIFFERENT key.
        // encode_bundle recomputes a correct SHA-256, so the integrity
        // checksum is genuinely valid — yet the provisioner, trusting only
        // harness_signing_key's public half, refuses the wrong-key signature. A
        // correct hash without the right signing key is NOT enough.
        let attacker_key = SigningKey::from_bytes(&[0x99; 32]);
        let bundle = provision_bundle_with_cross_signing();
        let wire = encode_bundle_with(&bundle, &attacker_key);

        // The checksum region is genuinely valid — this is a forgery under the
        // wrong key, not a corruption.
        let payload_len = u32::from_le_bytes([wire[4], wire[5], wire[6], wire[7]]) as usize;
        let checksum_start = HEADER_SIZE + payload_len;
        let computed = security::sha256(&wire[..checksum_start]);
        assert_eq!(
            &wire[checksum_start..checksum_start + SHA256_LEN],
            &computed[..],
            "attacker's SHA-256 checksum is valid; only the signature is wrong"
        );

        let mut prov = harness_provisioner();
        let state = prov.receive_chunk(&wire);
        assert_eq!(
            *state,
            ProvisionState::Error(ProvisionError::SignatureInvalid),
            "valid hash + wrong signing key must be rejected (#270)"
        );
    }

    #[test]
    fn display_provision_error_signature_invalid() {
        let err = ProvisionError::SignatureInvalid;
        let s = alloc::format!("{err}");
        assert!(s.contains("signature"));
    }
}
