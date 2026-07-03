//! Matrix E2E encryption: simplified Olm (1:1) and Megolm (group) sessions.
//!
//! Implements Matrix end-to-end encryption on top of the kernel's existing
//! cryptographic primitives (`security.rs` SHA-256/HMAC/HKDF, `csprng.rs`
//! ChaCha20 CSPRNG, `aes` crate for AES-256).
//!
//! This is a **simplified** implementation suitable for the Thumos kernel's
//! bare-metal environment. It implements the core cryptographic operations
//! (key generation, AES-256-CBC encrypt/decrypt, session management) without
//! the full libolm/vodozemac state machine. Key exchange uses HKDF-derived
//! keys rather than full X3DH, and Megolm ratcheting is hash-based rather
//! than the full 4-part ratchet.
//!
//! # Architecture
//!
//! - `DeviceKeys`: Ed25519 (signing) + Curve25519 (encryption) keypair
//! - `OlmSession`: 1:1 encrypted session with chain ratchet
//! - `MegolmSession`: group session with AES-256-CBC encryption
//! - `MatrixCrypto`: top-level manager coordinating sessions and keys
//!
//! # References
//!
//! - Matrix Olm specification: <https://spec.matrix.org/latest/client-server-api/#end-to-end-encryption>
//! - AES-CBC: NIST SP 800-38A

// WHY: Matrix crypto created in Phase 09 Wave 3, full integration pending.
#![expect(
    dead_code,
    reason = "Matrix crypto created in Phase 09 Wave 3, full messaging integration pending"
)]

extern crate alloc;

use core::fmt;

use alloc::string::String;
use alloc::vec::Vec;

use aes::Aes256;
use aes::cipher::block_padding::Pkcs7;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use cbc::{Decryptor as CbcDecryptor, Encryptor as CbcEncryptor};
use ed25519_dalek::{Signature, VerifyingKey};
use subtle::ConstantTimeEq;

use crate::csprng;
use crate::json_mini::{JsonParser, JsonValue, JsonWriter};
use crate::matrix_ids::MatrixRoomId;
use crate::security::{self, KEY_SIZE};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// AES block size in bytes (128 bits).
const AES_BLOCK_SIZE: usize = 16;

/// Megolm message authentication tag length: the first 8 bytes of HMAC-SHA256
/// (audit #231, matching the Megolm `m.megolm.v1.aes-sha2` spec).
const MEGOLM_MAC_LEN: usize = 8;

/// Length of the per-message key material expanded from the ratchet key:
/// AES-256 key (32) || HMAC-SHA256 key (32) || AES-CBC IV (16) = 80 bytes.
const MEGOLM_KEY_MATERIAL_LEN: usize = KEY_SIZE + KEY_SIZE + AES_BLOCK_SIZE;

/// Byte length of the Megolm message-index prefix (`u32` big-endian) that
/// precedes the ciphertext on the wire (audit #250 — the index is transmitted,
/// not read from a stale session counter).
const MEGOLM_INDEX_LEN: usize = 4;

/// Ed25519 signature length in bytes.
const ED25519_SIGNATURE_LEN: usize = 64;

/// Maximum number of Olm sessions tracked simultaneously.
const MAX_OLM_SESSIONS: usize = 64;

/// Maximum number of outbound Megolm sessions (one per room).
const MAX_MEGOLM_OUTBOUND: usize = 32;

/// Maximum number of inbound Megolm sessions (from other devices).
const MAX_MEGOLM_INBOUND: usize = 128;

/// Maximum number of one-time keys held in reserve.
const MAX_ONE_TIME_KEYS: usize = 100;

/// Maximum number of one-time keys generated in a single batch.
const MAX_GENERATED_KEYS: usize = 50;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors from Matrix E2E encryption operations.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
#[non_exhaustive]
pub enum CryptoError {
    /// The ciphertext length is not a multiple of the AES block size.
    InvalidCiphertextLength,
    /// The ciphertext is too short to contain the IV prefix.
    CiphertextTooShort,
    /// PKCS#7 padding is invalid during decryption.
    InvalidPadding,
    /// The session was not found.
    SessionNotFound,
    /// The session capacity has been reached.
    SessionCapacityReached,
    /// The one-time key pool is at capacity.
    KeyCapacityReached,
    /// The requested key count exceeds the maximum batch size.
    KeyCountTooLarge,
    /// JSON parsing failed during key query response processing.
    InvalidKeyResponse,
    /// HKDF key derivation failed.
    KeyDerivationFailed,
    /// The plaintext is empty.
    EmptyPlaintext,
    /// The kernel CSPRNG was not seeded, so no key material could be generated
    /// (fail-closed, audit #284).
    EntropyUnavailable,
    /// The Megolm message authentication tag failed verification — the
    /// ciphertext was forged or tampered with (audit #231).
    MacVerificationFailed,
    /// The Megolm message is too short to hold the index prefix + MAC tag
    /// (audit #231/#250).
    MegolmMessageTooShort,
    /// The decrypting Megolm session is bound to a different room than the one
    /// the event arrived in — cross-room session confusion (audit #229).
    RoomIdMismatch,
    /// A homeserver-supplied device key failed Ed25519 self-signature
    /// verification (audit #230).
    UntrustedDeviceKey,
    /// The room id supplied for session creation is not a well-formed Matrix
    /// room identifier (#373).
    InvalidRoomId(crate::matrix_ids::MatrixIdError),
}

impl From<csprng::CsprngError> for CryptoError {
    fn from(_: csprng::CsprngError) -> Self {
        Self::EntropyUnavailable
    }
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCiphertextLength => {
                write!(f, "ciphertext length is not a multiple of AES block size")
            }
            Self::CiphertextTooShort => {
                write!(f, "ciphertext too short to contain IV prefix")
            }
            Self::InvalidPadding => write!(f, "invalid PKCS#7 padding"),
            Self::SessionNotFound => write!(f, "session not found"),
            Self::SessionCapacityReached => write!(f, "session capacity reached"),
            Self::KeyCapacityReached => write!(f, "one-time key pool at capacity"),
            Self::KeyCountTooLarge => {
                write!(f, "requested key count exceeds maximum batch size")
            }
            Self::InvalidKeyResponse => write!(f, "invalid key query response JSON"),
            Self::KeyDerivationFailed => write!(f, "HKDF key derivation failed"),
            Self::EmptyPlaintext => write!(f, "plaintext is empty"),
            Self::EntropyUnavailable => write!(f, "kernel CSPRNG not seeded"),
            Self::MacVerificationFailed => {
                write!(
                    f,
                    "Megolm MAC verification failed (forged or tampered ciphertext)"
                )
            }
            Self::MegolmMessageTooShort => {
                write!(
                    f,
                    "Megolm message too short to contain index prefix and MAC"
                )
            }
            Self::RoomIdMismatch => {
                write!(
                    f,
                    "Megolm session bound to a different room (cross-room confusion)"
                )
            }
            Self::UntrustedDeviceKey => {
                write!(f, "device key failed Ed25519 self-signature verification")
            }
            Self::InvalidRoomId(e) => write!(f, "invalid room identifier: {e}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Device keys
// ---------------------------------------------------------------------------

/// Device identity keys for Matrix E2E encryption.
///
/// Contains an Ed25519 signing key and a Curve25519 encryption key.
/// In this simplified implementation, both are CSPRNG-derived 256-bit
/// keys used with HKDF for key agreement rather than actual elliptic
/// curve operations.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
#[non_exhaustive]
pub struct DeviceKeys {
    /// Ed25519 signing key (256 bits).
    pub ed25519_key: [u8; KEY_SIZE],
    /// Curve25519 encryption key (256 bits).
    pub curve25519_key: [u8; KEY_SIZE],
}

impl fmt::Display for DeviceKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Display only the first 4 bytes of each key for identification.
        write!(
            f,
            "DeviceKeys(ed25519:{:02x}{:02x}..., curve25519:{:02x}{:02x}...)",
            self.ed25519_key[0],
            self.ed25519_key[1],
            self.curve25519_key[0],
            self.curve25519_key[1],
        )
    }
}

// ---------------------------------------------------------------------------
// Olm session (1:1)
// ---------------------------------------------------------------------------

/// Simplified Olm session for 1:1 encrypted messaging.
///
/// Tracks a symmetric ratchet key and chain index. Each message
/// advances the ratchet via HKDF, providing forward secrecy within
/// the session.
// WHY: no derived `Debug` — a derive would print `ratchet_key` in the clear
// (audit #268). Fields are `pub(crate)`, not `pub`, so key material cannot
// escape the crate. The manual `Debug`/`Display` impls redact the key.
#[derive(Clone, PartialEq, Eq)]
#[must_use]
#[non_exhaustive]
pub struct OlmSession {
    /// Unique session identifier (SHA-256 of initial key material).
    pub(crate) session_id: [u8; KEY_SIZE],
    /// Current ratchet key (256 bits), advanced after each message.
    pub(crate) ratchet_key: [u8; KEY_SIZE],
    /// Number of messages sent/received in this session.
    pub(crate) chain_index: u32,
}

impl fmt::Debug for OlmSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // WARNING: never print `ratchet_key` — redacted to prevent key leakage.
        f.debug_struct("OlmSession")
            .field("session_id", &SessionIdRedact(&self.session_id))
            .field("ratchet_key", &"<redacted>")
            .field("chain_index", &self.chain_index)
            .finish()
    }
}

impl fmt::Display for OlmSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "OlmSession(id:{:02x}{:02x}..., chain:{})",
            self.session_id[0], self.session_id[1], self.chain_index,
        )
    }
}

// ---------------------------------------------------------------------------
// Megolm session (group)
// ---------------------------------------------------------------------------

/// Simplified Megolm session for group (room) encrypted messaging.
///
/// Each room has one outbound session (for sending) and potentially
/// multiple inbound sessions (one per remote device). The session key
/// is used for AES-256-CBC encryption, and the message index provides
/// ordering and replay protection.
// WHY: no derived `Debug` — a derive would print `session_key` in the clear
// (audit #268). Fields are `pub(crate)`, not `pub`. The manual `Debug`/`Display`
// impls redact the key.
#[derive(Clone, PartialEq, Eq)]
#[must_use]
#[non_exhaustive]
pub struct MegolmSession {
    /// Unique session identifier.
    pub(crate) session_id: [u8; KEY_SIZE],
    /// AES-256 encryption key (256 bits).
    pub(crate) session_key: [u8; KEY_SIZE],
    /// Number of messages encrypted with this session.
    pub(crate) message_index: u32,
    /// The Matrix room ID this session is bound to.
    pub(crate) room_id: MatrixRoomId,
}

impl fmt::Debug for MegolmSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // WARNING: never print `session_key` — redacted to prevent key leakage.
        f.debug_struct("MegolmSession")
            .field("session_id", &SessionIdRedact(&self.session_id))
            .field("session_key", &"<redacted>")
            .field("message_index", &self.message_index)
            .field("room_id", &self.room_id)
            .finish()
    }
}

/// Debug helper: renders a session-id prefix (first two bytes) without exposing
/// full identifier material.
struct SessionIdRedact<'a>(&'a [u8; KEY_SIZE]);

impl fmt::Debug for SessionIdRedact<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:02x}{:02x}...", self.0[0], self.0[1])
    }
}

impl fmt::Display for MegolmSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MegolmSession(id:{:02x}{:02x}..., room:{}, idx:{})",
            self.session_id[0], self.session_id[1], self.room_id, self.message_index,
        )
    }
}

// ---------------------------------------------------------------------------
// MatrixCrypto
// ---------------------------------------------------------------------------

/// Top-level Matrix E2E encryption manager.
///
/// Coordinates device keys, Olm sessions, Megolm sessions, and
/// one-time key pool. Provides methods for the Matrix key upload/query
/// API and message encrypt/decrypt operations.
#[non_exhaustive]
pub(crate) struct MatrixCrypto {
    /// This device's identity keys.
    device_keys: DeviceKeys,
    /// Active 1:1 Olm sessions.
    olm_sessions: Vec<OlmSession>,
    /// Outbound Megolm sessions (one per room, for sending).
    /// `pub(crate)` for direct mutable access from `harmostes.rs` during
    /// encrypted message sending.
    pub(crate) megolm_outbound: Vec<MegolmSession>,
    /// Inbound Megolm sessions (from other devices, for receiving).
    megolm_inbound: Vec<MegolmSession>,
    /// Pool of unsigned one-time Curve25519 keys.
    one_time_keys: Vec<[u8; KEY_SIZE]>,
}

impl MatrixCrypto {
    /// Create a new `MatrixCrypto` instance with freshly generated device keys.
    ///
    /// The device keys are generated from the kernel CSPRNG. The caller must
    /// ensure `csprng::init()` has been called before constructing this.
    ///
    /// # Errors
    ///
    /// [`CryptoError::EntropyUnavailable`] if the CSPRNG is not yet seeded
    /// (fail-closed, audit #284).
    pub(crate) fn new() -> Result<Self, CryptoError> {
        Ok(Self {
            device_keys: generate_device_keys()?,
            olm_sessions: Vec::new(),
            megolm_outbound: Vec::new(),
            megolm_inbound: Vec::new(),
            one_time_keys: Vec::new(),
        })
    }

    /// Return a reference to this device's identity keys.
    #[must_use]
    pub(crate) fn device_keys(&self) -> &DeviceKeys {
        &self.device_keys
    }

    /// Return the current one-time key pool.
    #[must_use]
    pub(crate) fn one_time_keys(&self) -> &[[u8; KEY_SIZE]] {
        &self.one_time_keys
    }

    /// Return the outbound Megolm sessions.
    #[must_use]
    pub(crate) fn megolm_outbound(&self) -> &[MegolmSession] {
        &self.megolm_outbound
    }

    /// Return the inbound Megolm sessions.
    #[must_use]
    pub(crate) fn megolm_inbound(&self) -> &[MegolmSession] {
        &self.megolm_inbound
    }

    /// Return the active Olm sessions.
    #[must_use]
    pub(crate) fn olm_sessions(&self) -> &[OlmSession] {
        &self.olm_sessions
    }

    // -----------------------------------------------------------------------
    // Key generation
    // -----------------------------------------------------------------------

    /// Generate a batch of one-time Curve25519 keys and add them to the pool.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::KeyCountTooLarge`] if `count` exceeds the
    /// maximum batch size.
    /// Returns [`CryptoError::KeyCapacityReached`] if the pool would exceed
    /// its maximum size.
    pub(crate) fn generate_one_time_keys(
        &mut self,
        count: u32,
    ) -> Result<Vec<[u8; KEY_SIZE]>, CryptoError> {
        let count_usize = count as usize;
        if count_usize > MAX_GENERATED_KEYS {
            return Err(CryptoError::KeyCountTooLarge);
        }
        if self.one_time_keys.len().saturating_add(count_usize) > MAX_ONE_TIME_KEYS {
            return Err(CryptoError::KeyCapacityReached);
        }

        let mut keys = Vec::with_capacity(count_usize);
        for _ in 0..count_usize {
            let mut key = [0u8; KEY_SIZE];
            csprng::kernel_random_bytes(&mut key)?;
            keys.push(key);
            self.one_time_keys.push(key);
        }
        Ok(keys)
    }

    // -----------------------------------------------------------------------
    // Key upload/query API
    // -----------------------------------------------------------------------

    /// Build the JSON body for `/_matrix/client/v3/keys/upload`.
    ///
    /// Returns a tuple of (device keys JSON, one-time keys JSON) suitable
    /// for inclusion in the upload request body.
    #[must_use]
    pub(crate) fn build_key_upload_request(&self) -> (String, String) {
        // Device keys JSON.
        let device_keys_json = build_device_keys_json(&self.device_keys);

        // One-time keys JSON.
        let otk_json = build_one_time_keys_json(&self.one_time_keys);

        (device_keys_json, otk_json)
    }

    /// Build the JSON body for `/_matrix/client/v3/keys/query`.
    ///
    /// Requests device keys for the given user IDs.
    #[must_use]
    pub(crate) fn build_key_query_request(user_ids: &[&str]) -> String {
        let mut w = JsonWriter::new();
        w.object_start();
        w.key("device_keys");
        w.object_start();
        for user_id in user_ids {
            w.key(user_id);
            // Empty array = request all devices for this user.
            w.array_start();
            w.end();
        }
        w.end(); // device_keys
        w.end(); // root
        w.finish()
    }

    /// Parse a `/keys/query` response and extract device keys.
    ///
    /// Returns a list of `DeviceKeys` for all devices found in the response.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidKeyResponse`] if the JSON structure
    /// is not valid or is missing expected fields.
    pub(crate) fn process_key_query_response(json: &str) -> Result<Vec<DeviceKeys>, CryptoError> {
        let root =
            JsonParser::parse(json.as_bytes()).map_err(|_| CryptoError::InvalidKeyResponse)?;

        let device_keys_obj = root
            .get("device_keys")
            .ok_or(CryptoError::InvalidKeyResponse)?;

        let users = device_keys_obj
            .as_object()
            .ok_or(CryptoError::InvalidKeyResponse)?;

        let mut result = Vec::new();

        for (user_id, devices_val) in users {
            let devices = devices_val
                .as_object()
                .ok_or(CryptoError::InvalidKeyResponse)?;

            for (device_id, device_info) in devices {
                let keys_obj = device_info
                    .get("keys")
                    .ok_or(CryptoError::InvalidKeyResponse)?;

                let keys_entries = keys_obj
                    .as_object()
                    .ok_or(CryptoError::InvalidKeyResponse)?;

                let mut ed25519 = [0u8; KEY_SIZE];
                let mut curve25519 = [0u8; KEY_SIZE];
                let mut found_ed = false;
                let mut found_curve = false;

                for (key_name, key_val) in keys_entries {
                    let key_str = key_val.as_str().ok_or(CryptoError::InvalidKeyResponse)?;

                    if key_name.starts_with("ed25519:") {
                        if let Some(decoded) = decode_base64_key(key_str) {
                            ed25519 = decoded;
                            found_ed = true;
                        }
                    } else if key_name.starts_with("curve25519:") {
                        if let Some(decoded) = decode_base64_key(key_str) {
                            curve25519 = decoded;
                            found_curve = true;
                        }
                    }
                }

                // #230: only trust a device key whose Ed25519 self-signature
                // verifies. A homeserver could otherwise inject arbitrary keys.
                if found_ed
                    && found_curve
                    && verify_device_self_signature(device_info, user_id, device_id, &ed25519)
                {
                    result.push(DeviceKeys {
                        ed25519_key: ed25519,
                        curve25519_key: curve25519,
                    });
                }
            }
        }

        Ok(result)
    }

    // -----------------------------------------------------------------------
    // Megolm session management
    // -----------------------------------------------------------------------

    /// Create a new outbound Megolm session for a room.
    ///
    /// If a session already exists for the room, it is replaced.
    /// Returns a reference to the newly created session.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidRoomId`] if `room_id` is not a well-formed
    /// Matrix room identifier (#373).
    /// Returns [`CryptoError::SessionCapacityReached`] if the outbound
    /// session list is at capacity and no existing session was replaced.
    pub(crate) fn create_outbound_megolm(
        &mut self,
        room_id: &str,
    ) -> Result<&MegolmSession, CryptoError> {
        // WHY(#373): validate the room id before spending entropy or storing a
        // session keyed on it.
        let validated_room = MatrixRoomId::new(room_id).map_err(CryptoError::InvalidRoomId)?;

        // Generate fresh session key and ID.
        let mut session_key = [0u8; KEY_SIZE];
        csprng::kernel_random_bytes(&mut session_key)?;

        let session_id = security::sha256(&session_key);

        let session = MegolmSession {
            session_id,
            session_key,
            message_index: 0,
            room_id: validated_room,
        };

        // Replace existing session for this room, or add new one.
        if let Some(idx) = self
            .megolm_outbound
            .iter()
            .position(|s| s.room_id == room_id)
        {
            self.megolm_outbound[idx] = session;
            Ok(&self.megolm_outbound[idx])
        } else {
            if self.megolm_outbound.len() >= MAX_MEGOLM_OUTBOUND {
                return Err(CryptoError::SessionCapacityReached);
            }
            self.megolm_outbound.push(session);
            // SAFETY: we just pushed, so last() is Some.
            Ok(self.megolm_outbound.last().unwrap_or_else(|| {
                // Unreachable: we just pushed to the vec.
                &self.megolm_outbound[0]
            }))
        }
    }

    /// Add an inbound Megolm session (received from another device).
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::SessionCapacityReached`] if the inbound
    /// session list is at capacity.
    pub(crate) fn add_inbound_megolm(&mut self, session: MegolmSession) -> Result<(), CryptoError> {
        if self.megolm_inbound.len() >= MAX_MEGOLM_INBOUND {
            return Err(CryptoError::SessionCapacityReached);
        }
        self.megolm_inbound.push(session);
        Ok(())
    }

    /// Find an inbound Megolm session by session ID.
    #[must_use]
    pub(crate) fn find_inbound_megolm(
        &self,
        session_id: &[u8; KEY_SIZE],
    ) -> Option<&MegolmSession> {
        self.megolm_inbound
            .iter()
            .find(|s| &s.session_id == session_id)
    }

    /// Find an outbound Megolm session by room ID.
    #[must_use]
    pub(crate) fn find_outbound_megolm(&self, room_id: &str) -> Option<&MegolmSession> {
        self.megolm_outbound.iter().find(|s| s.room_id == room_id)
    }
}

impl fmt::Display for MatrixCrypto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MatrixCrypto(olm:{}, megolm_out:{}, megolm_in:{}, otk:{})",
            self.olm_sessions.len(),
            self.megolm_outbound.len(),
            self.megolm_inbound.len(),
            self.one_time_keys.len(),
        )
    }
}

// ---------------------------------------------------------------------------
// Key generation
// ---------------------------------------------------------------------------

/// Generate a fresh Ed25519 + Curve25519 device keypair from the kernel CSPRNG.
///
/// # Errors
///
/// [`CryptoError::EntropyUnavailable`] if the CSPRNG is not yet seeded — device
/// keys are never emitted as zeroed key material (fail-closed, audit #284).
fn generate_device_keys() -> Result<DeviceKeys, CryptoError> {
    let mut ed25519_key = [0u8; KEY_SIZE];
    let mut curve25519_key = [0u8; KEY_SIZE];
    csprng::kernel_random_bytes(&mut ed25519_key)?;
    csprng::kernel_random_bytes(&mut curve25519_key)?;
    Ok(DeviceKeys {
        ed25519_key,
        curve25519_key,
    })
}

// ---------------------------------------------------------------------------
// AES-256-CBC core (audited `cbc` crate, NIST SP 800-38A + PKCS#7)
// ---------------------------------------------------------------------------

/// AES-256-CBC encrypt with an explicit IV and PKCS#7 padding.
///
/// Uses the audited RustCrypto `cbc` mode over the `aes` block cipher — no
/// hand-rolled chaining (audit #231). Returns the ciphertext blocks only; the
/// IV is a caller responsibility (derived, for Megolm; prepended, for the
/// standalone helper below).
fn cbc_encrypt(key: &[u8; KEY_SIZE], iv: &[u8; AES_BLOCK_SIZE], plaintext: &[u8]) -> Vec<u8> {
    let enc =
        CbcEncryptor::<Aes256>::new(GenericArray::from_slice(key), GenericArray::from_slice(iv));
    enc.encrypt_padded_vec_mut::<Pkcs7>(plaintext)
}

/// AES-256-CBC decrypt with an explicit IV, validating + stripping PKCS#7.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidCiphertextLength`] if `ciphertext` is empty or
/// not a block multiple; [`CryptoError::InvalidPadding`] if the PKCS#7 padding
/// is invalid.
fn cbc_decrypt(
    key: &[u8; KEY_SIZE],
    iv: &[u8; AES_BLOCK_SIZE],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if ciphertext.is_empty() || ciphertext.len() % AES_BLOCK_SIZE != 0 {
        return Err(CryptoError::InvalidCiphertextLength);
    }
    let dec =
        CbcDecryptor::<Aes256>::new(GenericArray::from_slice(key), GenericArray::from_slice(iv));
    dec.decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
        .map_err(|_| CryptoError::InvalidPadding)
}

/// Encrypt plaintext using AES-256-CBC with a random IV prefix (standalone
/// helper; Megolm uses the authenticated path below).
///
/// Output format: `IV (16 bytes) || ciphertext (padded to block boundary)`.
///
/// # Errors
///
/// Returns [`CryptoError::EmptyPlaintext`] if `plaintext` is empty.
fn aes256_cbc_encrypt(key: &[u8; KEY_SIZE], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if plaintext.is_empty() {
        return Err(CryptoError::EmptyPlaintext);
    }
    let mut iv = [0u8; AES_BLOCK_SIZE];
    csprng::kernel_random_bytes(&mut iv)?;
    let ciphertext = cbc_encrypt(key, &iv, plaintext);

    let mut output = Vec::with_capacity(AES_BLOCK_SIZE + ciphertext.len());
    output.extend_from_slice(&iv);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

/// Decrypt AES-256-CBC ciphertext with an IV prefix and PKCS#7 padding.
///
/// Expects input format: `IV (16 bytes) || ciphertext`.
///
/// # Errors
///
/// Returns [`CryptoError::CiphertextTooShort`] if the input is shorter than one
/// IV + one block; [`CryptoError::InvalidCiphertextLength`] /
/// [`CryptoError::InvalidPadding`] on structural / padding failures.
fn aes256_cbc_decrypt(key: &[u8; KEY_SIZE], data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    // Minimum: IV (16) + at least one block (16) = 32.
    if data.len() < AES_BLOCK_SIZE * 2 {
        return Err(CryptoError::CiphertextTooShort);
    }
    let (iv, ciphertext) = data.split_at(AES_BLOCK_SIZE);
    let mut iv_arr = [0u8; AES_BLOCK_SIZE];
    iv_arr.copy_from_slice(iv);
    cbc_decrypt(key, &iv_arr, ciphertext)
}

// ---------------------------------------------------------------------------
// Megolm authenticated encrypt/decrypt (AES-256-CBC + HMAC-SHA256)
// ---------------------------------------------------------------------------
//
// Wire layout of a Megolm payload (audit #231, #250):
//
//   message_index (4 bytes, big-endian) || AES-CBC ciphertext || MAC (8 bytes)
//
// The AES key, HMAC key, and IV are the three sections of the 80-byte
// HKDF-SHA256 expansion of the ratchet key at `message_index` — so the IV is
// derived, never transmitted, and unique per (key, index). The MAC is the
// first 8 bytes of HMAC-SHA256 over the transmitted body preceding the tag
// (`message_index || ciphertext`, matching libolm which MACs the whole message
// body; strictly stronger than ciphertext-only because it also authenticates
// the index selector). Decrypt verifies the MAC in constant time BEFORE
// touching the ciphertext, which closes the padding-oracle / bit-flipping /
// forgery classes.

/// The three key sections derived from a Megolm ratchet key for one message.
struct MegolmMessageKeys {
    /// AES-256-CBC encryption key.
    aes_key: [u8; KEY_SIZE],
    /// HMAC-SHA256 authentication key.
    hmac_key: [u8; KEY_SIZE],
    /// AES-CBC initialization vector (derived, not transmitted).
    iv: [u8; AES_BLOCK_SIZE],
}

/// Encrypt a plaintext message with a Megolm session (AES-256-CBC + HMAC-SHA256).
///
/// Produces the authenticated wire payload described above and advances the
/// session's message index. The receiver reads the embedded index to derive
/// the correct per-message keys (audit #250).
///
/// # Errors
///
/// Returns [`CryptoError::EmptyPlaintext`] if `plaintext` is empty, or
/// [`CryptoError::KeyDerivationFailed`] if HKDF fails.
pub(crate) fn encrypt_megolm(
    session: &mut MegolmSession,
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if plaintext.is_empty() {
        return Err(CryptoError::EmptyPlaintext);
    }

    let index = session.message_index;
    let keys = derive_megolm_message_keys(&session.session_key, index)?;
    let ciphertext = cbc_encrypt(&keys.aes_key, &keys.iv, plaintext);

    // Authenticated body = index || ciphertext (libolm MACs the whole body).
    let index_bytes = index.to_be_bytes();
    let mut body = Vec::with_capacity(index_bytes.len() + ciphertext.len());
    body.extend_from_slice(&index_bytes);
    body.extend_from_slice(&ciphertext);

    let tag = security::hmac_sha256(&keys.hmac_key, &body);

    let mut payload = Vec::with_capacity(body.len() + MEGOLM_MAC_LEN);
    payload.extend_from_slice(&body);
    payload.extend_from_slice(&tag[..MEGOLM_MAC_LEN]);

    session.message_index = index.saturating_add(1);
    Ok(payload)
}

/// Decrypt and authenticate a Megolm wire payload against a session.
///
/// Verifies, in order: the session is bound to `expected_room_id` (audit #229),
/// the payload carries an index + MAC (audit #250), and the MAC matches in
/// constant time BEFORE any decryption (audit #231). Only then is the AES-CBC
/// ciphertext decrypted.
///
/// `expected_room_id` is the room the event actually arrived in (from the sync
/// response grouping), NOT a value taken from the untrusted event body.
///
/// # Errors
///
/// [`CryptoError::RoomIdMismatch`] on cross-room confusion;
/// [`CryptoError::MegolmMessageTooShort`] on a truncated payload;
/// [`CryptoError::MacVerificationFailed`] on a forged / tampered MAC;
/// [`CryptoError::KeyDerivationFailed`] / [`CryptoError::InvalidCiphertextLength`]
/// / [`CryptoError::InvalidPadding`] on structural failures.
pub(crate) fn decrypt_megolm(
    session: &MegolmSession,
    payload: &[u8],
    expected_room_id: &str,
) -> Result<Vec<u8>, CryptoError> {
    // #229: the session must belong to the room the event arrived in. room_id
    // is public metadata (not secret), so a plain compare is appropriate.
    if session.room_id.as_str() != expected_room_id {
        return Err(CryptoError::RoomIdMismatch);
    }

    if payload.len() < MEGOLM_INDEX_LEN + MEGOLM_MAC_LEN {
        return Err(CryptoError::MegolmMessageTooShort);
    }

    let (body, tag) = payload.split_at(payload.len() - MEGOLM_MAC_LEN);
    let mut index_bytes = [0u8; MEGOLM_INDEX_LEN];
    index_bytes.copy_from_slice(&body[..MEGOLM_INDEX_LEN]);
    let index = u32::from_be_bytes(index_bytes);
    let ciphertext = &body[MEGOLM_INDEX_LEN..];

    // #250: derive the keys for the message's OWN index, not a stale counter.
    let keys = derive_megolm_message_keys(&session.session_key, index)?;

    // #231: verify the MAC in constant time BEFORE decrypting. `body` is
    // `index || ciphertext`; the transmitted tag is the first 8 HMAC bytes.
    let expected = security::hmac_sha256(&keys.hmac_key, body);
    if !bool::from(expected[..MEGOLM_MAC_LEN].ct_eq(tag)) {
        return Err(CryptoError::MacVerificationFailed);
    }

    cbc_decrypt(&keys.aes_key, &keys.iv, ciphertext)
}

// ---------------------------------------------------------------------------
// Message key derivation
// ---------------------------------------------------------------------------

/// Expand the Megolm ratchet key at `message_index` into the three message
/// key sections (AES key || HMAC key || IV) via one HKDF-SHA256 expansion.
///
/// Deriving the IV (rather than randomizing it) matches the Megolm spec and
/// guarantees a unique (key, IV) pair per message index.
fn derive_megolm_message_keys(
    session_key: &[u8; KEY_SIZE],
    message_index: u32,
) -> Result<MegolmMessageKeys, CryptoError> {
    const LABEL: &[u8] = b"megolm-keys";
    let index_bytes = message_index.to_be_bytes();
    let mut info = [0u8; LABEL.len() + MEGOLM_INDEX_LEN];
    info[..LABEL.len()].copy_from_slice(LABEL);
    info[LABEL.len()..].copy_from_slice(&index_bytes);

    let mut material = [0u8; MEGOLM_KEY_MATERIAL_LEN];
    security::hkdf_sha256(session_key, &[], &info, &mut material)
        .map_err(|_| CryptoError::KeyDerivationFailed)?;

    let mut aes_key = [0u8; KEY_SIZE];
    let mut hmac_key = [0u8; KEY_SIZE];
    let mut iv = [0u8; AES_BLOCK_SIZE];
    aes_key.copy_from_slice(&material[..KEY_SIZE]);
    hmac_key.copy_from_slice(&material[KEY_SIZE..KEY_SIZE * 2]);
    iv.copy_from_slice(&material[KEY_SIZE * 2..]);
    Ok(MegolmMessageKeys {
        aes_key,
        hmac_key,
        iv,
    })
}

// ---------------------------------------------------------------------------
// JSON helpers
// ---------------------------------------------------------------------------

/// Build device keys JSON for the `/keys/upload` endpoint.
fn build_device_keys_json(keys: &DeviceKeys) -> String {
    let mut w = JsonWriter::new();
    w.object_start();
    w.key("algorithms");
    w.array_start();
    w.string_value("m.olm.v1.curve25519-aes-sha2");
    w.string_value("m.megolm.v1.aes-sha2");
    w.end(); // algorithms
    w.key("keys");
    w.object_start();
    w.key("ed25519:DEVICE");
    w.string_value(&hex_encode(&keys.ed25519_key));
    w.key("curve25519:DEVICE");
    w.string_value(&hex_encode(&keys.curve25519_key));
    w.end(); // keys
    w.end(); // root
    w.finish()
}

/// Build one-time keys JSON for the `/keys/upload` endpoint.
fn build_one_time_keys_json(keys: &[[u8; KEY_SIZE]]) -> String {
    let mut w = JsonWriter::new();
    w.object_start();
    for (i, key) in keys.iter().enumerate() {
        let mut key_name = String::from("curve25519:AAAAAA");
        push_usize(&mut key_name, i);
        w.key(&key_name);
        w.string_value(&hex_encode(key));
    }
    w.end();
    w.finish()
}

// ---------------------------------------------------------------------------
// Device key self-signature verification (audit #230)
// ---------------------------------------------------------------------------

/// Verify a device key's Ed25519 self-signature.
///
/// The signature covers the Matrix-canonical JSON of the device-keys object
/// with the `signatures` and `unsigned` fields removed. The signing key is the
/// device's own `ed25519:<device_id>` key (self-signature). Returns `false`
/// (reject) if the signature field is missing, malformed, or does not verify —
/// homeserver-supplied device keys are never trusted without this check.
fn verify_device_self_signature(
    device_info: &JsonValue,
    user_id: &str,
    device_id: &str,
    ed25519_key: &[u8; KEY_SIZE],
) -> bool {
    let mut sig_key_name = String::from("ed25519:");
    sig_key_name.push_str(device_id);

    let signature_str = device_info
        .get("signatures")
        .and_then(|s| s.get(user_id))
        .and_then(|u| u.get(&sig_key_name))
        .and_then(JsonValue::as_str);
    let Some(signature_str) = signature_str else {
        return false;
    };
    let Some(signature_bytes) = decode_signature(signature_str) else {
        return false;
    };

    let mut signed = String::new();
    if !canonical_signed_json(device_info, &mut signed) {
        return false;
    }

    let Ok(verifying_key) = VerifyingKey::from_bytes(ed25519_key) else {
        return false;
    };
    let signature = Signature::from_bytes(&signature_bytes);
    verifying_key
        .verify_strict(signed.as_bytes(), &signature)
        .is_ok()
}

/// Serialize the signed portion of a device-keys object as Matrix-canonical
/// JSON: keys sorted lexicographically, compact separators, `signatures` and
/// `unsigned` removed. Returns `false` if `device_info` is not an object.
fn canonical_signed_json(device_info: &JsonValue, out: &mut String) -> bool {
    let Some(entries) = device_info.as_object() else {
        return false;
    };

    let mut order: Vec<usize> = (0..entries.len())
        .filter(|&i| entries[i].0 != "signatures" && entries[i].0 != "unsigned")
        .collect();
    order.sort_by(|&a, &b| entries[a].0.as_bytes().cmp(entries[b].0.as_bytes()));

    out.push('{');
    for (n, &i) in order.iter().enumerate() {
        if n > 0 {
            out.push(',');
        }
        canonical_json_string(&entries[i].0, out);
        out.push(':');
        canonical_json_value(&entries[i].1, out);
    }
    out.push('}');
    true
}

/// Serialize a JSON value as Matrix-canonical JSON (recursive; object keys
/// sorted, compact, integers without fraction).
fn canonical_json_value(value: &JsonValue, out: &mut String) {
    match value {
        JsonValue::Null => out.push_str("null"),
        JsonValue::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        JsonValue::Number(n) => push_i64(out, *n),
        JsonValue::String(s) => canonical_json_string(s, out),
        JsonValue::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                canonical_json_value(item, out);
            }
            out.push(']');
        }
        JsonValue::Object(entries) => {
            let mut order: Vec<usize> = (0..entries.len()).collect();
            order.sort_by(|&a, &b| entries[a].0.as_bytes().cmp(entries[b].0.as_bytes()));
            out.push('{');
            for (n, &i) in order.iter().enumerate() {
                if n > 0 {
                    out.push(',');
                }
                canonical_json_string(&entries[i].0, out);
                out.push(':');
                canonical_json_value(&entries[i].1, out);
            }
            out.push('}');
        }
    }
}

/// Append a JSON string literal with the standard escapes required by
/// canonical JSON.
fn canonical_json_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                out.push_str("\\u00");
                let byte = c as u32;
                out.push(HEX_CHARS[((byte >> 4) & 0x0f) as usize] as char);
                out.push(HEX_CHARS[(byte & 0x0f) as usize] as char);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Append a signed integer as canonical decimal digits.
fn push_i64(out: &mut String, val: i64) {
    if val < 0 {
        out.push('-');
    }
    let mut v = val.unsigned_abs();
    if v == 0 {
        out.push('0');
        return;
    }
    let start = out.len();
    while v > 0 {
        out.push((b'0' + (v % 10) as u8) as char);
        v /= 10;
    }
    // Reverse the digits just appended.
    // SAFETY: only ASCII digits were pushed at `start..`, so the bytes remain
    // valid UTF-8 after an in-place reverse.
    let bytes = unsafe { out.as_bytes_mut() };
    bytes[start..].reverse();
}

/// Decode a 64-byte Ed25519 signature from hex (128 chars) or base64
/// (unpadded/padded). Returns `None` if it does not decode to exactly 64 bytes.
fn decode_signature(s: &str) -> Option<[u8; ED25519_SIGNATURE_LEN]> {
    let bytes = if s.len() == ED25519_SIGNATURE_LEN * 2 {
        hex_decode_bytes(s)?
    } else {
        base64_decode_bytes(s)?
    };
    if bytes.len() != ED25519_SIGNATURE_LEN {
        return None;
    }
    let mut out = [0u8; ED25519_SIGNATURE_LEN];
    out.copy_from_slice(&bytes);
    Some(out)
}

/// Decode an even-length hex string into a byte vector.
fn hex_decode_bytes(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_nibble(bytes[i])?;
        let lo = hex_nibble(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Some(out)
}

/// Decode a standard-alphabet base64 string (padded or unpadded) into a byte
/// vector.
fn base64_decode_bytes(s: &str) -> Option<Vec<u8>> {
    let bytes = s.as_bytes();
    let len = bytes.iter().take_while(|&&b| b != b'=').count();

    let mut out = Vec::with_capacity(len * 3 / 4);
    let mut accum: u32 = 0;
    let mut bits: u32 = 0;
    for &b in &bytes[..len] {
        let val = base64_char_value(b)?;
        accum = (accum << 6) | u32::from(val);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((accum >> bits) as u8);
            accum &= (1 << bits) - 1;
        }
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// Base64 key decoding (simplified)
// ---------------------------------------------------------------------------

/// Decode a base64-encoded 32-byte key, or hex-encoded 32-byte key.
///
/// Returns `None` if the input doesn't decode to exactly 32 bytes.
/// Tries hex first (64 chars = 32 bytes), then unpadded base64 (43 chars = 32 bytes).
fn decode_base64_key(s: &str) -> Option<[u8; KEY_SIZE]> {
    // Try hex decoding first (our own output format).
    if s.len() == 64 {
        return hex_decode_32(s);
    }

    // Try unpadded base64 (Matrix standard format).
    if s.len() == 43 || s.len() == 44 {
        return base64_decode_32(s);
    }

    None
}

/// Decode a 64-character hex string into a 32-byte array.
fn hex_decode_32(s: &str) -> Option<[u8; KEY_SIZE]> {
    if s.len() != 64 {
        return None;
    }
    let bytes = s.as_bytes();
    let mut result = [0u8; KEY_SIZE];
    let mut i = 0;
    while i < KEY_SIZE {
        let hi = hex_nibble(bytes[i * 2])?;
        let lo = hex_nibble(bytes[i * 2 + 1])?;
        result[i] = (hi << 4) | lo;
        i += 1;
    }
    Some(result)
}

/// Convert a hex ASCII byte to its 4-bit value.
fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Decode an unpadded base64 string into a 32-byte array.
///
/// Supports standard base64 alphabet (A-Z, a-z, 0-9, +, /).
/// Returns `None` if the decoded length is not exactly 32 bytes.
fn base64_decode_32(s: &str) -> Option<[u8; KEY_SIZE]> {
    let bytes = s.as_bytes();
    // Strip trailing '=' padding if present.
    let len = if bytes.last() == Some(&b'=') {
        if bytes.len() > 1 && bytes[bytes.len() - 2] == b'=' {
            bytes.len() - 2
        } else {
            bytes.len() - 1
        }
    } else {
        bytes.len()
    };

    // Compute expected output length.
    let out_len = len * 3 / 4;
    if out_len != KEY_SIZE {
        return None;
    }

    let mut result = [0u8; KEY_SIZE];
    let mut out_idx = 0;
    let mut accum: u32 = 0;
    let mut bits: u32 = 0;

    for &b in &bytes[..len] {
        let val = base64_char_value(b)?;
        accum = (accum << 6) | u32::from(val);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            if out_idx < KEY_SIZE {
                result[out_idx] = (accum >> bits) as u8;
                out_idx += 1;
            }
            accum &= (1 << bits) - 1;
        }
    }

    if out_idx == KEY_SIZE {
        Some(result)
    } else {
        None
    }
}

/// Map a base64 character to its 6-bit value.
fn base64_char_value(b: u8) -> Option<u8> {
    match b {
        b'A'..=b'Z' => Some(b - b'A'),
        b'a'..=b'z' => Some(b - b'a' + 26),
        b'0'..=b'9' => Some(b - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Hex encoding
// ---------------------------------------------------------------------------

/// Encode a byte slice as lowercase hex string.
fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        let hi = HEX_CHARS[(b >> 4) as usize];
        let lo = HEX_CHARS[(b & 0x0f) as usize];
        s.push(hi as char);
        s.push(lo as char);
    }
    s
}

/// Hex character table.
const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

/// Append a usize as decimal digits to a string.
fn push_usize(s: &mut String, mut val: usize) {
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Seed the kernel CSPRNG for deterministic test output.
    /// Must be called before any test that uses random key generation.
    fn setup_test_rng() {
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let nonce = [0u8; 8];
        csprng::seed_for_test(&key, &nonce, 0);
    }

    /// Seed with an alternate key to produce different randomness.
    fn setup_test_rng_alt() {
        let key = [
            0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d,
            0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
            0x3c, 0x3d, 0x3e, 0x3f,
        ];
        let nonce = [0u8; 8];
        csprng::seed_for_test(&key, &nonce, 0);
    }

    // -- Key generation tests --

    #[test]
    fn device_keys_have_correct_length() {
        setup_test_rng();
        let keys = generate_device_keys().expect("test csprng seeded");
        assert_eq!(keys.ed25519_key.len(), KEY_SIZE);
        assert_eq!(keys.curve25519_key.len(), KEY_SIZE);
    }

    #[test]
    fn device_keys_are_distinct() {
        setup_test_rng();
        let keys = generate_device_keys().expect("test csprng seeded");
        // Ed25519 and Curve25519 keys should be independently generated.
        assert_ne!(
            keys.ed25519_key, keys.curve25519_key,
            "ed25519 and curve25519 keys must differ"
        );
    }

    #[test]
    fn one_time_keys_have_correct_count_and_length() {
        setup_test_rng();
        let mut crypto = MatrixCrypto::new().expect("test csprng seeded");
        let keys = crypto.generate_one_time_keys(5);
        assert!(keys.is_ok());
        let keys = keys.unwrap_or_default();
        assert_eq!(keys.len(), 5);
        for key in &keys {
            assert_eq!(key.len(), KEY_SIZE);
        }
        assert_eq!(crypto.one_time_keys().len(), 5);
    }

    #[test]
    fn one_time_key_count_too_large_fails() {
        setup_test_rng();
        let mut crypto = MatrixCrypto::new().expect("test csprng seeded");
        let result = crypto.generate_one_time_keys(MAX_GENERATED_KEYS as u32 + 1);
        assert_eq!(result, Err(CryptoError::KeyCountTooLarge));
    }

    // -- Encrypt/decrypt round-trip tests --

    #[test]
    fn aes256_cbc_round_trip_single_block() {
        setup_test_rng();
        let mut key = [0u8; KEY_SIZE];
        csprng::kernel_random_bytes(&mut key).expect("test csprng seeded");
        let plaintext = b"exactly16bytes!!";

        let ciphertext = aes256_cbc_encrypt(&key, plaintext);
        assert!(ciphertext.is_ok());
        let ciphertext = ciphertext.unwrap_or_default();

        // Ciphertext should be IV (16) + 2 blocks (32, because of PKCS#7 padding).
        assert_eq!(ciphertext.len(), AES_BLOCK_SIZE + AES_BLOCK_SIZE * 2);

        let decrypted = aes256_cbc_decrypt(&key, &ciphertext);
        assert!(decrypted.is_ok());
        assert_eq!(decrypted.unwrap_or_default().as_slice(), plaintext);
    }

    #[test]
    fn aes256_cbc_round_trip_multi_block() {
        setup_test_rng();
        let mut key = [0u8; KEY_SIZE];
        csprng::kernel_random_bytes(&mut key).expect("test csprng seeded");
        let plaintext = b"hello world, this is a longer test message for AES-256-CBC encryption!";

        let ciphertext = aes256_cbc_encrypt(&key, plaintext);
        assert!(ciphertext.is_ok());
        let ciphertext = ciphertext.unwrap_or_default();

        let decrypted = aes256_cbc_decrypt(&key, &ciphertext);
        assert!(decrypted.is_ok());
        assert_eq!(decrypted.unwrap_or_default().as_slice(), plaintext);
    }

    #[test]
    fn aes256_cbc_round_trip_short_message() {
        setup_test_rng();
        let mut key = [0u8; KEY_SIZE];
        csprng::kernel_random_bytes(&mut key).expect("test csprng seeded");
        let plaintext = b"hi";

        let ciphertext = aes256_cbc_encrypt(&key, plaintext);
        assert!(ciphertext.is_ok());
        let ciphertext = ciphertext.unwrap_or_default();

        let decrypted = aes256_cbc_decrypt(&key, &ciphertext);
        assert!(decrypted.is_ok());
        assert_eq!(decrypted.unwrap_or_default().as_slice(), plaintext);
    }

    #[test]
    fn aes256_cbc_wrong_key_fails_decrypt() {
        setup_test_rng();
        let mut key1 = [0u8; KEY_SIZE];
        let mut key2 = [0u8; KEY_SIZE];
        csprng::kernel_random_bytes(&mut key1).expect("test csprng seeded");
        csprng::kernel_random_bytes(&mut key2).expect("test csprng seeded");
        // Ensure keys differ.
        key2[0] ^= 0xff;

        let plaintext = b"secret message";
        let ciphertext = aes256_cbc_encrypt(&key1, plaintext);
        assert!(ciphertext.is_ok());
        let ciphertext = ciphertext.unwrap_or_default();

        // Decrypt with wrong key should fail (bad padding or garbage).
        let result = aes256_cbc_decrypt(&key2, &ciphertext);
        // It should either return InvalidPadding or produce wrong data.
        // In practice, random decryption almost always produces invalid padding.
        assert!(
            result.is_err() || result.unwrap_or_default().as_slice() != plaintext,
            "wrong key must not produce correct plaintext"
        );
    }

    #[test]
    fn aes256_cbc_empty_plaintext_fails() {
        let key = [0u8; KEY_SIZE];
        let result = aes256_cbc_encrypt(&key, b"");
        assert_eq!(result, Err(CryptoError::EmptyPlaintext));
    }

    #[test]
    fn aes256_cbc_short_ciphertext_fails() {
        let key = [0u8; KEY_SIZE];
        // Too short for IV + one block.
        let result = aes256_cbc_decrypt(&key, &[0u8; 16]);
        assert_eq!(result, Err(CryptoError::CiphertextTooShort));
    }

    // -- Megolm session tests --

    #[test]
    fn megolm_encrypt_decrypt_round_trip() {
        setup_test_rng();
        let mut crypto = MatrixCrypto::new().expect("test csprng seeded");
        let room_id = "!test:matrix.example.com";

        let result = crypto.create_outbound_megolm(room_id);
        assert!(result.is_ok());

        // Clone session for decryption (simulates inbound session).
        let session = crypto.find_outbound_megolm(room_id);
        assert!(session.is_some());
        let inbound = session.map(|s| s.clone()).unwrap_or_else(|| MegolmSession {
            session_id: [0u8; KEY_SIZE],
            session_key: [0u8; KEY_SIZE],
            message_index: 0,
            room_id: MatrixRoomId::new("!fallback:test").expect("valid test room id"),
        });

        // Get mutable reference to the outbound session.
        let outbound = &mut crypto.megolm_outbound[0];
        let plaintext = b"hello encrypted world";

        let ciphertext = encrypt_megolm(outbound, plaintext);
        assert!(ciphertext.is_ok());
        let ciphertext = ciphertext.unwrap_or_default();

        // Message index should have advanced.
        assert_eq!(outbound.message_index, 1);

        // Decrypt with the inbound copy (self-describing payload carries index).
        let decrypted = decrypt_megolm(&inbound, &ciphertext, room_id);
        assert!(decrypted.is_ok());
        assert_eq!(decrypted.unwrap_or_default().as_slice(), plaintext);
    }

    #[test]
    fn megolm_mac_rejects_flipped_ciphertext_bit() {
        setup_test_rng();
        let mut crypto = MatrixCrypto::new().expect("test csprng seeded");
        let room_id = "!mac:matrix.example.com";
        let _ = crypto.create_outbound_megolm(room_id);

        let inbound = crypto
            .find_outbound_megolm(room_id)
            .map(Clone::clone)
            .expect("session exists");

        let mut ciphertext =
            encrypt_megolm(&mut crypto.megolm_outbound[0], b"authenticated secret")
                .expect("encrypt");

        // Flip one bit inside the AES-CBC ciphertext region (after the 4-byte
        // index prefix, before the 8-byte MAC).
        let flip = 4 + 1;
        ciphertext[flip] ^= 0x01;

        let result = decrypt_megolm(&inbound, &ciphertext, room_id);
        assert_eq!(
            result,
            Err(CryptoError::MacVerificationFailed),
            "a flipped ciphertext bit must be rejected by the MAC before decryption"
        );
    }

    #[test]
    fn megolm_mac_rejects_tampered_tag() {
        setup_test_rng();
        let mut crypto = MatrixCrypto::new().expect("test csprng seeded");
        let room_id = "!tag:matrix.example.com";
        let _ = crypto.create_outbound_megolm(room_id);
        let inbound = crypto
            .find_outbound_megolm(room_id)
            .map(Clone::clone)
            .expect("session exists");

        let mut ct = encrypt_megolm(&mut crypto.megolm_outbound[0], b"tag test").expect("encrypt");
        let last = ct.len() - 1;
        ct[last] ^= 0xff;

        assert_eq!(
            decrypt_megolm(&inbound, &ct, room_id),
            Err(CryptoError::MacVerificationFailed)
        );
    }

    #[test]
    fn megolm_wrong_room_id_rejected() {
        setup_test_rng();
        let mut crypto = MatrixCrypto::new().expect("test csprng seeded");
        let room_id = "!bound:matrix.example.com";
        let _ = crypto.create_outbound_megolm(room_id);
        let inbound = crypto
            .find_outbound_megolm(room_id)
            .map(Clone::clone)
            .expect("session exists");

        let ct =
            encrypt_megolm(&mut crypto.megolm_outbound[0], b"room-bound message").expect("encrypt");

        // The session is bound to `room_id`; decrypting as if the event arrived
        // in a different room must be rejected before any MAC/crypto work.
        assert_eq!(
            decrypt_megolm(&inbound, &ct, "!attacker:matrix.example.com"),
            Err(CryptoError::RoomIdMismatch)
        );
        // Correct room still decrypts.
        assert!(decrypt_megolm(&inbound, &ct, room_id).is_ok());
    }

    #[test]
    fn megolm_out_of_order_index_decrypts() {
        setup_test_rng();
        let mut crypto = MatrixCrypto::new().expect("test csprng seeded");
        let room_id = "!ooo:matrix.example.com";
        let _ = crypto.create_outbound_megolm(room_id);
        let inbound = crypto
            .find_outbound_megolm(room_id)
            .map(Clone::clone)
            .expect("session exists");

        // Encrypt three messages (indices 0, 1, 2).
        let c0 = encrypt_megolm(&mut crypto.megolm_outbound[0], b"first").expect("encrypt 0");
        let c1 = encrypt_megolm(&mut crypto.megolm_outbound[0], b"second").expect("encrypt 1");
        let c2 = encrypt_megolm(&mut crypto.megolm_outbound[0], b"third").expect("encrypt 2");
        assert_eq!(crypto.megolm_outbound[0].message_index, 3);

        // Decrypt out of order — each payload carries its own index (audit #250).
        assert_eq!(
            decrypt_megolm(&inbound, &c2, room_id)
                .expect("d2")
                .as_slice(),
            b"third"
        );
        assert_eq!(
            decrypt_megolm(&inbound, &c0, room_id)
                .expect("d0")
                .as_slice(),
            b"first"
        );
        assert_eq!(
            decrypt_megolm(&inbound, &c1, room_id)
                .expect("d1")
                .as_slice(),
            b"second"
        );
    }

    #[test]
    fn megolm_message_index_increments() {
        setup_test_rng();
        let mut crypto = MatrixCrypto::new().expect("test csprng seeded");
        let room_id = "!test:matrix.example.com";
        let _ = crypto.create_outbound_megolm(room_id);

        let outbound = &mut crypto.megolm_outbound[0];
        assert_eq!(outbound.message_index, 0);

        let _ = encrypt_megolm(outbound, b"msg1");
        assert_eq!(outbound.message_index, 1);

        let _ = encrypt_megolm(outbound, b"msg2");
        assert_eq!(outbound.message_index, 2);

        let _ = encrypt_megolm(outbound, b"msg3");
        assert_eq!(outbound.message_index, 3);
    }

    #[test]
    fn megolm_different_sessions_produce_different_ciphertext() {
        setup_test_rng();
        let mut crypto = MatrixCrypto::new().expect("test csprng seeded");

        // Create two sessions for different rooms.
        let _ = crypto.create_outbound_megolm("!room1:example.com");
        let _ = crypto.create_outbound_megolm("!room2:example.com");

        let plaintext = b"same message";

        let ct1 = encrypt_megolm(&mut crypto.megolm_outbound[0], plaintext);
        let ct2 = encrypt_megolm(&mut crypto.megolm_outbound[1], plaintext);

        assert!(ct1.is_ok());
        assert!(ct2.is_ok());

        // Different sessions should produce different ciphertext (different keys + IVs).
        assert_ne!(
            ct1.unwrap_or_default(),
            ct2.unwrap_or_default(),
            "different sessions must produce different ciphertext"
        );
    }

    // -- Key upload JSON tests --

    #[test]
    fn key_upload_json_has_correct_structure() {
        setup_test_rng();
        let crypto = MatrixCrypto::new().expect("test csprng seeded");
        let (device_json, _otk_json) = crypto.build_key_upload_request();

        // Device keys JSON should contain algorithms and keys.
        assert!(device_json.contains("algorithms"));
        assert!(device_json.contains("m.olm.v1.curve25519-aes-sha2"));
        assert!(device_json.contains("m.megolm.v1.aes-sha2"));
        assert!(device_json.contains("ed25519:DEVICE"));
        assert!(device_json.contains("curve25519:DEVICE"));
    }

    #[test]
    fn key_upload_json_contains_hex_keys() {
        setup_test_rng();
        let crypto = MatrixCrypto::new().expect("test csprng seeded");
        let (device_json, _) = crypto.build_key_upload_request();

        // Parse the JSON back to verify key format.
        let parsed = JsonParser::parse(device_json.as_bytes());
        assert!(parsed.is_ok());

        let root = parsed.unwrap_or(JsonValue::Null);
        let keys = root.get("keys");
        assert!(keys.is_some());

        let keys_obj = keys.unwrap_or(&JsonValue::Null);
        let ed_key = keys_obj.get("ed25519:DEVICE");
        assert!(ed_key.is_some());

        // Key value should be 64 hex chars (32 bytes).
        let ed_str = ed_key.unwrap_or(&JsonValue::Null).as_str().unwrap_or("");
        assert_eq!(ed_str.len(), 64, "hex-encoded key must be 64 characters");
    }

    #[test]
    fn key_query_request_has_correct_format() {
        let json =
            MatrixCrypto::build_key_query_request(&["@alice:example.com", "@bob:example.com"]);

        assert!(json.contains("device_keys"));
        assert!(json.contains("@alice:example.com"));
        assert!(json.contains("@bob:example.com"));

        // Should parse successfully.
        let parsed = JsonParser::parse(json.as_bytes());
        assert!(parsed.is_ok());
    }

    // -- Key query response parsing tests --

    /// Build a `/keys/query` device object for one user+device. When
    /// `signature_hex` is `Some`, a `signatures` block is included.
    fn key_query_response(
        user_id: &str,
        device_id: &str,
        ed_hex: &str,
        curve_hex: &str,
        signature_hex: Option<&str>,
    ) -> String {
        let mut curve_name = String::from("curve25519:");
        curve_name.push_str(device_id);
        let mut ed_name = String::from("ed25519:");
        ed_name.push_str(device_id);

        let mut w = JsonWriter::new();
        w.object_start();
        w.key("device_keys");
        w.object_start();
        w.key(user_id);
        w.object_start();
        w.key(device_id);
        w.object_start(); // device_info
        w.key("algorithms");
        w.array_start();
        w.string_value("m.olm.v1.curve25519-aes-sha2");
        w.string_value("m.megolm.v1.aes-sha2");
        w.end();
        w.key("device_id");
        w.string_value(device_id);
        w.key("keys");
        w.object_start();
        w.key(&curve_name);
        w.string_value(curve_hex);
        w.key(&ed_name);
        w.string_value(ed_hex);
        w.end(); // keys
        if let Some(sig) = signature_hex {
            w.key("signatures");
            w.object_start();
            w.key(user_id);
            w.object_start();
            w.key(&ed_name);
            w.string_value(sig);
            w.end();
            w.end();
        }
        w.key("user_id");
        w.string_value(user_id);
        w.end(); // device_info
        w.end(); // device map
        w.end(); // user map
        w.end(); // device_keys
        w.end(); // root
        w.finish()
    }

    /// Produce a valid Ed25519 self-signature (hex) over the canonical device
    /// object, plus the corresponding public key.
    fn sign_device(
        user_id: &str,
        device_id: &str,
        curve_hex: &str,
        seed: &[u8; 32],
    ) -> (String, String) {
        use ed25519_dalek::{Signer, SigningKey};
        let signing = SigningKey::from_bytes(seed);
        let ed_pub = signing.verifying_key().to_bytes();
        let ed_hex = hex_encode(&ed_pub);

        // Canonical bytes = the device object (no signatures) that the verifier
        // will reconstruct.
        let unsigned = key_query_response(user_id, device_id, &ed_hex, curve_hex, None);
        let root = JsonParser::parse(unsigned.as_bytes()).expect("parse");
        let device_info = root
            .get("device_keys")
            .and_then(|d| d.get(user_id))
            .and_then(|u| u.get(device_id))
            .expect("device_info");
        let mut canonical = String::new();
        assert!(canonical_signed_json(device_info, &mut canonical));

        let sig = signing.sign(canonical.as_bytes());
        (ed_hex, hex_encode(&sig.to_bytes()))
    }

    #[test]
    fn process_key_query_response_parses_signed_device_keys() {
        let user = "@alice:example.com";
        let device = "DEVICEID";
        let curve_hex = hex_encode(&[0xBB; KEY_SIZE]);
        let seed = [0x11u8; 32];
        let (ed_hex, sig_hex) = sign_device(user, device, &curve_hex, &seed);

        let json = key_query_response(user, device, &ed_hex, &curve_hex, Some(&sig_hex));
        let result = MatrixCrypto::process_key_query_response(&json);
        assert!(result.is_ok());
        let keys = result.unwrap_or_default();
        assert_eq!(keys.len(), 1, "a validly self-signed device key is trusted");
        assert_eq!(keys[0].curve25519_key, [0xBB; KEY_SIZE]);
    }

    #[test]
    fn process_key_query_unsigned_device_key_rejected() {
        // A device key with NO signatures block must be rejected (audit #230).
        let user = "@mallory:example.com";
        let device = "DEVICEID";
        let ed_hex = hex_encode(&[0xAA; KEY_SIZE]);
        let curve_hex = hex_encode(&[0xBB; KEY_SIZE]);

        let json = key_query_response(user, device, &ed_hex, &curve_hex, None);
        let result = MatrixCrypto::process_key_query_response(&json);
        assert!(result.is_ok());
        assert!(
            result.unwrap_or_default().is_empty(),
            "an unsigned device key must not be trusted"
        );
    }

    #[test]
    fn process_key_query_bad_signature_rejected() {
        // A device key with an invalid self-signature must be rejected.
        let user = "@eve:example.com";
        let device = "DEVICEID";
        let curve_hex = hex_encode(&[0xCC; KEY_SIZE]);
        let seed = [0x22u8; 32];
        let (ed_hex, sig_hex) = sign_device(user, device, &curve_hex, &seed);

        // Corrupt the signature.
        let mut sig_bytes = hex_decode_bytes(&sig_hex).expect("hex");
        sig_bytes[0] ^= 0xff;
        let bad_hex = hex_encode(&sig_bytes);

        let json = key_query_response(user, device, &ed_hex, &curve_hex, Some(&bad_hex));
        let result = MatrixCrypto::process_key_query_response(&json);
        assert!(result.is_ok());
        assert!(
            result.unwrap_or_default().is_empty(),
            "a tampered self-signature must be rejected"
        );
    }

    #[test]
    fn process_key_query_empty_response() {
        let json = r#"{"device_keys":{}}"#;
        let result = MatrixCrypto::process_key_query_response(json);
        assert!(result.is_ok());
        assert!(result.unwrap_or_default().is_empty());
    }

    // -- Hex encoding/decoding tests --

    #[test]
    fn hex_round_trip() {
        let original = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x10, 0x20, 0x30, 0x40,
            0x50, 0x60, 0x70, 0x80,
        ];
        let encoded = hex_encode(&original);
        let decoded = hex_decode_32(&encoded);
        assert!(decoded.is_some());
        assert_eq!(decoded.unwrap_or([0u8; KEY_SIZE]), original);
    }

    // -- Display trait tests --

    #[test]
    fn display_traits_produce_output() {
        setup_test_rng();
        let crypto = MatrixCrypto::new().expect("test csprng seeded");
        let display = alloc::format!("{crypto}");
        assert!(display.contains("MatrixCrypto"));
        assert!(display.contains("olm:"));

        let keys = crypto.device_keys();
        let key_display = alloc::format!("{keys}");
        assert!(key_display.contains("DeviceKeys"));
        assert!(key_display.contains("ed25519:"));

        let err = CryptoError::InvalidPadding;
        let err_display = alloc::format!("{err}");
        assert!(err_display.contains("PKCS#7"));
    }

    // -- Megolm decrypt with wrong session --

    #[test]
    fn megolm_wrong_session_fails_decrypt() {
        setup_test_rng();
        let mut crypto = MatrixCrypto::new().expect("test csprng seeded");

        let _ = crypto.create_outbound_megolm("!room1:example.com");
        let _ = crypto.create_outbound_megolm("!room2:example.com");

        let plaintext = b"secret room1 message";
        let ciphertext = encrypt_megolm(&mut crypto.megolm_outbound[0], plaintext);
        assert!(ciphertext.is_ok());
        let ciphertext = ciphertext.unwrap_or_default();

        // Try to decrypt with room2's session (its own room passed as expected,
        // so the failure is the MAC, not the room check) — the wrong session key
        // yields a wrong HMAC key, so the MAC must reject it.
        let result = decrypt_megolm(
            &crypto.megolm_outbound[1],
            &ciphertext,
            "!room2:example.com",
        );
        assert_eq!(
            result,
            Err(CryptoError::MacVerificationFailed),
            "wrong session must not decrypt"
        );
    }

    // -- Session management tests --

    #[test]
    fn create_outbound_megolm_replaces_existing() {
        setup_test_rng();
        let mut crypto = MatrixCrypto::new().expect("test csprng seeded");
        let room = "!room:example.com";

        let _ = crypto.create_outbound_megolm(room);
        let key1 = crypto.megolm_outbound[0].session_key;

        let _ = crypto.create_outbound_megolm(room);
        let key2 = crypto.megolm_outbound[0].session_key;

        // Session should be replaced (new key).
        assert_ne!(key1, key2, "replaced session must have new key");
        // Should still be only one session.
        assert_eq!(crypto.megolm_outbound.len(), 1);
    }

    #[test]
    fn inbound_megolm_session_lookup() {
        setup_test_rng();
        let mut crypto = MatrixCrypto::new().expect("test csprng seeded");

        let session = MegolmSession {
            session_id: [0x42; KEY_SIZE],
            session_key: [0xFF; KEY_SIZE],
            message_index: 0,
            room_id: MatrixRoomId::new("!room:example.com").expect("valid test room id"),
        };

        let result = crypto.add_inbound_megolm(session);
        assert!(result.is_ok());

        let found = crypto.find_inbound_megolm(&[0x42; KEY_SIZE]);
        assert!(found.is_some());

        let not_found = crypto.find_inbound_megolm(&[0x00; KEY_SIZE]);
        assert!(not_found.is_none());
    }
}
