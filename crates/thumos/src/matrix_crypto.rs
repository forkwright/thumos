//! Matrix E2E encryption: simplified Olm (1:1) and Megolm (group) sessions.
//!
//! Implements Matrix end-to-end encryption on top of the kernel's existing
//! cryptographic primitives (`security.rs` SHA-256/HMAC/HKDF, `csprng.rs`
//! `ChaCha20` CSPRNG, `aes` crate for AES-256).
//!
//! This is a **simplified, non-interoperable** implementation suitable for
//! the Thumos kernel's bare-metal environment. It implements the core
//! cryptographic operations (key generation, AES-256-CBC encrypt/decrypt,
//! session management) without the full libolm/vodozemac state machine, and
//! is not wire-compatible with real Matrix clients: [`DeviceKeys`] are
//! CSPRNG-derived HKDF inputs rather than real Curve25519 points, key
//! exchange uses HKDF-derived keys rather than full X3DH, and the Megolm
//! wire payload (`message_index || AES-CBC ciphertext || 8-byte MAC`) is
//! this kernel's own layout rather than the spec's. `MegolmSession` is
//! never populated from a real peer's `m.room_key` event (#437 tracks that
//! integration) -- today it only talks to a future encrypt-side peer of
//! this same implementation. Megolm ratcheting is a one-way HMAC/HKDF hash
//! chain (not the Matrix spec's 4-part ratchet): the ratchet key advances
//! irreversibly after each message it authenticates, with superseded key
//! material volatile-zeroed, and a bounded skipped-key cache serves
//! out-of-order delivery without weakening that guarantee (#830).
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
// #437: `harmostes` builds the /keys/claim request and validates + returns
// the peer's claimed key (the send side of key exchange -- that key
// belongs to the remote device, never to this device's own
// `one_time_keys` pool). `consume_one_time_key`'s production call site is
// on the RECEIVE side instead, and now lives there:
// `harmostes::MatrixClient::process_to_device_event` extracts the local
// one-time key an inbound Olm pre-key message names and calls
// [`MatrixCrypto::process_olm_prekey_message`], which consumes it and
// establishes the resulting `OlmSession`. `process_sync_response` reaches
// that path via a `to_device.events` block. This module stays unreachable
// from `kernel_main` regardless -- `MatrixClient` itself is not yet
// constructed anywhere outside tests, a separate, broader integration
// this issue does not close.
#![expect(
    dead_code,
    reason = "MatrixClient (and therefore MatrixCrypto) is not yet constructed from kernel_main; unreachable pending Phase-09 unified-inbox integration (#753; tier in docs/capability-inventory.toml)"
)]

extern crate alloc;

use core::fmt;

use alloc::string::String;
use alloc::vec::Vec;

use aes::Aes256;
use aes::cipher::block_padding::Pkcs7;
// NOTE: cipher 0.5 renamed the block-mode traits (`BlockEncryptMut` ->
// `BlockModeEncrypt`, `BlockDecryptMut` -> `BlockModeDecrypt`) and dropped
// `generic_array` (replaced crate-wide by `hybrid-array`'s `Array`, re-exported
// as `aes::cipher::array::Array`/`aes::cipher::Array`). This module only ever
// builds `Array` references from already-fixed-size `&[u8; N]` inputs via the
// infallible `From<&[T; N]> for &Array<T, U>` impl (`.into()` below), so the
// `Array` type itself is never named directly.
use aes::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};
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

/// Maximum accepted Megolm wire payload length in bytes (issue #282 finding
/// 9). `decrypt_megolm` allocates proportional to the ciphertext length
/// during AES-CBC decrypt; without an explicit cap, a room member who holds
/// the (shared, group) session key -- and can therefore forge a valid MAC
/// over an arbitrarily large ciphertext -- can force an oversized
/// allocation on every device in the room. 64 KiB is generous for any real
/// text/media-key event on this device's 1 GB RAM budget.
const MEGOLM_MAX_PAYLOAD_LEN: usize = 65536;

/// Maximum forward gap `decrypt_megolm` will walk to reach a message's
/// index from the receiving session's current ratchet position (#830).
/// Without this bound, a room member who holds the (shared, group) session
/// key can name an arbitrarily large index, forcing unbounded forward HKDF
/// derivation per message -- mirrors `krypta::ratchet::MAX_SKIP_AHEAD`
/// (#212's DoS-bound pattern).
const MEGOLM_MAX_SKIP_AHEAD: u32 = 1024;

/// Maximum number of skipped message keys cached per Megolm session
/// (#830). The oldest entry is evicted (and volatile-zeroed) past this, so
/// cache growth is provably bounded regardless of traffic -- mirrors
/// `krypta::ratchet::MAX_SKIPPED_KEYS`.
const MEGOLM_MAX_SKIPPED_KEYS: usize = 1024;

/// Ed25519 signature length in bytes.
const ED25519_SIGNATURE_LEN: usize = 64;

/// Maximum number of Olm sessions tracked simultaneously.
const MAX_OLM_SESSIONS: usize = 64;

/// Byte length of this kernel's inbound Olm pre-key message body once
/// hex-decoded: `base_key (32) || one_time_key (32)`. Matrix does not
/// standardize the *contents* of an Olm ciphertext body -- that is the
/// sending/receiving Olm implementations' own wire format, invisible to the
/// homeserver that merely relays it -- and this module's device keys are
/// HKDF-derived values rather than real Curve25519 points (module docs), so
/// there is no libolm TLV encoding to interoperate with here; this is a
/// kernel-internal format for talking to a future encrypt side of this same
/// implementation (#437).
const OLM_PREKEY_BODY_LEN: usize = KEY_SIZE * 2;

/// Maximum number of outbound Megolm sessions (one per room).
const MAX_MEGOLM_OUTBOUND: usize = 32;

/// Maximum number of inbound Megolm sessions (from other devices).
const MAX_MEGOLM_INBOUND: usize = 128;

/// Maximum number of one-time keys held in reserve.
const MAX_ONE_TIME_KEYS: usize = 100;

/// Maximum number of one-time keys generated in a single batch.
const MAX_GENERATED_KEYS: usize = 50;

/// The one-time-key algorithm identifier this device generates, uploads, and
/// claims. Unsigned (raw Curve25519, not `signed_curve25519`) -- this
/// simplified implementation does not sign one-time keys (#437). Shared
/// between [`build_one_time_keys_json`] (upload) and `harmostes`'s
/// `/keys/claim` request/response so the algorithm string exists in exactly
/// one place.
pub(crate) const ONE_TIME_KEY_ALGORITHM: &str = "curve25519";

/// The Olm to-device encryption algorithm identifier (Matrix spec:
/// `m.olm.v1.curve25519-aes-sha2`) -- the top-level `content.algorithm`
/// value on an `m.room.encrypted` **to-device** event. Distinct from
/// [`ONE_TIME_KEY_ALGORITHM`], which names the per-key algorithm inside a
/// `/keys/claim` request/response, not the encrypted-payload algorithm.
/// Shared between [`build_device_keys_json`]'s advertised algorithm list
/// and `harmostes`'s inbound to-device filter (#437) so the string exists
/// in exactly one place.
pub(crate) const OLM_ALGORITHM: &str = "m.olm.v1.curve25519-aes-sha2";

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
    /// The Megolm message exceeds [`MEGOLM_MAX_PAYLOAD_LEN`] (issue #282
    /// finding 9) -- rejected before any allocation proportional to its
    /// length.
    MegolmMessageTooLong,
    /// The decrypting Megolm session is bound to a different room than the one
    /// the event arrived in — cross-room session confusion (audit #229).
    RoomIdMismatch,
    /// A homeserver-supplied device key failed Ed25519 self-signature
    /// verification (audit #230).
    UntrustedDeviceKey,
    /// The room id supplied for session creation is not a well-formed Matrix
    /// room identifier (#373).
    InvalidRoomId(crate::matrix_ids::MatrixIdError),
    /// The Megolm session's `message_index` has reached `u32::MAX`; encrypting
    /// further would reuse a (key, IV) pair (issue #282 finding 9). The
    /// session must be rotated.
    MegolmIndexExhausted,
    /// An inbound Megolm message named an index too far ahead of the
    /// receiving session's ratchet position (#830). Rejected before the
    /// forward-derivation walk that would otherwise be needed to reach it,
    /// bounding per-message CPU/allocation cost against a forged high index
    /// -- mirrors `krypta::ratchet`'s `MAX_SKIP_AHEAD` bound (#212).
    MegolmSkipAheadTooFar,
    /// An inbound Olm pre-key message's body did not decode to the expected
    /// `base_key || one_time_key` layout -- wrong length after decoding, or
    /// not decodable at all (#437).
    MalformedPreKeyMessage,
    /// An inbound Olm pre-key message named a one-time key this device's
    /// local pool does not currently hold. Covers BOTH a key this device
    /// never generated AND a replay of a key an earlier pre-key message
    /// already consumed (#437) -- deliberately the same disposition: the
    /// pool itself is the only record of "used", so there is no separate
    /// "already consumed" bookkeeping that could fall out of sync with it,
    /// and a caller cannot distinguish "never valid" from "already spent"
    /// by the error alone.
    UnknownOneTimeKey,
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
            Self::MegolmMessageTooLong => {
                write!(f, "Megolm message exceeds maximum accepted payload length")
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
            Self::MegolmIndexExhausted => {
                write!(
                    f,
                    "Megolm session message index exhausted -- rotate the session"
                )
            }
            Self::MegolmSkipAheadTooFar => {
                write!(
                    f,
                    "Megolm message index too far ahead of the receiving session's ratchet"
                )
            }
            Self::MalformedPreKeyMessage => {
                write!(f, "Olm pre-key message body is malformed")
            }
            Self::UnknownOneTimeKey => {
                write!(
                    f,
                    "Olm pre-key message named a one-time key not held locally"
                )
            }
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
/// Tracks a symmetric ratchet key and chain index established at session
/// creation ([`derive_olm_initial_ratchet_key`]).
///
/// WARNING: unlike [`MegolmSession`] (#830), `ratchet_key` does NOT
/// currently advance per message -- no production code path mutates it or
/// `chain_index` after [`MatrixCrypto::process_olm_prekey_message`]
/// constructs the session. There is no per-message Olm encrypt/decrypt path
/// yet (#437 tracks establishing sessions; message use is a separate,
/// unimplemented step), so this session provides no forward secrecy within
/// itself today -- `chain_index` is retained for that future ratchet step.
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
/// multiple inbound sessions (one per remote device). `session_key` is the
/// CURRENT position of a one-way ratchet, not a static root: every
/// [`encrypt_megolm`]/[`decrypt_megolm`] call that successfully authors or
/// authenticates a message advances it via [`advance_megolm_ratchet_key`]
/// and volatile-zeroes the superseded value, so no past message key is
/// recoverable from the session once advanced (#830). `message_index` is
/// the ratchet's current position (the next fresh index on the send side;
/// one past the highest index consumed in order on the receive side).
/// `skipped` is a bounded cache of message keys for indices the ratchet has
/// advanced past but that have not yet been decrypted, enabling
/// out-of-order delivery without retaining reversible ratchet state.
// WHY: no derived `Debug` — a derive would print `session_key` (and cached
// skipped-key material) in the clear (audit #268). Fields are `pub(crate)`,
// not `pub`. The manual `Debug`/`Display` impls redact all key material.
#[derive(Clone, PartialEq, Eq)]
#[must_use]
#[non_exhaustive]
pub struct MegolmSession {
    /// Unique session identifier.
    pub(crate) session_id: [u8; KEY_SIZE],
    /// Current Megolm ratchet key (256 bits) -- see struct docs (#830).
    pub(crate) session_key: [u8; KEY_SIZE],
    /// Current ratchet position (see struct docs).
    pub(crate) message_index: u32,
    /// The Matrix room ID this session is bound to.
    pub(crate) room_id: MatrixRoomId,
    /// Bounded cache of message keys for indices the ratchet has advanced
    /// past but that remain undelivered (#830). See
    /// [`MEGOLM_MAX_SKIPPED_KEYS`].
    pub(crate) skipped: Vec<SkippedMegolmKey>,
}

impl fmt::Debug for MegolmSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // WARNING: never print `session_key` or any `skipped` entry's key
        // material — redacted to prevent key leakage.
        f.debug_struct("MegolmSession")
            .field("session_id", &SessionIdRedact(&self.session_id))
            .field("session_key", &"<redacted>")
            .field("message_index", &self.message_index)
            .field("room_id", &self.room_id)
            .field("skipped_keys", &self.skipped.len())
            .finish()
    }
}

impl Drop for MegolmSession {
    fn drop(&mut self) {
        // WHY: write_volatile prevents the compiler from eliding the zeroing
        // as a dead store (audit #268 zeroization idiom, matching
        // `wifi::Ptk`'s `Drop`). Covers the live ratchet key AND every
        // cached skipped-message key -- #830's out-of-order support means
        // key material for not-yet-delivered messages also lives on this
        // struct, and it must not outlive the session either.
        zeroize_bytes(&mut self.session_key);
        for skipped in &mut self.skipped {
            zeroize_message_keys(&mut skipped.keys);
        }
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
    pub(crate) fn device_keys(&self) -> &DeviceKeys {
        &self.device_keys
    }

    /// Return the current one-time key pool.
    #[must_use]
    pub(crate) fn one_time_keys(&self) -> &[[u8; KEY_SIZE]] {
        &self.one_time_keys
    }

    /// Return the outbound Megolm sessions.
    pub(crate) fn megolm_outbound(&self) -> &[MegolmSession] {
        &self.megolm_outbound
    }

    /// Return the inbound Megolm sessions.
    pub(crate) fn megolm_inbound(&self) -> &[MegolmSession] {
        &self.megolm_inbound
    }

    /// Return the active Olm sessions.
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

    /// Remove a one-time key from the local pool after the homeserver
    /// reports it was claimed by a peer during key exchange.
    ///
    /// Without this, `one_time_keys` only ever grows: every key the
    /// homeserver has already handed to a peer for X3DH stays counted
    /// against [`MAX_ONE_TIME_KEYS`] forever, permanently deadlocking
    /// [`generate_one_time_keys`] once the pool fills (issue #282 finding
    /// 8).
    ///
    /// Returns `true` if `key` was present and removed.
    pub(crate) fn consume_one_time_key(&mut self, key: &[u8; KEY_SIZE]) -> bool {
        if let Some(idx) = self.one_time_keys.iter().position(|k| k == key) {
            self.one_time_keys.swap_remove(idx);
            true
        } else {
            false
        }
    }

    // -----------------------------------------------------------------------
    // Olm pre-key receive path (#437)
    // -----------------------------------------------------------------------

    /// Process an inbound Olm **pre-key** message (`to_device` event type
    /// `m.room.encrypted`, `content.algorithm ==` [`OLM_ALGORITHM`],
    /// ciphertext `type: 0`) addressed to this device: extract the local
    /// one-time key its sender used, consume it, and record the resulting
    /// [`OlmSession`].
    ///
    /// This is the RECEIVE side of Matrix key exchange (#437): a
    /// `/keys/claim` response (the send side, `harmostes`'s
    /// `process_claim_keys_response`) carries a *remote* device's key and
    /// never touches this pool. A pre-key message instead names one of
    /// THIS device's own uploaded keys, reporting that a peer already
    /// claimed and used it -- this is the only production call site for
    /// [`consume_one_time_key`].
    ///
    /// `sender_identity_key` is the sending device's Curve25519 identity key
    /// (the envelope's `content.sender_key`, already decoded by the caller).
    /// `body` is the already-decoded bytes of the matching
    /// `ciphertext.<our device key>.body` entry. Its layout is
    /// `base_key (32) || one_time_key (32)` -- see [`OLM_PREKEY_BODY_LEN`]
    /// for why this is a kernel-internal format rather than libolm's own
    /// encoding.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::MalformedPreKeyMessage`] if `body` is not
    /// exactly [`OLM_PREKEY_BODY_LEN`] bytes.
    /// Returns [`CryptoError::SessionCapacityReached`] if [`MAX_OLM_SESSIONS`]
    /// is already reached -- checked BEFORE consuming the named one-time
    /// key, so a session that cannot be recorded does not needlessly burn
    /// real key material this device can never get back (unlike CSPRNG
    /// output, a one-time key is not cheaply regenerable once a peer has
    /// already claimed it from the homeserver).
    /// Returns [`CryptoError::UnknownOneTimeKey`] if the named key is not
    /// present in the local pool -- this is the structural single-use
    /// enforcement: [`consume_one_time_key`] removes the key from the pool
    /// on its first successful use, so a replayed pre-key naming the same
    /// key finds the pool already empty of it and fails with the identical
    /// error a never-valid key would, with no separate "already consumed"
    /// state to go stale.
    /// Returns [`CryptoError::KeyDerivationFailed`] if HKDF fails (defensive;
    /// unreachable in practice at a 32-byte output length, mirroring
    /// [`derive_megolm_message_keys`]'s identical guard).
    ///
    /// [`consume_one_time_key`]: Self::consume_one_time_key
    pub(crate) fn process_olm_prekey_message(
        &mut self,
        sender_identity_key: &[u8; KEY_SIZE],
        body: &[u8],
    ) -> Result<(), CryptoError> {
        if body.len() != OLM_PREKEY_BODY_LEN {
            return Err(CryptoError::MalformedPreKeyMessage);
        }
        let mut base_key = [0u8; KEY_SIZE];
        let mut one_time_key = [0u8; KEY_SIZE];
        base_key.copy_from_slice(&body[..KEY_SIZE]);
        one_time_key.copy_from_slice(&body[KEY_SIZE..]);

        // WHY (capacity before consume): see the doc comment above -- a
        // session we cannot record must not cost this device a one-time key
        // it cannot recover.
        if self.olm_sessions.len() >= MAX_OLM_SESSIONS {
            return Err(CryptoError::SessionCapacityReached);
        }

        if !self.consume_one_time_key(&one_time_key) {
            return Err(CryptoError::UnknownOneTimeKey);
        }

        let ratchet_key =
            derive_olm_initial_ratchet_key(sender_identity_key, &base_key, &one_time_key)?;
        let session_id = security::sha256(&ratchet_key);

        self.olm_sessions.push(OlmSession {
            session_id,
            ratchet_key,
            chain_index: 0,
        });
        Ok(())
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
                        // WHY: a key that fails base64 decode is fail-closed
                        // excluded (found_ed stays false), not substituted
                        // with a zero/partial key -- the `found_ed &&
                        // found_curve` gate below then drops the whole
                        // device, the same disposition as a failed
                        // self-signature check (#230). Deliberate: an
                        // unparseable key from the homeserver is untrusted,
                        // not merely absent (issue #282 finding 8).
                        if let Some(decoded) = decode_base64_key(key_str) {
                            ed25519 = decoded;
                            found_ed = true;
                        }
                    } else if key_name.starts_with("curve25519:") {
                        // WHY: see the ed25519 branch above -- same policy.
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
            skipped: Vec::new(),
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
    /// A session with a `session_id` already present is REPLACED in place
    /// (matching [`create_outbound_megolm`]'s replace-on-match semantics)
    /// instead of pushed as a duplicate -- without this, an adversary
    /// resending the same `session_id` repeatedly fills all
    /// [`MAX_MEGOLM_INBOUND`] slots with copies of one session, permanently
    /// exhausting inbound capacity for every other room/device (issue #282
    /// finding 16).
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::SessionCapacityReached`] if the inbound
    /// session list is at capacity and `session.session_id` is not already
    /// present.
    ///
    /// [`create_outbound_megolm`]: Self::create_outbound_megolm
    pub(crate) fn add_inbound_megolm(&mut self, session: MegolmSession) -> Result<(), CryptoError> {
        if let Some(idx) = self
            .megolm_inbound
            .iter()
            .position(|s| s.session_id == session.session_id)
        {
            self.megolm_inbound[idx] = session;
            return Ok(());
        }
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

    /// Find an inbound Megolm session by session ID, mutably.
    ///
    /// [`decrypt_megolm`] needs `&mut MegolmSession` (#830): a successful
    /// decrypt advances the session's ratchet and/or consumes a cached
    /// skipped key, so the caller (the receive path in `harmostes`) must
    /// hold a mutable borrow through the call.
    pub(crate) fn find_inbound_megolm_mut(
        &mut self,
        session_id: &[u8; KEY_SIZE],
    ) -> Option<&mut MegolmSession> {
        self.megolm_inbound
            .iter_mut()
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
/// Uses the audited `RustCrypto` `cbc` mode over the `aes` block cipher — no
/// hand-rolled chaining (audit #231). Returns the ciphertext blocks only; the
/// IV is a caller responsibility (derived, for Megolm; prepended, for the
/// standalone helper below).
fn cbc_encrypt(key: &[u8; KEY_SIZE], iv: &[u8; AES_BLOCK_SIZE], plaintext: &[u8]) -> Vec<u8> {
    // NOTE: `encrypt_padded_vec` (cipher 0.5, no `_mut` suffix -- the
    // `BlockModeEncrypt` convenience methods now take `self` by value rather
    // than `&mut self`); `key`/`iv` convert via the infallible
    // `&[u8; N] -> &Array<u8, N>` `Into` impl, matching the cbc crate's own
    // doc example.
    CbcEncryptor::<Aes256>::new(key.into(), iv.into()).encrypt_padded_vec::<Pkcs7>(plaintext)
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
    if ciphertext.is_empty() || !ciphertext.len().is_multiple_of(AES_BLOCK_SIZE) {
        return Err(CryptoError::InvalidCiphertextLength);
    }
    // NOTE: see cbc_encrypt's NOTE -- `decrypt_padded_vec` (no `_mut`), same
    // `&[u8; N] -> &Array<u8, N>` conversion.
    CbcDecryptor::<Aes256>::new(key.into(), iv.into())
        .decrypt_padded_vec::<Pkcs7>(ciphertext)
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
// HKDF-SHA256 expansion of the ratchet key AT `message_index` — so the IV is
// derived, never transmitted, and unique per (key, index). The MAC is the
// first 8 bytes of HMAC-SHA256 over the transmitted body preceding the tag
// (`message_index || ciphertext`, matching libolm which MACs the whole message
// body; strictly stronger than ciphertext-only because it also authenticates
// the index selector). Decrypt verifies the MAC in constant time BEFORE
// touching the ciphertext, which closes the padding-oracle / bit-flipping /
// forgery classes.
//
// #830: "the ratchet key at `message_index`" is now literal, not aspirational
// -- `MegolmSession::session_key` is a one-way ratchet position, not a static
// root. `encrypt_megolm`/`decrypt_megolm` derive this message's keys from the
// CURRENT ratchet key, then irreversibly advance it via
// `advance_megolm_ratchet_key` (a domain-separated HKDF step, so a message
// key can never be inverted back into ratchet state) and volatile-zero the
// superseded value. Out-of-order delivery is served by a bounded
// `session.skipped` cache of already-derived message keys for indices the
// ratchet has advanced past but not yet delivered -- the ratchet itself only
// ever moves forward, so no past ratchet state is retained in reversible
// form.

/// The three key sections derived from a Megolm ratchet key for one message.
#[derive(Clone, PartialEq, Eq)]
struct MegolmMessageKeys {
    /// AES-256-CBC encryption key.
    aes_key: [u8; KEY_SIZE],
    /// HMAC-SHA256 authentication key.
    hmac_key: [u8; KEY_SIZE],
    /// AES-CBC initialization vector (derived, not transmitted).
    iv: [u8; AES_BLOCK_SIZE],
}

/// A message key retained for an out-of-order Megolm message whose index the
/// ratchet has advanced past but that has not yet been decrypted (#830).
/// Consumed (removed) on first successful use, matching
/// `krypta::ratchet::SkippedKey`'s single-use semantics.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct SkippedMegolmKey {
    /// The message index this cached key belongs to.
    index: u32,
    /// The AES/HMAC/IV material for that index.
    keys: MegolmMessageKeys,
}

/// Overwrite `buf` with zeros using a volatile write per byte.
///
/// Matches the zeroization idiom already used in this repo (`wifi::Ptk`'s
/// `Drop`, `krypta::ratchet`): `write_volatile` prevents the compiler from
/// eliding the store as a dead write, so superseded key material does not
/// linger in memory after a ratchet advances or a cache entry is evicted.
fn zeroize_bytes(buf: &mut [u8]) {
    for byte in buf.iter_mut() {
        // SAFETY: byte is a valid mutable reference to initialized memory.
        unsafe {
            core::ptr::write_volatile(byte, 0);
        }
    }
}

/// Zero every key field of a [`MegolmMessageKeys`] in place.
fn zeroize_message_keys(keys: &mut MegolmMessageKeys) {
    zeroize_bytes(&mut keys.aes_key);
    zeroize_bytes(&mut keys.hmac_key);
    zeroize_bytes(&mut keys.iv);
}

/// Encrypt a plaintext message with a Megolm session (AES-256-CBC + HMAC-SHA256).
///
/// Produces the authenticated wire payload described above, then advances
/// the session's ratchet (#830): the key just used is never re-derivable
/// from the session's post-send state, and the superseded value is
/// volatile-zeroed rather than merely overwritten. The receiver reads the
/// embedded index to derive the matching per-message keys (audit #250).
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
    // WHY: message_index is the HKDF derivation input for this message's
    // (AES key, HMAC key, IV) -- see derive_megolm_message_keys. Reject
    // BEFORE deriving/encrypting once no fresh index remains: the old
    // `saturating_add` let message_index sit at u32::MAX forever, so every
    // later call re-derived and reused the SAME (key, IV) pair, breaking
    // AES-CBC's IND-CPA guarantee (issue #282 finding 9). The session must
    // be rotated (a fresh create_outbound_megolm) instead.
    let next_index = index
        .checked_add(1)
        .ok_or(CryptoError::MegolmIndexExhausted)?;

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

    // #830: advance the ratchet irreversibly now that the message this
    // index's key encrypted has been produced -- `next_key` is a one-way
    // HKDF step domain-separated from message-key derivation (see
    // `advance_megolm_ratchet_key`), and the superseded key is
    // volatile-zeroed, not merely overwritten (matches `wifi::Ptk::drop`).
    let next_key = advance_megolm_ratchet_key(&session.session_key)?;
    zeroize_bytes(&mut session.session_key);
    session.session_key = next_key;
    session.message_index = next_index;
    Ok(payload)
}

/// Decrypt and authenticate a Megolm wire payload against a session.
///
/// Verifies, in order: the session is bound to `expected_room_id` (audit
/// #229), the payload carries an index + MAC (audit #250), and the MAC
/// matches in constant time BEFORE any decryption (audit #231). Only then is
/// the AES-CBC ciphertext decrypted.
///
/// Handles three cases relative to the session's current ratchet position
/// (#830):
/// - **In order** (`index == session.message_index`): decrypts directly and
///   advances the ratchet by one step.
/// - **Ahead** (`index > session.message_index`, within
///   [`MEGOLM_MAX_SKIP_AHEAD`]): walks the ratchet forward on a trial copy,
///   caching each intermediate message key in `session.skipped` (bounded by
///   [`MEGOLM_MAX_SKIPPED_KEYS`]) for messages that have not yet arrived,
///   then decrypts at the target index and commits the advance. Nothing is
///   mutated unless the target message authenticates.
/// - **Behind** (`index < session.message_index`): served from
///   `session.skipped` if a cached key for that index exists; the cached key
///   is consumed (removed) on success, giving replay rejection for an
///   already-decrypted index.
///
/// `expected_room_id` is the room the event actually arrived in (from the sync
/// response grouping), NOT a value taken from the untrusted event body.
///
/// # Errors
///
/// [`CryptoError::RoomIdMismatch`] on cross-room confusion;
/// [`CryptoError::MegolmMessageTooShort`] on a truncated payload;
/// [`CryptoError::MegolmMessageTooLong`] on an oversized payload;
/// [`CryptoError::MegolmSkipAheadTooFar`] if `index` is too far ahead of the
/// ratchet to reach;
/// [`CryptoError::MacVerificationFailed`] on a forged / tampered MAC, an
/// index behind the ratchet with no cached key, or a replayed already-consumed
/// index;
/// [`CryptoError::KeyDerivationFailed`] / [`CryptoError::InvalidCiphertextLength`]
/// / [`CryptoError::InvalidPadding`] on structural failures.
pub(crate) fn decrypt_megolm(
    session: &mut MegolmSession,
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

    // #282 finding 9: reject an oversized payload BEFORE the MAC check or
    // any allocation proportional to its length.
    if payload.len() > MEGOLM_MAX_PAYLOAD_LEN {
        return Err(CryptoError::MegolmMessageTooLong);
    }

    let (body, tag) = payload.split_at(payload.len() - MEGOLM_MAC_LEN);
    let mut index_bytes = [0u8; MEGOLM_INDEX_LEN];
    index_bytes.copy_from_slice(&body[..MEGOLM_INDEX_LEN]);
    let index = u32::from_be_bytes(index_bytes);
    let ciphertext = &body[MEGOLM_INDEX_LEN..];

    // #830: an index behind the ratchet can only be served from the skipped
    // cache -- the ratchet itself never moves backward.
    if index < session.message_index {
        return decrypt_megolm_from_skipped(session, index, body, tag, ciphertext);
    }

    // WHY(#830): bound the forward jump so a forged high index cannot force
    // unbounded key derivation (mirrors #212's MAX_SKIP_AHEAD bound).
    let gap = index - session.message_index;
    if gap > MEGOLM_MAX_SKIP_AHEAD {
        return Err(CryptoError::MegolmSkipAheadTooFar);
    }

    // Trial-walk the ratchet forward on a working copy; nothing on `session`
    // is mutated until the target message authenticates.
    let mut work_key = session.session_key;
    let mut pending: Vec<SkippedMegolmKey> = Vec::with_capacity(gap as usize);
    let mut idx = session.message_index;
    while idx < index {
        let msg_keys = derive_megolm_message_keys(&work_key, idx)?;
        pending.push(SkippedMegolmKey {
            index: idx,
            keys: msg_keys,
        });
        let next = advance_megolm_ratchet_key(&work_key)?;
        // WHY: `work_key` is a stack-local trial copy of ratchet state that
        // is about to be superseded -- zero it before overwriting so an
        // intermediate step does not linger in memory even on this
        // not-yet-committed path.
        zeroize_bytes(&mut work_key);
        work_key = next;
        idx += 1;
    }

    let target_keys = derive_megolm_message_keys(&work_key, index)?;

    // #231: verify the MAC in constant time BEFORE decrypting. `body` is
    // `index || ciphertext`; the transmitted tag is the first 8 HMAC bytes.
    let expected = security::hmac_sha256(&target_keys.hmac_key, body);
    if !bool::from(expected[..MEGOLM_MAC_LEN].ct_eq(tag)) {
        zeroize_bytes(&mut work_key);
        return Err(CryptoError::MacVerificationFailed);
    }

    let plaintext = match cbc_decrypt(&target_keys.aes_key, &target_keys.iv, ciphertext) {
        Ok(p) => p,
        Err(e) => {
            zeroize_bytes(&mut work_key);
            return Err(e);
        }
    };

    // Authenticated: commit the skipped keys and advance the ratchet one
    // step past the message just decrypted, so an in-order follow-up needs
    // no re-derivation.
    for skipped in pending {
        store_skipped_megolm(session, skipped);
    }
    let post = advance_megolm_ratchet_key(&work_key)?;
    zeroize_bytes(&mut work_key);
    zeroize_bytes(&mut session.session_key);
    session.session_key = post;
    // WHY: saturate rather than wrap at `u32::MAX` -- `encrypt_megolm`
    // refuses to ever PRODUCE that index (`MegolmIndexExhausted`, issue #282
    // finding 9's (key, IV)-reuse concern), so a message claiming it can
    // only be a forgery from a peer that already holds the session key.
    // Wrapping to 0 here would let that forgery reset this session's ratchet
    // position and desynchronize it from the real sender; saturating instead
    // freezes the session at its terminal index, matching "must be rotated".
    session.message_index = index.checked_add(1).unwrap_or(u32::MAX);

    Ok(plaintext)
}

/// Decrypt a Megolm message whose index is behind the session's ratchet,
/// using the bounded skipped-key cache (#830). The cached key is consumed
/// (removed and zeroed) only on successful authentication -- single-use,
/// giving replay rejection for an already-decrypted index -- mirroring
/// `krypta::ratchet::decrypt_from_skipped`.
///
/// A missing cache entry (never skipped, or already consumed) is reported
/// identically to a forged MAC: from the caller's perspective both mean
/// "this message cannot be authenticated with this session right now", and
/// this module already applies that same-disposition policy elsewhere (see
/// [`CryptoError::UnknownOneTimeKey`]'s doc).
fn decrypt_megolm_from_skipped(
    session: &mut MegolmSession,
    index: u32,
    body: &[u8],
    tag: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cache_idx = session
        .skipped
        .iter()
        .position(|k| k.index == index)
        .ok_or(CryptoError::MacVerificationFailed)?;

    let expected = security::hmac_sha256(&session.skipped[cache_idx].keys.hmac_key, body);
    if !bool::from(expected[..MEGOLM_MAC_LEN].ct_eq(tag)) {
        return Err(CryptoError::MacVerificationFailed);
    }

    let plaintext = cbc_decrypt(
        &session.skipped[cache_idx].keys.aes_key,
        &session.skipped[cache_idx].keys.iv,
        ciphertext,
    )?;

    // Consume: remove and zero, so a replay of this index finds no cache
    // entry (same disposition as any other unrecoverable index).
    let mut consumed = session.skipped.remove(cache_idx);
    zeroize_message_keys(&mut consumed.keys);

    Ok(plaintext)
}

/// Insert a skipped Megolm message key, evicting (and zeroing) the oldest
/// entry beyond [`MEGOLM_MAX_SKIPPED_KEYS`] so the cache is provably bounded
/// regardless of traffic (#830, mirrors `krypta::ratchet::store_skipped`).
fn store_skipped_megolm(session: &mut MegolmSession, key: SkippedMegolmKey) {
    session.skipped.push(key);
    while session.skipped.len() > MEGOLM_MAX_SKIPPED_KEYS {
        // WHY: zero the evicted entry's key material before dropping it --
        // a plain `remove` would let the compiler treat the freed bytes as
        // dead and skip clearing them.
        let mut evicted = session.skipped.remove(0);
        zeroize_message_keys(&mut evicted.keys);
    }
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

/// One-way step: derive the NEXT Megolm ratchet key from the current one via
/// HKDF-SHA256, under a label distinct from [`derive_megolm_message_keys`]
/// (#830). This domain separation means a message key can never be mistaken
/// for -- or algebraically related to -- ratchet state: HKDF-Expand is a PRF,
/// so recovering `ratchet_key` from `next` (or from any message key derived
/// under the OTHER label) is computationally infeasible. Once the caller
/// volatile-zeroes the prior `ratchet_key` after this call, no message key at
/// or before this step is reproducible from the session -- the forward-secrecy
/// property this module's docs claim.
fn advance_megolm_ratchet_key(ratchet_key: &[u8; KEY_SIZE]) -> Result<[u8; KEY_SIZE], CryptoError> {
    const LABEL: &[u8] = b"megolm-ratchet-advance";
    let mut next = [0u8; KEY_SIZE];
    security::hkdf_sha256(ratchet_key, &[], LABEL, &mut next)
        .map_err(|_| CryptoError::KeyDerivationFailed)?;
    Ok(next)
}

/// Derive a new Olm session's initial ratchet key from an inbound pre-key
/// message's key material (#437).
///
/// A simplified X3DH substitute: this module's device/one-time keys are
/// CSPRNG-derived values used directly as HKDF input rather than real
/// Curve25519 points (module docs), so there are no DH outputs to combine --
/// the three key values (sender identity, sender ephemeral, and the
/// consumed local one-time key) are concatenated as HKDF input key material
/// instead, matching this module's existing departure from full X3DH.
///
/// # Errors
///
/// Returns [`CryptoError::KeyDerivationFailed`] if HKDF fails (defensive;
/// unreachable at this fixed 32-byte output length).
fn derive_olm_initial_ratchet_key(
    sender_identity_key: &[u8; KEY_SIZE],
    base_key: &[u8; KEY_SIZE],
    one_time_key: &[u8; KEY_SIZE],
) -> Result<[u8; KEY_SIZE], CryptoError> {
    const LABEL: &[u8] = b"olm-prekey-session";
    let mut ikm = [0u8; KEY_SIZE * 3];
    ikm[..KEY_SIZE].copy_from_slice(sender_identity_key);
    ikm[KEY_SIZE..KEY_SIZE * 2].copy_from_slice(base_key);
    ikm[KEY_SIZE * 2..].copy_from_slice(one_time_key);

    let mut ratchet_key = [0u8; KEY_SIZE];
    security::hkdf_sha256(&ikm, &[], LABEL, &mut ratchet_key)
        .map_err(|_| CryptoError::KeyDerivationFailed)?;
    Ok(ratchet_key)
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
    w.string_value(OLM_ALGORITHM);
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
        let mut key_name = String::from(ONE_TIME_KEY_ALGORITHM);
        key_name.push_str(":AAAAAA");
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
    if !s.len().is_multiple_of(2) {
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
///
/// `pub(crate)`: also used by `harmostes`'s `/keys/claim` response handling
/// to decode a claimed one-time key value (#437) -- the same key-encoding
/// convention as `/keys/query` device keys, one decoder for both.
pub(crate) fn decode_base64_key(s: &str) -> Option<[u8; KEY_SIZE]> {
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

    #[test]
    fn encrypt_megolm_refuses_to_reuse_index_at_saturation() {
        setup_test_rng();
        let mut session = MegolmSession {
            session_id: [0u8; KEY_SIZE],
            session_key: [1u8; KEY_SIZE],
            message_index: u32::MAX,
            room_id: MatrixRoomId::new("!test:matrix.example.com").expect("valid test room id"),
            skipped: Vec::new(),
        };

        let result = encrypt_megolm(&mut session, b"one message too many");
        assert_eq!(result, Err(CryptoError::MegolmIndexExhausted));
        assert_eq!(
            session.message_index,
            u32::MAX,
            "index must not be mutated on refusal"
        );
    }

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

    #[test]
    fn consume_one_time_key_frees_capacity_for_regeneration() {
        setup_test_rng();
        let mut crypto = MatrixCrypto::new().expect("test csprng seeded");

        crypto
            .generate_one_time_keys(MAX_GENERATED_KEYS as u32)
            .expect("first batch must succeed");
        crypto
            .generate_one_time_keys(MAX_GENERATED_KEYS as u32)
            .expect("second batch must fill the pool to exactly capacity");
        assert_eq!(crypto.one_time_keys().len(), MAX_ONE_TIME_KEYS);

        assert_eq!(
            crypto.generate_one_time_keys(1),
            Err(CryptoError::KeyCapacityReached)
        );

        let claimed = crypto.one_time_keys()[0];
        assert!(
            crypto.consume_one_time_key(&claimed),
            "a present key must be removed"
        );
        assert_eq!(crypto.one_time_keys().len(), MAX_ONE_TIME_KEYS - 1);
        assert!(
            crypto.generate_one_time_keys(1).is_ok(),
            "freeing a slot must unblock regeneration"
        );

        assert!(
            !crypto.consume_one_time_key(&claimed),
            "consuming an already-removed key must return false, not panic"
        );
    }

    // -- Olm pre-key receive-path tests (#437) --

    /// Build a wire body matching this kernel's pre-key layout:
    /// `base_key || one_time_key`.
    fn prekey_body(base_key: &[u8; KEY_SIZE], one_time_key: &[u8; KEY_SIZE]) -> Vec<u8> {
        let mut body = Vec::with_capacity(OLM_PREKEY_BODY_LEN);
        body.extend_from_slice(base_key);
        body.extend_from_slice(one_time_key);
        body
    }

    #[test]
    fn process_olm_prekey_message_consumes_named_key_and_establishes_session() {
        setup_test_rng();
        let mut crypto = MatrixCrypto::new().expect("test csprng seeded");
        let otk = crypto
            .generate_one_time_keys(1)
            .expect("seeding must succeed")[0];

        let sender_identity_key = [0x11u8; KEY_SIZE];
        let base_key = [0x22u8; KEY_SIZE];
        let body = prekey_body(&base_key, &otk);

        let result = crypto.process_olm_prekey_message(&sender_identity_key, &body);
        assert!(result.is_ok(), "a valid pre-key message must be accepted");
        assert!(
            !crypto.one_time_keys().contains(&otk),
            "the claimed key must leave the local pool"
        );
        assert_eq!(
            crypto.olm_sessions().len(),
            1,
            "a valid pre-key message must establish exactly one session"
        );
    }

    #[test]
    fn process_olm_prekey_message_rejects_replay() {
        setup_test_rng();
        let mut crypto = MatrixCrypto::new().expect("test csprng seeded");
        let otk = crypto
            .generate_one_time_keys(1)
            .expect("seeding must succeed")[0];
        let sender_identity_key = [0x33u8; KEY_SIZE];
        let base_key = [0x44u8; KEY_SIZE];
        let body = prekey_body(&base_key, &otk);

        assert!(
            crypto
                .process_olm_prekey_message(&sender_identity_key, &body)
                .is_ok(),
            "the first delivery of a valid pre-key message must succeed"
        );
        assert_eq!(crypto.olm_sessions().len(), 1);

        let replay = crypto.process_olm_prekey_message(&sender_identity_key, &body);
        assert_eq!(
            replay,
            Err(CryptoError::UnknownOneTimeKey),
            "a replayed pre-key message naming an already-consumed key must be rejected"
        );
        assert_eq!(
            crypto.olm_sessions().len(),
            1,
            "a rejected replay must not establish a second session"
        );
    }

    #[test]
    fn process_olm_prekey_message_rejects_unknown_key() {
        setup_test_rng();
        let mut crypto = MatrixCrypto::new().expect("test csprng seeded");
        // Never generated or uploaded by this device.
        let never_ours = [0x55u8; KEY_SIZE];
        let sender_identity_key = [0x66u8; KEY_SIZE];
        let base_key = [0x77u8; KEY_SIZE];
        let body = prekey_body(&base_key, &never_ours);

        let result = crypto.process_olm_prekey_message(&sender_identity_key, &body);
        assert_eq!(result, Err(CryptoError::UnknownOneTimeKey));
        assert!(
            crypto.olm_sessions().is_empty(),
            "an unknown-key pre-key message must not establish a session"
        );
    }

    #[test]
    fn process_olm_prekey_message_rejects_malformed_body_length() {
        setup_test_rng();
        let mut crypto = MatrixCrypto::new().expect("test csprng seeded");
        let sender_identity_key = [0x88u8; KEY_SIZE];

        let short_body = alloc::vec![0u8; OLM_PREKEY_BODY_LEN - 1];
        assert_eq!(
            crypto.process_olm_prekey_message(&sender_identity_key, &short_body),
            Err(CryptoError::MalformedPreKeyMessage)
        );

        let long_body = alloc::vec![0u8; OLM_PREKEY_BODY_LEN + 1];
        assert_eq!(
            crypto.process_olm_prekey_message(&sender_identity_key, &long_body),
            Err(CryptoError::MalformedPreKeyMessage)
        );

        assert!(crypto.olm_sessions().is_empty());
    }

    #[test]
    fn process_olm_prekey_message_enforces_session_capacity_without_burning_key() {
        setup_test_rng();
        let mut crypto = MatrixCrypto::new().expect("test csprng seeded");

        for i in 0..MAX_OLM_SESSIONS {
            let otk = crypto
                .generate_one_time_keys(1)
                .expect("filling below capacity must succeed")[0];
            let sender_byte = u8::try_from(i).expect("MAX_OLM_SESSIONS fits in u8 range");
            let sender_identity_key = [sender_byte; KEY_SIZE];
            let base_key = [0xAAu8; KEY_SIZE];
            let body = prekey_body(&base_key, &otk);
            crypto
                .process_olm_prekey_message(&sender_identity_key, &body)
                .expect("filling below capacity must succeed");
        }
        assert_eq!(crypto.olm_sessions().len(), MAX_OLM_SESSIONS);

        let overflow_otk = crypto
            .generate_one_time_keys(1)
            .expect("seeding must succeed")[0];
        let before = crypto.one_time_keys().len();
        let body = prekey_body(&[0xBBu8; KEY_SIZE], &overflow_otk);
        let result = crypto.process_olm_prekey_message(&[0xFFu8; KEY_SIZE], &body);

        assert_eq!(result, Err(CryptoError::SessionCapacityReached));
        assert_eq!(
            crypto.one_time_keys().len(),
            before,
            "a session that cannot be recorded must not consume the one-time key"
        );
        assert_eq!(crypto.olm_sessions().len(), MAX_OLM_SESSIONS);
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
    fn aes256_cbc_corrupted_padding_byte_fails() {
        setup_test_rng();
        let key = [0u8; KEY_SIZE];
        // WHY: a plaintext of exactly one block forces PKCS#7 to append a
        // full padding block (16 bytes, each valued 0x10).
        let plaintext = b"exactly16bytes!!";
        let ciphertext = aes256_cbc_encrypt(&key, plaintext);
        assert!(ciphertext.is_ok());
        let mut ciphertext = ciphertext.unwrap_or_default();

        // WHY: CBC decryption computes P[n] = D(C[n]) XOR C[n-1], so
        // flipping a bit in the last byte of the first ciphertext block
        // (chained into the final padding block) flips the same bit,
        // deterministically, in the final block's last decrypted byte --
        // independent of key. 0x10 (padding length 16) XOR 0x01 = 0x11
        // (17), which exceeds the 16-byte block size, so PKCS#7 unpadding
        // must reject it.
        let flip_index = AES_BLOCK_SIZE + AES_BLOCK_SIZE - 1;
        ciphertext[flip_index] ^= 0x01;

        let result = aes256_cbc_decrypt(&key, &ciphertext);
        assert_eq!(result, Err(CryptoError::InvalidPadding));
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

    #[test]
    fn aes256_cbc_non_block_multiple_length_fails() {
        let key = [0u8; KEY_SIZE];
        // WHY: data.len() == 33 clears the CiphertextTooShort floor (IV +
        // one block = 32) but the ciphertext portion (33 - 16 = 17 bytes)
        // is not a multiple of AES_BLOCK_SIZE, hitting the
        // InvalidCiphertextLength guard in cbc_decrypt.
        let data = [0u8; AES_BLOCK_SIZE * 2 + 1];
        let result = aes256_cbc_decrypt(&key, &data);
        assert_eq!(result, Err(CryptoError::InvalidCiphertextLength));
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
        let mut inbound = session.cloned().unwrap_or_else(|| MegolmSession {
            session_id: [0u8; KEY_SIZE],
            session_key: [0u8; KEY_SIZE],
            message_index: 0,
            room_id: MatrixRoomId::new("!fallback:test").expect("valid test room id"),
            skipped: Vec::new(),
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
        let decrypted = decrypt_megolm(&mut inbound, &ciphertext, room_id);
        assert!(decrypted.is_ok());
        assert_eq!(decrypted.unwrap_or_default().as_slice(), plaintext);
    }

    #[test]
    fn megolm_mac_rejects_flipped_ciphertext_bit() {
        setup_test_rng();
        let mut crypto = MatrixCrypto::new().expect("test csprng seeded");
        let room_id = "!mac:matrix.example.com";
        let _ = crypto.create_outbound_megolm(room_id);

        let mut inbound = crypto
            .find_outbound_megolm(room_id)
            .cloned()
            .expect("session exists");

        let mut ciphertext =
            encrypt_megolm(&mut crypto.megolm_outbound[0], b"authenticated secret")
                .expect("encrypt");

        // Flip one bit inside the AES-CBC ciphertext region (after the 4-byte
        // index prefix, before the 8-byte MAC).
        let flip = 4 + 1;
        ciphertext[flip] ^= 0x01;

        let result = decrypt_megolm(&mut inbound, &ciphertext, room_id);
        assert_eq!(
            result,
            Err(CryptoError::MacVerificationFailed),
            "a flipped ciphertext bit must be rejected by the MAC before decryption"
        );
    }

    #[test]
    fn megolm_decrypt_rejects_oversized_payload_before_allocating() {
        setup_test_rng();
        let mut crypto = MatrixCrypto::new().expect("test csprng seeded");
        let room_id = "!oversized:matrix.example.com";
        let _ = crypto.create_outbound_megolm(room_id);
        let mut inbound = crypto
            .find_outbound_megolm(room_id)
            .cloned()
            .expect("session exists");

        let oversized = alloc::vec![0u8; MEGOLM_MAX_PAYLOAD_LEN + 1];
        let result = decrypt_megolm(&mut inbound, &oversized, room_id);
        assert_eq!(result, Err(CryptoError::MegolmMessageTooLong));
    }

    #[test]
    fn megolm_mac_rejects_tampered_tag() {
        setup_test_rng();
        let mut crypto = MatrixCrypto::new().expect("test csprng seeded");
        let room_id = "!tag:matrix.example.com";
        let _ = crypto.create_outbound_megolm(room_id);
        let mut inbound = crypto
            .find_outbound_megolm(room_id)
            .cloned()
            .expect("session exists");

        let mut ct = encrypt_megolm(&mut crypto.megolm_outbound[0], b"tag test").expect("encrypt");
        let last = ct.len() - 1;
        ct[last] ^= 0xff;

        assert_eq!(
            decrypt_megolm(&mut inbound, &ct, room_id),
            Err(CryptoError::MacVerificationFailed)
        );
    }

    #[test]
    fn megolm_wrong_room_id_rejected() {
        setup_test_rng();
        let mut crypto = MatrixCrypto::new().expect("test csprng seeded");
        let room_id = "!bound:matrix.example.com";
        let _ = crypto.create_outbound_megolm(room_id);
        let mut inbound = crypto
            .find_outbound_megolm(room_id)
            .cloned()
            .expect("session exists");

        let ct =
            encrypt_megolm(&mut crypto.megolm_outbound[0], b"room-bound message").expect("encrypt");

        // The session is bound to `room_id`; decrypting as if the event arrived
        // in a different room must be rejected before any MAC/crypto work.
        assert_eq!(
            decrypt_megolm(&mut inbound, &ct, "!attacker:matrix.example.com"),
            Err(CryptoError::RoomIdMismatch)
        );
        // Correct room still decrypts.
        assert!(decrypt_megolm(&mut inbound, &ct, room_id).is_ok());
    }

    #[test]
    fn megolm_out_of_order_index_decrypts() {
        setup_test_rng();
        let mut crypto = MatrixCrypto::new().expect("test csprng seeded");
        let room_id = "!ooo:matrix.example.com";
        let _ = crypto.create_outbound_megolm(room_id);
        let mut inbound = crypto
            .find_outbound_megolm(room_id)
            .cloned()
            .expect("session exists");

        // Encrypt three messages (indices 0, 1, 2).
        let c0 = encrypt_megolm(&mut crypto.megolm_outbound[0], b"first").expect("encrypt 0");
        let c1 = encrypt_megolm(&mut crypto.megolm_outbound[0], b"second").expect("encrypt 1");
        let c2 = encrypt_megolm(&mut crypto.megolm_outbound[0], b"third").expect("encrypt 2");
        assert_eq!(crypto.megolm_outbound[0].message_index, 3);

        // Decrypt out of order — each payload carries its own index (audit
        // #250). #830: c2 arriving first is served directly and caches
        // message keys for indices 0 and 1 in `inbound.skipped` as the
        // ratchet walks forward past them; c0 and c1 are then served from
        // that cache (single-use, consumed on read).
        assert_eq!(
            decrypt_megolm(&mut inbound, &c2, room_id)
                .expect("d2")
                .as_slice(),
            b"third"
        );
        assert_eq!(
            inbound.skipped.len(),
            2,
            "decrypting index 2 first must cache message keys for the skipped indices 0 and 1"
        );
        assert_eq!(
            decrypt_megolm(&mut inbound, &c0, room_id)
                .expect("d0")
                .as_slice(),
            b"first"
        );
        assert_eq!(
            decrypt_megolm(&mut inbound, &c1, room_id)
                .expect("d1")
                .as_slice(),
            b"second"
        );
        assert!(
            inbound.skipped.is_empty(),
            "both skipped keys must be consumed after their messages decrypt"
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
            &mut crypto.megolm_outbound[1],
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
    fn create_outbound_megolm_at_capacity_returns_session_capacity_reached() {
        setup_test_rng();
        let mut crypto = MatrixCrypto::new().expect("test csprng seeded");

        for i in 0..MAX_MEGOLM_OUTBOUND {
            let room = alloc::format!("!room{i}:example.com");
            assert!(
                crypto.create_outbound_megolm(&room).is_ok(),
                "filling the outbound pool to capacity must succeed"
            );
        }
        assert_eq!(crypto.megolm_outbound.len(), MAX_MEGOLM_OUTBOUND);

        let overflow_room = alloc::format!("!room{MAX_MEGOLM_OUTBOUND}:example.com");
        assert_eq!(
            crypto.create_outbound_megolm(&overflow_room),
            Err(CryptoError::SessionCapacityReached),
            "a genuinely new room past capacity must be rejected, not silently evict"
        );
        assert_eq!(crypto.megolm_outbound.len(), MAX_MEGOLM_OUTBOUND);
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
            skipped: Vec::new(),
        };

        let result = crypto.add_inbound_megolm(session);
        assert!(result.is_ok());

        let found = crypto.find_inbound_megolm(&[0x42; KEY_SIZE]);
        assert!(found.is_some());

        let not_found = crypto.find_inbound_megolm(&[0x00; KEY_SIZE]);
        assert!(not_found.is_none());
    }

    #[test]
    fn add_inbound_megolm_duplicate_session_id_replaces_not_duplicates() {
        setup_test_rng();
        let mut crypto = MatrixCrypto::new().expect("test csprng seeded");

        let room_a = MatrixRoomId::new("!a:example.com").expect("valid test room id");
        let room_b = MatrixRoomId::new("!b:example.com").expect("valid test room id");

        for _ in 0..MAX_MEGOLM_INBOUND {
            let session = MegolmSession {
                session_id: [0x11; KEY_SIZE],
                session_key: [0xFF; KEY_SIZE],
                message_index: 0,
                room_id: room_a.clone(),
                skipped: Vec::new(),
            };
            assert!(crypto.add_inbound_megolm(session).is_ok());
        }
        assert_eq!(
            crypto.megolm_inbound().len(),
            1,
            "resending the same session_id must replace, not accumulate duplicates"
        );

        let fresh = MegolmSession {
            session_id: [0x22; KEY_SIZE],
            session_key: [0xEE; KEY_SIZE],
            message_index: 0,
            room_id: room_b,
            skipped: Vec::new(),
        };
        assert!(
            crypto.add_inbound_megolm(fresh).is_ok(),
            "capacity must still be available for a genuinely new session after duplicate resends"
        );
        assert_eq!(crypto.megolm_inbound().len(), 2);
    }

    #[test]
    fn add_inbound_megolm_at_capacity_returns_session_capacity_reached() {
        setup_test_rng();
        let mut crypto = MatrixCrypto::new().expect("test csprng seeded");
        let room = MatrixRoomId::new("!room:example.com").expect("valid test room id");

        for i in 0..MAX_MEGOLM_INBOUND {
            let session_id_byte = u8::try_from(i).expect("MAX_MEGOLM_INBOUND fits in u8 range");
            let session = MegolmSession {
                session_id: [session_id_byte; KEY_SIZE],
                session_key: [0xFF; KEY_SIZE],
                message_index: 0,
                room_id: room.clone(),
                skipped: Vec::new(),
            };
            assert!(
                crypto.add_inbound_megolm(session).is_ok(),
                "filling the inbound pool to capacity must succeed"
            );
        }
        assert_eq!(crypto.megolm_inbound().len(), MAX_MEGOLM_INBOUND);

        let overflow = MegolmSession {
            session_id: [0xAA; KEY_SIZE],
            session_key: [0xBB; KEY_SIZE],
            message_index: 0,
            room_id: room,
            skipped: Vec::new(),
        };
        assert_eq!(
            crypto.add_inbound_megolm(overflow),
            Err(CryptoError::SessionCapacityReached),
            "a genuinely new session_id past capacity must be rejected, not silently evict"
        );
        assert_eq!(crypto.megolm_inbound().len(), MAX_MEGOLM_INBOUND);
    }

    // -- Ratchet / forward-secrecy tests (#830) --

    #[test]
    fn megolm_ratchet_key_advances_after_encrypt() {
        setup_test_rng();
        let mut crypto = MatrixCrypto::new().expect("test csprng seeded");
        let room_id = "!ratchet:matrix.example.com";
        let _ = crypto.create_outbound_megolm(room_id);

        let key_before = crypto.megolm_outbound[0].session_key;
        let _ = encrypt_megolm(&mut crypto.megolm_outbound[0], b"advance me").expect("encrypt");
        let key_after = crypto.megolm_outbound[0].session_key;

        assert_ne!(
            key_before, key_after,
            "the session's ratchet key must change after encrypting a message"
        );
    }

    #[test]
    fn megolm_message_key_at_index_not_reproducible_from_post_advance_state() {
        // The defining forward-secrecy property (#830): once the ratchet has
        // advanced past an index, that index's message key must not be
        // re-derivable from the session's current state.
        setup_test_rng();
        let mut crypto = MatrixCrypto::new().expect("test csprng seeded");
        let room_id = "!forward-secrecy:matrix.example.com";
        let _ = crypto.create_outbound_megolm(room_id);

        // The ratchet key actually used to derive index 0's message key,
        // captured BEFORE any advance.
        let root_at_0 = crypto.megolm_outbound[0].session_key;
        let keys0_actual = derive_megolm_message_keys(&root_at_0, 0).expect("derive");

        // Advance the ratchet past indices 0 and 1.
        let _ = encrypt_megolm(&mut crypto.megolm_outbound[0], b"first").expect("encrypt 0");
        let _ = encrypt_megolm(&mut crypto.megolm_outbound[0], b"second").expect("encrypt 1");

        // Attempt to reconstruct index 0's message key from the session's
        // CURRENT (post-advance) ratchet key.
        let root_after_advance = crypto.megolm_outbound[0].session_key;
        let keys0_from_post_advance =
            derive_megolm_message_keys(&root_after_advance, 0).expect("derive");

        assert!(
            keys0_actual != keys0_from_post_advance,
            "index 0's message key must not be reconstructable from the \
             ratchet's post-advance state -- a reversible advance is not a \
             ratchet"
        );
    }

    #[test]
    fn megolm_skip_ahead_beyond_bound_is_rejected() {
        setup_test_rng();
        let mut crypto = MatrixCrypto::new().expect("test csprng seeded");
        let room_id = "!skip-bound:matrix.example.com";
        let _ = crypto.create_outbound_megolm(room_id);
        let mut inbound = crypto
            .find_outbound_megolm(room_id)
            .cloned()
            .expect("session exists");

        // A genuine message, with its wire index forged far beyond the
        // receiving session's ratchet position. The skip-ahead bound is
        // checked before any MAC/key derivation work, so the forgery
        // doesn't need a valid MAC for this index to prove the point.
        let mut ct =
            encrypt_megolm(&mut crypto.megolm_outbound[0], b"forged index").expect("encrypt");
        let forged_index = (MEGOLM_MAX_SKIP_AHEAD + 5).to_be_bytes();
        ct[..MEGOLM_INDEX_LEN].copy_from_slice(&forged_index);

        let result = decrypt_megolm(&mut inbound, &ct, room_id);
        assert_eq!(result, Err(CryptoError::MegolmSkipAheadTooFar));
        assert_eq!(
            inbound.message_index, 0,
            "a rejected over-long jump must not advance the ratchet"
        );
        assert!(
            inbound.skipped.is_empty(),
            "a rejected over-long jump must not populate the skipped-key cache"
        );
    }

    #[test]
    fn megolm_skipped_key_is_single_use() {
        setup_test_rng();
        let mut crypto = MatrixCrypto::new().expect("test csprng seeded");
        let room_id = "!skip-once:matrix.example.com";
        let _ = crypto.create_outbound_megolm(room_id);
        let mut inbound = crypto
            .find_outbound_megolm(room_id)
            .cloned()
            .expect("session exists");

        let c0 = encrypt_megolm(&mut crypto.megolm_outbound[0], b"zero").expect("encrypt 0");
        let c1 = encrypt_megolm(&mut crypto.megolm_outbound[0], b"one").expect("encrypt 1");

        // c1 arrives first: the ratchet walks past index 0, caching its key.
        assert_eq!(
            decrypt_megolm(&mut inbound, &c1, room_id)
                .expect("d1")
                .as_slice(),
            b"one"
        );
        // c0 is served from the skipped cache.
        assert_eq!(
            decrypt_megolm(&mut inbound, &c0, room_id)
                .expect("d0")
                .as_slice(),
            b"zero"
        );
        // Replaying c0 must fail: the cached key was consumed on first use.
        assert_eq!(
            decrypt_megolm(&mut inbound, &c0, room_id),
            Err(CryptoError::MacVerificationFailed),
            "a consumed skipped key must not decrypt again (replay)"
        );
    }

    #[test]
    fn megolm_decrypt_does_not_mutate_session_on_mac_failure() {
        setup_test_rng();
        let mut crypto = MatrixCrypto::new().expect("test csprng seeded");
        let room_id = "!no-mutate:matrix.example.com";
        let _ = crypto.create_outbound_megolm(room_id);
        let mut inbound = crypto
            .find_outbound_megolm(room_id)
            .cloned()
            .expect("session exists");

        let mut ct = encrypt_megolm(&mut crypto.megolm_outbound[0], b"tamper me").expect("encrypt");
        let last = ct.len() - 1;
        ct[last] ^= 0xff; // corrupt the MAC tag

        let index_before = inbound.message_index;
        let key_before = inbound.session_key;
        assert_eq!(
            decrypt_megolm(&mut inbound, &ct, room_id),
            Err(CryptoError::MacVerificationFailed)
        );
        assert_eq!(
            inbound.message_index, index_before,
            "a failed decrypt must not advance the ratchet position"
        );
        assert_eq!(
            inbound.session_key, key_before,
            "a failed decrypt must not roll the ratchet key"
        );
        assert!(
            inbound.skipped.is_empty(),
            "a failed decrypt must not populate the skipped-key cache"
        );
    }
}
