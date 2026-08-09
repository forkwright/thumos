//! SMP PDU codec (BT Core Spec Vol 3, Part H §3) — the fixed-size wire
//! structures the [`super::pairing`] state machine exchanges over the LE
//! SMP fixed channel (CID `0x0006`, `crate::l2cap::CID_SMP`).
//!
//! Every SMP PDU has an EXACT length per opcode — there is no
//! variable-length or TLV field anywhere in this protocol — so decoding
//! reduces to "does this opcode's payload have exactly the right number
//! of bytes," never a length computed FROM attacker-supplied data. That
//! is the main defence this module contributes to the security-critical
//! posture #636 asks for: a truncated or padded PDU is rejected here,
//! before [`super::pairing`] ever sees it.
//!
//! # Byte-order convention
//!
//! [`super`] establishes big-endian display order as this module's
//! internal convention. The SMP wire format is little-endian for every
//! multi-byte "opaque value" field (confirm/random/`DHKey`-check values,
//! the IRK, and the ECDH public key coordinates) and for `BdAddr` (the
//! same LSB-first convention `hci.rs`'s `LESetRandomAddress` encoder
//! already reverses for). [`reversed`] is the one shared helper every
//! encode/decode function uses at that boundary — single-byte fields
//! (opcodes, capability/flag bytes) need no conversion.

use crate::hci::BdAddr;

// ── Opcodes (Vol 3, Part H §3.3, Table 3.7) ─────────────────────────────────────

pub(crate) const OP_PAIRING_REQUEST: u8 = 0x01;
pub(crate) const OP_PAIRING_RESPONSE: u8 = 0x02;
pub(crate) const OP_PAIRING_CONFIRM: u8 = 0x03;
pub(crate) const OP_PAIRING_RANDOM: u8 = 0x04;
pub(crate) const OP_PAIRING_FAILED: u8 = 0x05;
pub(crate) const OP_ENCRYPTION_INFORMATION: u8 = 0x06;
pub(crate) const OP_MASTER_IDENTIFICATION: u8 = 0x07;
pub(crate) const OP_IDENTITY_INFORMATION: u8 = 0x08;
pub(crate) const OP_IDENTITY_ADDRESS_INFORMATION: u8 = 0x09;
pub(crate) const OP_SIGNING_INFORMATION: u8 = 0x0A;
pub(crate) const OP_SECURITY_REQUEST: u8 = 0x0B;
pub(crate) const OP_PAIRING_PUBLIC_KEY: u8 = 0x0C;
pub(crate) const OP_PAIRING_DHKEY_CHECK: u8 = 0x0D;
pub(crate) const OP_PAIRING_KEYPRESS_NOTIFICATION: u8 = 0x0E;

// ── Field-value constants ────────────────────────────────────────────────────────

/// `AuthReq` bit for the `Bonding_Flags` field (Vol 3, Part H §3.5.1,
/// Table 3.5) — `0b01`; this module only ever sends/accepts bonding.
const AUTH_REQ_BONDING: u8 = 0x01;
/// `AuthReq` MITM Protection bit.
const AUTH_REQ_MITM: u8 = 0x04;
/// `AuthReq` LE Secure Connections bit — the pairing method this module
/// requires; a peer that does not set it on its own PDU is refused
/// ([`super::pairing`]).
const AUTH_REQ_SC: u8 = 0x08;
/// `AuthReq` Keypress Notifications bit (Passkey Entry only; unused here).
const AUTH_REQ_KEYPRESS: u8 = 0x10;
/// `AuthReq` CT2 (cross-transport key derivation generation) bit; unused here.
const AUTH_REQ_CT2: u8 = 0x20;

/// `KeyDistribution` bit for the encryption key (LTK/EDIV/Rand) — Legacy
/// Pairing only; SC derives the LTK directly via `f5` and must not set
/// this (Vol 3, Part H §3.6.1: "shall not distribute the LTK... when
/// using LE Secure Connections").
const KEY_DIST_ENC_KEY: u8 = 0x01;
/// `KeyDistribution` bit for the identity key (IRK) — the only key this
/// module requests or offers.
const KEY_DIST_ID_KEY: u8 = 0x02;
/// `KeyDistribution` bit for the signing key (CSRK); not requested here
/// (no ATT signing implemented).
const KEY_DIST_SIGN_KEY: u8 = 0x04;
/// `KeyDistribution` bit for BR/EDR cross-transport link-key derivation;
/// not requested here.
const KEY_DIST_LINK_KEY: u8 = 0x08;

/// Minimum accepted `Maximum Encryption Key Size` (Vol 3, Part H §3.5.1).
/// This module REQUIRES the full 16 bytes and refuses anything smaller —
/// accepting a smaller negotiated size is a documented downgrade-attack
/// surface, not just a compatibility knob.
pub(crate) const REQUIRED_MAX_ENC_KEY_SIZE: u8 = 16;

// ── Error type ─────────────────────────────────────────────────────────────────

/// Errors FROM SMP PDU decoding. Every variant means "reject this PDU
/// outright" — none of them describe a partially-usable result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, snafu::Snafu)]
#[non_exhaustive]
pub(crate) enum Error {
    /// `data` is empty — there is no opcode byte to dispatch on.
    #[snafu(display("empty SMP PDU: no opcode byte"))]
    Empty,

    /// The opcode's payload was the wrong length. SMP PDUs have no
    /// variable-length fields, so any mismatch here means a truncated,
    /// padded, or otherwise malformed PDU — never a valid one this
    /// decoder simply doesn't understand yet.
    #[snafu(display(
        "malformed SMP PDU (opcode 0x{opcode:02X}): expected {expected} bytes, got {actual}"
    ))]
    WrongLength {
        /// The opcode whose length didn't match.
        opcode: u8,
        /// The exact byte count that opcode requires.
        expected: usize,
        /// The byte count actually present.
        actual: usize,
    },

    /// The opcode is not one Vol 3 Part H §3.3 defines at all.
    #[snafu(display("unknown SMP opcode: 0x{opcode:02X}"))]
    UnknownOpcode {
        /// The unrecognised opcode byte.
        opcode: u8,
    },
}

/// Result alias for this module.
pub(crate) type Result<T> = core::result::Result<T, Error>;

// ── Shared byte-order helper ─────────────────────────────────────────────────────

/// Reverse a fixed-size array — the SMP-wire ↔ display-order conversion
/// every multi-byte "opaque value" field on this PDU boundary uses (see
/// module docs). A single shared helper so the convention lives in
/// exactly one place rather than N ad hoc reversals.
const fn reversed<const N: usize>(mut a: [u8; N]) -> [u8; N] {
    // `[u8; N]::reverse` is not `const`; unrolled swap keeps this callable
    // FROM a `const fn` context without pulling in an iterator.
    let mut i = 0;
    while i < N / 2 {
        let tmp = a[i];
        a[i] = a[N - 1 - i];
        a[N - 1 - i] = tmp;
        i += 1;
    }
    a
}

// ── IoCapability / AuthReq / KeyDistribution ─────────────────────────────────────

/// IO Capability (Vol 3, Part H §2.3.3, Table 2.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub(crate) enum IoCapability {
    /// `0x00` — can display a value, cannot accept input.
    DisplayOnly,
    /// `0x01` — can display a value and accept a yes/no confirmation.
    DisplayYesNo,
    /// `0x02` — can accept keyboard input, cannot display.
    KeyboardOnly,
    /// `0x03` — neither display nor input. This module's own capability
    /// ([`super::pairing`] docs): Just Works only, no MITM protection.
    NoInputNoOutput,
    /// `0x04` — can display a value and accept keyboard input.
    KeyboardDisplay,
}

impl IoCapability {
    const fn as_u8(self) -> u8 {
        match self {
            Self::DisplayOnly => 0x00,
            Self::DisplayYesNo => 0x01,
            Self::KeyboardOnly => 0x02,
            Self::NoInputNoOutput => 0x03,
            Self::KeyboardDisplay => 0x04,
        }
    }

    /// Decode a wire IO Capability byte. Unrecognised values (`0x05..`)
    /// are reserved by the spec, not an error this driver treats
    /// specially — they fold to `NoInputNoOutput`, the least-capable
    /// (never a MITM-claiming) interpretation, so a malformed or
    /// future-reserved value can never be read as offering more
    /// authentication strength than it actually has.
    const fn from_u8(byte: u8) -> Self {
        match byte {
            0x00 => Self::DisplayOnly,
            0x01 => Self::DisplayYesNo,
            0x02 => Self::KeyboardOnly,
            0x04 => Self::KeyboardDisplay,
            _ => Self::NoInputNoOutput,
        }
    }
}

/// `AuthReq` flags (Vol 3, Part H §3.5.1, Table 3.5).
// WHY: these five fields ARE the spec's own bitfield table (Table 3.5) —
// each is independently meaningful and independently set/read against a
// single wire byte; folding them into an enum would obscure that 1:1
// mapping rather than clarify it.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub(crate) struct AuthReq {
    /// `Bonding_Flags` bit — `true` requests a persistent bond.
    pub(crate) bonding: bool,
    /// MITM Protection bit.
    pub(crate) mitm: bool,
    /// LE Secure Connections bit. [`super::pairing`] refuses any peer
    /// that does not set this — see module docs.
    pub(crate) secure_connections: bool,
    /// Keypress Notifications bit (Passkey Entry only).
    pub(crate) keypress: bool,
    /// CT2 (cross-transport key derivation) bit.
    pub(crate) ct2: bool,
}

impl AuthReq {
    /// This module's own outgoing `AuthReq`: bonding + Secure Connections,
    /// no MITM (Just Works cannot claim it — see [`super::pairing`] docs),
    /// no keypress/CT2.
    pub(crate) const OURS: Self = Self {
        bonding: true,
        mitm: false,
        secure_connections: true,
        keypress: false,
        ct2: false,
    };

    const fn as_u8(self) -> u8 {
        (if self.bonding { AUTH_REQ_BONDING } else { 0 })
            | (if self.mitm { AUTH_REQ_MITM } else { 0 })
            | (if self.secure_connections {
                AUTH_REQ_SC
            } else {
                0
            })
            | (if self.keypress { AUTH_REQ_KEYPRESS } else { 0 })
            | (if self.ct2 { AUTH_REQ_CT2 } else { 0 })
    }

    const fn from_u8(byte: u8) -> Self {
        Self {
            bonding: byte & AUTH_REQ_BONDING != 0,
            mitm: byte & AUTH_REQ_MITM != 0,
            secure_connections: byte & AUTH_REQ_SC != 0,
            keypress: byte & AUTH_REQ_KEYPRESS != 0,
            ct2: byte & AUTH_REQ_CT2 != 0,
        }
    }
}

/// `KeyDistribution` flags (Vol 3, Part H §3.6.1, Table 3.6) — sent twice
/// per Pairing Request/Response (once for what the initiator will
/// distribute, once for what the responder will).
// WHY: same rationale as `AuthReq` — this is Table 3.6's own bitfield
// layout, not application state.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub(crate) struct KeyDistribution {
    /// `EncKey` (LTK/EDIV/Rand) — Legacy only; this module never sets it.
    pub(crate) enc_key: bool,
    /// `IdKey` (IRK + identity address) — the only key this module
    /// requests or offers.
    pub(crate) id_key: bool,
    /// `SignKey` (CSRK) — not requested here (no ATT signing implemented).
    pub(crate) sign_key: bool,
    /// `LinkKey` (BR/EDR cross-transport derivation) — not requested here.
    pub(crate) link_key: bool,
}

impl KeyDistribution {
    /// This module's own outgoing key-distribution request/offer: `IdKey`
    /// only.
    pub(crate) const ID_KEY_ONLY: Self = Self {
        enc_key: false,
        id_key: true,
        sign_key: false,
        link_key: false,
    };

    const fn as_u8(self) -> u8 {
        (if self.enc_key { KEY_DIST_ENC_KEY } else { 0 })
            | (if self.id_key { KEY_DIST_ID_KEY } else { 0 })
            | (if self.sign_key { KEY_DIST_SIGN_KEY } else { 0 })
            | (if self.link_key { KEY_DIST_LINK_KEY } else { 0 })
    }

    const fn from_u8(byte: u8) -> Self {
        Self {
            enc_key: byte & KEY_DIST_ENC_KEY != 0,
            id_key: byte & KEY_DIST_ID_KEY != 0,
            sign_key: byte & KEY_DIST_SIGN_KEY != 0,
            link_key: byte & KEY_DIST_LINK_KEY != 0,
        }
    }

    /// The keys both sides agree will actually move: bits present in
    /// BOTH `self` (what the peer offered) and `wanted` (what we'd
    /// accept). Used to bound key distribution to something this module
    /// actually asked for — a peer cannot push an `EncKey`/`SignKey`/`LinkKey`
    /// we never requested.
    const fn intersect(self, wanted: Self) -> Self {
        Self {
            enc_key: self.enc_key && wanted.enc_key,
            id_key: self.id_key && wanted.id_key,
            sign_key: self.sign_key && wanted.sign_key,
            link_key: self.link_key && wanted.link_key,
        }
    }
}

/// Pairing Failed reason codes (Vol 3, Part H §3.5.5, Table 3.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub(crate) enum PairingFailReason {
    /// `0x01`
    PasskeyEntryFailed,
    /// `0x02`
    OobNotAvailable,
    /// `0x03` — used here when a peer will not negotiate LE Secure
    /// Connections.
    AuthenticationRequirements,
    /// `0x04` — a received Pairing Confirm did not match its later
    /// Pairing Random.
    ConfirmValueFailed,
    /// `0x05`
    PairingNotSupported,
    /// `0x06` — used here when a peer negotiates an encryption key size
    /// below [`REQUIRED_MAX_ENC_KEY_SIZE`].
    EncryptionKeySize,
    /// `0x07` — used here for any PDU whose opcode is unexpected for the
    /// current pairing state.
    CommandNotSupported,
    /// `0x08` — generic catch-all.
    Unspecified,
    /// `0x09`
    RepeatedAttempts,
    /// `0x0A` — used here for a structurally-invalid field value (e.g. a
    /// peer public key equal to our own, or a `KeyDistribution` byte
    /// requesting keys we never offered).
    InvalidParameters,
    /// `0x0B` — a received `DHKey` Check value did not match.
    DhKeyCheckFailed,
    /// `0x0C`
    NumericComparisonFailed,
    /// `0x0D`
    BrEdrPairingInProgress,
    /// `0x0E`
    CrossTransportKeyDerivationNotAllowed,
    /// `0x0F`
    KeyRejected,
    /// A reason code this decoder does not recognise (spec-reserved or
    /// future). Carries the raw byte rather than being an `Err` — an
    /// unrecognised *reason* inside an otherwise well-formed Pairing
    /// Failed PDU is not itself malformed.
    Other(u8),
}

impl PairingFailReason {
    const fn as_u8(self) -> u8 {
        match self {
            Self::PasskeyEntryFailed => 0x01,
            Self::OobNotAvailable => 0x02,
            Self::AuthenticationRequirements => 0x03,
            Self::ConfirmValueFailed => 0x04,
            Self::PairingNotSupported => 0x05,
            Self::EncryptionKeySize => 0x06,
            Self::CommandNotSupported => 0x07,
            Self::Unspecified => 0x08,
            Self::RepeatedAttempts => 0x09,
            Self::InvalidParameters => 0x0A,
            Self::DhKeyCheckFailed => 0x0B,
            Self::NumericComparisonFailed => 0x0C,
            Self::BrEdrPairingInProgress => 0x0D,
            Self::CrossTransportKeyDerivationNotAllowed => 0x0E,
            Self::KeyRejected => 0x0F,
            Self::Other(byte) => byte,
        }
    }

    const fn from_u8(byte: u8) -> Self {
        match byte {
            0x01 => Self::PasskeyEntryFailed,
            0x02 => Self::OobNotAvailable,
            0x03 => Self::AuthenticationRequirements,
            0x04 => Self::ConfirmValueFailed,
            0x05 => Self::PairingNotSupported,
            0x06 => Self::EncryptionKeySize,
            0x07 => Self::CommandNotSupported,
            0x08 => Self::Unspecified,
            0x09 => Self::RepeatedAttempts,
            0x0A => Self::InvalidParameters,
            0x0B => Self::DhKeyCheckFailed,
            0x0C => Self::NumericComparisonFailed,
            0x0D => Self::BrEdrPairingInProgress,
            0x0E => Self::CrossTransportKeyDerivationNotAllowed,
            0x0F => Self::KeyRejected,
            other => Self::Other(other),
        }
    }
}

// ── Pairing Request / Pairing Response (Vol 3, Part H §3.5.1, §3.5.2) ────────────

/// The Pairing Request and Pairing Response PDUs share this exact 6-byte
/// body (7 with opcode) — only the opcode distinguishes them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub(crate) struct PairingFeatures {
    /// IO Capability.
    pub(crate) io_capability: IoCapability,
    /// OOB data present.
    pub(crate) oob_data_present: bool,
    /// `AuthReq` flags.
    pub(crate) auth_req: AuthReq,
    /// Maximum Encryption Key Size, 7..=16.
    pub(crate) max_key_size: u8,
    /// What the INITIATOR will distribute (in a Pairing Response, what
    /// the responder is willing for the initiator to send).
    pub(crate) initiator_key_dist: KeyDistribution,
    /// What the RESPONDER will distribute.
    pub(crate) responder_key_dist: KeyDistribution,
}

impl PairingFeatures {
    /// Body length (excludes the opcode byte).
    const BODY_LEN: usize = 6;

    /// This module's own outgoing features (used for both Pairing
    /// Request and Pairing Response): Just Works, SC-only, bonding, the
    /// full 16-byte key size, `IdKey` only.
    pub(crate) const OURS: Self = Self {
        io_capability: IoCapability::NoInputNoOutput,
        oob_data_present: false,
        auth_req: AuthReq::OURS,
        max_key_size: REQUIRED_MAX_ENC_KEY_SIZE,
        initiator_key_dist: KeyDistribution::ID_KEY_ONLY,
        responder_key_dist: KeyDistribution::ID_KEY_ONLY,
    };

    fn encode(self, opcode: u8) -> [u8; 7] {
        [
            opcode,
            self.io_capability.as_u8(),
            u8::from(self.oob_data_present),
            self.auth_req.as_u8(),
            self.max_key_size,
            self.initiator_key_dist.as_u8(),
            self.responder_key_dist.as_u8(),
        ]
    }

    fn decode(body: &[u8]) -> Self {
        Self {
            io_capability: IoCapability::from_u8(body[0]),
            oob_data_present: body[1] != 0,
            auth_req: AuthReq::from_u8(body[2]),
            max_key_size: body[3],
            initiator_key_dist: KeyDistribution::from_u8(body[4]),
            responder_key_dist: KeyDistribution::from_u8(body[5]),
        }
    }

    /// The 3-byte `IOcap` argument [`super::toolbox::f6`] takes for the
    /// device that sent this Pairing Request/Response: `[AuthReq,
    /// OOB_data_flag, IO_Capability]` — Vol 3 Part H §2.2.8 defines the
    /// check-value function's `IOcap` in THIS field order, which is the
    /// reverse of the PDU's own wire order (`IOCap, OOB, AuthReq`).
    pub(crate) const fn io_cap_for_check(&self) -> [u8; 3] {
        [
            self.auth_req.as_u8(),
            self.oob_data_present as u8,
            self.io_capability.as_u8(),
        ]
    }
}

// ── Fixed 16-byte "opaque value" PDUs ─────────────────────────────────────────────

/// Pairing Confirm (Vol 3, Part H §3.5.3): a commitment to a not-yet-revealed nonce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PairingConfirm {
    /// The confirm value (`Cb` for a responder, unused for SC Just Works
    /// initiator — see [`super::pairing`]), big-endian display order.
    pub(crate) value: [u8; 16],
}

/// Pairing Random (Vol 3, Part H §3.5.4): the nonce a prior Pairing
/// Confirm committed to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PairingRandom {
    /// The nonce, big-endian display order.
    pub(crate) value: [u8; 16],
}

/// Identity Information (Vol 3, Part H §3.6.4): distributes the sender's IRK.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct IdentityInformation {
    /// The IRK, big-endian display order.
    pub(crate) irk: [u8; 16],
}

/// Pairing `DHKey` Check (Vol 3, Part H §3.5.8): the `f6`-derived check value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DhKeyCheck {
    /// The check value (`Ea`/`Eb`), big-endian display order.
    pub(crate) value: [u8; 16],
}

/// Identity Address Information (Vol 3, Part H §3.6.5): the sender's
/// identity address, paired with a prior Identity Information PDU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IdentityAddressInformation {
    /// `0x00` = public, `0x01` = random (static) identity address.
    pub(crate) address_type: u8,
    /// The identity address, display order (matches [`BdAddr`]'s own
    /// convention).
    pub(crate) address: BdAddr,
}

/// Pairing Public Key (Vol 3, Part H §3.5.6): one device's ECDH P-256
/// public key coordinates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PublicKey {
    /// X coordinate, big-endian display order (matches
    /// [`super::toolbox::EcdhKeyPair::public_x`]'s convention directly —
    /// only the wire encoding reverses).
    pub(crate) x: [u8; 32],
    /// Y coordinate, big-endian display order.
    pub(crate) y: [u8; 32],
}

// ── Decoded PDU ────────────────────────────────────────────────────────────────

/// A decoded SMP PDU. Every opaque-value field has already been
/// converted FROM the little-endian wire format to this module's
/// big-endian display convention.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub(crate) enum PairingPdu {
    /// `0x01`
    PairingRequest(PairingFeatures),
    /// `0x02`
    PairingResponse(PairingFeatures),
    /// `0x03`
    PairingConfirm(PairingConfirm),
    /// `0x04`
    PairingRandom(PairingRandom),
    /// `0x05`
    PairingFailed(PairingFailReason),
    /// `0x08`
    IdentityInformation(IdentityInformation),
    /// `0x09`
    IdentityAddressInformation(IdentityAddressInformation),
    /// `0x0C`
    PublicKey(PublicKey),
    /// `0x0D`
    DhKeyCheck(DhKeyCheck),
    /// A recognised opcode this module does not act on under LE Secure
    /// Connections: Encryption Information (`0x06`), Master
    /// Identification (`0x07`, both Legacy-only), Signing Information
    /// (`0x0A`, no ATT signing implemented), Security Request (`0x0B`,
    /// this module never solicits a peer-initiated request), or
    /// Keypress Notification (`0x0E`, Passkey Entry only). Its length
    /// was still validated against the opcode's spec-fixed size — only
    /// the field values go unparsed.
    Unsupported {
        /// The recognised-but-unsupported opcode.
        opcode: u8,
    },
}

/// Decode one SMP PDU from an L2CAP SMP-channel SDU payload
/// (`crate::l2cap::L2capSdu::payload` when `cid == CID_SMP`).
///
/// # Errors
///
/// [`Error::Empty`] if `data` is empty. [`Error::UnknownOpcode`] if the
/// first byte is not one of the fifteen SMP opcodes. [`Error::WrongLength`]
/// if the opcode's payload is not EXACTLY the length that opcode's fixed
/// PDU layout requires — SMP has no variable-length fields, so any
/// mismatch here is a malformed PDU by construction, never a valid one
/// this decoder doesn't yet understand.
pub(crate) fn decode(data: &[u8]) -> Result<PairingPdu> {
    let (&opcode, body) = data.split_first().ok_or(Error::Empty)?;

    let expect = |want: usize| -> Result<()> {
        if body.len() == want {
            Ok(())
        } else {
            Err(Error::WrongLength {
                opcode,
                expected: want,
                actual: body.len(),
            })
        }
    };

    match opcode {
        OP_PAIRING_REQUEST => {
            expect(PairingFeatures::BODY_LEN)?;
            Ok(PairingPdu::PairingRequest(PairingFeatures::decode(body)))
        }
        OP_PAIRING_RESPONSE => {
            expect(PairingFeatures::BODY_LEN)?;
            Ok(PairingPdu::PairingResponse(PairingFeatures::decode(body)))
        }
        OP_PAIRING_CONFIRM => {
            expect(16)?;
            let mut value = [0u8; 16];
            value.copy_from_slice(body);
            Ok(PairingPdu::PairingConfirm(PairingConfirm {
                value: reversed(value),
            }))
        }
        OP_PAIRING_RANDOM => {
            expect(16)?;
            let mut value = [0u8; 16];
            value.copy_from_slice(body);
            Ok(PairingPdu::PairingRandom(PairingRandom {
                value: reversed(value),
            }))
        }
        OP_PAIRING_FAILED => {
            expect(1)?;
            Ok(PairingPdu::PairingFailed(PairingFailReason::from_u8(
                body[0],
            )))
        }
        // Both fixed-16-byte recognised-but-unsupported-under-SC opcodes
        // (module docs: `EncKey`/`SignKey` distribution is out of scope).
        OP_ENCRYPTION_INFORMATION | OP_SIGNING_INFORMATION => {
            expect(16)?;
            Ok(PairingPdu::Unsupported { opcode })
        }
        OP_MASTER_IDENTIFICATION => {
            expect(10)?;
            Ok(PairingPdu::Unsupported { opcode })
        }
        OP_IDENTITY_INFORMATION => {
            expect(16)?;
            let mut irk = [0u8; 16];
            irk.copy_from_slice(body);
            Ok(PairingPdu::IdentityInformation(IdentityInformation {
                irk: reversed(irk),
            }))
        }
        OP_IDENTITY_ADDRESS_INFORMATION => {
            expect(7)?;
            let mut addr_le = [0u8; 6];
            addr_le.copy_from_slice(&body[1..7]);
            Ok(PairingPdu::IdentityAddressInformation(
                IdentityAddressInformation {
                    address_type: body[0],
                    address: BdAddr::from_bytes(reversed(addr_le)),
                },
            ))
        }
        // Both fixed-1-byte recognised-but-unsupported opcodes (this
        // module never solicits a Security Request, and Keypress
        // Notification is Passkey Entry only).
        OP_SECURITY_REQUEST | OP_PAIRING_KEYPRESS_NOTIFICATION => {
            expect(1)?;
            Ok(PairingPdu::Unsupported { opcode })
        }
        OP_PAIRING_PUBLIC_KEY => {
            expect(64)?;
            let mut x = [0u8; 32];
            let mut y = [0u8; 32];
            x.copy_from_slice(&body[0..32]);
            y.copy_from_slice(&body[32..64]);
            Ok(PairingPdu::PublicKey(PublicKey {
                x: reversed(x),
                y: reversed(y),
            }))
        }
        OP_PAIRING_DHKEY_CHECK => {
            expect(16)?;
            let mut value = [0u8; 16];
            value.copy_from_slice(body);
            Ok(PairingPdu::DhKeyCheck(DhKeyCheck {
                value: reversed(value),
            }))
        }
        _ => Err(Error::UnknownOpcode { opcode }),
    }
}

// ── Encoders ───────────────────────────────────────────────────────────────────

/// Encode a Pairing Request.
pub(crate) fn encode_pairing_request(features: PairingFeatures) -> [u8; 7] {
    features.encode(OP_PAIRING_REQUEST)
}

/// Encode a Pairing Response.
pub(crate) fn encode_pairing_response(features: PairingFeatures) -> [u8; 7] {
    features.encode(OP_PAIRING_RESPONSE)
}

/// Encode a Pairing Confirm.
pub(crate) fn encode_pairing_confirm(value: [u8; 16]) -> [u8; 17] {
    encode_16(OP_PAIRING_CONFIRM, value)
}

/// Encode a Pairing Random.
pub(crate) fn encode_pairing_random(value: [u8; 16]) -> [u8; 17] {
    encode_16(OP_PAIRING_RANDOM, value)
}

/// Encode a Pairing Failed.
pub(crate) const fn encode_pairing_failed(reason: PairingFailReason) -> [u8; 2] {
    [OP_PAIRING_FAILED, reason.as_u8()]
}

/// Encode an Identity Information.
pub(crate) fn encode_identity_information(irk: [u8; 16]) -> [u8; 17] {
    encode_16(OP_IDENTITY_INFORMATION, irk)
}

/// Encode an Identity Address Information.
pub(crate) fn encode_identity_address_information(address_type: u8, address: &BdAddr) -> [u8; 8] {
    let addr_le = reversed(*address.as_bytes());
    let mut out = [0u8; 8];
    out[0] = OP_IDENTITY_ADDRESS_INFORMATION;
    out[1] = address_type;
    out[2..8].copy_from_slice(&addr_le);
    out
}

/// Encode a Pairing Public Key.
pub(crate) fn encode_public_key(x: [u8; 32], y: [u8; 32]) -> [u8; 65] {
    let mut out = [0u8; 65];
    out[0] = OP_PAIRING_PUBLIC_KEY;
    out[1..33].copy_from_slice(&reversed(x));
    out[33..65].copy_from_slice(&reversed(y));
    out
}

/// Encode a Pairing `DHKey` Check.
pub(crate) fn encode_dhkey_check(value: [u8; 16]) -> [u8; 17] {
    encode_16(OP_PAIRING_DHKEY_CHECK, value)
}

fn encode_16(opcode: u8, value: [u8; 16]) -> [u8; 17] {
    let mut out = [0u8; 17];
    out[0] = opcode;
    out[1..17].copy_from_slice(&reversed(value));
    out
}

/// [`KeyDistribution::intersect`] re-exported for [`super::pairing`] — the
/// negotiated set of keys that will actually move is a property of the
/// wire fields, computed here rather than duplicated in the state
/// machine.
pub(crate) const fn negotiate_key_distribution(
    offered: KeyDistribution,
    wanted: KeyDistribution,
) -> KeyDistribution {
    offered.intersect(wanted)
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── round-trips ──

    #[test]
    fn pairing_request_round_trips() {
        let features = PairingFeatures::OURS;
        let wire = encode_pairing_request(features);
        let Ok(PairingPdu::PairingRequest(decoded)) = decode(&wire) else {
            unreachable!("a freshly-encoded Pairing Request must decode as one");
        };
        assert_eq!(decoded, features);
    }

    #[test]
    fn pairing_response_round_trips() {
        let features = PairingFeatures::OURS;
        let wire = encode_pairing_response(features);
        let Ok(PairingPdu::PairingResponse(decoded)) = decode(&wire) else {
            unreachable!("a freshly-encoded Pairing Response must decode as one");
        };
        assert_eq!(decoded, features);
    }

    #[test]
    fn pairing_confirm_round_trips() {
        let value = [0x11; 16];
        let wire = encode_pairing_confirm(value);
        let Ok(PairingPdu::PairingConfirm(decoded)) = decode(&wire) else {
            unreachable!("a freshly-encoded Pairing Confirm must decode as one");
        };
        assert_eq!(decoded.value, value);
    }

    #[test]
    fn pairing_random_round_trips() {
        let value = [0x22; 16];
        let wire = encode_pairing_random(value);
        let Ok(PairingPdu::PairingRandom(decoded)) = decode(&wire) else {
            unreachable!("a freshly-encoded Pairing Random must decode as one");
        };
        assert_eq!(decoded.value, value);
    }

    #[test]
    fn identity_information_round_trips() {
        let irk = [0x33; 16];
        let wire = encode_identity_information(irk);
        let Ok(PairingPdu::IdentityInformation(decoded)) = decode(&wire) else {
            unreachable!("a freshly-encoded Identity Information must decode as one");
        };
        assert_eq!(decoded.irk, irk);
    }

    #[test]
    fn identity_address_information_round_trips() {
        let Ok(address) = BdAddr::parse("AA:BB:CC:DD:EE:FF") else {
            unreachable!("valid test address");
        };
        let wire = encode_identity_address_information(0x01, &address);
        let Ok(PairingPdu::IdentityAddressInformation(decoded)) = decode(&wire) else {
            unreachable!("a freshly-encoded Identity Address Information must decode as one");
        };
        assert_eq!(decoded.address_type, 0x01);
        assert_eq!(decoded.address, address);
    }

    #[test]
    fn public_key_round_trips() {
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        for (i, b) in x.iter_mut().enumerate() {
            *b = i as u8;
        }
        for (i, b) in y.iter_mut().enumerate() {
            *b = (i as u8).wrapping_add(0x80);
        }
        let wire = encode_public_key(x, y);
        let Ok(PairingPdu::PublicKey(decoded)) = decode(&wire) else {
            unreachable!("a freshly-encoded Public Key must decode as one");
        };
        assert_eq!(decoded.x, x);
        assert_eq!(decoded.y, y);
    }

    #[test]
    fn dhkey_check_round_trips() {
        let value = [0x44; 16];
        let wire = encode_dhkey_check(value);
        let Ok(PairingPdu::DhKeyCheck(decoded)) = decode(&wire) else {
            unreachable!("a freshly-encoded DHKey Check must decode as one");
        };
        assert_eq!(decoded.value, value);
    }

    #[test]
    fn pairing_failed_round_trips_a_known_reason() {
        let wire = encode_pairing_failed(PairingFailReason::DhKeyCheckFailed);
        let Ok(PairingPdu::PairingFailed(reason)) = decode(&wire) else {
            unreachable!("a freshly-encoded Pairing Failed must decode as one");
        };
        assert_eq!(reason, PairingFailReason::DhKeyCheckFailed);
    }

    // ── malformed-input rejection (the security-critical surface) ──

    #[test]
    fn empty_pdu_is_rejected() {
        assert_eq!(decode(&[]), Err(Error::Empty));
    }

    #[test]
    fn unknown_opcode_is_rejected() {
        assert_eq!(
            decode(&[0xFF, 0x00]),
            Err(Error::UnknownOpcode { opcode: 0xFF })
        );
    }

    #[test]
    fn truncated_pairing_confirm_is_rejected() {
        // Confirm requires exactly 16 body bytes; give it 15.
        let mut wire = vec![OP_PAIRING_CONFIRM];
        wire.extend_from_slice(&[0u8; 15]);
        assert_eq!(
            decode(&wire),
            Err(Error::WrongLength {
                opcode: OP_PAIRING_CONFIRM,
                expected: 16,
                actual: 15,
            })
        );
    }

    #[test]
    fn overlong_pairing_confirm_is_rejected() {
        // 17 body bytes instead of 16 — padding must not be silently dropped.
        let mut wire = vec![OP_PAIRING_CONFIRM];
        wire.extend_from_slice(&[0u8; 17]);
        assert_eq!(
            decode(&wire),
            Err(Error::WrongLength {
                opcode: OP_PAIRING_CONFIRM,
                expected: 16,
                actual: 17,
            })
        );
    }

    #[test]
    fn truncated_pairing_request_is_rejected() {
        let mut wire = vec![OP_PAIRING_REQUEST];
        wire.extend_from_slice(&[0u8; 5]); // needs 6
        assert_eq!(
            decode(&wire),
            Err(Error::WrongLength {
                opcode: OP_PAIRING_REQUEST,
                expected: 6,
                actual: 5,
            })
        );
    }

    #[test]
    fn truncated_public_key_is_rejected() {
        let mut wire = vec![OP_PAIRING_PUBLIC_KEY];
        wire.extend_from_slice(&[0u8; 63]); // needs 64
        assert_eq!(
            decode(&wire),
            Err(Error::WrongLength {
                opcode: OP_PAIRING_PUBLIC_KEY,
                expected: 64,
                actual: 63,
            })
        );
    }

    #[test]
    fn oversized_public_key_is_rejected_not_truncated() {
        // A peer padding the PDU with extra bytes must not have those
        // bytes silently ignored -- that would let a malformed PDU pass
        // as a well-formed one with the tail discarded.
        let mut wire = vec![OP_PAIRING_PUBLIC_KEY];
        wire.extend_from_slice(&[0u8; 65]);
        assert_eq!(
            decode(&wire),
            Err(Error::WrongLength {
                opcode: OP_PAIRING_PUBLIC_KEY,
                expected: 64,
                actual: 65,
            })
        );
    }

    #[test]
    fn opcode_only_pairing_confirm_is_rejected() {
        assert_eq!(
            decode(&[OP_PAIRING_CONFIRM]),
            Err(Error::WrongLength {
                opcode: OP_PAIRING_CONFIRM,
                expected: 16,
                actual: 0,
            })
        );
    }

    #[test]
    fn unsupported_but_recognised_opcode_still_bounds_length() {
        // Master Identification (Legacy-only, unsupported here) must
        // still reject a wrong-length body rather than accepting it
        // because the fields go unparsed.
        let mut wire = vec![OP_MASTER_IDENTIFICATION];
        wire.extend_from_slice(&[0u8; 9]); // needs 10
        assert_eq!(
            decode(&wire),
            Err(Error::WrongLength {
                opcode: OP_MASTER_IDENTIFICATION,
                expected: 10,
                actual: 9,
            })
        );
    }

    #[test]
    fn correctly_sized_unsupported_opcode_decodes_as_unsupported() {
        let mut wire = vec![OP_SECURITY_REQUEST];
        wire.push(0x01);
        assert_eq!(
            decode(&wire),
            Ok(PairingPdu::Unsupported {
                opcode: OP_SECURITY_REQUEST
            })
        );
    }

    #[test]
    fn pairing_failed_with_reserved_reason_decodes_as_other() {
        let wire = encode_pairing_failed(PairingFailReason::Other(0x7F));
        let Ok(PairingPdu::PairingFailed(reason)) = decode(&wire) else {
            unreachable!("a well-formed 2-byte Pairing Failed always decodes");
        };
        assert_eq!(reason, PairingFailReason::Other(0x7F));
    }

    // ── AuthReq / KeyDistribution bit semantics ──

    #[test]
    fn auth_req_round_trips_all_bits() {
        let req = AuthReq {
            bonding: true,
            mitm: true,
            secure_connections: true,
            keypress: true,
            ct2: true,
        };
        assert_eq!(AuthReq::from_u8(req.as_u8()), req);
    }

    #[test]
    fn our_auth_req_sets_sc_and_bonding_but_not_mitm() {
        let ours = AuthReq::OURS;
        assert!(
            ours.secure_connections,
            "must require LE Secure Connections"
        );
        assert!(
            ours.bonding,
            "must request bonding (#455 needs a stored IRK)"
        );
        assert!(!ours.mitm, "Just Works cannot claim MITM protection");
    }

    #[test]
    fn key_distribution_intersect_bounds_to_the_smaller_set() {
        let offered = KeyDistribution {
            enc_key: true,
            id_key: true,
            sign_key: true,
            link_key: false,
        };
        let wanted = KeyDistribution::ID_KEY_ONLY;
        let negotiated = negotiate_key_distribution(offered, wanted);
        assert!(negotiated.id_key);
        assert!(
            !negotiated.enc_key && !negotiated.sign_key && !negotiated.link_key,
            "a peer offering keys we never requested must not expand what we accept"
        );
    }

    #[test]
    fn io_cap_for_check_uses_authreq_oob_iocap_order() {
        let features = PairingFeatures {
            io_capability: IoCapability::KeyboardOnly, // 0x02
            oob_data_present: true,                    // 0x01
            auth_req: AuthReq::from_u8(0x01),          // bonding only
            max_key_size: 16,
            initiator_key_dist: KeyDistribution::ID_KEY_ONLY,
            responder_key_dist: KeyDistribution::ID_KEY_ONLY,
        };
        assert_eq!(features.io_cap_for_check(), [0x01, 0x01, 0x02]);
    }

    // ── reversed() ──

    #[test]
    fn reversed_is_its_own_inverse() {
        let a = [1u8, 2, 3, 4, 5];
        assert_eq!(reversed(reversed(a)), a);
    }
}
