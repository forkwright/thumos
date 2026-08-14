//! The LE Secure Connections pairing state machine (Vol 3, Part H §2.3.5.6,
//! §3.5) — #455 stage 3 / #636.
//!
//! # Scope: Just Works only, LE Secure Connections only
//!
//! This module implements exactly one association model: **Just Works**
//! (both sides' IO Capability is [`crate::smp::pdu::IoCapability::NoInputNoOutput`]).
//! Numeric Comparison, Passkey Entry, and Out-of-Band are NOT implemented
//! — each needs a UI feedback loop (display a 6-digit code, accept a
//! typed passkey) that lives above this driver crate, in `eidolon`/the
//! kernel, not here. Just Works gives no MITM protection (this device's
//! `AuthReq` never claims it — [`crate::smp::pdu::AuthReq::OURS`]), but
//! IS resistant to passive eavesdropping, because the LTK is derived from
//! an ECDH shared secret an eavesdropper cannot compute — the specific
//! weakness LE Legacy Pairing has and this module exists to avoid.
//!
//! A peer whose `AuthReq` does not set the LE Secure Connections bit is
//! refused outright ([`PairingFailReason::AuthenticationRequirements`]) —
//! this module never falls back to Legacy Pairing.
//!
//! # What "done" means here
//!
//! [`PairingSession`] runs through Phase 1 (feature exchange) and Phase 2
//! (ECDH key agreement + `DHKey` Check) to [`PairingState::AwaitingEncryption`],
//! then Phase 3 (`IdKey`-only key distribution) once
//! [`PairingSession::confirm_link_encrypted`] is called, producing a
//! [`BondingRecord`] once the negotiated Identity Information / Identity
//! Address Information exchange completes.
//!
//! `confirm_link_encrypted` is a deliberate seam: Phase 3 key
//! distribution REQUIRES an already-encrypted link (Vol 3, Part H
//! §2.3.5.6.5), so this state machine refuses to send or accept any
//! Phase 3 PDU until the caller — who owns the actual
//! `HCI_LE_Start_Encryption` / `HCI_LE_Long_Term_Key_Request` round trip
//! against real controller hardware, which this crate does not yet
//! implement (#636 remaining work) — confirms it happened. That HCI
//! encryption-establishment wiring, not this state machine, is what
//! stands between this module and running against a real peer.
//!
//! # Security posture
//!
//! Every `handle_pdu` call validates the PDU's opcode against what the
//! CURRENT state expects before touching any field. An unexpected
//! opcode, a decode failure, or a cryptographic check that doesn't
//! verify all transition the session to a terminal
//! [`PairingState::Failed`] and emit exactly one Pairing Failed PDU — no
//! partial state from a rejected PDU is ever retained, and a session
//! already in `Failed` silently drops further input rather than
//! reprocessing it (guards against a peer trying to resurrect a failed
//! session with a replay).

use zeroize::Zeroize;

use super::Irk;
use super::pdu::{
    self, DhKeyCheck, IdentityAddressInformation, IdentityInformation, PairingConfirm,
    PairingFailReason, PairingFeatures, PairingPdu, PairingRandom, PublicKey,
    REQUIRED_MAX_ENC_KEY_SIZE,
};
use super::toolbox::{self, EcdhKeyPair};
use crate::hci::BdAddr;

/// `Z` input to [`toolbox::f4`] for Just Works / Numeric Comparison (Vol
/// 3, Part H §2.3.5.6.2) — always zero; the nonzero, bit-varying value is
/// Passkey Entry only, which this module does not implement.
const ASSOCIATION_Z: u8 = 0x00;

/// `R` input to [`toolbox::f6`] for Just Works / Numeric Comparison —
/// always all-zero, for the same reason as [`ASSOCIATION_Z`].
const ASSOCIATION_R: [u8; 16] = [0u8; 16];

/// Bytes to send to the peer over the SMP fixed channel, in order. Zero,
/// one, or two elements — some transitions (e.g. a responder replying to
/// the initiator's Public Key with its own Public Key AND its Pairing
/// Confirm) legitimately produce two PDUs from one received one.
pub(crate) type Outbound = Vec<Vec<u8>>;

/// Which side of the pairing procedure this session is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Role {
    /// Sent the Pairing Request.
    Initiator,
    /// Received the Pairing Request, sent the Pairing Response.
    Responder,
}

/// Pairing procedure state. Every variant names exactly the PDU(s) this
/// session will accept next; anything else is rejected without touching
/// the session's cryptographic state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub(crate) enum PairingState {
    /// Initiator only: has not yet sent the Pairing Request.
    NotStarted,
    /// Initiator: sent Pairing Request, awaiting Pairing Response.
    AwaitingPairingResponse,
    /// Responder: awaiting the initial Pairing Request.
    AwaitingPairingRequest,
    /// Both: feature exchange done, awaiting the peer's Public Key.
    AwaitingPeerPublicKey,
    /// Initiator only: awaiting the responder's Pairing Confirm (`Cb`),
    /// which the responder must send before it has seen `Na`.
    AwaitingResponderConfirm,
    /// Initiator only: sent `Na`, awaiting the responder's Pairing
    /// Random (`Nb`).
    AwaitingResponderRandom,
    /// Responder only: sent its own Public Key and Confirm, awaiting the
    /// initiator's Pairing Random (`Na`).
    AwaitingInitiatorRandom,
    /// Initiator: sent its `DHKey` Check (`Ea`), awaiting the responder's
    /// (`Eb`).
    AwaitingResponderDhKeyCheck,
    /// Responder: awaiting the initiator's `DHKey` Check (`Ea`) before
    /// sending its own.
    AwaitingInitiatorDhKeyCheck,
    /// Both: `DHKey` Check passed both directions. Refuses every Phase 3
    /// PDU until [`PairingSession::confirm_link_encrypted`] is called —
    /// see module docs.
    AwaitingEncryption,
    /// Both: link confirmed encrypted; exchanging Identity Information /
    /// Identity Address Information per the negotiated key distribution.
    ExchangingKeys,
    /// Terminal: pairing is done. [`PairingSession::bonding_record`]
    /// holds whatever the negotiated key distribution produced (may be
    /// `None` if neither side negotiated `IdKey`).
    Complete,
    /// Terminal: pairing failed. No further PDU is processed.
    Failed(PairingFailReason),
}

/// A bonded peer's identity, once Phase 3 key distribution has completed
/// the receive direction: the address a resolvable private address must
/// be checked against, and the IRK to check it with.
///
/// RAM-only, same deliberate boundary as [`Irk`]'s own doc comment
/// (persistence is a kernel-side bonding-record port, #636 remaining
/// work — this crate has no filesystem access).
#[derive(Debug)]
#[non_exhaustive]
pub(crate) struct BondingRecord {
    /// The peer's identity address (`0x00` public / `0x01` static
    /// random) and value, from its Identity Address Information PDU.
    pub(crate) peer_identity_address: (u8, BdAddr),
    /// The peer's IRK, from its Identity Information PDU.
    pub(crate) peer_irk: Irk,
}

/// [`PairingSession`]'s Phase 2/3 cryptographic secret material — ECDH
/// key-agreement state, the derived `MacKey`/`LTK`, and the peer's
/// not-yet-bonded IRK — under one owner, so the zeroize-on-drop posture
/// [`Irk`] already established has exactly one place to reach from
/// instead of being scattered across [`PairingSession`]'s field list.
///
/// [`EcdhKeyPair`]'s inner `p256::ecdh::EphemeralSecret` already
/// zeroizes itself via its own `Drop` impl, so `ecdh` needs no explicit
/// clearing here. `peer_public_x` (the peer's ECDH public-key
/// x-coordinate) and `responder_confirm` (`Cb`) are both values the peer
/// transmits in cleartext over the SMP channel, not secrets, so neither
/// is zeroized here either — matching the coverage `PairingSession`'s
/// `Drop` had before this material moved into its own owner.
struct SessionSecrets {
    ecdh: Option<EcdhKeyPair>,
    peer_public_x: Option<[u8; 32]>,
    dhkey: Option<[u8; 32]>,

    our_nonce: Option<[u8; 16]>,
    peer_nonce: Option<[u8; 16]>,
    /// The responder's Confirm value (`Cb`), stored by whichever role
    /// needs to check it later — only the initiator ever verifies it,
    /// but both roles pass through a state where it's known.
    responder_confirm: Option<[u8; 16]>,

    mackey: Option<[u8; 16]>,
    ltk: Option<[u8; 16]>,

    /// Holds the peer's IRK between its Identity Information PDU and the
    /// Identity Address Information PDU that must immediately follow it
    /// (Vol 3, Part H §3.6.1 order) — a lone Identity Information never
    /// becomes a [`BondingRecord`] on its own.
    pending_peer_irk: Option<[u8; 16]>,
}

impl SessionSecrets {
    const fn new() -> Self {
        Self {
            ecdh: None,
            peer_public_x: None,
            dhkey: None,
            our_nonce: None,
            peer_nonce: None,
            responder_confirm: None,
            mackey: None,
            ltk: None,
            pending_peer_irk: None,
        }
    }
}

impl Drop for SessionSecrets {
    fn drop(&mut self) {
        // WHY: every intermediate secret this session ever holds (nonces,
        // the DHKey, MacKey, LTK) must not outlive the session in memory,
        // matching the zeroize-on-drop posture `Irk` already established.
        // `EcdhKeyPair`'s inner `p256::ecdh::EphemeralSecret` already
        // zeroizes itself via its own `Drop` impl.
        if let Some(dhkey) = self.dhkey.as_mut() {
            dhkey.zeroize();
        }
        if let Some(nonce) = self.our_nonce.as_mut() {
            nonce.zeroize();
        }
        if let Some(nonce) = self.peer_nonce.as_mut() {
            nonce.zeroize();
        }
        if let Some(mackey) = self.mackey.as_mut() {
            mackey.zeroize();
        }
        if let Some(ltk) = self.ltk.as_mut() {
            ltk.zeroize();
        }
        if let Some(irk) = self.pending_peer_irk.as_mut() {
            irk.zeroize();
        }
    }
}

/// One SMP pairing procedure's full cryptographic state.
///
/// Borrows the device's persistent [`Irk`] rather than owning or
/// generating one — a device's IRK must stay the SAME across every
/// bonding for `generate_rpa` to remain resolvable by every peer it
/// distributes to, so provisioning it is the caller's job (kernel-side,
/// once at boot), not this session's.
pub(crate) struct PairingSession<'a> {
    role: Role,
    state: PairingState,

    our_features: PairingFeatures,
    peer_features: Option<PairingFeatures>,

    our_address: (u8, BdAddr),
    peer_address: (u8, BdAddr),
    our_irk: &'a Irk,

    /// Phase 2/3 cryptographic secret material — see [`SessionSecrets`].
    secrets: SessionSecrets,

    will_send_irk: bool,
    will_recv_irk: bool,
    sent_our_identity: bool,
    bonding_record: Option<BondingRecord>,
}

impl<'a> PairingSession<'a> {
    /// Start a new session for the given `role` over an already-established
    /// LE connection.
    ///
    /// `our_address`/`peer_address` are `(address_type, address)` for the
    /// CURRENT connection (`0x00` public, `0x01` random) — the `A1`/`A2`
    /// inputs [`toolbox::f5`]/[`toolbox::f6`] require. `our_irk` is the
    /// device's persistent Identity Resolving Key; distributing it is
    /// what closes #455's "a bonded peer can resolve the address."
    ///
    /// Note: this session also distributes `our_address` itself as the
    /// Phase 3 identity address (see the field's use in
    /// [`Self::send_our_identity_if_owed`]) — it does not yet model connecting
    /// with one (rotating) address and revealing a DIFFERENT stable
    /// identity address in Phase 3. That RPA-during-pairing refinement
    /// is spec-valid future work, not a correctness gap in what this
    /// session does implement.
    pub(crate) const fn new(
        role: Role,
        our_address: (u8, BdAddr),
        peer_address: (u8, BdAddr),
        our_irk: &'a Irk,
    ) -> Self {
        Self {
            role,
            state: match role {
                Role::Initiator => PairingState::NotStarted,
                Role::Responder => PairingState::AwaitingPairingRequest,
            },
            our_features: PairingFeatures::OURS,
            peer_features: None,
            our_address,
            peer_address,
            our_irk,
            secrets: SessionSecrets::new(),
            will_send_irk: false,
            will_recv_irk: false,
            sent_our_identity: false,
            bonding_record: None,
        }
    }

    /// Current state.
    pub(crate) const fn state(&self) -> PairingState {
        self.state
    }

    /// The bonded peer's identity, once Phase 3 has received it. `None`
    /// before then, or if the negotiated key distribution never included
    /// `IdKey` in the receive direction.
    pub(crate) const fn bonding_record(&self) -> Option<&BondingRecord> {
        self.bonding_record.as_ref()
    }

    /// Initiator only: produce the Pairing Request and advance to
    /// [`PairingState::AwaitingPairingResponse`].
    ///
    /// Returns `None` (no-op) if called on a [`Role::Responder`] session
    /// or a session already past [`PairingState::NotStarted`] — starting
    /// pairing twice, or from the wrong role, is a caller bug this
    /// returns rather than silently reinitiating.
    pub(crate) fn initiate(&mut self) -> Option<Vec<u8>> {
        if self.role != Role::Initiator || self.state != PairingState::NotStarted {
            return None;
        }
        self.state = PairingState::AwaitingPairingResponse;
        Some(pdu::encode_pairing_request(self.our_features).to_vec())
    }

    /// Feed one received SMP PDU payload (`L2capSdu::payload` on
    /// `CID_SMP`) into this session.
    ///
    /// Always returns bytes to send (possibly none) — a rejected PDU is
    /// signalled by [`Self::state`] becoming [`PairingState::Failed`] and
    /// the returned [`Outbound`] carrying exactly one Pairing Failed PDU,
    /// not by any `Result::Err`. A session already in `Failed` drops the
    /// input immediately and returns nothing further.
    pub(crate) fn handle_pdu(
        &mut self,
        data: &[u8],
        random: &mut dyn FnMut(&mut [u8]),
    ) -> Outbound {
        if matches!(self.state, PairingState::Failed(_) | PairingState::Complete) {
            return Vec::new();
        }

        match pdu::decode(data) {
            Ok(parsed) => self.dispatch(parsed, random),
            Err(_decode_error) => self.fail(PairingFailReason::Unspecified),
        }
    }

    /// Caller confirms the link is now encrypted with this session's
    /// derived LTK (via the HCI encryption round trip — see module
    /// docs). Produces this device's own Phase 3 PDUs, if the negotiated
    /// key distribution calls for sending any, and advances to
    /// [`PairingState::ExchangingKeys`] (or straight to
    /// [`PairingState::Complete`] if nothing is expected in either
    /// direction).
    ///
    /// A no-op (returns nothing, no state change) if called outside
    /// [`PairingState::AwaitingEncryption`] — this is the ONE gate
    /// Phase 3 PDUs are allowed past, so calling it early or twice must
    /// not be able to re-trigger key distribution.
    pub(crate) fn confirm_link_encrypted(&mut self) -> Outbound {
        if self.state != PairingState::AwaitingEncryption {
            return Vec::new();
        }
        self.state = PairingState::ExchangingKeys;
        let out = self.send_our_identity_if_owed();
        self.complete_if_key_exchange_done();
        out
    }

    // ── dispatch ──

    fn dispatch(&mut self, parsed: PairingPdu, random: &mut dyn FnMut(&mut [u8])) -> Outbound {
        match (self.state, parsed) {
            (PairingState::AwaitingPairingRequest, PairingPdu::PairingRequest(features)) => {
                self.on_pairing_request(features, random)
            }
            (PairingState::AwaitingPairingResponse, PairingPdu::PairingResponse(features)) => {
                self.on_pairing_response(features, random)
            }
            (PairingState::AwaitingPeerPublicKey, PairingPdu::PublicKey(pk)) => {
                self.on_public_key(pk, random)
            }
            (PairingState::AwaitingResponderConfirm, PairingPdu::PairingConfirm(confirm)) => {
                self.on_responder_confirm(confirm, random)
            }
            (PairingState::AwaitingResponderRandom, PairingPdu::PairingRandom(rand)) => {
                self.on_responder_random(rand)
            }
            (PairingState::AwaitingInitiatorRandom, PairingPdu::PairingRandom(rand)) => {
                self.on_initiator_random(rand)
            }
            (PairingState::AwaitingResponderDhKeyCheck, PairingPdu::DhKeyCheck(check)) => {
                self.on_responder_dhkey_check(check)
            }
            (PairingState::AwaitingInitiatorDhKeyCheck, PairingPdu::DhKeyCheck(check)) => {
                self.on_initiator_dhkey_check(check)
            }
            (PairingState::ExchangingKeys, PairingPdu::IdentityInformation(info)) => {
                self.on_identity_information(info)
            }
            (PairingState::ExchangingKeys, PairingPdu::IdentityAddressInformation(info)) => {
                self.on_identity_address_information(info)
            }
            // A peer aborting pairing itself: adopt its stated reason
            // rather than substituting our own — no PDU to send back.
            (_, PairingPdu::PairingFailed(reason)) => {
                self.state = PairingState::Failed(reason);
                Vec::new()
            }
            // Any other (state, PDU) pairing is out-of-order or
            // unexpected for what this session is currently waiting on.
            _ => self.fail(PairingFailReason::CommandNotSupported),
        }
    }

    // ── Phase 1 ──

    fn on_pairing_request(
        &mut self,
        features: PairingFeatures,
        random: &mut dyn FnMut(&mut [u8]),
    ) -> Outbound {
        let Some(rejection) = Self::validate_peer_features(features) else {
            self.peer_features = Some(features);
            self.will_recv_irk =
                features.initiator_key_dist.id_key && self.our_features.initiator_key_dist.id_key;
            self.will_send_irk =
                features.responder_key_dist.id_key && self.our_features.responder_key_dist.id_key;

            let ecdh = EcdhKeyPair::generate(random);
            let response = pdu::encode_pairing_response(self.our_features).to_vec();
            self.secrets.ecdh = Some(ecdh);
            self.state = PairingState::AwaitingPeerPublicKey;
            return vec![response];
        };
        self.fail(rejection)
    }

    fn on_pairing_response(
        &mut self,
        features: PairingFeatures,
        random: &mut dyn FnMut(&mut [u8]),
    ) -> Outbound {
        let Some(rejection) = Self::validate_peer_features(features) else {
            self.peer_features = Some(features);
            self.will_send_irk =
                features.initiator_key_dist.id_key && self.our_features.initiator_key_dist.id_key;
            self.will_recv_irk =
                features.responder_key_dist.id_key && self.our_features.responder_key_dist.id_key;

            let ecdh = EcdhKeyPair::generate(random);
            let our_key = pdu::encode_public_key(*ecdh.public_x(), *ecdh.public_y()).to_vec();
            self.secrets.ecdh = Some(ecdh);
            self.state = PairingState::AwaitingPeerPublicKey;
            return vec![our_key];
        };
        self.fail(rejection)
    }

    /// Shared Phase-1 validation for a received Pairing Request/Response:
    /// LE Secure Connections required, full encryption key size required.
    /// Returns `Some(reason)` to reject, `None` to accept.
    const fn validate_peer_features(features: PairingFeatures) -> Option<PairingFailReason> {
        if !features.auth_req.secure_connections {
            return Some(PairingFailReason::AuthenticationRequirements);
        }
        if features.max_key_size < REQUIRED_MAX_ENC_KEY_SIZE {
            return Some(PairingFailReason::EncryptionKeySize);
        }
        None
    }

    // ── Phase 2 ──

    fn on_public_key(&mut self, pk: PublicKey, random: &mut dyn FnMut(&mut [u8])) -> Outbound {
        let Some(ecdh) = self.secrets.ecdh.as_ref() else {
            return self.fail(PairingFailReason::Unspecified);
        };
        let Some(agreed) = ecdh.agree(&pk.x, &pk.y) else {
            return self.fail(PairingFailReason::InvalidParameters);
        };
        self.secrets.peer_public_x = Some(agreed.peer_x);
        self.secrets.dhkey = Some(agreed.shared);

        match self.role {
            Role::Initiator => {
                self.state = PairingState::AwaitingResponderConfirm;
                Vec::new()
            }
            Role::Responder => {
                let mut nonce = [0u8; 16];
                random(&mut nonce);
                self.secrets.our_nonce = Some(nonce);

                let Some(ecdh) = self.secrets.ecdh.as_ref() else {
                    return self.fail(PairingFailReason::Unspecified);
                };
                let Some(peer_x) = self.secrets.peer_public_x else {
                    return self.fail(PairingFailReason::Unspecified);
                };
                // Cb = f4(PKb_x, PKa_x, Nb, 0) — the responder commits
                // BEFORE seeing Na (module docs: this is the one
                // ordering property Just Works/Numeric Comparison relies
                // on for security).
                let cb = toolbox::f4(ecdh.public_x(), &peer_x, &nonce, ASSOCIATION_Z);
                self.secrets.responder_confirm = Some(cb);

                let our_key = pdu::encode_public_key(*ecdh.public_x(), *ecdh.public_y()).to_vec();
                let confirm = pdu::encode_pairing_confirm(cb).to_vec();
                self.state = PairingState::AwaitingInitiatorRandom;
                vec![our_key, confirm]
            }
        }
    }

    fn on_responder_confirm(
        &mut self,
        confirm: PairingConfirm,
        random: &mut dyn FnMut(&mut [u8]),
    ) -> Outbound {
        // Initiator only (state guard in `dispatch`): store Cb — now safe
        // to reveal Na, since the responder has already committed to Nb.
        self.secrets.responder_confirm = Some(confirm.value);
        let mut nonce = [0u8; 16];
        random(&mut nonce);
        self.secrets.our_nonce = Some(nonce);
        self.state = PairingState::AwaitingResponderRandom;
        vec![pdu::encode_pairing_random(nonce).to_vec()]
    }

    fn on_responder_random(&mut self, rand: PairingRandom) -> Outbound {
        // Initiator only (state guard): Nb has arrived — verify Cb
        // against it before trusting anything derived from it.
        self.secrets.peer_nonce = Some(rand.value);
        let (Some(ecdh), Some(peer_x), Some(nb), Some(cb)) = (
            self.secrets.ecdh.as_ref(),
            self.secrets.peer_public_x,
            self.secrets.peer_nonce,
            self.secrets.responder_confirm,
        ) else {
            return self.fail(PairingFailReason::Unspecified);
        };
        let expected_cb = toolbox::f4(&peer_x, ecdh.public_x(), &nb, ASSOCIATION_Z);
        if expected_cb != cb {
            return self.fail(PairingFailReason::ConfirmValueFailed);
        }
        self.derive_mackey_ltk_and_send_dhkey_check()
    }

    fn on_initiator_random(&mut self, rand: PairingRandom) -> Outbound {
        // Responder only (state guard): Na has arrived. Nb (our_nonce)
        // was already generated in `on_public_key`. Send Nb, then derive
        // keys and wait for the initiator's DHKey Check.
        self.secrets.peer_nonce = Some(rand.value);
        let Some(nb) = self.secrets.our_nonce else {
            return self.fail(PairingFailReason::Unspecified);
        };
        let random_pdu = pdu::encode_pairing_random(nb).to_vec();
        let mut out = self.derive_mackey_ltk_and_send_dhkey_check();
        // For the responder this derives keys and moves to
        // `AwaitingInitiatorDhKeyCheck` without producing a PDU of its
        // own (it must not send Eb before verifying Ea) — Nb is the only
        // thing to send at this transition.
        out.insert(0, random_pdu);
        out
    }

    /// Derive `MacKey`/`LTK` via [`toolbox::f5`] from the now-complete
    /// `Na`/`Nb` pair, then: as initiator, compute and send `Ea`; as
    /// responder, only derive (it must wait for `Ea` before sending
    /// `Eb` — see [`Self::on_initiator_dhkey_check`]).
    fn derive_mackey_ltk_and_send_dhkey_check(&mut self) -> Outbound {
        let (Some(dhkey), Some(na), Some(nb)) = (
            self.secrets.dhkey,
            self.our_nonce_for_role(),
            self.peer_nonce_for_role(),
        ) else {
            return self.fail(PairingFailReason::Unspecified);
        };
        let (a1, a2) = self.initiator_then_responder_addresses();
        let (mackey, ltk) = toolbox::f5(&dhkey, &na, &nb, &a1, &a2);
        self.secrets.mackey = Some(mackey);
        self.secrets.ltk = Some(ltk);

        match self.role {
            Role::Initiator => {
                let Some((io_cap_a, _io_cap_b)) = self.io_caps_initiator_then_responder() else {
                    return self.fail(PairingFailReason::Unspecified);
                };
                // Ea = f6(MacKey, Na, Nb, rb=0, IOcapA, A1, A2)
                let ea = toolbox::f6(&mackey, &na, &nb, &ASSOCIATION_R, &io_cap_a, &a1, &a2);
                self.state = PairingState::AwaitingResponderDhKeyCheck;
                vec![pdu::encode_dhkey_check(ea).to_vec()]
            }
            Role::Responder => {
                self.state = PairingState::AwaitingInitiatorDhKeyCheck;
                Vec::new()
            }
        }
    }

    /// `Na` for whichever role we are — initiator's own nonce, or the
    /// responder's stored copy of the initiator's nonce.
    const fn our_nonce_for_role(&self) -> Option<[u8; 16]> {
        match self.role {
            Role::Initiator => self.secrets.our_nonce,
            Role::Responder => self.secrets.peer_nonce,
        }
    }

    /// `Nb` for whichever role we are.
    const fn peer_nonce_for_role(&self) -> Option<[u8; 16]> {
        match self.role {
            Role::Initiator => self.secrets.peer_nonce,
            Role::Responder => self.secrets.our_nonce,
        }
    }

    /// `(A1, A2)` = (initiator's, responder's) identity-address bytes for
    /// [`toolbox::f5`]/[`toolbox::f6`]: `[address_type] ||
    /// [6-byte address, MSB first]`.
    fn initiator_then_responder_addresses(&self) -> ([u8; 7], [u8; 7]) {
        let (init, resp) = match self.role {
            Role::Initiator => (self.our_address.clone(), self.peer_address.clone()),
            Role::Responder => (self.peer_address.clone(), self.our_address.clone()),
        };
        (address_octets(init), address_octets(resp))
    }

    /// `(IOcapA, IOcapB)` for [`toolbox::f6`] — the initiator's and
    /// responder's `[AuthReq, OOB, IOCap]` triples, in that
    /// initiator-then-responder order regardless of which one we are.
    fn io_caps_initiator_then_responder(&self) -> Option<([u8; 3], [u8; 3])> {
        let peer = self.peer_features?;
        let (init, resp) = match self.role {
            Role::Initiator => (self.our_features, peer),
            Role::Responder => (peer, self.our_features),
        };
        Some((init.io_cap_for_check(), resp.io_cap_for_check()))
    }

    fn on_responder_dhkey_check(&mut self, check: DhKeyCheck) -> Outbound {
        // Initiator only (state guard): verify the responder's Eb.
        let (Some(mackey), Some(na), Some(nb)) = (
            self.secrets.mackey,
            self.secrets.our_nonce,
            self.secrets.peer_nonce,
        ) else {
            return self.fail(PairingFailReason::Unspecified);
        };
        let (a1, a2) = self.initiator_then_responder_addresses();
        let Some((_io_cap_a, io_cap_b)) = self.io_caps_initiator_then_responder() else {
            return self.fail(PairingFailReason::Unspecified);
        };
        // Eb = f6(MacKey, Nb, Na, ra=0, IOcapB, A2, A1)
        let expected_eb = toolbox::f6(&mackey, &nb, &na, &ASSOCIATION_R, &io_cap_b, &a2, &a1);
        if expected_eb != check.value {
            return self.fail(PairingFailReason::DhKeyCheckFailed);
        }
        self.state = PairingState::AwaitingEncryption;
        Vec::new()
    }

    fn on_initiator_dhkey_check(&mut self, check: DhKeyCheck) -> Outbound {
        // Responder only (state guard): verify the initiator's Ea, then
        // send our own Eb.
        let (Some(mackey), Some(na), Some(nb)) = (
            self.secrets.mackey,
            self.secrets.peer_nonce,
            self.secrets.our_nonce,
        ) else {
            return self.fail(PairingFailReason::Unspecified);
        };
        let (a1, a2) = self.initiator_then_responder_addresses();
        let Some((io_cap_a, io_cap_b)) = self.io_caps_initiator_then_responder() else {
            return self.fail(PairingFailReason::Unspecified);
        };
        let expected_ea = toolbox::f6(&mackey, &na, &nb, &ASSOCIATION_R, &io_cap_a, &a1, &a2);
        if expected_ea != check.value {
            return self.fail(PairingFailReason::DhKeyCheckFailed);
        }
        // Eb = f6(MacKey, Nb, Na, ra=0, IOcapB, A2, A1)
        let eb = toolbox::f6(&mackey, &nb, &na, &ASSOCIATION_R, &io_cap_b, &a2, &a1);
        self.state = PairingState::AwaitingEncryption;
        vec![pdu::encode_dhkey_check(eb).to_vec()]
    }

    // ── Phase 3 ──

    fn send_our_identity_if_owed(&mut self) -> Outbound {
        if !self.will_send_irk || self.sent_our_identity {
            return Vec::new();
        }
        self.sent_our_identity = true;
        let info = pdu::encode_identity_information(*self.our_irk.as_bytes()).to_vec();
        let (addr_type, addr) = &self.our_address;
        let addr_info = pdu::encode_identity_address_information(*addr_type, addr).to_vec();
        vec![info, addr_info]
    }

    fn on_identity_information(&mut self, info: IdentityInformation) -> Outbound {
        if !self.will_recv_irk {
            return self.fail(PairingFailReason::InvalidParameters);
        }
        self.secrets.pending_peer_irk = Some(info.irk);
        Vec::new()
    }

    fn on_identity_address_information(&mut self, info: IdentityAddressInformation) -> Outbound {
        let Some(irk_bytes) = self.secrets.pending_peer_irk.take() else {
            // Identity Address Information without a preceding Identity
            // Information: the spec-mandated pair order was violated.
            return self.fail(PairingFailReason::InvalidParameters);
        };
        self.bonding_record = Some(BondingRecord {
            peer_identity_address: (info.address_type, info.address),
            peer_irk: Irk::from_bytes(irk_bytes),
        });
        self.complete_if_key_exchange_done();
        Vec::new()
    }

    const fn complete_if_key_exchange_done(&mut self) {
        let send_done = !self.will_send_irk || self.sent_our_identity;
        let recv_done = !self.will_recv_irk || self.bonding_record.is_some();
        if send_done && recv_done {
            self.state = PairingState::Complete;
        }
    }

    // ── failure ──

    fn fail(&mut self, reason: PairingFailReason) -> Outbound {
        self.state = PairingState::Failed(reason);
        vec![pdu::encode_pairing_failed(reason).to_vec()]
    }
}

/// `[address_type] || [6-byte address, MSB first]` — the `A1`/`A2` octet
/// layout [`toolbox::f5`]/[`toolbox::f6`] require.
fn address_octets((address_type, address): (u8, BdAddr)) -> [u8; 7] {
    let mut out = [0u8; 7];
    out[0] = address_type;
    out[1..7].copy_from_slice(address.as_bytes());
    out
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hci::{self, PbFlag};
    use crate::l2cap::{self, CID_SMP, FixedChannel};
    use crate::smp::pdu::{AuthReq, IoCapability, KeyDistribution};
    use crate::transport::{self, BtHciTransport};

    /// A small deterministic byte stream — enough entropy variety for
    /// ECDH key generation and nonces to differ from call to call and
    /// from one session to another, never a real CSPRNG (test-only).
    fn fixed_stream(seed: u8) -> impl FnMut(&mut [u8]) {
        let mut counter = seed;
        move |buf: &mut [u8]| {
            for b in buf.iter_mut() {
                *b = counter;
                counter = counter.wrapping_add(1);
            }
        }
    }

    /// Generate a deterministic test [`Irk`] from the same kind of stream
    /// [`fixed_stream`] produces, adapted to `Irk::generate`'s
    /// fixed-size `FnOnce(&mut [u8; 16])` signature.
    fn fixed_irk(seed: u8) -> Irk {
        Irk::generate(|buf: &mut [u8; 16]| {
            let mut stream = fixed_stream(seed);
            stream(buf);
        })
    }

    fn test_addr(last_octet: u8) -> (u8, BdAddr) {
        let bytes = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, last_octet];
        (0x01, BdAddr::from_bytes(bytes))
    }

    /// Feed `pdu` through `handle_pdu` — a thin named wrapper so each
    /// handshake step below reads as "step(role, pdu)" rather than a bare
    /// method call, matching this test module's step-by-step narration.
    fn step(
        session: &mut PairingSession<'_>,
        pdu: &[u8],
        random: &mut dyn FnMut(&mut [u8]),
    ) -> Outbound {
        session.handle_pdu(pdu, random)
    }

    #[test]
    fn full_handshake_bonds_both_directions() {
        let alice_irk = fixed_irk(0x10);
        let bob_irk = fixed_irk(0x90);
        let alice_addr = test_addr(0x01);
        let bob_addr = test_addr(0x02);

        let mut alice = PairingSession::new(
            Role::Initiator,
            alice_addr.clone(),
            bob_addr.clone(),
            &alice_irk,
        );
        let mut bob = PairingSession::new(
            Role::Responder,
            bob_addr.clone(),
            alice_addr.clone(),
            &bob_irk,
        );

        let mut rng_a = fixed_stream(0x01);
        let mut rng_b = fixed_stream(0x81);

        // Phase 1: Request / Response.
        let Some(request) = alice.initiate() else {
            unreachable!("fresh initiator session must produce a Pairing Request");
        };
        let to_alice = step(&mut bob, &request, &mut rng_b);
        assert_eq!(to_alice.len(), 1);

        // Phase 2: Public Key exchange.
        let to_bob = step(&mut alice, &to_alice[0], &mut rng_a);
        assert_eq!(
            to_bob.len(),
            1,
            "Pairing Response draws the initiator's Public Key"
        );

        let to_alice = step(&mut bob, &to_bob[0], &mut rng_b);
        assert_eq!(
            to_alice.len(),
            2,
            "the responder replies to a Public Key with its own Public Key AND Confirm"
        );

        let empty = step(&mut alice, &to_alice[0], &mut rng_a);
        assert!(
            empty.is_empty(),
            "the responder's Public Key alone produces no output yet"
        );
        let to_bob = step(&mut alice, &to_alice[1], &mut rng_a);
        assert_eq!(
            to_bob.len(),
            1,
            "the responder's Confirm draws the initiator's Random (Na)"
        );

        let to_alice = step(&mut bob, &to_bob[0], &mut rng_b);
        assert_eq!(to_alice.len(), 1, "Na draws the responder's Random (Nb)");

        let to_bob = step(&mut alice, &to_alice[0], &mut rng_a);
        assert_eq!(
            to_bob.len(),
            1,
            "Nb (matching the earlier Cb) draws the initiator's DHKey Check (Ea)"
        );
        assert_eq!(alice.state(), PairingState::AwaitingResponderDhKeyCheck);

        let to_alice = step(&mut bob, &to_bob[0], &mut rng_b);
        assert_eq!(
            to_alice.len(),
            1,
            "a verified Ea draws the responder's DHKey Check (Eb)"
        );
        assert_eq!(bob.state(), PairingState::AwaitingEncryption);

        let empty = step(&mut alice, &to_alice[0], &mut rng_a);
        assert!(
            empty.is_empty(),
            "a verified Eb produces no PDU, just the encryption gate"
        );
        assert_eq!(alice.state(), PairingState::AwaitingEncryption);

        // Phase 3: gated on confirm_link_encrypted, then IdKey exchange.
        let alice_identity = alice.confirm_link_encrypted();
        assert_eq!(
            alice_identity.len(),
            2,
            "Identity Information + Identity Address Information"
        );
        let bob_identity = bob.confirm_link_encrypted();
        assert_eq!(bob_identity.len(), 2);

        for pdu in &alice_identity {
            let out = step(&mut bob, pdu, &mut rng_b);
            assert!(
                out.is_empty(),
                "receiving an identity PDU produces no reply PDU"
            );
        }
        for pdu in &bob_identity {
            let out = step(&mut alice, pdu, &mut rng_a);
            assert!(out.is_empty());
        }

        assert_eq!(alice.state(), PairingState::Complete);
        assert_eq!(bob.state(), PairingState::Complete);

        let Some(alice_bond) = alice.bonding_record() else {
            unreachable!("alice must have bonded bob's identity");
        };
        assert_eq!(alice_bond.peer_identity_address, bob_addr);
        assert_eq!(alice_bond.peer_irk.as_bytes(), bob_irk.as_bytes());

        let Some(bob_bond) = bob.bonding_record() else {
            unreachable!(
                "bob must have bonded alice's identity — this is #455's done-when: bob now holds the IRK needed to resolve alice's rotating RPA"
            );
        };
        assert_eq!(bob_bond.peer_identity_address, alice_addr);
        assert_eq!(bob_bond.peer_irk.as_bytes(), alice_irk.as_bytes());
    }

    // ── rejection paths ──

    #[test]
    fn responder_rejects_a_peer_that_will_not_negotiate_secure_connections() {
        let irk = fixed_irk(0x10);
        let mut bob = PairingSession::new(Role::Responder, test_addr(0x02), test_addr(0x01), &irk);

        let legacy_only = PairingFeatures {
            io_capability: IoCapability::NoInputNoOutput,
            oob_data_present: false,
            auth_req: AuthReq {
                bonding: true,
                mitm: false,
                secure_connections: false,
                keypress: false,
                ct2: false,
            },
            max_key_size: REQUIRED_MAX_ENC_KEY_SIZE,
            initiator_key_dist: KeyDistribution::ID_KEY_ONLY,
            responder_key_dist: KeyDistribution::ID_KEY_ONLY,
        };
        let wire = pdu::encode_pairing_request(legacy_only);
        let mut rng = fixed_stream(0x01);
        let out = bob.handle_pdu(&wire, &mut rng);

        assert_eq!(
            bob.state(),
            PairingState::Failed(PairingFailReason::AuthenticationRequirements)
        );
        assert_eq!(out.len(), 1, "must send exactly one Pairing Failed");
    }

    #[test]
    fn responder_rejects_an_encryption_key_size_downgrade() {
        let irk = fixed_irk(0x10);
        let mut bob = PairingSession::new(Role::Responder, test_addr(0x02), test_addr(0x01), &irk);

        let mut downgraded = PairingFeatures::OURS;
        downgraded.max_key_size = REQUIRED_MAX_ENC_KEY_SIZE - 1;
        let wire = pdu::encode_pairing_request(downgraded);
        let mut rng = fixed_stream(0x01);
        let _ = bob.handle_pdu(&wire, &mut rng);

        assert_eq!(
            bob.state(),
            PairingState::Failed(PairingFailReason::EncryptionKeySize)
        );
    }

    #[test]
    fn responder_rejects_an_out_of_order_pdu_before_any_request() {
        let irk = fixed_irk(0x10);
        let mut bob = PairingSession::new(Role::Responder, test_addr(0x02), test_addr(0x01), &irk);

        // A Pairing Confirm before any Pairing Request has been seen.
        let wire = pdu::encode_pairing_confirm([0x42; 16]);
        let mut rng = fixed_stream(0x01);
        let out = bob.handle_pdu(&wire, &mut rng);

        assert_eq!(
            bob.state(),
            PairingState::Failed(PairingFailReason::CommandNotSupported)
        );
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn malformed_pdu_bytes_are_rejected_without_panicking() {
        let irk = fixed_irk(0x10);
        let mut bob = PairingSession::new(Role::Responder, test_addr(0x02), test_addr(0x01), &irk);
        let mut rng = fixed_stream(0x01);

        let out = bob.handle_pdu(&[], &mut rng);
        assert_eq!(
            bob.state(),
            PairingState::Failed(PairingFailReason::Unspecified)
        );
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn a_failed_session_drops_further_input_instead_of_reprocessing() {
        let irk = fixed_irk(0x10);
        let mut bob = PairingSession::new(Role::Responder, test_addr(0x02), test_addr(0x01), &irk);
        let mut rng = fixed_stream(0x01);

        let _ = bob.handle_pdu(&[], &mut rng); // fails the session
        assert!(matches!(bob.state(), PairingState::Failed(_)));

        // A second, perfectly well-formed PDU must not resurrect it.
        let wire = pdu::encode_pairing_request(PairingFeatures::OURS);
        let out = bob.handle_pdu(&wire, &mut rng);
        assert!(
            out.is_empty(),
            "a session already Failed must silently drop further input, not reprocess it"
        );
        assert!(matches!(bob.state(), PairingState::Failed(_)));
    }

    #[test]
    fn initiator_rejects_a_peer_echoing_its_own_public_key() {
        let irk = fixed_irk(0x10);
        let mut alice =
            PairingSession::new(Role::Initiator, test_addr(0x01), test_addr(0x02), &irk);
        let mut rng_a = fixed_stream(0x01);

        let Some(request) = alice.initiate() else {
            unreachable!("fresh initiator must produce a Pairing Request");
        };
        let _ = request;
        let response = pdu::encode_pairing_response(PairingFeatures::OURS);
        let to_bob = alice.handle_pdu(&response, &mut rng_a);
        assert_eq!(to_bob.len(), 1, "Pairing Response draws our own Public Key");

        // Replay alice's own just-sent Public Key back at her as if it
        // were the peer's (Vol 3 Part H §2.3.5.6.1).
        let out = alice.handle_pdu(&to_bob[0], &mut rng_a);
        assert_eq!(
            alice.state(),
            PairingState::Failed(PairingFailReason::InvalidParameters)
        );
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn initiator_rejects_a_tampered_confirm_value() {
        let alice_irk = fixed_irk(0x10);
        let bob_irk = fixed_irk(0x90);
        let mut alice = PairingSession::new(
            Role::Initiator,
            test_addr(0x01),
            test_addr(0x02),
            &alice_irk,
        );
        let mut bob =
            PairingSession::new(Role::Responder, test_addr(0x02), test_addr(0x01), &bob_irk);
        let mut rng_a = fixed_stream(0x01);
        let mut rng_b = fixed_stream(0x81);

        let Some(request) = alice.initiate() else {
            unreachable!()
        };
        let to_alice = bob.handle_pdu(&request, &mut rng_b);
        let to_bob = alice.handle_pdu(&to_alice[0], &mut rng_a);
        let to_alice = bob.handle_pdu(&to_bob[0], &mut rng_b);
        // to_alice[0] = bob's Public Key, to_alice[1] = bob's Confirm (Cb).
        let _ = alice.handle_pdu(&to_alice[0], &mut rng_a);

        // Tamper the Confirm value before alice ever sees the real one.
        let Ok(PairingPdu::PairingConfirm(real)) = pdu::decode(&to_alice[1]) else {
            unreachable!("just-encoded Confirm must decode");
        };
        let mut tampered = real.value;
        tampered[0] ^= 0xFF;
        let tampered_wire = pdu::encode_pairing_confirm(tampered);

        let out = alice.handle_pdu(&tampered_wire, &mut rng_a);
        // alice now sends Na (she cannot detect a bad Cb until Nb
        // arrives — that IS the commit/reveal scheme's point).
        assert_eq!(out.len(), 1);
        assert_eq!(alice.state(), PairingState::AwaitingResponderRandom);

        let to_bob = out;
        let to_alice = bob.handle_pdu(&to_bob[0], &mut rng_b);
        // Feed bob's REAL Nb back to alice: it won't match the tampered Cb.
        let out = alice.handle_pdu(&to_alice[0], &mut rng_a);
        assert_eq!(
            alice.state(),
            PairingState::Failed(PairingFailReason::ConfirmValueFailed)
        );
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn responder_rejects_dhkey_check_mismatch() {
        let alice_irk = fixed_irk(0x10);
        let bob_irk = fixed_irk(0x90);
        let mut alice = PairingSession::new(
            Role::Initiator,
            test_addr(0x01),
            test_addr(0x02),
            &alice_irk,
        );
        let mut bob =
            PairingSession::new(Role::Responder, test_addr(0x02), test_addr(0x01), &bob_irk);
        let mut rng_a = fixed_stream(0x01);
        let mut rng_b = fixed_stream(0x81);

        let Some(request) = alice.initiate() else {
            unreachable!()
        };
        let to_alice = bob.handle_pdu(&request, &mut rng_b);
        let to_bob = alice.handle_pdu(&to_alice[0], &mut rng_a);
        let to_alice = bob.handle_pdu(&to_bob[0], &mut rng_b);
        let _ = alice.handle_pdu(&to_alice[0], &mut rng_a);
        let to_bob = alice.handle_pdu(&to_alice[1], &mut rng_a);
        let to_alice = bob.handle_pdu(&to_bob[0], &mut rng_b);
        let to_bob = alice.handle_pdu(&to_alice[0], &mut rng_a);
        assert_eq!(alice.state(), PairingState::AwaitingResponderDhKeyCheck);

        // Tamper Ea before bob ever sees the real one.
        let Ok(PairingPdu::DhKeyCheck(real_ea)) = pdu::decode(&to_bob[0]) else {
            unreachable!("just-encoded DHKey Check must decode");
        };
        let mut tampered = real_ea.value;
        tampered[0] ^= 0xFF;
        let tampered_wire = pdu::encode_dhkey_check(tampered);

        let out = bob.handle_pdu(&tampered_wire, &mut rng_b);
        assert_eq!(
            bob.state(),
            PairingState::Failed(PairingFailReason::DhKeyCheckFailed)
        );
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn identity_address_information_without_preceding_identity_information_is_rejected() {
        let alice_irk = fixed_irk(0x10);
        let bob_irk = fixed_irk(0x90);
        let mut alice = PairingSession::new(
            Role::Initiator,
            test_addr(0x01),
            test_addr(0x02),
            &alice_irk,
        );
        let mut bob =
            PairingSession::new(Role::Responder, test_addr(0x02), test_addr(0x01), &bob_irk);
        let mut rng_a = fixed_stream(0x01);
        let mut rng_b = fixed_stream(0x81);

        let Some(request) = alice.initiate() else {
            unreachable!()
        };
        let to_alice = bob.handle_pdu(&request, &mut rng_b);
        let to_bob = alice.handle_pdu(&to_alice[0], &mut rng_a);
        let to_alice = bob.handle_pdu(&to_bob[0], &mut rng_b);
        let _ = alice.handle_pdu(&to_alice[0], &mut rng_a);
        let to_bob = alice.handle_pdu(&to_alice[1], &mut rng_a);
        let to_alice = bob.handle_pdu(&to_bob[0], &mut rng_b);
        let to_bob = alice.handle_pdu(&to_alice[0], &mut rng_a);
        let to_alice = bob.handle_pdu(&to_bob[0], &mut rng_b);
        let _ = alice.handle_pdu(&to_alice[0], &mut rng_a);
        assert_eq!(alice.state(), PairingState::AwaitingEncryption);

        let _ = alice.confirm_link_encrypted();
        assert_eq!(alice.state(), PairingState::ExchangingKeys);

        // Send Identity Address Information with no prior Identity
        // Information for this session.
        let (addr_type, addr) = test_addr(0x99);
        let wire = pdu::encode_identity_address_information(addr_type, &addr);
        let out = alice.handle_pdu(&wire, &mut rng_a);
        assert_eq!(
            alice.state(),
            PairingState::Failed(PairingFailReason::InvalidParameters)
        );
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn confirm_link_encrypted_before_dhkey_check_is_a_no_op() {
        let irk = fixed_irk(0x10);
        let mut alice =
            PairingSession::new(Role::Initiator, test_addr(0x01), test_addr(0x02), &irk);
        // Called far too early: no Public Key, no DHKey Check yet.
        let out = alice.confirm_link_encrypted();
        assert!(out.is_empty());
        assert_eq!(alice.state(), PairingState::NotStarted);
    }

    #[test]
    fn initiate_on_a_responder_session_is_a_no_op() {
        let irk = fixed_irk(0x10);
        let mut bob = PairingSession::new(Role::Responder, test_addr(0x02), test_addr(0x01), &irk);
        assert_eq!(bob.initiate(), None);
        assert_eq!(bob.state(), PairingState::AwaitingPairingRequest);
    }

    // ── #635/#657 composition: pairing + RPA over the real L2CAP dispatch ──
    //
    // `full_handshake_bonds_both_directions` above proves the state
    // machine correctly derives and exchanges IRKs, but it calls
    // `handle_pdu` directly with each PDU's raw SMP bytes — it never
    // touches `crate::l2cap`/`crate::transport`, so it does not prove SMP
    // PDUs actually travel the CID 0x0006 fixed channel #635/#657 built.
    // The helpers and tests below route the SAME handshake through the
    // real STP -> HCI ACL -> L2CAP dispatch pipeline, and then close
    // #455's "a bonded peer can resolve the address": the bonded IRK used
    // to resolve an RPA is the one the handshake itself delivered, not a
    // shared constant.

    /// Deliver one SMP PDU to `receiver`'s RX path exactly as a real combo
    /// chip forwarding an over-the-air SMP PDU would: L2CAP Basic-mode
    /// framing (CID 0x0006) inside one HCI ACL Data H4 packet inside one
    /// STP frame, pushed into the RX ring.
    fn deliver_smp_pdu(receiver: &mut BtHciTransport, seq: u8, handle: u16, smp_payload: &[u8]) {
        let l2cap_frame = l2cap::encode_pdu(CID_SMP, smp_payload);
        let acl_frame = hci::encode_acl_data(handle, PbFlag::FirstNonFlushable, 0b00, &l2cap_frame);
        let mut stp_buf = vec![0u8; acl_frame.len() + 16];
        let Ok(written) = transport::stp_encode(seq, &acl_frame, &mut stp_buf) else {
            unreachable!("a small SMP PDU always fits a buffer sized for it");
        };
        assert!(
            receiver.push_rx(&stp_buf[..written]),
            "test RX ring must have room for one small SMP PDU"
        );
    }

    /// Drain the next SMP PDU FROM `receiver` via the real STP -> HCI ACL
    /// -> L2CAP dispatch pipeline (`recv_l2cap_pdu`, #635/#657), asserting
    /// it actually resolved to the SMP fixed channel rather than being
    /// accepted off some other CID.
    fn recv_smp_pdu(receiver: &mut BtHciTransport) -> Vec<u8> {
        let Ok(Some(sdu)) = receiver.recv_l2cap_pdu() else {
            unreachable!("a delivered single-fragment SMP PDU must reassemble immediately");
        };
        assert_eq!(
            FixedChannel::from_cid(sdu.cid),
            FixedChannel::Smp,
            "an SMP PDU must dispatch via CID 0x0006, not be accepted off some other channel"
        );
        sdu.payload
    }

    /// Deliver every PDU in `outgoing` to `receiver` through the real
    /// L2CAP dispatch, feed each through `receiver.handle_pdu`, and return
    /// the concatenation of whatever that produces — the dispatch-routed
    /// equivalent of `full_handshake_bonds_both_directions`'s `step`
    /// helper above.
    fn relay(
        receiver: &mut PairingSession<'_>,
        receiver_transport: &mut BtHciTransport,
        handle: u16,
        seq: &mut u8,
        outgoing: &[Vec<u8>],
        random: &mut dyn FnMut(&mut [u8]),
    ) -> Outbound {
        let mut produced = Vec::new();
        for pdu in outgoing {
            deliver_smp_pdu(receiver_transport, *seq, handle, pdu);
            *seq = seq.wrapping_add(1) & 0x0F;
            let payload = recv_smp_pdu(receiver_transport);
            produced.extend(receiver.handle_pdu(&payload, &mut *random));
        }
        produced
    }

    /// Run the full LE Secure Connections handshake between `alice`
    /// (initiator) and `bob` (responder) with every PDU routed through the
    /// real L2CAP dispatch pipeline rather than a direct `handle_pdu`
    /// call. Leaves both sessions `Complete` with a populated
    /// `bonding_record`, mirroring `full_handshake_bonds_both_directions`.
    fn run_handshake_via_l2cap(
        alice: &mut PairingSession<'_>,
        bob: &mut PairingSession<'_>,
        rng_a: &mut dyn FnMut(&mut [u8]),
        rng_b: &mut dyn FnMut(&mut [u8]),
    ) {
        let mut alice_transport = BtHciTransport::new();
        let mut bob_transport = BtHciTransport::new();
        let (alice_handle, bob_handle) = (0x0040u16, 0x0041u16);
        let (mut seq_to_alice, mut seq_to_bob) = (0u8, 0u8);

        let Some(request) = alice.initiate() else {
            unreachable!("a fresh initiator session must produce a Pairing Request");
        };

        // Phase 1-2: alternate delivery until a side's handle_pdu produces
        // nothing further to send. That happens exactly once, right after
        // alice accepts bob's verified DHKey Check — mirrors the fixed
        // step sequence `full_handshake_bonds_both_directions` walks
        // through manually.
        let mut pending = vec![request];
        let mut next_is_bob = true;
        loop {
            pending = if next_is_bob {
                relay(
                    bob,
                    &mut bob_transport,
                    bob_handle,
                    &mut seq_to_bob,
                    &pending,
                    rng_b,
                )
            } else {
                relay(
                    alice,
                    &mut alice_transport,
                    alice_handle,
                    &mut seq_to_alice,
                    &pending,
                    rng_a,
                )
            };
            if pending.is_empty() {
                break;
            }
            next_is_bob = !next_is_bob;
        }
        assert_eq!(alice.state(), PairingState::AwaitingEncryption);
        assert_eq!(bob.state(), PairingState::AwaitingEncryption);

        // Phase 3: gated on confirm_link_encrypted, then IdKey exchange —
        // same shape as `full_handshake_bonds_both_directions`.
        let alice_identity = alice.confirm_link_encrypted();
        let bob_identity = bob.confirm_link_encrypted();
        let to_bob = relay(
            bob,
            &mut bob_transport,
            bob_handle,
            &mut seq_to_bob,
            &alice_identity,
            rng_b,
        );
        assert!(
            to_bob.is_empty(),
            "receiving an identity PDU produces no reply PDU"
        );
        let to_alice = relay(
            alice,
            &mut alice_transport,
            alice_handle,
            &mut seq_to_alice,
            &bob_identity,
            rng_a,
        );
        assert!(to_alice.is_empty());

        assert_eq!(alice.state(), PairingState::Complete);
        assert_eq!(bob.state(), PairingState::Complete);
    }

    #[test]
    fn full_handshake_bonds_both_directions_via_l2cap_dispatch() {
        let alice_irk = fixed_irk(0x20);
        let bob_irk = fixed_irk(0xA0);
        let alice_addr = test_addr(0x11);
        let bob_addr = test_addr(0x12);

        let mut alice = PairingSession::new(
            Role::Initiator,
            alice_addr.clone(),
            bob_addr.clone(),
            &alice_irk,
        );
        let mut bob = PairingSession::new(
            Role::Responder,
            bob_addr.clone(),
            alice_addr.clone(),
            &bob_irk,
        );
        let mut rng_a = fixed_stream(0x02);
        let mut rng_b = fixed_stream(0x82);

        run_handshake_via_l2cap(&mut alice, &mut bob, &mut rng_a, &mut rng_b);

        let Some(alice_bond) = alice.bonding_record() else {
            unreachable!("alice must have bonded bob's identity over the L2CAP dispatch path");
        };
        assert_eq!(alice_bond.peer_identity_address, bob_addr);
        assert_eq!(alice_bond.peer_irk.as_bytes(), bob_irk.as_bytes());

        let Some(bob_bond) = bob.bonding_record() else {
            unreachable!("bob must have bonded alice's identity over the L2CAP dispatch path");
        };
        assert_eq!(bob_bond.peer_identity_address, alice_addr);
        assert_eq!(
            bob_bond.peer_irk.as_bytes(),
            alice_irk.as_bytes(),
            "the IRK bob holds must be the one alice's session distributed, delivered through CID 0x0006 — not a copy handed over out of band"
        );
    }

    #[test]
    fn bonded_peer_resolves_an_rpa_generated_with_the_protocol_obtained_irk() {
        let alice_irk = fixed_irk(0x30);
        let bob_irk = fixed_irk(0xB0);
        let alice_addr = test_addr(0x21);
        let bob_addr = test_addr(0x22);

        let mut alice = PairingSession::new(
            Role::Initiator,
            alice_addr.clone(),
            bob_addr.clone(),
            &alice_irk,
        );
        // Neither address is used again after this — move rather than
        // clone (clippy::redundant_clone).
        let mut bob = PairingSession::new(Role::Responder, bob_addr, alice_addr, &bob_irk);
        let mut rng_a = fixed_stream(0x03);
        let mut rng_b = fixed_stream(0x83);

        run_handshake_via_l2cap(&mut alice, &mut bob, &mut rng_a, &mut rng_b);

        let Some(bob_bond) = bob.bonding_record() else {
            unreachable!("bob must hold alice's bonded IRK after the handshake");
        };

        // Alice generates an RPA with HER OWN IRK. `prand`'s top two bits
        // are deliberately NOT already 0b01 (0x2C = 0b00101100) — proves
        // generate_rpa hashes what actually lands in the address (#455
        // fix), not whatever raw bits the caller passed.
        let prand = [0x2C, 0x71, 0x9A];
        let alice_rpa = transport::generate_rpa(alice_irk.as_bytes(), &prand);

        // Peer B resolves using the IRK IT OBTAINED THROUGH THE HANDSHAKE
        // — never `alice_irk` directly. This is #455's "a bonded peer can
        // resolve the address," composed end to end: the IRK travelled
        // through the pairing protocol over the real L2CAP dispatch, and
        // is what actually resolves the address.
        assert!(
            transport::resolve_rpa(bob_bond.peer_irk.as_bytes(), &alice_rpa),
            "bob must resolve alice's RPA using the IRK the pairing handshake gave him"
        );

        // Negative case: an unbonded/wrong IRK must NOT resolve it — a
        // resolver that returns true for everything would pass the
        // positive assertion above too.
        let unbonded_irk = fixed_irk(0xE0);
        assert!(
            !transport::resolve_rpa(unbonded_irk.as_bytes(), &alice_rpa),
            "an IRK that never bonded with alice must not resolve her RPA"
        );
    }
}
