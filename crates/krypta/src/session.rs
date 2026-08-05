//! Session management: two-party encrypted communication over a shared ratchet.

use crate::error::Result;
use crate::identity::{IdentityKeyPair, PublicIdentityKey};
use crate::ratchet::{self, CiphertextMessage, RatchetState};
use crate::x3dh::{self, InitiatorMessage, OwnedBundle, PreKeyBundle};

/// An encrypted message ready for transmission.
#[derive(Debug, Clone)]
pub(crate) struct EncryptedMessage {
    /// The ratchet-encrypted ciphertext payload.
    pub(crate) inner: CiphertextMessage,
}

/// Two-party encrypted session backed by directional symmetric chain
/// ratchets (one HMAC chain per direction).
///
/// The initiator (Alice) calls [`Session::initiate`]; the responder (Bob)
/// calls [`Session::respond`]. After setup both sessions share the same
/// root key material and can exchange encrypted messages. This is NOT the
/// Signal Double Ratchet — the chains advance symmetrically with no DH
/// ratchet step (#543).
pub(crate) struct Session {
    identity: IdentityKeyPair,
    peer_identity: PublicIdentityKey,
    /// Ratchet for messages we send.
    send_ratchet: RatchetState,
    /// Ratchet for messages we receive.
    recv_ratchet: RatchetState,
    /// Ephemeral public key we generated (initiator only), so the caller
    /// can hand it to the responder.
    initiator_msg: Option<InitiatorMessage>,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("identity", &self.identity)
            .field("peer_identity", &self.peer_identity)
            .field("send_ratchet", &self.send_ratchet)
            .field("recv_ratchet", &self.recv_ratchet)
            .finish_non_exhaustive()
    }
}

impl Session {
    /// Initiates a session with the party identified by `their_bundle`.
    ///
    /// Returns the session. Call [`Session::initiator_message`] to retrieve
    /// the message that must be sent to the responder so it can compute the
    /// matching session keys.
    ///
    /// # Errors
    ///
    /// Returns an error if key generation, DH agreement, or HKDF derivation fails.
    pub(crate) fn initiate(
        our_identity: IdentityKeyPair,
        their_bundle: &PreKeyBundle,
    ) -> Result<Self> {
        let (_, keys, init_msg) = x3dh::initiate_session(&our_identity, their_bundle)?;
        let peer_identity = their_bundle.identity_key.clone();
        Ok(Self {
            identity: our_identity,
            peer_identity,
            send_ratchet: RatchetState::new(keys.initiator_to_responder),
            recv_ratchet: RatchetState::new(keys.responder_to_initiator),
            initiator_msg: Some(init_msg),
        })
    }

    /// Returns the initiator message to forward to the responder.
    /// `None` if this is not the initiating session.
    pub(crate) const fn initiator_message(&self) -> Option<&InitiatorMessage> {
        self.initiator_msg.as_ref()
    }

    /// Responds to a session initiated by `their_message`, consuming `our_bundle`.
    ///
    /// # Errors
    ///
    /// Returns an error if DH agreement or HKDF derivation fails.
    pub(crate) fn respond(
        our_identity: IdentityKeyPair,
        our_bundle: OwnedBundle,
        their_message: &InitiatorMessage,
    ) -> Result<Self> {
        let (_, keys) = x3dh::respond_session(our_bundle, their_message)?;
        let peer_identity = their_message.identity_key.clone();
        Ok(Self {
            identity: our_identity,
            peer_identity,
            // Responder's send key matches initiator's recv key.
            send_ratchet: RatchetState::new(keys.responder_to_initiator),
            recv_ratchet: RatchetState::new(keys.initiator_to_responder),
            initiator_msg: None,
        })
    }

    /// Encrypts `plaintext` for the peer, advancing the send ratchet.
    ///
    /// # Errors
    ///
    /// Returns an error if AES-256-GCM sealing fails.
    pub(crate) fn encrypt_message(&mut self, plaintext: &[u8]) -> Result<EncryptedMessage> {
        let ct = ratchet::encrypt(&mut self.send_ratchet, plaintext)?;
        Ok(EncryptedMessage { inner: ct })
    }

    /// Decrypts an [`EncryptedMessage`] from the peer, advancing the receive ratchet.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Decryption`] if the authentication tag is invalid or the
    /// ciphertext has been tampered with.
    pub(crate) fn decrypt_message(&mut self, msg: &EncryptedMessage) -> Result<Vec<u8>> {
        ratchet::decrypt(&mut self.recv_ratchet, &msg.inner)
    }

    /// Returns the local identity's public key.
    pub(crate) const fn our_identity(&self) -> PublicIdentityKey {
        self.identity.public_key()
    }

    /// Returns the peer's public identity key.
    pub(crate) const fn peer_identity(&self) -> &PublicIdentityKey {
        &self.peer_identity
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::IdentityKeyPair;
    use crate::x3dh;

    fn make_sessions() -> Result<(Session, Session)> {
        let alice_id = IdentityKeyPair::generate()?;
        let bob_id = IdentityKeyPair::generate()?;
        let bob_bundle = x3dh::create_bundle(&bob_id)?;
        let pub_bundle = bob_bundle.public_bundle.clone();

        let alice_session = Session::initiate(alice_id, &pub_bundle)?;

        let init_msg = alice_session
            .initiator_message()
            .ok_or_else(|| crate::error::Error::KeyAgreement {
                location: snafu::location!(),
            })?
            .clone();

        let bob_session = Session::respond(bob_id, bob_bundle, &init_msg)?;
        Ok((alice_session, bob_session))
    }

    #[test]
    fn session_initiate_succeeds() -> Result<()> {
        let alice_id = IdentityKeyPair::generate()?;
        let bob_id = IdentityKeyPair::generate()?;
        let bob_bundle = x3dh::create_bundle(&bob_id)?;
        let session = Session::initiate(alice_id, &bob_bundle.public_bundle)?;
        assert!(
            session.initiator_message().is_some(),
            "initiator session must produce an initiator message"
        );
        Ok(())
    }

    #[test]
    fn full_send_receive_flow_alice_to_bob() -> Result<()> {
        let (mut alice, mut bob) = make_sessions()?;
        let plaintext = b"hello FROM alice";
        let encrypted = alice.encrypt_message(plaintext)?;
        let decrypted = bob.decrypt_message(&encrypted)?;
        assert_eq!(
            decrypted.as_slice(),
            plaintext,
            "bob must recover alice's plaintext"
        );
        Ok(())
    }

    #[test]
    fn full_send_receive_flow_bob_to_alice() -> Result<()> {
        let (mut alice, mut bob) = make_sessions()?;
        let plaintext = b"hello FROM bob";
        let encrypted = bob.encrypt_message(plaintext)?;
        let decrypted = alice.decrypt_message(&encrypted)?;
        assert_eq!(
            decrypted.as_slice(),
            plaintext,
            "alice must recover bob's plaintext"
        );
        Ok(())
    }

    #[test]
    fn full_send_receive_multiple_messages() -> Result<()> {
        let (mut alice, mut bob) = make_sessions()?;
        let messages: &[&[u8]] = &[b"first", b"second", b"third"];
        for msg in messages {
            let ct = alice.encrypt_message(msg)?;
            let pt = bob.decrypt_message(&ct)?;
            assert_eq!(pt.as_slice(), *msg, "each message must round-trip");
        }
        Ok(())
    }

    #[test]
    fn session_recovers_from_out_of_order_and_dropped_messages() -> Result<()> {
        // #212 end-to-end: a session tolerates reordering and a permanent drop.
        let (mut alice, mut bob) = make_sessions()?;
        let m0 = alice.encrypt_message(b"zero")?;
        let _dropped = alice.encrypt_message(b"one-dropped")?;
        let m2 = alice.encrypt_message(b"two")?;
        let m3 = alice.encrypt_message(b"three")?;

        // Deliver 3 before 2 (reordered), never deliver the dropped message 1.
        assert_eq!(bob.decrypt_message(&m0)?.as_slice(), b"zero");
        assert_eq!(bob.decrypt_message(&m3)?.as_slice(), b"three");
        assert_eq!(
            bob.decrypt_message(&m2)?.as_slice(),
            b"two",
            "reordered message must decrypt after a later one"
        );
        Ok(())
    }

    #[test]
    fn decryption_with_wrong_session_fails() -> Result<()> {
        let (mut alice, _bob) = make_sessions()?;
        let (_, mut mallory) = make_sessions()?;
        let ct = alice.encrypt_message(b"secret")?;
        assert!(
            mallory.decrypt_message(&ct).is_err(),
            "decryption by a party with wrong session keys must fail"
        );
        Ok(())
    }

    #[test]
    fn session_exposes_peer_identity() -> Result<()> {
        let alice_id = IdentityKeyPair::generate()?;
        let bob_id = IdentityKeyPair::generate()?;
        let bob_pub = bob_id.public_key();
        let bob_bundle = x3dh::create_bundle(&bob_id)?;
        let alice = Session::initiate(alice_id, &bob_bundle.public_bundle)?;
        assert_eq!(
            alice.peer_identity(),
            &bob_pub,
            "session must record the peer's identity key"
        );
        Ok(())
    }
}
