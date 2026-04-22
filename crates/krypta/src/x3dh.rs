//! X3DH-style key agreement: pre-key bundles, X25519 ECDH, HKDF session key derivation.

use ring::agreement::{EphemeralPrivateKey, UnparsedPublicKey, X25519};
use ring::rand::SystemRandom;

use crate::error::{KeyAgreementSnafu, KeyDerivationSnafu, KeyGenerationSnafu, Result};
use crate::identity::{IdentityKeyPair, PublicIdentityKey};

const X25519_KEY_LEN: usize = 32;
const HKDF_SALT: [u8; 32] = [0u8; 32];

/// Public pre-key bundle advertised by a party. Contains no private material.
#[derive(Debug, Clone)]
pub(crate) struct PreKeyBundle {
    /// Ed25519 public identity key.
    pub(crate) identity_key: PublicIdentityKey,
    /// X25519 signed pre-key public bytes.
    pub(crate) signed_prekey: [u8; X25519_KEY_LEN],
    /// Ed25519 signature of `signed_prekey` by `identity_key`.
    pub(crate) prekey_signature: Vec<u8>,
    /// Optional one-time X25519 pre-key public bytes.
    pub(crate) one_time_prekey: Option<[u8; X25519_KEY_LEN]>,
}

/// Owned bundle: full bundle including private pre-key material.
/// Not clonable; private keys are single-use.
pub(crate) struct OwnedBundle {
    /// Public side  -  share this with initiators.
    pub(crate) public_bundle: PreKeyBundle,
    signed_prekey_private: EphemeralPrivateKey,
    one_time_prekey_private: Option<EphemeralPrivateKey>,
}

impl std::fmt::Debug for OwnedBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnedBundle")
            .field("public_bundle", &self.public_bundle)
            .finish_non_exhaustive()
    }
}

/// Derived shared secret (32 bytes). Not Clone intentionally.
pub(crate) struct SharedSecret {
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "crate-internal API — raw is unused in lib but accessed in tests and available to future consumers"
        )
    )]
    pub(crate) raw: [u8; 32],
}

impl std::fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedSecret")
            .field("raw", &"[REDACTED]")
            .finish()
    }
}

/// Session keys derived FROM a shared secret via HKDF.
pub(crate) struct SessionKeys {
    /// Key for messages FROM initiator to responder.
    pub(crate) initiator_to_responder: [u8; 32],
    /// Key for messages FROM responder to initiator.
    pub(crate) responder_to_initiator: [u8; 32],
}

impl std::fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionKeys")
            .field("initiator_to_responder", &"[REDACTED]")
            .field("responder_to_initiator", &"[REDACTED]")
            .finish()
    }
}

/// Message sent by the initiator to the responder after session setup.
#[derive(Debug, Clone)]
pub(crate) struct InitiatorMessage {
    /// Initiator's Ed25519 public identity key.
    pub(crate) identity_key: PublicIdentityKey,
    /// Initiator's primary ephemeral X25519 key (used for DH with signed pre-key).
    pub(crate) ephemeral_key: [u8; X25519_KEY_LEN],
    /// Initiator's second ephemeral key for DH with the one-time pre-key, if present.
    pub(crate) one_time_ephemeral_key: Option<[u8; X25519_KEY_LEN]>,
}

/// Creates a new pre-key bundle for `identity`, generating fresh X25519 pre-keys.
///
/// # Errors
///
/// Returns [`Error::KeyGeneration`] if key generation fails.
/// Returns [`Error::InvalidKey`] if the signing step fails.
pub(crate) fn create_bundle(identity: &IdentityKeyPair) -> Result<OwnedBundle> {
    let rng = SystemRandom::new();

    let (spk_priv, spk_pub) = generate_x25519(&rng)?;
    let prekey_signature = identity.sign(&spk_pub)?;
    let (otpk_priv, otpk_pub) = generate_x25519(&rng)?;

    Ok(OwnedBundle {
        public_bundle: PreKeyBundle {
            identity_key: identity.public_key(),
            signed_prekey: spk_pub,
            prekey_signature,
            one_time_prekey: Some(otpk_pub),
        },
        signed_prekey_private: spk_priv,
        one_time_prekey_private: Some(otpk_priv),
    })
}

/// Initiates a session with a party identified by `their_bundle`.
///
/// Returns `(shared_secret, session_keys, initiator_message)`. The
/// `initiator_message` must be transmitted to the responder so they can
/// reproduce the shared secret.
///
/// # Errors
///
/// Returns [`Error::KeyGeneration`] if ephemeral key generation fails.
/// Returns [`Error::KeyAgreement`] if any DH step fails.
/// Returns [`Error::KeyDerivation`] if HKDF expansion fails.
pub(crate) fn initiate_session(
    our_identity: &IdentityKeyPair,
    their_bundle: &PreKeyBundle,
) -> Result<(SharedSecret, SessionKeys, InitiatorMessage)> {
    let rng = SystemRandom::new();

    // Primary ephemeral key for DH with signed pre-key.
    let (spk_eph_priv, spk_eph_pub) = generate_x25519(&rng)?;
    let dh1 = agree(spk_eph_priv, &their_bundle.signed_prekey)?;

    // Optional second ephemeral key for DH with one-time pre-key.
    // Each DH uses a separate key because ring consumes EphemeralPrivateKey on use.
    // The second ephemeral public key is included in InitiatorMessage so the
    // responder can compute the matching DH output.
    let (ikm, otp_eph_pub) = match their_bundle.one_time_prekey {
        Some(bundle_otp_pub) => {
            let (otp_eph_priv, otp_pub) = generate_x25519(&rng)?;
            let dh2 = agree(otp_eph_priv, &bundle_otp_pub)?;
            let mut combined = [0u8; 64];
            combined[..32].copy_from_slice(&dh1);
            combined[32..].copy_from_slice(&dh2);
            (combined.to_vec(), Some(otp_pub))
        }
        None => (dh1.to_vec(), None),
    };

    let (shared_secret, session_keys) = derive_keys(&ikm)?;

    Ok((
        shared_secret,
        session_keys,
        InitiatorMessage {
            identity_key: our_identity.public_key(),
            ephemeral_key: spk_eph_pub,
            one_time_ephemeral_key: otp_eph_pub,
        },
    ))
}

/// Responds to a session initiation, consuming the owned bundle's private pre-keys.
///
/// # Errors
///
/// Returns [`Error::KeyAgreement`] if DH fails.
/// Returns [`Error::KeyDerivation`] if HKDF fails.
pub(crate) fn respond_session(
    bundle: OwnedBundle,
    msg: &InitiatorMessage,
) -> Result<(SharedSecret, SessionKeys)> {
    // DH1: SPK_B_priv × EK_A_pub  -  mirrors initiate's EK_A × SPK_B.
    let dh1 = agree(bundle.signed_prekey_private, &msg.ephemeral_key)?;

    let ikm = match (bundle.one_time_prekey_private, msg.one_time_ephemeral_key) {
        (Some(otpk_priv), Some(ek2_pub)) => {
            // DH2: OPK_B_priv × EK_A2_pub  -  mirrors initiate's EK_A2 × OPK_B.
            let dh2 = agree(otpk_priv, &ek2_pub)?;
            let mut combined = [0u8; 64];
            combined[..32].copy_from_slice(&dh1);
            combined[32..].copy_from_slice(&dh2);
            combined.to_vec()
        }
        _ => dh1.to_vec(),
    };

    derive_keys(&ikm)
}

/// Generates a fresh X25519 key pair, returning `(private_key, public_key_bytes)`.
fn generate_x25519(rng: &SystemRandom) -> Result<(EphemeralPrivateKey, [u8; X25519_KEY_LEN])> {
    let priv_key =
        EphemeralPrivateKey::generate(&X25519, rng).map_err(|_| KeyGenerationSnafu.build())?;
    let pub_ring = priv_key
        .compute_public_key()
        .map_err(|_| KeyGenerationSnafu.build())?;
    let mut pub_bytes = [0u8; X25519_KEY_LEN];
    pub_bytes.copy_from_slice(pub_ring.as_ref());
    Ok((priv_key, pub_bytes))
}

fn agree(priv_key: EphemeralPrivateKey, peer_pub_bytes: &[u8]) -> Result<[u8; 32]> {
    let peer = UnparsedPublicKey::new(&X25519, peer_pub_bytes);
    ring::agreement::agree_ephemeral(priv_key, &peer, |key_material| {
        let mut out = [0u8; 32];
        out.copy_from_slice(key_material);
        out
    })
    .map_err(|_| KeyAgreementSnafu.build())
}

fn derive_keys(ikm: &[u8]) -> Result<(SharedSecret, SessionKeys)> {
    let salt = ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA256, &HKDF_SALT);
    let prk = salt.extract(ikm);

    let raw = hkdf_expand_32(&prk, b"X3DH shared secret")?;
    let i2r = hkdf_expand_32(&prk, b"initiator-to-responder")?;
    let r2i = hkdf_expand_32(&prk, b"responder-to-initiator")?;

    Ok((
        SharedSecret { raw },
        SessionKeys {
            initiator_to_responder: i2r,
            responder_to_initiator: r2i,
        },
    ))
}

pub(crate) fn hkdf_expand_32(prk: &ring::hkdf::Prk, info: &[u8]) -> Result<[u8; 32]> {
    struct Len32;
    impl ring::hkdf::KeyType for Len32 {
        fn len(&self) -> usize {
            32
        }
    }
    let info_slice = [info];
    let okm = prk
        .expand(&info_slice, Len32)
        .map_err(|_| KeyDerivationSnafu.build())?;
    let mut out = [0u8; 32];
    okm.fill(&mut out).map_err(|_| KeyDerivationSnafu.build())?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::IdentityKeyPair;

    #[test]
    fn create_bundle_succeeds() -> Result<()> {
        let identity = IdentityKeyPair::generate()?;
        create_bundle(&identity)?;
        Ok(())
    }

    #[test]
    fn bundle_prekey_signature_verifies() -> Result<()> {
        let identity = IdentityKeyPair::generate()?;
        let bundle = create_bundle(&identity)?;
        let pub_bundle = &bundle.public_bundle;
        assert!(
            IdentityKeyPair::verify(
                &pub_bundle.identity_key,
                &pub_bundle.signed_prekey,
                &pub_bundle.prekey_signature
            )
            .is_ok(),
            "signed pre-key must verify against the bundle's identity key"
        );
        Ok(())
    }

    #[test]
    fn initiator_and_responder_derive_same_shared_secret() -> Result<()> {
        let alice = IdentityKeyPair::generate()?;
        let bob = IdentityKeyPair::generate()?;
        let bob_bundle = create_bundle(&bob)?;
        let pub_bundle = bob_bundle.public_bundle.clone();

        let (alice_secret, _, init_msg) = initiate_session(&alice, &pub_bundle)?;
        let (bob_secret, _) = respond_session(bob_bundle, &init_msg)?;

        assert_eq!(
            alice_secret.raw, bob_secret.raw,
            "initiator and responder must derive the same shared secret"
        );
        Ok(())
    }

    #[test]
    fn initiate_session_produces_well_formed_keys() -> Result<()> {
        let alice = IdentityKeyPair::generate()?;
        let bob = IdentityKeyPair::generate()?;
        let bob_bundle = create_bundle(&bob)?;
        let (_, keys, _) = initiate_session(&alice, &bob_bundle.public_bundle)?;
        assert_eq!(
            keys.initiator_to_responder.len(),
            32,
            "i→r key must be 32 bytes"
        );
        assert_eq!(
            keys.responder_to_initiator.len(),
            32,
            "r→i key must be 32 bytes"
        );
        Ok(())
    }

    #[test]
    fn session_keys_differ_per_direction() -> Result<()> {
        let alice = IdentityKeyPair::generate()?;
        let bob = IdentityKeyPair::generate()?;
        let bob_bundle = create_bundle(&bob)?;
        let (_, keys, _) = initiate_session(&alice, &bob_bundle.public_bundle)?;
        assert_ne!(
            keys.initiator_to_responder, keys.responder_to_initiator,
            "send and receive keys must differ"
        );
        Ok(())
    }
}
