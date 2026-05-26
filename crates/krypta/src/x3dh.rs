//! X3DH-style key agreement: pre-key bundles, X25519 ECDH, HKDF session key derivation.

use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

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
    signed_prekey_private: StaticSecret,
    one_time_prekey_private: Option<StaticSecret>,
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
    let (spk_priv, spk_pub) = generate_x25519()?;
    let prekey_signature = identity.sign(&spk_pub)?;
    let (otpk_priv, otpk_pub) = generate_x25519()?;

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
    // Primary ephemeral key for DH with signed pre-key.
    let (spk_eph_priv, spk_eph_pub) = generate_x25519()?;
    let dh1 = agree(&spk_eph_priv, &their_bundle.signed_prekey)?;

    // Optional second ephemeral key for DH with one-time pre-key.
    // Each DH uses separate initiator key material so every advertised public
    // key maps to one X25519 operation.
    // The second ephemeral public key is included in InitiatorMessage so the
    // responder can compute the matching DH output.
    let (ikm, otp_eph_pub) = match their_bundle.one_time_prekey {
        Some(bundle_otp_pub) => {
            let (otp_eph_priv, otp_pub) = generate_x25519()?;
            let dh2 = agree(&otp_eph_priv, &bundle_otp_pub)?;
            let mut combined = Vec::with_capacity(64);
            combined.extend_from_slice(&dh1);
            combined.extend_from_slice(&dh2);
            (combined, Some(otp_pub))
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
    let dh1 = agree(&bundle.signed_prekey_private, &msg.ephemeral_key)?;

    let ikm = match (bundle.one_time_prekey_private, msg.one_time_ephemeral_key) {
        (Some(otpk_priv), Some(ek2_pub)) => {
            // DH2: OPK_B_priv × EK_A2_pub  -  mirrors initiate's EK_A2 × OPK_B.
            let dh2 = agree(&otpk_priv, &ek2_pub)?;
            let mut combined = Vec::with_capacity(64);
            combined.extend_from_slice(&dh1);
            combined.extend_from_slice(&dh2);
            combined
        }
        _ => dh1.to_vec(),
    };

    derive_keys(&ikm)
}

/// Generates a fresh X25519 key pair, returning `(private_key, public_key_bytes)`.
fn generate_x25519() -> Result<(StaticSecret, [u8; X25519_KEY_LEN])> {
    let mut private_bytes = [0u8; X25519_KEY_LEN];
    getrandom::fill(&mut private_bytes).map_err(|_| KeyGenerationSnafu.build())?;
    let priv_key = StaticSecret::from(private_bytes);
    let pub_bytes = PublicKey::from(&priv_key).to_bytes();
    Ok((priv_key, pub_bytes))
}

fn agree(priv_key: &StaticSecret, peer_pub_bytes: &[u8; X25519_KEY_LEN]) -> Result<[u8; 32]> {
    let peer = PublicKey::from(*peer_pub_bytes);
    let out = priv_key.diffie_hellman(&peer).to_bytes();
    if out == [0u8; X25519_KEY_LEN] {
        return Err(KeyAgreementSnafu.build());
    }
    Ok(out)
}

fn derive_keys(ikm: &[u8]) -> Result<(SharedSecret, SessionKeys)> {
    let prk = Hkdf::<Sha256>::new(Some(&HKDF_SALT), ikm);

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

pub(crate) fn hkdf_expand_32(prk: &Hkdf<Sha256>, info: &[u8]) -> Result<[u8; 32]> {
    let mut out = [0u8; 32];
    prk.expand(info, &mut out)
        .map_err(|_| KeyDerivationSnafu.build())?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::IdentityKeyPair;

    #[test]
    fn create_bundle_succeeds() -> Result<()> {
        let identity = IdentityKeyPair::generate()?;
        let bundle = create_bundle(&identity)?;

        assert_ne!(
            bundle.public_bundle.signed_prekey, [0u8; X25519_KEY_LEN],
            "signed pre-key must not be all zeroes"
        );
        assert!(
            bundle.public_bundle.one_time_prekey.is_some(),
            "bundle must include an advertised one-time pre-key"
        );
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

    #[test]
    fn x25519_rfc7748_known_answer() -> Result<()> {
        let alice_private = [
            0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2,
            0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5,
            0x1d, 0xb9, 0x2c, 0x2a,
        ];
        let alice_public = [
            0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e,
            0xf7, 0x5a, 0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4, 0xeb, 0xa4, 0xa9, 0x8e,
            0xaa, 0x9b, 0x4e, 0x6a,
        ];
        let bob_public = [
            0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4, 0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4,
            0x35, 0x37, 0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d, 0xad, 0xfc, 0x7e, 0x14,
            0x6f, 0x88, 0x2b, 0x4f,
        ];
        let shared = [
            0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1, 0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35,
            0x0f, 0x25, 0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33, 0x76, 0xf0, 0x9b, 0x3c,
            0x1e, 0x16, 0x17, 0x42,
        ];
        let alice_secret = StaticSecret::from(alice_private);

        assert_eq!(
            PublicKey::from(&alice_secret).to_bytes(),
            alice_public,
            "RFC 7748 Alice public key must match"
        );
        assert_eq!(
            agree(&alice_secret, &bob_public)?,
            shared,
            "RFC 7748 X25519 shared secret must match"
        );
        Ok(())
    }

    #[test]
    fn x25519_rejects_all_zero_shared_secret() {
        let private_key = StaticSecret::from([0x11; X25519_KEY_LEN]);
        assert!(
            agree(&private_key, &[0u8; X25519_KEY_LEN]).is_err(),
            "all-zero X25519 shared secret must be rejected"
        );
    }

    #[test]
    fn hkdf_rfc5869_sha256_test_case_1_first_32_bytes() -> Result<()> {
        let salt = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let info = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
        let expected = [
            0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
            0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
            0xec, 0xc4, 0xc5, 0xbf,
        ];
        let ikm = [0x0b; 22];
        let prk = Hkdf::<Sha256>::new(Some(&salt), &ikm);

        assert_eq!(
            hkdf_expand_32(&prk, &info)?,
            expected,
            "RFC 5869 HKDF-SHA256 test case 1 prefix must match"
        );
        Ok(())
    }
}
