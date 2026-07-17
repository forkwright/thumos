//! X3DH-style key agreement: pre-key bundles, X25519 ECDH, HKDF session key derivation.

use hkdf::Hkdf;
use sha2::Sha256;
use snafu::ResultExt as _;
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
    /// WHY(#207): the responder's long-term X25519 identity secret, needed to
    /// mirror the initiator's identity DH legs at `respond_session` time.
    identity_x25519_private: StaticSecret,
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
            reason = "crate-internal API — raw is unused in lib but accessed in tests and held for future consumers"
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
        identity_x25519_private: identity.x25519_secret(),
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
/// Returns [`Error::InvalidSignature`] if the responder's signed pre-key is not
/// signed by its advertised identity key.
/// Returns [`Error::InvalidKey`] if the responder's identity key is not a valid
/// Ed25519 point.
/// Returns [`Error::KeyGeneration`] if ephemeral key generation fails.
/// Returns [`Error::KeyAgreement`] if any DH step fails.
/// Returns [`Error::KeyDerivation`] if HKDF expansion fails.
pub(crate) fn initiate_session(
    our_identity: &IdentityKeyPair,
    their_bundle: &PreKeyBundle,
) -> Result<(SharedSecret, SessionKeys, InitiatorMessage)> {
    // WHY(#213): the signed pre-key is only trustworthy if it is signed by the
    // advertised identity key. Reject before any DH so a substituted pre-key
    // (active MITM on bundle delivery) never enters key agreement.
    IdentityKeyPair::verify(
        &their_bundle.identity_key,
        &their_bundle.signed_prekey,
        &their_bundle.prekey_signature,
    )?;

    // WHY(#207): fold the long-term identity legs so the derived secret binds
    // to both identities. IK_A is our identity's X25519 secret; IK_B is the
    // peer identity mapped to Montgomery form.
    let our_identity_x25519 = our_identity.x25519_secret();
    let their_identity_x25519 = their_bundle.identity_key.to_x25519()?;

    // Primary ephemeral key (EK_A) for DH with the signed pre-key and IK_B.
    let (spk_eph_priv, spk_eph_pub) = generate_x25519()?;

    // INVARIANT: IKM leg order must match respond_session byte-for-byte:
    //   DH(IK_A, SPK_B) || DH(EK_A, IK_B) || DH(EK_A, SPK_B) [|| DH(EK_A2, OPK_B)]
    let leg_identity_prekey = agree(&our_identity_x25519, &their_bundle.signed_prekey)?;
    let leg_ephemeral_identity = agree(&spk_eph_priv, &their_identity_x25519)?;
    let leg_ephemeral_prekey = agree(&spk_eph_priv, &their_bundle.signed_prekey)?;

    let mut ikm = Vec::with_capacity(128);
    ikm.extend_from_slice(&leg_identity_prekey);
    ikm.extend_from_slice(&leg_ephemeral_identity);
    ikm.extend_from_slice(&leg_ephemeral_prekey);

    // Optional one-time pre-key leg. A second ephemeral (EK_A2) is used so
    // every advertised public key maps to one X25519 operation; its public is
    // carried in InitiatorMessage so the responder can mirror the DH output.
    let otp_eph_pub = match their_bundle.one_time_prekey {
        Some(bundle_otp_pub) => {
            let (otp_eph_priv, otp_pub) = generate_x25519()?;
            let leg_one_time = agree(&otp_eph_priv, &bundle_otp_pub)?;
            ikm.extend_from_slice(&leg_one_time);
            Some(otp_pub)
        }
        None => None,
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
/// Returns [`Error::InvalidKey`] if the initiator's identity key is not a valid
/// Ed25519 point.
/// Returns [`Error::KeyAgreement`] if DH fails, or if exactly one side offers a
/// one-time pre-key.
/// Returns [`Error::KeyDerivation`] if HKDF fails.
pub(crate) fn respond_session(
    bundle: OwnedBundle,
    msg: &InitiatorMessage,
) -> Result<(SharedSecret, SessionKeys)> {
    // WHY(#207): IK_A is the initiator's identity mapped to Montgomery form;
    // IK_B is our own long-term X25519 identity secret. Each leg mirrors an
    // initiate_session leg by DH symmetry, in the SAME byte order.
    let their_identity_x25519 = msg.identity_key.to_x25519()?;

    // DH(IK_A, SPK_B) : SPK_B_priv × IK_A_pub  ≡  IK_A_priv × SPK_B_pub
    let leg_identity_prekey = agree(&bundle.signed_prekey_private, &their_identity_x25519)?;
    // DH(EK_A, IK_B)  : IK_B_priv × EK_A_pub    ≡  EK_A_priv × IK_B_pub
    let leg_ephemeral_identity = agree(&bundle.identity_x25519_private, &msg.ephemeral_key)?;
    // DH(EK_A, SPK_B) : SPK_B_priv × EK_A_pub   ≡  EK_A_priv × SPK_B_pub
    let leg_ephemeral_prekey = agree(&bundle.signed_prekey_private, &msg.ephemeral_key)?;

    let mut ikm = Vec::with_capacity(128);
    ikm.extend_from_slice(&leg_identity_prekey);
    ikm.extend_from_slice(&leg_ephemeral_identity);
    ikm.extend_from_slice(&leg_ephemeral_prekey);

    // Optional one-time pre-key leg: DH(EK_A2, OPK_B). WHY: presence must
    // match on both sides — a bundle/message OTP mismatch (e.g. a MITM
    // stripping the ephemeral in transit) must fail loudly rather than
    // silently falling back to the 3-leg secret, which would only surface
    // downstream as an undiagnosable decrypt failure.
    match (bundle.one_time_prekey_private, msg.one_time_ephemeral_key) {
        (Some(otpk_priv), Some(ek2_pub)) => {
            let leg_one_time = agree(&otpk_priv, &ek2_pub)?;
            ikm.extend_from_slice(&leg_one_time);
        }
        (None, None) => {}
        (Some(_), None) | (None, Some(_)) => return Err(KeyAgreementSnafu.build()),
    }

    derive_keys(&ikm)
}

/// Generates a fresh X25519 key pair, returning `(private_key, public_key_bytes)`.
fn generate_x25519() -> Result<(StaticSecret, [u8; X25519_KEY_LEN])> {
    let mut private_bytes = [0u8; X25519_KEY_LEN];
    getrandom::fill(&mut private_bytes).context(KeyGenerationSnafu)?;
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
    fn shared_secret_is_bound_to_initiator_identity() -> Result<()> {
        // #207 Done-when: a session built with a DIFFERENT IK_A must NOT derive
        // the same shared secret. Models an active MITM who replays the honest
        // initiator's ephemerals but substitutes a different identity key.
        let alice = IdentityKeyPair::generate()?;
        let mallory = IdentityKeyPair::generate()?;
        let bob = IdentityKeyPair::generate()?;
        let bob_bundle = create_bundle(&bob)?;
        let pub_bundle = bob_bundle.public_bundle.clone();

        let (alice_secret, _, mut init_msg) = initiate_session(&alice, &pub_bundle)?;
        // Substitute a different initiator identity, keeping every ephemeral.
        init_msg.identity_key = mallory.public_key();

        let (bob_secret, _) = respond_session(bob_bundle, &init_msg)?;
        assert_ne!(
            alice_secret.raw, bob_secret.raw,
            "substituting the initiator identity must break shared-secret agreement (#207)"
        );
        Ok(())
    }

    #[test]
    fn shared_secret_is_bound_to_responder_identity() -> Result<()> {
        // The identity binding must also cover the responder: two bundles that
        // differ ONLY in the identity key produce different secrets under a
        // fixed initiator.
        let alice = IdentityKeyPair::generate()?;
        let bob = IdentityKeyPair::generate()?;
        let bob_bundle = create_bundle(&bob)?;

        let (alice_secret, _, _) = initiate_session(&alice, &bob_bundle.public_bundle)?;

        // Re-sign the SAME signed pre-key under a different identity so the
        // signature check passes but IK_B differs.
        let mallory = IdentityKeyPair::generate()?;
        let mut forged = bob_bundle.public_bundle;
        forged.identity_key = mallory.public_key();
        forged.prekey_signature = mallory.sign(&forged.signed_prekey)?;

        let (alice_secret_2, _, _) = initiate_session(&alice, &forged)?;
        assert_ne!(
            alice_secret.raw, alice_secret_2.raw,
            "a different responder identity must change the derived secret (#207)"
        );
        Ok(())
    }

    #[test]
    fn initiate_rejects_tampered_prekey_signature() -> Result<()> {
        // #213: a corrupted signed-pre-key signature must be rejected.
        let alice = IdentityKeyPair::generate()?;
        let bob = IdentityKeyPair::generate()?;
        let mut pub_bundle = create_bundle(&bob)?.public_bundle;
        if let Some(byte) = pub_bundle.prekey_signature.first_mut() {
            *byte ^= 0xFF;
        }
        let err = initiate_session(&alice, &pub_bundle);
        assert!(
            matches!(err, Err(crate::error::Error::InvalidSignature { .. })),
            "a tampered prekey signature must yield Err(InvalidSignature) (#213)"
        );
        Ok(())
    }

    #[test]
    fn initiate_rejects_prekey_not_signed_by_identity() -> Result<()> {
        // #213 attack model: MITM substitutes their own signed pre-key while
        // keeping the victim's identity key. The signature no longer verifies.
        let alice = IdentityKeyPair::generate()?;
        let bob = IdentityKeyPair::generate()?;
        let mallory = IdentityKeyPair::generate()?;
        let mallory_bundle = create_bundle(&mallory)?.public_bundle;
        let mut victim = create_bundle(&bob)?.public_bundle;
        // Swap in Mallory's signed pre-key + signature under Bob's identity.
        victim.signed_prekey = mallory_bundle.signed_prekey;
        victim.prekey_signature = mallory_bundle.prekey_signature;
        assert!(
            initiate_session(&alice, &victim).is_err(),
            "a signed pre-key not signed by the bundle identity must be rejected (#213)"
        );
        Ok(())
    }

    #[test]
    fn initiator_and_responder_agree_without_one_time_prekey() -> Result<()> {
        // Three-leg path (no OPK): both sides must still derive the same secret.
        let alice = IdentityKeyPair::generate()?;
        let bob = IdentityKeyPair::generate()?;
        let mut bob_bundle = create_bundle(&bob)?;
        bob_bundle.public_bundle.one_time_prekey = None;
        bob_bundle.one_time_prekey_private = None;
        let pub_bundle = bob_bundle.public_bundle.clone();

        let (alice_secret, _, init_msg) = initiate_session(&alice, &pub_bundle)?;
        let (bob_secret, _) = respond_session(bob_bundle, &init_msg)?;
        assert_eq!(
            alice_secret.raw, bob_secret.raw,
            "3-leg X3DH (no one-time pre-key) must still agree"
        );
        Ok(())
    }

    #[test]
    fn respond_rejects_missing_one_time_prekey_in_message() -> Result<()> {
        // Attack model: a MITM strips the optional OTP ephemeral from the
        // initiator message in transit while the responder's bundle still
        // holds the matching private key. The mismatch must be a hard error,
        // not a silent fallback to the 3-leg secret.
        let alice = IdentityKeyPair::generate()?;
        let bob = IdentityKeyPair::generate()?;
        let bob_bundle = create_bundle(&bob)?;
        let pub_bundle = bob_bundle.public_bundle.clone();

        let (_, _, mut init_msg) = initiate_session(&alice, &pub_bundle)?;
        init_msg.one_time_ephemeral_key = None;

        let err = respond_session(bob_bundle, &init_msg);
        assert!(
            matches!(err, Err(crate::error::Error::KeyAgreement { .. })),
            "a one-time pre-key present in the bundle but stripped from the message must be rejected"
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
