//! Ed25519 identity key pairs for signing and authentication.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use snafu::ResultExt as _;
use x25519_dalek::StaticSecret;

use crate::error::{InvalidKeySnafu, InvalidSignatureSnafu, KeyGenerationSnafu, Result};

const PUBLIC_KEY_LEN: usize = 32;
const PRIVATE_KEY_LEN: usize = 32;

/// Ed25519 public identity key (32 bytes).
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct PublicIdentityKey([u8; PUBLIC_KEY_LEN]);

impl PublicIdentityKey {
    /// Returns the raw 32-byte public key.
    pub(crate) const fn as_bytes(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.0
    }

    /// Constructs a `PublicIdentityKey` from raw bytes.
    pub(crate) const fn from_bytes(bytes: [u8; PUBLIC_KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Maps this Ed25519 identity key to its X25519 (Montgomery) public form.
    ///
    /// WHY(#207): lets the long-term identity enter X3DH DH legs with no new
    /// wire field. INVARIANT: pairs with [`IdentityKeyPair::x25519_secret`] —
    /// the returned bytes are the X25519 public whose secret is the peer's
    /// `to_scalar_bytes()` (guaranteed by `ed25519_dalek`'s birational map).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKey`] if the stored bytes are not a valid
    /// Ed25519 point.
    pub(crate) fn to_x25519(&self) -> Result<[u8; PUBLIC_KEY_LEN]> {
        let verifying_key =
            VerifyingKey::from_bytes(&self.0).map_err(|_| InvalidKeySnafu.build())?;
        Ok(verifying_key.to_montgomery().to_bytes())
    }
}

impl std::fmt::Debug for PublicIdentityKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PublicIdentityKey(")?;
        for byte in self.0.iter().take(2) {
            write!(f, "{byte:02x}")?;
        }
        write!(f, "..)")
    }
}

impl std::fmt::Display for PublicIdentityKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

/// Ed25519 identity key pair. Holds private key material; never logged.
pub(crate) struct IdentityKeyPair {
    /// Raw Ed25519 signing seed.
    private_key_bytes: [u8; PRIVATE_KEY_LEN],
    /// Cached public key bytes (32 bytes).
    public_key_bytes: [u8; PUBLIC_KEY_LEN],
}

impl std::fmt::Debug for IdentityKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityKeyPair")
            .field("public_key", &self.public_key())
            .finish_non_exhaustive()
    }
}

impl IdentityKeyPair {
    /// Generates a new random Ed25519 identity key pair.
    ///
    /// # Errors
    ///
    /// Returns [`Error::KeyGeneration`] if key generation or parsing fails.
    pub(crate) fn generate() -> Result<Self> {
        let mut private_key_bytes = [0u8; PRIVATE_KEY_LEN];
        getrandom::fill(&mut private_key_bytes).context(KeyGenerationSnafu)?;
        let key_pair = SigningKey::from_bytes(&private_key_bytes);
        let public_key_bytes = key_pair.verifying_key().to_bytes();
        Ok(Self {
            private_key_bytes,
            public_key_bytes,
        })
    }

    /// Returns the public key half of this identity key pair.
    pub(crate) const fn public_key(&self) -> PublicIdentityKey {
        PublicIdentityKey(self.public_key_bytes)
    }

    /// Derives the long-term X25519 secret from the Ed25519 seed via the
    /// birational Edwards→Montgomery map (`to_scalar_bytes` →
    /// `StaticSecret::from`). `StaticSecret` clamps at DH time, so the raw
    /// unclamped scalar bytes are the correct input.
    ///
    /// WHY(#207): binds X3DH to the long-term identity without adding an
    /// independent X25519 key or wire field. INVARIANT: the corresponding
    /// public equals `self.public_key().to_x25519()`.
    pub(crate) fn x25519_secret(&self) -> StaticSecret {
        let signing_key = SigningKey::from_bytes(&self.private_key_bytes);
        StaticSecret::from(signing_key.to_scalar_bytes())
    }

    /// Signs `data` using this identity key.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKey`] if the stored key bytes are malformed.
    ///
    /// Time: O(m) where m is `data.len()` — `SigningKey::from_bytes` parses
    /// a fixed 32-byte key (O(1)); the dominant cost is `ed25519_dalek`'s
    /// Ed25519 signing, which hashes the full message with SHA-512
    /// internally.
    /// Space: O(1) — the returned signature is a fixed 64 bytes regardless
    /// of `data.len()`, only converted to a heap `Vec`.
    pub(crate) fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        let key_pair = SigningKey::from_bytes(&self.private_key_bytes);
        Ok(key_pair.sign(data).to_bytes().to_vec())
    }

    /// Verifies an Ed25519 `signature` over `data` against `public_key`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidSignature`] if verification fails.
    pub(crate) fn verify(
        public_key: &PublicIdentityKey,
        data: &[u8],
        signature: &[u8],
    ) -> Result<()> {
        let pub_key =
            VerifyingKey::from_bytes(public_key.as_bytes()).map_err(|_| InvalidKeySnafu.build())?;
        let sig = Signature::from_slice(signature).map_err(|_| InvalidSignatureSnafu.build())?;
        pub_key
            .verify_strict(data, &sig)
            .map_err(|_| InvalidSignatureSnafu.build())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_key_pair_without_error() -> Result<()> {
        let key = IdentityKeyPair::generate()?;

        assert_ne!(
            key.public_key().as_bytes(),
            &[0u8; PUBLIC_KEY_LEN],
            "generated public key must not be all zeroes"
        );
        Ok(())
    }

    #[test]
    fn two_generated_keys_are_distinct() -> Result<()> {
        let a = IdentityKeyPair::generate()?;
        let b = IdentityKeyPair::generate()?;
        assert_ne!(
            a.public_key().as_bytes(),
            b.public_key().as_bytes(),
            "independently generated keys must differ"
        );
        Ok(())
    }

    #[test]
    fn sign_and_verify_round_trip() -> Result<()> {
        let key = IdentityKeyPair::generate()?;
        let message = b"thumos identity signing test";
        let sig = key.sign(message)?;
        assert!(
            IdentityKeyPair::verify(&key.public_key(), message, &sig).is_ok(),
            "valid signature must verify"
        );
        Ok(())
    }

    #[test]
    fn verify_fails_with_wrong_public_key() -> Result<()> {
        let alice = IdentityKeyPair::generate()?;
        let bob = IdentityKeyPair::generate()?;
        let message = b"signed by alice";
        let sig = alice.sign(message)?;
        assert!(
            IdentityKeyPair::verify(&bob.public_key(), message, &sig).is_err(),
            "alice's signature must not verify under bob's key"
        );
        Ok(())
    }

    #[test]
    fn verify_fails_with_tampered_message() -> Result<()> {
        let key = IdentityKeyPair::generate()?;
        let message = b"original message";
        let sig = key.sign(message)?;
        assert!(
            IdentityKeyPair::verify(&key.public_key(), b"tampered message", &sig).is_err(),
            "signature over original must not verify against tampered message"
        );
        Ok(())
    }

    #[test]
    fn public_key_is_32_bytes() -> Result<()> {
        let key = IdentityKeyPair::generate()?;
        assert_eq!(
            key.public_key().as_bytes().len(),
            32,
            "Ed25519 public key must be 32 bytes"
        );
        Ok(())
    }

    #[test]
    fn x25519_derivation_public_matches_montgomery_map() -> Result<()> {
        use x25519_dalek::PublicKey;

        let key = IdentityKeyPair::generate()?;
        let derived_public = PublicKey::from(&key.x25519_secret()).to_bytes();
        let mapped_public = key.public_key().to_x25519()?;
        assert_eq!(
            derived_public, mapped_public,
            "X25519 public derived from the secret must equal the Ed25519→Montgomery map of the identity"
        );
        Ok(())
    }

    #[test]
    fn ed25519_rfc8032_test_vector_1_signs_and_verifies() -> Result<()> {
        let private_key_bytes = [
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec,
            0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03,
            0x1c, 0xae, 0x7f, 0x60,
        ];
        let public_key_bytes = [
            0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64,
            0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68,
            0xf7, 0x07, 0x51, 0x1a,
        ];
        let expected_signature = [
            0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e,
            0x82, 0x8a, 0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74, 0xd8, 0x73, 0xe0, 0x65,
            0x22, 0x49, 0x01, 0x55, 0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac, 0xc6, 0x1e,
            0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b, 0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24,
            0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b,
        ];
        let key = IdentityKeyPair {
            private_key_bytes,
            public_key_bytes,
        };
        let signature = key.sign(b"")?;

        assert_eq!(
            signature, expected_signature,
            "RFC 8032 Ed25519 test vector 1 signature must match"
        );
        IdentityKeyPair::verify(&key.public_key(), b"", &signature)
    }
}
