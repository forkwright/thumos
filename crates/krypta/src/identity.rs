//! Ed25519 identity key pairs for signing and authentication.

use ring::rand::SystemRandom;
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};

use crate::error::{InvalidKeySnafu, InvalidSignatureSnafu, KeyGenerationSnafu, Result};

const PUBLIC_KEY_LEN: usize = 32;

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
}

impl std::fmt::Debug for PublicIdentityKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PublicIdentityKey({:02x}{:02x}..)", self.0[0], self.0[1])
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
    /// PKCS#8-encoded Ed25519 private key.
    pkcs8_bytes: Vec<u8>,
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
        let rng = SystemRandom::new();
        let pkcs8_doc =
            Ed25519KeyPair::generate_pkcs8(&rng).map_err(|_| KeyGenerationSnafu.build())?;
        let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_doc.as_ref())
            .map_err(|_| KeyGenerationSnafu.build())?;
        let pub_bytes = key_pair.public_key().as_ref();
        let mut public_key_bytes = [0u8; PUBLIC_KEY_LEN];
        public_key_bytes.copy_from_slice(pub_bytes);
        Ok(Self {
            pkcs8_bytes: pkcs8_doc.as_ref().to_vec(),
            public_key_bytes,
        })
    }

    /// Returns the public key half of this identity key pair.
    pub(crate) const fn public_key(&self) -> PublicIdentityKey {
        PublicIdentityKey(self.public_key_bytes)
    }

    /// Signs `data` using this identity key.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKey`] if the stored key bytes are malformed.
    pub(crate) fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        let key_pair =
            Ed25519KeyPair::from_pkcs8(&self.pkcs8_bytes).map_err(|_| InvalidKeySnafu.build())?;
        Ok(key_pair.sign(data).as_ref().to_vec())
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
        let pub_key = UnparsedPublicKey::new(&ED25519, public_key.as_bytes().as_ref());
        pub_key
            .verify(data, signature)
            .map_err(|_| InvalidSignatureSnafu.build())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_key_pair_without_error() -> Result<()> {
        IdentityKeyPair::generate()?;
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
}
