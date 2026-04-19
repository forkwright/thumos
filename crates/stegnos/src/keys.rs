//! Key management: PBKDF2 key derivation, AES-256-GCM primary key seal/unseal.

use std::num::NonZeroU32;

use jiff::Timestamp;
use ring::{
    aead::{self, AES_256_GCM, LessSafeKey, Nonce, UnboundKey},
    pbkdf2,
    rand::{SecureRandom, SystemRandom},
};
use snafu::Snafu;

use crate::config::Config;

const SALT_LEN: usize = 32;
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const SEALED_KEY_LEN: usize = KEY_LEN + TAG_LEN;

/// Errors from key management operations.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum Error {
    /// The iteration count passed to key derivation was zero.
    #[snafu(display("iterations must be non-zero"))]
    ZeroIterations {
        /// Source location.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// The system random number generator failed.
    #[snafu(display("random number generation failed"))]
    RandomGeneration {
        /// Source location.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// AES-256-GCM key construction failed (invalid key length).
    #[snafu(display("invalid key material for AES-256-GCM"))]
    InvalidKey {
        /// Source location.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// Encryption of the primary key failed.
    #[snafu(display("key sealing failed"))]
    KeySeal {
        /// Source location.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// Decryption failed — wrong passphrase or corrupted data.
    #[snafu(display("key unsealing failed: wrong passphrase or corrupted slot data"))]
    KeyUnseal {
        /// Source location.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// Decrypted plaintext has an unexpected length.
    #[snafu(display("decrypted key has unexpected length"))]
    BadPlaintextLength {
        /// Source location.
        #[snafu(implicit)]
        location: snafu::Location,
    },
}

/// Convenience alias.
pub type Result<T> = std::result::Result<T, Error>;

/// A key derived from a passphrase via PBKDF2-HMAC-SHA256.
#[derive(Debug)]
pub struct DerivedKey {
    /// The 32-byte derived key bytes.
    pub key: [u8; KEY_LEN],
    /// The salt used during derivation.
    pub salt: [u8; SALT_LEN],
    /// The PBKDF2 iteration count.
    pub iterations: u32,
}

/// Encryption algorithm used to seal a primary key in a [`KeySlot`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Algorithm {
    /// AES-256-GCM authenticated encryption.
    Aes256Gcm,
}

/// An encrypted primary key plus metadata needed to unseal it.
#[derive(Debug, Clone)]
pub struct KeySlot {
    /// PBKDF2 salt (randomly generated at seal time).
    pub salt: [u8; SALT_LEN],
    /// PBKDF2 iteration count used when sealing.
    pub iterations: u32,
    /// AES-GCM nonce (randomly generated at seal time).
    pub nonce: [u8; NONCE_LEN],
    /// Encryption algorithm used to protect the primary key.
    pub algorithm: Algorithm,
    /// When this slot was created.
    pub created: Timestamp,
    /// Encrypted primary key (ciphertext || GCM tag), 48 bytes total.
    pub ciphertext: [u8; SEALED_KEY_LEN],
}

/// Derive a 32-byte key from `passphrase` and `salt` using PBKDF2-HMAC-SHA256.
///
/// # Errors
///
/// Returns [`Error::ZeroIterations`] if `iterations` is zero.
pub fn derive_key(passphrase: &[u8], salt: &[u8; SALT_LEN], iterations: u32) -> Result<DerivedKey> {
    let iters = NonZeroU32::new(iterations).ok_or_else(|| ZeroIterationsSnafu.build())?;
    let mut key = [0u8; KEY_LEN];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        iters,
        salt,
        passphrase,
        &mut key,
    );
    Ok(DerivedKey {
        key,
        salt: *salt,
        iterations,
    })
}

/// Generate `N` cryptographically random bytes.
fn random_bytes<const N: usize>(rng: &SystemRandom) -> Result<[u8; N]> {
    let mut buf = [0u8; N];
    rng.fill(&mut buf)
        .map_err(|_| RandomGenerationSnafu.build())?;
    Ok(buf)
}

/// Seal `primary_key` with a key derived from `passphrase` using AES-256-GCM,
/// using the default [`Config`].
///
/// Generates a random salt and nonce. The resulting [`KeySlot`] contains everything
/// needed to unseal the key later.
///
/// # Errors
///
/// Returns an error if random generation fails, key construction fails, or encryption fails.
pub fn seal_key(primary_key: &[u8; KEY_LEN], passphrase: &[u8]) -> Result<KeySlot> {
    seal_key_with_config(primary_key, passphrase, &Config::default())
}

/// Seal `primary_key` with a key derived from `passphrase` using AES-256-GCM,
/// honouring the supplied [`Config`].
///
/// # Errors
///
/// Returns an error if random generation fails, key construction fails, or encryption fails.
pub fn seal_key_with_config(
    primary_key: &[u8; KEY_LEN],
    passphrase: &[u8],
    config: &Config,
) -> Result<KeySlot> {
    let rng = SystemRandom::new();

    let salt = random_bytes::<SALT_LEN>(&rng)?;
    let nonce_bytes = random_bytes::<NONCE_LEN>(&rng)?;

    let iterations = config.pbkdf2_iterations();
    let derived = derive_key(passphrase, &salt, iterations)?;

    let unbound =
        UnboundKey::new(&AES_256_GCM, &derived.key).map_err(|_| InvalidKeySnafu.build())?;
    let sealing_key = LessSafeKey::new(unbound);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let mut buf = primary_key.to_vec();
    sealing_key
        .seal_in_place_append_tag(nonce, aead::Aad::empty(), &mut buf)
        .map_err(|_| KeySealSnafu.build())?;

    let mut ciphertext = [0u8; SEALED_KEY_LEN];
    ciphertext.copy_from_slice(&buf);

    Ok(KeySlot {
        salt,
        iterations,
        nonce: nonce_bytes,
        algorithm: Algorithm::Aes256Gcm,
        created: Timestamp::now(),
        ciphertext,
    })
}

/// Unseal a primary key from `slot` using `passphrase`.
///
/// Re-derives the wrapping key from the passphrase and stored salt, then
/// decrypts and authenticates the primary key via AES-256-GCM.
///
/// # Errors
///
/// Returns [`Error::KeyUnseal`] if the passphrase is wrong or the slot is corrupted.
/// Returns [`Error::ZeroIterations`] if the stored iteration count is zero.
/// Returns [`Error::InvalidKey`] if key construction fails.
pub fn unseal_key(slot: &KeySlot, passphrase: &[u8]) -> Result<[u8; KEY_LEN]> {
    let derived = derive_key(passphrase, &slot.salt, slot.iterations)?;

    let unbound =
        UnboundKey::new(&AES_256_GCM, &derived.key).map_err(|_| InvalidKeySnafu.build())?;
    let opening_key = LessSafeKey::new(unbound);
    let nonce = Nonce::assume_unique_for_key(slot.nonce);

    let mut buf = slot.ciphertext.to_vec();
    let plaintext = opening_key
        .open_in_place(nonce, aead::Aad::empty(), &mut buf)
        .map_err(|_| KeyUnsealSnafu.build())?;

    let slice = plaintext
        .get(..KEY_LEN)
        .ok_or_else(|| BadPlaintextLengthSnafu.build())?;
    let mut primary_key = [0u8; KEY_LEN];
    primary_key.copy_from_slice(slice);
    Ok(primary_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_passphrase_and_salt_yields_same_key() -> Result<()> {
        // SAFETY: test fixture — deterministic values for PBKDF2 reproducibility check
        let passphrase = b"correct horse battery staple";
        let salt = [0x42u8; SALT_LEN];
        let a = derive_key(passphrase, &salt, 1)?;
        let b = derive_key(passphrase, &salt, 1)?;
        assert_eq!(
            a.key, b.key,
            "PBKDF2 must be deterministic for same passphrase and salt"
        );
        Ok(())
    }

    #[test]
    fn different_salt_yields_different_key() -> Result<()> {
        // SAFETY: test fixture — distinct fixed salts to verify PBKDF2 salt sensitivity
        let passphrase = b"correct horse battery staple";
        let salt_a = [0x11u8; SALT_LEN];
        let salt_b = [0x22u8; SALT_LEN];
        let a = derive_key(passphrase, &salt_a, 1)?;
        let b = derive_key(passphrase, &salt_b, 1)?;
        assert_ne!(
            a.key, b.key,
            "different salts must produce different derived keys"
        );
        Ok(())
    }

    #[test]
    fn zero_iterations_returns_error() {
        // SAFETY: test fixture — value irrelevant, testing iteration-count validation
        let salt = [0u8; SALT_LEN];
        let result = derive_key(b"pass", &salt, 0);
        assert!(result.is_err(), "zero iterations must be rejected");
    }

    #[test]
    fn seal_unseal_round_trip() -> Result<()> {
        let primary_key = [0xABu8; KEY_LEN];
        let passphrase = b"test passphrase";
        let slot = seal_key(&primary_key, passphrase)?;
        let recovered = unseal_key(&slot, passphrase)?;
        assert_eq!(
            primary_key, recovered,
            "unseal must return the original primary key"
        );
        Ok(())
    }

    #[test]
    fn wrong_passphrase_fails_unseal() -> Result<()> {
        let primary_key = [0xCDu8; KEY_LEN];
        let slot = seal_key(&primary_key, b"correct passphrase")?;
        let result = unseal_key(&slot, b"wrong passphrase");
        assert!(
            result.is_err(),
            "unseal with wrong passphrase must return an error"
        );
        Ok(())
    }

    #[test]
    fn non_default_iterations_round_trip() -> Result<()> {
        // WHY: prove Config actually flows through to the stored slot metadata
        // and is used on the unseal path. A Config change must observably
        // alter the iteration count recorded in the KeySlot.
        let primary_key = [0xEFu8; KEY_LEN];
        let config = Config {
            pbkdf2_iterations: 50_000,
        };
        let slot = seal_key_with_config(&primary_key, b"pass", &config)?;
        assert_eq!(
            slot.iterations, 50_000,
            "non-default config must change the recorded iteration count"
        );
        let recovered = unseal_key(&slot, b"pass")?;
        assert_eq!(primary_key, recovered, "unseal must reverse seal");
        Ok(())
    }

    #[test]
    fn default_seal_key_uses_config_default() -> Result<()> {
        let primary_key = [0x11u8; KEY_LEN];
        let slot = seal_key(&primary_key, b"pass")?;
        assert_eq!(
            slot.iterations,
            crate::config::DEFAULT_PBKDF2_ITERATIONS,
            "seal_key must use Config::default().pbkdf2_iterations",
        );
        Ok(())
    }
}
