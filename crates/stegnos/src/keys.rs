//! Key management: PBKDF2 key derivation, AES-256-GCM primary key seal/unseal.

use aes_gcm::{
    Aes256Gcm,
    aead::{AeadInOut, KeyInit},
};
use jiff::Timestamp;
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use snafu::Snafu;
use zeroize::{Zeroize, Zeroizing};

use crate::config::{Config, MAX_PBKDF2_ITERATIONS, MIN_PBKDF2_ITERATIONS};

const SALT_LEN: usize = 32;
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const SEALED_KEY_LEN: usize = KEY_LEN + TAG_LEN;

/// Errors from key management operations.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub(crate) enum Error {
    /// The iteration count passed to key derivation was zero.
    #[snafu(display("iterations must be non-zero"))]
    ZeroIterations {
        /// Source location.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// The persisted iteration count on an unseal attempt was below the
    /// configured minimum -- indicates a tampered on-device header (#357).
    #[snafu(display(
        "stored iteration count {iterations} is below the minimum {min} \
         (possible tampering)"
    ))]
    WeakIterations {
        /// The rejected, tampered-low iteration count read from the slot.
        iterations: u32,
        /// The enforced minimum ([`crate::config::MIN_PBKDF2_ITERATIONS`]).
        min: u32,
        /// Source location.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// The persisted iteration count on an unseal attempt was above the
    /// configured maximum -- the same tampered-header class as
    /// [`Error::WeakIterations`], from the other side of the range (#829).
    #[snafu(display(
        "stored iteration count {iterations} is above the maximum {max} \
         (possible tampering)"
    ))]
    ExcessiveIterations {
        /// The rejected, tampered-high iteration count read from the slot.
        iterations: u32,
        /// The enforced maximum ([`crate::config::MAX_PBKDF2_ITERATIONS`]).
        max: u32,
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
pub(crate) type Result<T> = std::result::Result<T, Error>;

/// A key derived from a passphrase via PBKDF2-HMAC-SHA256.
pub(crate) struct DerivedKey {
    /// The 32-byte derived key bytes — the AES-GCM wrapping key that
    /// protects the primary key at rest. Zeroized on drop (#356).
    pub(crate) key: Zeroizing<[u8; KEY_LEN]>,
    /// The salt used during derivation.
    pub(crate) salt: [u8; SALT_LEN],
    /// The PBKDF2 iteration count.
    pub(crate) iterations: u32,
}

impl std::fmt::Debug for DerivedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // WHY: a derived #[derive(Debug)] would print the raw 32-byte
        // wrapping key AND salt verbatim (#356) — redact both.
        f.debug_struct("DerivedKey")
            .field("key", &"[REDACTED]")
            .field("salt", &"[REDACTED]")
            .field("iterations", &self.iterations)
            .finish()
    }
}

/// Encryption algorithm used to seal a primary key in a [`KeySlot`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub(crate) enum Algorithm {
    /// AES-256-GCM authenticated encryption.
    Aes256Gcm,
}

/// An encrypted primary key plus metadata needed to unseal it.
#[derive(Debug, Clone)]
pub(crate) struct KeySlot {
    /// PBKDF2 salt (randomly generated at seal time).
    pub(crate) salt: [u8; SALT_LEN],
    /// PBKDF2 iteration count used when sealing.
    pub(crate) iterations: u32,
    /// AES-GCM nonce (randomly generated at seal time).
    pub(crate) nonce: [u8; NONCE_LEN],
    /// Encryption algorithm used to protect the primary key.
    pub(crate) algorithm: Algorithm,
    /// When this slot was created.
    pub(crate) created: Timestamp,
    /// Encrypted primary key (ciphertext || GCM tag), 48 bytes total.
    pub(crate) ciphertext: [u8; SEALED_KEY_LEN],
}

/// Derive a 32-byte key from `passphrase` and `salt` using PBKDF2-HMAC-SHA256.
///
/// # Errors
///
/// Returns [`Error::ZeroIterations`] if `iterations` is zero.
pub(crate) fn derive_key(
    passphrase: &[u8],
    salt: &[u8; SALT_LEN],
    iterations: u32,
) -> Result<DerivedKey> {
    if iterations == 0 {
        return ZeroIterationsSnafu.fail();
    }

    let mut key = [0u8; KEY_LEN];
    pbkdf2_hmac::<Sha256>(passphrase, salt, iterations, &mut key);
    Ok(DerivedKey {
        key: Zeroizing::new(key),
        salt: *salt,
        iterations,
    })
}

/// Generate `N` cryptographically random bytes.
fn random_bytes<const N: usize>() -> Result<[u8; N]> {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf).map_err(|_| RandomGenerationSnafu.build())?;
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
pub(crate) fn seal_key(primary_key: &[u8; KEY_LEN], passphrase: &[u8]) -> Result<KeySlot> {
    seal_key_with_config(primary_key, passphrase, Config::default())
}

/// Seal `primary_key` with a key derived from `passphrase` using AES-256-GCM,
/// honouring the supplied [`Config`].
///
/// # Errors
///
/// Returns an error if random generation fails, key construction fails, or encryption fails.
pub(crate) fn seal_key_with_config(
    primary_key: &[u8; KEY_LEN],
    passphrase: &[u8],
    config: Config,
) -> Result<KeySlot> {
    let salt = random_bytes::<SALT_LEN>()?;
    let nonce_bytes = random_bytes::<NONCE_LEN>()?;

    let iterations = config.pbkdf2_iterations();
    let derived = derive_key(passphrase, &salt, iterations)?;

    let sealing_key =
        Aes256Gcm::new_from_slice(derived.key.as_slice()).map_err(|_| InvalidKeySnafu.build())?;
    let mut buf = primary_key.to_vec();
    // WHY: hybrid-array deprecates Array::from_slice; the exact-length
    // `From<&[u8; N]>` impl is compile-time checked, so this conversion
    // cannot truncate and adds no error path to the seal routine.
    let encrypt_result = sealing_key.encrypt_in_place((&nonce_bytes).into(), b"", &mut buf);

    if encrypt_result.is_err() {
        // WHY: buf may still hold plaintext or partially-transformed data
        // on an error path; zeroize before propagating (#356).
        buf.zeroize();
        return Err(KeySealSnafu.build());
    }

    let mut ciphertext = [0u8; SEALED_KEY_LEN];
    ciphertext.copy_from_slice(&buf);
    // WHY: buf held the plaintext primary key before encrypt_in_place; zero
    // it now that the ciphertext has been extracted, rather than relying
    // on normal (non-zeroizing) Drop (#356).
    buf.zeroize();

    Ok(KeySlot {
        salt,
        iterations,
        nonce: nonce_bytes,
        algorithm: Algorithm::Aes256Gcm,
        created: Timestamp::now(),
        ciphertext,
    })
}

/// Reject a persisted iteration count outside the range the seal path clamps
/// into, before it reaches key derivation (#357, #829).
fn check_iteration_bounds(iterations: u32) -> Result<()> {
    if iterations < MIN_PBKDF2_ITERATIONS {
        return WeakIterationsSnafu {
            iterations,
            min: MIN_PBKDF2_ITERATIONS,
        }
        .fail();
    }
    // WHY the upper bound is checked on the READ path and not only on the seal
    // path: an attacker who can rewrite the header to a value below the
    // minimum can equally write one above the maximum, and `iterations` is a
    // `u32`. At `u32::MAX` each attempt runs ~430x the count
    // MAX_PBKDF2_ITERATIONS already pegs at over 30 s on the MT6739's A53, so
    // the unlock path blocks for hours before it can even fail -- a denial of
    // service that presents as a bricked device rather than as a rejected
    // header (#829).
    if iterations > MAX_PBKDF2_ITERATIONS {
        return ExcessiveIterationsSnafu {
            iterations,
            max: MAX_PBKDF2_ITERATIONS,
        }
        .fail();
    }
    Ok(())
}

/// Unseal a primary key from `slot` using `passphrase`.
///
/// Re-derives the wrapping key from the passphrase and stored salt, then
/// decrypts and authenticates the primary key via AES-256-GCM.
///
/// # Errors
///
/// Returns [`Error::KeyUnseal`] if the passphrase is wrong or the slot is corrupted.
/// Returns [`Error::WeakIterations`] or [`Error::ExcessiveIterations`] if the
/// stored iteration count falls outside
/// `MIN_PBKDF2_ITERATIONS..=MAX_PBKDF2_ITERATIONS` -- the seal path always
/// clamps into that range, so any stored value outside it indicates a tampered
/// header (#357, #829).
/// Returns [`Error::ZeroIterations`] if the stored iteration count is zero
/// (subsumed by the `WeakIterations` check above; kept for `derive_key`
/// callers that bypass `unseal_key`).
/// Returns [`Error::InvalidKey`] if key construction fails.
pub(crate) fn unseal_key(slot: &KeySlot, passphrase: &[u8]) -> Result<[u8; KEY_LEN]> {
    check_iteration_bounds(slot.iterations)?;

    let derived = derive_key(passphrase, &slot.salt, slot.iterations)?;

    let opening_key =
        Aes256Gcm::new_from_slice(derived.key.as_slice()).map_err(|_| InvalidKeySnafu.build())?;
    let mut buf = slot.ciphertext.to_vec();
    let decrypt_result = opening_key.decrypt_in_place((&slot.nonce).into(), b"", &mut buf);

    // WHY: buf holds the decrypted plaintext primary key from this point
    // regardless of outcome below; zero it before returning on every path
    // instead of relying on normal (non-zeroizing) Drop (#356).
    let outcome = decrypt_result
        .map_err(|_| KeyUnsealSnafu.build())
        .and_then(|()| {
            let mut primary_key = [0u8; KEY_LEN];
            let slice = buf
                .get(..KEY_LEN)
                .ok_or_else(|| BadPlaintextLengthSnafu.build())?;
            primary_key.copy_from_slice(slice);
            Ok(primary_key)
        });
    buf.zeroize();

    outcome
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
            *a.key, *b.key,
            "PBKDF2 must be deterministic for same passphrase and salt"
        );
        Ok(())
    }

    #[test]
    fn derive_key_matches_pbkdf2_sha256_known_answer() -> Result<()> {
        // PBKDF2-HMAC-SHA256 vector from common RFC 6070-style test suites.
        let mut salt = [0u8; SALT_LEN];
        salt[..4].copy_from_slice(b"salt");

        let derived = derive_key(b"password", &salt, 1)?;

        assert_eq!(
            *derived.key,
            [
                0x1f, 0x0b, 0x0d, 0x29, 0x78, 0x96, 0x2e, 0xb0, 0xa4, 0x14, 0x6d, 0xdc, 0x02, 0xe2,
                0x2c, 0x04, 0x5e, 0x42, 0xe4, 0x99, 0xf4, 0x0f, 0xf2, 0x84, 0x15, 0x3f, 0xa8, 0x45,
                0x68, 0xbf, 0xbf, 0xff,
            ],
            "PBKDF2-HMAC-SHA256 output must match known answer"
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
            *a.key, *b.key,
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
    fn unseal_rejects_tampered_low_iteration_slot() -> Result<()> {
        // #357: an attacker who rewrites the persisted KeySlot header can
        // set iterations=1, collapsing the PBKDF2 work factor. unseal_key
        // must reject any stored count below MIN_PBKDF2_ITERATIONS before
        // ever deriving a key, regardless of whether the passphrase is
        // otherwise correct.
        let primary_key = [0x77u8; KEY_LEN];
        let passphrase = b"correct passphrase";
        let mut slot = seal_key(&primary_key, passphrase)?;
        slot.iterations = 1;

        let result = unseal_key(&slot, passphrase);
        assert!(
            matches!(result, Err(Error::WeakIterations { iterations: 1, .. })),
            "tampered slot with iterations=1 must be rejected as WeakIterations"
        );
        Ok(())
    }

    #[test]
    fn unseal_rejects_tampered_high_iteration_slot() -> Result<()> {
        // #829: the other half of the same tampered-header class. A rewritten
        // u32::MAX makes the unlock path grind for hours before failing, so it
        // must be refused before any derivation, exactly as the low side is.
        let primary_key = [0x77u8; KEY_LEN];
        let passphrase = b"correct passphrase";
        let mut slot = seal_key(&primary_key, passphrase)?;
        slot.iterations = u32::MAX;

        let result = unseal_key(&slot, passphrase);
        assert!(
            matches!(
                result,
                Err(Error::ExcessiveIterations {
                    iterations: u32::MAX,
                    ..
                })
            ),
            "tampered slot with iterations=u32::MAX must be rejected as ExcessiveIterations"
        );
        Ok(())
    }

    #[test]
    fn iteration_bounds_are_inclusive_on_both_ends() {
        // The read path must accept exactly what the seal path's
        // `(MIN..=MAX).contains(&v)` can write. A predicate that excluded its
        // own endpoints would reject a legitimately sealed header and report
        // it as tampering.
        //
        // WHY this tests the predicate rather than driving `unseal_key`: an
        // end-to-end check at MAX_PBKDF2_ITERATIONS would run ten million
        // PBKDF2 rounds -- the very cost that bound exists to cap -- so the
        // test would be slower than the attack it guards against.
        assert!(check_iteration_bounds(MIN_PBKDF2_ITERATIONS).is_ok());
        assert!(check_iteration_bounds(MAX_PBKDF2_ITERATIONS).is_ok());
        assert!(matches!(
            check_iteration_bounds(MIN_PBKDF2_ITERATIONS - 1),
            Err(Error::WeakIterations { .. })
        ));
        assert!(matches!(
            check_iteration_bounds(MAX_PBKDF2_ITERATIONS + 1),
            Err(Error::ExcessiveIterations { .. })
        ));
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
        let slot = seal_key_with_config(&primary_key, b"pass", config)?;
        assert_eq!(
            slot.iterations, 50_000,
            "non-default config must change the recorded iteration count"
        );
        let recovered = unseal_key(&slot, b"pass")?;
        assert_eq!(primary_key, recovered, "unseal must reverse seal");
        Ok(())
    }

    #[test]
    fn derived_key_zeroizes_on_manual_zeroize() -> Result<()> {
        let salt = [0u8; SALT_LEN];
        let mut derived = derive_key(b"pass", &salt, 1)?;
        assert!(
            derived.key.iter().any(|&b| b != 0),
            "key must be non-zero before zeroize"
        );
        derived.key.zeroize();
        assert!(
            derived.key.iter().all(|&b| b == 0),
            "key must be zero after explicit zeroize"
        );
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
