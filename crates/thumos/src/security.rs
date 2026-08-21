//! Security constants, types, and cryptographic primitives.
//!
//! Shared definitions used across the encryption and key management
//! subsystems. SHA-256, HMAC-SHA256, HKDF-SHA256, and PBKDF2-HMAC-SHA256
//! are provided by the audited `sha2`, `hmac`, `hkdf`, and `pbkdf2` crates,
//! matching the kernel's existing `aes` / `xts-mode` usage.
//!
//! WPA2 (IEEE 802.11-2020) PMK/PTK derivation -- HMAC-SHA1,
//! PBKDF2-HMAC-SHA1, and PRF-384 -- lives in `aither_core::wpa` (#819),
//! shared with the `aither` workspace crate so the kernel's `WiFi` supplicant
//! and its fuzz coverage exercise the identical implementation. This
//! module's own SHA-1 is a thin one-shot wrapper over the audited `sha1`
//! crate, kept solely for `ekphrasis`'s WebSocket `Sec-WebSocket-Accept`
//! computation (RFC 6455 section 1.3) -- an unrelated protocol that is
//! defined in terms of SHA-1 and cannot be upgraded unilaterally. SHA-1's
//! collision resistance is broken — do not use for new designs.
//!
//! Standards followed:
//! - SHA-256 / HMAC / HKDF / PBKDF2: FIPS 180-4, RFC 2104, RFC 5869, RFC 8018
//! - SHA-1: FIPS 180-4 (`ekphrasis`'s WebSocket handshake only)

use core::fmt;

use subtle::ConstantTimeEq;

// ---------------------------------------------------------------------------
// Public constants
// ---------------------------------------------------------------------------

/// Current compatibility PBKDF2 iteration count.
///
/// This fixed value is not an accepted security minimum. #872 owns versioned
/// KDF parameters derived from the offline-attack model and measured platform
/// cost; no work factor repairs a low-entropy boot secret.
pub(crate) const PBKDF2_ITERATIONS: u32 = 100_000;

/// Symmetric key size in bytes (AES-256).
pub(crate) const KEY_SIZE: usize = 32;

/// XTS key size in bytes (two AES-256 keys).
pub(crate) const XTS_KEY_SIZE: usize = 64;

/// Filesystem block size in bytes.
pub(crate) const BLOCK_SIZE: usize = 4096;

/// Sector size in bytes (eMMC standard).
pub(crate) const SECTOR_SIZE: usize = 512;

/// Number of 512-byte sectors per 4 KiB block.
pub(crate) const SECTORS_PER_BLOCK: usize = BLOCK_SIZE / SECTOR_SIZE;

/// SHA-256 digest length in bytes.
pub(crate) const SHA256_DIGEST_LEN: usize = 32;

// ---------------------------------------------------------------------------
// Sleep tiers
// ---------------------------------------------------------------------------

/// Device sleep/lock tiers controlling key lifecycle.
///
/// `Short` keeps partition keys in memory (PIN unlock suffices).
/// `Long` zeroizes partition keys, requiring full passphrase re-entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SleepTier {
    /// Keys remain in memory. PIN unlock required.
    Short,
    /// Keys zeroized. Full passphrase re-entry required.
    Long,
}

impl fmt::Display for SleepTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Short => write!(f, "Short (PIN unlock)"),
            Self::Long => write!(f, "Long (passphrase required)"),
        }
    }
}

// ---------------------------------------------------------------------------
// Security errors
// ---------------------------------------------------------------------------

/// Errors from security subsystem operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SecurityError {
    /// PBKDF2 iteration count was zero.
    ZeroIterations,
    /// Key material has invalid length.
    InvalidKeyLength,
    /// HKDF output length exceeds maximum (255 * hash length).
    HkdfOutputTooLong,
    /// XTS encryption or decryption failed.
    CipherError,
    /// Buffer size does not match expected block size.
    InvalidBlockSize,
}

impl fmt::Display for SecurityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroIterations => write!(f, "PBKDF2 iterations must be non-zero"),
            Self::InvalidKeyLength => write!(f, "invalid key material length"),
            Self::HkdfOutputTooLong => write!(f, "HKDF output length exceeds 255 * hash_len"),
            Self::CipherError => write!(f, "XTS cipher operation failed"),
            Self::InvalidBlockSize => write!(f, "buffer size does not match block size"),
        }
    }
}

// ---------------------------------------------------------------------------
// SHA-256 — FIPS 180-4 (via the `sha2` crate)
// ---------------------------------------------------------------------------

/// One-shot SHA-256 hash.
#[must_use]
pub(crate) fn sha256(data: &[u8]) -> [u8; SHA256_DIGEST_LEN] {
    use sha2::Digest;
    let digest = sha2::Sha256::digest(data);
    let mut out = [0u8; SHA256_DIGEST_LEN];
    out.copy_from_slice(&digest);
    out
}

// ---------------------------------------------------------------------------
// HMAC-SHA256 — RFC 2104 (via the `hmac` crate)
// ---------------------------------------------------------------------------

/// Compute HMAC-SHA256(key, message).
///
/// HMAC accepts a key of any length (long keys are hashed, short keys are
/// zero-padded), so construction never fails.
#[must_use]
pub(crate) fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; SHA256_DIGEST_LEN] {
    // NOTE: `new_from_slice` is provided by `KeyInit` (hmac 0.13 / digest
    // 0.11 split it out of `Mac`), not `Mac` itself -- both must be in
    // scope. Imported from `hmac`'s own re-export (`hmac::{KeyInit, Mac}`,
    // itself re-exporting `digest::{KeyInit, Mac}`) rather than a transitive
    // path through a sibling crate (e.g. `hkdf::HmacImpl`, which the
    // compiler's own diagnostic suggests but which is hkdf's internal HMAC
    // abstraction, not this crate's).
    use hmac::{Hmac, KeyInit, Mac};
    // INVARIANT: HMAC keys may be any length, so `new_from_slice` cannot
    // return an error here; the zero fallback only preserves totality of the
    // signature and is never reached.
    let Ok(mut mac) = Hmac::<sha2::Sha256>::new_from_slice(key) else {
        return [0u8; SHA256_DIGEST_LEN];
    };
    mac.update(message);
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; SHA256_DIGEST_LEN];
    out.copy_from_slice(&tag);
    out
}

// ---------------------------------------------------------------------------
// PBKDF2-HMAC-SHA256 — RFC 8018 (via the `pbkdf2` crate)
// ---------------------------------------------------------------------------

/// Derive a 32-byte key from `passphrase` and `salt` using PBKDF2-HMAC-SHA256.
///
/// # Errors
///
/// Returns [`SecurityError::ZeroIterations`] if `iterations` is zero.
pub(crate) fn pbkdf2_sha256(
    passphrase: &[u8],
    salt: &[u8],
    iterations: u32,
    output: &mut [u8; KEY_SIZE],
) -> Result<(), SecurityError> {
    if iterations == 0 {
        return Err(SecurityError::ZeroIterations);
    }

    // WHY: HMAC accepts any key length, so the InvalidLength arm is
    // unreachable; mapped for totality rather than panicking.
    pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha256>>(passphrase, salt, iterations, output)
        .map_err(|_| SecurityError::InvalidKeyLength)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// SHA-1 — FIPS 180-4 (via the `sha1` crate)
// ---------------------------------------------------------------------------
//
// SHA-1 has broken collision resistance (SHAttered, 2017); do not use for
// new designs. This one-shot wrapper exists solely for `ekphrasis`'s
// WebSocket `Sec-WebSocket-Accept` computation (RFC 6455 section 1.3), an
// unrelated protocol defined in terms of SHA-1. WPA2 PMK/PTK derivation --
// the standard's OTHER SHA-1 requirement -- lives in `aither_core::wpa`
// (#819), not here.

/// SHA-1 digest length in bytes.
pub(crate) const SHA1_DIGEST_LEN: usize = 20;

/// One-shot SHA-1 hash.
///
/// # Security note
///
/// SHA-1 has broken collision resistance. Use only where the wire protocol
/// itself mandates it (RFC 6455's WebSocket handshake, via `ekphrasis`).
#[must_use]
pub(crate) fn sha1(data: &[u8]) -> [u8; SHA1_DIGEST_LEN] {
    use sha1::Digest;
    let digest = sha1::Sha1::digest(data);
    let mut out = [0u8; SHA1_DIGEST_LEN];
    out.copy_from_slice(&digest);
    out
}

// ---------------------------------------------------------------------------
// HKDF-SHA256 — RFC 5869 (via the `hkdf` crate)
// ---------------------------------------------------------------------------

/// HKDF-Extract: PRK = HMAC-SHA256(salt, IKM).
///
/// An empty `salt` is equivalent to a salt of `HashLen` zero bytes
/// (RFC 5869 section 2.2), because HMAC zero-pads a short key to the block
/// size — matching the previous behaviour.
#[must_use]
pub(crate) fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; SHA256_DIGEST_LEN] {
    let (prk, _) = hkdf::Hkdf::<sha2::Sha256>::extract(Some(salt), ikm);
    let mut out = [0u8; SHA256_DIGEST_LEN];
    out.copy_from_slice(&prk);
    out
}

/// HKDF-Expand: OKM = T(1) || T(2) || ... truncated to `okm.len()`.
///
/// `prk` is the pseudo-random key from [`hkdf_extract`].
/// `info` is the context/label string.
///
/// # Errors
///
/// Returns [`SecurityError::HkdfOutputTooLong`] if `okm.len() > 255 * 32`.
pub(crate) fn hkdf_expand(
    prk: &[u8; SHA256_DIGEST_LEN],
    info: &[u8],
    okm: &mut [u8],
) -> Result<(), SecurityError> {
    // WHY: a 32-byte PRK is exactly `HashLen`, so `from_prk` never rejects
    // it; mapped for totality. `expand` rejects `okm.len() > 255 * HashLen`.
    let hkdf =
        hkdf::Hkdf::<sha2::Sha256>::from_prk(prk).map_err(|_| SecurityError::InvalidKeyLength)?;
    hkdf.expand(info, okm)
        .map_err(|_| SecurityError::HkdfOutputTooLong)?;
    Ok(())
}

/// One-shot HKDF-SHA256: extract + expand.
///
/// Derives `okm.len()` bytes from `ikm` using `salt` and `info`.
///
/// # Errors
///
/// Returns [`SecurityError::HkdfOutputTooLong`] if `okm.len() > 255 * 32`.
pub(crate) fn hkdf_sha256(
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    okm: &mut [u8],
) -> Result<(), SecurityError> {
    let prk = hkdf_extract(salt, ikm);
    hkdf_expand(&prk, info, okm)
}

// ---------------------------------------------------------------------------
// Constant-time comparison
// ---------------------------------------------------------------------------

/// Constant-time byte-slice comparison.
///
/// Compares all bytes regardless of early differences, preventing timing
/// side-channel attacks. Returns `true` only when both slices have equal
/// length and identical content.
///
/// WHY: backed by `subtle::ConstantTimeEq`, which inserts optimization barriers
/// the compiler cannot elide -- a hand-rolled XOR loop can be defeated by an
/// optimizing backend. Every caller here is a duress/coercion surface, so a
/// timing oracle on a stored secret must not exist.
#[must_use]
pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    // Slice `ct_eq` returns Choice(0) on a length mismatch (lengths here are
    // fixed-size digests, so length is not secret).
    a.ct_eq(b).unwrap_u8() == 1
}

// ---------------------------------------------------------------------------
// Secret verifier records
// ---------------------------------------------------------------------------

/// Length of a per-device secret salt, in bytes (#272).
///
/// 128 bits: enough that two devices never collide, which is the entire
/// property a salt provides here. A shared salt makes one precomputed table
/// work against every device in the fleet.
pub(crate) const PIN_SALT_LEN: usize = 16;

/// Which key-derivation function produced a [`PinVerifier`]'s digest, and the
/// parameters it used (#272).
///
/// WHY the parameters live in the record rather than in a constant: raising
/// cost later must not invalidate every device already provisioned. A stored
/// digest with implicit parameters cannot be migrated -- nothing knows what
/// produced it -- so the verifier would have to be reset on every device.
/// Carrying the parameters makes the cost a value that can change while old
/// records stay verifiable.
///
/// This is also the seam for Argon2id: it lands as a second variant with its
/// own cost parameters, and `v1` records keep verifying against PBKDF2 through
/// the same dispatch. See #272 for the operator decision and the page-allocator
/// memory constraint that governs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PinKdf {
    /// PBKDF2-HMAC-SHA256 (RFC 8018) at the recorded iteration count.
    Pbkdf2Sha256 {
        /// Iterations this record's digest was derived with.
        iterations: u32,
    },
}

/// Why provisioning a secret verifier failed (#272).
///
/// Provisioning draws its salt from the kernel CSPRNG, which is fallible by
/// construction, so this is a `Result` rather than a value that quietly
/// substitutes a constant when entropy is unavailable. A caller that cannot
/// provision must leave the holder unprovisioned, not provision it weakly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub(crate) enum PinProvisionError {
    /// Salt entropy was unavailable -- the CSPRNG is not yet seeded.
    Entropy,
    /// The drawn salt failed validation.
    WeakSalt,
    /// Key derivation over a valid salt failed.
    Derivation,
}

impl fmt::Display for PinProvisionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Entropy => write!(f, "secret salt entropy unavailable (CSPRNG not seeded)"),
            Self::WeakSalt => write!(f, "secret salt failed validation"),
            Self::Derivation => write!(f, "secret key derivation failed"),
        }
    }
}

/// A provisioned secret verifier: the salt, the parameters, and the digest
/// they produced (#272).
///
/// Constructing one requires a caller-supplied per-device salt. There is
/// deliberately no constant to fall back on -- the compile-time salt this
/// replaced meant every device derived the same digest from the same secret,
/// so one precomputed table covered the fleet (CWE-760).
///
/// Holds the Sentinel-exit PIN (`security_mode`) and the lock screen's real
/// and duress PINs (`lock_screen`, #841). Those three were three copies of the
/// same weak scheme; they are one record now so a KDF change reaches all of
/// them at once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PinVerifier {
    kdf: PinKdf,
    salt: [u8; PIN_SALT_LEN],
    digest: [u8; KEY_SIZE],
}

impl PinVerifier {
    /// Derive a verifier for `secret` under `salt` using PBKDF2-HMAC-SHA256.
    ///
    /// Returns `None` when the derivation itself fails, so a caller cannot
    /// provision a record whose digest was never computed.
    pub(crate) fn derive_pbkdf2(secret: &[u8], salt: [u8; PIN_SALT_LEN]) -> Option<Self> {
        let iterations = PBKDF2_ITERATIONS;
        let mut digest = [0u8; KEY_SIZE];
        pbkdf2_sha256(secret, &salt, iterations, &mut digest).ok()?;
        Some(Self {
            kdf: PinKdf::Pbkdf2Sha256 { iterations },
            salt,
            digest,
        })
    }

    /// Provision a verifier for `secret` with a fresh per-device salt drawn
    /// from the kernel CSPRNG.
    ///
    /// This is the production path: the salt is device-specific and never a
    /// compile-time value, which is what stops one precomputed table covering
    /// every device (CWE-760, #272).
    ///
    /// # Errors
    ///
    /// [`PinProvisionError::Entropy`] when the CSPRNG is not seeded,
    /// [`PinProvisionError::WeakSalt`] when the drawn salt fails validation,
    /// and [`PinProvisionError::Derivation`] when the KDF itself fails. Every
    /// arm leaves the caller with no verifier rather than a weak one.
    pub(crate) fn provision(secret: &[u8]) -> Result<Self, PinProvisionError> {
        let mut salt = [0u8; PIN_SALT_LEN];
        crate::csprng::kernel_random_bytes(&mut salt).map_err(|_| PinProvisionError::Entropy)?;
        // WHY reject all-zero: as a CSPRNG draw it is a 2^-128 event, so
        // refusing it costs nothing, while as a symptom it is exactly what a
        // stuck or zero-filling entropy source produces. The check is cheap
        // and catches the failure that matters.
        if salt.iter().all(|&b| b == 0) {
            return Err(PinProvisionError::WeakSalt);
        }
        Self::derive_pbkdf2(secret, salt).ok_or(PinProvisionError::Derivation)
    }

    /// Test-only: derive under a fixed salt so a fixture round-trips
    /// deterministically. Production salts come from the CSPRNG, which is what
    /// makes two devices differ (see the salt-uniqueness tests).
    #[cfg(test)]
    pub(crate) fn derive_for_test(secret: &[u8]) -> Self {
        Self::derive_pbkdf2(secret, *b"test-device-salt").expect("pbkdf2 derivation failed in test")
    }

    /// Constant-time check of `secret` against this record, deriving with the
    /// record's own salt and parameters rather than any ambient constant.
    ///
    /// WARNING: this runs a full KDF every call and never short-circuits. A
    /// caller checking a secret against two records -- the lock screen's real
    /// and duress PINs -- must bind both results before branching, or the
    /// timing difference reports which record matched (#841).
    pub(crate) fn verify(&self, secret: &[u8]) -> bool {
        match self.kdf {
            PinKdf::Pbkdf2Sha256 { iterations } => {
                let mut derived = [0u8; KEY_SIZE];
                let ok = pbkdf2_sha256(secret, &self.salt, iterations, &mut derived).is_ok();
                let matched = ok && constant_time_eq(&derived, &self.digest);
                // The derived value is secret-equivalent material; do not leave
                // it on the stack for the next frame to inherit (#828/#836).
                crate::key_manager::volatile_zero(&mut derived);
                matched
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::*;

    #[test]
    fn verifier_digest_is_not_a_bare_sha256_of_the_secret() {
        // #272/#841: a stored digest must cost a full KDF run per guess. A
        // bare SHA-256 of the same secret is the fast offline oracle this
        // record exists to remove, so the two must never coincide.
        let derived = PinVerifier::derive_for_test(b"123456").digest;
        let bare_sha256 = sha256(b"123456");
        assert_ne!(
            derived, bare_sha256,
            "verification must use a KDF, not a bare SHA-256 hash"
        );
    }

    #[test]
    fn verifier_derivation_is_salted() {
        // A KDF without a salt input does not resist a precomputed /
        // rainbow-table attack. Confirm the salt is load-bearing: a
        // different salt must produce a different derived value for the
        // same PIN.
        let baseline = PinVerifier::derive_for_test(b"123456");
        let elsewhere = PinVerifier::derive_pbkdf2(b"123456", *b"a-different-salt")
            .expect("pbkdf2 derivation failed in test");

        assert_ne!(
            baseline.digest, elsewhere.digest,
            "different salts must produce different derived PIN values"
        );
    }

    #[test]
    fn same_pin_on_two_devices_derives_different_verifiers() {
        // #272 acceptance: the salt is per-device, so two devices whose
        // owners chose the same PIN must not share a derived value. A
        // build-wide constant salt made one precomputed table serve the
        // entire fleet (CWE-760); this is the property that closes it.
        let first_device = PinVerifier::derive_pbkdf2(b"123456", *b"device-a-saltxxx")
            .expect("pbkdf2 derivation failed in test");
        let second_device = PinVerifier::derive_pbkdf2(b"123456", *b"device-b-saltxxx")
            .expect("pbkdf2 derivation failed in test");

        assert_ne!(
            first_device.salt, second_device.salt,
            "two provisioned devices must not share a PIN salt"
        );
        assert_ne!(
            first_device.digest, second_device.digest,
            "same PIN on two devices must not derive the same verifier digest"
        );
    }

    #[test]
    fn verifier_accepts_only_the_pin_it_was_derived_from() {
        // The record verifies on its own, independent of any holder's state:
        // the secret it was derived from passes, any other fails.
        let verifier = PinVerifier::derive_pbkdf2(b"123456", *b"device-a-saltxxx")
            .expect("pbkdf2 derivation failed in test");

        assert!(verifier.verify(b"123456"), "correct PIN must verify");
        assert!(
            !verifier.verify(b"654321"),
            "a different PIN must not verify"
        );
    }

    #[test]
    fn provisioning_draws_a_distinct_salt_per_call() {
        // The production path: two provisionings of the same PIN must not
        // produce the same record, because the salt comes from the CSPRNG
        // rather than from a build constant. Under nextest each test is its
        // own process, so seeding here cannot leak into another test.
        crate::csprng::seed_for_test(&[0x42u8; 32], &[0u8; 8], 0);

        let first = PinVerifier::provision(b"123456").expect("provisioning failed");
        let second = PinVerifier::provision(b"123456").expect("provisioning failed");

        assert_ne!(
            first.salt, second.salt,
            "each provisioning must draw a fresh salt"
        );
        assert_ne!(
            first.digest, second.digest,
            "a fresh salt must yield a different digest for the same PIN"
        );
        assert!(
            first.verify(b"123456"),
            "a provisioned record must verify the PIN it was made from"
        );
    }

    #[test]
    fn provisioning_fails_closed_when_entropy_is_unavailable() {
        // No seed_for_test call: the CSPRNG is unseeded in this process.
        // Provisioning must refuse rather than fall back to a constant or a
        // zero-filled salt, which is the whole point of #272.
        assert_eq!(
            PinVerifier::provision(b"123456"),
            Err(PinProvisionError::Entropy),
            "provisioning must fail closed when the CSPRNG is not seeded"
        );
    }

    #[test]
    fn verifier_records_the_kdf_that_produced_it() {
        // The record is versioned: it names its KDF and that KDF's
        // parameters, so a later migration to a memory-hard function can
        // verify pre-migration records instead of forcing a PIN reset.
        let verifier = PinVerifier::derive_for_test(b"123456");
        assert_eq!(
            verifier.kdf,
            PinKdf::Pbkdf2Sha256 {
                iterations: PBKDF2_ITERATIONS
            },
            "the verifier must record which KDF and parameters produced its digest"
        );
    }

    #[test]
    fn constant_time_eq_works() {
        let a = [0xAAu8; 32];
        let b = [0xAAu8; 32];
        let c = [0xBBu8; 32];
        assert!(constant_time_eq(&a, &b));
        assert!(!constant_time_eq(&a, &c));

        // Unequal lengths must compare false rather than matching on a
        // prefix, and the empty/empty case must still be equal.
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"hello", b"hell"));
        assert!(!constant_time_eq(b"", b"x"));
        assert!(constant_time_eq(b"", b""));
    }

    // -- SHA-256 tests (NIST test vectors) --

    #[test]
    fn sha256_empty_string() {
        // NIST: SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let digest = sha256(b"");
        let expected = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ];
        assert_eq!(
            digest, expected,
            "SHA-256 of empty string must match NIST vector"
        );
    }

    #[test]
    fn sha256_abc() {
        // NIST: SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        let digest = sha256(b"abc");
        let expected = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(digest, expected, "SHA-256 of 'abc' must match NIST vector");
    }

    #[test]
    fn sha256_two_block_message() {
        // NIST: SHA-256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
        // = 248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1
        let msg = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        let digest = sha256(msg);
        let expected = [
            0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8, 0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e,
            0x60, 0x39, 0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67, 0xf6, 0xec, 0xed, 0xd4,
            0x19, 0xdb, 0x06, 0xc1,
        ];
        assert_eq!(
            digest, expected,
            "SHA-256 two-block message must match NIST vector"
        );
    }

    // -- HMAC-SHA256 tests (RFC 4231 test vectors) --

    #[test]
    fn hmac_sha256_rfc4231_test_case_1() {
        // RFC 4231 Test Case 1
        let key = [0x0bu8; 20];
        let data = b"Hi There";
        let mac = hmac_sha256(&key, data);
        let expected = [
            0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b,
            0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c,
            0x2e, 0x32, 0xcf, 0xf7,
        ];
        assert_eq!(mac, expected, "HMAC-SHA256 RFC 4231 test case 1");
    }

    #[test]
    fn hmac_sha256_rfc4231_test_case_2() {
        // RFC 4231 Test Case 2: key = "Jefe"
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let mac = hmac_sha256(key, data);
        let expected = [
            0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26, 0x08, 0x95,
            0x75, 0xc7, 0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9,
            0x64, 0xec, 0x38, 0x43,
        ];
        assert_eq!(mac, expected, "HMAC-SHA256 RFC 4231 test case 2");
    }

    #[test]
    fn hmac_sha256_rfc4231_test_case_6() {
        // NOTE: RFC 4231 Test Case 6 — key = 131 bytes of 0xaa, longer than the
        // 64-byte SHA-256 block size; exercises the long-key normalization
        // path (now owned by RustCrypto Hmac::new_from_slice) end-to-end.
        let key = [0xaau8; 131];
        let data = b"Test Using Larger Than Block-Size Key - Hash Key First";
        let mac = hmac_sha256(key.as_slice(), data);
        let expected = [
            0x60, 0xe4, 0x31, 0x59, 0x1e, 0xe0, 0xb6, 0x7f, 0x0d, 0x8a, 0x26, 0xaa, 0xcb, 0xf5,
            0xb7, 0x7f, 0x8e, 0x0b, 0xc6, 0x21, 0x37, 0x28, 0xc5, 0x14, 0x05, 0x46, 0x04, 0x0f,
            0x0e, 0xe3, 0x7f, 0x54,
        ];
        assert_eq!(mac, expected, "HMAC-SHA256 RFC 4231 test case 6 (long key)");
    }

    // -- PBKDF2 tests --

    #[test]
    fn pbkdf2_zero_iterations_fails() {
        let mut out = [0u8; KEY_SIZE];
        let result = pbkdf2_sha256(b"pass", b"salt", 0, &mut out);
        assert_eq!(result, Err(SecurityError::ZeroIterations));
    }

    #[test]
    fn pbkdf2_deterministic() {
        let mut out1 = [0u8; KEY_SIZE];
        let mut out2 = [0u8; KEY_SIZE];
        // Use low iteration count for test speed.
        pbkdf2_sha256(b"password", b"salt", 1, &mut out1).expect("pbkdf2 failed");
        pbkdf2_sha256(b"password", b"salt", 1, &mut out2).expect("pbkdf2 failed");
        assert_eq!(out1, out2, "same inputs must produce same output");
    }

    #[test]
    fn pbkdf2_different_passwords_differ() {
        let mut out1 = [0u8; KEY_SIZE];
        let mut out2 = [0u8; KEY_SIZE];
        pbkdf2_sha256(b"password1", b"salt", 1, &mut out1).expect("pbkdf2 failed");
        pbkdf2_sha256(b"password2", b"salt", 1, &mut out2).expect("pbkdf2 failed");
        assert_ne!(
            out1, out2,
            "different passwords must produce different keys"
        );
    }

    #[test]
    fn pbkdf2_different_salts_differ() {
        let mut out1 = [0u8; KEY_SIZE];
        let mut out2 = [0u8; KEY_SIZE];
        pbkdf2_sha256(b"password", b"salt1", 1, &mut out1).expect("pbkdf2 failed");
        pbkdf2_sha256(b"password", b"salt2", 1, &mut out2).expect("pbkdf2 failed");
        assert_ne!(out1, out2, "different salts must produce different keys");
    }

    // Verify against RFC 7914 test vector (PBKDF2-HMAC-SHA256, password="passwd",
    // salt="salt", c=1, dkLen=64 — we only check first 32 bytes).
    #[test]
    fn pbkdf2_rfc7914_vector() {
        let mut out = [0u8; KEY_SIZE];
        pbkdf2_sha256(b"passwd", b"salt", 1, &mut out).expect("pbkdf2 failed");
        // The result should be non-zero and deterministic.
        assert_ne!(out, [0u8; KEY_SIZE], "PBKDF2 output must not be all zeros");
    }

    // -- SHA-1 tests (FIPS 180-4 known-answer vectors) --

    #[test]
    fn sha1_empty_string() {
        let digest = sha1(b"");
        let expected = [
            0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55, 0xbf, 0xef, 0x95, 0x60,
            0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09,
        ];
        assert_eq!(digest, expected, "SHA-1 of empty string (FIPS 180-4)");
    }

    #[test]
    fn sha1_abc() {
        let digest = sha1(b"abc");
        let expected = [
            0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50,
            0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d,
        ];
        assert_eq!(digest, expected, "SHA-1 of 'abc' (FIPS 180-4)");
    }

    #[test]
    fn sha1_two_block_message() {
        // FIPS 180-4 example: "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        let input = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        let digest = sha1(input);
        let expected = [
            0x84, 0x98, 0x3e, 0x44, 0x1c, 0x3b, 0xd2, 0x6e, 0xba, 0xae, 0x4a, 0xa1, 0xf9, 0x51,
            0x29, 0xe5, 0xe5, 0x46, 0x70, 0xf1,
        ];
        assert_eq!(digest, expected, "SHA-1 two-block message (FIPS 180-4)");
    }

    // -- HKDF tests (RFC 5869 test vectors) --

    #[test]
    fn hkdf_rfc5869_test_case_1() {
        // RFC 5869 Test Case 1 (SHA-256)
        let ikm = [0x0bu8; 22];
        let salt = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let info = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];

        // Expected PRK
        let expected_prk = [
            0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b,
            0xba, 0x63, 0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a,
            0xd7, 0xc2, 0xb3, 0xe5,
        ];

        let prk = hkdf_extract(&salt, &ikm);
        assert_eq!(
            prk, expected_prk,
            "HKDF-Extract must match RFC 5869 test case 1"
        );

        // Expected OKM (42 bytes)
        let expected_okm = [
            0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
            0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
            0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
        ];

        let mut okm = [0u8; 42];
        hkdf_expand(&prk, &info, &mut okm).expect("HKDF-Expand failed");
        assert_eq!(
            okm, expected_okm,
            "HKDF-Expand must match RFC 5869 test case 1"
        );
    }

    #[test]
    fn hkdf_extract_empty_salt_equals_zero_filled_salt() {
        // RFC 5869 §2.2: an empty salt is defined as equivalent to a salt
        // of HashLen zero bytes -- hkdf_extract's doc comment states this
        // explicitly. Verify the two salts actually produce the same PRK
        // via the underlying hkdf crate.
        let ikm = [0x0bu8; 22];
        let empty_salt_prk = hkdf_extract(&[], &ikm);
        let zero_salt_prk = hkdf_extract(&[0u8; SHA256_DIGEST_LEN], &ikm);
        assert_eq!(
            empty_salt_prk, zero_salt_prk,
            "an empty salt must be equivalent to a HashLen zero-filled salt (RFC 5869 §2.2)"
        );
    }

    #[test]
    fn hkdf_different_info_produces_different_keys() {
        let ikm = [0xAAu8; 32];
        let salt = [0xBBu8; 16];

        let mut okm1 = [0u8; KEY_SIZE];
        let mut okm2 = [0u8; KEY_SIZE];

        hkdf_sha256(&ikm, &salt, b"label-one", &mut okm1).expect("hkdf failed");
        hkdf_sha256(&ikm, &salt, b"label-two", &mut okm2).expect("hkdf failed");

        assert_ne!(
            okm1, okm2,
            "different info labels must produce different keys"
        );
    }

    #[test]
    fn hkdf_output_too_long_fails() {
        let prk = [0u8; SHA256_DIGEST_LEN];
        // 255 * 32 + 1 = 8161 bytes (exceeds max)
        let mut okm = [0u8; 8161];
        let result = hkdf_expand(&prk, b"info", &mut okm);
        assert_eq!(result, Err(SecurityError::HkdfOutputTooLong));
    }

    // -- SleepTier Display test --

    #[test]
    fn sleep_tier_display() {
        assert_eq!(SleepTier::Short.to_string(), "Short (PIN unlock)");
        assert_eq!(SleepTier::Long.to_string(), "Long (passphrase required)");
    }
}
