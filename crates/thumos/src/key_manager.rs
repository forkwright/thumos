//! Key hierarchy management for the thumos kernel.
//!
//! Manages the cryptographic key lifecycle:
//! 1. Passphrase -> primary key (via PBKDF2-HMAC-SHA256)
//! 2. Primary key -> per-purpose sub-keys (via HKDF-SHA256)
//! 3. Secure zeroization on sleep/panic
//!
//! The primary key is zeroized immediately after deriving sub-keys.
//! Sub-keys are zeroized on long-sleep or panic transitions.
//!
//! Key hierarchy labels (HKDF info strings):
//! - `"thumos-data-v1"` — partition encryption key
//! - `"thumos-audit-v1"` — audit log HMAC key
//! - `"thumos-csprng-v1"` — stable domain-separated reseed input; never a
//!   standalone seed (#873)
//! - `"thumos-session-v1"` — stable session-key wrapper input

extern crate alloc;

use core::fmt;

use crate::security::{self, KEY_SIZE, SecurityError, SleepTier, XTS_KEY_SIZE};

// ---------------------------------------------------------------------------
// HKDF labels
// ---------------------------------------------------------------------------

/// HKDF info label for the data (partition encryption) key.
const LABEL_DATA: &[u8] = b"thumos-data-v1";

/// HKDF info label for the audit log HMAC key.
const LABEL_AUDIT: &[u8] = b"thumos-audit-v1";

/// HKDF info label for the stable CSPRNG reseed input (#873).
const LABEL_CSPRNG: &[u8] = b"thumos-csprng-v1";

/// HKDF info label for the stable session-key wrapper input.
const LABEL_SESSION: &[u8] = b"thumos-session-v1";

/// HKDF info label for the boot passphrase verifier (#446).
///
/// The verifier is not a key: it is stored plaintext in the secrets
/// preamble (`crate::secrets`) so the boot gate can distinguish a correct
/// passphrase from a wrong one before mounting. Deriving it from the
/// primary key keeps verification at PBKDF2 strength per guess.
const LABEL_VERIFY: &[u8] = b"thumos-verify-v1";

// NOTE (#449): there is deliberately NO compile-time salt constant. The
// PBKDF2 salt is a per-device random value generated at provisioning and
// persisted in the on-disk secrets preamble (crate::secrets); every caller
// passes it in. Two devices with the same passphrase must never derive the
// same primary key.

// ---------------------------------------------------------------------------
// SecureKey
// ---------------------------------------------------------------------------

/// A fixed-size cryptographic key that is zeroized on drop.
///
/// Uses `write_volatile` to prevent the compiler from eliding the
/// zeroization as a dead store.
pub(crate) struct SecureKey<const N: usize>([u8; N]);

impl<const N: usize> SecureKey<N> {
    /// Create a new `SecureKey` from raw bytes.
    pub(crate) fn new(bytes: [u8; N]) -> Self {
        Self(bytes)
    }

    /// Borrow the key bytes.
    pub(crate) fn as_bytes(&self) -> &[u8; N] {
        &self.0
    }

    /// Check whether the key is all zeros (zeroized or never set).
    pub(crate) fn is_zero(&self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }

    /// Explicitly zeroize the key material.
    pub(crate) fn zeroize(&mut self) {
        for byte in &mut self.0 {
            // SAFETY: write_volatile prevents dead-store elimination.
            // The pointer is valid because it points into our own array.
            #[expect(
                unsafe_code,
                reason = "write_volatile required to prevent dead-store elimination of zeroization"
            )]
            unsafe {
                core::ptr::write_volatile(byte, 0);
            }
        }
    }
}

impl<const N: usize> Drop for SecureKey<N> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<const N: usize> fmt::Debug for SecureKey<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecureKey<{N}>([REDACTED])")
    }
}

impl<const N: usize> fmt::Display for SecureKey<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecureKey<{N}>")
    }
}

/// Overwrite a stack key buffer with zeros via volatile writes.
///
/// WHY: mirrors [`SecureKey::zeroize`] for buffers that never become a
/// `SecureKey` themselves. The plaintext intermediate arrays in
/// [`KeyManager::derive_from_passphrase`] and
/// [`KeyManager::derive_partition_keys`] are `Copy`, so constructing a
/// `SecureKey` from them leaves the original array un-zeroized; this
/// closes that gap explicitly on every return path (#325).
pub(crate) fn volatile_zero<const N: usize>(buf: &mut [u8; N]) {
    volatile_zero_slice(buf);
}

/// [`volatile_zero`] for a buffer whose length is not known at compile time.
///
/// The Argon2id block matrix is sized from a record's recorded cost and lives
/// in pages borrowed from the page allocator, so it cannot be an array (#272).
/// One implementation rather than two, because a scrub that silently stopped
/// working would leave no symptom.
pub(crate) fn volatile_zero_slice(buf: &mut [u8]) {
    for byte in buf.iter_mut() {
        // SAFETY: write_volatile prevents dead-store elimination; byte
        // points into the caller-owned stack array.
        #[expect(
            unsafe_code,
            reason = "write_volatile required to prevent dead-store elimination of zeroization"
        )]
        unsafe {
            core::ptr::write_volatile(byte, 0);
        }
    }
}

// ---------------------------------------------------------------------------
// KeySet
// ---------------------------------------------------------------------------

/// The set of per-purpose keys derived from a primary key.
#[expect(
    clippy::struct_field_names,
    reason = "key suffix is domain terminology, not redundant with struct name"
)]
pub(crate) struct KeySet {
    /// Partition encryption key (AES-256-XTS, 64 bytes).
    pub data_key: SecureKey<XTS_KEY_SIZE>,
    /// Audit log HMAC key.
    pub audit_key: SecureKey<KEY_SIZE>,
    /// Stable CSPRNG reseed input; unsafe as a standalone reset seed (#873).
    pub csprng_key: SecureKey<KEY_SIZE>,
    /// Stable session-key wrapper input; not itself an ephemeral session key.
    pub session_key: SecureKey<KEY_SIZE>,
}

impl fmt::Debug for KeySet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeySet")
            .field("data_key", &self.data_key)
            .field("audit_key", &self.audit_key)
            .field("csprng_key", &self.csprng_key)
            .field("session_key", &self.session_key)
            .finish()
    }
}

impl fmt::Display for KeySet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeySet(data, audit, csprng, session)")
    }
}

// ---------------------------------------------------------------------------
// KeyManager
// ---------------------------------------------------------------------------

/// Manages the kernel key hierarchy and sleep-tier lifecycle.
///
/// Holds derived partition keys and tracks whether the primary key has been
/// used to derive them. The primary key itself is never stored — it is
/// zeroized immediately after deriving sub-keys.
pub(crate) struct KeyManager {
    /// Whether keys have been derived from a primary key.
    primary_key_derived: bool,
    /// Partition encryption key (XTS, 64 bytes).
    data_key: Option<SecureKey<XTS_KEY_SIZE>>,
    /// Audit log HMAC key.
    audit_key: Option<SecureKey<KEY_SIZE>>,
    /// Stable CSPRNG reseed input (#873).
    csprng_key: Option<SecureKey<KEY_SIZE>>,
    /// Stable session-key wrapper input.
    session_key: Option<SecureKey<KEY_SIZE>>,
    /// Current sleep tier.
    sleep_tier: SleepTier,
}

impl KeyManager {
    /// Create a new `KeyManager` with no keys loaded.
    #[must_use]
    pub(crate) const fn new() -> Self {
        Self {
            primary_key_derived: false,
            data_key: None,
            audit_key: None,
            csprng_key: None,
            session_key: None,
            sleep_tier: SleepTier::Long,
        }
    }

    /// Derive a primary key from a passphrase using PBKDF2-HMAC-SHA256.
    ///
    /// Returns the 32-byte primary key. The caller should immediately pass
    /// it to [`KeyManager::derive_partition_keys`] and then drop it (the
    /// `SecureKey` wrapper will zeroize on drop).
    ///
    /// `salt` is the per-device random salt from the secrets preamble
    /// (#449): generated once at provisioning, persisted in plaintext (a
    /// salt is public by design), and read back on every boot. It is what
    /// makes brute-force resistance per-DEVICE rather than per-image.
    ///
    /// `kdf` comes from the device's own secrets preamble (#914), never from a
    /// policy constant. The master key IS this derivation's output, so deriving
    /// under different parameters than the ones that produced it yields a
    /// different key and an unreadable partition -- the failure would surface
    /// as a rejected passphrase, which is the most misleading form it could
    /// take.
    ///
    /// # Errors
    ///
    /// Returns [`SecurityError`] if key derivation fails, including when
    /// Argon2id's memory was unavailable -- never a silently cheaper key.
    pub(crate) fn derive_from_passphrase(
        passphrase: &[u8],
        salt: &[u8],
        kdf: security::PinKdf,
    ) -> Result<SecureKey<KEY_SIZE>, SecurityError> {
        let derive_result = security::derive_under(kdf, passphrase, salt);
        let mut key_bytes = derive_result.unwrap_or([0u8; KEY_SIZE]);
        let result = if derive_result.is_ok() {
            Ok(SecureKey::new(key_bytes))
        } else {
            Err(SecurityError::KeyDerivationFailed)
        };
        // WHY: zero the stack copy on every path (success or error) — see
        // volatile_zero's doc comment. key_bytes is Copy, so SecureKey::new
        // above (on success) left this array fully populated (#325).
        volatile_zero(&mut key_bytes);
        result
    }

    /// Derive per-purpose partition keys from a primary key via HKDF-SHA256.
    ///
    /// Derives four sub-keys with distinct labels:
    /// - `data_key` (64 bytes, XTS): partition encryption
    /// - `audit_key` (32 bytes): audit log HMAC
    /// - `csprng_key` (32 bytes): one stable reseed input that must be mixed
    ///   with fresh credited entropy or authenticated non-repeating state (#873)
    /// - `session_key` (32 bytes): stable wrapper input for ephemeral sessions
    ///
    /// Stores the keys internally and marks the manager as initialized.
    /// The primary key should be dropped (zeroized) after this call.
    ///
    /// # Errors
    ///
    /// Returns [`SecurityError`] if HKDF derivation fails.
    pub(crate) fn derive_partition_keys(
        &mut self,
        primary: &SecureKey<KEY_SIZE>,
    ) -> Result<(), SecurityError> {
        // Derive each sub-key via HKDF with the primary key as IKM.
        let ikm = primary.as_bytes();

        let mut data_bytes = [0u8; XTS_KEY_SIZE];
        let data_result = security::hkdf_sha256(ikm, &[], LABEL_DATA, &mut data_bytes);

        let mut audit_bytes = [0u8; KEY_SIZE];
        let audit_result = security::hkdf_sha256(ikm, &[], LABEL_AUDIT, &mut audit_bytes);

        let mut csprng_bytes = [0u8; KEY_SIZE];
        let csprng_result = security::hkdf_sha256(ikm, &[], LABEL_CSPRNG, &mut csprng_bytes);

        let mut session_bytes = [0u8; KEY_SIZE];
        let session_result = security::hkdf_sha256(ikm, &[], LABEL_SESSION, &mut session_bytes);

        let result = data_result
            .and(audit_result)
            .and(csprng_result)
            .and(session_result);

        if result.is_ok() {
            self.data_key = Some(SecureKey::new(data_bytes));
            self.audit_key = Some(SecureKey::new(audit_bytes));
            self.csprng_key = Some(SecureKey::new(csprng_bytes));
            self.session_key = Some(SecureKey::new(session_bytes));
            self.primary_key_derived = true;
            self.sleep_tier = SleepTier::Short;
        }

        // WHY: zero every intermediate stack buffer on both the success and
        // error paths — each is Copy, so constructing the SecureKey above
        // (when successful) left the original array fully populated (#325).
        volatile_zero(&mut data_bytes);
        volatile_zero(&mut audit_bytes);
        volatile_zero(&mut csprng_bytes);
        volatile_zero(&mut session_bytes);

        result
    }

    /// Derive the boot passphrase verifier from a primary key (#446).
    ///
    /// The verifier is what first-boot setup stores in the secrets preamble
    /// (`crate::secrets`, slot kind 4, plaintext) and what the boot passphrase
    /// gate compares against (constant-time) BEFORE any mount. It is an
    /// HKDF output over the primary key, so a stored verifier costs an
    /// attacker one full PBKDF2 run per guess — the same as attacking the
    /// encrypted payload directly. It is deliberately NOT
    /// `SHA-256(passphrase)`, which would be a fast offline oracle.
    ///
    /// The verifier is public by construction, so the output is a plain
    /// array, not a [`SecureKey`].
    ///
    /// # Errors
    ///
    /// Returns [`SecurityError`] if HKDF derivation fails.
    pub(crate) fn derive_boot_verifier(
        primary: &SecureKey<KEY_SIZE>,
    ) -> Result<[u8; KEY_SIZE], SecurityError> {
        let mut out = [0u8; KEY_SIZE];
        let result = security::hkdf_sha256(primary.as_bytes(), &[], LABEL_VERIFY, &mut out);
        if result.is_err() {
            // WHY: a half-derived verifier must never escape — same
            // zero-on-every-path posture as derive_partition_keys (#325).
            volatile_zero(&mut out);
        }
        result.map(|()| out)
    }

    /// Zeroize all partition keys and transition to long-sleep tier.
    ///
    /// After this call, a full passphrase re-entry is required to
    /// re-derive keys.
    pub(crate) fn zeroize_all(&mut self) {
        self.data_key = None;
        self.audit_key = None;
        self.csprng_key = None;
        self.session_key = None;
        self.primary_key_derived = false;
        self.sleep_tier = SleepTier::Long;
    }

    /// Check whether partition keys are currently loaded.
    #[must_use]
    pub(crate) fn has_keys(&self) -> bool {
        self.primary_key_derived
            && self.data_key.is_some()
            && self.audit_key.is_some()
            && self.csprng_key.is_some()
            && self.session_key.is_some()
    }

    /// Borrow the data (partition encryption) key, if loaded.
    pub(crate) fn data_key(&self) -> Option<&SecureKey<XTS_KEY_SIZE>> {
        self.data_key.as_ref()
    }

    /// Borrow the audit log HMAC key, if loaded.
    pub(crate) fn audit_key(&self) -> Option<&SecureKey<KEY_SIZE>> {
        self.audit_key.as_ref()
    }

    /// Borrow the CSPRNG seed key, if loaded.
    pub(crate) fn csprng_key(&self) -> Option<&SecureKey<KEY_SIZE>> {
        self.csprng_key.as_ref()
    }

    /// Borrow the session key, if loaded.
    pub(crate) fn session_key(&self) -> Option<&SecureKey<KEY_SIZE>> {
        self.session_key.as_ref()
    }

    /// Current sleep tier.
    #[must_use]
    pub(crate) fn sleep_tier(&self) -> SleepTier {
        self.sleep_tier
    }

    /// Set the sleep tier. If transitioning to `Long`, zeroizes all keys.
    pub(crate) fn set_sleep_tier(&mut self, tier: SleepTier) {
        if tier == SleepTier::Long {
            self.zeroize_all();
        }
        self.sleep_tier = tier;
    }
}

impl Default for KeyManager {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for KeyManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // WHY: key fields are intentionally omitted (redacted) to prevent
        // accidental leakage in debug output. finish_non_exhaustive signals
        // that fields exist but are not shown.
        f.debug_struct("KeyManager")
            .field("primary_key_derived", &self.primary_key_derived)
            .field("has_keys", &self.has_keys())
            .field("sleep_tier", &self.sleep_tier)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for KeyManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "KeyManager(keys={}, tier={})",
            if self.has_keys() { "loaded" } else { "none" },
            self.sleep_tier,
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Fixed salt for deterministic unit tests (the production salt is a
    /// per-device random value from the secrets preamble, #449).
    const TEST_SALT: &[u8] = b"thumos-unit-test-salt";

    // Use a low iteration count for test speed.
    fn derive_test_primary(passphrase: &[u8]) -> SecureKey<KEY_SIZE> {
        let mut key_bytes = [0u8; KEY_SIZE];
        security::pbkdf2_sha256(passphrase, TEST_SALT, 1, &mut key_bytes)
            .expect("pbkdf2 derivation failed in test");
        SecureKey::new(key_bytes)
    }

    #[test]
    fn derive_from_passphrase_is_deterministic() {
        let key1 = derive_test_primary(b"test passphrase");
        let key2 = derive_test_primary(b"test passphrase");
        assert_eq!(
            key1.as_bytes(),
            key2.as_bytes(),
            "same passphrase must produce the same primary key"
        );
    }

    #[test]
    fn different_passphrases_produce_different_keys() {
        let key1 = derive_test_primary(b"passphrase alpha");
        let key2 = derive_test_primary(b"passphrase bravo");
        assert_ne!(
            key1.as_bytes(),
            key2.as_bytes(),
            "different passphrases must produce different keys"
        );
    }

    #[test]
    fn derive_partition_keys_produces_distinct_keys() {
        let primary = derive_test_primary(b"partition key test");
        let mut km = KeyManager::new();
        km.derive_partition_keys(&primary)
            .expect("derive_partition_keys failed");

        assert!(km.has_keys(), "keys must be loaded after derivation");

        let data = km.data_key().expect("data key missing");
        let audit = km.audit_key().expect("audit key missing");
        let csprng = km.csprng_key().expect("csprng key missing");
        let session = km.session_key().expect("session key missing");

        // All 32-byte sub-keys must differ from each other.
        assert_ne!(
            audit.as_bytes(),
            csprng.as_bytes(),
            "audit and csprng keys must differ"
        );
        assert_ne!(
            audit.as_bytes(),
            session.as_bytes(),
            "audit and session keys must differ"
        );
        assert_ne!(
            csprng.as_bytes(),
            session.as_bytes(),
            "csprng and session keys must differ"
        );

        // Data key (64 bytes) should not be all zeros.
        assert!(!data.is_zero(), "data key must not be all zeros");
        assert!(!audit.is_zero(), "audit key must not be all zeros");
    }

    #[test]
    fn zeroize_all_clears_keys() {
        let primary = derive_test_primary(b"zeroize test");
        let mut km = KeyManager::new();
        km.derive_partition_keys(&primary)
            .expect("derive_partition_keys failed");

        assert!(km.has_keys());

        km.zeroize_all();

        assert!(!km.has_keys(), "keys must be cleared after zeroize_all");
        assert!(km.data_key().is_none(), "data key must be None");
        assert!(km.audit_key().is_none(), "audit key must be None");
        assert!(km.csprng_key().is_none(), "csprng key must be None");
        assert!(km.session_key().is_none(), "session key must be None");
        assert_eq!(km.sleep_tier(), SleepTier::Long);
    }

    #[test]
    fn volatile_zero_clears_buffer() {
        let mut buf = [0xAAu8; KEY_SIZE];
        assert!(buf.iter().any(|&b| b != 0));
        volatile_zero(&mut buf);
        assert!(
            buf.iter().all(|&b| b == 0),
            "volatile_zero must clear every byte"
        );
    }

    #[test]
    fn secure_key_zeros_on_drop() {
        // We cannot observe the memory after drop directly, but we can verify
        // that zeroize() works before drop.
        let mut key = SecureKey::new([0xAA; KEY_SIZE]);
        assert!(!key.is_zero(), "key must not be zero before zeroize");
        key.zeroize();
        assert!(key.is_zero(), "key must be zero after explicit zeroize");
    }

    #[test]
    fn long_sleep_zeroizes_keys() {
        let primary = derive_test_primary(b"sleep tier test");
        let mut km = KeyManager::new();
        km.derive_partition_keys(&primary)
            .expect("derive_partition_keys failed");

        assert!(km.has_keys());
        assert_eq!(km.sleep_tier(), SleepTier::Short);

        km.set_sleep_tier(SleepTier::Long);

        assert!(!km.has_keys(), "long sleep must zeroize keys");
        assert_eq!(km.sleep_tier(), SleepTier::Long);
    }

    #[test]
    fn new_key_manager_has_no_keys() {
        let km = KeyManager::new();
        assert!(!km.has_keys());
        assert_eq!(km.sleep_tier(), SleepTier::Long);
    }

    #[test]
    fn key_manager_display() {
        let km = KeyManager::new();
        let s = alloc::format!("{km}");
        assert!(s.contains("none"), "display must show no keys");
        assert!(s.contains("Long"), "display must show long sleep tier");
    }

    #[test]
    fn derive_partition_keys_deterministic() {
        let primary = derive_test_primary(b"deterministic test");

        let mut km1 = KeyManager::new();
        km1.derive_partition_keys(&primary)
            .expect("derive_partition_keys failed");

        // Re-derive with same primary key.
        let primary2 = derive_test_primary(b"deterministic test");
        let mut km2 = KeyManager::new();
        km2.derive_partition_keys(&primary2)
            .expect("derive_partition_keys failed");

        assert_eq!(
            km1.data_key().expect("data key missing").as_bytes(),
            km2.data_key().expect("data key missing").as_bytes(),
            "same primary key must produce same data key"
        );
        assert_eq!(
            km1.audit_key().expect("audit key missing").as_bytes(),
            km2.audit_key().expect("audit key missing").as_bytes(),
            "same primary key must produce same audit key"
        );
    }

    #[test]
    fn derive_from_passphrase_production_entry_point() {
        // Done-when (finding 25): exercise the actual production entry
        // point -- 100k PBKDF2 iterations with the injected device salt --
        // not just the low-iteration derive_test_primary helper every other
        // test in this module uses for speed.
        let key1 = KeyManager::derive_from_passphrase(
            b"production entry point test",
            TEST_SALT,
            crate::secrets::V1_KDF,
        )
        .expect("derive_from_passphrase must succeed");
        assert!(!key1.is_zero(), "derived primary key must not be all zeros");

        let key2 = KeyManager::derive_from_passphrase(
            b"production entry point test",
            TEST_SALT,
            crate::secrets::V1_KDF,
        )
        .expect("derive_from_passphrase must succeed");
        assert_eq!(
            key1.as_bytes(),
            key2.as_bytes(),
            "the production entry point must be deterministic for the same passphrase + salt"
        );
    }

    #[test]
    fn derive_from_passphrase_differs_per_device_salt() {
        // The #449 contract: two devices (two persisted random salts) with
        // the same user passphrase MUST derive different primary keys —
        // brute-force/rainbow resistance is per-device, not per-image.
        let salt_a: &[u8] = b"device-a-persisted-salt";
        let salt_b: &[u8] = b"device-b-persisted-salt";
        let key_a = KeyManager::derive_from_passphrase(
            b"the same user passphrase",
            salt_a,
            crate::secrets::V1_KDF,
        )
        .expect("derive with salt A");
        let key_b = KeyManager::derive_from_passphrase(
            b"the same user passphrase",
            salt_b,
            crate::secrets::V1_KDF,
        )
        .expect("derive with salt B");
        assert_ne!(
            key_a.as_bytes(),
            key_b.as_bytes(),
            "same passphrase + different device salts must derive different primary keys"
        );
    }

    #[test]
    fn derive_from_passphrase_differs_per_kdf_parameters() {
        // #914's own done-when: the KDF record is pointless if two different
        // recorded parameter sets, for the same passphrase and salt, could
        // silently derive the same key -- that would mean the record is
        // decorative, not load-bearing.
        let low = security::PinKdf::Pbkdf2Sha256 { iterations: 1 };
        let high = security::PinKdf::Pbkdf2Sha256 { iterations: 2 };
        let key_low =
            KeyManager::derive_from_passphrase(b"same passphrase, same salt", TEST_SALT, low)
                .expect("derive under the low-iteration record");
        let key_high =
            KeyManager::derive_from_passphrase(b"same passphrase, same salt", TEST_SALT, high)
                .expect("derive under the high-iteration record");
        assert_ne!(
            key_low.as_bytes(),
            key_high.as_bytes(),
            "same passphrase + same salt + different recorded KDF parameters must derive different keys (#914 done-when)"
        );
    }

    #[test]
    fn boot_verifier_is_deterministic_per_primary() {
        let primary = derive_test_primary(b"verifier determinism");
        let v1 = KeyManager::derive_boot_verifier(&primary).expect("derive verifier");
        let v2 = KeyManager::derive_boot_verifier(&primary).expect("derive verifier");
        assert_eq!(v1, v2, "same primary must yield the same verifier");
        assert_ne!(v1, [0u8; KEY_SIZE], "verifier must not be zero");
    }

    #[test]
    fn boot_verifier_tracks_the_passphrase() {
        let primary_a = derive_test_primary(b"correct horse");
        let primary_b = derive_test_primary(b"battery staple");
        let v_a = KeyManager::derive_boot_verifier(&primary_a).expect("verifier a");
        let v_b = KeyManager::derive_boot_verifier(&primary_b).expect("verifier b");
        assert_ne!(
            v_a, v_b,
            "different passphrases must verify differently (the boot gate's whole point)"
        );
    }

    #[test]
    fn boot_verifier_is_label_separated_from_partition_keys() {
        let primary = derive_test_primary(b"label separation");
        let verifier = KeyManager::derive_boot_verifier(&primary).expect("verifier");
        let mut km = KeyManager::new();
        km.derive_partition_keys(&primary).expect("partition keys");
        let data = km.data_key().expect("data key").as_bytes();
        assert_ne!(
            &verifier[..],
            &data[..KEY_SIZE],
            "HKDF label separation: verifier must differ from the data key"
        );
        assert_ne!(
            &verifier[..],
            &primary.as_bytes()[..],
            "the verifier is a derived value, never the primary itself"
        );
    }

    #[test]
    fn set_sleep_tier_short_preserves_keys() {
        // Done-when (finding 26): set_sleep_tier's non-Long branch must
        // leave loaded keys untouched -- only a transition TO Long
        // triggers zeroize_all. The existing long_sleep_zeroizes_keys
        // test only exercises the Long branch.
        let primary = derive_test_primary(b"short tier preserves keys");
        let mut km = KeyManager::new();
        km.derive_partition_keys(&primary)
            .expect("derive_partition_keys failed");
        assert!(km.has_keys());

        let data_before = *km.data_key().expect("data key missing").as_bytes();

        km.set_sleep_tier(SleepTier::Short);

        assert!(
            km.has_keys(),
            "transitioning to Short must not zeroize keys"
        );
        assert_eq!(km.sleep_tier(), SleepTier::Short);
        assert_eq!(
            km.data_key().expect("data key missing").as_bytes(),
            &data_before,
            "data key must be unchanged by a non-Long sleep-tier transition"
        );
    }
}
