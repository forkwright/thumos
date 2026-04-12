//! Key hierarchy management for the thumos kernel.
//!
//! Manages the cryptographic key lifecycle:
//! 1. Passphrase -> master key (via PBKDF2-HMAC-SHA256)
//! 2. Master key -> per-purpose sub-keys (via HKDF-SHA256)
//! 3. Secure zeroization on sleep/panic
//!
//! The master key is zeroized immediately after deriving sub-keys.
//! Sub-keys are zeroized on long-sleep or panic transitions.
//!
//! Key hierarchy labels (HKDF info strings):
//! - `"thumos-data-v1"` — partition encryption key
//! - `"thumos-audit-v1"` — audit log HMAC key
//! - `"thumos-csprng-v1"` — CSPRNG seed key
//! - `"thumos-session-v1"` — ephemeral session key

extern crate alloc;

use core::fmt;

use crate::security::{
    self, SecurityError, SleepTier, KEY_SIZE, PBKDF2_ITERATIONS, XTS_KEY_SIZE,
};

// ---------------------------------------------------------------------------
// HKDF labels
// ---------------------------------------------------------------------------

/// HKDF info label for the data (partition encryption) key.
const LABEL_DATA: &[u8] = b"thumos-data-v1";

/// HKDF info label for the audit log HMAC key.
const LABEL_AUDIT: &[u8] = b"thumos-audit-v1";

/// HKDF info label for the CSPRNG seed key.
const LABEL_CSPRNG: &[u8] = b"thumos-csprng-v1";

/// HKDF info label for ephemeral session keys.
const LABEL_SESSION: &[u8] = b"thumos-session-v1";

/// Salt used for PBKDF2 derivation. In production this would be device-specific
/// (e.g., from eMMC CID or a stored random salt). Fixed here for
/// determinism until the key slot infrastructure (Wave 3) is added.
const PBKDF2_SALT: &[u8] = b"thumos-pbkdf2-salt-v1";

// ---------------------------------------------------------------------------
// SecureKey
// ---------------------------------------------------------------------------

/// A fixed-size cryptographic key that is zeroized on drop.
///
/// Uses `write_volatile` to prevent the compiler from eliding the
/// zeroization as a dead store.
pub struct SecureKey<const N: usize>([u8; N]);

impl<const N: usize> SecureKey<N> {
    /// Create a new `SecureKey` from raw bytes.
    pub fn new(bytes: [u8; N]) -> Self {
        Self(bytes)
    }

    /// Borrow the key bytes.
    pub fn as_bytes(&self) -> &[u8; N] {
        &self.0
    }

    /// Check whether the key is all zeros (zeroized or never set).
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }

    /// Explicitly zeroize the key material.
    pub fn zeroize(&mut self) {
        for byte in &mut self.0 {
            // SAFETY: write_volatile prevents dead-store elimination.
            // The pointer is valid because it points into our own array.
            #[expect(unsafe_code, reason = "write_volatile required to prevent dead-store elimination of zeroization")]
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

// ---------------------------------------------------------------------------
// KeySet
// ---------------------------------------------------------------------------

/// The set of per-purpose keys derived from a master key.
#[expect(clippy::struct_field_names, reason = "key suffix is domain terminology, not redundant with struct name")]
pub struct KeySet {
    /// Partition encryption key (AES-256-XTS, 64 bytes).
    pub data_key: SecureKey<XTS_KEY_SIZE>,
    /// Audit log HMAC key.
    pub audit_key: SecureKey<KEY_SIZE>,
    /// CSPRNG seed key.
    pub csprng_key: SecureKey<KEY_SIZE>,
    /// Ephemeral session key.
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
/// Holds derived partition keys and tracks whether the master key has been
/// used to derive them. The master key itself is never stored — it is
/// zeroized immediately after deriving sub-keys.
pub struct KeyManager {
    /// Whether keys have been derived from a master key.
    master_key_derived: bool,
    /// Partition encryption key (XTS, 64 bytes).
    data_key: Option<SecureKey<XTS_KEY_SIZE>>,
    /// Audit log HMAC key.
    audit_key: Option<SecureKey<KEY_SIZE>>,
    /// CSPRNG seed key.
    csprng_key: Option<SecureKey<KEY_SIZE>>,
    /// Ephemeral session key.
    session_key: Option<SecureKey<KEY_SIZE>>,
    /// Current sleep tier.
    sleep_tier: SleepTier,
}

impl KeyManager {
    /// Create a new `KeyManager` with no keys loaded.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            master_key_derived: false,
            data_key: None,
            audit_key: None,
            csprng_key: None,
            session_key: None,
            sleep_tier: SleepTier::Long,
        }
    }

    /// Derive a master key from a passphrase using PBKDF2-HMAC-SHA256.
    ///
    /// Returns the 32-byte master key. The caller should immediately pass
    /// it to [`KeyManager::derive_partition_keys`] and then drop it (the
    /// `SecureKey` wrapper will zeroize on drop).
    ///
    /// Uses [`PBKDF2_ITERATIONS`] rounds.
    ///
    /// # Errors
    ///
    /// Returns [`SecurityError`] if key derivation fails.
    pub fn derive_from_passphrase(
        passphrase: &[u8],
    ) -> Result<SecureKey<KEY_SIZE>, SecurityError> {
        let mut key_bytes = [0u8; KEY_SIZE];
        security::pbkdf2_sha256(passphrase, PBKDF2_SALT, PBKDF2_ITERATIONS, &mut key_bytes)?;
        Ok(SecureKey::new(key_bytes))
    }

    /// Derive per-purpose partition keys from a master key via HKDF-SHA256.
    ///
    /// Derives four sub-keys with distinct labels:
    /// - `data_key` (64 bytes, XTS): partition encryption
    /// - `audit_key` (32 bytes): audit log HMAC
    /// - `csprng_key` (32 bytes): CSPRNG seeding
    /// - `session_key` (32 bytes): ephemeral session operations
    ///
    /// Stores the keys internally and marks the manager as initialized.
    /// The master key should be dropped (zeroized) after this call.
    ///
    /// # Errors
    ///
    /// Returns [`SecurityError`] if HKDF derivation fails.
    pub fn derive_partition_keys(
        &mut self,
        master: &SecureKey<KEY_SIZE>,
    ) -> Result<(), SecurityError> {
        // Derive each sub-key via HKDF with the master key as IKM.
        let ikm = master.as_bytes();

        let mut data_bytes = [0u8; XTS_KEY_SIZE];
        security::hkdf_sha256(ikm, &[], LABEL_DATA, &mut data_bytes)?;

        let mut audit_bytes = [0u8; KEY_SIZE];
        security::hkdf_sha256(ikm, &[], LABEL_AUDIT, &mut audit_bytes)?;

        let mut csprng_bytes = [0u8; KEY_SIZE];
        security::hkdf_sha256(ikm, &[], LABEL_CSPRNG, &mut csprng_bytes)?;

        let mut session_bytes = [0u8; KEY_SIZE];
        security::hkdf_sha256(ikm, &[], LABEL_SESSION, &mut session_bytes)?;

        self.data_key = Some(SecureKey::new(data_bytes));
        self.audit_key = Some(SecureKey::new(audit_bytes));
        self.csprng_key = Some(SecureKey::new(csprng_bytes));
        self.session_key = Some(SecureKey::new(session_bytes));
        self.master_key_derived = true;
        self.sleep_tier = SleepTier::Short;

        Ok(())
    }

    /// Zeroize all partition keys and transition to long-sleep tier.
    ///
    /// After this call, a full passphrase re-entry is required to
    /// re-derive keys.
    pub fn zeroize_all(&mut self) {
        self.data_key = None;
        self.audit_key = None;
        self.csprng_key = None;
        self.session_key = None;
        self.master_key_derived = false;
        self.sleep_tier = SleepTier::Long;
    }

    /// Check whether partition keys are currently loaded.
    #[must_use]
    pub fn has_keys(&self) -> bool {
        self.master_key_derived
            && self.data_key.is_some()
            && self.audit_key.is_some()
            && self.csprng_key.is_some()
            && self.session_key.is_some()
    }

    /// Borrow the data (partition encryption) key, if loaded.
    pub fn data_key(&self) -> Option<&SecureKey<XTS_KEY_SIZE>> {
        self.data_key.as_ref()
    }

    /// Borrow the audit log HMAC key, if loaded.
    pub fn audit_key(&self) -> Option<&SecureKey<KEY_SIZE>> {
        self.audit_key.as_ref()
    }

    /// Borrow the CSPRNG seed key, if loaded.
    pub fn csprng_key(&self) -> Option<&SecureKey<KEY_SIZE>> {
        self.csprng_key.as_ref()
    }

    /// Borrow the session key, if loaded.
    pub fn session_key(&self) -> Option<&SecureKey<KEY_SIZE>> {
        self.session_key.as_ref()
    }

    /// Current sleep tier.
    #[must_use]
    pub fn sleep_tier(&self) -> SleepTier {
        self.sleep_tier
    }

    /// Set the sleep tier. If transitioning to `Long`, zeroizes all keys.
    pub fn set_sleep_tier(&mut self, tier: SleepTier) {
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
            .field("master_key_derived", &self.master_key_derived)
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

    // Use a low iteration count for test speed.
    fn derive_test_master(passphrase: &[u8]) -> SecureKey<KEY_SIZE> {
        let mut key_bytes = [0u8; KEY_SIZE];
        security::pbkdf2_sha256(passphrase, PBKDF2_SALT, 1, &mut key_bytes)
            .expect("pbkdf2 derivation failed in test");
        SecureKey::new(key_bytes)
    }

    #[test]
    fn derive_from_passphrase_is_deterministic() {
        let key1 = derive_test_master(b"test passphrase");
        let key2 = derive_test_master(b"test passphrase");
        assert_eq!(
            key1.as_bytes(),
            key2.as_bytes(),
            "same passphrase must produce the same master key"
        );
    }

    #[test]
    fn different_passphrases_produce_different_keys() {
        let key1 = derive_test_master(b"passphrase alpha");
        let key2 = derive_test_master(b"passphrase bravo");
        assert_ne!(
            key1.as_bytes(),
            key2.as_bytes(),
            "different passphrases must produce different keys"
        );
    }

    #[test]
    fn derive_partition_keys_produces_distinct_keys() {
        let master = derive_test_master(b"partition key test");
        let mut km = KeyManager::new();
        km.derive_partition_keys(&master)
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
        let master = derive_test_master(b"zeroize test");
        let mut km = KeyManager::new();
        km.derive_partition_keys(&master)
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
        let master = derive_test_master(b"sleep tier test");
        let mut km = KeyManager::new();
        km.derive_partition_keys(&master)
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
        let master = derive_test_master(b"deterministic test");

        let mut km1 = KeyManager::new();
        km1.derive_partition_keys(&master)
            .expect("derive_partition_keys failed");

        // Re-derive with same master key.
        let master2 = derive_test_master(b"deterministic test");
        let mut km2 = KeyManager::new();
        km2.derive_partition_keys(&master2)
            .expect("derive_partition_keys failed");

        assert_eq!(
            km1.data_key().expect("data key missing").as_bytes(),
            km2.data_key().expect("data key missing").as_bytes(),
            "same master key must produce same data key"
        );
        assert_eq!(
            km1.audit_key().expect("audit key missing").as_bytes(),
            km2.audit_key().expect("audit key missing").as_bytes(),
            "same master key must produce same audit key"
        );
    }
}
