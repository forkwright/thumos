//! On-disk secrets preamble — the LUKS-header analogue (#449).
//!
//! A fixed region at the head of the userdata partition, PLAINTEXT by
//! design (readable before any passphrase-derived key exists), holding
//! typed slots. A slot payload is either public by construction — the
//! PBKDF2 device salt resists precomputation by being unique per device,
//! not by being hidden — or sealed under the passphrase-derived primary
//! key (reserved kinds; the seal lands with the boot-time passphrase
//! loop, kinit Step 8c).
//!
//! # Layout (one 512-byte sector)
//!
//! ```text
//! [0..8)    magic "THSECR\0\0"
//! [8..12)   format version, u32 LE (= 1)
//! [12..16)  slot count, u32 LE (1 = salt only; 2 = salt + boot verifier)
//! [16..48)  integrity tag: SHA-256 of the sector with these 32 bytes zeroed
//! [48..80)  slot 1 payload: the device salt (32 bytes, plaintext)
//! [80..112) slot 2 payload: boot passphrase verifier (32 bytes, plaintext)
//! [112..512) zero (future slots)
//! ```
//!
//! Slot kinds: 1 = device salt (populated today); 2 = BT IRK (reserved,
//! sealed — #455 stage 2); 3 = vault PIN verifier (reserved, sealed —
//! the security-mode PIN store, whose `PIN_PBKDF2_SALT` is the same
//! fixed-salt defect class as #449); 4 = boot passphrase verifier
//! (populated at first-boot setup, #446).
//!
//! The boot verifier is PLAINTEXT by construction, like the salt: it must
//! be readable before any passphrase-derived key exists, and it is not a
//! fast oracle — it is `HKDF(primary, "thumos-verify-v1")` where the
//! primary is PBKDF2-HMAC-SHA256(passphrase, salt, 100_000), so a disk
//! image buys an attacker exactly the same per-guess cost as attacking
//! the encrypted payload itself (and NEVER a raw SHA-256(passphrase)
//! fast-path). It carries no entropy of its own beyond the passphrase.
//!
//! Provisioning is implicit: a missing, malformed, or corrupt header is
//! (re)provisioned with a fresh random salt; a valid header is read back.
//! The whole header fits one sector, so eMMC single-sector write
//! atomicity bounds the torn-write window to "old salt or new salt", and
//! the integrity tag detects the torn half.

use crate::block::{BlockDevice, BlockError, SECTOR_SIZE};

/// Header magic: "THSECR\0\0".
pub(crate) const MAGIC: [u8; 8] = *b"THSECR\0\0";

/// Preamble format version.
pub(crate) const VERSION: u32 = 1;

/// Device-salt payload length in bytes.
pub(crate) const SALT_LEN: usize = 32;

/// Byte offset of the format version field.
const VERSION_OFFSET: usize = 8;

/// Byte offset of the slot count field.
const SLOT_COUNT_OFFSET: usize = 12;

/// Byte offset of the integrity tag (SHA-256, 32 bytes).
const INTEGRITY_OFFSET: usize = 16;

/// Byte offset of the device-salt payload.
const SALT_OFFSET: usize = 48;

/// Boot-verifier payload length in bytes.
pub(crate) const VERIFIER_LEN: usize = 32;

/// Byte offset of the boot passphrase verifier payload (slot kind 4).
const VERIFIER_OFFSET: usize = 80;

/// The per-device secrets this boot derived from the preamble.
pub(crate) struct DeviceSecrets {
    /// The PBKDF2 device salt: random at provisioning, plaintext on disk,
    /// stable across boots.
    pub(crate) salt: [u8; SALT_LEN],
    /// The boot passphrase verifier (`HKDF(primary, "thumos-verify-v1")`),
    /// when first-boot setup has stored one. `None` means the device has
    /// never set a boot passphrase — the first-boot setup path.
    pub(crate) boot_verifier: Option<[u8; VERIFIER_LEN]>,
}

/// Compute the integrity tag over a sector image (tag field zeroed).
fn integrity_of(sector: &[u8; SECTOR_SIZE]) -> [u8; 32] {
    let mut copy = *sector;
    copy[INTEGRITY_OFFSET..INTEGRITY_OFFSET + 32].fill(0);
    crate::security::sha256(&copy)
}

/// Read the secrets from a sector image, or `None` if the header is
/// absent (bad magic/version/slot count) or corrupt (integrity
/// mismatch). Returns the salt plus the boot verifier when the header
/// carries one (slot count 2).
fn parse(sector: &[u8; SECTOR_SIZE]) -> Option<([u8; SALT_LEN], Option<[u8; VERIFIER_LEN]>)> {
    if sector[..8] != MAGIC {
        return None;
    }
    let version = u32::from_le_bytes(sector[VERSION_OFFSET..VERSION_OFFSET + 4].try_into().ok()?);
    if version != VERSION {
        return None;
    }
    let count = u32::from_le_bytes(
        sector[SLOT_COUNT_OFFSET..SLOT_COUNT_OFFSET + 4]
            .try_into()
            .ok()?,
    );
    if count != 1 && count != 2 {
        return None;
    }
    if sector[INTEGRITY_OFFSET..INTEGRITY_OFFSET + 32] != integrity_of(sector) {
        return None;
    }
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&sector[SALT_OFFSET..SALT_OFFSET + SALT_LEN]);
    if salt.iter().all(|&b| b == 0) {
        // An all-zero salt is never legitimate: it would silently re-create
        // the shared-salt failure mode #449 exists to kill.
        return None;
    }
    let verifier = if count == 2 {
        let mut v = [0u8; VERIFIER_LEN];
        v.copy_from_slice(&sector[VERIFIER_OFFSET..VERIFIER_OFFSET + VERIFIER_LEN]);
        if v.iter().all(|&b| b == 0) {
            // An all-zero verifier is never legitimate: a zero slot would
            // turn a corrupt read into an empty-derivation oracle.
            return None;
        }
        Some(v)
    } else {
        None
    };
    Some((salt, verifier))
}

/// Render a header sector around `salt`, optionally carrying the boot
/// verifier (slot count 2 when present, 1 otherwise).
fn render(salt: &[u8; SALT_LEN], verifier: Option<&[u8; VERIFIER_LEN]>) -> [u8; SECTOR_SIZE] {
    let mut sector = [0u8; SECTOR_SIZE];
    sector[..8].copy_from_slice(&MAGIC);
    sector[VERSION_OFFSET..VERSION_OFFSET + 4].copy_from_slice(&VERSION.to_le_bytes());
    let count: u32 = u32::from(verifier.is_some()) + 1;
    sector[SLOT_COUNT_OFFSET..SLOT_COUNT_OFFSET + 4].copy_from_slice(&count.to_le_bytes());
    sector[SALT_OFFSET..SALT_OFFSET + SALT_LEN].copy_from_slice(salt);
    if let Some(v) = verifier {
        sector[VERIFIER_OFFSET..VERIFIER_OFFSET + VERIFIER_LEN].copy_from_slice(v);
    }
    let tag = integrity_of(&sector);
    sector[INTEGRITY_OFFSET..INTEGRITY_OFFSET + 32].copy_from_slice(&tag);
    sector
}

/// Load the device secrets from the preamble, provisioning a fresh random
/// salt when the header is absent or corrupt (#449).
///
/// `dev` is the block view over the preamble region (a
/// `PartitionBlockDevice` carved at the userdata partition head — #603);
/// `random` fills the salt on a provisioning write
/// (`csprng::kernel_random_bytes` in production, an injected stream in
/// tests).
///
/// # Errors
///
/// Returns [`BlockError`] only when a REQUIRED block I/O fails — the read
/// probe, or the provisioning write. A corrupt header is not an error: it
/// is the re-provision signal.
pub(crate) fn load_or_provision<D: BlockDevice>(
    dev: &mut D,
    random: impl FnOnce(&mut [u8; SALT_LEN]),
) -> Result<DeviceSecrets, BlockError> {
    let mut sector = [0u8; SECTOR_SIZE];
    dev.read_sectors(0, 1, &mut sector)?;
    if let Some((salt, boot_verifier)) = parse(&sector) {
        return Ok(DeviceSecrets {
            salt,
            boot_verifier,
        });
    }

    let mut salt = [0u8; SALT_LEN];
    random(&mut salt);
    let rendered = render(&salt, None);
    dev.write_sectors(0, 1, &rendered)?;
    Ok(DeviceSecrets {
        salt,
        boot_verifier: None,
    })
}

/// Read-only load: parse the preamble WITHOUT provisioning (#446).
///
/// The boot path probes the preamble before the trust gate is evaluated
/// (the mount plan needs the fail-closed signal early), and a blind
/// re-provision there would clobber a valid header after a transient
/// fault — so this entry point never writes. `Ok(None)` means absent or
/// corrupt (a first-boot candidate); `Err` means the read itself failed.
///
/// # Errors
///
/// Returns [`BlockError`] when the sector read fails.
pub(crate) fn load<D: BlockDevice>(dev: &mut D) -> Result<Option<DeviceSecrets>, BlockError> {
    let mut sector = [0u8; SECTOR_SIZE];
    dev.read_sectors(0, 1, &mut sector)?;
    Ok(parse(&sector).map(|(salt, boot_verifier)| DeviceSecrets {
        salt,
        boot_verifier,
    }))
}

/// Store the boot passphrase verifier alongside the existing salt (#446).
///
/// First-boot setup calls this after the user enters and confirms a new
/// passphrase. `verifier` must be `key_manager::derive_boot_verifier`
/// output — never the passphrase and never a raw hash of it (see the
/// module doc for the no-fast-oracle argument). `salt` is the in-memory
/// salt from [`load_or_provision`]; the sector is re-rendered whole, so
/// the single-sector write remains the atomicity unit — a torn write
/// reads back as a corrupt header and re-provisions, never as a
/// half-updated verifier.
///
/// # Errors
///
/// Returns [`BlockError`] when the write fails.
pub(crate) fn store_boot_verifier<D: BlockDevice>(
    dev: &mut D,
    salt: &[u8; SALT_LEN],
    verifier: &[u8; VERIFIER_LEN],
) -> Result<DeviceSecrets, BlockError> {
    let rendered = render(salt, Some(verifier));
    dev.write_sectors(0, 1, &rendered)?;
    Ok(DeviceSecrets {
        salt: *salt,
        boot_verifier: Some(*verifier),
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::MemBlockDevice;

    /// Deterministic distinct random streams per test device.
    fn stream(seed: u8) -> impl FnOnce(&mut [u8; SALT_LEN]) {
        move |buf: &mut [u8; SALT_LEN]| {
            for (i, b) in buf.iter_mut().enumerate() {
                *b = seed.wrapping_add(i as u8);
            }
        }
    }

    #[test]
    fn blank_device_provisions_a_fresh_salt() {
        let mut dev = MemBlockDevice::new(1).expect("device");
        let secrets = load_or_provision(&mut dev, stream(0xA0)).expect("provision");
        assert_ne!(
            secrets.salt, [0u8; SALT_LEN],
            "salt must be random, not zero"
        );

        // The header on disk must be well-formed and parse back.
        let mut sector = [0u8; SECTOR_SIZE];
        dev.read_sectors(0, 1, &mut sector).expect("read back");
        assert_eq!(sector[..8], MAGIC, "magic written");
        assert_eq!(
            parse(&sector),
            Some((secrets.salt, None)),
            "header parses to the provisioned salt, no verifier yet"
        );
        assert_eq!(
            secrets.boot_verifier, None,
            "fresh provision has no verifier"
        );
    }

    #[test]
    fn second_boot_reads_back_the_same_salt() {
        let mut dev = MemBlockDevice::new(1).expect("device");
        let first = load_or_provision(&mut dev, stream(0xA0)).expect("provision");
        // A second call must NOT re-provision: the injected stream differs,
        // so any re-provision would change the salt.
        let second = load_or_provision(&mut dev, stream(0xB0)).expect("load");
        assert_eq!(
            first.salt, second.salt,
            "persistence: same salt across boots"
        );
    }

    #[test]
    fn corrupt_header_reprovisions_with_a_new_salt() {
        let mut dev = MemBlockDevice::new(1).expect("device");
        let first = load_or_provision(&mut dev, stream(0xA0)).expect("provision");

        // Corrupt one payload byte on disk: the integrity tag must reject it.
        let mut sector = [0u8; SECTOR_SIZE];
        dev.read_sectors(0, 1, &mut sector).expect("read");
        sector[SALT_OFFSET] ^= 0xFF;
        dev.write_sectors(0, 1, &sector).expect("corrupt");
        assert_eq!(parse(&sector), None, "corrupt payload must fail integrity");

        let second = load_or_provision(&mut dev, stream(0xB0)).expect("re-provision");
        assert_ne!(
            first.salt, second.salt,
            "re-provision generates a fresh salt"
        );
    }

    #[test]
    fn two_devices_provision_different_salts() {
        let mut dev_a = MemBlockDevice::new(1).expect("device a");
        let mut dev_b = MemBlockDevice::new(1).expect("device b");
        let a = load_or_provision(&mut dev_a, stream(0xA0)).expect("provision a");
        let b = load_or_provision(&mut dev_b, stream(0xB0)).expect("provision b");
        assert_ne!(
            a.salt, b.salt,
            "per-device salts must differ (#449 done-when)"
        );
    }

    /// A verifier byte pattern that is definitely not all-zero.
    fn sample_verifier() -> [u8; VERIFIER_LEN] {
        let mut v = [0u8; VERIFIER_LEN];
        for (i, b) in v.iter_mut().enumerate() {
            *b = 0x40u8.wrapping_add(i as u8);
        }
        v
    }

    #[test]
    fn stored_verifier_reads_back_with_the_salt_unchanged() {
        let mut dev = MemBlockDevice::new(1).expect("device");
        let first = load_or_provision(&mut dev, stream(0xA0)).expect("provision");
        let verifier = sample_verifier();
        let stored = store_boot_verifier(&mut dev, &first.salt, &verifier).expect("store verifier");
        assert_eq!(stored.boot_verifier, Some(verifier));
        assert_eq!(stored.salt, first.salt, "store preserves the salt");

        // A later boot loads both slots; the differing stream proves no
        // re-provision happened.
        let loaded = load_or_provision(&mut dev, stream(0xB0)).expect("load");
        assert_eq!(loaded.salt, first.salt, "salt stable across store+load");
        assert_eq!(loaded.boot_verifier, Some(verifier), "verifier persists");

        // The on-disk header declares two slots.
        let mut sector = [0u8; SECTOR_SIZE];
        dev.read_sectors(0, 1, &mut sector).expect("read back");
        assert_eq!(
            u32::from_le_bytes(
                sector[SLOT_COUNT_OFFSET..SLOT_COUNT_OFFSET + 4]
                    .try_into()
                    .unwrap_or_else(|_| unreachable!("4-byte slice"))
            ),
            2,
            "slot count 2 on disk"
        );
    }

    #[test]
    fn all_zero_verifier_is_rejected() {
        // A structurally valid, correctly tagged sector carrying a zero
        // verifier must not parse — the zero guard, not the integrity tag,
        // is what rejects it here.
        let salt = [0x11u8; SALT_LEN];
        let sector = render(&salt, Some(&[0u8; VERIFIER_LEN]));
        assert_eq!(parse(&sector), None, "zero verifier is never legitimate");
    }

    #[test]
    fn load_is_read_only_and_never_provisions() {
        // A blank device: load reports None and writes NOTHING — the
        // provisioning write is reserved for first-boot setup completion.
        let mut dev = MemBlockDevice::new(1).expect("device");
        let loaded = load(&mut dev).expect("load");
        assert!(loaded.is_none(), "blank preamble loads as None");
        let mut sector = [0xAAu8; SECTOR_SIZE];
        dev.read_sectors(0, 1, &mut sector).expect("read back");
        assert!(
            sector.iter().all(|&b| b == 0),
            "load must not write to the sector"
        );
    }

    #[test]
    fn load_reads_back_a_stored_verifier() {
        let mut dev = MemBlockDevice::new(1).expect("device");
        let first = load_or_provision(&mut dev, stream(0xA0)).expect("provision");
        let verifier = sample_verifier();
        store_boot_verifier(&mut dev, &first.salt, &verifier).expect("store");
        let loaded = load(&mut dev).expect("load").unwrap_or_else(|| {
            unreachable!("a stored preamble parses");
        });
        assert_eq!(loaded.salt, first.salt);
        assert_eq!(loaded.boot_verifier, Some(verifier));
    }

    #[test]
    fn tampered_verifier_fails_integrity_and_reprovisions() {
        let mut dev = MemBlockDevice::new(1).expect("device");
        let first = load_or_provision(&mut dev, stream(0xA0)).expect("provision");
        let verifier = sample_verifier();
        store_boot_verifier(&mut dev, &first.salt, &verifier).expect("store");

        let mut sector = [0u8; SECTOR_SIZE];
        dev.read_sectors(0, 1, &mut sector).expect("read");
        sector[VERIFIER_OFFSET] ^= 0xFF;
        dev.write_sectors(0, 1, &sector).expect("corrupt");
        assert_eq!(parse(&sector), None, "tampered verifier fails the tag");

        // Re-provision yields a fresh salt and no verifier (the device
        // returns to the first-boot setup path — never a half-valid state).
        let second = load_or_provision(&mut dev, stream(0xC0)).expect("re-provision");
        assert_ne!(second.salt, first.salt, "re-provision rerolls the salt");
        assert_eq!(second.boot_verifier, None);
    }
}
