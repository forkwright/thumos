//! On-disk secrets preamble — the LUKS-header analogue (#449).
//!
//! A fixed region at the head of the userdata partition, PLAINTEXT by
//! design (readable before any passphrase-derived key exists), holding
//! typed slots. A slot payload is either public by construction — the
//! PBKDF2 device salt resists precomputation by being unique per device,
//! not by being hidden — or sealed under the passphrase-derived primary
//! key (reserved kinds; the seal lands with the boot-time passphrase
//! loop, kinit Step 8d).
//!
//! # Layout (one 512-byte sector)
//!
//! ```text
//! [0..8)    magic "THSECR\0\0"
//! [8..12)   format version, u32 LE (= 1)
//! [12..16)  slot count, u32 LE (= 1 today)
//! [16..48)  integrity tag: SHA-256 of the sector with these 32 bytes zeroed
//! [48..80)  slot 1 payload: the device salt (32 bytes, plaintext)
//! [80..512) zero (future slots)
//! ```
//!
//! Slot kinds: 1 = device salt (populated today); 2 = BT IRK (reserved,
//! sealed — #455 stage 2); 3 = vault PIN verifier (reserved, sealed —
//! the security-mode PIN store, whose `PIN_PBKDF2_SALT` is the same
//! fixed-salt defect class as #449).
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

/// The per-device secrets this boot derived from the preamble.
pub(crate) struct DeviceSecrets {
    /// The PBKDF2 device salt: random at provisioning, plaintext on disk,
    /// stable across boots.
    pub(crate) salt: [u8; SALT_LEN],
}

/// Compute the integrity tag over a sector image (tag field zeroed).
fn integrity_of(sector: &[u8; SECTOR_SIZE]) -> [u8; 32] {
    let mut copy = *sector;
    copy[INTEGRITY_OFFSET..INTEGRITY_OFFSET + 32].fill(0);
    crate::security::sha256(&copy)
}

/// Read the device salt from a sector image, or `None` if the header is
/// absent (bad magic/version) or corrupt (integrity mismatch).
fn parse(sector: &[u8; SECTOR_SIZE]) -> Option<[u8; SALT_LEN]> {
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
    if count != 1 {
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
    Some(salt)
}

/// Render a header sector around `salt`.
fn render(salt: &[u8; SALT_LEN]) -> [u8; SECTOR_SIZE] {
    let mut sector = [0u8; SECTOR_SIZE];
    sector[..8].copy_from_slice(&MAGIC);
    sector[VERSION_OFFSET..VERSION_OFFSET + 4].copy_from_slice(&VERSION.to_le_bytes());
    sector[SLOT_COUNT_OFFSET..SLOT_COUNT_OFFSET + 4].copy_from_slice(&1u32.to_le_bytes());
    sector[SALT_OFFSET..SALT_OFFSET + SALT_LEN].copy_from_slice(salt);
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
    if let Some(salt) = parse(&sector) {
        return Ok(DeviceSecrets { salt });
    }

    let mut salt = [0u8; SALT_LEN];
    random(&mut salt);
    let rendered = render(&salt);
    dev.write_sectors(0, 1, &rendered)?;
    Ok(DeviceSecrets { salt })
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
            Some(secrets.salt),
            "header parses to the provisioned salt"
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
}
