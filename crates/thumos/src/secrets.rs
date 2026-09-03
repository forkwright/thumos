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
//! [8..12)   format version, u32 LE (1 or 2 — see below)
//! [12..16)  slot count, u32 LE
//! [16..48)  integrity tag: SHA-256 of the sector with these 32 bytes zeroed
//! [48..80)  slot 1 payload: the device salt (32 bytes, plaintext)
//! [80..112) slot 2 payload: boot passphrase verifier (32 bytes, plaintext)
//! [112..128) slot 5 payload: master-KDF record (v2 only, see below)
//! [128..512) zero (future slots)
//! ```
//!
//! # Format versions (#914)
//!
//! **v1** carries no KDF record, and a v1 device's master key is derived with
//! [`V1_KDF`] — PBKDF2-HMAC-SHA256 at 100,000 iterations. That is not a
//! default this code falls back to; it is what v1 *means*, because it is the
//! only thing every v1 device was ever written with. Stating it here and
//! testing it is the difference between a defined format and an invariant that
//! happens to hold because nobody has edited a constant.
//!
//! **v2** carries the KDF and its parameters in slot 5, so the cost can be
//! raised on new devices without making every existing partition unreadable.
//! The master key IS the derivation output: change the parameters for a
//! provisioned device and its data is gone. A record is what makes the
//! difference between a migration and a brick.
//!
//! ```text
//! [112..116) KDF id, u32 LE: 1 = PBKDF2-HMAC-SHA256, 2 = Argon2id
//! [116..120) param 0, u32 LE: PBKDF2 iterations   | Argon2id m_cost (KiB)
//! [120..124) param 1, u32 LE: 0                   | Argon2id t_cost
//! [124..128) param 2, u32 LE: 0                   | Argon2id p_cost
//! ```
//!
//! Slot counts are version-specific because the KDF record is mandatory in v2:
//! v1 accepts 1 (salt) or 2 (salt + verifier); v2 accepts 2 (salt + KDF) or 3
//! (salt + KDF + verifier).
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
//! primary is PBKDF2-HMAC-SHA256(passphrase, salt, `100_000`), so a disk
//! image buys an attacker exactly the same per-guess cost as attacking
//! the encrypted payload itself (and NEVER a raw SHA-256(passphrase)
//! fast-path). It carries no entropy of its own beyond the passphrase.
//!
//! Two read entry points, deliberately different fail modes (#621):
//! [`load_or_provision`] treats a missing OR corrupt header alike and
//! (re)provisions a fresh random salt over either — the whole header fits
//! one sector, so eMMC single-sector write atomicity bounds the torn-write
//! window to "old salt or new salt", and the integrity tag detects the
//! torn half. [`load`] is read-only and must NOT collapse that
//! distinction: the boot path (kinit) needs "never written" (a legitimate
//! first-boot candidate) kept apart from "written, then corrupted" (a
//! provisioned device whose only salt copy a re-provision would destroy,
//! or whose ciphertext a fallback plain-mount-and-format would destroy) —
//! see [`PreambleStatus`] and `kinit_plan::PreambleLoad::Corrupt`.

use crate::block::{BlockDevice, BlockError, SECTOR_SIZE};

/// Header magic: "THSECR\0\0".
pub(crate) const MAGIC: [u8; 8] = *b"THSECR\0\0";

/// Preamble format version written by every new provisioning (#914).
pub(crate) const VERSION: u32 = 2;

/// The oldest format version this kernel still reads.
const VERSION_V1: u32 = 1;

/// What a v1 preamble means (#914).
///
/// v1 stored no KDF record, so every v1 device's master key was derived with
/// exactly this. Defining it as a constant rather than reaching for
/// `PBKDF2_ITERATIONS` is deliberate: that constant is a *current policy*
/// value and may be raised, while this is a *historical fact* about bytes
/// already on devices. If the two were one symbol, raising policy would
/// silently redefine what every existing device's key is, and the partition
/// would stop opening.
pub(crate) const V1_KDF: crate::security::PinKdf = crate::security::PinKdf::Pbkdf2Sha256 {
    iterations: 100_000,
};

/// The KDF every new provisioning writes into its v2 record (#914).
///
/// Deliberately still PBKDF2 at the v1 cost, so this change is structural: no
/// device's key moves, and nothing about boot latency changes. What it buys is
/// that the cost is now a value in a record rather than a constant compiled
/// into the reader, so raising it is a migration instead of a brick.
///
/// Raising it to Argon2id — the construction #272 chose for every other secret
/// in this kernel — is now a one-line edit here. It is not made here because
/// the master key is derived on the live boot path, and the number that
/// decision needs is how long Argon2id takes on the M7, which cannot be
/// measured from a host or from QEMU. #272 shipped Argon2id for the secret
/// verifiers without that number because none of them has a production caller
/// yet; this one does.
pub(crate) const MASTER_KDF: crate::security::PinKdf = V1_KDF;

/// Byte offset of the v2 master-KDF record.
const KDF_OFFSET: usize = 112;

/// Bytes the KDF record occupies: id + three parameters.
const KDF_LEN: usize = 16;

// INVARIANT: the KDF record fits the sector and starts after the verifier
// slot. Both are fixed today; asserting it means a future slot added at the
// wrong offset fails to build rather than silently overlapping a field whose
// corruption reads as a wrong passphrase.
const _: () = assert!(KDF_OFFSET >= VERIFIER_OFFSET + VERIFIER_LEN);
const _: () = assert!(KDF_OFFSET + KDF_LEN <= SECTOR_SIZE);

/// On-disk KDF identifiers. Stable: these name bytes already written.
const KDF_ID_PBKDF2_SHA256: u32 = 1;
const KDF_ID_ARGON2ID: u32 = 2;

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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DeviceSecrets {
    /// The PBKDF2 device salt: random at provisioning, plaintext on disk,
    /// stable across boots.
    pub(crate) salt: [u8; SALT_LEN],
    /// The boot passphrase verifier (`HKDF(primary, "thumos-verify-v1")`),
    /// when first-boot setup has stored one. `None` means the device has
    /// never set a boot passphrase — the first-boot setup path.
    pub(crate) boot_verifier: Option<[u8; VERIFIER_LEN]>,
    /// The KDF that produced — and must reproduce — this device's master key
    /// (#914). Read from slot 5 on a v2 header, and [`V1_KDF`] on a v1 one.
    pub(crate) kdf: crate::security::PinKdf,
}

/// Outcome of parsing a preamble sector image (#621).
///
/// `Absent` and `Corrupt` must never be conflated: only `Absent` is a
/// legitimate first-boot candidate. `Corrupt` means a device WAS
/// provisioned and the sector no longer validates — the caller must treat
/// it the same as a read failure (unknown state = locked), never the same
/// as `Absent` (which would re-provision over, or plain-mount-and-format,
/// a payload that is still encrypted under the lost salt).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PreambleStatus {
    /// No preamble magic: the sector has never been written by this
    /// scheme (a factory-blank device).
    Absent,
    /// The preamble magic is present but the sector fails version,
    /// slot-count, integrity-tag, or zero-payload validation.
    Corrupt,
    /// A structurally valid, integrity-checked header.
    Valid(DeviceSecrets),
}

/// Compute the integrity tag over a sector image (tag field zeroed).
fn integrity_of(sector: &[u8; SECTOR_SIZE]) -> [u8; 32] {
    let mut copy = *sector;
    copy[INTEGRITY_OFFSET..INTEGRITY_OFFSET + 32].fill(0);
    crate::security::sha256(&copy)
}

/// Classify a sector image (#621): [`PreambleStatus::Absent`] when no
/// preamble was ever written here (bad magic — the sole "never
/// provisioned" signal); [`PreambleStatus::Corrupt`] when the magic is
/// present but version, slot count, integrity tag, or a zero-payload
/// guard fails (a provisioned device whose header is now unusable);
/// otherwise [`PreambleStatus::Valid`] with the salt plus the boot
/// verifier when the header carries one (slot count 2). Magic presence is
/// the ONLY line between `Absent` and `Corrupt` — every check after it
/// means "this was a preamble" and must not fall back to `Absent`.
fn parse(sector: &[u8; SECTOR_SIZE]) -> PreambleStatus {
    if sector[..8] != MAGIC {
        return PreambleStatus::Absent;
    }
    let mut version_bytes = [0u8; 4];
    version_bytes.copy_from_slice(&sector[VERSION_OFFSET..VERSION_OFFSET + 4]);
    let version = u32::from_le_bytes(version_bytes);
    if version != VERSION && version != VERSION_V1 {
        return PreambleStatus::Corrupt;
    }
    let mut count_bytes = [0u8; 4];
    count_bytes.copy_from_slice(&sector[SLOT_COUNT_OFFSET..SLOT_COUNT_OFFSET + 4]);
    let count = u32::from_le_bytes(count_bytes);
    // The KDF record is mandatory in v2, so the accepted counts differ by
    // version: a v2 header with a v1 count is missing the record entirely and
    // must not be read as though it were merely verifier-less.
    let accepted = if version == VERSION_V1 {
        count == 1 || count == 2
    } else {
        count == 2 || count == 3
    };
    if !accepted {
        return PreambleStatus::Corrupt;
    }
    if sector[INTEGRITY_OFFSET..INTEGRITY_OFFSET + 32] != integrity_of(sector) {
        return PreambleStatus::Corrupt;
    }
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&sector[SALT_OFFSET..SALT_OFFSET + SALT_LEN]);
    if salt.iter().all(|&b| b == 0) {
        // An all-zero salt is never legitimate: it would silently re-create
        // the shared-salt failure mode #449 exists to kill. Magic and
        // integrity both checked out, so this is corruption, not absence.
        return PreambleStatus::Corrupt;
    }
    let has_verifier = if version == VERSION_V1 {
        count == 2
    } else {
        count == 3
    };
    let boot_verifier = if has_verifier {
        let mut v = [0u8; VERIFIER_LEN];
        v.copy_from_slice(&sector[VERIFIER_OFFSET..VERIFIER_OFFSET + VERIFIER_LEN]);
        if v.iter().all(|&b| b == 0) {
            // An all-zero verifier is never legitimate: a zero slot would
            // turn a corrupt read into an empty-derivation oracle.
            return PreambleStatus::Corrupt;
        }
        Some(v)
    } else {
        None
    };
    let kdf = if version == VERSION_V1 {
        V1_KDF
    } else {
        match parse_kdf(sector) {
            Some(k) => k,
            // An unreadable KDF record on a v2 header is corruption, not a
            // reason to fall back to V1_KDF: falling back would derive a key
            // this device never used and report it as a wrong passphrase.
            None => return PreambleStatus::Corrupt,
        }
    };
    PreambleStatus::Valid(DeviceSecrets {
        salt,
        boot_verifier,
        kdf,
    })
}

/// Read the v2 master-KDF record, or `None` when it does not describe a KDF
/// this kernel implements.
fn parse_kdf(sector: &[u8; SECTOR_SIZE]) -> Option<crate::security::PinKdf> {
    let field = |i: usize| -> u32 {
        let at = KDF_OFFSET + i * 4;
        let mut b = [0u8; 4];
        b.copy_from_slice(&sector[at..at + 4]);
        u32::from_le_bytes(b)
    };
    match field(0) {
        KDF_ID_PBKDF2_SHA256 => {
            let iterations = field(1);
            // A zero work factor is not a weak KDF, it is no KDF; refusing it
            // keeps a corrupt record from becoming a fast oracle.
            (iterations > 0).then_some(crate::security::PinKdf::Pbkdf2Sha256 { iterations })
        }
        KDF_ID_ARGON2ID => {
            let (m_cost_kib, t_cost, p_cost) = (field(1), field(2), field(3));
            (m_cost_kib > 0 && t_cost > 0 && p_cost > 0).then_some(
                crate::security::PinKdf::Argon2id {
                    m_cost_kib,
                    t_cost,
                    p_cost,
                },
            )
        }
        _ => None,
    }
}

/// Write the v2 master-KDF record into `sector`.
fn render_kdf(sector: &mut [u8; SECTOR_SIZE], kdf: crate::security::PinKdf) {
    let mut put = |i: usize, v: u32| {
        let at = KDF_OFFSET + i * 4;
        sector[at..at + 4].copy_from_slice(&v.to_le_bytes());
    };
    match kdf {
        crate::security::PinKdf::Pbkdf2Sha256 { iterations } => {
            put(0, KDF_ID_PBKDF2_SHA256);
            put(1, iterations);
        }
        crate::security::PinKdf::Argon2id {
            m_cost_kib,
            t_cost,
            p_cost,
        } => {
            put(0, KDF_ID_ARGON2ID);
            put(1, m_cost_kib);
            put(2, t_cost);
            put(3, p_cost);
        }
    }
}

/// Render a header sector around `salt` and its v2 master-KDF record,
/// optionally carrying the boot verifier (slot count 3 when the verifier is
/// present, 2 otherwise -- v2 always carries the KDF record, so the count
/// never drops to the v1 1-or-2).
fn render(
    salt: &[u8; SALT_LEN],
    verifier: Option<&[u8; VERIFIER_LEN]>,
    kdf: crate::security::PinKdf,
) -> [u8; SECTOR_SIZE] {
    let mut sector = [0u8; SECTOR_SIZE];
    sector[..8].copy_from_slice(&MAGIC);
    sector[VERSION_OFFSET..VERSION_OFFSET + 4].copy_from_slice(&VERSION.to_le_bytes());
    // v2 always carries the KDF record, so the count starts at salt + KDF.
    let count: u32 = u32::from(verifier.is_some()) + 2;
    sector[SLOT_COUNT_OFFSET..SLOT_COUNT_OFFSET + 4].copy_from_slice(&count.to_le_bytes());
    sector[SALT_OFFSET..SALT_OFFSET + SALT_LEN].copy_from_slice(salt);
    if let Some(v) = verifier {
        sector[VERIFIER_OFFSET..VERIFIER_OFFSET + VERIFIER_LEN].copy_from_slice(v);
    }
    render_kdf(&mut sector, kdf);
    let tag = integrity_of(&sector);
    sector[INTEGRITY_OFFSET..INTEGRITY_OFFSET + 32].copy_from_slice(&tag);
    sector
}

/// Load the device secrets from the preamble, provisioning a fresh random
/// salt when the header is absent OR corrupt (#449).
///
/// WHY absent and corrupt are treated alike HERE (unlike [`load`], #621):
/// this entry point is never used on the early boot probe — it is a
/// blind provisioning helper, and its whole contract is "make the header
/// valid, no matter what state it started in". The boot path instead uses
/// the read-only [`load`], which keeps the two states apart so the caller
/// can lock instead of overwrite.
///
/// `dev` is the block view over the preamble region (a
/// `PartitionBlockDevice` carved at the userdata partition head — #603);
/// `random` fills the salt on a provisioning write
/// (`csprng::kernel_random_bytes` in production, an injected stream in
/// tests).
///
/// # Errors
///
/// Returns [`ProvisionError::Io`] only when a REQUIRED block I/O fails — the
/// read probe, or the provisioning write. A corrupt header is not an error: it
/// is the re-provision signal.
///
/// Returns [`ProvisionError::Entropy`] when `random` reports failure,
/// [`ProvisionError::ShortFill`] when it reports fewer than [`SALT_LEN`]
/// bytes, and [`ProvisionError::DegenerateSalt`] when it reports success and
/// leaves the salt all-zero. **No preamble is written on any of those paths**
/// (#842).
///
/// WHY `random` reports a byte count instead of simply filling the buffer: the
/// previous signature was infallible and returned nothing, so a closure that
/// wrote nothing at all was indistinguishable from one that succeeded — and
/// the all-zero salt it left behind was then persisted as this device's
/// permanent identity. A fallible source that must state how much it wrote
/// makes "did not fill it" a value this function can refuse rather than a
/// silence it cannot see.
pub(crate) fn load_or_provision<D: BlockDevice>(
    dev: &mut D,
    random: impl FnOnce(&mut [u8; SALT_LEN]) -> Result<usize, ()>,
) -> Result<DeviceSecrets, ProvisionError> {
    let mut sector = [0u8; SECTOR_SIZE];
    dev.read_sectors(0, 1, &mut sector)
        .map_err(ProvisionError::Io)?;
    if let PreambleStatus::Valid(secrets) = parse(&sector) {
        return Ok(secrets);
    }

    let mut salt = [0u8; SALT_LEN];
    let filled = random(&mut salt).map_err(|()| ProvisionError::Entropy)?;
    if filled != SALT_LEN {
        return Err(ProvisionError::ShortFill { filled });
    }
    // WHY all-zero is refused even when the source claims success: as a draw
    // from a real CSPRNG it is a 2^-256 event, and as a symptom it is what a
    // stuck or zero-filling source produces. Persisting it would fix this
    // device's salt at a value every other device can guess.
    if salt.iter().all(|&b| b == 0) {
        return Err(ProvisionError::DegenerateSalt);
    }

    let rendered = render(&salt, None, MASTER_KDF);
    dev.write_sectors(0, 1, &rendered)
        .map_err(ProvisionError::Io)?;
    Ok(DeviceSecrets {
        salt,
        boot_verifier: None,
        kdf: MASTER_KDF,
    })
}

/// Why provisioning a device salt could not complete (#842).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub(crate) enum ProvisionError {
    /// A required block read or write failed.
    Io(BlockError),
    /// The entropy source reported failure.
    Entropy,
    /// The entropy source succeeded but filled fewer bytes than the salt
    /// needs. Distinct from [`Self::Entropy`]: the source believed it had
    /// worked.
    ShortFill {
        /// How many bytes it reported writing.
        filled: usize,
    },
    /// The entropy source reported a full fill and left the salt all-zero.
    DegenerateSalt,
}

/// Read-only load: parse the preamble WITHOUT provisioning (#446).
///
/// The boot path probes the preamble before the trust gate is evaluated
/// (the mount plan needs the fail-closed signal early), and a blind
/// re-provision there would clobber a valid header after a transient
/// fault — so this entry point never writes.
///
/// `Ok(PreambleStatus::Absent)` means no preamble was ever written (a
/// first-boot candidate). `Ok(PreambleStatus::Corrupt)` means one WAS
/// written and no longer validates — the caller must route this the same
/// as a read failure, NEVER the same as `Absent` (#621): collapsing the
/// two turns a bit flip into first-boot re-provisioning (destroys the
/// salt) or a plain-mount-and-format (destroys the ciphertext). `Err`
/// means the sector read itself failed.
///
/// # Errors
///
/// Returns [`BlockError`] when the sector read fails.
pub(crate) fn load<D: BlockDevice>(dev: &mut D) -> Result<PreambleStatus, BlockError> {
    let mut sector = [0u8; SECTOR_SIZE];
    dev.read_sectors(0, 1, &mut sector)?;
    Ok(parse(&sector))
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
    kdf: crate::security::PinKdf,
) -> Result<DeviceSecrets, BlockError> {
    // WHY the caller passes the KDF rather than this reaching for MASTER_KDF:
    // storing a verifier does not re-derive the master key, so the record must
    // keep naming whatever produced the key already in use. Substituting the
    // current policy here would rewrite a provisioned device's KDF without
    // rewriting its key, and the next boot would refuse a correct passphrase.
    let rendered = render(salt, Some(verifier), kdf);
    dev.write_sectors(0, 1, &rendered)?;
    Ok(DeviceSecrets {
        salt: *salt,
        boot_verifier: Some(*verifier),
        kdf,
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
    /// A device whose sector 0 is blank, so `load_or_provision` takes the
    /// provisioning branch.
    fn blank_device() -> crate::block::MemBlockDevice {
        crate::block::MemBlockDevice::new(8).expect("test device")
    }

    #[test]
    fn provisioning_refuses_an_entropy_source_that_reports_failure() {
        // #842: the source failing must not persist anything at all.
        let mut dev = blank_device();
        let result = load_or_provision(&mut dev, |_| Err(()));
        assert_eq!(result, Err(ProvisionError::Entropy));
        assert!(
            matches!(load(&mut dev), Ok(PreambleStatus::Absent)),
            "a refused provisioning must leave sector 0 unwritten"
        );
    }

    #[test]
    fn provisioning_refuses_a_source_that_writes_nothing() {
        // The original defect: an infallible closure that did nothing left the
        // salt all-zero and that zero was persisted as the device identity.
        // Reporting a byte count is what makes "did nothing" visible.
        let mut dev = blank_device();
        let result = load_or_provision(&mut dev, |_| Ok(0));
        assert_eq!(result, Err(ProvisionError::ShortFill { filled: 0 }));
        assert!(
            matches!(load(&mut dev), Ok(PreambleStatus::Absent)),
            "a refused provisioning must leave sector 0 unwritten"
        );
    }

    #[test]
    fn provisioning_refuses_a_partial_fill() {
        let mut dev = blank_device();
        let result = load_or_provision(&mut dev, |buf| {
            buf[0] = 0xAB;
            Ok(1)
        });
        assert_eq!(result, Err(ProvisionError::ShortFill { filled: 1 }));
    }

    #[test]
    fn provisioning_refuses_an_all_zero_salt_reported_as_a_full_fill() {
        // A source can lie by omission: claim it filled the buffer while
        // leaving it zero. As a real draw that is a 2^-256 event; as a symptom
        // it is a stuck source, and persisting it fixes this device's salt at
        // a value every other device can guess.
        let mut dev = blank_device();
        let result = load_or_provision(&mut dev, |_| Ok(SALT_LEN));
        assert_eq!(result, Err(ProvisionError::DegenerateSalt));
        assert!(
            matches!(load(&mut dev), Ok(PreambleStatus::Absent)),
            "a refused provisioning must leave sector 0 unwritten"
        );
    }

    fn stream(seed: u8) -> impl FnOnce(&mut [u8; SALT_LEN]) -> Result<usize, ()> {
        move |buf: &mut [u8; SALT_LEN]| {
            for (i, b) in buf.iter_mut().enumerate() {
                *b = seed.wrapping_add(i as u8);
            }
            Ok(SALT_LEN)
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
            PreambleStatus::Valid(DeviceSecrets {
                salt: secrets.salt,
                boot_verifier: None,
                kdf: MASTER_KDF,
            }),
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
        assert_eq!(
            parse(&sector),
            PreambleStatus::Corrupt,
            "corrupt payload (magic present, integrity fails) is Corrupt, never Absent (#621)"
        );

        // load_or_provision's OWN contract (unlike load's, see module doc)
        // is to re-provision over Corrupt just like Absent.
        let second = load_or_provision(&mut dev, stream(0xB0)).expect("re-provision");
        assert_ne!(
            first.salt, second.salt,
            "re-provision generates a fresh salt"
        );
    }

    #[test]
    fn load_distinguishes_corrupt_from_absent_and_never_reprovisions_either() {
        // The #621 regression scenario at the `load()` boundary kinit
        // actually calls: a genuinely blank device reports Absent...
        let mut blank = MemBlockDevice::new(1).expect("blank device");
        assert_eq!(
            load(&mut blank).expect("load"),
            PreambleStatus::Absent,
            "never-written sector is Absent"
        );

        // ...while a PROVISIONED device whose sector was then corrupted
        // (a bit flip outside the magic bytes -- the common case) must
        // report Corrupt, not collapse to the same Absent state.
        let mut provisioned = MemBlockDevice::new(1).expect("provisioned device");
        load_or_provision(&mut provisioned, stream(0xA0)).expect("provision");
        let mut sector = [0u8; SECTOR_SIZE];
        provisioned
            .read_sectors(0, 1, &mut sector)
            .expect("read back");
        sector[SALT_OFFSET] ^= 0xFF;
        provisioned
            .write_sectors(0, 1, &sector)
            .expect("corrupt on disk");

        let status = load(&mut provisioned).expect("load corrupt");
        assert_eq!(
            status,
            PreambleStatus::Corrupt,
            "a provisioned-then-corrupted sector must read as Corrupt, never Absent"
        );
        assert_ne!(
            status,
            PreambleStatus::Absent,
            "Corrupt and Absent must route differently -- #621's whole point"
        );

        // load() is read-only regardless of outcome: the sector on disk
        // is untouched by either call above.
        let mut after = [0u8; SECTOR_SIZE];
        provisioned
            .read_sectors(0, 1, &mut after)
            .expect("read after load");
        assert_eq!(after, sector, "load must never write, corrupt or not");
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

    /// A literal v1-format sector, built byte-for-byte from the documented
    /// layout rather than through [`render`], which only ever writes v2
    /// today. A specimen produced by calling this file's own writer would
    /// still pass even if the writer and the reader had drifted together --
    /// this one is independent of both, the way a real pre-#914 device on
    /// disk is.
    fn v1_sector(salt: [u8; SALT_LEN], verifier: Option<[u8; VERIFIER_LEN]>) -> [u8; SECTOR_SIZE] {
        let mut sector = [0u8; SECTOR_SIZE];
        sector[..8].copy_from_slice(b"THSECR\0\0");
        sector[VERSION_OFFSET..VERSION_OFFSET + 4].copy_from_slice(&1u32.to_le_bytes());
        let count: u32 = if verifier.is_some() { 2 } else { 1 };
        sector[SLOT_COUNT_OFFSET..SLOT_COUNT_OFFSET + 4].copy_from_slice(&count.to_le_bytes());
        sector[SALT_OFFSET..SALT_OFFSET + SALT_LEN].copy_from_slice(&salt);
        if let Some(v) = verifier {
            sector[VERIFIER_OFFSET..VERIFIER_OFFSET + VERIFIER_LEN].copy_from_slice(&v);
        }
        let tag = integrity_of(&sector);
        sector[INTEGRITY_OFFSET..INTEGRITY_OFFSET + 32].copy_from_slice(&tag);
        sector
    }

    #[test]
    fn v1_preamble_bytes_parse_under_v1_kdf() {
        // A real pre-#914 device wrote no KDF record and no slot 5 -- salt
        // only (slot count 1) before any passphrase was set, salt + verifier
        // (slot count 2) after. Both must still parse, and both must resolve
        // exactly [`V1_KDF`]: that is the whole backward-compatibility claim
        // this change makes, and until this test, nothing checked it against
        // bytes the current writer never produces.
        let salt = [0x77u8; SALT_LEN];

        let salt_only = v1_sector(salt, None);
        assert_eq!(
            parse(&salt_only),
            PreambleStatus::Valid(DeviceSecrets {
                salt,
                boot_verifier: None,
                kdf: V1_KDF,
            }),
            "a genuine v1 salt-only header (version 1, slot count 1) must parse and resolve V1_KDF"
        );

        let verifier = sample_verifier();
        let with_verifier = v1_sector(salt, Some(verifier));
        assert_eq!(
            parse(&with_verifier),
            PreambleStatus::Valid(DeviceSecrets {
                salt,
                boot_verifier: Some(verifier),
                kdf: V1_KDF,
            }),
            "a genuine fully-provisioned v1 header (version 1, slot count 2) must parse, verifier and all, and resolve V1_KDF"
        );
    }

    #[test]
    fn stored_verifier_reads_back_with_the_salt_unchanged() {
        let mut dev = MemBlockDevice::new(1).expect("device");
        let first = load_or_provision(&mut dev, stream(0xA0)).expect("provision");
        let verifier = sample_verifier();
        let stored = store_boot_verifier(&mut dev, &first.salt, &verifier, MASTER_KDF)
            .expect("store verifier");
        assert_eq!(stored.boot_verifier, Some(verifier));
        assert_eq!(stored.salt, first.salt, "store preserves the salt");

        // A later boot loads both slots; the differing stream proves no
        // re-provision happened.
        let loaded = load_or_provision(&mut dev, stream(0xB0)).expect("load");
        assert_eq!(loaded.salt, first.salt, "salt stable across store+load");
        assert_eq!(loaded.boot_verifier, Some(verifier), "verifier persists");

        // The on-disk header declares three slots: salt, KDF record, verifier.
        let mut sector = [0u8; SECTOR_SIZE];
        dev.read_sectors(0, 1, &mut sector).expect("read back");
        assert_eq!(
            u32::from_le_bytes(
                sector[SLOT_COUNT_OFFSET..SLOT_COUNT_OFFSET + 4]
                    .try_into()
                    .unwrap_or_else(|_| unreachable!("4-byte slice"))
            ),
            3,
            "slot count 3 on disk (salt + KDF + verifier)"
        );
    }

    #[test]
    fn all_zero_verifier_is_rejected() {
        // A structurally valid, correctly tagged sector carrying a zero
        // verifier must not parse — the zero guard, not the integrity tag,
        // is what rejects it here.
        let salt = [0x11u8; SALT_LEN];
        let sector = render(&salt, Some(&[0u8; VERIFIER_LEN]), MASTER_KDF);
        assert_eq!(
            parse(&sector),
            PreambleStatus::Corrupt,
            "zero verifier is never legitimate (magic + integrity pass, so this is corrupt, not absent)"
        );
    }

    #[test]
    fn load_is_read_only_and_never_provisions() {
        // A blank device: load reports Absent and writes NOTHING — the
        // provisioning write is reserved for first-boot setup completion.
        let mut dev = MemBlockDevice::new(1).expect("device");
        let loaded = load(&mut dev).expect("load");
        assert_eq!(
            loaded,
            PreambleStatus::Absent,
            "blank preamble loads as Absent"
        );
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
        store_boot_verifier(&mut dev, &first.salt, &verifier, MASTER_KDF).expect("store");
        let loaded = match load(&mut dev).expect("load") {
            PreambleStatus::Valid(secrets) => secrets,
            other => unreachable!("a stored preamble parses as Valid, got {other:?}"),
        };
        assert_eq!(loaded.salt, first.salt);
        assert_eq!(loaded.boot_verifier, Some(verifier));
    }

    #[test]
    fn tampered_verifier_fails_integrity_and_reprovisions() {
        let mut dev = MemBlockDevice::new(1).expect("device");
        let first = load_or_provision(&mut dev, stream(0xA0)).expect("provision");
        let verifier = sample_verifier();
        store_boot_verifier(&mut dev, &first.salt, &verifier, MASTER_KDF).expect("store");

        let mut sector = [0u8; SECTOR_SIZE];
        dev.read_sectors(0, 1, &mut sector).expect("read");
        sector[VERIFIER_OFFSET] ^= 0xFF;
        dev.write_sectors(0, 1, &sector).expect("corrupt");
        assert_eq!(
            parse(&sector),
            PreambleStatus::Corrupt,
            "tampered verifier fails the tag -- corrupt, not absent"
        );

        // Re-provision yields a fresh salt and no verifier (the device
        // returns to the first-boot setup path — never a half-valid state).
        let second = load_or_provision(&mut dev, stream(0xC0)).expect("re-provision");
        assert_ne!(second.salt, first.salt, "re-provision rerolls the salt");
        assert_eq!(second.boot_verifier, None);
    }
}
