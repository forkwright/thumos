//! GPT (GUID Partition Table) parser — locate a partition by name (#467).
//!
//! The boot-verify gate reads the `boot` partition by NAME from the GPT,
//! never a hardcoded sector offset (derive-over-declare): the partition's
//! location is derived from the device's own table. The parser validates
//! the GPT signature, revision shape, header CRC32, and entries CRC32 —
//! a corrupt table is an explicit error, never a misparse into wrong LBAs.
//!
//! Host-testable: parsing runs over any [`BlockDevice`] (the RAM double in
//! tests, the eMMC partition view on hardware).

use crate::block::{BlockDevice, BlockError, SECTOR_SIZE};

/// GPT errors: every failure is explicit (#467's fail-closed invariant
/// relies on none of these ever collapsing into "no boot medium").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
#[non_exhaustive]
pub(crate) enum GptError {
    /// The GPT signature "EFI PART" is missing.
    BadSignature,
    /// The header CRC32 does not match.
    HeaderCrcMismatch,
    /// The partition-entries CRC32 does not match.
    EntriesCrcMismatch,
    /// A structural field is outside sane bounds (entry size, count).
    Malformed,
    /// No entry with the requested name.
    NotFound,
    /// A block read failed.
    Io,
}

impl core::fmt::Display for GptError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadSignature => f.write_str("GPT signature missing"),
            Self::HeaderCrcMismatch => f.write_str("GPT header CRC mismatch"),
            Self::EntriesCrcMismatch => f.write_str("GPT entries CRC mismatch"),
            Self::Malformed => f.write_str("GPT malformed structure"),
            Self::NotFound => f.write_str("GPT partition not found"),
            Self::Io => f.write_str("GPT block I/O error"),
        }
    }
}

impl From<BlockError> for GptError {
    fn from(_: BlockError) -> Self {
        Self::Io
    }
}

/// A located partition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub(crate) struct PartitionInfo {
    /// First LBA of the partition.
    pub(crate) first_lba: u64,
    /// Last LBA (inclusive).
    pub(crate) last_lba: u64,
}

impl PartitionInfo {
    /// Partition length in sectors.
    pub(crate) const fn sectors(&self) -> u64 {
        self.last_lba - self.first_lba + 1
    }
}

/// CRC32 (IEEE 802.3, reflected, polynomial 0xEDB88320), tableless.
///
/// WHY a local impl: the kernel has no general CRC32 today (sbc.rs's is
/// codec-specific); the GPT header/entries CRCs are the integrity proof
/// that the parsed table is intact — security-relevant for locating the
/// boot partition.
pub(crate) fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// Maximum partition entries examined (the spec's default table is 128).
const MAX_ENTRIES: u32 = 128;

/// Read one sector as a fixed array.
fn read_sector(dev: &dyn BlockDevice, lba: u64) -> Result<[u8; SECTOR_SIZE], GptError> {
    let mut buf = [0u8; SECTOR_SIZE];
    dev.read_sectors(lba, 1, &mut buf)?;
    Ok(buf)
}

fn le32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

fn le64(buf: &[u8], off: usize) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&buf[off..off + 8]);
    u64::from_le_bytes(b)
}

/// Locate a partition by its GPT entry name (compared against the UTF-16LE
/// name field, e.g. "boot").
///
/// # Errors
///
/// [`GptError::NotFound`] when no entry carries the name; structural and
/// integrity failures as their explicit variants.
pub(crate) fn find_partition(dev: &dyn BlockDevice, name: &str) -> Result<PartitionInfo, GptError> {
    // LBA 1: the GPT header.
    let header = read_sector(dev, 1)?;
    if &header[..8] != b"EFI PART" {
        return Err(GptError::BadSignature);
    }
    let header_size = le32(&header, 12) as usize;
    if header_size < 92 || header_size > SECTOR_SIZE {
        return Err(GptError::Malformed);
    }
    let stored_header_crc = le32(&header, 16);
    // The header CRC covers the first header_size bytes with the CRC field
    // itself zeroed.
    let mut header_for_crc = header;
    header_for_crc[16..20].fill(0);
    if crc32(&header_for_crc[..header_size]) != stored_header_crc {
        return Err(GptError::HeaderCrcMismatch);
    }
    // GPT header tail (UEFI spec): PartitionEntryLBA u64 @72, entry count
    // u32 @80, entry size u32 @84, entries CRC32 @88.
    let entries_lba = le64(&header, 72);
    let entry_count = le32(&header, 80);
    let entry_size = le32(&header, 84);
    if entry_count == 0 || entry_count > MAX_ENTRIES {
        return Err(GptError::Malformed);
    }
    if entry_size < 128 || entry_size as usize > SECTOR_SIZE || entry_size % 8 != 0 {
        return Err(GptError::Malformed);
    }
    let stored_entries_crc = le32(&header, 88);
    let entries_bytes = entry_count as u64 * u64::from(entry_size);
    let entries_sectors = entries_bytes.div_ceil(SECTOR_SIZE as u64);
    if entries_sectors > 32 {
        return Err(GptError::Malformed);
    }

    // Read + CRC the whole entries table before walking it.
    let mut table = [0u8; 32 * SECTOR_SIZE];
    dev.read_sectors(
        entries_lba,
        entries_sectors as u32,
        &mut table[..(entries_sectors as usize * SECTOR_SIZE)],
    )?;
    if crc32(&table[..entries_bytes as usize]) != stored_entries_crc {
        return Err(GptError::EntriesCrcMismatch);
    }

    // The requested name as UTF-16LE bytes.
    let mut name_utf16 = [0u8; 72];
    if name.len() > 36 {
        return Err(GptError::NotFound);
    }
    for (i, b) in name.bytes().enumerate() {
        name_utf16[i * 2] = b;
    }

    for i in 0..entry_count as usize {
        let base = i * entry_size as usize;
        let entry = &table[base..base + entry_size as usize];
        // A zero type GUID marks an unused entry.
        if entry[..16].iter().all(|&b| b == 0) {
            continue;
        }
        if entry[56..56 + 72] == name_utf16 {
            return Ok(PartitionInfo {
                first_lba: le64(entry, 32),
                last_lba: le64(entry, 40),
            });
        }
    }
    Err(GptError::NotFound)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::MemBlockDevice;
    use alloc::vec;

    /// CRC32 known answer: IEEE check value for "123456789".
    #[test]
    fn crc32_known_answer() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b""), 0);
    }

    /// Build a synthetic GPT device: protective LBA0 zeroed, header at LBA1,
    /// entries at LBA2, with real CRCs.
    fn gpt_device(entries: &[(&str, u64, u64)]) -> MemBlockDevice {
        let entry_size = 128usize;
        let entry_count = 128u32;
        let entries_bytes = entry_count as usize * entry_size; // 16 KiB
        let total_sectors = 2 + entries_bytes / SECTOR_SIZE + 512;
        let mut dev = MemBlockDevice::new(total_sectors as u64).expect("device");

        // Entries table.
        let mut table = vec![0u8; entries_bytes];
        for (i, (name, first, last)) in entries.iter().enumerate() {
            let base = i * entry_size;
            table[base] = 0xAF; // non-zero type GUID (contents irrelevant to the parser)
            table[base + 32..base + 40].copy_from_slice(&first.to_le_bytes());
            table[base + 40..base + 48].copy_from_slice(&last.to_le_bytes());
            for (j, b) in name.bytes().enumerate() {
                table[base + 56 + j * 2] = b;
            }
        }
        let entries_crc = crc32(&table);
        dev.write_sectors(2, (entries_bytes / SECTOR_SIZE) as u32, &table)
            .expect("write entries");

        // Header.
        let mut header = [0u8; SECTOR_SIZE];
        header[..8].copy_from_slice(b"EFI PART");
        header[12..16].copy_from_slice(&92u32.to_le_bytes()); // header size
        header[72..80].copy_from_slice(&2u64.to_le_bytes()); // entries LBA (u64 @72)
        header[80..84].copy_from_slice(&entry_count.to_le_bytes()); // count (u32 @80)
        header[84..88].copy_from_slice(&(entry_size as u32).to_le_bytes()); // entry size (@84)
        header[88..92].copy_from_slice(&entries_crc.to_le_bytes()); // entries CRC (@88)
        let header_crc = crc32(&header[..92]);
        header[16..20].copy_from_slice(&header_crc.to_le_bytes());
        dev.write_sectors(1, 1, &header).expect("write header");
        dev
    }

    #[test]
    fn finds_boot_partition_by_name() {
        let dev = gpt_device(&[("boot", 2048, 4095), ("userdata", 0x50C000, 0xB0BFDF)]);
        let boot = find_partition(&dev, "boot").expect("boot must be found");
        assert_eq!(boot.first_lba, 2048);
        assert_eq!(boot.last_lba, 4095);
        assert_eq!(boot.sectors(), 2048);
    }

    #[test]
    fn missing_partition_is_not_found() {
        let dev = gpt_device(&[("boot", 2048, 4095)]);
        assert_eq!(find_partition(&dev, "vendor"), Err(GptError::NotFound));
    }

    #[test]
    fn bad_signature_rejects() {
        let mut dev = gpt_device(&[("boot", 2048, 4095)]);
        let mut hdr = [0u8; SECTOR_SIZE];
        dev.read_sectors(1, 1, &mut hdr).expect("read");
        hdr[0] = b'X';
        dev.write_sectors(1, 1, &hdr).expect("write");
        assert_eq!(find_partition(&dev, "boot"), Err(GptError::BadSignature));
    }

    #[test]
    fn corrupt_header_crc_rejects() {
        let mut dev = gpt_device(&[("boot", 2048, 4095)]);
        let mut hdr = [0u8; SECTOR_SIZE];
        dev.read_sectors(1, 1, &mut hdr).expect("read");
        hdr[76] ^= 0x01; // flip an entry-count bit; header CRC now stale
        dev.write_sectors(1, 1, &hdr).expect("write");
        assert_eq!(
            find_partition(&dev, "boot"),
            Err(GptError::HeaderCrcMismatch)
        );
    }

    #[test]
    fn corrupt_entries_crc_rejects() {
        let mut dev = gpt_device(&[("boot", 2048, 4095)]);
        let mut entry = [0u8; SECTOR_SIZE];
        dev.read_sectors(2, 1, &mut entry).expect("read");
        entry[60] ^= 0x01; // corrupt the name region; entries CRC now stale
        dev.write_sectors(2, 1, &entry).expect("write");
        assert_eq!(
            find_partition(&dev, "boot"),
            Err(GptError::EntriesCrcMismatch)
        );
    }
}
