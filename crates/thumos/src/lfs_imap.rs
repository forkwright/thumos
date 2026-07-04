//! Inode map for the log-structured filesystem.
//!
//! Maps inode numbers to their current on-disk block addresses. In a
//! log-structured filesystem, inodes are written to new locations on each
//! update, so the imap is the authoritative source for finding the latest
//! version of any inode.
//!
//! The imap is serialized as a simple count-prefixed array of `(u32, u64)`
//! pairs and stored in consecutive 4 KiB blocks on disk.

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::block::{BLOCK_SIZE, BlockDevice, BlockError};
use crate::cache::BlockCache;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors specific to LFS operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LfsError {
    /// A low-level block I/O error occurred.
    BlockIo(BlockError),
    /// The on-disk data is corrupt or has an invalid magic number.
    Corrupt,
    /// The filesystem has not been formatted or the superblock is invalid.
    InvalidSuperblock,
    /// No free segments available for allocation.
    NoFreeSegments,
    /// An inode was not found in the imap.
    InodeNotFound,
    /// A checkpoint's imap + segment-bitmap payload exceeds the slot's
    /// reserved capacity.
    CheckpointOverflow,
    /// No segment is eligible for compaction (every segment is free or is
    /// the writer's active segment) -- distinct from `NoFreeSegments`,
    /// which means the filesystem is out of free segments entirely
    /// (finding 5).
    NoCompactionCandidate,
}

impl core::fmt::Display for LfsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BlockIo(e) => write!(f, "block I/O error: {e}"),
            Self::Corrupt => write!(f, "filesystem data corrupt"),
            Self::InvalidSuperblock => write!(f, "invalid superblock"),
            Self::NoFreeSegments => write!(f, "no free segments"),
            Self::InodeNotFound => write!(f, "inode not found"),
            Self::CheckpointOverflow => {
                write!(f, "checkpoint payload exceeds reserved slot capacity")
            }
            Self::NoCompactionCandidate => write!(f, "no segment eligible for compaction"),
        }
    }
}

impl From<BlockError> for LfsError {
    fn from(e: BlockError) -> Self {
        Self::BlockIo(e)
    }
}

// ---------------------------------------------------------------------------
// LfsImap
// ---------------------------------------------------------------------------

/// Entry size in the serialized imap: 4 bytes inode_id + 8 bytes block_number.
const IMAP_ENTRY_SIZE: usize = 12;

/// Size of the count prefix in the serialized imap (u32).
const IMAP_HEADER_SIZE: usize = 4;

/// In-memory inode map: maps inode IDs to the block number where their
/// [`super::lfs::DiskInode`] is currently stored.
///
/// The map is backed by a `BTreeMap` for deterministic iteration order,
/// which simplifies serialization and testing.
pub(crate) struct LfsImap {
    /// Inode ID to block number mapping.
    map: BTreeMap<u32, u64>,
}

impl LfsImap {
    /// Create an empty inode map.
    pub(crate) fn new() -> Self {
        Self {
            map: BTreeMap::new(),
        }
    }

    /// Look up the block number for an inode.
    ///
    /// # Errors
    ///
    /// This method is infallible; returns `None` if the inode is not mapped.
    pub(crate) fn get(&self, inode_id: u32) -> Option<u64> {
        self.map.get(&inode_id).copied()
    }

    /// Insert or update a mapping from inode ID to block number.
    ///
    /// # Errors
    ///
    /// This method is infallible.
    pub(crate) fn insert(&mut self, inode_id: u32, block: u64) {
        self.map.insert(inode_id, block);
    }

    /// Remove an inode mapping.
    ///
    /// # Errors
    ///
    /// This method is infallible. Removing a non-existent inode is a no-op.
    pub(crate) fn remove(&mut self, inode_id: u32) {
        self.map.remove(&inode_id);
    }

    /// Return the number of inode mappings.
    pub(crate) fn len(&self) -> usize {
        self.map.len()
    }

    /// Return whether the imap is empty.
    pub(crate) fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Return an iterator over all `(inode_id, block_number)` pairs.
    ///
    /// Used by the compactor to scan which blocks are still live.
    pub(crate) fn iter(&self) -> impl Iterator<Item = (u32, u64)> + '_ {
        self.map.iter().map(|(&id, &block)| (id, block))
    }

    /// Serialize the imap to bytes.
    ///
    /// Format: `count: u32` followed by `count` entries of `(inode_id: u32,
    /// block_number: u64)`, all in little-endian byte order.
    ///
    /// # Errors
    ///
    /// This method is infallible.
    pub(crate) fn serialize(&self, buf: &mut Vec<u8>) {
        let count = self.map.len() as u32;
        buf.extend_from_slice(&count.to_le_bytes());

        for (&inode_id, &block) in &self.map {
            buf.extend_from_slice(&inode_id.to_le_bytes());
            buf.extend_from_slice(&block.to_le_bytes());
        }
    }

    /// Deserialize an imap from bytes.
    ///
    /// # Errors
    ///
    /// Returns [`LfsError::Corrupt`] if the buffer is too short or contains
    /// invalid data.
    #[must_use]
    pub(crate) fn deserialize(buf: &[u8]) -> Result<Self, LfsError> {
        if buf.len() < IMAP_HEADER_SIZE {
            return Err(LfsError::Corrupt);
        }

        let count =
            u32::from_le_bytes(buf[..4].try_into().map_err(|_| LfsError::Corrupt)?) as usize;

        // WHY: count is an attacker-controlled on-disk field; count *
        // IMAP_ENTRY_SIZE wraps on the 32-bit target for a crafted large
        // count, defeating this length guard and letting the entry-parse
        // loop below index past `buf` (#333). Checked arithmetic rejects
        // the overflowing case instead of silently wrapping.
        let expected_len = count
            .checked_mul(IMAP_ENTRY_SIZE)
            .and_then(|entries_len| entries_len.checked_add(IMAP_HEADER_SIZE))
            .ok_or(LfsError::Corrupt)?;
        if buf.len() < expected_len {
            return Err(LfsError::Corrupt);
        }

        let mut map = BTreeMap::new();
        let mut offset = IMAP_HEADER_SIZE;

        for _ in 0..count {
            let inode_id = u32::from_le_bytes(
                buf[offset..offset + 4]
                    .try_into()
                    .map_err(|_| LfsError::Corrupt)?,
            );
            offset += 4;

            let block = u64::from_le_bytes(
                buf[offset..offset + 8]
                    .try_into()
                    .map_err(|_| LfsError::Corrupt)?,
            );
            offset += 8;

            map.insert(inode_id, block);
        }

        Ok(Self { map })
    }

    /// Serialize the imap and write it to consecutive blocks on disk.
    ///
    /// Returns the number of blocks written.
    ///
    /// # Errors
    ///
    /// Returns [`LfsError::BlockIo`] if any block write fails.
    pub(crate) fn save_to_disk(
        &self,
        dev: &mut dyn BlockDevice,
        cache: &mut BlockCache,
        start_block: u64,
    ) -> Result<u32, LfsError> {
        let mut data = Vec::new();
        self.serialize(&mut data);

        let block_count = blocks_needed(data.len());

        // Pad to full block boundary.
        data.resize(block_count as usize * BLOCK_SIZE, 0);

        for i in 0..block_count {
            let offset = i as usize * BLOCK_SIZE;
            let block_data: &[u8; BLOCK_SIZE] = data[offset..offset + BLOCK_SIZE]
                .try_into()
                .map_err(|_| LfsError::Corrupt)?;
            cache.write(dev, start_block + u64::from(i), block_data)?;
        }

        cache.flush(dev)?;
        Ok(block_count)
    }

    /// Read and deserialize the imap from consecutive blocks on disk.
    ///
    /// # Errors
    ///
    /// - [`LfsError::BlockIo`] if any block read fails.
    /// - [`LfsError::Corrupt`] if the deserialized data is invalid.
    pub(crate) fn load_from_disk(
        dev: &mut dyn BlockDevice,
        cache: &mut BlockCache,
        start_block: u64,
        block_count: u32,
    ) -> Result<Self, LfsError> {
        // WHY: block_count is an attacker-controlled on-disk field
        // (CheckpointHeader::imap_block_count, validated for magic only —
        // see lfs::mount). Bound it with checked arithmetic against the
        // device's actual capacity before sizing any allocation from it,
        // so a crafted/bit-flipped value cannot wrap the multiply (32-bit
        // target) or request an allocation the device could never back
        // (#333).
        let byte_len = (block_count as usize)
            .checked_mul(BLOCK_SIZE)
            .ok_or(LfsError::Corrupt)?;
        let device_bytes = dev.sector_count().saturating_mul(dev.sector_size() as u64);
        if byte_len as u64 > device_bytes {
            return Err(LfsError::Corrupt);
        }

        let mut data = Vec::with_capacity(byte_len);
        let mut buf = [0u8; BLOCK_SIZE];

        for i in 0..block_count {
            cache.read(dev, start_block + u64::from(i), &mut buf)?;
            data.extend_from_slice(&buf);
        }

        Self::deserialize(&data)
    }
}

impl Default for LfsImap {
    fn default() -> Self {
        Self::new()
    }
}

/// Calculate the number of 4 KiB blocks needed to store `byte_count` bytes.
fn blocks_needed(byte_count: usize) -> u32 {
    let full = byte_count / BLOCK_SIZE;
    let partial = if byte_count % BLOCK_SIZE != 0 { 1 } else { 0 };
    (full + partial) as u32
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::MemBlockDevice;

    #[test]
    fn insert_and_get_returns_value() {
        let mut imap = LfsImap::new();
        imap.insert(0, 100);
        imap.insert(1, 200);
        imap.insert(42, 999);

        assert_eq!(imap.get(0), Some(100));
        assert_eq!(imap.get(1), Some(200));
        assert_eq!(imap.get(42), Some(999));
        assert_eq!(imap.get(99), None);
    }

    #[test]
    fn remove_deletes_entry() {
        let mut imap = LfsImap::new();
        imap.insert(5, 500);
        assert_eq!(imap.get(5), Some(500));

        imap.remove(5);
        assert_eq!(imap.get(5), None);
    }

    #[test]
    fn serialize_deserialize_round_trips() {
        let mut imap = LfsImap::new();
        imap.insert(0, 10);
        imap.insert(1, 20);
        imap.insert(100, 300);
        imap.insert(255, 1024);

        let mut buf = Vec::new();
        imap.serialize(&mut buf);

        let restored = LfsImap::deserialize(&buf).expect("deserialize should succeed");
        assert_eq!(restored.get(0), Some(10));
        assert_eq!(restored.get(1), Some(20));
        assert_eq!(restored.get(100), Some(300));
        assert_eq!(restored.get(255), Some(1024));
        assert_eq!(restored.len(), 4);
    }

    #[test]
    fn save_and_load_from_disk_round_trips() {
        // 8 MB device = 16384 sectors = 2048 blocks.
        let mut dev = MemBlockDevice::new(16384).expect("create device");
        let mut cache = BlockCache::new();

        let mut imap = LfsImap::new();
        for i in 0..50 {
            imap.insert(i, u64::from(i) * 10 + 100);
        }

        let start_block = 64;
        let block_count = imap
            .save_to_disk(&mut dev, &mut cache, start_block)
            .expect("save should succeed");

        // Create a fresh cache to prove we're reading from disk.
        let mut cache2 = BlockCache::new();
        let restored = LfsImap::load_from_disk(&mut dev, &mut cache2, start_block, block_count)
            .expect("load should succeed");

        assert_eq!(restored.len(), 50);
        for i in 0..50 {
            assert_eq!(
                restored.get(i),
                Some(u64::from(i) * 10 + 100),
                "inode {i} mismatch"
            );
        }
    }

    #[test]
    fn deserialize_rejects_truncated_data() {
        let result = LfsImap::deserialize(&[0; 2]);
        assert!(
            matches!(result, Err(LfsError::Corrupt)),
            "expected Corrupt error for truncated data"
        );
    }

    #[test]
    fn deserialize_rejects_short_entry_data() {
        // Header says 1 entry but data is too short.
        let mut buf = Vec::new();
        buf.extend_from_slice(&1u32.to_le_bytes());
        // Only 4 bytes instead of 12.
        buf.extend_from_slice(&0u32.to_le_bytes());

        let result = LfsImap::deserialize(&buf);
        assert!(
            matches!(result, Err(LfsError::Corrupt)),
            "expected Corrupt error for short entry data"
        );
    }

    #[test]
    fn empty_imap_round_trips() {
        let imap = LfsImap::new();
        let mut buf = Vec::new();
        imap.serialize(&mut buf);

        let restored = LfsImap::deserialize(&buf).expect("deserialize empty");
        assert!(restored.is_empty());
    }

    #[test]
    fn deserialize_rejects_overflowing_count() {
        // WHY: count * IMAP_ENTRY_SIZE must not wrap on a 32-bit usize. A
        // crafted count near usize::MAX must be rejected via checked
        // arithmetic, not silently truncated into a short expected_len that
        // then lets the entry-parse loop index past `buf` (#333).
        let mut buf = Vec::new();
        buf.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        buf.extend_from_slice(&[0u8; 16]);

        let result = LfsImap::deserialize(&buf);
        assert!(
            matches!(result, Err(LfsError::Corrupt)),
            "overflowing count must be rejected as Corrupt, not wrap and OOB-index"
        );
    }

    #[test]
    fn load_from_disk_rejects_block_count_exceeding_device_capacity() {
        // WHY: block_count is an attacker-controlled on-disk field; an
        // oversized value must be rejected against the device's actual
        // capacity before Vec::with_capacity is sized from it (#333).
        let mut dev = MemBlockDevice::new(64).expect("create device"); // 32 KiB device
        let mut cache = BlockCache::new();

        let result = LfsImap::load_from_disk(&mut dev, &mut cache, 0, 262_145);
        assert!(
            matches!(result, Err(LfsError::Corrupt)),
            "block_count implying ~1 GiB on a 32 KiB device must be rejected before allocating"
        );
    }

    #[test]
    fn load_from_disk_rejects_overflowing_block_count() {
        // WHY: block_count * BLOCK_SIZE must not wrap on a 32-bit usize (#333).
        let mut dev = MemBlockDevice::new(64).expect("create device");
        let mut cache = BlockCache::new();

        let result = LfsImap::load_from_disk(&mut dev, &mut cache, 0, u32::MAX);
        assert!(
            matches!(result, Err(LfsError::Corrupt)),
            "overflowing block_count must be rejected, not wrap into a tiny allocation"
        );
    }

    #[test]
    fn save_and_load_from_disk_round_trips_across_multiple_blocks() {
        // Done-when (finding 30): an imap large enough to span more than
        // one 4 KiB block must still round-trip correctly through
        // save_to_disk / load_from_disk -- the existing
        // save_and_load_from_disk_round_trips test only has 50 entries
        // (604 bytes), which fits in a single block and never exercises
        // the multi-block write/read loop.
        let mut dev = MemBlockDevice::new(65536).expect("create device"); // 32 MiB
        let mut cache = BlockCache::new();

        let mut imap = LfsImap::new();
        const ENTRY_COUNT: u32 = 1000;
        for i in 0..ENTRY_COUNT {
            imap.insert(i, u64::from(i) * 7 + 1000);
        }

        let start_block = 100;
        let block_count = imap
            .save_to_disk(&mut dev, &mut cache, start_block)
            .expect("save should succeed");
        assert!(
            block_count > 1,
            "test fixture must actually span multiple blocks, got {block_count}"
        );

        let mut cache2 = BlockCache::new();
        let restored = LfsImap::load_from_disk(&mut dev, &mut cache2, start_block, block_count)
            .expect("load should succeed");

        assert_eq!(restored.len(), ENTRY_COUNT as usize);
        for i in 0..ENTRY_COUNT {
            assert_eq!(
                restored.get(i),
                Some(u64::from(i) * 7 + 1000),
                "inode {i} mismatch across multi-block round-trip"
            );
        }
    }
}
