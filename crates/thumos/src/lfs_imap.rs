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

use crate::block::{BlockDevice, BlockError, BLOCK_SIZE};
use crate::cache::BlockCache;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors specific to LFS operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
pub struct LfsImap {
    /// Inode ID to block number mapping.
    map: BTreeMap<u32, u64>,
}

impl LfsImap {
    /// Create an empty inode map.
    pub fn new() -> Self {
        Self {
            map: BTreeMap::new(),
        }
    }

    /// Look up the block number for an inode.
    ///
    /// # Errors
    ///
    /// This method is infallible; returns `None` if the inode is not mapped.
    pub fn get(&self, inode_id: u32) -> Option<u64> {
        self.map.get(&inode_id).copied()
    }

    /// Insert or update a mapping from inode ID to block number.
    ///
    /// # Errors
    ///
    /// This method is infallible.
    pub fn insert(&mut self, inode_id: u32, block: u64) {
        self.map.insert(inode_id, block);
    }

    /// Remove an inode mapping.
    ///
    /// # Errors
    ///
    /// This method is infallible. Removing a non-existent inode is a no-op.
    pub fn remove(&mut self, inode_id: u32) {
        self.map.remove(&inode_id);
    }

    /// Return the number of inode mappings.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Return whether the imap is empty.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Serialize the imap to bytes.
    ///
    /// Format: `count: u32` followed by `count` entries of `(inode_id: u32,
    /// block_number: u64)`, all in little-endian byte order.
    ///
    /// # Errors
    ///
    /// This method is infallible.
    pub fn serialize(&self, buf: &mut Vec<u8>) {
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
    pub fn deserialize(buf: &[u8]) -> Result<Self, LfsError> {
        if buf.len() < IMAP_HEADER_SIZE {
            return Err(LfsError::Corrupt);
        }

        let count = u32::from_le_bytes(
            buf[..4].try_into().map_err(|_| LfsError::Corrupt)?,
        ) as usize;

        let expected_len = IMAP_HEADER_SIZE + count * IMAP_ENTRY_SIZE;
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
    pub fn save_to_disk(
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
    pub fn load_from_disk(
        dev: &dyn BlockDevice,
        cache: &mut BlockCache,
        start_block: u64,
        block_count: u32,
    ) -> Result<Self, LfsError> {
        let mut data = Vec::with_capacity(block_count as usize * BLOCK_SIZE);
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
        let restored = LfsImap::load_from_disk(&dev, &mut cache2, start_block, block_count)
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
}
