//! Log write path for the log-structured filesystem.
//!
//! Buffers writes into the current segment, seals the segment when full,
//! and manages checkpoint persistence. All new data (inodes and file data
//! blocks) flows through [`LfsWriter`] which appends sequentially to the
//! active segment.
//!
//! # Segment layout
//!
//! ```text
//! Block 0:     SegmentHeader (written at seal time)
//! Block 1..N:  Data blocks (inodes, file data) written sequentially
//! ```
//!
//! The header at block 0 is written when the segment is sealed, not when
//! it is first allocated. This ensures partial segment writes are detected
//! as incomplete on recovery (missing or stale header).

extern crate alloc;
use alloc::vec::Vec;

use crate::block::{BlockDevice, BLOCK_SIZE};
use crate::cache::BlockCache;
use crate::lfs::{DiskInode, SegmentHeader, SEGMENT_MAGIC};
use crate::lfs_checkpoint::{self, CheckpointHeader, CHECKPOINT_MAGIC};
use crate::lfs_imap::{LfsError, LfsImap};
use crate::lfs_segment::LfsSegmentManager;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Percentage of total segments that must remain free before compaction is
/// triggered. WHY: 10% headroom prevents allocation failures during burst
/// writes while keeping the threshold low enough to avoid unnecessary I/O.
pub const COMPACT_THRESHOLD_PERCENT: u32 = 10;

// ---------------------------------------------------------------------------
// LfsWriter
// ---------------------------------------------------------------------------

/// Sequential write head for the log-structured filesystem.
///
/// Maintains the current write position within the active segment and
/// handles segment transitions (seal + allocate) when the segment fills.
/// All block writes flow through this struct to ensure the log invariant:
/// new data is always appended, never overwritten in place.
pub struct LfsWriter {
    /// Index of the segment currently being written to.
    current_segment: u32,
    /// Next block offset within the current segment (0 = header, 1..N = data).
    write_position: u32,
    /// Monotonically increasing sequence number for segment headers.
    sequence: u64,
}

impl LfsWriter {
    /// Allocate the first write segment and create a new writer.
    ///
    /// # Errors
    ///
    /// Returns [`LfsError::NoFreeSegments`] if no segments are available.
    #[must_use]
    pub fn new(seg_mgr: &mut LfsSegmentManager) -> Result<Self, LfsError> {
        let seg = seg_mgr.allocate().ok_or(LfsError::NoFreeSegments)?;
        Ok(Self {
            current_segment: seg,
            // Position 1: skip block 0 which is reserved for the segment header.
            write_position: 1,
            sequence: 1,
        })
    }

    /// Create a writer with a specific initial sequence number.
    ///
    /// Used when resuming from a checkpoint to continue the sequence
    /// where the previous session left off.
    ///
    /// # Errors
    ///
    /// Returns [`LfsError::NoFreeSegments`] if no segments are available.
    pub fn with_sequence(
        seg_mgr: &mut LfsSegmentManager,
        sequence: u64,
    ) -> Result<Self, LfsError> {
        let seg = seg_mgr.allocate().ok_or(LfsError::NoFreeSegments)?;
        Ok(Self {
            current_segment: seg,
            write_position: 1,
            sequence,
        })
    }

    /// Return the current sequence number.
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Return the index of the segment currently being written to.
    ///
    /// Used by the compactor to avoid selecting the active write segment
    /// as a compaction candidate.
    pub fn current_segment(&self) -> u32 {
        self.current_segment
    }

    /// Serialize an inode to a block and write it to the current segment.
    ///
    /// Updates the imap to record the new block address for this inode.
    /// If the current segment is full, it is sealed first and a new
    /// segment is allocated.
    ///
    /// Returns the absolute block number where the inode was written.
    ///
    /// # Errors
    ///
    /// - [`LfsError::NoFreeSegments`] if a new segment is needed but none are free.
    /// - [`LfsError::BlockIo`] if any block write fails.
    pub fn write_inode(
        &mut self,
        dev: &mut dyn BlockDevice,
        cache: &mut BlockCache,
        imap: &mut LfsImap,
        seg_mgr: &mut LfsSegmentManager,
        inode_id: u32,
        inode: &DiskInode,
    ) -> Result<u64, LfsError> {
        // Seal and allocate a new segment if the current one is full.
        if self.write_position >= seg_mgr.segment_size() {
            self.seal_segment(dev, cache, seg_mgr)?;
        }

        let block_num = seg_mgr.segment_start_block(self.current_segment)
            + u64::from(self.write_position);

        // Serialize the inode into a block-sized buffer.
        let mut buf = [0u8; BLOCK_SIZE];
        inode.write_to(&mut buf, 0);

        cache.write(dev, block_num, &buf)?;
        self.write_position += 1;

        // Update the imap to point to the new location.
        imap.insert(inode_id, block_num);

        Ok(block_num)
    }

    /// Write a raw 4 KiB data block to the current segment.
    ///
    /// Returns the absolute block number where the data was written.
    /// If the current segment is full, it is sealed first and a new
    /// segment is allocated.
    ///
    /// # Errors
    ///
    /// - [`LfsError::NoFreeSegments`] if a new segment is needed but none are free.
    /// - [`LfsError::BlockIo`] if the block write fails.
    pub fn write_data_block(
        &mut self,
        dev: &mut dyn BlockDevice,
        cache: &mut BlockCache,
        seg_mgr: &mut LfsSegmentManager,
        data: &[u8; BLOCK_SIZE],
    ) -> Result<u64, LfsError> {
        if self.write_position >= seg_mgr.segment_size() {
            self.seal_segment(dev, cache, seg_mgr)?;
        }

        let block_num = seg_mgr.segment_start_block(self.current_segment)
            + u64::from(self.write_position);

        cache.write(dev, block_num, data)?;
        self.write_position += 1;

        Ok(block_num)
    }

    /// Seal the current segment and allocate a new one.
    ///
    /// Writes the [`SegmentHeader`] at block 0 of the current segment
    /// with the current sequence number and block count. Then allocates
    /// a fresh segment for subsequent writes.
    ///
    /// # Errors
    ///
    /// - [`LfsError::NoFreeSegments`] if no new segment can be allocated.
    /// - [`LfsError::BlockIo`] if writing the segment header fails.
    pub fn seal_segment(
        &mut self,
        dev: &mut dyn BlockDevice,
        cache: &mut BlockCache,
        seg_mgr: &mut LfsSegmentManager,
    ) -> Result<(), LfsError> {
        // The number of data blocks written is write_position - 1 (block 0 is header).
        let data_block_count = self.write_position.saturating_sub(1);

        let header = SegmentHeader {
            magic: SEGMENT_MAGIC,
            sequence: self.sequence,
            timestamp: 0,
            block_count: data_block_count,
        };

        let header_block = seg_mgr.segment_start_block(self.current_segment);
        let buf = header.to_block();
        cache.write(dev, header_block, &buf)?;

        self.sequence += 1;

        // Allocate a new segment for the next writes.
        let new_seg = seg_mgr.allocate().ok_or(LfsError::NoFreeSegments)?;
        self.current_segment = new_seg;
        self.write_position = 1; // Skip header block.

        Ok(())
    }

    /// Persist the filesystem state by writing a checkpoint.
    ///
    /// Serializes the imap and segment bitmap, writes them to the
    /// appropriate checkpoint slot (alternating between slot A and slot B),
    /// and increments the checkpoint sequence.
    ///
    /// `checkpoint_slots` is `(slot_a_block, slot_b_block)` from the superblock.
    /// `checkpoint_sequence` is the current checkpoint sequence counter.
    ///
    /// # Errors
    ///
    /// - [`LfsError::BlockIo`] if any block write fails.
    pub fn write_checkpoint(
        &mut self,
        dev: &mut dyn BlockDevice,
        cache: &mut BlockCache,
        imap: &LfsImap,
        seg_mgr: &LfsSegmentManager,
        checkpoint_slots: (u64, u64),
        checkpoint_sequence: u64,
        next_inode: u32,
    ) -> Result<(), LfsError> {
        // Serialize imap.
        let mut imap_data = Vec::new();
        imap.serialize(&mut imap_data);

        // Serialize segment bitmap.
        let segment_data = seg_mgr.serialize();

        // Compute block layout: imap goes right after the header block,
        // segment bitmap follows the imap.
        let imap_blocks = blocks_needed(imap_data.len());
        let seg_bitmap_blocks = blocks_needed(segment_data.len());

        // Alternate between slot A (even sequence) and slot B (odd sequence).
        let slot_block = if checkpoint_sequence % 2 == 0 {
            checkpoint_slots.0
        } else {
            checkpoint_slots.1
        };

        // Imap data starts at slot_block + 1 (after the header).
        let imap_block = slot_block + 1;
        let segment_bitmap_block = imap_block + imap_blocks as u64;

        let header = CheckpointHeader {
            magic: CHECKPOINT_MAGIC,
            sequence: checkpoint_sequence,
            imap_block,
            imap_block_count: imap_blocks as u32,
            segment_bitmap_block,
            segment_bitmap_count: seg_bitmap_blocks as u32,
            next_inode,
            last_segment_sequence: self.sequence,
        };

        lfs_checkpoint::write_checkpoint(
            dev,
            cache,
            slot_block,
            &header,
            &imap_data,
            &segment_data,
        )?;

        Ok(())
    }
}

/// Calculate the number of 4 KiB blocks needed to store `byte_count` bytes.
fn blocks_needed(byte_count: usize) -> usize {
    let full = byte_count / BLOCK_SIZE;
    let partial = if byte_count % BLOCK_SIZE != 0 { 1 } else { 0 };
    full + partial
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::MemBlockDevice;
    use crate::lfs::{DiskInode, INODE_TYPE_FILE};

    /// Create an 8 MB test device (16384 sectors = 2048 blocks = 8 segments of 256).
    fn block_device_for_writer() -> MemBlockDevice {
        MemBlockDevice::new(16384).expect("create 8 MB test device")
    }

    fn new_file_inode(size: u64) -> DiskInode {
        DiskInode {
            inode_type: INODE_TYPE_FILE,
            link_count: 1,
            size,
            direct: [0u64; 12],
            indirect: 0,
        }
    }

    #[test]
    fn write_inode_updates_imap() {
        let mut dev = block_device_for_writer();
        let mut cache = BlockCache::new();
        let mut imap = LfsImap::new();
        let mut seg_mgr = LfsSegmentManager::new(8, 256);
        seg_mgr.mark_used(0); // segment 0 is metadata

        let mut writer = LfsWriter::new(&mut seg_mgr).expect("create writer");

        let inode = new_file_inode(100);
        let block = writer
            .write_inode(&mut dev, &mut cache, &mut imap, &mut seg_mgr, 42, &inode)
            .expect("write inode");

        // Imap should now map inode 42 to the written block.
        assert_eq!(imap.get(42), Some(block));

        // Read the block back and verify the inode data.
        let mut buf = [0u8; BLOCK_SIZE];
        cache.read(&mut dev, block, &mut buf).expect("read back");
        let restored = DiskInode::read_from(&buf, 0).expect("parse inode");
        assert_eq!(restored.inode_type, INODE_TYPE_FILE);
        assert_eq!(restored.size, 100);
        assert_eq!(restored.link_count, 1);
    }

    #[test]
    fn write_data_block_advances_position() {
        let mut dev = block_device_for_writer();
        let mut cache = BlockCache::new();
        let mut seg_mgr = LfsSegmentManager::new(8, 256);
        seg_mgr.mark_used(0);

        let mut writer = LfsWriter::new(&mut seg_mgr).expect("create writer");

        let data1 = [0xAAu8; BLOCK_SIZE];
        let data2 = [0xBBu8; BLOCK_SIZE];

        let block1 = writer
            .write_data_block(&mut dev, &mut cache, &mut seg_mgr, &data1)
            .expect("write block 1");
        let block2 = writer
            .write_data_block(&mut dev, &mut cache, &mut seg_mgr, &data2)
            .expect("write block 2");

        // Blocks should be sequential within the segment.
        assert_eq!(block2, block1 + 1);

        // Verify data round-trips.
        let mut buf = [0u8; BLOCK_SIZE];
        cache.read(&mut dev, block1, &mut buf).expect("read block 1");
        assert!(buf.iter().all(|&b| b == 0xAA));

        cache.read(&mut dev, block2, &mut buf).expect("read block 2");
        assert!(buf.iter().all(|&b| b == 0xBB));
    }

    #[test]
    fn seal_segment_writes_header() {
        let mut dev = block_device_for_writer();
        let mut cache = BlockCache::new();
        let mut seg_mgr = LfsSegmentManager::new(8, 256);
        seg_mgr.mark_used(0);

        let mut writer = LfsWriter::new(&mut seg_mgr).expect("create writer");
        let initial_segment = writer.current_segment;
        let initial_sequence = writer.sequence;

        // Write a couple of data blocks.
        let data = [0xCCu8; BLOCK_SIZE];
        writer
            .write_data_block(&mut dev, &mut cache, &mut seg_mgr, &data)
            .expect("write 1");
        writer
            .write_data_block(&mut dev, &mut cache, &mut seg_mgr, &data)
            .expect("write 2");

        // Seal the segment.
        writer
            .seal_segment(&mut dev, &mut cache, &mut seg_mgr)
            .expect("seal");

        // The writer should have moved to a new segment.
        assert_ne!(writer.current_segment, initial_segment);
        assert_eq!(writer.sequence, initial_sequence + 1);

        // Read the segment header from the sealed segment.
        cache.flush(&mut dev).expect("flush");
        let header_block = seg_mgr.segment_start_block(initial_segment);
        let mut buf = [0u8; BLOCK_SIZE];
        cache.read(&mut dev, header_block, &mut buf).expect("read header");

        // Verify the magic and block count in the header.
        let magic = u32::from_le_bytes(buf[0..4].try_into().expect("magic bytes"));
        assert_eq!(magic, SEGMENT_MAGIC);

        // Sequence should be the initial sequence.
        let seq = u64::from_le_bytes(buf[4..12].try_into().expect("seq bytes"));
        assert_eq!(seq, initial_sequence);

        // Block count should be 2 (the two data blocks we wrote).
        let block_count = u32::from_le_bytes(buf[20..24].try_into().expect("count bytes"));
        assert_eq!(block_count, 2);
    }

    #[test]
    fn checkpoint_round_trips() {
        let mut dev = block_device_for_writer();
        let mut cache = BlockCache::new();
        let mut imap = LfsImap::new();
        let mut seg_mgr = LfsSegmentManager::new(8, 256);
        seg_mgr.mark_used(0);

        let mut writer = LfsWriter::new(&mut seg_mgr).expect("create writer");

        // Write some inodes to build up the imap.
        let inode = new_file_inode(42);
        writer
            .write_inode(&mut dev, &mut cache, &mut imap, &mut seg_mgr, 0, &inode)
            .expect("write inode 0");
        writer
            .write_inode(&mut dev, &mut cache, &mut imap, &mut seg_mgr, 1, &inode)
            .expect("write inode 1");

        let checkpoint_slots = (1u64, 2u64); // slot A at block 1, slot B at block 2
        let checkpoint_seq = 2u64; // even -> slot A

        writer
            .write_checkpoint(
                &mut dev,
                &mut cache,
                &imap,
                &seg_mgr,
                checkpoint_slots,
                checkpoint_seq,
                3, // next_inode
            )
            .expect("write checkpoint");

        cache.flush(&mut dev).expect("flush");

        // Read the checkpoint back.
        let mut cache2 = BlockCache::new();
        let header = lfs_checkpoint::read_checkpoint(&mut dev, &mut cache2, 1)
            .expect("read checkpoint");

        assert_eq!(header.magic, CHECKPOINT_MAGIC);
        assert_eq!(header.sequence, checkpoint_seq);
        assert_eq!(header.next_inode, 3);

        // Load the imap from the checkpoint and verify.
        let restored_imap = LfsImap::load_from_disk(
            &mut dev,
            &mut cache2,
            header.imap_block,
            header.imap_block_count,
        )
        .expect("load imap");

        assert_eq!(restored_imap.len(), 2);
        assert!(restored_imap.get(0).is_some());
        assert!(restored_imap.get(1).is_some());

        // Load the segment bitmap and verify.
        let mut seg_data = Vec::new();
        let mut buf = [0u8; BLOCK_SIZE];
        for i in 0..header.segment_bitmap_count {
            cache2
                .read(&mut dev, header.segment_bitmap_block + u64::from(i), &mut buf)
                .expect("read seg bitmap");
            seg_data.extend_from_slice(&buf);
        }
        let restored_seg = LfsSegmentManager::deserialize(&seg_data, 8, 256)
            .expect("deserialize segments");

        assert_eq!(restored_seg.segment_count(), 8);
        // Segment 0 and the writer's segments should be in use.
        assert!(!restored_seg.is_free(0));
    }

    #[test]
    fn write_multiple_blocks_fills_segment() {
        let mut dev = block_device_for_writer();
        let mut cache = BlockCache::new();
        let mut seg_mgr = LfsSegmentManager::new(8, 4); // small segments: 4 blocks each
        seg_mgr.mark_used(0);

        let mut writer = LfsWriter::new(&mut seg_mgr).expect("create writer");
        let initial_segment = writer.current_segment;

        let data = [0xFFu8; BLOCK_SIZE];

        // Segment size is 4: block 0 = header, blocks 1-3 = data.
        // Writing 3 blocks should fill the segment.
        writer
            .write_data_block(&mut dev, &mut cache, &mut seg_mgr, &data)
            .expect("write 1");
        writer
            .write_data_block(&mut dev, &mut cache, &mut seg_mgr, &data)
            .expect("write 2");
        writer
            .write_data_block(&mut dev, &mut cache, &mut seg_mgr, &data)
            .expect("write 3");

        // Now we are at write_position 4 == segment_size, next write should seal.
        assert_eq!(writer.write_position, 4);

        // Writing one more block should trigger seal + new segment.
        writer
            .write_data_block(&mut dev, &mut cache, &mut seg_mgr, &data)
            .expect("write 4 (triggers seal)");

        assert_ne!(
            writer.current_segment, initial_segment,
            "writer should have moved to a new segment after fill"
        );
    }
}
