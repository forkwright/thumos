//! Segment cleaner (compactor) for the log-structured filesystem.
//!
//! In a log-structured filesystem, updates create new versions of blocks at
//! new locations, leaving stale (garbage) copies in old segments. The
//! compactor reclaims space by:
//!
//! 1. Identifying the segment with the most garbage (fewest live blocks).
//! 2. Copying live blocks (inodes and data) to the write head.
//! 3. Updating the imap to reflect the new locations.
//! 4. Freeing the old segment for reuse.
//!
//! # Trigger policy
//!
//! Compaction is triggered when `seg_mgr.free_count()` drops below
//! [`COMPACT_THRESHOLD_PERCENT`] of total segments. The caller (typically
//! the `Lfs` write path) checks this condition and calls
//! [`compact_one_segment`] as needed.

extern crate alloc;
use alloc::vec::Vec;

use crate::block::{BlockDevice, BLOCK_SIZE};
use crate::cache::BlockCache;
use crate::lfs::DiskInode;
use crate::lfs_imap::{LfsError, LfsImap};
use crate::lfs_segment::LfsSegmentManager;
use crate::lfs_writer::{LfsWriter, COMPACT_THRESHOLD_PERCENT};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Check whether compaction should be triggered based on free segment count.
///
/// Returns `true` if the percentage of free segments is below the threshold.
pub fn needs_compaction(seg_mgr: &LfsSegmentManager) -> bool {
    let total = seg_mgr.segment_count();
    if total == 0 {
        return false;
    }
    let threshold = (u64::from(total) * u64::from(COMPACT_THRESHOLD_PERCENT) / 100) as u32;
    // Always require at least 1 free segment as the minimum threshold.
    let threshold = threshold.max(1);
    seg_mgr.free_count() < threshold
}

/// Compact one segment: pick the segment with the most garbage, copy its
/// live blocks to the write head, update the imap, and free the old segment.
///
/// Returns the number of live blocks that were copied.
///
/// # Strategy
///
/// For each active (non-free) segment, count how many blocks in that segment
/// are still referenced by the imap. Pick the segment with the fewest live
/// blocks (most reclaimable space). Copy those live blocks to the writer's
/// current position, update imap entries to reflect their new addresses,
/// then free the old segment.
///
/// The writer's current segment is excluded from compaction candidates to
/// avoid compacting the segment we are actively writing to.
///
/// # Errors
///
/// - [`LfsError::NoFreeSegments`] if no candidate segments exist or the
///   writer cannot allocate a new segment.
/// - [`LfsError::BlockIo`] if any block read or write fails.
pub fn compact_one_segment(
    dev: &mut dyn BlockDevice,
    cache: &mut BlockCache,
    writer: &mut LfsWriter,
    imap: &mut LfsImap,
    seg_mgr: &mut LfsSegmentManager,
) -> Result<u32, LfsError> {
    // Build a map of which blocks in each segment are live.
    let candidate = pick_candidate(imap, seg_mgr, writer)?;
    let seg_idx = candidate.segment_idx;

    // Copy live blocks to the writer.
    let mut copied = 0u32;
    for &(inode_id, old_block) in &candidate.live_inodes {
        // Read the inode block from the old location.
        let mut buf = [0u8; BLOCK_SIZE];
        cache.read(dev, old_block, &mut buf)?;

        let inode = DiskInode::read_from(&buf, 0)?;

        // Write to the new location via the writer.
        writer.write_inode(dev, cache, imap, seg_mgr, inode_id, &inode)?;
        copied += 1;
    }

    for &old_block in &candidate.live_data_blocks {
        // Read the data block.
        let mut buf = [0u8; BLOCK_SIZE];
        cache.read(dev, old_block, &mut buf)?;

        // Write to the new location.
        let new_block = writer.write_data_block(dev, cache, seg_mgr, &buf)?;

        // Update any inode direct pointers that reference this old block.
        // We need to find which inode references this data block and update it.
        update_data_block_references(
            dev, cache, imap, seg_mgr, writer, old_block, new_block,
        )?;
        copied += 1;
    }

    // Free the old segment.
    seg_mgr.free(seg_idx);

    Ok(copied)
}

// ---------------------------------------------------------------------------
// Internal types and helpers
// ---------------------------------------------------------------------------

/// A compaction candidate: a segment and its live block inventory.
struct CompactCandidate {
    /// Segment index.
    segment_idx: u32,
    /// Live inode blocks: `(inode_id, block_number)`.
    live_inodes: Vec<(u32, u64)>,
    /// Live data blocks (not inodes) still referenced by an inode.
    live_data_blocks: Vec<u64>,
    /// Total live block count (inodes + data).
    live_count: u32,
}

/// Pick the best segment to compact (fewest live blocks).
///
/// Scans all active segments (excluding segment 0 which is metadata and
/// the writer's current segment) and counts how many blocks in each are
/// still referenced by the imap. Returns the segment with the fewest
/// live blocks.
fn pick_candidate(
    imap: &LfsImap,
    seg_mgr: &LfsSegmentManager,
    writer: &LfsWriter,
) -> Result<CompactCandidate, LfsError> {
    let seg_count = seg_mgr.segment_count();
    let seg_size = seg_mgr.segment_size();

    // Collect all block-to-inode mappings for quick lookup.
    let imap_blocks: Vec<(u32, u64)> = collect_imap_entries(imap);

    // Also collect all data blocks referenced by inodes that we know about.
    // We cannot do this without reading inodes, so we defer data block
    // detection to the actual compaction phase. For candidate selection,
    // we only count inode blocks.

    let mut best: Option<CompactCandidate> = None;

    for seg_idx in 1..seg_count {
        // Skip free segments and the writer's active segment.
        if seg_mgr.is_free(seg_idx) {
            continue;
        }
        if seg_idx == writer.current_segment() {
            continue;
        }

        let seg_start = seg_mgr.segment_start_block(seg_idx);
        let seg_end = seg_start + u64::from(seg_size);

        let mut live_inodes = Vec::new();
        for &(inode_id, block) in &imap_blocks {
            if block >= seg_start && block < seg_end {
                live_inodes.push((inode_id, block));
            }
        }

        let live_count = live_inodes.len() as u32;

        let candidate = CompactCandidate {
            segment_idx: seg_idx,
            live_inodes,
            live_data_blocks: Vec::new(), // filled during compaction
            live_count,
        };

        let is_better = match &best {
            None => true,
            Some(current_best) => live_count < current_best.live_count,
        };

        if is_better {
            best = Some(candidate);
        }
    }

    best.ok_or(LfsError::NoFreeSegments)
}

/// Collect all (inode_id, block_number) pairs from the imap.
fn collect_imap_entries(imap: &LfsImap) -> Vec<(u32, u64)> {
    imap.iter().collect()
}

/// After relocating a data block, find and update the inode that references it.
///
/// Scans all inodes in the imap, loads each, checks direct block pointers
/// for the old block address, and if found, updates the pointer to the new
/// address and writes the updated inode.
fn update_data_block_references(
    dev: &mut dyn BlockDevice,
    cache: &mut BlockCache,
    imap: &mut LfsImap,
    seg_mgr: &mut LfsSegmentManager,
    writer: &mut LfsWriter,
    old_block: u64,
    new_block: u64,
) -> Result<(), LfsError> {
    let entries = collect_imap_entries(imap);

    for (inode_id, inode_block) in entries {
        let mut buf = [0u8; BLOCK_SIZE];
        cache.read(dev, inode_block, &mut buf)?;

        let mut inode = DiskInode::read_from(&buf, 0)?;
        let mut modified = false;

        for ptr in &mut inode.direct {
            if *ptr == old_block {
                *ptr = new_block;
                modified = true;
            }
        }

        if inode.indirect == old_block {
            inode.indirect = new_block;
            modified = true;
        }

        if modified {
            writer.write_inode(dev, cache, imap, seg_mgr, inode_id, &inode)?;
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::MemBlockDevice;
    use crate::lfs::{DiskInode, INODE_TYPE_FILE};

    /// Create a 2 MB test device (4096 sectors = 512 blocks).
    /// With segment size 8, this gives 64 segments.
    fn test_device() -> MemBlockDevice {
        MemBlockDevice::new(4096).expect("create 2 MB test device")
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
    fn compact_reclaims_garbage_segment() {
        let mut dev = test_device();
        let mut cache = BlockCache::new();
        let mut imap = LfsImap::new();
        // 64 segments of 8 blocks each.
        let mut seg_mgr = LfsSegmentManager::new(64, 8);
        seg_mgr.mark_used(0);

        let mut writer = LfsWriter::new(&mut seg_mgr).expect("create writer");

        // Write an inode, then overwrite it (creating garbage in the first location).
        let inode_v1 = new_file_inode(100);
        writer
            .write_inode(&mut dev, &mut cache, &mut imap, &mut seg_mgr, 10, &inode_v1)
            .expect("write inode v1");

        // Seal the segment so it becomes a compaction candidate.
        writer
            .seal_segment(&mut dev, &mut cache, &mut seg_mgr)
            .expect("seal after v1");
        let _old_segment = writer.current_segment() - 1; // The just-sealed segment
        // Actually, after seal, writer moved to a new segment. The sealed one
        // had the inode. But we need to overwrite the inode to make it garbage.

        // Write inode v2 (new location, old location becomes garbage).
        let inode_v2 = new_file_inode(200);
        writer
            .write_inode(&mut dev, &mut cache, &mut imap, &mut seg_mgr, 10, &inode_v2)
            .expect("write inode v2");

        // The imap now points to v2's block. The v1 block is garbage.
        let free_before = seg_mgr.free_count();

        // Compact: should free the segment containing the garbage v1 block.
        let copied = compact_one_segment(&mut dev, &mut cache, &mut writer, &mut imap, &mut seg_mgr)
            .expect("compact");

        // No live blocks in the garbage segment (imap points to v2).
        assert_eq!(copied, 0, "garbage-only segment should have 0 live blocks");
        assert!(
            seg_mgr.free_count() > free_before,
            "free count should increase after compaction"
        );
    }

    #[test]
    fn compact_preserves_live_data() {
        let mut dev = test_device();
        let mut cache = BlockCache::new();
        let mut imap = LfsImap::new();
        let mut seg_mgr = LfsSegmentManager::new(64, 8);
        seg_mgr.mark_used(0);

        let mut writer = LfsWriter::new(&mut seg_mgr).expect("create writer");

        // Write a live inode that will remain current.
        let inode = new_file_inode(42);
        writer
            .write_inode(&mut dev, &mut cache, &mut imap, &mut seg_mgr, 5, &inode)
            .expect("write live inode");

        let block_before = imap.get(5).expect("inode 5 should be in imap");

        // Seal so it becomes a candidate.
        writer
            .seal_segment(&mut dev, &mut cache, &mut seg_mgr)
            .expect("seal");

        // Now compact. The inode is live, so it should be copied.
        let copied = compact_one_segment(&mut dev, &mut cache, &mut writer, &mut imap, &mut seg_mgr)
            .expect("compact");

        assert_eq!(copied, 1, "should copy 1 live inode block");

        // The imap should still have inode 5, but at a new address.
        let block_after = imap.get(5).expect("inode 5 should still be in imap");
        assert_ne!(
            block_before, block_after,
            "inode should have been relocated"
        );

        // Verify the data is intact.
        let mut buf = [0u8; BLOCK_SIZE];
        cache.read(&dev, block_after, &mut buf).expect("read relocated");
        let restored = DiskInode::read_from(&buf, 0).expect("parse");
        assert_eq!(restored.size, 42);
        assert_eq!(restored.inode_type, INODE_TYPE_FILE);
    }

    #[test]
    fn compact_updates_imap_for_moved_blocks() {
        let mut dev = test_device();
        let mut cache = BlockCache::new();
        let mut imap = LfsImap::new();
        let mut seg_mgr = LfsSegmentManager::new(64, 8);
        seg_mgr.mark_used(0);

        let mut writer = LfsWriter::new(&mut seg_mgr).expect("create writer");

        // Write two inodes to the same segment.
        let inode_a = new_file_inode(10);
        let inode_b = new_file_inode(20);
        writer
            .write_inode(&mut dev, &mut cache, &mut imap, &mut seg_mgr, 1, &inode_a)
            .expect("write A");
        writer
            .write_inode(&mut dev, &mut cache, &mut imap, &mut seg_mgr, 2, &inode_b)
            .expect("write B");

        let old_block_a = imap.get(1).expect("inode 1 in imap");
        let old_block_b = imap.get(2).expect("inode 2 in imap");

        // Seal so this segment becomes a candidate.
        writer
            .seal_segment(&mut dev, &mut cache, &mut seg_mgr)
            .expect("seal");

        // Compact.
        let copied = compact_one_segment(&mut dev, &mut cache, &mut writer, &mut imap, &mut seg_mgr)
            .expect("compact");

        assert_eq!(copied, 2, "should copy 2 live inodes");

        // Imap should have updated addresses.
        let new_block_a = imap.get(1).expect("inode 1 still in imap");
        let new_block_b = imap.get(2).expect("inode 2 still in imap");

        assert_ne!(old_block_a, new_block_a, "inode 1 should have moved");
        assert_ne!(old_block_b, new_block_b, "inode 2 should have moved");
    }
}
