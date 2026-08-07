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

use crate::block::{BLOCK_SIZE, BlockDevice};
use crate::cache::BlockCache;
use crate::lfs::DiskInode;
use crate::lfs_imap::{LfsError, LfsImap};
use crate::lfs_segment::LfsSegmentManager;
use crate::lfs_writer::{COMPACT_THRESHOLD_PERCENT, LfsWriter};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Check whether compaction should be triggered based on free segment count.
///
/// Returns `true` if the percentage of free segments available to ordinary
/// writers is below the threshold.
pub(crate) fn needs_compaction(seg_mgr: &LfsSegmentManager) -> bool {
    let total = seg_mgr.segment_count();
    if total == 0 {
        return false;
    }
    let threshold = (u64::from(total) * u64::from(COMPACT_THRESHOLD_PERCENT) / 100) as u32;
    // Always require at least 1 free segment as the minimum threshold.
    let threshold = threshold.max(1);
    // WHY: `LfsSegmentManager::allocate` withholds the last free segment as
    // a compaction reserve (#329), so ordinary writers can never drive
    // `free_count()` below 1. Comparing raw `free_count()` against a
    // threshold that floors at 1 makes the trigger unreachable through any
    // production write path on filesystems below 20 segments (#625) --
    // compare the segments actually available to ordinary writers instead.
    let usable_free = seg_mgr.free_count().saturating_sub(1);
    usable_free < threshold
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
pub(crate) fn compact_one_segment(
    dev: &mut dyn BlockDevice,
    cache: &mut BlockCache,
    writer: &mut LfsWriter,
    imap: &mut LfsImap,
    seg_mgr: &mut LfsSegmentManager,
) -> Result<u32, LfsError> {
    // Build a map of which blocks in each segment are live.
    let candidate = pick_candidate(dev, cache, imap, seg_mgr, writer)?;
    let seg_idx = candidate.segment_idx;
    let seg_start = seg_mgr.segment_start_block(seg_idx);
    let seg_end = seg_start + u64::from(seg_mgr.segment_size());

    // Copy live blocks to the writer.
    let mut copied = 0u32;
    for &(inode_id, old_block) in &candidate.live_inodes {
        // Read the inode block from the old location.
        let mut buf = [0u8; BLOCK_SIZE];
        cache.read(dev, old_block, &mut buf)?;

        let inode = DiskInode::read_from(&buf, 0)?;

        // Write to the new location via the writer. Uses the compaction
        // reserve so a mid-relocation seal always has a segment to land
        // in, instead of racing ordinary writers for the last free
        // segment (#329).
        writer.write_inode_for_compaction(dev, cache, imap, seg_mgr, inode_id, &inode)?;
        copied += 1;
    }

    for &old_block in &candidate.live_data_blocks {
        // Read the data block.
        let mut buf = [0u8; BLOCK_SIZE];
        cache.read(dev, old_block, &mut buf)?;

        // Write to the new location. Uses the compaction reserve (#329).
        let new_block = writer.write_data_block_for_compaction(dev, cache, seg_mgr, &buf)?;

        // Update any inode direct pointers that reference this old block.
        // We need to find which inode references this data block and update it.
        update_data_block_references(dev, cache, imap, seg_mgr, writer, old_block, new_block)?;
        copied += 1;
    }

    // Refuse to free a segment that still has live blocks referencing it.
    // INVARIANT: relocation above must have moved every inode block and
    // every data block pointer out of [seg_start, seg_end) before the
    // segment is handed back to the allocator -- freeing with live blocks
    // still present is exactly the silent data-loss defect this guards
    // against (#315).
    if segment_has_live_blocks(dev, cache, imap, seg_start, seg_end)? {
        return Err(LfsError::Corrupt);
    }

    // Free the old segment.
    seg_mgr.free(seg_idx);

    Ok(copied)
}

/// Check whether any live inode, or a data block it still references,
/// falls within `[seg_start, seg_end)`.
///
/// Used as the final guard before freeing a compacted segment: relocation
/// must leave zero live references behind, or the freed segment's next
/// write silently overwrites data that was never copied out (#315).
fn segment_has_live_blocks(
    dev: &mut dyn BlockDevice,
    cache: &mut BlockCache,
    imap: &LfsImap,
    seg_start: u64,
    seg_end: u64,
) -> Result<bool, LfsError> {
    for (_, block) in imap.iter() {
        if block >= seg_start && block < seg_end {
            return Ok(true);
        }

        let mut buf = [0u8; BLOCK_SIZE];
        cache.read(dev, block, &mut buf)?;
        let inode = DiskInode::read_from(&buf, 0)?;

        for &ptr in &inode.direct {
            if ptr != 0 && ptr >= seg_start && ptr < seg_end {
                return Ok(true);
            }
        }
        if inode.indirect != 0 && inode.indirect >= seg_start && inode.indirect < seg_end {
            return Ok(true);
        }
    }

    Ok(false)
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

/// Pick the best segment to compact (fewest live blocks -- inode blocks
/// plus the data blocks any live inode still references within that
/// segment).
///
/// Scans all active segments (excluding segment 0 which is metadata and
/// the writer's current segment). Every live inode is loaded from disk
/// once and its non-zero direct/indirect pointers are recorded, so each
/// candidate segment's live-data inventory can be built without
/// re-reading inodes per segment. Returns the segment with the fewest
/// live blocks (inode + data combined) -- the previous inode-only count
/// treated a data-heavy segment as fully reclaimable and silently lost
/// its contents (#315).
fn pick_candidate(
    dev: &mut dyn BlockDevice,
    cache: &mut BlockCache,
    imap: &LfsImap,
    seg_mgr: &LfsSegmentManager,
    writer: &LfsWriter,
) -> Result<CompactCandidate, LfsError> {
    let seg_count = seg_mgr.segment_count();
    let seg_size = seg_mgr.segment_size();

    // Collect all block-to-inode mappings for quick lookup.
    let imap_blocks: Vec<(u32, u64)> = collect_imap_entries(imap);

    // Load every live inode once and collect the data blocks (direct +
    // indirect pointers) it references, so per-segment buckets below can
    // be built without re-reading inodes for each candidate segment.
    let mut live_data_pointers: Vec<u64> = Vec::new();
    for &(_, inode_block) in &imap_blocks {
        let mut buf = [0u8; BLOCK_SIZE];
        cache.read(dev, inode_block, &mut buf)?;
        let inode = DiskInode::read_from(&buf, 0)?;

        for &ptr in &inode.direct {
            if ptr != 0 {
                live_data_pointers.push(ptr);
            }
        }
        if inode.indirect != 0 {
            live_data_pointers.push(inode.indirect);
        }
    }

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

        let mut live_data_blocks = Vec::new();
        for &ptr in &live_data_pointers {
            if ptr >= seg_start && ptr < seg_end {
                live_data_blocks.push(ptr);
            }
        }

        let live_count = (live_inodes.len() + live_data_blocks.len()) as u32;

        let candidate = CompactCandidate {
            segment_idx: seg_idx,
            live_inodes,
            live_data_blocks,
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

    // WHY (finding 5): distinct from "no free segments" (the filesystem is
    // completely full) -- this means no segment qualifies as a compaction
    // candidate (every segment is either free already or is the writer's
    // active segment), which can legitimately happen when compaction is
    // triggered but nothing is actually reclaimable yet.
    best.ok_or(LfsError::NoCompactionCandidate)
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
            // Part of the same relocation pass as the caller's data-block
            // write, so it must also be able to seal into the compaction
            // reserve (#329).
            writer.write_inode_for_compaction(dev, cache, imap, seg_mgr, inode_id, &inode)?;
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
    fn block_device_for_compact() -> MemBlockDevice {
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
        let mut dev = block_device_for_compact();
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
        let copied =
            compact_one_segment(&mut dev, &mut cache, &mut writer, &mut imap, &mut seg_mgr)
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
        let mut dev = block_device_for_compact();
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
        let copied =
            compact_one_segment(&mut dev, &mut cache, &mut writer, &mut imap, &mut seg_mgr)
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
        cache
            .read(&mut dev, block_after, &mut buf)
            .expect("read relocated");
        let restored = DiskInode::read_from(&buf, 0).expect("parse");
        assert_eq!(restored.size, 42);
        assert_eq!(restored.inode_type, INODE_TYPE_FILE);
    }

    #[test]
    fn compact_updates_imap_for_moved_blocks() {
        let mut dev = block_device_for_compact();
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
        let copied =
            compact_one_segment(&mut dev, &mut cache, &mut writer, &mut imap, &mut seg_mgr)
                .expect("compact");

        assert_eq!(copied, 2, "should copy 2 live inodes");

        // Imap should have updated addresses.
        let new_block_a = imap.get(1).expect("inode 1 still in imap");
        let new_block_b = imap.get(2).expect("inode 2 still in imap");

        assert_ne!(old_block_a, new_block_a, "inode 1 should have moved");
        assert_ne!(old_block_b, new_block_b, "inode 2 should have moved");
    }

    #[test]
    fn compact_relocates_live_data_block_before_freeing_segment() {
        let mut dev = block_device_for_compact();
        let mut cache = BlockCache::new();
        let mut imap = LfsImap::new();
        let mut seg_mgr = LfsSegmentManager::new(64, 8);
        seg_mgr.mark_used(0);

        let mut writer = LfsWriter::new(&mut seg_mgr).expect("create writer");

        // Write a data block with known content.
        let mut data = [0u8; BLOCK_SIZE];
        data[0] = 0xAB;
        data[1] = 0xCD;
        let data_block = writer
            .write_data_block(&mut dev, &mut cache, &mut seg_mgr, &data)
            .expect("write data block");

        // Write an inode that references the data block as its first
        // direct pointer; write_inode records it live in the imap.
        let mut inode = new_file_inode(BLOCK_SIZE as u64);
        inode.direct[0] = data_block;
        writer
            .write_inode(&mut dev, &mut cache, &mut imap, &mut seg_mgr, 7, &inode)
            .expect("write inode referencing data block");

        // Seal so this segment (holding both the inode and its data
        // block) becomes a compaction candidate.
        writer
            .seal_segment(&mut dev, &mut cache, &mut seg_mgr)
            .expect("seal");

        // Compact: both the inode block and the data block it references
        // are live and must be relocated together, not silently dropped
        // (#315).
        let copied =
            compact_one_segment(&mut dev, &mut cache, &mut writer, &mut imap, &mut seg_mgr)
                .expect("compact");
        assert_eq!(copied, 2, "should copy 1 live inode + 1 live data block");

        // The data must still be reachable at its new address via the
        // relocated inode, after the old segment was freed.
        let new_inode_block = imap.get(7).expect("inode 7 still in imap");
        let mut inode_buf = [0u8; BLOCK_SIZE];
        cache
            .read(&mut dev, new_inode_block, &mut inode_buf)
            .expect("read relocated inode");
        let restored_inode = DiskInode::read_from(&inode_buf, 0).expect("parse relocated inode");
        let new_data_block = restored_inode.direct[0];
        assert_ne!(
            new_data_block, data_block,
            "data block should have been relocated"
        );

        let mut data_buf = [0u8; BLOCK_SIZE];
        cache
            .read(&mut dev, new_data_block, &mut data_buf)
            .expect("read relocated data block");
        assert_eq!(data_buf[0], 0xAB);
        assert_eq!(data_buf[1], 0xCD);
    }

    #[test]
    fn compact_relocates_live_inode_with_only_the_reserve_segment_free() {
        // 4 segments of 2 blocks each (1 data slot per segment): segment 0
        // reserved, segment 1 holds a sealed live inode (the compaction
        // candidate), segment 2 is the writer's current (and already
        // full) segment, segment 3 is the LAST free segment -- the
        // compaction reserve. Before #329, relocating live_inodes here
        // would hit the writer's own seal-on-full path, which called the
        // ordinary (non-reserve) allocate() and deadlocked with
        // NoFreeSegments while segment 1 sat unreclaimed forever.
        let mut dev = block_device_for_compact();
        let mut cache = BlockCache::new();
        let mut imap = LfsImap::new();
        let mut seg_mgr = LfsSegmentManager::new(4, 2);
        seg_mgr.mark_used(0);

        let mut writer = LfsWriter::new(&mut seg_mgr).expect("create writer");

        // Inode 1 fills segment 1's single data slot.
        let inode_a = new_file_inode(10);
        writer
            .write_inode(&mut dev, &mut cache, &mut imap, &mut seg_mgr, 1, &inode_a)
            .expect("write inode 1 (fills segment 1)");

        // Inode 2 triggers the ordinary seal of segment 1 and lands in
        // segment 2, filling ITS single data slot too.
        let inode_b = new_file_inode(20);
        writer
            .write_inode(&mut dev, &mut cache, &mut imap, &mut seg_mgr, 2, &inode_b)
            .expect("write inode 2 (seals segment 1, fills segment 2)");

        // Exactly one segment (3) remains free: the compaction reserve.
        assert_eq!(
            seg_mgr.free_count(),
            1,
            "only the reserve should remain free"
        );
        assert_eq!(
            seg_mgr.allocate(),
            None,
            "ordinary allocation must refuse the last standing (reserve) segment"
        );

        // Segment 1 is sealed, holds one live inode, and is not the
        // writer's current segment -- it is the sole compaction
        // candidate. The writer's current segment (2) is already full,
        // so relocating inode 1 will force an immediate seal.
        let copied =
            compact_one_segment(&mut dev, &mut cache, &mut writer, &mut imap, &mut seg_mgr)
                .expect("compaction must not deadlock with only the reserve segment free");
        assert_eq!(copied, 1, "should relocate the one live inode");

        // The reserve was consumed to land the relocated inode, but
        // freeing the reclaimed candidate segment restores exactly one
        // free segment overall.
        assert_eq!(
            seg_mgr.free_count(),
            1,
            "the reclaimed segment replaces the consumed reserve"
        );

        // Inode 1 must still be reachable at its new location.
        let new_block = imap.get(1).expect("inode 1 still in imap");
        let mut buf = [0u8; BLOCK_SIZE];
        cache
            .read(&mut dev, new_block, &mut buf)
            .expect("read relocated inode 1");
        let restored = DiskInode::read_from(&buf, 0).expect("parse relocated inode 1");
        assert_eq!(restored.size, 10);
    }

    #[test]
    fn compact_picks_the_fewest_live_blocks_among_multiple_candidates() {
        // Done-when (finding 27): when more than one sealed segment is a
        // compaction candidate, pick_candidate must select the one with
        // the FEWEST live blocks, not merely the first one scanned. Sets
        // up three distinct candidate segments with live counts 2, 1, and
        // 0 and verifies the all-garbage segment (0 live) is the one
        // reclaimed, while the other two are left completely untouched.
        let mut dev = block_device_for_compact();
        let mut cache = BlockCache::new();
        let mut imap = LfsImap::new();
        // Segments of 4 blocks (1 header + 3 data slots) so a segment can
        // hold more than one live inode, letting live counts differ.
        let mut seg_mgr = LfsSegmentManager::new(8, 4);
        seg_mgr.mark_used(0);

        let mut writer = LfsWriter::new(&mut seg_mgr).expect("create writer");
        let seg1 = writer.current_segment();

        // Segment 1: two live inodes (live_count = 2), sealed without
        // filling its third slot.
        let inode1 = new_file_inode(10);
        let inode2 = new_file_inode(20);
        writer
            .write_inode(&mut dev, &mut cache, &mut imap, &mut seg_mgr, 1, &inode1)
            .expect("write inode 1");
        writer
            .write_inode(&mut dev, &mut cache, &mut imap, &mut seg_mgr, 2, &inode2)
            .expect("write inode 2");
        writer
            .seal_segment(&mut dev, &mut cache, &mut seg_mgr)
            .expect("seal segment 1");

        // Segment 2: one live inode (live_count = 1).
        let seg2 = writer.current_segment();
        assert_ne!(seg2, seg1, "writer must have moved to a new segment");
        let inode3 = new_file_inode(30);
        writer
            .write_inode(&mut dev, &mut cache, &mut imap, &mut seg_mgr, 3, &inode3)
            .expect("write inode 3");
        writer
            .seal_segment(&mut dev, &mut cache, &mut seg_mgr)
            .expect("seal segment 2");

        // Segment 3: one inode written and then sealed, so it starts with
        // one live block.
        let seg3 = writer.current_segment();
        assert_ne!(seg3, seg2, "writer must have moved to a new segment");
        let inode4_v1 = new_file_inode(40);
        writer
            .write_inode(&mut dev, &mut cache, &mut imap, &mut seg_mgr, 4, &inode4_v1)
            .expect("write inode 4 v1");
        writer
            .seal_segment(&mut dev, &mut cache, &mut seg_mgr)
            .expect("seal segment 3");

        // Overwrite inode 4 from the NEW (writer's current) segment, so
        // segment 3's only live block becomes garbage: segment 3 now has
        // live_count = 0, the fewest of the three candidates.
        let inode4_v2 = new_file_inode(41);
        writer
            .write_inode(&mut dev, &mut cache, &mut imap, &mut seg_mgr, 4, &inode4_v2)
            .expect("write inode 4 v2");

        let block1_before = imap.get(1).expect("inode 1 in imap");
        let block2_before = imap.get(2).expect("inode 2 in imap");
        let block3_before = imap.get(3).expect("inode 3 in imap");

        let copied =
            compact_one_segment(&mut dev, &mut cache, &mut writer, &mut imap, &mut seg_mgr)
                .expect("compact");

        assert_eq!(
            copied, 0,
            "the all-garbage segment (segment 3) has nothing live to relocate"
        );
        assert!(
            seg_mgr.is_free(seg3),
            "segment 3 (0 live blocks, the fewest) must be the one reclaimed"
        );
        assert!(
            !seg_mgr.is_free(seg1),
            "segment 1 (2 live blocks) must NOT have been reclaimed"
        );
        assert!(
            !seg_mgr.is_free(seg2),
            "segment 2 (1 live block) must NOT have been reclaimed"
        );

        // Segments 1 and 2's inodes must be completely untouched (same
        // addresses as before compaction).
        assert_eq!(imap.get(1), Some(block1_before));
        assert_eq!(imap.get(2), Some(block2_before));
        assert_eq!(imap.get(3), Some(block3_before));
    }

    #[test]
    fn needs_compaction_triggers_below_threshold() {
        // Done-when (finding 29): compaction must trigger once free
        // segments drop below COMPACT_THRESHOLD_PERCENT of total, and
        // must NOT trigger while comfortably above it. No existing test
        // in this module calls needs_compaction at all.
        let mut seg_mgr = LfsSegmentManager::new(100, 8);
        seg_mgr.mark_used(0);
        // 99 segments free (far above the 10% = 10 threshold).
        assert!(
            !needs_compaction(&seg_mgr),
            "far above the free-segment threshold must not trigger compaction"
        );

        // Drain down to just below the threshold (9 free, threshold 10).
        while seg_mgr.free_count() > 9 {
            seg_mgr.allocate_for_compaction();
        }
        assert_eq!(seg_mgr.free_count(), 9);
        assert!(
            needs_compaction(&seg_mgr),
            "free_count below the 10% threshold must trigger compaction"
        );
    }

    #[test]
    fn needs_compaction_requires_at_least_one_free_segment_floor() {
        // A small filesystem where 10% of total rounds down to 0 must
        // still require at least 1 free segment (the `.max(1)` floor), not
        // treat "0 free required" as never needing compaction.
        let mut seg_mgr = LfsSegmentManager::new(4, 8);
        seg_mgr.mark_used(0);
        // 3 segments free; threshold floors to 1, so this must not
        // trigger yet.
        assert!(
            !needs_compaction(&seg_mgr),
            "3 free segments (above the floor of 1) must not trigger compaction"
        );

        // Drain all free segments (bypassing the compaction-reserve floor
        // via allocate_for_compaction) down to zero.
        while seg_mgr.allocate_for_compaction().is_some() {}
        assert_eq!(seg_mgr.free_count(), 0);
        assert!(
            needs_compaction(&seg_mgr),
            "zero free segments must trigger compaction even when 10% of total rounds to 0"
        );
    }

    #[test]
    fn needs_compaction_zero_segments_is_false() {
        let seg_mgr = LfsSegmentManager::new(0, 8);
        assert!(
            !needs_compaction(&seg_mgr),
            "a filesystem with zero segments must not report needing compaction"
        );
    }
}
