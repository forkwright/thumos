//! Dual-slot checkpointing for the log-structured filesystem.
//!
//! The LFS uses two alternating checkpoint slots for crash safety. Each
//! checkpoint records the location of the imap, the segment bitmap, and
//! other metadata needed to recover the filesystem state. On mount, the
//! slot with the higher sequence number is selected as the current state.
//!
//! Checkpoint layout (at each slot block):
//! - Block 0: [`CheckpointHeader`] (256 bytes, padded to block size)
//! - Blocks 1..N: imap data (written separately by the imap module)
//! - Blocks N+1..M: segment bitmap data (written separately by the segment module)

extern crate alloc;
use alloc::vec::Vec;

use crate::block::{BlockDevice, BLOCK_SIZE};
use crate::cache::BlockCache;
use crate::lfs_imap::LfsError;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Magic number for checkpoint headers: "CKPT" in ASCII.
pub(crate) const CHECKPOINT_MAGIC: u32 = 0x434B_5054;

/// Number of blocks reserved for each checkpoint slot: 1 header block plus
/// headroom for the imap + segment-bitmap payload. WHY 64: at 4 KiB/block
/// this reserves ~258 KiB per slot (tens of thousands of imap entries),
/// far beyond any inode/segment count this device can host, while keeping
/// slot A and slot B far enough apart that neither slot's payload can
/// ever reach the other slot's header block (#319).
pub(crate) const CHECKPOINT_SLOT_BLOCKS: u64 = 64;

// ---------------------------------------------------------------------------
// CheckpointHeader
// ---------------------------------------------------------------------------

/// On-disk checkpoint header.
///
/// Stored at the first block of each checkpoint slot. Contains pointers
/// to the imap and segment bitmap data that were written as part of this
/// checkpoint. The `sequence` field is used to determine which of the
/// two checkpoint slots is more recent.
///
/// The header is 256 bytes, stored at the beginning of a 4 KiB block.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct CheckpointHeader {
    /// Magic number ([`CHECKPOINT_MAGIC`]).
    pub magic: u32,
    /// Checkpoint sequence number (monotonically increasing).
    pub sequence: u64,
    /// Block number where the imap data starts.
    pub imap_block: u64,
    /// Number of blocks occupied by the imap.
    pub imap_block_count: u32,
    /// Block number where the segment bitmap data starts.
    pub segment_bitmap_block: u64,
    /// Number of blocks occupied by the segment bitmap.
    pub segment_bitmap_count: u32,
    /// Next available inode number at checkpoint time.
    pub next_inode: u32,
    /// Sequence number of the last segment written before this checkpoint.
    pub last_segment_sequence: u64,
}

/// Size of the serialized checkpoint header.
const HEADER_SERIALIZED_SIZE: usize = 4 + 8 + 8 + 4 + 8 + 4 + 4 + 8; // 48 bytes of data

impl CheckpointHeader {
    /// Serialize the header to a 4 KiB block buffer.
    ///
    /// The header fields are written in little-endian byte order at the
    /// start of the buffer. The remainder is zero-padded.
    ///
    /// # Errors
    ///
    /// This method is infallible.
    pub(crate) fn to_block(&self) -> [u8; BLOCK_SIZE] {
        let mut buf = [0u8; BLOCK_SIZE];
        let mut offset = 0;

        write_u32_le(&mut buf, &mut offset, self.magic);
        write_u64_le(&mut buf, &mut offset, self.sequence);
        write_u64_le(&mut buf, &mut offset, self.imap_block);
        write_u32_le(&mut buf, &mut offset, self.imap_block_count);
        write_u64_le(&mut buf, &mut offset, self.segment_bitmap_block);
        write_u32_le(&mut buf, &mut offset, self.segment_bitmap_count);
        write_u32_le(&mut buf, &mut offset, self.next_inode);
        write_u64_le(&mut buf, &mut offset, self.last_segment_sequence);

        buf
    }

    /// Deserialize a header from a 4 KiB block buffer.
    ///
    /// # Errors
    ///
    /// Returns [`LfsError::Corrupt`] if the magic number does not match.
    #[must_use]
    pub(crate) fn from_block(buf: &[u8; BLOCK_SIZE]) -> Result<Self, LfsError> {
        if buf.len() < HEADER_SERIALIZED_SIZE {
            return Err(LfsError::Corrupt);
        }

        let mut offset = 0;

        let magic = read_u32_le(buf, &mut offset);
        if magic != CHECKPOINT_MAGIC {
            return Err(LfsError::Corrupt);
        }

        let sequence = read_u64_le(buf, &mut offset);
        let imap_block = read_u64_le(buf, &mut offset);
        let imap_block_count = read_u32_le(buf, &mut offset);
        let segment_bitmap_block = read_u64_le(buf, &mut offset);
        let segment_bitmap_count = read_u32_le(buf, &mut offset);
        let next_inode = read_u32_le(buf, &mut offset);
        let last_segment_sequence = read_u64_le(buf, &mut offset);

        Ok(Self {
            magic,
            sequence,
            imap_block,
            imap_block_count,
            segment_bitmap_block,
            segment_bitmap_count,
            next_inode,
            last_segment_sequence,
        })
    }
}

// ---------------------------------------------------------------------------
// Checkpoint I/O
// ---------------------------------------------------------------------------

/// Write a checkpoint to a slot on disk.
///
/// Writes the checkpoint header at `slot_block`, then the imap data and
/// segment bitmap data at consecutive blocks after the header.
///
/// # Errors
///
/// Returns [`LfsError::BlockIo`] if any block write fails.
pub(crate) fn write_checkpoint(
    dev: &mut dyn BlockDevice,
    cache: &mut BlockCache,
    slot_block: u64,
    header: &CheckpointHeader,
    imap_data: &[u8],
    segment_data: &[u8],
) -> Result<(), LfsError> {
    // Reject a checkpoint whose imap + segment-bitmap payload would run
    // past this slot's reserved region and into the adjacent slot's
    // header block. Fail closed before any bytes are written so a
    // rejected checkpoint leaves the previously-committed slot untouched
    // (#319).
    let slot_end = slot_block + CHECKPOINT_SLOT_BLOCKS;
    let payload_end = header.segment_bitmap_block + u64::from(header.segment_bitmap_count);
    if header.imap_block <= slot_block || payload_end > slot_end {
        return Err(LfsError::CheckpointOverflow);
    }

    // Write imap data blocks.
    let imap_blocks = blocks_needed(imap_data.len());
    let mut padded_imap = Vec::from(imap_data);
    padded_imap.resize(imap_blocks * BLOCK_SIZE, 0);

    for i in 0..imap_blocks {
        let offset = i * BLOCK_SIZE;
        let block_data: &[u8; BLOCK_SIZE] = padded_imap[offset..offset + BLOCK_SIZE]
            .try_into()
            .map_err(|_| LfsError::Corrupt)?;
        cache.write(dev, header.imap_block + i as u64, block_data)?;
    }

    // Write segment bitmap data blocks.
    let seg_blocks = blocks_needed(segment_data.len());
    let mut padded_seg = Vec::from(segment_data);
    padded_seg.resize(seg_blocks * BLOCK_SIZE, 0);

    for i in 0..seg_blocks {
        let offset = i * BLOCK_SIZE;
        let block_data: &[u8; BLOCK_SIZE] = padded_seg[offset..offset + BLOCK_SIZE]
            .try_into()
            .map_err(|_| LfsError::Corrupt)?;
        cache.write(
            dev,
            header.segment_bitmap_block + i as u64,
            block_data,
        )?;
    }

    // WHY: flush the imap + segment-bitmap payload to media BEFORE the
    // header is written. A crash between this flush and the header write
    // leaves the slot's prior (still-valid) header in place instead of a
    // new header pointing at data that never landed (#320).
    cache.flush(dev)?;

    // Write and commit the header last: it is the single point at which
    // this checkpoint becomes selectable by `pick_latest`.
    let header_buf = header.to_block();
    cache.write(dev, slot_block, &header_buf)?;
    cache.flush(dev)?;

    Ok(())
}

/// Read a checkpoint header from a slot on disk.
///
/// # Errors
///
/// - [`LfsError::BlockIo`] if the block read fails.
/// - [`LfsError::Corrupt`] if the magic number does not match.
pub(crate) fn read_checkpoint(
    dev: &mut dyn BlockDevice,
    cache: &mut BlockCache,
    slot_block: u64,
) -> Result<CheckpointHeader, LfsError> {
    let mut buf = [0u8; BLOCK_SIZE];
    cache.read(dev, slot_block, &mut buf)?;
    CheckpointHeader::from_block(&buf)
}

/// Read both checkpoint slots and return the one with the higher sequence.
///
/// Returns `(header, slot_block)` for the winning checkpoint. If only one
/// slot has a valid magic, that one is returned. If both are corrupt, returns
/// [`LfsError::Corrupt`].
///
/// # Errors
///
/// Returns [`LfsError::Corrupt`] if neither checkpoint slot is valid.
/// Returns [`LfsError::BlockIo`] if block reads fail on both slots.
pub(crate) fn pick_latest(
    dev: &mut dyn BlockDevice,
    cache: &mut BlockCache,
    slot_a_block: u64,
    slot_b_block: u64,
) -> Result<(CheckpointHeader, u64), LfsError> {
    let a = read_checkpoint(dev, cache, slot_a_block);
    let b = read_checkpoint(dev, cache, slot_b_block);

    match (a, b) {
        (Ok(ha), Ok(hb)) => {
            if ha.sequence >= hb.sequence {
                Ok((ha, slot_a_block))
            } else {
                Ok((hb, slot_b_block))
            }
        }
        (Ok(ha), Err(_)) => Ok((ha, slot_a_block)),
        (Err(_), Ok(hb)) => Ok((hb, slot_b_block)),
        // WHY: only collapse to Corrupt when at least one read failed on
        // a parse/magic mismatch; two transient BlockIo failures are a
        // recoverable I/O fault, not proof the metadata is corrupt
        // (#326).
        (Err(ea), Err(eb)) => match (ea, eb) {
            (LfsError::BlockIo(_), LfsError::BlockIo(_)) => Err(ea),
            _ => Err(LfsError::Corrupt),
        },
    }
}

// ---------------------------------------------------------------------------
// Byte-order helpers
// ---------------------------------------------------------------------------

fn write_u32_le(buf: &mut [u8], offset: &mut usize, val: u32) {
    buf[*offset..*offset + 4].copy_from_slice(&val.to_le_bytes());
    *offset += 4;
}

fn write_u64_le(buf: &mut [u8], offset: &mut usize, val: u64) {
    buf[*offset..*offset + 8].copy_from_slice(&val.to_le_bytes());
    *offset += 8;
}

fn read_u32_le(buf: &[u8], offset: &mut usize) -> u32 {
    let val = u32::from_le_bytes([
        buf[*offset],
        buf[*offset + 1],
        buf[*offset + 2],
        buf[*offset + 3],
    ]);
    *offset += 4;
    val
}

fn read_u64_le(buf: &[u8], offset: &mut usize) -> u64 {
    let val = u64::from_le_bytes([
        buf[*offset],
        buf[*offset + 1],
        buf[*offset + 2],
        buf[*offset + 3],
        buf[*offset + 4],
        buf[*offset + 5],
        buf[*offset + 6],
        buf[*offset + 7],
    ]);
    *offset += 8;
    val
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
    use alloc::vec;

    use super::*;
    use crate::block::MemBlockDevice;

    /// Create an 8 MB test device (16384 sectors = 2048 blocks).
    fn block_device_for_checkpoint() -> MemBlockDevice {
        MemBlockDevice::new(16384).expect("create test device")
    }

    #[test]
    fn write_and_read_checkpoint_round_trips() {
        let mut dev = block_device_for_checkpoint();
        let mut cache = BlockCache::new();

        let header = CheckpointHeader {
            magic: CHECKPOINT_MAGIC,
            sequence: 42,
            imap_block: 10,
            imap_block_count: 1,
            segment_bitmap_block: 11,
            segment_bitmap_count: 1,
            next_inode: 5,
            last_segment_sequence: 100,
        };

        let imap_data = vec![0xAA; 128];
        let segment_data = vec![0xBB; 64];

        write_checkpoint(&mut dev, &mut cache, 1, &header, &imap_data, &segment_data)
            .expect("write checkpoint");

        let mut cache2 = BlockCache::new();
        let restored = read_checkpoint(&mut dev, &mut cache2, 1).expect("read checkpoint");

        assert_eq!(restored.magic, CHECKPOINT_MAGIC);
        assert_eq!(restored.sequence, 42);
        assert_eq!(restored.imap_block, 10);
        assert_eq!(restored.imap_block_count, 1);
        assert_eq!(restored.segment_bitmap_block, 11);
        assert_eq!(restored.segment_bitmap_count, 1);
        assert_eq!(restored.next_inode, 5);
        assert_eq!(restored.last_segment_sequence, 100);
    }

    #[test]
    fn pick_latest_returns_higher_sequence() {
        let mut dev = block_device_for_checkpoint();
        let mut cache = BlockCache::new();

        let header_a = CheckpointHeader {
            magic: CHECKPOINT_MAGIC,
            sequence: 10,
            imap_block: 20,
            imap_block_count: 1,
            segment_bitmap_block: 21,
            segment_bitmap_count: 1,
            next_inode: 3,
            last_segment_sequence: 50,
        };

        let header_b = CheckpointHeader {
            magic: CHECKPOINT_MAGIC,
            sequence: 20,
            imap_block: 30,
            imap_block_count: 1,
            segment_bitmap_block: 31,
            segment_bitmap_count: 1,
            next_inode: 7,
            last_segment_sequence: 80,
        };

        let imap_data = vec![0; 16];
        let seg_data = vec![0; 16];

        write_checkpoint(&mut dev, &mut cache, 1, &header_a, &imap_data, &seg_data)
            .expect("write A");
        write_checkpoint(&mut dev, &mut cache, 5, &header_b, &imap_data, &seg_data)
            .expect("write B");

        let mut cache2 = BlockCache::new();
        let (latest, slot) =
            pick_latest(&mut dev, &mut cache2, 1, 5).expect("pick latest");

        assert_eq!(latest.sequence, 20, "should pick higher sequence");
        assert_eq!(slot, 5, "should return slot B block");
        assert_eq!(latest.next_inode, 7);
    }

    #[test]
    fn pick_latest_handles_one_corrupt_slot() {
        let mut dev = block_device_for_checkpoint();
        let mut cache = BlockCache::new();

        let header = CheckpointHeader {
            magic: CHECKPOINT_MAGIC,
            sequence: 5,
            imap_block: 10,
            imap_block_count: 1,
            segment_bitmap_block: 11,
            segment_bitmap_count: 1,
            next_inode: 2,
            last_segment_sequence: 30,
        };

        let imap_data = vec![0; 16];
        let seg_data = vec![0; 16];

        // Only write to slot A. Slot B is zeroed (corrupt magic).
        write_checkpoint(&mut dev, &mut cache, 1, &header, &imap_data, &seg_data)
            .expect("write A");

        let mut cache2 = BlockCache::new();
        let (latest, slot) =
            pick_latest(&mut dev, &mut cache2, 1, 100).expect("pick with corrupt B");

        assert_eq!(latest.sequence, 5);
        assert_eq!(slot, 1, "should pick the valid slot");
    }

    #[test]
    fn pick_latest_returns_error_when_both_corrupt() {
        let mut dev = block_device_for_checkpoint();
        let mut cache = BlockCache::new();

        // Both slots are zeroed (invalid magic).
        let result = pick_latest(&mut dev, &mut cache, 1, 5);
        assert!(
            matches!(result, Err(LfsError::Corrupt)),
            "expected Corrupt when both checkpoint slots are invalid"
        );
    }

    #[test]
    fn pick_latest_propagates_block_io_when_both_reads_fail() {
        let mut dev = block_device_for_checkpoint();
        let mut cache = BlockCache::new();

        // Both slot blocks are beyond the device's block count, so each
        // read fails with BlockError::OutOfBounds (a transient/
        // environmental I/O fault), not a magic-mismatch parse failure.
        let result = pick_latest(&mut dev, &mut cache, 5000, 6000);

        assert!(
            matches!(result, Err(LfsError::BlockIo(_))),
            "two transient BlockIo failures must not be reported as Corrupt"
        );
    }

    #[test]
    fn header_round_trips_through_block() {
        let header = CheckpointHeader {
            magic: CHECKPOINT_MAGIC,
            sequence: 999,
            imap_block: 42,
            imap_block_count: 3,
            segment_bitmap_block: 45,
            segment_bitmap_count: 2,
            next_inode: 128,
            last_segment_sequence: 500,
        };

        let block = header.to_block();
        let restored =
            CheckpointHeader::from_block(&block).expect("from_block should succeed");

        assert_eq!(restored.sequence, 999);
        assert_eq!(restored.imap_block, 42);
        assert_eq!(restored.imap_block_count, 3);
        assert_eq!(restored.segment_bitmap_block, 45);
        assert_eq!(restored.segment_bitmap_count, 2);
        assert_eq!(restored.next_inode, 128);
        assert_eq!(restored.last_segment_sequence, 500);
    }

    #[test]
    fn crash_between_data_and_header_write_leaves_prior_checkpoint_selectable() {
        let mut dev = block_device_for_checkpoint();
        let mut cache = BlockCache::new();

        // Commit a full, valid checkpoint first -- this is the "prior
        // good" state the dual-slot design exists to preserve.
        let header_v1 = CheckpointHeader {
            magic: CHECKPOINT_MAGIC,
            sequence: 1,
            imap_block: 10,
            imap_block_count: 1,
            segment_bitmap_block: 11,
            segment_bitmap_count: 1,
            next_inode: 2,
            last_segment_sequence: 5,
        };
        let imap_v1 = vec![0xAA; 16];
        let seg_v1 = vec![0xBB; 16];
        write_checkpoint(&mut dev, &mut cache, 1, &header_v1, &imap_v1, &seg_v1)
            .expect("write v1 checkpoint");

        // Simulate a crash between the data write and the header write of
        // a would-be v2 checkpoint: the new imap payload lands on disk,
        // but the header at slot_block (1) is never rewritten. With
        // write_checkpoint now committing data before the header (#320),
        // this is exactly what an interrupted checkpoint looks like on
        // media.
        let torn_block = [0xCCu8; BLOCK_SIZE];
        cache
            .write(&mut dev, header_v1.imap_block, &torn_block)
            .expect("write torn imap payload");
        cache.flush(&mut dev).expect("flush torn payload");

        // The slot's header must still be the v1 header: pick_latest must
        // not be misled into thinking a new checkpoint landed.
        let mut cache2 = BlockCache::new();
        let (selected, slot) = pick_latest(&mut dev, &mut cache2, 1, 100)
            .expect("prior checkpoint must remain selectable");

        assert_eq!(selected.sequence, 1, "an uncommitted header must not win");
        assert_eq!(slot, 1);
    }

    #[test]
    fn write_checkpoint_rejects_payload_exceeding_slot_capacity() {
        let mut dev = block_device_for_checkpoint();
        let mut cache = BlockCache::new();

        // A header claiming a segment-bitmap payload that runs past the
        // slot's reserved region (slot_block + CHECKPOINT_SLOT_BLOCKS)
        // must be rejected before anything is written (#319).
        let slot_block = 1u64;
        let header = CheckpointHeader {
            magic: CHECKPOINT_MAGIC,
            sequence: 1,
            imap_block: slot_block + 1,
            imap_block_count: 1,
            segment_bitmap_block: slot_block + CHECKPOINT_SLOT_BLOCKS - 1,
            segment_bitmap_count: 5,
            next_inode: 1,
            last_segment_sequence: 1,
        };

        let imap_data = vec![0u8; BLOCK_SIZE];
        let segment_data = vec![0u8; BLOCK_SIZE];

        let result = write_checkpoint(
            &mut dev,
            &mut cache,
            slot_block,
            &header,
            &imap_data,
            &segment_data,
        );
        assert!(
            matches!(result, Err(LfsError::CheckpointOverflow)),
            "oversized checkpoint payload must be rejected, not written past the slot"
        );

        // Nothing should have been written for this rejected checkpoint.
        let mut cache2 = BlockCache::new();
        assert!(read_checkpoint(&mut dev, &mut cache2, slot_block).is_err());
    }
}
