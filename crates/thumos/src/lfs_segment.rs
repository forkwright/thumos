//! Segment manager for the log-structured filesystem.
//!
//! Tracks which segments are free or in use and manages segment allocation.
//! Each segment is a contiguous group of blocks (default 256 blocks = 1 MiB).
//! Segment 0 is always reserved for the superblock and metadata.
//!
//! The segment bitmap is serialized as a packed bitfield for on-disk storage
//! within checkpoints.

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use crate::lfs_imap::LfsError;

// ---------------------------------------------------------------------------
// LfsSegmentManager
// ---------------------------------------------------------------------------

/// Manages segment allocation and tracking for the LFS.
///
/// Each segment is a contiguous run of [`Self::segment_size`] blocks.
/// The manager maintains a bitmap of segment usage and tracks the
/// number of free segments for quick capacity checks.
pub struct LfsSegmentManager {
    /// Segment usage bitmap. `true` means the segment is in use.
    bitmap: Vec<bool>,
    /// Total number of segments in the filesystem.
    segment_count: u32,
    /// Number of blocks per segment.
    segment_size: u32,
    /// Number of free (unused) segments.
    free_count: u32,
}

impl LfsSegmentManager {
    /// Create a new segment manager.
    ///
    /// All segments start free except segment 0, which is reserved for the
    /// superblock and initial metadata.
    ///
    /// # Errors
    ///
    /// This method is infallible.
    pub fn new(segment_count: u32, segment_size: u32) -> Self {
        let mut bitmap = vec![false; segment_count as usize];

        // Segment 0 is always reserved for the superblock.
        if segment_count > 0 {
            bitmap[0] = true;
        }

        let free_count = if segment_count > 0 {
            segment_count - 1
        } else {
            0
        };

        Self {
            bitmap,
            segment_count,
            segment_size,
            free_count,
        }
    }

    /// Allocate the first available free segment.
    ///
    /// Returns the segment index, or `None` if no free segments remain.
    /// The allocated segment is marked as in-use.
    ///
    /// # Errors
    ///
    /// This method is infallible; returns `None` when full.
    pub fn allocate(&mut self) -> Option<u32> {
        for i in 0..self.bitmap.len() {
            if !self.bitmap[i] {
                self.bitmap[i] = true;
                self.free_count -= 1;
                return Some(i as u32);
            }
        }
        None
    }

    /// Mark a segment as free.
    ///
    /// # Errors
    ///
    /// This method is infallible. Freeing an already-free segment or an
    /// out-of-range index is a no-op.
    pub fn free(&mut self, segment_idx: u32) {
        let idx = segment_idx as usize;
        if idx < self.bitmap.len() && self.bitmap[idx] {
            self.bitmap[idx] = false;
            self.free_count += 1;
        }
    }

    /// Check whether a segment is free.
    ///
    /// Returns `false` for out-of-range indices.
    ///
    /// # Errors
    ///
    /// This method is infallible.
    pub fn is_free(&self, segment_idx: u32) -> bool {
        let idx = segment_idx as usize;
        if idx < self.bitmap.len() {
            !self.bitmap[idx]
        } else {
            false
        }
    }

    /// Return the number of free segments.
    ///
    /// # Errors
    ///
    /// This method is infallible.
    pub fn free_count(&self) -> u32 {
        self.free_count
    }

    /// Return the total number of segments.
    ///
    /// # Errors
    ///
    /// This method is infallible.
    pub fn segment_count(&self) -> u32 {
        self.segment_count
    }

    /// Return the number of blocks per segment.
    ///
    /// # Errors
    ///
    /// This method is infallible.
    pub fn segment_size(&self) -> u32 {
        self.segment_size
    }

    /// Compute the starting block number for a segment.
    ///
    /// # Errors
    ///
    /// This method is infallible.
    pub fn segment_start_block(&self, segment_idx: u32) -> u64 {
        u64::from(segment_idx) * u64::from(self.segment_size)
    }

    /// Mark a segment as in-use.
    ///
    /// # Errors
    ///
    /// This method is infallible. Marking an already-used segment is a no-op.
    pub fn mark_used(&mut self, segment_idx: u32) {
        let idx = segment_idx as usize;
        if idx < self.bitmap.len() && !self.bitmap[idx] {
            self.bitmap[idx] = true;
            self.free_count -= 1;
        }
    }

    /// Serialize the segment bitmap to bytes.
    ///
    /// Format: `segment_count: u32` (LE), `segment_size: u32` (LE), followed
    /// by a packed bitfield where each bit represents one segment (bit 0 of
    /// byte 0 = segment 0, bit 1 of byte 0 = segment 1, etc.). `1` = in use,
    /// `0` = free.
    ///
    /// # Errors
    ///
    /// This method is infallible.
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.segment_count.to_le_bytes());
        buf.extend_from_slice(&self.segment_size.to_le_bytes());

        // Pack bitmap into bytes, 8 segments per byte.
        let byte_count = (self.segment_count as usize + 7) / 8;
        for byte_idx in 0..byte_count {
            let mut byte_val: u8 = 0;
            for bit in 0..8 {
                let seg_idx = byte_idx * 8 + bit;
                if seg_idx < self.bitmap.len() && self.bitmap[seg_idx] {
                    byte_val |= 1 << bit;
                }
            }
            buf.push(byte_val);
        }

        buf
    }

    /// Deserialize a segment manager from bytes.
    ///
    /// The `segment_count` and `segment_size` parameters are used to validate
    /// the deserialized data against expected filesystem geometry.
    ///
    /// # Errors
    ///
    /// Returns [`LfsError::Corrupt`] if the data is too short or the stored
    /// geometry does not match the expected values.
    pub fn deserialize(
        data: &[u8],
        segment_count: u32,
        segment_size: u32,
    ) -> Result<Self, LfsError> {
        if data.len() < 8 {
            return Err(LfsError::Corrupt);
        }

        let stored_count = u32::from_le_bytes(
            data[..4].try_into().map_err(|_| LfsError::Corrupt)?,
        );
        let stored_size = u32::from_le_bytes(
            data[4..8].try_into().map_err(|_| LfsError::Corrupt)?,
        );

        if stored_count != segment_count || stored_size != segment_size {
            return Err(LfsError::Corrupt);
        }

        let byte_count = (segment_count as usize + 7) / 8;
        let bitmap_data = &data[8..];
        if bitmap_data.len() < byte_count {
            return Err(LfsError::Corrupt);
        }

        let mut bitmap = vec![false; segment_count as usize];
        let mut free_count = 0u32;

        for (seg_idx, used) in bitmap.iter_mut().enumerate() {
            let byte_idx = seg_idx / 8;
            let bit_idx = seg_idx % 8;
            *used = (bitmap_data[byte_idx] >> bit_idx) & 1 == 1;
            if !*used {
                free_count += 1;
            }
        }

        Ok(Self {
            bitmap,
            segment_count,
            segment_size,
            free_count,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocate_returns_first_free() {
        // Segment 0 is reserved, so the first allocation returns segment 1.
        let mut mgr = LfsSegmentManager::new(8, 256);
        let seg = mgr.allocate();
        assert_eq!(seg, Some(1), "first free segment should be 1 (0 is reserved)");
    }

    #[test]
    fn free_makes_segment_available() {
        let mut mgr = LfsSegmentManager::new(4, 256);
        let seg = mgr.allocate().expect("should allocate");
        assert!(!mgr.is_free(seg));

        mgr.free(seg);
        assert!(mgr.is_free(seg), "freed segment should be available");
    }

    #[test]
    fn allocate_skips_segment_zero() {
        let mut mgr = LfsSegmentManager::new(4, 256);

        // Allocate all available segments.
        let mut allocated = Vec::new();
        while let Some(seg) = mgr.allocate() {
            allocated.push(seg);
        }

        // Segment 0 should never appear in allocations.
        assert!(
            !allocated.contains(&0),
            "segment 0 should never be allocated"
        );
        assert_eq!(allocated, &[1, 2, 3]);
    }

    #[test]
    fn free_count_tracks_correctly() {
        let mut mgr = LfsSegmentManager::new(8, 256);
        // 8 segments total, segment 0 reserved = 7 free.
        assert_eq!(mgr.free_count(), 7);

        mgr.allocate();
        assert_eq!(mgr.free_count(), 6);

        mgr.allocate();
        assert_eq!(mgr.free_count(), 5);

        mgr.free(1);
        assert_eq!(mgr.free_count(), 6);
    }

    #[test]
    fn serialize_deserialize_round_trips() {
        let mut mgr = LfsSegmentManager::new(16, 256);
        mgr.allocate(); // seg 1
        mgr.allocate(); // seg 2
        mgr.allocate(); // seg 3
        mgr.free(2);    // free seg 2

        let data = mgr.serialize();
        let restored =
            LfsSegmentManager::deserialize(&data, 16, 256).expect("deserialize should succeed");

        assert_eq!(restored.segment_count(), 16);
        assert_eq!(restored.segment_size(), 256);
        assert!(!restored.is_free(0), "segment 0 should be in use");
        assert!(!restored.is_free(1), "segment 1 should be in use");
        assert!(restored.is_free(2), "segment 2 should be free");
        assert!(!restored.is_free(3), "segment 3 should be in use");
        assert!(restored.is_free(4), "segment 4 should be free");
        assert_eq!(restored.free_count(), mgr.free_count());
    }

    #[test]
    fn segment_start_block_computes_correctly() {
        let mgr = LfsSegmentManager::new(8, 256);
        assert_eq!(mgr.segment_start_block(0), 0);
        assert_eq!(mgr.segment_start_block(1), 256);
        assert_eq!(mgr.segment_start_block(7), 7 * 256);
    }

    #[test]
    fn is_free_returns_false_for_out_of_range() {
        let mgr = LfsSegmentManager::new(4, 256);
        assert!(!mgr.is_free(100));
    }

    #[test]
    fn free_out_of_range_is_noop() {
        let mut mgr = LfsSegmentManager::new(4, 256);
        let before = mgr.free_count();
        mgr.free(100);
        assert_eq!(mgr.free_count(), before);
    }

    #[test]
    fn deserialize_rejects_mismatched_geometry() {
        let mgr = LfsSegmentManager::new(8, 256);
        let data = mgr.serialize();

        // Wrong segment count.
        let result = LfsSegmentManager::deserialize(&data, 16, 256);
        assert!(
            matches!(result, Err(LfsError::Corrupt)),
            "expected Corrupt for wrong segment count"
        );

        // Wrong segment size.
        let result = LfsSegmentManager::deserialize(&data, 8, 128);
        assert!(
            matches!(result, Err(LfsError::Corrupt)),
            "expected Corrupt for wrong segment size"
        );
    }

    #[test]
    fn mark_used_sets_segment() {
        let mut mgr = LfsSegmentManager::new(8, 256);
        assert!(mgr.is_free(5));
        mgr.mark_used(5);
        assert!(!mgr.is_free(5));
    }
}
