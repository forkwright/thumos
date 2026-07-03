//! LRU block cache for block devices.
//!
//! Provides a fixed-size cache operating at 4 KiB logical-block granularity
//! over a [`BlockDevice`]. The cache holds up to [`CACHE_ENTRIES`] blocks
//! (1 MiB total) and uses LRU eviction. Dirty entries are written back to
//! the device before eviction.
//!
//! # Design
//!
//! - Single-threaded (bare-metal, no locking required).
//! - Heap-allocated backing store (`Vec<CacheEntry>`) to avoid 1 MiB stack usage.
//! - Each cache miss reads [`SECTORS_PER_BLOCK`] sectors (8 x 512 bytes = 4 KiB).
//! - Write-back policy: writes go to cache only; [`BlockCache::flush`] commits
//!   dirty entries to the device.

extern crate alloc;
use alloc::vec::Vec;

use crate::block::{BlockDevice, BlockError, BLOCK_SIZE, SECTORS_PER_BLOCK};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Number of cache entries (256 x 4 KiB = 1 MiB of cached data).
pub(crate) const CACHE_ENTRIES: usize = 256;

// ---------------------------------------------------------------------------
// CacheEntry
// ---------------------------------------------------------------------------

/// A single entry in the block cache.
struct CacheEntry {
    /// Logical block number this entry maps to.
    block_num: u64,
    /// Cached block data (4 KiB).
    data: [u8; BLOCK_SIZE],
    /// Whether this entry has been written but not flushed to device.
    dirty: bool,
    /// Whether this entry contains valid data.
    valid: bool,
    /// LRU counter — higher values are more recently used.
    lru_counter: u64,
}

impl CacheEntry {
    /// Create a new invalid (empty) cache entry.
    fn new() -> Self {
        Self {
            block_num: 0,
            data: [0u8; BLOCK_SIZE],
            dirty: false,
            valid: false,
            lru_counter: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// BlockCache
// ---------------------------------------------------------------------------

/// Fixed-size LRU block cache for 4 KiB logical blocks.
///
/// The cache is backed by a heap-allocated `Vec<CacheEntry>` to avoid placing
/// 1 MiB on the stack. Cache entries are evicted using a simple LRU counter:
/// every access increments a global counter and stamps the accessed entry.
/// On eviction, the entry with the lowest counter value is selected.
pub(crate) struct BlockCache {
    /// Heap-allocated cache entries.
    entries: Vec<CacheEntry>,
    /// Monotonically increasing counter for LRU tracking.
    counter: u64,
}

impl BlockCache {
    /// Create a new block cache with all entries marked invalid.
    pub(crate) fn new() -> Self {
        let mut entries = Vec::with_capacity(CACHE_ENTRIES);
        for _ in 0..CACHE_ENTRIES {
            entries.push(CacheEntry::new());
        }
        Self {
            entries,
            counter: 0,
        }
    }

    /// Read a 4 KiB logical block, using the cache when possible.
    ///
    /// On a cache hit, copies cached data to `buf`. On a cache miss, reads
    /// [`SECTORS_PER_BLOCK`] sectors from `dev`, fills a cache entry, then
    /// copies to `buf`. If all entries are occupied, the least-recently-used
    /// entry is evicted (flushing it to `dev` if dirty).
    ///
    /// # Errors
    ///
    /// Returns [`BlockError`] if the underlying device read or a dirty-entry
    /// write-back fails.
    pub(crate) fn read(
        &mut self,
        dev: &mut dyn BlockDevice,
        block_num: u64,
        buf: &mut [u8; BLOCK_SIZE],
    ) -> Result<(), BlockError> {
        // Check for cache hit.
        if let Some(idx) = self.find_entry(block_num) {
            self.touch(idx);
            buf.copy_from_slice(&self.entries[idx].data);
            return Ok(());
        }

        // Cache miss — need to load from device. Allocation may write back
        // a dirty evictee.
        let idx = self.allocate_entry(dev)?;

        // Read SECTORS_PER_BLOCK sectors from the device into the entry.
        let lba = block_num * SECTORS_PER_BLOCK as u64;
        dev.read_sectors(lba, SECTORS_PER_BLOCK as u32, &mut self.entries[idx].data)?;

        self.entries[idx].block_num = block_num;
        self.entries[idx].valid = true;
        self.entries[idx].dirty = false;
        self.touch(idx);

        buf.copy_from_slice(&self.entries[idx].data);
        Ok(())
    }

    /// Write a 4 KiB logical block to the cache.
    ///
    /// The data is written to a cache entry and marked dirty. It is NOT
    /// immediately written to the device — call [`BlockCache::flush`] to
    /// commit dirty entries. If a dirty entry must be evicted to make room,
    /// it is written back to `dev` first.
    ///
    /// # Errors
    ///
    /// Returns [`BlockError`] if evicting a dirty entry for the new write fails.
    pub(crate) fn write(
        &mut self,
        dev: &mut dyn BlockDevice,
        block_num: u64,
        buf: &[u8; BLOCK_SIZE],
    ) -> Result<(), BlockError> {
        let idx = match self.find_entry(block_num) {
            Some(idx) => idx,
            None => self.allocate_entry(dev)?,
        };

        self.entries[idx].data.copy_from_slice(buf);
        self.entries[idx].block_num = block_num;
        self.entries[idx].valid = true;
        self.entries[idx].dirty = true;
        self.touch(idx);
        Ok(())
    }

    /// Flush all dirty cache entries to the device.
    ///
    /// Every dirty entry is attempted, even after an earlier one fails --
    /// a single persistently-failing block must not permanently block
    /// flushing of every entry that sorts after it in the cache (#375).
    /// Entries that flush successfully are marked clean regardless of
    /// failures elsewhere in the same pass.
    ///
    /// # Errors
    ///
    /// Returns the first [`BlockError`] encountered, if any. Entries that
    /// flushed successfully (including ones after the first failure) are
    /// marked clean; the entry (or entries) that failed remain dirty and
    /// are retried on the next `flush` call.
    pub(crate) fn flush(&mut self, dev: &mut dyn BlockDevice) -> Result<(), BlockError> {
        let mut first_err = None;
        for i in 0..self.entries.len() {
            if self.entries[i].valid && self.entries[i].dirty
                && let Err(e) = self.write_back(dev, i)
            {
                first_err.get_or_insert(e);
            }
        }
        match first_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// Sync all dirty cache entries to the device.
    ///
    /// This is an alias for [`BlockCache::flush`].
    ///
    /// # Errors
    ///
    /// Returns [`BlockError`] if any write-back fails.
    pub(crate) fn sync(&mut self, dev: &mut dyn BlockDevice) -> Result<(), BlockError> {
        self.flush(dev)
    }

    /// Invalidate all cache entries, discarding any dirty data.
    ///
    /// After invalidation, all entries are empty. Any unflushed dirty data
    /// is lost — call [`BlockCache::flush`] first if dirty data must be
    /// preserved.
    pub(crate) fn invalidate(&mut self) {
        for entry in &mut self.entries {
            entry.valid = false;
            entry.dirty = false;
            entry.lru_counter = 0;
        }
        self.counter = 0;
    }

    // -- Internal helpers --

    /// Find the cache entry index for `block_num`, if it exists and is valid.
    fn find_entry(&self, block_num: u64) -> Option<usize> {
        self.entries
            .iter()
            .position(|e| e.valid && e.block_num == block_num)
    }

    /// Find a free entry or evict the LRU entry. Returns the index of the
    /// entry to use. If the evicted entry is dirty, it is written back to
    /// the device before eviction.
    ///
    /// # Errors
    ///
    /// Returns [`BlockError`] if writing back a dirty evicted entry fails.
    fn allocate_entry(&mut self, dev: &mut dyn BlockDevice) -> Result<usize, BlockError> {
        // First, look for an invalid (free) entry.
        if let Some(idx) = self.entries.iter().position(|e| !e.valid) {
            return Ok(idx);
        }

        // All entries are valid — evict the LRU entry (lowest counter).
        let idx = self.lru_victim();

        // Write back dirty data before eviction to prevent data loss.
        if self.entries[idx].dirty {
            self.write_back(dev, idx)?;
        }

        self.entries[idx].dirty = false;
        self.entries[idx].valid = false;
        Ok(idx)
    }

    /// Find the index of the least-recently-used (lowest counter) valid entry.
    fn lru_victim(&self) -> usize {
        let mut min_idx = 0;
        let mut min_counter = u64::MAX;
        for (i, entry) in self.entries.iter().enumerate() {
            if entry.valid && entry.lru_counter < min_counter {
                min_counter = entry.lru_counter;
                min_idx = i;
            }
        }
        min_idx
    }

    /// Update the LRU counter for entry `idx`.
    fn touch(&mut self, idx: usize) {
        self.counter += 1;
        self.entries[idx].lru_counter = self.counter;
    }

    /// Write a dirty cache entry back to the device and mark it clean.
    fn write_back(&mut self, dev: &mut dyn BlockDevice, idx: usize) -> Result<(), BlockError> {
        let lba = self.entries[idx].block_num * SECTORS_PER_BLOCK as u64;
        dev.write_sectors(lba, SECTORS_PER_BLOCK as u32, &self.entries[idx].data)?;
        self.entries[idx].dirty = false;
        Ok(())
    }
}

impl Default for BlockCache {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;
    use crate::block::tests::FailingBlockDevice;
    use crate::block::MemBlockDevice;

    /// Helper: create a device large enough for cache testing.
    /// 2048 sectors = 256 logical blocks (matches cache size exactly).
    fn block_device_for_cache() -> MemBlockDevice {
        MemBlockDevice::new(2048).expect("failed to create test device")
    }

    /// Helper: create a 4 KiB buffer filled with a pattern byte.
    fn pattern_block(byte: u8) -> [u8; BLOCK_SIZE] {
        [byte; BLOCK_SIZE]
    }

    #[test]
    fn read_fills_cache_on_miss() {
        let mut dev = block_device_for_cache();
        let mut cache = BlockCache::new();
        let mut buf = [0u8; BLOCK_SIZE];

        cache.read(&mut dev, 0, &mut buf).expect("read failed");

        // After read, entry should be cached.
        assert!(cache.find_entry(0).is_some(), "block 0 should be cached");
        // Fresh device data is zeroed.
        assert!(buf.iter().all(|&b| b == 0));
    }

    #[test]
    fn read_hits_cache_on_second_access() {
        let mut dev = block_device_for_cache();
        let mut cache = BlockCache::new();
        let mut buf = [0u8; BLOCK_SIZE];

        // First read — cache miss, fills from device.
        cache.read(&mut dev, 5, &mut buf).expect("first read failed");
        let counter_after_first = cache.counter;

        // Second read — should be a cache hit (counter increments but no device I/O).
        cache.read(&mut dev, 5, &mut buf).expect("second read failed");
        let counter_after_second = cache.counter;

        assert_eq!(
            counter_after_second,
            counter_after_first + 1,
            "counter should increment by 1 for cache hit"
        );
        assert!(cache.find_entry(5).is_some());
    }

    #[test]
    fn write_marks_entry_dirty() {
        let mut dev = block_device_for_cache();
        let mut cache = BlockCache::new();
        let data = pattern_block(0xAB);

        cache.write(&mut dev, 3, &data).expect("write failed");

        let idx = cache.find_entry(3).expect("block 3 should be cached");
        assert!(cache.entries[idx].dirty, "written entry should be dirty");
        assert!(cache.entries[idx].valid, "written entry should be valid");
        assert_eq!(cache.entries[idx].data, data);
    }

    #[test]
    fn flush_writes_dirty_entries_to_device() {
        let mut dev = block_device_for_cache();
        let mut cache = BlockCache::new();
        let data = pattern_block(0xCD);

        // Write to cache (block 2).
        cache.write(&mut dev, 2, &data).expect("cache write failed");

        // Verify device is still zeroed at block 2's sectors.
        let mut verify = vec![0u8; BLOCK_SIZE];
        let lba = 2 * SECTORS_PER_BLOCK as u64;
        dev.read_sectors(lba, SECTORS_PER_BLOCK as u32, &mut verify)
            .expect("device read failed");
        assert!(
            verify.iter().all(|&b| b == 0),
            "device should still be zeroed before flush"
        );

        // Flush.
        cache.flush(&mut dev).expect("flush failed");

        // Now device should have the data.
        dev.read_sectors(lba, SECTORS_PER_BLOCK as u32, &mut verify)
            .expect("device read after flush failed");
        assert_eq!(verify, data.to_vec());

        // Entry should no longer be dirty.
        let idx = cache.find_entry(2).expect("block 2 should still be cached");
        assert!(
            !cache.entries[idx].dirty,
            "entry should be clean after flush"
        );
    }

    #[test]
    fn flush_continues_past_failing_entry_and_returns_first_error() {
        // #375: entry 4 (block_num 4) fails write-back. flush() must still
        // attempt every OTHER dirty entry rather than aborting at the first
        // failure -- otherwise a single persistently-bad block would
        // permanently block flushing of every entry ordered after it, since
        // a retried flush() restarts from index 0 and hits the same
        // failure every time.
        let fail_lba = 4 * SECTORS_PER_BLOCK as u64;
        let mut dev = FailingBlockDevice::new(4096, fail_lba);
        dev.ready = true;
        let mut cache = BlockCache::new();

        // Fill 10 dirty entries; blocks 0..10 land in cache slots 0..10 on
        // an empty cache (same fill-order assumption as the eviction test
        // below).
        for i in 0..10u64 {
            let data = pattern_block((i & 0xFF) as u8);
            cache.write(&mut dev, i, &data).expect("fill write failed");
        }

        let result = cache.flush(&mut dev);
        assert_eq!(
            result,
            Err(BlockError::IoError),
            "flush must surface the write-back error"
        );

        for i in 0..10u64 {
            let idx = cache.find_entry(i).expect("block should still be cached");
            if i == 4 {
                assert!(
                    cache.entries[idx].dirty,
                    "the failing entry must remain dirty"
                );
            } else {
                assert!(
                    !cache.entries[idx].dirty,
                    "entry {i} must still be flushed despite entry 4's failure"
                );
            }
        }
    }

    #[test]
    fn evict_writes_dirty_entry_before_replacing() {
        // Use a large device so we have enough blocks beyond cache capacity.
        let mut dev = MemBlockDevice::new(4096).expect("failed to create large device");
        let mut cache = BlockCache::new();

        // Fill all 256 cache entries with dirty writes.
        for i in 0..CACHE_ENTRIES {
            let data = pattern_block((i & 0xFF) as u8);
            cache
                .write(&mut dev, i as u64, &data)
                .expect("fill write failed");
        }

        // All entries should be valid and dirty now.
        assert!(cache.entries.iter().all(|e| e.valid && e.dirty));

        // Write a new block that forces eviction of the LRU entry (block 0,
        // which was written first and has the lowest counter).
        // The evicted dirty entry should be written back to the device
        // automatically by allocate_entry.
        let evict_data = pattern_block(0xFF);
        cache
            .write(&mut dev, 999, &evict_data)
            .expect("eviction write failed");

        // Block 999 should now be in the cache.
        assert!(cache.find_entry(999).is_some());
        // The evicted block (0) should no longer be cached.
        assert!(
            cache.find_entry(0).is_none(),
            "block 0 should have been evicted"
        );

        // Verify the evicted dirty block 0 was written back to the device.
        let mut verify = [0u8; BLOCK_SIZE];
        dev.read_sectors(0, SECTORS_PER_BLOCK as u32, &mut verify)
            .expect("device read of evicted block failed");
        assert_eq!(
            verify,
            pattern_block(0x00),
            "evicted dirty block 0 must have been flushed to device"
        );
    }

    #[test]
    fn lru_evicts_least_recently_used() {
        let mut dev = MemBlockDevice::new(4096).expect("failed to create device");
        let mut cache = BlockCache::new();

        // Fill the cache with blocks 0..255.
        for i in 0..CACHE_ENTRIES {
            let mut buf = [0u8; BLOCK_SIZE];
            cache
                .read(&mut dev, i as u64, &mut buf)
                .expect("fill read failed");
        }

        // Touch block 0 again to make it recently used.
        let mut buf = [0u8; BLOCK_SIZE];
        cache.read(&mut dev, 0, &mut buf).expect("touch read failed");

        // Now insert a new block (256) — should evict block 1 (the true LRU),
        // not block 0 (which was just touched).
        cache
            .read(&mut dev, 256, &mut buf)
            .expect("eviction read failed");

        assert!(
            cache.find_entry(0).is_some(),
            "block 0 was touched recently, should not be evicted"
        );
        assert!(
            cache.find_entry(1).is_none(),
            "block 1 was LRU and should have been evicted"
        );
        assert!(cache.find_entry(256).is_some(), "block 256 should be cached");
    }

    #[test]
    fn invalidate_clears_all_entries() {
        let mut dev = block_device_for_cache();
        let mut cache = BlockCache::new();

        // Fill some entries.
        let mut buf = [0u8; BLOCK_SIZE];
        cache.read(&mut dev, 0, &mut buf).expect("read failed");
        cache.read(&mut dev, 1, &mut buf).expect("read failed");

        assert!(cache.find_entry(0).is_some());
        assert!(cache.find_entry(1).is_some());

        cache.invalidate();

        assert!(
            cache.find_entry(0).is_none(),
            "block 0 should be gone after invalidate"
        );
        assert!(
            cache.find_entry(1).is_none(),
            "block 1 should be gone after invalidate"
        );
        assert!(
            cache.entries.iter().all(|e| !e.valid && !e.dirty),
            "all entries should be invalid and clean"
        );
        assert_eq!(cache.counter, 0, "counter should be reset");
    }

    #[test]
    fn cache_handles_block_zero() {
        let mut dev = block_device_for_cache();
        let mut cache = BlockCache::new();

        // Write to block 0.
        let data = pattern_block(0x42);
        cache.write(&mut dev, 0, &data).expect("write block 0 failed");

        // Read it back from cache.
        let mut buf = [0u8; BLOCK_SIZE];
        cache.read(&mut dev, 0, &mut buf).expect("read block 0 failed");
        assert_eq!(buf, data);

        // Flush and verify on device.
        cache.flush(&mut dev).expect("flush failed");
        let mut verify = [0u8; BLOCK_SIZE];
        let lba = 0;
        dev.read_sectors(lba, SECTORS_PER_BLOCK as u32, &mut verify)
            .expect("device read failed");
        assert_eq!(verify, data);
    }

    #[test]
    fn sync_is_alias_for_flush() {
        let mut dev = block_device_for_cache();
        let mut cache = BlockCache::new();
        let data = pattern_block(0xEE);

        cache.write(&mut dev, 7, &data).expect("write failed");
        cache.sync(&mut dev).expect("sync failed");

        let idx = cache.find_entry(7).expect("block 7 should be cached");
        assert!(
            !cache.entries[idx].dirty,
            "entry should be clean after sync"
        );
    }

    #[test]
    fn write_then_read_returns_cached_data() {
        let mut dev = block_device_for_cache();
        let mut cache = BlockCache::new();
        let data = pattern_block(0x77);

        cache.write(&mut dev, 10, &data).expect("write failed");

        let mut buf = [0u8; BLOCK_SIZE];
        cache.read(&mut dev, 10, &mut buf).expect("read failed");
        assert_eq!(buf, data, "read should return the cached write data");
    }
}
