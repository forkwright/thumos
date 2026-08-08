//! Log-structured filesystem (LFS) implementation.
//!
//! Provides a log-structured filesystem with the following properties:
//!
//! - **On-disk format**: superblock at block 0, dual-slot checkpointing,
//!   inode map, segment-based allocation.
//! - **Read path**: inode lookup via imap, direct block reads for file data,
//!   directory entry parsing for lookup/readdir.
//! - **Write path**: deferred to Wave 5. All write operations currently
//!   return [`VfsError::IoError`].
//!
//! # On-disk layout
//!
//! ```text
//! Block 0:                Superblock (256 bytes, padded to 4 KiB)
//! Block 1..1+R:           Checkpoint slot A (header + reserved imap/bitmap payload)
//! Block 1+R..1+2R:        Checkpoint slot B (header + reserved imap/bitmap payload)
//! Segment 1..M:           Data segments (each 256 blocks = 1 MiB)
//! ```
//!
//! `R` is `CHECKPOINT_SLOT_BLOCKS` (`lfs_checkpoint.rs`): each checkpoint
//! slot reserves a fixed payload region so a slot's imap/bitmap data can
//! never grow into the other slot's header block (#319).
//!
//! # Usage
//!
//! ```ignore
//! use crate::block::MemBlockDevice;
//! use crate::lfs;
//!
//! let mut dev = MemBlockDevice::new(16384)?;
//! lfs::format(&mut dev)?;
//! let fs = lfs::mount(dev)?;
//! ```

extern crate alloc;
use core::cell::RefCell;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use crate::block::{BLOCK_SIZE, BlockDevice, SECTORS_PER_BLOCK};
use crate::cache::BlockCache;
use crate::lfs_checkpoint::{self, CHECKPOINT_MAGIC, CHECKPOINT_SLOT_BLOCKS, CheckpointHeader};
use crate::lfs_compact;
use crate::lfs_imap::{LfsError, LfsImap};
use crate::lfs_segment::LfsSegmentManager;
use crate::lfs_writer::LfsWriter;
use crate::vfs::{DirEntry, Filesystem, InodeStat, InodeType, VfsError};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Superblock magic number: "LFS!" in little-endian.
const LFS_MAGIC: u32 = 0x4C46_5321;

/// On-disk format version.
const LFS_VERSION: u32 = 1;

/// Default number of blocks per segment (256 blocks = 1 MiB at 4 KiB/block).
const DEFAULT_SEGMENT_SIZE: u32 = 256;

/// Superblock is stored at block 0.
const SUPERBLOCK_BLOCK: u64 = 0;

/// Checkpoint slot A is at block 1.
const CHECKPOINT_SLOT_A: u64 = 1;

/// Checkpoint slot B starts one full reserved slot region after slot A,
/// so slot A's imap/segment-bitmap payload can never grow into slot B's
/// header block (#319).
const CHECKPOINT_SLOT_B: u64 = CHECKPOINT_SLOT_A + CHECKPOINT_SLOT_BLOCKS;

/// Imap region starts at block 3.
const IMAP_REGION_START: u64 = 3;

/// Default imap region size in blocks.
const DEFAULT_IMAP_BLOCKS: u32 = 4;

/// On-disk inode type: regular file.
pub(crate) const INODE_TYPE_FILE: u8 = 1;

/// On-disk inode type: directory.
pub(crate) const INODE_TYPE_DIR: u8 = 2;

/// Number of direct block pointers in an inode.
pub(crate) const DIRECT_BLOCK_COUNT: usize = 12;

/// Largest file size representable using only direct block pointers.
///
/// The indirect pointer is declared on-disk (see [`DiskInode::indirect`])
/// but not yet consumed by `read()`/`write()`/`truncate()` -- until it
/// is, every size-setting path must fail closed at this bound rather
/// than let `stat()` promise data the direct pointers cannot back
/// (#620).
pub(crate) const LFS_MAX_FILE_SIZE: u64 = (DIRECT_BLOCK_COUNT * BLOCK_SIZE) as u64;

/// Size of a serialized on-disk inode in bytes.
pub(crate) const DISK_INODE_SIZE: usize = 128;

/// Size of the serialized superblock in bytes.
const SUPERBLOCK_SIZE: usize = 256;

/// Number of inodes that fit in one 4 KiB block.
const INODES_PER_BLOCK: usize = BLOCK_SIZE / DISK_INODE_SIZE;

// ---------------------------------------------------------------------------
// On-disk structures
// ---------------------------------------------------------------------------

/// On-disk superblock, stored at block 0.
///
/// Contains filesystem geometry and pointers to the checkpoint slots
/// and imap region. Fits in 256 bytes with reserved padding.
#[derive(Debug, Clone, Copy)]
pub struct LfsSuperblock {
    /// Magic number ([`LFS_MAGIC`]).
    pub magic: u32,
    /// Format version ([`LFS_VERSION`]).
    pub version: u32,
    /// Total number of 4 KiB blocks in the partition.
    pub block_count: u64,
    /// Number of blocks per segment.
    pub segment_size: u32,
    /// Total number of segments.
    pub segment_count: u32,
    /// Block number of checkpoint slot A.
    pub checkpoint_block_a: u64,
    /// Block number of checkpoint slot B.
    pub checkpoint_block_b: u64,
    /// Block number where the imap region starts.
    pub imap_block: u64,
    /// Number of blocks reserved for the imap.
    pub imap_block_count: u32,
    /// Inode number of the root directory.
    pub root_inode: u32,
    /// Next available inode number.
    pub next_inode: u32,
}

impl LfsSuperblock {
    /// Serialize the superblock to a 4 KiB block buffer.
    ///
    /// # Errors
    ///
    /// This method is infallible.
    fn to_block(&self) -> [u8; BLOCK_SIZE] {
        let mut buf = [0u8; BLOCK_SIZE];
        let mut off = 0;
        write_u32_le(&mut buf, &mut off, self.magic);
        write_u32_le(&mut buf, &mut off, self.version);
        write_u64_le(&mut buf, &mut off, self.block_count);
        write_u32_le(&mut buf, &mut off, self.segment_size);
        write_u32_le(&mut buf, &mut off, self.segment_count);
        write_u64_le(&mut buf, &mut off, self.checkpoint_block_a);
        write_u64_le(&mut buf, &mut off, self.checkpoint_block_b);
        write_u64_le(&mut buf, &mut off, self.imap_block);
        write_u32_le(&mut buf, &mut off, self.imap_block_count);
        write_u32_le(&mut buf, &mut off, self.root_inode);
        write_u32_le(&mut buf, &mut off, self.next_inode);
        buf
    }

    /// Deserialize a superblock from a 4 KiB block buffer.
    ///
    /// # Errors
    ///
    /// Returns [`LfsError::InvalidSuperblock`] if the magic or version is wrong.
    fn from_block(buf: &[u8; BLOCK_SIZE]) -> Result<Self, LfsError> {
        let mut off = 0;
        let magic = read_u32_le(buf, &mut off);
        if magic != LFS_MAGIC {
            return Err(LfsError::InvalidSuperblock);
        }
        let version = read_u32_le(buf, &mut off);
        if version != LFS_VERSION {
            return Err(LfsError::InvalidSuperblock);
        }
        let block_count = read_u64_le(buf, &mut off);
        let segment_size = read_u32_le(buf, &mut off);
        let segment_count = read_u32_le(buf, &mut off);
        let checkpoint_block_a = read_u64_le(buf, &mut off);
        let checkpoint_block_b = read_u64_le(buf, &mut off);
        let imap_block = read_u64_le(buf, &mut off);
        let imap_block_count = read_u32_le(buf, &mut off);
        let root_inode = read_u32_le(buf, &mut off);
        let next_inode = read_u32_le(buf, &mut off);

        Ok(Self {
            magic,
            version,
            block_count,
            segment_size,
            segment_count,
            checkpoint_block_a,
            checkpoint_block_b,
            imap_block,
            imap_block_count,
            root_inode,
            next_inode,
        })
    }
}

/// On-disk inode structure (128 bytes).
///
/// Contains file type, size, link count, and block pointers. Supports
/// up to 12 direct block pointers (48 KiB) plus one indirect block
/// pointer for larger files.
#[derive(Debug, Clone, Copy)]
pub struct DiskInode {
    /// Inode type: 1 = file, 2 = directory.
    pub inode_type: u8,
    /// Number of hard links to this inode.
    pub link_count: u16,
    /// File size in bytes.
    pub size: u64,
    /// Direct block pointers (block numbers). 0 means unused.
    pub direct: [u64; DIRECT_BLOCK_COUNT],
    /// Indirect block pointer. 0 means no indirect block.
    pub indirect: u64,
}

impl DiskInode {
    /// Serialize an inode to bytes within a buffer at the given offset.
    ///
    /// # Errors
    ///
    /// This method is infallible.
    pub(crate) fn write_to(&self, buf: &mut [u8], start: usize) {
        let mut off = start;
        buf[off] = self.inode_type;
        off += 1;
        buf[off..off + 2].copy_from_slice(&self.link_count.to_le_bytes());
        off += 2;
        buf[off..off + 8].copy_from_slice(&self.size.to_le_bytes());
        off += 8;
        for &ptr in &self.direct {
            buf[off..off + 8].copy_from_slice(&ptr.to_le_bytes());
            off += 8;
        }
        buf[off..off + 8].copy_from_slice(&self.indirect.to_le_bytes());
        // Remaining bytes up to 128 are already zeroed.
    }

    /// Deserialize an inode from bytes at the given offset.
    ///
    /// # Errors
    ///
    /// Returns [`LfsError::Corrupt`] if the buffer is too short.
    pub(crate) fn read_from(buf: &[u8], start: usize) -> Result<Self, LfsError> {
        if buf.len() < start + DISK_INODE_SIZE {
            return Err(LfsError::Corrupt);
        }
        let mut off = start;
        let inode_type = buf[off];
        off += 1;
        let link_count = u16::from_le_bytes(
            buf[off..off + 2]
                .try_into()
                .map_err(|_| LfsError::Corrupt)?,
        );
        off += 2;
        let size = u64::from_le_bytes(
            buf[off..off + 8]
                .try_into()
                .map_err(|_| LfsError::Corrupt)?,
        );
        off += 8;
        let mut direct = [0u64; DIRECT_BLOCK_COUNT];
        for ptr in &mut direct {
            *ptr = u64::from_le_bytes(
                buf[off..off + 8]
                    .try_into()
                    .map_err(|_| LfsError::Corrupt)?,
            );
            off += 8;
        }
        let indirect = u64::from_le_bytes(
            buf[off..off + 8]
                .try_into()
                .map_err(|_| LfsError::Corrupt)?,
        );

        Ok(Self {
            inode_type,
            link_count,
            size,
            direct,
            indirect,
        })
    }
}

/// On-disk directory entry header.
///
/// Variable-length entries stored in 4 KiB directory data blocks.
/// Each entry is `record_len` bytes total, with the name immediately
/// following the header.
#[derive(Debug, Clone)]
pub struct DiskDirEntry {
    /// Inode number this entry points to.
    pub inode_id: u32,
    /// Length of the filename in bytes.
    pub name_len: u16,
    /// Total record length including header and padding.
    pub record_len: u16,
    /// The filename (not null-terminated on disk).
    pub name: String,
}

/// Size of the directory entry header (before the name).
pub(crate) const DIR_ENTRY_HEADER_SIZE: usize = 8; // 4 + 2 + 2

/// Segment header, stored at the first block of each segment.
///
/// Contains a magic number and metadata about the segment's contents.
#[derive(Debug, Clone, Copy)]
pub struct SegmentHeader {
    /// Magic number: 0x5345_4721 ("SEG!").
    pub magic: u32,
    /// Monotonically increasing sequence number.
    pub sequence: u64,
    /// Timestamp of segment creation (kernel ticks or zero).
    pub timestamp: u64,
    /// Number of data blocks written in this segment.
    pub block_count: u32,
}

/// Segment header magic: "SEG!".
pub(crate) const SEGMENT_MAGIC: u32 = 0x5345_4721;

impl SegmentHeader {
    /// Serialize a segment header to a 4 KiB block buffer.
    ///
    /// # Errors
    ///
    /// This method is infallible.
    pub(crate) fn to_block(&self) -> [u8; BLOCK_SIZE] {
        let mut buf = [0u8; BLOCK_SIZE];
        let mut off = 0;
        write_u32_le(&mut buf, &mut off, self.magic);
        write_u64_le(&mut buf, &mut off, self.sequence);
        write_u64_le(&mut buf, &mut off, self.timestamp);
        write_u32_le(&mut buf, &mut off, self.block_count);
        buf
    }
}

// ---------------------------------------------------------------------------
// Lfs — the filesystem instance
// ---------------------------------------------------------------------------

/// Log-structured filesystem instance.
///
/// Holds all in-memory state needed to serve filesystem operations. The
/// block device and cache are wrapped in `RefCell` to allow the read-path
/// methods (which take `&self` per the [`Filesystem`] trait) to perform
/// I/O through the mutable cache.
///
/// # Interior mutability
///
/// The [`Filesystem`] trait requires `&self` for read-path methods (`stat`,
/// `lookup`, `read`, `readdir`), but the block cache requires `&mut self`
/// for every access (even reads, to update LRU state). `RefCell` provides
/// runtime borrow checking for this single-threaded bare-metal kernel.
pub(crate) struct Lfs {
    /// The underlying block device.
    dev: RefCell<Box<dyn BlockDevice>>,
    /// Block cache for 4 KiB logical blocks.
    cache: RefCell<BlockCache>,
    /// In-memory inode map.
    imap: LfsImap,
    /// Segment allocation manager.
    segments: LfsSegmentManager,
    /// Copy of the on-disk superblock.
    superblock: LfsSuperblock,
    /// Next sequence number for segment writes.
    next_sequence: u64,
    /// Log write head. `None` before the first write operation.
    writer: Option<LfsWriter>,
    /// Next available inode number.
    next_inode: u32,
    /// Checkpoint sequence counter (monotonically increasing).
    checkpoint_sequence: u64,
}

// ---------------------------------------------------------------------------
// Format and mount
// ---------------------------------------------------------------------------

/// Format a block device with an empty LFS filesystem.
///
/// Writes the superblock, initial empty root directory inode, initial
/// checkpoint, and initial imap. The device must have at least 2 segments
/// worth of blocks (512 blocks = 2 MiB at default geometry).
///
/// # Errors
///
/// - [`LfsError::BlockIo`] if any block write fails.
/// - [`LfsError::InvalidSuperblock`] if the device is too small.
#[must_use]
pub(crate) fn format(dev: &mut dyn BlockDevice) -> Result<(), LfsError> {
    let total_sectors = dev.sector_count();
    let total_blocks = total_sectors / SECTORS_PER_BLOCK as u64;

    if total_blocks < u64::from(DEFAULT_SEGMENT_SIZE) * 2 {
        return Err(LfsError::InvalidSuperblock);
    }

    let segment_count = (total_blocks / u64::from(DEFAULT_SEGMENT_SIZE)) as u32;
    let mut cache = BlockCache::new();

    // Build superblock.
    let superblock = LfsSuperblock {
        magic: LFS_MAGIC,
        version: LFS_VERSION,
        block_count: total_blocks,
        segment_size: DEFAULT_SEGMENT_SIZE,
        segment_count,
        checkpoint_block_a: CHECKPOINT_SLOT_A,
        checkpoint_block_b: CHECKPOINT_SLOT_B,
        imap_block: IMAP_REGION_START,
        imap_block_count: DEFAULT_IMAP_BLOCKS,
        root_inode: 0,
        next_inode: 1,
    };

    // Write superblock.
    let sb_block = superblock.to_block();
    cache.write(dev, SUPERBLOCK_BLOCK, &sb_block)?;

    // Create root directory inode (inode 0) in the first data segment.
    // The first usable segment is segment 1 (segment 0 holds the superblock
    // and metadata region). We write the root inode at the first data block
    // of segment 1 (block 256 + 1 to leave room for the segment header).
    let seg1_start = u64::from(DEFAULT_SEGMENT_SIZE); // block 256
    let root_inode_block = seg1_start + 1; // block 257

    // Write a segment header for segment 1.
    let seg_header = SegmentHeader {
        magic: SEGMENT_MAGIC,
        sequence: 1,
        timestamp: 0,
        block_count: 1,
    };
    let seg_header_buf = seg_header.to_block();
    cache.write(dev, seg1_start, &seg_header_buf)?;

    // Write root directory inode (empty directory, size 0).
    let root_inode = DiskInode {
        inode_type: INODE_TYPE_DIR,
        link_count: 1,
        size: 0,
        direct: [0u64; DIRECT_BLOCK_COUNT],
        indirect: 0,
    };

    let mut inode_block = [0u8; BLOCK_SIZE];
    root_inode.write_to(&mut inode_block, 0);
    cache.write(dev, root_inode_block, &inode_block)?;

    // Build imap with root inode mapping.
    let mut imap = LfsImap::new();
    imap.insert(0, root_inode_block);

    // Build segment manager and mark segment 0 (metadata) and segment 1 (root) as used.
    let mut segments = LfsSegmentManager::new(segment_count, DEFAULT_SEGMENT_SIZE);
    segments.mark_used(1);

    // Serialize imap and segment data.
    let mut imap_data = Vec::new();
    imap.serialize(&mut imap_data);
    let segment_data = segments.serialize();

    // Write initial checkpoint to slot A.
    let checkpoint = CheckpointHeader {
        magic: CHECKPOINT_MAGIC,
        sequence: 1,
        imap_block: IMAP_REGION_START,
        imap_block_count: DEFAULT_IMAP_BLOCKS,
        segment_bitmap_block: IMAP_REGION_START + u64::from(DEFAULT_IMAP_BLOCKS),
        segment_bitmap_count: 1,
        next_inode: 1,
        last_segment_sequence: 1,
    };

    lfs_checkpoint::write_checkpoint(
        dev,
        &mut cache,
        CHECKPOINT_SLOT_A,
        &checkpoint,
        &imap_data,
        &segment_data,
    )?;

    // Flush everything to device.
    cache.flush(dev)?;

    Ok(())
}

/// Mount an LFS filesystem from a block device.
///
/// Reads the superblock, selects the latest checkpoint, loads the imap
/// and segment bitmap, and returns a ready-to-use [`Lfs`] instance.
///
/// # Errors
///
/// - [`LfsError::InvalidSuperblock`] if the superblock magic/version is wrong.
/// - [`LfsError::Corrupt`] if neither checkpoint is valid.
/// - [`LfsError::BlockIo`] if any block read fails.
#[must_use]
pub(crate) fn mount(mut dev: Box<dyn BlockDevice>) -> Result<Lfs, LfsError> {
    let mut cache = BlockCache::new();

    // Read superblock.
    let mut sb_buf = [0u8; BLOCK_SIZE];
    cache.read(dev.as_mut(), SUPERBLOCK_BLOCK, &mut sb_buf)?;
    let superblock = LfsSuperblock::from_block(&sb_buf)?;

    // Pick the latest checkpoint.
    let (checkpoint, _slot_block) = lfs_checkpoint::pick_latest(
        dev.as_mut(),
        &mut cache,
        superblock.checkpoint_block_a,
        superblock.checkpoint_block_b,
    )?;

    // Load imap from checkpoint. superblock.segment_size/block_count are
    // passed through as the reserved-segment/extent bounds for every
    // parsed entry (#643, #653) -- the same geometry validate_block_num
    // applies below to imap-derived pointers at load_inode/unlink,
    // enforced here at parse time instead.
    let imap = LfsImap::load_from_disk(
        dev.as_mut(),
        &mut cache,
        checkpoint.imap_block,
        checkpoint.imap_block_count,
        superblock.segment_size,
        superblock.block_count,
    )?;

    // Sanity-bound segment_bitmap_count before trusting it to drive an
    // allocation loop: persisted checkpoint data is untrusted input, and
    // an adversarial or bit-flipped value must not OOM the kernel at
    // mount (#302).
    let bits_per_block = (BLOCK_SIZE as u32) * 8;
    let full_bitmap_blocks = superblock.segment_count / bits_per_block;
    let partial_bitmap_block = u32::from(superblock.segment_count % bits_per_block != 0);
    let max_bitmap_blocks = full_bitmap_blocks + partial_bitmap_block + 1;
    if checkpoint.segment_bitmap_count > max_bitmap_blocks {
        return Err(LfsError::Corrupt);
    }

    // Load segment bitmap from checkpoint.
    let mut seg_data = Vec::new();
    let mut block_buf = [0u8; BLOCK_SIZE];
    for i in 0..checkpoint.segment_bitmap_count {
        cache.read(
            dev.as_mut(),
            checkpoint.segment_bitmap_block + u64::from(i),
            &mut block_buf,
        )?;
        seg_data.extend_from_slice(&block_buf);
    }
    let segments = LfsSegmentManager::deserialize(
        &seg_data,
        superblock.segment_count,
        superblock.segment_size,
        superblock.block_count,
    )?;

    Ok(Lfs {
        dev: RefCell::new(dev),
        cache: RefCell::new(cache),
        imap,
        segments,
        superblock,
        next_sequence: checkpoint.last_segment_sequence + 1,
        writer: None,
        next_inode: checkpoint.next_inode,
        checkpoint_sequence: checkpoint.sequence + 1,
    })
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

impl Lfs {
    /// Validate that an on-disk block pointer falls within the
    /// filesystem's own block extent before it is used to address the
    /// block cache.
    ///
    /// `inode.direct[]` entries are on-disk, untrusted data: a
    /// corrupted or maliciously crafted inode could set them to any
    /// `u64`. Every block the filesystem itself allocates stays within
    /// `[1, superblock.block_count)` (block 0 is the superblock, never
    /// an allocatable data block), so any pointer outside that range is
    /// corruption -- fail closed rather than let it reach the block
    /// cache and read/write memory outside the filesystem's own
    /// extent, even when that block number is still within the raw
    /// block device's physical capacity.
    ///
    /// # Errors
    ///
    /// Returns [`VfsError::IoError`] if `block_num` is 0 or `>=
    /// superblock.block_count`.
    fn validate_block_num(&self, block_num: u64) -> Result<(), VfsError> {
        if block_num == 0 || block_num >= self.superblock.block_count {
            return Err(VfsError::IoError);
        }
        Ok(())
    }

    /// Load a `DiskInode` from disk given its inode ID.
    ///
    /// Looks up the block number via the imap, reads the block, and
    /// deserializes the inode. Multiple inodes may be packed in one block;
    /// the inode's position within the block is determined by `inode_id %
    /// INODES_PER_BLOCK`.
    fn load_inode(&self, inode_id: u32) -> Result<DiskInode, VfsError> {
        let block_num = self.imap.get(inode_id).ok_or(VfsError::NotFound)?;
        // WARNING: imap entries are on-disk, untrusted data -- exactly
        // the same class as inode.direct[], which this file already
        // bounds before it reaches the block cache. The imap is the
        // pointer table that selects which block is authoritative for
        // every inode, so an unguarded entry here can serve one file's
        // content as another's (#624, #security).
        self.validate_block_num(block_num)?;

        let mut buf = [0u8; BLOCK_SIZE];
        let mut dev = self.dev.borrow_mut();
        let mut cache = self.cache.borrow_mut();
        cache
            .read(dev.as_mut(), block_num, &mut buf)
            .map_err(|_| VfsError::IoError)?;

        // Each block can hold multiple inodes. For format(), we write
        // one inode at offset 0 of the block. For a general case, the
        // offset within the block depends on how inodes are packed.
        // In our current format, each inode gets its own block (offset 0).
        let offset = 0;
        DiskInode::read_from(&buf, offset).map_err(|_| VfsError::IoError)
    }

    /// Convert a `DiskInode` to an `InodeStat`.
    ///
    /// # Errors
    ///
    /// Returns [`VfsError::IoError`] if `inode.inode_type` is not a
    /// recognized on-disk type value.
    fn inode_to_stat(inode_id: u32, inode: &DiskInode) -> Result<InodeStat, VfsError> {
        let inode_type = match inode.inode_type {
            INODE_TYPE_FILE => InodeType::RegularFile,
            INODE_TYPE_DIR => InodeType::Directory,
            // WHY: an unrecognized on-disk type is corruption -- guessing
            // RegularFile here would misreport a corrupt inode's type to
            // every caller of stat() instead of surfacing the fault.
            _ => return Err(VfsError::IoError),
        };

        // Count allocated blocks (non-zero direct pointers).
        let block_count = inode.direct.iter().filter(|&&p| p != 0).count() as u32;

        Ok(InodeStat {
            inode_id,
            inode_type,
            size: inode.size,
            link_count: u32::from(inode.link_count),
            block_count,
        })
    }

    /// Parse directory entries from a data block.
    ///
    /// Returns all valid entries found in the block. Entries with
    /// `inode_id == 0` or `record_len == 0` are skipped (sentinel/padding).
    ///
    /// # Errors
    ///
    /// Returns [`VfsError::IoError`] if an entry's `name_len` would read
    /// past that entry's own `record_len`, or past the end of the block.
    fn parse_dir_entries(buf: &[u8; BLOCK_SIZE]) -> Result<Vec<DiskDirEntry>, VfsError> {
        let mut entries = Vec::new();
        let mut offset = 0;

        while offset + DIR_ENTRY_HEADER_SIZE <= BLOCK_SIZE {
            let inode_id = u32::from_le_bytes(match buf[offset..offset + 4].try_into() {
                Ok(b) => b,
                Err(_) => break,
            });
            let name_len = u16::from_le_bytes(match buf[offset + 4..offset + 6].try_into() {
                Ok(b) => b,
                Err(_) => break,
            });
            let record_len = u16::from_le_bytes(match buf[offset + 6..offset + 8].try_into() {
                Ok(b) => b,
                Err(_) => break,
            });

            // End of entries sentinel.
            if record_len == 0 {
                break;
            }

            // Skip deleted entries (inode_id == 0).
            if inode_id != 0 && name_len > 0 {
                // WARNING: name_len and record_len are on-disk fields --
                // treat them as untrusted. name_len must be bounded by
                // this entry's own record_len before it is used to slice
                // `buf`; otherwise the name reads past this entry's
                // reserved span into the next entry's header/name bytes
                // (a buffer over-read across the record boundary, not
                // caught by a bare `name_end <= BLOCK_SIZE` check). Fail
                // closed on corruption rather than silently truncate.
                let name_capacity = (record_len as usize)
                    .checked_sub(DIR_ENTRY_HEADER_SIZE)
                    .ok_or(VfsError::IoError)?;
                if name_len as usize > name_capacity {
                    return Err(VfsError::IoError);
                }

                let name_start = offset + DIR_ENTRY_HEADER_SIZE;
                let name_end = name_start + name_len as usize;
                if name_end > BLOCK_SIZE {
                    return Err(VfsError::IoError);
                }
                let name = String::from_utf8_lossy(&buf[name_start..name_end]);
                entries.push(DiskDirEntry {
                    inode_id,
                    name_len,
                    record_len,
                    name: String::from(name.as_ref()),
                });
            }

            offset += record_len as usize;
        }

        Ok(entries)
    }

    /// Read all directory entries for a directory inode.
    ///
    /// # Errors
    ///
    /// Returns [`VfsError::IoError`] if `inode.size` does not fit in
    /// `usize` on this target (32-bit ARM: on-disk `size` is `u64` and
    /// must never silently truncate through an `as usize` cast), or if
    /// `inode.inode_type` is not a directory.
    fn read_dir_entries(&self, inode: &DiskInode) -> Result<Vec<DiskDirEntry>, VfsError> {
        if inode.inode_type != INODE_TYPE_DIR {
            return Err(VfsError::NotADirectory);
        }

        let mut all_entries = Vec::new();

        // Read each direct block that contains directory data.
        let data_blocks = if inode.size == 0 {
            0
        } else {
            let size = usize::try_from(inode.size).map_err(|_| VfsError::IoError)?;
            size.div_ceil(BLOCK_SIZE).min(DIRECT_BLOCK_COUNT)
        };

        for i in 0..data_blocks {
            let block_num = inode.direct[i];
            if block_num == 0 {
                continue;
            }
            // WARNING: inode.direct[] is on-disk, untrusted data -- a
            // corrupted or crafted inode could point anywhere. Bound it
            // to the filesystem's own extent before it ever reaches the
            // block cache (#security).
            self.validate_block_num(block_num)?;

            let mut buf = [0u8; BLOCK_SIZE];
            let mut dev = self.dev.borrow_mut();
            let mut cache = self.cache.borrow_mut();
            cache
                .read(dev.as_mut(), block_num, &mut buf)
                .map_err(|_| VfsError::IoError)?;

            let entries = Self::parse_dir_entries(&buf)?;
            all_entries.extend(entries);
        }

        Ok(all_entries)
    }

    /// Ensure the writer is initialized, lazily creating it on first write.
    ///
    /// Returns a mutable reference to the writer. Takes `&mut self` because
    /// it may allocate a segment.
    fn ensure_writer(&mut self) -> Result<(), VfsError> {
        if self.writer.is_none() {
            let writer = LfsWriter::with_sequence(&mut self.segments, self.next_sequence)
                .map_err(|_| VfsError::NoSpace)?;
            self.writer = Some(writer);
        }
        Ok(())
    }

    /// Run compaction if free segment count is below threshold.
    ///
    /// Called after write operations that consume segment space.
    fn maybe_compact(&mut self) -> Result<(), VfsError> {
        if !lfs_compact::needs_compaction(&self.segments) {
            return Ok(());
        }

        let writer = match self.writer.as_mut() {
            Some(w) => w,
            None => return Ok(()),
        };

        let mut dev = self.dev.borrow_mut();
        let mut cache = self.cache.borrow_mut();

        // Run one compaction pass. block_count is the same imap-pointer
        // extent bound applied at load_inode/unlink (#624), threaded
        // through so the compactor's own imap walk is guarded too
        // (#643).
        let _copied = lfs_compact::compact_one_segment(
            dev.as_mut(),
            &mut cache,
            writer,
            &mut self.imap,
            &mut self.segments,
            self.superblock.block_count,
        )
        .map_err(|_| VfsError::IoError)?;

        Ok(())
    }

    /// Serialize a directory's entries into a data block and write it.
    ///
    /// Returns the block number of the written directory data block.
    fn write_dir_block(
        dev: &mut dyn BlockDevice,
        cache: &mut BlockCache,
        writer: &mut LfsWriter,
        seg_mgr: &mut LfsSegmentManager,
        entries: &[DiskDirEntry],
    ) -> Result<u64, VfsError> {
        let mut buf = [0u8; BLOCK_SIZE];
        let mut offset = 0;

        for entry in entries {
            let name_bytes = entry.name.as_bytes();

            // A record whose aligned length overflows u16 (or exceeds
            // BLOCK_SIZE) cannot be represented on disk. The previous
            // `as u16` cast silently wrapped such a length to a small
            // value, which bypassed the block-full guard below and wrote
            // out of bounds into `buf` (#290).
            let name_len: u16 =
                u16::try_from(name_bytes.len()).map_err(|_| VfsError::InvalidPath)?;
            let aligned_len = (DIR_ENTRY_HEADER_SIZE + name_bytes.len() + 3) & !3;
            let record_len: u16 = u16::try_from(aligned_len)
                .ok()
                .filter(|&len| (len as usize) <= BLOCK_SIZE)
                .ok_or(VfsError::InvalidPath)?;

            if offset + record_len as usize > BLOCK_SIZE {
                // A single directory data block cannot hold every entry.
                // WHY: silently truncating here would report create()/
                // unlink() as successful while dropping the entry that
                // overflowed -- multi-block directories are not yet
                // implemented, so the caller must see this as NoSpace
                // rather than lose data (#287).
                return Err(VfsError::NoSpace);
            }

            buf[offset..offset + 4].copy_from_slice(&entry.inode_id.to_le_bytes());
            buf[offset + 4..offset + 6].copy_from_slice(&name_len.to_le_bytes());
            buf[offset + 6..offset + 8].copy_from_slice(&record_len.to_le_bytes());
            buf[offset + DIR_ENTRY_HEADER_SIZE..offset + DIR_ENTRY_HEADER_SIZE + name_bytes.len()]
                .copy_from_slice(name_bytes);

            offset += record_len as usize;
        }

        let block_num = writer
            .write_data_block(dev, cache, seg_mgr, &buf)
            .map_err(Self::map_write_data_block_err)?;

        Ok(block_num)
    }

    /// Map an [`LfsError`] from a `write_data_block` call to the
    /// [`VfsError`] the caller expects.
    ///
    /// WHY a shared helper: call sites previously collapsed every
    /// `write_data_block` failure to one hardcoded `VfsError` variant --
    /// some sites always reported `NoSpace`, others always reported
    /// `IoError` -- which misreported the other failure mode at each
    /// site: a genuine disk-full condition ([`LfsError::NoFreeSegments`])
    /// surfaced as a generic I/O error at one call site, while a genuine
    /// device I/O fault surfaced as "no space left on device" at
    /// another. This maps each `LfsError` variant once so every call
    /// site reports the correct condition.
    fn map_write_data_block_err(err: LfsError) -> VfsError {
        match err {
            LfsError::NoFreeSegments => VfsError::NoSpace,
            LfsError::BlockIo(_)
            | LfsError::Corrupt
            | LfsError::InvalidSuperblock
            | LfsError::InodeNotFound
            | LfsError::CheckpointOverflow
            | LfsError::NoCompactionCandidate => VfsError::IoError,
        }
    }

    /// Allocate the next inode number.
    fn alloc_inode_id(&mut self) -> u32 {
        let id = self.next_inode;
        self.next_inode += 1;
        id
    }
}

// ---------------------------------------------------------------------------
// Filesystem trait implementation
// ---------------------------------------------------------------------------

impl Filesystem for Lfs {
    /// Return the root inode ID from the superblock.
    ///
    /// # Errors
    ///
    /// This method is infallible.
    fn root_inode(&self) -> u32 {
        self.superblock.root_inode
    }

    /// Retrieve metadata for an inode.
    ///
    /// # Errors
    ///
    /// Returns [`VfsError::NotFound`] if the inode is not in the imap.
    /// Returns [`VfsError::IoError`] if the block read fails.
    fn stat(&self, inode_id: u32) -> Result<InodeStat, VfsError> {
        let inode = self.load_inode(inode_id)?;
        Self::inode_to_stat(inode_id, &inode)
    }

    /// Look up a child entry by name within a directory.
    ///
    /// # Errors
    ///
    /// - [`VfsError::NotADirectory`] if `dir_inode` is not a directory.
    /// - [`VfsError::NotFound`] if no entry with `name` exists.
    /// - [`VfsError::IoError`] on I/O failure.
    fn lookup(&self, dir_inode: u32, name: &str) -> Result<u32, VfsError> {
        let inode = self.load_inode(dir_inode)?;
        let entries = self.read_dir_entries(&inode)?;

        for entry in &entries {
            if entry.name == name {
                return Ok(entry.inode_id);
            }
        }

        Err(VfsError::NotFound)
    }

    /// Read bytes from a file.
    ///
    /// Reads up to `buf.len()` bytes starting at `offset`. Returns the
    /// number of bytes actually read (0 at EOF).
    ///
    /// # Errors
    ///
    /// - [`VfsError::NotFound`] if the inode does not exist.
    /// - [`VfsError::IsADirectory`] if the inode is a directory.
    /// - [`VfsError::IoError`] on I/O failure.
    fn read(&self, inode_id: u32, offset: u64, buf: &mut [u8]) -> Result<usize, VfsError> {
        let inode = self.load_inode(inode_id)?;

        if inode.inode_type == INODE_TYPE_DIR {
            return Err(VfsError::IsADirectory);
        }

        // Clamp read range to file size.
        if offset >= inode.size {
            return Ok(0);
        }

        // WHY: only direct block pointers are consumed today (the
        // indirect pointer is unimplemented, #620) -- an offset at or
        // past LFS_MAX_FILE_SIZE is not representable by any inode this
        // filesystem writes anymore, but on-disk state predating this
        // bound (or corrupted on-disk state) could still carry a size
        // that promises more. Ok(0) here would be indistinguishable
        // from true EOF to every caller even though offset < inode.size;
        // fail loudly instead.
        if offset >= LFS_MAX_FILE_SIZE {
            return Err(VfsError::IoError);
        }

        let available = inode.size - offset;
        // WHY usize::try_from: inode.size is on-disk, untrusted u64 data
        // -- an `as usize` cast here would silently wrap on a 32-bit
        // target instead of erroring (#620), the same class already
        // fixed at read_dir_entries (lfs.rs:743).
        let available = usize::try_from(available).map_err(|_| VfsError::IoError)?;
        let to_read = buf.len().min(available);

        if to_read == 0 {
            return Ok(0);
        }

        let mut bytes_read = 0;

        while bytes_read < to_read {
            let file_offset = offset + bytes_read as u64;
            let block_index = (file_offset / BLOCK_SIZE as u64) as usize;
            let block_offset = (file_offset % BLOCK_SIZE as u64) as usize;

            // INVARIANT: the offset >= LFS_MAX_FILE_SIZE check above
            // guarantees bytes_read > 0 by the time block_index can
            // reach DIRECT_BLOCK_COUNT here, so this is always a
            // legitimate short read (some bytes served, more exist past
            // the direct-block wall) -- never the false-EOF Ok(0) #620
            // described. The next call at the resulting offset hits the
            // guard above and errors instead of repeating the lie.
            if block_index >= DIRECT_BLOCK_COUNT {
                break;
            }

            let block_num = inode.direct[block_index];
            if block_num == 0 {
                // Sparse block — fill with zeros.
                let chunk = (BLOCK_SIZE - block_offset).min(to_read - bytes_read);
                for b in &mut buf[bytes_read..bytes_read + chunk] {
                    *b = 0;
                }
                bytes_read += chunk;
                continue;
            }
            // WARNING: inode.direct[] is on-disk, untrusted data -- a
            // corrupted or crafted inode could point anywhere. Bound it
            // to the filesystem's own extent before it ever reaches the
            // block cache (#security).
            self.validate_block_num(block_num)?;

            let mut block_buf = [0u8; BLOCK_SIZE];
            {
                let mut dev = self.dev.borrow_mut();
                let mut cache = self.cache.borrow_mut();
                cache
                    .read(dev.as_mut(), block_num, &mut block_buf)
                    .map_err(|_| VfsError::IoError)?;
            }

            let chunk = (BLOCK_SIZE - block_offset).min(to_read - bytes_read);
            buf[bytes_read..bytes_read + chunk]
                .copy_from_slice(&block_buf[block_offset..block_offset + chunk]);
            bytes_read += chunk;
        }

        Ok(bytes_read)
    }

    /// Write bytes to a file.
    ///
    /// Writes up to `buf.len()` bytes starting at `offset`. Allocates new
    /// data blocks as needed via the log write path. Updates the inode's
    /// direct block pointers and file size.
    ///
    /// # Errors
    ///
    /// - [`VfsError::NotFound`] if the inode does not exist.
    /// - [`VfsError::IsADirectory`] if the inode is a directory.
    /// - [`VfsError::NoSpace`] if the filesystem is full, or if the
    ///   requested range would cross [`LFS_MAX_FILE_SIZE`] (only direct
    ///   block pointers are consumed today, #620).
    /// - [`VfsError::IoError`] on I/O failure.
    fn write(&mut self, inode_id: u32, offset: u64, buf: &[u8]) -> Result<usize, VfsError> {
        let mut inode = self.load_inode(inode_id)?;

        if inode.inode_type == INODE_TYPE_DIR {
            return Err(VfsError::IsADirectory);
        }

        if buf.is_empty() {
            return Ok(0);
        }

        // WHY: only direct block pointers are consumed today (the
        // indirect pointer is unimplemented, #620) -- a write whose
        // range would cross LFS_MAX_FILE_SIZE must fail closed instead
        // of silently stopping partway through the block loop below and
        // returning Ok(0), which is indistinguishable from a
        // zero-length request (so a caller's write-all loop spins
        // forever) while the data it was meant to persist is dropped.
        offset
            .checked_add(buf.len() as u64)
            .filter(|&end| end <= LFS_MAX_FILE_SIZE)
            .ok_or(VfsError::NoSpace)?;

        self.ensure_writer()?;

        // Captured before the writer/cache borrows below so the extent
        // check inside the loop doesn't need a `&self` method call while
        // `self.writer` is exclusively borrowed.
        let block_count = self.superblock.block_count;

        let mut bytes_written = 0usize;
        let mut dev = self.dev.borrow_mut();
        let mut cache = self.cache.borrow_mut();
        let writer = self.writer.as_mut().ok_or(VfsError::IoError)?;

        while bytes_written < buf.len() {
            let file_offset = offset + bytes_written as u64;
            let block_index = (file_offset / BLOCK_SIZE as u64) as usize;
            let block_offset = (file_offset % BLOCK_SIZE as u64) as usize;

            // INVARIANT: unreachable given the checked_add + LFS_MAX_FILE_SIZE
            // guard above (offset + buf.len() <= LFS_MAX_FILE_SIZE bounds
            // every file_offset in this loop below DIRECT_BLOCK_COUNT
            // blocks). Kept as a fail-closed backstop -- returning an
            // error here instead of break/Ok(0) means a future change
            // that weakens the guard fails loudly rather than silently
            // reopening #620.
            if block_index >= DIRECT_BLOCK_COUNT {
                return Err(VfsError::IoError);
            }

            // Prepare the block data.
            let mut block_buf = [0u8; BLOCK_SIZE];

            // If we're doing a partial block write, read the existing block first.
            if block_offset != 0 || bytes_written + BLOCK_SIZE > buf.len() {
                let existing_block = inode.direct[block_index];
                if existing_block != 0 {
                    // WARNING: inode.direct[] is on-disk, untrusted data --
                    // bound it to the filesystem's own extent before it
                    // reaches the block cache (#security, mirrors read()'s
                    // validate_block_num; inlined here because `writer`
                    // already holds an exclusive borrow of `self.writer`,
                    // so a `&self` method call is not available).
                    if existing_block >= block_count {
                        return Err(VfsError::IoError);
                    }
                    cache
                        .read(dev.as_mut(), existing_block, &mut block_buf)
                        .map_err(|_| VfsError::IoError)?;
                }
            }

            // Copy user data into the block buffer.
            let chunk = (BLOCK_SIZE - block_offset).min(buf.len() - bytes_written);
            block_buf[block_offset..block_offset + chunk]
                .copy_from_slice(&buf[bytes_written..bytes_written + chunk]);

            // Write the data block to the log.
            let new_block = writer
                .write_data_block(dev.as_mut(), &mut cache, &mut self.segments, &block_buf)
                .map_err(Self::map_write_data_block_err)?;

            inode.direct[block_index] = new_block;
            bytes_written += chunk;
        }

        // Update file size if we wrote past the current end.
        let new_end = offset + bytes_written as u64;
        if new_end > inode.size {
            inode.size = new_end;
        }

        // Write the updated inode.
        writer
            .write_inode(
                dev.as_mut(),
                &mut cache,
                &mut self.imap,
                &mut self.segments,
                inode_id,
                &inode,
            )
            .map_err(|_| VfsError::IoError)?;

        drop(cache);
        drop(dev);
        self.maybe_compact()?;

        Ok(bytes_written)
    }

    /// Create a new inode in a directory.
    ///
    /// Allocates a new inode number, creates the on-disk inode, writes it
    /// via the log write path, and adds a directory entry to the parent.
    ///
    /// # Errors
    ///
    /// - [`VfsError::NotADirectory`] if `dir_inode` is not a directory.
    /// - [`VfsError::AlreadyExists`] if `name` already exists.
    /// - [`VfsError::NoSpace`] if the filesystem is full.
    /// - [`VfsError::IoError`] on I/O failure.
    fn create(
        &mut self,
        dir_inode: u32,
        name: &str,
        inode_type: InodeType,
    ) -> Result<u32, VfsError> {
        // WHY 255: matches the traditional POSIX NAME_MAX and keeps a
        // serialized directory-entry record_len (header + name, aligned
        // to 4 bytes) far under u16::MAX / BLOCK_SIZE, so a userspace-
        // supplied name can never overflow the on-disk record length
        // field (#290).
        if name.len() > 255 {
            return Err(VfsError::InvalidPath);
        }

        let mut parent = self.load_inode(dir_inode)?;

        if parent.inode_type != INODE_TYPE_DIR {
            return Err(VfsError::NotADirectory);
        }

        // Check for duplicates.
        let existing = self.read_dir_entries(&parent)?;
        for entry in &existing {
            if entry.name == name {
                return Err(VfsError::AlreadyExists);
            }
        }

        self.ensure_writer()?;

        // Allocate new inode ID.
        let new_inode_id = self.alloc_inode_id();

        let disk_type = match inode_type {
            InodeType::Directory => INODE_TYPE_DIR,
            _ => INODE_TYPE_FILE,
        };

        let new_inode = DiskInode {
            inode_type: disk_type,
            link_count: 1,
            size: 0,
            direct: [0u64; DIRECT_BLOCK_COUNT],
            indirect: 0,
        };

        let mut dev = self.dev.borrow_mut();
        let mut cache = self.cache.borrow_mut();
        let writer = self.writer.as_mut().ok_or(VfsError::IoError)?;

        // Write the new inode to the log.
        writer
            .write_inode(
                dev.as_mut(),
                &mut cache,
                &mut self.imap,
                &mut self.segments,
                new_inode_id,
                &new_inode,
            )
            .map_err(|_| VfsError::NoSpace)?;

        // Add directory entry to parent.
        let mut entries = existing;
        entries.push(DiskDirEntry {
            inode_id: new_inode_id,
            name_len: name.len() as u16,
            record_len: ((DIR_ENTRY_HEADER_SIZE + name.len() + 3) & !3) as u16,
            name: String::from(name),
        });

        // Write the updated directory data block. On failure, the new
        // inode above is already durable in the imap with no directory
        // entry pointing to it -- roll back the imap insert so a failed
        // create() never leaks storage (mirror of the dangling-reference
        // guard in unlink(): that guard avoids a namespace entry
        // outliving its imap entry; this guard avoids an imap entry
        // outliving its namespace entry).
        let dir_block = match Self::write_dir_block(
            dev.as_mut(),
            &mut cache,
            writer,
            &mut self.segments,
            &entries,
        ) {
            Ok(block) => block,
            Err(e) => {
                self.imap.remove(new_inode_id);
                return Err(e);
            }
        };

        // Update parent inode to point to the new directory data block.
        parent.direct[0] = dir_block;
        parent.size = entries.iter().map(|e| e.record_len as u64).sum();

        match writer.write_inode(
            dev.as_mut(),
            &mut cache,
            &mut self.imap,
            &mut self.segments,
            dir_inode,
            &parent,
        ) {
            Ok(_) => {}
            Err(_) => {
                self.imap.remove(new_inode_id);
                return Err(VfsError::IoError);
            }
        }

        drop(cache);
        drop(dev);
        self.maybe_compact()?;

        Ok(new_inode_id)
    }

    /// Remove an entry from a directory.
    ///
    /// Removes the named directory entry and decrements the target inode's
    /// link count. If the link count reaches zero, the inode's blocks become
    /// garbage (reclaimed by the compactor).
    ///
    /// # Errors
    ///
    /// - [`VfsError::NotADirectory`] if `dir_inode` is not a directory.
    /// - [`VfsError::NotFound`] if `name` does not exist in the directory.
    /// - [`VfsError::NotEmpty`] if `name` names a non-empty directory
    ///   (#623).
    /// - [`VfsError::IoError`] on I/O failure.
    fn unlink(&mut self, dir_inode: u32, name: &str) -> Result<(), VfsError> {
        let mut parent = self.load_inode(dir_inode)?;

        if parent.inode_type != INODE_TYPE_DIR {
            return Err(VfsError::NotADirectory);
        }

        let entries = self.read_dir_entries(&parent)?;

        // Find the entry to remove.
        let target_id = entries
            .iter()
            .find(|e| e.name == name)
            .map(|e| e.inode_id)
            .ok_or(VfsError::NotFound)?;

        // Remove the entry from the list.
        let remaining: Vec<DiskDirEntry> = entries.into_iter().filter(|e| e.name != name).collect();

        self.ensure_writer()?;

        let mut dev = self.dev.borrow_mut();
        let mut cache = self.cache.borrow_mut();
        let writer = self.writer.as_mut().ok_or(VfsError::IoError)?;

        // Load the target inode and compute its post-unlink link count,
        // but do NOT mutate the imap yet: the directory entry must be
        // durably removed first, or an I/O failure below leaves a
        // dangling entry that points at an inode already missing from
        // the imap (#301).
        let mut target_inode = {
            let block_num = self.imap.get(target_id).ok_or(VfsError::NotFound)?;
            // WARNING: imap entries are on-disk, untrusted data -- the
            // same class as inode.direct[], which this file already
            // bounds before it reaches the block cache (#624,
            // #security). Inlined here (rather than calling
            // self.validate_block_num) because `writer` above already
            // holds an exclusive borrow of `self.writer`, so a `&self`
            // method call on the whole struct is not available.
            if block_num == 0 || block_num >= self.superblock.block_count {
                return Err(VfsError::IoError);
            }
            let mut buf = [0u8; BLOCK_SIZE];
            cache
                .read(dev.as_mut(), block_num, &mut buf)
                .map_err(|_| VfsError::IoError)?;
            DiskInode::read_from(&buf, 0).map_err(|_| VfsError::IoError)?
        };

        // A non-empty directory must not be unlinked -- its children
        // would survive in the imap with no path that reaches them,
        // unreclaimable by the compactor (#623). Directories track
        // their content size the same way files do (create() starts
        // every new directory at size 0; the empty-directory branch
        // below resets it to 0 on removal), so `size != 0` is exactly
        // "has entries" for a directory inode -- checked before any
        // directory rewrite or imap mutation below.
        if target_inode.inode_type == INODE_TYPE_DIR && target_inode.size != 0 {
            return Err(VfsError::NotEmpty);
        }

        target_inode.link_count = target_inode.link_count.saturating_sub(1);

        // Write updated directory data FIRST -- this is the durable
        // operation that actually removes the entry from the namespace.
        if remaining.is_empty() {
            // Empty directory: set size to 0, clear data pointers.
            parent.direct[0] = 0;
            parent.size = 0;
        } else {
            let dir_block = Self::write_dir_block(
                dev.as_mut(),
                &mut cache,
                writer,
                &mut self.segments,
                &remaining,
            )?;
            parent.direct[0] = dir_block;
            parent.size = remaining.iter().map(|e| e.record_len as u64).sum();
        }

        writer
            .write_inode(
                dev.as_mut(),
                &mut cache,
                &mut self.imap,
                &mut self.segments,
                dir_inode,
                &parent,
            )
            .map_err(|_| VfsError::IoError)?;

        // Only now, after the directory entry removal is durable, retire
        // the target inode: drop it from the imap if this was the last
        // link, or persist its decremented link count otherwise.
        if target_inode.link_count == 0 {
            self.imap.remove(target_id);
        } else {
            writer
                .write_inode(
                    dev.as_mut(),
                    &mut cache,
                    &mut self.imap,
                    &mut self.segments,
                    target_id,
                    &target_inode,
                )
                .map_err(|_| VfsError::IoError)?;
        }

        drop(cache);
        drop(dev);
        self.maybe_compact()?;

        Ok(())
    }

    /// List all entries in a directory.
    ///
    /// # Errors
    ///
    /// - [`VfsError::NotADirectory`] if `dir_inode` is not a directory.
    /// - [`VfsError::NotFound`] if the inode does not exist.
    /// - [`VfsError::IoError`] on I/O failure.
    fn readdir(&self, dir_inode: u32) -> Result<Vec<DirEntry>, VfsError> {
        let inode = self.load_inode(dir_inode)?;
        let disk_entries = self.read_dir_entries(&inode)?;

        let mut entries = Vec::with_capacity(disk_entries.len());
        for de in &disk_entries {
            // WHY: a failed child load or an unrecognized on-disk type
            // is on-disk corruption; propagate it per this method's
            // documented error contract instead of silently reporting
            // the entry as a regular file.
            let child = self.load_inode(de.inode_id)?;
            let child_type = match child.inode_type {
                INODE_TYPE_DIR => InodeType::Directory,
                INODE_TYPE_FILE => InodeType::RegularFile,
                _ => return Err(VfsError::IoError),
            };

            entries.push(DirEntry {
                name: de.name.clone(),
                inode_id: de.inode_id,
                inode_type: child_type,
            });
        }

        Ok(entries)
    }

    /// Truncate a file to the specified size.
    ///
    /// If shrinking, data blocks beyond the new size become garbage
    /// (reclaimed by the compactor). If growing, new zeroed blocks are
    /// allocated.
    ///
    /// # Errors
    ///
    /// - [`VfsError::NotFound`] if the inode does not exist.
    /// - [`VfsError::IsADirectory`] if the inode is a directory.
    /// - [`VfsError::NoSpace`] if the filesystem is full (growing case),
    ///   or if `size` exceeds [`LFS_MAX_FILE_SIZE`] (only direct block
    ///   pointers are consumed today, #620).
    /// - [`VfsError::IoError`] on I/O failure.
    fn truncate(&mut self, inode_id: u32, size: u64) -> Result<(), VfsError> {
        let mut inode = self.load_inode(inode_id)?;

        if inode.inode_type == INODE_TYPE_DIR {
            return Err(VfsError::IsADirectory);
        }

        // WHY: only direct block pointers are consumed today (the
        // indirect pointer is unimplemented, #620) -- accepting a
        // larger size here would record a size write()/read() can never
        // fully service, so stat() and the file's actual servable
        // extent would permanently disagree with no error anywhere in
        // the stack.
        if size > LFS_MAX_FILE_SIZE {
            return Err(VfsError::NoSpace);
        }

        let old_size = inode.size;
        inode.size = size;

        if size < old_size {
            // Shrinking: zero out direct pointers for blocks beyond new size.
            let new_block_count = if size == 0 {
                0
            } else {
                // WHY usize::try_from: `size` is already bounded by
                // LFS_MAX_FILE_SIZE above and always fits, but an `as
                // usize` cast here would still silently wrap instead of
                // erroring should that bound ever change -- fail
                // closed rather than trust the caller's proof twice
                // over, the same class already fixed at
                // read_dir_entries (lfs.rs:743, #620).
                let size = usize::try_from(size).map_err(|_| VfsError::IoError)?;
                size.div_ceil(BLOCK_SIZE).min(DIRECT_BLOCK_COUNT)
            };

            for i in new_block_count..DIRECT_BLOCK_COUNT {
                inode.direct[i] = 0; // Becomes garbage, reclaimed by compactor.
            }
        } else if size > old_size {
            // Growing: allocate zeroed blocks for the new range.
            self.ensure_writer()?;

            let old_blocks = if old_size == 0 {
                0
            } else {
                // WHY usize::try_from: unlike `size`, `old_size` came
                // from the on-disk inode loaded above and predates
                // this bound -- untrusted u64 data that must not
                // silently wrap on a 32-bit target (#620).
                let old_size = usize::try_from(old_size).map_err(|_| VfsError::IoError)?;
                old_size.div_ceil(BLOCK_SIZE).min(DIRECT_BLOCK_COUNT)
            };
            let new_blocks = {
                let size = usize::try_from(size).map_err(|_| VfsError::IoError)?;
                size.div_ceil(BLOCK_SIZE).min(DIRECT_BLOCK_COUNT)
            };

            let mut dev = self.dev.borrow_mut();
            let mut cache = self.cache.borrow_mut();
            let writer = self.writer.as_mut().ok_or(VfsError::IoError)?;

            for i in old_blocks..new_blocks {
                if inode.direct[i] == 0 {
                    let zeroed = [0u8; BLOCK_SIZE];
                    let block_num = writer
                        .write_data_block(dev.as_mut(), &mut cache, &mut self.segments, &zeroed)
                        .map_err(Self::map_write_data_block_err)?;
                    inode.direct[i] = block_num;
                }
            }
        }

        // Write the updated inode.
        self.ensure_writer()?;

        let mut dev = self.dev.borrow_mut();
        let mut cache = self.cache.borrow_mut();
        let writer = self.writer.as_mut().ok_or(VfsError::IoError)?;

        writer
            .write_inode(
                dev.as_mut(),
                &mut cache,
                &mut self.imap,
                &mut self.segments,
                inode_id,
                &inode,
            )
            .map_err(|_| VfsError::IoError)?;

        Ok(())
    }

    /// Flush cached writes and write a checkpoint to the block device.
    ///
    /// Persists the current imap and segment bitmap so the filesystem
    /// can be recovered on next mount.
    ///
    /// # Errors
    ///
    /// Returns [`VfsError::IoError`] if the cache flush or checkpoint write fails.
    fn sync(&mut self) -> Result<(), VfsError> {
        let mut cache = self.cache.borrow_mut();
        let mut dev = self.dev.borrow_mut();

        // Flush the block cache first.
        cache.flush(dev.as_mut()).map_err(|_| VfsError::IoError)?;

        // Write checkpoint if we have a writer (i.e., writes have occurred).
        if let Some(ref mut writer) = self.writer {
            let slots = (
                self.superblock.checkpoint_block_a,
                self.superblock.checkpoint_block_b,
            );

            writer
                .write_checkpoint(
                    dev.as_mut(),
                    &mut cache,
                    &self.imap,
                    &self.segments,
                    slots,
                    self.checkpoint_sequence,
                    self.next_inode,
                )
                .map_err(|_| VfsError::IoError)?;

            self.checkpoint_sequence += 1;

            cache.flush(dev.as_mut()).map_err(|_| VfsError::IoError)?;
        }

        Ok(())
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::{self as block, MemBlockDevice};
    use crate::vfs::Filesystem;

    /// Create an 8 MB test device (16384 sectors = 2048 blocks = 8 segments).
    fn block_device_for_lfs() -> MemBlockDevice {
        MemBlockDevice::new(16384).expect("create 8 MB test device")
    }

    #[test]
    fn format_creates_valid_superblock() {
        let mut dev = block_device_for_lfs();
        format(&mut dev).expect("format should succeed");

        // Read superblock back directly.
        let mut buf = [0u8; BLOCK_SIZE];
        block::read_block(&dev, SUPERBLOCK_BLOCK, &mut buf).expect("read superblock");
        let sb = LfsSuperblock::from_block(&buf).expect("parse superblock");

        assert_eq!(sb.magic, LFS_MAGIC);
        assert_eq!(sb.version, LFS_VERSION);
        assert_eq!(sb.block_count, 2048);
        assert_eq!(sb.segment_size, 256);
        assert_eq!(sb.segment_count, 8);
        assert_eq!(sb.root_inode, 0);
        assert_eq!(sb.next_inode, 1);
        assert_eq!(sb.checkpoint_block_a, CHECKPOINT_SLOT_A);
        assert_eq!(sb.checkpoint_block_b, CHECKPOINT_SLOT_B);
    }

    #[test]
    fn format_rejects_device_smaller_than_two_segments() {
        // total_blocks must be >= DEFAULT_SEGMENT_SIZE * 2 (512 blocks);
        // this device provides only 100 blocks (800 sectors), well under
        // the minimum -- format() must fail closed rather than write a
        // superblock describing a filesystem the device cannot hold.
        let mut dev = MemBlockDevice::new(800).expect("create undersized test device");
        let result = format(&mut dev);
        assert_eq!(
            result,
            Err(LfsError::InvalidSuperblock),
            "a device with fewer than two segments worth of blocks must be rejected"
        );
    }

    #[test]
    fn mount_reads_formatted_filesystem() {
        let mut dev = block_device_for_lfs();
        format(&mut dev).expect("format");

        let fs = mount(Box::new(dev)).expect("mount should succeed");

        assert_eq!(fs.superblock.magic, LFS_MAGIC);
        assert_eq!(fs.superblock.root_inode, 0);
        assert_eq!(fs.superblock.block_count, 2048);
        assert!(fs.imap.get(0).is_some(), "root inode should be in the imap");
    }

    #[test]
    fn read_empty_root_returns_no_entries() {
        let mut dev = block_device_for_lfs();
        format(&mut dev).expect("format");

        let fs = mount(Box::new(dev)).expect("mount");
        let root = fs.root_inode();
        let entries = fs.readdir(root).expect("readdir root");

        assert!(
            entries.is_empty(),
            "freshly formatted root should have no entries"
        );
    }

    #[test]
    fn readdir_propagates_child_inode_load_failure_instead_of_faking_regular_file() {
        let mut dev = block_device_for_lfs();
        format(&mut dev).expect("format");

        let mut fs = mount(Box::new(dev)).expect("mount");
        let root = fs.root_inode();

        let file_id = fs
            .create(root, "orphan.txt", InodeType::RegularFile)
            .expect("create file");

        // Corrupt the imap so the child inode can no longer be loaded,
        // while the directory entry itself (which still names the
        // child) is untouched. Before the fix, readdir() swallowed
        // this load failure and reported the entry as InodeType::
        // RegularFile regardless of the real (unknown) type.
        fs.imap.remove(file_id);

        let result = fs.readdir(root);
        assert_eq!(
            result,
            Err(VfsError::NotFound),
            "a child inode that can no longer be loaded must surface as an error, not be silently reported as a regular file"
        );
    }

    #[test]
    fn format_then_mount_round_trips() {
        let mut dev = block_device_for_lfs();
        format(&mut dev).expect("format");

        let fs = mount(Box::new(dev)).expect("mount");

        // Verify root inode exists and is a directory.
        let root_id = fs.root_inode();
        let stat = fs.stat(root_id).expect("stat root");
        assert_eq!(stat.inode_type, InodeType::Directory);
        assert_eq!(stat.inode_id, 0);
        assert_eq!(stat.size, 0, "empty root dir should have size 0");
    }

    #[test]
    fn stat_nonexistent_inode_returns_not_found() {
        let mut dev = block_device_for_lfs();
        format(&mut dev).expect("format");

        let fs = mount(Box::new(dev)).expect("mount");
        let result = fs.stat(999);
        assert_eq!(result, Err(VfsError::NotFound));
    }

    #[test]
    fn read_dir_entries_rejects_size_that_overflows_usize_on_32_bit() {
        let mut dev = block_device_for_lfs();
        format(&mut dev).expect("format");
        let fs = mount(Box::new(dev)).expect("mount");

        // On this 32-bit test target (i686/armv7 usize), u32::MAX + 1
        // does not fit in usize. Before the fix, `inode.size as usize`
        // silently truncated instead of erroring.
        let inode = DiskInode {
            inode_type: INODE_TYPE_DIR,
            link_count: 1,
            size: u64::from(u32::MAX) + 1,
            direct: [0u64; DIRECT_BLOCK_COUNT],
            indirect: 0,
        };

        let result = fs.read_dir_entries(&inode);
        assert!(
            matches!(result, Err(VfsError::IoError)),
            "an inode size that does not fit in usize must be rejected, not silently truncated"
        );
    }

    #[test]
    fn inode_to_stat_rejects_unrecognized_on_disk_type() {
        let inode = DiskInode {
            inode_type: 99, // neither INODE_TYPE_FILE nor INODE_TYPE_DIR
            link_count: 1,
            size: 0,
            direct: [0u64; DIRECT_BLOCK_COUNT],
            indirect: 0,
        };

        // Before the fix, an unrecognized on-disk type silently fell
        // through to InodeType::RegularFile instead of being reported
        // as corruption.
        let result = Lfs::inode_to_stat(1, &inode);
        assert_eq!(result, Err(VfsError::IoError));
    }

    #[test]
    fn lookup_in_empty_root_returns_not_found() {
        let mut dev = block_device_for_lfs();
        format(&mut dev).expect("format");

        let fs = mount(Box::new(dev)).expect("mount");
        let result = fs.lookup(fs.root_inode(), "nonexistent");
        assert_eq!(result, Err(VfsError::NotFound));
    }

    #[test]
    fn read_dir_entries_rejects_direct_pointer_outside_extent() {
        let mut dev = block_device_for_lfs();
        format(&mut dev).expect("format");
        let mut fs = mount(Box::new(dev)).expect("mount");

        // Simulate a corrupted/crafted inode whose direct pointer targets
        // a block within the raw device's capacity but outside the
        // filesystem's own declared extent -- the block-device layer
        // alone would happily serve this read (it is a valid LBA); only
        // a filesystem-level bound check catches it.
        let real_block_count = fs.superblock.block_count;
        fs.superblock.block_count = 4;

        let mut inode = DiskInode {
            inode_type: INODE_TYPE_DIR,
            link_count: 1,
            size: BLOCK_SIZE as u64,
            direct: [0u64; DIRECT_BLOCK_COUNT],
            indirect: 0,
        };
        inode.direct[0] = real_block_count - 1;

        let result = fs.read_dir_entries(&inode);
        assert!(
            matches!(result, Err(VfsError::IoError)),
            "a direct block pointer inside the raw device but outside the filesystem's own extent must be rejected, not read"
        );
    }

    #[test]
    fn load_inode_rejects_imap_block_pointing_at_superblock() {
        let mut dev = block_device_for_lfs();
        format(&mut dev).expect("format");
        let mut fs = mount(Box::new(dev)).expect("mount");
        let root = fs.root_inode();

        let file_id = fs
            .create(root, "f", InodeType::RegularFile)
            .expect("create");

        // Point the target's imap entry at block 0 -- the superblock
        // itself, always present and always readable at the raw device
        // level, so a pre-fix read would succeed and misparse
        // superblock bytes as the target's DiskInode instead of
        // failing. load_inode() handed imap-derived block numbers
        // straight to the cache with no bound check, unlike
        // inode.direct[] which this file already guards (#624).
        fs.imap.insert(file_id, 0);

        let result = fs.load_inode(file_id);
        assert!(
            matches!(result, Err(VfsError::IoError)),
            "an imap entry pointing at block 0 (the superblock) must be rejected, not read as the inode's own data"
        );
    }

    #[test]
    fn create_file_then_read_back() {
        let mut dev = block_device_for_lfs();
        format(&mut dev).expect("format");

        let mut fs = mount(Box::new(dev)).expect("mount");
        let root = fs.root_inode();

        // Create a file.
        let file_id = fs
            .create(root, "hello.txt", InodeType::RegularFile)
            .expect("create file");

        // Verify it appears in readdir.
        let entries = fs.readdir(root).expect("readdir");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "hello.txt");
        assert_eq!(entries[0].inode_id, file_id);
        assert_eq!(entries[0].inode_type, InodeType::RegularFile);

        // Verify stat.
        let stat = fs.stat(file_id).expect("stat");
        assert_eq!(stat.inode_type, InodeType::RegularFile);
        assert_eq!(stat.size, 0);

        // Verify lookup.
        let found_id = fs.lookup(root, "hello.txt").expect("lookup");
        assert_eq!(found_id, file_id);
    }

    #[test]
    fn create_rejects_duplicate_name() {
        let mut dev = block_device_for_lfs();
        format(&mut dev).expect("format");
        let mut fs = mount(Box::new(dev)).expect("mount");
        let root = fs.root_inode();

        fs.create(root, "dup", InodeType::RegularFile)
            .expect("first create must succeed");

        let result = fs.create(root, "dup", InodeType::RegularFile);
        assert_eq!(
            result,
            Err(VfsError::AlreadyExists),
            "creating a name that already exists in the directory must be rejected"
        );
    }

    #[test]
    fn write_sync_remount_persists_data() {
        let mut dev = block_device_for_lfs();
        format(&mut dev).expect("format");

        // First mount: write data and sync (checkpoint) it to the device.
        let mut fs = mount(Box::new(dev)).expect("mount");
        let root = fs.root_inode();
        let file_id = fs
            .create(root, "data.bin", InodeType::RegularFile)
            .expect("create");

        let data = b"Hello, LFS write path!";
        let written = fs.write(file_id, 0, data).expect("write");
        assert_eq!(written, data.len());

        fs.sync().expect("sync");

        // WHY this is the real persistence boundary a reboot crosses: the
        // in-memory Lfs is dropped, but the device bytes (including the
        // checkpoint sync() just wrote) are handed intact to a fresh mount().
        // fs.dev is RefCell<Box<dyn BlockDevice>>; into_inner() yields exactly
        // the Box<dyn BlockDevice> that mount() consumes — no downcast needed,
        // so the old test's stated blocker was spurious.
        let boxed_dev = fs.dev.into_inner();

        let fs2 = mount(boxed_dev).expect("remount");

        let mut buf = [0u8; 64];
        let read = fs2.read(file_id, 0, &mut buf).expect("read after remount");
        assert_eq!(read, data.len());
        assert_eq!(
            &buf[..data.len()],
            data,
            "data written before sync must survive a real remount"
        );
    }

    #[test]
    fn mkdir_creates_directory_on_disk() {
        let mut dev = block_device_for_lfs();
        format(&mut dev).expect("format");

        let mut fs = mount(Box::new(dev)).expect("mount");
        let root = fs.root_inode();

        let dir_id = fs
            .create(root, "subdir", InodeType::Directory)
            .expect("mkdir");

        let stat = fs.stat(dir_id).expect("stat");
        assert_eq!(stat.inode_type, InodeType::Directory);
        assert_eq!(stat.size, 0);

        // Parent should list it.
        let entries = fs.readdir(root).expect("readdir root");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "subdir");
        assert_eq!(entries[0].inode_type, InodeType::Directory);
    }

    #[test]
    fn unlink_marks_blocks_as_garbage() {
        let mut dev = block_device_for_lfs();
        format(&mut dev).expect("format");

        let mut fs = mount(Box::new(dev)).expect("mount");
        let root = fs.root_inode();

        let file_id = fs
            .create(root, "remove_me", InodeType::RegularFile)
            .expect("create");

        // Verify it exists.
        assert!(fs.lookup(root, "remove_me").is_ok());

        // Unlink it.
        fs.unlink(root, "remove_me").expect("unlink");

        // Should no longer be found.
        assert_eq!(fs.lookup(root, "remove_me"), Err(VfsError::NotFound));

        // Inode should be removed from imap (link count was 1).
        assert_eq!(fs.stat(file_id), Err(VfsError::NotFound));
    }

    #[test]
    fn unlink_rejects_target_imap_block_pointing_at_superblock() {
        let mut dev = block_device_for_lfs();
        format(&mut dev).expect("format");
        let mut fs = mount(Box::new(dev)).expect("mount");
        let root = fs.root_inode();

        let file_id = fs
            .create(root, "f", InodeType::RegularFile)
            .expect("create");

        // Point the target's imap entry at block 0 -- the superblock
        // itself. Root's own imap entry is untouched, so the parent
        // lookup at the top of unlink() is unaffected by this
        // corruption; only unlink()'s own direct imap read (distinct
        // from load_inode's, and unguarded before the fix) is exercised
        // (#624).
        fs.imap.insert(file_id, 0);

        let result = fs.unlink(root, "f");
        assert!(
            matches!(result, Err(VfsError::IoError)),
            "unlink() must reject an imap entry pointing at block 0 (the superblock), not read it as the target inode"
        );

        assert!(
            fs.lookup(root, "f").is_ok(),
            "a rejected unlink must not have mutated the parent directory"
        );
    }

    #[test]
    fn unlink_removes_empty_directory() {
        let mut dev = block_device_for_lfs();
        format(&mut dev).expect("format");
        let mut fs = mount(Box::new(dev)).expect("mount");
        let root = fs.root_inode();

        let dir_id = fs.create(root, "sub", InodeType::Directory).expect("mkdir");

        fs.unlink(root, "sub")
            .expect("unlink of an empty directory must succeed");

        assert_eq!(fs.lookup(root, "sub"), Err(VfsError::NotFound));
        assert_eq!(fs.stat(dir_id), Err(VfsError::NotFound));
    }

    #[test]
    fn unlink_rejects_non_empty_directory() {
        let mut dev = block_device_for_lfs();
        format(&mut dev).expect("format");
        let mut fs = mount(Box::new(dev)).expect("mount");
        let root = fs.root_inode();

        let sub_id = fs.create(root, "sub", InodeType::Directory).expect("mkdir");
        let file_id = fs
            .create(sub_id, "f", InodeType::RegularFile)
            .expect("create nested file");

        // Before the fix, unlink() never inspected the target's type or
        // contents: it decremented link_count and dropped the inode
        // from the imap unconditionally, orphaning "f" -- reachable by
        // no path, but never reclaimed (#623).
        let result = fs.unlink(root, "sub");
        assert_eq!(
            result,
            Err(VfsError::NotEmpty),
            "unlink of a non-empty directory must fail, not orphan its children"
        );

        // Nothing must have been mutated: the directory and its child
        // both remain reachable.
        assert!(
            fs.lookup(root, "sub").is_ok(),
            "directory must remain in its parent after a rejected unlink"
        );
        assert!(
            fs.stat(file_id).is_ok(),
            "child inode must remain in the imap after a rejected unlink"
        );
        assert_eq!(
            fs.readdir(sub_id).expect("readdir sub").len(),
            1,
            "the child directory entry must be untouched"
        );
    }

    #[test]
    fn unlink_persists_decremented_link_count_when_links_remain() {
        let mut dev = block_device_for_lfs();
        format(&mut dev).expect("format");
        let mut fs = mount(Box::new(dev)).expect("mount");
        let root = fs.root_inode();

        let file_id = fs
            .create(root, "a", InodeType::RegularFile)
            .expect("create must succeed");

        // Simulate a second hard link ("b") to the same inode with
        // link_count bumped to 2 -- this filesystem has no public link()
        // syscall yet, so the second name and the elevated link_count
        // are constructed directly at the LFS internals level, mirroring
        // what a real link() implementation would leave on disk.
        fs.ensure_writer().expect("ensure_writer");
        let mut parent = fs.load_inode(root).expect("load root");
        let mut entries = fs.read_dir_entries(&parent).expect("read root entries");
        entries.push(DiskDirEntry {
            inode_id: file_id,
            name_len: 1,
            record_len: ((DIR_ENTRY_HEADER_SIZE + 1 + 3) & !3) as u16,
            name: String::from("b"),
        });

        let mut target_inode = fs.load_inode(file_id).expect("load target");
        target_inode.link_count = 2;

        {
            let mut raw_dev = fs.dev.borrow_mut();
            let mut cache = fs.cache.borrow_mut();
            let writer = fs
                .writer
                .as_mut()
                .expect("writer present after ensure_writer");

            let dir_block = Lfs::write_dir_block(
                raw_dev.as_mut(),
                &mut cache,
                writer,
                &mut fs.segments,
                &entries,
            )
            .expect("write_dir_block must succeed");
            parent.direct[0] = dir_block;
            parent.size = entries.iter().map(|e| e.record_len as u64).sum();

            writer
                .write_inode(
                    raw_dev.as_mut(),
                    &mut cache,
                    &mut fs.imap,
                    &mut fs.segments,
                    root,
                    &parent,
                )
                .expect("write parent inode");
            writer
                .write_inode(
                    raw_dev.as_mut(),
                    &mut cache,
                    &mut fs.imap,
                    &mut fs.segments,
                    file_id,
                    &target_inode,
                )
                .expect("write bumped link_count inode");
        }

        // Now unlink "a" -- the inode has link_count=2, so this must hit
        // the else-branch: persist link_count=1 and keep the inode in the
        // imap (not remove it), and "b" must still resolve to it.
        let result = fs.unlink(root, "a");
        assert!(result.is_ok(), "unlink must succeed");

        let stat = fs.stat(file_id);
        assert!(
            stat.is_ok(),
            "an inode with remaining links must not be removed from the imap"
        );

        let via_b = fs
            .lookup(root, "b")
            .expect("second link must still resolve");
        assert_eq!(via_b, file_id);

        let reloaded = fs.load_inode(file_id).expect("load after unlink");
        assert_eq!(
            reloaded.link_count, 1,
            "link_count must be persisted as decremented (2 -> 1), not left stale or removed"
        );
    }

    #[test]
    fn truncate_shrinks_file() {
        let mut dev = block_device_for_lfs();
        format(&mut dev).expect("format");

        let mut fs = mount(Box::new(dev)).expect("mount");
        let root = fs.root_inode();

        let file_id = fs
            .create(root, "shrink.txt", InodeType::RegularFile)
            .expect("create");

        // Write 8 KiB of data (2 blocks).
        let data = [0xAAu8; 8192];
        let written = fs.write(file_id, 0, &data).expect("write");
        assert_eq!(written, 8192);

        let stat = fs.stat(file_id).expect("stat before truncate");
        assert_eq!(stat.size, 8192);

        // Truncate to 100 bytes.
        fs.truncate(file_id, 100).expect("truncate");

        let stat = fs.stat(file_id).expect("stat after truncate");
        assert_eq!(stat.size, 100);
    }

    #[test]
    fn truncate_grows_file_with_zeroed_extension() {
        let mut dev = block_device_for_lfs();
        format(&mut dev).expect("format");

        let mut fs = mount(Box::new(dev)).expect("mount");
        let root = fs.root_inode();

        let file_id = fs
            .create(root, "grow.txt", InodeType::RegularFile)
            .expect("create");

        // WHY payload confined to block 0: keeps the read-back assertion below
        // targeting only the block the grow branch allocated, never write()'s
        // own same-block zero padding.
        let data = b"seed data";
        let written = fs.write(file_id, 0, data).expect("write");
        assert_eq!(written, data.len());

        // NOTE: old_blocks=ceil(9/4096)=1, new_blocks=ceil(8192/4096)=2, so the
        // grow loop runs once (block index 1) — exercises truncate's grow
        // branch (ensure_writer + zeroed-block allocation), not the shrink path.
        let new_size: u64 = 8192;
        fs.truncate(file_id, new_size).expect("truncate grow");

        let stat = fs.stat(file_id).expect("stat after grow");
        assert_eq!(stat.size, new_size, "size must report the grown length");

        let mut buf = [0u8; BLOCK_SIZE];
        let read = fs
            .read(file_id, BLOCK_SIZE as u64, &mut buf)
            .expect("read grown block");
        assert_eq!(read, buf.len());
        assert!(
            buf.iter().all(|&b| b == 0),
            "the newly grown block must read back zero, not stale memory"
        );
    }

    #[test]
    fn truncate_rejects_size_past_direct_block_limit() {
        let mut dev = block_device_for_lfs();
        format(&mut dev).expect("format");
        let mut fs = mount(Box::new(dev)).expect("mount");
        let root = fs.root_inode();

        let file_id = fs
            .create(root, "big.bin", InodeType::RegularFile)
            .expect("create");

        // DIRECT_BLOCK_COUNT * BLOCK_SIZE (48 KiB) is the largest size
        // direct blocks alone can back; before the fix, truncate()
        // accepted any u64 size and stored it unchecked, even though
        // write()/read() could never fully service it (#620).
        let result = fs.truncate(file_id, LFS_MAX_FILE_SIZE + 1);
        assert_eq!(
            result,
            Err(VfsError::NoSpace),
            "truncate() must reject a size beyond what direct blocks can serve"
        );

        let stat = fs.stat(file_id).expect("stat");
        assert_eq!(
            stat.size, 0,
            "a rejected truncate must not have recorded the oversized size"
        );
    }

    #[test]
    fn write_past_direct_block_limit_errors_instead_of_dropping_data() {
        let mut dev = block_device_for_lfs();
        format(&mut dev).expect("format");
        let mut fs = mount(Box::new(dev)).expect("mount");
        let root = fs.root_inode();

        let file_id = fs
            .create(root, "f", InodeType::RegularFile)
            .expect("create");

        // A write whose starting offset is already past the last direct
        // block must fail closed, not report Ok(0) -- indistinguishable
        // from a zero-length request, so a caller's write-all loop would
        // spin forever while the data is silently discarded. Before the
        // fix this also phantom-bumped inode.size to the requested tail
        // offset despite writing zero bytes (#620).
        let buf = [0xAAu8; 16];
        let result = fs.write(file_id, LFS_MAX_FILE_SIZE, &buf);
        assert_eq!(
            result,
            Err(VfsError::NoSpace),
            "write() past the direct-block limit must error, not return Ok(0)"
        );

        let stat = fs.stat(file_id).expect("stat");
        assert_eq!(
            stat.size, 0,
            "a rejected write must not have recorded a phantom size"
        );
    }

    #[test]
    fn read_at_offset_past_direct_block_limit_errors_instead_of_false_eof() {
        let mut dev = block_device_for_lfs();
        format(&mut dev).expect("format");
        let mut fs = mount(Box::new(dev)).expect("mount");
        let root = fs.root_inode();

        let file_id = fs
            .create(root, "f", InodeType::RegularFile)
            .expect("create");

        // Simulate on-disk state whose recorded size promises more than
        // direct blocks can back (pre-fix truncate()/write() could both
        // produce this; post-fix it can only arise from legacy or
        // corrupted on-disk data). This filesystem has no public API to
        // reach that state anymore, so it is constructed directly at
        // the LFS internals level, mirroring
        // unlink_persists_decremented_link_count_when_links_remain.
        fs.ensure_writer().expect("ensure_writer");
        let mut inode = fs.load_inode(file_id).expect("load");
        inode.size = LFS_MAX_FILE_SIZE + 4096;
        {
            let mut dev_ref = fs.dev.borrow_mut();
            let mut cache = fs.cache.borrow_mut();
            let writer = fs
                .writer
                .as_mut()
                .expect("writer present after ensure_writer");
            writer
                .write_inode(
                    dev_ref.as_mut(),
                    &mut cache,
                    &mut fs.imap,
                    &mut fs.segments,
                    file_id,
                    &inode,
                )
                .expect("write oversized-size inode");
        }

        let stat = fs.stat(file_id).expect("stat");
        assert_eq!(stat.size, LFS_MAX_FILE_SIZE + 4096);

        // offset is within the file per stat(), but past what direct
        // blocks can serve -- before the fix this returned Ok(0),
        // indistinguishable from true EOF, even though offset <
        // inode.size (#620).
        let mut buf = [0u8; 16];
        let result = fs.read(file_id, LFS_MAX_FILE_SIZE, &mut buf);
        assert_eq!(
            result,
            Err(VfsError::IoError),
            "read() at an in-file offset past the direct-block limit must error, not report Ok(0)"
        );
    }

    #[test]
    fn read_rejects_available_size_that_overflows_usize_on_32_bit() {
        let mut dev = block_device_for_lfs();
        format(&mut dev).expect("format");
        let mut fs = mount(Box::new(dev)).expect("mount");
        let root = fs.root_inode();

        let file_id = fs
            .create(root, "f", InodeType::RegularFile)
            .expect("create");

        // On this 32-bit test target (i686/armv7 usize), u32::MAX + 1
        // does not fit in usize. Before the fix, `available as usize`
        // in read() silently wrapped instead of erroring, short-reading
        // (as a lying Ok(0), since to_read collapsed to 0) any file
        // larger than u32::MAX rather than surfacing the fault (#620).
        fs.ensure_writer().expect("ensure_writer");
        let mut inode = fs.load_inode(file_id).expect("load");
        inode.size = u64::from(u32::MAX) + 1;
        {
            let mut dev_ref = fs.dev.borrow_mut();
            let mut cache = fs.cache.borrow_mut();
            let writer = fs
                .writer
                .as_mut()
                .expect("writer present after ensure_writer");
            writer
                .write_inode(
                    dev_ref.as_mut(),
                    &mut cache,
                    &mut fs.imap,
                    &mut fs.segments,
                    file_id,
                    &inode,
                )
                .expect("write oversized-size inode");
        }

        let mut buf = [0u8; 16];
        let result = fs.read(file_id, 0, &mut buf);
        assert_eq!(
            result,
            Err(VfsError::IoError),
            "read() must reject a size cast that would truncate on a 32-bit target rather than silently wrap"
        );
    }

    #[test]
    fn sync_writes_checkpoint() {
        let mut dev = block_device_for_lfs();
        format(&mut dev).expect("format");

        let mut fs = mount(Box::new(dev)).expect("mount");
        let root = fs.root_inode();

        // Create a file so there is state to checkpoint.
        fs.create(root, "checkpoint_test", InodeType::RegularFile)
            .expect("create");

        // Sync should write a checkpoint without error.
        fs.sync().expect("sync");

        // Verify the file is still accessible after sync.
        let found = fs.lookup(root, "checkpoint_test");
        assert!(found.is_ok(), "file should be accessible after sync");

        // Verify checkpoint sequence was incremented.
        assert!(
            fs.checkpoint_sequence > 1,
            "checkpoint sequence should have incremented"
        );
    }

    #[test]
    fn read_block_and_write_block_round_trip() {
        let mut dev = block_device_for_lfs();
        let buf = [0xAB_u8; BLOCK_SIZE];
        block::write_block(&mut dev, 5, &buf).expect("write_block");

        let mut read_buf = [0u8; BLOCK_SIZE];
        block::read_block(&dev, 5, &mut read_buf).expect("read_block");
        assert_eq!(read_buf, buf);
    }

    #[test]
    fn superblock_round_trips_through_block() {
        let sb = LfsSuperblock {
            magic: LFS_MAGIC,
            version: LFS_VERSION,
            block_count: 4096,
            segment_size: 256,
            segment_count: 16,
            checkpoint_block_a: 1,
            checkpoint_block_b: 2,
            imap_block: 3,
            imap_block_count: 4,
            root_inode: 0,
            next_inode: 10,
        };

        let block = sb.to_block();
        let restored = LfsSuperblock::from_block(&block).expect("parse");

        assert_eq!(restored.magic, LFS_MAGIC);
        assert_eq!(restored.version, LFS_VERSION);
        assert_eq!(restored.block_count, 4096);
        assert_eq!(restored.segment_count, 16);
        assert_eq!(restored.next_inode, 10);
    }

    #[test]
    fn alternating_sync_checkpoints_leave_both_slots_valid() {
        let mut dev = block_device_for_lfs();
        format(&mut dev).expect("format");

        let mut fs = mount(Box::new(dev)).expect("mount");
        let root = fs.root_inode();

        // First sync after mount uses an even checkpoint_sequence -> slot A.
        fs.create(root, "a.txt", InodeType::RegularFile)
            .expect("create a");
        fs.sync().expect("sync 1 (slot A)");

        // Second sync -> odd sequence -> slot B.
        fs.create(root, "b.txt", InodeType::RegularFile)
            .expect("create b");
        fs.sync().expect("sync 2 (slot B)");

        // Both on-disk checkpoint slot headers must still carry a valid
        // magic and be independently readable: slot A's payload must not
        // have overwritten slot B's header or vice versa (#319).
        let mut dev2 = fs.dev.into_inner();
        let mut cache = BlockCache::new();
        let header_a =
            lfs_checkpoint::read_checkpoint(dev2.as_mut(), &mut cache, CHECKPOINT_SLOT_A)
                .expect("slot A header still valid");
        let header_b =
            lfs_checkpoint::read_checkpoint(dev2.as_mut(), &mut cache, CHECKPOINT_SLOT_B)
                .expect("slot B header still valid");

        assert_eq!(header_a.magic, CHECKPOINT_MAGIC);
        assert_eq!(header_b.magic, CHECKPOINT_MAGIC);
    }

    #[test]
    fn unlink_io_failure_during_directory_write_leaves_imap_and_directory_consistent() {
        // A hand-built, minimal Lfs: 5 segments of 6 blocks each. Segment
        // 0 is reserved; segments 2 and 3 are pinned used up front,
        // leaving segments 1 and 4 free. LfsWriter::new() ordinarily
        // allocates segment 1, and segment 4 is withheld as the
        // compaction reserve (#329) -- ordinary allocation can never
        // touch it, so once segment 1's 5 data slots fill, there is
        // nowhere left for the ordinary path to seal into, letting the
        // directory rewrite inside unlink() fail with a real I/O error
        // (#301).
        let mut dev =
            MemBlockDevice::new(5 * 6 * SECTORS_PER_BLOCK as u64).expect("create tiny device");
        let mut cache = BlockCache::new();
        let mut seg_mgr = LfsSegmentManager::new(5, 6);
        seg_mgr.mark_used(0);
        seg_mgr.mark_used(2);
        seg_mgr.mark_used(3);

        let mut imap = LfsImap::new();
        let mut writer = LfsWriter::new(&mut seg_mgr).expect("create writer");

        let dir_inode_template = DiskInode {
            inode_type: INODE_TYPE_DIR,
            link_count: 1,
            size: 0,
            direct: [0u64; DIRECT_BLOCK_COUNT],
            indirect: 0,
        };
        let file_inode_template = DiskInode {
            inode_type: INODE_TYPE_FILE,
            link_count: 1,
            size: 0,
            direct: [0u64; DIRECT_BLOCK_COUNT],
            indirect: 0,
        };

        // Write 1/5: root placeholder (fills a slot; superseded below).
        writer
            .write_inode(
                &mut dev,
                &mut cache,
                &mut imap,
                &mut seg_mgr,
                0,
                &dir_inode_template,
            )
            .expect("write root placeholder");
        // Write 2/5: victim inode.
        writer
            .write_inode(
                &mut dev,
                &mut cache,
                &mut imap,
                &mut seg_mgr,
                1,
                &file_inode_template,
            )
            .expect("write victim inode");
        // Write 3/5: keeper inode.
        writer
            .write_inode(
                &mut dev,
                &mut cache,
                &mut imap,
                &mut seg_mgr,
                2,
                &file_inode_template,
            )
            .expect("write keeper inode");

        // Write 4/5: initial directory block listing both entries.
        let mut entries: Vec<DiskDirEntry> = Vec::new();
        entries.push(DiskDirEntry {
            inode_id: 1,
            name_len: 6,
            record_len: ((DIR_ENTRY_HEADER_SIZE + 6 + 3) & !3) as u16,
            name: String::from("victim"),
        });
        entries.push(DiskDirEntry {
            inode_id: 2,
            name_len: 6,
            record_len: ((DIR_ENTRY_HEADER_SIZE + 6 + 3) & !3) as u16,
            name: String::from("keeper"),
        });
        let dir_block =
            Lfs::write_dir_block(&mut dev, &mut cache, &mut writer, &mut seg_mgr, &entries)
                .expect("write initial dir block");

        // Write 5/5: root inode updated to point at the directory block.
        // This consumes the last of segment 1's 5 data slots.
        let mut root = dir_inode_template;
        root.direct[0] = dir_block;
        root.size = entries.iter().map(|e| e.record_len as u64).sum();
        writer
            .write_inode(&mut dev, &mut cache, &mut imap, &mut seg_mgr, 0, &root)
            .expect("write updated root inode");

        assert_eq!(
            seg_mgr.free_count(),
            1,
            "setup must exhaust every ordinarily-allocatable segment, leaving only the compaction reserve"
        );

        let superblock = LfsSuperblock {
            magic: LFS_MAGIC,
            version: LFS_VERSION,
            block_count: dev.sector_count() / SECTORS_PER_BLOCK as u64,
            segment_size: 6,
            segment_count: 5,
            checkpoint_block_a: 1,
            checkpoint_block_b: 2,
            imap_block: 3,
            imap_block_count: 1,
            root_inode: 0,
            next_inode: 3,
        };

        let mut fs = Lfs {
            dev: RefCell::new(Box::new(dev)),
            cache: RefCell::new(cache),
            imap,
            segments: seg_mgr,
            superblock,
            next_sequence: writer.sequence(),
            writer: Some(writer),
            next_inode: 3,
            checkpoint_sequence: 1,
        };

        // The directory now has zero spare capacity in its segment.
        // Unlinking "victim" must rewrite the directory block for the
        // remaining "keeper" entry, which needs to seal into a new
        // segment -- and none is free, so the write fails.
        let result = fs.unlink(0, "victim");
        assert_eq!(
            result,
            Err(VfsError::NoSpace),
            "the directory rewrite should fail: no free segment remains to seal into"
        );

        // The imap must still show the victim inode: it must NOT have
        // been removed when the durable directory write never landed
        // (#301).
        assert!(
            fs.stat(1).is_ok(),
            "victim inode must remain in the imap after a failed unlink"
        );

        // The on-disk directory must still list the victim entry.
        let dir_entries = fs.readdir(0).expect("readdir root");
        assert!(
            dir_entries.iter().any(|e| e.name == "victim"),
            "directory entry must remain after a failed unlink"
        );
    }

    #[test]
    fn create_failure_rolls_back_orphaned_imap_entry() {
        use alloc::format;

        let mut dev = block_device_for_lfs();
        format(&mut dev).expect("format");

        let mut fs = mount(Box::new(dev)).expect("mount");
        let root = fs.root_inode();

        // Fill the one-block directory to capacity (256 fixed-size
        // entries; see create_past_one_block_capacity_fails_without_dropping_entries).
        let mut created = 0usize;
        loop {
            let name = format!("file{:03}", created);
            match fs.create(root, &name, InodeType::RegularFile) {
                Ok(_) => created += 1,
                Err(VfsError::NoSpace) => break,
                Err(e) => panic!("unexpected error at entry {created}: {e:?}"),
            }
            if created > 300 {
                panic!("directory did not report NoSpace within expected bounds");
            }
        }

        // The 257th create() allocated (and durably wrote) a new inode
        // via write_inode() before write_dir_block() rejected the entry
        // for lack of room -- without a rollback, that inode is now an
        // orphan: present in the imap, reachable FROM no directory.
        let orphan_candidate = fs.next_inode - 1;
        assert!(
            fs.stat(orphan_candidate).is_err(),
            "a create() that fails after write_inode() but before the directory entry \
             lands must roll back the imap insert, not leak the inode"
        );
    }

    #[test]
    fn mount_rejects_oversized_segment_bitmap_count() {
        let mut dev = block_device_for_lfs();
        format(&mut dev).expect("format");

        // Corrupt the on-disk checkpoint header: claim a
        // segment_bitmap_count far beyond what this device's
        // segment_count could ever need. This must be rejected before
        // mount() allocates anything sized by it (#302).
        let mut cache = BlockCache::new();
        let mut header = lfs_checkpoint::read_checkpoint(&mut dev, &mut cache, CHECKPOINT_SLOT_A)
            .expect("read initial checkpoint");
        header.segment_bitmap_count = u32::MAX / 2;
        let header_buf = header.to_block();
        block::write_block(&mut dev, CHECKPOINT_SLOT_A, &header_buf)
            .expect("write corrupted header");

        let result = mount(Box::new(dev));
        assert!(
            matches!(result, Err(LfsError::Corrupt)),
            "an oversized segment_bitmap_count must be rejected, not used to drive an allocation"
        );
    }

    /// A device wrapper whose writes always fail: used to prove a code
    /// path (here, `mount()` rejecting a corrupt image) performs reads
    /// only and never writes through to the disk it is validating,
    /// regardless of what value would otherwise land there.
    struct ReadOnlyDevice(MemBlockDevice);

    impl BlockDevice for ReadOnlyDevice {
        fn read_sectors(
            &self,
            lba: u64,
            count: u32,
            buf: &mut [u8],
        ) -> Result<(), block::BlockError> {
            self.0.read_sectors(lba, count, buf)
        }

        fn write_sectors(
            &mut self,
            _lba: u64,
            _count: u32,
            _buf: &[u8],
        ) -> Result<(), block::BlockError> {
            Err(block::BlockError::IoError)
        }

        fn sector_count(&self) -> u64 {
            self.0.sector_count()
        }
    }

    #[test]
    fn mount_rejects_self_consistent_zero_segment_size() {
        // WHY (SECURITY, #626): `LfsSuperblock::from_block` validates only
        // magic/version, and the pre-fix `LfsSegmentManager::deserialize`
        // check only compared the on-disk segment bitmap's stored geometry
        // against the superblock's -- both drawn from the same untrusted
        // image, so a self-consistent segment_size == 0 mounted cleanly.
        // `segment_start_block` then collapses every segment to block 0,
        // and the first ordinary write seals a `SegmentHeader` over the
        // superblock. Craft that exact self-consistent corruption and
        // confirm mount() now fails closed, through reads alone.
        let mut dev = block_device_for_lfs();
        format(&mut dev).expect("format");

        // Corrupt the superblock's segment_size.
        let mut sb_buf = [0u8; BLOCK_SIZE];
        block::read_block(&dev, SUPERBLOCK_BLOCK, &mut sb_buf).expect("read superblock");
        let mut sb = LfsSuperblock::from_block(&sb_buf).expect("parse superblock");
        sb.segment_size = 0;
        let corrupted_sb_block = sb.to_block();
        block::write_block(&mut dev, SUPERBLOCK_BLOCK, &corrupted_sb_block)
            .expect("write corrupted superblock");

        // Corrupt the on-disk segment bitmap's stored segment_size to
        // match, so the geometry is self-consistent -- the property the
        // pre-fix mismatch check alone could not catch.
        let mut cache = BlockCache::new();
        let header = lfs_checkpoint::read_checkpoint(&mut dev, &mut cache, CHECKPOINT_SLOT_A)
            .expect("read checkpoint");
        let mut bitmap_block = [0u8; BLOCK_SIZE];
        block::read_block(&dev, header.segment_bitmap_block, &mut bitmap_block)
            .expect("read segment bitmap block");
        bitmap_block[4..8].copy_from_slice(&0u32.to_le_bytes());
        block::write_block(&mut dev, header.segment_bitmap_block, &bitmap_block)
            .expect("write corrupted segment bitmap");

        let result = mount(Box::new(ReadOnlyDevice(dev)));
        assert!(
            matches!(result, Err(LfsError::Corrupt)),
            "a self-consistent on-disk segment_size == 0 must be rejected, not mounted"
        );
    }

    #[test]
    fn create_write_unlink_loop_triggers_compaction_before_nospace() {
        // Done-when (#625): an 8-segment filesystem driven only through
        // ordinary write()/unlink() calls must trigger compaction and
        // reclaim garbage before any NoSpace is returned. Before the fix,
        // `needs_compaction`'s threshold compared raw `free_count()`
        // against a floor of 1 -- but `allocate()` withholds the last
        // free segment as a compaction reserve (#329), so ordinary writes
        // can never drive `free_count()` below 1, and the trigger was
        // unreachable on any filesystem under 20 segments.
        use alloc::format;

        let mut dev = block_device_for_lfs(); // 8 segments (2048 blocks).
        format(&mut dev).expect("format");

        let mut fs = mount(Box::new(dev)).expect("mount");
        let root = fs.root_inode();

        // Each iteration creates and immediately deletes a 48 KiB file
        // (12 direct blocks at 4 KiB each, the maximum reachable without
        // an indirect block), stranding its inode and data blocks as
        // garbage for the next iteration to potentially reclaim. Run far
        // more iterations than the device's raw 2048 blocks could ever
        // absorb without reclaim (roughly 13 blocks of log traffic per
        // iteration) -- sustained success across all of them is only
        // possible if compaction is actually running.
        let payload = [0xABu8; 12 * BLOCK_SIZE];
        for i in 0..300 {
            let name = format!("f{i}");
            let file_id = fs
                .create(root, &name, InodeType::RegularFile)
                .unwrap_or_else(|e| panic!("create at iteration {i} failed: {e:?}"));
            fs.write(file_id, 0, &payload)
                .unwrap_or_else(|e| panic!("write at iteration {i} failed: {e:?}"));
            fs.unlink(root, &name)
                .unwrap_or_else(|e| panic!("unlink at iteration {i} failed: {e:?}"));
        }
    }

    #[test]
    fn create_past_one_block_capacity_fails_without_dropping_entries() {
        use alloc::format;

        let mut dev = block_device_for_lfs();
        format(&mut dev).expect("format");

        let mut fs = mount(Box::new(dev)).expect("mount");
        let root = fs.root_inode();

        // Each "fileNNN" entry serializes to a fixed 16-byte record
        // (8-byte header + 7-byte name, aligned to 4). A 4 KiB block
        // holds exactly 256 such entries; the 257th must not silently
        // vanish (#287).
        let mut created = 0usize;
        loop {
            let name = format!("file{:03}", created);
            match fs.create(root, &name, InodeType::RegularFile) {
                Ok(_) => created += 1,
                Err(VfsError::NoSpace) => break,
                Err(e) => panic!("unexpected error at entry {created}: {e:?}"),
            }
            if created > 300 {
                panic!("directory did not report NoSpace within expected bounds");
            }
        }

        assert_eq!(
            created, 256,
            "exactly 256 fixed-size entries should fit in one 4 KiB block"
        );

        // Every entry that WAS created must still be reachable -- none
        // were silently dropped while create() reported success.
        for i in 0..created {
            let name = format!("file{:03}", i);
            assert!(
                fs.lookup(root, &name).is_ok(),
                "entry {name} must be reachable after fitting in the directory block"
            );
        }

        // parent.size must reflect exactly what was serialized -- the
        // failed 257th create must not have inflated it.
        let stat = fs.stat(root).expect("stat root");
        assert_eq!(
            stat.size,
            256 * 16,
            "parent.size must match only the entries actually written"
        );
    }

    #[test]
    fn create_rejects_name_over_255_bytes() {
        let mut dev = block_device_for_lfs();
        format(&mut dev).expect("format");
        let mut fs = mount(Box::new(dev)).expect("mount");
        let root = fs.root_inode();

        let mut name_bytes = Vec::new();
        for _ in 0..256 {
            name_bytes.push(b'a');
        }
        let long_name = String::from_utf8(name_bytes).expect("valid utf8");

        let result = fs.create(root, &long_name, InodeType::RegularFile);
        assert_eq!(result, Err(VfsError::InvalidPath));
    }

    #[test]
    fn write_dir_block_rejects_name_that_would_overflow_record_len() {
        let mut dev = block_device_for_lfs();
        let mut cache = BlockCache::new();
        let mut seg_mgr = LfsSegmentManager::new(8, 256);
        seg_mgr.mark_used(0);
        let mut writer = LfsWriter::new(&mut seg_mgr).expect("create writer");

        // A name long enough that `(DIR_ENTRY_HEADER_SIZE + name.len() +
        // 3) & !3` overflows u16::MAX (65535); the old `as u16` cast
        // wrapped this to a small value and bypassed the block-full
        // guard entirely (#290). Called directly to exercise the guard
        // independent of create()'s own 255-byte gate.
        let mut name_bytes = Vec::new();
        for _ in 0..65530 {
            name_bytes.push(b'x');
        }
        let huge_name = String::from_utf8(name_bytes).expect("valid utf8");

        let mut entries: Vec<DiskDirEntry> = Vec::new();
        entries.push(DiskDirEntry {
            inode_id: 1,
            name_len: 0, // recomputed inside write_dir_block
            record_len: 0,
            name: huge_name,
        });

        let result =
            Lfs::write_dir_block(&mut dev, &mut cache, &mut writer, &mut seg_mgr, &entries);
        assert_eq!(result, Err(VfsError::InvalidPath));
    }

    #[test]
    fn parse_dir_entries_rejects_name_len_exceeding_record_len() {
        let mut buf = [0u8; BLOCK_SIZE];

        // A single crafted entry: record_len reserves only 4 bytes for
        // the name (12 - DIR_ENTRY_HEADER_SIZE), but name_len claims 20.
        // name_start(8) + name_len(20) = 28, well within BLOCK_SIZE, so
        // the old bare `name_end <= BLOCK_SIZE` check would have let
        // this read 16 bytes past the entry's own record boundary --
        // into whatever bytes follow (the next entry's header/name).
        buf[0..4].copy_from_slice(&1u32.to_le_bytes()); // inode_id
        buf[4..6].copy_from_slice(&20u16.to_le_bytes()); // name_len
        buf[6..8].copy_from_slice(&12u16.to_le_bytes()); // record_len

        let result = Lfs::parse_dir_entries(&buf);
        assert!(
            matches!(result, Err(VfsError::IoError)),
            "name_len exceeding the entry's own record_len must be rejected as corruption, not read past the record boundary"
        );
    }

    #[test]
    fn parse_dir_entries_rejects_record_len_shorter_than_header() {
        let mut buf = [0u8; BLOCK_SIZE];

        // record_len (4) is shorter than DIR_ENTRY_HEADER_SIZE (8) -- the
        // entry cannot even fit its own header, let alone a name.
        buf[0..4].copy_from_slice(&1u32.to_le_bytes()); // inode_id
        buf[4..6].copy_from_slice(&1u16.to_le_bytes()); // name_len
        buf[6..8].copy_from_slice(&4u16.to_le_bytes()); // record_len

        let result = Lfs::parse_dir_entries(&buf);
        assert!(matches!(result, Err(VfsError::IoError)));
    }

    #[test]
    fn disk_inode_round_trips() {
        let inode = DiskInode {
            inode_type: INODE_TYPE_FILE,
            link_count: 3,
            size: 12345,
            direct: [10, 20, 30, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            indirect: 99,
        };

        let mut buf = [0u8; BLOCK_SIZE];
        inode.write_to(&mut buf, 0);
        let restored = DiskInode::read_from(&buf, 0).expect("parse inode");

        assert_eq!(restored.inode_type, INODE_TYPE_FILE);
        assert_eq!(restored.link_count, 3);
        assert_eq!(restored.size, 12345);
        assert_eq!(restored.direct[0], 10);
        assert_eq!(restored.direct[1], 20);
        assert_eq!(restored.direct[2], 30);
        assert_eq!(restored.indirect, 99);
    }

    #[test]
    fn map_write_data_block_err_distinguishes_no_space_from_io_error() {
        assert_eq!(
            Lfs::map_write_data_block_err(LfsError::NoFreeSegments),
            VfsError::NoSpace,
            "disk-full must map to NoSpace, not a generic I/O error"
        );

        assert_eq!(
            Lfs::map_write_data_block_err(LfsError::BlockIo(block::BlockError::IoError)),
            VfsError::IoError,
            "a genuine device I/O fault must map to IoError, not NoSpace"
        );
        assert_eq!(
            Lfs::map_write_data_block_err(LfsError::Corrupt),
            VfsError::IoError
        );
        assert_eq!(
            Lfs::map_write_data_block_err(LfsError::InvalidSuperblock),
            VfsError::IoError
        );
        assert_eq!(
            Lfs::map_write_data_block_err(LfsError::InodeNotFound),
            VfsError::IoError
        );
        assert_eq!(
            Lfs::map_write_data_block_err(LfsError::CheckpointOverflow),
            VfsError::IoError
        );
    }
}
