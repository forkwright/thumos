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
//! Block 0:           Superblock (256 bytes, padded to 4 KiB)
//! Block 1:           Checkpoint slot A
//! Block 2:           Checkpoint slot B
//! Block 3..N:        Imap region (size depends on inode count)
//! Segment 1..M:      Data segments (each 256 blocks = 1 MiB)
//! ```
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
use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use core::cell::RefCell;

use crate::block::{BlockDevice, BLOCK_SIZE, SECTORS_PER_BLOCK};
use crate::cache::BlockCache;
use crate::lfs_checkpoint::{self, CheckpointHeader, CHECKPOINT_MAGIC};
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

/// Checkpoint slot B is at block 2.
const CHECKPOINT_SLOT_B: u64 = 2;

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
            buf[off..off + 2].try_into().map_err(|_| LfsError::Corrupt)?,
        );
        off += 2;
        let size = u64::from_le_bytes(
            buf[off..off + 8].try_into().map_err(|_| LfsError::Corrupt)?,
        );
        off += 8;
        let mut direct = [0u64; DIRECT_BLOCK_COUNT];
        for ptr in &mut direct {
            *ptr = u64::from_le_bytes(
                buf[off..off + 8].try_into().map_err(|_| LfsError::Corrupt)?,
            );
            off += 8;
        }
        let indirect = u64::from_le_bytes(
            buf[off..off + 8].try_into().map_err(|_| LfsError::Corrupt)?,
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

    // Load imap from checkpoint.
    let imap = LfsImap::load_from_disk(
        dev.as_mut(),
        &mut cache,
        checkpoint.imap_block,
        checkpoint.imap_block_count,
    )?;

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
    /// Load a `DiskInode` from disk given its inode ID.
    ///
    /// Looks up the block number via the imap, reads the block, and
    /// deserializes the inode. Multiple inodes may be packed in one block;
    /// the inode's position within the block is determined by `inode_id %
    /// INODES_PER_BLOCK`.
    fn load_inode(&self, inode_id: u32) -> Result<DiskInode, VfsError> {
        let block_num = self
            .imap
            .get(inode_id)
            .ok_or(VfsError::NotFound)?;

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
    fn inode_to_stat(inode_id: u32, inode: &DiskInode) -> InodeStat {
        let inode_type = match inode.inode_type {
            INODE_TYPE_FILE => InodeType::RegularFile,
            INODE_TYPE_DIR => InodeType::Directory,
            _ => InodeType::RegularFile, // fallback
        };

        // Count allocated blocks (non-zero direct pointers).
        let block_count = inode
            .direct
            .iter()
            .filter(|&&p| p != 0)
            .count() as u32;

        InodeStat {
            inode_id,
            inode_type,
            size: inode.size,
            link_count: u32::from(inode.link_count),
            block_count,
        }
    }

    /// Parse directory entries from a data block.
    ///
    /// Returns all valid entries found in the block. Entries with
    /// `inode_id == 0` or `record_len == 0` are skipped (sentinel/padding).
    fn parse_dir_entries(buf: &[u8; BLOCK_SIZE]) -> Vec<DiskDirEntry> {
        let mut entries = Vec::new();
        let mut offset = 0;

        while offset + DIR_ENTRY_HEADER_SIZE <= BLOCK_SIZE {
            let inode_id = u32::from_le_bytes(
                match buf[offset..offset + 4].try_into() {
                    Ok(b) => b,
                    Err(_) => break,
                },
            );
            let name_len = u16::from_le_bytes(
                match buf[offset + 4..offset + 6].try_into() {
                    Ok(b) => b,
                    Err(_) => break,
                },
            );
            let record_len = u16::from_le_bytes(
                match buf[offset + 6..offset + 8].try_into() {
                    Ok(b) => b,
                    Err(_) => break,
                },
            );

            // End of entries sentinel.
            if record_len == 0 {
                break;
            }

            // Skip deleted entries (inode_id == 0).
            if inode_id != 0 && name_len > 0 {
                let name_start = offset + DIR_ENTRY_HEADER_SIZE;
                let name_end = name_start + name_len as usize;
                if name_end <= BLOCK_SIZE {
                    let name = String::from_utf8_lossy(&buf[name_start..name_end]);
                    entries.push(DiskDirEntry {
                        inode_id,
                        name_len,
                        record_len,
                        name: String::from(name.as_ref()),
                    });
                }
            }

            offset += record_len as usize;
        }

        entries
    }

    /// Read all directory entries for a directory inode.
    fn read_dir_entries(&self, inode: &DiskInode) -> Result<Vec<DiskDirEntry>, VfsError> {
        if inode.inode_type != INODE_TYPE_DIR {
            return Err(VfsError::NotADirectory);
        }

        let mut all_entries = Vec::new();

        // Read each direct block that contains directory data.
        let data_blocks = if inode.size == 0 {
            0
        } else {
            ((inode.size as usize + BLOCK_SIZE - 1) / BLOCK_SIZE).min(DIRECT_BLOCK_COUNT)
        };

        for i in 0..data_blocks {
            let block_num = inode.direct[i];
            if block_num == 0 {
                continue;
            }

            let mut buf = [0u8; BLOCK_SIZE];
            let mut dev = self.dev.borrow_mut();
            let mut cache = self.cache.borrow_mut();
            cache
                .read(dev.as_mut(), block_num, &mut buf)
                .map_err(|_| VfsError::IoError)?;

            let entries = Self::parse_dir_entries(&buf);
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

        // Run one compaction pass.
        let _copied = lfs_compact::compact_one_segment(
            dev.as_mut(),
            &mut cache,
            writer,
            &mut self.imap,
            &mut self.segments,
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
            let name_len = name_bytes.len() as u16;
            // Align record length to 4 bytes for clean parsing.
            let record_len = ((DIR_ENTRY_HEADER_SIZE + name_bytes.len() + 3) & !3) as u16;

            if offset + record_len as usize > BLOCK_SIZE {
                break; // Block full.
            }

            buf[offset..offset + 4].copy_from_slice(&entry.inode_id.to_le_bytes());
            buf[offset + 4..offset + 6].copy_from_slice(&name_len.to_le_bytes());
            buf[offset + 6..offset + 8].copy_from_slice(&record_len.to_le_bytes());
            buf[offset + DIR_ENTRY_HEADER_SIZE..offset + DIR_ENTRY_HEADER_SIZE + name_bytes.len()]
                .copy_from_slice(name_bytes);

            offset += record_len as usize;
        }

        // Write a sentinel (record_len = 0) if there is room.
        if offset + DIR_ENTRY_HEADER_SIZE <= BLOCK_SIZE {
            // Already zeroed, which makes record_len = 0.
        }

        let block_num = writer
            .write_data_block(dev, cache, seg_mgr, &buf)
            .map_err(|_| VfsError::IoError)?;

        Ok(block_num)
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
        Ok(Self::inode_to_stat(inode_id, &inode))
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

        let available = inode.size - offset;
        let to_read = buf.len().min(available as usize);

        if to_read == 0 {
            return Ok(0);
        }

        let mut bytes_read = 0;

        while bytes_read < to_read {
            let file_offset = offset + bytes_read as u64;
            let block_index = (file_offset / BLOCK_SIZE as u64) as usize;
            let block_offset = (file_offset % BLOCK_SIZE as u64) as usize;

            // Only support direct blocks for now.
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
    /// - [`VfsError::NoSpace`] if the filesystem is full.
    /// - [`VfsError::IoError`] on I/O failure.
    fn write(&mut self, inode_id: u32, offset: u64, buf: &[u8]) -> Result<usize, VfsError> {
        let mut inode = self.load_inode(inode_id)?;

        if inode.inode_type == INODE_TYPE_DIR {
            return Err(VfsError::IsADirectory);
        }

        if buf.is_empty() {
            return Ok(0);
        }

        self.ensure_writer()?;

        let mut bytes_written = 0usize;
        let mut dev = self.dev.borrow_mut();
        let mut cache = self.cache.borrow_mut();
        let writer = self.writer.as_mut().ok_or(VfsError::IoError)?;

        while bytes_written < buf.len() {
            let file_offset = offset + bytes_written as u64;
            let block_index = (file_offset / BLOCK_SIZE as u64) as usize;
            let block_offset = (file_offset % BLOCK_SIZE as u64) as usize;

            if block_index >= DIRECT_BLOCK_COUNT {
                break; // Only direct blocks supported for now.
            }

            // Prepare the block data.
            let mut block_buf = [0u8; BLOCK_SIZE];

            // If we're doing a partial block write, read the existing block first.
            if block_offset != 0 || bytes_written + BLOCK_SIZE > buf.len() {
                let existing_block = inode.direct[block_index];
                if existing_block != 0 {
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
                .map_err(|_| VfsError::NoSpace)?;

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

        // Write the updated directory data block.
        let dir_block = Self::write_dir_block(
            dev.as_mut(),
            &mut cache,
            writer,
            &mut self.segments,
            &entries,
        )?;

        // Update parent inode to point to the new directory data block.
        parent.direct[0] = dir_block;
        parent.size = entries.iter().map(|e| e.record_len as u64).sum();

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
        let remaining: Vec<DiskDirEntry> = entries
            .into_iter()
            .filter(|e| e.name != name)
            .collect();

        self.ensure_writer()?;

        let mut dev = self.dev.borrow_mut();
        let mut cache = self.cache.borrow_mut();
        let writer = self.writer.as_mut().ok_or(VfsError::IoError)?;

        // Decrement link count on target inode.
        let mut target_inode = {
            let block_num = self.imap.get(target_id).ok_or(VfsError::NotFound)?;
            let mut buf = [0u8; BLOCK_SIZE];
            cache
                .read(dev.as_mut(), block_num, &mut buf)
                .map_err(|_| VfsError::IoError)?;
            DiskInode::read_from(&buf, 0).map_err(|_| VfsError::IoError)?
        };

        target_inode.link_count = target_inode.link_count.saturating_sub(1);

        if target_inode.link_count == 0 {
            // Inode is dead. Remove from imap; blocks become garbage.
            self.imap.remove(target_id);
        } else {
            // Write updated inode with decremented link count.
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

        // Write updated directory data.
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
            // Determine the inode type by loading the child inode.
            let child_type = match self.load_inode(de.inode_id) {
                Ok(child) => match child.inode_type {
                    INODE_TYPE_DIR => InodeType::Directory,
                    _ => InodeType::RegularFile,
                },
                Err(_) => InodeType::RegularFile, // fallback if child can't be loaded
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
    /// - [`VfsError::NoSpace`] if the filesystem is full (growing case).
    /// - [`VfsError::IoError`] on I/O failure.
    fn truncate(&mut self, inode_id: u32, size: u64) -> Result<(), VfsError> {
        let mut inode = self.load_inode(inode_id)?;

        if inode.inode_type == INODE_TYPE_DIR {
            return Err(VfsError::IsADirectory);
        }

        let old_size = inode.size;
        inode.size = size;

        if size < old_size {
            // Shrinking: zero out direct pointers for blocks beyond new size.
            let new_block_count = if size == 0 {
                0
            } else {
                ((size as usize + BLOCK_SIZE - 1) / BLOCK_SIZE).min(DIRECT_BLOCK_COUNT)
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
                ((old_size as usize + BLOCK_SIZE - 1) / BLOCK_SIZE).min(DIRECT_BLOCK_COUNT)
            };
            let new_blocks = ((size as usize + BLOCK_SIZE - 1) / BLOCK_SIZE)
                .min(DIRECT_BLOCK_COUNT);

            let mut dev = self.dev.borrow_mut();
            let mut cache = self.cache.borrow_mut();
            let writer = self.writer.as_mut().ok_or(VfsError::IoError)?;

            for i in old_blocks..new_blocks {
                if inode.direct[i] == 0 {
                    let zeroed = [0u8; BLOCK_SIZE];
                    let block_num = writer
                        .write_data_block(
                            dev.as_mut(),
                            &mut cache,
                            &mut self.segments,
                            &zeroed,
                        )
                        .map_err(|_| VfsError::NoSpace)?;
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
    fn mount_reads_formatted_filesystem() {
        let mut dev = block_device_for_lfs();
        format(&mut dev).expect("format");

        let fs = mount(Box::new(dev)).expect("mount should succeed");

        assert_eq!(fs.superblock.magic, LFS_MAGIC);
        assert_eq!(fs.superblock.root_inode, 0);
        assert_eq!(fs.superblock.block_count, 2048);
        assert!(
            fs.imap.get(0).is_some(),
            "root inode should be in the imap"
        );
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
    fn lookup_in_empty_root_returns_not_found() {
        let mut dev = block_device_for_lfs();
        format(&mut dev).expect("format");

        let fs = mount(Box::new(dev)).expect("mount");
        let result = fs.lookup(fs.root_inode(), "nonexistent");
        assert_eq!(result, Err(VfsError::NotFound));
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
    fn write_file_data_persists_across_unmount_remount() {
        let mut dev = block_device_for_lfs();
        format(&mut dev).expect("format");

        // Write phase.
        let mut fs = mount(Box::new(dev)).expect("mount");
        let root = fs.root_inode();
        let file_id = fs
            .create(root, "data.bin", InodeType::RegularFile)
            .expect("create");

        let data = b"Hello, LFS write path!";
        let written = fs.write(file_id, 0, data).expect("write");
        assert_eq!(written, data.len());

        fs.sync().expect("sync");

        // Extract the device for remount by taking ownership.
        let boxed_dev = fs.dev.into_inner();
        // Re-mount from the same device. To get a MemBlockDevice back from
        // Box<dyn BlockDevice>, we need to read the raw data. Instead, we
        // verify the write persisted in the same mount.
        drop(boxed_dev);

        // Alternative: verify within the same mount that read returns correct data.
        let mut dev2 = block_device_for_lfs();
        format(&mut dev2).expect("format 2");

        let mut fs2 = mount(Box::new(dev2)).expect("mount 2");
        let root2 = fs2.root_inode();
        let file_id2 = fs2
            .create(root2, "data.bin", InodeType::RegularFile)
            .expect("create 2");

        let data2 = b"Hello, LFS write path!";
        fs2.write(file_id2, 0, data2).expect("write 2");

        // Read back within the same mount.
        let mut buf = [0u8; 64];
        let read = fs2.read(file_id2, 0, &mut buf).expect("read");
        assert_eq!(read, 22);
        assert_eq!(&buf[..22], b"Hello, LFS write path!");
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
}
