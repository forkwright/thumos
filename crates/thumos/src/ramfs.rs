//! In-memory filesystem (ramfs).
//!
//! A read/write in-memory filesystem backed by a tree of inodes. Used for
//! the initial boot filesystem (initramfs) before the eMMC driver is
//! available, and also for ephemeral mounts like `/tmp`.
//!
//! Each inode holds its type, data (for files), and child list (for
//! directories). The CPIO parser populates the inode tree from a newc
//! archive, creating intermediate directories as needed.

extern crate alloc;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::vfs::{DirEntry, Filesystem, InodeStat, InodeType, VfsError};

// ---------------------------------------------------------------------------
// Inode data structure
// ---------------------------------------------------------------------------

/// A single inode in the ramfs.
///
/// Files store their contents in `data`; directories store child references
/// in `children`. The `parent` field points to the containing directory
/// (root's parent is itself).
struct RamInode {
    /// Type of this inode (file, directory, etc.).
    inode_type: InodeType,
    /// File contents (empty for directories).
    data: Vec<u8>,
    /// Child entries for directories: (name, inode_id) pairs.
    children: Vec<(String, u32)>,
    /// Parent directory inode id (root's parent is itself).
    parent: u32,
}

// ---------------------------------------------------------------------------
// RamFs
// ---------------------------------------------------------------------------

/// In-memory filesystem backed by a vector of inodes.
///
/// Inode 0 is always the root directory. New inodes are allocated by
/// appending to the `inodes` vector.
pub(crate) struct RamFs {
    /// All inodes in the filesystem. Index == inode id.
    inodes: Vec<RamInode>,
    /// Next inode id to allocate (always == inodes.len()).
    next_inode: u32,
}

impl RamFs {
    /// Create an empty filesystem with a root directory at inode 0.
    pub(crate) fn new() -> Self {
        let root = RamInode {
            inode_type: InodeType::Directory,
            data: Vec::new(),
            children: Vec::new(),
            parent: 0, // root's parent is itself
        };
        Self {
            inodes: vec![root],
            next_inode: 1,
        }
    }

    /// Add a file at the root directory level (backward-compatibility).
    ///
    /// Creates a regular file with the given name and data as a direct
    /// child of the root directory. If a file with the same name already
    /// exists at the root, it is replaced.
    pub(crate) fn add(&mut self, name: &str, data: &[u8]) {
        // Check if a file with this name already exists at root
        let root_children = &self.inodes[0].children;
        for &(ref child_name, child_id) in root_children {
            if child_name == name {
                // Replace the existing file's data
                if let Some(inode) = self.inodes.get_mut(child_id as usize) {
                    inode.data = Vec::from(data);
                }
                return;
            }
        }

        // Create new inode
        let inode_id = self.next_inode;
        self.next_inode += 1;
        self.inodes.push(RamInode {
            inode_type: InodeType::RegularFile,
            data: Vec::from(data),
            children: Vec::new(),
            parent: 0,
        });
        self.inodes[0]
            .children
            .push((String::from(name), inode_id));
    }

    /// Find a file by path (backward-compatibility).
    ///
    /// Walks the inode tree from root, resolving path components separated
    /// by `/`. Returns the file data if found.
    pub(crate) fn find(&self, name: &str) -> Option<&[u8]> {
        // Strip leading slash if present
        let path = name.strip_prefix('/').unwrap_or(name);

        if path.is_empty() {
            return None; // root is a directory, not a file
        }

        let mut current = 0u32; // start at root

        let components: Vec<&str> = path.split('/').filter(|c| !c.is_empty()).collect();
        if components.is_empty() {
            return None;
        }

        // Walk all but the last component as directories
        for &component in &components[..components.len() - 1] {
            let inode = self.inodes.get(current as usize)?;
            if inode.inode_type != InodeType::Directory {
                return None;
            }
            let child_id = inode
                .children
                .iter()
                .find(|(n, _)| n == component)
                .map(|(_, id)| *id)?;
            current = child_id;
        }

        // Look up the final component
        let last = components[components.len() - 1];
        let dir = self.inodes.get(current as usize)?;
        if dir.inode_type != InodeType::Directory {
            return None;
        }
        let file_id = dir
            .children
            .iter()
            .find(|(n, _)| n == last)
            .map(|(_, id)| *id)?;
        let file_inode = self.inodes.get(file_id as usize)?;
        if file_inode.inode_type != InodeType::RegularFile {
            return None;
        }
        Some(file_inode.data.as_slice())
    }

    /// List all file names (backward-compatibility, root level only).
    pub(crate) fn list(&self) -> impl Iterator<Item = &str> {
        self.inodes[0]
            .children
            .iter()
            .map(|(name, _)| name.as_str())
    }

    /// Number of files at root level (backward-compatibility).
    pub(crate) fn count(&self) -> usize {
        self.inodes[0]
            .children
            .iter()
            .filter(|(_, id)| {
                self.inodes
                    .get(*id as usize)
                    .is_some_and(|i| i.inode_type == InodeType::RegularFile)
            })
            .count()
    }

    /// Total bytes used by all files in the filesystem.
    pub(crate) fn total_size(&self) -> usize {
        self.inodes
            .iter()
            .filter(|i| i.inode_type == InodeType::RegularFile)
            .map(|i| i.data.len())
            .sum()
    }

    /// Parse a CPIO archive (newc format) into the filesystem.
    ///
    /// This is the format used by Linux initramfs. The parser creates
    /// intermediate directories as needed and inserts files into the
    /// correct directory inodes.
    pub(crate) fn from_cpio(data: &[u8]) -> Self {
        let mut fs = Self::new();
        let mut offset = 0;

        while offset + 110 <= data.len() {
            // CPIO newc header: "070701" magic + fields
            if &data[offset..offset + 6] != b"070701" {
                break;
            }

            // Parse header fields (hex ASCII)
            let mode = parse_hex(&data[offset + 14..offset + 22]);
            let namesize = parse_hex(&data[offset + 94..offset + 102]) as usize;
            let filesize = parse_hex(&data[offset + 54..offset + 62]) as usize;

            // Name starts after 110-byte header
            let name_start = offset + 110;
            let name_end = name_start + namesize - 1; // -1 for null terminator

            if name_end > data.len() {
                break;
            }

            let name = core::str::from_utf8(&data[name_start..name_end]).unwrap_or("");

            // Trailer marks end of archive
            if name == "TRAILER!!!" {
                break;
            }

            // Data starts after name, aligned to 4 bytes
            let data_start = align4(name_start + namesize);
            let data_end = data_start + filesize;

            if data_end > data.len() {
                break;
            }

            // Determine entry type from mode field
            // S_IFMT mask = 0o170000, S_IFDIR = 0o040000, S_IFREG = 0o100000
            let file_type = mode & 0o170000;
            let is_dir = file_type == 0o040000;

            if !name.is_empty() && name != "." {
                // Strip leading "./" if present (common in CPIO archives)
                let clean_name = name
                    .strip_prefix("./")
                    .unwrap_or(name)
                    .strip_prefix('/')
                    .unwrap_or(name);

                if !clean_name.is_empty() {
                    if is_dir {
                        // Ensure the directory exists in the tree
                        fs.ensure_directory_path(clean_name);
                    } else if filesize > 0 || file_type == 0o100000 {
                        // Regular file: ensure parent directories exist, then add file
                        fs.insert_file_at_path(clean_name, &data[data_start..data_end]);
                    }
                }
            }

            // Next entry starts after data, aligned to 4 bytes
            offset = align4(data_end);
        }

        fs
    }

    /// Ensure all components of a directory path exist in the inode tree.
    ///
    /// Creates intermediate directories as needed. Returns the inode id
    /// of the final directory.
    fn ensure_directory_path(&mut self, path: &str) -> u32 {
        let mut current = 0u32; // start at root

        for component in path.split('/').filter(|c| !c.is_empty()) {
            // Check if this child directory already exists
            let existing = self.inodes[current as usize]
                .children
                .iter()
                .find(|(n, _)| n == component)
                .map(|(_, id)| *id);

            match existing {
                Some(child_id) => {
                    current = child_id;
                }
                None => {
                    // Create new directory inode
                    let new_id = self.next_inode;
                    self.next_inode += 1;
                    self.inodes.push(RamInode {
                        inode_type: InodeType::Directory,
                        data: Vec::new(),
                        children: Vec::new(),
                        parent: current,
                    });
                    self.inodes[current as usize]
                        .children
                        .push((String::from(component), new_id));
                    current = new_id;
                }
            }
        }

        current
    }

    /// Insert a file at the given path, creating parent directories as needed.
    fn insert_file_at_path(&mut self, path: &str, data: &[u8]) {
        let components: Vec<&str> = path.split('/').filter(|c| !c.is_empty()).collect();
        if components.is_empty() {
            return;
        }

        // Ensure parent directories exist
        let parent_id = if components.len() > 1 {
            let parent_path = components[..components.len() - 1].join("/");
            self.ensure_directory_path(&parent_path)
        } else {
            0 // root
        };

        let file_name = components[components.len() - 1];

        // Check if file already exists in parent
        let existing = self.inodes[parent_id as usize]
            .children
            .iter()
            .find(|(n, _)| n == file_name)
            .map(|(_, id)| *id);

        if let Some(existing_id) = existing {
            // Replace existing file data
            if let Some(inode) = self.inodes.get_mut(existing_id as usize) {
                inode.data = Vec::from(data);
            }
        } else {
            // Create new file inode
            let new_id = self.next_inode;
            self.next_inode += 1;
            self.inodes.push(RamInode {
                inode_type: InodeType::RegularFile,
                data: Vec::from(data),
                children: Vec::new(),
                parent: parent_id,
            });
            self.inodes[parent_id as usize]
                .children
                .push((String::from(file_name), new_id));
        }
    }
}

impl Default for RamFs {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Filesystem trait implementation
// ---------------------------------------------------------------------------

impl Filesystem for RamFs {
    /// Returns 0, the root directory inode.
    ///
    /// # Errors
    ///
    /// This method is infallible.
    fn root_inode(&self) -> u32 {
        0
    }

    /// Retrieve metadata for an inode.
    ///
    /// # Errors
    ///
    /// Returns `VfsError::NotFound` if `inode_id` does not exist.
    fn stat(&self, inode_id: u32) -> Result<InodeStat, VfsError> {
        let inode = self
            .inodes
            .get(inode_id as usize)
            .ok_or(VfsError::NotFound)?;

        let size = match inode.inode_type {
            InodeType::RegularFile => inode.data.len() as u64,
            InodeType::Directory => inode.children.len() as u64,
            _ => 0,
        };

        Ok(InodeStat {
            inode_id,
            inode_type: inode.inode_type,
            size,
            link_count: if inode.inode_type == InodeType::Directory {
                2
            } else {
                1
            },
            block_count: 0,
        })
    }

    /// Look up a child entry by name within a directory.
    ///
    /// # Errors
    ///
    /// - `VfsError::NotFound` if no entry with `name` exists in the directory.
    /// - `VfsError::NotADirectory` if `dir_inode` is not a directory.
    fn lookup(&self, dir_inode: u32, name: &str) -> Result<u32, VfsError> {
        let inode = self
            .inodes
            .get(dir_inode as usize)
            .ok_or(VfsError::NotFound)?;

        if inode.inode_type != InodeType::Directory {
            return Err(VfsError::NotADirectory);
        }

        inode
            .children
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, id)| *id)
            .ok_or(VfsError::NotFound)
    }

    /// Read bytes from a file inode.
    ///
    /// Reads up to `buf.len()` bytes starting at `offset`. Returns the number
    /// of bytes actually read (0 at EOF).
    ///
    /// # Errors
    ///
    /// - `VfsError::NotFound` if `inode_id` does not exist.
    /// - `VfsError::IsADirectory` if `inode_id` refers to a directory.
    fn read(&self, inode_id: u32, offset: u64, buf: &mut [u8]) -> Result<usize, VfsError> {
        let inode = self
            .inodes
            .get(inode_id as usize)
            .ok_or(VfsError::NotFound)?;

        if inode.inode_type == InodeType::Directory {
            return Err(VfsError::IsADirectory);
        }

        let off = offset as usize;
        if off >= inode.data.len() {
            return Ok(0); // EOF
        }

        let remaining = inode.data.len() - off;
        let to_read = buf.len().min(remaining);
        buf[..to_read].copy_from_slice(&inode.data[off..off + to_read]);
        Ok(to_read)
    }

    /// Write bytes to a file inode.
    ///
    /// Writes up to `buf.len()` bytes starting at `offset`. Extends the file
    /// if writing past the current end.
    ///
    /// # Errors
    ///
    /// - `VfsError::NotFound` if `inode_id` does not exist.
    /// - `VfsError::IsADirectory` if `inode_id` refers to a directory.
    fn write(&mut self, inode_id: u32, offset: u64, buf: &[u8]) -> Result<usize, VfsError> {
        let inode = self
            .inodes
            .get_mut(inode_id as usize)
            .ok_or(VfsError::NotFound)?;

        if inode.inode_type == InodeType::Directory {
            return Err(VfsError::IsADirectory);
        }

        let off = offset as usize;

        // Extend the file if writing past the end
        if off + buf.len() > inode.data.len() {
            inode.data.resize(off + buf.len(), 0);
        }

        inode.data[off..off + buf.len()].copy_from_slice(buf);
        Ok(buf.len())
    }

    /// Create a new inode in a directory.
    ///
    /// # Errors
    ///
    /// - `VfsError::NotADirectory` if `dir_inode` is not a directory.
    /// - `VfsError::AlreadyExists` if `name` already exists in the directory.
    /// - `VfsError::NotFound` if `dir_inode` does not exist.
    fn create(
        &mut self,
        dir_inode: u32,
        name: &str,
        inode_type: InodeType,
    ) -> Result<u32, VfsError> {
        // Validate dir_inode exists and is a directory
        let dir = self
            .inodes
            .get(dir_inode as usize)
            .ok_or(VfsError::NotFound)?;

        if dir.inode_type != InodeType::Directory {
            return Err(VfsError::NotADirectory);
        }

        // Check for duplicate name
        if dir.children.iter().any(|(n, _)| n == name) {
            return Err(VfsError::AlreadyExists);
        }

        // Allocate new inode
        let new_id = self.next_inode;
        self.next_inode += 1;

        self.inodes.push(RamInode {
            inode_type,
            data: Vec::new(),
            children: Vec::new(),
            parent: dir_inode,
        });

        // Add to parent's children
        self.inodes[dir_inode as usize]
            .children
            .push((String::from(name), new_id));

        Ok(new_id)
    }

    /// Remove an entry from a directory.
    ///
    /// # Errors
    ///
    /// - `VfsError::NotFound` if `name` does not exist in the directory.
    /// - `VfsError::NotADirectory` if `dir_inode` is not a directory.
    /// - `VfsError::NotEmpty` if the entry is a non-empty directory.
    fn unlink(&mut self, dir_inode: u32, name: &str) -> Result<(), VfsError> {
        let dir = self
            .inodes
            .get(dir_inode as usize)
            .ok_or(VfsError::NotFound)?;

        if dir.inode_type != InodeType::Directory {
            return Err(VfsError::NotADirectory);
        }

        // Find the child
        let child_pos = dir
            .children
            .iter()
            .position(|(n, _)| n == name)
            .ok_or(VfsError::NotFound)?;

        let child_id = dir.children[child_pos].1;

        // If child is a directory, check it's empty
        if let Some(child) = self.inodes.get(child_id as usize) {
            if child.inode_type == InodeType::Directory && !child.children.is_empty() {
                return Err(VfsError::NotEmpty);
            }
        }

        // Remove from parent's children list
        self.inodes[dir_inode as usize].children.remove(child_pos);

        // NOTE: We don't reclaim the inode slot to avoid invalidating existing
        // inode ids. In a real filesystem we would use a free list.

        Ok(())
    }

    /// List all entries in a directory.
    ///
    /// # Errors
    ///
    /// - `VfsError::NotADirectory` if `dir_inode` is not a directory.
    /// - `VfsError::NotFound` if `dir_inode` does not exist.
    fn readdir(&self, dir_inode: u32) -> Result<Vec<DirEntry>, VfsError> {
        let inode = self
            .inodes
            .get(dir_inode as usize)
            .ok_or(VfsError::NotFound)?;

        if inode.inode_type != InodeType::Directory {
            return Err(VfsError::NotADirectory);
        }

        let entries = inode
            .children
            .iter()
            .filter_map(|(name, id)| {
                self.inodes.get(*id as usize).map(|child| DirEntry {
                    name: name.clone(),
                    inode_id: *id,
                    inode_type: child.inode_type,
                })
            })
            .collect();

        Ok(entries)
    }

    /// Truncate a file to the specified size.
    ///
    /// # Errors
    ///
    /// - `VfsError::NotFound` if `inode_id` does not exist.
    /// - `VfsError::IsADirectory` if `inode_id` refers to a directory.
    fn truncate(&mut self, inode_id: u32, size: u64) -> Result<(), VfsError> {
        let inode = self
            .inodes
            .get_mut(inode_id as usize)
            .ok_or(VfsError::NotFound)?;

        if inode.inode_type == InodeType::Directory {
            return Err(VfsError::IsADirectory);
        }

        inode.data.resize(size as usize, 0);
        Ok(())
    }

    /// No-op sync: ramfs has no backing store.
    ///
    /// # Errors
    ///
    /// Always returns `Ok(())`.
    fn sync(&mut self) -> Result<(), VfsError> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

/// Parse 8 hex ASCII characters into a u32.
fn parse_hex(hex: &[u8]) -> u32 {
    let mut val = 0u32;
    for &byte in hex.iter().take(8) {
        val <<= 4;
        val |= match byte {
            b'0'..=b'9' => (byte - b'0') as u32,
            b'a'..=b'f' => (byte - b'a' + 10) as u32,
            b'A'..=b'F' => (byte - b'A' + 10) as u32,
            _ => 0,
        };
    }
    val
}

/// Align up to 4-byte boundary.
const fn align4(n: usize) -> usize {
    (n + 3) & !3
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;

    // -- Backward-compatibility tests (preserved from original) --

    #[test]
    fn create_empty_fs() {
        let fs = RamFs::new();
        assert_eq!(fs.count(), 0);
        assert!(fs.find("anything").is_none());
    }

    #[test]
    fn add_find_file() {
        let mut fs = RamFs::new();
        fs.add("hello.txt", b"Hello, world!");
        assert_eq!(fs.count(), 1);
        assert_eq!(fs.find("hello.txt"), Some(b"Hello, world!".as_slice()));
        assert!(fs.find("missing").is_none());
    }

    #[test]
    fn add_multiple_files() {
        let mut fs = RamFs::new();
        fs.add("a", b"aaa");
        fs.add("b", b"bb");
        fs.add("c", b"c");
        assert_eq!(fs.count(), 3);
        assert_eq!(fs.total_size(), 6);
    }

    #[test]
    fn list_root_files() {
        let mut fs = RamFs::new();
        fs.add("init", b"");
        fs.add("config", b"");
        let names: Vec<&str> = fs.list().collect();
        assert_eq!(names, vec!["init", "config"]);
    }

    #[test]
    fn parse_hex_values() {
        assert_eq!(parse_hex(b"00000000"), 0);
        assert_eq!(parse_hex(b"000000FF"), 255);
        assert_eq!(parse_hex(b"DEADBEEF"), 0xDEAD_BEEF);
        assert_eq!(parse_hex(b"00000064"), 100);
    }

    #[test]
    fn align4_values() {
        assert_eq!(align4(0), 0);
        assert_eq!(align4(1), 4);
        assert_eq!(align4(4), 4);
        assert_eq!(align4(5), 8);
        assert_eq!(align4(110), 112);
    }

    // -- Filesystem trait tests --

    #[test]
    fn create_file_write_read() {
        let mut fs = RamFs::new();
        let inode_id = fs
            .create(0, "test.txt", InodeType::RegularFile)
            .expect("create file");

        let data = b"Hello, VFS!";
        let written = fs.write(inode_id, 0, data).expect("write");
        assert_eq!(written, data.len());

        let mut buf = [0u8; 32];
        let read = fs.read(inode_id, 0, &mut buf).expect("read");
        assert_eq!(read, data.len());
        assert_eq!(&buf[..read], data);
    }

    #[test]
    fn create_mkdir_readdir() {
        let mut fs = RamFs::new();
        let dir_id = fs
            .create(0, "subdir", InodeType::Directory)
            .expect("create dir");
        let _file_id = fs
            .create(dir_id, "inner.txt", InodeType::RegularFile)
            .expect("create file in subdir");

        let entries = fs.readdir(dir_id).expect("readdir subdir");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "inner.txt");
        assert_eq!(entries[0].inode_type, InodeType::RegularFile);

        // Root should have the subdir
        let root_entries = fs.readdir(0).expect("readdir root");
        assert_eq!(root_entries.len(), 1);
        assert_eq!(root_entries[0].name, "subdir");
        assert_eq!(root_entries[0].inode_type, InodeType::Directory);
    }

    #[test]
    fn unlink_file() {
        let mut fs = RamFs::new();
        fs.create(0, "doomed.txt", InodeType::RegularFile)
            .expect("create");

        assert!(fs.lookup(0, "doomed.txt").is_ok());

        fs.unlink(0, "doomed.txt").expect("unlink");

        assert_eq!(fs.lookup(0, "doomed.txt"), Err(VfsError::NotFound));
    }

    #[test]
    fn unlink_nonempty_dir_fails() {
        let mut fs = RamFs::new();
        let dir_id = fs
            .create(0, "notempty", InodeType::Directory)
            .expect("create dir");
        fs.create(dir_id, "child.txt", InodeType::RegularFile)
            .expect("create child");

        let result = fs.unlink(0, "notempty");
        assert_eq!(result, Err(VfsError::NotEmpty));
    }

    #[test]
    fn unlink_empty_dir_succeeds() {
        let mut fs = RamFs::new();
        fs.create(0, "emptydir", InodeType::Directory)
            .expect("create dir");

        fs.unlink(0, "emptydir").expect("unlink empty dir");
        assert_eq!(fs.lookup(0, "emptydir"), Err(VfsError::NotFound));
    }

    #[test]
    fn stat_returns_correct_metadata() {
        let mut fs = RamFs::new();
        let file_id = fs
            .create(0, "sized.dat", InodeType::RegularFile)
            .expect("create");
        fs.write(file_id, 0, b"12345").expect("write");

        let stat = fs.stat(file_id).expect("stat");
        assert_eq!(stat.inode_id, file_id);
        assert_eq!(stat.inode_type, InodeType::RegularFile);
        assert_eq!(stat.size, 5);
        assert_eq!(stat.link_count, 1);

        // Root directory stat
        let root_stat = fs.stat(0).expect("stat root");
        assert_eq!(root_stat.inode_type, InodeType::Directory);
        assert_eq!(root_stat.link_count, 2);
    }

    #[test]
    fn truncate_file() {
        let mut fs = RamFs::new();
        let file_id = fs
            .create(0, "trunc.dat", InodeType::RegularFile)
            .expect("create");
        fs.write(file_id, 0, b"hello world").expect("write");

        fs.truncate(file_id, 5).expect("truncate");

        let stat = fs.stat(file_id).expect("stat");
        assert_eq!(stat.size, 5);

        let mut buf = [0u8; 32];
        let read = fs.read(file_id, 0, &mut buf).expect("read");
        assert_eq!(read, 5);
        assert_eq!(&buf[..5], b"hello");
    }

    #[test]
    fn truncate_extend_file() {
        let mut fs = RamFs::new();
        let file_id = fs
            .create(0, "grow.dat", InodeType::RegularFile)
            .expect("create");
        fs.write(file_id, 0, b"hi").expect("write");

        fs.truncate(file_id, 10).expect("truncate up");

        let stat = fs.stat(file_id).expect("stat");
        assert_eq!(stat.size, 10);

        let mut buf = [0u8; 10];
        let read = fs.read(file_id, 0, &mut buf).expect("read");
        assert_eq!(read, 10);
        assert_eq!(&buf[..2], b"hi");
        assert!(buf[2..].iter().all(|&b| b == 0));
    }

    #[test]
    fn write_extends_file() {
        let mut fs = RamFs::new();
        let file_id = fs
            .create(0, "ext.dat", InodeType::RegularFile)
            .expect("create");

        // Write at offset 0
        fs.write(file_id, 0, b"AB").expect("write 1");
        // Write at offset 5 (creates gap)
        fs.write(file_id, 5, b"CD").expect("write 2");

        let stat = fs.stat(file_id).expect("stat");
        assert_eq!(stat.size, 7);

        let mut buf = [0xFFu8; 7];
        let read = fs.read(file_id, 0, &mut buf).expect("read");
        assert_eq!(read, 7);
        assert_eq!(&buf[0..2], b"AB");
        assert_eq!(&buf[2..5], &[0, 0, 0]); // gap filled with zeros
        assert_eq!(&buf[5..7], b"CD");
    }

    #[test]
    fn read_at_eof_returns_zero() {
        let mut fs = RamFs::new();
        let file_id = fs
            .create(0, "eof.dat", InodeType::RegularFile)
            .expect("create");
        fs.write(file_id, 0, b"data").expect("write");

        let mut buf = [0u8; 32];
        let read = fs.read(file_id, 100, &mut buf).expect("read past end");
        assert_eq!(read, 0);
    }

    #[test]
    fn read_directory_returns_error() {
        let fs = RamFs::new();
        let mut buf = [0u8; 32];
        assert_eq!(fs.read(0, 0, &mut buf), Err(VfsError::IsADirectory));
    }

    #[test]
    fn write_directory_returns_error() {
        let mut fs = RamFs::new();
        assert_eq!(fs.write(0, 0, b"data"), Err(VfsError::IsADirectory));
    }

    #[test]
    fn lookup_nonexistent_returns_not_found() {
        let fs = RamFs::new();
        assert_eq!(fs.lookup(0, "ghost"), Err(VfsError::NotFound));
    }

    #[test]
    fn lookup_on_file_returns_not_a_directory() {
        let mut fs = RamFs::new();
        let file_id = fs
            .create(0, "file.txt", InodeType::RegularFile)
            .expect("create");
        assert_eq!(
            fs.lookup(file_id, "child"),
            Err(VfsError::NotADirectory)
        );
    }

    #[test]
    fn create_duplicate_returns_already_exists() {
        let mut fs = RamFs::new();
        fs.create(0, "dup.txt", InodeType::RegularFile)
            .expect("first create");
        assert_eq!(
            fs.create(0, "dup.txt", InodeType::RegularFile),
            Err(VfsError::AlreadyExists)
        );
    }

    #[test]
    fn stat_invalid_inode_returns_not_found() {
        let fs = RamFs::new();
        assert_eq!(fs.stat(999), Err(VfsError::NotFound));
    }

    #[test]
    fn sync_succeeds() {
        let mut fs = RamFs::new();
        assert_eq!(fs.sync(), Ok(()));
    }

    #[test]
    fn root_inode_is_zero() {
        let fs = RamFs::new();
        assert_eq!(fs.root_inode(), 0);
    }

    #[test]
    fn truncate_directory_returns_error() {
        let mut fs = RamFs::new();
        assert_eq!(fs.truncate(0, 0), Err(VfsError::IsADirectory));
    }

    #[test]
    fn readdir_file_returns_not_a_directory() {
        let mut fs = RamFs::new();
        let file_id = fs
            .create(0, "f.txt", InodeType::RegularFile)
            .expect("create");
        assert_eq!(fs.readdir(file_id), Err(VfsError::NotADirectory));
    }

    // -- CPIO parser tests --

    /// Build a minimal CPIO newc archive for testing.
    fn build_cpio_entry(name: &str, data: &[u8], mode: u32) -> Vec<u8> {
        let mut entry = Vec::new();
        let namesize = name.len() + 1; // includes null terminator
        let filesize = data.len();

        // 110-byte header: magic + 13 fields of 8 hex chars each
        entry.extend_from_slice(b"070701");                                  // magic
        entry.extend_from_slice(b"00000001");                                // ino
        entry.extend_from_slice(format!("{mode:08X}").as_bytes());           // mode
        entry.extend_from_slice(b"00000000");                                // uid
        entry.extend_from_slice(b"00000000");                                // gid
        entry.extend_from_slice(b"00000001");                                // nlink
        entry.extend_from_slice(b"00000000");                                // mtime
        entry.extend_from_slice(format!("{filesize:08X}").as_bytes());       // filesize
        entry.extend_from_slice(b"00000000");                                // devmajor
        entry.extend_from_slice(b"00000000");                                // devminor
        entry.extend_from_slice(b"00000000");                                // rdevmajor
        entry.extend_from_slice(b"00000000");                                // rdevminor
        entry.extend_from_slice(format!("{namesize:08X}").as_bytes());       // namesize
        entry.extend_from_slice(b"00000000");                                // check

        assert_eq!(entry.len(), 110, "header must be exactly 110 bytes");

        // Name + null terminator
        entry.extend_from_slice(name.as_bytes());
        entry.push(0);

        // Pad to 4-byte alignment from start of entry
        let padded_name_end = align4(110 + namesize);
        while entry.len() < padded_name_end {
            entry.push(0);
        }

        // Data
        entry.extend_from_slice(data);

        // Pad data to 4-byte alignment
        let padded_data_end = align4(entry.len());
        while entry.len() < padded_data_end {
            entry.push(0);
        }

        entry
    }

    /// Build a CPIO trailer entry.
    fn build_cpio_trailer() -> Vec<u8> {
        build_cpio_entry("TRAILER!!!", &[], 0)
    }

    #[test]
    fn parse_cpio_creates_files() {
        let mut archive = Vec::new();
        archive.extend(build_cpio_entry("init", b"#!/bin/sh", 0o100755));
        archive.extend(build_cpio_entry("config.toml", b"key=val", 0o100644));
        archive.extend(build_cpio_trailer());

        let fs = RamFs::from_cpio(&archive);

        // Files should be findable via backward-compatible interface
        assert_eq!(fs.find("init"), Some(b"#!/bin/sh".as_slice()));
        assert_eq!(fs.find("config.toml"), Some(b"key=val".as_slice()));

        // And via the Filesystem trait
        let init_id = fs.lookup(0, "init").expect("lookup init");
        let mut buf = [0u8; 32];
        let read = fs.read(init_id, 0, &mut buf).expect("read init");
        assert_eq!(&buf[..read], b"#!/bin/sh");
    }

    #[test]
    fn parse_cpio_creates_directories() {
        let mut archive = Vec::new();
        // Directory entry
        archive.extend(build_cpio_entry("etc", &[], 0o040755));
        // File inside directory
        archive.extend(build_cpio_entry("etc/hostname", b"thumos", 0o100644));
        archive.extend(build_cpio_trailer());

        let fs = RamFs::from_cpio(&archive);

        // Should be able to walk the path
        let etc_id = fs.lookup(0, "etc").expect("lookup etc");
        let hostname_id = fs.lookup(etc_id, "hostname").expect("lookup hostname");

        let mut buf = [0u8; 32];
        let read = fs.read(hostname_id, 0, &mut buf).expect("read hostname");
        assert_eq!(&buf[..read], b"thumos");

        // Also findable via backward-compatible path
        assert_eq!(fs.find("etc/hostname"), Some(b"thumos".as_slice()));
    }

    #[test]
    fn parse_cpio_creates_implicit_parent_dirs() {
        let mut archive = Vec::new();
        // File in nested path without explicit directory entries
        archive.extend(build_cpio_entry("usr/bin/hello", b"binary", 0o100755));
        archive.extend(build_cpio_trailer());

        let fs = RamFs::from_cpio(&archive);

        // Implicit directories should exist
        let usr_id = fs.lookup(0, "usr").expect("lookup usr");
        let bin_id = fs.lookup(usr_id, "bin").expect("lookup bin");
        let hello_id = fs.lookup(bin_id, "hello").expect("lookup hello");

        let mut buf = [0u8; 32];
        let read = fs.read(hello_id, 0, &mut buf).expect("read hello");
        assert_eq!(&buf[..read], b"binary");
    }
}
