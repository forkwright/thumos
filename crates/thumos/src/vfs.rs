//! Virtual Filesystem Switch (VFS).
//!
//! Provides the trait-based filesystem abstraction layer, mount table, and
//! path resolution for the thumos kernel. Concrete filesystem implementations
//! (devfs, ramfs, etc.) implement the `Filesystem` trait and register via
//! `MountTable::mount`.
//!
//! Design decisions:
//!   - `dyn Filesystem` dispatch: simplicity over monomorphization. This is a
//!     kernel with a handful of mount points, not a high-throughput file server.
//!   - Fixed-size mount table (8 entries): avoids heap allocation for the table
//!     structure itself, consistent with the kernel's fixed-size-table pattern.
//!   - Only absolute paths: relative path resolution requires per-process cwd
//!     tracking, which is deferred to a later phase.

extern crate alloc;
use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// VFS error codes, mapping to Linux ARM errno values.
///
/// Each variant corresponds to a POSIX error number. Use `to_errno()` to
/// obtain the two's complement negation suitable for returning to userspace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum VfsError {
    /// Entry not found (ENOENT = 2).
    NotFound,
    /// Path component is not a directory (ENOTDIR = 20).
    NotADirectory,
    /// Target is a directory when a file was expected (EISDIR = 21).
    IsADirectory,
    /// Entry already exists (EEXIST = 17).
    AlreadyExists,
    /// Directory is not empty (ENOTEMPTY = 39).
    NotEmpty,
    /// Invalid path or argument (EINVAL = 22).
    InvalidPath,
    /// No space left on device (ENOSPC = 28).
    NoSpace,
    /// I/O error (EIO = 5).
    IoError,
    /// Permission denied (EACCES = 13).
    PermissionDenied,
    /// Too many links (EMLINK = 31).
    TooManyLinks,
}

impl core::fmt::Display for VfsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotFound => write!(f, "not found"),
            Self::NotADirectory => write!(f, "not a directory"),
            Self::IsADirectory => write!(f, "is a directory"),
            Self::AlreadyExists => write!(f, "already exists"),
            Self::NotEmpty => write!(f, "directory not empty"),
            Self::InvalidPath => write!(f, "invalid path"),
            Self::NoSpace => write!(f, "no space left on device"),
            Self::IoError => write!(f, "I/O error"),
            Self::PermissionDenied => write!(f, "permission denied"),
            Self::TooManyLinks => write!(f, "too many links"),
        }
    }
}

impl VfsError {
    /// Convert to Linux ARM errno as two's complement negation.
    ///
    /// Returns the value that would be placed in r0 for a failed syscall on
    /// ARM Linux (e.g., `ENOENT` -> `0u32.wrapping_sub(2)` = `0xFFFF_FFFE`).
    pub const fn to_errno(self) -> u32 {
        let raw = match self {
            Self::NotFound => 2,
            Self::NotADirectory => 20,
            Self::IsADirectory => 21,
            Self::AlreadyExists => 17,
            Self::NotEmpty => 39,
            Self::InvalidPath => 22,
            Self::NoSpace => 28,
            Self::IoError => 5,
            Self::PermissionDenied => 13,
            Self::TooManyLinks => 31,
        };
        0u32.wrapping_sub(raw)
    }
}

// ---------------------------------------------------------------------------
// Inode metadata
// ---------------------------------------------------------------------------

/// Type of a filesystem inode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum InodeType {
    /// Regular file.
    RegularFile,
    /// Directory.
    Directory,
    /// Character device (e.g., `/dev/null`).
    CharDevice,
    /// Block device (e.g., `/dev/mmcblk0`).
    BlockDevice,
    /// Symbolic link.
    Symlink,
}

impl core::fmt::Display for InodeType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::RegularFile => write!(f, "regular file"),
            Self::Directory => write!(f, "directory"),
            Self::CharDevice => write!(f, "char device"),
            Self::BlockDevice => write!(f, "block device"),
            Self::Symlink => write!(f, "symlink"),
        }
    }
}

/// Metadata for a single inode, returned by `Filesystem::stat`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct InodeStat {
    /// Inode number within the filesystem.
    pub inode_id: u32,
    /// Type of the inode (file, directory, device, etc.).
    pub inode_type: InodeType,
    /// Size in bytes (0 for devices).
    pub size: u64,
    /// Number of hard links to this inode.
    pub link_count: u32,
    /// Number of blocks allocated (filesystem-specific granularity).
    pub block_count: u32,
}

impl core::fmt::Display for InodeStat {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "inode {} ({}, {} bytes)", self.inode_id, self.inode_type, self.size)
    }
}

// ---------------------------------------------------------------------------
// Directory entry
// ---------------------------------------------------------------------------

/// A single entry in a directory listing.
#[derive(Debug, PartialEq)]
pub struct DirEntry {
    /// Entry name (filename component, not full path).
    pub name: String,
    /// Inode number of the entry.
    pub inode_id: u32,
    /// Type of the inode this entry refers to.
    pub inode_type: InodeType,
}

impl core::fmt::Display for DirEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} (inode {}, {})", self.name, self.inode_id, self.inode_type)
    }
}

// ---------------------------------------------------------------------------
// Filesystem trait
// ---------------------------------------------------------------------------

/// Core filesystem interface.
///
/// Each mounted filesystem implements this trait. The VFS layer uses dynamic
/// dispatch (`dyn Filesystem`) to call into concrete implementations.
///
/// All inode IDs are filesystem-local; the mount table maps paths to
/// filesystem instances.
pub trait Filesystem {
    /// Return the inode ID of the filesystem root directory.
    fn root_inode(&self) -> u32;

    /// Retrieve metadata for an inode.
    ///
    /// # Errors
    ///
    /// Returns `VfsError::NotFound` if `inode_id` does not exist.
    fn stat(&self, inode_id: u32) -> Result<InodeStat, VfsError>;

    /// Look up a child entry by name within a directory.
    ///
    /// # Errors
    ///
    /// - `VfsError::NotFound` if no entry with `name` exists in the directory.
    /// - `VfsError::NotADirectory` if `dir_inode` is not a directory.
    fn lookup(&self, dir_inode: u32, name: &str) -> Result<u32, VfsError>;

    /// Read bytes from a file.
    ///
    /// Reads up to `buf.len()` bytes starting at `offset`. Returns the number
    /// of bytes actually read (0 at EOF).
    ///
    /// # Errors
    ///
    /// - `VfsError::NotFound` if `inode_id` does not exist.
    /// - `VfsError::IsADirectory` if `inode_id` refers to a directory.
    /// - `VfsError::IoError` on I/O failure.
    fn read(&self, inode_id: u32, offset: u64, buf: &mut [u8]) -> Result<usize, VfsError>;

    /// Write bytes to a file.
    ///
    /// Writes up to `buf.len()` bytes starting at `offset`. Returns the number
    /// of bytes actually written.
    ///
    /// # Errors
    ///
    /// - `VfsError::NotFound` if `inode_id` does not exist.
    /// - `VfsError::IsADirectory` if `inode_id` refers to a directory.
    /// - `VfsError::PermissionDenied` if the filesystem is read-only.
    /// - `VfsError::NoSpace` if the filesystem is full.
    /// - `VfsError::IoError` on I/O failure.
    fn write(&mut self, inode_id: u32, offset: u64, buf: &[u8]) -> Result<usize, VfsError>;

    /// Create a new inode in a directory.
    ///
    /// # Errors
    ///
    /// - `VfsError::NotADirectory` if `dir_inode` is not a directory.
    /// - `VfsError::AlreadyExists` if `name` already exists in the directory.
    /// - `VfsError::PermissionDenied` if the filesystem is read-only.
    /// - `VfsError::NoSpace` if the filesystem is full.
    fn create(
        &mut self,
        dir_inode: u32,
        name: &str,
        inode_type: InodeType,
    ) -> Result<u32, VfsError>;

    /// Remove an entry from a directory.
    ///
    /// # Errors
    ///
    /// - `VfsError::NotFound` if `name` does not exist in the directory.
    /// - `VfsError::NotADirectory` if `dir_inode` is not a directory.
    /// - `VfsError::NotEmpty` if the entry is a non-empty directory.
    /// - `VfsError::PermissionDenied` if the filesystem is read-only.
    fn unlink(&mut self, dir_inode: u32, name: &str) -> Result<(), VfsError>;

    /// List all entries in a directory.
    ///
    /// # Errors
    ///
    /// - `VfsError::NotADirectory` if `dir_inode` is not a directory.
    /// - `VfsError::NotFound` if `dir_inode` does not exist.
    fn readdir(&self, dir_inode: u32) -> Result<Vec<DirEntry>, VfsError>;

    /// Truncate a file to the specified size.
    ///
    /// # Errors
    ///
    /// - `VfsError::NotFound` if `inode_id` does not exist.
    /// - `VfsError::IsADirectory` if `inode_id` refers to a directory.
    /// - `VfsError::PermissionDenied` if the filesystem is read-only.
    fn truncate(&mut self, inode_id: u32, size: u64) -> Result<(), VfsError>;

    /// Flush any cached writes to persistent storage.
    ///
    /// # Errors
    ///
    /// Returns `VfsError::IoError` if flushing fails.
    fn sync(&mut self) -> Result<(), VfsError>;
}

// ---------------------------------------------------------------------------
// Mount table
// ---------------------------------------------------------------------------

/// Maximum number of simultaneous mount points.
const MAX_MOUNTS: usize = 8;

/// A single mount point entry: a path prefix and its associated filesystem.
struct MountEntry {
    /// Mount path (e.g., "/", "/dev", "/proc"). Always absolute, no trailing
    /// slash (except for root "/").
    path: String,
    /// The mounted filesystem instance.
    fs: Box<dyn Filesystem>,
}

/// Table of mounted filesystems.
///
/// Stores up to `MAX_MOUNTS` mount entries. Path resolution uses
/// longest-prefix matching to find the correct filesystem for a given path.
pub struct MountTable {
    /// Fixed-size array of optional mount entries.
    entries: [Option<MountEntry>; MAX_MOUNTS],
}

impl MountTable {
    /// Create an empty mount table.
    pub const fn new() -> Self {
        // WHY manual const array: MountEntry contains Box<dyn Filesystem>
        // which is not Copy, so we cannot use `[None; MAX_MOUNTS]` directly.
        // Default::default() is not const, so we build the array manually.
        const NONE: Option<MountEntry> = None;
        Self {
            entries: [NONE; MAX_MOUNTS],
        }
    }

    /// Mount a filesystem at the given path.
    ///
    /// The path must be absolute (start with `/`). Duplicate mount paths are
    /// rejected.
    ///
    /// # Errors
    ///
    /// - `VfsError::InvalidPath` if the path does not start with `/`.
    /// - `VfsError::AlreadyExists` if the path is already mounted.
    /// - `VfsError::NoSpace` if all mount slots are occupied.
    #[must_use]
    pub fn mount(&mut self, path: &str, fs: Box<dyn Filesystem>) -> Result<(), VfsError> {
        if !path.starts_with('/') {
            return Err(VfsError::InvalidPath);
        }

        // Reject duplicate mount paths.
        for entry in self.entries.iter().flatten() {
            if entry.path == path {
                return Err(VfsError::AlreadyExists);
            }
        }

        // Find the first empty slot.
        for slot in &mut self.entries {
            if slot.is_none() {
                *slot = Some(MountEntry {
                    path: String::from(path),
                    fs,
                });
                return Ok(());
            }
        }

        Err(VfsError::NoSpace)
    }

    /// Find the mount entry whose path is the longest prefix of `path`.
    ///
    /// Returns `(mount_index, remaining_path)` where `remaining_path` is the
    /// portion of `path` after stripping the mount prefix. The remaining path
    /// always starts with `/` or is `"/"` for an exact match on a non-root
    /// mount. For the root mount `/`, the full path is returned as remaining.
    ///
    /// Returns `None` if no mount matches (should not happen if `/` is mounted).
    pub fn lookup<'a>(&self, path: &'a str) -> Option<(usize, &'a str)> {
        let mut best_idx = None;
        let mut best_len = 0;

        for (i, slot) in self.entries.iter().enumerate() {
            let entry = match slot {
                Some(e) => e,
                None => continue,
            };

            let mount_path = entry.path.as_str();

            // Root mount "/" matches everything.
            if mount_path == "/" {
                if best_len == 0 {
                    best_idx = Some(i);
                    best_len = 1;
                }
                continue;
            }

            // Non-root: path must equal mount_path or have mount_path as a
            // prefix followed by '/'.
            if path == mount_path
                || (path.starts_with(mount_path)
                    && path.as_bytes().get(mount_path.len()) == Some(&b'/'))
            {
                if mount_path.len() > best_len {
                    best_idx = Some(i);
                    best_len = mount_path.len();
                }
            }
        }

        best_idx.map(move |idx| {
            let is_root = best_len == 1;
            let remaining = if is_root {
                path
            } else if path.len() == best_len {
                // Exact match on mount path — remaining is "/"
                "/"
            } else {
                // Strip mount prefix; remainder starts with '/'
                &path[best_len..]
            };
            (idx, remaining)
        })
    }

    /// Get a shared reference to the filesystem at mount index `idx`.
    ///
    /// # Errors
    ///
    /// Returns `None` if `idx` is out of range or the slot is empty.
    pub fn get(&self, idx: usize) -> Option<&dyn Filesystem> {
        if idx >= MAX_MOUNTS {
            return None;
        }
        self.entries[idx].as_ref().map(|e| e.fs.as_ref())
    }

    /// Get a mutable reference to the filesystem at mount index `idx`.
    ///
    /// # Errors
    ///
    /// Returns `None` if `idx` is out of range or the slot is empty.
    pub fn get_mut(&mut self, idx: usize) -> Option<&mut dyn Filesystem> {
        if idx >= MAX_MOUNTS {
            return None;
        }
        match self.entries[idx] {
            Some(ref mut entry) => Some(entry.fs.as_mut()),
            None => None,
        }
    }
}

impl Default for MountTable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Path resolution
// ---------------------------------------------------------------------------

/// Resolve an absolute path to a (mount_index, inode_id) pair.
///
/// Walks each component of `path` via `Filesystem::lookup()`, starting from
/// the filesystem root inode. Handles `.` (current directory, skip) and `..`
/// (parent directory, pop from parent stack). Only absolute paths are accepted
/// (must start with `/`).
///
/// # Errors
///
/// - `VfsError::InvalidPath` if the path is empty or does not start with `/`.
/// - `VfsError::NotFound` if any path component cannot be found.
/// - `VfsError::NotADirectory` if a non-terminal component is not a directory.
#[must_use]
pub fn resolve_path(mounts: &MountTable, path: &str) -> Result<(usize, u32), VfsError> {
    if path.is_empty() || !path.starts_with('/') {
        return Err(VfsError::InvalidPath);
    }

    let (mount_idx, remaining) = mounts.lookup(path).ok_or(VfsError::NotFound)?;
    let fs = mounts.get(mount_idx).ok_or(VfsError::NotFound)?;

    let root = fs.root_inode();

    // Split the remaining path into components, filtering out empty segments
    // (from leading/trailing/doubled slashes).
    let components: Vec<&str> = remaining
        .split('/')
        .filter(|c| !c.is_empty())
        .collect();

    if components.is_empty() {
        // Path resolves to the mount root itself.
        return Ok((mount_idx, root));
    }

    // Parent stack tracks inode IDs so `..` can pop back.
    let mut parent_stack: Vec<u32> = Vec::new();
    let mut current = root;

    for component in &components {
        match *component {
            "." => {
                // Current directory — no-op.
            }
            ".." => {
                // Parent directory — pop if possible, otherwise stay at root.
                current = parent_stack.pop().unwrap_or(root);
            }
            name => {
                // Push current as parent before descending.
                parent_stack.push(current);
                current = fs.lookup(current, name)?;
            }
        }
    }

    Ok((mount_idx, current))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    // -- TestFs: in-memory filesystem for testing --
    //
    // Hardcoded tree:
    //   inode 0 (dir):  root, contains "foo" (1), "bar" (2), "sub" (3)
    //   inode 1 (file): "foo"
    //   inode 2 (file): "bar"
    //   inode 3 (dir):  "sub", contains "baz" (4)
    //   inode 4 (file): "baz"

    struct TestFs;

    impl Filesystem for TestFs {
        fn root_inode(&self) -> u32 {
            0
        }

        fn stat(&self, inode_id: u32) -> Result<InodeStat, VfsError> {
            let inode_type = match inode_id {
                0 | 3 => InodeType::Directory,
                1 | 2 | 4 => InodeType::RegularFile,
                _ => return Err(VfsError::NotFound),
            };
            Ok(InodeStat {
                inode_id,
                inode_type,
                size: 0,
                link_count: 1,
                block_count: 0,
            })
        }

        fn lookup(&self, dir_inode: u32, name: &str) -> Result<u32, VfsError> {
            match (dir_inode, name) {
                (0, "foo") => Ok(1),
                (0, "bar") => Ok(2),
                (0, "sub") => Ok(3),
                (3, "baz") => Ok(4),
                (0 | 3, _) => Err(VfsError::NotFound),
                _ => Err(VfsError::NotADirectory),
            }
        }

        fn read(&self, _inode_id: u32, _offset: u64, _buf: &mut [u8]) -> Result<usize, VfsError> {
            Ok(0)
        }

        fn write(
            &mut self,
            _inode_id: u32,
            _offset: u64,
            _buf: &[u8],
        ) -> Result<usize, VfsError> {
            Ok(0)
        }

        fn create(
            &mut self,
            _dir_inode: u32,
            _name: &str,
            _inode_type: InodeType,
        ) -> Result<u32, VfsError> {
            Err(VfsError::PermissionDenied)
        }

        fn unlink(&mut self, _dir_inode: u32, _name: &str) -> Result<(), VfsError> {
            Err(VfsError::PermissionDenied)
        }

        fn readdir(&self, dir_inode: u32) -> Result<Vec<DirEntry>, VfsError> {
            match dir_inode {
                0 => Ok(vec![
                    DirEntry {
                        name: String::from("foo"),
                        inode_id: 1,
                        inode_type: InodeType::RegularFile,
                    },
                    DirEntry {
                        name: String::from("bar"),
                        inode_id: 2,
                        inode_type: InodeType::RegularFile,
                    },
                    DirEntry {
                        name: String::from("sub"),
                        inode_id: 3,
                        inode_type: InodeType::Directory,
                    },
                ]),
                3 => Ok(vec![DirEntry {
                    name: String::from("baz"),
                    inode_id: 4,
                    inode_type: InodeType::RegularFile,
                }]),
                _ => Err(VfsError::NotADirectory),
            }
        }

        fn truncate(&mut self, _inode_id: u32, _size: u64) -> Result<(), VfsError> {
            Err(VfsError::PermissionDenied)
        }

        fn sync(&mut self) -> Result<(), VfsError> {
            Ok(())
        }
    }

    /// A second test filesystem to verify multi-mount resolution.
    struct TestFs2;

    impl Filesystem for TestFs2 {
        fn root_inode(&self) -> u32 {
            0
        }

        fn stat(&self, inode_id: u32) -> Result<InodeStat, VfsError> {
            if inode_id == 0 {
                Ok(InodeStat {
                    inode_id: 0,
                    inode_type: InodeType::Directory,
                    size: 0,
                    link_count: 1,
                    block_count: 0,
                })
            } else {
                Err(VfsError::NotFound)
            }
        }

        fn lookup(&self, dir_inode: u32, name: &str) -> Result<u32, VfsError> {
            if dir_inode == 0 && name == "special" {
                Ok(10)
            } else if dir_inode == 0 {
                Err(VfsError::NotFound)
            } else {
                Err(VfsError::NotADirectory)
            }
        }

        fn read(&self, _inode_id: u32, _offset: u64, _buf: &mut [u8]) -> Result<usize, VfsError> {
            Ok(0)
        }

        fn write(
            &mut self,
            _inode_id: u32,
            _offset: u64,
            _buf: &[u8],
        ) -> Result<usize, VfsError> {
            Ok(0)
        }

        fn create(
            &mut self,
            _dir_inode: u32,
            _name: &str,
            _inode_type: InodeType,
        ) -> Result<u32, VfsError> {
            Err(VfsError::PermissionDenied)
        }

        fn unlink(&mut self, _dir_inode: u32, _name: &str) -> Result<(), VfsError> {
            Err(VfsError::PermissionDenied)
        }

        fn readdir(&self, _dir_inode: u32) -> Result<Vec<DirEntry>, VfsError> {
            Ok(Vec::new())
        }

        fn truncate(&mut self, _inode_id: u32, _size: u64) -> Result<(), VfsError> {
            Err(VfsError::PermissionDenied)
        }

        fn sync(&mut self) -> Result<(), VfsError> {
            Ok(())
        }
    }

    // -- Mount table tests --

    #[test]
    fn mount_table_resolves_root() {
        let mut mt = MountTable::new();
        mt.mount("/", Box::new(TestFs)).expect("mount root");

        let result = mt.lookup("/");
        assert!(result.is_some(), "root mount must be found");
        let (idx, remaining) = result.expect("already checked");
        assert_eq!(idx, 0);
        assert_eq!(remaining, "/");
    }

    #[test]
    fn mount_table_resolves_longest_prefix() {
        let mut mt = MountTable::new();
        mt.mount("/", Box::new(TestFs)).expect("mount root");
        mt.mount("/dev", Box::new(TestFs2)).expect("mount /dev");

        // "/dev/special" should resolve to the /dev mount (index 1), not root.
        let result = mt.lookup("/dev/special");
        assert!(result.is_some(), "/dev mount must match");
        let (idx, remaining) = result.expect("already checked");
        assert_eq!(idx, 1, "longest prefix should select /dev mount");
        assert_eq!(remaining, "/special");

        // "/foo" should resolve to root mount (index 0).
        let root_result = mt.lookup("/foo");
        assert!(root_result.is_some());
        let (root_idx, root_remaining) = root_result.expect("already checked");
        assert_eq!(root_idx, 0, "non-/dev path should use root mount");
        assert_eq!(root_remaining, "/foo");
    }

    // -- Path resolution tests --

    #[test]
    fn resolve_path_finds_file_at_root() {
        let mut mt = MountTable::new();
        mt.mount("/", Box::new(TestFs)).expect("mount root");

        let result = resolve_path(&mt, "/foo");
        assert!(result.is_ok(), "resolving /foo must succeed");
        let (mount_idx, inode) = result.expect("already checked");
        assert_eq!(mount_idx, 0);
        assert_eq!(inode, 1, "foo is inode 1");
    }

    #[test]
    fn resolve_path_walks_subdirectory() {
        let mut mt = MountTable::new();
        mt.mount("/", Box::new(TestFs)).expect("mount root");

        let result = resolve_path(&mt, "/sub/baz");
        assert!(result.is_ok(), "resolving /sub/baz must succeed");
        let (_, inode) = result.expect("already checked");
        assert_eq!(inode, 4, "baz is inode 4");
    }

    #[test]
    fn resolve_path_handles_dot() {
        let mut mt = MountTable::new();
        mt.mount("/", Box::new(TestFs)).expect("mount root");

        // "/./foo" should resolve the same as "/foo"
        let result = resolve_path(&mt, "/./foo");
        assert!(result.is_ok(), "dot component must be skipped");
        let (_, inode) = result.expect("already checked");
        assert_eq!(inode, 1);
    }

    #[test]
    fn resolve_path_handles_dotdot() {
        let mut mt = MountTable::new();
        mt.mount("/", Box::new(TestFs)).expect("mount root");

        // "/sub/../foo" — enter sub (inode 3), back to root (inode 0), then foo (inode 1)
        let result = resolve_path(&mt, "/sub/../foo");
        assert!(result.is_ok(), "dotdot must navigate to parent");
        let (_, inode) = result.expect("already checked");
        assert_eq!(inode, 1, "should resolve to foo after ..");
    }

    #[test]
    fn resolve_path_returns_not_found_for_missing() {
        let mut mt = MountTable::new();
        mt.mount("/", Box::new(TestFs)).expect("mount root");

        let result = resolve_path(&mt, "/nonexistent");
        assert_eq!(result, Err(VfsError::NotFound));
    }

    #[test]
    fn vfs_error_maps_to_correct_errno() {
        assert_eq!(VfsError::NotFound.to_errno(), 0u32.wrapping_sub(2));
        assert_eq!(VfsError::NotADirectory.to_errno(), 0u32.wrapping_sub(20));
        assert_eq!(VfsError::IsADirectory.to_errno(), 0u32.wrapping_sub(21));
        assert_eq!(VfsError::AlreadyExists.to_errno(), 0u32.wrapping_sub(17));
        assert_eq!(VfsError::NotEmpty.to_errno(), 0u32.wrapping_sub(39));
        assert_eq!(VfsError::InvalidPath.to_errno(), 0u32.wrapping_sub(22));
        assert_eq!(VfsError::NoSpace.to_errno(), 0u32.wrapping_sub(28));
        assert_eq!(VfsError::IoError.to_errno(), 0u32.wrapping_sub(5));
        assert_eq!(VfsError::PermissionDenied.to_errno(), 0u32.wrapping_sub(13));
        assert_eq!(VfsError::TooManyLinks.to_errno(), 0u32.wrapping_sub(31));
    }

    // -- Edge cases --

    #[test]
    fn mount_rejects_relative_path() {
        let mut mt = MountTable::new();
        let result = mt.mount("dev", Box::new(TestFs));
        assert_eq!(result, Err(VfsError::InvalidPath));
    }

    #[test]
    fn mount_rejects_duplicate_path() {
        let mut mt = MountTable::new();
        mt.mount("/", Box::new(TestFs)).expect("first mount");
        let result = mt.mount("/", Box::new(TestFs));
        assert_eq!(result, Err(VfsError::AlreadyExists));
    }

    #[test]
    fn resolve_path_rejects_empty_path() {
        let mt = MountTable::new();
        assert_eq!(resolve_path(&mt, ""), Err(VfsError::InvalidPath));
    }

    #[test]
    fn resolve_path_rejects_relative_path() {
        let mut mt = MountTable::new();
        mt.mount("/", Box::new(TestFs)).expect("mount");
        assert_eq!(resolve_path(&mt, "foo"), Err(VfsError::InvalidPath));
    }

    #[test]
    fn resolve_path_returns_root_inode_for_slash() {
        let mut mt = MountTable::new();
        mt.mount("/", Box::new(TestFs)).expect("mount");
        let (mount_idx, inode) = resolve_path(&mt, "/")
            .expect("resolving / must succeed when root is mounted");
        assert_eq!(mount_idx, 0, "/ must resolve to mount index 0");
        assert_eq!(inode, 0, "/ must resolve to root inode 0");
    }

    #[test]
    fn get_returns_none_for_empty_slot() {
        let mt = MountTable::new();
        assert!(mt.get(0).is_none());
        assert!(mt.get(99).is_none());
    }

    #[test]
    fn get_mut_returns_none_for_empty_slot() {
        let mut mt = MountTable::new();
        assert!(mt.get_mut(0).is_none());
        assert!(mt.get_mut(99).is_none());
    }
}
