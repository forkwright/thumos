//! File descriptor table and VFS-backed syscall implementations.
//!
//! Each open file descriptor holds a reference to a mounted filesystem
//! (via mount index), an inode within that filesystem, a read/write
//! offset, and flags. The table is a fixed-size array per process, with
//! methods to allocate, look up, and release entries.
//!
//! All data access goes through `Filesystem::read()`/`Filesystem::write()`
//! via the mount table. No raw pointers to file data are stored.
//!
//! WHY fixed-size: avoids heap allocation in the fd table itself, keeps
//! the structure predictable for a bare-metal kernel. 256 entries is
//! sufficient for a BusyBox shell + init + concurrent processes.

extern crate alloc;
use alloc::boxed::Box;
use crate::vfs::{self, InodeType, MountTable, VfsError};

/// Maximum number of open file descriptors per process.
pub const MAX_FDS: usize = 256;

/// Error codes matching Linux ARM conventions (two's complement negation).
/// WHY: toolchain compatibility with userspace built against Linux headers.
pub const EBADF: u32 = 0u32.wrapping_sub(9);
/// No such file or directory.
pub const ENOENT: u32 = 0u32.wrapping_sub(2);
/// Too many open files.
pub const EMFILE: u32 = 0u32.wrapping_sub(24);
/// Invalid argument.
pub const EINVAL: u32 = 0u32.wrapping_sub(22);
/// Bad address.
pub const EFAULT: u32 = 0u32.wrapping_sub(14);
/// Is a directory.
pub const EISDIR: u32 = 0u32.wrapping_sub(21);

/// Seek whence constants (POSIX).
pub const SEEK_SET: u32 = 0;
/// Seek from current position.
pub const SEEK_CUR: u32 = 1;
/// Seek from end of file.
pub const SEEK_END: u32 = 2;

/// File type constants for StatBuf.
pub const S_IFREG: u32 = 0o100000;
/// Directory file type.
pub const S_IFDIR: u32 = 0o040000;
/// Character device file type.
pub const S_IFCHR: u32 = 0o020000;

/// Stat buffer written to userspace.
///
/// WHY minimal struct: size and type are the only metadata the kernel
/// tracks at this phase. Extended fields (mode, uid, timestamps) are
/// future work.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct StatBuf {
    /// File size in bytes.
    pub size: u32,
    /// File type (S_IFREG, S_IFDIR, S_IFCHR).
    pub file_type: u32,
}

/// A single open file descriptor.
///
/// References a file via mount table index and inode ID. No raw pointers
/// to file data are stored; all access goes through the VFS.
///
/// For pipe file descriptors, the pipe identity is encoded in `flags`
/// (see `pipe.rs` for the encoding). `mount_idx` and `inode_id` are
/// unused for pipes.
#[derive(Clone, Copy)]
pub struct FileDescriptor {
    /// Index into the global MountTable identifying the filesystem.
    pub mount_idx: u8,
    /// Inode ID within the filesystem.
    pub inode_id: u32,
    /// Current read/write position within the file.
    pub offset: usize,
    /// Open flags (O_RDONLY, O_WRONLY, O_RDWR, pipe encoding, etc.).
    pub flags: u32,
}

impl FileDescriptor {
    /// Create a new file descriptor for a VFS file.
    pub fn from_vfs(mount_idx: u8, inode_id: u32, flags: u32) -> Self {
        Self {
            mount_idx,
            inode_id,
            offset: 0,
            flags,
        }
    }

    /// Create a file descriptor with flags only (for pipes).
    ///
    /// Pipe file descriptors do not reference VFS inodes; the pipe
    /// identity is encoded entirely in `flags`.
    pub fn new(_data: &[u8], flags: u32) -> Self {
        Self {
            mount_idx: 0,
            inode_id: 0,
            offset: 0,
            flags,
        }
    }

    /// File size via VFS stat (returns 0 if unavailable).
    ///
    /// For pipe fds this returns 0, which is correct (pipes have no
    /// seekable size).
    pub fn size(&self) -> usize {
        // SAFETY: MOUNT_TABLE is a static mut; single-core cooperative
        // kernel ensures exclusive access during syscall handling.
        let mt_opt = unsafe { &*core::ptr::addr_of!(MOUNT_TABLE) };
        let mt = match mt_opt.as_ref() {
            Some(t) => t,
            None => return 0,
        };
        match mt.get(self.mount_idx as usize) {
            Some(fs) => match fs.stat(self.inode_id) {
                Ok(stat) => stat.size as usize,
                Err(_) => 0,
            },
            None => 0,
        }
    }
}

/// Per-process file descriptor table.
pub struct FdTable {
    entries: [Option<FileDescriptor>; MAX_FDS],
}

impl FdTable {
    /// Create an empty fd table.
    pub const fn new() -> Self {
        const NONE: Option<FileDescriptor> = None;
        Self {
            entries: [NONE; MAX_FDS],
        }
    }

    /// Allocate the lowest available file descriptor slot.
    /// Returns the fd number, or None if the table is full.
    pub fn alloc(&mut self, fd: FileDescriptor) -> Option<usize> {
        for (i, slot) in self.entries.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(fd);
                return Some(i);
            }
        }
        None
    }

    /// Allocate a specific fd slot, closing any existing entry.
    /// Returns true on success, false if the slot index is out of range.
    pub fn alloc_at(&mut self, index: usize, fd: FileDescriptor) -> bool {
        if index >= MAX_FDS {
            return false;
        }
        self.entries[index] = Some(fd);
        true
    }

    /// Get a reference to a file descriptor by index.
    pub fn get(&self, index: usize) -> Option<&FileDescriptor> {
        if index >= MAX_FDS {
            return None;
        }
        self.entries[index].as_ref()
    }

    /// Get a mutable reference to a file descriptor by index.
    pub fn get_mut(&mut self, index: usize) -> Option<&mut FileDescriptor> {
        if index >= MAX_FDS {
            return None;
        }
        self.entries[index].as_mut()
    }

    /// Close a file descriptor. Returns true if it was open.
    pub fn close(&mut self, index: usize) -> bool {
        if index >= MAX_FDS {
            return false;
        }
        self.entries[index].take().is_some()
    }
}

/// Global file descriptor table.
///
/// WHY global instead of per-process: the Process struct does not currently
/// support generic fields without significant refactoring (fixed-size array
/// in a static table). A global table indexed by PID would be ideal, but
/// for the initial bring-up a single global table is sufficient since only
/// one process uses filesystem syscalls at a time in the cooperative scheduler.
///
/// TODO(#32): migrate to per-process fd tables when Process struct supports it.
pub(crate) static mut FD_TABLE: FdTable = FdTable::new();

/// Global mount table for VFS dispatch.
///
/// Populated by `init_vfs()` during kernel boot. All filesystem syscalls
/// resolve paths and perform I/O through this table.
///
/// WHY Option: `MountTable::new()` is not const (contains `Option<Box<dyn Filesystem>>`),
/// so we cannot use it as a static initializer. The Option is None until
/// `init_vfs()` is called during kernel boot.
static mut MOUNT_TABLE: Option<MountTable> = None;

/// Maximum path length for the CWD buffer.
const CWD_MAX: usize = 256;

/// Global current working directory buffer.
///
/// Stored as a fixed-size byte buffer with a length field to avoid heap
/// allocation in a static mut. Defaults to "/" (len=1). Updated by
/// `sys_chdir`. Per-process cwd tracking is deferred to a later phase.
static mut CWD_BUF: [u8; CWD_MAX] = {
    let mut buf = [0u8; CWD_MAX];
    buf[0] = b'/';
    buf
};

/// Length of the current CWD string in `CWD_BUF`.
static mut CWD_LEN: usize = 1;

/// Get the current working directory path.
///
/// # Safety
///
/// Caller must ensure single-threaded access (cooperative kernel guarantee).
unsafe fn get_cwd() -> &'static str {
    // SAFETY: CWD_BUF and CWD_LEN are static muts; addr_of! avoids
    // intermediate references. Single-core cooperative kernel ensures
    // exclusive access.
    unsafe {
        let buf = &*core::ptr::addr_of!(CWD_BUF);
        let len = *core::ptr::addr_of!(CWD_LEN);
        core::str::from_utf8_unchecked(&buf[..len])
    }
}

/// Set the current working directory.
///
/// # Safety
///
/// Caller must ensure single-threaded access.
unsafe fn set_cwd(path: &str) {
    unsafe {
        let buf = &mut *core::ptr::addr_of_mut!(CWD_BUF);
        let len_ptr = &mut *core::ptr::addr_of_mut!(CWD_LEN);
        let copy_len = path.len().min(CWD_MAX);
        buf[..copy_len].copy_from_slice(&path.as_bytes()[..copy_len]);
        *len_ptr = copy_len;
    }
}

/// Get a shared reference to the global mount table.
///
/// # Safety
///
/// Caller must ensure `init_vfs` or `init_ramfs` has been called.
/// Returns None if the mount table is not initialized.
unsafe fn get_mount_table() -> Option<&'static MountTable> {
    // SAFETY: MOUNT_TABLE is a static mut; addr_of! avoids an intermediate reference.
    unsafe {
        let mt_opt = &*core::ptr::addr_of!(MOUNT_TABLE);
        mt_opt.as_ref()
    }
}

/// Get a mutable reference to the global mount table.
///
/// # Safety
///
/// Caller must ensure `init_vfs` or `init_ramfs` has been called.
/// Single-core cooperative kernel ensures exclusive access during syscall handling.
/// Returns None if the mount table is not initialized.
unsafe fn get_mount_table_mut() -> Option<&'static mut MountTable> {
    // SAFETY: MOUNT_TABLE is a static mut; addr_of_mut! avoids an intermediate reference.
    unsafe {
        let mt_opt = &mut *core::ptr::addr_of_mut!(MOUNT_TABLE);
        mt_opt.as_mut()
    }
}

/// Initialize the VFS with root ramfs, /dev, and /tmp.
///
/// Creates the mount table, populates the root filesystem from CPIO data,
/// mounts devfs at /dev, and creates an empty ramfs at /tmp.
///
/// # Safety
///
/// Must be called once during kernel init, before any filesystem syscalls.
/// After this call, `MOUNT_TABLE` is populated and ready for use.
pub unsafe fn init_vfs(cpio_data: Option<&[u8]>) {
    // SAFETY: called once during kernel init before any filesystem syscalls.
    // MOUNT_TABLE is a static mut; addr_of_mut! avoids an intermediate reference.
    // No concurrent access is possible because the scheduler has not started.
    unsafe {
        let mut mt = MountTable::new();

        // Root filesystem from CPIO or empty
        let root_fs = match cpio_data {
            Some(data) => crate::ramfs::RamFs::from_cpio(data),
            None => crate::ramfs::RamFs::new(),
        };
        // Ignore mount errors during init; these are fatal if they fail but
        // the mount table has 8 slots and we use only 3.
        let _ = mt.mount("/", Box::new(root_fs));

        // /dev filesystem
        let devfs = crate::devfs::DevFs::new(0xDEAD_BEEF_CAFE_BABE);
        let _ = mt.mount("/dev", Box::new(devfs));

        // /tmp filesystem (empty ramfs)
        let tmp_fs = crate::ramfs::RamFs::new();
        let _ = mt.mount("/tmp", Box::new(tmp_fs));

        let mt_opt = &mut *core::ptr::addr_of_mut!(MOUNT_TABLE);
        *mt_opt = Some(mt);

        // CWD is initialized to "/" by the static initializer; no action needed.
    }
}

/// Legacy: Initialize the global ramfs for syscall use.
///
/// This is a backward-compatible shim. New code should use `init_vfs()`.
///
/// # Safety
///
/// Must be called once during kernel init, before any filesystem syscalls.
pub unsafe fn init_ramfs(fs: crate::ramfs::RamFs) {
    // SAFETY: called once during kernel init before any filesystem syscalls.
    unsafe {
        let mt_opt = &mut *core::ptr::addr_of_mut!(MOUNT_TABLE);

        match mt_opt {
            Some(mt) => {
                // Only mount root if not already mounted (init_vfs may have been called first)
                if mt.lookup("/").is_none() {
                    let _ = mt.mount("/", Box::new(fs));
                }
            }
            None => {
                // init_vfs was never called; create a new mount table with just ramfs.
                let mut mt = MountTable::new();
                let _ = mt.mount("/", Box::new(fs));
                *mt_opt = Some(mt);
            }
        }
    }
}

/// Look up a file in the mounted filesystems by path.
/// Returns a reference to the file data, or None if not found.
///
/// # Safety
///
/// Caller must ensure the mount table has been initialized.
pub unsafe fn ramfs_find(path: &str) -> Option<&'static [u8]> {
    // SAFETY: mount table has been initialized during kernel boot.
    // Single-core cooperative kernel ensures exclusive access.
    unsafe {
        let mt = get_mount_table()?;

        let (mount_idx, inode_id) = match vfs::resolve_path(mt, path) {
            Ok(r) => r,
            Err(_) => return None,
        };

        let fs = mt.get(mount_idx)?;

        // Check it's a regular file
        let stat = fs.stat(inode_id).ok()?;
        if stat.inode_type != InodeType::RegularFile {
            return None;
        }

        // Read the entire file into a buffer
        // WHY alloc: we need a 'static reference but Filesystem::read copies
        // into a provided buffer. We allocate a Vec, leak it to get 'static
        // lifetime. This matches the original behavior where ramfs data lived
        // for the kernel's lifetime.
        let size = stat.size as usize;
        if size == 0 {
            return Some(&[]);
        }

        let mut buf = alloc::vec![0u8; size];
        match fs.read(inode_id, 0, &mut buf) {
            Ok(n) => {
                buf.truncate(n);
                let leaked = buf.leak();
                Some(leaked)
            }
            Err(_) => None,
        }
    }
}

// -- Syscall implementation functions --

/// SYS_open: open a file by path.
///
/// # Arguments
/// - `path_ptr`: userspace pointer to the path string
/// - `path_len`: length of the path string
/// - `flags`: open flags (reserved, currently ignored)
///
/// # Returns
/// File descriptor number on success, or negative error code.
pub fn sys_open(path_ptr: u32, path_len: u32, flags: u32) -> u32 {
    let len = path_len as usize;

    if path_ptr == 0 || len == 0 {
        return ENOENT;
    }

    // SAFETY: path_ptr is a userspace pointer validated non-null above; len
    // is the caller-supplied path length. Wave 4 will add proper bounds
    // validation; for now we trust the pointer per the existing syscall pattern.
    let path_slice = unsafe { core::slice::from_raw_parts(path_ptr as *const u8, len) };
    let path = match core::str::from_utf8(path_slice) {
        Ok(s) => s,
        Err(_) => return EINVAL,
    };

    // SAFETY: init_vfs has been called during kernel init.
    let mt = match unsafe { get_mount_table() } {
        Some(t) => t,
        None => return ENOENT,
    };

    let (mount_idx, inode_id) = match vfs::resolve_path(mt, path) {
        Ok(r) => r,
        Err(_) => return ENOENT,
    };

    let fd = FileDescriptor::from_vfs(mount_idx as u8, inode_id, flags);

    // SAFETY: FD_TABLE is a static mut; addr_of_mut! avoids an intermediate
    // reference. Single-core kernel with cooperative scheduling ensures
    // exclusive access during syscall handling.
    let table = unsafe { &mut *core::ptr::addr_of_mut!(FD_TABLE) };
    match table.alloc(fd) {
        Some(n) => n as u32,
        None => EMFILE,
    }
}

/// SYS_read: read bytes from an open file descriptor.
///
/// # Arguments
/// - `fd`: file descriptor number
/// - `buf_ptr`: userspace buffer to write into
/// - `count`: maximum bytes to read
///
/// # Returns
/// Number of bytes read (0 at EOF), or negative error code.
pub fn sys_read(fd: u32, buf_ptr: u32, count: u32) -> u32 {
    let fd_idx = fd as usize;
    let count = count as usize;

    if buf_ptr == 0 {
        return EFAULT;
    }

    // SAFETY: FD_TABLE is a static mut; addr_of_mut! avoids an intermediate
    // reference. Single-core kernel with cooperative scheduling ensures
    // exclusive access during syscall handling.
    let table = unsafe { &mut *core::ptr::addr_of_mut!(FD_TABLE) };
    let entry = match table.get_mut(fd_idx) {
        Some(e) => e,
        None => return EBADF,
    };

    let mount_idx = entry.mount_idx as usize;
    let inode_id = entry.inode_id;
    let offset = entry.offset as u64;

    // SAFETY: init_vfs has been called during kernel init.
    let mt = match unsafe { get_mount_table() } {
        Some(t) => t,
        None => return EBADF,
    };
    let fs = match mt.get(mount_idx) {
        Some(f) => f,
        None => return EBADF,
    };

    // SAFETY: buf_ptr is a userspace pointer validated non-null above.
    // Wave 4 will add proper bounds validation.
    let dst = unsafe { core::slice::from_raw_parts_mut(buf_ptr as *mut u8, count) };

    match fs.read(inode_id, offset, dst) {
        Ok(n) => {
            // Update offset in the fd entry
            let entry = unsafe { &mut *core::ptr::addr_of_mut!(FD_TABLE) }
                .get_mut(fd_idx)
                .expect("fd was valid above");
            entry.offset += n;
            n as u32
        }
        Err(e) => e.to_errno(),
    }
}

/// SYS_write: write bytes to an open file descriptor.
///
/// # Arguments
/// - `fd`: file descriptor number
/// - `buf_ptr`: userspace buffer to read from
/// - `count`: number of bytes to write
///
/// # Returns
/// Number of bytes written, or negative error code.
pub fn sys_write(fd: u32, buf_ptr: u32, count: u32) -> u32 {
    let fd_idx = fd as usize;
    let count = count as usize;

    if buf_ptr == 0 {
        return EFAULT;
    }

    // SAFETY: FD_TABLE is a static mut; addr_of! avoids an intermediate
    // reference. Single-core cooperative kernel ensures exclusive access.
    let table = unsafe { &*core::ptr::addr_of!(FD_TABLE) };
    let entry = match table.get(fd_idx) {
        Some(e) => *e,
        None => return EBADF,
    };

    let mount_idx = entry.mount_idx as usize;
    let inode_id = entry.inode_id;
    let offset = entry.offset as u64;

    // SAFETY: init_vfs has been called during kernel init.
    // Mutable access needed for write.
    let mt = match unsafe { get_mount_table_mut() } {
        Some(t) => t,
        None => return EBADF,
    };
    let fs = match mt.get_mut(mount_idx) {
        Some(f) => f,
        None => return EBADF,
    };

    // SAFETY: buf_ptr is a userspace pointer validated non-null above.
    let src = unsafe { core::slice::from_raw_parts(buf_ptr as *const u8, count) };

    match fs.write(inode_id, offset, src) {
        Ok(n) => {
            // Update offset in the fd entry
            let table = unsafe { &mut *core::ptr::addr_of_mut!(FD_TABLE) };
            if let Some(e) = table.get_mut(fd_idx) {
                e.offset += n;
            }
            n as u32
        }
        Err(e) => e.to_errno(),
    }
}

/// SYS_close: close an open file descriptor.
///
/// # Arguments
/// - `fd`: file descriptor number
///
/// # Returns
/// 0 on success, EBADF if fd is not open.
pub fn sys_close(fd: u32) -> u32 {
    let fd_idx = fd as usize;
    // SAFETY: FD_TABLE is a static mut; addr_of_mut! avoids an intermediate
    // reference. Single-core kernel ensures exclusive access during syscall.
    let table = unsafe { &mut *core::ptr::addr_of_mut!(FD_TABLE) };
    if table.close(fd_idx) {
        0
    } else {
        EBADF
    }
}

/// SYS_stat: get file status by path.
///
/// # Arguments
/// - `path_ptr`: userspace pointer to the path string
/// - `path_len`: length of the path string
/// - `stat_buf_ptr`: userspace pointer to a StatBuf
///
/// # Returns
/// 0 on success, negative error code on failure.
pub fn sys_stat(path_ptr: u32, path_len: u32, stat_buf_ptr: u32) -> u32 {
    let len = path_len as usize;

    if path_ptr == 0 || len == 0 {
        return ENOENT;
    }
    if stat_buf_ptr == 0 {
        return EFAULT;
    }

    // SAFETY: path_ptr is validated non-null above.
    let path_slice = unsafe { core::slice::from_raw_parts(path_ptr as *const u8, len) };
    let path = match core::str::from_utf8(path_slice) {
        Ok(s) => s,
        Err(_) => return EINVAL,
    };

    // SAFETY: init_vfs has been called during kernel init.
    let mt = match unsafe { get_mount_table() } {
        Some(t) => t,
        None => return ENOENT,
    };

    let (mount_idx, inode_id) = match vfs::resolve_path(mt, path) {
        Ok(r) => r,
        Err(_) => return ENOENT,
    };

    let fs = match mt.get(mount_idx) {
        Some(f) => f,
        None => return ENOENT,
    };

    let inode_stat = match fs.stat(inode_id) {
        Ok(s) => s,
        Err(e) => return e.to_errno(),
    };

    let file_type = match inode_stat.inode_type {
        InodeType::Directory => S_IFDIR,
        InodeType::CharDevice | InodeType::BlockDevice => S_IFCHR,
        _ => S_IFREG,
    };

    let stat = StatBuf {
        size: inode_stat.size as u32,
        file_type,
    };

    // SAFETY: stat_buf_ptr is validated non-null above.
    unsafe {
        let dst = stat_buf_ptr as *mut StatBuf;
        core::ptr::write(dst, stat);
    }

    0
}

/// SYS_fstat: get file status by file descriptor.
///
/// # Arguments
/// - `fd`: file descriptor number
/// - `stat_buf_ptr`: userspace pointer to a StatBuf
///
/// # Returns
/// 0 on success, negative error code on failure.
pub fn sys_fstat(fd: u32, stat_buf_ptr: u32) -> u32 {
    let fd_idx = fd as usize;

    if stat_buf_ptr == 0 {
        return EFAULT;
    }

    // SAFETY: FD_TABLE is a static mut.
    let table = unsafe { &*core::ptr::addr_of!(FD_TABLE) };
    let entry = match table.get(fd_idx) {
        Some(e) => *e,
        None => return EBADF,
    };

    // SAFETY: init_vfs has been called during kernel init.
    let mt = match unsafe { get_mount_table() } {
        Some(t) => t,
        None => {
            // Mount table not initialized — return minimal stat.
            let stat = StatBuf {
                size: 0,
                file_type: S_IFREG,
            };
            unsafe {
                let dst = stat_buf_ptr as *mut StatBuf;
                core::ptr::write(dst, stat);
            }
            return 0;
        }
    };
    let fs = match mt.get(entry.mount_idx as usize) {
        Some(f) => f,
        None => {
            // Pipe fd or no filesystem — return minimal stat
            let stat = StatBuf {
                size: 0,
                file_type: S_IFREG,
            };
            unsafe {
                let dst = stat_buf_ptr as *mut StatBuf;
                core::ptr::write(dst, stat);
            }
            return 0;
        }
    };

    let inode_stat = match fs.stat(entry.inode_id) {
        Ok(s) => s,
        Err(_) => {
            let stat = StatBuf {
                size: 0,
                file_type: S_IFREG,
            };
            unsafe {
                let dst = stat_buf_ptr as *mut StatBuf;
                core::ptr::write(dst, stat);
            }
            return 0;
        }
    };

    let file_type = match inode_stat.inode_type {
        InodeType::Directory => S_IFDIR,
        InodeType::CharDevice | InodeType::BlockDevice => S_IFCHR,
        _ => S_IFREG,
    };

    let stat = StatBuf {
        size: inode_stat.size as u32,
        file_type,
    };

    // SAFETY: stat_buf_ptr is validated non-null above.
    unsafe {
        let dst = stat_buf_ptr as *mut StatBuf;
        core::ptr::write(dst, stat);
    }

    0
}

/// SYS_lseek: reposition the file offset.
///
/// # Arguments
/// - `fd`: file descriptor number
/// - `offset`: offset value (interpreted based on whence)
/// - `whence`: SEEK_SET (0), SEEK_CUR (1), or SEEK_END (2)
///
/// # Returns
/// New file offset on success, negative error code on failure.
pub fn sys_lseek(fd: u32, offset: u32, whence: u32) -> u32 {
    let fd_idx = fd as usize;

    // SAFETY: FD_TABLE is a static mut.
    let table = unsafe { &mut *core::ptr::addr_of_mut!(FD_TABLE) };
    let entry = match table.get_mut(fd_idx) {
        Some(e) => e,
        None => return EBADF,
    };

    // WHY: offset is treated as signed (i32) for SEEK_CUR and SEEK_END.
    let offset_signed = offset as i32;
    let file_size = entry.size() as i32;

    let new_pos: i32 = match whence {
        SEEK_SET => offset_signed,
        SEEK_CUR => {
            let current = entry.offset as i32;
            current.saturating_add(offset_signed)
        }
        SEEK_END => file_size.saturating_add(offset_signed),
        _ => return EINVAL,
    };

    if new_pos < 0 {
        return EINVAL;
    }

    entry.offset = new_pos as usize;
    new_pos as u32
}

/// SYS_dup: duplicate a file descriptor.
///
/// # Arguments
/// - `fd`: file descriptor to duplicate
///
/// # Returns
/// New (lowest available) fd number on success, negative error code on failure.
pub fn sys_dup(fd: u32) -> u32 {
    let fd_idx = fd as usize;
    // SAFETY: FD_TABLE is a static mut.
    let table = unsafe { &mut *core::ptr::addr_of_mut!(FD_TABLE) };

    let entry = match table.get(fd_idx) {
        Some(e) => *e,
        None => return EBADF,
    };

    match table.alloc(entry) {
        Some(n) => n as u32,
        None => EMFILE,
    }
}

/// SYS_dup2: duplicate a file descriptor to a specific number.
///
/// # Arguments
/// - `oldfd`: source file descriptor
/// - `newfd`: target file descriptor number
///
/// # Returns
/// `newfd` on success, negative error code on failure.
pub fn sys_dup2(oldfd: u32, newfd: u32) -> u32 {
    let old_idx = oldfd as usize;
    let new_idx = newfd as usize;

    if new_idx >= MAX_FDS {
        return EBADF;
    }

    // SAFETY: FD_TABLE is a static mut.
    let table = unsafe { &mut *core::ptr::addr_of_mut!(FD_TABLE) };

    let entry = match table.get(old_idx) {
        Some(e) => *e,
        None => return EBADF,
    };

    if old_idx == new_idx {
        return newfd;
    }

    let _ = table.close(new_idx);

    if table.alloc_at(new_idx, entry) {
        newfd
    } else {
        EBADF
    }
}

/// SYS_getcwd: get current working directory.
///
/// # Arguments
/// - `buf_ptr`: userspace buffer
/// - `size`: buffer size
///
/// # Returns
/// 0 on success, negative error code on failure.
pub fn sys_getcwd(buf_ptr: u32, size: u32) -> u32 {
    if buf_ptr == 0 {
        return EFAULT;
    }

    // SAFETY: single-core cooperative kernel.
    let cwd = unsafe { get_cwd() };
    let cwd_bytes = cwd.as_bytes();

    // Need room for cwd + null terminator
    if (size as usize) < cwd_bytes.len() + 1 {
        return EINVAL;
    }

    // SAFETY: buf_ptr is validated non-null above; size is sufficient.
    unsafe {
        let dst = buf_ptr as *mut u8;
        core::ptr::copy_nonoverlapping(cwd_bytes.as_ptr(), dst, cwd_bytes.len());
        core::ptr::write(dst.add(cwd_bytes.len()), 0); // null terminator
    }

    0
}

/// SYS_mkdir: create a directory at the given path.
///
/// Resolves the parent directory from the path, then calls
/// `Filesystem::create()` with `InodeType::Directory`.
///
/// # Arguments
/// - `path_ptr`: userspace pointer to the path string
/// - `path_len`: length of the path string
///
/// # Returns
/// 0 on success, negative error code on failure.
pub fn sys_mkdir(path_ptr: u32, path_len: u32) -> u32 {
    let len = path_len as usize;

    if path_ptr == 0 || len == 0 {
        return EINVAL;
    }

    // SAFETY: path_ptr is validated non-null above.
    let path_slice = unsafe { core::slice::from_raw_parts(path_ptr as *const u8, len) };
    let path = match core::str::from_utf8(path_slice) {
        Ok(s) => s,
        Err(_) => return EINVAL,
    };

    vfs_mkdir(path)
}

/// Create a directory via VFS path resolution.
///
/// Splits the path into parent and final component, resolves the parent
/// directory, then creates the directory entry.
pub fn vfs_mkdir(path: &str) -> u32 {
    let (parent_path, name) = match split_parent_name(path) {
        Some(r) => r,
        None => return EINVAL,
    };

    // SAFETY: init_vfs has been called during kernel init.
    let mt = match unsafe { get_mount_table_mut() } {
        Some(t) => t,
        None => return VfsError::NotFound.to_errno(),
    };

    let (mount_idx, parent_inode) = match vfs::resolve_path(mt, parent_path) {
        Ok(r) => r,
        Err(e) => return e.to_errno(),
    };

    let fs = match mt.get_mut(mount_idx) {
        Some(f) => f,
        None => return VfsError::NotFound.to_errno(),
    };

    match fs.create(parent_inode, name, InodeType::Directory) {
        Ok(_) => 0,
        Err(e) => e.to_errno(),
    }
}

/// SYS_unlink: remove a file or directory entry.
///
/// # Arguments
/// - `path_ptr`: userspace pointer to the path string
/// - `path_len`: length of the path string
///
/// # Returns
/// 0 on success, negative error code on failure.
pub fn sys_unlink(path_ptr: u32, path_len: u32) -> u32 {
    let len = path_len as usize;

    if path_ptr == 0 || len == 0 {
        return EINVAL;
    }

    // SAFETY: path_ptr is validated non-null above.
    let path_slice = unsafe { core::slice::from_raw_parts(path_ptr as *const u8, len) };
    let path = match core::str::from_utf8(path_slice) {
        Ok(s) => s,
        Err(_) => return EINVAL,
    };

    vfs_unlink(path)
}

/// Remove a file or directory via VFS path resolution.
pub fn vfs_unlink(path: &str) -> u32 {
    let (parent_path, name) = match split_parent_name(path) {
        Some(r) => r,
        None => return EINVAL,
    };

    // SAFETY: init_vfs has been called during kernel init.
    let mt = match unsafe { get_mount_table_mut() } {
        Some(t) => t,
        None => return VfsError::NotFound.to_errno(),
    };

    let (mount_idx, parent_inode) = match vfs::resolve_path(mt, parent_path) {
        Ok(r) => r,
        Err(e) => return e.to_errno(),
    };

    let fs = match mt.get_mut(mount_idx) {
        Some(f) => f,
        None => return VfsError::NotFound.to_errno(),
    };

    match fs.unlink(parent_inode, name) {
        Ok(()) => 0,
        Err(e) => e.to_errno(),
    }
}

/// SYS_chdir: change the current working directory.
///
/// # Arguments
/// - `path_ptr`: userspace pointer to the path string
/// - `path_len`: length of the path string
///
/// # Returns
/// 0 on success, negative error code on failure.
pub fn sys_chdir(path_ptr: u32, path_len: u32) -> u32 {
    let len = path_len as usize;

    if path_ptr == 0 || len == 0 {
        return EINVAL;
    }

    // SAFETY: path_ptr is validated non-null above.
    let path_slice = unsafe { core::slice::from_raw_parts(path_ptr as *const u8, len) };
    let path = match core::str::from_utf8(path_slice) {
        Ok(s) => s,
        Err(_) => return EINVAL,
    };

    vfs_chdir(path)
}

/// Change the current working directory via VFS path resolution.
///
/// Verifies the path resolves to a directory, then updates the global CWD.
pub fn vfs_chdir(path: &str) -> u32 {
    // SAFETY: init_vfs has been called during kernel init.
    let mt = match unsafe { get_mount_table() } {
        Some(t) => t,
        None => return VfsError::NotFound.to_errno(),
    };

    let (mount_idx, inode_id) = match vfs::resolve_path(mt, path) {
        Ok(r) => r,
        Err(e) => return e.to_errno(),
    };

    let fs = match mt.get(mount_idx) {
        Some(f) => f,
        None => return VfsError::NotFound.to_errno(),
    };

    // Verify it's a directory
    match fs.stat(inode_id) {
        Ok(stat) if stat.inode_type == InodeType::Directory => {}
        Ok(_) => return VfsError::NotADirectory.to_errno(),
        Err(e) => return e.to_errno(),
    }

    // Update global CWD
    // SAFETY: single-core cooperative kernel.
    unsafe {
        set_cwd(path);
    }

    0
}

/// Split a path into (parent_path, final_component).
///
/// Returns `None` for paths without a valid split (empty, root-only).
fn split_parent_name(path: &str) -> Option<(&str, &str)> {
    if path.is_empty() || !path.starts_with('/') {
        return None;
    }

    // Find the last '/' that separates parent from name
    let path = path.strip_suffix('/').unwrap_or(path);

    match path.rfind('/') {
        Some(0) => {
            // Parent is root "/"
            let name = &path[1..];
            if name.is_empty() {
                None
            } else {
                Some(("/", name))
            }
        }
        Some(pos) => {
            let parent = &path[..pos];
            let name = &path[pos + 1..];
            if name.is_empty() {
                None
            } else {
                Some((parent, name))
            }
        }
        None => None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vfs::InodeType;

    /// Reset global state for test isolation.
    ///
    /// # Safety
    ///
    /// Test-only. Resets FD_TABLE and MOUNT_TABLE to clean state.
    unsafe fn setup_test_vfs() {
        unsafe {
            // Reset fd table
            let table = &mut *core::ptr::addr_of_mut!(FD_TABLE);
            *table = FdTable::new();

            // Reset mount table
            let mut mt = MountTable::new();

            // Mount a ramfs at root with test files
            let mut root_fs = crate::ramfs::RamFs::new();
            root_fs.add("test.txt", b"Hello, thumos!");
            root_fs.add("empty.dat", b"");
            root_fs.add("binary.bin", &[0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE]);
            let _ = mt.mount("/", Box::new(root_fs));

            // Mount devfs at /dev
            let devfs = crate::devfs::DevFs::new(42);
            let _ = mt.mount("/dev", Box::new(devfs));

            let mt_opt = &mut *core::ptr::addr_of_mut!(MOUNT_TABLE);
            *mt_opt = Some(mt);

            // Reset CWD to "/"
            set_cwd("/");
        }
    }

    // -- FdTable unit tests --

    #[test]
    fn alloc_returns_lowest_available() {
        let mut table = FdTable::new();
        let fd0 = table.alloc(FileDescriptor::from_vfs(0, 1, 0));
        let fd1 = table.alloc(FileDescriptor::from_vfs(0, 2, 0));
        assert_eq!(fd0, Some(0));
        assert_eq!(fd1, Some(1));
    }

    #[test]
    fn close_frees_slot_for_reuse() {
        let mut table = FdTable::new();
        let fd0 = table.alloc(FileDescriptor::from_vfs(0, 1, 0));
        assert_eq!(fd0, Some(0));

        assert!(table.close(0));

        // Next alloc should reuse slot 0
        let fd_reused = table.alloc(FileDescriptor::from_vfs(0, 1, 0));
        assert_eq!(fd_reused, Some(0));
    }

    #[test]
    fn close_invalid_fd_returns_false() {
        let mut table = FdTable::new();
        assert!(!table.close(0));
        assert!(!table.close(MAX_FDS));
        assert!(!table.close(999));
    }

    #[test]
    fn get_returns_none_for_closed_fd() {
        let table = FdTable::new();
        assert!(table.get(0).is_none());
        assert!(table.get(MAX_FDS).is_none());
    }

    #[test]
    fn alloc_at_overwrites_existing() {
        let mut table = FdTable::new();

        table.alloc(FileDescriptor::from_vfs(0, 1, 0)); // fd 0
        assert!(table.alloc_at(0, FileDescriptor::from_vfs(0, 2, 0)));

        let entry = table.get(0);
        assert!(entry.is_some());
        assert_eq!(entry.map(|e| e.inode_id), Some(2));
    }

    #[test]
    fn table_full_returns_none() {
        let mut table = FdTable::new();
        for _ in 0..MAX_FDS {
            assert!(table.alloc(FileDescriptor::from_vfs(0, 1, 0)).is_some());
        }
        // Table is full
        assert!(table.alloc(FileDescriptor::from_vfs(0, 1, 0)).is_none());
    }

    // -- VFS-backed syscall tests --

    // FIXME: gated on 32-bit pointer width — this test uses
    // `path.as_ptr() as u32` / `buf.as_mut_ptr() as u32` which is the
    // real kernel syscall ABI (ARMv7). On x86_64 host it truncates
    // 64-bit pointers and dereferences garbage. Revisit with
    // host-safe buffer helpers or leak-on-test heap allocations.
    #[cfg(target_pointer_width = "32")]
    #[test]
    fn open_existing_file() {
        // SAFETY: test-only; setup_test_vfs resets global state.
        unsafe {
            setup_test_vfs();
        }
        let path = b"/test.txt";
        let fd = sys_open(path.as_ptr() as u32, path.len() as u32, 0);
        assert_eq!(fd, 0, "first open should return fd 0");
    }

    // FIXME: gated on 32-bit pointer width — this test uses
    // `path.as_ptr() as u32` / `buf.as_mut_ptr() as u32` which is the
    // real kernel syscall ABI (ARMv7). On x86_64 host it truncates
    // 64-bit pointers and dereferences garbage. Revisit with
    // host-safe buffer helpers or leak-on-test heap allocations.
    #[cfg(target_pointer_width = "32")]
    #[test]
    fn open_nonexistent_file_returns_enoent() {
        // SAFETY: test-only.
        unsafe {
            setup_test_vfs();
        }
        let path = b"/no_such_file";
        let result = sys_open(path.as_ptr() as u32, path.len() as u32, 0);
        assert_eq!(result, ENOENT);
    }

    // FIXME: gated on 32-bit pointer width — this test uses
    // `path.as_ptr() as u32` / `buf.as_mut_ptr() as u32` which is the
    // real kernel syscall ABI (ARMv7). On x86_64 host it truncates
    // 64-bit pointers and dereferences garbage. Revisit with
    // host-safe buffer helpers or leak-on-test heap allocations.
    #[cfg(target_pointer_width = "32")]
    #[test]
    fn read_file_contents() {
        // SAFETY: test-only.
        unsafe {
            setup_test_vfs();
        }
        let path = b"/test.txt";
        let fd = sys_open(path.as_ptr() as u32, path.len() as u32, 0);
        assert_eq!(fd, 0);

        let mut buf = [0u8; 64];
        let bytes_read = sys_read(fd, buf.as_mut_ptr() as u32, 64);
        assert_eq!(bytes_read, 14); // "Hello, thumos!" is 14 bytes
        assert_eq!(&buf[..14], b"Hello, thumos!");
    }

    // FIXME: gated on 32-bit pointer width — this test uses
    // `path.as_ptr() as u32` / `buf.as_mut_ptr() as u32` which is the
    // real kernel syscall ABI (ARMv7). On x86_64 host it truncates
    // 64-bit pointers and dereferences garbage. Revisit with
    // host-safe buffer helpers or leak-on-test heap allocations.
    #[cfg(target_pointer_width = "32")]
    #[test]
    fn read_at_eof_returns_zero() {
        // SAFETY: test-only.
        unsafe {
            setup_test_vfs();
        }
        let path = b"/test.txt";
        let fd = sys_open(path.as_ptr() as u32, path.len() as u32, 0);

        let mut buf = [0u8; 64];
        let _ = sys_read(fd, buf.as_mut_ptr() as u32, 64);

        // Second read should return 0 (EOF)
        let bytes_read = sys_read(fd, buf.as_mut_ptr() as u32, 64);
        assert_eq!(bytes_read, 0, "read at EOF must return 0");
    }

    // FIXME: gated on 32-bit pointer width — this test uses
    // `path.as_ptr() as u32` / `buf.as_mut_ptr() as u32` which is the
    // real kernel syscall ABI (ARMv7). On x86_64 host it truncates
    // 64-bit pointers and dereferences garbage. Revisit with
    // host-safe buffer helpers or leak-on-test heap allocations.
    #[cfg(target_pointer_width = "32")]
    #[test]
    fn close_then_read_returns_ebadf() {
        // SAFETY: test-only.
        unsafe {
            setup_test_vfs();
        }
        let path = b"/test.txt";
        let fd = sys_open(path.as_ptr() as u32, path.len() as u32, 0);
        assert_eq!(sys_close(fd), 0);

        let mut buf = [0u8; 64];
        let result = sys_read(fd, buf.as_mut_ptr() as u32, 64);
        assert_eq!(result, EBADF, "read after close must return EBADF");
    }

    // FIXME: gated on 32-bit pointer width — this test uses
    // `path.as_ptr() as u32` / `buf.as_mut_ptr() as u32` which is the
    // real kernel syscall ABI (ARMv7). On x86_64 host it truncates
    // 64-bit pointers and dereferences garbage. Revisit with
    // host-safe buffer helpers or leak-on-test heap allocations.
    #[cfg(target_pointer_width = "32")]
    #[test]
    fn lseek_set_then_read() {
        // SAFETY: test-only.
        unsafe {
            setup_test_vfs();
        }
        let path = b"/test.txt";
        let fd = sys_open(path.as_ptr() as u32, path.len() as u32, 0);

        // Seek to offset 7 ("thumos!")
        let new_pos = sys_lseek(fd, 7, SEEK_SET);
        assert_eq!(new_pos, 7);

        let mut buf = [0u8; 32];
        let bytes_read = sys_read(fd, buf.as_mut_ptr() as u32, 32);
        assert_eq!(bytes_read, 7); // "thumos!" is 7 bytes
        assert_eq!(&buf[..7], b"thumos!");
    }

    // FIXME: gated on 32-bit pointer width — this test uses
    // `path.as_ptr() as u32` / `buf.as_mut_ptr() as u32` which is the
    // real kernel syscall ABI (ARMv7). On x86_64 host it truncates
    // 64-bit pointers and dereferences garbage. Revisit with
    // host-safe buffer helpers or leak-on-test heap allocations.
    #[cfg(target_pointer_width = "32")]
    #[test]
    fn lseek_end_positions_at_eof() {
        // SAFETY: test-only.
        unsafe {
            setup_test_vfs();
        }
        let path = b"/test.txt";
        let fd = sys_open(path.as_ptr() as u32, path.len() as u32, 0);

        let new_pos = sys_lseek(fd, 0, SEEK_END);
        assert_eq!(new_pos, 14);

        let mut buf = [0u8; 32];
        let bytes_read = sys_read(fd, buf.as_mut_ptr() as u32, 32);
        assert_eq!(bytes_read, 0, "read at EOF (via SEEK_END) must return 0");
    }

    // FIXME: gated on 32-bit pointer width — this test uses
    // `path.as_ptr() as u32` / `buf.as_mut_ptr() as u32` which is the
    // real kernel syscall ABI (ARMv7). On x86_64 host it truncates
    // 64-bit pointers and dereferences garbage. Revisit with
    // host-safe buffer helpers or leak-on-test heap allocations.
    #[cfg(target_pointer_width = "32")]
    #[test]
    fn dup_creates_independent_fd() {
        // SAFETY: test-only.
        unsafe {
            setup_test_vfs();
        }
        let path = b"/test.txt";
        let fd0 = sys_open(path.as_ptr() as u32, path.len() as u32, 0);
        assert_eq!(fd0, 0);

        let fd1 = sys_dup(fd0);
        assert_eq!(fd1, 1, "dup should return lowest available fd");

        // Read from fd0 — should not affect fd1's offset
        let mut buf = [0u8; 5];
        let _ = sys_read(fd0, buf.as_mut_ptr() as u32, 5);

        // fd1 should still read from offset 0
        let mut buf2 = [0u8; 5];
        let bytes = sys_read(fd1, buf2.as_mut_ptr() as u32, 5);
        assert_eq!(bytes, 5);
        assert_eq!(&buf2, b"Hello");
    }

    // FIXME: gated on 32-bit pointer width — this test uses
    // `path.as_ptr() as u32` / `buf.as_mut_ptr() as u32` which is the
    // real kernel syscall ABI (ARMv7). On x86_64 host it truncates
    // 64-bit pointers and dereferences garbage. Revisit with
    // host-safe buffer helpers or leak-on-test heap allocations.
    #[cfg(target_pointer_width = "32")]
    #[test]
    fn dup2_replaces_target_fd() {
        // SAFETY: test-only.
        unsafe {
            setup_test_vfs();
        }
        let path_a = b"/test.txt";
        let path_b = b"/binary.bin";
        let fd0 = sys_open(path_a.as_ptr() as u32, path_a.len() as u32, 0);
        let fd1 = sys_open(path_b.as_ptr() as u32, path_b.len() as u32, 0);
        assert_eq!(fd0, 0);
        assert_eq!(fd1, 1);

        let result = sys_dup2(fd0, fd1);
        assert_eq!(result, 1);

        let mut buf = [0u8; 5];
        let bytes = sys_read(1, buf.as_mut_ptr() as u32, 5);
        assert_eq!(bytes, 5);
        assert_eq!(&buf, b"Hello");
    }

    // FIXME: gated on 32-bit pointer width — this test uses
    // `path.as_ptr() as u32` / `buf.as_mut_ptr() as u32` which is the
    // real kernel syscall ABI (ARMv7). On x86_64 host it truncates
    // 64-bit pointers and dereferences garbage. Revisit with
    // host-safe buffer helpers or leak-on-test heap allocations.
    #[cfg(target_pointer_width = "32")]
    #[test]
    fn stat_existing_file() {
        // SAFETY: test-only.
        unsafe {
            setup_test_vfs();
        }
        let path = b"/test.txt";
        let mut stat = StatBuf {
            size: 0,
            file_type: 0,
        };
        let result = sys_stat(
            path.as_ptr() as u32,
            path.len() as u32,
            &mut stat as *mut StatBuf as u32,
        );
        assert_eq!(result, 0);
        assert_eq!(stat.size, 14);
        assert_eq!(stat.file_type, S_IFREG);
    }

    // FIXME: gated on 32-bit pointer width — this test uses
    // `path.as_ptr() as u32` / `buf.as_mut_ptr() as u32` which is the
    // real kernel syscall ABI (ARMv7). On x86_64 host it truncates
    // 64-bit pointers and dereferences garbage. Revisit with
    // host-safe buffer helpers or leak-on-test heap allocations.
    #[cfg(target_pointer_width = "32")]
    #[test]
    fn stat_nonexistent_returns_enoent() {
        // SAFETY: test-only.
        unsafe {
            setup_test_vfs();
        }
        let path = b"/nope";
        let mut stat = StatBuf {
            size: 0,
            file_type: 0,
        };
        let result = sys_stat(
            path.as_ptr() as u32,
            path.len() as u32,
            &mut stat as *mut StatBuf as u32,
        );
        assert_eq!(result, ENOENT);
    }

    // FIXME: gated on 32-bit pointer width — this test uses
    // `path.as_ptr() as u32` / `buf.as_mut_ptr() as u32` which is the
    // real kernel syscall ABI (ARMv7). On x86_64 host it truncates
    // 64-bit pointers and dereferences garbage. Revisit with
    // host-safe buffer helpers or leak-on-test heap allocations.
    #[cfg(target_pointer_width = "32")]
    #[test]
    fn fstat_open_fd() {
        // SAFETY: test-only.
        unsafe {
            setup_test_vfs();
        }
        let path = b"/binary.bin";
        let fd = sys_open(path.as_ptr() as u32, path.len() as u32, 0);
        assert_eq!(fd, 0);

        let mut stat = StatBuf {
            size: 0,
            file_type: 0,
        };
        let result = sys_fstat(fd, &mut stat as *mut StatBuf as u32);
        assert_eq!(result, 0);
        assert_eq!(stat.size, 6);
        assert_eq!(stat.file_type, S_IFREG);
    }

    #[test]
    fn fstat_closed_fd_returns_ebadf() {
        // SAFETY: test-only.
        unsafe {
            setup_test_vfs();
        }
        let mut stat = StatBuf {
            size: 0,
            file_type: 0,
        };
        let result = sys_fstat(99, &mut stat as *mut StatBuf as u32);
        assert_eq!(result, EBADF);
    }

    // FIXME: gated on 32-bit pointer width — this test uses
    // `path.as_ptr() as u32` / `buf.as_mut_ptr() as u32` which is the
    // real kernel syscall ABI (ARMv7). On x86_64 host it truncates
    // 64-bit pointers and dereferences garbage. Revisit with
    // host-safe buffer helpers or leak-on-test heap allocations.
    #[cfg(target_pointer_width = "32")]
    #[test]
    fn getcwd_returns_root() {
        // SAFETY: test-only.
        unsafe {
            setup_test_vfs();
        }
        let mut buf = [0u8; 16];
        let result = sys_getcwd(buf.as_mut_ptr() as u32, 16);
        assert_eq!(result, 0);
        assert_eq!(buf[0], b'/');
        assert_eq!(buf[1], 0);
    }

    // -- New VFS-specific tests --

    // FIXME: gated on 32-bit pointer width — this test uses
    // `path.as_ptr() as u32` / `buf.as_mut_ptr() as u32` which is the
    // real kernel syscall ABI (ARMv7). On x86_64 host it truncates
    // 64-bit pointers and dereferences garbage. Revisit with
    // host-safe buffer helpers or leak-on-test heap allocations.
    #[cfg(target_pointer_width = "32")]
    #[test]
    fn write_and_read_back_via_vfs() {
        // SAFETY: test-only.
        unsafe {
            setup_test_vfs();
        }

        // Create a new file by writing through VFS
        // First, use vfs_mkdir to create a directory, then create a file through the mount table
        let mt = unsafe { get_mount_table_mut() }.expect("mount table");
        let fs = mt.get_mut(0).expect("root fs");
        let file_id = fs
            .create(0, "new.txt", InodeType::RegularFile)
            .expect("create");
        fs.write(file_id, 0, b"written data").expect("write");

        // Open and read through syscall interface
        let path = b"/new.txt";
        let fd = sys_open(path.as_ptr() as u32, path.len() as u32, 0);
        assert!(fd < MAX_FDS as u32, "open should succeed");

        let mut buf = [0u8; 32];
        let read = sys_read(fd, buf.as_mut_ptr() as u32, 32);
        assert_eq!(read, 12);
        assert_eq!(&buf[..12], b"written data");
    }

    // FIXME: gated on 32-bit pointer width — this test uses
    // `path.as_ptr() as u32` / `buf.as_mut_ptr() as u32` which is the
    // real kernel syscall ABI (ARMv7). On x86_64 host it truncates
    // 64-bit pointers and dereferences garbage. Revisit with
    // host-safe buffer helpers or leak-on-test heap allocations.
    #[cfg(target_pointer_width = "32")]
    #[test]
    fn open_dev_null() {
        // SAFETY: test-only.
        unsafe {
            setup_test_vfs();
        }
        let path = b"/dev/null";
        let fd = sys_open(path.as_ptr() as u32, path.len() as u32, 0);
        assert!(fd < MAX_FDS as u32, "opening /dev/null should succeed");
    }

    // FIXME: gated on 32-bit pointer width — this test uses
    // `path.as_ptr() as u32` / `buf.as_mut_ptr() as u32` which is the
    // real kernel syscall ABI (ARMv7). On x86_64 host it truncates
    // 64-bit pointers and dereferences garbage. Revisit with
    // host-safe buffer helpers or leak-on-test heap allocations.
    #[cfg(target_pointer_width = "32")]
    #[test]
    fn mkdir_and_verify() {
        // SAFETY: test-only.
        unsafe {
            setup_test_vfs();
        }
        let result = vfs_mkdir("/mydir");
        assert_eq!(result, 0, "mkdir should succeed");

        // Stat should show directory
        let path = b"/mydir";
        let mut stat = StatBuf {
            size: 0,
            file_type: 0,
        };
        let r = sys_stat(
            path.as_ptr() as u32,
            path.len() as u32,
            &mut stat as *mut StatBuf as u32,
        );
        assert_eq!(r, 0);
        assert_eq!(stat.file_type, S_IFDIR);
    }

    // FIXME: gated on 32-bit pointer width — this test uses
    // `path.as_ptr() as u32` / `buf.as_mut_ptr() as u32` which is the
    // real kernel syscall ABI (ARMv7). On x86_64 host it truncates
    // 64-bit pointers and dereferences garbage. Revisit with
    // host-safe buffer helpers or leak-on-test heap allocations.
    #[cfg(target_pointer_width = "32")]
    #[test]
    fn unlink_file_via_vfs() {
        // SAFETY: test-only.
        unsafe {
            setup_test_vfs();
        }

        // Verify file exists
        let path = b"/test.txt";
        let fd = sys_open(path.as_ptr() as u32, path.len() as u32, 0);
        assert!(fd < MAX_FDS as u32, "file should exist before unlink");
        sys_close(fd);

        // Unlink it
        let result = vfs_unlink("/test.txt");
        assert_eq!(result, 0);

        // Should no longer be openable
        let fd2 = sys_open(path.as_ptr() as u32, path.len() as u32, 0);
        assert_eq!(fd2, ENOENT);
    }

    // FIXME: gated on 32-bit pointer width — this test uses
    // `path.as_ptr() as u32` / `buf.as_mut_ptr() as u32` which is the
    // real kernel syscall ABI (ARMv7). On x86_64 host it truncates
    // 64-bit pointers and dereferences garbage. Revisit with
    // host-safe buffer helpers or leak-on-test heap allocations.
    #[cfg(target_pointer_width = "32")]
    #[test]
    fn chdir_to_valid_directory() {
        // SAFETY: test-only.
        unsafe {
            setup_test_vfs();
        }

        // Create a directory first
        vfs_mkdir("/subdir");

        let result = vfs_chdir("/subdir");
        assert_eq!(result, 0);

        // getcwd should return "/subdir"
        let mut buf = [0u8; 32];
        sys_getcwd(buf.as_mut_ptr() as u32, 32);
        let cwd = core::str::from_utf8(&buf[..7]).expect("utf8");
        assert_eq!(cwd, "/subdir");
    }

    #[test]
    fn chdir_to_file_returns_not_a_directory() {
        // SAFETY: test-only.
        unsafe {
            setup_test_vfs();
        }

        let result = vfs_chdir("/test.txt");
        assert_ne!(result, 0, "chdir to a file should fail");
    }

    #[test]
    fn split_parent_name_basic() {
        assert_eq!(split_parent_name("/foo"), Some(("/", "foo")));
        assert_eq!(split_parent_name("/a/b"), Some(("/a", "b")));
        assert_eq!(split_parent_name("/a/b/c"), Some(("/a/b", "c")));
        assert!(split_parent_name("/").is_none());
        assert!(split_parent_name("").is_none());
        assert!(split_parent_name("relative").is_none());
    }

    #[test]
    fn init_vfs_mounts_three_filesystems() {
        // SAFETY: test-only.
        unsafe {
            let mt_opt = &mut *core::ptr::addr_of_mut!(MOUNT_TABLE);
            *mt_opt = None;
            let table = &mut *core::ptr::addr_of_mut!(FD_TABLE);
            *table = FdTable::new();

            init_vfs(None);

            // Should have root, /dev, /tmp mounted
            let mt = get_mount_table().expect("mount table should exist");
            assert!(mt.lookup("/").is_some(), "root should be mounted");
            assert!(mt.lookup("/dev").is_some(), "/dev should be mounted");
            assert!(mt.lookup("/tmp").is_some(), "/tmp should be mounted");
        }
    }
}
