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
use crate::memguard::validate_user_buffer;
use crate::vfs::{self, InodeType, MountTable, VfsError};

/// Maximum number of open file descriptors per process.
pub(crate) const MAX_FDS: usize = 256;

/// Maximum path length accepted from userspace for path-taking syscalls
/// (open/stat/mkdir/unlink/chdir), mirroring `sys_execve`'s bound. WHY: an
/// unbounded caller-supplied length drives an unbounded UTF-8 scan and VFS
/// path-resolve over the validated buffer — a CPU-time denial of service
/// from a single syscall, independent of whether the pointer range itself
/// is valid.
pub(crate) const MAX_PATH: usize = 256;

/// Error codes matching Linux ARM conventions (two's complement negation).
/// WHY: toolchain compatibility with userspace built against Linux headers.
pub(crate) const EBADF: u32 = 0u32.wrapping_sub(9);
/// No such file or directory.
pub(crate) const ENOENT: u32 = 0u32.wrapping_sub(2);
/// Too many open files.
pub(crate) const EMFILE: u32 = 0u32.wrapping_sub(24);
/// Invalid argument.
pub(crate) const EINVAL: u32 = 0u32.wrapping_sub(22);
/// Bad address.
pub(crate) const EFAULT: u32 = 0u32.wrapping_sub(14);
/// Is a directory.
pub(crate) const EISDIR: u32 = 0u32.wrapping_sub(21);
/// Inappropriate ioctl for device.
pub(crate) const ENOTTY: u32 = 0u32.wrapping_sub(25);

// -- fcntl command constants --

/// Duplicate fd to lowest available >= arg.
pub(crate) const F_DUPFD: u32 = 0;
/// Get file descriptor flags.
pub(crate) const F_GETFL: u32 = 3;
/// Set file descriptor flags.
pub(crate) const F_SETFL: u32 = 4;

// -- open flag constants --

/// Append mode flag.
pub(crate) const O_APPEND: u32 = 0x400;
/// Mask for access mode bits (O_RDONLY | O_WRONLY | O_RDWR).
/// WHY: these bits are immutable after open; F_SETFL must not modify them.
pub(crate) const O_ACCMODE: u32 = 0o3;

/// Seek whence constants (POSIX).
pub(crate) const SEEK_SET: u32 = 0;
/// Seek from current position.
pub(crate) const SEEK_CUR: u32 = 1;
/// Seek from end of file.
pub(crate) const SEEK_END: u32 = 2;

/// File type constants for StatBuf.
pub(crate) const S_IFREG: u32 = 0o100000;
/// Directory file type.
pub(crate) const S_IFDIR: u32 = 0o040000;
/// Character device file type.
pub(crate) const S_IFCHR: u32 = 0o020000;

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
///
/// TODO(#84)[deliberate-prudent]: close-on-exec flag (O_CLOEXEC) -- not tracked in current FileDescriptor
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
    pub(crate) fn from_vfs(mount_idx: u8, inode_id: u32, flags: u32) -> Self {
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
    pub(crate) fn new(_data: &[u8], flags: u32) -> Self {
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
    pub(crate) fn size(&self) -> usize {
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
pub(crate) struct FdTable {
    entries: [Option<FileDescriptor>; MAX_FDS],
}

impl FdTable {
    /// Create an empty fd table.
    pub(crate) const fn new() -> Self {
        const NONE: Option<FileDescriptor> = None;
        Self {
            entries: [NONE; MAX_FDS],
        }
    }

    /// Allocate the lowest available file descriptor slot.
    /// Returns the fd number, or None if the table is full.
    pub(crate) fn alloc(&mut self, fd: FileDescriptor) -> Option<usize> {
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
    pub(crate) fn alloc_at(&mut self, index: usize, fd: FileDescriptor) -> bool {
        if index >= MAX_FDS {
            return false;
        }
        self.entries[index] = Some(fd);
        true
    }

    /// Allocate the lowest available file descriptor slot >= `min_fd`.
    ///
    /// Used by `F_DUPFD` to duplicate an fd to a slot at or above a
    /// caller-specified minimum. Returns the fd number, or None if no
    /// slot is available at or above `min_fd`.
    pub(crate) fn alloc_from(&mut self, min_fd: usize, fd: FileDescriptor) -> Option<usize> {
        if min_fd >= MAX_FDS {
            return None;
        }
        for (i, slot) in self.entries[min_fd..].iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(fd);
                return Some(min_fd + i);
            }
        }
        None
    }

    /// Get a reference to a file descriptor by index.
    pub(crate) fn get(&self, index: usize) -> Option<&FileDescriptor> {
        if index >= MAX_FDS {
            return None;
        }
        self.entries[index].as_ref()
    }

    /// Get a mutable reference to a file descriptor by index.
    pub(crate) fn get_mut(&mut self, index: usize) -> Option<&mut FileDescriptor> {
        if index >= MAX_FDS {
            return None;
        }
        self.entries[index].as_mut()
    }

    /// Close a file descriptor. Returns true if it was open.
    pub(crate) fn close(&mut self, index: usize) -> bool {
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
/// TODO(#32)[deliberate-prudent]: migrate to per-process fd tables when Process struct supports it.
/// TODO(#84)[deliberate-prudent]: per-process fd tables -- current global table doesn't support concurrent processes
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
        let _ = mt.mount("/", Box::new(root_fs)); // WHY: init-time best-effort mount; failure is fatal and detected by later syscalls

        // /dev filesystem
        let devfs = crate::devfs::DevFs::new(0xDEAD_BEEF_CAFE_BABE);
        let _ = mt.mount("/dev", Box::new(devfs)); // WHY: init-time best-effort mount; failure is fatal and detected by later syscalls

        // /tmp filesystem (empty ramfs)
        let tmp_fs = crate::ramfs::RamFs::new();
        let _ = mt.mount("/tmp", Box::new(tmp_fs)); // WHY: init-time best-effort mount; failure is fatal and detected by later syscalls

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
                    let _ = mt.mount("/", Box::new(fs)); // WHY: legacy init shim; mount failure leaves table unpopulated and later syscalls fail
                }
            }
            None => {
                // init_vfs was never called; create a new mount table with just ramfs.
                let mut mt = MountTable::new();
                let _ = mt.mount("/", Box::new(fs)); // WHY: legacy init shim; mount failure leaves table unpopulated and later syscalls fail
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
pub(crate) fn sys_open(path_ptr: u32, path_len: u32, flags: u32) -> u32 {
    let len = path_len as usize;

    if path_ptr == 0 || len == 0 {
        return ENOENT;
    }
    if len > MAX_PATH {
        return ENOENT;
    }

    if !validate_user_buffer(path_ptr as usize, len) {
        return EFAULT;
    }

    // SAFETY: validate_user_buffer confirmed [path_ptr, path_ptr+len) lies
    // within user-accessible DRAM.
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
pub(crate) fn sys_read(fd: u32, buf_ptr: u32, count: u32) -> u32 {
    let fd_idx = fd as usize;
    let count = count as usize;

    if buf_ptr == 0 {
        return EFAULT;
    }
    // Validated ahead of the FD_TABLE/mount-table lookups below (an
    // early-reject, rather than right at the deref) so a bad buf_ptr is
    // rejected regardless of fd/mount state.
    if !validate_user_buffer(buf_ptr as usize, count) {
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

    // SAFETY: init_vfs has been called during kernel init. Mutable access is
    // required so devfs can serve /dev/urandom via Filesystem::read_mut()
    // (its PRNG needs &mut self); every other filesystem's read_mut()
    // defaults to its immutable read() (see vfs.rs).
    let mt = match unsafe { get_mount_table_mut() } {
        Some(t) => t,
        None => return EBADF,
    };
    let fs = match mt.get_mut(mount_idx) {
        Some(f) => f,
        None => return EBADF,
    };

    // SAFETY: buf_ptr + count validated by validate_user_buffer above
    // (before the FD_TABLE/mount-table lookups) to lie within
    // user-accessible DRAM.
    let dst = unsafe { core::slice::from_raw_parts_mut(buf_ptr as *mut u8, count) };

    match fs.read_mut(inode_id, offset, dst) {
        Ok(n) => {
            // Update offset in the fd entry. The fd was validated above, so
            // this is expected to be Some; guard defensively instead of
            // panicking (expect_used is denied in kernel code).
            if let Some(entry) =
                unsafe { &mut *core::ptr::addr_of_mut!(FD_TABLE) }.get_mut(fd_idx)
            {
                entry.offset += n;
            }
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
pub(crate) fn sys_write(fd: u32, buf_ptr: u32, count: u32) -> u32 {
    let fd_idx = fd as usize;
    let count = count as usize;

    if buf_ptr == 0 {
        return EFAULT;
    }
    // Validated ahead of the FD_TABLE/mount-table lookups below (an
    // early-reject, rather than right at the deref) so a bad buf_ptr is
    // rejected regardless of fd/mount state.
    if !validate_user_buffer(buf_ptr as usize, count) {
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

    // SAFETY: buf_ptr + count validated by validate_user_buffer above
    // (before the FD_TABLE/mount-table lookups) to lie within
    // user-accessible DRAM.
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
pub(crate) fn sys_close(fd: u32) -> u32 {
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
pub(crate) fn sys_stat(path_ptr: u32, path_len: u32, stat_buf_ptr: u32) -> u32 {
    let len = path_len as usize;

    if path_ptr == 0 || len == 0 {
        return ENOENT;
    }
    if len > MAX_PATH {
        return ENOENT;
    }
    if stat_buf_ptr == 0 {
        return EFAULT;
    }
    if !validate_user_buffer(path_ptr as usize, len)
        || !validate_user_buffer(stat_buf_ptr as usize, core::mem::size_of::<StatBuf>())
    {
        return EFAULT;
    }

    // SAFETY: validate_user_buffer confirmed [path_ptr, path_ptr+len) lies
    // within user-accessible DRAM.
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
pub(crate) fn sys_fstat(fd: u32, stat_buf_ptr: u32) -> u32 {
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

    // Validated once the fd is confirmed to exist — every return path below
    // (mount-absent, fs-absent, fs.stat() error, and success) writes through
    // stat_buf_ptr, so this one guard covers all four unsafe writes.
    if !validate_user_buffer(stat_buf_ptr as usize, core::mem::size_of::<StatBuf>()) {
        return EFAULT;
    }

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
pub(crate) fn sys_lseek(fd: u32, offset: u32, whence: u32) -> u32 {
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
pub(crate) fn sys_dup(fd: u32) -> u32 {
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
pub(crate) fn sys_dup2(oldfd: u32, newfd: u32) -> u32 {
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

    let _ = table.close(new_idx); // WHY: dup2 must close target fd before reuse; failure means it was already closed

    if table.alloc_at(new_idx, entry) {
        newfd
    } else {
        EBADF
    }
}

/// SYS_fcntl: file descriptor control.
///
/// Supports:
/// - `F_GETFL` (3): return the fd's flags.
/// - `F_SETFL` (4): set modifiable flags (only `O_APPEND`; access mode
///   bits are immutable after open).
/// - `F_DUPFD` (0): duplicate the fd to the lowest available slot >= `arg`.
///
/// # Arguments
/// - `fd`: file descriptor number
/// - `cmd`: fcntl command (F_DUPFD, F_GETFL, F_SETFL)
/// - `arg`: command-specific argument
///
/// # Returns
/// Command-dependent value on success, or negative error code.
pub(crate) fn sys_fcntl(fd: u32, cmd: u32, arg: u32) -> u32 {
    let fd_idx = fd as usize;

    match cmd {
        F_GETFL => {
            // SAFETY: FD_TABLE is a static mut; addr_of! avoids an
            // intermediate reference. Single-core cooperative kernel.
            let table = unsafe { &*core::ptr::addr_of!(FD_TABLE) };
            match table.get(fd_idx) {
                Some(e) => e.flags,
                None => EBADF,
            }
        }
        F_SETFL => {
            // SAFETY: FD_TABLE is a static mut; addr_of_mut! avoids an
            // intermediate reference.
            let table = unsafe { &mut *core::ptr::addr_of_mut!(FD_TABLE) };
            match table.get_mut(fd_idx) {
                Some(e) => {
                    // Preserve immutable access-mode bits; merge only
                    // modifiable bits (O_APPEND).
                    let preserved = e.flags & O_ACCMODE;
                    let modifiable = arg & O_APPEND;
                    e.flags = preserved | modifiable;
                    0
                }
                None => EBADF,
            }
        }
        F_DUPFD => {
            let min_fd = arg as usize;
            // SAFETY: FD_TABLE is a static mut.
            let table = unsafe { &mut *core::ptr::addr_of_mut!(FD_TABLE) };
            let entry = match table.get(fd_idx) {
                Some(e) => *e,
                None => return EBADF,
            };
            match table.alloc_from(min_fd, entry) {
                Some(n) => n as u32,
                None => EMFILE,
            }
        }
        _ => EINVAL,
    }
}

/// SYS_ioctl: device-specific control operations.
///
/// Currently returns `ENOTTY` for all file descriptors. This establishes
/// the dispatch path for future device-specific ioctl support.
///
/// # Arguments
/// - `fd`: file descriptor number
/// - `_request`: ioctl request code (ignored)
/// - `_arg`: request-specific argument (ignored)
///
/// # Returns
/// `ENOTTY` (no device supports ioctl yet), or `EBADF` for invalid fds.
pub(crate) fn sys_ioctl(fd: u32, _request: u32, _arg: u32) -> u32 {
    let fd_idx = fd as usize;

    // Validate fd exists before returning ENOTTY.
    // SAFETY: FD_TABLE is a static mut; addr_of! avoids an intermediate
    // reference.
    let table = unsafe { &*core::ptr::addr_of!(FD_TABLE) };
    match table.get(fd_idx) {
        Some(_) => ENOTTY,
        None => EBADF,
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
pub(crate) fn sys_getcwd(buf_ptr: u32, size: u32) -> u32 {
    if buf_ptr == 0 {
        return EFAULT;
    }
    if !validate_user_buffer(buf_ptr as usize, size as usize) {
        return EFAULT;
    }

    // SAFETY: single-core cooperative kernel.
    let cwd = unsafe { get_cwd() };
    let cwd_bytes = cwd.as_bytes();

    // Need room for cwd + null terminator
    if (size as usize) < cwd_bytes.len() + 1 {
        return EINVAL;
    }

    // SAFETY: validate_user_buffer confirmed [buf_ptr, buf_ptr+size) lies
    // within user-accessible DRAM; size is sufficient for cwd_bytes plus the
    // null terminator (checked above).
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
pub(crate) fn sys_mkdir(path_ptr: u32, path_len: u32) -> u32 {
    let len = path_len as usize;

    if path_ptr == 0 || len == 0 {
        return EINVAL;
    }
    if len > MAX_PATH {
        return ENOENT;
    }

    if !validate_user_buffer(path_ptr as usize, len) {
        return EFAULT;
    }

    // SAFETY: validate_user_buffer confirmed [path_ptr, path_ptr+len) lies
    // within user-accessible DRAM.
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
pub(crate) fn vfs_mkdir(path: &str) -> u32 {
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
pub(crate) fn sys_unlink(path_ptr: u32, path_len: u32) -> u32 {
    let len = path_len as usize;

    if path_ptr == 0 || len == 0 {
        return EINVAL;
    }
    if len > MAX_PATH {
        return ENOENT;
    }

    if !validate_user_buffer(path_ptr as usize, len) {
        return EFAULT;
    }

    // SAFETY: validate_user_buffer confirmed [path_ptr, path_ptr+len) lies
    // within user-accessible DRAM.
    let path_slice = unsafe { core::slice::from_raw_parts(path_ptr as *const u8, len) };
    let path = match core::str::from_utf8(path_slice) {
        Ok(s) => s,
        Err(_) => return EINVAL,
    };

    vfs_unlink(path)
}

/// Remove a file or directory via VFS path resolution.
pub(crate) fn vfs_unlink(path: &str) -> u32 {
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
pub(crate) fn sys_chdir(path_ptr: u32, path_len: u32) -> u32 {
    let len = path_len as usize;

    if path_ptr == 0 || len == 0 {
        return EINVAL;
    }
    if len > MAX_PATH {
        return ENOENT;
    }

    if !validate_user_buffer(path_ptr as usize, len) {
        return EFAULT;
    }

    // SAFETY: validate_user_buffer confirmed [path_ptr, path_ptr+len) lies
    // within user-accessible DRAM.
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
pub(crate) fn vfs_chdir(path: &str) -> u32 {
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

    // TODO(#129)[deliberate-prudent]: gated on 32-bit pointer width — this test uses
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

    // TODO(#129)[deliberate-prudent]: gated on 32-bit pointer width — this test uses
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

    // TODO(#129)[deliberate-prudent]: gated on 32-bit pointer width — this test uses
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

        // WHY function-local `static mut`: sys_read now validates buf_ptr via
        // validate_user_buffer before dereferencing it. This binary's PIE
        // image (hence any `static`) loads inside
        // [kconfig::KERNEL_END, kconfig::RAM_END) on this host toolchain;
        // a stack array does not (verified: glibc places the per-test-thread
        // stack near the top of the 32-bit address space, above RAM_END).
        static mut BUF: [u8; 64] = [0u8; 64];
        // SAFETY: test-only static; single-threaded per test.
        let buf = unsafe { &mut *core::ptr::addr_of_mut!(BUF) };
        let bytes_read = sys_read(fd, buf.as_mut_ptr() as u32, 64);
        assert_eq!(bytes_read, 14); // "Hello, thumos!" is 14 bytes
        assert_eq!(&buf[..14], b"Hello, thumos!");
    }

    // TODO(#129)[deliberate-prudent]: gated on 32-bit pointer width — this test uses
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

        static mut BUF: [u8; 64] = [0u8; 64];
        // SAFETY: test-only static; single-threaded per test.
        let buf = unsafe { &mut *core::ptr::addr_of_mut!(BUF) };
        let _ = sys_read(fd, buf.as_mut_ptr() as u32, 64);

        // Second read should return 0 (EOF)
        let bytes_read = sys_read(fd, buf.as_mut_ptr() as u32, 64);
        assert_eq!(bytes_read, 0, "read at EOF must return 0");
    }

    // TODO(#129)[deliberate-prudent]: gated on 32-bit pointer width — this test uses
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

        static mut BUF: [u8; 64] = [0u8; 64];
        // SAFETY: test-only static; single-threaded per test.
        let buf = unsafe { &mut *core::ptr::addr_of_mut!(BUF) };
        let result = sys_read(fd, buf.as_mut_ptr() as u32, 64);
        assert_eq!(result, EBADF, "read after close must return EBADF");
    }

    // TODO(#129)[deliberate-prudent]: gated on 32-bit pointer width — this test uses
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

        static mut BUF: [u8; 32] = [0u8; 32];
        // SAFETY: test-only static; single-threaded per test.
        let buf = unsafe { &mut *core::ptr::addr_of_mut!(BUF) };
        let bytes_read = sys_read(fd, buf.as_mut_ptr() as u32, 32);
        assert_eq!(bytes_read, 7); // "thumos!" is 7 bytes
        assert_eq!(&buf[..7], b"thumos!");
    }

    // TODO(#129)[deliberate-prudent]: gated on 32-bit pointer width — this test uses
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

        static mut BUF: [u8; 32] = [0u8; 32];
        // SAFETY: test-only static; single-threaded per test.
        let buf = unsafe { &mut *core::ptr::addr_of_mut!(BUF) };
        let bytes_read = sys_read(fd, buf.as_mut_ptr() as u32, 32);
        assert_eq!(bytes_read, 0, "read at EOF (via SEEK_END) must return 0");
    }

    // TODO(#129)[deliberate-prudent]: gated on 32-bit pointer width — this test uses
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
        static mut BUF: [u8; 5] = [0u8; 5];
        // SAFETY: test-only static; single-threaded per test.
        let buf = unsafe { &mut *core::ptr::addr_of_mut!(BUF) };
        let _ = sys_read(fd0, buf.as_mut_ptr() as u32, 5);

        // fd1 should still read from offset 0
        static mut BUF2: [u8; 5] = [0u8; 5];
        // SAFETY: test-only static; single-threaded per test.
        let buf2 = unsafe { &mut *core::ptr::addr_of_mut!(BUF2) };
        let bytes = sys_read(fd1, buf2.as_mut_ptr() as u32, 5);
        assert_eq!(bytes, 5);
        assert_eq!(&*buf2, b"Hello");
    }

    // TODO(#129)[deliberate-prudent]: gated on 32-bit pointer width — this test uses
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

        static mut BUF: [u8; 5] = [0u8; 5];
        // SAFETY: test-only static; single-threaded per test.
        let buf = unsafe { &mut *core::ptr::addr_of_mut!(BUF) };
        let bytes = sys_read(1, buf.as_mut_ptr() as u32, 5);
        assert_eq!(bytes, 5);
        assert_eq!(&*buf, b"Hello");
    }

    // TODO(#129)[deliberate-prudent]: gated on 32-bit pointer width — this test uses
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
        static mut STAT: StatBuf = StatBuf {
            size: 0,
            file_type: 0,
        };
        // SAFETY: test-only static; single-threaded per test.
        let stat = unsafe { &mut *core::ptr::addr_of_mut!(STAT) };
        let result = sys_stat(
            path.as_ptr() as u32,
            path.len() as u32,
            stat as *mut StatBuf as u32,
        );
        assert_eq!(result, 0);
        assert_eq!(stat.size, 14);
        assert_eq!(stat.file_type, S_IFREG);
    }

    // TODO(#129)[deliberate-prudent]: gated on 32-bit pointer width — this test uses
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
        static mut STAT: StatBuf = StatBuf {
            size: 0,
            file_type: 0,
        };
        // SAFETY: test-only static; single-threaded per test.
        let stat = unsafe { &mut *core::ptr::addr_of_mut!(STAT) };
        let result = sys_stat(
            path.as_ptr() as u32,
            path.len() as u32,
            stat as *mut StatBuf as u32,
        );
        assert_eq!(result, ENOENT);
    }

    // TODO(#129)[deliberate-prudent]: gated on 32-bit pointer width — this test uses
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

        static mut STAT: StatBuf = StatBuf {
            size: 0,
            file_type: 0,
        };
        // SAFETY: test-only static; single-threaded per test.
        let stat = unsafe { &mut *core::ptr::addr_of_mut!(STAT) };
        let result = sys_fstat(fd, stat as *mut StatBuf as u32);
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
        static mut STAT: StatBuf = StatBuf {
            size: 0,
            file_type: 0,
        };
        // SAFETY: test-only static; single-threaded per test.
        let stat = unsafe { &mut *core::ptr::addr_of_mut!(STAT) };
        let result = sys_fstat(99, stat as *mut StatBuf as u32);
        assert_eq!(result, EBADF);
    }

    // TODO(#129)[deliberate-prudent]: gated on 32-bit pointer width — this test uses
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
        static mut BUF: [u8; 16] = [0u8; 16];
        // SAFETY: test-only static; single-threaded per test.
        let buf = unsafe { &mut *core::ptr::addr_of_mut!(BUF) };
        let result = sys_getcwd(buf.as_mut_ptr() as u32, 16);
        assert_eq!(result, 0);
        assert_eq!(buf[0], b'/');
        assert_eq!(buf[1], 0);
    }

    // -- New VFS-specific tests --

    // TODO(#129)[deliberate-prudent]: gated on 32-bit pointer width — this test uses
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

        static mut BUF: [u8; 32] = [0u8; 32];
        // SAFETY: test-only static; single-threaded per test.
        let buf = unsafe { &mut *core::ptr::addr_of_mut!(BUF) };
        let read = sys_read(fd, buf.as_mut_ptr() as u32, 32);
        assert_eq!(read, 12);
        assert_eq!(&buf[..12], b"written data");
    }

    // TODO(#129)[deliberate-prudent]: gated on 32-bit pointer width — this test uses
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

    // TODO(#129)[deliberate-prudent]: gated on 32-bit pointer width — this test uses
    // `path.as_ptr() as u32` / `buf.as_mut_ptr() as u32` which is the
    // real kernel syscall ABI (ARMv7). On x86_64 host it truncates
    // 64-bit pointers and dereferences garbage. Revisit with
    // host-safe buffer helpers or leak-on-test heap allocations.
    #[cfg(target_pointer_width = "32")]
    #[test]
    fn read_dev_urandom_returns_random_bytes() {
        // SAFETY: test-only.
        unsafe {
            setup_test_vfs();
        }
        let path = b"/dev/urandom";
        let fd = sys_open(path.as_ptr() as u32, path.len() as u32, 0);
        assert!(fd < MAX_FDS as u32, "opening /dev/urandom should succeed");

        static mut BUF: [u8; 32] = [0u8; 32];
        // SAFETY: test-only static; single-threaded per test.
        let buf = unsafe { &mut *core::ptr::addr_of_mut!(BUF) };
        let read = sys_read(fd, buf.as_mut_ptr() as u32, 32);
        assert_eq!(read, 32, "sys_read on /dev/urandom must fill the buffer, not return an errno");
        assert!(
            buf.iter().any(|&b| b != 0),
            "sys_read on /dev/urandom must return real entropy, not silently-zeroed/garbage data"
        );
    }

    // TODO(#129)[deliberate-prudent]: gated on 32-bit pointer width — this test uses
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
        static mut STAT: StatBuf = StatBuf {
            size: 0,
            file_type: 0,
        };
        // SAFETY: test-only static; single-threaded per test.
        let stat = unsafe { &mut *core::ptr::addr_of_mut!(STAT) };
        let r = sys_stat(
            path.as_ptr() as u32,
            path.len() as u32,
            stat as *mut StatBuf as u32,
        );
        assert_eq!(r, 0);
        assert_eq!(stat.file_type, S_IFDIR);
    }

    // TODO(#129)[deliberate-prudent]: gated on 32-bit pointer width — this test uses
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

    // TODO(#129)[deliberate-prudent]: gated on 32-bit pointer width — this test uses
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
        static mut BUF: [u8; 32] = [0u8; 32];
        // SAFETY: test-only static; single-threaded per test.
        let buf = unsafe { &mut *core::ptr::addr_of_mut!(BUF) };
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

    // -- fcntl tests --
    // WHY no pointer-width gate: sys_fcntl takes u32 fd/cmd/arg — no
    // pointers — so it works identically on 32-bit ARM and 64-bit host.

    #[test]
    fn fcntl_getfl_returns_flags() {
        // SAFETY: test-only; setup_test_vfs resets global state.
        unsafe { setup_test_vfs(); }

        // Open a file via internal APIs (avoids pointer truncation).
        let table = unsafe { &mut *core::ptr::addr_of_mut!(FD_TABLE) };
        let fd_num = table
            .alloc(FileDescriptor::from_vfs(0, 1, O_APPEND))
            .expect("alloc fd") as u32;

        let result = sys_fcntl(fd_num, F_GETFL, 0);
        assert_eq!(result, O_APPEND, "F_GETFL must return the fd's flags");
    }

    #[test]
    fn fcntl_setfl_sets_append() {
        unsafe { setup_test_vfs(); }

        let table = unsafe { &mut *core::ptr::addr_of_mut!(FD_TABLE) };
        let fd_num = table
            .alloc(FileDescriptor::from_vfs(0, 1, 0))
            .expect("alloc fd") as u32;

        // Set O_APPEND
        let set_result = sys_fcntl(fd_num, F_SETFL, O_APPEND);
        assert_eq!(set_result, 0, "F_SETFL should succeed");

        // Verify via F_GETFL
        let flags = sys_fcntl(fd_num, F_GETFL, 0);
        assert_eq!(
            flags & O_APPEND,
            O_APPEND,
            "O_APPEND must be set after F_SETFL"
        );
    }

    #[test]
    fn fcntl_setfl_preserves_accmode() {
        unsafe { setup_test_vfs(); }

        // Open with access mode bits set (O_RDWR = 2)
        let table = unsafe { &mut *core::ptr::addr_of_mut!(FD_TABLE) };
        let fd_num = table
            .alloc(FileDescriptor::from_vfs(0, 1, 2)) // O_RDWR
            .expect("alloc fd") as u32;

        // Set O_APPEND — access mode must be preserved
        sys_fcntl(fd_num, F_SETFL, O_APPEND);
        let flags = sys_fcntl(fd_num, F_GETFL, 0);
        assert_eq!(
            flags & O_ACCMODE,
            2,
            "access mode bits must be preserved by F_SETFL"
        );
        assert_eq!(
            flags & O_APPEND,
            O_APPEND,
            "O_APPEND must be set"
        );
    }

    #[test]
    fn fcntl_dupfd_duplicates_above_arg() {
        unsafe { setup_test_vfs(); }

        // Allocate fd 0
        let table = unsafe { &mut *core::ptr::addr_of_mut!(FD_TABLE) };
        let fd_num = table
            .alloc(FileDescriptor::from_vfs(0, 1, 0))
            .expect("alloc fd") as u32;
        assert_eq!(fd_num, 0);

        // F_DUPFD with arg=5 — new fd must be >= 5
        let new_fd = sys_fcntl(fd_num, F_DUPFD, 5);
        assert!(
            new_fd >= 5 && new_fd < MAX_FDS as u32,
            "F_DUPFD(5) returned {new_fd}, expected >= 5"
        );

        // Verify the new fd points to the same inode
        let table = unsafe { &*core::ptr::addr_of!(FD_TABLE) };
        let orig = table.get(fd_num as usize).expect("original fd");
        let duped = table.get(new_fd as usize).expect("duped fd");
        assert_eq!(orig.inode_id, duped.inode_id, "duped fd must reference same inode");
        assert_eq!(orig.mount_idx, duped.mount_idx, "duped fd must reference same mount");
    }

    #[test]
    fn fcntl_dupfd_returns_emfile_when_full() {
        unsafe { setup_test_vfs(); }

        // Fill fd table
        let table = unsafe { &mut *core::ptr::addr_of_mut!(FD_TABLE) };
        for _ in 0..MAX_FDS {
            table.alloc(FileDescriptor::from_vfs(0, 1, 0));
        }

        // F_DUPFD should fail with EMFILE
        let result = sys_fcntl(0, F_DUPFD, 0);
        assert_eq!(result, EMFILE, "F_DUPFD on full table must return EMFILE");
    }

    #[test]
    fn fcntl_invalid_cmd_returns_einval() {
        unsafe { setup_test_vfs(); }

        let table = unsafe { &mut *core::ptr::addr_of_mut!(FD_TABLE) };
        table.alloc(FileDescriptor::from_vfs(0, 1, 0));

        let result = sys_fcntl(0, 99, 0);
        assert_eq!(result, EINVAL, "unknown fcntl command must return EINVAL");
    }

    #[test]
    fn fcntl_bad_fd_returns_ebadf() {
        unsafe { setup_test_vfs(); }

        assert_eq!(sys_fcntl(99, F_GETFL, 0), EBADF);
        assert_eq!(sys_fcntl(99, F_SETFL, 0), EBADF);
        assert_eq!(sys_fcntl(99, F_DUPFD, 0), EBADF);
    }

    // -- ioctl tests --

    #[test]
    fn ioctl_returns_enotty() {
        unsafe { setup_test_vfs(); }

        // Allocate a regular file fd
        let table = unsafe { &mut *core::ptr::addr_of_mut!(FD_TABLE) };
        let fd_num = table
            .alloc(FileDescriptor::from_vfs(0, 1, 0))
            .expect("alloc fd") as u32;

        let result = sys_ioctl(fd_num, 0, 0);
        assert_eq!(result, ENOTTY, "ioctl on a file fd must return ENOTTY");
    }

    #[test]
    fn ioctl_bad_fd_returns_ebadf() {
        unsafe { setup_test_vfs(); }

        let result = sys_ioctl(99, 0, 0);
        assert_eq!(result, EBADF, "ioctl on invalid fd must return EBADF");
    }

    #[test]
    fn ioctl_devfs_returns_enotty() {
        unsafe { setup_test_vfs(); }

        // Open a devfs file via internal APIs — devfs is mount index 1
        let table = unsafe { &mut *core::ptr::addr_of_mut!(FD_TABLE) };
        let fd_num = table
            .alloc(FileDescriptor::from_vfs(1, 0, 0))
            .expect("alloc fd") as u32;

        let result = sys_ioctl(fd_num, 0x5401, 0); // TCGETS
        assert_eq!(result, ENOTTY, "ioctl on devfs fd must return ENOTTY");
    }

    // -- sys_write file dispatch test --

    #[cfg(target_pointer_width = "32")]
    #[test]
    fn write_dispatches_to_vfs_for_file_fds() {
        unsafe { setup_test_vfs(); }

        // Create a file through VFS, open it, write through sys_write
        let mt = unsafe { get_mount_table_mut() }.expect("mount table");
        let fs = mt.get_mut(0).expect("root fs");
        let file_id = fs
            .create(0, "writable.txt", InodeType::RegularFile)
            .expect("create");
        drop(fs);

        let path = b"/writable.txt";
        let fd = sys_open(path.as_ptr() as u32, path.len() as u32, 0);
        assert!(fd < MAX_FDS as u32, "open should succeed");

        let data = b"test write data";
        let written = sys_write(fd, data.as_ptr() as u32, data.len() as u32);
        assert_eq!(written, data.len() as u32, "sys_write should write all bytes");

        // Read back
        let _ = sys_lseek(fd, 0, SEEK_SET);
        static mut BUF: [u8; 32] = [0u8; 32];
        // SAFETY: test-only static; single-threaded per test.
        let buf = unsafe { &mut *core::ptr::addr_of_mut!(BUF) };
        let read = sys_read(fd, buf.as_mut_ptr() as u32, 32);
        assert_eq!(read, data.len() as u32);
        assert_eq!(&buf[..data.len()], data);
    }

    // -- alloc_from tests --

    #[test]
    fn alloc_from_returns_at_or_above_min() {
        let mut table = FdTable::new();
        // Fill fds 0-4
        for _ in 0..5 {
            table.alloc(FileDescriptor::from_vfs(0, 1, 0));
        }
        let fd = table.alloc_from(3, FileDescriptor::from_vfs(0, 2, 0));
        assert_eq!(fd, Some(5), "alloc_from(3) with 0-4 taken should return 5");
    }

    #[test]
    fn alloc_from_uses_exact_min_if_available() {
        let mut table = FdTable::new();
        let fd = table.alloc_from(10, FileDescriptor::from_vfs(0, 1, 0));
        assert_eq!(fd, Some(10), "alloc_from(10) on empty table should return 10");
    }

    #[test]
    fn alloc_from_max_fds_returns_none() {
        let mut table = FdTable::new();
        let fd = table.alloc_from(MAX_FDS, FileDescriptor::from_vfs(0, 1, 0));
        assert_eq!(fd, None, "alloc_from(MAX_FDS) must return None");
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

    // -- User pointer validation (#223) --
    //
    // Every case here is rejected before any pointer is dereferenced, so
    // these tests are host-safe and pointer-width-independent (unlike the
    // VFS-backed tests above, gated #[cfg(target_pointer_width = "32")] per
    // #129). validate_user_buffer's own null/overflow/boundary behavior is
    // covered by memguard's tests; these confirm each fd-layer entry point
    // actually calls it.

    /// A non-null, in-range address used as the "already valid" side of a
    // two-argument validate_user_buffer check — the other (deliberately
    // bad) argument's rejection short-circuits before either pointer would
    // be dereferenced.
    const IN_RANGE_UNBACKED_PTR: u32 = 0x5000_0000;

    #[test]
    fn sys_open_rejects_oversized_path_len() {
        // Rejected by the MAX_PATH cap before any slice is built or
        // validate_user_buffer is consulted — path_ptr is a plausible
        // in-range value so this isolates the length check.
        let result = sys_open(IN_RANGE_UNBACKED_PTR, u32::MAX, 0);
        assert_eq!(result, ENOENT, "path_len > MAX_PATH must return ENOENT before any slice is built");
    }

    #[test]
    fn sys_mkdir_rejects_oversized_path_len() {
        let result = sys_mkdir(IN_RANGE_UNBACKED_PTR, u32::MAX);
        assert_eq!(result, ENOENT, "path_len > MAX_PATH must return ENOENT before any slice is built");
    }

    #[test]
    fn sys_open_rejects_kernel_range_path_ptr() {
        let kernel_ptr = crate::kconfig::KERNEL_LOAD as u32;
        let result = sys_open(kernel_ptr, 4, 0);
        assert_eq!(result, EFAULT, "kernel-range path_ptr must return EFAULT");
    }

    #[test]
    fn sys_read_rejects_kernel_range_buf_ptr() {
        let kernel_ptr = crate::kconfig::KERNEL_LOAD as u32;
        let result = sys_read(99, kernel_ptr, 4);
        assert_eq!(result, EFAULT, "kernel-range buf_ptr must return EFAULT");
    }

    #[test]
    fn sys_write_rejects_kernel_range_buf_ptr() {
        let kernel_ptr = crate::kconfig::KERNEL_LOAD as u32;
        let result = sys_write(99, kernel_ptr, 4);
        assert_eq!(result, EFAULT, "kernel-range buf_ptr must return EFAULT");
    }

    #[test]
    fn sys_stat_rejects_kernel_range_path_ptr() {
        let kernel_ptr = crate::kconfig::KERNEL_LOAD as u32;
        let result = sys_stat(kernel_ptr, 4, IN_RANGE_UNBACKED_PTR);
        assert_eq!(result, EFAULT, "kernel-range path_ptr must return EFAULT");
    }

    #[test]
    fn sys_stat_rejects_kernel_range_stat_buf_ptr() {
        let kernel_ptr = crate::kconfig::KERNEL_LOAD as u32;
        let result = sys_stat(IN_RANGE_UNBACKED_PTR, 4, kernel_ptr);
        assert_eq!(result, EFAULT, "kernel-range stat_buf_ptr must return EFAULT");
    }

    #[test]
    fn sys_fstat_rejects_kernel_range_stat_buf_ptr() {
        // SAFETY: test-only; FD_TABLE reset/alloc is a plain array write.
        let fd = unsafe {
            let table = &mut *core::ptr::addr_of_mut!(FD_TABLE);
            *table = FdTable::new();
            table
                .alloc(FileDescriptor::from_vfs(0, 1, 0))
                .expect("alloc fd") as u32
        };

        let kernel_ptr = crate::kconfig::KERNEL_LOAD as u32;
        let result = sys_fstat(fd, kernel_ptr);
        assert_eq!(result, EFAULT, "kernel-range stat_buf_ptr must return EFAULT");
    }

    #[test]
    fn sys_getcwd_rejects_kernel_range_buf_ptr() {
        let kernel_ptr = crate::kconfig::KERNEL_LOAD as u32;
        let result = sys_getcwd(kernel_ptr, 32);
        assert_eq!(result, EFAULT, "kernel-range buf_ptr must return EFAULT");
    }

    #[test]
    fn sys_mkdir_rejects_kernel_range_path_ptr() {
        let kernel_ptr = crate::kconfig::KERNEL_LOAD as u32;
        let result = sys_mkdir(kernel_ptr, 4);
        assert_eq!(result, EFAULT, "kernel-range path_ptr must return EFAULT");
    }

    #[test]
    fn sys_unlink_rejects_kernel_range_path_ptr() {
        let kernel_ptr = crate::kconfig::KERNEL_LOAD as u32;
        let result = sys_unlink(kernel_ptr, 4);
        assert_eq!(result, EFAULT, "kernel-range path_ptr must return EFAULT");
    }

    #[test]
    fn sys_chdir_rejects_kernel_range_path_ptr() {
        let kernel_ptr = crate::kconfig::KERNEL_LOAD as u32;
        let result = sys_chdir(kernel_ptr, 4);
        assert_eq!(result, EFAULT, "kernel-range path_ptr must return EFAULT");
    }
}
