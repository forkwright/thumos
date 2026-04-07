//! File descriptor table for per-process open file tracking.
//!
//! Each open file descriptor holds a reference to a ramfs file entry
//! (pointer + length), a read offset, and flags. The table is a
//! fixed-size array per process, with methods to allocate, look up,
//! and release entries.
//!
//! WHY fixed-size: avoids heap allocation in the fd table itself, keeps
//! the structure predictable for a bare-metal kernel. 64 entries is
//! sufficient for an early userspace (BusyBox shell + init).

/// Maximum number of open file descriptors per process.
pub const MAX_FDS: usize = 64;

/// Error codes matching Linux ARM conventions (two's complement negation).
/// WHY: toolchain compatibility with userspace built against Linux headers.
pub const EBADF: u32 = 0u32.wrapping_sub(9);
pub const ENOENT: u32 = 0u32.wrapping_sub(2);
pub const EMFILE: u32 = 0u32.wrapping_sub(24);
pub const EINVAL: u32 = 0u32.wrapping_sub(22);
pub const EFAULT: u32 = 0u32.wrapping_sub(14);

/// Seek whence constants (POSIX).
pub const SEEK_SET: u32 = 0;
pub const SEEK_CUR: u32 = 1;
pub const SEEK_END: u32 = 2;

/// File type constants for StatBuf.
pub const S_IFREG: u32 = 0o100000;

/// Stat buffer written to userspace.
/// WHY: minimal struct — size and type are the only metadata the ramfs
/// tracks. Extended fields (mode, uid, timestamps) are future work.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct StatBuf {
    /// File size in bytes.
    pub size: u32,
    /// File type (S_IFREG for regular files).
    pub file_type: u32,
}

/// A single open file descriptor.
///
/// Holds a raw pointer to the ramfs file data and its length.
/// WHY raw pointer: the ramfs data is `'static` (lives for the kernel's
/// lifetime), but Rust's borrow checker cannot express that through the
/// `unsafe static mut RAMFS` indirection. The pointer is valid as long
/// as the ramfs is not dropped, which is never.
#[derive(Clone, Copy)]
pub struct FileDescriptor {
    /// Pointer to the start of file data in the ramfs.
    data_ptr: *const u8,
    /// Length of the file data.
    data_len: usize,
    /// Current read offset within the file.
    pub offset: usize,
    /// Open flags (reserved for future use: O_RDONLY, O_WRONLY, etc.).
    pub flags: u32,
}

impl FileDescriptor {
    /// Create a new file descriptor referencing ramfs data.
    ///
    /// # Safety
    ///
    /// `data` must point to memory that remains valid for the lifetime
    /// of this descriptor (i.e., the ramfs backing store).
    pub fn new(data: &[u8], flags: u32) -> Self {
        Self {
            data_ptr: data.as_ptr(),
            data_len: data.len(),
            offset: 0,
            flags,
        }
    }

    /// Get the file data as a byte slice.
    ///
    /// # Safety
    ///
    /// The caller must ensure the underlying ramfs data has not been freed.
    /// In practice this is always true because the ramfs is never dropped.
    pub unsafe fn data(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.data_ptr, self.data_len) }
    }

    /// File size in bytes.
    pub fn size(&self) -> usize {
        self.data_len
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
static mut FD_TABLE: FdTable = FdTable::new();

/// Global ramfs instance.
///
/// WHY: syscalls need access to the filesystem to resolve paths. The ramfs
/// is populated during boot (kinit) and never modified afterward. A global
/// reference avoids threading the ramfs through every syscall dispatch.
static mut RAMFS: Option<crate::ramfs::RamFs> = None;

/// Initialize the global ramfs for syscall use.
///
/// # Safety
///
/// Must be called once during kernel init, before any filesystem syscalls.
/// The provided `RamFs` is moved into the global and must not be accessed
/// from the caller afterward.
pub unsafe fn init_ramfs(fs: crate::ramfs::RamFs) {
    unsafe {
        let ramfs = &mut *core::ptr::addr_of_mut!(RAMFS);
        *ramfs = Some(fs);
    }
}

/// Look up a file in the global ramfs by path.
/// Returns a slice of the file data, or None if not found.
///
/// # Safety
///
/// Caller must ensure `init_ramfs` has been called.
pub unsafe fn ramfs_find(path: &str) -> Option<&'static [u8]> {
    unsafe {
        let ramfs = &*core::ptr::addr_of!(RAMFS);
        let fs = ramfs.as_ref()?;
        // WHY: the ramfs data lives in heap-allocated Vecs that are never freed
        // (the global RAMFS is never dropped). We transmute the lifetime to
        // 'static because the data genuinely outlives any fd that references it.
        fs.find(path).map(|data| core::mem::transmute::<&[u8], &'static [u8]>(data))
    }
}

// -- Syscall implementation functions --
// WHY: separated from dispatch() to keep syscall.rs focused on routing.
// Each function takes raw u32 args and returns a u32 result, matching
// the syscall ABI.

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

    // TODO(#0): Wave 4 adds proper userspace address validation.
    // For now we trust the pointer, matching the existing Write syscall pattern.
    if path_ptr == 0 || len == 0 {
        return ENOENT;
    }

    let path_slice = unsafe { core::slice::from_raw_parts(path_ptr as *const u8, len) };
    let path = match core::str::from_utf8(path_slice) {
        Ok(s) => s,
        Err(_) => return EINVAL,
    };

    let data = match unsafe { ramfs_find(path) } {
        Some(d) => d,
        None => return ENOENT,
    };

    let fd = FileDescriptor::new(data, flags);
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

    let table = unsafe { &mut *core::ptr::addr_of_mut!(FD_TABLE) };
    let entry = match table.get_mut(fd_idx) {
        Some(e) => e,
        None => return EBADF,
    };

    let data = unsafe { entry.data() };
    let remaining = data.len().saturating_sub(entry.offset);
    let to_read = count.min(remaining);

    if to_read == 0 {
        return 0; // EOF
    }

    // TODO(#0): Wave 4 adds proper userspace address validation.
    let dst = unsafe { core::slice::from_raw_parts_mut(buf_ptr as *mut u8, to_read) };
    dst.copy_from_slice(&data[entry.offset..entry.offset + to_read]);
    entry.offset += to_read;

    to_read as u32
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

    let path_slice = unsafe { core::slice::from_raw_parts(path_ptr as *const u8, len) };
    let path = match core::str::from_utf8(path_slice) {
        Ok(s) => s,
        Err(_) => return EINVAL,
    };

    let data = match unsafe { ramfs_find(path) } {
        Some(d) => d,
        None => return ENOENT,
    };

    let stat = StatBuf {
        size: data.len() as u32,
        file_type: S_IFREG,
    };

    // TODO(#0): Wave 4 adds proper userspace address validation.
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

    let table = unsafe { &*core::ptr::addr_of!(FD_TABLE) };
    let entry = match table.get(fd_idx) {
        Some(e) => e,
        None => return EBADF,
    };

    let stat = StatBuf {
        size: entry.size() as u32,
        file_type: S_IFREG,
    };

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

    let table = unsafe { &mut *core::ptr::addr_of_mut!(FD_TABLE) };
    let entry = match table.get_mut(fd_idx) {
        Some(e) => e,
        None => return EBADF,
    };

    // WHY: offset is treated as signed (i32) for SEEK_CUR and SEEK_END,
    // allowing backward seeks. Reinterpret the u32 bits as i32.
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

    // Clamp to [0, file_size] — negative seek results in 0
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

    let table = unsafe { &mut *core::ptr::addr_of_mut!(FD_TABLE) };

    let entry = match table.get(old_idx) {
        Some(e) => *e,
        None => return EBADF,
    };

    // If oldfd == newfd and oldfd is valid, just return newfd
    if old_idx == new_idx {
        return newfd;
    }

    // Close newfd if open (ignore result — closing an already-closed fd is fine)
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
///
/// WHY always "/": the ramfs has no directory hierarchy, so the cwd
/// is always the root. Future directory support will track cwd per-process.
pub fn sys_getcwd(buf_ptr: u32, size: u32) -> u32 {
    if buf_ptr == 0 {
        return EFAULT;
    }

    // Need at least 2 bytes for "/" + null terminator
    if size < 2 {
        return EINVAL;
    }

    // TODO(#0): Wave 4 adds proper userspace address validation.
    unsafe {
        let dst = buf_ptr as *mut u8;
        core::ptr::write(dst, b'/');
        core::ptr::write(dst.add(1), 0); // null terminator
    }

    0
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- FdTable unit tests --

    #[test]
    fn alloc_returns_lowest_available() {
        let mut table = FdTable::new();
        let data = [1u8, 2, 3];
        let fd0 = table.alloc(FileDescriptor::new(&data, 0));
        let fd1 = table.alloc(FileDescriptor::new(&data, 0));
        assert_eq!(fd0, Some(0));
        assert_eq!(fd1, Some(1));
    }

    #[test]
    fn close_frees_slot_for_reuse() {
        let mut table = FdTable::new();
        let data = [1u8, 2, 3];
        let fd0 = table.alloc(FileDescriptor::new(&data, 0));
        assert_eq!(fd0, Some(0));

        assert!(table.close(0));

        // Next alloc should reuse slot 0
        let fd_reused = table.alloc(FileDescriptor::new(&data, 0));
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
    fn file_descriptor_tracks_data() {
        let data = b"hello world";
        let fd = FileDescriptor::new(data, 0);
        assert_eq!(fd.size(), 11);
        assert_eq!(fd.offset, 0);
        let read_data = unsafe { fd.data() };
        assert_eq!(read_data, b"hello world");
    }

    #[test]
    fn alloc_at_overwrites_existing() {
        let mut table = FdTable::new();
        let data_a = [1u8, 2, 3];
        let data_b = [4u8, 5, 6, 7];

        table.alloc(FileDescriptor::new(&data_a, 0)); // fd 0
        assert!(table.alloc_at(0, FileDescriptor::new(&data_b, 0)));

        let entry = table.get(0);
        assert!(entry.is_some());
        assert_eq!(entry.map(|e| e.size()), Some(4));
    }

    #[test]
    fn table_full_returns_none() {
        let mut table = FdTable::new();
        let data = [0u8];
        for _ in 0..MAX_FDS {
            assert!(table.alloc(FileDescriptor::new(&data, 0)).is_some());
        }
        // Table is full
        assert!(table.alloc(FileDescriptor::new(&data, 0)).is_none());
    }

    // -- Syscall-level integration tests --
    // WHY: these test the sys_* functions directly against an in-memory
    // ramfs, without going through the SVC dispatch path. They verify
    // the fd table + ramfs interaction end-to-end.

    /// Set up a test ramfs with known files.
    unsafe fn setup_test_ramfs() {
        let mut fs = crate::ramfs::RamFs::new();
        fs.add("test.txt", b"Hello, thumos!");
        fs.add("empty.dat", b"");
        fs.add("binary.bin", &[0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE]);

        unsafe {
            let ramfs = &mut *core::ptr::addr_of_mut!(RAMFS);
            *ramfs = Some(fs);

            // Reset fd table
            let table = &mut *core::ptr::addr_of_mut!(FD_TABLE);
            *table = FdTable::new();
        }
    }

    #[test]
    fn open_existing_file() {
        unsafe {
            setup_test_ramfs();
        }
        let path = b"test.txt";
        let fd = sys_open(path.as_ptr() as u32, path.len() as u32, 0);
        assert_eq!(fd, 0, "first open should return fd 0");
    }

    #[test]
    fn open_nonexistent_file_returns_enoent() {
        unsafe {
            setup_test_ramfs();
        }
        let path = b"no_such_file";
        let result = sys_open(path.as_ptr() as u32, path.len() as u32, 0);
        assert_eq!(result, ENOENT);
    }

    #[test]
    fn read_file_contents() {
        unsafe {
            setup_test_ramfs();
        }
        let path = b"test.txt";
        let fd = sys_open(path.as_ptr() as u32, path.len() as u32, 0);
        assert_eq!(fd, 0);

        let mut buf = [0u8; 64];
        let bytes_read = sys_read(fd, buf.as_mut_ptr() as u32, 64);
        assert_eq!(bytes_read, 14); // "Hello, thumos!" is 14 bytes
        assert_eq!(&buf[..14], b"Hello, thumos!");
    }

    #[test]
    fn read_at_eof_returns_zero() {
        unsafe {
            setup_test_ramfs();
        }
        let path = b"test.txt";
        let fd = sys_open(path.as_ptr() as u32, path.len() as u32, 0);

        // Read entire file
        let mut buf = [0u8; 64];
        let _ = sys_read(fd, buf.as_mut_ptr() as u32, 64);

        // Second read should return 0 (EOF)
        let bytes_read = sys_read(fd, buf.as_mut_ptr() as u32, 64);
        assert_eq!(bytes_read, 0, "read at EOF must return 0");
    }

    #[test]
    fn close_then_read_returns_ebadf() {
        unsafe {
            setup_test_ramfs();
        }
        let path = b"test.txt";
        let fd = sys_open(path.as_ptr() as u32, path.len() as u32, 0);
        assert_eq!(sys_close(fd), 0);

        let mut buf = [0u8; 64];
        let result = sys_read(fd, buf.as_mut_ptr() as u32, 64);
        assert_eq!(result, EBADF, "read after close must return EBADF");
    }

    #[test]
    fn lseek_set_then_read() {
        unsafe {
            setup_test_ramfs();
        }
        let path = b"test.txt";
        let fd = sys_open(path.as_ptr() as u32, path.len() as u32, 0);

        // Seek to offset 7 ("thumos!")
        let new_pos = sys_lseek(fd, 7, SEEK_SET);
        assert_eq!(new_pos, 7);

        let mut buf = [0u8; 32];
        let bytes_read = sys_read(fd, buf.as_mut_ptr() as u32, 32);
        assert_eq!(bytes_read, 7); // "thumos!" is 7 bytes
        assert_eq!(&buf[..7], b"thumos!");
    }

    #[test]
    fn lseek_end_positions_at_eof() {
        unsafe {
            setup_test_ramfs();
        }
        let path = b"test.txt";
        let fd = sys_open(path.as_ptr() as u32, path.len() as u32, 0);

        // SEEK_END with offset 0 → position at file size
        let new_pos = sys_lseek(fd, 0, SEEK_END);
        assert_eq!(new_pos, 14); // file is 14 bytes

        let mut buf = [0u8; 32];
        let bytes_read = sys_read(fd, buf.as_mut_ptr() as u32, 32);
        assert_eq!(bytes_read, 0, "read at EOF (via SEEK_END) must return 0");
    }

    #[test]
    fn dup_creates_independent_fd() {
        unsafe {
            setup_test_ramfs();
        }
        let path = b"test.txt";
        let fd0 = sys_open(path.as_ptr() as u32, path.len() as u32, 0);
        assert_eq!(fd0, 0);

        let fd1 = sys_dup(fd0);
        assert_eq!(fd1, 1, "dup should return lowest available fd");

        // Read from fd0 — should not affect fd1's offset (they are copies,
        // not shared — offset was 0 at dup time)
        let mut buf = [0u8; 5];
        let _ = sys_read(fd0, buf.as_mut_ptr() as u32, 5);

        // fd1 should still read from offset 0 (independent copy)
        let mut buf2 = [0u8; 5];
        let bytes = sys_read(fd1, buf2.as_mut_ptr() as u32, 5);
        assert_eq!(bytes, 5);
        assert_eq!(&buf2, b"Hello");
    }

    #[test]
    fn dup2_replaces_target_fd() {
        unsafe {
            setup_test_ramfs();
        }
        let path_a = b"test.txt";
        let path_b = b"binary.bin";
        let fd0 = sys_open(path_a.as_ptr() as u32, path_a.len() as u32, 0);
        let fd1 = sys_open(path_b.as_ptr() as u32, path_b.len() as u32, 0);
        assert_eq!(fd0, 0);
        assert_eq!(fd1, 1);

        // dup2(0, 1) — fd1 should now point to test.txt
        let result = sys_dup2(fd0, fd1);
        assert_eq!(result, 1);

        let mut buf = [0u8; 5];
        let bytes = sys_read(1, buf.as_mut_ptr() as u32, 5);
        assert_eq!(bytes, 5);
        assert_eq!(&buf, b"Hello");
    }

    #[test]
    fn stat_existing_file() {
        unsafe {
            setup_test_ramfs();
        }
        let path = b"test.txt";
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

    #[test]
    fn stat_nonexistent_returns_enoent() {
        unsafe {
            setup_test_ramfs();
        }
        let path = b"nope";
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

    #[test]
    fn fstat_open_fd() {
        unsafe {
            setup_test_ramfs();
        }
        let path = b"binary.bin";
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
        unsafe {
            setup_test_ramfs();
        }
        let mut stat = StatBuf {
            size: 0,
            file_type: 0,
        };
        let result = sys_fstat(99, &mut stat as *mut StatBuf as u32);
        assert_eq!(result, EBADF);
    }

    #[test]
    fn getcwd_returns_root() {
        let mut buf = [0u8; 16];
        let result = sys_getcwd(buf.as_mut_ptr() as u32, 16);
        assert_eq!(result, 0);
        assert_eq!(buf[0], b'/');
        assert_eq!(buf[1], 0); // null terminator
    }
}
