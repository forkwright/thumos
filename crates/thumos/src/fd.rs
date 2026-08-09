//! Two-level file descriptor model and VFS-backed syscall implementations
//! (#267).
//!
//! Level 1 is a per-process fd table (`FdTable` on `process::Process::fds`):
//! fd number -> `FdEntry { ofd, cloexec }`. Level 2 is the system-wide
//! `OFD_TABLE` of refcounted open-file descriptions (`OpenFile { desc, refs }`),
//! where `FileDescriptor` (mount index, inode, offset, status flags) is the
//! shared description. `dup()`/`fork()` share one OFD - one byte offset, one
//! set of status flags, per POSIX - while a fresh `open()` creates a new one.
//!
//! Isolation is structural: every fd syscall resolves fd numbers through the
//! CURRENT process (`process::with_current_fds` -> `resolve_fd`), so a process
//! can never name another process's OFDs - there is no global fd namespace.
//!
//! All data access goes through `Filesystem::read()`/`Filesystem::write()`
//! via the mount table. No raw pointers to file data are stored.
//!
//! WHY fixed-size: avoids heap allocation in the fd tables, keeps the
//! structures predictable for a bare-metal kernel. 256 per-process fds and
//! 256 system-wide OFDs suffice for a `BusyBox` shell + init + concurrent
//! processes.

extern crate alloc;

use alloc::boxed::Box;

use crate::memguard::validate_user_buffer;
use crate::vfs::{self, Filesystem, InodeType, MountTable, VfsError};

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
/// Too many open files in system (OFD table full).
pub(crate) const ENFILE: u32 = 0u32.wrapping_sub(23);
/// Invalid argument.
pub(crate) const EINVAL: u32 = 0u32.wrapping_sub(22);
/// Bad address.
pub(crate) const EFAULT: u32 = 0u32.wrapping_sub(14);
/// Is a directory.
pub(crate) const EISDIR: u32 = 0u32.wrapping_sub(21);
/// Not a directory.
pub(crate) const ENOTDIR: u32 = 0u32.wrapping_sub(20);
/// Entry already exists.
pub(crate) const EEXIST: u32 = 0u32.wrapping_sub(17);
/// Directory not empty.
pub(crate) const ENOTEMPTY: u32 = 0u32.wrapping_sub(39);
/// No space left on device.
pub(crate) const ENOSPC: u32 = 0u32.wrapping_sub(28);
/// I/O error.
pub(crate) const EIO: u32 = 0u32.wrapping_sub(5);
/// Permission denied.
pub(crate) const EACCES: u32 = 0u32.wrapping_sub(13);
/// Too many links.
pub(crate) const EMLINK: u32 = 0u32.wrapping_sub(31);
/// Inappropriate ioctl for device.
pub(crate) const ENOTTY: u32 = 0u32.wrapping_sub(25);

// -- fcntl command constants --

/// Duplicate fd to lowest available >= arg.
pub(crate) const F_DUPFD: u32 = 0;
/// Get per-fd flags (`FD_CLOEXEC`).
pub(crate) const F_GETFD: u32 = 1;
/// Set per-fd flags (`FD_CLOEXEC`).
pub(crate) const F_SETFD: u32 = 2;
/// Get file descriptor flags.
pub(crate) const F_GETFL: u32 = 3;
/// Set file descriptor flags.
pub(crate) const F_SETFL: u32 = 4;
/// The only defined per-fd flag: close-on-exec.
pub(crate) const FD_CLOEXEC: u32 = 1;

// -- open flag constants --

/// Append mode flag.
pub(crate) const O_APPEND: u32 = 0x400;
/// Close-on-exec open flag (Linux ARM 0o2000000). Recorded on the per-fd
/// entry and stripped from the OFD status flags at open (POSIX: it is an
/// fd flag, not a file-status flag).
pub(crate) const O_CLOEXEC: u32 = 0o2_000_000;
/// Mask for access mode bits (`O_RDONLY` | `O_WRONLY` | `O_RDWR`).
/// WHY: these bits are immutable after open; `F_SETFL` must not modify them.
pub(crate) const O_ACCMODE: u32 = 0o3;

/// Seek whence constants (POSIX).
pub(crate) const SEEK_SET: u32 = 0;
/// Seek from current position.
pub(crate) const SEEK_CUR: u32 = 1;
/// Seek from end of file.
pub(crate) const SEEK_END: u32 = 2;

/// File type constants for `StatBuf`.
pub(crate) const S_IFREG: u32 = 0o100_000;
/// Directory file type.
pub(crate) const S_IFDIR: u32 = 0o040_000;
/// Character device file type.
pub(crate) const S_IFCHR: u32 = 0o020_000;

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
    /// File type (`S_IFREG`, `S_IFDIR`, `S_IFCHR`).
    pub file_type: u32,
}

/// An open-file description payload: file identity, offset, and status flags.
///
/// This is the shared level-2 state stored inside `OpenFile` (#267): a `dup()`
/// or `fork()` shares one `FileDescriptor` (hence one offset and one set of
/// status flags), while a fresh `open()` creates a new one. Close-on-exec is
/// NOT here - it is a per-fd flag on `FdEntry` (two dups may disagree on it).
///
/// References a file via mount table index and inode ID. No raw pointers
/// to file data are stored; all access goes through the VFS.
///
/// For pipe/socket descriptions, the kind identity is encoded in `flags`
/// (see `pipe.rs`/`socket.rs`). `mount_idx` and `inode_id` are unused there.
#[derive(Clone, Copy)]
pub struct FileDescriptor {
    /// Index into the global `MountTable` identifying the filesystem.
    pub mount_idx: u8,
    /// Inode ID within the filesystem.
    pub inode_id: u32,
    /// Current read/write position within the file.
    pub offset: usize,
    /// Open flags (`O_RDONLY`, `O_WRONLY`, `O_RDWR`, pipe encoding, etc.).
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

/// One per-process fd slot: the OFD it names plus the per-fd `FD_CLOEXEC`
/// flag.
///
/// INVARIANT: `cloexec` lives on the fd entry, never on the shared OFD --
/// POSIX scopes close-on-exec to the descriptor, so two dups of one OFD
/// may disagree on it.
#[derive(Clone, Copy)]
pub(crate) struct FdEntry {
    /// Index into `OFD_TABLE`.
    pub ofd: u16,
    /// Close this fd on successful execve.
    pub cloexec: bool,
}

/// Per-process file descriptor table: fd number -> open-file description.
/// Lives on `process::Process::fds`, so its lifetime is the process's
/// lifetime by construction (#267).
pub(crate) struct FdTable {
    entries: [Option<FdEntry>; MAX_FDS],
}

impl FdTable {
    /// Create an empty fd table.
    pub(crate) const fn new() -> Self {
        const NONE: Option<FdEntry> = None;
        Self {
            entries: [NONE; MAX_FDS],
        }
    }

    /// Allocate the lowest available file descriptor slot.
    /// Returns the fd number, or None if the table is full.
    pub(crate) fn alloc(&mut self, entry: FdEntry) -> Option<usize> {
        for (i, slot) in self.entries.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(entry);
                return Some(i);
            }
        }
        None
    }

    /// Allocate a specific fd slot. Returns false if out of range.
    ///
    /// INVARIANT: the caller must `take()` the slot first and unref the
    /// displaced entry's OFD -- overwriting a live entry leaks a reference.
    pub(crate) fn alloc_at(&mut self, index: usize, entry: FdEntry) -> bool {
        if index >= MAX_FDS {
            return false;
        }
        self.entries[index] = Some(entry);
        true
    }

    /// Allocate the lowest available file descriptor slot >= `min_fd`
    /// (`F_DUPFD`). Returns the fd number, or None if no slot is available.
    pub(crate) fn alloc_from(&mut self, min_fd: usize, entry: FdEntry) -> Option<usize> {
        if min_fd >= MAX_FDS {
            return None;
        }
        for (i, slot) in self.entries[min_fd..].iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(entry);
                return Some(min_fd + i);
            }
        }
        None
    }

    /// Get an fd entry by index (Copy).
    pub(crate) fn get(&self, index: usize) -> Option<FdEntry> {
        if index >= MAX_FDS {
            return None;
        }
        self.entries[index]
    }

    /// Get a mutable reference to an fd entry by index.
    pub(crate) fn get_mut(&mut self, index: usize) -> Option<&mut FdEntry> {
        if index >= MAX_FDS {
            return None;
        }
        self.entries[index].as_mut()
    }

    /// Remove an fd entry, returning it so the caller can unref its OFD.
    /// WHY take-not-close: forcing the entry through the caller makes a
    /// silently-dropped OFD reference unrepresentable.
    pub(crate) fn take(&mut self, index: usize) -> Option<FdEntry> {
        if index >= MAX_FDS {
            return None;
        }
        self.entries[index].take()
    }
}

/// A shared open-file description (OFD): the second level of the two-level
/// fd model (#267). `dup()` and `fork()` share one `OpenFile` -- one byte
/// offset, one set of status flags -- while a fresh `open()` of the same
/// file creates a new one.
pub(crate) struct OpenFile {
    /// File identity, offset, and status flags.
    pub desc: FileDescriptor,
    /// Number of per-process fd entries referencing this OFD.
    refs: u32,
}

/// System-wide maximum of simultaneously open file descriptions.
pub(crate) const MAX_OFDS: usize = 256;

/// System-wide open-file-description table.
///
/// WHY fixed-size static: no heap in core kernel tables; single-core
/// cooperative kernel ensures exclusive access during syscall handling.
/// Per-process fd tables (`process::Process::fds`) reference slots here by
/// index, so a process can only ever name OFDs installed in its OWN table
/// -- the cross-process fd hole (#267) is closed structurally, not by a
/// per-call ownership check.
static mut OFD_TABLE: [Option<OpenFile>; MAX_OFDS] = {
    const NONE: Option<OpenFile> = None;
    [NONE; MAX_OFDS]
};

/// Allocate an OFD slot with refcount 1. None when the system-wide table
/// is full (callers map to ENFILE).
pub(crate) fn ofd_alloc(desc: FileDescriptor) -> Option<u16> {
    // SAFETY: OFD_TABLE is a static mut; single-core cooperative kernel.
    let ofds = unsafe { &mut *core::ptr::addr_of_mut!(OFD_TABLE) };
    for (i, slot) in ofds.iter_mut().enumerate() {
        if slot.is_none() {
            *slot = Some(OpenFile { desc, refs: 1 });
            return u16::try_from(i).ok();
        }
    }
    None
}

/// Install an already-allocated OFD into the CURRENT process's fd table at
/// the lowest free fd. For non-VFS openers (sockets today). Returns the fd
/// number, or None (absent PCB or per-process table full) -- the caller then
/// unrefs the OFD to avoid orphaning it (fail closed).
pub(crate) fn install_current_fd(ofd: u16) -> Option<usize> {
    crate::process::with_current_fds(|t| {
        t.alloc(FdEntry {
            ofd,
            cloexec: false,
        })
    })
    .flatten()
}

/// Add one reference to an OFD (dup/fork).
pub(crate) fn ofd_ref(idx: u16) {
    // SAFETY: OFD_TABLE is a static mut; single-core cooperative kernel.
    let ofds = unsafe { &mut *core::ptr::addr_of_mut!(OFD_TABLE) };
    if let Some(ofd) = ofds.get_mut(usize::from(idx)).and_then(Option::as_mut) {
        ofd.refs = ofd.refs.saturating_add(1);
    }
}

/// Drop one reference to an OFD; at zero, free the slot and run kind
/// teardown (pipe EOF accounting, socket release).
///
/// WHY teardown here and not in `sys_close`: with dup and fork a close no
/// longer implies the description is dead -- pipe close-notification and
/// socket release are correct only at refcount zero.
pub(crate) fn ofd_unref(idx: u16) {
    // SAFETY: OFD_TABLE is a static mut; single-core cooperative kernel.
    let ofds = unsafe { &mut *core::ptr::addr_of_mut!(OFD_TABLE) };
    let Some(slot) = ofds.get_mut(usize::from(idx)) else {
        return;
    };
    let Some(ofd) = slot.as_mut() else {
        return;
    };
    ofd.refs = ofd.refs.saturating_sub(1);
    if ofd.refs == 0 {
        let desc = ofd.desc;
        *slot = None;
        if crate::pipe::is_pipe_fd(desc.flags) {
            crate::pipe::on_pipe_fd_closed(
                crate::pipe::pipe_idx_from_flags(desc.flags),
                crate::pipe::is_write_end(desc.flags),
            );
        }
        if crate::socket::is_socket_fd(desc.flags) {
            crate::socket::on_socket_fd_closed(usize::from(idx));
        }
    }
}

/// Resolve an fd number through the CURRENT process's table to its OFD
/// index. None (fail closed) for an unmapped fd or an absent PCB.
pub(crate) fn resolve_fd(fd: usize) -> Option<u16> {
    crate::process::with_current_fds(|t| t.get(fd).map(|e| e.ofd)).flatten()
}

/// Status flags of the current process's fd, for kind dispatch in
/// syscall.rs (pipe/socket routing and the fd-1 UART fallback).
pub(crate) fn current_fd_flags(fd: usize) -> Option<u32> {
    let idx = resolve_fd(fd)?;
    // SAFETY: OFD_TABLE is a static mut; single-core cooperative kernel.
    let ofds = unsafe { &*core::ptr::addr_of!(OFD_TABLE) };
    ofds.get(usize::from(idx))?.as_ref().map(|o| o.desc.flags)
}

/// `fork()` (#267): copy a parent fd table for the child, bumping each
/// entry's OFD refcount. Each fd entry is one reference, so a dup'd pair
/// in the parent bumps its OFD twice -- exactly matching the two entries
/// the child receives.
pub(crate) fn fork_table(parent: &FdTable) -> FdTable {
    let mut child = FdTable::new();
    for (i, slot) in parent.entries.iter().enumerate() {
        if let Some(entry) = slot {
            ofd_ref(entry.ofd);
            child.entries[i] = Some(*entry);
        }
    }
    child
}

/// exit/fault (#267): close every fd -- drain the table, unref each OFD.
/// Idempotent: a drained table is a no-op.
pub(crate) fn close_all(table: &mut FdTable) {
    for slot in table.entries.iter_mut() {
        if let Some(entry) = slot.take() {
            ofd_unref(entry.ofd);
        }
    }
}

/// execve (#267): close every fd with `FD_CLOEXEC` set. Called only after
/// the last execve failure point (POSIX: fds close on SUCCESSFUL exec).
pub(crate) fn close_cloexec(table: &mut FdTable) {
    for slot in table.entries.iter_mut() {
        if slot.map(|e| e.cloexec).unwrap_or(false) {
            if let Some(entry) = slot.take() {
                ofd_unref(entry.ofd);
            }
        }
    }
}

/// Test-only: refcount of an OFD slot (None when free).
#[cfg(test)]
pub(crate) fn ofd_refs(idx: u16) -> Option<u32> {
    // SAFETY: single-threaded test execution.
    let ofds = unsafe { &*core::ptr::addr_of!(OFD_TABLE) };
    ofds.get(usize::from(idx))?.as_ref().map(|o| o.refs)
}

/// Test-only: reset the process table (PROCS[0] owns the per-process fd
/// table) and the shared OFD table. Shared by fd/pipe/socket/syscall tests
/// so the reset logic exists exactly once.
#[cfg(test)]
pub(crate) unsafe fn reset_fd_state_for_test() {
    // SAFETY: test-only, single-threaded.
    unsafe {
        crate::process::reset_for_test();
        let ofds = &mut *core::ptr::addr_of_mut!(OFD_TABLE);
        for slot in ofds.iter_mut() {
            *slot = None;
        }
    }
}

/// Global mount table for VFS dispatch.
///
/// Populated by `init_vfs()` during kernel boot. All filesystem syscalls
/// resolve paths and perform I/O through this table.
///
/// WHY Option: `MountTable::new()` is not const (contains `Option<Box<dyn Filesystem>>`),
/// so we cannot use it as a static initializer. The Option is None until
/// `init_vfs()` is called during kernel boot.
static mut MOUNT_TABLE: Option<MountTable> = None;

/// Maximum CWD path length.
pub(crate) const CWD_MAX: usize = 256;

/// Default working directory at process creation ("/").
pub(crate) const DEFAULT_CWD: [u8; CWD_MAX] = {
    let mut buf = [0u8; CWD_MAX];
    buf[0] = b'/';
    buf
};

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

/// Initialize the VFS with a root filesystem, /dev, and /tmp.
///
/// Creates the mount table, mounts the root filesystem at `/`, mounts
/// devfs at `/dev`, and creates an empty ramfs at `/tmp`.
///
/// The root filesystem is `root_override` when given one -- e.g. an
/// already-mounted durable [`crate::lfs::Lfs`] -- so callers with
/// persistent storage do not lose it to a fresh, volatile ramfs on every
/// boot (#343). When `root_override` is `None`, the root is built fresh
/// from `cpio_data` (or empty), matching the previous ramfs-only
/// behavior.
///
/// # Safety
///
/// Must be called once during kernel init, before any filesystem syscalls.
/// After this call, `MOUNT_TABLE` is populated and ready for use.
pub unsafe fn init_vfs(cpio_data: Option<&[u8]>, root_override: Option<Box<dyn Filesystem>>) {
    // SAFETY: called once during kernel init before any filesystem syscalls.
    // MOUNT_TABLE is a static mut; addr_of_mut! avoids an intermediate reference.
    // No concurrent access is possible because the scheduler has not started.
    unsafe {
        let mut mt = MountTable::new();

        // Root filesystem: the caller's already-mounted filesystem when
        // given one (#343), otherwise a fresh ramfs from CPIO data (or
        // empty), matching the previous behavior.
        let root_fs: Box<dyn Filesystem> = match root_override {
            Some(fs) => fs,
            None => match cpio_data {
                Some(data) => Box::new(crate::ramfs::RamFs::from_cpio(data)),
                None => Box::new(crate::ramfs::RamFs::new()),
            },
        };
        // Ignore mount errors during init; these are fatal if they fail but
        // the mount table has 8 slots and we use only 3.
        let _ = mt.mount("/", root_fs); // WHY: init-time best-effort mount; failure is fatal and detected by later syscalls

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

/// Maximum distinct ramfs files kept resident in the exec-image cache.
/// WHY (#222): `ramfs_find` used to leak a fresh heap copy of the file on
/// every call (every `execve` and kinit spawn), accumulating without bound
/// across process restarts. Caching by (mount, inode, size) bounds the leak
/// to at most this many resident images, and makes repeated launches of the
/// same binary free after the first.
const ELF_CACHE_SLOTS: usize = 16;

/// One resident cache entry: the (mount, inode, size) it was loaded for, and
/// the leaked `'static` slice backing it.
struct ElfCacheEntry {
    mount_idx: u8,
    inode_id: u32,
    size: usize,
    data: &'static [u8],
}

/// Cache of previously-leaked `ramfs_find` reads, keyed on (mount, inode,
/// size). A size mismatch (the file was rewritten to a different length
/// since it was cached) is treated as a miss, so a stale entry is never
/// served as if it were current.
static mut ELF_CACHE: [Option<ElfCacheEntry>; ELF_CACHE_SLOTS] = {
    const NONE: Option<ElfCacheEntry> = None;
    [NONE; ELF_CACHE_SLOTS]
};

/// Next cache slot to evict when all `ELF_CACHE_SLOTS` are occupied
/// (round-robin).
static mut ELF_CACHE_NEXT: usize = 0;

/// Look up a file in the mounted filesystems by path.
/// Returns a reference to the file data, or None if not found.
///
/// Repeated lookups of the same (mount, inode, size) are served from a
/// bounded resident cache instead of leaking a fresh heap copy on every
/// call (#222).
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

        let size = stat.size as usize;
        let mount_idx_u8 = mount_idx as u8;

        // Serve from cache if this (mount, inode, size) was already loaded.
        let cache = &*core::ptr::addr_of!(ELF_CACHE);
        for slot in cache.iter().flatten() {
            if slot.mount_idx == mount_idx_u8 && slot.inode_id == inode_id && slot.size == size {
                return Some(slot.data);
            }
        }

        // Read the entire file into a buffer
        // WHY alloc: we need a 'static reference but Filesystem::read copies
        // into a provided buffer. We allocate a Vec, leak it to get 'static
        // lifetime, and register it in ELF_CACHE so a later lookup of the
        // same (mount, inode, size) reuses it instead of leaking again.
        if size == 0 {
            return Some(&[]);
        }

        let mut buf = alloc::vec![0u8; size];
        match fs.read(inode_id, 0, &mut buf) {
            Ok(n) => {
                buf.truncate(n);
                let leaked = buf.leak();

                let cache = &mut *core::ptr::addr_of_mut!(ELF_CACHE);
                let slot_idx = match cache.iter().position(|s| s.is_none()) {
                    Some(idx) => idx,
                    None => {
                        let next = &mut *core::ptr::addr_of_mut!(ELF_CACHE_NEXT);
                        let idx = *next % ELF_CACHE_SLOTS;
                        *next = (*next + 1) % ELF_CACHE_SLOTS;
                        idx
                    }
                };
                cache[slot_idx] = Some(ElfCacheEntry {
                    mount_idx: mount_idx_u8,
                    inode_id,
                    size,
                    data: leaked,
                });

                Some(leaked)
            }
            Err(_) => None,
        }
    }
}

// -- Syscall implementation functions --

/// `SYS_open`: open a file by path.
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
        Err(VfsError::NotFound) => return ENOENT,
        Err(VfsError::NotADirectory) => return ENOTDIR,
        Err(VfsError::IsADirectory) => return EISDIR,
        Err(VfsError::AlreadyExists) => return EEXIST,
        Err(VfsError::NotEmpty) => return ENOTEMPTY,
        Err(VfsError::InvalidPath) => return EINVAL,
        Err(VfsError::NoSpace) => return ENOSPC,
        Err(VfsError::IoError | VfsError::RequiresMut) => return EIO,
        Err(VfsError::PermissionDenied) => return EACCES,
        Err(VfsError::TooManyLinks) => return EMLINK,
    };

    // O_CLOEXEC is a per-fd flag: record it on the fd entry and strip it
    // from the stored status flags (POSIX).
    let cloexec = flags & O_CLOEXEC != 0;
    let desc = FileDescriptor::from_vfs(mount_idx as u8, inode_id, flags & !O_CLOEXEC);

    let Some(ofd) = ofd_alloc(desc) else {
        return ENFILE;
    };
    let installed =
        crate::process::with_current_fds(|t| t.alloc(FdEntry { ofd, cloexec })).flatten();
    match installed {
        Some(n) => n as u32,
        None => {
            // Absent PCB or per-process table full: roll the OFD back --
            // never leave an orphaned description (fail closed).
            ofd_unref(ofd);
            EMFILE
        }
    }
}

/// `SYS_read`: read bytes from an open file descriptor.
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
    // Validated ahead of the fd/mount-table lookups below (an early-reject,
    // rather than right at the deref) so a bad buf_ptr is rejected regardless
    // of fd/mount state.
    if !validate_user_buffer(buf_ptr as usize, count) {
        return EFAULT;
    }

    // Two-level lookup (#267): fd -> current process's table -> shared OFD.
    let Some(ofd_idx) = resolve_fd(fd_idx) else {
        return EBADF;
    };
    // SAFETY: OFD_TABLE is a static mut; single-core cooperative kernel.
    let entry = {
        let ofds = unsafe { &*core::ptr::addr_of!(OFD_TABLE) };
        match ofds[usize::from(ofd_idx)].as_ref() {
            Some(o) => o.desc,
            None => return EBADF,
        }
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
    // (before the fd/mount-table lookups) to lie within user-accessible DRAM.
    let dst = unsafe { core::slice::from_raw_parts_mut(buf_ptr as *mut u8, count) };

    match fs.read_mut(inode_id, offset, dst) {
        Ok(n) => {
            // Update the SHARED offset on the OFD so dup'd and forked
            // descriptors advance together. Guard defensively instead of
            // panicking (expect_used is denied in kernel code).
            let ofds = unsafe { &mut *core::ptr::addr_of_mut!(OFD_TABLE) };
            if let Some(o) = ofds[usize::from(ofd_idx)].as_mut() {
                o.desc.offset += n;
            }
            n as u32
        }
        Err(e) => e.to_errno(),
    }
}

/// `SYS_write`: write bytes to an open file descriptor.
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
    // Validated ahead of the fd/mount-table lookups below (an early-reject,
    // rather than right at the deref) so a bad buf_ptr is rejected regardless
    // of fd/mount state.
    if !validate_user_buffer(buf_ptr as usize, count) {
        return EFAULT;
    }

    // Two-level lookup (#267): fd -> current process's table -> shared OFD.
    let Some(ofd_idx) = resolve_fd(fd_idx) else {
        return EBADF;
    };
    // SAFETY: OFD_TABLE is a static mut; single-core cooperative kernel.
    let entry = {
        let ofds = unsafe { &*core::ptr::addr_of!(OFD_TABLE) };
        match ofds[usize::from(ofd_idx)].as_ref() {
            Some(o) => o.desc,
            None => return EBADF,
        }
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
    // (before the fd/mount-table lookups) to lie within user-accessible DRAM.
    let src = unsafe { core::slice::from_raw_parts(buf_ptr as *const u8, count) };

    match fs.write(inode_id, offset, src) {
        Ok(n) => {
            // Update the SHARED offset on the OFD so dup'd and forked
            // descriptors advance together.
            let ofds = unsafe { &mut *core::ptr::addr_of_mut!(OFD_TABLE) };
            if let Some(o) = ofds[usize::from(ofd_idx)].as_mut() {
                o.desc.offset += n;
            }
            n as u32
        }
        Err(e) => e.to_errno(),
    }
}

/// `SYS_close`: close an open file descriptor.
///
/// # Arguments
/// - `fd`: file descriptor number
///
/// # Returns
/// 0 on success, EBADF if fd is not open.
pub(crate) fn sys_close(fd: u32) -> u32 {
    let fd_idx = fd as usize;
    let taken = crate::process::with_current_fds(|t| t.take(fd_idx)).flatten();
    match taken {
        Some(entry) => {
            // Pipe/socket teardown fires inside ofd_unref, only at
            // refcount zero -- a dup'd descriptor keeps the OFD alive.
            ofd_unref(entry.ofd);
            0
        }
        None => EBADF,
    }
}

/// `SYS_stat`: get file status by path.
///
/// # Arguments
/// - `path_ptr`: userspace pointer to the path string
/// - `path_len`: length of the path string
/// - `stat_buf_ptr`: userspace pointer to a `StatBuf`
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

/// `SYS_fstat`: get file status by file descriptor.
///
/// # Arguments
/// - `fd`: file descriptor number
/// - `stat_buf_ptr`: userspace pointer to a `StatBuf`
///
/// # Returns
/// 0 on success, negative error code on failure.
pub(crate) fn sys_fstat(fd: u32, stat_buf_ptr: u32) -> u32 {
    let fd_idx = fd as usize;

    if stat_buf_ptr == 0 {
        return EFAULT;
    }

    // Two-level lookup (#267): fd -> current process's table -> shared OFD.
    // A process can only fstat an fd installed in its OWN table.
    let Some(ofd_idx) = resolve_fd(fd_idx) else {
        return EBADF;
    };
    // SAFETY: OFD_TABLE is a static mut; single-core cooperative kernel.
    let entry = {
        let ofds = unsafe { &*core::ptr::addr_of!(OFD_TABLE) };
        match ofds[usize::from(ofd_idx)].as_ref() {
            Some(o) => o.desc,
            None => return EBADF,
        }
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
        // WHY (#249): a real fs.stat() failure (corrupt inode, I/O error) is a
        // genuine error, unlike the two preceding arms above (mount table /
        // filesystem absent), which are expected fallbacks for fds without
        // VFS backing (pipes/sockets). Propagate it instead of fabricating a
        // zeroed success stat that would mask the failure from the caller.
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

/// `SYS_lseek`: reposition the file offset.
///
/// # Arguments
/// - `fd`: file descriptor number
/// - `offset`: offset value (interpreted based on whence)
/// - `whence`: `SEEK_SET` (0), `SEEK_CUR` (1), or `SEEK_END` (2)
///
/// # Returns
/// New file offset on success, negative error code on failure.
pub(crate) fn sys_lseek(fd: u32, offset: u32, whence: u32) -> u32 {
    let fd_idx = fd as usize;

    let Some(ofd_idx) = resolve_fd(fd_idx) else {
        return EBADF;
    };
    // SAFETY: OFD_TABLE is a static mut; single-core cooperative kernel.
    let ofds = unsafe { &mut *core::ptr::addr_of_mut!(OFD_TABLE) };
    let entry = match ofds[usize::from(ofd_idx)].as_mut() {
        Some(o) => &mut o.desc,
        None => return EBADF,
    };

    // WHY: offset is treated as signed (i32) for SEEK_CUR and SEEK_END.
    let offset_signed = offset as i32;

    // WHY: entry.offset/file_size are inherently non-negative `usize`
    // quantities; the old blind `as i32` reinterpreted a legitimate value
    // >= 2^31 as negative mid-calculation, corrupting SEEK_CUR/SEEK_END
    // (issue #282 finding 7). Widen via try_from (not `as`) into i64 so
    // the arithmetic itself cannot silently wrap; unwrap_or(i64::MAX) is a
    // panic-free fallback for a conversion that cannot fail on this
    // 32-bit target (usize/u32 always fits i64).
    let file_size = i64::try_from(entry.size()).unwrap_or(i64::MAX);

    let new_pos: i64 = match whence {
        SEEK_SET => i64::from(offset_signed),
        SEEK_CUR => {
            let current = i64::try_from(entry.offset).unwrap_or(i64::MAX);
            current.saturating_add(i64::from(offset_signed))
        }
        SEEK_END => file_size.saturating_add(i64::from(offset_signed)),
        _ => return EINVAL,
    };

    // The syscall ABI reports the result in r0 as a signed i32 (0 =
    // success); the representable non-error domain is 0..=i32::MAX.
    const MAX_REPRESENTABLE_POS: i64 = 0x7FFF_FFFF;
    if new_pos < 0 || new_pos > MAX_REPRESENTABLE_POS {
        return EINVAL;
    }

    let Ok(new_pos_u32) = u32::try_from(new_pos) else {
        return EINVAL;
    };
    let Ok(new_pos_usize) = usize::try_from(new_pos) else {
        return EINVAL;
    };

    entry.offset = new_pos_usize;
    new_pos_u32
}

/// `SYS_dup`: duplicate a file descriptor.
///
/// # Arguments
/// - `fd`: file descriptor to duplicate
///
/// # Returns
/// New (lowest available) fd number on success, negative error code on failure.
pub(crate) fn sys_dup(fd: u32) -> u32 {
    let fd_idx = fd as usize;
    // POSIX: the dup shares the OFD but never inherits FD_CLOEXEC.
    let result = crate::process::with_current_fds(|t| {
        let Some(entry) = t.get(fd_idx) else {
            return Err(EBADF);
        };
        match t.alloc(FdEntry {
            ofd: entry.ofd,
            cloexec: false,
        }) {
            Some(n) => {
                ofd_ref(entry.ofd);
                Ok(n)
            }
            None => Err(EMFILE),
        }
    });
    match result {
        Some(Ok(n)) => n as u32,
        Some(Err(e)) => e,
        None => EBADF,
    }
}

/// `SYS_dup2`: duplicate a file descriptor to a specific number.
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

    let result = crate::process::with_current_fds(|t| {
        let Some(entry) = t.get(old_idx) else {
            return Err(EBADF);
        };
        if old_idx == new_idx {
            return Ok((newfd, None));
        }
        // dup2 closes the target first; its OFD is unreffed AFTER the new
        // entry is installed and reffed, so a shared-OFD displacement can
        // never dip the refcount to zero mid-flight (old_idx holds a ref).
        let displaced = t.take(new_idx);
        // POSIX: the dup never inherits FD_CLOEXEC.
        if !t.alloc_at(
            new_idx,
            FdEntry {
                ofd: entry.ofd,
                cloexec: false,
            },
        ) {
            return Err(EBADF);
        }
        ofd_ref(entry.ofd);
        Ok((newfd, displaced))
    });
    match result {
        Some(Ok((n, displaced))) => {
            if let Some(d) = displaced {
                ofd_unref(d.ofd);
            }
            n
        }
        Some(Err(e)) => e,
        None => EBADF,
    }
}

/// `SYS_fcntl`: file descriptor control.
///
/// Supports:
/// - `F_GETFL` (3): return the fd's flags.
/// - `F_SETFL` (4): set modifiable flags (only `O_APPEND`; access mode
///   bits are immutable after open).
/// - `F_DUPFD` (0): duplicate the fd to the lowest available slot >= `arg`.
///
/// # Arguments
/// - `fd`: file descriptor number
/// - `cmd`: fcntl command (`F_DUPFD`, `F_GETFL`, `F_SETFL`)
/// - `arg`: command-specific argument
///
/// # Returns
/// Command-dependent value on success, or negative error code.
pub(crate) fn sys_fcntl(fd: u32, cmd: u32, arg: u32) -> u32 {
    let fd_idx = fd as usize;

    match cmd {
        // F_GETFD/F_SETFD operate on the PER-FD flag (FD_CLOEXEC, #267),
        // not the shared OFD status flags.
        F_GETFD => {
            let r = crate::process::with_current_fds(|t| {
                t.get(fd_idx)
                    .map(|e| if e.cloexec { FD_CLOEXEC } else { 0 })
            });
            match r {
                Some(Some(v)) => v,
                _ => EBADF,
            }
        }
        F_SETFD => {
            let r = crate::process::with_current_fds(|t| {
                t.get_mut(fd_idx).map(|e| {
                    e.cloexec = arg & FD_CLOEXEC != 0;
                })
            });
            match r {
                Some(Some(())) => 0,
                _ => EBADF,
            }
        }
        F_GETFL => match current_fd_flags(fd_idx) {
            Some(flags) => flags,
            None => EBADF,
        },
        F_SETFL => {
            let Some(ofd_idx) = resolve_fd(fd_idx) else {
                return EBADF;
            };
            // SAFETY: OFD_TABLE is a static mut; single-core cooperative
            // kernel. Status flags live on the OFD: F_SETFL through one
            // dup is visible through the other (POSIX).
            let ofds = unsafe { &mut *core::ptr::addr_of_mut!(OFD_TABLE) };
            match ofds[usize::from(ofd_idx)].as_mut() {
                Some(o) => {
                    // WHY replace-only-O_APPEND: the old `& O_ACCMODE`
                    // preservation wiped the pipe/socket kind encoding
                    // (and O_ACCMODE aliases FD_KIND_PIPE); keeping every
                    // non-O_APPEND bit preserves both access mode and kind.
                    o.desc.flags = (o.desc.flags & !O_APPEND) | (arg & O_APPEND);
                    0
                }
                None => EBADF,
            }
        }
        F_DUPFD => {
            let min_fd = arg as usize;
            let result = crate::process::with_current_fds(|t| {
                let Some(entry) = t.get(fd_idx) else {
                    return Err(EBADF);
                };
                match t.alloc_from(
                    min_fd,
                    FdEntry {
                        ofd: entry.ofd,
                        cloexec: false,
                    },
                ) {
                    Some(n) => {
                        ofd_ref(entry.ofd);
                        Ok(n)
                    }
                    None => Err(EMFILE),
                }
            });
            match result {
                Some(Ok(n)) => n as u32,
                Some(Err(e)) => e,
                None => EBADF,
            }
        }
        _ => EINVAL,
    }
}

/// `SYS_ioctl`: device-specific control operations.
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

    // Validate the fd exists in the CURRENT process's table before returning
    // ENOTTY (#267): a process can only ioctl an fd it actually owns.
    match resolve_fd(fd_idx) {
        Some(_) => ENOTTY,
        None => EBADF,
    }
}

/// `SYS_getcwd`: get current working directory.
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

    // Read the current process's cwd (#437); proc0/PID 0 always has one, and
    // an absent PCB falls back to "/" rather than a bogus path.
    let (cwd_buf, cwd_len) = crate::process::with_current_cwd(|c| {
        let mut b = [0u8; crate::fd::CWD_MAX];
        b[..c.len()].copy_from_slice(c);
        (b, c.len())
    })
    .unwrap_or((crate::fd::DEFAULT_CWD, 1));
    let cwd_bytes = &cwd_buf[..cwd_len];

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

/// `SYS_mkdir`: create a directory at the given path.
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

/// `SYS_unlink`: remove a file or directory entry.
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

/// `SYS_chdir`: change the current working directory.
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

    // Update the current process's CWD (#437) — per-process, so a chdir here
    // never leaks into another process.
    crate::process::set_current_cwd(path);

    0
}

/// Split a path into (`parent_path`, `final_component`).
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

    #[cfg(target_pointer_width = "32")]
    #[test]
    fn sys_open_returns_enotdir_not_enoent_for_path_through_a_file() {
        // SAFETY: test-only.
        unsafe {
            setup_test_vfs();
        }
        // "/test.txt" is a regular file; walking a further component through
        // it must surface ENOTDIR (issue #282 finding 6), not the generic
        // ENOENT the old blanket `Err(_) => ENOENT` mapping returned.
        let path = b"/test.txt/foo";
        let result = sys_open(path.as_ptr() as u32, path.len() as u32, 0);
        assert_eq!(
            result, ENOTDIR,
            "path through a non-directory component must return ENOTDIR"
        );
    }

    #[cfg(target_pointer_width = "32")]
    #[test]
    fn lseek_seek_cur_large_offset_no_i32_wraparound() {
        // SAFETY: test-only.
        unsafe {
            setup_test_vfs();
        }
        // A descriptor whose current position sits exactly at the i32 domain
        // boundary (2^31) -- `as i32` reinterprets this as i32::MIN, which
        // previously made a legitimate SEEK_CUR result look negative and
        // return EINVAL (issue #282 finding 7).
        let mut fd_entry = FileDescriptor::from_vfs(0, 0, 0);
        fd_entry.offset = 0x8000_0000; // 2^31
        let fd = install_test_fd(fd_entry);

        // Seek back by exactly 2^31 (raw bit pattern 0x8000_0000 == -2^31 when
        // reinterpreted as i32) -- the true result is position 0.
        let new_pos = sys_lseek(fd, 0x8000_0000, SEEK_CUR);
        assert_eq!(
            new_pos, 0,
            "SEEK_CUR must not misreport a valid position as EINVAL from i32 truncation"
        );
    }

    #[cfg(target_pointer_width = "32")]
    #[test]
    fn lseek_seek_cur_negative_result_rejected_with_einval() {
        // SAFETY: test-only.
        unsafe {
            setup_test_vfs();
        }
        // Seeking further back than the current position with SEEK_CUR
        // would land at a negative file position -- must be rejected with
        // EINVAL, not wrap or silently succeed (issue #282 finding 12).
        let mut fd_entry = FileDescriptor::from_vfs(0, 0, 0);
        fd_entry.offset = 100;
        let fd = install_test_fd(fd_entry);

        let negative_offset = 0u32.wrapping_sub(200); // -200 two's complement
        let result = sys_lseek(fd, negative_offset, SEEK_CUR);
        assert_eq!(
            result, EINVAL,
            "SEEK_CUR producing a negative file position must return EINVAL"
        );

        // A rejected seek must not mutate the stored offset.
        let unchanged = sys_lseek(fd, 0, SEEK_CUR);
        assert_eq!(
            unchanged, 100,
            "a rejected SEEK_CUR must not mutate the stored file offset"
        );
    }

    use super::*;
    use crate::vfs::InodeType;

    /// Reset global state for test isolation.
    ///
    /// # Safety
    ///
    /// Test-only. Resets the process fd table, the OFD table (#267), and the
    /// mount table to a clean state.
    unsafe fn setup_test_vfs() {
        unsafe {
            // Reset the process table (PROCS[0] owns the per-process fd
            // table) and the shared OFD table (#267).
            reset_fd_state_for_test();

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

            // Reset the current process's CWD to "/" (#437; proc0 is already
            // created at "/", so this matters for test re-initialization).
            crate::process::set_current_cwd("/");
        }
    }

    /// Test helper: install `desc` as a fresh OFD in the CURRENT process and
    /// return its fd number. Collapses the old `FD_TABLE.alloc(FileDescriptor)`
    /// pattern onto the two-level path (#267); requires the current process to
    /// exist (call `setup_test_vfs` / `reset_fd_state_for_test` first).
    fn install_test_fd(desc: FileDescriptor) -> u32 {
        let ofd = ofd_alloc(desc).expect("OFD alloc must succeed");
        crate::process::with_current_fds(|t| {
            t.alloc(FdEntry {
                ofd,
                cloexec: false,
            })
        })
        .flatten()
        .expect("fd install must succeed") as u32
    }

    // -- FdTable unit tests --

    #[test]
    fn alloc_returns_lowest_available() {
        let mut table = FdTable::new();
        let fd0 = table.alloc(FdEntry {
            ofd: 1,
            cloexec: false,
        });
        let fd1 = table.alloc(FdEntry {
            ofd: 2,
            cloexec: false,
        });
        assert_eq!(fd0, Some(0));
        assert_eq!(fd1, Some(1));
    }

    #[test]
    fn take_frees_slot_for_reuse() {
        let mut table = FdTable::new();
        let fd0 = table.alloc(FdEntry {
            ofd: 1,
            cloexec: false,
        });
        assert_eq!(fd0, Some(0));

        assert!(table.take(0).is_some());

        // Next alloc should reuse slot 0
        let fd_reused = table.alloc(FdEntry {
            ofd: 1,
            cloexec: false,
        });
        assert_eq!(fd_reused, Some(0));
    }

    #[test]
    fn take_invalid_fd_returns_none() {
        let mut table = FdTable::new();
        assert!(table.take(0).is_none());
        assert!(table.take(MAX_FDS).is_none());
        assert!(table.take(999).is_none());
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

        table.alloc(FdEntry {
            ofd: 1,
            cloexec: false,
        }); // fd 0
        assert!(table.alloc_at(
            0,
            FdEntry {
                ofd: 2,
                cloexec: false,
            }
        ));

        let entry = table.get(0);
        assert!(entry.is_some());
        assert_eq!(entry.map(|e| e.ofd), Some(2));
    }

    #[test]
    fn table_full_returns_none() {
        let mut table = FdTable::new();
        for _ in 0..MAX_FDS {
            assert!(
                table
                    .alloc(FdEntry {
                        ofd: 1,
                        cloexec: false,
                    })
                    .is_some()
            );
        }
        // Table is full
        assert!(
            table
                .alloc(FdEntry {
                    ofd: 1,
                    cloexec: false,
                })
                .is_none()
        );
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

    /// #222: repeated `ramfs_find` on the same file must reuse the cached
    /// leak, not allocate a fresh copy on every call.
    #[test]
    fn ramfs_find_caches_repeated_lookups() {
        unsafe {
            setup_test_vfs();
            let first = ramfs_find("/test.txt").expect("file must be found");
            let second = ramfs_find("/test.txt").expect("file must be found");
            assert_eq!(
                first.as_ptr(),
                second.as_ptr(),
                "repeated ramfs_find on the same file must reuse the cached leak (#222)"
            );
            assert_eq!(
                first, second,
                "cached and fresh reads must return identical content"
            );
        }
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
        // [board::KERNEL_END, board::RAM_END) on this host toolchain;
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
    // WHY: the two-level model shares one OFD -- and hence one byte offset
    // -- between an fd and its dup (POSIX); this asserts that shared-offset
    // behavior, not a private per-fd offset.
    #[cfg(target_pointer_width = "32")]
    #[test]
    fn dup_shares_offset_with_original() {
        // SAFETY: test-only.
        unsafe {
            setup_test_vfs();
        }
        let path = b"/test.txt";
        let fd0 = sys_open(path.as_ptr() as u32, path.len() as u32, 0);
        assert_eq!(fd0, 0);

        let fd1 = sys_dup(fd0);
        assert_eq!(fd1, 1, "dup should return lowest available fd");

        // Read from fd0 — the dup SHARES the OFD, so fd1's offset advances too.
        static mut BUF: [u8; 5] = [0u8; 5];
        // SAFETY: test-only static; single-threaded per test.
        let buf = unsafe { &mut *core::ptr::addr_of_mut!(BUF) };
        let n = sys_read(fd0, buf.as_mut_ptr() as u32, 5);
        assert_eq!(n, 5);
        assert_eq!(&*buf, b"Hello");

        // fd1 must continue from the offset fd0 just advanced to (5), not
        // restart from 0.
        static mut BUF2: [u8; 7] = [0u8; 7];
        // SAFETY: test-only static; single-threaded per test.
        let buf2 = unsafe { &mut *core::ptr::addr_of_mut!(BUF2) };
        let bytes = sys_read(fd1, buf2.as_mut_ptr() as u32, 7);
        assert_eq!(
            bytes, 7,
            "dup must share the original's OFD, hence its advanced offset"
        );
        assert_eq!(&*buf2, b", thumo");
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

    /// #249: a genuine `fs.stat()` failure (bogus inode) must propagate a
    /// non-zero errno, not a fabricated zeroed success stat.
    #[cfg(target_pointer_width = "32")]
    #[test]
    fn fstat_propagates_real_stat_error_instead_of_fabricating_success() {
        // SAFETY: test-only.
        unsafe {
            setup_test_vfs();
        }
        let bogus = FileDescriptor::from_vfs(0, 9_999, 0);
        let fd = install_test_fd(bogus);

        static mut STAT: StatBuf = StatBuf {
            size: 0,
            file_type: 0,
        };
        // SAFETY: test-only static; single-threaded per test.
        let stat = unsafe { &mut *core::ptr::addr_of_mut!(STAT) };
        let result = sys_fstat(fd, stat as *mut StatBuf as u32);

        assert_ne!(
            result, 0,
            "fstat must propagate a real VFS stat error, not fabricate success (#249)"
        );
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

    #[cfg(target_pointer_width = "32")]
    #[test]
    fn getcwd_buffer_too_small_returns_einval() {
        // SAFETY: test-only.
        unsafe {
            setup_test_vfs();
        }
        // The root cwd ("/") needs 2 bytes (1 char + NUL terminator); a
        // 1-byte buffer must be rejected, not truncated or overflowed
        // (issue #282 finding 14).
        static mut BUF: [u8; 1] = [0u8; 1];
        // SAFETY: test-only static; single-threaded per test.
        let buf = unsafe { &mut *core::ptr::addr_of_mut!(BUF) };
        let result = sys_getcwd(buf.as_mut_ptr() as u32, 1);
        assert_eq!(
            result, EINVAL,
            "a buffer too small for cwd + NUL must return EINVAL"
        );
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
        assert_eq!(
            read, 32,
            "sys_read on /dev/urandom must fill the buffer, not return an errno"
        );
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
        unsafe {
            setup_test_vfs();
        }

        // Open a file via internal APIs (avoids pointer truncation).
        let fd_num = install_test_fd(FileDescriptor::from_vfs(0, 1, O_APPEND));

        let result = sys_fcntl(fd_num, F_GETFL, 0);
        assert_eq!(result, O_APPEND, "F_GETFL must return the fd's flags");
    }

    #[test]
    fn fcntl_setfl_sets_append() {
        unsafe {
            setup_test_vfs();
        }

        let fd_num = install_test_fd(FileDescriptor::from_vfs(0, 1, 0));

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
        unsafe {
            setup_test_vfs();
        }

        // Open with access mode bits set (O_RDWR = 2)
        let fd_num = install_test_fd(FileDescriptor::from_vfs(0, 1, 2)); // O_RDWR

        // Set O_APPEND — access mode must be preserved
        sys_fcntl(fd_num, F_SETFL, O_APPEND);
        let flags = sys_fcntl(fd_num, F_GETFL, 0);
        assert_eq!(
            flags & O_ACCMODE,
            2,
            "access mode bits must be preserved by F_SETFL"
        );
        assert_eq!(flags & O_APPEND, O_APPEND, "O_APPEND must be set");
    }

    #[test]
    fn fcntl_dupfd_duplicates_above_arg() {
        unsafe {
            setup_test_vfs();
        }

        // Allocate fd 0
        let fd_num = install_test_fd(FileDescriptor::from_vfs(0, 1, 0));
        assert_eq!(fd_num, 0);

        // F_DUPFD with arg=5 — new fd must be >= 5
        let new_fd = sys_fcntl(fd_num, F_DUPFD, 5);
        assert!(
            new_fd >= 5 && new_fd < MAX_FDS as u32,
            "F_DUPFD(5) returned {new_fd}, expected >= 5"
        );

        // Verify the new fd shares the SAME OFD -- F_DUPFD is a dup, not a
        // copy (POSIX): both fd numbers must resolve to one open-file
        // description.
        let orig_ofd = resolve_fd(fd_num as usize).expect("original fd");
        let duped_ofd = resolve_fd(new_fd as usize).expect("duped fd");
        assert_eq!(
            orig_ofd, duped_ofd,
            "F_DUPFD must share the same OFD as the original fd"
        );
    }

    #[test]
    fn fcntl_dupfd_returns_emfile_when_full() {
        unsafe {
            setup_test_vfs();
        }

        // Fill fd table
        for _ in 0..MAX_FDS {
            install_test_fd(FileDescriptor::from_vfs(0, 1, 0));
        }

        // F_DUPFD should fail with EMFILE
        let result = sys_fcntl(0, F_DUPFD, 0);
        assert_eq!(result, EMFILE, "F_DUPFD on full table must return EMFILE");
    }

    #[test]
    fn fcntl_invalid_cmd_returns_einval() {
        unsafe {
            setup_test_vfs();
        }

        install_test_fd(FileDescriptor::from_vfs(0, 1, 0));

        let result = sys_fcntl(0, 99, 0);
        assert_eq!(result, EINVAL, "unknown fcntl command must return EINVAL");
    }

    #[test]
    fn fcntl_bad_fd_returns_ebadf() {
        unsafe {
            setup_test_vfs();
        }

        assert_eq!(sys_fcntl(99, F_GETFL, 0), EBADF);
        assert_eq!(sys_fcntl(99, F_SETFL, 0), EBADF);
        assert_eq!(sys_fcntl(99, F_DUPFD, 0), EBADF);
    }

    // -- ioctl tests --

    #[test]
    fn ioctl_returns_enotty() {
        unsafe {
            setup_test_vfs();
        }

        // Allocate a regular file fd
        let fd_num = install_test_fd(FileDescriptor::from_vfs(0, 1, 0));

        let result = sys_ioctl(fd_num, 0, 0);
        assert_eq!(result, ENOTTY, "ioctl on a file fd must return ENOTTY");
    }

    #[test]
    fn ioctl_bad_fd_returns_ebadf() {
        unsafe {
            setup_test_vfs();
        }

        let result = sys_ioctl(99, 0, 0);
        assert_eq!(result, EBADF, "ioctl on invalid fd must return EBADF");
    }

    #[test]
    fn ioctl_devfs_returns_enotty() {
        unsafe {
            setup_test_vfs();
        }

        // Open a devfs file via internal APIs — devfs is mount index 1
        let fd_num = install_test_fd(FileDescriptor::from_vfs(1, 0, 0));

        let result = sys_ioctl(fd_num, 0x5401, 0); // TCGETS
        assert_eq!(result, ENOTTY, "ioctl on devfs fd must return ENOTTY");
    }

    // -- sys_write file dispatch test --

    #[cfg(target_pointer_width = "32")]
    #[test]
    fn write_dispatches_to_vfs_for_file_fds() {
        unsafe {
            setup_test_vfs();
        }

        // Create a file through VFS, open it, write through sys_write
        let mt = unsafe { get_mount_table_mut() }.expect("mount table");
        let fs = mt.get_mut(0).expect("root fs");
        let _file_id = fs
            .create(0, "writable.txt", InodeType::RegularFile)
            .expect("create");
        drop(fs);

        let path = b"/writable.txt";
        let fd = sys_open(path.as_ptr() as u32, path.len() as u32, 0);
        assert!(fd < MAX_FDS as u32, "open should succeed");

        let data = b"test write data";
        let written = sys_write(fd, data.as_ptr() as u32, data.len() as u32);
        assert_eq!(
            written,
            data.len() as u32,
            "sys_write should write all bytes"
        );

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
            table.alloc(FdEntry {
                ofd: 1,
                cloexec: false,
            });
        }
        let fd = table.alloc_from(
            3,
            FdEntry {
                ofd: 2,
                cloexec: false,
            },
        );
        assert_eq!(fd, Some(5), "alloc_from(3) with 0-4 taken should return 5");
    }

    #[test]
    fn alloc_from_uses_exact_min_if_available() {
        let mut table = FdTable::new();
        let fd = table.alloc_from(
            10,
            FdEntry {
                ofd: 1,
                cloexec: false,
            },
        );
        assert_eq!(
            fd,
            Some(10),
            "alloc_from(10) on empty table should return 10"
        );
    }

    #[test]
    fn alloc_from_max_fds_returns_none() {
        let mut table = FdTable::new();
        let fd = table.alloc_from(
            MAX_FDS,
            FdEntry {
                ofd: 1,
                cloexec: false,
            },
        );
        assert_eq!(fd, None, "alloc_from(MAX_FDS) must return None");
    }

    #[test]
    fn init_vfs_mounts_three_filesystems() {
        // SAFETY: test-only.
        unsafe {
            let mt_opt = &mut *core::ptr::addr_of_mut!(MOUNT_TABLE);
            *mt_opt = None;

            init_vfs(None, None);

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
        assert_eq!(
            result, ENOENT,
            "path_len > MAX_PATH must return ENOENT before any slice is built"
        );
    }

    #[test]
    fn sys_mkdir_rejects_oversized_path_len() {
        let result = sys_mkdir(IN_RANGE_UNBACKED_PTR, u32::MAX);
        assert_eq!(
            result, ENOENT,
            "path_len > MAX_PATH must return ENOENT before any slice is built"
        );
    }

    #[test]
    fn sys_open_rejects_kernel_range_path_ptr() {
        let kernel_ptr = crate::board::KERNEL_LOAD as u32;
        let result = sys_open(kernel_ptr, 4, 0);
        assert_eq!(result, EFAULT, "kernel-range path_ptr must return EFAULT");
    }

    #[test]
    fn sys_read_rejects_kernel_range_buf_ptr() {
        let kernel_ptr = crate::board::KERNEL_LOAD as u32;
        let result = sys_read(99, kernel_ptr, 4);
        assert_eq!(result, EFAULT, "kernel-range buf_ptr must return EFAULT");
    }

    #[test]
    fn sys_write_rejects_kernel_range_buf_ptr() {
        let kernel_ptr = crate::board::KERNEL_LOAD as u32;
        let result = sys_write(99, kernel_ptr, 4);
        assert_eq!(result, EFAULT, "kernel-range buf_ptr must return EFAULT");
    }

    #[test]
    fn sys_stat_rejects_kernel_range_path_ptr() {
        let kernel_ptr = crate::board::KERNEL_LOAD as u32;
        let result = sys_stat(kernel_ptr, 4, IN_RANGE_UNBACKED_PTR);
        assert_eq!(result, EFAULT, "kernel-range path_ptr must return EFAULT");
    }

    #[test]
    fn sys_stat_rejects_kernel_range_stat_buf_ptr() {
        let kernel_ptr = crate::board::KERNEL_LOAD as u32;
        let result = sys_stat(IN_RANGE_UNBACKED_PTR, 4, kernel_ptr);
        assert_eq!(
            result, EFAULT,
            "kernel-range stat_buf_ptr must return EFAULT"
        );
    }

    #[test]
    fn sys_fstat_rejects_kernel_range_stat_buf_ptr() {
        // SAFETY: test-only; establishes a fresh current process and clears
        // the shared OFD table.
        unsafe {
            reset_fd_state_for_test();
        }
        let fd = install_test_fd(FileDescriptor::from_vfs(0, 1, 0));

        let kernel_ptr = crate::board::KERNEL_LOAD as u32;
        let result = sys_fstat(fd, kernel_ptr);
        assert_eq!(
            result, EFAULT,
            "kernel-range stat_buf_ptr must return EFAULT"
        );
    }

    #[test]
    fn sys_getcwd_rejects_kernel_range_buf_ptr() {
        let kernel_ptr = crate::board::KERNEL_LOAD as u32;
        let result = sys_getcwd(kernel_ptr, 32);
        assert_eq!(result, EFAULT, "kernel-range buf_ptr must return EFAULT");
    }

    #[test]
    fn sys_mkdir_rejects_kernel_range_path_ptr() {
        let kernel_ptr = crate::board::KERNEL_LOAD as u32;
        let result = sys_mkdir(kernel_ptr, 4);
        assert_eq!(result, EFAULT, "kernel-range path_ptr must return EFAULT");
    }

    #[test]
    fn sys_unlink_rejects_kernel_range_path_ptr() {
        let kernel_ptr = crate::board::KERNEL_LOAD as u32;
        let result = sys_unlink(kernel_ptr, 4);
        assert_eq!(result, EFAULT, "kernel-range path_ptr must return EFAULT");
    }

    #[test]
    fn sys_chdir_rejects_kernel_range_path_ptr() {
        let kernel_ptr = crate::board::KERNEL_LOAD as u32;
        let result = sys_chdir(kernel_ptr, 4);
        assert_eq!(result, EFAULT, "kernel-range path_ptr must return EFAULT");
    }

    // -- Two-level fd table isolation and lifecycle tests (#267) --

    /// A no-op process entry point for `process::spawn` in tests -- never
    /// actually invoked (the test never context-switches into it), only
    /// referenced as a function pointer to populate the new PCB's context.
    #[cfg(target_pointer_width = "32")]
    fn isolation_test_entry() -> ! {
        loop {}
    }

    /// ISOLATION: a different process must not be able to name proc0's fd
    /// by number. The two-level model resolves every fd through the
    /// CURRENT process's own table, so a process whose table lacks that
    /// slot fails closed with EBADF -- there is no global fd namespace.
    #[cfg(target_pointer_width = "32")]
    #[test]
    fn fd_isolation_cross_process_ops_return_ebadf() {
        // SAFETY: test-only.
        unsafe {
            setup_test_vfs();
        }
        let path = b"/test.txt";
        let fd = sys_open(path.as_ptr() as u32, path.len() as u32, 0);
        assert_eq!(fd, 0, "proc0 opens fd 0");

        // A freshly spawned process gets its OWN, empty fd table -- it does
        // not inherit proc0's fds (unlike fork).
        let other_pid = crate::process::spawn(isolation_test_entry).expect("spawn must succeed");
        // SAFETY: test-only; single-threaded test execution.
        unsafe {
            crate::process::set_current_for_test(other_pid);
        }

        static mut BUF: [u8; 8] = [0u8; 8];
        // SAFETY: test-only static; single-threaded per test.
        let buf = unsafe { &mut *core::ptr::addr_of_mut!(BUF) };
        assert_eq!(
            sys_read(fd, buf.as_mut_ptr() as u32, 8),
            EBADF,
            "a different process must not be able to read proc0's fd number"
        );
        assert_eq!(
            sys_write(fd, buf.as_ptr() as u32, 8),
            EBADF,
            "a different process must not be able to write proc0's fd number"
        );
        assert_eq!(
            sys_dup(fd),
            EBADF,
            "a different process must not be able to dup proc0's fd number"
        );
        assert_eq!(
            sys_close(fd),
            EBADF,
            "a different process must not be able to close proc0's fd number"
        );
    }

    /// FORK-SHARES-OFFSET: `fork()` copies the fd table, but the copied entry
    /// still names the SAME OFD as the parent -- one shared byte offset, per
    /// POSIX. A close in the parent must not affect the child's reference
    /// (the OFD lives until the LAST reference is gone).
    #[cfg(target_pointer_width = "32")]
    #[test]
    fn fork_shares_ofd_offset_advances_together() {
        // SAFETY: test-only.
        unsafe {
            setup_test_vfs();
        }
        let path = b"/test.txt"; // "Hello, thumos!" (14 bytes)
        let fd = sys_open(path.as_ptr() as u32, path.len() as u32, 0);
        assert_eq!(fd, 0);

        // Parent reads 5 bytes ("Hello") before forking.
        static mut BUF: [u8; 5] = [0u8; 5];
        // SAFETY: test-only static; single-threaded per test.
        let buf = unsafe { &mut *core::ptr::addr_of_mut!(BUF) };
        assert_eq!(sys_read(fd, buf.as_mut_ptr() as u32, 5), 5);
        assert_eq!(&*buf, b"Hello");

        let child_pid = crate::process::fork().expect("fork must succeed");
        // SAFETY: test-only; single-threaded test execution.
        unsafe {
            crate::process::set_current_for_test(child_pid);
        }

        // Child's fd 0 shares the SAME OFD -- offset continues at 5, not 0.
        static mut BUF2: [u8; 7] = [0u8; 7];
        // SAFETY: test-only static; single-threaded per test.
        let buf2 = unsafe { &mut *core::ptr::addr_of_mut!(BUF2) };
        let n2 = sys_read(fd, buf2.as_mut_ptr() as u32, 7);
        assert_eq!(
            n2, 7,
            "child's inherited fd must continue at the parent's advanced offset"
        );
        assert_eq!(&*buf2, b", thumo");

        // Parent closes its copy of fd 0; the OFD stays alive because the
        // child still holds a reference.
        // SAFETY: test-only; single-threaded test execution.
        unsafe {
            crate::process::set_current_for_test(0);
        }
        assert_eq!(sys_close(fd), 0);

        // SAFETY: test-only; single-threaded test execution.
        unsafe {
            crate::process::set_current_for_test(child_pid);
        }
        static mut BUF3: [u8; 2] = [0u8; 2];
        // SAFETY: test-only static; single-threaded per test.
        let buf3 = unsafe { &mut *core::ptr::addr_of_mut!(BUF3) };
        let n3 = sys_read(fd, buf3.as_mut_ptr() as u32, 2);
        assert_eq!(
            n3, 2,
            "child's fd must still work after the parent's close (shared OFD ref held)"
        );
        assert_eq!(&*buf3, b"s!");
    }

    /// OPEN-AFTER-FORK-INDEPENDENT: a fresh `open()` in the child (even of the
    /// SAME path) allocates a brand-new OFD at offset 0 -- it does not
    /// alias the parent's inherited, already-advanced descriptor.
    #[cfg(target_pointer_width = "32")]
    #[test]
    fn fork_then_open_is_independent_ofd() {
        // SAFETY: test-only.
        unsafe {
            setup_test_vfs();
        }
        let path = b"/test.txt";
        let parent_fd = sys_open(path.as_ptr() as u32, path.len() as u32, 0);
        assert_eq!(parent_fd, 0);

        // Parent advances its offset by reading 5 bytes.
        static mut BUF: [u8; 5] = [0u8; 5];
        // SAFETY: test-only static; single-threaded per test.
        let buf = unsafe { &mut *core::ptr::addr_of_mut!(BUF) };
        assert_eq!(sys_read(parent_fd, buf.as_mut_ptr() as u32, 5), 5);

        let child_pid = crate::process::fork().expect("fork must succeed");
        // SAFETY: test-only; single-threaded test execution.
        unsafe {
            crate::process::set_current_for_test(child_pid);
        }

        // Child opens the SAME path fresh -- a brand-new OFD at offset 0,
        // not the parent's shared, already-advanced descriptor.
        let child_fd = sys_open(path.as_ptr() as u32, path.len() as u32, 0);
        assert_eq!(
            child_fd, 1,
            "child's fresh open lands on its own next-free slot (inherited fd 0 is taken)"
        );

        static mut BUF2: [u8; 5] = [0u8; 5];
        // SAFETY: test-only static; single-threaded per test.
        let buf2 = unsafe { &mut *core::ptr::addr_of_mut!(BUF2) };
        let n = sys_read(child_fd, buf2.as_mut_ptr() as u32, 5);
        assert_eq!(n, 5, "child's fresh open must start at offset 0");
        assert_eq!(
            &*buf2, b"Hello",
            "child's independent open reads from the start of the file"
        );

        // Parent's shared fd must be unaffected by the child's independent open.
        // SAFETY: test-only; single-threaded test execution.
        unsafe {
            crate::process::set_current_for_test(0);
        }
        static mut BUF3: [u8; 2] = [0u8; 2];
        // SAFETY: test-only static; single-threaded per test.
        let buf3 = unsafe { &mut *core::ptr::addr_of_mut!(BUF3) };
        assert_eq!(sys_read(parent_fd, buf3.as_mut_ptr() as u32, 2), 2);
        assert_eq!(
            &*buf3, b", ",
            "parent's own OFD offset must still be at 5, unaffected by the child's independent open"
        );
    }

    /// CWD-PER-PROCESS (#437): a chdir in one process never leaks into
    /// another, and fork inherits the parent's cwd (POSIX) — replacing the
    /// old global `CWD_BUF/CWD_LEN` statics where every process shared one cwd.
    #[cfg(target_pointer_width = "32")]
    #[test]
    fn chdir_is_per_process_and_fork_inherits() {
        // SAFETY: test-only.
        unsafe {
            setup_test_vfs();
        }

        // Parent chdirs to /dev; its cwd reads back.
        assert_eq!(vfs_chdir("/dev"), 0);
        crate::process::with_current_cwd(|c| assert_eq!(c, b"/dev"))
            .expect("current process must exist");

        // Fork: the child INHERITS /dev.
        let child_pid = crate::process::fork().expect("fork must succeed");
        // SAFETY: test-only; single-threaded test execution.
        unsafe {
            crate::process::set_current_for_test(child_pid);
        }
        crate::process::with_current_cwd(|c| {
            assert_eq!(c, b"/dev", "fork must inherit the parent's cwd")
        })
        .expect("child process must exist");

        // The child chdirs back to / — the parent's cwd is untouched.
        assert_eq!(vfs_chdir("/"), 0);
        // SAFETY: test-only; single-threaded test execution.
        unsafe {
            crate::process::set_current_for_test(0);
        }
        crate::process::with_current_cwd(|c| {
            assert_eq!(
                c, b"/dev",
                "a chdir in the child must never leak into the parent (the global-CWD bug, #437)"
            )
        })
        .expect("parent process must exist");

        // Restore for later tests.
        crate::process::set_current_cwd("/");
    }

    /// CWD-GETCWD-SYSCALL (#437): `sys_getcwd` reports the CURRENT process's
    /// cwd, not a shared global — after the child chdirs, parent and child
    /// read different paths from the same syscall.
    #[cfg(target_pointer_width = "32")]
    #[test]
    fn getcwd_reports_the_current_process_cwd() {
        // SAFETY: test-only.
        unsafe {
            setup_test_vfs();
        }
        assert_eq!(vfs_chdir("/dev"), 0);

        static mut BUFCWD: [u8; 8] = [0u8; 8];
        // SAFETY: test-only static; single-threaded per test.
        let buf = unsafe { &mut *core::ptr::addr_of_mut!(BUFCWD) };
        assert_eq!(sys_getcwd(buf.as_mut_ptr() as u32, 8), 0);
        assert_eq!(&buf[..4], b"/dev");

        let child_pid = crate::process::fork().expect("fork must succeed");
        // SAFETY: test-only; single-threaded test execution.
        unsafe {
            crate::process::set_current_for_test(child_pid);
        }
        assert_eq!(vfs_chdir("/"), 0);
        static mut BUFCWD2: [u8; 8] = [0u8; 8];
        // SAFETY: test-only static; single-threaded per test.
        let buf2 = unsafe { &mut *core::ptr::addr_of_mut!(BUFCWD2) };
        assert_eq!(sys_getcwd(buf2.as_mut_ptr() as u32, 8), 0);
        assert_eq!(&buf2[..1], b"/", "child reads its own cwd");

        // SAFETY: test-only; single-threaded test execution.
        unsafe {
            crate::process::set_current_for_test(0);
        }
        static mut BUFCWD3: [u8; 8] = [0u8; 8];
        // SAFETY: test-only static; single-threaded per test.
        let buf3 = unsafe { &mut *core::ptr::addr_of_mut!(BUFCWD3) };
        assert_eq!(sys_getcwd(buf3.as_mut_ptr() as u32, 8), 0);
        assert_eq!(&buf3[..4], b"/dev", "parent still reads its own cwd");

        crate::process::set_current_cwd("/");
    }

    /// CLOSE-ON-EXEC: `close_cloexec` sweeps ONLY fds marked `FD_CLOEXEC`
    /// (whether set at `open()` via `O_CLOEXEC` or later via `F_SETFD`) and
    /// leaves plain fds untouched; a dup of a cloexec fd never inherits the
    /// flag (POSIX).
    #[cfg(target_pointer_width = "32")]
    #[test]
    fn close_cloexec_sweeps_only_cloexec_fds_dup_clears_flag() {
        // SAFETY: test-only.
        unsafe {
            setup_test_vfs();
        }
        let path = b"/test.txt";

        // fd 0: plain open, no O_CLOEXEC.
        let plain_fd = sys_open(path.as_ptr() as u32, path.len() as u32, 0);
        assert_eq!(plain_fd, 0);

        // fd 1: opened with O_CLOEXEC directly.
        let cloexec_fd = sys_open(path.as_ptr() as u32, path.len() as u32, O_CLOEXEC);
        assert_eq!(cloexec_fd, 1);
        assert_eq!(sys_fcntl(cloexec_fd, F_GETFD, 0), FD_CLOEXEC);

        // fd 2: opened plain, THEN marked FD_CLOEXEC via F_SETFD.
        let setfd_cloexec_fd = sys_open(path.as_ptr() as u32, path.len() as u32, 0);
        assert_eq!(setfd_cloexec_fd, 2);
        assert_eq!(sys_fcntl(setfd_cloexec_fd, F_SETFD, FD_CLOEXEC), 0);
        assert_eq!(sys_fcntl(setfd_cloexec_fd, F_GETFD, 0), FD_CLOEXEC);

        // A dup of a cloexec fd must NOT inherit FD_CLOEXEC.
        let duped = sys_dup(cloexec_fd);
        assert_eq!(
            sys_fcntl(duped, F_GETFD, 0),
            0,
            "dup must never inherit FD_CLOEXEC"
        );

        // Sweep: only the two cloexec-marked fds close; the plain fd and
        // the cloexec-clear dup survive.
        let swept = crate::process::with_current_fds(close_cloexec);
        assert!(swept.is_some(), "current process must exist");

        static mut BUF: [u8; 4] = [0u8; 4];
        // SAFETY: test-only static; single-threaded per test.
        let buf = unsafe { &mut *core::ptr::addr_of_mut!(BUF) };
        assert_eq!(
            sys_read(cloexec_fd, buf.as_mut_ptr() as u32, 4),
            EBADF,
            "an O_CLOEXEC-opened fd must close on the sweep"
        );
        assert_eq!(
            sys_read(setfd_cloexec_fd, buf.as_mut_ptr() as u32, 4),
            EBADF,
            "an F_SETFD(FD_CLOEXEC)-marked fd must close on the sweep"
        );
        assert_eq!(
            sys_read(plain_fd, buf.as_mut_ptr() as u32, 4),
            4,
            "a plain fd (no cloexec) must survive the sweep"
        );
        assert_eq!(
            sys_read(duped, buf.as_mut_ptr() as u32, 4),
            4,
            "a dup with FD_CLOEXEC cleared must survive the sweep"
        );
    }

    /// CLOSE-ON-EXIT-FREES-OFD: the exit/fault teardown path (`close_all`)
    /// drains every fd in the current process's table and unrefs its OFD,
    /// freeing the slot.
    #[cfg(target_pointer_width = "32")]
    #[test]
    fn close_all_frees_both_ofds_on_exit() {
        // SAFETY: test-only.
        unsafe {
            setup_test_vfs();
        }
        let path = b"/test.txt";
        let fd0 = sys_open(path.as_ptr() as u32, path.len() as u32, 0);
        let fd1 = sys_open(path.as_ptr() as u32, path.len() as u32, 0);
        assert_eq!(fd0, 0);
        assert_eq!(fd1, 1);

        let ofd0 = resolve_fd(fd0 as usize).expect("fd0 resolves");
        let ofd1 = resolve_fd(fd1 as usize).expect("fd1 resolves");
        assert_eq!(ofd_refs(ofd0), Some(1));
        assert_eq!(ofd_refs(ofd1), Some(1));

        let drained = crate::process::with_current_fds(close_all);
        assert!(drained.is_some(), "current process must exist");

        assert_eq!(
            ofd_refs(ofd0),
            None,
            "exit-path close_all must free the first OFD"
        );
        assert_eq!(
            ofd_refs(ofd1),
            None,
            "exit-path close_all must free the second OFD"
        );

        static mut BUF: [u8; 1] = [0u8; 1];
        // SAFETY: test-only static; single-threaded per test.
        let buf = unsafe { &mut *core::ptr::addr_of_mut!(BUF) };
        assert_eq!(
            sys_read(fd0, buf.as_mut_ptr() as u32, 1),
            EBADF,
            "a closed fd must be unusable after close_all"
        );
    }

    /// DUP-SHARES-OFD: reading via the DUP advances the ORIGINAL's shared
    /// offset (the reverse direction from `dup_shares_offset_with_original`
    /// above), and `F_SETFL(O_APPEND)` through one fd is visible through the
    /// other -- both fds name one OFD's status flags, not a private copy.
    #[cfg(target_pointer_width = "32")]
    #[test]
    fn dup_shares_ofd_offset_and_status_flags() {
        // SAFETY: test-only.
        unsafe {
            setup_test_vfs();
        }
        let path = b"/test.txt"; // "Hello, thumos!" (14 bytes)
        let fd0 = sys_open(path.as_ptr() as u32, path.len() as u32, 0);
        assert_eq!(fd0, 0);
        let fd1 = sys_dup(fd0);
        assert_eq!(fd1, 1);

        // Reading via the dup must advance the ORIGINAL's shared offset.
        static mut BUF: [u8; 5] = [0u8; 5];
        // SAFETY: test-only static; single-threaded per test.
        let buf = unsafe { &mut *core::ptr::addr_of_mut!(BUF) };
        assert_eq!(sys_read(fd1, buf.as_mut_ptr() as u32, 5), 5);
        assert_eq!(&*buf, b"Hello");

        static mut BUF2: [u8; 2] = [0u8; 2];
        // SAFETY: test-only static; single-threaded per test.
        let buf2 = unsafe { &mut *core::ptr::addr_of_mut!(BUF2) };
        let n = sys_read(fd0, buf2.as_mut_ptr() as u32, 2);
        assert_eq!(
            n, 2,
            "read via the original must continue from the dup's advanced offset"
        );
        assert_eq!(&*buf2, b", ");

        // F_SETFL through one fd is visible through the other (shared OFD
        // status flags).
        assert_eq!(sys_fcntl(fd1, F_SETFL, O_APPEND), 0);
        assert_eq!(
            sys_fcntl(fd0, F_GETFL, 0) & O_APPEND,
            O_APPEND,
            "O_APPEND set via the dup must be visible through the original"
        );
    }

    /// REFCOUNT-FREE-AT-ZERO: an OFD's slot is freed only when its refcount
    /// reaches zero -- not at the first close -- and a subsequent open
    /// reuses the freed slot.
    #[cfg(target_pointer_width = "32")]
    #[test]
    fn ofd_refcount_frees_slot_only_at_zero_and_slot_is_reused() {
        // SAFETY: test-only.
        unsafe {
            setup_test_vfs();
        }
        let path = b"/test.txt";
        let fd0 = sys_open(path.as_ptr() as u32, path.len() as u32, 0);
        assert_eq!(fd0, 0);
        let ofd = resolve_fd(fd0 as usize).expect("fd0 resolves");
        assert_eq!(
            ofd_refs(ofd),
            Some(1),
            "a fresh open holds exactly one reference"
        );

        // WHY fork before dup: fork_table bumps the OFD refcount ONCE PER
        // COPIED FD ENTRY (a dup'd pair in the parent would earn the child
        // two bumps at once, not one), so forking a single-entry table
        // first isolates each +1 step: open (1) -> fork (2) -> dup-in-child (3).
        let child_pid = crate::process::fork().expect("fork must succeed");
        assert_eq!(
            ofd_refs(ofd),
            Some(2),
            "fork must add exactly one reference for the single inherited entry"
        );

        // SAFETY: test-only; single-threaded test execution.
        unsafe {
            crate::process::set_current_for_test(child_pid);
        }
        let child_dup = sys_dup(fd0);
        assert_eq!(child_dup, 1);
        assert_eq!(
            ofd_refs(ofd),
            Some(3),
            "a dup in the child must add exactly one more reference"
        );

        // Close all three holders; the slot must stay alive until the LAST one.
        assert_eq!(sys_close(child_dup), 0);
        assert_eq!(
            ofd_refs(ofd),
            Some(2),
            "closing one of three references must not free the OFD"
        );
        assert_eq!(sys_close(fd0), 0, "close the child's inherited copy of fd0");
        assert_eq!(
            ofd_refs(ofd),
            Some(1),
            "closing the second of three references must not free the OFD"
        );

        // SAFETY: test-only; single-threaded test execution.
        unsafe {
            crate::process::set_current_for_test(0);
        }
        assert_eq!(
            sys_close(fd0),
            0,
            "close the parent's original fd0 -- the last reference"
        );
        assert_eq!(
            ofd_refs(ofd),
            None,
            "the OFD must free only when the LAST reference closes"
        );

        // A later open must be able to reuse the freed OFD slot.
        let fd_new = sys_open(path.as_ptr() as u32, path.len() as u32, 0);
        assert_eq!(
            fd_new, 0,
            "parent's fd table is fully drained; the new open reuses fd 0"
        );
        let ofd_new = resolve_fd(fd_new as usize).expect("new fd resolves");
        assert_eq!(
            ofd_new, ofd,
            "the freed OFD slot must be reused by the next open"
        );
        assert_eq!(ofd_refs(ofd_new), Some(1));
    }

    /// DUP2-UNREF-DISPLACED: dup2 onto an already-open target fd unrefs the
    /// DISPLACED OFD (never leaks it), and dup2(fd, fd) is a documented
    /// no-op that leaves the refcount untouched.
    #[cfg(target_pointer_width = "32")]
    #[test]
    fn dup2_unrefs_displaced_target_and_self_dup_is_noop() {
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

        let ofd0 = resolve_fd(fd0 as usize).expect("fd0 resolves");
        let ofd1 = resolve_fd(fd1 as usize).expect("fd1 resolves");
        assert_eq!(ofd_refs(ofd1), Some(1));

        // dup2(fd0, fd1) displaces fd1's original target -- its OFD must free.
        let result = sys_dup2(fd0, fd1);
        assert_eq!(result, 1);
        assert_eq!(
            ofd_refs(ofd1),
            None,
            "dup2 must unref the displaced target's OFD"
        );
        assert_eq!(ofd_refs(ofd0), Some(2), "fd1 now shares fd0's OFD");
        assert_eq!(
            resolve_fd(fd1 as usize),
            Some(ofd0),
            "fd1 must now resolve to fd0's OFD"
        );

        // dup2(fd, fd) is a documented no-op -- refcount must be untouched.
        let self_dup = sys_dup2(fd0, fd0);
        assert_eq!(self_dup, fd0);
        assert_eq!(
            ofd_refs(ofd0),
            Some(2),
            "dup2(fd, fd) must not change the refcount"
        );
    }
}
