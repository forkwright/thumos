//! Pipe subsystem: unidirectional byte-stream IPC.
//!
//! A pipe is a fixed-size ring buffer shared between a write end and a read
//! end. Each end is represented as a file descriptor in the global FD table.
//! Pipes are identified by a pipe index (0-7); the FD kind field encodes
//! which pipe and which end (read vs. write).
//!
//! # Buffer policy
//! - Write when full: return EAGAIN (non-blocking; future work adds blocking).
//! - Read when empty and write end is open: return EAGAIN.
//! - Read when empty and write end is closed: return 0 (EOF).
//! - Write when read end is closed: deliver SIGPIPE to the writer and return EPIPE.
//!
//! WHY static array of 8 pipes: avoids heap allocation, consistent with the
//! rest of the kernel's fixed-size-table pattern. 8 concurrent pipes is
//! sufficient for an early `BusyBox` shell (pipelines have at most 2-3 stages).

use crate::fd::EMFILE;
// Signal is only used in the #[cfg(not(test))] SIGPIPE delivery block.
// Keep the import unconditional to avoid dead_code noise; the compiler will
// drop it in test builds since Signal types are not exported from test-only paths.
#[cfg(not(test))]
use crate::signal::Signal;

/// Maximum number of simultaneously open pipes.
pub(crate) const MAX_PIPES: usize = 8;

/// Pipe buffer size: one 4 KB page.
pub(crate) const PIPE_BUF_SIZE: usize = 4096;

/// EAGAIN — operation would block (two's complement -11, Linux ARM convention).
pub(crate) const EAGAIN: u32 = 0u32.wrapping_sub(11);

/// EPIPE — broken pipe (two's complement -32, Linux ARM convention).
pub(crate) const EPIPE: u32 = 0u32.wrapping_sub(32);

/// EBADF — bad file descriptor (two's complement -9, Linux ARM convention).
pub(crate) const EBADF: u32 = crate::fd::EBADF;

/// EFAULT — bad address (two's complement -14, Linux ARM convention).
pub(crate) const EFAULT: u32 = crate::fd::EFAULT;

/// A pipe's internal ring buffer.
pub(crate) struct PipeBuffer {
    data: [u8; PIPE_BUF_SIZE],
    /// Index of the next byte to read.
    read_pos: usize,
    /// Index of the next byte to write.
    write_pos: usize,
    /// Number of bytes currently in the buffer.
    count: usize,
    /// True once the write end has been closed.
    pub write_closed: bool,
    /// True once the read end has been closed.
    pub read_closed: bool,
    /// PID of the process that created this pipe -- used by
    /// `alloc_pipe_slot` to enforce `MAX_PIPES_PER_PROCESS`.
    owner_pid: u8,
}

impl PipeBuffer {
    const fn new(owner_pid: u8) -> Self {
        Self {
            data: [0u8; PIPE_BUF_SIZE],
            read_pos: 0,
            write_pos: 0,
            count: 0,
            write_closed: false,
            read_closed: false,
            owner_pid,
        }
    }

    /// Write bytes into the buffer. Returns the number of bytes written, or 0 if full.
    pub(crate) fn write(&mut self, src: &[u8]) -> usize {
        let space = PIPE_BUF_SIZE - self.count;
        if space == 0 {
            return 0;
        }
        let to_write = src.len().min(space);
        for &b in &src[..to_write] {
            self.data[self.write_pos] = b;
            self.write_pos = (self.write_pos + 1) % PIPE_BUF_SIZE;
        }
        self.count += to_write;
        to_write
    }

    /// Read bytes from the buffer. Returns the number of bytes read.
    pub(crate) fn read(&mut self, dst: &mut [u8]) -> usize {
        if self.count == 0 {
            return 0;
        }
        let to_read = dst.len().min(self.count);
        for slot in &mut dst[..to_read] {
            *slot = self.data[self.read_pos];
            self.read_pos = (self.read_pos + 1) % PIPE_BUF_SIZE;
        }
        self.count -= to_read;
        to_read
    }

    /// Bytes currently available to read.
    pub(crate) fn available(&self) -> usize {
        self.count
    }

    /// Whether the buffer is full.
    pub(crate) fn is_full(&self) -> bool {
        self.count == PIPE_BUF_SIZE
    }
}

/// Global pipe buffer pool.
static mut PIPE_POOL: [Option<PipeBuffer>; MAX_PIPES] = {
    const NONE: Option<PipeBuffer> = None;
    [NONE; MAX_PIPES]
};

/// Maximum pipes a single process may have open at once, so one process
/// cannot exhaust the entire `MAX_PIPES` pool and starve every other
/// process of pipe fds.
const MAX_PIPES_PER_PROCESS: usize = 4;

/// Allocate a new pipe slot for `owner_pid`. Returns the pipe index, or
/// `None` if all slots are taken, or if `owner_pid` already holds
/// `MAX_PIPES_PER_PROCESS` pipes.
fn alloc_pipe_slot(owner_pid: u8) -> Option<usize> {
    // SAFETY: single-core cooperative kernel; no concurrent mutation.
    // addr_of_mut! avoids creating a reference to the static mut.
    let pool = unsafe { &mut *core::ptr::addr_of_mut!(PIPE_POOL) };

    let owned_count = pool
        .iter()
        .filter(|slot| slot.as_ref().is_some_and(|buf| buf.owner_pid == owner_pid))
        .count();
    if owned_count >= MAX_PIPES_PER_PROCESS {
        return None;
    }

    for (i, slot) in pool.iter_mut().enumerate() {
        if slot.is_none() {
            *slot = Some(PipeBuffer::new(owner_pid));
            return Some(i);
        }
    }
    None
}

/// Borrow the pipe buffer at `pipe_idx` mutably.
///
/// # Safety
///
/// `pipe_idx` must be in bounds and the slot must be `Some`. The caller
/// must not alias this reference with any other access to the same slot.
unsafe fn get_pipe_mut(pipe_idx: usize) -> Option<&'static mut PipeBuffer> {
    // SAFETY: caller contract above.
    let pool = unsafe { &mut *core::ptr::addr_of_mut!(PIPE_POOL) };
    pool[pipe_idx].as_mut()
}

/// Free a pipe slot if both ends are closed.
fn maybe_free_pipe(pipe_idx: usize) {
    // SAFETY: single-core cooperative kernel; no concurrent mutation.
    let pool = unsafe { &mut *core::ptr::addr_of_mut!(PIPE_POOL) };
    if let Some(ref buf) = pool[pipe_idx]
        && buf.write_closed
        && buf.read_closed
    {
        pool[pipe_idx] = None;
    }
}

// ---------------------------------------------------------------------------
// FD kind encoding
// ---------------------------------------------------------------------------
//
// The existing FileDescriptor struct holds data_ptr/data_len/offset/flags.
// We repurpose the flags field to encode pipe identity:
//
//   flags & FD_KIND_MASK == FD_KIND_PIPE  →  this fd is a pipe end
//   (flags >> 8) & 0xFF                  →  pipe index (0-7)
//   flags & FD_END_MASK                  →  0 = read end, 1 = write end
//
// data_ptr is set to null and data_len is set to 0. The fd::sys_read /
// sys_write callers in fd.rs do not know about pipes — we intercept at the
// pipe-specific sys_pipe_read/write level before the generic fd layer.
//
// WHY repurpose flags: avoids modifying the FileDescriptor struct (which
// would require touching every existing syscall). The kernel's cooperative
// single-core model means no race between flag read and pipe access.

pub(crate) const FD_KIND_MASK: u32 = 0x00FF;
pub(crate) const FD_KIND_PIPE: u32 = 0x0001;
pub(crate) const FD_END_MASK: u32 = 0x0100;
pub(crate) const FD_END_READ: u32 = 0x0000;
pub(crate) const FD_END_WRITE: u32 = 0x0100;
pub(crate) const FD_PIPE_IDX_SHIFT: u32 = 9;

/// Encode a pipe fd flags word.
pub(crate) fn pipe_flags(pipe_idx: usize, end: u32) -> u32 {
    FD_KIND_PIPE | end | ((pipe_idx as u32) << FD_PIPE_IDX_SHIFT)
}

/// Extract the pipe index from an fd flags word.
///
/// WHY 0x07 not 0x7F: the previous 7-bit mask (max 127) did not match
/// `MAX_PIPES` (8 slots) -- a flags word with any of bits 12-15 set would
/// decode to an out-of-range pipe index and panic on the array index in
/// `get_pipe_mut/on_pipe_fd_closed/maybe_free_pipe`. This mask covers
/// exactly the valid `0..MAX_PIPES` range.
pub(crate) fn pipe_idx_from_flags(flags: u32) -> usize {
    ((flags >> FD_PIPE_IDX_SHIFT) & 0x07) as usize
}

/// Return true if the fd flags word identifies a pipe fd.
pub(crate) fn is_pipe_fd(flags: u32) -> bool {
    (flags & FD_KIND_MASK) == FD_KIND_PIPE
}

/// Return true if the fd flags word identifies the write end.
pub(crate) fn is_write_end(flags: u32) -> bool {
    (flags & FD_END_MASK) == FD_END_WRITE
}

// ---------------------------------------------------------------------------
// Syscall implementation
// ---------------------------------------------------------------------------

/// `SYS_pipe`: create a pipe and write two fd numbers to userspace.
///
/// # Arguments
/// - `fds_ptr`: pointer to a `[u32; 2]` in userspace.
///   `fds[0]` = read end fd, `fds[1]` = write end fd.
///
/// # Returns
/// 0 on success, negative error code on failure.
// WHY: `read_ofd`/`write_ofd` (open-file-description table indices) and
// `read_fd`/`write_fd` (the per-process fd numbers derived from them) are
// standard POSIX fd/ofd terminology naming two genuinely distinct values --
// renaming either pair to defeat the Levenshtein check would decouple the
// names from the concepts they name.
#[expect(
    clippy::similar_names,
    reason = "read_ofd/write_ofd (open-file-description table indices) and read_fd/write_fd (the per-process fd numbers derived from them) are standard POSIX fd/ofd terminology naming two genuinely distinct values -- renaming either pair to defeat the Levenshtein check would decouple the names from the concepts they name"
)]
/// Byte length of the two-`u32` fd pair written back to the caller.
const FDS_OUT_LEN: usize = 2 * core::mem::size_of::<u32>();

pub(crate) fn sys_pipe(fds_ptr: u32) -> u32 {
    // Write: both fd numbers are copied INTO the caller's buffer, so the whole
    // eight-byte range must be mapped by this process and PL0-writable.
    //
    // WHY this precedes every allocation rather than sitting next to the write
    // it guards: the ordering is the security property. Validating late would
    // still reject the pointer, but only after a pipe slot, two open-file
    // descriptions and two fd-table entries had been created and then had to be
    // unwound — turning a bad pointer into a way to churn the pool. Rejecting
    // first means a failed call costs nothing and leaves nothing behind.
    //
    // The null case is covered here too: the numeric gate inside
    // `validate_user_range` rejects a null pointer, so a separate check would
    // be a second answer to a question this one already answers.
    if !crate::memguard::validate_user_range(
        fds_ptr as usize,
        FDS_OUT_LEN,
        crate::memguard::Access::Write,
    ) {
        return EFAULT;
    }

    // Allocate a pipe buffer slot, capped per-process (MAX_PIPES_PER_PROCESS)
    // so one process cannot exhaust the entire pool.
    let owner_pid = crate::process::current_pid();
    let Some(pipe_idx) = alloc_pipe_slot(owner_pid) else {
        return EMFILE;
    };

    // Two-level alloc (#267): one OFD per pipe end (refs=1 each), then
    // install both ends in the CURRENT process's fd table.
    let free_pipe_slot = || {
        // SAFETY: we just created the slot; rollback is idempotent even if
        // ofd_unref teardown already released it.
        unsafe {
            let pool = &mut *core::ptr::addr_of_mut!(PIPE_POOL);
            pool[pipe_idx] = None;
        }
    };

    let read_desc = crate::fd::FileDescriptor::new(&[], pipe_flags(pipe_idx, FD_END_READ));
    let write_desc = crate::fd::FileDescriptor::new(&[], pipe_flags(pipe_idx, FD_END_WRITE));

    let Some(read_ofd) = crate::fd::ofd_alloc(read_desc) else {
        free_pipe_slot();
        return EMFILE;
    };
    let Some(write_ofd) = crate::fd::ofd_alloc(write_desc) else {
        crate::fd::ofd_unref(read_ofd);
        free_pipe_slot();
        return EMFILE;
    };

    let installed = crate::process::with_current_fds(|t| {
        let r = t.alloc(crate::fd::FdEntry {
            ofd: read_ofd,
            cloexec: false,
        })?;
        let Some(w) = t.alloc(crate::fd::FdEntry {
            ofd: write_ofd,
            cloexec: false,
        }) else {
            t.take(r);
            return None;
        };
        Some((r, w))
    })
    .flatten();

    let Some((read_fd, write_fd)) = installed else {
        crate::fd::ofd_unref(read_ofd);
        crate::fd::ofd_unref(write_ofd);
        free_pipe_slot();
        return EMFILE;
    };
    let (read_fd, write_fd) = (read_fd as u32, write_fd as u32);

    // Write the two fd numbers to userspace.
    // SAFETY: the whole eight-byte range was validated at entry against the
    // caller's own page tables with PL0 write permission, so both stores land
    // in memory this process maps and may write. The pointer alignment is NOT
    // guaranteed by the ABI (POSIX allows any alignment for char-typed buffers
    // -- the same reasoning time::sys_clock_gettime documents for its own
    // userspace writes), so write_unaligned is required: a plain
    // core::ptr::write on a misaligned fds_ptr is undefined behavior and can
    // fault on ARM.
    unsafe {
        let fds = fds_ptr as *mut u32;
        core::ptr::write_unaligned(fds, read_fd);
        core::ptr::write_unaligned(fds.add(1), write_fd);
    }

    0
}

/// `SYS_read` on a pipe fd.
///
/// Called from the generic `sys_read` path when the fd is detected as a pipe.
///
/// # Returns
/// Bytes read on success, 0 on EOF, negative error code on failure.
pub(crate) fn sys_pipe_read(pipe_idx: usize, buf_ptr: u32, count: u32) -> u32 {
    let count = count as usize;
    if buf_ptr == 0 {
        return EFAULT;
    }

    // SAFETY: single-core cooperative kernel; no concurrent mutation of pipe pool.
    let Some(buf) = (unsafe { get_pipe_mut(pipe_idx) }) else {
        return EBADF;
    };

    if buf.available() == 0 {
        if buf.write_closed {
            // EOF
            return 0;
        }
        // Data not yet available, write end still open.
        return EAGAIN;
    }

    // Write: pipe data is copied INTO the caller's buffer, so every page must
    // be mapped by this process and PL0-writable. Placed after the EOF/EAGAIN
    // early returns so a bad pointer is only rejected once the read would
    // actually dereference it.
    if !crate::memguard::validate_user_range(
        buf_ptr as usize,
        count,
        crate::memguard::Access::Write,
    ) {
        return EFAULT;
    }
    // SAFETY: validated above against the caller's own page tables with PL0
    // write permission, so all `count` bytes are mapped and writable.
    let dst = unsafe { core::slice::from_raw_parts_mut(buf_ptr as *mut u8, count) };
    buf.read(dst) as u32
}

/// `SYS_write` on a pipe fd.
///
/// Called from the generic `sys_write` path when the fd is detected as a pipe.
/// `writer_pid` is the PID of the calling process (for SIGPIPE delivery).
///
/// # Returns
/// Bytes written on success, negative error code on failure.
pub(crate) fn sys_pipe_write(pipe_idx: usize, buf_ptr: u32, count: u32, writer_pid: u8) -> u32 {
    let count = count as usize;
    if buf_ptr == 0 {
        return EFAULT;
    }

    // SAFETY: single-core cooperative kernel; no concurrent mutation.
    let Some(buf) = (unsafe { get_pipe_mut(pipe_idx) }) else {
        return EBADF;
    };

    if buf.read_closed {
        // Deliver SIGPIPE to the writer and return EPIPE.
        // WHY cfg(not(test)): crate::process is not compiled under test
        // (requires ARM + full kernel environment). The EPIPE return is
        // always correct; signal delivery is a best-effort side effect.
        #[cfg(not(test))]
        unsafe {
            // SAFETY: deliver_signal_to accesses PROCS via addr_of_mut!.
            // Single-core kernel; no concurrent access.
            crate::process::deliver_signal_to(writer_pid, Signal::Sigpipe);
        }
        #[cfg(test)]
        let _ = writer_pid; // suppress unused warning in test builds
        return EPIPE;
    }

    if buf.is_full() {
        return EAGAIN;
    }

    // Read: the payload is copied OUT of the caller's buffer, so every page
    // must be mapped by this process and PL0-readable. Placed after the
    // EPIPE/EAGAIN early returns.
    if !crate::memguard::validate_user_range(buf_ptr as usize, count, crate::memguard::Access::Read)
    {
        return EFAULT;
    }
    // SAFETY: validated above against the caller's own page tables with PL0
    // read permission, so all `count` bytes are mapped and readable.
    let src = unsafe { core::slice::from_raw_parts(buf_ptr as *const u8, count) };
    buf.write(src) as u32
}

/// Called from `sys_close` when a pipe fd is closed.
/// Marks the appropriate end closed and frees the slot if both ends are gone.
pub fn on_pipe_fd_closed(pipe_idx: usize, end_is_write: bool) {
    // SAFETY: single-core cooperative kernel; no concurrent mutation.
    let pool = unsafe { &mut *core::ptr::addr_of_mut!(PIPE_POOL) };
    if let Some(ref mut buf) = pool[pipe_idx] {
        if end_is_write {
            buf.write_closed = true;
        } else {
            buf.read_closed = true;
        }
    }
    maybe_free_pipe(pipe_idx);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Reset the pipe pool between tests.
    fn reset_pool() {
        unsafe {
            let pool = &mut *core::ptr::addr_of_mut!(PIPE_POOL);
            for slot in pool.iter_mut() {
                *slot = None;
            }
        }
    }

    /// Count occupied pipe slots — the observable that proves a rejected
    /// `sys_pipe` allocated nothing (#868).
    fn occupied_slots() -> usize {
        // SAFETY: test-only; single-threaded per test.
        unsafe {
            let pool = &*core::ptr::addr_of!(PIPE_POOL);
            pool.iter().filter(|slot| slot.is_some()).count()
        }
    }

    #[test]
    fn pipe_idx_from_flags_masks_out_of_range_bits() {
        // Bits 12-15 (which the old 0x7F mask would have included) must
        // not leak into the decoded pipe index -- it must stay within
        // 0..MAX_PIPES.
        let flags = pipe_flags(3, FD_END_READ) | (0xF << 12);
        assert!(
            pipe_idx_from_flags(flags) < MAX_PIPES,
            "decoded pipe index must never exceed MAX_PIPES - 1"
        );
        assert_eq!(
            pipe_idx_from_flags(flags),
            3,
            "high garbage bits must not corrupt the real pipe index"
        );
    }

    #[test]
    fn pipe_creates_two_fds() {
        // WHY function-local `static mut` rather than a stack array (#868):
        // sys_pipe now validates the full writable range, and this binary's PIE
        // image -- hence any `static` -- loads inside
        // [board::KERNEL_END, board::RAM_END) on this host toolchain, while the
        // per-test-thread stack sits above RAM_END. A stack buffer would be
        // rejected before pipe() ran. Same pattern as the fd/socket tests.
        static mut FDS: [u32; 2] = [0u32; 2];
        // Reset the pipe pool and establish a fresh current process (#267).
        reset_pool();
        unsafe {
            crate::fd::reset_fd_state_for_test();
        }

        let result = sys_pipe(core::ptr::addr_of_mut!(FDS) as u32);
        assert_eq!(result, 0, "pipe() should succeed");

        // SAFETY: test-only static; single-threaded per test.
        let fds = unsafe { &*core::ptr::addr_of!(FDS) };
        // Both fds should be valid (different) numbers in range [0, MAX_FDS).
        let (read_fd, write_fd) = (fds[0] as usize, fds[1] as usize);
        assert!(read_fd < crate::fd::MAX_FDS, "read fd must be in range");
        assert!(write_fd < crate::fd::MAX_FDS, "write fd must be in range");
        assert_ne!(read_fd, write_fd, "read and write fds must differ");
    }

    #[test]
    fn pipe_writes_fds_to_unaligned_userspace_pointer() {
        reset_pool();
        unsafe {
            crate::fd::reset_fd_state_for_test();
        }

        // Deliberately misaligned: offset 1 byte into the buffer, so a
        // plain core::ptr::write (which requires u32 alignment) would be
        // undefined behavior. write_unaligned must handle this correctly.
        // Static rather than stack for the reason given in
        // `pipe_creates_two_fds`; the +1 offset stays inside the same page.
        static mut FDS_BUF: [u8; 9] = [0u8; 9];
        let unaligned_ptr = core::ptr::addr_of_mut!(FDS_BUF)
            .cast::<u8>()
            .wrapping_add(1);
        let result = sys_pipe(unaligned_ptr as u32);
        assert_eq!(
            result, 0,
            "pipe() must succeed even with an unaligned fds pointer"
        );

        let read_fd = unsafe { core::ptr::read_unaligned(unaligned_ptr as *const u32) };
        let write_fd = unsafe { core::ptr::read_unaligned(unaligned_ptr.add(4) as *const u32) };
        assert!((read_fd as usize) < crate::fd::MAX_FDS);
        assert!((write_fd as usize) < crate::fd::MAX_FDS);
        assert_ne!(read_fd, write_fd);
    }

    #[test]
    fn pipe_write_read_round_trip() {
        reset_pool();

        // Allocate a pipe slot directly for test isolation.
        let pipe_idx = alloc_pipe_slot(0).expect("alloc pipe");

        let message = b"hello from pipe";
        let written = unsafe {
            let buf = get_pipe_mut(pipe_idx).unwrap();
            buf.write(message)
        };
        assert_eq!(written, message.len(), "all bytes should be written");

        let mut dst = [0u8; 64];
        let read_n = unsafe {
            let buf = get_pipe_mut(pipe_idx).unwrap();
            buf.read(&mut dst)
        };
        assert_eq!(
            read_n,
            message.len(),
            "should read back same number of bytes"
        );
        assert_eq!(&dst[..read_n], message, "data should match");
    }

    #[test]
    fn pipe_eof_on_write_close() {
        reset_pool();

        let pipe_idx = alloc_pipe_slot(0).expect("alloc pipe");

        // Close the write end.
        on_pipe_fd_closed(pipe_idx, true /* write end */);

        // Buffer is empty and write end is closed → read returns 0 (EOF).
        let mut dst = [0u8; 16];
        let result = sys_pipe_read(pipe_idx, dst.as_mut_ptr() as u32, 16);
        assert_eq!(result, 0, "read after write-close should return EOF (0)");
    }

    #[test]
    fn pipe_read_eagain_when_empty_write_open() {
        reset_pool();

        let pipe_idx = alloc_pipe_slot(0).expect("alloc pipe");
        // Write end is still open (default), buffer empty.
        let mut dst = [0u8; 8];
        let result = sys_pipe_read(pipe_idx, dst.as_mut_ptr() as u32, 8);
        assert_eq!(result, EAGAIN, "empty pipe with open write end → EAGAIN");
    }

    #[test]
    fn pipe_write_full_returns_eagain() {
        reset_pool();

        let pipe_idx = alloc_pipe_slot(0).expect("alloc pipe");

        // Fill the buffer.
        unsafe {
            let buf = get_pipe_mut(pipe_idx).unwrap();
            let full_data = [0xAAu8; PIPE_BUF_SIZE];
            let written = buf.write(&full_data);
            assert_eq!(written, PIPE_BUF_SIZE);
        }

        // Next write should return EAGAIN.
        let more = [0u8; 1];
        let result = sys_pipe_write(pipe_idx, more.as_ptr() as u32, 1, 0);
        assert_eq!(result, EAGAIN, "write to full pipe → EAGAIN");
    }

    /// The property this issue is actually about: rejection happens BEFORE any
    /// allocation. The return value alone does not establish that — validating
    /// after allocation would return the same `EFAULT` while leaving a pipe
    /// slot, two open-file descriptions and two fd-table entries to unwind. So
    /// the assertion that carries the fix is the pool count, not the errno.
    #[test]
    fn pipe_rejects_a_bad_pointer_without_allocating_a_slot() {
        reset_pool();
        unsafe {
            crate::fd::reset_fd_state_for_test();
        }
        assert_eq!(occupied_slots(), 0, "fixture must start with an empty pool");

        assert_eq!(
            sys_pipe(crate::board::KERNEL_LOAD as u32),
            EFAULT,
            "a kernel-range fds_ptr must be refused"
        );
        assert_eq!(
            occupied_slots(),
            0,
            "a refused pipe() must leave no pipe slot behind"
        );
    }

    #[test]
    fn pipe_rejects_the_fds_pointer_range_adversarially() {
        reset_pool();
        unsafe {
            crate::fd::reset_fd_state_for_test();
        }

        // Null: covered by the numeric gate inside validate_user_range, so no
        // separate null check is needed in sys_pipe.
        assert_eq!(sys_pipe(0), EFAULT, "null fds_ptr must be refused");
        // Device MMIO.
        assert_eq!(
            sys_pipe(0x1100_2000),
            EFAULT,
            "MMIO fds_ptr must be refused"
        );
        // Kernel image.
        assert_eq!(
            sys_pipe(crate::board::KERNEL_LOAD as u32),
            EFAULT,
            "kernel-image fds_ptr must be refused"
        );
        // Straddling the top of DRAM: the first four bytes are in range and the
        // second four are not. A check that validated only the starting address,
        // or only one u32, would accept this and write past the end of RAM.
        let straddle = (crate::board::RAM_END - 4) as u32;
        assert_eq!(
            sys_pipe(straddle),
            EFAULT,
            "a range crossing RAM_END must be refused even though its first word is in range"
        );
        // Wrapping: ptr + 8 overflows the 32-bit address space.
        assert_eq!(
            sys_pipe(u32::MAX - 3),
            EFAULT,
            "a wrapping fds_ptr range must be refused"
        );

        assert_eq!(
            occupied_slots(),
            0,
            "none of the refused calls may allocate a slot"
        );
    }

    #[test]
    fn pipe_read_rejects_kernel_range_buffer() {
        reset_pool();
        let pipe_idx = alloc_pipe_slot(0).expect("alloc pipe");
        // Make data available so the read reaches buffer validation rather than
        // short-circuiting on EAGAIN/EOF.
        unsafe {
            let buf = get_pipe_mut(pipe_idx).unwrap();
            assert_eq!(buf.write(b"data"), 4);
        }
        // A pointer inside the kernel image must be rejected before any deref.
        let kernel_ptr = crate::board::KERNEL_LOAD as u32;
        let result = sys_pipe_read(pipe_idx, kernel_ptr, 4);
        assert_eq!(result, EFAULT, "kernel-range buf_ptr must return EFAULT");
    }

    #[test]
    fn pipe_write_rejects_kernel_range_buffer() {
        reset_pool();
        let pipe_idx = alloc_pipe_slot(0).expect("alloc pipe");
        // Buffer empty and both ends open, so the write reaches validation.
        let kernel_ptr = crate::board::KERNEL_LOAD as u32;
        let result = sys_pipe_write(pipe_idx, kernel_ptr, 4, 0);
        assert_eq!(result, EFAULT, "kernel-range buf_ptr must return EFAULT");
    }

    #[test]
    fn pipe_flag_encoding_round_trips() {
        let flags = pipe_flags(3, FD_END_WRITE);
        assert!(is_pipe_fd(flags));
        assert!(is_write_end(flags));
        assert_eq!(pipe_idx_from_flags(flags), 3);

        let flags_r = pipe_flags(7, FD_END_READ);
        assert!(is_pipe_fd(flags_r));
        assert!(!is_write_end(flags_r));
        assert_eq!(pipe_idx_from_flags(flags_r), 7);
    }

    #[test]
    fn alloc_pipe_slot_enforces_per_process_cap() {
        reset_pool();
        for _ in 0..MAX_PIPES_PER_PROCESS {
            assert!(
                alloc_pipe_slot(1).is_some(),
                "must allow up to the per-process cap"
            );
        }
        assert!(
            alloc_pipe_slot(1).is_none(),
            "must reject a pipe past the per-process cap even though pool slots remain"
        );
        // A different process must still be able to allocate -- the pool
        // has MAX_PIPES - MAX_PIPES_PER_PROCESS slots free.
        assert!(
            alloc_pipe_slot(2).is_some(),
            "a different process must not be starved by another process's cap"
        );
    }

    /// PIPE-DUP-CLOSE: teardown fires at OFD refcount ZERO, not at the
    /// first close of the write end. Dup'ing the write end must delay EOF
    /// until every write-end reference is closed (#267).
    #[cfg(target_pointer_width = "32")]
    #[test]
    fn dup_of_pipe_write_end_delays_eof_until_last_close() {
        static mut FDS: [u32; 2] = [0, 0];
        static mut BUF: [u8; 8] = [0u8; 8];
        reset_pool();
        // SAFETY: test-only; establishes a fresh current process for
        // sys_pipe/sys_dup/sys_close to install fds into.
        unsafe {
            crate::fd::reset_fd_state_for_test();
        }

        let fds_ptr = core::ptr::addr_of_mut!(FDS) as u32;
        assert_eq!(sys_pipe(fds_ptr), 0, "pipe() should succeed");
        // SAFETY: test-only static; single-threaded per test.
        let (read_fd, write_fd) = unsafe {
            let fds = &*core::ptr::addr_of!(FDS);
            (fds[0], fds[1])
        };

        // Dup the write end: two fds now reference the SAME OFD (refs=2).
        let write_dup = crate::fd::sys_dup(write_fd);
        assert!(
            write_dup < crate::fd::MAX_FDS as u32,
            "dup of the write end must succeed"
        );

        let flags = crate::fd::current_fd_flags(read_fd as usize).expect("read fd must resolve");
        let pipe_idx = pipe_idx_from_flags(flags);

        // Close the ORIGINAL write fd; the dup still holds a reference, so
        // the reader must NOT see EOF yet -- teardown fires at refcount
        // ZERO, not at the first close of the write end.
        assert_eq!(crate::fd::sys_close(write_fd), 0);

        // SAFETY: test-only static; single-threaded per test.
        let buf = unsafe { &mut *core::ptr::addr_of_mut!(BUF) };
        assert_eq!(
            sys_pipe_read(pipe_idx, buf.as_mut_ptr() as u32, 8),
            EAGAIN,
            "the reader must not see EOF while the dup keeps the write end alive"
        );

        // Close the dup too -- the write-end refcount now reaches zero and
        // the pipe's write-closed flag is set; the reader must observe EOF.
        assert_eq!(crate::fd::sys_close(write_dup), 0);
        assert_eq!(
            sys_pipe_read(pipe_idx, buf.as_mut_ptr() as u32, 8),
            0,
            "EOF must appear only after the LAST write-end reference closes"
        );
    }
}
