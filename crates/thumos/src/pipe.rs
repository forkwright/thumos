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
//! sufficient for an early BusyBox shell (pipelines have at most 2-3 stages).

use crate::fd::{FdTable, EMFILE};
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
}

impl PipeBuffer {
    const fn new() -> Self {
        Self {
            data: [0u8; PIPE_BUF_SIZE],
            read_pos: 0,
            write_pos: 0,
            count: 0,
            write_closed: false,
            read_closed: false,
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

/// Allocate a new pipe slot. Returns the pipe index, or None if all slots taken.
fn alloc_pipe_slot() -> Option<usize> {
    // SAFETY: single-core cooperative kernel; no concurrent mutation.
    // addr_of_mut! avoids creating a reference to the static mut.
    let pool = unsafe { &mut *core::ptr::addr_of_mut!(PIPE_POOL) };
    for (i, slot) in pool.iter_mut().enumerate() {
        if slot.is_none() {
            *slot = Some(PipeBuffer::new());
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
    if let Some(ref buf) = pool[pipe_idx] {
        if buf.write_closed && buf.read_closed {
            pool[pipe_idx] = None;
        }
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
pub(crate) fn pipe_idx_from_flags(flags: u32) -> usize {
    ((flags >> FD_PIPE_IDX_SHIFT) & 0x7F) as usize
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

/// SYS_pipe: create a pipe and write two fd numbers to userspace.
///
/// # Arguments
/// - `fds_ptr`: pointer to a `[u32; 2]` in userspace.
///   `fds[0]` = read end fd, `fds[1]` = write end fd.
///
/// # Returns
/// 0 on success, negative error code on failure.
pub(crate) fn sys_pipe(fds_ptr: u32) -> u32 {
    if fds_ptr == 0 {
        return EFAULT;
    }

    // Allocate a pipe buffer slot.
    let pipe_idx = match alloc_pipe_slot() {
        Some(i) => i,
        None => return EMFILE,
    };

    // Allocate two fd slots.
    // SAFETY: FD_TABLE is a global static; addr_of_mut! avoids an intermediate
    // reference. Single-core cooperative kernel ensures exclusive access.
    let table = unsafe { &mut *core::ptr::addr_of_mut!(crate::fd::FD_TABLE) };

    let read_fd = alloc_pipe_fd(table, pipe_idx, FD_END_READ);
    let write_fd = alloc_pipe_fd(table, pipe_idx, FD_END_WRITE);

    let (read_fd, write_fd) = match (read_fd, write_fd) {
        (Some(r), Some(w)) => (r as u32, w as u32),
        (Some(r), None) => {
            table.close(r);
            // SAFETY: we just created the slot and no write end was allocated yet.
            unsafe {
                let pool = &mut *core::ptr::addr_of_mut!(PIPE_POOL);
                pool[pipe_idx] = None;
            }
            return EMFILE;
        }
        _ => {
            // SAFETY: we just created the slot; no fds were allocated.
            unsafe {
                let pool = &mut *core::ptr::addr_of_mut!(PIPE_POOL);
                pool[pipe_idx] = None;
            }
            return EMFILE;
        }
    };

    // Write the two fd numbers to userspace.
    // SAFETY: fds_ptr is validated non-null above. We write 8 bytes (two u32s).
    // Wave 4 will add proper bounds validation; this matches the existing syscall
    // pattern in fd.rs (TODO(#84): plan gaps).
    unsafe {
        let fds = fds_ptr as *mut u32;
        core::ptr::write(fds, read_fd);
        core::ptr::write(fds.add(1), write_fd);
    }

    0
}

/// Allocate a pipe fd in the table.
fn alloc_pipe_fd(table: &mut FdTable, pipe_idx: usize, end: u32) -> Option<usize> {
    // We create a FileDescriptor with null data and encode the pipe identity in flags.
    // SAFETY: data_ptr is null but we never call .data() on a pipe fd — pipe reads
    // and writes are intercepted by sys_pipe_read/write before reaching the generic
    // file path. The null pointer is never dereferenced.
    let fake_data: &[u8] = &[];
    let mut fd = crate::fd::FileDescriptor::new(fake_data, pipe_flags(pipe_idx, end));
    // Offset is unused for pipes but zero is consistent.
    fd.offset = 0;
    table.alloc(fd)
}

/// SYS_read on a pipe fd.
///
/// Called from the generic sys_read path when the fd is detected as a pipe.
///
/// # Returns
/// Bytes read on success, 0 on EOF, negative error code on failure.
pub(crate) fn sys_pipe_read(pipe_idx: usize, buf_ptr: u32, count: u32) -> u32 {
    let count = count as usize;
    if buf_ptr == 0 {
        return EFAULT;
    }

    // SAFETY: single-core cooperative kernel; no concurrent mutation of pipe pool.
    let buf = match unsafe { get_pipe_mut(pipe_idx) } {
        Some(b) => b,
        None => return EBADF,
    };

    if buf.available() == 0 {
        if buf.write_closed {
            // EOF
            return 0;
        }
        // Data not yet available, write end still open.
        return EAGAIN;
    }

    // SAFETY: buf_ptr is validated non-null above; count bytes are available.
    // Wave 4 will add proper bounds validation.
    let dst = unsafe { core::slice::from_raw_parts_mut(buf_ptr as *mut u8, count) };
    buf.read(dst) as u32
}

/// SYS_write on a pipe fd.
///
/// Called from the generic sys_write path when the fd is detected as a pipe.
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
    let buf = match unsafe { get_pipe_mut(pipe_idx) } {
        Some(b) => b,
        None => return EBADF,
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

    // SAFETY: buf_ptr is validated non-null above; count bytes available in src.
    let src = unsafe { core::slice::from_raw_parts(buf_ptr as *const u8, count) };
    buf.write(src) as u32
}

/// Called from sys_close when a pipe fd is closed.
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

    #[test]
    fn pipe_creates_two_fds() {
        // Reset global fd table and pipe pool.
        reset_pool();
        unsafe {
            let table = &mut *core::ptr::addr_of_mut!(crate::fd::FD_TABLE);
            *table = crate::fd::FdTable::new();
        }

        let mut fds = [0u32; 2];
        let result = sys_pipe(fds.as_mut_ptr() as u32);
        assert_eq!(result, 0, "pipe() should succeed");

        // Both fds should be valid (different) numbers in range [0, MAX_FDS).
        let (read_fd, write_fd) = (fds[0] as usize, fds[1] as usize);
        assert!(read_fd < crate::fd::MAX_FDS, "read fd must be in range");
        assert!(write_fd < crate::fd::MAX_FDS, "write fd must be in range");
        assert_ne!(read_fd, write_fd, "read and write fds must differ");
    }

    #[test]
    fn pipe_write_read_round_trip() {
        reset_pool();

        // Allocate a pipe slot directly for test isolation.
        let pipe_idx = alloc_pipe_slot().expect("alloc pipe");

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
        assert_eq!(read_n, message.len(), "should read back same number of bytes");
        assert_eq!(&dst[..read_n], message, "data should match");
    }

    #[test]
    fn pipe_eof_on_write_close() {
        reset_pool();

        let pipe_idx = alloc_pipe_slot().expect("alloc pipe");

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

        let pipe_idx = alloc_pipe_slot().expect("alloc pipe");
        // Write end is still open (default), buffer empty.
        let mut dst = [0u8; 8];
        let result = sys_pipe_read(pipe_idx, dst.as_mut_ptr() as u32, 8);
        assert_eq!(result, EAGAIN, "empty pipe with open write end → EAGAIN");
    }

    #[test]
    fn pipe_write_full_returns_eagain() {
        reset_pool();

        let pipe_idx = alloc_pipe_slot().expect("alloc pipe");

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
}
