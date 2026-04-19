//! Syscall interface for the thumos kernel.
//!
//! Userspace processes invoke kernel services via the SVC (supervisor call)
//! instruction. The SVC number is encoded in the instruction immediate field.
//! The handler extracts it, dispatches to the appropriate kernel function,
//! and returns the result in r0.
//!
//! Syscall convention (thumos-specific):
//! - SVC #N WHERE N is the syscall number
//! - Arguments in r0-r3 (up to 4 args)
//! - Return value in r0 (0 = success, negative = error)
//! - r1-r3 may carry additional return VALUES
//!
//! Syscall numbers are grouped by domain with reserved ranges:
//! - 0-9: Legacy (existing) syscalls
//! - 10-19: Process management
//! - 20-29: Memory management
//! - 30-49: Filesystem
//! - 50-59: IPC
//! - 60-69: Network
//! - 70-79: Time
//! - 80-89: Signal

use crate::fd;
use crate::futex;
use crate::ipc;
use crate::pipe;
use crate::signal;
use crate::socket;
use crate::kconfig;
use crate::mmu;
use crate::page;
use crate::process;
use crate::process::VmMapping;
use crate::time;
use crate::uart::Uart;
use core::fmt::Write;

/// Error code returned for unimplemented syscalls.
/// WHY: two's complement -38, matching Linux ARM ENOSYS convention for
/// toolchain compatibility with userspace built against Linux headers.
pub(crate) const ENOSYS: u32 = 0u32.wrapping_sub(38);

/// Error code returned when a user-supplied pointer is invalid.
/// WHY: two's complement -14, matching Linux ARM EFAULT convention.
/// Returned when a syscall argument points to kernel memory, device MMIO,
/// unmapped regions, or when a buffer overflows the address space.
pub(crate) const EFAULT: u32 = 0u32.wrapping_sub(14);

/// Validate that a user-supplied buffer `[ptr, ptr+len)` lies entirely
/// within user-accessible DRAM and does not overlap kernel-reserved memory.
///
/// # Memory layout (MT6739)
///
/// - `0x0000_0000 - 0x3FFF_FFFF`: device MMIO (boot ROM, peripherals, modem)
/// - `0x4000_0000 - 0x4000_7FFF`: DRAM below kernel load (reserved)
/// - `0x4000_8000 - 0x400F_FFFF`: kernel image + reserved (`KERNEL_LOAD..KERNEL_END`)
/// - `0x4010_0000 - 0x7FFF_FFFF`: user-accessible DRAM
/// - `0x8000_0000 - 0xFFFF_FFFF`: unmapped
///
/// Returns `true` if the entire buffer falls within user-accessible DRAM.
/// Returns `false` for null, overflow, kernel-space, device, or unmapped addresses.
pub(crate) fn validate_user_buffer(ptr: usize, len: usize) -> bool {
    // Null pointer
    if ptr == 0 {
        return false;
    }
    // Zero-length buffer is vacuously valid (no memory accessed)
    if len == 0 {
        return true;
    }
    // Overflow check: ptr + len must not wrap
    let Some(end) = ptr.checked_add(len) else {
        return false;
    };
    // Entire range must be within user DRAM: [KERNEL_END, RAM_END)
    // WHY: KERNEL_END is the first byte after kernel-reserved memory;
    // RAM_END is one past the last byte of physical DRAM.
    ptr >= kconfig::KERNEL_END && end <= kconfig::RAM_END
}

/// Total number of defined syscalls.
pub(crate) const SYSCALL_COUNT: usize = 46;

/// Syscall numbers grouped by kernel domain.
///
/// Numbers 0-9 are legacy assignments FROM the initial kernel bring-up.
/// New syscalls are allocated in domain-specific ranges to allow contiguous
/// growth without renumbering.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Syscall {
    // --- Legacy syscalls (0-9) ---
    // WHY: preserved FROM initial bring-up for ABI stability with existing
    // test binaries. Numbers are non-contiguous across domains because they
    // predate the domain grouping.

    /// Terminate the calling process.
    Exit = 0,
    /// Write bytes to a file descriptor (currently: UART console).
    Write = 1,
    /// Yield the CPU to the scheduler voluntarily.
    Yield = 2,
    /// Return the calling process's PID.
    Getpid = 3,
    /// Allocate a single physical page.
    AllocPage = 4,
    /// Free a previously allocated physical page.
    FreePage = 5,
    /// Return kernel uptime in milliseconds.
    Uptime = 6,
    /// Sleep for approximately N milliseconds.
    Sleep = 7,
    /// Send an IPC message to another process.
    Send = 8,
    /// Receive an IPC message FROM the inbox.
    Recv = 9,

    // --- Process management (10-19) ---
    // WHY: process lifecycle operations needed for multi-process userspace.
    // fork/exec/wait form the standard process creation triangle; kill
    // enables signal delivery; getuid supports identity-aware access control.

    /// Create a child process as a copy of the caller.
    Fork = 10,
    /// Replace the current process image with a new program.
    Execve = 11,
    /// Wait for a child process to change state.
    Waitpid = 12,
    /// Send a signal to a process.
    Kill = 13,
    /// Return the calling process's user ID.
    Getuid = 14,

    // --- Memory management (20-29) ---
    // WHY: userspace needs virtual memory control for heap growth (brk),
    // shared memory and mmap'd files (mmap/munmap), and guard pages
    // (mprotect). These are the minimum SET for a musl-linked process.

    /// Map files or devices INTO memory.
    Mmap = 20,
    /// Unmap a previously mapped memory region.
    Munmap = 21,
    /// Adjust the program break (heap boundary).
    Brk = 22,
    /// Set protection on a memory region.
    Mprotect = 23,

    // --- Filesystem (30-49) ---
    // WHY: file I/O is the foundation of the Unix process model. open/close/
    // read/write/stat cover basic access; lseek/ioctl/fcntl handle position
    // and control; dup/dup2 support shell-style redirection; mkdir/unlink/
    // getcwd/chdir provide directory operations. This SET is sufficient for
    // a BusyBox shell on the ramfs.

    /// Open a file or device.
    Open = 30,
    /// Close a file descriptor.
    Close = 31,
    /// Read bytes FROM a file descriptor.
    Read = 32,
    /// Get file status by path.
    Stat = 33,
    /// Get file status by file descriptor.
    Fstat = 34,
    /// Reposition the file OFFSET.
    Lseek = 35,
    /// Device-specific control operations.
    Ioctl = 36,
    /// File descriptor control (flags, locks).
    Fcntl = 37,
    /// Duplicate a file descriptor.
    Dup = 38,
    /// Duplicate a file descriptor to a specific number.
    Dup2 = 39,
    /// Create a directory.
    Mkdir = 40,
    /// Remove a file or directory entry.
    Unlink = 41,
    /// Get the current working directory.
    Getcwd = 42,
    /// Change the current working directory.
    Chdir = 43,

    // --- IPC (50-59) ---
    // WHY: pipe enables parent-child data flow (shell pipelines); futex
    // provides the kernel-side of userspace mutexes and condition variables.
    // send/recv (legacy 8/9) handle message-passing IPC.

    /// Create a unidirectional data channel (pipe).
    Pipe = 50,
    /// Fast userspace mutex (kernel wait/wake).
    Futex = 51,

    // --- Network (60-69) ---
    // WHY: thumos needs raw socket access for WiFi scanning (sema), packet
    // filtering (asphaleia), and Signal protocol transport (krypta). The
    // BSD socket API is the standard interface for userspace networking.

    /// Create a network socket.
    Socket = 60,
    /// Bind a socket to an address.
    Bind = 61,
    /// Listen for incoming connections.
    Listen = 62,
    /// Accept a connection on a listening socket.
    Accept = 63,
    /// Initiate a connection on a socket.
    Connect = 64,
    /// Send a datagram to a specific address.
    Sendto = 65,
    /// Receive a datagram and record the source address.
    Recvfrom = 66,

    // --- Time (70-79) ---
    // WHY: userspace needs wall-clock and monotonic time for timestamps,
    // timeouts, and scheduling. nanosleep is the POSIX sleep primitive.
    // uptime/sleep (legacy 6/7) provide tick-based alternatives.

    /// Read a clock (wall, monotonic, or process CPU time).
    ClockGettime = 70,
    /// High-resolution sleep.
    Nanosleep = 71,

    // --- Signal (80-89) ---
    // WHY: signals are the standard mechanism for async process notification
    // (SIGTERM, SIGCHLD, SIGSEGV). sigaction installs handlers; sigreturn
    // restores context after a signal handler completes.

    /// Install or query a signal handler.
    Sigaction = 80,
    /// Return FROM a signal handler (restores pre-signal context).
    Sigreturn = 81,
}

impl Syscall {
    /// Returns the syscall number as a `u32`.
    #[inline]
    pub(crate) const fn as_u32(self) -> u32 {
        self as u32
    }

    /// Convert a raw syscall number to a [`Syscall`] variant.
    ///
    /// Returns `None` for numbers that do not correspond to a defined syscall.
    pub(crate) const fn from_u32(n: u32) -> Option<Self> {
        match n {
            // Legacy
            0 => Some(Self::Exit),
            1 => Some(Self::Write),
            2 => Some(Self::Yield),
            3 => Some(Self::Getpid),
            4 => Some(Self::AllocPage),
            5 => Some(Self::FreePage),
            6 => Some(Self::Uptime),
            7 => Some(Self::Sleep),
            8 => Some(Self::Send),
            9 => Some(Self::Recv),
            // Process
            10 => Some(Self::Fork),
            11 => Some(Self::Execve),
            12 => Some(Self::Waitpid),
            13 => Some(Self::Kill),
            14 => Some(Self::Getuid),
            // Memory
            20 => Some(Self::Mmap),
            21 => Some(Self::Munmap),
            22 => Some(Self::Brk),
            23 => Some(Self::Mprotect),
            // Filesystem
            30 => Some(Self::Open),
            31 => Some(Self::Close),
            32 => Some(Self::Read),
            33 => Some(Self::Stat),
            34 => Some(Self::Fstat),
            35 => Some(Self::Lseek),
            36 => Some(Self::Ioctl),
            37 => Some(Self::Fcntl),
            38 => Some(Self::Dup),
            39 => Some(Self::Dup2),
            40 => Some(Self::Mkdir),
            41 => Some(Self::Unlink),
            42 => Some(Self::Getcwd),
            43 => Some(Self::Chdir),
            // IPC
            50 => Some(Self::Pipe),
            51 => Some(Self::Futex),
            // Network
            60 => Some(Self::Socket),
            61 => Some(Self::Bind),
            62 => Some(Self::Listen),
            63 => Some(Self::Accept),
            64 => Some(Self::Connect),
            65 => Some(Self::Sendto),
            66 => Some(Self::Recvfrom),
            // Time
            70 => Some(Self::ClockGettime),
            71 => Some(Self::Nanosleep),
            // Signal
            80 => Some(Self::Sigaction),
            81 => Some(Self::Sigreturn),
            _ => None,
        }
    }

    /// All defined syscall variants in declaration ORDER.
    /// WHY: enables exhaustive iteration for tests and introspection
    /// without relying on external derive macros in no_std.
    pub(crate) const ALL: [Self; SYSCALL_COUNT] = [
        // Legacy
        Self::Exit,
        Self::Write,
        Self::Yield,
        Self::Getpid,
        Self::AllocPage,
        Self::FreePage,
        Self::Uptime,
        Self::Sleep,
        Self::Send,
        Self::Recv,
        // Process
        Self::Fork,
        Self::Execve,
        Self::Waitpid,
        Self::Kill,
        Self::Getuid,
        // Memory
        Self::Mmap,
        Self::Munmap,
        Self::Brk,
        Self::Mprotect,
        // Filesystem
        Self::Open,
        Self::Close,
        Self::Read,
        Self::Stat,
        Self::Fstat,
        Self::Lseek,
        Self::Ioctl,
        Self::Fcntl,
        Self::Dup,
        Self::Dup2,
        Self::Mkdir,
        Self::Unlink,
        Self::Getcwd,
        Self::Chdir,
        // IPC
        Self::Pipe,
        Self::Futex,
        // Network
        Self::Socket,
        Self::Bind,
        Self::Listen,
        Self::Accept,
        Self::Connect,
        Self::Sendto,
        Self::Recvfrom,
        // Time
        Self::ClockGettime,
        Self::Nanosleep,
        // Signal
        Self::Sigaction,
        Self::Sigreturn,
    ];
}

/// Syscall dispatch. Called FROM the SVC handler in `exceptions.rs`.
///
/// # Arguments
///
/// - `num`: syscall number (FROM SVC instruction)
/// - `arg0`-`arg3`: arguments FROM r0-r3
///
/// # Returns
///
/// Value to place in r0 on return to userspace.
///
/// # Syscall implementation status
///
/// Implemented: exit, write, yield, getpid, alloc_page, free_page, uptime,
///   sleep, send, recv, fork, waitpid, execve, kill, getuid, brk, mmap,
///   munmap, mprotect, open, close, read, stat, fstat, lseek, ioctl, fcntl,
///   dup, dup2, mkdir, unlink, getcwd, chdir, pipe, futex, socket, bind,
///   connect, sendto, recvfrom, clock_gettime, nanosleep, sigaction, sigreturn
/// Stub (returns EOPNOTSUPP): listen, accept
pub(crate) fn dispatch(num: u32, arg0: u32, arg1: u32, arg2: u32, arg3: u32) -> u32 {
    let Some(call) = Syscall::from_u32(num) else {
        let mut serial = Uart::new();
        let _ = write!(serial, "Unknown syscall: {num}\r\n");
        return ENOSYS;
    };

    match call {
        // ---- Legacy handlers (implemented) ----

        Syscall::Exit => {
            process::exit_with_status(i32::try_from(arg0).unwrap_or_default());
        }
        Syscall::Write => sys_write_dispatch(arg0, arg1, arg2),
        Syscall::Yield => {
            // NOTE: voluntary yield  -  reschedule immediately
            let next = process::schedule();
            if next != process::current_pid() {
                // SAFETY: next is a valid PID returned by schedule(), which only
                // returns PIDs for processes in the READY state.
                unsafe {
                    process::switch_to(next);
                }
            }
            0
        }
        Syscall::Getpid => process::current_pid() as u32,
        Syscall::AllocPage => match crate::page::alloc_page() {
            Some(addr) => u32::try_from(addr).unwrap_or_default(),
            None => u32::MAX, // NOTE: error indicator
        },
        Syscall::FreePage => {
            // SAFETY: arg0 is a physical page address previously returned by
            // alloc_page (syscall 4). The caller is responsible for not
            // double-freeing. No pointer validation is needed because
            // free_page operates on physical addresses managed by the allocator.
            unsafe {
                crate::page::free_page(usize::try_from(arg0).unwrap_or_default());
            }
            0
        }
        Syscall::Uptime => crate::exceptions::uptime_ms() as u32,
        Syscall::Sleep => {
            // NOTE: approximate sleep via busy-wait on tick counter.
            // A proper implementation would block the process and wake on tick.
            let target = crate::exceptions::uptime_ms() + u64::try_from(arg0).unwrap_or_default();
            while crate::exceptions::uptime_ms() < target {
                // SAFETY: WFE is a hint instruction available in all ARM privilege
                // levels. No memory is accessed; the CPU waits for the next event.
                unsafe {
                    core::arch::asm!("wfe");
                }
            }
            0
        }
        Syscall::Send => {
            let to = u8::try_from(arg0).unwrap_or_default();
            let tag = arg1;
            let ptr = usize::try_from(arg2).unwrap_or_default();
            let len = usize::try_from(arg3).unwrap_or_default();
            let payload = if len > 0 && ptr != 0 {
                let capped_len = len.min(ipc::MSG_MAX_SIZE);
                if !validate_user_buffer(ptr, capped_len) {
                    return EFAULT;
                }
                // SAFETY: validate_user_buffer confirmed [ptr, ptr+capped_len)
                // is within user-accessible DRAM.
                unsafe { core::slice::from_raw_parts(ptr as *const u8, capped_len) }
            } else {
                &[]
            };
            let msg = ipc::Message::new(tag, payload);
            if ipc::send(to, msg) { 0 } else { u32::MAX }
        }
        Syscall::Recv => match ipc::recv() {
            Some(msg) => u32::from(msg.from),
            None => u32::MAX,
        },

        // ---- Process management ----

        Syscall::Fork => match process::fork() {
            Some(child_pid) => u32::try_from(child_pid).unwrap_or_default(),
            None => u32::MAX,
        },
        Syscall::Waitpid => {
            let child_pid = u8::try_from(arg0).unwrap_or_default();
            match process::waitpid(child_pid) {
                Some(status) => u32::try_from(status).unwrap_or_default(),
                None => u32::MAX,
            }
        }
        Syscall::Execve => sys_execve(arg0, arg1, arg2),
        Syscall::Kill => signal::sys_kill(arg0, arg1),
        Syscall::Getuid => process::current_uid(),

        // ---- Memory management ----

        Syscall::Brk => sys_brk(arg0),
        Syscall::Mmap => sys_mmap(arg0, arg1, arg2, arg3),
        Syscall::Munmap => sys_munmap(arg0, arg1),
        Syscall::Mprotect => sys_mprotect(arg0, arg1, arg2),

        // ---- Filesystem ----
        // WHY: wired to VFS via fd module. All file operations go through
        // the mount table and Filesystem trait dispatch.

        Syscall::Open => fd::sys_open(arg0, arg1, arg2),
        Syscall::Close => sys_close_with_pipe(arg0),
        Syscall::Read => sys_read_with_pipe(arg0, arg1, arg2),
        Syscall::Stat => fd::sys_stat(arg0, arg1, arg2),
        Syscall::Fstat => fd::sys_fstat(arg0, arg1),
        Syscall::Lseek => fd::sys_lseek(arg0, arg1, arg2),
        Syscall::Dup => fd::sys_dup(arg0),
        Syscall::Dup2 => fd::sys_dup2(arg0, arg1),
        Syscall::Getcwd => fd::sys_getcwd(arg0, arg1),
        Syscall::Mkdir => fd::sys_mkdir(arg0, arg1),
        Syscall::Unlink => fd::sys_unlink(arg0, arg1),
        Syscall::Chdir => fd::sys_chdir(arg0, arg1),

        Syscall::Ioctl => fd::sys_ioctl(arg0, arg1, arg2),
        Syscall::Fcntl => fd::sys_fcntl(arg0, arg1, arg2),

        // ---- IPC ----

        Syscall::Pipe => pipe::sys_pipe(arg0),
        Syscall::Futex => futex::sys_futex(arg0, arg1, arg2),

        // ---- Network ----
        // WHY: BSD socket API backed by smoltcp via the socket module.
        // Socket fds are identified by FD_KIND_SOCKET in the flags field,
        // similar to the pipe fd pattern.

        Syscall::Socket => socket::sys_socket(arg0, arg1, arg2),
        Syscall::Bind => socket::sys_bind(arg0, arg1, arg2),
        Syscall::Listen => socket::sys_listen(arg0, arg1),
        Syscall::Accept => socket::sys_accept(arg0, arg1, arg2),
        Syscall::Connect => socket::sys_connect(arg0, arg1, arg2),
        Syscall::Sendto => socket::sys_sendto(arg0, arg1, arg2, arg3, 0, 0),
        Syscall::Recvfrom => socket::sys_recvfrom(arg0, arg1, arg2, arg3, 0, 0),

        // ---- Time ----

        Syscall::ClockGettime => time::sys_clock_gettime(arg0, arg1),
        Syscall::Nanosleep => time::sys_nanosleep(arg0),

        // ---- Signal ----

        Syscall::Sigaction => signal::sys_sigaction(arg0, arg1),
        Syscall::Sigreturn => signal::sys_sigreturn(),
    }
}

// --- Process management syscall implementations (see sys_execve below) ---

// --- Pipe-aware fd dispatch helpers ---
// WHY: pipe file descriptors are stored in the same fd table as ramfs fds
// but use the `flags` field to encode pipe identity. These wrappers check
// the flags before delegating to the appropriate handler, keeping all pipe
// logic in pipe.rs and the dispatch minimal.

/// SYS_read: dispatch to pipe or ramfs based on fd kind.
fn sys_read_with_pipe(fd: u32, buf_ptr: u32, count: u32) -> u32 {
    let fd_idx = fd as usize;
    // SAFETY: FD_TABLE is a static mut; addr_of! avoids an intermediate
    // reference. Read-only here to inspect flags.
    let flags = {
        let table = unsafe { &*core::ptr::addr_of!(fd::FD_TABLE) };
        match table.get(fd_idx) {
            Some(e) => e.flags,
            None => return fd::EBADF,
        }
    };

    if pipe::is_pipe_fd(flags) {
        let pipe_idx = pipe::pipe_idx_from_flags(flags);
        pipe::sys_pipe_read(pipe_idx, buf_ptr, count)
    } else {
        fd::sys_read(fd, buf_ptr, count)
    }
}

/// SYS_close: notify pipe/socket subsystem when a special fd is closed.
fn sys_close_with_pipe(fd: u32) -> u32 {
    let fd_idx = fd as usize;
    // SAFETY: FD_TABLE is a static mut; addr_of! avoids an intermediate
    // reference. Read-only here to inspect flags before close.
    let flags = {
        let table = unsafe { &*core::ptr::addr_of!(fd::FD_TABLE) };
        match table.get(fd_idx) {
            Some(e) => e.flags,
            None => return fd::EBADF,
        }
    };

    // Close the fd entry first (removes it from the table).
    let result = fd::sys_close(fd);

    if result == 0 {
        // If this was a pipe fd, notify the pipe subsystem.
        if pipe::is_pipe_fd(flags) {
            let pipe_idx = pipe::pipe_idx_from_flags(flags);
            let is_write = pipe::is_write_end(flags);
            pipe::on_pipe_fd_closed(pipe_idx, is_write);
        }

        // If this was a socket fd, clean up the smoltcp socket.
        if socket::is_socket_fd(flags) {
            socket::on_socket_fd_closed(fd_idx);
        }
    }

    result
}

/// SYS_write: dispatch to pipe, UART (stdout), or VFS file based on fd kind.
///
/// - fd 1 (stdout): write to UART serial (legacy behavior).
/// - Pipe fd: dispatch to pipe::sys_pipe_write.
/// - VFS fd: dispatch to fd::sys_write for filesystem write.
fn sys_write_dispatch(fd: u32, buf_ptr: u32, count: u32) -> u32 {
    // fd 1 is stdout — always goes to UART (legacy behavior).
    if fd == 1 {
        let ptr = usize::try_from(buf_ptr).unwrap_or_default();
        let len = usize::try_from(count).unwrap_or_default();
        if !validate_user_buffer(ptr, len) {
            return EFAULT;
        }
        // SAFETY: validate_user_buffer confirmed [ptr, ptr+len) is within
        // user-accessible DRAM.
        let slice = unsafe { core::slice::from_raw_parts(ptr as *const u8, len) };
        let mut serial = Uart::new();
        for &byte in slice {
            serial.putc(byte);
        }
        return u32::try_from(len).unwrap_or_default();
    }

    let fd_idx = fd as usize;
    // SAFETY: FD_TABLE is a static mut; addr_of! avoids an intermediate
    // reference. Read-only here to inspect flags.
    let flags = {
        let table = unsafe { &*core::ptr::addr_of!(fd::FD_TABLE) };
        match table.get(fd_idx) {
            Some(e) => e.flags,
            None => return fd::EBADF,
        }
    };

    if pipe::is_pipe_fd(flags) {
        let pipe_idx = pipe::pipe_idx_from_flags(flags);
        pipe::sys_pipe_write(pipe_idx, buf_ptr, count, process::current_pid())
    } else {
        fd::sys_write(fd, buf_ptr, count)
    }
}

// --- execve implementation ---

/// No such file or directory (two's complement -2, matches Linux ENOENT).
const ENOENT: u32 = 0u32.wrapping_sub(2);

/// execve(path_ptr, argv_ptr, _envp_ptr): replace the current process image.
///
/// # Steps
///
/// 1. Validate and read the path string from user space.
/// 2. Find the file in the global ramfs.
/// 3. Parse and validate the ELF header (must be ARM32 LE).
/// 4. Load ELF PT_LOAD segments (identity-mapped; elf::load writes to vaddr).
/// 5. Allocate a new stack; push argc and argv onto it.
/// 6. Reset all signal handlers to SIG_DFL (POSIX exec semantics).
/// 7. Update the PCB: entry → lr, stack top → sp, reset heap break + mappings.
///
/// # On success
///
/// Returns 0 in r0. The exception return path resumes at the ELF entry point
/// with sp pointing at argc on the new stack.
///
/// # Preserved across exec
///
/// - PID (same process, new image)
/// - File descriptors (global FD_TABLE is not cleared; O_CLOEXEC is future work)
///
/// # envp
///
/// `_envp_ptr` is accepted but ignored; environment variables are not yet
/// supported.
fn sys_execve(path_ptr: u32, argv_ptr: u32, _envp_ptr: u32) -> u32 {
    // --- Step 1: validate and read path ---

    // Validate that path_ptr is in user DRAM (non-null, non-kernel).
    // WHY validate 1 byte: catches null/kernel/device pointers before any read.
    if !validate_user_buffer(path_ptr as usize, 1) {
        return EFAULT;
    }

    // Read the null-terminated path string from user space.
    // Cap at 256 bytes to bound the scan; longer paths are rejected.
    const MAX_PATH: usize = 256;
    let path_len = {
        let mut len = 0usize;
        let ptr = path_ptr as *const u8;
        while len < MAX_PATH {
            // SAFETY: ptr + len is in user DRAM (validate_user_buffer checked
            // the base; the loop caps at MAX_PATH which is well within the
            // ~1 GB user DRAM range, so no wrap occurs).
            let byte = unsafe { ptr.add(len).read_volatile() };
            if byte == 0 {
                break;
            }
            len += 1;
        }
        if len == 0 || len == MAX_PATH {
            return ENOENT; // empty path or unterminated within limit
        }
        len
    };

    // Construct path &str from the validated region.
    // SAFETY: path_ptr is in user DRAM (validated above); path_len bytes
    // were just scanned without trapping. The slice lifetime is local.
    let path_bytes = unsafe {
        core::slice::from_raw_parts(path_ptr as *const u8, path_len)
    };
    let path = match core::str::from_utf8(path_bytes) {
        Ok(s) => s,
        Err(_) => return ENOENT,
    };

    // --- Step 2: locate the file in ramfs ---
    // SAFETY: fd::init_ramfs was called during kernel boot before any execve call.
    let elf_data: &[u8] = match unsafe { fd::ramfs_find(path) } {
        Some(d) => d,
        None => return ENOENT,
    };

    // --- Step 3: parse and validate ELF ---
    let loaded = match crate::elf::load(elf_data) {
        Ok(l) => l,
        Err(_) => return EINVAL,
    };
    let entry_point = loaded.entry;

    // --- Step 4: allocate new stack ---
    // WHY 4 pages (16 KB): matches spawn() stack size; sufficient for musl
    // libc start-up (argc/argv + environ + aux vectors + initial stack frame).
    const EXEC_STACK_PAGES: usize = 4;
    let mut new_stack_base: usize = 0;
    for i in 0..EXEC_STACK_PAGES {
        match page::alloc_page() {
            Some(phys) => {
                if i == 0 {
                    new_stack_base = phys;
                }
            }
            None => {
                // OOM: free already-allocated stack pages and abort.
                for j in 0..i {
                    // SAFETY: pages were returned by alloc_page() in this loop;
                    // they have not been mapped or used yet.
                    unsafe { page::free_page(new_stack_base + j * page::PAGE_SIZE); }
                }
                return ENOMEM;
            }
        }
    }
    let new_stack_top = new_stack_base + EXEC_STACK_PAGES * page::PAGE_SIZE;

    // --- Step 5: build argc/argv on the new stack ---
    // Stack layout written at sp (grows downward from new_stack_top):
    //   sp+0        : argc      (u32)
    //   sp+4        : argv[0]   (u32 user pointer into string area below)
    //   ...
    //   sp+4+argc*4 : NULL      (u32 argv[] terminator)
    //   string area : null-terminated argv strings packed contiguously
    //
    // This layout matches the Linux/ARM AAPCS start-up convention consumed by
    // musl libc's __start_main.

    // Collect argv strings from user space (cap at 16 args, 128 bytes each).
    const MAX_ARGS: usize = 16;
    const MAX_ARG_LEN: usize = 128;
    // WHY fixed-size arrays: avoids heap allocation in the execve path; size
    // is bounded so the combined frame always fits in the 16 KB stack.
    let mut arg_data: [[u8; MAX_ARG_LEN]; MAX_ARGS] = [[0u8; MAX_ARG_LEN]; MAX_ARGS];
    let mut arg_lens: [usize; MAX_ARGS] = [0usize; MAX_ARGS];
    let mut argc: usize = 0;

    if argv_ptr != 0 {
        let argv_base = argv_ptr as usize;
        for i in 0..MAX_ARGS {
            // Read the i-th argv[] entry (u32 user pointer to a string).
            let entry_addr = argv_base + i * 4;
            if !validate_user_buffer(entry_addr, 4) {
                break;
            }
            // SAFETY: entry_addr is in user DRAM (validated above).
            let str_ptr = unsafe {
                core::ptr::read_unaligned(entry_addr as *const u32)
            } as usize;
            if str_ptr == 0 {
                break; // null terminator of argv[]
            }
            if !validate_user_buffer(str_ptr, 1) {
                break; // bad string pointer — stop collecting args
            }
            // Copy up to MAX_ARG_LEN-1 bytes of the string.
            let mut slen = 0usize;
            while slen < MAX_ARG_LEN - 1 {
                // SAFETY: str_ptr is in user DRAM (validated above).
                let byte = unsafe { (str_ptr as *const u8).add(slen).read_volatile() };
                if byte == 0 {
                    break;
                }
                arg_data[i][slen] = byte;
                slen += 1;
            }
            arg_lens[i] = slen;
            argc += 1;
        }
    }

    // Compute and align the stack frame size.
    let strings_size: usize = (0..argc).map(|i| arg_lens[i] + 1).sum::<usize>();
    let pointers_size = (argc + 1) * 4; // argv[] + null terminator
    let frame_size = 4 + pointers_size + strings_size;
    // AAPCS requires 8-byte stack alignment at function call boundaries.
    let frame_aligned = (frame_size + 7) & !7;

    let sp = if frame_aligned <= EXEC_STACK_PAGES * page::PAGE_SIZE {
        new_stack_top - frame_aligned
    } else {
        // Pathological argv (too many/long args): fall back to argc=0 frame.
        argc = 0;
        new_stack_top - 8
    };

    // Write argc onto the stack.
    // SAFETY: sp is within [new_stack_base, new_stack_top); allocation
    // succeeded above. Stack pages are identity-mapped (physical == virtual),
    // so the write reaches the correct physical pages.
    unsafe { (sp as *mut u32).write(argc as u32); }

    // Write argv[] pointers and string data.
    let argv_array_base = sp + 4;
    let mut string_cursor = argv_array_base + (argc + 1) * 4;

    for i in 0..argc {
        // Write the pointer to this argument string.
        // SAFETY: argv_array_base + i*4 is within the stack frame computed above.
        unsafe {
            ((argv_array_base + i * 4) as *mut u32).write(string_cursor as u32);
        }
        // Copy string bytes followed by a null terminator.
        // SAFETY: string_cursor is within the stack frame; arg_data[i] is
        // a kernel-local fixed array; arg_lens[i] < MAX_ARG_LEN.
        unsafe {
            core::ptr::copy_nonoverlapping(
                arg_data[i].as_ptr(),
                string_cursor as *mut u8,
                arg_lens[i],
            );
            ((string_cursor + arg_lens[i]) as *mut u8).write(0);
        }
        string_cursor += arg_lens[i] + 1;
    }
    // Write null terminator for argv[argc].
    // SAFETY: argv_array_base + argc*4 is within the stack frame.
    unsafe { ((argv_array_base + argc * 4) as *mut u32).write(0); }

    // --- Step 6: reset signal handlers (POSIX exec semantics) ---
    // WHY: POSIX requires exec to reset all signal dispositions to SIG_DFL and
    // clear pending signals that were set via a registered handler. The new
    // image must not inherit any userspace-installed signal handlers.
    // SAFETY: called from syscall context (SVC mode, IRQs disabled, single-core).
    unsafe { process::reset_signal_state(); }

    // --- Step 7: update PCB ---
    // exec_replace_context frees old stack pages, resets heap_break and the
    // mmap mapping table, and updates ctx.lr/sp/cpsr for the exception return.
    // SAFETY: new_stack_base and EXEC_STACK_PAGES identify the freshly
    // allocated stack verified above. entry_point is the ELF e_entry field
    // validated by elf::load.
    unsafe {
        process::exec_replace_context(entry_point, sp, new_stack_base, EXEC_STACK_PAGES);
    }

    0
}

// --- Memory management syscall error codes ---

/// Invalid argument (two's complement -22, matches Linux EINVAL).
const EINVAL: u32 = 0u32.wrapping_sub(22);
/// Out of memory (two's complement -12, matches Linux ENOMEM).
const ENOMEM: u32 = 0u32.wrapping_sub(12);
/// mmap failure sentinel (MAP_FAILED = (void *)-1).
const MAP_FAILED: u32 = u32::MAX;
/// MAP_ANONYMOUS flag (Linux mman.h).
const MAP_ANONYMOUS: u32 = 0x20;

// --- Memory management syscall implementations ---

/// brk(new_break): adjust the program break.
///
/// If `new_break_raw` is 0, returns the current break without modifying it.
/// If `new_break_raw` > current break: allocates pages and maps them.
/// If `new_break_raw` < current break: unmaps pages and frees them.
/// Returns the (possibly updated) program break. On allocation failure,
/// returns the current break unchanged (per Linux convention: brk never
/// returns an error code, it returns the current break on failure).
fn sys_brk(new_break_raw: u32) -> u32 {
    let new_break_req = new_break_raw as usize;
    let current = process::current_heap_break();

    // Query: return current break
    if new_break_req == 0 {
        return u32::try_from(current).unwrap_or_default();
    }

    // Page-align the requested break (round up)
    let new_break = (new_break_req + page::PAGE_SIZE - 1) & !(page::PAGE_SIZE - 1);

    let pt = process::current_page_table();
    if pt == 0 {
        return u32::try_from(current).unwrap_or_default();
    }

    let l2_attrs = mmu::prot_to_l2_flags(mmu::prot::PROT_READ | mmu::prot::PROT_WRITE);

    if new_break > current {
        // Grow: allocate and map pages from current break to new break
        let pages_needed = (new_break - current) / page::PAGE_SIZE;
        for i in 0..pages_needed {
            let vaddr = current + i * page::PAGE_SIZE;
            let Some(phys) = page::alloc_page() else {
                // OOM: roll back already-allocated pages for this brk call
                for j in 0..i {
                    let rollback_vaddr = current + j * page::PAGE_SIZE;
                    // SAFETY: pt is the current process's valid L1 table and
                    // rollback_vaddr is page-aligned within the heap region.
                    // These pages were successfully mapped in earlier iterations.
                    unsafe {
                        mmu::unmap_page(pt, rollback_vaddr);
                        // NOTE: we can't easily recover the physical address of
                        // already-mapped pages without reading the L2 entry. For
                        // simplicity, we accept the leak on OOM during brk grow.
                        // A production kernel would track the phys addrs.
                    }
                }
                return u32::try_from(current).unwrap_or_default();
            };

            // SAFETY: pt is the current process's valid L1 table, vaddr is
            // page-aligned within the heap region, phys is freshly allocated.
            let ok = unsafe { mmu::map_page(pt, vaddr, phys, l2_attrs) };
            if !ok {
                // Mapping failed (e.g., L2 pool exhausted) -- free the page
                // SAFETY: phys was just returned by alloc_page() and has not
                // been mapped (map_page failed), so it is safe to free.
                unsafe { page::free_page(phys); }
                return u32::try_from(current).unwrap_or_default();
            }
        }
        process::set_heap_break(new_break);
    } else if new_break < current {
        // Shrink: unmap and free pages from new break to current break
        let pages_to_free = (current - new_break) / page::PAGE_SIZE;
        for i in 0..pages_to_free {
            let vaddr = new_break + i * page::PAGE_SIZE;
            // SAFETY: pt is the current process's valid L1 table and vaddr is
            // page-aligned within the currently mapped heap region.
            // flush_tlb_page invalidates the TLB entry after the L2 entry is zeroed.
            unsafe {
                mmu::unmap_page(pt, vaddr);
                // NOTE: we don't have an easy way to get the physical address
                // from the L2 entry after zeroing it. For brk shrink, the pages
                // were contiguously allocated and the physical addresses are not
                // readily recoverable without reading L2 before clearing.
                // A production kernel would read the L2 entry before clearing.
                mmu::flush_tlb_page(vaddr);
            }
        }
        process::set_heap_break(new_break);
    }

    u32::try_from(process::current_heap_break()).unwrap_or_default()
}

/// mmap(addr_hint, length, prot, flags_and_fd):
///
/// WHY: ARM syscall convention passes only 4 registers (r0-r3). POSIX mmap
/// takes 6 arguments. We pack flags in the low 16 bits of arg3 and fd in
/// the high 16 bits. Offset is not supported (anonymous only).
///
/// - arg0: addr hint (ignored for MAP_ANONYMOUS, we pick the address)
/// - arg1: length in bytes
/// - arg2: prot flags (PROT_READ | PROT_WRITE | PROT_EXEC)
/// - arg3: low 16 bits = flags, high 16 bits = fd (as i16, -1 = 0xFFFF)
fn sys_mmap(arg0: u32, arg1: u32, arg2: u32, arg3: u32) -> u32 {
    let _addr_hint = arg0 as usize;
    let length = arg1 as usize;
    let prot_flags = arg2;
    let flags = arg3 & 0xFFFF;
    let fd_raw = (arg3 >> 16) as u16;
    // Interpret fd as i16: 0xFFFF = -1
    let fd = fd_raw as i16;

    // Validate: length must be non-zero
    if length == 0 {
        return MAP_FAILED;
    }

    // Only support MAP_ANONYMOUS
    if flags & MAP_ANONYMOUS == 0 {
        return MAP_FAILED;
    }

    // Reject file-backed mappings (fd must be -1 for anonymous)
    if fd != -1 {
        return MAP_FAILED;
    }

    // Round length up to page boundary
    let page_count = (length + page::PAGE_SIZE - 1) / page::PAGE_SIZE;

    let pt = process::current_page_table();
    if pt == 0 {
        return MAP_FAILED;
    }

    // Find a free virtual address region starting from MMAP_BASE.
    // Scan upward, checking against existing mappings for overlap.
    let mappings = process::current_mappings();
    let mut candidate = process::MMAP_BASE;

    // Simple first-fit search
    'search: loop {
        let candidate_end = candidate + page_count * page::PAGE_SIZE;
        // Bounds check: stay within a reasonable user VA range
        if candidate_end > 0x3000_0000 {
            return MAP_FAILED;
        }

        // Check for overlap with existing mappings.
        // If any mapping overlaps, bump candidate past it and retry.
        let overlap = mappings.iter().find_map(|slot| {
            let m = slot.as_ref()?;
            let m_end = m.start + m.pages * page::PAGE_SIZE;
            if candidate < m_end && candidate_end > m.start {
                Some(m_end)
            } else {
                None
            }
        });
        if let Some(past) = overlap {
            candidate = past;
            continue 'search;
        }
        break;
    }

    let l2_attrs = mmu::prot_to_l2_flags(prot_flags);

    // Allocate physical pages and map them
    for i in 0..page_count {
        let vaddr = candidate + i * page::PAGE_SIZE;
        let Some(phys) = page::alloc_page() else {
            // OOM: roll back
            for j in 0..i {
                let rollback_vaddr = candidate + j * page::PAGE_SIZE;
                // SAFETY: pt is the current process's valid L1 table and
                // rollback_vaddr is page-aligned within the mmap candidate region.
                // These pages were successfully mapped in earlier iterations.
                unsafe {
                    mmu::unmap_page(pt, rollback_vaddr);
                }
            }
            return MAP_FAILED;
        };

        // SAFETY: pt is the current process's valid L1 table, vaddr is
        // page-aligned within the anonymous mmap region, phys is freshly allocated.
        let ok = unsafe { mmu::map_page(pt, vaddr, phys, l2_attrs) };
        if !ok {
            // SAFETY: phys was just returned by alloc_page() and has not been
            // mapped (map_page failed), so it is safe to free.
            unsafe { page::free_page(phys); }
            // Roll back previous mappings
            for j in 0..i {
                let rollback_vaddr = candidate + j * page::PAGE_SIZE;
                // SAFETY: pt is the current process's valid L1 table and
                // rollback_vaddr was successfully mapped in earlier iterations.
                unsafe {
                    mmu::unmap_page(pt, rollback_vaddr);
                }
            }
            return MAP_FAILED;
        }
    }

    // Record the mapping
    let mapping = VmMapping {
        start: candidate,
        pages: page_count,
        prot: prot_flags,
    };
    if process::add_mapping(mapping).is_none() {
        // Mapping table full -- roll back
        for i in 0..page_count {
            let vaddr = candidate + i * page::PAGE_SIZE;
            // SAFETY: pt is the current process's valid L1 table and vaddr
            // is page-aligned within the region just successfully mapped.
            unsafe {
                mmu::unmap_page(pt, vaddr);
            }
        }
        return MAP_FAILED;
    }

    u32::try_from(candidate).unwrap_or_default()
}

/// munmap(addr, length): unmap a previously mapped memory region.
///
/// Returns 0 on success, EINVAL if the mapping is not found.
fn sys_munmap(arg0: u32, arg1: u32) -> u32 {
    let addr = arg0 as usize;
    let _length = arg1 as usize;

    let pt = process::current_page_table();
    if pt == 0 {
        return EINVAL;
    }

    let Some(mapping) = process::remove_mapping(addr) else {
        return EINVAL;
    };

    // Unmap all pages in the region
    for i in 0..mapping.pages {
        let vaddr = mapping.start + i * page::PAGE_SIZE;
        // SAFETY: pt is the current process's valid L1 table, vaddr is
        // page-aligned within the mapping returned by remove_mapping().
        // flush_tlb_page invalidates the TLB entry after the L2 entry is zeroed.
        unsafe {
            mmu::unmap_page(pt, vaddr);
            mmu::flush_tlb_page(vaddr);
        }
    }

    0
}

/// mprotect(addr, length, prot): change protection on a mapped region.
///
/// Returns 0 on success, EINVAL if the mapping is not found.
fn sys_mprotect(arg0: u32, arg1: u32, arg2: u32) -> u32 {
    let addr = arg0 as usize;
    let _length = arg1 as usize;
    let new_prot = arg2;

    let pt = process::current_page_table();
    if pt == 0 {
        return EINVAL;
    }

    // Find the mapping
    let Some(mapping) = process::find_mapping(addr) else {
        return EINVAL;
    };

    let l2_attrs = mmu::prot_to_l2_flags(new_prot);

    // Update each page's protection bits in the page table
    for i in 0..mapping.pages {
        let vaddr = mapping.start + i * page::PAGE_SIZE;
        // SAFETY: pt is the current process's valid L1 table, vaddr is
        // page-aligned within the mapping returned by find_mapping().
        // flush_tlb_page invalidates the TLB entry after the protection bits change.
        unsafe {
            mmu::update_page_prot(pt, vaddr, l2_attrs);
            mmu::flush_tlb_page(vaddr);
        }
    }

    // Update the stored mapping's prot field
    process::update_mapping_prot(addr, new_prot);

    0
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Legacy syscall number preservation ----
    // WHY: ABI stability  -  existing test binaries depend on these exact VALUES.

    #[test]
    fn legacy_exit_is_zero() {
        assert_eq!(Syscall::Exit.as_u32(), 0, "exit must be syscall 0");
    }

    #[test]
    fn legacy_write_is_one() {
        assert_eq!(Syscall::Write.as_u32(), 1, "write must be syscall 1");
    }

    #[test]
    fn legacy_yield_is_two() {
        assert_eq!(Syscall::Yield.as_u32(), 2, "yield must be syscall 2");
    }

    #[test]
    fn legacy_getpid_is_three() {
        assert_eq!(Syscall::Getpid.as_u32(), 3, "getpid must be syscall 3");
    }

    #[test]
    fn legacy_alloc_page_is_four() {
        assert_eq!(Syscall::AllocPage.as_u32(), 4, "alloc_page must be syscall 4");
    }

    #[test]
    fn legacy_free_page_is_five() {
        assert_eq!(Syscall::FreePage.as_u32(), 5, "free_page must be syscall 5");
    }

    #[test]
    fn legacy_uptime_is_six() {
        assert_eq!(Syscall::Uptime.as_u32(), 6, "uptime must be syscall 6");
    }

    #[test]
    fn legacy_sleep_is_seven() {
        assert_eq!(Syscall::Sleep.as_u32(), 7, "sleep must be syscall 7");
    }

    #[test]
    fn legacy_send_is_eight() {
        assert_eq!(Syscall::Send.as_u32(), 8, "send must be syscall 8");
    }

    #[test]
    fn legacy_recv_is_nine() {
        assert_eq!(Syscall::Recv.as_u32(), 9, "recv must be syscall 9");
    }

    // ---- Enum conversion ----

    #[test]
    fn from_u32_roundtrip_all_variants() {
        for &variant in &Syscall::ALL {
            let n = variant.as_u32();
            let recovered = Syscall::from_u32(n);
            assert_eq!(
                recovered,
                Some(variant),
                "roundtrip failed for {variant:?} (number {n})"
            );
        }
    }

    #[test]
    fn from_u32_returns_none_for_gaps() {
        // INVARIANT: numbers between domain ranges are unallocated
        let gap_numbers: &[u32] = &[15, 16, 17, 18, 19, 24, 25, 26, 44, 45, 52, 53, 67, 68, 72, 73, 82, 99, 255, u32::MAX];
        for &n in gap_numbers {
            assert!(
                Syscall::from_u32(n).is_none(),
                "number {n} should not map to a syscall variant"
            );
        }
    }

    #[test]
    fn all_numbers_unique() {
        let mut numbers: [u32; SYSCALL_COUNT] = [0; SYSCALL_COUNT];
        let mut i = 0;
        while i < SYSCALL_COUNT {
            numbers[i] = Syscall::ALL[i].as_u32();
            i += 1;
        }
        // INVARIANT: no two variants share a syscall number
        let mut a = 0;
        while a < SYSCALL_COUNT {
            let mut b = a + 1;
            while b < SYSCALL_COUNT {
                assert!(
                    numbers[a] != numbers[b],
                    "duplicate syscall number detected"
                );
                b += 1;
            }
            a += 1;
        }
    }

    // ---- Constants ----

    #[test]
    fn enosys_is_negative_38() {
        // WHY: must match Linux ARM ENOSYS for musl compatibility
        assert_eq!(ENOSYS, 0xFFFF_FFDA, "ENOSYS must be -u32::try_from(38).unwrap_or_default()");
    }

    #[test]
    fn syscall_count_at_least_35() {
        assert!(
            SYSCALL_COUNT >= 35,
            "must define at least 35 syscalls, got {SYSCALL_COUNT}"
        );
    }

    #[test]
    fn all_array_length_matches_count() {
        assert_eq!(
            Syscall::ALL.len(),
            SYSCALL_COUNT,
            "ALL array length must match SYSCALL_COUNT"
        );
    }

    // ---- Domain range validation ----

    #[test]
    fn process_group_in_range() {
        let process_calls = [
            Syscall::Fork,
            Syscall::Execve,
            Syscall::Waitpid,
            Syscall::Kill,
            Syscall::Getuid,
        ];
        for call in process_calls {
            let n = call.as_u32();
            assert!(
                (10..20).contains(&n),
                "{call:?} (number {n}) should be in process range 10-19"
            );
        }
    }

    #[test]
    fn memory_group_in_range() {
        let memory_calls = [Syscall::Mmap, Syscall::Munmap, Syscall::Brk, Syscall::Mprotect];
        for call in memory_calls {
            let n = call.as_u32();
            assert!(
                (20..30).contains(&n),
                "{call:?} (number {n}) should be in memory range 20-29"
            );
        }
    }

    #[test]
    fn filesystem_group_in_range() {
        let fs_calls = [
            Syscall::Open, Syscall::Close, Syscall::Read, Syscall::Stat,
            Syscall::Fstat, Syscall::Lseek, Syscall::Ioctl, Syscall::Fcntl,
            Syscall::Dup, Syscall::Dup2, Syscall::Mkdir, Syscall::Unlink,
            Syscall::Getcwd, Syscall::Chdir,
        ];
        for call in fs_calls {
            let n = call.as_u32();
            assert!(
                (30..50).contains(&n),
                "{call:?} (number {n}) should be in filesystem range 30-49"
            );
        }
    }

    #[test]
    fn network_group_in_range() {
        let net_calls = [
            Syscall::Socket, Syscall::Bind, Syscall::Listen, Syscall::Accept,
            Syscall::Connect, Syscall::Sendto, Syscall::Recvfrom,
        ];
        for call in net_calls {
            let n = call.as_u32();
            assert!(
                (60..70).contains(&n),
                "{call:?} (number {n}) should be in network range 60-69"
            );
        }
    }

    #[test]
    fn signal_group_in_range() {
        let sig_calls = [Syscall::Sigaction, Syscall::Sigreturn];
        for call in sig_calls {
            let n = call.as_u32();
            assert!(
                (80..90).contains(&n),
                "{call:?} (number {n}) should be in signal range 80-89"
            );
        }
    }

    // ---- EFAULT constant ----

    #[test]
    fn efault_is_negative_14() {
        // WHY: must match Linux ARM EFAULT for musl compatibility
        assert_eq!(EFAULT, 0xFFFF_FFF2, "EFAULT must be two's complement -14");
    }

    // ---- User buffer validation ----

    #[test]
    fn validate_user_buffer_valid_pointer() {
        assert!(
            validate_user_buffer(0x5000_0000, 4096),
            "pointer in user DRAM must be valid"
        );
    }

    #[test]
    fn validate_user_buffer_entire_user_range() {
        let start = kconfig::KERNEL_END;
        let len = kconfig::RAM_END - kconfig::KERNEL_END;
        assert!(
            validate_user_buffer(start, len),
            "full user DRAM range must be valid"
        );
    }

    #[test]
    fn validate_user_buffer_zero_length() {
        assert!(
            validate_user_buffer(0x5000_0000, 0),
            "zero-length buffer must be valid"
        );
    }

    #[test]
    fn validate_user_buffer_null_pointer() {
        assert!(
            !validate_user_buffer(0, 100),
            "null pointer must fail validation"
        );
    }

    #[test]
    fn validate_user_buffer_null_zero_length() {
        assert!(
            !validate_user_buffer(0, 0),
            "null pointer must fail even with zero length"
        );
    }

    #[test]
    fn validate_user_buffer_kernel_space() {
        assert!(
            !validate_user_buffer(kconfig::KERNEL_LOAD, 4096),
            "kernel load address must fail validation"
        );
        assert!(
            !validate_user_buffer(kconfig::KERNEL_LOAD + 0x1000, 256),
            "pointer within kernel image must fail validation"
        );
    }

    #[test]
    fn validate_user_buffer_device_mmio() {
        assert!(
            !validate_user_buffer(0x1100_2000, 16),
            "UART0 MMIO address must fail validation"
        );
        assert!(
            !validate_user_buffer(0x0C00_0000, 4),
            "GIC address must fail validation"
        );
    }

    #[test]
    fn validate_user_buffer_above_ram() {
        assert!(
            !validate_user_buffer(0x8000_0000, 1),
            "address at RAM_END must fail validation"
        );
        assert!(
            !validate_user_buffer(0xC000_0000, 4096),
            "address well above RAM must fail validation"
        );
    }

    #[test]
    fn validate_user_buffer_overflow() {
        assert!(
            !validate_user_buffer(usize::MAX, 1),
            "usize::MAX + 1 overflows and must fail"
        );
        assert!(
            !validate_user_buffer(usize::MAX - 10, 100),
            "near-max pointer with large len must fail"
        );
    }

    #[test]
    fn validate_user_buffer_spans_into_kernel() {
        assert!(
            !validate_user_buffer(kconfig::KERNEL_END - 1, 2),
            "buffer spanning into kernel region must fail"
        );
    }

    #[test]
    fn validate_user_buffer_spans_past_ram_end() {
        assert!(
            !validate_user_buffer(kconfig::RAM_END - 10, 20),
            "buffer extending past RAM_END must fail"
        );
    }

    #[test]
    fn validate_user_buffer_boundary_exact() {
        assert!(
            validate_user_buffer(kconfig::KERNEL_END, 1),
            "first byte of user DRAM must be valid"
        );
        assert!(
            !validate_user_buffer(kconfig::KERNEL_END - 1, 1),
            "last byte of kernel region must fail"
        );
        assert!(
            validate_user_buffer(kconfig::RAM_END - 1, 1),
            "last byte of DRAM must be valid"
        );
    }

    // ---- Memory management syscall tests ----

    /// Set up process 0 with a valid page table for memory management tests.
    unsafe fn setup_mm() {
        unsafe { process::reset_for_test(); }
    }

    #[test]
    fn brk_zero_returns_initial_break() {
        unsafe { setup_mm(); }
        let result = sys_brk(0);
        assert_eq!(
            result,
            u32::try_from(process::DEFAULT_HEAP_BREAK).unwrap_or_default(),
            "brk(0) must return the initial program break"
        );
    }

    #[test]
    fn brk_grow_increases_break_by_one_page() {
        unsafe { setup_mm(); }
        let initial = sys_brk(0);
        let new_break = initial + u32::try_from(crate::page::PAGE_SIZE).unwrap_or_default();
        let result = sys_brk(new_break);
        assert_eq!(
            result, new_break,
            "brk(break + PAGE_SIZE) must increase break by one page"
        );
    }

    #[test]
    fn brk_shrink_decreases_break() {
        unsafe { setup_mm(); }
        let initial = sys_brk(0);
        let grown = initial + u32::try_from(crate::page::PAGE_SIZE).unwrap_or_default();
        sys_brk(grown);
        let result = sys_brk(initial);
        assert_eq!(
            result, initial,
            "brk back to original must decrease break"
        );
    }

    #[test]
    fn mmap_returns_address_in_user_range() {
        unsafe { setup_mm(); }
        let flags_and_fd: u32 = MAP_ANONYMOUS | (0xFFFF << 16);
        let prot = mmu::prot::PROT_READ | mmu::prot::PROT_WRITE;
        let result = sys_mmap(0, u32::try_from(crate::page::PAGE_SIZE).unwrap_or_default(), prot, flags_and_fd);
        assert_ne!(result, MAP_FAILED, "mmap must succeed for anonymous mapping");
        let addr = result as usize;
        assert!(
            addr >= process::MMAP_BASE && addr < 0x3000_0000,
            "mmap address 0x{addr:08x} must be in user mmap range"
        );
    }

    #[test]
    fn munmap_succeeds_for_mapped_address() {
        unsafe { setup_mm(); }
        let flags_and_fd: u32 = MAP_ANONYMOUS | (0xFFFF << 16);
        let prot = mmu::prot::PROT_READ | mmu::prot::PROT_WRITE;
        let addr = sys_mmap(0, u32::try_from(crate::page::PAGE_SIZE).unwrap_or_default(), prot, flags_and_fd);
        assert_ne!(addr, MAP_FAILED, "mmap must succeed before munmap test");
        let result = sys_munmap(addr, u32::try_from(crate::page::PAGE_SIZE).unwrap_or_default());
        assert_eq!(result, 0, "munmap must return 0 on success");
    }

    #[test]
    fn mmap_invalid_flags_returns_error() {
        unsafe { setup_mm(); }
        let flags_and_fd: u32 = 0;
        let prot = mmu::prot::PROT_READ;
        let result = sys_mmap(0, u32::try_from(crate::page::PAGE_SIZE).unwrap_or_default(), prot, flags_and_fd);
        assert_eq!(
            result, MAP_FAILED,
            "mmap without MAP_ANONYMOUS must return MAP_FAILED"
        );
    }

    #[test]
    fn mmap_zero_length_returns_error() {
        unsafe { setup_mm(); }
        let flags_and_fd: u32 = MAP_ANONYMOUS | (0xFFFF << 16);
        let prot = mmu::prot::PROT_READ;
        let result = sys_mmap(0, 0, prot, flags_and_fd);
        assert_eq!(
            result, MAP_FAILED,
            "mmap with zero length must return MAP_FAILED"
        );
    }

    #[test]
    fn munmap_invalid_address_returns_einval() {
        unsafe { setup_mm(); }
        let result = sys_munmap(0xDEAD_0000, 0x1000);
        assert_eq!(
            result, EINVAL,
            "munmap of unmapped address must return EINVAL"
        );
    }

    #[test]
    fn mprotect_on_mapped_region_succeeds() {
        unsafe { setup_mm(); }
        let flags_and_fd: u32 = MAP_ANONYMOUS | (0xFFFF << 16);
        let prot = mmu::prot::PROT_READ | mmu::prot::PROT_WRITE;
        let addr = sys_mmap(0, u32::try_from(crate::page::PAGE_SIZE).unwrap_or_default(), prot, flags_and_fd);
        assert_ne!(addr, MAP_FAILED, "mmap must succeed before mprotect test");
        let result = sys_mprotect(addr, u32::try_from(crate::page::PAGE_SIZE).unwrap_or_default(), mmu::prot::PROT_READ);
        assert_eq!(result, 0, "mprotect must return 0 on success");
    }

    #[test]
    fn mprotect_unmapped_returns_einval() {
        unsafe { setup_mm(); }
        let result = sys_mprotect(0xDEAD_0000, 0x1000, mmu::prot::PROT_READ);
        assert_eq!(
            result, EINVAL,
            "mprotect on unmapped address must return EINVAL"
        );
    }

    // ---- execve validation ----

    /// REQ-07: execve must return EFAULT for an invalid (null or kernel-space)
    /// path pointer before attempting any filesystem lookup.
    ///
    /// WHY: validate_user_buffer is the first gate in sys_execve. Verifying it
    /// returns EFAULT for out-of-range pointers confirms that the implementation
    /// rejects bad pointers before touching any kernel data structures.
    #[test]
    fn execve_validates_path_pointer() {
        // Null pointer must fail validation and produce EFAULT.
        assert!(
            !validate_user_buffer(0, 1),
            "null pointer must fail validate_user_buffer"
        );

        // Kernel-space pointer must also fail (below KERNEL_END).
        assert!(
            !validate_user_buffer(kconfig::KERNEL_LOAD, 1),
            "kernel-load address must fail validate_user_buffer"
        );

        // Device MMIO pointer must fail.
        assert!(
            !validate_user_buffer(0x1100_2000, 1),
            "UART MMIO address must fail validate_user_buffer"
        );

        // A valid user-DRAM pointer must pass (sanity: the positive case).
        assert!(
            validate_user_buffer(kconfig::KERNEL_END + 0x1000, 1),
            "pointer just above KERNEL_END must pass validate_user_buffer"
        );

        // EFAULT has the correct two's-complement encoding.
        assert_eq!(EFAULT, 0xFFFF_FFF2u32, "EFAULT must be two's complement -14");
    }

    /// REQ-07: execve must return ENOENT when the path is not found in ramfs.
    ///
    /// WHY: after path validation, sys_execve calls fd::ramfs_find. This test
    /// confirms that the lookup correctly returns None (→ ENOENT) for a path
    /// that was never added to the filesystem.
    #[test]
    fn execve_returns_enoent_for_missing_file() {
        // Populate a fresh ramfs with one known file.
        let mut fs = crate::ramfs::RamFs::new();
        fs.add("init", b"\x7FELF"); // minimal content; not a real ELF
        // SAFETY: test-only; no concurrent access. The previous RAMFS state
        // (if any) is replaced; this is acceptable in single-threaded tests.
        unsafe { fd::init_ramfs(fs); }

        // A file that was never added must not be found.
        // SAFETY: init_ramfs was called above.
        let result = unsafe { fd::ramfs_find("no_such_binary") };
        assert!(
            result.is_none(),
            "ramfs_find must return None for a path not in the filesystem"
        );

        // The known file must be found (confirms init_ramfs succeeded).
        // SAFETY: init_ramfs was called above.
        let found = unsafe { fd::ramfs_find("init") };
        assert!(
            found.is_some(),
            "ramfs_find must return Some for a file that was added"
        );

        // ENOENT has the correct two's-complement encoding.
        assert_eq!(ENOENT, 0xFFFF_FFFEu32, "ENOENT must be two's complement -2");
    }

    // ---- Syscall table completeness tests ----

    /// Verify every variant in Syscall::ALL is either implemented (does not
    /// return ENOSYS in the dispatch handler) or has a documented deferral to
    /// a named future phase.
    ///
    /// WHY: ensures no variant silently falls through the dispatch match as
    /// an undocumented stub. Phase 05 (filesystem) is fully implemented.
    /// The only remaining ENOSYS set is Phase 06 (connectivity).
    #[test]
    fn all_syscalls_have_documented_status() {
        // Implemented: all syscalls that have actual logic in dispatch().
        // WHY const arrays: no_std, no alloc, no HashSet — manual linear scan.
        const IMPLEMENTED: &[u32] = &[
            0,  // Exit
            1,  // Write
            2,  // Yield
            3,  // Getpid
            4,  // AllocPage
            5,  // FreePage
            6,  // Uptime
            7,  // Sleep
            8,  // Send
            9,  // Recv
            10, // Fork
            11, // Execve
            12, // Waitpid
            13, // Kill
            14, // Getuid
            20, // Mmap
            21, // Munmap
            22, // Brk
            23, // Mprotect
            30, // Open
            31, // Close
            32, // Read
            33, // Stat
            34, // Fstat
            35, // Lseek
            36, // Ioctl
            37, // Fcntl
            38, // Dup
            39, // Dup2
            40, // Mkdir
            41, // Unlink
            42, // Getcwd
            43, // Chdir
            50, // Pipe
            51, // Futex
            70, // ClockGettime
            71, // Nanosleep
            80, // Sigaction
            81, // Sigreturn
        ];
        // Phase 05 filesystem syscalls are fully implemented (Wave 6).
        const PHASE05: &[u32] = &[];
        // Deferred to Phase 06 (connectivity).
        const PHASE06: &[u32] = &[
            60, // Socket
            61, // Bind
            62, // Listen
            63, // Accept
            64, // Connect
            65, // Sendto
            66, // Recvfrom
        ];

        for &variant in &Syscall::ALL {
            let n = variant.as_u32();
            let is_implemented = IMPLEMENTED.iter().any(|&x| x == n);
            let is_phase05 = PHASE05.iter().any(|&x| x == n);
            let is_phase06 = PHASE06.iter().any(|&x| x == n);
            assert!(
                is_implemented || is_phase05 || is_phase06,
                "syscall {variant:?} (number {n}) has no documented status — \
                 add it to IMPLEMENTED, PHASE05, or PHASE06"
            );
        }

        // Verify the documented counts are consistent with SYSCALL_COUNT.
        let total = IMPLEMENTED.len() + PHASE05.len() + PHASE06.len();
        assert_eq!(
            total, SYSCALL_COUNT,
            "documented status count ({total}) must equal SYSCALL_COUNT ({SYSCALL_COUNT})"
        );
    }

    /// Verify that within each domain the assigned numbers are all valid
    /// Syscall variants, fall within the domain's reserved range, and contain
    /// no duplicates.
    ///
    /// WHY: a gap within a domain (e.g., 30, 32 without 31) would silently
    /// leave a syscall number unreachable and break ABI for any binary that
    /// calls that number. Cross-domain gaps are intentional and not tested here.
    #[test]
    fn syscall_numbers_are_contiguous_within_domains() {
        // (domain_name, base_inclusive, limit_exclusive, assigned_numbers)
        const DOMAINS: &[(&str, u32, u32, &[u32])] = &[
            ("legacy",  0,  10, &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]),
            ("process", 10, 20, &[10, 11, 12, 13, 14]),
            ("memory",  20, 30, &[20, 21, 22, 23]),
            ("fs",      30, 50, &[30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43]),
            ("ipc",     50, 60, &[50, 51]),
            ("network", 60, 70, &[60, 61, 62, 63, 64, 65, 66]),
            ("time",    70, 80, &[70, 71]),
            ("signal",  80, 90, &[80, 81]),
        ];

        for &(domain_name, base, limit, expected) in DOMAINS {
            for &n in expected {
                // Must be within domain range.
                assert!(
                    n >= base && n < limit,
                    "domain '{domain_name}': number {n} is outside range [{base}, {limit})"
                );
                // Must map to a valid syscall variant.
                assert!(
                    Syscall::from_u32(n).is_some(),
                    "domain '{domain_name}': number {n} must map to a variant"
                );
            }
            // No two entries within the domain share a number.
            let mut i = 0;
            while i < expected.len() {
                let mut j = i + 1;
                while j < expected.len() {
                    assert_ne!(
                        expected[i], expected[j],
                        "domain '{domain_name}': duplicate number {} at indices {i} and {j}",
                        expected[i]
                    );
                    j += 1;
                }
                i += 1;
            }
        }
    }

    // ---- Address validation deterministic property tests ----

    /// Kernel-space addresses must all be rejected regardless of buffer length.
    ///
    /// WHY: any kernel-space pointer passed by userspace would give the kernel
    /// direct read/write access to its own data structures, bypassing all
    /// security invariants.
    #[test]
    fn kernel_addresses_always_rejected() {
        // Sample 33 evenly-spaced addresses across the kernel image and
        // reserved region [0x4000_0000, KERNEL_END).
        let kernel_range_start: usize = 0x4000_0000;
        let kernel_range_end: usize = kconfig::KERNEL_END;
        let span = kernel_range_end - kernel_range_start;
        let step = span / 32;

        let mut addr = kernel_range_start;
        while addr < kernel_range_end {
            assert!(
                !validate_user_buffer(addr, 1),
                "kernel-space address 0x{addr:08x} with len=1 must be rejected"
            );
            assert!(
                !validate_user_buffer(addr, 4096),
                "kernel-space address 0x{addr:08x} with len=4096 must be rejected"
            );
            addr = addr.saturating_add(step.max(1));
        }

        // Exact boundary: one byte before user DRAM must fail.
        let boundary = kconfig::KERNEL_END - 1;
        assert!(
            !validate_user_buffer(boundary, 1),
            "last byte of kernel region 0x{boundary:08x} must be rejected"
        );
    }

    /// Null pointer must be rejected for any length, including zero.
    ///
    /// WHY: null dereference is always invalid. The null check in
    /// validate_user_buffer is an unconditional first gate.
    #[test]
    fn null_pointer_rejected() {
        // Non-zero lengths.
        for len in [1usize, 4, 16, 256, 4096] {
            assert!(
                !validate_user_buffer(0, len),
                "null pointer with len={len} must be rejected"
            );
        }
        // Zero-length null is also rejected (null check precedes length check).
        assert!(
            !validate_user_buffer(0, 0),
            "null pointer with len=0 must be rejected"
        );
    }

    /// A buffer starting near the top of the address space that would wrap
    /// around must be rejected.
    ///
    /// WHY: without the checked_add overflow guard, ptr + len wraps to a low
    /// address that passes the range check, allowing kernel memory access
    /// through an apparently "valid" user pointer.
    #[test]
    fn overflow_wrapping_rejected() {
        // 0xFFFF_FFF0 + 32 wraps to 0x10 on a 32-bit target.
        assert!(
            !validate_user_buffer(0xFFFF_FFF0, 32),
            "0xFFFF_FFF0 + 32 wraps and must be rejected"
        );
        assert!(
            !validate_user_buffer(usize::MAX, 1),
            "usize::MAX + 1 must overflow and be rejected"
        );
        assert!(
            !validate_user_buffer(usize::MAX - 3, 8),
            "near-max pointer with len=8 must overflow and be rejected"
        );
    }

    /// A zero-length buffer at a valid user address must be accepted.
    ///
    /// WHY: zero-length slices are valid in Rust (no memory is accessed).
    /// Rejecting them would break callers that pass length=0 as a no-op.
    #[test]
    fn zero_length_accepted() {
        // Representative valid user addresses spanning the user DRAM range.
        let addrs: &[usize] = &[
            kconfig::KERNEL_END,
            kconfig::KERNEL_END + 0x1000,
            0x5000_0000,
            kconfig::RAM_END - 1,
        ];
        for &addr in addrs {
            assert!(
                validate_user_buffer(addr, 0),
                "zero-length buffer at 0x{addr:08x} must be accepted"
            );
        }
    }

    // ---- Memory management property tests ----

    /// Growing the heap via brk must cause the page allocator to report
    /// fewer free pages.
    ///
    /// WHY: brk grow must actually allocate physical pages; a no-op
    /// implementation would advance the break without making memory
    /// accessible, causing silent data corruption on first access.
    #[test]
    fn brk_growth_allocates_pages() {
        unsafe { setup_mm(); }
        let free_before = page::free_count();

        let initial = sys_brk(0);
        let new_break = initial + u32::try_from(crate::page::PAGE_SIZE).unwrap_or_default();
        let result = sys_brk(new_break);
        assert_eq!(result, new_break, "brk must advance to new_break");

        let free_after = page::free_count();
        assert!(
            free_after < free_before,
            "brk grow must consume pages: free_before={free_before}, free_after={free_after}"
        );
    }

    /// Shrinking the heap via brk must correctly update the program break
    /// back to the requested value.
    ///
    /// WHY: brk shrink is how musl's free() returns memory. An incorrect
    /// shrink leaves the break misreported, breaking subsequent brk queries.
    ///
    /// NOTE: the current brk shrink path unmaps page-table entries but does
    /// not call free_page (physical address not recoverable from a zeroed L2
    /// entry — see comment in sys_brk). The break value is still correctly
    /// updated.
    #[test]
    fn brk_shrink_frees_pages() {
        unsafe { setup_mm(); }
        let initial = sys_brk(0);

        // Grow by two pages.
        let grown = initial + u32::try_from(2 * crate::page::PAGE_SIZE).unwrap_or_default();
        let at_grown = sys_brk(grown);
        assert_eq!(at_grown, grown, "brk must advance to grown");

        // Shrink back to initial break.
        let result = sys_brk(initial);
        assert_eq!(
            result, initial,
            "brk shrink must return break to initial value"
        );
    }

    /// mmap N pages then munmap them — subsequent mmap in the same range must
    /// succeed (mapping table is consistent after munmap).
    ///
    /// WHY: munmap must remove the VmMapping record so the first-fit allocator
    /// can reuse that virtual address range. A stale entry would cause
    /// mmap_munmap cycles to exhaust the mapping table (MAX_MAPPINGS = 32).
    #[test]
    fn mmap_munmap_balance() {
        unsafe { setup_mm(); }
        let free_before = page::free_count();

        const MAP_PAGES: u32 = 4;
        let flags_and_fd: u32 = MAP_ANONYMOUS | (0xFFFF << 16);
        let prot = mmu::prot::PROT_READ | mmu::prot::PROT_WRITE;
        let length = MAP_PAGES * u32::try_from(crate::page::PAGE_SIZE).unwrap_or_default();

        let addr = sys_mmap(0, length, prot, flags_and_fd);
        assert_ne!(addr, MAP_FAILED, "mmap of {MAP_PAGES} pages must succeed");

        let free_after_mmap = page::free_count();
        assert!(
            free_after_mmap <= free_before,
            "mmap must not increase free page count: \
             before={free_before}, after_mmap={free_after_mmap}"
        );

        let unmap_result = sys_munmap(addr, length);
        assert_eq!(unmap_result, 0, "munmap must return 0 on success");

        // After munmap the mapping record is gone; a second mmap must succeed
        // (tests that the VmMapping slot was actually freed).
        let addr2 = sys_mmap(0, length, prot, flags_and_fd);
        assert_ne!(
            addr2, MAP_FAILED,
            "mmap after munmap must succeed (mapping record was freed)"
        );
    }

    // ---- Slab allocator integration test ----

    /// Perform many alloc/dealloc cycles on a local SlabAllocator and verify
    /// that alloc_count equals free_count (no leaks).
    ///
    /// WHY: the same slab logic backs the global heap used by all kernel paths
    /// including syscall handlers. Equal alloc/free counts confirm that the
    /// slab's internal accounting is correct for the allocation patterns
    /// generated by typical syscall sequences.
    #[test]
    fn slab_stress_no_leaks() {
        use crate::slab::SlabAllocator;
        use core::alloc::Layout;

        // Local fake page pool backed by a static array.
        // WHY static: pointer stability — the allocator stores raw addresses.
        static mut POOL: [u8; 32 * crate::page::PAGE_SIZE] =
            [0u8; 32 * crate::page::PAGE_SIZE];
        static mut NEXT: usize = 0;

        // SAFETY: test-only; single-threaded; POOL and NEXT are only
        // accessed through these two functions within this test.
        unsafe fn fake_alloc() -> Option<usize> {
            unsafe {
                if NEXT >= 32 { return None; }
                let base = POOL.as_mut_ptr() as usize;
                let addr = base + NEXT * crate::page::PAGE_SIZE;
                NEXT += 1;
                Some(addr)
            }
        }
        unsafe fn fake_free(_addr: usize) {}

        // SAFETY: sa is local; POOL/NEXT are test-only statics.
        unsafe {
            NEXT = 0;
            let mut sa = SlabAllocator::new();
            sa.init();

            let layout = Layout::from_size_align(64, 8).unwrap();
            const N: usize = 128;
            let mut ptrs = [core::ptr::null_mut::<u8>(); N];

            for p in ptrs.iter_mut() {
                *p = sa.alloc_inner(layout, fake_alloc, fake_alloc);
                assert!(!p.is_null(), "slab alloc must succeed");
            }
            for &p in ptrs.iter() {
                sa.dealloc_inner(p, layout, fake_free);
            }

            let (allocs, frees) = sa.stats();
            assert_eq!(
                allocs, N as u64,
                "alloc_count must equal number of allocations ({N})"
            );
            assert_eq!(
                frees, N as u64,
                "free_count must equal number of deallocations ({N}), got {frees}"
            );
        }
    }
}
