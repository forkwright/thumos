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
use crate::ipc;
use crate::kconfig;
use crate::process;
use crate::uart::Uart;
use core::fmt::Write;

/// Error code returned for unimplemented syscalls.
/// WHY: two's complement -38, matching Linux ARM ENOSYS convention for
/// toolchain compatibility with userspace built against Linux headers.
pub const ENOSYS: u32 = 0u32.wrapping_sub(38);

/// Error code returned when a user-supplied pointer is invalid.
/// WHY: two's complement -14, matching Linux ARM EFAULT convention.
/// Returned when a syscall argument points to kernel memory, device MMIO,
/// unmapped regions, or when a buffer overflows the address space.
pub const EFAULT: u32 = 0u32.wrapping_sub(14);

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
pub fn validate_user_buffer(ptr: usize, len: usize) -> bool {
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
pub const SYSCALL_COUNT: usize = 46;

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
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    /// Convert a raw syscall number to a [`Syscall`] variant.
    ///
    /// Returns `None` for numbers that do not correspond to a defined syscall.
    pub const fn from_u32(n: u32) -> Option<Self> {
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
    pub const ALL: [Self; SYSCALL_COUNT] = [
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
pub fn dispatch(num: u32, arg0: u32, arg1: u32, arg2: u32, arg3: u32) -> u32 {
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
        Syscall::Write => {
            let ptr = usize::try_from(arg0).unwrap_or_default();
            let len = usize::try_from(arg1).unwrap_or_default();
            if !validate_user_buffer(ptr, len) {
                return EFAULT;
            }
            // SAFETY: validate_user_buffer confirmed [ptr, ptr+len) is within
            // user-accessible DRAM, not null, not overflowing, and not in
            // kernel-reserved or device memory.
            let slice = unsafe { core::slice::from_raw_parts(ptr as *const u8, len) };
            let mut serial = Uart::new();
            for &byte in slice {
                serial.putc(byte);
            }
            u32::try_from(len).unwrap_or_default()
        }
        Syscall::Yield => {
            // NOTE: voluntary yield  -  reschedule immediately
            let next = process::schedule();
            if next != process::current_pid() {
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
            Some(msg) => u32::from(msg.FROM),
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
        Syscall::Execve | Syscall::Kill | Syscall::Getuid => ENOSYS,

        // ---- Memory management (stubs) ----

        Syscall::Mmap
        | Syscall::Munmap
        | Syscall::Brk
        | Syscall::Mprotect => ENOSYS,

        // ---- Filesystem ----
        // WHY: wired to ramfs via fd module. Read-only operations are
        // implemented; write/directory ops remain ENOSYS (future phases).

        Syscall::Open => fd::sys_open(arg0, arg1, arg2),
        Syscall::Close => fd::sys_close(arg0),
        Syscall::Read => fd::sys_read(arg0, arg1, arg2),
        Syscall::Stat => fd::sys_stat(arg0, arg1, arg2),
        Syscall::Fstat => fd::sys_fstat(arg0, arg1),
        Syscall::Lseek => fd::sys_lseek(arg0, arg1, arg2),
        Syscall::Dup => fd::sys_dup(arg0),
        Syscall::Dup2 => fd::sys_dup2(arg0, arg1),
        Syscall::Getcwd => fd::sys_getcwd(arg0, arg1),

        // WHY ENOSYS: these require write support (mkdir, unlink),
        // directory tracking (chdir), or device abstraction (ioctl, fcntl).
        // Deferred to future phases.
        Syscall::Ioctl
        | Syscall::Fcntl
        | Syscall::Mkdir
        | Syscall::Unlink
        | Syscall::Chdir => ENOSYS,

        // ---- IPC (stubs) ----

        Syscall::Pipe | Syscall::Futex => ENOSYS,

        // ---- Network (stubs) ----

        Syscall::Socket
        | Syscall::Bind
        | Syscall::Listen
        | Syscall::Accept
        | Syscall::Connect
        | Syscall::Sendto
        | Syscall::Recvfrom => ENOSYS,

        // ---- Time (stubs) ----

        Syscall::ClockGettime | Syscall::Nanosleep => ENOSYS,

        // ---- Signal (stubs) ----

        Syscall::Sigaction | Syscall::Sigreturn => ENOSYS,
    }
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
        // WHY: a pointer inside user DRAM [KERNEL_END, RAM_END) must pass.
        // 0x5000_0000 is well within the 0x4010_0000..0x8000_0000 range.
        assert!(
            validate_user_buffer(0x5000_0000, 4096),
            "pointer in user DRAM must be valid"
        );
    }

    #[test]
    fn validate_user_buffer_entire_user_range() {
        // WHY: the full user DRAM range must be valid.
        let start = kconfig::KERNEL_END;
        let len = kconfig::RAM_END - kconfig::KERNEL_END;
        assert!(
            validate_user_buffer(start, len),
            "full user DRAM range must be valid"
        );
    }

    #[test]
    fn validate_user_buffer_zero_length() {
        // WHY: zero-length reads touch no memory, so any non-null address is ok.
        assert!(
            validate_user_buffer(0x5000_0000, 0),
            "zero-length buffer must be valid"
        );
    }

    #[test]
    fn validate_user_buffer_null_pointer() {
        // WHY: null pointer dereference must be caught unconditionally.
        assert!(
            !validate_user_buffer(0, 100),
            "null pointer must fail validation"
        );
    }

    #[test]
    fn validate_user_buffer_null_zero_length() {
        // WHY: null is always invalid, even with zero length.
        assert!(
            !validate_user_buffer(0, 0),
            "null pointer must fail even with zero length"
        );
    }

    #[test]
    fn validate_user_buffer_kernel_space() {
        // WHY: kernel-reserved memory (0x4000_8000..0x4010_0000) must be
        // inaccessible to userspace syscalls to prevent privilege escalation.
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
        // WHY: device MMIO regions (below RAM_START) must be blocked to
        // prevent userspace from reading/writing hardware registers.
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
        // WHY: addresses above RAM_END (0x8000_0000) are unmapped and must
        // be rejected.
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
        // WHY: ptr + len wrapping around the address space must be caught.
        // usize::MAX with any nonzero len overflows.
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
        // WHY: a buffer that starts before KERNEL_END must not pass even if
        // it starts within the kernel reserved region.
        assert!(
            !validate_user_buffer(kconfig::KERNEL_END - 1, 2),
            "buffer spanning into kernel region must fail"
        );
    }

    #[test]
    fn validate_user_buffer_spans_past_ram_end() {
        // WHY: a buffer that starts in valid user DRAM but extends past
        // RAM_END must fail.
        assert!(
            !validate_user_buffer(kconfig::RAM_END - 10, 20),
            "buffer extending past RAM_END must fail"
        );
    }

    #[test]
    fn validate_user_buffer_boundary_exact() {
        // WHY: KERNEL_END is the first valid user address; a single byte
        // there must pass. One byte before must fail.
        assert!(
            validate_user_buffer(kconfig::KERNEL_END, 1),
            "first byte of user DRAM must be valid"
        );
        assert!(
            !validate_user_buffer(kconfig::KERNEL_END - 1, 1),
            "last byte of kernel region must fail"
        );
        // Last byte of DRAM
        assert!(
            validate_user_buffer(kconfig::RAM_END - 1, 1),
            "last byte of DRAM must be valid"
        );
    }
}
