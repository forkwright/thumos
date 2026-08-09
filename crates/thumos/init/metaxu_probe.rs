//! thumos /metaxu_probe (#544 on-device leg): the userspace origin of the
//! authenticated Aletheia round trip.
//!
//! Criterion 3's done-when is "one harmless typed task that travels from a
//! real Thumos userspace process to an Aletheia endpoint and returns" --
//! this program IS that process. It never touches the wire itself (PL0 has
//! no MMIO access, by design); it issues two syscalls
//! (`MetaxuSubmit`/`MetaxuPoll`, syscall.rs #52/#53) and the KERNEL
//! performs the real `metaxu-core` encode/UART/decode/verify sequence
//! (`metaxu_bridge.rs`) against the `pylon-bridge` host process on the
//! other end of the second PL011.
//!
//! `MetaxuPoll` is non-blocking (mirrors `Uart::getc`); this program
//! busy-polls it first (costs no scheduler ticks -- see
//! `BUSY_POLL_ATTEMPTS`'s doc) and falls back to a small number of
//! `sys_sleep`-paced retries, the SAME poll-with-sleep idiom `init.rs`'s
//! fork/forkexec/guard harnesses use for a child's non-blocking
//! `waitpid`, only reached if the busy-poll bound is not enough.
//!
//! kinit spawns this ONLY under the `metaxu-probe` feature (never in a
//! normal boot, mirrors `/crasher`'s `crashloop-probe` gating) -- see
//! `crates/thumos/src/kinit.rs`.
#![no_std]
#![no_main]

/// write(fd, buf, len) via the thumos ABI (r7 = num, r0-r2 = args).
///
/// # Safety
/// `buf` must point to `len` readable bytes in the loaded image.
#[inline(always)]
unsafe fn sys_write(fd: u32, buf: *const u8, len: u32) -> u32 {
    let ret;
    // SAFETY: SVC #1 (Write); the kernel validates the buffer.
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("r7") 1u32,
            inlateout("r0") fd => ret,
            in("r1") buf,
            in("r2") len,
            options(nostack),
        );
    }
    ret
}

/// sleep(ms): suspend this process for at least `ms` milliseconds.
///
/// # Safety
/// Yields to the scheduler; the kernel resumes this process after the interval.
#[inline(always)]
unsafe fn sys_sleep(ms: u32) {
    // SAFETY: SVC #7 (Sleep) per the thumos ABI.
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("r7") 7u32,
            in("r0") ms,
            lateout("r0") _,
            options(nostack),
        );
    }
}

/// exit(code): never returns.
///
/// # Safety
/// Ends the process; the kernel switches away.
#[inline(always)]
unsafe fn sys_exit(code: u32) -> ! {
    // SAFETY: SVC #0 (Exit); does not return.
    unsafe {
        core::arch::asm!("svc #0", in("r7") 0u32, in("r0") code, options(noreturn, nostack));
    }
}

/// metaxu_submit() -> status (#544, syscall.rs `Syscall::MetaxuSubmit`
/// = 52): build + sign the authenticated request and write it to the
/// second UART. 0 on success.
///
/// # Safety
/// Issues SVC #52 per the thumos ABI.
#[inline(always)]
unsafe fn sys_metaxu_submit() -> u32 {
    let ret;
    // SAFETY: SVC #52 (MetaxuSubmit).
    unsafe {
        core::arch::asm!("svc #0", in("r7") 52u32, lateout("r0") ret, options(nostack));
    }
    ret
}

/// metaxu_poll() -> status (#544, syscall.rs `Syscall::MetaxuPoll` = 53):
/// non-blocking check for the response. Returns `EAGAIN` until a complete
/// frame has arrived, then a definitive outcome code.
///
/// # Safety
/// Issues SVC #53 per the thumos ABI.
#[inline(always)]
unsafe fn sys_metaxu_poll() -> u32 {
    let ret;
    // SAFETY: SVC #53 (MetaxuPoll).
    unsafe {
        core::arch::asm!("svc #0", in("r7") 53u32, lateout("r0") ret, options(nostack));
    }
    ret
}

/// EAGAIN (two's complement -11), mirroring `crate::syscall::EAGAIN` --
/// userspace has no access to the kernel crate, so the ABI constant is
/// restated here (matches Linux ARM's EAGAIN, the same convention every
/// other thumos syscall returning "would block" uses).
const EAGAIN: u32 = 0u32.wrapping_sub(11);

/// Busy-poll attempts (no `sys_sleep` between them) before falling back to
/// a `sys_sleep`-paced retry.
///
/// WHY busy-poll first (#544, found via a real QEMU boot): the round trip
/// itself is fast in real wall-clock time (UART TX/RX + a local TCP hop +
/// pylon-bridge's compute, all sub-millisecond in practice), but
/// `kardia::QEMU_TICK_CAP` bounds the ENTIRE boot+service-loop run to a
/// fixed, small tick budget shared with every other process and the
/// kernel's own per-tick housekeeping. A `sys_sleep`-paced retry loop
/// spends that shared budget just waiting -- the busy-poll costs no ticks
/// at all (a `sys_metaxu_poll` syscall does not sleep or yield), so it
/// finds an already-arrived response on one of its first iterations
/// without competing for the scarce tick budget other processes need too.
const BUSY_POLL_ATTEMPTS: u32 = 200_000;

/// `sys_sleep`-paced fallback attempts, each costing one tick (`TICK_MS`
/// in syscall.rs) -- a much smaller budget than the busy-poll's, for the
/// genuinely-slow case the busy-poll bound does not cover.
const SLEEP_POLL_ATTEMPTS: u32 = 5;

/// ELF entry point.
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    // SAFETY: every literal below is a .rodata slice in the loaded image
    // (VA >= 0x40100000); every syscall wrapper validates its own args.
    unsafe {
        let submit_rc = sys_metaxu_submit();
        if submit_rc != 0 {
            let m = b"metaxu: submit failed\n";
            sys_write(1, m.as_ptr(), u32::try_from(m.len()).unwrap_or(0));
            sys_exit(1);
        }
        let m = b"metaxu: request submitted\n";
        sys_write(1, m.as_ptr(), u32::try_from(m.len()).unwrap_or(0));

        let mut busy_attempts: u32 = 0;
        let mut sleep_attempts: u32 = 0;
        let rc = loop {
            let rc = sys_metaxu_poll();
            if rc != EAGAIN {
                break rc;
            }
            busy_attempts += 1;
            if busy_attempts <= BUSY_POLL_ATTEMPTS {
                continue;
            }
            sleep_attempts += 1;
            if sleep_attempts > SLEEP_POLL_ATTEMPTS {
                let m = b"metaxu: round trip timed out\n";
                sys_write(1, m.as_ptr(), u32::try_from(m.len()).unwrap_or(0));
                sys_exit(1);
            }
            sys_sleep(10);
        };
        let m: &[u8] = match rc {
            0 => b"metaxu: round trip accepted\n",
            1 => b"metaxu: round trip rejected\n",
            2 => b"metaxu: round trip mac verification failed\n",
            3 => b"metaxu: round trip response mismatch\n",
            _ => b"metaxu: round trip transport error\n",
        };
        sys_write(1, m.as_ptr(), u32::try_from(m.len()).unwrap_or(0));
        sys_exit(0);
    }
}

/// Panic handler: exit(1). no_std has no unwinding.
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // SAFETY: exit is the only action available; nothing reads its result.
    unsafe { sys_exit(1) }
}
