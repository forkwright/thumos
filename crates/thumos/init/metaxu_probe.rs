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
//! `MetaxuPoll` is non-blocking (mirrors `Uart::getc`); this program polls
//! it with `sys_sleep` between attempts -- the SAME poll-with-sleep idiom
//! `init.rs`'s fork/forkexec/guard harnesses already use for a child's
//! non-blocking `waitpid`.
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

/// Poll attempts before giving up: 200 x 10 ms = ~2 s, comfortably inside
/// the witness's overall QEMU timeout.
const MAX_POLL_ATTEMPTS: u32 = 200;

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

        let mut attempts: u32 = 0;
        loop {
            let rc = sys_metaxu_poll();
            if rc == EAGAIN {
                attempts += 1;
                if attempts > MAX_POLL_ATTEMPTS {
                    let m = b"metaxu: round trip timed out\n";
                    sys_write(1, m.as_ptr(), u32::try_from(m.len()).unwrap_or(0));
                    sys_exit(1);
                }
                sys_sleep(10);
                continue;
            }
            let m: &[u8] = match rc {
                0 => b"metaxu: round trip accepted\n",
                1 => b"metaxu: round trip rejected\n",
                2 => b"metaxu: round trip mac verification failed\n",
                3 => b"metaxu: round trip response mismatch\n",
                _ => b"metaxu: round trip transport error\n",
            };
            sys_write(1, m.as_ptr(), u32::try_from(m.len()).unwrap_or(0));
            break;
        }
        sys_exit(0);
    }
}

/// Panic handler: exit(1). no_std has no unwinding.
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // SAFETY: exit is the only action available; nothing reads its result.
    unsafe { sys_exit(1) }
}
