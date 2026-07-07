//! thumos /init2 (#489): the exec target for the fork/exec harness.
//!
//! A second userspace program, built + embedded like /init. The exec /init
//! variant execs this; it proves the NEW image runs at PL0 (via a privileged
//! cp15 read that UNDEF-faults at PL0) with the old image gone.
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

/// ELF entry point.
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let msg = b"init2: reached via exec\n";
    // SAFETY: msg is a .rodata literal in the loaded image; the cp15 read below
    // UNDEF-faults at PL0 (proving the exec'd image dropped to PL0), so control
    // does not fall through -- if it DID, the mode drop across exec is broken.
    unsafe {
        sys_write(1, msg.as_ptr(), u32::try_from(msg.len()).unwrap_or(0));
        // Privileged read (SCTLR) -- UNDEF at PL0, succeeds at PL1.
        core::arch::asm!("mrc p15, 0, {}, c1, c0, 0", out(reg) _);
        // Only reached if the exec'd image runs PRIVILEGED (a bug).
        let bad = b"init2: PRIVILEGED\n";
        sys_write(1, bad.as_ptr(), u32::try_from(bad.len()).unwrap_or(0));
        sys_exit(1);
    }
}

/// Panic handler: exit(1).
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // SAFETY: exit is the only action available.
    unsafe { sys_exit(1) }
}
