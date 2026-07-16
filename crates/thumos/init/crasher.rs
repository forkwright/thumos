//! thumos /crasher (#492): the fault-supervisor witness.
//!
//! A supervised service that FAULTS on every launch. It prints a marker first --
//! so the log proves the image actually RAN, not merely that spawn returned --
//! then reads kernel memory, which data-aborts at PL0 (0x4000_8000 is PL1-only
//! in every process table, #482), killing it every time.
//!
//! kinit spawns + registers it supervised ONLY under the `crashloop-probe`
//! feature, so PID 0's restart policy can be witnessed end to end in QEMU:
//! restart, restart, restart, then give up. It is never in a normal boot.
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
    let msg = b"crasher: start\n";
    // SAFETY: msg is a .rodata literal in the loaded image; the kernel read below
    // data-aborts at PL0, so control never falls through on a correctly-isolated
    // kernel -- this process is killed on every launch, by design.
    unsafe {
        sys_write(1, msg.as_ptr(), u32::try_from(msg.len()).unwrap_or(0));
        core::ptr::read_volatile(0x4000_8000 as *const u32);
        // Only reached if the kernel read did NOT fault (isolation broken).
        let bad = b"crasher: NOT killed\n";
        sys_write(1, bad.as_ptr(), u32::try_from(bad.len()).unwrap_or(0));
        sys_exit(1);
    }
}

/// Panic handler: exit(1). no_std has no unwinding.
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // SAFETY: exit is the only action available; nothing reads its result.
    unsafe { sys_exit(1) }
}
