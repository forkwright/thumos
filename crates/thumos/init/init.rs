//! thumos /init (#474): minimal userspace bring-up program.
//!
//! Built by build.rs to a static armv7a ELF linked at 0x7FF00000
//! (kconfig::USER_TEXT_BASE), wrapped in a newc CPIO, and embedded into the
//! kernel image. kinit spawns it from the boot root ramfs.
//!
//! Runs UNPRIVILEGED: spawn_user runs this at PL0 (User mode) in its own
//! address space with the image mapped W^X (#482), so a kernel-memory access
//! faults. Proves the spawn -> schedule -> SVC -> dispatch path AND the
//! isolation boundary (see the #487 probe variants below).
#![no_std]
#![no_main]

// WHY: thumos syscall ABI -- r7 = syscall number, r0-r3 = args, return in r0
// (exceptions.rs svc_handler). Numbers from syscall.rs: Write = 1, Exit = 0.

/// write(fd, buf, len) -> bytes written / negative errno.
///
/// # Safety
/// `buf` must point to `len` readable bytes inside the loaded image
/// (VA >= 0x40100000, the range the kernel's validate_user_buffer accepts).
#[inline(always)]
unsafe fn sys_write(fd: u32, buf: *const u8, len: u32) -> u32 {
    let ret;
    // SAFETY: issues SVC #1 (Write) per the thumos ABI; the kernel validates
    // the buffer before reading it.
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

/// exit(code): terminate this process; never returns.
///
/// # Safety
/// Ends the process -- the kernel context-switches away and never resumes it.
#[inline(always)]
unsafe fn sys_exit(code: u32) -> ! {
    // SAFETY: issues SVC #0 (Exit); dispatch calls process::exit_with_status,
    // which switches away and does not return through the SVC path.
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("r7") 0u32,
            in("r0") code,
            options(noreturn, nostack),
        );
    }
}

/// ELF entry point (e_entry). The kernel transmutes the loaded entry to
/// PL0 isolation probe (#487): under a `thumos_init_<variant>` cfg (set by
/// build.rs from THUMOS_INIT_VARIANT), attempt a kernel-memory or privileged
/// operation that MUST fault at PL0 -- BEFORE the normal write, so a working
/// isolation boundary faults and "hello from userspace" never prints. CI
/// asserts the exact qemu abort exit code per variant. The default build (no
/// cfg) is a no-op, so /init behaves normally.
///
/// # Safety
/// Each probe deliberately performs an operation that is illegal at PL0; on a
/// correctly-isolated kernel it faults (never returns to the caller).
#[inline(always)]
unsafe fn isolation_probe() {
    // Kernel load address (0x4000_8000) -- PL1-only in every process page
    // table (#482), so a PL0 read data-aborts (qemu exit 2).
    #[cfg(thumos_init_kread)]
    // SAFETY: the read is expected to fault at PL0; it never completes.
    unsafe {
        core::ptr::read_volatile(0x4000_8000 as *const u32);
    }
    // A PL0 WRITE to kernel memory (the more dangerous capability) must also
    // data-abort (exit 2). With the ARM AP model a page is all-or-nothing for
    // PL0, so this shares the read's fault, but it exercises the write fault
    // path specifically -- the capability an isolation break would most want.
    #[cfg(thumos_init_kwrite)]
    // SAFETY: the write is expected to fault at PL0; it never completes.
    unsafe {
        core::ptr::write_volatile(0x4000_8000 as *mut u32, 0);
    }
    // Kernel .text (PL1-RX) -- a PL0 instruction fetch prefetch-aborts (exit 3).
    #[cfg(thumos_init_kexec)]
    // SAFETY: transmuting a kernel address to a fn and calling it is expected
    // to prefetch-abort at PL0; it never returns.
    unsafe {
        let f: extern "C" fn() = core::mem::transmute(0x4000_8000usize);
        f();
    }
    // CP15 read (SCTLR) is privileged -- undefined instruction at PL0 (exit 4).
    // Proves the mode drop directly: at PL1 this succeeds, so a broken drop
    // would fall through to exit 0 (a visible red).
    #[cfg(thumos_init_cp15)]
    // SAFETY: mrc p15 at PL0 traps as UNDEF; it never completes.
    unsafe {
        core::arch::asm!("mrc p15, 0, {}, c1, c0, 0", out(reg) _);
    }
}

/// `fn() -> !` and calls it on the kernel-allocated process stack.
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let msg = b"init: hello from userspace\n";
    // SAFETY: `msg` is a .rodata literal in the loaded image (VA >= 0x40100000);
    // sys_exit terminates the process so control never falls through.
    unsafe {
        // #487: no-op unless an isolation-probe variant is compiled, in which
        // case this faults at PL0 before the write.
        isolation_probe();
        sys_write(1, msg.as_ptr(), u32::try_from(msg.len()).unwrap_or(0));
        sys_exit(0);
    }
}

/// Panic handler: exit(1). no_std has no unwinding.
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // SAFETY: exit is the only action available; nothing reads its result.
    unsafe { sys_exit(1) }
}
