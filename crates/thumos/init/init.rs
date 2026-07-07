//! thumos /init (#474): minimal userspace bring-up program.
//!
//! Built by build.rs to a static armv7a ELF linked at 0x40100000
//! (kconfig::KERNEL_END), wrapped in a newc CPIO, and embedded into the
//! kernel image. kinit spawns it from the boot root ramfs.
//!
//! WHY privileged: spawn currently runs this at PL1 (System mode) in the
//! kernel address space -- true PL0 usermode isolation (own page table, W^X
//! user pages, exception-return) is deferred (elf.rs Wave 4+). This proves the
//! spawn -> schedule -> SVC -> dispatch path end to end, not a security
//! boundary.
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
/// `fn() -> !` and calls it on the kernel-allocated process stack.
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let msg = b"init: hello from userspace\n";
    // SAFETY: `msg` is a .rodata literal in the loaded image (VA >= 0x40100000);
    // sys_exit terminates the process so control never falls through.
    unsafe {
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
