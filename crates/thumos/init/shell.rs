//! thumos /shell (#526): a SECOND boot-resident userspace program.
//!
//! kinit spawns BOTH /init (PID 1) and /shell (PID 2) from the boot ramfs.
//! Pre-#502 this was impossible: every image mapped at the identity
//! USER_TEXT_BASE, so /shell would clobber /init's live image. #502 gave each
//! process its OWN per-process image frame, so the two coexist -- this program
//! is the witness: it prints a marker and exits cleanly, proving a second image
//! ran from its own frame while /init's frame stayed intact.
//!
//! Deliberately does NO privileged probe (unlike init2.rs, which UNDEF-faults
//! as its PL0 proof): /shell is auto-spawned on EVERY boot, so a fault here
//! would break every init variant. A richer interactive shell is future work.
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
    let msg = b"shell: hello from userspace\n";
    // SAFETY: msg is a .rodata literal in the loaded image; sys_exit terminates
    // the process so control never falls through.
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
