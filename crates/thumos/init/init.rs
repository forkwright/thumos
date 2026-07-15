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

/// sleep(ms): suspend this process for at least `ms` milliseconds (#477 harness).
///
/// # Safety
/// Yields to the scheduler; the kernel resumes this process after the interval.
#[cfg(any(thumos_init_sleep, thumos_init_fork, thumos_init_forkexec))]
#[inline(always)]
unsafe fn sys_sleep(ms: u32) {
    // SAFETY: issues SVC #7 (Sleep) per the thumos ABI; the kernel marks this
    // process Sleeping, switches away, and resumes it after `ms` elapses.
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

/// fork() -> child pid in the parent, 0 in the child, u32::MAX on failure.
///
/// # Safety
/// Creates a child process; both branches return here (the #478 ctx seed).
#[cfg(any(thumos_init_fork, thumos_init_forkexec))]
#[inline(always)]
unsafe fn sys_fork() -> u32 {
    let ret;
    // SAFETY: SVC #10 (Fork) per the thumos ABI.
    unsafe {
        core::arch::asm!("svc #0", in("r7") 10u32, lateout("r0") ret, options(nostack));
    }
    ret
}

/// waitpid(pid) -> exit status, or u32::MAX while the child is not yet Dead
/// (non-blocking).
///
/// # Safety
/// Reads a child's exit status; reaps its slot when Dead.
#[cfg(any(thumos_init_fork, thumos_init_forkexec))]
#[inline(always)]
unsafe fn sys_waitpid(pid: u32) -> u32 {
    let ret;
    // SAFETY: SVC #12 (Waitpid) per the thumos ABI.
    unsafe {
        core::arch::asm!("svc #0", in("r7") 12u32, inlateout("r0") pid => ret, options(nostack));
    }
    ret
}

/// .data isolation canary (#478): a user-RW image page. The child mutates its
/// OWN copy; a shared-page fork would leak the mutation into the parent.
#[cfg(thumos_init_fork)]
static mut FORK_DATA_CANARY: u32 = 0x0000_5EED;

/// #502 parent-integrity canary: a .data value the forkexec parent re-checks
/// after the child's exec + exit. A wrong-owner free during the child's exec
/// (per-process image mapping done wrong) would zero the parent's OWN image
/// frame -- this catches that where a fork/exit count alone would not.
#[cfg(thumos_init_forkexec)]
static mut PARENT_CANARY: u32 = 0x600D_600D;

/// execve(path, argv, envp) -> only returns (u32 errno) on FAILURE (#489); on
/// success the process image is replaced and never returns here.
///
/// # Safety
/// Replaces this process's image with the program at `path`.
#[cfg(any(thumos_init_exec, thumos_init_forkexec))]
#[inline(always)]
unsafe fn sys_execve(path: *const u8, argv: u32, envp: u32) -> u32 {
    let ret;
    // SAFETY: SVC #11 (Execve) per the thumos ABI.
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("r7") 11u32,
            // Pointer in, errno out -- passed directly (no int cast); asm allows
            // differing in/out types on one register.
            inlateout("r0") path => ret,
            in("r1") argv,
            in("r2") envp,
            options(nostack),
        );
    }
    ret
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
    // WHY (#491 review): emit a per-variant marker BEFORE the illegal op so CI
    // can tell the probes apart -- kread and kwrite otherwise produce identical
    // kind=data-abort output, so a cfg copy-paste swap would be invisible. A
    // successful write here also confirms /init reached PL0 and can syscall.
    #[cfg(any(
        thumos_init_kread,
        thumos_init_kwrite,
        thumos_init_kexec,
        thumos_init_cp15
    ))]
    // SAFETY: the marker literal lives in the loaded image (PL0-readable); the
    // write is a normal syscall that returns before the illegal op below.
    unsafe {
        #[cfg(thumos_init_kread)]
        let marker: &[u8] = b"PROBE: kread\n";
        #[cfg(thumos_init_kwrite)]
        let marker: &[u8] = b"PROBE: kwrite\n";
        #[cfg(thumos_init_kexec)]
        let marker: &[u8] = b"PROBE: kexec\n";
        #[cfg(thumos_init_cp15)]
        let marker: &[u8] = b"PROBE: cp15\n";
        sys_write(1, marker.as_ptr(), u32::try_from(marker.len()).unwrap_or(0));
    }
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
        // #489 exec harness: exec /init2. On success this process is replaced by
        // /init2 (which runs at PL0 and never returns here); on failure execve
        // returns an errno. NULL argv (argv-across-exec is a separate refinement,
        // #499).
        #[cfg(thumos_init_exec)]
        {
            let m = b"init: exec-ing /init2\n";
            sys_write(1, m.as_ptr(), u32::try_from(m.len()).unwrap_or(0));
            sys_execve(b"/init2\0".as_ptr(), 0, 0);
            // Only reached if execve FAILED (it does not return on success).
            let f = b"init: exec FAILED\n";
            sys_write(1, f.as_ptr(), u32::try_from(f.len()).unwrap_or(0));
            sys_exit(1);
        }
        // #477 sleep harness: sleep, then continue. If the kernel's sleep is a
        // real yield, /init suspends (the service loop runs meanwhile) and
        // resumes to print "woke"; a broken busy-wait sleep runs IRQ-masked and
        // hard-hangs the whole kernel (runner timeout), so "woke" never prints.
        #[cfg(thumos_init_sleep)]
        {
            let s = b"init: sleeping\n";
            sys_write(1, s.as_ptr(), u32::try_from(s.len()).unwrap_or(0));
            sys_sleep(30); // 30 ms = 3 scheduler ticks
            let w = b"init: woke\n";
            sys_write(1, w.as_ptr(), u32::try_from(w.len()).unwrap_or(0));
        }
        // #478 fork harness: fork, both branches write a DISTINCT marker (proving
        // the r0 split + the child resuming at the fork return), the child
        // mutates two canaries the parent then checks (a shared-page fork leaks
        // them = isolation BROKEN), the child exits and the parent waitpids it.
        #[cfg(thumos_init_fork)]
        {
            let mut stack_canary: u32 = 0xA5A5_5A5A;
            core::ptr::write_volatile(&mut stack_canary, 0xA5A5_5A5A);
            let pid = sys_fork();
            if pid == 0 {
                // CHILD: resumes HERE (the fork return) iff the ctx seed is
                // right; mutates its OWN canary copies.
                core::ptr::write_volatile(&mut stack_canary, 0xDEAD_DEAD);
                core::ptr::write_volatile(core::ptr::addr_of_mut!(FORK_DATA_CANARY), 0xDEAD_DEAD);
                let m = b"init: fork child\n";
                sys_write(1, m.as_ptr(), u32::try_from(m.len()).unwrap_or(0));
                sys_exit(7);
            }
            if pid == u32::MAX {
                let m = b"init: fork FAILED\n";
                sys_write(1, m.as_ptr(), u32::try_from(m.len()).unwrap_or(0));
                sys_exit(1);
            }
            let m = b"init: fork parent\n";
            sys_write(1, m.as_ptr(), u32::try_from(m.len()).unwrap_or(0));
            // Reap: waitpid is non-blocking (u32::MAX until Dead); sleep yields
            // so the Ready child runs.
            loop {
                if sys_waitpid(pid) != u32::MAX {
                    break;
                }
                sys_sleep(10);
            }
            let ok = core::ptr::read_volatile(&stack_canary) == 0xA5A5_5A5A
                && core::ptr::read_volatile(core::ptr::addr_of!(FORK_DATA_CANARY)) == 0x0000_5EED;
            let m: &[u8] = if ok {
                b"init: fork isolation intact\n"
            } else {
                b"init: fork isolation BROKEN\n"
            };
            sys_write(1, m.as_ptr(), u32::try_from(m.len()).unwrap_or(0));
        }
        // #502 forkexec harness: /init forks; the CHILD execs /init2 (which must
        // run /init2's OWN image + print "init2: reached via exec", NOT re-run
        // this /init image -- the identity-USER_TEXT fork bomb); the PARENT
        // waitpids the child, then verifies its own .data survived the child's
        // exec (a wrong-owner free during exec would zero the parent's frame).
        #[cfg(thumos_init_forkexec)]
        {
            let s = b"forkexec: start\n";
            sys_write(1, s.as_ptr(), u32::try_from(s.len()).unwrap_or(0));
            core::ptr::write_volatile(core::ptr::addr_of_mut!(PARENT_CANARY), 0x600D_600D);
            let pid = sys_fork();
            if pid == 0 {
                // CHILD: exec /init2. On success this image is replaced (never
                // returns here); a #502 fork bomb would re-run THIS /init instead.
                let m = b"forkexec: child exec-ing /init2\n";
                sys_write(1, m.as_ptr(), u32::try_from(m.len()).unwrap_or(0));
                sys_execve(b"/init2\0".as_ptr(), 0, 0);
                let f = b"forkexec: child exec FAILED\n";
                sys_write(1, f.as_ptr(), u32::try_from(f.len()).unwrap_or(0));
                sys_exit(1);
            }
            if pid == u32::MAX {
                let m = b"forkexec: fork FAILED\n";
                sys_write(1, m.as_ptr(), u32::try_from(m.len()).unwrap_or(0));
                sys_exit(1);
            }
            let m = b"forkexec: parent waiting\n";
            sys_write(1, m.as_ptr(), u32::try_from(m.len()).unwrap_or(0));
            // Reap the child (non-blocking waitpid; sleep yields to the child).
            loop {
                if sys_waitpid(pid) != u32::MAX {
                    break;
                }
                sys_sleep(10);
            }
            let ok = core::ptr::read_volatile(core::ptr::addr_of!(PARENT_CANARY)) == 0x600D_600D;
            let m: &[u8] = if ok {
                b"forkexec: parent integrity ok\n"
            } else {
                b"forkexec: parent integrity BROKEN\n"
            };
            sys_write(1, m.as_ptr(), u32::try_from(m.len()).unwrap_or(0));
        }
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
