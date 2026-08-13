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
#[cfg(any(thumos_init_sleep, thumos_init_fork, thumos_init_forkexec, thumos_init_guard, thumos_init_signal))]
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

/// sigaction(signum, handler) -> 0 on success (#446 signal harness).
///
/// # Safety
/// `handler` must be a PL0-executable function address in this image (or 0
/// for the default action, 1 for ignore), per sys_sigaction's contract.
#[cfg(thumos_init_signal)]
#[inline(always)]
unsafe fn sys_sigaction(signum: u32, handler: u32) -> u32 {
    let ret;
    // SAFETY: issues SVC #80 (Sigaction) per the thumos ABI.
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("r7") 80u32,
            inlateout("r0") signum => ret,
            in("r1") handler,
            options(nostack),
        );
    }
    ret
}

/// kill(pid, signum) -> 0 on success, negative errno otherwise (#446 harness).
///
/// # Safety
/// Raising a signal against this (or a permitted) process.
#[cfg(thumos_init_signal)]
#[inline(always)]
unsafe fn sys_kill(pid: u32, signum: u32) -> u32 {
    let ret;
    // SAFETY: issues SVC #13 (Kill) per the thumos ABI.
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("r7") 13u32,
            inlateout("r0") pid => ret,
            in("r1") signum,
            options(nostack),
        );
    }
    ret
}

/// getpid() -> this process's PID (#446 harness).
///
/// # Safety
/// Issues SVC #3 (Getpid) per the thumos ABI.
#[cfg(thumos_init_signal)]
#[inline(always)]
unsafe fn sys_getpid() -> u32 {
    let ret;
    // SAFETY: SVC #3.
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("r7") 3u32,
            lateout("r0") ret,
            options(nostack),
        );
    }
    ret
}

/// The SIGUSR1 handler (#446): the kernel delivers into this function with
/// the signal frame as its stack and the sigreturn trampoline as lr. Writing
/// a marker proves handler ENTRY; returning enters the trampoline, whose
/// ldr+svc drives sigreturn_frame back to the interrupted flow.
#[cfg(thumos_init_signal)]
unsafe fn usr1_handler() {
    let m = b"signal: handler usr1\n";
    // SAFETY: marker literal is PL0-readable; sys_write is a plain syscall.
    unsafe {
        sys_write(1, m.as_ptr(), u32::try_from(m.len()).unwrap_or(0));
    }
}

/// The SIGUSR2 handler (#446): its marker MUST appear only if SIGUSR2's
/// pending bit survived SIGUSR1's delivery + sigreturn — the exact-clear
/// contract (the old clear-any-pending could clear the wrong signal).
#[cfg(thumos_init_signal)]
unsafe fn usr2_handler() {
    let m = b"signal: handler usr2\n";
    // SAFETY: as usr1_handler.
    unsafe {
        sys_write(1, m.as_ptr(), u32::try_from(m.len()).unwrap_or(0));
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
#[cfg(any(thumos_init_fork, thumos_init_forkexec, thumos_init_guard, thumos_init_signal))]
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
#[cfg(any(thumos_init_fork, thumos_init_forkexec, thumos_init_guard, thumos_init_signal))]
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

/// mmap(addr_hint, len, prot, flags) -> mapped address, or u32::MAX (MAP_FAILED).
///
/// # Safety
/// Requests a new user mapping; the returned VA is valid only if != u32::MAX.
#[cfg(thumos_init_guard)]
#[inline(always)]
unsafe fn sys_mmap(addr: u32, len: u32, prot: u32, flags: u32) -> u32 {
    let ret;
    // SAFETY: SVC #20 (Mmap) per the thumos ABI.
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("r7") 20u32,
            inlateout("r0") addr => ret,
            in("r1") len,
            in("r2") prot,
            in("r3") flags,
            options(nostack),
        );
    }
    ret
}

/// mprotect(addr, len, prot) -> 0 on success, else an errno.
///
/// # Safety
/// Changes the protection of an existing user mapping.
#[cfg(thumos_init_guard)]
#[inline(always)]
unsafe fn sys_mprotect(addr: u32, len: u32, prot: u32) -> u32 {
    let ret;
    // SAFETY: SVC #23 (Mprotect) per the thumos ABI.
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("r7") 23u32,
            inlateout("r0") addr => ret,
            in("r1") len,
            in("r2") prot,
            options(nostack),
        );
    }
    ret
}

/// brk(new_break) -> the (possibly updated) program break. The kernel reports
/// failure by returning the UNCHANGED break (Linux convention), never an
/// errno.
///
/// # Safety
/// Adjusts this process's heap break; pages at/above the new break are
/// unmapped and freed.
#[cfg(thumos_init_brk)]
#[inline(always)]
unsafe fn sys_brk(new_break: u32) -> u32 {
    let ret;
    // SAFETY: SVC #22 (Brk) per the thumos ABI.
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("r7") 22u32,
            inlateout("r0") new_break => ret,
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
        // #496 guard harness: mmap a PROT_NONE guard page, fork, and prove the
        // child got its OWN copy of the guard page -- a read faults with a
        // PERMISSION status (the page EXISTS as PROT_NONE, so fork enumerated the
        // PL0-inaccessible page), not a TRANSLATION status (which would mean fork
        // dropped it). Then the parent lifts the guard to PROT_READ and reads it.
        #[cfg(thumos_init_guard)]
        {
            // prot = PROT_NONE (0); flags = MAP_ANONYMOUS (0x20) | fd(-1) in the
            // high 16 bits (0xFFFF). In a fresh /init the first mmap lands
            // deterministically at MMAP_BASE.
            let guard = sys_mmap(0, 4096, 0, 0xFFFF_0020);
            if guard == u32::MAX {
                let m = b"init: guard mmap FAILED\n";
                sys_write(1, m.as_ptr(), u32::try_from(m.len()).unwrap_or(0));
                sys_exit(1);
            }
            let m = b"init: guard mapped\n";
            sys_write(1, m.as_ptr(), u32::try_from(m.len()).unwrap_or(0));
            // The guard VA as a pointer, converted once (mmap returned != MAX).
            let guard_addr = usize::try_from(guard).unwrap_or(0) as *const u32;
            let pid = sys_fork();
            if pid == 0 {
                // CHILD: touch the guard -> data-abort. A permission fault
                // (DFSR status ...0f) proves fork COPIED the PROT_NONE page; a
                // translation fault (...07) would mean it was dropped.
                core::ptr::read_volatile(guard_addr);
                // Only reached if the read did NOT fault -- guard not enforced.
                let m = b"init: guard NOT enforced\n";
                sys_write(1, m.as_ptr(), u32::try_from(m.len()).unwrap_or(0));
                sys_exit(2);
            }
            if pid == u32::MAX {
                let m = b"init: guard fork FAILED\n";
                sys_write(1, m.as_ptr(), u32::try_from(m.len()).unwrap_or(0));
                sys_exit(1);
            }
            // PARENT: reap the guard-killed child (SIGSEGV -> status 139).
            let status = loop {
                let s = sys_waitpid(pid);
                if s != u32::MAX {
                    break s;
                }
                sys_sleep(10);
            };
            let m: &[u8] = if status == 139 {
                b"init: guard child killed status=139\n"
            } else {
                b"init: guard child WRONG status\n"
            };
            sys_write(1, m.as_ptr(), u32::try_from(m.len()).unwrap_or(0));
            // PARENT: lift the guard to PROT_READ (=1) and read it -- the frame
            // survived, and NONE->READ is a live mprotect on a PROT_NONE page.
            if sys_mprotect(guard, 4096, 1) != 0 {
                let m = b"init: guard mprotect FAILED\n";
                sys_write(1, m.as_ptr(), u32::try_from(m.len()).unwrap_or(0));
                sys_exit(1);
            }
            core::ptr::read_volatile(guard_addr);
            let m = b"init: guard readable after mprotect\n";
            sys_write(1, m.as_ptr(), u32::try_from(m.len()).unwrap_or(0));
        }
        // #533 brk harness: grow the heap by two pages on a REAL process table
        // -- a cloned identity map whose heap window (mb 0x100) is a 1 MB
        // SECTION that map_page refuses to overlay, so brk growth failed on
        // every real boot while host tests (absent-entry fixture) stayed
        // green. sys_brk reports failure by returning the UNCHANGED break, so
        // the return-value checks catch that directly; the canary then proves
        // the new pages are genuinely PL0-writable (a missing or kernel-only
        // grant data-aborts here -> USERFAULT, which CI reds on). Finally
        // shrink back, proving the teardown half on the same table shape.
        #[cfg(thumos_init_brk)]
        {
            let initial = sys_brk(0);
            let grown = initial + 2 * 4096;
            if initial == 0 || sys_brk(grown) != grown {
                let m = b"init: brk grow FAILED\n";
                sys_write(1, m.as_ptr(), u32::try_from(m.len()).unwrap_or(0));
                sys_exit(1);
            }
            let m = b"init: brk grown\n";
            sys_write(1, m.as_ptr(), u32::try_from(m.len()).unwrap_or(0));
            // The heap VA as a pointer, converted once (brk returned != 0).
            // .add(1024) steps one u32 page (1024 * 4 = 4096 bytes). Both
            // pages [initial, grown) were just mapped user-RW by the
            // successful grow above; a broken grant faults here (by design).
            let heap = usize::try_from(initial).unwrap_or(0) as *mut u32;
            core::ptr::write_volatile(heap, 0xCAFE_0001);
            core::ptr::write_volatile(heap.add(1024), 0xCAFE_0002);
            let ok = core::ptr::read_volatile(heap) == 0xCAFE_0001
                && core::ptr::read_volatile(heap.add(1024)) == 0xCAFE_0002;
            if !ok {
                let m = b"init: brk canary BROKEN\n";
                sys_write(1, m.as_ptr(), u32::try_from(m.len()).unwrap_or(0));
                sys_exit(1);
            }
            let m = b"init: brk canary ok\n";
            sys_write(1, m.as_ptr(), u32::try_from(m.len()).unwrap_or(0));
            if sys_brk(initial) != initial {
                let m = b"init: brk shrink FAILED\n";
                sys_write(1, m.as_ptr(), u32::try_from(m.len()).unwrap_or(0));
                sys_exit(1);
            }
            let m = b"init: brk shrunk\n";
            sys_write(1, m.as_ptr(), u32::try_from(m.len()).unwrap_or(0));
        }
        // #446 signal harness: install handlers for SIGUSR1 (10) and SIGUSR2
        // (12), raise BOTH against self, then yield so the kernel delivers
        // them. next_pending takes the lowest signum, so USR1 delivers first:
        // its handler marker proves the IRQ-frame rewrite + trampoline entry,
        // and control returning HERE after it proves sigreturn restored the
        // interrupted context. USR2's marker then proves its pending bit
        // survived USR1's delivery -- the exact-clear contract (the old
        // clear-any-pending could wipe the wrong bit). "flows complete"
        // prints only if both sigreturns returned control to this flow.
        #[cfg(thumos_init_signal)]
        {
            let pid = sys_getpid();
            // SAFETY: both handlers are PL0-executable functions in this
            // image; the pointer-to-usize cast takes their PL0 VA (no
            // TryFrom exists for a pointer, so `as` is the only route).
            // WARNING: usize == u32 on armv7a so the narrowing below is
            // provably lossless, but that is a target fact, not one the
            // type system checks. Fail closed to SIG_DFL (0) rather than
            // trust an `as` truncation to silently wrap into a bogus VA:
            // sys_sigaction never validates a nonzero handler address, so a
            // wrapped pointer would be stored and only fault on delivery,
            // whereas SIG_DFL takes the signal's default action -- observable
            // here as "flows complete" never printing, instead of a jump to
            // unrelated PL0 code.
            let h1 = u32::try_from(usr1_handler as usize).unwrap_or(0);
            let h2 = u32::try_from(usr2_handler as usize).unwrap_or(0);
            if sys_sigaction(10, h1) != 0 || sys_sigaction(12, h2) != 0 {
                let m = b"signal: sigaction FAILED\n";
                sys_write(1, m.as_ptr(), u32::try_from(m.len()).unwrap_or(0));
                sys_exit(1);
            }
            if sys_kill(pid, 12) != 0 || sys_kill(pid, 10) != 0 {
                let m = b"signal: kill FAILED\n";
                sys_write(1, m.as_ptr(), u32::try_from(m.len()).unwrap_or(0));
                sys_exit(1);
            }
            // Two yields: the first gives the kernel an exception return on
            // which to deliver USR1; the second a return for USR2 (still
            // pending iff the delivery clear was exact).
            sys_sleep(30);
            sys_sleep(30);
            let m = b"signal: flows complete\n";
            sys_write(1, m.as_ptr(), u32::try_from(m.len()).unwrap_or(0));
            // W^X probe: the sigreturn trampoline page (SIGNAL_TRAMPOLINE_VA
            // = USER_TEXT_BASE - 4096 = 0x7FEF_F000, mirrored from
            // signal.rs) is PL0 read+EXECUTE — a PL0 WRITE to it must die to
            // a data-abort PERMISSION fault (DFSR 0x0f: mapped, write
            // denied; a 0x07 translation fault would prove the page is not
            // where signal.rs claims). The child forks, writes it, and must
            // be fault-killed; the parent reaps and confirms. A writable
            // trampoline would let userspace rewrite its own sigreturn path.
            let probe = sys_fork();
            if probe == 0 {
                // CHILD: the write below must never complete.
                let tramp = 0x7FEF_F000usize as *mut u32;
                core::ptr::write_volatile(tramp, 0xDEAD_BEEF);
                let m = b"signal: trampoline WRITEABLE (W^X broken)\n";
                sys_write(1, m.as_ptr(), u32::try_from(m.len()).unwrap_or(0));
                sys_exit(3);
            }
            if probe == u32::MAX {
                let m = b"signal: rx-probe fork FAILED\n";
                sys_write(1, m.as_ptr(), u32::try_from(m.len()).unwrap_or(0));
                sys_exit(1);
            }
            let status = loop {
                let s = sys_waitpid(probe);
                if s != u32::MAX {
                    break s;
                }
                sys_sleep(10);
            };
            // Fault-killed children report 139 (the guard harness's contract).
            let m: &[u8] = if status == 139 {
                b"signal: trampoline rx enforced\n"
            } else {
                b"signal: trampoline rx probe WRONG status\n"
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
