//! ARM exception vector table and interrupt handler.
//!
//! The ARMv7-A (Cortex-A7) has 7 exception vectors at fixed offsets. We place
//! the vector table at a known address and install handlers for IRQ (FROM GIC),
//! SVC (syscalls), and the abort/undef traps. Abort/undef traps from PL0 kill
//! the faulting process; from PL1 they halt the kernel (see `handle_fault`).
//!
//! Vector table layout (ARM ARM B1.8):
//! Offset 0x00: Reset
//! Offset 0x04: Undefined instruction
//! Offset 0x08: Supervisor call (SVC)
//! Offset 0x0C: Prefetch abort
//! Offset 0x10: Data abort
//! Offset 0x14: Not used (hypervisor)
//! Offset 0x18: IRQ
//! Offset 0x1C: FIQ

use core::fmt::Write;

#[cfg(not(feature = "qemu"))]
use crate::board;
use crate::csprng;
use crate::gic;
use crate::power;
use crate::process;
use crate::timer;
use crate::uart::Uart;
#[cfg(not(feature = "qemu"))]
use crate::usb;
use crate::watchdog;

/// Tick counter incremented by the timer IRQ handler, split into
/// high/low 32-bit halves.
///
/// WHY split: a bare `u64` read on 32-bit ARM lowers to two 32-bit loads,
/// which can tear if the timer IRQ increments (and carries into the high
/// half) between them -- `ticks()` could observe a spurious jump forward
/// or backward once per low-word wraparound (~497 days at 100 Hz).
/// Reading hi-lo-hi with a retry-on-mismatch (seqlock-lite, see
/// `ticks()`) makes the combined value tear-free without a real lock: the
/// sole writer (this IRQ handler) always runs with IRQs disabled and is
/// never reentrant on this single-core kernel, so a retry only ever needs
/// to catch a single writer/reader interleaving, never writer/writer
/// contention.
static mut TICK_COUNT_HI: u32 = 0;
static mut TICK_COUNT_LO: u32 = 0;

/// Timer tick interval in milliseconds.
const TICK_MS: u32 = 10;

/// Install the exception vector table and enable IRQs.
///
/// # Safety
///
/// Must be called after GIC init and MMU enable.
pub unsafe fn init() {
    // SAFETY: vector table address is aligned to 32 bytes (enforced by .balign 32 in
    // global_asm!) and contains valid exception handler entries. VBAR write is a
    // privileged CP15 operation. cpsie i enables IRQ delivery after the vector table
    // and GIC are fully configured.
    unsafe {
        core::arch::asm!(
            "mcr p15, 0, {}, c12, c0, 0", // VBAR
            in(reg) (vector_table as *const () as usize),
        );

        // Enable IRQs (clear I bit in CPSR)
        core::arch::asm!("cpsie i");

        // Enable the timer IRQ in the GIC
        gic::enable_irq(timer::TIMER_IRQ);

        // Set the first timer tick
        timer::set_ms(TICK_MS);

        // Enable the MUSB serial RX IRQ in the GIC (#666), alongside the
        // timer registration above -- same call site, same mechanism, no
        // second registration path. board::m7::MUSB_IRQ is `None` until
        // hardware-confirmed (see its doc comment), so this is a no-op on
        // every build today; flipping the board constant to `Some(n)` is
        // the entire remaining step. Safe to enable before
        // usb::init_controller() runs later in kinit: a MUSB interrupt
        // reaching the CPU here can only come from a genuine bus event
        // (SOFTCONN, set inside init(), is what attaches D+/D- to the bus
        // in the first place) or a stale latched condition surviving the
        // bootloader handoff -- either way, usb::handle_musb_interrupt's
        // own not-yet-ready gate turns a pre-init fire into a controlled
        // no-op rather than dispatching into a partially-initialized
        // controller.
        #[cfg(not(feature = "qemu"))]
        if let Some(musb_irq) = board::MUSB_IRQ {
            gic::enable_irq(musb_irq);
        }
    }
}

/// Get the current tick count.
///
/// Reads the hi/lo split with a seqlock-lite retry: `hi` is read before
/// and after `lo`. If the timer IRQ carried into `hi` while `lo` was
/// being read (a torn read), `hi1 != hi2` and the read is retried. See
/// `TICK_COUNT_HI`/`TICK_COUNT_LO` and `combine_tick_halves` in
/// `exceptions_stub.rs` for the host-tested version of this logic.
pub(crate) fn ticks() -> u64 {
    loop {
        // SAFETY: TICK_COUNT_HI/LO are written only from the timer IRQ
        // handler with IRQs disabled (single-core, non-reentrant); this
        // hi-lo-hi retry loop is the reader side of that seqlock-lite.
        let hi1 = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(TICK_COUNT_HI)) };
        let lo = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(TICK_COUNT_LO)) };
        let hi2 = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(TICK_COUNT_HI)) };
        if hi1 == hi2 {
            return (u64::from(hi1) << 32) | u64::from(lo);
        }
    }
}

/// Get uptime in milliseconds FROM tick count.
pub(crate) fn uptime_ms() -> u64 {
    ticks() * u64::from(TICK_MS)
}

// ARM vector table  -  must be 32-byte aligned
core::arch::global_asm!(
    ".section .text",
    ".balign 32",
    ".global vector_table",
    "vector_table:",
    "    b   .", // Reset: shouldn't happen
    "    b   undefined_handler_asm",
    "    b   svc_handler_asm",
    "    b   prefetch_abort_handler_asm",
    "    b   data_abort_handler_asm",
    "    b   .", // Not used
    "    b   irq_handler_asm",
    "    b   .", // FIQ: not used
    // IRQ handler wrapper (#465): build a full process::Context trap frame on
    // the IRQ stack (r0-r12 @0..48, banked sp @52, lr @56, pc @60, cpsr @64),
    // hand its pointer to the Rust handler (which may swap it to another
    // process via switch_to), then exception-return into the resulting frame.
    // INVARIANT: interrupted code is ALWAYS in the user/system bank (0x10/0x1F)
    // -- _start runs the kernel in SYS, spawn/exec never set another mode -- so
    // ldm/stm {r13,r14}^ names the interrupted sp/lr unconditionally.
    "irq_handler_asm:",
    "    sub     lr, lr, #4",     // resume pc = interrupted instruction
    "    sub     sp, sp, #68",    // Context frame
    "    stmia   sp, {{r0-r12}}", // r[0..=12] @ 0..48
    "    str     lr, [sp, #60]",  // pc
    "    mrs     r0, spsr",
    "    str     r0, [sp, #64]", // cpsr (= SPSR at entry)
    "    add     r0, sp, #52",
    "    stmia   r0, {{r13, r14}}^", // banked user sp @52, lr @56
    "    nop",                       // ARM ldm/stm(user) hazard barrier
    "    mov     r0, sp",            // frame ptr -> handler
    "    bl      irq_handler_rust",
    "    add     r0, sp, #52",
    "    ldmia   r0, {{r13, r14}}^", // next process's banked sp/lr
    "    nop",                       // hazard barrier (next reads sp)
    "    ldr     r0, [sp, #64]",
    "    msr     spsr_cxsf, r0", // full SPSR: flags + mode + masks
    "    ldr     lr, [sp, #60]", // pc -> lr
    "    ldmia   sp, {{r0-r12}}",
    "    add     sp, sp, #68",
    "    movs    pc, lr", // exception return: CPSR := SPSR
    // Abort/undef wrappers (graceful user-fault kill): same full-frame contract
    // as IRQ/SVC (#465). Build a process::Context on the banked ABT/UND stack,
    // pass it to the Rust handler, which either KILLS a PL0 faulter (frame
    // swapped to the successor via process::switch_to; this epilogue
    // exception-returns into it) or HALTS on a PL1 fault (the handler diverges;
    // this epilogue is never reached). Saved pc = the FAULTING instruction (ARM
    // ARM B1.8.3 Table B1-7 link offsets: data abort lr-8, prefetch abort lr-4,
    // undef lr-4 ARM / lr-2 Thumb); pc is diagnostic-only on both paths -- a
    // fault frame is never resumed.
    // INVARIANT: this epilogue's `ldm {r13,r14}^` user-bank restore is correct
    // ONLY because it is reached solely on the kill path, where the frame holds
    // a scheduled process's context (mode 0x10 or 0x1F -- both use the user
    // bank). A PL1 fault (including one from SVC/IRQ/ABT/UND mode, whose banked
    // sp/lr this frame does NOT capture) halts in Rust and never returns here.
    "data_abort_handler_asm:",
    "    sub     lr, lr, #8", // pc = faulting instruction (DA: lr = pc+8)
    "    sub     sp, sp, #68",
    "    stmia   sp, {{r0-r12}}",
    "    str     lr, [sp, #60]", // pc
    "    mrs     r0, spsr",
    "    str     r0, [sp, #64]", // cpsr (= SPSR: the faulter's mode)
    "    add     r0, sp, #52",
    "    stmia   r0, {{r13, r14}}^", // banked user sp @52, lr @56
    "    nop",                       // ldm/stm(user) hazard barrier
    "    mov     r0, sp",            // frame ptr -> handler
    "    bl      data_abort_handler_rust",
    "    add     r0, sp, #52", // kill path only: frame = successor
    "    ldmia   r0, {{r13, r14}}^",
    "    nop", // hazard barrier
    "    ldr     r0, [sp, #64]",
    "    msr     spsr_cxsf, r0",
    "    ldr     lr, [sp, #60]",
    "    ldmia   sp, {{r0-r12}}",
    "    add     sp, sp, #68",
    "    movs    pc, lr", // exception return: CPSR := SPSR
    "prefetch_abort_handler_asm:",
    "    sub     lr, lr, #4", // pc = faulting instruction (PA: lr = pc+4)
    "    sub     sp, sp, #68",
    "    stmia   sp, {{r0-r12}}",
    "    str     lr, [sp, #60]",
    "    mrs     r0, spsr",
    "    str     r0, [sp, #64]",
    "    add     r0, sp, #52",
    "    stmia   r0, {{r13, r14}}^",
    "    nop",
    "    mov     r0, sp",
    "    bl      prefetch_abort_handler_rust",
    "    add     r0, sp, #52",
    "    ldmia   r0, {{r13, r14}}^",
    "    nop",
    "    ldr     r0, [sp, #64]",
    "    msr     spsr_cxsf, r0",
    "    ldr     lr, [sp, #60]",
    "    ldmia   sp, {{r0-r12}}",
    "    add     sp, sp, #68",
    "    movs    pc, lr",
    "undefined_handler_asm:",
    // UNDEF's link offset is STATE-dependent (ARM pc+4, Thumb pc+2), so adjust
    // pc using SPSR.T after saving the registers (r0 is already captured).
    "    sub     sp, sp, #68",
    "    stmia   sp, {{r0-r12}}",
    "    mrs     r0, spsr",
    "    str     r0, [sp, #64]", // cpsr
    "    tst     r0, #0x20",     // SPSR.T (Thumb)?
    "    subeq   lr, lr, #4",    // ARM:   pc = lr - 4
    "    subne   lr, lr, #2",    // Thumb: pc = lr - 2
    "    str     lr, [sp, #60]", // pc = faulting instruction
    "    add     r0, sp, #52",
    "    stmia   r0, {{r13, r14}}^",
    "    nop",
    "    mov     r0, sp",
    "    bl      undefined_handler_rust",
    "    add     r0, sp, #52",
    "    ldmia   r0, {{r13, r14}}^",
    "    nop",
    "    ldr     r0, [sp, #64]",
    "    msr     spsr_cxsf, r0",
    "    ldr     lr, [sp, #60]",
    "    ldmia   sp, {{r0-r12}}",
    "    add     sp, sp, #68",
    "    movs    pc, lr",
    // SVC (syscall) wrapper (#465/#474): identical full-frame handling to IRQ,
    // EXCEPT no `sub lr, #4` -- SVC lr already points at the instruction after
    // `svc`. The frame lets a syscall that switches away (Yield/Exit/futex)
    // resume its caller later exactly where it left off.
    "svc_handler_asm:",
    "    sub     sp, sp, #68", // Context frame on the SVC stack
    "    stmia   sp, {{r0-r12}}",
    "    str     lr, [sp, #60]", // pc = instruction after svc
    "    mrs     r0, spsr",
    "    str     r0, [sp, #64]",
    "    add     r0, sp, #52",
    "    stmia   r0, {{r13, r14}}^", // banked user sp/lr
    "    nop",                       // hazard barrier
    "    mov     r0, sp",            // frame ptr -> handler
    "    bl      svc_handler_rust",
    "    add     r0, sp, #52",
    "    ldmia   r0, {{r13, r14}}^",
    "    nop", // hazard barrier
    "    ldr     r0, [sp, #64]",
    "    msr     spsr_cxsf, r0",
    "    ldr     lr, [sp, #60]",
    "    ldmia   sp, {{r0-r12}}",
    "    add     sp, sp, #68",
    "    movs    pc, lr", // exception return: CPSR := SPSR
);

unsafe extern "C" {
    fn vector_table();
}

/// IRQ handler called FROM the assembly wrapper with the interrupted process's
/// trap frame (#465). A timer tick may `switch_to` another process, which swaps
/// `*frame` in place; the stub epilogue then exception-returns into it.
#[unsafe(no_mangle)]
pub extern "C" fn irq_handler_rust(frame: *mut process::Context) {
    // SAFETY: `frame` is the Context the stub built on the IRQ stack -- valid
    // and unaliased for this call (traps never nest: entry masks I, and no
    // handler re-enables it).
    unsafe { process::trap_enter(frame) };
    irq_handler_body();
    // #446: real signal delivery, consumed at the exception return — if the
    // current process has a handled signal pending, build its user frame and
    // rewrite the trap frame to enter the handler (the pending bit is
    // cleared at dispatch inside deliver()).
    if let Some((sig, handler)) = process::check_pending_signal() {
        // SAFETY: frame is the current process's trap Context on the IRQ
        // stack; its sp/pc/lr are the interrupted user state.
        unsafe { crate::signal::deliver(&mut *frame, sig, handler) };
    }
    process::trap_leave();
}

fn irq_handler_body() {
    let irq = gic::acknowledge();

    if irq == gic::SPURIOUS {
        return;
    }

    // WHY: EOI must be written in the CURRENT execution context, before any
    // interrupt-specific work below that can abandon this context via
    // process::switch_to(). GICv2 requires GICC_EOIR to deactivate the
    // interrupt; skipping it after a scheduler switch leaves the interrupt
    // permanently active and blocks all further IRQ delivery at every
    // priority (GICC_PMR = 0xFF) (#341).
    gic::end_of_interrupt(irq);

    if irq == timer::TIMER_IRQ {
        // Timer tick
        // SAFETY: TICK_COUNT_HI/LO are only written from this IRQ
        // handler, which is non-reentrant on a single-core ARMv7. The IRQ
        // is disabled during handler execution so there is no concurrent
        // write. LO is written before HI so a reader's hi-lo-hi retry (see
        // ticks()) never observes a new HI paired with a stale pre-carry
        // LO.
        unsafe {
            let lo = core::ptr::read_volatile(core::ptr::addr_of!(TICK_COUNT_LO));
            let (new_lo, carried) = lo.overflowing_add(1);
            core::ptr::write_volatile(core::ptr::addr_of_mut!(TICK_COUNT_LO), new_lo);
            if carried {
                let hi = core::ptr::read_volatile(core::ptr::addr_of!(TICK_COUNT_HI));
                core::ptr::write_volatile(
                    core::ptr::addr_of_mut!(TICK_COUNT_HI),
                    hi.wrapping_add(1),
                );
            }
        }

        // Collect entropy from timer counter LSBs for the CSPRNG.
        // SAFETY: collect_timer_entropy() only accesses ENTROPY which is
        // written exclusively from this IRQ handler. Non-reentrant on single-
        // core ARMv7 with IRQs masked during handler execution.
        unsafe {
            csprng::collect_timer_entropy();
        }

        // Pet the watchdog to prevent hardware reset.
        // SAFETY: watchdog::pet() writes to WDT_RESTART MMIO. Called from
        // the timer IRQ handler at 100 Hz, well within the 5-second WDT
        // timeout. Safe after watchdog::init() has been called in kinit.
        unsafe {
            watchdog::pet();
        }

        // Reset timer for next tick
        timer::set_ms(TICK_MS);

        // REQ-19b: DVFS — estimate load as a simple binary sample.
        // WHY: a single-tick sample (running vs idle) is the coarsest
        // estimate available without per-process accounting.  The rolling
        // average inside evaluate_dvfs smooths over LOAD_HISTORY_LEN ticks.
        let runnable = process::runnable_count();
        // 100 if any non-idle work exists, 0 if only the idle process runs.
        let load_sample: u8 = if runnable > 1 { 100 } else { 0 };
        power::evaluate_dvfs(load_sample);

        // REQ-19c: core parking.
        power::evaluate_core_parking(runnable);

        // REQ-19d: display backlight timeout.
        let now = ticks();
        power::check_backlight_timeout(now);

        // Run scheduler -- only once boot has enabled scheduling. WHY: during
        // kinit the boot runs in the bare boot context (not a scheduled
        // process), so a context switch here would abandon the boot
        // mid-init; process::enable_scheduling() is called once at the end of
        // kinit, after userspace spawn.
        if process::scheduling_enabled() {
            let next = process::schedule();
            if next != process::current_pid() {
                // SAFETY: next is a valid PID returned by schedule(), which only
                // returns PIDs for processes in the READY state.
                unsafe {
                    process::switch_to(next);
                }
            }
            // WHY (REQ-19a, #420): the idle WFI moved to the PID-0 service
            // loop (kardia.rs). A WFI here ran INSIDE the IRQ handler,
            // stalling return-from-IRQ until the NEXT interrupt pended; the
            // interrupted context (the service loop) is the correct idle
            // point and issues power::idle() itself when no tick work
            // remains.
        }

        // NOTE: signal delivery is consumed by irq_handler_rust at the
        // exception return (#446), not here — the old discard-only peek is
        // gone. The delivery happens on every timer IRQ once the body has
        // done its scheduler work, so a handled signal lands in user context
        // at the next return.
    }

    // #666: MUSB serial RX. board::m7::MUSB_IRQ is `None` until
    // hardware-confirmed, so `Some(irq) == board::MUSB_IRQ` is always false
    // today and this branch never dispatches -- see MUSB_IRQ's doc comment
    // and exceptions::init()'s registration above.
    #[cfg(not(feature = "qemu"))]
    if Some(irq) == board::MUSB_IRQ {
        usb::handle_musb_interrupt();
    }
}

/// Data abort trap: a PL0 fault kills the process, a PL1 fault halts. See
/// [`handle_fault`].
#[unsafe(no_mangle)]
pub(crate) extern "C" fn data_abort_handler_rust(frame: *mut process::Context) {
    let dfar: u32;
    let fault_status: u32;
    // SAFETY: CP15 access is privileged. DFAR (c6, c0, 0) holds the faulting
    // address, DFSR (c5, c0, 0) the fault status; both valid after a data abort.
    unsafe {
        core::arch::asm!("mrc p15, 0, {}, c6, c0, 0", out(reg) dfar); // DFAR
        core::arch::asm!("mrc p15, 0, {}, c5, c0, 0", out(reg) fault_status); // DFSR
    }
    handle_fault(
        frame,
        process::FaultKind::DataAbort {
            fault_addr: dfar,
            fault_status,
        },
        2,
    );
}

/// Prefetch abort trap: a PL0 fault kills the process, a PL1 fault halts.
#[unsafe(no_mangle)]
pub(crate) extern "C" fn prefetch_abort_handler_rust(frame: *mut process::Context) {
    let ifar: u32;
    let fault_status: u32;
    // SAFETY: CP15 access is privileged. IFAR (c6, c0, 2) holds the faulting
    // fetch address, IFSR (c5, c0, 1) the status; both valid after a prefetch abort.
    unsafe {
        core::arch::asm!("mrc p15, 0, {}, c6, c0, 2", out(reg) ifar); // IFAR
        core::arch::asm!("mrc p15, 0, {}, c5, c0, 1", out(reg) fault_status); // IFSR
    }
    handle_fault(
        frame,
        process::FaultKind::PrefetchAbort {
            fault_addr: ifar,
            fault_status,
        },
        3,
    );
}

/// Undefined-instruction trap: a PL0 fault kills the process, a PL1 fault halts.
#[unsafe(no_mangle)]
pub(crate) extern "C" fn undefined_handler_rust(frame: *mut process::Context) {
    handle_fault(frame, process::FaultKind::UndefinedInstruction, 4);
}

/// Shared fault-trap body for the abort/undef handlers.
///
/// Disposition comes from the SAVED CPSR mode in the trap frame
/// (`process::fault_disposition`, host-tested):
/// - PL0 (User): print the `USERFAULT` kill marker, kill via
///   `process::fault_exit_current` (Dead + PID-0 IPC + teardown + frame swap to
///   the successor) and RETURN -- the stub epilogue exception-returns into the
///   successor. The kernel and every other process continue.
/// - PL1 (everything else): a kernel bug. Print the fault state and halt: qemu
///   exits with the per-kind CI code; hardware parks with IRQs masked so the
///   un-petted watchdog resets. NEVER returns -- continuing past a kernel fault
///   would mask corruption of unknown extent.
fn handle_fault(frame: *mut process::Context, kind: process::FaultKind, qemu_exit_code: u32) {
    // SAFETY: `frame` is the Context the stub built on the ABT/UND stack, valid
    // and unaliased for this call. ACTIVE_FRAME holds one frame at a time: an
    // IRQ cannot preempt this handler (entry masks CPSR.I). A SYNCHRONOUS
    // re-fault from within this handler's own code IS architecturally possible
    // (aborts/undef are not I-gated) -- but it is made safe, not by
    // non-nesting, but because such a re-fault's saved mode is a privileged
    // mode (ABT/UND/SVC/...), never User 0x10, so fault_disposition routes it to
    // KernelHalt, which parks without resuming or recursing further -- bounding
    // the depth at one level.
    unsafe { process::trap_enter(frame) };
    // SAFETY: same frame liveness; copy the saved state for reporting.
    let saved = unsafe { *frame };
    let mut serial = Uart::new();
    match process::fault_disposition(saved.cpsr) {
        process::FaultDisposition::KillUser => {
            let pid = process::current_pid();
            // WHY: machine-parseable kill marker -- the CI isolation matrix
            // asserts `USERFAULT: pid=N kind=<kind>` per probe. Best-effort
            // serial write; cannot recover from UART failure.
            let _ = match kind {
                process::FaultKind::DataAbort {
                    fault_addr,
                    fault_status,
                } => write!(
                    serial,
                    "USERFAULT: pid={pid} kind=data-abort addr={fault_addr:#010x} status={fault_status:#010x} killed\r\n"
                ),
                process::FaultKind::PrefetchAbort {
                    fault_addr,
                    fault_status,
                } => write!(
                    serial,
                    "USERFAULT: pid={pid} kind=prefetch-abort addr={fault_addr:#010x} status={fault_status:#010x} killed\r\n"
                ),
                process::FaultKind::UndefinedInstruction => write!(
                    serial,
                    "USERFAULT: pid={pid} kind=undefined-instruction pc={:#010x} killed\r\n",
                    saved.pc
                ),
            };
            process::fault_exit_current(kind);
            process::trap_leave();
            // Returning re-enters the stub epilogue, which exception-returns
            // into the successor's frame.
        }
        process::FaultDisposition::KernelHalt => {
            let name = match kind {
                process::FaultKind::DataAbort { .. } => "DATA ABORT",
                process::FaultKind::PrefetchAbort { .. } => "PREFETCH ABORT",
                process::FaultKind::UndefinedInstruction => "UNDEFINED INSTRUCTION",
            };
            let _ = write!(serial, "\r\n!!! KERNEL {name} !!!\r\n"); // WHY: best-effort serial write in exception handler
            let _ = write!(
                serial,
                "PC:   {:#010x} (faulting instruction)\r\n",
                saved.pc
            ); // WHY: best-effort serial write
            let _ = write!(serial, "CPSR: {:#010x} (faulting mode)\r\n", saved.cpsr); // WHY: best-effort serial write
            match kind {
                process::FaultKind::DataAbort {
                    fault_addr,
                    fault_status,
                } => {
                    let _ = write!(serial, "DFAR: {fault_addr:#010x} (fault address)\r\n"); // WHY: best-effort serial write
                    let _ = write!(serial, "DFSR: {fault_status:#010x} (fault status)\r\n"); // WHY: best-effort serial write
                }
                process::FaultKind::PrefetchAbort {
                    fault_addr,
                    fault_status,
                } => {
                    let _ = write!(serial, "IFAR: {fault_addr:#010x}\r\n"); // WHY: best-effort serial write
                    let _ = write!(serial, "IFSR: {fault_status:#010x}\r\n"); // WHY: best-effort serial write
                }
                process::FaultKind::UndefinedInstruction => {}
            }
            // WHY(qemu): distinct exit codes let CI tell a KERNEL data abort (2)
            // / prefetch abort (3) / undef (4) from a panic (1) or hang.
            #[cfg(feature = "qemu")]
            crate::qemu::request_exit(qemu_exit_code);
            #[cfg(not(feature = "qemu"))]
            let _ = qemu_exit_code;
            // INVARIANT: never continue past a PL1 fault. Park with IRQs masked
            // (exception entry set CPSR.I); the timer IRQ can no longer pet the
            // watchdog, so hardware resets -- the same end-state as the previous
            // `b .` stubs.
            loop {
                core::hint::spin_loop();
            }
        }
    }
}

/// SVC (supervisor call) handler -- the userspace -> kernel syscall entry
/// (#474), now over the shared full trap frame (#465).
///
/// ABI (thumos, ARM-EABI style): `r7` = syscall number, `r0`-`r3` = args,
/// return value in `r0`. `svc_handler_asm` built a `process::Context` frame and
/// passes its pointer here; the return value is written into the frame's saved
/// r0, which the stub epilogue restores. A syscall that switches away
/// (Yield/Exit/futex/sleep) swaps the frame to the successor via
/// `process::switch_to`; in that case the frame now holds the SUCCESSOR's
/// context, so writing the return value would clobber its live r0 -- the guard
/// on `trap_switched()` skips it (the switched-away caller's return value was
/// deposited pre-swap by `process::set_trap_return`).
#[unsafe(no_mangle)]
pub(crate) extern "C" fn svc_handler_rust(frame: *mut process::Context) {
    // SAFETY: `frame` is the Context svc_handler_asm built on the SVC stack;
    // valid and unaliased for this call (traps never nest).
    unsafe { process::trap_enter(frame) };
    let f = unsafe { &mut *frame };
    // #446: sigreturn is special-cased before the generic dispatch — the
    // frame restore needs THIS SVC trap frame (dispatch receives only arg
    // registers). The trampoline entered with user sp = the signal frame and
    // r0 = the handled signum; the pending bit was cleared at dispatch.
    if f.r[7] == crate::signal::SIGRETURN_NUM {
        // SAFETY: as above; the trampoline's user sp is the frame deliver()
        // built.
        unsafe { crate::signal::sigreturn_frame(&mut *frame) };
        process::trap_leave();
        return;
    }
    let ret = crate::syscall::dispatch(f.r[7], f.r[0], f.r[1], f.r[2], f.r[3]);
    if !process::trap_switched() {
        // SAFETY: no switch occurred, so `frame` still holds this caller's
        // context; depositing the return value is correct.
        unsafe { (*frame).r[0] = ret };
    }
    process::trap_leave();
}
