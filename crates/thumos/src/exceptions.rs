//! ARM exception vector table and interrupt handler.
//!
//! The ARM Cortex-A53 has 7 exception vectors at fixed offsets.
//! We place the vector table at a known address and install handlers
//! for IRQ (FROM GIC) and data/prefetch abort (for debugging).
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

use crate::csprng;
use crate::gic;
use crate::power;
use crate::process;
use crate::timer;
use crate::uart::Uart;
use crate::watchdog;

/// Tick counter incremented by the timer IRQ handler.
static mut TICK_COUNT: u64 = 0;

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
            in(reg) (vector_table as usize),
        );

        // Enable IRQs (clear I bit in CPSR)
        core::arch::asm!("cpsie i");

        // Enable the timer IRQ in the GIC
        gic::enable_irq(timer::TIMER_IRQ);

        // Set the first timer tick
        timer::set_ms(TICK_MS);
    }
}

/// Get the current tick count.
pub(crate) fn ticks() -> u64 {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(TICK_COUNT)) }
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
    // IRQ handler wrapper: save context, call Rust, restore
    "irq_handler_asm:",
    "    sub     lr, lr, #4",       // Adjust return address
    "    push    {{r0-r12, lr}}",   // Save registers
    "    bl      irq_handler_rust", // Call Rust handler
    "    pop     {{r0-r12, lr}}",   // Restore registers
    "    movs    pc, lr",           // Return FROM IRQ (restores CPSR)
    // Abort handlers: print info and hang
    "data_abort_handler_asm:",
    "    push    {{r0-r12, lr}}",
    "    bl      data_abort_handler_rust",
    "    pop     {{r0-r12, lr}}",
    "    b       .",
    "prefetch_abort_handler_asm:",
    "    push    {{r0-r12, lr}}",
    "    bl      prefetch_abort_handler_rust",
    "    pop     {{r0-r12, lr}}",
    "    b       .",
    "undefined_handler_asm:",
    "    push    {{r0-r12, lr}}",
    "    bl      undefined_handler_rust",
    "    pop     {{r0-r12, lr}}",
    "    b       .",
    "svc_handler_asm:",
    "    push    {{r0-r12, lr}}",
    "    bl      svc_handler_rust",
    "    pop     {{r0-r12, lr}}",
    "    movs    pc, lr",
);

unsafe extern "C" {
    fn vector_table();
}

/// IRQ handler called FROM assembly wrapper.
#[unsafe(no_mangle)]
pub extern "C" fn irq_handler_rust() {
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
        // SAFETY: TICK_COUNT is only written from this IRQ handler, which
        // is non-reentrant on a single-core ARMv7. The IRQ is disabled
        // during handler execution so there is no concurrent write.
        unsafe {
            TICK_COUNT += 1;
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

        // Run scheduler
        let next = process::schedule();
        if next != process::current_pid() {
            // SAFETY: next is a valid PID returned by schedule(), which only
            // returns PIDs for processes in the READY state.
            unsafe {
                process::switch_to(next);
            }
        } else {
            // REQ-19a: idle — no other runnable process, enter WFI.
            // WHY: wfi suspends the core until the next interrupt, reducing
            // power consumption in the idle path without affecting correctness.
            power::idle();
        }

        // Check for pending signals on the current process.
        // WHY: signals must be delivered before the next return to user mode.
        // The timer IRQ is the primary exception return point. Full signal
        // frame setup requires user-mode register state from the IRQ stack;
        // that is wired through the SVC path once userspace is active.
        let _ = process::check_pending_signal(); // WHY: signal delivery failure is non-actionable in IRQ context; will retry on next tick

    }
}

/// Data abort handler  -  print fault info and hang.
#[unsafe(no_mangle)]
pub extern "C" fn data_abort_handler_rust() {
    let mut serial = Uart::new();
    let dfar: u32;
    let dfsr: u32;
    // SAFETY: CP15 system register access is a privileged operation. DFAR (c6, c0, 0)
    // holds the faulting address and DFSR (c5, c0, 0) holds the fault status. Both
    // are read-only in this context and are valid after a data abort exception.
    unsafe {
        core::arch::asm!("mrc p15, 0, {}, c6, c0, 0", out(reg) dfar); // DFAR
        core::arch::asm!("mrc p15, 0, {}, c5, c0, 0", out(reg) dfsr); // DFSR
    }
    let _ = write!(serial, "\r\n!!! DATA ABORT !!!\r\n"); // WHY: best-effort serial write in exception handler; cannot recover from UART failure
    let _ = write!(serial, "DFAR: {dfar:#010x} (fault address)\r\n"); // WHY: best-effort serial write in exception handler; cannot recover from UART failure
    let _ = write!(serial, "DFSR: {dfsr:#010x} (fault status)\r\n"); // WHY: best-effort serial write in exception handler; cannot recover from UART failure
}

/// Prefetch abort handler.
#[unsafe(no_mangle)]
pub extern "C" fn prefetch_abort_handler_rust() {
    let mut serial = Uart::new();
    let ifar: u32;
    let ifsr: u32;
    // SAFETY: CP15 system register access is a privileged operation. IFAR (c6, c0, 2)
    // holds the faulting instruction address and IFSR (c5, c0, 1) holds the fault
    // status. Both are read-only in this context and are valid after a prefetch abort.
    unsafe {
        core::arch::asm!("mrc p15, 0, {}, c6, c0, 2", out(reg) ifar); // IFAR
        core::arch::asm!("mrc p15, 0, {}, c5, c0, 1", out(reg) ifsr); // IFSR
    }
    let _ = write!(serial, "\r\n!!! PREFETCH ABORT !!!\r\n"); // WHY: best-effort serial write in exception handler; cannot recover from UART failure
    let _ = write!(serial, "IFAR: {ifar:#010x}\r\n"); // WHY: best-effort serial write in exception handler; cannot recover from UART failure
    let _ = write!(serial, "IFSR: {ifsr:#010x}\r\n"); // WHY: best-effort serial write in exception handler; cannot recover from UART failure
}

/// Undefined instruction handler.
#[unsafe(no_mangle)]
pub extern "C" fn undefined_handler_rust() {
    let mut serial = Uart::new();
    let _ = serial
        .write_str("\r\n!!! UNDEFINED INSTRUCTION !!!\r\n");
}

/// SVC handler (placeholder for future syscall implementation).
#[unsafe(no_mangle)]
pub extern "C" fn svc_handler_rust() {
    // NOTE: in a full implementation, extract SVC number FROM the instruction
    // at the return address (lr - 4), and read r0-r3 FROM the saved context
    // on the stack. For now this is a placeholder that will be properly
    // wired when we have userspace processes making SVC calls.
}
