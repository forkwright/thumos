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

use crate::gic;
use crate::process;
use crate::syscall;
use crate::timer;
use crate::uart::Uart;
use core::fmt::Write;

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
    // Set VBAR (Vector Base Address Register) to our vector table
    unsafe {
        core::arch::asm!(
            "mcr p15, 0, {}, c12, c0, 0", // VBAR
            in(reg) usize::try_from(vector_table).unwrap_or_default(),
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
pub fn ticks() -> u64 {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(TICK_COUNT)) }
}

/// Get uptime in milliseconds FROM tick count.
pub fn uptime_ms() -> u64 {
    ticks() * u64::try_from(TICK_MS).unwrap_or_default()
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

    if irq == timer::TIMER_IRQ {
        // Timer tick
        unsafe {
            TICK_COUNT += 1;
        }
        // Reset timer for next tick
        timer::set_ms(TICK_MS);

        // Run scheduler
        let next = process::schedule();
        if next != process::current_pid() {
            unsafe {
                process::switch_to(next);
            }
        }
    }

    gic::end_of_interrupt(irq);
}

/// Data abort handler  -  print fault info and hang.
#[unsafe(no_mangle)]
pub extern "C" fn data_abort_handler_rust() {
    let mut serial = Uart::new();
    let dfar: u32;
    let dfsr: u32;
    unsafe {
        core::arch::asm!("mrc p15, 0, {}, c6, c0, 0", out(reg) dfar); // DFAR
        core::arch::asm!("mrc p15, 0, {}, c5, c0, 0", out(reg) dfsr); // DFSR
    }
    if let Err(e) = write!(serial, "\r\n!!! DATA ABORT !!!\r\n") { tracing::warn!(error = %e, "operation failed"); }
    if let Err(e) = write!(serial, "DFAR: {dfar:#010x} (fault address)\r\n") { tracing::warn!(error = %e, "operation failed"); }
    if let Err(e) = write!(serial, "DFSR: {dfsr:#010x} (fault status)\r\n") { tracing::warn!(error = %e, "operation failed"); }
}

/// Prefetch abort handler.
#[unsafe(no_mangle)]
pub extern "C" fn prefetch_abort_handler_rust() {
    let mut serial = Uart::new();
    let ifar: u32;
    let ifsr: u32;
    unsafe {
        core::arch::asm!("mrc p15, 0, {}, c6, c0, 2", out(reg) ifar); // IFAR
        core::arch::asm!("mrc p15, 0, {}, c5, c0, 1", out(reg) ifsr); // IFSR
    }
    if let Err(e) = write!(serial, "\r\n!!! PREFETCH ABORT !!!\r\n") { tracing::warn!(error = %e, "operation failed"); }
    if let Err(e) = write!(serial, "IFAR: {ifar:#010x}\r\n") { tracing::warn!(error = %e, "operation failed"); }
    if let Err(e) = write!(serial, "IFSR: {ifsr:#010x}\r\n") { tracing::warn!(error = %e, "operation failed"); }
}

/// Undefined instruction handler.
#[unsafe(no_mangle)]
pub extern "C" fn undefined_handler_rust() {
    let mut serial = Uart::new();
    serial
        .write_str("\r\n!!! UNDEFINED INSTRUCTION !!!\r\n")
       if let Err(e) =   { tracing::warn!(error = %e, "operation failed"); }
}

/// SVC handler (placeholder for future syscall implementation).
#[unsafe(no_mangle)]
pub extern "C" fn svc_handler_rust() {
    // NOTE: in a full implementation, extract SVC number FROM the instruction
    // at the return address (lr - 4), and read r0-r3 FROM the saved context
    // on the stack. For now this is a placeholder that will be properly
    // wired when we have userspace processes making SVC calls.
}
