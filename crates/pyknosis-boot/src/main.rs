//! Thumos kernel: pyknosis
//!
//! Bare-metal Rust kernel for the MT6739. ARM boot stub is inline
//! assembly that sets up the stack and zeros BSS before jumping to
//! kernel_main.

#![no_std]
#![cfg_attr(not(test), no_main)]
extern crate alloc;

use core::fmt::Write;
use core::panic::PanicInfo;

mod ccci;
#[cfg(not(test))]
mod console;
#[cfg(not(test))]
mod device;
mod display;
#[cfg(not(test))]
mod elf;
#[cfg(not(test))]
mod emmc;
#[cfg(not(test))]
mod exceptions;
mod fd;
#[cfg(not(test))]
mod gic;
#[cfg(not(test))]
mod heap;
#[cfg(not(test))]
mod ipc;
#[cfg(not(test))]
mod kconfig;
#[cfg(not(test))]
mod kinit;
mod mmio;
#[cfg(not(test))]
mod mmu;
mod page;
mod power;
#[cfg(not(test))]
mod process;
mod ramfs;
#[cfg(not(test))]
mod syscall;
#[cfg(not(test))]
mod timer;
#[cfg(not(test))]
mod uart;
mod usb;

#[cfg(not(test))]
#[global_allocator]
static ALLOCATOR: heap::KernelAllocator = heap::KernelAllocator;

// ARM boot stub — this is the entry point from the bootloader
#[cfg(not(test))]
core::arch::global_asm!(
    ".section .text.boot, \"ax\"",
    ".global _start",
    ".arm",
    "_start:",
    "    cpsid   if",               // Disable interrupts
    "    ldr     sp, =__stack_top", // Set stack pointer
    "    ldr     r0, =__bss_start", // Zero BSS
    "    ldr     r1, =__bss_end",
    "    mov     r2, #0",
    "1:  cmp     r0, r1",
    "    strlt   r2, [r0], #4",
    "    blt     1b",
    "    bl      kernel_main", // Jump to Rust
    "2:  wfe",                 // Hang if kernel_main returns
    "    b       2b",
);

/// Kernel entry point. Called from boot stub after ARM initialization.
#[cfg(not(test))]
#[unsafe(no_mangle)]
pub extern "C" fn kernel_main() -> ! {
    // WHY: delegate everything to kinit::run() which handles the full
    // boot sequence with fault isolation and driver integration.
    // SAFETY: called exactly once from the boot stub (_start) on the boot
    // processor, after the stack is set and BSS is zeroed. Interrupts are
    // disabled at entry; kinit::run() enables them after GIC init.
    unsafe {
        kinit::run();
    }
}

/// Kernel panic handler.
///
/// Attempts display output (red screen) if the display pipeline was
/// initialized, then writes to UART serial, then halts.
#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    // Attempt visual panic indicator on display (if available).
    if kinit::DISPLAY_AVAILABLE.load(core::sync::atomic::Ordering::Acquire) {
        // SAFETY: DISPLAY_AVAILABLE is only set to true after display.init()
        // succeeds, guaranteeing FB_BASE is a valid, mapped framebuffer of at
        // least DISPLAY_WIDTH * DISPLAY_HEIGHT * 2 bytes (RGB565).
        unsafe {
            kinit::fill_framebuffer(
                kconfig::FB_BASE,
                kconfig::DISPLAY_WIDTH,
                kconfig::DISPLAY_HEIGHT,
                0xF800, // NOTE: RGB565 pure red
            );
        }
    }

    // Always write to UART serial (primary debug output).
    let mut serial = uart::Uart::new();
    serial.write_str("\r\n").ok();
    serial.write_str("!!! KERNEL PANIC !!!\r\n").ok();
    write!(serial, "{info}\r\n").ok();

    if kinit::DISPLAY_AVAILABLE.load(core::sync::atomic::Ordering::Relaxed) {
        serial.write_str("(display: red screen rendered)\r\n").ok();
    }

    loop {
        // SAFETY: WFE is a hint instruction available in all ARM privilege levels.
        // No memory is accessed; the CPU enters a low-power wait state until an event.
        unsafe {
            core::arch::asm!("wfe");
        }
    }
}
