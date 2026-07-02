//! Thumos kernel
//!
//! Bare-metal Rust kernel for the MT6739. ARM boot stub is inline
//! assembly that sets up the stack and zeros BSS before jumping to
//! kernel_main.

#![no_std]
#![cfg_attr(not(test), no_main)]
extern crate alloc;

use core::fmt::Write;
use core::panic::PanicInfo;

mod audit;
mod audio;
mod audio_codec;
mod audio_route;
mod battery;
mod bfu_timer;
mod block;
mod bluetooth;
mod briar;
mod bt_audio;
mod avdtp;
mod cache;
mod ccci;
mod ccci_logger;
mod capability;
mod clock;
mod contacts;
mod lfs;
mod lfs_checkpoint;
mod lfs_compact;
mod lfs_imap;
mod lfs_segment;
mod lfs_writer;
#[cfg(not(test))]
mod console;
mod csprng;
mod devfs;
mod dhcp;
mod dns;
mod dns_tls;
#[cfg(not(test))]
mod device;
mod ekphrasis;
mod display;
mod elf;
#[cfg(not(test))]
mod emmc;
mod encryption;
#[cfg(not(test))]
mod exceptions;
// WHY(host-test): process.rs calls exceptions::ticks() (the timer-IRQ tick
// counter). The real exceptions module is ARM-only (CP15 vector table, GIC).
// Under test a stub supplies the tick source so process is host-testable
// without dragging in gic/timer/uart/watchdog. Production is unaffected.
#[cfg(test)]
#[path = "exceptions_stub.rs"]
mod exceptions;
mod fd;
mod firewall;
mod fm_radio;
mod futex;
mod gps;
mod gsm7;
mod harmostes;
mod heorte;
mod matrix_ids;
// WHY: not test-gated because matrix_crypto types will be used by harmostes
// at runtime for E2E message encryption/decryption.
mod matrix_crypto;
mod meshtastic;
mod heorte_alarm;
mod heorte_timer;
mod http_client;
#[cfg(not(test))]
mod gic;
#[cfg(not(test))]
mod heap;
mod json_mini;
mod ipc;
mod irq;
mod kconfig;
mod key_manager;
mod lock_screen;
#[cfg(not(test))]
mod kinit;
mod memguard;
mod mic_audit;
mod mmio;
mod mmu;
mod net;
mod nous;
mod page;
mod panic_wipe;
mod pipe;
mod power;
mod process;
mod provision;
mod ramfs;
mod screen_alarm;
mod screen_calendar;
mod screen_call;
mod screen_contacts;
mod screen_dialer;
mod screen_fm;
mod screen_home;
mod screen_messages;
mod screen_nous;
mod screen_privacy;
mod screen_radio;
mod screen_search;
mod screen_settings;
mod screen_threat;
mod secure_boot;
mod security;
mod security_mode;
mod signal;
mod sim;
mod slab;
mod sbc;
mod sms;
mod socket;
mod status_bar;
mod t9;
mod telephony;
#[cfg(test)]
mod telephony_mock;
mod telephony_parser;
mod syscall;
mod time;
#[cfg(not(test))]
mod timer;
// WHY(host-test): time::sys_clock_gettime reads the ARM generic timer (CP15
// CNTPCT/CNTFRQ), which is ARM-only. Under test a stub returns fixed sane
// values so time is host-testable without dragging in CP15 asm. Production
// is unaffected.
#[cfg(test)]
#[path = "timer_stub.rs"]
mod timer;
mod ui;
#[cfg(not(test))]
mod uart;
// WHY(host-test): syscall's stdout (fd 1) and unknown-syscall debug paths
// write to the MT6739 UART (ttyMT0 MMIO), which is ARM-only. Under test a
// stub swallows output so syscall is host-testable. Production is unaffected.
#[cfg(test)]
#[path = "uart_stub.rs"]
mod uart;
mod usb;
mod vfs;
#[cfg(not(test))]
mod watchdog;
mod wifi;

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
