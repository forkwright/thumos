//! Kernel init — the first code that runs after kernel boot.
//!
//! Initializes all kernel subsystems in the correct order, then
//! loads and starts userspace daemons from the ramfs. This is the
//! bridge between the kernel and the thumos userspace.

extern crate alloc;

use crate::console::Console;
use crate::device::DeviceRegistry;
use crate::exceptions;
use crate::gic;
use crate::heap;
use crate::kconfig;
use crate::mmu;
use crate::page;
use crate::power::PowerManager;
use crate::process;
use crate::uart::Uart;
use core::fmt::Write;

/// Run the kernel initialization sequence.
///
/// This is called from `kernel_main` and performs all subsystem
/// initialization in dependency order.
///
/// # Safety
///
/// Must be called exactly once, from the boot processor, with
/// interrupts disabled.
pub unsafe fn run() -> ! {
    let mut serial = Uart::new();

    // Banner
    serial.write_str("\r\n").ok();
    serial
        .write_str("================================\r\n")
        .ok();
    serial.write_str("  THUMOS / pyknosis v0.1.0\r\n").ok();
    serial.write_str("  Sovereign OS for MT6739\r\n").ok();
    serial
        .write_str("================================\r\n")
        .ok();
    serial.write_str("\r\n").ok();

    // 1. MMU + caches
    serial.write_str("[init] MMU + caches\r\n").ok();
    unsafe {
        mmu::init_and_enable();
    }

    // 2. Page allocator
    serial.write_str("[init] Page allocator\r\n").ok();
    unsafe {
        page::init(kconfig::RAM_START, kconfig::RAM_END, kconfig::KERNEL_END);
    }
    write!(
        serial,
        "       {} pages free ({} MB)\r\n",
        page::free_count(),
        page::free_bytes() / 1024 / 1024
    )
    .ok();

    // 3. Kernel heap
    serial.write_str("[init] Kernel heap\r\n").ok();
    unsafe {
        heap::init();
    }
    let (used, total) = heap::stats();
    write!(serial, "       {} / {} bytes\r\n", used, total).ok();

    // 4. GIC
    serial.write_str("[init] GIC\r\n").ok();
    unsafe {
        gic::init();
    }

    // 5. Process subsystem
    serial.write_str("[init] Process subsystem\r\n").ok();
    unsafe {
        process::init();
    }

    // 6. Exception handlers + timer
    serial.write_str("[init] Exceptions + timer\r\n").ok();
    unsafe {
        exceptions::init();
    }
    write!(
        serial,
        "       Timer frequency: {} Hz\r\n",
        crate::timer::frequency()
    )
    .ok();

    // 7. Device registry
    serial.write_str("[init] Device registry\r\n").ok();
    let mut devices = DeviceRegistry::new();
    devices.register_mt6739_devices();
    write!(
        serial,
        "       {} devices registered\r\n",
        devices.list().len()
    )
    .ok();

    // 8. Power manager
    serial.write_str("[init] Power manager\r\n").ok();
    let _pm = PowerManager::new();
    serial
        .write_str("       All radios OFF (silent mode)\r\n")
        .ok();

    // Boot complete
    serial.write_str("\r\n").ok();
    write!(
        serial,
        "[init] Boot complete at {} ms\r\n",
        crate::timer::elapsed_ms()
    )
    .ok();
    serial.write_str("\r\n").ok();

    // Start debug console
    if unsafe { kconfig::DEBUG_CONSOLE } {
        serial.write_str("[init] Starting debug console\r\n").ok();
        serial
            .write_str("       Type 'help' for commands\r\n\r\n")
            .ok();
        let mut console = Console::new();
        console.prompt();

        // Main loop: handle console input + timer ticks
        loop {
            // NOTE: in a real implementation, UART RX would be interrupt-driven.
            // For now, we poll. This gets replaced when the UART driver has
            // proper RX interrupt support.
            unsafe {
                core::arch::asm!("wfe");
            }
        }
    } else {
        // No console — just idle
        loop {
            unsafe {
                core::arch::asm!("wfe");
            }
        }
    }
}
