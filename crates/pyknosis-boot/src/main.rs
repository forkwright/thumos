//! Thumos kernel: pyknosis
//!
//! Bare-metal Rust kernel for the MT6739. ARM boot stub is inline
//! assembly that sets up the stack and zeros BSS before jumping to
//! kernel_main.

#![no_std]
#![no_main]
extern crate alloc;

use core::fmt::Write;
use core::panic::PanicInfo;

mod console;
mod device;
mod elf;
mod exceptions;
mod gic;
mod heap;
mod ipc;
mod mmio;
mod mmu;
mod page;
mod power;
mod process;
mod ramfs;
mod syscall;
mod timer;
mod uart;

#[global_allocator]
static ALLOCATOR: heap::KernelAllocator = heap::KernelAllocator;

// ARM boot stub — this is the entry point from the bootloader
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
#[unsafe(no_mangle)]
pub extern "C" fn kernel_main() -> ! {
    let mut serial = uart::Uart::new();

    serial.write_str("\r\n").ok();
    serial.write_str("=============================\r\n").ok();
    serial.write_str("  THUMOS / pyknosis v0.1.0\r\n").ok();
    serial.write_str("=============================\r\n").ok();
    serial.write_str("\r\n").ok();

    serial.write_str("Rust kernel running on MT6739\r\n").ok();

    // Enable MMU with identity mapping
    serial.write_str("Enabling MMU...\r\n").ok();
    unsafe {
        mmu::init_and_enable();
    }
    serial.write_str("MMU enabled. Caches active.\r\n").ok();
    serial.write_str("UART: ttyMT0 @ 0x11002000\r\n").ok();

    // Read CPU ID register
    let cpuid: u32;
    #[allow(asm_sub_register)]
    unsafe {
        core::arch::asm!("mrc p15, 0, {}, c0, c0, 0", out(reg) cpuid, options(nostack));
    }
    write!(serial, "CPU ID: {cpuid:#010x}\r\n").ok();

    // Read MPIDR (core ID)
    let mpidr: u32;
    #[allow(asm_sub_register)]
    unsafe {
        core::arch::asm!("mrc p15, 0, {}, c0, c0, 5", out(reg) mpidr, options(nostack));
    }
    write!(serial, "MPIDR: {mpidr:#010x} (core {})\r\n", mpidr & 0x3).ok();

    // Initialize physical page allocator
    // MT6739: RAM from 0x40000000 to 0x7FFFFFFF (1 GB)
    // Kernel loaded at 0x40008000, assume kernel ends at 0x40100000 (1 MB reserved)
    unsafe {
        page::init(0x4000_0000, 0x8000_0000, 0x4010_0000);
    }
    write!(
        serial,
        "\r\nMemory: {} pages free ({} MB)\r\n",
        page::free_count(),
        page::free_bytes() / 1024 / 1024
    )
    .ok();

    // Initialize kernel heap (1 MB from page allocator)
    unsafe {
        heap::init();
    }
    let (used, total) = heap::stats();
    write!(
        serial,
        "Heap: {used} / {total} bytes
"
    )
    .ok();

    // Test heap allocation
    {
        let v: alloc::vec::Vec<u32> = alloc::vec![1, 2, 3, 4, 5];
        write!(
            serial,
            "Vec test: {:?}
",
            v.as_slice()
        )
        .ok();
    }

    // Test page allocation
    if let Some(addr) = page::alloc_page() {
        write!(serial, "Allocated page at {addr:#010x}\r\n").ok();
        unsafe {
            page::free_page(addr);
        }
        serial.write_str("Freed page OK\r\n").ok();
    } else {
        serial.write_str("Page allocation failed!\r\n").ok();
    }

    serial
        .write_str("\r\nKernel running. Tick counter active.\r\n")
        .ok();

    // Main loop: print tick count periodically
    let mut last_print: u64 = 0;
    loop {
        let ticks = exceptions::ticks();
        let ms = exceptions::uptime_ms();
        if ms - last_print >= 1000 {
            write!(serial, "  ticks={ticks} uptime={ms}ms\r\n").ok();
            last_print = ms;
        }
        // WHY: wfe (wait for event) sleeps until next interrupt
        unsafe {
            core::arch::asm!("wfe");
        }
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    let mut serial = uart::Uart::new();
    serial.write_str("\r\n!!! KERNEL PANIC !!!\r\n").ok();
    write!(serial, "{info}\r\n").ok();
    loop {
        unsafe {
            core::arch::asm!("wfe");
        }
    }
}
