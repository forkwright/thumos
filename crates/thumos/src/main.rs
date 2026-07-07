//! Thumos kernel
//!
//! Bare-metal Rust kernel for the MT6739. ARM boot stub is inline
//! assembly that sets up the stack and zeros BSS before jumping to
//! kernel_main.

#![no_std]
#![cfg_attr(not(test), no_main)]
// WHY (#431): the kernel carries a large compiled-and-tested surface that is
// not yet boot-wired (radio/messaging/UI subsystems built ahead of the boot
// path). That is a deliberate, tracked state (#145 wiring audit, #420
// boot-wiring), not cruft, so dead_code is expected crate-wide rather than
// annotated at ~715 sites. WHY expect not allow: the wiring waves progressively
// consume the surface, and once it is fully wired this expectation goes
// unfulfilled and prompts its own removal. All OTHER warning classes stay live
// under the -D warnings gate.
#![expect(dead_code, reason = "compiled-but-unwired surface, tracked #145/#420")]
extern crate alloc;

#[cfg(not(test))]
use core::fmt::Write;
#[cfg(not(test))]
use core::panic::PanicInfo;

mod audio;
mod audio_codec;
mod audio_route;
mod audit;
mod avdtp;
mod battery;
mod bfu_timer;
mod block;
mod bluetooth;
mod briar;
mod bt_audio;
mod cache;
mod capability;
mod ccci;
mod ccci_logger;
mod clock;

// WHY (issue #372): `debug-console` and `production` are structurally
// mutually exclusive -- the dev-only kernel shell (unauthenticated UART
// command execution, no capability check) must never be compiled into a
// shippable/production image. A CI grep on a diff cannot catch a future
// `--all-features` invocation (security.yml's cargo-deny job already runs
// one, though today scoped to the workspace, which excludes this crate);
// this compile_error! does, because --all-features enables both features
// at once regardless of workspace membership.
#[cfg(all(feature = "debug-console", feature = "production"))]
compile_error!(
    "debug-console and production are mutually exclusive (issue #372): the dev-only kernel UART shell must never ship. Build with --features debug-console (no --features production) for a bring-up/dev image, or --features production (no --features debug-console) for the ship/flash artifact."
);

// WHY: the qemu feature remaps peripheral base addresses and no-ops SoC-only
// MMIO -- structurally incompatible with a shippable image. Fails an
// --all-features build loudly instead of producing a kernel that cannot run
// on the phone.
#[cfg(all(feature = "qemu", feature = "production"))]
compile_error!(
    "qemu and production are mutually exclusive: the QEMU bring-up harness remaps MT6739 peripheral addresses and must never ship."
);

// WHY (#487 fault-handling): the kfault-probe injects a deliberate kernel fault
// for CI; a production image must never contain one.
#[cfg(all(feature = "kfault-probe", feature = "production"))]
compile_error!(
    "kfault-probe is a CI fault-injection harness; a production image must not contain a deliberate kernel fault."
);

// WHY (issue #372): also gated `not(test)` — the console's command methods
// (cmd_mem/cmd_ps/…) read kernel state via `crate::heap`/`page`/`process`,
// several of which are themselves `#[cfg(not(test))]`, so the module cannot
// compile under the host-test cfg. Making the console host-testable (to
// resurrect the #337 receive_byte tests + the new presence test) needs
// heap/page/process host stubs — tracked separately; out of #372's
// structural-gate scope. The armv7a `--features debug-console` build proves
// the console compiles for its real target.
#[cfg(all(feature = "debug-console", not(test)))]
mod console;
mod contacts;
mod csprng;
mod devfs;
#[cfg(not(test))]
mod device;
mod dhcp;
mod display;
mod dns;
mod dns_tls;
mod ekphrasis;
mod elf;
#[cfg(not(test))]
mod emmc;
mod encryption;
#[cfg(not(test))]
mod exceptions;
mod lfs;
mod lfs_checkpoint;
mod lfs_compact;
mod lfs_imap;
mod lfs_segment;
mod lfs_writer;
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
#[cfg(not(test))]
mod gic;
#[cfg(not(test))]
mod heap;
mod heorte_alarm;
mod heorte_timer;
mod http_client;
mod ipc;
mod irq;
mod json_mini;
// WHY (#420): post-boot service loop + persisted KernelState. Test-gated
// like kinit -- it consumes kinit::BootState and device::DeviceRegistry,
// both cfg(not(test)).
#[cfg(not(test))]
mod kardia;
mod kconfig;
mod key_manager;
#[cfg(not(test))]
mod kinit;
mod lock_screen;
mod matrix_crypto;
mod memguard;
mod meshtastic;
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
// WHY(qemu): semihosting exit codes + early host-console writes for the
// QEMU runner (see scripts/qemu-runner.sh).
#[cfg(all(not(test), feature = "qemu"))]
mod qemu;
mod ramfs;
mod reflex;
mod sbc;
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
mod sms;
mod socket;
mod status_bar;
mod syscall;
mod t9;
mod telephony;
#[cfg(test)]
mod telephony_mock;
mod telephony_parser;
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
#[cfg(all(not(test), not(feature = "qemu")))]
mod uart;
// WHY(qemu): virt has a PL011 at kconfig::UART0_BASE, not the MTK 8250-style
// UART; same module surface, different register map (see uart_pl011.rs).
#[cfg(all(not(test), feature = "qemu"))]
#[path = "uart_pl011.rs"]
mod uart;
mod ui;
// WHY(host-test): syscall's stdout (fd 1) and unknown-syscall debug paths
// write to the MT6739 UART (ttyMT0 MMIO), which is ARM-only. Under test a
// stub swallows output so syscall is host-testable. Production is unaffected.
#[cfg(test)]
#[path = "uart_stub.rs"]
mod uart;
mod usb;
mod vfs;
#[cfg(all(not(test), not(feature = "qemu")))]
mod watchdog;
// WHY(qemu): virt models no MT6739 WDT; a no-op stub keeps the timer-IRQ
// pet path and kinit call sites identical without touching MMIO.
#[cfg(all(not(test), feature = "qemu"))]
#[path = "watchdog_qemu.rs"]
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
    "    cpsid   if", // Disable interrupts
    // WHY: banked-mode stacks. Reset leaves SP_irq/SP_abt/SP_und UNKNOWN;
    // the first timer IRQ (or any abort) pushes {r0-r12,lr} through them
    // (exceptions.rs asm wrappers), so without this setup the first tick
    // corrupts memory or double-faults silently. Latent on every target --
    // QEMU bring-up is simply the first place the timer IRQ has ever fired.
    "    msr     cpsr_c, #0xD2", // IRQ mode (I+F masked)
    "    ldr     sp, =__irq_stack_top",
    "    msr     cpsr_c, #0xD7", // ABT mode (I+F masked)
    "    ldr     sp, =__abt_stack_top",
    "    msr     cpsr_c, #0xDB", // UND mode (I+F masked)
    "    ldr     sp, =__und_stack_top",
    "    msr     cpsr_c, #0xD3", // SVC mode (I+F masked) -- transient trap mode
    "    ldr     sp, =__svc_stack_top",
    // WHY(#465): enter SYSTEM mode for the kernel proper. kinit and the kardia
    // service loop (PID 0) run here, sharing the user/system register bank with
    // spawned processes, so the exception stubs capture/restore the interrupted
    // sp/lr uniformly (see exceptions.rs). System is PL1, so CP15/MMU/GIC and
    // cpsid/cpsie stay legal.
    "    msr     cpsr_c, #0xDF",    // SYSTEM mode (I+F masked)
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
    // WHY(qemu): earliest possible liveness marker -- proves _start ran and
    // semihosting works even when the UART path is broken.
    #[cfg(feature = "qemu")]
    qemu::write0(c"thumos-qemu: kernel_main reached\n");
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

    // WHY(qemu): report exit code 1 via semihosting so a panic fails the
    // run immediately instead of hanging to the runner timeout.
    #[cfg(feature = "qemu")]
    qemu::request_exit(1);

    loop {
        // SAFETY: WFE is a hint instruction available in all ARM privilege levels.
        // No memory is accessed; the CPU enters a low-power wait state until an event.
        unsafe {
            core::arch::asm!("wfe");
        }
    }
}
