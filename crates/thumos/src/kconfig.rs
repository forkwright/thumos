//! Kernel configuration parameters.
//!
//! Runtime-configurable parameters for kernel behavior. These can be
//! set from the boot command line, the debug console, or from userspace
//! via syscall. All parameters have defaults suitable for the MT6739.

/// Scheduler tick interval in milliseconds.
pub(crate) static mut TICK_MS: u32 = 10;

/// Maximum number of processes.
pub(crate) static mut MAX_PROCESSES: usize = 16;

/// Kernel heap size in pages (4 KB each).
pub(crate) static mut HEAP_PAGES: usize = 256;

/// UART baud rate (set by bootloader, informational only).
pub(crate) static mut UART_BAUD: u32 = 921_600;

/// Whether to print boot messages to UART.
pub(crate) static mut VERBOSE_BOOT: bool = true;

/// Enable kernel debug console on UART.
///
/// WARNING: defaults `false` (issue #372) -- the console is a dev-only
/// UART shell with no authentication. The former `console=` cmdline arm
/// that let a boot-args attacker force this to `true` has been deleted;
/// flipping this back to `true` is now a deliberate, reviewable source
/// edit, not a runtime toggle. See `kinit`'s `debug_console_gate` for the
/// full gate (this flag is one layer of three, alongside the
/// `debug-console` compile-time feature and the physical-presence check).
pub(crate) static mut DEBUG_CONSOLE: bool = false;

/// Panic behavior: 0 = halt, N = reboot after N seconds.
pub(crate) static mut PANIC_TIMEOUT: u32 = 0;

/// RAM start address.
pub(crate) const RAM_START: usize = 0x4000_0000;

/// RAM end address (1 GB).
pub(crate) const RAM_END: usize = 0x8000_0000;

/// Kernel load address.
pub(crate) const KERNEL_LOAD: usize = 0x4000_8000;

/// Kernel reserved size (992 KB).
/// WHY: kernel image + reserved region spans `0x4000_8000..0x400F_FFFF`
/// (see the memory map in `memguard.rs`), so KERNEL_END lands on the
/// 0x4010_0000 page boundary rather than a full 1 MB past KERNEL_LOAD.
pub(crate) const KERNEL_RESERVED: usize = 0xF_8000;

/// Kernel end address (load + reserved).
pub(crate) const KERNEL_END: usize = KERNEL_LOAD + KERNEL_RESERVED;

/// Userspace text region base (#474): the top 1 MB of DRAM
/// (0x7FF0_0000..0x8000_0000). Mapped EXECUTABLE (all other DRAM is
/// execute-never per W^X #417) and EXCLUDED from the page allocator (kinit
/// passes this as the allocator's upper bound), so spawned userspace ELFs run
/// here without colliding with kernel page allocations. A single shared region
/// suffices while userspace runs privileged in the kernel address space;
/// per-process user address spaces + PL0 isolation are Wave 4+.
pub(crate) const USER_TEXT_BASE: usize = 0x7FF0_0000;

/// UART0 base address (MT6739 ttyMT0, MTK 8250-style register map).
#[cfg(not(feature = "qemu"))]
pub(crate) const UART0_BASE: usize = 0x1100_2000;

/// UART0 base address (PL011 on QEMU `-machine virt`).
/// NOTE: consumed by uart_pl011.rs, which main.rs swaps in under the qemu
/// feature -- the register map differs, not just the base.
#[cfg(feature = "qemu")]
pub(crate) const UART0_BASE: usize = 0x0900_0000;

/// GIC distributor base address (MT6739 device tree, intc node).
#[cfg(not(feature = "qemu"))]
pub(crate) const GICD_BASE: usize = 0x0C00_0000;

/// GIC distributor base address (QEMU `-machine virt`, GICv2).
#[cfg(feature = "qemu")]
pub(crate) const GICD_BASE: usize = 0x0800_0000;

/// GIC CPU interface base address (MT6739).
#[cfg(not(feature = "qemu"))]
pub(crate) const GICC_BASE: usize = 0x0C00_2000;

/// GIC CPU interface base address (QEMU `-machine virt`, GICv2).
#[cfg(feature = "qemu")]
pub(crate) const GICC_BASE: usize = 0x0801_0000;

/// Display framebuffer base (set by LK bootloader).
pub(crate) const FB_BASE: usize = 0x77EE_0000;

/// Start sector of the LFS partition on eMMC.
/// WHY: the boot, recovery, system, vendor partitions occupy the first ~2.6 GB.
/// LFS uses the userdata region starting at sector 0x50C000 (~2.6 GB offset).
/// Value from GPT dump of the MT6739 eMMC (printgpt: userdata partition).
pub(crate) const LFS_PARTITION_START: u64 = 0x50C000;

/// Size of the LFS partition in sectors.
/// WHY: ~3 GB of the 8 GB eMMC is available for user data.
/// Rounded down from the actual userdata partition length (0x97BFDF sectors)
/// to a clean segment-aligned boundary.
pub(crate) const LFS_PARTITION_SIZE: u64 = 0x600000;

/// Number of blocks in the block cache.
/// WHY: 256 entries x 4 KiB = 1 MiB of cached data. Balances memory usage
/// against hit rate for typical file access patterns.
pub(crate) const BLOCK_CACHE_BLOCKS: usize = 256;

/// Display width.
pub(crate) const DISPLAY_WIDTH: u32 = 240;

/// Display height.
pub(crate) const DISPLAY_HEIGHT: u32 = 320;

/// Parse a boot command line parameter.
/// Format: "key=value" pairs separated by spaces.
pub(crate) fn parse_cmdline(cmdline: &str) {
    for param in cmdline.split_whitespace() {
        if let Some((key, value)) = param.split_once('=') {
            match key {
                "panic" => {
                    if let Ok(v) = value.parse::<u32>() {
                        // SAFETY: parse_cmdline is called once during early boot before
                        // any concurrent access to these static mut config globals.
                        unsafe {
                            PANIC_TIMEOUT = v;
                        }
                    }
                }
                // SAFETY: parse_cmdline is called once during early boot before
                // any concurrent access to these static mut config globals.
                "verbose" => unsafe {
                    VERBOSE_BOOT = value != "0";
                },
                // WHY (issue #372): the `console=` key is deliberately NOT
                // handled -- it falls through to the `_` (ignored) arm
                // below. A boot-args attacker must not be able to force
                // the debug console on; `DEBUG_CONSOLE` is now a
                // compile-time-fixed default (see its doc comment) with no
                // runtime cmdline path.
                "tick_ms" => {
                    if let Ok(v) = value.parse::<u32>() {
                        // SAFETY: parse_cmdline is called once during early boot before
                        // any concurrent access to these static mut config globals.
                        unsafe {
                            TICK_MS = v.max(1).min(100);
                        }
                    }
                }
                _ => {} // NOTE: ignore unknown parameters
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_are_correct() {
        assert_eq!(RAM_END - RAM_START, 1024 * 1024 * 1024);
        assert_eq!(KERNEL_END, 0x4010_0000);
        assert_eq!(DISPLAY_WIDTH * DISPLAY_HEIGHT * 2, 153_600); // RGB565 framebuffer size
    }

    #[test]
    fn parse_cmdline_sets_tick_rate_and_security_flags() {
        parse_cmdline("tick_ms=25 verbose=0 console=1 panic=5");

        // SAFETY: single-threaded test (nextest process-isolates per test);
        // addr_of!().read() avoids a shared reference to the static mut.
        let (tick, verbose, console, panic) = unsafe {
            (
                core::ptr::addr_of!(TICK_MS).read(),
                core::ptr::addr_of!(VERBOSE_BOOT).read(),
                core::ptr::addr_of!(DEBUG_CONSOLE).read(),
                core::ptr::addr_of!(PANIC_TIMEOUT).read(),
            )
        };
        assert_eq!(tick, 25);
        assert!(!verbose);
        // WHY (issue #372): `console=` is deliberately a no-op (see
        // parse_cmdline) -- a boot-args attacker must not be able to force
        // the debug console on. `console=1` here proves that: DEBUG_CONSOLE
        // stays at its compile-time default (false) regardless of cmdline
        // input.
        assert!(!console, "console= must not be settable from the cmdline");
        assert_eq!(panic, 5);
    }

    #[test]
    fn parse_cmdline_clamps_tick_ms_to_valid_range() {
        parse_cmdline("tick_ms=500");
        // SAFETY: single-threaded test; addr_of!().read() avoids a static-mut ref.
        let tick_hi = unsafe { core::ptr::addr_of!(TICK_MS).read() };
        assert_eq!(tick_hi, 100, "tick_ms must clamp to the 100ms ceiling");

        parse_cmdline("tick_ms=0");
        // SAFETY: single-threaded test; addr_of!().read() avoids a static-mut ref.
        let tick_lo = unsafe { core::ptr::addr_of!(TICK_MS).read() };
        assert_eq!(tick_lo, 1, "tick_ms must clamp to the 1ms floor");
    }

    #[test]
    fn parse_cmdline_ignores_unknown_and_malformed_params() {
        // SAFETY: single-threaded test; addr_of!().read() avoids a static-mut ref.
        let before = unsafe { core::ptr::addr_of!(PANIC_TIMEOUT).read() };
        parse_cmdline("bogus=1 no_equals_sign panic=notanumber");
        // SAFETY: single-threaded test; addr_of!().read() avoids a static-mut ref.
        let after = unsafe { core::ptr::addr_of!(PANIC_TIMEOUT).read() };
        assert_eq!(
            after, before,
            "malformed panic= value must be ignored, not applied"
        );
    }
}
