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
pub(crate) static mut DEBUG_CONSOLE: bool = true;

/// Panic behavior: 0 = halt, N = reboot after N seconds.
pub(crate) static mut PANIC_TIMEOUT: u32 = 0;

/// RAM start address.
pub(crate) const RAM_START: usize = 0x4000_0000;

/// RAM end address (1 GB).
pub(crate) const RAM_END: usize = 0x8000_0000;

/// Kernel load address.
pub(crate) const KERNEL_LOAD: usize = 0x4000_8000;

/// Kernel reserved size (1 MB).
pub(crate) const KERNEL_RESERVED: usize = 0x10_0000;

/// Kernel end address (load + reserved).
pub(crate) const KERNEL_END: usize = KERNEL_LOAD + KERNEL_RESERVED;

/// UART0 base address.
pub(crate) const UART0_BASE: usize = 0x1100_2000;

/// GIC distributor base address.
pub(crate) const GICD_BASE: usize = 0x0C00_0000;

/// GIC CPU interface base address.
pub(crate) const GICC_BASE: usize = 0x0C00_2000;

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
                // SAFETY: parse_cmdline is called once during early boot before
                // any concurrent access to these static mut config globals.
                "console" => unsafe {
                    DEBUG_CONSOLE = value != "0";
                },
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
}
