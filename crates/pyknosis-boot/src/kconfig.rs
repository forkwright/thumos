//! Kernel configuration parameters.
//!
//! Runtime-configurable parameters for kernel behavior. These can be
//! set from the boot command line, the debug console, or from userspace
//! via syscall. All parameters have defaults suitable for the MT6739.

/// Scheduler tick interval in milliseconds.
pub static mut TICK_MS: u32 = 10;

/// Maximum number of processes.
pub static mut MAX_PROCESSES: usize = 16;

/// Kernel heap size in pages (4 KB each).
pub static mut HEAP_PAGES: usize = 256;

/// UART baud rate (set by bootloader, informational only).
pub static mut UART_BAUD: u32 = 921_600;

/// Whether to print boot messages to UART.
pub static mut VERBOSE_BOOT: bool = true;

/// Enable kernel debug console on UART.
pub static mut DEBUG_CONSOLE: bool = true;

/// Panic behavior: 0 = halt, N = reboot after N seconds.
pub static mut PANIC_TIMEOUT: u32 = 0;

/// RAM start address.
pub const RAM_START: usize = 0x4000_0000;

/// RAM end address (1 GB).
pub const RAM_END: usize = 0x8000_0000;

/// Kernel load address.
pub const KERNEL_LOAD: usize = 0x4000_8000;

/// Kernel reserved size (1 MB).
pub const KERNEL_RESERVED: usize = 0x10_0000;

/// Kernel end address (load + reserved).
pub const KERNEL_END: usize = KERNEL_LOAD + KERNEL_RESERVED;

/// UART0 base address.
pub const UART0_BASE: usize = 0x1100_2000;

/// GIC distributor base address.
pub const GICD_BASE: usize = 0x0C00_0000;

/// GIC CPU interface base address.
pub const GICC_BASE: usize = 0x0C00_2000;

/// Display framebuffer base (set by LK bootloader).
pub const FB_BASE: usize = 0x77EE_0000;

/// Display width.
pub const DISPLAY_WIDTH: u32 = 240;

/// Display height.
pub const DISPLAY_HEIGHT: u32 = 320;

/// Parse a boot command line parameter.
/// Format: "key=value" pairs separated by spaces.
pub fn parse_cmdline(cmdline: &str) {
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
