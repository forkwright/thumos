//! Kernel configuration parameters.
//!
//! Runtime-configurable parameters for kernel behavior. These can be
//! set from the boot command line, the debug console, or from userspace
//! via syscall. All parameters have defaults suitable for the MT6739.
//!
//! Board and memory-map CONSTANTS (UART/GIC bases, RAM window, kernel
//! layout, framebuffer, partition table, display geometry) are NOT here —
//! they live under `crate::board` (#534: one seam, one selection point).

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

/// Number of blocks in the block cache.
/// WHY: 256 entries x 4 KiB = 1 MiB of cached data. Balances memory usage
/// against hit rate for typical file access patterns.
pub(crate) const BLOCK_CACHE_BLOCKS: usize = 256;

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
                            TICK_MS = v.clamp(1, 100);
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
