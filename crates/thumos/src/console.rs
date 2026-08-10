//! Kernel debug console.
//!
//! A minimal command-line shell for kernel debugging over UART.
//! Provides commands to inspect memory, processes, devices, and system state.
//! This is a development tool, not part of the production UI.

extern crate alloc;

use core::fmt::Write;

use crate::exceptions;
use crate::page;
use crate::process;
use crate::uart::Uart;

/// Maximum command line length.
const MAX_CMD_LEN: usize = 128;

/// Magic byte sequence required over UART before the console will start
/// (issue #372 defense-in-depth: the console must not auto-start merely
/// because a debug-console build booted and the boot-time gates passed --
/// an operator must prove physical presence by typing this sequence).
const PRESENCE_SEQUENCE: &[u8] = b"THUMOS-UNLOCK\r";

/// Bound on presence-sequence idle polling, in iterations between bytes
/// (not wall-clock time -- mirrors `uart::Uart`'s `UART_TX_TIMEOUT_SPINS`:
/// this runs before any timer dependency is guaranteed available, so a raw
/// iteration bound is the correct choice, not an elapsed-ticks check).
/// TODO(#459)[deliberate-prudent]: the wall-clock window this represents is uncalibrated against
/// real UART polling throughput; tune once measured on hardware.
const PRESENCE_POLL_SPINS: u32 = 1_000_000;

/// Kernel debug console.
pub(crate) struct Console {
    serial: Uart,
    line_buf: [u8; MAX_CMD_LEN],
    line_len: usize,
}

impl Console {
    /// Create a new console on the default UART.
    pub(crate) fn new() -> Self {
        Self {
            serial: Uart::new(),
            line_buf: [0; MAX_CMD_LEN],
            line_len: 0,
        }
    }

    /// Block (bounded) until `PRESENCE_SEQUENCE` is received over UART,
    /// confirming a physically-present operator before the caller starts
    /// the interactive shell (issue #372).
    ///
    /// Fails closed: if no byte arrives for `PRESENCE_POLL_SPINS`
    /// iterations, or the caller never supplies the exact sequence,
    /// returns `false` and the caller must not start the console. Any
    /// mismatched byte resets the match (a typo requires retyping the
    /// whole sequence, not just the wrong character).
    pub(crate) fn wait_for_physical_presence(serial: &Uart) -> bool {
        let mut matched = 0usize;
        let mut idle_spins: u32 = 0;
        while matched < PRESENCE_SEQUENCE.len() {
            match serial.getc() {
                Some(byte) if byte == PRESENCE_SEQUENCE[matched] => {
                    matched += 1;
                    idle_spins = 0; // NOTE: reset the idle bound on forward progress
                }
                Some(_) => {
                    matched = 0; // NOTE: any mismatched byte resets the sequence
                    idle_spins = 0;
                }
                None => {
                    idle_spins += 1;
                    if idle_spins >= PRESENCE_POLL_SPINS {
                        return false;
                    }
                }
            }
        }
        true
    }

    /// Print the prompt.
    pub(crate) fn prompt(&mut self) {
        let _ = self.serial.write_str("thumos> "); // WHY: best-effort serial write; kernel cannot block on failed UART output
    }

    /// Process a received byte (FROM UART RX interrupt or polling).
    pub(crate) fn receive_byte(&mut self, byte: u8) {
        match byte {
            // Enter
            b'\r' | b'\n' => {
                let _ = self.serial.write_str("\r\n"); // WHY: best-effort serial write; kernel cannot block on failed UART output
                if self.line_len > 0 {
                    let mut cmd_buf = [0u8; 128];
                    cmd_buf[..self.line_len].copy_from_slice(&self.line_buf[..self.line_len]);
                    let len = self.line_len;
                    self.line_len = 0;
                    let cmd = core::str::from_utf8(&cmd_buf[..len]).unwrap_or("");
                    self.execute(cmd);
                    self.line_len = 0;
                }
                self.prompt();
            }
            // Backspace
            0x7F | 0x08 => {
                if self.line_len > 0 {
                    self.line_len -= 1;
                    let _ = self.serial.write_str("\x08 \x08"); // WHY: best-effort serial write; kernel cannot block on failed UART output
                }
            }
            // Printable
            0x20..=0x7E => {
                if self.line_len < MAX_CMD_LEN - 1 {
                    self.line_buf[self.line_len] = byte;
                    self.line_len += 1;
                    self.serial.putc(byte); // Echo
                }
            }
            _ => {} // WHY: silently drop other control bytes (buffer-full fallthrough handled above)
        }
    }

    /// Execute a console command.
    fn execute(&mut self, cmd: &str) {
        let parts: alloc::vec::Vec<&str> = cmd.split_whitespace().collect();
        if parts.is_empty() {
            return;
        }

        match parts.first().copied().unwrap_or_default() {
            "help" | "?" => self.cmd_help(),
            "uptime" => self.cmd_uptime(),
            "mem" => self.cmd_mem(),
            "ps" => self.cmd_ps(),
            "ver" => self.cmd_version(),
            "panic" => Self::cmd_panic(),
            "reboot" => self.cmd_reboot(),
            _ => {
                let _ = write!(
                    self.serial,
                    "unknown command: {}\r\n",
                    parts.first().copied().unwrap_or_default()
                ); // WHY: best-effort serial write; kernel cannot block on failed UART output
                let _ = self.serial.write_str("type 'help' for commands\r\n"); // WHY: best-effort serial write; kernel cannot block on failed UART output
            }
        }
    }

    fn cmd_help(&mut self) {
        let _ = self.serial.write_str("commands:\r\n"); // WHY: best-effort serial write; kernel cannot block on failed UART output
        let _ = self.serial.write_str("  help     -  show this help\r\n"); // WHY: best-effort serial write; kernel cannot block on failed UART output
        let _ = self
            .serial
            .write_str("  uptime   -  show system uptime\r\n");
        let _ = self.serial.write_str("  mem      -  show memory usage\r\n"); // WHY: best-effort serial write; kernel cannot block on failed UART output
        let _ = self.serial.write_str("  ps       -  show processes\r\n"); // WHY: best-effort serial write; kernel cannot block on failed UART output
        let _ = self
            .serial
            .write_str("  ver      -  show kernel version\r\n");
        let _ = self
            .serial
            .write_str("  panic    -  trigger kernel panic (test)\r\n");
        let _ = self.serial.write_str("  reboot   -  reboot the system\r\n"); // WHY: best-effort serial write; kernel cannot block on failed UART output
    }

    fn cmd_uptime(&mut self) {
        let ms = exceptions::uptime_ms();
        let secs = ms / 1000;
        let mins = secs / 60;
        let hours = mins / 60;
        let _ = write!(
            self.serial,
            "up {}h {}m {}s ({} ticks)\r\n",
            hours,
            mins % 60,
            secs % 60,
            exceptions::ticks()
        );
    }

    fn cmd_mem(&mut self) {
        let free = page::free_count();
        let free_mb = page::free_bytes() / 1024 / 1024;
        let (heap_allocs, heap_frees) = crate::heap::stats();
        let _ = write!(self.serial, "pages: {free} free ({free_mb} MB)\r\n"); // WHY: best-effort serial write; kernel cannot block on failed UART output
        let _ = write!(
            self.serial,
            "heap: {} allocs, {} frees, {} live\r\n",
            heap_allocs,
            heap_frees,
            heap_allocs.saturating_sub(heap_frees),
        );
    }

    fn cmd_ps(&mut self) {
        let _ = write!(self.serial, "PID {} running\r\n", process::current_pid()); // WHY: best-effort serial write; kernel cannot block on failed UART output
    }

    fn cmd_version(&mut self) {
        let _ = self.serial.write_str("thumos v0.1.0\r\n"); // WHY: best-effort serial write; kernel cannot block on failed UART output
        let _ = self
            .serial
            .write_str("Rust monolithic kernel for MT6739\r\n");
    }

    fn cmd_panic() {
        panic!("user-triggered panic FROM console");
    }

    fn cmd_reboot(&mut self) {
        let _ = self.serial.write_str("rebooting...\r\n"); // WHY: best-effort serial write; kernel cannot block on failed UART output
        // NOTE: ARM watchdog reset
        // SAFETY: WDT_MODE and WDT_SWRST are MT6739 watchdog MMIO registers at known addresses.
        unsafe {
            // Write to the MT6739 watchdog to trigger a reset
            // WDT_MODE at 0x10007000, SET bit 0 (enable) + key 0x2200
            let wdt_mode = 0x1000_7000 as *mut u32;
            core::ptr::write_volatile(wdt_mode, 0x2200_0001);
            // WDT_SWRST at 0x10007014, write key to trigger
            let wdt_swrst = 0x1000_7014 as *mut u32;
            core::ptr::write_volatile(wdt_swrst, 0x1209);
        }
        // WHY(#459): wfi has no i686 encoding, so the host-test build gates
        // this whole loop out; the reboot path never returns in production
        // anyway, and no host test calls cmd_reboot. Gating the STATEMENT
        // (not a `break` inside it) means the test build never contains a
        // loop that runs its body once and exits -- clippy::never_loop has
        // nothing to flag there, because there is no loop there at all.
        #[cfg(not(test))]
        loop {
            // SAFETY: wfi is a safe wait-for-interrupt instruction accessible at EL1.
            unsafe {
                core::arch::asm!("wfi");
            }
        }
    }
}

impl Default for Console {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receive_byte_buffers_printable_chars() {
        let mut console = Console::new();
        console.receive_byte(b'h');
        console.receive_byte(b'i');
        assert_eq!(console.line_len, 2);
        assert_eq!(&console.line_buf[..2], b"hi");
    }

    #[test]
    fn receive_byte_overflow_drops_excess_bytes_without_panic() {
        let mut console = Console::new();
        for _ in 0..MAX_CMD_LEN + 16 {
            console.receive_byte(b'x');
        }
        assert_eq!(
            console.line_len,
            MAX_CMD_LEN - 1,
            "line buffer must cap at MAX_CMD_LEN - 1, dropping excess bytes rather than overflowing"
        );
    }

    #[test]
    fn receive_byte_backspace_after_overflow_shrinks_buffer() {
        let mut console = Console::new();
        for _ in 0..MAX_CMD_LEN + 16 {
            console.receive_byte(b'x');
        }
        console.receive_byte(0x7F);
        assert_eq!(console.line_len, MAX_CMD_LEN - 2);
    }

    #[test]
    fn wait_for_physical_presence_times_out_without_input() {
        // WHY: the host-test `uart::Uart` stub never has RX data available
        // (see uart_stub.rs), so this exercises the fail-closed path: no
        // presence sequence arrives, and the bounded poll must return
        // `false` rather than hang.
        let serial = Uart::new();
        assert!(!Console::wait_for_physical_presence(&serial));
    }
}
