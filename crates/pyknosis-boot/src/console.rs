//! Kernel debug console.
//!
//! A minimal command-line shell for kernel debugging over UART.
//! Provides commands to inspect memory, processes, devices, and system state.
//! This is a development tool, not part of the production UI.

extern crate alloc;

use crate::device::DeviceRegistry;
use crate::exceptions;
use crate::page;
use crate::process;
use crate::uart::Uart;
use alloc::string::String;
use core::fmt::Write;

/// Maximum command line length.
const MAX_CMD_LEN: usize = 128;

/// Kernel debug console.
pub struct Console {
    serial: Uart,
    line_buf: [u8; MAX_CMD_LEN],
    line_len: usize,
}

impl Console {
    /// Create a new console on the default UART.
    pub fn new() -> Self {
        Self {
            serial: Uart::new(),
            line_buf: [0; MAX_CMD_LEN],
            line_len: 0,
        }
    }

    /// Print the prompt.
    pub fn prompt(&mut self) {
        if let Err(e) = self.serial.write_str("thumos> ") { tracing::warn!(error = %e, "operation failed"); }
    }

    /// Process a received byte (FROM UART RX interrupt or polling).
    pub fn receive_byte(&mut self, byte: u8) {
        match byte {
            // Enter
            b'\r' | b'\n' => {
                if let Err(e) = self.serial.write_str("\r\n") { tracing::warn!(error = %e, "operation failed"); }
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
                    if let Err(e) = self.serial.write_str("\x08 \x08") { tracing::warn!(error = %e, "operation failed"); }
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
            _ => {}
        }
    }

    /// Execute a console command.
    fn execute(&mut self, cmd: &str) {
        let parts: alloc::vec::Vec<&str> = cmd.split_whitespace().collect();
        if parts.is_empty() {
            return;
        }

        match parts.get(0).copied().unwrap_or_default() {
            "help" | "?" => self.cmd_help(),
            "uptime" => self.cmd_uptime(),
            "mem" => self.cmd_mem(),
            "ps" => self.cmd_ps(),
            "ver" => self.cmd_version(),
            "panic" => self.cmd_panic(),
            "reboot" => self.cmd_reboot(),
            _ => {
                if let Err(e) = write!(self.serial, "unknown command: {}\r\n", parts.get(0).copied().unwrap_or_default()) { tracing::warn!(error = %e, "operation failed"); }
                if let Err(e) = self.serial.write_str("type 'help' for commands\r\n") { tracing::warn!(error = %e, "operation failed"); }
            }
        }
    }

    fn cmd_help(&mut self) {
        if let Err(e) = self.serial.write_str("commands:\r\n") { tracing::warn!(error = %e, "operation failed"); }
        if let Err(e) = self.serial.write_str("  help     -  show this help\r\n") { tracing::warn!(error = %e, "operation failed"); }
        self.serial
            .write_str("  uptime   -  show system uptime\r\n")
           if let Err(e) =   { tracing::warn!(error = %e, "operation failed"); }
        self.serial
            .write_str("  mem      -  show memory usage\r\n")
           if let Err(e) =   { tracing::warn!(error = %e, "operation failed"); }
        if let Err(e) = self.serial.write_str("  ps       -  show processes\r\n") { tracing::warn!(error = %e, "operation failed"); }
        self.serial
            .write_str("  ver      -  show kernel version\r\n")
           if let Err(e) =   { tracing::warn!(error = %e, "operation failed"); }
        self.serial
            .write_str("  panic    -  trigger kernel panic (test)\r\n")
           if let Err(e) =   { tracing::warn!(error = %e, "operation failed"); }
        self.serial
            .write_str("  reboot   -  reboot the system\r\n")
           if let Err(e) =   { tracing::warn!(error = %e, "operation failed"); }
    }

    fn cmd_uptime(&mut self) {
        let ms = exceptions::uptime_ms();
        let secs = ms / 1000;
        let mins = secs / 60;
        let hours = mins / 60;
        write!(
            self.serial,
            "up {}h {}m {}s ({} ticks)\r\n",
            hours,
            mins % 60,
            secs % 60,
            exceptions::ticks()
        )
       if let Err(e) =   { tracing::warn!(error = %e, "operation failed"); }
    }

    fn cmd_mem(&mut self) {
        let free = page::free_count();
        let free_mb = page::free_bytes() / 1024 / 1024;
        let (heap_used, heap_total) = crate::heap::stats();
        if let Err(e) = write!(self.serial, "pages: {} free ({} MB)\r\n", free, free_mb) { tracing::warn!(error = %e, "operation failed"); }
        write!(
            self.serial,
            "heap: {} / {} bytes ({:.1}%)\r\n",
            heap_used,
            heap_total,
            f64::try_from(heap_used).unwrap_or_default() / f64::try_from(heap_total).unwrap_or_default() * 100.0
        )
       if let Err(e) =   { tracing::warn!(error = %e, "operation failed"); }
    }

    fn cmd_ps(&mut self) {
        if let Err(e) = write!(self.serial, "PID {} running\r\n", process::current_pid()) { tracing::warn!(error = %e, "operation failed"); }
    }

    fn cmd_version(&mut self) {
        if let Err(e) = self.serial.write_str("thumos/pyknosis v0.1.0\r\n") { tracing::warn!(error = %e, "operation failed"); }
        self.serial
            .write_str("Rust monolithic kernel for MT6739\r\n")
           if let Err(e) =   { tracing::warn!(error = %e, "operation failed"); }
    }

    fn cmd_panic(&mut self) {
        panic!("user-triggered panic FROM console");
    }

    fn cmd_reboot(&mut self) {
        if let Err(e) = self.serial.write_str("rebooting...\r\n") { tracing::warn!(error = %e, "operation failed"); }
        // NOTE: ARM watchdog reset
        unsafe {
            // Write to the MT6739 watchdog to trigger a reset
            // WDT_MODE at 0x10007000, SET bit 0 (enable) + key 0x2200
            let wdt_mode = 0x1000_7000 as *mut u32;
            core::ptr::write_volatile(wdt_mode, 0x2200_0001);
            // WDT_SWRST at 0x10007014, write key to trigger
            let wdt_swrst = 0x1000_7014 as *mut u32;
            core::ptr::write_volatile(wdt_swrst, 0x1209);
        }
        loop {
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
