//! MT6739 UART driver (ttyMT0).
//!
//! The MT6739 has 4 UART controllers. UART0 (ttyMT0) is the debug console
//! at base address 0x11002000. The bootloader (LK) already configures it
//! to 921600 baud, 8N1. We just write to the TX holding register.
//!
//! Register map (FROM driver interface spec):
//! - 0x00: RBR/THR (receive buffer / transmit holding)
//! - 0x04: IER (interrupt enable)
//! - 0x14: LSR (line status)
//!   - bit 5: THRE (transmit holding register empty)
//!   - bit 6: TEMT (transmitter empty)

use core::fmt;

/// Base address of UART0 on MT6739.
const UART0_BASE: usize = 0x1100_2000;

/// Transmit holding register OFFSET.
const THR: usize = 0x00;

/// Line status register OFFSET.
const LSR: usize = 0x14;

/// LSR bit: transmit holding register empty.
const LSR_THRE: u32 = 1 << 5;

/// UART driver for MT6739.
pub struct Uart {
    base: usize,
}

impl Uart {
    /// Create a UART driver for the debug console.
    /// LK has already configured baud rate and pin mux.
    pub fn new() -> Self {
        Self { base: UART0_BASE }
    }

    /// Write a single byte, waiting for the TX buffer to be ready.
    pub fn putc(&self, byte: u8) {
        // SAFETY: MMIO register access at known physical address.
        // The UART is already initialized by the bootloader.
        unsafe {
            let lsr = (self.base + LSR) as *const u32;
            let thr = (self.base + THR) as *mut u32;

            // Wait until transmit holding register is empty
            #[allow(clippy::while_immutable_condition)]
            while core::ptr::read_volatile(lsr) & LSR_THRE == 0 {}

            // Write byte
            *thr = u32::try_from(byte).unwrap_or_default();
        }
    }

    /// Write a string to the UART.
    pub fn write_str_raw(&self, s: &str) {
        for byte in s.bytes() {
            self.putc(byte);
        }
    }
}

impl fmt::Write for Uart {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.write_str_raw(s);
        Ok(())
    }
}
