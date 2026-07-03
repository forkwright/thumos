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

/// Bound on `putc`'s TX-ready poll, in iterations (not wall-clock time --
/// see `putc`'s doc comment). Generous enough to never trip under normal
/// operation (THRE typically clears within a handful of polls at 921600
/// baud) while still finite, so a stalled/disconnected UART cannot hang
/// the kernel.
const UART_TX_TIMEOUT_SPINS: u32 = 1_000_000;

/// UART driver for MT6739.
pub(crate) struct Uart {
    base: usize,
}

impl Uart {
    /// Create a UART driver for the debug console.
    /// LK has already configured baud rate and pin mux.
    pub(crate) fn new() -> Self {
        Self { base: UART0_BASE }
    }

    /// Write a single byte, waiting (bounded) for the TX buffer to be ready.
    ///
    /// WHY bounded: an unbounded spin here can hang the kernel forever if
    /// the UART TX is stalled (no host listening, cable unplugged) -- this
    /// path is reached from exception/fault handlers, where an indefinite
    /// spin means the kernel never even finishes printing a fault report,
    /// let alone recovers. `UART_TX_TIMEOUT_SPINS` bounds the number of
    /// polls, not wall-clock time: uart.rs has no timer dependency (fault
    /// handlers can fire before the timer subsystem is configured), so
    /// exceeding it means "give up polling", not "N ms elapsed". A dropped
    /// byte is preferable to a wedged kernel.
    pub(crate) fn putc(&self, byte: u8) {
        // SAFETY: MMIO register access at known physical address.
        // The UART is already initialized by the bootloader.
        unsafe {
            let lsr = (self.base + LSR) as *const u32;
            let thr = (self.base + THR) as *mut u32;

            // Wait until transmit holding register is empty, bounded so a
            // stalled UART cannot hang the kernel.
            let mut spins: u32 = 0;
            #[expect(
                clippy::while_immutable_condition,
                reason = "volatile MMIO read sees hardware-driven changes the compiler cannot observe"
            )]
            while core::ptr::read_volatile(lsr) & LSR_THRE == 0 {
                spins += 1;
                if spins >= UART_TX_TIMEOUT_SPINS {
                    return;
                }
            }

            // Write byte
            core::ptr::write_volatile(thr, u32::from(byte));
        }
    }

    /// Write a string to the UART.
    pub(crate) fn write_str_raw(&self, s: &str) {
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
