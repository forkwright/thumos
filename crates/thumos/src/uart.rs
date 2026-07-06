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
//!   - bit 0: DR (receiver data ready) -- TODO(#459)[deliberate-prudent]: unverified against the
//!     MT6739 TRM, see `Uart::getc`
//!   - bit 5: THRE (transmit holding register empty)
//!   - bit 6: TEMT (transmitter empty)

use core::fmt;

/// Base address of UART0 on MT6739.
const UART0_BASE: usize = 0x1100_2000;

/// Transmit holding register OFFSET.
const THR: usize = 0x00;

/// Receive buffer register OFFSET.
/// NOTE: shares the THR offset, per the standard 16550-style register
/// layout this module's TX side already follows (RBR on read, THR on
/// write) -- see the module doc's register map.
const RBR: usize = 0x00;

/// Line status register OFFSET.
const LSR: usize = 0x14;

/// LSR bit: transmit holding register empty.
const LSR_THRE: u32 = 1 << 5;

/// LSR bit: receiver data ready.
/// TODO(#459)[deliberate-prudent]: unverified against the MT6739 TRM -- see `Uart::getc`.
const LSR_DR: u32 = 1 << 0;

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

    /// Non-blocking receive: returns the next byte if the RX FIFO has one
    /// ready, `None` otherwise.
    ///
    /// TODO(#459)[deliberate-prudent]: `LSR_DR` (bit 0, "data ready") is the standard 16550-style
    /// position and matches this module's existing THR/LSR offset layout,
    /// but has not been independently confirmed against the MT6739 TRM for
    /// this UART instance -- verify on real hardware before any boot-path
    /// behavior depends on RX timing (issue #372,
    /// `console::wait_for_physical_presence`).
    pub(crate) fn getc(&self) -> Option<u8> {
        // SAFETY: MMIO register access at known physical address. The UART
        // is already initialized by the bootloader.
        unsafe {
            let lsr = (self.base + LSR) as *const u32;
            if core::ptr::read_volatile(lsr) & LSR_DR == 0 {
                return None;
            }
            let rbr = (self.base + RBR) as *const u32;
            let raw = core::ptr::read_volatile(rbr) & 0xFF;
            u8::try_from(raw).ok()
        }
    }
}

impl fmt::Write for Uart {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.write_str_raw(s);
        Ok(())
    }
}
