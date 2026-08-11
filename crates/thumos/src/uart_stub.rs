//! Host-test stub for the ARM-only `uart` module (MT6739 ttyMT0 MMIO).
//!
//! The real `uart` module writes to the UART0 transmit-holding register at a
//! fixed MMIO address, which does not exist on the host test target. Under
//! test this stub swallows all output, exposing only the API that
//! host-testable modules (syscall's stdout/debug paths) reference.
//!
//! WHY(pattern): a gated-out hardware dependency is made test-visible by a
//! parallel `#[cfg(test)] #[path = "..._stub.rs"] mod x;` binding in main.rs.

use core::fmt;

/// Host-test UART: discards all output (no MMIO on the host target).
pub(crate) struct Uart;

impl Uart {
    /// Create a stub UART handle.
    pub(crate) fn new() -> Self {
        Self
    }

    /// Discard a single byte.
    // WHY: this stub's whole purpose is API parity with uart.rs's real
    // `putc(&self, ..)`/`getc(&self)` (both genuine MMIO-register accesses
    // tied to the instance), via the parallel `#[cfg(test)] #[path = ..]`
    // binding described above -- callers like console.rs/syscall.rs (out of
    // scope here) call `.putc(..)`/`.getc()` on whichever binding is active.
    // Dropping &self would break that parity.
    pub(crate) fn putc(&self, _byte: u8) {}

    /// Host-test RX stub: no real UART, so no bytes are ever available.
    pub(crate) fn getc(&self) -> Option<u8> {
        None
    }
}

impl fmt::Write for Uart {
    fn write_str(&mut self, _s: &str) -> fmt::Result {
        Ok(())
    }
}
