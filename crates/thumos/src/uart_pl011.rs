//! PL011 UART driver for QEMU `-machine virt` (bring-up feature `qemu`).
//!
//! Same module surface as the MT6739 driver in `uart.rs` (main.rs swaps this
//! in via `#[path]` under the qemu feature) so kernel call sites are
//! identical. PL011 register map (ARM DDI 0183):
//! - 0x00: DR (data; read = RX, write = TX)
//! - 0x18: FR (flags; bit 4 = RXFE rx-fifo-empty, bit 5 = TXFF tx-fifo-full)

use core::fmt;

use crate::kconfig::UART0_BASE;

/// Data register OFFSET.
const DR: usize = 0x00;

/// Flag register OFFSET.
const FR: usize = 0x18;

/// FR bit: receive FIFO empty.
const FR_RXFE: u32 = 1 << 4;

/// FR bit: transmit FIFO full.
const FR_TXFF: u32 = 1 << 5;

/// Bound on `putc`'s TX-ready poll, in iterations (not wall-clock time).
/// QEMU drains the PL011 FIFO promptly; the bound exists so a wedged device
/// model cannot hang the kernel (mirrors the MT6739 driver's contract).
const UART_TX_TIMEOUT_SPINS: u32 = 1_000_000;

/// UART driver for the QEMU virt PL011 console.
pub(crate) struct Uart {
    base: usize,
}

impl Uart {
    /// Create a UART driver for the QEMU virt debug console.
    pub(crate) fn new() -> Self {
        Self { base: UART0_BASE }
    }

    /// Write a single byte, waiting (bounded) for TX FIFO space.
    pub(crate) fn putc(&self, byte: u8) {
        // SAFETY: DR/FR are PL011 MMIO registers at UART0_BASE on the QEMU
        // virt board; volatile access is required for hardware registers.
        unsafe {
            let fr = (self.base + FR) as *const u32;
            let dr = (self.base + DR) as *mut u32;

            let mut spins: u32 = 0;
            #[expect(
                clippy::while_immutable_condition,
                reason = "volatile MMIO read sees hardware-driven changes the compiler cannot observe"
            )]
            while core::ptr::read_volatile(fr) & FR_TXFF != 0 {
                spins += 1;
                if spins >= UART_TX_TIMEOUT_SPINS {
                    return;
                }
            }

            core::ptr::write_volatile(dr, u32::from(byte));
        }
    }

    /// Write a string to the UART.
    pub(crate) fn write_str_raw(&self, s: &str) {
        for byte in s.bytes() {
            self.putc(byte);
        }
    }

    /// Non-blocking receive: returns the next byte if the RX FIFO has one
    /// ready, `None` otherwise. Surface parity with `uart.rs::getc`.
    pub(crate) fn getc(&self) -> Option<u8> {
        // SAFETY: DR/FR are PL011 MMIO registers at UART0_BASE on the QEMU
        // virt board; volatile access is required for hardware registers.
        unsafe {
            let fr = (self.base + FR) as *const u32;
            if core::ptr::read_volatile(fr) & FR_RXFE != 0 {
                return None;
            }
            let dr = (self.base + DR) as *const u32;
            let raw = core::ptr::read_volatile(dr) & 0xFF;
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
