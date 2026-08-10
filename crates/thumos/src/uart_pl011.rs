//! PL011 UART driver for QEMU `-machine virt` (bring-up feature `qemu`).
//!
//! Same module surface as the MT6739 driver in `uart.rs` (main.rs swaps this
//! in via `#[path]` under the qemu feature) so kernel call sites are
//! identical. PL011 register map (ARM DDI 0183):
//! - 0x00: DR (data; read = RX, write = TX)
//! - 0x18: FR (flags; bit 4 = RXFE rx-fifo-empty, bit 5 = TXFF tx-fifo-full)

use core::fmt;

use crate::board::UART0_BASE;

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

/// Run `f` with IRQs masked, restoring the caller's previous mask state.
///
/// WHY: kernel thread-mode prints (the kinit handoff, the kardia service
/// loop) run with IRQs live — a timer IRQ mid-print preempts into userspace,
/// whose own writes (already atomic: SVC entry sets CPSR.I) then split the
/// kernel's line. The 2026-08-05 boot witness caught exactly that:
/// `kardia: modem ready state=` and its value landed on different lines.
/// Masking for the byte loop keeps a kernel print contiguous without
/// changing userspace (SVC/IRQ paths are atomic by hardware already).
/// Nested calls are safe: the prior I-bit is restored, never force-enabled.
#[inline]
fn irqs_masked<R>(f: impl FnOnce() -> R) -> R {
    let saved: u32;
    // SAFETY: privileged CPSR read; always available at PL1 on armv7a.
    unsafe {
        core::arch::asm!("mrs {}, cpsr", out(reg) saved, options(nomem, nostack, preserves_flags));
    };
    // SAFETY: mask IRQs for the critical section.
    unsafe { core::arch::asm!("cpsid i", options(nomem, nostack, preserves_flags)) };
    let r = f();
    if saved & 0x80 == 0 {
        // SAFETY: the caller had IRQs enabled; restore that state.
        unsafe { core::arch::asm!("cpsie i", options(nomem, nostack, preserves_flags)) };
    }
    r
}

impl Uart {
    /// Create a UART driver for the QEMU virt debug console.
    pub(crate) fn new() -> Self {
        Self { base: UART0_BASE }
    }

    /// Create a UART driver for an arbitrary PL011 instance base -- the
    /// `metaxu-probe` bridge (#544) uses this for `board::UART1_BASE`
    /// rather than adding a second hardcoded constructor per instance.
    #[cfg(feature = "metaxu-probe")]
    pub(crate) const fn at(base: usize) -> Self {
        Self { base }
    }

    /// Write a single byte, waiting (bounded) for TX FIFO space.
    pub(crate) fn putc(&self, byte: u8) {
        // SAFETY: DR/FR are PL011 MMIO registers at UART0_BASE on the QEMU
        // virt board; volatile access is required for hardware registers.
        unsafe {
            let fr = (self.base + FR) as *const u32;
            let dr = (self.base + DR) as *mut u32;

            let mut spins: u32 = 0;
            // WHY: volatile MMIO read sees hardware-driven changes the
            // compiler cannot observe -- clippy does not flag
            // while_immutable_condition here because the condition calls
            // a function (read_volatile), which it treats as
            // potentially side-effecting.
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
        irqs_masked(|| {
            for byte in s.bytes() {
                self.putc(byte);
            }
        });
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

impl Uart {
    /// Write a string to the console as a boot log line.
    ///
    /// INVARIANT: `write_str_raw` polls a TX register and cannot report
    /// failure, so `<Uart as fmt::Write>::write_str` returns `Ok` for every
    /// input and the boot path has no console error to handle. This is the
    /// single entry point that states that, so call sites neither discard a
    /// `Result` that is always `Ok` nor imply an error path exists. Mirrors
    /// `uart.rs::Uart::log` (same module surface, per this file's header).
    pub(crate) fn log(&self, s: &str) {
        self.write_str_raw(s);
    }

    /// Formatted counterpart to [`Uart::log`]. Prefer the `boot_log!` macro.
    pub(crate) fn log_fmt(&mut self, args: fmt::Arguments<'_>) {
        // INVARIANT: per `Uart::log`, this type's `write_str` never returns
        // `Err`, so `write_fmt` can only surface an error raised inside a
        // `Display`/`Debug` impl in `args`. The boot path formats integers
        // and driver error enums, none of which fail.
        let _ = fmt::Write::write_fmt(self, args); // kanon:ignore RUST/no-silent-result-swallow
    }
}

/// Write a formatted boot log line to a [`Uart`].
///
/// WHY: the boot path is the kernel's only progress channel and its writes
/// cannot fail, so formatted output routes through [`Uart::log_fmt`] rather
/// than `write!` plus a `Result` the call site must discard. Mirrors
/// `uart.rs::boot_log!` (same module surface, per this file's header) --
/// `mod uart` path-swaps to this file under the `qemu` feature, so
/// `crate::uart::boot_log` must resolve here too.
macro_rules! boot_log {
    ($uart:expr, $($arg:tt)*) => {
        $uart.log_fmt(format_args!($($arg)*))
    };
}

pub(crate) use boot_log;
