//! ARM GIC (Generic Interrupt Controller) driver for MT6739.
//!
//! The MT6739 uses a GICv2 with:
//! - Distributor (GICD) at 0x0C000000
//! - CPU Interface (GICC) at 0x0C002000
//!
//! These addresses come FROM the MT6739 device tree (intc node).
//! The GIC handles all hardware interrupts and routes them to cores.

/// GIC Distributor base address.
const GICD_BASE: usize = 0x0C00_0000;

/// GIC CPU Interface base address.
const GICC_BASE: usize = 0x0C00_2000;

// Distributor registers
mod gicd {
    use super::GICD_BASE;

    /// Distributor control.
    pub(crate) const CTLR: usize = GICD_BASE;
    /// Interrupt controller type.
    pub(crate) const TYPER: usize = GICD_BASE + 0x004;
    /// Interrupt SET-enable (32 IRQs per register).
    pub(crate) const fn isenabler(n: usize) -> usize {
        GICD_BASE + 0x100 + n * 4
    }
    /// Interrupt clear-enable.
    pub(crate) const fn icenabler(n: usize) -> usize {
        GICD_BASE + 0x180 + n * 4
    }
    /// Interrupt clear-pending.
    pub(crate) const fn icpendr(n: usize) -> usize {
        GICD_BASE + 0x280 + n * 4
    }
    /// Interrupt priority (4 IRQs per register, 8 bits each).
    pub(crate) const fn ipriorityr(n: usize) -> usize {
        GICD_BASE + 0x400 + n * 4
    }
    /// Interrupt processor target (4 IRQs per register, 8 bits each).
    pub(crate) const fn itargetsr(n: usize) -> usize {
        GICD_BASE + 0x800 + n * 4
    }
    /// Interrupt configuration (16 IRQs per register, 2 bits each).
    pub(crate) const fn icfgr(n: usize) -> usize {
        GICD_BASE + 0xC00 + n * 4
    }
}

// CPU Interface registers
mod gicc {
    use super::GICC_BASE;

    /// CPU interface control.
    pub(crate) const CTLR: usize = GICC_BASE;
    /// Interrupt priority mask.
    pub(crate) const PMR: usize = GICC_BASE + 0x004;
    /// Interrupt acknowledge.
    pub(crate) const IAR: usize = GICC_BASE + 0x00C;
    /// End of interrupt.
    pub(crate) const EOIR: usize = GICC_BASE + 0x010;
}

use crate::mmio;

/// Maximum number of IRQs supported.
const MAX_IRQS: usize = 256;

/// Initialize the GIC distributor and CPU interface.
///
/// Enables the GIC, sets all IRQ priorities to the same level,
/// targets all IRQs to core 0, and enables the CPU interface.
///
/// # Safety
///
/// Must be called once during early boot with MMU enabled
/// (the GIC registers must be mapped).
pub unsafe fn init() {
    // SAFETY: GIC distributor/CPU interface register at known MMIO address.
    unsafe {
        // Disable distributor during config
        mmio::write32(gicd::CTLR, 0);

        // Read number of interrupt lines
        let typer = mmio::read32(gicd::TYPER);
        let num_irqs = ((typer & 0x1F) + 1) * 32;
        let num_irqs = if num_irqs > u32::try_from(MAX_IRQS).unwrap_or_default() {
            u32::try_from(MAX_IRQS).unwrap_or_default()
        } else {
            num_irqs
        };

        // Disable all interrupts
        let num_regs = (num_irqs + 31) / 32;
        for i in 0..usize::try_from(num_regs).unwrap_or_default() {
            mmio::write32(gicd::icenabler(i), 0xFFFF_FFFF);
            mmio::write32(gicd::icpendr(i), 0xFFFF_FFFF);
        }

        // Set all priorities to 0xA0 (medium)
        let num_prio_regs = (num_irqs + 3) / 4;
        for i in 0..usize::try_from(num_prio_regs).unwrap_or_default() {
            mmio::write32(gicd::ipriorityr(i), 0xA0A0_A0A0);
        }

        // Target all SPIs to core 0
        let num_target_regs = (num_irqs + 3) / 4;
        for i in 8..usize::try_from(num_target_regs).unwrap_or_default() {
            // NOTE: skip first 8 regs (SGI/PPI, read-only targets)
            mmio::write32(gicd::itargetsr(i), 0x0101_0101);
        }

        // Enable distributor
        mmio::write32(gicd::CTLR, 1);

        // Configure CPU interface
        mmio::write32(gicc::PMR, 0xFF); // Accept all priority levels
        mmio::write32(gicc::CTLR, 1); // Enable CPU interface
    }
}

/// Enable a specific IRQ number.
///
/// # Safety
///
/// The IRQ handler for this interrupt must be installed before enabling.
pub unsafe fn enable_irq(irq: u32) {
    let reg = (irq / 32) as usize;
    let bit = irq % 32;
    // SAFETY: GIC distributor/CPU interface register at known MMIO address.
    unsafe {
        mmio::set_bits(gicd::isenabler(reg), 1 << bit);
    }
}

/// Disable a specific IRQ number.
pub(crate) fn disable_irq(irq: u32) {
    let reg = (irq / 32) as usize;
    let bit = irq % 32;
    // SAFETY: GIC distributor/CPU interface register at known MMIO address.
    unsafe {
        mmio::write32(gicd::icenabler(reg), 1 << bit);
    }
}

/// Acknowledge an interrupt (read IAR).
/// Returns the interrupt ID (10 bits). ID 1023 = spurious.
pub(crate) fn acknowledge() -> u32 {
    // SAFETY: GIC distributor/CPU interface register at known MMIO address.
    unsafe { mmio::read32(gicc::IAR) & 0x3FF }
}

/// Signal end of interrupt handling.
pub(crate) fn end_of_interrupt(irq: u32) {
    // SAFETY: GIC distributor/CPU interface register at known MMIO address.
    unsafe {
        mmio::write32(gicc::EOIR, irq);
    }
}

/// Spurious interrupt ID.
pub(crate) const SPURIOUS: u32 = 1023;
