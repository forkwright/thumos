//! The QEMU `-machine virt` dev board (armv7a) — the board every CI witness
//! boots on (#534). Only hardware the virt machine actually HAS is defined
//! here: a PL011 UART, a GICv2, and DRAM. There is no eMMC, no display
//! pipeline, no combo chip, no keypad — those consts exist only in
//! `board::m7`, and code referencing them is selected out of virt builds.

use crate::device::DeviceRegistry;

/// Board name for the boot banner and docs.
pub(crate) const BOARD_NAME: &str = "QEMU virt (armv7a)";

/// UART0 MMIO base (PL011; the register MAP differs from the M7's MTK 8250,
/// not just the base — main.rs swaps the driver file under this board).
pub(crate) const UART0_BASE: usize = 0x0900_0000;

/// GIC distributor MMIO base (virt, GICv2).
pub(crate) const GICD_BASE: usize = 0x0800_0000;

/// GIC CPU interface MMIO base (virt, GICv2).
pub(crate) const GICC_BASE: usize = 0x0801_0000;

/// Register the devices the virt machine actually models (#534). Honestly
/// minimal: the PL011 console UART and the GICv2 — no eMMC, display, combo
/// chip, keypad, USB, or modem entries, because qemu provides none.
pub(crate) fn register_devices(registry: &mut DeviceRegistry) {
    registry.register("uart0", UART0_BASE, 0);
    registry.register("gic-dist", GICD_BASE, 0);
    registry.register("gic-cpu", GICC_BASE, 0);
}
