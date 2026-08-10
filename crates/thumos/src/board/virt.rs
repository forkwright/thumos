//! The QEMU `-machine virt` dev board (armv7a) — the board every CI witness
//! boots on (#534). Only hardware the virt machine actually HAS is defined
//! here: the console PL011 UART (always present), a second PL011 the
//! machine models only under ARM Security Extensions (#544's on-device
//! transport), a `GICv2`, and DRAM. There is no eMMC, no display pipeline,
//! no combo chip, no keypad — those consts exist only in `board::m7`, and
//! code referencing them is selected out of virt builds.

use crate::device::DeviceRegistry;

/// Board name for the boot banner and docs.
pub(crate) const BOARD_NAME: &str = "QEMU virt (armv7a)";

/// UART0 MMIO base (PL011; the register MAP differs from the M7's MTK 8250,
/// not just the base — main.rs swaps the driver file under this board).
pub(crate) const UART0_BASE: usize = 0x0900_0000;

/// UART1 MMIO base: the virt machine's SECOND PL011, the "secure" UART
/// QEMU's `hw/arm/virt.c` instantiates only under ARM Security Extensions
/// (`-machine virt,secure=on`) — offset 0x40000 past UART0, verified via
/// `-machine virt,secure=on,dumpdtb=...` (`pl011@9040000` alongside the
/// primary `pl011@9000000`; unchanged GIC addresses). Absent under the
/// default `secure=off` boot every OTHER witness uses (#544 on-device
/// leg): only `scripts/qemu-runner.sh`'s opt-in `THUMOS_QEMU_METAXU_PORT`
/// path enables `secure=on` + a second `-serial`, so touching this base
/// outside that path faults (unassigned MMIO). See `metaxu_bridge.rs`.
pub(crate) const UART1_BASE: usize = 0x0904_0000;

/// GIC distributor MMIO base (virt, `GICv2`).
pub(crate) const GICD_BASE: usize = 0x0800_0000;

/// GIC CPU interface MMIO base (virt, `GICv2`).
pub(crate) const GICC_BASE: usize = 0x0801_0000;

/// Register the devices the virt machine actually models (#534). Honestly
/// minimal: the two PL011 UARTs and the `GICv2` — no eMMC, display, combo
/// chip, keypad, USB, or modem entries, because qemu provides none. `uart1`
/// is registered unconditionally (a board FACT, like `board::m7`'s own
/// `uart1`), even though it MMIO-faults unless the boot used
/// `-machine virt,secure=on` — registration is bookkeeping, not a probe.
pub(crate) fn register_devices(registry: &mut DeviceRegistry) {
    registry.register("uart0", UART0_BASE, 0);
    registry.register("uart1", UART1_BASE, 0);
    registry.register("gic-dist", GICD_BASE, 0);
    registry.register("gic-cpu", GICC_BASE, 0);
}
