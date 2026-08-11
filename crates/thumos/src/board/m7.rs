//! The AGM M7 field board (MT6739 `SoC`) — every MT6739-specific fact in the
//! kernel lives HERE and nowhere else (#534's standing invariant, enforced
//! by `scripts/check-board-seam.sh`).
//!
//! Sources: `docs/PROBE.md`, `docs/DRIVER-INTERFACES.md`, the MT6739 device
//! tree, and the GPT dump of the AGM M7 eMMC. These are STATIC config
//! structs by design — two real boards want no device-tree parser (#534
//! explicitly retires the old "Phase 04+ DT" ambition).
//!
//! WHY `cfg_attr(not(test))` on some expects (#528 shape): this module
//! compiles on the host test target, where this file's own tests reference
//! the consts — a blanket `expect(dead_code)` would be UNFULFILLED there,
//! while on armv7a a const with no runtime consumer is genuinely dead.

use crate::device::DeviceRegistry;

/// Board name for the boot banner and docs.
pub(crate) const BOARD_NAME: &str = "AGM M7 (MT6739)";

// ---------------------------------------------------------------------------
// Console + interrupt controller
// ---------------------------------------------------------------------------

/// UART0 (ttyMT0) MMIO base, MTK 8250-style register map.
pub(crate) const UART0_BASE: usize = 0x1100_2000;

/// UART1 (ttyMT1) MMIO base.
pub(crate) const UART1_BASE: usize = 0x1100_3000;

/// GIC distributor MMIO base (MT6739 device tree, intc node).
pub(crate) const GICD_BASE: usize = 0x0C00_0000;

/// GIC CPU interface MMIO base (MT6739).
pub(crate) const GICC_BASE: usize = 0x0C00_2000;

// ---------------------------------------------------------------------------
// Storage
// ---------------------------------------------------------------------------

/// MSDC0 eMMC controller MMIO base.
pub(crate) const MSDC0_BASE: usize = 0x1123_0000;

/// Start sector of the LFS partition on eMMC.
/// WHY: the boot, recovery, system, vendor partitions occupy the first
/// ~2.6 GB. LFS uses the userdata region starting at sector 0x50C000
/// (~2.6 GB offset). Value from the GPT dump of the MT6739 eMMC
/// (printgpt: userdata partition).
pub(crate) const LFS_PARTITION_START: u64 = 0x0050_C000;

/// Size of the LFS partition in sectors.
/// WHY: ~3 GB of the 8 GB eMMC is available for user data. Rounded down
/// from the actual userdata partition length (0x97BFDF sectors) to a clean
/// segment-aligned boundary.
pub(crate) const LFS_PARTITION_SIZE: u64 = 0x0060_0000;

/// Sectors reserved at the userdata partition head for the plaintext
/// secrets preamble (#449). The encrypted LFS payload starts this many
/// sectors past `LFS_PARTITION_START` (#446); a pre-#446 unprovisioned
/// image mounts plain AT the head (the dev/transition path).
pub(crate) const LFS_PREAMBLE_SECTORS: u64 = 1;

// ---------------------------------------------------------------------------
// USB
// ---------------------------------------------------------------------------

/// MUSB OTG USB controller MMIO base, from the `MediaTek` MT6739 vendor
/// device tree's `usb0@11200000` node: `compatible = "mediatek,mt6739-usb20"`,
/// `reg = <0 0x11200000 0 0x10000>, <0 0x11CC0000 0 0x10000>`. Two
/// independently hosted copies agree byte-for-byte
/// (github.com/fukehan/kernel-4.4,
/// github.com/iscle/OrangePi_4G-IOT_Android_8.1_BSP), and `0x11210000`
/// appears nowhere in either 2499-line tree.
///
/// WHY this replaced `0x1121_0000` (#676): that address is real in this `SoC`
/// family but belongs to a different device. Mainline
/// `arch/arm/boot/dts/mediatek/mt2701.dtsi` splits the pair explicitly --
/// `usb@11200000` is the `mtk-musb` controller, `t-phy@11210000` is the
/// T-PHY, whose registers are PHY tuning and carry no FADDR/POWER/INTRTX or
/// EP CSRs. MT6739 breaks the family's controller+0x10000 pattern by moving
/// its second region to `0x11CC0000`, so following that pattern lands on
/// nothing. `usb.rs` drives MUSB-core operations, so it needs the controller.
///
/// WARNING: source-resolved, NOT hardware-confirmed. `usb::init_controller`'s
/// `POWER` readback (`UsbInitError::NotResponding`) is the falsifier, and it
/// reads a register inside the byte range `usb.rs` gets right -- test this
/// base alone before concluding anything about #724's register-map
/// divergence, or a failure downstream of `POWER` gets misattributed back
/// to this value.
pub(crate) const MUSB_BASE: usize = 0x1120_0000;

/// MUSB OTG controller GIC interrupt (raw GIC INTID, the form
/// `gic::enable_irq` and the IRQ-dispatch comparison in `exceptions.rs`
/// both consume -- SPI number + 32, same convention as `timer::TIMER_IRQ`).
///
/// `None` -- NOT hardware-confirmed (#666, tracked to closure by #676).
/// Every `MediaTek` MT6739 vendor Android kernel DTS this driver's own
/// history cites was re-checked while wiring this constant, and none of it
/// resolves cleanly: two independently hosted copies of `MediaTek`'s mt6739
/// vendor tree
/// (github.com/fukehan/kernel-4.4, github.com/iscle/OrangePi_4G-IOT_Android_8.1_BSP)
/// carry a `usb0@11200000` node -- `compatible = "mediatek,mt6739-usb20"`,
/// `interrupts = <GIC_SPI 73 IRQ_TYPE_LEVEL_LOW>` (INTID 32+73 = 105) -- but
/// `MUSB_BASE` above now carries that same node's `reg` base, so the address
/// conflict this comment was written against is resolved by source (#676).
/// What is still missing is a hardware artifact: nothing confirms INTID 105
/// on real AGM M7 silicon, and a vendor DT is the same evidence class that
/// carried the wrong base for two releases -- right about the base, unproven
/// about this. The asymmetry is deliberate: a wrong base fails loudly and
/// detectably at the `POWER` readback, while a wrongly-enabled IRQ wedges the
/// interrupt path in ways that are far harder to attribute. Wiring a real
/// GIC INTID into a live `enable_irq` call on that contested foundation
/// would be a fabricated fact wearing a hardware-verified constant's
/// clothes, not an engineering shortcut -- so this stays `None` (a
/// no-op at the `exceptions::init()` call site) until #676 closes the gap
/// by hardware probe or a source that resolves the base-address conflict.
/// Flipping this to `Some(105)` (the one researched candidate, unverified)
/// is then the ENTIRE remaining step -- see `exceptions::init()` and
/// `exceptions::irq_handler_body()`, both already written against this
/// constant.
/// TODO(#676)[deliberate-prudent]: confirm the AGM M7 MUSB GIC INTID (candidate:
/// 105) against real hardware or a source that resolves the `MUSB_BASE`
/// 0x1121_0000-vs-0x1120_0000 conflict noted above, then set this to Some(n).
pub(crate) const MUSB_IRQ: Option<u32> = None;

// ---------------------------------------------------------------------------
// Display pipeline
// ---------------------------------------------------------------------------

/// MMSYS configuration base (display pipeline).
pub(crate) const MMSYS_BASE: usize = 0x1400_0000;

/// Display mutex controller MMIO base.
pub(crate) const DISP_MUTEX_BASE: usize = 0x1400_1000;

/// OVL0 (overlay engine) MMIO base.
pub(crate) const OVL0_BASE: usize = 0x1400_7000;

/// RDMA0 (read DMA engine) MMIO base.
pub(crate) const RDMA0_BASE: usize = 0x1400_8000;

/// DSI0 controller MMIO base.
pub(crate) const DSI0_BASE: usize = 0x1400_D000;

/// DSI0 command FIFO register (DSI0 + 0x200), used by the DCS power path.
pub(crate) const DSI0_CMD_FIFO: usize = DSI0_BASE + 0x200;

/// GC9306 LCM (panel) MMIO base.
pub(crate) const GC9306_LCM_BASE: usize = 0x1100_A000;

/// Display framebuffer physical base (set by the LK bootloader).
pub(crate) const FB_BASE: usize = 0x77EE_0000;

// ---------------------------------------------------------------------------
// Input
// ---------------------------------------------------------------------------

/// Keypad (KPD) controller MMIO base.
pub(crate) const KPD_BASE: usize = 0x1001_0000;

/// KPD enable register offset.
pub(crate) const KPD_EN: usize = 0x00;

/// KPD debounce register offset.
pub(crate) const KPD_DEBOUNCE: usize = 0x18;

/// GPIO controller MMIO base (`MT67xx` standard bank base).
///
/// NOTE: standard `MT67xx` base — verify against the MT6739 TRM GPIO section.
/// Mirrors haphe's `GPIO_BASE` (crates/haphe/src/gpio.rs); the #446 boot
/// keypad reader scans the matrix through these registers because the KPD
/// hardware block has no verified read-out register map.
pub(crate) const GPIO_BASE: usize = 0x1000_5000;

/// GPIO direction register bank offset (0 = input, 1 = output).
pub(crate) const GPIO_DIR_BASE: usize = 0x000;

/// GPIO data-out register bank offset.
pub(crate) const GPIO_DOUT_BASE: usize = 0x100;

/// GPIO data-in register bank offset (reads current pin level).
pub(crate) const GPIO_DIN_BASE: usize = 0x200;

/// GPIO pull-enable register bank offset.
pub(crate) const GPIO_PULLEN_BASE: usize = 0x300;

/// GPIO pull-select register bank offset (0 = pull-down, 1 = pull-up).
pub(crate) const GPIO_PULLSEL_BASE: usize = 0x400;

/// Keypad matrix row GPIO pins (driven low in turn during a scan).
///
/// NOTE: placeholder values pending AGM M7 schematic verification —
/// mirrors haphe's `ROW_PINS`.
pub(crate) const KEYPAD_ROW_PINS: [u8; 4] = [40, 41, 42, 43];

/// Keypad matrix column GPIO pins (inputs with pull-up; a pressed key
/// shorts the driven-low row to the column, reading low).
///
/// NOTE: placeholder values pending AGM M7 schematic verification —
/// mirrors haphe's `COL_PINS`.
pub(crate) const KEYPAD_COL_PINS: [u8; 3] = [44, 45, 46];

// ---------------------------------------------------------------------------
// Combo chip (WiFi / BT / GPS / FM over the WMT transport)
// ---------------------------------------------------------------------------

/// WMT combo-chip (CONSYS) MMIO base.
pub(crate) const CONSYS_BASE: usize = 0x1800_0000;

/// `WiFi` (WLAN) MMIO base.
pub(crate) const WLAN_BASE: usize = 0x180F_0000;

// ---------------------------------------------------------------------------
// Power + watchdog
// ---------------------------------------------------------------------------

/// Watchdog (WDT) controller MMIO base.
pub(crate) const WDT_BASE: usize = 0x1000_7000;

/// ARMPLL control register 1 (DVFS clock source switch).
pub(crate) const ARMPLL_CON1: usize = 0x1000_C104;

/// MCDI (multi-core deep-idle) controller MMIO base.
pub(crate) const MCDI_BASE: usize = 0x1000_DC00;

/// MCDI per-core enable register (MCDI + 0x04).
pub(crate) const MCDI_CORE_EN: usize = MCDI_BASE + 0x04;

/// PMIC wrapper (PWRAP, MT6357 access path) MMIO base.
pub(crate) const PWRAP_BASE: usize = 0x1000_D000;

// ---------------------------------------------------------------------------
// Device registry population
// ---------------------------------------------------------------------------

/// Register every M7 device with a known address (#534: moved here from the
/// board-neutral registry framework — the device SET is a board fact).
/// Addresses from `docs/DRIVER-INTERFACES.md` and `docs/PROBE.md`.
/// IRQs are all 0 today: every driver polls; no IRQ table exists yet.
pub(crate) fn register_devices(registry: &mut DeviceRegistry) {
    // Console UARTs
    registry.register("uart0", UART0_BASE, 0);
    registry.register("uart1", UART1_BASE, 0);

    // Display
    registry.register("disp-ovl0", OVL0_BASE, 0);
    registry.register("disp-rdma0", RDMA0_BASE, 0);
    registry.register("gc9306-lcm", GC9306_LCM_BASE, 0);

    // Input
    registry.register("mtk-kpd", KPD_BASE, 0); // Keypad
    registry.register("gpio", GPIO_BASE, 0); // GPIO bank (boot keypad matrix scan)
    registry.register("mtk-tpd", 0x0, 0); // Touch (I2C, addr TBD from teardown)

    // Modem (ccci-family addresses; the ccci seam owns those drivers)
    registry.register("ccci-cldma", 0x200F_0000, 0); // CLDMA AP base
    registry.register("ccci-ccif", 0x2051_0000, 0); // CCIF peer

    // Connectivity
    registry.register("wmt-consys", CONSYS_BASE, 0); // WMT combo chip
    registry.register("wlan0", WLAN_BASE, 0); // WiFi
    registry.register("bt0", 0x0, 0); // BT (via WMT STP)
    registry.register("gps0", 0x0, 0); // GPS (via WMT STP)
    registry.register("fm0", 0x0, 0); // FM (via WMT)

    // USB
    registry.register("musb-hdrc", MUSB_BASE, 0); // USB controller

    // Storage
    registry.register("msdc0", MSDC0_BASE, 0); // eMMC controller

    // GIC
    registry.register("gic-dist", GICD_BASE, 0);
    registry.register("gic-cpu", GICC_BASE, 0);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// The registered device set must pin to the module's canonical consts —
    /// this replaces `kinit_plan`'s pre-#534 address test, which pinned the
    /// consts the OLD device.rs carried (including the GIC aliases that
    /// silently resolved to QEMU addresses under --features qemu).
    #[test]
    fn register_devices_pins_canonical_addresses() {
        let mut registry = DeviceRegistry::new();
        register_devices(&mut registry);

        assert_eq!(registry.list().len(), 19);
        let cases: &[(&str, usize)] = &[
            ("uart0", UART0_BASE),
            ("uart1", UART1_BASE),
            ("disp-ovl0", OVL0_BASE),
            ("disp-rdma0", RDMA0_BASE),
            ("gc9306-lcm", GC9306_LCM_BASE),
            ("mtk-kpd", KPD_BASE),
            ("gpio", GPIO_BASE),
            ("wmt-consys", CONSYS_BASE),
            ("wlan0", WLAN_BASE),
            ("musb-hdrc", MUSB_BASE),
            ("msdc0", MSDC0_BASE),
            ("gic-dist", GICD_BASE),
            ("gic-cpu", GICC_BASE),
        ];
        for (name, want) in cases {
            let dev = registry
                .find(name)
                .unwrap_or_else(|| panic!("{name} registered"));
            assert_eq!(&dev.base_addr, want, "{name} base address drifted");
        }
        assert_eq!(
            registry.count_by_status(crate::device::DeviceStatus::Registered),
            19,
            "all devices start in the Registered state"
        );
    }

    #[test]
    fn derived_register_addresses_are_self_consistent() {
        assert_eq!(DSI0_CMD_FIFO, 0x1400_D200);
        assert_eq!(MCDI_CORE_EN, 0x1000_DC04);
        assert!(!BOARD_NAME.is_empty());
    }

    /// WHY (#666): `MUSB_IRQ` is `None` until hardware-confirmed (see its doc
    /// comment). Guards the day it flips to `Some(n)` -- n must be a real
    /// SPI (INTID >= 32; 0..31 are SGI/PPI, never a peripheral line), so a
    /// typo during the eventual hardware-confirmed edit cannot silently
    /// enable a reserved software/private interrupt line instead of a real
    /// peripheral one.
    #[test]
    fn musb_irq_is_unset_or_a_valid_spi() {
        match MUSB_IRQ {
            None => {}
            Some(n) => assert!(
                n >= 32,
                "MUSB_IRQ must be a real SPI (INTID >= 32, not an SGI/PPI slot), got {n}"
            ),
        }
    }
}
