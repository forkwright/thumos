//! Device registry and driver framework.
//!
//! Each hardware peripheral is represented as a `Device` with a base
//! address, IRQ number, and driver-specific init function. The registry
//! holds all known devices and initializes them in dependency order.
//!
//! This is the framework that connects the kernel to UART, display,
//! keypad, touch, modem, WiFi, BT, GPS, FM, USB, and eMMC.

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

// ---------------------------------------------------------------------------
// MT6739 register base addresses
// ---------------------------------------------------------------------------

// NOTE: Hardcoded for Phase 03. Device-tree parsing replaces these in Phase 04+.
// Source: `docs/PROBE.md`, `docs/DRIVER-INTERFACES.md`, MT6739 device tree.
//
// WHY: central registry of all hardware base addresses. Individual driver
// modules have local copies — these are the canonical source of truth for
// cross-module reference and kinit boot validation.

/// UART0 (ttyMT0) MMIO base.
#[expect(dead_code, reason = "canonical reference; driver uses local const")]
pub(crate) const MT6739_UART0: usize = 0x1100_2000;

/// UART1 (ttyMT1) MMIO base.
#[expect(dead_code, reason = "canonical reference; driver uses local const")]
pub(crate) const MT6739_UART1: usize = 0x1100_3000;

/// MSDC0 eMMC controller MMIO base.
#[expect(dead_code, reason = "canonical reference; driver uses local const")]
pub(crate) const MT6739_MSDC0: usize = 0x1123_0000;

/// MUSB OTG USB controller MMIO base.
#[expect(dead_code, reason = "canonical reference; driver uses local const")]
pub(crate) const MT6739_MUSB: usize = 0x1121_0000;

/// MMSYS configuration base (display pipeline).
#[expect(dead_code, reason = "canonical reference; driver uses local const")]
pub(crate) const MT6739_MMSYS: usize = 0x1400_0000;

/// OVL0 (overlay engine) MMIO base.
#[expect(dead_code, reason = "canonical reference; driver uses local const")]
pub(crate) const MT6739_OVL0: usize = 0x1400_7000;

/// RDMA0 (read DMA engine) MMIO base.
#[expect(dead_code, reason = "canonical reference; driver uses local const")]
pub(crate) const MT6739_RDMA0: usize = 0x1400_8000;

/// DSI0 controller MMIO base.
#[expect(dead_code, reason = "canonical reference; driver uses local const")]
pub(crate) const MT6739_DSI0: usize = 0x1400_D000;

/// CLDMA AP-side register base (modem DMA).
#[expect(dead_code, reason = "canonical reference; driver uses local const")]
pub(crate) const MT6739_CLDMA_AP: usize = 0x200F_0000;

/// CCIF peer register base (modem mailbox).
#[expect(dead_code, reason = "canonical reference; driver uses local const")]
pub(crate) const MT6739_CCIF: usize = 0x2051_0000;

/// GIC distributor MMIO base.
#[expect(dead_code, reason = "canonical reference; driver uses local const")]
pub(crate) const MT6739_GIC_DIST: usize = 0x0C00_0000;

/// GIC CPU interface MMIO base.
#[expect(dead_code, reason = "canonical reference; driver uses local const")]
pub(crate) const MT6739_GIC_CPU: usize = 0x0C00_2000;

/// Keypad (KPD) controller MMIO base.
pub(crate) const MT6739_KPD: usize = 0x1001_0000;

/// WMT combo-chip (CONSYS) MMIO base.
#[expect(dead_code, reason = "canonical reference; driver uses local const")]
pub(crate) const MT6739_CONSYS: usize = 0x1800_0000;

/// WiFi MMIO base.
#[expect(dead_code, reason = "canonical reference; driver uses local const")]
pub(crate) const MT6739_WLAN: usize = 0x180F_0000;

/// Framebuffer physical address (set by LK bootloader).
#[expect(dead_code, reason = "canonical reference; kconfig has matching const")]
pub(crate) const MT6739_FB: usize = 0x77EE_0000;

/// KPD enable register offset.
pub(crate) const KPD_EN: usize = 0x00;

/// KPD debounce register offset.
pub(crate) const KPD_DEBOUNCE: usize = 0x18;

/// Device status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceStatus {
    /// Registered but not initialized.
    Registered,
    /// Successfully initialized and operational.
    Active,
    /// Initialization failed.
    Failed,
    /// Powered off by kill switch or software.
    PoweredOff,
}

/// A hardware device descriptor.
pub(crate) struct Device {
    /// Human-readable name (e.g., "uart0", "mtk-tpd", "ccci-modem").
    pub name: String,
    /// MMIO base address.
    pub base_addr: usize,
    /// Primary IRQ number (0 if polled).
    pub irq: u32,
    /// Current status.
    pub status: DeviceStatus,
}

/// Device registry.
pub(crate) struct DeviceRegistry {
    devices: Vec<Device>,
}

impl DeviceRegistry {
    /// Create an empty registry.
    pub(crate) fn new() -> Self {
        Self {
            devices: Vec::new(),
        }
    }

    /// Register a device.
    pub(crate) fn register(&mut self, name: &str, base_addr: usize, irq: u32) {
        self.devices.push(Device {
            name: String::from(name),
            base_addr,
            irq,
            status: DeviceStatus::Registered,
        });
    }

    /// Find a device by name.
    pub(crate) fn find(&self, name: &str) -> Option<&Device> {
        self.devices.iter().find(|d| d.name == name)
    }

    /// Find a device by name (mutable).
    pub(crate) fn find_mut(&mut self, name: &str) -> Option<&mut Device> {
        self.devices.iter_mut().find(|d| d.name == name)
    }

    /// Mark a device as active.
    ///
    /// Returns `true` if `name` matched a registered device and its status
    /// was updated, `false` if no such device is registered -- previously
    /// this was a silent no-op with no way for the caller to detect a
    /// typo'd or never-registered device name.
    pub(crate) fn activate(&mut self, name: &str) -> bool {
        match self.find_mut(name) {
            Some(dev) => {
                dev.status = DeviceStatus::Active;
                true
            }
            None => false,
        }
    }

    /// Mark a device as powered off.
    ///
    /// Returns `true` if `name` matched a registered device and its status
    /// was updated, `false` otherwise (see [`Self::activate`]).
    pub(crate) fn power_off(&mut self, name: &str) -> bool {
        match self.find_mut(name) {
            Some(dev) => {
                dev.status = DeviceStatus::PoweredOff;
                true
            }
            None => false,
        }
    }

    /// List all devices.
    pub(crate) fn list(&self) -> &[Device] {
        &self.devices
    }

    /// Count devices by status.
    pub(crate) fn count_by_status(&self, status: DeviceStatus) -> usize {
        self.devices.iter().filter(|d| d.status == status).count()
    }

    /// Register all MT6739 AGM M7 devices with known addresses.
    /// Addresses from `docs/DRIVER-INTERFACES.md` and `docs/PROBE.md`.
    pub(crate) fn register_mt6739_devices(&mut self) {
        // UART
        self.register("uart0", 0x1100_2000, 0);
        self.register("uart1", 0x1100_3000, 0);

        // Display
        self.register("disp-ovl0", 0x1400_7000, 0);
        self.register("disp-rdma0", 0x1400_8000, 0);
        self.register("gc9306-lcm", 0x1100_A000, 0);

        // Input
        self.register("mtk-kpd", 0x1001_0000, 0); // Keypad
        self.register("mtk-tpd", 0x0, 0); // Touch (I2C, addr TBD from teardown)

        // Modem
        self.register("ccci-cldma", 0x200F_0000, 0); // CLDMA AP base
        self.register("ccci-ccif", 0x2051_0000, 0); // CCIF peer

        // Connectivity
        self.register("wmt-consys", 0x1800_0000, 0); // WMT combo chip
        self.register("wlan0", 0x180F_0000, 0); // WiFi
        self.register("bt0", 0x0, 0); // BT (via WMT STP)
        self.register("gps0", 0x0, 0); // GPS (via WMT STP)
        self.register("fm0", 0x0, 0); // FM (via WMT)

        // USB
        self.register("musb-hdrc", 0x1120_0000, 0); // USB controller

        // Storage
        self.register("msdc0", 0x1123_0000, 0); // eMMC controller

        // GIC
        self.register("gic-dist", 0x0C00_0000, 0);
        self.register("gic-cpu", 0x0C00_2000, 0);
    }
}

impl Default for DeviceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn activate_returns_false_for_unknown_device() {
        let mut registry = DeviceRegistry::new();
        registry.register("uart0", 0x1100_2000, 0);

        assert!(
            !registry.activate("does-not-exist"),
            "activating an unregistered device name must report false, not silently no-op"
        );
        assert_eq!(
            registry.find("uart0").map(|d| d.status),
            Some(DeviceStatus::Registered)
        );
    }

    #[test]
    fn activate_returns_true_and_updates_status_for_known_device() {
        let mut registry = DeviceRegistry::new();
        registry.register("uart0", 0x1100_2000, 0);

        assert!(registry.activate("uart0"));
        assert_eq!(
            registry.find("uart0").map(|d| d.status),
            Some(DeviceStatus::Active)
        );
    }

    #[test]
    fn power_off_returns_false_for_unknown_device() {
        let mut registry = DeviceRegistry::new();
        registry.register("uart0", 0x1100_2000, 0);

        assert!(!registry.power_off("does-not-exist"));
    }

    #[test]
    fn power_off_returns_true_and_updates_status_for_known_device() {
        let mut registry = DeviceRegistry::new();
        registry.register("uart0", 0x1100_2000, 0);
        registry.activate("uart0");

        assert!(registry.power_off("uart0"));
        assert_eq!(
            registry.find("uart0").map(|d| d.status),
            Some(DeviceStatus::PoweredOff)
        );
    }

    #[test]
    fn list_returns_all_registered_devices() {
        let mut registry = DeviceRegistry::new();
        assert!(registry.list().is_empty());
        registry.register("uart0", 0x1100_2000, 0);
        registry.register("uart1", 0x1100_3000, 0);
        assert_eq!(registry.list().len(), 2);
    }

    #[test]
    fn count_by_status_reflects_registry_state() {
        let mut registry = DeviceRegistry::new();
        registry.register("uart0", 0x1100_2000, 0);
        registry.register("uart1", 0x1100_3000, 0);
        registry.activate("uart0");

        assert_eq!(registry.count_by_status(DeviceStatus::Registered), 1);
        assert_eq!(registry.count_by_status(DeviceStatus::Active), 1);
        assert_eq!(registry.count_by_status(DeviceStatus::PoweredOff), 0);
    }

    #[test]
    fn register_mt6739_devices_populates_expected_device_set() {
        let mut registry = DeviceRegistry::new();
        registry.register_mt6739_devices();

        assert_eq!(registry.list().len(), 18);
        assert!(registry.find("uart0").is_some());
        assert!(registry.find("ccci-cldma").is_some());
        assert!(registry.find("gic-cpu").is_some());
        assert_eq!(
            registry.count_by_status(DeviceStatus::Registered),
            18,
            "all devices start in the Registered state"
        );
    }
}
