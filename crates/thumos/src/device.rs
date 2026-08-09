//! Device registry and driver framework.
//!
//! Each hardware peripheral is represented as a `Device` with a base
//! address, IRQ number, and driver-specific init function. The registry
//! holds all known devices and initializes them in dependency order.
//!
//! This is the framework that connects the kernel to UART, display,
//! keypad, touch, modem, `WiFi`, BT, GPS, FM, USB, and eMMC.
//!
//! The DEVICE SET and every MMIO base address are board facts — they live
//! in `crate::board` (#534): `board::m7::register_devices` populates the
//! registry on the field board, `board::virt::register_devices` on the dev
//! board. This file is the board-neutral framework only.

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

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
}
