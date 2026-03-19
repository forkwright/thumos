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
pub struct Device {
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
pub struct DeviceRegistry {
    devices: Vec<Device>,
}

impl DeviceRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            devices: Vec::new(),
        }
    }

    /// Register a device.
    pub fn register(&mut self, name: &str, base_addr: usize, irq: u32) {
        self.devices.push(Device {
            name: String::from(name),
            base_addr,
            irq,
            status: DeviceStatus::Registered,
        });
    }

    /// Find a device by name.
    pub fn find(&self, name: &str) -> Option<&Device> {
        self.devices.iter().find(|d| d.name == name)
    }

    /// Find a device by name (mutable).
    pub fn find_mut(&mut self, name: &str) -> Option<&mut Device> {
        self.devices.iter_mut().find(|d| d.name == name)
    }

    /// Mark a device as active.
    pub fn activate(&mut self, name: &str) {
        if let Some(dev) = self.find_mut(name) {
            dev.status = DeviceStatus::Active;
        }
    }

    /// Mark a device as powered off.
    pub fn power_off(&mut self, name: &str) {
        if let Some(dev) = self.find_mut(name) {
            dev.status = DeviceStatus::PoweredOff;
        }
    }

    /// List all devices.
    pub fn list(&self) -> &[Device] {
        &self.devices
    }

    /// Count devices by status.
    pub fn count_by_status(&self, status: DeviceStatus) -> usize {
        self.devices.iter().filter(|d| d.status == status).count()
    }

    /// Register all MT6739 AGM M7 devices with known addresses.
    /// Addresses from `docs/DRIVER-INTERFACES.md` and `docs/PROBE.md`.
    pub fn register_mt6739_devices(&mut self) {
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
