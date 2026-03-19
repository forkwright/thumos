//! Bluetooth device tracking: deduplication by address and stale-device detection.

use std::collections::HashMap;

use jiff::{SignedDuration, Timestamp};

use crate::hci::BdAddr;

// ── Types ──────────────────────────────────────────────────────────────────────

/// A Bluetooth device observed during scanning or inquiry.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct BluetoothDevice {
    /// Bluetooth device address.
    pub address: BdAddr,
    /// Friendly device name, if received via name request or EIR.
    pub name: Option<String>,
    /// Most-recently observed RSSI in dBm.
    pub rssi: i8,
    /// 24-bit Class of Device (classic BT only; `0` for BLE).
    pub class_of_device: u32,
    /// Wall-clock time of the last observation.
    pub last_seen: Timestamp,
    /// Total number of times this device has been observed.
    pub seen_count: u32,
}

/// A deduplicated collection of discovered Bluetooth devices, keyed by address.
#[derive(Debug, Default)]
pub struct DeviceList {
    devices: HashMap<BdAddr, BluetoothDevice>,
}

// ── BluetoothDevice impl ───────────────────────────────────────────────────────

impl BluetoothDevice {
    /// Construct a new [`BluetoothDevice`] with `seen_count` initialised to `1`.
    pub const fn new(
        address: BdAddr,
        name: Option<String>,
        rssi: i8,
        class_of_device: u32,
        last_seen: Timestamp,
    ) -> Self {
        Self {
            address,
            name,
            rssi,
            class_of_device,
            last_seen,
            seen_count: 1,
        }
    }
}

// ── DeviceList impl ────────────────────────────────────────────────────────────

impl DeviceList {
    /// Create an empty [`DeviceList`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a new device or update an existing one with the same address.
    ///
    /// If the address is already present, the `rssi`, `last_seen`, and
    /// `seen_count` fields are updated.  The `name` is updated if the
    /// incoming device carries a non-`None` name.
    pub fn add_or_update(&mut self, device: BluetoothDevice) {
        self.devices
            .entry(device.address.clone())
            .and_modify(|existing| {
                existing.rssi = device.rssi;
                existing.last_seen = device.last_seen;
                existing.seen_count = existing.seen_count.saturating_add(1);
                if device.name.is_some() {
                    existing.name.clone_from(&device.name);
                }
            })
            .or_insert(device);
    }

    /// Return all devices whose `last_seen` timestamp is older than `max_age`
    /// relative to the current wall-clock time.
    pub fn stale_devices(&self, max_age: SignedDuration) -> Vec<&BluetoothDevice> {
        let now = Timestamp::now();
        self.devices
            .values()
            .filter(|d| now.duration_since(d.last_seen) >= max_age)
            .collect()
    }

    /// Return the number of devices currently tracked.
    pub fn len(&self) -> usize {
        self.devices.len()
    }

    /// Return `true` if no devices are tracked.
    pub fn is_empty(&self) -> bool {
        self.devices.is_empty()
    }

    /// Look up a device by address.
    pub fn get(&self, address: &BdAddr) -> Option<&BluetoothDevice> {
        self.devices.get(address)
    }

    /// Iterate over all tracked devices.
    pub fn iter(&self) -> impl Iterator<Item = &BluetoothDevice> {
        self.devices.values()
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hci::BdAddr;

    fn make_device(addr: &str, rssi: i8, last_seen: Timestamp) -> BluetoothDevice {
        let Ok(address) = BdAddr::parse(addr) else {
            unreachable!("test address should be valid");
        };
        BluetoothDevice::new(address, None, rssi, 0x00, last_seen)
    }

    #[test]
    fn device_list_starts_empty() {
        let list = DeviceList::new();
        assert!(list.is_empty(), "newly created DeviceList should be empty");
        assert_eq!(list.len(), 0, "len should be 0 for empty DeviceList");
    }

    #[test]
    fn add_new_device_inserts_entry() {
        let mut list = DeviceList::new();
        let device = make_device("AA:BB:CC:DD:EE:01", -60, Timestamp::now());
        list.add_or_update(device);
        assert_eq!(
            list.len(),
            1,
            "list should contain exactly one device after add"
        );
    }

    #[test]
    fn add_two_different_devices_inserts_both() {
        let mut list = DeviceList::new();
        list.add_or_update(make_device("AA:BB:CC:DD:EE:01", -60, Timestamp::now()));
        list.add_or_update(make_device("AA:BB:CC:DD:EE:02", -70, Timestamp::now()));
        assert_eq!(
            list.len(),
            2,
            "two distinct addresses should produce two entries"
        );
    }

    #[test]
    fn update_existing_device_increments_seen_count() {
        let mut list = DeviceList::new();
        let addr = "AA:BB:CC:DD:EE:01";
        list.add_or_update(make_device(addr, -60, Timestamp::now()));
        list.add_or_update(make_device(addr, -55, Timestamp::now()));

        let Ok(bd) = BdAddr::parse(addr) else {
            unreachable!("test address should be valid");
        };
        let Some(device) = list.get(&bd) else {
            unreachable!("device should exist after two adds");
        };
        assert_eq!(
            device.seen_count, 2,
            "seen_count should be 2 after two observations of the same address"
        );
    }

    #[test]
    fn update_existing_device_refreshes_rssi() {
        let mut list = DeviceList::new();
        let addr = "AA:BB:CC:DD:EE:01";
        list.add_or_update(make_device(addr, -80, Timestamp::now()));
        list.add_or_update(make_device(addr, -50, Timestamp::now()));

        let Ok(bd) = BdAddr::parse(addr) else {
            unreachable!("test address should be valid");
        };
        let Some(device) = list.get(&bd) else {
            unreachable!("device should exist");
        };
        assert_eq!(
            device.rssi, -50,
            "rssi should be updated to the most recent observation"
        );
    }

    #[test]
    fn stale_devices_returns_old_entries() {
        let mut list = DeviceList::new();
        // Use the Unix epoch — guaranteed to be older than any real max_age
        let ancient = Timestamp::UNIX_EPOCH;
        list.add_or_update(make_device("AA:BB:CC:DD:EE:01", -60, ancient));

        let stale = list.stale_devices(SignedDuration::from_secs(1));
        assert_eq!(
            stale.len(),
            1,
            "device last seen at epoch should be stale with a 1-second max_age"
        );
    }

    #[test]
    fn stale_devices_excludes_fresh_entries() {
        let mut list = DeviceList::new();
        // Use the Unix epoch for one device, and now for the other
        list.add_or_update(make_device("AA:BB:CC:DD:EE:01", -60, Timestamp::UNIX_EPOCH));
        list.add_or_update(make_device("AA:BB:CC:DD:EE:02", -70, Timestamp::now()));

        let stale = list.stale_devices(SignedDuration::from_secs(1));
        assert_eq!(
            stale.len(),
            1,
            "only the device last seen at epoch should be stale"
        );
        assert_eq!(
            stale[0].address.to_string(),
            "AA:BB:CC:DD:EE:01",
            "the stale device should be the one with the ancient timestamp"
        );
    }

    #[test]
    fn update_name_when_incoming_has_name() {
        let mut list = DeviceList::new();
        let addr = "AA:BB:CC:DD:EE:01";
        list.add_or_update(make_device(addr, -60, Timestamp::now()));

        // Second observation carries a name
        let Ok(bd) = BdAddr::parse(addr) else {
            unreachable!("test address should be valid");
        };
        let named = BluetoothDevice::new(
            bd.clone(),
            Some("MyDevice".to_owned()),
            -58,
            0x00,
            Timestamp::now(),
        );
        list.add_or_update(named);

        let Some(device) = list.get(&bd) else {
            unreachable!("device should exist");
        };
        assert_eq!(
            device.name.as_deref(),
            Some("MyDevice"),
            "name should be updated from the second observation"
        );
    }
}
