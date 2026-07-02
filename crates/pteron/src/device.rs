//! Bluetooth device tracking: deduplication by address and stale-device detection.

use std::collections::HashMap;

use jiff::{SignedDuration, Timestamp};

use crate::hci::BdAddr;

// ── Types ──────────────────────────────────────────────────────────────────────

/// A Bluetooth device observed during scanning or inquiry.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub(crate) struct BluetoothDevice {
    /// Bluetooth device address.
    pub(crate) address: BdAddr,
    /// Friendly device name, if received via name request or EIR.
    pub(crate) name: Option<String>,
    /// Most-recently observed RSSI in dBm.
    pub(crate) rssi: i8,
    /// 24-bit Class of Device (classic BT only; `0` for BLE).
    pub(crate) class_of_device: u32,
    /// Wall-clock time of the last observation.
    pub(crate) last_seen: Timestamp,
    /// Total number of times this device has been observed.
    pub(crate) seen_count: u32,
}

/// Hard cap on tracked devices. Bounds worst-case memory even under a burst
/// of spoofed/rotating BLE advertisements within a single `remove_stale`
/// window, before any entry would otherwise qualify as stale.
pub(crate) const MAX_TRACKED_DEVICES: usize = 256;

/// A deduplicated collection of discovered Bluetooth devices, keyed by address.
#[derive(Debug, Default)]
pub(crate) struct DeviceList {
    devices: HashMap<BdAddr, BluetoothDevice>,
}

// ── BluetoothDevice impl ───────────────────────────────────────────────────────

impl BluetoothDevice {
    /// Construct a new [`BluetoothDevice`] with `seen_count` initialised to `1`.
    pub(crate) const fn new(
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
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Insert a new device or update an existing one with the same address.
    ///
    /// If the address is already present, the `rssi`, `last_seen`, and
    /// `seen_count` fields are updated.  The `name` is updated if the
    /// incoming device carries a non-`None` name.
    ///
    /// A brand-new address inserted at [`MAX_TRACKED_DEVICES`] capacity
    /// evicts the single oldest-`last_seen` entry first, bounding memory
    /// under a burst of spoofed/rotating BLE advertisements.
    pub(crate) fn add_or_update(&mut self, device: BluetoothDevice) {
        if let Some(existing) = self.devices.get_mut(&device.address) {
            existing.rssi = device.rssi;
            existing.last_seen = device.last_seen;
            existing.seen_count = existing.seen_count.saturating_add(1);
            if device.name.is_some() {
                existing.name.clone_from(&device.name);
            }
            return;
        }

        if self.devices.len() >= MAX_TRACKED_DEVICES
            && let Some(oldest) = self
                .devices
                .iter()
                .min_by_key(|(_, d)| d.last_seen)
                .map(|(addr, _)| addr.clone())
        {
            self.devices.remove(&oldest);
        }

        self.devices.insert(device.address.clone(), device);
    }

    /// Return all devices whose `last_seen` timestamp is older than `max_age`
    /// relative to the current wall-clock time.
    pub(crate) fn stale_devices(&self, max_age: SignedDuration) -> Vec<&BluetoothDevice> {
        let now = Timestamp::now();
        self.devices
            .values()
            .filter(|d| now.duration_since(d.last_seen) >= max_age)
            .collect()
    }

    /// Prune tracked devices whose `last_seen` timestamp is older than
    /// `max_age` relative to the current wall-clock time.
    ///
    /// Call on the same cadence as [`stale_devices`](Self::stale_devices) to
    /// keep the map bounded by recency under BLE address rotation and
    /// long-running passive scan sessions.
    pub(crate) fn remove_stale(&mut self, max_age: SignedDuration) {
        let now = Timestamp::now();
        self.devices
            .retain(|_, d| now.duration_since(d.last_seen) < max_age);
    }

    /// Return the number of devices currently tracked.
    pub(crate) fn len(&self) -> usize {
        self.devices.len()
    }

    /// Return `true` if no devices are tracked.
    pub(crate) fn is_empty(&self) -> bool {
        self.devices.is_empty()
    }

    /// Look up a device by address.
    pub(crate) fn get(&self, address: &BdAddr) -> Option<&BluetoothDevice> {
        self.devices.get(address)
    }

    /// Iterate over all tracked devices.
    pub(crate) fn iter(&self) -> impl Iterator<Item = &BluetoothDevice> {
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
        let Some(stale_device) = stale.first() else {
            unreachable!("stale vec is non-empty");
        };
        assert_eq!(
            stale_device.address.to_string(),
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
            "name should be updated FROM the second observation"
        );
    }

    #[test]
    fn remove_stale_evicts_aged_entries_and_keeps_fresh() {
        let mut list = DeviceList::new();
        list.add_or_update(make_device("AA:BB:CC:DD:EE:01", -60, Timestamp::UNIX_EPOCH));
        list.add_or_update(make_device("AA:BB:CC:DD:EE:02", -70, Timestamp::now()));

        list.remove_stale(SignedDuration::from_secs(1));

        assert_eq!(
            list.len(),
            1,
            "only the fresh entry should remain after pruning"
        );
        let Ok(fresh) = BdAddr::parse("AA:BB:CC:DD:EE:02") else {
            unreachable!("test address should be valid");
        };
        assert!(
            list.get(&fresh).is_some(),
            "fresh entry must survive pruning"
        );
    }

    #[test]
    fn add_or_update_evicts_oldest_when_at_capacity() {
        let mut list = DeviceList::new();
        for i in 0..MAX_TRACKED_DEVICES {
            let addr = format!("AA:BB:CC:DD:EE:{i:02X}");
            let Ok(last_seen) = Timestamp::from_second(i64::try_from(i).unwrap_or_default()) else {
                unreachable!("small positive second should be valid");
            };
            list.add_or_update(make_device(&addr, -60, last_seen));
        }
        assert_eq!(list.len(), MAX_TRACKED_DEVICES, "list must be at capacity");

        let Ok(newest) =
            Timestamp::from_second(i64::try_from(MAX_TRACKED_DEVICES).unwrap_or_default())
        else {
            unreachable!("small positive second should be valid");
        };
        list.add_or_update(make_device("FF:FF:FF:FF:FF:FF", -40, newest));

        assert_eq!(
            list.len(),
            MAX_TRACKED_DEVICES,
            "insertion at capacity must evict rather than grow the map"
        );
        let Ok(oldest) = BdAddr::parse("AA:BB:CC:DD:EE:00") else {
            unreachable!("test address should be valid");
        };
        assert!(
            list.get(&oldest).is_none(),
            "the oldest entry must have been evicted to make room"
        );
    }
}
