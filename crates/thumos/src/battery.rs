//! Battery monitoring for LiPo cells.
//!
//! Provides [`BatteryInfo`] snapshots and a [`BatteryMonitor`] that polls
//! hardware via the [`BatteryHwOps`] trait. Voltage-to-percentage conversion
//! uses a piecewise-linear lookup table matching typical 3.7V LiPo discharge
//! curves.
//!
//! ## Voltage table (3.7V single-cell LiPo)
//!
//! | Voltage (mV) | Percentage |
//! |--------------|------------|
//! | 4200         | 100        |
//! | 4100         | 90         |
//! | 3900         | 70         |
//! | 3800         | 50         |
//! | 3700         | 30         |
//! | 3600         | 15         |
//! | 3400         | 5          |
//! | 3000         | 0          |
//!
//! ## Polling
//!
//! The monitor polls every 60 seconds. Each poll reads voltage, current,
//! temperature, and charging state from the hardware abstraction. The
//! [`BatteryInfo`] snapshot is updated atomically (no partial reads).

// WHY: battery monitor created in Phase 07 Wave 5, kinit wiring pending.
#![expect(
    dead_code,
    reason = "Battery monitor created in Phase 07 Wave 5, kinit wiring pending"
)]

// ---------------------------------------------------------------------------
// Voltage-to-percentage lookup table
// ---------------------------------------------------------------------------

/// Entry in the voltage-to-percentage lookup table.
///
/// Stored as `(millivolts, percentage)`. The table must be sorted in
/// descending order by voltage.
struct LookupEntry {
    voltage_mv: u16,
    percentage: u8,
}

/// LiPo discharge curve lookup table.
///
/// Sorted descending by voltage. Linear interpolation is used between
/// adjacent entries.
const VOLTAGE_TABLE: &[LookupEntry] = &[
    LookupEntry { voltage_mv: 4200, percentage: 100 },
    LookupEntry { voltage_mv: 4100, percentage: 90 },
    LookupEntry { voltage_mv: 3900, percentage: 70 },
    LookupEntry { voltage_mv: 3800, percentage: 50 },
    LookupEntry { voltage_mv: 3700, percentage: 30 },
    LookupEntry { voltage_mv: 3600, percentage: 15 },
    LookupEntry { voltage_mv: 3400, percentage: 5 },
    LookupEntry { voltage_mv: 3000, percentage: 0 },
];

/// Polling interval in seconds.
///
/// The battery state changes slowly; 60 seconds is sufficient for
/// UI updates while keeping CPU usage minimal.
pub(crate) const POLL_INTERVAL_SECS: u64 = 60;

// ---------------------------------------------------------------------------
// Battery info
// ---------------------------------------------------------------------------

/// Snapshot of battery state at a point in time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BatteryInfo {
    /// Battery voltage in millivolts (3000-4200 typical LiPo).
    pub voltage_mv: u16,
    /// Estimated charge percentage (0-100).
    pub percentage: u8,
    /// Whether the battery is currently charging.
    pub charging: bool,
    /// Battery temperature in degrees Celsius.
    pub temperature_c: i8,
}

impl core::fmt::Display for BatteryInfo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}% {}mV", self.percentage, self.voltage_mv)
    }
}

impl Default for BatteryInfo {
    fn default() -> Self {
        Self {
            voltage_mv: 0,
            percentage: 0,
            charging: false,
            temperature_c: 25,
        }
    }
}

// ---------------------------------------------------------------------------
// Hardware abstraction
// ---------------------------------------------------------------------------

/// Hardware operations for reading battery state.
///
/// Implementors provide platform-specific register reads for the fuel
/// gauge IC (e.g., MAX17048, BQ27441) or ADC-based voltage measurement.
pub(crate) trait BatteryHwOps {
    /// Read the battery terminal voltage in millivolts.
    fn read_voltage(&self) -> u16;

    /// Read the instantaneous current in milliamps.
    ///
    /// Positive values indicate charging; negative values indicate
    /// discharging.
    fn read_current(&self) -> i16;

    /// Read the battery temperature in degrees Celsius.
    fn read_temperature(&self) -> i8;

    /// Whether the charger IC reports active charging.
    fn is_charging(&self) -> bool;
}

// ---------------------------------------------------------------------------
// Voltage-to-percentage conversion
// ---------------------------------------------------------------------------

/// Convert a battery voltage (millivolts) to a charge percentage (0-100).
///
/// Uses piecewise linear interpolation over [`VOLTAGE_TABLE`]. Voltages
/// above 4200 mV clamp to 100%; below 3000 mV clamp to 0%.
pub(crate) fn voltage_to_percentage(voltage_mv: u16) -> u8 {
    // Above the highest entry: full charge.
    if voltage_mv >= VOLTAGE_TABLE[0].voltage_mv {
        return VOLTAGE_TABLE[0].percentage;
    }

    // Below the lowest entry: empty.
    let last_idx = VOLTAGE_TABLE.len() - 1;
    if voltage_mv <= VOLTAGE_TABLE[last_idx].voltage_mv {
        return VOLTAGE_TABLE[last_idx].percentage;
    }

    // Find the two adjacent entries that bracket the voltage.
    // Table is sorted descending, so we walk from high to low.
    for i in 0..VOLTAGE_TABLE.len() - 1 {
        let high = &VOLTAGE_TABLE[i];
        let low = &VOLTAGE_TABLE[i + 1];

        if voltage_mv <= high.voltage_mv && voltage_mv >= low.voltage_mv {
            // Linear interpolation between low and high.
            let v_range = high.voltage_mv.saturating_sub(low.voltage_mv) as u32;
            let p_range = high.percentage.saturating_sub(low.percentage) as u32;

            if v_range == 0 {
                return high.percentage;
            }

            let v_offset = voltage_mv.saturating_sub(low.voltage_mv) as u32;
            let interpolated = low.percentage as u32 + (v_offset * p_range) / v_range;

            // Clamp to valid range.
            return if interpolated > 100 { 100 } else { interpolated as u8 };
        }
    }

    // Fallback (should not be reached with a well-formed table).
    0
}

// ---------------------------------------------------------------------------
// Battery monitor
// ---------------------------------------------------------------------------

/// Battery monitor that periodically samples hardware and produces
/// [`BatteryInfo`] snapshots.
///
/// The caller is responsible for invoking [`poll`](Self::poll) at
/// appropriate intervals (see [`POLL_INTERVAL_SECS`]).
pub(crate) struct BatteryMonitor {
    /// Most recent battery state snapshot.
    info: BatteryInfo,
    /// Kernel tick (milliseconds) of the last successful poll.
    last_poll_tick: u64,
}

impl BatteryMonitor {
    /// Create a new battery monitor with default (unknown) state.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            info: BatteryInfo::default(),
            last_poll_tick: 0,
        }
    }

    /// Return the most recent battery info snapshot.
    #[must_use]
    pub(crate) fn info(&self) -> &BatteryInfo {
        &self.info
    }

    /// Poll the hardware for updated battery state.
    ///
    /// Reads voltage, current, temperature, and charging state from
    /// the provided hardware ops, then updates the internal snapshot.
    pub(crate) fn poll<H: BatteryHwOps>(&mut self, hw: &H, current_tick: u64) {
        let voltage_mv = hw.read_voltage();
        let _current_ma = hw.read_current();
        let temperature_c = hw.read_temperature();
        let charging = hw.is_charging();
        let percentage = voltage_to_percentage(voltage_mv);

        self.info = BatteryInfo {
            voltage_mv,
            percentage,
            charging,
            temperature_c,
        };
        self.last_poll_tick = current_tick;
    }

    /// Check whether enough time has elapsed to warrant a new poll.
    ///
    /// Returns `true` if at least [`POLL_INTERVAL_SECS`] seconds have
    /// passed since the last poll.
    #[must_use]
    pub(crate) fn should_poll(&self, current_tick: u64) -> bool {
        let elapsed_ms = current_tick.saturating_sub(self.last_poll_tick);
        elapsed_ms >= POLL_INTERVAL_SECS * 1000
    }

    /// Return the tick of the last poll.
    #[must_use]
    pub(crate) fn last_poll_tick(&self) -> u64 {
        self.last_poll_tick
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Mock hardware for testing.
    struct MockHw {
        voltage: u16,
        current: i16,
        temperature: i8,
        charging: bool,
    }

    impl BatteryHwOps for MockHw {
        fn read_voltage(&self) -> u16 {
            self.voltage
        }
        fn read_current(&self) -> i16 {
            self.current
        }
        fn read_temperature(&self) -> i8 {
            self.temperature
        }
        fn is_charging(&self) -> bool {
            self.charging
        }
    }

    fn default_hw(voltage: u16) -> MockHw {
        MockHw {
            voltage,
            current: 0,
            temperature: 25,
            charging: false,
        }
    }

    // --- voltage_to_percentage tests ---

    #[test]
    fn voltage_to_percentage_boundaries() {
        // Exact table entries.
        assert_eq!(voltage_to_percentage(4200), 100);
        assert_eq!(voltage_to_percentage(4100), 90);
        assert_eq!(voltage_to_percentage(3900), 70);
        assert_eq!(voltage_to_percentage(3800), 50);
        assert_eq!(voltage_to_percentage(3700), 30);
        assert_eq!(voltage_to_percentage(3600), 15);
        assert_eq!(voltage_to_percentage(3400), 5);
        assert_eq!(voltage_to_percentage(3000), 0);
    }

    #[test]
    fn full_charge_is_100() {
        // At and above 4200 mV.
        assert_eq!(voltage_to_percentage(4200), 100);
        assert_eq!(voltage_to_percentage(4300), 100);
        assert_eq!(voltage_to_percentage(4500), 100);
    }

    #[test]
    fn empty_is_0() {
        // At and below 3000 mV.
        assert_eq!(voltage_to_percentage(3000), 0);
        assert_eq!(voltage_to_percentage(2900), 0);
        assert_eq!(voltage_to_percentage(2500), 0);
        assert_eq!(voltage_to_percentage(0), 0);
    }

    #[test]
    fn interpolation_between_points() {
        // Midpoint between 3800 mV (50%) and 3900 mV (70%) = 3850 mV.
        // Expected: 50 + (50/100 * 20) = 60%.
        let pct = voltage_to_percentage(3850);
        assert_eq!(pct, 60, "midpoint between 3800 and 3900 must be 60%");

        // 3950 mV: between 3900 (70%) and 4100 (90%).
        // offset = 50 out of 200, range = 20. 70 + (50*20)/200 = 75.
        let pct = voltage_to_percentage(3950);
        assert_eq!(pct, 75, "3950 mV must be 75%");

        // 3500 mV: between 3400 (5%) and 3600 (15%).
        // offset = 100 out of 200, range = 10. 5 + (100*10)/200 = 10.
        let pct = voltage_to_percentage(3500);
        assert_eq!(pct, 10, "3500 mV must be 10%");
    }

    // --- BatteryMonitor tests ---

    #[test]
    fn monitor_initial_state() {
        let monitor = BatteryMonitor::new();
        let info = monitor.info();
        assert_eq!(info.voltage_mv, 0);
        assert_eq!(info.percentage, 0);
        assert!(!info.charging);
        assert_eq!(info.temperature_c, 25);
    }

    #[test]
    fn monitor_poll_updates_info() {
        let mut monitor = BatteryMonitor::new();
        let hw = MockHw {
            voltage: 3900,
            current: 500,
            temperature: 30,
            charging: true,
        };
        monitor.poll(&hw, 1000);

        let info = monitor.info();
        assert_eq!(info.voltage_mv, 3900);
        assert_eq!(info.percentage, 70);
        assert!(info.charging);
        assert_eq!(info.temperature_c, 30);
        assert_eq!(monitor.last_poll_tick(), 1000);
    }

    #[test]
    fn should_poll_respects_interval() {
        let mut monitor = BatteryMonitor::new();
        let hw = default_hw(4000);

        // First poll always needed (last_poll_tick=0, current_tick >= 60000).
        assert!(
            monitor.should_poll(60_000),
            "first poll after 60s must be needed"
        );

        monitor.poll(&hw, 60_000);

        // Immediately after: not needed.
        assert!(
            !monitor.should_poll(60_001),
            "poll right after previous must not be needed"
        );

        // After the interval: needed.
        assert!(
            monitor.should_poll(60_000 + POLL_INTERVAL_SECS * 1000),
            "poll after interval must be needed"
        );
    }

    #[test]
    fn info_default_is_reasonable() {
        let info = BatteryInfo::default();
        assert_eq!(info.voltage_mv, 0);
        assert_eq!(info.percentage, 0);
        assert!(!info.charging);
        assert_eq!(info.temperature_c, 25);
    }

    #[test]
    fn voltage_monotonically_maps_to_percentage() {
        // Verify that higher voltage always gives >= percentage.
        let mut prev_pct = 0u8;
        for mv in (3000..=4200).step_by(10) {
            let pct = voltage_to_percentage(mv);
            assert!(
                pct >= prev_pct,
                "voltage {mv} mV yielded {pct}% but previous was {prev_pct}%"
            );
            prev_pct = pct;
        }
    }
}
