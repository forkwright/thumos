//! Behavioral tuning parameters for the BT HCI transport.
//!
//! The knobs exposed here control LE Privacy cadence and similar runtime
//! behaviours that an agent or operator may want to adjust without
//! recompiling.
//!
//! Protocol invariants (ring-buffer size mandated by the MT6739 character
//! device, STP delimiter, `Own_Address_Type` enum, RPA/NRPA bit layouts,
//! HCI opcodes) remain as [`crate::transport`] compile-time `const` values.

// ── BLE address rotation ──────────────────────────────────────────────────────

/// Default BLE random-address rotation interval in seconds.
///
/// Source: Bluetooth Core spec Vol 6 Part B §6 recommends rotating resolvable
/// private addresses at most once per 15 minutes to balance tracker resistance
/// against bonding costs. Shorter rotation leaks transient peers; longer
/// rotation enables cross-session correlation.
pub const DEFAULT_ROTATION_INTERVAL_SECS: u64 = 15 * 60;

/// Minimum accepted rotation interval.
///
/// Source: 10 s is the BLE spec floor for resolvable addresses. Faster rotation
/// exhausts the resolving-list cache on bonded peers and causes reconnect storms.
pub const MIN_ROTATION_INTERVAL_SECS: u64 = 10;

/// Maximum accepted rotation interval.
///
/// Source: 24 hours is the practical ceiling; beyond this, cross-day
/// correlation is no longer meaningfully defeated and the parameter has
/// effectively disabled rotation.
pub const MAX_ROTATION_INTERVAL_SECS: u64 = 24 * 60 * 60;

/// Runtime-tunable knobs for [`crate::transport::BtHciTransport`].
///
/// [`Default`] reproduces the historical `const` behaviour so adopting
/// `Config` is a no-op for callers that do not override anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Config {
    /// BLE random-address rotation interval in seconds.
    ///
    /// **Affects:** tracker-correlation window for this device.
    /// **Evidence:** privacy-mode requirement (Daily: 15 min, Sentinel: 1 min).
    /// **Bounds:** `[MIN_ROTATION_INTERVAL_SECS, MAX_ROTATION_INTERVAL_SECS]`.
    pub rotation_interval_secs: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            rotation_interval_secs: DEFAULT_ROTATION_INTERVAL_SECS,
        }
    }
}

impl Config {
    /// Rotation interval clamped to the accepted domain range.
    #[must_use]
    pub fn rotation_interval_secs(&self) -> u64 {
        let v = self.rotation_interval_secs;
        if (MIN_ROTATION_INTERVAL_SECS..=MAX_ROTATION_INTERVAL_SECS).contains(&v) {
            v
        } else {
            log::warn!(
                "rotation_interval_secs={v} out of range \
                 [{MIN_ROTATION_INTERVAL_SECS}, {MAX_ROTATION_INTERVAL_SECS}]; \
                 using default {DEFAULT_ROTATION_INTERVAL_SECS}",
            );
            DEFAULT_ROTATION_INTERVAL_SECS
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_matches_historical_const() {
        // WHY: the historical const was 15 * 60 = 900 seconds.
        assert_eq!(Config::default().rotation_interval_secs, 900);
    }

    #[test]
    fn accessor_clamps_below_minimum() {
        let c = Config {
            rotation_interval_secs: 0,
        };
        assert_eq!(c.rotation_interval_secs(), DEFAULT_ROTATION_INTERVAL_SECS);
    }

    #[test]
    fn accessor_clamps_above_maximum() {
        let c = Config {
            rotation_interval_secs: u64::MAX,
        };
        assert_eq!(c.rotation_interval_secs(), DEFAULT_ROTATION_INTERVAL_SECS);
    }

    #[test]
    fn accessor_passes_valid_values() {
        let c = Config {
            rotation_interval_secs: 60,
        };
        assert_eq!(c.rotation_interval_secs(), 60);
    }
}
