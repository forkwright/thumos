//! Behavioral tuning parameters for cell-tower threat analysis.
//!
//! The IMSI-catcher detector combines five heuristic signals. Each signal has
//! a weight that feeds a cumulative threat score and some signals carry a
//! threshold that gates firing at all. Those values are tunable per deployment
//! profile (daily vs. sentinel vs. panic) and should be adjustable by agents
//! reviewing detection-vs-false-positive telemetry — not baked into the binary.
//!
//! Protocol invariants (cipher algorithm IDs, threat-level boundaries at
//! 30/60/80) remain as [`crate::cell`] compile-time values; the level
//! thresholds are documented in the public [`crate::cell::ThreatLevel`] API
//! and changing them is a semver break, not a tuning knob.

use serde::{Deserialize, Serialize};

// ── Signal-strength threshold ─────────────────────────────────────────────────

/// Default signal threshold above which a previously-unseen tower is flagged.
///
/// Source: IMSI catchers typically outpower legitimate cells to force
/// reselection; -50 dBm indicates a transmitter within ~10 m line-of-sight,
/// which is implausible for a licensed cell site in typical deployment.
pub(crate) const DEFAULT_UNUSUALLY_STRONG_SIGNAL_DBM: i32 = -50;

/// Minimum sensible signal threshold (never flag).
///
/// Source: -30 dBm is roughly "device touching the antenna"; values above
/// this are physically implausible but tolerated to avoid clamping operator
/// intent.
pub(crate) const MIN_UNUSUALLY_STRONG_SIGNAL_DBM: i32 = -30;

/// Maximum sensible signal threshold (flag almost everything).
///
/// Source: -110 dBm is at the edge of GSM demodulation; below this, a signal
/// would not be usable as a serving cell, so flagging it as "unusually strong"
/// is never correct.
pub(crate) const MIN_BOUND_DBM: i32 = -110;

// ── Rapid reselection threshold ───────────────────────────────────────────────

/// Default reselection-count threshold that triggers the rapid-reselection
/// signal.
///
/// Source: normal mobility produces 0-2 reselections per observation window;
/// 3+ within a short window suggests coerced reselection.
pub(crate) const DEFAULT_RAPID_RESELECTION_THRESHOLD: u32 = 3;

/// Minimum accepted rapid-reselection threshold.
///
/// A threshold of 0 would flag every observation; 1 flags any reselection.
pub(crate) const MIN_RAPID_RESELECTION_THRESHOLD: u32 = 1;

/// Maximum accepted rapid-reselection threshold.
///
/// Beyond 100 the signal effectively never fires; documented as a sanity bound.
pub(crate) const MAX_RAPID_RESELECTION_THRESHOLD: u32 = 100;

// ── Threat-score weights ──────────────────────────────────────────────────────

/// Default weight for a cipher-downgrade alert (A5/0, A5/1, A5/2).
///
/// Source: cipher downgrade is the strongest single indicator of active
/// interception; the historical value of 40 lifts a lone alert to Medium
/// level on its own.
pub(crate) const DEFAULT_WEIGHT_CIPHER_DOWNGRADE: u32 = 40;

/// Default weight for an unannounced handover (sudden-tower-change).
pub(crate) const DEFAULT_WEIGHT_UNUSUAL_LAC_CID: u32 = 30;

/// Default weight for an unknown tower advertising an unusually strong signal.
pub(crate) const DEFAULT_WEIGHT_ABNORMAL_SIGNAL: u32 = 20;

/// Default weight for rapid-reselection.
pub(crate) const DEFAULT_WEIGHT_RAPID_RESELECTION: u32 = 10;

/// Upper bound on any single weight.
///
/// Source: the Critical threshold is 80; no single alert should exceed that
/// on its own because Critical means "multiple strong indicators".
pub(crate) const MAX_SIGNAL_WEIGHT: u32 = 80;

// ── Config ────────────────────────────────────────────────────────────────────

/// Runtime-tunable knobs for [`crate::cell`] IMSI-catcher detection and
/// threat scoring.
///
/// All fields have [`Default`] values that reproduce the historical `const`
/// behaviour; adopting `Config` is a no-op for callers that do not override
/// anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct Config {
    /// Signal threshold (dBm, higher is stronger) above which a new tower is
    /// flagged as unusually strong.
    ///
    /// **Affects:** false-positive rate of `UnusuallyStrongNewTower`.
    /// **Evidence:** measured tower-signal histogram in the deployment area.
    /// **Bounds:** `[MIN_BOUND_DBM, MIN_UNUSUALLY_STRONG_SIGNAL_DBM]`.
    pub(crate) unusually_strong_signal_dbm: i32,

    /// Reselection count above which `RapidReselection` fires.
    ///
    /// **Affects:** sensitivity to coerced handovers vs. normal mobility.
    /// **Evidence:** baseline reselection-per-minute in the target area.
    /// **Bounds:** `[MIN_RAPID_RESELECTION_THRESHOLD, MAX_RAPID_RESELECTION_THRESHOLD]`.
    pub(crate) rapid_reselection_threshold: u32,

    /// Threat-score weight for a cipher-downgrade alert.
    pub(crate) weight_cipher_downgrade: u32,

    /// Threat-score weight for an unannounced handover.
    pub(crate) weight_unusual_lac_cid: u32,

    /// Threat-score weight for an abnormally strong unknown tower.
    pub(crate) weight_abnormal_signal: u32,

    /// Threat-score weight for rapid-reselection.
    pub(crate) weight_rapid_reselection: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            unusually_strong_signal_dbm: DEFAULT_UNUSUALLY_STRONG_SIGNAL_DBM,
            rapid_reselection_threshold: DEFAULT_RAPID_RESELECTION_THRESHOLD,
            weight_cipher_downgrade: DEFAULT_WEIGHT_CIPHER_DOWNGRADE,
            weight_unusual_lac_cid: DEFAULT_WEIGHT_UNUSUAL_LAC_CID,
            weight_abnormal_signal: DEFAULT_WEIGHT_ABNORMAL_SIGNAL,
            weight_rapid_reselection: DEFAULT_WEIGHT_RAPID_RESELECTION,
        }
    }
}

impl Config {
    /// Bounded unusually-strong-signal threshold.
    ///
    /// Logs at `warn` and falls back to default for out-of-range values.
    #[must_use]
    pub(crate) fn unusually_strong_signal_dbm(&self) -> i32 {
        let v = self.unusually_strong_signal_dbm;
        if (MIN_BOUND_DBM..=MIN_UNUSUALLY_STRONG_SIGNAL_DBM).contains(&v) {
            v
        } else {
            log::warn!(
                "unusually_strong_signal_dbm={v} out of range \
                 [{MIN_BOUND_DBM}, {MIN_UNUSUALLY_STRONG_SIGNAL_DBM}]; \
                 using default {DEFAULT_UNUSUALLY_STRONG_SIGNAL_DBM}",
            );
            DEFAULT_UNUSUALLY_STRONG_SIGNAL_DBM
        }
    }

    /// Bounded rapid-reselection threshold.
    #[must_use]
    pub(crate) fn rapid_reselection_threshold(&self) -> u32 {
        bounded_u32(
            self.rapid_reselection_threshold,
            DEFAULT_RAPID_RESELECTION_THRESHOLD,
            MIN_RAPID_RESELECTION_THRESHOLD,
            MAX_RAPID_RESELECTION_THRESHOLD,
            "rapid_reselection_threshold",
        )
    }

    /// Bounded cipher-downgrade weight.
    #[must_use]
    pub(crate) fn weight_cipher_downgrade(&self) -> u32 {
        bounded_weight(
            self.weight_cipher_downgrade,
            DEFAULT_WEIGHT_CIPHER_DOWNGRADE,
            "weight_cipher_downgrade",
        )
    }

    /// Bounded unusual-LAC/CID weight.
    #[must_use]
    pub(crate) fn weight_unusual_lac_cid(&self) -> u32 {
        bounded_weight(
            self.weight_unusual_lac_cid,
            DEFAULT_WEIGHT_UNUSUAL_LAC_CID,
            "weight_unusual_lac_cid",
        )
    }

    /// Bounded abnormal-signal weight.
    #[must_use]
    pub(crate) fn weight_abnormal_signal(&self) -> u32 {
        bounded_weight(
            self.weight_abnormal_signal,
            DEFAULT_WEIGHT_ABNORMAL_SIGNAL,
            "weight_abnormal_signal",
        )
    }

    /// Bounded rapid-reselection weight.
    #[must_use]
    pub(crate) fn weight_rapid_reselection(&self) -> u32 {
        bounded_weight(
            self.weight_rapid_reselection,
            DEFAULT_WEIGHT_RAPID_RESELECTION,
            "weight_rapid_reselection",
        )
    }
}

fn bounded_u32(v: u32, default: u32, min: u32, max: u32, name: &str) -> u32 {
    if (min..=max).contains(&v) {
        v
    } else {
        log::warn!("{name}={v} out of range [{min}, {max}]; using default {default}");
        default
    }
}

fn bounded_weight(v: u32, default: u32, name: &str) -> u32 {
    if v <= MAX_SIGNAL_WEIGHT {
        v
    } else {
        log::warn!(
            "{name}={v} exceeds MAX_SIGNAL_WEIGHT={MAX_SIGNAL_WEIGHT}; using default {default}",
        );
        default
    }
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test code — panics and expect are intentional for assertion failures"
)]
mod tests {
    use super::*;

    #[test]
    fn default_matches_historical_constants() {
        let c = Config::default();
        assert_eq!(c.unusually_strong_signal_dbm, -50);
        assert_eq!(c.rapid_reselection_threshold, 3);
        assert_eq!(c.weight_cipher_downgrade, 40);
        assert_eq!(c.weight_unusual_lac_cid, 30);
        assert_eq!(c.weight_abnormal_signal, 20);
        assert_eq!(c.weight_rapid_reselection, 10);
    }

    #[test]
    fn serde_round_trip_preserves_all_fields() {
        let c = Config {
            unusually_strong_signal_dbm: -55,
            rapid_reselection_threshold: 5,
            weight_cipher_downgrade: 50,
            weight_unusual_lac_cid: 25,
            weight_abnormal_signal: 15,
            weight_rapid_reselection: 5,
        };
        let bytes = postcard::to_allocvec(&c).expect("serialize");
        let back: Config = postcard::from_bytes(&bytes).expect("deserialize");
        assert_eq!(c, back);
    }

    #[test]
    fn dbm_accessor_clamps_above_ceiling() {
        let c = Config {
            unusually_strong_signal_dbm: 0,
            ..Config::default()
        };
        assert_eq!(
            c.unusually_strong_signal_dbm(),
            DEFAULT_UNUSUALLY_STRONG_SIGNAL_DBM
        );
    }

    #[test]
    fn dbm_accessor_clamps_below_floor() {
        let c = Config {
            unusually_strong_signal_dbm: -200,
            ..Config::default()
        };
        assert_eq!(
            c.unusually_strong_signal_dbm(),
            DEFAULT_UNUSUALLY_STRONG_SIGNAL_DBM
        );
    }

    #[test]
    fn dbm_accessor_passes_valid_values() {
        let c = Config {
            unusually_strong_signal_dbm: -70,
            ..Config::default()
        };
        assert_eq!(c.unusually_strong_signal_dbm(), -70);
    }

    #[test]
    fn threshold_accessor_rejects_zero() {
        let c = Config {
            rapid_reselection_threshold: 0,
            ..Config::default()
        };
        assert_eq!(
            c.rapid_reselection_threshold(),
            DEFAULT_RAPID_RESELECTION_THRESHOLD
        );
    }

    #[test]
    fn weight_accessor_clamps_excessive_weight() {
        let c = Config {
            weight_cipher_downgrade: 10_000,
            ..Config::default()
        };
        assert_eq!(c.weight_cipher_downgrade(), DEFAULT_WEIGHT_CIPHER_DOWNGRADE);
    }
}
