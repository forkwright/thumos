//! Cell tower types and IMSI catcher detection via tower behaviour analysis.
//!
//! IMSI catchers (fake base stations / "Stingrays") impersonate legitimate towers to
//! intercept mobile traffic. This module detects three common signatures:
//!
//! 1. **Technology downgrade** — the device is forced from LTE/UMTS down to GSM, where
//!    encryption is weaker or absent.
//! 2. **Unusually strong new tower** — a tower the device has never seen before
//!    advertises an unrealistically strong signal, suggesting it is physically close
//!    and deliberately overpowering legitimate cells.
//! 3. **Sudden tower change** — the device hands over to a tower that was never
//!    advertised as a neighbour, bypassing the normal measurement-report handover flow.

use std::collections::HashSet;

use jiff::{SignedDuration, Timestamp};
use serde::{Deserialize, Serialize};

use crate::config::Config;

/// Radio access technology generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub(crate) enum CellTechnology {
    /// GSM (2G). Weak encryption (A5/1 or A5/2); susceptible to downgrade attacks.
    Gsm,
    /// UMTS / WCDMA (3G).
    Umts,
    /// LTE (4G). Strongest security of the three generations listed here.
    Lte,
}

/// A cell tower observed or connected to by the device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub(crate) struct CellTower {
    /// Mobile Country Code (3 decimal digits, e.g. 234 for UK).
    pub(crate) mcc: u16,
    /// Mobile Network Code (2–3 decimal digits).
    pub(crate) mnc: u16,
    /// Location Area Code (2G/3G) or Tracking Area Code (4G).
    pub(crate) lac: u32,
    /// Cell Identity.
    pub(crate) cid: u32,
    /// Received signal strength in dBm (higher is stronger).
    pub(crate) signal_dbm: i32,
    /// Radio access technology generation.
    pub(crate) technology: CellTechnology,
    /// Wall-clock time when this tower was observed.
    pub(crate) timestamp: Timestamp,
}

/// An event in the device's cell tower history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub(crate) enum CellEvent {
    /// Device registered to a serving cell.
    Connected(CellTower),
    /// Device lost registration with a serving cell.
    Disconnected(CellTower),
    /// Device handed over from the previous serving cell to this tower.
    HandoverTo(CellTower),
    /// Tower was reported in a neighbour list but is not (yet) the serving cell.
    NeighborSeen(CellTower),
    /// The air-interface cipher algorithm changed (from modem cipher mode indication).
    CipherChange {
        /// The cipher algorithm now in use.
        algorithm: CipherAlgorithm,
    },
}

/// An alert raised by [`detect_imsi_catcher`].
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub(crate) enum ImsiCatcherAlert {
    /// The device was forced to a weaker radio technology.
    TechnologyDowngrade {
        /// Technology before the downgrade.
        from: CellTechnology,
        /// Technology after the downgrade.
        to: CellTechnology,
    },
    /// A tower not previously seen is advertising an unusually strong signal.
    UnusuallyStrongNewTower {
        /// The suspicious tower.
        tower: CellTower,
    },
    /// Handover to a tower that was never announced as a neighbour.
    SuddenTowerChange {
        /// Serving cell before the change.
        previous: CellTower,
        /// New serving cell.
        current: CellTower,
    },
    /// A5/1 or A5/2 cipher downgrade detected on the air interface.
    CipherDowngrade {
        /// The cipher algorithm that was negotiated.
        algorithm: CipherAlgorithm,
    },
    /// Rapid cell reselection: [`Config::rapid_reselection_threshold`] or
    /// more serving-cell changes fell within a single
    /// [`Config::rapid_reselection_window_secs`]-second span.
    RapidReselection {
        /// Largest number of reselections observed within any single
        /// window-length span (not the raw total across the whole
        /// caller-supplied event slice).
        count: u32,
    },
}

impl core::fmt::Display for ImsiCatcherAlert {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TechnologyDowngrade { from, to } => {
                write!(f, "technology downgrade: {from} → {to}")
            }
            Self::UnusuallyStrongNewTower { tower } => {
                write!(f, "unusually strong new tower: {tower}")
            }
            Self::SuddenTowerChange { previous, current } => {
                write!(f, "sudden tower change: {previous} → {current}")
            }
            Self::CipherDowngrade { algorithm } => {
                write!(f, "cipher downgrade to {algorithm}")
            }
            Self::RapidReselection { count } => {
                write!(f, "rapid cell reselection ({count} changes)")
            }
        }
    }
}

// ── Cipher algorithms ────────────────────────────────────────────────────────

/// GSM cipher algorithm identifier (3GPP TS 43.020).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub(crate) enum CipherAlgorithm {
    /// A5/0: no encryption.
    A5_0,
    /// A5/1: weak stream cipher, broken since 2009.
    A5_1,
    /// A5/2: export-grade cipher, trivially broken.
    A5_2,
    /// A5/3: KASUMI-based, acceptable.
    A5_3,
    /// A5/4: 128-bit KASUMI variant, acceptable.
    A5_4,
}

impl core::fmt::Display for CipherAlgorithm {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::A5_0 => f.write_str("A5/0 (no encryption)"),
            Self::A5_1 => f.write_str("A5/1"),
            Self::A5_2 => f.write_str("A5/2"),
            Self::A5_3 => f.write_str("A5/3"),
            Self::A5_4 => f.write_str("A5/4"),
        }
    }
}

// ── Threat scoring ──────────────────────────────────────────────────────────

/// The canonical threat semantics now live in `sema_core` (#545) — one
/// implementation, shared by this crate and the kernel. Re-exported here so
/// existing paths (`crate::cell::ThreatLevel`, etc.) keep working.
pub(crate) use sema_core::{Calibration, ThreatLevel, level_from_score};

/// A contributing factor to the overall [`ThreatScore`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ThreatFactor {
    /// Short identifier for this factor (e.g. `cipher_downgrade`).
    pub(crate) name: &'static str,
    /// Numeric weight this factor contributes to the total score.
    pub(crate) weight: u32,
    /// Human-readable description of what was detected.
    pub(crate) description: String,
}

impl core::fmt::Display for ThreatFactor {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{} (weight {}): {}",
            self.name, self.weight, self.description
        )
    }
}

/// Weighted threat score combining all IMSI catcher detection signals.
///
/// Produced by [`score_threat`] from a set of [`ImsiCatcherAlert`]s.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub(crate) struct ThreatScore {
    /// Cumulative numeric score.
    pub(crate) total: u32,
    /// Threat level derived from `total`.
    pub(crate) level: ThreatLevel,
    /// Individual contributing factors.
    pub(crate) factors: Vec<ThreatFactor>,
    /// Calibration provenance (#555). Every score states it; presentation
    /// and any future automatic response must honor it.
    pub(crate) calibration: Calibration,
}

impl core::fmt::Display for ThreatScore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "threat score {} [{}]: {} ({} factor{})",
            self.total,
            self.calibration,
            self.level,
            self.factors.len(),
            if self.factors.len() == 1 { "" } else { "s" },
        )
    }
}

/// Compute a weighted [`ThreatScore`] using [`Config::default`] weights.
///
/// Each alert type maps to a weight defined by the active [`Config`]; see
/// [`score_threat_with_config`] for the configurable form.
pub(crate) fn score_threat(alerts: &[ImsiCatcherAlert]) -> ThreatScore {
    score_threat_with_config(alerts, &Config::default())
}

/// Compute a weighted [`ThreatScore`] using explicit [`Config`] weights.
///
/// Supplying a non-default `config` observably changes the per-alert weights
/// in the result and can move the overall [`ThreatLevel`] boundary. This is
/// the primary entry point for agents tuning detection policy.
///
/// # Correlation model (#555)
///
/// Repeated alerts of the SAME kind are correlated observations — one
/// underlying event re-reported — not independent evidence. Summing them at
/// full weight let a single benign burst (e.g. dense-urban reselection
/// churn) accumulate into a Critical score. The contribution of the *n*-th
/// alert of a kind is therefore `weight / n` (harmonic discount: first
/// alert full weight, second half, third a third, …). The harmonic series
/// is parameter-free — it models diminishing independent information per
/// repeat without minting another hand-maintained constant. Distinct kinds
/// still sum fully (a cipher downgrade AND a sudden tower change ARE
/// independent signals).
///
/// Time: O(a) where a is `alerts.len()` — one pass, O(1) work per alert
/// (the per-kind occurrence count is a fixed 5-slot array indexed by a
/// compile-time-known discriminant).
/// Space: O(a) — the returned `factors: Vec<ThreatFactor>` holds one entry
/// per alert.
pub(crate) fn score_threat_with_config(
    alerts: &[ImsiCatcherAlert],
    config: &Config,
) -> ThreatScore {
    let mut total: u32 = 0;
    let mut factors = Vec::new();
    // Per-kind occurrence index for the harmonic correlation discount (#555).
    let mut kind_counts = [0u32; 5];

    let w_cipher = config.weight_cipher_downgrade();
    let w_lac_cid = config.weight_unusual_lac_cid();
    let w_abnormal = config.weight_abnormal_signal();
    let w_rapid = config.weight_rapid_reselection();

    for alert in alerts {
        let (kind_idx, name, base_weight, description) = match alert {
            ImsiCatcherAlert::TechnologyDowngrade { from, to } => (
                0,
                "tech_downgrade",
                w_cipher,
                format!("technology downgrade: {from} → {to}"),
            ),
            ImsiCatcherAlert::CipherDowngrade { algorithm } => (
                1,
                "cipher_downgrade",
                w_cipher,
                format!("weak cipher negotiated: {algorithm}"),
            ),
            ImsiCatcherAlert::SuddenTowerChange { previous, current } => (
                2,
                "unusual_lac_cid",
                w_lac_cid,
                format!(
                    "handover to unannounced tower: LAC {} CID {} → LAC {} CID {}",
                    previous.lac, previous.cid, current.lac, current.cid
                ),
            ),
            ImsiCatcherAlert::UnusuallyStrongNewTower { tower } => (
                3,
                "abnormal_signal",
                w_abnormal,
                format!(
                    "unknown tower at {} dBm (CID {})",
                    tower.signal_dbm, tower.cid
                ),
            ),
            ImsiCatcherAlert::RapidReselection { count } => (
                4,
                "rapid_reselection",
                w_rapid,
                format!("{count} cell reselections in observation window"), // kanon:ignore STORAGE/sql-string-concat -- false positive: "reselections" contains "SELECT" substring; this is a human-readable alert string, not SQL. kanon:ignore RUST/format-sql -- same rationale
            ),
        };

        // Harmonic correlation discount: the n-th alert of this kind
        // contributes base_weight/n (#555; doc on the function).
        kind_counts[kind_idx] += 1;
        let n = kind_counts[kind_idx];
        let weight = base_weight / n;
        total = total.saturating_add(weight);
        factors.push(ThreatFactor {
            name,
            weight,
            description,
        });
    }

    let level = level_from_score(total);
    ThreatScore {
        total,
        level,
        factors,
        // Every score ships uncalibrated until the eval harness + a versioned
        // corpus establish an operating point (#555).
        calibration: Calibration::Uncalibrated,
    }
}

impl CellTower {
    /// Construct a [`CellTower`] with all fields.
    pub(crate) const fn new(
        mcc: u16,
        mnc: u16,
        lac: u32,
        cid: u32,
        signal_dbm: i32,
        technology: CellTechnology,
        timestamp: Timestamp,
    ) -> Self {
        Self {
            mcc,
            mnc,
            lac,
            cid,
            signal_dbm,
            technology,
            timestamp,
        }
    }

    const fn id(&self) -> (u16, u16, u32, u32) {
        (self.mcc, self.mnc, self.lac, self.cid)
    }
}

impl std::fmt::Display for CellTechnology {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Gsm => "GSM (2G)",
            Self::Umts => "UMTS (3G)",
            Self::Lte => "LTE (4G)",
        };
        f.write_str(s)
    }
}

impl std::fmt::Display for CellTower {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} MCC={} MNC={} LAC={} CID={} {}dBm",
            self.technology, self.mcc, self.mnc, self.lac, self.cid, self.signal_dbm
        )
    }
}

/// Returns `true` if transitioning from `from` to `to` represents a technology downgrade.
const fn is_technology_downgrade(from: &CellTechnology, to: &CellTechnology) -> bool {
    matches!(
        (from, to),
        (
            CellTechnology::Lte,
            CellTechnology::Umts | CellTechnology::Gsm
        ) | (CellTechnology::Umts, CellTechnology::Gsm)
    )
}

/// Analyse a sequence of cell events for IMSI catcher signatures using the
/// default [`Config`].
///
/// See [`detect_imsi_catcher_with_config`] for the configurable form.
#[must_use]
pub(crate) fn detect_imsi_catcher(events: &[CellEvent]) -> Vec<ImsiCatcherAlert> {
    detect_imsi_catcher_with_config(events, &Config::default())
}

/// Analyse a sequence of cell events for IMSI catcher signatures using
/// explicit [`Config`] thresholds.
///
/// Five patterns are detected:
///
/// - **Technology downgrade**: any `Connected` or `HandoverTo` event that transitions
///   the device to a lower-capability radio technology.
/// - **Unusually strong new tower**: a `Connected` or `HandoverTo` event where the tower
///   has never been seen before and its signal exceeds
///   [`Config::unusually_strong_signal_dbm`].
/// - **Sudden tower change**: a `HandoverTo` event to a tower that was never previously
///   announced via `NeighborSeen`, suggesting an abnormal handover.
/// - **Cipher downgrade**: a `CipherChange` event indicating A5/0, A5/1, or A5/2.
/// - **Rapid reselection**: [`Config::rapid_reselection_threshold`] or more serving-cell
///   changes (`Connected` and `HandoverTo` events with a changed tower id) falling
///   within any single [`Config::rapid_reselection_window_secs`]-second span, evaluated
///   with a timestamp-bounded sliding window rather than a raw count across the whole
///   slice.
///
/// Events are processed in order; `NeighborSeen` events accumulate a set of known
/// neighbours used to evaluate subsequent handovers. Reselection timestamps are sorted
/// independently of event order before the window scan, so out-of-order or
/// reordered timestamps do not affect the result.
///
/// Time: O(e log e) where e is `events.len()`. The main scan over `events` is
/// O(e) (average-case `HashSet` operations per event); the dominant cost is
/// [`max_reselections_in_window`] sorting the collected reselection
/// timestamps (at most e of them) before its O(e) two-pointer window scan.
/// Space: O(e) — `alerts`, the `seen_tower_ids`/`known_neighbor_ids`
/// `HashSet`s, and `reselection_timestamps` each hold at most one entry per
/// event.
#[must_use]
pub(crate) fn detect_imsi_catcher_with_config(
    events: &[CellEvent],
    config: &Config,
) -> Vec<ImsiCatcherAlert> {
    let strong_signal_dbm = config.unusually_strong_signal_dbm();
    let rapid_threshold = config.rapid_reselection_threshold();
    // WHY: bounded to [MIN_RAPID_RESELECTION_WINDOW_SECS, MAX_RAPID_RESELECTION_WINDOW_SECS]
    // (10..=3600) by the accessor, so the cast to i64 is always exact.
    let rapid_window =
        SignedDuration::from_secs(config.rapid_reselection_window_secs().cast_signed());

    let mut alerts = Vec::new();
    let mut seen_tower_ids: HashSet<(u16, u16, u32, u32)> = HashSet::new();
    let mut known_neighbor_ids: HashSet<(u16, u16, u32, u32)> = HashSet::new();
    let mut prev_serving: Option<&CellTower> = None;
    let mut reselection_timestamps: Vec<Timestamp> = Vec::new();

    for event in events {
        match event {
            CellEvent::NeighborSeen(tower) => {
                known_neighbor_ids.insert(tower.id());
                seen_tower_ids.insert(tower.id());
            }

            CellEvent::Connected(tower) => {
                // Unusually strong new tower.
                if !seen_tower_ids.contains(&tower.id()) && tower.signal_dbm > strong_signal_dbm {
                    alerts.push(ImsiCatcherAlert::UnusuallyStrongNewTower {
                        tower: tower.clone(),
                    });
                }

                // Technology downgrade from previous serving cell.
                if let Some(prev) = prev_serving
                    && is_technology_downgrade(&prev.technology, &tower.technology)
                {
                    alerts.push(ImsiCatcherAlert::TechnologyDowngrade {
                        from: prev.technology.clone(),
                        to: tower.technology.clone(),
                    });
                }

                // Track reselection: a new serving cell counts as a reselection
                // if we had a previous serving cell and the tower changed.
                if let Some(prev) = prev_serving
                    && prev.id() != tower.id()
                {
                    reselection_timestamps.push(tower.timestamp);
                }

                // #355: a cell the device has actively connected to is a
                // known handover target for future SuddenTowerChange checks,
                // the same as one seen via NeighborSeen -- real devices
                // routinely hand back to a previously-served cell without
                // the serving cell re-announcing it as a neighbour.
                seen_tower_ids.insert(tower.id());
                known_neighbor_ids.insert(tower.id());
                prev_serving = Some(tower);
            }

            CellEvent::HandoverTo(tower) => {
                // Sudden handover to a tower not in the neighbour list.
                if !known_neighbor_ids.contains(&tower.id())
                    && let Some(prev) = prev_serving
                {
                    alerts.push(ImsiCatcherAlert::SuddenTowerChange {
                        previous: prev.clone(),
                        current: tower.clone(),
                    });
                }

                // Technology downgrade.
                if let Some(prev) = prev_serving
                    && is_technology_downgrade(&prev.technology, &tower.technology)
                {
                    alerts.push(ImsiCatcherAlert::TechnologyDowngrade {
                        from: prev.technology.clone(),
                        to: tower.technology.clone(),
                    });
                }

                // Unusually strong new tower.
                if !seen_tower_ids.contains(&tower.id()) && tower.signal_dbm > strong_signal_dbm {
                    alerts.push(ImsiCatcherAlert::UnusuallyStrongNewTower {
                        tower: tower.clone(),
                    });
                }

                // Handover always counts as a reselection.
                reselection_timestamps.push(tower.timestamp);

                seen_tower_ids.insert(tower.id());
                prev_serving = Some(tower);
            }

            CellEvent::CipherChange { algorithm } => {
                // A5/0, A5/1, and A5/2 are all considered downgrades.
                if matches!(
                    algorithm,
                    CipherAlgorithm::A5_0 | CipherAlgorithm::A5_1 | CipherAlgorithm::A5_2
                ) {
                    alerts.push(ImsiCatcherAlert::CipherDowngrade {
                        algorithm: *algorithm,
                    });
                }
            }

            CellEvent::Disconnected(_) => {}
        }
    }

    // Check for rapid reselection: the maximum number of reselections that
    // fall within any single rapid_window-length span, not the raw total
    // across the whole caller-supplied slice.
    let max_in_window = max_reselections_in_window(&mut reselection_timestamps, rapid_window);
    if max_in_window >= rapid_threshold {
        alerts.push(ImsiCatcherAlert::RapidReselection {
            count: max_in_window,
        });
    }

    alerts
}

/// Largest number of `timestamps` entries that fall within any single
/// `window`-length span.
///
/// `timestamps` is sorted in place first, so callers may supply reselection
/// events in any order — including reordered or out-of-order timestamps
/// (e.g. clock skew across a buffered event log) — without affecting the
/// result. Entries sharing an identical timestamp have zero elapsed duration
/// between them and always share a window; a span exactly `window` long is
/// treated as inside the window (inclusive boundary). An empty slice yields
/// `0`.
fn max_reselections_in_window(timestamps: &mut [Timestamp], window: SignedDuration) -> u32 {
    timestamps.sort_unstable();

    let mut max_count: u32 = 0;
    let mut left = 0usize;
    for right in 0..timestamps.len() {
        while timestamps[right].duration_since(timestamps[left]) > window {
            left += 1;
        }
        // WHY try_from + saturate, not `as`: an overflow here would silently
        // wrap to a small u32 and under-report the reselection count on the
        // exact metric a threat-detection scorer thresholds against --
        // saturating to u32::MAX keeps an implausible count visibly extreme
        // rather than a plausible-looking wrong number.
        let count = u32::try_from(right - left + 1).unwrap_or(u32::MAX);
        if count > max_count {
            max_count = count;
        }
    }
    max_count
}

#[cfg(test)]
mod tests {
    use jiff::{SignedDuration, Timestamp};

    use super::*;

    fn ts() -> Timestamp {
        Timestamp::UNIX_EPOCH
    }

    /// `ts()` offset by `secs` seconds (saturating; falls back to `ts()` on
    /// the unreachable overflow path so tests never need `unwrap`/`expect`).
    fn ts_offset(secs: i64) -> Timestamp {
        Timestamp::UNIX_EPOCH
            .saturating_add(SignedDuration::from_secs(secs))
            .unwrap_or_else(|_| ts())
    }

    fn tower(cid: u32, signal_dbm: i32, technology: CellTechnology) -> CellTower {
        CellTower::new(234, 30, 1234, cid, signal_dbm, technology, ts())
    }

    fn tower_at(
        cid: u32,
        signal_dbm: i32,
        technology: CellTechnology,
        timestamp: Timestamp,
    ) -> CellTower {
        CellTower::new(234, 30, 1234, cid, signal_dbm, technology, timestamp)
    }

    // ── Existing detection tests ─────────────────────────────────────────────

    #[test]
    fn imsi_catcher_detects_lte_to_gsm_downgrade() {
        let events = [
            CellEvent::Connected(tower(1, -70, CellTechnology::Lte)),
            CellEvent::Connected(tower(2, -65, CellTechnology::Gsm)),
        ];
        let alerts = detect_imsi_catcher(&events);
        assert!(
            alerts.iter().any(|a| matches!(
                a,
                ImsiCatcherAlert::TechnologyDowngrade {
                    from: CellTechnology::Lte,
                    to: CellTechnology::Gsm,
                }
            )),
            "LTE→GSM downgrade should raise a TechnologyDowngrade alert"
        );
    }

    #[test]
    fn imsi_catcher_detects_lte_to_umts_downgrade() {
        let events = [
            CellEvent::Connected(tower(1, -70, CellTechnology::Lte)),
            CellEvent::HandoverTo(tower(2, -68, CellTechnology::Umts)),
        ];
        let alerts = detect_imsi_catcher(&events);
        assert!(
            alerts.iter().any(|a| matches!(
                a,
                ImsiCatcherAlert::TechnologyDowngrade {
                    from: CellTechnology::Lte,
                    to: CellTechnology::Umts,
                }
            )),
            "LTE→UMTS handover downgrade should raise a TechnologyDowngrade alert"
        );
    }

    #[test]
    fn imsi_catcher_detects_unusually_strong_new_tower() {
        let strong = tower(99, -30, CellTechnology::Gsm);
        let events = [CellEvent::Connected(strong.clone())];
        let alerts = detect_imsi_catcher(&events);
        assert!(
            alerts.iter().any(|a| matches!(
                a,
                ImsiCatcherAlert::UnusuallyStrongNewTower { tower: t } if t.cid == strong.cid
            )),
            "a previously-unseen tower with signal above threshold should be flagged"
        );
    }

    #[test]
    fn imsi_catcher_no_alert_for_normal_strength_new_tower() {
        let events = [CellEvent::Connected(tower(1, -80, CellTechnology::Lte))];
        let alerts = detect_imsi_catcher(&events);
        assert!(
            !alerts
                .iter()
                .any(|a| matches!(a, ImsiCatcherAlert::UnusuallyStrongNewTower { .. })),
            "a new tower with normal signal strength should not be flagged"
        );
    }

    #[test]
    fn imsi_catcher_detects_sudden_tower_change_via_handover() {
        let known = tower(1, -70, CellTechnology::Lte);
        let ghost = tower(99, -65, CellTechnology::Lte);
        let events = [
            CellEvent::Connected(known),
            // No NeighborSeen for ghost before HandoverTo.
            CellEvent::HandoverTo(ghost.clone()),
        ];
        let alerts = detect_imsi_catcher(&events);
        assert!(
            alerts.iter().any(|a| matches!(
                a,
                ImsiCatcherAlert::SuddenTowerChange { current: t, .. } if t.cid == ghost.cid
            )),
            "handover to a tower not in the neighbour list should raise SuddenTowerChange"
        );
    }

    #[test]
    fn imsi_catcher_no_sudden_change_when_tower_was_neighbor() {
        let serving = tower(1, -70, CellTechnology::Lte);
        let neighbor = tower(2, -75, CellTechnology::Lte);
        let events = [
            CellEvent::Connected(serving),
            CellEvent::NeighborSeen(neighbor.clone()),
            CellEvent::HandoverTo(neighbor),
        ];
        let alerts = detect_imsi_catcher(&events);
        assert!(
            !alerts
                .iter()
                .any(|a| matches!(a, ImsiCatcherAlert::SuddenTowerChange { .. })),
            "handover to a previously-announced neighbour should not raise SuddenTowerChange"
        );
    }

    #[test]
    fn imsi_catcher_no_sudden_change_on_handover_back_to_previously_connected_cell() {
        // #355: Connected(A) must register A as a known neighbour, so a
        // later HandoverTo(A) -- returning to a cell the device previously
        // served on, without an intervening NeighborSeen(A) -- must not
        // raise SuddenTowerChange. Real devices hand back to
        // previously-served cells during normal mobility.
        let first_cell = tower(1, -70, CellTechnology::Lte);
        let second_cell = tower(2, -72, CellTechnology::Lte);
        let events = [
            CellEvent::Connected(first_cell.clone()),
            // Reselection to another serving cell (Connected, not a
            // HandoverTo -- the latter to a never-known tower would raise
            // its own SuddenTowerChange and confound this test).
            CellEvent::Connected(second_cell),
            // Hand back to first_cell, which was only ever Connected, never
            // explicitly announced via NeighborSeen. Pre-#355 this raised a
            // false SuddenTowerChange because Connected did not register the
            // cell as a known neighbour.
            CellEvent::HandoverTo(first_cell),
        ];
        let alerts = detect_imsi_catcher(&events);
        assert!(
            !alerts
                .iter()
                .any(|a| matches!(a, ImsiCatcherAlert::SuddenTowerChange { .. })),
            "handover back to a previously-Connected cell must not raise SuddenTowerChange"
        );
    }

    #[test]
    fn imsi_catcher_no_alerts_for_normal_lte_handover_sequence() {
        let t1 = tower(1, -70, CellTechnology::Lte);
        let t2 = tower(2, -72, CellTechnology::Lte);
        let events = [
            CellEvent::Connected(t1),
            CellEvent::NeighborSeen(t2.clone()),
            CellEvent::HandoverTo(t2),
        ];
        let alerts = detect_imsi_catcher(&events);
        assert!(
            alerts.is_empty(),
            "normal LTE handover sequence should produce no alerts"
        );
    }

    // ── Cipher downgrade detection ──────────────────────────────────────────

    #[test]
    fn cipher_downgrade_a5_1_detected() {
        let events = [
            CellEvent::Connected(tower(1, -70, CellTechnology::Gsm)),
            CellEvent::CipherChange {
                algorithm: CipherAlgorithm::A5_1,
            },
        ];
        let alerts = detect_imsi_catcher(&events);
        assert!(
            alerts.iter().any(|a| matches!(
                a,
                ImsiCatcherAlert::CipherDowngrade {
                    algorithm: CipherAlgorithm::A5_1,
                }
            )),
            "A5/1 cipher must trigger CipherDowngrade alert"
        );
    }

    #[test]
    fn cipher_downgrade_a5_2_detected() {
        let events = [CellEvent::CipherChange {
            algorithm: CipherAlgorithm::A5_2,
        }];
        let alerts = detect_imsi_catcher(&events);
        assert!(
            alerts.iter().any(|a| matches!(
                a,
                ImsiCatcherAlert::CipherDowngrade {
                    algorithm: CipherAlgorithm::A5_2,
                }
            )),
            "A5/2 cipher must trigger CipherDowngrade alert"
        );
    }

    #[test]
    fn cipher_a5_0_no_encryption_detected() {
        let events = [CellEvent::CipherChange {
            algorithm: CipherAlgorithm::A5_0,
        }];
        let alerts = detect_imsi_catcher(&events);
        assert!(
            alerts.iter().any(|a| matches!(
                a,
                ImsiCatcherAlert::CipherDowngrade {
                    algorithm: CipherAlgorithm::A5_0,
                }
            )),
            "A5/0 (no encryption) must trigger CipherDowngrade alert"
        );
    }

    #[test]
    fn cipher_a5_3_no_alert() {
        let events = [CellEvent::CipherChange {
            algorithm: CipherAlgorithm::A5_3,
        }];
        let alerts = detect_imsi_catcher(&events);
        assert!(alerts.is_empty(), "A5/3 cipher must not trigger any alert");
    }

    // ── Rapid reselection detection ─────────────────────────────────────────

    #[test]
    fn rapid_reselection_three_at_threshold_triggers_alert() {
        // WHY(#554): pins the inclusive `>= threshold` semantic. The doc says
        // "3+ ... is suspicious" and the default threshold is 3, but the old
        // `> threshold` comparison required 4 to fire. All three reselections
        // share a timestamp (zero elapsed, trivially inside any window), so
        // only the threshold boundary is under test here.
        let events = [
            CellEvent::NeighborSeen(tower(2, -80, CellTechnology::Lte)),
            CellEvent::NeighborSeen(tower(3, -80, CellTechnology::Lte)),
            CellEvent::NeighborSeen(tower(4, -80, CellTechnology::Lte)),
            CellEvent::Connected(tower(1, -70, CellTechnology::Lte)),
            CellEvent::HandoverTo(tower(2, -72, CellTechnology::Lte)),
            CellEvent::HandoverTo(tower(3, -71, CellTechnology::Lte)),
            CellEvent::HandoverTo(tower(4, -73, CellTechnology::Lte)),
        ];
        let alerts = detect_imsi_catcher(&events);
        assert!(
            alerts
                .iter()
                .any(|a| matches!(a, ImsiCatcherAlert::RapidReselection { count: 3 })),
            "3 reselections at the default threshold, all within the window, \
             must trigger RapidReselection"
        );
    }

    #[test]
    fn rapid_reselection_above_threshold_triggers_alert() {
        // 4 handovers = 4 reselections, all within the default window.
        let mut events: Vec<CellEvent> = Vec::new();
        // Pre-announce neighbours.
        for cid in 1..=5 {
            events.push(CellEvent::NeighborSeen(tower(
                cid,
                -80,
                CellTechnology::Lte,
            )));
        }
        events.push(CellEvent::Connected(tower(1, -70, CellTechnology::Lte)));
        events.push(CellEvent::HandoverTo(tower(2, -72, CellTechnology::Lte)));
        events.push(CellEvent::HandoverTo(tower(3, -71, CellTechnology::Lte)));
        events.push(CellEvent::HandoverTo(tower(4, -73, CellTechnology::Lte)));
        events.push(CellEvent::HandoverTo(tower(5, -74, CellTechnology::Lte)));

        let alerts = detect_imsi_catcher(&events);
        assert!(
            alerts
                .iter()
                .any(|a| matches!(a, ImsiCatcherAlert::RapidReselection { count: 4 })),
            "4 reselections must trigger RapidReselection with count=4"
        );
    }

    #[test]
    fn rapid_reselection_spread_across_hours_no_alert() {
        // WHY(#554): pins the elapsed-time semantic. Same 4 reselections as
        // `rapid_reselection_above_threshold_triggers_alert`, but spread an
        // hour apart each -- ordinary mobility, not a burst. The old code
        // counted raw occurrences across the whole slice with no regard for
        // elapsed time and would have fired here too; the corrected sliding
        // window must not, since no single default (300s) window ever
        // contains more than one reselection.
        let mut events: Vec<CellEvent> = Vec::new();
        for cid in 1..=5 {
            events.push(CellEvent::NeighborSeen(tower(
                cid,
                -80,
                CellTechnology::Lte,
            )));
        }
        events.push(CellEvent::Connected(tower(1, -70, CellTechnology::Lte)));
        events.push(CellEvent::HandoverTo(tower_at(
            2,
            -72,
            CellTechnology::Lte,
            ts_offset(3_600),
        )));
        events.push(CellEvent::HandoverTo(tower_at(
            3,
            -71,
            CellTechnology::Lte,
            ts_offset(7_200),
        )));
        events.push(CellEvent::HandoverTo(tower_at(
            4,
            -73,
            CellTechnology::Lte,
            ts_offset(10_800),
        )));
        events.push(CellEvent::HandoverTo(tower_at(
            5,
            -74,
            CellTechnology::Lte,
            ts_offset(14_400),
        )));

        let alerts = detect_imsi_catcher(&events);
        assert!(
            !alerts
                .iter()
                .any(|a| matches!(a, ImsiCatcherAlert::RapidReselection { .. })),
            "4 reselections spread an hour apart must not trigger RapidReselection"
        );
    }

    #[test]
    fn rapid_reselection_four_events_straddling_window_boundary() {
        // WHY(#554): pins sliding-window-max semantics distinctly from a raw
        // total. 4 reselections total, but only 3 fall inside any single
        // 300s window; the boundary-exact 300s gap (0 -> 300) counts as
        // inside (inclusive boundary), while the 4th (at 450s) falls outside
        // every window that contains the first three. Must fire with
        // count=3, not the raw total of 4.
        let mut events: Vec<CellEvent> = Vec::new();
        for cid in 1..=5 {
            events.push(CellEvent::NeighborSeen(tower(
                cid,
                -80,
                CellTechnology::Lte,
            )));
        }
        events.push(CellEvent::Connected(tower(1, -70, CellTechnology::Lte)));
        events.push(CellEvent::HandoverTo(tower_at(
            2,
            -72,
            CellTechnology::Lte,
            ts_offset(0),
        )));
        events.push(CellEvent::HandoverTo(tower_at(
            3,
            -71,
            CellTechnology::Lte,
            ts_offset(150),
        )));
        events.push(CellEvent::HandoverTo(tower_at(
            4,
            -73,
            CellTechnology::Lte,
            ts_offset(300),
        )));
        events.push(CellEvent::HandoverTo(tower_at(
            5,
            -74,
            CellTechnology::Lte,
            ts_offset(450),
        )));

        let alerts = detect_imsi_catcher(&events);
        assert!(
            alerts
                .iter()
                .any(|a| matches!(a, ImsiCatcherAlert::RapidReselection { count: 3 })),
            "the windowed max must be 3 (boundary-inclusive), not the raw total of 4"
        );
    }

    #[test]
    fn rapid_reselection_reordered_timestamps_still_detected() {
        // WHY(#554): pins robustness to out-of-order/reordered timestamps
        // (e.g. clock skew across a buffered event log). Array order (which
        // drives handover-chain bookkeeping) stays causal, but the
        // timestamps attached to each event are not monotonically
        // increasing with array position.
        let mut events: Vec<CellEvent> = Vec::new();
        for cid in 1..=4 {
            events.push(CellEvent::NeighborSeen(tower(
                cid,
                -80,
                CellTechnology::Lte,
            )));
        }
        events.push(CellEvent::Connected(tower(1, -70, CellTechnology::Lte)));
        events.push(CellEvent::HandoverTo(tower_at(
            2,
            -72,
            CellTechnology::Lte,
            ts_offset(200),
        )));
        events.push(CellEvent::HandoverTo(tower_at(
            3,
            -71,
            CellTechnology::Lte,
            ts_offset(0),
        )));
        events.push(CellEvent::HandoverTo(tower_at(
            4,
            -73,
            CellTechnology::Lte,
            ts_offset(100),
        )));

        let alerts = detect_imsi_catcher(&events);
        assert!(
            alerts
                .iter()
                .any(|a| matches!(a, ImsiCatcherAlert::RapidReselection { count: 3 })),
            "out-of-order timestamps within the window must still be detected as a burst"
        );
    }

    #[test]
    fn rapid_reselection_repeated_identical_tower_not_counted() {
        // WHY(#554): a re-report of the same serving cell is not a
        // reselection; the id-change guard must still hold once counting
        // moved from a plain increment to timestamp collection.
        let events = [
            CellEvent::Connected(tower_at(1, -70, CellTechnology::Lte, ts_offset(0))),
            CellEvent::Connected(tower_at(1, -70, CellTechnology::Lte, ts_offset(10))),
            CellEvent::Connected(tower_at(1, -70, CellTechnology::Lte, ts_offset(20))),
        ];
        let alerts = detect_imsi_catcher(&events);
        assert!(
            !alerts
                .iter()
                .any(|a| matches!(a, ImsiCatcherAlert::RapidReselection { .. })),
            "repeated reports of the same serving cell must not accumulate as reselections"
        );
    }

    #[test]
    fn rapid_reselection_ping_pong_between_two_towers_triggers_alert() {
        // WHY(#554): oscillating between the same two towers is a distinct
        // real-world burst signature and must still be detected -- each
        // actual id change counts even though both ids have been seen
        // before.
        let events = [
            CellEvent::NeighborSeen(tower(2, -80, CellTechnology::Lte)),
            CellEvent::Connected(tower_at(1, -70, CellTechnology::Lte, ts_offset(0))),
            CellEvent::HandoverTo(tower_at(2, -72, CellTechnology::Lte, ts_offset(30))),
            CellEvent::HandoverTo(tower_at(1, -70, CellTechnology::Lte, ts_offset(60))),
            CellEvent::HandoverTo(tower_at(2, -72, CellTechnology::Lte, ts_offset(90))),
        ];
        let alerts = detect_imsi_catcher(&events);
        assert!(
            alerts
                .iter()
                .any(|a| matches!(a, ImsiCatcherAlert::RapidReselection { count: 3 })),
            "oscillating handovers between two towers must accumulate as reselections"
        );
    }

    // ── Weighted threat scoring ─────────────────────────────────────────────

    #[test]
    fn score_threat_no_alerts_is_low() {
        let score = score_threat(&[]);
        assert_eq!(score.total, 0, "no alerts must produce score 0");
        assert_eq!(score.level, ThreatLevel::Low, "score 0 must be Low");
        assert!(
            score.factors.is_empty(),
            "no alerts must produce no factors"
        );
    }

    #[test]
    fn score_threat_cipher_downgrade_is_medium() {
        let alerts = [ImsiCatcherAlert::CipherDowngrade {
            algorithm: CipherAlgorithm::A5_1,
        }];
        let score = score_threat(&alerts);
        assert_eq!(score.total, 40, "cipher downgrade weight must be 40");
        assert_eq!(score.level, ThreatLevel::Medium, "score 40 must be Medium");
        assert_eq!(score.factors.len(), 1, "one alert must produce one factor");
        assert_eq!(
            score.factors[0].name, "cipher_downgrade",
            "factor name must be cipher_downgrade"
        );
    }

    #[test]
    fn score_threat_strong_tower_is_low() {
        let alerts = [ImsiCatcherAlert::UnusuallyStrongNewTower {
            tower: tower(99, -30, CellTechnology::Gsm),
        }];
        let score = score_threat(&alerts);
        assert_eq!(score.total, 20, "strong tower weight must be 20");
        assert_eq!(score.level, ThreatLevel::Low, "score 20 must be Low");
    }

    #[test]
    fn score_threat_sudden_tower_is_medium() {
        let alerts = [ImsiCatcherAlert::SuddenTowerChange {
            previous: tower(1, -70, CellTechnology::Lte),
            current: tower(99, -65, CellTechnology::Lte),
        }];
        let score = score_threat(&alerts);
        assert_eq!(score.total, 30, "sudden tower change weight must be 30");
        assert_eq!(score.level, ThreatLevel::Medium, "score 30 must be Medium");
    }

    #[test]
    fn score_threat_rapid_reselection_is_low() {
        let alerts = [ImsiCatcherAlert::RapidReselection { count: 5 }];
        let score = score_threat(&alerts);
        assert_eq!(score.total, 10, "rapid reselection weight must be 10");
        assert_eq!(score.level, ThreatLevel::Low, "score 10 must be Low");
    }

    #[test]
    fn score_threat_repeated_kind_gets_harmonic_discount() {
        // #555 correlation model: three RapidReselection alerts are
        // correlated observations of churn, not three independent events.
        // Contributions: 10/1 + 10/2 + 10/3 = 10 + 5 + 3 = 18, NOT 30.
        let alerts = [
            ImsiCatcherAlert::RapidReselection { count: 3 },
            ImsiCatcherAlert::RapidReselection { count: 4 },
            ImsiCatcherAlert::RapidReselection { count: 5 },
        ];
        let score = score_threat(&alerts);
        assert_eq!(
            score.total, 18,
            "repeated kind must score harmonically (10 + 5 + 3), not independently (30)"
        );
        assert_eq!(score.level, ThreatLevel::Low);
        let weights: Vec<u32> = score.factors.iter().map(|f| f.weight).collect();
        assert_eq!(weights, [10, 5, 3], "factor weights must be w, w/2, w/3");
    }

    #[test]
    fn score_threat_repeated_strong_towers_do_not_stack_to_critical() {
        // #555: the pre-model failure mode — five benign-but-strong tower
        // sightings (dense-urban RF churn) stacking to 100 = Critical.
        // Harmonic: 20 + 10 + 6 + 5 + 4 = 45 (Medium), still provisional
        // but no longer a fabricated Critical from correlated noise.
        let alerts: Vec<ImsiCatcherAlert> = (1..=5)
            .map(|cid| ImsiCatcherAlert::UnusuallyStrongNewTower {
                tower: tower(cid, -40, CellTechnology::Lte),
            })
            .collect();
        let score = score_threat(&alerts);
        assert_eq!(score.total, 45, "harmonic sum 20+10+6+5+4 = 45");
        assert_eq!(score.level, ThreatLevel::Medium);
    }

    #[test]
    fn score_threat_distinct_kinds_still_sum_fully() {
        // The discount applies WITHIN a kind; distinct kinds are
        // independent observations and sum at full weight.
        let alerts = [
            ImsiCatcherAlert::RapidReselection { count: 3 },
            ImsiCatcherAlert::RapidReselection { count: 4 },
            ImsiCatcherAlert::UnusuallyStrongNewTower {
                tower: tower(9, -40, CellTechnology::Lte),
            },
        ];
        let score = score_threat(&alerts);
        assert_eq!(score.total, 35, "10 + 5 (harmonic) + 20 (full) = 35");
    }

    #[test]
    fn score_threat_ships_uncalibrated() {
        // #555: no score may exist without stating its provenance.
        let alerts = [ImsiCatcherAlert::RapidReselection { count: 3 }];
        let score = score_threat(&alerts);
        assert_eq!(score.calibration, Calibration::Uncalibrated);
        assert!(format!("{score}").contains("UNCALIBRATED"));
    }

    #[test]
    fn score_threat_combined_high() {
        // Cipher downgrade (40) + sudden tower (30) = 70 → High.
        let alerts = [
            ImsiCatcherAlert::CipherDowngrade {
                algorithm: CipherAlgorithm::A5_1,
            },
            ImsiCatcherAlert::SuddenTowerChange {
                previous: tower(1, -70, CellTechnology::Lte),
                current: tower(99, -65, CellTechnology::Lte),
            },
        ];
        let score = score_threat(&alerts);
        assert_eq!(score.total, 70, "cipher(40) + sudden(30) must equal 70");
        assert_eq!(score.level, ThreatLevel::High, "score 70 must be High");
        assert_eq!(
            score.factors.len(),
            2,
            "two alerts must produce two factors"
        );
    }

    #[test]
    fn score_threat_combined_critical() {
        // Cipher downgrade (40) + sudden tower (30) + strong tower (20) = 90 → Critical.
        let alerts = [
            ImsiCatcherAlert::CipherDowngrade {
                algorithm: CipherAlgorithm::A5_2,
            },
            ImsiCatcherAlert::SuddenTowerChange {
                previous: tower(1, -70, CellTechnology::Lte),
                current: tower(99, -65, CellTechnology::Lte),
            },
            ImsiCatcherAlert::UnusuallyStrongNewTower {
                tower: tower(99, -30, CellTechnology::Gsm),
            },
        ];
        let score = score_threat(&alerts);
        assert_eq!(
            score.total, 90,
            "cipher(40) + sudden(30) + strong(20) must equal 90"
        );
        assert_eq!(
            score.level,
            ThreatLevel::Critical,
            "score 90 must be Critical"
        );
    }

    #[test]
    fn score_threat_boundary_values() {
        // Verify exact boundary thresholds.
        assert_eq!(level_from_score(0), ThreatLevel::Low, "score 0 must be Low");
        assert_eq!(
            level_from_score(29),
            ThreatLevel::Low,
            "score 29 must be Low"
        );
        assert_eq!(
            level_from_score(30),
            ThreatLevel::Medium,
            "score 30 must be Medium"
        );
        assert_eq!(
            level_from_score(59),
            ThreatLevel::Medium,
            "score 59 must be Medium"
        );
        assert_eq!(
            level_from_score(60),
            ThreatLevel::High,
            "score 60 must be High"
        );
        assert_eq!(
            level_from_score(79),
            ThreatLevel::High,
            "score 79 must be High"
        );
        assert_eq!(
            level_from_score(80),
            ThreatLevel::Critical,
            "score 80 must be Critical"
        );
        assert_eq!(
            level_from_score(u32::MAX),
            ThreatLevel::Critical,
            "max score must be Critical"
        );
    }

    #[test]
    fn score_threat_tech_downgrade_weight() {
        let alerts = [ImsiCatcherAlert::TechnologyDowngrade {
            from: CellTechnology::Lte,
            to: CellTechnology::Gsm,
        }];
        let score = score_threat(&alerts);
        assert_eq!(score.total, 40, "technology downgrade weight must be 40");
        assert_eq!(
            score.factors[0].name, "tech_downgrade",
            "factor name must be tech_downgrade"
        );
    }

    // ── Display impls ────────────────────────────────────────────────────────

    #[test]
    fn threat_level_display() {
        assert_eq!(ThreatLevel::Low.to_string(), "LOW");
        assert_eq!(ThreatLevel::Medium.to_string(), "MEDIUM");
        assert_eq!(ThreatLevel::High.to_string(), "HIGH");
        assert_eq!(ThreatLevel::Critical.to_string(), "CRITICAL");
    }

    #[test]
    fn threat_score_display() {
        let score = ThreatScore {
            total: 70,
            level: ThreatLevel::High,
            factors: vec![
                ThreatFactor {
                    name: "test_a",
                    weight: 40,
                    description: "first".to_owned(),
                },
                ThreatFactor {
                    name: "test_b",
                    weight: 30,
                    description: "second".to_owned(),
                },
            ],
            calibration: Calibration::Uncalibrated,
        };
        let display = format!("{score}");
        assert!(display.contains("70"), "display must contain total score");
        assert!(
            display.contains("HIGH"),
            "display must contain threat level"
        );
        assert!(
            display.contains("2 factors"),
            "display must contain factor count"
        );
        assert!(
            display.contains("UNCALIBRATED"),
            "display must carry the calibration marker (#555) so no score reads as validated severity"
        );
    }

    #[test]
    fn cipher_algorithm_display() {
        assert_eq!(CipherAlgorithm::A5_0.to_string(), "A5/0 (no encryption)");
        assert_eq!(CipherAlgorithm::A5_1.to_string(), "A5/1");
        assert_eq!(CipherAlgorithm::A5_2.to_string(), "A5/2");
        assert_eq!(CipherAlgorithm::A5_3.to_string(), "A5/3");
        assert_eq!(CipherAlgorithm::A5_4.to_string(), "A5/4");
    }

    #[test]
    fn imsi_catcher_alert_display() {
        let alert = ImsiCatcherAlert::CipherDowngrade {
            algorithm: CipherAlgorithm::A5_1,
        };
        let display = format!("{alert}");
        assert!(
            display.contains("A5/1"),
            "CipherDowngrade display must mention the algorithm"
        );

        let alert = ImsiCatcherAlert::RapidReselection { count: 7 };
        let display = format!("{alert}");
        assert!(
            display.contains('7'),
            "RapidReselection display must mention the count"
        );
    }

    // ── End-to-end: detect + score ──────────────────────────────────────────

    // ── Config-driven behaviour ─────────────────────────────────────────────

    #[test]
    fn strict_dbm_threshold_flags_tower_default_would_accept() {
        // WHY: prove Config.unusually_strong_signal_dbm flows through to detection.
        // A tower at -65 dBm is accepted by the default (-50) threshold but
        // should trigger under a stricter (-80) profile an agent might choose
        // while operating in Sentinel mode.
        let events = [CellEvent::Connected(tower(1, -65, CellTechnology::Lte))];

        let defaults = detect_imsi_catcher(&events);
        assert!(
            !defaults
                .iter()
                .any(|a| matches!(a, ImsiCatcherAlert::UnusuallyStrongNewTower { .. })),
            "default -50 dBm threshold must not flag a -65 dBm tower"
        );

        let strict = detect_imsi_catcher_with_config(
            &events,
            &Config {
                unusually_strong_signal_dbm: -80,
                ..Config::default()
            },
        );
        assert!(
            strict
                .iter()
                .any(|a| matches!(a, ImsiCatcherAlert::UnusuallyStrongNewTower { .. })),
            "stricter -80 dBm threshold must flag a -65 dBm tower"
        );
    }

    #[test]
    fn custom_weight_changes_threat_total() {
        // WHY: prove Config.weight_* flows through to score_threat. Doubling the
        // cipher-downgrade weight must double the score contribution.
        let alerts = [ImsiCatcherAlert::CipherDowngrade {
            algorithm: CipherAlgorithm::A5_1,
        }];
        let doubled = score_threat_with_config(
            &alerts,
            &Config {
                weight_cipher_downgrade: 80,
                ..Config::default()
            },
        );
        assert_eq!(
            doubled.total, 80,
            "doubled cipher-downgrade weight must produce total 80"
        );
        assert_eq!(
            doubled.level,
            ThreatLevel::Critical,
            "score 80 must be Critical"
        );
    }

    #[test]
    fn detect_and_score_combined_attack_scenario() {
        // Simulate: LTE connection, cipher downgrade to A5/1, then rapid
        // handovers to unannounced towers with strong signals.
        let events = vec![
            CellEvent::Connected(tower(1, -70, CellTechnology::Lte)),
            CellEvent::CipherChange {
                algorithm: CipherAlgorithm::A5_1,
            },
            CellEvent::HandoverTo(tower(10, -30, CellTechnology::Gsm)),
            CellEvent::HandoverTo(tower(11, -28, CellTechnology::Gsm)),
            CellEvent::HandoverTo(tower(12, -25, CellTechnology::Gsm)),
            CellEvent::HandoverTo(tower(13, -27, CellTechnology::Gsm)),
        ];

        let alerts = detect_imsi_catcher(&events);
        let score = score_threat(&alerts);

        // Expected alerts: cipher downgrade, tech downgrade, 4x sudden tower,
        // 4x strong tower, rapid reselection, plus tech downgrade on subsequent
        // GSM handovers (only first is a downgrade from LTE).
        assert_eq!(
            score.level,
            ThreatLevel::Critical,
            "full attack scenario must produce Critical threat level"
        );
        assert!(
            score.total >= 80,
            "full attack scenario score must be >= 80, got {}",
            score.total
        );
        assert!(
            alerts
                .iter()
                .any(|a| matches!(a, ImsiCatcherAlert::CipherDowngrade { .. })),
            "must detect cipher downgrade"
        );
        assert!(
            alerts
                .iter()
                .any(|a| matches!(a, ImsiCatcherAlert::RapidReselection { .. })),
            "must detect rapid reselection"
        );
    }
}
