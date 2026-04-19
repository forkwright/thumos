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

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::config::Config;

/// Radio access technology generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum CellTechnology {
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
pub struct CellTower {
    /// Mobile Country Code (3 decimal digits, e.g. 234 for UK).
    pub mcc: u16,
    /// Mobile Network Code (2–3 decimal digits).
    pub mnc: u16,
    /// Location Area Code (2G/3G) or Tracking Area Code (4G).
    pub lac: u32,
    /// Cell Identity.
    pub cid: u32,
    /// Received signal strength in dBm (higher is stronger).
    pub signal_dbm: i32,
    /// Radio access technology generation.
    pub technology: CellTechnology,
    /// Wall-clock time when this tower was observed.
    pub timestamp: Timestamp,
}

/// An event in the device's cell tower history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum CellEvent {
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
pub enum ImsiCatcherAlert {
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
    /// Rapid cell reselection: the device has been forced to reselect cells
    /// more than [`Config::rapid_reselection_threshold`] times within the
    /// observation window.
    RapidReselection {
        /// Number of reselections observed.
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
pub enum CipherAlgorithm {
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

/// Threat level derived from the cumulative [`ThreatScore`].
///
/// Thresholds: `<30` Low, `30–59` Medium, `60–79` High, `≥80` Critical.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[must_use]
#[non_exhaustive]
pub enum ThreatLevel {
    /// Score below 30. Normal operating conditions.
    Low,
    /// Score 30–59. Suspicious activity detected.
    Medium,
    /// Score 60–79. Likely IMSI catcher or active attack.
    High,
    /// Score 80+. Multiple strong indicators of an active attack.
    Critical,
}

impl core::fmt::Display for ThreatLevel {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Low => f.write_str("LOW"),
            Self::Medium => f.write_str("MEDIUM"),
            Self::High => f.write_str("HIGH"),
            Self::Critical => f.write_str("CRITICAL"),
        }
    }
}

/// A contributing factor to the overall [`ThreatScore`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreatFactor {
    /// Short identifier for this factor (e.g. `cipher_downgrade`).
    pub name: &'static str,
    /// Numeric weight this factor contributes to the total score.
    pub weight: u32,
    /// Human-readable description of what was detected.
    pub description: String,
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
pub struct ThreatScore {
    /// Cumulative numeric score.
    pub total: u32,
    /// Threat level derived from `total`.
    pub level: ThreatLevel,
    /// Individual contributing factors.
    pub factors: Vec<ThreatFactor>,
}

impl core::fmt::Display for ThreatScore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "threat score {}: {} ({} factor{})",
            self.total,
            self.level,
            self.factors.len(),
            if self.factors.len() == 1 { "" } else { "s" },
        )
    }
}

/// Derive a [`ThreatLevel`] from a numeric score.
const fn level_from_score(score: u32) -> ThreatLevel {
    match score {
        0..30 => ThreatLevel::Low,
        30..60 => ThreatLevel::Medium,
        60..80 => ThreatLevel::High,
        _ => ThreatLevel::Critical,
    }
}

/// Compute a weighted [`ThreatScore`] using [`Config::default`] weights.
///
/// Each alert type maps to a weight defined by the active [`Config`]; see
/// [`score_threat_with_config`] for the configurable form.
pub fn score_threat(alerts: &[ImsiCatcherAlert]) -> ThreatScore {
    score_threat_with_config(alerts, &Config::default())
}

/// Compute a weighted [`ThreatScore`] using explicit [`Config`] weights.
///
/// Supplying a non-default `config` observably changes the per-alert weights
/// in the result and can move the overall [`ThreatLevel`] boundary. This is
/// the primary entry point for agents tuning detection policy.
pub fn score_threat_with_config(alerts: &[ImsiCatcherAlert], config: &Config) -> ThreatScore {
    let mut total: u32 = 0;
    let mut factors = Vec::new();

    let w_cipher = config.weight_cipher_downgrade();
    let w_lac_cid = config.weight_unusual_lac_cid();
    let w_abnormal = config.weight_abnormal_signal();
    let w_rapid = config.weight_rapid_reselection();

    for alert in alerts {
        let (name, weight, description) = match alert {
            ImsiCatcherAlert::TechnologyDowngrade { from, to } => (
                "tech_downgrade",
                w_cipher,
                format!("technology downgrade: {from} → {to}"),
            ),
            ImsiCatcherAlert::CipherDowngrade { algorithm } => (
                "cipher_downgrade",
                w_cipher,
                format!("weak cipher negotiated: {algorithm}"),
            ),
            ImsiCatcherAlert::SuddenTowerChange { previous, current } => (
                "unusual_lac_cid",
                w_lac_cid,
                format!(
                    "handover to unannounced tower: LAC {} CID {} → LAC {} CID {}",
                    previous.lac, previous.cid, current.lac, current.cid
                ),
            ),
            ImsiCatcherAlert::UnusuallyStrongNewTower { tower } => (
                "abnormal_signal",
                w_abnormal,
                format!(
                    "unknown tower at {} dBm (CID {})",
                    tower.signal_dbm, tower.cid
                ),
            ),
            ImsiCatcherAlert::RapidReselection { count } => (
                "rapid_reselection",
                w_rapid,
                format!("{count} cell reselections in observation window"), // kanon:ignore STORAGE/sql-string-concat -- false positive: "reselections" contains "SELECT" substring; this is a human-readable alert string, not SQL. kanon:ignore RUST/format-sql -- same rationale
            ),
        };

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
    }
}

impl CellTower {
    /// Construct a [`CellTower`] with all fields.
    pub const fn new(
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
pub fn detect_imsi_catcher(events: &[CellEvent]) -> Vec<ImsiCatcherAlert> {
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
/// - **Rapid reselection**: more than [`Config::rapid_reselection_threshold`]
///   serving cell changes across `Connected` and `HandoverTo` events.
///
/// Events are processed in order; `NeighborSeen` events accumulate a set of known
/// neighbours used to evaluate subsequent handovers.
#[must_use]
pub fn detect_imsi_catcher_with_config(
    events: &[CellEvent],
    config: &Config,
) -> Vec<ImsiCatcherAlert> {
    let strong_signal_dbm = config.unusually_strong_signal_dbm();
    let rapid_threshold = config.rapid_reselection_threshold();

    let mut alerts = Vec::new();
    let mut seen_tower_ids: HashSet<(u16, u16, u32, u32)> = HashSet::new();
    let mut known_neighbor_ids: HashSet<(u16, u16, u32, u32)> = HashSet::new();
    let mut prev_serving: Option<&CellTower> = None;
    let mut reselection_count: u32 = 0;

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
                    reselection_count = reselection_count.saturating_add(1);
                }

                seen_tower_ids.insert(tower.id());
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
                reselection_count = reselection_count.saturating_add(1);

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

    // Check for rapid reselection after processing all events.
    if reselection_count > rapid_threshold {
        alerts.push(ImsiCatcherAlert::RapidReselection {
            count: reselection_count,
        });
    }

    alerts
}

#[cfg(test)]
mod tests {
    use jiff::Timestamp;

    use super::*;

    fn ts() -> Timestamp {
        Timestamp::UNIX_EPOCH
    }

    fn tower(cid: u32, signal_dbm: i32, technology: CellTechnology) -> CellTower {
        CellTower::new(234, 30, 1234, cid, signal_dbm, technology, ts())
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
    fn rapid_reselection_below_threshold_no_alert() {
        // 3 reselections = at threshold, should NOT trigger (> threshold required).
        let events = [
            CellEvent::Connected(tower(1, -70, CellTechnology::Lte)),
            CellEvent::HandoverTo(tower(2, -72, CellTechnology::Lte)),
            CellEvent::HandoverTo(tower(3, -71, CellTechnology::Lte)),
            CellEvent::HandoverTo(tower(4, -73, CellTechnology::Lte)),
        ];
        // Pre-announce towers as neighbours to avoid SuddenTowerChange noise.
        let mut full_events = vec![
            CellEvent::NeighborSeen(tower(2, -80, CellTechnology::Lte)),
            CellEvent::NeighborSeen(tower(3, -80, CellTechnology::Lte)),
            CellEvent::NeighborSeen(tower(4, -80, CellTechnology::Lte)),
        ];
        full_events.extend_from_slice(&events);
        let alerts = detect_imsi_catcher(&full_events);
        assert!(
            !alerts
                .iter()
                .any(|a| matches!(a, ImsiCatcherAlert::RapidReselection { .. })),
            "3 reselections (at threshold) must not trigger RapidReselection"
        );
    }

    #[test]
    fn rapid_reselection_above_threshold_triggers_alert() {
        // 4 handovers = 4 reselections, above threshold of 3.
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
