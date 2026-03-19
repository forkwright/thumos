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

/// Signal strength threshold above which a previously-unseen tower is considered
/// suspiciously strong. IMSI catchers are often deployed close to the target and
/// deliberately transmit at high power.
const UNUSUALLY_STRONG_SIGNAL_DBM: i32 = -50;

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

/// Analyse a sequence of cell events for IMSI catcher signatures.
///
/// Three patterns are detected:
///
/// - **Technology downgrade**: any `Connected` or `HandoverTo` event that transitions
///   the device to a lower-capability radio technology.
/// - **Unusually strong new tower**: a `Connected` or `HandoverTo` event where the tower
///   has never been seen before and its signal exceeds [`UNUSUALLY_STRONG_SIGNAL_DBM`].
/// - **Sudden tower change**: a `HandoverTo` event to a tower that was never previously
///   announced via `NeighborSeen`, suggesting an abnormal handover.
///
/// Events are processed in order; `NeighborSeen` events accumulate a set of known
/// neighbours used to evaluate subsequent handovers.
#[must_use]
pub fn detect_imsi_catcher(events: &[CellEvent]) -> Vec<ImsiCatcherAlert> {
    let mut alerts = Vec::new();
    let mut seen_tower_ids: HashSet<(u16, u16, u32, u32)> = HashSet::new();
    let mut known_neighbor_ids: HashSet<(u16, u16, u32, u32)> = HashSet::new();
    let mut prev_serving: Option<&CellTower> = None;

    for event in events {
        match event {
            CellEvent::NeighborSeen(tower) => {
                known_neighbor_ids.insert(tower.id());
                seen_tower_ids.insert(tower.id());
            }

            CellEvent::Connected(tower) => {
                // Unusually strong new tower.
                if !seen_tower_ids.contains(&tower.id())
                    && tower.signal_dbm > UNUSUALLY_STRONG_SIGNAL_DBM
                {
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
                if !seen_tower_ids.contains(&tower.id())
                    && tower.signal_dbm > UNUSUALLY_STRONG_SIGNAL_DBM
                {
                    alerts.push(ImsiCatcherAlert::UnusuallyStrongNewTower {
                        tower: tower.clone(),
                    });
                }

                seen_tower_ids.insert(tower.id());
                prev_serving = Some(tower);
            }

            CellEvent::Disconnected(_) => {}
        }
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
}
