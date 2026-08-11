//! Deterministic replay/evaluation harness for the IMSI-catcher detector
//! (#555).
//!
//! The detector's weights and thresholds are provisional constants. The only
//! honest path to calibrated ones is evaluation over a versioned,
//! privacy-safe trace corpus (`crates/sema/corpus/*.toml`): each scenario
//! carries its provenance (synthetic vs field-measured) and a labeled
//! target level; [`evaluate`] replays the alerts through
//! [`score_threat_with_config`] and reports per-scenario outcomes plus the
//! corpus-level false-positive / false-negative sets. Deterministic: no
//! wall clock, no randomness, no I/O beyond the corpus files the tests load.
//!
//! What this harness deliberately does NOT do: learn weights. An optimizer
//! over this report is the calibration work that follows; until a corpus
//! version + operating point + measured error budget are recorded in
//! [`Calibration::Calibrated`], every score stays `Uncalibrated` (#555).

use serde::{Deserialize, Serialize};

use crate::cell::{
    CellTechnology, CellTower, CipherAlgorithm, ImsiCatcherAlert, ThreatLevel,
    score_threat_with_config,
};
use crate::config::Config;

/// Scenario kinds the corpus must eventually cover with field data (#555).
/// Today every entry is synthetic; the kind is what future field traces map
/// onto, not a claim about current provenance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ScenarioKind {
    /// Device stationary, ordinary home macro coverage.
    BenignStationary,
    /// Ordinary mobility at driving speed.
    Driving,
    /// Dense-urban RF churn (many strong neighbor cells).
    DenseUrban,
    /// A carrier femtocell / small cell appears nearby.
    Femtocell,
    /// Roaming onto a foreign network.
    Roaming,
    /// Serving-cell outage and recovery.
    Outage,
    /// A controlled attack emulation (red-team / faraday-cage IMSI catcher).
    ControlledAttack,
}

/// A corpus scenario: a replayable alert sequence plus the labeled truth.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Scenario {
    /// Corpus schema version (1).
    pub(crate) schema_version: u32,
    /// Unique scenario identifier.
    pub(crate) id: String,
    /// Scenario kind (drives the positive/negative classification).
    pub(crate) kind: ScenarioKind,
    /// Where this trace came from — "synthetic" entries say so loudly;
    /// field traces must name the collection session and privacy review.
    pub(crate) provenance: String,
    /// The labeled target: the level a calibrated scorer SHOULD produce.
    pub(crate) target_level: ThreatLevel,
    /// The alert sequence to replay (already privacy-minimized).
    #[serde(default)]
    pub(crate) alerts: Vec<AlertSpec>,
}

/// A TOML-friendly alert description. Towers are synthetic placeholders —
/// scoring reads the alert KIND and its parameters, never real cell IDs
/// (privacy: no real LAC/CID/measurements in the corpus).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case", tag = "kind")]
pub(crate) enum AlertSpec {
    /// Cipher downgrade to the named algorithm.
    CipherDowngrade {
        /// A5 algorithm negotiated.
        algorithm: CipherAlgorithm,
    },
    /// Radio-technology downgrade (e.g. LTE → GSM).
    TechnologyDowngrade,
    /// Handover to an unannounced tower.
    SuddenTowerChange,
    /// Unknown tower at an unusually strong signal.
    UnusuallyStrongNewTower {
        /// Advertised signal strength, dBm.
        signal_dbm: i32,
    },
    /// Coerced-reselection burst.
    RapidReselection {
        /// Reselections in the observation window.
        count: u32,
    },
}

impl AlertSpec {
    /// Realize the spec as a scored alert (synthetic tower fields).
    const fn to_alert(&self) -> ImsiCatcherAlert {
        match self {
            Self::CipherDowngrade { algorithm } => ImsiCatcherAlert::CipherDowngrade {
                algorithm: *algorithm,
            },
            Self::TechnologyDowngrade => ImsiCatcherAlert::TechnologyDowngrade {
                from: CellTechnology::Lte,
                to: CellTechnology::Gsm,
            },
            Self::SuddenTowerChange => ImsiCatcherAlert::SuddenTowerChange {
                previous: CellTower::new(
                    0,
                    0,
                    0,
                    0,
                    -70,
                    CellTechnology::Lte,
                    jiff::Timestamp::UNIX_EPOCH,
                ),
                current: CellTower::new(
                    0,
                    0,
                    0,
                    0,
                    -70,
                    CellTechnology::Lte,
                    jiff::Timestamp::UNIX_EPOCH,
                ),
            },
            Self::UnusuallyStrongNewTower { signal_dbm } => {
                ImsiCatcherAlert::UnusuallyStrongNewTower {
                    tower: CellTower::new(
                        0,
                        0,
                        0,
                        0,
                        *signal_dbm,
                        CellTechnology::Lte,
                        jiff::Timestamp::UNIX_EPOCH,
                    ),
                }
            }
            Self::RapidReselection { count } => {
                ImsiCatcherAlert::RapidReselection { count: *count }
            }
        }
    }
}

/// One scenario's evaluated outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScenarioOutcome {
    /// Scenario id.
    pub(crate) id: String,
    /// Scenario kind.
    pub(crate) kind: ScenarioKind,
    /// Score the current weights produce.
    pub(crate) total: u32,
    /// Level the current thresholds produce.
    pub(crate) level: ThreatLevel,
    /// The labeled target level.
    pub(crate) target: ThreatLevel,
    /// Whether the produced level meets the target's expectation class:
    /// benign kinds must score AT or BELOW target, attack kinds AT or ABOVE.
    pub(crate) pass: bool,
}

/// The corpus-level evaluation report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EvalReport {
    /// Per-scenario outcomes, corpus order.
    pub(crate) outcomes: Vec<ScenarioOutcome>,
    /// Benign scenarios whose level exceeded the target (false positives).
    pub(crate) false_positives: Vec<String>,
    /// Attack scenarios whose level fell below the target (false negatives).
    pub(crate) false_negatives: Vec<String>,
}

impl EvalReport {
    /// Precision at the corpus level: detected-as-attack scenarios that are
    /// attack scenarios. `None` when nothing was detected as attack.
    pub(crate) fn precision_milli(&self) -> Option<u32> {
        let detected: Vec<&ScenarioOutcome> = self
            .outcomes
            .iter()
            .filter(|o| o.level >= ThreatLevel::Medium)
            .collect();
        if detected.is_empty() {
            return None;
        }
        let true_pos = detected
            .iter()
            .filter(|o| o.kind == ScenarioKind::ControlledAttack)
            .count();
        // INVARIANT: true_pos counts a filtered subset of `detected`, so
        // true_pos <= detected.len() always -- the quotient is bounded to
        // [0, 1000] by integer-division identity regardless of corpus size,
        // well within u32 on any platform.
        Some((true_pos * 1000 / detected.len()) as u32)
    }

    /// Recall at the corpus level: attack scenarios detected as attack.
    /// `None` when the corpus has no attack scenarios.
    pub(crate) fn recall_milli(&self) -> Option<u32> {
        let attacks: Vec<&ScenarioOutcome> = self
            .outcomes
            .iter()
            .filter(|o| o.kind == ScenarioKind::ControlledAttack)
            .collect();
        if attacks.is_empty() {
            return None;
        }
        let found = attacks
            .iter()
            .filter(|o| o.level >= ThreatLevel::Medium)
            .count();
        // INVARIANT: found counts a filtered subset of `attacks`, so
        // found <= attacks.len() always -- the quotient is bounded to
        // [0, 1000] by integer-division identity regardless of corpus size,
        // well within u32 on any platform.
        Some((found * 1000 / attacks.len()) as u32)
    }
}

/// Replay every scenario through the scorer at `config` and report outcomes.
pub(crate) fn evaluate(scenarios: &[Scenario], config: &Config) -> EvalReport {
    let mut outcomes = Vec::new();
    let mut false_positives = Vec::new();
    let mut false_negatives = Vec::new();

    for scenario in scenarios {
        let alerts: Vec<ImsiCatcherAlert> =
            scenario.alerts.iter().map(AlertSpec::to_alert).collect();
        let score = score_threat_with_config(&alerts, config);
        let is_attack = scenario.kind == ScenarioKind::ControlledAttack;
        let pass = if is_attack {
            score.level >= scenario.target_level
        } else {
            score.level <= scenario.target_level
        };
        if !pass && is_attack {
            false_negatives.push(scenario.id.clone());
        } else if !pass {
            false_positives.push(scenario.id.clone());
        }
        outcomes.push(ScenarioOutcome {
            id: scenario.id.clone(),
            kind: scenario.kind,
            total: score.total,
            level: score.level,
            target: scenario.target_level,
            pass,
        });
    }

    EvalReport {
        outcomes,
        false_positives,
        false_negatives,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn corpus_dir() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("corpus")
    }

    /// Load every corpus entry from a directory of TOML files, sorted by
    /// file name for determinism. Unreadable/unparseable entries are
    /// skipped; the corpus tests assert the exact expected count, so a
    /// broken file fails loudly there (the workspace lint set forbids
    /// panic!/expect anywhere, tests included).
    fn load_corpus(dir: &std::path::Path) -> Vec<Scenario> {
        let mut files: Vec<_> = std::fs::read_dir(dir)
            .map(|rd| {
                rd.filter_map(std::result::Result::ok)
                    .map(|e| e.path())
                    .collect()
            })
            .unwrap_or_default();
        files.sort();
        files
            .iter()
            .filter(|p| p.extension().is_some_and(|x| x == "toml"))
            .filter_map(|p| std::fs::read_to_string(p).ok())
            .filter_map(|text| toml::from_str::<Scenario>(&text).ok())
            .collect()
    }

    #[test]
    fn corpus_parses_and_covers_required_kinds() {
        let scenarios = load_corpus(&corpus_dir());
        assert_eq!(
            scenarios.len(),
            7,
            "every corpus file must load (a parse/IO failure shows here): {scenarios:?}"
        );
        for kind in [
            ScenarioKind::BenignStationary,
            ScenarioKind::Driving,
            ScenarioKind::DenseUrban,
            ScenarioKind::Femtocell,
            ScenarioKind::Roaming,
            ScenarioKind::Outage,
            ScenarioKind::ControlledAttack,
        ] {
            assert!(
                scenarios.iter().any(|s| s.kind == kind),
                "corpus must contain a {kind:?} scenario"
            );
        }
        for s in &scenarios {
            assert_eq!(s.schema_version, 1, "{}: schema version", s.id);
            assert!(
                s.provenance.contains("synthetic"),
                "{}: provenance must declare its class (field traces must name their session)",
                s.id
            );
        }
    }

    #[test]
    fn corpus_evaluation_is_deterministic() {
        let scenarios = load_corpus(&corpus_dir());
        let a = evaluate(&scenarios, &Config::default());
        let b = evaluate(&scenarios, &Config::default());
        assert_eq!(a, b, "the harness must be deterministic");
    }

    #[test]
    fn benign_core_scenarios_stay_low_at_current_weights() {
        // Ordinary benign traces must not fabricate attack detections.
        // The documented RESIDUAL false positives (dense-urban, roaming —
        // see corpus_evaluates_residual_fps) are excluded here on purpose.
        let scenarios = load_corpus(&corpus_dir());
        let report = evaluate(&scenarios, &Config::default());
        for outcome in &report.outcomes {
            if matches!(
                outcome.kind,
                ScenarioKind::BenignStationary
                    | ScenarioKind::Driving
                    | ScenarioKind::Femtocell
                    | ScenarioKind::Outage
            ) {
                assert!(
                    outcome.level <= ThreatLevel::Low,
                    "benign scenario {} must not score above Low (got {:?} at {})",
                    outcome.id,
                    outcome.level,
                    outcome.total
                );
            }
        }
    }

    #[test]
    fn corpus_evaluates_residual_fps_honestly() {
        // Dense-urban and roaming are the documented residual false-positive
        // classes at the provisional weights (the harmonic model BOUNDS
        // dense-urban at Medium instead of the old fabricated Critical;
        // closing both to Low is calibration work, tracked by this report).
        let scenarios = load_corpus(&corpus_dir());
        let report = evaluate(&scenarios, &Config::default());
        assert!(
            report
                .false_positives
                .iter()
                .any(|id| id == "dense-urban-01"),
            "dense-urban must be counted as a residual FP: {:?}",
            report.false_positives
        );
        assert!(
            report.false_positives.iter().any(|id| id == "roaming-01"),
            "roaming must be counted as a residual FP: {:?}",
            report.false_positives
        );
        assert_eq!(
            report.false_positives.len(),
            2,
            "exactly the two documented residual FPs"
        );
        // The harness reports the degraded precision these FPs cause:
        // 1 attack detected out of 3 attack-band scenarios.
        assert_eq!(report.precision_milli(), Some(333));
    }

    #[test]
    fn controlled_attack_is_detected_at_current_weights() {
        let scenarios = load_corpus(&corpus_dir());
        let report = evaluate(&scenarios, &Config::default());
        assert!(
            report.false_negatives.is_empty(),
            "the controlled attack must be detected: {:?}",
            report.false_negatives
        );
        assert_eq!(report.recall_milli(), Some(1000), "recall on the corpus");
    }

    #[test]
    fn harmonic_model_bounds_dense_urban_fp() {
        // The pre-#555 independent-sum model stacked five strong-tower
        // sightings to Critical (100). The harmonic model bounds the same
        // trace at Medium — still above the Low target (an honest residual
        // FP the calibration work must close), but no longer a fabricated
        // Critical. This test pins the MODEL's effect, not the constants.
        let scenario = Scenario {
            schema_version: 1,
            id: "dense-urban-model-check".to_owned(),
            kind: ScenarioKind::DenseUrban,
            provenance: "synthetic (#555)".to_owned(),
            target_level: ThreatLevel::Low,
            alerts: (0..5)
                .map(|_| AlertSpec::UnusuallyStrongNewTower { signal_dbm: -40 })
                .collect(),
        };
        let report = evaluate(&[scenario], &Config::default());
        assert_eq!(report.outcomes[0].total, 45, "20+10+6+5+4 harmonic bound");
        assert_eq!(report.outcomes[0].level, ThreatLevel::Medium);
    }
}
