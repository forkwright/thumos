#![no_std]
//! sema-core: the canonical threat-semantics types (#545).
//!
//! This crate is the single home of [`ThreatLevel`], [`Calibration`], and
//! the band boundaries between them, shared by the `sema` workspace crate
//! (the IMSI-catcher detector + evaluation harness) and the thumos kernel
//! (the threat screen's display bands). It exists because the two sides
//! drifted: the kernel's screen mapped scores at 25/50/75 while `sema`'s
//! protocol invariants are 30/60/80 — one protocol, one implementation.
//!
//! `no_std` + alloc so the bare-metal kernel can link it via a path
//! dependency; nothing here performs I/O.

extern crate alloc;

use alloc::string::String;

use serde::{Deserialize, Serialize};

/// Threat level derived from a cumulative threat score.
///
/// Thresholds (protocol invariants, changing them is a semver break):
/// `<30` Low, `30–59` Medium, `60–79` High, `≥80` Critical. Their MEANING
/// is provisional until the score behind them is `Calibration::Calibrated`
/// (#555): the bands name score ranges, not yet validated detection
/// confidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[must_use]
#[non_exhaustive]
pub enum ThreatLevel {
    /// Score below 30. Normal operating conditions (provisional band).
    Low,
    /// Score 30–59. Suspicious activity band (provisional).
    Medium,
    /// Score 60–79. High band — labeled "likely IMSI catcher" only after
    /// calibration establishes what the band actually separates (#555).
    High,
    /// Score 80+. Critical band (provisional; see High).
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

/// The canonical band edges (the protocol invariants, #545/#555).
pub(crate) const MEDIUM_AT: u32 = 30;
/// High begins at this score.
pub(crate) const HIGH_AT: u32 = 60;
/// Critical begins at this score.
pub(crate) const CRITICAL_AT: u32 = 80;

/// Derive a [`ThreatLevel`] from a numeric score — the ONE boundary table.
pub const fn level_from_score(score: u32) -> ThreatLevel {
    match score {
        0..MEDIUM_AT => ThreatLevel::Low,
        MEDIUM_AT..HIGH_AT => ThreatLevel::Medium,
        HIGH_AT..CRITICAL_AT => ThreatLevel::High,
        _ => ThreatLevel::Critical,
    }
}

/// Calibration provenance of a threat score (#555).
///
/// The detector's weights and thresholds ship as provisional defaults with
/// no retained calibration corpus or evaluation behind them. Until the
/// evaluation harness (`sema::eval`) reports an operating point over a
/// versioned trace corpus, every score must be presented as UNCALIBRATED —
/// never as validated operational severity. Any future automatic response
/// must match on `Calibrated` before it may act.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[must_use]
#[non_exhaustive]
pub enum Calibration {
    /// Weights/thresholds are the provisional hand-maintained defaults; no
    /// corpus-backed evaluation has established an operating point.
    Uncalibrated,
    /// Weights/thresholds were derived from the named corpus version at the
    /// recorded operating point, satisfying the recorded error budget.
    Calibrated {
        /// Version identifier of the trace corpus the evaluation ran over.
        corpus: String,
        /// The operating point (weight set + thresholds) the evaluation
        /// selected, in config-serializable form.
        operating_point: String,
        /// The measured error rates at that operating point
        /// (false-positive and false-negative rates, per mille).
        error_budget_per_mille: (u32, u32),
    },
}

impl core::fmt::Display for Calibration {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Uncalibrated => f.write_str("UNCALIBRATED"),
            Self::Calibrated { corpus, .. } => write!(f, "calibrated({corpus})"),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use alloc::borrow::ToOwned;
    use alloc::format;
    use alloc::string::ToString;

    use super::*;

    #[test]
    fn band_boundaries_are_the_canonical_30_60_80() {
        assert_eq!(level_from_score(0), ThreatLevel::Low);
        assert_eq!(level_from_score(29), ThreatLevel::Low);
        assert_eq!(level_from_score(30), ThreatLevel::Medium);
        assert_eq!(level_from_score(59), ThreatLevel::Medium);
        assert_eq!(level_from_score(60), ThreatLevel::High);
        assert_eq!(level_from_score(79), ThreatLevel::High);
        assert_eq!(level_from_score(80), ThreatLevel::Critical);
        assert_eq!(level_from_score(u32::MAX), ThreatLevel::Critical);
    }

    #[test]
    fn labels_are_stable() {
        assert_eq!(ThreatLevel::Low.to_string(), "LOW");
        assert_eq!(ThreatLevel::Medium.to_string(), "MEDIUM");
        assert_eq!(ThreatLevel::High.to_string(), "HIGH");
        assert_eq!(ThreatLevel::Critical.to_string(), "CRITICAL");
        assert_eq!(Calibration::Uncalibrated.to_string(), "UNCALIBRATED");
    }

    #[test]
    fn calibration_carries_corpus_provenance() {
        let c = Calibration::Calibrated {
            corpus: "corpus-v1".to_owned(),
            operating_point: "defaults".to_owned(),
            error_budget_per_mille: (50, 10),
        };
        assert!(format!("{c}").contains("corpus-v1"));
    }
}
