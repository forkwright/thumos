//! Behavioral tuning parameters for key management.
//!
//! Every value here is a runtime knob — moved out of `const` so operators and
//! agents can tune without recompiling. Protocol invariants (AES key/tag
//! lengths, PBKDF2 HMAC-SHA256 output length) stay as compile-time `const`
//! in [`crate::keys`].
//!
//! # Guards
//!
//! Per `PARAMETERS.md`, every parameter has:
//! - A `DEFAULT_*` constant with a rationale comment
//! - A `MIN_*` / `MAX_*` bound grounded in the domain, not the wire type
//! - A bounded accessor that clamps invalid values and logs the fallback

/// Default PBKDF2 iteration count for primary-key derivation.
///
/// Source: NIST SP 800-132 recommends ≥ 10 000 for PBKDF2-HMAC-SHA256; 100 000
/// is a practical 2026 minimum that still completes under 500 ms on the
/// MT6739 Cortex-A53 cores. OWASP (2023) recommends 600 000 for desktop
/// hardware; we sit below that to keep mobile unlock responsive.
pub(crate) const DEFAULT_PBKDF2_ITERATIONS: u32 = 100_000;

/// Minimum accepted PBKDF2 iteration count.
///
/// Source: NIST SP 800-132 §5.2 hard floor. Below 1 000, brute-force search
/// becomes trivial on commodity hardware.
pub(crate) const MIN_PBKDF2_ITERATIONS: u32 = 1_000;

/// Maximum accepted PBKDF2 iteration count.
///
/// Domain bound: 10 000 000 iterations on an A53 core takes > 30 s, which is
/// a UX failure regardless of security benefit. Above this we log and clamp.
pub(crate) const MAX_PBKDF2_ITERATIONS: u32 = 10_000_000;

/// Runtime-tunable knobs for [`crate::keys`] key sealing and derivation.
///
/// All fields have [`Default`] values that reproduce the historical `const`
/// behaviour, so adopting `Config` is a no-op for callers that do not set
/// anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Config {
    /// PBKDF2-HMAC-SHA256 iteration count used when sealing a new key slot.
    ///
    /// **What it affects:** time to unlock on boot, resistance to brute force.
    /// **Evidence to change:** measured unlock latency, threat-model update.
    /// **Bounds:** `[MIN_PBKDF2_ITERATIONS, MAX_PBKDF2_ITERATIONS]`.
    pub(crate) pbkdf2_iterations: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            pbkdf2_iterations: DEFAULT_PBKDF2_ITERATIONS,
        }
    }
}

impl Config {
    /// Iteration count clamped to the accepted domain range.
    ///
    /// Out-of-range values log at `warn` and fall back to
    /// [`DEFAULT_PBKDF2_ITERATIONS`] per the standard.
    #[must_use]
    pub(crate) fn pbkdf2_iterations(self) -> u32 {
        let v = self.pbkdf2_iterations;
        if (MIN_PBKDF2_ITERATIONS..=MAX_PBKDF2_ITERATIONS).contains(&v) {
            v
        } else {
            log::warn!(
                "pbkdf2_iterations={v} out of range [{MIN_PBKDF2_ITERATIONS}, \
                 {MAX_PBKDF2_ITERATIONS}]; using default {DEFAULT_PBKDF2_ITERATIONS}",
            );
            DEFAULT_PBKDF2_ITERATIONS
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_matches_historical_const() {
        // WHY: the historical const was 100_000; changing Default would be a silent
        // behaviour change for every existing caller of seal_key.
        assert_eq!(Config::default().pbkdf2_iterations, 100_000);
    }

    #[test]
    fn accessor_clamps_below_minimum() {
        let cfg = Config {
            pbkdf2_iterations: 0,
        };
        assert_eq!(cfg.pbkdf2_iterations(), DEFAULT_PBKDF2_ITERATIONS);
    }

    #[test]
    fn accessor_clamps_above_maximum() {
        let cfg = Config {
            pbkdf2_iterations: u32::MAX,
        };
        assert_eq!(cfg.pbkdf2_iterations(), DEFAULT_PBKDF2_ITERATIONS);
    }

    #[test]
    fn accessor_passes_valid_values_through() {
        let cfg = Config {
            pbkdf2_iterations: 600_000,
        };
        assert_eq!(cfg.pbkdf2_iterations(), 600_000);
    }

    #[test]
    fn minimum_boundary_accepted() {
        let cfg = Config {
            pbkdf2_iterations: MIN_PBKDF2_ITERATIONS,
        };
        assert_eq!(cfg.pbkdf2_iterations(), MIN_PBKDF2_ITERATIONS);
    }

    #[test]
    fn maximum_boundary_accepted() {
        let cfg = Config {
            pbkdf2_iterations: MAX_PBKDF2_ITERATIONS,
        };
        assert_eq!(cfg.pbkdf2_iterations(), MAX_PBKDF2_ITERATIONS);
    }
}
