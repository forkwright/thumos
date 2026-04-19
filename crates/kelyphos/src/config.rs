//! Behavioral tuning parameters for the WMT driver.
//!
//! Covers tuning knobs for the STP UART transport (retransmit timing, retry
//! budget) and for the WMT power-on state machine (register-poll iteration
//! cap). These are runtime knobs — an agent should be able to choose
//! aggressive timeouts on known-good hardware or relaxed timeouts when the
//! combo chip is thermally stressed, without recompiling.
//!
//! Protocol invariants (STP [`WINDOW_SIZE`], SOF byte, `MAX_PAYLOAD`,
//! CONSYS register addresses, chip-ID expectation) remain as
//! [`crate::transport`] / [`crate::wmt`] compile-time `const` values.
//!
//! [`WINDOW_SIZE`]: crate::transport::WINDOW_SIZE

// ── STP transport tuning ──────────────────────────────────────────────────────

/// Default TX timeout in milliseconds before a frame is assumed lost and
/// retransmitted.
///
/// Source: `stp_core.h` reference value; tuned for a 921 600 baud BTIF UART
/// with up to two software hops in the driver.
pub const DEFAULT_TX_TIMEOUT_MS: u32 = 180;

/// Minimum accepted TX timeout.
///
/// Source: below 10 ms, the UART round-trip plus STP framing time consumes
/// more than the timeout budget, producing spurious retransmits.
pub const MIN_TX_TIMEOUT_MS: u32 = 10;

/// Maximum accepted TX timeout.
///
/// Source: 10 s is the practical ceiling; beyond this, a lost ACK causes the
/// whole radio subsystem to appear hung rather than erroring cleanly.
pub const MAX_TX_TIMEOUT_MS: u32 = 10_000;

/// Default maximum retransmissions per frame before the link is declared dead.
///
/// Source: `stp_core.h` reference value. 10 retries at 180 ms is roughly 2 s
/// of "give up early" budget; 0 would declare the link dead on every lost ACK.
pub const DEFAULT_RETRY_LIMIT: u8 = 10;

/// Minimum accepted retry limit.
///
/// Source: retrying at least once absorbs a single lost ACK; zero is a
/// configuration error.
pub const MIN_RETRY_LIMIT: u8 = 1;

/// Maximum accepted retry limit.
///
/// Source: 64 retries at the maximum 10 s timeout would stall the link for
/// over 10 minutes; beyond this the parameter has effectively disabled
/// link-dead detection.
pub const MAX_RETRY_LIMIT: u8 = 64;

// ── WMT register-poll tuning ──────────────────────────────────────────────────

/// Default maximum poll iterations before a hardware ack is declared timed
/// out in the CONSYS power-on sequence.
///
/// Source: empirical — 1 000 iterations of a register read completes in
/// well under 1 ms on a 1.2 GHz Cortex-A53, which is generous for ack
/// registers the hardware sets within nanoseconds.
pub const DEFAULT_POLL_TIMEOUT_ITERS: u32 = 1_000;

/// Minimum accepted poll iteration count.
///
/// Source: below 100 the hardware may not have time to latch the ack bit on
/// a cold-boot cache-miss read, producing spurious `PowerAckTimeout` errors.
pub const MIN_POLL_TIMEOUT_ITERS: u32 = 100;

/// Maximum accepted poll iteration count.
///
/// Source: 1 million iterations is about 1 second of busy-wait on a 1 GHz
/// core; beyond this, a stuck-bit ack produces an unusable hang rather than
/// a clean error.
pub const MAX_POLL_TIMEOUT_ITERS: u32 = 1_000_000;

// ── Config ────────────────────────────────────────────────────────────────────

/// Runtime-tunable knobs for the kelyphos WMT driver.
///
/// [`Default`] reproduces the historical `const` behaviour, so adopting
/// `Config` is a no-op for callers that do not override anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Config {
    /// STP TX timeout in milliseconds before a frame is retransmitted.
    ///
    /// **Affects:** throughput vs. retransmit rate under packet loss.
    /// **Evidence:** measured UART round-trip time in the target environment.
    /// **Bounds:** `[MIN_TX_TIMEOUT_MS, MAX_TX_TIMEOUT_MS]`.
    pub tx_timeout_ms: u32,

    /// Maximum STP retransmissions before the link is declared dead.
    ///
    /// **Affects:** time-to-detect link failure vs. resilience to loss bursts.
    /// **Bounds:** `[MIN_RETRY_LIMIT, MAX_RETRY_LIMIT]`.
    pub retry_limit: u8,

    /// Maximum poll iterations before a CONSYS hardware ack is declared
    /// timed out.
    ///
    /// **Affects:** boot-time responsiveness vs. tolerance for slow ack latch.
    /// **Bounds:** `[MIN_POLL_TIMEOUT_ITERS, MAX_POLL_TIMEOUT_ITERS]`.
    pub poll_timeout_iters: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            tx_timeout_ms: DEFAULT_TX_TIMEOUT_MS,
            retry_limit: DEFAULT_RETRY_LIMIT,
            poll_timeout_iters: DEFAULT_POLL_TIMEOUT_ITERS,
        }
    }
}

impl Config {
    /// TX timeout clamped to the accepted domain range.
    #[must_use]
    pub fn tx_timeout_ms(&self) -> u32 {
        bounded_u32(
            self.tx_timeout_ms,
            DEFAULT_TX_TIMEOUT_MS,
            MIN_TX_TIMEOUT_MS,
            MAX_TX_TIMEOUT_MS,
            "tx_timeout_ms",
        )
    }

    /// Retry limit clamped to the accepted domain range.
    #[must_use]
    pub fn retry_limit(&self) -> u8 {
        let v = self.retry_limit;
        if (MIN_RETRY_LIMIT..=MAX_RETRY_LIMIT).contains(&v) {
            v
        } else {
            log::warn!(
                "retry_limit={v} out of range [{MIN_RETRY_LIMIT}, \
                 {MAX_RETRY_LIMIT}]; using default {DEFAULT_RETRY_LIMIT}",
            );
            DEFAULT_RETRY_LIMIT
        }
    }

    /// Poll iteration count clamped to the accepted domain range.
    #[must_use]
    pub fn poll_timeout_iters(&self) -> u32 {
        bounded_u32(
            self.poll_timeout_iters,
            DEFAULT_POLL_TIMEOUT_ITERS,
            MIN_POLL_TIMEOUT_ITERS,
            MAX_POLL_TIMEOUT_ITERS,
            "poll_timeout_iters",
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_matches_historical_constants() {
        let c = Config::default();
        assert_eq!(c.tx_timeout_ms, 180);
        assert_eq!(c.retry_limit, 10);
        assert_eq!(c.poll_timeout_iters, 1_000);
    }

    #[test]
    fn tx_timeout_accessor_clamps_zero() {
        let c = Config {
            tx_timeout_ms: 0,
            ..Config::default()
        };
        assert_eq!(c.tx_timeout_ms(), DEFAULT_TX_TIMEOUT_MS);
    }

    #[test]
    fn tx_timeout_accessor_clamps_huge() {
        let c = Config {
            tx_timeout_ms: u32::MAX,
            ..Config::default()
        };
        assert_eq!(c.tx_timeout_ms(), DEFAULT_TX_TIMEOUT_MS);
    }

    #[test]
    fn retry_limit_accessor_clamps_zero() {
        let c = Config {
            retry_limit: 0,
            ..Config::default()
        };
        assert_eq!(c.retry_limit(), DEFAULT_RETRY_LIMIT);
    }

    #[test]
    fn poll_iters_accessor_clamps_tiny() {
        let c = Config {
            poll_timeout_iters: 1,
            ..Config::default()
        };
        assert_eq!(c.poll_timeout_iters(), DEFAULT_POLL_TIMEOUT_ITERS);
    }

    #[test]
    fn accessors_pass_valid_values() {
        let c = Config {
            tx_timeout_ms: 500,
            retry_limit: 5,
            poll_timeout_iters: 10_000,
        };
        assert_eq!(c.tx_timeout_ms(), 500);
        assert_eq!(c.retry_limit(), 5);
        assert_eq!(c.poll_timeout_iters(), 10_000);
    }
}
