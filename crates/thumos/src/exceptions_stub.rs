//! Host-test stub for the ARM-only `exceptions` module.
//!
//! The real `exceptions` module installs the CP15 vector table, drives the
//! GIC, and maintains the timer-IRQ tick counter — none of which exist on the
//! host test target. This stub supplies the subset of the `exceptions` API
//! that host-testable modules reference, so those modules compile and run
//! under `cargo nextest` without pulling in gic/timer/uart/watchdog.
//!
//! WHY(pattern): a gated-out hardware dependency is made test-visible by a
//! parallel `#[cfg(test)] #[path = "..._stub.rs"] mod x;` binding in main.rs.

use core::sync::atomic::{AtomicU64, Ordering};

/// Timer tick interval in milliseconds. Mirrors the production
/// `exceptions::TICK_MS` so `uptime_ms` keeps the same ticks×interval
/// relationship on the host.
const TICK_MS: u64 = 10;

/// Settable host-test tick source.
///
/// Production advances its tick counter from the timer IRQ; on the host there
/// is no timer, so tests drive this value directly.
///
/// WHY settable: a constant-zero tick is a landmine for any scheduler/time
/// logic that compares the current tick against a future wake tick — the
/// comparison is trivially satisfied (or never satisfied) regardless of the
/// code under test. A test that needs elapsed/monotonic progression sets this
/// explicitly via [`set_ticks`] / [`advance_ticks`].
static TICKS: AtomicU64 = AtomicU64::new(0);

/// Timer-IRQ tick counter (reads the settable host-test source).
pub(crate) fn ticks() -> u64 {
    TICKS.load(Ordering::Relaxed)
}

/// Uptime in milliseconds derived from the tick counter (ticks × `TICK_MS`),
/// matching the production `exceptions::uptime_ms` relationship.
pub(crate) fn uptime_ms() -> u64 {
    ticks() * TICK_MS
}

/// Test helper: set the tick counter to an absolute value.
#[expect(
    dead_code,
    reason = "settable-tick API for scheduler/time host tests; provided for the un-gating seam, not yet exercised by an un-gated test (test-fixture)"
)]
pub(crate) fn set_ticks(value: u64) {
    TICKS.store(value, Ordering::Relaxed);
}

/// Test helper: advance the tick counter by `delta` ticks.
#[expect(
    dead_code,
    reason = "settable-tick API for scheduler/time host tests; provided for the un-gating seam, not yet exercised by an un-gated test (test-fixture)"
)]
pub(crate) fn advance_ticks(delta: u64) {
    TICKS.fetch_add(delta, Ordering::Relaxed);
}

/// Host-test mirror of the production `exceptions::ticks()` seqlock-lite
/// combine logic. The real `exceptions` module is ARM-only and entirely
/// swapped for this stub under test, so its `TICK_COUNT_HI`/`TICK_COUNT_LO`
/// statics are not reachable from a host test; this pure function is kept
/// in lockstep with the read in `exceptions::ticks()` so the torn-read fix
/// has host-test coverage.
///
/// Given a hi-lo-hi read triple, returns the combined 64-bit tick count if
/// the two `hi` reads agree (no writer carried into `hi` between them), or
/// `None` if the reader must retry.
pub(crate) fn combine_tick_halves(hi1: u32, lo: u32, hi2: u32) -> Option<u64> {
    if hi1 == hi2 {
        Some((u64::from(hi1) << 32) | u64::from(lo))
    } else {
        None
    }
}

/// Host-test mirror of the production tick-increment carry logic in
/// `exceptions::irq_handler_rust`'s timer-tick branch. Given the current
/// hi/lo halves, returns the incremented pair, carrying into `hi` when
/// `lo` wraps. Kept in lockstep with the write in `irq_handler_rust` so the
/// carry-on-overflow path (previously untested) has host-test coverage.
pub(crate) fn advance_tick_halves(hi: u32, lo: u32) -> (u32, u32) {
    let (new_lo, carried) = lo.overflowing_add(1);
    let new_hi = if carried { hi.wrapping_add(1) } else { hi };
    (new_hi, new_lo)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn combine_tick_halves_returns_value_when_hi_stable() {
        assert_eq!(combine_tick_halves(0, 42, 0), Some(42));
        assert_eq!(combine_tick_halves(1, 0, 1), Some(1u64 << 32));
    }

    #[test]
    fn combine_tick_halves_signals_retry_on_torn_read() {
        // hi changed between the two reads (a carry from a LO wraparound
        // occurred mid-read) -- the reader must retry, not return a torn
        // combination of the pre- and post-carry halves.
        assert_eq!(combine_tick_halves(0, 0xFFFF_FFFF, 1), None);
    }

    #[test]
    fn advance_tick_halves_increments_lo_without_carry() {
        assert_eq!(advance_tick_halves(0, 41), (0, 42));
    }

    #[test]
    fn advance_tick_halves_carries_into_hi_on_lo_wraparound() {
        assert_eq!(advance_tick_halves(0, u32::MAX), (1, 0));
    }
}
