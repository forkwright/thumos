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
    reason = "settable-tick API for scheduler/time host tests; provided for the un-gating seam, not yet exercised by an un-gated test"
)]
pub(crate) fn set_ticks(value: u64) {
    TICKS.store(value, Ordering::Relaxed);
}

/// Test helper: advance the tick counter by `delta` ticks.
#[expect(
    dead_code,
    reason = "settable-tick API for scheduler/time host tests; provided for the un-gating seam, not yet exercised by an un-gated test"
)]
pub(crate) fn advance_ticks(delta: u64) {
    TICKS.fetch_add(delta, Ordering::Relaxed);
}
