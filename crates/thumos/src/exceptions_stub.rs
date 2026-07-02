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
//! Extend this stub (e.g. `uptime_ms`) as further modules — syscall, time —
//! are un-gated for host testing.

/// Timer-IRQ tick counter.
///
/// The production counter advances on every timer interrupt; on the host there
/// is no timer, so ticks are fixed at zero. The only host-test consumer is the
/// scheduler's sleeping-process wake check (`schedule`), whose logic tests do
/// not depend on tick progression.
pub(crate) fn ticks() -> u64 {
    0
}
