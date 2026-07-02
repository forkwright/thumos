//! Host-test stub for the ARM-only `timer` module (ARM generic timer, CP15).
//!
//! The real `timer` module reads CNTFRQ/CNTPCT via CP15 (`mrc`/`mrrc`), which
//! is ARM-only. Under test this stub returns fixed, sane values so the
//! `time::sys_clock_gettime` conversion path is host-compilable, exposing only
//! the API that host-testable modules reference.
//!
//! WHY(pattern): a gated-out hardware dependency is made test-visible by a
//! parallel `#[cfg(test)] #[path = "..._stub.rs"] mod x;` binding in main.rs.

/// CNTFRQ stub: a plausible fixed MT6739 counter frequency (13 MHz).
///
/// WHY non-zero: `counter_to_timespec` and `monotonic_secs` guard against a
/// zero frequency (divide-by-zero) by returning zero; a non-zero value keeps
/// the conversion path meaningful under test.
pub(crate) fn frequency() -> u32 {
    13_000_000
}

/// CNTPCT stub: a fixed non-zero counter value (≈ 1 s at the stub frequency).
pub(crate) fn counter() -> u64 {
    13_000_000
}
