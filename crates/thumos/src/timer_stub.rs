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

/// Host-test mirror of the production `elapsed_ms` computation (mirrors
/// `timer::elapsed_ms` exactly, but composed from the stub `frequency`/
/// `counter` above so host-tested callers like `ccci::boot_modem`'s
/// deadline check are host-compilable).
pub(crate) fn elapsed_ms() -> u64 {
    let freq = u64::from(frequency());
    if freq == 0 {
        return 0;
    }
    (counter() * 1000) / freq
}

/// Host-test mirror of the production `set_ms` tick-conversion arithmetic.
/// `timer::set_ms` itself is ARM-only (it also programs `CNTP_TVAL/CNTP_CTL`
/// via CP15, which does not exist on the host target); this mirrors just
/// the overflow-safety fix so it has host-test coverage. Kept in lockstep
/// with the arithmetic in `timer::set_ms`.
pub(crate) fn ms_to_ticks(freq: u32, ms: u32) -> u32 {
    (freq / 1000).saturating_mul(ms)
}

/// Host-test mirror of the production `elapsed_ms` conversion arithmetic.
/// `timer::elapsed_ms` itself is ARM-only (it calls the CP15 `frequency`/
/// `counter` accessors, neither of which exist on the host target -- this
/// module fully replaces `timer` under `#[cfg(test)]`, see main.rs); this
/// mirrors just the counter-to-ms conversion, including the zero-frequency
/// guard, so it has host-test coverage. Kept in lockstep with the
/// arithmetic in `timer::elapsed_ms`.
pub(crate) fn elapsed_ms_from(counter: u64, freq: u32) -> u64 {
    let freq = u64::from(freq);
    if freq == 0 {
        return 0;
    }
    (counter * 1000) / freq
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ms_to_ticks_saturates_instead_of_overflowing() {
        // At 13 MHz, ms values past ~330_382 overflow a plain
        // `(freq / 1000) * ms` multiplication in u32.
        let freq = 13_000_000;
        let ticks = ms_to_ticks(freq, u32::MAX);
        assert_eq!(
            ticks,
            u32::MAX,
            "an overflowing delay must saturate at u32::MAX ticks, not wrap"
        );
    }

    #[test]
    fn ms_to_ticks_matches_plain_multiply_below_overflow() {
        let freq = 13_000_000;
        assert_eq!(ms_to_ticks(freq, 100), (freq / 1000) * 100);
    }

    #[test]
    fn elapsed_ms_from_converts_counter_to_milliseconds() {
        // At 13 MHz, one second of counter ticks (13_000_000) must convert
        // to 1000 ms, matching `timer::elapsed_ms`'s (counter * 1000) / freq.
        assert_eq!(elapsed_ms_from(13_000_000, 13_000_000), 1_000);
    }

    #[test]
    fn elapsed_ms_from_returns_zero_when_frequency_is_zero() {
        // Guards the divide-by-zero the production function also guards
        // against (an uncalibrated/unread CNTFRQ before boot).
        assert_eq!(elapsed_ms_from(1_000_000, 0), 0);
    }

    #[test]
    fn elapsed_ms_from_zero_counter_is_zero_elapsed() {
        assert_eq!(elapsed_ms_from(0, 13_000_000), 0);
    }
}
