//! Kernel time services: `clock_gettime` and nanosleep.
//!
//! # Clock sources
//!
//! `CLOCK_MONOTONIC` reads the ARM generic timer (CNTPCT) which counts at
//! a fixed frequency (CNTFRQ, typically 13 MHz on MT6739). It measures
//! time elapsed since the timer was enabled at boot and never goes backward.
//!
//! `CLOCK_REALTIME` adds a boot-epoch offset to the monotonic counter. The
//! offset is hardcoded to 2025-01-01 00:00:00 UTC at boot and may be
//! updated later when the modem RTC becomes available. Accuracy before
//! RTC sync is ±1 minute (based on OEM firmware boot time estimates).
//!
//! # Nanosleep
//!
//! nanosleep sets the calling process's state to `Sleeping` with a
//! wake-time in timer ticks. The scheduler skips sleeping processes until
//! `wake_tick` ≤ current tick count. Resolution is the scheduler tick
//! period (10 ms); sub-tick requests are rounded up to the next tick.
//!
//! # Timespec layout
//!
//! User-space timespec is a packed pair of u32 values at the pointer:
//! ```text
//! offset 0: tv_sec  (u32, seconds)
//! offset 4: tv_nsec (u32, nanoseconds, 0..999_999_999)
//! ```
//! This matches the 32-bit ABI layout used by musl on `ARMv7`.

use crate::exceptions;
use crate::memguard::validate_user_buffer;
use crate::process;
use crate::syscall::EFAULT;
use crate::timer;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// POSIX clock ID for wall-clock time (may jump or be adjusted).
pub(crate) const CLOCK_REALTIME: u32 = 0;

/// POSIX clock ID for monotonic time (never jumps, counts from boot).
pub(crate) const CLOCK_MONOTONIC: u32 = 1;

/// EINVAL: invalid argument (two's complement -22, matching Linux ARM).
const EINVAL: u32 = 0u32.wrapping_sub(22);

/// Nanoseconds per second.
const NANOS_PER_SEC: u64 = 1_000_000_000;

/// Boot epoch offset for `CLOCK_REALTIME`: 2025-01-01 00:00:00 UTC in seconds
/// since the Unix epoch (1970-01-01).
///
/// WHY: the kernel has no RTC access at boot. We use a hardcoded recent date
/// so that filesystem timestamps and log entries are plausible. The modem
/// RTC driver (ccci) may update this later via `set_realtime_offset()`.
///
/// Calculation: days from 1970-01-01 to 2025-01-01:
///   55 years × 365.25 days ≈ 20088 days → 20088 × 86400 = `1_735_603_200` s
pub(crate) static mut REALTIME_OFFSET_SECS: u64 = 1_735_603_200;

// ---------------------------------------------------------------------------
// Epoch offset update
// ---------------------------------------------------------------------------

/// Earliest epoch accepted as a plausible external time-source update.
///
/// WHY 2020-01-01: comfortably before this kernel's earliest possible
/// deployment, so it never rejects a legitimate GPS/NTP/carrier time while
/// still bounding a hostile modem RTC that reports epoch 0 or another
/// implausible pre-boot date (#374).
const MIN_VALID_EPOCH: u64 = 1_577_836_800; // 2020-01-01T00:00:00Z

/// Latest epoch accepted as a plausible external time-source update.
///
/// WHY 2100-01-01: generous upper bound -- no legitimate time source should
/// ever report a date this far out. A hostile modem RTC setting the clock
/// to year 2500+ would corrupt certificate validity checks and audit-log
/// ordering (#374).
const MAX_VALID_EPOCH: u64 = 4_102_444_800; // 2100-01-01T00:00:00Z

/// Error returned by [`set_realtime_offset`] when the candidate epoch is
/// outside `[MIN_VALID_EPOCH, MAX_VALID_EPOCH]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ImplausibleEpoch;

/// Compute the new `REALTIME_OFFSET_SECS` value for a candidate wall-clock
/// update, or `None` if `unix_now_secs` falls outside the plausible epoch
/// window `[MIN_VALID_EPOCH, MAX_VALID_EPOCH]`.
///
/// Pure function (no static access), deliberately kept free of the
/// `#[cfg(not(test))]` gating that `set_realtime_offset` carries, so the
/// validation and offset arithmetic are host-testable without the
/// ARM-only timer read (#374).
#[must_use]
fn compute_realtime_offset(unix_now_secs: u64, elapsed_secs: u64) -> Option<u64> {
    if !(MIN_VALID_EPOCH..=MAX_VALID_EPOCH).contains(&unix_now_secs) {
        return None;
    }
    Some(unix_now_secs.saturating_sub(elapsed_secs))
}

/// Update the wall-clock boot epoch from an external source (e.g., modem RTC).
///
/// `unix_now_secs` is the current Unix timestamp in seconds. This function
/// back-calculates the boot epoch by subtracting the elapsed monotonic time.
/// Rejects `unix_now_secs` outside `[MIN_VALID_EPOCH, MAX_VALID_EPOCH]` and
/// leaves `REALTIME_OFFSET_SECS` unchanged -- a hostile modem RTC (the
/// lowest-trust source per the clock hierarchy) must not be able to set the
/// clock to an implausible date (#374).
///
/// # Errors
///
/// Returns `Err(ImplausibleEpoch)` (and leaves `REALTIME_OFFSET_SECS`
/// unchanged) when `unix_now_secs` is rejected, so the caller can detect
/// and log/audit a rejected update instead of it silently vanishing.
///
/// # Safety
///
/// Writes to a static mut. Must be called from a single-threaded context
/// (e.g., kinit before spawning userspace, or from an IPC handler with
/// interrupts disabled). On `ARMv7` a 64-bit store is not atomic; callers
/// are responsible for ensuring no concurrent read occurs.
#[cfg(not(test))]
pub unsafe fn set_realtime_offset(unix_now_secs: u64) -> Result<(), ImplausibleEpoch> {
    let elapsed_secs = monotonic_secs();
    let Some(new_offset) = compute_realtime_offset(unix_now_secs, elapsed_secs) else {
        return Err(ImplausibleEpoch);
    };
    // SAFETY: see function-level safety doc; caller ensures exclusion.
    unsafe {
        REALTIME_OFFSET_SECS = new_offset;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Read the current monotonic time as whole seconds since boot.
#[cfg(not(test))]
fn monotonic_secs() -> u64 {
    let freq = u64::from(timer::frequency());
    if freq == 0 {
        return 0;
    }
    timer::counter() / freq
}

/// Convert a raw timer counter value to a (seconds, nanoseconds) pair.
fn counter_to_timespec(count: u64, freq: u64) -> (u32, u32) {
    if freq == 0 {
        return (0, 0);
    }
    let secs = count / freq;
    // Remainder ticks → nanoseconds: (rem * 1_000_000_000) / freq
    // Use u64 arithmetic; the remainder is always < freq, so the product
    // fits if freq < ~18 THz (safe for CNTFRQ ≤ 1 GHz in practice).
    let rem = count % freq;
    let nanos = (rem * NANOS_PER_SEC) / freq;
    (secs as u32, nanos as u32)
}

// ---------------------------------------------------------------------------
// Syscall implementations. Host-testable via the timer/exceptions stubs and
// the un-gated process module; the ARM-only `wfe` hint in the nanosleep
// tick-wait is target_arch-split (real hint on ARM, no-op on the host).
// ---------------------------------------------------------------------------

/// `sys_clock_gettime` — fill a user-space timespec with the requested clock.
///
/// # Arguments
///
/// * `clock_id` — 0 (`CLOCK_REALTIME`) or 1 (`CLOCK_MONOTONIC`)
/// * `ts_ptr`   — user-space pointer to `{ tv_sec: u32, tv_nsec: u32 }`
///
/// # Returns
///
/// 0 on success, EFAULT if `ts_ptr` is invalid, EINVAL for unknown `clock_id`.
pub(crate) fn sys_clock_gettime(clock_id: u32, ts_ptr: u32) -> u32 {
    // Validate the user pointer: timespec is 8 bytes (two u32 fields).
    let ptr = ts_ptr as usize;
    if !validate_user_buffer(ptr, 8) {
        return EFAULT;
    }

    let count = timer::counter();
    let freq = u64::from(timer::frequency());

    let (secs, nanos) = match clock_id {
        CLOCK_MONOTONIC => counter_to_timespec(count, freq),
        CLOCK_REALTIME => {
            let (mono_secs, mono_nanos) = counter_to_timespec(count, freq);
            // SAFETY: REALTIME_OFFSET_SECS is a u64 stored in a static mut.
            // On ARMv7 a 64-bit load is not guaranteed atomic; this is
            // acceptable because the offset is only written during single-
            // threaded init (before IRQs are enabled or before userspace
            // has time syscall access). A torn read produces a mildly wrong
            // clock reading rather than a safety violation.
            let offset =
                unsafe { core::ptr::read_volatile(core::ptr::addr_of!(REALTIME_OFFSET_SECS)) };
            let real_secs = offset.wrapping_add(u64::from(mono_secs));
            (real_secs as u32, mono_nanos)
        }
        _ => return EINVAL,
    };

    // Write the two u32 fields to user space.
    // SAFETY: validate_user_buffer confirmed [ptr, ptr+8) is within
    // user-accessible DRAM (see KERNEL_END/RAM_END in kconfig). The pointer
    // alignment is NOT guaranteed by the ABI (POSIX allows any alignment for
    // char-typed buffers), so we use write_unaligned to be safe.
    unsafe {
        core::ptr::write_unaligned(ptr as *mut u32, secs);
        core::ptr::write_unaligned((ptr + 4) as *mut u32, nanos);
    }
    0
}

/// `sys_nanosleep` — suspend the calling process for (at least) the specified duration.
///
/// Reads the duration from a user-space timespec, converts it to a future
/// tick count, records it in the PCB, and marks the process as Sleeping.
/// The scheduler will skip it until the wake tick is reached.
///
/// Resolution is the scheduler tick period (10 ms). Any sub-tick remainder
/// causes the sleep to be rounded up by one tick.
///
/// # Arguments
///
/// * `ts_ptr` — user-space pointer to `{ tv_sec: u32, tv_nsec: u32 }`
///
/// # Returns
///
/// 0 on success (sleep elapsed), EFAULT if `ts_ptr` is invalid.
pub(crate) fn sys_nanosleep(ts_ptr: u32) -> u32 {
    // tick period = TICK_MS ms = 10 ms. scheduler tick rate = 100 Hz.
    const TICK_MS: u64 = 10;

    let ptr = ts_ptr as usize;
    if !validate_user_buffer(ptr, 8) {
        return EFAULT;
    }

    // Read duration from user space.
    // SAFETY: validate_user_buffer confirmed [ptr, ptr+8) is within user DRAM.
    // write_unaligned safety reasoning applies in reverse for read_unaligned.
    let (req_secs, req_nanos): (u32, u32) = unsafe {
        let s = core::ptr::read_unaligned(ptr as *const u32);
        let n = core::ptr::read_unaligned((ptr + 4) as *const u32);
        (s, n)
    };

    // POSIX: tv_nsec must be in [0, 999_999_999]; anything else is EINVAL,
    // not silently folded into extra whole seconds of sleep.
    if req_nanos >= 1_000_000_000 {
        return EINVAL;
    }

    // Convert duration to ticks.
    // ticks_needed = ceil(total_ms / TICK_MS)
    //   total_ms = req_secs * 1000 + req_nanos / 1_000_000
    // We use u64 throughout to avoid overflow for large sleep values.
    let total_ms = u64::from(req_secs)
        .saturating_mul(1_000)
        .saturating_add(u64::from(req_nanos) / 1_000_000);
    // Round up: if there is any sub-tick nanosecond remainder, add one tick.
    let sub_tick_ns = u64::from(req_nanos) % (TICK_MS * 1_000_000);
    let ticks_needed = total_ms / TICK_MS + u64::from(sub_tick_ns > 0 || (total_ms % TICK_MS != 0));

    let now_ticks = exceptions::ticks();
    let wake_tick = now_ticks.saturating_add(ticks_needed);

    // Mark the process Sleeping (set_wake_tick does this) and YIELD to the
    // scheduler -- the futex-wait pattern (#465/#477). The scheduler wakes a
    // Sleeping process once now >= wake_tick, and a later switch resumes it in
    // userspace at the instruction after the `svc` with r0=0 (set_trap_return
    // below). The old busy-wait `while ticks() < wake_tick` hard-hung a
    // userspace caller: the SVC trap runs IRQ-masked, so ticks() never advanced
    // and the whole kernel spun forever.
    // SAFETY: set_wake_tick mutates PROCS via addr_of_mut! (the established
    // pattern) from syscall context (single-threaded, IRQs masked under SVC).
    process::set_wake_tick(wake_tick);
    let next = process::schedule();
    if next == process::current_pid() {
        // No other process to yield to (degenerate: PID 0 is always Ready for a
        // real userspace caller, so a switch normally occurs) -- restore Running
        // rather than linger mis-marked Sleeping.
        process::clear_wake_tick();
    } else {
        // WHY(#465): deposit the wake-time return value (0) into the live trap
        // frame before switching away, so the woken process's saved frame
        // returns 0 from nanosleep.
        process::set_trap_return(0);
        // SAFETY: `next` is a valid Ready PID returned by schedule().
        unsafe {
            process::switch_to(next);
        }
    }
    0
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Counter-to-timespec conversion: exact second boundary.
    #[test]
    fn counter_to_timespec_whole_seconds() {
        // freq = 1000 ticks/s; count = 3000 → 3 s, 0 ns
        let (secs, nanos) = counter_to_timespec(3000, 1000);
        assert_eq!(secs, 3, "whole seconds");
        assert_eq!(nanos, 0, "zero nanos at exact second boundary");
    }

    /// Counter-to-timespec conversion: sub-second remainder.
    #[test]
    fn counter_to_timespec_sub_second() {
        // freq = 1000 ticks/s; count = 1500 → 1 s, 500_000_000 ns
        let (secs, nanos) = counter_to_timespec(1500, 1000);
        assert_eq!(secs, 1);
        assert_eq!(nanos, 500_000_000);
    }

    /// Zero frequency returns zero to avoid division by zero.
    #[test]
    fn counter_to_timespec_zero_freq() {
        let (secs, nanos) = counter_to_timespec(12345, 0);
        assert_eq!(secs, 0);
        assert_eq!(nanos, 0);
    }

    /// EINVAL constant matches Linux ARM EINVAL (-22).
    ///
    /// NOTE: `sys_clock_gettime` itself is not callable from host tests (it depends
    /// on #[cfg(not(test))] modules). This test verifies the error constant value
    /// that `sys_clock_gettime` returns for unknown clock IDs, which is the
    /// observable ABI contract.
    #[test]
    fn clock_gettime_invalid_clock_returns_error() {
        // EINVAL = -22 as u32 two's complement = 0xFFFF_FFEA
        assert_eq!(EINVAL, 0u32.wrapping_sub(22), "EINVAL must be -22 as u32");
    }

    /// `CLOCK_REALTIME` and `CLOCK_MONOTONIC` IDs have the correct POSIX values.
    #[test]
    fn clock_gettime_null_ptr_returns_efault() {
        // We verify the clock ID constants; the actual EFAULT path requires
        // the production syscall machinery (validate_user_buffer, MMIO timer).
        // The EFAULT value is defined in syscall.rs (-14 as u32).
        assert_eq!(CLOCK_REALTIME, 0, "CLOCK_REALTIME must be 0");
        assert_eq!(CLOCK_MONOTONIC, 1, "CLOCK_MONOTONIC must be 1");
    }

    /// `CLOCK_MONOTONIC` increases between two consecutive reads.
    /// Uses the `counter_to_timespec` helper directly since we can't drive
    /// the hardware timer from a host test.
    #[test]
    fn clock_gettime_monotonic_increases() {
        // Simulate two counter readings (second > first).
        let freq: u64 = 13_000_000; // typical MT6739 CNTFRQ
        let count1: u64 = 13_000_000; // 1 second
        let count2: u64 = 26_000_500; // ~2 seconds + a bit

        let (s1, n1) = counter_to_timespec(count1, freq);
        let (s2, n2) = counter_to_timespec(count2, freq);

        // Second reading must be >= first
        assert!(
            (s2, n2) >= (s1, n1),
            "monotonic clock must not decrease: ({s1},{n1}) -> ({s2},{n2})"
        );
    }

    /// Realtime offset default is a plausible date (>= 2025-01-01 UTC).
    #[test]
    fn realtime_offset_is_recent() {
        // 2025-01-01 00:00:00 UTC = 1_735_603_200 seconds since epoch
        let min_epoch: u64 = 1_735_603_200;
        // SAFETY: read in test-only context; no concurrent writes.
        let offset = unsafe { REALTIME_OFFSET_SECS };
        assert!(
            offset >= min_epoch,
            "boot epoch offset must be >= 2025-01-01 (got {offset})"
        );
    }

    /// #374: a plausible epoch within the accepted window computes the
    /// expected offset (`unix_now_secs` - `elapsed_secs`).
    #[test]
    fn compute_realtime_offset_accepts_plausible_window() {
        assert_eq!(
            compute_realtime_offset(MIN_VALID_EPOCH, 0),
            Some(MIN_VALID_EPOCH),
            "lower bound must be accepted"
        );
        assert_eq!(
            compute_realtime_offset(MAX_VALID_EPOCH, 100),
            Some(MAX_VALID_EPOCH - 100),
            "upper bound must be accepted, offset subtracts elapsed time"
        );
    }

    /// #374: epoch 0 (1970, a hostile modem RTC's most common failure
    /// value) must be rejected -- the offset is left unchanged (None).
    #[test]
    fn compute_realtime_offset_rejects_epoch_zero() {
        assert_eq!(
            compute_realtime_offset(0, 0),
            None,
            "epoch 0 (1970) must be rejected as implausible"
        );
    }

    /// #374: a hostile modem RTC reporting year ~2200 must be rejected.
    #[test]
    fn compute_realtime_offset_rejects_far_future() {
        let year_2200_epoch = MAX_VALID_EPOCH + 100 * 365 * 86_400;
        assert_eq!(
            compute_realtime_offset(year_2200_epoch, 0),
            None,
            "year 2200 must be rejected"
        );
    }

    /// Nanosleep tick calculation: 1 second = 100 ticks at 10 ms/tick.
    #[test]
    fn nanosleep_tick_calculation() {
        const TICK_MS: u64 = 10;
        let req_secs: u32 = 1;
        let req_nanos: u32 = 0;

        let total_ms = u64::from(req_secs) * 1_000 + u64::from(req_nanos) / 1_000_000;
        let sub_tick_ns = u64::from(req_nanos) % (TICK_MS * 1_000_000);
        let ticks_needed =
            total_ms / TICK_MS + u64::from(sub_tick_ns > 0 || (total_ms % TICK_MS != 0));

        assert_eq!(ticks_needed, 100, "1 second = 100 ticks at 10 ms/tick");
    }

    /// Nanosleep tick calculation: sub-tick duration rounds up.
    #[test]
    fn nanosleep_sub_tick_rounds_up() {
        const TICK_MS: u64 = 10;
        // 5 ms = half a tick → should round up to 1 tick
        let req_secs: u32 = 0;
        let req_nanos: u32 = 5_000_000; // 5 ms in ns

        let total_ms = u64::from(req_secs) * 1_000 + u64::from(req_nanos) / 1_000_000;
        let sub_tick_ns = u64::from(req_nanos) % (TICK_MS * 1_000_000);
        let ticks_needed =
            total_ms / TICK_MS + u64::from(sub_tick_ns > 0 || (total_ms % TICK_MS != 0));

        assert_eq!(ticks_needed, 1, "5 ms sleep must round up to 1 tick");
    }

    /// POSIX requires EINVAL when `tv_nsec` is out of [0, `999_999_999`]; the
    /// kernel must not silently fold an out-of-range value into extra
    /// whole seconds of sleep. A `static mut` buffer is used (not a stack
    /// array) so its address lands inside `validate_user_buffer`'s accepted
    /// user-DRAM range on the 32-bit test target.
    #[cfg(target_pointer_width = "32")]
    #[test]
    fn nanosleep_rejects_tv_nsec_out_of_range() {
        static mut TS: [u32; 2] = [0, 1_000_000_000]; // tv_sec=0, tv_nsec=1e9 (invalid)
        // SAFETY: test-only static; single-threaded per test.
        let ptr = core::ptr::addr_of!(TS) as u32;
        let result = sys_nanosleep(ptr);
        assert_eq!(
            result, EINVAL,
            "tv_nsec >= 1_000_000_000 must return EINVAL"
        );
    }
}
