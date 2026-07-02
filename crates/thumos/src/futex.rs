//! Futex subsystem: fast userspace mutex kernel support.
//!
//! Provides FUTEX_WAIT and FUTEX_WAKE operations sufficient to implement
//! userspace mutexes and condition variables. This is the minimal kernel
//! half of the Linux futex(2) interface.
//!
//! # Protocol
//! - FUTEX_WAIT (op=0): atomically check `*addr == val` and, if equal,
//!   suspend the calling process. If `*addr != val`, return EAGAIN immediately
//!   (the value changed before we could sleep — caller should retry).
//! - FUTEX_WAKE (op=1): wake up to `val` processes waiting on `addr`.
//!   Returns the number of processes woken.
//!
//! # Design constraints
//! - No heap: waiter list is a fixed-size static array (32 slots).
//! - No atomics beyond pointer reads: single-core cooperative kernel means
//!   there is no preemption between the addr check and the state transition,
//!   so the check-then-block is not a race.
//! - Process suspension: set state to Blocked; the scheduler will not
//!   reschedule a Blocked process. Wakeup sets it back to Ready.
//!
//! WHY 32 waiters: the maximum number of processes is 16 (MAX_PROCS), so 32
//! slots is 2× headroom in case a process waits on multiple futexes in sequence
//! before the slots are reclaimed. Each slot is freed immediately on wakeup.

/// EAGAIN — value mismatch (two's complement -11, Linux ARM convention).
pub(crate) const EAGAIN: u32 = 0u32.wrapping_sub(11);

/// EINVAL — unknown op (two's complement -22, Linux ARM convention).
pub(crate) const EINVAL: u32 = 0u32.wrapping_sub(22);

/// FUTEX_WAIT operation code.
pub(crate) const FUTEX_WAIT: u32 = 0;

/// FUTEX_WAKE operation code.
pub(crate) const FUTEX_WAKE: u32 = 1;

/// Maximum number of simultaneously sleeping futex waiters.
const MAX_FUTEX_WAITERS: usize = 32;

/// A single futex waiter record.
pub(crate) struct FutexWaiter {
    /// The address being waited on.
    pub addr: u32,
    /// PID of the waiting process.
    pub pid: u32,
}

/// Global futex waiter table.
static mut FUTEX_WAITERS: [Option<FutexWaiter>; MAX_FUTEX_WAITERS] = {
    const NONE: Option<FutexWaiter> = None;
    [NONE; MAX_FUTEX_WAITERS]
};

/// FUTEX_WAIT: if `*addr == val`, block the current process.
///
/// Returns 0 after being woken, EAGAIN if `*addr != val`, or EINVAL if
/// `addr` does not lie within user-accessible DRAM (see
/// `memguard::validate_user_buffer`) — checked before any dereference.
///
/// WHY split: the value-mismatch fast path does not call `crate::process` and
/// is therefore testable on the host. The register-and-block path is gated
/// `#[cfg(not(test))]` because `crate::process` is not compiled under test
/// (it requires ARM-specific code and the full kernel environment).
pub(crate) fn sys_futex_wait(addr: u32, val: u32) -> u32 {
    // validate_user_buffer rejects null, kernel-space, MMIO, and
    // above-RAM addresses in one gate (see memguard.rs) — this also covers
    // the waiter registration below, which stores this same `addr` for
    // later comparison in sys_futex_wake without ever dereferencing it.
    if !crate::memguard::validate_user_buffer(addr as usize, 4) {
        return EINVAL;
    }

    // Read the current value atomically (single-core: no racing stores).
    // SAFETY: validate_user_buffer confirmed [addr, addr+4) lies within
    // user-accessible DRAM.
    let current_val = unsafe { core::ptr::read_volatile(addr as *const u32) };

    if current_val != val {
        // Value already changed — tell the caller to retry.
        return EAGAIN;
    }

    // --- Block path: requires crate::process (not available in test builds) ---
    #[cfg(not(test))]
    {
        // Register this process as a waiter.
        let pid = crate::process::current_pid() as u32;

        // SAFETY: FUTEX_WAITERS is a static mut; addr_of_mut! avoids an intermediate
        // reference. Single-core cooperative kernel ensures exclusive access here.
        let waiters = unsafe { &mut *core::ptr::addr_of_mut!(FUTEX_WAITERS) };
        let slot = waiters.iter_mut().find(|s| s.is_none());
        let slot = match slot {
            Some(s) => s,
            None => {
                // Waiter table full — fail gracefully.
                return EAGAIN;
            }
        };
        *slot = Some(FutexWaiter { addr, pid });

        // Block the current process. The scheduler will not pick it until WAKE.
        // SAFETY: setting our own process state to Blocked is safe on a cooperative
        // single-core kernel — no other CPU can observe the intermediate state.
        // The next reschedule (timer tick or explicit yield) will skip this process.
        unsafe {
            crate::process::set_state(pid as u8, crate::process::State::Blocked);
            // Yield to the scheduler immediately so we don't busy-loop.
            let next = crate::process::schedule();
            if next != crate::process::current_pid() {
                crate::process::switch_to(next);
            }
        }

        // Execution resumes here after FUTEX_WAKE unblocks us.
        return 0;
    }

    // In test builds the block path is absent; the matching value case returns
    // EAGAIN as a conservative sentinel (tests should only exercise the
    // mismatch path).
    #[cfg(test)]
    EAGAIN
}

/// FUTEX_WAKE: wake up to `max_wake` processes waiting on `addr`.
///
/// Returns the number of processes woken.
pub fn sys_futex_wake(addr: u32, max_wake: u32) -> u32 {
    if addr == 0 {
        return 0;
    }

    // SAFETY: FUTEX_WAITERS is a static mut; addr_of_mut! avoids an
    // intermediate reference. Single-core cooperative kernel ensures exclusive
    // access here.
    let waiters = unsafe { &mut *core::ptr::addr_of_mut!(FUTEX_WAITERS) };

    let mut woken: u32 = 0;
    for slot in waiters.iter_mut() {
        if woken >= max_wake {
            break;
        }
        if let Some(ref w) = *slot {
            if w.addr == addr {
                let pid = w.pid as u8;
                *slot = None;
                // SAFETY: pid is a valid PID previously registered in
                // sys_futex_wait; set_state is safe on cooperative single-core.
                // WHY cfg(not(test)): crate::process is not compiled under test
                // (requires ARM + full kernel environment). In test builds the
                // slot is cleared but no process state change occurs, which is
                // fine because no process was actually blocked.
                #[cfg(not(test))]
                unsafe {
                    crate::process::set_state(pid, crate::process::State::Ready);
                }
                #[cfg(test)]
                let _ = pid; // suppress unused warning in test builds
                woken += 1;
            }
        }
    }
    woken
}

/// Dispatch futex syscall.
///
/// # Arguments
/// - `addr`: userspace address of the futex word
/// - `op`: FUTEX_WAIT (0) or FUTEX_WAKE (1)
/// - `val`: for WAIT — expected value; for WAKE — max processes to wake
///
/// # Returns
/// Operation-specific return value (see individual functions).
pub fn sys_futex(addr: u32, op: u32, val: u32) -> u32 {
    match op {
        FUTEX_WAIT => sys_futex_wait(addr, val),
        FUTEX_WAKE => sys_futex_wake(addr, val),
        _ => EINVAL,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn reset_waiters() {
        unsafe {
            let waiters = &mut *core::ptr::addr_of_mut!(FUTEX_WAITERS);
            for slot in waiters.iter_mut() {
                *slot = None;
            }
        }
    }

    #[test]
    fn futex_wait_returns_eagain_on_mismatch() {
        reset_waiters();

        // WHY function-local `static mut`: sys_futex_wait now validates
        // `addr` via validate_user_buffer before dereferencing it. A stack
        // address (e.g. `&word`) falls outside
        // [kconfig::KERNEL_END, kconfig::RAM_END) on this host binary and
        // would be rejected before the mismatch check is ever reached; a
        // function-local static lands inside that window (see fd.rs tests
        // for the same pattern).
        static mut WORD: u32 = 42;
        // SAFETY: test-only static; single-threaded per test.
        let addr = unsafe { core::ptr::addr_of!(WORD) as u32 };

        // val != *addr → should return EAGAIN immediately without blocking.
        let result = sys_futex_wait(addr, 99);
        assert_eq!(result, EAGAIN, "mismatch on futex word should return EAGAIN");
    }

    #[test]
    fn futex_wait_rejects_kernel_range_addr() {
        reset_waiters();
        // A kernel-range addr must be rejected by validate_user_buffer
        // before any read_volatile — verified by never reaching the mismatch
        // path (which would return EAGAIN, not EINVAL).
        let result = sys_futex_wait(crate::kconfig::KERNEL_LOAD as u32, 0);
        assert_eq!(result, EINVAL, "kernel-range addr must return EINVAL without a load");
    }

    #[test]
    fn futex_wake_returns_zero_with_no_waiters() {
        reset_waiters();

        let word: u32 = 0;
        let woken = sys_futex_wake((&word) as *const u32 as u32, 10);
        assert_eq!(woken, 0, "no waiters → 0 processes woken");
    }

    #[test]
    fn futex_invalid_op_returns_einval() {
        let word: u32 = 0;
        let result = sys_futex((&word) as *const u32 as u32, 99, 0);
        assert_eq!(result, EINVAL, "unknown op should return EINVAL");
    }

    #[test]
    fn futex_null_addr_returns_einval_or_eagain() {
        // FUTEX_WAIT with null addr returns EINVAL.
        let result_wait = sys_futex_wait(0, 0);
        assert_eq!(result_wait, EINVAL);

        // FUTEX_WAKE with null addr returns 0 (no waiters at null).
        let result_wake = sys_futex_wake(0, 1);
        assert_eq!(result_wake, 0);
    }
}
