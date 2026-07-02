//! IRQ-mask primitives for IRQ-safe critical sections.
//!
//! On the single-core MT6739 boot CPU, the only concurrent caller of a
//! kernel data structure guarded by a plain spinlock is an IRQ handler
//! running on top of interrupted non-IRQ code. A spinlock's atomic flag
//! alone does not stop that reentrancy -- it converts it into a
//! self-deadlock: if the IRQ fires while the interrupted context holds the
//! lock and the handler tries to acquire it too, the handler spins forever
//! on a lock the interrupted context can never release, because IRQ
//! handlers run to completion before the interrupted context resumes
//! (#322, #331). Masking IRQ delivery (the CPSR I-bit) for the duration of
//! the critical section is what actually prevents that: while masked, the
//! IRQ cannot fire at all, so it cannot observe the lock held.
//!
//! # Host testability
//!
//! The ARM CPSR I-bit is not observable off-target. The save/nest/restore
//! CONTRACT -- a nested mask must not let an inner `restore` prematurely
//! unmask an outer critical section -- is architecture-independent, so it is
//! mirrored here through a mock global flag under
//! `cfg(not(target_arch = "arm"))`, giving [`disable`]/[`restore`] (and
//! everything built on them) the same tested contract on the host i686
//! target used by `cargo nextest`.

use core::sync::atomic::{AtomicBool, Ordering};

/// Host-test mock of "IRQ delivery enabled" -- unused on the real ARM target,
/// where the CPSR I-bit is the actual mask.
#[cfg(not(target_arch = "arm"))]
static MOCK_IRQ_ENABLED: AtomicBool = AtomicBool::new(true);

/// Mask IRQ delivery on this core and return the prior mask state, for use
/// with [`restore`]. Safe to call with IRQs already masked (nests
/// correctly).
#[cfg(target_arch = "arm")]
#[inline(always)]
fn disable() -> u32 {
    let cpsr: u32;
    // SAFETY: MRS is a non-faulting status-register read; CPSID only clears
    // the CPSR I-bit (IRQ mask). Neither touches memory or requires any
    // precondition beyond running at PL1, which the kernel does throughout.
    unsafe {
        core::arch::asm!("mrs {0}, cpsr", out(reg) cpsr);
        core::arch::asm!("cpsid i");
    }
    cpsr
}

/// Restore the IRQ mask state previously returned by [`disable`]. If the
/// saved state already had IRQs masked (a nested critical section), this is
/// a no-op -- only the outermost `restore` re-enables delivery.
#[cfg(target_arch = "arm")]
#[inline(always)]
fn restore(saved: u32) {
    /// CPSR I-bit (bit 7): IRQ mask, 1 = masked.
    const I_BIT: u32 = 1 << 7;
    if saved & I_BIT == 0 {
        // SAFETY: CPSIE only clears the CPSR I-bit; no memory access.
        unsafe {
            core::arch::asm!("cpsie i");
        }
    }
}

/// Host-test stand-in for [`disable`]: flips the mock flag instead of the
/// CPSR I-bit, preserving the same "return prior state" contract.
#[cfg(not(target_arch = "arm"))]
#[inline(always)]
fn disable() -> u32 {
    let was_enabled = MOCK_IRQ_ENABLED.swap(false, Ordering::AcqRel);
    u32::from(was_enabled)
}

/// Host-test stand-in for [`restore`]: mirrors the real nesting contract
/// against the mock flag.
#[cfg(not(target_arch = "arm"))]
#[inline(always)]
fn restore(saved: u32) {
    if saved != 0 {
        MOCK_IRQ_ENABLED.store(true, Ordering::Release);
    }
}

/// Test-only accessor for the mock IRQ-enabled flag, so callers' own tests
/// (slab, page) can assert masking/unmasking directly, not just this
/// module's own nesting test.
#[cfg(all(test, not(target_arch = "arm")))]
pub(crate) fn mock_enabled() -> bool {
    MOCK_IRQ_ENABLED.load(Ordering::Acquire)
}

/// Test-only reset of the mock IRQ-enabled flag to its default (enabled)
/// state, for tests that need a known starting point.
#[cfg(all(test, not(target_arch = "arm")))]
pub(crate) fn reset_mock() {
    MOCK_IRQ_ENABLED.store(true, Ordering::Release);
}

/// RAII guard: masks IRQ delivery on construction, restores the prior mask
/// state on drop. Nests correctly -- an inner guard constructed while
/// already masked leaves the mask alone on drop, so the outer critical
/// section it is nested inside stays protected.
pub(crate) struct IrqGuard(u32);

impl IrqGuard {
    /// Mask IRQ delivery and capture the prior mask state.
    pub(crate) fn new() -> Self {
        IrqGuard(disable())
    }
}

impl Drop for IrqGuard {
    fn drop(&mut self) {
        restore(self.0);
    }
}

/// IRQ-safe spinlock: an atomic flag guarded by IRQ masking.
///
/// The atomic flag alone only serializes against another CPU; on this
/// single-core kernel the only other caller is an IRQ handler, so `lock()`
/// masks IRQ delivery for the whole critical section (mask, then spin for
/// the flag; release the flag, then unmask on drop) -- this is what actually
/// makes the section IRQ-safe (#322, #331).
pub(crate) struct IrqSpinlock {
    locked: AtomicBool,
}

impl IrqSpinlock {
    pub(crate) const fn new() -> Self {
        IrqSpinlock {
            locked: AtomicBool::new(false),
        }
    }

    /// Mask IRQ delivery, then spin until the flag is acquired. Returns a
    /// guard that releases the flag and restores the prior IRQ mask (in
    /// that order) on drop.
    pub(crate) fn lock(&self) -> IrqSpinGuard<'_> {
        let irq = IrqGuard::new();
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            // Hint the CPU to yield. On ARM, `yield` is a NOP hint that allows
            // speculative execution to be abandoned on in-order cores.
            core::hint::spin_loop();
        }
        IrqSpinGuard { lock: self, _irq: irq }
    }
}

pub(crate) struct IrqSpinGuard<'a> {
    lock: &'a IrqSpinlock,
    /// Restores the prior IRQ mask on drop, AFTER the flag is released below
    /// -- field drops run after `Drop::drop`, in declaration order, and
    /// `lock`'s reference drop is a no-op, so `_irq` unmasks last.
    _irq: IrqGuard,
}

impl Drop for IrqSpinGuard<'_> {
    fn drop(&mut self) {
        self.lock.locked.store(false, Ordering::Release);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_guard_round_trips() {
        reset_mock();
        assert!(mock_enabled(), "starts unmasked");
        let g = IrqGuard::new();
        assert!(!mock_enabled(), "guard must mask IRQ delivery");
        drop(g);
        assert!(mock_enabled(), "dropping the guard must restore IRQ delivery");
    }

    #[test]
    fn nested_guards_leave_irqs_masked_until_outer_drops() {
        // The property that actually prevents the #322/#331 self-deadlock:
        // an inner critical section entered while already masked must not
        // unmask on its own drop and let a handler run before the OUTER
        // critical section finishes.
        reset_mock();
        let outer = IrqGuard::new();
        assert!(!mock_enabled(), "outer guard masks");
        {
            let inner = IrqGuard::new();
            assert!(!mock_enabled(), "inner guard: still masked");
            drop(inner);
            assert!(!mock_enabled(), "inner drop must not unmask -- outer still holds");
        }
        drop(outer);
        assert!(mock_enabled(), "outer drop restores unmasked");
    }

    #[test]
    fn spinlock_masks_irqs_while_held() {
        reset_mock();
        let lock = IrqSpinlock::new();
        assert!(mock_enabled(), "starts unmasked");
        let guard = lock.lock();
        assert!(!mock_enabled(), "lock() must mask IRQ delivery while held");
        drop(guard);
        assert!(mock_enabled(), "dropping the guard must restore IRQ delivery");
    }

    #[test]
    fn spinlock_clears_the_flag_and_unmasks_on_drop() {
        // The flag and the IRQ mask must both be back to their pre-lock
        // state after drop; the DECLARATION order on IrqSpinGuard (see its
        // doc comment) is what guarantees the flag is cleared before IRQs
        // are unmasked, not just that both eventually happen.
        reset_mock();
        let lock = IrqSpinlock::new();
        let guard = lock.lock();
        assert!(lock.locked.load(Ordering::Acquire), "flag set while held");
        drop(guard);
        assert!(!lock.locked.load(Ordering::Acquire), "flag must be clear after drop");
        assert!(mock_enabled(), "and IRQs unmasked after drop");
    }
}
