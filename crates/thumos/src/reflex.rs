//! Reflex -- the IRQ fast-path: a deliberately tiny allowlist of events an
//! interrupt handler may flag for immediate service-loop attention, ahead of
//! the normal 100 Hz poll cadence.
//!
//! ADMISSION RULE: an entry must justify why a 10 ms poll-cadence response is
//! unacceptable. Current allowlist: duress key, panic-wipe trigger,
//! incoming-call ring. Everything else goes through `KernelState::poll_all`.
//! Adding an entry is a reviewable diff to this one small file, not a
//! scattered pattern.
//!
//! Concurrency CONTRACT (single-core): setters run in IRQ context;
//! [`drain`]/[`peek_pending`] run in the service loop (PID 0). All take the
//! same [`IrqSpinlock`], which masks IRQ delivery for the critical section, so
//! a drain's read-and-clear can never interleave with a setter (#322/#331
//! class), and a setter in IRQ context nests correctly via the `IrqGuard`
//! save/restore. `static mut PENDING` is never touched off-lock.
//!
//! WHY booleans, not payloads: reflex is a WAKE-HINT channel -- the loop
//! fetches any associated data (ring caller-ID, which key) from the owning
//! subsystem's state after the hint. This keeps IRQ handlers minimal; a
//! future payload need extends [`Pending`] to small `Copy` fields under the
//! same lock without changing the concurrency story.

use crate::irq::IrqSpinlock;

/// Pending reflex flags, drained atomically by the service loop.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Pending {
    pub(crate) duress: bool,
    pub(crate) panic_wipe: bool,
    pub(crate) incoming_ring: bool,
}

impl Pending {
    /// True when any reflex is pending.
    pub(crate) const fn any(&self) -> bool {
        self.duress || self.panic_wipe || self.incoming_ring
    }
}

static LOCK: IrqSpinlock = IrqSpinlock::new();

/// Guarded by [`LOCK`] -- never touch without holding it.
static mut PENDING: Pending = Pending {
    duress: false,
    panic_wipe: false,
    incoming_ring: false,
};

fn set(mutate: impl FnOnce(&mut Pending)) {
    let _guard = LOCK.lock();
    // SAFETY: PENDING is only accessed under LOCK, whose IrqSpinlock masks IRQ
    // delivery for the critical section -- no IRQ-vs-loop interleaving is
    // possible on this single-core kernel.
    unsafe { mutate(&mut *core::ptr::addr_of_mut!(PENDING)) }
}

/// Raise the duress-key reflex.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "raised by the keypad IRQ wiring (#400/#404)")
)]
pub(crate) fn raise_duress() {
    set(|p| p.duress = true);
}

/// Raise the panic-wipe reflex.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "raised by the panic-wipe trigger wiring (#404)")
)]
pub(crate) fn raise_panic_wipe() {
    set(|p| p.panic_wipe = true);
}

/// Raise the incoming-call-ring reflex.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "raised by the CCCI RING URC wiring (#398)")
)]
pub(crate) fn raise_incoming_ring() {
    set(|p| p.incoming_ring = true);
}

/// True if any reflex is pending, WITHOUT clearing it.
///
/// WHY: the service loop's IRQ-masked idle (`kardia::idle`) re-checks this
/// under the mask before committing to WFI, so a flag raised by an IRQ that
/// already retired in the drain->idle window is seen rather than slept
/// through. Unused under the qemu idle (busy-poll, no WFI).
#[cfg_attr(
    all(feature = "qemu", not(test)),
    expect(
        dead_code,
        reason = "the qemu idle busy-polls; peek is the phone masked-WFI re-check (#463)"
    )
)]
pub(crate) fn peek_pending() -> bool {
    let _guard = LOCK.lock();
    // SAFETY: as in `set` -- exclusive access under LOCK.
    unsafe { (*core::ptr::addr_of!(PENDING)).any() }
}

/// Take and clear all pending reflex flags in one critical section.
pub(crate) fn drain() -> Pending {
    let _guard = LOCK.lock();
    // SAFETY: as in `set` -- exclusive access under LOCK.
    unsafe { core::mem::take(&mut *core::ptr::addr_of_mut!(PENDING)) }
}

#[cfg(test)]
mod tests {
    use super::*;

    // WHY not #[test]-parallel-safe individually: PENDING is a shared static;
    // nextest process-isolates each test (its own process), so these do not
    // race each other. Each drains at the end to leave a clean slate.

    #[test]
    fn pending_any_reflects_flags() {
        assert!(!Pending::default().any());
        assert!(
            Pending {
                duress: true,
                ..Pending::default()
            }
            .any()
        );
    }

    #[test]
    fn raise_then_drain_returns_the_flag_and_clears() {
        let _ = drain(); // clean slate
        raise_duress();
        assert!(
            peek_pending(),
            "peek must see the raised flag without clearing"
        );
        let p = drain();
        assert!(p.duress && !p.panic_wipe && !p.incoming_ring);
        assert!(
            !peek_pending(),
            "drain must clear -- a second peek sees nothing"
        );
        assert!(!drain().any(), "second drain is empty");
    }

    #[test]
    fn multiple_raises_coalesce_into_one_drain() {
        let _ = drain();
        raise_duress();
        raise_panic_wipe();
        raise_incoming_ring();
        let p = drain();
        assert_eq!(
            p,
            Pending {
                duress: true,
                panic_wipe: true,
                incoming_ring: true,
            }
        );
        assert!(!drain().any());
    }
}
