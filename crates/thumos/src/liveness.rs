//! Watchdog liveness gate: pet only on proved forward progress (#875).
//!
//! The hardware watchdog resets the board when it is not fed. Feeding it from
//! the timer IRQ unconditionally proves only that timer interrupts are still
//! being delivered -- which they are during every deadlock this device has,
//! because the timer IRQ is exactly what keeps running when the scheduler,
//! the service loop, or a lock has stopped making progress. The watchdog then
//! never fires, and the one class of fault it exists to bound is the one class
//! it cannot see.
//!
//! So the pet is gated on evidence instead. Each liveness owner bumps its own
//! epoch when it completes a unit of real work; the gate feeds the watchdog
//! only while every owner is still advancing, and withholds when one has gone
//! quiet for longer than its deadline. Withholding is how the reset happens:
//! this module never touches the watchdog itself.
//!
//! **Idling is progress.** The service loop advances its epoch on every
//! iteration including the ones where it finds nothing to do and returns to
//! `WFI` -- a device asleep with nothing queued is healthy, and a gate that
//! could not tell that from a hang would reset an idle phone every two
//! seconds.

use core::fmt::Write as _;
use core::sync::atomic::{AtomicU32, Ordering};

/// Kernel components whose forward progress the watchdog is a proof of.
///
/// Adding one is a deliberate act: the gate requires EVERY owner to advance,
/// so a new owner that stalls legitimately will reset the device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProgressOwner {
    /// The timer-IRQ scheduler round: a tick was accounted and the next
    /// runnable process selected.
    Scheduler,
    /// PID 0's service loop: one full iteration of the reflex/render/idle body.
    ServiceLoop,
}

impl ProgressOwner {
    /// Every owner, in index order -- the gate iterates this rather than a
    /// hand-written range, so adding a variant cannot leave one unwatched.
    pub(crate) const ALL: [Self; OWNER_COUNT] = [Self::Scheduler, Self::ServiceLoop];

    const fn index(self) -> usize {
        match self {
            Self::Scheduler => 0,
            Self::ServiceLoop => 1,
        }
    }

    /// Name for the boot log; the refusal must say WHICH owner stopped.
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Scheduler => "scheduler",
            Self::ServiceLoop => "service-loop",
        }
    }
}

/// How many owners the gate watches.
pub(crate) const OWNER_COUNT: usize = 2;

/// Ticks an owner may go without advancing before the gate withholds.
///
/// 200 ticks is 2 seconds at the 100 Hz timer. The hardware watchdog's period
/// is 5 seconds, so a withheld pet leaves roughly 3 seconds -- enough for the
/// refusal to reach the boot log before the reset lands, which is the whole
/// value of refusing early rather than simply timing out. A deadline at or
/// above the hardware period would never be reached: the device would reset
/// first and the gate would have decided nothing.
pub(crate) const STALL_DEADLINE_TICKS: u64 = 200;

/// Ticks an intentional shutdown may take before the gate stops covering it.
///
/// A shutdown legitimately stops scheduler and service-loop progress, so the
/// gate would withhold and reset the device mid-flush. It therefore pets
/// unconditionally once shutdown begins -- but only for this long, because a
/// shutdown that HANGS is still a hang, and an unbounded exemption would turn
/// the one path that disables the watchdog into a way to disable it forever.
pub(crate) const SHUTDOWN_GRACE_TICKS: u64 = 500;

/// What the gate says about feeding the watchdog right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub(crate) enum PetDecision {
    /// Feed it.
    Pet,
    /// Withhold. Left alone, the hardware resets the board.
    Withhold {
        /// The owner that stopped advancing. `None` when the shutdown grace
        /// window expired, which is not any single owner's fault.
        owner: Option<ProgressOwner>,
        /// Ticks since that owner last advanced.
        stalled_ticks: u64,
    },
}

/// Per-owner progress counters.
///
/// `AtomicU32` rather than `AtomicU64`: armv7a has no native 64-bit atomic
/// load/store, and the gate only ever compares two samples for inequality, so
/// wrapping at 2^32 is harmless -- it would take 32 bits of ticks at 100 Hz to
/// alias, and an owner that advanced exactly 2^32 times between two adjacent
/// ticks is not a case worth widening a word for.
static EPOCHS: [AtomicU32; OWNER_COUNT] = [const { AtomicU32::new(0) }; OWNER_COUNT];

/// Record that `owner` completed a unit of work.
///
/// Called from the owners themselves, on the ordinary path rather than an
/// error path: this is the assertion "I am still running", and it must be
/// unreachable when the owner is stuck.
pub(crate) fn record_progress(owner: ProgressOwner) {
    // Relaxed is sufficient: the gate reads these to detect CHANGE, not to
    // order any other memory, and both sides run on one core.
    EPOCHS[owner.index()].fetch_add(1, Ordering::Relaxed);
}

/// Sample every owner's epoch.
pub(crate) fn sample() -> [u32; OWNER_COUNT] {
    let mut out = [0u32; OWNER_COUNT];
    for (slot, epoch) in out.iter_mut().zip(EPOCHS.iter()) {
        *slot = epoch.load(Ordering::Relaxed);
    }
    out
}

/// The progress-coupled watchdog gate.
///
/// Pure: it holds no MMIO and reads no globals. The timer IRQ owns one
/// instance and hands it the epoch sample and the current tick, which is what
/// makes every rule here host-testable without a device.
#[derive(Debug)]
pub(crate) struct LivenessGate {
    /// Epoch values at the last observation.
    seen: [u32; OWNER_COUNT],
    /// Tick at which each owner last advanced.
    last_progress: [u64; OWNER_COUNT],
    /// False until the owners exist; before that the gate pets unconditionally.
    armed: bool,
    /// Tick at which an intentional shutdown began.
    shutdown_since: Option<u64>,
}

impl LivenessGate {
    /// A disarmed gate.
    ///
    /// WHY it starts disarmed and pets: `kinit` runs for a long time before a
    /// scheduler or a service loop exists, and a gate that demanded their
    /// progress from the first tick would reset the device during boot -- every
    /// time, on every device, before anything could log why.
    pub(crate) const fn new() -> Self {
        Self {
            seen: [0; OWNER_COUNT],
            last_progress: [0; OWNER_COUNT],
            armed: false,
            shutdown_since: None,
        }
    }

    /// Begin requiring progress, as of `now`.
    ///
    /// Called once the owners are running. The epoch sample is taken here so
    /// the work they did before arming does not count as progress afterwards.
    pub(crate) fn arm(&mut self, epochs: [u32; OWNER_COUNT], now: u64) {
        self.seen = epochs;
        self.last_progress = [now; OWNER_COUNT];
        self.armed = true;
    }

    /// Whether the gate is requiring progress.
    pub(crate) const fn is_armed(&self) -> bool {
        self.armed
    }

    /// Note that an intentional shutdown began at `now`.
    pub(crate) const fn begin_shutdown(&mut self, now: u64) {
        self.shutdown_since = Some(now);
    }

    /// Decide whether to feed the watchdog.
    ///
    /// Takes the epoch sample rather than reading it, so a test can drive any
    /// progress pattern it likes.
    pub(crate) fn decide(&mut self, epochs: [u32; OWNER_COUNT], now: u64) -> PetDecision {
        if let Some(began) = self.shutdown_since {
            let elapsed = now.saturating_sub(began);
            return if elapsed <= SHUTDOWN_GRACE_TICKS {
                PetDecision::Pet
            } else {
                PetDecision::Withhold {
                    owner: None,
                    stalled_ticks: elapsed,
                }
            };
        }

        if !self.armed {
            return PetDecision::Pet;
        }

        // Record advancement first, for every owner, before judging any of
        // them. A loop that judged as it went would report the first stalled
        // owner it happened to reach rather than the one that has been stalled
        // longest, and the boot log would then name a different owner run to
        // run for one underlying fault.
        for (i, epoch) in epochs.iter().enumerate() {
            if *epoch != self.seen[i] {
                self.seen[i] = *epoch;
                self.last_progress[i] = now;
            }
        }

        let mut worst: Option<(ProgressOwner, u64)> = None;
        for owner in ProgressOwner::ALL {
            let stalled = now.saturating_sub(self.last_progress[owner.index()]);
            if stalled > STALL_DEADLINE_TICKS
                && worst.is_none_or(|(_, worst_stalled)| stalled > worst_stalled)
            {
                worst = Some((owner, stalled));
            }
        }

        match worst {
            Some((owner, stalled_ticks)) => PetDecision::Withhold {
                owner: Some(owner),
                stalled_ticks,
            },
            None => PetDecision::Pet,
        }
    }

    /// Ticks since `owner` last advanced, for the boot log.
    ///
    /// Reading this must never move a deadline -- it is a report, and a report
    /// that extended the thing it reports on would make the gate unfalsifiable.
    pub(crate) fn stalled_ticks(&self, owner: ProgressOwner, now: u64) -> u64 {
        now.saturating_sub(self.last_progress[owner.index()])
    }
}

// ---------------------------------------------------------------------------
// The kernel's single gate
// ---------------------------------------------------------------------------

/// The one gate, owned by the timer IRQ.
static mut GATE: LivenessGate = LivenessGate::new();

/// Whether the current withhold episode has already been logged.
///
/// Without this the refusal prints at 100 Hz for the three seconds before the
/// reset, and the UART's own backpressure becomes part of the fault. One line
/// per episode is the report; repeating it adds nothing and costs the log its
/// legibility exactly when someone needs to read it.
static mut WITHHOLD_REPORTED: bool = false;

/// Begin requiring progress. Called once, where the owners start running.
///
/// # Safety
///
/// Single-core kernel context, no concurrent access to `GATE`.
pub(crate) unsafe fn arm(now: u64) {
    // SAFETY: delegated to the caller's contract above.
    let gate = unsafe { &mut *core::ptr::addr_of_mut!(GATE) };
    gate.arm(sample(), now);
}

/// Note that an intentional shutdown began.
///
/// # Safety
///
/// As [`arm`].
pub(crate) unsafe fn begin_shutdown(now: u64) {
    // SAFETY: delegated to the caller's contract above.
    let gate = unsafe { &mut *core::ptr::addr_of_mut!(GATE) };
    gate.begin_shutdown(now);
}

/// Decide whether to feed the watchdog this tick.
///
/// # Safety
///
/// Must be called only from the timer IRQ, which owns `GATE`.
pub(crate) unsafe fn decide(now: u64) -> PetDecision {
    // SAFETY: delegated to the caller's contract above.
    let gate = unsafe { &mut *core::ptr::addr_of_mut!(GATE) };
    let decision = gate.decide(sample(), now);
    if matches!(decision, PetDecision::Pet) {
        // SAFETY: same single-owner contract.
        unsafe { WITHHOLD_REPORTED = false };
    }
    decision
}

/// Log a withheld pet, once per episode.
///
/// # Safety
///
/// As [`decide`].
pub(crate) unsafe fn report_withheld(owner: Option<ProgressOwner>, stalled_ticks: u64) {
    // SAFETY: delegated to the caller's contract above.
    if unsafe { WITHHOLD_REPORTED } {
        return;
    }
    // SAFETY: same.
    unsafe { WITHHOLD_REPORTED = true };

    let mut serial = crate::uart::Uart::new();
    let what = match owner {
        Some(o) => o.name(),
        None => "shutdown",
    };
    // Best-effort serial write from an IRQ handler: a failed log must not
    // change the decision that produced it.
    let _ = write!(
        serial,
        "\r\n!!! WATCHDOG WITHHELD: {what} has not advanced for {stalled_ticks} ticks !!!\r\n"
    );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Advance every owner: what a healthy tick looks like.
    fn all_advanced(base: [u32; OWNER_COUNT]) -> [u32; OWNER_COUNT] {
        let mut next = base;
        for e in &mut next {
            *e = e.wrapping_add(1);
        }
        next
    }

    #[test]
    fn a_disarmed_gate_pets_so_boot_survives_having_no_scheduler_yet() {
        // kinit runs for a long time before a scheduler or service loop
        // exists. A gate that demanded their progress from the first tick
        // would reset every device during boot, every time.
        let mut gate = LivenessGate::new();
        assert!(!gate.is_armed());
        for tick in 0..(STALL_DEADLINE_TICKS * 4) {
            assert_eq!(
                gate.decide([0; OWNER_COUNT], tick),
                PetDecision::Pet,
                "a disarmed gate must feed the watchdog however long boot takes"
            );
        }
    }

    #[test]
    fn a_healthy_system_pets_indefinitely() {
        let mut gate = LivenessGate::new();
        let mut epochs = [0u32; OWNER_COUNT];
        gate.arm(epochs, 0);
        for tick in 1..(STALL_DEADLINE_TICKS * 5) {
            epochs = all_advanced(epochs);
            assert_eq!(gate.decide(epochs, tick), PetDecision::Pet);
        }
    }

    #[test]
    fn each_owner_stalling_alone_is_caught_and_named() {
        // The acceptance asks that each progress owner be frozen
        // independently. Freezing one while the other keeps advancing is the
        // case a single global "did anything happen" counter cannot see, and
        // it is the realistic one: a wedged service loop with a live
        // scheduler, or the reverse.
        for stuck in ProgressOwner::ALL {
            let mut gate = LivenessGate::new();
            let mut epochs = [0u32; OWNER_COUNT];
            gate.arm(epochs, 0);

            for tick in 1..=STALL_DEADLINE_TICKS {
                for owner in ProgressOwner::ALL {
                    if owner != stuck {
                        epochs[owner.index()] = epochs[owner.index()].wrapping_add(1);
                    }
                }
                assert_eq!(
                    gate.decide(epochs, tick),
                    PetDecision::Pet,
                    "{} must still be covered at tick {tick}, inside its deadline",
                    stuck.name()
                );
            }

            let past = STALL_DEADLINE_TICKS + 1;
            assert_eq!(
                gate.decide(epochs, past),
                PetDecision::Withhold {
                    owner: Some(stuck),
                    stalled_ticks: past,
                },
                "a stalled {} must be withheld and named",
                stuck.name()
            );
        }
    }

    #[test]
    fn an_owner_that_recovers_is_covered_again() {
        // Withholding is not a latch. A transient overrun that resumes should
        // stop the reset, or the gate would turn every long critical section
        // into a reboot.
        let mut gate = LivenessGate::new();
        let mut epochs = [0u32; OWNER_COUNT];
        gate.arm(epochs, 0);

        let stalled_at = STALL_DEADLINE_TICKS + 10;
        assert!(matches!(
            gate.decide(epochs, stalled_at),
            PetDecision::Withhold { .. }
        ));

        epochs = all_advanced(epochs);
        assert_eq!(
            gate.decide(epochs, stalled_at + 1),
            PetDecision::Pet,
            "progress after a withheld pet must restore cover"
        );
    }

    #[test]
    fn the_longest_stalled_owner_is_the_one_reported() {
        // Two stalled owners must produce a stable answer. Reporting whichever
        // the loop reached first would name a different owner run to run for
        // one underlying fault, and the boot log would look like two bugs.
        let mut gate = LivenessGate::new();
        let mut epochs = [0u32; OWNER_COUNT];
        gate.arm(epochs, 0);

        // ServiceLoop keeps going for a while; Scheduler froze at arm time.
        for tick in 1..=50 {
            epochs[ProgressOwner::ServiceLoop.index()] =
                epochs[ProgressOwner::ServiceLoop.index()].wrapping_add(1);
            let _ = gate.decide(epochs, tick);
        }

        let now = STALL_DEADLINE_TICKS + 100;
        assert_eq!(
            gate.decide(epochs, now),
            PetDecision::Withhold {
                owner: Some(ProgressOwner::Scheduler),
                stalled_ticks: now,
            },
            "the owner stalled longest is the one named"
        );
    }

    #[test]
    fn a_repeated_epoch_is_not_progress() {
        // The counter is evidence only when it CHANGES. An owner that keeps
        // reporting the same value -- a stuck write, a dead loop that still
        // touches the counter -- must read as stalled, not as alive.
        let mut gate = LivenessGate::new();
        let epochs = [7u32; OWNER_COUNT];
        gate.arm(epochs, 0);

        let now = STALL_DEADLINE_TICKS + 1;
        assert!(
            matches!(gate.decide(epochs, now), PetDecision::Withhold { .. }),
            "an unchanged epoch must not count as progress"
        );
    }

    #[test]
    fn a_wrapped_epoch_still_reads_as_progress() {
        // u32 wrapping must not look like a stall: the gate compares for
        // inequality, never for ordering, precisely so the wrap is a non-event.
        let mut gate = LivenessGate::new();
        let epochs = [u32::MAX; OWNER_COUNT];
        gate.arm(epochs, 0);

        let wrapped = [0u32; OWNER_COUNT];
        assert_eq!(
            gate.decide(wrapped, STALL_DEADLINE_TICKS + 1),
            PetDecision::Pet,
            "wrapping past u32::MAX is progress, not a stall"
        );
    }

    #[test]
    fn shutdown_is_covered_but_not_forever() {
        // A shutdown legitimately stops both owners, so the gate covers it --
        // otherwise the device resets mid-flush. But a shutdown that hangs is
        // still a hang, and an unbounded exemption would make the one path
        // that quiets the watchdog a way to disable it permanently.
        let mut gate = LivenessGate::new();
        let epochs = [0u32; OWNER_COUNT];
        gate.arm(epochs, 0);
        gate.begin_shutdown(1_000);

        assert_eq!(
            gate.decide(epochs, 1_000 + SHUTDOWN_GRACE_TICKS),
            PetDecision::Pet
        );
        assert_eq!(
            gate.decide(epochs, 1_000 + SHUTDOWN_GRACE_TICKS + 1),
            PetDecision::Withhold {
                owner: None,
                stalled_ticks: SHUTDOWN_GRACE_TICKS + 1,
            },
            "a shutdown that outruns its grace window stops being covered"
        );
    }

    #[test]
    fn the_deadline_leaves_room_for_the_refusal_to_be_logged() {
        // The point of refusing early is that the log lands before the reset.
        // A deadline at or past the hardware period would never be reached --
        // the device would reset first and the gate would have decided nothing.
        const TICK_HZ: u64 = 100;
        const WATCHDOG_SECS: u64 = 5;
        let hardware_period_ticks = TICK_HZ * WATCHDOG_SECS;
        assert!(
            STALL_DEADLINE_TICKS < hardware_period_ticks,
            "the stall deadline must fire before the hardware does"
        );
        assert!(
            hardware_period_ticks - STALL_DEADLINE_TICKS >= TICK_HZ,
            "leave at least a second between the refusal and the reset"
        );
        assert!(
            SHUTDOWN_GRACE_TICKS >= hardware_period_ticks,
            "the shutdown window must outlast one watchdog period, or an \
             ordinary shutdown would race the reset it is trying to beat"
        );
    }

    #[test]
    fn reporting_a_stall_does_not_move_the_deadline() {
        // A report that extended what it reports on would make the gate
        // unfalsifiable: every query would postpone the reset it exists to
        // cause.
        let mut gate = LivenessGate::new();
        let epochs = [0u32; OWNER_COUNT];
        gate.arm(epochs, 0);

        let now = STALL_DEADLINE_TICKS + 5;
        let first = gate.stalled_ticks(ProgressOwner::Scheduler, now);
        let second = gate.stalled_ticks(ProgressOwner::Scheduler, now);
        assert_eq!(first, second);
        assert_eq!(first, now);
        assert!(matches!(
            gate.decide(epochs, now),
            PetDecision::Withhold { .. }
        ));
    }

    #[test]
    fn arming_ignores_work_done_before_it() {
        // Owners bump their counters during boot too. If arm() kept the old
        // baseline, that pre-arm work would read as post-arm progress and the
        // gate would cover a system that had already stopped.
        let mut gate = LivenessGate::new();
        let busy = [99u32; OWNER_COUNT];
        gate.arm(busy, 500);
        assert_eq!(
            gate.decide(busy, 500 + STALL_DEADLINE_TICKS + 1),
            PetDecision::Withhold {
                owner: Some(ProgressOwner::Scheduler),
                stalled_ticks: STALL_DEADLINE_TICKS + 1,
            },
            "pre-arm epochs are the baseline, not evidence"
        );
    }

    #[test]
    fn every_owner_is_watched() {
        // ProgressOwner::ALL is what the gate iterates. A variant missing from
        // it would be an owner nobody checks -- silently, since the gate would
        // still work for the others.
        assert_eq!(ProgressOwner::ALL.len(), OWNER_COUNT);
        for (i, owner) in ProgressOwner::ALL.iter().enumerate() {
            assert_eq!(owner.index(), i, "ALL must be in index order");
        }
    }
}
