//! Kardia -- the kernel heartbeat: post-boot KernelState + service loop.
//!
//! `kinit::run()` hands its fn-scope subsystem state to [`KernelState`], and
//! the boot context (PID 0, the kernel/idle process created by
//! `process::init`) becomes [`service_loop`]. Each wake: drain the reflex
//! fast-path FIRST (reflex.rs), then on a new 100 Hz tick poll every
//! persisted subsystem non-blockingly, render if dirty, then idle until the
//! next interrupt. Userspace runs by PREEMPTING this loop -- the timer IRQ's
//! scheduler round-robins away from PID 0 and back; the loop itself never
//! calls `process::schedule()`.
//!
//! Coexistence is VERIFIED (#482/#487 + fault handling): the qemu isolation
//! matrix boots a real PL0 `/init`, so the timer IRQ preempts PID 0 into
//! userspace, `process::switch_to`'s taken branch runs, the process faults, the
//! kernel kills + reaps it, and control round-robins back to this loop (which
//! then services ticks to the cap). That is the two-process preempt-and-return
//! soak TODO(#420) asked for, now permanent in CI.
//!
//! WHY WFI (not WFE) for the phone idle (#461): WFE has no configured event
//! source (no SEV/SEVONPEND) and parks forever under qemu-virt; WFI wakes on
//! the 100 Hz timer IRQ on both targets. The idle WFI is issued IRQ-masked
//! (see [`service_loop`]) so a reflex IRQ that fires+retires in the check ->
//! idle window cannot be lost. WHY `exceptions::ticks()`, not
//! `timer::elapsed_ms()`, as the tick source (#461): the CNTPCT-backed
//! elapsed_ms does not advance under qemu-virt, while the IRQ-incremented
//! tick counter does.

use core::fmt::Write;

use crate::device::DeviceRegistry;
use crate::exceptions;
use crate::kinit::BootState;
use crate::power::PowerManager;
use crate::reflex;
use crate::security_mode::ModeManager;
use crate::uart::Uart;

/// Timer ticks per wall-clock second (exceptions.rs TICK_MS = 10).
const TICKS_PER_SECOND: u64 = 100;

/// QEMU CI cap: serviced ticks before a clean semihosting-exit 0. Proves the
/// service loop RUNS -- ticks advance and the loop body executes repeatedly
/// -- not merely that boot reached its end.
///
/// NOTE: this is 50 *serviced ticks*, NOT a wall-clock duration. Under
/// qemu-virt the generic-timer CNTFRQ is uncalibrated (#461), so the tick
/// rate is not a true 100 Hz; do not read this as "500 ms".
#[cfg(feature = "qemu")]
const QEMU_TICK_CAP: u32 = 50;

/// QEMU stall escape: a hard ceiling on total loop wakes. Under qemu the idle
/// is a busy-poll (not WFI -- see [`service_loop`]) so the loop always keeps
/// spinning; if `exceptions::ticks()` ever stalls (the #461 class: timer IRQ
/// stops / a frozen counter), the serviced-tick cap can never be reached, so
/// this ceiling forces a FAST exit with a distinct diagnostic code instead of
/// a 60 s runner timeout (which is indistinguishable from CI infra flake).
/// Far above `QEMU_TICK_CAP` so healthy runs never hit it.
#[cfg(feature = "qemu")]
const QEMU_WAKE_CEILING: u32 = 5_000_000;

/// Owned post-boot kernel state: every subsystem that must outlive
/// `kinit::run()`'s init blocks lives here, moved in at the boot->service
/// handoff and owned exclusively by the service loop.
///
/// INVARIANT (load-bearing -- the whole point of this struct): a subsystem
/// may be a `KernelState` field ONLY if it is never mutated in IRQ context.
/// Single-ownership by the loop is what makes plain (unsynchronized) access
/// race-free. An IRQ-fed subsystem (the CCCI modem's CLDMA RX, a RING URC, a
/// network device's RX -- i.e. exactly #398/#402) MUST NOT be a bare field:
/// it hands data to the loop through an `IrqSpinlock`-guarded structure (the
/// [`reflex`] mechanism, generalised to carry payloads), not by the loop and
/// an ISR both touching the same object. IRQ handlers communicate with this
/// struct through reflex flags ONLY.
///
/// Follow-on wirings (#398, #400-#404) each add their subsystem as a field
/// plus one non-blocking step in [`Self::poll_all`] -- subject to the
/// invariant above.
///
/// NOTE (power split-brain, #404): `power` is persisted here, but the timer
/// IRQ independently drives DVFS/core-parking/backlight on `power`-module
/// statics. #404 must unify these into a single owner (loop-owned here, IRQ
/// enqueuing) rather than double-managing two `PowerManager`s.
pub(crate) struct KernelState {
    pub(crate) boot: BootState,
    #[expect(
        dead_code,
        reason = "device lifecycle steps land with the subsystem wirings (#398, #400-#404)"
    )]
    pub(crate) devices: DeviceRegistry,
    #[expect(
        dead_code,
        reason = "radio-policy service steps land with the security-mode wiring (#404)"
    )]
    pub(crate) power: PowerManager,
    #[expect(
        dead_code,
        reason = "duress/panic mode transitions land with the security-mode wiring (#404)"
    )]
    pub(crate) mode: ModeManager,
    /// Last whole second observed, for once-per-second dirty marking.
    last_second: u64,
}

impl KernelState {
    /// Take ownership of the boot-built subsystem state.
    pub(crate) fn new(
        boot: BootState,
        devices: DeviceRegistry,
        power: PowerManager,
        mode: ModeManager,
    ) -> Self {
        Self {
            boot,
            devices,
            power,
            mode,
            last_second: 0,
        }
    }

    /// Poll every persisted subsystem once for tick `now`. Returns true when
    /// the active screen should re-render.
    ///
    /// INVARIANT: no step may block or wait -- poll(now)/tick(now)-style calls
    /// only; anything slower belongs in a budgeted state machine inside its
    /// subsystem.
    pub(crate) fn poll_all(&mut self, now: u64) -> bool {
        // NOTE(foundation): the home clock (once per second) is the only
        // persisted render input; each subsystem wiring adds its step here.
        let second = now / TICKS_PER_SECOND;
        if second != self.last_second {
            self.last_second = second;
            return true;
        }
        false
    }

    /// Render the active screen when marked dirty.
    ///
    /// TODO(#400)[deliberate-prudent]: screen-registry dispatch + framebuffer render; until then
    /// this is the seam where the frame is produced. Rendering is skipped when
    /// no display was brought up.
    pub(crate) fn render_if_dirty(&mut self) {
        if !self.boot.display_ok {
            return;
        }
        // TODO(#400)[deliberate-prudent]: dispatch to the active screen's draw().
    }

    /// Execute pending reflex fast-path events in privileged (loop) context.
    pub(crate) fn handle_reflex(&mut self, pending: reflex::Pending, serial: &mut Uart) {
        if pending.panic_wipe {
            let _ = serial.write_str("[kardia] REFLEX panic-wipe\r\n"); // WHY: best-effort loop diagnostic; must not block on a failed UART write
            // TODO(#404)[deliberate-prudent]: invoke panic_wipe via the persisted key manager.
        }
        if pending.duress {
            let _ = serial.write_str("[kardia] REFLEX duress\r\n"); // WHY: best-effort loop diagnostic; must not block on a failed UART write
            // TODO(#404)[deliberate-prudent]: duress transition via self.mode + wipe policy.
        }
        if pending.incoming_ring {
            let _ = serial.write_str("[kardia] REFLEX incoming-ring\r\n"); // WHY: best-effort loop diagnostic; must not block on a failed UART write
            // TODO(#398)[deliberate-prudent]: ring UI + audio route via persisted telephony.
        }
    }
}

/// The kernel service loop -- PID 0's body. Never returns (on the phone).
///
/// INVARIANT: entered with scheduling already enabled (kinit calls
/// `process::enable_scheduling()` first); everything here tolerates preemption
/// at any instruction outside an `IrqSpinlock` critical section.
pub(crate) fn service_loop(mut kernel: KernelState, mut serial: Uart) -> ! {
    let _ = serial.write_str("[kardia] service loop running\r\n"); // WHY: best-effort loop diagnostic; must not block on a failed UART write
    let mut last_tick = exceptions::ticks();
    #[cfg(feature = "qemu")]
    let mut serviced: u32 = 0;
    #[cfg(feature = "qemu")]
    let mut wakes: u32 = 0;
    loop {
        #[cfg(feature = "qemu")]
        {
            wakes += 1;
            if wakes >= QEMU_WAKE_CEILING {
                // ticks() stalled before QEMU_TICK_CAP -- fail FAST with a
                // distinct code rather than let the runner time out (#461).
                let _ = write!(
                    serial,
                    "THUMOS-QEMU: service-loop STALLED wakes={wakes} ticks={serviced}\r\n"
                );
                crate::qemu::request_exit(5);
            }
        }

        // Reflex fast-path FIRST -- drained on every wake, ahead of the tick
        // test, so a raised flag is handled promptly. Re-loop after handling
        // so a reflex handler that raises another is serviced immediately.
        let pending = reflex::drain();
        if pending.any() {
            kernel.handle_reflex(pending, &mut serial);
            continue;
        }

        let now = exceptions::ticks();
        if now != last_tick {
            // NOTE: a preemption gap of K ticks collapses to ONE service pass
            // with the latest `now` -- poll(now) interfaces are time-based, so
            // catch-up replay is unnecessary.
            last_tick = now;
            // WHY (#491 review): PID 0 is the parent of every spawned process,
            // so it reaps fault-killed (and exited) children each tick --
            // otherwise a fault-killed PCB slot leaks and the process table
            // exhausts at MAX_PROCS after repeated user faults. The marker is
            // the reaped-half witness the CI isolation matrix asserts.
            let reaped = crate::process::reap_dead_children();
            if reaped > 0 {
                let _ = write!(
                    serial,
                    "kardia: reaped {reaped} fault-killed process(es)\r\n"
                ); // WHY: best-effort diagnostic + CI marker
            }
            // TODO(#400)[deliberate-prudent]: poll_input() -> key events -> active-screen dispatch.
            if kernel.poll_all(now) {
                kernel.render_if_dirty();
            }
            #[cfg(feature = "qemu")]
            {
                serviced += 1;
                if serviced >= QEMU_TICK_CAP {
                    let _ = write!(serial, "THUMOS-QEMU: service-loop ticks={serviced}\r\n"); // WHY: best-effort CI marker; exit follows regardless
                    crate::qemu::request_exit(0);
                }
            }
            continue;
        }

        // Idle: no reflex, no new tick.
        idle(last_tick);
    }
}

/// Idle until the next interrupt.
///
/// On the phone: IRQ-masked WFI. WHY masked (closes the lost-wakeup window):
/// a reflex IRQ that fires+retires between the unmasked `drain` above and the
/// WFI would, with IRQs enabled, leave WFI waiting for an interrupt that
/// already passed -- degrading the fast-path to the 10 ms tick cadence it
/// exists to beat, and hiding a dependency on the timer never being gated (a
/// future tickless idle would then hang). Masking + re-checking under the
/// mask + WFI-while-masked (ARM WFI wakes on a GIC-pending interrupt
/// regardless of CPSR.I) closes it: either the re-check sees the flag/tick, or
/// the pending IRQ wakes the WFI; unmasking on guard drop takes it.
///
/// Under qemu: a busy-poll (`spin_loop`), NOT WFI, so the loop keeps spinning
/// and [`QEMU_WAKE_CEILING`] can always fire a fast diagnostic exit if ticks
/// stall (#461) -- termination must not itself depend on WFI waking.
fn idle(last_tick: u64) {
    #[cfg(feature = "qemu")]
    {
        let _ = last_tick;
        core::hint::spin_loop();
    }
    #[cfg(not(feature = "qemu"))]
    {
        let _guard = crate::irq::IrqGuard::new();
        // Re-check under the mask: a reflex flag set by an IRQ that already
        // retired, or a tick that advanced, means there is work -- skip WFI.
        if !reflex::peek_pending() && exceptions::ticks() == last_tick {
            crate::power::idle();
        }
        // _guard drops here -> IRQs unmask -> any GIC-pending IRQ is taken.
    }
}
