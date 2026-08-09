//! PID-0 fault supervision (#492): the fault channel + the restart policy.
//!
//! A PL0 fault reaches PID 0 as a [`FaultReport`] pushed onto a dedicated ring
//! from the abort handler, and the service loop drains it once per tick: it
//! audit-logs every report, and RESTARTS a supervised service that crashed --
//! with crash-loop rate limiting.
//!
//! WHY a dedicated ring, not PID 0's IPC inbox: `notify_fault` used to
//! `ipc::send(0, ..)` the report, but nothing ever drained it, so reports piled
//! up and (at `INBOX_SIZE`) were dropped, while any legitimate userspace
//! `send(0, ..)` then failed with `InboxFull`. A naive drain is not the answer
//! either -- `ipc::recv` pops the FRONT regardless of tag, so it would discard
//! real user->PID0 IPC. Separating the channels is what makes the drain safe,
//! and it also drops the `CURRENT`-swap hack `notify_fault` needed only so
//! `ipc::send` would stamp the right sender.
//!
//! Concurrency CONTRACT (single-core), mirroring [`crate::reflex`]: the writer
//! ([`report_fault`]) runs in ABORT context; the drainer ([`pop_report`]) and
//! the policy run in the service loop (PID 0). All take the same
//! [`IrqSpinlock`] -- which masks IRQ delivery AND holds a flag for the critical
//! section -- so a drain can never interleave with a report. The `static mut`s
//! are never touched off-lock.
//!
//! WHY the abort-context writer cannot deadlock on a lock the loop already holds
//! (this is load-bearing and NOT obvious): the spinlock's flag does NOT nest --
//! re-entering `lock()` on a held flag would spin forever, with no other core to
//! release it -- and an abort is an EXCEPTION, so IRQ masking does not prevent
//! one from being taken. The argument is instead:
//!
//! - A PL0 fault can only be taken while a USER process is running, which
//!   requires the loop to have been preempted by the timer IRQ. IRQ delivery is
//!   masked for exactly as long as the loop holds this lock, so no user process
//!   can run -- and therefore no PL0 fault can be raised -- inside that window.
//! - A PL1 (kernel) fault taken under the lock never reaches here at all:
//!   `process::fault_disposition` routes a non-User-mode fault to `KernelHalt`
//!   (fail-closed), not to `notify_fault`.
//!
//! So `report_fault` only ever runs when the loop is NOT in its critical section.
//!
//! The reaper ([`crate::process::reap_dead_children`]) stays the slot-reclaim
//! backstop: it scans PCB `Dead` state, so a report dropped on a full ring still
//! costs nothing but the notification.

use crate::irq::IrqSpinlock;
use crate::process::Pid;

/// Fault reports buffered between the abort handler and the service loop.
///
/// WHY 16: a tick drains the whole ring, so this only has to absorb the faults
/// of one 10 ms window. A crash-looping service produces one per restart.
const RING_SIZE: usize = 16;

/// Supervised services tracked at once. /shell today (+ /crasher under the
/// crashloop-probe feature); sized for the handful a phone would run.
const MAX_SUPERVISED: usize = 4;

/// Restarts allowed inside [`WINDOW_TICKS`] before the supervisor gives up.
const MAX_RESTARTS: u8 = 3;

/// Crash-loop window, in scheduler ticks (100 Hz -> 5 s).
const WINDOW_TICKS: u64 = 500;

/// A PL0 fault, as handed to PID 0.
///
/// `kind` matches the wire tags the old inbox protocol used: 1 = data abort,
/// 2 = prefetch abort, 3 = undefined instruction.
///
/// `service` is resolved AT FAULT TIME, not at drain time. WHY: a pid only
/// names one process while that process is alive, and pids are reused -- by the
/// time the loop drains, the faulting pid may already belong to something else,
/// so a drain-time registry lookup would restart the wrong service (observed:
/// /crasher was relaunched into /shell's freed pid, and the next fault matched
/// /shell's stale claim). At fault time the pid is unambiguous: the process is
/// dying right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FaultReport {
    pub(crate) pid: Pid,
    pub(crate) kind: u8,
    pub(crate) fault_addr: u32,
    pub(crate) fault_status: u32,
    /// The supervised service this pid WAS, if any.
    pub(crate) service: Option<&'static str>,
}

/// A supervised service: a boot-resident program PID 0 relaunches when it
/// FAULTS. Keyed by ramfs path because the PCB retains no image identity -- a
/// restart must re-plan from the ramfs by name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SupervisedService {
    path: &'static str,
    current_pid: Option<Pid>,
    restarts_in_window: u8,
    window_start_tick: u64,
    gave_up: bool,
}

/// What the service loop should do about a drained report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Decision {
    /// Not a supervised service (or already given up): audit only.
    None,
    /// Relaunch this service from the ramfs.
    Restart(&'static str),
    /// The crash-loop limit is spent -- stop relaunching this service.
    GiveUp(&'static str),
}

static LOCK: IrqSpinlock = IrqSpinlock::new();

/// Guarded by [`LOCK`] -- never touch without holding it.
static mut RING: [Option<FaultReport>; RING_SIZE] = [None; RING_SIZE];
/// Guarded by [`LOCK`]. Head = next pop, count = live entries (FIFO).
static mut RING_HEAD: usize = 0;
static mut RING_COUNT: usize = 0;
/// Guarded by [`LOCK`].
static mut SERVICES: [Option<SupervisedService>; MAX_SUPERVISED] = [None; MAX_SUPERVISED];

/// Push a fault report for PID 0. Called from the abort handler.
///
/// A full ring DROPS the newest report and says so on the UART: the report is
/// only a notification, and the scan-based reaper still reclaims the slot, so
/// dropping is survivable (and preferable to evicting an older, unserviced one).
pub(crate) fn report_fault(pid: Pid, kind: u8, fault_addr: u32, fault_status: u32) {
    let _guard = LOCK.lock();
    // SAFETY: the ring + registry are only touched under LOCK, whose IrqSpinlock
    // masks IRQ delivery for the critical section -- no abort-vs-loop
    // interleaving is possible on this single-core kernel.
    let full = unsafe {
        // Resolve pid -> service NOW, while the pid still unambiguously names the
        // dying process, and drop the claim: after this the pid is free to be
        // reused, and no later fault may match this service through it.
        let mut service = None;
        for svc in (*core::ptr::addr_of_mut!(SERVICES)).iter_mut().flatten() {
            if svc.current_pid == Some(pid) {
                svc.current_pid = None;
                service = Some(svc.path);
                break;
            }
        }
        let count = *core::ptr::addr_of!(RING_COUNT);
        if count >= RING_SIZE {
            true
        } else {
            let head = *core::ptr::addr_of!(RING_HEAD);
            let slot = (head + count) % RING_SIZE;
            (*core::ptr::addr_of_mut!(RING))[slot] = Some(FaultReport {
                pid,
                kind,
                fault_addr,
                fault_status,
                service,
            });
            *core::ptr::addr_of_mut!(RING_COUNT) = count + 1;
            false
        }
    };
    if full {
        use core::fmt::Write;

        use crate::uart::Uart;
        let mut serial = Uart::new();
        write!(
            serial,
            "FAULTDROP pid={pid} kind={kind} fault-ring-full\r\n"
        )
        .ok();
    }
}

/// Pop the oldest pending report, or `None` when the ring is empty.
pub(crate) fn pop_report() -> Option<FaultReport> {
    let _guard = LOCK.lock();
    // SAFETY: see `report_fault` -- the ring is only touched under LOCK.
    unsafe {
        let count = *core::ptr::addr_of!(RING_COUNT);
        if count == 0 {
            return None;
        }
        let head = *core::ptr::addr_of!(RING_HEAD);
        let report = (*core::ptr::addr_of_mut!(RING))[head].take();
        *core::ptr::addr_of_mut!(RING_HEAD) = (head + 1) % RING_SIZE;
        *core::ptr::addr_of_mut!(RING_COUNT) = count - 1;
        report
    }
}

/// Register `path` as supervised, currently running as `pid`.
///
/// Called by kinit right after a successful supervised spawn. Re-registering a
/// known path just refreshes its pid (it does NOT reset the crash-loop window,
/// so a service cannot escape rate limiting by re-registering).
pub(crate) fn register(path: &'static str, pid: Pid) {
    let _guard = LOCK.lock();
    // SAFETY: SERVICES is only touched under LOCK (see `report_fault`).
    unsafe {
        let services = &mut *core::ptr::addr_of_mut!(SERVICES);
        for slot in services.iter_mut() {
            if let Some(svc) = slot {
                if svc.path == path {
                    svc.current_pid = Some(pid);
                    return;
                }
            }
        }
        for slot in services.iter_mut() {
            if slot.is_none() {
                *slot = Some(SupervisedService {
                    path,
                    current_pid: Some(pid),
                    restarts_in_window: 0,
                    window_start_tick: 0,
                    gave_up: false,
                });
                return;
            }
        }
    }
}

/// Point a supervised service at its freshly-restarted pid (`None` if the
/// relaunch failed, so a later fault cannot match a stale pid).
pub(crate) fn set_current_pid(path: &'static str, pid: Option<Pid>) {
    let _guard = LOCK.lock();
    // SAFETY: SERVICES is only touched under LOCK (see `report_fault`).
    unsafe {
        let services = &mut *core::ptr::addr_of_mut!(SERVICES);
        for svc in services.iter_mut().flatten() {
            if svc.path == path {
                svc.current_pid = pid;
                return;
            }
        }
    }
}

/// Decide what a drained report means for supervision.
///
/// Keyed on the report's fault-time-resolved `service`, never on a drain-time pid
/// lookup (pids are reused) and never on PCB `Dead` state -- so a service that
/// exits CLEANLY (like /shell today) is never relaunched; only a crash is.
pub(crate) fn decide(report: &FaultReport, now: u64) -> Decision {
    let Some(path) = report.service else {
        return Decision::None; // not a supervised service: audit only
    };
    let _guard = LOCK.lock();
    // SAFETY: SERVICES is only touched under LOCK (see `report_fault`).
    unsafe {
        let services = &mut *core::ptr::addr_of_mut!(SERVICES);
        for svc in services.iter_mut().flatten() {
            if svc.path != path {
                continue;
            }
            if svc.gave_up {
                return Decision::None;
            }
            // A fault outside the window opens a fresh one -- an occasional
            // crash every few minutes is not a crash LOOP.
            if now.saturating_sub(svc.window_start_tick) > WINDOW_TICKS {
                svc.window_start_tick = now;
                svc.restarts_in_window = 0;
            }
            if svc.restarts_in_window < MAX_RESTARTS {
                svc.restarts_in_window += 1;
                return Decision::Restart(svc.path);
            }
            svc.gave_up = true;
            return Decision::GiveUp(svc.path);
        }
        Decision::None
    }
}

/// Drop any supervised claim on `pid` -- that process is gone.
///
/// Called from the EXIT path, so a service that exits CLEANLY (and therefore
/// never files a fault report) cannot leave a stale pid behind for an unrelated
/// process to inherit and alias into a spurious restart. A fault-exit reaches
/// here too, but `report_fault` already released the claim, so this is a no-op
/// there -- which is why the claim must be released at fault time and not here.
pub(crate) fn clear_pid(pid: Pid) {
    let _guard = LOCK.lock();
    // SAFETY: SERVICES is only touched under LOCK (see `report_fault`).
    unsafe {
        for svc in (*core::ptr::addr_of_mut!(SERVICES)).iter_mut().flatten() {
            if svc.current_pid == Some(pid) {
                svc.current_pid = None;
            }
        }
    }
}

/// Restarts allowed per window, for the give-up marker.
pub(crate) const fn max_restarts() -> u8 {
    MAX_RESTARTS
}

/// Render a report as an audit detail: `kind=<n> addr=<hex> status=<hex>`.
///
/// Returns the buffer and its used length (the caller passes `&buf[..len]`).
/// Fixed-size and allocation-free; a detail that would overrun is truncated,
/// since a short audit record still beats no record.
pub(crate) fn audit_detail(report: &FaultReport) -> ([u8; DETAIL_CAP], usize) {
    struct Buf {
        bytes: [u8; DETAIL_CAP],
        len: usize,
    }
    impl core::fmt::Write for Buf {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            for &b in s.as_bytes() {
                if self.len >= self.bytes.len() {
                    return Err(core::fmt::Error);
                }
                self.bytes[self.len] = b;
                self.len += 1;
            }
            Ok(())
        }
    }
    let mut buf = Buf {
        bytes: [0u8; DETAIL_CAP],
        len: 0,
    };
    let _ = core::fmt::Write::write_fmt(
        &mut buf,
        format_args!(
            "kind={} addr={:#010x} status={:#010x}",
            report.kind, report.fault_addr, report.fault_status
        ),
    );
    (buf.bytes, buf.len)
}

/// Audit-detail buffer size; matches `audit::DETAIL_LEN`.
const DETAIL_CAP: usize = 64;

/// Drop all supervision state (tests).
#[cfg(test)]
pub(crate) fn reset() {
    let _guard = LOCK.lock();
    // SAFETY: see `report_fault` -- state is only touched under LOCK.
    unsafe {
        *core::ptr::addr_of_mut!(RING) = [None; RING_SIZE];
        *core::ptr::addr_of_mut!(RING_HEAD) = 0;
        *core::ptr::addr_of_mut!(RING_COUNT) = 0;
        *core::ptr::addr_of_mut!(SERVICES) = [None; MAX_SUPERVISED];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(pid: Pid) -> FaultReport {
        FaultReport {
            pid,
            kind: 1,
            fault_addr: 0xDEAD_0000,
            fault_status: 0x0000_000F,
            service: None,
        }
    }

    /// Fault `pid` through the real path: abort-context report (which resolves
    /// the service) -> service-loop drain.
    fn fault(pid: Pid) -> FaultReport {
        report_fault(pid, 1, 0xDEAD_0000, 0x0000_000F);
        pop_report().expect("a report must reach the ring")
    }

    #[test]
    fn ring_is_fifo_and_drains_empty() {
        reset();
        assert_eq!(pop_report(), None, "an empty ring yields nothing");
        report_fault(1, 1, 0xDEAD_0000, 0x0000_000F);
        report_fault(2, 3, 0, 0);
        let first = pop_report().expect("first report");
        assert_eq!(first, report(1), "oldest report pops first");
        assert_eq!(pop_report().map(|r| r.pid), Some(2), "then the next");
        assert_eq!(pop_report(), None, "ring drains empty");
    }

    #[test]
    fn ring_full_drops_the_newest_and_keeps_the_backlog() {
        reset();
        for pid in 0..u8::try_from(RING_SIZE).unwrap_or(u8::MAX) {
            report_fault(pid, 1, 0, 0);
        }
        // One past capacity: dropped, and the existing backlog is intact.
        report_fault(99, 1, 0, 0);
        for pid in 0..u8::try_from(RING_SIZE).unwrap_or(u8::MAX) {
            assert_eq!(
                pop_report().map(|r| r.pid),
                Some(pid),
                "the backlog must survive an overflow"
            );
        }
        assert_eq!(pop_report(), None, "the overflowing report was dropped");
    }

    #[test]
    fn an_unsupervised_pid_yields_no_decision() {
        reset();
        assert_eq!(
            decide(&fault(7), 0),
            Decision::None,
            "unknown pid: audit only"
        );
        register("/shell", 2);
        assert_eq!(
            decide(&fault(7), 0),
            Decision::None,
            "a fault by another pid must not touch /shell"
        );
    }

    #[test]
    fn a_supervised_crash_restarts_up_to_the_limit_then_gives_up() {
        reset();
        register("/svc", 2);
        for i in 1..=MAX_RESTARTS {
            assert_eq!(
                decide(&fault(2), 10),
                Decision::Restart("/svc"),
                "restart {i} must be allowed"
            );
            // The relaunch installs the pid the next fault resolves through.
            set_current_pid("/svc", Some(2));
        }
        assert_eq!(
            decide(&fault(2), 10),
            Decision::GiveUp("/svc"),
            "the {MAX_RESTARTS}th restart exhausts the window"
        );
    }

    #[test]
    fn give_up_is_permanent_within_a_boot() {
        reset();
        register("/svc", 2);
        for _ in 0..MAX_RESTARTS {
            let _ = decide(&fault(2), 0);
            set_current_pid("/svc", Some(2));
        }
        assert_eq!(decide(&fault(2), 0), Decision::GiveUp("/svc"));
        set_current_pid("/svc", Some(2));
        // Far outside the window: a fresh window must NOT resurrect it.
        assert_eq!(
            decide(&fault(2), WINDOW_TICKS * 10),
            Decision::None,
            "give-up must not be undone by a window reset"
        );
    }

    #[test]
    fn a_crash_outside_the_window_opens_a_fresh_one() {
        reset();
        register("/svc", 2);
        for _ in 0..MAX_RESTARTS {
            assert_eq!(decide(&fault(2), 10), Decision::Restart("/svc"));
            set_current_pid("/svc", Some(2));
        }
        // A crash long after the window: rate limiting resets, so an occasional
        // crash never accumulates into a give-up.
        assert_eq!(
            decide(&fault(2), 10 + WINDOW_TICKS + 1),
            Decision::Restart("/svc"),
            "a fault past the window starts a new budget"
        );
    }

    #[test]
    fn re_registering_refreshes_the_pid_without_resetting_the_budget() {
        reset();
        register("/svc", 2);
        assert_eq!(decide(&fault(2), 0), Decision::Restart("/svc"));
        // Re-register (as a relaunch would) must not hand back a fresh budget.
        register("/svc", 5);
        assert_eq!(decide(&fault(5), 0), Decision::Restart("/svc"));
        register("/svc", 6);
        assert_eq!(decide(&fault(6), 0), Decision::Restart("/svc"));
        register("/svc", 7);
        assert_eq!(
            decide(&fault(7), 0),
            Decision::GiveUp("/svc"),
            "re-registration must not escape rate limiting"
        );
    }

    #[test]
    fn a_fault_resolves_its_service_at_fault_time_and_releases_the_pid() {
        reset();
        register("/svc", 2);
        let r = fault(2);
        assert_eq!(
            r.service,
            Some("/svc"),
            "the report must name the service while the pid is unambiguous"
        );
        // The claim is released immediately, so the pid may be reused freely.
        assert_eq!(
            fault(2).service,
            None,
            "the released pid must not resolve to the service again"
        );
    }

    #[test]
    fn a_pid_reused_after_a_clean_exit_restarts_its_current_owner_not_the_old_one() {
        // The bug the crash-loop witness caught: /shell registered pid 2 and then
        // exited CLEANLY -- which files no fault report, so nothing released its
        // claim. /crasher was later relaunched INTO the freed pid 2, and its next
        // fault matched /shell's stale claim, restarting the wrong service.
        reset();
        register("/shell", 2);
        clear_pid(2); // the exit path releases the claim on a clean exit
        register("/crasher", 2); // the pid is reused by another supervised service
        assert_eq!(
            decide(&fault(2), 0),
            Decision::Restart("/crasher"),
            "a fault on a reused pid must restart its CURRENT owner"
        );
    }

    #[test]
    fn a_cleanly_exited_service_is_never_restarted_by_someone_elses_fault() {
        reset();
        register("/shell", 2);
        clear_pid(2); // /shell exits cleanly
        // An unrelated, unsupervised process later inherits pid 2 and faults.
        assert_eq!(
            decide(&fault(2), 0),
            Decision::None,
            "a clean exit must never be turned into a restart by a pid reuse"
        );
    }

    #[test]
    fn audit_detail_carries_kind_addr_and_status() {
        let (buf, len) = audit_detail(&report(4));
        let text = core::str::from_utf8(&buf[..len]).expect("detail must be utf-8");
        assert_eq!(
            text, "kind=1 addr=0xdead0000 status=0x0000000f",
            "the audit record must carry the forensic fields"
        );
        assert!(
            len <= DETAIL_CAP,
            "the detail must fit the audit record's field"
        );
    }

    #[test]
    fn a_failed_relaunch_clears_the_pid_so_no_stale_match() {
        reset();
        register("/svc", 2);
        assert_eq!(decide(&fault(2), 0), Decision::Restart("/svc"));
        set_current_pid("/svc", None); // relaunch failed
        assert_eq!(
            decide(&fault(2), 0),
            Decision::None,
            "a stale pid must not match after a failed relaunch"
        );
    }
}
