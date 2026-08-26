//! Observable watchdog model for QEMU `-machine virt`.
//!
//! The virt board has no MT6739 watchdog block at `0x1000_7000`, so MMIO
//! access would data-abort. A no-op backend cannot prove liveness wiring,
//! though: withholding a pet produces no different outcome. This backend
//! models the same tick countdown in software and exits QEMU with a distinct
//! status when it expires. Fault-injection features can therefore freeze an
//! owner and make the witness fail if any link from progress evidence through
//! pet refusal to reset disappears.

#[cfg(feature = "qemu")]
use core::fmt::Write as _;

use crate::liveness::WATCHDOG_TIMEOUT_TICKS;

/// Board-neutral watchdog countdown state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WatchdogModel {
    last_pet_tick: u64,
    is_armed: bool,
}

impl WatchdogModel {
    /// A disarmed model, matching the device before watchdog initialization.
    const fn new() -> Self {
        Self {
            last_pet_tick: 0,
            is_armed: false,
        }
    }

    /// Arm and start a fresh countdown.
    const fn init(&mut self, now: u64) {
        self.last_pet_tick = now;
        self.is_armed = true;
    }

    /// Restart the countdown.
    const fn pet(&mut self, now: u64) {
        if self.is_armed {
            self.last_pet_tick = now;
        }
    }

    /// Stop the countdown.
    const fn disable(&mut self) {
        self.is_armed = false;
    }

    /// Whether the autonomous countdown has reached its reset deadline.
    const fn is_expired(self, now: u64) -> bool {
        self.is_armed && now.saturating_sub(self.last_pet_tick) >= WATCHDOG_TIMEOUT_TICKS
    }
}

/// The QEMU board's single watchdog model.
#[cfg(feature = "qemu")]
static mut MODEL: WatchdogModel = WatchdogModel::new();

/// Tick at which the hung-shutdown probe's real reset backend was reached.
#[cfg(all(feature = "qemu", feature = "watchdog-shutdown-hang-probe"))]
static mut SHUTDOWN_PROBE_STARTED_AT: Option<u64> = None;

/// Whether the target observed the final permitted grace pet.
#[cfg(all(feature = "qemu", feature = "watchdog-shutdown-hang-probe"))]
static mut SHUTDOWN_PROBE_FINAL_PET_OBSERVED: bool = false;

/// Whether the target already exercised the late re-entry assertion.
#[cfg(all(feature = "qemu", feature = "watchdog-shutdown-hang-probe"))]
static mut SHUTDOWN_PROBE_REENTRY_OBSERVED: bool = false;

/// Initialize the modeled watchdog with a five-second countdown.
///
/// # Safety
///
/// Must run once during single-core kernel initialization, before timer-IRQ
/// calls to [`pet`] or [`observe_tick`].
#[cfg(feature = "qemu")]
pub unsafe fn init() {
    // SAFETY: delegated to the caller's single-owner contract.
    let model = unsafe { &mut *core::ptr::addr_of_mut!(MODEL) };
    model.init(crate::exceptions::ticks());
    #[cfg(feature = "watchdog-shutdown-hang-probe")]
    {
        // SAFETY: same initialization exclusion as MODEL above.
        unsafe {
            SHUTDOWN_PROBE_STARTED_AT = None;
            SHUTDOWN_PROBE_FINAL_PET_OBSERVED = false;
            SHUTDOWN_PROBE_REENTRY_OBSERVED = false;
        }
    }
}

/// Restart the modeled watchdog countdown.
///
/// # Safety
///
/// Must be called from the timer IRQ after [`init`].
#[cfg(feature = "qemu")]
pub unsafe fn pet() {
    // SAFETY: delegated to the caller's timer-IRQ ownership contract.
    let model = unsafe { &mut *core::ptr::addr_of_mut!(MODEL) };
    let now = crate::exceptions::ticks();
    model.pet(now);

    #[cfg(feature = "watchdog-shutdown-hang-probe")]
    {
        // SAFETY: the timer IRQ exclusively owns all probe state after init.
        let started_at = unsafe { SHUTDOWN_PROBE_STARTED_AT };
        // SAFETY: same timer-IRQ ownership.
        let final_pet_observed = unsafe { SHUTDOWN_PROBE_FINAL_PET_OBSERVED };
        if let Some(started_at) = started_at
            && !final_pet_observed
            && now.saturating_sub(started_at) == crate::liveness::SHUTDOWN_GRACE_TICKS
        {
            // SAFETY: same timer-IRQ ownership.
            unsafe { SHUTDOWN_PROBE_FINAL_PET_OBSERVED = true };
            let mut serial = crate::uart::Uart::new();
            let _ = writeln!(
                serial,
                "THUMOS-QEMU: shutdown grace final pet elapsed={}",
                crate::liveness::SHUTDOWN_GRACE_TICKS
            ); // WHY: target witness for the final allowed grace pet
        }
    }
}

/// Advance the modeled autonomous countdown and terminate on expiry.
///
/// # Safety
///
/// Must be called from the timer IRQ, which exclusively owns the model after
/// initialization.
#[cfg(feature = "qemu")]
pub unsafe fn observe_tick(now: u64) {
    // SAFETY: delegated to the caller's timer-IRQ ownership contract.
    let model = unsafe { &*core::ptr::addr_of!(MODEL) };
    if model.is_expired(now) {
        let mut serial = crate::uart::Uart::new();
        let since_pet = now.saturating_sub(model.last_pet_tick);
        let _ = writeln!(
            serial,
            "THUMOS-QEMU: emulated watchdog expired since_pet={since_pet}"
        ); // WHY: best-effort terminal witness; semihosting exit remains authoritative
        crate::qemu::request_exit(crate::qemu::WATCHDOG_EXPIRED_EXIT);
    }
}

/// Request a controlled QEMU reboot.
///
/// # Safety
///
/// Must be called only after the shutdown coordinator has entered liveness
/// grace. Semihosting terminates the emulated machine instead of touching
/// absent MT6739 reset registers.
#[cfg(feature = "qemu")]
pub unsafe fn request_reboot() {
    let mut serial = crate::uart::Uart::new();
    let _ = serial.write_str("THUMOS-QEMU: controlled reboot requested\r\n"); // WHY: best-effort terminal witness; semihosting exit remains authoritative

    #[cfg(feature = "watchdog-shutdown-hang-probe")]
    {
        // The production coordinator holds IRQs masked across grace acceptance
        // and this backend call, so this is the exact accepted-grace tick.
        // SAFETY: request_reboot is called under that single-core exclusion.
        unsafe { SHUTDOWN_PROBE_STARTED_AT = Some(crate::exceptions::ticks()) };
        let _ = serial.write_str("THUMOS-QEMU: controlled reboot reset failure injected\r\n"); // WHY: explicit target evidence that reset did not occur
    }

    #[cfg(not(feature = "watchdog-shutdown-hang-probe"))]
    crate::qemu::request_exit(crate::qemu::CONTROLLED_REBOOT_EXIT);
}

/// Exercise and verify a late grace re-entry after shutdown withholding began.
///
/// # Safety
///
/// Must be called from the timer IRQ after [`observe_tick`] and the liveness
/// decision for `now`. It mutates the same IRQ-exclusive model/probe state.
#[cfg(all(feature = "qemu", feature = "watchdog-shutdown-hang-probe"))]
pub unsafe fn probe_late_shutdown_reentry(now: u64) {
    // SAFETY: delegated to the timer-IRQ ownership contract.
    if unsafe { SHUTDOWN_PROBE_REENTRY_OBSERVED } {
        return;
    }
    // SAFETY: same ownership.
    unsafe { SHUTDOWN_PROBE_REENTRY_OBSERVED = true };

    // SAFETY: same ownership; model was armed during kinit.
    let model = unsafe { &*core::ptr::addr_of!(MODEL) };
    // SAFETY: same ownership.
    let Some(started_at) = (unsafe { SHUTDOWN_PROBE_STARTED_AT }) else {
        probe_failure("late re-entry observed before reset-failure injection");
    };
    let shutdown_elapsed = now.saturating_sub(started_at);
    let last_pet_elapsed = model.last_pet_tick.saturating_sub(started_at);
    // SAFETY: same ownership.
    let final_pet_observed = unsafe { SHUTDOWN_PROBE_FINAL_PET_OBSERVED };

    if shutdown_elapsed != crate::liveness::SHUTDOWN_GRACE_TICKS + 1
        || last_pet_elapsed != crate::liveness::SHUTDOWN_GRACE_TICKS
        || !final_pet_observed
    {
        probe_failure("shutdown pet boundary did not match the accepted grace");
    }

    let transition = crate::shutdown::probe_reenter_grace(now);
    let decision = unsafe { crate::liveness::decide(now) };
    if transition != crate::liveness::ShutdownTransition::AlreadyStarted
        || decision
            != (crate::liveness::PetDecision::Withhold {
                owner: None,
                stalled_ticks: shutdown_elapsed,
            })
    {
        probe_failure("late shutdown re-entry extended or replaced the original deadline");
    }

    let mut serial = crate::uart::Uart::new();
    let _ = writeln!(
        serial,
        "THUMOS-QEMU: shutdown grace immutable elapsed={shutdown_elapsed} last_pet_elapsed={last_pet_elapsed}"
    ); // WHY: target evidence that late re-entry did not resume petting
}

/// Terminate a malformed fault-injection run with a result distinct from the
/// expected watchdog expiry.
#[cfg(all(feature = "qemu", feature = "watchdog-shutdown-hang-probe"))]
fn probe_failure(reason: &str) -> ! {
    let mut serial = crate::uart::Uart::new();
    let _ = writeln!(serial, "THUMOS-QEMU: watchdog probe failure: {reason}"); // WHY: preserve the failed invariant in CI output
    crate::qemu::request_exit(crate::qemu::WATCHDOG_PROBE_FAILURE_EXIT);
    loop {
        core::hint::spin_loop();
    }
}

/// Disable the modeled watchdog.
///
/// # Safety
///
/// Must run with the same single-owner exclusion as [`init`].
#[cfg(feature = "qemu")]
pub unsafe fn disable() {
    // SAFETY: delegated to the caller's single-owner contract.
    let model = unsafe { &mut *core::ptr::addr_of_mut!(MODEL) };
    model.disable();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disarmed_model_never_expires() {
        let model = WatchdogModel::new();

        assert!(
            !model.is_expired(u64::MAX),
            "a watchdog that has not been initialized must remain disarmed"
        );
    }

    #[test]
    fn initialized_model_expires_at_the_hardware_deadline() {
        let mut model = WatchdogModel::new();
        model.init(10);

        assert!(
            !model.is_expired(10 + WATCHDOG_TIMEOUT_TICKS - 1),
            "the modeled watchdog must cover every tick before its deadline"
        );
        assert!(
            model.is_expired(10 + WATCHDOG_TIMEOUT_TICKS),
            "the modeled watchdog must expire at the shared hardware deadline"
        );
    }

    #[test]
    fn pet_restarts_the_modeled_countdown() {
        let mut model = WatchdogModel::new();
        model.init(10);
        model.pet(10 + WATCHDOG_TIMEOUT_TICKS - 1);

        assert!(
            !model.is_expired(10 + WATCHDOG_TIMEOUT_TICKS),
            "a pet immediately before expiry must start a fresh countdown"
        );
        assert!(
            model.is_expired(10 + (WATCHDOG_TIMEOUT_TICKS * 2) - 1),
            "the fresh countdown must still expire when no later pet arrives"
        );
    }

    #[test]
    fn disabled_model_stays_stopped() {
        let mut model = WatchdogModel::new();
        model.init(10);
        model.disable();
        model.pet(20);

        assert!(
            !model.is_expired(u64::MAX),
            "disable must stop expiry and later pets must not re-arm the model"
        );
    }
}
