//! Controlled shutdown and reboot coordination.
//!
//! Every intentional reset crosses one boundary: enter the bounded watchdog
//! grace period before requesting the platform reset. Keeping that ordering in
//! one coordinator prevents a caller from stopping liveness owners first and
//! then discovering that the watchdog still judges them as ordinary stalls.

use crate::liveness::ShutdownTransition;

/// Platform operations sequenced by the shutdown coordinator.
trait RebootPlatform {
    /// Enter the watchdog's bounded shutdown grace period.
    fn begin_grace(&mut self, now: u64) -> ShutdownTransition;

    /// Ask the platform to reset.
    fn request_reset(&mut self);
}

/// The real kernel reboot platform.
struct KernelRebootPlatform;

impl RebootPlatform for KernelRebootPlatform {
    fn begin_grace(&mut self, now: u64) -> ShutdownTransition {
        let _irq_guard = crate::irq::IrqGuard::new();
        // SAFETY: IRQ delivery is masked for the mutation, so the timer IRQ
        // cannot concurrently access its otherwise IRQ-exclusive gate.
        unsafe { crate::liveness::begin_shutdown(now) }
    }

    fn request_reset(&mut self) {
        // SAFETY: the watchdog was initialized during kinit after MMIO became
        // available. The QEMU implementation has the same contract and emits
        // an observable semihosting reset instead of touching MT6739 MMIO.
        unsafe { crate::watchdog::request_reboot() }
    }
}

/// Sequence the accepted grace transition before the reset request.
fn coordinate_reboot<P: RebootPlatform>(platform: &mut P, now: u64) -> ShutdownTransition {
    let transition = platform.begin_grace(now);
    platform.request_reset();
    transition
}

/// Reboot through the kernel's single controlled-shutdown boundary.
///
/// WHY: callers must not write reset registers directly. This boundary enters
/// the bounded watchdog grace first, then requests reset, so a failed reset
/// remains bounded by the watchdog instead of disabling liveness forever.
pub(crate) fn reboot() -> ! {
    {
        // Keep the accepted grace transition and reset request atomic relative
        // to the timer IRQ. In particular, a failed reset may resume IRQs only
        // after the immutable grace timestamp has been installed.
        let _irq_guard = crate::irq::IrqGuard::new();
        let mut platform = KernelRebootPlatform;
        let _transition = coordinate_reboot(&mut platform, crate::exceptions::ticks());
    }

    loop {
        #[cfg(target_arch = "arm")]
        {
            // SAFETY: WFI is a privileged wait hint. IRQs are enabled again
            // after begin_grace's guard dropped, so the watchdog gate keeps
            // enforcing the bounded shutdown window if reset does not land.
            unsafe { core::arch::asm!("wfi") };
        }
        #[cfg(not(target_arch = "arm"))]
        core::hint::spin_loop();
    }
}

/// Re-enter the production grace operation for the QEMU late-entry witness.
///
/// This deliberately calls the same [`KernelRebootPlatform`] operation used
/// by [`reboot`], rather than editing the liveness gate from the test backend.
/// The caller is already in the timer IRQ; the nested guard preserves that
/// prior mask state.
#[cfg(all(feature = "qemu", feature = "watchdog-shutdown-hang-probe"))]
pub(crate) fn probe_reenter_grace(now: u64) -> ShutdownTransition {
    let mut platform = KernelRebootPlatform;
    platform.begin_grace(now)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Call {
        BeginGrace(u64),
        RequestReset,
    }

    struct RecordingPlatform {
        calls: [Option<Call>; 2],
        call_count: usize,
        transition: ShutdownTransition,
    }

    impl RecordingPlatform {
        fn record(&mut self, call: Call) {
            let slot = self
                .calls
                .get_mut(self.call_count)
                .expect("the coordinator must make exactly two platform calls");
            *slot = Some(call);
            self.call_count += 1;
        }
    }

    impl RebootPlatform for RecordingPlatform {
        fn begin_grace(&mut self, now: u64) -> ShutdownTransition {
            self.record(Call::BeginGrace(now));
            self.transition
        }

        fn request_reset(&mut self) {
            self.record(Call::RequestReset);
        }
    }

    #[test]
    fn reboot_enters_grace_before_requesting_reset() {
        let mut platform = RecordingPlatform {
            calls: [None; 2],
            call_count: 0,
            transition: ShutdownTransition::Started,
        };

        let transition = coordinate_reboot(&mut platform, 41);

        assert_eq!(
            transition,
            ShutdownTransition::Started,
            "the coordinator must return the liveness transition"
        );
        assert_eq!(
            platform.calls,
            [Some(Call::BeginGrace(41)), Some(Call::RequestReset)],
            "shutdown grace must begin before the platform reset is requested"
        );
        assert_eq!(
            platform.call_count, 2,
            "the coordinator must make each platform call exactly once"
        );
    }

    #[test]
    fn repeated_transition_does_not_skip_the_reset_request() {
        let mut platform = RecordingPlatform {
            calls: [None; 2],
            call_count: 0,
            transition: ShutdownTransition::AlreadyStarted,
        };

        let transition = coordinate_reboot(&mut platform, 99);

        assert_eq!(
            transition,
            ShutdownTransition::AlreadyStarted,
            "an existing grace window must remain visible to the caller"
        );
        assert_eq!(
            platform.calls,
            [Some(Call::BeginGrace(99)), Some(Call::RequestReset)],
            "a repeated request must not postpone or omit the platform reset"
        );
    }
}
