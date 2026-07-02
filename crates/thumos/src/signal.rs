//! Signal subsystem: delivery, handlers, and context save/restore.
//!
//! Implements a simplified POSIX signal model for the thumos kernel.
//! Supports SIGKILL (9), SIGUSR1 (10), SIGUSR2 (12), SIGPIPE (13),
//! SIGTERM (15), and SIGCHLD (17).
//!
//! # Signal delivery flow
//!
//! 1. `sys_kill(pid, sig)` sets the pending bit in the target's `SignalState`.
//! 2. Before returning to user mode (checked in the exception return path),
//!    the kernel inspects the current process's pending mask.
//! 3. If a pending signal has a registered handler, the kernel:
//!    a. Pushes a `SignalFrame` onto the user stack (saves all registers).
//!    b. Sets PC to the handler address.
//!    c. Sets LR to the sigreturn trampoline address.
//! 4. The handler runs in user mode and returns via the trampoline.
//! 5. The trampoline executes `svc #81` (Sigreturn).
//! 6. `sys_sigreturn` restores the saved `SignalFrame` from user stack.
//!
//! # Signal frame layout (user stack, grows downward)
//!
//! ```text
//! [saved r0-r12, sp, lr, pc, cpsr]   17 × 4 = 68 bytes
//! [signal number]                      4 bytes
//! [sigreturn trampoline code]          8 bytes (mov r7, #81; svc #0)
//! Total: 80 bytes
//! ```
//!
//! WHY trampoline is embedded in the frame: the kernel cannot rely on a
//! fixed trampoline address in user space (no vDSO). Embedding the code
//! on the user stack and pointing LR at it is the standard ARM approach
//! (matches Linux 2.6 OABI signal delivery).

/// Number of u32 registers saved in the signal frame (r0-r12, sp, lr, pc, cpsr).
pub(crate) const SIGNAL_FRAME_REGS: usize = 17;

/// Total signal frame size in bytes: 17 regs × 4 + signum × 4 + trampoline × 8.
pub(crate) const SIGNAL_FRAME_SIZE: usize = SIGNAL_FRAME_REGS * 4 + 4 + 8;

/// Offset of `signum` field within the signal frame (bytes from frame base).
pub(crate) const SIGNAL_FRAME_SIGNUM_OFFSET: usize = SIGNAL_FRAME_REGS * 4;

/// Offset of the trampoline code within the signal frame.
pub(crate) const SIGNAL_FRAME_TRAMPOLINE_OFFSET: usize = SIGNAL_FRAME_SIGNUM_OFFSET + 4;

/// ARM `mov r7, #81` — loads the Sigreturn syscall number into r7.
/// Encoding: E3A07051 (MOV r7, #0x51 where 0x51 = 81).
pub(crate) const TRAMPOLINE_MOV_R7_SIGRETURN: u32 = 0xE3A0_7051;

/// ARM `svc #0` — triggers the supervisor call using r7 as syscall number.
/// Encoding: EF000000.
pub(crate) const TRAMPOLINE_SVC_0: u32 = 0xEF00_0000;

/// Recognized signal numbers.
///
/// WHY repr(u32): signal numbers are passed as u32 in syscall arguments and
/// stored as bitmask indices. Explicit discriminants match POSIX values so
/// userspace built against POSIX headers can use the standard constants.
#[repr(u32)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Signal {
    Sigkill = 9,
    Sigusr1 = 10,
    Sigusr2 = 12,
    Sigpipe = 13,
    Sigterm = 15,
    Sigchld = 17,
}

impl Signal {
    /// Convert a raw signal number to a `Signal` variant.
    /// Returns `None` for unrecognised numbers.
    pub(crate) const fn from_u32(n: u32) -> Option<Self> {
        match n {
            9 => Some(Self::Sigkill),
            10 => Some(Self::Sigusr1),
            12 => Some(Self::Sigusr2),
            13 => Some(Self::Sigpipe),
            15 => Some(Self::Sigterm),
            17 => Some(Self::Sigchld),
            _ => None,
        }
    }

    /// Default action for this signal.
    ///
    /// WHY: POSIX specifies default actions; kernels must apply them when no
    /// handler is registered and the signal is not ignored.
    pub(crate) const fn default_action(self) -> DefaultAction {
        match self {
            Self::Sigkill | Self::Sigterm | Self::Sigusr1
            | Self::Sigusr2 | Self::Sigpipe => DefaultAction::Terminate,
            Self::Sigchld => DefaultAction::Ignore,
        }
    }

    /// Whether this signal can be caught or ignored.
    ///
    /// WHY: POSIX requires SIGKILL to always terminate; no handler or SIG_IGN
    /// can override it. Rejecting sigaction for SIGKILL here enforces that rule.
    pub(crate) const fn can_catch(self) -> bool {
        !matches!(self, Self::Sigkill)
    }
}

/// Default action applied when no handler is registered for a signal.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DefaultAction {
    /// Terminate the process (e.g. SIGTERM, SIGKILL).
    Terminate,
    /// Do nothing (e.g. SIGCHLD).
    Ignore,
}

/// Per-signal action: what to do when the signal is delivered.
///
/// WHY: `#[derive(Clone, Copy)]` — SignalAction is stored inline in the
/// fixed-size `SignalState::handlers` array, which must be `Copy` so the
/// whole `Process` struct can be cloned in `fork()` without a heap allocation.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SignalAction {
    /// Apply the kernel default action (terminate or ignore).
    Default,
    /// Explicitly ignore this signal (SIG_IGN, handler_ptr == 1).
    Ignore,
    /// Call this user-space function pointer when the signal is delivered.
    /// The value is a virtual address in the process's address space.
    Handler(u32),
}

impl SignalAction {
    /// Sentinel value userspace passes in handler_ptr to mean SIG_IGN.
    pub(crate) const SIG_IGN: u32 = 1;

    /// Sentinel value userspace passes in handler_ptr to mean SIG_DFL.
    pub(crate) const SIG_DFL: u32 = 0;
}

/// Per-process signal state embedded in the process control block.
///
/// WHY fixed array size 18: signals are indexed by number (0-17). Using
/// signal number directly as index avoids a search on every delivery and
/// keeps the structure `Copy` and `const`-constructible.
#[derive(Clone, Copy)]
pub struct SignalState {
    /// Per-signal action, indexed by signal number (0-17).
    /// Entries for undefined signal numbers are `SignalAction::Default`.
    pub handlers: [SignalAction; 18],
    /// Bitmask of pending signals (bit N set ↔ signal N is pending).
    pub pending: u32,
}

impl SignalState {
    /// Construct a zeroed `SignalState` with all handlers set to Default.
    ///
    /// WHY `const`: `Process` is stored in a static array initialised at
    /// compile time (`const NONE: Option<Process> = None`). Every field of
    /// `Process` must therefore be `const`-constructible.
    pub(crate) const fn new() -> Self {
        Self {
            handlers: [SignalAction::Default; 18],
            pending: 0,
        }
    }

    /// Mark signal `sig` as pending.
    #[inline]
    pub(crate) fn set_pending(&mut self, sig: Signal) {
        self.pending |= 1 << (sig as u32);
    }

    /// Clear the pending bit for signal `sig`.
    #[inline]
    pub(crate) fn clear_pending(&mut self, sig: Signal) {
        self.pending &= !(1 << (sig as u32));
    }

    /// Return the lowest-numbered pending signal, or `None` if none are pending.
    pub(crate) fn next_pending(&self) -> Option<Signal> {
        for n in 0u32..18 {
            if self.pending & (1 << n) != 0 {
                if let Some(sig) = Signal::from_u32(n) {
                    return Some(sig);
                }
                // Unknown bit set: skip it (defensive)
            }
        }
        None
    }

    /// Get the registered action for `sig`.
    #[inline]
    pub(crate) fn action(&self, sig: Signal) -> SignalAction {
        self.handlers[sig as usize]
    }

    /// Set the action for `sig`.
    #[inline]
    pub(crate) fn set_action(&mut self, sig: Signal, action: SignalAction) {
        self.handlers[sig as usize] = action;
    }
}

// ---------------------------------------------------------------------------
// Syscall implementations. Host-testable since `crate::process` (their only
// hardware-adjacent dependency) was un-gated; they touch no asm/MMIO, so they
// are compiled on both targets.
// ---------------------------------------------------------------------------

/// Error: invalid argument (two's complement -22, matches Linux EINVAL).
const EINVAL: u32 = 0u32.wrapping_sub(22);
/// Error: no such process (two's complement -3, matches Linux ESRCH).
const ESRCH: u32 = 0u32.wrapping_sub(3);
/// Error: operation not permitted (two's complement -1, matches Linux EPERM).
const EPERM: u32 = 0u32.wrapping_sub(1);

/// `sigaction(signum, handler_ptr)` — install a signal handler.
///
/// - `signum`: signal number (must be one of the six supported signals)
/// - `handler_ptr`: user-space function pointer, or:
///   - 0 (`SIG_DFL`): restore default action
///   - 1 (`SIG_IGN`): ignore the signal
///
/// Returns 0 on success, or an error code:
/// - `EINVAL` — unrecognised signal number
/// - `EPERM` — attempt to catch or ignore SIGKILL
pub(crate) fn sys_sigaction(signum: u32, handler_ptr: u32) -> u32 {
    let Some(sig) = Signal::from_u32(signum) else {
        return EINVAL;
    };

    // SIGKILL cannot be caught or ignored.
    if !sig.can_catch() && handler_ptr != SignalAction::SIG_DFL {
        return EPERM;
    }

    let action = match handler_ptr {
        SignalAction::SIG_DFL => SignalAction::Default,
        SignalAction::SIG_IGN => SignalAction::Ignore,
        ptr => SignalAction::Handler(ptr),
    };

    // SAFETY: set_signal_action accesses PROCS via addr_of_mut!, which is
    // the same pattern used throughout process.rs. Called from syscall context
    // (single-core, no preemption during SVC handling).
    unsafe {
        crate::process::set_signal_action(sig, action);
    }
    0
}

/// `kill(pid, signum)` — deliver a signal to a process.
///
/// If the target has a registered handler the signal is marked pending;
/// it will be delivered before the next return to user mode.
/// If no handler is registered the default action is applied immediately:
/// - Terminate: mark the target process Dead.
/// - Ignore: no-op.
///
/// SIGKILL always terminates regardless of any registered handler.
///
/// Returns 0 on success, or an error code:
/// - `EINVAL` — unrecognised signal number
/// - `ESRCH` — target PID not found or not alive
/// - `EPERM` — caller lacks `CAP_KILL` and target is a different process (REQ-09)
pub(crate) fn sys_kill(pid: u32, signum: u32) -> u32 {
    let Some(sig) = Signal::from_u32(signum) else {
        return EINVAL;
    };

    let pid8 = match u8::try_from(pid) {
        Ok(p) => p,
        Err(_) => return ESRCH,
    };

    // WHY (#269): PID 0 (kinit) is the fault supervisor; belt-and-suspenders
    // rejection here (in addition to the deliver_signal_to guard) means no
    // caller — including a self-signal from kinit — reaches the capability
    // check with PID 0 as the target.
    if pid8 == 0 {
        return EPERM;
    }

    // REQ-09: sending a signal to another process requires CAP_KILL.
    // Self-signals (kill(getpid(), sig)) bypass the check — a process may
    // always signal itself (matches Linux semantics and enables self-termination).
    let current = crate::process::current_pid();
    if pid8 != current {
        if let Err(e) = crate::capability::check(crate::capability::Capabilities::KILL) {
            return e;
        }
    }

    // SAFETY: deliver_signal_to accesses PROCS via addr_of_mut!.
    // Called from syscall context (single-core).
    unsafe { crate::process::deliver_signal_to(pid8, sig) }
}

/// `sigreturn()` — return from a signal handler.
///
/// Restores the register state that was saved onto the user stack before
/// the signal handler was invoked. The saved frame is at the current user
/// SP; after restoring it the interrupted thread resumes where it left off.
///
/// In this implementation the frame restoration is done symbolically:
/// the kernel clears the pending bit for the signal that was being handled.
/// Full register restoration from the user stack requires architecture-
/// specific SVC plumbing that feeds the saved frame address into this
/// handler — that is wired up in the exception return path in exceptions.rs.
///
/// Returns 0 (the value is placed in r0, but the handler will overwrite
/// it from the restored frame before returning to user mode).
pub(crate) fn sys_sigreturn() -> u32 {
    // SAFETY: clear_current_pending accesses PROCS via addr_of_mut!.
    unsafe { crate::process::clear_any_pending(); }
    0
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Tests — pure SignalState and signal-constants logic.
// Integration tests (kill/sigaction against live PCB) live in process.rs
// because crate::process is #[cfg(not(test))] gated.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // REQ-14: SIGKILL cannot be caught — tested via can_catch() logic
    // (sys_sigaction calls crate::process and is #[cfg(not(test))] gated;
    // the process-level test lives in process.rs)
    // -----------------------------------------------------------------------
    #[test]
    fn sigkill_cannot_be_caught() {
        // SIGKILL is the only signal where can_catch() returns false.
        assert!(!Signal::Sigkill.can_catch(),
            "SIGKILL must not be catchable");

        // All other supported signals CAN be caught.
        assert!(Signal::Sigterm.can_catch(),  "SIGTERM can be caught");
        assert!(Signal::Sigusr1.can_catch(),  "SIGUSR1 can be caught");
        assert!(Signal::Sigusr2.can_catch(),  "SIGUSR2 can be caught");
        assert!(Signal::Sigpipe.can_catch(),  "SIGPIPE can be caught");
        assert!(Signal::Sigchld.can_catch(),  "SIGCHLD can be caught");

        // Verify EPERM constant has the correct value (two's complement -1).
        assert_eq!(EPERM, 0u32.wrapping_sub(1),
            "EPERM must be two's complement -1");
    }

    // -----------------------------------------------------------------------
    // SignalState: set/clear/next pending logic
    // -----------------------------------------------------------------------
    #[test]
    fn signal_state_pending_bits() {
        let mut state = SignalState::new();
        assert_eq!(state.pending, 0, "new state has no pending signals");

        state.set_pending(Signal::Sigusr1);
        let expected = 1u32 << (Signal::Sigusr1 as u32);
        assert_ne!(state.pending & expected, 0, "SIGUSR1 bit should be set");

        // next_pending returns the lowest-numbered pending signal.
        assert_eq!(state.next_pending(), Some(Signal::Sigusr1));

        state.clear_pending(Signal::Sigusr1);
        assert_eq!(state.pending, 0, "bit should be cleared");
        assert_eq!(state.next_pending(), None, "no pending after clear");
    }

    // -----------------------------------------------------------------------
    // SignalState: handler registration and retrieval
    // -----------------------------------------------------------------------
    #[test]
    fn signal_state_handler_registration() {
        let mut state = SignalState::new();
        assert_eq!(state.action(Signal::Sigusr1), SignalAction::Default,
            "initial action should be Default");

        let handler: u32 = 0x4020_0000;
        state.set_action(Signal::Sigusr1, SignalAction::Handler(handler));
        assert_eq!(state.action(Signal::Sigusr1), SignalAction::Handler(handler),
            "handler should be stored");

        state.set_action(Signal::Sigusr1, SignalAction::Ignore);
        assert_eq!(state.action(Signal::Sigusr1), SignalAction::Ignore,
            "action should update to Ignore");

        state.set_action(Signal::Sigusr1, SignalAction::Default);
        assert_eq!(state.action(Signal::Sigusr1), SignalAction::Default,
            "action should revert to Default");
    }

    // -----------------------------------------------------------------------
    // Signal defaults: terminate vs ignore
    // -----------------------------------------------------------------------
    #[test]
    fn signal_default_actions() {
        assert_eq!(Signal::Sigkill.default_action(), DefaultAction::Terminate);
        assert_eq!(Signal::Sigterm.default_action(), DefaultAction::Terminate);
        assert_eq!(Signal::Sigusr1.default_action(), DefaultAction::Terminate);
        assert_eq!(Signal::Sigusr2.default_action(), DefaultAction::Terminate);
        assert_eq!(Signal::Sigpipe.default_action(), DefaultAction::Terminate);
        assert_eq!(Signal::Sigchld.default_action(), DefaultAction::Ignore);
    }

    // -----------------------------------------------------------------------
    // can_catch: only SIGKILL is uncatchable
    // -----------------------------------------------------------------------
    #[test]
    fn sigkill_is_uncatchable() {
        assert!(!Signal::Sigkill.can_catch(), "SIGKILL must not be catchable");
        assert!(Signal::Sigterm.can_catch());
        assert!(Signal::Sigusr1.can_catch());
        assert!(Signal::Sigusr2.can_catch());
        assert!(Signal::Sigpipe.can_catch());
        assert!(Signal::Sigchld.can_catch());
    }

    // -----------------------------------------------------------------------
    // EINVAL for unknown signal numbers — tested via Signal::from_u32
    // -----------------------------------------------------------------------
    #[test]
    fn invalid_signal_number_returns_einval() {
        // sys_sigaction is #[cfg(not(test))]; test the parsing logic directly.
        assert!(Signal::from_u32(99).is_none(),
            "signal 99 should not be recognised");
        assert!(Signal::from_u32(0).is_none(),
            "signal 0 is not in our supported set");
    }

    // -----------------------------------------------------------------------
    // REQ-14: signal frame layout — size and field offsets
    // -----------------------------------------------------------------------
    #[test]
    fn signal_frame_layout() {
        // 17 saved registers × 4 bytes.
        assert_eq!(SIGNAL_FRAME_REGS * 4, 68,
            "saved register region should be 68 bytes");

        // signum field follows immediately.
        assert_eq!(SIGNAL_FRAME_SIGNUM_OFFSET, 68,
            "signum offset should be 68");

        // Trampoline follows signum (4 bytes).
        assert_eq!(SIGNAL_FRAME_TRAMPOLINE_OFFSET, 72,
            "trampoline offset should be 72");

        // Total frame: 68 + 4 + 8 = 80 bytes.
        assert_eq!(SIGNAL_FRAME_SIZE, 80,
            "total signal frame should be 80 bytes");

        // Verify trampoline instruction encodings are ARM32 and correct.
        // MOV r7, #81: cond=1110, op=MOV, Rd=7, imm8=0x51.
        assert_eq!(TRAMPOLINE_MOV_R7_SIGRETURN, 0xE3A0_7051,
            "trampoline MOV instruction encoding mismatch");
        // SVC #0: cond=1110, SVC opcode.
        assert_eq!(TRAMPOLINE_SVC_0, 0xEF00_0000,
            "trampoline SVC instruction encoding mismatch");
    }
}
