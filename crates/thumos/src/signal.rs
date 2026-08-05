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
//!    b. Sets r0 to the signal number (the POSIX handler argument).
//!    c. Sets PC to the handler address.
//!    d. Sets LR to the sigreturn trampoline page (`SIGNAL_TRAMPOLINE_VA`).
//! 4. The handler runs in user mode and returns via the trampoline.
//! 5. The trampoline executes `svc #81` (Sigreturn).
//! 6. `sys_sigreturn` restores the saved `SignalFrame` from user stack.
//!
//! # Signal frame layout (user stack, grows downward)
//!
//! ```text
//! [saved r0-r12, sp, lr, pc, cpsr]   17 × 4 = 68 bytes
//! Total: 68 bytes
//! ```
//!
//! # The sigreturn trampoline page
//!
//! The trampoline (`mov r7, #81; svc #0`) lives in a dedicated per-process
//! page at the fixed virtual address `SIGNAL_TRAMPOLINE_VA` (one page below
//! `USER_TEXT_BASE`), mapped PL0 read+execute / PL1 read-write at process
//! creation (`map_signal_trampoline` in process.rs). WHY a page, not code on
//! the stack: the user stack is PL0 RW + execute-never (#482 W^X), so an
//! on-stack trampoline prefetch-aborts the moment the handler returns into
//! it — the QEMU signal witness caught exactly that (USERFAULT
//! prefetch-abort status 0x0f at the stack VA). A fixed RX page is the
//! vDSO-shaped answer: PL0 can execute but never write it, the kernel wrote
//! it once through the PL1 mapping, the address is known without per-frame
//! code, and fork copies it / exec inherits it (it sits outside the
//! USER_TEXT section exec rebuilds) / exit's page walk reclaims it.

/// Number of u32 registers saved in the signal frame (r0-r12, sp, lr, pc, cpsr).
pub(crate) const SIGNAL_FRAME_REGS: usize = 17;

/// Total signal frame size in bytes: exactly the saved `Context` (17 × 4).
/// The frame carries NO code — the trampoline lives in the RX page above.
pub(crate) const SIGNAL_FRAME_SIZE: usize = SIGNAL_FRAME_REGS * 4;

/// Virtual address of the per-process sigreturn trampoline page: the page
/// directly below `USER_TEXT_BASE`. WHY here: heap grows up from
/// `DEFAULT_HEAP_BREAK` (0x1000_0000) and mmap from `MMAP_BASE`
/// (0x2000_0000), so this page is unreachable by legitimate user mappings;
/// it sits OUTSIDE the USER_TEXT 1 MB section that exec revokes and rebuilds
/// (exec_replace_context resets only USER_TEXT_BASE's section), so the
/// trampoline survives exec; and fork's copy-all-user-pages replicates it
/// for the child automatically.
pub(crate) const SIGNAL_TRAMPOLINE_VA: usize =
    crate::kconfig::USER_TEXT_BASE - crate::page::PAGE_SIZE;

/// ARM `mov r7, #81` — loads the Sigreturn syscall number into r7.
/// Encoding: E3A07051 (MOV r7, #0x51 where 0x51 = 81).
pub(crate) const TRAMPOLINE_MOV_R7_SIGRETURN: u32 = 0xE3A0_7051;

/// ARM `svc #0` — triggers the supervisor call using r7 as syscall number.
/// Encoding: EF000000.
pub(crate) const TRAMPOLINE_SVC_0: u32 = 0xEF00_0000;

/// Trampoline length in bytes: mov + svc (#446).
pub(crate) const TRAMPOLINE_LEN: usize = 8;

/// Deliver a handled signal to the interrupted user context (#446).
///
/// Builds a signal frame on the user stack (the 17 saved `Context` words)
/// and rewrites `frame` so the exception return lands in `handler` with the
/// frame as its stack, r0 = the signal number (the POSIX handler argument),
/// and lr = `SIGNAL_TRAMPOLINE_VA` (the per-process RX trampoline page). The
/// pending bit for `sig` is cleared AT DISPATCH (here), so the handler runs
/// once per raise and a re-raise during the handler re-delivers — never
/// cleared-early at peek (the #446 contract; clear-on-peek loses signals).
///
/// `frame` is the current process's trap Context on the IRQ stack; the user
/// stack pages it points at are PL0-mapped and thus writable from PL1 here.
///
/// # Safety
///
/// `frame` must be the live trap frame of the process the signal targets
/// (its sp/pc/lr are the interrupted user state), and the process must own a
/// mapped trampoline page (`map_signal_trampoline` ran at spawn).
pub(crate) unsafe fn deliver(frame: &mut crate::process::Context, sig: Signal, handler: u32) {
    let frame_addr = frame.sp.wrapping_sub(SIGNAL_FRAME_SIZE as u32) as *mut u32;
    // SAFETY: the user stack range below the interrupted sp is mapped user-RW
    // for this process (map_user_stack grants the run; sp always has
    // SIGNAL_FRAME_SIZE of headroom in the reserved top page).
    unsafe {
        let dst = frame_addr;
        for (i, word) in frame.r.iter().enumerate() {
            dst.add(i).write_volatile(*word);
        }
        dst.add(13).write_volatile(frame.sp);
        dst.add(14).write_volatile(frame.lr);
        dst.add(15).write_volatile(frame.pc);
        dst.add(16).write_volatile(frame.cpsr);
    }
    // Dispatch: handler runs with the frame as its stack, the signum as its
    // first argument (r0), and lr at the RX trampoline page. The pending bit
    // for THIS signal is cleared now so the handler runs exactly once per
    // raise.
    frame.sp = frame_addr as u32;
    frame.pc = handler;
    frame.lr = SIGNAL_TRAMPOLINE_VA as u32;
    frame.r[0] = sig as u32;
    crate::process::clear_pending_for_current(sig);
}

/// The sigreturn trampoline as machine words: `mov r7, #81; svc #0` (#446).
/// Pure so host tests can pin the exact bytes the ARM writer emits.
pub(crate) const fn trampoline_words() -> [u32; 2] {
    [TRAMPOLINE_MOV_R7_SIGRETURN, TRAMPOLINE_SVC_0]
}

/// Write the sigreturn trampoline into a freshly-allocated trampoline frame
/// (#446), then an I-cache sync so the freshly-written words are visible to
/// instruction fetch on real hardware (D-cache writes are not
/// architecturally coherent with the I-side).
///
/// # Safety
///
/// `phys` must name a writable page under the CURRENT (kernel identity) L1 —
/// the caller (process creation) holds that guarantee. The page becomes
/// PL0-executable only via the caller's later map_page grant.
#[cfg(target_arch = "arm")]
pub(crate) unsafe fn write_trampoline_page(phys: usize) {
    // SAFETY: per this function's contract; phys is identity-mapped and
    // writable from PL1 here, and TRAMPOLINE_LEN < PAGE_SIZE.
    unsafe {
        let dst = phys as *mut u32;
        let words = trampoline_words();
        dst.write_volatile(words[0]);
        dst.add(1).write_volatile(words[1]);
        crate::mmu::sync_icache_range(phys, TRAMPOLINE_LEN);
    }
}

/// No-op trampoline writer for non-ARM (host test) builds: host page frames
/// are simulated addresses that must never be dereferenced, and no
/// instruction fetch ever reads the page.
#[cfg(not(target_arch = "arm"))]
pub(crate) unsafe fn write_trampoline_page(_phys: usize) {}

/// Sigreturn (#446): restore the interrupted context the signal frame saved,
/// resuming user mode exactly where the signal interrupted it. Called from
/// svc_handler_rust's special case for syscall 81 with the SVC trap frame:
/// the trampoline page's `svc` entered with user sp = the signal frame's
/// base, and the pending bit was already cleared at dispatch, so this
/// function only restores — it never touches pending state (the old
/// clear-any-pending semantics could clear the WRONG signal when several
/// were pending).
///
/// # Safety
///
/// `frame` must be the SVC trap frame built from the sigreturn trampoline.
pub(crate) unsafe fn sigreturn_frame(frame: &mut crate::process::Context) {
    let src = frame.sp as *const u32;
    // SAFETY: the trampoline's user sp is the signal frame deliver() built;
    // it is PL0-mapped and valid for the full 17-word saved Context.
    unsafe {
        for (i, word) in frame.r.iter_mut().enumerate() {
            *word = src.add(i).read_volatile();
        }
        frame.sp = src.add(13).read_volatile();
        frame.lr = src.add(14).read_volatile();
        frame.pc = src.add(15).read_volatile();
        frame.cpsr = src.add(16).read_volatile();
    }
}

/// Unreachable by design: svc_handler_rust special-cases syscall 81 before
/// the generic dispatch, because the frame restore needs the SVC trap frame
/// (which `dispatch` does not receive). This shim exists only so the
/// dispatcher's match stays exhaustive (#446).
pub(crate) fn sigreturn_unreachable() -> u32 {
    crate::syscall::ENOSYS
}

/// The sigreturn syscall number (81), for svc_handler_rust's special case.
pub(crate) const SIGRETURN_NUM: u32 = 81;

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
            Self::Sigkill | Self::Sigterm | Self::Sigusr1 | Self::Sigusr2 | Self::Sigpipe => {
                DefaultAction::Terminate
            }
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
        assert!(
            !Signal::Sigkill.can_catch(),
            "SIGKILL must not be catchable"
        );

        // All other supported signals CAN be caught.
        assert!(Signal::Sigterm.can_catch(), "SIGTERM can be caught");
        assert!(Signal::Sigusr1.can_catch(), "SIGUSR1 can be caught");
        assert!(Signal::Sigusr2.can_catch(), "SIGUSR2 can be caught");
        assert!(Signal::Sigpipe.can_catch(), "SIGPIPE can be caught");
        assert!(Signal::Sigchld.can_catch(), "SIGCHLD can be caught");

        // Verify EPERM constant has the correct value (two's complement -1).
        assert_eq!(
            EPERM,
            0u32.wrapping_sub(1),
            "EPERM must be two's complement -1"
        );
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
        assert_eq!(
            state.action(Signal::Sigusr1),
            SignalAction::Default,
            "initial action should be Default"
        );

        let handler: u32 = 0x4020_0000;
        state.set_action(Signal::Sigusr1, SignalAction::Handler(handler));
        assert_eq!(
            state.action(Signal::Sigusr1),
            SignalAction::Handler(handler),
            "handler should be stored"
        );

        state.set_action(Signal::Sigusr1, SignalAction::Ignore);
        assert_eq!(
            state.action(Signal::Sigusr1),
            SignalAction::Ignore,
            "action should update to Ignore"
        );

        state.set_action(Signal::Sigusr1, SignalAction::Default);
        assert_eq!(
            state.action(Signal::Sigusr1),
            SignalAction::Default,
            "action should revert to Default"
        );
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
        assert!(
            !Signal::Sigkill.can_catch(),
            "SIGKILL must not be catchable"
        );
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
        assert!(
            Signal::from_u32(99).is_none(),
            "signal 99 should not be recognised"
        );
        assert!(
            Signal::from_u32(0).is_none(),
            "signal 0 is not in our supported set"
        );
    }

    // -----------------------------------------------------------------------
    // REQ-14: signal frame layout — size and field offsets
    // -----------------------------------------------------------------------
    #[test]
    fn signal_frame_layout() {
        // The frame is exactly the saved Context: 17 registers × 4 bytes,
        // no code (the trampoline lives in the RX page, never on the stack).
        assert_eq!(
            SIGNAL_FRAME_SIZE,
            SIGNAL_FRAME_REGS * 4,
            "signal frame is exactly the 17-word saved Context"
        );
        assert_eq!(SIGNAL_FRAME_SIZE, 68, "signal frame should be 68 bytes");

        // Verify trampoline instruction encodings are ARM32 and correct.
        // MOV r7, #81: cond=1110, op=MOV, Rd=7, imm8=0x51.
        assert_eq!(
            TRAMPOLINE_MOV_R7_SIGRETURN, 0xE3A0_7051,
            "trampoline MOV instruction encoding mismatch"
        );
        // SVC #0: cond=1110, SVC opcode.
        assert_eq!(
            TRAMPOLINE_SVC_0, 0xEF00_0000,
            "trampoline SVC instruction encoding mismatch"
        );
        assert_eq!(TRAMPOLINE_LEN, 8, "trampoline is mov + svc");
    }

    /// The trampoline page's VA is the reserved slot one page below
    /// USER_TEXT_BASE — outside the section exec rebuilds, above every
    /// growing user region (heap at 0x1000_0000, mmap at 0x2000_0000).
    #[test]
    fn signal_trampoline_va_is_the_reserved_slot() {
        assert_eq!(
            SIGNAL_TRAMPOLINE_VA,
            crate::kconfig::USER_TEXT_BASE - crate::page::PAGE_SIZE,
            "trampoline page sits directly below USER_TEXT_BASE"
        );
        assert_eq!(
            SIGNAL_TRAMPOLINE_VA % crate::page::PAGE_SIZE,
            0,
            "trampoline VA is page-aligned"
        );
        // Outside the USER_TEXT 1 MB section exec revokes + rebuilds.
        assert!(
            SIGNAL_TRAMPOLINE_VA < crate::kconfig::USER_TEXT_BASE,
            "trampoline must not share the exec-rebuilt section"
        );
    }

    /// trampoline_words() must emit [mov r7, #81; svc #0] — the whole
    /// trampoline, exactly what the ARM writer emits into the page.
    #[test]
    fn trampoline_words_are_mov_then_svc() {
        let words = trampoline_words();
        assert_eq!(words[0], TRAMPOLINE_MOV_R7_SIGRETURN, "word 0 = mov");
        assert_eq!(words[1], TRAMPOLINE_SVC_0, "word 1 = svc");
    }

    // --- #446 frame build + restore ---

    /// deliver() must lay out the 17 saved Context words on the user stack
    /// and rewrite the trap frame to enter the handler with the frame as its
    /// stack, r0 = the signum, and lr = the RX trampoline page.
    #[test]
    fn deliver_builds_frame_and_rewrites_context() {
        let mut frame = crate::process::Context {
            r: [0; 13],
            sp: 0,
            lr: 0,
            pc: 0,
            cpsr: 0,
        };
        frame.r[0] = 0xAAAA;
        frame.r[5] = 0x5555;
        frame.lr = 0xBEEF;
        frame.pc = 0xDEAD;
        frame.cpsr = 0x10;
        static mut USER_STACK: [u32; 64] = [0; 64];
        // SAFETY: test-only static; single-threaded per test.
        let base = unsafe { core::ptr::addr_of_mut!(USER_STACK) };
        let stack_top = base as u32 + (64 * 4);
        frame.sp = stack_top;

        // SAFETY: frame is a test Context whose sp points at the test buffer.
        unsafe { deliver(&mut frame, Signal::Sigusr1, 0xCAFE) };

        let frame_addr = stack_top - (SIGNAL_FRAME_SIZE as u32);
        assert_eq!(frame.sp, frame_addr, "sp must land at the frame base");
        assert_eq!(frame.pc, 0xCAFE, "pc must enter the handler");
        assert_eq!(
            frame.lr, SIGNAL_TRAMPOLINE_VA as u32,
            "lr must point at the RX trampoline page"
        );
        assert_eq!(frame.r[0], 10, "r0 carries the signum (Sigusr1 = 10)");
        // SAFETY: the buffer was just written by deliver().
        let f = frame_addr as *const u32;
        unsafe {
            assert_eq!(f.read(), 0xAAAA, "r0 saved");
            assert_eq!(f.add(5).read(), 0x5555, "r5 saved");
            assert_eq!(f.add(13).read(), stack_top, "interrupted sp saved");
            assert_eq!(f.add(14).read(), 0xBEEF, "interrupted lr saved");
            assert_eq!(f.add(15).read(), 0xDEAD, "interrupted pc saved");
            assert_eq!(f.add(16).read(), 0x10, "cpsr saved");
        }
    }

    /// sigreturn_frame() must restore all 17 saved registers into the SVC
    /// trap frame, resuming the interrupted context exactly.
    #[test]
    fn sigreturn_frame_restores_interrupted_context() {
        static mut SIGFRAME: [u32; 21] = [0; 21];
        // SAFETY: test-only static; single-threaded per test.
        let base = unsafe { core::ptr::addr_of_mut!(SIGFRAME) };
        let mut saved = crate::process::Context {
            r: [0; 13],
            sp: 0,
            lr: 0,
            pc: 0,
            cpsr: 0,
        };
        saved.r[0] = 0x1111;
        saved.r[9] = 0x9999;
        saved.sp = 0x7777;
        saved.lr = 0x6666;
        saved.pc = 0x5555;
        saved.cpsr = 0x10;
        // Lay out the frame as deliver() would.
        unsafe {
            let dst = base as *mut u32;
            for (i, word) in saved.r.iter().enumerate() {
                dst.add(i).write_volatile(*word);
            }
            dst.add(13).write_volatile(saved.sp);
            dst.add(14).write_volatile(saved.lr);
            dst.add(15).write_volatile(saved.pc);
            dst.add(16).write_volatile(saved.cpsr);
        }
        // The SVC trap frame: user sp = the frame base (as the trampoline left it).
        let mut trap = crate::process::Context {
            r: [0; 13],
            sp: 0,
            lr: 0,
            pc: 0,
            cpsr: 0,
        };
        trap.sp = base as u32;
        // SAFETY: trap.sp points at the frame built above.
        unsafe { sigreturn_frame(&mut trap) };
        assert_eq!(trap.r[0], 0x1111);
        assert_eq!(trap.r[9], 0x9999);
        assert_eq!(trap.sp, 0x7777, "sp restored to the interrupted value");
        assert_eq!(trap.lr, 0x6666, "lr restored");
        assert_eq!(
            trap.pc, 0x5555,
            "pc restored to the interrupted instruction"
        );
        assert_eq!(trap.cpsr, 0x10, "cpsr restored");
    }
}
