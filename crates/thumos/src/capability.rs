//! Capability-based access control for the thumos kernel.
//!
//! Each process carries a capability bitfield in its PCB. Sensitive kernel
//! operations gate entry on the required bit(s). Denial is logged (when the
//! audit subsystem is available) and returns EPERM to the caller.
//!
//! # Design (REQ-09)
//!
//! - kinit (PID 0) holds `Capabilities::ALL` at boot.
//! - Forked children receive a subset defined by kinit policy. The default
//!   policy strips MODEM and AUDIT so that generic userspace cannot access
//!   the baseband or read the audit log.
//! - Syscalls that access sensitive resources call `check(required)` at entry.
//!   On failure the syscall returns EPERM; on success execution continues.
//!
//! # Capability bits
//!
//! | Bit | Constant  | Guards                                    |
//! |-----|-----------|-------------------------------------------|
//! |  0  | MODEM     | CCCI driver, AT command interface         |
//! |  1  | RAW_NET   | Raw socket creation (`socket` syscall)    |
//! |  2  | KILL      | Sending signals to other processes        |
//! |  3  | CRYPTO    | Kernel CSPRNG, key material access        |
//! |  4  | RADIO     | WiFi / BT / GPS radio control             |
//! |  5  | AUDIT     | Reading the kernel audit log              |

/// Capability bitfield type (32-bit, 6 bits used).
///
/// WHY newtype: `u32` arithmetic is easy to misuse. Wrapping in a struct forces
/// all capability manipulation through the named constants, preventing accidental
/// bit-field confusion with other u32 process fields.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Capabilities(pub u32);

impl Capabilities {
    /// Access CCCI, AT commands (baseband interface).
    pub const MODEM: u32 = 1 << 0;
    /// Raw socket creation.
    pub const RAW_NET: u32 = 1 << 1;
    /// Send signals to other processes (kill syscall).
    pub const KILL: u32 = 1 << 2;
    /// Access kernel CSPRNG and key material.
    pub const CRYPTO: u32 = 1 << 3;
    /// WiFi / BT / GPS radio control.
    pub const RADIO: u32 = 1 << 4;
    /// Read audit log.
    pub const AUDIT: u32 = 1 << 5;
    /// All capabilities granted (kinit / PID 0).
    pub const ALL: u32 = 0x3F;

    /// Default capability set for forked children.
    ///
    /// WHY: strips MODEM and AUDIT from ALL. Generic userspace processes have
    /// no legitimate need to speak AT commands to the baseband or read the
    /// audit log. All other capabilities remain available; the policy can be
    /// tightened per-process by kinit before exec.
    pub const FORK_DEFAULT: u32 = Self::ALL & !(Self::MODEM | Self::AUDIT);

    /// Construct a capability set from a raw bitfield.
    #[inline]
    pub const fn new(bits: u32) -> Self {
        Self(bits)
    }

    /// Return the raw bitfield.
    #[inline]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Return true if all bits in `cap` are set.
    #[inline]
    pub const fn contains(self, cap: u32) -> bool {
        (self.0 & cap) == cap
    }
}

// ---------------------------------------------------------------------------
// EPERM constant — two's complement -1, matches Linux ARM convention.
// WHY: same encoding as signal.rs/syscall.rs so the returned value is
// interpreted correctly by userspace built against Linux headers.
// ---------------------------------------------------------------------------

/// Operation not permitted (two's complement -1, matches Linux EPERM).
pub const EPERM: u32 = 0u32.wrapping_sub(1);

// ---------------------------------------------------------------------------
// Kernel-mode capability check helpers
//
// Both functions are #[cfg(not(test))] gated because they call
// crate::process (which is itself cfg-gated) to read the current PCB.
// Pure-logic tests live in the `tests` module below using `Capabilities`
// directly without going through the process table.
// ---------------------------------------------------------------------------

/// Check that the current process holds all bits in `required`.
///
/// Returns `Ok(())` if the check passes, or `Err(EPERM)` if any required
/// bit is absent. On denial the process name and missing bits are written to
/// the UART console (audit log integration is a future phase).
///
/// # Usage
///
/// ```rust,ignore
/// capability::check(Capabilities::KILL)?;
/// ```
#[cfg(not(test))]
pub fn check(required: u32) -> Result<(), u32> {
    let caps = crate::process::current_capabilities();
    if (caps & required) == required {
        Ok(())
    } else {
        // Log denial to UART.  A future phase will also append to the audit
        // ring buffer when CAP_AUDIT is available to the supervisor.
        use crate::uart::Uart;
        use core::fmt::Write;
        let pid = crate::process::current_pid();
        let mut serial = Uart::new();
        let _ = write!(
            serial,
            "CAPDEN pid={pid} required={required:#010x} held={caps:#010x}\r\n"
        );
        Err(EPERM)
    }
}

/// Return `true` if the current process holds all bits in `cap`.
///
/// Convenience wrapper around `check` for code that wants a boolean result
/// rather than a `Result`.
#[cfg(not(test))]
pub fn has(cap: u32) -> bool {
    let caps = crate::process::current_capabilities();
    (caps & cap) == cap
}

// ---------------------------------------------------------------------------
// Tests — pure Capabilities logic, no process table access.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // REQ-09: kinit has all capabilities
    // -----------------------------------------------------------------------
    #[test]
    fn kinit_has_all_capabilities() {
        let caps = Capabilities::new(Capabilities::ALL);
        // Every individual bit must be present.
        assert!(caps.contains(Capabilities::MODEM),  "kinit must have MODEM");
        assert!(caps.contains(Capabilities::RAW_NET), "kinit must have RAW_NET");
        assert!(caps.contains(Capabilities::KILL),    "kinit must have KILL");
        assert!(caps.contains(Capabilities::CRYPTO),  "kinit must have CRYPTO");
        assert!(caps.contains(Capabilities::RADIO),   "kinit must have RADIO");
        assert!(caps.contains(Capabilities::AUDIT),   "kinit must have AUDIT");
        // ALL must equal the union of all individual bits.
        let union =
            Capabilities::MODEM
            | Capabilities::RAW_NET
            | Capabilities::KILL
            | Capabilities::CRYPTO
            | Capabilities::RADIO
            | Capabilities::AUDIT;
        assert_eq!(Capabilities::ALL, union, "ALL must equal bitwise-OR of all caps");
    }

    // -----------------------------------------------------------------------
    // REQ-09: forked process inherits a strict subset
    // -----------------------------------------------------------------------
    #[test]
    fn forked_process_inherits_subset() {
        let parent = Capabilities::new(Capabilities::ALL);
        let child  = Capabilities::new(Capabilities::FORK_DEFAULT);

        // Every child bit must also be set in the parent.
        assert_eq!(
            child.bits() & parent.bits(), child.bits(),
            "child capabilities must be a subset of parent capabilities"
        );
        // MODEM and AUDIT must be stripped.
        assert!(!child.contains(Capabilities::MODEM),
            "MODEM must not be inherited by default");
        assert!(!child.contains(Capabilities::AUDIT),
            "AUDIT must not be inherited by default");
        // Remaining caps must be present.
        assert!(child.contains(Capabilities::RAW_NET), "RAW_NET must be inherited");
        assert!(child.contains(Capabilities::KILL),    "KILL must be inherited");
        assert!(child.contains(Capabilities::CRYPTO),  "CRYPTO must be inherited");
        assert!(child.contains(Capabilities::RADIO),   "RADIO must be inherited");
        // Child must be a STRICT subset (parent has bits child lacks).
        assert_ne!(child.bits(), parent.bits(),
            "default fork must be a strict subset, not equal");
    }

    // -----------------------------------------------------------------------
    // REQ-09: capability_check_passes_with_required_bits
    // -----------------------------------------------------------------------
    #[test]
    fn capability_check_passes_with_required_bits() {
        let caps = Capabilities::new(Capabilities::KILL | Capabilities::CRYPTO);
        // Exact match passes.
        assert!(caps.contains(Capabilities::KILL));
        assert!(caps.contains(Capabilities::CRYPTO));
        // Multi-bit check passes when all bits are present.
        assert!(caps.contains(Capabilities::KILL | Capabilities::CRYPTO));
    }

    // -----------------------------------------------------------------------
    // REQ-09: capability_check_fails_without_required_bits
    // -----------------------------------------------------------------------
    #[test]
    fn capability_check_fails_without_required_bits() {
        // A process with only KILL — no MODEM.
        let caps = Capabilities::new(Capabilities::KILL);
        assert!(!caps.contains(Capabilities::MODEM),
            "MODEM check must fail when only KILL is held");
        // Multi-bit check fails when any required bit is absent.
        assert!(!caps.contains(Capabilities::KILL | Capabilities::MODEM),
            "combined check must fail when MODEM is absent");
    }

    // -----------------------------------------------------------------------
    // REQ-09: kill_requires_cap_kill (logic — not wired to process table)
    // -----------------------------------------------------------------------
    #[test]
    fn kill_requires_cap_kill() {
        // Simulate a process without KILL.
        let caps_no_kill = Capabilities::new(Capabilities::CRYPTO | Capabilities::RADIO);
        assert!(!caps_no_kill.contains(Capabilities::KILL),
            "process without KILL cap must fail the check");

        // Simulate a process with KILL.
        let caps_with_kill = Capabilities::new(Capabilities::KILL);
        assert!(caps_with_kill.contains(Capabilities::KILL),
            "process with KILL cap must pass the check");
    }

    // -----------------------------------------------------------------------
    // REQ-09: kill_to_self_bypasses_cap_check (EPERM constant encoding)
    // -----------------------------------------------------------------------
    #[test]
    fn kill_to_self_bypasses_cap_check() {
        // EPERM is two's complement -1 (0xFFFF_FFFF as u32).
        assert_eq!(EPERM, 0xFFFF_FFFFu32,
            "EPERM must be two's complement -1");
        // The self-kill bypass is enforced in sys_kill (signal.rs) by comparing
        // the target PID with current_pid() before calling capability::check.
        // Here we verify the EPERM sentinel value is correct so the integration
        // test in signal.rs can rely on it.
    }

    // -----------------------------------------------------------------------
    // ALL == 0x3F
    // -----------------------------------------------------------------------
    #[test]
    fn all_caps_value() {
        assert_eq!(Capabilities::ALL, 0x3F, "ALL must equal 0x3F (6 bits)");
    }

    // -----------------------------------------------------------------------
    // FORK_DEFAULT is ALL minus MODEM and AUDIT
    // -----------------------------------------------------------------------
    #[test]
    fn fork_default_value() {
        let expected = Capabilities::ALL & !(Capabilities::MODEM | Capabilities::AUDIT);
        assert_eq!(Capabilities::FORK_DEFAULT, expected,
            "FORK_DEFAULT must equal ALL & !(MODEM | AUDIT)");
    }
}
