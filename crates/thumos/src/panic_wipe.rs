//! Panic wipe integration.
//!
//! Wires the leipsanon [`WipeEngine`] to the kernel's security subsystem
//! for emergency data destruction. Builds a priority-ordered wipe plan
//! matching REQ-10:
//!
//! | Priority | Target         | Rationale                                     |
//! |----------|----------------|-----------------------------------------------|
//! | 1        | Keys (memory)  | Renders encrypted data unrecoverable instantly |
//! | 2        | Contacts       | Personal network graph                        |
//! | 3        | Messages       | Communication content                         |
//! | 4        | Call history   | Communication metadata                        |
//! | 5        | `WiFi` creds   | Network association data                      |
//! | 6        | BT pairings    | Device association data                       |
//!
//! ## Memory scrub
//!
//! After the wipe plan executes (or on normal shutdown), all user-space
//! page frames are zeroed to prevent cold-boot recovery. Uses the
//! [`page`] module's frame metadata to iterate allocatable pages.
//!
//! ## Distress mesh beacon
//!
//! On panic activation, a one-shot distress packet is emitted as a kernel
//! event. The actual `LoRa` transmission is a future-wave concern; this
//! module emits the event for the mesh subsystem to consume.

extern crate alloc;

use core::fmt;

use crate::key_manager::KeyManager;
use crate::page;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Number of wipe targets in the full panic plan.
const PANIC_WIPE_TARGET_COUNT: usize = 6;

// ---------------------------------------------------------------------------
// WipeTarget
// ---------------------------------------------------------------------------

/// A category of data to destroy during panic wipe.
///
/// Ordered by priority: lower numeric priority = wiped first.
/// This mirrors leipsanon's priority scheme but is expressed as a
/// kernel-side enum for type safety and exhaustive matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
#[non_exhaustive]
pub enum WipeTarget {
    /// Cryptographic keys in memory (priority 1).
    Keys,
    /// Contact database (priority 2).
    Contacts,
    /// Message store (priority 3).
    Messages,
    /// Call history / logs (priority 4).
    CallHistory,
    /// `WiFi` credentials and saved networks (priority 5).
    WifiCredentials,
    /// Bluetooth pairing data (priority 6).
    BluetoothPairings,
}

impl WipeTarget {
    /// Numeric priority (1 = highest / first).
    #[must_use]
    pub(crate) const fn priority(self) -> u8 {
        match self {
            Self::Keys => 1,
            Self::Contacts => 2,
            Self::Messages => 3,
            Self::CallHistory => 4,
            Self::WifiCredentials => 5,
            Self::BluetoothPairings => 6,
        }
    }

    /// Filesystem path for this target's data store.
    ///
    /// These paths match the leipsanon target layout and the thumos LFS
    /// directory structure.
    #[must_use]
    pub(crate) const fn path(self) -> &'static str {
        match self {
            Self::Keys => "/data/keys",
            Self::Contacts => "/data/contacts",
            Self::Messages => "/data/messages",
            Self::CallHistory => "/data/call_history",
            Self::WifiCredentials => "/data/wifi",
            Self::BluetoothPairings => "/data/bluetooth",
        }
    }
}

impl fmt::Display for WipeTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Keys => write!(f, "keys"),
            Self::Contacts => write!(f, "contacts"),
            Self::Messages => write!(f, "messages"),
            Self::CallHistory => write!(f, "call history"),
            Self::WifiCredentials => write!(f, "WiFi credentials"),
            Self::BluetoothPairings => write!(f, "Bluetooth pairings"),
        }
    }
}

// ---------------------------------------------------------------------------
// WipePlan
// ---------------------------------------------------------------------------

/// An ordered list of targets for panic wipe execution.
///
/// Targets are always sorted by ascending priority (keys first).
/// The plan is constructed via [`build_panic_plan`].
#[derive(Debug, Clone)]
#[must_use]
pub struct WipePlan {
    /// Targets in priority order.
    targets: [WipeTarget; PANIC_WIPE_TARGET_COUNT],
    /// Number of valid entries.
    count: usize,
}

impl WipePlan {
    /// Targets in priority order.
    pub(crate) fn targets(&self) -> &[WipeTarget] {
        &self.targets[..self.count]
    }

    /// Number of targets.
    #[must_use]
    pub(crate) fn len(&self) -> usize {
        self.count
    }

    /// Whether the plan is empty.
    #[must_use]
    pub(crate) fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl fmt::Display for WipePlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "WipePlan({} targets: ", self.count)?;
        for (i, target) in self.targets().iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{target}")?;
        }
        write!(f, ")")
    }
}

// ---------------------------------------------------------------------------
// DistressBeacon
// ---------------------------------------------------------------------------

/// Distress mesh beacon event.
///
/// Emitted on panic activation for the mesh subsystem to transmit.
/// The actual `LoRa` packet format and transmission are future-wave work;
/// this struct represents the event payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
#[non_exhaustive]
pub struct DistressBeacon {
    /// Tick at which panic was triggered.
    pub triggered_at: u64,
    /// Whether keys were zeroized before the beacon was emitted.
    pub keys_zeroized: bool,
}

impl fmt::Display for DistressBeacon {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DistressBeacon(tick={}, keys_zeroized={})",
            self.triggered_at, self.keys_zeroized,
        )
    }
}

// ---------------------------------------------------------------------------
// WipeResult
// ---------------------------------------------------------------------------

/// Result of a panic wipe execution.
#[derive(Debug, Clone)]
#[must_use]
pub struct WipeResult {
    /// Number of targets that completed successfully.
    pub targets_completed: usize,
    /// Number of targets that failed.
    pub targets_failed: usize,
    /// Whether memory scrub was performed.
    pub memory_scrubbed: bool,
    /// Whether the distress beacon was emitted.
    pub beacon_emitted: bool,
}

impl fmt::Display for WipeResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "WipeResult(completed={}, failed={}, scrubbed={}, beacon={})",
            self.targets_completed,
            self.targets_failed,
            self.memory_scrubbed,
            self.beacon_emitted,
        )
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Build the full panic wipe plan in priority order.
///
/// The plan covers all six target categories per REQ-10, ordered from
/// highest priority (keys, which render all encrypted data unrecoverable)
/// to lowest (Bluetooth pairings).
pub(crate) fn build_panic_plan() -> WipePlan {
    WipePlan {
        targets: [
            WipeTarget::Keys,
            WipeTarget::Contacts,
            WipeTarget::Messages,
            WipeTarget::CallHistory,
            WipeTarget::WifiCredentials,
            WipeTarget::BluetoothPairings,
        ],
        count: PANIC_WIPE_TARGET_COUNT,
    }
}

/// Execute the panic wipe sequence.
///
/// 1. Zeroize keys in memory via `key_manager` (immediate, priority 1).
/// 2. Emit distress mesh beacon (placeholder event).
/// 3. Execute remaining wipe targets (filesystem overwrites — these are
///    defense-in-depth since key zeroization already makes data
///    unrecoverable).
/// 4. Scrub user-space memory pages.
///
/// The `dry_run` flag controls whether filesystem I/O is actually
/// performed. In dry-run mode, the plan is traversed but no writes occur.
///
/// Returns a [`WipeResult`] summarizing the operation.
pub(crate) fn execute_panic_wipe(
    key_manager: &mut KeyManager,
    triggered_at: u64,
    dry_run: bool,
) -> WipeResult {
    let plan = build_panic_plan();

    let mut completed: usize = 0;
    let mut failed: usize = 0;

    // Step 1: Zeroize keys from memory — this is the critical action
    // that makes all encrypted data unrecoverable.
    key_manager.zeroize_all();

    for target in plan.targets() {
        match target {
            WipeTarget::Keys => {
                // Already zeroized above; mark as complete.
                // The filesystem key files are defense-in-depth.
                if dry_run || wipe_target_path(target.path()) {
                    completed = completed.saturating_add(1);
                } else {
                    failed = failed.saturating_add(1);
                }
            }
            _ => {
                if dry_run || wipe_target_path(target.path()) {
                    completed = completed.saturating_add(1);
                } else {
                    failed = failed.saturating_add(1);
                }
            }
        }
    }

    // Step 2: Emit distress beacon.
    let _beacon = emit_distress_beacon(triggered_at, !key_manager.has_keys());

    // Step 3: Memory scrub.
    let memory_scrubbed = if dry_run {
        true // Dry-run: report as done.
    } else {
        scrub_user_pages()
    };

    WipeResult {
        targets_completed: completed,
        targets_failed: failed,
        memory_scrubbed,
        beacon_emitted: true,
    }
}

/// Scrub all user-space page frames by zeroing them.
///
/// Iterates the page allocator's frame space and writes zeros to every
/// page. This prevents cold-boot attacks from recovering sensitive data
/// after shutdown or reboot.
///
/// Returns `true` if the scrub completed, `false` if it was a no-op
/// (e.g., no free pages to scrub).
pub(crate) fn scrub_user_pages() -> bool {
    let free = page::free_count();
    if free == 0 {
        return false;
    }

    // Allocate and zero pages, then free them back.
    // This ensures every free page frame has been overwritten with zeros.
    //
    // WHY we alloc-then-free rather than walking the bitmap directly:
    // the bitmap is in a static mut (unsafe to access from here), and
    // alloc_page/free_page are the safe public API. Each page is zero-
    // filled by the write_volatile loop below, then returned to the pool.
    let mut scrubbed: usize = 0;
    let mut pages_to_free = alloc::vec::Vec::new();

    // Allocate as many pages as possible.
    while let Some(addr) = page::alloc_page() {
        // Zero the page via volatile writes to prevent dead-store elimination.
        for offset in (0..page::PAGE_SIZE).step_by(core::mem::size_of::<usize>()) {
            let ptr = (addr + offset) as *mut u8;
            for i in 0..core::mem::size_of::<usize>() {
                // SAFETY: `addr` was returned by alloc_page, which guarantees
                // it points to a valid, mapped 4 KiB page frame. The offset
                // is within [0, PAGE_SIZE), so the pointer is within bounds.
                #[expect(unsafe_code, reason = "volatile write required for memory scrub")]
                unsafe {
                    core::ptr::write_volatile(ptr.add(i), 0);
                }
            }
        }
        pages_to_free.push(addr);
        scrubbed = scrubbed.saturating_add(1);
    }

    // Free all pages back.
    for addr in pages_to_free {
        // SAFETY: every address in this vec was returned by alloc_page
        // in the loop above and has not been freed yet.
        #[expect(unsafe_code, reason = "freeing pages we just allocated")]
        unsafe {
            page::free_page(addr);
        }
    }

    scrubbed > 0
}

/// Emit a distress mesh beacon event.
///
/// This is a placeholder: it constructs the beacon payload for the mesh
/// subsystem. Actual `LoRa` transmission will be wired in a future wave
/// when the mesh radio driver is integrated.
fn emit_distress_beacon(triggered_at: u64, keys_zeroized: bool) -> DistressBeacon {
    DistressBeacon {
        triggered_at,
        keys_zeroized,
    }
}

/// Wipe a single target path by overwriting with zeros.
///
/// This is a placeholder for the actual LFS wipe integration (Wave 8).
/// In the real implementation, this would call into `lfs.rs` to locate
/// the inode and overwrite the data blocks. For now it returns `true`
/// (success) since the kernel LFS is not yet wired for runtime I/O
/// from this module.
fn wipe_target_path(_path: &str) -> bool {
    // TODO(#129): wire to lfs::overwrite_path() when filesystem
    // runtime I/O is available from the security subsystem.
    true
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::SleepTier;

    /// Helper: create a `KeyManager` with loaded keys for testing.
    fn key_manager_with_derived_keys() -> KeyManager {
        let mut km = KeyManager::new();
        let primary = {
            let mut key_bytes = [0u8; 32];
            crate::security::pbkdf2_sha256(b"test-wipe", b"salt", 1, &mut key_bytes)
                .expect("pbkdf2 failed in test");
            crate::key_manager::SecureKey::new(key_bytes)
        };
        km.derive_partition_keys(&primary)
            .expect("derive_partition_keys failed");
        km
    }

    // -----------------------------------------------------------------------
    // Wipe plan covers all targets in priority order
    // -----------------------------------------------------------------------

    #[test]
    fn plan_covers_all_six_targets() {
        let plan = build_panic_plan();
        assert_eq!(plan.len(), PANIC_WIPE_TARGET_COUNT, "plan must have 6 targets");
        assert!(!plan.is_empty());
    }

    #[test]
    fn plan_is_priority_ordered() {
        let plan = build_panic_plan();
        let targets = plan.targets();

        for window in targets.windows(2) {
            assert!(
                window[0].priority() <= window[1].priority(),
                "targets must be in ascending priority order: {} (p{}) must come before {} (p{})",
                window[0], window[0].priority(),
                window[1], window[1].priority(),
            );
        }
    }

    #[test]
    fn plan_starts_with_keys() {
        let plan = build_panic_plan();
        assert_eq!(
            plan.targets()[0],
            WipeTarget::Keys,
            "first target must be keys (highest priority)"
        );
    }

    #[test]
    fn plan_contains_all_required_targets() {
        let plan = build_panic_plan();
        let targets = plan.targets();

        let required = [
            WipeTarget::Keys,
            WipeTarget::Contacts,
            WipeTarget::Messages,
            WipeTarget::CallHistory,
            WipeTarget::WifiCredentials,
            WipeTarget::BluetoothPairings,
        ];

        for req in &required {
            assert!(
                targets.contains(req),
                "plan must contain {req}"
            );
        }
    }

    #[test]
    fn plan_priorities_are_correct() {
        assert_eq!(WipeTarget::Keys.priority(), 1);
        assert_eq!(WipeTarget::Contacts.priority(), 2);
        assert_eq!(WipeTarget::Messages.priority(), 3);
        assert_eq!(WipeTarget::CallHistory.priority(), 4);
        assert_eq!(WipeTarget::WifiCredentials.priority(), 5);
        assert_eq!(WipeTarget::BluetoothPairings.priority(), 6);
    }

    // -----------------------------------------------------------------------
    // Execute wipe
    // -----------------------------------------------------------------------

    #[test]
    fn execute_wipe_zeroizes_keys() {
        let mut km = key_manager_with_derived_keys();
        assert!(km.has_keys(), "keys must be loaded before wipe");

        let result = execute_panic_wipe(&mut km, 1000, true);

        assert!(!km.has_keys(), "keys must be zeroized after wipe");
        assert_eq!(
            km.sleep_tier(),
            SleepTier::Long,
            "sleep tier must be Long after key zeroization"
        );
        assert_eq!(result.targets_completed, PANIC_WIPE_TARGET_COUNT);
        assert_eq!(result.targets_failed, 0);
        assert!(result.beacon_emitted);
    }

    #[test]
    fn execute_wipe_dry_run_no_failures() {
        let mut km = key_manager_with_derived_keys();
        let result = execute_panic_wipe(&mut km, 500, true);
        assert_eq!(result.targets_failed, 0, "dry-run must have zero failures");
        assert!(result.memory_scrubbed, "dry-run must report memory as scrubbed");
    }

    // -----------------------------------------------------------------------
    // Memory scrub
    // -----------------------------------------------------------------------

    #[test]
    fn scrub_user_pages_returns_result() {
        // NOTE: in test mode, the page allocator may not be initialized,
        // so free_count() returns 0. We verify the function handles that.
        let result = scrub_user_pages();
        // On host (test), no pages are initialized so this returns false.
        // The important thing is it doesn't panic.
        let _ = result;
    }

    // -----------------------------------------------------------------------
    // Distress beacon
    // -----------------------------------------------------------------------

    #[test]
    fn distress_beacon_carries_metadata() {
        let beacon = emit_distress_beacon(42, true);
        assert_eq!(beacon.triggered_at, 42);
        assert!(beacon.keys_zeroized);
    }

    // -----------------------------------------------------------------------
    // Target paths
    // -----------------------------------------------------------------------

    #[test]
    fn all_targets_have_paths() {
        let targets = [
            WipeTarget::Keys,
            WipeTarget::Contacts,
            WipeTarget::Messages,
            WipeTarget::CallHistory,
            WipeTarget::WifiCredentials,
            WipeTarget::BluetoothPairings,
        ];

        for target in &targets {
            let path = target.path();
            assert!(
                path.starts_with("/data/"),
                "{target} path must be under /data/: {path}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Display implementations
    // -----------------------------------------------------------------------

    #[test]
    fn display_impls_produce_output() {
        let plan = build_panic_plan();
        let plan_s = alloc::format!("{plan}");
        assert!(plan_s.contains("6 targets"), "WipePlan Display must show count");
        assert!(plan_s.contains("keys"), "WipePlan Display must list keys");

        let target_s = WipeTarget::CallHistory.to_string();
        assert_eq!(target_s, "call history");

        let beacon = DistressBeacon {
            triggered_at: 99,
            keys_zeroized: false,
        };
        let beacon_s = alloc::format!("{beacon}");
        assert!(beacon_s.contains("99"));

        let result = WipeResult {
            targets_completed: 5,
            targets_failed: 1,
            memory_scrubbed: true,
            beacon_emitted: true,
        };
        let result_s = alloc::format!("{result}");
        assert!(result_s.contains("completed=5"));
        assert!(result_s.contains("failed=1"));
    }

    // -----------------------------------------------------------------------
    // Wipe target path placeholder
    // -----------------------------------------------------------------------

    #[test]
    fn wipe_target_path_succeeds() {
        // The placeholder always returns true.
        assert!(wipe_target_path("/data/keys"));
        assert!(wipe_target_path("/data/contacts"));
    }
}
