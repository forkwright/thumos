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
//! After the wipe plan executes, every page frame in the managed usable
//! range is zeroed in place — free and in-use alike — via
//! [`page::zero_usable_range`], which walks physical addresses directly
//! and performs no heap allocation (#321: the previous alloc_page-then-
//! free_page loop only reached free frames and could abort via
//! `handle_alloc_error` under memory pressure). This is destructive to any
//! live kernel/user state backed by that range and must be the LAST
//! action taken before an immediate halt/reboot.
//!
//! ## Distress mesh beacon
//!
//! On panic activation, a one-shot distress packet is emitted as a kernel
//! event. The actual `LoRa` transmission is a future-wave concern; this
//! module emits the event for the mesh subsystem to consume.

extern crate alloc;

use core::fmt;

use crate::irq;
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
    /// Whether the primary encryption keys were zeroized in memory.
    /// WHY (SECURITY, finding 14, info): tracked separately from
    /// `failed_targets`'s entry for `WipeTarget::Keys`, which reflects
    /// ONLY the on-disk key-file overwrite (defense-in-depth, currently
    /// always fails per #324/#129) -- conflating the two under one bit
    /// would let a reader mistake "Keys in failed_targets" for "the
    /// encryption keys are still recoverable" when the in-memory keys
    /// (the actual protection) are already destroyed. Set inside the
    /// IRQ-masked critical section in Step 1 (finding 15).
    pub keys_zeroized_in_memory: bool,
    /// Number of targets that failed.
    pub targets_failed: usize,
    /// Which targets failed, in plan order (up to `PANIC_WIPE_TARGET_COUNT`
    /// slots; unused slots are `None`). WHY (SECURITY, finding 9): the
    /// caller needs to know WHICH category of sensitive data survived an
    /// incomplete wipe, not just how many -- a bare count cannot
    /// distinguish "WiFi credentials intact" from "message store intact".
    pub failed_targets: [Option<WipeTarget>; PANIC_WIPE_TARGET_COUNT],
    /// Whether memory scrub was performed.
    pub memory_scrubbed: bool,
    /// Whether the distress beacon was emitted.
    pub beacon_emitted: bool,
}

impl fmt::Display for WipeResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "WipeResult(completed={}, failed={}, scrubbed={}, beacon={}",
            self.targets_completed, self.targets_failed, self.memory_scrubbed, self.beacon_emitted,
        )?;
        if self.targets_failed > 0 {
            write!(f, ", failed_targets=[")?;
            for (i, target) in self.failed_targets.iter().flatten().enumerate() {
                if i > 0 {
                    write!(f, ", ")?;
                }
                write!(f, "{target}")?;
            }
            write!(f, "]")?;
        }
        write!(f, ")")
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
/// 2. Build and queue a distress mesh beacon (placeholder).
/// 3. Execute remaining wipe targets (filesystem overwrites — these are
///    defense-in-depth since key zeroization already makes data
///    unrecoverable).
/// 4. Scrub user-space memory pages.
///
/// The `dry_run` flag controls whether filesystem I/O is actually
/// performed. In dry-run mode, the plan is traversed but no writes occur.
///
/// Returns a [`WipeResult`] summarizing the operation.
///
/// # Safety
///
/// When `dry_run` is `false`, this destroys live memory: step 4
/// ([`scrub_user_pages`]) zeroes every page frame in the managed usable
/// range, including pages currently backing the kernel's own heap and any
/// running process. The caller must treat a non-dry-run call as the LAST
/// kernel action before an immediate halt/reboot — nothing may read or
/// write heap/page-backed memory afterward. `dry_run = true` performs no
/// destructive I/O and carries no such requirement.
pub(crate) unsafe fn execute_panic_wipe(
    key_manager: &mut KeyManager,
    triggered_at: u64,
    dry_run: bool,
) -> WipeResult {
    let plan = build_panic_plan();

    let mut completed: usize = 0;
    let mut failed: usize = 0;
    let mut failed_targets: [Option<WipeTarget>; PANIC_WIPE_TARGET_COUNT] =
        [None; PANIC_WIPE_TARGET_COUNT];

    // Step 1: Zeroize keys from memory — this is the critical action
    // that makes all encrypted data unrecoverable. WHY (SECURITY, finding
    // 15): wrapped in a stop-the-world IRQ-masked critical section so no
    // timer/scheduler-tick or other IRQ handler can preempt between "wipe
    // triggered" and "keys destroyed" -- without this, an interrupt firing
    // mid-zeroize could switch away to code that still observes the live
    // keys for one or more scheduling quanta.
    let keys_zeroized_in_memory = {
        let _irq_guard = irq::IrqGuard::new();
        key_manager.zeroize_all();
        true
    };

    for target in plan.targets() {
        // WHY (SECURITY, finding 9): every target's on-disk tally comes
        // from the same wipe_target_path() check -- WipeTarget::Keys' own
        // in-memory zeroization already happened unconditionally in Step 1
        // above and is tracked separately via `keys_zeroized_in_memory`
        // (finding 14), so a failure recorded here must not be read as
        // "the encryption keys are still recoverable".
        if dry_run || wipe_target_path(target.path()) {
            completed = completed.saturating_add(1);
        } else {
            // WHY (SECURITY, finding 9): record WHICH target failed, not
            // just a bare count -- an operator needs to know whether it
            // was WiFi credentials or the message store that survived an
            // incomplete wipe.
            if let Some(slot) = failed_targets.get_mut(failed) {
                *slot = Some(*target);
            }
            failed = failed.saturating_add(1);
        }
    }

    // Step 2: Build the distress beacon payload. WHY (SECURITY, finding
    // 10): emit_distress_beacon only constructs the in-memory payload --
    // the actual mesh/LoRa transmission is not yet wired (same class as
    // #129's wipe_target_path stub), so this function never hands the
    // beacon to a radio driver. beacon_emitted below must report false
    // rather than claiming a distress signal was actually transmitted.
    let _beacon = emit_distress_beacon(triggered_at, !key_manager.has_keys());
    let beacon_emitted = false;

    // Step 3: Memory scrub.
    let memory_scrubbed = if dry_run {
        true // Dry-run: report as done.
    } else {
        // SAFETY: propagated from execute_panic_wipe's own `# Safety`
        // section — a non-dry-run caller must already be treating this as
        // the last action before an immediate halt/reboot.
        unsafe { scrub_user_pages() }
    };

    WipeResult {
        targets_completed: completed,
        keys_zeroized_in_memory,
        targets_failed: failed,
        failed_targets,
        memory_scrubbed,
        beacon_emitted,
    }
}

/// Scrub every page frame in the managed usable range by zeroing it in
/// place — free and in-use alike.
///
/// Walks the physical page range directly via [`page::zero_usable_range`]
/// rather than allocating through `page::alloc_page`, so it reaches
/// frames that are currently in use as well as free ones, and cannot
/// abort via `handle_alloc_error` regardless of free-page count (#321).
///
/// Returns `true` if any page was scrubbed, `false` if the usable range is
/// empty (e.g., the page allocator was never initialized — the host test
/// harness case).
///
/// # Safety
///
/// See [`page::zero_usable_range`]. This must be the last action taken
/// before an immediate halt/reboot; it is not yet wired into a live
/// boot/panic path (Wave 8 integration item).
pub(crate) unsafe fn scrub_user_pages() -> bool {
    // SAFETY: propagated from this function's own `# Safety` contract.
    let zeroed = unsafe { page::zero_usable_range() };
    zeroed > 0
}

/// Build the distress mesh beacon payload.
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
/// the inode and overwrite the data blocks. Until that lands, this
/// performs no I/O and must report failure — reporting success for a
/// target it never touched would tell the caller a persisted key/data
/// store was destroyed when it was not (#324).
fn wipe_target_path(_path: &str) -> bool {
    // TODO(#129)[deliberate-prudent]: wire to lfs::overwrite_path() when filesystem
    // runtime I/O is available from the security subsystem. Until then this
    // MUST return false — see the WHY above.
    false
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

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
        assert_eq!(
            plan.len(),
            PANIC_WIPE_TARGET_COUNT,
            "plan must have 6 targets"
        );
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
                window[0],
                window[0].priority(),
                window[1],
                window[1].priority(),
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
            assert!(targets.contains(req), "plan must contain {req}");
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

        // SAFETY: dry_run = true performs no destructive I/O.
        let result = unsafe { execute_panic_wipe(&mut km, 1000, true) };

        assert!(!km.has_keys(), "keys must be zeroized after wipe");
        assert_eq!(
            km.sleep_tier(),
            SleepTier::Long,
            "sleep tier must be Long after key zeroization"
        );
        assert_eq!(result.targets_completed, PANIC_WIPE_TARGET_COUNT);
        assert_eq!(result.targets_failed, 0);
        assert!(
            !result.beacon_emitted,
            "beacon_emitted must be false until mesh transmission is actually wired (finding 10)"
        );
    }

    #[test]
    fn execute_wipe_dry_run_no_failures() {
        let mut km = key_manager_with_derived_keys();
        // SAFETY: dry_run = true performs no destructive I/O.
        let result = unsafe { execute_panic_wipe(&mut km, 500, true) };
        assert_eq!(result.targets_failed, 0, "dry-run must have zero failures");
        assert!(
            result.memory_scrubbed,
            "dry-run must report memory as scrubbed"
        );
    }

    #[test]
    fn execute_panic_wipe_restores_irq_state_after_key_zeroization() {
        // SECURITY (finding 15): the key-zeroization step in Step 1 runs
        // inside an IrqGuard so no IRQ/scheduler-tick can preempt between
        // "wipe triggered" and "keys destroyed". Verify the guard is
        // correctly scoped: IRQ delivery must be back in its normal
        // (enabled) state once execute_panic_wipe returns, not left
        // masked.
        crate::irq::reset_mock();
        assert!(crate::irq::mock_enabled(), "starts unmasked");

        let mut km = key_manager_with_derived_keys();
        // SAFETY: dry_run = true performs no destructive I/O.
        let _result = unsafe { execute_panic_wipe(&mut km, 6000, true) };

        assert!(
            crate::irq::mock_enabled(),
            "IRQ delivery must be restored (guard dropped) after the wipe completes"
        );
    }

    // -----------------------------------------------------------------------
    // Memory scrub
    // -----------------------------------------------------------------------

    #[test]
    fn scrub_user_pages_returns_result() {
        // NOTE: page::init() is never called in this test binary (no test
        // in this module maps real physical RAM), so the usable range is
        // empty and this exercises the "nothing to scrub" path.
        // SAFETY: an empty usable range means zero_usable_range performs no
        // memory access.
        let result = unsafe { scrub_user_pages() };
        assert!(
            !result,
            "scrub of an empty (uninitialized) usable range must report false"
        );
        assert_eq!(
            page::free_count(),
            0,
            "scrub must never mutate FREE_PAGES bookkeeping"
        );
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

    #[test]
    fn keys_zeroized_in_memory_is_tracked_separately_from_file_tally() {
        // SECURITY (finding 14, info): WipeTarget::Keys' entry in
        // failed_targets reflects ONLY the on-disk key-file overwrite
        // (currently always fails: #324/#129's wipe_target_path stub).
        // The in-memory zeroization in Step 1 is unconditional and
        // infallible, and must be visible independent of that filesystem
        // tally so a reader cannot mistake "Keys in failed_targets" for
        // "the encryption keys are still recoverable".
        let mut km = key_manager_with_derived_keys();
        // SAFETY: this is the last action in this test.
        let result = unsafe { execute_panic_wipe(&mut km, 5000, false) };

        assert!(
            result.keys_zeroized_in_memory,
            "in-memory key zeroization must be reported true independent of the file tally"
        );
        assert!(
            result.failed_targets.contains(&Some(WipeTarget::Keys)),
            "the key-FILE overwrite is still expected to fail while wipe_target_path is a stub"
        );
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

    #[test]
    fn beacon_emitted_reports_false_while_transmission_is_unwired() {
        // SECURITY (finding 10): emit_distress_beacon only builds the
        // payload in memory -- execute_panic_wipe never hands it to a
        // mesh/radio driver, so reporting beacon_emitted=true would tell
        // the operator a distress signal went out over LoRa when nothing
        // was actually transmitted.
        let mut km = key_manager_with_derived_keys();
        // SAFETY: dry_run = true performs no destructive I/O.
        let result = unsafe { execute_panic_wipe(&mut km, 4000, true) };
        assert!(
            !result.beacon_emitted,
            "beacon_emitted must be false until mesh transmission is actually wired"
        );
    }

    // -----------------------------------------------------------------------
    // Display implementations
    // -----------------------------------------------------------------------

    #[test]
    fn display_impls_produce_output() {
        let plan = build_panic_plan();
        let plan_s = alloc::format!("{plan}");
        assert!(
            plan_s.contains("6 targets"),
            "WipePlan Display must show count"
        );
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
            keys_zeroized_in_memory: true,
            targets_failed: 1,
            failed_targets: [None; PANIC_WIPE_TARGET_COUNT],
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
    fn wipe_target_path_reports_not_implemented() {
        // Regression test for #324: the LFS wipe backend (#129) is not yet
        // wired, so wipe_target_path must not claim success for filesystem
        // targets it never actually overwrote.
        assert!(!wipe_target_path("/data/keys"));
        assert!(!wipe_target_path("/data/contacts"));
    }

    #[test]
    fn execute_wipe_records_which_targets_failed() {
        // SECURITY (finding 9): a bare failure count cannot tell an
        // operator WHICH category of sensitive data survived an
        // incomplete panic wipe. With the LFS wipe backend absent (#129),
        // every filesystem target fails, so failed_targets must name each
        // one individually.
        let mut km = key_manager_with_derived_keys();
        // SAFETY: this is the last action in this test.
        let result = unsafe { execute_panic_wipe(&mut km, 3000, false) };

        assert_eq!(result.targets_failed, PANIC_WIPE_TARGET_COUNT);
        let named_count = result.failed_targets.iter().flatten().count();
        assert_eq!(
            named_count, PANIC_WIPE_TARGET_COUNT,
            "every failed target must be individually named, not just counted"
        );
        for expected in [
            WipeTarget::Keys,
            WipeTarget::Contacts,
            WipeTarget::Messages,
            WipeTarget::CallHistory,
            WipeTarget::WifiCredentials,
            WipeTarget::BluetoothPairings,
        ] {
            assert!(
                result.failed_targets.contains(&Some(expected)),
                "{expected} must appear in failed_targets"
            );
        }
    }

    #[test]
    fn execute_wipe_real_run_reports_filesystem_targets_as_failed() {
        // Regression test for #324: with the LFS backend absent (#129), a
        // real (non-dry-run) panic wipe must not claim the filesystem
        // targets completed — it never overwrote them. The in-memory key
        // zeroization (step 1) still happens independently and is verified
        // by execute_wipe_zeroizes_keys.
        let mut km = key_manager_with_derived_keys();
        // SAFETY: this is the last action in this test — nothing reads
        // page/heap-backed memory afterward.
        let result = unsafe { execute_panic_wipe(&mut km, 2000, false) };

        assert!(
            !km.has_keys(),
            "in-memory keys must still be zeroized on a real run"
        );
        assert_eq!(
            result.targets_completed, 0,
            "no filesystem target can be reported completed while wipe_target_path is a no-op stub"
        );
        assert_eq!(
            result.targets_failed, PANIC_WIPE_TARGET_COUNT,
            "every target, including keys' filesystem copy, must be reported failed/unverified"
        );
    }
}
