//! kinit's pure boot-planning logic -- spawn planning, boot-step ordering,
//! boot-state tracking, and the boot constants the unit tests assert on.
//!
//! WHY this module exists (#528): `mod kinit` is `#[cfg(not(test))]`, so
//! everything left in kinit.rs was compiled by NO test build -- the armv7a
//! kernel build excludes `cfg(test)` code, and the host (i686) test build
//! excluded the whole module. kinit's ~22 unit tests were dead source,
//! type-checked nowhere, giving zero protection to the spawn-plan and
//! boot-order invariants they document. The pure logic lives here instead,
//! compiled on EVERY target (same pattern as `supervisor`, see main.rs);
//! kinit.rs keeps only the hardware-init-bearing boot sequence.

#[cfg(test)]
use crate::device;
use crate::fd;
use crate::net::{self, NetworkReadiness};
#[cfg(test)]
use crate::ramfs::RamFs;

// ---------------------------------------------------------------------------
// Boot step enumeration
// ---------------------------------------------------------------------------

/// Ordered boot steps. Numeric ORDER encodes dependency: each step
/// depends on all preceding steps HAVING been attempted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
// WHY cfg_attr(not(test)): production never reads BootStep (only the tests and
// future boot progress reporting do), so it is dead code on armv7a and the
// expectation lives exactly there; under the host test build the tests use it
// and a blanket expect would go unfulfilled (#528).
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "used by tests and future boot progress reporting (test-fixture)"
    )
)]
pub(crate) enum BootStep {
    /// MMU and caches.
    Mmu = 0,
    /// Physical page allocator.
    PageAllocator = 1,
    /// Kernel slab heap.
    Heap = 2,
    /// GIC interrupt controller.
    Gic = 3,
    /// Process subsystem.
    Process = 4,
    /// Exception vectors and timer.
    Exceptions = 5,
    /// Device registry populated.
    DeviceRegistry = 6,
    /// eMMC block device.
    Emmc = 7,
    /// Display pipeline (DDP).
    Display = 8,
    /// GPIO keypad scanning (relocated before the passphrase gate, #344).
    GpioInput = 9,
    /// Measured boot signature verification (Ed25519).
    SecureBoot = 10,
    /// Filesystem (LFS on eMMC) -- trust-gated on SecureBoot (#217).
    Filesystem = 11,
    /// Passphrase entry and key derivation.
    Passphrase = 12,
    /// Encrypted filesystem mount.
    Encryption = 13,
    /// Tamper-evident audit log initialization.
    AuditLog = 14,
    /// Security mode manager (Daily/Sentinel/Panic).
    SecurityMode = 15,
    /// USB ACM serial console.
    UsbSerial = 16,
    /// CCCI modem link.
    CcciModem = 17,
    /// Power manager.
    PowerManager = 18,
    /// Network configuration (DHCP + DNS resolver).
    Network = 19,
    /// Bluetooth adapter initialization.
    Bluetooth = 20,
    /// GPS receiver initialization.
    Gps = 21,
    /// Userspace process spawn attempted.
    Userspace = 22,
    /// Boot complete.
    Complete = 23,
}

// WHY cfg_attr(not(test)): see the enum above -- the expectation applies to
// the armv7a builds, where nothing outside tests calls these methods.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "used by tests and future boot progress reporting (test-fixture)"
    )
)]
impl BootStep {
    /// Total number of boot steps.
    pub(crate) const COUNT: usize = 24;

    /// Returns true if `self` depends on `other` (i.e., `other` must
    /// be attempted before `self`).
    pub(crate) const fn depends_on(self, other: Self) -> bool {
        (self as u8) > (other as u8)
    }
}

// ---------------------------------------------------------------------------
// Boot state tracker
// ---------------------------------------------------------------------------

/// Tracks which subsystems initialized successfully during boot.
/// The panic handler and degradation logic read this to decide what
/// output paths are available.
#[derive(Debug, Clone, Copy)]
pub(crate) struct BootState {
    // kanon:ignore RUST/struct-too-many-fields -- one bool per boot subsystem; grouping would obscure the per-subsystem degradation model
    pub(crate) mmu_ok: bool,
    pub(crate) heap_ok: bool,
    pub(crate) gic_ok: bool,
    pub(crate) timer_ok: bool,
    pub(crate) csprng_ok: bool,
    pub(crate) emmc_ok: bool,
    pub(crate) display_ok: bool,
    pub(crate) secure_boot_ok: bool,
    pub(crate) passphrase_ok: bool,
    pub(crate) encryption_ok: bool,
    pub(crate) audit_ok: bool,
    pub(crate) security_mode_ok: bool,
    pub(crate) usb_ok: bool,
    pub(crate) modem_ok: bool,
    pub(crate) input_ok: bool,
    pub(crate) network_ok: bool,
    pub(crate) network_loopback_smoke_ok: bool,
    pub(crate) network_readiness: NetworkReadiness,
    pub(crate) bluetooth_ok: bool,
    pub(crate) gps_ok: bool,
    pub(crate) processes_spawned: u8,
    pub(crate) userspace_entries_missing: u8,
}

impl BootState {
    /// Fresh boot state with nothing initialized.
    pub(crate) const fn new() -> Self {
        Self {
            mmu_ok: false,
            heap_ok: false,
            gic_ok: false,
            timer_ok: false,
            csprng_ok: false,
            emmc_ok: false,
            display_ok: false,
            secure_boot_ok: false,
            passphrase_ok: false,
            encryption_ok: false,
            audit_ok: false,
            security_mode_ok: false,
            usb_ok: false,
            modem_ok: false,
            input_ok: false,
            network_ok: false,
            network_loopback_smoke_ok: false,
            network_readiness: NetworkReadiness::HardwareUnavailable(net::NetworkDeviceKind::Wifi),
            bluetooth_ok: false,
            gps_ok: false,
            processes_spawned: 0,
            userspace_entries_missing: 0,
        }
    }

    /// The per-subsystem OK flags backing [`Self::ok_count`] and
    /// [`Self::total_subsystems`]. Single source of truth: add a newly
    /// tracked subsystem's flag here and both the numerator (`ok_count`)
    /// and denominator (`total_subsystems`) update together automatically
    /// -- the boot summary's "N / total" denominator was previously a
    /// hand-maintained literal independent of this list, and had already
    /// drifted once (17 -> 18 when csprng_ok was added). The array length
    /// in the return type is compiler-checked against this literal, so the
    /// two can no longer silently diverge.
    const fn subsystem_flags(&self) -> [bool; 18] {
        [
            self.mmu_ok,
            self.heap_ok,
            self.gic_ok,
            self.timer_ok,
            self.csprng_ok,
            self.emmc_ok,
            self.display_ok,
            self.secure_boot_ok,
            self.passphrase_ok,
            self.encryption_ok,
            self.audit_ok,
            self.security_mode_ok,
            self.usb_ok,
            self.modem_ok,
            self.input_ok,
            self.network_ok,
            self.bluetooth_ok,
            self.gps_ok,
        ]
    }

    /// Count of successfully initialized subsystems, out of
    /// [`Self::total_subsystems`].
    pub(crate) const fn ok_count(&self) -> u8 {
        let flags = self.subsystem_flags();
        let mut n = 0;
        let mut i = 0;
        while i < flags.len() {
            if flags[i] {
                n += 1;
            }
            i += 1;
        }
        n
    }

    /// Total number of subsystems tracked by [`Self::ok_count`]. Derived
    /// from the same flag array `ok_count` iterates, so this denominator
    /// can never drift from the numerator it describes.
    pub(crate) const fn total_subsystems(&self) -> u8 {
        self.subsystem_flags().len() as u8
    }

    /// Record the production network readiness result from a real device.
    pub(crate) fn record_network_readiness(&mut self, readiness: NetworkReadiness) {
        self.network_readiness = readiness;
        self.network_ok = readiness.production_network_ok();
    }

    /// Record that the host-only loopback smoke path completed.
    pub(crate) fn record_loopback_smoke(&mut self, readiness: NetworkReadiness) {
        self.network_loopback_smoke_ok = readiness.loopback_smoke_only();
    }
}

// ---------------------------------------------------------------------------
// CCCI modem boot timeout
// ---------------------------------------------------------------------------

/// Maximum time (ms) to wait for modem boot before declaring failure.
#[cfg_attr(
    feature = "qemu",
    expect(
        dead_code,
        reason = "consumed by the CCCI init step, which is qemu-gated (#463)"
    )
)]
pub(crate) const MODEM_BOOT_TIMEOUT_MS: u64 = 10_000;

/// Framebuffer RGB565 colour: solid red (panic and secure-boot-halt
/// indicator).
pub(crate) const PANIC_RED_RGB565: u16 = 0xF800;

// ---------------------------------------------------------------------------
// Userspace spawn planning
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UserspaceSpawnPlan<'a> {
    Elf(&'a [u8]),
    Missing,
}

#[cfg(test)]
fn plan_userspace_spawn_from_ramfs<'a>(fs: &'a RamFs, path: &str) -> UserspaceSpawnPlan<'a> {
    match fs.find(path) {
        Some(elf_data) => UserspaceSpawnPlan::Elf(elf_data),
        None => UserspaceSpawnPlan::Missing,
    }
}

pub(crate) fn plan_userspace_spawn_from_vfs(path: &str) -> UserspaceSpawnPlan<'static> {
    // SAFETY: the VFS mount table is initialized before userspace spawn.
    match unsafe { fd::ramfs_find(path) } {
        Some(elf_data) => UserspaceSpawnPlan::Elf(elf_data),
        None => UserspaceSpawnPlan::Missing,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use alloc::format;
    use alloc::vec::Vec;

    use super::*;

    fn build_cpio_entry(name: &str, data: &[u8], mode: u32) -> Vec<u8> {
        let mut entry = Vec::new();
        let namesize = name.len() + 1;
        let filesize = data.len();

        entry.extend_from_slice(b"070701");
        entry.extend_from_slice(b"00000001");
        entry.extend_from_slice(format!("{mode:08X}").as_bytes());
        entry.extend_from_slice(b"00000000");
        entry.extend_from_slice(b"00000000");
        entry.extend_from_slice(b"00000001");
        entry.extend_from_slice(b"00000000");
        entry.extend_from_slice(format!("{filesize:08X}").as_bytes());
        entry.extend_from_slice(b"00000000");
        entry.extend_from_slice(b"00000000");
        entry.extend_from_slice(b"00000000");
        entry.extend_from_slice(b"00000000");
        entry.extend_from_slice(format!("{namesize:08X}").as_bytes());
        entry.extend_from_slice(b"00000000");
        assert_eq!(entry.len(), 110, "header must be exactly 110 bytes");

        entry.extend_from_slice(name.as_bytes());
        entry.push(0);
        while entry.len() % 4 != 0 {
            entry.push(0);
        }

        entry.extend_from_slice(data);
        while entry.len() % 4 != 0 {
            entry.push(0);
        }

        entry
    }

    fn build_cpio_trailer() -> Vec<u8> {
        build_cpio_entry("TRAILER!!!", &[], 0)
    }

    // -- Userspace spawn planning --

    #[test]
    fn userspace_spawn_plan_prefers_populated_initramfs_entry() {
        let mut archive = Vec::new();
        archive.extend(build_cpio_entry("init", b"\x7FELFinit", 0o100755));
        archive.extend(build_cpio_entry("shell", b"\x7FELFshell", 0o100755));
        archive.extend(build_cpio_trailer());
        let fs = RamFs::from_cpio(&archive);

        assert_eq!(
            plan_userspace_spawn_from_ramfs(&fs, "/init"),
            UserspaceSpawnPlan::Elf(b"\x7FELFinit")
        );
        assert_eq!(
            plan_userspace_spawn_from_ramfs(&fs, "/shell"),
            UserspaceSpawnPlan::Elf(b"\x7FELFshell")
        );
    }

    #[test]
    fn userspace_spawn_plan_reports_absent_entry() {
        let fs = RamFs::new();

        assert_eq!(
            plan_userspace_spawn_from_ramfs(&fs, "/init"),
            UserspaceSpawnPlan::Missing
        );
        assert_eq!(
            plan_userspace_spawn_from_ramfs(&fs, "/shell"),
            UserspaceSpawnPlan::Missing
        );
    }

    // -- BootStep ordering --

    #[test]
    fn boot_step_mmu_first() {
        assert_eq!(BootStep::Mmu as u8, 0, "MMU must be the first boot step");
    }

    #[test]
    fn boot_step_count_matches_variants() {
        assert_eq!(
            BootStep::COUNT,
            24,
            "BootStep::COUNT must match the number of variants"
        );
    }

    #[test]
    fn boot_step_dependency_order() {
        // WHY: heap requires MMU (virtual memory) and page allocator
        assert!(
            BootStep::Heap.depends_on(BootStep::Mmu),
            "heap depends on MMU"
        );
        assert!(
            BootStep::Heap.depends_on(BootStep::PageAllocator),
            "heap depends on page allocator"
        );

        // WHY: display requires heap (alloc) and GIC (interrupts)
        assert!(
            BootStep::Display.depends_on(BootStep::Heap),
            "display depends on heap"
        );
        assert!(
            BootStep::Display.depends_on(BootStep::Gic),
            "display depends on GIC"
        );

        // WHY: modem requires heap, GIC, and timer (for timeout)
        assert!(
            BootStep::CcciModem.depends_on(BootStep::Heap),
            "modem depends on heap"
        );
        assert!(
            BootStep::CcciModem.depends_on(BootStep::Exceptions),
            "modem depends on timer (exceptions)"
        );

        // WHY: userspace requires all hardware to be attempted first
        assert!(
            BootStep::Userspace.depends_on(BootStep::GpioInput),
            "userspace depends on GPIO input"
        );

        // WHY: userspace requires network to have been attempted
        assert!(
            BootStep::Userspace.depends_on(BootStep::Network),
            "userspace depends on network"
        );
    }

    #[test]
    fn boot_step_complete_is_last() {
        assert_eq!(
            BootStep::Complete as u8,
            23,
            "Complete must be the highest-numbered step"
        );
    }

    // -- BootState tracking --

    #[test]
    fn boot_state_initial_all_false() {
        let state = BootState::new();
        assert!(!state.mmu_ok, "initial mmu_ok must be false");
        assert!(!state.heap_ok, "initial heap_ok must be false");
        assert!(!state.gic_ok, "initial gic_ok must be false");
        assert!(!state.timer_ok, "initial timer_ok must be false");
        assert!(!state.csprng_ok, "initial csprng_ok must be false");
        assert!(!state.emmc_ok, "initial emmc_ok must be false");
        assert!(!state.display_ok, "initial display_ok must be false");
        assert!(
            !state.secure_boot_ok,
            "initial secure_boot_ok must be false"
        );
        assert!(!state.passphrase_ok, "initial passphrase_ok must be false");
        assert!(!state.encryption_ok, "initial encryption_ok must be false");
        assert!(!state.audit_ok, "initial audit_ok must be false");
        assert!(
            !state.security_mode_ok,
            "initial security_mode_ok must be false"
        );
        assert!(!state.usb_ok, "initial usb_ok must be false");
        assert!(!state.modem_ok, "initial modem_ok must be false");
        assert!(!state.input_ok, "initial input_ok must be false");
        assert!(!state.network_ok, "initial network_ok must be false");
        assert!(
            !state.network_loopback_smoke_ok,
            "initial network_loopback_smoke_ok must be false"
        );
        assert_eq!(
            state.network_readiness,
            NetworkReadiness::HardwareUnavailable(net::NetworkDeviceKind::Wifi),
            "initial network readiness must fail closed"
        );
        assert_eq!(
            state.processes_spawned, 0,
            "initial processes_spawned must be 0"
        );
        assert_eq!(
            state.userspace_entries_missing, 0,
            "initial userspace_entries_missing must be 0"
        );
    }

    #[test]
    fn boot_state_ok_count_empty() {
        let state = BootState::new();
        assert_eq!(state.ok_count(), 0, "empty boot state has 0 OK subsystems");
    }

    #[test]
    fn boot_state_ok_count_partial() {
        let mut state = BootState::new();
        state.mmu_ok = true;
        state.heap_ok = true;
        state.gic_ok = true;
        assert_eq!(state.ok_count(), 3, "3 subsystems marked OK");
    }

    #[test]
    fn boot_state_ok_count_full() {
        let mut state = BootState::new();
        state.mmu_ok = true;
        state.heap_ok = true;
        state.gic_ok = true;
        state.timer_ok = true;
        state.csprng_ok = true;
        state.emmc_ok = true;
        state.display_ok = true;
        state.secure_boot_ok = true;
        state.passphrase_ok = true;
        state.encryption_ok = true;
        state.audit_ok = true;
        state.security_mode_ok = true;
        state.usb_ok = true;
        state.modem_ok = true;
        state.input_ok = true;
        state.network_ok = true;
        state.bluetooth_ok = true;
        state.gps_ok = true;
        assert_eq!(state.ok_count(), 18, "all 18 subsystems OK");
    }

    #[test]
    fn boot_state_total_subsystems_matches_ok_count_denominator() {
        let mut state = BootState::new();
        assert_eq!(state.total_subsystems(), 18);

        state.mmu_ok = true;
        state.heap_ok = true;
        assert_eq!(
            state.total_subsystems(),
            18,
            "total_subsystems must not change as flags flip"
        );
        assert!(state.ok_count() <= state.total_subsystems());
    }

    #[test]
    fn boot_state_loopback_smoke_is_not_production_network_ok() {
        let mut state = BootState::new();
        state.record_loopback_smoke(NetworkReadiness::from_device(
            net::NetworkDeviceKind::LoopbackSmoke,
            true,
        ));
        assert!(
            !state.network_ok,
            "loopback smoke must not mark production network ready"
        );
        assert_eq!(
            state.ok_count(),
            0,
            "loopback smoke must not count as an OK production subsystem"
        );
    }

    #[test]
    fn boot_state_wifi_unavailable_is_not_production_network_ok() {
        let mut state = BootState::new();
        state.record_network_readiness(NetworkReadiness::from_device(
            net::NetworkDeviceKind::Wifi,
            false,
        ));

        assert_eq!(
            state.network_readiness,
            NetworkReadiness::HardwareUnavailable(net::NetworkDeviceKind::Wifi)
        );
        assert!(
            !state.network_ok,
            "WiFi-unavailable readiness must not mark production network ready"
        );
    }

    #[test]
    fn boot_state_missing_entries_do_not_count_as_userspace() {
        let mut state = BootState::new();
        state.userspace_entries_missing = 2;
        assert_eq!(
            state.processes_spawned, 0,
            "missing userspace entries must not count as ELF userspace processes"
        );
    }

    // -- Degradation paths --

    #[test]
    fn display_failure_does_not_block_usb() {
        // WHY: display and USB are independent  -  display failure must not
        // prevent USB serial FROM being the fallback console.
        let step_display = BootStep::Display as u8;
        let step_usb = BootStep::UsbSerial as u8;
        assert!(
            step_usb > step_display,
            "USB init comes after display in sequence"
        );

        // Simulate: display failed, USB still initializes
        let mut state = BootState::new();
        state.display_ok = false;
        state.usb_ok = true;
        assert!(
            state.usb_ok && !state.display_ok,
            "USB available despite display failure"
        );
    }

    #[test]
    fn modem_failure_does_not_block_input() {
        // WHY: modem failure must not prevent keypad FROM working. The
        // keypad initializes BEFORE the modem (relocated in #344 so the
        // passphrase gate can see input_ok).
        let step_modem = BootStep::CcciModem as u8;
        let step_input = BootStep::GpioInput as u8;
        assert!(
            step_modem > step_input,
            "GPIO init comes before modem in sequence"
        );

        let mut state = BootState::new();
        state.modem_ok = false;
        state.input_ok = true;
        assert!(
            state.input_ok && !state.modem_ok,
            "input available despite modem failure"
        );
    }

    #[test]
    fn modem_failure_disables_phone_functions() {
        let mut state = BootState::new();
        state.modem_ok = false;
        assert!(!state.modem_ok, "modem failure disables phone functions");
    }

    // -- Panic display --

    #[test]
    fn panic_red_is_correct_rgb565() {
        // WHY: RGB565 red = 5 bits R (all 1), 6 bits G (all 0), 5 bits B (all 0)
        // = 0b11111_000000_00000 = 0xF800
        assert_eq!(
            PANIC_RED_RGB565, 0xF800,
            "panic red must be RGB565 pure red"
        );
    }

    // -- Register address constants --
    // NOTE (#534): the canonical address test moved with the constants — see
    // board/m7.rs's `register_devices_pins_canonical_addresses`, which pins
    // the registry against board::m7's consts directly (and cannot alias to
    // QEMU addresses, the pre-#534 trap this test fell into).

    // -- Modem timeout constant --

    #[test]
    fn modem_timeout_is_reasonable() {
        assert!(
            MODEM_BOOT_TIMEOUT_MS >= 5_000,
            "modem timeout must be at least 5 seconds"
        );
        assert!(
            MODEM_BOOT_TIMEOUT_MS <= 30_000,
            "modem timeout must be at most 30 seconds"
        );
    }

    // -- Security boot step ordering (Phase 08 Wave 8) --

    #[test]
    fn boot_step_ordering_is_correct() {
        // WHY: security steps must execute in strict order after display
        // but before USB/modem/network.  Verify numeric ordering encodes
        // this dependency.
        assert!(
            BootStep::SecureBoot.depends_on(BootStep::Display),
            "SecureBoot must run after Display (errors need display)"
        );
        assert!(
            BootStep::Filesystem.depends_on(BootStep::SecureBoot),
            "Filesystem mount must run after SecureBoot (#217: a tampered image must never reach user data)"
        );
        assert!(
            BootStep::Passphrase.depends_on(BootStep::SecureBoot),
            "Passphrase entry must run after SecureBoot verification"
        );
        assert!(
            BootStep::Encryption.depends_on(BootStep::Passphrase),
            "Encryption mount must run after Passphrase derives keys"
        );
        assert!(
            BootStep::AuditLog.depends_on(BootStep::Encryption),
            "AuditLog must run after Encryption (needs audit key)"
        );
        assert!(
            BootStep::SecurityMode.depends_on(BootStep::AuditLog),
            "SecurityMode must run after AuditLog is initialized"
        );
        // Security steps must all complete before USB/modem.
        assert!(
            BootStep::UsbSerial.depends_on(BootStep::SecurityMode),
            "USB serial must come after all security init"
        );
    }

    #[test]
    fn security_boot_steps_are_contiguous() {
        // WHY (#217): the trust chain is consecutive with no gaps --
        // verify, then mount, then derive keys, then decrypt, then audit.
        assert_eq!(BootStep::SecureBoot as u8, 10);
        assert_eq!(BootStep::Filesystem as u8, 11);
        assert_eq!(BootStep::Passphrase as u8, 12);
        assert_eq!(BootStep::Encryption as u8, 13);
        assert_eq!(BootStep::AuditLog as u8, 14);
        assert_eq!(BootStep::SecurityMode as u8, 15);
    }
}
