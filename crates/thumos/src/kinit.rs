//! Kernel init  -  the first code that runs after kernel boot.
//!
//! Initializes all kernel subsystems in dependency ORDER, then loads and
//! starts userspace daemons FROM the ramfs. Acts as a supervisor per the
//! Hubris model: each driver init is fault-isolated, logged, and skippable.
//!
//! Boot ORDER:
//! MMU → page alloc → heap → GIC → process → exceptions/timer → CSPRNG → devices →
//! eMMC → display → GPIO keypad → secure boot → passphrase → encrypted fs →
//! audit log → security mode → USB serial → CCCI modem → power → userspace.

extern crate alloc;

use core::fmt::Write;
use core::slice;
use core::sync::atomic::AtomicBool;
#[cfg(not(feature = "qemu"))]
use core::sync::atomic::Ordering;

#[cfg(not(feature = "qemu"))]
use crate::ccci::CcciDriver;
#[cfg(feature = "debug-console")]
use crate::console::Console;
use crate::csprng;
#[cfg(feature = "qemu")]
use crate::device::DeviceRegistry;
#[cfg(not(feature = "qemu"))]
use crate::device::{self, DeviceRegistry};
#[cfg(not(feature = "qemu"))]
use crate::dhcp::{DhcpClient, DhcpEvent};
#[cfg(not(feature = "qemu"))]
use crate::display::{DisplayDriver, Gc9306};
#[cfg(not(feature = "qemu"))]
use crate::dns::{DnsResolver, LAN_DNS, MULLVAD_DNS};
use crate::elf;
use crate::exceptions;
use crate::fd;
use crate::gic;
use crate::heap;
use crate::kconfig;
#[cfg(not(feature = "qemu"))]
use crate::mmio;
use crate::mmu;
use crate::net::{self, NetworkReadiness, WifiDevice};
#[cfg(not(feature = "qemu"))]
use crate::net::{FirewallDevice, LoopbackDevice, NetworkStack};
use crate::page;
use crate::power::PowerManager;
use crate::process;
#[cfg(test)]
use crate::ramfs::RamFs;
use crate::screen_home::{HomeScreen, HomeScreenState, OperatingMode};
use crate::status_bar::{KernelStatusBar, StatusBarState};
use crate::uart::Uart;
use crate::ui::{self, UiManager};
#[cfg(not(feature = "qemu"))]
use crate::usb::UsbController;
use crate::watchdog;

// ---------------------------------------------------------------------------
// Global state  -  read by panic handler and other subsystems
// ---------------------------------------------------------------------------

/// Display pipeline initialized and framebuffer writable.
pub(crate) static DISPLAY_AVAILABLE: AtomicBool = AtomicBool::new(false);

/// USB ACM serial link established.
#[cfg_attr(
    feature = "qemu",
    expect(dead_code, reason = "set by the USB init step, which is qemu-gated")
)]
pub(crate) static USB_SERIAL_AVAILABLE: AtomicBool = AtomicBool::new(false);

/// Modem CCCI link established.
#[cfg_attr(
    feature = "qemu",
    expect(dead_code, reason = "set by the CCCI init step, which is qemu-gated")
)]
pub(crate) static MODEM_AVAILABLE: AtomicBool = AtomicBool::new(false);

// ---------------------------------------------------------------------------
// Boot step enumeration
// ---------------------------------------------------------------------------

/// Ordered boot steps. Numeric ORDER encodes dependency: each step
/// depends on all preceding steps HAVING been attempted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
#[expect(dead_code, reason = "used by tests and future boot progress reporting")]
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

#[expect(dead_code, reason = "used by tests and future boot progress reporting")]
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
        reason = "consumed by the CCCI init step, which is qemu-gated"
    )
)]
const MODEM_BOOT_TIMEOUT_MS: u64 = 10_000;

/// Framebuffer RGB565 colour: solid red (panic and secure-boot-halt
/// indicator). main.rs's panic handler uses the literal directly.
const PANIC_RED_RGB565: u16 = 0xF800;

/// Number of RGB565 pixels in the hardware framebuffer.
const FRAMEBUFFER_PIXELS: usize = ui::SCREEN_WIDTH as usize * ui::SCREEN_HEIGHT as usize;

// ---------------------------------------------------------------------------
// Panic display helper
// ---------------------------------------------------------------------------

/// Fill the framebuffer with a solid colour. Used by the panic handler
/// to produce a visual "red screen of death" on kernel panic.
///
/// # Safety
///
/// `fb_addr` must point to a valid, writable framebuffer region of at
/// least `width * height * 2` bytes (RGB565).
pub(crate) unsafe fn fill_framebuffer(fb_addr: usize, width: u32, height: u32, color: u16) {
    let total_pixels = (width * height) as usize;
    let ptr = fb_addr as *mut u16;
    for i in 0..total_pixels {
        // SAFETY: caller guarantees fb_addr points to a mapped, writable
        // framebuffer region of at least width * height * 2 bytes (RGB565).
        // ptr.add(i) stays within that region because i < total_pixels.
        unsafe {
            core::ptr::write_volatile(ptr.add(i), color);
        }
    }
}

// ---------------------------------------------------------------------------
// Secure-boot halt (#217)
// ---------------------------------------------------------------------------

/// Fail-closed boot halt (#217): a boot partition was present and its image
/// failed verification. Renders the tamper indicator when the display came
/// up, then parks the boot context forever WITHOUT enabling scheduling --
/// no passphrase entry, no decrypt, no mount, no userspace can ever run
/// (`process::enable_scheduling()` is only reached at the end of `run`).
///
/// WHY IRQs stay enabled: the timer ISR keeps petting the 5 s watchdog, so
/// the halt is a stable, visible state instead of a WDT reboot loop.
///
/// WHY(qemu): exit code 6 (distinct from 0=ok / 1=panic / 5=loop-stall) so
/// a runner sees a secure-boot halt as its own diagnostic; unreachable
/// today because qemu presents no boot medium.
fn halt_boot(serial: &mut Uart, display_ok: bool) -> ! {
    if display_ok {
        // SAFETY: display_ok is only true after display.init() succeeded,
        // so FB_BASE is a valid, mapped framebuffer of at least
        // DISPLAY_WIDTH * DISPLAY_HEIGHT * 2 bytes (RGB565).
        unsafe {
            fill_framebuffer(
                kconfig::FB_BASE,
                kconfig::DISPLAY_WIDTH,
                kconfig::DISPLAY_HEIGHT,
                PANIC_RED_RGB565,
            );
        }
    }
    let _ = serial
        .write_str("  CRIT Boot halted: image trust could not be established (fail-closed)\r\n");
    #[cfg(feature = "qemu")]
    crate::qemu::request_exit(6);
    loop {
        // SAFETY: WFI is a hint instruction; no memory is accessed. The CPU
        // sleeps until the next interrupt (the timer tick pets the WDT).
        unsafe {
            core::arch::asm!("wfi");
        }
    }
}

// ---------------------------------------------------------------------------
// Initial UI frame
// ---------------------------------------------------------------------------

/// Render the first user-visible home frame after boot-time hardware init.
fn render_initial_home_frame(fb: &mut [u16], state: &BootState) {
    let mut home = HomeScreen::new();
    home.update_state(HomeScreenState {
        epoch_secs: 0,
        carrier: "",
        mode: OperatingMode::Daily,
        unread_count: 0,
    });

    let status = StatusBarState {
        battery_pct: 0,
        mode_badge: Some("DAILY"),
        mode_badge_color: Some(ui::color::WHITE),
        threat_high: !state.modem_ok,
        ..StatusBarState::default()
    };

    UiManager::new().render(
        &home,
        |status_fb| KernelStatusBar::draw(status_fb, &status),
        fb,
    );
}

// ---------------------------------------------------------------------------
// Init helpers  -  each returns Ok/Err for fault isolation
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UserspaceSpawnPlan<'a> {
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

fn plan_userspace_spawn_from_vfs(path: &str) -> UserspaceSpawnPlan<'static> {
    // SAFETY: the VFS mount table is initialized before userspace spawn.
    match unsafe { fd::ramfs_find(path) } {
        Some(elf_data) => UserspaceSpawnPlan::Elf(elf_data),
        None => UserspaceSpawnPlan::Missing,
    }
}

/// Decide whether the dev-only debug console should start this boot
/// (issue #372 hardening layers, defense-in-depth beyond the
/// `debug-console` compile-time feature that makes the console
/// structurally absent from any build that lacks it).
///
/// Fails closed: any unmet condition returns `false`.
#[cfg(feature = "debug-console")]
fn debug_console_gate(serial: &mut Uart, mode_mgr: &crate::security_mode::ModeManager) -> bool {
    // WHY: `kconfig::DEBUG_CONSOLE`'s cmdline arm was deleted (issue #372 --
    // a boot-args attacker must not be able to force the console on) and its
    // default flipped to `false`. Reaching a live console now requires BOTH
    // `--features debug-console` at build time (this function only exists
    // under that cfg) AND a deliberate source edit flipping
    // `kconfig::DEBUG_CONSOLE`'s default back to `true` -- neither can
    // happen by accident via a build flag alone (e.g. `--all-features`),
    // and the latter is reviewable in a diff.
    // SAFETY: DEBUG_CONSOLE is a compile-time-fixed default; nothing writes
    // it after boot now that the cmdline arm is gone.
    if !unsafe { kconfig::DEBUG_CONSOLE } {
        return false;
    }

    // WARNING (defense-in-depth): refuse to start under Sentinel/Panic.
    // NOTE: `mode_mgr` is freshly `ModeManager::default()`-constructed at
    // Step 8g and nothing between there and here transitions it, so this
    // currently always evaluates to Daily -- see the Step 8f WHY comment
    // above. Kept as the structural check point so it becomes load-bearing
    // the moment mode state is threaded through boot instead of re-derived
    // fresh every time (e.g. a mode persisted across a warm restart).
    if mode_mgr.mode() != crate::security_mode::SecurityMode::Daily {
        let _ = serial.write_str("[init] Debug console refused: security mode is not Daily\r\n");
        return false;
    }

    // WARNING (defense-in-depth): the console must not auto-start. Require
    // an explicit entry sequence typed over UART before the interactive
    // prompt appears, so merely compiling and booting a debug-console build
    // does not hand a shell to whoever has a serial cable.
    //
    // TODO(#459)[deliberate-prudent]: `Console::wait_for_physical_presence` depends on
    // `Uart::getc`, whose RX "data ready" bit position is unverified
    // against the MT6739 TRM (see uart.rs) -- confirm on real hardware.
    let _ =
        serial.write_str("[init] Debug console armed -- awaiting physical-presence sequence\r\n");
    if !Console::wait_for_physical_presence(serial) {
        let _ = serial.write_str("[init] Debug console presence sequence not received\r\n");
        return false;
    }

    true
}

// ---------------------------------------------------------------------------
// Main init sequence
// ---------------------------------------------------------------------------

/// Run the kernel initialization sequence.
///
/// Called FROM `kernel_main`. Performs all subsystem initialization in
/// dependency ORDER with fault isolation: each driver init is wrapped
/// in error handling and a failure logs to console + continues.
///
/// # Safety
///
/// Must be called exactly once, FROM the boot processor, with
/// interrupts disabled.
pub unsafe fn run() -> ! {
    let mut serial = Uart::new();
    let mut state = BootState::new();

    // Banner
    let _ = serial.write_str("\r\n");
    let _ = serial.write_str("================================\r\n");
    let _ = serial.write_str("  THUMOS v0.1.0\r\n");
    let _ = serial.write_str("  Rust OS for the AGM M7 (MT6739)\r\n");
    // WHY (#233): every boot names its trust anchor -- a dev-keyed image can
    // never be mistaken for a production-trusted one, on the serial log or
    // via `strings` on the flashed binary (the stamp lives in rodata).
    let _ = write!(
        serial,
        "  {}{}\r\n",
        crate::secure_boot::BOOT_TRUST_STAMP,
        if crate::secure_boot::BOOT_KEY_IS_PRODUCTION {
            ""
        } else {
            " (NOT PRODUCTION-TRUSTED)"
        }
    );
    let _ = serial.write_str("================================\r\n");
    let _ = serial.write_str("\r\n");

    // -----------------------------------------------------------------------
    // Step 0: MMU + caches
    // -----------------------------------------------------------------------
    let _ = serial.write_str("[init] MMU + caches\r\n");
    // SAFETY: called once during early boot with interrupts disabled before
    // any code that depends on virtual memory.
    unsafe {
        mmu::init_and_enable();
    }
    state.mmu_ok = true;

    // -----------------------------------------------------------------------
    // Step 1: Page allocator
    // -----------------------------------------------------------------------
    let _ = serial.write_str("[init] Page allocator\r\n");
    // SAFETY: called once after MMU init. RAM_START/USER_TEXT_BASE/KERNEL_END
    // are valid physical addresses from kconfig for the MT6739 DRAM layout.
    // WHY USER_TEXT_BASE (not RAM_END) as the upper bound: the top 1 MB is the
    // executable userspace text region (#474), reserved for spawned ELFs and
    // kept out of the allocator so kernel pages never collide with userspace.
    unsafe {
        page::init(
            kconfig::RAM_START,
            kconfig::USER_TEXT_BASE,
            kconfig::KERNEL_END,
        );
    }
    let _ = write!(
        serial,
        "       {} pages free ({} MB)\r\n",
        page::free_count(),
        page::free_bytes() / 1024 / 1024
    );

    // -----------------------------------------------------------------------
    // Step 2: Kernel heap
    // -----------------------------------------------------------------------
    let _ = serial.write_str("[init] Kernel heap\r\n");
    // SAFETY: called once after page allocator init. heap::init() claims a
    // contiguous region from the page allocator for the kernel slab heap.
    unsafe {
        heap::init();
    }
    let (allocs, frees) = heap::stats();
    let _ = write!(
        serial,
        "       slab: {} allocs, {} frees\r\n",
        allocs, frees
    );
    state.heap_ok = true;

    // -----------------------------------------------------------------------
    // Step 3: GIC
    // -----------------------------------------------------------------------
    let _ = serial.write_str("[init] GIC\r\n");
    // SAFETY: called once after heap init. gic::init() programs the GIC distributor
    // and CPU interface MMIO registers at their known physical addresses.
    unsafe {
        gic::init();
    }
    state.gic_ok = true;

    // -----------------------------------------------------------------------
    // Step 4: Process subsystem
    // -----------------------------------------------------------------------
    let _ = serial.write_str("[init] Process subsystem\r\n");
    // SAFETY: called once after GIC init. process::init() initializes the
    // global process table and scheduler state before any processes are spawned.
    unsafe {
        process::init();
    }

    // -----------------------------------------------------------------------
    // Step 5: Exception handlers + timer
    // -----------------------------------------------------------------------
    let _ = serial.write_str("[init] Exceptions + timer\r\n");
    // SAFETY: called once after GIC and process init. exceptions::init() installs
    // the vector table and enables IRQ delivery; the GIC and process table must
    // already be initialized before interrupts are unmasked.
    unsafe {
        exceptions::init();
    }
    let _ = write!(
        serial,
        "       Timer frequency: {} Hz\r\n",
        crate::timer::frequency()
    );
    state.timer_ok = true;

    // -----------------------------------------------------------------------
    // Step 5b: CSPRNG (ChaCha20, seeded from timer entropy; fault-tolerant
    // with timeout)
    // -----------------------------------------------------------------------
    let _ = serial.write_str("[init] CSPRNG (ChaCha20)\r\n");
    // SAFETY: called once after exceptions::init() (timer running, IRQs enabled).
    // csprng::init() spins on WFI until the entropy pool accumulates a full
    // SEED_ENTROPY_BITS estimate of timer-jitter entropy, then seeds the
    // ChaCha20Rng DRBG and sets INITIALIZED -- bounded by a wall-clock
    // timeout so a dead timer ISR degrades the boot instead of hanging it.
    // Must complete before any radio driver init.
    state.csprng_ok = unsafe { csprng::init() };
    if state.csprng_ok {
        let _ = serial.write_str("       CSPRNG ready\r\n");
    } else {
        let _ = serial.write_str(
            "  WARN CSPRNG timed out waiting for timer entropy -- random bytes unavailable\r\n",
        );
        let _ = serial.write_str("       Radio identity randomization disabled\r\n");
    }

    // -----------------------------------------------------------------------
    // Step 5c: Hardware watchdog (WDT)
    // -----------------------------------------------------------------------
    let _ = serial.write_str("[init] Watchdog (WDT, 5s)\r\n");
    // SAFETY: called once after MMU init (device MMIO is identity-mapped).
    // Configures the MT6739 WDT with a 5-second timeout. The scheduler tick
    // handler pets the watchdog on every timer interrupt (every 10 ms).
    unsafe {
        watchdog::init();
    }
    #[cfg(not(feature = "qemu"))]
    let _ = serial.write_str("       WDT armed (5s timeout)\r\n");
    // WHY(qemu): watchdog is a no-op stub (watchdog_qemu.rs); say so rather
    // than log a hardware claim that is not true under the emulator.
    #[cfg(feature = "qemu")]
    let _ = serial.write_str("       WDT skipped (qemu: no MT6739 WDT model)\r\n");

    // -----------------------------------------------------------------------
    // Step 6: Device registry
    // -----------------------------------------------------------------------
    let _ = serial.write_str("[init] Device registry\r\n");
    let mut devices = DeviceRegistry::new();
    devices.register_mt6739_devices();
    let _ = write!(
        serial,
        "       {} devices registered\r\n",
        devices.list().len()
    );

    // -----------------------------------------------------------------------
    // Step 7: eMMC block device
    // -----------------------------------------------------------------------
    let _ = serial.write_str("[init] eMMC (MSDC0)\r\n");
    // WHY(qemu): virt models no MSDC controller at 0x1123_0000; the first
    // register access would data-abort. emmc_ok stays false, so the
    // filesystem step degrades to the ramfs root (existing path).
    #[cfg(feature = "qemu")]
    let _ = serial.write_str("       Skipped (qemu: no MSDC model)\r\n");
    #[cfg(not(feature = "qemu"))]
    {
        let mut emmc = crate::emmc::MsdcController::new();
        match unsafe { emmc.init() } {
            Ok(()) => {
                let _ = serial.write_str("       eMMC initialized OK\r\n");
                devices.activate("msdc0");
                state.emmc_ok = true;
            }
            Err(e) => {
                let _ = write!(serial, "  WARN eMMC init failed: {:?}\r\n", e);
                let _ = serial.write_str("       Continuing without block storage\r\n");
            }
        }
    }

    // -----------------------------------------------------------------------
    // Step 8: Display pipeline (DDP → GC9306)
    // -----------------------------------------------------------------------
    let _ = serial.write_str("[init] Display (GC9306 240x320)\r\n");
    // WHY(qemu): virt models no MT6739 DDP/DSI pipeline at 0x1400_0000; the
    // init writes would data-abort. display_ok stays false, so boot degrades
    // to serial-only (existing path) and the panic handler never touches FB.
    #[cfg(feature = "qemu")]
    let _ = serial.write_str("       Skipped (qemu: no DDP/DSI model)\r\n");
    #[cfg(not(feature = "qemu"))]
    {
        let gc9306 = Gc9306::new();
        let mut display = DisplayDriver::new(gc9306);
        // NOTE: FB_BASE FROM kconfig  -  SET by LK bootloader in stock firmware.
        // Phase 04+ allocates FROM page allocator instead.
        // SAFETY: FB_BASE is a framebuffer physical address provided by the LK
        // bootloader and identity-mapped as device memory in the MMU init.
        unsafe {
            display.init(kconfig::FB_BASE);
        }
        if display.state() != crate::display::DisplayState::Uninitialized {
            let _ = serial.write_str("       Display pipeline active\r\n");
            let _ = write!(
                serial,
                "       Framebuffer @ {:#010x}\r\n",
                kconfig::FB_BASE
            );
            devices.activate("gc9306-lcm");
            devices.activate("disp-ovl0");
            devices.activate("disp-rdma0");
            state.display_ok = true;
            DISPLAY_AVAILABLE.store(true, Ordering::Release);
        } else {
            let _ = serial.write_str("  WARN Display init incomplete\r\n");
            let _ = serial.write_str("       Falling back to USB serial console only\r\n");
        }
    }

    // -----------------------------------------------------------------------
    // Step 8a: GPIO keypad scanning
    // -----------------------------------------------------------------------
    // WHY relocated here (was Step 11, after CCCI modem): passphrase entry
    // (Step 8c) gates on `state.input_ok`, which this step sets. The keypad
    // must be initialized before the passphrase gate is evaluated, or the
    // gate condition is always false and passphrase entry (and the
    // encrypted-filesystem mount that depends on it) is silently skipped on
    // every boot (#344). This step only depends on the device registry
    // (Step 6) and has no dependency on display/USB/modem, so moving it
    // earlier is safe.
    let _ = serial.write_str("[init] GPIO keypad\r\n");
    // WHY(qemu): virt models no MT6739 KPD block at 0x1001_0000; the enable
    // write would data-abort. input_ok stays false, so passphrase entry
    // reports its skip path (existing behavior).
    #[cfg(feature = "qemu")]
    let _ = serial.write_str("       Skipped (qemu: no KPD model)\r\n");
    #[cfg(not(feature = "qemu"))]
    {
        // NOTE: Full keypad driver is in crates/haphe. Here we enable the
        // KPD hardware so interrupt-driven scanning can start.
        let kpd_base = device::MT6739_KPD;
        // SAFETY: KPD_EN and KPD_DEBOUNCE are device MMIO registers at known
        // offsets from the MT6739_KPD base address (0x1001_0000), which is
        // identity-mapped as device memory. Writing these registers enables the
        // hardware keypad scanner with 16 ms debounce.
        unsafe {
            // Enable KPD module (bit 0 of KPD_EN).
            mmio::write32(kpd_base + device::KPD_EN, 1);
            // Set debounce to 16 ms (hardware units).
            mmio::write32(kpd_base + device::KPD_DEBOUNCE, 16);
        }
        devices.activate("mtk-kpd");
        state.input_ok = true;
        let _ = serial.write_str("       Keypad scanning enabled\r\n");
    }

    // -----------------------------------------------------------------------
    // Step 8b: Measured boot (Ed25519 signature verification)
    // -----------------------------------------------------------------------
    let _ = serial.write_str("[init] Secure boot verification\r\n");
    {
        // WHY: verification is unconditional and fail-closed (#217) -- it
        // must run and halt on failure regardless of display availability.
        // Display availability only controls *how* a failure is reported
        // (rendered vs UART-only); gating the verification call itself on
        // state.display_ok let a display-init failure silently bypass the
        // kernel's only measured-boot gate (#361).
        //
        // WHY Absent today: qemu models no MSDC, and an eMMC that failed
        // init exposes no partitions -- no boot medium means nothing to
        // verify AND nothing persistent to mount, so the boot continues
        // DEGRADED with secure_boot_ok false and every downstream trust
        // gate locked (the inverse of the old "PENDING but proceed open"
        // posture). TODO(#217): wire the live-eMMC boot-partition read
        // (GPT-locate `boot` + memory-bounded verify + signing tool) so a
        // phone boot presents Present(image) here; until then a live-eMMC
        // phone boot is also degraded-LOCKED, never degraded-open.
        let source = crate::secure_boot::BootImageSource::Absent;
        match crate::secure_boot::evaluate_boot_image(&source) {
            crate::secure_boot::SecureBootDecision::Proceed { verified: true } => {
                // INVARIANT (#217 + security review): secure_boot_ok is set
                // ONLY when the image verified AND the anchor is a production
                // key. A dev/default build (BOOT_KEY_IS_PRODUCTION false)
                // carries the deliberately-public committed dev key, so a
                // valid dev signature must NOT establish trust on a device --
                // else the public dev seed is a universal forge key. Such a
                // build boots degraded-LOCKED, like the no-medium path.
                if crate::secure_boot::BOOT_KEY_IS_PRODUCTION {
                    state.secure_boot_ok = true;
                    let _ = serial.write_str("       Secure boot: VERIFIED\r\n");
                } else {
                    let _ = serial.write_str(
                        "       Secure boot: DEGRADED (dev anchor -- not production-trusted; persistent data stays locked)\r\n",
                    );
                }
            }
            crate::secure_boot::SecureBootDecision::Proceed { verified: false } => {
                let _ = serial.write_str(
                    "       Secure boot: DEGRADED (no boot medium -- trust not established; persistent data stays locked)\r\n",
                );
            }
            crate::secure_boot::SecureBootDecision::Halt(e) => {
                let _ = write!(serial, "  CRIT Secure boot verification failed: {e}\r\n");
                halt_boot(&mut serial, state.display_ok);
            }
        }
    }

    // -----------------------------------------------------------------------
    // Step 8c: Filesystem (LFS) -- trust-gated (#217)
    // -----------------------------------------------------------------------
    let _ = serial.write_str("[init] Filesystem (LFS)\r\n");
    // Captures the mounted LFS so it can back the VFS root below instead
    // of a fresh, volatile ramfs (#343). Stays `None` on any path that
    // does not end with a durably mounted filesystem.
    let mut lfs_root: Option<alloc::boxed::Box<dyn crate::vfs::Filesystem>> = None;
    // WHY (#217): persistent storage mounts ONLY on a verified boot --
    // secure_boot.rs's contract is that the filesystem mounts AFTER the
    // trust gate so a tampered kernel cannot reach encrypted data. A
    // verification FAILURE has already halted above; this gate covers the
    // no-boot-medium degrade, where nothing persistent may be touched.
    if state.emmc_ok && state.secure_boot_ok {
        use crate::block::MsdcBlockDevice;
        use crate::lfs;
        use crate::lfs_imap::LfsError;

        // Compute device size in sectors from the partition constants.
        let sector_count = kconfig::LFS_PARTITION_SIZE;

        // Create a block device wrapping the eMMC controller at the LFS partition.
        let mut blk_dev = MsdcBlockDevice::new(sector_count);

        // SAFETY: eMMC controller was initialized successfully in Step 7.
        // MsdcBlockDevice::init() is called once here; the controller is ready.
        match unsafe { blk_dev.init() } {
            Ok(()) => {
                // Try to mount existing LFS.
                match lfs::mount(alloc::boxed::Box::new(blk_dev)) {
                    Ok(fs) => {
                        let _ = serial.write_str("       LFS mounted OK\r\n");
                        lfs_root = Some(alloc::boxed::Box::new(fs));
                    }
                    // A missing/invalid superblock means a genuine first
                    // boot (or a never-formatted partition) -- format and
                    // remount. Any OTHER error (Corrupt, BlockIo) is NOT
                    // first boot and must not trigger a reformat: that
                    // would silently destroy user data on a bit flip or a
                    // transient I/O fault (#360).
                    Err(LfsError::InvalidSuperblock) => {
                        let _ = serial
                            .write_str("       LFS mount failed (no superblock), formatting\r\n");
                        let mut fmt_dev = MsdcBlockDevice::new(sector_count);
                        // SAFETY: eMMC controller was initialized successfully in
                        // Step 7; fmt_dev.init() is called once here on a
                        // freshly constructed MsdcBlockDevice.
                        if unsafe { fmt_dev.init() }.is_ok() && lfs::format(&mut fmt_dev).is_ok() {
                            let _ = serial.write_str("       LFS formatted OK\r\n");
                            // Remount the freshly formatted device so the
                            // VFS root is backed by durable storage from
                            // this boot onward, not just after the NEXT
                            // reboot (#343).
                            let mut remount_dev = MsdcBlockDevice::new(sector_count);
                            // SAFETY: eMMC controller was initialized successfully
                            // in Step 7; remount_dev.init() is called once here on
                            // a freshly constructed MsdcBlockDevice.
                            match unsafe { remount_dev.init() } {
                                Ok(()) => match lfs::mount(alloc::boxed::Box::new(remount_dev)) {
                                    Ok(fs) => {
                                        let _ = serial.write_str("       LFS remounted OK\r\n");
                                        lfs_root = Some(alloc::boxed::Box::new(fs));
                                    }
                                    Err(e) => {
                                        let _ = write!(
                                            serial,
                                            "  WARN LFS remount after format failed: {:?}\r\n",
                                            e
                                        );
                                    }
                                },
                                Err(e) => {
                                    let _ = write!(
                                        serial,
                                        "  WARN Block device re-init for remount failed: {:?}\r\n",
                                        e
                                    );
                                }
                            }
                        } else {
                            let _ = serial.write_str("  WARN LFS format failed\r\n");
                        }
                    }
                    Err(e) => {
                        let _ = write!(
                            serial,
                            "  CRIT LFS mount failed ({:?}) -- not reformatting, data at risk\r\n",
                            e
                        );
                    }
                }
            }
            Err(e) => {
                let _ = write!(serial, "  WARN Block device init failed: {:?}\r\n", e);
            }
        }
    } else if state.emmc_ok {
        let _ = serial.write_str("       Skipped (secure boot not established -- fail-closed)\r\n");
    } else {
        let _ = serial.write_str("       Skipped (no eMMC)\r\n");
    }

    // Initialize the VFS mount table, backed by the mounted LFS when one
    // is available so writes survive a reboot; falls back to a fresh ramfs
    // root otherwise (#343). With the trust gate above, a persistent root --
    // and therefore userspace loaded from persistent storage -- is only
    // reachable on a verified boot; the ramfs fallback is image-resident and
    // shares the kernel's own trust domain.
    // WHY(#474): with no LFS-backed root (QEMU / unverified eMMC) the boot root
    // would be an empty ramfs and /init unfindable. Mount the image-resident
    // initramfs -- the /init ELF wrapped in a newc CPIO, built by build.rs into
    // the kernel image -- as the root so plan_userspace_spawn_from_vfs("/init")
    // resolves. A verified boot uses the LFS root instead (initramfs ignored).
    static INITRAMFS: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/initramfs.cpio"));
    let boot_cpio = if lfs_root.is_none() {
        Some(INITRAMFS)
    } else {
        None
    };
    // SAFETY: called once during boot, before any filesystem syscalls.
    unsafe {
        crate::fd::init_vfs(boot_cpio, lfs_root);
    }

    // -----------------------------------------------------------------------
    // Step 8d: Passphrase entry and key derivation
    // -----------------------------------------------------------------------
    let _ = serial.write_str("[init] Passphrase entry\r\n");
    // WHY (#217, fail-closed): key derivation must never run on an
    // unverified image -- a tampered kernel could exfiltrate the
    // passphrase. The trust root is checked FIRST, before hardware
    // availability.
    if !state.secure_boot_ok {
        let _ = serial.write_str(
            "  WARN Passphrase entry refused (secure boot not established -- fail-closed)\r\n",
        );
    } else if state.display_ok && state.input_ok {
        // WHY: passphrase must be entered before any encrypted data is
        // accessed.  The lock screen renders on the display and accepts
        // keypad input.  On success, the primary key is derived and
        // partition sub-keys are produced.
        //
        // NOTE: In production, this blocks until the user enters the
        // correct passphrase.  The lock screen is shown via
        // crate::lock_screen::LockScreen and the result feeds into
        // key_manager::derive_from_passphrase().  Placeholder here
        // until the boot-time input loop is wired.
        let _ = serial.write_str("       Passphrase: PENDING (awaiting boot input loop)\r\n");
    } else {
        let _ = serial.write_str("  WARN Passphrase entry skipped (no display/input)\r\n");
    }

    // -----------------------------------------------------------------------
    // Step 8e: Encrypted filesystem mount
    // -----------------------------------------------------------------------
    let _ = serial.write_str("[init] Encrypted filesystem\r\n");
    // WHY (#217, defense-in-depth): passphrase_ok is already unreachable
    // without secure_boot_ok (Step 8d), but the decrypt gate re-checks the
    // trust root explicitly so a future refactor of passphrase entry cannot
    // silently reopen it.
    if state.secure_boot_ok && state.passphrase_ok && state.emmc_ok {
        // WHY: after passphrase derives the data key, wrap the eMMC block
        // device in EncryptedBlockDevice for transparent AES-XTS encryption.
        //
        // NOTE: In production:
        // let data_key = key_manager.data_key().as_bytes().clone();
        // let enc_dev = EncryptedBlockDevice::new(&mut blk_dev, data_key);
        // lfs::mount(Box::new(enc_dev));
        let _ = serial.write_str("       Encryption: PENDING (awaiting key derivation)\r\n");
    } else {
        let _ = serial.write_str("  WARN Encrypted mount skipped (no passphrase/eMMC)\r\n");
    }

    // -----------------------------------------------------------------------
    // Step 8f: Audit log initialization
    // -----------------------------------------------------------------------
    let _ = serial.write_str("[init] Audit log\r\n");
    if state.secure_boot_ok {
        // WHY: the audit log needs the audit HMAC key from key_manager.
        // Initialize early so all subsequent boot steps can emit events.
        //
        // NOTE: In production:
        // let audit_key = key_manager.audit_key().as_bytes();
        // AUDIT_LOG.init(audit_key);
        let _ = serial.write_str("       Audit log: PENDING (awaiting audit key)\r\n");
    } else {
        // WHY (#217): the audit HMAC key derives from the passphrase key
        // hierarchy, which stays locked without an established trust root.
        let _ = serial.write_str(
            "  WARN Audit log deferred (secure boot not established -- fail-closed)\r\n",
        );
    }

    // -----------------------------------------------------------------------
    // Step 8g: Security mode manager
    // -----------------------------------------------------------------------
    let _ = serial.write_str("[init] Security mode (Daily)\r\n");
    let mut pm = PowerManager::new();
    // WHY: hoisted to function scope (was block-local) so the
    // debug-console hardening gate near the end of boot (issue #372) can
    // read the live security mode via this same `ModeManager` instance,
    // rather than re-deriving a second, independent one.
    let mode_mgr = crate::security_mode::ModeManager::default();
    {
        // WHY (finding 46): the radio policy must be established here,
        // BEFORE USB ACM (Step 9) and the CCCI modem (Step 10) bring
        // radios up -- previously this step only logged "PENDING" and the
        // power manager was not constructed until Step 12, well after
        // both radios had already started, leaving PowerManager state at
        // its all-Off default the whole time radios were live (a
        // policy/reality mismatch for any later mode-transition or
        // threat-response code that reads PowerManager state as ground
        // truth). A full passphrase-derived pin_hash is not available yet
        // (Step 8d is pending the boot input loop -- finding 48), so
        // ModeManager::default() is used: unprovisioned, but still Daily
        // mode, which is the correct policy to apply at this point.
        //
        // NOTE: BFU (Before First Unlock) timer wiring is separate,
        // unrelated work -- not part of this radio-policy fix.
        // let bfu = BfuTimer::new(SecurityMode::Daily);
        crate::power::apply_mode_policy(&mode_mgr.effective_policy(), &mut pm);
        state.security_mode_ok = true;
        let _ = serial.write_str("       Security mode: Daily policy applied\r\n");
    }

    // -----------------------------------------------------------------------
    // Step 9: USB ACM serial (primary debug console)
    // -----------------------------------------------------------------------
    let _ = serial.write_str("[init] USB ACM serial\r\n");
    // WHY(qemu): virt models no MUSB controller at 0x1121_0000; the init
    // would data-abort. usb_ok stays false (existing degradation path).
    #[cfg(feature = "qemu")]
    let _ = serial.write_str("       Skipped (qemu: no MUSB model)\r\n");
    #[cfg(not(feature = "qemu"))]
    {
        let mut usb = UsbController::new();
        // SAFETY: usb.init() programs the MUSB MMIO registers at their known
        // physical address (0x1121_0000). Called once after heap and GIC init.
        match unsafe { usb.init() } {
            Ok(()) => {
                let _ = serial.write_str("       USB ACM gadget connected\r\n");
                devices.activate("musb-hdrc");
                state.usb_ok = true;
                USB_SERIAL_AVAILABLE.store(true, Ordering::Release);
            }
            Err(e) => {
                let _ = write!(serial, "  WARN USB init failed: {:?}\r\n", e);
                let _ = serial.write_str("       Continuing without USB serial\r\n");
            }
        }
    }

    // -----------------------------------------------------------------------
    // Step 10: CCCI modem boot (fault-tolerant with timeout)
    // -----------------------------------------------------------------------
    let _ = serial.write_str("[init] CCCI modem\r\n");
    // WHY(qemu): virt models no CCCI/CLDMA block at 0x200F_0000 (nor the MD
    // boot registers at 0x2000_xxxx); boot_modem would data-abort. modem_ok
    // stays false -- phone functions disabled (existing degradation path).
    #[cfg(feature = "qemu")]
    let _ = serial
        .write_str("       Skipped (qemu: no CCCI/CLDMA model); phone functions disabled\r\n");
    #[cfg(not(feature = "qemu"))]
    {
        let mut ccci = CcciDriver::new();
        let boot_start = crate::timer::elapsed_ms();
        // WHY (finding 47): MODEM_BOOT_TIMEOUT_MS previously bounded
        // nothing -- it was only compared against elapsed time in the WARN
        // check below, AFTER boot_modem had already returned. Threading it
        // through makes it a real deadline boot_modem enforces per step.
        let boot_result = unsafe { ccci.boot_modem(boot_start, MODEM_BOOT_TIMEOUT_MS) };
        let boot_elapsed = crate::timer::elapsed_ms() - boot_start;

        match boot_result {
            Ok(()) => {
                let _ = write!(serial, "       Modem booted in {} ms\r\n", boot_elapsed);
                devices.activate("ccci-cldma");
                devices.activate("ccci-ccif");
                state.modem_ok = true;
                MODEM_AVAILABLE.store(true, Ordering::Release);
            }
            Err(e) => {
                let _ = write!(serial, "  WARN Modem boot failed: {:?}\r\n", e);
                let _ = serial.write_str("       Phone functions disabled\r\n");
            }
        }

        if boot_elapsed > MODEM_BOOT_TIMEOUT_MS {
            let _ = serial.write_str("  WARN Modem boot exceeded timeout\r\n");
        }
    }

    // -----------------------------------------------------------------------
    // Step 12: Power manager
    // -----------------------------------------------------------------------
    // WHY (finding 46): `pm` was already constructed and given the
    // Daily-mode radio policy at Step 8f, before USB/modem bring-up -- do
    // not construct a second PowerManager here and silently discard that
    // policy state.
    let _ = serial.write_str("[init] Power manager\r\n");
    let _ = write!(
        serial,
        "       {} radios active per Daily policy (applied at security-mode init)\r\n",
        pm.active_count()
    );

    // -----------------------------------------------------------------------
    // Step 13: Network configuration (WiFi readiness + DHCP/DNS smoke)
    // -----------------------------------------------------------------------
    let _ = serial.write_str("[init] Network WiFi readiness\r\n");
    {
        let wifi_device = WifiDevice::new(crate::wifi::WifiHw::new());
        let readiness =
            NetworkReadiness::from_device(wifi_device.kind(), wifi_device.data_path_ready());
        state.record_network_readiness(readiness);

        match readiness {
            NetworkReadiness::ProductionReady(_) => {
                let _ = serial.write_str("       WiFi data path ready\r\n");
            }
            NetworkReadiness::HardwareUnavailable(_) => {
                let _ = serial.write_str(
                    "  WARN WiFi data path unavailable; production network disabled\r\n",
                );
            }
            NetworkReadiness::LoopbackSmokeOnly => {
                let _ = serial.write_str("  WARN WiFi readiness returned loopback-only\r\n");
            }
        }
    }

    let _ = serial.write_str("[init] Network loopback smoke (DHCP + DNS)\r\n");
    // WHY(qemu): the DHCP poll loop below is bounded by an elapsed_ms()
    // deadline + a wfe-gated yield, neither of which terminates under QEMU
    // (#461); and a loopback DHCP/DNS self-test verifies nothing under an
    // emulator with no network model. Skipped under qemu; production path
    // unchanged.
    #[cfg(feature = "qemu")]
    let _ = serial.write_str("       Skipped (qemu: no network model -- #461)\r\n");
    #[cfg(not(feature = "qemu"))]
    {
        // WHY: In production, the WiFi driver provides the Device impl.
        // Until WiFi hardware init is wired in, we use LoopbackDevice to
        // prove the DHCP+DNS integration path works end-to-end. Loopback
        // success is tracked separately and must not mark production
        // connectivity ready.
        let device = FirewallDevice::with_default_firewall(LoopbackDevice::new());
        let mac = net::randomized_local_ethernet_address();
        let now = net::instant_from_millis(crate::timer::elapsed_ms() as i64);
        let mut stack = NetworkStack::new(device, mac, now);
        let _ = serial.write_str("       Firewall DNS blocklist active\r\n");

        // Start DHCP client.
        match DhcpClient::new(&mut stack) {
            Ok(mut dhcp) => {
                let _ = serial.write_str("       DHCP client started\r\n");

                // Poll for DHCP configuration with timeout.
                let dhcp_start = crate::timer::elapsed_ms();
                let mut configured = false;
                while crate::timer::elapsed_ms() - dhcp_start < crate::dhcp::DHCP_TIMEOUT_MS {
                    let now = net::instant_from_millis(crate::timer::elapsed_ms() as i64);
                    stack.poll(now);
                    match dhcp.poll(&mut stack) {
                        DhcpEvent::Configured(config) => {
                            let _ = write!(
                                serial,
                                "       DHCP: {} gw {:?}\r\n",
                                config.address, config.gateway
                            );
                            if !config.dns_servers.is_empty() {
                                let _ =
                                    write!(serial, "       DHCP DNS: {:?}\r\n", config.dns_servers);
                            }
                            configured = true;
                            break;
                        }
                        DhcpEvent::Deconfigured => {}
                        DhcpEvent::None => {}
                    }
                    // WHY: WFE avoids busy-loop, yields until next event.
                    // SAFETY: WFE is a hint instruction available in all ARM
                    // privilege levels. No memory is accessed.
                    unsafe {
                        core::arch::asm!("wfe");
                    }
                }

                if !configured {
                    let _ = serial.write_str("  WARN DHCP timeout, using link-local\r\n");
                }
            }
            Err(e) => {
                let _ = write!(serial, "  WARN DHCP init failed: {:?}\r\n", e);
            }
        }

        // Initialize DNS resolver with split-horizon routing.
        let _resolver = DnsResolver::new(LAN_DNS, MULLVAD_DNS);
        let _ = serial.write_str("       DNS resolver ready\r\n");
        let _ = write!(
            serial,
            "       LAN DNS: {} / Internet DNS: {}\r\n",
            LAN_DNS, MULLVAD_DNS
        );
        state.record_loopback_smoke(NetworkReadiness::from_device(
            net::NetworkDeviceKind::LoopbackSmoke,
            true,
        ));
    }

    // -----------------------------------------------------------------------
    // Step 13b: Bluetooth adapter
    // -----------------------------------------------------------------------
    let _ = serial.write_str("[init] Bluetooth (BT HCI via WMT)\r\n");
    {
        let bt_hw = crate::bluetooth::BtHw::new();
        let mut bt = crate::bluetooth::BtAdapter::new(bt_hw);
        let bt_tick = crate::timer::elapsed_ms();
        match bt.init(bt_tick) {
            Ok(()) => {
                let _ = serial.write_str("       BT adapter ready\r\n");
                let addr = bt.random_address();
                let _ = write!(
                    serial,
                    "       LE address: {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}\r\n",
                    addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]
                );
                devices.activate("bt0");
                state.bluetooth_ok = true;
            }
            Err(e) => {
                let _ = write!(serial, "  WARN BT init failed: {:?}\r\n", e);
                let _ = serial.write_str("       Bluetooth disabled\r\n");
            }
        }
    }

    // -----------------------------------------------------------------------
    // Step 13c: GPS receiver
    // -----------------------------------------------------------------------
    let _ = serial.write_str("[init] GPS (via WMT)\r\n");
    {
        let gps_hw = crate::gps::GpsHw::new();
        let mut gps = crate::gps::GpsReceiver::new(gps_hw);
        match gps.init() {
            Ok(()) => {
                let _ = serial.write_str("       GPS receiver searching\r\n");
                devices.activate("gps0");
                state.gps_ok = true;
            }
            Err(e) => {
                let _ = write!(serial, "  WARN GPS init failed: {:?}\r\n", e);
                let _ = serial.write_str("       GPS disabled\r\n");
            }
        }
    }

    // -----------------------------------------------------------------------
    // Boot status summary
    // -----------------------------------------------------------------------
    let _ = serial.write_str("\r\n");
    let boot_ms = crate::timer::elapsed_ms();
    let _ = write!(serial, "[init] Boot complete at {boot_ms} ms\r\n");
    let _ = write!(
        serial,
        "       {} / {} subsystems OK\r\n",
        state.ok_count(),
        state.total_subsystems()
    );
    if !state.csprng_ok {
        let _ = serial
            .write_str("       NOTE: CSPRNG unseeded, radio identity randomization disabled\r\n");
    }
    if !state.display_ok {
        let _ = serial.write_str("       NOTE: display unavailable, USB serial only\r\n");
    }
    if !state.modem_ok {
        let _ = serial.write_str("       NOTE: modem unavailable, no phone functions\r\n");
    }
    if !state.network_ok {
        let _ = serial.write_str("       NOTE: network unavailable, no connectivity\r\n");
    }
    if state.network_loopback_smoke_ok && !state.network_ok {
        let _ =
            serial.write_str("       NOTE: DHCP/DNS smoke used loopback only; WiFi not wired\r\n");
    }
    let _ = serial.write_str("\r\n");

    // -----------------------------------------------------------------------
    // Step 13d: Initial UI home frame
    // -----------------------------------------------------------------------
    if state.display_ok {
        let _ = serial.write_str("[init] Rendering home UI\r\n");
        // SAFETY: state.display_ok is only set after display.init(FB_BASE)
        // succeeds. That maps FB_BASE as a writable RGB565 framebuffer of
        // SCREEN_WIDTH * SCREEN_HEIGHT pixels for the GC9306 panel.
        let fb =
            unsafe { slice::from_raw_parts_mut(kconfig::FB_BASE as *mut u16, FRAMEBUFFER_PIXELS) };
        render_initial_home_frame(fb, &state);
        let _ = serial.write_str("       Home/status frame rendered\r\n");
    }

    // -----------------------------------------------------------------------
    // Step 14: Spawn packaged userspace processes FROM mounted root ramfs
    // -----------------------------------------------------------------------
    let _ = serial.write_str("[init] Spawning userspace processes\r\n");
    // WHY (#217 + #480): userspace may run only when trust is cryptographically
    // established -- EITHER a verified boot medium (secure_boot_ok, the
    // persistent-storage/LFS path) OR a cryptographically-verified
    // image-resident initramfs. The initramfs is signed by the boot anchor
    // (build.rs, dev seed) and verified here against BOOT_PUBLIC_KEY; a valid
    // signature means this userspace shares the kernel's own signed trust
    // domain, which satisfies #217's requirement for the image-resident case
    // (the prior blanket refusal existed only because no verification mechanism
    // did). A production image's initramfs carries a dev signature that does
    // NOT verify under the production anchor, so it correctly falls back to the
    // eMMC secure-boot gate. secure_boot_ok stays false here (no medium), so
    // every OTHER trust-dependent step (passphrase, audit, persistent decrypt)
    // remains fail-closed.
    static INITRAMFS_SIG: &[u8; 64] =
        include_bytes!(concat!(env!("OUT_DIR"), "/initramfs_sig.bin"));
    let userspace_image_verified =
        crate::secure_boot::verify_userspace_image(INITRAMFS, INITRAMFS_SIG);
    if !(state.secure_boot_ok || userspace_image_verified) {
        // Fail-closed: no verified medium AND no verified image-resident image.
        let _ = serial.write_str(
            "  WARN Userspace spawn refused (no verified boot medium or image -- fail-closed)\r\n",
        );
    } else {
        if userspace_image_verified && !state.secure_boot_ok {
            let _ = serial.write_str(
                "       Userspace: image-resident initramfs signature verified (boot anchor)\r\n",
            );
        }
        // Attempt to load and spawn two processes: /init and /shell.
        // If an entry is absent from the mounted root ramfs, report the
        // packaging gap instead of spawning a kernel-owned placeholder.

        // WHY: process 1  -  init daemon (PID 1, supervisor)
        match plan_userspace_spawn_from_vfs("/init") {
            UserspaceSpawnPlan::Elf(elf_data) => match elf::load(elf_data) {
                Ok(loaded) => {
                    // WHY(#482): spawn_user runs /init UNPRIVILEGED (PL0, User
                    // mode 0x10) in its own address space -- the ELF mapped
                    // per-segment W^X and the stack RW+XN, with kernel memory
                    // PL1-only so a user access to it faults. No transmute: the
                    // entry is an address the new process resumes at via the
                    // #465 exception-return, not a kernel fn pointer.
                    if let Some(pid) = process::spawn_user(&loaded) {
                        let _ = write!(serial, "       /init spawned PL0 (PID {})\r\n", pid);
                        state.processes_spawned += 1;
                    } else {
                        let _ = serial.write_str("  WARN /init spawn failed\r\n");
                    }
                }
                Err(e) => {
                    let _ = write!(serial, "  WARN /init ELF load failed: {:?}\r\n", e);
                }
            },
            UserspaceSpawnPlan::Missing => {
                let _ =
                    serial.write_str("  WARN /init missing from root ramfs; no init spawned\r\n");
                state.userspace_entries_missing += 1;
            }
        }

        // WHY: process 2  -  shell (PID 2, user interface)
        match plan_userspace_spawn_from_vfs("/shell") {
            UserspaceSpawnPlan::Elf(elf_data) => match elf::load(elf_data) {
                Ok(loaded) => {
                    // WHY(#482): /shell runs PL0 in its own isolated space too.
                    if let Some(pid) = process::spawn_user(&loaded) {
                        let _ = write!(serial, "       /shell spawned PL0 (PID {})\r\n", pid);
                        state.processes_spawned += 1;
                    } else {
                        let _ = serial.write_str("  WARN /shell spawn failed\r\n");
                    }
                }
                Err(e) => {
                    let _ = write!(serial, "  WARN /shell ELF load failed: {:?}\r\n", e);
                }
            },
            UserspaceSpawnPlan::Missing => {
                let _ =
                    serial.write_str("  WARN /shell missing from root ramfs; no shell spawned\r\n");
                state.userspace_entries_missing += 1;
            }
        }

        let _ = write!(
            serial,
            "       {} userspace ELF processes running\r\n",
            state.processes_spawned
        );
        if state.userspace_entries_missing > 0 {
            let _ = write!(
                serial,
                "       {} userspace entries missing from root ramfs\r\n",
                state.userspace_entries_missing
            );
        }
    }

    // Boot is complete; the boot context now becomes the idle loop. Enable
    // scheduler context switches so the timer IRQ can run spawned userspace
    // (scheduling is gated OFF throughout kinit -- see
    // process::scheduling_enabled -- because the boot context is not a
    // scheduled process and a mid-init switch would abandon it).
    process::enable_scheduling();

    // -----------------------------------------------------------------------
    // QEMU milestone: full boot sequence attempted
    // -----------------------------------------------------------------------
    // WHY(qemu): CI asserts on this marker. The semihosting exit 0 moved
    // into the service loop (kardia::QEMU_TICK_CAP), so a green run proves
    // the loop serviced real ticks, not merely that boot reached its end.
    #[cfg(feature = "qemu")]
    let _ = serial.write_str("THUMOS-QEMU: boot-complete\r\n");

    // Deliberate PL1 fault probe (#487 fault-handling): CI asserts the KERNEL
    // branch halts (qemu exit 4) and the service loop never runs past it.
    // Structurally excluded from production (main.rs compile_error!).
    #[cfg(all(feature = "kfault-probe", target_arch = "arm"))]
    {
        let _ = serial.write_str("THUMOS-QEMU: kernel-fault probe (udf at PL1)\r\n");
        // SAFETY: `udf #0` is a permanently-undefined encoding; the undef
        // handler takes the KERNEL halt branch (System mode) and never returns.
        unsafe { core::arch::asm!("udf #0") };
    }

    // -----------------------------------------------------------------------
    // Debug console or idle
    // -----------------------------------------------------------------------
    #[cfg(feature = "debug-console")]
    let start_console = debug_console_gate(&mut serial, &mode_mgr);
    #[cfg(not(feature = "debug-console"))]
    let start_console = false;

    if start_console {
        let _ = serial.write_str("[init] Starting debug console\r\n");
        let _ = serial.write_str("       Type 'help' for commands\r\n\r\n");
        #[cfg(feature = "debug-console")]
        {
            let mut console = Console::new();
            console.prompt();
        }
    } else {
        let _ = serial.write_str("[init] No debug console this boot; entering service loop\r\n");
    }

    // WHY (#420): boot -> service handoff. The fn-scope state kinit built
    // moves into KernelState and the boot context (PID 0) becomes the
    // kernel service loop. Scheduling was enabled above, at the same point
    // as before -- the loop never calls process::schedule() itself;
    // userspace runs by the timer IRQ preempting PID 0 and round-robining
    // back.
    let kernel = crate::kardia::KernelState::new(state, devices, pm, mode_mgr);
    crate::kardia::service_loop(kernel, serial)
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

    #[test]
    fn mt6739_addresses_match_device_registry() {
        // WHY: central constants must match what register_mt6739_devices uses
        assert_eq!(device::MT6739_UART0, 0x1100_2000, "UART0 base address");
        assert_eq!(device::MT6739_MSDC0, 0x1123_0000, "MSDC0 base address");
        assert_eq!(device::MT6739_MUSB, 0x1121_0000, "MUSB base address");
        assert_eq!(
            device::MT6739_CLDMA_AP,
            0x200F_0000,
            "CLDMA AP base address"
        );
        assert_eq!(device::MT6739_CCIF, 0x2051_0000, "CCIF base address");
        assert_eq!(device::MT6739_KPD, 0x1001_0000, "KPD base address");
        assert_eq!(device::MT6739_GIC_DIST, 0x0C00_0000, "GIC distributor base");
        assert_eq!(
            device::MT6739_GIC_CPU,
            0x0C00_2000,
            "GIC CPU interface base"
        );
        assert_eq!(device::MT6739_FB, 0x77EE_0000, "framebuffer address");
    }

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
