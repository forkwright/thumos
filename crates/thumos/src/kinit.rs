//! Kernel init  -  the first code that runs after kernel boot.
//!
//! Initializes all kernel subsystems in dependency ORDER, then loads and
//! starts userspace daemons FROM the ramfs. Acts as a supervisor per the
//! Hubris model: each driver init is fault-isolated, logged, and skippable.
//!
//! Boot ORDER:
//! MMU → page alloc → heap → GIC → process → exceptions/timer → CSPRNG → devices →
//! eMMC → display → USB serial → CCCI modem → GPIO keypad → power → userspace.

extern crate alloc;

use core::fmt::Write;
use core::slice;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::ccci::CcciDriver;
use crate::console::Console;
use crate::csprng;
use crate::device::{self, DeviceRegistry};
use crate::dhcp::{DhcpClient, DhcpEvent};
use crate::display::{DisplayDriver, Gc9306};
use crate::dns::{DnsResolver, LAN_DNS, MULLVAD_DNS};
use crate::elf;
use crate::exceptions;
use crate::fd;
use crate::gic;
use crate::heap;
use crate::kconfig;
use crate::mmio;
use crate::mmu;
use crate::net::{
    self, FirewallDevice, LoopbackDevice, NetworkReadiness, NetworkStack, WifiDevice,
};
use crate::page;
use crate::power::PowerManager;
use crate::process;
#[cfg(test)]
use crate::ramfs::RamFs;
use crate::screen_home::{HomeScreen, HomeScreenState, OperatingMode};
use crate::status_bar::{KernelStatusBar, StatusBarState};
use crate::uart::Uart;
use crate::ui::{self, UiManager};
use crate::usb::UsbController;
use crate::watchdog;

// ---------------------------------------------------------------------------
// Global state  -  read by panic handler and other subsystems
// ---------------------------------------------------------------------------

/// Display pipeline initialized and framebuffer writable.
pub(crate) static DISPLAY_AVAILABLE: AtomicBool = AtomicBool::new(false);

/// USB ACM serial link established.
pub(crate) static USB_SERIAL_AVAILABLE: AtomicBool = AtomicBool::new(false);

/// Modem CCCI link established.
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
    /// Filesystem (LFS on eMMC).
    Filesystem = 8,
    /// Display pipeline (DDP).
    Display = 9,
    /// Measured boot signature verification (Ed25519).
    SecureBoot = 10,
    /// Passphrase entry and key derivation.
    Passphrase = 11,
    /// Encrypted filesystem mount.
    Encryption = 12,
    /// Tamper-evident audit log initialization.
    AuditLog = 13,
    /// Security mode manager (Daily/Sentinel/Panic).
    SecurityMode = 14,
    /// USB ACM serial console.
    UsbSerial = 15,
    /// CCCI modem link.
    CcciModem = 16,
    /// GPIO keypad scanning.
    GpioInput = 17,
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
pub(crate) struct BootState { // kanon:ignore RUST/struct-too-many-fields -- one bool per boot subsystem; grouping would obscure the per-subsystem degradation model

    pub(crate) mmu_ok: bool,
    pub(crate) heap_ok: bool,
    pub(crate) gic_ok: bool,
    pub(crate) timer_ok: bool,
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
            network_readiness: NetworkReadiness::HardwareUnavailable(
                net::NetworkDeviceKind::Wifi,
            ),
            bluetooth_ok: false,
            gps_ok: false,
            processes_spawned: 0,
            userspace_entries_missing: 0,
        }
    }

    /// Count of successfully initialized subsystems.
    pub(crate) const fn ok_count(&self) -> u8 {
        let mut n = 0;
        if self.mmu_ok {
            n += 1;
        }
        if self.heap_ok {
            n += 1;
        }
        if self.gic_ok {
            n += 1;
        }
        if self.timer_ok {
            n += 1;
        }
        if self.emmc_ok {
            n += 1;
        }
        if self.display_ok {
            n += 1;
        }
        if self.secure_boot_ok {
            n += 1;
        }
        if self.passphrase_ok {
            n += 1;
        }
        if self.encryption_ok {
            n += 1;
        }
        if self.audit_ok {
            n += 1;
        }
        if self.security_mode_ok {
            n += 1;
        }
        if self.usb_ok {
            n += 1;
        }
        if self.modem_ok {
            n += 1;
        }
        if self.input_ok {
            n += 1;
        }
        if self.network_ok {
            n += 1;
        }
        if self.bluetooth_ok {
            n += 1;
        }
        if self.gps_ok {
            n += 1;
        }
        n
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
const MODEM_BOOT_TIMEOUT_MS: u64 = 10_000;

/// Framebuffer RGB565 colour: solid red (panic indicator).
#[expect(
    dead_code,
    reason = "used by tests; main.rs panic handler uses literal"
)]
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
    let _ = serial
        .write_str("================================\r\n");
    let _ = serial.write_str("  THUMOS v0.1.0\r\n");
    let _ = serial.write_str("  Sovereign OS for MT6739\r\n");
    let _ = serial
        .write_str("================================\r\n");
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
    // SAFETY: called once after MMU init. RAM_START/RAM_END/KERNEL_END are valid
    // physical addresses from kconfig for the MT6739 DRAM layout.
    unsafe {
        page::init(kconfig::RAM_START, kconfig::RAM_END, kconfig::KERNEL_END);
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
    let _ = write!(serial, "       slab: {} allocs, {} frees\r\n", allocs, frees);
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
    // Step 5b: CSPRNG (ChaCha20, seeded from timer entropy)
    // -----------------------------------------------------------------------
    let _ = serial.write_str("[init] CSPRNG (ChaCha20)\r\n");
    // SAFETY: called once after exceptions::init() (timer running, IRQs enabled).
    // csprng::init() spins on WFI until the entropy pool accumulates a full
    // SEED_ENTROPY_BITS estimate of timer-jitter entropy, then seeds the
    // ChaCha20Rng DRBG and sets INITIALIZED. Must complete before any radio
    // driver init.
    unsafe {
        csprng::init();
    }
    let _ = serial.write_str("       CSPRNG ready\r\n");

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
    let _ = serial.write_str("       WDT armed (5s timeout)\r\n");

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
                let _ = serial
                    .write_str("       Continuing without block storage\r\n");
            }
        }
    }

    // -----------------------------------------------------------------------
    // Step 7b: Filesystem
    // -----------------------------------------------------------------------
    let _ = serial.write_str("[init] Filesystem (LFS)\r\n");
    if state.emmc_ok {
        use crate::block::MsdcBlockDevice;
        use crate::lfs;

        // Compute device size in sectors from the partition constants.
        let sector_count = kconfig::LFS_PARTITION_SIZE;

        // Create a block device wrapping the eMMC controller at the LFS partition.
        let mut blk_dev = MsdcBlockDevice::new(sector_count);

        // SAFETY: eMMC controller was initialized successfully in Step 7.
        // MsdcBlockDevice::init() is called once here; the controller is ready.
        match unsafe { blk_dev.init() } {
            Ok(()) => {
                // Try to mount existing LFS.
                let mount_result = lfs::mount(alloc::boxed::Box::new(blk_dev));
                match mount_result {
                    Ok(_fs) => {
                        let _ = serial.write_str("       LFS mounted OK\r\n");
                    }
                    Err(_) => {
                        let _ = serial.write_str("       LFS mount failed, formatting\r\n");
                        // First boot: format and try again.
                        let mut fmt_dev = MsdcBlockDevice::new(sector_count);
                        if unsafe { fmt_dev.init() }.is_ok() {
                            if lfs::format(&mut fmt_dev).is_ok() {
                                let _ = serial.write_str("       LFS formatted OK\r\n");
                            } else {
                                let _ = serial.write_str("  WARN LFS format failed\r\n");
                            }
                        }
                    }
                }
            }
            Err(e) => {
                let _ = write!(serial, "  WARN Block device init failed: {:?}\r\n", e);
            }
        }

        // Initialize the VFS mount table.
        // SAFETY: called once during boot, before any filesystem syscalls.
        unsafe {
            crate::fd::init_vfs(None);
        }
    } else {
        let _ = serial.write_str("       Skipped (no eMMC)\r\n");
        // Initialize VFS with ramfs-only fallback.
        // SAFETY: called once during boot, before any filesystem syscalls.
        unsafe {
            crate::fd::init_vfs(None);
        }
    }

    // -----------------------------------------------------------------------
    // Step 8: Display pipeline (DDP → GC9306)
    // -----------------------------------------------------------------------
    let _ = serial.write_str("[init] Display (GC9306 240x320)\r\n");
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
            let _ = serial
                .write_str("       Falling back to USB serial console only\r\n");
        }
    }

    // -----------------------------------------------------------------------
    // Step 8b: Measured boot (Ed25519 signature verification)
    // -----------------------------------------------------------------------
    let _ = serial.write_str("[init] Secure boot verification\r\n");
    if state.display_ok {
        // WHY: verify kernel image signature AFTER display (so errors
        // are visible) but BEFORE filesystem mount (so a tampered kernel
        // cannot access encrypted data).
        //
        // NOTE: In production, the kernel image is read from a known
        // partition offset.  Here we log the verification step and mark
        // it as pending.  The actual image read + verify_combined_image()
        // call is wired when the boot partition layout is finalized.
        //
        // let image = read_kernel_image_from_partition();
        // match crate::secure_boot::verify_combined_image(&image) {
        //     Ok(()) => { ... }
        //     Err(e) => { display error, halt }
        // }
        let _ = serial.write_str("       Secure boot: PENDING (awaiting boot partition)\r\n");
    } else {
        let _ = serial.write_str("  WARN Secure boot skipped (no display for error)\r\n");
    }

    // -----------------------------------------------------------------------
    // Step 8c: Passphrase entry and key derivation
    // -----------------------------------------------------------------------
    let _ = serial.write_str("[init] Passphrase entry\r\n");
    if state.display_ok && state.input_ok {
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
    // Step 8d: Encrypted filesystem mount
    // -----------------------------------------------------------------------
    let _ = serial.write_str("[init] Encrypted filesystem\r\n");
    if state.passphrase_ok && state.emmc_ok {
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
    // Step 8e: Audit log initialization
    // -----------------------------------------------------------------------
    let _ = serial.write_str("[init] Audit log\r\n");
    {
        // WHY: the audit log needs the audit HMAC key from key_manager.
        // Initialize early so all subsequent boot steps can emit events.
        //
        // NOTE: In production:
        // let audit_key = key_manager.audit_key().as_bytes();
        // AUDIT_LOG.init(audit_key);
        let _ = serial.write_str("       Audit log: PENDING (awaiting audit key)\r\n");
    }

    // -----------------------------------------------------------------------
    // Step 8f: Security mode manager
    // -----------------------------------------------------------------------
    let _ = serial.write_str("[init] Security mode (Daily)\r\n");
    {
        // WHY: start in Daily mode with BFU timer running.  Mode manager
        // controls radio policy, scan intervals, and key lifecycle.
        //
        // NOTE: In production:
        // let mode_mgr = ModeManager::new(pin_hash);
        // let bfu = BfuTimer::new(SecurityMode::Daily);
        // apply_mode_policy(&mode_mgr.effective_policy(), &mut pm);
        let _ = serial.write_str("       Security mode: PENDING (Daily policy not applied)\r\n");
    }

    // -----------------------------------------------------------------------
    // Step 9: USB ACM serial (primary debug console)
    // -----------------------------------------------------------------------
    let _ = serial.write_str("[init] USB ACM serial\r\n");
    {
        let mut usb = UsbController::new();
        // SAFETY: usb.init() programs the MUSB MMIO registers at their known
        // physical address (0x1121_0000). Called once after heap and GIC init.
        unsafe {
            usb.init();
        }
        let _ = serial.write_str("       USB ACM gadget connected\r\n");
        devices.activate("musb-hdrc");
        state.usb_ok = true;
        USB_SERIAL_AVAILABLE.store(true, Ordering::Release);
    }

    // -----------------------------------------------------------------------
    // Step 10: CCCI modem boot (fault-tolerant with timeout)
    // -----------------------------------------------------------------------
    let _ = serial.write_str("[init] CCCI modem\r\n");
    {
        let mut ccci = CcciDriver::new();
        let boot_start = crate::timer::elapsed_ms();
        let boot_result = unsafe { ccci.boot_modem(boot_start) };
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
            let _ = serial
                .write_str("  WARN Modem boot exceeded timeout\r\n");
        }
    }

    // -----------------------------------------------------------------------
    // Step 11: GPIO keypad scanning
    // -----------------------------------------------------------------------
    let _ = serial.write_str("[init] GPIO keypad\r\n");
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
    // Step 12: Power manager
    // -----------------------------------------------------------------------
    let _ = serial.write_str("[init] Power manager\r\n");
    let _pm = PowerManager::new();
    let _ = serial
        .write_str("       All radios OFF (silent mode)\r\n");

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
                while crate::timer::elapsed_ms() - dhcp_start
                    < crate::dhcp::DHCP_TIMEOUT_MS
                {
                    let now =
                        net::instant_from_millis(crate::timer::elapsed_ms() as i64);
                    stack.poll(now);
                    match dhcp.poll(&mut stack) {
                        DhcpEvent::Configured(config) => {
                            let _ = write!(
                                serial,
                                "       DHCP: {} gw {:?}\r\n",
                                config.address,
                                config.gateway
                            );
                            if !config.dns_servers.is_empty() {
                                let _ = write!(
                                    serial,
                                    "       DHCP DNS: {:?}\r\n",
                                    config.dns_servers
                                );
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
                    let _ = serial
                        .write_str("  WARN DHCP timeout, using link-local\r\n");
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
            LAN_DNS,
            MULLVAD_DNS
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
    let _ = write!(
        serial,
        "[init] Boot complete at {} ms\r\n",
        crate::timer::elapsed_ms()
    );
    let _ = write!(serial, "       {} / 17 subsystems OK\r\n", state.ok_count());
    if !state.display_ok {
        let _ = serial
            .write_str("       NOTE: display unavailable, USB serial only\r\n");
    }
    if !state.modem_ok {
        let _ = serial
            .write_str("       NOTE: modem unavailable, no phone functions\r\n");
    }
    if !state.network_ok {
        let _ = serial
            .write_str("       NOTE: network unavailable, no connectivity\r\n");
    }
    if state.network_loopback_smoke_ok && !state.network_ok {
        let _ = serial.write_str(
            "       NOTE: DHCP/DNS smoke used loopback only; WiFi not wired\r\n",
        );
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
    let _ = serial
        .write_str("[init] Spawning userspace processes\r\n");
    {
        // Attempt to load and spawn two processes: /init and /shell.
        // If an entry is absent from the mounted root ramfs, report the
        // packaging gap instead of spawning a kernel-owned placeholder.

        // WHY: process 1  -  init daemon (PID 1, supervisor)
        match plan_userspace_spawn_from_vfs("/init") {
            UserspaceSpawnPlan::Elf(elf_data) => match elf::load(elf_data) {
                Ok(loaded) => {
                    if let Some(pid) = process::spawn(
                        // SAFETY: loaded.entry is the ELF entry point validated
                        // by elf::load() to be within a loaded PT_LOAD segment.
                        // The identity-mapped physical address is a callable
                        // no-return function per the ELF ABI contract.
                        unsafe { core::mem::transmute::<usize, fn() -> !>(loaded.entry) },
                    ) {
                        let _ = write!(serial, "       /init spawned (PID {})\r\n", pid);
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
                let _ = serial
                    .write_str("  WARN /init missing from root ramfs; no init spawned\r\n");
                state.userspace_entries_missing += 1;
            }
        }

        // WHY: process 2  -  shell (PID 2, user interface)
        match plan_userspace_spawn_from_vfs("/shell") {
            UserspaceSpawnPlan::Elf(elf_data) => match elf::load(elf_data) {
                Ok(loaded) => {
                    if let Some(pid) = process::spawn(
                        // SAFETY: loaded.entry is the ELF entry point validated
                        // by elf::load() to be within a loaded PT_LOAD segment.
                        // The identity-mapped physical address is a callable
                        // no-return function per the ELF ABI contract.
                        unsafe { core::mem::transmute::<usize, fn() -> !>(loaded.entry) },
                    ) {
                        let _ = write!(serial, "       /shell spawned (PID {})\r\n", pid);
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
                let _ = serial
                    .write_str("  WARN /shell missing from root ramfs; no shell spawned\r\n");
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

    // -----------------------------------------------------------------------
    // Debug console or idle
    // -----------------------------------------------------------------------
    // SAFETY: DEBUG_CONSOLE is a compile-time or boot-time constant; reading it
    // is safe here as it is never written after boot.
    if unsafe { kconfig::DEBUG_CONSOLE } {
        let _ = serial.write_str("[init] Starting debug console\r\n");
        let _ = serial
            .write_str("       Type 'help' for commands\r\n\r\n");
        let mut console = Console::new();
        console.prompt();

        // NOTE: in a real implementation, UART RX would be interrupt-driven.
        // For now, we poll. This gets replaced when the UART driver has
        // proper RX interrupt support.
        loop {
            // SAFETY: WFE is a hint instruction available in all ARM privilege levels.
            // No memory is accessed; the CPU enters a low-power wait state.
            unsafe {
                core::arch::asm!("wfe");
            }
        }
    } else {
        // No console  -  just idle
        loop {
            // SAFETY: WFE is a hint instruction available in all ARM privilege levels.
            // No memory is accessed; the CPU enters a low-power wait state.
            unsafe {
                core::arch::asm!("wfe");
            }
        }
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
        assert!(!state.emmc_ok, "initial emmc_ok must be false");
        assert!(!state.display_ok, "initial display_ok must be false");
        assert!(!state.secure_boot_ok, "initial secure_boot_ok must be false");
        assert!(!state.passphrase_ok, "initial passphrase_ok must be false");
        assert!(!state.encryption_ok, "initial encryption_ok must be false");
        assert!(!state.audit_ok, "initial audit_ok must be false");
        assert!(!state.security_mode_ok, "initial security_mode_ok must be false");
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
        assert_eq!(state.ok_count(), 17, "all 17 subsystems OK");
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
        // WHY: modem failure must not prevent keypad FROM working.
        let step_modem = BootStep::CcciModem as u8;
        let step_input = BootStep::GpioInput as u8;
        assert!(
            step_input > step_modem,
            "GPIO init comes after modem in sequence"
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
        // WHY: the five security steps must be consecutive with no gaps.
        assert_eq!(BootStep::SecureBoot as u8, 10);
        assert_eq!(BootStep::Passphrase as u8, 11);
        assert_eq!(BootStep::Encryption as u8, 12);
        assert_eq!(BootStep::AuditLog as u8, 13);
        assert_eq!(BootStep::SecurityMode as u8, 14);
    }
}
