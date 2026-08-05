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
//!
//! Pure planning logic (BootStep ordering, BootState, userspace spawn
//! planning) lives in `kinit_plan` (#528) so the host test build compiles and
//! runs its unit tests; this module keeps only the hardware-init-bearing
//! boot sequence.

extern crate alloc;

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
use crate::gic;
use crate::heap;
use crate::kconfig;
#[cfg(not(feature = "qemu"))]
use crate::kinit_plan::MODEM_BOOT_TIMEOUT_MS;
use crate::kinit_plan::{
    BootState, PANIC_RED_RGB565, UserspaceSpawnPlan, plan_userspace_spawn_from_vfs,
};
#[cfg(not(feature = "qemu"))]
use crate::mmio;
use crate::mmu;
use crate::net::{self, NetworkReadiness, WifiDevice};
// #403: the net stack is built on both targets (loop-persistent), so these are
// no longer qemu-gated. DhcpClient/DnsResolver stay gated -- used only in the
// non-qemu DHCP/DNS self-test below.
use crate::net::{FirewallDevice, LoopbackDevice, NetworkStack};
use crate::page;
use crate::power::PowerManager;
use crate::process;
use crate::uart::Uart;
use crate::uart::boot_log;
use crate::ui;
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
    expect(
        dead_code,
        reason = "set by the USB init step, which is qemu-gated (#463)"
    )
)]
pub(crate) static USB_SERIAL_AVAILABLE: AtomicBool = AtomicBool::new(false);

/// Modem CCCI link established.
#[cfg_attr(
    feature = "qemu",
    expect(
        dead_code,
        reason = "set by the CCCI init step, which is qemu-gated (#463)"
    )
)]
pub(crate) static MODEM_AVAILABLE: AtomicBool = AtomicBool::new(false);

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
    serial.log(" CRIT Boot halted: image trust could not be established (fail-closed)\r\n");
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

// ---------------------------------------------------------------------------
// Init helpers  -  each returns Ok/Err for fault isolation
// ---------------------------------------------------------------------------

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
        serial.log("[init] Debug console refused: security mode is not Daily\r\n");
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
    serial.log("[init] Debug console armed -- awaiting physical-presence sequence\r\n");
    if !Console::wait_for_physical_presence(serial) {
        serial.log("[init] Debug console presence sequence not received\r\n");
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
    serial.log("\r\n");
    serial.log("================================\r\n");
    serial.log(" THUMOS v0.1.0\r\n");
    serial.log(" Rust OS for the AGM M7 (MT6739)\r\n");
    // WHY (#233): every boot names its trust anchor -- a dev-keyed image can
    // never be mistaken for a production-trusted one, on the serial log or
    // via `strings` on the flashed binary (the stamp lives in rodata).
    boot_log!(
        serial,
        " {}{}\r\n",
        crate::secure_boot::BOOT_TRUST_STAMP,
        if crate::secure_boot::BOOT_KEY_IS_PRODUCTION {
            ""
        } else {
            " (NOT PRODUCTION-TRUSTED)"
        }
    );
    serial.log("================================\r\n");
    serial.log("\r\n");

    // -----------------------------------------------------------------------
    // Step 0: MMU + caches
    // -----------------------------------------------------------------------
    serial.log("[init] MMU + caches\r\n");
    // SAFETY: called once during early boot with interrupts disabled before
    // any code that depends on virtual memory.
    unsafe {
        mmu::init_and_enable();
    }
    state.mmu_ok = true;

    // -----------------------------------------------------------------------
    // Step 1: Page allocator
    // -----------------------------------------------------------------------
    serial.log("[init] Page allocator\r\n");
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
    boot_log!(
        serial,
        " {} pages free ({} MB)\r\n",
        page::free_count(),
        page::free_bytes() / 1024 / 1024
    );

    // -----------------------------------------------------------------------
    // Step 2: Kernel heap
    // -----------------------------------------------------------------------
    serial.log("[init] Kernel heap\r\n");
    // SAFETY: called once after page allocator init. heap::init() claims a
    // contiguous region from the page allocator for the kernel slab heap.
    unsafe {
        heap::init();
    }
    let (allocs, frees) = heap::stats();
    boot_log!(serial, " slab: {} allocs, {} frees\r\n", allocs, frees);
    state.heap_ok = true;

    // -----------------------------------------------------------------------
    // Step 3: GIC
    // -----------------------------------------------------------------------
    serial.log("[init] GIC\r\n");
    // SAFETY: called once after heap init. gic::init() programs the GIC distributor
    // and CPU interface MMIO registers at their known physical addresses.
    unsafe {
        gic::init();
    }
    state.gic_ok = true;

    // -----------------------------------------------------------------------
    // Step 4: Process subsystem
    // -----------------------------------------------------------------------
    serial.log("[init] Process subsystem\r\n");
    // SAFETY: called once after GIC init. process::init() initializes the
    // global process table and scheduler state before any processes are spawned.
    unsafe {
        process::init();
    }

    // -----------------------------------------------------------------------
    // Step 5: Exception handlers + timer
    // -----------------------------------------------------------------------
    serial.log("[init] Exceptions + timer\r\n");
    // SAFETY: called once after GIC and process init. exceptions::init() installs
    // the vector table and enables IRQ delivery; the GIC and process table must
    // already be initialized before interrupts are unmasked.
    unsafe {
        exceptions::init();
    }
    boot_log!(
        serial,
        " Timer frequency: {} Hz\r\n",
        crate::timer::frequency()
    );
    state.timer_ok = true;

    // ------------------------------------------------------------------
    // #461 clock witness (permanent): CNTPCT/CNTFRQ and elapsed_ms are
    // healthy under qemu-virt — measured freq=62.5 MHz, counter advancing,
    // elapsed_ms advancing across a 10-tick interval (2026-08-04, the
    // "clock broken under QEMU" premise was refuted by this measurement).
    // Assert it every boot so a counter/frequency regression reds the
    // witness instead of silently hanging the wait loops that consume
    // elapsed_ms (csprng deadline, DHCP smoke, #506's wiring).
    // ------------------------------------------------------------------
    #[cfg(feature = "qemu")]
    {
        let freq_a = crate::timer::frequency();
        let el_a = crate::timer::elapsed_ms();
        let tick_a = crate::exceptions::ticks();
        while crate::exceptions::ticks() < tick_a + 10 {}
        let el_b = crate::timer::elapsed_ms();
        if freq_a == 0 || el_b <= el_a {
            boot_log!(
                serial,
                " FAIL timer: elapsed_ms not advancing under qemu (freq={}, {} ms -> {} ms) -- the #461 class is BACK\r\n",
                freq_a, el_a, el_b
            );
            state.timer_ok = false;
        } else {
            boot_log!(
                serial,
                "kardia: timer elapsed_ms=advancing freq={} ({} ms -> {} ms)\r\n",
                freq_a, el_a, el_b
            );
        }
    }

    // -----------------------------------------------------------------------
    // Step 5b: CSPRNG (ChaCha20, seeded from timer entropy; fault-tolerant
    // with timeout)
    // -----------------------------------------------------------------------
    serial.log("[init] CSPRNG (ChaCha20)\r\n");
    // SAFETY: called once after exceptions::init() (timer running, IRQs enabled).
    // csprng::init() spins on WFI until the entropy pool accumulates a full
    // SEED_ENTROPY_BITS estimate of timer-jitter entropy, then seeds the
    // ChaCha20Rng DRBG and sets INITIALIZED -- bounded by a wall-clock
    // timeout so a dead timer ISR degrades the boot instead of hanging it.
    // Must complete before any radio driver init.
    state.csprng_ok = unsafe { csprng::init() };
    if state.csprng_ok {
        serial.log(" CSPRNG ready\r\n");
    } else {
        serial.log(
            " WARN CSPRNG timed out waiting for timer entropy -- random bytes unavailable\r\n",
        );
        serial.log(" Radio identity randomization disabled\r\n");
    }

    // -----------------------------------------------------------------------
    // Step 5c: Hardware watchdog (WDT)
    // -----------------------------------------------------------------------
    serial.log("[init] Watchdog (WDT, 5s)\r\n");
    // SAFETY: called once after MMU init (device MMIO is identity-mapped).
    // Configures the MT6739 WDT with a 5-second timeout. The scheduler tick
    // handler pets the watchdog on every timer interrupt (every 10 ms).
    unsafe {
        watchdog::init();
    }
    #[cfg(not(feature = "qemu"))]
    serial.log(" WDT armed (5s timeout)\r\n");
    // WHY(qemu): watchdog is a no-op stub (watchdog_qemu.rs); say so rather
    // than log a hardware claim that is not true under the emulator.
    #[cfg(feature = "qemu")]
    serial.log(" WDT skipped (qemu: no MT6739 WDT model)\r\n");

    // -----------------------------------------------------------------------
    // Step 6: Device registry
    // -----------------------------------------------------------------------
    serial.log("[init] Device registry\r\n");
    let mut devices = DeviceRegistry::new();
    devices.register_mt6739_devices();
    boot_log!(serial, " {} devices registered\r\n", devices.list().len());

    // -----------------------------------------------------------------------
    // Step 7: eMMC block device
    // -----------------------------------------------------------------------
    serial.log("[init] eMMC (MSDC0)\r\n");
    // WHY(qemu): virt models no MSDC controller at 0x1123_0000; the first
    // register access would data-abort. emmc_ok stays false, so the
    // filesystem step degrades to the ramfs root (existing path).
    #[cfg(feature = "qemu")]
    serial.log(" Skipped (qemu: no MSDC model)\r\n");
    #[cfg(not(feature = "qemu"))]
    {
        let mut emmc = crate::emmc::MsdcController::new();
        match unsafe { emmc.init() } {
            Ok(()) => {
                serial.log(" eMMC initialized OK\r\n");
                devices.activate("msdc0");
                state.emmc_ok = true;
            }
            Err(e) => {
                boot_log!(serial, " WARN eMMC init failed: {:?}\r\n", e);
                serial.log(" Continuing without block storage\r\n");
            }
        }
    }

    // -----------------------------------------------------------------------
    // Step 8: Display pipeline (DDP → GC9306)
    // -----------------------------------------------------------------------
    serial.log("[init] Display (GC9306 240x320)\r\n");
    // WHY(qemu): virt models no MT6739 DDP/DSI pipeline at 0x1400_0000; the
    // init writes would data-abort. display_ok stays false, so boot degrades
    // to serial-only (existing path) and the panic handler never touches FB.
    #[cfg(feature = "qemu")]
    serial.log(" Skipped (qemu: no DDP/DSI model)\r\n");
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
            serial.log(" Display pipeline active\r\n");
            boot_log!(serial, " Framebuffer @ {:#010x}\r\n", kconfig::FB_BASE);
            devices.activate("gc9306-lcm");
            devices.activate("disp-ovl0");
            devices.activate("disp-rdma0");
            state.display_ok = true;
            DISPLAY_AVAILABLE.store(true, Ordering::Release);
        } else {
            serial.log(" WARN Display init incomplete\r\n");
            serial.log(" Falling back to USB serial console only\r\n");
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
    serial.log("[init] GPIO keypad\r\n");
    // WHY(qemu): virt models no MT6739 KPD block at 0x1001_0000; the enable
    // write would data-abort. input_ok stays false, so passphrase entry
    // reports its skip path (existing behavior).
    #[cfg(feature = "qemu")]
    serial.log(" Skipped (qemu: no KPD model)\r\n");
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
        serial.log(" Keypad scanning enabled\r\n");
    }

    // -----------------------------------------------------------------------
    // Step 8b: Measured boot (Ed25519 signature verification)
    // -----------------------------------------------------------------------
    serial.log("[init] Secure boot verification\r\n");
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
                    serial.log(" Secure boot: VERIFIED\r\n");
                } else {
                    serial.log( " Secure boot: DEGRADED (dev anchor -- not production-trusted; persistent data stays locked)\r\n", );
                }
            }
            crate::secure_boot::SecureBootDecision::Proceed { verified: false } => {
                serial.log( " Secure boot: DEGRADED (no boot medium -- trust not established; persistent data stays locked)\r\n", );
            }
            crate::secure_boot::SecureBootDecision::Halt(e) => {
                boot_log!(serial, " CRIT Secure boot verification failed: {e}\r\n");
                halt_boot(&mut serial, state.display_ok);
            }
        }
    }

    // -----------------------------------------------------------------------
    // Step 8c: Filesystem (LFS) -- trust-gated (#217)
    // -----------------------------------------------------------------------
    serial.log("[init] Filesystem (LFS)\r\n");
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
                        serial.log(" LFS mounted OK\r\n");
                        lfs_root = Some(alloc::boxed::Box::new(fs));
                    }
                    // A missing/invalid superblock means a genuine first
                    // boot (or a never-formatted partition) -- format and
                    // remount. Any OTHER error (Corrupt, BlockIo) is NOT
                    // first boot and must not trigger a reformat: that
                    // would silently destroy user data on a bit flip or a
                    // transient I/O fault (#360).
                    Err(LfsError::InvalidSuperblock) => {
                        serial.log(" LFS mount failed (no superblock), formatting\r\n");
                        let mut fmt_dev = MsdcBlockDevice::new(sector_count);
                        // SAFETY: eMMC controller was initialized successfully in
                        // Step 7; fmt_dev.init() is called once here on a
                        // freshly constructed MsdcBlockDevice.
                        if unsafe { fmt_dev.init() }.is_ok() && lfs::format(&mut fmt_dev).is_ok() {
                            serial.log(" LFS formatted OK\r\n");
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
                                        serial.log(" LFS remounted OK\r\n");
                                        lfs_root = Some(alloc::boxed::Box::new(fs));
                                    }
                                    Err(e) => {
                                        boot_log!(
                                            serial,
                                            " WARN LFS remount after format failed: {:?}\r\n",
                                            e
                                        );
                                    }
                                },
                                Err(e) => {
                                    boot_log!(
                                        serial,
                                        " WARN Block device re-init for remount failed: {:?}\r\n",
                                        e
                                    );
                                }
                            }
                        } else {
                            serial.log(" WARN LFS format failed\r\n");
                        }
                    }
                    Err(e) => {
                        boot_log!(
                            serial,
                            " CRIT LFS mount failed ({:?}) -- not reformatting, data at risk\r\n",
                            e
                        );
                    }
                }
            }
            Err(e) => {
                boot_log!(serial, " WARN Block device init failed: {:?}\r\n", e);
            }
        }
    } else if state.emmc_ok {
        serial.log(" Skipped (secure boot not established -- fail-closed)\r\n");
    } else {
        serial.log(" Skipped (no eMMC)\r\n");
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
    serial.log("[init] Passphrase entry\r\n");
    // WHY (#217, fail-closed): key derivation must never run on an
    // unverified image -- a tampered kernel could exfiltrate the
    // passphrase. The trust root is checked FIRST, before hardware
    // availability.
    if !state.secure_boot_ok {
        serial
            .log(" WARN Passphrase entry refused (secure boot not established -- fail-closed)\r\n");
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
        serial.log(" Passphrase: PENDING (awaiting boot input loop)\r\n");
    } else {
        serial.log(" WARN Passphrase entry skipped (no display/input)\r\n");
    }

    // -----------------------------------------------------------------------
    // Step 8e: Encrypted filesystem mount
    // -----------------------------------------------------------------------
    serial.log("[init] Encrypted filesystem\r\n");
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
        serial.log(" Encryption: PENDING (awaiting key derivation)\r\n");
    } else {
        serial.log(" WARN Encrypted mount skipped (no passphrase/eMMC)\r\n");
    }

    // -----------------------------------------------------------------------
    // Step 8f: Audit log initialization
    // -----------------------------------------------------------------------
    serial.log("[init] Audit log\r\n");
    if state.secure_boot_ok {
        // WHY: the audit log needs the audit HMAC key from key_manager.
        // Initialize early so all subsequent boot steps can emit events.
        //
        // NOTE: In production:
        // let audit_key = key_manager.audit_key().as_bytes();
        // AUDIT_LOG.init(audit_key);
        serial.log(" Audit log: PENDING (awaiting audit key)\r\n");
    } else {
        // WHY (#217): the audit HMAC key derives from the passphrase key
        // hierarchy, which stays locked without an established trust root.
        serial.log(" WARN Audit log deferred (secure boot not established -- fail-closed)\r\n");
    }

    // -----------------------------------------------------------------------
    // Step 8g: Security mode manager
    // -----------------------------------------------------------------------
    serial.log("[init] Security mode (Daily)\r\n");
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
        serial.log(" Security mode: Daily policy applied\r\n");
    }

    // -----------------------------------------------------------------------
    // Step 9: USB ACM serial (primary debug console)
    // -----------------------------------------------------------------------
    serial.log("[init] USB ACM serial\r\n");
    // WHY(qemu): virt models no MUSB controller at 0x1121_0000; the init
    // would data-abort. usb_ok stays false (existing degradation path).
    #[cfg(feature = "qemu")]
    serial.log(" Skipped (qemu: no MUSB model)\r\n");
    #[cfg(not(feature = "qemu"))]
    {
        let mut usb = UsbController::new();
        // SAFETY: usb.init() programs the MUSB MMIO registers at their known
        // physical address (0x1121_0000). Called once after heap and GIC init.
        match unsafe { usb.init() } {
            Ok(()) => {
                serial.log(" USB ACM gadget connected\r\n");
                devices.activate("musb-hdrc");
                state.usb_ok = true;
                USB_SERIAL_AVAILABLE.store(true, Ordering::Release);
            }
            Err(e) => {
                boot_log!(serial, " WARN USB init failed: {:?}\r\n", e);
                serial.log(" Continuing without USB serial\r\n");
            }
        }
    }

    // -----------------------------------------------------------------------
    // Step 10: CCCI modem boot (fault-tolerant with timeout)
    // -----------------------------------------------------------------------
    serial.log("[init] CCCI modem\r\n");
    // WHY(qemu): virt models no CCCI/CLDMA block at 0x200F_0000 (nor the MD
    // boot registers at 0x2000_xxxx); boot_modem would data-abort. modem_ok
    // stays false -- phone functions disabled (existing degradation path).
    #[cfg(feature = "qemu")]
    serial.log(" Skipped (qemu: no CCCI/CLDMA model); phone functions disabled\r\n");
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
                boot_log!(serial, " Modem booted in {} ms\r\n", boot_elapsed);
                devices.activate("ccci-cldma");
                devices.activate("ccci-ccif");
                state.modem_ok = true;
                MODEM_AVAILABLE.store(true, Ordering::Release);
            }
            Err(e) => {
                boot_log!(serial, " WARN Modem boot failed: {:?}\r\n", e);
                serial.log(" Phone functions disabled\r\n");
            }
        }

        if boot_elapsed > MODEM_BOOT_TIMEOUT_MS {
            serial.log(" WARN Modem boot exceeded timeout\r\n");
        }
    }

    // -----------------------------------------------------------------------
    // Step 12: Power manager
    // -----------------------------------------------------------------------
    // WHY (finding 46): `pm` was already constructed and given the
    // Daily-mode radio policy at Step 8f, before USB/modem bring-up -- do
    // not construct a second PowerManager here and silently discard that
    // policy state.
    serial.log("[init] Power manager\r\n");
    boot_log!(
        serial,
        " {} radios active per Daily policy (applied at security-mode init)\r\n",
        pm.active_count()
    );

    // -----------------------------------------------------------------------
    // Step 13: Network configuration (WiFi readiness + DHCP/DNS smoke)
    // -----------------------------------------------------------------------
    serial.log("[init] Network WiFi readiness\r\n");
    {
        let wifi_device = WifiDevice::new(crate::wifi::WifiHw::new());
        let readiness =
            NetworkReadiness::from_device(wifi_device.kind(), wifi_device.data_path_ready());
        state.record_network_readiness(readiness);

        match readiness {
            NetworkReadiness::ProductionReady(_) => {
                serial.log(" WiFi data path ready\r\n");
            }
            NetworkReadiness::HardwareUnavailable(_) => {
                serial.log(" WARN WiFi data path unavailable; production network disabled\r\n");
            }
            NetworkReadiness::LoopbackSmokeOnly => {
                serial.log(" WARN WiFi readiness returned loopback-only\r\n");
            }
        }
    }

    serial.log("[init] Network loopback smoke (DHCP + DNS)\r\n");
    // #403: the net stack is now LOOP-PERSISTENT -- built here on BOTH targets
    // and handed to KernelState, so its firewall is the single loop-owned
    // instance (runtime policy + audit at the drop-site). Until WiFi hardware
    // init lands (#129), the device is LoopbackDevice; it must stay
    // synchronous/polled to satisfy the KernelState IRQ-safety invariant.
    // #461: smoltcp time comes from the IRQ tick counter (exceptions::uptime_ms),
    // never CNTPCT (timer::elapsed_ms) -- it advances under qemu-virt and must be
    // monotonic across the stack's whole life (this boot smoke -> service loop).
    //
    // `mut` is used by the DHCP smoke (non-qemu) + the service loop after the
    // move; under qemu the smoke is skipped, so the binding is move-only here.
    #[cfg_attr(feature = "qemu", allow(unused_mut))]
    let mut net = {
        let device = FirewallDevice::with_default_firewall(LoopbackDevice::new());
        let mac = net::randomized_local_ethernet_address();
        let now = net::instant_from_millis(crate::exceptions::uptime_ms() as i64);
        NetworkStack::new(device, mac, now)
    };
    // WHY(qemu): a loopback DHCP/DNS self-test verifies nothing under an
    // emulator with no network model, so the smoke stays skipped — but on
    // semantics, not fear of a hang: the #461 measurement (Step 5 witness)
    // proved CNTPCT/CNTFRQ/elapsed_ms healthy under virt, and the wait
    // primitive below is now WFI (see the comment in the loop), so the
    // deadline + yield shape terminates correctly on either target.
    #[cfg(feature = "qemu")]
    serial.log(" Skipped (qemu: no network model -- #461)\r\n");
    #[cfg(not(feature = "qemu"))]
    {
        serial.log(" Firewall DNS blocklist active\r\n");

        // Start DHCP client on the persistent stack.
        match DhcpClient::new(&mut net) {
            Ok(mut dhcp) => {
                serial.log(" DHCP client started\r\n");

                // Poll for DHCP configuration with timeout. The DEADLINE stays
                // on elapsed_ms (a device-only wall-clock bound, not fed to
                // smoltcp); the smoltcp timestamp uses uptime_ms (#461, and
                // monotone with the service loop).
                let dhcp_start = crate::timer::elapsed_ms();
                let mut configured = false;
                while crate::timer::elapsed_ms() - dhcp_start < crate::dhcp::DHCP_TIMEOUT_MS {
                    let now = net::instant_from_millis(crate::exceptions::uptime_ms() as i64);
                    net.poll(now);
                    match dhcp.poll(&mut net) {
                        DhcpEvent::Configured(config) => {
                            boot_log!(
                                serial,
                                " DHCP: {} gw {:?}\r\n",
                                config.address,
                                config.gateway
                            );
                            if !config.dns_servers.is_empty() {
                                boot_log!(serial, " DHCP DNS: {:?}\r\n", config.dns_servers);
                            }
                            configured = true;
                            break;
                        }
                        DhcpEvent::Deconfigured => {}
                        DhcpEvent::None => {}
                    }
                    // WHY: WFI yields until the next interrupt (the timer
                    // tick). WFE was the wrong primitive here: with no SEV
                    // issuer and SEVONPEND unset, a WFE entered with a clear
                    // event register sleeps forever — the latent hang the
                    // #461 qemu gate was compensating for. Measured
                    // 2026-08-04 under qemu-virt: the clock itself is healthy
                    // (CNTFRQ=62.5 MHz, elapsed_ms advancing, witness in
                    // Step 5), so the bounded deadline above terminates
                    // correctly once the wait primitive is WFI.
                    // SAFETY: WFI is a hint instruction available in all ARM
                    // privilege levels. No memory is accessed.
                    unsafe {
                        core::arch::asm!("wfi");
                    }
                }

                if !configured {
                    serial.log(" WARN DHCP timeout, using link-local\r\n");
                }
            }
            Err(e) => {
                boot_log!(serial, " WARN DHCP init failed: {:?}\r\n", e);
            }
        }

        // Initialize DNS resolver with split-horizon routing.
        let _resolver = DnsResolver::new(LAN_DNS, MULLVAD_DNS);
        serial.log(" DNS resolver ready\r\n");
        boot_log!(
            serial,
            " LAN DNS: {} / Internet DNS: {}\r\n",
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
    serial.log("[init] Bluetooth (BT HCI via WMT)\r\n");
    {
        let bt_hw = crate::bluetooth::BtHw::new();
        let mut bt = crate::bluetooth::BtAdapter::new(bt_hw);
        let bt_tick = crate::timer::elapsed_ms();
        match bt.init(bt_tick) {
            Ok(()) => {
                serial.log(" BT adapter ready\r\n");
                let addr = bt.random_address();
                boot_log!(
                    serial,
                    " LE address: {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}\r\n",
                    addr[0],
                    addr[1],
                    addr[2],
                    addr[3],
                    addr[4],
                    addr[5]
                );
                devices.activate("bt0");
                state.bluetooth_ok = true;
            }
            Err(e) => {
                boot_log!(serial, " WARN BT init failed: {:?}\r\n", e);
                serial.log(" Bluetooth disabled\r\n");
            }
        }
    }

    // -----------------------------------------------------------------------
    // Step 13c: GPS receiver
    // -----------------------------------------------------------------------
    serial.log("[init] GPS (via WMT)\r\n");
    {
        let gps_hw = crate::gps::GpsHw::new();
        let mut gps = crate::gps::GpsReceiver::new(gps_hw);
        match gps.init() {
            Ok(()) => {
                serial.log(" GPS receiver searching\r\n");
                devices.activate("gps0");
                state.gps_ok = true;
            }
            Err(e) => {
                boot_log!(serial, " WARN GPS init failed: {:?}\r\n", e);
                serial.log(" GPS disabled\r\n");
            }
        }
    }

    // -----------------------------------------------------------------------
    // Boot status summary
    // -----------------------------------------------------------------------
    serial.log("\r\n");
    let boot_ms = crate::timer::elapsed_ms();
    boot_log!(serial, "[init] Boot complete at {boot_ms} ms\r\n");
    boot_log!(
        serial,
        " {} / {} subsystems OK\r\n",
        state.ok_count(),
        state.total_subsystems()
    );
    if !state.csprng_ok {
        serial.log(" NOTE: CSPRNG unseeded, radio identity randomization disabled\r\n");
    }
    if !state.display_ok {
        serial.log(" NOTE: display unavailable, USB serial only\r\n");
    }
    if !state.modem_ok {
        serial.log(" NOTE: modem unavailable, no phone functions\r\n");
    }
    if !state.network_ok {
        serial.log(" NOTE: network unavailable, no connectivity\r\n");
    }
    if state.network_loopback_smoke_ok && !state.network_ok {
        serial.log(" NOTE: DHCP/DNS smoke used loopback only; WiFi not wired\r\n");
    }
    serial.log("\r\n");

    // WHY (#400): the home frame is no longer rendered once here at boot -- the
    // kardia service loop owns rendering now (render_if_dirty paints the initial
    // frame at loop entry, then on every dirty tick), through the same
    // screen-dispatch path the running UI uses.

    // -----------------------------------------------------------------------
    // Step 14: Spawn packaged userspace processes FROM mounted root ramfs
    // -----------------------------------------------------------------------
    serial.log("[init] Spawning userspace processes\r\n");
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
        serial.log(
            " WARN Userspace spawn refused (no verified boot medium or image -- fail-closed)\r\n",
        );
    } else {
        if userspace_image_verified && !state.secure_boot_ok {
            serial.log(" Userspace: image-resident initramfs signature verified (boot anchor)\r\n");
        }
        // Attempt to load and spawn two processes: /init and /shell.
        // If an entry is absent from the mounted root ramfs, report the
        // packaging gap instead of spawning a kernel-owned placeholder.

        // WHY: process 1  -  init daemon (PID 1, supervisor)
        match plan_userspace_spawn_from_vfs("/init") {
            UserspaceSpawnPlan::Elf(elf_data) => {
                // SAFETY (#502): kinit runs under the kernel L1 (proc0's table,
                // scheduling disabled), satisfying load_confined's TTBR0
                // precondition -- the image write lands in identity DRAM.
                match unsafe {
                    elf::load_confined(elf_data, kconfig::USER_TEXT_BASE, kconfig::RAM_END)
                } {
                    Ok(loaded) => {
                        // WHY(#482): spawn_user runs /init UNPRIVILEGED (PL0, User
                        // mode 0x10) in its own address space -- the ELF mapped
                        // per-segment W^X and the stack RW+XN, with kernel memory
                        // PL1-only so a user access to it faults. No transmute: the
                        // entry is an address the new process resumes at via the
                        // #465 exception-return, not a kernel fn pointer.
                        if let Some(pid) = process::spawn_user(&loaded) {
                            boot_log!(serial, " /init spawned PL0 (PID {})\r\n", pid);
                            state.processes_spawned += 1;
                        } else {
                            serial.log(" WARN /init spawn failed\r\n");
                        }
                    }
                    Err(e) => {
                        boot_log!(serial, " WARN /init ELF load failed: {:?}\r\n", e);
                    }
                }
            }
            UserspaceSpawnPlan::Missing => {
                serial.log(" WARN /init missing from root ramfs; no init spawned\r\n");
                state.userspace_entries_missing += 1;
            }
        }

        // WHY: process 2  -  shell (PID 2, user interface)
        match plan_userspace_spawn_from_vfs("/shell") {
            UserspaceSpawnPlan::Elf(elf_data) => {
                // SAFETY (#502): kinit runs under the kernel L1 (proc0's table,
                // scheduling disabled), satisfying load_confined's TTBR0
                // precondition -- the image write lands in identity DRAM.
                match unsafe {
                    elf::load_confined(elf_data, kconfig::USER_TEXT_BASE, kconfig::RAM_END)
                } {
                    Ok(loaded) => {
                        // WHY(#482): /shell runs PL0 in its own isolated space too.
                        if let Some(pid) = process::spawn_user(&loaded) {
                            boot_log!(serial, " /shell spawned PL0 (PID {})\r\n", pid);
                            state.processes_spawned += 1;
                            // #492: /shell is a SUPERVISED service -- if it
                            // CRASHES, PID 0 relaunches it (rate-limited). A clean
                            // exit never triggers a restart: the supervisor keys on
                            // fault reports, not on Dead state. /init is
                            // deliberately NOT supervised -- the isolation-probe
                            // variants fault it on purpose and CI asserts exactly
                            // one USERFAULT, which supervising it would crash-loop.
                            crate::supervisor::register("/shell", pid);
                        } else {
                            serial.log(" WARN /shell spawn failed\r\n");
                        }
                    }
                    Err(e) => {
                        boot_log!(serial, " WARN /shell ELF load failed: {:?}\r\n", e);
                    }
                }
            }
            UserspaceSpawnPlan::Missing => {
                serial.log(" WARN /shell missing from root ramfs; no shell spawned\r\n");
                state.userspace_entries_missing += 1;
            }
        }

        // #492: the crash-loop witness, spawned + SUPERVISED only under the
        // crashloop-probe feature (never in a normal boot). /crasher data-aborts
        // on every launch, so PID 0's restart policy becomes observable in QEMU:
        // restart up to the limit, then give up. This has to live in kinit rather
        // than a THUMOS_INIT_VARIANT -- a variant only selects /init's `_start`
        // body, whereas supervised registration is kinit behaviour.
        #[cfg(feature = "crashloop-probe")]
        if let UserspaceSpawnPlan::Elf(elf_data) = plan_userspace_spawn_from_vfs("/crasher") {
            // SAFETY (#502): kinit runs under the kernel L1 (proc0's table,
            // scheduling disabled), satisfying load_confined's TTBR0 precondition.
            match unsafe { elf::load_confined(elf_data, kconfig::USER_TEXT_BASE, kconfig::RAM_END) }
            {
                Ok(loaded) => {
                    if let Some(pid) = process::spawn_user(&loaded) {
                        boot_log!(serial, " /crasher spawned PL0 (PID {})\r\n", pid);
                        state.processes_spawned += 1;
                        crate::supervisor::register("/crasher", pid);
                    } else {
                        serial.log(" WARN /crasher spawn failed\r\n");
                    }
                }
                Err(e) => {
                    boot_log!(serial, " WARN /crasher ELF load failed: {:?}\r\n", e);
                }
            }
        }

        boot_log!(
            serial,
            " {} userspace ELF processes running\r\n",
            state.processes_spawned
        );
        if state.userspace_entries_missing > 0 {
            boot_log!(
                serial,
                " {} userspace entries missing from root ramfs\r\n",
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
    serial.log("THUMOS-QEMU: boot-complete\r\n");

    // Deliberate PL1 fault probe (#487 fault-handling): CI asserts the KERNEL
    // branch halts (qemu exit 4) and the service loop never runs past it.
    // Structurally excluded from production (main.rs compile_error!).
    #[cfg(all(feature = "kfault-probe", target_arch = "arm"))]
    {
        serial.log("THUMOS-QEMU: kernel-fault probe (udf at PL1)\r\n");
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
        serial.log("[init] Starting debug console\r\n");
        serial.log(" Type 'help' for commands\r\n\r\n");
        #[cfg(feature = "debug-console")]
        {
            let mut console = Console::new();
            console.prompt();
        }
    } else {
        serial.log("[init] No debug console this boot; entering service loop\r\n");
    }

    // WHY (#420): boot -> service handoff. The fn-scope state kinit built
    // moves into KernelState and the boot context (PID 0) becomes the
    // kernel service loop. Scheduling was enabled above, at the same point
    // as before -- the loop never calls process::schedule() itself;
    // userspace runs by the timer IRQ preempting PID 0 and round-robining
    // back.
    // #400: resolve the render target the service loop paints each frame into.
    // On device this is the hardware framebuffer FB_BASE (only when the display
    // came up). Under qemu, where -machine virt models no display, a synthetic
    // heap buffer -- so render_if_dirty actually runs and the UI surface is
    // CI-verifiable in emulation (the render path was dead under qemu before).
    #[cfg(feature = "qemu")]
    let fb: Option<&'static mut [u16]> = Some(alloc::vec![0u16; FRAMEBUFFER_PIXELS].leak());
    #[cfg(not(feature = "qemu"))]
    let fb: Option<&'static mut [u16]> = if state.display_ok {
        // SAFETY: display_ok is set only after display.init(FB_BASE) mapped
        // FB_BASE as a writable RGB565 framebuffer of FRAMEBUFFER_PIXELS pixels.
        Some(unsafe {
            core::slice::from_raw_parts_mut(kconfig::FB_BASE as *mut u16, FRAMEBUFFER_PIXELS)
        })
    } else {
        None
    };
    // #398: bring up the AT/call telephony stack on the modem transport. Under
    // qemu a seeded mock runs the real 10-step init + state machines; on device
    // the CCCI transport (init succeeds only once its wire protocol lands --
    // hardware-gated) -- the WIRING is present either way.
    #[cfg(feature = "qemu")]
    let telephony = {
        let mut t = crate::telephony::Telephony::new(
            crate::telephony_mock::MockModemTransport::seeded_for_boot(),
        );
        match t.initialize() {
            Ok(()) => {
                boot_log!(
                    serial,
                    "kardia: modem ready state={:?}\r\n",
                    t.modem_state()
                );
                Some(t)
            }
            Err(e) => {
                boot_log!(serial, "kardia: modem init FAILED {e:?}\r\n");
                None
            }
        }
    };
    #[cfg(not(feature = "qemu"))]
    let telephony = if state.modem_ok {
        let mut t = crate::telephony::Telephony::new(crate::telephony::CcciModemTransport::new());
        t.initialize().ok().map(|()| t)
    } else {
        None
    };
    // #403: interim SESSION audit key -- CSPRNG-seeded, volatile (RAM-only,
    // zeroized on drop). The persistent, passphrase-derived audit key (Step 8f)
    // stays PENDING/deferred; this key derives nothing and unlocks nothing -- it
    // only gives the loop-owned firewall audit chain HMAC integrity for THIS
    // boot. Fails closed: an all-zero key (CSPRNG unavailable) makes log_event
    // return NoKey, so no audit entry is forged without integrity.
    let mut audit_key = [0u8; crate::security::KEY_SIZE];
    if state.csprng_ok {
        crate::csprng::kernel_random_bytes(&mut audit_key).ok();
        serial.log(" Audit trail: interim session key (persistent key PENDING #217)\r\n");
    }
    let kernel = crate::kardia::KernelState::new(
        state, devices, pm, mode_mgr, fb, telephony, net, audit_key,
    );
    crate::kardia::service_loop(kernel, serial)
}
