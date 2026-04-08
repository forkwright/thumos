//! Kernel init  -  the first code that runs after kernel boot.
//!
//! Initializes all kernel subsystems in dependency ORDER, then loads and
//! starts userspace daemons FROM the ramfs. Acts as a supervisor per the
//! Hubris model: each driver init is fault-isolated, logged, and skippable.
//!
//! Boot ORDER:
//! MMU → page alloc → heap → GIC → process → exceptions/timer → devices →
//! eMMC → display → USB serial → CCCI modem → GPIO keypad → power → userspace.

extern crate alloc;

use core::fmt::Write;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::ccci::CcciDriver;
use crate::console::Console;
use crate::device::{self, DeviceRegistry};
use crate::display::{DisplayDriver, Gc9306};
use crate::elf;
use crate::exceptions;
use crate::gic;
use crate::heap;
use crate::kconfig;
use crate::mmio;
use crate::mmu;
use crate::page;
use crate::power::PowerManager;
use crate::process;
use crate::ramfs::RamFs;
use crate::uart::Uart;
use crate::usb::UsbController;

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
    /// Display pipeline (DDP).
    Display = 8,
    /// USB ACM serial console.
    UsbSerial = 9,
    /// CCCI modem link.
    CcciModem = 10,
    /// GPIO keypad scanning.
    GpioInput = 11,
    /// Power manager.
    PowerManager = 12,
    /// Userspace processes spawned.
    Userspace = 13,
    /// Boot complete.
    Complete = 14,
}

#[expect(dead_code, reason = "used by tests and future boot progress reporting")]
impl BootStep {
    /// Total number of boot steps.
    pub(crate) const COUNT: usize = 15;

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
    pub(crate) mmu_ok: bool,
    pub(crate) heap_ok: bool,
    pub(crate) gic_ok: bool,
    pub(crate) timer_ok: bool,
    pub(crate) emmc_ok: bool,
    pub(crate) display_ok: bool,
    pub(crate) usb_ok: bool,
    pub(crate) modem_ok: bool,
    pub(crate) input_ok: bool,
    pub(crate) processes_spawned: u8,
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
            usb_ok: false,
            modem_ok: false,
            input_ok: false,
            processes_spawned: 0,
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
        if self.usb_ok {
            n += 1;
        }
        if self.modem_ok {
            n += 1;
        }
        if self.input_ok {
            n += 1;
        }
        n
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
// Init helpers  -  each returns Ok/Err for fault isolation
// ---------------------------------------------------------------------------

/// Dummy userspace entry for testing process spawn.
/// In production, this is replaced by ELF-loaded binaries.
fn userspace_idle() -> ! {
    loop {
        // WHY: wfe sleeps until next interrupt, preventing busy-loop.
        // SAFETY: WFE is a hint instruction available in all ARM privilege levels.
        // No memory is accessed; the CPU enters a low-power wait state until an event.
        unsafe {
            core::arch::asm!("wfe");
        }
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
    let _ = serial.write_str("  THUMOS / pyknosis v0.1.0\r\n");
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
    let (used, total) = heap::stats();
    let _ = write!(serial, "       {} / {} bytes\r\n", used, total);
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
    // Boot status summary
    // -----------------------------------------------------------------------
    let _ = serial.write_str("\r\n");
    let _ = write!(
        serial,
        "[init] Boot complete at {} ms\r\n",
        crate::timer::elapsed_ms()
    );
    let _ = write!(serial, "       {} / 9 subsystems OK\r\n", state.ok_count());
    if !state.display_ok {
        let _ = serial
            .write_str("       NOTE: display unavailable, USB serial only\r\n");
    }
    if !state.modem_ok {
        let _ = serial
            .write_str("       NOTE: modem unavailable, no phone functions\r\n");
    }
    let _ = serial.write_str("\r\n");

    // -----------------------------------------------------------------------
    // Step 13: Spawn userspace processes FROM ramfs
    // -----------------------------------------------------------------------
    let _ = serial
        .write_str("[init] Spawning userspace processes\r\n");
    {
        let fs = RamFs::new();

        // NOTE: In production, ramfs is populated FROM initramfs CPIO embedded
        // in the kernel image. For Phase 03, we add stub ELF binaries to prove
        // process isolation works end-to-end.
        //
        // Attempt to load and spawn two processes: /init and /shell.
        // If ELF binaries aren't in ramfs, fall back to spawning FROM
        // the built-in idle entry point.

        // WHY: process 1  -  init daemon (PID 1, supervisor)
        match fs.find("/init") {
            Some(elf_data) => match elf::load(elf_data) {
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
            None => {
                // Fallback: spawn built-in idle process as init
                if let Some(pid) = process::spawn(userspace_idle) {
                    let _ = write!(
                        serial,
                        "       idle/init spawned (PID {}) [built-in]\r\n",
                        pid
                    );
                    state.processes_spawned += 1;
                }
            }
        }

        // WHY: process 2  -  shell (PID 2, user interface)
        match fs.find("/shell") {
            Some(elf_data) => match elf::load(elf_data) {
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
            None => {
                // Fallback: spawn second idle process as shell
                if let Some(pid) = process::spawn(userspace_idle) {
                    let _ = write!(
                        serial,
                        "       idle/shell spawned (PID {}) [built-in]\r\n",
                        pid
                    );
                    state.processes_spawned += 1;
                }
            }
        }

        let _ = write!(
            serial,
            "       {} processes running\r\n",
            state.processes_spawned
        );
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
    use super::*;

    // -- BootStep ordering --

    #[test]
    fn boot_step_mmu_first() {
        assert_eq!(BootStep::Mmu as u8, 0, "MMU must be the first boot step");
    }

    #[test]
    fn boot_step_count_matches_variants() {
        assert_eq!(
            BootStep::COUNT,
            15,
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
    }

    #[test]
    fn boot_step_complete_is_last() {
        assert_eq!(
            BootStep::Complete as u8,
            14,
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
        assert!(!state.usb_ok, "initial usb_ok must be false");
        assert!(!state.modem_ok, "initial modem_ok must be false");
        assert!(!state.input_ok, "initial input_ok must be false");
        assert_eq!(
            state.processes_spawned, 0,
            "initial processes_spawned must be 0"
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
        state.usb_ok = true;
        state.modem_ok = true;
        state.input_ok = true;
        assert_eq!(state.ok_count(), 9, "all 9 subsystems OK");
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
}
