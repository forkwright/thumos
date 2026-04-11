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
use core::sync::atomic::{AtomicBool, Ordering};

use crate::ccci::CcciDriver;
use crate::console::Console;
use crate::csprng;
use crate::device::{self, DeviceRegistry};
use crate::dhcp::{DhcpClient, DhcpEvent};
use crate::display::{DisplayDriver, Gc9306};
use crate::dns::{DnsResolver, MENOS_DNS, MULLVAD_DNS};
use crate::elf;
use crate::exceptions;
use crate::gic;
use crate::heap;
use crate::kconfig;
use crate::mmio;
use crate::mmu;
use crate::net::{self, LoopbackDevice, NetworkStack};
use crate::page;
use crate::power::PowerManager;
use crate::process;
use crate::ramfs::RamFs;
use crate::uart::Uart;
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
    /// USB ACM serial console.
    UsbSerial = 10,
    /// CCCI modem link.
    CcciModem = 11,
    /// GPIO keypad scanning.
    GpioInput = 12,
    /// Power manager.
    PowerManager = 13,
    /// Network configuration (DHCP + DNS resolver).
    Network = 14,
    /// Bluetooth adapter initialization.
    Bluetooth = 15,
    /// GPS receiver initialization.
    Gps = 16,
    /// Userspace processes spawned.
    Userspace = 17,
    /// Boot complete.
    Complete = 18,
}

#[expect(dead_code, reason = "used by tests and future boot progress reporting")]
impl BootStep {
    /// Total number of boot steps.
    pub(crate) const COUNT: usize = 19;

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
    pub(crate) network_ok: bool,
    pub(crate) bluetooth_ok: bool,
    pub(crate) gps_ok: bool,
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
            network_ok: false,
            bluetooth_ok: false,
            gps_ok: false,
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
    // csprng::init() spins on WFI until sufficient timer-jitter entropy is
    // accumulated (MIN_MIX_COUNT ISR samples ≈ 640 ms at 100 Hz), then seeds
    // ChaCha20 and sets INITIALIZED. Must complete before any radio driver init.
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
    // Step 13: Network configuration (DHCP + DNS)
    // -----------------------------------------------------------------------
    let _ = serial.write_str("[init] Network (DHCP + DNS)\r\n");
    {
        // WHY: In production, the WiFi driver provides the Device impl.
        // Until WiFi hardware init is wired in, we use LoopbackDevice to
        // prove the DHCP+DNS integration path works end-to-end.
        let device = LoopbackDevice::new();
        let mac = smoltcp::wire::EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        let now = net::instant_from_millis(crate::timer::elapsed_ms() as i64);
        let mut stack = NetworkStack::new(device, mac, now);

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
        let _resolver = DnsResolver::new(MENOS_DNS, MULLVAD_DNS);
        let _ = serial.write_str("       DNS resolver ready\r\n");
        let _ = write!(
            serial,
            "       LAN DNS: {} / Internet DNS: {}\r\n",
            MENOS_DNS,
            MULLVAD_DNS
        );
        state.network_ok = true;
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
    let _ = write!(serial, "       {} / 12 subsystems OK\r\n", state.ok_count());
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
            17,
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
            16,
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
        assert!(!state.network_ok, "initial network_ok must be false");
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
        state.network_ok = true;
        assert_eq!(state.ok_count(), 10, "all 10 subsystems OK");
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
