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
//! Pure planning logic (`BootStep` ordering, `BootState`, userspace spawn
//! planning) lives in `kinit_plan` (#528) so the host test build compiles and
//! runs its unit tests; this module keeps only the hardware-init-bearing
//! boot sequence.

extern crate alloc;

use core::sync::atomic::AtomicBool;
#[cfg(not(feature = "qemu"))]
use core::sync::atomic::Ordering;

use crate::board;
#[cfg(not(feature = "qemu"))]
use crate::ccci::CcciDriver;
#[cfg(feature = "debug-console")]
use crate::console::Console;
use crate::csprng;
use crate::device::DeviceRegistry;
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
// Gated: only the debug-console gate reads kconfig::DEBUG_CONSOLE.
#[cfg(not(feature = "qemu"))]
use crate::block::{MsdcBlockDevice, MsdcBlockDeviceUninit};
#[cfg(feature = "debug-console")]
use crate::kconfig;
#[cfg(not(feature = "qemu"))]
use crate::kinit_plan::MODEM_BOOT_TIMEOUT_MS;
use crate::kinit_plan::{BootState, UserspaceSpawnPlan, plan_userspace_spawn_from_vfs};
// M7-only: the boot passphrase loops render the lock screen (the Screen
// trait's draw) into the hardware framebuffer.
#[cfg(not(feature = "qemu"))]
use crate::ui::Screen as _;
// M7-only: the panic-red fill exists only where a hardware framebuffer does.
#[cfg(not(feature = "qemu"))]
use crate::kinit_plan::PANIC_RED_RGB565;
#[cfg(not(feature = "qemu"))]
use crate::mmio;
use crate::mmu;
use crate::net;
#[cfg(not(feature = "qemu"))]
use crate::net::{NetworkReadiness, WifiDevice};
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
use crate::usb;
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
/// WHY IRQs stay enabled: the timer ISR currently keeps petting the 5 s
/// watchdog. This is an intentional halt path, not scheduler liveness; #875
/// owns progress-coupled petting for normal operation.
#[cfg(not(feature = "qemu"))]
/// Map a keypad matrix key to its ASCII digit — the boot passphrase entry
/// alphabet (#446). Star/Hash are control keys at boot (backspace/submit),
/// never passphrase bytes.
const fn boot_digit(key: crate::ui::Key) -> Option<u8> {
    match key {
        crate::ui::Key::Num0 => Some(b'0'),
        crate::ui::Key::Num1 => Some(b'1'),
        crate::ui::Key::Num2 => Some(b'2'),
        crate::ui::Key::Num3 => Some(b'3'),
        crate::ui::Key::Num4 => Some(b'4'),
        crate::ui::Key::Num5 => Some(b'5'),
        crate::ui::Key::Num6 => Some(b'6'),
        crate::ui::Key::Num7 => Some(b'7'),
        crate::ui::Key::Num8 => Some(b'8'),
        crate::ui::Key::Num9 => Some(b'9'),
        _ => None,
    }
}

#[cfg(not(feature = "qemu"))]
/// Build a fresh encrypted view over the userdata payload (#446): physical
/// eMMC -> partition view one sector past the plaintext preamble -> AES-XTS
/// wrapper. Returns `None` when the block device fails init (the caller
/// logs and stays unmounted — fail-closed).
///
/// WHY the leak: `EncryptedBlockDevice` borrows its inner device while
/// `lfs::mount` takes ownership — a one-time `Box::leak` of the small view
/// struct satisfies both. Bounded (once per mount attempt) and deliberate.
fn encrypted_payload_device(
    data_key: &[u8; crate::security::XTS_KEY_SIZE],
) -> Option<crate::encryption::EncryptedBlockDevice<'static>> {
    let uninit = MsdcBlockDeviceUninit::new(board::LFS_PARTITION_START + board::LFS_PARTITION_SIZE);
    // SAFETY: the eMMC controller was initialized in Step 7; init() is
    // called once here on a freshly constructed device.
    let Ok(phys) = (unsafe { uninit.init() }) else {
        return None;
    };
    let payload = crate::block::PartitionBlockDevice::new(
        phys,
        board::LFS_PARTITION_START + board::LFS_PREAMBLE_SECTORS,
        board::LFS_PARTITION_SIZE - board::LFS_PREAMBLE_SECTORS,
    );
    let payload: &'static mut dyn crate::block::BlockDevice =
        alloc::boxed::Box::leak(alloc::boxed::Box::new(payload));
    Some(crate::encryption::EncryptedBlockDevice::new(
        payload, *data_key,
    ))
}

#[cfg(not(feature = "qemu"))]
/// The boot verify loop (#446): poll the keypad, drive the lock screen,
/// and on submit verify at PBKDF2 strength against the stored preamble
/// verifier. On success the partition keys are derived into `key_manager`
/// and the loop returns `true`. Throttle/wipe bookkeeping is the lock
/// screen's own state machine; the wipe trigger executes the panic wipe
/// and halts (never returns). Otherwise the loop runs until success — the
/// gate is the only work this boot has until the passphrase lands.
fn boot_verify_loop(
    serial: &mut Uart,
    lock: &mut crate::lock_screen::LockScreen,
    keypad: &mut crate::keypad::BootKeypad,
    fb: &mut [u16],
    secrets: &crate::secrets::DeviceSecrets,
    key_manager: &mut crate::key_manager::KeyManager,
    display_ok: bool,
) -> bool {
    let Some(verifier) = secrets.boot_verifier else {
        // Unreachable by construction (Verify is planned only for a
        // provisioned preamble); stay total rather than panic.
        return false;
    };
    let salt = secrets.salt;
    loop {
        let tick = crate::exceptions::uptime_ms() / 1000;
        lock.advance_tick(tick);
        if let Some(key) = keypad.poll() {
            match boot_digit(key) {
                Some(digit) => lock.push_passphrase_byte(digit),
                None => match key {
                    crate::ui::Key::Star => lock.backspace_passphrase(),
                    crate::ui::Key::Hash => {
                        let mut primary_out = None;
                        let result = lock.submit_passphrase_with(tick, |entered| {
                            let Ok(primary) =
                                crate::key_manager::KeyManager::derive_from_passphrase(
                                    entered, &salt,
                                )
                            else {
                                return false;
                            };
                            let Ok(candidate) =
                                crate::key_manager::KeyManager::derive_boot_verifier(&primary)
                            else {
                                return false;
                            };
                            let matches =
                                crate::lock_screen::constant_time_eq(&candidate, &verifier);
                            if matches {
                                primary_out = Some(primary);
                            }
                            matches
                        });
                        match result {
                            crate::lock_screen::UnlockResult::Success => {
                                if let Some(primary) = primary_out
                                    && key_manager.derive_partition_keys(&primary).is_ok()
                                {
                                    return true;
                                }
                                // A verified passphrase that cannot derive
                                // partition keys is a crypto fault, not a
                                // wrong passphrase — fail closed, stay locked.
                                serial.log(" CRIT Key derivation failed after verify\r\n");
                                return false;
                            }
                            crate::lock_screen::UnlockResult::WipeTrigger => {
                                serial.log(" CRIT Passphrase attempt limit reached\r\n");
                                // SAFETY: the panic wipe is the last kernel
                                // action before halt_boot (which never
                                // returns); dry_run=false zeroes the usable
                                // range. key_manager holds no keys on this
                                // path, so the wipe's key-zeroize is inert.
                                // The WipeResult is deliberately discarded:
                                // halt_boot never returns, so there is no
                                // caller left to report it to.
                                let _ = unsafe {
                                    crate::panic_wipe::execute_panic_wipe(
                                        key_manager,
                                        crate::exceptions::uptime_ms(),
                                        false,
                                    )
                                };
                                halt_boot(serial, display_ok);
                            }
                            // NOTE: WrongPassphrase / Throttled -- no-op by
                            // design. The lock screen's own state (attempt
                            // count, throttle countdown) already renders on
                            // the next `lock.draw()`; this loop just needs to
                            // keep polling. DuressDetected / WrongPin are
                            // unreachable through THIS path: the closure
                            // above only ever compares a PBKDF2 passphrase
                            // verifier, never a PIN, and boot-passphrase mode
                            // has no duress variant today. If boot-passphrase
                            // duress support is ever added, this arm must be
                            // split to handle it explicitly rather than
                            // silently swallowing it here.
                            _ => {} // NOTE: see block comment above -- WrongPassphrase/Throttled no-op; Duress/WrongPin unreachable here
                        }
                    }
                    // NOTE: D-pad/softkey/call/end/power -- every UI key
                    // besides digits, Star, and Hash is a deliberate no-op on
                    // the boot lock screen; there is no navigation target
                    // here.
                    _ => {} // NOTE: see comment above -- non-digit/Star/Hash keys are a deliberate no-op here
                },
            }
            lock.draw(&mut fb[..crate::ui::CONTENT_PIXELS]);
        }
        // ~10 ms poll cadence. The busy-wait is deliberate: boot is
        // single-threaded here and the gate is the only outstanding work.
        let wait_until = crate::exceptions::uptime_ms() + 10;
        while crate::exceptions::uptime_ms() < wait_until {
            core::hint::spin_loop();
        }
    }
}

#[cfg(not(feature = "qemu"))]
/// First-boot setup (#446): enter, confirm, store the PBKDF2-strength
/// verifier in the preamble, derive keys. Returns `true` once provisioning
/// completes. There is deliberately no skip binding: dev-anchor builds
/// never reach this loop (`secure_boot_ok` is false there), so every
/// production-signed boot of an unprovisioned device sets a passphrase.
fn boot_setup_loop(
    serial: &mut Uart,
    lock: &mut crate::lock_screen::LockScreen,
    keypad: &mut crate::keypad::BootKeypad,
    fb: &mut [u16],
    preamble_view: &mut crate::block::PartitionBlockDevice<MsdcBlockDevice>,
    key_manager: &mut crate::key_manager::KeyManager,
) -> bool {
    serial.log(" Set boot passphrase (6+ digits; Star backspace; Hash confirm)\r\n");
    let mut confirming = false;
    let mut first = [0u8; crate::lock_screen::MAX_PASSPHRASE_LEN];
    let mut first_len = 0usize;
    loop {
        let tick = crate::exceptions::uptime_ms() / 1000;
        lock.advance_tick(tick);
        if let Some(key) = keypad.poll() {
            match boot_digit(key) {
                Some(digit) => lock.push_passphrase_byte(digit),
                None => match key {
                    crate::ui::Key::Star => lock.backspace_passphrase(),
                    crate::ui::Key::Hash => {
                        let entered_len = lock.passphrase_len() as usize;
                        if confirming {
                            let matches = entered_len == first_len
                                && lock.passphrase_bytes() == &first[..first_len];
                            if matches {
                                let mut salt = [0u8; crate::secrets::SALT_LEN];
                                if crate::csprng::kernel_random_bytes(&mut salt).is_err() {
                                    serial.log(" CRIT CSPRNG unavailable -- cannot provision\r\n");
                                    crate::key_manager::volatile_zero(&mut first);
                                    return false;
                                }
                                let mut ok = false;
                                if let Ok(primary) =
                                    crate::key_manager::KeyManager::derive_from_passphrase(
                                        lock.passphrase_bytes(),
                                        &salt,
                                    )
                                    && let Ok(verifier) =
                                        crate::key_manager::KeyManager::derive_boot_verifier(
                                            &primary,
                                        )
                                    && crate::secrets::store_boot_verifier(
                                        preamble_view,
                                        &salt,
                                        &verifier,
                                    )
                                    .is_ok()
                                    && key_manager.derive_partition_keys(&primary).is_ok()
                                {
                                    ok = true;
                                }
                                lock.clear_passphrase();
                                crate::key_manager::volatile_zero(&mut first);
                                if ok {
                                    serial.log(" Passphrase set -- userdata encrypted\r\n");
                                    return true;
                                }
                                serial.log(" CRIT Provisioning failed (derive/store)\r\n");
                                return false;
                            }
                            serial.log(" Mismatch -- start over\r\n");
                            lock.clear_passphrase();
                            confirming = false;
                            crate::key_manager::volatile_zero(&mut first);
                            first_len = 0;
                        } else if entered_len >= crate::kinit_plan::MIN_BOOT_PASSPHRASE_LEN as usize
                        {
                            first[..entered_len].copy_from_slice(lock.passphrase_bytes());
                            first_len = entered_len;
                            lock.clear_passphrase();
                            confirming = true;
                            serial.log(" Confirm passphrase\r\n");
                        } else {
                            serial.log(" Passphrase too short (6+ digits)\r\n");
                        }
                    }
                    // NOTE: D-pad/softkey/call/end/power -- every UI key
                    // besides digits, Star, and Hash is a deliberate no-op on
                    // the boot setup screen; there is no navigation target
                    // here.
                    _ => {} // NOTE: see comment above -- non-digit/Star/Hash keys are a deliberate no-op here
                },
            }
            lock.draw(&mut fb[..crate::ui::CONTENT_PIXELS]);
        }
        // Same deliberate busy-wait cadence as the verify loop.
        let wait_until = crate::exceptions::uptime_ms() + 10;
        while crate::exceptions::uptime_ms() < wait_until {
            core::hint::spin_loop();
        }
    }
}

/// the halt is a stable, visible state instead of a WDT reboot loop.
///
/// WHY(qemu): exit code 6 (distinct from 0=ok / 1=panic / 5=loop-stall) so
/// a runner sees a secure-boot halt as its own diagnostic; unreachable
/// today because qemu presents no boot medium.
#[cfg_attr(feature = "qemu", allow(unused_variables))]
fn halt_boot(serial: &mut Uart, display_ok: bool) -> ! {
    // WHY not(qemu): virt has no hardware framebuffer (its render target is
    // a synthetic heap buffer) and display_ok can only be set on the M7 --
    // the fill is M7 bring-up, so it is selected out, not emulated.
    #[cfg(not(feature = "qemu"))]
    if display_ok {
        // SAFETY: display_ok is only true after display.init() succeeded,
        // so board::FB_BASE is a valid, mapped framebuffer of at least
        // DISPLAY_WIDTH * DISPLAY_HEIGHT * 2 bytes (RGB565).
        unsafe {
            fill_framebuffer(
                board::FB_BASE,
                board::DISPLAY_WIDTH,
                board::DISPLAY_HEIGHT,
                PANIC_RED_RGB565,
            );
        }
    }
    serial.log(" CRIT Boot halted: image trust could not be established (fail-closed)\r\n");
    #[cfg(feature = "qemu")]
    crate::qemu::request_exit(6);
    loop {
        // SAFETY: WFI is a hint instruction; no memory is accessed. The CPU
        // sleeps until the next interrupt (the timer tick currently pets the
        // WDT; #875 owns the normal-operation progress gate).
        unsafe {
            core::arch::asm!("wfi");
        }
    }
}

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
    // Step 8f and nothing between there and here transitions it, so this
    // currently always evaluates to Daily -- see the Step 8f WHY comment. Kept as the structural check point so it becomes load-bearing
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
    // TODO(#865)[deliberate-prudent]: `Console::wait_for_physical_presence` depends on
    // `Uart::getc`, whose RX "data ready" bit position is unverified
    // against authoritative MT6739 source (see uart.rs) -- source-ground and
    // host-test it before a later hardware receipt.
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
//
// WHY the allow: this is the boot sequencer -- one linear, numbered "Step N"
// narrative over ~20 subsystems, called from exactly one site, executed
// exactly once, never reused or independently tested in isolation. Splitting
// it into helper functions would thread `serial`/`state`/intermediate
// hand-offs (e.g. the mounted LFS feeding the VFS step) through a growing set
// of new `unsafe fn` boundaries -- each needing its own safety contract --
// purely to satisfy a line count, while making the top-to-bottom boot order
// this function exists to keep auditable harder to read in one pass.
#[expect(
    clippy::too_many_lines,
    reason = "the boot sequencer -- one linear, numbered Step-N narrative over ~20 subsystems, called from exactly one site, executed exactly once, never reused or independently tested in isolation; splitting into helpers would thread serial/state/intermediate hand-offs through a growing set of new unsafe fn boundaries purely to satisfy a line count, making the top-to-bottom boot order this function exists to keep auditable harder to read in one pass"
)]
pub unsafe fn run() -> ! {
    let mut serial = Uart::new();
    let mut state = BootState::new();

    // Banner
    serial.log("\r\n");
    serial.log("================================\r\n");
    serial.log(" THUMOS v0.1.0\r\n");
    serial.log(" Rust OS for the ");
    serial.log(board::BOARD_NAME);
    serial.log("\r\n");
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
        page::init(board::RAM_START, board::USER_TEXT_BASE, board::KERNEL_END);
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
    serial.log(" CPU DVFS/core parking unavailable (no source-grounded actuator, #879)\r\n");
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
                freq_a,
                el_a,
                el_b
            );
            state.timer_ok = false;
        } else {
            boot_log!(
                serial,
                "kardia: timer elapsed_ms=advancing freq={} ({} ms -> {} ms)\r\n",
                freq_a,
                el_a,
                el_b
            );
        }
    }

    // -----------------------------------------------------------------------
    // Step 5b: CSPRNG (ChaCha20, provisional timer-derived gate with timeout;
    // #840 blocks treating it as production entropy acceptance)
    // -----------------------------------------------------------------------
    serial.log("[init] CSPRNG (ChaCha20)\r\n");
    // SAFETY: called once after exceptions::init() (timer running, IRQs enabled).
    // csprng::init() spins on WFI until the provisional credit counter reaches
    // SEED_ENTROPY_BITS, then seeds ChaCha20Rng and sets INITIALIZED. #840
    // establishes that deterministic timer increments can satisfy that counter;
    // the wall-clock bound only prevents a dead timer ISR from hanging boot.
    // Must complete before any radio driver init.
    state.csprng_ok = unsafe { csprng::init() };
    if state.csprng_ok {
        serial.log(" CSPRNG gate reached (entropy UNQUALIFIED, #840)\r\n");
    } else {
        serial.log(" WARN CSPRNG timed out waiting for timer credits -- bytes unavailable\r\n");
        serial.log(" Radio identity randomization disabled\r\n");
    }

    // -----------------------------------------------------------------------
    // Step 5c: Hardware watchdog (WDT)
    // -----------------------------------------------------------------------
    serial.log("[init] Watchdog (WDT, 5s)\r\n");
    // SAFETY: called once after MMU init (device MMIO is identity-mapped).
    // Configures the MT6739 WDT with a 5-second timeout. The timer handler
    // currently pets it every 10 ms before scheduler progress; #875 owns the
    // required progress-coupled liveness gate.
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
    board::register_devices(&mut devices);
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
            display.init(board::FB_BASE);
        }
        if display.state() == crate::display::DisplayState::Uninitialized {
            serial.log(" WARN Display init incomplete\r\n");
            serial.log(" Falling back to USB serial console only\r\n");
        } else {
            serial.log(" Display pipeline active\r\n");
            boot_log!(serial, " Framebuffer @ {:#010x}\r\n", board::FB_BASE);
            devices.activate("gc9306-lcm");
            devices.activate("disp-ovl0");
            devices.activate("disp-rdma0");
            state.display_ok = true;
            DISPLAY_AVAILABLE.store(true, Ordering::Release);
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
        let kpd_base = board::KPD_BASE;
        // SAFETY: KPD_EN and KPD_DEBOUNCE are device MMIO registers at known
        // offsets from the KPD base address (0x1001_0000), which is
        // identity-mapped as device memory. Writing these registers enables the
        // hardware keypad scanner with 16 ms debounce.
        unsafe {
            // Enable KPD module (bit 0 of KPD_EN).
            mmio::write32(kpd_base + board::KPD_EN, 1);
            // Set debounce to 16 ms (hardware units).
            mmio::write32(kpd_base + board::KPD_DEBOUNCE, 16);
        }
        devices.activate("mtk-kpd");
        state.input_ok = true;
        serial.log(" Keypad scanning enabled\r\n");
    }

    // -----------------------------------------------------------------------
    // Step 8b: Post-entry boot-region signature verification (Ed25519)
    // -----------------------------------------------------------------------
    serial.log("[init] Secure boot verification\r\n");
    {
        // WHY: verification is unconditional and fail-closed (#217) -- it
        // must run and halt on failure regardless of display availability.
        // Display availability only controls *how* a failure is reported
        // (rendered vs UART-only); gating the verification call itself on
        // state.display_ok let a display-init failure silently bypass the
        // kernel's post-entry signature gate (#361).
        //
        // WHY the source derives from the medium (#467): qemu models no
        // MSDC, and an eMMC that failed init exposes no partitions -- no
        // boot medium means nothing to verify AND nothing persistent to
        // mount, so the boot continues DEGRADED with secure_boot_ok false
        // and every downstream trust gate locked. On the M7, the boot
        // partition is GPT-located by name and verified by streamed
        // Ed25519ph; a present-but-unreadable partition maps to Unreadable,
        // which HALTS -- never the Absent degrade (an attacker deleting the
        // boot partition must not downgrade boot to degraded-open).
        // Bound: the GPT-documented region (userdata end covers boot);
        // a read past it errors -> Unreadable -> Halt, by design (#467).
        // The physical device outlives `source` (the enum borrows it).
        #[cfg(not(feature = "qemu"))]
        let mut phys_dev = if state.emmc_ok {
            let uninit =
                MsdcBlockDeviceUninit::new(board::LFS_PARTITION_START + board::LFS_PARTITION_SIZE);
            // SAFETY: the eMMC controller was initialized in Step 7; init() is
            // called once here on a freshly constructed device. Step 7's
            // controller is a separate instance, so its success says nothing
            // about this one — this device must be initialized in its own
            // right before any I/O (#619).
            unsafe { uninit.init() }.ok()
        } else {
            None
        };
        #[cfg(feature = "qemu")]
        let source = crate::secure_boot::BootImageSource::Absent;
        #[cfg(not(feature = "qemu"))]
        let source = match phys_dev.as_mut() {
            Some(dev) => crate::secure_boot::boot_image_source(dev),
            // Absent, per BootImageSource's own contract: "no boot medium:
            // qemu (no MSDC model) or an eMMC that failed init". A failed
            // init is the degrade class, not the Unreadable halt class —
            // Unreadable means a medium exists and its partition could not
            // be read.
            None => crate::secure_boot::BootImageSource::Absent,
        };
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
    // Step 8c: Passphrase entry and key derivation (#446)
    // -----------------------------------------------------------------------
    serial.log("[init] Passphrase entry\r\n");
    // WHY before any mount (#446): once first-boot setup stores a verifier,
    // the userdata payload is ciphertext (AES-XTS under the derived data
    // key) — the mount needs the key, and a locked payload must never be
    // plain-mounted or formatted. The secrets preamble (#449) is therefore
    // probed here, READ-ONLY and ahead of the mount, and the mount plan
    // keys off what it found.
    //
    // WHY this post-entry gate is checked first (#217): this implementation
    // does not derive keys after its signature check fails. It cannot defend
    // against a tampered executing kernel, which could bypass the branch and
    // exfiltrate the passphrase; #467's pre-entry chain must authenticate it.
    //
    // Boot pad binding (the 4x3 matrix yields only digits/Star/Hash):
    // digits append, Star = backspace, Hash = submit/confirm. First-boot
    // setup constrains the alphabet identically, so a passphrase set at
    // setup is always enterable at boot.
    #[cfg_attr(feature = "qemu", allow(unused_mut, unused_variables))]
    let mut key_manager = crate::key_manager::KeyManager::new();
    #[cfg(not(feature = "qemu"))]
    let mut boot_secrets: Option<crate::secrets::DeviceSecrets> = None;
    #[cfg(not(feature = "qemu"))]
    let mut preamble_view: Option<crate::block::PartitionBlockDevice<MsdcBlockDevice>> = None;
    #[cfg(not(feature = "qemu"))]
    {
        use crate::kinit_plan::PreambleLoad;

        // Early read-only preamble probe — the mount gate's fail-closed
        // signal. Runs whenever eMMC is up, independent of the trust gate,
        // and NEVER writes here: the provisioning write happens only inside
        // the first-boot setup completion below.
        if state.emmc_ok {
            let preamble_uninit =
                MsdcBlockDeviceUninit::new(board::LFS_PARTITION_START + board::LFS_PARTITION_SIZE);
            // SAFETY: eMMC init succeeded in Step 7; init() is called once
            // here on a freshly constructed device.
            match unsafe { preamble_uninit.init() } {
                Ok(preamble_phys) => {
                    let mut view = crate::block::PartitionBlockDevice::new(
                        preamble_phys,
                        board::LFS_PARTITION_START,
                        board::LFS_PREAMBLE_SECTORS,
                    );
                    match crate::secrets::load(&mut view) {
                        Ok(crate::secrets::PreambleStatus::Valid(found)) => {
                            state.preamble = if found.boot_verifier.is_some() {
                                PreambleLoad::Provisioned
                            } else {
                                PreambleLoad::Unprovisioned
                            };
                            boot_secrets = Some(found);
                        }
                        Ok(crate::secrets::PreambleStatus::Absent) => {
                            state.preamble = PreambleLoad::Unprovisioned;
                        }
                        // #621: magic present but validation failed -- a
                        // PROVISIONED device, not a blank one. Must never
                        // collapse to Unprovisioned: that would let
                        // first-boot setup overwrite the only copy of the
                        // salt, or let the mount gate plain-mount (and
                        // then format) the still-encrypted payload.
                        Ok(crate::secrets::PreambleStatus::Corrupt) => {
                            serial.log(
                                " WARN Secrets preamble corrupt (magic present, validation failed) -- locking\r\n",
                            );
                            state.preamble = PreambleLoad::Corrupt;
                        }
                        Err(e) => {
                            boot_log!(serial, " WARN Secrets preamble read failed: {:?}\r\n", e);
                            state.preamble = PreambleLoad::ReadFailed;
                        }
                    }
                    preamble_view = Some(view);
                }
                Err(e) => {
                    boot_log!(serial, " WARN Preamble device init failed: {:?}\r\n", e);
                    state.preamble = PreambleLoad::ReadFailed;
                }
            }
        }
    }

    match crate::kinit_plan::boot_passphrase_plan(
        state.secure_boot_ok,
        state.display_ok,
        state.input_ok,
        state.preamble,
    ) {
        crate::kinit_plan::BootPassphrasePlan::Skip => {
            serial.log(crate::kinit_plan::passphrase_skip_reason(
                state.secure_boot_ok,
                state.display_ok,
                state.input_ok,
            ));
        }
        #[cfg(not(feature = "qemu"))]
        crate::kinit_plan::BootPassphrasePlan::Verify => {
            if let Some(found) = boot_secrets.as_ref() {
                // SAFETY: the plan guarantees display_ok, and the display
                // init mapped FB_BASE as a writable RGB565 framebuffer of
                // FRAMEBUFFER_PIXELS pixels. The slice is dropped at the
                // end of this arm, before the kardia handoff re-derives
                // its own framebuffer slice.
                let fb = unsafe {
                    core::slice::from_raw_parts_mut(board::FB_BASE as *mut u16, FRAMEBUFFER_PIXELS)
                };
                fb.fill(0);
                let mut keypad = crate::keypad::BootKeypad::new();
                keypad.init();
                // WHY zero hashes: the boot gate never uses the raw
                // SHA-256 compare — submit goes through
                // submit_passphrase_with at PBKDF2 strength, so the
                // stored-hash fields are inert in this construction.
                let mut lock = crate::lock_screen::LockScreen::new([0u8; 32], [0u8; 32], [0u8; 32]);
                if boot_verify_loop(
                    &mut serial,
                    &mut lock,
                    &mut keypad,
                    fb,
                    found,
                    &mut key_manager,
                    state.display_ok,
                ) {
                    state.passphrase_ok = true;
                    serial.log(" Passphrase: OK (keys derived)\r\n");
                }
            }
        }
        #[cfg(not(feature = "qemu"))]
        crate::kinit_plan::BootPassphrasePlan::FirstBootSetup => {
            if let Some(view) = preamble_view.as_mut() {
                // SAFETY: as above — the plan guarantees display_ok.
                let fb = unsafe {
                    core::slice::from_raw_parts_mut(board::FB_BASE as *mut u16, FRAMEBUFFER_PIXELS)
                };
                fb.fill(0);
                let mut keypad = crate::keypad::BootKeypad::new();
                keypad.init();
                let mut lock = crate::lock_screen::LockScreen::new([0u8; 32], [0u8; 32], [0u8; 32]);
                if boot_setup_loop(
                    &mut serial,
                    &mut lock,
                    &mut keypad,
                    fb,
                    view,
                    &mut key_manager,
                ) {
                    state.passphrase_ok = true;
                    state.preamble = crate::kinit_plan::PreambleLoad::Provisioned;
                    // WHY (#360): the line above overwrites the `Unprovisioned`
                    // that made this a first boot, so record the fact here
                    // while it is still known. The encrypted mount uses it to
                    // tell an LFS that does not exist yet from one that is
                    // damaged — after this point `preamble` cannot.
                    state.provisioned_this_boot = true;
                    serial.log(" Passphrase: SET (userdata encrypted)\r\n");
                }
            }
        }
        #[cfg(feature = "qemu")]
        _ => {
            // Virt never establishes trust (dev anchor, no boot medium), so
            // the plan is always Skip on this board; the interactive arms'
            // hardware paths are M7-only.
        }
    }

    // -----------------------------------------------------------------------
    // Step 8d: Filesystem (LFS) -- trust-gated (#217), fail-closed on a
    // locked payload (#446)
    // -----------------------------------------------------------------------
    serial.log("[init] Filesystem (LFS)\r\n");
    // Captures the mounted LFS so it can back the VFS root below instead
    // of a fresh, volatile ramfs (#343). Stays `None` on any path that
    // does not end with a durably mounted filesystem.
    #[cfg_attr(feature = "qemu", allow(unused_mut))]
    let mut lfs_root: Option<alloc::boxed::Box<dyn crate::vfs::Filesystem>> = None;
    // WHY (#217): this implementation mounts persistent storage only after
    // its post-entry signature check succeeds. That is a conditional software
    // gate, not protection from a tampered executing kernel; #467 owns the
    // pre-entry chain. WHY fail-closed on a
    // provisioned-or-unreadable preamble (#446): the payload is ciphertext
    // under a key this boot does not have — plain-mounting it reads garbage
    // and the InvalidSuperblock reformat path would DESTROY it, so the only
    // honest mount without the derived key is none.
    // WHY not(qemu): the mount path is eMMC + LFS-partition bring-up, which
    // exists only on the M7 (#534) -- virt models no block medium, so
    // `lfs_root` stays None there exactly as the runtime gate already
    // produced, and the VFS root falls back to the initramfs.
    #[cfg(not(feature = "qemu"))]
    match crate::kinit_plan::mount_plan(
        state.emmc_ok,
        state.secure_boot_ok,
        state.preamble,
        state.passphrase_ok,
    ) {
        crate::kinit_plan::MountPlan::Encrypted => {
            use crate::lfs;
            use crate::lfs_imap::LfsError;

            let data_key = key_manager.data_key().map(|k| *k.as_bytes());
            match data_key {
                Some(mut data_key) => {
                    match encrypted_payload_device(&data_key) {
                        Some(enc) => match lfs::mount(alloc::boxed::Box::new(enc)) {
                            Ok(fs) => {
                                serial.log(" LFS mounted (encrypted)\r\n");
                                lfs_root = Some(alloc::boxed::Box::new(fs));
                                state.encryption_ok = true;
                            }
                            // #360: this result covers a never-formatted payload
                            // AND damaged or version-incompatible existing
                            // metadata. `kinit_plan::may_format_encrypted_lfs`
                            // separates them on the only fact that can: whether
                            // this boot provisioned the device. Formatting a
                            // device provisioned earlier destroys userdata still
                            // encrypted under a salt the preamble still holds.
                            Err(LfsError::InvalidSuperblock)
                                if !crate::kinit_plan::may_format_encrypted_lfs(
                                    state.preamble,
                                    state.provisioned_this_boot,
                                ) =>
                            {
                                serial.log(
                                    " CRIT Encrypted LFS superblock unreadable on a previously provisioned device -- not formatting, data at risk (#360)\r\n",
                                );
                            }
                            Err(LfsError::InvalidSuperblock) => {
                                serial.log(
                                    " First boot: formatting encrypted LFS (provisioned this boot)\r\n",
                                );
                                if let Some(mut fmt_enc) = encrypted_payload_device(&data_key) {
                                    if lfs::format(&mut fmt_enc).is_ok() {
                                        serial.log(" Encrypted LFS formatted\r\n");
                                        match encrypted_payload_device(&data_key) {
                                            Some(remount_enc) => {
                                                match lfs::mount(alloc::boxed::Box::new(
                                                    remount_enc,
                                                )) {
                                                    Ok(fs) => {
                                                        serial
                                                            .log(" LFS remounted (encrypted)\r\n");
                                                        lfs_root = Some(alloc::boxed::Box::new(fs));
                                                        state.encryption_ok = true;
                                                    }
                                                    Err(e) => {
                                                        boot_log!(
                                                            serial,
                                                            " WARN Encrypted LFS remount failed: {:?}\r\n",
                                                            e
                                                        );
                                                    }
                                                }
                                            }
                                            None => serial
                                                .log(" WARN Device re-init for remount failed\r\n"),
                                        }
                                    } else {
                                        serial.log(" WARN Encrypted LFS format failed\r\n");
                                    }
                                } else {
                                    serial.log(" WARN Device init for format failed\r\n");
                                }
                            }
                            Err(e) => {
                                boot_log!(
                                    serial,
                                    " CRIT Encrypted LFS mount failed ({:?}) -- not reformatting, data at risk\r\n",
                                    e
                                );
                            }
                        },
                        None => serial.log(" WARN Device init failed (encrypted payload)\r\n"),
                    }
                    // WHY: EncryptedBlockDevice::new copied the key into its
                    // own SecureKey; zero this stack copy on every path (#325
                    // posture).
                    crate::key_manager::volatile_zero(&mut data_key);
                }
                None => {
                    // passphrase_ok implies loaded keys; a missing data key
                    // here is a bug — fail closed (no mount), never panic.
                    serial.log(" CRIT passphrase_ok without a data key\r\n");
                }
            }
        }
        crate::kinit_plan::MountPlan::Plain => {
            use crate::lfs;
            use crate::lfs_imap::LfsError;

            // Compute device size in sectors from the partition constants.
            let sector_count = board::LFS_PARTITION_SIZE;

            // #603: the eMMC block device addresses the PHYSICAL medium (its LBA
            // 0 is the eMMC's sector 0 -- the GPT/boot region), so its bound is
            // the partition's END; the LFS mount then runs inside the userdata
            // partition VIEW carved at LFS_PARTITION_START. Before the view, LFS
            // would have formatted over the boot/vendor partitions.
            //
            // WHY the plain mount is still at the partition head: this arm is
            // reachable only on an UNPROVISIONED device (no preamble), so no
            // plaintext sector has been carved — byte-compatible with pre-#446
            // images.
            let uninit = MsdcBlockDeviceUninit::new(board::LFS_PARTITION_START + sector_count);

            // SAFETY: eMMC controller was initialized successfully in Step 7.
            // init() is called once here on a freshly constructed device.
            match unsafe { uninit.init() } {
                Ok(phys_dev) => {
                    let blk_dev = crate::block::PartitionBlockDevice::new(
                        phys_dev,
                        board::LFS_PARTITION_START,
                        sector_count,
                    );
                    // Try to mount existing LFS.
                    match lfs::mount(alloc::boxed::Box::new(blk_dev)) {
                        Ok(fs) => {
                            serial.log(" LFS mounted OK\r\n");
                            lfs_root = Some(alloc::boxed::Box::new(fs));
                        }
                        // CURRENT UNSAFE COMPATIBILITY (#360): this result does
                        // not prove first boot. It also covers damaged or
                        // version-incompatible existing metadata, but this
                        // branch still formats. Production must distinguish an
                        // authenticated first-provisioning state or require an
                        // explicit operator-confirmed format action.
                        //
                        // WHY this arm is still ungated while the encrypted one
                        // above is not: the encrypted mount is reached only
                        // after a passphrase verifies, so `provisioned_this_boot`
                        // separates a device provisioned moments ago from one
                        // provisioned earlier. This arm is reached only when the
                        // preamble is `Unprovisioned` — a device that has never
                        // held a passphrase — so no such marker exists to
                        // consult, and nothing on the medium distinguishes a
                        // never-formatted plain LFS from a damaged one. Closing
                        // it needs a durable formatted-before marker, which is
                        // the remaining half of #360.
                        Err(LfsError::InvalidSuperblock) => {
                            serial.log(
                                " CRIT Ambiguous LFS superblock; legacy auto-format path (#360)\r\n",
                            );
                            let fmt_uninit = MsdcBlockDeviceUninit::new(
                                board::LFS_PARTITION_START + sector_count,
                            );
                            // SAFETY: eMMC controller was initialized successfully in
                            // Step 7; init() is called once here on a freshly
                            // constructed device.
                            if let Ok(fmt_phys) = unsafe { fmt_uninit.init() } {
                                let mut fmt_dev = crate::block::PartitionBlockDevice::new(
                                    fmt_phys,
                                    board::LFS_PARTITION_START,
                                    sector_count,
                                );
                                if lfs::format(&mut fmt_dev).is_ok() {
                                    serial.log(" LFS formatted OK\r\n");
                                    // Remount the freshly formatted device so the
                                    // VFS root is backed by durable storage from
                                    // this boot onward, not just after the NEXT
                                    // reboot (#343).
                                    let remount_uninit = MsdcBlockDeviceUninit::new(
                                        board::LFS_PARTITION_START + sector_count,
                                    );
                                    // SAFETY: eMMC controller was initialized successfully
                                    // in Step 7; init() is called once here on a freshly
                                    // constructed device.
                                    match unsafe { remount_uninit.init() } {
                                        Ok(remount_phys) => {
                                            let remount_dev =
                                                crate::block::PartitionBlockDevice::new(
                                                    remount_phys,
                                                    board::LFS_PARTITION_START,
                                                    sector_count,
                                                );
                                            match lfs::mount(alloc::boxed::Box::new(remount_dev)) {
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
                                            }
                                        }
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
        }
        crate::kinit_plan::MountPlan::RamfsFallback => {
            if state.emmc_ok && state.secure_boot_ok {
                serial.log(" Skipped (payload locked or unreadable -- fail-closed)\r\n");
            } else if state.emmc_ok {
                serial.log(" Skipped (secure boot not established -- fail-closed)\r\n");
            } else {
                serial.log(" Skipped (no eMMC)\r\n");
            }
        }
    }

    // Initialize the VFS mount table, backed by the mounted LFS when one
    // is available so writes survive a reboot; falls back to a fresh ramfs
    // root otherwise (#343). With the trust gate above, a persistent root --
    // and therefore userspace loaded from persistent storage -- is only
    // reachable only after the running kernel accepts the selected boot region;
    // the ramfs fallback is image-resident and separately signature-checked.
    // Neither post-entry check authenticates the executing kernel (#467).
    // WHY(#474): with no LFS-backed root (QEMU / unverified eMMC) the boot root
    // would be an empty ramfs and /init unfindable. Mount the image-resident
    // initramfs -- the /init ELF wrapped in a newc CPIO, built by build.rs into
    // the kernel image -- as the root so plan_userspace_spawn_from_vfs("/init")
    // resolves. A verified boot uses the LFS root instead (initramfs ignored).
    //
    // WHY the allow: hoisting to the top of `run()`'s ~900-line boot sequence
    // would separate this declaration from its use two lines below by
    // hundreds of lines, for the same audit-ability reason `run()` itself
    // carries a `too_many_lines` allow above.
    #[expect(
        clippy::items_after_statements,
        reason = "hoisting to the top of run()'s ~900-line boot sequence would separate this declaration from its use two lines below by hundreds of lines, for the same audit-ability reason run() itself carries a too_many_lines expect above"
    )]
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
    // Step 8e: Audit log initialization
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
    // Step 8f: Security mode manager
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
        // policy/reality mismatch for code that once treated PowerManager as
        // ground truth. It is now explicitly desired state only (#874).
        // A full passphrase-derived pin_hash is not threaded
        // through yet (Step 8c derives the keys; the mode manager's
        // pin-hash provisioning is separate work), so
        // ModeManager::default() is used: unprovisioned, but still Daily
        // mode, which is the correct policy to apply at this point.
        //
        // NOTE: BFU (Before First Unlock) timer wiring is separate,
        // unrelated work -- not part of this radio-policy fix.
        // let bfu = BfuTimer::new(SecurityMode::Daily);
        crate::power::apply_mode_policy(&mode_mgr.effective_policy(), &mut pm);
        state.security_mode_ok = true;
        serial.log(" Security mode: Daily policy requested (actuation unverified)\r\n");
    }

    // -----------------------------------------------------------------------
    // Step 9: USB ACM serial (primary debug console)
    // -----------------------------------------------------------------------
    serial.log("[init] USB ACM serial\r\n");
    // WHY(qemu): virt models no MUSB controller at 0x1120_0000; the init
    // would data-abort. usb_ok stays false (existing degradation path).
    #[cfg(feature = "qemu")]
    serial.log(" Skipped (qemu: no MUSB model)\r\n");
    #[cfg(not(feature = "qemu"))]
    {
        // SAFETY: init_controller() programs the MUSB MMIO registers at
        // their source-resolved physical address (0x1120_0000) on the shared static
        // controller (#666, promoted off this stack frame so
        // exceptions::irq_handler_body's ISR path can reach it). Called
        // once, here, after heap and GIC init -- the sole init call site.
        match unsafe { usb::init_controller() } {
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
        " {} radios requested active by Daily policy (actuation unverified)\r\n",
        pm.active_count()
    );

    // -----------------------------------------------------------------------
    // Step 13: Network configuration (WiFi readiness + DHCP/DNS smoke)
    // -----------------------------------------------------------------------
    serial.log("[init] Network WiFi readiness\r\n");
    #[cfg(not(feature = "qemu"))]
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
    // WHY(virt): no combo chip exists on this board; the old path probed the
    // M7's CONSYS address and relied on qemu's RAZ/WI to fail the probe.
    // BootState's default is already HardwareUnavailable(Wifi), so the skip
    // leaves the boot record identical -- but the board truth is now named.
    #[cfg(feature = "qemu")]
    serial.log(" WiFi skipped (virt: no combo chip)\r\n");

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
        // INVARIANT: `uptime_ms()` is a device-uptime millisecond count;
        // `i64::MAX` ms is ~292 million years of uptime, so this
        // bit-reinterpretation (required by smoltcp's
        // `Instant::from_millis(i64)`) cannot flip sign.
        let now = net::instant_from_millis(crate::exceptions::uptime_ms().cast_signed());
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
                    // INVARIANT: `uptime_ms()` is a device-uptime millisecond
                    // count; `i64::MAX` ms is ~292 million years of uptime,
                    // so this bit-reinterpretation (required by smoltcp's
                    // `Instant::from_millis(i64)`) cannot flip sign.
                    let now =
                        net::instant_from_millis(crate::exceptions::uptime_ms().cast_signed());
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
                        DhcpEvent::Deconfigured | DhcpEvent::None => {}
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
    #[cfg(not(feature = "qemu"))]
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
    #[cfg(feature = "qemu")]
    serial.log(" BT skipped (virt: no combo chip)\r\n");

    // -----------------------------------------------------------------------
    // Step 13c: GPS receiver
    // -----------------------------------------------------------------------
    serial.log("[init] GPS (via WMT)\r\n");
    #[cfg(not(feature = "qemu"))]
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
    #[cfg(feature = "qemu")]
    serial.log(" GPS skipped (virt: no combo chip)\r\n");

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
    // WHY (#217 + #480): the running kernel gates userspace on EITHER a
    // signature-checked boot medium (secure_boot_ok, the persistent-storage/LFS
    // path) OR a signature-checked image-resident initramfs. The initramfs is
    // signed by the build anchor (build.rs, dev seed) and checked here against
    // BOOT_PUBLIC_KEY. Because this check runs post-entry, it authenticates
    // neither the executing kernel nor a trust domain that includes it; #467
    // owns that pre-entry chain. A production image's initramfs carries a dev signature that does
    // NOT verify under the production anchor, so it correctly falls back to the
    // eMMC post-entry signature gate. secure_boot_ok stays false here (no medium), so
    // every OTHER trust-dependent step (passphrase, audit, persistent decrypt)
    // remains fail-closed.
    //
    // WHY the allow: see `INITRAMFS`'s identical note above -- hoisting out of
    // `run()`'s boot narrative to satisfy a line-position lint would separate
    // this from its use three lines below by well over a thousand lines.
    #[expect(
        clippy::items_after_statements,
        reason = "see INITRAMFS's identical note above -- hoisting out of run()'s boot narrative to satisfy a line-position lint would separate this from its use three lines below by well over a thousand lines"
    )]
    static INITRAMFS_SIG: &[u8; 64] =
        include_bytes!(concat!(env!("OUT_DIR"), "/initramfs_sig.bin"));
    let userspace_image_verified =
        crate::secure_boot::verify_userspace_image(INITRAMFS, INITRAMFS_SIG);
    if state.secure_boot_ok || userspace_image_verified {
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
                match unsafe { elf::load_confined(elf_data, board::USER_TEXT_BASE, board::RAM_END) }
                {
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
                match unsafe { elf::load_confined(elf_data, board::USER_TEXT_BASE, board::RAM_END) }
                {
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
            match unsafe { elf::load_confined(elf_data, board::USER_TEXT_BASE, board::RAM_END) } {
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

        // #544 on-device leg: /metaxu_probe, spawned ONLY under the
        // metaxu-probe feature (never in a normal boot). Unlike /crasher it
        // is NOT supervised -- a one-shot probe that exits cleanly, not a
        // service the supervisor should relaunch.
        #[cfg(feature = "metaxu-probe")]
        if let UserspaceSpawnPlan::Elf(elf_data) = plan_userspace_spawn_from_vfs("/metaxu_probe") {
            // SAFETY (#502): kinit runs under the kernel L1 (proc0's table,
            // scheduling disabled), satisfying load_confined's TTBR0 precondition.
            match unsafe { elf::load_confined(elf_data, board::USER_TEXT_BASE, board::RAM_END) } {
                Ok(loaded) => {
                    if let Some(pid) = process::spawn_user(&loaded) {
                        boot_log!(serial, " /metaxu_probe spawned PL0 (PID {})\r\n", pid);
                        state.processes_spawned += 1;
                    } else {
                        serial.log(" WARN /metaxu_probe spawn failed\r\n");
                    }
                }
                Err(e) => {
                    boot_log!(serial, " WARN /metaxu_probe ELF load failed: {:?}\r\n", e);
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
    } else {
        // Fail-closed: no verified medium AND no verified image-resident image.
        serial.log(
            " WARN Userspace spawn refused (no verified boot medium or image -- fail-closed)\r\n",
        );
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
    let mut fb: Option<&'static mut [u16]> = Some(alloc::vec![0u16; FRAMEBUFFER_PIXELS].leak());
    #[cfg(not(feature = "qemu"))]
    let mut fb: Option<&'static mut [u16]> = if state.display_ok {
        // SAFETY: display_ok is set only after display.init(FB_BASE) mapped
        // FB_BASE as a writable RGB565 framebuffer of FRAMEBUFFER_PIXELS pixels.
        Some(unsafe {
            core::slice::from_raw_parts_mut(board::FB_BASE as *mut u16, FRAMEBUFFER_PIXELS)
        })
    } else {
        None
    };

    // -----------------------------------------------------------------------
    // Boot splash (#458)
    // -----------------------------------------------------------------------
    // WHY here, not Step 8 (display init): on device the panel is already
    // live at Step 8 and painting the splash there would hold it on screen
    // for the whole remaining boot -- but `fb` above is the one binding that
    // exists identically on BOTH targets (Step 8's DDP/DSI writes are
    // skipped entirely under qemu, which has no display model; `fb` is a
    // synthetic heap buffer there instead). Painting here, once, right
    // before this same buffer is handed to kardia, is the only insertion
    // point that covers hardware and the CI-verifiable emulation with one
    // code path, and it runs before kardia's OWN first frame -- the
    // `render_if_dirty` call at the top of `kardia::service_loop` (#400) --
    // so the splash is strictly the first thing painted, never a frame
    // fighting the running UI for the buffer.
    //
    // WHY splash-only (never lock screen / status bar / running UI) and
    // ASCII-through-the-existing-font (never a bitmap asset): see the WHY
    // block above `ui::draw_splash` -- this is the mark's only call site,
    // by design.
    if let Some(fb) = fb.as_deref_mut() {
        let splash_painted = ui::draw_splash(fb);
        // Witness marker (#458), qemu-only like every other loop-entry
        // witness in this boot path (scripts/witness/boot.sh has no
        // observer on real hardware). WHY `splash_px=` and not
        // `painted_px=`: the #400 witness extracts its pixel count with an
        // UNANCHORED `grep -oE 'painted_px=[0-9]+' | head -1` -- a shared
        // field name would make it silently pick up THIS line instead
        // (this one lands earlier in the log than kardia's own frame
        // render), passing while checking the wrong render entirely.
        #[cfg(feature = "qemu")]
        boot_log!(
            serial,
            "kardia: splash rendered splash_px={splash_painted}\r\n"
        );
        // WHY discarded here: real hardware has no CI witness to feed (see
        // above); this keeps the binding used on both targets without a
        // leading-underscore name (`_splash_painted` would trip
        // clippy::used_underscore_binding the moment the qemu branch reads
        // it, since pedantic is warn-level crate-wide).
        #[cfg(not(feature = "qemu"))]
        let _ = splash_painted;
    }

    // #398: bring up the AT/call telephony stack on the modem transport. Under
    // qemu a seeded mock runs the real 10-step init + state machines; on device
    // the CCCI transport cannot initialize until its software wire protocol
    // lands under #398; only then can the same wiring reach M7 qualification.
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
    // zeroized on drop). The persistent, passphrase-derived audit key (Step 8e)
    // stays PENDING/deferred; this key derives nothing and unlocks nothing -- it
    // only gives the loop-owned firewall audit chain HMAC integrity for THIS
    // boot. Fails closed: an all-zero key (CSPRNG unavailable) makes log_event
    // return NoKey, so no audit entry is forged without integrity.
    let mut audit_key = [0u8; crate::security::KEY_SIZE];
    if state.csprng_ok {
        crate::csprng::kernel_random_bytes(&mut audit_key).ok();
        serial.log(" Audit trail: interim session key (persistent key PENDING #863)\r\n");
    }
    let kernel = crate::kardia::KernelState::new(
        state, devices, pm, mode_mgr, fb, telephony, net, audit_key,
    );
    crate::kardia::service_loop(kernel, serial)
}
