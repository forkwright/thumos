//! MT6739 Watchdog Timer (WDT) driver.
//!
//! The MT6739 WDT resets the `SoC` if software stops petting it within the
//! configured timeout. The timer IRQ pets only after the progress gate accepts
//! fresh scheduler and PID-0 service-loop epochs. Controlled reboot requests
//! enter the same gate's bounded shutdown grace before writing `WDT_SWRST`.
//!
//! Register facts have two independent grounds. The MT6739 vendor device tree
//! places TOPRGU/WDT at `0x1000_7000`, and its WDT header defines the offsets and
//! write keys below. Mainline Linux's `drivers/watchdog/mtk_wdt.c` independently
//! matches those offsets and keys, while correctly obtaining the base from the
//! platform resource rather than hard-coding a `SoC` address.
//!
//! WHY the citation is explicit here rather than "per BSP reference": every sibling
//! driver in this crate names its source file and line, and this one named a category
//! instead. A provenance audit could not verify the constants from this crate alone
//! and flagged it — not because anything looked copied, but because an unverifiable
//! claim and a false one are indistinguishable from the outside.
//!
//! | Offset | Register      | Description                                    |
//! |--------|---------------|------------------------------------------------|
//! | 0x00   | `WDT_MODE`    | Enable, IRQ/dual, and platform reset policy     |
//! | 0x04   | `WDT_LENGTH`  | Timeout value (encoded, see below)             |
//! | 0x08   | `WDT_RESTART` | Write 0x1971 to reset the countdown            |
//! | 0x0C   | `WDT_STATUS`  | Reset cause; HW/SW/IRQ WDT are bits 31/30/29   |
//! | 0x14   | `WDT_SWRST`   | Write 0x1209 to request a software reset       |
//!
//! Timeout encoding (`WDT_LENGTH)`:
//!   bits [15:5] = timeout in units of 512/32768 s ≈ 15.6 ms per unit
//!   bits [4:0]  = key (must be 0x08 to commit the write)
//!
//! For a 5-second timeout: 5 / (512/32768) ≈ 320 units → 320 << 5 | 0x08.
//!
//! `WDT_MODE` fields used here:
//!   bit 0  = `WDT_EN` (1 = enabled)
//!   bit 3  = `WDT_IRQ` (interrupt mode; cleared during initialization)
//!   bit 6  = `WDT_DUAL_MODE` (IRQ followed by reset; left clear here)
//!   write key = `0x2200_0000` (required on every mode write)
//!
//! The MT6739 vendor and mainline drivers both update `WDT_MODE` with a
//! read-modify-write. Thumos owns enable plus the IRQ/dual selection and
//! preserves every other field, including boot-platform reset policy.
//!
//! WHY 5-second timeout: long enough for the scheduler to complete a full
//! tick cycle even under heavy load, short enough to recover from a hang
//! before userspace notices a frozen system.
//!
//! [MT6739 device tree]: https://github.com/fukehan/kernel-4.4/blob/b698b8dbb7fb0c7326a1121bbce72fdd3db6d3d8/arch/arm/boot/dts/mt6739.dts#L464-L468
//! [MT6739 WDT header]: https://github.com/fukehan/kernel-4.4/blob/b698b8dbb7fb0c7326a1121bbce72fdd3db6d3d8/drivers/watchdog/mediatek/wdt/common/wdt_v1/mtk_wdt.h#L17-L62
//! [MT6739 mode update]: https://github.com/fukehan/kernel-4.4/blob/b698b8dbb7fb0c7326a1121bbce72fdd3db6d3d8/drivers/watchdog/mediatek/wdt/common/wdt_v1/mtk_wdt_v1.c#L194-L266
//! [mainline WDT constants]: https://github.com/torvalds/linux/blob/98f21c54f99519329c18e2625b0ea6db14524d09/drivers/watchdog/mtk_wdt.c#L37-L57
//! [mainline mode update]: https://github.com/torvalds/linux/blob/98f21c54f99519329c18e2625b0ea6db14524d09/drivers/watchdog/mtk_wdt.c#L301-L336

use crate::mmio;

/// WDT register base address for MT6739.
/// WHY: `0x1000_7000` is the documented WDT base in the MT6739 BSP and matches
/// the typical MTK layout for this `SoC` family. Verify against your specific
/// BSP header (wdt.h or `mach/mt_wdt.h`) if porting to a different MT variant.
/// `WDT_MODE`: enable/disable and mode control.
const WDT_MODE: usize = crate::board::WDT_BASE;

/// `WDT_LENGTH`: timeout value register.
const WDT_LENGTH: usize = crate::board::WDT_BASE + 0x04;

/// `WDT_RESTART`: write 0x1971 here to pet the watchdog.
const WDT_RESTART: usize = crate::board::WDT_BASE + 0x08;

/// `WDT_SWRST`: write 0x1209 here to request a whole-system reset.
const WDT_SWRST: usize = crate::board::WDT_BASE + 0x14;

/// Magic value required to pet (restart) the watchdog countdown.
const WDT_RESTART_KEY: u32 = 0x1971;

/// Magic value required to request a software reset.
const WDT_SWRST_KEY: u32 = 0x1209;

/// `WDT_MODE` enable bit (bit 0).
const WDT_MODE_EN: u32 = 1 << 0;

/// `WDT_MODE` interrupt-mode bit (bit 3).
const WDT_MODE_IRQ: u32 = 1 << 3;

/// `WDT_MODE` dual IRQ-then-reset bit (bit 6).
const WDT_MODE_DUAL_MODE: u32 = 1 << 6;

/// `WDT_MODE` write key: must accompany every mode-register write.
const WDT_MODE_KEY: u32 = 0x2200_0000;

/// Fields initialization intentionally controls.
const WDT_MODE_INIT_FIELDS: u32 = WDT_MODE_EN | WDT_MODE_IRQ | WDT_MODE_DUAL_MODE;

/// Build a non-IRQ reset-mode write while preserving platform-owned fields.
const fn mode_enable_value(current: u32) -> u32 {
    (current & !WDT_MODE_INIT_FIELDS) | WDT_MODE_KEY | WDT_MODE_EN
}

/// Build a disable write while preserving every field except enable.
const fn mode_disable_value(current: u32) -> u32 {
    (current & !WDT_MODE_EN) | WDT_MODE_KEY
}

/// `WDT_LENGTH` key bits [4:0]: must be 0x08 to commit a length write.
const WDT_LENGTH_KEY: u64 = 0x08;

/// `WDT_LENGTH` advances at 64 units per second (32768 / 512).
const WDT_UNITS_PER_SECOND: u64 = 64;

/// Timeout units mechanically derived from the canonical watchdog duration.
const WDT_TIMEOUT_UNITS: u64 = crate::liveness::WATCHDOG_TIMEOUT_SECONDS * WDT_UNITS_PER_SECOND;

/// Encoded `WDT_LENGTH` register value: timeout units in [15:5] | key in [4:0].
const WDT_LENGTH_VAL: u64 = (WDT_TIMEOUT_UNITS << 5) | WDT_LENGTH_KEY;

// `WDT_LENGTH` has eleven timeout bits. Reject a canonical duration that the
// physical register cannot represent instead of truncating it at the write.
const _: () = assert!(WDT_TIMEOUT_UNITS <= 0x07ff);

/// Narrow the statically range-checked timeout encoding for the 32-bit MMIO.
fn wdt_length_value() -> u32 {
    u32::try_from(WDT_LENGTH_VAL).unwrap_or_else(|_| {
        unreachable!("WDT_LENGTH encoding was compile-time checked to fit in 16 bits")
    })
}

/// Initialize the hardware watchdog with a 5-second timeout and start it.
///
/// Must be called once during kernel init after MMIO identity-mapping is
/// established (i.e., after `mmu::init_and_enable()`).
///
/// # Safety
///
/// Writes to MMIO registers at the MT6739 WDT base address. Safe only
/// after the MMU has identity-mapped device MMIO (which includes `0x1000_7000`).
pub unsafe fn init() {
    // SAFETY: WDT_LENGTH and WDT_MODE are MMIO registers at the MT6739 WDT base,
    // identity-mapped as device memory by mmu::init_and_enable(). Write ordering
    // is enforced by write_volatile inside mmio::write32. Setting length before
    // enabling prevents a brief window where WDT is enabled with an undefined
    // timeout value.
    unsafe {
        // Step 1: program timeout before enabling
        mmio::write32(WDT_LENGTH, wdt_length_value());
        // Start the new interval from a known full countdown. Mainline does
        // the same restart write after programming WDT_LENGTH.
        mmio::write32(WDT_RESTART, WDT_RESTART_KEY);

        // Step 2: enable WDT on the reset path, without an IRQ pretimeout.
        // WHY: clear only the IRQ/dual fields Thumos deliberately owns. The
        // bootloader may have configured external-reset polarity, bypass-power-key,
        // or counter-selection policy; both cited drivers preserve those fields.
        let current_mode = mmio::read32(WDT_MODE);
        mmio::write32(WDT_MODE, mode_enable_value(current_mode));
    }
}

/// Pet (restart) the watchdog, resetting the countdown to 5 seconds.
///
/// Called only after the liveness gate accepts fresh scheduler and service-loop
/// evidence, or while its bounded controlled-shutdown grace remains active.
///
/// # Safety
///
/// Writes to the `WDT_RESTART` MMIO register. Safe after `init()` has
/// been called and the MMU has identity-mapped device MMIO.
pub unsafe fn pet() {
    // SAFETY: WDT_RESTART is a write-only MMIO register; writing 0x1971 resets
    // the countdown. No side effects beyond resetting the timer.
    unsafe {
        mmio::write32(WDT_RESTART, WDT_RESTART_KEY);
    }
}

/// Observe a timer tick for parity with the QEMU watchdog model.
///
/// WHY: MT6739 hardware advances its own countdown. The QEMU backend needs an
/// explicit tick observation to model that autonomous behavior; retaining the
/// same call surface keeps the timer IRQ board-neutral.
///
/// # Safety
///
/// Must be called from the timer IRQ, matching the QEMU backend's exclusive
/// model ownership. This hardware implementation performs no memory access.
pub unsafe fn observe_tick(_now: u64) {}

/// Request an immediate whole-system reboot through the watchdog block.
///
/// The caller must enter the bounded liveness shutdown grace before invoking
/// this operation. If the reset write fails to take effect, ordinary timer
/// IRQs keep servicing that grace until it expires, after which the watchdog
/// countdown is deliberately allowed to reset the device.
///
/// # Safety
///
/// Writes MT6739 watchdog MMIO. Safe after [`init`] and MMIO mapping.
pub unsafe fn request_reboot() {
    // SAFETY: both addresses are registers in the mapped MT6739 watchdog
    // block. Reasserting enabled reset mode preserves platform-owned fields;
    // WDT_SWRST accepts only its documented key.
    unsafe {
        let current_mode = mmio::read32(WDT_MODE);
        mmio::write32(WDT_MODE, mode_enable_value(current_mode));
        mmio::write32(WDT_SWRST, WDT_SWRST_KEY);
    }
}

/// Disable the hardware watchdog.
///
/// Used during controlled shutdown or power-off sequences where the
/// watchdog firing would cause an unintended reboot.
///
/// # Safety
///
/// Writes to `WDT_MODE`. Safe after `init()` has been called.
pub unsafe fn disable() {
    // SAFETY: WDT_MODE is a readable MMIO register at the MT6739 WDT base.
    // The read-modify-write clears only WDT_MODE_EN and carries the full key.
    unsafe {
        let current_mode = mmio::read32(WDT_MODE);
        mmio::write32(WDT_MODE, mode_disable_value(current_mode));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that the WDT register addresses are at their expected offsets
    /// from the documented base.
    #[test]
    fn watchdog_register_addresses() {
        assert_eq!(WDT_MODE, 0x1000_7000, "WDT_MODE must be at base + 0x00");
        assert_eq!(WDT_LENGTH, 0x1000_7004, "WDT_LENGTH must be at base + 0x04");
        assert_eq!(
            WDT_RESTART, 0x1000_7008,
            "WDT_RESTART must be at base + 0x08"
        );
        assert_eq!(WDT_SWRST, 0x1000_7014, "WDT_SWRST must be at base + 0x14");
    }

    /// Verify the pet magic value matches the MT6739 BSP specification.
    #[test]
    fn watchdog_pet_writes_restart_register() {
        // WHY: the magic value 0x1971 is required by the MT6739 WDT hardware
        // to accept a restart command. Any other value is ignored.
        assert_eq!(WDT_RESTART_KEY, 0x1971, "WDT_RESTART_KEY must be 0x1971");
        assert_eq!(
            WDT_SWRST_KEY, 0x1209,
            "WDT_SWRST_KEY must match the MT6739 software-reset key"
        );
    }

    /// Verify mode writes carry the full key and preserve unowned policy.
    #[test]
    fn watchdog_mode_values_preserve_platform_fields() {
        assert_eq!(
            WDT_MODE_KEY, 0x2200_0000,
            "WDT_MODE writes must carry the full 0x22000000 key"
        );

        let platform_fields = (1 << 1) | (1 << 2) | (1 << 4) | (1 << 8);
        let current = platform_fields | WDT_MODE_EN | WDT_MODE_IRQ | WDT_MODE_DUAL_MODE;
        assert_eq!(
            mode_enable_value(current),
            platform_fields | WDT_MODE_KEY | WDT_MODE_EN,
            "enable must clear IRQ/dual and preserve every platform field"
        );
        assert_eq!(
            mode_disable_value(current),
            platform_fields | WDT_MODE_IRQ | WDT_MODE_DUAL_MODE | WDT_MODE_KEY,
            "disable must clear only enable and preserve every other field"
        );
        assert_eq!(
            WDT_MODE_KEY & WDT_MODE_DUAL_MODE,
            0,
            "bit 6 is DUAL_MODE, not the mode write key"
        );
    }

    /// Verify the encoded timeout value is correct for a 5-second timeout.
    #[test]
    fn watchdog_timeout_encoding_is_5_seconds() {
        // Each WDT unit = 512 / 32768 Hz = 15.625 ms
        // 5000 ms / 15.625 ms = 320 units
        assert_eq!(
            WDT_TIMEOUT_UNITS, 320,
            "5-second timeout must encode to 320 WDT units"
        );
        // Verify the key is correct
        assert_eq!(WDT_LENGTH_KEY, 0x08, "WDT_LENGTH write key must be 0x08");
        // Verify the full encoded value
        assert_eq!(
            wdt_length_value(),
            (320u32 << 5) | 0x08,
            "WDT_LENGTH_VAL must be timeout_units<<5 | 0x08"
        );
    }
}
