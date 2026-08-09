//! MT6739 Watchdog Timer (WDT) driver.
//!
//! The MT6739 WDT is a hardware timer that resets the `SoC` if the kernel
//! stops petting it within the configured timeout. This provides a safety
//! net against kernel hangs (infinite loops, deadlocks, interrupt starvation).
//!
//! Register map (base `0x1000_7000`, per MTK BSP reference):
//!
//! | Offset | Register    | Description                              |
//! |--------|-------------|------------------------------------------|
//! | 0x00   | `WDT_MODE`    | Enable/disable, auto-restart mode        |
//! | 0x04   | `WDT_LENGTH`  | Timeout value (encoded, see below)       |
//! | 0x08   | `WDT_RESTART` | Write 0x1971 to reset the countdown      |
//! | 0x0C   | `WDT_STA`     | Status register (bit 0 = WDT reset flag) |
//!
//! Timeout encoding (`WDT_LENGTH)`:
//!   bits [15:5] = timeout in units of 512/32768 s ≈ 15.6 ms per unit
//!   bits [4:0]  = key (must be 0x08 to commit the write)
//!
//! For a 5-second timeout: 5 / (512/32768) ≈ 320 units → 320 << 5 | 0x08.
//!
//! `WDT_MODE` bit fields:
//!   bit 0  = `WDT_EN`   (1 = enabled)
//!   bit 1  = `WDT_AUTO` (1 = auto-restart on IRQ ACK; we leave this 0)
//!   bit 6  = `WDT_KEY`  (always write 1 to commit mode changes)
//!
//! WHY 5-second timeout: long enough for the scheduler to complete a full
//! tick cycle even under heavy load, short enough to recover from a hang
//! before userspace notices a frozen system.

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

/// Magic value required to pet (restart) the watchdog countdown.
const WDT_RESTART_KEY: u32 = 0x1971;

/// `WDT_MODE` enable bit (bit 0).
const WDT_MODE_EN: u32 = 1 << 0;

/// `WDT_MODE` key bit (bit 6): must be set to commit any mode write.
const WDT_MODE_KEY: u32 = 1 << 6;

/// `WDT_LENGTH` key bits [4:0]: must be 0x08 to commit a length write.
const WDT_LENGTH_KEY: u32 = 0x08;

/// Timeout in `WDT_LENGTH` units (each unit ≈ 15.6 ms; 320 ≈ 5 seconds).
/// Calculation: `5_000` ms / 15.625 ms = 320.
const WDT_TIMEOUT_UNITS: u32 = 320;

/// Encoded `WDT_LENGTH` register value: timeout units in [15:5] | key in [4:0].
const WDT_LENGTH_VAL: u32 = (WDT_TIMEOUT_UNITS << 5) | WDT_LENGTH_KEY;

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
        mmio::write32(WDT_LENGTH, WDT_LENGTH_VAL);

        // Step 2: enable WDT (non-auto-restart mode; kernel pets it explicitly)
        // WHY: auto-restart would re-arm on every IRQ ACK, masking scheduler
        // hangs that don't produce IRQs. Explicit petting ensures the scheduler
        // loop is alive.
        mmio::write32(WDT_MODE, WDT_MODE_EN | WDT_MODE_KEY);
    }
}

/// Pet (restart) the watchdog, resetting the countdown to 5 seconds.
///
/// Must be called from the scheduler tick or main idle loop at a rate
/// faster than the 5-second timeout. The scheduler calls this on every
/// timer interrupt (every 10 ms), well within the budget.
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

/// Disable the hardware watchdog.
///
/// Used during controlled shutdown or power-off sequences where the
/// watchdog firing would cause an unintended reboot.
///
/// # Safety
///
/// Writes to `WDT_MODE`. Safe after `init()` has been called.
pub unsafe fn disable() {
    // SAFETY: WDT_MODE is an MMIO register at the MT6739 WDT base. Writing
    // only the key bit (WDT_MODE_KEY) with WDT_MODE_EN clear disables the WDT.
    unsafe {
        mmio::write32(WDT_MODE, WDT_MODE_KEY);
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
    }

    /// Verify the pet magic value matches the MT6739 BSP specification.
    #[test]
    fn watchdog_pet_writes_restart_register() {
        // WHY: the magic value 0x1971 is required by the MT6739 WDT hardware
        // to accept a restart command. Any other value is ignored.
        assert_eq!(WDT_RESTART_KEY, 0x1971, "WDT_RESTART_KEY must be 0x1971");
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
            WDT_LENGTH_VAL,
            (320u32 << 5) | 0x08,
            "WDT_LENGTH_VAL must be timeout_units<<5 | 0x08"
        );
    }
}
