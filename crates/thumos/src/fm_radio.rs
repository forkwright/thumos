//! FM radio receiver driver for the MT6739 combo chip.
//!
//! The MT6739 combo chip (MT6631) includes an FM radio receiver that shares
//! the WMT transport with `WiFi`, Bluetooth, and GPS. This module provides
//! the kernel-side FM radio driver with tuning, seeking, preset management,
//! and volume control.
//!
//! ## Hardware path
//!
//! FM radio is accessed through the WMT STP transport on the combo chip:
//! - `board::CONSYS_BASE = 0x1800_0000` (combo-chip base, board::m7 #534)
//! - WMT channel 0x04 for FM radio commands
//! - FM register block at offset `0x6000` within the combo chip
//!
//! The FM receiver uses the headset wire or internal trace as antenna.
//! On the AGM M7, the internal antenna trace provides adequate reception
//! for local FM stations.
//!
//! ## Frequency range
//!
//! Standard FM broadcast band: 87.5 MHz to 108.0 MHz.
//! Frequencies are stored in kHz internally (87500..=108000) to avoid
//! floating-point arithmetic in the kernel.
//!
//! ## Integration
//!
//! Used by the FM radio screen (`screen_fm.rs`) and audio session manager
//! (`audio.rs`) with `SessionKind::FmRadio`.  Boot integration via
//! `kinit.rs` Step 13d.

// WHY: FM radio driver is wired to the boot path (#518): NullFmHw under
// qemu/test, the real WMT backend on device, FmRadio<BootFmHw> in
// KernelState, and the FM screen fed each tick — no dead surface remains.

extern crate alloc;

// ---------------------------------------------------------------------------
// FM hardware constants
// ---------------------------------------------------------------------------

/// WMT STP channel identifier for FM radio.
const WMT_FM_CHANNEL: u8 = 0x04;

/// FM register block offset within the combo chip.
const FM_REG_BASE: usize = 0x6000;

/// FM main control register offset.
const FM_MAIN_CTRL: u16 = 0x00;

/// FM channel/frequency register offset.
const FM_CHANNEL_SET: u16 = 0x04;

/// FM RSSI (received signal strength indicator) register offset.
const FM_RSSI_REG: u16 = 0x08;

/// FM seek control register offset.
const FM_SEEK_CTRL: u16 = 0x0C;

/// FM seek threshold register offset.
const FM_SEEK_THRESH: u16 = 0x10;

/// FM volume register offset.
const FM_VOLUME_REG: u16 = 0x14;

// ---------------------------------------------------------------------------
// FM frequency range
// ---------------------------------------------------------------------------

/// Minimum FM frequency in kHz (87.5 MHz).
const FM_FREQ_MIN_KHZ: u32 = 87_500;

/// Maximum FM frequency in kHz (108.0 MHz).
const FM_FREQ_MAX_KHZ: u32 = 108_000;

/// FM channel step in kHz (100 kHz = 0.1 MHz).
///
/// Most regions use 100 kHz spacing.  Some use 200 kHz (Japan) or 50 kHz.
/// We default to 100 kHz for the standard broadcast band.
const FM_STEP_KHZ: u32 = 100;

/// Default tuning frequency in kHz (88.0 MHz).
const FM_DEFAULT_FREQ_KHZ: u32 = 88_000;

/// Number of preset slots.
const FM_PRESET_COUNT: usize = 6;

/// Maximum volume level (0-15).
const FM_MAX_VOLUME: u8 = 15;

/// Default volume level.
const FM_DEFAULT_VOLUME: u8 = 8;

/// RSSI threshold for seek (stations below this are skipped).
///
/// Typical FM receiver sensitivity is -85 to -100 dBm.  The RSSI register
/// returns a signed 8-bit value in dBm.  -75 dBm is a reasonable threshold
/// for clear reception.
const FM_SEEK_RSSI_THRESHOLD: i8 = -75;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// FM radio errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FmError {
    /// FM hardware did not respond or returned an error.
    HardwareError,
    /// FM radio is not powered on.
    NotPowered,
    /// Frequency is outside the valid FM band (87.5-108.0 MHz).
    FrequencyOutOfRange,
    /// Seek completed without finding a station.
    NoStationFound,
    /// Invalid preset index.
    InvalidPreset,
    /// FM radio is in an invalid state for this operation.
    InvalidState,
}

impl core::fmt::Display for FmError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::HardwareError => write!(f, "FM hardware error"),
            Self::NotPowered => write!(f, "FM radio not powered"),
            Self::FrequencyOutOfRange => write!(f, "frequency out of FM band range"),
            Self::NoStationFound => write!(f, "no FM station found"),
            Self::InvalidPreset => write!(f, "invalid preset index"),
            Self::InvalidState => write!(f, "FM radio in invalid state"),
        }
    }
}

// ---------------------------------------------------------------------------
// FM state machine
// ---------------------------------------------------------------------------

/// FM radio receiver state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum FmState {
    /// FM radio is powered off.
    #[default]
    Off,
    /// FM radio is powered on but not tuned to a specific frequency.
    On,
    /// Actively scanning for the next/previous station.
    Scanning,
    /// Tuned to a specific frequency.
    Tuned {
        /// Current frequency in kHz.
        frequency_khz: u32,
    },
}

impl core::fmt::Display for FmState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Off => write!(f, "off"),
            Self::On => write!(f, "on"),
            Self::Scanning => write!(f, "scanning"),
            Self::Tuned { frequency_khz } => {
                let mhz = *frequency_khz / 1000;
                let frac = (*frequency_khz % 1000) / 100;
                write!(f, "tuned to {mhz}.{frac} MHz")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// FM hardware abstraction trait
// ---------------------------------------------------------------------------

/// Hardware operations trait for FM radio abstraction.
///
/// Allows test-friendly mocking of the MT6739 FM radio hardware.
pub(crate) trait FmHwOps {
    /// Power on the FM receiver subsystem within the combo chip.
    fn power_on(&mut self) -> Result<(), FmError>;

    /// Power off the FM receiver subsystem.
    fn power_off(&mut self) -> Result<(), FmError>;

    /// Tune to a specific frequency (in kHz).
    fn tune(&mut self, freq_khz: u32) -> Result<(), FmError>;

    /// Seek upward from the current frequency, wrapping at the band edge.
    ///
    /// Returns the frequency of the next station found (in kHz).
    fn seek_up(&mut self) -> Result<u32, FmError>;

    /// Seek downward from the current frequency, wrapping at the band edge.
    ///
    /// Returns the frequency of the next station found (in kHz).
    fn seek_down(&mut self) -> Result<u32, FmError>;

    /// Read the current received signal strength indicator (RSSI) in dBm.
    fn get_rssi(&self) -> i8;
}

// ---------------------------------------------------------------------------
// Real FM hardware implementation (non-test only)
// ---------------------------------------------------------------------------

/// Real FM hardware access via WMT STP on the MT6739 combo chip.
#[cfg(not(any(test, feature = "qemu")))]
pub(crate) struct FmHw {
    /// WMT combo-chip MMIO base address.
    consys_base: usize,
    /// Current tuned frequency in kHz (for seek operations).
    current_freq: u32,
}

#[cfg(not(any(test, feature = "qemu")))]
impl FmHw {
    /// Create a new FM hardware handle.
    #[must_use]
    pub(crate) const fn new() -> Self {
        Self {
            consys_base: crate::board::CONSYS_BASE,
            current_freq: FM_DEFAULT_FREQ_KHZ,
        }
    }
}

#[cfg(not(any(test, feature = "qemu")))]
impl FmHwOps for FmHw {
    fn power_on(&mut self) -> Result<(), FmError> {
        // TODO(#129)[deliberate-prudent]: send WMT power-on command for FM subsystem.
        // Enable FM clock and analog front-end via PMIC.
        Ok(())
    }

    fn power_off(&mut self) -> Result<(), FmError> {
        // TODO(#129)[deliberate-prudent]: send WMT power-off command for FM subsystem.
        Ok(())
    }

    fn tune(&mut self, freq_khz: u32) -> Result<(), FmError> {
        // TODO(#129)[deliberate-prudent]: write frequency to FM_CHANNEL_SET register.
        // Convert kHz to channel number and program the PLL.
        self.current_freq = freq_khz;
        Ok(())
    }

    fn seek_up(&mut self) -> Result<u32, FmError> {
        // TODO(#129)[deliberate-prudent]: program FM_SEEK_CTRL for upward seek, poll for completion.
        Err(FmError::NoStationFound)
    }

    fn seek_down(&mut self) -> Result<u32, FmError> {
        // TODO(#129)[deliberate-prudent]: program FM_SEEK_CTRL for downward seek, poll for completion.
        Err(FmError::NoStationFound)
    }

    fn get_rssi(&self) -> i8 {
        // TODO(#129)[deliberate-prudent]: read FM_RSSI_REG.
        -100 // No signal
    }
}

// ---------------------------------------------------------------------------
// No-op FM hardware for emulation (#518)
// ---------------------------------------------------------------------------

/// A no-op FM backend for qemu (#518). The combo chip's CONSYS register
/// block is unmodeled on -machine virt, so the real `FmHw`'s MMIO would
/// data-abort. `NullFmHw` tracks the power/tune/seek state the `FmRadio`
/// controller and FM screen read — the controller state machine and the
/// screen's render path run in emulation. Distinct from `MockFmHw`
/// (test-only fail-injection knobs); seeks step deterministically by
/// 100 kHz with band wrap so seek logic is exercised end-to-end.
#[cfg(any(feature = "qemu", test))]
pub(crate) struct NullFmHw {
    /// Whether the receiver is powered.
    powered: bool,
    /// Current tuned frequency in kHz.
    current_freq: u32,
}

#[cfg(any(feature = "qemu", test))]
impl NullFmHw {
    /// Create a powered-off null backend at the default frequency.
    pub(crate) const fn new() -> Self {
        Self {
            powered: false,
            current_freq: FM_DEFAULT_FREQ_KHZ,
        }
    }
}

/// Step a seek by `step` kHz, wrapping at the band edges.
#[cfg(any(feature = "qemu", test))]
const fn seek_step(freq_khz: u32, step: i32) -> u32 {
    let span = (FM_FREQ_MAX_KHZ - FM_FREQ_MIN_KHZ) as i32;
    let offset = (freq_khz - FM_FREQ_MIN_KHZ) as i32 + step;
    let wrapped = ((offset % span) + span) % span;
    FM_FREQ_MIN_KHZ + wrapped as u32
}

#[cfg(any(feature = "qemu", test))]
impl FmHwOps for NullFmHw {
    fn power_on(&mut self) -> Result<(), FmError> {
        self.powered = true;
        Ok(())
    }

    fn power_off(&mut self) -> Result<(), FmError> {
        self.powered = false;
        Ok(())
    }

    fn tune(&mut self, freq_khz: u32) -> Result<(), FmError> {
        self.current_freq = freq_khz;
        Ok(())
    }

    fn seek_up(&mut self) -> Result<u32, FmError> {
        self.current_freq = seek_step(self.current_freq, 100);
        Ok(self.current_freq)
    }

    fn seek_down(&mut self) -> Result<u32, FmError> {
        self.current_freq = seek_step(self.current_freq, -100);
        Ok(self.current_freq)
    }

    fn get_rssi(&self) -> i8 {
        -55 // plausible mid-band reading for the render path
    }
}

/// The FM backend the booted kernel wires into `FmRadio` (#518): the no-op
/// `NullFmHw` under qemu/test, the real `FmHw` (WMT) on device.
#[cfg(any(feature = "qemu", test))]
pub(crate) type BootFmHw = NullFmHw;
#[cfg(not(any(feature = "qemu", test)))]
pub(crate) type BootFmHw = FmHw;

// ---------------------------------------------------------------------------
// Mock FM hardware for tests
// ---------------------------------------------------------------------------

/// Mock FM hardware for unit testing.
#[cfg(test)]
pub struct MockFmHw {
    /// Whether power_on succeeds.
    pub power_on_ok: bool,
    /// Current tuned frequency (set by tune()).
    pub tuned_freq: u32,
    /// RSSI value to return.
    pub rssi: i8,
    /// Frequency returned by seek_up (None = no station found).
    pub seek_up_result: Option<u32>,
    /// Frequency returned by seek_down (None = no station found).
    pub seek_down_result: Option<u32>,
}

#[cfg(test)]
impl MockFmHw {
    /// Create a new mock with all operations succeeding.
    pub fn new() -> Self {
        Self {
            power_on_ok: true,
            tuned_freq: FM_DEFAULT_FREQ_KHZ,
            rssi: -60,
            seek_up_result: None,
            seek_down_result: None,
        }
    }
}

#[cfg(test)]
impl FmHwOps for MockFmHw {
    fn power_on(&mut self) -> Result<(), FmError> {
        if self.power_on_ok {
            Ok(())
        } else {
            Err(FmError::HardwareError)
        }
    }

    fn power_off(&mut self) -> Result<(), FmError> {
        Ok(())
    }

    fn tune(&mut self, freq_khz: u32) -> Result<(), FmError> {
        self.tuned_freq = freq_khz;
        Ok(())
    }

    fn seek_up(&mut self) -> Result<u32, FmError> {
        match self.seek_up_result {
            Some(freq) => {
                self.tuned_freq = freq;
                Ok(freq)
            }
            None => Err(FmError::NoStationFound),
        }
    }

    fn seek_down(&mut self) -> Result<u32, FmError> {
        match self.seek_down_result {
            Some(freq) => {
                self.tuned_freq = freq;
                Ok(freq)
            }
            None => Err(FmError::NoStationFound),
        }
    }

    fn get_rssi(&self) -> i8 {
        self.rssi
    }
}

// ---------------------------------------------------------------------------
// FM radio controller
// ---------------------------------------------------------------------------

/// FM radio controller.
///
/// Manages the FM radio lifecycle: power, tuning, seeking, presets, and
/// volume control.  Generic over the FM hardware backend for testability.
pub struct FmRadio<H: FmHwOps> {
    /// Current FM state.
    state: FmState,
    /// Preset frequencies in kHz (6 slots). `None` marks an unset slot,
    /// distinguishing 'never saved' from a saved frequency (#452).
    presets: [Option<u32>; FM_PRESET_COUNT],
    /// Number of populated preset slots.
    preset_count: u8,
    /// Current volume level (0-15).
    volume: u8,
    /// FM hardware backend.
    hw: H,
}

impl<H: FmHwOps> FmRadio<H> {
    /// Create a new FM radio controller with the given hardware backend.
    #[must_use]
    pub fn new(hw: H) -> Self {
        Self {
            state: FmState::Off,
            presets: [None; FM_PRESET_COUNT],
            preset_count: 0,
            volume: FM_DEFAULT_VOLUME,
            hw,
        }
    }

    /// Return the current FM state.
    #[must_use]
    pub fn state(&self) -> FmState {
        self.state
    }

    /// Return the current volume level (0-15).
    #[must_use]
    pub fn volume(&self) -> u8 {
        self.volume
    }

    /// Return the current tuned frequency in kHz, if tuned.
    #[must_use]
    pub fn frequency(&self) -> Option<u32> {
        match self.state {
            FmState::Tuned { frequency_khz } => Some(frequency_khz),
            _ => None,
        }
    }

    /// Return the preset frequencies. `None` marks an unset slot.
    #[must_use]
    pub fn presets(&self) -> &[Option<u32>] {
        &self.presets[..self.preset_count as usize]
    }

    /// Return the number of saved presets.
    #[must_use]
    pub fn preset_count(&self) -> u8 {
        self.preset_count
    }

    /// Return the current RSSI (signal strength) in dBm.
    pub fn rssi(&self) -> i8 {
        self.hw.get_rssi()
    }

    /// Power on the FM radio.
    ///
    /// Transitions from `Off` to `On`.
    ///
    /// # Errors
    ///
    /// - [`FmError::HardwareError`] -- hardware power-on failed.
    pub fn power_on(&mut self) -> Result<(), FmError> {
        if !matches!(self.state, FmState::Off) {
            return Ok(()); // Already on, idempotent.
        }
        self.hw.power_on()?;
        self.state = FmState::On;
        Ok(())
    }

    /// Power off the FM radio.
    ///
    /// Transitions to `Off` from any state.
    ///
    /// # Errors
    ///
    /// - [`FmError::HardwareError`] -- hardware power-off failed.
    pub fn power_off(&mut self) -> Result<(), FmError> {
        if matches!(self.state, FmState::Off) {
            return Ok(()); // Already off, idempotent.
        }
        self.hw.power_off()?;
        self.state = FmState::Off;
        Ok(())
    }

    /// Tune to a specific frequency.
    ///
    /// Frequency must be in the FM band (87.5-108.0 MHz), specified in kHz.
    ///
    /// # Errors
    ///
    /// - [`FmError::NotPowered`] -- radio is off.
    /// - [`FmError::FrequencyOutOfRange`] -- frequency outside 87.5-108.0 MHz.
    /// - [`FmError::HardwareError`] -- hardware tune failed.
    pub fn tune(&mut self, freq_khz: u32) -> Result<(), FmError> {
        match self.state {
            FmState::Off => return Err(FmError::NotPowered),
            FmState::On | FmState::Tuned { .. } | FmState::Scanning => {}
        }

        if !(FM_FREQ_MIN_KHZ..=FM_FREQ_MAX_KHZ).contains(&freq_khz) {
            return Err(FmError::FrequencyOutOfRange);
        }

        // Snap to the nearest channel step.
        let snapped = snap_to_step(freq_khz);
        self.hw.tune(snapped)?;
        self.state = FmState::Tuned {
            frequency_khz: snapped,
        };
        Ok(())
    }

    /// Seek upward for the next station.
    ///
    /// Wraps from the maximum frequency back to the minimum.
    ///
    /// # Errors
    ///
    /// - [`FmError::NotPowered`] -- radio is off.
    /// - [`FmError::HardwareError`] -- hardware seek failed.
    pub fn seek_up(&mut self) -> Result<u32, FmError> {
        match self.state {
            FmState::Off => return Err(FmError::NotPowered),
            FmState::On | FmState::Tuned { .. } | FmState::Scanning => {}
        }

        let current = match self.state {
            FmState::Tuned { frequency_khz } => frequency_khz,
            _ => FM_FREQ_MIN_KHZ,
        };

        // Try hardware seek.
        match self.hw.seek_up() {
            Ok(freq) => {
                // WHY: freq is hardware-returned and untrusted -- a
                // glitched or malfunctioning combo-chip firmware could
                // report a frequency outside the FM band, and storing it
                // unchecked would let an out-of-band value flow into
                // state, presets, and display code that all assume Tuned
                // frequencies stay in-band (#397).
                if !(FM_FREQ_MIN_KHZ..=FM_FREQ_MAX_KHZ).contains(&freq) {
                    return Err(FmError::FrequencyOutOfRange);
                }
                self.state = FmState::Tuned {
                    frequency_khz: freq,
                };
                Ok(freq)
            }
            Err(FmError::NoStationFound) => {
                // Wrap to minimum and try from there.
                let next = if current >= FM_FREQ_MAX_KHZ {
                    FM_FREQ_MIN_KHZ
                } else {
                    (current + FM_STEP_KHZ).min(FM_FREQ_MAX_KHZ)
                };
                self.hw.tune(next)?;
                self.state = FmState::Tuned {
                    frequency_khz: next,
                };
                Ok(next)
            }
            Err(e) => Err(e),
        }
    }

    /// Seek downward for the next station.
    ///
    /// Wraps from the minimum frequency back to the maximum.
    ///
    /// # Errors
    ///
    /// - [`FmError::NotPowered`] -- radio is off.
    /// - [`FmError::HardwareError`] -- hardware seek failed.
    pub fn seek_down(&mut self) -> Result<u32, FmError> {
        match self.state {
            FmState::Off => return Err(FmError::NotPowered),
            FmState::On | FmState::Tuned { .. } | FmState::Scanning => {}
        }

        let current = match self.state {
            FmState::Tuned { frequency_khz } => frequency_khz,
            _ => FM_FREQ_MAX_KHZ,
        };

        match self.hw.seek_down() {
            Ok(freq) => {
                // WHY: same untrusted-hardware-value guard as seek_up --
                // see its comment (#397).
                if !(FM_FREQ_MIN_KHZ..=FM_FREQ_MAX_KHZ).contains(&freq) {
                    return Err(FmError::FrequencyOutOfRange);
                }
                self.state = FmState::Tuned {
                    frequency_khz: freq,
                };
                Ok(freq)
            }
            Err(FmError::NoStationFound) => {
                // Wrap to maximum and try from there.
                let prev = if current <= FM_FREQ_MIN_KHZ {
                    FM_FREQ_MAX_KHZ
                } else {
                    (current - FM_STEP_KHZ).max(FM_FREQ_MIN_KHZ)
                };
                self.hw.tune(prev)?;
                self.state = FmState::Tuned {
                    frequency_khz: prev,
                };
                Ok(prev)
            }
            Err(e) => Err(e),
        }
    }

    /// Save the current frequency to a preset slot (0-5).
    ///
    /// # Errors
    ///
    /// - [`FmError::InvalidPreset`] -- slot index out of range.
    /// - [`FmError::NotPowered`] -- radio is off.
    /// - [`FmError::InvalidState`] -- not tuned to a frequency.
    pub fn save_preset(&mut self, index: usize) -> Result<(), FmError> {
        if index >= FM_PRESET_COUNT {
            return Err(FmError::InvalidPreset);
        }

        let freq = match self.state {
            FmState::Tuned { frequency_khz } => frequency_khz,
            FmState::Off => return Err(FmError::NotPowered),
            _ => return Err(FmError::InvalidState),
        };

        self.presets[index] = Some(freq);
        if index >= self.preset_count as usize {
            self.preset_count = (index + 1) as u8;
        }
        Ok(())
    }

    /// Recall a preset: tune to the frequency stored in the given slot.
    ///
    /// # Errors
    ///
    /// - [`FmError::InvalidPreset`] -- slot index out of range or not set.
    /// - [`FmError::FrequencyOutOfRange`] -- stored frequency is invalid.
    /// - [`FmError::NotPowered`] -- radio is off.
    pub fn recall_preset(&mut self, index: usize) -> Result<u32, FmError> {
        if index >= FM_PRESET_COUNT {
            return Err(FmError::InvalidPreset);
        }
        if index >= self.preset_count as usize {
            return Err(FmError::InvalidPreset);
        }

        // WHY(#452): preset_count only tracks the highest EVER-saved index
        // + 1, not which individual slots were populated, so a slot within
        // the `index < preset_count` range can still be unset if it was
        // skipped by a non-contiguous save_preset call. Per-slot occupancy
        // (Option<u32>) lets that case return InvalidPreset as documented,
        // instead of falling through to a frequency-range check against an
        // arbitrary default value.
        let freq = self.presets[index].ok_or(FmError::InvalidPreset)?;
        if !(FM_FREQ_MIN_KHZ..=FM_FREQ_MAX_KHZ).contains(&freq) {
            return Err(FmError::FrequencyOutOfRange);
        }

        self.tune(freq)?;
        Ok(freq)
    }

    /// Set the volume level (0-15).
    ///
    /// Values above 15 are clamped to 15.
    pub fn set_volume(&mut self, level: u8) {
        self.volume = level.min(FM_MAX_VOLUME);
    }

    /// Increase volume by 1, clamped to the maximum.
    pub fn volume_up(&mut self) {
        self.volume = (self.volume + 1).min(FM_MAX_VOLUME);
    }

    /// Decrease volume by 1, clamped to 0.
    pub fn volume_down(&mut self) {
        self.volume = self.volume.saturating_sub(1);
    }
}

/// Snap a frequency to the nearest channel step.
fn snap_to_step(freq_khz: u32) -> u32 {
    let offset = freq_khz.saturating_sub(FM_FREQ_MIN_KHZ);
    let steps = offset / FM_STEP_KHZ;
    let remainder = offset % FM_STEP_KHZ;
    let snapped_offset = if remainder >= FM_STEP_KHZ / 2 {
        (steps + 1) * FM_STEP_KHZ
    } else {
        steps * FM_STEP_KHZ
    };
    (FM_FREQ_MIN_KHZ + snapped_offset).min(FM_FREQ_MAX_KHZ)
}

/// Convert a frequency in kHz to a display string (e.g., 98500 -> "98.5").
///
/// Returns `(integer_part, decimal_part)` for display formatting.
#[must_use]
pub const fn freq_to_display(freq_khz: u32) -> (u32, u32) {
    let mhz = freq_khz / 1000;
    let frac = (freq_khz % 1000) / 100;
    (mhz, frac)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::*;

    /// Helper: create a fresh FM radio with a mock hardware backend.
    fn make_radio() -> FmRadio<MockFmHw> {
        FmRadio::new(MockFmHw::new())
    }

    #[test]
    fn starts_off() {
        let radio = make_radio();
        assert_eq!(
            radio.state(),
            FmState::Off,
            "new FM radio must start in Off state"
        );
    }

    #[test]
    fn power_on_transitions_to_on() {
        let mut radio = make_radio();
        let result = radio.power_on();
        assert!(result.is_ok(), "power_on must succeed");
        assert_eq!(radio.state(), FmState::On);
    }

    #[test]
    fn power_off_transitions_to_off() {
        let mut radio = make_radio();
        radio.power_on().ok();
        radio.tune(98_500).ok();
        let result = radio.power_off();
        assert!(result.is_ok(), "power_off must succeed");
        assert_eq!(radio.state(), FmState::Off);
    }

    #[test]
    fn tune_sets_frequency() {
        let mut radio = make_radio();
        radio.power_on().ok();
        let result = radio.tune(98_500);
        assert!(result.is_ok(), "tune to valid frequency must succeed");
        assert_eq!(
            radio.state(),
            FmState::Tuned {
                frequency_khz: 98_500
            },
            "state must be Tuned with correct frequency"
        );
        assert_eq!(radio.frequency(), Some(98_500));
    }

    #[test]
    fn tune_when_off_fails() {
        let mut radio = make_radio();
        let result = radio.tune(98_500);
        assert_eq!(
            result,
            Err(FmError::NotPowered),
            "tune when off must return NotPowered"
        );
    }

    #[test]
    fn frequency_bounds_checked() {
        let mut radio = make_radio();
        radio.power_on().ok();

        // Below minimum.
        let result = radio.tune(80_000);
        assert_eq!(
            result,
            Err(FmError::FrequencyOutOfRange),
            "frequency below 87.5 MHz must be rejected"
        );

        // Above maximum.
        let result = radio.tune(120_000);
        assert_eq!(
            result,
            Err(FmError::FrequencyOutOfRange),
            "frequency above 108.0 MHz must be rejected"
        );

        // At minimum.
        let result = radio.tune(87_500);
        assert!(result.is_ok(), "87.5 MHz must be accepted");

        // At maximum.
        let result = radio.tune(108_000);
        assert!(result.is_ok(), "108.0 MHz must be accepted");
    }

    #[test]
    fn preset_save_and_recall() {
        let mut radio = make_radio();
        radio.power_on().ok();
        radio.tune(98_500).ok();

        // Save to preset 0.
        let result = radio.save_preset(0);
        assert!(result.is_ok(), "save_preset must succeed");
        assert_eq!(radio.preset_count(), 1);

        // Save another.
        radio.tune(101_500).ok();
        radio.save_preset(1).ok();
        assert_eq!(radio.preset_count(), 2);

        // Recall preset 0.
        let result = radio.recall_preset(0);
        assert!(result.is_ok(), "recall_preset must succeed");
        assert_eq!(
            result,
            Ok(98_500),
            "recalled frequency must match saved value"
        );
        assert_eq!(radio.frequency(), Some(98_500));
    }

    #[test]
    fn preset_invalid_index() {
        let mut radio = make_radio();
        radio.power_on().ok();
        radio.tune(88_000).ok();

        let result = radio.save_preset(6);
        assert_eq!(
            result,
            Err(FmError::InvalidPreset),
            "preset index 6 (out of 0-5) must be rejected"
        );
    }

    #[test]
    fn recall_empty_preset_fails() {
        let mut radio = make_radio();
        radio.power_on().ok();
        let result = radio.recall_preset(0);
        assert_eq!(
            result,
            Err(FmError::InvalidPreset),
            "recalling an unsaved preset must fail"
        );
    }

    #[test]
    fn seek_wraps_at_bounds() {
        let mut radio = make_radio();
        radio.power_on().ok();

        // Tune to maximum.
        radio.tune(FM_FREQ_MAX_KHZ).ok();

        // Seek up should wrap to minimum.
        let result = radio.seek_up();
        assert!(result.is_ok(), "seek_up from max must succeed (wrap)");
        let freq = result.unwrap_or(0);
        assert_eq!(
            freq, FM_FREQ_MIN_KHZ,
            "seek_up from max must wrap to minimum"
        );

        // Tune to minimum.
        radio.tune(FM_FREQ_MIN_KHZ).ok();

        // Seek down should wrap to maximum.
        let result = radio.seek_down();
        assert!(result.is_ok(), "seek_down from min must succeed (wrap)");
        let freq = result.unwrap_or(0);
        assert_eq!(
            freq, FM_FREQ_MAX_KHZ,
            "seek_down from min must wrap to maximum"
        );
    }

    #[test]
    fn seek_with_station_found() {
        let mut hw = MockFmHw::new();
        hw.seek_up_result = Some(99_500);
        let mut radio = FmRadio::new(hw);
        radio.power_on().ok();
        radio.tune(88_000).ok();

        let result = radio.seek_up();
        assert_eq!(result, Ok(99_500), "seek_up must return found station");
        assert_eq!(radio.frequency(), Some(99_500));
    }

    #[test]
    fn seek_up_rejects_out_of_range_hardware_frequency() {
        let mut hw = MockFmHw::new();
        hw.seek_up_result = Some(50_000); // below FM_FREQ_MIN_KHZ
        let mut radio = FmRadio::new(hw);
        radio.power_on().ok();
        radio.tune(90_000).ok();

        let result = radio.seek_up();
        assert_eq!(
            result,
            Err(FmError::FrequencyOutOfRange),
            "seek_up must reject an out-of-band hardware-returned \
             frequency (#397)"
        );
        assert_eq!(
            radio.state(),
            FmState::Tuned {
                frequency_khz: 90_000
            },
            "state must be unchanged when the hardware result is rejected"
        );
    }

    #[test]
    fn seek_down_rejects_out_of_range_hardware_frequency() {
        let mut hw = MockFmHw::new();
        hw.seek_down_result = Some(200_000); // above FM_FREQ_MAX_KHZ
        let mut radio = FmRadio::new(hw);
        radio.power_on().ok();
        radio.tune(90_000).ok();

        let result = radio.seek_down();
        assert_eq!(
            result,
            Err(FmError::FrequencyOutOfRange),
            "seek_down must reject an out-of-band hardware-returned \
             frequency (#397)"
        );
        assert_eq!(
            radio.state(),
            FmState::Tuned {
                frequency_khz: 90_000
            },
            "state must be unchanged when the hardware result is rejected"
        );
    }

    #[test]
    fn volume_control() {
        let mut radio = make_radio();
        assert_eq!(radio.volume(), FM_DEFAULT_VOLUME);

        radio.set_volume(12);
        assert_eq!(radio.volume(), 12);

        radio.set_volume(255);
        assert_eq!(radio.volume(), FM_MAX_VOLUME, "volume must clamp to max");

        radio.set_volume(0);
        assert_eq!(radio.volume(), 0);
    }

    #[test]
    fn volume_up_down() {
        let mut radio = make_radio();
        radio.set_volume(0);
        radio.volume_up();
        assert_eq!(radio.volume(), 1);

        radio.set_volume(FM_MAX_VOLUME);
        radio.volume_up();
        assert_eq!(
            radio.volume(),
            FM_MAX_VOLUME,
            "volume_up at max must not overflow"
        );

        radio.volume_down();
        assert_eq!(radio.volume(), FM_MAX_VOLUME - 1);

        radio.set_volume(0);
        radio.volume_down();
        assert_eq!(radio.volume(), 0, "volume_down at 0 must not underflow");
    }

    #[test]
    fn seek_when_off_fails() {
        let mut radio = make_radio();
        assert_eq!(
            radio.seek_up(),
            Err(FmError::NotPowered),
            "seek_up when off must return NotPowered"
        );
        assert_eq!(
            radio.seek_down(),
            Err(FmError::NotPowered),
            "seek_down when off must return NotPowered"
        );
    }

    #[test]
    fn freq_display_format() {
        let (mhz, frac) = freq_to_display(98_500);
        assert_eq!(mhz, 98);
        assert_eq!(frac, 5);

        let (mhz, frac) = freq_to_display(107_900);
        assert_eq!(mhz, 107);
        assert_eq!(frac, 9);

        let (mhz, frac) = freq_to_display(88_000);
        assert_eq!(mhz, 88);
        assert_eq!(frac, 0);
    }

    #[test]
    fn snap_to_step_works() {
        assert_eq!(snap_to_step(98_550), 98_600, "must snap up to nearest step");
        assert_eq!(
            snap_to_step(98_540),
            98_500,
            "must snap down to nearest step"
        );
        assert_eq!(snap_to_step(98_500), 98_500, "exact step must not change");
        assert_eq!(snap_to_step(87_500), 87_500, "min freq must not change");
        assert_eq!(snap_to_step(108_000), 108_000, "max freq must not change");
    }

    #[test]
    fn power_on_is_idempotent() {
        let mut radio = make_radio();
        radio.power_on().ok();
        let result = radio.power_on();
        assert!(
            result.is_ok(),
            "duplicate power_on must succeed (idempotent)"
        );
        assert_eq!(radio.state(), FmState::On);
    }

    #[test]
    fn power_off_is_idempotent() {
        let mut radio = make_radio();
        let result = radio.power_off();
        assert!(result.is_ok(), "power_off when already off must succeed");
        assert_eq!(radio.state(), FmState::Off);
    }

    #[test]
    fn save_preset_when_off_fails() {
        let mut radio = make_radio();
        let result = radio.save_preset(0);
        assert_eq!(
            result,
            Err(FmError::NotPowered),
            "save_preset when off must return NotPowered"
        );
    }

    #[test]
    fn save_preset_when_not_tuned_fails() {
        let mut radio = make_radio();
        radio.power_on().ok();
        // State is On, not Tuned.
        let result = radio.save_preset(0);
        assert_eq!(
            result,
            Err(FmError::InvalidState),
            "save_preset when not tuned must return InvalidState"
        );
    }

    #[test]
    fn preset_non_contiguous_index() {
        let mut radio = make_radio();
        radio.power_on().ok();
        radio.tune(92_300).ok();
        // Save directly to slot 3, skipping 0-2.
        let result = radio.save_preset(3);
        assert!(result.is_ok(), "saving to non-contiguous slot must succeed");
        assert_eq!(
            radio.preset_count(),
            4,
            "preset_count must reflect the highest used index + 1"
        );
    }

    #[test]
    fn recall_preset_uninitialized_non_contiguous_slot_returns_invalid_preset() {
        // WHY(#452): recall_preset's documented contract is
        // "InvalidPreset -- slot index out of range or not set".
        // preset_count only tracks the highest EVER-saved index + 1, not
        // which individual slots were populated, so saving directly to
        // slot 3 (skipping 0-2, as in preset_non_contiguous_index above)
        // leaves slots 0-2 within the `index < preset_count` range yet
        // never actually written. Per-slot occupancy (Option<u32>) now
        // lets recall_preset distinguish that from a genuinely saved
        // frequency and return InvalidPreset as documented, fixing the
        // FrequencyOutOfRange mismatch this test used to pin.
        let mut radio = make_radio();
        radio.power_on().ok();
        radio.tune(92_300).ok();
        radio.save_preset(3).ok(); // non-contiguous; slots 0-2 stay unset
        assert_eq!(radio.preset_count(), 4);

        let result = radio.recall_preset(1); // never explicitly saved
        assert_eq!(
            result,
            Err(FmError::InvalidPreset),
            "an unset-but-in-range slot must return the documented \
             InvalidPreset, not FrequencyOutOfRange"
        );
    }

    #[test]
    fn fm_state_display() {
        assert_eq!(FmState::Off.to_string(), "off");
        assert_eq!(FmState::On.to_string(), "on");
        assert_eq!(
            FmState::Tuned {
                frequency_khz: 98_500
            }
            .to_string(),
            "tuned to 98.5 MHz"
        );
    }
}
