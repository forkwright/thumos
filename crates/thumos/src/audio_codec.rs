//! MT6357 PMIC audio codec driver.
//!
//! Hardware abstraction for the MT6357 analog codec on the AGM M7.
//! The codec handles DAC (output), ADC (mic input), amplifier routing,
//! volume control, and mic bias voltage generation.
//!
//! ## Hardware path
//!
//! The MT6357 PMIC is accessed via the PMIC wrapper bus (PWRAP) on the
//! MT6739 SoC.  Register writes go through PWRAP MMIO at `0x1000_D000`,
//! which bridges to the PMIC I2C/SPI bus.
//!
//! ## PMIC audio register map (MT6357)
//!
//! | Register           | Offset   | Purpose                              |
//! |--------------------|----------|--------------------------------------|
//! | AUD_TOP_CON0       | 0x2000   | Audio top-level power control        |
//! | AFE_UL_DL_CON0     | 0x2004   | UL/DL path enable                   |
//! | AFE_DL_CON0        | 0x2008   | Downlink (DAC) control               |
//! | AFE_UL_CON0        | 0x200C   | Uplink (ADC) control                 |
//! | AFE_DL_GAIN        | 0x2010   | DAC digital gain (volume)            |
//! | AFE_UL_GAIN        | 0x2014   | ADC digital gain                     |
//! | AUDDEC_ANA_CON0    | 0x2080   | Decoder analog control 0 (HPL/HPR)   |
//! | AUDDEC_ANA_CON1    | 0x2084   | Decoder analog control 1 (earpiece)  |
//! | AUDDEC_ANA_CON6    | 0x2098   | Decoder analog control 6 (speaker)   |
//! | AUDENC_ANA_CON0    | 0x20C0   | Encoder analog control (mic preamp)  |
//! | AUDENC_ANA_CON9    | 0x20E4   | Mic bias voltage control             |
//! | AUD_TOP_LDO_CON0   | 0x2100   | Audio LDO enable                    |
//!
//! These offsets are within the PMIC register space; actual access goes
//! through PWRAP at `PWRAP_BASE + offset`.
//!
//! ## Integration
//!
//! Used by [`super::audio::AudioManager`] for codec power management and
//! route switching.  The `AudioCodecOps` trait enables mock-based testing.

// WHY: audio codec API not yet wired to kinit (Wave 4 integration pending).
#![expect(
    dead_code,
    reason = "audio codec API created in Phase 07 Wave 4, kinit wiring pending (#145)"
)]

extern crate alloc;

use super::audio_route::AudioRoute;

// ---------------------------------------------------------------------------
// MT6357 PMIC audio registers
// ---------------------------------------------------------------------------

/// PWRAP (PMIC Wrapper) base address on MT6739.
///
/// All PMIC register accesses go through PWRAP MMIO.
/// Audio top-level power control register offset.
const AUD_TOP_CON0: u16 = 0x2000;

/// UL/DL path enable register offset.
const AFE_UL_DL_CON0: u16 = 0x2004;

/// Downlink (DAC) control register offset.
const AFE_DL_CON0: u16 = 0x2008;

/// Uplink (ADC) control register offset.
const AFE_UL_CON0: u16 = 0x200C;

/// DAC digital gain (volume) register offset.
const AFE_DL_GAIN: u16 = 0x2010;

/// ADC digital gain register offset.
#[expect(
    dead_code,
    reason = "register constant reserved for future gain control (#145)"
)]
const AFE_UL_GAIN: u16 = 0x2014;

/// Decoder analog control 0: HPL/HPR (headphone left/right) amplifier.
const AUDDEC_ANA_CON0: u16 = 0x2080;

/// Decoder analog control 1: earpiece receiver amplifier.
const AUDDEC_ANA_CON1: u16 = 0x2084;

/// Decoder analog control 6: loudspeaker amplifier.
const AUDDEC_ANA_CON6: u16 = 0x2098;

/// Encoder analog control 0: mic preamp enable.
const AUDENC_ANA_CON0: u16 = 0x20C0;

/// Mic bias voltage control register.
const AUDENC_ANA_CON9: u16 = 0x20E4;

/// Audio LDO enable register.
const AUD_TOP_LDO_CON0: u16 = 0x2100;

// ---------------------------------------------------------------------------
// Register bit definitions
// ---------------------------------------------------------------------------

/// AUD_TOP_CON0: audio subsystem power-on bit.
const AUD_TOP_POWER_ON: u32 = 1 << 0;

/// AUD_TOP_LDO_CON0: audio LDO enable bit.
const AUD_LDO_ENABLE: u32 = 1 << 0;

/// AFE_UL_DL_CON0: downlink path enable.
const AFE_DL_EN: u32 = 1 << 0;

/// AFE_UL_DL_CON0: uplink path enable.
const AFE_UL_EN: u32 = 1 << 1;

/// AFE_DL_CON0: DAC enable bit.
const DAC_ENABLE: u32 = 1 << 0;

/// AFE_UL_CON0: ADC enable bit.
const ADC_ENABLE: u32 = 1 << 0;

/// AUDDEC_ANA_CON0: headphone left amplifier enable.
const HPL_AMP_EN: u32 = 1 << 0;

/// AUDDEC_ANA_CON0: headphone right amplifier enable.
const HPR_AMP_EN: u32 = 1 << 1;

/// AUDDEC_ANA_CON1: earpiece receiver amplifier enable.
const EARPIECE_AMP_EN: u32 = 1 << 0;

/// AUDDEC_ANA_CON6: loudspeaker amplifier enable.
const SPEAKER_AMP_EN: u32 = 1 << 0;

/// AUDENC_ANA_CON0: mic preamp enable.
const MIC_PREAMP_EN: u32 = 1 << 0;

/// AUDENC_ANA_CON9: mic bias voltage enable.
const MIC_BIAS_EN: u32 = 1 << 0;

/// Maximum hardware volume level (4-bit, 0-15).
const MAX_VOLUME: u8 = 15;

/// Volume step in hardware gain units.
///
/// Each step is approximately 1 dB.  The MT6357 AFE_DL_GAIN register
/// uses a 16-bit value; we map 0-15 linearly into the usable range.
const VOLUME_STEP: u32 = 0x0800;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Audio codec errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AudioError {
    /// Codec is not powered on.
    CodecNotPowered,
    /// DAC is not enabled (cannot set output route).
    DacNotEnabled,
    /// Invalid volume level (exceeds hardware maximum).
    InvalidVolume,
    /// Hardware register access failed.
    HardwareError,
    /// The requested route is not available.
    RouteUnavailable,
    /// The requested session was not found.
    SessionNotFound,
    /// Mic bias requires ADC to be enabled.
    AdcNotEnabled,
}

impl core::fmt::Display for AudioError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::CodecNotPowered => write!(f, "codec not powered"),
            Self::DacNotEnabled => write!(f, "DAC not enabled"),
            Self::InvalidVolume => write!(f, "invalid volume level"),
            Self::HardwareError => write!(f, "hardware error"),
            Self::RouteUnavailable => write!(f, "route unavailable"),
            Self::SessionNotFound => write!(f, "session not found"),
            Self::AdcNotEnabled => write!(f, "ADC not enabled"),
        }
    }
}

// ---------------------------------------------------------------------------
// Codec operations trait
// ---------------------------------------------------------------------------

/// Hardware-abstracted audio codec operations.
///
/// Provides a uniform interface for the MT6357 PMIC codec, allowing
/// real hardware access in production and mock verification in tests.
pub(crate) trait AudioCodecOps {
    /// Power on the audio codec: enable LDO, wait for stabilization,
    /// enable top-level power.
    fn power_on(&mut self) -> Result<(), AudioError>;

    /// Power off the audio codec: disable top-level power, disable LDO.
    fn power_off(&mut self) -> Result<(), AudioError>;

    /// Enable the DAC (digital-to-analog converter) for audio output.
    ///
    /// Requires the codec to be powered on first.
    fn enable_dac(&mut self) -> Result<(), AudioError>;

    /// Enable the ADC (analog-to-digital converter) for mic input.
    ///
    /// Requires the codec to be powered on first.
    fn enable_adc(&mut self) -> Result<(), AudioError>;

    /// Disable the DAC.
    fn disable_dac(&mut self) -> Result<(), AudioError>;

    /// Disable the ADC.
    fn disable_adc(&mut self) -> Result<(), AudioError>;

    /// Set the audio output route (earpiece, speaker, etc.).
    ///
    /// Configures the appropriate amplifier for the selected output.
    fn set_output(&mut self, route: AudioRoute) -> Result<(), AudioError>;

    /// Set the output volume level (0-15).
    ///
    /// Values above 15 are clamped to 15.  Level 0 is the minimum
    /// audible output (not mute — use `disable_dac` for silence).
    fn set_volume(&mut self, level: u8) -> Result<(), AudioError>;

    /// Enable mic bias voltage for electret condenser microphones.
    ///
    /// Required before the internal mic can capture audio.  The bias
    /// voltage powers the mic's FET preamp.
    fn enable_mic_bias(&mut self) -> Result<(), AudioError>;

    /// Disable mic bias voltage.
    fn disable_mic_bias(&mut self) -> Result<(), AudioError>;

    /// Return whether the codec is currently powered on.
    fn is_powered(&self) -> bool;

    /// Return whether the DAC is currently enabled.
    fn is_dac_enabled(&self) -> bool;

    /// Return whether the ADC is currently enabled.
    fn is_adc_enabled(&self) -> bool;

    /// Return whether mic bias is currently enabled.
    fn is_mic_bias_enabled(&self) -> bool;

    /// Return the current volume level (0-15).
    fn volume(&self) -> u8;

    /// Return the current output route.
    fn current_route(&self) -> AudioRoute;
}

// ---------------------------------------------------------------------------
// Real MT6357 codec implementation (non-test only)
// ---------------------------------------------------------------------------

/// MT6357 PMIC audio codec driver.
///
/// Accesses PMIC registers through the PWRAP bus on the MT6739.
/// Manages LDO power gating, DAC/ADC enable, amplifier routing,
/// volume control, and mic bias.
#[cfg(not(any(test, feature = "qemu")))]
pub(crate) struct Mt6357Codec {
    /// Whether the codec is powered on (LDO active).
    powered: bool,
    /// Whether the DAC is enabled.
    dac_enabled: bool,
    /// Whether the ADC is enabled.
    adc_enabled: bool,
    /// Whether mic bias is enabled.
    mic_bias: bool,
    /// Current volume level (0-15).
    vol: u8,
    /// Current output route.
    route: AudioRoute,
}

#[cfg(not(any(test, feature = "qemu")))]
impl Mt6357Codec {
    /// Create a new MT6357 codec handle.
    ///
    /// The codec starts unpowered; call `power_on()` before any other
    /// operation.
    #[must_use]
    pub(crate) const fn new() -> Self {
        Self {
            powered: false,
            dac_enabled: false,
            adc_enabled: false,
            mic_bias: false,
            vol: 0,
            route: AudioRoute::Speaker,
        }
    }

    /// Write a 32-bit value to a PMIC register via PWRAP.
    ///
    /// # Safety
    ///
    /// The caller must ensure `offset` is a valid MT6357 register offset
    /// and that PWRAP is initialized.
    #[inline]
    unsafe fn pmic_write(offset: u16, value: u32) {
        let addr = crate::board::PWRAP_BASE + offset as usize;
        // SAFETY: board::PWRAP_BASE + offset is a valid MMIO address in the
        // MT6739 address map.  Volatile write ensures the compiler does
        // not reorder or elide the store.
        unsafe {
            core::ptr::write_volatile(addr as *mut u32, value);
        }
    }

    /// Read a 32-bit value from a PMIC register via PWRAP.
    ///
    /// # Safety
    ///
    /// The caller must ensure `offset` is a valid MT6357 register offset
    /// and that PWRAP is initialized.
    #[inline]
    unsafe fn pmic_read(offset: u16) -> u32 {
        let addr = crate::board::PWRAP_BASE + offset as usize;
        // SAFETY: same as pmic_write; volatile read ensures no elision.
        unsafe { core::ptr::read_volatile(addr as *const u32) }
    }

    /// Set bits in a PMIC register (read-modify-write).
    ///
    /// # Safety
    ///
    /// The caller must ensure `offset` is a valid MT6357 register offset.
    unsafe fn pmic_set_bits(offset: u16, bits: u32) {
        // WHY: mask IRQ delivery around the read-modify-write -- an
        // interrupt firing between the read and the write here could
        // itself touch the same PMIC register, and this write would
        // clobber whatever change the interrupt made (the same
        // preemption-corruption class crate::irq::IrqGuard exists for,
        // see irq.rs's #322/#331 module docs).
        let _irq_guard = crate::irq::IrqGuard::new();
        // SAFETY: caller guarantees valid register offset.
        unsafe {
            let current = Self::pmic_read(offset);
            Self::pmic_write(offset, current | bits);
        }
    }

    /// Clear bits in a PMIC register (read-modify-write).
    ///
    /// # Safety
    ///
    /// The caller must ensure `offset` is a valid MT6357 register offset.
    unsafe fn pmic_clear_bits(offset: u16, bits: u32) {
        // WHY: IRQ-safe RMW -- see pmic_set_bits.
        let _irq_guard = crate::irq::IrqGuard::new();
        // SAFETY: caller guarantees valid register offset.
        unsafe {
            let current = Self::pmic_read(offset);
            Self::pmic_write(offset, current & !bits);
        }
    }

    /// Disable all output amplifiers (earpiece, speaker).
    ///
    /// # Safety
    ///
    /// Must only be called when the codec is powered on.
    unsafe fn disable_all_amps(&mut self) {
        // SAFETY: codec is powered, PWRAP is active, register offsets are valid.
        unsafe {
            Self::pmic_clear_bits(AUDDEC_ANA_CON1, EARPIECE_AMP_EN);
            Self::pmic_clear_bits(AUDDEC_ANA_CON6, SPEAKER_AMP_EN);
            Self::pmic_clear_bits(AUDDEC_ANA_CON0, HPL_AMP_EN | HPR_AMP_EN);
        }
    }
}

#[cfg(not(any(test, feature = "qemu")))]
impl AudioCodecOps for Mt6357Codec {
    fn power_on(&mut self) -> Result<(), AudioError> {
        if self.powered {
            return Ok(());
        }

        // SAFETY: PWRAP is initialized during kinit; register offsets are
        // valid MT6357 audio registers documented in the header.
        unsafe {
            // Step 1: Enable audio LDO.
            Self::pmic_set_bits(AUD_TOP_LDO_CON0, AUD_LDO_ENABLE);

            // Step 2: Wait for LDO voltage stabilization (~10 ms).
            // NOTE: in a real kernel this would use a timer; for now we
            // spin-wait with a volatile barrier.
            for _ in 0..100_000 {
                core::hint::spin_loop();
            }

            // Step 3: Enable audio top-level power.
            Self::pmic_set_bits(AUD_TOP_CON0, AUD_TOP_POWER_ON);
        }

        self.powered = true;
        Ok(())
    }

    fn power_off(&mut self) -> Result<(), AudioError> {
        if !self.powered {
            return Ok(());
        }

        // Disable active paths first.
        if self.dac_enabled {
            self.disable_dac()?;
        }
        if self.adc_enabled {
            self.disable_adc()?;
        }
        if self.mic_bias {
            self.disable_mic_bias()?;
        }

        // SAFETY: PWRAP initialized, valid register offsets.
        unsafe {
            // Disable all amplifiers.
            self.disable_all_amps();

            // Disable top-level power.
            Self::pmic_clear_bits(AUD_TOP_CON0, AUD_TOP_POWER_ON);

            // Disable LDO.
            Self::pmic_clear_bits(AUD_TOP_LDO_CON0, AUD_LDO_ENABLE);
        }

        self.powered = false;
        Ok(())
    }

    fn enable_dac(&mut self) -> Result<(), AudioError> {
        if !self.powered {
            return Err(AudioError::CodecNotPowered);
        }
        if self.dac_enabled {
            return Ok(());
        }

        // SAFETY: codec powered, valid registers.
        unsafe {
            Self::pmic_set_bits(AFE_UL_DL_CON0, AFE_DL_EN);
            Self::pmic_set_bits(AFE_DL_CON0, DAC_ENABLE);
        }

        self.dac_enabled = true;
        Ok(())
    }

    fn enable_adc(&mut self) -> Result<(), AudioError> {
        if !self.powered {
            return Err(AudioError::CodecNotPowered);
        }
        if self.adc_enabled {
            return Ok(());
        }

        // SAFETY: codec powered, valid registers.
        unsafe {
            Self::pmic_set_bits(AFE_UL_DL_CON0, AFE_UL_EN);
            Self::pmic_set_bits(AFE_UL_CON0, ADC_ENABLE);
            Self::pmic_set_bits(AUDENC_ANA_CON0, MIC_PREAMP_EN);
        }

        self.adc_enabled = true;
        Ok(())
    }

    fn disable_dac(&mut self) -> Result<(), AudioError> {
        if !self.dac_enabled {
            return Ok(());
        }

        // SAFETY: codec powered (checked by enable_dac precondition),
        // valid registers.
        unsafe {
            self.disable_all_amps();
            Self::pmic_clear_bits(AFE_DL_CON0, DAC_ENABLE);
            Self::pmic_clear_bits(AFE_UL_DL_CON0, AFE_DL_EN);
        }

        self.dac_enabled = false;
        Ok(())
    }

    fn disable_adc(&mut self) -> Result<(), AudioError> {
        if !self.adc_enabled {
            return Ok(());
        }

        // SAFETY: codec powered, valid registers.
        unsafe {
            Self::pmic_clear_bits(AUDENC_ANA_CON0, MIC_PREAMP_EN);
            Self::pmic_clear_bits(AFE_UL_CON0, ADC_ENABLE);
            Self::pmic_clear_bits(AFE_UL_DL_CON0, AFE_UL_EN);
        }

        self.adc_enabled = false;
        Ok(())
    }

    fn set_output(&mut self, route: AudioRoute) -> Result<(), AudioError> {
        if !self.powered {
            return Err(AudioError::CodecNotPowered);
        }
        if !self.dac_enabled {
            return Err(AudioError::DacNotEnabled);
        }

        // SAFETY: codec powered, DAC enabled, valid registers.
        unsafe {
            // Disable all amps first, then enable the target.
            self.disable_all_amps();

            match route {
                AudioRoute::Earpiece => {
                    Self::pmic_set_bits(AUDDEC_ANA_CON1, EARPIECE_AMP_EN);
                }
                AudioRoute::Speaker => {
                    Self::pmic_set_bits(AUDDEC_ANA_CON6, SPEAKER_AMP_EN);
                }
                AudioRoute::Headset => {
                    // Wired headset uses the HPL/HPR amplifiers.
                    Self::pmic_set_bits(AUDDEC_ANA_CON0, HPL_AMP_EN | HPR_AMP_EN);
                }
                AudioRoute::BluetoothA2dp | AudioRoute::UsbDac => {
                    // BT and USB DAC are digital outputs — no analog amp needed.
                    // The codec DAC feeds the AFE which routes to the digital path.
                }
            }
        }

        self.route = route;
        Ok(())
    }

    fn set_volume(&mut self, level: u8) -> Result<(), AudioError> {
        if !self.powered {
            return Err(AudioError::CodecNotPowered);
        }

        let clamped = level.min(MAX_VOLUME);
        let gain = u32::from(clamped) * VOLUME_STEP;

        // SAFETY: codec powered, valid register.
        unsafe {
            Self::pmic_write(AFE_DL_GAIN, gain);
        }

        self.vol = clamped;
        Ok(())
    }

    fn enable_mic_bias(&mut self) -> Result<(), AudioError> {
        if !self.powered {
            return Err(AudioError::CodecNotPowered);
        }
        // WHY: enforce the documented precondition -- AudioError::AdcNotEnabled
        // exists specifically for "mic bias requires ADC to be enabled", but
        // no implementation actually checked it, so a caller reaching the
        // codec directly (bypassing AudioManager's enable_adc-then-
        // enable_mic_bias ordering) could power the mic bias FET preamp
        // with the ADC never enabled (#397).
        if !self.adc_enabled {
            return Err(AudioError::AdcNotEnabled);
        }
        if self.mic_bias {
            return Ok(());
        }

        // SAFETY: codec powered, valid register.
        unsafe {
            Self::pmic_set_bits(AUDENC_ANA_CON9, MIC_BIAS_EN);
        }

        self.mic_bias = true;
        Ok(())
    }

    fn disable_mic_bias(&mut self) -> Result<(), AudioError> {
        if !self.mic_bias {
            return Ok(());
        }

        // SAFETY: codec powered, valid register.
        unsafe {
            Self::pmic_clear_bits(AUDENC_ANA_CON9, MIC_BIAS_EN);
        }

        self.mic_bias = false;
        Ok(())
    }

    fn is_powered(&self) -> bool {
        self.powered
    }

    fn is_dac_enabled(&self) -> bool {
        self.dac_enabled
    }

    fn is_adc_enabled(&self) -> bool {
        self.adc_enabled
    }

    fn is_mic_bias_enabled(&self) -> bool {
        self.mic_bias
    }

    fn volume(&self) -> u8 {
        self.vol
    }

    fn current_route(&self) -> AudioRoute {
        self.route
    }
}

// ---------------------------------------------------------------------------
// Mock codec for testing
// ---------------------------------------------------------------------------

/// Mock audio codec for unit testing.
///
/// Records all operations in order for test verification.  Controllable
/// failure injection via the `fail_*` flags.
// kanon:ignore RUST/struct-too-many-fields -- test-only mock: one state flag + one fail-injection flag per codec hardware operation; each field targets a distinct operation's failure path
#[cfg(test)]
pub struct MockCodec {
    /// Whether the codec is powered on.
    pub powered: bool,
    /// Whether the DAC is enabled.
    pub dac_enabled: bool,
    /// Whether the ADC is enabled.
    pub adc_enabled: bool,
    /// Current volume level (0-15).
    pub vol: u8,
    /// Current output route.
    pub route: AudioRoute,
    /// Whether mic bias is enabled.
    pub mic_bias: bool,
    /// Ordered log of operations performed.
    pub operations: alloc::vec::Vec<alloc::string::String>,
    /// If set, `power_on` returns this error.
    pub fail_power_on: Option<AudioError>,
    /// If set, `enable_dac` returns this error (#390).
    pub fail_enable_dac: Option<AudioError>,
    /// If set, `enable_adc` returns this error (#390).
    pub fail_enable_adc: Option<AudioError>,
    /// If set, `enable_mic_bias` returns this error (#390).
    pub fail_enable_mic_bias: Option<AudioError>,
    /// If set, `set_output` returns this error (#390).
    pub fail_set_output: Option<AudioError>,
    /// If set, `disable_dac` returns this error.
    pub fail_disable_dac: Option<AudioError>,
    /// If set, `disable_adc` returns this error (#397) -- exercises the
    /// power_down_mic partial-teardown path (disable_mic_bias succeeds,
    /// disable_adc fails).
    pub fail_disable_adc: Option<AudioError>,
    /// If set, `power_off` returns this error.
    pub fail_power_off: Option<AudioError>,
}

#[cfg(test)]
impl MockCodec {
    /// Create a new mock codec in the unpowered state.
    pub fn new() -> Self {
        Self {
            powered: false,
            dac_enabled: false,
            adc_enabled: false,
            vol: 0,
            route: AudioRoute::Speaker,
            mic_bias: false,
            operations: alloc::vec::Vec::new(),
            fail_power_on: None,
            fail_enable_dac: None,
            fail_enable_adc: None,
            fail_enable_mic_bias: None,
            fail_set_output: None,
            fail_disable_dac: None,
            fail_disable_adc: None,
            fail_power_off: None,
        }
    }
}

#[cfg(test)]
impl AudioCodecOps for MockCodec {
    fn power_on(&mut self) -> Result<(), AudioError> {
        if let Some(err) = self.fail_power_on {
            self.operations
                .push(alloc::string::String::from("power_on:FAIL"));
            return Err(err);
        }
        self.powered = true;
        self.operations
            .push(alloc::string::String::from("power_on"));
        Ok(())
    }

    fn power_off(&mut self) -> Result<(), AudioError> {
        if let Some(err) = self.fail_power_off {
            self.operations
                .push(alloc::string::String::from("power_off:FAIL"));
            return Err(err);
        }
        self.powered = false;
        self.dac_enabled = false;
        self.adc_enabled = false;
        self.mic_bias = false;
        self.vol = 0;
        self.operations
            .push(alloc::string::String::from("power_off"));
        Ok(())
    }

    fn enable_dac(&mut self) -> Result<(), AudioError> {
        if !self.powered {
            return Err(AudioError::CodecNotPowered);
        }
        if let Some(err) = self.fail_enable_dac {
            self.operations
                .push(alloc::string::String::from("enable_dac:FAIL"));
            return Err(err);
        }
        self.dac_enabled = true;
        self.operations
            .push(alloc::string::String::from("enable_dac"));
        Ok(())
    }

    fn enable_adc(&mut self) -> Result<(), AudioError> {
        if !self.powered {
            return Err(AudioError::CodecNotPowered);
        }
        if let Some(err) = self.fail_enable_adc {
            self.operations
                .push(alloc::string::String::from("enable_adc:FAIL"));
            return Err(err);
        }
        self.adc_enabled = true;
        self.operations
            .push(alloc::string::String::from("enable_adc"));
        Ok(())
    }

    fn disable_dac(&mut self) -> Result<(), AudioError> {
        if let Some(err) = self.fail_disable_dac {
            self.operations
                .push(alloc::string::String::from("disable_dac:FAIL"));
            return Err(err);
        }
        self.dac_enabled = false;
        self.operations
            .push(alloc::string::String::from("disable_dac"));
        Ok(())
    }

    fn disable_adc(&mut self) -> Result<(), AudioError> {
        if let Some(err) = self.fail_disable_adc {
            self.operations
                .push(alloc::string::String::from("disable_adc:FAIL"));
            return Err(err);
        }
        self.adc_enabled = false;
        self.operations
            .push(alloc::string::String::from("disable_adc"));
        Ok(())
    }

    fn set_output(&mut self, route: AudioRoute) -> Result<(), AudioError> {
        if !self.powered {
            return Err(AudioError::CodecNotPowered);
        }
        if !self.dac_enabled {
            return Err(AudioError::DacNotEnabled);
        }
        if let Some(err) = self.fail_set_output {
            self.operations
                .push(alloc::string::String::from("set_output:FAIL"));
            return Err(err);
        }
        self.route = route;
        self.operations.push(alloc::format!("set_output:{route:?}"));
        Ok(())
    }

    fn set_volume(&mut self, level: u8) -> Result<(), AudioError> {
        if !self.powered {
            return Err(AudioError::CodecNotPowered);
        }
        let clamped = level.min(MAX_VOLUME);
        self.vol = clamped;
        self.operations.push(alloc::format!("set_volume:{clamped}"));
        Ok(())
    }

    fn enable_mic_bias(&mut self) -> Result<(), AudioError> {
        if !self.powered {
            return Err(AudioError::CodecNotPowered);
        }
        // WHY: mirror the real Mt6357Codec's ADC-enabled precondition
        // (#397) so a test exercising this invariant at the MockCodec
        // level actually observes the enforced behavior.
        if !self.adc_enabled {
            return Err(AudioError::AdcNotEnabled);
        }
        if let Some(err) = self.fail_enable_mic_bias {
            self.operations
                .push(alloc::string::String::from("enable_mic_bias:FAIL"));
            return Err(err);
        }
        self.mic_bias = true;
        self.operations
            .push(alloc::string::String::from("enable_mic_bias"));
        Ok(())
    }

    fn disable_mic_bias(&mut self) -> Result<(), AudioError> {
        self.mic_bias = false;
        self.operations
            .push(alloc::string::String::from("disable_mic_bias"));
        Ok(())
    }

    fn is_powered(&self) -> bool {
        self.powered
    }

    fn is_dac_enabled(&self) -> bool {
        self.dac_enabled
    }

    fn is_adc_enabled(&self) -> bool {
        self.adc_enabled
    }

    fn is_mic_bias_enabled(&self) -> bool {
        self.mic_bias
    }

    fn volume(&self) -> u8 {
        self.vol
    }

    fn current_route(&self) -> AudioRoute {
        self.route
    }
}

/// A no-op audio codec for qemu (#399). The MT6357 PMIC/PWRAP MMIO is unmodeled
/// on -machine virt, so the real `Mt6357Codec`'s register writes would
/// data-abort. `NullCodec` tracks the power/enable/route state the AudioManager
/// session logic reads, but touches no hardware -- so the session / priority /
/// route state machine runs in emulation. Distinct from the test-only
/// `MockCodec` (which carries fail-injection knobs).
#[cfg(any(feature = "qemu", test))]
pub(crate) struct NullCodec {
    powered: bool,
    dac_enabled: bool,
    adc_enabled: bool,
    mic_bias: bool,
    volume: u8,
    route: AudioRoute,
}

#[cfg(any(feature = "qemu", test))]
impl NullCodec {
    pub(crate) fn new() -> Self {
        Self {
            powered: false,
            dac_enabled: false,
            adc_enabled: false,
            mic_bias: false,
            volume: 0,
            route: AudioRoute::Speaker,
        }
    }
}

#[cfg(any(feature = "qemu", test))]
impl AudioCodecOps for NullCodec {
    fn power_on(&mut self) -> Result<(), AudioError> {
        self.powered = true;
        Ok(())
    }
    fn power_off(&mut self) -> Result<(), AudioError> {
        self.powered = false;
        self.dac_enabled = false;
        self.adc_enabled = false;
        self.mic_bias = false;
        Ok(())
    }
    fn enable_dac(&mut self) -> Result<(), AudioError> {
        self.dac_enabled = true;
        Ok(())
    }
    fn enable_adc(&mut self) -> Result<(), AudioError> {
        self.adc_enabled = true;
        Ok(())
    }
    fn disable_dac(&mut self) -> Result<(), AudioError> {
        self.dac_enabled = false;
        Ok(())
    }
    fn disable_adc(&mut self) -> Result<(), AudioError> {
        self.adc_enabled = false;
        Ok(())
    }
    fn set_output(&mut self, route: AudioRoute) -> Result<(), AudioError> {
        self.route = route;
        Ok(())
    }
    fn set_volume(&mut self, level: u8) -> Result<(), AudioError> {
        self.volume = level;
        Ok(())
    }
    fn enable_mic_bias(&mut self) -> Result<(), AudioError> {
        self.mic_bias = true;
        Ok(())
    }
    fn disable_mic_bias(&mut self) -> Result<(), AudioError> {
        self.mic_bias = false;
        Ok(())
    }
    fn is_powered(&self) -> bool {
        self.powered
    }
    fn is_dac_enabled(&self) -> bool {
        self.dac_enabled
    }
    fn is_adc_enabled(&self) -> bool {
        self.adc_enabled
    }
    fn is_mic_bias_enabled(&self) -> bool {
        self.mic_bias
    }
    fn volume(&self) -> u8 {
        self.volume
    }
    fn current_route(&self) -> AudioRoute {
        self.route
    }
}

/// The codec the booted kernel wires into its AudioManager (#399): the no-op
/// `NullCodec` under qemu/test (no PMIC model on -machine virt), the real
/// `Mt6357Codec` on device.
#[cfg(any(feature = "qemu", test))]
pub(crate) type BootCodec = NullCodec;
#[cfg(not(any(feature = "qemu", test)))]
pub(crate) type BootCodec = Mt6357Codec;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_codec_starts_unpowered() {
        let codec = MockCodec::new();
        assert!(!codec.is_powered(), "new mock codec must start unpowered");
        assert!(!codec.is_dac_enabled(), "DAC must be disabled on new codec");
        assert!(!codec.is_adc_enabled(), "ADC must be disabled on new codec");
        assert!(
            !codec.is_mic_bias_enabled(),
            "mic bias must be disabled on new codec"
        );
        assert_eq!(codec.volume(), 0, "initial volume must be 0");
    }

    #[test]
    fn power_on_enables_codec() {
        let mut codec = MockCodec::new();
        let result = codec.power_on();
        assert!(result.is_ok(), "power_on must succeed");
        assert!(codec.is_powered(), "codec must be powered after power_on");
    }

    #[test]
    fn power_off_disables_everything() {
        let mut codec = MockCodec::new();
        codec.power_on().ok();
        codec.enable_dac().ok();
        codec.enable_adc().ok();
        codec.enable_mic_bias().ok();
        codec.set_volume(10).ok();

        codec.power_off().ok();

        assert!(
            !codec.is_powered(),
            "codec must be unpowered after power_off"
        );
        assert!(
            !codec.is_dac_enabled(),
            "DAC must be disabled after power_off"
        );
        assert!(
            !codec.is_adc_enabled(),
            "ADC must be disabled after power_off"
        );
        assert!(
            !codec.is_mic_bias_enabled(),
            "mic bias must be disabled after power_off"
        );
        assert_eq!(codec.volume(), 0, "volume must reset to 0 after power_off");
    }

    #[test]
    fn set_volume_clamps_to_max() {
        let mut codec = MockCodec::new();
        codec.power_on().ok();

        // Set volume above max.
        let result = codec.set_volume(255);
        assert!(result.is_ok(), "set_volume must succeed when powered");
        assert_eq!(
            codec.volume(),
            MAX_VOLUME,
            "volume must be clamped to {MAX_VOLUME}"
        );

        // Set volume within range.
        codec.set_volume(7).ok();
        assert_eq!(codec.volume(), 7, "volume must accept valid values");

        // Set to exactly max.
        codec.set_volume(MAX_VOLUME).ok();
        assert_eq!(codec.volume(), MAX_VOLUME, "volume at max must be accepted");
    }

    #[test]
    fn enable_dac_requires_power() {
        let mut codec = MockCodec::new();
        let result = codec.enable_dac();
        assert_eq!(
            result,
            Err(AudioError::CodecNotPowered),
            "enable_dac without power must return CodecNotPowered"
        );

        // Power on, then enable.
        codec.power_on().ok();
        let result = codec.enable_dac();
        assert!(result.is_ok(), "enable_dac must succeed when powered");
        assert!(
            codec.is_dac_enabled(),
            "DAC must be enabled after enable_dac"
        );
    }

    #[test]
    fn enable_adc_requires_power() {
        let mut codec = MockCodec::new();
        let result = codec.enable_adc();
        assert_eq!(
            result,
            Err(AudioError::CodecNotPowered),
            "enable_adc without power must return CodecNotPowered"
        );

        codec.power_on().ok();
        let result = codec.enable_adc();
        assert!(result.is_ok(), "enable_adc must succeed when powered");
        assert!(
            codec.is_adc_enabled(),
            "ADC must be enabled after enable_adc"
        );
    }

    #[test]
    fn set_output_requires_dac() {
        let mut codec = MockCodec::new();
        codec.power_on().ok();

        // DAC not enabled.
        let result = codec.set_output(AudioRoute::Speaker);
        assert_eq!(
            result,
            Err(AudioError::DacNotEnabled),
            "set_output without DAC must return DacNotEnabled"
        );

        // Enable DAC, then set output.
        codec.enable_dac().ok();
        let result = codec.set_output(AudioRoute::Earpiece);
        assert!(result.is_ok(), "set_output must succeed with DAC enabled");
        assert_eq!(
            codec.current_route(),
            AudioRoute::Earpiece,
            "route must be earpiece after set_output"
        );
    }

    #[test]
    fn operations_recorded_in_order() {
        let mut codec = MockCodec::new();
        codec.power_on().ok();
        codec.enable_dac().ok();
        codec.set_volume(5).ok();
        codec.set_output(AudioRoute::Speaker).ok();
        codec.enable_adc().ok();
        codec.enable_mic_bias().ok();

        let expected = &[
            "power_on",
            "enable_dac",
            "set_volume:5",
            "set_output:Speaker",
            "enable_adc",
            "enable_mic_bias",
        ];

        assert_eq!(
            codec.operations.len(),
            expected.len(),
            "operation count must match"
        );

        for (i, (got, want)) in codec.operations.iter().zip(expected.iter()).enumerate() {
            assert_eq!(got, want, "operation {i} must be {want}, got {got}");
        }
    }

    #[test]
    fn disable_dac_and_adc_succeed_when_not_enabled() {
        let mut codec = MockCodec::new();
        // Disabling when not enabled should be a no-op success.
        let result = codec.disable_dac();
        assert!(result.is_ok(), "disable_dac when not enabled must succeed");
        let result = codec.disable_adc();
        assert!(result.is_ok(), "disable_adc when not enabled must succeed");
    }

    #[test]
    fn mic_bias_requires_power() {
        let mut codec = MockCodec::new();
        let result = codec.enable_mic_bias();
        assert_eq!(
            result,
            Err(AudioError::CodecNotPowered),
            "enable_mic_bias without power must return CodecNotPowered"
        );
    }

    #[test]
    fn mic_bias_requires_adc_enabled() {
        let mut codec = MockCodec::new();
        codec.power_on().ok();

        // ADC not enabled yet.
        let result = codec.enable_mic_bias();
        assert_eq!(
            result,
            Err(AudioError::AdcNotEnabled),
            "enable_mic_bias without ADC enabled must return \
             AdcNotEnabled (#397)"
        );
        assert!(
            !codec.is_mic_bias_enabled(),
            "mic bias must not be marked enabled when the ADC \
             precondition fails"
        );

        // Enable ADC, then mic bias must succeed.
        codec.enable_adc().ok();
        let result = codec.enable_mic_bias();
        assert!(
            result.is_ok(),
            "enable_mic_bias must succeed once ADC is enabled"
        );
        assert!(codec.is_mic_bias_enabled());
    }

    #[test]
    fn set_volume_requires_power() {
        let mut codec = MockCodec::new();
        let result = codec.set_volume(5);
        assert_eq!(
            result,
            Err(AudioError::CodecNotPowered),
            "set_volume without power must return CodecNotPowered"
        );
    }

    #[test]
    fn power_on_failure_propagates() {
        let mut codec = MockCodec::new();
        codec.fail_power_on = Some(AudioError::HardwareError);
        let result = codec.power_on();
        assert_eq!(
            result,
            Err(AudioError::HardwareError),
            "power_on failure must propagate the error"
        );
        assert!(
            !codec.is_powered(),
            "codec must remain unpowered on failure"
        );
        assert_eq!(
            codec.operations,
            &["power_on:FAIL"],
            "failed operation must be recorded"
        );
    }

    #[test]
    fn set_output_to_bluetooth_succeeds() {
        let mut codec = MockCodec::new();
        codec.power_on().ok();
        codec.enable_dac().ok();

        let result = codec.set_output(AudioRoute::BluetoothA2dp);
        assert!(result.is_ok(), "BT output must succeed");
        assert_eq!(
            codec.current_route(),
            AudioRoute::BluetoothA2dp,
            "route must be BluetoothA2dp"
        );
    }

    #[test]
    fn set_output_to_usb_dac_succeeds() {
        let mut codec = MockCodec::new();
        codec.power_on().ok();
        codec.enable_dac().ok();

        let result = codec.set_output(AudioRoute::UsbDac);
        assert!(result.is_ok(), "USB DAC output must succeed");
        assert_eq!(
            codec.current_route(),
            AudioRoute::UsbDac,
            "route must be UsbDac"
        );
    }

    #[test]
    fn adc_not_enabled_error_display() {
        // AdcNotEnabled is defined for the case where mic bias is requested
        // without ADC being enabled first. The real Mt6357Codec checks this;
        // here we verify the variant is constructable and has correct Display.
        let err = AudioError::AdcNotEnabled;
        let msg = alloc::format!("{err}");
        assert_eq!(msg, "ADC not enabled", "AdcNotEnabled display must match");
    }
}
