//! Fail-closed MT6357 PMIC audio codec adapter.
//!
//! Hardware abstraction for the MT6357 analog codec on the AGM M7.
//! The codec handles DAC (output), ADC (mic input), amplifier routing,
//! volume control, and mic bias voltage generation.
//!
//! The MT6357 PMIC requires transactions through the MT6739 PWRAP
//! controller. Until #862 lands a source-grounded, bounded transaction seam,
//! the device adapter returns [`AudioError::PmicUnavailable`] and performs no
//! AP or PMIC MMIO. QEMU retains its state-only codec for session testing.
//!
//! ## Integration
//!
//! Used by [`super::audio::AudioManager`] for codec power management and
//! route switching.  The `AudioCodecOps` trait enables mock-based testing.

// WHY: kardia constructs AudioManager<BootCodec> and the QEMU witness exercises
// its state machine, but real MT6357 codec/PMIC behavior remains unqualified.
#![expect(
    dead_code,
    reason = "audio codec API is QEMU-wired; unused operations await accepted production integration and M7 qualification (#753)"
)]

extern crate alloc;

use super::audio_route::AudioRoute;

/// Maximum logical volume accepted by the codec API.
///
/// The eventual hardware gain mapping remains part of #862's source-grounded
/// PMIC integration.
const MAX_VOLUME: u8 = 15;

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
    /// Invalid volume level (exceeds the logical API range).
    InvalidVolume,
    /// Hardware register access failed.
    HardwareError,
    /// No source-grounded PMIC/PWRAP transport is available (#862).
    PmicUnavailable,
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
            Self::PmicUnavailable => write!(f, "PMIC transport unavailable"),
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
/// Provides a uniform interface for an eventual source-grounded MT6357 PMIC
/// seam and for mock verification in tests. The current production-target
/// implementation is deliberately fail-closed pending #862.
pub(crate) trait AudioCodecOps {
    /// Request that the codec power on.
    fn power_on(&mut self) -> Result<(), AudioError>;

    /// Request that the codec power off.
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
    /// Values above 15 are clamped to 15 by stateful test/emulation codecs.
    /// The device mapping remains undefined until #862 lands.
    fn set_volume(&mut self, level: u8) -> Result<(), AudioError>;

    /// Enable mic bias voltage for electret condenser microphones.
    ///
    /// Required before the internal mic can capture audio.  The bias
    /// voltage powers the mic's FET preamp.
    fn enable_mic_bias(&mut self) -> Result<(), AudioError>;

    /// Disable mic bias voltage.
    fn disable_mic_bias(&mut self) -> Result<(), AudioError>;

    /// Return the adapter's recorded powered state, not physical readback.
    fn is_powered(&self) -> bool;

    /// Return the adapter's recorded DAC state, not physical readback.
    fn is_dac_enabled(&self) -> bool;

    /// Return the adapter's recorded ADC state, not physical readback.
    fn is_adc_enabled(&self) -> bool;

    /// Return the adapter's recorded mic-bias state, not physical readback.
    fn is_mic_bias_enabled(&self) -> bool;

    /// Return the current volume level (0-15).
    fn volume(&self) -> u8;

    /// Return the current output route.
    fn current_route(&self) -> AudioRoute;
}

// ---------------------------------------------------------------------------
// Production-target fail-closed MT6357 seam
// ---------------------------------------------------------------------------

/// Production-target MT6357 codec seam without a PMIC transport.
///
/// Every mutating operation returns [`AudioError::PmicUnavailable`]. The type
/// is compiled in tests so the device-side fail-closed contract is directly
/// verifiable. #862 remains open for the bounded, source-grounded PWRAP seam.
pub(crate) struct Mt6357Codec;

impl Mt6357Codec {
    /// Create a fail-closed MT6357 codec handle.
    ///
    /// Construction performs no AP or PMIC MMIO.
    #[must_use]
    pub(crate) const fn new() -> Self {
        Self
    }
}

impl AudioCodecOps for Mt6357Codec {
    fn power_on(&mut self) -> Result<(), AudioError> {
        Err(AudioError::PmicUnavailable)
    }

    fn power_off(&mut self) -> Result<(), AudioError> {
        Err(AudioError::PmicUnavailable)
    }

    fn enable_dac(&mut self) -> Result<(), AudioError> {
        Err(AudioError::PmicUnavailable)
    }

    fn enable_adc(&mut self) -> Result<(), AudioError> {
        Err(AudioError::PmicUnavailable)
    }

    fn disable_dac(&mut self) -> Result<(), AudioError> {
        Err(AudioError::PmicUnavailable)
    }

    fn disable_adc(&mut self) -> Result<(), AudioError> {
        Err(AudioError::PmicUnavailable)
    }

    fn set_output(&mut self, _route: AudioRoute) -> Result<(), AudioError> {
        Err(AudioError::PmicUnavailable)
    }

    fn set_volume(&mut self, _level: u8) -> Result<(), AudioError> {
        Err(AudioError::PmicUnavailable)
    }

    fn enable_mic_bias(&mut self) -> Result<(), AudioError> {
        Err(AudioError::PmicUnavailable)
    }

    fn disable_mic_bias(&mut self) -> Result<(), AudioError> {
        Err(AudioError::PmicUnavailable)
    }

    fn is_powered(&self) -> bool {
        false
    }

    fn is_dac_enabled(&self) -> bool {
        false
    }

    fn is_adc_enabled(&self) -> bool {
        false
    }

    fn is_mic_bias_enabled(&self) -> bool {
        false
    }

    fn volume(&self) -> u8 {
        0
    }

    fn current_route(&self) -> AudioRoute {
        AudioRoute::Speaker
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
// WHY: powered/dac_enabled/adc_enabled/mic_bias mirror independent interface
// states, not a state machine, so no bitflags/enum recast applies here.
#[expect(
    clippy::struct_excessive_bools,
    reason = "powered/dac_enabled/adc_enabled/mic_bias mirror independent codec interface states, not a state machine"
)]
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
    /// `power_down_mic` partial-teardown path (`disable_mic_bias` succeeds,
    /// `disable_adc` fails).
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
        // WHY: mirror the production-target interface's ADC-enabled precondition
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

/// A state-only audio codec for qemu (#399). The MT6357 PMIC/PWRAP interface is
/// unmodeled on -machine virt. `NullCodec` tracks the power/enable/route state
/// the `AudioManager` session logic reads, but touches no hardware, so the
/// session/priority/route state machine runs in emulation. Distinct from the
/// test-only `MockCodec` (which carries fail-injection knobs).
// WHY: powered/dac_enabled/adc_enabled/mic_bias mirror independent interface
// states, not a state machine, so no bitflags/enum recast applies here.
#[expect(
    clippy::struct_excessive_bools,
    reason = "powered/dac_enabled/adc_enabled/mic_bias mirror independent codec interface states, not a state machine"
)]
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
        self.volume = level.min(MAX_VOLUME);
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

/// The codec type the booted kernel wires into its `AudioManager` (#399): the
/// state-only `NullCodec` under qemu/test (no PMIC model on -machine virt), and
/// the fail-closed `Mt6357Codec` on device. The latter performs no PMIC access
/// until #862 supplies an accepted PWRAP transaction seam.
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
    fn device_codec_fails_closed_without_pwrap_transport() {
        let mut codec = Mt6357Codec::new();

        assert_eq!(codec.power_on(), Err(AudioError::PmicUnavailable));
        assert_eq!(codec.power_off(), Err(AudioError::PmicUnavailable));
        assert_eq!(codec.enable_dac(), Err(AudioError::PmicUnavailable));
        assert_eq!(codec.enable_adc(), Err(AudioError::PmicUnavailable));
        assert_eq!(codec.disable_dac(), Err(AudioError::PmicUnavailable));
        assert_eq!(codec.disable_adc(), Err(AudioError::PmicUnavailable));
        assert_eq!(
            codec.set_output(AudioRoute::Earpiece),
            Err(AudioError::PmicUnavailable)
        );
        assert_eq!(codec.set_volume(7), Err(AudioError::PmicUnavailable));
        assert_eq!(codec.enable_mic_bias(), Err(AudioError::PmicUnavailable));
        assert_eq!(codec.disable_mic_bias(), Err(AudioError::PmicUnavailable));
        assert!(!codec.is_powered());
        assert!(!codec.is_dac_enabled());
        assert!(!codec.is_adc_enabled());
        assert!(!codec.is_mic_bias_enabled());
        assert_eq!(codec.volume(), 0);
        assert_eq!(codec.current_route(), AudioRoute::Speaker);
    }

    #[test]
    fn qemu_codec_clamps_volume_to_logical_range() {
        let mut codec = NullCodec::new();

        assert_eq!(codec.set_volume(u8::MAX), Ok(()));
        assert_eq!(codec.volume(), MAX_VOLUME);
    }

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
        // AdcNotEnabled represents a mic-bias request made before ADC enable.
        // Stateful mock/emulation adapters enforce that interface precondition;
        // here we verify the variant is constructable and has correct Display.
        let err = AudioError::AdcNotEnabled;
        let msg = alloc::format!("{err}");
        assert_eq!(msg, "ADC not enabled", "AdcNotEnabled display must match");
    }
}
