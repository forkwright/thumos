//! WMT power sequencing and subsystem management for the MT6739 CONSYS block.
//!
//! Models the 17-step CONSYS power-on sequence as an explicit state machine.
//! Hardware register I/O is abstracted through [`RegisterIo`] for testability.
//!
//! Source: `connectivity/common/common_main/platform/mt6739.c:419–546`

use snafu::Snafu;

// ── Register base addresses ────────────────────────────────────────────────────

/// System power manager base address (MT6739).
pub const SPM_BASE: u32 = 0xF000_6000;

/// Top clock generator base address (MT6739).
pub const TOPCKGEN_BASE: u32 = 0xF000_0000;

/// CONSYS MCU config base address (MT6739).
pub const CONN_MCU_CONFIG_BASE: u32 = 0xF807_0000;

/// AP reset generator base address (MT6739).
pub const AP_RGU_BASE: u32 = 0xF000_7000;

/// CONSYS EMI firmware physical base  -  MCU firmware load target.
pub const CONSYS_EMI_FW_PHY_BASE: u32 = 0xF008_0000;

/// CONSYS EMI AP-view physical base.
pub const CONSYS_EMI_AP_PHY_BASE: u32 = 0x8008_0000;

// ── SPM registers ─────────────────────────────────────────────────────────────

/// SPM clock gating config register (SPM + 0x000).
pub const CONSYS_SPM_PWRON_CFG_REG: u32 = SPM_BASE;

/// CONSYS top1 power control register (SPM + 0x32C).
pub const CONSYS_TOP1_PWR_CTRL_REG: u32 = SPM_BASE + 0x32C;

/// Power-on ack register  -  bit 1 = ready (SPM + 0x180).
pub const CONSYS_PWR_CONN_ACK_REG: u32 = SPM_BASE + 0x180;

/// Power-on ack shadow register  -  bit 1 = ready (SPM + 0x184).
pub const CONSYS_PWR_CONN_ACK_S_REG: u32 = SPM_BASE + 0x184;

// ── SPM CONSYS_TOP1_PWR_CTRL_REG bit fields ───────────────────────────────────

/// Bit 0: release SW reset of CONSYS.
pub const CONSYS_SPM_PWR_RST_BIT: u32 = 1 << 0;

/// Bit 1: ISO control  -  1 = isolated.
pub const CONSYS_SPM_PWR_ISO_S_BIT: u32 = 1 << 1;

/// Bit 2: power on CONSYS top1.
pub const CONSYS_SPM_PWR_ON_BIT: u32 = 1 << 2;

/// Bit 3: power on CONSYS top1 (shadow).
pub const CONSYS_SPM_PWR_ON_S_BIT: u32 = 1 << 3;

/// Bit 4: clock disable  -  writing 0 enables the clock.
pub const CONSYS_CLK_CTRL_BIT: u32 = 1 << 4;

/// Bit 8: SRAM power-down.
pub const CONSYS_SRAM_CONN_PD_BIT: u32 = 1 << 8;

/// Value written to [`CONSYS_SPM_PWRON_CFG_REG`] to enable SPM clock gating.
pub const CONSYS_PWRON_CONFG_EN_VALUE: u32 = 0x0B16_0001;

// ── TOPCKGEN registers ────────────────────────────────────────────────────────

/// Watchdog system reset register (TOPCKGEN + 0x018).
pub const CONSYS_WD_SYS_RST_REG: u32 = TOPCKGEN_BASE + 0x018;

/// Clock gate SET register (TOPCKGEN + 0x054), bit 26.
pub const CONSYS_TOP_CLKCG_SET_REG: u32 = TOPCKGEN_BASE + 0x054;

/// Clock gate clear register (TOPCKGEN + 0x084), bit 26.
pub const CONSYS_TOP_CLKCG_CLR_REG: u32 = TOPCKGEN_BASE + 0x084;

/// AXI bus protect enable register (TOPCKGEN + 0x1220), bits 13–14.
pub const CONSYS_TOPAXI_PROT_EN: u32 = TOPCKGEN_BASE + 0x1220;

/// AXI bus protect status register (TOPCKGEN + 0x1228), bits 13–14.
pub const CONSYS_TOPAXI_PROT_STA1: u32 = TOPCKGEN_BASE + 0x1228;

/// EMI remapping register (TOPCKGEN + 0x1380).
pub const CONSYS_EMI_MAPPING: u32 = TOPCKGEN_BASE + 0x1380;

/// OSC enable register (TOPCKGEN + 0x1800): bit 10 = `OSC_EN`, bit 9 = WAKEUP.
pub const CONSYS_AP2CONN_OSC_EN_REG: u32 = TOPCKGEN_BASE + 0x1800;

/// AXI bus protect bits (13 and 14) used in [`CONSYS_TOPAXI_PROT_EN`].
pub const CONSYS_TOPAXI_PROT_BITS: u32 = (1 << 13) | (1 << 14);

/// CONSYS clock gate bit (bit 26) in [`CONSYS_TOP_CLKCG_SET_REG`] / [`CONSYS_TOP_CLKCG_CLR_REG`].
pub const CONSYS_CLKCG_BIT: u32 = 1 << 26;

// ── AP_RGU registers ──────────────────────────────────────────────────────────

/// CONSYS CPU SW reset register (`AP_RGU` + 0x018).
pub const CONSYS_CPU_SW_RST_REG: u32 = AP_RGU_BASE + 0x018;

/// Key field required by writes to [`CONSYS_CPU_SW_RST_REG`].
pub const CONSYS_CPU_SW_RST_KEY: u32 = 0x88 << 24;

/// Bit 12: CONSYS CPU SW reset assert.
pub const CONSYS_CPU_SW_RST_BIT: u32 = 1 << 12;

// ── CONN_MCU registers ────────────────────────────────────────────────────────

/// Chip ID register (`CONN_MCU` + 0x008). Expected value: [`CONSYS_CHIP_ID_EXPECTED`].
pub const CONSYS_CHIP_ID_REG: u32 = CONN_MCU_CONFIG_BASE + 0x008;

/// Expected MT6739 CONSYS chip ID value.
pub const CONSYS_CHIP_ID_EXPECTED: u32 = 0x0699;

/// ACR register (`CONN_MCU` + 0x110).
pub const CONSYS_MCU_CFG_ACR_REG: u32 = CONN_MCU_CONFIG_BASE + 0x110;

/// Bit 18: MBIST control in [`CONSYS_MCU_CFG_ACR_REG`].
pub const CONSYS_MCU_CFG_ACR_MBIST_BIT: u32 = 1 << 18;

// ── PMIC ──────────────────────────────────────────────────────────────────────

/// PMIC `DCXO_CW16` register address (MT6335) for co-clock type detection.
///
/// WHY: lower byte of the full PMIC address 0x47E; accessed via I2C abstraction.
const DCXO_CW16_REG: u8 = 0x7E;

/// `DCXO_CW16` bit 6: indicates CO-TSX co-clock mode.
const DCXO_CO_TSX_BIT: u8 = 1 << 6;

/// `DCXO_CW16` bit 7: indicates TCXO clock mode.
const DCXO_TCXO_BIT: u8 = 1 << 7;

// ── EMI region offsets ────────────────────────────────────────────────────────

/// Paged trace ring OFFSET FROM firmware base.
pub const EMI_PAGED_TRACE_OFFSET: u32 = 0x0000_0400;

/// Paged dump OFFSET FROM firmware base (32 KB region).
pub const EMI_PAGED_DUMP_OFFSET: u32 = 0x0000_8400;

/// Full dump (DLM) OFFSET FROM firmware base (0x1F000 bytes).
pub const EMI_FULL_DUMP_DLM_OFFSET: u32 = 0x0001_0400;

/// Full dump SYSB2 OFFSET  -  immediately after DLM region (0x6800 bytes).
pub const EMI_FULL_DUMP_SYSB2_OFFSET: u32 = EMI_FULL_DUMP_DLM_OFFSET + 0x1F000;

/// Full dump SYSB3 OFFSET  -  immediately after SYSB2 region (0x16800 bytes).
pub const EMI_FULL_DUMP_SYSB3_OFFSET: u32 = EMI_FULL_DUMP_SYSB2_OFFSET + 0x6800;

// ── Poll LIMIT ────────────────────────────────────────────────────────────────

/// Maximum poll iterations before a hardware ack is declared timed out.
const POLL_TIMEOUT_ITERS: u32 = 1_000;

// ── Error types ───────────────────────────────────────────────────────────────

/// Errors produced by WMT power and subsystem operations.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum WmtError {
    /// CONSYS power-on ack register did not become ready within the poll LIMIT.
    #[snafu(display("CONSYS power-on ack timed out at step {step}"))]
    PowerAckTimeout {
        /// Power-on step index (1-based) at which the timeout occurred.
        step: u8,
    },

    /// Chip ID register returned an unexpected value after CPU reset release.
    #[snafu(display("CONSYS chip ID mismatch: expected {expected:#010x}, got {got:#010x}"))]
    ChipIdMismatch {
        /// Expected chip ID.
        expected: u32,
        /// Actual chip ID read FROM hardware.
        got: u32,
    },

    /// AXI bus protect bits did not clear within the poll LIMIT.
    #[snafu(display("AXI bus protect clear timed out"))]
    AxiProtectTimeout,

    /// `power_on` called when CONSYS is already powered on.
    #[snafu(display("CONSYS is already powered on"))]
    AlreadyPoweredOn,

    /// `power_off` called when CONSYS is already powered off.
    #[snafu(display("CONSYS is already powered off"))]
    AlreadyPoweredOff,

    /// Subsystem enable/disable called when already in the requested state.
    #[snafu(display("subsystem {subsystem:?} is already {state}"))]
    SubsystemStateConflict {
        /// Subsystem that triggered the conflict.
        subsystem: Subsystem,
        /// Human-readable current state ("enabled" or "disabled").
        state: &'static str,
    },
}

// ── Domain types ──────────────────────────────────────────────────────────────

/// Radio subsystems managed by WMT over the CONSYS combo chip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Subsystem {
    /// Bluetooth.
    Bt,
    /// FM radio.
    Fm,
    /// GPS.
    Gps,
    /// `WiFi`.
    Wifi,
}

impl Subsystem {
    /// Internal bitmask bit for this subsystem.
    const fn mask(self) -> u8 {
        match self {
            Self::Bt => 1 << 0,
            Self::Fm => 1 << 1,
            Self::Gps => 1 << 2,
            Self::Wifi => 1 << 3,
        }
    }
}

/// PMIC voltage regulators used by CONSYS subsystems.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[non_exhaustive]
pub enum PmicRegulator {
    /// VCN 1.8V  -  all CONSYS core logic.
    Vcn18,
    /// VCN 2.8V  -  GPS and FM RF circuits.
    Vcn28,
    /// VCN 3.3V  -  Bluetooth power amplifier.
    Vcn33Bt,
    /// VCN 3.3V  -  `WiFi` power amplifier.
    Vcn33Wifi,
}

impl PmicRegulator {
    /// Nominal output voltage in millivolts.
    pub const fn millivolts(self) -> u32 {
        match self {
            Self::Vcn18 => 1800,
            Self::Vcn28 => 2800,
            Self::Vcn33Bt | Self::Vcn33Wifi => 3300,
        }
    }
}

impl From<PmicRegulator> for u8 {
    fn from(reg: PmicRegulator) -> Self {
        reg as Self
    }
}

/// Co-clock type detected during step 12 of the power-on sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ClockType {
    /// CO-TSX: crystal shared with AP (`DCXO_CW16` bit 6 SET).
    CoTsx,
    /// TCXO: temperature-compensated XO (`DCXO_CW16` bit 7 SET).
    Tcxo,
    /// Could not determine clock type FROM PMIC register.
    Unknown,
}

/// Overall CONSYS block power state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PowerState {
    /// CONSYS is powered off.
    Off,
    /// CONSYS is powered on and the firmware CPU is running.
    On,
}

/// EMI memory regions used for CONSYS firmware and crash dumps.
///
/// All addresses are physical. Construct with [`EmiRegion::from_fw_base`] or
/// use [`EmiRegion::CONSYS_DEFAULT`] for the standard MT6739 layout.
#[expect(
    clippy::struct_field_names,
    reason = "hardware addresses share _base suffix to distinguish FROM offsets; renaming removes clarity"
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmiRegion {
    /// CONSYS MCU firmware load target.
    pub(crate) fw_base: u32,
    /// Live paged trace ring (`fw_base` + 0x400).
    pub(crate) paged_trace_base: u32,
    /// Paged crash dump, 32 KB (`fw_base` + 0x8400).
    pub(crate) paged_dump_base: u32,
    /// Full core dump DLM region, 0x1F000 bytes (`fw_base` + 0x10400).
    pub(crate) full_dump_dlm_base: u32,
    /// Full core dump SYSB2 region, 0x6800 bytes.
    pub(crate) full_dump_sysb2_base: u32,
    /// Full core dump SYSB3 region, 0x16800 bytes.
    pub(crate) full_dump_sysb3_base: u32,
}

impl EmiRegion {
    /// Compute all region addresses FROM a firmware base address.
    pub const fn from_fw_base(fw_base: u32) -> Self {
        Self {
            fw_base,
            paged_trace_base: fw_base + EMI_PAGED_TRACE_OFFSET,
            paged_dump_base: fw_base + EMI_PAGED_DUMP_OFFSET,
            full_dump_dlm_base: fw_base + EMI_FULL_DUMP_DLM_OFFSET,
            full_dump_sysb2_base: fw_base + EMI_FULL_DUMP_SYSB2_OFFSET,
            full_dump_sysb3_base: fw_base + EMI_FULL_DUMP_SYSB3_OFFSET,
        }
    }

    /// Standard CONSYS EMI layout for MT6739.
    pub const CONSYS_DEFAULT: Self = Self::from_fw_base(CONSYS_EMI_FW_PHY_BASE);
}

// ── Power-on state machine ────────────────────────────────────────────────────

/// Step in the 17-step CONSYS power-on sequence.
///
/// Each variant maps 1-to-1 to a numbered step FROM
/// `connectivity/common/common_main/platform/mt6739.c:459–545`.
/// [`Done`](Self::Done) marks successful completion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum PowerOnStep {
    #[default]
    /// Step 1: write [`CONSYS_PWRON_CONFG_EN_VALUE`] to SPM clock config.
    SpmClockEnable,
    /// Step 2: SET `PWR_ON_BIT` in `CONSYS_TOP1_PWR_CTRL_REG`.
    Top1PowerOn,
    /// Step 3: poll `CONSYS_PWR_CONN_ACK_REG` bit 1.
    PollPowerAck,
    /// Step 4: SET `PWR_ON_S_BIT` in `CONSYS_TOP1_PWR_CTRL_REG`.
    ShadowPowerOn,
    /// Step 5: clear `CLK_CTRL_BIT` in `CONSYS_TOP1_PWR_CTRL_REG`.
    ClockEnable,
    /// Step 6: delay 1 µs.
    DelayMicros,
    /// Step 7: poll `CONSYS_PWR_CONN_ACK_S_REG` bit 1.
    PollShadowAck,
    /// Step 8: clear `ISO_S_BIT` in `CONSYS_TOP1_PWR_CTRL_REG`.
    ReleaseIso,
    /// Step 9: SET `PWR_RST_BIT` in `CONSYS_TOP1_PWR_CTRL_REG`.
    ReleaseSwReset,
    /// Step 10: clear AXI bus protect bits and poll until clear.
    DisableAxiProtect,
    /// Step 11: write key + reset bit to `CONSYS_CPU_SW_RST_REG`.
    AssertCpuReset,
    /// Step 12: read PMIC `DCXO_CW16` to detect CO-TSX vs TCXO.
    DetectClockType,
    /// Step 13: enable clock buffer via `clk_buf_ctrl`.
    EnableClockBuffer,
    /// Step 14: enable AHB clock via CCF `clk_prepare_enable`.
    EnableAhbClock,
    /// Step 15: poll `CONSYS_CHIP_ID_REG` until `0x0699`.
    PollChipId,
    /// Step 16: clear CPU reset bit in `CONSYS_CPU_SW_RST_REG`.
    ReleaseCpuReset,
    /// Step 17: SET `MBIST` bit in `CONSYS_MCU_CFG_ACR_REG`.
    ApplyAcrSetting,
    /// Power-on sequence completed successfully.
    Done,
}

impl PowerOnStep {
    /// 1-based step index for diagnostics. Returns 0 for [`Done`](Self::Done).
    pub const fn index(self) -> u8 {
        match self {
            Self::SpmClockEnable => 1,
            Self::Top1PowerOn => 2,
            Self::PollPowerAck => 3,
            Self::ShadowPowerOn => 4,
            Self::ClockEnable => 5,
            Self::DelayMicros => 6,
            Self::PollShadowAck => 7,
            Self::ReleaseIso => 8,
            Self::ReleaseSwReset => 9,
            Self::DisableAxiProtect => 10,
            Self::AssertCpuReset => 11,
            Self::DetectClockType => 12,
            Self::EnableClockBuffer => 13,
            Self::EnableAhbClock => 14,
            Self::PollChipId => 15,
            Self::ReleaseCpuReset => 16,
            Self::ApplyAcrSetting => 17,
            Self::Done => 0,
        }
    }

    /// Execute this step via `io` and return the next step, or an error.
    ///
    /// `clock_type` is an out-parameter updated during [`DetectClockType`](Self::DetectClockType).
    pub fn execute_and_advance<R: RegisterIo>(
        self,
        io: &mut R,
        clock_type: &mut ClockType,
    ) -> Result<Self, WmtError> {
        match self {
            // Step 1: enable SPM clock gating for CONSYS domain
            Self::SpmClockEnable => {
                io.write32(CONSYS_SPM_PWRON_CFG_REG, CONSYS_PWRON_CONFG_EN_VALUE);
                Ok(Self::Top1PowerOn)
            }

            // Step 2: assert power-on for CONSYS top1
            Self::Top1PowerOn => {
                io.set_bits32(CONSYS_TOP1_PWR_CTRL_REG, CONSYS_SPM_PWR_ON_BIT);
                Ok(Self::PollPowerAck)
            }

            // Step 3: spin until power-on ack register bit 1 is SET
            Self::PollPowerAck => {
                for _ in 0..POLL_TIMEOUT_ITERS {
                    if io.read32(CONSYS_PWR_CONN_ACK_REG) & (1 << 1) != 0 {
                        return Ok(Self::ShadowPowerOn);
                    }
                }
                Err(WmtError::PowerAckTimeout { step: self.index() })
            }

            // Step 4: power on shadow register
            Self::ShadowPowerOn => {
                io.set_bits32(CONSYS_TOP1_PWR_CTRL_REG, CONSYS_SPM_PWR_ON_S_BIT);
                Ok(Self::ClockEnable)
            }

            // Step 5: enable clock by clearing the clock-disable bit
            Self::ClockEnable => {
                io.clear_bits32(CONSYS_TOP1_PWR_CTRL_REG, CONSYS_CLK_CTRL_BIT);
                Ok(Self::DelayMicros)
            }

            // Step 6: hardware setup time after clock enable
            Self::DelayMicros => {
                io.udelay(1);
                Ok(Self::PollShadowAck)
            }

            // Step 7: spin until shadow power-on ack bit 1 is SET
            Self::PollShadowAck => {
                for _ in 0..POLL_TIMEOUT_ITERS {
                    if io.read32(CONSYS_PWR_CONN_ACK_S_REG) & (1 << 1) != 0 {
                        return Ok(Self::ReleaseIso);
                    }
                }
                Err(WmtError::PowerAckTimeout { step: self.index() })
            }

            // Step 8: release isolation  -  CONSYS power domain can now communicate
            Self::ReleaseIso => {
                io.clear_bits32(CONSYS_TOP1_PWR_CTRL_REG, CONSYS_SPM_PWR_ISO_S_BIT);
                Ok(Self::ReleaseSwReset)
            }

            // Step 9: release software reset of CONSYS
            Self::ReleaseSwReset => {
                io.set_bits32(CONSYS_TOP1_PWR_CTRL_REG, CONSYS_SPM_PWR_RST_BIT);
                Ok(Self::DisableAxiProtect)
            }

            // Step 10: remove AXI bus isolation so CONSYS can reach system bus
            Self::DisableAxiProtect => {
                io.clear_bits32(CONSYS_TOPAXI_PROT_EN, CONSYS_TOPAXI_PROT_BITS);
                for _ in 0..POLL_TIMEOUT_ITERS {
                    if io.read32(CONSYS_TOPAXI_PROT_STA1) & CONSYS_TOPAXI_PROT_BITS == 0 {
                        return Ok(Self::AssertCpuReset);
                    }
                }
                Err(WmtError::AxiProtectTimeout)
            }

            // Step 11: hold CONSYS MCU in reset while firmware is loaded
            Self::AssertCpuReset => {
                io.write32(
                    CONSYS_CPU_SW_RST_REG,
                    CONSYS_CPU_SW_RST_KEY | CONSYS_CPU_SW_RST_BIT,
                );
                Ok(Self::DetectClockType)
            }

            // Step 12: read PMIC DCXO_CW16 to SELECT co-clock configuration
            Self::DetectClockType => {
                let cw16 = io.pmic_read(DCXO_CW16_REG);
                *clock_type = if cw16 & DCXO_CO_TSX_BIT != 0 {
                    ClockType::CoTsx
                } else if cw16 & DCXO_TCXO_BIT != 0 {
                    ClockType::Tcxo
                } else {
                    ClockType::Unknown
                };
                Ok(Self::EnableClockBuffer)
            }

            // Step 13: enable CONSYS clock buffer so the reference clock is stable
            Self::EnableClockBuffer => {
                io.clk_buf_ctrl(true);
                Ok(Self::EnableAhbClock)
            }

            // Step 14: gate-on the AHB clock for the CONSYS power domain
            Self::EnableAhbClock => {
                io.clk_ahb_enable();
                Ok(Self::PollChipId)
            }

            // Step 15: verify the CONSYS MCU responded with the correct chip ID
            Self::PollChipId => {
                for _ in 0..POLL_TIMEOUT_ITERS {
                    let id = io.read32(CONSYS_CHIP_ID_REG);
                    if id == CONSYS_CHIP_ID_EXPECTED {
                        return Ok(Self::ReleaseCpuReset);
                    }
                }
                Err(WmtError::ChipIdMismatch {
                    expected: CONSYS_CHIP_ID_EXPECTED,
                    got: io.read32(CONSYS_CHIP_ID_REG),
                })
            }

            // Step 16: release MCU reset  -  firmware begins executing
            Self::ReleaseCpuReset => {
                // WHY: keep key in register; only clear the reset bit
                io.write32(CONSYS_CPU_SW_RST_REG, CONSYS_CPU_SW_RST_KEY);
                Ok(Self::ApplyAcrSetting)
            }

            // Step 17: enable MBIST in ACR for built-in self-test readiness
            Self::ApplyAcrSetting => {
                io.set_bits32(CONSYS_MCU_CFG_ACR_REG, CONSYS_MCU_CFG_ACR_MBIST_BIT);
                Ok(Self::Done)
            }

            Self::Done => Ok(Self::Done),
        }
    }
}

// ── Hardware abstraction ───────────────────────────────────────────────────────

/// Hardware register and platform I/O abstraction.
///
/// WHY: abstracting all hardware operations behind this trait allows the
/// [`WmtManager`] power-on state machine to be unit-tested without physical
/// hardware by substituting a [`FakeIo`] implementation.
pub trait RegisterIo {
    /// Read a 32-bit MMIO register at `addr`.
    fn read32(&mut self, addr: u32) -> u32;

    /// Write `val` to a 32-bit MMIO register at `addr`.
    fn write32(&mut self, addr: u32, val: u32);

    /// Set bits in `mask` in the register at `addr` (read-modify-write).
    fn set_bits32(&mut self, addr: u32, mask: u32) {
        let v = self.read32(addr);
        self.write32(addr, v | mask);
    }

    /// Clear bits in `mask` in the register at `addr` (read-modify-write).
    fn clear_bits32(&mut self, addr: u32, mask: u32) {
        let v = self.read32(addr);
        self.write32(addr, v & !mask);
    }

    /// Delay at least `micros` microseconds.
    fn udelay(&mut self, micros: u32);

    /// Read an 8-bit PMIC register at `reg` via I2C.
    fn pmic_read(&mut self, reg: u8) -> u8;

    /// Enable or disable the CONSYS clock buffer.
    fn clk_buf_ctrl(&mut self, enable: bool);

    /// Enable the AHB bus clock for the CONSYS power domain via CCF.
    fn clk_ahb_enable(&mut self);

    /// Enable a PMIC voltage regulator.
    fn pmic_regulator_enable(&mut self, reg: PmicRegulator);

    /// Disable a PMIC voltage regulator.
    fn pmic_regulator_disable(&mut self, reg: PmicRegulator);
}

/// MMIO [`RegisterIo`] implementation using volatile reads/writes to physical addresses.
pub struct MmioRegisterIo;

impl RegisterIo for MmioRegisterIo {
    #[expect(
        unsafe_code,
        reason = "MMIO requires volatile read FROM physical address"
    )]
    fn read32(&mut self, addr: u32) -> u32 {
        // SAFETY: addr is a known-valid CONSYS MMIO register mapped by the kernel.
        unsafe { core::ptr::read_volatile(addr as *const u32) }
    }

    #[expect(
        unsafe_code,
        reason = "MMIO requires volatile write to physical address"
    )]
    fn write32(&mut self, addr: u32, val: u32) {
        // SAFETY: addr is a known-valid CONSYS MMIO register mapped by the kernel.
        unsafe { core::ptr::write_volatile(addr as *mut u32, val) }
    }

    fn udelay(&mut self, micros: u32) {
        // WHY: busy-loop delay in kernel context WHERE sleep is unavailable.
        // Calibration assumes ~1000 cycles/µs at 1 GHz; acceptable for 1 µs steps.
        let cycles = usize::try_from(micros).unwrap_or_default() * 1000;
        for _ in 0..cycles {
            core::hint::spin_loop();
        }
    }

    fn pmic_read(&mut self, _reg: u8) -> u8 {
        // NOTE: full PMIC I2C driver is implemented in the telephony crate.
        // Return 0 here; clock type will be Unknown until the PMIC driver is wired in.
        0
    }

    fn clk_buf_ctrl(&mut self, _enable: bool) {
        // NOTE: clock buffer control requires CCF integration (future wave).
    }

    fn clk_ahb_enable(&mut self) {
        // NOTE: CCF clock gating integration (future wave).
    }

    fn pmic_regulator_enable(&mut self, _reg: PmicRegulator) {
        // NOTE: PMIC regulator control via I2C (future wave).
    }

    fn pmic_regulator_disable(&mut self, _reg: PmicRegulator) {
        // NOTE: PMIC regulator control via I2C (future wave).
    }
}

// ── WmtManager ────────────────────────────────────────────────────────────────

/// WMT connectivity manager for the MT6739 CONSYS combo chip.
///
/// Owns power sequencing, subsystem enable/disable, and the platform I/O handle.
/// Generic over [`RegisterIo`] so the power-on state machine can be tested
/// without hardware.
pub struct WmtManager<R: RegisterIo> {
    io: R,
    power: PowerState,
    /// WHY: persisted for post-failure diagnostics  -  tells the debugger
    /// exactly which of the 17 steps failed during power-on.
    power_on_step: PowerOnStep,
    clock_type: ClockType,
    /// Bitmask of currently enabled subsystems.
    subsystems: u8,
    /// Computed EMI region layout for this device.
    emi: EmiRegion,
}

impl<R: RegisterIo> WmtManager<R> {
    /// Create a new manager with the given I/O handle.
    ///
    /// CONSYS starts in [`PowerState::Off`]. Call [`power_on`](Self::power_on)
    /// before enabling any subsystem.
    pub const fn new(io: R) -> Self {
        Self {
            io,
            power: PowerState::Off,
            power_on_step: PowerOnStep::SpmClockEnable,
            clock_type: ClockType::Unknown,
            subsystems: 0,
            emi: EmiRegion::CONSYS_DEFAULT,
        }
    }

    /// Execute the 17-step CONSYS power-on sequence.
    ///
    /// Drives the [`PowerOnStep`] state machine FROM `SpmClockEnable` through
    /// `Done`, returning an error if any step fails. The failing step is
    /// preserved in the manager and visible via [`current_step`](Self::current_step).
    #[must_use = "power-on failure must be handled"]
    pub fn power_on(&mut self) -> Result<(), WmtError> {
        if self.power == PowerState::On {
            return Err(WmtError::AlreadyPoweredOn);
        }

        // Enable core 1.8V regulator before touching any CONSYS register.
        self.io.pmic_regulator_enable(PmicRegulator::Vcn18);

        let mut step = PowerOnStep::SpmClockEnable;
        loop {
            self.power_on_step = step;
            step = step.execute_and_advance(&mut self.io, &mut self.clock_type)?;
            if step == PowerOnStep::Done {
                self.power_on_step = PowerOnStep::Done;
                break;
            }
        }

        self.power = PowerState::On;
        Ok(())
    }

    /// Reverse shutdown sequence  -  mirrors power-on in reverse ORDER.
    #[must_use = "power-off failure must be handled"]
    pub fn power_off(&mut self) -> Result<(), WmtError> {
        if self.power == PowerState::Off {
            return Err(WmtError::AlreadyPoweredOff);
        }

        // Assert CPU reset before touching clocks.
        self.io.write32(
            CONSYS_CPU_SW_RST_REG,
            CONSYS_CPU_SW_RST_KEY | CONSYS_CPU_SW_RST_BIT,
        );

        // Re-enable AXI bus protect to isolate CONSYS FROM system bus.
        self.io
            .set_bits32(CONSYS_TOPAXI_PROT_EN, CONSYS_TOPAXI_PROT_BITS);

        // Gate AHB clock and clock buffer.
        self.io.clk_buf_ctrl(false);

        // Assert isolation.
        self.io
            .set_bits32(CONSYS_TOP1_PWR_CTRL_REG, CONSYS_SPM_PWR_ISO_S_BIT);

        // Clear SW reset bit.
        self.io
            .clear_bits32(CONSYS_TOP1_PWR_CTRL_REG, CONSYS_SPM_PWR_RST_BIT);

        // Disable clock, shadow, and main power.
        self.io
            .set_bits32(CONSYS_TOP1_PWR_CTRL_REG, CONSYS_CLK_CTRL_BIT);
        self.io
            .clear_bits32(CONSYS_TOP1_PWR_CTRL_REG, CONSYS_SPM_PWR_ON_S_BIT);
        self.io
            .clear_bits32(CONSYS_TOP1_PWR_CTRL_REG, CONSYS_SPM_PWR_ON_BIT);

        // Disable core regulator last.
        self.io.pmic_regulator_disable(PmicRegulator::Vcn18);

        self.power = PowerState::Off;
        self.subsystems = 0;
        Ok(())
    }

    /// Enable a radio subsystem.
    ///
    /// Turns on the appropriate PMIC regulator for the subsystem and records
    /// it as active. CONSYS must already be powered on.
    #[must_use = "subsystem enable failure must be handled"]
    pub fn enable_subsystem(&mut self, subsystem: Subsystem) -> Result<(), WmtError> {
        if self.subsystems & subsystem.mask() != 0 {
            return Err(WmtError::SubsystemStateConflict {
                subsystem,
                state: "enabled",
            });
        }
        let reg = Self::subsystem_regulator(subsystem);
        self.io.pmic_regulator_enable(reg);
        self.subsystems |= subsystem.mask();
        Ok(())
    }

    /// Disable a radio subsystem.
    ///
    /// Turns off the subsystem's PMIC regulator (if no other subsystem sharing
    /// it remains active) and records it as inactive.
    #[must_use = "subsystem disable failure must be handled"]
    pub fn disable_subsystem(&mut self, subsystem: Subsystem) -> Result<(), WmtError> {
        if self.subsystems & subsystem.mask() == 0 {
            return Err(WmtError::SubsystemStateConflict {
                subsystem,
                state: "disabled",
            });
        }
        let reg = Self::subsystem_regulator(subsystem);
        self.io.pmic_regulator_disable(reg);
        self.subsystems &= !subsystem.mask();
        Ok(())
    }

    /// Enable a PMIC regulator directly.
    pub fn enable_regulator(&mut self, reg: PmicRegulator) {
        self.io.pmic_regulator_enable(reg);
    }

    /// Disable a PMIC regulator directly.
    pub fn disable_regulator(&mut self, reg: PmicRegulator) {
        self.io.pmic_regulator_disable(reg);
    }

    /// Current power-on step  -  useful for diagnosing boot failures.
    pub const fn current_step(&self) -> PowerOnStep {
        self.power_on_step
    }

    /// Current CONSYS power state.
    pub const fn power_state(&self) -> PowerState {
        self.power
    }

    /// Detected co-clock type (valid after [`power_on`](Self::power_on) succeeds).
    pub const fn clock_type(&self) -> ClockType {
        self.clock_type
    }

    /// Reference to the EMI region layout.
    pub const fn emi_region(&self) -> &EmiRegion {
        &self.emi
    }

    /// Returns true if the given subsystem is currently enabled.
    pub const fn subsystem_enabled(&self, subsystem: Subsystem) -> bool {
        self.subsystems & subsystem.mask() != 0
    }

    /// Map a subsystem to its primary PMIC regulator.
    const fn subsystem_regulator(subsystem: Subsystem) -> PmicRegulator {
        match subsystem {
            Subsystem::Bt => PmicRegulator::Vcn33Bt,
            Subsystem::Wifi => PmicRegulator::Vcn33Wifi,
            // GPS and FM share the 2.8V RF regulator.
            Subsystem::Gps | Subsystem::Fm => PmicRegulator::Vcn28,
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test code — expect_err on Results is intentional for verifying error conditions"
)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    /// Fake register I/O for unit testing without hardware.
    struct FakeIo {
        regs: HashMap<u32, u32>,
        pmic_regs: HashMap<u8, u8>,
        /// Bitmask of regulators currently enabled.
        regulators: u8,
        /// Whether `clk_buf` is enabled.
        clk_buf: bool,
        /// Whether AHB clock is enabled.
        ahb_clk: bool,
        /// Force chip ID register to return this value.
        chip_id: u32,
        /// Ops log for asserting call ordering.
        log: Vec<String>,
    }

    impl FakeIo {
        fn new() -> Self {
            let mut regs = HashMap::new();
            // Pre-SET ack bits so polls succeed immediately.
            regs.insert(CONSYS_PWR_CONN_ACK_REG, 0b10);
            regs.insert(CONSYS_PWR_CONN_ACK_S_REG, 0b10);
            // Pre-clear AXI protect status so step 10 poll succeeds.
            regs.insert(CONSYS_TOPAXI_PROT_STA1, 0x0000_0000);
            // Set correct chip ID.
            regs.insert(CONSYS_CHIP_ID_REG, CONSYS_CHIP_ID_EXPECTED);

            Self {
                regs,
                pmic_regs: HashMap::new(),
                regulators: 0,
                clk_buf: false,
                ahb_clk: false,
                chip_id: CONSYS_CHIP_ID_EXPECTED,
                log: Vec::new(),
            }
        }

        fn reg(&self, addr: u32) -> u32 {
            self.regs.get(&addr).copied().unwrap_or(0)
        }
    }

    impl RegisterIo for FakeIo {
        fn read32(&mut self, addr: u32) -> u32 {
            // WHY: chip ID register returns the configurable field for mismatch tests.
            if addr == CONSYS_CHIP_ID_REG {
                return self.chip_id;
            }
            self.regs.get(&addr).copied().unwrap_or(0)
        }

        fn write32(&mut self, addr: u32, val: u32) {
            self.log.push(format!("write32({addr:#010x}, {val:#010x})"));
            self.regs.insert(addr, val);
        }

        fn udelay(&mut self, micros: u32) {
            self.log.push(format!("udelay({micros})"));
        }

        fn pmic_read(&mut self, reg: u8) -> u8 {
            self.pmic_regs.get(&reg).copied().unwrap_or(0)
        }

        fn clk_buf_ctrl(&mut self, enable: bool) {
            self.clk_buf = enable;
            self.log.push(format!("clk_buf_ctrl({enable})"));
        }

        fn clk_ahb_enable(&mut self) {
            self.ahb_clk = true;
            self.log.push("clk_ahb_enable".to_owned());
        }

        fn pmic_regulator_enable(&mut self, reg: PmicRegulator) {
            self.regulators |= 1 << u8::from(reg);
            self.log.push(format!("pmic_enable({reg:?})"));
        }

        fn pmic_regulator_disable(&mut self, reg: PmicRegulator) {
            self.regulators &= !(1 << u8::from(reg));
            self.log.push(format!("pmic_disable({reg:?})"));
        }
    }

    // ── register constant correctness ─────────────────────────────────────────

    #[test]
    fn register_constants_spm_base() {
        assert_eq!(
            SPM_BASE, 0xF000_6000,
            "SPM_BASE must match MT6739 datasheet"
        );
    }

    #[test]
    fn register_constants_top1_pwr_ctrl() {
        assert_eq!(
            CONSYS_TOP1_PWR_CTRL_REG, 0xF000_632C,
            "CONSYS_TOP1_PWR_CTRL_REG = SPM_BASE + 0x32C"
        );
    }

    #[test]
    fn register_constants_conn_mcu_chip_id() {
        assert_eq!(
            CONSYS_CHIP_ID_REG, 0xF807_0008,
            "CONSYS_CHIP_ID_REG = CONN_MCU_CONFIG_BASE + 0x008"
        );
    }

    #[test]
    fn register_constants_topaxi_prot() {
        assert_eq!(
            CONSYS_TOPAXI_PROT_EN, 0xF000_1220,
            "CONSYS_TOPAXI_PROT_EN = TOPCKGEN_BASE + 0x1220"
        );
        assert_eq!(
            CONSYS_TOPAXI_PROT_STA1, 0xF000_1228,
            "CONSYS_TOPAXI_PROT_STA1 = TOPCKGEN_BASE + 0x1228"
        );
    }

    // ── power-on state machine ────────────────────────────────────────────────

    #[test]
    fn power_on_step1_writes_spm_clock_enable() {
        let mut io = FakeIo::new();
        let mut ct = ClockType::Unknown;
        let next = PowerOnStep::SpmClockEnable
            .execute_and_advance(&mut io, &mut ct)
            .unwrap_or_default();
        assert_eq!(
            io.reg(CONSYS_SPM_PWRON_CFG_REG),
            CONSYS_PWRON_CONFG_EN_VALUE,
            "step 1 must write CONSYS_PWRON_CONFG_EN_VALUE to SPM clock config"
        );
        assert_eq!(next, PowerOnStep::Top1PowerOn, "step 1 advances to step 2");
    }

    #[test]
    fn power_on_step2_sets_pwr_on_bit() {
        let mut io = FakeIo::new();
        let mut ct = ClockType::Unknown;
        let next = PowerOnStep::Top1PowerOn
            .execute_and_advance(&mut io, &mut ct)
            .unwrap_or_default();
        let ctrl = io.reg(CONSYS_TOP1_PWR_CTRL_REG);
        assert!(
            ctrl & CONSYS_SPM_PWR_ON_BIT != 0,
            "step 2 must SET PWR_ON_BIT in CONSYS_TOP1_PWR_CTRL_REG"
        );
        assert_eq!(next, PowerOnStep::PollPowerAck, "step 2 advances to step 3");
    }

    #[test]
    fn power_on_step4_sets_shadow_pwr_on_bit() {
        let mut io = FakeIo::new();
        let mut ct = ClockType::Unknown;
        PowerOnStep::ShadowPowerOn
            .execute_and_advance(&mut io, &mut ct)
            .unwrap_or_default();
        let ctrl = io.reg(CONSYS_TOP1_PWR_CTRL_REG);
        assert!(
            ctrl & CONSYS_SPM_PWR_ON_S_BIT != 0,
            "step 4 must SET PWR_ON_S_BIT"
        );
    }

    #[test]
    fn power_on_step5_clears_clk_ctrl_bit() {
        let mut io = FakeIo::new();
        // Pre-SET the clock-disable bit so we can observe it being cleared.
        io.regs
            .insert(CONSYS_TOP1_PWR_CTRL_REG, CONSYS_CLK_CTRL_BIT);
        let mut ct = ClockType::Unknown;
        PowerOnStep::ClockEnable
            .execute_and_advance(&mut io, &mut ct)
            .unwrap_or_default();
        let ctrl = io.reg(CONSYS_TOP1_PWR_CTRL_REG);
        assert_eq!(
            ctrl & CONSYS_CLK_CTRL_BIT,
            0,
            "step 5 must clear CLK_CTRL_BIT to enable clock"
        );
    }

    #[test]
    fn power_on_step11_writes_cpu_reset_with_key() {
        let mut io = FakeIo::new();
        let mut ct = ClockType::Unknown;
        PowerOnStep::AssertCpuReset
            .execute_and_advance(&mut io, &mut ct)
            .unwrap_or_default();
        let val = io.reg(CONSYS_CPU_SW_RST_REG);
        assert_eq!(
            val,
            CONSYS_CPU_SW_RST_KEY | CONSYS_CPU_SW_RST_BIT,
            "step 11 must write key + reset bit to CONSYS_CPU_SW_RST_REG"
        );
    }

    #[test]
    fn power_on_step16_clears_cpu_reset_keeps_key() {
        let mut io = FakeIo::new();
        let mut ct = ClockType::Unknown;
        PowerOnStep::ReleaseCpuReset
            .execute_and_advance(&mut io, &mut ct)
            .unwrap_or_default();
        let val = io.reg(CONSYS_CPU_SW_RST_REG);
        assert_eq!(
            val & CONSYS_CPU_SW_RST_BIT,
            0,
            "step 16 must clear reset bit"
        );
        assert_eq!(
            val & CONSYS_CPU_SW_RST_KEY,
            CONSYS_CPU_SW_RST_KEY,
            "step 16 must preserve key field"
        );
    }

    #[test]
    fn power_on_full_sequence_succeeds() {
        let io = FakeIo::new();
        let mut mgr = WmtManager::new(io);
        mgr.power_on().unwrap_or_default();
        assert_eq!(
            mgr.power_state(),
            PowerState::On,
            "power state must be On after successful power_on"
        );
        assert_eq!(
            mgr.current_step(),
            PowerOnStep::Done,
            "step must be Done after successful power_on"
        );
    }

    #[test]
    fn power_on_ack_timeout_returns_error() {
        let mut io = FakeIo::new();
        // Remove the ack bit so polling never succeeds.
        io.regs.insert(CONSYS_PWR_CONN_ACK_REG, 0x0000_0000);
        let mut mgr = WmtManager::new(io);
        let err = mgr
            .power_on()
            .expect_err("must fail when ack bit never sets");
        assert!(
            matches!(err, WmtError::PowerAckTimeout { step: 3 }),
            "error must be PowerAckTimeout at step 3, got {err:?}"
        );
    }

    #[test]
    fn power_on_chip_id_mismatch_returns_error() {
        let mut io = FakeIo::new();
        // Return wrong chip ID so step 15 never matches.
        io.chip_id = 0xDEAD_BEEF;
        let mut mgr = WmtManager::new(io);
        let err = mgr
            .power_on()
            .expect_err("must fail when chip ID does not match 0x0699");
        assert!(
            matches!(
                err,
                WmtError::ChipIdMismatch {
                    expected: CONSYS_CHIP_ID_EXPECTED,
                    got: 0xDEAD_BEEF
                }
            ),
            "error must be ChipIdMismatch, got {err:?}"
        );
    }

    #[test]
    fn power_on_already_on_returns_error() {
        let io = FakeIo::new();
        let mut mgr = WmtManager::new(io);
        mgr.power_on().unwrap_or_default();
        let err = mgr
            .power_on()
            .expect_err("second power_on must fail with AlreadyPoweredOn");
        assert!(
            matches!(err, WmtError::AlreadyPoweredOn),
            "error must be AlreadyPoweredOn, got {err:?}"
        );
    }

    // ── subsystem enable/disable ──────────────────────────────────────────────

    #[test]
    fn enable_subsystem_bt_succeeds() {
        let io = FakeIo::new();
        let mut mgr = WmtManager::new(io);
        mgr.power_on().unwrap_or_default();
        mgr.enable_subsystem(Subsystem::Bt).unwrap_or_default();
        assert!(
            mgr.subsystem_enabled(Subsystem::Bt),
            "BT must be enabled after enable_subsystem(Bt)"
        );
    }

    #[test]
    fn enable_subsystem_wifi_uses_vcn33_wifi_regulator() {
        let io = FakeIo::new();
        let mut mgr = WmtManager::new(io);
        mgr.power_on().unwrap_or_default();
        mgr.enable_subsystem(Subsystem::Wifi).unwrap_or_default();
        let enabled_bit = 1u8 << u8::from(PmicRegulator::Vcn33Wifi);
        assert!(
            mgr.io.regulators & enabled_bit != 0,
            "Vcn33Wifi regulator must be enabled when WiFi subsystem is enabled"
        );
    }

    #[test]
    fn enable_subsystem_gps_fm_use_vcn28_regulator() {
        let io = FakeIo::new();
        let mut mgr = WmtManager::new(io);
        mgr.power_on().unwrap_or_default();
        mgr.enable_subsystem(Subsystem::Gps).unwrap_or_default();
        let vcn28_bit = 1u8 << u8::from(PmicRegulator::Vcn28);
        assert!(
            mgr.io.regulators & vcn28_bit != 0,
            "Vcn28 regulator must be enabled for GPS"
        );
    }

    #[test]
    fn disable_subsystem_bt_succeeds() {
        let io = FakeIo::new();
        let mut mgr = WmtManager::new(io);
        mgr.power_on().unwrap_or_default();
        mgr.enable_subsystem(Subsystem::Bt).unwrap_or_default();
        mgr.disable_subsystem(Subsystem::Bt).unwrap_or_default();
        assert!(
            !mgr.subsystem_enabled(Subsystem::Bt),
            "BT must not be enabled after disable_subsystem(Bt)"
        );
    }

    #[test]
    fn disable_subsystem_already_disabled_returns_error() {
        let io = FakeIo::new();
        let mut mgr = WmtManager::new(io);
        mgr.power_on().unwrap_or_default();
        let err = mgr
            .disable_subsystem(Subsystem::Fm)
            .expect_err("disabling already-disabled FM must fail");
        assert!(
            matches!(
                err,
                WmtError::SubsystemStateConflict {
                    subsystem: Subsystem::Fm,
                    state: "disabled"
                }
            ),
            "error must be SubsystemStateConflict, got {err:?}"
        );
    }

    #[test]
    fn enable_subsystem_already_enabled_returns_error() {
        let io = FakeIo::new();
        let mut mgr = WmtManager::new(io);
        mgr.power_on().unwrap_or_default();
        mgr.enable_subsystem(Subsystem::Gps).unwrap_or_default();
        let err = mgr
            .enable_subsystem(Subsystem::Gps)
            .expect_err("second enable must fail with SubsystemStateConflict");
        assert!(
            matches!(
                err,
                WmtError::SubsystemStateConflict {
                    subsystem: Subsystem::Gps,
                    state: "enabled"
                }
            ),
            "error must be SubsystemStateConflict, got {err:?}"
        );
    }

    // ── EMI layout ────────────────────────────────────────────────────────────

    #[test]
    fn emi_region_default_layout() {
        let emi = EmiRegion::CONSYS_DEFAULT;
        assert_eq!(
            emi.fw_base, CONSYS_EMI_FW_PHY_BASE,
            "default fw_base must equal CONSYS_EMI_FW_PHY_BASE"
        );
        assert_eq!(
            emi.paged_trace_base,
            CONSYS_EMI_FW_PHY_BASE + 0x0000_0400,
            "paged_trace_base must be fw_base + 0x400"
        );
        assert_eq!(
            emi.paged_dump_base,
            CONSYS_EMI_FW_PHY_BASE + 0x0000_8400,
            "paged_dump_base must be fw_base + 0x8400"
        );
        assert_eq!(
            emi.full_dump_dlm_base,
            CONSYS_EMI_FW_PHY_BASE + 0x0001_0400,
            "full_dump_dlm_base must be fw_base + 0x10400"
        );
    }

    // ── PMIC regulator types ──────────────────────────────────────────────────

    #[test]
    fn pmic_regulator_millivolts() {
        assert_eq!(
            PmicRegulator::Vcn18.millivolts(),
            1800,
            "Vcn18 must report 1800 mV"
        );
        assert_eq!(
            PmicRegulator::Vcn28.millivolts(),
            2800,
            "Vcn28 must report 2800 mV"
        );
        assert_eq!(
            PmicRegulator::Vcn33Bt.millivolts(),
            3300,
            "Vcn33Bt must report 3300 mV"
        );
        assert_eq!(
            PmicRegulator::Vcn33Wifi.millivolts(),
            3300,
            "Vcn33Wifi must report 3300 mV"
        );
    }

    // ── power-off ─────────────────────────────────────────────────────────────

    #[test]
    fn power_off_after_power_on_succeeds() {
        let io = FakeIo::new();
        let mut mgr = WmtManager::new(io);
        mgr.power_on().unwrap_or_default();
        mgr.power_off().unwrap_or_default();
        assert_eq!(
            mgr.power_state(),
            PowerState::Off,
            "power state must be Off after power_off"
        );
    }

    #[test]
    fn power_off_already_off_returns_error() {
        let io = FakeIo::new();
        let mut mgr = WmtManager::new(io);
        let err = mgr
            .power_off()
            .expect_err("power_off on Off state must fail");
        assert!(
            matches!(err, WmtError::AlreadyPoweredOff),
            "error must be AlreadyPoweredOff, got {err:?}"
        );
    }
}
