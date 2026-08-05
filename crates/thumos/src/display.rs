//! Display Data Path (DDP) driver for the MT6739.
//!
//! Implements the MediaTek display pipeline: OVL0 → RDMA0 → DSI0 → LCM.
//! The [`DisplayDriver`] orchestrates the 10-step hardware init sequence
//! and provides framebuffer UPDATE via RDMA0 memory mode.
//!
//! Panel support is pluggable via the [`LcmControl`] and [`LcmBacklight`]
//! traits. The [`Gc9306`] implements these for the AGM M7's GC9306
//! panel controller using the init sequence from `docs/GC9306-INIT.md`.
//!
//! Register offsets FROM `docs/DRIVER-INTERFACES.md` §7.

use crate::mmio;
#[cfg(not(test))]
use crate::timer;

// ---------------------------------------------------------------------------
// Constants: base addresses
// ---------------------------------------------------------------------------

/// AGM M7 display width in pixels.
const DISPLAY_WIDTH: u16 = 240;

/// AGM M7 display height in pixels.
const DISPLAY_HEIGHT: u16 = 320;

/// RGB565 bytes per pixel.
const BPP_RGB565: u16 = 2;

/// Framebuffer address alignment (16-byte boundary for DMA).
const FB_ADDR_ALIGN: usize = 16;

// ---------------------------------------------------------------------------
// Constants: MMSYS registers (§7.2)
// ---------------------------------------------------------------------------

/// MMSYS register block.
mod mmsys {

    /// Clock gate status 0.
    pub(crate) const CG_CON0: usize = crate::board::MMSYS_BASE + 0x100;
    /// Clock gate SET 0 (write 1 = disable clock).
    pub(crate) const CG_SET0: usize = crate::board::MMSYS_BASE + 0x104;
    /// Clock gate clear 0 (write 1 = enable clock).
    pub(crate) const CG_CLR0: usize = crate::board::MMSYS_BASE + 0x108;
    /// Clock gate status 1.
    pub(crate) const CG_CON1: usize = crate::board::MMSYS_BASE + 0x110;
    /// Clock gate SET 1 (write 1 = disable clock).
    pub(crate) const CG_SET1: usize = crate::board::MMSYS_BASE + 0x114;
    /// Clock gate clear 1 (write 1 = enable clock).
    pub(crate) const CG_CLR1: usize = crate::board::MMSYS_BASE + 0x118;
    /// Software reset 0 (active low  -  write 1 to release).
    pub(crate) const SW0_RST_B: usize = crate::board::MMSYS_BASE + 0x140;
    /// Software reset 1 (active low  -  write 1 to release).
    pub(crate) const SW1_RST_B: usize = crate::board::MMSYS_BASE + 0x144;
    /// LCM reset control (active low  -  write 1 to release).
    pub(crate) const LCM_RST_B: usize = crate::board::MMSYS_BASE + 0x150;

    // WHY: clock gate bits for display pipeline modules in CG_CLR0/CG_CLR1.
    // These enable the clocks for each module when written to the CLR register.

    /// Bit mask: all display pipeline clocks in CG0.
    /// OVL0(bit 0) | RDMA0(bit 3) | COLOR0(bit 5) | DSI0(bit 24).
    pub(crate) const CG0_DISP_ALL: u32 = (1 << 0) | (1 << 3) | (1 << 5) | (1 << 24);

    /// Bit mask: display pipeline clocks in CG1.
    /// DSI0_DIGITAL(bit 0) | DSI0_ENGINE(bit 1).
    pub(crate) const CG1_DISP_ALL: u32 = (1 << 0) | (1 << 1);

    /// Full release mask for SW0_RST_B.
    pub(crate) const SW0_RST_RELEASE: u32 = 0xFFFF_FFFF;

    /// Full release mask for SW1_RST_B.
    pub(crate) const SW1_RST_RELEASE: u32 = 0xFFFF_FFFF;

    /// LCM reset release (bit 0).
    pub(crate) const LCM_RST_RELEASE: u32 = 1;
}

// ---------------------------------------------------------------------------
// Constants: OVL registers (§7.3)
// ---------------------------------------------------------------------------

/// OVL0 register block.
mod ovl {

    /// Status; bit 0 = running.
    pub(crate) const STA: usize = crate::board::OVL0_BASE;
    /// Interrupt enable.
    pub(crate) const INTEN: usize = crate::board::OVL0_BASE + 0x004;
    /// Interrupt status.
    pub(crate) const INTSTA: usize = crate::board::OVL0_BASE + 0x008;
    /// Enable; bit 0 = OVL_EN, bit 8 = CK_ON.
    pub(crate) const EN: usize = crate::board::OVL0_BASE + 0x00C;
    /// Trigger; bit 0 = SW_TRIG.
    pub(crate) const TRIG: usize = crate::board::OVL0_BASE + 0x010;
    /// Reset.
    pub(crate) const RST: usize = crate::board::OVL0_BASE + 0x014;
    /// Region of interest size; bits [12:0] = W, bits [28:16] = H.
    pub(crate) const ROI_SIZE: usize = crate::board::OVL0_BASE + 0x020;
    /// Datapath config.
    pub(crate) const DATAPATH_CON: usize = crate::board::OVL0_BASE + 0x024;
    /// Background colour RGBA.
    pub(crate) const ROI_BGCLR: usize = crate::board::OVL0_BASE + 0x028;
    /// Source enable; bits 0–3 = layer 0–3 enable.
    pub(crate) const SRC_CON: usize = crate::board::OVL0_BASE + 0x02C;
    /// Layer 0 control (alpha, flip, format).
    pub(crate) const L0_CON: usize = crate::board::OVL0_BASE + 0x030;

    /// OVL_EN bit.
    pub(crate) const EN_BIT: u32 = 1 << 0;
    /// CK_ON bit (force clock on).
    pub(crate) const CK_ON_BIT: u32 = 1 << 8;
    /// SW_TRIG bit.
    pub(crate) const SW_TRIG_BIT: u32 = 1 << 0;
    /// Layer 0 enable bit in SRC_CON.
    pub(crate) const LAYER0_EN: u32 = 1 << 0;

    /// Frame complete interrupt enable.
    pub(crate) const FME_CPL_INTEN: u32 = 1 << 1;

    // WHY: L0_CON format field  -  bits [15:12] SELECT pixel format.
    // 0b0000 = RGB565, 0b0010 = RGB888, 0b0011 = ARGB8888.

    /// RGB565 format in layer control register bits [15:12].
    pub(crate) const FMT_RGB565: u32 = 0b0000 << 12;
}

// ---------------------------------------------------------------------------
// Constants: RDMA registers
// ---------------------------------------------------------------------------

/// RDMA0 register block.
mod rdma {

    /// Global control; bit 0 = ENGINE_EN, bit 1 = MODE_SEL (1=memory).
    pub(crate) const GLOBAL_CON: usize = crate::board::RDMA0_BASE;
    /// Output frame width.
    pub(crate) const SIZE_CON_0: usize = crate::board::RDMA0_BASE + 0x014;
    /// Output frame height.
    pub(crate) const SIZE_CON_1: usize = crate::board::RDMA0_BASE + 0x018;
    /// Memory mode control (format selection).
    pub(crate) const MEM_CON: usize = crate::board::RDMA0_BASE + 0x024;
    /// Memory source pitch (stride in bytes).
    pub(crate) const MEM_SRC_PITCH: usize = crate::board::RDMA0_BASE + 0x02C;
    /// Framebuffer start address (physical).
    pub(crate) const MEM_START_ADDR: usize = crate::board::RDMA0_BASE + 0x0F0;

    /// ENGINE_EN bit.
    pub(crate) const ENGINE_EN: u32 = 1 << 0;
    /// MODE_SEL bit (1 = memory mode).
    pub(crate) const MODE_MEMORY: u32 = 1 << 1;

    /// RGB565 input format in MEM_CON.
    pub(crate) const FMT_RGB565: u32 = 0;
}

// ---------------------------------------------------------------------------
// Constants: DSI registers
// ---------------------------------------------------------------------------

/// DSI0 register block.
mod dsi {

    /// DSI start control.
    pub(crate) const START: usize = crate::board::DSI0_BASE;
    /// Interrupt enable.
    pub(crate) const INTEN: usize = crate::board::DSI0_BASE + 0x008;
    /// Interrupt status.
    pub(crate) const INTSTA: usize = crate::board::DSI0_BASE + 0x00C;
    /// Connection control.
    pub(crate) const CON_CTRL: usize = crate::board::DSI0_BASE + 0x010;
    /// Mode control (CMD vs VDO).
    pub(crate) const MODE_CTRL: usize = crate::board::DSI0_BASE + 0x014;
    /// TX/RX control (lane count).
    pub(crate) const TXRX_CTRL: usize = crate::board::DSI0_BASE + 0x018;
    /// Packet size control.
    pub(crate) const PSCTRL: usize = crate::board::DSI0_BASE + 0x01C;
    /// Vertical sync active lines.
    pub(crate) const VSA_NL: usize = crate::board::DSI0_BASE + 0x020;
    /// Vertical back porch lines.
    pub(crate) const VBP_NL: usize = crate::board::DSI0_BASE + 0x024;
    /// Vertical front porch lines.
    pub(crate) const VFP_NL: usize = crate::board::DSI0_BASE + 0x028;
    /// Vertical active lines.
    pub(crate) const VACT_NL: usize = crate::board::DSI0_BASE + 0x02C;
    /// Horizontal sync active word count.
    pub(crate) const HSA_WC: usize = crate::board::DSI0_BASE + 0x050;
    /// Horizontal back porch word count.
    pub(crate) const HBP_WC: usize = crate::board::DSI0_BASE + 0x054;
    /// Horizontal front porch word count.
    pub(crate) const HFP_WC: usize = crate::board::DSI0_BASE + 0x058;
    /// PHY LC (clock lane) control.
    pub(crate) const PHY_LCCON: usize = crate::board::DSI0_BASE + 0x104;
    /// PHY LD0 (data lane 0) control.
    pub(crate) const PHY_LD0CON: usize = crate::board::DSI0_BASE + 0x108;

    /// Command queue size register (number of entries).
    pub(crate) const CMDQ_SIZE: usize = crate::board::DSI0_BASE + 0x060;
    /// Command queue data register 0 (first slot in the 128-entry queue).
    ///
    /// Each slot is 4 bytes. Slot N is at `CMDQ_DATA + N * 4`.
    pub(crate) const CMDQ_DATA: usize = crate::board::DSI0_BASE + 0x200;
    /// Rack (read-ack) register — write 1 to acknowledge completed command.
    pub(crate) const RACK: usize = crate::board::DSI0_BASE + 0x084;

    /// DSI_START bit.
    pub(crate) const START_BIT: u32 = 1;
    /// Video mode sync pulse.
    pub(crate) const MODE_SYNC_PULSE: u32 = 1;
    /// 1 data lane in TXRX_CTRL bits [3:2].
    pub(crate) const LANE_1: u32 = 0b00 << 2;
    /// Clock lane enable in PHY_LCCON.
    pub(crate) const LC_HS_TX_EN: u32 = 1 << 0;
    /// Data lane 0 enable in PHY_LD0CON.
    pub(crate) const LD0_HS_TX_EN: u32 = 1 << 0;

    // WHY: CMDQ word format for DCS short writes (the only type we use):
    //   bits [7:0]   = config (0x05 = short write 0-param, 0x15 = short write
    //                          1-param, 0x39 = long write / generic long) —
    //                          these are the MIPI DSI standard
    //                          "Processor-Sourced" packet data types
    //                          (DCS_SHORT_WRITE / _PARAM / DCS_LONG_WRITE),
    //                          the same values used by upstream mtk-dsi.c (#387).
    //   bits [15:8]  = DCS command byte
    //   bits [23:16] = first data byte (for 1-param short writes)
    //   bits [31:24] = second data byte (unused for short writes, set to 0)
    //
    // For long writes (>1 data byte), the format packs the word count and
    // subsequent data into additional CMDQ slots.

    /// CMDQ config: DCS short write, no parameter (data type 0x05).
    pub(crate) const CMDQ_SHORT_W0: u32 = 0x05;
    /// CMDQ config: DCS short write, 1 parameter (data type 0x15).
    pub(crate) const CMDQ_SHORT_W1: u32 = 0x15;
    /// CMDQ config: DCS long write (data type 0x39).
    pub(crate) const CMDQ_LONG_W: u32 = 0x39;
}

// ---------------------------------------------------------------------------
// Constants: display mutex
// ---------------------------------------------------------------------------

/// Display mutex register block.
mod disp_mutex {

    /// Mutex 0 enable.
    pub(crate) const EN: usize = crate::board::DISP_MUTEX_BASE + 0x020;
    /// Mutex 0 module membership.
    pub(crate) const MOD: usize = crate::board::DISP_MUTEX_BASE + 0x02C;
    /// Mutex 0 SOF source.
    pub(crate) const SOF: usize = crate::board::DISP_MUTEX_BASE + 0x030;

    /// Mutex enable bit.
    pub(crate) const EN_BIT: u32 = 1;
    /// Module membership: OVL0(bit 0) | RDMA0(bit 3).
    pub(crate) const MOD_OVL0_RDMA0: u32 = (1 << 0) | (1 << 3);
    /// SOF source: single mode (SW trigger, no external vsync).
    pub(crate) const SOF_SINGLE: u32 = 0;
}

// ---------------------------------------------------------------------------
// LCM types and traits
// ---------------------------------------------------------------------------

/// LCM interface type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LcmType {
    /// MIPI DSI interface.
    Dsi,
}

/// Display color format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColorFormat {
    /// 16-bit RGB (5-6-5), 2 bytes per pixel.
    Rgb565,
    /// 24-bit RGB (8-8-8), 3 bytes per pixel.
    Rgb888,
}

impl ColorFormat {
    /// Bytes per pixel for this format.
    pub(crate) const fn bpp(self) -> u16 {
        match self {
            Self::Rgb565 => 2,
            Self::Rgb888 => 3,
        }
    }
}

/// DSI operating mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DsiMode {
    /// Command mode (partial updates, lower bandwidth).
    CmdMode,
    /// Sync pulse video mode (continuous refresh).
    SyncPulseVdo,
    /// Sync event video mode.
    SyncEventVdo,
    /// Burst video mode (highest bandwidth).
    BurstVdo,
}

/// LCM panel parameters.
///
/// Describes the physical panel's interface, resolution, timing, and
/// clock configuration. Returned by [`LcmControl::get_params`].
#[derive(Debug, Clone)]
pub struct LcmParams {
    /// Interface type (DSI for MT6739).
    pub lcm_type: LcmType,
    /// Panel width in pixels.
    pub width: u16,
    /// Panel height in pixels.
    pub height: u16,
    /// Pixel color format.
    pub color_format: ColorFormat,
    /// DSI operating mode.
    pub dsi_mode: DsiMode,
    /// MIPI PLL clock frequency in MHz.
    pub pll_clock_mhz: u16,
}

impl LcmParams {
    /// Compute the stride (bytes per row) for this panel's format.
    pub(crate) const fn stride(&self) -> u32 {
        (self.width as u32) * self.color_format.bpp() as u32
    }

    /// Compute the total framebuffer size in bytes.
    pub(crate) const fn framebuffer_size(&self) -> u32 {
        self.stride() * (self.height as u32)
    }
}

/// Panel initialization and power management.
///
/// Split FROM [`LcmBacklight`] following Tock OS HIL patterns: not all
/// panels support software backlight control, and init/power is a
/// distinct concern FROM brightness adjustment.
pub(crate) trait LcmControl {
    /// Return the panel's static parameters.
    fn get_params(&self) -> &LcmParams;

    /// Send the panel initialization command sequence via DSI.
    ///
    /// # Errors
    ///
    /// Returns [`DsiTimeout`] if any DCS command in the sequence times out
    /// (#389); the remainder of the sequence is aborted.
    ///
    /// # Safety
    ///
    /// DSI0 must be configured and clock lanes active before calling.
    unsafe fn init(&self) -> Result<(), DsiTimeout>;

    /// Enter panel sleep mode (MIPI DCS Sleep In).
    ///
    /// # Safety
    ///
    /// DSI0 must be active.
    unsafe fn suspend(&self);

    /// Exit panel sleep mode (MIPI DCS Sleep Out).
    ///
    /// # Safety
    ///
    /// DSI0 must be active.
    unsafe fn resume(&self);
}

/// Panel backlight control.
///
/// Separated FROM [`LcmControl`] because backlight hardware varies:
/// some panels use PWM, others use DSI DCS commands, some have no
/// software control at all.
pub(crate) trait LcmBacklight {
    /// Set backlight brightness level (0 = off, 255 = maximum).
    ///
    /// # Safety
    ///
    /// The panel must be initialized and not in sleep mode.
    unsafe fn set_backlight(&self, level: u8);
}

/// Combined LCM driver capability.
///
/// Implementors provide both panel control and backlight management.
/// The [`DisplayDriver`] requires this trait bound for full pipeline
/// operation.
pub(crate) trait LcmDriver: LcmControl + LcmBacklight {}

// WHY: blanket impl lets any type implementing both sub-traits
// automatically satisfy LcmDriver without boilerplate.
impl<T: LcmControl + LcmBacklight> LcmDriver for T {}

// ---------------------------------------------------------------------------
// DSI DCS command helpers
// ---------------------------------------------------------------------------

/// Maximum iterations to poll for DSI command completion.
const DSI_POLL_TIMEOUT: u32 = 100_000;

/// Maximum total DCS long-write payload (1 command byte + data bytes).
///
/// The CMDQ has 16 slots of 4 bytes each; slot 0 holds the long-write
/// header, leaving 15 slots (60 bytes) for the payload. Writing more
/// than this walks the packing loop in `dcs_write_long` past slot 15
/// and corrupts whatever DSI MMIO register follows `CMDQ_DATA`.
const MAX_DCS_LONG_PAYLOAD_LEN: usize = 15 * 4;

/// Busy-wait delay using the ARM generic timer.
///
/// Spins on the counter until `ms` milliseconds have elapsed. This is
/// appropriate for panel init delays where no interrupt-driven timer is
/// available yet.
#[cfg(not(test))]
fn delay_ms(ms: u32) {
    let freq = timer::frequency() as u64;
    if freq == 0 {
        // No timer frequency available; fall back to a rough spin.
        for _ in 0..ms.saturating_mul(10_000) {
            core::hint::spin_loop();
        }
        return;
    }
    let target = timer::counter() + (freq * u64::from(ms)) / 1000;
    while timer::counter() < target {
        core::hint::spin_loop();
    }
}

/// Test stub: no-op delay.
#[cfg(test)]
fn delay_ms(_ms: u32) {}

/// Wait for a DSI command to complete by polling the START register.
///
/// The DSI engine clears `START_BIT` when the command finishes.
///
/// # Safety
///
/// DSI0 registers must be mapped and accessible.
/// A DSI command's poll-wait exhausted [`DSI_POLL_TIMEOUT`] without the
/// engine going idle (#389). The caller must not proceed to overwrite
/// `START`/CMDQ while a prior transfer may still be in flight.
pub(crate) struct DsiTimeout;

unsafe fn dsi_wait_idle() -> Result<(), DsiTimeout> {
    // SAFETY: DSI0_START is a valid MMIO register at 0x1400_D000 within the DSI0 address space. Volatile access is required for hardware registers.
    unsafe {
        if mmio::wait_bits_clear(dsi::START, dsi::START_BIT, DSI_POLL_TIMEOUT) {
            Ok(())
        } else {
            Err(DsiTimeout)
        }
    }
}

/// Send a DCS short write with no parameters (e.g., Sleep Out, Display On).
///
/// # Safety
///
/// DSI0 must be configured with clock and data lanes active.
unsafe fn dcs_write_cmd0(cmd: u8) -> Result<(), DsiTimeout> {
    // SAFETY: DSI0 registers (START, CMDQ_SIZE, CMDQ_DATA) are valid MMIO registers within the DSI0 address space at 0x1400_D000. Volatile access is required for hardware registers.
    unsafe {
        dsi_wait_idle()?;
        // Clear start bit before writing command queue
        mmio::write32(dsi::START, 0);
        // One CMDQ entry: short write, 0 params
        mmio::write32(dsi::CMDQ_SIZE, 1);
        mmio::write32(dsi::CMDQ_DATA, dsi::CMDQ_SHORT_W0 | (u32::from(cmd) << 8));
        // Trigger DSI command
        mmio::write32(dsi::START, dsi::START_BIT);
        dsi_wait_idle()
    }
}

/// Send a DCS short write with one parameter byte.
///
/// # Safety
///
/// DSI0 must be configured with clock and data lanes active.
unsafe fn dcs_write_cmd1(cmd: u8, data: u8) -> Result<(), DsiTimeout> {
    // SAFETY: DSI0 registers (START, CMDQ_SIZE, CMDQ_DATA) are valid MMIO registers within the DSI0 address space at 0x1400_D000. Volatile access is required for hardware registers.
    unsafe {
        dsi_wait_idle()?;
        mmio::write32(dsi::START, 0);
        mmio::write32(dsi::CMDQ_SIZE, 1);
        mmio::write32(
            dsi::CMDQ_DATA,
            dsi::CMDQ_SHORT_W1 | (u32::from(cmd) << 8) | (u32::from(data) << 16),
        );
        mmio::write32(dsi::START, dsi::START_BIT);
        dsi_wait_idle()
    }
}

/// Send a DCS long write with multiple data bytes.
///
/// The `data` slice contains all bytes after the DCS command byte.
/// The total payload is `1 (cmd) + data.len()` bytes, packed into CMDQ
/// slots in little-endian order.
///
/// # Errors
///
/// Returns [`DsiTimeout`] if the total payload (`1 + data.len()`)
/// exceeds [`MAX_DCS_LONG_PAYLOAD_LEN`], or if the underlying DSI
/// transfer times out.
///
/// # Safety
///
/// DSI0 must be configured. `1 + data.len()` must be <=
/// [`MAX_DCS_LONG_PAYLOAD_LEN`] -- enforced below, not merely a caller
/// contract.
unsafe fn dcs_write_long(cmd: u8, data: &[u8]) -> Result<(), DsiTimeout> {
    // WHY: bound the payload BEFORE touching any hardware register.
    // Without this check, a data slice larger than the CMDQ's capacity
    // walks the packing loop below past slot 15 and writes into
    // whatever DSI MMIO register follows CMDQ_DATA in the address
    // space -- a memory-safety issue, not just a logic error.
    let payload_len = 1 + data.len();
    if payload_len > MAX_DCS_LONG_PAYLOAD_LEN {
        return Err(DsiTimeout);
    }

    // SAFETY: DSI0 registers (START, CMDQ_SIZE, CMDQ_DATA) are valid MMIO registers within the DSI0 address space at 0x1400_D000. Volatile access is required for hardware registers.
    unsafe {
        dsi_wait_idle()?;
        mmio::write32(dsi::START, 0);

        // WHY: CMDQ slot 0 holds the long-write header:
        //   bits [7:0]   = data type (0x39 = DCS long write)
        //   bits [23:8]  = word count (total payload length)
        let header = dsi::CMDQ_LONG_W | ((payload_len as u32) << 8);
        mmio::write32(dsi::CMDQ_DATA, header);

        // Pack payload bytes into subsequent CMDQ slots, 4 bytes per slot.
        // First byte of payload is the DCS command itself.
        let mut slot = 1usize;
        let mut byte_idx = 0usize;
        let mut word: u32 = u32::from(cmd);
        byte_idx += 1;

        for &b in data {
            let shift = (byte_idx % 4) * 8;
            word |= u32::from(b) << shift;
            byte_idx += 1;
            if byte_idx % 4 == 0 {
                mmio::write32(dsi::CMDQ_DATA + slot * 4, word);
                slot += 1;
                word = 0;
            }
        }
        // Flush any remaining partial word.
        if byte_idx % 4 != 0 {
            mmio::write32(dsi::CMDQ_DATA + slot * 4, word);
            slot += 1;
        }

        // CMDQ_SIZE = number of 32-bit slots used.
        mmio::write32(dsi::CMDQ_SIZE, slot as u32);
        mmio::write32(dsi::START, dsi::START_BIT);
        dsi_wait_idle()
    }
}

/// Assert DSI video-mode START.
///
/// Must be called after the LCM DCS init sequence has been fully sent
/// ([`LcmControl::init`]) — asserting video START first can prevent the
/// panel from receiving DCS init commands (#391).
///
/// # Safety
///
/// DSI0 must be configured (`DisplayDriver::configure_dsi`) and the LCM
/// init sequence must have completed.
unsafe fn dsi_start_video_mode() {
    // SAFETY: DSI0_START is a valid MMIO register within the DSI0 address space at 0x1400_D000. Volatile access is required for hardware registers.
    unsafe {
        mmio::write32(dsi::START, dsi::START_BIT);
    }
}

// ---------------------------------------------------------------------------
// GC9306 panel driver
// ---------------------------------------------------------------------------

/// GC9306 DBI panel controller for the AGM M7.
///
/// The GC9306 drives a 240x320 QVGA TFT via MIPI DSI. The init sequence
/// configures power rails, gamma correction, pixel format (RGB565), and
/// display orientation via DCS commands. See `docs/GC9306-INIT.md` for
/// the full register sequence and provenance from four independent sources.
pub struct Gc9306 {
    params: LcmParams,
}

impl Gc9306 {
    /// Create a new GC9306 driver instance with default AGM M7 parameters.
    pub fn new() -> Self {
        Self {
            params: LcmParams {
                lcm_type: LcmType::Dsi,
                width: DISPLAY_WIDTH,
                height: DISPLAY_HEIGHT,
                color_format: ColorFormat::Rgb565,
                dsi_mode: DsiMode::SyncPulseVdo,
                // NOTE: 156 MHz is a typical MT6739 MIPI PLL clock for QVGA.
                // Actual value to be confirmed FROM BSP lcm_get_params().
                pll_clock_mhz: 156,
            },
        }
    }
}

impl Default for Gc9306 {
    fn default() -> Self {
        Self::new()
    }
}

impl LcmControl for Gc9306 {
    fn get_params(&self) -> &LcmParams {
        &self.params
    }

    unsafe fn init(&self) -> Result<(), DsiTimeout> {
        // GC9306 init sequence derived from four independent GPL/Apache
        // driver sources. See docs/GC9306-INIT.md for provenance and
        // per-source gamma differences.
        // SAFETY: DSI0 is configured with clock and data lanes active per caller contract. All DCS commands are routed through dcs_write_* helpers which access valid DSI0 MMIO registers.
        unsafe {
            // Inter register enable (GC-specific page unlock)
            dcs_write_cmd0(0xFE)?;
            dcs_write_cmd0(0xEF)?;

            // Memory access control: MX=1, BGR=1 (direction 0 for AGM M7)
            dcs_write_cmd1(0x36, 0x48)?;

            // Pixel format: RGB565, 16-bit
            dcs_write_cmd1(0x3A, 0x05)?;

            // Power control registers
            dcs_write_long(0xA4, &[0x44, 0x44])?; // Power control 7
            dcs_write_long(0xA5, &[0x42, 0x42])?; // Power control 8
            dcs_write_long(0xAA, &[0x88, 0x88])?; // Power control (undocumented)
            dcs_write_long(0xE8, &[0x11, 0x0B])?; // Frame rate control
            dcs_write_long(0xE3, &[0x01, 0x10])?; // Source precharge control

            // Internal registers
            dcs_write_cmd1(0xFF, 0x61)?; // Internal register (undocumented)
            dcs_write_cmd1(0xAC, 0x00)?; // LDO enable
            dcs_write_cmd1(0xAD, 0x33)?; // VGLO voltage control
            dcs_write_cmd1(0xAE, 0x2B)?; // Internal power (undocumented)
            dcs_write_cmd1(0xAF, 0x55)?; // DIG_VREFAD_VRDD control

            // VCOM offset voltages
            dcs_write_long(0xA6, &[0x2A, 0x2A])?; // VCOM offset 1
            dcs_write_long(0xA7, &[0x2B, 0x2B])?; // VCOM offset 2
            dcs_write_long(0xA8, &[0x18, 0x18])?; // VCOM offset 3
            dcs_write_long(0xA9, &[0x2A, 0x2A])?; // VCOM offset 4

            // Column address set: 0-239
            dcs_write_long(0x2A, &[0x00, 0x00, 0x00, 0xEF])?;
            // Row address set: 0-319
            dcs_write_long(0x2B, &[0x00, 0x00, 0x01, 0x3F])?;
            // Memory write start
            dcs_write_cmd0(0x2C)?;

            // Gamma correction (LuatOS/Fibocom values; may need panel tuning)
            dcs_write_long(0xF0, &[0x02, 0x00, 0x00, 0x1B, 0x1F, 0x0B])?; // Positive gamma 1
            dcs_write_long(0xF1, &[0x01, 0x03, 0x00, 0x28, 0x2B, 0x0E])?; // Positive gamma 2
            dcs_write_long(0xF2, &[0x0B, 0x08, 0x3B, 0x04, 0x03, 0x4C])?; // Positive gamma 3
            dcs_write_long(0xF3, &[0x0E, 0x07, 0x46, 0x04, 0x05, 0x51])?; // Positive gamma 4
            dcs_write_long(0xF4, &[0x08, 0x15, 0x15, 0x1F, 0x22, 0x0F])?; // Negative gamma 1
            dcs_write_long(0xF5, &[0x0B, 0x13, 0x11, 0x1F, 0x21, 0x0F])?; // Negative gamma 2

            // Sleep Out — wait 120 ms for internal voltage stabilization
            dcs_write_cmd0(0x11)?;
            delay_ms(120);

            // Display On — wait 20 ms for display to become active
            dcs_write_cmd0(0x29)?;
            delay_ms(20);

            // Memory write (ready for pixel data)
            dcs_write_cmd0(0x2C)?;
        }
        Ok(())
    }

    unsafe fn suspend(&self) {
        // GC9306 sleep-in sequence from docs/GC9306-INIT.md.
        // Inter register enable must precede power commands.
        // SAFETY: DSI0 is active and panel is in normal operating state per caller contract. All DCS commands are routed through dcs_write_* helpers which access valid DSI0 MMIO registers.
        unsafe {
            // WHY: best-effort teardown — a timed-out DCS command here has
            // no established recovery path (unlike init, #389); the panel
            // is being suspended either way.
            let _ = dcs_write_cmd0(0xFE); // Inter register enable 1
            let _ = dcs_write_cmd0(0xEF); // Inter register enable 2
            // Display Off first, then Sleep In per MIPI DCS spec
            let _ = dcs_write_cmd0(0x28); // Display Off
            delay_ms(120);
            let _ = dcs_write_cmd0(0x10); // Sleep In (enter minimum power)
        }
    }

    unsafe fn resume(&self) {
        // GC9306 sleep-out sequence from docs/GC9306-INIT.md.
        // SAFETY: DSI0 is active and panel is in suspended state per caller contract. All DCS commands are routed through dcs_write_* helpers which access valid DSI0 MMIO registers.
        unsafe {
            // WHY: best-effort resume — same rationale as suspend() above.
            let _ = dcs_write_cmd0(0xFE); // Inter register enable 1
            let _ = dcs_write_cmd0(0xEF); // Inter register enable 2
            // Sleep Out — wait 120 ms for voltage stabilization
            let _ = dcs_write_cmd0(0x11);
            delay_ms(120);
            // Display On
            let _ = dcs_write_cmd0(0x29);
        }
    }
}

impl LcmBacklight for Gc9306 {
    unsafe fn set_backlight(&self, level: u8) {
        // DCS Write Display Brightness (0x51): 0x00 = off, 0xFF = max.
        // The GC9306 supports this command natively.
        // SAFETY: DSI0 is active and panel is not suspended per caller contract. dcs_write_cmd1 accesses valid DSI0 MMIO registers within the DSI0 address space at 0x1400_D000.
        unsafe {
            // WHY: best-effort — a timed-out backlight write has no
            // established recovery path from this ()-returning trait method.
            let _ = dcs_write_cmd1(0x51, level);
        }
    }
}

// ---------------------------------------------------------------------------
// Display driver state machine
// ---------------------------------------------------------------------------

/// Display pipeline initialization state.
///
/// Tracks progress through the 10-step init sequence. Each state
/// represents completion of that step. The driver must progress
/// through states in ORDER  -  skipping steps causes hardware faults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisplayState {
    /// No hardware interaction yet.
    Uninitialized,
    /// Step 1: MMSYS clocks enabled.
    ClocksEnabled,
    /// Step 2–3: software and LCM resets released.
    ResetReleased,
    /// Step 4–5: OVL ROI size and layers configured.
    OvlConfigured,
    /// Step 6: RDMA0 configured in memory mode.
    RdmaConfigured,
    /// Step 7: DSI0 lanes and timing configured.
    DsiConfigured,
    /// Step 8: LCM panel init sequence sent.
    LcmInitialized,
    /// Step 9: display mutex configured.
    MutexConfigured,
    /// Step 10: first frame triggered, pipeline active.
    Active,
    /// Panel in sleep mode.
    Suspended,
    /// A DSI command timed out during initialization; the pipeline is not
    /// usable (#389).
    Error,
}

// ---------------------------------------------------------------------------
// Pure helper functions (testable without hardware)
// ---------------------------------------------------------------------------

/// Encode width and height INTO OVL_ROI_SIZE register format.
///
/// Format: bits [12:0] = width, bits [28:16] = height.
pub const fn encode_roi_size(width: u16, height: u16) -> u32 {
    ((height as u32) << 16) | (width as u32)
}

/// Check whether a framebuffer address is properly aligned for DMA.
pub const fn is_fb_addr_aligned(addr: usize) -> bool {
    addr.is_multiple_of(FB_ADDR_ALIGN)
}

/// Compute the stride (bytes per row) for a given width and format.
pub const fn compute_stride(width: u16, format: ColorFormat) -> u32 {
    (width as u32) * format.bpp() as u32
}

// ---------------------------------------------------------------------------
// DisplayDriver
// ---------------------------------------------------------------------------

/// DDP pipeline driver.
///
/// Owns the LCM driver instance and orchestrates the full display
/// init sequence. Generic over the panel driver so different LCM
/// panels can be dropped in without changing pipeline code.
pub struct DisplayDriver<L: LcmDriver> {
    lcm: L,
    state: DisplayState,
}

impl<L: LcmDriver> DisplayDriver<L> {
    /// Create a new display driver with the given LCM panel driver.
    pub fn new(lcm: L) -> Self {
        Self {
            lcm,
            state: DisplayState::Uninitialized,
        }
    }

    /// Current pipeline state.
    pub fn state(&self) -> DisplayState {
        self.state
    }

    /// Reference to the LCM driver.
    pub fn lcm(&self) -> &L {
        &self.lcm
    }

    /// Execute the full 10-step display initialization sequence.
    ///
    /// Progresses through each state in ORDER. On completion, the
    /// pipeline is active and the first frame has been triggered.
    ///
    /// # Safety
    ///
    /// - MMU must be enabled with MMIO regions mapped.
    /// - Must be called exactly once during boot.
    /// - The framebuffer at `fb_addr` must be a valid physical address
    ///   with at least `width * height * bpp` bytes allocated.
    pub unsafe fn init(&mut self, fb_addr: usize) {
        // WHY: clone to release the immutable borrow on self.lcm before
        // calling &mut self methods. LcmParams is small (Copy-sized fields).
        let params = self.lcm.get_params().clone();
        let width = params.width;
        let height = params.height;
        let stride = params.stride();

        // Step 1: enable MMSYS clocks
        // SAFETY: MMSYS clock gate registers (CG_CLR0, CG_CLR1) are valid MMIO registers at 0x1400_0108 and 0x1400_0118 within the MMSYS address space. Called once during boot per caller contract.
        unsafe {
            self.enable_clocks();
        }

        // Step 2: release software resets
        // SAFETY: MMSYS reset registers (SW0_RST_B, SW1_RST_B, LCM_RST_B) are valid MMIO registers within the MMSYS address space at 0x1400_0000. Volatile access is required for hardware registers.
        unsafe {
            self.release_resets();
        }

        // Step 3: release LCM reset (folded INTO step 2 state)
        // NOTE: already handled in release_resets()

        // Step 4–5: configure OVL
        // SAFETY: OVL0 registers are valid MMIO registers within the OVL0 address space at 0x1400_7000. Volatile access is required for hardware registers.
        unsafe {
            self.configure_ovl(width, height);
        }

        // Step 6: configure RDMA0
        // SAFETY: RDMA0 registers are valid MMIO registers within the RDMA0 address space at 0x1400_8000. fb_addr is a valid physical address per caller contract.
        unsafe {
            self.configure_rdma(fb_addr, width, height, stride);
        }

        // Step 7: configure DSI0
        // SAFETY: DSI0 registers are valid MMIO registers within the DSI0 address space at 0x1400_D000. Volatile access is required for hardware registers.
        unsafe {
            self.configure_dsi(&params);
        }

        // Step 8: send LCM init commands
        // SAFETY: DSI0 is configured with clock and data lanes active after configure_dsi(). DCS commands access valid DSI0 MMIO registers.
        let lcm_init_result = unsafe { self.lcm.init() };
        if lcm_init_result.is_err() {
            // WHY: a DSI command timeout during LCM init means the panel
            // may not have received its DCS init sequence — entering
            // DisplayState::Error stops the pipeline from proceeding to
            // configure the mutex and trigger a frame against a
            // half-initialized (or unresponsive) panel (#389).
            self.state = DisplayState::Error;
            return;
        }
        self.state = DisplayState::LcmInitialized;

        // Step 8b: start DSI video mode — must occur AFTER the LCM DCS
        // init sequence has been fully sent, not before (#391). Asserting
        // START while the panel is still processing init commands can
        // prevent those commands from being received correctly.
        // SAFETY: DSI0_START is a valid MMIO register within the DSI0 address space at 0x1400_D000. Volatile access is required for hardware registers.
        unsafe {
            dsi_start_video_mode();
        }

        // Step 9: configure mutex
        // SAFETY: display mutex registers are valid MMIO registers within the DISP_MUTEX address space at 0x1400_1000. Volatile access is required for hardware registers.
        unsafe {
            self.configure_mutex();
        }

        // Step 10: trigger first frame
        // SAFETY: OVL0_TRIG is a valid MMIO register at 0x1400_7010 within the OVL0 address space. Volatile access is required for hardware registers.
        unsafe {
            mmio::write32(ovl::TRIG, ovl::SW_TRIG_BIT);
        }
        self.state = DisplayState::Active;
    }

    /// Update the RDMA0 framebuffer source address.
    ///
    /// Call this to point the display pipeline at a new framebuffer
    /// (e.g., for double-buffering). The address must be 16-byte
    /// aligned for DMA.
    ///
    /// # Safety
    ///
    /// - Pipeline must be in [`DisplayState::Active`] state.
    /// - `addr` must be a valid physical address with a full frame
    ///   of pixel data.
    /// - `stride` is bytes per row (width × bpp).
    pub unsafe fn write_framebuffer(&mut self, addr: usize, stride: u32) {
        debug_assert!(
            is_fb_addr_aligned(addr),
            "framebuffer address must be 16-byte aligned for DMA"
        );
        // SAFETY: RDMA0_MEM_START_ADDR and RDMA0_MEM_SRC_PITCH are valid MMIO registers within the RDMA0 address space at 0x1400_8000. addr is a valid physical address per caller contract. Volatile access is required for hardware registers.
        unsafe {
            mmio::write32(
                rdma::MEM_START_ADDR,
                u32::try_from(addr).unwrap_or_default(),
            );
            mmio::write32(rdma::MEM_SRC_PITCH, stride);
        }
    }

    /// Set panel backlight level (0–255).
    ///
    /// Delegates to the LCM driver's backlight implementation.
    ///
    /// # Safety
    ///
    /// Pipeline must be active and panel must not be suspended.
    pub unsafe fn set_backlight(&self, level: u8) {
        // SAFETY: Pipeline is active and panel is not suspended per caller contract. Delegates to LCM driver which accesses valid DSI0 MMIO registers.
        unsafe {
            self.lcm.set_backlight(level);
        }
    }

    // -- Private init step helpers --

    /// Step 1: enable all display pipeline clocks via MMSYS CG clear registers.
    unsafe fn enable_clocks(&mut self) {
        // SAFETY: MMSYS_CG_CLR0 (0x1400_0108) and MMSYS_CG_CLR1 (0x1400_0118) are valid MMIO registers within the MMSYS address space. Volatile access is required for hardware registers.
        unsafe {
            mmio::write32(mmsys::CG_CLR0, mmsys::CG0_DISP_ALL);
            mmio::write32(mmsys::CG_CLR1, mmsys::CG1_DISP_ALL);
        }
        self.state = DisplayState::ClocksEnabled;
    }

    /// Steps 2–3: release software resets and LCM reset.
    unsafe fn release_resets(&mut self) {
        // SAFETY: MMSYS SW0_RST_B (0x1400_0140), SW1_RST_B (0x1400_0144), and LCM_RST_B (0x1400_0150) are valid MMIO registers within the MMSYS address space. Volatile access is required for hardware registers.
        unsafe {
            // Step 2: release module software resets (active low  -  write 1)
            mmio::write32(mmsys::SW0_RST_B, mmsys::SW0_RST_RELEASE);
            mmio::write32(mmsys::SW1_RST_B, mmsys::SW1_RST_RELEASE);

            // Step 3: release LCM reset
            mmio::write32(mmsys::LCM_RST_B, mmsys::LCM_RST_RELEASE);
        }
        self.state = DisplayState::ResetReleased;
    }

    /// Steps 4–5: configure OVL ROI size, background, and enable layer 0.
    unsafe fn configure_ovl(&mut self, width: u16, height: u16) {
        // SAFETY: OVL0 registers (ROI_SIZE, ROI_BGCLR, L0_CON, SRC_CON, EN, INTEN) are valid MMIO registers within the OVL0 address space at 0x1400_7000. Volatile access is required for hardware registers.
        unsafe {
            // Step 4: SET ROI size
            mmio::write32(ovl::ROI_SIZE, encode_roi_size(width, height));

            // Black background
            mmio::write32(ovl::ROI_BGCLR, 0x0000_0000);

            // Layer 0: RGB565 format, constant alpha 0xFF
            mmio::write32(ovl::L0_CON, ovl::FMT_RGB565 | 0xFF);

            // Step 5: enable layer 0
            mmio::write32(ovl::SRC_CON, ovl::LAYER0_EN);

            // Enable OVL engine + force clock on
            mmio::write32(ovl::EN, ovl::EN_BIT | ovl::CK_ON_BIT);

            // Enable frame complete interrupt
            mmio::write32(ovl::INTEN, ovl::FME_CPL_INTEN);
        }
        self.state = DisplayState::OvlConfigured;
    }

    /// Step 6: configure RDMA0 in memory mode with framebuffer source.
    unsafe fn configure_rdma(&mut self, fb_addr: usize, width: u16, height: u16, stride: u32) {
        // SAFETY: RDMA0 registers (GLOBAL_CON, SIZE_CON_0, SIZE_CON_1, MEM_CON, MEM_SRC_PITCH, MEM_START_ADDR) are valid MMIO registers within the RDMA0 address space at 0x1400_8000. fb_addr is a valid DMA-accessible physical address per caller contract. Volatile access is required for hardware registers.
        unsafe {
            // Memory mode: read FROM framebuffer address
            mmio::write32(rdma::GLOBAL_CON, rdma::ENGINE_EN | rdma::MODE_MEMORY);

            // Output dimensions
            mmio::write32(rdma::SIZE_CON_0, u32::from(width));
            mmio::write32(rdma::SIZE_CON_1, u32::from(height));

            // Input format: RGB565
            mmio::write32(rdma::MEM_CON, rdma::FMT_RGB565);

            // Source pitch (stride)
            mmio::write32(rdma::MEM_SRC_PITCH, stride);

            // Framebuffer address
            mmio::write32(
                rdma::MEM_START_ADDR,
                u32::try_from(fb_addr).unwrap_or_default(),
            );
        }
        self.state = DisplayState::RdmaConfigured;
    }

    /// Step 7: configure DSI0 clock/data lanes and timing.
    unsafe fn configure_dsi(&mut self, params: &LcmParams) {
        // SAFETY: DSI0 registers (CON_CTRL, MODE_CTRL, TXRX_CTRL, VSA_NL, VBP_NL, VFP_NL, VACT_NL, HSA_WC, HBP_WC, HFP_WC, PHY_LCCON, PHY_LD0CON, START) are valid MMIO registers within the DSI0 address space at 0x1400_D000. Volatile access is required for hardware registers.
        unsafe {
            // Reset DSI
            mmio::write32(dsi::CON_CTRL, 0);

            // Set mode: sync pulse VDO for continuous refresh
            let mode_val = match params.dsi_mode {
                DsiMode::CmdMode => 0,
                DsiMode::SyncPulseVdo => dsi::MODE_SYNC_PULSE,
                DsiMode::SyncEventVdo => 2,
                DsiMode::BurstVdo => 3,
            };
            mmio::write32(dsi::MODE_CTRL, mode_val);

            // 1 data lane (QVGA doesn't need more)
            mmio::write32(dsi::TXRX_CTRL, dsi::LANE_1);

            // Vertical timing (typical for QVGA panel)
            mmio::write32(dsi::VSA_NL, 2); // 2 lines vsync
            mmio::write32(dsi::VBP_NL, 8); // 8 lines back porch
            mmio::write32(dsi::VFP_NL, 4); // 4 lines front porch
            mmio::write32(dsi::VACT_NL, u32::from(params.height));

            // Horizontal timing (word counts  -  bytes per line)
            let hsa_wc: u32 = 4; // sync active
            let hbp_wc: u32 = 40; // back porch
            let hfp_wc: u32 = 40; // front porch
            mmio::write32(dsi::HSA_WC, hsa_wc);
            mmio::write32(dsi::HBP_WC, hbp_wc);
            mmio::write32(dsi::HFP_WC, hfp_wc);

            // Enable clock lane and data lane 0
            mmio::write32(dsi::PHY_LCCON, dsi::LC_HS_TX_EN);
            mmio::write32(dsi::PHY_LD0CON, dsi::LD0_HS_TX_EN);

            // WHY: DSI video-mode START is intentionally NOT asserted here.
            // Asserting START puts the panel into continuous video clocking
            // before the LCM has received its DCS init sequence (Sleep Out,
            // gamma, etc.), which can prevent the panel from receiving
            // those commands correctly. START is asserted by
            // dsi_start_video_mode(), called after the LCM init sequence
            // completes (see DisplayDriver::init) (#391).
        }
        self.state = DisplayState::DsiConfigured;
    }

    /// Step 9: configure display mutex for frame synchronization.
    unsafe fn configure_mutex(&mut self) {
        // SAFETY: display mutex registers (MOD, SOF, EN) are valid MMIO registers within the DISP_MUTEX address space at 0x1400_1000. Volatile access is required for hardware registers.
        unsafe {
            // Module membership: OVL0 + RDMA0
            mmio::write32(disp_mutex::MOD, disp_mutex::MOD_OVL0_RDMA0);

            // SOF source: single mode (SW triggered)
            mmio::write32(disp_mutex::SOF, disp_mutex::SOF_SINGLE);

            // Enable mutex
            mmio::write32(disp_mutex::EN, disp_mutex::EN_BIT);
        }
        self.state = DisplayState::MutexConfigured;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- ROI size encoding --

    #[test]
    fn roi_size_240x320() {
        let encoded = encode_roi_size(240, 320);
        assert_eq!(
            encoded, 0x0140_00F0,
            "240×320 encodes to (320 << 16) | 240 = 0x01400F0"
        );
    }

    #[test]
    fn roi_size_width_in_lower_bits() {
        let encoded = encode_roi_size(240, 320);
        let width = encoded & 0x1FFF;
        assert_eq!(width, 240, "width occupies bits [12:0]");
    }

    #[test]
    fn roi_size_height_in_upper_bits() {
        let encoded = encode_roi_size(240, 320);
        let height = (encoded >> 16) & 0x1FFF;
        assert_eq!(height, 320, "height occupies bits [28:16]");
    }

    #[test]
    fn roi_size_zero() {
        assert_eq!(encode_roi_size(0, 0), 0, "zero dimensions encode to zero");
    }

    // -- Clock gate bit manipulation --

    #[test]
    fn cg0_includes_ovl_bit() {
        assert_ne!(
            mmsys::CG0_DISP_ALL & (1 << 0),
            0,
            "CG0 must include OVL0 at bit 0"
        );
    }

    #[test]
    fn cg0_includes_rdma_bit() {
        assert_ne!(
            mmsys::CG0_DISP_ALL & (1 << 3),
            0,
            "CG0 must include RDMA0 at bit 3"
        );
    }

    #[test]
    fn cg0_includes_dsi_bit() {
        assert_ne!(
            mmsys::CG0_DISP_ALL & (1 << 24),
            0,
            "CG0 must include DSI0 at bit 24"
        );
    }

    #[test]
    fn cg1_includes_dsi_digital_and_engine() {
        assert_ne!(
            mmsys::CG1_DISP_ALL & (1 << 0),
            0,
            "CG1 must include DSI0_DIGITAL at bit 0"
        );
        assert_ne!(
            mmsys::CG1_DISP_ALL & (1 << 1),
            0,
            "CG1 must include DSI0_ENGINE at bit 1"
        );
    }

    // -- LCM params validation --

    #[test]
    fn lcm_params_stride_rgb565() {
        let params = LcmParams {
            lcm_type: LcmType::Dsi,
            width: 240,
            height: 320,
            color_format: ColorFormat::Rgb565,
            dsi_mode: DsiMode::SyncPulseVdo,
            pll_clock_mhz: 156,
        };
        assert_eq!(params.stride(), 480, "RGB565 stride = 240 × 2 = 480 bytes");
    }

    #[test]
    fn lcm_params_framebuffer_size_rgb565() {
        let params = LcmParams {
            lcm_type: LcmType::Dsi,
            width: 240,
            height: 320,
            color_format: ColorFormat::Rgb565,
            dsi_mode: DsiMode::SyncPulseVdo,
            pll_clock_mhz: 156,
        };
        assert_eq!(
            params.framebuffer_size(),
            153_600,
            "RGB565 fb = 240 × 320 × 2 = 153600 bytes"
        );
    }

    #[test]
    fn lcm_params_stride_rgb888() {
        let params = LcmParams {
            lcm_type: LcmType::Dsi,
            width: 240,
            height: 320,
            color_format: ColorFormat::Rgb888,
            dsi_mode: DsiMode::CmdMode,
            pll_clock_mhz: 200,
        };
        assert_eq!(params.stride(), 720, "RGB888 stride = 240 × 3 = 720 bytes");
    }

    // -- Init sequence state ordering --

    #[test]
    fn gc9306_default_params() {
        let panel = Gc9306::new();
        let params = panel.get_params();
        assert_eq!(params.lcm_type, LcmType::Dsi, "GC9306 uses DSI interface");
        assert_eq!(params.width, 240, "AGM M7 width is 240");
        assert_eq!(params.height, 320, "AGM M7 height is 320");
        assert_eq!(
            params.color_format,
            ColorFormat::Rgb565,
            "default format is RGB565"
        );
    }

    #[test]
    fn display_driver_initial_state() {
        let panel = Gc9306::new();
        let driver = DisplayDriver::new(panel);
        assert_eq!(
            driver.state(),
            DisplayState::Uninitialized,
            "driver starts uninitialized"
        );
    }

    // -- Framebuffer address alignment --

    #[test]
    fn fb_addr_aligned_at_16() {
        assert!(
            is_fb_addr_aligned(0x4020_0000),
            "16-byte aligned address should pass"
        );
    }

    #[test]
    fn fb_addr_unaligned() {
        assert!(
            !is_fb_addr_aligned(0x4020_0001),
            "odd address is not 16-byte aligned"
        );
    }

    #[test]
    fn fb_addr_aligned_zero() {
        assert!(is_fb_addr_aligned(0), "zero is trivially aligned");
    }

    // -- Compute stride helper --

    #[test]
    fn compute_stride_rgb565_240() {
        assert_eq!(
            compute_stride(240, ColorFormat::Rgb565),
            480,
            "240px × 2bpp = 480 bytes"
        );
    }

    // -- OVL register bit constants --

    #[test]
    fn ovl_en_and_ck_on_bits() {
        let combined = ovl::EN_BIT | ovl::CK_ON_BIT;
        assert_eq!(combined, 0x101, "EN=bit0, CK_ON=bit8 → 0x101");
    }

    // -- DSI CMDQ register layout --

    #[test]
    fn dsi_cmdq_data_at_expected_offset() {
        assert_eq!(
            dsi::CMDQ_DATA,
            crate::board::DSI0_BASE + 0x200,
            "CMDQ_DATA must be at DSI0 + 0x200"
        );
    }

    #[test]
    fn dsi_cmdq_size_at_expected_offset() {
        assert_eq!(
            dsi::CMDQ_SIZE,
            crate::board::DSI0_BASE + 0x060,
            "CMDQ_SIZE must be at DSI0 + 0x060"
        );
    }

    #[test]
    fn dcs_write_long_rejects_oversized_payload_before_touching_hardware() {
        // The accept path dereferences real MMIO addresses and cannot run
        // off-target, but the bounds check must reject an oversized
        // payload BEFORE any MMIO access -- which is exactly what makes
        // this reachable as a host test.
        let oversized = [0u8; 60]; // payload_len = 1 (cmd) + 60 = 61 > 60 max
        let result = unsafe { dcs_write_long(0x00, &oversized) };
        assert!(
            result.is_err(),
            "a DCS long-write payload past CMDQ capacity must be rejected, \
             not walk the packing loop past the 16-slot region"
        );
    }

    // -- DSI CMDQ data-type constants (#387) --

    #[test]
    fn cmdq_short_w0_matches_mipi_dcs_short_write_no_param() {
        assert_eq!(
            dsi::CMDQ_SHORT_W0,
            0x05,
            "CMDQ_SHORT_W0 must equal the MIPI DSI DCS short-write, \
             0-parameter data type (0x05)"
        );
    }

    #[test]
    fn cmdq_short_w1_matches_mipi_dcs_short_write_one_param() {
        assert_eq!(
            dsi::CMDQ_SHORT_W1,
            0x15,
            "CMDQ_SHORT_W1 must equal the MIPI DSI DCS short-write, \
             1-parameter data type (0x15)"
        );
    }

    #[test]
    fn cmdq_word_low_byte_zero_param_command() {
        let cmd: u8 = 0x11; // Sleep Out
        let word = dsi::CMDQ_SHORT_W0 | (u32::from(cmd) << 8);
        assert_eq!(
            word & 0xFF,
            0x05,
            "packed CMDQ word for a 0-param DCS command must carry data type 0x05 in its low byte"
        );
    }

    #[test]
    fn cmdq_word_low_byte_one_param_command() {
        let cmd: u8 = 0x36; // Memory Access Control
        let data: u8 = 0x48;
        let word = dsi::CMDQ_SHORT_W1 | (u32::from(cmd) << 8) | (u32::from(data) << 16);
        assert_eq!(
            word & 0xFF,
            0x15,
            "packed CMDQ word for a 1-param DCS command must carry data type 0x15 in its low byte"
        );
    }

    // -- GC9306 panel parameters --

    #[test]
    fn gc9306_default_is_rgb565() {
        let panel = Gc9306::default();
        assert_eq!(
            panel.get_params().color_format,
            ColorFormat::Rgb565,
            "GC9306 defaults to RGB565"
        );
    }

    #[test]
    fn gc9306_default_is_sync_pulse_vdo() {
        let panel = Gc9306::default();
        assert_eq!(
            panel.get_params().dsi_mode,
            DsiMode::SyncPulseVdo,
            "GC9306 uses sync pulse video mode"
        );
    }

    #[test]
    fn gc9306_dimensions_match_display_constants() {
        let panel = Gc9306::new();
        let params = panel.get_params();
        assert_eq!(params.width, DISPLAY_WIDTH, "width matches DISPLAY_WIDTH");
        assert_eq!(
            params.height, DISPLAY_HEIGHT,
            "height matches DISPLAY_HEIGHT"
        );
    }

    #[test]
    fn gc9306_framebuffer_size() {
        let panel = Gc9306::new();
        let params = panel.get_params();
        let expected = u32::from(DISPLAY_WIDTH) * u32::from(DISPLAY_HEIGHT) * u32::from(BPP_RGB565);
        assert_eq!(
            params.framebuffer_size(),
            expected,
            "framebuffer = W * H * BPP"
        );
    }

    // -- DSI CMDQ word encoding --

    #[test]
    fn cmdq_short_w0_encodes_cmd_byte() {
        // Short write 0-param: config=0x05 (MIPI DCS short write, no param), cmd in bits[15:8]
        let word = dsi::CMDQ_SHORT_W0 | (0x11_u32 << 8);
        assert_eq!(
            word & 0xFF,
            0x05,
            "config byte = short write 0-param (#387)"
        );
        assert_eq!((word >> 8) & 0xFF, 0x11, "cmd byte = Sleep Out");
    }

    #[test]
    fn cmdq_short_w1_encodes_cmd_and_data() {
        // Short write 1-param: config=0x15 (MIPI DCS short write, 1 param), cmd in [15:8], data in [23:16]
        let word = dsi::CMDQ_SHORT_W1 | (0x36_u32 << 8) | (0x48_u32 << 16);
        assert_eq!(
            word & 0xFF,
            0x15,
            "config byte = short write 1-param (#387)"
        );
        assert_eq!((word >> 8) & 0xFF, 0x36, "cmd byte = MADCTL");
        assert_eq!((word >> 16) & 0xFF, 0x48, "data byte = MX|BGR");
    }

    #[test]
    fn cmdq_long_w_header_encodes_word_count() {
        // Long write header: config=0x39, word count in [23:8]
        let payload_len: u32 = 7; // 1 cmd + 6 data bytes
        let header = dsi::CMDQ_LONG_W | (payload_len << 8);
        assert_eq!(header & 0xFF, 0x39, "config byte = long write");
        assert_eq!((header >> 8) & 0xFFFF, 7, "word count = 7");
    }
}
