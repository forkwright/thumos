//! Display Data Path (DDP) driver for the MT6739.
//!
//! Implements the MediaTek display pipeline: OVL0 → RDMA0 → DSI0 → LCM.
//! The [`DisplayDriver`] orchestrates the 10-step hardware init sequence
//! and provides framebuffer UPDATE via RDMA0 memory mode.
//!
//! Panel support is pluggable via the [`LcmControl`] and [`LcmBacklight`]
//! traits. The [`Gc9306`] stub implements these for the AGM M7's GC9306
//! panel controller  -  its init sequence is pending extraction FROM the BSP.
//!
//! Register offsets FROM `docs/DRIVER-INTERFACES.md` §7.

use crate::mmio;

// ---------------------------------------------------------------------------
// Constants: base addresses
// ---------------------------------------------------------------------------

/// MMSYS configuration base (MT6739 device tree).
const MMSYS_CONFIG_BASE: usize = 0x1400_0000;

/// OVL0 engine base.
const OVL0_BASE: usize = 0x1400_7000;

/// RDMA0 engine base.
const RDMA0_BASE: usize = 0x1400_8000;

/// DSI0 controller base.
const DSI0_BASE: usize = 0x1400_D000;

/// Display mutex base.
const DISP_MUTEX_BASE: usize = 0x1400_1000;

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
    use super::MMSYS_CONFIG_BASE;

    /// Clock gate status 0.
    pub const CG_CON0: usize = MMSYS_CONFIG_BASE + 0x100;
    /// Clock gate SET 0 (write 1 = disable clock).
    pub const CG_SET0: usize = MMSYS_CONFIG_BASE + 0x104;
    /// Clock gate clear 0 (write 1 = enable clock).
    pub const CG_CLR0: usize = MMSYS_CONFIG_BASE + 0x108;
    /// Clock gate status 1.
    pub const CG_CON1: usize = MMSYS_CONFIG_BASE + 0x110;
    /// Clock gate SET 1 (write 1 = disable clock).
    pub const CG_SET1: usize = MMSYS_CONFIG_BASE + 0x114;
    /// Clock gate clear 1 (write 1 = enable clock).
    pub const CG_CLR1: usize = MMSYS_CONFIG_BASE + 0x118;
    /// Software reset 0 (active low  -  write 1 to release).
    pub const SW0_RST_B: usize = MMSYS_CONFIG_BASE + 0x140;
    /// Software reset 1 (active low  -  write 1 to release).
    pub const SW1_RST_B: usize = MMSYS_CONFIG_BASE + 0x144;
    /// LCM reset control (active low  -  write 1 to release).
    pub const LCM_RST_B: usize = MMSYS_CONFIG_BASE + 0x150;

    // WHY: clock gate bits for display pipeline modules in CG_CLR0/CG_CLR1.
    // These enable the clocks for each module when written to the CLR register.

    /// Bit mask: all display pipeline clocks in CG0.
    /// OVL0(bit 0) | RDMA0(bit 3) | COLOR0(bit 5) | DSI0(bit 24).
    pub const CG0_DISP_ALL: u32 = (1 << 0) | (1 << 3) | (1 << 5) | (1 << 24);

    /// Bit mask: display pipeline clocks in CG1.
    /// DSI0_DIGITAL(bit 0) | DSI0_ENGINE(bit 1).
    pub const CG1_DISP_ALL: u32 = (1 << 0) | (1 << 1);

    /// Full release mask for SW0_RST_B.
    pub const SW0_RST_RELEASE: u32 = 0xFFFF_FFFF;

    /// Full release mask for SW1_RST_B.
    pub const SW1_RST_RELEASE: u32 = 0xFFFF_FFFF;

    /// LCM reset release (bit 0).
    pub const LCM_RST_RELEASE: u32 = 1;
}

// ---------------------------------------------------------------------------
// Constants: OVL registers (§7.3)
// ---------------------------------------------------------------------------

/// OVL0 register block.
mod ovl {
    use super::OVL0_BASE;

    /// Status; bit 0 = running.
    pub const STA: usize = OVL0_BASE;
    /// Interrupt enable.
    pub const INTEN: usize = OVL0_BASE + 0x004;
    /// Interrupt status.
    pub const INTSTA: usize = OVL0_BASE + 0x008;
    /// Enable; bit 0 = OVL_EN, bit 8 = CK_ON.
    pub const EN: usize = OVL0_BASE + 0x00C;
    /// Trigger; bit 0 = SW_TRIG.
    pub const TRIG: usize = OVL0_BASE + 0x010;
    /// Reset.
    pub const RST: usize = OVL0_BASE + 0x014;
    /// Region of interest size; bits [12:0] = W, bits [28:16] = H.
    pub const ROI_SIZE: usize = OVL0_BASE + 0x020;
    /// Datapath config.
    pub const DATAPATH_CON: usize = OVL0_BASE + 0x024;
    /// Background colour RGBA.
    pub const ROI_BGCLR: usize = OVL0_BASE + 0x028;
    /// Source enable; bits 0–3 = layer 0–3 enable.
    pub const SRC_CON: usize = OVL0_BASE + 0x02C;
    /// Layer 0 control (alpha, flip, format).
    pub const L0_CON: usize = OVL0_BASE + 0x030;

    /// OVL_EN bit.
    pub const EN_BIT: u32 = 1 << 0;
    /// CK_ON bit (force clock on).
    pub const CK_ON_BIT: u32 = 1 << 8;
    /// SW_TRIG bit.
    pub const SW_TRIG_BIT: u32 = 1 << 0;
    /// Layer 0 enable bit in SRC_CON.
    pub const LAYER0_EN: u32 = 1 << 0;

    /// Frame complete interrupt enable.
    pub const FME_CPL_INTEN: u32 = 1 << 1;

    // WHY: L0_CON format field  -  bits [15:12] SELECT pixel format.
    // 0b0000 = RGB565, 0b0010 = RGB888, 0b0011 = ARGB8888.

    /// RGB565 format in layer control register bits [15:12].
    pub const FMT_RGB565: u32 = 0b0000 << 12;
}

// ---------------------------------------------------------------------------
// Constants: RDMA registers
// ---------------------------------------------------------------------------

/// RDMA0 register block.
mod rdma {
    use super::RDMA0_BASE;

    /// Global control; bit 0 = ENGINE_EN, bit 1 = MODE_SEL (1=memory).
    pub const GLOBAL_CON: usize = RDMA0_BASE;
    /// Output frame width.
    pub const SIZE_CON_0: usize = RDMA0_BASE + 0x014;
    /// Output frame height.
    pub const SIZE_CON_1: usize = RDMA0_BASE + 0x018;
    /// Memory mode control (format selection).
    pub const MEM_CON: usize = RDMA0_BASE + 0x024;
    /// Memory source pitch (stride in bytes).
    pub const MEM_SRC_PITCH: usize = RDMA0_BASE + 0x02C;
    /// Framebuffer start address (physical).
    pub const MEM_START_ADDR: usize = RDMA0_BASE + 0x0F0;

    /// ENGINE_EN bit.
    pub const ENGINE_EN: u32 = 1 << 0;
    /// MODE_SEL bit (1 = memory mode).
    pub const MODE_MEMORY: u32 = 1 << 1;

    /// RGB565 input format in MEM_CON.
    pub const FMT_RGB565: u32 = 0;
}

// ---------------------------------------------------------------------------
// Constants: DSI registers
// ---------------------------------------------------------------------------

/// DSI0 register block.
mod dsi {
    use super::DSI0_BASE;

    /// DSI start control.
    pub const START: usize = DSI0_BASE;
    /// Interrupt enable.
    pub const INTEN: usize = DSI0_BASE + 0x008;
    /// Interrupt status.
    pub const INTSTA: usize = DSI0_BASE + 0x00C;
    /// Connection control.
    pub const CON_CTRL: usize = DSI0_BASE + 0x010;
    /// Mode control (CMD vs VDO).
    pub const MODE_CTRL: usize = DSI0_BASE + 0x014;
    /// TX/RX control (lane count).
    pub const TXRX_CTRL: usize = DSI0_BASE + 0x018;
    /// Packet size control.
    pub const PSCTRL: usize = DSI0_BASE + 0x01C;
    /// Vertical sync active lines.
    pub const VSA_NL: usize = DSI0_BASE + 0x020;
    /// Vertical back porch lines.
    pub const VBP_NL: usize = DSI0_BASE + 0x024;
    /// Vertical front porch lines.
    pub const VFP_NL: usize = DSI0_BASE + 0x028;
    /// Vertical active lines.
    pub const VACT_NL: usize = DSI0_BASE + 0x02C;
    /// Horizontal sync active word count.
    pub const HSA_WC: usize = DSI0_BASE + 0x050;
    /// Horizontal back porch word count.
    pub const HBP_WC: usize = DSI0_BASE + 0x054;
    /// Horizontal front porch word count.
    pub const HFP_WC: usize = DSI0_BASE + 0x058;
    /// PHY LC (clock lane) control.
    pub const PHY_LCCON: usize = DSI0_BASE + 0x104;
    /// PHY LD0 (data lane 0) control.
    pub const PHY_LD0CON: usize = DSI0_BASE + 0x108;

    /// DSI_START bit.
    pub const START_BIT: u32 = 1;
    /// Video mode sync pulse.
    pub const MODE_SYNC_PULSE: u32 = 1;
    /// 1 data lane in TXRX_CTRL bits [3:2].
    pub const LANE_1: u32 = 0b00 << 2;
    /// Clock lane enable in PHY_LCCON.
    pub const LC_HS_TX_EN: u32 = 1 << 0;
    /// Data lane 0 enable in PHY_LD0CON.
    pub const LD0_HS_TX_EN: u32 = 1 << 0;
}

// ---------------------------------------------------------------------------
// Constants: display mutex
// ---------------------------------------------------------------------------

/// Display mutex register block.
mod disp_mutex {
    use super::DISP_MUTEX_BASE;

    /// Mutex 0 enable.
    pub const EN: usize = DISP_MUTEX_BASE + 0x020;
    /// Mutex 0 module membership.
    pub const MOD: usize = DISP_MUTEX_BASE + 0x02C;
    /// Mutex 0 SOF source.
    pub const SOF: usize = DISP_MUTEX_BASE + 0x030;

    /// Mutex enable bit.
    pub const EN_BIT: u32 = 1;
    /// Module membership: OVL0(bit 0) | RDMA0(bit 3).
    pub const MOD_OVL0_RDMA0: u32 = (1 << 0) | (1 << 3);
    /// SOF source: single mode (SW trigger, no external vsync).
    pub const SOF_SINGLE: u32 = 0;
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
    pub const fn bpp(self) -> u16 {
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
    pub const fn stride(&self) -> u32 {
        self.u32::try_from(width).unwrap_or_default() * self.color_format.bpp() as u32
    }

    /// Compute the total framebuffer size in bytes.
    pub const fn framebuffer_size(&self) -> u32 {
        self.stride() * self.u32::try_from(height).unwrap_or_default()
    }
}

/// Panel initialization and power management.
///
/// Split FROM [`LcmBacklight`] following Tock OS HIL patterns: not all
/// panels support software backlight control, and init/power is a
/// distinct concern FROM brightness adjustment.
pub trait LcmControl {
    /// Return the panel's static parameters.
    fn get_params(&self) -> &LcmParams;

    /// Send the panel initialization command sequence via DSI.
    ///
    /// # Safety
    ///
    /// DSI0 must be configured and clock lanes active before calling.
    unsafe fn init(&self);

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
pub trait LcmBacklight {
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
pub trait LcmDriver: LcmControl + LcmBacklight {}

// WHY: blanket impl lets any type implementing both sub-traits
// automatically satisfy LcmDriver without boilerplate.
impl<T: LcmControl + LcmBacklight> LcmDriver for T {}

// ---------------------------------------------------------------------------
// GC9306 panel stub
// ---------------------------------------------------------------------------

/// GC9306 DBI panel controller stub for the AGM M7.
///
/// The GC9306 drives a 240×320 QVGA TFT via MIPI DSI. The actual init
/// sequence (register writes to configure gamma, power, timing) is
/// pending extraction FROM the BSP  -  see `docs/DRIVER-INTERFACES.md` §7.6.
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

    unsafe fn init(&self) {
        // TODO(#TBD): extract GC9306 init sequence FROM BSP.
        //
        // The init sequence consists of ~50-100 DSI DCS write commands
        // that configure the panel's internal registers (gamma curves,
        // power supply voltages, pixel format, display orientation).
        //
        // Template (each line becomes a DSI write):
        //   write_cmd(0xFE, 0x01);  // Enter page 1
        //   write_cmd(0x24, 0xC0);  // REF_V_VGLO control
        //   write_cmd(0x25, 0x53);  // REF_V_VGHO control
        //   ...
        //   write_cmd(0xFE, 0x00);  // Return to page 0
        //   write_cmd(0x35, 0x00);  // Tearing effect on
        //   write_cmd(0x11);        // Sleep out
        //   delay_ms(120);
        //   write_cmd(0x29);        // Display on
    }

    unsafe fn suspend(&self) {
        // TODO(#TBD): send MIPI DCS Sleep In (0x10) command via DSI.
    }

    unsafe fn resume(&self) {
        // TODO(#TBD): send MIPI DCS Sleep Out (0x11) + Display On (0x29).
    }
}

impl LcmBacklight for Gc9306 {
    unsafe fn set_backlight(&self, _level: u8) {
        // TODO(#TBD): implement backlight control.
        // GC9306 supports DCS Write Display Brightness (0x51).
        // Alternatively, the MT6739 may use a PWM pin for backlight.
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
}

// ---------------------------------------------------------------------------
// Pure helper functions (testable without hardware)
// ---------------------------------------------------------------------------

/// Encode width and height INTO OVL_ROI_SIZE register format.
///
/// Format: bits [12:0] = width, bits [28:16] = height.
pub const fn encode_roi_size(width: u16, height: u16) -> u32 {
    ((u32::try_from(height).unwrap_or_default()) << 16) | (u32::try_from(width).unwrap_or_default())
}

/// Check whether a framebuffer address is properly aligned for DMA.
pub const fn is_fb_addr_aligned(addr: usize) -> bool {
    addr.is_multiple_of(FB_ADDR_ALIGN)
}

/// Compute the stride (bytes per row) for a given width and format.
pub const fn compute_stride(width: u16, format: ColorFormat) -> u32 {
    u32::try_from(width).unwrap_or_default() * format.bpp() as u32
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
        unsafe {
            self.enable_clocks();
        }

        // Step 2: release software resets
        unsafe {
            self.release_resets();
        }

        // Step 3: release LCM reset (folded INTO step 2 state)
        // NOTE: already handled in release_resets()

        // Step 4–5: configure OVL
        unsafe {
            self.configure_ovl(width, height);
        }

        // Step 6: configure RDMA0
        unsafe {
            self.configure_rdma(fb_addr, width, height, stride);
        }

        // Step 7: configure DSI0
        unsafe {
            self.configure_dsi(&params);
        }

        // Step 8: send LCM init commands
        unsafe {
            self.lcm.init();
        }
        self.state = DisplayState::LcmInitialized;

        // Step 9: configure mutex
        unsafe {
            self.configure_mutex();
        }

        // Step 10: trigger first frame
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
        unsafe {
            mmio::write32(rdma::MEM_START_ADDR, u32::try_from(addr).unwrap_or_default());
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
        unsafe {
            self.lcm.set_backlight(level);
        }
    }

    // -- Private init step helpers --

    /// Step 1: enable all display pipeline clocks via MMSYS CG clear registers.
    unsafe fn enable_clocks(&mut self) {
        unsafe {
            mmio::write32(mmsys::CG_CLR0, mmsys::CG0_DISP_ALL);
            mmio::write32(mmsys::CG_CLR1, mmsys::CG1_DISP_ALL);
        }
        self.state = DisplayState::ClocksEnabled;
    }

    /// Steps 2–3: release software resets and LCM reset.
    unsafe fn release_resets(&mut self) {
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
    unsafe fn configure_rdma(
        &mut self,
        fb_addr: usize,
        width: u16,
        height: u16,
        stride: u32,
    ) {
        unsafe {
            // Memory mode: read FROM framebuffer address
            mmio::write32(rdma::GLOBAL_CON, rdma::ENGINE_EN | rdma::MODE_MEMORY);

            // Output dimensions
            mmio::write32(rdma::SIZE_CON_0, u32::FROM(width));
            mmio::write32(rdma::SIZE_CON_1, u32::FROM(height));

            // Input format: RGB565
            mmio::write32(rdma::MEM_CON, rdma::FMT_RGB565);

            // Source pitch (stride)
            mmio::write32(rdma::MEM_SRC_PITCH, stride);

            // Framebuffer address
            mmio::write32(rdma::MEM_START_ADDR, u32::try_from(fb_addr).unwrap_or_default());
        }
        self.state = DisplayState::RdmaConfigured;
    }

    /// Step 7: configure DSI0 clock/data lanes and timing.
    unsafe fn configure_dsi(&mut self, params: &LcmParams) {
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
            mmio::write32(dsi::VACT_NL, u32::FROM(params.height));

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

            // Start DSI
            mmio::write32(dsi::START, dsi::START_BIT);
        }
        self.state = DisplayState::DsiConfigured;
    }

    /// Step 9: configure display mutex for frame synchronization.
    unsafe fn configure_mutex(&mut self) {
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
        assert_eq!(
            params.stride(),
            480,
            "RGB565 stride = 240 × 2 = 480 bytes"
        );
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
        assert_eq!(
            params.stride(),
            720,
            "RGB888 stride = 240 × 3 = 720 bytes"
        );
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
}
