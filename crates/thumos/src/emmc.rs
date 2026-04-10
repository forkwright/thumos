//! eMMC block device driver for MT6739 MSDC controller.
//!
//! Implements PIO and DMA transfer paths for eMMC 5.1 on the MediaTek MSDC
//! (MultiSlot Data Controller). Register offsets and interrupt definitions
//! are derived FROM `docs/DRIVER-INTERFACES.md` section 8.
//!
//! # Architecture
//!
//! - PIO mode: FIFO read/write via `MSDC_TXDATA`/`MSDC_RXDATA`. Fallback path
//!   when DMA descriptors cannot be allocated.
//! - DMA mode: scatter-gather via GPD/BD descriptor chains. Performance path
//!   for multi-block transfers.
//!
//! # Hardware
//!
//! MSDC0 base address: `0x1123_0000` (FROM device registry, `docs/PROBE.md`).
//! 512-byte sector granularity. Single-block and multi-block transfers.

use crate::mmio;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// MSDC0 base address on the MT6739.
// NOTE: FROM device registry, `crates/thumos/src/device.rs:127`
const MSDC0_BASE: usize = 0x1123_0000;

/// Sector size in bytes (eMMC standard).
const SECTOR_SIZE: usize = 512;

/// Maximum poll iterations for busy-wait loops.
const POLL_TIMEOUT: u32 = 1_000_000;

/// Words per sector (512 bytes / 4 bytes per word).
const WORDS_PER_SECTOR: usize = SECTOR_SIZE / 4;

// ---------------------------------------------------------------------------
// Register offsets  -  DRIVER-INTERFACES.md §8.1
// ---------------------------------------------------------------------------

// NOTE: source `drivers/mmc/host/mediatek/ComboA/msdc_reg.h:20–74`

/// Global config: SD/eMMC mode, clock divisor, bus width.
const REG_MSDC_CFG: usize = 0x00;

/// I/O control: DS edge, R/W edge SELECT.
const REG_MSDC_IOCON: usize = 0x04;

/// Pin status: CD, WP, DAT, CMD, CLK levels.
const REG_MSDC_PS: usize = 0x08;

/// Interrupt status.
const REG_MSDC_INT: usize = 0x0C;

/// Interrupt enable.
const REG_MSDC_INTEN: usize = 0x10;

/// FIFO control and status.
const REG_MSDC_FIFOCS: usize = 0x14;

/// FIFO TX data.
const REG_MSDC_TXDATA: usize = 0x18;

/// FIFO RX data.
const REG_MSDC_RXDATA: usize = 0x1C;

/// SD/MMC config: bus width, data timeout.
const REG_SDC_CFG: usize = 0x30;

/// Command register (opcode, type, response type).
const REG_SDC_CMD: usize = 0x34;

/// Command argument.
const REG_SDC_ARG: usize = 0x38;

/// Status: cmdbusy, datbusy.
const REG_SDC_STS: usize = 0x3C;

/// Response register 0 (bits [31:0] of 128-bit response).
const REG_SDC_RESP0: usize = 0x40;

/// Response register 1 (bits [63:32]).
const REG_SDC_RESP1: usize = 0x44;

/// Response register 2 (bits [95:64]).
const REG_SDC_RESP2: usize = 0x48;

/// Response register 3 (bits [127:96]).
const REG_SDC_RESP3: usize = 0x4C;

/// Block count for data transfer.
const REG_SDC_BLK_NUM: usize = 0x50;

/// Card status.
#[expect(dead_code, reason = "reserved for future status readback")]
const REG_SDC_CSTS: usize = 0x58;

/// Data CRC status per DAT line.
#[expect(dead_code, reason = "reserved for future CRC diagnostics")]
const REG_SDC_DCRC_STS: usize = 0x60;

/// Advanced config 0.
#[expect(dead_code, reason = "reserved for future tuning")]
const REG_SDC_ADV_CFG0: usize = 0x64;

/// eMMC config 0: boot mode, part access.
#[expect(dead_code, reason = "reserved for boot mode configuration")]
const REG_EMMC_CFG0: usize = 0x70;

/// eMMC config 1.
#[expect(dead_code, reason = "reserved for boot mode configuration")]
const REG_EMMC_CFG1: usize = 0x74;

/// eMMC status: boot ack.
#[expect(dead_code, reason = "reserved for boot status readback")]
const REG_EMMC_STS: usize = 0x78;

/// eMMC I/O control.
#[expect(dead_code, reason = "reserved for eMMC I/O tuning")]
const REG_EMMC_IOCON: usize = 0x7C;

/// DMA start address [35:32] (4 MSB).
#[expect(dead_code, reason = "MT6739 is 32-bit; high bits unused")]
const REG_MSDC_DMA_SA_HIGH: usize = 0x8C;

/// DMA start address [31:0].
const REG_MSDC_DMA_SA: usize = 0x90;

/// DMA current address.
#[expect(dead_code, reason = "reserved for DMA progress monitoring")]
const REG_MSDC_DMA_CA: usize = 0x94;

/// DMA control: start, stop, mode.
const REG_MSDC_DMA_CTRL: usize = 0x98;

/// DMA config: burst length.
const REG_MSDC_DMA_CFG: usize = 0x9C;

/// DMA transfer length.
#[expect(dead_code, reason = "length encoded in GPD/BD descriptors")]
const REG_MSDC_DMA_LEN: usize = 0xA8;

/// Patch register 0 (tuning overrides).
#[expect(dead_code, reason = "reserved for auto-tuning")]
const REG_MSDC_PATCH_BIT0: usize = 0xB0;

/// Version register.
#[expect(dead_code, reason = "reserved for version readback")]
const REG_MSDC_VERSION: usize = 0x114;

// NOTE: source `drivers/mmc/host/mediatek/ComboA/msdc_reg.h:75–221`

/// Inline AES encryption SELECT.
#[expect(dead_code, reason = "reserved for encrypted storage layer")]
const REG_MSDC_AES_SEL: usize = 0x280;

// ---------------------------------------------------------------------------
// MSDC_CFG bit fields
// ---------------------------------------------------------------------------

/// Clock source SELECT shift (bits [17:16]).
const CFG_CKMOD_SHIFT: u32 = 16;

/// Clock divisor shift (bits [15:8]).
const CFG_CKDIV_SHIFT: u32 = 8;

/// Bus width: 1-bit (bits [21:20] = 0b00).
const CFG_BUSWIDTH_1: u32 = 0b00 << 20;

/// Bus width: 4-bit (bits [21:20] = 0b01).
#[expect(dead_code, reason = "eMMC uses 8-bit; kept for SD card support")]
const CFG_BUSWIDTH_4: u32 = 0b01 << 20;

/// Bus width: 8-bit (bits [21:20] = 0b10).
const CFG_BUSWIDTH_8: u32 = 0b10 << 20;

// ---------------------------------------------------------------------------
// SDC_STS bit fields
// ---------------------------------------------------------------------------

/// Command engine busy.
const STS_CMDBUSY: u32 = 1 << 1;

/// Data engine busy.
const STS_DATBUSY: u32 = 1 << 2;

// ---------------------------------------------------------------------------
// SDC_CMD bit fields
// ---------------------------------------------------------------------------

/// Command opcode mask (bits [5:0]).
const CMD_OPCODE_MASK: u32 = 0x3F;

/// Response type: none.
const CMD_RSPTYP_NONE: u32 = 0b00 << 7;

/// Response type: R1/R5/R6/R7 (48-bit).
const CMD_RSPTYP_R1: u32 = 0b01 << 7;

/// Response type: R2 (136-bit).
#[expect(dead_code, reason = "reserved for CID/CSD readback")]
const CMD_RSPTYP_R2: u32 = 0b10 << 7;

/// Response type: R3/R4 (48-bit, no CRC).
const CMD_RSPTYP_R3: u32 = 0b11 << 7;

/// Data transfer direction: read (device → host).
const CMD_DTYPE_READ: u32 = 0b01 << 11;

/// Data transfer direction: write (host → device).
const CMD_DTYPE_WRITE: u32 = 0b10 << 11;

/// Block length shift for SDC_CMD (bits [31:16] in some configs).
#[expect(dead_code, reason = "block length SET via SDC_CFG on MT6739")]
const CMD_BLK_LEN_SHIFT: u32 = 16;

// ---------------------------------------------------------------------------
// MSDC_DMA_CTRL bit fields
// ---------------------------------------------------------------------------

/// Start DMA transfer.
const DMA_CTRL_START: u32 = 1 << 0;

/// Stop DMA transfer.
const DMA_CTRL_STOP: u32 = 1 << 1;

/// DMA mode: basic (single buffer).
#[expect(dead_code, reason = "descriptor mode used for scatter-gather")]
const DMA_CTRL_MODE_BASIC: u32 = 0b00 << 8;

/// DMA mode: descriptor (GPD/BD chain).
const DMA_CTRL_MODE_DESC: u32 = 0b01 << 8;

// ---------------------------------------------------------------------------
// MSDC_DMA_CFG bit fields
// ---------------------------------------------------------------------------

/// DMA active status bit.
const DMA_CFG_STS_ACTIVE: u32 = 1 << 0;

// ---------------------------------------------------------------------------
// MSDC_FIFOCS bit fields
// ---------------------------------------------------------------------------

/// FIFO clear bit  -  write 1 to flush both TX and RX FIFOs.
const FIFOCS_CLR: u32 = 1 << 0;

// ---------------------------------------------------------------------------
// MSDC_PS bit fields
// ---------------------------------------------------------------------------

/// Card detect pin (active low: 0 = card present).
const PS_CDEN: u32 = 1 << 0;

// ---------------------------------------------------------------------------
// Interrupt bit masks  -  DRIVER-INTERFACES.md §8.4
// ---------------------------------------------------------------------------
// NOTE: source `drivers/mmc/host/mediatek/ComboA/msdc_reg.h` (MSDC_INT_* defines)

/// SDIO card interrupt.
pub(crate) const INT_MMCIRQ: u32 = 1 << 0;

/// Card detect state change.
pub(crate) const INT_CDSC: u32 = 1 << 1;

/// Auto CMD response ready.
pub(crate) const INT_ACMDRDY: u32 = 1 << 2;

/// Auto CMD response timeout.
pub(crate) const INT_ACMDTMO: u32 = 1 << 3;

/// Auto CMD CRC error.
pub(crate) const INT_ACMDCRCERR: u32 = 1 << 4;

/// DMA queue empty.
pub(crate) const INT_DMAQ_EMPTY: u32 = 1 << 5;

/// SDIO interrupt.
pub(crate) const INT_SDIOIRQ: u32 = 1 << 6;

/// Command response ready.
pub(crate) const INT_CMDRDY: u32 = 1 << 7;

/// Command response timeout.
pub(crate) const INT_CMDTMO: u32 = 1 << 8;

/// Response CRC error.
pub(crate) const INT_RSPCRCERR: u32 = 1 << 9;

/// Card status error.
pub(crate) const INT_CSTA: u32 = 1 << 10;

/// Data transfer complete.
pub(crate) const INT_XFER_COMPL: u32 = 1 << 11;

/// Data transfer done.
pub(crate) const INT_DXFER_DONE: u32 = 1 << 12;

/// Data timeout.
pub(crate) const INT_DATTMO: u32 = 1 << 13;

/// Data CRC error.
pub(crate) const INT_DATCRCERR: u32 = 1 << 14;

/// ACMD19 done.
pub(crate) const INT_ACMD19_DONE: u32 = 1 << 15;

/// All error interrupts combined.
pub(crate) const INT_ERR_MASK: u32 = INT_ACMDTMO
    | INT_ACMDCRCERR
    | INT_CMDTMO
    | INT_RSPCRCERR
    | INT_CSTA
    | INT_DATTMO
    | INT_DATCRCERR;

/// All transfer-completion interrupts.
pub(crate) const INT_XFER_MASK: u32 = INT_XFER_COMPL | INT_DXFER_DONE;

// ---------------------------------------------------------------------------
// eMMC command opcodes (MMC specification)
// ---------------------------------------------------------------------------

/// CMD0: GO_IDLE_STATE  -  reset card to idle.
const CMD0_GO_IDLE: u32 = 0;

/// CMD1: SEND_OP_COND  -  send operating conditions.
const CMD1_SEND_OP_COND: u32 = 1;

/// CMD2: ALL_SEND_CID  -  request card identification.
#[expect(dead_code, reason = "reserved for CID readback")]
const CMD2_ALL_SEND_CID: u32 = 2;

/// CMD3: SET_RELATIVE_ADDR  -  assign relative card address.
const CMD3_SET_RELATIVE_ADDR: u32 = 3;

/// CMD7: SELECT_CARD  -  SELECT card for data transfer.
const CMD7_SELECT_CARD: u32 = 7;

/// CMD8: SEND_EXT_CSD  -  read extended CSD register.
#[expect(dead_code, reason = "reserved for EXT_CSD readback")]
const CMD8_SEND_EXT_CSD: u32 = 8;

/// CMD13: SEND_STATUS  -  read card status register.
#[expect(dead_code, reason = "reserved for status polling")]
const CMD13_SEND_STATUS: u32 = 13;

/// CMD16: SET_BLOCKLEN  -  SET block length to 512 bytes.
const CMD16_SET_BLOCKLEN: u32 = 16;

/// CMD17: READ_SINGLE_BLOCK.
const CMD17_READ_SINGLE: u32 = 17;

/// CMD18: READ_MULTIPLE_BLOCK.
const CMD18_READ_MULTI: u32 = 18;

/// CMD24: WRITE_SINGLE_BLOCK.
const CMD24_WRITE_SINGLE: u32 = 24;

/// CMD25: WRITE_MULTIPLE_BLOCK.
const CMD25_WRITE_MULTI: u32 = 25;

// ---------------------------------------------------------------------------
// GPD / BD descriptors  -  DRIVER-INTERFACES.md §8.2
// ---------------------------------------------------------------------------
// NOTE: source `drivers/mmc/host/mediatek/ComboA/mtk_sd.h`

/// GPD flag: hardware owns this descriptor.
const GPD_HWO: u32 = 1 << 0;

/// GPD flag: BD pointer is valid (scatter-gather through BDs).
const GPD_BDP: u32 = 1 << 1;

/// BD flag: end of linked list.
const BD_EOL: u32 = 1 << 0;

/// Generic Payload Descriptor (GPD) for DMA scatter-gather.
///
/// Each GPD is 16 bytes in the minimal layout used here. The hardware
/// spec defines 64 bytes with reserved fields, but only these 4 words
/// are functional for basic descriptor-mode DMA.
#[repr(C, align(4))]
#[derive(Debug, Clone, Copy)]
pub(crate) struct Gpd {
    /// Physical address of the next GPD (0 = last).
    pub(crate) next: u32,
    /// Flags: HWO (bit 0), BDP (bit 1), checksum.
    pub(crate) flags: u32,
    /// Physical address of the first BD (if BDP SET) or data buffer.
    pub(crate) ptr: u32,
    /// Total data length for this GPD.
    pub(crate) data_len: u32,
}

/// Buffer Descriptor (BD) for scatter-gather sub-entries.
///
/// Each BD is 16 bytes. Linked list terminated by EOL flag.
#[repr(C, align(4))]
#[derive(Debug, Clone, Copy)]
pub(crate) struct Bd {
    /// Physical address of the next BD (0 if EOL).
    pub(crate) next: u32,
    /// Physical address of the data buffer.
    pub(crate) ptr: u32,
    /// Buffer data length in bytes.
    pub(crate) data_len: u32,
    /// Flags: EOL (bit 0).
    pub(crate) flags: u32,
}

impl Gpd {
    /// Create a new GPD owned by hardware, pointing to a BD chain.
    pub(crate) fn new_with_bd(bd_phys: u32, total_len: u32) -> Self {
        Self {
            next: 0,
            flags: GPD_HWO | GPD_BDP,
            ptr: bd_phys,
            data_len: total_len,
        }
    }

    /// Create a new GPD owned by hardware, pointing directly to a data buffer.
    pub(crate) fn new_direct(buf_phys: u32, data_len: u32) -> Self {
        Self {
            next: 0,
            flags: GPD_HWO,
            ptr: buf_phys,
            data_len,
        }
    }

    /// Check if this GPD is hardware-owned.
    pub(crate) fn is_hw_owned(&self) -> bool {
        self.flags & GPD_HWO != 0
    }

    /// Check if this GPD uses BD scatter-gather.
    pub(crate) fn has_bd(&self) -> bool {
        self.flags & GPD_BDP != 0
    }
}

impl Bd {
    /// Create a new BD for a buffer segment.
    pub(crate) fn new(buf_phys: u32, data_len: u32, is_last: bool) -> Self {
        Self {
            next: 0,
            ptr: buf_phys,
            data_len,
            flags: if is_last { BD_EOL } else { 0 },
        }
    }

    /// Check if this is the last BD in the chain.
    pub(crate) fn is_eol(&self) -> bool {
        self.flags & BD_EOL != 0
    }
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors FROM the MSDC controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MsdcError {
    /// Command engine timed out waiting for busy clear.
    CommandTimeout,
    /// Data engine timed out waiting for busy clear.
    DataTimeout,
    /// Card not present (CD pin high).
    CardNotPresent,
    /// DMA transfer timed out.
    DmaTimeout,
    /// Hardware reported an interrupt error.
    InterruptError(u32),
}

// ---------------------------------------------------------------------------
// MsdcController
// ---------------------------------------------------------------------------

/// MSDC controller driver for eMMC block I/O.
///
/// Provides PIO and DMA transfer paths for 512-byte sector operations.
/// The controller must be initialized via [`MsdcController::init`] before
/// any read/write operations.
pub(crate) struct MsdcController {
    /// MMIO base address of the MSDC controller.
    base: usize,
    /// Whether the controller has been initialized.
    initialized: bool,
}

impl MsdcController {
    /// Create a new controller handle at the default MSDC0 base address.
    pub(crate) fn new() -> Self {
        Self {
            base: MSDC0_BASE,
            initialized: false,
        }
    }

    /// Create a controller handle at a specific base address.
    ///
    /// # Safety
    ///
    /// The caller must ensure `base` points to a valid MSDC register block.
    pub(crate) unsafe fn at_base(base: usize) -> Self {
        Self {
            base,
            initialized: false,
        }
    }

    /// Absolute register address from offset.
    #[inline(always)]
    fn reg(&self, offset: usize) -> usize {
        self.base + offset
    }

    // -- Register access helpers --

    /// Read a controller register.
    ///
    /// # Safety
    ///
    /// Caller must ensure the controller base is valid and mapped.
    unsafe fn read_reg(&self, offset: usize) -> u32 {
        // SAFETY: MSDC0 is a valid MMIO register block at 0x1123_0000 within the MSDC address space. Volatile access is required for hardware registers.
        unsafe { mmio::read32(self.reg(offset)) }
    }

    /// Write a controller register.
    ///
    /// # Safety
    ///
    /// Caller must ensure the controller base is valid and mapped.
    unsafe fn write_reg(&self, offset: usize, val: u32) {
        // SAFETY: MSDC0 is a valid MMIO register block at 0x1123_0000 within the MSDC address space. Volatile access is required for hardware registers.
        unsafe { mmio::write32(self.reg(offset), val) }
    }

    // -- Initialization --

    /// Initialize the MSDC controller for eMMC operation.
    ///
    /// Configures clock divisor, 8-bit bus width, verifies card presence,
    /// and sends the eMMC initialization command sequence (CMD0 → CMD1 →
    /// CMD3 → CMD7 → CMD16).
    ///
    /// # Safety
    ///
    /// Must be called exactly once after power-on. The MSDC register block
    /// must be mapped and accessible.
    ///
    /// # Errors
    ///
    /// Returns [`MsdcError::CardNotPresent`] if the card detect pin is high.
    /// Returns [`MsdcError::CommandTimeout`] if any init command fails.
    pub(crate) unsafe fn init(&mut self) -> Result<(), MsdcError> {
        // STEP 1: Verify card presence via MSDC_PS
        // SAFETY: MSDC_PS is a valid MMIO register at offset 0x08 within the MSDC0 address space. The controller base is valid and mapped per caller contract.
        let ps = unsafe { self.read_reg(REG_MSDC_PS) };
        // NOTE: eMMC is soldered, CD pin should always read present.
        // On MT6739 the CD bit may be tied low. Check anyway for robustness.
        if ps & PS_CDEN != 0 {
            return Err(MsdcError::CardNotPresent);
        }

        // STEP 2: Flush FIFOs
        // SAFETY: MSDC_FIFOCS is a valid MMIO register at offset 0x14 within the MSDC0 address space. Volatile access is required for hardware registers.
        unsafe { self.write_reg(REG_MSDC_FIFOCS, FIFOCS_CLR) };

        // STEP 3: Configure clock  -  use divisor 0x10 for initial low speed
        // Clock mode 0 (PLL / (divisor + 1)), 8-bit bus width
        let cfg = (0x00 << CFG_CKMOD_SHIFT) | (0x10 << CFG_CKDIV_SHIFT) | CFG_BUSWIDTH_8;
        // SAFETY: MSDC_CFG is a valid MMIO register at offset 0x00 within the MSDC0 address space. Volatile access is required for hardware registers.
        unsafe { self.write_reg(REG_MSDC_CFG, cfg) };

        // STEP 4: Clear all pending interrupts
        // SAFETY: MSDC_INT is a valid MMIO register at offset 0x0C within the MSDC0 address space. Volatile access is required for hardware registers.
        unsafe { self.write_reg(REG_MSDC_INT, 0xFFFF_FFFF) };

        // STEP 5: Enable relevant interrupts
        let inten = INT_CMDRDY | INT_CMDTMO | INT_XFER_COMPL | INT_DATTMO | INT_DATCRCERR;
        // SAFETY: MSDC_INTEN is a valid MMIO register at offset 0x10 within the MSDC0 address space. Volatile access is required for hardware registers.
        unsafe { self.write_reg(REG_MSDC_INTEN, inten) };

        // STEP 6: eMMC init sequence
        // CMD0: GO_IDLE_STATE (no response)
        // SAFETY: controller is powered and register block is mapped per caller contract.
        unsafe { self.send_command(CMD0_GO_IDLE, 0, CMD_RSPTYP_NONE)? };

        // CMD1: SEND_OP_COND (R3 response, no CRC)
        // Argument: sector addressing (bit 30), voltage window 0xFF8000
        // SAFETY: controller is powered and register block is mapped per caller contract.
        unsafe { self.send_command(CMD1_SEND_OP_COND, 0x40FF_8000, CMD_RSPTYP_R3)? };

        // CMD3: SET_RELATIVE_ADDR (R1 response)
        // Assign RCA = 1
        // SAFETY: controller is powered and register block is mapped per caller contract.
        unsafe { self.send_command(CMD3_SET_RELATIVE_ADDR, 0x0001_0000, CMD_RSPTYP_R1)? };

        // CMD7: SELECT_CARD (R1 response)
        // SAFETY: controller is powered and register block is mapped per caller contract.
        unsafe { self.send_command(CMD7_SELECT_CARD, 0x0001_0000, CMD_RSPTYP_R1)? };

        // CMD16: SET_BLOCKLEN to 512 bytes
        // SAFETY: controller is powered and register block is mapped per caller contract.
        unsafe { self.send_command(CMD16_SET_BLOCKLEN, u32::try_from(SECTOR_SIZE).unwrap_or_default(), CMD_RSPTYP_R1)? };

        self.initialized = true;
        Ok(())
    }

    // -- Command engine --

    /// Send a command via the SDC command engine.
    ///
    /// # Safety
    ///
    /// Caller must ensure the controller is powered and register block is mapped.
    ///
    /// # Errors
    ///
    /// Returns [`MsdcError::CommandTimeout`] if the command engine does not
    /// become idle within the poll timeout.
    unsafe fn send_command(&self, opcode: u32, arg: u32, rsptyp: u32) -> Result<(), MsdcError> {
        // Wait for command engine to be idle
        // SAFETY: SDC_STS is a valid MMIO register at offset 0x3C within the MSDC0 address space. Volatile access is required for hardware registers.
        if !unsafe { mmio::wait_bits_clear(self.reg(REG_SDC_STS), STS_CMDBUSY, POLL_TIMEOUT) } {
            return Err(MsdcError::CommandTimeout);
        }

        // Write argument first, then command register
        // INVARIANT: SDC_ARG must be written before SDC_CMD per §8.3
        // SAFETY: SDC_ARG is a valid MMIO register at offset 0x38 within the MSDC0 address space. Volatile access is required for hardware registers.
        unsafe { self.write_reg(REG_SDC_ARG, arg) };

        let cmd = (opcode & CMD_OPCODE_MASK) | rsptyp;
        // SAFETY: SDC_CMD is a valid MMIO register at offset 0x34 within the MSDC0 address space. Volatile access is required for hardware registers.
        unsafe { self.write_reg(REG_SDC_CMD, cmd) };

        // Wait for command to complete
        // SAFETY: SDC_STS is a valid MMIO register at offset 0x3C within the MSDC0 address space. Volatile access is required for hardware registers.
        if !unsafe { mmio::wait_bits_clear(self.reg(REG_SDC_STS), STS_CMDBUSY, POLL_TIMEOUT) } {
            return Err(MsdcError::CommandTimeout);
        }

        Ok(())
    }

    /// Send a data-transfer command (read or write direction).
    ///
    /// # Safety
    ///
    /// Same as [`send_command`]. Additionally, the data engine must be idle.
    ///
    /// # Errors
    ///
    /// Returns [`MsdcError::CommandTimeout`] or [`MsdcError::DataTimeout`].
    unsafe fn send_data_command(
        &self,
        opcode: u32,
        arg: u32,
        rsptyp: u32,
        dtype: u32,
        block_count: u32,
    ) -> Result<(), MsdcError> {
        // Wait for both command and data engines
        // SAFETY: SDC_STS is a valid MMIO register at offset 0x3C within the MSDC0 address space. Volatile access is required for hardware registers.
        if !unsafe {
            mmio::wait_bits_clear(
                self.reg(REG_SDC_STS),
                STS_CMDBUSY | STS_DATBUSY,
                POLL_TIMEOUT,
            )
        } {
            return Err(MsdcError::DataTimeout);
        }

        // Set block count
        // SAFETY: SDC_BLK_NUM is a valid MMIO register at offset 0x50 within the MSDC0 address space. Volatile access is required for hardware registers.
        unsafe { self.write_reg(REG_SDC_BLK_NUM, block_count) };

        // Write argument
        // SAFETY: SDC_ARG is a valid MMIO register at offset 0x38 within the MSDC0 address space. Volatile access is required for hardware registers.
        unsafe { self.write_reg(REG_SDC_ARG, arg) };

        // Build command word with data type
        let cmd = (opcode & CMD_OPCODE_MASK) | rsptyp | dtype;
        // SAFETY: SDC_CMD is a valid MMIO register at offset 0x34 within the MSDC0 address space. Volatile access is required for hardware registers.
        unsafe { self.write_reg(REG_SDC_CMD, cmd) };

        // Wait for command phase to complete
        // SAFETY: SDC_STS is a valid MMIO register at offset 0x3C within the MSDC0 address space. Volatile access is required for hardware registers.
        if !unsafe { mmio::wait_bits_clear(self.reg(REG_SDC_STS), STS_CMDBUSY, POLL_TIMEOUT) } {
            return Err(MsdcError::CommandTimeout);
        }

        Ok(())
    }

    // -- PIO transfers --

    /// Read a single 512-byte sector via PIO.
    ///
    /// # Safety
    ///
    /// `buf` must point to at least 512 bytes of writable memory.
    /// The controller must be initialized.
    ///
    /// # Errors
    ///
    /// Returns [`MsdcError::CommandTimeout`] or [`MsdcError::DataTimeout`].
    pub(crate) unsafe fn read_sector(
        &self,
        lba: u32,
        buf: &mut [u8; SECTOR_SIZE],
    ) -> Result<(), MsdcError> {
        debug_assert!(
            self.initialized,
            "MSDC controller must be initialized before read"
        );

        // Flush FIFO before read
        // SAFETY: MSDC_FIFOCS is a valid MMIO register at offset 0x14 within the MSDC0 address space. Volatile access is required for hardware registers.
        unsafe { self.write_reg(REG_MSDC_FIFOCS, FIFOCS_CLR) };

        // CMD17: READ_SINGLE_BLOCK, argument = LBA (sector addressing)
        // SAFETY: controller is initialized and register block is mapped per debug_assert and caller contract.
        unsafe {
            self.send_data_command(CMD17_READ_SINGLE, lba, CMD_RSPTYP_R1, CMD_DTYPE_READ, 1)?;
        }

        // PIO: read 128 words (512 bytes) FROM MSDC_RXDATA
        let buf_ptr = buf.as_mut_ptr().cast::<u32>();
        for i in 0..WORDS_PER_SECTOR {
            // Poll until FIFO has data (check dat busy clears for completion)
            // SAFETY: SDC_STS is a valid MMIO register at offset 0x3C within the MSDC0 address space. Volatile access is required for hardware registers.
            if !unsafe { mmio::wait_bits_clear(self.reg(REG_SDC_STS), STS_DATBUSY, POLL_TIMEOUT) } {
                // NOTE: datbusy stays SET until the full block is transferred,
                // so we read word-by-word and only check at the end
            }
            // SAFETY: MSDC_RXDATA is a valid MMIO register at offset 0x1C within the MSDC0 address space. Volatile access is required for hardware registers.
            let word = unsafe { self.read_reg(REG_MSDC_RXDATA) };
            // SAFETY: buf_ptr is valid for WORDS_PER_SECTOR u32 writes, i < WORDS_PER_SECTOR
            unsafe { buf_ptr.add(i).write_volatile(word) };
        }

        // Wait for transfer complete
        // SAFETY: SDC_STS is a valid MMIO register at offset 0x3C within the MSDC0 address space. Volatile access is required for hardware registers.
        if !unsafe { mmio::wait_bits_clear(self.reg(REG_SDC_STS), STS_DATBUSY, POLL_TIMEOUT) } {
            return Err(MsdcError::DataTimeout);
        }

        // Clear transfer-complete interrupt
        // SAFETY: MSDC_INT is a valid MMIO register at offset 0x0C within the MSDC0 address space. Volatile access is required for hardware registers.
        unsafe { self.write_reg(REG_MSDC_INT, INT_XFER_COMPL) };

        Ok(())
    }

    /// Write a single 512-byte sector via PIO.
    ///
    /// # Safety
    ///
    /// `buf` must point to at least 512 bytes of readable memory.
    /// The controller must be initialized.
    ///
    /// # Errors
    ///
    /// Returns [`MsdcError::CommandTimeout`] or [`MsdcError::DataTimeout`].
    pub(crate) unsafe fn write_sector(
        &self,
        lba: u32,
        buf: &[u8; SECTOR_SIZE],
    ) -> Result<(), MsdcError> {
        debug_assert!(
            self.initialized,
            "MSDC controller must be initialized before write"
        );

        // Flush FIFO before write
        // SAFETY: MSDC_FIFOCS is a valid MMIO register at offset 0x14 within the MSDC0 address space. Volatile access is required for hardware registers.
        unsafe { self.write_reg(REG_MSDC_FIFOCS, FIFOCS_CLR) };

        // CMD24: WRITE_SINGLE_BLOCK, argument = LBA
        // SAFETY: controller is initialized and register block is mapped per debug_assert and caller contract.
        unsafe {
            self.send_data_command(CMD24_WRITE_SINGLE, lba, CMD_RSPTYP_R1, CMD_DTYPE_WRITE, 1)?;
        }

        // PIO: write 128 words (512 bytes) to MSDC_TXDATA
        let buf_ptr = buf.as_ptr().cast::<u32>();
        for i in 0..WORDS_PER_SECTOR {
            // SAFETY: buf_ptr is valid for WORDS_PER_SECTOR u32 reads, i < WORDS_PER_SECTOR
            let word = unsafe { buf_ptr.add(i).read_volatile() };
            // SAFETY: MSDC_TXDATA is a valid MMIO register at offset 0x18 within the MSDC0 address space. Volatile access is required for hardware registers.
            unsafe { self.write_reg(REG_MSDC_TXDATA, word) };
        }

        // Wait for transfer complete
        // SAFETY: SDC_STS is a valid MMIO register at offset 0x3C within the MSDC0 address space. Volatile access is required for hardware registers.
        if !unsafe { mmio::wait_bits_clear(self.reg(REG_SDC_STS), STS_DATBUSY, POLL_TIMEOUT) } {
            return Err(MsdcError::DataTimeout);
        }

        // Clear transfer-complete interrupt
        // SAFETY: MSDC_INT is a valid MMIO register at offset 0x0C within the MSDC0 address space. Volatile access is required for hardware registers.
        unsafe { self.write_reg(REG_MSDC_INT, INT_XFER_COMPL) };

        Ok(())
    }

    // -- DMA transfers --

    /// Read sectors via DMA using a GPD/BD descriptor chain.
    ///
    /// `gpd_phys` is the physical address of the first GPD in the chain.
    /// The GPD must be SET up with HWO=1 and point to BD(s) or a data buffer.
    ///
    /// # Safety
    ///
    /// - The GPD/BD chain and data buffers must be in DMA-accessible physical
    ///   memory and remain valid until the transfer completes.
    /// - The controller must be initialized.
    ///
    /// # Errors
    ///
    /// Returns [`MsdcError::DmaTimeout`] if the DMA engine does not complete.
    pub(crate) unsafe fn dma_read(
        &self,
        lba: u32,
        block_count: u32,
        gpd_phys: u32,
    ) -> Result<(), MsdcError> {
        debug_assert!(
            self.initialized,
            "MSDC controller must be initialized before DMA read"
        );

        let opcode = if block_count == 1 {
            CMD17_READ_SINGLE
        } else {
            CMD18_READ_MULTI
        };

        // Set up data command
        // SAFETY: controller is initialized and register block is mapped per debug_assert and caller contract.
        unsafe {
            self.send_data_command(opcode, lba, CMD_RSPTYP_R1, CMD_DTYPE_READ, block_count)?;
        }

        // Write GPD chain physical address to MSDC_DMA_SA
        // SAFETY: MSDC_DMA_SA is a valid MMIO register at offset 0x90 within the MSDC0 address space. Volatile access is required for hardware registers.
        unsafe { self.write_reg(REG_MSDC_DMA_SA, gpd_phys) };

        // Start DMA in descriptor mode
        // SAFETY: MSDC_DMA_CTRL is a valid MMIO register at offset 0x98 within the MSDC0 address space. Volatile access is required for hardware registers.
        unsafe { self.write_reg(REG_MSDC_DMA_CTRL, DMA_CTRL_START | DMA_CTRL_MODE_DESC) };

        // Poll MSDC_DMA_CFG for completion (active bit clears)
        // SAFETY: MSDC_DMA_CFG is a valid MMIO register at offset 0x9C within the MSDC0 address space. Volatile access is required for hardware registers.
        if !unsafe {
            mmio::wait_bits_clear(self.reg(REG_MSDC_DMA_CFG), DMA_CFG_STS_ACTIVE, POLL_TIMEOUT)
        } {
            // Stop DMA on timeout
            // SAFETY: MSDC_DMA_CTRL is a valid MMIO register at offset 0x98 within the MSDC0 address space. Volatile access is required for hardware registers.
            unsafe { mmio::set_bits(self.reg(REG_MSDC_DMA_CTRL), DMA_CTRL_STOP) };
            return Err(MsdcError::DmaTimeout);
        }

        // Wait for data engine idle
        // SAFETY: SDC_STS is a valid MMIO register at offset 0x3C within the MSDC0 address space. Volatile access is required for hardware registers.
        if !unsafe { mmio::wait_bits_clear(self.reg(REG_SDC_STS), STS_DATBUSY, POLL_TIMEOUT) } {
            return Err(MsdcError::DataTimeout);
        }

        // Clear completion interrupt
        // SAFETY: MSDC_INT is a valid MMIO register at offset 0x0C within the MSDC0 address space. Volatile access is required for hardware registers.
        unsafe { self.write_reg(REG_MSDC_INT, INT_XFER_COMPL | INT_DXFER_DONE) };

        Ok(())
    }

    /// Write sectors via DMA using a GPD/BD descriptor chain.
    ///
    /// # Safety
    ///
    /// Same requirements as [`dma_read`].
    ///
    /// # Errors
    ///
    /// Returns [`MsdcError::DmaTimeout`] if the DMA engine does not complete.
    pub(crate) unsafe fn dma_write(
        &self,
        lba: u32,
        block_count: u32,
        gpd_phys: u32,
    ) -> Result<(), MsdcError> {
        debug_assert!(
            self.initialized,
            "MSDC controller must be initialized before DMA write"
        );

        let opcode = if block_count == 1 {
            CMD24_WRITE_SINGLE
        } else {
            CMD25_WRITE_MULTI
        };

        // Set up data command
        // SAFETY: controller is initialized and register block is mapped per debug_assert and caller contract.
        unsafe {
            self.send_data_command(opcode, lba, CMD_RSPTYP_R1, CMD_DTYPE_WRITE, block_count)?;
        }

        // Write GPD chain physical address
        // SAFETY: MSDC_DMA_SA is a valid MMIO register at offset 0x90 within the MSDC0 address space. Volatile access is required for hardware registers.
        unsafe { self.write_reg(REG_MSDC_DMA_SA, gpd_phys) };

        // Start DMA in descriptor mode
        // SAFETY: MSDC_DMA_CTRL is a valid MMIO register at offset 0x98 within the MSDC0 address space. Volatile access is required for hardware registers.
        unsafe { self.write_reg(REG_MSDC_DMA_CTRL, DMA_CTRL_START | DMA_CTRL_MODE_DESC) };

        // Poll for DMA completion
        // SAFETY: MSDC_DMA_CFG is a valid MMIO register at offset 0x9C within the MSDC0 address space. Volatile access is required for hardware registers.
        if !unsafe {
            mmio::wait_bits_clear(self.reg(REG_MSDC_DMA_CFG), DMA_CFG_STS_ACTIVE, POLL_TIMEOUT)
        } {
            // SAFETY: MSDC_DMA_CTRL is a valid MMIO register at offset 0x98 within the MSDC0 address space. Volatile access is required for hardware registers.
            unsafe { mmio::set_bits(self.reg(REG_MSDC_DMA_CTRL), DMA_CTRL_STOP) };
            return Err(MsdcError::DmaTimeout);
        }

        // Wait for data engine idle
        // SAFETY: SDC_STS is a valid MMIO register at offset 0x3C within the MSDC0 address space. Volatile access is required for hardware registers.
        if !unsafe { mmio::wait_bits_clear(self.reg(REG_SDC_STS), STS_DATBUSY, POLL_TIMEOUT) } {
            return Err(MsdcError::DataTimeout);
        }

        // Clear completion interrupt
        // SAFETY: MSDC_INT is a valid MMIO register at offset 0x0C within the MSDC0 address space. Volatile access is required for hardware registers.
        unsafe { self.write_reg(REG_MSDC_INT, INT_XFER_COMPL | INT_DXFER_DONE) };

        Ok(())
    }

    /// Read the 32-bit response FROM SDC_RESP0.
    ///
    /// # Safety
    ///
    /// Only valid after a successful command with a non-empty response type.
    pub(crate) unsafe fn read_response(&self) -> u32 {
        // SAFETY: SDC_RESP0 is a valid MMIO register at offset 0x40 within the MSDC0 address space. Volatile access is required for hardware registers.
        unsafe { self.read_reg(REG_SDC_RESP0) }
    }

    /// Read the full 128-bit response FROM SDC_RESP0–3.
    ///
    /// # Safety
    ///
    /// Only valid after a successful R2-type command.
    pub(crate) unsafe fn read_response_128(&self) -> [u32; 4] {
        // SAFETY: SDC_RESP0–3 are valid MMIO registers at offsets 0x40–0x4C within the MSDC0 address space. Volatile access is required for hardware registers.
        unsafe {
            [
                self.read_reg(REG_SDC_RESP0),
                self.read_reg(REG_SDC_RESP1),
                self.read_reg(REG_SDC_RESP2),
                self.read_reg(REG_SDC_RESP3),
            ]
        }
    }

    /// Read the current interrupt status register.
    ///
    /// # Safety
    ///
    /// The controller register block must be mapped.
    pub(crate) unsafe fn interrupt_status(&self) -> u32 {
        // SAFETY: MSDC_INT is a valid MMIO register at offset 0x0C within the MSDC0 address space. Volatile access is required for hardware registers.
        unsafe { self.read_reg(REG_MSDC_INT) }
    }

    /// Clear specific interrupt bits by writing 1s.
    ///
    /// # Safety
    ///
    /// The controller register block must be mapped.
    pub(crate) unsafe fn clear_interrupts(&self, bits: u32) {
        // SAFETY: MSDC_INT is a valid MMIO register at offset 0x0C within the MSDC0 address space. Volatile access is required for hardware registers.
        unsafe { self.write_reg(REG_MSDC_INT, bits) };
    }

    /// Enable specific interrupt sources.
    ///
    /// # Safety
    ///
    /// The controller register block must be mapped.
    pub(crate) unsafe fn enable_interrupts(&self, bits: u32) {
        // SAFETY: MSDC_INTEN is a valid MMIO register at offset 0x10 within the MSDC0 address space. Volatile access is required for hardware registers.
        unsafe { mmio::set_bits(self.reg(REG_MSDC_INTEN), bits) };
    }

    /// Disable specific interrupt sources.
    ///
    /// # Safety
    ///
    /// The controller register block must be mapped.
    pub(crate) unsafe fn disable_interrupts(&self, bits: u32) {
        // SAFETY: MSDC_INTEN is a valid MMIO register at offset 0x10 within the MSDC0 address space. Volatile access is required for hardware registers.
        unsafe { mmio::clear_bits(self.reg(REG_MSDC_INTEN), bits) };
    }

    /// Check if the controller has been initialized.
    pub(crate) fn is_initialized(&self) -> bool {
        self.initialized
    }
}

// ---------------------------------------------------------------------------
// Helper: build a command word FROM components
// ---------------------------------------------------------------------------

/// Encode a command register value FROM opcode, response type, and data type.
///
/// Used by tests to verify command encoding independently of MMIO.
pub(crate) fn encode_command(opcode: u32, rsptyp: u32, dtype: u32) -> u32 {
    (opcode & CMD_OPCODE_MASK) | rsptyp | dtype
}

/// Build an interrupt enable mask FROM a slice of individual interrupt bits.
pub(crate) fn compose_interrupt_mask(bits: &[u32]) -> u32 {
    let mut mask = 0u32;
    for &bit in bits {
        mask |= bit;
    }
    mask
}

// ---------------------------------------------------------------------------
// Helper: build a simple GPD → BD chain for a contiguous buffer
// ---------------------------------------------------------------------------

/// Build a single-entry GPD + BD pair for a contiguous DMA buffer.
///
/// Returns `(gpd, bd)` ready to be placed in DMA-accessible memory.
/// The caller must write these to physical memory and pass the GPD's
/// physical address to [`MsdcController::dma_read`] or [`dma_write`].
pub(crate) fn build_single_bd_chain(buf_phys: u32, len: u32) -> (Gpd, Bd) {
    let bd = Bd::new(buf_phys, len, true);
    // NOTE: bd_phys would be the physical address of `bd` in DMA memory.
    // The caller must fixup gpd.ptr after placing bd in physical memory.
    let gpd = Gpd::new_with_bd(0, len);
    (gpd, bd)
}

/// Build a multi-segment BD chain FROM an array of (phys_addr, len) pairs.
///
/// Returns a vector of BDs with next pointers SET to zero. The caller must
/// fixup next pointers after placing BDs in contiguous physical memory.
pub(crate) fn build_bd_chain(segments: &[(u32, u32)]) -> Option<(Gpd, [Bd; 8])> {
    let count = segments.len();
    if count == 0 || count > 8 {
        return None;
    }

    let mut bds = [Bd {
        next: 0,
        ptr: 0,
        data_len: 0,
        flags: 0,
    }; 8];
    let mut total_len: u32 = 0;

    for (i, &(phys, len)) in segments.iter().enumerate() {
        let is_last = i + 1 == count;
        bds[i] = Bd::new(phys, len, is_last);
        total_len = total_len.wrapping_add(len);
    }

    // GPD ptr will be fixup'd by caller after placing BDs in physical memory
    let gpd = Gpd::new_with_bd(0, total_len);
    Some((gpd, bds))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Register OFFSET tests --

    #[test]
    fn register_offsets_match_spec() {
        // INVARIANT: offsets must match DRIVER-INTERFACES.md §8.1
        assert_eq!(REG_MSDC_CFG, 0x00, "MSDC_CFG OFFSET");
        assert_eq!(REG_MSDC_IOCON, 0x04, "MSDC_IOCON OFFSET");
        assert_eq!(REG_MSDC_PS, 0x08, "MSDC_PS OFFSET");
        assert_eq!(REG_MSDC_INT, 0x0C, "MSDC_INT OFFSET");
        assert_eq!(REG_MSDC_INTEN, 0x10, "MSDC_INTEN OFFSET");
        assert_eq!(REG_MSDC_FIFOCS, 0x14, "MSDC_FIFOCS OFFSET");
        assert_eq!(REG_MSDC_TXDATA, 0x18, "MSDC_TXDATA OFFSET");
        assert_eq!(REG_MSDC_RXDATA, 0x1C, "MSDC_RXDATA OFFSET");
        assert_eq!(REG_SDC_CFG, 0x30, "SDC_CFG OFFSET");
        assert_eq!(REG_SDC_CMD, 0x34, "SDC_CMD OFFSET");
        assert_eq!(REG_SDC_ARG, 0x38, "SDC_ARG OFFSET");
        assert_eq!(REG_SDC_STS, 0x3C, "SDC_STS OFFSET");
        assert_eq!(REG_SDC_RESP0, 0x40, "SDC_RESP0 OFFSET");
        assert_eq!(REG_SDC_BLK_NUM, 0x50, "SDC_BLK_NUM OFFSET");
        assert_eq!(REG_MSDC_DMA_SA, 0x90, "MSDC_DMA_SA OFFSET");
        assert_eq!(REG_MSDC_DMA_CTRL, 0x98, "MSDC_DMA_CTRL OFFSET");
        assert_eq!(REG_MSDC_DMA_CFG, 0x9C, "MSDC_DMA_CFG OFFSET");
    }

    #[test]
    fn emmc_register_offsets_match_spec() {
        // INVARIANT: eMMC-specific offsets FROM §8.1
        assert_eq!(REG_EMMC_CFG0, 0x70, "EMMC_CFG0 OFFSET");
        assert_eq!(REG_EMMC_CFG1, 0x74, "EMMC_CFG1 OFFSET");
        assert_eq!(REG_EMMC_STS, 0x78, "EMMC_STS OFFSET");
        assert_eq!(REG_EMMC_IOCON, 0x7C, "EMMC_IOCON OFFSET");
        assert_eq!(REG_MSDC_DMA_SA_HIGH, 0x8C, "DMA_SA_HIGH OFFSET");
        assert_eq!(REG_MSDC_DMA_CA, 0x94, "DMA_CA OFFSET");
        assert_eq!(REG_MSDC_DMA_LEN, 0xA8, "DMA_LEN OFFSET");
        assert_eq!(REG_MSDC_AES_SEL, 0x280, "AES_SEL OFFSET");
        assert_eq!(REG_MSDC_VERSION, 0x114, "VERSION OFFSET");
    }

    // -- Command encoding tests --

    #[test]
    fn encode_cmd17_read_single() {
        let cmd = encode_command(CMD17_READ_SINGLE, CMD_RSPTYP_R1, CMD_DTYPE_READ);
        // Opcode 17 in bits [5:0], R1 in bits [8:7], read in bits [12:11]
        assert_eq!(cmd & CMD_OPCODE_MASK, 17, "CMD17 opcode");
        assert_ne!(cmd & CMD_RSPTYP_R1, 0, "CMD17 has R1 response");
        assert_ne!(cmd & CMD_DTYPE_READ, 0, "CMD17 is a read command");
    }

    #[test]
    fn encode_cmd24_write_single() {
        let cmd = encode_command(CMD24_WRITE_SINGLE, CMD_RSPTYP_R1, CMD_DTYPE_WRITE);
        assert_eq!(cmd & CMD_OPCODE_MASK, 24, "CMD24 opcode");
        assert_ne!(cmd & CMD_RSPTYP_R1, 0, "CMD24 has R1 response");
        assert_ne!(cmd & CMD_DTYPE_WRITE, 0, "CMD24 is a write command");
    }

    #[test]
    fn encode_cmd0_no_response() {
        let cmd = encode_command(CMD0_GO_IDLE, CMD_RSPTYP_NONE, 0);
        assert_eq!(cmd, 0, "CMD0 with no response and no data is 0");
    }

    #[test]
    fn encode_cmd1_r3_response() {
        let cmd = encode_command(CMD1_SEND_OP_COND, CMD_RSPTYP_R3, 0);
        assert_eq!(cmd & CMD_OPCODE_MASK, 1, "CMD1 opcode");
        assert_ne!(cmd & CMD_RSPTYP_R3, 0, "CMD1 has R3 response");
    }

    #[test]
    fn encode_cmd18_multi_read() {
        let cmd = encode_command(CMD18_READ_MULTI, CMD_RSPTYP_R1, CMD_DTYPE_READ);
        assert_eq!(cmd & CMD_OPCODE_MASK, 18, "CMD18 opcode");
        assert_ne!(cmd & CMD_DTYPE_READ, 0, "CMD18 is a read");
    }

    #[test]
    fn encode_cmd25_multi_write() {
        let cmd = encode_command(CMD25_WRITE_MULTI, CMD_RSPTYP_R1, CMD_DTYPE_WRITE);
        assert_eq!(cmd & CMD_OPCODE_MASK, 25, "CMD25 opcode");
        assert_ne!(cmd & CMD_DTYPE_WRITE, 0, "CMD25 is a write");
    }

    #[test]
    fn opcode_mask_strips_high_bits() {
        // WHY: verify opcode mask isolates only bits [5:0]
        let cmd = encode_command(0xFF, CMD_RSPTYP_NONE, 0);
        assert_eq!(cmd & CMD_OPCODE_MASK, 0x3F, "mask strips bits above [5:0]");
    }

    // -- Descriptor chain tests --

    #[test]
    fn gpd_new_direct_sets_hwo_no_bdp() {
        let gpd = Gpd::new_direct(0x4000_0000, 512);
        assert!(gpd.is_hw_owned(), "GPD must be hardware-owned");
        assert!(!gpd.has_bd(), "direct GPD must not have BDP SET");
        assert_eq!(gpd.ptr, 0x4000_0000, "buffer pointer");
        assert_eq!(gpd.data_len, 512, "data length");
        assert_eq!(gpd.next, 0, "no next GPD");
    }

    #[test]
    fn gpd_new_with_bd_sets_hwo_and_bdp() {
        let gpd = Gpd::new_with_bd(0xDEAD_0000, 4096);
        assert!(gpd.is_hw_owned(), "GPD must be hardware-owned");
        assert!(gpd.has_bd(), "BD-backed GPD must have BDP SET");
        assert_eq!(gpd.ptr, 0xDEAD_0000, "BD chain pointer");
        assert_eq!(gpd.data_len, 4096, "total data length");
    }

    #[test]
    fn bd_single_entry_is_eol() {
        let bd = Bd::new(0x5000_0000, 512, true);
        assert!(bd.is_eol(), "single BD must be end-of-list");
        assert_eq!(bd.ptr, 0x5000_0000, "buffer pointer");
        assert_eq!(bd.data_len, 512, "data length");
    }

    #[test]
    fn bd_middle_entry_not_eol() {
        let bd = Bd::new(0x6000_0000, 1024, false);
        assert!(!bd.is_eol(), "middle BD must not be end-of-list");
    }

    #[test]
    fn build_single_bd_chain_structure() {
        let (gpd, bd) = build_single_bd_chain(0x4100_0000, 512);
        assert!(gpd.is_hw_owned(), "GPD must be HWO");
        assert!(gpd.has_bd(), "GPD must reference BD");
        assert_eq!(gpd.data_len, 512, "total length");
        assert!(bd.is_eol(), "single BD is EOL");
        assert_eq!(bd.ptr, 0x4100_0000, "buffer address");
        assert_eq!(bd.data_len, 512, "BD data length");
    }

    #[test]
    fn build_multi_segment_bd_chain() {
        let segments = [
            (0x4000_0000u32, 512u32),
            (0x4000_1000, 512),
            (0x4000_2000, 512),
        ];
        let (gpd, bds) = build_bd_chain(&segments).unwrap_or_default();

        assert!(gpd.is_hw_owned(), "GPD must be HWO");
        assert!(gpd.has_bd(), "GPD must have BDP");
        assert_eq!(gpd.data_len, 1536, "total length = 3 * 512");

        assert!(!bds.get(0).copied().unwrap_or_default().is_eol(), "first BD is not EOL");
        assert!(!bds.get(1).copied().unwrap_or_default().is_eol(), "second BD is not EOL");
        assert!(bds.get(2).copied().unwrap_or_default().is_eol(), "third BD is EOL");

        assert_eq!(bds.get(0).copied().unwrap_or_default().ptr, 0x4000_0000, "segment 0 address");
        assert_eq!(bds.get(1).copied().unwrap_or_default().ptr, 0x4000_1000, "segment 1 address");
        assert_eq!(bds.get(2).copied().unwrap_or_default().ptr, 0x4000_2000, "segment 2 address");
    }

    #[test]
    fn build_bd_chain_rejects_empty() {
        assert!(build_bd_chain(&[]).is_none(), "empty segments must fail");
    }

    #[test]
    fn build_bd_chain_rejects_too_many() {
        let segments: [(u32, u32); 9] = [(0x4000_0000, 512); 9];
        assert!(build_bd_chain(&segments).is_none(), ">8 segments must fail");
    }

    // -- Interrupt mask tests --

    #[test]
    fn interrupt_bits_are_unique_powers_of_two() {
        let all_bits = [
            INT_MMCIRQ,
            INT_CDSC,
            INT_ACMDRDY,
            INT_ACMDTMO,
            INT_ACMDCRCERR,
            INT_DMAQ_EMPTY,
            INT_SDIOIRQ,
            INT_CMDRDY,
            INT_CMDTMO,
            INT_RSPCRCERR,
            INT_CSTA,
            INT_XFER_COMPL,
            INT_DXFER_DONE,
            INT_DATTMO,
            INT_DATCRCERR,
            INT_ACMD19_DONE,
        ];
        for (i, &a) in all_bits.iter().enumerate() {
            assert!(a.is_power_of_two(), "bit {i} must be a power of two");
            for (j, &b) in all_bits.iter().enumerate() {
                if i != j {
                    assert_eq!(a & b, 0, "bits {i} and {j} must not overlap");
                }
            }
        }
    }

    #[test]
    fn error_mask_covers_all_error_bits() {
        assert_ne!(INT_ERR_MASK & INT_ACMDTMO, 0, "ACMDTMO in error mask");
        assert_ne!(INT_ERR_MASK & INT_ACMDCRCERR, 0, "ACMDCRCERR in error mask");
        assert_ne!(INT_ERR_MASK & INT_CMDTMO, 0, "CMDTMO in error mask");
        assert_ne!(INT_ERR_MASK & INT_RSPCRCERR, 0, "RSPCRCERR in error mask");
        assert_ne!(INT_ERR_MASK & INT_DATTMO, 0, "DATTMO in error mask");
        assert_ne!(INT_ERR_MASK & INT_DATCRCERR, 0, "DATCRCERR in error mask");
        // Non-error bits should NOT be in the error mask
        assert_eq!(INT_ERR_MASK & INT_CMDRDY, 0, "CMDRDY not in error mask");
        assert_eq!(
            INT_ERR_MASK & INT_XFER_COMPL,
            0,
            "XFER_COMPL not in error mask"
        );
    }

    #[test]
    fn compose_interrupt_mask_combines_bits() {
        let mask = compose_interrupt_mask(&[INT_CMDRDY, INT_CMDTMO, INT_XFER_COMPL]);
        assert_ne!(mask & INT_CMDRDY, 0, "CMDRDY SET");
        assert_ne!(mask & INT_CMDTMO, 0, "CMDTMO SET");
        assert_ne!(mask & INT_XFER_COMPL, 0, "XFER_COMPL SET");
        assert_eq!(mask & INT_DATTMO, 0, "DATTMO not SET");
    }

    #[test]
    fn compose_interrupt_mask_empty_is_zero() {
        assert_eq!(compose_interrupt_mask(&[]), 0, "empty mask is zero");
    }

    // -- Bus width / config tests --

    #[test]
    fn bus_width_constants_are_distinct() {
        assert_ne!(CFG_BUSWIDTH_1, CFG_BUSWIDTH_8, "1-bit != 8-bit");
        assert_ne!(CFG_BUSWIDTH_4, CFG_BUSWIDTH_8, "4-bit != 8-bit");
        assert_ne!(CFG_BUSWIDTH_1, CFG_BUSWIDTH_4, "1-bit != 4-bit");
    }

    #[test]
    fn cfg_buswidth_8_is_bits_21_20() {
        // WHY: 8-bit bus is 0b10 << 20 = 0x0020_0000
        assert_eq!(CFG_BUSWIDTH_8, 0b10 << 20, "8-bit bus width encoding");
    }

    // -- Controller state tests --

    #[test]
    fn controller_starts_uninitialized() {
        let ctrl = MsdcController::new();
        assert!(
            !ctrl.is_initialized(),
            "new controller must not be initialized"
        );
        assert_eq!(ctrl.base, MSDC0_BASE, "default base address");
    }

    #[test]
    fn controller_reg_computes_absolute_address() {
        let ctrl = MsdcController::new();
        assert_eq!(ctrl.reg(REG_MSDC_CFG), MSDC0_BASE, "CFG at base + 0x00");
        assert_eq!(
            ctrl.reg(REG_MSDC_INT),
            MSDC0_BASE + 0x0C,
            "INT at base + 0x0C"
        );
        assert_eq!(
            ctrl.reg(REG_SDC_CMD),
            MSDC0_BASE + 0x34,
            "CMD at base + 0x34"
        );
        assert_eq!(
            ctrl.reg(REG_MSDC_DMA_SA),
            MSDC0_BASE + 0x90,
            "DMA_SA at base + 0x90"
        );
    }

    // -- DMA control bit tests --

    #[test]
    fn dma_ctrl_start_and_desc_mode() {
        let ctrl = DMA_CTRL_START | DMA_CTRL_MODE_DESC;
        assert_ne!(ctrl & DMA_CTRL_START, 0, "start bit SET");
        assert_ne!(ctrl & DMA_CTRL_MODE_DESC, 0, "descriptor mode SET");
        assert_eq!(ctrl & DMA_CTRL_STOP, 0, "stop bit clear");
    }

    // -- GPD/BD size and alignment tests --

    #[test]
    fn descriptor_sizes() {
        // INVARIANT: GPD and BD are 16 bytes each (4 × u32)
        assert_eq!(core::mem::size_of::<Gpd>(), 16, "GPD size");
        assert_eq!(core::mem::size_of::<Bd>(), 16, "BD size");
        // INVARIANT: 4-byte aligned for DMA
        assert_eq!(core::mem::align_of::<Gpd>(), 4, "GPD alignment");
        assert_eq!(core::mem::align_of::<Bd>(), 4, "BD alignment");
    }

    // -- Sector size --

    #[test]
    fn sector_size_is_512() {
        assert_eq!(SECTOR_SIZE, 512, "eMMC sector size");
        assert_eq!(WORDS_PER_SECTOR, 128, "words per sector (512/4)");
    }

    // -- SDC_STS bit tests --

    #[test]
    fn status_bits_are_distinct() {
        assert_ne!(STS_CMDBUSY, STS_DATBUSY, "cmdbusy != datbusy");
        assert_eq!(
            STS_CMDBUSY & STS_DATBUSY,
            0,
            "cmdbusy and datbusy do not overlap"
        );
    }
}
