//! eMMC block device driver for MT6739 MSDC controller.
//!
//! Implements PIO and DMA transfer paths for eMMC 5.1 on the `MediaTek` MSDC
//! (`MultiSlot` Data Controller). Register offsets and interrupt definitions
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

// WHY: only the MMIO controller touches these registers, and it is absent on
// the virt board (no MSDC peripheral) -- see the gate on MsdcController.
#[cfg(not(feature = "qemu"))]
use crate::mmio;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// MSDC0 base address on the MT6739.
// NOTE: FROM device registry, `crates/thumos/src/device.rs:127`
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
#[expect(dead_code, reason = "reserved for future status readback (#753)")]
const REG_SDC_CSTS: usize = 0x58;

/// Data CRC status per DAT line.
#[expect(dead_code, reason = "reserved for future CRC diagnostics (#753)")]
const REG_SDC_DCRC_STS: usize = 0x60;

/// Advanced config 0.
#[expect(dead_code, reason = "reserved for future tuning (#753)")]
const REG_SDC_ADV_CFG0: usize = 0x64;

/// eMMC config 0: boot mode, part access.
// WHY cfg_attr(not(test)): a regression test asserts this offset/value
// against the datasheet, so it is used under the host test build; on
// armv7a nothing outside tests reads it, and the expectation lives
// exactly there so it stays fulfilled in both configurations.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "reserved for boot mode configuration (#753)")
)]
const REG_EMMC_CFG0: usize = 0x70;

/// eMMC config 1.
// WHY cfg_attr(not(test)): see REG_EMMC_CFG0 above -- same reasoning.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "reserved for boot mode configuration (#753)")
)]
const REG_EMMC_CFG1: usize = 0x74;

/// eMMC status: boot ack.
// WHY cfg_attr(not(test)): see REG_EMMC_CFG0 above -- same reasoning.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "reserved for boot status readback (#753)")
)]
const REG_EMMC_STS: usize = 0x78;

/// eMMC I/O control.
// WHY cfg_attr(not(test)): see REG_EMMC_CFG0 above -- same reasoning.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "reserved for eMMC I/O tuning (#753)")
)]
const REG_EMMC_IOCON: usize = 0x7C;

/// DMA start address [35:32] (4 MSB).
// WHY cfg_attr(not(test)): see REG_EMMC_CFG0 above -- same reasoning.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "MT6739 is 32-bit; high bits unused (#753)")
)]
const REG_MSDC_DMA_SA_HIGH: usize = 0x8C;

/// DMA start address [31:0].
const REG_MSDC_DMA_SA: usize = 0x90;

/// DMA current address.
// WHY cfg_attr(not(test)): see REG_EMMC_CFG0 above -- same reasoning.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "reserved for DMA progress monitoring (#753)")
)]
const REG_MSDC_DMA_CA: usize = 0x94;

/// DMA control: start, stop, mode.
const REG_MSDC_DMA_CTRL: usize = 0x98;

/// DMA config: burst length.
const REG_MSDC_DMA_CFG: usize = 0x9C;

/// DMA transfer length.
// WHY cfg_attr(not(test)): see REG_EMMC_CFG0 above -- same reasoning.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "length encoded in GPD/BD descriptors (#753)")
)]
const REG_MSDC_DMA_LEN: usize = 0xA8;

/// Patch register 0 (tuning overrides).
#[expect(dead_code, reason = "reserved for auto-tuning (#753)")]
const REG_MSDC_PATCH_BIT0: usize = 0xB0;

/// Version register.
// WHY cfg_attr(not(test)): see REG_EMMC_CFG0 above -- same reasoning.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "reserved for version readback (#753)")
)]
const REG_MSDC_VERSION: usize = 0x114;

// NOTE: source `drivers/mmc/host/mediatek/ComboA/msdc_reg.h:75–221`

/// Inline AES encryption SELECT.
// WHY cfg_attr(not(test)): see REG_EMMC_CFG0 above -- same reasoning.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "reserved for encrypted storage layer (#753)")
)]
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
// WHY cfg_attr(not(test)): see REG_EMMC_CFG0 above -- same reasoning.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "eMMC uses 8-bit; kept for SD card support (#753)")
)]
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
#[expect(dead_code, reason = "reserved for CID/CSD readback (#753)")]
const CMD_RSPTYP_R2: u32 = 0b10 << 7;

/// Response type: R3/R4 (48-bit, no CRC).
const CMD_RSPTYP_R3: u32 = 0b11 << 7;

/// Data transfer direction: read (device → host).
const CMD_DTYPE_READ: u32 = 0b01 << 11;

/// Data transfer direction: write (host → device).
const CMD_DTYPE_WRITE: u32 = 0b10 << 11;

/// Block length shift for `SDC_CMD` (bits [31:16] in some configs).
#[expect(dead_code, reason = "block length SET via SDC_CFG on MT6739 (#753)")]
const CMD_BLK_LEN_SHIFT: u32 = 16;

// ---------------------------------------------------------------------------
// MSDC_DMA_CTRL bit fields
// ---------------------------------------------------------------------------

/// Start DMA transfer.
const DMA_CTRL_START: u32 = 1 << 0;

/// Stop DMA transfer.
const DMA_CTRL_STOP: u32 = 1 << 1;

/// DMA mode: basic (single buffer).
#[expect(dead_code, reason = "descriptor mode used for scatter-gather (#753)")]
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

/// RX FIFO word-count field shift (bits [23:16] per the MT6739 MSDC
/// datasheet, as cited in issue #293).
///
/// WARNING: the exact bit position is taken from the issue's datasheet
/// citation, not independently re-derived against the BSP header. The
/// per-word poll is bounded by `POLL_TIMEOUT` so a wrong field position
/// degrades to a `DataTimeout` (safe), but must be verified before silicon.
/// TODO(#870)[deliberate-prudent]: confirm FIFOCS RXCNT field position against pinned MT6739 source; #293 only added the bounded poll.
const FIFOCS_RXCNT_SHIFT: u32 = 16;

/// RX FIFO word-count field mask (8 bits at [23:16]).
const FIFOCS_RXCNT_MASK: u32 = 0xFF << FIFOCS_RXCNT_SHIFT;

/// True if the `MSDC_FIFOCS` RX word count is nonzero, i.e. at least one word
/// is buffered and safe to read FROM `MSDC_RXDATA`.
///
/// WHY: `STS_DATBUSY` stays SET for the duration of an entire block transfer,
/// so it cannot signal per-word FIFO readiness during a PIO read; the RX
/// count field is the per-word-accurate signal (issue #293).
fn fifo_rx_ready(fifocs: u32) -> bool {
    fifocs & FIFOCS_RXCNT_MASK != 0
}

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

/// Classify an observed `MSDC_INT` status against [`INT_ERR_MASK`].
///
/// Returns the error `check_and_clear_completion` should raise (carrying
/// only the error bits) if `status` carries any [`INT_ERR_MASK`] bit, or
/// `None` if it does not.
///
/// WHY: extracted so `send_command`'s post-command error check (issue #622)
/// is host-testable without a live `MSDC_INT` register.
fn classify_interrupt_status(status: u32) -> Option<MsdcError> {
    let err_bits = status & INT_ERR_MASK;
    if err_bits != 0 {
        Some(MsdcError::InterruptError(err_bits))
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// eMMC command opcodes (MMC specification)
// ---------------------------------------------------------------------------

/// CMD0: `GO_IDLE_STATE`  -  reset card to idle.
const CMD0_GO_IDLE: u32 = 0;

/// CMD1: `SEND_OP_COND`  -  send operating conditions.
const CMD1_SEND_OP_COND: u32 = 1;

/// CMD2: `ALL_SEND_CID`  -  request card identification.
#[expect(dead_code, reason = "reserved for CID readback (#753)")]
const CMD2_ALL_SEND_CID: u32 = 2;

/// CMD3: `SET_RELATIVE_ADDR`  -  assign relative card address.
const CMD3_SET_RELATIVE_ADDR: u32 = 3;

/// CMD7: `SELECT_CARD`  -  SELECT card for data transfer.
const CMD7_SELECT_CARD: u32 = 7;

/// CMD8: `SEND_EXT_CSD`  -  read extended CSD register.
#[expect(dead_code, reason = "reserved for EXT_CSD readback (#753)")]
const CMD8_SEND_EXT_CSD: u32 = 8;

/// CMD13: `SEND_STATUS`  -  read card status register.
#[expect(dead_code, reason = "reserved for status polling (#753)")]
const CMD13_SEND_STATUS: u32 = 13;

/// CMD16: `SET_BLOCKLEN`  -  SET block length to 512 bytes.
const CMD16_SET_BLOCKLEN: u32 = 16;

/// CMD17: `READ_SINGLE_BLOCK`.
const CMD17_READ_SINGLE: u32 = 17;

/// CMD18: `READ_MULTIPLE_BLOCK`.
const CMD18_READ_MULTI: u32 = 18;

/// CMD24: `WRITE_SINGLE_BLOCK`.
const CMD24_WRITE_SINGLE: u32 = 24;

/// CMD25: `WRITE_MULTIPLE_BLOCK`.
const CMD25_WRITE_MULTI: u32 = 25;

// ---------------------------------------------------------------------------
// OCR (CMD1 SEND_OP_COND response) bit fields
// ---------------------------------------------------------------------------

/// OCR "power-up status" bit (bit 31) in the CMD1 (`SEND_OP_COND`) R3
/// response. 0 while the card is still completing power-up, 1 once ready.
/// The eMMC spec requires CMD1 to be repeated until this bit is observed
/// set (issue #622).
const OCR_BUSY_BIT: u32 = 1 << 31;

/// Maximum CMD1 (`SEND_OP_COND`) attempts during init before giving up.
///
/// WHY: eMMC power-up on real hardware completes within a handful of
/// attempts; an absent/dead card fails fast through `send_command`'s own
/// `INT_ERR_MASK` check rather than exhausting this bound. Bounding it at
/// all is the point -- an unbounded spin degrades a dead card into a hang
/// with no diagnostic instead of a reported `CommandTimeout` (issue #622).
const CMD1_MAX_RETRIES: u32 = 1000;

/// True once the OCR "power-up status" bit (bit 31) reports the card ready.
///
/// WHY: extracted so `init`'s CMD1 retry termination condition is
/// host-testable without a live MSDC register (issue #622).
fn ocr_ready(ocr: u32) -> bool {
    ocr & OCR_BUSY_BIT != 0
}

/// Repeatedly invoke `attempt` (issuing CMD1 and reading its OCR response),
/// stopping as soon as it reports the OCR power-up status bit set.
///
/// A hardware error from `attempt` propagates immediately without
/// retrying -- a latched command/CRC error is a bus fault, not "still
/// powering up." Returns [`MsdcError::CommandTimeout`] once `max_attempts`
/// is exhausted with the card never reporting ready.
///
/// Generic over the CMD1 issuer so the eMMC spec's "repeat CMD1 until OCR
/// bit 31 is set" termination condition is host-testable without a live
/// MSDC register (issue #622).
fn poll_cmd1_ready<F>(mut attempt: F, max_attempts: u32) -> Result<(), MsdcError>
where
    F: FnMut() -> Result<u32, MsdcError>,
{
    for _ in 0..max_attempts {
        if ocr_ready(attempt()?) {
            return Ok(());
        }
    }
    Err(MsdcError::CommandTimeout)
}

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
#[derive(Debug, Clone, Copy, Default)]
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
#[derive(Debug, Clone, Copy, Default)]
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
// MsdcOps — hardware abstraction trait (#631)
// ---------------------------------------------------------------------------

/// Hardware operations trait for MSDC/eMMC abstraction.
///
/// Extracts the four operations `crate::block::MsdcBlockDevice` and
/// `crate::block::MsdcBlockDeviceUninit` drive against the controller --
/// `init`, `read_sector`, `write_sector`, `is_initialized` -- so their
/// wrapper logic (bounds checking, the `u32` LBA narrowing, buffer-length
/// validation, and the #619 typestate transition) compiles and runs off
/// hardware. Same seam as `fm_radio::FmHwOps` (#518),
/// `audio_codec::AudioCodecOps` (#399), and `wifi::WifiHwOps`.
pub(crate) trait MsdcOps {
    /// Initialize the controller for eMMC operation.
    ///
    /// # Safety
    ///
    /// Must be called exactly once after power-on. The MSDC register block
    /// must be mapped and accessible.
    ///
    /// # Errors
    ///
    /// Returns an [`MsdcError`] if hardware initialization fails.
    unsafe fn init(&mut self) -> Result<(), MsdcError>;

    /// Read a single 512-byte sector at `lba`.
    ///
    /// # Safety
    ///
    /// The controller must be initialized.
    ///
    /// # Errors
    ///
    /// Returns an [`MsdcError`] on command/data-transfer failure.
    unsafe fn read_sector(&self, lba: u32, buf: &mut [u8; SECTOR_SIZE]) -> Result<(), MsdcError>;

    /// Write a single 512-byte sector at `lba`.
    ///
    /// # Safety
    ///
    /// The controller must be initialized.
    ///
    /// # Errors
    ///
    /// Returns an [`MsdcError`] on command/data-transfer failure.
    unsafe fn write_sector(&self, lba: u32, buf: &[u8; SECTOR_SIZE]) -> Result<(), MsdcError>;

    /// Whether the controller has completed initialization.
    fn is_initialized(&self) -> bool;
}

// ---------------------------------------------------------------------------
// MsdcController
// ---------------------------------------------------------------------------

/// MSDC controller driver for eMMC block I/O.
///
/// Provides PIO and DMA transfer paths for 512-byte sector operations.
/// The controller must be initialized via [`MsdcController::init`] before
/// any read/write operations.
// WHY (#631): the MMIO controller reads `board::MSDC0_BASE`, which only the
// m7 board declares -- the virt board QEMU runs has no MSDC peripheral at all.
// Gate on the qemu feature ALONE, not on `test`: a host test build selects the
// m7 board, so MSDC0_BASE resolves there and this type's own tests need it.
#[cfg(not(feature = "qemu"))]
pub(crate) struct MsdcController {
    /// MMIO base address of the MSDC controller.
    base: usize,
    /// Whether the controller has been initialized.
    initialized: bool,
}

/// Store a 32-bit little-endian word into a sector buffer at word index `i`.
///
/// Byte-level store rather than a `*mut u32` cast, because a `&mut [u8;
/// SECTOR_SIZE]` carries no alignment guarantee (see `read_sector`'s call
/// site) -- this is correct for any buffer alignment, unlike a typed
/// pointer write.
#[cfg(not(feature = "qemu"))]
#[inline]
fn store_word_le(buf: &mut [u8; SECTOR_SIZE], i: usize, word: u32) {
    buf[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
}

/// Load a 32-bit little-endian word from a sector buffer at word index `i`.
/// See [`store_word_le`].
#[cfg(not(feature = "qemu"))]
#[inline]
fn load_word_le(buf: &[u8; SECTOR_SIZE], i: usize) -> u32 {
    let mut word_bytes = [0u8; 4];
    word_bytes.copy_from_slice(&buf[i * 4..i * 4 + 4]);
    u32::from_le_bytes(word_bytes)
}

#[cfg(not(feature = "qemu"))]
impl MsdcController {
    /// Create a new controller handle at the default MSDC0 base address.
    pub(crate) fn new() -> Self {
        Self {
            base: crate::board::MSDC0_BASE,
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
    #[inline]
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
    /// Returns [`MsdcError::CommandTimeout`] if any init command's busy-wait
    /// never clears, or if the card never reports OCR ready within the CMD1
    /// retry bound. Returns [`MsdcError::InterruptError`] if any init
    /// command latches a card-side failure in `MSDC_INT`.
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

        // CMD1: SEND_OP_COND (R3 response, no CRC). Argument: sector
        // addressing (bit 30), voltage window 0xFF8000. The eMMC spec
        // requires repeating CMD1 until the card reports the OCR power-up
        // status bit (bit 31) set -- a card still powering up leaves it
        // clear, and proceeding to CMD3 against a not-ready card corrupts
        // the rest of the sequence (issue #622).
        poll_cmd1_ready(
            || {
                // SAFETY: controller is powered and register block is mapped per caller contract.
                unsafe { self.send_command(CMD1_SEND_OP_COND, 0x40FF_8000, CMD_RSPTYP_R3)? };
                // SAFETY: valid immediately after a successful R3-response command.
                Ok(unsafe { self.read_response() })
            },
            CMD1_MAX_RETRIES,
        )?;

        // CMD3: SET_RELATIVE_ADDR (R1 response)
        // Assign RCA = 1
        // SAFETY: controller is powered and register block is mapped per caller contract.
        unsafe { self.send_command(CMD3_SET_RELATIVE_ADDR, 0x0001_0000, CMD_RSPTYP_R1)? };

        // CMD7: SELECT_CARD (R1 response)
        // SAFETY: controller is powered and register block is mapped per caller contract.
        unsafe { self.send_command(CMD7_SELECT_CARD, 0x0001_0000, CMD_RSPTYP_R1)? };

        // CMD16: SET_BLOCKLEN to 512 bytes
        // SAFETY: controller is powered and register block is mapped per caller contract.
        let Ok(blocklen) = u32::try_from(SECTOR_SIZE) else {
            return Err(MsdcError::CommandTimeout);
        };
        // SAFETY: controller is powered and register block is mapped per caller contract.
        unsafe { self.send_command(CMD16_SET_BLOCKLEN, blocklen, CMD_RSPTYP_R1)? };

        // STEP 7: Clear every interrupt bit latched during init (e.g.
        // INT_CDSC from clock/voltage settling, or per-command INT_CMDRDY)
        // so none of them survive to be misread as an error by the first
        // post-init check_and_clear_completion call (issue #622).
        // SAFETY: MSDC_INT is a valid MMIO register at offset 0x0C within the MSDC0 address space. Volatile access is required for hardware registers.
        unsafe { self.clear_interrupts(0xFFFF_FFFF) };

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
    /// become idle within the poll timeout. Returns
    /// [`MsdcError::InterruptError`] if the command phase ends with a
    /// card-side failure (timeout or response CRC error) latched in
    /// `MSDC_INT`.
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

        // Wait for the command phase to end. The engine clears CMDBUSY when
        // the phase ends for ANY reason -- success, a card-side timeout
        // (INT_CMDTMO), or a response CRC failure (INT_RSPCRCERR) -- so
        // CMDBUSY alone cannot distinguish a failed command from a
        // completed one (issue #622).
        // SAFETY: SDC_STS is a valid MMIO register at offset 0x3C within the MSDC0 address space. Volatile access is required for hardware registers.
        if !unsafe { mmio::wait_bits_clear(self.reg(REG_SDC_STS), STS_CMDBUSY, POLL_TIMEOUT) } {
            return Err(MsdcError::CommandTimeout);
        }

        // Inspect MSDC_INT for a latched card-side failure before reporting
        // success, reusing the same INT_ERR_MASK check the data-transfer
        // paths already run after DATBUSY clears (issue #286). INT_CMDRDY
        // is the command-phase completion bit cleared on the non-error path
        // (issue #622).
        // SAFETY: controller register block is mapped per caller contract.
        unsafe { self.check_and_clear_completion(INT_CMDRDY) }
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

        // PIO: read 128 words (512 bytes) FROM MSDC_RXDATA.
        //
        // INVARIANT: `buf` is a caller-supplied `&mut [u8; SECTOR_SIZE]` --
        // nothing in its type or this function's `# Safety` contract above
        // promises 4-byte alignment (a bare `[u8; N]` has `align_of` 1, and
        // both real callers -- `block.rs`'s slice-sourced `sector_buf` and
        // `gpt.rs`'s stack-local array -- pass buffers with no alignment
        // guarantee). Forming a `*mut u32` over it and dereferencing (as the
        // previous `buf_ptr.add(i).write_volatile(word)` form did) is
        // undefined behaviour whenever the address is not 4-byte aligned:
        // armv7a data-aborts on the misaligned access, while the i686 host
        // build this was linted on tolerates it silently -- see
        // `page.rs`'s `AlignedBuf` comment for the same class caught once
        // already via a CI SIGABRT. Storing each word byte-by-byte is
        // correct for any alignment and, as a byte-swap-free bonus, makes
        // the wire order (little-endian, matching every target this crate
        // builds for) explicit rather than implicit in `write_volatile`'s
        // native-endian store.
        for i in 0..WORDS_PER_SECTOR {
            // Poll the RX FIFO word count until at least one word is
            // buffered, instead of STS_DATBUSY (which cannot signal
            // per-word readiness -- see fifo_rx_ready, issue #293).
            let mut ready = false;
            for _ in 0..POLL_TIMEOUT {
                // SAFETY: MSDC_FIFOCS is a valid MMIO register at offset 0x14 within the MSDC0 address space. Volatile access is required for hardware registers.
                let fifocs = unsafe { self.read_reg(REG_MSDC_FIFOCS) };
                if fifo_rx_ready(fifocs) {
                    ready = true;
                    break;
                }
            }
            if !ready {
                return Err(MsdcError::DataTimeout);
            }
            // SAFETY: MSDC_RXDATA is a valid MMIO register at offset 0x1C within the MSDC0 address space. Volatile access is required for hardware registers.
            let word = unsafe { self.read_reg(REG_MSDC_RXDATA) };
            store_word_le(buf, i, word);
        }

        // Wait for transfer complete
        // SAFETY: SDC_STS is a valid MMIO register at offset 0x3C within the MSDC0 address space. Volatile access is required for hardware registers.
        if !unsafe { mmio::wait_bits_clear(self.reg(REG_SDC_STS), STS_DATBUSY, POLL_TIMEOUT) } {
            return Err(MsdcError::DataTimeout);
        }

        // Check INT_ERR_MASK before clearing completion so a hardware error
        // (e.g. INT_DATCRCERR) coinciding with INT_XFER_COMPL is not
        // silently discarded (issue #286).
        // SAFETY: controller register block is mapped per caller contract.
        unsafe { self.check_and_clear_completion(INT_XFER_COMPL) }
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

        // PIO: write 128 words (512 bytes) to MSDC_TXDATA.
        //
        // INVARIANT: `buf` carries the same no-alignment-guarantee as
        // `read_sector`'s `buf` above -- see that comment. Read each word's
        // bytes explicitly rather than forming a `*const u32` over `buf`.
        for i in 0..WORDS_PER_SECTOR {
            let word = load_word_le(buf, i);
            // SAFETY: MSDC_TXDATA is a valid MMIO register at offset 0x18 within the MSDC0 address space. Volatile access is required for hardware registers.
            unsafe { self.write_reg(REG_MSDC_TXDATA, word) };
        }

        // Wait for transfer complete
        // SAFETY: SDC_STS is a valid MMIO register at offset 0x3C within the MSDC0 address space. Volatile access is required for hardware registers.
        if !unsafe { mmio::wait_bits_clear(self.reg(REG_SDC_STS), STS_DATBUSY, POLL_TIMEOUT) } {
            return Err(MsdcError::DataTimeout);
        }

        // Check INT_ERR_MASK before clearing completion so a hardware error
        // coinciding with INT_XFER_COMPL is not silently discarded (issue #286).
        // SAFETY: controller register block is mapped per caller contract.
        unsafe { self.check_and_clear_completion(INT_XFER_COMPL) }
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

        // Check INT_ERR_MASK before clearing completion so a hardware error
        // coinciding with INT_XFER_COMPL/INT_DXFER_DONE is not silently
        // discarded (issue #286).
        // SAFETY: controller register block is mapped per caller contract.
        unsafe { self.check_and_clear_completion(INT_XFER_COMPL | INT_DXFER_DONE) }
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

        // Check INT_ERR_MASK before clearing completion so a hardware error
        // coinciding with INT_XFER_COMPL/INT_DXFER_DONE is not silently
        // discarded (issue #286).
        // SAFETY: controller register block is mapped per caller contract.
        unsafe { self.check_and_clear_completion(INT_XFER_COMPL | INT_DXFER_DONE) }
    }

    /// Read the 32-bit response FROM `SDC_RESP0`.
    ///
    /// # Safety
    ///
    /// Only valid after a successful command with a non-empty response type.
    pub(crate) unsafe fn read_response(&self) -> u32 {
        // SAFETY: SDC_RESP0 is a valid MMIO register at offset 0x40 within the MSDC0 address space. Volatile access is required for hardware registers.
        unsafe { self.read_reg(REG_SDC_RESP0) }
    }

    /// Read the full 128-bit response FROM `SDC_RESP0–3`.
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

    /// Check for hardware error interrupts before clearing a transfer's
    /// completion bits.
    ///
    /// Reads `MSDC_INT`; if any bit in [`INT_ERR_MASK`] is set, clears every
    /// observed bit (`MSDC_INT` is write-1-to-clear) and returns
    /// [`MsdcError::InterruptError`] carrying the error bits. Otherwise
    /// clears only `completion_bits` and returns `Ok(())`.
    ///
    /// WHY: clearing a completion bit (e.g. `INT_XFER_COMPL`) without first
    /// inspecting `INT_ERR_MASK` silently discards a hardware error that
    /// coincided with completion (issue #286).
    ///
    /// # Safety
    ///
    /// The controller register block must be mapped.
    unsafe fn check_and_clear_completion(&self, completion_bits: u32) -> Result<(), MsdcError> {
        // SAFETY: MSDC_INT is a valid MMIO register at offset 0x0C within the MSDC0 address space. Volatile access is required for hardware registers.
        let status = unsafe { self.interrupt_status() };
        if let Some(err) = classify_interrupt_status(status) {
            // SAFETY: MSDC_INT is write-1-to-clear; writing the full observed status clears every pending bit, including the error bits just inspected.
            unsafe { self.clear_interrupts(status) };
            return Err(err);
        }
        // SAFETY: MSDC_INT is a valid MMIO register at offset 0x0C within the MSDC0 address space. Volatile access is required for hardware registers.
        unsafe { self.clear_interrupts(completion_bits) };
        Ok(())
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

/// The real controller's [`MsdcOps`] conformance is hardware-only (#631) --
/// the same `FmHw`/`NullFmHw` split as #518: off hardware, `FakeMsdc` stands
/// in so `crate::block::MsdcBlockDevice` has something to run against.
/// `MsdcController` itself stays available on every target (its
/// register-arithmetic and command-encoding helpers are host-tested
/// directly, below); it just cannot serve as an [`MsdcOps`] off hardware.
#[cfg(not(any(test, feature = "qemu")))]
impl MsdcOps for MsdcController {
    unsafe fn init(&mut self) -> Result<(), MsdcError> {
        // SAFETY: forwarded verbatim to the inherent `init`, whose contract
        // this trait method mirrors exactly.
        unsafe { MsdcController::init(self) }
    }

    unsafe fn read_sector(&self, lba: u32, buf: &mut [u8; SECTOR_SIZE]) -> Result<(), MsdcError> {
        // SAFETY: forwarded verbatim to the inherent `read_sector`.
        unsafe { MsdcController::read_sector(self, lba, buf) }
    }

    unsafe fn write_sector(&self, lba: u32, buf: &[u8; SECTOR_SIZE]) -> Result<(), MsdcError> {
        // SAFETY: forwarded verbatim to the inherent `write_sector`.
        unsafe { MsdcController::write_sector(self, lba, buf) }
    }

    fn is_initialized(&self) -> bool {
        MsdcController::is_initialized(self)
    }
}

/// `MsdcController::new()` performs no MMIO (it only stores the base address
/// and clears `initialized`), so `Default` is available on every target --
/// `crate::block::MsdcBlockDeviceUninit::new` calls it through [`BootMsdc`]
/// without needing to know which concrete controller that resolves to.
#[cfg(not(feature = "qemu"))]
impl Default for MsdcController {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// FakeMsdc — test/qemu MSDC stand-in (#631)
// ---------------------------------------------------------------------------

/// A fake MSDC backend for host tests and qemu (#631). The real
/// `MsdcController` dereferences MSDC0 at a fixed physical address
/// (`0x1123_0000`); off hardware that address is unmapped, so touching it
/// would data-abort (target) or segfault (host test binary). `FakeMsdc`
/// tracks init state in ordinary memory instead. Every operation succeeds by
/// default, so `FakeMsdc` also serves as the deterministic `qemu` stand-in
/// ([`BootMsdc`]) with no failure injection configured; `force_init_failure`
/// and `fail_at_sector` opt individual tests into the error paths
/// `crate::block::MsdcBlockDevice`'s wrapper must handle.
#[cfg(any(test, feature = "qemu"))]
#[derive(Default)]
pub(crate) struct FakeMsdc {
    initialized: bool,
    /// When set, the next `init()` call fails with this error instead of
    /// succeeding.
    pub(crate) force_init_failure: Option<MsdcError>,
    /// LBA at which `read_sector`/`write_sector` fail with
    /// [`MsdcError::DataTimeout`]. `None` means every sector succeeds.
    pub(crate) fail_at_sector: Option<u32>,
}

#[cfg(any(test, feature = "qemu"))]
impl FakeMsdc {
    /// A fake that initializes and transfers every sector successfully.
    pub(crate) fn new() -> Self {
        Self::default()
    }
}

#[cfg(any(test, feature = "qemu"))]
impl MsdcOps for FakeMsdc {
    unsafe fn init(&mut self) -> Result<(), MsdcError> {
        if let Some(err) = self.force_init_failure {
            return Err(err);
        }
        self.initialized = true;
        Ok(())
    }

    unsafe fn read_sector(&self, lba: u32, buf: &mut [u8; SECTOR_SIZE]) -> Result<(), MsdcError> {
        if self.fail_at_sector == Some(lba) {
            return Err(MsdcError::DataTimeout);
        }
        buf.fill(0);
        Ok(())
    }

    unsafe fn write_sector(&self, lba: u32, _buf: &[u8; SECTOR_SIZE]) -> Result<(), MsdcError> {
        if self.fail_at_sector == Some(lba) {
            return Err(MsdcError::DataTimeout);
        }
        Ok(())
    }

    fn is_initialized(&self) -> bool {
        self.initialized
    }
}

/// The MSDC backend the booted kernel wires into
/// `crate::block::MsdcBlockDeviceUninit` (#631): `FakeMsdc` under qemu/test
/// (no MSDC model on `-machine virt`), the real `MsdcController` on device.
#[cfg(any(test, feature = "qemu"))]
pub(crate) type BootMsdc = FakeMsdc;
#[cfg(not(any(test, feature = "qemu")))]
pub(crate) type BootMsdc = MsdcController;

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

/// Build a multi-segment BD chain FROM an array of (`phys_addr`, len) pairs.
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

#[cfg(all(test, not(feature = "qemu")))]
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
        let (gpd, bds) = build_bd_chain(&segments)
            .expect("build_bd_chain must succeed for 3 valid (1..=8) segments");

        assert!(gpd.is_hw_owned(), "GPD must be HWO");
        assert!(gpd.has_bd(), "GPD must have BDP");
        assert_eq!(gpd.data_len, 1536, "total length = 3 * 512");

        assert!(
            !bds.first().copied().unwrap_or_default().is_eol(),
            "first BD is not EOL"
        );
        assert!(
            !bds.get(1).copied().unwrap_or_default().is_eol(),
            "second BD is not EOL"
        );
        assert!(
            bds.get(2).copied().unwrap_or_default().is_eol(),
            "third BD is EOL"
        );

        assert_eq!(
            bds.first().copied().unwrap_or_default().ptr,
            0x4000_0000,
            "segment 0 address"
        );
        assert_eq!(
            bds.get(1).copied().unwrap_or_default().ptr,
            0x4000_1000,
            "segment 1 address"
        );
        assert_eq!(
            bds.get(2).copied().unwrap_or_default().ptr,
            0x4000_2000,
            "segment 2 address"
        );
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
        assert_eq!(ctrl.base, crate::board::MSDC0_BASE, "default base address");
    }

    #[test]
    fn controller_reg_computes_absolute_address() {
        let ctrl = MsdcController::new();
        assert_eq!(
            ctrl.reg(REG_MSDC_CFG),
            crate::board::MSDC0_BASE,
            "CFG at base + 0x00"
        );
        assert_eq!(
            ctrl.reg(REG_MSDC_INT),
            crate::board::MSDC0_BASE + 0x0C,
            "INT at base + 0x0C"
        );
        assert_eq!(
            ctrl.reg(REG_SDC_CMD),
            crate::board::MSDC0_BASE + 0x34,
            "CMD at base + 0x34"
        );
        assert_eq!(
            ctrl.reg(REG_MSDC_DMA_SA),
            crate::board::MSDC0_BASE + 0x90,
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

    #[test]
    fn sector_word_roundtrip_is_correct_and_alignment_independent() {
        // `read_sector`/`write_sector` move PIO data through `store_word_le`/
        // `load_word_le` (byte-by-byte) rather than reinterpreting `buf` as
        // `*mut/const u32`, because a `&[u8; SECTOR_SIZE]` carries no
        // alignment guarantee -- real callers slice one out of a larger
        // buffer (`block.rs`) or place it on the stack (`gpt.rs`), neither of
        // which promises 4-byte alignment. Confirm the byte-level round trip
        // is correct regardless of where the backing array actually lands,
        // by deliberately misaligning it.
        //
        // WHY the offset is derived from the runtime address rather than a
        // fixed constant: `[u8; N]` has `align_of` 1, so the compiler is
        // free to place the backing array at any address. A FIXED pad only
        // shifts alignment relative to a base whose residue is unknown, so
        // it can land back on a 4-byte boundary depending on that residue
        // (a constant 1-byte pad is misaligning only when `base % 4 != 3`)
        // -- silently passing while exercising nothing, the opposite of
        // this test's purpose. `off` is chosen from the OBSERVED
        // `base % 4` so the result is never 0 for any base: off=1 covers
        // residues 0/1/2 (giving 1/2/3), and residue 3 alone needs off=2
        // (giving 1), since off=1 there reproduces the boundary case above.
        let mut backing = [0u8; SECTOR_SIZE + 4];
        let base = backing.as_ptr() as usize;
        let off = if base % 4 == 3 { 2 } else { 1 };
        let Ok(sector) = <&mut [u8; SECTOR_SIZE]>::try_from(&mut backing[off..off + SECTOR_SIZE])
        else {
            unreachable!("[off..off + SECTOR_SIZE] fits within backing for off in 1..=2")
        };
        assert_ne!(
            sector.as_ptr() as usize % 4,
            0,
            "test setup must actually produce a misaligned buffer"
        );

        for i in 0..WORDS_PER_SECTOR {
            let word = 0xDEAD_0000u32.wrapping_add(i as u32);
            store_word_le(sector, i, word);
        }
        for i in 0..WORDS_PER_SECTOR {
            let expected = 0xDEAD_0000u32.wrapping_add(i as u32);
            assert_eq!(
                load_word_le(sector, i),
                expected,
                "word {i} did not round-trip"
            );
        }

        // Wire order is little-endian on every target this crate builds for.
        assert_eq!(&sector[0..4], &0xDEAD_0000u32.to_le_bytes());
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

    // -- MSDC_FIFOCS RX readiness (issue #293) --

    #[test]
    fn fifo_rx_ready_false_when_count_field_zero() {
        assert!(!fifo_rx_ready(0), "zero RX count must not be ready");
        assert!(
            !fifo_rx_ready(FIFOCS_CLR),
            "bits outside the RXCNT field must not signal readiness"
        );
    }

    #[test]
    fn fifo_rx_ready_true_when_count_field_nonzero() {
        assert!(
            fifo_rx_ready(1 << FIFOCS_RXCNT_SHIFT),
            "a single buffered word must signal readiness"
        );
        assert!(
            fifo_rx_ready(0xFF << FIFOCS_RXCNT_SHIFT),
            "a full RXCNT field must signal readiness"
        );
    }

    // -- MSDC_INT error classification (issue #622) --
    //
    // Without the fix, `send_command` never called anything that inspects
    // MSDC_INT, so a latched INT_CMDTMO/INT_RSPCRCERR was silently dropped
    // and the command reported Ok. These tests pin the extracted
    // classification `send_command` now relies on: any INT_ERR_MASK bit
    // becomes an InterruptError carrying only the error bits, and
    // non-error activity (including the command-phase completion bit
    // send_command clears on success) is not misclassified as failure.

    #[test]
    fn classify_interrupt_status_none_when_no_error_bits() {
        assert_eq!(
            classify_interrupt_status(0),
            None,
            "an empty status is not an error"
        );
        assert_eq!(
            classify_interrupt_status(INT_CMDRDY),
            None,
            "command-ready alone is not an error"
        );
    }

    #[test]
    fn classify_interrupt_status_reports_cmdtmo() {
        assert_eq!(
            classify_interrupt_status(INT_CMDTMO),
            Some(MsdcError::InterruptError(INT_CMDTMO)),
            "a latched command timeout must be reported, not swallowed"
        );
    }

    #[test]
    fn classify_interrupt_status_reports_rspcrcerr() {
        assert_eq!(
            classify_interrupt_status(INT_RSPCRCERR),
            Some(MsdcError::InterruptError(INT_RSPCRCERR)),
            "a latched response CRC error must be reported, not swallowed"
        );
    }

    #[test]
    fn classify_interrupt_status_masks_out_non_error_bits() {
        // WHY: CMDRDY can coincide with an error bit (issue #286's
        // pattern); the reported payload must carry only the error bits.
        let status = classify_interrupt_status(INT_CMDRDY | INT_CMDTMO);
        assert_eq!(
            status,
            Some(MsdcError::InterruptError(INT_CMDTMO)),
            "non-error bits must be masked out of the reported payload"
        );
    }

    // -- OCR power-up polling (issue #622) --
    //
    // Without the fix, `init` sent CMD1 exactly once and never read the
    // response, so a card still powering up (OCR bit 31 clear) let init
    // proceed to CMD3 against a not-ready card. These tests pin the
    // extracted retry logic `init` now runs.

    #[test]
    fn ocr_ready_false_when_busy_bit_clear() {
        assert!(!ocr_ready(0), "an all-zero OCR must not be ready");
        assert!(
            !ocr_ready(0x7FFF_FFFF),
            "every bit set except bit 31 must not be ready"
        );
    }

    #[test]
    fn ocr_ready_true_when_busy_bit_set() {
        assert!(ocr_ready(OCR_BUSY_BIT), "bit 31 alone must report ready");
        assert!(
            ocr_ready(0xFFFF_FFFF),
            "bit 31 among other set bits must report ready"
        );
    }

    #[test]
    fn poll_cmd1_ready_succeeds_immediately_when_first_response_ready() {
        let mut calls = 0u32;
        let result = poll_cmd1_ready(
            || {
                calls += 1;
                Ok(OCR_BUSY_BIT)
            },
            CMD1_MAX_RETRIES,
        );
        assert_eq!(result, Ok(()), "a ready response must succeed");
        assert_eq!(calls, 1, "must not retry once the card reports ready");
    }

    #[test]
    fn poll_cmd1_ready_retries_while_busy_then_succeeds() {
        // A card still completing power-up: two busy responses, then ready.
        let responses = [0u32, 0u32, OCR_BUSY_BIT];
        let mut i = 0usize;
        let result = poll_cmd1_ready(
            || {
                let r = responses[i];
                i += 1;
                Ok(r)
            },
            CMD1_MAX_RETRIES,
        );
        assert_eq!(result, Ok(()), "must succeed once the busy bit is set");
        assert_eq!(i, 3, "must stop polling as soon as the card is ready");
    }

    #[test]
    fn poll_cmd1_ready_bounded_retry_returns_command_timeout() {
        // A card that never leaves busy must not spin forever -- this is
        // the "unbounded spin is a hang" requirement from issue #622.
        let mut calls = 0u32;
        let result = poll_cmd1_ready(
            || {
                calls += 1;
                Ok(0u32)
            },
            5,
        );
        assert_eq!(
            result,
            Err(MsdcError::CommandTimeout),
            "exhausting the retry bound must report CommandTimeout"
        );
        assert_eq!(calls, 5, "must attempt exactly max_attempts times");
    }

    #[test]
    fn poll_cmd1_ready_propagates_hardware_error_without_retrying() {
        // A latched command/CRC error is a bus fault, not "still busy" --
        // it must not be retried through.
        let mut calls = 0u32;
        let result = poll_cmd1_ready(
            || {
                calls += 1;
                Err(MsdcError::InterruptError(INT_CMDTMO))
            },
            CMD1_MAX_RETRIES,
        );
        assert_eq!(
            result,
            Err(MsdcError::InterruptError(INT_CMDTMO)),
            "a hardware error must propagate as-is"
        );
        assert_eq!(calls, 1, "must not retry past a hardware error");
    }
}
