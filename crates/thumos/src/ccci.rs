//! CCCI (Cross-Core Communication Interface) kernel driver.
//!
//! Manages the AP↔modem link on the MT6739. The modem (MD 6293) is a separate
//! ARM core running opaque MediaTek firmware. This driver is the kernel boundary
//! between the trusted AP and the hostile modem — every byte from the modem is
//! untrusted.
//!
//! Two physical transports:
//! - **CLDMA** — ring-buffer DMA for data channels (network, audio, logging)
//! - **CCIF** — low-latency mailbox for control messages (24 channels, 512-byte SRAM)
//!
//! SECURITY: The MT6739 has no IOMMU. Validation at this boundary is the only
//! defense against modem-initiated attacks. All shared memory is treated as
//! untrusted input — data is copied out before processing to prevent TOCTOU.

use core::fmt;

use crate::mmio;

// ---------------------------------------------------------------------------
// CLDMA register constants
// ---------------------------------------------------------------------------

/// AP-side CLDMA register base.
/// Source: `eccci/mt6739/modem_reg_base.h:21–128`
const CLDMA_AP_BASE: usize = 0x200F_0000;

/// MD-side CLDMA register base (read-only from AP for debug).
/// Source: `eccci/mt6739/modem_reg_base.h:21–128`
#[cfg(test)]
const _CLDMA_MD_BASE: usize = 0x200E_0000;

/// MD boot vector enable register.
/// Source: `eccci/mt6739/modem_reg_base.h:21–128`
const MD_BOOT_VECTOR_EN: usize = 0x2000_0024;

/// MD global control 0; bit 12 = CLDMA enable.
/// Source: `eccci/mt6739/modem_reg_base.h:21–128`
const MD_GLOBAL_CON0: usize = 0x2000_0450;

/// MD boot status register 0.
/// Source: `eccci/mt6739/modem_reg_base.h:21–128`
const MD1_CFG_BOOT_STATS0: usize = 0x1020_E300;

/// MD boot status register 1.
/// Source: `eccci/mt6739/modem_reg_base.h:21–128`
const MD1_CFG_BOOT_STATS1: usize = 0x1020_E304;

// CLDMA AO (Always-On) register offsets — survive power-down.
// Source: `eccci/mt6739/cldma_reg.h:43–68`
mod cldma_ao {
    use super::CLDMA_AP_BASE;

    /// TX Q0 start address backup.
    pub(crate) const UL_START_ADDR_BK_0: usize = CLDMA_AP_BASE + 0x0004;
    /// TX current address backup.
    pub(crate) const UL_CURRENT_ADDR_BK_0: usize = CLDMA_AP_BASE + 0x0018;
    /// RX operation configuration.
    pub(crate) const SO_CFG: usize = CLDMA_AP_BASE + 0x0400;
    /// RX Q0 start address.
    pub(crate) const SO_START_ADDR_0: usize = CLDMA_AP_BASE + 0x0404;
    /// RX current RGPD address.
    pub(crate) const SO_CURRENT_ADDR_0: usize = CLDMA_AP_BASE + 0x0408;
    /// Maximum RX MTU.
    pub(crate) const DL_MTU_SIZE: usize = CLDMA_AP_BASE + 0x0418;
    /// L2 RX interrupt mask.
    pub(crate) const L2RIMR0: usize = CLDMA_AP_BASE + 0x0800;
    /// L2 RX interrupt mask clear.
    pub(crate) const L2RIMCR0: usize = CLDMA_AP_BASE + 0x0804;
    /// L2 RX interrupt mask set.
    pub(crate) const L2RIMSR0: usize = CLDMA_AP_BASE + 0x0808;
}

// CLDMA PD (Power-Domain) register offsets.
// Source: `eccci/mt6739/cldma_reg.h:69–133`
mod cldma_pd {
    // NOTE: PD base is populated from DT at probe time. In our bare-metal
    // driver we use the known MT6739 address CLDMA_AP_BASE + PD_OFFSET.
    // The PD block sits in the same CLDMA_AP register space.
    // Source: `eccci/mt6739/cldma_reg.h:69–133`

    /// PD base — TX/RX DMA control registers.
    /// On MT6739 the PD registers share the CLDMA_AP aperture.
    const PD_BASE: usize = super::CLDMA_AP_BASE;

    // TX (UL = uplink = AP→MD) registers
    /// TX Q0 start address.
    pub(crate) const UL_START_ADDR_0: usize = PD_BASE;
    /// TX Q0 current processing address.
    pub(crate) const UL_CURRENT_ADDR_0: usize = PD_BASE + 0x0014;
    /// UL SBDMA operation status.
    pub(crate) const UL_STATUS: usize = PD_BASE + 0x0028;
    /// Start TX DMA on a queue.
    pub(crate) const UL_START_CMD: usize = PD_BASE + 0x0030;
    /// Resume TX DMA after stall.
    pub(crate) const UL_RESUME_CMD: usize = PD_BASE + 0x0034;
    /// Stop TX DMA on a queue.
    pub(crate) const UL_STOP_CMD: usize = PD_BASE + 0x0038;
    /// TX error status.
    pub(crate) const UL_ERROR: usize = PD_BASE + 0x003C;
    /// TX operation configuration.
    pub(crate) const UL_CFG: usize = PD_BASE + 0x0040;

    // RX (SO = smart out = MD→AP) registers
    /// RX error status.
    pub(crate) const SO_ERROR: usize = PD_BASE + 0x0400;
    /// Start RX DMA.
    pub(crate) const SO_START_CMD: usize = PD_BASE + 0x0404;
    /// Resume RX DMA.
    pub(crate) const SO_RESUME_CMD: usize = PD_BASE + 0x0408;
    /// Stop RX DMA.
    pub(crate) const SO_STOP_CMD: usize = PD_BASE + 0x040C;

    // Interrupt registers
    /// L2 TX interrupt status & acknowledge.
    pub(crate) const L2TISAR0: usize = PD_BASE + 0x0800;
    /// L2 TX interrupt mask.
    pub(crate) const L2TIMR0: usize = PD_BASE + 0x0804;
    /// L2 TX interrupt mask clear.
    pub(crate) const L2TIMCR0: usize = PD_BASE + 0x0808;
    /// L2 TX interrupt mask set.
    pub(crate) const L2TIMSR0: usize = PD_BASE + 0x080C;
    /// L3 TX interrupt status 0.
    pub(crate) const L3TISAR0: usize = PD_BASE + 0x0810;
    /// L3 TX interrupt status 1.
    pub(crate) const L3TISAR1: usize = PD_BASE + 0x0814;
    /// L2 RX interrupt status & acknowledge.
    pub(crate) const L2RISAR0: usize = PD_BASE + 0x0830;
    /// CLDMA IP busy flag.
    pub(crate) const CLDMA_IP_BUSY: usize = PD_BASE + 0x0860;
    /// DMA exception status.
    pub(crate) const DMA_ERR: usize = PD_BASE + 0x0870;
    /// DMA exception mask.
    pub(crate) const DMA_ERR_MASK: usize = PD_BASE + 0x0874;
}

// L2 Interrupt bitmasks.
// Source: `eccci/mt6739/cldma_reg.h:152–163`

/// TX error on queue (bits 8–11, one per queue).
const CLDMA_TX_INT_ERROR: u32 = 0x0000_0F00;
/// TX queue empty (bits 4–7).
const CLDMA_TX_INT_QUEUE_EMPTY: u32 = 0x0000_00F0;
/// TX descriptor done (bits 0–3).
const CLDMA_TX_INT_DONE: u32 = 0x0000_000F;
/// RX error.
const CLDMA_RX_INT_ERROR: u32 = 0x0000_0004;
/// RX queue empty.
const CLDMA_RX_INT_QUEUE_EMPTY: u32 = 0x0000_0002;
/// RX descriptor done.
const CLDMA_RX_INT_DONE: u32 = 0x0000_0001;
/// All 4 queues mask.
const CLDMA_BM_ALL_QUEUE: u32 = 0x0F;

// INFRA reset registers for CLDMA hard reset.
// Source: `eccci/mt6739/cldma_reg.h:19–26`

/// Infrastructure AO base for clock/reset control.
const INFRA_AO_BASE: usize = 0x1000_1000;
/// AO domain reset set.
const INFRA_RST0_REG_AO: usize = INFRA_AO_BASE + 0x0140;
/// AO domain reset clear.
const INFRA_RST1_REG_AO: usize = INFRA_AO_BASE + 0x0144;
/// PD domain reset set.
const INFRA_RST0_REG_PD: usize = INFRA_AO_BASE + 0x0150;
/// PD domain reset clear.
const INFRA_RST1_REG_PD: usize = INFRA_AO_BASE + 0x0154;
/// CLDMA wakeup source mask; bit 1 = `CLDMA_IP_BUSY_MASK`.
const INFRA_CLDMA_CTRL_REG: usize = INFRA_AO_BASE + 0x0C00;
/// AO domain CLDMA reset mask (bit 6).
const CLDMA_AO_RST_MASK: u32 = 1 << 6;
/// PD domain CLDMA reset mask (bit 2).
const CLDMA_PD_RST_MASK: u32 = 1 << 2;
/// CLDMA IP busy mask (bit 1).
const CLDMA_IP_BUSY_MASK: u32 = 1 << 1;
/// Bit 12 in MD_GLOBAL_CON0 enables CLDMA.
const MD_GLOBAL_CON0_CLDMA_EN: u32 = 1 << 12;

// ---------------------------------------------------------------------------
// Modem watchdog registers
// ---------------------------------------------------------------------------

/// Base address for MD reset control (WDT).
/// Source: `eccci/mt6739/md_sys1_platform.h:26–34`
const MD_RSTCTL_BASE: usize = 0x200F_0000;

/// WDT mode register; key = `0x55000030`.
const REG_MDRSTCTL_WDTCR: usize = MD_RSTCTL_BASE;
/// WDT restart register.
const REG_MDRSTCTL_WDTRR: usize = MD_RSTCTL_BASE + 0x0010;
/// WDT status register — read to determine crash cause.
const REG_MDRSTCTL_WDTSR: usize = MD_RSTCTL_BASE + 0x0034;
/// WDT interval register.
const REG_MDRSTCTL_WDTIR: usize = MD_RSTCTL_BASE + 0x023C;
/// WDT mode key for writes.
const WDT_MODE_KEY: u32 = 0x5500_0030;

// ---------------------------------------------------------------------------
// CCIF register constants
// ---------------------------------------------------------------------------

/// AP CCIF base address (from DT, known for MT6739).
/// Source: `eccci/mt6739/ccif_hif_platform.h:27–85`
const AP_CCIF_BASE: usize = 0x200A_0000;

/// MD peer CCIF base.
/// Source: `eccci/mt6739/modem_reg_base.h:21–128`
const MD_CCIF_BASE: usize = 0x2051_0000;

// CCIF register offsets.
// Source: `eccci/mt6739/ccif_hif_platform.h:27–85`
mod ccif_reg {
    use super::AP_CCIF_BASE;

    /// Control register.
    pub(crate) const CON: usize = AP_CCIF_BASE;
    /// Busy mask (one bit per channel).
    pub(crate) const BUSY: usize = AP_CCIF_BASE + 0x04;
    /// Write channel bit to trigger interrupt to modem.
    pub(crate) const START: usize = AP_CCIF_BASE + 0x08;
    /// AP→MD channel number just triggered.
    pub(crate) const TCHNUM: usize = AP_CCIF_BASE + 0x0C;
    /// MD→AP channel number received.
    pub(crate) const RCHNUM: usize = AP_CCIF_BASE + 0x10;
    /// Write channel bit to acknowledge received interrupt.
    pub(crate) const ACK: usize = AP_CCIF_BASE + 0x14;
    /// SRAM window (512 bytes).
    pub(crate) const CHDATA: usize = AP_CCIF_BASE + 0x100;
}

/// CCIF channel assignments for MD gen ≥ 6293.
/// Source: `eccci/mt6739/ccif_hif_platform.h:27–85`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum CcifChannel {
    /// Ring-buffer queue 0 (AP→MD / MD→AP).
    RingQ0 = 0,
    RingQ1 = 1,
    RingQ2 = 2,
    RingQ3 = 3,
    RingQ4 = 4,
    RingQ5 = 5,
    RingQ6 = 6,
    /// Ring-buffer queue 7 / CCB wakeup (AP→MD).
    RingQ7 = 7,
    /// SRAM-based message (bidirectional).
    Sram = 15,
    /// Exception acknowledge (AP→MD) / Exception start (MD→AP).
    Exception = 16,
    /// Exception clear-queue ack (AP→MD) / init done (MD→AP).
    ExceptionClearQ = 17,
    /// Force modem assert (AP→MD) / clear done (MD→AP).
    ForceAssert = 18,
    /// MPU force assert (AP→MD) / all-queue reset (MD→AP).
    MpuAssert = 19,
    /// Peer wakeup (MD→AP).
    PeerWakeup = 20,
    /// Sequence error (MD→AP).
    SeqError = 21,
}

impl CcifChannel {
    /// Convert a raw channel number to a typed enum.
    /// Returns `None` for unrecognized channels.
    pub(crate) fn from_raw(ch: u8) -> Option<Self> {
        match ch {
            0 => Some(Self::RingQ0),
            1 => Some(Self::RingQ1),
            2 => Some(Self::RingQ2),
            3 => Some(Self::RingQ3),
            4 => Some(Self::RingQ4),
            5 => Some(Self::RingQ5),
            6 => Some(Self::RingQ6),
            7 => Some(Self::RingQ7),
            15 => Some(Self::Sram),
            16 => Some(Self::Exception),
            17 => Some(Self::ExceptionClearQ),
            18 => Some(Self::ForceAssert),
            19 => Some(Self::MpuAssert),
            20 => Some(Self::PeerWakeup),
            21 => Some(Self::SeqError),
            _ => None,
        }
    }

    /// Channel number as bit mask for CCIF registers.
    pub(crate) fn mask(self) -> u32 {
        1u32 << (self as u8)
    }
}

/// True if the raw CCIF `BUSY` register value has `channel`'s bit set,
/// meaning the modem has not yet consumed a previously sent message on
/// that channel (issue #261).
fn ccif_channel_busy(busy: u32, channel: CcifChannel) -> bool {
    busy & channel.mask() != 0
}

// ---------------------------------------------------------------------------
// CCCI message format
// ---------------------------------------------------------------------------

/// CCCI message MTU (maximum transfer unit).
/// Source: `eccci/mt6739/ccci_config.h`, `eccci/inc/ccci_core.h:33`
pub(crate) const CCCI_MTU: usize = 3456;

/// Magic value in `data[0]` indicating an internal control message.
/// Source: `eccci/inc/ccci_core.h:33`
pub(crate) const CCCI_MAGIC: u32 = 0xFFFF_FFFF;

/// CCCI message header (16 bytes).
/// Source: `eccci/inc/ccci_core.h` — `struct ccci_header`
///
/// All fields are little-endian as the AP and MD are both ARM LE.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
#[repr(C)]
pub(crate) struct CcciHeader {
    /// Channel-specific payload word 0. `CCCI_MAGIC` for control messages.
    pub(crate) data0: u32,
    /// Channel-specific payload word 1.
    pub(crate) data1: u32,
    /// CCCI channel number.
    pub(crate) channel: u32,
    /// Sequence number / flags.
    pub(crate) reserved: u32,
}

/// Size of the CCCI header in bytes.
pub(crate) const CCCI_HEADER_SIZE: usize = 16;

impl CcciHeader {
    /// Create a new control message header (magic in data0).
    pub(crate) fn new_control(channel: u32, seq: u32) -> Self {
        Self {
            data0: CCCI_MAGIC,
            data1: 0,
            channel,
            reserved: seq,
        }
    }

    /// Create a data message header.
    pub(crate) fn new_data(data0: u32, data1: u32, channel: u32, seq: u32) -> Self {
        Self {
            data0,
            data1,
            channel,
            reserved: seq,
        }
    }

    /// Whether this is an internal control message.
    pub(crate) fn is_control(&self) -> bool {
        self.data0 == CCCI_MAGIC
    }

    /// Serialize to a 16-byte little-endian buffer.
    pub(crate) fn to_bytes(self) -> [u8; CCCI_HEADER_SIZE] {
        let mut buf = [0u8; CCCI_HEADER_SIZE];
        buf[0..4].copy_from_slice(&self.data0.to_le_bytes());
        buf[4..8].copy_from_slice(&self.data1.to_le_bytes());
        buf[8..12].copy_from_slice(&self.channel.to_le_bytes());
        buf[12..16].copy_from_slice(&self.reserved.to_le_bytes());
        buf
    }

    /// Deserialize from a 16-byte little-endian buffer.
    /// Returns `None` if the buffer is too short.
    pub(crate) fn from_bytes(buf: &[u8]) -> Option<Self> {
        if buf.len() < CCCI_HEADER_SIZE {
            return None;
        }
        Some(Self {
            data0: u32::from_le_bytes([
                *buf.first()?,
                *buf.get(1)?,
                *buf.get(2)?,
                *buf.get(3)?,
            ]),
            data1: u32::from_le_bytes([
                *buf.get(4)?,
                *buf.get(5)?,
                *buf.get(6)?,
                *buf.get(7)?,
            ]),
            channel: u32::from_le_bytes([
                *buf.get(8)?,
                *buf.get(9)?,
                *buf.get(10)?,
                *buf.get(11)?,
            ]),
            reserved: u32::from_le_bytes([
                *buf.get(12)?,
                *buf.get(13)?,
                *buf.get(14)?,
                *buf.get(15)?,
            ]),
        })
    }

    /// Validate a header received from the modem.
    ///
    /// Checks:
    /// - Channel number maps to a known `CcciChannel` variant
    /// - If control message, magic must be exact
    ///
    /// SECURITY: Always call on modem-sourced headers after copying out of
    /// shared memory.
    pub(crate) fn validate(&self) -> Result<(), CcciError> {
        // WHY: channel numbers are sparse (0–21). Only known variants are
        // accepted — anything else is rejected at the boundary.
        if !CcciChannel::is_valid(self.channel) {
            return Err(CcciError::InvalidChannel(self.channel));
        }
        Ok(())
    }
}

impl fmt::Debug for CcciHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CcciHeader")
            .field("data0", &format_args!("{:#010x}", self.data0))
            .field("data1", &format_args!("{:#010x}", self.data1))
            .field("channel", &self.channel)
            .field("reserved", &format_args!("{:#010x}", self.reserved))
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Packet validation
// ---------------------------------------------------------------------------

/// Validate a modem packet header against its containing buffer.
///
/// SECURITY: This is the primary defense at the modem boundary. Must be
/// called on every packet received from the modem, AFTER copying the header
/// out of shared memory (TOCTOU defense).
///
/// Checks:
/// 1. Channel number is a known `CcciChannel` variant
/// 2. `data0` (used as length in data packets) does not exceed `buffer_len`
/// 3. `data1` (used as offset in some channels) is within `buffer_len`
///
/// Control messages (`data0 == CCCI_MAGIC`) skip the length check since
/// `data0` carries the magic sentinel, not a length.
pub(crate) fn validate_packet(header: &CcciHeader, buffer_len: usize) -> Result<(), CcciError> {
    // 1. Channel must be a recognized variant.
    header.validate()?;

    // 2. For data packets, data0 carries the payload length. Verify it
    //    fits within the buffer that was actually received.
    if !header.is_control() && (header.data0 as usize) > buffer_len {
        return Err(CcciError::PacketLengthExceeded {
            header_length: header.data0,
            buffer_len,
        });
    }

    // 3. data1 is used as an offset/index on several channels. Verify it
    //    does not point past the buffer boundary.
    if header.data1 != 0 && (header.data1 as usize) > buffer_len {
        return Err(CcciError::OffsetOutOfBounds {
            offset: header.data1,
            buffer_len,
        });
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// CCCI channel map
// ---------------------------------------------------------------------------

/// Key CCCI logical channel numbers.
/// Source: `eccci/inc/ccci_core.h:46+`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub(crate) enum CcciChannel {
    /// Modem control handshake (TX).
    ControlTx = 0,
    /// Modem control handshake (RX).
    ControlRx = 1,
    /// System messages (TX).
    SystemTx = 2,
    /// System messages (RX).
    SystemRx = 3,
    /// AT command / RILD (TX).
    Uart1Tx = 4,
    /// AT command / RILD (RX).
    Uart1Rx = 5,
    /// META UART (TX).
    Uart2Tx = 6,
    /// META UART (RX).
    Uart2Rx = 7,
    /// File system proxy (TX).
    FsTx = 8,
    /// File system proxy (RX).
    FsRx = 9,
    /// PMIC proxy (TX).
    PmicTx = 10,
    /// PMIC proxy (RX).
    PmicRx = 11,
    /// Network channel 1 (TX).
    Ccmni1Tx = 12,
    /// Network channel 1 (RX).
    Ccmni1Rx = 13,
    /// Network channel 2 (TX).
    Ccmni2Tx = 14,
    /// Network channel 2 (RX).
    Ccmni2Rx = 15,
    /// Network channel 3 (TX).
    Ccmni3Tx = 16,
    /// Network channel 3 (RX).
    Ccmni3Rx = 17,
    /// Inter-processor call (TX).
    IpcTx = 18,
    /// Inter-processor call (RX).
    IpcRx = 19,
    /// Modem logging (TX).
    MdLogTx = 20,
    /// Modem logging (RX).
    MdLogRx = 21,
}

impl CcciChannel {
    /// Whether a raw channel number maps to a known variant.
    ///
    /// SECURITY: Used at the modem boundary to reject unknown channel IDs.
    /// Only channels defined in the protocol are accepted.
    pub(crate) fn is_valid(ch: u32) -> bool {
        matches!(
            ch,
            0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 | 16 | 17
                | 18 | 19 | 20 | 21
        )
    }
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors from CCCI operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CcciError {
    /// Invalid CCCI channel number from modem.
    InvalidChannel(u32),
    /// Modem boot failed at the given step.
    BootFailed(BootStep),
    /// CLDMA DMA error.
    DmaError(u32),
    /// Shared memory offset out of bounds.
    SharedMemoryOutOfBounds {
        offset: u32,
        length: u32,
        region_size: u32,
    },
    /// Message payload exceeds MTU.
    PayloadTooLarge(usize),
    /// Ring buffer is full — no free descriptors.
    RingBufferFull,
    /// CCIF channel is still busy with an unconsumed message (issue #261).
    CcifChannelBusy(CcifChannel),
    /// Modem watchdog timeout.
    ModemWatchdog(u32),
    /// Identity response blocked by kernel filter.
    IdentityFiltered,
    /// Header deserialization failed.
    MalformedHeader,
    /// Packet header length field exceeds the actual buffer size.
    PacketLengthExceeded {
        header_length: u32,
        buffer_len: usize,
    },
    /// data1 offset field points past the end of the buffer.
    OffsetOutOfBounds { offset: u32, buffer_len: usize },
    /// Poll timeout waiting for hardware.
    Timeout,
}

impl fmt::Display for CcciError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidChannel(ch) => write!(f, "invalid CCCI channel {ch}"),
            Self::BootFailed(step) => write!(f, "modem boot failed at {step:?}"),
            Self::DmaError(status) => write!(f, "CLDMA DMA error: {status:#010x}"),
            Self::SharedMemoryOutOfBounds {
                offset,
                length,
                region_size,
            } => write!(
                f,
                "shared memory OOB: offset={offset:#x} len={length:#x} region={region_size:#x}"
            ),
            Self::PayloadTooLarge(size) => {
                write!(f, "payload {size} exceeds MTU {CCCI_MTU}")
            }
            Self::RingBufferFull => write!(f, "ring buffer full"),
            Self::CcifChannelBusy(channel) => write!(f, "CCIF channel {channel:?} busy"),
            Self::ModemWatchdog(status) => write!(f, "modem WDT: {status:#010x}"),
            Self::IdentityFiltered => write!(f, "identity response filtered"),
            Self::MalformedHeader => write!(f, "malformed CCCI header"),
            Self::PacketLengthExceeded {
                header_length,
                buffer_len,
            } => write!(
                f,
                "packet header length {header_length} exceeds buffer {buffer_len}"
            ),
            Self::OffsetOutOfBounds { offset, buffer_len } => write!(
                f,
                "data1 offset {offset:#x} exceeds buffer {buffer_len}"
            ),
            Self::Timeout => write!(f, "hardware poll timeout"),
        }
    }
}

// ---------------------------------------------------------------------------
// Modem boot state machine
// ---------------------------------------------------------------------------

/// Boot sequence step for the 6-step modem bring-up.
/// Source: `eccci/mt6739/md_sys1_platform.c`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BootStep {
    /// Step 1: Enable required clocks.
    EnableClocks,
    /// Step 2: Hard-reset CLDMA (AO then PD domain).
    ResetCldma,
    /// Step 3: Map hardware (CLDMA bases, CCIF, IRQs).
    MapHardware,
    /// Step 4: Write MD boot vector, release reset, poll status.
    ReleaseMd,
    /// Step 5: Send runtime data via CCIF H2D_SRAM (channel 15).
    SendRuntime,
    /// Step 6: Wait for MD acknowledge.
    WaitAck,
    /// Boot complete.
    Complete,
}

impl BootStep {
    /// Advance to the next boot step.
    fn next(self) -> Self {
        match self {
            Self::EnableClocks => Self::ResetCldma,
            Self::ResetCldma => Self::MapHardware,
            Self::MapHardware => Self::ReleaseMd,
            Self::ReleaseMd => Self::SendRuntime,
            Self::SendRuntime => Self::WaitAck,
            Self::WaitAck => Self::Complete,
            Self::Complete => Self::Complete,
        }
    }
}

/// Maximum iterations for polling loops during boot.
const BOOT_POLL_MAX: u32 = 100_000;

// ---------------------------------------------------------------------------
// CLDMA ring buffer descriptors
// ---------------------------------------------------------------------------

/// Number of TX queues supported by CLDMA.
const TX_QUEUE_COUNT: usize = 4;

/// Number of descriptors per TX queue.
const TX_RING_SIZE: usize = 16;

/// Number of descriptors per RX queue (single queue).
const RX_RING_SIZE: usize = 16;

/// Full-system memory barrier (ARM `dmb sy`), used to order CLDMA GPD
/// descriptor field writes/reads across the AP/DMA-engine ownership
/// handoff (issue #262).
#[cfg(target_arch = "arm")]
#[inline(always)]
fn dmb_sy() {
    // SAFETY: dmb is a non-privileged memory-barrier instruction; always safe to execute.
    unsafe {
        core::arch::asm!("dmb sy");
    }
}

/// No-op stub for non-ARM builds so ccci.rs unit tests compile on the host,
/// where there is no real DMA engine to synchronize with.
#[cfg(not(target_arch = "arm"))]
#[inline(always)]
fn dmb_sy() {}

/// CLDMA GPD (General Purpose Descriptor) for DMA transfer.
///
/// Each descriptor describes one DMA buffer. Descriptors are chained
/// in a circular linked list.
///
/// SAFETY: `repr(C)` ensures the hardware-expected layout. Fields are
/// accessed by the CLDMA DMA engine directly.
#[derive(Clone, Copy, Default)]
#[repr(C, align(8))]
pub(crate) struct CldmaGpd {
    /// Flags: bit 0 = HWO (hardware owned), bit 1 = BDP (buffer descriptor present).
    pub(crate) flags: u32,
    /// Checksum (not used, set to 0).
    pub(crate) checksum: u32,
    /// Physical address of the data buffer.
    pub(crate) data_ptr: u32,
    /// Next GPD physical address (circular: last points to first).
    pub(crate) next: u32,
    /// Data buffer length (TX: bytes to send, RX: buffer capacity).
    pub(crate) data_len: u16,
    /// Actual received length (RX only, filled by hardware).
    pub(crate) recv_len: u16,
}

/// GPD flag: hardware owns this descriptor.
const GPD_FLAG_HWO: u32 = 1 << 0;
/// GPD flag: buffer descriptor present (chained BD).
const GPD_FLAG_BDP: u32 = 1 << 1;

impl CldmaGpd {
    /// Create a zeroed descriptor.
    pub(crate) const fn zeroed() -> Self {
        Self {
            flags: 0,
            checksum: 0,
            data_ptr: 0,
            next: 0,
            data_len: 0,
            recv_len: 0,
        }
    }

    /// Whether hardware currently owns this descriptor.
    ///
    /// WHY: `flags` is shared with the CLDMA DMA engine (issue #262) -- a
    /// volatile load is required so a caller polling this method observes
    /// a hardware-side ownership change rather than a value the compiler
    /// cached from an earlier read.
    pub(crate) fn is_hw_owned(&self) -> bool {
        // SAFETY: `flags` is a `repr(C)` field of a descriptor the CLDMA
        // engine writes concurrently; a volatile read is required.
        let flags = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(self.flags)) };
        let owned = flags & GPD_FLAG_HWO != 0;
        if !owned {
            // Acquire half of the ownership handoff: once HWO reads clear,
            // this barrier ensures a subsequent read of a DMA-written field
            // (e.g. recv_len) observes the data the CLDMA engine wrote
            // before it cleared HWO, rather than a stale/reordered value.
            dmb_sy();
        }
        owned
    }

    /// Set hardware ownership (give to DMA engine).
    ///
    /// WHY: this is the release half of the ownership handoff (issue
    /// #262) -- the barrier ensures data_ptr/data_len/recv_len writes the
    /// caller made before this call are visible to the CLDMA engine before
    /// it can observe HWO set.
    pub(crate) fn set_hw_owned(&mut self) {
        dmb_sy();
        let flags = self.flags | GPD_FLAG_HWO;
        // SAFETY: `flags` is a `repr(C)` field shared with the CLDMA DMA
        // engine; a volatile store is required so the compiler does not
        // reorder, elide, or coalesce the ownership-transfer write.
        unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!(self.flags), flags) };
    }

    /// Clear hardware ownership (reclaim from DMA engine).
    pub(crate) fn clear_hw_owned(&mut self) {
        let flags = self.flags & !GPD_FLAG_HWO;
        // SAFETY: `flags` is a `repr(C)` field shared with the CLDMA DMA
        // engine; a volatile store is required for the same reason as
        // `set_hw_owned`.
        unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!(self.flags), flags) };
    }

    /// Read `recv_len` with a volatile access.
    ///
    /// WHY: `recv_len` is written by the CLDMA DMA engine while the AP does
    /// not hold Rust-visible ownership of the descriptor (issue #262); a
    /// plain field read could return the AP's own last write (`0`, set at
    /// `submit`/`rearm` time) instead of the hardware-written value.
    ///
    /// Callers must only trust the result after [`is_hw_owned`] has
    /// observed `false` for this descriptor.
    ///
    /// [`is_hw_owned`]: CldmaGpd::is_hw_owned
    pub(crate) fn recv_len_volatile(&self) -> u16 {
        // SAFETY: `recv_len` is a `repr(C)` field the CLDMA engine writes
        // concurrently; a volatile read is required.
        unsafe { core::ptr::read_volatile(core::ptr::addr_of!(self.recv_len)) }
    }
}

impl fmt::Debug for CldmaGpd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CldmaGpd")
            .field("flags", &format_args!("{:#010x}", self.flags))
            .field("data_ptr", &format_args!("{:#010x}", self.data_ptr))
            .field("next", &format_args!("{:#010x}", self.next))
            .field("data_len", &self.data_len)
            .field("recv_len", &self.recv_len)
            .finish()
    }
}

/// TX ring buffer for one CLDMA queue.
pub(crate) struct TxRing {
    /// Descriptor array (circular).
    descriptors: [CldmaGpd; TX_RING_SIZE],
    /// Index of the next descriptor to submit.
    head: usize,
    /// Index of the next descriptor to reclaim.
    tail: usize,
    /// Number of descriptors currently owned by hardware.
    hw_count: usize,
}

impl TxRing {
    /// Create a new empty TX ring.
    pub(crate) const fn new() -> Self {
        Self {
            descriptors: [CldmaGpd::zeroed(); TX_RING_SIZE],
            head: 0,
            tail: 0,
            hw_count: 0,
        }
    }

    /// Initialize the descriptor chain (circular linked list).
    ///
    /// `base_addr` is the physical address of `self.descriptors[0]`.
    /// Each descriptor's `next` field points to the following descriptor,
    /// with the last wrapping back to the first.
    pub(crate) fn init_chain(&mut self, base_addr: u32) {
        let gpd_size: u32 = core::mem::size_of::<CldmaGpd>() as u32;
        let count = TX_RING_SIZE;
        for i in 0..count {
            let next_idx = (i + 1) % count;
            self.descriptors[i].next = base_addr + (u32::try_from(next_idx).unwrap_or_default()) * gpd_size;
            self.descriptors[i].flags = 0;
        }
        self.head = 0;
        self.tail = 0;
        self.hw_count = 0;
    }

    /// Submit a buffer for TX. Returns the descriptor index used.
    ///
    /// SECURITY: `data_phys` must point to an AP-owned DMA buffer, not
    /// shared memory that the modem can modify.
    pub(crate) fn submit(
        &mut self,
        data_phys: u32,
        length: u16,
    ) -> Result<usize, CcciError> {
        if self.hw_count >= TX_RING_SIZE {
            return Err(CcciError::RingBufferFull);
        }
        let idx = self.head;
        self.descriptors[idx].data_ptr = data_phys;
        self.descriptors[idx].data_len = length;
        self.descriptors[idx].recv_len = 0;
        self.descriptors[idx].set_hw_owned();
        self.head = (self.head + 1) % TX_RING_SIZE;
        self.hw_count += 1;
        Ok(idx)
    }

    /// Reclaim completed descriptors. Returns the number reclaimed.
    pub(crate) fn reclaim(&mut self) -> usize {
        let mut count = 0;
        while self.hw_count > 0 {
            if self.descriptors[self.tail].is_hw_owned() {
                // INVARIANT: hardware still owns this descriptor
                break;
            }
            self.tail = (self.tail + 1) % TX_RING_SIZE;
            self.hw_count -= 1;
            count += 1;
        }
        count
    }

    /// Number of free descriptor slots.
    pub(crate) fn free_count(&self) -> usize {
        TX_RING_SIZE - self.hw_count
    }

    /// Whether the ring is empty (no pending TX).
    pub(crate) fn is_empty(&self) -> bool {
        self.hw_count == 0
    }

    /// Physical address of the first descriptor (for CLDMA start register).
    pub(crate) fn start_addr(&self, base_addr: u32) -> u32 {
        base_addr
    }
}

/// RX ring buffer for CLDMA.
pub(crate) struct RxRing {
    /// Descriptor array (circular).
    descriptors: [CldmaGpd; RX_RING_SIZE],
    /// Index of the next descriptor to check for received data.
    head: usize,
    /// Number of descriptors currently owned by hardware.
    hw_count: usize,
}

impl RxRing {
    /// Create a new empty RX ring.
    pub(crate) const fn new() -> Self {
        Self {
            descriptors: [CldmaGpd::zeroed(); RX_RING_SIZE],
            head: 0,
            hw_count: 0,
        }
    }

    /// Initialize the descriptor chain and give all descriptors to hardware.
    ///
    /// Each descriptor gets a pre-allocated RX buffer of `buf_size` bytes.
    /// `base_addr` is the physical address of `self.descriptors[0]`.
    /// `buf_addrs` are the physical addresses of the RX buffers.
    pub(crate) fn init_chain(&mut self, base_addr: u32, buf_addrs: &[u32], buf_size: u16) {
        let gpd_size = core::mem::size_of::<CldmaGpd>() as u32;
        let count = RX_RING_SIZE.min(buf_addrs.len());
        for (i, &addr) in buf_addrs.iter().enumerate().take(count) {
            let next_idx = (i + 1) % count;
            self.descriptors[i].next = base_addr + (u32::try_from(next_idx).unwrap_or_default()) * gpd_size;
            self.descriptors[i].data_ptr = addr;
            self.descriptors[i].data_len = buf_size;
            self.descriptors[i].recv_len = 0;
            self.descriptors[i].set_hw_owned();
        }
        self.head = 0;
        self.hw_count = count;
    }

    /// Poll for received data. Returns descriptor index and received length,
    /// or `None` if no data is ready.
    ///
    /// SECURITY: The returned descriptor index points to a buffer that was
    /// filled by the modem DMA engine. The caller MUST copy data out of the
    /// RX buffer before processing — the modem can modify DMA buffers at any
    /// time (TOCTOU defense).
    pub(crate) fn poll_rx(&mut self) -> Option<(usize, u16)> {
        if self.hw_count == 0 {
            return None;
        }
        let idx = self.head;
        if self.descriptors[idx].is_hw_owned() {
            return None;
        }
        // SECURITY: recv_len is modem-written and untrusted; clamp to the
        // AP-allocated buffer capacity (data_len) before it can be used as a
        // slice length/copy count by the caller.
        // WHY: recv_len_volatile, not the plain field -- see
        // CldmaGpd::recv_len_volatile for why a plain read is unsound here
        // (issue #262).
        let recv_len = self.descriptors[idx]
            .recv_len_volatile()
            .min(self.descriptors[idx].data_len);
        self.head = (self.head + 1) % RX_RING_SIZE;
        self.hw_count -= 1;
        Some((idx, recv_len))
    }

    /// Return a descriptor to hardware after processing.
    pub(crate) fn rearm(&mut self, idx: usize, buf_addr: u32, buf_size: u16) {
        self.descriptors[idx].data_ptr = buf_addr;
        self.descriptors[idx].data_len = buf_size;
        self.descriptors[idx].recv_len = 0;
        self.descriptors[idx].set_hw_owned();
        self.hw_count += 1;
    }
}

// ---------------------------------------------------------------------------
// Shared memory layout
// ---------------------------------------------------------------------------

/// Shared memory region descriptor.
///
/// SECURITY: All pointers into shared memory are untrusted. Bounds-check
/// every offset before access. Copy data out before processing.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SharedMemRegion {
    /// Physical base address of the region.
    pub(crate) base: u32,
    /// Size in bytes.
    pub(crate) size: u32,
}

impl SharedMemRegion {
    /// Create a new shared memory region descriptor.
    pub(crate) const fn new(base: u32, size: u32) -> Self {
        Self { base, size }
    }

    /// Validate that an offset + length falls within this region.
    ///
    /// SECURITY: Call this before every access to shared memory. The modem
    /// can supply arbitrary offsets in message headers.
    pub(crate) fn validate_bounds(&self, offset: u32, length: u32) -> Result<(), CcciError> {
        // WHY: use checked arithmetic to prevent overflow attacks
        let end = offset
            .checked_add(length)
            .ok_or(CcciError::SharedMemoryOutOfBounds {
                offset,
                length,
                region_size: self.size,
            })?;
        if end > self.size {
            return Err(CcciError::SharedMemoryOutOfBounds {
                offset,
                length,
                region_size: self.size,
            });
        }
        Ok(())
    }

    /// Compute the physical address for a validated offset.
    ///
    /// # Safety
    ///
    /// Caller must have validated bounds with `validate_bounds()` first.
    pub(crate) fn phys_addr(&self, offset: u32) -> u32 {
        self.base.wrapping_add(offset)
    }
}

/// Non-cacheable shared memory IDs.
/// Source: `eccci/inc/ccci_modem.h:99–172`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NonCacheableRegion {
    /// Boot information (version, image info).
    BootInfo,
    /// Exception dump area (MD crash context).
    ExceptionShare,
    /// CCIF SRAM backup.
    CcifShare,
    /// CCISM control.
    CcismShare,
    /// CCB (Credit Control Buffer) for network flow control.
    CcbShare,
    /// DHLogger raw.
    DhlRawShare,
    /// Modem-consys shared.
    MdConsysShare,
}

/// Cacheable shared memory IDs.
/// Source: `eccci/inc/ccci_modem.h:99–172`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CacheableRegion {
    /// Smart logging.
    SmartLogging,
    /// Net daemon.
    DtNetd,
    /// Audio raw data.
    AudioRaw,
}

/// Full shared memory layout for AP↔modem communication.
/// Source: `eccci/inc/ccci_modem.h:99–172`
pub(crate) struct SharedMemLayout {
    /// MD image region (bank 0).
    pub(crate) md_image: SharedMemRegion,
    /// Non-cacheable control region (bank 4 NC).
    pub(crate) noncacheable: SharedMemRegion,
    /// Cacheable bulk data region (bank 4 C).
    pub(crate) cacheable: SharedMemRegion,
}

impl SharedMemLayout {
    /// Default layout for MT6739. Addresses are from the modem DT node.
    ///
    /// WARNING: These are placeholder addresses. Real values come from
    /// the modem image header and device tree at boot time.
    pub(crate) const fn mt6739_default() -> Self {
        Self {
            md_image: SharedMemRegion::new(0x8000_0000, 0x0800_0000),
            noncacheable: SharedMemRegion::new(0x8800_0000, 0x0020_0000),
            cacheable: SharedMemRegion::new(0x8A00_0000, 0x0010_0000),
        }
    }
}

// ---------------------------------------------------------------------------
// Kernel audit ring buffer
// ---------------------------------------------------------------------------

/// Maximum number of entries in the audit ring buffer.
const AUDIT_RING_CAPACITY: usize = 64;

/// Maximum payload bytes stored per audit entry.
const AUDIT_PAYLOAD_MAX: usize = 64;

/// Type of audit event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuditEventKind {
    /// Modem-initiated data transmission.
    ModemTx,
    /// Modem-initiated data reception.
    ModemRx,
    /// Identity query intercepted (AT+CGSN / AT+CIMI).
    IdentityQuery,
    /// Identity response filtered.
    IdentityFiltered,
    /// Modem watchdog event.
    ModemWatchdog,
    /// Modem boot state change.
    BootStateChange,
    /// CCIF control message.
    CcifControl,
    /// Modem exception.
    ModemException,
}

/// Single audit ring buffer entry.
#[derive(Clone)]
pub(crate) struct AuditEntry {
    /// Monotonic timestamp (kernel ticks).
    pub(crate) timestamp: u64,
    /// Event type.
    pub(crate) kind: AuditEventKind,
    /// CCCI channel (if applicable).
    pub(crate) channel: u32,
    /// Short payload snippet (first N bytes, copied out).
    pub(crate) payload: [u8; AUDIT_PAYLOAD_MAX],
    /// Actual payload length (may exceed `AUDIT_PAYLOAD_MAX`; truncated).
    pub(crate) payload_len: usize,
}

impl AuditEntry {
    /// Create a new audit entry with truncated payload.
    pub(crate) fn new(
        timestamp: u64,
        kind: AuditEventKind,
        channel: u32,
        data: &[u8],
    ) -> Self {
        let mut payload = [0u8; AUDIT_PAYLOAD_MAX];
        let copy_len = data.len().min(AUDIT_PAYLOAD_MAX);
        payload[..copy_len].copy_from_slice(
            data.get(..copy_len).unwrap_or(data),
        );
        Self {
            timestamp,
            kind,
            channel,
            payload,
            payload_len: data.len(),
        }
    }
}

/// Fixed-size ring buffer for modem audit logging.
///
/// SECURITY: Every modem-initiated transmission is logged here. This is
/// the kernel's record of what the modem has sent and received.
pub(crate) struct AuditRing {
    entries: [Option<AuditEntry>; AUDIT_RING_CAPACITY],
    /// Write index (wraps around).
    write_idx: usize,
    /// Total entries written (monotonic, for overflow detection).
    total_written: u64,
}

impl AuditRing {
    /// Create a new empty audit ring.
    pub(crate) const fn new() -> Self {
        // NOTE: we need const initialization so this can be a static
        const NONE: Option<AuditEntry> = None;
        Self {
            entries: [NONE; AUDIT_RING_CAPACITY],
            write_idx: 0,
            total_written: 0,
        }
    }

    /// Record an audit entry. Overwrites the oldest entry when full.
    pub(crate) fn record(&mut self, entry: AuditEntry) {
        self.entries[self.write_idx] = Some(entry);
        self.write_idx = (self.write_idx + 1) % AUDIT_RING_CAPACITY;
        self.total_written += 1;
    }

    /// Total entries recorded (including overwritten).
    pub(crate) fn total_written(&self) -> u64 {
        self.total_written
    }

    /// Number of entries currently available (up to capacity).
    pub(crate) fn count(&self) -> usize {
        if self.total_written >= AUDIT_RING_CAPACITY as u64 {
            AUDIT_RING_CAPACITY
        } else {
            self.total_written as usize
        }
    }

    /// Read the entry at a logical index (0 = oldest available).
    /// Returns `None` if index is out of range.
    pub(crate) fn get(&self, logical_idx: usize) -> Option<&AuditEntry> {
        let count = self.count();
        if logical_idx >= count {
            return None;
        }
        let actual_idx = if self.total_written >= AUDIT_RING_CAPACITY as u64 {
            (self.write_idx + logical_idx) % AUDIT_RING_CAPACITY
        } else {
            logical_idx
        };
        self.entries[actual_idx].as_ref()
    }

    /// Check if the ring has overflowed (dropped old entries).
    pub(crate) fn has_overflowed(&self) -> bool {
        self.total_written > AUDIT_RING_CAPACITY as u64
    }
}

// ---------------------------------------------------------------------------
// Modem identity filter
// ---------------------------------------------------------------------------

/// AT command prefixes that reveal device identity.
/// SECURITY: These are intercepted at the kernel boundary. The modem
/// firmware responds to these AT commands with the device's IMEI (CGSN)
/// and IMSI (CIMI), which tie the physical device to a person. Matching is
/// ASCII case-insensitive (see `contains_subsequence`) because AT commands
/// are case-insensitive per 3GPP TS 27.007.
const IDENTITY_AT_COMMANDS: &[&[u8]] = &[
    b"AT+CGSN",  // IMEI query
    b"AT+CIMI",  // IMSI query
    b"+CGSN:",   // IMEI response prefix
    b"+CIMI:",   // IMSI response prefix
];

/// Length of a bare IMEI or IMSI decimal digit string (3GPP TS 23.003).
const IDENTITY_DIGIT_RUN_LEN: usize = 15;

/// Check if a data buffer contains an identity-revealing AT command or response.
///
/// SECURITY: This runs on every UART channel message from the modem. The
/// check must be performed on data already copied out of shared memory.
/// Covers three forms: the AT query itself, a `+CGSN:`/`+CIMI:`-prefixed
/// response, and the bare (unprefixed) digit-string response that the
/// standard 3GPP TS 27.007 Execute form of `AT+CGSN`/`AT+CIMI` actually
/// returns.
///
/// Returns `true` if the buffer matches an identity pattern.
pub(crate) fn contains_identity_pattern(data: &[u8]) -> bool {
    for pattern in IDENTITY_AT_COMMANDS {
        if data.len() >= pattern.len() {
            // NOTE: search entire buffer for the pattern, not just prefix.
            // Modem responses may include preceding whitespace or channel framing.
            if contains_subsequence(data, pattern) {
                return true;
            }
        }
    }
    contains_bare_identity_digits(data)
}

/// Scan `haystack` for the first occurrence of `needle`, ASCII
/// case-insensitively.
///
/// SECURITY: AT commands are case-insensitive per 3GPP TS 27.007. A
/// byte-exact scan let a lowercase response (e.g. `at+cgsn`) bypass the
/// identity filter entirely.
fn contains_subsequence(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if haystack.len() < needle.len() {
        return false;
    }
    let limit = haystack.len() - needle.len() + 1;
    for i in 0..limit {
        if let Some(window) = haystack.get(i..i + needle.len())
            && window
                .iter()
                .zip(needle.iter())
                .all(|(&a, &b)| a.eq_ignore_ascii_case(&b))
        {
            return true;
        }
    }
    false
}

/// Check for a bare (unprefixed) IMEI/IMSI response: a run of exactly
/// [`IDENTITY_DIGIT_RUN_LEN`] ASCII digits, not part of a longer digit run.
///
/// SECURITY: the Execute form of `AT+CGSN`/`AT+CIMI` (3GPP TS 27.007)
/// returns the identifier as a bare digit string with no `+CGSN:`/`+CIMI:`
/// prefix -- only the extended `AT+CGSN=<snt>` form is prefixed. Without
/// this check, a compliant bare-digit response bypasses
/// `IDENTITY_AT_COMMANDS` entirely.
fn contains_bare_identity_digits(data: &[u8]) -> bool {
    let mut run_len = 0usize;
    for &b in data {
        if b.is_ascii_digit() {
            run_len += 1;
        } else {
            if run_len == IDENTITY_DIGIT_RUN_LEN {
                return true;
            }
            run_len = 0;
        }
    }
    run_len == IDENTITY_DIGIT_RUN_LEN
}

/// Capability flag required to pass identity data to userspace.
/// SECURITY: Userspace processes must hold this capability bit to receive
/// IMEI/IMSI data. Without it, identity responses are silently dropped
/// after being logged to the audit ring.
pub(crate) const CAP_MODEM_IDENTITY: u32 = 1 << 16;

// ---------------------------------------------------------------------------
// Interrupt dispatch
// ---------------------------------------------------------------------------

/// Result of dispatching a CLDMA interrupt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CldmaIrqEvent {
    /// TX descriptor(s) completed on the given queue mask.
    TxDone(u32),
    /// TX queue(s) empty.
    TxQueueEmpty(u32),
    /// TX error on queue(s).
    TxError(u32),
    /// RX data available.
    RxDone,
    /// RX queue empty.
    RxQueueEmpty,
    /// RX error.
    RxError,
}

/// Read and acknowledge CLDMA L2 interrupt status.
///
/// SECURITY: This is called from the IRQ handler. Reads hardware registers
/// and returns the set of events. The caller must process events and handle
/// modem data with full validation.
///
/// # Safety
///
/// Must be called from IRQ context with CLDMA registers mapped.
pub(crate) unsafe fn dispatch_cldma_irq() -> (u32, u32) {
    // WHY: read both TX and RX status atomically (relative to AP) to avoid
    // missing events during the dispatch window.
    // SAFETY: shared memory region at L2TISAR0/L2RISAR0 is mapped and within
    // the CCCI aperture. Access is synchronized via CCIF doorbell.
    let tx_status = unsafe { mmio::read32(cldma_pd::L2TISAR0) };
    // SAFETY: shared memory region at L2RISAR0 is mapped and within the CCCI
    // aperture. Access is synchronized via CCIF doorbell.
    let rx_status = unsafe { mmio::read32(cldma_pd::L2RISAR0) };

    // Acknowledge by writing back the same bits.
    // Source: §1.8 — "Write the same bit back to acknowledge"
    if tx_status != 0 {
        // SAFETY: shared memory region at L2TISAR0 is mapped and within the
        // CCCI aperture. Access is synchronized via CCIF doorbell.
        unsafe {
            mmio::write32(cldma_pd::L2TISAR0, tx_status);
        }
    }
    if rx_status != 0 {
        // SAFETY: shared memory region at L2RISAR0 is mapped and within the
        // CCCI aperture. Access is synchronized via CCIF doorbell.
        unsafe {
            mmio::write32(cldma_pd::L2RISAR0, rx_status);
        }
    }

    (tx_status, rx_status)
}

/// Parse raw CLDMA TX interrupt status into typed events.
pub(crate) fn parse_cldma_tx_status(status: u32) -> [Option<CldmaIrqEvent>; 3] {
    let mut events: [Option<CldmaIrqEvent>; 3] = [None; 3];
    let mut idx = 0;

    let done = status & CLDMA_TX_INT_DONE;
    if done != 0 && idx < 3 {
        events[idx] = Some(CldmaIrqEvent::TxDone(done));
        idx += 1;
    }

    let empty = (status & CLDMA_TX_INT_QUEUE_EMPTY) >> 4;
    if empty != 0 && idx < 3 {
        events[idx] = Some(CldmaIrqEvent::TxQueueEmpty(empty));
        idx += 1;
    }

    let error = (status & CLDMA_TX_INT_ERROR) >> 8;
    if error != 0 && idx < 3 {
        events[idx] = Some(CldmaIrqEvent::TxError(error));
    }

    events
}

/// Parse raw CLDMA RX interrupt status into typed events.
pub(crate) fn parse_cldma_rx_status(status: u32) -> [Option<CldmaIrqEvent>; 3] {
    let mut events: [Option<CldmaIrqEvent>; 3] = [None; 3];
    let mut idx = 0;

    if status & CLDMA_RX_INT_DONE != 0 && idx < 3 {
        events[idx] = Some(CldmaIrqEvent::RxDone);
        idx += 1;
    }

    if status & CLDMA_RX_INT_QUEUE_EMPTY != 0 && idx < 3 {
        events[idx] = Some(CldmaIrqEvent::RxQueueEmpty);
        idx += 1;
    }

    if status & CLDMA_RX_INT_ERROR != 0 && idx < 3 {
        events[idx] = Some(CldmaIrqEvent::RxError);
    }

    events
}

/// Read and acknowledge CCIF interrupt status.
///
/// Returns the bitmask of channels that triggered (MD→AP).
///
/// # Safety
///
/// Must be called from IRQ context with CCIF registers mapped.
pub(crate) unsafe fn dispatch_ccif_irq() -> u32 {
    // Source: §1.8 — read RCHNUM, write bitmask to ACK
    // SAFETY: shared memory region at RCHNUM is mapped and within the CCCI
    // aperture. Access is synchronized via CCIF doorbell.
    let channels = unsafe { mmio::read32(ccif_reg::RCHNUM) };
    if channels != 0 {
        // SAFETY: shared memory region at ACK is mapped and within the CCCI
        // aperture. Access is synchronized via CCIF doorbell.
        unsafe {
            mmio::write32(ccif_reg::ACK, channels);
        }
    }
    channels
}

/// Dispatch CCIF channels to typed events.
pub(crate) fn parse_ccif_channels(raw: u32) -> [Option<CcifChannel>; 8] {
    let mut result: [Option<CcifChannel>; 8] = [None; 8];
    let mut idx = 0;
    for bit in 0..24u8 {
        if raw & (1u32 << bit) != 0 && idx < 8 {
            result[idx] = CcifChannel::from_raw(bit);
            idx += 1;
        }
    }
    result
}

// ---------------------------------------------------------------------------
// Modem watchdog handler
// ---------------------------------------------------------------------------

/// Modem WDT status bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WdtStatus {
    /// Raw status register value.
    pub(crate) raw: u32,
}

impl WdtStatus {
    /// Read the modem WDT status register.
    ///
    /// # Safety
    ///
    /// MD reset control registers must be mapped.
    pub(crate) unsafe fn read() -> Self {
        Self {
            // SAFETY: shared memory region at REG_MDRSTCTL_WDTSR is mapped and
            // within the CCCI aperture. Access is synchronized via CCIF doorbell.
            raw: unsafe { mmio::read32(REG_MDRSTCTL_WDTSR) },
        }
    }

    /// Whether the modem has crashed (WDT triggered).
    pub(crate) fn is_triggered(&self) -> bool {
        self.raw != 0
    }
}

/// Handle a modem watchdog IRQ.
///
/// 1. Read WDT status register for crash cause
/// 2. Log to audit ring
/// 3. Initiate exception dump via CCIF exception channel
///
/// # Safety
///
/// Must be called from IRQ context with all CCCI registers mapped.
pub(crate) unsafe fn handle_modem_watchdog(audit: &mut AuditRing, timestamp: u64) -> WdtStatus {
    // SAFETY: shared memory region at REG_MDRSTCTL_WDTSR is mapped and within
    // the CCCI aperture. Access is synchronized via CCIF doorbell.
    let status = unsafe { WdtStatus::read() };

    // Log the watchdog event
    let status_bytes = status.raw.to_le_bytes();
    audit.record(AuditEntry::new(
        timestamp,
        AuditEventKind::ModemWatchdog,
        0,
        &status_bytes,
    ));

    // Trigger exception acknowledge via CCIF to initiate dump.
    // Source: §1.8 — force dump via CCIF exception channels
    // SAFETY: shared memory region at START is mapped and within the CCCI
    // aperture. Access is synchronized via CCIF doorbell.
    unsafe {
        mmio::write32(ccif_reg::START, CcifChannel::Exception.mask());
    }

    status
}

// ---------------------------------------------------------------------------
// CCIF mailbox send/receive
// ---------------------------------------------------------------------------

/// CCIF SRAM window size in bytes.
const CCIF_SRAM_SIZE: usize = 512;

/// Send data to the modem via CCIF channel.
///
/// For SRAM-based channels (channel 15), data is written to the SRAM window
/// first, then the channel interrupt is triggered.
///
/// # Safety
///
/// CCIF registers must be mapped.
pub(crate) unsafe fn ccif_send(channel: CcifChannel, data: &[u8]) -> Result<(), CcciError> {
    if data.len() > CCIF_SRAM_SIZE {
        return Err(CcciError::PayloadTooLarge(data.len()));
    }

    // Confirm the modem has consumed any previous message on this channel
    // before overwriting the shared SRAM window (issue #261).
    // SAFETY: shared memory region at BUSY is mapped and within the CCCI
    // aperture. Access is synchronized via CCIF doorbell.
    let busy = unsafe { mmio::read32(ccif_reg::BUSY) };
    if ccif_channel_busy(busy, channel) {
        return Err(CcciError::CcifChannelBusy(channel));
    }

    // Write data to SRAM window (word-aligned writes).
    // Source: §1.2 — APCCIF_CHDATA at offset 0x100
    let sram_base = ccif_reg::CHDATA;
    let mut offset = 0;
    while offset + 4 <= data.len() {
        let word = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        // SAFETY: shared memory region at sram_base+offset is within the CCIF
        // SRAM window (512 bytes). data.len() <= CCIF_SRAM_SIZE checked above.
        // Access is synchronized via CCIF doorbell.
        unsafe {
            mmio::write32(sram_base + offset, word);
        }
        offset += 4;
    }
    // Handle trailing bytes (pad with zeros).
    if offset < data.len() {
        let mut last = [0u8; 4];
        for (i, byte) in data[offset..].iter().enumerate() {
            last[i] = *byte;
        }
        let word = u32::from_le_bytes(last);
        // SAFETY: shared memory region at sram_base+offset is within the CCIF
        // SRAM window. Trailing word is within the validated length bound.
        // Access is synchronized via CCIF doorbell.
        unsafe {
            mmio::write32(sram_base + offset, word);
        }
    }

    // Trigger interrupt to modem on this channel.
    // Source: §1.2 — write channel bit to APCCIF_START
    // SAFETY: shared memory region at START is mapped and within the CCCI
    // aperture. Access is synchronized via CCIF doorbell.
    unsafe {
        mmio::write32(ccif_reg::START, channel.mask());
    }

    Ok(())
}

/// Read data from the CCIF SRAM window.
///
/// SECURITY: Data is copied out of the SRAM window into `buf` before
/// returning. The modem can modify SRAM at any time (TOCTOU defense).
///
/// Returns the number of bytes read (capped by `buf.len()` and SRAM size).
///
/// # Safety
///
/// CCIF registers must be mapped.
pub(crate) unsafe fn ccif_recv(buf: &mut [u8]) -> usize {
    let read_len = buf.len().min(CCIF_SRAM_SIZE);
    let sram_base = ccif_reg::CHDATA;

    // SECURITY: Copy word-by-word from SRAM into local buffer.
    // The modem can modify SRAM concurrently, so we read each word
    // exactly once via volatile read and copy to our buffer.
    let mut offset = 0;
    while offset + 4 <= read_len {
        // SAFETY: shared memory region at sram_base+offset is within the CCIF
        // SRAM window (512 bytes). read_len <= CCIF_SRAM_SIZE ensured above.
        // Access is synchronized via CCIF doorbell.
        let word = unsafe { mmio::read32(sram_base + offset) };
        let bytes = word.to_le_bytes();
        buf[offset] = bytes.get(0).copied().unwrap_or_default();
        buf[offset + 1] = bytes.get(1).copied().unwrap_or_default();
        buf[offset + 2] = bytes.get(2).copied().unwrap_or_default();
        buf[offset + 3] = bytes.get(3).copied().unwrap_or_default();
        offset += 4;
    }
    // Handle trailing bytes.
    if offset < read_len {
        // SAFETY: shared memory region at sram_base+offset is within the CCIF
        // SRAM window. Trailing word is within the validated length bound.
        // Access is synchronized via CCIF doorbell.
        let word = unsafe { mmio::read32(sram_base + offset) };
        let bytes = word.to_le_bytes();
        let remaining = read_len - offset;
        buf[offset..offset + remaining].copy_from_slice(&bytes[..remaining]);
    }

    read_len
}

// ---------------------------------------------------------------------------
// CLDMA ring buffer hardware operations
// ---------------------------------------------------------------------------

/// Start TX DMA on a queue (write to start command register).
///
/// # Safety
///
/// CLDMA PD registers must be mapped and the ring buffer initialized.
pub(crate) unsafe fn cldma_tx_start(queue_mask: u32) {
    // SAFETY: shared memory region at UL_START_CMD is mapped and within the
    // CCCI aperture. Access is synchronized via CCIF doorbell.
    unsafe {
        mmio::write32(cldma_pd::UL_START_CMD, queue_mask);
    }
}

/// Resume TX DMA on a queue after stall.
///
/// # Safety
///
/// CLDMA PD registers must be mapped.
pub(crate) unsafe fn cldma_tx_resume(queue_mask: u32) {
    // SAFETY: shared memory region at UL_RESUME_CMD is mapped and within the
    // CCCI aperture. Access is synchronized via CCIF doorbell.
    unsafe {
        mmio::write32(cldma_pd::UL_RESUME_CMD, queue_mask);
    }
}

/// Stop TX DMA on a queue.
///
/// # Safety
///
/// CLDMA PD registers must be mapped.
pub(crate) unsafe fn cldma_tx_stop(queue_mask: u32) {
    // SAFETY: shared memory region at UL_STOP_CMD is mapped and within the
    // CCCI aperture. Access is synchronized via CCIF doorbell.
    unsafe {
        mmio::write32(cldma_pd::UL_STOP_CMD, queue_mask);
    }
}

/// Start RX DMA.
///
/// # Safety
///
/// CLDMA PD registers must be mapped and the RX ring initialized.
pub(crate) unsafe fn cldma_rx_start(queue_mask: u32) {
    // SAFETY: shared memory region at SO_START_CMD is mapped and within the
    // CCCI aperture. Access is synchronized via CCIF doorbell.
    unsafe {
        mmio::write32(cldma_pd::SO_START_CMD, queue_mask);
    }
}

/// Resume RX DMA after stall.
///
/// # Safety
///
/// CLDMA PD registers must be mapped.
pub(crate) unsafe fn cldma_rx_resume(queue_mask: u32) {
    // SAFETY: shared memory region at SO_RESUME_CMD is mapped and within the
    // CCCI aperture. Access is synchronized via CCIF doorbell.
    unsafe {
        mmio::write32(cldma_pd::SO_RESUME_CMD, queue_mask);
    }
}

/// Stop RX DMA.
///
/// # Safety
///
/// CLDMA PD registers must be mapped.
pub(crate) unsafe fn cldma_rx_stop(queue_mask: u32) {
    // SAFETY: shared memory region at SO_STOP_CMD is mapped and within the
    // CCCI aperture. Access is synchronized via CCIF doorbell.
    unsafe {
        mmio::write32(cldma_pd::SO_STOP_CMD, queue_mask);
    }
}

// ---------------------------------------------------------------------------
// CcciDriver — main driver struct
// ---------------------------------------------------------------------------

/// The CCCI kernel driver.
///
/// Manages the AP↔modem link: CLDMA ring buffers for data, CCIF mailbox
/// for control, identity filtering, and audit logging.
pub(crate) struct CcciDriver {
    /// Current boot step.
    boot_state: BootStep,
    /// TX rings (one per CLDMA queue).
    tx_rings: [TxRing; TX_QUEUE_COUNT],
    /// RX ring (single queue for MT6739).
    rx_ring: RxRing,
    /// Shared memory layout.
    shared_mem: SharedMemLayout,
    /// Kernel audit ring buffer for modem communication logging.
    audit: AuditRing,
    /// Whether identity filtering is active.
    identity_filter_enabled: bool,
    /// Capability mask for the current userspace process context.
    /// SECURITY: identity data passes only if `CAP_MODEM_IDENTITY` is set.
    user_capabilities: u32,
    /// Count of malformed packets dropped at the modem boundary.
    ///
    /// SECURITY: Monotonically increasing. A non-zero or rapidly growing
    /// value indicates the modem is sending garbage — possible attack or
    /// firmware bug.
    malformed_packet_count: u32,
}

impl CcciDriver {
    /// Create a new CCCI driver instance.
    pub(crate) fn new() -> Self {
        Self {
            boot_state: BootStep::EnableClocks,
            tx_rings: [TxRing::new(), TxRing::new(), TxRing::new(), TxRing::new()],
            rx_ring: RxRing::new(),
            shared_mem: SharedMemLayout::mt6739_default(),
            audit: AuditRing::new(),
            identity_filter_enabled: true,
            user_capabilities: 0,
            malformed_packet_count: 0,
        }
    }

    /// Get the current boot state.
    pub(crate) fn boot_state(&self) -> BootStep {
        self.boot_state
    }

    /// Access the audit ring buffer.
    pub(crate) fn audit(&self) -> &AuditRing {
        &self.audit
    }

    /// Mutable access to the audit ring buffer.
    pub(crate) fn audit_mut(&mut self) -> &mut AuditRing {
        &mut self.audit
    }

    /// Set the capability mask for userspace access control.
    pub(crate) fn set_capabilities(&mut self, caps: u32) {
        self.user_capabilities = caps;
    }

    /// Number of malformed packets dropped at the modem boundary.
    ///
    /// SECURITY: A non-zero value means the modem has sent at least one
    /// packet that failed validation. Useful for anomaly detection.
    pub(crate) fn malformed_packet_count(&self) -> u32 {
        self.malformed_packet_count
    }

    /// Record a malformed packet drop. Increments the counter (saturating
    /// to avoid wrapping to zero on a long-running attack).
    fn record_malformed_packet(&mut self) {
        self.malformed_packet_count = self.malformed_packet_count.saturating_add(1);
    }

    /// Execute the 6-step modem boot sequence as a state machine.
    ///
    /// Each call advances one step. Returns the new state on success,
    /// or an error identifying which step failed.
    ///
    /// Source: `eccci/mt6739/md_sys1_platform.c`
    ///
    /// # Safety
    ///
    /// All CCCI-related hardware registers must be mapped (CLDMA, CCIF,
    /// INFRA AO, MD config). Must be called during early boot.
    pub(crate) unsafe fn boot_modem_step(
        &mut self,
        timestamp: u64,
    ) -> Result<BootStep, CcciError> {
        match self.boot_state {
            BootStep::EnableClocks => {
                // Step 1: Enable required clocks.
                // Source: `eccci/mt6739/md_sys1_platform.c:45–52`
                // On bare metal we enable CLDMA via MD_GLOBAL_CON0 bit 12.
                // SAFETY: shared memory region at MD_GLOBAL_CON0 is mapped and
                // within the CCCI aperture. Access is synchronized via CCIF doorbell.
                unsafe {
                    mmio::set_bits(MD_GLOBAL_CON0, MD_GLOBAL_CON0_CLDMA_EN);
                }
                self.audit.record(AuditEntry::new(
                    timestamp,
                    AuditEventKind::BootStateChange,
                    0,
                    b"clocks_enabled",
                ));
                self.boot_state = self.boot_state.next();
                Ok(self.boot_state)
            }

            BootStep::ResetCldma => {
                // Step 2: Hard-reset CLDMA (AO then PD domain).
                // Source: `eccci/mt6739/md_sys1_platform.c:66–102`
                // SAFETY: INFRA reset registers are mapped and within the CCCI
                // aperture. Access is synchronized via CCIF doorbell.
                unsafe {
                    // AO domain reset: set then clear
                    mmio::write32(INFRA_RST0_REG_AO, CLDMA_AO_RST_MASK);
                    mmio::write32(INFRA_RST1_REG_AO, CLDMA_AO_RST_MASK);
                    // PD domain reset: set then clear
                    mmio::write32(INFRA_RST0_REG_PD, CLDMA_PD_RST_MASK);
                    mmio::write32(INFRA_RST1_REG_PD, CLDMA_PD_RST_MASK);
                    // Set CLDMA_IP_BUSY_MASK in control register
                    mmio::set_bits(INFRA_CLDMA_CTRL_REG, CLDMA_IP_BUSY_MASK);
                }
                self.audit.record(AuditEntry::new(
                    timestamp,
                    AuditEventKind::BootStateChange,
                    0,
                    b"cldma_reset",
                ));
                self.boot_state = self.boot_state.next();
                Ok(self.boot_state)
            }

            BootStep::MapHardware => {
                // Step 3: Map hardware from DT.
                // Source: `eccci/mt6739/md_sys1_platform.c:138–148`
                // On bare metal with identity-mapped MMU, the addresses are
                // already accessible. Verify CLDMA is responsive.
                // SAFETY: shared memory region at CLDMA_IP_BUSY is mapped and
                // within the CCCI aperture. Access is synchronized via CCIF doorbell.
                let busy = unsafe { mmio::read32(cldma_pd::CLDMA_IP_BUSY) };
                self.audit.record(AuditEntry::new(
                    timestamp,
                    AuditEventKind::BootStateChange,
                    0,
                    &busy.to_le_bytes(),
                ));
                self.boot_state = self.boot_state.next();
                Ok(self.boot_state)
            }

            BootStep::ReleaseMd => {
                // Step 4: Write MD boot vector, release CPU reset, poll status.
                // Source: §1.5 step 4
                // SAFETY: shared memory region at MD_BOOT_VECTOR_EN and
                // MD1_CFG_BOOT_STATS0 are mapped and within the CCCI aperture.
                // Access is synchronized via CCIF doorbell.
                unsafe {
                    // Enable MD boot vector
                    mmio::write32(MD_BOOT_VECTOR_EN, 1);
                    // Poll boot status registers
                    if !mmio::wait_bits_set(MD1_CFG_BOOT_STATS0, 1, BOOT_POLL_MAX) {
                        return Err(CcciError::BootFailed(BootStep::ReleaseMd));
                    }
                }
                self.audit.record(AuditEntry::new(
                    timestamp,
                    AuditEventKind::BootStateChange,
                    0,
                    b"md_released",
                ));
                self.boot_state = self.boot_state.next();
                Ok(self.boot_state)
            }

            BootStep::SendRuntime => {
                // Step 5: Send runtime data via CCIF H2D_SRAM (channel 15).
                // Source: `eccci/inc/ccci_modem.h:130–172`
                // Send a minimal runtime message with feature negotiation.
                let runtime_msg = CcciHeader::new_control(
                    CcifChannel::Sram as u32,
                    0, // WHY: sequence 0 for initial handshake
                );
                let msg_bytes = runtime_msg.to_bytes();
                // SAFETY: ccif_send accesses CCIF SRAM and START registers which
                // are mapped and within the CCCI aperture. Access is synchronized
                // via CCIF doorbell.
                unsafe {
                    ccif_send(CcifChannel::Sram, &msg_bytes)?;
                }
                self.audit.record(AuditEntry::new(
                    timestamp,
                    AuditEventKind::BootStateChange,
                    CcifChannel::Sram as u32,
                    b"runtime_sent",
                ));
                self.boot_state = self.boot_state.next();
                Ok(self.boot_state)
            }

            BootStep::WaitAck => {
                // Step 6: Wait for MD acknowledge via D2H_SRAM or ring-queue 0.
                // Source: §1.5 step 6
                // SAFETY: shared memory region at RCHNUM is mapped and within
                // the CCCI aperture. Access is synchronized via CCIF doorbell.
                let channels = unsafe { mmio::read32(ccif_reg::RCHNUM) };
                let sram_bit = CcifChannel::Sram.mask();
                let ring0_bit = CcifChannel::RingQ0.mask();

                if channels & (sram_bit | ring0_bit) != 0 {
                    // Acknowledge
                    // SAFETY: shared memory region at ACK is mapped and within
                    // the CCCI aperture. Access is synchronized via CCIF doorbell.
                    unsafe {
                        mmio::write32(ccif_reg::ACK, channels & (sram_bit | ring0_bit));
                    }
                    self.audit.record(AuditEntry::new(
                        timestamp,
                        AuditEventKind::BootStateChange,
                        0,
                        b"md_ack_received",
                    ));
                    self.boot_state = self.boot_state.next();
                    Ok(self.boot_state)
                } else {
                    // NOTE: not ready yet — caller should retry
                    Err(CcciError::Timeout)
                }
            }

            BootStep::Complete => Ok(BootStep::Complete),
        }
    }

    /// Run the full boot sequence to completion.
    ///
    /// # Safety
    ///
    /// Same as `boot_modem_step`.
    pub(crate) unsafe fn boot_modem(&mut self, timestamp: u64) -> Result<(), CcciError> {
        while self.boot_state != BootStep::Complete {
            // SAFETY: same preconditions as boot_modem_step: all CCCI hardware
            // registers must be mapped and the caller is in early boot context.
            unsafe {
                self.boot_modem_step(timestamp)?;
            }
        }
        Ok(())
    }

    /// Process received data from the modem with identity filtering.
    ///
    /// SECURITY: This is the kernel boundary filter. Every byte from the
    /// modem passes through here before reaching userspace.
    ///
    /// 1. Validates the CCCI packet header against the payload buffer
    /// 2. Logs the transmission to the audit ring
    /// 3. Checks for identity patterns (AT+CGSN, AT+CIMI)
    /// 4. Blocks identity data unless caller has `CAP_MODEM_IDENTITY`
    ///
    /// Returns `Ok(true)` if data should be forwarded to userspace,
    /// `Ok(false)` if filtered, or `Err` on validation failure.
    pub(crate) fn process_modem_rx(
        &mut self,
        header: &CcciHeader,
        payload: &[u8],
        timestamp: u64,
    ) -> Result<bool, CcciError> {
        // Step 1: Full packet validation (header + buffer bounds)
        // SECURITY: validate_packet checks channel, length, and offset fields
        // against the actual buffer size.
        if let Err(e) = validate_packet(header, payload.len()) {
            self.record_malformed_packet();
            return Err(e);
        }

        // Step 2: Log to audit ring
        self.audit.record(AuditEntry::new(
            timestamp,
            AuditEventKind::ModemRx,
            header.channel,
            payload,
        ));

        // Step 3: Check for identity patterns on UART channels
        // SECURITY: AT+CGSN (IMEI) and AT+CIMI (IMSI) responses are
        // intercepted here. These channels carry AT command responses.
        if self.identity_filter_enabled && contains_identity_pattern(payload) {
            // Log the interception
            self.audit.record(AuditEntry::new(
                timestamp,
                AuditEventKind::IdentityFiltered,
                header.channel,
                payload,
            ));

            // Step 4: Check capability
            if self.user_capabilities & CAP_MODEM_IDENTITY == 0 {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Validate and copy data from shared memory.
    ///
    /// SECURITY: Bounds-checks the offset, then copies data out of the
    /// shared memory region into `dest`. The copy uses volatile reads to
    /// prevent the modem from modifying data between validation and use
    /// (TOCTOU defense).
    pub(crate) fn copy_from_shared(
        &self,
        region: &SharedMemRegion,
        offset: u32,
        dest: &mut [u8],
    ) -> Result<usize, CcciError> {
        let length = dest.len() as u32;
        region.validate_bounds(offset, length)?;

        // SECURITY: Copy via volatile reads — the modem has DMA access
        // to shared memory and can modify it at any time.
        let base = region.phys_addr(offset) as usize;
        let mut i = 0;
        while i + 4 <= dest.len() {
            // SAFETY: shared memory region at base+i is mapped and within the
            // CCCI aperture; bounds were validated by validate_bounds() above.
            // Access is synchronized via CCIF doorbell.
            let word = unsafe { mmio::read32(base + i) };
            let bytes = word.to_le_bytes();
            dest[i] = bytes.get(0).copied().unwrap_or_default();
            dest[i + 1] = bytes.get(1).copied().unwrap_or_default();
            dest[i + 2] = bytes.get(2).copied().unwrap_or_default();
            dest[i + 3] = bytes.get(3).copied().unwrap_or_default();
            i += 4;
        }
        // Trailing bytes
        if i < dest.len() {
            // SAFETY: shared memory region at base+i is within the validated
            // bounds. Trailing word access is safe after validate_bounds() check.
            let word = unsafe { mmio::read32(base + i) };
            let bytes = word.to_le_bytes();
            let remaining = dest.len() - i;
            dest[i..i + remaining].copy_from_slice(&bytes[..remaining]);
        }

        Ok(dest.len())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use alloc::format;
    use alloc::vec::Vec;

    use super::*;

    // -- Message header encode/decode --

    #[test]
    fn header_roundtrip() {
        let hdr = CcciHeader::new_data(0x1234_5678, 0xABCD_EF01, 5, 0x42);
        let bytes = hdr.to_bytes();
        let decoded = CcciHeader::from_bytes(&bytes)
            .unwrap_or_default();
        assert_eq!(decoded, hdr, "roundtrip must be lossless");
    }

    #[test]
    fn header_control_roundtrip() {
        let hdr = CcciHeader::new_control(1, 0xFF);
        let bytes = hdr.to_bytes();
        let decoded = CcciHeader::from_bytes(&bytes)
            .unwrap_or_default();
        assert!(decoded.is_control(), "control flag must survive roundtrip");
        assert_eq!(decoded.data0, CCCI_MAGIC, "magic must be preserved");
    }

    #[test]
    fn header_from_short_buffer() {
        let short = [0u8; 15];
        assert!(
            CcciHeader::from_bytes(&short).is_none(),
            "must reject buffer shorter than 16 bytes"
        );
    }

    #[test]
    fn header_from_empty_buffer() {
        assert!(
            CcciHeader::from_bytes(&[]).is_none(),
            "must reject empty buffer"
        );
    }

    #[test]
    fn header_magic_validation() {
        let control = CcciHeader::new_control(0, 0);
        assert!(control.is_control(), "control message must have magic");

        let data = CcciHeader::new_data(0x1234, 0, 0, 0);
        assert!(!data.is_control(), "data message must not have magic");
    }

    #[test]
    fn header_validate_good_channel() {
        let hdr = CcciHeader::new_data(0, 0, 5, 0);
        assert!(hdr.validate().is_ok(), "channel 5 should be valid");
    }

    #[test]
    fn header_validate_bad_channel() {
        // WHY: channel 22 is the first unassigned value (valid range 0–21)
        let hdr = CcciHeader::new_data(0, 0, 22, 0);
        assert_eq!(
            hdr.validate(),
            Err(CcciError::InvalidChannel(22)),
            "channel 22 is unassigned and must be rejected"
        );

        let hdr_large = CcciHeader::new_data(0, 0, 0x1_0000, 0);
        assert_eq!(
            hdr_large.validate(),
            Err(CcciError::InvalidChannel(0x1_0000)),
            "channel > 255 must be rejected"
        );
    }

    #[test]
    fn header_debug_format() {
        let hdr = CcciHeader::new_control(7, 0);
        let dbg = format!("{hdr:?}");
        assert!(
            dbg.contains("CcciHeader"),
            "debug output must include type name"
        );
        assert!(
            dbg.contains("0xffffffff"),
            "debug output must show magic value"
        );
    }

    // -- Ring buffer management --

    #[test]
    fn tx_ring_init_chain() {
        let mut ring = TxRing::new();
        let base: u32 = 0x4020_0000;
        ring.init_chain(base);

        assert_eq!(ring.free_count(), TX_RING_SIZE, "all slots must be free after init");
        assert!(ring.is_empty(), "ring must be empty after init");
    }

    #[test]
    fn tx_ring_submit_and_reclaim() {
        let mut ring = TxRing::new();
        ring.init_chain(0x4020_0000);

        // Submit a buffer
        let idx = ring.submit(0x5000_0000, 128).unwrap_or_default();
        assert_eq!(idx, 0, "first submit gets index 0");
        assert_eq!(ring.free_count(), TX_RING_SIZE - 1, "one slot consumed");
        assert!(!ring.is_empty(), "ring is not empty after submit");

        // Simulate hardware completion by clearing HWO on the actual descriptor
        ring.descriptors[0].clear_hw_owned();

        let reclaimed = ring.reclaim();
        assert_eq!(reclaimed, 1, "should reclaim one descriptor");
        assert_eq!(ring.free_count(), TX_RING_SIZE, "all slots free after reclaim");
    }

    #[test]
    fn tx_ring_full() {
        let mut ring = TxRing::new();
        ring.init_chain(0x4020_0000);

        // Fill the ring
        for i in 0..TX_RING_SIZE {
            ring.submit(0x5000_0000 + (u32::try_from(i).unwrap_or_default()) * 0x1000, 64)
                .unwrap_or_default();
        }

        // One more should fail
        let result = ring.submit(0x6000_0000, 64);
        assert_eq!(result, Err(CcciError::RingBufferFull), "must reject when full");
    }

    #[test]
    fn tx_ring_wrap_around() {
        let mut ring = TxRing::new();
        ring.init_chain(0x4020_0000);

        // Fill half, reclaim, fill again to test wrapping
        for i in 0..8 {
            ring.submit(0x5000_0000 + (u32::try_from(i).unwrap_or_default()) * 0x1000, 64)
                .unwrap_or_default();
        }
        // Simulate completion of all 8
        for i in 0..8 {
            ring.descriptors[i].clear_hw_owned();
        }
        ring.reclaim();

        // Submit more — these should wrap around
        for i in 0..TX_RING_SIZE {
            ring.submit(0x6000_0000 + (u32::try_from(i).unwrap_or_default()) * 0x1000, 32)
                .unwrap_or_default();
        }
        assert_eq!(ring.free_count(), 0, "all slots consumed after second fill");
    }

    #[test]
    fn rx_ring_init_and_poll() {
        let mut ring = RxRing::new();
        let base: u32 = 0x4030_0000;
        let buf_addrs: [u32; RX_RING_SIZE] =
            core::array::from_fn(|i| 0x5100_0000 + (u32::try_from(i).unwrap_or_default()) * 0x1000);
        ring.init_chain(base, &buf_addrs, 2048);

        // All descriptors are hardware-owned, so poll should return None
        assert!(ring.poll_rx().is_none(), "no data ready before HW completes");

        // Simulate hardware filling descriptor 0 — must mutate in-place, not a copy
        ring.descriptors[0].clear_hw_owned();
        ring.descriptors[0].recv_len = 256;

        let (idx, len) = ring.poll_rx().unwrap_or_default();
        assert_eq!(idx, 0, "first descriptor should be polled first");
        assert_eq!(len, 256, "received length must match");

        // Rearm the descriptor
        ring.rearm(idx, buf_addrs.get(0).copied().unwrap_or_default(), 2048);
        assert!(
            ring.descriptors[idx].is_hw_owned(),
            "descriptor must be HW-owned after rearm"
        );
    }

    #[test]
    fn rx_ring_clamps_oversized_recv_len_to_buffer_capacity() {
        let mut ring = RxRing::new();
        let base: u32 = 0x4030_0000;
        let buf_addrs: [u32; RX_RING_SIZE] =
            core::array::from_fn(|i| 0x5100_0000 + (u32::try_from(i).unwrap_or_default()) * 0x1000);
        let buf_size: u16 = 2048;
        ring.init_chain(base, &buf_addrs, buf_size);

        // A hostile/malfunctioning modem writes a recv_len larger than the
        // AP-allocated buffer.
        ring.descriptors[0].clear_hw_owned();
        ring.descriptors[0].recv_len = 0xFFFF;

        let (idx, len) = ring.poll_rx().unwrap_or_default();
        assert_eq!(idx, 0, "first descriptor should be polled first");
        assert_eq!(
            len, buf_size,
            "recv_len must be clamped to the descriptor's data_len (buffer capacity)"
        );
    }

    // -- Shared memory bounds checking --

    #[test]
    fn shared_mem_valid_bounds() {
        let region = SharedMemRegion::new(0x8800_0000, 0x0020_0000);
        assert!(
            region.validate_bounds(0, 100).is_ok(),
            "OFFSET 0, len 100 within 2MB region"
        );
        assert!(
            region.validate_bounds(0x001F_FFFC, 4).is_ok(),
            "last 4 bytes of region"
        );
    }

    #[test]
    fn shared_mem_out_of_bounds() {
        let region = SharedMemRegion::new(0x8800_0000, 0x0020_0000);
        assert!(
            region.validate_bounds(0x0020_0000, 1).is_err(),
            "OFFSET at region end is OOB"
        );
        assert!(
            region.validate_bounds(0, 0x0020_0001).is_err(),
            "length exceeding region is OOB"
        );
    }

    #[test]
    fn shared_mem_overflow_attack() {
        let region = SharedMemRegion::new(0x8800_0000, 0x0020_0000);
        // SECURITY: attacker sends offset + length that wraps u32
        assert!(
            region.validate_bounds(0xFFFF_FFF0, 0x20).is_err(),
            "arithmetic overflow must be caught"
        );
    }

    #[test]
    fn shared_mem_zero_length() {
        let region = SharedMemRegion::new(0x8800_0000, 0x0020_0000);
        assert!(
            region.validate_bounds(0, 0).is_ok(),
            "zero-length access is valid"
        );
    }

    #[test]
    fn shared_mem_phys_addr() {
        let region = SharedMemRegion::new(0x8800_0000, 0x0020_0000);
        assert_eq!(
            region.phys_addr(0x100),
            0x8800_0100,
            "physical address must be base + OFFSET"
        );
    }

    // -- Identity filter matching --

    #[test]
    fn identity_filter_cgsn() {
        assert!(
            contains_identity_pattern(b"AT+CGSN\r"),
            "must match IMEI query"
        );
    }

    #[test]
    fn identity_filter_cimi() {
        assert!(
            contains_identity_pattern(b"AT+CIMI\r\n"),
            "must match IMSI query"
        );
    }

    #[test]
    fn identity_filter_response_prefix() {
        assert!(
            contains_identity_pattern(b"+CGSN: 123456789012345\r\n"),
            "must match IMEI response"
        );
        assert!(
            contains_identity_pattern(b"+CIMI: 310260000000000\r\n"),
            "must match IMSI response"
        );
    }

    #[test]
    fn identity_filter_embedded() {
        // SECURITY: modem may embed identity in framed data
        assert!(
            contains_identity_pattern(b"\x00\x00AT+CGSN\r\n\x00"),
            "must detect identity pattern embedded in framing"
        );
    }

    #[test]
    fn identity_filter_no_match() {
        assert!(
            !contains_identity_pattern(b"AT+CSQ\r\n"),
            "signal quality query is not an identity command"
        );
        assert!(
            !contains_identity_pattern(b"OK\r\n"),
            "OK response is not an identity command"
        );
        assert!(
            !contains_identity_pattern(b""),
            "empty buffer should not match"
        );
    }

    #[test]
    fn identity_filter_partial_match() {
        assert!(
            !contains_identity_pattern(b"AT+CGS"),
            "partial CGSN must not match"
        );
        assert!(
            !contains_identity_pattern(b"+CIM"),
            "partial CIMI must not match"
        );
    }

    #[test]
    fn identity_filter_case_insensitive() {
        assert!(
            contains_identity_pattern(b"at+cgsn\r\n"),
            "lowercase 'at+cgsn' must still match the IMEI query pattern"
        );
        assert!(
            contains_identity_pattern(b"+cimi: 310260000000000\r\n"),
            "lowercase '+cimi:' must still match the IMSI response prefix"
        );
        assert!(
            contains_identity_pattern(b"At+CgSn\r\n"),
            "mixed-case 'At+CgSn' must still match"
        );
    }

    #[test]
    fn identity_filter_bare_imei_digits() {
        assert!(
            contains_identity_pattern(b"353882085372845\r\nOK\r\n"),
            "a bare 15-digit IMEI/IMSI response with no +CGSN:/+CIMI: prefix must still be filtered"
        );
    }

    #[test]
    fn identity_filter_bare_digits_wrong_length_no_match() {
        assert!(
            !contains_identity_pattern(b"1234567890\r\nOK\r\n"),
            "a 10-digit run must not be mistaken for a bare IMEI/IMSI (15 digits)"
        );
        assert!(
            !contains_identity_pattern(b"3538820853728451\r\nOK\r\n"),
            "a 16-digit run must not be mistaken for a bare IMEI/IMSI (exactly 15 digits)"
        );
    }

    // -- CCIF channel dispatch --

    #[test]
    fn ccif_channel_from_raw() {
        assert_eq!(
            CcifChannel::from_raw(0),
            Some(CcifChannel::RingQ0),
            "channel 0 is RingQ0"
        );
        assert_eq!(
            CcifChannel::from_raw(15),
            Some(CcifChannel::Sram),
            "channel 15 is SRAM"
        );
        assert_eq!(
            CcifChannel::from_raw(16),
            Some(CcifChannel::Exception),
            "channel 16 is Exception"
        );
        assert_eq!(
            CcifChannel::from_raw(21),
            Some(CcifChannel::SeqError),
            "channel 21 is SeqError"
        );
        assert!(
            CcifChannel::from_raw(22).is_none(),
            "channel 22 is unassigned"
        );
        assert!(
            CcifChannel::from_raw(255).is_none(),
            "channel 255 is unassigned"
        );
    }

    #[test]
    fn ccif_channel_mask() {
        assert_eq!(
            CcifChannel::RingQ0.mask(),
            1,
            "RingQ0 mask is bit 0"
        );
        assert_eq!(
            CcifChannel::Sram.mask(),
            1 << 15,
            "Sram mask is bit 15"
        );
        assert_eq!(
            CcifChannel::Exception.mask(),
            1 << 16,
            "Exception mask is bit 16"
        );
    }

    #[test]
    fn ccif_channel_busy_detects_target_bit() {
        let busy = CcifChannel::Sram.mask();
        assert!(
            ccif_channel_busy(busy, CcifChannel::Sram),
            "BUSY bit set for the target channel must report busy"
        );
        assert!(
            !ccif_channel_busy(busy, CcifChannel::RingQ0),
            "BUSY bit for a different channel must not report busy"
        );
        assert!(
            !ccif_channel_busy(0, CcifChannel::Sram),
            "a clear BUSY register must never report busy"
        );
    }

    #[test]
    fn ccif_parse_multiple_channels() {
        // Simulate SRAM + Exception channels firing
        let raw = CcifChannel::Sram.mask() | CcifChannel::Exception.mask();
        let parsed = parse_ccif_channels(raw);
        let active: Vec<CcifChannel> = parsed.iter().flatten().copied().collect();
        assert!(
            active.contains(&CcifChannel::Sram),
            "must detect SRAM channel"
        );
        assert!(
            active.contains(&CcifChannel::Exception),
            "must detect Exception channel"
        );
        assert_eq!(active.len(), 2, "exactly two channels active");
    }

    // -- Boot sequence state transitions --

    #[test]
    fn boot_step_progression() {
        assert_eq!(
            BootStep::EnableClocks.next(),
            BootStep::ResetCldma,
            "clocks -> reset"
        );
        assert_eq!(
            BootStep::ResetCldma.next(),
            BootStep::MapHardware,
            "reset -> map"
        );
        assert_eq!(
            BootStep::MapHardware.next(),
            BootStep::ReleaseMd,
            "map -> release"
        );
        assert_eq!(
            BootStep::ReleaseMd.next(),
            BootStep::SendRuntime,
            "release -> send"
        );
        assert_eq!(
            BootStep::SendRuntime.next(),
            BootStep::WaitAck,
            "send -> wait"
        );
        assert_eq!(
            BootStep::WaitAck.next(),
            BootStep::Complete,
            "wait -> complete"
        );
        assert_eq!(
            BootStep::Complete.next(),
            BootStep::Complete,
            "complete is terminal"
        );
    }

    #[test]
    fn driver_initial_state() {
        let driver = CcciDriver::new();
        assert_eq!(
            driver.boot_state(),
            BootStep::EnableClocks,
            "driver starts at EnableClocks"
        );
        assert!(
            driver.audit().count() == 0,
            "audit ring starts empty"
        );
    }

    // -- Audit ring buffer --

    #[test]
    fn audit_ring_basic() {
        let mut ring = AuditRing::new();
        assert_eq!(ring.count(), 0, "starts empty");
        assert!(!ring.has_overflowed(), "not overflowed when empty");

        ring.record(AuditEntry::new(
            100,
            AuditEventKind::ModemRx,
            5,
            b"test data",
        ));
        assert_eq!(ring.count(), 1, "one entry after record");
        assert_eq!(ring.total_written(), 1, "total matches");

        let entry = ring.get(0).expect("entry should exist");
        assert_eq!(entry.timestamp, 100, "timestamp preserved");
        assert_eq!(entry.kind, AuditEventKind::ModemRx, "kind preserved");
        assert_eq!(entry.channel, 5, "channel preserved");
        assert_eq!(entry.payload_len, 9, "payload_len is original length");
        assert_eq!(
            &entry.payload[..9],
            b"test data",
            "payload data preserved"
        );
    }

    #[test]
    fn audit_ring_overflow() {
        let mut ring = AuditRing::new();

        // Fill past capacity
        for i in 0..(AUDIT_RING_CAPACITY + 10) {
            ring.record(AuditEntry::new(
                u64::try_from(i).unwrap_or_default(),
                AuditEventKind::ModemTx,
                0,
                &[u8::try_from(i).unwrap_or_default()],
            ));
        }

        assert!(ring.has_overflowed(), "must detect overflow");
        assert_eq!(ring.count(), AUDIT_RING_CAPACITY, "count capped at capacity");
        assert_eq!(
            ring.total_written(),
            (AUDIT_RING_CAPACITY + 10) as u64,
            "total tracks all writes"
        );

        // Oldest available should be entry 10 (first 10 were overwritten)
        let oldest = ring.get(0).expect("entry should exist");
        assert_eq!(
            oldest.timestamp, 10,
            "oldest available should be entry 10"
        );
    }

    #[test]
    fn audit_ring_payload_truncation() {
        let mut ring = AuditRing::new();
        let long_data = [0xAB; 128];
        ring.record(AuditEntry::new(1, AuditEventKind::ModemRx, 0, &long_data));

        let entry = ring.get(0).expect("entry should exist");
        assert_eq!(
            entry.payload_len, 128,
            "payload_len records original length"
        );
        assert_eq!(
            &entry.payload[..AUDIT_PAYLOAD_MAX],
            &[0xAB; AUDIT_PAYLOAD_MAX],
            "truncated payload preserved"
        );
    }

    #[test]
    fn audit_ring_out_of_range() {
        let ring = AuditRing::new();
        assert!(ring.get(0).is_none(), "empty ring returns None for index 0");
        assert!(ring.get(100).is_none(), "out of range returns None");
    }

    // -- CLDMA interrupt parsing --

    #[test]
    fn cldma_tx_interrupt_done() {
        let events = parse_cldma_tx_status(CLDMA_TX_INT_DONE);
        assert_eq!(
            events.get(0).copied().unwrap_or_default(),
            Some(CldmaIrqEvent::TxDone(0x0F)),
            "all 4 queues done"
        );
    }

    #[test]
    fn cldma_tx_interrupt_combined() {
        let status = CLDMA_TX_INT_DONE | CLDMA_TX_INT_ERROR;
        let events = parse_cldma_tx_status(status);
        assert_eq!(events.get(0).copied().unwrap_or_default(), Some(CldmaIrqEvent::TxDone(0x0F)), "done bits");
        assert_eq!(events.get(1).copied().unwrap_or_default(), Some(CldmaIrqEvent::TxError(0x0F)), "error bits");
    }

    #[test]
    fn cldma_rx_interrupt_done() {
        let events = parse_cldma_rx_status(CLDMA_RX_INT_DONE);
        assert_eq!(events.get(0).copied().unwrap_or_default(), Some(CldmaIrqEvent::RxDone), "RX done");
    }

    #[test]
    fn cldma_rx_interrupt_all() {
        let status = CLDMA_RX_INT_DONE | CLDMA_RX_INT_QUEUE_EMPTY | CLDMA_RX_INT_ERROR;
        let events = parse_cldma_rx_status(status);
        assert_eq!(events.get(0).copied().unwrap_or_default(), Some(CldmaIrqEvent::RxDone), "RX done");
        assert_eq!(events.get(1).copied().unwrap_or_default(), Some(CldmaIrqEvent::RxQueueEmpty), "RX empty");
        assert_eq!(events.get(2).copied().unwrap_or_default(), Some(CldmaIrqEvent::RxError), "RX error");
    }

    #[test]
    fn cldma_tx_no_interrupts() {
        let events = parse_cldma_tx_status(0);
        assert!(events.iter().all(|e| e.is_none()), "zero status = no events");
    }

    // -- Process modem RX with identity filtering --

    #[test]
    fn process_rx_normal_data() {
        let mut driver = CcciDriver::new();
        let payload = b"normal modem data";
        // WHY: data0 = payload length, data1 = 0 (no offset), channel 5 (Uart1Rx)
        let hdr = CcciHeader::new_data(payload.len() as u32, 0, 5, 1);

        let result = driver.process_modem_rx(&hdr, payload, 1000);
        assert_eq!(result, Ok(true), "normal data should pass through");
        assert_eq!(driver.audit().count(), 1, "one audit entry for RX");
    }

    #[test]
    fn process_rx_identity_filtered() {
        let mut driver = CcciDriver::new();
        let payload = b"+CGSN: 123456789012345\r\n";
        let hdr = CcciHeader::new_data(payload.len() as u32, 0, 5, 1);

        let result = driver.process_modem_rx(&hdr, payload, 1000);
        assert_eq!(result, Ok(false), "identity response must be filtered");
        // WHY: 2 entries — one for the RX, one for the filter event
        assert_eq!(driver.audit().count(), 2, "RX + filter audit entries");
    }

    #[test]
    fn process_rx_identity_with_capability() {
        let mut driver = CcciDriver::new();
        driver.set_capabilities(CAP_MODEM_IDENTITY);
        let payload = b"+CGSN: 123456789012345\r\n";
        let hdr = CcciHeader::new_data(payload.len() as u32, 0, 5, 1);

        let result = driver.process_modem_rx(&hdr, payload, 1000);
        assert_eq!(
            result,
            Ok(true),
            "identity data passes with capability"
        );
    }

    #[test]
    fn process_rx_invalid_header() {
        let mut driver = CcciDriver::new();
        let hdr = CcciHeader::new_data(0, 0, 0x1_0000, 0);

        let result = driver.process_modem_rx(&hdr, b"data", 1000);
        assert!(result.is_err(), "invalid channel must be rejected");
        assert_eq!(
            driver.malformed_packet_count(),
            1,
            "malformed counter increments on validation failure"
        );
    }

    // -- GPD descriptor flags --

    #[test]
    fn gpd_ownership_flags() {
        let mut gpd = CldmaGpd::zeroed();
        assert!(!gpd.is_hw_owned(), "starts as SW-owned");

        gpd.set_hw_owned();
        assert!(gpd.is_hw_owned(), "set_hw_owned works");

        gpd.clear_hw_owned();
        assert!(!gpd.is_hw_owned(), "clear_hw_owned works");
    }

    #[test]
    fn gpd_recv_len_volatile_reads_current_value() {
        let mut gpd = CldmaGpd::zeroed();
        assert_eq!(gpd.recv_len_volatile(), 0, "starts at zero");
        gpd.recv_len = 42;
        assert_eq!(
            gpd.recv_len_volatile(),
            42,
            "reflects a direct field write (host build has no concurrent DMA writer)"
        );
    }

    // -- Error display --

    #[test]
    fn error_display() {
        let err = CcciError::PayloadTooLarge(4000);
        let msg = format!("{err}");
        assert!(
            msg.contains("4000"),
            "error message must include the payload size"
        );
        assert!(
            msg.contains("3456"),
            "error message must include the MTU"
        );
    }

    // -- CcciChannel (logical) --

    #[test]
    fn ccci_channel_values() {
        assert_eq!(CcciChannel::ControlTx as u32, 0, "control TX is 0");
        assert_eq!(CcciChannel::Uart1Rx as u32, 5, "UART1 RX is 5");
        assert_eq!(CcciChannel::MdLogRx as u32, 21, "MD log RX is 21");
    }

    // -- Packet validation (hardening) --

    #[test]
    fn validate_packet_valid() {
        let payload = b"hello modem";
        let hdr = CcciHeader::new_data(payload.len() as u32, 0, 5, 0);
        assert!(
            validate_packet(&hdr, payload.len()).is_ok(),
            "valid packet with matching length must pass"
        );
    }

    #[test]
    fn validate_packet_control_message() {
        // Control messages have data0 = CCCI_MAGIC, which is large but
        // should not be treated as a length field.
        let hdr = CcciHeader::new_control(5, 0);
        assert!(
            validate_packet(&hdr, 16).is_ok(),
            "control message must pass even though data0 >> buffer_len"
        );
    }

    #[test]
    fn validate_packet_length_exceeds_buffer() {
        let hdr = CcciHeader::new_data(1024, 0, 5, 0);
        let result = validate_packet(&hdr, 64);
        assert_eq!(
            result,
            Err(CcciError::PacketLengthExceeded {
                header_length: 1024,
                buffer_len: 64,
            }),
            "data0 length exceeding buffer must fail"
        );
    }

    #[test]
    fn validate_packet_invalid_channel() {
        let hdr = CcciHeader::new_data(10, 0, 99, 0);
        let result = validate_packet(&hdr, 64);
        assert_eq!(
            result,
            Err(CcciError::InvalidChannel(99)),
            "unknown channel 99 must be rejected"
        );
    }

    #[test]
    fn validate_packet_offset_past_buffer() {
        // data1 used as offset, points past buffer end
        let hdr = CcciHeader::new_data(10, 500, 5, 0);
        let result = validate_packet(&hdr, 64);
        assert_eq!(
            result,
            Err(CcciError::OffsetOutOfBounds {
                offset: 500,
                buffer_len: 64,
            }),
            "data1 offset past buffer must fail"
        );
    }

    #[test]
    fn validate_packet_zero_offset_ok() {
        // data1 = 0 is always valid (no offset)
        let hdr = CcciHeader::new_data(10, 0, 5, 0);
        assert!(
            validate_packet(&hdr, 64).is_ok(),
            "zero offset must pass"
        );
    }

    #[test]
    fn validate_packet_offset_at_boundary() {
        // data1 exactly at buffer_len is valid (points to end, not past)
        let hdr = CcciHeader::new_data(10, 64, 5, 0);
        assert!(
            validate_packet(&hdr, 64).is_ok(),
            "offset == buffer_len must pass (points to end)"
        );
    }

    #[test]
    fn validate_packet_offset_past_boundary() {
        // data1 one past buffer_len is invalid
        let hdr = CcciHeader::new_data(10, 65, 5, 0);
        assert!(
            validate_packet(&hdr, 64).is_err(),
            "offset == buffer_len + 1 must fail"
        );
    }

    // -- Malformed packet counter --

    #[test]
    fn malformed_counter_starts_at_zero() {
        let driver = CcciDriver::new();
        assert_eq!(
            driver.malformed_packet_count(),
            0,
            "counter must start at zero"
        );
    }

    #[test]
    fn malformed_counter_increments_on_bad_channel() {
        let mut driver = CcciDriver::new();
        let hdr = CcciHeader::new_data(4, 0, 99, 0);
        let _ = driver.process_modem_rx(&hdr, b"data", 1000);
        assert_eq!(
            driver.malformed_packet_count(),
            1,
            "counter increments on invalid channel"
        );
    }

    #[test]
    fn malformed_counter_increments_on_bad_length() {
        let mut driver = CcciDriver::new();
        let hdr = CcciHeader::new_data(1000, 0, 5, 0);
        let _ = driver.process_modem_rx(&hdr, b"short", 1000);
        assert_eq!(
            driver.malformed_packet_count(),
            1,
            "counter increments on length mismatch"
        );
    }

    #[test]
    fn malformed_counter_increments_on_bad_offset() {
        let mut driver = CcciDriver::new();
        let hdr = CcciHeader::new_data(4, 9999, 5, 0);
        let _ = driver.process_modem_rx(&hdr, b"data", 1000);
        assert_eq!(
            driver.malformed_packet_count(),
            1,
            "counter increments on offset OOB"
        );
    }

    #[test]
    fn malformed_counter_accumulates() {
        let mut driver = CcciDriver::new();

        // Three different failure modes
        let _ = driver.process_modem_rx(
            &CcciHeader::new_data(0, 0, 99, 0),
            b"data",
            1000,
        );
        let _ = driver.process_modem_rx(
            &CcciHeader::new_data(9999, 0, 5, 0),
            b"data",
            2000,
        );
        let _ = driver.process_modem_rx(
            &CcciHeader::new_data(4, 9999, 5, 0),
            b"data",
            3000,
        );

        assert_eq!(
            driver.malformed_packet_count(),
            3,
            "counter must accumulate across multiple failures"
        );
    }

    #[test]
    fn malformed_counter_not_incremented_on_valid() {
        let mut driver = CcciDriver::new();
        let payload = b"valid data";
        let hdr = CcciHeader::new_data(payload.len() as u32, 0, 5, 0);
        let _ = driver.process_modem_rx(&hdr, payload, 1000);
        assert_eq!(
            driver.malformed_packet_count(),
            0,
            "counter must not increment on valid packet"
        );
    }

    // -- CcciChannel::is_valid --

    #[test]
    fn ccci_channel_is_valid() {
        for ch in 0..=21u32 {
            assert!(
                CcciChannel::is_valid(ch),
                "channel {ch} must be valid"
            );
        }
        assert!(!CcciChannel::is_valid(22), "22 is unassigned");
        assert!(!CcciChannel::is_valid(255), "255 is unassigned");
        assert!(!CcciChannel::is_valid(0x1_0000), "large value is invalid");
    }
}
