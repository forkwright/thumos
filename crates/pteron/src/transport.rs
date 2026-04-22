//! BT HCI transport over STP (Serial Transport Protocol) for the MT6739 combo chip.
//!
//! BT uses STP function type 0. All HCI packets are wrapped in STP frames
//! before transmission to the BTIF UART. Received STP frames are unwrapped
//! and decoded as HCI events.
//!
//! Frame format (DRIVER-INTERFACES.md §2.7):
//! ```text
//! [0x55 0x55] [HDR0] [HDR1] [HDR2] [HDR3] [payload 0..N-1]
//! HDR0[7:4] = function type (0=BT)
//! HDR0[3:0] = sequence number (4-bit, mod-16)
//! HDR1[7:4] = ACK number
//! HDR1[3:0] = payload length bits [11:8]
//! HDR2      = payload length bits [7:0]
//! HDR3      = checksum (XOR of HDR0..HDR2)
//! ```

use snafu::Snafu;

use crate::config::Config;
use crate::hci::{BdAddr, HciCommand, HciEvent, decode_event, encode_command};

// ── Constants ──────────────────────────────────────────────────────────────────

/// STP delimiter bytes that optionally precede every frame.
const STP_DELIMITER: [u8; 2] = [0x55, 0x55];

/// STP header size in bytes (HDR0..HDR3).
const STP_HEADER_LEN: usize = 4;

/// STP delimiter length when enabled.
const STP_DELIMITER_LEN: usize = 2;

/// STP function type for Bluetooth (DRIVER-INTERFACES.md §4.3).
const STP_FUNC_BT: u8 = 0;

/// RX/TX ring buffer capacity mandated by hardware (DRIVER-INTERFACES.md §4.1).
pub(crate) const RING_BUF_SIZE: usize = 2048;

/// Maximum HCI payload in a single STP frame (12-bit length field).
const STP_MAX_PAYLOAD: usize = 0xFFF;

/// Default address-rotation interval: 15 minutes in seconds, matching BLE spec
/// recommendation.
///
/// Kept as a `pub(crate) const` for backward compatibility with external callers; the
/// runtime-tunable entry point is [`Config::rotation_interval_secs`].
///
/// WHY: persistent random addresses allow tracking within a session; rotating at
/// 15-minute boundaries limits the correlation window to spec-recommended duration.
pub(crate) const ROTATION_INTERVAL_SECS: u64 = crate::config::DEFAULT_ROTATION_INTERVAL_SECS;

/// `Own_Address_Type` value for random address (BLE spec Table 7.2).
///
/// WHY: all LE HCI commands that accept an address type must use random (0x01)
/// so the controller sends the random address rather than the burned-in `BD_ADDR`.
pub(crate) const OWN_ADDR_TYPE_RANDOM: u8 = 0x01;

/// IOCTL magic byte for the BT character device (DRIVER-INTERFACES.md §4.2).
pub(crate) const IOCTL_MAGIC: u8 = 0xb0;

// ── IOCTL command numbers ──────────────────────────────────────────────────────

/// Trigger a firmware assert  -  used for diagnostics and crash reporting.
pub(crate) const COMBO_IOCTL_FW_ASSERT: u32 = 0;

/// Enable or disable BT power-save mode.
pub(crate) const COMBO_IOCTL_BT_SET_PSM: u32 = 1;

/// Read the hardware version FROM the combo chip.
pub(crate) const COMBO_IOCTL_BT_IC_HW_VER: u32 = 2;

/// Read the firmware version FROM the combo chip.
pub(crate) const COMBO_IOCTL_BT_IC_FW_VER: u32 = 3;

// ── RPA/NRPA address bit masks ─────────────────────────────────────────────────

/// Mask for the two most-significant bits of byte 5 (MSB) of a BLE random address.
const RANDOM_ADDR_MSB_MASK: u8 = 0b1100_0000;

/// NRPA: two MSBs = 0b00 (BLE spec Vol 6, Part B §1.3.2.2).
///
/// WHY: non-resolvable private addresses provide maximum anonymity when no
/// bonding exists  -  neither the public address nor a resolvable salt is exposed.
const NRPA_MSB_BITS: u8 = 0b0000_0000;

/// RPA: two MSBs = 0b01 (BLE spec Vol 6, Part B §1.3.2.2).
///
/// WHY: resolvable private addresses allow bonded peers to re-identify us via
/// the IRK while remaining opaque to unregistered observers.
const RPA_MSB_BITS: u8 = 0b0100_0000;

/// `HCI_LE_Set_Random_Address` opcode (OGF=0x08, OCF=0x0005).
///
/// WHY: the controller must know the random address before it can use it in
/// advertising or scanning; this command loads it INTO controller memory.
const HCI_LE_SET_RANDOM_ADDR_OPCODE: u16 = (0x08 << 10) | 0x0005;

// ── Error type ─────────────────────────────────────────────────────────────────

/// Errors FROM the STP transport layer.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub(crate) enum Error {
    /// The STP frame header checksum did not match the computed value.
    #[snafu(display("STP checksum mismatch: expected 0x{expected:02X}, got 0x{actual:02X}"))]
    ChecksumMismatch {
        /// Expected checksum.
        expected: u8,
        /// Actual checksum found in frame.
        actual: u8,
    },

    /// The supplied buffer is too short to hold the STP frame.
    #[snafu(display("STP buffer overflow: need {need} bytes, have {have}"))]
    BufferOverflow {
        /// Bytes required.
        need: usize,
        /// Bytes available.
        have: usize,
    },

    /// The STP frame carries the wrong function type for BT.
    #[snafu(display("STP function type mismatch: expected {expected}, got {actual}"))]
    FuncTypeMismatch {
        /// Expected function type.
        expected: u8,
        /// Received function type.
        actual: u8,
    },

    /// The payload length in the STP header exceeds the ring-buffer capacity.
    #[snafu(display("STP payload length {length} exceeds ring-buffer limit {limit}"))]
    PayloadTooLarge {
        /// Payload length FROM the STP header.
        length: usize,
        /// Maximum allowed.
        limit: usize,
    },

    /// The RX ring buffer does not contain a complete STP frame yet.
    #[snafu(display("STP receive buffer underrun: incomplete frame"))]
    RxUnderrun,

    /// HCI event decoding failed.
    #[snafu(display("HCI decode error: {source}"))]
    HciDecode {
        /// Underlying HCI decode error.
        source: crate::hci::Error,
    },

    /// The reset state machine is in an unexpected state for the requested
    /// operation.
    #[snafu(display("transport reset in unexpected state: rstflag={rstflag}"))]
    UnexpectedResetState {
        /// Current rstflag value.
        rstflag: u8,
    },
}

/// Result alias for this module.
pub(crate) type Result<T> = core::result::Result<T, Error>;

// ── Reset state ────────────────────────────────────────────────────────────────

/// Reset state flag VALUES, matching the WMT reset callback contract
/// (DRIVER-INTERFACES.md §4.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[non_exhaustive]
pub(crate) enum RstFlag {
    /// Normal operation  -  no reset in progress.
    Normal = 0,
    /// Reset started  -  HCI traffic must be gated.
    ResetStart = 1,
    /// Reset complete  -  HCI Hardware Error event not yet delivered.
    ResetCompleteEventPending = 2,
    /// Reset complete  -  Hardware Error event injected INTO the RX path.
    ResetCompleteEventDelivered = 3,
}

impl RstFlag {
    const fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Normal,
            1 => Self::ResetStart,
            2 => Self::ResetCompleteEventPending,
            _ => Self::ResetCompleteEventDelivered,
        }
    }
}

// ── Ring buffer ────────────────────────────────────────────────────────────────

/// Fixed-capacity byte ring buffer for HCI/STP framing.
///
/// INVARIANT: `read_pos` and `write_pos` are always in `[0, RING_BUF_SIZE)`.
/// The buffer is full when `(write_pos + 1) % RING_BUF_SIZE == read_pos`.
pub(crate) struct RingBuffer {
    buf: [u8; RING_BUF_SIZE],
    read_pos: usize,
    write_pos: usize,
}

impl RingBuffer {
    /// Construct an empty ring buffer.
    pub(crate) const fn new() -> Self {
        Self {
            buf: [0u8; RING_BUF_SIZE],
            read_pos: 0,
            write_pos: 0,
        }
    }

    /// Return the number of bytes available to read.
    pub(crate) const fn len(&self) -> usize {
        self.write_pos.wrapping_sub(self.read_pos) % RING_BUF_SIZE
    }

    /// Return `true` when the buffer contains no bytes.
    pub(crate) const fn is_empty(&self) -> bool {
        self.read_pos == self.write_pos
    }

    /// Push `data` INTO the ring buffer.
    ///
    /// Returns `false` if there is insufficient space; no bytes are written in
    /// that case.
    pub(crate) fn push(&mut self, data: &[u8]) -> bool {
        let free = RING_BUF_SIZE - 1 - self.len();
        if data.len() > free {
            return false;
        }
        for &byte in data {
            if let Some(slot) = self.buf.get_mut(self.write_pos) {
                *slot = byte;
            }
            self.write_pos = (self.write_pos + 1) % RING_BUF_SIZE;
        }
        true
    }

    /// Peek at the byte at `OFFSET` positions ahead of the read cursor
    /// without consuming it.
    pub(crate) fn peek_at(&self, offset: usize) -> Option<u8> {
        if offset >= self.len() {
            return None;
        }
        self.buf
            .get((self.read_pos + offset) % RING_BUF_SIZE)
            .copied()
    }

    /// Consume `n` bytes FROM the front, copying them INTO `out`.
    ///
    /// Returns `false` if fewer than `n` bytes are available; no bytes are
    /// consumed in that case.
    pub(crate) fn drain_into(&mut self, out: &mut [u8]) -> bool {
        if out.len() > self.len() {
            return false;
        }
        for slot in out.iter_mut() {
            if let Some(&byte) = self.buf.get(self.read_pos) {
                *slot = byte;
            }
            self.read_pos = (self.read_pos + 1) % RING_BUF_SIZE;
        }
        true
    }

    /// Discard `n` bytes FROM the front of the buffer.
    pub(crate) fn skip(&mut self, n: usize) {
        let to_skip = n.min(self.len());
        self.read_pos = (self.read_pos + to_skip) % RING_BUF_SIZE;
    }
}

// ── STP framing ────────────────────────────────────────────────────────────────

/// Encode an HCI packet in an STP frame with BT function type 0.
///
/// Layout: `[0x55, 0x55, HDR0, HDR1, HDR2, HDR3, payload...]`
///
/// # Errors
///
/// Returns [`Error::BufferOverflow`] if `out` is too short for the encoded frame.
/// Returns [`Error::PayloadTooLarge`] if `payload` exceeds the 12-bit STP length
/// field maximum.
pub(crate) fn stp_encode(seq: u8, payload: &[u8], out: &mut [u8]) -> Result<usize> {
    if payload.len() > STP_MAX_PAYLOAD {
        return Err(Error::PayloadTooLarge {
            length: payload.len(),
            limit: STP_MAX_PAYLOAD,
        });
    }
    let total = STP_DELIMITER_LEN + STP_HEADER_LEN + payload.len();
    if out.len() < total {
        return Err(Error::BufferOverflow {
            need: total,
            have: out.len(),
        });
    }

    // INVARIANT: payload.len() <= STP_MAX_PAYLOAD (0xFFF), checked above; fits in u16.
    let plen = u16::try_from(payload.len()).unwrap_or_default();
    let [plen_lo, plen_hi_raw] = plen.to_le_bytes();
    let seq4 = seq & 0x0F;

    // HDR0: function_type(4b) | seq[3:0](4b)
    // WHY: BT function type is 0, so upper nibble is 0x0; lower nibble is sequence.
    let hdr0 = (STP_FUNC_BT << 4) | seq4;
    // HDR1: ack_num(4b) = 0 | payload_len[11:8](4b)
    let hdr1 = plen_hi_raw & 0x0F;
    // HDR2: payload_len[7:0]
    let hdr2 = plen_lo;
    // HDR3: checksum = XOR(HDR0, HDR1, HDR2)
    let hdr3 = hdr0 ^ hdr1 ^ hdr2;

    let (delim_buf, rest) = out.split_at_mut(STP_DELIMITER_LEN);
    let (hdr_buf, payload_buf) = rest.split_at_mut(STP_HEADER_LEN);
    delim_buf.copy_from_slice(&STP_DELIMITER);
    hdr_buf.copy_from_slice(&[hdr0, hdr1, hdr2, hdr3]);

    if let Some(dst) = payload_buf.get_mut(..payload.len()) {
        dst.copy_from_slice(payload);
    }

    Ok(total)
}

/// Decode an STP frame FROM a byte slice, verifying checksum and function type.
///
/// Returns `(payload_slice, frame_total_len)` on success.
///
/// # Errors
///
/// Returns [`Error::RxUnderrun`] if there are not enough bytes for a complete frame.
/// Returns [`Error::ChecksumMismatch`] if HDR3 does not match `XOR(HDR0..HDR2)`.
/// Returns [`Error::FuncTypeMismatch`] if the frame is not for BT (function type 0).
/// Returns [`Error::PayloadTooLarge`] if the declared payload length exceeds the
/// ring-buffer size.
pub(crate) fn stp_decode(data: &[u8]) -> Result<(&[u8], usize)> {
    // Skip optional delimiter bytes
    let start = if data.get(..2) == Some(&STP_DELIMITER) {
        STP_DELIMITER_LEN
    } else {
        0
    };

    let header_end = start + STP_HEADER_LEN;
    let header = data.get(start..header_end).ok_or(Error::RxUnderrun)?;

    let hdr0 = header.first().copied().unwrap_or_default();
    let hdr1 = header.get(1).copied().unwrap_or_default();
    let hdr2 = header.get(2).copied().unwrap_or_default();
    let hdr3 = header.get(3).copied().unwrap_or_default();

    // Verify checksum
    let expected_checksum = hdr0 ^ hdr1 ^ hdr2;
    if hdr3 != expected_checksum {
        return Err(Error::ChecksumMismatch {
            expected: expected_checksum,
            actual: hdr3,
        });
    }

    // Extract function type FROM HDR0[7:4]
    let func_type = (hdr0 >> 4) & 0x0F;
    if func_type != STP_FUNC_BT {
        return Err(Error::FuncTypeMismatch {
            expected: STP_FUNC_BT,
            actual: func_type,
        });
    }

    // Payload length FROM HDR1[3:0] (bits 11:8) and HDR2 (bits 7:0)
    let plen = (usize::from(hdr1 & 0x0F) << 8) | usize::from(hdr2);
    if plen > RING_BUF_SIZE {
        return Err(Error::PayloadTooLarge {
            length: plen,
            limit: RING_BUF_SIZE,
        });
    }

    let payload_start = header_end;
    let payload_end = payload_start + plen;
    let payload = data
        .get(payload_start..payload_end)
        .ok_or(Error::RxUnderrun)?;

    Ok((payload, payload_end))
}

// ── LE Privacy ─────────────────────────────────────────────────────────────────

/// Generate a Non-Resolvable Private Address (NRPA).
///
/// NRPA bit format: two MSBs of byte 5 (the address MSB) are 0b00.
/// All other bits are pseudo-random.
///
/// WHY: used when no bonding exists; provides maximum anonymity because the
/// address cannot be linked to the device even by a paired peer.
///
/// # Errors
///
/// Returns [`Error::BufferOverflow`] if `entropy` does not contain enough bytes.
pub(crate) const fn generate_nrpa(entropy: &[u8; 6]) -> BdAddr {
    let [mut b0, b1, b2, b3, b4, b5] = *entropy;
    // Force two MSBs to 0b00 in the most-significant byte (index 0 = display MSB)
    b0 = (b0 & !RANDOM_ADDR_MSB_MASK) | NRPA_MSB_BITS;
    BdAddr::from_bytes([b0, b1, b2, b3, b4, b5])
}

/// Generate a Resolvable Private Address (RPA) preamble.
///
/// RPA bit format: two MSBs of byte 5 (the address MSB) are 0b01.
/// The lower 22 bits are a random prand; the upper 24 bits (bytes 0-2 in
/// display ORDER) would normally be the hash(IRK, prand) in a full
/// implementation.  This function returns the address with the prand portion
/// SET and the hash portion filled FROM `entropy`, sufficient for address
/// rotation without a full IRK implementation.
///
/// WHY: used when bonding is established; allows the bonded peer to resolve
/// the address via their stored IRK while remaining opaque to others.
pub(crate) const fn generate_rpa(entropy: &[u8; 6]) -> BdAddr {
    let [mut b0, b1, b2, b3, b4, b5] = *entropy;
    // Force two MSBs to 0b01 in the most-significant byte (index 0 = display MSB)
    b0 = (b0 & !RANDOM_ADDR_MSB_MASK) | RPA_MSB_BITS;
    BdAddr::from_bytes([b0, b1, b2, b3, b4, b5])
}

/// Build the `HCI_LE_Set_Random_Address` command packet (OGF=0x08, OCF=0x0005).
///
/// The address bytes are encoded LSB-first per HCI spec §7.8.4.
pub(crate) fn build_le_set_random_address_cmd(addr: &BdAddr) -> Vec<u8> {
    let opcode_bytes = HCI_LE_SET_RANDOM_ADDR_OPCODE.to_le_bytes();
    // H4 type(1) + opcode(2) + param_len(1) + addr(6)
    let mut pkt = Vec::with_capacity(10);
    let [op_lo, op_hi] = opcode_bytes;
    pkt.push(0x01_u8); // H4 command indicator
    pkt.push(op_lo);
    pkt.push(op_hi);
    pkt.push(6_u8); // parameter length: BD_ADDR is always 6 bytes
    // Address is stored MSB-first in BdAddr; HCI wants LSB-first
    let a = addr.as_bytes();
    pkt.push(a.get(5).copied().unwrap_or_default());
    pkt.push(a.get(4).copied().unwrap_or_default());
    pkt.push(a.get(3).copied().unwrap_or_default());
    pkt.push(a.get(2).copied().unwrap_or_default());
    pkt.push(a.get(1).copied().unwrap_or_default());
    pkt.push(a.first().copied().unwrap_or_default());
    pkt
}

// ── Transport struct ───────────────────────────────────────────────────────────

/// BT HCI transport: STP framing, RX/TX ring buffers, reset state, and
/// LE Privacy address management.
///
/// This struct owns the 2048-byte RX and TX ring buffers mandated by the
/// MT6739 hardware character device (DRIVER-INTERFACES.md §4.1).
pub(crate) struct BtHciTransport {
    rx: RingBuffer,
    tx: RingBuffer,

    /// Outbound STP sequence number (4-bit, wraps mod 16).
    tx_seq: u8,

    /// Current reset state (DRIVER-INTERFACES.md §4.4).
    rstflag: RstFlag,

    /// The random address currently loaded INTO the BT controller.
    current_random_addr: Option<BdAddr>,

    /// Seconds elapsed since the last address rotation.
    ///
    /// NOTE: In a real system this would be driven by a hardware timer callback.
    /// Here it is a counter incremented by the caller via [`tick_seconds`].
    secs_since_rotation: u64,

    /// Address-rotation interval in seconds, resolved from [`Config`] at
    /// construction time.
    ///
    /// WHY: stored per-instance so different transports (Daily vs. Sentinel
    /// mode) can use different rotation cadences without a global mutable.
    rotation_interval_secs: u64,
}

impl BtHciTransport {
    /// Create a new transport with empty buffers, normal reset state, and the
    /// default [`Config`] rotation cadence.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self::new_with_config(&Config::default())
    }

    /// Create a new transport with an explicit [`Config`].
    ///
    /// The only currently-tunable knob is
    /// [`Config::rotation_interval_secs`], which controls how often
    /// [`tick_seconds`] signals that a new random address should be installed.
    #[must_use]
    pub(crate) fn new_with_config(config: &Config) -> Self {
        Self {
            rx: RingBuffer::new(),
            tx: RingBuffer::new(),
            tx_seq: 0,
            rstflag: RstFlag::Normal,
            current_random_addr: None,
            secs_since_rotation: 0,
            rotation_interval_secs: config.rotation_interval_secs(),
        }
    }

    // ── Reset state machine ────────────────────────────────────────────────────

    /// Advance the reset state machine to the next state.
    ///
    /// The valid transition sequence is:
    /// `Normal → ResetStart → ResetCompleteEventPending → ResetCompleteEventDelivered → Normal`
    ///
    /// When advancing to `ResetCompleteEventDelivered`, this method injects the
    /// Hardware Error event `{0x04, 0x10, 0x01, 0x00}` INTO the RX ring buffer
    /// so that callers see the same event that real hardware would produce.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnexpectedResetState`] if the transition is not valid.
    pub(crate) fn advance_reset(&mut self) -> Result<RstFlag> {
        let next = match self.rstflag {
            RstFlag::Normal => RstFlag::ResetStart,
            RstFlag::ResetStart => RstFlag::ResetCompleteEventPending,
            RstFlag::ResetCompleteEventPending => {
                // Inject HCI Hardware Error event INTO RX path per DRIVER-INTERFACES.md §4.4.
                // Event: H4=0x04, code=0x10, param_len=0x01, hw_code=0x00
                let hw_error_event: [u8; 4] = [0x04, 0x10, 0x01, 0x00];
                let _ = self.rx.push(&hw_error_event);
                RstFlag::ResetCompleteEventDelivered
            }
            RstFlag::ResetCompleteEventDelivered => RstFlag::Normal,
        };
        self.rstflag = next;
        Ok(next)
    }

    /// Return the current reset state flag.
    pub(crate) const fn rstflag(&self) -> RstFlag {
        self.rstflag
    }

    /// Force the reset state to a specific value (used by WMT reset callback).
    pub(crate) const fn set_rstflag(&mut self, flag: u8) {
        self.rstflag = RstFlag::from_u8(flag);
    }

    // ── TX path ────────────────────────────────────────────────────────────────

    /// Encode an HCI command as an STP frame and place it in the TX ring buffer.
    ///
    /// Returns the number of bytes queued INTO the TX buffer.
    ///
    /// # Errors
    ///
    /// Returns [`Error::BufferOverflow`] if the TX ring buffer does not have
    /// enough space for the encoded frame.
    pub(crate) fn send_command(&mut self, cmd: &HciCommand) -> Result<usize> {
        let hci_bytes = encode_command(cmd);
        let frame_size = STP_DELIMITER_LEN + STP_HEADER_LEN + hci_bytes.len();
        let mut frame_buf = vec![0u8; frame_size];
        let written = stp_encode(self.tx_seq, &hci_bytes, &mut frame_buf)?;
        if !self.tx.push(&frame_buf[..written]) {
            return Err(Error::BufferOverflow {
                need: written,
                have: RING_BUF_SIZE - self.tx.len(),
            });
        }
        self.tx_seq = (self.tx_seq + 1) & 0x0F;
        Ok(written)
    }

    /// Drain up to `out.len()` bytes FROM the TX ring buffer INTO `out`.
    ///
    /// Returns the number of bytes actually drained.
    pub(crate) fn drain_tx(&mut self, out: &mut [u8]) -> usize {
        let available = self.tx.len().min(out.len());
        if available == 0 {
            return 0;
        }
        if self.tx.drain_into(&mut out[..available]) {
            available
        } else {
            0
        }
    }

    // ── RX path ────────────────────────────────────────────────────────────────

    /// Push raw bytes FROM the hardware character device INTO the RX ring buffer.
    ///
    /// Returns `false` if the buffer does not have sufficient free space.
    pub(crate) fn push_rx(&mut self, data: &[u8]) -> bool {
        self.rx.push(data)
    }

    /// Attempt to decode one HCI event FROM the front of the RX ring buffer.
    ///
    /// This method checks whether the RX buffer contains enough bytes for a
    /// complete STP frame (delimiter + header + payload), then decodes the
    /// payload as an HCI event.
    ///
    /// Returns `Ok(None)` when no complete frame is available yet.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ChecksumMismatch`] on STP header corruption.
    /// Returns [`Error::FuncTypeMismatch`] if the frame is not BT function type 0.
    /// Returns [`Error::HciDecode`] if the HCI payload is malformed.
    pub(crate) fn recv_event(&mut self) -> Result<Option<HciEvent>> {
        if self.rx.is_empty() {
            return Ok(None);
        }
        // Need at least delimiter + header
        let min_avail = STP_DELIMITER_LEN + STP_HEADER_LEN;
        if self.rx.len() < min_avail {
            return Ok(None);
        }

        // Peek at enough bytes to determine the payload length without consuming
        // Build a contiguous slice FROM the ring buffer for stp_decode.
        // We read up to RING_BUF_SIZE bytes ahead to find the frame boundary.
        let available = self.rx.len();
        let mut peek_buf = vec![0u8; available];
        for (i, slot) in peek_buf.iter_mut().enumerate() {
            *slot = match self.rx.peek_at(i) {
                Some(b) => b,
                None => break,
            };
        }

        match stp_decode(&peek_buf) {
            Ok((payload, frame_len)) => {
                // We have a complete frame  -  consume it FROM the ring buffer
                self.rx.skip(frame_len);
                let event = decode_event(payload).map_err(|source| Error::HciDecode { source })?;
                Ok(Some(event))
            }
            Err(Error::RxUnderrun) => Ok(None),
            Err(e) => Err(e),
        }
    }

    // ── LE Privacy ─────────────────────────────────────────────────────────────

    /// Set a pre-generated random address by sending `HCI_LE_Set_Random_Address`.
    ///
    /// The HCI command bytes are placed INTO the TX ring buffer via [`send_raw`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::BufferOverflow`] if the TX ring buffer is full.
    pub(crate) fn set_random_address(&mut self, addr: BdAddr) -> Result<usize> {
        let pkt = build_le_set_random_address_cmd(&addr);
        let frame_size = STP_DELIMITER_LEN + STP_HEADER_LEN + pkt.len();
        let mut frame_buf = vec![0u8; frame_size];
        let written = stp_encode(self.tx_seq, &pkt, &mut frame_buf)?;
        if !self.tx.push(&frame_buf[..written]) {
            return Err(Error::BufferOverflow {
                need: written,
                have: RING_BUF_SIZE - self.tx.len(),
            });
        }
        self.tx_seq = (self.tx_seq + 1) & 0x0F;
        self.current_random_addr = Some(addr);
        self.secs_since_rotation = 0;
        Ok(written)
    }

    /// Return the currently active random address, if one has been SET.
    pub(crate) const fn current_random_addr(&self) -> Option<&BdAddr> {
        self.current_random_addr.as_ref()
    }

    /// Advance the rotation timer by `secs` seconds.
    ///
    /// Returns `true` when the rotation interval has elapsed and a new address
    /// should be generated and installed via [`set_random_address`]. The
    /// rotation interval was captured at construction time from [`Config`].
    ///
    /// WHY: the caller drives time in this bare-metal driver; the transport
    /// signals when rotation is due rather than managing entropy itself.
    pub(crate) const fn tick_seconds(&mut self, secs: u64) -> bool {
        self.secs_since_rotation = self.secs_since_rotation.saturating_add(secs);
        if self.secs_since_rotation >= self.rotation_interval_secs {
            self.secs_since_rotation = 0;
            return true;
        }
        false
    }

    /// Return the rotation interval this transport was constructed with.
    pub(crate) const fn rotation_interval_secs(&self) -> u64 {
        self.rotation_interval_secs
    }

    /// Return the number of seconds elapsed since the last address rotation.
    pub(crate) const fn secs_since_rotation(&self) -> u64 {
        self.secs_since_rotation
    }

    // ── LE HCI helpers using random Own_Address_Type ───────────────────────────

    /// Build and enqueue a `LE_Set_Scan_Parameters` command with
    /// `Own_Address_Type = 0x01` (Random).
    ///
    /// # Errors
    ///
    /// Returns [`Error::BufferOverflow`] if the TX ring buffer is full.
    pub(crate) fn send_le_set_scan_parameters(
        &mut self,
        scan_type: u8,
        scan_interval: u16,
        scan_window: u16,
        filter_policy: u8,
    ) -> Result<usize> {
        let cmd = HciCommand::LESetScanParameters {
            scan_type,
            scan_interval,
            scan_window,
            // INVARIANT: Own_Address_Type must always be 0x01 (Random) so the
            // controller uses the loaded random address rather than the permanent BD_ADDR.
            own_address_type: OWN_ADDR_TYPE_RANDOM,
            filter_policy,
        };
        self.send_command(&cmd)
    }
}

impl Default for BtHciTransport {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Ring buffer ──

    #[test]
    fn ring_buffer_starts_empty() {
        let rb = RingBuffer::new();
        assert!(rb.is_empty(), "new ring buffer must be empty");
        assert_eq!(rb.len(), 0, "len must be 0 for an empty ring buffer");
    }

    #[test]
    fn ring_buffer_push_and_drain() {
        let mut rb = RingBuffer::new();
        assert!(rb.push(b"hello"), "push should succeed for small data");
        let mut out = [0u8; 5];
        assert!(rb.drain_into(&mut out), "drain should succeed");
        assert_eq!(&out, b"hello", "drained bytes must match pushed bytes");
    }

    #[test]
    fn ring_buffer_rejects_overflow() {
        let mut rb = RingBuffer::new();
        // Fill the buffer to capacity
        let big = vec![0u8; RING_BUF_SIZE - 1];
        assert!(rb.push(&big), "should accept data up to capacity - 1");
        // One more byte must fail
        assert!(
            !rb.push(b"x"),
            "push beyond capacity must return false, not panic"
        );
    }

    // ── STP encapsulation roundtrip ──

    #[test]
    fn stp_encode_decode_roundtrip() -> Result<()> {
        let payload = b"\x01\x03\x0C\x00"; // HCI Reset command
        let mut buf = [0u8; 64];
        let written = stp_encode(0, payload, &mut buf)?;

        let (decoded_payload, frame_len) = stp_decode(&buf[..written])?;

        assert_eq!(
            decoded_payload, payload,
            "decoded payload must match the original"
        );
        assert_eq!(
            frame_len, written,
            "frame_len must equal the total encoded size"
        );
        Ok(())
    }

    #[test]
    fn stp_encode_sets_bt_function_type() -> Result<()> {
        let payload = b"\x01\x03\x0C\x00";
        let mut buf = [0u8; 64];
        stp_encode(0, payload, &mut buf)?;

        // HDR0 is at OFFSET 2 (after the two delimiter bytes)
        let hdr0 = buf.get(2).copied().unwrap_or_default();
        let func_type = (hdr0 >> 4) & 0x0F;
        assert_eq!(
            func_type, STP_FUNC_BT,
            "STP function type must be 0 (BT) for all BT frames"
        );
        Ok(())
    }

    #[test]
    fn stp_encode_checksum_is_xor_of_header_bytes() -> Result<()> {
        let payload = b"\xDE\xAD";
        let mut buf = [0u8; 64];
        stp_encode(3, payload, &mut buf)?;

        let hdr0 = buf.get(2).copied().unwrap_or_default();
        let hdr1 = buf.get(3).copied().unwrap_or_default();
        let hdr2 = buf.get(4).copied().unwrap_or_default();
        let hdr3 = buf.get(5).copied().unwrap_or_default();
        assert_eq!(
            hdr3,
            hdr0 ^ hdr1 ^ hdr2,
            "HDR3 (checksum) must equal XOR of HDR0, HDR1, HDR2"
        );
        Ok(())
    }

    #[test]
    fn stp_decode_rejects_bad_checksum() -> Result<()> {
        let payload = b"\x01";
        let mut buf = [0u8; 64];
        stp_encode(0, payload, &mut buf)?;
        // Corrupt the checksum byte (HDR3 at OFFSET 5)
        buf[5] ^= 0xFF;

        let result = stp_decode(&buf[..7]);
        assert!(
            matches!(result, Err(Error::ChecksumMismatch { .. })),
            "corrupted checksum must produce ChecksumMismatch error"
        );
        Ok(())
    }

    #[test]
    fn stp_decode_rejects_underrun() {
        // Only 3 bytes  -  not enough for delimiter + header
        let result = stp_decode(&[0x55, 0x55, 0x00]);
        assert!(
            matches!(result, Err(Error::RxUnderrun)),
            "insufficient bytes must produce RxUnderrun error"
        );
    }

    // ── Reset state machine ──

    #[test]
    fn reset_state_machine_normal_transitions() -> Result<()> {
        let mut transport = BtHciTransport::new();
        assert_eq!(
            transport.rstflag(),
            RstFlag::Normal,
            "transport must start in Normal state"
        );

        let s1 = transport.advance_reset()?;
        assert_eq!(
            s1,
            RstFlag::ResetStart,
            "first advance must enter ResetStart"
        );

        let s2 = transport.advance_reset()?;
        assert_eq!(
            s2,
            RstFlag::ResetCompleteEventPending,
            "second advance must enter ResetCompleteEventPending"
        );

        let s3 = transport.advance_reset()?;
        assert_eq!(
            s3,
            RstFlag::ResetCompleteEventDelivered,
            "third advance must enter ResetCompleteEventDelivered"
        );

        let s4 = transport.advance_reset()?;
        assert_eq!(s4, RstFlag::Normal, "fourth advance must return to Normal");
        Ok(())
    }

    #[test]
    fn reset_injects_hardware_error_event_at_state3() -> Result<()> {
        let mut transport = BtHciTransport::new();
        // Advance to the state that injects the Hardware Error event
        transport.advance_reset()?;
        transport.advance_reset()?;
        transport.advance_reset()?;

        // The RX buffer must now contain the Hardware Error event bytes
        assert!(
            !transport.rx.is_empty(),
            "RX buffer must contain the injected Hardware Error event"
        );
        // Event: 0x04 0x10 0x01 0x00
        assert_eq!(
            transport.rx.peek_at(0),
            Some(0x04),
            "first byte of injected event must be 0x04 (H4 event type)"
        );
        assert_eq!(
            transport.rx.peek_at(1),
            Some(0x10),
            "second byte must be 0x10 (Hardware Error event code)"
        );
        assert_eq!(
            transport.rx.peek_at(2),
            Some(0x01),
            "third byte must be 0x01 (param_len)"
        );
        assert_eq!(
            transport.rx.peek_at(3),
            Some(0x00),
            "fourth byte must be 0x00 (hw_code)"
        );
        Ok(())
    }

    // ── Random address format validation ──

    #[test]
    fn nrpa_two_msbs_are_zero() {
        let entropy = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        let addr = generate_nrpa(&entropy);
        let msb = addr.as_bytes()[0];
        assert_eq!(
            msb & RANDOM_ADDR_MSB_MASK,
            NRPA_MSB_BITS,
            "NRPA must have two MSBs = 0b00 (non-resolvable)"
        );
    }

    #[test]
    fn nrpa_lower_bits_preserved() {
        let entropy = [0x3F, 0xAB, 0xCD, 0xEF, 0x12, 0x34];
        let addr = generate_nrpa(&entropy);
        // Lower 6 bits of MSB and all other bytes should be FROM entropy
        assert_eq!(
            addr.as_bytes()[0] & !RANDOM_ADDR_MSB_MASK,
            entropy.first().copied().unwrap_or_default() & !RANDOM_ADDR_MSB_MASK,
            "lower bits of MSB byte must be preserved FROM entropy"
        );
        assert_eq!(
            &addr.as_bytes()[1..],
            &entropy[1..],
            "bytes 1-5 of NRPA must be copied FROM entropy unchanged"
        );
    }

    #[test]
    fn rpa_two_msbs_are_01() {
        let entropy = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let addr = generate_rpa(&entropy);
        let msb = addr.as_bytes()[0];
        assert_eq!(
            msb & RANDOM_ADDR_MSB_MASK,
            RPA_MSB_BITS,
            "RPA must have two MSBs = 0b01 (resolvable)"
        );
    }

    #[test]
    fn rpa_lower_bits_preserved() {
        let entropy = [0x7F, 0x11, 0x22, 0x33, 0x44, 0x55];
        let addr = generate_rpa(&entropy);
        assert_eq!(
            addr.as_bytes()[0] & !RANDOM_ADDR_MSB_MASK,
            entropy.first().copied().unwrap_or_default() & !RANDOM_ADDR_MSB_MASK,
            "lower bits of MSB byte must be preserved FROM entropy"
        );
        assert_eq!(
            &addr.as_bytes()[1..],
            &entropy[1..],
            "bytes 1-5 of RPA must be copied FROM entropy unchanged"
        );
    }

    // ── Address rotation interval ──

    #[test]
    fn rotation_not_triggered_before_interval() {
        let mut transport = BtHciTransport::new();
        // Advance by just under the interval
        let result = transport.tick_seconds(ROTATION_INTERVAL_SECS - 1);
        assert!(
            !result,
            "rotation must not trigger before the 15-minute interval has elapsed"
        );
    }

    #[test]
    fn rotation_triggered_at_interval() {
        let mut transport = BtHciTransport::new();
        let result = transport.tick_seconds(ROTATION_INTERVAL_SECS);
        assert!(
            result,
            "rotation must trigger exactly when the 15-minute interval elapses"
        );
    }

    #[test]
    fn rotation_resets_counter_after_trigger() {
        let mut transport = BtHciTransport::new();
        transport.tick_seconds(ROTATION_INTERVAL_SECS);
        // After a rotation trigger the counter is reset  -  another tick just under
        // the interval must not trigger again immediately.
        let result = transport.tick_seconds(ROTATION_INTERVAL_SECS - 1);
        assert!(
            !result,
            "rotation counter must reset to 0 after triggering; second early tick must not rotate"
        );
    }

    #[test]
    fn custom_config_changes_rotation_interval() {
        // WHY: prove Config.rotation_interval_secs flows through to tick_seconds.
        // A Sentinel-mode transport using 60-second rotation must trigger at
        // 60 s where a default (900 s) transport would not.
        let config = Config {
            rotation_interval_secs: 60,
        };
        let mut transport = BtHciTransport::new_with_config(&config);
        assert_eq!(
            transport.rotation_interval_secs(),
            60,
            "transport must report the configured interval"
        );

        let triggered = transport.tick_seconds(60);
        assert!(
            triggered,
            "rotation must trigger at the configured 60-second interval"
        );

        // A default-configured transport ticked by the same amount must NOT fire.
        let mut default_transport = BtHciTransport::new();
        assert!(
            !default_transport.tick_seconds(60),
            "default 15-minute transport must not rotate after only 60 s"
        );
    }

    #[test]
    fn default_config_matches_historical_const() {
        let transport = BtHciTransport::new();
        assert_eq!(
            transport.rotation_interval_secs(),
            ROTATION_INTERVAL_SECS,
            "default transport must honour the historical 15-minute interval"
        );
    }

    // ── HCI command Own_Address_Type enforcement ──

    #[test]
    fn send_le_set_scan_parameters_uses_random_address_type() -> Result<()> {
        let mut transport = BtHciTransport::new();
        transport.send_le_set_scan_parameters(0x00, 0x0010, 0x0010, 0x00)?;

        // Drain the TX buffer and inspect the encoded HCI command bytes.
        // Layout after STP unwrap: H4(1) + opcode(2) + param_len(1) + scan_type(1)
        //   + interval(2) + window(2) + own_addr_type(1) + filter(1) = 11 HCI bytes
        let mut raw = vec![0u8; RING_BUF_SIZE];
        let drained = transport.drain_tx(&mut raw);
        assert!(drained > 0, "TX buffer must contain the encoded frame");

        // Decode the STP frame to get the HCI payload
        let (payload, _) = stp_decode(&raw[..drained])?;

        // HCI payload: H4=0x01, opcode_lo, opcode_hi, param_len=7,
        //   scan_type, interval_lo, interval_hi, window_lo, window_hi,
        //   own_addr_type, filter_policy
        // own_addr_type is at OFFSET 9 (0-indexed FROM H4 byte)
        let own_addr_type = payload.get(9).copied().ok_or(Error::RxUnderrun)?;
        assert_eq!(
            own_addr_type, OWN_ADDR_TYPE_RANDOM,
            "LE_Set_Scan_Parameters must always use Own_Address_Type = 0x01 (Random)"
        );
        Ok(())
    }

    #[test]
    fn set_random_address_cmd_encodes_lsb_first() {
        let addr = BdAddr::from_bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let pkt = build_le_set_random_address_cmd(&addr);
        // Bytes: H4(1) + opcode(2) + param_len(1) + addr_lsb_first(6) = 10
        assert_eq!(
            pkt.len(),
            10,
            "HCI_LE_Set_Random_Address packet must be 10 bytes"
        );
        assert_eq!(
            pkt.first().copied().unwrap_or_default(),
            0x01,
            "H4 type must be 0x01 (HCI command)"
        );
        // Address starts at OFFSET 4; HCI wants LSB first so 0xFF is first
        assert_eq!(
            pkt.get(4).copied().unwrap_or_default(),
            0xFF,
            "first address byte in HCI packet must be the LSB (0xFF)"
        );
        assert_eq!(
            pkt.get(9).copied().unwrap_or_default(),
            0xAA,
            "last address byte in HCI packet must be the MSB (0xAA)"
        );
    }
}
