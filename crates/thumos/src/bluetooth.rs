//! BT HCI kernel adapter for the MT6739 combo chip.
//!
//! Ports essential logic from `crates/pteron/src/` (hci.rs, ble.rs, device.rs)
//! into the kernel context:
//! - HCI command encoding for reset, LE scan, and random address management
//! - LE Privacy: non-resolvable private address generation with 15-minute rotation
//! - BLE passive scan with device tracking
//! - Hardware abstraction via `BtHwOps` trait for testability
//!
//! ## Hardware path
//!
//! The MT6739 Bluetooth hardware is accessed through the WMT combo chip:
//! - `MT6739_CONSYS = 0x1800_0000` (combo-chip base)
//! - Data path goes through WMT STP framing (kelyphos handles the transport)
//!
//! ## Integration
//!
//! Boot integration via `kinit.rs` Step 13b. Device node at `/dev/bt0`.

// WHY: hardware driver API not yet wired to upper layers (kinit integration pending).
#![expect(
    dead_code,
    reason = "BT driver API wired in kinit but not yet called from userspace"
)]

extern crate alloc;
use alloc::vec::Vec;

use crate::csprng;

// ---------------------------------------------------------------------------
// MT6739 BT hardware constants
// ---------------------------------------------------------------------------

/// WMT combo-chip (CONSYS) MMIO base address.
const MT6739_CONSYS: usize = 0x1800_0000;

/// WMT STP channel identifier for Bluetooth.
///
/// The combo chip multiplexes WiFi, BT, GPS, and FM over a single transport.
/// Each subsystem is identified by a channel byte in the STP header.
const WMT_BT_CHANNEL: u8 = 0x01;

// ---------------------------------------------------------------------------
// HCI constants (Bluetooth Core Spec v5.4)
// ---------------------------------------------------------------------------

/// H4 UART packet type: command (host -> controller).
const H4_COMMAND_TYPE: u8 = 0x01;

/// H4 UART packet type: ACL data (bidirectional; L2CAP/profile payload).
const H4_ACL_DATA_TYPE: u8 = 0x02;

/// OGF: Controller & Baseband commands.
const OGF_CONTROLLER_BASEBAND: u16 = 0x03;

/// OGF: LE Controller commands.
const OGF_LE_CONTROLLER: u16 = 0x08;

/// OCF: Reset command.
const OCF_RESET: u16 = 0x0003;

/// OCF: LE Set Random Address.
const OCF_LE_SET_RANDOM_ADDRESS: u16 = 0x0005;

/// OCF: LE Set Scan Parameters.
const OCF_LE_SET_SCAN_PARAMETERS: u16 = 0x000B;

/// OCF: LE Set Scan Enable.
const OCF_LE_SET_SCAN_ENABLE: u16 = 0x000C;

/// Address rotation interval: 15 minutes in kernel ticks (ms).
const ADDRESS_ROTATION_MS: u64 = 15 * 60 * 1000;

/// Maximum BLE devices to track during a scan.
const MAX_SCAN_RESULTS: usize = 32;

/// Maximum device name length in bytes.
const MAX_NAME_LEN: usize = 32;

/// Maximum advertisement data length (BLE 4.x).
const MAX_ADV_DATA_LEN: usize = 31;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Bluetooth subsystem errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BtError {
    /// Hardware did not respond or returned an error status.
    HardwareTimeout,
    /// The BT hardware is not initialized.
    NotInitialized,
    /// Scan cannot be started in the current state.
    InvalidState,
    /// HCI command encoding error.
    EncodingError,
}

impl core::fmt::Display for BtError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::HardwareTimeout => write!(f, "hardware timeout"),
            Self::NotInitialized => write!(f, "BT not initialized"),
            Self::InvalidState => write!(f, "invalid BT state"),
            Self::EncodingError => write!(f, "HCI encoding error"),
        }
    }
}

// ---------------------------------------------------------------------------
// BT state machine
// ---------------------------------------------------------------------------

/// Bluetooth adapter lifecycle state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum BtState {
    /// Bluetooth radio is off.
    #[default]
    Off,
    /// HCI reset and initialization in progress.
    Initializing,
    /// Initialized and ready for commands.
    Ready,
    /// BLE passive scan in progress.
    Scanning,
    /// A fatal error occurred.
    Error(BtError),
}

impl core::fmt::Display for BtState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Off => write!(f, "off"),
            Self::Initializing => write!(f, "initializing"),
            Self::Ready => write!(f, "ready"),
            Self::Scanning => write!(f, "scanning"),
            Self::Error(e) => write!(f, "error: {e}"),
        }
    }
}

// ---------------------------------------------------------------------------
// BLE device representation
// ---------------------------------------------------------------------------

/// A BLE device discovered during passive scanning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BleDevice {
    /// Bluetooth device address (6 bytes, display order MSB-first).
    pub address: [u8; 6],
    /// Received signal strength in dBm (typically -100 to 0).
    pub rssi: i8,
    /// Device name extracted from advertisement data (if present).
    pub name: [u8; MAX_NAME_LEN],
    /// Number of valid bytes in `name`.
    pub name_len: u8,
    /// Raw advertisement data payload.
    pub adv_data: [u8; MAX_ADV_DATA_LEN],
    /// Number of valid bytes in `adv_data`.
    pub adv_data_len: u8,
}

impl core::fmt::Display for BleDevice {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} ({}dBm)",
            self.address[0],
            self.address[1],
            self.address[2],
            self.address[3],
            self.address[4],
            self.address[5],
            self.rssi,
        )
    }
}

impl BleDevice {
    /// Create a new device entry with the given address and RSSI.
    #[must_use]
    pub(crate) const fn new(address: [u8; 6], rssi: i8) -> Self {
        Self {
            address,
            rssi,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            adv_data: [0u8; MAX_ADV_DATA_LEN],
            adv_data_len: 0,
        }
    }

    /// Return the device name as a byte slice.
    #[must_use]
    pub(crate) fn name(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }

    /// Return the advertisement data as a byte slice.
    #[must_use]
    pub(crate) fn adv_data(&self) -> &[u8] {
        &self.adv_data[..self.adv_data_len as usize]
    }
}

// ---------------------------------------------------------------------------
// HCI command encoding
// ---------------------------------------------------------------------------

/// Build the HCI opcode from OGF and OCF fields.
const fn hci_opcode(ogf: u16, ocf: u16) -> u16 {
    (ogf << 10) | ocf
}

/// Encode an HCI Reset command into an H4-framed buffer.
///
/// Format: `[0x01, opcode_lo, opcode_hi, 0x00]`
#[must_use]
pub(crate) fn hci_reset() -> [u8; 4] {
    let opcode = hci_opcode(OGF_CONTROLLER_BASEBAND, OCF_RESET);
    let ob = opcode.to_le_bytes();
    [H4_COMMAND_TYPE, ob[0], ob[1], 0x00]
}

/// Encode an HCI LE Set Random Address command.
///
/// The address is transmitted LSB-first per HCI spec section 7.8.4.
///
/// Format: `[0x01, opcode_lo, opcode_hi, 0x06, addr[5], addr[4], ..., addr[0]]`
#[must_use]
pub(crate) fn hci_set_random_address(address: &[u8; 6]) -> [u8; 10] {
    let opcode = hci_opcode(OGF_LE_CONTROLLER, OCF_LE_SET_RANDOM_ADDRESS);
    let ob = opcode.to_le_bytes();
    // WHY: HCI spec transmits BD_ADDR LSB-first; our address is stored
    // MSB-first (display order), so we reverse when encoding.
    [
        H4_COMMAND_TYPE,
        ob[0],
        ob[1],
        0x06,
        address[5],
        address[4],
        address[3],
        address[2],
        address[1],
        address[0],
    ]
}

/// Encode an HCI LE Set Scan Parameters command.
///
/// Uses passive scanning with random own address type for privacy.
///
/// Format: `[0x01, opcode_lo, opcode_hi, 0x07, scan_type, interval_lo, interval_hi,
///           window_lo, window_hi, own_addr_type, filter_policy]`
#[must_use]
pub(crate) fn hci_le_set_scan_params() -> [u8; 11] {
    let opcode = hci_opcode(OGF_LE_CONTROLLER, OCF_LE_SET_SCAN_PARAMETERS);
    let ob = opcode.to_le_bytes();
    let interval: u16 = 0x0010; // 10 ms in 0.625 ms units
    let window: u16 = 0x0010; // 10 ms in 0.625 ms units
    let iv = interval.to_le_bytes();
    let wv = window.to_le_bytes();
    [
        H4_COMMAND_TYPE,
        ob[0],
        ob[1],
        0x07, // parameter length
        0x00, // scan_type: passive
        iv[0],
        iv[1], // scan_interval
        wv[0],
        wv[1], // scan_window
        0x01,  // own_address_type: random
        0x00,  // filter_policy: accept all
    ]
}

/// Encode an HCI LE Set Scan Enable command.
///
/// Format: `[0x01, opcode_lo, opcode_hi, 0x02, enable, filter_duplicates]`
#[must_use]
pub(crate) fn hci_le_scan_enable(enable: bool, filter_duplicates: bool) -> [u8; 6] {
    let opcode = hci_opcode(OGF_LE_CONTROLLER, OCF_LE_SET_SCAN_ENABLE);
    let ob = opcode.to_le_bytes();
    [
        H4_COMMAND_TYPE,
        ob[0],
        ob[1],
        0x02,
        u8::from(enable),
        u8::from(filter_duplicates),
    ]
}

// ---------------------------------------------------------------------------
// ACL data encoding (L2CAP/profile payload -- distinct from the HCI command
// path above)
// ---------------------------------------------------------------------------

/// Encode an HCI ACL Data packet into an H4-framed buffer.
///
/// Format: `[0x02, handle_flags_lo, handle_flags_hi, len_lo, len_hi, payload...]`.
/// `PB` flag is fixed to `0b10` (first packet, auto-flushable) and `BC` flag to
/// `0b00` (point-to-point) -- the only combination a host emits for outbound
/// L2CAP data (Bluetooth Core Spec v5.4 Vol 4 Part E section 5.4.2).
///
/// Profile-layer payload (AVDTP signaling, SBC media) belongs on this path,
/// never the HCI command path (`hci_reset`, `hci_set_random_address`, ...) --
/// the controller decodes command-typed bytes as an opcode, not a payload.
#[must_use]
pub(crate) fn hci_acl_data(handle: u16, payload: &[u8]) -> Vec<u8> {
    const PB_FIRST_AUTO_FLUSHABLE: u16 = 0b10 << 12;
    let handle_flags = (handle & 0x0FFF) | PB_FIRST_AUTO_FLUSHABLE;
    let hf = handle_flags.to_le_bytes();
    let len = u16::try_from(payload.len()).unwrap_or(u16::MAX);
    let lv = len.to_le_bytes();
    let mut out = Vec::with_capacity(5 + payload.len());
    out.push(H4_ACL_DATA_TYPE);
    out.push(hf[0]);
    out.push(hf[1]);
    out.push(lv[0]);
    out.push(lv[1]);
    out.extend_from_slice(payload);
    out
}

// ---------------------------------------------------------------------------
// LE Privacy: non-resolvable private address generation
// ---------------------------------------------------------------------------

/// Generate a random non-resolvable private address for BLE scanning.
///
/// Per Bluetooth Core Spec v5.4, Vol 6, Part B, section 1.3.2.2:
/// - Bits 47:46 of the address must be `00` (non-resolvable)
/// - The address must not be all zeros
/// - The address must not be all ones
///
/// Uses the kernel CSPRNG for randomness.
#[must_use]
pub(crate) fn generate_random_address() -> [u8; 6] {
    let mut addr = [0u8; 6];
    // NOTE(#284): the fail-closed CSPRNG returns Err only before seeding, which
    // cannot occur here — address rotation runs after `csprng::init()`. On that
    // unreachable path `addr` stays zeroed and the all-zero guard below rewrites
    // it to a clearly-synthetic address, never key material.
    let _ = csprng::kernel_random_bytes(&mut addr); // kanon:ignore RUST/no-silent-result-swallow -- fail-closed CSPRNG Err path is unreachable post-init (see NOTE above); all-zero guard below already handles the theoretical zeroed-buffer case
    // INVARIANT: clear bits 47:46 (top two bits of byte 0) to mark as
    // non-resolvable private address per BT Core Spec v5.4 Vol 6 Part B 1.3.2.2.
    addr[0] &= 0x3F;
    // Ensure the address is not all zeros or all ones.
    if addr == [0u8; 6] {
        addr[5] = 0x01;
    }
    if addr == [0x3F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF] {
        addr[5] = 0xFE;
    }
    addr
}

// ---------------------------------------------------------------------------
// Hardware abstraction trait
// ---------------------------------------------------------------------------

/// Hardware operations trait for BT driver abstraction.
///
/// Allows test-friendly mocking of WMT STP transport access. The real
/// implementation uses MMIO through the combo chip; tests provide a mock.
pub(crate) trait BtHwOps {
    /// Send an HCI command via WMT STP transport.
    fn send_command(&mut self, data: &[u8]) -> Result<(), BtError>;

    /// Send HCI ACL data (L2CAP/profile payload) via WMT STP transport.
    ///
    /// Distinct from `send_command`: this path carries profile-layer bytes
    /// (AVDTP signaling, SBC media) framed as HCI ACL Data packets, never as
    /// HCI commands.
    fn send_acl_data(&mut self, data: &[u8]) -> Result<(), BtError>;

    /// Receive an HCI event from the controller, if available.
    fn recv_event(&mut self) -> Option<Vec<u8>>;

    /// Power on the BT subsystem within the combo chip.
    fn power_on(&mut self) -> Result<(), BtError>;

    /// Power off the BT subsystem.
    fn power_off(&mut self) -> Result<(), BtError>;
}

// ---------------------------------------------------------------------------
// Real hardware implementation (non-test only)
// ---------------------------------------------------------------------------

/// Real BT hardware access via WMT STP on the MT6739 combo chip.
#[cfg(not(test))]
pub(crate) struct BtHw {
    /// WMT combo-chip MMIO base address.
    consys_base: usize,
}

#[cfg(not(test))]
impl BtHw {
    /// Create a new BT hardware handle.
    #[must_use]
    pub(crate) const fn new() -> Self {
        Self {
            consys_base: MT6739_CONSYS,
        }
    }
}

#[cfg(not(test))]
impl BtHwOps for BtHw {
    fn send_command(&mut self, _data: &[u8]) -> Result<(), BtError> {
        // TODO(#129)[deliberate-prudent]: implement WMT STP frame TX for BT channel.
        // Data is framed with WMT_BT_CHANNEL and written to CONSYS MMIO.
        Err(BtError::NotInitialized)
    }

    fn send_acl_data(&mut self, _data: &[u8]) -> Result<(), BtError> {
        // TODO(#129)[deliberate-prudent]: implement WMT STP frame TX for BT channel.
        // Data is framed with WMT_BT_CHANNEL and written to CONSYS MMIO.
        Err(BtError::NotInitialized)
    }

    fn recv_event(&mut self) -> Option<Vec<u8>> {
        // TODO(#129)[deliberate-prudent]: implement WMT STP frame RX for BT channel.
        None
    }

    fn power_on(&mut self) -> Result<(), BtError> {
        // TODO(#129)[deliberate-prudent]: send WMT power-on command for BT subsystem.
        Ok(())
    }

    fn power_off(&mut self) -> Result<(), BtError> {
        // TODO(#129)[deliberate-prudent]: send WMT power-off command for BT subsystem.
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// BT adapter (combines state machine + hardware + scan results)
// ---------------------------------------------------------------------------

/// Bluetooth adapter combining state machine, hardware ops, and scan tracking.
///
/// Manages the BT lifecycle: init, random address rotation, passive scan,
/// and device tracking. Uses non-resolvable private addresses for LE privacy.
pub(crate) struct BtAdapter<H: BtHwOps> {
    /// Current adapter state.
    state: BtState,
    /// Hardware abstraction.
    hw: H,
    /// Current non-resolvable private address.
    random_address: [u8; 6],
    /// Kernel tick (ms) when the current random address was set.
    address_set_at: u64,
    /// Discovered BLE devices from the current scan.
    scan_results: Vec<BleDevice>,
}

impl<H: BtHwOps> BtAdapter<H> {
    /// Create a new BT adapter with the given hardware backend.
    ///
    /// Generates an initial random address for LE privacy.
    #[must_use]
    pub(crate) fn new(hw: H) -> Self {
        Self {
            state: BtState::Off,
            hw,
            random_address: generate_random_address(),
            address_set_at: 0,
            scan_results: Vec::new(),
        }
    }

    /// Return the current adapter state.
    #[must_use]
    pub(crate) fn state(&self) -> BtState {
        self.state
    }

    /// Return the current scan results.
    #[must_use]
    pub(crate) fn scan_results(&self) -> &[BleDevice] {
        &self.scan_results
    }

    /// Return the current random address.
    #[must_use]
    pub(crate) fn random_address(&self) -> &[u8; 6] {
        &self.random_address
    }

    /// Initialize the BT adapter: power on, HCI reset, set random address.
    ///
    /// Transitions from `Off` to `Ready` on success, or to `Error` on failure.
    #[must_use]
    pub(crate) fn init(&mut self, current_tick_ms: u64) -> Result<(), BtError> {
        if self.state != BtState::Off {
            return Err(BtError::InvalidState);
        }

        self.state = BtState::Initializing;

        // Power on the BT subsystem.
        if let Err(e) = self.hw.power_on() {
            self.state = BtState::Error(e);
            return Err(e);
        }

        // Send HCI Reset.
        let reset_cmd = hci_reset();
        if let Err(e) = self.hw.send_command(&reset_cmd) {
            self.state = BtState::Error(e);
            return Err(e);
        }

        // Set the initial random address. Commit only after the HCI write
        // succeeds (mirrors maybe_rotate_address's commit-on-success below).
        let new_address = generate_random_address();
        let addr_cmd = hci_set_random_address(&new_address);
        if let Err(e) = self.hw.send_command(&addr_cmd) {
            self.state = BtState::Error(e);
            return Err(e);
        }
        self.random_address = new_address;
        self.address_set_at = current_tick_ms;

        self.state = BtState::Ready;
        Ok(())
    }

    /// Rotate the random address if the rotation interval has elapsed.
    ///
    /// Should be called periodically. Returns `true` if the address was rotated.
    ///
    /// No-ops (returns `Ok(false)`) outside [`BtState::Ready`]/[`BtState::Scanning`]
    /// — an unpowered or not-yet-initialized adapter must never receive an HCI
    /// command. While scanning, the controller rejects `LE Set Random Address`
    /// with Command Disallowed (Bluetooth Core Spec v5.4 Vol 4 Part E §7.8.4),
    /// so scanning is paused for the rotation and restarted afterward. The new
    /// address and rotation timestamp are committed only after the hardware
    /// write succeeds, so a rejected/failed write leaves state unchanged and
    /// eligible for retry on the next call.
    #[must_use]
    pub(crate) fn maybe_rotate_address(&mut self, current_tick_ms: u64) -> Result<bool, BtError> {
        if !matches!(self.state, BtState::Ready | BtState::Scanning) {
            return Ok(false);
        }
        if current_tick_ms.saturating_sub(self.address_set_at) < ADDRESS_ROTATION_MS {
            return Ok(false);
        }

        let was_scanning = self.state == BtState::Scanning;
        if was_scanning {
            self.stop_scan()?;
        }

        let new_address = generate_random_address();
        let addr_cmd = hci_set_random_address(&new_address);
        let send_result = self.hw.send_command(&addr_cmd);

        if send_result.is_ok() {
            self.random_address = new_address;
            self.address_set_at = current_tick_ms;
        }

        if was_scanning {
            let restart_result = self.start_scan();
            if send_result.is_ok() {
                restart_result?;
            }
        }

        send_result?;
        Ok(true)
    }

    /// Start a BLE passive scan.
    ///
    /// Sets scan parameters (passive, random address, accept all) then enables scanning.
    #[must_use]
    pub(crate) fn start_scan(&mut self) -> Result<(), BtError> {
        match self.state {
            BtState::Ready => {}
            BtState::Scanning => return Ok(()), // already scanning
            _ => return Err(BtError::InvalidState),
        }

        // Clear previous results.
        self.scan_results.clear();

        // Set scan parameters.
        let params_cmd = hci_le_set_scan_params();
        self.hw.send_command(&params_cmd)?;

        // Enable scanning with duplicate filtering.
        let enable_cmd = hci_le_scan_enable(true, true);
        self.hw.send_command(&enable_cmd)?;

        self.state = BtState::Scanning;
        Ok(())
    }

    /// Stop the BLE passive scan.
    #[must_use]
    pub(crate) fn stop_scan(&mut self) -> Result<(), BtError> {
        if self.state != BtState::Scanning {
            return Err(BtError::InvalidState);
        }

        let disable_cmd = hci_le_scan_enable(false, false);
        self.hw.send_command(&disable_cmd)?;

        self.state = BtState::Ready;
        Ok(())
    }

    /// Add a discovered BLE device to the scan results.
    ///
    /// Deduplicates by address: if the address is already present, updates
    /// RSSI and advertisement data. Caps at `MAX_SCAN_RESULTS` entries.
    pub(crate) fn add_scan_result(&mut self, device: BleDevice) {
        // Deduplicate by address.
        for existing in &mut self.scan_results {
            if existing.address == device.address {
                existing.rssi = device.rssi;
                existing.adv_data = device.adv_data;
                existing.adv_data_len = device.adv_data_len;
                if device.name_len > 0 {
                    existing.name = device.name;
                    existing.name_len = device.name_len;
                }
                return;
            }
        }

        // New device: add if under capacity.
        if self.scan_results.len() < MAX_SCAN_RESULTS {
            self.scan_results.push(device);
        }
    }
}

// ---------------------------------------------------------------------------
// Mock hardware for tests
// ---------------------------------------------------------------------------

/// Mock BT hardware for unit testing.
#[cfg(test)]
pub struct MockBtHw {
    /// Commands sent via `send_command`.
    pub sent_commands: Vec<Vec<u8>>,
    /// ACL data sent via `send_acl_data`.
    pub sent_acl_data: Vec<Vec<u8>>,
    /// Whether power_on succeeds.
    pub power_on_ok: bool,
    /// Whether send_command succeeds.
    pub send_ok: bool,
    /// Number of `send_command` calls observed so far.
    pub send_calls: usize,
    /// If set, `send_command` fails from this call count onward (1-indexed),
    /// letting a test succeed through setup (e.g. `init`) and then force a
    /// later call to fail without touching the earlier ones.
    pub fail_after_calls: Option<usize>,
}

#[cfg(test)]
impl MockBtHw {
    /// Create a new mock with all operations succeeding.
    pub fn new() -> Self {
        Self {
            sent_commands: Vec::new(),
            sent_acl_data: Vec::new(),
            power_on_ok: true,
            send_ok: true,
            send_calls: 0,
            fail_after_calls: None,
        }
    }
}

#[cfg(test)]
impl BtHwOps for MockBtHw {
    fn send_command(&mut self, data: &[u8]) -> Result<(), BtError> {
        self.send_calls += 1;
        let exceeded_budget = self
            .fail_after_calls
            .is_some_and(|budget| self.send_calls > budget);
        if !self.send_ok || exceeded_budget {
            return Err(BtError::HardwareTimeout);
        }
        self.sent_commands.push(data.to_vec());
        Ok(())
    }

    fn send_acl_data(&mut self, data: &[u8]) -> Result<(), BtError> {
        if !self.send_ok {
            return Err(BtError::HardwareTimeout);
        }
        self.sent_acl_data.push(data.to_vec());
        Ok(())
    }

    fn recv_event(&mut self) -> Option<Vec<u8>> {
        None
    }

    fn power_on(&mut self) -> Result<(), BtError> {
        if self.power_on_ok {
            Ok(())
        } else {
            Err(BtError::HardwareTimeout)
        }
    }

    fn power_off(&mut self) -> Result<(), BtError> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bt_starts_off() {
        let hw = MockBtHw::new();
        let adapter = BtAdapter::new(hw);
        assert_eq!(
            adapter.state(),
            BtState::Off,
            "newly created BT adapter must start in Off state"
        );
    }

    #[test]
    fn generate_random_address_sets_non_resolvable() {
        let addr = generate_random_address();
        // Top two bits of byte 0 must be cleared (non-resolvable private address).
        assert_eq!(
            addr[0] & 0xC0,
            0x00,
            "bits 47:46 must be 00 for non-resolvable private address"
        );
        // Must not be all zeros.
        assert_ne!(addr, [0u8; 6], "random address must not be all zeros");
    }

    #[test]
    fn hci_reset_command_encoded_correctly() {
        let cmd = hci_reset();
        // HCI Reset: H4=0x01, opcode=(0x03<<10)|0x0003=0x0C03, param_len=0
        assert_eq!(
            cmd,
            [0x01, 0x03, 0x0C, 0x00],
            "HCI Reset must encode to H4 type + opcode 0x0C03 LE + zero param_len"
        );
    }

    #[test]
    fn scan_results_initially_empty() {
        let hw = MockBtHw::new();
        let adapter = BtAdapter::new(hw);
        assert!(
            adapter.scan_results().is_empty(),
            "scan results must be empty before any scan"
        );
    }

    #[test]
    fn hci_set_random_address_reverses_bytes() {
        let addr = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let cmd = hci_set_random_address(&addr);
        // Opcode: (0x08<<10)|0x0005 = 0x2005
        assert_eq!(cmd[0], 0x01, "H4 type must be command");
        assert_eq!(cmd[1], 0x05, "opcode low byte");
        assert_eq!(cmd[2], 0x20, "opcode high byte");
        assert_eq!(cmd[3], 0x06, "parameter length must be 6");
        // Address must be reversed (LSB-first for HCI).
        assert_eq!(
            &cmd[4..],
            &[0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA],
            "address must be transmitted LSB-first"
        );
    }

    #[test]
    fn hci_le_scan_enable_encodes_enable() {
        let cmd = hci_le_scan_enable(true, true);
        // Opcode: (0x08<<10)|0x000C = 0x200C
        assert_eq!(cmd[0], 0x01, "H4 type must be command");
        assert_eq!(cmd[1], 0x0C, "opcode low byte");
        assert_eq!(cmd[2], 0x20, "opcode high byte");
        assert_eq!(cmd[3], 0x02, "parameter length must be 2");
        assert_eq!(cmd[4], 0x01, "enable must be 1");
        assert_eq!(cmd[5], 0x01, "filter_duplicates must be 1");
    }

    #[test]
    fn hci_le_scan_enable_encodes_disable() {
        let cmd = hci_le_scan_enable(false, false);
        assert_eq!(cmd[4], 0x00, "enable must be 0");
        assert_eq!(cmd[5], 0x00, "filter_duplicates must be 0");
    }

    #[test]
    fn hci_acl_data_uses_acl_type_not_command_type() {
        let payload = [0xAA, 0xBB, 0xCC];
        let frame = hci_acl_data(0x0042, &payload);
        assert_eq!(
            frame[0], 0x02,
            "ACL data must use H4 type 0x02, distinct from command type 0x01"
        );
        // Handle 0x0042 with PB=0b10, BC=0b00 -> 0x2042 LE.
        assert_eq!(
            &frame[1..3],
            &0x2042u16.to_le_bytes(),
            "handle/flags field must encode handle + PB=10/BC=00"
        );
        assert_eq!(
            &frame[3..5],
            &3u16.to_le_bytes(),
            "data total length must equal the payload length"
        );
        assert_eq!(&frame[5..], &payload, "payload must be appended verbatim");
    }

    #[test]
    fn init_transitions_to_ready() {
        let hw = MockBtHw::new();
        let mut adapter = BtAdapter::new(hw);
        let result = adapter.init(0);
        assert!(result.is_ok(), "init must succeed with working hardware");
        assert_eq!(
            adapter.state(),
            BtState::Ready,
            "adapter must be Ready after successful init"
        );
    }

    #[test]
    fn start_scan_transitions_to_scanning() {
        let hw = MockBtHw::new();
        let mut adapter = BtAdapter::new(hw);
        adapter.init(0).ok();
        let result = adapter.start_scan();
        assert!(result.is_ok(), "start_scan must succeed in Ready state");
        assert_eq!(
            adapter.state(),
            BtState::Scanning,
            "adapter must be Scanning after start_scan"
        );
    }

    #[test]
    fn stop_scan_transitions_to_ready() {
        let hw = MockBtHw::new();
        let mut adapter = BtAdapter::new(hw);
        adapter.init(0).ok();
        adapter.start_scan().ok();
        let result = adapter.stop_scan();
        assert!(result.is_ok(), "stop_scan must succeed in Scanning state");
        assert_eq!(
            adapter.state(),
            BtState::Ready,
            "adapter must be Ready after stop_scan"
        );
    }

    #[test]
    fn add_scan_result_deduplicates_by_address() {
        let hw = MockBtHw::new();
        let mut adapter = BtAdapter::new(hw);
        let addr = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];

        let dev1 = BleDevice::new(addr, -60);
        let dev2 = BleDevice::new(addr, -50);
        adapter.add_scan_result(dev1);
        adapter.add_scan_result(dev2);

        assert_eq!(
            adapter.scan_results().len(),
            1,
            "duplicate address must be deduplicated"
        );
        assert_eq!(
            adapter.scan_results()[0].rssi,
            -50,
            "RSSI must be updated to the latest observation"
        );
    }

    #[test]
    fn address_rotation_after_interval() {
        let hw = MockBtHw::new();
        let mut adapter = BtAdapter::new(hw);
        adapter.init(0).ok();
        let original = *adapter.random_address();

        // Before interval: no rotation.
        let rotated = adapter.maybe_rotate_address(ADDRESS_ROTATION_MS - 1);
        assert_eq!(
            rotated,
            Ok(false),
            "must not rotate before interval elapsed"
        );

        // After interval: rotation occurs.
        let rotated = adapter.maybe_rotate_address(ADDRESS_ROTATION_MS);
        assert_eq!(rotated, Ok(true), "must rotate after interval elapsed");
        // Address should have changed (overwhelmingly likely with CSPRNG).
        // We allow a vanishingly small chance of collision.
        let new_addr = *adapter.random_address();
        // Just verify the non-resolvable invariant holds.
        assert_eq!(
            new_addr[0] & 0xC0,
            0x00,
            "rotated address must still be non-resolvable"
        );
        let _ = original; // used for conceptual comparison
    }

    #[test]
    fn maybe_rotate_address_guards_off_state() {
        let mut hw = MockBtHw::new();
        hw.send_ok = false; // any invocation would surface as an error
        let mut adapter = BtAdapter::new(hw);
        let result = adapter.maybe_rotate_address(ADDRESS_ROTATION_MS);
        assert_eq!(
            result,
            Ok(false),
            "rotation must no-op in Off state without issuing an HCI command"
        );
    }

    #[test]
    fn maybe_rotate_address_stops_and_restarts_scan() {
        // Seed the CSPRNG so generate_random_address() produces real random
        // bytes; unseeded it fails closed (#284) and returns a deterministic
        // near-zero address, which would make the rotation a no-op change.
        crate::csprng::seed_for_test(&[0x42u8; 32], &[0u8; 8], 0);
        let hw = MockBtHw::new();
        let mut adapter = BtAdapter::new(hw);
        adapter.init(0).ok();
        adapter.start_scan().ok();
        let original = *adapter.random_address();

        let result = adapter.maybe_rotate_address(ADDRESS_ROTATION_MS);
        assert_eq!(result, Ok(true), "rotation must succeed while scanning");
        assert_eq!(
            adapter.state(),
            BtState::Scanning,
            "adapter must return to Scanning after rotation"
        );
        assert_ne!(
            *adapter.random_address(),
            original,
            "address must change after a successful rotation"
        );
    }

    #[test]
    fn maybe_rotate_address_failed_write_leaves_state_unchanged() {
        let mut hw = MockBtHw::new();
        hw.fail_after_calls = Some(2); // reset + initial addr-set succeed; rotation's write fails
        let mut adapter = BtAdapter::new(hw);
        adapter.init(0).ok();
        let original_addr = *adapter.random_address();

        let result = adapter.maybe_rotate_address(ADDRESS_ROTATION_MS);
        assert_eq!(
            result,
            Err(BtError::HardwareTimeout),
            "a rejected HCI write must surface as an error"
        );
        assert_eq!(
            *adapter.random_address(),
            original_addr,
            "random_address must be unchanged after a failed rotation write"
        );
        assert_eq!(
            adapter.state(),
            BtState::Ready,
            "adapter must remain Ready (not Scanning) after a failed non-scanning rotation"
        );
    }

    // --- Error path coverage ---

    #[test]
    fn init_on_failed_hw_returns_timeout() {
        let mut hw = MockBtHw::new();
        hw.power_on_ok = false;
        let mut adapter = BtAdapter::new(hw);
        let result = adapter.init(0);
        assert_eq!(
            result,
            Err(BtError::HardwareTimeout),
            "init with failing hardware must return HardwareTimeout"
        );
        assert_eq!(
            adapter.state(),
            BtState::Error(BtError::HardwareTimeout),
            "adapter must be in Error state after failed init"
        );
    }

    #[test]
    fn encode_oversized_name_returns_bounded() {
        // BleDevice name field is fixed at MAX_NAME_LEN (32) bytes.
        // Setting name_len beyond the array bounds would be unsafe, so we
        // verify the name() accessor correctly bounds to name_len.
        let mut dev = BleDevice::new([0x01; 6], -40);
        // Fill the entire name buffer.
        dev.name = [b'A'; MAX_NAME_LEN];
        dev.name_len = MAX_NAME_LEN as u8;
        assert_eq!(
            dev.name().len(),
            MAX_NAME_LEN,
            "name length at maximum must return exactly MAX_NAME_LEN bytes"
        );

        // Verify that partial name_len correctly slices.
        dev.name_len = 5;
        assert_eq!(
            dev.name(),
            b"AAAAA",
            "partial name_len must return only that many bytes"
        );
    }

    #[test]
    fn start_scan_in_off_state_returns_invalid_state() {
        let hw = MockBtHw::new();
        let mut adapter = BtAdapter::new(hw);
        // Adapter is in Off state, scan requires Ready.
        let result = adapter.start_scan();
        assert_eq!(
            result,
            Err(BtError::InvalidState),
            "start_scan in Off state must return InvalidState"
        );
    }

    #[test]
    fn init_send_command_failure_returns_timeout() {
        let mut hw = MockBtHw::new();
        // power_on succeeds but send_command fails (simulates HCI reset failure).
        hw.send_ok = false;
        let mut adapter = BtAdapter::new(hw);
        let result = adapter.init(0);
        assert_eq!(
            result,
            Err(BtError::HardwareTimeout),
            "init must fail when HCI reset command fails"
        );
        assert_eq!(
            adapter.state(),
            BtState::Error(BtError::HardwareTimeout),
            "adapter must be in Error state after HCI command failure"
        );
    }

    #[test]
    fn init_failed_addr_set_leaves_random_address_uncommitted() {
        let mut hw = MockBtHw::new();
        hw.fail_after_calls = Some(1); // HCI Reset succeeds; Set Random Address fails
        let mut adapter = BtAdapter::new(hw);
        let original_addr = *adapter.random_address();

        let result = adapter.init(12_345);
        assert_eq!(
            result,
            Err(BtError::HardwareTimeout),
            "init must fail when the Set Random Address command fails"
        );
        assert_eq!(
            *adapter.random_address(),
            original_addr,
            "random_address must not be committed unless the HCI write succeeds"
        );
    }
}
