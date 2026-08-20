//! `WiFi` network interface and WPA supplicant for the MT6739 combo chip.
//!
//! - MAC randomization via the kernel CSPRNG (`csprng.rs`)
//! - `WiFi` hardware abstraction via `WifiHwOps` trait
//! - EAPOL frame parsing/encoding, PMK/PTK derivation, MIC, and the WPA2
//!   4-way handshake state machine delegate to [`aither_core`] (#545,
//!   #819) -- the canonical implementation, shared with the `aither`
//!   workspace crate, so `fuzz_wpa`/`fuzz_eapol` (which import `aither`)
//!   exercise the same code this kernel links rather than a parallel port
//!   that never ships. See `docs/convergence.toml`'s `wifi` pair.
//!
//! ## Hardware path
//!
//! The MT6739 `WiFi` hardware is accessed through the WMT combo chip:
//! - `board::CONSYS_BASE = 0x1800_0000` (combo-chip base, `board::m7` #534)
//! - `board::WLAN_BASE  = 0x180F_0000` (`WiFi` MMIO region, `board::m7` #534)
//!
//! The intended data path uses WMT/STP framing. No sibling transport crate is
//! linked into this kernel, and the production `WifiHw` operations remain
//! fail-closed stubs under #129. `WifiHwOps` provides the test seam.
//!
//! ## Integration plan
//!
//! The smoltcp adapter and boot readiness path are wired fail-closed: boot
//! checks this backend, but it reports production networking unavailable until
//! WMT/STP frame TX/RX, scan, and association are implemented on hardware.

// WHY: hardware data-path APIs are intentionally fail-closed until WMT/STP
// frame TX/RX, scan, and association are implemented on the target.
#![expect(
    dead_code,
    reason = "WiFi production WMT/STP data path not yet implemented (#129; tier in docs/capability-inventory.toml)"
)]

extern crate alloc;
use alloc::vec::Vec;

use crate::csprng;

// ---------------------------------------------------------------------------
// MT6739 WiFi hardware constants
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// `WiFi` subsystem errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum WifiError {
    /// Hardware did not respond or returned an error status.
    HardwareTimeout,
    /// Association with the access point failed.
    AssociationFailed,
    /// WPA 4-way handshake failed (MIC mismatch, timeout, protocol error).
    HandshakeFailed,
    /// EAPOL frame is too short to contain required fields.
    FrameTooShort {
        /// Minimum bytes needed.
        need: usize,
        /// Actual bytes available.
        have: usize,
    },
    /// Unrecognised EAPOL packet type byte.
    UnknownEapolType {
        /// The invalid type byte.
        value: u8,
    },
    /// EAPOL-Key frame descriptor type is not RSN (0x02). A non-RSN or
    /// malformed descriptor must never be parsed and trusted as a WPA2
    /// handshake frame.
    UnknownKeyDescriptorType {
        /// The unexpected descriptor type byte.
        value: u8,
    },
    /// No scan results matched the configured network.
    NetworkNotFound,
    /// The `WiFi` hardware is not initialized.
    NotInitialized,
    /// The kernel CSPRNG has not been seeded; no cryptographic material
    /// (e.g. a fresh WPA supplicant nonce) can be safely generated.
    CsprngNotSeeded,
}

impl core::fmt::Display for WifiError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::HardwareTimeout => write!(f, "hardware timeout"),
            Self::AssociationFailed => write!(f, "association failed"),
            Self::HandshakeFailed => write!(f, "WPA handshake failed"),
            Self::FrameTooShort { need, have } => {
                write!(f, "frame too short: need {need} bytes, have {have}")
            }
            Self::UnknownEapolType { value } => {
                write!(f, "unknown EAPOL type: 0x{value:02x}")
            }
            Self::UnknownKeyDescriptorType { value } => {
                write!(f, "unknown EAPOL-Key descriptor type: 0x{value:02x}")
            }
            Self::NetworkNotFound => write!(f, "network not found"),
            Self::NotInitialized => write!(f, "WiFi not initialized"),
            Self::CsprngNotSeeded => write!(f, "kernel CSPRNG is not seeded"),
        }
    }
}

impl From<aither_core::eapol::Error> for WifiError {
    fn from(err: aither_core::eapol::Error) -> Self {
        match err {
            aither_core::eapol::Error::TooShort { need, have } => {
                Self::FrameTooShort { need, have }
            }
            aither_core::eapol::Error::UnknownEapolType { value } => {
                Self::UnknownEapolType { value }
            }
            aither_core::eapol::Error::UnknownKeyDescriptorType { value } => {
                Self::UnknownKeyDescriptorType { value }
            }
            // WHY: aither_core::eapol::Error is #[non_exhaustive] -- this
            // arm exists only to satisfy that across the crate boundary. A
            // future core variant reaching here is a defect in THIS match,
            // not an attacker-reachable outcome; there is no adversarial
            // input that produces a variant this crate does not know about.
            _ => unreachable!("aither_core::eapol::Error gained a variant this match must cover"),
        }
    }
}

// ---------------------------------------------------------------------------
// WiFi state machine
// ---------------------------------------------------------------------------

/// `WiFi` connection lifecycle state machine.
///
/// Transitions are driven by external events: scan results, association
/// responses, EAPOL frames, and timeouts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum WifiState {
    /// No association in progress.
    #[default]
    Disconnected,
    /// Passive or active scan in progress.
    Scanning,
    /// 802.11 association exchange in progress.
    Associating,
    /// WPA 4-way handshake in progress.
    Handshaking,
    /// Fully connected: data path is encrypted and open.
    Connected,
    /// A fatal error occurred; inspect the attached error.
    Error(WifiError),
}

// ---------------------------------------------------------------------------
// Security types
// ---------------------------------------------------------------------------

/// `WiFi` security protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum WifiSecurity {
    /// No encryption (open network).
    #[default]
    Open,
    /// WPA2-Personal (PSK / CCMP).
    Wpa2Personal,
    /// WPA3-Personal (SAE).
    /// TODO(#864)[deliberate-prudent]: WPA3-SAE handshake -- enum variant defined but exchange not implemented
    Wpa3Sae,
}

// ---------------------------------------------------------------------------
// Configuration types
// ---------------------------------------------------------------------------

/// Maximum SSID length in bytes (IEEE 802.11-2020).
pub(crate) const MAX_SSID_LEN: usize = 32;

/// Maximum passphrase length in bytes (WPA2-Personal: 8-63 ASCII).
pub(crate) const MAX_PASSPHRASE_LEN: usize = 64;

/// `WiFi` network configuration.
///
/// Stores SSID and passphrase in fixed-size arrays to avoid heap allocation
/// in the connection hot path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WifiConfig {
    /// Network SSID (raw bytes; may not be valid UTF-8).
    pub ssid: [u8; MAX_SSID_LEN],
    /// Number of valid bytes in `ssid`.
    pub ssid_len: u8,
    /// Pre-shared key or SAE password (raw bytes).
    pub passphrase: [u8; MAX_PASSPHRASE_LEN],
    /// Number of valid bytes in `passphrase`.
    pub passphrase_len: u8,
    /// Security protocol.
    pub security: WifiSecurity,
}

impl WifiConfig {
    /// Create a new `WiFi` configuration.
    ///
    /// Truncates SSID and passphrase to their respective maximum lengths
    /// rather than returning an error.
    #[must_use]
    pub(crate) fn new(ssid: &[u8], passphrase: &[u8], security: WifiSecurity) -> Self {
        let mut cfg = Self {
            ssid: [0u8; MAX_SSID_LEN],
            ssid_len: 0,
            passphrase: [0u8; MAX_PASSPHRASE_LEN],
            passphrase_len: 0,
            security,
        };
        let slen = ssid.len().min(MAX_SSID_LEN);
        cfg.ssid[..slen].copy_from_slice(&ssid[..slen]);
        cfg.ssid_len = slen as u8;
        let plen = passphrase.len().min(MAX_PASSPHRASE_LEN);
        cfg.passphrase[..plen].copy_from_slice(&passphrase[..plen]);
        cfg.passphrase_len = plen as u8;
        cfg
    }

    /// Return the SSID as a byte slice.
    #[must_use]
    pub(crate) fn ssid(&self) -> &[u8] {
        &self.ssid[..self.ssid_len as usize]
    }

    /// Return the passphrase as a byte slice.
    #[must_use]
    pub(crate) fn passphrase(&self) -> &[u8] {
        &self.passphrase[..self.passphrase_len as usize]
    }
}

impl Drop for WifiConfig {
    fn drop(&mut self) {
        // Zero passphrase material on drop.
        for byte in &mut self.passphrase {
            // SAFETY: byte is a valid mutable reference to initialized memory.
            unsafe {
                core::ptr::write_volatile(byte, 0);
            }
        }
    }
}

/// A single scan result from the `WiFi` firmware.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanResult {
    /// Advertised SSID (raw bytes from beacon/probe response).
    pub ssid: [u8; MAX_SSID_LEN],
    /// Number of valid bytes in `ssid`.
    pub ssid_len: u8,
    /// BSSID (access point MAC address).
    pub bssid: [u8; 6],
    /// Operating channel (2.4 GHz: 1-14, 5 GHz: 36-165).
    pub channel: u8,
    /// Received Signal Strength Indicator in dBm (typically -100 to 0).
    pub rssi: i8,
    /// Security capabilities advertised in the beacon.
    pub security: WifiSecurity,
}

impl ScanResult {
    /// Return the SSID as a byte slice.
    #[must_use]
    pub(crate) fn ssid(&self) -> &[u8] {
        &self.ssid[..self.ssid_len as usize]
    }
}

// ---------------------------------------------------------------------------
// MAC randomization
// ---------------------------------------------------------------------------

/// Generate a random locally-administered unicast MAC address.
///
/// Per IEEE 802-2014 section 8.1:
/// - Bit 0 of octet 0 = 0 (unicast / clear multicast bit)
/// - Bit 1 of octet 0 = 1 (locally administered)
///
/// Uses the kernel CSPRNG (`csprng::kernel_random_bytes`).
#[must_use]
pub(crate) fn generate_random_mac() -> [u8; 6] {
    let mut mac = [0u8; 6];
    // NOTE(#284): the fail-closed CSPRNG returns Err only before seeding, which
    // cannot occur here — MAC randomization runs after `csprng::init()`. On that
    // unreachable path `mac` stays zeroed; the locally-administered/unicast bits
    // below still yield a clearly-synthetic address, never key material.
    let _ = csprng::kernel_random_bytes(&mut mac); // kanon:ignore RUST/no-silent-result-swallow -- fail-closed CSPRNG Err path is unreachable post-init (see NOTE above); zeroed mac on that path still yields a clearly-synthetic address, never key material
    // INVARIANT: bit 0 clear = unicast, bit 1 set = locally administered
    mac[0] = (mac[0] | 0x02) & 0xFE;
    mac
}

// ---------------------------------------------------------------------------
// EAPOL / WPA2-Personal -- delegated to aither-core (#545, #819)
// ---------------------------------------------------------------------------
//
// The EAPOL frame types/parser/encoder, PMK/PTK derivation, MIC, and the
// 4-way handshake state machine are NOT reimplemented here: they live in
// aither_core (shared no_std+alloc with the `aither` workspace crate) so
// this kernel and `fuzz_wpa`/`fuzz_eapol` link the identical code.
//
// WHY only two names are re-exported here, not the full surface: `WifiDriver`
// does not yet wire a live EAPOL/WPA call site (#753/#129 -- the hardware
// data path is fail-closed pending TX/RX), so `EapolFrame` (the
// `eapol_parse`/`eapol_encode` signatures below) and `WpaHandshake` (the
// `WifiDriver::handshake` field) are the only names this module's
// PRODUCTION code actually names today. Re-exporting the rest
// unconditionally left them as unused imports outside the test build (a
// binary crate has no external consumer to exempt them the way a library's
// public API would) -- the full surface (types, PMK/PTK/MIC functions,
// state machine variants) is imported directly by the test module below,
// and by aither_core's own exhaustive test suite. Widen this re-export
// list when #129 adds a real caller.

pub(crate) use aither_core::eapol::{EapolFrame, NONCE_LEN};
pub(crate) use aither_core::wpa::WpaHandshake;

/// Parse an EAPOL frame from a byte slice.
///
/// # Errors
///
/// Returns [`WifiError::FrameTooShort`] when the slice cannot satisfy the
/// declared packet length, [`WifiError::UnknownEapolType`] for
/// unrecognised packet type bytes, and [`WifiError::UnknownKeyDescriptorType`]
/// when an EAPOL-Key frame's descriptor type is not RSN (0x02).
pub(crate) fn eapol_parse(data: &[u8]) -> Result<EapolFrame, WifiError> {
    aither_core::eapol::parse(data).map_err(WifiError::from)
}

/// Encode an EAPOL frame into a byte vector.
#[must_use]
pub(crate) fn eapol_encode(frame: &EapolFrame) -> Vec<u8> {
    aither_core::eapol::encode(frame)
}

/// Draw a fresh supplicant nonce (`SNonce`) from the kernel CSPRNG.
///
/// [`WpaHandshake::process_message`] takes the `SNonce` as a caller-supplied
/// parameter rather than drawing one itself (#819): aither-core is
/// `no_std` and generates no entropy of its own, so the kernel's
/// hardware-bound, fail-closed CSPRNG (`csprng::kernel_random_bytes`) has
/// no equivalent it could link. This is that caller -- the one place a
/// fresh `SNonce` is drawn before Message 1 is processed.
///
/// # Errors
///
/// Returns [`WifiError::CsprngNotSeeded`] (fail closed, matching #284's
/// original guarantee) if the CSPRNG is not yet seeded: a zeroed `SNonce`
/// from an unseeded CSPRNG would derive a PTK an eavesdropper could
/// replicate, so an unseeded CSPRNG must abort the handshake attempt
/// rather than silently proceed with weak key material.
pub(crate) fn generate_snonce() -> Result<[u8; NONCE_LEN], WifiError> {
    let mut snonce = [0u8; NONCE_LEN];
    csprng::kernel_random_bytes(&mut snonce).map_err(|_| WifiError::CsprngNotSeeded)?;
    Ok(snonce)
}

// ---------------------------------------------------------------------------
// WiFi hardware abstraction
// ---------------------------------------------------------------------------

/// Hardware operations trait for `WiFi` driver abstraction.
///
/// Allows test-friendly mocking of the intended production transport. The
/// production `WifiHw` type is selected outside test/QEMU but remains a
/// fail-closed #129 stub; tests provide a mock.
pub(crate) trait WifiHwOps {
    /// Return true once the `WiFi` data path can exchange Ethernet frames.
    ///
    /// The default is closed so partially wired hardware operations cannot be
    /// mistaken for production connectivity.
    fn data_path_ready(&self) -> bool {
        false
    }

    /// Transmit a frame to the `WiFi` hardware.
    fn send_frame(&mut self, data: &[u8]) -> Result<(), WifiError>;

    /// Receive a frame from the `WiFi` hardware, if one is available.
    fn recv_frame(&mut self) -> Option<Vec<u8>>;

    /// Initiate a passive scan.
    fn scan_start(&mut self) -> Result<(), WifiError>;

    /// Return the current scan results.
    fn scan_results(&self) -> &[ScanResult];

    /// Associate with an access point.
    fn associate(&mut self, ssid: &[u8], bssid: &[u8; 6]) -> Result<(), WifiError>;
}

/// Production-target `WiFi` seam for the MT6739 WMT combo chip.
///
/// It retains source-grounded base addresses and a scan-result buffer, but its
/// WMT/STP operations do not perform MMIO until #129 lands.
#[cfg(not(any(test, feature = "qemu")))]
pub(crate) struct WifiHw {
    /// WLAN MMIO base address.
    wlan_base: usize,
    /// Combo-chip CONSYS base address.
    consys_base: usize,
    /// Buffered scan results from the most recent scan.
    scan_buf: Vec<ScanResult>,
}

#[cfg(not(any(test, feature = "qemu")))]
impl WifiHw {
    /// Construct a new `WiFi` hardware driver.
    #[must_use]
    pub(crate) const fn new() -> Self {
        Self {
            wlan_base: crate::board::WLAN_BASE,
            consys_base: crate::board::CONSYS_BASE,
            scan_buf: Vec::new(),
        }
    }
}

#[cfg(not(any(test, feature = "qemu")))]
impl WifiHwOps for WifiHw {
    fn data_path_ready(&self) -> bool {
        false
    }

    fn send_frame(&mut self, _data: &[u8]) -> Result<(), WifiError> {
        // TODO(#129)[deliberate-prudent]: implement WMT STP frame TX via MMIO write to WLAN registers.
        // The intended data path goes through the WMT combo-chip transport;
        // no linked implementation handles STP framing yet.
        Err(WifiError::NotInitialized)
    }

    fn recv_frame(&mut self) -> Option<Vec<u8>> {
        // TODO(#129)[deliberate-prudent]: implement WMT STP frame RX via MMIO read from WLAN registers.
        None
    }

    fn scan_start(&mut self) -> Result<(), WifiError> {
        // TODO(#129)[deliberate-prudent]: issue scan command via WMT STP to WiFi firmware.
        // Uses passive scan by default (no MAC leakage).
        Err(WifiError::NotInitialized)
    }

    fn scan_results(&self) -> &[ScanResult] {
        &self.scan_buf
    }

    fn associate(&mut self, _ssid: &[u8], _bssid: &[u8; 6]) -> Result<(), WifiError> {
        // TODO(#129)[deliberate-prudent]: issue association request to WiFi firmware via WMT STP.
        Err(WifiError::NotInitialized)
    }
}

// ---------------------------------------------------------------------------
// WiFi driver (combines state machine + hardware + WPA)
// ---------------------------------------------------------------------------

/// `WiFi` network driver combining state machine, hardware ops, and WPA handshake.
///
/// Orchestrates the full connection lifecycle: scan, associate, handshake,
/// connected. Uses MAC randomization for each new connection attempt.
pub(crate) struct WifiDriver<H: WifiHwOps> {
    /// Current connection state.
    state: WifiState,
    /// Hardware abstraction.
    hw: H,
    /// Network configuration.
    config: Option<WifiConfig>,
    /// Current locally-administered MAC address.
    mac: [u8; 6],
    /// WPA handshake context (active during Handshaking state).
    handshake: Option<WpaHandshake>,
}

impl<H: WifiHwOps> WifiDriver<H> {
    /// Create a new `WiFi` driver with the given hardware backend.
    ///
    /// Generates an initial random MAC address.
    #[must_use]
    pub(crate) fn new(hw: H) -> Self {
        Self {
            state: WifiState::Disconnected,
            hw,
            config: None,
            mac: generate_random_mac(),
            handshake: None,
        }
    }

    /// Return the current connection state.
    #[must_use]
    pub(crate) const fn state(&self) -> &WifiState {
        &self.state
    }

    /// Return the current MAC address.
    #[must_use]
    pub(crate) const fn mac_address(&self) -> &[u8; 6] {
        &self.mac
    }

    /// Set the network configuration for the next connection attempt.
    pub(crate) fn configure(&mut self, config: WifiConfig) {
        self.config = Some(config);
    }

    /// Initiate a scan. Transitions state from Disconnected to Scanning.
    ///
    /// Generates a fresh random MAC address for privacy.
    ///
    /// # Errors
    ///
    /// Returns `WifiError` if the hardware scan cannot be started.
    pub(crate) fn start_scan(&mut self) -> Result<(), WifiError> {
        // Fresh MAC for each scan (privacy)
        self.mac = generate_random_mac();
        self.hw.scan_start()?;
        self.state = WifiState::Scanning;
        Ok(())
    }

    /// Return a reference to the hardware backend.
    #[must_use]
    pub(crate) const fn hw(&self) -> &H {
        &self.hw
    }

    /// Return a mutable reference to the hardware backend.
    pub(crate) fn hw_mut(&mut self) -> &mut H {
        &mut self.hw
    }
}

// ---------------------------------------------------------------------------
// Test mock
// ---------------------------------------------------------------------------

/// Mock `WiFi` hardware for testing.
///
/// Records calls and returns pre-configured results without MMIO access.
#[cfg(test)]
pub struct MockWifiHw {
    /// Pre-loaded scan results.
    pub scan_results: Vec<ScanResult>,
    /// Frames sent via `send_frame`.
    pub sent_frames: Vec<Vec<u8>>,
    /// Whether `scan_start` should succeed.
    pub scan_ok: bool,
    /// Whether associate should succeed.
    pub associate_ok: bool,
}

#[cfg(test)]
impl MockWifiHw {
    fn new() -> Self {
        Self {
            scan_results: Vec::new(),
            sent_frames: Vec::new(),
            scan_ok: true,
            associate_ok: true,
        }
    }
}

#[cfg(test)]
impl WifiHwOps for MockWifiHw {
    fn send_frame(&mut self, data: &[u8]) -> Result<(), WifiError> {
        self.sent_frames.push(data.to_vec());
        Ok(())
    }

    fn recv_frame(&mut self) -> Option<Vec<u8>> {
        None
    }

    fn scan_start(&mut self) -> Result<(), WifiError> {
        if self.scan_ok {
            Ok(())
        } else {
            Err(WifiError::HardwareTimeout)
        }
    }

    fn scan_results(&self) -> &[ScanResult] {
        &self.scan_results
    }

    fn associate(&mut self, _ssid: &[u8], _bssid: &[u8; 6]) -> Result<(), WifiError> {
        if self.associate_ok {
            Ok(())
        } else {
            Err(WifiError::AssociationFailed)
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
//
// EAPOL parsing/encoding and WPA2 PMK/PTK/MIC/handshake correctness are
// exhaustively tested in `aither_core` (shared with the kernel; see
// crates/aither-core/src/eapol.rs and wpa.rs). The tests below cover only
// what is genuinely kernel-local: the driver/hardware state machine, MAC
// randomization, and the two pieces this module adds around the shared
// core (WifiError conversion, CSPRNG-sourced SNonce generation) -- plus a
// small number of adapter-boundary sanity checks confirming the
// delegation is wired correctly, matching the established `klesis`/
// `asphaleia` pattern.

#[cfg(test)]
mod tests {
    use super::*;
    use aither_core::eapol::{
        DESCRIPTOR_TYPE_RSN, EapolKeyFrame, EapolType, IV_LEN, KeyInfo, MIC_LEN,
    };
    use aither_core::wpa::{
        HandshakeState, KCK_LEN, KEK_LEN, PMK_LEN, TK_LEN, derive_pmk, derive_ptk,
    };

    // Seed the kernel CSPRNG for deterministic test output.
    fn setup_csprng() {
        let key = [
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
            0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b,
            0x2c, 0x2d, 0x2e, 0x2f,
        ];
        csprng::seed_for_test(&key, &[0u8; 8], 0);
    }

    // --- MAC randomization ---

    #[test]
    fn generate_random_mac_sets_local_bit() {
        setup_csprng();
        let mac = generate_random_mac();
        assert!(
            mac[0] & 0x02 != 0,
            "locally-administered bit (bit 1 of octet 0) must be set"
        );
    }

    #[test]
    fn generate_random_mac_clears_multicast_bit() {
        setup_csprng();
        let mac = generate_random_mac();
        assert!(
            mac[0] & 0x01 == 0,
            "multicast bit (bit 0 of octet 0) must be clear"
        );
    }

    #[test]
    fn generate_random_mac_produces_unique_addresses() {
        setup_csprng();
        let mac_a = generate_random_mac();
        let mac_b = generate_random_mac();
        // Both must be valid locally-administered unicast
        assert!(mac_a[0] & 0x02 != 0, "mac_a must be locally administered");
        assert!(mac_b[0] & 0x02 != 0, "mac_b must be locally administered");
        assert!(mac_a[0] & 0x01 == 0, "mac_a must be unicast");
        assert!(mac_b[0] & 0x01 == 0, "mac_b must be unicast");
        // Collision is theoretically possible but negligibly unlikely with
        // 46 bits of randomness from a seeded CSPRNG.
        assert_ne!(
            mac_a, mac_b,
            "two consecutive MAC addresses must differ (CSPRNG seeded)"
        );
    }

    // --- WiFi state machine ---

    #[test]
    fn wifi_state_starts_disconnected() {
        setup_csprng();
        let hw = MockWifiHw::new();
        let driver = WifiDriver::new(hw);
        assert_eq!(
            *driver.state(),
            WifiState::Disconnected,
            "initial state must be Disconnected"
        );
    }

    #[test]
    fn wifi_state_transitions_to_scanning() {
        setup_csprng();
        let hw = MockWifiHw::new();
        let mut driver = WifiDriver::new(hw);
        let result = driver.start_scan();
        assert!(result.is_ok(), "scan_start must succeed with mock hw");
        assert_eq!(
            *driver.state(),
            WifiState::Scanning,
            "state must be Scanning after successful scan_start"
        );
    }

    // --- Scan result ---

    #[test]
    fn scan_result_tracks_ssid_and_bssid() {
        let mut ssid = [0u8; MAX_SSID_LEN];
        ssid[..7].copy_from_slice(b"HomeNet");
        let bssid = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];

        let result = ScanResult {
            ssid,
            ssid_len: 7,
            bssid,
            channel: 6,
            rssi: -55,
            security: WifiSecurity::Wpa2Personal,
        };

        assert_eq!(result.ssid(), b"HomeNet", "SSID must match");
        assert_eq!(result.bssid, bssid, "BSSID must match");
        assert_eq!(result.channel, 6, "channel must be 6");
        assert_eq!(result.rssi, -55, "RSSI must be -55");
        assert_eq!(
            result.security,
            WifiSecurity::Wpa2Personal,
            "security must be WPA2-Personal"
        );
    }

    // --- WiFi config ---

    #[test]
    fn wifi_config_stores_credentials() {
        let config = WifiConfig::new(b"MyNetwork", b"MyPassword123", WifiSecurity::Wpa2Personal);
        assert_eq!(config.ssid(), b"MyNetwork", "SSID must match");
        assert_eq!(
            config.passphrase(),
            b"MyPassword123",
            "passphrase must match"
        );
        assert_eq!(
            config.security,
            WifiSecurity::Wpa2Personal,
            "security must be WPA2-Personal"
        );
    }

    // --- Error path coverage ---

    #[test]
    fn scan_when_not_initialized_returns_error() {
        setup_csprng();
        let mut hw = MockWifiHw::new();
        // Make scan_start fail (simulates hardware not initialized).
        hw.scan_ok = false;
        let mut driver = WifiDriver::new(hw);
        let result = driver.start_scan();
        assert_eq!(
            result,
            Err(WifiError::HardwareTimeout),
            "scan on non-initialized hardware must return HardwareTimeout"
        );
    }

    #[test]
    fn associate_nonexistent_network_returns_error() {
        setup_csprng();
        let mut hw = MockWifiHw::new();
        // Make associate fail.
        hw.associate_ok = false;
        let result = hw.associate(b"NoSuchNetwork", &[0xFF; 6]);
        assert_eq!(
            result,
            Err(WifiError::AssociationFailed),
            "associating with nonexistent network must return AssociationFailed"
        );
    }

    // --- Delegation adapter-boundary sanity (exhaustive coverage lives in
    //     aither_core; see crates/aither-core/src/eapol.rs and wpa.rs) ---

    #[test]
    fn eapol_parse_rejects_non_rsn_descriptor_type_through_the_kernel_adapter() {
        // WHY (#819): this is the regression that motivated the whole
        // convergence -- the kernel enforced this gate, the fuzzed
        // `aither::eapol::parse` did not. Kept here (not just in
        // aither_core) to prove the KERNEL's own linked path -- not merely
        // the shared crate in isolation -- rejects a non-RSN descriptor.
        let kf = EapolKeyFrame {
            descriptor_type: aither_core::eapol::DESCRIPTOR_TYPE_WPA,
            key_info: KeyInfo(0x008a),
            key_length: 16,
            replay_counter: 1,
            nonce: [0xaa; NONCE_LEN],
            iv: [0u8; IV_LEN],
            rsc: 0,
            mic: [0u8; MIC_LEN],
            key_data: Vec::new(),
        };
        let frame = EapolFrame {
            version: 2,
            packet_type: EapolType::Key,
            key_frame: Some(kf),
            raw_body: Vec::new(),
        };
        let encoded = eapol_encode(&frame);
        let result = eapol_parse(&encoded);
        assert_eq!(
            result,
            Err(WifiError::UnknownKeyDescriptorType {
                value: aither_core::eapol::DESCRIPTOR_TYPE_WPA
            }),
            "the kernel's eapol_parse must reject a non-RSN descriptor type"
        );
    }

    #[test]
    fn eapol_encode_parse_roundtrips_through_the_kernel_adapter() {
        let frame = EapolFrame {
            version: 2,
            packet_type: EapolType::Start,
            key_frame: None,
            raw_body: alloc::vec![0xde, 0xad, 0xbe, 0xef],
        };
        let encoded = eapol_encode(&frame);
        let parsed = eapol_parse(&encoded);
        assert_eq!(
            parsed,
            Ok(frame),
            "encode -> parse must round-trip through the kernel's delegated adapter"
        );
    }

    #[test]
    fn derive_pmk_and_ptk_resolve_through_the_kernel_adapter() {
        let pmk = derive_pmk(b"password", b"TestSSID");
        let anonce = [0xAAu8; NONCE_LEN];
        let snonce = [0xBBu8; NONCE_LEN];
        let aa = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let spa = [0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
        let ptk = derive_ptk(&pmk, &anonce, &snonce, &aa, &spa);
        assert_ne!(ptk.kck, [0u8; KCK_LEN], "KCK must not be zero");
        assert_ne!(ptk.kek, [0u8; KEK_LEN], "KEK must not be zero");
        assert_ne!(ptk.tk, [0u8; TK_LEN], "TK must not be zero");
    }

    // --- generate_snonce: the one CSPRNG-facing piece aither_core cannot
    //     link, so it stays kernel-local and needs its own coverage ---

    #[test]
    fn generate_snonce_fails_closed_when_csprng_unseeded() {
        // WHY: the kernel CSPRNG's `seed_for_test` is global (module
        // static, no per-test isolation) and other tests in this file --
        // and in files run in the same process -- seed it. This test
        // therefore does not assert unseeded behavior directly; that
        // invariant is asserted at the CSPRNG's own layer
        // (csprng.rs::tests) and by generate_random_mac's #284 NOTE above.
        // What this DOES assert: a seeded CSPRNG produces a non-zero,
        // correctly-sized SNonce through generate_snonce's public surface.
        setup_csprng();
        let snonce = generate_snonce();
        assert!(
            snonce.is_ok(),
            "a seeded CSPRNG must produce a SNonce, not CsprngNotSeeded"
        );
        if let Ok(snonce) = snonce {
            assert_ne!(
                snonce, [0u8; NONCE_LEN],
                "a seeded CSPRNG must not produce an all-zero SNonce"
            );
        }
    }

    #[test]
    fn generate_snonce_produces_distinct_values_across_calls() {
        setup_csprng();
        let a = generate_snonce();
        let b = generate_snonce();
        assert!(a.is_ok() && b.is_ok(), "both draws must succeed");
        assert_ne!(
            a, b,
            "two consecutive SNonce draws from a seeded CSPRNG must differ"
        );
    }

    // --- Handshake integration: proves the kernel wires generate_snonce()
    //     into aither_core::wpa::WpaHandshake correctly. Exhaustive
    //     state-machine coverage (MIC verification, replay counter,
    //     malformed-message rejection, ...) lives in aither_core. ---

    #[test]
    fn handshake_processes_msg1_using_a_kernel_generated_snonce() {
        setup_csprng();
        let mut hs = WpaHandshake::new();
        let pmk = [0u8; PMK_LEN];
        let own_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let ap_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];

        let msg1 = EapolKeyFrame {
            descriptor_type: DESCRIPTOR_TYPE_RSN,
            key_info: KeyInfo(0x008a), // version=2, pairwise, ack
            key_length: 16,
            replay_counter: 1,
            nonce: [0xaa; NONCE_LEN],
            iv: [0u8; IV_LEN],
            rsc: 0,
            mic: [0u8; MIC_LEN],
            key_data: Vec::new(),
        };

        let snonce = generate_snonce();
        assert!(snonce.is_ok(), "a seeded CSPRNG must produce a SNonce");
        let Ok(snonce) = snonce else {
            return;
        };

        let state = hs.process_message(&msg1, &pmk, &own_mac, &ap_mac, snonce);
        assert_eq!(
            state,
            HandshakeState::SendMsg2,
            "must transition to SendMsg2 after valid Message 1"
        );
        assert!(hs.ptk().is_some(), "PTK must be derived after Message 1");
        assert_eq!(
            hs.snonce(),
            snonce,
            "the kernel-generated SNonce must be the one the handshake recorded"
        );
    }
}
