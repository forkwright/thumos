//! WiFi network interface and WPA supplicant for the MT6739 combo chip.
//!
//! Ports essential logic from the `aither` userspace crate into the kernel:
//! - MAC randomization via the kernel CSPRNG (`csprng.rs`)
//! - WPA2-Personal 4-way handshake state machine
//! - EAPOL frame parsing and construction (IEEE 802.1X-2020)
//! - WiFi hardware abstraction via `WifiHwOps` trait
//!
//! ## Hardware path
//!
//! The MT6739 WiFi hardware is accessed through the WMT combo chip:
//! - `MT6739_CONSYS = 0x1800_0000` (combo-chip base)
//! - `MT6739_WLAN  = 0x180F_0000` (WiFi MMIO region)
//!
//! Data path goes through WMT STP framing (kelyphos handles the transport).
//! The `WifiHw` struct provides `#[cfg(not(test))]` MMIO access with a
//! test-friendly abstraction via `WifiHwOps`.
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
    reason = "WiFi hardware data path not yet implemented on target"
)]

extern crate alloc;
use alloc::vec::Vec;

use crate::csprng;
use crate::security::{SHA1_DIGEST_LEN, hmac_sha1, pbkdf2_hmac_sha1, prf_384};

// ---------------------------------------------------------------------------
// MT6739 WiFi hardware constants
// ---------------------------------------------------------------------------

/// WMT combo-chip (CONSYS) MMIO base address.
const MT6739_CONSYS: usize = 0x1800_0000;

/// WiFi MMIO base address within the combo-chip region.
const MT6739_WLAN: usize = 0x180F_0000;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// WiFi subsystem errors.
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
    /// No scan results matched the configured network.
    NetworkNotFound,
    /// The WiFi hardware is not initialized.
    NotInitialized,
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
            Self::NetworkNotFound => write!(f, "network not found"),
            Self::NotInitialized => write!(f, "WiFi not initialized"),
        }
    }
}

// ---------------------------------------------------------------------------
// WiFi state machine
// ---------------------------------------------------------------------------

/// WiFi connection lifecycle state machine.
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

/// WiFi security protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum WifiSecurity {
    /// No encryption (open network).
    #[default]
    Open,
    /// WPA2-Personal (PSK / CCMP).
    Wpa2Personal,
    /// WPA3-Personal (SAE).
    /// TODO(#84)[deliberate-prudent]: WPA3-SAE handshake -- enum variant defined but exchange not implemented
    Wpa3Sae,
}

// ---------------------------------------------------------------------------
// Configuration types
// ---------------------------------------------------------------------------

/// Maximum SSID length in bytes (IEEE 802.11-2020).
pub(crate) const MAX_SSID_LEN: usize = 32;

/// Maximum passphrase length in bytes (WPA2-Personal: 8-63 ASCII).
pub(crate) const MAX_PASSPHRASE_LEN: usize = 64;

/// WiFi network configuration.
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
    /// Create a new WiFi configuration.
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

/// A single scan result from the WiFi firmware.
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
// WPA2-Personal key derivation (stubbed)
// ---------------------------------------------------------------------------

/// PMK/PSK output length in bytes (IEEE 802.11-2020).
pub(crate) const PMK_LEN: usize = 32;

/// Key Confirmation Key length in bytes.
pub(crate) const KCK_LEN: usize = 16;

/// Key Encryption Key length in bytes.
pub(crate) const KEK_LEN: usize = 16;

/// Temporal Key length in bytes (WPA2-CCMP).
pub(crate) const TK_LEN: usize = 16;

/// Total PTK length: KCK + KEK + TK (WPA2-CCMP, 384 bits).
pub(crate) const PTK_LEN: usize = KCK_LEN + KEK_LEN + TK_LEN;

/// MIC length in bytes.
pub(crate) const MIC_LEN: usize = 16;

/// Pairwise Transient Key components.
///
/// Derived from the PMK by PTK = PRF-384(PMK, "Pairwise key expansion", ...).
///
/// Implements [`Drop`] to zero key material, preventing it from persisting
/// in memory after the handshake completes. Uses `write_volatile` to prevent
/// the compiler from optimizing away the zeroing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ptk {
    /// Key Confirmation Key: used to compute and verify MIC.
    pub kck: [u8; KCK_LEN],
    /// Key Encryption Key: used to wrap the GTK with AES-KEYWRAP.
    pub kek: [u8; KEK_LEN],
    /// Temporal Key: used for data frame encryption (AES-CCMP).
    pub tk: [u8; TK_LEN],
}

impl Drop for Ptk {
    fn drop(&mut self) {
        // WHY: write_volatile prevents the compiler from eliding the zeroing
        // as a dead store, ensuring key material is actually cleared from memory.
        for byte in &mut self.kck {
            // SAFETY: byte is a valid mutable reference to initialized memory.
            unsafe {
                core::ptr::write_volatile(byte, 0);
            }
        }
        for byte in &mut self.kek {
            // SAFETY: byte is a valid mutable reference to initialized memory.
            unsafe {
                core::ptr::write_volatile(byte, 0);
            }
        }
        for byte in &mut self.tk {
            // SAFETY: byte is a valid mutable reference to initialized memory.
            unsafe {
                core::ptr::write_volatile(byte, 0);
            }
        }
    }
}

/// Derive the Pairwise Master Key from a passphrase and SSID.
///
/// Uses PBKDF2-HMAC-SHA1 with 4096 iterations and a 32-byte output as
/// specified in IEEE 802.11-2020, section 12.4.4.3.1.
#[must_use]
pub(crate) fn derive_pmk(passphrase: &[u8], ssid: &[u8]) -> [u8; PMK_LEN] {
    let mut pmk = [0u8; PMK_LEN];
    let _ = pbkdf2_hmac_sha1(passphrase, ssid, 4096, &mut pmk); // WHY: pbkdf2 with 4096 iterations is infallible; Result discarded for API uniformity
    pmk
}

/// Derive the Pairwise Transient Key using PRF-384.
///
/// Implements IEEE 802.11-2020 section 12.7.1.2:
/// ```text
/// PTK = PRF-384(PMK, "Pairwise key expansion",
///               min(AA,SPA) || max(AA,SPA) || min(ANonce,SNonce) || max(ANonce,SNonce))
/// ```
#[must_use]
pub(crate) fn derive_ptk(
    pmk: &[u8; PMK_LEN],
    anonce: &[u8; 32],
    snonce: &[u8; 32],
    aa: &[u8; 6],
    spa: &[u8; 6],
) -> Ptk {
    // Build concatenated data: min(AA,SPA) || max(AA,SPA) ||
    //                          min(ANonce,SNonce) || max(ANonce,SNonce)
    let mut data = [0u8; 76];
    if aa <= spa {
        data[0..6].copy_from_slice(aa);
        data[6..12].copy_from_slice(spa);
    } else {
        data[0..6].copy_from_slice(spa);
        data[6..12].copy_from_slice(aa);
    }
    if anonce <= snonce {
        data[12..44].copy_from_slice(anonce);
        data[44..76].copy_from_slice(snonce);
    } else {
        data[12..44].copy_from_slice(snonce);
        data[44..76].copy_from_slice(anonce);
    }

    let ptk_bytes = prf_384(pmk, b"Pairwise key expansion", &data);

    let mut kck = [0u8; KCK_LEN];
    let mut kek = [0u8; KEK_LEN];
    let mut tk = [0u8; TK_LEN];
    kck.copy_from_slice(&ptk_bytes[0..16]);
    kek.copy_from_slice(&ptk_bytes[16..32]);
    tk.copy_from_slice(&ptk_bytes[32..48]);

    Ptk { kck, kek, tk }
}

/// Compute a 16-byte MIC using HMAC-SHA1 truncated to 128 bits.
///
/// Used to authenticate EAPOL-Key frames during the 4-way handshake
/// (messages 2, 3, and 4).
#[must_use]
pub(crate) fn compute_mic(kck: &[u8; KCK_LEN], data: &[u8]) -> [u8; MIC_LEN] {
    let full = hmac_sha1(kck, data);
    let mut mic = [0u8; MIC_LEN];
    mic.copy_from_slice(&full[..MIC_LEN]);
    mic
}

/// Verify that `expected_mic` matches the MIC computed over `data` with `kck`.
///
/// Uses constant-time comparison to prevent timing side-channel attacks.
/// Returns `true` only when the MIC is correct.
#[must_use]
pub(crate) fn verify_mic(kck: &[u8; KCK_LEN], data: &[u8], expected_mic: &[u8; MIC_LEN]) -> bool {
    let computed = compute_mic(kck, data);
    constant_time_eq(&computed, expected_mic)
}

/// Constant-time byte slice comparison.
///
/// Compares all bytes regardless of early differences, preventing timing
/// side-channel attacks that could leak information about secret key material.
/// Returns `true` only when both slices have equal length and identical content.
#[must_use]
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ---------------------------------------------------------------------------
// EAPOL frame handling (IEEE 802.1X-2020)
// ---------------------------------------------------------------------------

/// Size of the EAPOL common header (version + type + length).
const EAPOL_HEADER_LEN: usize = 4;

/// Size of the fixed portion of an EAPOL-Key body (before variable key data).
///
/// Fields: descriptor_type(1) + key_info(2) + key_length(2) + replay_counter(8)
/// + nonce(32) + iv(16) + rsc(8) + reserved(8) + mic(16) + key_data_length(2) = 95
const EAPOL_KEY_FIXED_LEN: usize = 95;

/// Nonce field length in bytes.
pub(crate) const NONCE_LEN: usize = 32;

/// IV field length in bytes.
pub(crate) const IV_LEN: usize = 16;

/// RSN key descriptor type (WPA2/WPA3).
pub(crate) const DESCRIPTOR_TYPE_RSN: u8 = 0x02;

/// EAPOL packet type discriminant (IEEE 802.1X-2020, table 11-3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EapolType {
    /// EAP authentication message.
    EapPacket,
    /// Supplicant requests authentication start.
    Start,
    /// Supplicant ends the authenticated session.
    Logoff,
    /// Key negotiation message (4-way handshake).
    Key,
}

impl EapolType {
    /// Parse from wire byte.
    const fn from_byte(b: u8) -> Result<Self, WifiError> {
        match b {
            0x00 => Ok(Self::EapPacket),
            0x01 => Ok(Self::Start),
            0x02 => Ok(Self::Logoff),
            0x03 => Ok(Self::Key),
            v => Err(WifiError::UnknownEapolType { value: v }),
        }
    }

    /// Encode to wire byte.
    const fn to_byte(self) -> u8 {
        match self {
            Self::EapPacket => 0x00,
            Self::Start => 0x01,
            Self::Logoff => 0x02,
            Self::Key => 0x03,
        }
    }
}

/// Packed key-information field (IEEE 802.11-2020, section 12.7.2, figure 12-33).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct KeyInfo(pub u16);

impl KeyInfo {
    /// Key descriptor version (bits 0-2).
    #[must_use]
    pub(crate) const fn descriptor_version(self) -> u8 {
        (self.0 & 0x0007) as u8
    }

    /// True if pairwise (unicast) key; false for group/broadcast key.
    #[must_use]
    pub(crate) const fn pairwise(self) -> bool {
        self.0 & 0x0008 != 0
    }

    /// True if supplicant shall install the key.
    #[must_use]
    pub(crate) const fn install(self) -> bool {
        self.0 & 0x0040 != 0
    }

    /// True if message requires an acknowledgement.
    #[must_use]
    pub(crate) const fn ack(self) -> bool {
        self.0 & 0x0080 != 0
    }

    /// True if a MIC is present in this frame.
    #[must_use]
    pub(crate) const fn mic(self) -> bool {
        self.0 & 0x0100 != 0
    }

    /// True if the RSNA has been established.
    #[must_use]
    pub(crate) const fn secure(self) -> bool {
        self.0 & 0x0200 != 0
    }

    /// True if key data is encrypted (AES-KEYWRAP).
    #[must_use]
    pub(crate) const fn encrypted_key_data(self) -> bool {
        self.0 & 0x1000 != 0
    }
}

/// EAPOL-Key frame body (IEEE 802.11-2020, section 12.7.2).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct EapolKeyFrame {
    /// Key descriptor type (0x02 = RSN, 0xFE = WPA legacy).
    pub descriptor_type: u8,
    /// Key information flags.
    pub key_info: KeyInfo,
    /// Length of the pairwise temporal key in octets.
    pub key_length: u16,
    /// Strictly monotonic replay counter.
    pub replay_counter: u64,
    /// Authenticator or supplicant nonce (ANonce / SNonce).
    pub nonce: [u8; NONCE_LEN],
    /// Key IV (all-zero for CCMP; used by TKIP).
    pub iv: [u8; IV_LEN],
    /// RSC / GTK sequence counter.
    pub rsc: u64,
    /// Message Integrity Code (MIC field zeroed before MIC computation).
    pub mic: [u8; MIC_LEN],
    /// Optional key material (wrapped GTK or RSNE IE).
    pub key_data: Vec<u8>,
}

/// Top-level EAPOL frame.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct EapolFrame {
    /// Protocol version (1 = 802.1X-2001, 2 = 802.1X-2004, 3 = 802.1X-2010).
    pub version: u8,
    /// Packet type discriminant.
    pub packet_type: EapolType,
    /// Key frame (present only when `packet_type == EapolType::Key`).
    pub key_frame: Option<EapolKeyFrame>,
    /// Raw body bytes (for EAP-Packet, Start, and Logoff).
    pub raw_body: Vec<u8>,
}

/// Parse an EAPOL frame from a byte slice.
///
/// # Errors
///
/// Returns [`WifiError::FrameTooShort`] when the slice cannot satisfy the
/// declared packet length, and [`WifiError::UnknownEapolType`] for
/// unrecognised packet type bytes.
#[must_use]
pub(crate) fn eapol_parse(data: &[u8]) -> Result<EapolFrame, WifiError> {
    if data.len() < EAPOL_HEADER_LEN {
        return Err(WifiError::FrameTooShort {
            need: EAPOL_HEADER_LEN,
            have: data.len(),
        });
    }

    let version = data[0];
    let packet_type = EapolType::from_byte(data[1])?;
    let body_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    let total = EAPOL_HEADER_LEN + body_len;

    if data.len() < total {
        return Err(WifiError::FrameTooShort {
            need: total,
            have: data.len(),
        });
    }

    let body = &data[EAPOL_HEADER_LEN..total];

    if packet_type == EapolType::Key {
        let key_frame = eapol_parse_key_frame(body)?;
        Ok(EapolFrame {
            version,
            packet_type,
            key_frame: Some(key_frame),
            raw_body: Vec::new(),
        })
    } else {
        Ok(EapolFrame {
            version,
            packet_type,
            key_frame: None,
            raw_body: body.to_vec(),
        })
    }
}

/// Parse the body of an EAPOL-Key frame.
fn eapol_parse_key_frame(body: &[u8]) -> Result<EapolKeyFrame, WifiError> {
    if body.len() < EAPOL_KEY_FIXED_LEN {
        return Err(WifiError::FrameTooShort {
            need: EAPOL_KEY_FIXED_LEN,
            have: body.len(),
        });
    }

    let descriptor_type = body[0];
    let key_info = KeyInfo(u16::from_be_bytes([body[1], body[2]]));
    let key_length = u16::from_be_bytes([body[3], body[4]]);

    let mut replay_buf = [0u8; 8];
    replay_buf.copy_from_slice(&body[5..13]);
    let replay_counter = u64::from_be_bytes(replay_buf);

    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&body[13..45]);

    let mut iv = [0u8; IV_LEN];
    iv.copy_from_slice(&body[45..61]);

    let mut rsc_buf = [0u8; 8];
    rsc_buf.copy_from_slice(&body[61..69]);
    let rsc = u64::from_be_bytes(rsc_buf);
    // body[69..77] is reserved; skip.

    let mut mic = [0u8; MIC_LEN];
    mic.copy_from_slice(&body[77..93]);

    let key_data_len = u16::from_be_bytes([body[93], body[94]]) as usize;
    let key_data_end = EAPOL_KEY_FIXED_LEN + key_data_len;

    if body.len() < key_data_end {
        return Err(WifiError::FrameTooShort {
            need: key_data_end,
            have: body.len(),
        });
    }

    let key_data = body[EAPOL_KEY_FIXED_LEN..key_data_end].to_vec();

    Ok(EapolKeyFrame {
        descriptor_type,
        key_info,
        key_length,
        replay_counter,
        nonce,
        iv,
        rsc,
        mic,
        key_data,
    })
}

/// Encode an EAPOL frame into a byte vector.
#[must_use]
pub(crate) fn eapol_encode(frame: &EapolFrame) -> Vec<u8> {
    let body = frame
        .key_frame
        .as_ref()
        .map_or_else(|| frame.raw_body.clone(), eapol_encode_key_frame);

    // WHY: body length is capped at u16::MAX to match the 2-byte length field
    // in the EAPOL header. Frames exceeding this are malformed; truncating
    // the body is the least-bad option in a no_std context without Result
    // overhead -- but the truncation must apply to the BYTES WRITTEN, not
    // just the length field, or the declared length and the actual frame
    // body diverge (issue #282 finding 5: the old code capped only
    // `body_len` and then unconditionally wrote the full untruncated
    // `body`, corrupting any frame whose body exceeded u16::MAX).
    let body_len = u16::try_from(body.len()).unwrap_or(u16::MAX);
    let truncated_body = &body[..usize::from(body_len)];

    let mut out = Vec::with_capacity(EAPOL_HEADER_LEN + truncated_body.len());
    out.push(frame.version);
    out.push(frame.packet_type.to_byte());
    out.extend_from_slice(&body_len.to_be_bytes());
    out.extend_from_slice(truncated_body);
    out
}

/// Encode an EAPOL-Key frame body.
fn eapol_encode_key_frame(kf: &EapolKeyFrame) -> Vec<u8> {
    // WHY: same u16::MAX cap and WRITTEN-bytes truncation fix as
    // eapol_encode, applied to the key_data_length field (issue #282
    // finding 5).
    let key_data_len = u16::try_from(kf.key_data.len()).unwrap_or(u16::MAX);
    let truncated_key_data = &kf.key_data[..usize::from(key_data_len)];
    let mut out = Vec::with_capacity(EAPOL_KEY_FIXED_LEN + truncated_key_data.len());

    out.push(kf.descriptor_type);
    out.extend_from_slice(&kf.key_info.0.to_be_bytes());
    out.extend_from_slice(&kf.key_length.to_be_bytes());
    out.extend_from_slice(&kf.replay_counter.to_be_bytes());
    out.extend_from_slice(&kf.nonce);
    out.extend_from_slice(&kf.iv);
    out.extend_from_slice(&kf.rsc.to_be_bytes());
    out.extend_from_slice(&[0u8; 8]); // reserved
    out.extend_from_slice(&kf.mic);
    out.extend_from_slice(&key_data_len.to_be_bytes());
    out.extend_from_slice(truncated_key_data);
    out
}

// ---------------------------------------------------------------------------
// WPA2 4-way handshake state machine
// ---------------------------------------------------------------------------

/// WPA2-Personal 4-way handshake progression.
///
/// State machine for the supplicant side of the IEEE 802.11-2020 4-way
/// handshake (section 12.7.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum HandshakeState {
    /// Waiting for Message 1 (ANonce from authenticator).
    #[default]
    AwaitMsg1,
    /// Message 1 received; supplicant generated SNonce and derived PTK.
    /// Waiting to send Message 2.
    SendMsg2,
    /// Message 2 sent; waiting for Message 3 (GTK + Install).
    AwaitMsg3,
    /// Message 3 received; waiting to send Message 4 (final ACK).
    SendMsg4,
    /// Handshake complete; keys installed.
    Complete,
    /// Handshake failed.
    Failed,
}

/// WPA2-Personal 4-way handshake context.
///
/// Tracks handshake progression and stores transient cryptographic material
/// (nonces, derived keys) for the duration of the handshake.
#[derive(Debug, Clone)]
pub struct WpaHandshake {
    /// Current handshake state.
    pub state: HandshakeState,
    /// Authenticator nonce (received in Message 1).
    pub anonce: [u8; NONCE_LEN],
    /// Supplicant nonce (generated locally).
    pub snonce: [u8; NONCE_LEN],
    /// Derived Pairwise Transient Key (populated after Message 1 processing).
    pub ptk: Option<Ptk>,
    /// Replay counter from the most recent authenticator message.
    pub replay_counter: u64,
    /// EAPOL protocol version (IEEE 802.1X-2020 §11.3.1) of the most
    /// recently received frame. Msg3 MIC reconstruction and the Msg2/Msg4
    /// responses echo this value instead of hardcoding version 2 (audit
    /// #259) — a version-1 AP (802.1X-2001, common on embedded/enterprise
    /// gear) otherwise fails every MIC check.
    pub eapol_version: u8,
}

impl WpaHandshake {
    /// Create a new handshake context.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            state: HandshakeState::AwaitMsg1,
            anonce: [0u8; NONCE_LEN],
            snonce: [0u8; NONCE_LEN],
            ptk: None,
            replay_counter: 0,
            eapol_version: 2,
        }
    }

    /// Record the EAPOL protocol version of the most recently received frame.
    ///
    /// Callers should invoke this with the wire frame's `version` byte
    /// before passing its key body to [`Self::process_message`] — Msg3 MIC
    /// reconstruction and Msg2/Msg4 responses then echo the value instead
    /// of hardcoding version 2 (audit #259).
    pub(crate) fn set_eapol_version(&mut self, version: u8) {
        self.eapol_version = version;
    }

    /// Process an incoming EAPOL-Key frame (Message 1 or Message 3).
    ///
    /// Advances the handshake state machine. Returns the new state.
    ///
    /// # Arguments
    ///
    /// * `key_frame` - The received EAPOL-Key frame body.
    /// * `pmk` - Pre-computed Pairwise Master Key.
    /// * `own_mac` - Supplicant MAC address (locally-administered).
    /// * `ap_mac` - Authenticator (AP) MAC address.
    pub(crate) fn process_message(
        &mut self,
        key_frame: &EapolKeyFrame,
        pmk: &[u8; PMK_LEN],
        own_mac: &[u8; 6],
        ap_mac: &[u8; 6],
    ) -> HandshakeState {
        match self.state {
            HandshakeState::AwaitMsg1 => {
                // Message 1: AP sends ANonce, ack=true, mic=false, pairwise=true
                if !key_frame.key_info.ack()
                    || key_frame.key_info.mic()
                    || !key_frame.key_info.pairwise()
                {
                    self.state = HandshakeState::Failed;
                    return self.state;
                }
                self.anonce = key_frame.nonce;
                self.replay_counter = key_frame.replay_counter;

                // Generate supplicant nonce. Fail closed (#284): if the CSPRNG
                // is unseeded, abort the handshake rather than deriving a PTK
                // from a zero SNonce.
                if csprng::kernel_random_bytes(&mut self.snonce).is_err() {
                    self.state = HandshakeState::Failed;
                    return self.state;
                }

                // Derive PTK
                let ptk = derive_ptk(pmk, &self.anonce, &self.snonce, ap_mac, own_mac);
                self.ptk = Some(ptk);

                self.state = HandshakeState::SendMsg2;
                self.state
            }
            HandshakeState::AwaitMsg3 => {
                // Message 3: AP sends ANonce again, ack=true, mic=true, install=true, pairwise=true
                if !key_frame.key_info.ack()
                    || !key_frame.key_info.mic()
                    || !key_frame.key_info.install()
                    || !key_frame.key_info.pairwise()
                {
                    self.state = HandshakeState::Failed;
                    return self.state;
                }

                // Verify replay counter is monotonically increasing
                if key_frame.replay_counter <= self.replay_counter {
                    self.state = HandshakeState::Failed;
                    return self.state;
                }
                self.replay_counter = key_frame.replay_counter;

                // Verify MIC using KCK from PTK (IEEE 802.11-2020 section 12.7.6.4).
                // Fail closed (#274): a missing PTK means no MIC can be
                // verified — never fall through to SendMsg4 unchecked.
                let Some(ref ptk) = self.ptk else {
                    self.state = HandshakeState::Failed;
                    return self.state;
                };
                let mut zeroed_kf = key_frame.clone();
                zeroed_kf.mic = [0u8; MIC_LEN];
                let zeroed_frame = EapolFrame {
                    version: self.eapol_version,
                    packet_type: EapolType::Key,
                    key_frame: Some(zeroed_kf),
                    raw_body: Vec::new(),
                };
                let encoded = eapol_encode(&zeroed_frame);
                if !verify_mic(&ptk.kck, &encoded, &key_frame.mic) {
                    self.state = HandshakeState::Failed;
                    return self.state;
                }

                self.state = HandshakeState::SendMsg4;
                self.state
            }
            _ => self.state,
        }
    }

    /// Mark the handshake as complete after Message 4 has been sent.
    pub(crate) fn complete(&mut self) {
        if self.state == HandshakeState::SendMsg4 {
            self.state = HandshakeState::Complete;
        }
    }

    /// Advance the handshake after Message 2 has been transmitted.
    ///
    /// Transitions `SendMsg2 -> AwaitMsg3`. Without this call the state
    /// machine has no path out of `SendMsg2` (audit #260): `process_message`
    /// only has match arms for `AwaitMsg1` and `AwaitMsg3`, so the AP's
    /// Message 3 would otherwise fall through the `_ => self.state`
    /// catch-all and the handshake could never reach `SendMsg4`/`Complete`.
    /// No-ops (state unchanged) unless currently in `SendMsg2`.
    pub(crate) fn msg2_sent(&mut self) {
        if self.state == HandshakeState::SendMsg2 {
            self.state = HandshakeState::AwaitMsg3;
        }
    }

    /// Build an EAPOL-Key response frame (Message 2 or Message 4).
    ///
    /// Returns `None` if the handshake is not in a state that requires sending.
    #[must_use]
    pub(crate) fn build_response(&self) -> Option<EapolFrame> {
        match self.state {
            HandshakeState::SendMsg2 => {
                // Message 2: supplicant sends SNonce, mic=true, ack=false
                // Key info: version=2 (AES), pairwise, MIC
                let key_info = KeyInfo(0x010a); // version=2, pairwise, MIC
                let mut kf = EapolKeyFrame {
                    descriptor_type: DESCRIPTOR_TYPE_RSN,
                    key_info,
                    key_length: 0,
                    replay_counter: self.replay_counter,
                    nonce: self.snonce,
                    iv: [0u8; IV_LEN],
                    rsc: 0,
                    mic: [0u8; MIC_LEN],
                    key_data: Vec::new(),
                };
                // Compute MIC over the frame with zeroed MIC field.
                if let Some(ref ptk) = self.ptk {
                    let frame_for_mic = EapolFrame {
                        version: self.eapol_version,
                        packet_type: EapolType::Key,
                        key_frame: Some(kf.clone()),
                        raw_body: Vec::new(),
                    };
                    kf.mic = compute_mic(&ptk.kck, &eapol_encode(&frame_for_mic));
                }
                Some(EapolFrame {
                    version: self.eapol_version,
                    packet_type: EapolType::Key,
                    key_frame: Some(kf),
                    raw_body: Vec::new(),
                })
            }
            HandshakeState::SendMsg4 => {
                // Message 4: supplicant sends final ACK, mic=true, secure=true
                let key_info = KeyInfo(0x030a); // version=2, pairwise, MIC, secure
                let mut kf = EapolKeyFrame {
                    descriptor_type: DESCRIPTOR_TYPE_RSN,
                    key_info,
                    key_length: 0,
                    replay_counter: self.replay_counter,
                    nonce: [0u8; NONCE_LEN],
                    iv: [0u8; IV_LEN],
                    rsc: 0,
                    mic: [0u8; MIC_LEN],
                    key_data: Vec::new(),
                };
                // Compute MIC over the frame with zeroed MIC field.
                if let Some(ref ptk) = self.ptk {
                    let frame_for_mic = EapolFrame {
                        version: self.eapol_version,
                        packet_type: EapolType::Key,
                        key_frame: Some(kf.clone()),
                        raw_body: Vec::new(),
                    };
                    kf.mic = compute_mic(&ptk.kck, &eapol_encode(&frame_for_mic));
                }
                Some(EapolFrame {
                    version: self.eapol_version,
                    packet_type: EapolType::Key,
                    key_frame: Some(kf),
                    raw_body: Vec::new(),
                })
            }
            _ => None,
        }
    }
}

impl Drop for WpaHandshake {
    fn drop(&mut self) {
        // Zero nonces — they contribute to key derivation and are sensitive.
        for byte in &mut self.anonce {
            // SAFETY: byte is a valid mutable reference to initialized memory.
            unsafe {
                core::ptr::write_volatile(byte, 0);
            }
        }
        for byte in &mut self.snonce {
            // SAFETY: byte is a valid mutable reference to initialized memory.
            unsafe {
                core::ptr::write_volatile(byte, 0);
            }
        }
        // The PTK is zeroed by its own Drop impl when this Option is dropped.
    }
}

impl Default for WpaHandshake {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// WiFi hardware abstraction
// ---------------------------------------------------------------------------

/// Hardware operations trait for WiFi driver abstraction.
///
/// Allows test-friendly mocking of MMIO access. The real implementation
/// (`WifiHw`) uses `#[cfg(not(test))]` MMIO; tests provide a mock.
pub(crate) trait WifiHwOps {
    /// Return true once the WiFi data path can exchange Ethernet frames.
    ///
    /// The default is closed so partially wired hardware operations cannot be
    /// mistaken for production connectivity.
    fn data_path_ready(&self) -> bool {
        false
    }

    /// Transmit a frame to the WiFi hardware.
    fn send_frame(&mut self, data: &[u8]) -> Result<(), WifiError>;

    /// Receive a frame from the WiFi hardware, if one is available.
    fn recv_frame(&mut self) -> Option<Vec<u8>>;

    /// Initiate a passive scan.
    fn scan_start(&mut self) -> Result<(), WifiError>;

    /// Return the current scan results.
    fn scan_results(&self) -> &[ScanResult];

    /// Associate with an access point.
    fn associate(&mut self, ssid: &[u8], bssid: &[u8; 6]) -> Result<(), WifiError>;
}

/// WiFi hardware driver for the MT6739 WMT combo chip.
///
/// Provides MMIO-based access to the WiFi hardware on the real target,
/// and a mock-friendly scan result buffer for testing.
pub(crate) struct WifiHw {
    /// WLAN MMIO base address.
    wlan_base: usize,
    /// Combo-chip CONSYS base address.
    consys_base: usize,
    /// Buffered scan results from the most recent scan.
    scan_buf: Vec<ScanResult>,
}

impl WifiHw {
    /// Construct a new WiFi hardware driver.
    #[must_use]
    pub(crate) const fn new() -> Self {
        Self {
            wlan_base: MT6739_WLAN,
            consys_base: MT6739_CONSYS,
            scan_buf: Vec::new(),
        }
    }
}

impl WifiHwOps for WifiHw {
    fn data_path_ready(&self) -> bool {
        false
    }

    fn send_frame(&mut self, _data: &[u8]) -> Result<(), WifiError> {
        // TODO(#129)[deliberate-prudent]: implement WMT STP frame TX via MMIO write to WLAN registers.
        // The data path goes through the WMT combo-chip transport layer
        // (kelyphos handles STP framing).
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

/// WiFi network driver combining state machine, hardware ops, and WPA handshake.
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
    /// Create a new WiFi driver with the given hardware backend.
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
    #[must_use]
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

/// Mock WiFi hardware for testing.
///
/// Records calls and returns pre-configured results without MMIO access.
#[cfg(test)]
pub struct MockWifiHw {
    /// Pre-loaded scan results.
    pub scan_results: Vec<ScanResult>,
    /// Frames sent via `send_frame`.
    pub sent_frames: Vec<Vec<u8>>,
    /// Whether scan_start should succeed.
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

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

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

    // --- EAPOL frame parsing ---

    #[test]
    fn eapol_frame_parse_valid() {
        // version=2, type=Start(0x01), length=0
        let data = [0x02, 0x01, 0x00, 0x00];
        let frame = eapol_parse(&data);
        assert!(frame.is_ok(), "valid Start frame must parse successfully");
        let frame = frame.ok();
        assert!(frame.is_some(), "parsed frame must be Some");
        let frame = frame.as_ref();
        assert_eq!(frame.map(|f| f.version), Some(2), "version must be 2");
        assert_eq!(
            frame.map(|f| f.packet_type),
            Some(EapolType::Start),
            "packet type must be Start"
        );
        assert!(
            frame.is_some_and(|f| f.key_frame.is_none()),
            "Start frame must have no key frame"
        );
    }

    #[test]
    fn eapol_frame_parse_short_returns_error() {
        // Only 3 bytes: too short for EAPOL header
        let data = [0x02, 0x01, 0x00];
        let result = eapol_parse(&data);
        assert!(result.is_err(), "truncated frame must return error");
        match result {
            Err(WifiError::FrameTooShort { need, have }) => {
                assert_eq!(need, EAPOL_HEADER_LEN, "need must be EAPOL_HEADER_LEN");
                assert_eq!(have, 3, "have must be 3");
            }
            _ => panic!("must return FrameTooShort variant"),
        }
    }

    // --- EAPOL key frame roundtrip ---

    #[test]
    fn eapol_key_frame_roundtrips() {
        let kf = EapolKeyFrame {
            descriptor_type: DESCRIPTOR_TYPE_RSN,
            key_info: KeyInfo(0x008a),
            key_length: 16,
            replay_counter: 1,
            nonce: [0xaa; NONCE_LEN],
            iv: [0u8; IV_LEN],
            rsc: 0,
            mic: [0u8; MIC_LEN],
            key_data: vec![0x01, 0x02, 0x03, 0x04],
        };
        let frame = EapolFrame {
            version: 2,
            packet_type: EapolType::Key,
            key_frame: Some(kf.clone()),
            raw_body: Vec::new(),
        };
        let encoded = eapol_encode(&frame);
        let parsed = eapol_parse(&encoded);
        assert!(parsed.is_ok(), "roundtrip must succeed");
        let parsed = parsed.ok();
        assert_eq!(
            parsed.as_ref().and_then(|f| f.key_frame.as_ref()),
            Some(&kf),
            "key frame must survive encode/parse roundtrip"
        );
    }

    #[test]
    fn eapol_encode_truncates_body_bytes_to_match_declared_length_field() {
        let oversized_len = usize::from(u16::MAX) + 100;
        let frame = EapolFrame {
            version: 2,
            packet_type: EapolType::Start,
            key_frame: None,
            raw_body: vec![0xAB; oversized_len],
        };
        let encoded = eapol_encode(&frame);
        let declared_len = u16::from_be_bytes([encoded[2], encoded[3]]);
        assert_eq!(declared_len, u16::MAX, "length field must be capped");
        assert_eq!(
            encoded.len(),
            EAPOL_HEADER_LEN + usize::from(u16::MAX),
            "encoded frame length must match the declared length field, not the untruncated body"
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

    // --- WPA handshake state machine ---

    #[test]
    fn handshake_starts_awaiting_msg1() {
        let hs = WpaHandshake::new();
        assert_eq!(
            hs.state,
            HandshakeState::AwaitMsg1,
            "initial handshake state must be AwaitMsg1"
        );
    }

    #[test]
    fn handshake_transitions_to_send_msg2_on_valid_msg1() {
        setup_csprng();
        let mut hs = WpaHandshake::new();
        let pmk = [0u8; PMK_LEN];
        let own_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let ap_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];

        // Simulate Message 1: ack=true, mic=false
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

        let state = hs.process_message(&msg1, &pmk, &own_mac, &ap_mac);
        assert_eq!(
            state,
            HandshakeState::SendMsg2,
            "must transition to SendMsg2 after valid Message 1"
        );
        assert!(hs.ptk.is_some(), "PTK must be derived after Message 1");
    }

    #[test]
    fn handshake_rejects_msg1_with_mic_set() {
        setup_csprng();
        let mut hs = WpaHandshake::new();
        let pmk = [0u8; PMK_LEN];
        let own_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let ap_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];

        // Invalid Message 1: has MIC set (Message 1 must not have MIC)
        let msg1 = EapolKeyFrame {
            descriptor_type: DESCRIPTOR_TYPE_RSN,
            key_info: KeyInfo(0x018a), // version=2, pairwise, ack, MIC (invalid)
            key_length: 16,
            replay_counter: 1,
            nonce: [0xaa; NONCE_LEN],
            iv: [0u8; IV_LEN],
            rsc: 0,
            mic: [0u8; MIC_LEN],
            key_data: Vec::new(),
        };

        let state = hs.process_message(&msg1, &pmk, &own_mac, &ap_mac);
        assert_eq!(
            state,
            HandshakeState::Failed,
            "must reject Message 1 that has MIC set"
        );
    }

    #[test]
    fn handshake_rejects_msg1_with_pairwise_bit_clear() {
        setup_csprng();
        let mut hs = WpaHandshake::new();
        let pmk = [0u8; PMK_LEN];
        let own_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let ap_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];

        // Group-key frame: ack=true, mic=false, pairwise=false (invalid as Msg1).
        let msg1 = EapolKeyFrame {
            descriptor_type: DESCRIPTOR_TYPE_RSN,
            key_info: KeyInfo(0x0082), // version=2, ack; pairwise CLEAR
            key_length: 16,
            replay_counter: 1,
            nonce: [0xaa; NONCE_LEN],
            iv: [0u8; IV_LEN],
            rsc: 0,
            mic: [0u8; MIC_LEN],
            key_data: Vec::new(),
        };

        let state = hs.process_message(&msg1, &pmk, &own_mac, &ap_mac);
        assert_eq!(
            state,
            HandshakeState::Failed,
            "must reject a group-key (pairwise=0) frame as Message 1"
        );
    }

    #[test]
    fn handshake_rejects_msg3_with_pairwise_bit_clear() {
        setup_csprng();
        let mut hs = WpaHandshake::new();
        let pmk = [0u8; PMK_LEN];
        let own_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let ap_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];

        let msg1 = EapolKeyFrame {
            descriptor_type: DESCRIPTOR_TYPE_RSN,
            key_info: KeyInfo(0x008a),
            key_length: 16,
            replay_counter: 1,
            nonce: [0xaa; NONCE_LEN],
            iv: [0u8; IV_LEN],
            rsc: 0,
            mic: [0u8; MIC_LEN],
            key_data: Vec::new(),
        };
        hs.process_message(&msg1, &pmk, &own_mac, &ap_mac);
        // Drive to AwaitMsg3 directly (state is `pub`); independent of
        // whether audit #260's msg2_sent() transition has landed.
        hs.state = HandshakeState::AwaitMsg3;

        // Group-key frame masquerading as Msg3: ack, mic, install set,
        // pairwise CLEAR (0x01c2 = version=2 | install | ack | mic).
        let msg3 = EapolKeyFrame {
            descriptor_type: DESCRIPTOR_TYPE_RSN,
            key_info: KeyInfo(0x01c2),
            key_length: 16,
            replay_counter: 2,
            nonce: [0xaa; NONCE_LEN],
            iv: [0u8; IV_LEN],
            rsc: 0,
            mic: [0u8; MIC_LEN],
            key_data: Vec::new(),
        };

        let state = hs.process_message(&msg3, &pmk, &own_mac, &ap_mac);
        assert_eq!(
            state,
            HandshakeState::Failed,
            "must reject a group-key (pairwise=0) frame as Message 3"
        );
    }

    #[test]
    fn handshake_builds_msg2_response() {
        setup_csprng();
        let mut hs = WpaHandshake::new();
        let pmk = [0u8; PMK_LEN];
        let own_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let ap_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];

        let msg1 = EapolKeyFrame {
            descriptor_type: DESCRIPTOR_TYPE_RSN,
            key_info: KeyInfo(0x008a),
            key_length: 16,
            replay_counter: 1,
            nonce: [0xaa; NONCE_LEN],
            iv: [0u8; IV_LEN],
            rsc: 0,
            mic: [0u8; MIC_LEN],
            key_data: Vec::new(),
        };
        hs.process_message(&msg1, &pmk, &own_mac, &ap_mac);

        let response = hs.build_response();
        assert!(response.is_some(), "must produce Message 2 response");
        let response = response.as_ref();
        assert_eq!(
            response.map(|f| f.packet_type),
            Some(EapolType::Key),
            "response must be a Key frame"
        );
        // The response nonce must be the supplicant nonce (non-zero from CSPRNG)
        let resp_kf = response.and_then(|f| f.key_frame.as_ref());
        assert!(resp_kf.is_some(), "response must have key frame");
        assert_eq!(
            resp_kf.map(|kf| kf.nonce),
            Some(hs.snonce),
            "response nonce must be the supplicant nonce"
        );
    }

    #[test]
    fn handshake_completes_full_round_trip_after_msg2_sent() {
        setup_csprng();
        let mut hs = WpaHandshake::new();
        let pmk = [0u8; PMK_LEN];
        let own_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let ap_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];

        let msg1 = EapolKeyFrame {
            descriptor_type: DESCRIPTOR_TYPE_RSN,
            key_info: KeyInfo(0x008a),
            key_length: 16,
            replay_counter: 1,
            nonce: [0xaa; NONCE_LEN],
            iv: [0u8; IV_LEN],
            rsc: 0,
            mic: [0u8; MIC_LEN],
            key_data: Vec::new(),
        };
        let state = hs.process_message(&msg1, &pmk, &own_mac, &ap_mac);
        assert_eq!(
            state,
            HandshakeState::SendMsg2,
            "Message 1 must yield SendMsg2"
        );

        assert!(
            hs.build_response().is_some(),
            "SendMsg2 must produce a Message 2 response"
        );
        hs.msg2_sent();
        assert_eq!(
            hs.state,
            HandshakeState::AwaitMsg3,
            "msg2_sent must transition SendMsg2 -> AwaitMsg3"
        );

        // Message 3: ack=true, mic=true, install=true, pairwise=true.
        let mut msg3 = EapolKeyFrame {
            descriptor_type: DESCRIPTOR_TYPE_RSN,
            key_info: KeyInfo(0x01ca),
            key_length: 16,
            replay_counter: 2,
            nonce: [0xaa; NONCE_LEN],
            iv: [0u8; IV_LEN],
            rsc: 0,
            mic: [0u8; MIC_LEN],
            key_data: Vec::new(),
        };
        assert!(hs.ptk.is_some(), "PTK must be derived after Message 1");
        if let Some(ptk) = hs.ptk.clone() {
            let zeroed_frame = EapolFrame {
                version: 2,
                packet_type: EapolType::Key,
                key_frame: Some(msg3.clone()),
                raw_body: Vec::new(),
            };
            msg3.mic = compute_mic(&ptk.kck, &eapol_encode(&zeroed_frame));
        }

        let state = hs.process_message(&msg3, &pmk, &own_mac, &ap_mac);
        assert_eq!(
            state,
            HandshakeState::SendMsg4,
            "Message 3 after msg2_sent must be processed and yield SendMsg4"
        );
    }

    // --- Key info flags ---

    #[test]
    fn key_info_decodes_flags() {
        // 0x008a = pairwise(bit3) | ack(bit7) | descriptor_version=2
        let ki = KeyInfo(0x008a);
        assert_eq!(ki.descriptor_version(), 2, "descriptor version must be 2");
        assert!(ki.pairwise(), "pairwise bit must be set");
        assert!(ki.ack(), "ack bit must be set");
        assert!(!ki.install(), "install bit must be clear");
        assert!(!ki.mic(), "MIC bit must be clear");
    }

    #[test]
    fn handshake_fails_closed_when_awaiting_msg3_without_ptk() {
        let mut hs = WpaHandshake::new();
        let pmk = [0u8; PMK_LEN];
        let own_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let ap_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];

        // Driver misuse: reach AwaitMsg3 without ever processing Message 1,
        // so `ptk` is still None (`state` is `pub`, per audit #274/#260).
        hs.state = HandshakeState::AwaitMsg3;
        assert!(hs.ptk.is_none(), "PTK must be None on this path");

        let msg3 = EapolKeyFrame {
            descriptor_type: DESCRIPTOR_TYPE_RSN,
            key_info: KeyInfo(0x01ca), // version=2, pairwise, install, ack, MIC
            key_length: 16,
            replay_counter: 1,
            nonce: [0xaa; NONCE_LEN],
            iv: [0u8; IV_LEN],
            rsc: 0,
            mic: [0xffu8; MIC_LEN],
            key_data: Vec::new(),
        };

        let state = hs.process_message(&msg3, &pmk, &own_mac, &ap_mac);
        assert_eq!(
            state,
            HandshakeState::Failed,
            "entering AwaitMsg3 with ptk == None must fail closed, never reach SendMsg4"
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

    // -- WPA2 crypto tests --

    #[test]
    fn derive_pmk_ieee_annex_j3() {
        // IEEE 802.11-2020 Annex J.3: passphrase="password", SSID="IEEE"
        let pmk = derive_pmk(b"password", b"IEEE");
        let expected = [
            0xf4, 0x2c, 0x6f, 0xc5, 0x2d, 0xf0, 0xeb, 0xef, 0x9e, 0xbb, 0x4b, 0x90, 0xb3, 0x8a,
            0x5f, 0x90, 0x2e, 0x83, 0xfe, 0x1b, 0x13, 0x5a, 0x70, 0xe2, 0x3a, 0xed, 0x76, 0x2e,
            0x97, 0x10, 0xa1, 0x2e,
        ];
        assert_eq!(pmk, expected, "PMK must match IEEE 802.11-2020 Annex J.3");
    }

    #[test]
    fn derive_pmk_differs_by_ssid() {
        let pmk1 = derive_pmk(b"password", b"Network1");
        let pmk2 = derive_pmk(b"password", b"Network2");
        assert_ne!(pmk1, pmk2, "different SSIDs must produce different PMKs");
    }

    #[test]
    fn derive_ptk_produces_nonzero_keys() {
        let pmk = derive_pmk(b"password", b"TestSSID");
        let anonce = [0xAAu8; 32];
        let snonce = [0xBBu8; 32];
        let aa = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let spa = [0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
        let ptk = derive_ptk(&pmk, &anonce, &snonce, &aa, &spa);
        assert_ne!(ptk.kck, [0u8; KCK_LEN], "KCK must not be zero");
        assert_ne!(ptk.kek, [0u8; KEK_LEN], "KEK must not be zero");
        assert_ne!(ptk.tk, [0u8; TK_LEN], "TK must not be zero");
    }

    /// IEEE Std 802.11i-2004, Table H.13 / Table H.15 (Annex H.7.1,
    /// "Pairwise key derivation") — the standard's own published PTK
    /// worked example. Note the published SNonce/ANonce are 20 bytes each
    /// (not the 32-byte EAPOL Key Nonce field), as printed in Table H.13;
    /// this test exercises `prf_384` directly with the literal published
    /// B-string rather than `derive_ptk`'s 32-byte-nonce typed wrapper,
    /// since 20-byte values cannot be passed through that signature
    /// without altering the vector.
    #[test]
    // WHY: expected_kck/expected_kek/expected_tk mirror the IEEE standard's
    // own KCK/KEK/TK terminology (Table H.15) — renaming would obscure the
    // cross-reference to the source table.
    #[allow(clippy::similar_names)]
    fn prf384_matches_ieee_802_11i_h7_1_vector() {
        let pmk: [u8; PMK_LEN] = [
            0x0d, 0xc0, 0xd6, 0xeb, 0x90, 0x55, 0x5e, 0xd6, 0x41, 0x97, 0x56, 0xb9, 0xa1, 0x5e,
            0xc3, 0xe3, 0x20, 0x9b, 0x63, 0xdf, 0x70, 0x7d, 0xd5, 0x08, 0xd1, 0x45, 0x81, 0xf8,
            0x98, 0x27, 0x21, 0xaf,
        ];
        let aa: [u8; 6] = [0xa0, 0xa1, 0xa1, 0xa3, 0xa4, 0xa5];
        let spa: [u8; 6] = [0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5];
        let snonce: [u8; 20] = [
            0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xd0, 0xd1, 0xd2, 0xd3,
            0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9,
        ];
        let anonce: [u8; 20] = [
            0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xf0, 0xf1, 0xf2, 0xf3,
            0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9,
        ];

        // B = Min(AA,SPA) || Max(AA,SPA) || Min(ANonce,SNonce) || Max(ANonce,SNonce)
        let (mac_lo, mac_hi) = if aa <= spa { (aa, spa) } else { (spa, aa) };
        let (nonce_lo, nonce_hi) = if anonce <= snonce {
            (anonce, snonce)
        } else {
            (snonce, anonce)
        };
        let mut data = Vec::with_capacity(6 + 6 + 20 + 20);
        data.extend_from_slice(&mac_lo);
        data.extend_from_slice(&mac_hi);
        data.extend_from_slice(&nonce_lo);
        data.extend_from_slice(&nonce_hi);

        let ptk_bytes = prf_384(&pmk, b"Pairwise key expansion", &data);

        let expected_kck: [u8; KCK_LEN] = [
            0xaa, 0x7c, 0xfc, 0x85, 0x60, 0x25, 0x1e, 0x4b, 0xc6, 0x87, 0xe0, 0xcb, 0x8d, 0x29,
            0x83, 0x63,
        ];
        let expected_kek: [u8; KEK_LEN] = [
            0xba, 0x53, 0x16, 0x3d, 0xf3, 0x2a, 0x86, 0x38, 0xf4, 0x79, 0xab, 0xe3, 0x4b, 0xfd,
            0x2b, 0xc8,
        ];
        let expected_tk: [u8; TK_LEN] = [
            0x8c, 0xb7, 0x78, 0x33, 0x2e, 0x94, 0xac, 0xa6, 0xd3, 0x0b, 0x89, 0xcb, 0xe8, 0x2a,
            0x9c, 0xa9,
        ];

        assert_eq!(
            &ptk_bytes[0..16],
            &expected_kck,
            "KCK must match IEEE 802.11i-2004 Table H.15"
        );
        assert_eq!(
            &ptk_bytes[16..32],
            &expected_kek,
            "KEK must match IEEE 802.11i-2004 Table H.15"
        );
        assert_eq!(
            &ptk_bytes[32..48],
            &expected_tk,
            "TK must match IEEE 802.11i-2004 Table H.15 / Table H.14"
        );
    }

    #[test]
    fn compute_mic_is_16_bytes_nonzero() {
        let kck = [0xCCu8; KCK_LEN];
        let data = b"test eapol frame data";
        let mic = compute_mic(&kck, data);
        assert_ne!(mic, [0u8; MIC_LEN], "MIC must not be zero");
    }

    #[test]
    fn verify_mic_accepts_correct_mic() {
        let kck = [0xCCu8; KCK_LEN];
        let data = b"test eapol frame data";
        let mic = compute_mic(&kck, data);
        assert!(verify_mic(&kck, data, &mic), "correct MIC must verify");
    }

    #[test]
    fn verify_mic_rejects_wrong_mic() {
        let kck = [0xCCu8; KCK_LEN];
        let data = b"test eapol frame data";
        let mut bad_mic = compute_mic(&kck, data);
        bad_mic[0] ^= 0xFF; // flip one byte
        assert!(
            !verify_mic(&kck, data, &bad_mic),
            "wrong MIC must not verify"
        );
    }

    #[test]
    fn handshake_verifies_msg3_mic_using_received_eapol_version() {
        setup_csprng();
        for version in [1u8, 2u8] {
            let mut hs = WpaHandshake::new();
            hs.set_eapol_version(version);
            let pmk = [0u8; PMK_LEN];
            let own_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
            let ap_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];

            let msg1 = EapolKeyFrame {
                descriptor_type: DESCRIPTOR_TYPE_RSN,
                key_info: KeyInfo(0x008a),
                key_length: 16,
                replay_counter: 1,
                nonce: [0xaa; NONCE_LEN],
                iv: [0u8; IV_LEN],
                rsc: 0,
                mic: [0u8; MIC_LEN],
                key_data: Vec::new(),
            };
            hs.process_message(&msg1, &pmk, &own_mac, &ap_mac);
            hs.state = HandshakeState::AwaitMsg3;

            let mut msg3 = EapolKeyFrame {
                descriptor_type: DESCRIPTOR_TYPE_RSN,
                key_info: KeyInfo(0x01ca),
                key_length: 16,
                replay_counter: 2,
                nonce: [0xaa; NONCE_LEN],
                iv: [0u8; IV_LEN],
                rsc: 0,
                mic: [0u8; MIC_LEN],
                key_data: Vec::new(),
            };
            if let Some(ptk) = hs.ptk.clone() {
                let frame_for_mic = EapolFrame {
                    version,
                    packet_type: EapolType::Key,
                    key_frame: Some(msg3.clone()),
                    raw_body: Vec::new(),
                };
                msg3.mic = compute_mic(&ptk.kck, &eapol_encode(&frame_for_mic));
            }

            let state = hs.process_message(&msg3, &pmk, &own_mac, &ap_mac);
            assert_eq!(
                state,
                HandshakeState::SendMsg4,
                "Message 3 MIC must verify using the received EAPOL version {version}"
            );
        }
    }
}
