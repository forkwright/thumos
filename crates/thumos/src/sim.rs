//! SIM card and signal management for the MT6739 modem.
//!
//! Manages SIM card state (PIN status, ICCID), signal quality monitoring,
//! and periodic signal strength polling. Works with the telephony subsystem's
//! `ModemTransport` trait for hardware abstraction.
//!
//! ## Signal strength mapping
//!
//! Raw RSSI from `AT+CSQ` (0-31, 99=unknown) is converted to dBm per
//! 3GPP TS 27.007, then mapped to bars:
//!
//! | dBm range     | Bars | Quality    |
//! |---------------|------|------------|
//! | >= -70        | 4    | Excellent  |
//! | -85 to -71    | 3    | Good       |
//! | -100 to -86   | 2    | Fair       |
//! | -110 to -101  | 1    | Poor       |
//! | < -110        | 0    | No signal  |
//!
//! ## Integration
//!
//! Used by the telephony subsystem during modem initialization and
//! periodic signal polling. Boot integration deferred to Phase 07 kinit wiring.

// WHY: SIM management API not yet wired to upper layers (kinit integration pending).
#![expect(dead_code, reason = "SIM management API not yet wired to kinit")]

extern crate alloc;

use crate::telephony::{self, AtResponse, MAX_LINE_LEN, ModemTransport, TelephonyError};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum ICCID length in bytes (standard is 19-20 digits).
const MAX_ICCID_LEN: usize = 20;

/// Maximum IMSI length in bytes (up to 15 digits).
const MAX_IMSI_LEN: usize = 15;

/// Signal polling interval in milliseconds (30 seconds).
const SIGNAL_POLL_INTERVAL_MS: u64 = 30_000;

// ---------------------------------------------------------------------------
// SIM information
// ---------------------------------------------------------------------------

/// SIM card information and status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimInfo {
    /// Whether a PIN is required to unlock the SIM.
    pub pin_required: bool,
    /// ICCID (Integrated Circuit Card Identifier).
    pub iccid: [u8; MAX_ICCID_LEN],
    /// Number of valid bytes in `iccid`.
    pub iccid_len: u8,
    /// IMSI (International Mobile Subscriber Identity), if available.
    pub imsi: [u8; MAX_IMSI_LEN],
    /// Number of valid bytes in `imsi`.
    pub imsi_len: u8,
}

impl Default for SimInfo {
    fn default() -> Self {
        Self {
            pin_required: false,
            iccid: [0u8; MAX_ICCID_LEN],
            iccid_len: 0,
            imsi: [0u8; MAX_IMSI_LEN],
            imsi_len: 0,
        }
    }
}

impl core::fmt::Display for SimInfo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SIM(")?;
        if self.pin_required {
            write!(f, "PIN required")?;
        } else {
            write!(f, "ready")?;
        }
        if self.iccid_len > 0 {
            write!(f, ", ICCID=")?;
            for &b in &self.iccid[..self.iccid_len as usize] {
                write!(f, "{}", b as char)?;
            }
        }
        write!(f, ")")
    }
}

// ---------------------------------------------------------------------------
// Signal information
// ---------------------------------------------------------------------------

/// Cellular signal quality information.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignalInfo {
    /// Signal strength in dBm.
    pub rssi: i16,
    /// Signal strength in bars (0-4).
    pub bars: u8,
    /// Bit error rate (0-7, 99=unknown).
    pub ber: u8,
    /// Raw RSSI value from AT+CSQ (0-31, 99=unknown).
    pub rssi_raw: u8,
}

impl Default for SignalInfo {
    fn default() -> Self {
        Self {
            rssi: -999,
            bars: 0,
            ber: 99,
            rssi_raw: 99,
        }
    }
}

impl core::fmt::Display for SignalInfo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.rssi_raw == 99 {
            write!(f, "Signal: unknown (0 bars)")
        } else {
            write!(f, "Signal: {} dBm ({} bars)", self.rssi, self.bars)
        }
    }
}

// ---------------------------------------------------------------------------
// SIM manager
// ---------------------------------------------------------------------------

/// SIM card and signal quality manager.
///
/// Handles SIM status queries, signal strength monitoring, and periodic
/// polling. Designed to work alongside the `Telephony` subsystem, sharing
/// the same `ModemTransport`.
pub(crate) struct SimManager {
    /// Current SIM information.
    sim_info: SimInfo,
    /// Current signal quality.
    signal_info: SignalInfo,
    /// Last signal poll tick (ms). `None` means never polled.
    last_poll_tick: Option<u64>,
    /// Whether the SIM has been checked.
    sim_checked: bool,
}

impl SimManager {
    /// Create a new SIM manager.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            sim_info: SimInfo::default(),
            signal_info: SignalInfo::default(),
            last_poll_tick: None,
            sim_checked: false,
        }
    }

    /// Return the current SIM information.
    #[must_use]
    pub(crate) fn sim_info(&self) -> &SimInfo {
        &self.sim_info
    }

    /// Return the current signal quality.
    #[must_use]
    pub(crate) fn signal_info(&self) -> &SignalInfo {
        &self.signal_info
    }

    /// Return whether a PIN is required.
    #[must_use]
    pub(crate) fn pin_required(&self) -> bool {
        self.sim_info.pin_required
    }

    // -----------------------------------------------------------------------
    // SIM PIN check
    // -----------------------------------------------------------------------

    /// Check SIM PIN status via `AT+CPIN?`.
    ///
    /// Updates `sim_info.pin_required` based on the response:
    /// - `+CPIN: READY` -> no PIN required
    /// - `+CPIN: SIM PIN` -> PIN required
    /// - Other responses -> treated as PIN required (not ready)
    pub(crate) fn check_pin<T: ModemTransport>(
        &mut self,
        transport: &mut T,
    ) -> Result<bool, TelephonyError> {
        let (result, info_line, info_len) = send_with_info(transport, "AT+CPIN?", 5000)?;

        match result {
            AtResponse::Ok if info_len > 0 => {
                let line = &info_line[..info_len];
                self.sim_info.pin_required = !parse_cpin_ready(line);
                self.sim_checked = true;
                Ok(!self.sim_info.pin_required)
            }
            AtResponse::Ok => {
                // No info line — can't determine status, assume not ready.
                self.sim_info.pin_required = true;
                Ok(false)
            }
            AtResponse::CmeError(code) => Err(TelephonyError::CmeError(code)),
            AtResponse::CmsError(code) => Err(TelephonyError::CmeError(code)),
            AtResponse::Error => Err(TelephonyError::ModemError),
        }
    }

    // -----------------------------------------------------------------------
    // ICCID query
    // -----------------------------------------------------------------------

    /// Query the SIM ICCID via `AT+ICCID` (or `AT+CCID` on some modems).
    ///
    /// The ICCID is a 19-20 digit identifier printed on the SIM card.
    pub(crate) fn query_iccid<T: ModemTransport>(
        &mut self,
        transport: &mut T,
    ) -> Result<(), TelephonyError> {
        let (result, info_line, info_len) = send_with_info(transport, "AT+ICCID", 5000)?;

        match result {
            AtResponse::Ok if info_len > 0 => {
                let line = &info_line[..info_len];
                // Response format varies: "+ICCID: <iccid>" or just "<iccid>"
                let iccid_bytes = if let Some(rest) = strip_prefix(line, b"+ICCID: ") {
                    rest
                } else {
                    line
                };
                let len = iccid_bytes.len().min(MAX_ICCID_LEN);
                self.sim_info.iccid[..len].copy_from_slice(&iccid_bytes[..len]);
                self.sim_info.iccid_len = len as u8;
                Ok(())
            }
            AtResponse::Ok => Ok(()),
            AtResponse::CmeError(code) => Err(TelephonyError::CmeError(code)),
            AtResponse::CmsError(code) => Err(TelephonyError::CmeError(code)),
            AtResponse::Error => Err(TelephonyError::ModemError),
        }
    }

    // -----------------------------------------------------------------------
    // Signal strength
    // -----------------------------------------------------------------------

    /// Query signal strength via `AT+CSQ`.
    ///
    /// Updates the internal `signal_info` with the response.
    pub(crate) fn query_signal<T: ModemTransport>(
        &mut self,
        transport: &mut T,
    ) -> Result<&SignalInfo, TelephonyError> {
        let (result, info_line, info_len) = send_with_info(transport, "AT+CSQ", 2000)?;

        match result {
            AtResponse::Ok if info_len > 0 => {
                let line = &info_line[..info_len];
                if let Some((rssi_raw, ber)) = telephony::parse_csq_response(line) {
                    let dbm = rssi_to_dbm(rssi_raw);
                    self.signal_info = SignalInfo {
                        rssi: dbm,
                        bars: dbm_to_bars(dbm),
                        ber,
                        rssi_raw,
                    };
                }
                Ok(&self.signal_info)
            }
            AtResponse::Ok => Ok(&self.signal_info),
            AtResponse::CmeError(code) => Err(TelephonyError::CmeError(code)),
            AtResponse::CmsError(code) => Err(TelephonyError::CmeError(code)),
            AtResponse::Error => Err(TelephonyError::ModemError),
        }
    }

    /// Poll signal strength if the polling interval has elapsed.
    ///
    /// Returns the updated signal info if a poll was performed.
    pub(crate) fn poll_signal<T: ModemTransport>(
        &mut self,
        transport: &mut T,
        current_tick: u64,
    ) -> Option<&SignalInfo> {
        if let Some(last) = self.last_poll_tick {
            if current_tick.saturating_sub(last) < SIGNAL_POLL_INTERVAL_MS {
                return None;
            }
        }

        self.last_poll_tick = Some(current_tick);
        self.query_signal(transport).ok()
    }

    // -----------------------------------------------------------------------
    // Operator query
    // -----------------------------------------------------------------------

    /// Query the operator name via `AT+COPS?`.
    ///
    /// Returns the operator name as a byte slice (within the provided buffer).
    pub(crate) fn query_operator<T: ModemTransport>(
        transport: &mut T,
        name_buf: &mut [u8; 32],
    ) -> Result<u8, TelephonyError> {
        let (result, info_line, info_len) = send_with_info(transport, "AT+COPS?", 5000)?;

        match result {
            AtResponse::Ok if info_len > 0 => {
                let line = &info_line[..info_len];
                telephony::parse_cops_response(line, name_buf).ok_or(TelephonyError::ParseError)
            }
            AtResponse::Ok => Ok(0),
            AtResponse::CmeError(code) => Err(TelephonyError::CmeError(code)),
            AtResponse::CmsError(code) => Err(TelephonyError::CmeError(code)),
            AtResponse::Error => Err(TelephonyError::ModemError),
        }
    }
}

// ---------------------------------------------------------------------------
// AT response parsing helpers
// ---------------------------------------------------------------------------

/// Parse a +CPIN? response to determine if SIM is ready.
///
/// Returns `true` if the response indicates the SIM is ready (no PIN required).
fn parse_cpin_ready(line: &[u8]) -> bool {
    if let Some(rest) = strip_prefix(line, b"+CPIN: ") {
        rest == b"READY"
    } else {
        false
    }
}

/// Parse a +CPIN? response to determine if a SIM PIN is required.
///
/// Returns `true` if the response indicates a PIN is needed.
fn parse_cpin_sim_pin(line: &[u8]) -> bool {
    if let Some(rest) = strip_prefix(line, b"+CPIN: ") {
        starts_with(rest, b"SIM PIN")
    } else {
        false
    }
}

// ---------------------------------------------------------------------------
// Signal conversion functions
// ---------------------------------------------------------------------------

/// Convert raw AT+CSQ RSSI value (0-31, 99=unknown) to dBm.
///
/// Formula: dBm = -113 + (rssi * 2), per 3GPP TS 27.007.
fn rssi_to_dbm(rssi: u8) -> i16 {
    if rssi == 99 {
        return -999; // unknown sentinel
    }
    -113 + (i16::from(rssi) * 2)
}

/// Map signal strength in dBm to bars (0-4).
///
/// Uses the same thresholds as `telephony::dbm_to_bars`:
/// - >= -70 dBm -> 4 bars
/// - >= -85 dBm -> 3 bars
/// - >= -100 dBm -> 2 bars
/// - >= -110 dBm -> 1 bar
/// - <  -110 dBm -> 0 bars
fn dbm_to_bars(dbm: i16) -> u8 {
    telephony::dbm_to_bars(dbm)
}

// ---------------------------------------------------------------------------
// Byte-level parsing helpers (reuse pattern from telephony.rs)
// ---------------------------------------------------------------------------

/// Strip a prefix from a byte slice. Returns `None` if the prefix doesn't match.
fn strip_prefix<'a>(input: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    if input.len() >= prefix.len() && &input[..prefix.len()] == prefix {
        Some(&input[prefix.len()..])
    } else {
        None
    }
}

/// Check if `input` starts with `prefix`.
fn starts_with(input: &[u8], prefix: &[u8]) -> bool {
    input.len() >= prefix.len() && &input[..prefix.len()] == prefix
}

// ---------------------------------------------------------------------------
// AT command exchange helper (delegated from telephony)
// ---------------------------------------------------------------------------

/// Send an AT command and collect one info line.
///
/// Mirrors `telephony::send_with_info` but takes a generic transport reference
/// for SIM-specific queries.
fn send_with_info<T: ModemTransport>(
    transport: &mut T,
    command: &str,
    timeout_ms: u32,
) -> Result<(AtResponse, [u8; MAX_LINE_LEN], usize), TelephonyError> {
    transport.send_at(command)?;

    let mut info_line = [0u8; MAX_LINE_LEN];
    let mut info_len = 0usize;
    let mut got_info = false;
    let mut line_buf = [0u8; MAX_LINE_LEN];

    for _ in 0..64 {
        let n = transport.recv_line(&mut line_buf, timeout_ms)?;
        let line = &line_buf[..n];

        if line.is_empty() {
            continue;
        }

        if let Some(result) = telephony::parse_final_result(line) {
            return Ok((result, info_line, info_len));
        }

        if !got_info {
            info_line[..n].copy_from_slice(line);
            info_len = n;
            got_info = true;
        }
    }

    Err(TelephonyError::Timeout)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telephony::MockModemTransport;

    #[test]
    fn cpin_ready_means_no_pin_required() {
        let mut transport = MockModemTransport::new();
        transport.queue_info_ok(b"+CPIN: READY");

        let mut sim = SimManager::new();
        let result = sim.check_pin(&mut transport);
        assert!(result.is_ok(), "check_pin must succeed");
        assert_eq!(
            result.unwrap_or(false),
            true,
            "READY response must indicate no PIN required"
        );
        assert!(
            !sim.pin_required(),
            "pin_required must be false when SIM is READY"
        );
    }

    #[test]
    fn cpin_sim_pin_means_pin_required() {
        let mut transport = MockModemTransport::new();
        transport.queue_info_ok(b"+CPIN: SIM PIN");

        let mut sim = SimManager::new();
        let result = sim.check_pin(&mut transport);
        assert!(result.is_ok(), "check_pin must succeed");
        assert_eq!(
            result.unwrap_or(true),
            false,
            "SIM PIN response must indicate PIN required"
        );
        assert!(
            sim.pin_required(),
            "pin_required must be true when SIM PIN is needed"
        );
    }

    #[test]
    fn rssi_to_bars_boundary_values() {
        // Test the complete mapping at exact boundary values.

        // 4 bars: >= -70 dBm
        assert_eq!(dbm_to_bars(-70), 4, "-70 dBm must be 4 bars");
        assert_eq!(dbm_to_bars(-50), 4, "-50 dBm must be 4 bars");
        assert_eq!(dbm_to_bars(0), 4, "0 dBm must be 4 bars");

        // 3 bars: -85 to -71 dBm
        assert_eq!(dbm_to_bars(-71), 3, "-71 dBm must be 3 bars");
        assert_eq!(dbm_to_bars(-85), 3, "-85 dBm must be 3 bars");

        // 2 bars: -100 to -86 dBm
        assert_eq!(dbm_to_bars(-86), 2, "-86 dBm must be 2 bars");
        assert_eq!(dbm_to_bars(-100), 2, "-100 dBm must be 2 bars");

        // 1 bar: -110 to -101 dBm
        assert_eq!(dbm_to_bars(-101), 1, "-101 dBm must be 1 bar");
        assert_eq!(dbm_to_bars(-110), 1, "-110 dBm must be 1 bar");

        // 0 bars: < -110 dBm
        assert_eq!(dbm_to_bars(-111), 0, "-111 dBm must be 0 bars");
        assert_eq!(dbm_to_bars(-999), 0, "unknown sentinel must be 0 bars");

        // Verify RSSI-to-dBm conversion at key points.
        assert_eq!(rssi_to_dbm(0), -113, "RSSI 0 must be -113 dBm");
        assert_eq!(rssi_to_dbm(31), -51, "RSSI 31 must be -51 dBm");
        assert_eq!(rssi_to_dbm(99), -999, "RSSI 99 must be -999 dBm (unknown)");
        assert_eq!(rssi_to_dbm(15), -83, "RSSI 15 must be -83 dBm");
    }

    #[test]
    fn signal_query_updates_info() {
        let mut transport = MockModemTransport::new();
        transport.queue_info_ok(b"+CSQ: 18,99");

        let mut sim = SimManager::new();
        let result = sim.query_signal(&mut transport);
        assert!(result.is_ok(), "signal query must succeed");

        let info = sim.signal_info();
        assert_eq!(info.rssi_raw, 18, "raw RSSI must be 18");
        assert_eq!(info.rssi, -77, "RSSI 18 must convert to -77 dBm");
        assert_eq!(info.bars, 3, "-77 dBm must be 3 bars");
        assert_eq!(info.ber, 99, "BER must be 99");
    }

    #[test]
    fn iccid_query_extracts_iccid() {
        let mut transport = MockModemTransport::new();
        transport.queue_info_ok(b"+ICCID: 89012345678901234567");

        let mut sim = SimManager::new();
        let result = sim.query_iccid(&mut transport);
        assert!(result.is_ok(), "ICCID query must succeed");
        assert_eq!(
            sim.sim_info().iccid_len,
            20,
            "ICCID length must be 20 (max)"
        );
        assert_eq!(
            &sim.sim_info().iccid[..20],
            b"89012345678901234567",
            "ICCID must match"
        );
    }

    #[test]
    fn signal_poll_respects_interval() {
        let mut transport = MockModemTransport::new();
        let mut sim = SimManager::new();

        // First poll at tick 0 should trigger.
        transport.queue_info_ok(b"+CSQ: 20,0");
        let result = sim.poll_signal(&mut transport, 0);
        assert!(result.is_some(), "first poll must trigger");

        // Second poll at tick 1000 (< 30s interval) should not trigger.
        let result = sim.poll_signal(&mut transport, 1000);
        assert!(result.is_none(), "poll within interval must not trigger");

        // Third poll at tick 31000 (> 30s) should trigger.
        transport.queue_info_ok(b"+CSQ: 25,0");
        let result = sim.poll_signal(&mut transport, 31_000);
        assert!(result.is_some(), "poll after interval must trigger");
    }

    #[test]
    fn parse_cpin_ready_recognizes_ready() {
        assert!(
            parse_cpin_ready(b"+CPIN: READY"),
            "must recognize +CPIN: READY"
        );
        assert!(
            !parse_cpin_ready(b"+CPIN: SIM PIN"),
            "must not recognize SIM PIN as ready"
        );
        assert!(
            !parse_cpin_ready(b"READY"),
            "must not match without +CPIN: prefix"
        );
    }

    #[test]
    fn parse_cpin_sim_pin_recognizes_pin() {
        assert!(
            parse_cpin_sim_pin(b"+CPIN: SIM PIN"),
            "must recognize +CPIN: SIM PIN"
        );
        assert!(
            !parse_cpin_sim_pin(b"+CPIN: READY"),
            "must not recognize READY as SIM PIN"
        );
    }
}
