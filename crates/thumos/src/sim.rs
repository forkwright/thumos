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
//! Wired into the kernel at boot: `kardia::KernelState` holds a `SimManager`
//! and the qemu boot smoke exercises ICCID / PIN status / signal / operator
//! queries over the modem transport (#398).

extern crate alloc;

use crate::telephony::{self, AtResponse, MAX_LINE_LEN, ModemTransport, TelephonyError};
use crate::telephony_parser;

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
            // WHY: CmsError deliberately collapses into the same
            // TelephonyError::CmeError variant as CmeError -- there is no
            // distinct CmsError case in TelephonyError, per
            // query_operator_maps_at_error_branches below.
            AtResponse::CmeError(code) | AtResponse::CmsError(code) => {
                Err(TelephonyError::CmeError(code))
            }
            AtResponse::Error => Err(TelephonyError::ModemError),
        }
    }

    // -----------------------------------------------------------------------
    // SIM PIN/PUK unlock (#517)
    // -----------------------------------------------------------------------

    /// Query remaining PIN/PUK attempts via `AT+CPINR`.
    ///
    /// Returns `Ok(Some(n))` when the modem reports a count, `Ok(None)` when
    /// the response is absent or unparsable — the caller degrades to
    /// "unknown" and must NOT assume attempts remain. NOTE: the exact
    /// MT6739 `+CPINR` report format is bench-verify before relying on the
    /// count for a last-attempt warning on hardware.
    // WHY: no `self` -- the count comes straight back from the modem and is
    // never cached on `SimManager` (same shape as `query_operator` below).
    pub(crate) fn pin_attempts_remaining<T: ModemTransport>(
        transport: &mut T,
    ) -> Result<Option<u8>, TelephonyError> {
        let (result, info_line, info_len) = send_with_info(transport, "AT+CPINR", 5000)?;
        match result {
            AtResponse::Ok if info_len > 0 => Ok(telephony_parser::parse_cpinr_attempts(
                &info_line[..info_len],
            )),
            AtResponse::Ok => Ok(None),
            // WHY: see check_pin above -- CmsError collapses into CmeError.
            AtResponse::CmeError(code) | AtResponse::CmsError(code) => {
                Err(TelephonyError::CmeError(code))
            }
            AtResponse::Error => Err(TelephonyError::ModemError),
        }
    }

    /// Unlock a PIN-locked SIM via `AT+CPIN=<pin>`.
    ///
    /// Format is validated client-side (4-8 ASCII digits) so a malformed PIN
    /// never burns an attempt on the modem. On any send result the SIM state
    /// is re-queried (`check_pin`), so the return reflects the modem's
    /// post-unlock truth, not the command's bare OK: `Ok(true)` = SIM ready,
    /// `Ok(false)` = still locked (wrong PIN — attempts are decremented by
    /// the modem; use [`Self::pin_attempts_remaining`] to warn).
    pub(crate) fn unlock_pin<T: ModemTransport>(
        &mut self,
        transport: &mut T,
        pin: &str,
    ) -> Result<bool, TelephonyError> {
        if !valid_pin_format(pin) {
            return Err(TelephonyError::InvalidState);
        }
        let command = alloc::format!("AT+CPIN={pin}");
        let (result, _info, _len) = send_with_info(transport, &command, 8000)?;
        match result {
            AtResponse::Ok => self.check_pin(transport),
            // WHY: see check_pin above -- CmsError collapses into CmeError.
            AtResponse::CmeError(code) | AtResponse::CmsError(code) => {
                Err(TelephonyError::CmeError(code))
            }
            AtResponse::Error => Err(TelephonyError::ModemError),
        }
    }

    /// Unlock a PUK-locked SIM via `AT+CPIN=<puk>,<new_pin>`.
    ///
    /// A PUK has ~10 attempts total across the SIM's lifetime; the last one
    /// bricks the card. `confirm_last_attempt` MUST be true when the modem
    /// reports a single attempt remaining (query
    /// [`Self::pin_attempts_remaining`] first) — refusing to submit without
    /// that explicit confirmation returns `ConfirmationRequired` and burns
    /// nothing. When the count is unknown (None), the same guard applies:
    /// an unknown count near the end is treated as 1 (fail closed).
    pub(crate) fn unlock_puk<T: ModemTransport>(
        &mut self,
        transport: &mut T,
        puk: &str,
        new_pin: &str,
        confirm_last_attempt: bool,
    ) -> Result<bool, TelephonyError> {
        if !valid_puk_format(puk) || !valid_pin_format(new_pin) {
            return Err(TelephonyError::InvalidState);
        }
        let attempts = Self::pin_attempts_remaining(transport)?;
        if attempts.unwrap_or(1) <= 1 && !confirm_last_attempt {
            return Err(TelephonyError::ConfirmationRequired);
        }
        let command = alloc::format!("AT+CPIN={puk},{new_pin}");
        let (result, _info, _len) = send_with_info(transport, &command, 8000)?;
        match result {
            AtResponse::Ok => self.check_pin(transport),
            // WHY: see check_pin above -- CmsError collapses into CmeError.
            AtResponse::CmeError(code) | AtResponse::CmsError(code) => {
                Err(TelephonyError::CmeError(code))
            }
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
            // WHY: see check_pin above -- CmsError collapses into CmeError.
            AtResponse::CmeError(code) | AtResponse::CmsError(code) => {
                Err(TelephonyError::CmeError(code))
            }
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
                // WHY (finding 11): a +CSQ line that fails to parse must
                // surface as an error, not silently return Ok with the
                // previous (possibly stale) signal_info left unchanged.
                match telephony::parse_csq_response(line) {
                    Some((rssi_raw, ber)) => {
                        let dbm = rssi_to_dbm(rssi_raw);
                        self.signal_info = SignalInfo {
                            rssi: dbm,
                            bars: dbm_to_bars(dbm),
                            ber,
                            rssi_raw,
                        };
                        Ok(&self.signal_info)
                    }
                    None => Err(TelephonyError::ParseError),
                }
            }
            AtResponse::Ok => Ok(&self.signal_info),
            // WHY: see check_pin above -- CmsError collapses into CmeError.
            AtResponse::CmeError(code) | AtResponse::CmsError(code) => {
                Err(TelephonyError::CmeError(code))
            }
            AtResponse::Error => Err(TelephonyError::ModemError),
        }
    }

    /// Poll signal strength if the polling interval has elapsed.
    ///
    /// Returns `None` if the polling interval has not yet elapsed (no poll
    /// was attempted). Returns `Some(Ok(..))` with the updated signal info
    /// if the poll succeeded, or `Some(Err(..))` if a poll was attempted
    /// but the modem query failed. WHY (finding 12): collapsing a failed
    /// poll into the same `None` used for "not time yet" (via `.ok()`)
    /// made a modem error indistinguishable from routine throttling,
    /// mirroring the fix already applied to `Telephony::poll_signal`
    /// (issue #282 finding 3).
    pub(crate) fn poll_signal<T: ModemTransport>(
        &mut self,
        transport: &mut T,
        current_tick: u64,
    ) -> Option<Result<&SignalInfo, TelephonyError>> {
        if let Some(last) = self.last_poll_tick
            && current_tick.saturating_sub(last) < SIGNAL_POLL_INTERVAL_MS
        {
            return None;
        }

        self.last_poll_tick = Some(current_tick);
        Some(self.query_signal(transport))
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
            // WHY: see check_pin above -- CmsError collapses into CmeError.
            AtResponse::CmeError(code) | AtResponse::CmsError(code) => {
                Err(TelephonyError::CmeError(code))
            }
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
///
/// Canonical definition: [`klesis_core::rssi_to_dbm`] (#545), the same
/// implementation `telephony_parser` and klesis link.
use klesis_core::rssi_to_dbm;

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

/// PIN format per 3GPP: 4-8 ASCII digits. Validated client-side so a
/// malformed entry never burns a modem attempt (#517).
fn valid_pin_format(pin: &str) -> bool {
    (4..=8).contains(&pin.len()) && pin.bytes().all(|b| b.is_ascii_digit())
}

/// PUK format per 3GPP: 8-16 ASCII digits.
fn valid_puk_format(puk: &str) -> bool {
    (8..=16).contains(&puk.len()) && puk.bytes().all(|b| b.is_ascii_digit())
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
    use alloc::vec::Vec;

    #[test]
    fn cpin_ready_means_no_pin_required() {
        let mut transport = MockModemTransport::new();
        transport.queue_info_ok(b"+CPIN: READY");

        let mut sim = SimManager::new();
        let result = sim.check_pin(&mut transport);
        assert!(result.is_ok(), "check_pin must succeed");
        assert!(
            result.unwrap_or(false),
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
        assert!(
            !result.unwrap_or(true),
            "SIM PIN response must indicate PIN required"
        );
        assert!(
            sim.pin_required(),
            "pin_required must be true when SIM PIN is needed"
        );
    }

    // -----------------------------------------------------------------------
    // PIN/PUK unlock (#517)
    // -----------------------------------------------------------------------

    #[test]
    fn unlock_pin_success_reports_ready_after_requery() {
        let mut transport = MockModemTransport::new();
        transport.queue_ok(); // AT+CPIN=1234
        transport.queue_info_ok(b"+CPIN: READY"); // re-query

        let mut sim = SimManager::new();
        sim.sim_info.pin_required = true;
        let result = sim.unlock_pin(&mut transport, "1234");
        assert_eq!(result, Ok(true), "correct PIN must leave the SIM READY");
        assert!(!sim.pin_required(), "pin_required must clear on READY");
        assert_eq!(
            transport.sent_commands.first().map(Vec::as_slice),
            Some(b"AT+CPIN=1234".as_slice()),
            "the unlock must send AT+CPIN=<pin>"
        );
    }

    #[test]
    fn unlock_pin_wrong_pin_stays_locked() {
        let mut transport = MockModemTransport::new();
        transport.queue_ok(); // AT+CPIN=0000 accepted by modem, PIN wrong
        transport.queue_info_ok(b"+CPIN: SIM PIN"); // re-query: still locked

        let mut sim = SimManager::new();
        sim.sim_info.pin_required = true;
        let result = sim.unlock_pin(&mut transport, "0000");
        assert_eq!(result, Ok(false), "a wrong PIN must report still-locked");
        assert!(sim.pin_required(), "pin_required must stay set");
    }

    #[test]
    fn unlock_pin_rejects_malformed_without_burning_an_attempt() {
        let mut transport = MockModemTransport::new();
        let mut sim = SimManager::new();
        assert_eq!(
            sim.unlock_pin(&mut transport, "12"),
            Err(TelephonyError::InvalidState),
            "too-short PIN must be rejected client-side"
        );
        assert_eq!(
            sim.unlock_pin(&mut transport, "1234A"),
            Err(TelephonyError::InvalidState),
            "non-digit PIN must be rejected client-side"
        );
        assert!(
            transport.sent_commands.is_empty(),
            "a malformed PIN must never reach the modem (no attempt burned)"
        );
    }

    #[test]
    fn unlock_puk_success_with_attempts_remaining() {
        let mut transport = MockModemTransport::new();
        transport.queue_info_ok(b"+CPINR: 3"); // AT+CPINR
        transport.queue_ok(); // AT+CPIN=<puk>,<pin>
        transport.queue_info_ok(b"+CPIN: READY"); // re-query

        let mut sim = SimManager::new();
        let result = sim.unlock_puk(&mut transport, "12345678", "4321", false);
        assert_eq!(
            result,
            Ok(true),
            "PUK unlock with attempts remaining must succeed"
        );
        assert_eq!(
            transport.sent_commands.get(1).map(Vec::as_slice),
            Some(b"AT+CPIN=12345678,4321".as_slice()),
            "the unlock must send AT+CPIN=<puk>,<new_pin>"
        );
    }

    #[test]
    fn unlock_puk_refuses_last_attempt_without_confirmation() {
        let mut transport = MockModemTransport::new();
        transport.queue_info_ok(b"+CPINR: 1"); // one attempt left

        let mut sim = SimManager::new();
        let result = sim.unlock_puk(&mut transport, "12345678", "4321", false);
        assert_eq!(
            result,
            Err(TelephonyError::ConfirmationRequired),
            "the final PUK attempt must require explicit confirmation"
        );
        assert_eq!(
            transport.sent_commands.len(),
            1,
            "only AT+CPINR may be sent; the PUK itself must not go out unconfirmed"
        );
        assert_eq!(
            transport.sent_commands.first().map(Vec::as_slice),
            Some(b"AT+CPINR".as_slice())
        );
    }

    #[test]
    fn unlock_puk_last_attempt_proceeds_with_confirmation() {
        let mut transport = MockModemTransport::new();
        transport.queue_info_ok(b"+CPINR: 1");
        transport.queue_ok();
        transport.queue_info_ok(b"+CPIN: READY");

        let mut sim = SimManager::new();
        let result = sim.unlock_puk(&mut transport, "12345678", "4321", true);
        assert_eq!(
            result,
            Ok(true),
            "an explicitly-confirmed final attempt may proceed"
        );
    }

    #[test]
    fn unlock_puk_unknown_count_fails_closed() {
        let mut transport = MockModemTransport::new();
        transport.queue_ok(); // AT+CPINR with no info line -> count unknown

        let mut sim = SimManager::new();
        let result = sim.unlock_puk(&mut transport, "12345678", "4321", false);
        assert_eq!(
            result,
            Err(TelephonyError::ConfirmationRequired),
            "an unknown attempts count must fail closed, not assume attempts remain"
        );
    }

    #[test]
    fn cpinr_attempts_parser_accepts_known_shapes_and_rejects_malformed() {
        assert_eq!(
            telephony_parser::parse_cpinr_attempts(b"+CPINR: 3"),
            Some(3)
        );
        assert_eq!(
            telephony_parser::parse_cpinr_attempts(b"+CPINR: SIM PIN,2"),
            Some(2)
        );
        assert_eq!(
            telephony_parser::parse_cpinr_attempts(b"+CPINR: SIM PUK,1"),
            Some(1)
        );
        assert_eq!(telephony_parser::parse_cpinr_attempts(b"+CPINR: x"), None);
        assert_eq!(telephony_parser::parse_cpinr_attempts(b"+CPINR:"), None);
        assert_eq!(telephony_parser::parse_cpinr_attempts(b"+CSQ: 3"), None);
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
    fn poll_signal_distinguishes_modem_error_from_interval_skip() {
        // finding 12: a failed poll (modem/transport error) must be
        // visible as Some(Err(..)), not collapsed into the same None used
        // for "too soon to poll again".
        let mut transport = MockModemTransport::new();
        transport.send_ok = false;
        let mut sim = SimManager::new();

        let result = sim.poll_signal(&mut transport, 0);
        assert!(
            matches!(result, Some(Err(_))),
            "a failed poll must surface as Some(Err(..)), not None"
        );
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

    #[test]
    fn query_operator_extracts_name_from_valid_response() {
        // Done-when (finding 41): SimManager::query_operator has zero
        // existing coverage in this module.
        let mut transport = MockModemTransport::new();
        transport.queue_info_ok(b"+COPS: 0,0,\"Vodafone\"");

        let mut name = [0u8; 32];
        let result = SimManager::query_operator(&mut transport, &mut name);
        assert_eq!(result, Ok(8), "operator name length must be 8");
        assert_eq!(&name[..8], b"Vodafone", "operator name must be Vodafone");
    }

    #[test]
    fn query_operator_ok_with_no_info_line_returns_zero() {
        let mut transport = MockModemTransport::new();
        transport.queue_ok();

        let mut name = [0u8; 32];
        let result = SimManager::query_operator(&mut transport, &mut name);
        assert_eq!(
            result,
            Ok(0),
            "an OK with no info line must return length 0"
        );
    }

    #[test]
    fn query_operator_maps_at_error_branches() {
        // Done-when (finding 41): every AT error-branch mapping in
        // query_operator -- CmeError, CmsError (which collapses to the
        // SAME TelephonyError::CmeError variant, not a distinct one), and
        // the bare generic Error -> ModemError.
        let mut name = [0u8; 32];

        let mut transport = MockModemTransport::new();
        transport.queue_response(b"+CME ERROR: 10");
        assert_eq!(
            SimManager::query_operator(&mut transport, &mut name),
            Err(TelephonyError::CmeError(10)),
            "a +CME ERROR must map to TelephonyError::CmeError with its code"
        );

        let mut transport = MockModemTransport::new();
        transport.queue_response(b"+CMS ERROR: 302");
        assert_eq!(
            SimManager::query_operator(&mut transport, &mut name),
            Err(TelephonyError::CmeError(302)),
            "a +CMS ERROR must ALSO map to TelephonyError::CmeError (no distinct CmsError variant)"
        );

        let mut transport = MockModemTransport::new();
        transport.queue_response(b"ERROR");
        assert_eq!(
            SimManager::query_operator(&mut transport, &mut name),
            Err(TelephonyError::ModemError),
            "a bare ERROR must map to TelephonyError::ModemError"
        );
    }
}
