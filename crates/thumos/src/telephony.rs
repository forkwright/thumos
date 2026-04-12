//! Telephony subsystem: modem control and voice calls for the MT6739.
//!
//! Ports the AT command interface from `crates/klesis/src/` (at.rs, transport.rs)
//! into the kernel context:
//! - AT command/response parsing (OK, ERROR, +CSQ, +CREG, +CLIP, RING, etc.)
//! - Modem initialization sequence (AT, ATE0, AT+CFUN=1, etc.)
//! - Voice call state machine (dial, answer, hangup, incoming)
//! - Signal strength and network registration monitoring
//! - Hardware abstraction via `ModemTransport` trait for testability
//!
//! ## Hardware path
//!
//! The MT6739 modem (MD 6293) is a separate ARM core communicating via the CCCI
//! (Cross-Core Communication Interface). AT commands travel over the UART1
//! channel (`CcciChannel::Uart1Tx/Rx`). The kernel CCCI driver (`ccci.rs`)
//! provides the ring-buffer DMA and CCIF mailbox plumbing; this module sits
//! above it via the `ModemTransport` abstraction.
//!
//! ## Integration
//!
//! Boot integration deferred to Wave 3 (telephony + UI merge via `kinit.rs`).
//! For now, modules are independently testable via mock `ModemTransport`.
//!
//! ## Module structure
//!
//! AT response parsers are in [`crate::telephony_parser`].
//! Mock transport for testing is in [`crate::telephony_mock`].

// WHY: hardware driver API not yet wired to upper layers (Wave 3 integration).
#![expect(
    dead_code,
    reason = "Telephony driver API not yet wired to kinit (Wave 3)"
)]

// Re-export parser functions so external callers can still use crate::telephony::*.
pub(crate) use crate::telephony_parser::*;
#[cfg(test)]
pub(crate) use crate::telephony_mock::MockModemTransport;

extern crate alloc;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum phone number length in bytes.
pub(crate) const MAX_NUMBER_LEN: usize = 32;

/// Maximum AT response line length in bytes.
pub(crate) const MAX_LINE_LEN: usize = 256;

/// Signal strength polling interval in milliseconds (30 seconds).
const SIGNAL_POLL_INTERVAL_MS: u64 = 30_000;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Telephony subsystem errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TelephonyError {
    /// Modem hardware did not respond within timeout.
    Timeout,
    /// Modem returned an error response.
    ModemError,
    /// Modem returned a CME error with code.
    CmeError(u32),
    /// AT response could not be parsed.
    ParseError,
    /// Operation not valid in current modem state.
    InvalidState,
    /// Transport layer send/receive failure.
    TransportError,
    /// SIM card not ready or PIN required.
    SimNotReady,
    /// Phone number exceeds maximum length.
    NumberTooLong,
}

impl core::fmt::Display for TelephonyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Timeout => write!(f, "modem timeout"),
            Self::ModemError => write!(f, "modem error"),
            Self::CmeError(code) => write!(f, "CME error {code}"),
            Self::ParseError => write!(f, "AT parse error"),
            Self::InvalidState => write!(f, "invalid telephony state"),
            Self::TransportError => write!(f, "transport error"),
            Self::SimNotReady => write!(f, "SIM not ready"),
            Self::NumberTooLong => write!(f, "number too long"),
        }
    }
}

// ---------------------------------------------------------------------------
// AT response types (no_std port from klesis/src/at.rs)
// ---------------------------------------------------------------------------

/// Parsed AT response from the modem.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AtResponse {
    /// Command succeeded.
    Ok,
    /// Generic error (no code).
    Error,
    /// CME error with code.
    CmeError(u32),
}

impl Default for AtResponse {
    fn default() -> Self {
        Self::Ok
    }
}

/// Unsolicited result code from the modem.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Urc {
    /// Incoming call (RING).
    Ring,
    /// Call ended (NO CARRIER).
    NoCarrier,
    /// Line busy (BUSY).
    Busy,
    /// Signal quality report (+CSQ: rssi,ber).
    Csq { rssi: u8, ber: u8 },
    /// Network registration status changed (+CREG: stat).
    Creg { stat: RegStatus },
    /// Caller ID (+CLIP: "number",type).
    Clip {
        number: [u8; MAX_NUMBER_LEN],
        number_len: u8,
    },
}

/// Network registration status (3GPP TS 27.007 +CREG).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RegStatus {
    /// Not registered, not searching.
    NotRegistered,
    /// Registered on home network.
    RegisteredHome,
    /// Searching for network.
    Searching,
    /// Registration denied.
    Denied,
    /// Status unknown.
    Unknown,
    /// Registered, roaming.
    RegisteredRoaming,
}

impl From<u8> for RegStatus {
    fn from(val: u8) -> Self {
        match val {
            0 => Self::NotRegistered,
            1 => Self::RegisteredHome,
            2 => Self::Searching,
            3 => Self::Denied,
            5 => Self::RegisteredRoaming,
            _ => Self::Unknown,
        }
    }
}

impl core::fmt::Display for RegStatus {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotRegistered => write!(f, "not registered"),
            Self::RegisteredHome => write!(f, "registered (home)"),
            Self::Searching => write!(f, "searching"),
            Self::Denied => write!(f, "denied"),
            Self::Unknown => write!(f, "unknown"),
            Self::RegisteredRoaming => write!(f, "registered (roaming)"),
        }
    }
}

// ---------------------------------------------------------------------------
// Telephony event (returned from poll)
// ---------------------------------------------------------------------------

/// Events emitted by the telephony subsystem during polling.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TelephonyEvent {
    /// Incoming call with caller ID (if available).
    IncomingCall {
        number: [u8; MAX_NUMBER_LEN],
        number_len: u8,
    },
    /// Call ended by remote party.
    CallEnded,
    /// Remote line is busy.
    LineBusy,
    /// Signal strength changed.
    SignalUpdate { bars: u8, rssi_dbm: i16 },
    /// Network registration status changed.
    RegistrationUpdate { status: RegStatus },
    /// Modem initialization completed.
    ModemReady,
    /// Modem entered error state.
    ModemError(TelephonyError),
}

// ---------------------------------------------------------------------------
// Modem state machine
// ---------------------------------------------------------------------------

/// Modem lifecycle state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum ModemState {
    /// Modem radio is powered off.
    #[default]
    Off,
    /// Initialization sequence in progress.
    Initializing,
    /// Registered on a cellular network.
    Registered,
    /// A fatal error occurred.
    Error(TelephonyError),
}

impl core::fmt::Display for ModemState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Off => write!(f, "off"),
            Self::Initializing => write!(f, "initializing"),
            Self::Registered => write!(f, "registered"),
            Self::Error(e) => write!(f, "error: {e}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Voice call state machine
// ---------------------------------------------------------------------------

/// Voice call lifecycle state machine.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum CallState {
    /// No active call.
    #[default]
    Idle,
    /// Outgoing call dialing.
    Dialing {
        number: [u8; MAX_NUMBER_LEN],
        len: u8,
    },
    /// Ringing at remote end.
    Alerting,
    /// Call connected.
    Active { start_tick: u64 },
    /// Call on hold.
    Held,
    /// Incoming call ringing.
    Incoming {
        number: [u8; MAX_NUMBER_LEN],
        len: u8,
    },
    /// Hangup in progress.
    Hangup,
}

impl core::fmt::Display for CallState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Idle => write!(f, "idle"),
            Self::Dialing { .. } => write!(f, "dialing"),
            Self::Alerting => write!(f, "alerting"),
            Self::Active { .. } => write!(f, "active"),
            Self::Held => write!(f, "held"),
            Self::Incoming { .. } => write!(f, "incoming"),
            Self::Hangup => write!(f, "hangup"),
        }
    }
}

// ---------------------------------------------------------------------------
// ModemTransport trait
// ---------------------------------------------------------------------------

/// Hardware abstraction for modem communication.
///
/// Implementors map this onto the kernel CCCI driver (Uart1 channel) or a
/// test fixture. This trait operates at the AT command level, not raw bytes,
/// because the CCCI framing and line buffering are transport concerns.
pub trait ModemTransport {
    /// Send an AT command string to the modem (without CR/LF termination;
    /// the implementation adds framing).
    fn send_at(&mut self, command: &str) -> Result<(), TelephonyError>;

    /// Receive the next AT response line from the modem.
    ///
    /// Returns the raw response bytes (without CR/LF) into the provided
    /// buffer. Returns the number of bytes written, or an error.
    /// A timeout of 0 means non-blocking poll.
    fn recv_line(&mut self, buf: &mut [u8; MAX_LINE_LEN], timeout_ms: u32)
        -> Result<usize, TelephonyError>;

    /// Poll for an unsolicited result code without blocking.
    ///
    /// Returns `None` if no URC is available.
    fn poll_urc_line(&mut self, buf: &mut [u8; MAX_LINE_LEN]) -> Option<usize>;
}

// ---------------------------------------------------------------------------
// AT command/response exchange helper
// ---------------------------------------------------------------------------

/// Send an AT command and wait for the final result code.
///
/// Collects informational lines into `info_buf` (up to `info_buf.len()` lines).
/// Returns the final result code and the number of info lines collected.
fn send_and_wait<T: ModemTransport>(
    transport: &mut T,
    command: &str,
    info_buf: &mut [[u8; MAX_LINE_LEN]],
    timeout_ms: u32,
) -> Result<(AtResponse, usize), TelephonyError> {
    transport.send_at(command)?;

    let mut info_count = 0;
    let mut line_buf = [0u8; MAX_LINE_LEN];

    // Read lines until we get a final result code.
    // Limit iterations to prevent infinite loop on broken transport.
    for _ in 0..64 {
        let n = transport.recv_line(&mut line_buf, timeout_ms)?;
        let line = &line_buf[..n];

        // Skip blank lines.
        if line.is_empty() {
            continue;
        }

        // Check for final result code.
        if let Some(result) = parse_final_result(line) {
            return Ok((result, info_count));
        }

        // Store as informational line.
        if info_count < info_buf.len() {
            info_buf[info_count][..n].copy_from_slice(line);
            // Zero-fill the rest for clean comparison.
            for b in &mut info_buf[info_count][n..] {
                *b = 0;
            }
            info_count += 1;
        }
    }

    Err(TelephonyError::Timeout)
}

/// Send a simple AT command expecting only OK/ERROR, no info lines needed.
fn send_simple<T: ModemTransport>(
    transport: &mut T,
    command: &str,
    timeout_ms: u32,
) -> Result<AtResponse, TelephonyError> {
    let mut info_buf = [[0u8; MAX_LINE_LEN]; 0];
    let (result, _) = send_and_wait(transport, command, &mut info_buf, timeout_ms)?;
    Ok(result)
}

/// Send an AT command and collect one info line.
fn send_with_info<T: ModemTransport>(
    transport: &mut T,
    command: &str,
    timeout_ms: u32,
) -> Result<(AtResponse, [u8; MAX_LINE_LEN], usize), TelephonyError> {
    let mut info_buf = [[0u8; MAX_LINE_LEN]; 1];
    let (result, info_count) = send_and_wait(transport, command, &mut info_buf, timeout_ms)?;
    if info_count > 0 {
        // Find actual length of the info line.
        let len = info_buf[0]
            .iter()
            .rposition(|&b| b != 0)
            .map_or(0, |p| p + 1);
        Ok((result, info_buf[0], len))
    } else {
        Ok((result, [0u8; MAX_LINE_LEN], 0))
    }
}

// ---------------------------------------------------------------------------
// Telephony subsystem
// ---------------------------------------------------------------------------

/// Telephony subsystem: manages modem state and voice calls.
pub struct Telephony<T: ModemTransport> {
    /// Current modem state.
    modem_state: ModemState,
    /// Current voice call state.
    call_state: CallState,
    /// Signal strength in bars (0-4).
    signal_strength: u8,
    /// Signal strength in dBm.
    signal_dbm: i16,
    /// Bit error rate from last CSQ query.
    signal_ber: u8,
    /// Operator name.
    operator_name: [u8; MAX_OPERATOR_LEN],
    /// Length of valid bytes in operator_name.
    operator_len: u8,
    /// Network registration status.
    registered: bool,
    /// Registration status detail.
    reg_status: RegStatus,
    /// Whether LTE-only mode is active (2G/3G refused via `AT+COPS=0,,,7`).
    lte_only: bool,
    /// Hardware transport.
    transport: T,
    /// Last signal poll tick (ms).
    last_signal_poll: u64,
    /// Initialization step tracker.
    init_step: u8,
}

impl<T: ModemTransport> Telephony<T> {
    /// Create a new telephony subsystem with the given transport.
    #[must_use]
    pub fn new(transport: T) -> Self {
        Self {
            modem_state: ModemState::Off,
            call_state: CallState::Idle,
            signal_strength: 0,
            signal_dbm: -999,
            signal_ber: 99,
            operator_name: [0u8; MAX_OPERATOR_LEN],
            operator_len: 0,
            registered: false,
            reg_status: RegStatus::NotRegistered,
            lte_only: false,
            transport,
            last_signal_poll: 0,
            init_step: 0,
        }
    }

    /// Return the current modem state.
    #[must_use]
    pub fn modem_state(&self) -> ModemState {
        self.modem_state
    }

    /// Return the current call state.
    #[must_use]
    pub fn call_state(&self) -> &CallState {
        &self.call_state
    }

    /// Return the current signal strength in bars (0-4).
    #[must_use]
    pub fn signal_strength(&self) -> u8 {
        self.signal_strength
    }

    /// Return the current signal strength in dBm.
    #[must_use]
    pub fn signal_dbm(&self) -> i16 {
        self.signal_dbm
    }

    /// Return the operator name as a byte slice.
    #[must_use]
    pub fn operator_name(&self) -> &[u8] {
        &self.operator_name[..self.operator_len as usize]
    }

    /// Return whether the modem is registered on a network.
    #[must_use]
    pub fn is_registered(&self) -> bool {
        self.registered
    }

    // -----------------------------------------------------------------------
    // Modem initialization
    // -----------------------------------------------------------------------

    /// Initialize the modem.
    ///
    /// Runs the full AT initialization sequence:
    /// 1. `AT`              — verify modem responds
    /// 2. `ATE0`            — disable echo
    /// 3. `AT+CFUN=1`       — full functionality
    /// 4. `AT+CPIN?`        — check SIM PIN status
    /// 5. `AT+COPS=0,,,7`   — restrict to LTE only (refuse 2G/3G)
    /// 6. `AT+COPS?`        — check network registration / operator
    /// 7. `AT+CREG=1`       — enable network registration URCs
    /// 8. `AT+CLIP=1`       — enable caller ID
    /// 9. `AT+CSQ`          — initial signal strength query
    ///
    /// Returns `Ok(())` on success, or an error describing which step failed.
    pub fn initialize(&mut self) -> Result<(), TelephonyError> {
        self.modem_state = ModemState::Initializing;
        self.init_step = 0;

        // Step 1: Verify modem responds.
        let result = send_simple(&mut self.transport, "AT", 5000);
        match result {
            Ok(AtResponse::Ok) => {}
            Ok(AtResponse::Error | AtResponse::CmeError(_)) | Err(_) => {
                self.modem_state = ModemState::Error(TelephonyError::Timeout);
                return Err(TelephonyError::Timeout);
            }
        }
        self.init_step = 1;

        // Step 2: Disable echo.
        let result = send_simple(&mut self.transport, "ATE0", 2000);
        if !matches!(result, Ok(AtResponse::Ok)) {
            self.modem_state = ModemState::Error(TelephonyError::ModemError);
            return Err(TelephonyError::ModemError);
        }
        self.init_step = 2;

        // Step 3: Full functionality mode.
        let result = send_simple(&mut self.transport, "AT+CFUN=1", 5000);
        if !matches!(result, Ok(AtResponse::Ok)) {
            self.modem_state = ModemState::Error(TelephonyError::ModemError);
            return Err(TelephonyError::ModemError);
        }
        self.init_step = 3;

        // Step 4: Check SIM PIN status.
        let cpin_result = send_with_info(&mut self.transport, "AT+CPIN?", 5000);
        match cpin_result {
            Ok((AtResponse::Ok, ref info_line, info_len)) if info_len > 0 => {
                let line = &info_line[..info_len];
                match parse_cpin_response(line) {
                    Some(true) => {
                        // SIM ready, no PIN required.
                    }
                    Some(false) => {
                        self.modem_state = ModemState::Error(TelephonyError::SimNotReady);
                        return Err(TelephonyError::SimNotReady);
                    }
                    None => {
                        self.modem_state = ModemState::Error(TelephonyError::ParseError);
                        return Err(TelephonyError::ParseError);
                    }
                }
            }
            Ok((AtResponse::CmeError(code), _, _)) => {
                self.modem_state = ModemState::Error(TelephonyError::CmeError(code));
                return Err(TelephonyError::CmeError(code));
            }
            _ => {
                self.modem_state = ModemState::Error(TelephonyError::SimNotReady);
                return Err(TelephonyError::SimNotReady);
            }
        }
        self.init_step = 4;

        // Step 5: Refuse 2G/3G — restrict to LTE only.
        // WHY: 2G (GSM) networks use weak A5/1 or A5/2 encryption that is
        // trivially broken by IMSI catchers. By refusing to register on
        // anything below LTE, we eliminate the primary downgrade attack vector.
        // Non-fatal: if the modem rejects this (e.g. no LTE coverage), we
        // log but continue — better to have degraded service than no service.
        self.refuse_2g();
        self.init_step = 5;

        // Step 6: Query operator name.
        let cops_result = send_with_info(&mut self.transport, "AT+COPS?", 5000);
        if let Ok((AtResponse::Ok, ref info_line, info_len)) = cops_result {
            if info_len > 0 {
                let line = &info_line[..info_len];
                if let Some(len) = parse_cops_response(line, &mut self.operator_name) {
                    self.operator_len = len;
                }
            }
        }
        self.init_step = 6;

        // Step 7: Enable network registration URCs.
        let _ = send_simple(&mut self.transport, "AT+CREG=1", 2000);
        self.init_step = 7;

        // Step 8: Enable caller ID.
        let _ = send_simple(&mut self.transport, "AT+CLIP=1", 2000);
        self.init_step = 8;

        // Step 9: Initial signal strength query.
        self.update_signal_strength()?;
        self.init_step = 9;

        self.modem_state = ModemState::Registered;
        self.registered = true;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // 2G refusal
    // -----------------------------------------------------------------------

    /// Send `AT+COPS=0,,,7` to restrict the modem to LTE-only mode.
    ///
    /// This prevents the modem from registering on GSM (2G) or UMTS (3G)
    /// networks, blocking the primary downgrade attack vector used by IMSI
    /// catchers. The command sets automatic operator selection with access
    /// technology restricted to E-UTRAN (LTE).
    ///
    /// Non-fatal: if the modem rejects this command (e.g. the SIM or network
    /// does not support LTE), the error is recorded but initialization
    /// continues. Some connectivity is better than none.
    pub fn refuse_2g(&mut self) {
        let result = send_simple(&mut self.transport, "AT+COPS=0,,,7", 10_000);
        self.lte_only = matches!(result, Ok(AtResponse::Ok));
    }

    /// Return whether LTE-only mode is active (2G/3G refused).
    #[must_use]
    pub fn is_lte_only(&self) -> bool {
        self.lte_only
    }

    // -----------------------------------------------------------------------
    // Signal strength
    // -----------------------------------------------------------------------

    /// Query and update signal strength from the modem.
    fn update_signal_strength(&mut self) -> Result<(), TelephonyError> {
        let result = send_with_info(&mut self.transport, "AT+CSQ", 2000);
        match result {
            Ok((AtResponse::Ok, ref info_line, info_len)) if info_len > 0 => {
                let line = &info_line[..info_len];
                if let Some((rssi, ber)) = parse_csq_response(line) {
                    let dbm = rssi_to_dbm(rssi);
                    self.signal_dbm = dbm;
                    self.signal_strength = dbm_to_bars(dbm);
                    self.signal_ber = ber;
                }
                Ok(())
            }
            Ok((AtResponse::Ok, _, _)) => Ok(()), // No info line, keep current values.
            Ok(_) => Err(TelephonyError::ModemError),
            Err(e) => Err(e),
        }
    }

    /// Poll signal strength if the polling interval has elapsed.
    ///
    /// `current_tick` is the current kernel tick in milliseconds.
    pub fn poll_signal(&mut self, current_tick: u64) -> Option<TelephonyEvent> {
        if !matches!(self.modem_state, ModemState::Registered) {
            return None;
        }

        if current_tick.saturating_sub(self.last_signal_poll) < SIGNAL_POLL_INTERVAL_MS {
            return None;
        }

        self.last_signal_poll = current_tick;
        if self.update_signal_strength().is_ok() {
            Some(TelephonyEvent::SignalUpdate {
                bars: self.signal_strength,
                rssi_dbm: self.signal_dbm,
            })
        } else {
            None
        }
    }

    // -----------------------------------------------------------------------
    // Voice call operations
    // -----------------------------------------------------------------------

    /// Dial a phone number.
    ///
    /// Sends `ATD<number>;` and transitions to Dialing state.
    pub fn dial(&mut self, number: &[u8]) -> Result<(), TelephonyError> {
        if !matches!(self.modem_state, ModemState::Registered) {
            return Err(TelephonyError::InvalidState);
        }
        if !matches!(self.call_state, CallState::Idle) {
            return Err(TelephonyError::InvalidState);
        }
        if number.len() > MAX_NUMBER_LEN {
            return Err(TelephonyError::NumberTooLong);
        }

        // Build ATD command: "ATD+15551234567;"
        let mut cmd_buf = [0u8; 4 + MAX_NUMBER_LEN + 1]; // "ATD" + number + ";"
        cmd_buf[0] = b'A';
        cmd_buf[1] = b'T';
        cmd_buf[2] = b'D';
        cmd_buf[3..3 + number.len()].copy_from_slice(number);
        cmd_buf[3 + number.len()] = b';';
        let cmd_len = 4 + number.len();

        // SAFETY: number was validated as fitting in MAX_NUMBER_LEN,
        // and we only wrote ASCII bytes from the input + "ATD" + ";".
        let cmd_str = core::str::from_utf8(&cmd_buf[..cmd_len])
            .map_err(|_| TelephonyError::ParseError)?;

        let result = send_simple(&mut self.transport, cmd_str, 10_000)?;
        match result {
            AtResponse::Ok => {
                let mut dial_number = [0u8; MAX_NUMBER_LEN];
                dial_number[..number.len()].copy_from_slice(number);
                self.call_state = CallState::Dialing {
                    number: dial_number,
                    len: number.len() as u8,
                };
                Ok(())
            }
            AtResponse::Error => Err(TelephonyError::ModemError),
            AtResponse::CmeError(code) => Err(TelephonyError::CmeError(code)),
        }
    }

    /// Answer an incoming call.
    ///
    /// Sends `ATA` and transitions to Active state.
    pub fn answer(&mut self, current_tick: u64) -> Result<(), TelephonyError> {
        if !matches!(self.call_state, CallState::Incoming { .. }) {
            return Err(TelephonyError::InvalidState);
        }

        let result = send_simple(&mut self.transport, "ATA", 10_000)?;
        match result {
            AtResponse::Ok => {
                self.call_state = CallState::Active {
                    start_tick: current_tick,
                };
                Ok(())
            }
            AtResponse::Error => Err(TelephonyError::ModemError),
            AtResponse::CmeError(code) => Err(TelephonyError::CmeError(code)),
        }
    }

    /// Hang up the current call.
    ///
    /// Sends `ATH` and transitions to Idle state.
    pub fn hangup(&mut self) -> Result<(), TelephonyError> {
        // Allow hangup from any active call state.
        match &self.call_state {
            CallState::Idle => return Err(TelephonyError::InvalidState),
            _ => {}
        }

        let result = send_simple(&mut self.transport, "ATH", 10_000)?;
        match result {
            AtResponse::Ok => {
                self.call_state = CallState::Idle;
                Ok(())
            }
            AtResponse::Error => {
                // Some modems return ERROR after ATH if call already ended;
                // transition to Idle anyway.
                self.call_state = CallState::Idle;
                Ok(())
            }
            AtResponse::CmeError(code) => Err(TelephonyError::CmeError(code)),
        }
    }

    // -----------------------------------------------------------------------
    // URC polling
    // -----------------------------------------------------------------------

    /// Poll for unsolicited result codes and return any telephony events.
    ///
    /// Should be called periodically (e.g., from the main event loop).
    pub fn poll(&mut self) -> Option<TelephonyEvent> {
        let mut line_buf = [0u8; MAX_LINE_LEN];
        let n = self.transport.poll_urc_line(&mut line_buf)?;
        let line = &line_buf[..n];

        if line.is_empty() {
            return None;
        }

        if let Some(urc) = parse_urc(line) {
            return self.handle_urc(urc);
        }

        None
    }

    /// Handle a parsed URC and update internal state.
    fn handle_urc(&mut self, urc: Urc) -> Option<TelephonyEvent> {
        match urc {
            Urc::Ring => {
                // Only transition to Incoming if we're currently Idle.
                if matches!(self.call_state, CallState::Idle) {
                    self.call_state = CallState::Incoming {
                        number: [0u8; MAX_NUMBER_LEN],
                        len: 0,
                    };
                }
                Some(TelephonyEvent::IncomingCall {
                    number: [0u8; MAX_NUMBER_LEN],
                    number_len: 0,
                })
            }
            Urc::Clip { number, number_len } => {
                // Update the incoming call with caller ID.
                if let CallState::Incoming {
                    number: ref mut n,
                    len: ref mut l,
                } = self.call_state
                {
                    *n = number;
                    *l = number_len;
                }
                Some(TelephonyEvent::IncomingCall {
                    number,
                    number_len,
                })
            }
            Urc::NoCarrier => {
                self.call_state = CallState::Idle;
                Some(TelephonyEvent::CallEnded)
            }
            Urc::Busy => {
                self.call_state = CallState::Idle;
                Some(TelephonyEvent::LineBusy)
            }
            Urc::Csq { rssi, ber } => {
                let dbm = rssi_to_dbm(rssi);
                self.signal_dbm = dbm;
                self.signal_strength = dbm_to_bars(dbm);
                self.signal_ber = ber;
                Some(TelephonyEvent::SignalUpdate {
                    bars: self.signal_strength,
                    rssi_dbm: dbm,
                })
            }
            Urc::Creg { stat } => {
                self.reg_status = stat;
                self.registered = matches!(
                    stat,
                    RegStatus::RegisteredHome | RegStatus::RegisteredRoaming
                );
                Some(TelephonyEvent::RegistrationUpdate { status: stat })
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Real hardware implementation (non-test only)
// ---------------------------------------------------------------------------

/// Real modem transport via the kernel CCCI driver (Uart1 channel).
#[cfg(not(test))]
pub struct CcciModemTransport {
    /// Receive line buffer for accumulating bytes.
    rx_buf: [u8; MAX_LINE_LEN],
    /// Number of valid bytes in rx_buf.
    rx_len: usize,
}

#[cfg(not(test))]
impl CcciModemTransport {
    /// Create a new CCCI-backed modem transport.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            rx_buf: [0u8; MAX_LINE_LEN],
            rx_len: 0,
        }
    }
}

#[cfg(not(test))]
impl ModemTransport for CcciModemTransport {
    fn send_at(&mut self, command: &str) -> Result<(), TelephonyError> {
        // WHY: Wave 3 will wire this to the CCCI Uart1Tx channel.
        // For now, the transport is structurally complete but not connected.
        let _ = command;
        Err(TelephonyError::TransportError)
    }

    fn recv_line(
        &mut self,
        buf: &mut [u8; MAX_LINE_LEN],
        timeout_ms: u32,
    ) -> Result<usize, TelephonyError> {
        let _ = (buf, timeout_ms);
        Err(TelephonyError::TransportError)
    }

    fn poll_urc_line(&mut self, buf: &mut [u8; MAX_LINE_LEN]) -> Option<usize> {
        let _ = buf;
        None
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create a mock transport pre-loaded for a full init sequence.
    fn mock_for_init() -> MockModemTransport {
        let mut mock = MockModemTransport::new();
        // Step 1: AT -> OK
        mock.queue_ok();
        // Step 2: ATE0 -> OK
        mock.queue_ok();
        // Step 3: AT+CFUN=1 -> OK
        mock.queue_ok();
        // Step 4: AT+CPIN? -> +CPIN: READY + OK
        mock.queue_info_ok(b"+CPIN: READY");
        // Step 5: AT+COPS=0,,,7 -> OK (LTE only / refuse 2G)
        mock.queue_ok();
        // Step 6: AT+COPS? -> +COPS: 0,0,"T-Mobile" + OK
        mock.queue_info_ok(b"+COPS: 0,0,\"T-Mobile\"");
        // Step 7: AT+CREG=1 -> OK
        mock.queue_ok();
        // Step 8: AT+CLIP=1 -> OK
        mock.queue_ok();
        // Step 9: AT+CSQ -> +CSQ: 18,99 + OK
        mock.queue_info_ok(b"+CSQ: 18,99");
        mock
    }

    #[test]
    fn modem_starts_off() {
        let mock = MockModemTransport::new();
        let tel = Telephony::new(mock);
        assert_eq!(
            tel.modem_state(),
            ModemState::Off,
            "newly created telephony must start in Off state"
        );
        assert_eq!(
            *tel.call_state(),
            CallState::Idle,
            "call state must be Idle at start"
        );
    }

    #[test]
    fn init_sequence_sends_correct_commands() {
        let mock = mock_for_init();
        let mut tel = Telephony::new(mock);
        let result = tel.initialize();
        assert!(result.is_ok(), "initialization must succeed with valid mock");

        let commands = &tel.transport.sent_commands;
        assert_eq!(commands.len(), 9, "init must send exactly 9 AT commands");
        assert_eq!(commands[0], b"AT", "step 1: AT");
        assert_eq!(commands[1], b"ATE0", "step 2: ATE0");
        assert_eq!(commands[2], b"AT+CFUN=1", "step 3: AT+CFUN=1");
        assert_eq!(commands[3], b"AT+CPIN?", "step 4: AT+CPIN?");
        assert_eq!(commands[4], b"AT+COPS=0,,,7", "step 5: AT+COPS=0,,,7 (LTE only)");
        assert_eq!(commands[5], b"AT+COPS?", "step 6: AT+COPS?");
        assert_eq!(commands[6], b"AT+CREG=1", "step 7: AT+CREG=1");
        assert_eq!(commands[7], b"AT+CLIP=1", "step 8: AT+CLIP=1");
        assert_eq!(commands[8], b"AT+CSQ", "step 9: AT+CSQ");

        assert_eq!(
            tel.modem_state(),
            ModemState::Registered,
            "modem must be Registered after successful init"
        );
        assert!(
            tel.is_registered(),
            "must report registered after init"
        );
    }

    #[test]
    fn dial_transitions_to_dialing() {
        let mock = mock_for_init();
        let mut tel = Telephony::new(mock);
        tel.initialize().ok();

        // Queue OK for the ATD command.
        tel.transport.queue_ok();

        let number = b"+15551234567";
        let result = tel.dial(number);
        assert!(result.is_ok(), "dial must succeed");

        match tel.call_state() {
            CallState::Dialing { number: n, len } => {
                assert_eq!(
                    &n[..*len as usize],
                    number,
                    "dialing number must match"
                );
            }
            other => panic!("expected Dialing state, got: {other}"),
        }

        // Verify the ATD command was sent.
        let last_cmd = tel.transport.sent_commands.last();
        assert_eq!(
            last_cmd.map(|c| c.as_slice()),
            Some(b"ATD+15551234567;" as &[u8]),
            "ATD command must be formatted correctly"
        );
    }

    #[test]
    fn ring_urc_transitions_to_incoming() {
        let mock = mock_for_init();
        let mut tel = Telephony::new(mock);
        tel.initialize().ok();

        tel.transport.queue_urc(b"RING");
        let event = tel.poll();
        assert!(
            matches!(event, Some(TelephonyEvent::IncomingCall { .. })),
            "RING URC must produce IncomingCall event"
        );
        assert!(
            matches!(tel.call_state(), CallState::Incoming { .. }),
            "call state must transition to Incoming on RING"
        );
    }

    #[test]
    fn answer_transitions_to_active() {
        let mock = mock_for_init();
        let mut tel = Telephony::new(mock);
        tel.initialize().ok();

        // Simulate incoming call.
        tel.call_state = CallState::Incoming {
            number: [0u8; MAX_NUMBER_LEN],
            len: 0,
        };

        // Queue OK for ATA.
        tel.transport.queue_ok();

        let result = tel.answer(1000);
        assert!(result.is_ok(), "answer must succeed");
        assert!(
            matches!(tel.call_state(), CallState::Active { start_tick: 1000 }),
            "call state must transition to Active with correct tick"
        );
    }

    #[test]
    fn hangup_transitions_to_idle() {
        let mock = mock_for_init();
        let mut tel = Telephony::new(mock);
        tel.initialize().ok();

        // Simulate active call.
        tel.call_state = CallState::Active { start_tick: 500 };

        // Queue OK for ATH.
        tel.transport.queue_ok();

        let result = tel.hangup();
        assert!(result.is_ok(), "hangup must succeed");
        assert_eq!(
            *tel.call_state(),
            CallState::Idle,
            "call state must transition to Idle after hangup"
        );
    }

    #[test]
    fn no_carrier_transitions_to_idle() {
        let mock = mock_for_init();
        let mut tel = Telephony::new(mock);
        tel.initialize().ok();

        // Simulate active call.
        tel.call_state = CallState::Active { start_tick: 500 };

        tel.transport.queue_urc(b"NO CARRIER");
        let event = tel.poll();
        assert_eq!(
            event,
            Some(TelephonyEvent::CallEnded),
            "NO CARRIER must produce CallEnded event"
        );
        assert_eq!(
            *tel.call_state(),
            CallState::Idle,
            "call state must transition to Idle on NO CARRIER"
        );
    }

    #[test]
    fn number_too_long_error() {
        // TelephonyError::NumberTooLong is returned when dialing a number
        // that exceeds MAX_NUMBER_LEN. Verify the variant displays correctly.
        let err = TelephonyError::NumberTooLong;
        let msg = alloc::format!("{err}");
        assert_eq!(msg, "number too long", "NumberTooLong display must match");
    }

    // ── 2G refusal tests ─────────────────────────────────────────────────────

    #[test]
    fn init_sends_lte_only_command() {
        let mock = mock_for_init();
        let mut tel = Telephony::new(mock);
        tel.initialize().ok();

        // Step 5 must be the LTE-only command.
        assert_eq!(
            tel.transport.sent_commands[4],
            b"AT+COPS=0,,,7",
            "step 5 must send AT+COPS=0,,,7 (LTE only)"
        );
        assert!(
            tel.is_lte_only(),
            "LTE-only mode must be active after successful init"
        );
    }

    #[test]
    fn refuse_2g_sets_lte_only_flag() {
        let mut mock = MockModemTransport::new();
        // Queue OK for refuse_2g.
        mock.queue_ok();
        let mut tel = Telephony::new(mock);
        // Manually call refuse_2g outside init.
        tel.refuse_2g();
        assert!(
            tel.is_lte_only(),
            "refuse_2g must set lte_only=true on OK response"
        );
        assert_eq!(
            tel.transport.sent_commands.last().map(|c| c.as_slice()),
            Some(b"AT+COPS=0,,,7" as &[u8]),
            "refuse_2g must send AT+COPS=0,,,7"
        );
    }

    #[test]
    fn refuse_2g_non_fatal_on_error() {
        let mut mock = MockModemTransport::new();
        // Queue ERROR for refuse_2g (modem rejects LTE-only).
        mock.queue_response(b"ERROR");
        let mut tel = Telephony::new(mock);
        tel.refuse_2g();
        assert!(
            !tel.is_lte_only(),
            "refuse_2g must set lte_only=false on ERROR response"
        );
    }

    #[test]
    fn refuse_2g_command_is_correct_at_string() {
        // Verify the exact AT command string matches the 3GPP TS 27.007 spec.
        let mut mock = MockModemTransport::new();
        mock.queue_ok();
        let mut tel = Telephony::new(mock);
        tel.refuse_2g();
        let cmd = &tel.transport.sent_commands[0];
        assert_eq!(
            cmd,
            b"AT+COPS=0,,,7",
            "command must be AT+COPS=0,,,7 per 3GPP TS 27.007 section 7.3"
        );
    }

    #[test]
    fn init_continues_if_lte_only_rejected() {
        // If the modem rejects AT+COPS=0,,,7, init must still complete.
        let mut mock = MockModemTransport::new();
        // Step 1: AT -> OK
        mock.queue_ok();
        // Step 2: ATE0 -> OK
        mock.queue_ok();
        // Step 3: AT+CFUN=1 -> OK
        mock.queue_ok();
        // Step 4: AT+CPIN? -> +CPIN: READY + OK
        mock.queue_info_ok(b"+CPIN: READY");
        // Step 5: AT+COPS=0,,,7 -> ERROR (rejected)
        mock.queue_response(b"ERROR");
        // Step 6: AT+COPS? -> +COPS: 0,0,"T-Mobile" + OK
        mock.queue_info_ok(b"+COPS: 0,0,\"T-Mobile\"");
        // Step 7: AT+CREG=1 -> OK
        mock.queue_ok();
        // Step 8: AT+CLIP=1 -> OK
        mock.queue_ok();
        // Step 9: AT+CSQ -> +CSQ: 18,99 + OK
        mock.queue_info_ok(b"+CSQ: 18,99");

        let mut tel = Telephony::new(mock);
        let result = tel.initialize();
        assert!(
            result.is_ok(),
            "init must succeed even if LTE-only command is rejected"
        );
        assert!(
            !tel.is_lte_only(),
            "lte_only must be false when the modem rejected the command"
        );
        assert_eq!(
            tel.modem_state(),
            ModemState::Registered,
            "modem must reach Registered state despite LTE-only rejection"
        );
    }
}
