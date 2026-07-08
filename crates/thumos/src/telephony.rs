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
#[cfg(test)]
pub(crate) use crate::telephony_mock::MockModemTransport;
pub(crate) use crate::telephony_parser::*;

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
    /// SIM card requires PUK unlock (too many wrong PIN attempts) -- kept
    /// distinct from [`Self::SimNotReady`] so a caller does not route to
    /// the wrong (PIN) unlock flow (issue #282 finding 17). Entering a PIN
    /// against a PUK-locked SIM burns limited PUK attempts and can
    /// permanently lock the SIM.
    SimPukRequired,
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
            Self::SimPukRequired => write!(f, "SIM PUK required"),
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
    /// CMS error with code (SMS-specific, 3GPP TS 27.005).
    CmsError(u32),
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
    /// Network registration status changed (+CREG: stat[,...,AcT]).
    Creg {
        stat: RegStatus,
        act: Option<RadioAccessTech>,
    },
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

/// Radio access technology, parsed from the `+CREG` `<AcT>` field (3GPP TS
/// 27.007 §7.2). Distinguishes the technology a registration actually landed
/// on -- the status bar renders it (2G/3G/LTE) and the threat model reads it
/// (a GSM/UTRAN registration is a downgrade signal even when LTE-only
/// selection was requested via `AT+COPS=0,,,7`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RadioAccessTech {
    /// GSM (`<AcT>`=0).
    Gsm,
    /// GSM Compact (`<AcT>`=1).
    GsmCompact,
    /// UTRAN / UMTS (`<AcT>`=2).
    Utran,
    /// GSM with EGPRS -- EDGE (`<AcT>`=3).
    GsmEgprs,
    /// UTRAN with HSDPA (`<AcT>`=4).
    UtranHsdpa,
    /// UTRAN with HSUPA (`<AcT>`=5).
    UtranHsupa,
    /// UTRAN with HSDPA and HSUPA (`<AcT>`=6).
    UtranHsdpaHsupa,
    /// E-UTRAN -- LTE (`<AcT>`=7).
    EUtran,
    /// E-UTRAN in NB-S1 mode -- LTE (NB-IoT) (`<AcT>`=8).
    EUtranNbS1,
}

impl RadioAccessTech {
    /// Map a raw `+CREG` `<AcT>` code to a radio access technology.
    ///
    /// Returns `None` for a code outside the defined 0-8 range rather than a
    /// wrong technology -- an unknown RAT must not masquerade as a known one.
    #[must_use]
    pub const fn from_act(val: u8) -> Option<Self> {
        Some(match val {
            0 => Self::Gsm,
            1 => Self::GsmCompact,
            2 => Self::Utran,
            3 => Self::GsmEgprs,
            4 => Self::UtranHsdpa,
            5 => Self::UtranHsupa,
            6 => Self::UtranHsdpaHsupa,
            7 => Self::EUtran,
            8 => Self::EUtranNbS1,
            _ => return None,
        })
    }

    /// The cellular generation this technology belongs to. GSM/EGPRS map to
    /// 2G, the UTRAN family to 3G, and E-UTRAN to 4G/LTE.
    #[must_use]
    pub const fn generation(self) -> RatGeneration {
        match self {
            Self::Gsm | Self::GsmCompact | Self::GsmEgprs => RatGeneration::TwoG,
            Self::Utran | Self::UtranHsdpa | Self::UtranHsupa | Self::UtranHsdpaHsupa => {
                RatGeneration::ThreeG
            }
            Self::EUtran | Self::EUtranNbS1 => RatGeneration::FourG,
        }
    }
}

/// Cellular generation of a [`RadioAccessTech`] -- the coarse 2G/3G/4G tier the
/// status bar and threat model reason about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RatGeneration {
    /// 2G (GSM / GPRS / EDGE).
    TwoG,
    /// 3G (UTRAN / UMTS / HSPA).
    ThreeG,
    /// 4G (LTE / E-UTRAN).
    FourG,
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
    /// Radio is on and initialized; network registration not yet
    /// confirmed. Set at the end of [`Telephony::initialize`]; promoted to
    /// / demoted from [`ModemState::Registered`] only by
    /// `Telephony::apply_reg_status` reacting to `+CREG` state.
    Ready,
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
            Self::Ready => write!(f, "ready (not registered)"),
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
    fn recv_line(
        &mut self,
        buf: &mut [u8; MAX_LINE_LEN],
        timeout_ms: u32,
    ) -> Result<usize, TelephonyError>;

    /// Poll for an unsolicited result code without blocking.
    ///
    /// Returns `None` if no URC is available.
    fn poll_urc_line(&mut self, buf: &mut [u8; MAX_LINE_LEN]) -> Option<usize>;
}

// ---------------------------------------------------------------------------
// AT command/response exchange helper
// ---------------------------------------------------------------------------

/// Maximum informational/blank lines read while waiting for a command's
/// final result code.
///
/// Every AT exchange in this module expects at most one info line before
/// the final result ([`send_simple`] stores none, [`send_with_info`] stores
/// one); this cap is generous headroom for stray echo/blank lines, not an
/// expected-traffic budget. Bounding it (down from 64) shrinks the
/// worst-case block time a modem pacing junk lines just under `timeout_ms`
/// can impose on a single command (issue #282 finding 14) -- it narrows,
/// but does not eliminate, that window; a full fix needs a wall-clock
/// total budget, which would require threading a clock source into this
/// currently transport-mock-only, timer-agnostic function.
const MAX_RESPONSE_LINES: usize = 16;

/// Maximum best-effort drain attempts after a `recv_line` failure.
///
/// Bounded the same way [`MAX_RESPONSE_LINES`] is, so a transport that
/// (incorrectly) always reports a line available cannot loop unboundedly.
const MAX_DRAIN_LINES: usize = 16;

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
    for _ in 0..MAX_RESPONSE_LINES {
        let n = match transport.recv_line(&mut line_buf, timeout_ms) {
            Ok(n) => n,
            Err(e) => {
                // WHY: send_at already committed this command to the modem
                // -- a recv_line failure here does not mean the modem
                // won't still emit the final result code a moment later.
                // Leaving that response unread desyncs the AT channel: the
                // NEXT send_and_wait call would read the STALE response as
                // if it belonged to its own command (issue #282 finding
                // 13). Best-effort non-blocking drain (timeout_ms=0, per
                // the ModemTransport contract) mops up anything already
                // sitting in the transport's receive buffer at the moment
                // of failure; it cannot recover a response that arrives
                // strictly after this drain.
                let mut drain_buf = [0u8; MAX_LINE_LEN];
                for _ in 0..MAX_DRAIN_LINES {
                    if transport.recv_line(&mut drain_buf, 0).is_err() {
                        break;
                    }
                }
                return Err(e);
            }
        };
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

/// The modem transport the booted kernel wires into its Telephony stack (#398).
/// A build-time choice so `KernelState` (a concrete struct) can hold a
/// `Telephony<BootModemTransport>` without going generic: the seeded mock under
/// qemu (no CCCI/CLDMA model on -machine virt), the real CCCI transport on
/// device.
#[cfg(any(feature = "qemu", test))]
pub(crate) type BootModemTransport = crate::telephony_mock::MockModemTransport;
#[cfg(not(any(feature = "qemu", test)))]
pub(crate) type BootModemTransport = CcciModemTransport;

/// Telephony subsystem: manages modem state and voice calls.
pub struct Telephony<T: ModemTransport> {
    // kanon:ignore RUST/struct-too-many-fields -- cohesive modem state: radio + signal + registration + call + operator fields track one hardware subsystem
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
    /// Registration status detail. [`Telephony::is_registered`] derives
    /// directly from this -- no separate `registered` bool is kept, so
    /// there is exactly one source of truth for registration state.
    reg_status: RegStatus,
    /// Whether LTE-only mode is active (2G/3G refused via `AT+COPS=0,,,7`).
    lte_only: bool,
    /// Whether `AT+CREG=1` (registration-URC subscription) succeeded
    /// during init. `false` means registration state updates were never
    /// subscribed to and `handle_urc` will not see `+CREG` URCs.
    creg_urc_enabled: bool,
    /// Whether `AT+CLIP=1` (caller-ID subscription) succeeded during init.
    /// `false` means incoming calls will not carry caller ID.
    clip_enabled: bool,
    /// Radio access technology of the current registration, from the `+CREG`
    /// `<AcT>` field. `None` when unregistered or when the modem reports no
    /// `<AcT>` (short-form `+CREG`); a registered URC without `<AcT>` keeps the
    /// last known value.
    current_rat: Option<RadioAccessTech>,
    /// Hardware transport.
    transport: T,
    /// Last signal poll tick (ms).
    last_signal_poll: u64,
    /// Initialization step tracker.
    init_step: u8,
}

/// Classify a simple OK/ERROR AT command result into a `TelephonyError`,
/// preserving the modem's own CME/CMS error code and the transport's own
/// error type instead of collapsing everything to one generic value
/// (issue #282 findings 16/17).
fn classify_simple_result(
    result: Result<AtResponse, TelephonyError>,
) -> Result<(), TelephonyError> {
    match result {
        Ok(AtResponse::Ok) => Ok(()),
        Ok(AtResponse::CmeError(code) | AtResponse::CmsError(code)) => {
            Err(TelephonyError::CmeError(code))
        }
        Ok(AtResponse::Error) => Err(TelephonyError::ModemError),
        Err(e) => Err(e),
    }
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
            reg_status: RegStatus::NotRegistered,
            lte_only: false,
            creg_urc_enabled: false,
            clip_enabled: false,
            current_rat: None,
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
    ///
    /// Derived directly from [`RegStatus`] -- there is no separate
    /// `registered` bool to fall out of sync with it.
    #[must_use]
    pub fn is_registered(&self) -> bool {
        matches!(
            self.reg_status,
            RegStatus::RegisteredHome | RegStatus::RegisteredRoaming
        )
    }

    /// Radio access technology of the current registration (`+CREG` `<AcT>`),
    /// or `None` when unregistered or the modem never reported one.
    #[must_use]
    pub fn rat(&self) -> Option<RadioAccessTech> {
        self.current_rat
    }

    /// The owned modem transport, for `SimManager`/`SmsManager` AT queries that
    /// operate over the same physical modem link (#398). Single-threaded loop
    /// context serializes access; there is one physical modem, so the SIM/SMS
    /// managers borrow Telephony's transport rather than owning a second.
    pub(crate) fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
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
    /// 10. `AT+CREG?`       — seed initial registration state
    ///
    /// `AT+CFUN=1` (step 3) only powers the radio; it does not mean the
    /// modem is registered. This method leaves `modem_state` at
    /// [`ModemState::Ready`] unless step 10's query confirms registration,
    /// and never asserts [`ModemState::Registered`] itself -- all
    /// subsequent Ready/Registered transitions are owned by
    /// [`Telephony::apply_reg_status`] (via [`Telephony::handle_urc`]
    /// reacting to `+CREG` URCs).
    ///
    /// Returns `Ok(())` on success, or an error describing which step failed.
    pub fn initialize(&mut self) -> Result<(), TelephonyError> {
        self.modem_state = ModemState::Initializing;
        self.init_step = 0;

        // Step 1: Verify modem responds.
        let result = send_simple(&mut self.transport, "AT", 5000);
        if let Err(e) = classify_simple_result(result) {
            self.modem_state = ModemState::Error(e);
            return Err(e);
        }
        self.init_step = 1;

        // Step 2: Disable echo.
        let result = send_simple(&mut self.transport, "ATE0", 2000);
        if let Err(e) = classify_simple_result(result) {
            self.modem_state = ModemState::Error(e);
            return Err(e);
        }
        self.init_step = 2;

        // Step 3: Full functionality mode.
        let result = send_simple(&mut self.transport, "AT+CFUN=1", 5000);
        if let Err(e) = classify_simple_result(result) {
            self.modem_state = ModemState::Error(e);
            return Err(e);
        }
        self.init_step = 3;

        // Step 4: Check SIM PIN status.
        let cpin_result = send_with_info(&mut self.transport, "AT+CPIN?", 5000);
        match cpin_result {
            Ok((AtResponse::Ok, ref info_line, info_len)) if info_len > 0 => {
                let line = &info_line[..info_len];
                match parse_cpin_response(line) {
                    Some(SimPinState::Ready) => {
                        // SIM ready, no PIN required.
                    }
                    Some(SimPinState::PinRequired | SimPinState::Other) => {
                        self.modem_state = ModemState::Error(TelephonyError::SimNotReady);
                        return Err(TelephonyError::SimNotReady);
                    }
                    Some(SimPinState::PukRequired) => {
                        self.modem_state = ModemState::Error(TelephonyError::SimPukRequired);
                        return Err(TelephonyError::SimPukRequired);
                    }
                    None => {
                        self.modem_state = ModemState::Error(TelephonyError::ParseError);
                        return Err(TelephonyError::ParseError);
                    }
                }
            }
            Ok((AtResponse::Ok, _, _)) => {
                // OK with no info line -- the modem accepted the command but
                // sent no +CPIN status; a malformed/unparseable response, not
                // evidence the SIM specifically needs a PIN (issue #282
                // finding 18).
                self.modem_state = ModemState::Error(TelephonyError::ParseError);
                return Err(TelephonyError::ParseError);
            }
            Ok((AtResponse::CmeError(code), _, _)) => {
                self.modem_state = ModemState::Error(TelephonyError::CmeError(code));
                return Err(TelephonyError::CmeError(code));
            }
            Ok((AtResponse::CmsError(code), _, _)) => {
                self.modem_state = ModemState::Error(TelephonyError::CmeError(code));
                return Err(TelephonyError::CmeError(code));
            }
            Ok((AtResponse::Error, _, _)) => {
                self.modem_state = ModemState::Error(TelephonyError::ModemError);
                return Err(TelephonyError::ModemError);
            }
            Err(e) => {
                self.modem_state = ModemState::Error(e);
                return Err(e);
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
        // Non-fatal like refuse_2g, but the outcome is now recorded rather
        // than silently discarded -- see is_creg_urc_enabled().
        let creg_result = send_simple(&mut self.transport, "AT+CREG=1", 2000);
        self.creg_urc_enabled = matches!(creg_result, Ok(AtResponse::Ok));
        self.init_step = 7;

        // Step 8: Enable caller ID.
        // Non-fatal, outcome recorded -- see is_clip_enabled().
        let clip_result = send_simple(&mut self.transport, "AT+CLIP=1", 2000);
        self.clip_enabled = matches!(clip_result, Ok(AtResponse::Ok));
        self.init_step = 8;

        // Step 9: Initial signal strength query.
        if let Err(e) = self.update_signal_strength() {
            self.modem_state = ModemState::Error(e);
            return Err(e);
        }
        self.init_step = 9;

        // Step 10: Seed registration state. AT+CFUN=1 (step 3) only powers
        // the radio; registration is asynchronous and may take seconds to
        // minutes. Query it directly instead of assuming success. All
        // further Ready/Registered transitions are owned by
        // apply_reg_status (via handle_urc reacting to +CREG URCs).
        self.modem_state = ModemState::Ready;
        let creg_query = send_with_info(&mut self.transport, "AT+CREG?", 5000);
        if let Ok((AtResponse::Ok, ref info_line, info_len)) = creg_query
            && info_len > 0
            && let Some((stat, act)) = parse_creg_response(&info_line[..info_len])
        {
            self.apply_reg_status(stat, act);
        }
        self.init_step = 10;

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

    /// Return whether `AT+CREG=1` (registration-URC subscription) succeeded
    /// during initialization.
    ///
    /// `false` means the modem never subscribed to `+CREG` URCs, so
    /// registration state will never update after the initial
    /// [`Telephony::initialize`] query -- a silent degradation the caller
    /// should surface (e.g. in the threat/diagnostics screen).
    #[must_use]
    pub fn is_creg_urc_enabled(&self) -> bool {
        self.creg_urc_enabled
    }

    /// Return whether `AT+CLIP=1` (caller-ID subscription) succeeded during
    /// initialization.
    ///
    /// `false` means incoming calls will never carry caller ID.
    #[must_use]
    pub fn is_clip_enabled(&self) -> bool {
        self.clip_enabled
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
        if !matches!(self.modem_state, ModemState::Ready | ModemState::Registered) {
            return None;
        }

        if current_tick.saturating_sub(self.last_signal_poll) < SIGNAL_POLL_INTERVAL_MS {
            return None;
        }

        self.last_signal_poll = current_tick;
        match self.update_signal_strength() {
            Ok(()) => Some(TelephonyEvent::SignalUpdate {
                bars: self.signal_strength,
                rssi_dbm: self.signal_dbm,
            }),
            // WHY: a failed signal poll must be visible (issue #282 finding
            // 3), not silently swallowed into None (indistinguishable from
            // "not time to poll yet"). Reuses the existing ModemError event
            // vocabulary rather than adding new API surface. A single
            // transient failure does not change modem_state -- Ready and
            // Registered are owned by initialize()/apply_reg_status, not by
            // one periodic CSQ query.
            Err(e) => Some(TelephonyEvent::ModemError(e)),
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
        // SECURITY: reject any byte outside the legal GSM dial-string
        // charset before it reaches the ATD command buffer. Without this,
        // a `\r`/`\n` in `number` (e.g. relayed verbatim from a forged
        // +CLIP URC via a UI redial callback) would terminate the ATD line
        // early and inject arbitrary follow-on AT commands into the modem
        // stream.
        if !number.iter().all(|&b| is_valid_dial_byte(b)) {
            return Err(TelephonyError::ParseError);
        }

        // Build ATD command: "ATD+15551234567;"
        let mut cmd_buf = [0u8; 4 + MAX_NUMBER_LEN + 1]; // "ATD" + number + ";"
        cmd_buf[0] = b'A';
        cmd_buf[1] = b'T';
        cmd_buf[2] = b'D';
        cmd_buf[3..3 + number.len()].copy_from_slice(number);
        cmd_buf[3 + number.len()] = b';';
        let cmd_len = 4 + number.len();

        // INVARIANT: every byte of `number` was validated by
        // `is_valid_dial_byte` above (a strict ASCII subset), so `cmd_buf`
        // contains only ASCII bytes and this conversion cannot fail.
        let cmd_str =
            core::str::from_utf8(&cmd_buf[..cmd_len]).map_err(|_| TelephonyError::ParseError)?;

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
            // WHY: +CMS ERROR is SMS-specific and not expected on a voice
            // dial, but AtResponse is exhaustively matched here; surface it
            // through the same numeric-code channel as CME errors.
            AtResponse::CmsError(code) => Err(TelephonyError::CmeError(code)),
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
            AtResponse::CmsError(code) => Err(TelephonyError::CmeError(code)),
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
            AtResponse::CmsError(code) => Err(TelephonyError::CmeError(code)),
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

    /// Apply a registration status, keeping `reg_status` and `modem_state`
    /// consistent.
    ///
    /// This is the single place that transitions `modem_state` between
    /// [`ModemState::Ready`] and [`ModemState::Registered`] -- no other
    /// code path may assert `ModemState::Registered` directly. A stray
    /// `+CREG` URC arriving outside `Ready`/`Registered` (e.g. during
    /// `Off`/`Initializing`/`Error`) updates `reg_status` but does not
    /// clobber the modem's lifecycle state.
    fn apply_reg_status(&mut self, stat: RegStatus, act: Option<RadioAccessTech>) {
        self.reg_status = stat;
        if matches!(self.modem_state, ModemState::Ready | ModemState::Registered) {
            self.modem_state = if self.is_registered() {
                ModemState::Registered
            } else {
                ModemState::Ready
            };
        }
        // Track the radio access technology alongside registration. When
        // registered, a fresh `<AcT>` updates it and an absent one keeps the
        // last known value (a short-form `+CREG` URC omits `<AcT>`). Losing
        // registration clears it -- an unregistered modem has no RAT.
        self.current_rat = if self.is_registered() {
            act.or(self.current_rat)
        } else {
            None
        };
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
                // Update the incoming call with caller ID -- only if a RING
                // already transitioned call_state to Incoming. A +CLIP URC
                // arriving without a prior RING is out-of-order (or forged
                // -- the modem/network is untrusted per this project's
                // threat model) and must not synthesize a phantom
                // IncomingCall event while call_state stays Idle (issue
                // #282 finding 19).
                if let CallState::Incoming {
                    number: ref mut n,
                    len: ref mut l,
                } = self.call_state
                {
                    *n = number;
                    *l = number_len;
                    Some(TelephonyEvent::IncomingCall { number, number_len })
                } else {
                    None
                }
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
            Urc::Creg { stat, act } => {
                self.apply_reg_status(stat, act);
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

    #[test]
    fn classify_simple_result_preserves_cme_cms_code_and_transport_error() {
        assert_eq!(classify_simple_result(Ok(AtResponse::Ok)), Ok(()));
        assert_eq!(
            classify_simple_result(Ok(AtResponse::Error)),
            Err(TelephonyError::ModemError)
        );
        assert_eq!(
            classify_simple_result(Ok(AtResponse::CmeError(42))),
            Err(TelephonyError::CmeError(42))
        );
        assert_eq!(
            classify_simple_result(Ok(AtResponse::CmsError(7))),
            Err(TelephonyError::CmeError(7))
        );
        assert_eq!(
            classify_simple_result(Err(TelephonyError::TransportError)),
            Err(TelephonyError::TransportError),
            "a genuine transport error must not be relabeled as Timeout"
        );
    }

    #[test]
    fn cpin_cms_error_preserves_code_not_sim_not_ready() {
        let mut mock = MockModemTransport::new();
        mock.queue_ok(); // Step 1: AT
        mock.queue_ok(); // Step 2: ATE0
        mock.queue_ok(); // Step 3: AT+CFUN=1
        // Step 4: AT+CPIN? -> +CMS ERROR (SMS-storage-class failure, not a SIM
        // PIN state) -- the old wildcard `_ =>` arm mapped this to
        // SimNotReady, discarding the code (issue #282 finding 18).
        mock.queue_response(b"+CMS ERROR: 302");

        let mut tel = Telephony::new(mock);
        let result = tel.initialize();
        assert_eq!(
            result,
            Err(TelephonyError::CmeError(302)),
            "a +CMS ERROR on AT+CPIN? must preserve its code, not collapse to SimNotReady"
        );
    }

    #[test]
    fn cpin_sim_puk_surfaces_sim_puk_required_not_sim_not_ready() {
        let mut mock = MockModemTransport::new();
        mock.queue_ok(); // Step 1: AT
        mock.queue_ok(); // Step 2: ATE0
        mock.queue_ok(); // Step 3: AT+CFUN=1
        // Step 4: AT+CPIN? -> +CPIN: SIM PUK -- must not be conflated with
        // SIM PIN (issue #282 finding 17): a UI that responds to
        // SimNotReady with a 4-digit PIN prompt would burn PUK attempts.
        mock.queue_info_ok(b"+CPIN: SIM PUK");

        let mut tel = Telephony::new(mock);
        let result = tel.initialize();
        assert_eq!(
            result,
            Err(TelephonyError::SimPukRequired),
            "SIM PUK must surface as SimPukRequired, not SimNotReady"
        );
        assert_eq!(
            tel.modem_state(),
            ModemState::Error(TelephonyError::SimPukRequired)
        );
    }

    #[test]
    fn cpin_sim_pin_required_surfaces_sim_not_ready() {
        let mut mock = MockModemTransport::new();
        mock.queue_ok(); // Step 1: AT
        mock.queue_ok(); // Step 2: ATE0
        mock.queue_ok(); // Step 3: AT+CFUN=1
        // Step 4: AT+CPIN? -> +CPIN: SIM PIN -- the ordinary PIN-required
        // case, distinct from the already-covered SIM PUK case.
        mock.queue_info_ok(b"+CPIN: SIM PIN");

        let mut tel = Telephony::new(mock);
        let result = tel.initialize();
        assert_eq!(
            result,
            Err(TelephonyError::SimNotReady),
            "SIM PIN required must surface as SimNotReady"
        );
        assert_eq!(
            tel.modem_state(),
            ModemState::Error(TelephonyError::SimNotReady)
        );
    }

    #[test]
    fn cpin_cme_error_preserves_code_not_sim_not_ready() {
        let mut mock = MockModemTransport::new();
        mock.queue_ok(); // Step 1: AT
        mock.queue_ok(); // Step 2: ATE0
        mock.queue_ok(); // Step 3: AT+CFUN=1
        // Step 4: AT+CPIN? -> +CME ERROR (modem-level failure, not a SIM
        // PIN/PUK state) -- must preserve the code, not collapse to
        // SimNotReady (the same class of bug as issue #282 finding 18, but
        // on the CME rather CMS error path).
        mock.queue_response(b"+CME ERROR: 10");

        let mut tel = Telephony::new(mock);
        let result = tel.initialize();
        assert_eq!(
            result,
            Err(TelephonyError::CmeError(10)),
            "a +CME ERROR on AT+CPIN? must preserve its code, not collapse to SimNotReady"
        );
        assert_eq!(
            tel.modem_state(),
            ModemState::Error(TelephonyError::CmeError(10))
        );
    }

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
        // Step 10: AT+CREG? -> +CREG: 1 (registered home) + OK
        mock.queue_info_ok(b"+CREG: 1");
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
        assert!(
            result.is_ok(),
            "initialization must succeed with valid mock"
        );

        let commands = &tel.transport.sent_commands;
        assert_eq!(commands.len(), 10, "init must send exactly 10 AT commands");
        assert_eq!(commands[0], b"AT", "step 1: AT");
        assert_eq!(commands[1], b"ATE0", "step 2: ATE0");
        assert_eq!(commands[2], b"AT+CFUN=1", "step 3: AT+CFUN=1");
        assert_eq!(commands[3], b"AT+CPIN?", "step 4: AT+CPIN?");
        assert_eq!(
            commands[4], b"AT+COPS=0,,,7",
            "step 5: AT+COPS=0,,,7 (LTE only)"
        );
        assert_eq!(commands[5], b"AT+COPS?", "step 6: AT+COPS?");
        assert_eq!(commands[6], b"AT+CREG=1", "step 7: AT+CREG=1");
        assert_eq!(commands[7], b"AT+CLIP=1", "step 8: AT+CLIP=1");
        assert_eq!(commands[8], b"AT+CSQ", "step 9: AT+CSQ");
        assert_eq!(commands[9], b"AT+CREG?", "step 10: AT+CREG?");

        assert_eq!(
            tel.modem_state(),
            ModemState::Registered,
            "modem must be Registered once step 10's AT+CREG? confirms it"
        );
        assert!(
            tel.is_registered(),
            "must report registered once AT+CREG? confirms it"
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
                assert_eq!(&n[..*len as usize], number, "dialing number must match");
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
    fn dial_rejects_crlf_injection() {
        let mock = mock_for_init();
        let mut tel = Telephony::new(mock);
        tel.initialize().ok();

        let before = tel.transport.sent_commands.len();
        let result = tel.dial(b"+1\r\nAT+CFUN=0");
        assert_eq!(
            result,
            Err(TelephonyError::ParseError),
            "CR/LF in dial number must be rejected"
        );
        assert_eq!(
            tel.transport.sent_commands.len(),
            before,
            "no ATD command may reach the transport when the number is rejected"
        );
    }

    #[test]
    fn dial_rejects_semicolon_injection() {
        let mock = mock_for_init();
        let mut tel = Telephony::new(mock);
        tel.initialize().ok();

        let result = tel.dial(b"+1;AT+CFUN=0");
        assert_eq!(
            result,
            Err(TelephonyError::ParseError),
            "embedded semicolon must be rejected (would close ATD early)"
        );
    }

    #[test]
    fn dial_accepts_full_valid_charset() {
        let mock = mock_for_init();
        let mut tel = Telephony::new(mock);
        tel.initialize().ok();
        tel.transport.queue_ok();

        let result = tel.dial(b"+15551234567*#ABCD");
        assert!(result.is_ok(), "digits/+/*/#/A-D must be accepted");
    }

    #[test]
    fn poll_signal_surfaces_error_instead_of_silently_discarding_it() {
        let mock = mock_for_init();
        let mut tel = Telephony::new(mock);
        tel.initialize().ok();
        assert_eq!(tel.modem_state(), ModemState::Registered);

        // AT+CSQ fails -- the failure must be surfaced as a ModemError
        // event, not silently discarded as if nothing happened (issue #282
        // finding 3).
        tel.transport.queue_response(b"ERROR");

        let event = tel.poll_signal(SIGNAL_POLL_INTERVAL_MS);
        assert_eq!(
            event,
            Some(TelephonyEvent::ModemError(TelephonyError::ModemError)),
            "a failed signal poll must surface as an event, not silently return None"
        );
        assert_eq!(
            tel.modem_state(),
            ModemState::Registered,
            "a single transient poll failure must not kill the Ready/Registered state"
        );
    }

    #[test]
    fn poll_signal_emits_signal_update_when_interval_has_elapsed() {
        let mock = mock_for_init();
        let mut tel = Telephony::new(mock);
        tel.initialize().ok();
        assert_eq!(tel.modem_state(), ModemState::Registered);

        // RSSI 20 => -113 + (20*2) = -73 dBm (3 bars), distinct from init's
        // "+CSQ: 18,99" (-77 dBm) so the assertion proves this poll's fresh
        // data was used, not stale init-time state.
        tel.transport.queue_info_ok(b"+CSQ: 20,1");
        let commands_before = tel.transport.sent_commands.len();

        let event = tel.poll_signal(SIGNAL_POLL_INTERVAL_MS);
        assert_eq!(
            event,
            Some(TelephonyEvent::SignalUpdate {
                bars: 3,
                rssi_dbm: -73,
            }),
            "an elapsed-interval poll_signal must emit SignalUpdate with the freshly queried data"
        );
        assert_eq!(
            tel.transport.sent_commands.len(),
            commands_before + 1,
            "poll_signal must issue AT+CSQ when the interval has elapsed"
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
    fn poll_signal_returns_none_and_does_not_repoll_before_interval_elapsed() {
        let mock = mock_for_init();
        let mut tel = Telephony::new(mock);
        tel.initialize().ok();

        // First elapsed-interval poll succeeds and advances last_signal_poll.
        tel.transport.queue_info_ok(b"+CSQ: 20,1");
        let first = tel.poll_signal(SIGNAL_POLL_INTERVAL_MS);
        assert!(
            first.is_some(),
            "sanity: first elapsed-interval poll must succeed"
        );

        let commands_before = tel.transport.sent_commands.len();
        let dbm_before = tel.signal_dbm();

        // A second call before another full interval has elapsed must be
        // throttled: no AT+CSQ reissued, no event emitted, no state mutated.
        let second = tel.poll_signal(SIGNAL_POLL_INTERVAL_MS + 1);
        assert_eq!(
            second, None,
            "poll_signal must return None when called before the interval has elapsed again"
        );
        assert_eq!(
            tel.transport.sent_commands.len(),
            commands_before,
            "a throttled poll_signal call must not re-issue AT+CSQ"
        );
        assert_eq!(
            tel.signal_dbm(),
            dbm_before,
            "a throttled poll_signal call must not mutate signal state"
        );
    }

    #[test]
    fn clip_without_prior_ring_does_not_emit_phantom_incoming_call() {
        let mock = mock_for_init();
        let mut tel = Telephony::new(mock);
        tel.initialize().ok();

        tel.transport.queue_urc(b"+CLIP: \"+15551234567\",145");
        let event = tel.poll();
        assert!(
            event.is_none(),
            "CLIP without a prior RING must not emit a phantom IncomingCall event"
        );
        assert!(
            matches!(tel.call_state(), CallState::Idle),
            "call state must remain Idle"
        );
    }

    #[test]
    fn ring_then_clip_populates_caller_id_on_incoming_call() {
        let mock = mock_for_init();
        let mut tel = Telephony::new(mock);
        tel.initialize().ok();

        tel.transport.queue_urc(b"RING");
        tel.poll();
        assert!(
            matches!(tel.call_state(), CallState::Incoming { .. }),
            "RING must transition call state to Incoming before CLIP arrives"
        );

        tel.transport.queue_urc(b"+CLIP: \"+15551234567\",145");
        let event = tel.poll();

        let expected_number = b"+15551234567";
        match tel.call_state() {
            CallState::Incoming { number, len } => {
                assert_eq!(
                    &number[..usize::from(*len)],
                    expected_number,
                    "CLIP after a prior RING must populate the incoming call's caller ID"
                );
            }
            other => panic!("expected Incoming state with caller ID, got: {other}"),
        }
        match event {
            Some(TelephonyEvent::IncomingCall { number, number_len }) => {
                assert_eq!(
                    &number[..usize::from(number_len)],
                    expected_number,
                    "CLIP after RING must emit an IncomingCall event carrying the caller ID"
                );
            }
            other => panic!("expected IncomingCall event with caller ID, got: {other:?}"),
        }
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
    fn send_and_wait_gives_up_after_max_response_lines_not_64() {
        let mut mock = MockModemTransport::new();
        for _ in 0..(MAX_RESPONSE_LINES + 4) {
            mock.queue_response(b"+JUNK: 0");
        }
        let mut info_buf = [[0u8; MAX_LINE_LEN]; 1];
        let result = send_and_wait(&mut mock, "AT", &mut info_buf, 100);
        assert_eq!(result, Err(TelephonyError::Timeout));
        assert!(
            mock.response_lines.len() >= 4,
            "must give up at MAX_RESPONSE_LINES, leaving unread lines queued"
        );
    }

    #[test]
    fn send_and_wait_drains_stale_response_after_recv_error() {
        let mut mock = MockModemTransport::new();
        mock.queue_response(b"OK");
        mock.fail_next_recv(1);

        let mut info_buf = [[0u8; MAX_LINE_LEN]; 1];
        let result = send_and_wait(&mut mock, "AT", &mut info_buf, 100);
        assert_eq!(
            result,
            Err(TelephonyError::TransportError),
            "the injected failure must still surface as an error"
        );
        assert!(
            mock.response_lines.is_empty(),
            "the stale OK response must be drained, not left for the next exchange"
        );
    }

    #[test]
    fn send_and_wait_terminates_immediately_on_cms_error() {
        let mut mock = MockModemTransport::new();
        mock.queue_response(b"+CMS ERROR: 302");
        let mut info_buf = [[0u8; MAX_LINE_LEN]; 4];
        let result = send_and_wait(&mut mock, "AT+CMGS=10", &mut info_buf, 2000);
        assert_eq!(
            result,
            Ok((AtResponse::CmsError(302), 0)),
            "a +CMS ERROR final result must terminate immediately with the code, not fall through to Timeout"
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
            tel.transport.sent_commands[4], b"AT+COPS=0,,,7",
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
            "refuse_2g must SET lte_only=true on OK response"
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
            "refuse_2g must SET lte_only=false on ERROR response"
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
            cmd, b"AT+COPS=0,,,7",
            "command must be AT+COPS=0,,,7 per 3GPP TS 27.007 section 7.3"
        );
    }

    // See #257's spec for the full initialize()/ModemState edit that this
    // test depends on (creg_urc_enabled/clip_enabled + apply_reg_status).

    #[test]
    fn creg_and_clip_init_failures_are_recorded_not_swallowed() {
        let mut mock = MockModemTransport::new();
        mock.queue_ok(); // AT
        mock.queue_ok(); // ATE0
        mock.queue_ok(); // AT+CFUN=1
        mock.queue_info_ok(b"+CPIN: READY");
        mock.queue_ok(); // AT+COPS=0,,,7
        mock.queue_info_ok(b"+COPS: 0,0,\"T-Mobile\""); // AT+COPS?
        mock.queue_response(b"ERROR"); // AT+CREG=1 -> ERROR
        mock.queue_response(b"ERROR"); // AT+CLIP=1 -> ERROR
        mock.queue_info_ok(b"+CSQ: 18,99");
        mock.queue_info_ok(b"+CREG: 0");

        let mut tel = Telephony::new(mock);
        let result = tel.initialize();
        assert!(
            result.is_ok(),
            "AT+CREG=1/AT+CLIP=1 failures must not abort the whole init sequence"
        );
        assert!(
            !tel.is_creg_urc_enabled(),
            "a rejected AT+CREG=1 must be recorded as disabled, not silently assumed enabled"
        );
        assert!(
            !tel.is_clip_enabled(),
            "a rejected AT+CLIP=1 must be recorded as disabled, not silently assumed enabled"
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
        // Step 10: AT+CREG? -> +CREG: 1 (registered home) + OK
        mock.queue_info_ok(b"+CREG: 1");

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
            "modem must reach Registered state once AT+CREG? confirms it, despite LTE-only rejection"
        );
    }

    #[test]
    fn initialize_records_error_state_on_step_9_signal_query_failure() {
        let mut mock = MockModemTransport::new();
        mock.queue_ok(); // AT
        mock.queue_ok(); // ATE0
        mock.queue_ok(); // AT+CFUN=1
        mock.queue_info_ok(b"+CPIN: READY");
        mock.queue_ok(); // AT+COPS=0,,,7
        mock.queue_info_ok(b"+COPS: 0,0,\"T-Mobile\"");
        mock.queue_ok(); // AT+CREG=1
        mock.queue_ok(); // AT+CLIP=1
        mock.queue_response(b"ERROR");

        let mut tel = Telephony::new(mock);
        let result = tel.initialize();
        assert!(
            result.is_err(),
            "a failed signal query must fail initialize()"
        );
        assert_eq!(
            tel.modem_state(),
            ModemState::Error(TelephonyError::ModemError),
            "modem_state must record Error, not remain stuck at Initializing"
        );
    }

    #[test]
    fn initialize_fails_fast_on_early_step_at_command_errors() {
        // Step 1: AT -> ERROR must abort before any later step is attempted.
        let mut mock = MockModemTransport::new();
        mock.queue_response(b"ERROR");
        let mut tel = Telephony::new(mock);
        let result = tel.initialize();
        assert_eq!(
            result,
            Err(TelephonyError::ModemError),
            "step 1 AT failure must fail initialize()"
        );
        assert_eq!(
            tel.modem_state(),
            ModemState::Error(TelephonyError::ModemError),
            "modem_state must record Error on step 1 failure"
        );
        assert_eq!(
            tel.transport.sent_commands.len(),
            1,
            "a step 1 failure must abort before step 2 (ATE0) is sent"
        );

        // Step 2: ATE0 -> ERROR must abort before step 3 is attempted.
        let mut mock = MockModemTransport::new();
        mock.queue_ok(); // Step 1: AT
        mock.queue_response(b"ERROR"); // Step 2: ATE0
        let mut tel = Telephony::new(mock);
        let result = tel.initialize();
        assert_eq!(
            result,
            Err(TelephonyError::ModemError),
            "step 2 ATE0 failure must fail initialize()"
        );
        assert_eq!(
            tel.transport.sent_commands.len(),
            2,
            "a step 2 failure must abort before step 3 (AT+CFUN=1) is sent"
        );

        // Step 3: AT+CFUN=1 -> ERROR must abort before step 4 is attempted.
        let mut mock = MockModemTransport::new();
        mock.queue_ok(); // Step 1: AT
        mock.queue_ok(); // Step 2: ATE0
        mock.queue_response(b"ERROR"); // Step 3: AT+CFUN=1
        let mut tel = Telephony::new(mock);
        let result = tel.initialize();
        assert_eq!(
            result,
            Err(TelephonyError::ModemError),
            "step 3 AT+CFUN=1 failure must fail initialize()"
        );
        assert_eq!(
            tel.transport.sent_commands.len(),
            3,
            "a step 3 failure must abort before step 4 (AT+CPIN?) is sent"
        );
    }

    // --- registration-state confirmation tests (#257) ---

    #[test]
    fn initialize_stays_unregistered_when_creg_reports_searching() {
        let mut mock = MockModemTransport::new();
        mock.queue_ok(); // AT
        mock.queue_ok(); // ATE0
        mock.queue_ok(); // AT+CFUN=1
        mock.queue_info_ok(b"+CPIN: READY");
        mock.queue_ok(); // AT+COPS=0,,,7
        mock.queue_info_ok(b"+COPS: 0,0,\"T-Mobile\"");
        mock.queue_ok(); // AT+CREG=1
        mock.queue_ok(); // AT+CLIP=1
        mock.queue_info_ok(b"+CSQ: 18,99");
        mock.queue_info_ok(b"+CREG: 2"); // searching, not registered

        let mut tel = Telephony::new(mock);
        let result = tel.initialize();
        assert!(
            result.is_ok(),
            "init must succeed even if not yet registered"
        );
        assert!(
            !tel.is_registered(),
            "is_registered must be false when AT+CREG? reports searching (2)"
        );
        assert_eq!(
            tel.modem_state(),
            ModemState::Ready,
            "modem_state must stay Ready (not Registered) until actually registered"
        );
    }

    #[test]
    fn creg_urc_downgrades_modem_state_from_registered() {
        let mock = mock_for_init();
        let mut tel = Telephony::new(mock);
        tel.initialize().ok();
        assert_eq!(
            tel.modem_state(),
            ModemState::Registered,
            "must start Registered"
        );

        tel.transport.queue_urc(b"+CREG: 0");
        let event = tel.poll();
        assert!(
            matches!(event, Some(TelephonyEvent::RegistrationUpdate { .. })),
            "CREG URC must produce a RegistrationUpdate event"
        );
        assert!(
            !tel.is_registered(),
            "is_registered must become false after +CREG: 0"
        );
        assert_eq!(
            tel.modem_state(),
            ModemState::Ready,
            "modem_state must downgrade from Registered to Ready on +CREG: 0"
        );
    }

    #[test]
    fn creg_urc_promotes_ready_to_registered() {
        let mut mock = MockModemTransport::new();
        mock.queue_ok();
        mock.queue_ok();
        mock.queue_ok();
        mock.queue_info_ok(b"+CPIN: READY");
        mock.queue_ok();
        mock.queue_info_ok(b"+COPS: 0,0,\"T-Mobile\"");
        mock.queue_ok();
        mock.queue_ok();
        mock.queue_info_ok(b"+CSQ: 18,99");
        mock.queue_info_ok(b"+CREG: 2"); // searching at init time

        let mut tel = Telephony::new(mock);
        tel.initialize().ok();
        assert_eq!(
            tel.modem_state(),
            ModemState::Ready,
            "must start Ready (searching)"
        );

        tel.transport.queue_urc(b"+CREG: 5");
        tel.poll();
        assert!(
            tel.is_registered(),
            "must report registered after +CREG: 5 (roaming)"
        );
        assert_eq!(
            tel.modem_state(),
            ModemState::Registered,
            "modem_state must promote from Ready to Registered on +CREG: 5"
        );
    }

    #[test]
    fn radio_access_tech_maps_act_codes_to_generations() {
        use RatGeneration::{FourG, ThreeG, TwoG};
        let cases = [
            (0u8, RadioAccessTech::Gsm, TwoG),
            (1, RadioAccessTech::GsmCompact, TwoG),
            (2, RadioAccessTech::Utran, ThreeG),
            (3, RadioAccessTech::GsmEgprs, TwoG),
            (4, RadioAccessTech::UtranHsdpa, ThreeG),
            (5, RadioAccessTech::UtranHsupa, ThreeG),
            (6, RadioAccessTech::UtranHsdpaHsupa, ThreeG),
            (7, RadioAccessTech::EUtran, FourG),
            (8, RadioAccessTech::EUtranNbS1, FourG),
        ];
        for (code, rat, generation) in cases {
            assert_eq!(
                RadioAccessTech::from_act(code),
                Some(rat),
                "AcT code {code} must map to the expected radio access technology"
            );
            assert_eq!(
                rat.generation(),
                generation,
                "{rat:?} must report the expected cellular generation"
            );
        }
        assert_eq!(
            RadioAccessTech::from_act(9),
            None,
            "an AcT code outside 0-8 must yield no technology"
        );
    }

    /// A mock seeded through the full init sequence whose `AT+CREG?` response
    /// carries the given `<AcT>`, for exercising the RAT seed path.
    fn mock_for_init_with_creg(creg_line: &[u8]) -> MockModemTransport {
        let mut mock = MockModemTransport::new();
        mock.queue_ok();
        mock.queue_ok();
        mock.queue_ok();
        mock.queue_info_ok(b"+CPIN: READY");
        mock.queue_ok();
        mock.queue_info_ok(b"+COPS: 0,0,\"T-Mobile\"");
        mock.queue_ok();
        mock.queue_ok();
        mock.queue_info_ok(b"+CSQ: 18,99");
        mock.queue_info_ok(creg_line);
        mock
    }

    #[test]
    fn rat_is_seeded_from_creg_query_at_init() {
        let mock = mock_for_init_with_creg(b"+CREG: 1,\"1A2B\",\"0100CE01\",7");
        let mut tel = Telephony::new(mock);
        tel.initialize().ok();
        assert!(tel.is_registered(), "must be registered (stat=1)");
        assert_eq!(
            tel.rat(),
            Some(RadioAccessTech::EUtran),
            "the boot AT+CREG? <AcT>=7 must seed the RAT to E-UTRAN"
        );
    }

    #[test]
    fn rat_tracks_urc_updates_and_clears_on_deregistration() {
        // Init registered on LTE.
        let mock = mock_for_init_with_creg(b"+CREG: 1,\"1A2B\",\"0100CE01\",7");
        let mut tel = Telephony::new(mock);
        tel.initialize().ok();
        assert_eq!(tel.rat(), Some(RadioAccessTech::EUtran), "seeded LTE");

        // A URC reporting a UTRAN registration updates the RAT.
        tel.transport.queue_urc(b"+CREG: 1,\"1A2B\",\"0100CE01\",2");
        tel.poll();
        assert_eq!(
            tel.rat(),
            Some(RadioAccessTech::Utran),
            "a +CREG URC carrying <AcT>=2 must update the RAT to UTRAN (3G)"
        );

        // A registered URC without an <AcT> keeps the last known RAT.
        tel.transport.queue_urc(b"+CREG: 1");
        tel.poll();
        assert_eq!(
            tel.rat(),
            Some(RadioAccessTech::Utran),
            "a short-form +CREG URC (no <AcT>) must keep the last known RAT"
        );

        // Losing registration clears the RAT.
        tel.transport.queue_urc(b"+CREG: 0");
        tel.poll();
        assert_eq!(
            tel.rat(),
            None,
            "deregistration (+CREG: 0) must clear the RAT -- no technology without a registration"
        );
    }
}
