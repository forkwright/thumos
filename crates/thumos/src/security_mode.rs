//! Security mode state machine.
//!
//! Implements the Daily/Sentinel/Panic mode system with Covert Lock,
//! enforced transitions, and radio control policies.
//!
//! ## Mode transitions
//!
//! ```text
//!   Daily <----> Sentinel  (PIN required to exit Sentinel)
//!     |             |
//!     +------+------+
//!            |
//!            v
//!          Panic  (one-way; abort only within 15 s window)
//! ```
//!
//! ## Covert Lock
//!
//! Independent RF-kill toggle. When active, kills all radios except mesh
//! (`LoRa`). Toggled via PTT long-press or menu action.
//!
//! ## Panic activation paths
//!
//! 1. Key combo: star + hash + power held 3 s
//! 2. PTT triple-click
//! 3. Duress PIN (detected in Wave 3 lock screen)
//!
//! Panic immediately zeroizes all keys via [`KeyManager::zeroize_all`] and
//! emits a [`PanicEvent`] for the Wave 4 wipe integration to handle.

extern crate alloc;

use core::fmt;

use subtle::ConstantTimeEq;

use crate::audit::{AuditEventType, AuditLog};
use crate::key_manager::KeyManager;
use crate::power::PowerManager;
// WHY cfg(test): PowerState/Radio are named only in this module's tests.
#[cfg(test)]
use crate::power::{PowerState, Radio};
use crate::security::{KEY_SIZE, SleepTier};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Panic abort window in ticks (15 seconds at 10 ms/tick = 1 500 ticks).
const PANIC_ABORT_WINDOW_TICKS: u64 = 1_500;

/// Scan interval for Daily mode (60 s at 10 ms/tick).
const SCAN_INTERVAL_DAILY_MS: u32 = 60_000;

/// Scan interval for Sentinel mode (10 s at 10 ms/tick).
const SCAN_INTERVAL_SENTINEL_MS: u32 = 10_000;

/// Scan interval for Panic mode (0 — no scanning).
const SCAN_INTERVAL_PANIC_MS: u32 = 0;

/// Salt for the Sentinel-exit PIN PBKDF2 derivation.
///
/// NOTE: fixed (not per-device random) for determinism, mirroring the
/// `PBKDF2_SALT` pattern in `key_manager.rs`, until the key-slot
/// provisioning infrastructure (kinit.rs Step 8f, currently PENDING) wires
/// a per-device random salt into persistent storage.
const PIN_PBKDF2_SALT: &[u8] = b"thumos-sentinel-pin-salt-v1";

// ---------------------------------------------------------------------------
// SecurityMode
// ---------------------------------------------------------------------------

/// Operating security mode.
///
/// Controls radio policy, scan intervals, sleep tiers, and panic behavior.
/// See module-level documentation for transition rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[must_use]
#[non_exhaustive]
pub enum SecurityMode {
    /// Normal operation. All radios enabled, short sleep, 60 s scan.
    #[default]
    Daily,
    /// Heightened awareness. Cellular/WiFi/BT off, GPS+mesh on, long
    /// sleep, 10 s scan.
    Sentinel,
    /// Emergency. All radios off, keys zeroized, wipe initiated.
    Panic,
}

impl fmt::Display for SecurityMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Daily => write!(f, "Daily"),
            Self::Sentinel => write!(f, "Sentinel"),
            Self::Panic => write!(f, "Panic"),
        }
    }
}

// ---------------------------------------------------------------------------
// ModePolicy
// ---------------------------------------------------------------------------

/// Radio and behavior policy for a given security mode.
///
/// Each mode maps to a fixed policy. Covert Lock overrides radio fields
/// independently (see [`ModeManager::effective_policy`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
#[expect(
    clippy::struct_excessive_bools,
    reason = "radio enable/disable states are inherently boolean"
)]
pub(crate) struct ModePolicy {
    /// Whether the cellular modem is enabled.
    pub cellular_enabled: bool,
    /// Whether `WiFi` is enabled.
    pub wifi_enabled: bool,
    /// Whether Bluetooth is enabled.
    pub bluetooth_enabled: bool,
    /// Whether GPS is enabled.
    pub gps_enabled: bool,
    /// Whether mesh (`LoRa`) networking is enabled.
    pub mesh_enabled: bool,
    /// Sleep tier controlling key lifecycle.
    pub sleep_tier: SleepTier,
    /// Scan interval in milliseconds (0 = disabled).
    pub scan_interval_ms: u32,
}

impl fmt::Display for ModePolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ModePolicy(cell={}, wifi={}, bt={}, gps={}, mesh={}, sleep={}, scan={}ms)",
            self.cellular_enabled,
            self.wifi_enabled,
            self.bluetooth_enabled,
            self.gps_enabled,
            self.mesh_enabled,
            self.sleep_tier,
            self.scan_interval_ms,
        )
    }
}

/// Return the base policy for a security mode (before Covert Lock overlay).
const fn base_policy(mode: SecurityMode) -> ModePolicy {
    match mode {
        SecurityMode::Daily => ModePolicy {
            cellular_enabled: true,
            wifi_enabled: true,
            bluetooth_enabled: true,
            gps_enabled: true,
            mesh_enabled: true,
            sleep_tier: SleepTier::Short,
            scan_interval_ms: SCAN_INTERVAL_DAILY_MS,
        },
        SecurityMode::Sentinel => ModePolicy {
            cellular_enabled: false,
            wifi_enabled: false,
            bluetooth_enabled: false,
            gps_enabled: true,
            mesh_enabled: true,
            sleep_tier: SleepTier::Long,
            scan_interval_ms: SCAN_INTERVAL_SENTINEL_MS,
        },
        SecurityMode::Panic => ModePolicy {
            cellular_enabled: false,
            wifi_enabled: false,
            bluetooth_enabled: false,
            gps_enabled: false,
            mesh_enabled: false,
            sleep_tier: SleepTier::Long,
            scan_interval_ms: SCAN_INTERVAL_PANIC_MS,
        },
    }
}

// ---------------------------------------------------------------------------
// PanicEvent
// ---------------------------------------------------------------------------

/// Event emitted when panic mode activates.
///
/// Wave 4 wipe integration consumes this to execute the full wipe
/// sequence via leipsanon. The event carries the tick at which panic
/// was triggered for audit logging.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub struct PanicEvent {
    /// Tick at which panic was triggered.
    pub triggered_at: u64,
    /// Whether keys were successfully zeroized.
    pub keys_zeroized: bool,
}

impl fmt::Display for PanicEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PanicEvent(tick={}, keys_zeroized={})",
            self.triggered_at, self.keys_zeroized,
        )
    }
}

// ---------------------------------------------------------------------------
// ModeTransitionError
// ---------------------------------------------------------------------------

/// Errors from mode transition attempts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
#[non_exhaustive]
pub enum ModeTransitionError {
    /// PIN is required to exit Sentinel mode.
    PinRequired,
    /// The provided PIN did not match.
    PinMismatch,
    /// Cannot transition from Panic (it is terminal).
    PanicIsTerminal,
    /// The panic abort window has expired.
    AbortWindowExpired,
    /// Already in the requested mode.
    AlreadyInMode,
    /// Panic abort requested while not currently in Panic mode -- the
    /// opposite condition from `AlreadyInMode` (which means "transition
    /// target == current mode"), previously conflated with it (issue #282
    /// finding 11).
    NotInPanic,
    /// Sentinel exit was attempted before a real PIN was provisioned
    /// (`pin_hash` is `None`) -- distinct from `PinMismatch` so an
    /// unprovisioned manager fails closed instead of silently accepting or
    /// permanently masquerading as a wrong-PIN lockout (issue #282,
    /// security_mode.rs).
    NotProvisioned,
}

impl fmt::Display for ModeTransitionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PinRequired => write!(f, "PIN required to exit Sentinel mode"),
            Self::PinMismatch => write!(f, "PIN does not match"),
            Self::PanicIsTerminal => write!(f, "cannot transition out of Panic mode"),
            Self::AbortWindowExpired => write!(f, "panic abort window has expired"),
            Self::AlreadyInMode => write!(f, "already in the requested mode"),
            Self::NotInPanic => write!(f, "not currently in Panic mode"),
            Self::NotProvisioned => write!(f, "Sentinel exit PIN not yet provisioned"),
        }
    }
}

// ---------------------------------------------------------------------------
// PanicActivation
// ---------------------------------------------------------------------------

/// How panic mode was activated (for audit trail).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
#[non_exhaustive]
pub enum PanicActivation {
    /// Star + hash + power held 3 seconds.
    KeyCombo,
    /// PTT triple-click.
    PttTripleClick,
    /// Duress PIN entered at lock screen.
    DuressPin,
}

impl fmt::Display for PanicActivation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeyCombo => write!(f, "key combo (star+hash+power)"),
            Self::PttTripleClick => write!(f, "PTT triple-click"),
            Self::DuressPin => write!(f, "duress PIN"),
        }
    }
}

// ---------------------------------------------------------------------------
// ModeManager
// ---------------------------------------------------------------------------

/// Security mode state machine.
///
/// Manages transitions between [`SecurityMode`] variants, enforces
/// transition rules (PIN for Sentinel exit, abort window for Panic),
/// and tracks Covert Lock state independently.
pub(crate) struct ModeManager {
    /// Current security mode.
    mode: SecurityMode,
    /// Covert Lock: independent RF-kill (all radios except mesh).
    covert_lock: bool,
    /// Tick at which panic was activated (for abort window).
    /// `None` when not in panic or after abort window closes.
    panic_initiated_tick: Option<u64>,
    /// Mode before panic was activated (for abort restoration).
    pre_panic_mode: SecurityMode,
    /// Most recent panic event, if any.
    last_panic_event: Option<PanicEvent>,
    /// PBKDF2-HMAC-SHA256 derived value for Sentinel exit PIN verification
    /// (RFC 8018, salted + iterated — see [`ModeManager::exit_sentinel`]).
    ///
    /// `None` means this manager has never been provisioned with a real
    /// PIN. Tracked as an explicit state rather than storing an all-zero
    /// placeholder: a PBKDF2-HMAC-SHA256 output colliding with all-zero is
    /// cryptographically negligible, so an all-zero `pin_hash` would be
    /// indistinguishable from "unprovisioned" yet would silently behave as
    /// if provisioned -- permanently failing every future PIN check
    /// (issue #282, security_mode.rs).
    pin_hash: Option<[u8; 32]>,
}

impl ModeManager {
    /// Create a new `ModeManager` starting in Daily mode.
    ///
    /// `pin_hash` is the PBKDF2-HMAC-SHA256 derived value of the user's PIN
    /// for Sentinel exit verification (see [`ModeManager::exit_sentinel`]).
    #[must_use]
    pub(crate) const fn new(pin_hash: [u8; 32]) -> Self {
        Self {
            mode: SecurityMode::Daily,
            covert_lock: false,
            panic_initiated_tick: None,
            pre_panic_mode: SecurityMode::Daily,
            last_panic_event: None,
            pin_hash: Some(pin_hash),
        }
    }

    /// Current security mode.
    pub(crate) fn mode(&self) -> SecurityMode {
        self.mode
    }

    /// Whether Covert Lock is active.
    #[must_use]
    pub(crate) fn covert_lock(&self) -> bool {
        self.covert_lock
    }

    /// The last emitted panic event, if any.
    #[must_use]
    pub(crate) fn last_panic_event(&self) -> Option<PanicEvent> {
        self.last_panic_event
    }

    // -----------------------------------------------------------------------
    // Mode transitions
    // -----------------------------------------------------------------------

    /// Transition from Daily to Sentinel mode.
    ///
    /// Applies Sentinel radio policy and forces long-sleep key lifecycle.
    ///
    /// # Errors
    ///
    /// Returns [`ModeTransitionError::AlreadyInMode`] if already in Sentinel.
    /// Returns [`ModeTransitionError::PanicIsTerminal`] if in Panic.
    pub(crate) fn enter_sentinel(
        &mut self,
        key_manager: &mut KeyManager,
        power_manager: &mut PowerManager,
    ) -> Result<(), ModeTransitionError> {
        if self.mode == SecurityMode::Panic {
            return Err(ModeTransitionError::PanicIsTerminal);
        }
        if self.mode == SecurityMode::Sentinel {
            return Err(ModeTransitionError::AlreadyInMode);
        }

        self.mode = SecurityMode::Sentinel;
        key_manager.set_sleep_tier(SleepTier::Long);
        self.apply_radio_policy(power_manager);
        Ok(())
    }

    /// Transition from Sentinel back to Daily mode.
    ///
    /// Requires PIN confirmation. The provided `pin` is derived with
    /// PBKDF2-HMAC-SHA256 (RFC 8018, `PIN_PBKDF2_SALT`,
    /// `security::PBKDF2_ITERATIONS` rounds) and compared in constant time
    /// against the stored derived value — a single fast unsalted hash is
    /// brute-forceable offline in milliseconds over the PIN's small
    /// candidate space (CWE-916 / CWE-759).
    ///
    /// # Errors
    ///
    /// Returns [`ModeTransitionError::PinRequired`] if `pin` is empty.
    /// Returns [`ModeTransitionError::NotProvisioned`] if no PIN has ever
    /// been set for this manager.
    /// Returns [`ModeTransitionError::PinMismatch`] if the PIN is wrong.
    /// Returns [`ModeTransitionError::PanicIsTerminal`] if in Panic.
    /// Returns [`ModeTransitionError::AlreadyInMode`] if already in Daily.
    pub(crate) fn exit_sentinel(
        &mut self,
        pin: &[u8],
        power_manager: &mut PowerManager,
    ) -> Result<(), ModeTransitionError> {
        if self.mode == SecurityMode::Panic {
            return Err(ModeTransitionError::PanicIsTerminal);
        }
        if self.mode == SecurityMode::Daily {
            return Err(ModeTransitionError::AlreadyInMode);
        }
        if pin.is_empty() {
            return Err(ModeTransitionError::PinRequired);
        }
        // WHY: an unprovisioned manager (Default::default(), or any
        // constructor path that never received a real PIN derivation) must
        // fail closed and distinguishably from a wrong-PIN guess -- never
        // silently accept, and never present as a permanent PinMismatch
        // that looks like an ordinary typo (issue #282, security_mode.rs).
        let Some(stored_hash) = self.pin_hash else {
            return Err(ModeTransitionError::NotProvisioned);
        };

        // WHY: PBKDF2-HMAC-SHA256 (RFC 8018) replaces the prior single-round
        // unsalted SHA-256 hash — a 4-6 digit PIN has only 1e4-1e6
        // candidates, exhaustively searchable offline in milliseconds
        // against a fast unsalted hash and reusable across every device via
        // one precomputed table (CWE-916 / CWE-759). The salted, iterated
        // derivation costs a full PBKDF2 round per guess.
        let mut derived_pin = [0u8; KEY_SIZE];
        // INVARIANT: PBKDF2_ITERATIONS is a nonzero constant, so
        // ZeroIterations is unreachable here; mapped to PinMismatch
        // (fail-closed) rather than unwrapped.
        let derive_ok = crate::security::pbkdf2_sha256(
            pin,
            PIN_PBKDF2_SALT,
            crate::security::PBKDF2_ITERATIONS,
            &mut derived_pin,
        )
        .is_ok();
        if !derive_ok || !constant_time_eq(&derived_pin, &stored_hash) {
            return Err(ModeTransitionError::PinMismatch);
        }

        self.mode = SecurityMode::Daily;
        self.apply_radio_policy(power_manager);
        Ok(())
    }

    /// Activate Panic mode.
    ///
    /// Immediately zeroizes all keys, disables all radios, and emits a
    /// [`PanicEvent`]. The 15-second abort window begins at `current_tick`.
    ///
    /// Returns the emitted [`PanicEvent`].
    ///
    /// # Errors
    ///
    /// Returns [`ModeTransitionError::AlreadyInMode`] if already in Panic.
    pub(crate) fn activate_panic(
        &mut self,
        current_tick: u64,
        _activation: PanicActivation,
        key_manager: &mut KeyManager,
        power_manager: &mut PowerManager,
    ) -> Result<PanicEvent, ModeTransitionError> {
        if self.mode == SecurityMode::Panic {
            return Err(ModeTransitionError::AlreadyInMode);
        }

        self.pre_panic_mode = self.mode;
        self.mode = SecurityMode::Panic;
        self.panic_initiated_tick = Some(current_tick);

        // Zeroize all cryptographic key material.
        key_manager.zeroize_all();

        // Kill all radios.
        self.apply_radio_policy(power_manager);

        let event = PanicEvent {
            triggered_at: current_tick,
            keys_zeroized: !key_manager.has_keys(),
        };
        self.last_panic_event = Some(event);

        Ok(event)
    }

    /// Abort panic mode within the 15-second window.
    ///
    /// Restores the mode that was active before panic. Note that keys
    /// remain zeroized (a full passphrase re-entry is required).
    ///
    /// # Errors
    ///
    /// Returns [`ModeTransitionError::AbortWindowExpired`] if the abort
    /// window has closed.
    /// Returns [`ModeTransitionError::NotInPanic`] if not currently in Panic mode.
    pub(crate) fn abort_panic(
        &mut self,
        current_tick: u64,
        power_manager: &mut PowerManager,
    ) -> Result<(), ModeTransitionError> {
        if self.mode != SecurityMode::Panic {
            return Err(ModeTransitionError::NotInPanic);
        }

        let Some(initiated) = self.panic_initiated_tick else {
            return Err(ModeTransitionError::AbortWindowExpired);
        };

        if current_tick.saturating_sub(initiated) > PANIC_ABORT_WINDOW_TICKS {
            return Err(ModeTransitionError::AbortWindowExpired);
        }

        self.mode = self.pre_panic_mode;
        self.panic_initiated_tick = None;
        self.apply_radio_policy(power_manager);

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Covert Lock
    // -----------------------------------------------------------------------

    /// Toggle Covert Lock on/off.
    ///
    /// When activating: kills cellular, `WiFi`, BT, GPS. Mesh stays on.
    /// When deactivating: restores radio state per current mode policy.
    pub(crate) fn toggle_covert_lock(&mut self, power_manager: &mut PowerManager) {
        self.covert_lock = !self.covert_lock;
        self.apply_radio_policy(power_manager);
    }

    /// Set Covert Lock to a specific state.
    pub(crate) fn set_covert_lock(&mut self, active: bool, power_manager: &mut PowerManager) {
        if self.covert_lock != active {
            self.covert_lock = active;
            self.apply_radio_policy(power_manager);
        }
    }

    // -----------------------------------------------------------------------
    // Policy
    // -----------------------------------------------------------------------

    /// Return the effective policy, accounting for both mode and Covert Lock.
    pub(crate) fn effective_policy(&self) -> ModePolicy {
        let mut policy = base_policy(self.mode);

        // Covert Lock overrides: kill all RF except mesh.
        if self.covert_lock {
            policy.cellular_enabled = false;
            policy.wifi_enabled = false;
            policy.bluetooth_enabled = false;
            policy.gps_enabled = false;
            // Mesh stays as per mode policy.
        }

        policy
    }

    /// Apply the current effective policy to the power manager.
    ///
    /// Delegates to [`crate::power::apply_mode_policy`] — the single
    /// authoritative `ModePolicy` -> radio-actuation mapping, including
    /// Mesh/LoRa (#254). Do not hand-roll radio actuation here again: a
    /// second, independently-drifting copy of this mapping is exactly how
    /// Mesh went unactuated in two places at once.
    fn apply_radio_policy(&self, pm: &mut PowerManager) {
        let policy = self.effective_policy();
        crate::power::apply_mode_policy(&policy, pm);
    }

    // -----------------------------------------------------------------------
    // Status bar
    // -----------------------------------------------------------------------

    /// Return the status bar badge label for the current mode.
    ///
    /// - Daily: `"DAILY"` (when Covert Lock is off)
    /// - Sentinel: `"SENTL"`
    /// - Panic: `"PANIC"`
    /// - Any + Covert Lock: `"COVRT"`
    #[must_use]
    pub(crate) fn status_badge(&self) -> &'static str {
        if self.covert_lock && self.mode != SecurityMode::Panic {
            return "COVRT";
        }
        match self.mode {
            SecurityMode::Daily => "DAILY",
            SecurityMode::Sentinel => "SENTL",
            SecurityMode::Panic => "PANIC",
        }
    }

    /// Return the RGB565 color for the status bar badge.
    ///
    /// - Daily: green (0x07E0)
    /// - Sentinel: yellow (0xFFE0)
    /// - Covert Lock: red (0xF800)
    /// - Panic: red (0xF800)
    #[must_use]
    pub(crate) fn status_badge_color(&self) -> u16 {
        use crate::ui::color;

        if self.covert_lock && self.mode != SecurityMode::Panic {
            return color::RED;
        }
        match self.mode {
            SecurityMode::Daily => color::GREEN,
            SecurityMode::Sentinel => color::YELLOW,
            SecurityMode::Panic => color::RED,
        }
    }

    /// Return the mode character for the status bar center indicator.
    ///
    /// Used by `StatusBarState::mode_char` for backward compatibility.
    #[must_use]
    pub(crate) fn mode_char(&self) -> char {
        match self.mode {
            SecurityMode::Daily => 'D',
            SecurityMode::Sentinel => 'S',
            SecurityMode::Panic => 'P',
        }
    }
}

impl Default for ModeManager {
    fn default() -> Self {
        // INVARIANT: default-constructed managers are explicitly
        // unprovisioned (`pin_hash: None`), not a `Some([0u8; 32])`
        // placeholder -- the latter would silently look provisioned and
        // permanently fail every future Sentinel-exit PIN check, since a
        // real PBKDF2-HMAC-SHA256 derivation colliding with all-zero is
        // cryptographically negligible (issue #282, security_mode.rs).
        Self {
            mode: SecurityMode::Daily,
            covert_lock: false,
            panic_initiated_tick: None,
            pre_panic_mode: SecurityMode::Daily,
            last_panic_event: None,
            pin_hash: None,
        }
    }
}

impl fmt::Debug for ModeManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ModeManager")
            .field("mode", &self.mode)
            .field("covert_lock", &self.covert_lock)
            .field("panic_initiated_tick", &self.panic_initiated_tick)
            .field("pre_panic_mode", &self.pre_panic_mode)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for ModeManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ModeManager(mode={}, covert={}, badge={})",
            self.mode,
            self.covert_lock,
            self.status_badge(),
        )
    }
}

// ---------------------------------------------------------------------------
// Audit integration
// ---------------------------------------------------------------------------

/// Log a mode transition event to the audit log.
///
/// Records the transition as a `ModeChange` event with the mode names.
pub(crate) fn log_mode_change(
    from: SecurityMode,
    to: SecurityMode,
    audit_log: &mut AuditLog,
    audit_key: &[u8; KEY_SIZE],
    timestamp: u64,
) {
    // Format "Daily->Sentinel" etc. into a fixed buffer.
    let mut detail = [0u8; 32];
    let from_str = mode_name(from);
    let to_str = mode_name(to);
    let arrow = b"->";
    let mut offset = 0;
    for &b in from_str.as_bytes() {
        if offset < detail.len() {
            detail[offset] = b;
            offset += 1;
        }
    }
    for &b in arrow {
        if offset < detail.len() {
            detail[offset] = b;
            offset += 1;
        }
    }
    for &b in to_str.as_bytes() {
        if offset < detail.len() {
            detail[offset] = b;
            offset += 1;
        }
    }
    // WHY: an audit-log write failure (e.g. capacity, missing key) must
    // never block the mode transition itself -- the transition has already
    // committed by the time this logs. Best-effort discard via `.ok()`,
    // not `let _ =` (kanon standard; issue #282 finding 12).
    audit_log
        .log_event(
            AuditEventType::ModeChange,
            0,
            &detail[..offset],
            timestamp,
            audit_key,
        )
        .ok();
}

/// Log a panic trigger event to the audit log.
///
/// Records the activation method as a `PanicTrigger` event.
pub(crate) fn log_panic_trigger(
    activation: PanicActivation,
    audit_log: &mut AuditLog,
    audit_key: &[u8; KEY_SIZE],
    timestamp: u64,
) {
    let detail = match activation {
        PanicActivation::KeyCombo => b"key combo" as &[u8],
        PanicActivation::PttTripleClick => b"PTT triple-click",
        PanicActivation::DuressPin => b"duress PIN",
    };
    // WHY: see log_mode_change -- audit-log failure must not block the
    // panic-trigger critical path (issue #282 finding 12).
    audit_log
        .log_event(
            AuditEventType::PanicTrigger,
            0,
            detail,
            timestamp,
            audit_key,
        )
        .ok();
}

/// Return the string name of a security mode for audit detail fields.
const fn mode_name(mode: SecurityMode) -> &'static str {
    match mode {
        SecurityMode::Daily => "Daily",
        SecurityMode::Sentinel => "Sentinel",
        SecurityMode::Panic => "Panic",
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Threat response integration (Phase 10 Wave 3)
// ---------------------------------------------------------------------------

/// Threat response action taken by the security mode system.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
#[non_exhaustive]
pub enum ThreatResponse {
    /// Firewall switched to restricted (Sentinel) whitelist.
    FirewallRestricted,
    /// Modem power cut via PMIC.
    ModemPowerCut,
    /// No action needed (threat below threshold).
    None,
}

impl fmt::Display for ThreatResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FirewallRestricted => write!(f, "firewall restricted"),
            Self::ModemPowerCut => write!(f, "modem power cut"),
            Self::None => write!(f, "none"),
        }
    }
}

/// Evaluate a threat score and apply the appropriate response.
///
/// - Score >= `critical_threshold`: trigger modem power cut.
/// - Sentinel mode active: restrict firewall to Sentinel whitelist.
/// - Below threshold: no action.
///
/// Returns the action taken for audit logging.
pub(crate) fn evaluate_threat(
    mode: SecurityMode,
    threat_score: u32,
    critical_threshold: u32,
    firewall: &mut crate::ccci_logger::CcciFirewall,
    power_manager: &mut PowerManager,
) -> ThreatResponse {
    use crate::ccci_logger::FirewallMode;

    // Critical threat score: modem power cut.
    if threat_score >= critical_threshold {
        firewall.apply_mode(FirewallMode::Panic);
        // SAFETY: PMIC registers must be mapped. This is only called from
        // kernel context where PMIC is accessible.
        unsafe {
            power_manager.modem_power_cut();
        }
        return ThreatResponse::ModemPowerCut;
    }

    // Sentinel mode: restrict firewall.
    if mode == SecurityMode::Sentinel {
        firewall.apply_mode(FirewallMode::Sentinel);
        return ThreatResponse::FirewallRestricted;
    }

    ThreatResponse::None
}

/// Apply firewall mode matching the current security mode.
///
/// Called during mode transitions to sync the CCCI firewall with the
/// security mode state machine.
pub(crate) fn sync_firewall_mode(
    mode: SecurityMode,
    firewall: &mut crate::ccci_logger::CcciFirewall,
) {
    use crate::ccci_logger::FirewallMode;

    let fw_mode = match mode {
        SecurityMode::Daily => FirewallMode::Daily,
        SecurityMode::Sentinel => FirewallMode::Sentinel,
        SecurityMode::Panic => FirewallMode::Panic,
    };
    firewall.apply_mode(fw_mode);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Constant-time byte array comparison to prevent timing side-channels
/// on PIN verification.
///
/// WHY: backed by `subtle::ConstantTimeEq`, which inserts optimization
/// barriers the compiler cannot elide — a hand-rolled XOR loop can be
/// defeated by an optimizing backend. Mirrors the `lock_screen.rs`
/// constant-time compare: the duress/coercion surface has the same
/// timing-oracle requirement as Sentinel-exit PIN verification.
fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let a_slice: &[u8] = a;
    let b_slice: &[u8] = b;
    a_slice.ct_eq(b_slice).unwrap_u8() == 1
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::*;

    /// Helper: derive the PBKDF2-HMAC-SHA256 value of a test PIN, matching
    /// `ModeManager::exit_sentinel`'s verification derivation exactly (same
    /// salt + iteration count) so the stored fixture round-trips.
    fn derive_test_pin_hash(pin: &[u8]) -> [u8; 32] {
        let mut derived = [0u8; 32];
        crate::security::pbkdf2_sha256(
            pin,
            PIN_PBKDF2_SALT,
            crate::security::PBKDF2_ITERATIONS,
            &mut derived,
        )
        .expect("pbkdf2 derivation failed in test");
        derived
    }

    /// Helper: create a ModeManager with a known test PIN.
    fn mode_manager_with_test_pin() -> ModeManager {
        ModeManager::new(derive_test_pin_hash(b"123456"))
    }

    /// Helper: create a KeyManager with loaded keys for testing.
    fn key_manager_with_derived_keys() -> KeyManager {
        let mut km = KeyManager::new();
        let primary = {
            let mut key_bytes = [0u8; 32];
            crate::security::pbkdf2_sha256(b"test", b"salt", 1, &mut key_bytes)
                .expect("pbkdf2 failed");
            crate::key_manager::SecureKey::new(key_bytes)
        };
        km.derive_partition_keys(&primary)
            .expect("derive_partition_keys failed");
        km
    }

    // -----------------------------------------------------------------------
    // Mode starts Daily
    // -----------------------------------------------------------------------

    #[test]
    fn mode_starts_daily() {
        let mm = mode_manager_with_test_pin();
        assert_eq!(mm.mode(), SecurityMode::Daily);
        assert!(!mm.covert_lock());
        assert!(mm.last_panic_event().is_none());
    }

    /// A `Default`-constructed manager has never been provisioned with a
    /// real PIN; Sentinel exit must fail closed (`NotProvisioned`), not
    /// silently accept any input and not masquerade as an ordinary
    /// wrong-PIN `PinMismatch` (issue #282, security_mode.rs).
    #[test]
    fn default_mode_manager_is_unprovisioned_and_cannot_exit_sentinel() {
        let mut mm = ModeManager::default();
        let mut km = key_manager_with_derived_keys();
        let mut pm = PowerManager::new();

        mm.enter_sentinel(&mut km, &mut pm)
            .expect("enter_sentinel failed");

        let result = mm.exit_sentinel(b"123456", &mut pm);
        assert_eq!(
            result,
            Err(ModeTransitionError::NotProvisioned),
            "an unprovisioned manager must reject Sentinel exit distinctly from a wrong PIN"
        );
        assert_eq!(
            mm.mode(),
            SecurityMode::Sentinel,
            "a rejected exit must not change mode"
        );
    }

    // -----------------------------------------------------------------------
    // Daily -> Sentinel
    // -----------------------------------------------------------------------

    #[test]
    fn transition_daily_to_sentinel() {
        let mut mm = mode_manager_with_test_pin();
        let mut km = key_manager_with_derived_keys();
        let mut pm = PowerManager::new();
        pm.apply_mode(crate::power::PowerMode::Full);

        mm.enter_sentinel(&mut km, &mut pm)
            .expect("enter_sentinel failed");

        assert_eq!(mm.mode(), SecurityMode::Sentinel);
        // Sentinel forces long-sleep, which zeroizes keys.
        assert_eq!(km.sleep_tier(), SleepTier::Long);
        // Cellular/WiFi/BT should be off.
        assert_eq!(pm.state(Radio::Cellular), PowerState::Off);
        assert_eq!(pm.state(Radio::Wifi), PowerState::Off);
        assert_eq!(pm.state(Radio::Bluetooth), PowerState::Off);
        // GPS stays on in Sentinel.
        assert_eq!(pm.state(Radio::Gps), PowerState::On);
    }

    // -----------------------------------------------------------------------
    // Sentinel -> Daily requires PIN
    // -----------------------------------------------------------------------

    #[test]
    fn transition_sentinel_to_daily_requires_pin() {
        let mut mm = mode_manager_with_test_pin();
        let mut km = key_manager_with_derived_keys();
        let mut pm = PowerManager::new();

        mm.enter_sentinel(&mut km, &mut pm)
            .expect("enter_sentinel failed");

        // Empty PIN should fail.
        let result = mm.exit_sentinel(b"", &mut pm);
        assert_eq!(result, Err(ModeTransitionError::PinRequired));

        // Wrong PIN should fail.
        let result = mm.exit_sentinel(b"000000", &mut pm);
        assert_eq!(result, Err(ModeTransitionError::PinMismatch));

        // Correct PIN should succeed.
        mm.exit_sentinel(b"123456", &mut pm)
            .expect("exit_sentinel failed");
        assert_eq!(mm.mode(), SecurityMode::Daily);
    }

    // -----------------------------------------------------------------------
    // Sentinel-exit PIN uses a salted, iterated KDF (#272)
    // -----------------------------------------------------------------------

    #[test]
    fn exit_sentinel_pin_is_not_verified_by_plain_sha256() {
        // Regression test for #272: exit_sentinel previously verified the
        // PIN via a single-round, unsalted SHA-256 hash. Proves the
        // stored/derived value is now the PBKDF2-HMAC-SHA256 derivation,
        // not a bare SHA-256 digest of the same PIN.
        let derived = derive_test_pin_hash(b"123456");
        let bare_sha256 = crate::security::sha256(b"123456");
        assert_ne!(
            derived, bare_sha256,
            "Sentinel-exit PIN verification must use a KDF, not a bare SHA-256 hash"
        );
    }

    #[test]
    fn exit_sentinel_pin_derivation_is_salted() {
        // A KDF without a salt input does not resist a precomputed /
        // rainbow-table attack. Confirm the salt is load-bearing: a
        // different salt must produce a different derived value for the
        // same PIN.
        let mut with_salt = [0u8; 32];
        crate::security::pbkdf2_sha256(
            b"123456",
            PIN_PBKDF2_SALT,
            crate::security::PBKDF2_ITERATIONS,
            &mut with_salt,
        )
        .expect("pbkdf2 failed");

        let mut different_salt = [0u8; 32];
        crate::security::pbkdf2_sha256(
            b"123456",
            b"a-different-salt",
            crate::security::PBKDF2_ITERATIONS,
            &mut different_salt,
        )
        .expect("pbkdf2 failed");

        assert_ne!(
            with_salt, different_salt,
            "different salts must produce different derived PIN values"
        );
    }

    #[test]
    fn exit_sentinel_still_succeeds_with_correct_pin_after_kdf_fix() {
        // Round-trip regression: the salted KDF must not break legitimate
        // Sentinel exit with the correct PIN (covered indirectly by
        // transition_sentinel_to_daily_requires_pin above; asserted
        // directly here for #272 traceability).
        let mut mm = mode_manager_with_test_pin();
        let mut km = key_manager_with_derived_keys();
        let mut pm = PowerManager::new();

        mm.enter_sentinel(&mut km, &mut pm)
            .expect("enter_sentinel failed");
        mm.exit_sentinel(b"123456", &mut pm)
            .expect("correct PIN must still unlock after KDF fix");
        assert_eq!(mm.mode(), SecurityMode::Daily);
    }

    // -----------------------------------------------------------------------
    // Panic triggers key zeroize
    // -----------------------------------------------------------------------

    #[test]
    fn panic_triggers_key_zeroize() {
        let mut mm = mode_manager_with_test_pin();
        let mut km = key_manager_with_derived_keys();
        let mut pm = PowerManager::new();
        pm.apply_mode(crate::power::PowerMode::Full);

        assert!(km.has_keys(), "keys must be loaded before panic");

        let event = mm
            .activate_panic(1000, PanicActivation::KeyCombo, &mut km, &mut pm)
            .expect("activate_panic failed");

        assert_eq!(mm.mode(), SecurityMode::Panic);
        assert!(!km.has_keys(), "keys must be zeroized after panic");
        assert!(event.keys_zeroized);
        assert_eq!(event.triggered_at, 1000);

        // All radios must be off, including Mesh/LoRa (#254).
        assert_eq!(pm.state(Radio::Cellular), PowerState::Off);
        assert_eq!(pm.state(Radio::Wifi), PowerState::Off);
        assert_eq!(pm.state(Radio::Bluetooth), PowerState::Off);
        assert_eq!(pm.state(Radio::Gps), PowerState::Off);
        assert_eq!(
            pm.state(Radio::Mesh),
            PowerState::Off,
            "Panic must leave the Mesh/LoRa transceiver off (#254)"
        );
    }

    // -----------------------------------------------------------------------
    // Panic abort within window
    // -----------------------------------------------------------------------

    #[test]
    fn panic_abort_within_window() {
        let mut mm = mode_manager_with_test_pin();
        let mut km = key_manager_with_derived_keys();
        let mut pm = PowerManager::new();

        // Start in Daily, activate panic at tick 1000.
        mm.activate_panic(1000, PanicActivation::PttTripleClick, &mut km, &mut pm)
            .expect("activate_panic failed");

        assert_eq!(mm.mode(), SecurityMode::Panic);

        // Abort at tick 1500 (500 ticks later, within 1500-tick window).
        mm.abort_panic(1500, &mut pm).expect("abort_panic failed");

        // Should restore to Daily (the pre-panic mode).
        assert_eq!(mm.mode(), SecurityMode::Daily);
    }

    // -----------------------------------------------------------------------
    // Panic abort after window fails
    // -----------------------------------------------------------------------

    #[test]
    fn panic_abort_after_window_fails() {
        let mut mm = mode_manager_with_test_pin();
        let mut km = key_manager_with_derived_keys();
        let mut pm = PowerManager::new();

        mm.activate_panic(1000, PanicActivation::DuressPin, &mut km, &mut pm)
            .expect("activate_panic failed");

        // Try to abort at tick 3000 (2000 ticks later, exceeds 1500-tick window).
        let result = mm.abort_panic(3000, &mut pm);
        assert_eq!(result, Err(ModeTransitionError::AbortWindowExpired));
        assert_eq!(mm.mode(), SecurityMode::Panic);
    }

    #[test]
    fn panic_abort_window_exact_boundary_ticks() {
        // WHY: elapsed == PANIC_ABORT_WINDOW_TICKS (1500) sits on the
        // inclusive edge of `elapsed > PANIC_ABORT_WINDOW_TICKS` -- the
        // abort must still succeed here.
        let mut mm = mode_manager_with_test_pin();
        let mut km = key_manager_with_derived_keys();
        let mut pm = PowerManager::new();

        mm.activate_panic(1000, PanicActivation::KeyCombo, &mut km, &mut pm)
            .expect("activate_panic failed");
        mm.abort_panic(2500, &mut pm)
            .expect("abort at elapsed == PANIC_ABORT_WINDOW_TICKS must succeed");
        assert_eq!(mm.mode(), SecurityMode::Daily);

        // WHY: elapsed == PANIC_ABORT_WINDOW_TICKS + 1 (1501) is one tick
        // past the inclusive edge -- the abort must fail here.
        let mut mm = mode_manager_with_test_pin();
        let mut km = key_manager_with_derived_keys();
        let mut pm = PowerManager::new();

        mm.activate_panic(1000, PanicActivation::KeyCombo, &mut km, &mut pm)
            .expect("activate_panic failed");
        let result = mm.abort_panic(2501, &mut pm);
        assert_eq!(result, Err(ModeTransitionError::AbortWindowExpired));
        assert_eq!(mm.mode(), SecurityMode::Panic);
    }

    // -----------------------------------------------------------------------
    // Covert Lock toggles RF
    // -----------------------------------------------------------------------

    #[test]
    fn covert_lock_toggles_rf() {
        let mut mm = mode_manager_with_test_pin();
        let mut pm = PowerManager::new();
        pm.apply_mode(crate::power::PowerMode::Full);

        assert!(!mm.covert_lock());

        // Activate Covert Lock.
        mm.toggle_covert_lock(&mut pm);

        assert!(mm.covert_lock());
        assert_eq!(pm.state(Radio::Cellular), PowerState::Off);
        assert_eq!(pm.state(Radio::Wifi), PowerState::Off);
        assert_eq!(pm.state(Radio::Bluetooth), PowerState::Off);
        assert_eq!(pm.state(Radio::Gps), PowerState::Off);
        assert_eq!(
            pm.state(Radio::Mesh),
            PowerState::On,
            "Covert Lock must keep mesh on (#254)"
        );

        // Deactivate Covert Lock — Daily mode restores all radios.
        mm.toggle_covert_lock(&mut pm);

        assert!(!mm.covert_lock());
        assert_eq!(pm.state(Radio::Cellular), PowerState::On);
        assert_eq!(pm.state(Radio::Wifi), PowerState::On);
        assert_eq!(pm.state(Radio::Bluetooth), PowerState::On);
        assert_eq!(pm.state(Radio::Gps), PowerState::On);
        assert_eq!(pm.state(Radio::Mesh), PowerState::On);
    }

    // -----------------------------------------------------------------------
    // Mode policy tests
    // -----------------------------------------------------------------------

    #[test]
    fn mode_policy_sentinel_disables_cellular() {
        let policy = base_policy(SecurityMode::Sentinel);
        assert!(!policy.cellular_enabled, "Sentinel must disable cellular");
        assert!(!policy.wifi_enabled, "Sentinel must disable WiFi");
        assert!(!policy.bluetooth_enabled, "Sentinel must disable Bluetooth");
        assert!(policy.gps_enabled, "Sentinel must keep GPS on");
        assert!(policy.mesh_enabled, "Sentinel must keep mesh on");
        assert_eq!(policy.sleep_tier, SleepTier::Long);
        assert_eq!(policy.scan_interval_ms, SCAN_INTERVAL_SENTINEL_MS);
    }

    #[test]
    fn mode_policy_daily_enables_all() {
        let policy = base_policy(SecurityMode::Daily);
        assert!(policy.cellular_enabled, "Daily must enable cellular");
        assert!(policy.wifi_enabled, "Daily must enable WiFi");
        assert!(policy.bluetooth_enabled, "Daily must enable Bluetooth");
        assert!(policy.gps_enabled, "Daily must enable GPS");
        assert!(policy.mesh_enabled, "Daily must enable mesh");
        assert_eq!(policy.sleep_tier, SleepTier::Short);
        assert_eq!(policy.scan_interval_ms, SCAN_INTERVAL_DAILY_MS);
    }

    #[test]
    fn mode_policy_panic_disables_all() {
        let policy = base_policy(SecurityMode::Panic);
        assert!(!policy.cellular_enabled, "Panic must disable cellular");
        assert!(!policy.wifi_enabled, "Panic must disable WiFi");
        assert!(!policy.bluetooth_enabled, "Panic must disable Bluetooth");
        assert!(!policy.gps_enabled, "Panic must disable GPS");
        assert!(!policy.mesh_enabled, "Panic must disable mesh");
        assert_eq!(policy.sleep_tier, SleepTier::Long);
        assert_eq!(policy.scan_interval_ms, SCAN_INTERVAL_PANIC_MS);
    }

    // -----------------------------------------------------------------------
    // Effective policy with Covert Lock
    // -----------------------------------------------------------------------

    #[test]
    fn effective_policy_covert_lock_overrides_daily() {
        let mut mm = mode_manager_with_test_pin();
        let mut pm = PowerManager::new();
        mm.toggle_covert_lock(&mut pm);

        let policy = mm.effective_policy();
        assert!(!policy.cellular_enabled, "Covert must kill cellular");
        assert!(!policy.wifi_enabled, "Covert must kill WiFi");
        assert!(!policy.bluetooth_enabled, "Covert must kill Bluetooth");
        assert!(!policy.gps_enabled, "Covert must kill GPS");
        // Mesh stays per mode policy (Daily = on).
        assert!(policy.mesh_enabled, "Covert must keep mesh on");
    }

    // -----------------------------------------------------------------------
    // Status bar badge
    // -----------------------------------------------------------------------

    #[test]
    fn status_badge_daily() {
        let mm = mode_manager_with_test_pin();
        assert_eq!(mm.status_badge(), "DAILY");
    }

    #[test]
    fn status_badge_sentinel() {
        let mut mm = mode_manager_with_test_pin();
        let mut km = KeyManager::new();
        let mut pm = PowerManager::new();
        mm.enter_sentinel(&mut km, &mut pm)
            .expect("enter_sentinel failed");
        assert_eq!(mm.status_badge(), "SENTL");
    }

    #[test]
    fn status_badge_panic() {
        let mut mm = mode_manager_with_test_pin();
        let mut km = KeyManager::new();
        let mut pm = PowerManager::new();
        mm.activate_panic(0, PanicActivation::KeyCombo, &mut km, &mut pm)
            .expect("activate_panic failed");
        assert_eq!(mm.status_badge(), "PANIC");
    }

    #[test]
    fn status_badge_covert_overrides_daily() {
        let mut mm = mode_manager_with_test_pin();
        let mut pm = PowerManager::new();
        mm.toggle_covert_lock(&mut pm);
        assert_eq!(mm.status_badge(), "COVRT");
    }

    #[test]
    fn status_badge_covert_does_not_override_panic() {
        let mut mm = mode_manager_with_test_pin();
        let mut km = KeyManager::new();
        let mut pm = PowerManager::new();

        // Activate covert lock first, then panic.
        mm.toggle_covert_lock(&mut pm);
        mm.activate_panic(0, PanicActivation::KeyCombo, &mut km, &mut pm)
            .expect("activate_panic failed");

        // Panic overrides covert badge.
        assert_eq!(mm.status_badge(), "PANIC");
    }

    // -----------------------------------------------------------------------
    // Mode character
    // -----------------------------------------------------------------------

    #[test]
    fn mode_char_maps_correctly() {
        let mut mm = mode_manager_with_test_pin();
        assert_eq!(mm.mode_char(), 'D');

        let mut km = KeyManager::new();
        let mut pm = PowerManager::new();
        mm.enter_sentinel(&mut km, &mut pm)
            .expect("enter_sentinel failed");
        assert_eq!(mm.mode_char(), 'S');

        mm.activate_panic(0, PanicActivation::KeyCombo, &mut km, &mut pm)
            .expect("activate_panic failed");
        assert_eq!(mm.mode_char(), 'P');
    }

    // -----------------------------------------------------------------------
    // Edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn double_sentinel_entry_fails() {
        let mut mm = mode_manager_with_test_pin();
        let mut km = KeyManager::new();
        let mut pm = PowerManager::new();

        mm.enter_sentinel(&mut km, &mut pm).expect("first entry");
        let result = mm.enter_sentinel(&mut km, &mut pm);
        assert_eq!(result, Err(ModeTransitionError::AlreadyInMode));
    }

    #[test]
    fn sentinel_from_panic_fails() {
        let mut mm = mode_manager_with_test_pin();
        let mut km = KeyManager::new();
        let mut pm = PowerManager::new();

        mm.activate_panic(0, PanicActivation::KeyCombo, &mut km, &mut pm)
            .expect("activate_panic failed");

        let result = mm.enter_sentinel(&mut km, &mut pm);
        assert_eq!(result, Err(ModeTransitionError::PanicIsTerminal));
    }

    #[test]
    fn exit_sentinel_from_daily_fails() {
        let mut mm = mode_manager_with_test_pin();
        let mut pm = PowerManager::new();

        let result = mm.exit_sentinel(b"123456", &mut pm);
        assert_eq!(result, Err(ModeTransitionError::AlreadyInMode));
    }

    #[test]
    fn double_panic_fails() {
        let mut mm = mode_manager_with_test_pin();
        let mut km = KeyManager::new();
        let mut pm = PowerManager::new();

        mm.activate_panic(0, PanicActivation::KeyCombo, &mut km, &mut pm)
            .expect("first panic");

        let result = mm.activate_panic(100, PanicActivation::DuressPin, &mut km, &mut pm);
        assert_eq!(result, Err(ModeTransitionError::AlreadyInMode));
    }

    #[test]
    fn abort_from_non_panic_fails() {
        let mut mm = mode_manager_with_test_pin();
        let mut pm = PowerManager::new();

        let result = mm.abort_panic(0, &mut pm);
        assert_eq!(result, Err(ModeTransitionError::NotInPanic));
    }

    #[test]
    fn panic_abort_restores_sentinel_if_panic_from_sentinel() {
        let mut mm = mode_manager_with_test_pin();
        let mut km = key_manager_with_derived_keys();
        let mut pm = PowerManager::new();

        mm.enter_sentinel(&mut km, &mut pm)
            .expect("enter_sentinel failed");
        assert_eq!(mm.mode(), SecurityMode::Sentinel);

        mm.activate_panic(1000, PanicActivation::KeyCombo, &mut km, &mut pm)
            .expect("activate_panic failed");

        mm.abort_panic(1100, &mut pm).expect("abort_panic failed");
        assert_eq!(
            mm.mode(),
            SecurityMode::Sentinel,
            "abort must restore pre-panic mode (Sentinel)"
        );
    }

    // -----------------------------------------------------------------------
    // Display implementations
    // -----------------------------------------------------------------------

    #[test]
    fn display_impls_produce_output() {
        let mm = mode_manager_with_test_pin();
        let s = alloc::format!("{mm}");
        assert!(s.contains("Daily"), "Display must show mode");
        assert!(s.contains("covert=false"), "Display must show covert state");

        let mode_s = SecurityMode::Sentinel.to_string();
        assert_eq!(mode_s, "Sentinel");

        let policy_s = base_policy(SecurityMode::Daily).to_string();
        assert!(policy_s.contains("cell=true"));

        let event = PanicEvent {
            triggered_at: 42,
            keys_zeroized: true,
        };
        let event_s = alloc::format!("{event}");
        assert!(event_s.contains("42"));

        let err_s = ModeTransitionError::PinRequired.to_string();
        assert!(err_s.contains("PIN"));

        let act_s = PanicActivation::KeyCombo.to_string();
        assert!(act_s.contains("key combo"));
    }

    // -----------------------------------------------------------------------
    // Constant-time comparison
    // -----------------------------------------------------------------------

    #[test]
    fn constant_time_eq_works() {
        let a = [0xAAu8; 32];
        let b = [0xAAu8; 32];
        let c = [0xBBu8; 32];
        assert!(constant_time_eq(&a, &b));
        assert!(!constant_time_eq(&a, &c));
    }

    #[test]
    fn log_mode_change_records_audit_entry() {
        let mut log = AuditLog::new();
        let key = [0xAAu8; KEY_SIZE];

        assert!(log.is_empty(), "audit log must start empty");

        log_mode_change(
            SecurityMode::Daily,
            SecurityMode::Sentinel,
            &mut log,
            &key,
            12345,
        );

        assert_eq!(
            log.len(),
            1,
            "log_mode_change must append exactly one entry"
        );
        let (older, newer) = log.recent(1);
        let entry = if newer.is_empty() {
            &older[0]
        } else {
            &newer[0]
        };
        assert_eq!(entry.event_type, AuditEventType::ModeChange);
        assert_eq!(entry.timestamp, 12345);
        assert_eq!(entry.detail(), b"Daily->Sentinel");
    }

    #[test]
    fn log_panic_trigger_records_audit_entry() {
        let mut log = AuditLog::new();
        let key = [0xAAu8; KEY_SIZE];

        log_panic_trigger(PanicActivation::PttTripleClick, &mut log, &key, 99);

        assert_eq!(
            log.len(),
            1,
            "log_panic_trigger must append exactly one entry"
        );
        let (older, newer) = log.recent(1);
        let entry = if newer.is_empty() {
            &older[0]
        } else {
            &newer[0]
        };
        assert_eq!(entry.event_type, AuditEventType::PanicTrigger);
        assert_eq!(entry.timestamp, 99);
        assert_eq!(entry.detail(), b"PTT triple-click");
    }

    // -----------------------------------------------------------------------
    // Threat response tests (Phase 10 Wave 3)
    // -----------------------------------------------------------------------

    #[test]
    fn evaluate_threat_critical_triggers_power_cut() {
        use crate::ccci_logger::{CcciFirewall, FirewallMode};

        let mut fw = CcciFirewall::new(FirewallMode::Daily);
        let mut pm = PowerManager::new();
        pm.apply_mode(crate::power::PowerMode::Full);

        let response = evaluate_threat(
            SecurityMode::Daily,
            100, // score
            80,  // threshold
            &mut fw,
            &mut pm,
        );

        assert_eq!(
            response,
            ThreatResponse::ModemPowerCut,
            "critical score must trigger modem power cut"
        );
        assert_eq!(
            fw.mode(),
            FirewallMode::Panic,
            "firewall must switch to Panic on critical"
        );
        assert!(pm.is_modem_pmic_killed(), "modem must be PMIC-killed");
    }

    #[test]
    fn evaluate_threat_sentinel_restricts_firewall() {
        use crate::ccci_logger::{CcciFirewall, FirewallMode};

        let mut fw = CcciFirewall::new(FirewallMode::Daily);
        let mut pm = PowerManager::new();

        let response = evaluate_threat(
            SecurityMode::Sentinel,
            10, // score below threshold
            80,
            &mut fw,
            &mut pm,
        );

        assert_eq!(
            response,
            ThreatResponse::FirewallRestricted,
            "Sentinel mode must restrict firewall"
        );
        assert_eq!(
            fw.mode(),
            FirewallMode::Sentinel,
            "firewall must switch to Sentinel"
        );
    }

    #[test]
    fn evaluate_threat_daily_below_threshold_no_action() {
        use crate::ccci_logger::{CcciFirewall, FirewallMode};

        let mut fw = CcciFirewall::new(FirewallMode::Daily);
        let mut pm = PowerManager::new();

        let response = evaluate_threat(SecurityMode::Daily, 10, 80, &mut fw, &mut pm);

        assert_eq!(
            response,
            ThreatResponse::None,
            "below threshold in Daily must take no action"
        );
        assert_eq!(
            fw.mode(),
            FirewallMode::Daily,
            "firewall must remain in Daily mode"
        );
    }

    #[test]
    fn evaluate_threat_score_equals_threshold_is_critical() {
        // WHY: the critical branch compares `threat_score >= critical_threshold`,
        // so the threshold value is inclusive of "critical", and the critical
        // check must short-circuit ahead of the Sentinel-restrict branch even
        // while Sentinel mode is active.
        use crate::ccci_logger::{CcciFirewall, FirewallMode};

        let mut fw = CcciFirewall::new(FirewallMode::Daily);
        let mut pm = PowerManager::new();
        pm.apply_mode(crate::power::PowerMode::Full);

        let response = evaluate_threat(
            SecurityMode::Sentinel,
            80, // score == threshold
            80, // threshold
            &mut fw,
            &mut pm,
        );

        assert_eq!(
            response,
            ThreatResponse::ModemPowerCut,
            "score exactly equal to critical_threshold must be classified critical"
        );
        assert_eq!(
            fw.mode(),
            FirewallMode::Panic,
            "firewall must switch to Panic, not Sentinel, when the score meets the threshold exactly"
        );
        assert!(
            pm.is_modem_pmic_killed(),
            "modem must be PMIC-killed at the exact threshold"
        );
    }

    #[test]
    fn sync_firewall_mode_matches_security_mode() {
        use crate::ccci_logger::{CcciFirewall, FirewallMode};

        let mut fw = CcciFirewall::new(FirewallMode::Daily);

        sync_firewall_mode(SecurityMode::Sentinel, &mut fw);
        assert_eq!(fw.mode(), FirewallMode::Sentinel);

        sync_firewall_mode(SecurityMode::Panic, &mut fw);
        assert_eq!(fw.mode(), FirewallMode::Panic);

        sync_firewall_mode(SecurityMode::Daily, &mut fw);
        assert_eq!(fw.mode(), FirewallMode::Daily);
    }

    #[test]
    fn threat_response_display() {
        let cut = ThreatResponse::ModemPowerCut.to_string();
        assert!(cut.contains("power cut"));

        let restrict = ThreatResponse::FirewallRestricted.to_string();
        assert!(restrict.contains("restricted"));

        let none = ThreatResponse::None.to_string();
        assert!(none.contains("none"));
    }
}
