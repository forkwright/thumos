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

use crate::audit::{AuditEventType, AuditLog};
use crate::key_manager::KeyManager;
use crate::power::{PowerManager, PowerState, Radio};
use crate::security::{SleepTier, KEY_SIZE};

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
#[expect(clippy::struct_excessive_bools, reason = "radio enable/disable states are inherently boolean")]
pub struct ModePolicy {
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
}

impl fmt::Display for ModeTransitionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PinRequired => write!(f, "PIN required to exit Sentinel mode"),
            Self::PinMismatch => write!(f, "PIN does not match"),
            Self::PanicIsTerminal => write!(f, "cannot transition out of Panic mode"),
            Self::AbortWindowExpired => write!(f, "panic abort window has expired"),
            Self::AlreadyInMode => write!(f, "already in the requested mode"),
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
pub struct ModeManager {
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
    /// Stored PIN hash for Sentinel exit verification.
    /// In production this would be a SHA-256 hash; for now a simple
    /// fixed-size array suffices until Wave 3 wires the real PIN system.
    pin_hash: [u8; 32],
}

impl ModeManager {
    /// Create a new `ModeManager` starting in Daily mode.
    ///
    /// `pin_hash` is the SHA-256 hash of the user's PIN for Sentinel
    /// exit verification.
    #[must_use]
    pub const fn new(pin_hash: [u8; 32]) -> Self {
        Self {
            mode: SecurityMode::Daily,
            covert_lock: false,
            panic_initiated_tick: None,
            pre_panic_mode: SecurityMode::Daily,
            last_panic_event: None,
            pin_hash,
        }
    }

    /// Current security mode.
    pub fn mode(&self) -> SecurityMode {
        self.mode
    }

    /// Whether Covert Lock is active.
    #[must_use]
    pub fn covert_lock(&self) -> bool {
        self.covert_lock
    }

    /// The last emitted panic event, if any.
    #[must_use]
    pub fn last_panic_event(&self) -> Option<PanicEvent> {
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
    pub fn enter_sentinel(
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
    /// Requires PIN confirmation. The provided `pin` is hashed with SHA-256
    /// and compared against the stored hash.
    ///
    /// # Errors
    ///
    /// Returns [`ModeTransitionError::PinRequired`] if `pin` is empty.
    /// Returns [`ModeTransitionError::PinMismatch`] if the PIN is wrong.
    /// Returns [`ModeTransitionError::PanicIsTerminal`] if in Panic.
    /// Returns [`ModeTransitionError::AlreadyInMode`] if already in Daily.
    pub fn exit_sentinel(
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

        // Verify PIN by comparing SHA-256 hash.
        let pin_hash = crate::security::sha256(pin);
        if !constant_time_eq(&pin_hash, &self.pin_hash) {
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
    pub fn activate_panic(
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
    /// Returns [`ModeTransitionError::AlreadyInMode`] if not in Panic.
    pub fn abort_panic(
        &mut self,
        current_tick: u64,
        power_manager: &mut PowerManager,
    ) -> Result<(), ModeTransitionError> {
        if self.mode != SecurityMode::Panic {
            return Err(ModeTransitionError::AlreadyInMode);
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
    pub fn toggle_covert_lock(&mut self, power_manager: &mut PowerManager) {
        self.covert_lock = !self.covert_lock;
        self.apply_radio_policy(power_manager);
    }

    /// Set Covert Lock to a specific state.
    pub fn set_covert_lock(&mut self, active: bool, power_manager: &mut PowerManager) {
        if self.covert_lock != active {
            self.covert_lock = active;
            self.apply_radio_policy(power_manager);
        }
    }

    // -----------------------------------------------------------------------
    // Policy
    // -----------------------------------------------------------------------

    /// Return the effective policy, accounting for both mode and Covert Lock.
    pub fn effective_policy(&self) -> ModePolicy {
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
    fn apply_radio_policy(&self, pm: &mut PowerManager) {
        let policy = self.effective_policy();

        let cell_state = if policy.cellular_enabled { PowerState::On } else { PowerState::Off };
        let wifi_state = if policy.wifi_enabled { PowerState::On } else { PowerState::Off };
        let bt_state = if policy.bluetooth_enabled { PowerState::On } else { PowerState::Off };
        let gps_state = if policy.gps_enabled { PowerState::On } else { PowerState::Off };

        pm.set_state(Radio::Cellular, cell_state);
        pm.set_state(Radio::Wifi, wifi_state);
        pm.set_state(Radio::Bluetooth, bt_state);
        pm.set_state(Radio::Gps, gps_state);
        // FM is always off in security modes (not a security-relevant radio).
        pm.set_state(Radio::Fm, PowerState::Off);
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
    pub fn status_badge(&self) -> &'static str {
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
    pub fn status_badge_color(&self) -> u16 {
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
    pub fn mode_char(&self) -> char {
        match self.mode {
            SecurityMode::Daily => 'D',
            SecurityMode::Sentinel => 'S',
            SecurityMode::Panic => 'P',
        }
    }
}

impl Default for ModeManager {
    fn default() -> Self {
        Self::new([0u8; 32])
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
pub fn log_mode_change(
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
    let _ = audit_log.log_event(
        AuditEventType::ModeChange,
        0,
        &detail[..offset],
        timestamp,
        audit_key,
    );
}

/// Log a panic trigger event to the audit log.
///
/// Records the activation method as a `PanicTrigger` event.
pub fn log_panic_trigger(
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
    let _ = audit_log.log_event(
        AuditEventType::PanicTrigger,
        0,
        detail,
        timestamp,
        audit_key,
    );
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

/// Constant-time byte array comparison to prevent timing side-channels
/// on PIN verification.
fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: compute SHA-256 hash of a test PIN.
    fn test_pin_hash(pin: &[u8]) -> [u8; 32] {
        crate::security::sha256(pin)
    }

    /// Helper: create a ModeManager with a known test PIN.
    fn test_manager() -> ModeManager {
        ModeManager::new(test_pin_hash(b"123456"))
    }

    /// Helper: create a KeyManager with loaded keys for testing.
    fn test_key_manager_with_keys() -> KeyManager {
        let mut km = KeyManager::new();
        let master = {
            let mut key_bytes = [0u8; 32];
            crate::security::pbkdf2_sha256(b"test", b"salt", 1, &mut key_bytes)
                .expect("pbkdf2 failed");
            crate::key_manager::SecureKey::new(key_bytes)
        };
        km.derive_partition_keys(&master)
            .expect("derive_partition_keys failed");
        km
    }

    // -----------------------------------------------------------------------
    // Mode starts Daily
    // -----------------------------------------------------------------------

    #[test]
    fn mode_starts_daily() {
        let mm = test_manager();
        assert_eq!(mm.mode(), SecurityMode::Daily);
        assert!(!mm.covert_lock());
        assert!(mm.last_panic_event().is_none());
    }

    // -----------------------------------------------------------------------
    // Daily -> Sentinel
    // -----------------------------------------------------------------------

    #[test]
    fn transition_daily_to_sentinel() {
        let mut mm = test_manager();
        let mut km = test_key_manager_with_keys();
        let mut pm = PowerManager::new();
        pm.apply_mode(crate::power::PowerMode::Full);

        mm.enter_sentinel(&mut km, &mut pm).expect("enter_sentinel failed");

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
        let mut mm = test_manager();
        let mut km = test_key_manager_with_keys();
        let mut pm = PowerManager::new();

        mm.enter_sentinel(&mut km, &mut pm).expect("enter_sentinel failed");

        // Empty PIN should fail.
        let result = mm.exit_sentinel(b"", &mut pm);
        assert_eq!(result, Err(ModeTransitionError::PinRequired));

        // Wrong PIN should fail.
        let result = mm.exit_sentinel(b"000000", &mut pm);
        assert_eq!(result, Err(ModeTransitionError::PinMismatch));

        // Correct PIN should succeed.
        mm.exit_sentinel(b"123456", &mut pm).expect("exit_sentinel failed");
        assert_eq!(mm.mode(), SecurityMode::Daily);
    }

    // -----------------------------------------------------------------------
    // Panic triggers key zeroize
    // -----------------------------------------------------------------------

    #[test]
    fn panic_triggers_key_zeroize() {
        let mut mm = test_manager();
        let mut km = test_key_manager_with_keys();
        let mut pm = PowerManager::new();
        pm.apply_mode(crate::power::PowerMode::Full);

        assert!(km.has_keys(), "keys must be loaded before panic");

        let event = mm.activate_panic(1000, PanicActivation::KeyCombo, &mut km, &mut pm)
            .expect("activate_panic failed");

        assert_eq!(mm.mode(), SecurityMode::Panic);
        assert!(!km.has_keys(), "keys must be zeroized after panic");
        assert!(event.keys_zeroized);
        assert_eq!(event.triggered_at, 1000);

        // All radios must be off.
        assert_eq!(pm.state(Radio::Cellular), PowerState::Off);
        assert_eq!(pm.state(Radio::Wifi), PowerState::Off);
        assert_eq!(pm.state(Radio::Bluetooth), PowerState::Off);
        assert_eq!(pm.state(Radio::Gps), PowerState::Off);
    }

    // -----------------------------------------------------------------------
    // Panic abort within window
    // -----------------------------------------------------------------------

    #[test]
    fn panic_abort_within_window() {
        let mut mm = test_manager();
        let mut km = test_key_manager_with_keys();
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
        let mut mm = test_manager();
        let mut km = test_key_manager_with_keys();
        let mut pm = PowerManager::new();

        mm.activate_panic(1000, PanicActivation::DuressPin, &mut km, &mut pm)
            .expect("activate_panic failed");

        // Try to abort at tick 3000 (2000 ticks later, exceeds 1500-tick window).
        let result = mm.abort_panic(3000, &mut pm);
        assert_eq!(result, Err(ModeTransitionError::AbortWindowExpired));
        assert_eq!(mm.mode(), SecurityMode::Panic);
    }

    // -----------------------------------------------------------------------
    // Covert Lock toggles RF
    // -----------------------------------------------------------------------

    #[test]
    fn covert_lock_toggles_rf() {
        let mut mm = test_manager();
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

        // Deactivate Covert Lock — Daily mode restores all radios.
        mm.toggle_covert_lock(&mut pm);

        assert!(!mm.covert_lock());
        assert_eq!(pm.state(Radio::Cellular), PowerState::On);
        assert_eq!(pm.state(Radio::Wifi), PowerState::On);
        assert_eq!(pm.state(Radio::Bluetooth), PowerState::On);
        assert_eq!(pm.state(Radio::Gps), PowerState::On);
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
        let mut mm = test_manager();
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
        let mm = test_manager();
        assert_eq!(mm.status_badge(), "DAILY");
    }

    #[test]
    fn status_badge_sentinel() {
        let mut mm = test_manager();
        let mut km = KeyManager::new();
        let mut pm = PowerManager::new();
        mm.enter_sentinel(&mut km, &mut pm).expect("enter_sentinel failed");
        assert_eq!(mm.status_badge(), "SENTL");
    }

    #[test]
    fn status_badge_panic() {
        let mut mm = test_manager();
        let mut km = KeyManager::new();
        let mut pm = PowerManager::new();
        mm.activate_panic(0, PanicActivation::KeyCombo, &mut km, &mut pm)
            .expect("activate_panic failed");
        assert_eq!(mm.status_badge(), "PANIC");
    }

    #[test]
    fn status_badge_covert_overrides_daily() {
        let mut mm = test_manager();
        let mut pm = PowerManager::new();
        mm.toggle_covert_lock(&mut pm);
        assert_eq!(mm.status_badge(), "COVRT");
    }

    #[test]
    fn status_badge_covert_does_not_override_panic() {
        let mut mm = test_manager();
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
        let mut mm = test_manager();
        assert_eq!(mm.mode_char(), 'D');

        let mut km = KeyManager::new();
        let mut pm = PowerManager::new();
        mm.enter_sentinel(&mut km, &mut pm).expect("enter_sentinel failed");
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
        let mut mm = test_manager();
        let mut km = KeyManager::new();
        let mut pm = PowerManager::new();

        mm.enter_sentinel(&mut km, &mut pm).expect("first entry");
        let result = mm.enter_sentinel(&mut km, &mut pm);
        assert_eq!(result, Err(ModeTransitionError::AlreadyInMode));
    }

    #[test]
    fn sentinel_from_panic_fails() {
        let mut mm = test_manager();
        let mut km = KeyManager::new();
        let mut pm = PowerManager::new();

        mm.activate_panic(0, PanicActivation::KeyCombo, &mut km, &mut pm)
            .expect("activate_panic failed");

        let result = mm.enter_sentinel(&mut km, &mut pm);
        assert_eq!(result, Err(ModeTransitionError::PanicIsTerminal));
    }

    #[test]
    fn exit_sentinel_from_daily_fails() {
        let mut mm = test_manager();
        let mut pm = PowerManager::new();

        let result = mm.exit_sentinel(b"123456", &mut pm);
        assert_eq!(result, Err(ModeTransitionError::AlreadyInMode));
    }

    #[test]
    fn double_panic_fails() {
        let mut mm = test_manager();
        let mut km = KeyManager::new();
        let mut pm = PowerManager::new();

        mm.activate_panic(0, PanicActivation::KeyCombo, &mut km, &mut pm)
            .expect("first panic");

        let result = mm.activate_panic(100, PanicActivation::DuressPin, &mut km, &mut pm);
        assert_eq!(result, Err(ModeTransitionError::AlreadyInMode));
    }

    #[test]
    fn abort_from_non_panic_fails() {
        let mut mm = test_manager();
        let mut pm = PowerManager::new();

        let result = mm.abort_panic(0, &mut pm);
        assert_eq!(result, Err(ModeTransitionError::AlreadyInMode));
    }

    #[test]
    fn panic_abort_restores_sentinel_if_panic_from_sentinel() {
        let mut mm = test_manager();
        let mut km = test_key_manager_with_keys();
        let mut pm = PowerManager::new();

        mm.enter_sentinel(&mut km, &mut pm).expect("enter_sentinel failed");
        assert_eq!(mm.mode(), SecurityMode::Sentinel);

        mm.activate_panic(1000, PanicActivation::KeyCombo, &mut km, &mut pm)
            .expect("activate_panic failed");

        mm.abort_panic(1100, &mut pm).expect("abort_panic failed");
        assert_eq!(mm.mode(), SecurityMode::Sentinel,
            "abort must restore pre-panic mode (Sentinel)");
    }

    // -----------------------------------------------------------------------
    // Display implementations
    // -----------------------------------------------------------------------

    #[test]
    fn display_impls_produce_output() {
        let mm = test_manager();
        let s = alloc::format!("{mm}");
        assert!(s.contains("Daily"), "Display must show mode");
        assert!(s.contains("covert=false"), "Display must show covert state");

        let mode_s = alloc::format!("{}", SecurityMode::Sentinel);
        assert_eq!(mode_s, "Sentinel");

        let policy_s = alloc::format!("{}", base_policy(SecurityMode::Daily));
        assert!(policy_s.contains("cell=true"));

        let event = PanicEvent { triggered_at: 42, keys_zeroized: true };
        let event_s = alloc::format!("{event}");
        assert!(event_s.contains("42"));

        let err_s = alloc::format!("{}", ModeTransitionError::PinRequired);
        assert!(err_s.contains("PIN"));

        let act_s = alloc::format!("{}", PanicActivation::KeyCombo);
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
}
