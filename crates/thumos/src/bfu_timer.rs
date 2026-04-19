//! Auto-reboot-to-BFU (Before First Unlock) timer.
//!
//! Tracks time since last successful unlock and triggers a reboot to
//! BFU state when the idle threshold expires. The threshold varies by
//! security mode:
//!
//! | Mode     | Threshold          | Rationale                          |
//! |----------|--------------------|------------------------------------|
//! | Daily    | 4 h (1 440 000 ms) | Normal use, generous idle window   |
//! | Sentinel | 30 min (1 800 000) | Heightened awareness, shorter fuse |
//! | Panic    | 0 (immediate)      | Emergency — instant BFU transition |
//!
//! ## Expiry sequence
//!
//! 1. Zeroize all partition keys via [`KeyManager::zeroize_all`].
//! 2. Flush filesystem (placeholder — actual `lfs` sync is wired in Wave 8).
//! 3. Reboot into BFU state (device comes up at passphrase prompt).
//!
//! The timer is reset on every successful unlock. It can also be paused
//! (e.g., during active user interaction) and resumed.

extern crate alloc;

use core::fmt;

use crate::key_manager::KeyManager;
use crate::security::SleepTier;
use crate::security_mode::SecurityMode;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// BFU timeout for Daily mode: 4 hours in milliseconds.
const DAILY_TIMEOUT_MS: u64 = 4 * 60 * 60 * 1_000;

/// BFU timeout for Sentinel mode: 30 minutes in milliseconds.
const SENTINEL_TIMEOUT_MS: u64 = 30 * 60 * 1_000;

/// BFU timeout for Panic mode: 0 (immediate).
const PANIC_TIMEOUT_MS: u64 = 0;

/// Tick period: 10 ms per kernel tick.
const TICK_PERIOD_MS: u64 = 10;

/// Daily threshold in ticks.
const DAILY_THRESHOLD_TICKS: u64 = DAILY_TIMEOUT_MS / TICK_PERIOD_MS;

/// Sentinel threshold in ticks.
const SENTINEL_THRESHOLD_TICKS: u64 = SENTINEL_TIMEOUT_MS / TICK_PERIOD_MS;

/// Panic threshold in ticks (0 = immediate).
const PANIC_THRESHOLD_TICKS: u64 = PANIC_TIMEOUT_MS / TICK_PERIOD_MS;

// ---------------------------------------------------------------------------
// BfuAction
// ---------------------------------------------------------------------------

/// Action the caller must take after a [`BfuTimer::tick`] call.
///
/// The timer itself does not perform I/O or reboot; it returns an action
/// that the caller (kinit loop) must execute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
#[non_exhaustive]
pub enum BfuAction {
    /// No action needed; timer is still running.
    None,
    /// Timer expired. Caller must:
    /// 1. Zeroize keys (already done by the timer).
    /// 2. Flush filesystem.
    /// 3. Reboot to BFU state.
    Reboot,
}

impl fmt::Display for BfuAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => write!(f, "no action"),
            Self::Reboot => write!(f, "reboot to BFU"),
        }
    }
}

// ---------------------------------------------------------------------------
// BfuTimerState
// ---------------------------------------------------------------------------

/// Internal state of the BFU timer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
#[non_exhaustive]
pub enum BfuTimerState {
    /// Timer is counting down.
    Running,
    /// Timer is paused (e.g., during active user interaction).
    Paused,
    /// Timer has expired and reboot is pending.
    Expired,
}

impl fmt::Display for BfuTimerState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Running => write!(f, "running"),
            Self::Paused => write!(f, "paused"),
            Self::Expired => write!(f, "expired"),
        }
    }
}

// ---------------------------------------------------------------------------
// BfuTimer
// ---------------------------------------------------------------------------

/// Tracks idle time since last unlock and triggers BFU reboot on expiry.
///
/// The timer is mode-aware: the threshold changes when the security mode
/// changes. Call [`BfuTimer::tick`] from the kernel main loop at 10 ms
/// intervals.
pub(crate) struct BfuTimer {
    /// Ticks elapsed since last unlock (or last reset).
    elapsed_ticks: u64,
    /// Current threshold in ticks (derived from security mode).
    threshold_ticks: u64,
    /// Current state.
    state: BfuTimerState,
    /// Current security mode (cached for threshold lookup).
    mode: SecurityMode,
    /// Whether the timer has already fired (prevents repeated reboot).
    fired: bool,
}

impl BfuTimer {
    /// Create a new BFU timer for the given security mode.
    ///
    /// The timer starts in [`BfuTimerState::Running`] with zero elapsed
    /// ticks.
    #[must_use]
    pub(crate) const fn new(mode: SecurityMode) -> Self {
        Self {
            elapsed_ticks: 0,
            threshold_ticks: threshold_for_mode(mode),
            state: BfuTimerState::Running,
            mode,
            fired: false,
        }
    }

    /// Advance the timer by one tick (10 ms).
    ///
    /// If the timer expires, zeroizes all keys via `key_manager` and
    /// returns [`BfuAction::Reboot`]. The caller is responsible for
    /// flushing the filesystem and issuing the actual reboot.
    ///
    /// Once fired, subsequent ticks return [`BfuAction::Reboot`] until
    /// the timer is reset.
    pub(crate) fn tick(&mut self, key_manager: &mut KeyManager) -> BfuAction {
        if self.fired {
            return BfuAction::Reboot;
        }

        if self.state != BfuTimerState::Running {
            return BfuAction::None;
        }

        self.elapsed_ticks = self.elapsed_ticks.saturating_add(1);

        if self.elapsed_ticks >= self.threshold_ticks {
            self.expire(key_manager)
        } else {
            BfuAction::None
        }
    }

    /// Reset the timer (e.g., after a successful unlock).
    ///
    /// Clears elapsed ticks, resets state to [`BfuTimerState::Running`],
    /// and clears the fired flag.
    pub(crate) fn reset(&mut self) {
        self.elapsed_ticks = 0;
        self.state = BfuTimerState::Running;
        self.fired = false;
    }

    /// Pause the timer. Ticks will not be counted while paused.
    pub(crate) fn pause(&mut self) {
        if self.state == BfuTimerState::Running {
            self.state = BfuTimerState::Paused;
        }
    }

    /// Resume the timer from a paused state.
    pub(crate) fn resume(&mut self) {
        if self.state == BfuTimerState::Paused {
            self.state = BfuTimerState::Running;
        }
    }

    /// Update the security mode, recalculating the threshold.
    ///
    /// If the new mode has a shorter threshold than the current elapsed
    /// time, the timer fires immediately on the next tick.
    pub(crate) fn set_mode(&mut self, mode: SecurityMode) {
        self.mode = mode;
        self.threshold_ticks = threshold_for_mode(mode);
    }

    /// Current timer state.
    pub(crate) fn state(&self) -> BfuTimerState {
        self.state
    }

    /// Elapsed ticks since last reset.
    #[must_use]
    pub(crate) fn elapsed_ticks(&self) -> u64 {
        self.elapsed_ticks
    }

    /// Current threshold in ticks.
    #[must_use]
    pub(crate) fn threshold_ticks(&self) -> u64 {
        self.threshold_ticks
    }

    /// Current security mode.
    pub(crate) fn mode(&self) -> SecurityMode {
        self.mode
    }

    /// Whether the timer has fired.
    #[must_use]
    pub(crate) fn has_fired(&self) -> bool {
        self.fired
    }

    /// Elapsed time in milliseconds.
    #[must_use]
    pub(crate) fn elapsed_ms(&self) -> u64 {
        self.elapsed_ticks.saturating_mul(TICK_PERIOD_MS)
    }

    /// Remaining time in milliseconds before expiry.
    ///
    /// Returns 0 if the timer has expired or the threshold is 0.
    #[must_use]
    pub(crate) fn remaining_ms(&self) -> u64 {
        if self.fired || self.elapsed_ticks >= self.threshold_ticks {
            return 0;
        }
        self.threshold_ticks
            .saturating_sub(self.elapsed_ticks)
            .saturating_mul(TICK_PERIOD_MS)
    }

    /// Threshold in milliseconds for the current mode.
    #[must_use]
    pub(crate) fn threshold_ms(&self) -> u64 {
        self.threshold_ticks.saturating_mul(TICK_PERIOD_MS)
    }

    // -----------------------------------------------------------------------
    // Internal
    // -----------------------------------------------------------------------

    /// Handle timer expiry: zeroize keys, mark as expired/fired.
    fn expire(&mut self, key_manager: &mut KeyManager) -> BfuAction {
        // Zeroize all partition keys — this is the critical security action.
        // Even if the reboot fails, the keys are gone from memory.
        key_manager.zeroize_all();

        // Force long-sleep tier so any subsequent unlock requires full
        // passphrase re-entry.
        key_manager.set_sleep_tier(SleepTier::Long);

        self.state = BfuTimerState::Expired;
        self.fired = true;
        BfuAction::Reboot
    }
}

impl Default for BfuTimer {
    fn default() -> Self {
        Self::new(SecurityMode::Daily)
    }
}

impl fmt::Debug for BfuTimer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BfuTimer")
            .field("elapsed_ticks", &self.elapsed_ticks)
            .field("threshold_ticks", &self.threshold_ticks)
            .field("state", &self.state)
            .field("mode", &self.mode)
            .field("fired", &self.fired)
            .finish()
    }
}

impl fmt::Display for BfuTimer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "BfuTimer(mode={}, state={}, elapsed={}ms, remaining={}ms)",
            self.mode,
            self.state,
            self.elapsed_ms(),
            self.remaining_ms(),
        )
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Return the BFU threshold in ticks for a given security mode.
const fn threshold_for_mode(mode: SecurityMode) -> u64 {
    match mode {
        SecurityMode::Daily => DAILY_THRESHOLD_TICKS,
        SecurityMode::Sentinel => SENTINEL_THRESHOLD_TICKS,
        SecurityMode::Panic => PANIC_THRESHOLD_TICKS,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create a `KeyManager` with loaded keys for testing.
    fn key_manager_with_derived_keys() -> KeyManager {
        let mut km = KeyManager::new();
        let primary = {
            let mut key_bytes = [0u8; 32];
            crate::security::pbkdf2_sha256(b"test-bfu", b"salt", 1, &mut key_bytes)
                .expect("pbkdf2 failed in test");
            crate::key_manager::SecureKey::new(key_bytes)
        };
        km.derive_partition_keys(&primary)
            .expect("derive_partition_keys failed");
        km
    }

    // -----------------------------------------------------------------------
    // Threshold values
    // -----------------------------------------------------------------------

    #[test]
    fn daily_threshold_is_4_hours() {
        let timer = BfuTimer::new(SecurityMode::Daily);
        assert_eq!(
            timer.threshold_ms(),
            4 * 60 * 60 * 1_000,
            "Daily threshold must be 4 hours"
        );
    }

    #[test]
    fn sentinel_threshold_is_30_minutes() {
        let timer = BfuTimer::new(SecurityMode::Sentinel);
        assert_eq!(
            timer.threshold_ms(),
            30 * 60 * 1_000,
            "Sentinel threshold must be 30 minutes"
        );
    }

    #[test]
    fn panic_threshold_is_immediate() {
        let timer = BfuTimer::new(SecurityMode::Panic);
        assert_eq!(
            timer.threshold_ticks(),
            0,
            "Panic threshold must be 0 (immediate)"
        );
    }

    // -----------------------------------------------------------------------
    // Timer fires at correct thresholds per mode
    // -----------------------------------------------------------------------

    #[test]
    fn daily_timer_fires_at_threshold() {
        let mut km = key_manager_with_derived_keys();
        let mut timer = BfuTimer::new(SecurityMode::Daily);

        // Tick to one before threshold — should not fire.
        for _ in 0..DAILY_THRESHOLD_TICKS.saturating_sub(1) {
            let action = timer.tick(&mut km);
            assert_eq!(action, BfuAction::None, "must not fire before threshold");
        }

        assert!(km.has_keys(), "keys must still be loaded before expiry");

        // One more tick pushes it to the threshold — should fire.
        let action = timer.tick(&mut km);
        assert_eq!(action, BfuAction::Reboot, "must fire at threshold");
        assert!(!km.has_keys(), "keys must be zeroized after expiry");
        assert!(timer.has_fired());
        assert_eq!(timer.state(), BfuTimerState::Expired);
    }

    #[test]
    fn sentinel_timer_fires_at_threshold() {
        let mut km = key_manager_with_derived_keys();
        let mut timer = BfuTimer::new(SecurityMode::Sentinel);

        for _ in 0..SENTINEL_THRESHOLD_TICKS.saturating_sub(1) {
            let action = timer.tick(&mut km);
            assert_eq!(action, BfuAction::None, "must not fire before threshold");
        }

        assert!(km.has_keys(), "keys must still be loaded before expiry");

        let action = timer.tick(&mut km);
        assert_eq!(action, BfuAction::Reboot, "must fire at Sentinel threshold");
        assert!(!km.has_keys(), "keys must be zeroized after expiry");
    }

    #[test]
    fn panic_timer_fires_immediately() {
        let mut km = key_manager_with_derived_keys();
        let mut timer = BfuTimer::new(SecurityMode::Panic);

        assert!(km.has_keys(), "keys must be loaded before panic tick");

        // Panic threshold is 0, so the very first tick fires.
        let action = timer.tick(&mut km);
        assert_eq!(action, BfuAction::Reboot, "Panic mode must fire on first tick");
        assert!(!km.has_keys(), "keys must be zeroized in Panic mode");
    }

    // -----------------------------------------------------------------------
    // Reset clears state
    // -----------------------------------------------------------------------

    #[test]
    fn reset_clears_timer() {
        let mut km = key_manager_with_derived_keys();
        let mut timer = BfuTimer::new(SecurityMode::Panic);

        // Fire the timer.
        let _ = timer.tick(&mut km);
        assert!(timer.has_fired());

        // Reset.
        timer.reset();
        assert!(!timer.has_fired());
        assert_eq!(timer.elapsed_ticks(), 0);
        assert_eq!(timer.state(), BfuTimerState::Running);
    }

    // -----------------------------------------------------------------------
    // Pause / resume
    // -----------------------------------------------------------------------

    #[test]
    fn pause_stops_counting() {
        let mut km = key_manager_with_derived_keys();
        let mut timer = BfuTimer::new(SecurityMode::Daily);

        // Tick a few times.
        for _ in 0..100 {
            timer.tick(&mut km);
        }
        assert_eq!(timer.elapsed_ticks(), 100);

        // Pause and tick more — elapsed should not increase.
        timer.pause();
        for _ in 0..50 {
            let action = timer.tick(&mut km);
            assert_eq!(action, BfuAction::None);
        }
        assert_eq!(timer.elapsed_ticks(), 100, "paused timer must not advance");

        // Resume and tick — should advance again.
        timer.resume();
        timer.tick(&mut km);
        assert_eq!(timer.elapsed_ticks(), 101);
    }

    // -----------------------------------------------------------------------
    // Mode change recalculates threshold
    // -----------------------------------------------------------------------

    #[test]
    fn mode_change_updates_threshold() {
        let mut timer = BfuTimer::new(SecurityMode::Daily);
        assert_eq!(timer.threshold_ticks(), DAILY_THRESHOLD_TICKS);

        timer.set_mode(SecurityMode::Sentinel);
        assert_eq!(timer.threshold_ticks(), SENTINEL_THRESHOLD_TICKS);

        timer.set_mode(SecurityMode::Panic);
        assert_eq!(timer.threshold_ticks(), PANIC_THRESHOLD_TICKS);
    }

    #[test]
    fn mode_change_to_shorter_fires_on_next_tick() {
        let mut km = key_manager_with_derived_keys();
        let mut timer = BfuTimer::new(SecurityMode::Daily);

        // Advance past Sentinel threshold but under Daily threshold.
        for _ in 0..SENTINEL_THRESHOLD_TICKS + 1 {
            timer.tick(&mut km);
        }
        assert!(km.has_keys(), "Daily threshold not reached yet");

        // Switch to Sentinel — elapsed exceeds new threshold.
        timer.set_mode(SecurityMode::Sentinel);

        let action = timer.tick(&mut km);
        assert_eq!(action, BfuAction::Reboot, "must fire after mode shortens threshold");
        assert!(!km.has_keys());
    }

    // -----------------------------------------------------------------------
    // Fired timer keeps returning Reboot
    // -----------------------------------------------------------------------

    #[test]
    fn fired_timer_keeps_returning_reboot() {
        let mut km = key_manager_with_derived_keys();
        let mut timer = BfuTimer::new(SecurityMode::Panic);

        let action = timer.tick(&mut km);
        assert_eq!(action, BfuAction::Reboot);

        // Subsequent ticks should still return Reboot.
        let action = timer.tick(&mut km);
        assert_eq!(action, BfuAction::Reboot, "fired timer must keep signaling reboot");
    }

    // -----------------------------------------------------------------------
    // Remaining time
    // -----------------------------------------------------------------------

    #[test]
    fn remaining_ms_decreases() {
        let mut km = key_manager_with_derived_keys();
        let mut timer = BfuTimer::new(SecurityMode::Daily);

        let initial = timer.remaining_ms();
        assert_eq!(initial, DAILY_TIMEOUT_MS);

        timer.tick(&mut km);
        let after_one = timer.remaining_ms();
        assert_eq!(after_one, DAILY_TIMEOUT_MS - TICK_PERIOD_MS);
    }

    #[test]
    fn remaining_ms_zero_after_expiry() {
        let mut km = key_manager_with_derived_keys();
        let mut timer = BfuTimer::new(SecurityMode::Panic);
        timer.tick(&mut km);
        assert_eq!(timer.remaining_ms(), 0);
    }

    // -----------------------------------------------------------------------
    // Default
    // -----------------------------------------------------------------------

    #[test]
    fn default_is_daily_mode() {
        let timer = BfuTimer::default();
        assert_eq!(timer.mode(), SecurityMode::Daily);
        assert_eq!(timer.state(), BfuTimerState::Running);
        assert_eq!(timer.elapsed_ticks(), 0);
    }

    // -----------------------------------------------------------------------
    // Display implementations
    // -----------------------------------------------------------------------

    #[test]
    fn display_impls_produce_output() {
        let timer = BfuTimer::new(SecurityMode::Daily);
        let s = alloc::format!("{timer}");
        assert!(s.contains("Daily"), "Display must show mode");
        assert!(s.contains("running"), "Display must show state");
        assert!(s.contains("elapsed=0ms"), "Display must show elapsed time");

        let action_s = BfuAction::Reboot.to_string();
        assert!(action_s.contains("reboot"), "BfuAction Display must describe action");

        let state_s = BfuTimerState::Expired.to_string();
        assert_eq!(state_s, "expired");
    }

    // -----------------------------------------------------------------------
    // Zeroize confirms sleep tier
    // -----------------------------------------------------------------------

    #[test]
    fn expiry_forces_long_sleep_tier() {
        let mut km = key_manager_with_derived_keys();
        assert_eq!(km.sleep_tier(), SleepTier::Short);

        let mut timer = BfuTimer::new(SecurityMode::Panic);
        timer.tick(&mut km);

        assert_eq!(
            km.sleep_tier(),
            SleepTier::Long,
            "BFU expiry must force long sleep tier"
        );
    }
}
