//! Lock screen with passphrase, PIN unlock, and duress detection.
//!
//! Implements three authentication modes:
//! - **Boot passphrase**: full passphrase required on first boot and after
//!   long sleep. Derives master key via [`KeyManager::derive_from_passphrase`].
//! - **PIN unlock**: 6-digit PIN for short-sleep re-entry (keys still in memory).
//! - **Duress PIN**: a secondary PIN whose entry silently triggers panic mode
//!   with identical visual feedback to a successful unlock (no tell).
//!
//! Security features:
//! - Dot-masked input (characters are never displayed)
//! - Adaptive throttling: delays escalate from 0s to 1h over 10 attempts
//! - After 5 wrong attempts: force long-sleep (zeroize session keys)
//! - After 10 wrong attempts: trigger full wipe
//! - Constant-time hash comparison for both PIN and passphrase
//! - Tiered sleep: PIN allowed under 5 min since lock, passphrase otherwise
//!
//! Implements the [`Screen`] trait from `ui.rs` for rendering the passphrase
//! and PIN entry UI on the 240x320 display.

extern crate alloc;

use core::fmt;

use subtle::ConstantTimeEq;

use crate::audit::{AuditEventType, AuditLog};
use crate::key_manager::KeyManager;
use crate::security::{self, KEY_SIZE, SHA256_DIGEST_LEN};
use crate::ui::{
    self, CHAR_HEIGHT, CHAR_WIDTH, CONTENT_HEIGHT, Key, SCREEN_WIDTH, Screen, ScreenAction, color,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum passphrase length in bytes.
const MAX_PASSPHRASE_LEN: usize = 64;

/// Maximum PIN length in digits.
const MAX_PIN_LEN: usize = 10;

/// Required PIN length for validation.
const REQUIRED_PIN_LEN: u8 = 6;

/// Number of wrong attempts before forcing long-sleep (key zeroization).
const FORCE_LONG_SLEEP_THRESHOLD: u32 = 5;

/// Number of wrong attempts before triggering a full wipe.
const WIPE_THRESHOLD: u32 = 10;

/// Duration in ticks below which PIN unlock is allowed (5 minutes).
/// Assumes 1 tick = 1 second for the kernel's monotonic clock.
const SHORT_SLEEP_TICKS: u64 = 300;

/// Y offset for the header text.
const HEADER_Y: u16 = 30;

/// Y offset for the dot-masked input display.
const INPUT_Y: u16 = 80;

/// Y offset for the status/error message.
const STATUS_Y: u16 = 130;

/// Dot character used to mask input.
const DOT_CHAR: char = '\u{002A}'; // asterisk as dot substitute in bitmap font

/// Width of each dot in the masked display.
const DOT_WIDTH: u16 = CHAR_WIDTH * 2;

// ---------------------------------------------------------------------------
// Lock mode
// ---------------------------------------------------------------------------

/// Authentication mode for the lock screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LockMode {
    /// First boot — full passphrase required to derive master key.
    BootPassphrase,
    /// Short sleep — PIN-only unlock (keys still in memory).
    PinUnlock,
    /// Long sleep or sentinel mode — full passphrase required.
    Locked,
}

impl fmt::Display for LockMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BootPassphrase => write!(f, "Boot Passphrase"),
            Self::PinUnlock => write!(f, "PIN Unlock"),
            Self::Locked => write!(f, "Locked (passphrase required)"),
        }
    }
}

// ---------------------------------------------------------------------------
// Unlock result
// ---------------------------------------------------------------------------

/// Outcome of an authentication attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
#[non_exhaustive]
pub enum UnlockResult {
    /// Authentication succeeded.
    Success,
    /// Wrong passphrase entered.
    WrongPassphrase,
    /// Wrong PIN entered.
    WrongPin,
    /// Duress PIN detected — triggers silent panic (identical visual to success).
    DuressDetected,
    /// Currently throttled — must wait before next attempt.
    Throttled {
        /// Seconds remaining before next attempt is allowed.
        wait_secs: u32,
    },
    /// Ten wrong attempts — triggers full wipe.
    WipeTrigger,
}

impl fmt::Display for UnlockResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Success => write!(f, "Unlock successful"),
            Self::WrongPassphrase => write!(f, "Wrong passphrase"),
            Self::WrongPin => write!(f, "Wrong PIN"),
            Self::DuressDetected => write!(f, "Duress detected"),
            Self::Throttled { wait_secs } => write!(f, "Throttled ({wait_secs}s remaining)"),
            Self::WipeTrigger => write!(f, "Wipe triggered"),
        }
    }
}

// ---------------------------------------------------------------------------
// Constant-time comparison
// ---------------------------------------------------------------------------

/// Constant-time byte-slice comparison.
///
/// Compares all bytes regardless of early differences, preventing timing
/// side-channel attacks. Returns `true` only when both slices have equal
/// length and identical content.
///
/// WHY: backed by `subtle::ConstantTimeEq`, which inserts optimization barriers
/// the compiler cannot elide — a hand-rolled XOR loop can be defeated by an
/// optimizing backend. The lock screen is the duress/coercion surface, so a
/// timing oracle on PIN/passphrase hashes must not exist.
#[must_use]
pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    // Slice `ct_eq` returns Choice(0) on a length mismatch (lengths here are
    // fixed 32-byte SHA-256 digests, so length is not secret).
    a.ct_eq(b).unwrap_u8() == 1
}

// ---------------------------------------------------------------------------
// Throttle delay
// ---------------------------------------------------------------------------

/// Compute the throttle delay in seconds for the given attempt count.
///
/// Delay escalation:
/// - 0-2 attempts: no delay
/// - 3-4: 5 seconds
/// - 5-6: 30 seconds
/// - 7-8: 5 minutes (300s)
/// - 9: 1 hour (3600s)
/// - 10+: wipe trigger (`u32::MAX` sentinel)
#[must_use]
pub(crate) const fn throttle_delay(attempts: u32) -> u32 {
    match attempts {
        0..=2 => 0,
        3..=4 => 5,
        5..=6 => 30,
        7..=8 => 300,
        9 => 3600,
        _ => u32::MAX,
    }
}

// ---------------------------------------------------------------------------
// Lock screen
// ---------------------------------------------------------------------------

/// Lock screen state for passphrase and PIN authentication.
///
/// Manages input buffers, attempt counting, throttling, and duress detection.
/// The screen renders a dot-masked input field and handles numpad/OK/End keys.
pub(crate) struct LockScreen {
    // kanon:ignore RUST/struct-too-many-fields -- cohesive auth state machine; splitting would scatter throttle/attempt/duress tracking across types
    /// Current authentication mode.
    mode: LockMode,
    /// PIN input buffer (digit bytes, e.g., b'0'..b'9').
    pin_buffer: [u8; MAX_PIN_LEN],
    /// Number of PIN digits entered.
    pin_len: u8,
    /// Passphrase input buffer (raw bytes).
    passphrase_buffer: [u8; MAX_PASSPHRASE_LEN],
    /// Number of passphrase bytes entered.
    passphrase_len: u8,
    /// Cumulative wrong attempt count (resets on success).
    attempts: u32,
    /// Monotonic tick of the last failed attempt.
    last_attempt_tick: u64,
    /// Tick until which input is throttled (no attempts accepted).
    throttle_until_tick: u64,
    /// The current monotonic tick, as last reported by [`Self::advance_tick`].
    /// `on_key` forwards this to `submit_pin`/`submit_passphrase` instead of
    /// a hardcoded value, so throttle deadlines actually advance (#388).
    current_tick: u64,
    /// SHA-256 hash of the real PIN (set during provisioning).
    pin_hash: [u8; SHA256_DIGEST_LEN],
    /// SHA-256 hash of the duress PIN (checked before real PIN).
    duress_pin_hash: [u8; SHA256_DIGEST_LEN],
    /// SHA-256 hash of the passphrase (for verification).
    passphrase_hash: [u8; SHA256_DIGEST_LEN],
    /// Tick when the device was last locked (for tiered sleep).
    locked_at_tick: u64,
    /// Last result for display feedback.
    last_result: Option<UnlockResult>,
    /// Whether long-sleep was forced (after 5 wrong attempts).
    long_sleep_forced: bool,
}

impl LockScreen {
    /// Create a new lock screen in boot passphrase mode.
    ///
    /// Stored hashes are for the real PIN, duress PIN, and passphrase.
    /// These would be provisioned during device setup and persisted in
    /// secure storage.
    #[must_use]
    pub(crate) fn new(
        pin_hash: [u8; SHA256_DIGEST_LEN],
        duress_pin_hash: [u8; SHA256_DIGEST_LEN],
        passphrase_hash: [u8; SHA256_DIGEST_LEN],
    ) -> Self {
        Self {
            mode: LockMode::BootPassphrase,
            pin_buffer: [0u8; MAX_PIN_LEN],
            pin_len: 0,
            passphrase_buffer: [0u8; MAX_PASSPHRASE_LEN],
            passphrase_len: 0,
            attempts: 0,
            last_attempt_tick: 0,
            throttle_until_tick: 0,
            current_tick: 0,
            pin_hash,
            duress_pin_hash,
            passphrase_hash,
            locked_at_tick: 0,
            last_result: None,
            long_sleep_forced: false,
        }
    }

    /// Create a lock screen for testing with pre-set hashes derived from
    /// known PIN/passphrase values.
    #[cfg(test)]
    pub fn new_for_test(pin: &[u8], duress_pin: &[u8], passphrase: &[u8]) -> Self {
        Self::new(
            security::sha256(pin),
            security::sha256(duress_pin),
            security::sha256(passphrase),
        )
    }

    /// Current authentication mode.
    #[must_use]
    pub fn mode(&self) -> LockMode {
        self.mode
    }

    /// Number of failed attempts since last success.
    #[must_use]
    pub fn attempts(&self) -> u32 {
        self.attempts
    }

    /// Whether long-sleep was forced by exceeding the attempt threshold.
    #[must_use]
    pub fn long_sleep_forced(&self) -> bool {
        self.long_sleep_forced
    }

    /// Set the mode (used by tiered sleep logic).
    pub fn set_mode(&mut self, mode: LockMode) {
        self.mode = mode;
    }

    /// Record the tick when the device was locked, for tiered sleep.
    pub fn set_locked_at(&mut self, tick: u64) {
        self.locked_at_tick = tick;
    }

    /// Advance the lock screen's notion of "now" to `tick`.
    ///
    /// The event loop must call this (or otherwise keep it current) before
    /// dispatching key events, so `on_key` can pass a real monotonic tick
    /// to `submit_pin`/`submit_passphrase` instead of a frozen constant.
    /// Without this, the throttle deadline computed in `on_failure` never
    /// advances relative to what `on_key` checks against, and after 3
    /// failures every later attempt — including the correct PIN — is
    /// rejected as throttled forever, and the 10-attempt wipe threshold is
    /// never reached (#388).
    pub fn advance_tick(&mut self, tick: u64) {
        self.current_tick = tick;
    }

    /// Determine the lock mode based on elapsed time since lock.
    ///
    /// - Under 5 minutes: PIN unlock
    /// - Over 5 minutes: full passphrase required
    pub fn update_mode_for_sleep(&mut self, current_tick: u64) {
        let elapsed = current_tick.saturating_sub(self.locked_at_tick);
        if elapsed <= SHORT_SLEEP_TICKS {
            self.mode = LockMode::PinUnlock;
        } else {
            self.mode = LockMode::Locked;
        }
    }

    /// Clear the PIN input buffer. Zeroizes content to prevent leakage.
    pub fn clear_pin(&mut self) {
        for byte in &mut self.pin_buffer {
            // SAFETY: write_volatile prevents dead-store elimination of
            // the zeroization — same pattern as SecureKey.
            #[expect(
                unsafe_code,
                reason = "write_volatile for secure zeroization of PIN buffer"
            )]
            unsafe {
                core::ptr::write_volatile(byte, 0);
            }
        }
        self.pin_len = 0;
    }

    /// Clear the passphrase input buffer. Zeroizes content to prevent leakage.
    pub fn clear_passphrase(&mut self) {
        for byte in &mut self.passphrase_buffer {
            #[expect(
                unsafe_code,
                reason = "write_volatile for secure zeroization of passphrase buffer"
            )]
            unsafe {
                core::ptr::write_volatile(byte, 0);
            }
        }
        self.passphrase_len = 0;
    }

    /// Clear all input buffers.
    pub fn clear_input(&mut self) {
        self.clear_pin();
        self.clear_passphrase();
    }

    /// Number of PIN digits currently entered.
    #[must_use]
    pub fn pin_len(&self) -> u8 {
        self.pin_len
    }

    /// Number of passphrase bytes currently entered.
    #[must_use]
    pub fn passphrase_len(&self) -> u8 {
        self.passphrase_len
    }

    /// Check whether we are currently throttled.
    #[must_use]
    fn is_throttled(&self, current_tick: u64) -> bool {
        current_tick < self.throttle_until_tick
    }

    /// Remaining throttle wait in seconds.
    #[must_use]
    fn throttle_remaining(&self, current_tick: u64) -> u32 {
        if current_tick >= self.throttle_until_tick {
            0
        } else {
            // Ticks are seconds, cap at u32::MAX.
            let remaining = self.throttle_until_tick.saturating_sub(current_tick);
            if remaining > u64::from(u32::MAX) {
                u32::MAX
            } else {
                remaining as u32
            }
        }
    }

    /// Submit the current passphrase for verification.
    ///
    /// Returns the unlock result. On success, resets attempt counters.
    /// On failure, increments attempts and applies throttling.
    ///
    /// The caller is responsible for calling `KeyManager::derive_from_passphrase`
    /// on success — this method only verifies the hash.
    pub fn submit_passphrase(&mut self, current_tick: u64) -> UnlockResult {
        // Check throttle.
        if self.is_throttled(current_tick) {
            let wait = self.throttle_remaining(current_tick);
            // WHY clear here: mirrors submit_pin — the throttled early
            // return is the only submit exit that would otherwise leave the
            // entered buffer in place, letting it accumulate across
            // throttled attempts so the correct passphrase can never
            // re-match after the window elapses (#388). Keeps throttle
            // recoverable and keeps all submit exits consistent.
            self.clear_input();
            return UnlockResult::Throttled { wait_secs: wait };
        }

        // Hash the entered passphrase and compare (constant-time).
        let entered = &self.passphrase_buffer[..self.passphrase_len as usize];
        let hash = security::sha256(entered);

        if constant_time_eq(&hash, &self.passphrase_hash) {
            self.on_success(UnlockResult::Success);
            UnlockResult::Success
        } else {
            self.on_failure(current_tick)
        }
    }

    /// Submit the current PIN for verification.
    ///
    /// Checks duress PIN first (constant-time), then real PIN (constant-time).
    /// Duress match returns `DuressDetected` with no visual tell.
    pub fn submit_pin(&mut self, current_tick: u64) -> UnlockResult {
        // Check throttle.
        if self.is_throttled(current_tick) {
            let wait = self.throttle_remaining(current_tick);
            // WHY clear here: this is the only submit exit that does not
            // otherwise clear the buffer (on_failure/on_success both do). A
            // throttled OK-press that left its digits in place would append
            // to the next entry, so after the throttle window elapsed the
            // buffer would exceed REQUIRED_PIN_LEN and the correct PIN could
            // never re-match — the same "locked out after throttle" failure
            // class #388 targets. Clearing keeps the throttle recoverable.
            self.clear_input();
            return UnlockResult::Throttled { wait_secs: wait };
        }

        // Require exactly REQUIRED_PIN_LEN digits.
        if self.pin_len != REQUIRED_PIN_LEN {
            return UnlockResult::WrongPin;
        }

        let entered = &self.pin_buffer[..self.pin_len as usize];
        let hash = security::sha256(entered);

        // WHY: check duress FIRST (constant-time). Both checks always run
        // to prevent timing side-channel from revealing which hash matched.
        let is_duress = constant_time_eq(&hash, &self.duress_pin_hash);
        let is_real = constant_time_eq(&hash, &self.pin_hash);

        if is_duress {
            // Duress detected — visual feedback is identical to success.
            // Caller triggers panic after a 2-second delay with no tell.
            // last_result records DuressDetected so the signal is not lost.
            self.on_success(UnlockResult::DuressDetected);
            UnlockResult::DuressDetected
        } else if is_real {
            self.on_success(UnlockResult::Success);
            UnlockResult::Success
        } else {
            self.on_failure(current_tick)
        }
    }

    /// Handle a successful authentication.
    ///
    /// WHY `result` param: the duress path and the real-unlock path both funnel
    /// here, but a caller must be able to tell them apart. Recording the actual
    /// `result` keeps `last_result` faithful — duress stays visually identical
    /// to success in `draw()` (both render "UNLOCKED"), yet the field carries
    /// the duress signal to the privileged panic dispatch instead of being
    /// clobbered to `Success`.
    fn on_success(&mut self, result: UnlockResult) {
        self.attempts = 0;
        self.last_attempt_tick = 0;
        self.throttle_until_tick = 0;
        self.last_result = Some(result);
        self.long_sleep_forced = false;
        self.clear_input();
    }

    /// Handle a failed authentication attempt.
    ///
    /// Increments the attempt counter, applies throttle delay, and checks
    /// for wipe/long-sleep thresholds.
    fn on_failure(&mut self, current_tick: u64) -> UnlockResult {
        self.attempts += 1;
        self.last_attempt_tick = current_tick;

        // Apply throttle.
        let delay = throttle_delay(self.attempts);
        if delay == u32::MAX {
            self.last_result = Some(UnlockResult::WipeTrigger);
            self.clear_input();
            return UnlockResult::WipeTrigger;
        }
        self.throttle_until_tick = current_tick.saturating_add(u64::from(delay));

        // WHY: read the escalation-decision value (self.mode) BEFORE
        // mutating it below. This attempt was entered under the CURRENT
        // mode, so it must be reported (and audit-logged by
        // log_auth_event) as WrongPin/WrongPassphrase matching what was
        // actually typed -- not relabeled just because this same
        // failure also escalates the mode for the NEXT attempt.
        // Computing `result` after the mode flip caused the 5th failed
        // PIN to report WrongPassphrase (and audit-log "wrong
        // passphrase") even though a PIN was entered.
        let result = match self.mode {
            LockMode::PinUnlock => UnlockResult::WrongPin,
            LockMode::BootPassphrase | LockMode::Locked => UnlockResult::WrongPassphrase,
        };

        // After 5 wrong: force long-sleep (zeroize session keys) for the
        // NEXT attempt. Does not change how THIS attempt is reported.
        if self.attempts >= FORCE_LONG_SLEEP_THRESHOLD {
            self.long_sleep_forced = true;
            self.mode = LockMode::Locked;
        }

        self.last_result = Some(result);
        self.clear_input();
        result
    }

    /// Force transition to long-sleep mode and zeroize keys.
    ///
    /// Called when the attempt threshold is reached. The caller should
    /// also call `key_manager.zeroize_all()`.
    pub fn force_long_sleep(&mut self, key_manager: &mut KeyManager) {
        self.mode = LockMode::Locked;
        self.long_sleep_forced = true;
        key_manager.zeroize_all();
    }

    /// Push a digit into the PIN buffer.
    fn push_pin_digit(&mut self, digit: u8) {
        if self.pin_len < MAX_PIN_LEN as u8 {
            self.pin_buffer[self.pin_len as usize] = digit;
            self.pin_len += 1;
        }
    }

    /// Push a byte into the passphrase buffer.
    ///
    /// For T9-style input, the caller maps key sequences to characters.
    /// For simplicity, numeric keys append their digit character directly.
    fn push_passphrase_byte(&mut self, byte: u8) {
        if self.passphrase_len < MAX_PASSPHRASE_LEN as u8 {
            self.passphrase_buffer[self.passphrase_len as usize] = byte;
            self.passphrase_len += 1;
        }
    }

    /// Map a Key to a digit byte (b'0'..b'9').
    const fn key_to_digit(key: Key) -> Option<u8> {
        match key {
            Key::Num0 => Some(b'0'),
            Key::Num1 => Some(b'1'),
            Key::Num2 => Some(b'2'),
            Key::Num3 => Some(b'3'),
            Key::Num4 => Some(b'4'),
            Key::Num5 => Some(b'5'),
            Key::Num6 => Some(b'6'),
            Key::Num7 => Some(b'7'),
            Key::Num8 => Some(b'8'),
            Key::Num9 => Some(b'9'),
            _ => None,
        }
    }

    /// Render dot-masked input for the current buffer length.
    fn draw_dots(fb: &mut [u16], count: u8) {
        let total_width = u16::from(count) * DOT_WIDTH;
        let x_start = SCREEN_WIDTH.saturating_sub(total_width) / 2;

        for i in 0..count {
            let x = x_start + u16::from(i) * DOT_WIDTH;
            ui::draw_char_scaled(
                fb,
                SCREEN_WIDTH,
                x,
                INPUT_Y,
                DOT_CHAR,
                color::WHITE,
                color::BLACK,
                2,
            );
        }
    }

    /// Header text for the current mode.
    fn header_text(&self) -> &'static str {
        match self.mode {
            LockMode::PinUnlock => "ENTER PIN",
            LockMode::BootPassphrase | LockMode::Locked => "ENTER PASSPHRASE",
        }
    }

    /// Input length for the current mode.
    fn current_input_len(&self) -> u8 {
        match self.mode {
            LockMode::PinUnlock => self.pin_len,
            LockMode::BootPassphrase | LockMode::Locked => self.passphrase_len,
        }
    }
}

impl Screen for LockScreen {
    fn draw(&self, fb: &mut [u16]) {
        let w = SCREEN_WIDTH;
        let h = CONTENT_HEIGHT;

        // Clear content area.
        ui::fill_rect(fb, w, h, 0, 0, w, h, color::BLACK);

        // Header.
        ui::draw_str_centered(
            fb,
            w,
            0,
            w,
            HEADER_Y,
            self.header_text(),
            color::WHITE,
            color::BLACK,
        );

        // Dot-masked input.
        let input_len = self.current_input_len();
        if input_len > 0 {
            Self::draw_dots(fb, input_len);
        } else {
            // Placeholder.
            let hint = match self.mode {
                LockMode::PinUnlock => "6 digits",
                LockMode::BootPassphrase | LockMode::Locked => "Type passphrase",
            };
            ui::draw_str_centered(
                fb,
                w,
                0,
                w,
                INPUT_Y + CHAR_HEIGHT / 2,
                hint,
                color::DARK_GREY,
                color::BLACK,
            );
        }

        // Status/error message.
        if let Some(ref result) = self.last_result {
            let (msg, msg_color) = match result {
                UnlockResult::Success | UnlockResult::DuressDetected => ("UNLOCKED", color::GREEN),
                UnlockResult::WrongPassphrase | UnlockResult::WrongPin => {
                    ("WRONG - TRY AGAIN", color::RED)
                }
                UnlockResult::Throttled { .. } => ("WAIT...", color::YELLOW),
                UnlockResult::WipeTrigger => ("WIPING DEVICE", color::RED),
            };
            ui::draw_str_centered(fb, w, 0, w, STATUS_Y, msg, msg_color, color::BLACK);
        }

        // Attempt counter (show after first failure).
        if self.attempts > 0 {
            // Format attempt count as "Attempts: N".
            let mut attempt_buf = [0u8; 16];
            let attempt_str = format_attempts(self.attempts, &mut attempt_buf);
            if let Ok(s) = core::str::from_utf8(attempt_str) {
                ui::draw_str_centered(
                    fb,
                    w,
                    0,
                    w,
                    STATUS_Y + CHAR_HEIGHT + 4,
                    s,
                    color::DARK_GREY,
                    color::BLACK,
                );
            }
        }
    }

    fn on_key(&mut self, key: Key) -> ScreenAction {
        match self.mode {
            LockMode::PinUnlock => {
                // Digit keys: append to PIN.
                if let Some(digit) = Self::key_to_digit(key) {
                    self.push_pin_digit(digit);
                    return ScreenAction::None;
                }
                match key {
                    Key::Ok | Key::Rsk => {
                        // Submit PIN. Duress must reach the caller on a distinct
                        // channel: last_result records DuressDetected (visually
                        // identical to Success in draw()), and a DuressDetected
                        // result surfaces ScreenAction::Duress so the privileged
                        // event loop can start the silent panic sequence. A real
                        // unlock stays ScreenAction::None (caller reads
                        // last_result == Success for normal dispatch).
                        match self.submit_pin(self.current_tick) {
                            UnlockResult::DuressDetected => ScreenAction::Duress,
                            _ => ScreenAction::None,
                        }
                    }
                    Key::End => {
                        self.clear_pin();
                        ScreenAction::None
                    }
                    Key::Left => {
                        // Backspace.
                        if self.pin_len > 0 {
                            self.pin_len -= 1;
                        }
                        ScreenAction::None
                    }
                    _ => ScreenAction::None,
                }
            }
            LockMode::BootPassphrase | LockMode::Locked => {
                // Digit keys: append to passphrase as T9 numeric.
                if let Some(digit) = Self::key_to_digit(key) {
                    self.push_passphrase_byte(digit);
                    return ScreenAction::None;
                }
                match key {
                    Key::Ok | Key::Rsk => {
                        let _ = self.submit_passphrase(self.current_tick);
                        ScreenAction::None
                    }
                    Key::End => {
                        self.clear_passphrase();
                        ScreenAction::None
                    }
                    Key::Left => {
                        // Backspace.
                        if self.passphrase_len > 0 {
                            self.passphrase_len -= 1;
                        }
                        ScreenAction::None
                    }
                    Key::Star => {
                        // Star appends '*' to passphrase (T9 symbol entry).
                        self.push_passphrase_byte(b'*');
                        ScreenAction::None
                    }
                    Key::Hash => {
                        // Hash appends '#' to passphrase.
                        self.push_passphrase_byte(b'#');
                        ScreenAction::None
                    }
                    _ => ScreenAction::None,
                }
            }
        }
    }

    fn softkey_left(&self) -> &'static str {
        ""
    }

    fn softkey_right(&self) -> &'static str {
        "OK"
    }

    fn title(&self) -> &'static str {
        "LOCK"
    }
}

impl fmt::Debug for LockScreen {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // WHY: input buffers and hashes intentionally omitted to prevent leakage.
        f.debug_struct("LockScreen")
            .field("mode", &self.mode)
            .field("pin_len", &self.pin_len)
            .field("passphrase_len", &self.passphrase_len)
            .field("attempts", &self.attempts)
            .field("long_sleep_forced", &self.long_sleep_forced)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for LockScreen {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "LockScreen(mode={}, attempts={})",
            self.mode, self.attempts,
        )
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Log an authentication event to the audit log.
///
/// Called after [`LockScreen::submit_passphrase`] or
/// [`LockScreen::submit_pin`] to record the outcome. The caller
/// provides the audit log, HMAC key, and current timestamp.
///
/// Events logged:
/// - [`UnlockResult::WrongPassphrase`] / [`UnlockResult::WrongPin`] -> `AuthFail`
/// - [`UnlockResult::DuressDetected`] -> `DuressAttempt`
pub fn log_auth_event(
    result: UnlockResult,
    audit_log: &mut AuditLog,
    audit_key: &[u8; KEY_SIZE],
    timestamp: u64,
) {
    match result {
        UnlockResult::WrongPassphrase => {
            let _ = audit_log.log_event(
                AuditEventType::AuthFail,
                0,
                b"wrong passphrase",
                timestamp,
                audit_key,
            );
        }
        UnlockResult::WrongPin => {
            let _ = audit_log.log_event(
                AuditEventType::AuthFail,
                0,
                b"wrong PIN",
                timestamp,
                audit_key,
            );
        }
        UnlockResult::DuressDetected => {
            let _ = audit_log.log_event(
                AuditEventType::DuressAttempt,
                0,
                b"duress PIN entered",
                timestamp,
                audit_key,
            );
        }
        // Success, Throttled, and WipeTrigger are not audit-logged here.
        _ => {}
    }
}

/// Format an attempt count into a byte buffer as "Attempts: N".
///
/// Returns the formatted slice. Handles values up to 999.
fn format_attempts(n: u32, buf: &mut [u8; 16]) -> &[u8] {
    let prefix = b"Attempts: ";
    let plen = prefix.len();
    buf[..plen].copy_from_slice(prefix);

    if n == 0 {
        buf[plen] = b'0';
        return &buf[..=plen];
    }

    // Format the number (up to 3 digits for our use case).
    let mut digits = [0u8; 4];
    let mut val = n;
    let mut count = 0;
    while val > 0 && count < 4 {
        digits[count] = b'0' + (val % 10) as u8;
        val /= 10;
        count += 1;
    }

    // Reverse digits into buffer.
    for i in 0..count {
        buf[plen + i] = digits[count - 1 - i];
    }

    &buf[..plen + count]
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::CONTENT_HEIGHT;

    const TEST_PIN: &[u8] = b"123456";
    const TEST_DURESS_PIN: &[u8] = b"654321";
    const TEST_PASSPHRASE: &[u8] = b"correct horse battery staple";

    fn make_screen() -> LockScreen {
        LockScreen::new_for_test(TEST_PIN, TEST_DURESS_PIN, TEST_PASSPHRASE)
    }

    #[test]
    fn boot_passphrase_starts_in_passphrase_mode() {
        let screen = make_screen();
        assert_eq!(
            screen.mode(),
            LockMode::BootPassphrase,
            "new lock screen must start in BootPassphrase mode"
        );
    }

    #[test]
    fn correct_passphrase_returns_success() {
        let mut screen = make_screen();
        // Enter the correct passphrase.
        for &byte in TEST_PASSPHRASE {
            screen.push_passphrase_byte(byte);
        }
        let result = screen.submit_passphrase(100);
        assert_eq!(result, UnlockResult::Success);
        assert_eq!(screen.attempts(), 0, "attempts must reset on success");
    }

    #[test]
    fn wrong_passphrase_returns_wrong() {
        let mut screen = make_screen();
        for &byte in b"wrong passphrase entirely" {
            screen.push_passphrase_byte(byte);
        }
        let result = screen.submit_passphrase(100);
        assert_eq!(result, UnlockResult::WrongPassphrase);
        assert_eq!(screen.attempts(), 1);
    }

    #[test]
    fn pin_entry_accepts_6_digits() {
        let mut screen = make_screen();
        screen.set_mode(LockMode::PinUnlock);

        // Enter the correct PIN digits.
        for &byte in TEST_PIN {
            screen.push_pin_digit(byte);
        }
        assert_eq!(screen.pin_len(), 6);

        let result = screen.submit_pin(100);
        assert_eq!(result, UnlockResult::Success);
    }

    #[test]
    fn duress_pin_returns_duress_detected() {
        let mut screen = make_screen();
        screen.set_mode(LockMode::PinUnlock);

        // Enter the duress PIN.
        for &byte in TEST_DURESS_PIN {
            screen.push_pin_digit(byte);
        }
        let result = screen.submit_pin(100);
        assert_eq!(
            result,
            UnlockResult::DuressDetected,
            "duress PIN must return DuressDetected"
        );
    }

    /// Map a decimal digit byte to its keypad key (inverse of key_to_digit).
    fn digit_key(byte: u8) -> Key {
        match byte {
            b'0' => Key::Num0,
            b'1' => Key::Num1,
            b'2' => Key::Num2,
            b'3' => Key::Num3,
            b'4' => Key::Num4,
            b'5' => Key::Num5,
            b'6' => Key::Num6,
            b'7' => Key::Num7,
            b'8' => Key::Num8,
            _ => Key::Num9,
        }
    }

    #[test]
    fn duress_via_on_key_is_distinguishable_from_real_unlock() {
        // Drive the duress PIN through on_key key events (not submit_pin
        // directly) and confirm the duress signal survives on both observable
        // channels — the ScreenAction return and the last_result field.
        let mut duress_screen = make_screen();
        duress_screen.set_mode(LockMode::PinUnlock);
        for &byte in TEST_DURESS_PIN {
            duress_screen.on_key(digit_key(byte));
        }
        let duress_action = duress_screen.on_key(Key::Ok);

        // A real unlock for comparison, driven the same way.
        let mut real_screen = make_screen();
        real_screen.set_mode(LockMode::PinUnlock);
        for &byte in TEST_PIN {
            real_screen.on_key(digit_key(byte));
        }
        let real_action = real_screen.on_key(Key::Ok);

        // last_result must differ; the fix fails if on_success() clobbers the
        // duress result to Success.
        assert_eq!(
            duress_screen.last_result,
            Some(UnlockResult::DuressDetected),
            "duress via on_key must record DuressDetected in last_result"
        );
        assert_eq!(real_screen.last_result, Some(UnlockResult::Success));
        assert_ne!(duress_screen.last_result, real_screen.last_result);

        // The ScreenAction channel also carries duress, distinct from a normal
        // unlock which stays ScreenAction::None.
        assert!(
            matches!(duress_action, ScreenAction::Duress),
            "duress via on_key must surface ScreenAction::Duress"
        );
        assert!(matches!(real_action, ScreenAction::None));
    }

    #[test]
    fn wrong_pin_via_on_key_reports_wrong_pin_not_success_or_duress() {
        // Security-critical: drive a WRONG (neither real nor duress) PIN
        // through the actual UI key-dispatch path (on_key), not
        // submit_pin directly, and confirm both observable channels
        // report failure -- not success and not a duress false-positive
        // (#397).
        let mut screen = make_screen();
        screen.set_mode(LockMode::PinUnlock);

        for &byte in b"000000" {
            screen.on_key(digit_key(byte));
        }
        let action = screen.on_key(Key::Ok);

        assert_eq!(
            screen.last_result,
            Some(UnlockResult::WrongPin),
            "a wrong (non-duress) PIN entered via on_key must record WrongPin"
        );
        assert!(
            matches!(action, ScreenAction::None),
            "a wrong PIN must not surface ScreenAction::Duress or any \
             navigation action"
        );
        assert_eq!(screen.attempts(), 1);
    }

    #[test]
    fn on_key_forwards_a_real_tick_so_unlock_recovers_after_throttle() {
        // Regression test for #388: on_key previously called
        // submit_pin(0)/submit_passphrase(0) unconditionally. Since
        // is_throttled compares against a frozen tick of 0, once 3
        // failures set throttle_until_tick = 5, EVERY later on_key call
        // (still passing 0) hit the throttled early-return in submit_pin
        // forever — the correct PIN could never be entered again. Driving
        // real, advancing ticks via advance_tick() and confirming the
        // correct PIN eventually succeeds through on_key proves the tick
        // is no longer frozen at 0.
        let mut screen = make_screen();
        screen.set_mode(LockMode::PinUnlock);

        for i in 0..3u64 {
            screen.advance_tick(100 + i);
            for &byte in b"999999" {
                screen.on_key(digit_key(byte));
            }
            screen.on_key(Key::Ok);
        }
        assert_eq!(screen.attempts(), 3, "3 wrong attempts must be recorded");

        // Immediately retrying (tick barely advanced past the 3rd failure
        // at tick 102, throttle_until_tick = 107) must still be throttled —
        // attempts must not grow further while throttled.
        screen.advance_tick(103);
        for &byte in TEST_PIN {
            screen.on_key(digit_key(byte));
        }
        screen.on_key(Key::Ok);
        assert_eq!(
            screen.attempts(),
            3,
            "an attempt inside the throttle window must be rejected before \
             ever checking the PIN, leaving the attempt count unchanged"
        );

        // Advance past the 5-second throttle (3 failures -> 5s delay) and
        // retry with the correct PIN: this must now succeed, proving the
        // throttle clock is fed a real, advancing tick rather than a
        // frozen 0.
        screen.advance_tick(200);
        for &byte in TEST_PIN {
            screen.on_key(digit_key(byte));
        }
        screen.on_key(Key::Ok);
        assert_eq!(
            screen.last_result,
            Some(UnlockResult::Success),
            "the correct PIN must be accepted once the throttle window has \
             elapsed, proving on_key no longer freezes the throttle clock at 0"
        );
        assert_eq!(screen.attempts(), 0, "attempts must reset on success");
    }

    #[test]
    fn throttle_delay_increases_with_attempts() {
        assert_eq!(throttle_delay(0), 0);
        assert_eq!(throttle_delay(1), 0);
        assert_eq!(throttle_delay(2), 0);
        assert_eq!(throttle_delay(3), 5);
        assert_eq!(throttle_delay(4), 5);
        assert_eq!(throttle_delay(5), 30);
        assert_eq!(throttle_delay(6), 30);
        assert_eq!(throttle_delay(7), 300);
        assert_eq!(throttle_delay(8), 300);
        assert_eq!(throttle_delay(9), 3600);
        assert_eq!(
            throttle_delay(10),
            u32::MAX,
            "10+ must trigger wipe sentinel"
        );
        assert_eq!(throttle_delay(100), u32::MAX);
    }

    #[test]
    fn five_wrong_forces_long_sleep() {
        let mut screen = make_screen();
        screen.set_mode(LockMode::PinUnlock);

        for i in 0..5 {
            // Enter a wrong PIN each time.
            for &byte in b"999999" {
                screen.push_pin_digit(byte);
            }
            let result = screen.submit_pin(100 + (i as u64) * 100);
            assert_ne!(
                result,
                UnlockResult::WipeTrigger,
                "should not wipe before 10 attempts"
            );
        }

        assert!(
            screen.long_sleep_forced(),
            "5 wrong attempts must force long-sleep"
        );
        assert_eq!(
            screen.mode(),
            LockMode::Locked,
            "mode must transition to Locked after 5 wrong"
        );
    }

    #[test]
    fn fifth_wrong_pin_reports_wrong_pin_not_wrong_passphrase() {
        let mut screen = make_screen();
        screen.set_mode(LockMode::PinUnlock);

        let mut result = UnlockResult::Success;
        for i in 0..5 {
            for &byte in b"999999" {
                screen.push_pin_digit(byte);
            }
            result = screen.submit_pin(100 + (i as u64) * 100);
        }

        assert_eq!(
            result,
            UnlockResult::WrongPin,
            "the 5th failed PIN attempt must report WrongPin, matching \
             what was actually entered -- the mode escalation to Locked \
             (for the NEXT attempt) must not retroactively relabel this \
             attempt's result as WrongPassphrase"
        );
        assert_eq!(
            screen.mode(),
            LockMode::Locked,
            "mode must still escalate to Locked after the 5th failure"
        );
    }

    #[test]
    fn ten_wrong_triggers_wipe() {
        let mut screen = make_screen();

        for i in 0..10 {
            for &byte in b"wrong passphrase" {
                screen.push_passphrase_byte(byte);
            }
            let result = screen.submit_passphrase(1000 + (i as u64) * 10000);

            if i < 9 {
                assert_ne!(
                    result,
                    UnlockResult::WipeTrigger,
                    "should not wipe before 10 attempts (attempt {})",
                    i + 1,
                );
            } else {
                assert_eq!(
                    result,
                    UnlockResult::WipeTrigger,
                    "10th wrong attempt must trigger wipe"
                );
            }
        }
    }

    #[test]
    fn dot_masking_hides_input() {
        let screen = make_screen();

        // Allocate a framebuffer for the content area.
        let fb_size = SCREEN_WIDTH as usize * CONTENT_HEIGHT as usize;
        let mut fb = alloc::vec![0u16; fb_size];

        // Draw with empty input — should not show dots.
        screen.draw(&mut fb);

        // Now enter some passphrase bytes and redraw.
        let mut screen2 = make_screen();
        for &byte in b"secret" {
            screen2.push_passphrase_byte(byte);
        }
        let mut fb2 = alloc::vec![0u16; fb_size];
        screen2.draw(&mut fb2);

        // The framebuffers should differ (dots rendered vs placeholder).
        assert_ne!(fb, fb2, "input dots must change the framebuffer");

        // Verify the passphrase length matches what we entered.
        assert_eq!(screen2.passphrase_len(), 6);

        // Verify no raw passphrase bytes appear in the draw output:
        // we check that the Screen's draw method only renders dots, not
        // the actual characters. The draw_dots method uses DOT_CHAR ('*')
        // for all positions regardless of input content.
        // This is verified by the fact that draw() only calls draw_dots()
        // with the count, never exposing the buffer contents.
    }

    #[test]
    fn clear_resets_buffer() {
        let mut screen = make_screen();

        // Fill both buffers.
        for &byte in b"passphrase" {
            screen.push_passphrase_byte(byte);
        }
        for &byte in b"123456" {
            screen.push_pin_digit(byte);
        }

        assert!(screen.passphrase_len() > 0);
        assert!(screen.pin_len() > 0);

        screen.clear_input();

        assert_eq!(screen.passphrase_len(), 0, "passphrase must be cleared");
        assert_eq!(screen.pin_len(), 0, "PIN must be cleared");
    }

    #[test]
    fn constant_time_eq_works() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"hello", b"hell"));
        assert!(!constant_time_eq(b"", b"x"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn throttle_prevents_rapid_attempts() {
        let mut screen = make_screen();

        // Use up 3 attempts to enter throttle territory.
        for i in 0..3 {
            for &byte in b"wrong" {
                screen.push_passphrase_byte(byte);
            }
            screen.submit_passphrase(100 + (i as u64) * 100);
        }

        // 4th attempt should now have a 5-second throttle.
        // Try immediately — should be throttled.
        for &byte in TEST_PASSPHRASE {
            screen.push_passphrase_byte(byte);
        }
        let result = screen.submit_passphrase(301);
        assert!(
            matches!(result, UnlockResult::Throttled { .. }),
            "should be throttled at tick 301 (throttle until 305)"
        );
    }

    #[test]
    fn tiered_sleep_mode_selection() {
        let mut screen = make_screen();

        // Lock at tick 1000, check at 1100 (100s < 300s threshold).
        screen.set_locked_at(1000);
        screen.update_mode_for_sleep(1100);
        assert_eq!(
            screen.mode(),
            LockMode::PinUnlock,
            "under 5 min should use PIN"
        );

        // Check at 1400 (400s > 300s threshold).
        screen.update_mode_for_sleep(1400);
        assert_eq!(
            screen.mode(),
            LockMode::Locked,
            "over 5 min should require passphrase"
        );
    }

    #[test]
    fn format_attempts_output() {
        let mut buf = [0u8; 16];
        let s = format_attempts(3, &mut buf);
        assert_eq!(s, b"Attempts: 3");

        let s = format_attempts(10, &mut buf);
        assert_eq!(s, b"Attempts: 10");

        let s = format_attempts(0, &mut buf);
        assert_eq!(s, b"Attempts: 0");
    }

    #[test]
    fn screen_trait_softkeys() {
        let screen = make_screen();
        assert_eq!(screen.softkey_left(), "");
        assert_eq!(screen.softkey_right(), "OK");
        assert_eq!(screen.title(), "LOCK");
    }

    #[test]
    fn display_and_debug_dont_leak_secrets() {
        let screen = make_screen();
        let display = alloc::format!("{screen}");
        let debug = alloc::format!("{screen:?}");

        // Neither should contain passphrase or PIN material.
        assert!(
            !display.contains("correct"),
            "Display must not leak passphrase"
        );
        assert!(!debug.contains("correct"), "Debug must not leak passphrase");
        assert!(!display.contains("123456"), "Display must not leak PIN");
        assert!(!debug.contains("123456"), "Debug must not leak PIN");
    }
}
