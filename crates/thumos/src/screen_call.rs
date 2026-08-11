//! Active call screen for the thumos kernel UI.
//!
//! Implements the [`Screen`] trait to display voice call state:
//! - **Outgoing**: shows "Dialing..." + number, then "Ringing...", then active
//! - **Incoming**: shows "INCOMING CALL" + caller number, LSK "ANSWER", RSK "DECLINE"
//! - **Active**: shows call duration timer counting up from connection time
//!
//! The call screen does not own the telephony state; it receives a snapshot
//! via [`CallScreenState`] to avoid holding references to kernel globals.
//!
//! ## Timer format
//!
//! The call duration is displayed as `MM:SS` (e.g., `01:05` for 65 seconds).
//! The kernel tick counter (milliseconds) is used to compute elapsed time.

// WHY: call screen created in Phase 07 Wave 3, kinit wiring pending.
#![expect(
    dead_code,
    reason = "Call screen created in Phase 07 Wave 3, kinit wiring pending (#737)"
)]

use crate::ui::{
    self, CHAR_HEIGHT, CONTENT_HEIGHT, Key, SCREEN_WIDTH, Screen, ScreenAction, color,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Y offset for the call state label ("Dialing...", "INCOMING CALL", etc.).
const STATE_LABEL_Y: u16 = 40;

/// Y offset for the phone number / caller name.
const NUMBER_Y: u16 = STATE_LABEL_Y + CHAR_HEIGHT + 16;

/// Y offset for the call duration timer.
const TIMER_Y: u16 = NUMBER_Y + CHAR_HEIGHT + 24;

/// Y offset for mute/speaker indicators.
const INDICATOR_Y: u16 = TIMER_Y + CHAR_HEIGHT * 2 + 8;

/// Maximum caller number display length.
const MAX_DISPLAY_NUMBER: usize = 20;

// ---------------------------------------------------------------------------
// Call screen state
// ---------------------------------------------------------------------------

/// Possible call phases for display purposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CallPhase {
    /// Outgoing call being dialed.
    Dialing,
    /// Remote end is ringing (outgoing).
    Ringing,
    /// Call is connected and active.
    Active,
    /// Incoming call ringing (inbound).
    Incoming,
}

impl CallPhase {
    /// Display label for the call phase.
    const fn label(self) -> &'static str {
        match self {
            Self::Dialing => "Dialing...",
            Self::Ringing => "Ringing...",
            Self::Active => "Connected",
            Self::Incoming => "INCOMING CALL",
        }
    }

    /// Color for the phase label.
    const fn label_color(self) -> u16 {
        match self {
            Self::Dialing | Self::Ringing => color::YELLOW,
            Self::Active => color::GREEN,
            Self::Incoming => color::RED,
        }
    }
}

/// Snapshot of call state for rendering.
///
/// Updated each render cycle from the telephony subsystem.
pub(crate) struct CallScreenState {
    /// Current call phase.
    pub phase: CallPhase,
    /// Caller/callee phone number (ASCII bytes).
    pub number: [u8; MAX_DISPLAY_NUMBER],
    /// Valid length of the number field.
    pub number_len: u8,
    /// Call start tick in milliseconds (for duration calculation).
    /// Only meaningful when `phase == Active`.
    pub start_tick: u64,
    /// Current kernel tick in milliseconds.
    pub current_tick: u64,
    /// Whether the microphone is muted.
    pub muted: bool,
    /// Whether the speaker is enabled.
    pub speaker: bool,
}

impl Default for CallScreenState {
    fn default() -> Self {
        Self {
            phase: CallPhase::Dialing,
            number: [0u8; MAX_DISPLAY_NUMBER],
            number_len: 0,
            start_tick: 0,
            current_tick: 0,
            muted: false,
            speaker: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Call duration formatting
// ---------------------------------------------------------------------------

/// Format a call duration in seconds as "MM:SS" (or "MMM:SS" once the
/// call passes 99 minutes).
///
/// Returns a fixed-size buffer and valid length: 5 for "MM:SS" (under
/// 100 minutes), 6 for "MMM:SS" (100-999 minutes). Minutes beyond 999
/// (16+ hours) saturate at 999 rather than wrap the display back to
/// "00:00" -- which previously made an in-progress long call look like
/// it had just connected.
pub(crate) fn format_duration(total_seconds: u64) -> ([u8; 8], usize) {
    let minutes = (total_seconds / 60).min(999);
    let seconds = total_seconds % 60;

    let mut buf = [0u8; 8];

    if minutes < 100 {
        buf[0] = b'0' + (minutes / 10) as u8;
        buf[1] = b'0' + (minutes % 10) as u8;
        buf[2] = b':';
        buf[3] = b'0' + (seconds / 10) as u8;
        buf[4] = b'0' + (seconds % 10) as u8;
        (buf, 5)
    } else {
        buf[0] = b'0' + (minutes / 100) as u8;
        buf[1] = b'0' + (minutes / 10 % 10) as u8;
        buf[2] = b'0' + (minutes % 10) as u8;
        buf[3] = b':';
        buf[4] = b'0' + (seconds / 10) as u8;
        buf[5] = b'0' + (seconds % 10) as u8;
        (buf, 6)
    }
}

// ---------------------------------------------------------------------------
// Call screen
// ---------------------------------------------------------------------------

/// Active call screen.
///
/// Displays call state, number, duration timer, and mute/speaker status.
/// Input handling varies by call phase:
/// - Incoming: LSK answers, RSK/End declines
/// - Active/Dialing/Ringing: End hangs up
pub(crate) struct CallScreen {
    /// Current state snapshot, updated before each render.
    pub state: CallScreenState,
}

/// Action specific to the call screen, returned alongside `ScreenAction`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CallAction {
    /// No call-specific action.
    None,
    /// Answer the incoming call.
    Answer,
    /// Hang up the current call.
    Hangup,
    /// Toggle mute state.
    ToggleMute,
    /// Toggle speaker state.
    ToggleSpeaker,
}

impl CallScreen {
    /// Create a new call screen with default state.
    pub(crate) fn new() -> Self {
        Self {
            state: CallScreenState::default(),
        }
    }

    /// Update the state snapshot. Called each render cycle.
    pub(crate) fn update_state(&mut self, state: CallScreenState) {
        self.state = state;
    }

    /// Return the number as a string slice.
    ///
    /// `number_len` is clamped to the buffer length before slicing — it is
    /// a public field the telephony driver populates directly from raw
    /// caller-ID data, with no compile-time guarantee it stays in bounds
    /// (#394).
    fn number_str(&self) -> &str {
        let len = (self.state.number_len as usize).min(self.state.number.len());
        core::str::from_utf8(&self.state.number[..len]).unwrap_or("")
    }

    /// Calculate the elapsed call duration in seconds.
    fn elapsed_seconds(&self) -> u64 {
        if self.state.phase != CallPhase::Active {
            return 0;
        }
        self.state
            .current_tick
            .saturating_sub(self.state.start_tick)
            / 1000
    }

    /// Handle input and return a call-specific action.
    ///
    /// The caller should inspect the returned `CallAction` to perform
    /// telephony operations (answer, hangup, mute, speaker).
    pub(crate) fn handle_key(&mut self, key: Key) -> CallAction {
        match self.state.phase {
            CallPhase::Incoming => match key {
                Key::Lsk | Key::Call => CallAction::Answer,
                Key::Rsk | Key::End => CallAction::Hangup,
                _ => CallAction::None,
            },
            CallPhase::Active => match key {
                Key::End => CallAction::Hangup,
                Key::Lsk => CallAction::ToggleMute,
                Key::Rsk => CallAction::ToggleSpeaker,
                _ => CallAction::None,
            },
            CallPhase::Dialing | CallPhase::Ringing => match key {
                Key::End => CallAction::Hangup,
                _ => CallAction::None,
            },
        }
    }
}

impl Screen for CallScreen {
    fn draw(&self, fb: &mut [u16]) {
        let w = SCREEN_WIDTH;
        let h = CONTENT_HEIGHT;

        // Clear content area to black.
        ui::fill_rect(fb, w, h, 0, 0, w, h, color::BLACK);

        // Call phase label.
        let label = self.state.phase.label();
        let label_color = self.state.phase.label_color();
        ui::draw_str_centered(fb, w, 0, w, STATE_LABEL_Y, label, label_color, color::BLACK);

        // Phone number.
        let number_str = self.number_str();
        if !number_str.is_empty() {
            ui::draw_str_centered(
                fb,
                w,
                0,
                w,
                NUMBER_Y,
                number_str,
                color::WHITE,
                color::BLACK,
            );
        }

        // Duration timer (only for active calls).
        if self.state.phase == CallPhase::Active {
            let elapsed = self.elapsed_seconds();
            let (timer_buf, timer_len) = format_duration(elapsed);
            let timer_str = core::str::from_utf8(&timer_buf[..timer_len]).unwrap_or("00:00");
            ui::draw_str_centered(fb, w, 0, w, TIMER_Y, timer_str, color::GREEN, color::BLACK);
        }

        // Mute/Speaker indicators (only for active calls).
        if self.state.phase == CallPhase::Active {
            let mute_str = if self.state.muted { "MUTED" } else { "" };
            let speaker_str = if self.state.speaker { "SPEAKER" } else { "" };

            if !mute_str.is_empty() {
                ui::draw_str(fb, w, 4, INDICATOR_Y, mute_str, color::RED, color::BLACK);
            }
            if !speaker_str.is_empty() {
                let sw = ui::str_pixel_width(speaker_str);
                let sx = w.saturating_sub(sw).saturating_sub(4);
                ui::draw_str(
                    fb,
                    w,
                    sx,
                    INDICATOR_Y,
                    speaker_str,
                    color::YELLOW,
                    color::BLACK,
                );
            }
        }
    }

    fn on_key(&mut self, key: Key) -> ScreenAction {
        let call_action = self.handle_key(key);
        match call_action {
            CallAction::Hangup => ScreenAction::Back,
            CallAction::Answer | CallAction::ToggleMute | CallAction::ToggleSpeaker => {
                // These are handled by the caller via `handle_key` return value;
                // the screen itself does not navigate.
                ScreenAction::None
            }
            CallAction::None => ScreenAction::None,
        }
    }

    fn softkey_left(&self) -> &'static str {
        match self.state.phase {
            CallPhase::Incoming => "ANSWER",
            CallPhase::Active => "MUTE",
            CallPhase::Dialing | CallPhase::Ringing => "",
        }
    }

    fn softkey_right(&self) -> &'static str {
        match self.state.phase {
            CallPhase::Incoming => "DECLINE",
            CallPhase::Active => "SPEAKER",
            CallPhase::Dialing | CallPhase::Ringing => "HANGUP",
        }
    }

    fn title(&self) -> &'static str {
        "Call"
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_incoming_screen() -> CallScreen {
        let mut screen = CallScreen::new();
        let mut number = [0u8; MAX_DISPLAY_NUMBER];
        let num_bytes = b"+15551234567";
        number[..num_bytes.len()].copy_from_slice(num_bytes);
        screen.update_state(CallScreenState {
            phase: CallPhase::Incoming,
            number,
            number_len: num_bytes.len() as u8,
            start_tick: 0,
            current_tick: 0,
            muted: false,
            speaker: false,
        });
        screen
    }

    fn make_active_screen(start: u64, current: u64) -> CallScreen {
        let mut screen = CallScreen::new();
        let mut number = [0u8; MAX_DISPLAY_NUMBER];
        let num_bytes = b"+15551234567";
        number[..num_bytes.len()].copy_from_slice(num_bytes);
        screen.update_state(CallScreenState {
            phase: CallPhase::Active,
            number,
            number_len: num_bytes.len() as u8,
            start_tick: start,
            current_tick: current,
            muted: false,
            speaker: false,
        });
        screen
    }

    #[test]
    fn incoming_call_shows_answer_decline() {
        let screen = make_incoming_screen();
        assert_eq!(
            screen.softkey_left(),
            "ANSWER",
            "incoming call LSK must be ANSWER"
        );
        assert_eq!(
            screen.softkey_right(),
            "DECLINE",
            "incoming call RSK must be DECLINE"
        );
    }

    #[test]
    fn active_call_shows_hangup() {
        let screen = make_active_screen(0, 5000);
        assert_eq!(
            screen.softkey_left(),
            "MUTE",
            "active call LSK must be MUTE"
        );
        assert_eq!(
            screen.softkey_right(),
            "SPEAKER",
            "active call RSK must be SPEAKER"
        );
    }

    #[test]
    fn end_key_returns_hangup_action() {
        let mut screen = make_active_screen(0, 5000);
        let action = screen.on_key(Key::End);
        assert_eq!(
            action,
            ScreenAction::Back,
            "End key on active call must return Back (hangup)"
        );

        let call_action = screen.handle_key(Key::End);
        assert_eq!(
            call_action,
            CallAction::Hangup,
            "End key must produce Hangup call action"
        );
    }

    #[test]
    fn timer_formats_correctly() {
        // 65 seconds -> "01:05"
        let (buf, len) = format_duration(65);
        let s = core::str::from_utf8(&buf[..len]).unwrap_or("");
        assert_eq!(s, "01:05", "65 seconds must format as 01:05");

        // 0 seconds -> "00:00"
        let (buf, len) = format_duration(0);
        let s = core::str::from_utf8(&buf[..len]).unwrap_or("");
        assert_eq!(s, "00:00", "0 seconds must format as 00:00");

        // 3661 seconds -> "61:01" (minutes mod 100, no hour display)
        let (buf, len) = format_duration(3661);
        let s = core::str::from_utf8(&buf[..len]).unwrap_or("");
        assert_eq!(
            s, "61:01",
            "3661 seconds must format as 61:01 (61 min, 1 sec)"
        );

        // 59 seconds -> "00:59"
        let (buf, len) = format_duration(59);
        let s = core::str::from_utf8(&buf[..len]).unwrap_or("");
        assert_eq!(s, "00:59", "59 seconds must format as 00:59");
    }

    #[test]
    fn timer_past_99_minutes_grows_instead_of_wrapping() {
        // 6000 seconds = 100 minutes exactly -- must NOT wrap to "00:00".
        let (buf, len) = format_duration(6000);
        let s = core::str::from_utf8(&buf[..len]).unwrap_or("");
        assert_eq!(s, "100:00", "100 minutes must not wrap to 00:00");

        // One second before the wrap point: still 2-digit minutes.
        let (buf, len) = format_duration(5999);
        let s = core::str::from_utf8(&buf[..len]).unwrap_or("");
        assert_eq!(s, "99:59", "5999 seconds is 99:59, the last 2-digit value");

        // Absurdly long call: must saturate, not overflow the buffer.
        let (buf, len) = format_duration(3_600_030);
        let s = core::str::from_utf8(&buf[..len]).unwrap_or("");
        assert_eq!(
            s, "999:30",
            "duration must saturate at 999 minutes, never overflow the \
             display buffer"
        );
    }

    #[test]
    fn incoming_lsk_answers() {
        let mut screen = make_incoming_screen();
        let action = screen.handle_key(Key::Lsk);
        assert_eq!(
            action,
            CallAction::Answer,
            "LSK on incoming call must answer"
        );
    }

    #[test]
    fn incoming_end_declines() {
        let mut screen = make_incoming_screen();
        let action = screen.handle_key(Key::End);
        assert_eq!(
            action,
            CallAction::Hangup,
            "End on incoming call must decline (hangup)"
        );
    }

    #[test]
    fn active_lsk_toggles_mute() {
        let mut screen = make_active_screen(0, 5000);
        let action = screen.handle_key(Key::Lsk);
        assert_eq!(
            action,
            CallAction::ToggleMute,
            "LSK on active call must toggle mute"
        );
    }

    #[test]
    fn active_rsk_toggles_speaker() {
        let mut screen = make_active_screen(0, 5000);
        let action = screen.handle_key(Key::Rsk);
        assert_eq!(
            action,
            CallAction::ToggleSpeaker,
            "RSK on active call must toggle speaker"
        );
    }

    #[test]
    fn elapsed_seconds_calculates_correctly() {
        let screen = make_active_screen(10_000, 75_000);
        assert_eq!(
            screen.elapsed_seconds(),
            65,
            "75000 - 10000 = 65000ms = 65s"
        );
    }

    #[test]
    fn elapsed_seconds_zero_when_not_active() {
        let screen = make_incoming_screen();
        assert_eq!(
            screen.elapsed_seconds(),
            0,
            "elapsed must be 0 when not in Active phase"
        );
    }

    #[test]
    fn dialing_end_key_hangs_up() {
        let mut screen = CallScreen::new();
        screen.update_state(CallScreenState {
            phase: CallPhase::Dialing,
            ..CallScreenState::default()
        });
        let action = screen.handle_key(Key::End);
        assert_eq!(
            action,
            CallAction::Hangup,
            "End key while dialing must hangup"
        );
    }

    #[test]
    fn draw_does_not_panic() {
        let screen = make_active_screen(0, 5000);
        let mut fb = alloc::vec![0u16; SCREEN_WIDTH as usize * CONTENT_HEIGHT as usize];
        screen.draw(&mut fb);
        let any_set = fb.iter().any(|&px| px != 0);
        assert!(any_set, "active call screen must render visible content");
    }

    #[test]
    fn draw_does_not_panic_on_oversized_number_len() {
        let mut screen = make_incoming_screen();
        // Driver/attacker-controlled caller-ID length exceeding the 20-byte
        // buffer (#394) — number_str() must clamp instead of panicking.
        screen.state.number_len = 255;

        let mut fb = alloc::vec![0u16; SCREEN_WIDTH as usize * CONTENT_HEIGHT as usize];
        screen.draw(&mut fb);
        assert!(
            fb.iter().any(|&px| px != 0),
            "screen must still render after clamping an oversized number_len"
        );
    }

    #[test]
    fn incoming_call_key_answers() {
        let mut screen = make_incoming_screen();
        let action = screen.handle_key(Key::Call);
        assert_eq!(
            action,
            CallAction::Answer,
            "Call key on incoming must answer"
        );
    }

    #[test]
    fn incoming_rsk_declines() {
        let mut screen = make_incoming_screen();
        let action = screen.handle_key(Key::Rsk);
        assert_eq!(
            action,
            CallAction::Hangup,
            "RSK on incoming call must decline (hangup)"
        );
    }
}
