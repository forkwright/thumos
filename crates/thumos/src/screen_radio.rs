//! Radio control panel for the thumos kernel UI.
//!
//! Displays per-radio ON/OFF status for all wireless subsystems
//! (cellular, `WiFi`, Bluetooth, GPS) and provides quick-action
//! presets for privacy-oriented operation:
//!
//! - **COVERT LOCK**: all radios off (full RF silence)
//! - **STEALTH**: cellular off, `WiFi` + BT on (local-only connectivity)
//! - **RESTORE**: all radios on (normal operation)
//!
//! The screen does not directly control hardware; it sets a desired
//! [`RadioState`] that the kernel radio manager applies. This
//! separation keeps the UI decoupled from driver initialization
//! sequences and error handling.

// WHY: radio control screen created in Phase 07 Wave 6, kinit wiring pending.
// cfg_attr(not(test), ...): the module's own tests now exercise its full
// surface, so nothing is dead in the test build -- expecting dead_code there
// makes the expectation unfulfilled. Production reachability is unchanged;
// the expectation is scoped to the build where it is still real.
#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "Radio control screen created in Phase 07 Wave 6, kinit wiring pending (#145)"
    )
)]

use crate::ui::{
    self, CHAR_HEIGHT, CHAR_WIDTH, CONTENT_HEIGHT, Key, SCREEN_WIDTH, Screen, ScreenAction, color,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Left padding for radio labels and status.
const PADDING_X: u16 = 12;

/// Y offset for the first radio row.
const RADIO_START_Y: u16 = 16;

/// Height of each radio row.
const ROW_HEIGHT: u16 = CHAR_HEIGHT + 10;

/// Y offset for the preset indicator.
const PRESET_Y: u16 = RADIO_START_Y + ROW_HEIGHT * 4 + 16;

/// X offset for ON/OFF status text (right-aligned area).
const STATUS_X: u16 = SCREEN_WIDTH - PADDING_X - 3 * CHAR_WIDTH;

/// Number of preset modes.
const PRESET_COUNT: usize = 3;

// ---------------------------------------------------------------------------
// Radio state
// ---------------------------------------------------------------------------

/// Aggregate state of all wireless radios.
///
/// Each field represents the desired power state of a radio subsystem.
/// `true` = powered on, `false` = powered off.
// WHY: cellular/wifi/bluetooth/gps are four independent radio power flags,
// not a state machine -- an enum or bitflags wouldn't remove any of the
// four axes, just rename how each is read.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RadioState {
    /// Cellular modem (voice + data).
    pub cellular: bool,
    /// `WiFi` radio.
    pub wifi: bool,
    /// Bluetooth radio.
    pub bluetooth: bool,
    /// GPS receiver.
    pub gps: bool,
}

impl RadioState {
    /// All radios on (normal operation).
    pub(crate) const ALL_ON: Self = Self {
        cellular: true,
        wifi: true,
        bluetooth: true,
        gps: true,
    };

    /// All radios off (RF silence / COVERT LOCK).
    pub(crate) const ALL_OFF: Self = Self {
        cellular: false,
        wifi: false,
        bluetooth: false,
        gps: false,
    };

    /// Stealth mode: cellular + GPS off, `WiFi` + BT on.
    pub(crate) const STEALTH: Self = Self {
        cellular: false,
        wifi: true,
        bluetooth: true,
        gps: false,
    };
}

impl Default for RadioState {
    fn default() -> Self {
        Self::ALL_ON
    }
}

// ---------------------------------------------------------------------------
// Presets
// ---------------------------------------------------------------------------

/// Named radio preset with a display label and target state.
#[derive(Debug, Clone, Copy)]
struct RadioPreset {
    /// Display name shown on screen.
    label: &'static str,
    /// Target radio state.
    state: RadioState,
}

/// Available radio presets, cycled by the PRESET softkey.
const PRESETS: [RadioPreset; PRESET_COUNT] = [
    RadioPreset {
        label: "COVERT LOCK",
        state: RadioState::ALL_OFF,
    },
    RadioPreset {
        label: "STEALTH",
        state: RadioState::STEALTH,
    },
    RadioPreset {
        label: "RESTORE",
        state: RadioState::ALL_ON,
    },
];

// ---------------------------------------------------------------------------
// Radio control screen
// ---------------------------------------------------------------------------

/// Radio control panel screen.
pub(crate) struct RadioControlScreen {
    /// Current radio state (desired, not necessarily applied).
    pub state: RadioState,
    /// Currently highlighted preset index for display.
    active_preset: Option<usize>,
}

impl RadioControlScreen {
    /// Create a new radio control screen with all radios on.
    pub(crate) fn new() -> Self {
        Self {
            state: RadioState::default(),
            active_preset: None,
        }
    }

    /// Apply a preset by index, updating the radio state.
    fn apply_preset(&mut self, index: usize) {
        if index < PRESET_COUNT {
            self.state = PRESETS[index].state;
            self.active_preset = Some(index);
        }
    }

    /// Cycle to the next preset.
    fn cycle_preset(&mut self) {
        let next = match self.active_preset {
            Some(i) => (i + 1) % PRESET_COUNT,
            None => 0,
        };
        self.apply_preset(next);
    }

    /// Detect which preset (if any) matches the current state.
    fn detect_preset(&self) -> Option<usize> {
        for (i, preset) in PRESETS.iter().enumerate() {
            if self.state == preset.state {
                return Some(i);
            }
        }
        None
    }

    /// Return the current active preset label, or "CUSTOM" if no preset matches.
    fn preset_label(&self) -> &'static str {
        match self.detect_preset() {
            Some(i) => PRESETS[i].label,
            None => "CUSTOM",
        }
    }
}

/// Radio labels for each row, in display order.
const RADIO_LABELS: [&str; 4] = ["Cellular", "WiFi", "Bluetooth", "GPS"];

/// Helper to get the status of a radio by index.
fn radio_enabled(state: RadioState, index: usize) -> bool {
    match index {
        0 => state.cellular,
        1 => state.wifi,
        2 => state.bluetooth,
        3 => state.gps,
        _ => false,
    }
}

impl Screen for RadioControlScreen {
    fn draw(&self, fb: &mut [u16]) {
        let w = SCREEN_WIDTH;
        let h = CONTENT_HEIGHT;

        // Clear content area.
        ui::fill_rect(fb, w, h, 0, 0, w, h, color::BLACK);

        // Draw each radio row.
        for (i, label) in RADIO_LABELS.iter().enumerate() {
            let row_y = RADIO_START_Y + (i as u16) * ROW_HEIGHT;
            let enabled = radio_enabled(self.state, i);

            // Radio name.
            ui::draw_str(fb, w, PADDING_X, row_y, label, color::WHITE, color::BLACK);

            // ON/OFF status.
            let (status_text, status_color) = if enabled {
                ("ON", color::GREEN)
            } else {
                ("OFF", color::RED)
            };
            ui::draw_str(
                fb,
                w,
                STATUS_X,
                row_y,
                status_text,
                status_color,
                color::BLACK,
            );
        }

        // Separator line above preset area.
        let sep_y = PRESET_Y - 8;
        ui::fill_rect(
            fb,
            w,
            h,
            PADDING_X,
            sep_y,
            w - PADDING_X * 2,
            1,
            color::DARK_GREY,
        );

        // Active preset label.
        let preset_text = self.preset_label();
        ui::draw_str(
            fb,
            w,
            PADDING_X,
            PRESET_Y,
            "Mode:",
            color::DARK_GREY,
            color::BLACK,
        );
        let mode_color = match self.detect_preset() {
            Some(0) => color::RED,    // COVERT LOCK.
            Some(1) => color::YELLOW, // STEALTH.
            Some(2) => color::GREEN,  // RESTORE.
            _ => color::WHITE,        // CUSTOM.
        };
        ui::draw_str(
            fb,
            w,
            PADDING_X + 6 * CHAR_WIDTH,
            PRESET_Y,
            preset_text,
            mode_color,
            color::BLACK,
        );
    }

    fn on_key(&mut self, key: Key) -> ScreenAction {
        match key {
            // LSK cycles through presets.
            Key::Lsk => {
                self.cycle_preset();
                ScreenAction::None
            }
            // RSK or End goes back.
            Key::Rsk | Key::End => ScreenAction::Back,
            _ => ScreenAction::None,
        }
    }

    fn softkey_left(&self) -> &'static str {
        "PRESET"
    }

    fn softkey_right(&self) -> &'static str {
        "BACK"
    }

    fn title(&self) -> &'static str {
        "Radio Control"
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::CONTENT_PIXELS;

    #[test]
    fn covert_lock_disables_all() {
        let mut screen = RadioControlScreen::new();
        screen.apply_preset(0); // COVERT LOCK
        assert!(!screen.state.cellular, "cellular must be off");
        assert!(!screen.state.wifi, "wifi must be off");
        assert!(!screen.state.bluetooth, "bluetooth must be off");
        assert!(!screen.state.gps, "gps must be off");
        assert_eq!(screen.preset_label(), "COVERT LOCK");
    }

    #[test]
    fn restore_enables_all() {
        let mut screen = RadioControlScreen::new();
        // First disable all, then restore.
        screen.apply_preset(0); // COVERT LOCK
        screen.apply_preset(2); // RESTORE
        assert!(screen.state.cellular, "cellular must be on");
        assert!(screen.state.wifi, "wifi must be on");
        assert!(screen.state.bluetooth, "bluetooth must be on");
        assert!(screen.state.gps, "gps must be on");
        assert_eq!(screen.preset_label(), "RESTORE");
    }

    #[test]
    fn stealth_mixed_state() {
        let mut screen = RadioControlScreen::new();
        screen.apply_preset(1); // STEALTH
        assert!(!screen.state.cellular, "cellular must be off in stealth");
        assert!(screen.state.wifi, "wifi must be on in stealth");
        assert!(screen.state.bluetooth, "bluetooth must be on in stealth");
        assert!(!screen.state.gps, "gps must be off in stealth");
        assert_eq!(screen.preset_label(), "STEALTH");
    }

    #[test]
    fn cycle_preset_wraps() {
        let mut screen = RadioControlScreen::new();
        // From no preset, cycles to COVERT LOCK (0).
        screen.cycle_preset();
        assert_eq!(screen.state, RadioState::ALL_OFF);

        // To STEALTH (1).
        screen.cycle_preset();
        assert_eq!(screen.state, RadioState::STEALTH);

        // To RESTORE (2).
        screen.cycle_preset();
        assert_eq!(screen.state, RadioState::ALL_ON);

        // Wraps to COVERT LOCK (0).
        screen.cycle_preset();
        assert_eq!(screen.state, RadioState::ALL_OFF);
    }

    #[test]
    fn custom_preset_label() {
        let mut screen = RadioControlScreen::new();
        // Manually set a non-preset state.
        screen.state = RadioState {
            cellular: true,
            wifi: false,
            bluetooth: true,
            gps: false,
        };
        screen.active_preset = None;
        assert_eq!(screen.preset_label(), "CUSTOM");
    }

    #[test]
    fn detect_preset_matches() {
        let screen = RadioControlScreen::new();
        // Default is ALL_ON = RESTORE.
        assert_eq!(screen.detect_preset(), Some(2));
    }

    #[test]
    fn softkeys_correct() {
        let screen = RadioControlScreen::new();
        assert_eq!(screen.softkey_left(), "PRESET");
        assert_eq!(screen.softkey_right(), "BACK");
    }

    #[test]
    fn title_correct() {
        let screen = RadioControlScreen::new();
        assert_eq!(screen.title(), "Radio Control");
    }

    #[test]
    fn lsk_cycles_preset() {
        let mut screen = RadioControlScreen::new();
        let action = screen.on_key(Key::Lsk);
        assert_eq!(action, ScreenAction::None);
        // Should have applied first preset (COVERT LOCK).
        assert_eq!(screen.state, RadioState::ALL_OFF);
    }

    #[test]
    fn rsk_goes_back() {
        let mut screen = RadioControlScreen::new();
        let action = screen.on_key(Key::Rsk);
        assert_eq!(action, ScreenAction::Back);
    }

    #[test]
    fn draw_does_not_panic() {
        let screen = RadioControlScreen::new();
        let mut fb = alloc::vec![0u16; CONTENT_PIXELS];
        screen.draw(&mut fb);
        let any_set = fb.iter().any(|&px| px != 0);
        assert!(any_set, "radio control screen must render visible content");
    }

    #[test]
    fn draw_covert_lock_does_not_panic() {
        let mut screen = RadioControlScreen::new();
        screen.apply_preset(0);
        let mut fb = alloc::vec![0u16; CONTENT_PIXELS];
        screen.draw(&mut fb);
        let off_status_rendered = fb.contains(&color::RED);
        assert!(
            off_status_rendered,
            "covert lock must render OFF radio status text"
        );
    }

    #[test]
    fn radio_enabled_helper_correct() {
        let state = RadioState::STEALTH;
        assert!(!radio_enabled(state, 0), "cellular off in stealth");
        assert!(radio_enabled(state, 1), "wifi on in stealth");
        assert!(radio_enabled(state, 2), "bluetooth on in stealth");
        assert!(!radio_enabled(state, 3), "gps off in stealth");
        assert!(!radio_enabled(state, 4), "out-of-range returns false");
    }
}
