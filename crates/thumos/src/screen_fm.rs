//! FM radio UI screen.
//!
//! Displays the FM radio interface with:
//! - Large frequency display (e.g., "98.5 MHz")
//! - Signal strength indicator
//! - Preset buttons (1-6 mapped to numpad keys 1-6)
//! - Seek up/down via Left/Right keys
//! - LSK: "PRESETS" (cycles through saved presets)
//! - RSK: "BACK"
//!
//! ## Integration
//!
//! This screen is displayed when the user navigates to `ScreenId::FmRadio`
//! from the home screen or settings.  It interacts with the `FmRadio`
//! controller in `fm_radio.rs` for hardware operations.

// WHY: FM screen not yet wired to kinit (Wave 8, kinit wiring pending).
#![expect(
    dead_code,
    reason = "FM radio screen created in Phase 07 Wave 8, kinit wiring pending"
)]

extern crate alloc;
use alloc::string::String;

use crate::fm_radio::{self, FmState};
use crate::ui::{
    self, color, Key, Screen, ScreenAction,
    CHAR_HEIGHT, CHAR_WIDTH, CONTENT_HEIGHT, SCREEN_WIDTH,
};

// ---------------------------------------------------------------------------
// Layout constants
// ---------------------------------------------------------------------------

/// Left padding for content.
const PADDING_X: u16 = 12;

/// Y offset for the large frequency display.
const FREQ_Y: u16 = 40;

/// Y offset for the "MHz" label.
const MHZ_LABEL_Y: u16 = FREQ_Y + CHAR_HEIGHT * 2 + 4;

/// Y offset for the signal strength indicator.
const SIGNAL_Y: u16 = MHZ_LABEL_Y + CHAR_HEIGHT + 12;

/// Y offset for the status text (ON/OFF/SCANNING).
const STATUS_Y: u16 = SIGNAL_Y + CHAR_HEIGHT + 8;

/// Y offset for preset labels row.
const PRESETS_Y: u16 = STATUS_Y + CHAR_HEIGHT + 16;

/// Y offset for the preset frequency values.
const PRESET_FREQ_Y: u16 = PRESETS_Y + CHAR_HEIGHT + 4;

/// Number of signal bars.
const SIGNAL_BAR_COUNT: u16 = 5;

/// Width of each signal bar.
const SIGNAL_BAR_WIDTH: u16 = 6;

/// Gap between signal bars.
const SIGNAL_BAR_GAP: u16 = 3;

/// Maximum bar height.
const SIGNAL_BAR_MAX_HEIGHT: u16 = 20;

/// Number of preset slots.
const PRESET_COUNT: usize = 6;

// ---------------------------------------------------------------------------
// FM screen state (decoupled from hardware)
// ---------------------------------------------------------------------------

/// FM radio screen state.
///
/// Holds a snapshot of the FM radio state for display purposes.
/// The actual hardware control is done through the `FmRadio` controller.
pub struct FmScreen {
    /// Current FM state.
    pub fm_state: FmState,
    /// Current frequency in kHz (if tuned).
    pub frequency_khz: u32,
    /// Current RSSI in dBm.
    pub rssi: i8,
    /// Preset frequencies in kHz.
    pub presets: [u32; PRESET_COUNT],
    /// Number of populated presets.
    pub preset_count: u8,
    /// Volume level (0-15).
    pub volume: u8,
    /// Currently highlighted preset index (for visual feedback).
    active_preset: Option<usize>,
}

impl FmScreen {
    /// Create a new FM screen in the Off state.
    #[must_use]
    pub fn new() -> Self {
        Self {
            fm_state: FmState::Off,
            frequency_khz: 88_000,
            rssi: -100,
            presets: [0u32; PRESET_COUNT],
            preset_count: 0,
            volume: 8,
            active_preset: None,
        }
    }

    /// Update the screen state from an FM radio controller snapshot.
    pub fn update_from_state(
        &mut self,
        state: FmState,
        rssi: i8,
        presets: &[u32],
        preset_count: u8,
        volume: u8,
    ) {
        self.fm_state = state;
        if let FmState::Tuned { frequency_khz } = state {
            self.frequency_khz = frequency_khz;
        }
        self.rssi = rssi;
        let copy_count = presets.len().min(PRESET_COUNT);
        self.presets[..copy_count].copy_from_slice(&presets[..copy_count]);
        self.preset_count = preset_count;
        self.volume = volume;
    }

    /// Format the current frequency as a display string.
    ///
    /// Returns a string like "98.5" or "107.9".
    fn format_frequency(&self) -> String {
        let (mhz, frac) = fm_radio::freq_to_display(self.frequency_khz);
        alloc::format!("{mhz}.{frac}")
    }

    /// Map RSSI to signal bar count (0-5).
    ///
    /// RSSI ranges from about -100 dBm (no signal) to -30 dBm (strong).
    fn signal_bars(&self) -> u16 {
        if self.rssi <= -90 {
            0
        } else if self.rssi <= -80 {
            1
        } else if self.rssi <= -70 {
            2
        } else if self.rssi <= -60 {
            3
        } else if self.rssi <= -50 {
            4
        } else {
            5
        }
    }

    /// Map a numpad key (1-6) to a preset index.
    const fn key_to_preset(key: Key) -> Option<usize> {
        match key {
            Key::Num1 => Some(0),
            Key::Num2 => Some(1),
            Key::Num3 => Some(2),
            Key::Num4 => Some(3),
            Key::Num5 => Some(4),
            Key::Num6 => Some(5),
            _ => None,
        }
    }

    /// Draw the large frequency display (scaled 2x).
    fn draw_frequency(&self, fb: &mut [u16]) {
        let freq_str = self.format_frequency();
        let w = SCREEN_WIDTH;

        // Draw at 2x scale by drawing each character doubled.
        let total_width = (freq_str.len() as u16) * CHAR_WIDTH * 2;
        let start_x = (w.saturating_sub(total_width)) / 2;

        for (i, ch) in freq_str.chars().enumerate() {
            let cx = start_x + (i as u16) * CHAR_WIDTH * 2;
            // Draw 2x scaled: render each pixel of the glyph as a 2x2 block.
            ui::draw_char_scaled(fb, w, cx, FREQ_Y, ch, color::WHITE, color::BLACK, 2);
        }
    }

    /// Draw the signal strength bars.
    fn draw_signal_bars(&self, fb: &mut [u16]) {
        let bars = self.signal_bars();
        let w = SCREEN_WIDTH;
        let h = CONTENT_HEIGHT;
        let start_x = PADDING_X;

        // Label.
        ui::draw_str(fb, w, start_x, SIGNAL_Y, "Signal:", color::DARK_GREY, color::BLACK);
        let bars_start_x = start_x + 8 * CHAR_WIDTH;

        for i in 0..SIGNAL_BAR_COUNT {
            let bar_height = (i + 1) * (SIGNAL_BAR_MAX_HEIGHT / SIGNAL_BAR_COUNT);
            let bar_x = bars_start_x + i * (SIGNAL_BAR_WIDTH + SIGNAL_BAR_GAP);
            let bar_y = SIGNAL_Y + SIGNAL_BAR_MAX_HEIGHT - bar_height;

            let bar_color = if i < bars {
                if bars >= 4 {
                    color::GREEN
                } else if bars >= 2 {
                    color::YELLOW
                } else {
                    color::RED
                }
            } else {
                color::DARK_GREY
            };

            ui::fill_rect(fb, w, h, bar_x, bar_y, SIGNAL_BAR_WIDTH, bar_height, bar_color);
        }
    }

    /// Draw the preset bar.
    fn draw_presets(&self, fb: &mut [u16]) {
        let w = SCREEN_WIDTH;

        // Preset header.
        ui::draw_str(fb, w, PADDING_X, PRESETS_Y, "Presets:", color::DARK_GREY, color::BLACK);

        // Draw each preset slot.
        for i in 0..PRESET_COUNT {
            let slot_x = PADDING_X + (i as u16) * (CHAR_WIDTH * 5 + 4);
            let label_num = (i + 1) as u8;
            let label_char = (b'0' + label_num) as char;

            // Highlight active preset.
            let fg = if self.active_preset == Some(i) {
                color::GREEN
            } else {
                color::WHITE
            };

            // Slot number.
            let label = alloc::format!("{label_char}:");
            ui::draw_str(fb, w, slot_x, PRESET_FREQ_Y, &label, fg, color::BLACK);

            // Preset frequency (if set).
            if i < self.preset_count as usize && self.presets[i] > 0 {
                let (mhz, frac) = fm_radio::freq_to_display(self.presets[i]);
                let freq_text = alloc::format!("{mhz}.{frac}");
                ui::draw_str(
                    fb,
                    w,
                    slot_x + 2 * CHAR_WIDTH,
                    PRESET_FREQ_Y,
                    &freq_text,
                    fg,
                    color::BLACK,
                );
            } else {
                ui::draw_str(
                    fb,
                    w,
                    slot_x + 2 * CHAR_WIDTH,
                    PRESET_FREQ_Y,
                    "---",
                    color::DARK_GREY,
                    color::BLACK,
                );
            }
        }
    }
}

impl Screen for FmScreen {
    fn draw(&self, fb: &mut [u16]) {
        let w = SCREEN_WIDTH;
        let h = CONTENT_HEIGHT;

        // Clear content area.
        ui::fill_rect(fb, w, h, 0, 0, w, h, color::BLACK);

        match self.fm_state {
            FmState::Off => {
                // Show "FM Radio OFF" centered.
                ui::draw_str_centered(
                    fb, w, 0, w, FREQ_Y,
                    "FM Radio OFF", color::DARK_GREY, color::BLACK,
                );
                ui::draw_str_centered(
                    fb, w, 0, w, FREQ_Y + CHAR_HEIGHT + 8,
                    "Press OK to turn on", color::DARK_GREY, color::BLACK,
                );
            }
            FmState::On => {
                // Powered on but not tuned.
                ui::draw_str_centered(
                    fb, w, 0, w, FREQ_Y,
                    "No Station", color::YELLOW, color::BLACK,
                );
            }
            FmState::Scanning => {
                // Show scanning animation.
                ui::draw_str_centered(
                    fb, w, 0, w, FREQ_Y,
                    "Scanning...", color::YELLOW, color::BLACK,
                );
            }
            FmState::Tuned { .. } => {
                // Draw the frequency display.
                self.draw_frequency(fb);

                // Draw "MHz" label.
                ui::draw_str_centered(
                    fb, w, 0, w, MHZ_LABEL_Y,
                    "MHz", color::DARK_GREY, color::BLACK,
                );

                // Draw signal bars.
                self.draw_signal_bars(fb);

                // Draw status line.
                let vol_text = alloc::format!("Vol: {}", self.volume);
                ui::draw_str(fb, w, PADDING_X, STATUS_Y, &vol_text, color::WHITE, color::BLACK);

                // Draw seek arrows.
                let arrows = "<< SEEK >>";
                ui::draw_str_centered(
                    fb, w, 0, w, STATUS_Y,
                    arrows, color::DARK_GREY, color::BLACK,
                );
            }
        }

        // Draw presets (always visible when not off).
        if !matches!(self.fm_state, FmState::Off) {
            self.draw_presets(fb);
        }
    }

    fn on_key(&mut self, key: Key) -> ScreenAction {
        match key {
            // OK toggles power.
            Key::Ok => {
                if matches!(self.fm_state, FmState::Off) {
                    // Signal to turn on (handled by screen dispatcher).
                    self.fm_state = FmState::On;
                }
                ScreenAction::None
            }

            // Left/Right seek.
            Key::Left => {
                // Seek down handled by screen dispatcher via FM controller.
                ScreenAction::None
            }
            Key::Right => {
                // Seek up handled by screen dispatcher via FM controller.
                ScreenAction::None
            }

            // Up/Down volume.
            Key::Up => {
                self.volume = (self.volume + 1).min(15);
                ScreenAction::None
            }
            Key::Down => {
                self.volume = self.volume.saturating_sub(1);
                ScreenAction::None
            }

            // Numpad 1-6: preset recall.
            Key::Num1 | Key::Num2 | Key::Num3 | Key::Num4 | Key::Num5 | Key::Num6 => {
                if let Some(idx) = Self::key_to_preset(key) {
                    self.active_preset = Some(idx);
                }
                ScreenAction::None
            }

            // LSK: cycle presets.
            Key::Lsk => {
                let next = match self.active_preset {
                    Some(i) if i + 1 < self.preset_count as usize => Some(i + 1),
                    _ => {
                        if self.preset_count > 0 {
                            Some(0)
                        } else {
                            None
                        }
                    }
                };
                self.active_preset = next;
                ScreenAction::None
            }

            // RSK or End goes back.
            Key::Rsk | Key::End => ScreenAction::Back,

            _ => ScreenAction::None,
        }
    }

    fn softkey_left(&self) -> &'static str {
        "PRESETS"
    }

    fn softkey_right(&self) -> &'static str {
        "BACK"
    }

    fn title(&self) -> &'static str {
        "FM Radio"
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
    fn frequency_display_formats_correctly() {
        let mut screen = FmScreen::new();
        screen.frequency_khz = 98_500;
        let display = screen.format_frequency();
        assert_eq!(display, "98.5", "98500 kHz must display as 98.5");

        screen.frequency_khz = 107_900;
        let display = screen.format_frequency();
        assert_eq!(display, "107.9", "107900 kHz must display as 107.9");

        screen.frequency_khz = 88_000;
        let display = screen.format_frequency();
        assert_eq!(display, "88.0", "88000 kHz must display as 88.0");
    }

    #[test]
    fn preset_keys_mapped() {
        assert_eq!(FmScreen::key_to_preset(Key::Num1), Some(0));
        assert_eq!(FmScreen::key_to_preset(Key::Num2), Some(1));
        assert_eq!(FmScreen::key_to_preset(Key::Num3), Some(2));
        assert_eq!(FmScreen::key_to_preset(Key::Num4), Some(3));
        assert_eq!(FmScreen::key_to_preset(Key::Num5), Some(4));
        assert_eq!(FmScreen::key_to_preset(Key::Num6), Some(5));
        assert_eq!(FmScreen::key_to_preset(Key::Num7), None, "Num7 must not map to a preset");
        assert_eq!(FmScreen::key_to_preset(Key::Ok), None, "Ok must not map to a preset");
    }

    #[test]
    fn softkeys_correct() {
        let screen = FmScreen::new();
        assert_eq!(screen.softkey_left(), "PRESETS");
        assert_eq!(screen.softkey_right(), "BACK");
    }

    #[test]
    fn title_correct() {
        let screen = FmScreen::new();
        assert_eq!(screen.title(), "FM Radio");
    }

    #[test]
    fn rsk_goes_back() {
        let mut screen = FmScreen::new();
        let action = screen.on_key(Key::Rsk);
        assert_eq!(action, ScreenAction::Back);
    }

    #[test]
    fn end_goes_back() {
        let mut screen = FmScreen::new();
        let action = screen.on_key(Key::End);
        assert_eq!(action, ScreenAction::Back);
    }

    #[test]
    fn signal_bars_mapping() {
        let mut screen = FmScreen::new();

        screen.rssi = -100;
        assert_eq!(screen.signal_bars(), 0, "RSSI -100 must show 0 bars");

        screen.rssi = -85;
        assert_eq!(screen.signal_bars(), 1, "RSSI -85 must show 1 bar");

        screen.rssi = -75;
        assert_eq!(screen.signal_bars(), 2, "RSSI -75 must show 2 bars");

        screen.rssi = -65;
        assert_eq!(screen.signal_bars(), 3, "RSSI -65 must show 3 bars");

        screen.rssi = -55;
        assert_eq!(screen.signal_bars(), 4, "RSSI -55 must show 4 bars");

        screen.rssi = -40;
        assert_eq!(screen.signal_bars(), 5, "RSSI -40 must show 5 bars");
    }

    #[test]
    fn volume_up_down_keys() {
        let mut screen = FmScreen::new();
        screen.volume = 8;

        screen.on_key(Key::Up);
        assert_eq!(screen.volume, 9, "Up must increase volume");

        screen.on_key(Key::Down);
        assert_eq!(screen.volume, 8, "Down must decrease volume");

        screen.volume = 15;
        screen.on_key(Key::Up);
        assert_eq!(screen.volume, 15, "volume at max must not overflow");

        screen.volume = 0;
        screen.on_key(Key::Down);
        assert_eq!(screen.volume, 0, "volume at 0 must not underflow");
    }

    #[test]
    fn numpad_selects_preset() {
        let mut screen = FmScreen::new();
        screen.on_key(Key::Num3);
        assert_eq!(screen.active_preset, Some(2), "Num3 must select preset 2");
    }

    #[test]
    fn ok_toggles_power_on() {
        let mut screen = FmScreen::new();
        assert_eq!(screen.fm_state, FmState::Off);
        screen.on_key(Key::Ok);
        assert_eq!(screen.fm_state, FmState::On, "OK must turn on the radio");
    }

    #[test]
    fn draw_off_does_not_panic() {
        let screen = FmScreen::new();
        let mut fb = [0u16; CONTENT_PIXELS];
        screen.draw(&mut fb);
        let any_set = fb.iter().any(|&px| px != 0);
        assert!(any_set, "FM screen in Off state must render visible content");
    }

    #[test]
    fn draw_tuned_does_not_panic() {
        let mut screen = FmScreen::new();
        screen.fm_state = FmState::Tuned {
            frequency_khz: 98_500,
        };
        screen.frequency_khz = 98_500;
        screen.rssi = -60;
        let mut fb = [0u16; CONTENT_PIXELS];
        screen.draw(&mut fb);
        let any_set = fb.iter().any(|&px| px != 0);
        assert!(any_set, "FM screen in Tuned state must render visible content");
    }

    #[test]
    fn lsk_cycles_presets() {
        let mut screen = FmScreen::new();
        screen.preset_count = 3;
        screen.presets[0] = 88_000;
        screen.presets[1] = 98_500;
        screen.presets[2] = 107_900;

        screen.on_key(Key::Lsk);
        assert_eq!(screen.active_preset, Some(0), "first LSK must select preset 0");

        screen.on_key(Key::Lsk);
        assert_eq!(screen.active_preset, Some(1), "second LSK must select preset 1");

        screen.on_key(Key::Lsk);
        assert_eq!(screen.active_preset, Some(2), "third LSK must select preset 2");

        screen.on_key(Key::Lsk);
        assert_eq!(screen.active_preset, Some(0), "fourth LSK must wrap to preset 0");
    }
}
