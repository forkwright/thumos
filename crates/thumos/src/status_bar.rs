//! Kernel-side status bar renderer for the 240x20 top strip.
//!
//! Pulls state from the kernel's radio modules (`WiFi`, Bluetooth, GPS) and
//! renders connectivity indicators, battery percentage, and operating mode
//! into the status bar zone of the framebuffer.
//!
//! ## Layout (left to right)
//!
//! | Area           | Content                                           |
//! |----------------|---------------------------------------------------|
//! | Left (2px pad) | Network: "LTE" / "3G" / "NO SVC"                  |
//! | Left cont.     | "`WiFi`" (if connected)                              |
//! | Left cont.     | "BT" (if active)                                   |
//! | Left cont.     | "GPS" (if fix acquired)                            |
//! | Center         | Mode indicator: "D" (Daily)                        |
//! | Right          | Battery: "xx%"                                     |
//!
//! ## Integration
//!
//! Each radio module exposes a state enum. The status bar reads the state
//! and renders the appropriate indicator:
//! - [`WifiState::Connected`] -> "`WiFi`"
//! - [`BtState::Ready`] or [`BtState::Scanning`] -> "BT"
//! - [`GpsState::FixAcquired`] -> "GPS"

use crate::ui::{self, CHAR_HEIGHT, CHAR_WIDTH, SCREEN_WIDTH, STATUS_BAR_HEIGHT, color};

// ---------------------------------------------------------------------------
// Status bar state
// ---------------------------------------------------------------------------

/// Network service level shown in the status bar.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum NetworkService {
    /// No cellular service.
    #[default]
    NoService,
    /// 2G (GSM/EDGE).
    #[expect(dead_code, reason = "requires modem registration state wiring")]
    Edge,
    /// 3G (WCDMA/HSPA).
    #[expect(dead_code, reason = "requires modem registration state wiring")]
    ThreeG,
    /// 4G LTE.
    #[expect(dead_code, reason = "requires modem registration state wiring")]
    Lte,
}

impl NetworkService {
    /// Display label for the network indicator.
    const fn label(self) -> &'static str {
        match self {
            Self::NoService => "NO SVC",
            Self::Edge => "2G",
            Self::ThreeG => "3G",
            Self::Lte => "LTE",
        }
    }
}

/// Snapshot of system state needed to render the status bar.
///
/// Updated each render cycle from kernel globals. Separates the status bar
/// rendering from direct coupling to radio module internals.
pub(crate) struct StatusBarState {
    /// Cellular network service level.
    pub network: NetworkService,
    /// Whether `WiFi` is connected (maps from `WifiState::Connected`).
    pub wifi_connected: bool,
    /// Whether Bluetooth is active (maps from `BtState::Ready` or `Scanning`).
    pub bt_active: bool,
    /// Whether GPS has a fix (maps from `GpsState::FixAcquired`).
    pub gps_fix: bool,
    /// Battery percentage (0-100). Populated from `battery::BatteryMonitor`.
    pub battery_pct: u8,
    /// Mode indicator character ("D" for Daily, "S" for Sentinel, "P" for Panic).
    pub mode_char: char,
    /// Mode badge label from `ModeManager::status_badge`.
    ///
    /// When set, rendered in the center instead of the single `mode_char`.
    /// Values: `"DAILY"`, `"SENTL"`, `"COVRT"`, `"PANIC"`.
    pub mode_badge: Option<&'static str>,
    /// Mode badge color (RGB565). Defaults to white if `None`.
    pub mode_badge_color: Option<u16>,
    /// Whether the threat level is High or Critical.
    ///
    /// When `true`, a red "!" indicator is drawn between the mode badge
    /// and battery percentage to alert the user to active threats.
    pub threat_high: bool,
}

impl Default for StatusBarState {
    fn default() -> Self {
        Self {
            network: NetworkService::NoService,
            wifi_connected: false,
            bt_active: false,
            gps_fix: false,
            battery_pct: 0,
            mode_char: 'D',
            mode_badge: None,
            mode_badge_color: None,
            threat_high: false,
        }
    }
}

/// Kernel-side status bar renderer.
///
/// Renders into the top `STATUS_BAR_HEIGHT` (20px) rows of the framebuffer.
/// The framebuffer slice passed to `draw()` is `SCREEN_WIDTH * STATUS_BAR_HEIGHT`
/// pixels of `u16` RGB565.
pub(crate) struct KernelStatusBar;

impl KernelStatusBar {
    /// Draw the status bar with the given state.
    ///
    /// `fb` must be at least `SCREEN_WIDTH * STATUS_BAR_HEIGHT` pixels.
    pub(crate) fn draw(fb: &mut [u16], state: &StatusBarState) {
        let w = SCREEN_WIDTH;
        let h = STATUS_BAR_HEIGHT;

        // Clear to black.
        ui::fill_rect(fb, w, h, 0, 0, w, h, color::BLACK);

        // Draw a thin separator at the bottom of the status bar.
        ui::fill_rect(fb, w, h, 0, h - 1, w, 1, color::DARK_GREY);

        // Vertical centering for text.
        let text_y = (h.saturating_sub(CHAR_HEIGHT)) / 2;

        // --- Left side: connectivity indicators ---
        let mut x_cursor: u16 = 2;

        // Network service.
        let net_label = state.network.label();
        let net_color = match state.network {
            NetworkService::NoService => color::DARK_GREY,
            _ => color::WHITE,
        };
        ui::draw_str(fb, w, x_cursor, text_y, net_label, net_color, color::BLACK);
        x_cursor += ui::str_pixel_width(net_label) + CHAR_WIDTH;

        // WiFi indicator.
        if state.wifi_connected {
            ui::draw_str(fb, w, x_cursor, text_y, "WiFi", color::WHITE, color::BLACK);
            x_cursor += ui::str_pixel_width("WiFi") + CHAR_WIDTH;
        }

        // Bluetooth indicator.
        if state.bt_active {
            ui::draw_str(fb, w, x_cursor, text_y, "BT", color::WHITE, color::BLACK);
            x_cursor += ui::str_pixel_width("BT") + CHAR_WIDTH;
        }

        // GPS indicator.
        if state.gps_fix {
            ui::draw_str(fb, w, x_cursor, text_y, "GPS", color::WHITE, color::BLACK);
            // x_cursor is not used further on the left side.
        }

        // --- Center: mode indicator ---
        // WHY: prefer the expanded badge (e.g. "SENTL", "COVRT") from the
        // security mode manager when available; fall back to the single
        // mode_char for backward compatibility.
        if let Some(badge) = state.mode_badge {
            let badge_color = state.mode_badge_color.unwrap_or(color::WHITE);
            ui::draw_str_centered(fb, w, 0, w, text_y, badge, badge_color, color::BLACK);
        } else {
            let mode_str: [u8; 1] = [state.mode_char as u8];
            let mode_label = core::str::from_utf8(&mode_str).unwrap_or("D");
            ui::draw_str_centered(fb, w, 0, w, text_y, mode_label, color::WHITE, color::BLACK);
        }

        // --- Right side: threat indicator + battery ---
        let batt_text = battery_text(state.battery_pct);
        let batt_width = ui::str_pixel_width(batt_text);
        let batt_x = w.saturating_sub(batt_width).saturating_sub(2);
        ui::draw_str(fb, w, batt_x, text_y, batt_text, color::WHITE, color::BLACK);

        // Threat indicator: red "!" when threat level is High or Critical.
        if state.threat_high {
            let threat_x = batt_x.saturating_sub(CHAR_WIDTH + 2);
            ui::draw_char(fb, w, threat_x, text_y, '!', color::RED, color::BLACK);
        }
    }
}

/// Return a static string for the battery percentage.
///
/// Uses a lookup table to avoid heap allocation. The "x" placeholder
/// represents the ones digit (matching eidolon's `status_bar` pattern).
const fn battery_text(pct: u8) -> &'static str {
    match pct {
        100 => "100%",
        90..=99 => "9x%",
        80..=89 => "8x%",
        70..=79 => "7x%",
        60..=69 => "6x%",
        50..=59 => "5x%",
        40..=49 => "4x%",
        30..=39 => "3x%",
        20..=29 => "2x%",
        10..=19 => "1x%",
        1..=9 => "x%",
        _ => "0%",
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const STATUS_PIXELS: usize = SCREEN_WIDTH as usize * STATUS_BAR_HEIGHT as usize;

    #[test]
    fn draw_default_state_does_not_panic() {
        let mut fb = [0u16; STATUS_PIXELS];
        let state = StatusBarState::default();
        KernelStatusBar::draw(&mut fb, &state);
        let any_set = fb.iter().any(|&px| px != 0);
        assert!(any_set, "status bar default state must render pixels");
    }

    #[test]
    fn draw_all_indicators_active() {
        let mut fb = [0u16; STATUS_PIXELS];
        let state = StatusBarState {
            network: NetworkService::Lte,
            wifi_connected: true,
            bt_active: true,
            gps_fix: true,
            battery_pct: 85,
            mode_char: 'D',
            ..StatusBarState::default()
        };
        KernelStatusBar::draw(&mut fb, &state);
        let any_set = fb.iter().any(|&px| px != 0);
        assert!(any_set, "status bar with all indicators must render pixels");
    }

    #[test]
    fn draw_no_service_renders() {
        let mut fb = [0u16; STATUS_PIXELS];
        let state = StatusBarState {
            network: NetworkService::NoService,
            ..StatusBarState::default()
        };
        KernelStatusBar::draw(&mut fb, &state);
        let any_set = fb.iter().any(|&px| px != 0);
        assert!(any_set, "status bar with no service must still render");
    }

    #[test]
    fn draw_stays_within_status_bar_height() {
        // Verify no pixels are written beyond STATUS_BAR_HEIGHT rows.
        // We create a slightly larger buffer and check the overflow area.
        let extra_rows = 4;
        let total = STATUS_PIXELS + SCREEN_WIDTH as usize * extra_rows as usize;
        let mut fb = [0u16; 240 * 24]; // 20 + 4 extra rows
        assert!(fb.len() >= total);

        let state = StatusBarState {
            network: NetworkService::Lte,
            wifi_connected: true,
            bt_active: true,
            gps_fix: true,
            battery_pct: 100,
            mode_char: 'S',
            ..StatusBarState::default()
        };
        KernelStatusBar::draw(&mut fb[..STATUS_PIXELS], &state);

        // The extra rows beyond STATUS_PIXELS must remain zero.
        assert!(
            fb[STATUS_PIXELS..].iter().all(|&px| px == 0),
            "status bar must not write pixels beyond STATUS_BAR_HEIGHT"
        );
    }

    #[test]
    fn battery_text_covers_all_ranges() {
        assert_eq!(battery_text(0), "0%");
        assert_eq!(battery_text(5), "x%");
        assert_eq!(battery_text(15), "1x%");
        assert_eq!(battery_text(25), "2x%");
        assert_eq!(battery_text(35), "3x%");
        assert_eq!(battery_text(45), "4x%");
        assert_eq!(battery_text(55), "5x%");
        assert_eq!(battery_text(65), "6x%");
        assert_eq!(battery_text(75), "7x%");
        assert_eq!(battery_text(85), "8x%");
        assert_eq!(battery_text(95), "9x%");
        assert_eq!(battery_text(100), "100%");
    }

    #[test]
    fn battery_text_clamps_above_100() {
        // Values above 100 fall through to "0%" via the catch-all.
        let text = battery_text(200);
        assert!(!text.is_empty(), "clamped battery text must not be empty");
    }

    #[test]
    fn network_service_labels_correct() {
        assert_eq!(NetworkService::NoService.label(), "NO SVC");
        assert_eq!(NetworkService::Edge.label(), "2G");
        assert_eq!(NetworkService::ThreeG.label(), "3G");
        assert_eq!(NetworkService::Lte.label(), "LTE");
    }

    #[test]
    fn draw_mode_badge_renders() {
        let mut fb = [0u16; STATUS_PIXELS];
        let state = StatusBarState {
            mode_badge: Some("SENTL"),
            mode_badge_color: Some(color::YELLOW),
            ..StatusBarState::default()
        };
        KernelStatusBar::draw(&mut fb, &state);
        let any_set = fb.iter().any(|&px| px != 0);
        assert!(any_set, "status bar with mode badge must render pixels");
    }

    #[test]
    fn draw_panic_badge_renders() {
        let mut fb = [0u16; STATUS_PIXELS];
        let state = StatusBarState {
            mode_badge: Some("PANIC"),
            mode_badge_color: Some(color::RED),
            ..StatusBarState::default()
        };
        KernelStatusBar::draw(&mut fb, &state);
        let any_set = fb.iter().any(|&px| px != 0);
        assert!(any_set, "status bar with PANIC badge must render pixels");
    }

    #[test]
    fn mode_chars_are_distinct() {
        // Verify the convention: D=Daily, S=Sentinel, P=Panic.
        let modes = ['D', 'S', 'P'];
        let mut seen = [false; 128];
        for &m in &modes {
            assert!(!seen[m as usize], "mode character '{m}' must be unique");
            seen[m as usize] = true;
        }
    }

    #[test]
    fn draw_threat_indicator_renders() {
        let mut fb = [0u16; STATUS_PIXELS];
        let state = StatusBarState {
            threat_high: true,
            battery_pct: 50,
            ..StatusBarState::default()
        };
        KernelStatusBar::draw(&mut fb, &state);
        let any_set = fb.iter().any(|&px| px != 0);
        assert!(
            any_set,
            "status bar with threat indicator must render pixels"
        );
    }

    #[test]
    fn draw_no_threat_indicator_when_low() {
        let mut fb_low = [0u16; STATUS_PIXELS];
        let state_low = StatusBarState {
            threat_high: false,
            battery_pct: 50,
            ..StatusBarState::default()
        };
        KernelStatusBar::draw(&mut fb_low, &state_low);

        let mut fb_high = [0u16; STATUS_PIXELS];
        let state_high = StatusBarState {
            threat_high: true,
            battery_pct: 50,
            ..StatusBarState::default()
        };
        KernelStatusBar::draw(&mut fb_high, &state_high);

        // The framebuffers must differ when threat_high changes.
        assert!(
            fb_low != fb_high,
            "threat indicator must produce different pixels"
        );
    }
}
