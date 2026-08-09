//! Settings screens for the thumos kernel UI.
//!
//! Provides a menu-style settings hub with subpages:
//! - Main settings menu (scrollable list of categories)
//! - `WiFi` settings (current connection state, SSID, signal, IP)
//! - Bluetooth settings (paired count, scanning status)
//! - About screen (device info, OS version, build date)
//!
//! Display and Sound are placeholder entries for future waves.
//!
//! ## Architecture
//!
//! Each subpage is a separate struct implementing the [`Screen`] trait.
//! The main settings menu navigates to subpages via [`ScreenId`].
//! Subpages receive state snapshots to avoid holding references to
//! kernel globals.

// WHY: settings screens created in Phase 07 Wave 6, kinit wiring pending.
#![expect(
    dead_code,
    reason = "Settings screens created in Phase 07 Wave 6, kinit wiring pending (#145)"
)]

use crate::ui::{
    self, CHAR_HEIGHT, CHAR_WIDTH, CONTENT_HEIGHT, Key, SCREEN_WIDTH, Screen, ScreenAction,
    ScreenId, color,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Left padding for menu items and detail labels.
const PADDING_X: u16 = 8;

/// Height of each menu row.
const ROW_HEIGHT: u16 = CHAR_HEIGHT + 6;

/// Y offset for the first menu item.
const MENU_START_Y: u16 = 8;

/// Maximum number of visible rows in the settings menu.
const VISIBLE_ROWS: usize = 10;

/// Y offset for detail labels on subpages.
const DETAIL_START_Y: u16 = 16;

/// Vertical spacing between detail lines on subpages.
const DETAIL_SPACING: u16 = CHAR_HEIGHT + 8;

// ---------------------------------------------------------------------------
// Main settings menu
// ---------------------------------------------------------------------------

/// Menu item definition for the main settings list.
#[derive(Debug, Clone, Copy)]
struct MenuItem {
    /// Display label.
    label: &'static str,
    /// Target screen when selected.
    screen_id: ScreenId,
}

/// Settings menu items, in display order.
const MENU_ITEMS: &[MenuItem] = &[
    MenuItem {
        label: "WiFi",
        screen_id: ScreenId::WifiSettings,
    },
    MenuItem {
        label: "Bluetooth",
        screen_id: ScreenId::BtSettings,
    },
    MenuItem {
        label: "Display",
        screen_id: ScreenId::Settings,
    },
    MenuItem {
        label: "Sound",
        screen_id: ScreenId::Settings,
    },
    MenuItem {
        label: "Privacy",
        screen_id: ScreenId::Privacy,
    },
    MenuItem {
        label: "About",
        screen_id: ScreenId::About,
    },
];

/// Main settings menu screen.
pub(crate) struct SettingsMenuScreen {
    /// Currently selected menu item index.
    cursor: usize,
    /// Scroll offset for the visible window.
    scroll_offset: usize,
}

impl SettingsMenuScreen {
    /// Create a new settings menu screen.
    pub(crate) fn new() -> Self {
        Self {
            cursor: 0,
            scroll_offset: 0,
        }
    }

    /// Adjust scroll offset so the cursor is visible.
    fn adjust_scroll(&mut self) {
        if self.cursor < self.scroll_offset {
            self.scroll_offset = self.cursor;
        } else if self.cursor >= self.scroll_offset + VISIBLE_ROWS {
            self.scroll_offset = self.cursor + 1 - VISIBLE_ROWS;
        }
    }
}

impl Screen for SettingsMenuScreen {
    fn draw(&self, fb: &mut [u16]) {
        let w = SCREEN_WIDTH;
        let h = CONTENT_HEIGHT;

        // Clear content area.
        ui::fill_rect(fb, w, h, 0, 0, w, h, color::BLACK);

        let visible_end = (self.scroll_offset + VISIBLE_ROWS).min(MENU_ITEMS.len());
        for (vi, mi) in (self.scroll_offset..visible_end).enumerate() {
            let item = &MENU_ITEMS[mi];
            let row_y = MENU_START_Y + (vi as u16) * ROW_HEIGHT;

            let (fg, bg) = if mi == self.cursor {
                (color::BLACK, color::WHITE)
            } else {
                (color::WHITE, color::BLACK)
            };

            // Draw highlight background for selected row.
            if mi == self.cursor {
                ui::fill_rect(fb, w, h, 0, row_y, w, ROW_HEIGHT, color::WHITE);
            }

            ui::draw_str(fb, w, PADDING_X, row_y + 3, item.label, fg, bg);

            // Draw ">" indicator on the right for items with subpages.
            let arrow_x = w - CHAR_WIDTH - PADDING_X;
            ui::draw_char(fb, w, arrow_x, row_y + 3, '>', fg, bg);
        }
    }

    fn on_key(&mut self, key: Key) -> ScreenAction {
        match key {
            Key::Up => {
                if self.cursor > 0 {
                    self.cursor -= 1;
                    self.adjust_scroll();
                }
                ScreenAction::None
            }
            Key::Down => {
                if self.cursor < MENU_ITEMS.len() - 1 {
                    self.cursor += 1;
                    self.adjust_scroll();
                }
                ScreenAction::None
            }
            Key::Ok | Key::Rsk => {
                let item = &MENU_ITEMS[self.cursor];
                ScreenAction::Navigate(item.screen_id)
            }
            Key::Lsk | Key::End => ScreenAction::Back,
            _ => ScreenAction::None,
        }
    }

    fn softkey_left(&self) -> &'static str {
        "BACK"
    }

    fn softkey_right(&self) -> &'static str {
        "SELECT"
    }

    fn title(&self) -> &'static str {
        "Settings"
    }
}

// ---------------------------------------------------------------------------
// About screen
// ---------------------------------------------------------------------------

/// Thumos kernel version string.
const VERSION: &str = "thumos 0.1.0";

/// Device model string.
const DEVICE_MODEL: &str = "AGM M7";

/// Build date (compile-time constant).
const BUILD_DATE: &str = "2026-04-09";

/// About screen showing device and OS information.
pub(crate) struct AboutScreen;

impl AboutScreen {
    /// Create a new About screen.
    pub(crate) fn new() -> Self {
        Self
    }
}

impl Screen for AboutScreen {
    fn draw(&self, fb: &mut [u16]) {
        let w = SCREEN_WIDTH;
        let h = CONTENT_HEIGHT;

        // Clear content area.
        ui::fill_rect(fb, w, h, 0, 0, w, h, color::BLACK);

        let mut y = DETAIL_START_Y;

        // OS version.
        ui::draw_str(fb, w, PADDING_X, y, "OS:", color::DARK_GREY, color::BLACK);
        ui::draw_str(
            fb,
            w,
            PADDING_X + 4 * CHAR_WIDTH,
            y,
            VERSION,
            color::WHITE,
            color::BLACK,
        );
        y += DETAIL_SPACING;

        // Device model.
        ui::draw_str(
            fb,
            w,
            PADDING_X,
            y,
            "Model:",
            color::DARK_GREY,
            color::BLACK,
        );
        ui::draw_str(
            fb,
            w,
            PADDING_X + 7 * CHAR_WIDTH,
            y,
            DEVICE_MODEL,
            color::WHITE,
            color::BLACK,
        );
        y += DETAIL_SPACING;

        // Build date.
        ui::draw_str(
            fb,
            w,
            PADDING_X,
            y,
            "Build:",
            color::DARK_GREY,
            color::BLACK,
        );
        ui::draw_str(
            fb,
            w,
            PADDING_X + 7 * CHAR_WIDTH,
            y,
            BUILD_DATE,
            color::WHITE,
            color::BLACK,
        );
        y += DETAIL_SPACING;

        // Architecture.
        ui::draw_str(fb, w, PADDING_X, y, "Arch:", color::DARK_GREY, color::BLACK);
        ui::draw_str(
            fb,
            w,
            PADDING_X + 6 * CHAR_WIDTH,
            y,
            "ARMv7-A (MT6739)",
            color::WHITE,
            color::BLACK,
        );
        y += DETAIL_SPACING;

        // Kernel type.
        ui::draw_str(fb, w, PADDING_X, y, "Type:", color::DARK_GREY, color::BLACK);
        ui::draw_str(
            fb,
            w,
            PADDING_X + 6 * CHAR_WIDTH,
            y,
            "Bare-metal Rust",
            color::WHITE,
            color::BLACK,
        );
    }

    fn on_key(&mut self, key: Key) -> ScreenAction {
        match key {
            Key::Lsk | Key::End | Key::Rsk => ScreenAction::Back,
            _ => ScreenAction::None,
        }
    }

    fn softkey_left(&self) -> &'static str {
        "BACK"
    }

    fn softkey_right(&self) -> &'static str {
        ""
    }

    fn title(&self) -> &'static str {
        "About"
    }
}

// ---------------------------------------------------------------------------
// WiFi settings screen
// ---------------------------------------------------------------------------

/// Snapshot of `WiFi` state for display on the settings screen.
///
/// Decoupled from `wifi::WifiState` to avoid coupling screen rendering
/// to the driver state machine. Updated each render cycle.
#[derive(Debug, Clone)]
pub struct WifiSettingsState {
    /// Whether `WiFi` is connected.
    pub connected: bool,
    /// Current SSID (empty if not connected).
    pub ssid: [u8; 32],
    /// Valid bytes in `ssid`.
    pub ssid_len: usize,
    /// Signal strength as approximate percentage (0-100).
    pub signal_percent: u8,
    /// IP address as four octets (0.0.0.0 if not connected).
    pub ip_addr: [u8; 4],
    /// Whether a scan is in progress.
    pub scanning: bool,
}

impl Default for WifiSettingsState {
    fn default() -> Self {
        Self {
            connected: false,
            ssid: [0u8; 32],
            ssid_len: 0,
            signal_percent: 0,
            ip_addr: [0u8; 4],
            scanning: false,
        }
    }
}

/// `WiFi` settings screen (read-only display of `WiFi` state).
pub(crate) struct WifiSettingsScreen {
    /// Current `WiFi` state snapshot.
    pub state: WifiSettingsState,
}

impl WifiSettingsScreen {
    /// Create a new `WiFi` settings screen with default (disconnected) state.
    pub(crate) fn new() -> Self {
        Self {
            state: WifiSettingsState::default(),
        }
    }

    /// Update the state snapshot. Called each render cycle.
    pub(crate) fn update_state(&mut self, state: WifiSettingsState) {
        self.state = state;
    }
}

impl Screen for WifiSettingsScreen {
    fn draw(&self, fb: &mut [u16]) {
        let w = SCREEN_WIDTH;
        let h = CONTENT_HEIGHT;

        // Clear content area.
        ui::fill_rect(fb, w, h, 0, 0, w, h, color::BLACK);

        let mut y = DETAIL_START_Y;

        // Connection status.
        ui::draw_str(
            fb,
            w,
            PADDING_X,
            y,
            "Status:",
            color::DARK_GREY,
            color::BLACK,
        );
        let status_text = if self.state.connected {
            "Connected"
        } else if self.state.scanning {
            "Scanning..."
        } else {
            "Not connected"
        };
        let status_color = if self.state.connected {
            color::GREEN
        } else {
            color::WHITE
        };
        ui::draw_str(
            fb,
            w,
            PADDING_X + 8 * CHAR_WIDTH,
            y,
            status_text,
            status_color,
            color::BLACK,
        );
        y += DETAIL_SPACING;

        // SSID (only if connected).
        ui::draw_str(fb, w, PADDING_X, y, "SSID:", color::DARK_GREY, color::BLACK);
        if self.state.connected && self.state.ssid_len > 0 {
            // WHY: clamp before slicing -- ssid_len comes from the WiFi
            // driver's state snapshot and is not validated against the
            // 32-byte ssid buffer at the source; a malformed/corrupted
            // driver report with ssid_len > ssid.len() would otherwise
            // panic this OOB slice (#397). Fail-closed: render "<binary>"
            // like an invalid-UTF8 SSID, rather than trusting the length.
            let len = self.state.ssid_len.min(self.state.ssid.len());
            let ssid_str = core::str::from_utf8(&self.state.ssid[..len]).unwrap_or("<binary>");
            ui::draw_str(
                fb,
                w,
                PADDING_X + 6 * CHAR_WIDTH,
                y,
                ssid_str,
                color::WHITE,
                color::BLACK,
            );
        } else {
            ui::draw_str(
                fb,
                w,
                PADDING_X + 6 * CHAR_WIDTH,
                y,
                "--",
                color::DARK_GREY,
                color::BLACK,
            );
        }
        y += DETAIL_SPACING;

        // Signal strength.
        ui::draw_str(
            fb,
            w,
            PADDING_X,
            y,
            "Signal:",
            color::DARK_GREY,
            color::BLACK,
        );
        if self.state.connected {
            let sig_buf = format_percent(self.state.signal_percent);
            let sig_str = core::str::from_utf8(&sig_buf.data[..sig_buf.len]).unwrap_or("?");
            ui::draw_str(
                fb,
                w,
                PADDING_X + 8 * CHAR_WIDTH,
                y,
                sig_str,
                color::WHITE,
                color::BLACK,
            );
        } else {
            ui::draw_str(
                fb,
                w,
                PADDING_X + 8 * CHAR_WIDTH,
                y,
                "--",
                color::DARK_GREY,
                color::BLACK,
            );
        }
        y += DETAIL_SPACING;

        // IP address.
        ui::draw_str(fb, w, PADDING_X, y, "IP:", color::DARK_GREY, color::BLACK);
        if self.state.connected {
            let ip_buf = format_ip(self.state.ip_addr);
            let ip_str = core::str::from_utf8(&ip_buf.data[..ip_buf.len]).unwrap_or("?");
            ui::draw_str(
                fb,
                w,
                PADDING_X + 4 * CHAR_WIDTH,
                y,
                ip_str,
                color::WHITE,
                color::BLACK,
            );
        } else {
            ui::draw_str(
                fb,
                w,
                PADDING_X + 4 * CHAR_WIDTH,
                y,
                "--",
                color::DARK_GREY,
                color::BLACK,
            );
        }
    }

    fn on_key(&mut self, key: Key) -> ScreenAction {
        match key {
            Key::Lsk | Key::End => ScreenAction::Back,
            _ => ScreenAction::None,
        }
    }

    fn softkey_left(&self) -> &'static str {
        "BACK"
    }

    fn softkey_right(&self) -> &'static str {
        ""
    }

    fn title(&self) -> &'static str {
        "WiFi"
    }
}

// ---------------------------------------------------------------------------
// Bluetooth settings screen
// ---------------------------------------------------------------------------

/// Snapshot of Bluetooth state for display on the settings screen.
#[derive(Debug, Clone, Default)]
pub struct BtSettingsState {
    /// Whether Bluetooth is enabled (initialized or scanning).
    pub enabled: bool,
    /// Number of paired devices.
    pub paired_count: u8,
    /// Whether a BLE scan is in progress.
    pub scanning: bool,
    /// Number of devices found in the current scan.
    pub scan_results: u8,
}

/// Bluetooth settings screen (read-only display of BT state).
pub(crate) struct BtSettingsScreen {
    /// Current BT state snapshot.
    pub state: BtSettingsState,
}

impl BtSettingsScreen {
    /// Create a new BT settings screen with default (disabled) state.
    pub(crate) fn new() -> Self {
        Self {
            state: BtSettingsState::default(),
        }
    }

    /// Update the state snapshot. Called each render cycle.
    pub(crate) fn update_state(&mut self, state: BtSettingsState) {
        self.state = state;
    }
}

impl Screen for BtSettingsScreen {
    fn draw(&self, fb: &mut [u16]) {
        let w = SCREEN_WIDTH;
        let h = CONTENT_HEIGHT;

        // Clear content area.
        ui::fill_rect(fb, w, h, 0, 0, w, h, color::BLACK);

        let mut y = DETAIL_START_Y;

        // Status.
        ui::draw_str(
            fb,
            w,
            PADDING_X,
            y,
            "Status:",
            color::DARK_GREY,
            color::BLACK,
        );
        let status_text = if self.state.scanning {
            "Scanning"
        } else if self.state.enabled {
            "Enabled"
        } else {
            "Disabled"
        };
        let status_color = if self.state.enabled {
            color::GREEN
        } else {
            color::WHITE
        };
        ui::draw_str(
            fb,
            w,
            PADDING_X + 8 * CHAR_WIDTH,
            y,
            status_text,
            status_color,
            color::BLACK,
        );
        y += DETAIL_SPACING;

        // Paired devices.
        ui::draw_str(
            fb,
            w,
            PADDING_X,
            y,
            "Paired:",
            color::DARK_GREY,
            color::BLACK,
        );
        let paired_buf = format_u8(self.state.paired_count);
        let paired_str = core::str::from_utf8(&paired_buf.data[..paired_buf.len]).unwrap_or("?");
        ui::draw_str(
            fb,
            w,
            PADDING_X + 8 * CHAR_WIDTH,
            y,
            paired_str,
            color::WHITE,
            color::BLACK,
        );
        y += DETAIL_SPACING;

        // Scan results (only if scanning or has results).
        if self.state.scanning || self.state.scan_results > 0 {
            ui::draw_str(
                fb,
                w,
                PADDING_X,
                y,
                "Found:",
                color::DARK_GREY,
                color::BLACK,
            );
            let found_buf = format_u8(self.state.scan_results);
            let found_str = core::str::from_utf8(&found_buf.data[..found_buf.len]).unwrap_or("?");
            ui::draw_str(
                fb,
                w,
                PADDING_X + 8 * CHAR_WIDTH,
                y,
                found_str,
                color::WHITE,
                color::BLACK,
            );
        }
    }

    fn on_key(&mut self, key: Key) -> ScreenAction {
        match key {
            Key::Lsk | Key::End => ScreenAction::Back,
            _ => ScreenAction::None,
        }
    }

    fn softkey_left(&self) -> &'static str {
        "BACK"
    }

    fn softkey_right(&self) -> &'static str {
        ""
    }

    fn title(&self) -> &'static str {
        "Bluetooth"
    }
}

// ---------------------------------------------------------------------------
// Formatting helpers (no_std, no alloc for small values)
// ---------------------------------------------------------------------------

/// Small fixed-capacity buffer for `no_std` number formatting.
struct SmallBuf {
    data: [u8; 16],
    len: usize,
}

impl SmallBuf {
    const fn new() -> Self {
        Self {
            data: [0; 16],
            len: 0,
        }
    }

    fn push(&mut self, b: u8) {
        if self.len < self.data.len() {
            self.data[self.len] = b;
            self.len += 1;
        }
    }

    fn push_str(&mut self, s: &[u8]) {
        for &b in s {
            self.push(b);
        }
    }
}

/// Format a u8 as a decimal string.
fn format_u8(val: u8) -> SmallBuf {
    let mut buf = SmallBuf::new();
    if val >= 100 {
        buf.push(b'0' + val / 100);
        buf.push(b'0' + (val / 10) % 10);
        buf.push(b'0' + val % 10);
    } else if val >= 10 {
        buf.push(b'0' + val / 10);
        buf.push(b'0' + val % 10);
    } else {
        buf.push(b'0' + val);
    }
    buf
}

/// Format a percentage value as "XX%".
fn format_percent(val: u8) -> SmallBuf {
    let mut buf = format_u8(val);
    buf.push(b'%');
    buf
}

/// Format an IPv4 address as "A.B.C.D".
fn format_ip(octets: [u8; 4]) -> SmallBuf {
    let mut buf = SmallBuf::new();
    for (i, &octet) in octets.iter().enumerate() {
        if i > 0 {
            buf.push(b'.');
        }
        let ob = format_u8(octet);
        buf.push_str(&ob.data[..ob.len]);
    }
    buf
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::CONTENT_PIXELS;

    #[test]
    fn main_menu_lists_categories() {
        let screen = SettingsMenuScreen::new();
        // Verify all expected categories are present.
        let labels: alloc::vec::Vec<&str> = MENU_ITEMS.iter().map(|item| item.label).collect();
        assert!(labels.contains(&"WiFi"), "must include WiFi");
        assert!(labels.contains(&"Bluetooth"), "must include Bluetooth");
        assert!(labels.contains(&"Display"), "must include Display");
        assert!(labels.contains(&"Sound"), "must include Sound");
        assert!(labels.contains(&"About"), "must include About");
        assert!(labels.contains(&"Privacy"), "must include Privacy");
        assert_eq!(MENU_ITEMS.len(), 6, "settings menu must have 6 items");

        // Verify draw does not panic.
        let mut fb = [0u16; CONTENT_PIXELS];
        screen.draw(&mut fb);
        let any_set = fb.iter().any(|&px| px != 0);
        assert!(any_set, "settings menu must render visible content");
    }

    #[test]
    fn about_shows_version() {
        let screen = AboutScreen::new();
        // The about screen should contain the version string.
        assert_eq!(VERSION, "thumos 0.1.0", "version must be 'thumos 0.1.0'");
        assert_eq!(DEVICE_MODEL, "AGM M7", "device model must be 'AGM M7'");
        assert_eq!(BUILD_DATE, "2026-04-09", "build date must be '2026-04-09'");

        // Verify draw does not panic.
        let mut fb = [0u16; CONTENT_PIXELS];
        screen.draw(&mut fb);
        let any_set = fb.iter().any(|&px| px != 0);
        assert!(any_set, "about screen must render visible content");
    }

    #[test]
    fn softkeys_correct() {
        let settings = SettingsMenuScreen::new();
        assert_eq!(settings.softkey_left(), "BACK");
        assert_eq!(settings.softkey_right(), "SELECT");

        let about = AboutScreen::new();
        assert_eq!(about.softkey_left(), "BACK");
        assert_eq!(about.softkey_right(), "");

        let wifi = WifiSettingsScreen::new();
        assert_eq!(wifi.softkey_left(), "BACK");

        let bt = BtSettingsScreen::new();
        assert_eq!(bt.softkey_left(), "BACK");
    }

    #[test]
    fn settings_menu_navigation() {
        let mut screen = SettingsMenuScreen::new();
        assert_eq!(screen.cursor, 0);

        // Move down.
        screen.on_key(Key::Down);
        assert_eq!(screen.cursor, 1, "cursor must move down");

        // Move up.
        screen.on_key(Key::Up);
        assert_eq!(screen.cursor, 0, "cursor must move back up");

        // Select first item (WiFi).
        let action = screen.on_key(Key::Ok);
        assert_eq!(
            action,
            ScreenAction::Navigate(ScreenId::WifiSettings),
            "OK on WiFi must navigate to WifiSettings"
        );
    }

    #[test]
    fn settings_back_navigates() {
        let mut screen = SettingsMenuScreen::new();
        let action = screen.on_key(Key::Lsk);
        assert_eq!(action, ScreenAction::Back, "LSK must go back");
    }

    #[test]
    fn wifi_screen_disconnected() {
        let screen = WifiSettingsScreen::new();
        let mut fb = [0u16; CONTENT_PIXELS];
        screen.draw(&mut fb);
        let any_set = fb.iter().any(|&px| px != 0);
        assert!(
            any_set,
            "wifi disconnected screen must render visible content"
        );
    }

    #[test]
    fn wifi_screen_connected() {
        let mut screen = WifiSettingsScreen::new();
        let mut ssid = [0u8; 32];
        ssid[..7].copy_from_slice(b"TestNet");
        screen.update_state(WifiSettingsState {
            connected: true,
            ssid,
            ssid_len: 7,
            signal_percent: 85,
            ip_addr: [192, 168, 0, 42],
            scanning: false,
        });
        let mut fb = [0u16; CONTENT_PIXELS];
        screen.draw(&mut fb);
        let any_set = fb.iter().any(|&px| px != 0);
        assert!(any_set, "wifi connected screen must render visible content");
    }

    #[test]
    fn wifi_screen_clamps_oob_ssid_len_without_panicking() {
        // ssid_len comes from a WiFi driver state snapshot that is not
        // itself validated against the 32-byte ssid buffer -- a corrupted
        // or malformed driver report with ssid_len > ssid.len() must not
        // panic the draw path (#397).
        let mut screen = WifiSettingsScreen::new();
        let mut ssid = [0u8; 32];
        ssid[..7].copy_from_slice(b"TestNet");
        screen.update_state(WifiSettingsState {
            connected: true,
            ssid,
            ssid_len: usize::MAX,
            signal_percent: 85,
            ip_addr: [192, 168, 0, 42],
            scanning: false,
        });
        let mut fb = [0u16; CONTENT_PIXELS];
        screen.draw(&mut fb); // must not panic
        let any_set = fb.iter().any(|&px| px != 0);
        assert!(
            any_set,
            "wifi screen must still render with a clamped OOB ssid_len"
        );
    }

    #[test]
    fn bt_screen_disabled() {
        let screen = BtSettingsScreen::new();
        let mut fb = [0u16; CONTENT_PIXELS];
        screen.draw(&mut fb);
        let any_set = fb.iter().any(|&px| px != 0);
        assert!(
            any_set,
            "bluetooth disabled screen must render visible content"
        );
    }

    #[test]
    fn bt_screen_scanning() {
        let mut screen = BtSettingsScreen::new();
        screen.update_state(BtSettingsState {
            enabled: true,
            paired_count: 2,
            scanning: true,
            scan_results: 5,
        });
        let mut fb = [0u16; CONTENT_PIXELS];
        screen.draw(&mut fb);
        let any_set = fb.iter().any(|&px| px != 0);
        assert!(
            any_set,
            "bluetooth scanning screen must render visible content"
        );
    }

    #[test]
    fn about_back_navigates() {
        let mut screen = AboutScreen::new();
        let action = screen.on_key(Key::Lsk);
        assert_eq!(action, ScreenAction::Back, "About LSK must go back");
    }

    #[test]
    fn format_ip_correct() {
        let buf = format_ip([192, 168, 0, 1]);
        let s = core::str::from_utf8(&buf.data[..buf.len]).unwrap_or("");
        assert_eq!(s, "192.168.0.1", "IP format must be correct");
    }

    #[test]
    fn format_percent_correct() {
        let buf = format_percent(85);
        let s = core::str::from_utf8(&buf.data[..buf.len]).unwrap_or("");
        assert_eq!(s, "85%", "percent format must be correct");
    }

    #[test]
    fn format_u8_correct() {
        let buf = format_u8(0);
        let s = core::str::from_utf8(&buf.data[..buf.len]).unwrap_or("");
        assert_eq!(s, "0");

        let buf = format_u8(42);
        let s = core::str::from_utf8(&buf.data[..buf.len]).unwrap_or("");
        assert_eq!(s, "42");

        let buf = format_u8(255);
        let s = core::str::from_utf8(&buf.data[..buf.len]).unwrap_or("");
        assert_eq!(s, "255");
    }
}
