//! Centralized threat monitor screen for the thumos kernel UI.
//!
//! Implements the [`Screen`] trait to display a unified view of all Phase 10
//! radio intelligence subsystems: IMSI catcher detection, BLE tracker
//! alerts, deauth attack detection, CCCI anomaly flagging, geofence breach
//! warnings, Silent SMS detection, and WAP Push rejection.
//!
//! ## Layout (240x320)
//!
//! | Zone             | Height | Content                                     |
//! |------------------|--------|---------------------------------------------|
//! | Top bar          | 40px   | Threat level color bar + numeric score       |
//! | Alert list       | 200px  | Scrollable recent alerts, newest first       |
//! | Modem status     | 30px   | Channel count, firewall mode, power state    |
//!
//! ## Softkeys
//!
//! - LSK: "DETAILS" — show full alert info for selected entry
//! - RSK: "KILL MODEM" — trigger modem PMIC power cut via power.rs
//! - End: BACK
//!
//! ## Integration
//!
//! Accessible from `screen_search.rs` via function search "Threat Monitor"
//! (`ScreenId::ThreatMonitor`), and from the status bar threat indicator.

// WHY: threat monitor screen created in Phase 10 Wave 5, kinit wiring pending.
#![expect(
    dead_code,
    reason = "Threat monitor screen created in Phase 10 Wave 5, kinit wiring pending"
)]

extern crate alloc;
use core::fmt;

use alloc::string::String;
use alloc::vec::Vec;

use crate::ui::{
    self, color, Key, Screen, ScreenAction,
    CHAR_HEIGHT, CONTENT_HEIGHT, SCREEN_WIDTH,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Height of the threat level top bar.
const TOP_BAR_HEIGHT: u16 = 40;

/// Height of the alert list zone.
const ALERT_LIST_HEIGHT: u16 = 200;

/// Height of the modem status zone.
const MODEM_STATUS_HEIGHT: u16 = CONTENT_HEIGHT - TOP_BAR_HEIGHT - ALERT_LIST_HEIGHT;

/// Y offset where the alert list begins.
const ALERT_LIST_Y: u16 = TOP_BAR_HEIGHT;

/// Y offset where the modem status zone begins.
const MODEM_STATUS_Y: u16 = TOP_BAR_HEIGHT + ALERT_LIST_HEIGHT;

/// Height of each alert row in the list.
const ALERT_ROW_HEIGHT: u16 = CHAR_HEIGHT + 6;

/// Maximum number of visible alert rows.
const VISIBLE_ALERTS: usize = (ALERT_LIST_HEIGHT / ALERT_ROW_HEIGHT) as usize;

/// Left padding for text in all zones.
const PADDING_X: u16 = 4;

/// Maximum number of alerts retained in the ring buffer.
const MAX_ALERTS: usize = 64;

/// Maximum length of an alert description string.
const MAX_DESC_LEN: usize = 48;

/// RGB565 orange for HIGH threat level.
const COLOR_ORANGE: u16 = color::from_rgb(255, 165, 0);

// ---------------------------------------------------------------------------
// Threat level (matches sema crate convention)
// ---------------------------------------------------------------------------

/// Threat severity level, ordered from lowest to highest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[must_use]
#[non_exhaustive]
pub enum ThreatLevel {
    /// No active threats detected.
    Low,
    /// Minor anomalies that may warrant attention.
    Medium,
    /// Active threat indicators present.
    High,
    /// Confirmed active attack or compromise.
    Critical,
}

impl ThreatLevel {
    /// RGB565 color for this threat level.
    const fn color(self) -> u16 {
        match self {
            Self::Low => color::GREEN,
            Self::Medium => color::YELLOW,
            Self::High => COLOR_ORANGE,
            Self::Critical => color::RED,
        }
    }

    /// Display label for the threat level.
    const fn label(self) -> &'static str {
        match self {
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
            Self::Critical => "CRITICAL",
        }
    }
}

impl Default for ThreatLevel {
    fn default() -> Self {
        Self::Low
    }
}

impl fmt::Display for ThreatLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ---------------------------------------------------------------------------
// Alert types
// ---------------------------------------------------------------------------

/// Type of threat alert detected by the radio intelligence subsystems.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
#[non_exhaustive]
pub enum ThreatAlertType {
    /// IMSI catcher / rogue base station detected.
    ImsiCatcher,
    /// BLE tracker device following the user.
    BleTracker,
    /// WiFi deauthentication attack in progress.
    DeauthAttack,
    /// CCCI modem traffic anomaly detected.
    CcciAnomaly,
    /// Device has left a defined geofence.
    GeofenceBreach,
    /// Silent SMS (Type 0) received and blocked.
    SilentSms,
    /// WAP Push message rejected by firewall.
    WapPushRejected,
    /// Modem behavior anomaly (unexpected power/channel changes).
    ModemAnomaly,
}

impl ThreatAlertType {
    /// Single-character icon for the alert list display.
    const fn icon(self) -> char {
        match self {
            Self::ImsiCatcher => 'I',
            Self::BleTracker => 'B',
            Self::DeauthAttack => 'D',
            Self::CcciAnomaly => 'C',
            Self::GeofenceBreach => 'G',
            Self::SilentSms => 'S',
            Self::WapPushRejected => 'W',
            Self::ModemAnomaly => 'M',
        }
    }
}

impl fmt::Display for ThreatAlertType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ImsiCatcher => f.write_str("IMSI_CATCHER"),
            Self::BleTracker => f.write_str("BLE_TRACKER"),
            Self::DeauthAttack => f.write_str("DEAUTH_ATTACK"),
            Self::CcciAnomaly => f.write_str("CCCI_ANOMALY"),
            Self::GeofenceBreach => f.write_str("GEOFENCE_BREACH"),
            Self::SilentSms => f.write_str("SILENT_SMS"),
            Self::WapPushRejected => f.write_str("WAP_PUSH_REJECTED"),
            Self::ModemAnomaly => f.write_str("MODEM_ANOMALY"),
        }
    }
}

// ---------------------------------------------------------------------------
// Firewall mode
// ---------------------------------------------------------------------------

/// Modem firewall operating mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
#[non_exhaustive]
pub enum FirewallMode {
    /// All traffic permitted (monitoring only).
    Open,
    /// Suspicious traffic blocked, normal traffic allowed.
    Restricted,
    /// All modem traffic blocked.
    Blocked,
}

impl FirewallMode {
    /// Display label for the firewall mode.
    const fn label(self) -> &'static str {
        match self {
            Self::Open => "OPEN",
            Self::Restricted => "RESTRICTED",
            Self::Blocked => "BLOCKED",
        }
    }

    /// Color for the firewall mode indicator.
    const fn color(self) -> u16 {
        match self {
            Self::Open => color::GREEN,
            Self::Restricted => color::YELLOW,
            Self::Blocked => color::RED,
        }
    }
}

impl Default for FirewallMode {
    fn default() -> Self {
        Self::Open
    }
}

impl fmt::Display for FirewallMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ---------------------------------------------------------------------------
// Threat alert
// ---------------------------------------------------------------------------

/// A single threat alert event.
#[derive(Debug, Clone)]
#[must_use]
pub struct ThreatAlert {
    /// Monotonic timestamp (kernel ticks, milliseconds).
    pub timestamp: u64,
    /// Type of threat detected.
    pub alert_type: ThreatAlertType,
    /// Human-readable description (truncated to `MAX_DESC_LEN`).
    pub description: String,
    /// Severity of this alert.
    pub severity: ThreatLevel,
}

// ---------------------------------------------------------------------------
// Threat monitor state
// ---------------------------------------------------------------------------

/// Centralized threat monitor aggregating all radio intelligence alerts.
///
/// Maintains a ring buffer of recent alerts sorted by timestamp (newest
/// first for display) and tracks the overall threat posture.
pub(crate) struct ThreatMonitor {
    /// Recent alerts, newest first.
    alerts: Vec<ThreatAlert>,
    /// Current composite threat score (0-100).
    current_score: u32,
    /// Current overall threat level.
    current_level: ThreatLevel,
    /// Number of active modem channels.
    modem_channels: u8,
    /// Current firewall operating mode.
    firewall_mode: FirewallMode,
    /// Whether the modem is powered on.
    modem_power: bool,
    /// Scroll offset in the alert list.
    scroll_offset: usize,
    /// Currently selected alert index.
    cursor: usize,
}

impl ThreatMonitor {
    /// Create a new threat monitor with no alerts and default state.
    pub(crate) fn new() -> Self {
        Self {
            alerts: Vec::new(),
            current_score: 0,
            current_level: ThreatLevel::Low,
            modem_channels: 0,
            firewall_mode: FirewallMode::Open,
            modem_power: true,
            scroll_offset: 0,
            cursor: 0,
        }
    }

    /// Add a new alert, maintaining newest-first order and the
    /// `MAX_ALERTS` capacity limit.
    pub(crate) fn push_alert(&mut self, alert: ThreatAlert) {
        // Insert at position determined by timestamp (newest first).
        let pos = self.alerts
            .iter()
            .position(|a| a.timestamp < alert.timestamp)
            .unwrap_or(self.alerts.len());
        self.alerts.insert(pos, alert);

        // Trim oldest alerts beyond capacity.
        while self.alerts.len() > MAX_ALERTS {
            self.alerts.pop();
        }
    }

    /// Update the composite threat score and level.
    pub(crate) fn set_score(&mut self, score: u32) {
        self.current_score = score.min(100);
        self.current_level = match self.current_score {
            0..=25 => ThreatLevel::Low,
            26..=50 => ThreatLevel::Medium,
            51..=75 => ThreatLevel::High,
            _ => ThreatLevel::Critical,
        };
    }

    /// Update modem status fields.
    pub(crate) fn set_modem_status(&mut self, channels: u8, mode: FirewallMode, power: bool) {
        self.modem_channels = channels;
        self.firewall_mode = mode;
        self.modem_power = power;
    }

    /// Get the current threat level.
    pub(crate) fn threat_level(&self) -> ThreatLevel {
        self.current_level
    }

    /// Get the current threat score.
    pub(crate) fn threat_score(&self) -> u32 {
        self.current_score
    }

    /// Number of alerts currently stored.
    pub(crate) fn alert_count(&self) -> usize {
        self.alerts.len()
    }

    /// Adjust scroll offset to keep cursor visible.
    fn adjust_scroll(&mut self) {
        if self.cursor < self.scroll_offset {
            self.scroll_offset = self.cursor;
        } else if self.cursor >= self.scroll_offset + VISIBLE_ALERTS {
            self.scroll_offset = self.cursor + 1 - VISIBLE_ALERTS;
        }
    }

    /// Format the threat score as a static-ish string for display.
    ///
    /// Returns a 3-character buffer with the numeric score (right-aligned).
    fn score_text(&self) -> [u8; 4] {
        let s = self.current_score;
        let d2 = b'0' + (s / 100 % 10) as u8;
        let d1 = b'0' + (s / 10 % 10) as u8;
        let d0 = b'0' + (s % 10) as u8;
        if s >= 100 {
            [d2, d1, d0, 0]
        } else if s >= 10 {
            [b' ', d1, d0, 0]
        } else {
            [b' ', b' ', d0, 0]
        }
    }

    /// Format a timestamp as MM:SS for compact display.
    ///
    /// Timestamps are kernel ticks in milliseconds; this shows
    /// minutes:seconds of the raw tick value for relative ordering.
    fn format_time(timestamp: u64) -> [u8; 6] {
        let total_secs = timestamp / 1000;
        let mins = (total_secs / 60) % 100;
        let secs = total_secs % 60;
        [
            b'0' + (mins / 10 % 10) as u8,
            b'0' + (mins % 10) as u8,
            b':',
            b'0' + (secs / 10) as u8,
            b'0' + (secs % 10) as u8,
            0,
        ]
    }
}

impl Default for ThreatMonitor {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Screen implementation
// ---------------------------------------------------------------------------

impl Screen for ThreatMonitor {
    fn draw(&self, fb: &mut [u16]) {
        let w = SCREEN_WIDTH;
        let h = CONTENT_HEIGHT;

        // Clear content area.
        ui::fill_rect(fb, w, h, 0, 0, w, h, color::BLACK);

        // --- Top bar: threat level color bar + numeric score ---
        let level_color = self.current_level.color();
        // Fill the entire top bar with the threat level color.
        ui::fill_rect(fb, w, h, 0, 0, w, TOP_BAR_HEIGHT, level_color);

        // Draw threat level label (centered, black text on colored bar).
        let label = self.current_level.label();
        let label_y = (TOP_BAR_HEIGHT.saturating_sub(CHAR_HEIGHT)) / 2;
        ui::draw_str_centered(fb, w, 0, w / 2, label_y, label, color::BLACK, level_color);

        // Draw numeric score on the right side of the bar.
        let score_buf = self.score_text();
        let score_str = core::str::from_utf8(&score_buf[..3]).unwrap_or("  0");
        let score_x = w / 2 + 20;
        ui::draw_str(fb, w, score_x, label_y, score_str, color::BLACK, level_color);

        // --- Alert list ---
        if self.alerts.is_empty() {
            // Show "No alerts" message.
            let no_alerts_y = ALERT_LIST_Y + ALERT_LIST_HEIGHT / 2 - CHAR_HEIGHT / 2;
            ui::draw_str_centered(
                fb, w, 0, w, no_alerts_y,
                "No alerts", color::DARK_GREY, color::BLACK,
            );
        } else {
            let visible_end = (self.scroll_offset + VISIBLE_ALERTS).min(self.alerts.len());
            for (vi, ai) in (self.scroll_offset..visible_end).enumerate() {
                let alert = &self.alerts[ai];
                let row_y = ALERT_LIST_Y + (vi as u16) * ALERT_ROW_HEIGHT;

                // Highlight selected row.
                let (fg, bg) = if ai == self.cursor {
                    (color::BLACK, color::WHITE)
                } else {
                    (color::WHITE, color::BLACK)
                };

                if ai == self.cursor {
                    ui::fill_rect(fb, w, h, 0, row_y, w, ALERT_ROW_HEIGHT, color::WHITE);
                }

                // Timestamp (MM:SS).
                let time_buf = Self::format_time(alert.timestamp);
                let time_str = core::str::from_utf8(&time_buf[..5]).unwrap_or("00:00");
                ui::draw_str(fb, w, PADDING_X, row_y + 3, time_str, fg, bg);

                // Type icon.
                let icon = alert.alert_type.icon();
                let icon_x = PADDING_X + 6 * 8; // after timestamp
                ui::draw_char(fb, w, icon_x, row_y + 3, icon, alert.severity.color(), bg);

                // Description (truncated to fit).
                let desc_x = icon_x + 2 * 8;
                let max_chars = ((w - desc_x) / 8) as usize;
                let desc = if alert.description.len() > max_chars {
                    &alert.description[..max_chars]
                } else {
                    &alert.description
                };
                ui::draw_str(fb, w, desc_x, row_y + 3, desc, fg, bg);
            }

            // Scroll indicators.
            if self.scroll_offset > 0 {
                ui::draw_char(fb, w, w - 12, ALERT_LIST_Y + 2, '^', color::DARK_GREY, color::BLACK);
            }
            if visible_end < self.alerts.len() {
                let arrow_y = ALERT_LIST_Y + ALERT_LIST_HEIGHT - CHAR_HEIGHT - 2;
                ui::draw_char(fb, w, w - 12, arrow_y, 'v', color::DARK_GREY, color::BLACK);
            }
        }

        // --- Separator above modem status ---
        ui::fill_rect(fb, w, h, PADDING_X, MODEM_STATUS_Y, w - PADDING_X * 2, 1, color::DARK_GREY);

        // --- Modem status zone ---
        let status_y = MODEM_STATUS_Y + 4;

        // Channel count.
        let ch_label = "CH:";
        ui::draw_str(fb, w, PADDING_X, status_y, ch_label, color::DARK_GREY, color::BLACK);
        let ch_digit = b'0' + self.modem_channels.min(9);
        let ch_str: [u8; 2] = [ch_digit, 0];
        let ch_text = core::str::from_utf8(&ch_str[..1]).unwrap_or("0");
        ui::draw_str(fb, w, PADDING_X + 3 * 8, status_y, ch_text, color::WHITE, color::BLACK);

        // Firewall mode.
        let fw_label = self.firewall_mode.label();
        let fw_x = PADDING_X + 6 * 8;
        ui::draw_str(fb, w, fw_x, status_y, fw_label, self.firewall_mode.color(), color::BLACK);

        // Power state.
        let (pwr_label, pwr_color) = if self.modem_power {
            ("ON", color::GREEN)
        } else {
            ("KILLED", color::RED)
        };
        let pwr_x = w - PADDING_X - (pwr_label.len() as u16) * 8;
        ui::draw_str(fb, w, pwr_x, status_y, pwr_label, pwr_color, color::BLACK);
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
                if !self.alerts.is_empty() && self.cursor < self.alerts.len() - 1 {
                    self.cursor += 1;
                    self.adjust_scroll();
                }
                ScreenAction::None
            }
            // LSK: DETAILS — for now, a no-op (detail view is a future wave).
            Key::Lsk => ScreenAction::None,
            // RSK: KILL MODEM — triggers modem power cut.
            Key::Rsk => ScreenAction::KillModem,
            // End: BACK.
            Key::End => ScreenAction::Back,
            _ => ScreenAction::None,
        }
    }

    fn softkey_left(&self) -> &'static str {
        "DETAILS"
    }

    fn softkey_right(&self) -> &'static str {
        "KILL MODEM"
    }

    fn title(&self) -> &'static str {
        "Threat Monitor"
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::CONTENT_PIXELS;

    fn make_alert(timestamp: u64, alert_type: ThreatAlertType, severity: ThreatLevel) -> ThreatAlert {
        ThreatAlert {
            timestamp,
            alert_type,
            description: String::from("test alert"),
            severity,
        }
    }

    #[test]
    fn alert_list_sorts_by_time_newest_first() {
        let mut monitor = ThreatMonitor::new();
        monitor.push_alert(make_alert(1000, ThreatAlertType::SilentSms, ThreatLevel::Medium));
        monitor.push_alert(make_alert(3000, ThreatAlertType::ImsiCatcher, ThreatLevel::Critical));
        monitor.push_alert(make_alert(2000, ThreatAlertType::BleTracker, ThreatLevel::Low));

        assert_eq!(monitor.alert_count(), 3);
        assert_eq!(
            monitor.alerts[0].timestamp, 3000,
            "newest alert must be first"
        );
        assert_eq!(
            monitor.alerts[1].timestamp, 2000,
            "middle alert must be second"
        );
        assert_eq!(
            monitor.alerts[2].timestamp, 1000,
            "oldest alert must be last"
        );
    }

    #[test]
    fn threat_level_renders_correct_color() {
        assert_eq!(
            ThreatLevel::Low.color(), color::GREEN,
            "LOW must render green"
        );
        assert_eq!(
            ThreatLevel::Medium.color(), color::YELLOW,
            "MEDIUM must render yellow"
        );
        assert_eq!(
            ThreatLevel::High.color(), COLOR_ORANGE,
            "HIGH must render orange"
        );
        assert_eq!(
            ThreatLevel::Critical.color(), color::RED,
            "CRITICAL must render red"
        );
    }

    #[test]
    fn kill_modem_softkey_returns_correct_action() {
        let mut monitor = ThreatMonitor::new();
        let action = monitor.on_key(Key::Rsk);
        assert_eq!(
            action,
            ScreenAction::KillModem,
            "RSK must return KillModem action"
        );
    }

    #[test]
    fn alert_type_display() {
        use alloc::format;

        assert_eq!(ThreatAlertType::ImsiCatcher.to_string(), "IMSI_CATCHER");
        assert_eq!(ThreatAlertType::BleTracker.to_string(), "BLE_TRACKER");
        assert_eq!(ThreatAlertType::DeauthAttack.to_string(), "DEAUTH_ATTACK");
        assert_eq!(ThreatAlertType::CcciAnomaly.to_string(), "CCCI_ANOMALY");
        assert_eq!(ThreatAlertType::GeofenceBreach.to_string(), "GEOFENCE_BREACH");
        assert_eq!(ThreatAlertType::SilentSms.to_string(), "SILENT_SMS");
        assert_eq!(ThreatAlertType::WapPushRejected.to_string(), "WAP_PUSH_REJECTED");
        assert_eq!(ThreatAlertType::ModemAnomaly.to_string(), "MODEM_ANOMALY");
    }

    #[test]
    fn screen_renders_without_panic() {
        let monitor = ThreatMonitor::new();
        let mut fb = [0u16; CONTENT_PIXELS];
        monitor.draw(&mut fb);
        let any_set = fb.iter().any(|&px| px != 0);
        assert!(any_set, "threat monitor must render visible content");
    }

    #[test]
    fn screen_renders_with_alerts_without_panic() {
        let mut monitor = ThreatMonitor::new();
        monitor.push_alert(make_alert(1000, ThreatAlertType::SilentSms, ThreatLevel::Medium));
        monitor.push_alert(make_alert(2000, ThreatAlertType::ImsiCatcher, ThreatLevel::Critical));
        monitor.set_score(80);
        let mut fb = [0u16; CONTENT_PIXELS];
        monitor.draw(&mut fb);
        let any_set = fb.iter().any(|&px| px != 0);
        assert!(any_set, "threat monitor with alerts must render visible content");
    }

    #[test]
    fn threat_level_display() {
        use alloc::format;

        assert_eq!(ThreatLevel::Low.to_string(), "LOW");
        assert_eq!(ThreatLevel::Medium.to_string(), "MEDIUM");
        assert_eq!(ThreatLevel::High.to_string(), "HIGH");
        assert_eq!(ThreatLevel::Critical.to_string(), "CRITICAL");
    }

    #[test]
    fn firewall_mode_display() {
        use alloc::format;

        assert_eq!(FirewallMode::Open.to_string(), "OPEN");
        assert_eq!(FirewallMode::Restricted.to_string(), "RESTRICTED");
        assert_eq!(FirewallMode::Blocked.to_string(), "BLOCKED");
    }

    #[test]
    fn set_score_updates_level() {
        let mut monitor = ThreatMonitor::new();
        monitor.set_score(10);
        assert_eq!(monitor.threat_level(), ThreatLevel::Low);
        monitor.set_score(30);
        assert_eq!(monitor.threat_level(), ThreatLevel::Medium);
        monitor.set_score(60);
        assert_eq!(monitor.threat_level(), ThreatLevel::High);
        monitor.set_score(90);
        assert_eq!(monitor.threat_level(), ThreatLevel::Critical);
    }

    #[test]
    fn score_clamps_to_100() {
        let mut monitor = ThreatMonitor::new();
        monitor.set_score(200);
        assert_eq!(monitor.threat_score(), 100);
    }

    #[test]
    fn max_alerts_capacity() {
        let mut monitor = ThreatMonitor::new();
        for i in 0..MAX_ALERTS + 10 {
            monitor.push_alert(make_alert(i as u64, ThreatAlertType::SilentSms, ThreatLevel::Low));
        }
        assert_eq!(
            monitor.alert_count(), MAX_ALERTS,
            "alert count must not exceed MAX_ALERTS"
        );
    }

    #[test]
    fn navigation_keys() {
        let mut monitor = ThreatMonitor::new();
        monitor.push_alert(make_alert(1000, ThreatAlertType::SilentSms, ThreatLevel::Low));
        monitor.push_alert(make_alert(2000, ThreatAlertType::ImsiCatcher, ThreatLevel::High));
        monitor.push_alert(make_alert(3000, ThreatAlertType::BleTracker, ThreatLevel::Medium));

        // Starts at cursor 0.
        assert_eq!(monitor.cursor, 0);

        // Down moves cursor.
        let action = monitor.on_key(Key::Down);
        assert_eq!(action, ScreenAction::None);
        assert_eq!(monitor.cursor, 1);

        // Up moves cursor back.
        let action = monitor.on_key(Key::Up);
        assert_eq!(action, ScreenAction::None);
        assert_eq!(monitor.cursor, 0);

        // Up at top does not underflow.
        let action = monitor.on_key(Key::Up);
        assert_eq!(action, ScreenAction::None);
        assert_eq!(monitor.cursor, 0);

        // End goes back.
        let action = monitor.on_key(Key::End);
        assert_eq!(action, ScreenAction::Back);
    }

    #[test]
    fn softkeys_correct() {
        let monitor = ThreatMonitor::new();
        assert_eq!(monitor.softkey_left(), "DETAILS");
        assert_eq!(monitor.softkey_right(), "KILL MODEM");
    }

    #[test]
    fn title_is_threat_monitor() {
        let monitor = ThreatMonitor::new();
        assert_eq!(monitor.title(), "Threat Monitor");
    }

    #[test]
    fn modem_status_updates() {
        let mut monitor = ThreatMonitor::new();
        monitor.set_modem_status(3, FirewallMode::Restricted, false);
        assert_eq!(monitor.modem_channels, 3);
        assert_eq!(monitor.firewall_mode, FirewallMode::Restricted);
        assert!(!monitor.modem_power);
    }

    #[test]
    fn alert_type_icon_unique() {
        let types = [
            ThreatAlertType::ImsiCatcher,
            ThreatAlertType::BleTracker,
            ThreatAlertType::DeauthAttack,
            ThreatAlertType::CcciAnomaly,
            ThreatAlertType::GeofenceBreach,
            ThreatAlertType::SilentSms,
            ThreatAlertType::WapPushRejected,
            ThreatAlertType::ModemAnomaly,
        ];
        let mut seen = [false; 128];
        for t in &types {
            let icon = t.icon() as usize;
            assert!(
                !seen[icon],
                "icon '{}' for {:?} must be unique",
                t.icon(), t
            );
            seen[icon] = true;
        }
    }
}
