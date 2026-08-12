//! Centralized threat monitor screen for the thumos kernel UI.
//!
//! Implements the [`Screen`] trait to display a unified view of all Phase 10
//! radio intelligence subsystems: IMSI catcher detection, BLE tracker
//! alerts, deauth attack detection, CCCI anomaly flagging, geofence breach
//! warnings, and the Silent SMS / WAP Push classifications raised by the
//! SMS decoder (`crate::sms`, via `klesis_core::MessageClass`).
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
//!
//! ## Score as a lens over the log (#737)
//!
//! The design is BOTH the audit trail and the composite score, not either
//! alone: the alert log is the substrate (specific, attributable events),
//! and the top-bar score is a derived VIEW over that log, explicitly
//! labelled "UNCAL" in the rendered UI. The score is NOT sema's detector
//! engine -- `crates/sema` (IMSI-catcher/BLE-tracker/deauth analysis,
//! `crates/sema/src/{cell,wifi_analysis}.rs`) is not a thumos dependency at
//! all (only the shared `sema-core` types crate is), so its detectors
//! cannot reach `KernelState`; #555 calibrated sema's OWN corpus and never
//! wired sema into the kernel. Until that integration exists,
//! [`ThreatMonitor::recompute_score_from_log`] derives the score as a
//! simple volume/severity heuristic over whatever real alerts the log
//! holds -- currently only the SMS surveillance classification path
//! (`ThreatAlertType::from_message_class`, #662). `ImsiCatcher`,
//! `BleTracker`, `DeauthAttack`, `CcciAnomaly`, `GeofenceBreach`, and
//! `ModemAnomaly` have no producer yet and stay unconstructed outside
//! tests.

// WHY: ThreatMonitor itself is wired into KernelState (#737), fed from the
// real SMS surveillance classification path (#662). ImsiCatcher/
// BleTracker/DeauthAttack/CcciAnomaly/GeofenceBreach/ModemAnomaly and
// FirewallMode::Restricted/Blocked stay unconstructed outside tests: sema
// (crates/sema) is not a thumos dependency, so its detectors cannot reach
// KernelState (see the module doc), and no firewall-mode switch exists
// anywhere in the kernel. cfg_attr(not(test), ...): the module's tests
// construct every variant, so expecting dead_code there would be
// unfulfilled.
#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "(#753) sema (crates/sema) is not a thumos dependency, so ImsiCatcher/BleTracker/DeauthAttack/CcciAnomaly/GeofenceBreach/ModemAnomaly have no producer; FirewallMode::Restricted/Blocked have no switch anywhere in the kernel"
    )
)]

extern crate alloc;
use core::fmt;

use alloc::string::String;
use alloc::vec::Vec;

use crate::ui::{
    self, CHAR_HEIGHT, CONTENT_HEIGHT, Key, SCREEN_WIDTH, Screen, ScreenAction, color,
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
// Threat level — the canonical type from sema-core (#545)
// ---------------------------------------------------------------------------

/// The canonical threat severity level: defined ONCE in `sema_core` (the
/// `no_std+alloc` core shared with the `sema` workspace crate) and re-exported
/// here. The pre-#545 kernel copy drifted (bands 25/50/75 vs the canonical
/// 30/60/80 protocol invariants) — the exact divergence class #545 exists
/// to kill. Screen-specific presentation rides in the extension trait
/// below; semantics stay in one place.
pub use sema_core::ThreatLevel;

/// Screen-side presentation for the canonical [`ThreatLevel`].
pub(crate) trait ThreatLevelScreenExt {
    /// RGB565 color for this threat level.
    fn color(self) -> u16;
    /// Display label for this threat level.
    fn label(self) -> &'static str;
}

impl ThreatLevelScreenExt for ThreatLevel {
    // WHY: High and the non_exhaustive wildcard both resolve to COLOR_ORANGE,
    // but for different reasons -- High is orange on its own merits, the
    // wildcard is a defensive "unknown future band renders as attention,
    // never fine". Merging them into one arm would blur that distinction.
    #[expect(
        clippy::match_same_arms,
        reason = "High and the non_exhaustive wildcard both resolve to COLOR_ORANGE, but for different reasons -- High is orange on its own merits, the wildcard is a defensive unknown-future-band-renders-as-attention-never-fine; merging them into one arm would blur that distinction"
    )]
    fn color(self) -> u16 {
        match self {
            Self::Low => color::GREEN,
            Self::Medium => color::YELLOW,
            Self::High => COLOR_ORANGE,
            Self::Critical => color::RED,
            // sema-core's ThreatLevel is non_exhaustive; a future band the
            // screen doesn't know yet renders as attention, never "fine".
            _ => COLOR_ORANGE,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
            Self::Critical => "CRITICAL",
            // Non-exhaustive forward compat: unknown future bands read as
            // unknown, not as a fabricated level name.
            _ => "?",
        }
    }
}

/// Baseline weight a [`ThreatLevel`] contributes to
/// [`ThreatMonitor::recompute_score_from_log`]'s uncalibrated composite
/// score. A volume/severity heuristic, not sema's calibrated engine --
/// see the module doc.
const fn severity_weight(level: ThreatLevel) -> u32 {
    match level {
        ThreatLevel::Low => 15,
        ThreatLevel::Medium => 40,
        ThreatLevel::Critical => 95,
        // High and the non_exhaustive wildcard both read as "elevated but
        // not confirmed critical" -- same defensive shape as
        // ThreatLevelScreenExt::color above, merged into one arm since
        // both share this exact weight.
        ThreatLevel::High | _ => 70,
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
    /// `WiFi` deauthentication attack in progress.
    DeauthAttack,
    /// CCCI modem traffic anomaly detected.
    CcciAnomaly,
    /// Device has left a defined geofence.
    GeofenceBreach,
    /// Silent SMS (Type 0) received — recorded, not discarded.
    SilentSms,
    /// WAP Push / OMA-CP message received — recorded, not discarded.
    WapPushRejected,
    /// Modem behavior anomaly (unexpected power/channel changes).
    ModemAnomaly,
}

impl ThreatAlertType {
    /// The alert an incoming SMS classification raises, if any.
    ///
    /// WHY this mapping exists (#662): the `SilentSms` and
    /// `WapPushRejected` variants had no producer anywhere in the kernel —
    /// the SMS decoder read the PID and threw it away, so the alert type,
    /// its icon, and its tests described an event that could never occur.
    /// This is the seam that lets a decode result reach the screen. The
    /// remaining step is the kinit event loop, which does not yet reach the
    /// SMS path at all.
    #[must_use]
    pub(crate) const fn from_message_class(class: klesis_core::MessageClass) -> Option<Self> {
        match class {
            klesis_core::MessageClass::Normal => None,
            klesis_core::MessageClass::Silent { .. } => Some(Self::SilentSms),
            klesis_core::MessageClass::WapPush { .. } => Some(Self::WapPushRejected),
        }
    }
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[must_use]
#[non_exhaustive]
pub enum FirewallMode {
    /// All traffic permitted (monitoring only).
    #[default]
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

impl ThreatAlert {
    /// Build the alert an SMS surveillance classification raises (#662,
    /// #737): shared by the qemu boot smoke (`kardia.rs::threat_boot_smoke`)
    /// and, once a production incoming-SMS event loop exists (there is none
    /// today -- `TelephonyEvent` has no SMS-received variant), the live
    /// receive path. One construction site for what an SMS classification
    /// means as a threat log entry, rather than each caller inventing its
    /// own description/severity mapping.
    ///
    /// `Medium` for both mapped alert types: neither a silent (Type 0) SMS
    /// nor an unsolicited WAP Push / OMA-CP message alone proves a
    /// targeted attack (both have benign carrier uses), but both are the
    /// standard covert-surveillance delivery mechanisms and belong in the
    /// log rather than silently filed as ordinary mail (#662).
    pub(crate) fn from_sms_classification(timestamp: u64, alert_type: ThreatAlertType) -> Self {
        let description = match alert_type {
            ThreatAlertType::SilentSms => "Silent SMS (Type 0) received",
            ThreatAlertType::WapPushRejected => "WAP Push / OMA-CP message received",
            // WHY a catch-all: from_message_class only ever returns these
            // two variants (see its match arms above); a future addition
            // there must not silently mis-describe as one of these two.
            _ => "SMS classification alert",
        };
        Self {
            timestamp,
            alert_type,
            description: String::from(description),
            severity: ThreatLevel::Medium,
        }
    }
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
    /// Whether any detector has ever reported to this monitor (#743).
    ///
    /// INVARIANT: false means "nothing is watching", which is NOT the same
    /// state as "watching, nothing found". Only a real detector report sets
    /// it -- see `mark_detector_online`. While false the screen suppresses
    /// the score entirely rather than rendering 0, because a score is a
    /// claim and there is nothing to claim.
    detector_online: bool,
    /// Scroll offset in the alert list.
    scroll_offset: usize,
    /// Currently selected alert index.
    cursor: usize,
}

/// Truncate `s` to at most `max_bytes`, backing off to the nearest earlier
/// UTF-8 char boundary so a multi-byte codepoint is never split (#396).
fn truncate_at_char_boundary(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
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
            detector_online: false,
            scroll_offset: 0,
            cursor: 0,
        }
    }

    /// Record that a detector is reporting to this monitor (#743).
    ///
    /// A detector that has scanned and found nothing MUST call this, so the
    /// screen can distinguish that from no detector running at all. Pushing
    /// an alert implies it; this exists for the found-nothing case, which
    /// otherwise looks identical to silence.
    pub(crate) fn mark_detector_online(&mut self) {
        self.detector_online = true;
    }

    /// Whether any detector has reported (#743).
    pub(crate) const fn detector_online(&self) -> bool {
        self.detector_online
    }

    /// Add a new alert, maintaining newest-first order and the
    /// `MAX_ALERTS` capacity limit.
    pub(crate) fn push_alert(&mut self, mut alert: ThreatAlert) {
        // An alert IS a detector report (#743).
        self.detector_online = true;
        // Enforce MAX_DESC_LEN here (not just at render time) so a single
        // oversized attacker-controlled description cannot inflate ring
        // buffer memory (#396).
        if alert.description.len() > MAX_DESC_LEN {
            alert.description =
                String::from(truncate_at_char_boundary(&alert.description, MAX_DESC_LEN));
        }

        // Insert at position determined by timestamp (newest first).
        let pos = self
            .alerts
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
        // #545: the canonical 30/60/80 band function, shared with sema.
        self.current_level = sema_core::level_from_score(self.current_score);
    }

    /// Derive the composite score PURELY from the alert log's own contents
    /// (#737) -- score as a lens over the log, not an independent number.
    /// This is a volume/severity heuristic, NOT sema's calibrated detector
    /// engine (sema is not a thumos dependency; see the module doc): the
    /// peak severity present sets a baseline, and each additional alert
    /// (up to 5) adds a small bump, capped at 100. The rendered UI labels
    /// the score "UNCAL" so it is never mistaken for a validated risk
    /// assessment. Call after any log mutation (`push_alert`) to keep the
    /// score current.
    pub(crate) fn recompute_score_from_log(&mut self) {
        let Some(peak) = self
            .alerts
            .iter()
            .map(|a| severity_weight(a.severity))
            .max()
        else {
            self.set_score(0);
            return;
        };
        let volume_bump = (self.alerts.len().saturating_sub(1)).min(5) as u32 * 3;
        self.set_score(peak + volume_bump);
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
        // WHY(#743): with no detector reporting, the level and the score are
        // both unfounded -- current_level is Low and current_score is 0
        // because nothing has ever written them, not because the radio
        // environment is clean. Rendering the normal readout in that state
        // tells the operator "you are safe" on the authority of an empty
        // log. The bar goes neutral, the score is suppressed entirely, and
        // the label says so.
        let level_color = if self.detector_online {
            self.current_level.color()
        } else {
            color::DARK_GREY
        };
        // Fill the entire top bar with the threat level color.
        ui::fill_rect(fb, w, h, 0, 0, w, TOP_BAR_HEIGHT, level_color);

        // Draw threat level label (centered, black text on colored bar).
        let label = if self.detector_online {
            self.current_level.label()
        } else {
            "NO DETECTOR"
        };
        let label_y = (TOP_BAR_HEIGHT.saturating_sub(CHAR_HEIGHT)) / 2;
        ui::draw_str_centered(fb, w, 0, w / 2, label_y, label, color::BLACK, level_color);

        // Draw numeric score on the right side of the bar -- only when a
        // detector has reported (#743). A score is a claim; with nothing
        // watching there is nothing to claim, so no number is drawn at all
        // rather than a reassuring zero.
        if self.detector_online {
            let score_buf = self.score_text();
            let score_str = core::str::from_utf8(&score_buf[..3]).unwrap_or("  0");
            let score_x = w / 2 + 20;
            ui::draw_str(
                fb,
                w,
                score_x,
                label_y,
                score_str,
                color::BLACK,
                level_color,
            );

            // #737: the score is a log-derived heuristic
            // (recompute_score_from_log), NOT sema's calibrated detector engine
            // -- sema is not a thumos dependency and cannot reach KernelState
            // (see the module doc). Labelled directly on the readout so it is
            // never mistaken for a validated risk assessment.
            let uncal_x = score_x + 3 * 8 + 8;
            ui::draw_str(
                fb,
                w,
                uncal_x,
                label_y,
                "UNCAL",
                color::DARK_GREY,
                level_color,
            );
        }

        // --- Alert list ---
        if !self.detector_online {
            // WHY(#743): "No alerts" is true here and misleading -- it reads
            // as a finding when it is the absence of a search. Say which one
            // it is.
            let msg_y = ALERT_LIST_Y + ALERT_LIST_HEIGHT / 2 - CHAR_HEIGHT / 2;
            ui::draw_str_centered(
                fb,
                w,
                0,
                w,
                msg_y,
                "Monitoring unavailable",
                color::DARK_GREY,
                color::BLACK,
            );
        } else if self.alerts.is_empty() {
            // Show "No alerts" message.
            let no_alerts_y = ALERT_LIST_Y + ALERT_LIST_HEIGHT / 2 - CHAR_HEIGHT / 2;
            ui::draw_str_centered(
                fb,
                w,
                0,
                w,
                no_alerts_y,
                "No alerts",
                color::DARK_GREY,
                color::BLACK,
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

                // Description (truncated to fit the row width). draw_str
                // renders one glyph per `char`, so the cut must be made at
                // a character boundary, not a raw byte offset (#396) — a
                // byte-index slice can land mid-codepoint and panic.
                let desc_x = icon_x + 2 * 8;
                let max_chars = ((w - desc_x) / 8) as usize;
                let desc = alert
                    .description
                    .char_indices()
                    .nth(max_chars)
                    .map_or(alert.description.as_str(), |(i, _)| &alert.description[..i]);
                ui::draw_str(fb, w, desc_x, row_y + 3, desc, fg, bg);
            }

            // Scroll indicators.
            if self.scroll_offset > 0 {
                ui::draw_char(
                    fb,
                    w,
                    w - 12,
                    ALERT_LIST_Y + 2,
                    '^',
                    color::DARK_GREY,
                    color::BLACK,
                );
            }
            if visible_end < self.alerts.len() {
                let arrow_y = ALERT_LIST_Y + ALERT_LIST_HEIGHT - CHAR_HEIGHT - 2;
                ui::draw_char(fb, w, w - 12, arrow_y, 'v', color::DARK_GREY, color::BLACK);
            }
        }

        // --- Separator above modem status ---
        ui::fill_rect(
            fb,
            w,
            h,
            PADDING_X,
            MODEM_STATUS_Y,
            w - PADDING_X * 2,
            1,
            color::DARK_GREY,
        );

        // --- Modem status zone ---
        let status_y = MODEM_STATUS_Y + 4;

        // Channel count.
        let ch_label = "CH:";
        ui::draw_str(
            fb,
            w,
            PADDING_X,
            status_y,
            ch_label,
            color::DARK_GREY,
            color::BLACK,
        );
        let ch_digit = b'0' + self.modem_channels.min(9);
        let ch_str: [u8; 2] = [ch_digit, 0];
        let ch_text = core::str::from_utf8(&ch_str[..1]).unwrap_or("0");
        ui::draw_str(
            fb,
            w,
            PADDING_X + 3 * 8,
            status_y,
            ch_text,
            color::WHITE,
            color::BLACK,
        );

        // Firewall mode.
        let fw_label = self.firewall_mode.label();
        let fw_x = PADDING_X + 6 * 8;
        ui::draw_str(
            fb,
            w,
            fw_x,
            status_y,
            fw_label,
            self.firewall_mode.color(),
            color::BLACK,
        );

        // Power state.
        let (pwr_label, pwr_color) = if self.modem_power {
            ("ON", color::GREEN)
        } else {
            ("KILLED", color::RED)
        };
        let pwr_x = w - PADDING_X - (pwr_label.len() as u16) * 8;
        ui::draw_str(fb, w, pwr_x, status_y, pwr_label, pwr_color, color::BLACK);
    }

    // WHY: Key::Lsk's arm and the wildcard both return ScreenAction::None,
    // but the explicit Lsk arm documents that LSK is intentionally a no-op
    // (detail view pending, not a forgotten key) rather than silently
    // falling through the same as any unhandled key.
    #[expect(
        clippy::match_same_arms,
        reason = "Key::Lsk's arm documents LSK as an intentional no-op (detail view pending) rather than silently falling through the wildcard like any unhandled key"
    )]
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
    use alloc::string::ToString;

    use super::*;
    use crate::ui::CONTENT_PIXELS;

    fn make_alert(
        timestamp: u64,
        alert_type: ThreatAlertType,
        severity: ThreatLevel,
    ) -> ThreatAlert {
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
        monitor.push_alert(make_alert(
            1000,
            ThreatAlertType::SilentSms,
            ThreatLevel::Medium,
        ));
        monitor.push_alert(make_alert(
            3000,
            ThreatAlertType::ImsiCatcher,
            ThreatLevel::Critical,
        ));
        monitor.push_alert(make_alert(
            2000,
            ThreatAlertType::BleTracker,
            ThreatLevel::Low,
        ));

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
            ThreatLevel::Low.color(),
            color::GREEN,
            "LOW must render green"
        );
        assert_eq!(
            ThreatLevel::Medium.color(),
            color::YELLOW,
            "MEDIUM must render yellow"
        );
        assert_eq!(
            ThreatLevel::High.color(),
            COLOR_ORANGE,
            "HIGH must render orange"
        );
        assert_eq!(
            ThreatLevel::Critical.color(),
            color::RED,
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
        assert_eq!(ThreatAlertType::ImsiCatcher.to_string(), "IMSI_CATCHER");
        assert_eq!(ThreatAlertType::BleTracker.to_string(), "BLE_TRACKER");
        assert_eq!(ThreatAlertType::DeauthAttack.to_string(), "DEAUTH_ATTACK");
        assert_eq!(ThreatAlertType::CcciAnomaly.to_string(), "CCCI_ANOMALY");
        assert_eq!(
            ThreatAlertType::GeofenceBreach.to_string(),
            "GEOFENCE_BREACH"
        );
        assert_eq!(ThreatAlertType::SilentSms.to_string(), "SILENT_SMS");
        assert_eq!(
            ThreatAlertType::WapPushRejected.to_string(),
            "WAP_PUSH_REJECTED"
        );
        assert_eq!(ThreatAlertType::ModemAnomaly.to_string(), "MODEM_ANOMALY");
    }

    #[test]
    fn screen_renders_without_panic() {
        let monitor = ThreatMonitor::new();
        let mut fb = alloc::vec![0u16; CONTENT_PIXELS];
        monitor.draw(&mut fb);
        let any_set = fb.iter().any(|&px| px != 0);
        assert!(any_set, "threat monitor must render visible content");
    }

    #[test]
    fn screen_renders_with_alerts_without_panic() {
        let mut monitor = ThreatMonitor::new();
        monitor.push_alert(make_alert(
            1000,
            ThreatAlertType::SilentSms,
            ThreatLevel::Medium,
        ));
        monitor.push_alert(make_alert(
            2000,
            ThreatAlertType::ImsiCatcher,
            ThreatLevel::Critical,
        ));
        monitor.set_score(80);
        let mut fb = alloc::vec![0u16; CONTENT_PIXELS];
        monitor.draw(&mut fb);
        let any_set = fb.iter().any(|&px| px != 0);
        assert!(
            any_set,
            "threat monitor with alerts must render visible content"
        );
    }

    #[test]
    fn draw_handles_multibyte_description_at_truncation_boundary() {
        let mut monitor = ThreatMonitor::new();
        let mut alert = make_alert(1000, ThreatAlertType::BleTracker, ThreatLevel::Medium);
        // 20 ASCII chars + a 2-byte codepoint so the render-time truncation
        // boundary (byte 21 at this screen width) lands mid-codepoint
        // pre-fix (#396).
        alert.description = String::from("12345678901234567890é tracker seen nearby");
        monitor.push_alert(alert);

        let mut fb = alloc::vec![0u16; CONTENT_PIXELS];
        // Must not panic ("byte index N is not a char boundary").
        monitor.draw(&mut fb);
        assert!(
            fb.iter().any(|&px| px != 0),
            "threat screen must render the char-boundary-truncated description"
        );
    }

    #[test]
    fn push_alert_truncates_description_to_max_desc_len_on_char_boundary() {
        let mut monitor = ThreatMonitor::new();
        let mut alert = make_alert(1000, ThreatAlertType::BleTracker, ThreatLevel::Low);
        // 47 ASCII chars + a 2-byte codepoint so MAX_DESC_LEN (48) lands
        // mid-codepoint if truncation is not char-boundary-safe (#396).
        let mut long_desc = "A".repeat(47);
        long_desc.push('é');
        long_desc.push_str(" more text after the cap");
        alert.description = long_desc;
        monitor.push_alert(alert);

        let stored = &monitor.alerts[0].description;
        assert!(
            stored.len() <= MAX_DESC_LEN,
            "description must be capped at MAX_DESC_LEN"
        );
        assert_eq!(
            stored.as_str(),
            "A".repeat(47),
            "truncation must back off to the last full codepoint"
        );
    }

    #[test]
    fn threat_level_display() {
        assert_eq!(ThreatLevel::Low.to_string(), "LOW");
        assert_eq!(ThreatLevel::Medium.to_string(), "MEDIUM");
        assert_eq!(ThreatLevel::High.to_string(), "HIGH");
        assert_eq!(ThreatLevel::Critical.to_string(), "CRITICAL");
    }

    #[test]
    fn firewall_mode_display() {
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
            monitor.push_alert(make_alert(
                i as u64,
                ThreatAlertType::SilentSms,
                ThreatLevel::Low,
            ));
        }
        assert_eq!(
            monitor.alert_count(),
            MAX_ALERTS,
            "alert count must not exceed MAX_ALERTS"
        );
    }

    #[test]
    fn navigation_keys() {
        let mut monitor = ThreatMonitor::new();
        monitor.push_alert(make_alert(
            1000,
            ThreatAlertType::SilentSms,
            ThreatLevel::Low,
        ));
        monitor.push_alert(make_alert(
            2000,
            ThreatAlertType::ImsiCatcher,
            ThreatLevel::High,
        ));
        monitor.push_alert(make_alert(
            3000,
            ThreatAlertType::BleTracker,
            ThreatLevel::Medium,
        ));

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
                t.icon(),
                t
            );
            seen[icon] = true;
        }
    }

    /// #743: a fresh monitor has no detector. This is the state a production
    /// build sits in today, and it must be distinguishable from a clean scan.
    #[test]
    fn fresh_monitor_reports_no_detector() {
        let monitor = ThreatMonitor::new();
        assert!(
            !monitor.detector_online(),
            "a monitor nothing has reported to must not claim a detector"
        );
        assert_eq!(
            monitor.threat_score(),
            0,
            "score is 0 because nothing wrote it, which is exactly why the \
             render path must not draw it while detector_online is false"
        );
    }

    /// #743: an alert IS a detector report.
    #[test]
    fn pushing_an_alert_marks_the_detector_online() {
        let mut monitor = ThreatMonitor::new();
        monitor.push_alert(ThreatAlert::from_sms_classification(
            1_000,
            ThreatAlertType::SilentSms,
        ));
        assert!(monitor.detector_online());
    }

    /// #743: the distinction the whole issue turns on -- a detector that ran
    /// and found nothing is NOT the same as no detector. Both have an empty
    /// log and a zero score; only this flag separates them.
    #[test]
    fn a_clean_scan_is_distinguishable_from_no_detector() {
        let absent = ThreatMonitor::new();

        let mut clean = ThreatMonitor::new();
        clean.mark_detector_online();

        assert_eq!(absent.alert_count(), clean.alert_count());
        assert_eq!(absent.threat_score(), clean.threat_score());
        assert!(
            !absent.detector_online() && clean.detector_online(),
            "identical log and score, opposite meaning -- if this ever \
             collapses, the screen reports 'safe' when nothing is watching"
        );
    }
}
