//! Privacy dashboard for the thumos kernel UI.
//!
//! Implements the [`Screen`] trait to display a per-category data inventory
//! with size, retention period, and purge controls. Categories correspond to
//! the distinct data silos managed by the kernel: audit logs, messages,
//! contacts, call history, calendar, SIGINT intercepts, location traces,
//! usage statistics, and battery telemetry.
//!
//! ## Layout
//!
//! - Scrollable list of data categories with human-readable sizes
//! - Per-category retention period display (days)
//! - Softkeys: REVIEW (stub), PURGE (with passphrase re-entry), SETTINGS (stub)
//!
//! ## Integration
//!
//! Accessible from `screen_search.rs` via function search "Privacy"
//! (`ScreenId::Privacy`), and from the settings menu.

// WHY: privacy dashboard created in Phase 08 Wave 7, kinit wiring pending.
#![expect(
    dead_code,
    reason = "Privacy dashboard created in Phase 08 Wave 7, kinit wiring pending"
)]

use crate::ui::{
    self, color, Key, Screen, ScreenAction, ScreenId,
    CHAR_HEIGHT, CHAR_WIDTH, CONTENT_HEIGHT, SCREEN_WIDTH,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Number of data categories tracked by the privacy dashboard.
const CATEGORY_COUNT: usize = 9;

/// Maximum number of visible rows in the category list.
const VISIBLE_ROWS: usize = 10;

/// Y offset for the header line.
const HEADER_Y: u16 = 4;

/// Y offset where the category list begins (below header).
const LIST_Y: u16 = HEADER_Y + CHAR_HEIGHT + 8;

/// Height of each list row.
const ROW_HEIGHT: u16 = CHAR_HEIGHT + 6;

/// Left padding for category names.
const NAME_X: u16 = 4;

/// X position for the size column.
const SIZE_X: u16 = 120;

/// X position for the retention column.
const RETENTION_X: u16 = 180;

/// Left padding for detail view labels.
const DETAIL_LABEL_X: u16 = 8;

/// Left padding for detail view values.
const DETAIL_VALUE_X: u16 = 100;

/// Y offset for the first detail line.
const DETAIL_START_Y: u16 = 8;

/// Vertical spacing between detail lines.
const DETAIL_SPACING: u16 = CHAR_HEIGHT + 8;

// ---------------------------------------------------------------------------
// Data category model
// ---------------------------------------------------------------------------

/// A data category tracked by the privacy dashboard.
///
/// Each category represents a distinct data silo with its own storage
/// footprint, retention policy, and purge eligibility.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct DataCategory {
    /// Display name of the category.
    pub name: &'static str,
    /// Current storage usage in bytes.
    pub size_bytes: u64,
    /// Retention period in days (0 = indefinite).
    pub retention_days: u16,
    /// Whether this category can be purged by the user.
    pub purgeable: bool,
}

impl core::fmt::Display for DataCategory {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{}: {} ({}d retention, {})",
            self.name,
            format_size_display(self.size_bytes),
            self.retention_days,
            if self.purgeable { "purgeable" } else { "protected" },
        )
    }
}

/// Canonical category names in display order.
pub(crate) const CATEGORIES: &[&str] = &[
    "Audit log",
    "Messages",
    "Contacts",
    "Call log",
    "Calendar",
    "SIGINT",
    "Location",
    "Stats",
    "Battery",
];

/// Default data categories with placeholder sizes and retention.
///
/// In production, sizes would be read from `lfs.rs` inode metadata.
/// Retention defaults match security policy: audit logs are indefinite
/// and non-purgeable; user data has 90-day default retention.
const fn default_categories() -> [DataCategory; CATEGORY_COUNT] {
    [
        DataCategory { name: "Audit log",  size_bytes: 65536,  retention_days: 0,   purgeable: false },
        DataCategory { name: "Messages",   size_bytes: 524288, retention_days: 90,  purgeable: true  },
        DataCategory { name: "Contacts",   size_bytes: 32768,  retention_days: 0,   purgeable: true  },
        DataCategory { name: "Call log",   size_bytes: 16384,  retention_days: 30,  purgeable: true  },
        DataCategory { name: "Calendar",   size_bytes: 8192,   retention_days: 0,   purgeable: true  },
        DataCategory { name: "SIGINT",     size_bytes: 262144, retention_days: 7,   purgeable: true  },
        DataCategory { name: "Location",   size_bytes: 131072, retention_days: 14,  purgeable: true  },
        DataCategory { name: "Stats",      size_bytes: 4096,   retention_days: 365, purgeable: true  },
        DataCategory { name: "Battery",    size_bytes: 2048,   retention_days: 365, purgeable: true  },
    ]
}

// ---------------------------------------------------------------------------
// Human-readable size formatting
// ---------------------------------------------------------------------------

/// Fixed-size buffer for size formatting (no heap allocation).
struct SizeBuf {
    data: [u8; 16],
    len: usize,
}

impl SizeBuf {
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

    fn as_str(&self) -> &str {
        // Size format strings are always valid ASCII.
        core::str::from_utf8(&self.data[..self.len]).unwrap_or("???")
    }
}

/// Format a byte count as a human-readable string (B, KB, MB, GB).
///
/// Uses integer division for no_std compatibility. Rounds down.
fn format_size(bytes: u64) -> SizeBuf {
    let mut buf = SizeBuf::new();

    if bytes >= 1_073_741_824 {
        // GB range.
        let gb = bytes / 1_073_741_824;
        let frac = (bytes % 1_073_741_824) / 107_374_182; // tenths
        write_u64(&mut buf, gb);
        if frac > 0 {
            buf.push(b'.');
            write_u64(&mut buf, frac);
        }
        buf.push_str(b" GB");
    } else if bytes >= 1_048_576 {
        // MB range.
        let mb = bytes / 1_048_576;
        let frac = (bytes % 1_048_576) / 104_857; // tenths
        write_u64(&mut buf, mb);
        if frac > 0 {
            buf.push(b'.');
            write_u64(&mut buf, frac);
        }
        buf.push_str(b" MB");
    } else if bytes >= 1024 {
        // KB range.
        let kb = bytes / 1024;
        write_u64(&mut buf, kb);
        buf.push_str(b" KB");
    } else {
        write_u64(&mut buf, bytes);
        buf.push_str(b" B");
    }

    buf
}

/// Format a byte count for Display impl (returns a fixed-size array-backed string).
fn format_size_display(bytes: u64) -> SizeBufDisplay {
    SizeBufDisplay(format_size(bytes))
}

/// Wrapper to implement Display for SizeBuf without heap allocation.
struct SizeBufDisplay(SizeBuf);

impl core::fmt::Display for SizeBufDisplay {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.0.as_str())
    }
}

/// Write a u64 value as decimal digits into a SizeBuf.
fn write_u64(buf: &mut SizeBuf, mut val: u64) {
    if val == 0 {
        buf.push(b'0');
        return;
    }

    // Write digits in reverse, then reverse the written portion.
    let start = buf.len;
    while val > 0 {
        buf.push(b'0' + (val % 10) as u8);
        val /= 10;
    }

    // Reverse the digits we just wrote.
    let end = buf.len;
    let slice = &mut buf.data[start..end];
    slice.reverse();
}

/// Format a retention period as a human-readable string.
fn format_retention(days: u16) -> RetentionBuf {
    let mut buf = RetentionBuf::new();

    if days == 0 {
        buf.push_str(b"indef");
    } else if days >= 365 {
        let years = days / 365;
        write_u16_ret(&mut buf, years);
        buf.push(b'y');
    } else {
        write_u16_ret(&mut buf, days);
        buf.push(b'd');
    }

    buf
}

/// Fixed-size buffer for retention formatting.
struct RetentionBuf {
    data: [u8; 8],
    len: usize,
}

impl RetentionBuf {
    const fn new() -> Self {
        Self {
            data: [0; 8],
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

    fn as_str(&self) -> &str {
        core::str::from_utf8(&self.data[..self.len]).unwrap_or("???")
    }
}

/// Write a u16 value as decimal digits into a RetentionBuf.
fn write_u16_ret(buf: &mut RetentionBuf, mut val: u16) {
    if val == 0 {
        buf.push(b'0');
        return;
    }

    let start = buf.len;
    while val > 0 {
        buf.push(b'0' + (val % 10) as u8);
        val /= 10;
    }

    let end = buf.len;
    let slice = &mut buf.data[start..end];
    slice.reverse();
}

// ---------------------------------------------------------------------------
// Privacy screen sub-views
// ---------------------------------------------------------------------------

/// Sub-view state for the privacy dashboard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PrivacyView {
    /// Main category list view.
    List,
    /// Detail view for a single category.
    Detail,
    /// Purge confirmation dialog.
    PurgeConfirm,
}

// ---------------------------------------------------------------------------
// Purge confirmation state
// ---------------------------------------------------------------------------

/// Maximum passphrase length for purge confirmation.
const MAX_PASSPHRASE_LEN: usize = 16;

/// Purge confirmation state: requires passphrase re-entry.
struct PurgeConfirmState {
    /// Index of the category being purged.
    category_idx: usize,
    /// Entered passphrase digits.
    passphrase: [u8; MAX_PASSPHRASE_LEN],
    /// Number of digits entered.
    passphrase_len: usize,
}

impl PurgeConfirmState {
    fn new(category_idx: usize) -> Self {
        Self {
            category_idx,
            passphrase: [0u8; MAX_PASSPHRASE_LEN],
            passphrase_len: 0,
        }
    }

    /// Append a digit to the passphrase.
    fn push_digit(&mut self, digit: u8) {
        if self.passphrase_len < MAX_PASSPHRASE_LEN {
            self.passphrase[self.passphrase_len] = digit;
            self.passphrase_len += 1;
        }
    }

    /// Remove the last digit.
    fn backspace(&mut self) {
        self.passphrase_len = self.passphrase_len.saturating_sub(1);
    }

    /// Clear passphrase data from memory.
    fn zeroize(&mut self) {
        for b in &mut self.passphrase {
            *b = 0;
        }
        self.passphrase_len = 0;
    }
}

// ---------------------------------------------------------------------------
// Privacy screen
// ---------------------------------------------------------------------------

/// Privacy dashboard screen.
///
/// Displays a scrollable list of data categories with size, retention,
/// and purge controls. Implements the `Screen` trait for integration
/// with the thumos UI framework.
pub(crate) struct PrivacyScreen {
    /// Data categories with current state.
    categories: [DataCategory; CATEGORY_COUNT],
    /// Currently selected category index.
    cursor: usize,
    /// Scroll offset for the visible window.
    scroll_offset: usize,
    /// Current sub-view.
    view: PrivacyView,
    /// Purge confirmation state (valid when view == PurgeConfirm).
    purge_state: Option<PurgeConfirmState>,
    /// Total storage usage across all categories (cached).
    total_bytes: u64,
}

impl PrivacyScreen {
    /// Create a new privacy dashboard with default category data.
    ///
    /// In production, category sizes would be populated from `lfs.rs`
    /// inode metadata on screen entry.
    pub(crate) fn new() -> Self {
        let categories = default_categories();
        let total_bytes = categories.iter().map(|c| c.size_bytes).sum();
        Self {
            categories,
            cursor: 0,
            scroll_offset: 0,
            view: PrivacyView::List,
            purge_state: None,
            total_bytes,
        }
    }

    /// Update a category's size (called when refreshing from filesystem).
    pub(crate) fn update_size(&mut self, index: usize, size_bytes: u64) {
        if let Some(cat) = self.categories.get_mut(index) {
            cat.size_bytes = size_bytes;
            self.recalc_total();
        }
    }

    /// Update a category's retention period.
    pub(crate) fn update_retention(&mut self, index: usize, days: u16) {
        if let Some(cat) = self.categories.get_mut(index) {
            cat.retention_days = days;
        }
    }

    /// Return the category at the given index.
    pub(crate) fn category(&self, index: usize) -> Option<&DataCategory> {
        self.categories.get(index)
    }

    /// Return the total storage usage across all categories.
    pub(crate) fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    /// Return the number of purgeable categories.
    pub(crate) fn purgeable_count(&self) -> usize {
        self.categories.iter().filter(|c| c.purgeable).count()
    }

    /// Recalculate the cached total bytes.
    fn recalc_total(&mut self) {
        self.total_bytes = self.categories.iter().map(|c| c.size_bytes).sum();
    }

    /// Adjust scroll offset so the cursor is visible.
    fn adjust_scroll(&mut self) {
        if self.cursor < self.scroll_offset {
            self.scroll_offset = self.cursor;
        } else if self.cursor >= self.scroll_offset + VISIBLE_ROWS {
            self.scroll_offset = self.cursor + 1 - VISIBLE_ROWS;
        }
    }

    /// Execute a purge on the selected category.
    ///
    /// In production, this would invoke `leipsanon::WipeEngine` for
    /// secure erasure with passphrase verification via `key_manager`.
    /// For now, it zeroes the size and resets the purge state.
    fn execute_purge(&mut self, category_idx: usize) {
        if let Some(cat) = self.categories.get_mut(category_idx) {
            if cat.purgeable {
                cat.size_bytes = 0;
                self.recalc_total();
            }
        }
        if let Some(state) = &mut self.purge_state {
            state.zeroize();
        }
        self.purge_state = None;
        self.view = PrivacyView::List;
    }

    /// Cancel a pending purge and return to the list view.
    fn cancel_purge(&mut self) {
        if let Some(state) = &mut self.purge_state {
            state.zeroize();
        }
        self.purge_state = None;
        self.view = PrivacyView::List;
    }

    /// Draw the main category list view.
    fn draw_list(&self, fb: &mut [u16]) {
        let w = SCREEN_WIDTH;
        let h = CONTENT_HEIGHT;

        // Clear content area.
        ui::fill_rect(fb, w, h, 0, 0, w, h, color::BLACK);

        // Draw column headers.
        ui::draw_str(fb, w, NAME_X, HEADER_Y, "Category", color::DARK_GREY, color::BLACK);
        ui::draw_str(fb, w, SIZE_X, HEADER_Y, "Size", color::DARK_GREY, color::BLACK);
        ui::draw_str(fb, w, RETENTION_X, HEADER_Y, "Retain", color::DARK_GREY, color::BLACK);

        // Draw header separator.
        let sep_y = HEADER_Y + CHAR_HEIGHT + 2;
        ui::fill_rect(fb, w, h, NAME_X, sep_y, w - NAME_X * 2, 1, color::DARK_GREY);

        // Draw category rows.
        let visible_end = (self.scroll_offset + VISIBLE_ROWS).min(CATEGORY_COUNT);
        for (vi, ci) in (self.scroll_offset..visible_end).enumerate() {
            let cat = &self.categories[ci];
            let row_y = LIST_Y + (vi as u16) * ROW_HEIGHT;

            // Highlight selected row.
            let (fg, bg) = if ci == self.cursor {
                (color::BLACK, color::WHITE)
            } else {
                (color::WHITE, color::BLACK)
            };

            if ci == self.cursor {
                ui::fill_rect(fb, w, h, 0, row_y, w, ROW_HEIGHT, color::WHITE);
            }

            // Category name.
            ui::draw_str(fb, w, NAME_X, row_y + 2, cat.name, fg, bg);

            // Size (human-readable).
            let size_str = format_size(cat.size_bytes);
            ui::draw_str(fb, w, SIZE_X, row_y + 2, size_str.as_str(), fg, bg);

            // Retention period.
            let ret_str = format_retention(cat.retention_days);
            ui::draw_str(fb, w, RETENTION_X, row_y + 2, ret_str.as_str(), fg, bg);

            // Purgeable indicator.
            if !cat.purgeable {
                let lock_x = w - CHAR_WIDTH - 4;
                let lock_color = if ci == self.cursor { color::DARK_GREY } else { color::DARK_GREY };
                ui::draw_char(fb, w, lock_x, row_y + 2, '*', lock_color, bg);
            }
        }

        // Scroll indicators.
        if self.scroll_offset > 0 {
            ui::draw_char(
                fb, w, w - CHAR_WIDTH - 4, LIST_Y,
                '^', color::DARK_GREY, color::BLACK,
            );
        }
        if visible_end < CATEGORY_COUNT {
            let arrow_y = LIST_Y + (VISIBLE_ROWS as u16) * ROW_HEIGHT;
            ui::draw_char(
                fb, w, w - CHAR_WIDTH - 4, arrow_y,
                'v', color::DARK_GREY, color::BLACK,
            );
        }

        // Total usage at bottom.
        let total_size = format_size(self.total_bytes);
        let total_y = LIST_Y + (VISIBLE_ROWS as u16) * ROW_HEIGHT + 4;
        if total_y + CHAR_HEIGHT < h {
            ui::draw_str(fb, w, NAME_X, total_y, "Total:", color::DARK_GREY, color::BLACK);
            ui::draw_str(fb, w, SIZE_X, total_y, total_size.as_str(), color::DARK_GREY, color::BLACK);
        }
    }

    /// Draw the detail view for a single category.
    fn draw_detail(&self, fb: &mut [u16]) {
        let w = SCREEN_WIDTH;
        let h = CONTENT_HEIGHT;

        ui::fill_rect(fb, w, h, 0, 0, w, h, color::BLACK);

        let cat = &self.categories[self.cursor];

        // Category name as title.
        ui::draw_str_centered(
            fb, w, 0, w, DETAIL_START_Y,
            cat.name, color::WHITE, color::BLACK,
        );

        // Separator.
        let sep_y = DETAIL_START_Y + CHAR_HEIGHT + 4;
        ui::fill_rect(fb, w, h, DETAIL_LABEL_X, sep_y, w - DETAIL_LABEL_X * 2, 1, color::DARK_GREY);

        // Detail rows.
        let row1_y = sep_y + 8;

        // Size.
        ui::draw_str(fb, w, DETAIL_LABEL_X, row1_y, "Size:", color::DARK_GREY, color::BLACK);
        let size_str = format_size(cat.size_bytes);
        ui::draw_str(fb, w, DETAIL_VALUE_X, row1_y, size_str.as_str(), color::WHITE, color::BLACK);

        // Retention.
        let row2_y = row1_y + DETAIL_SPACING;
        ui::draw_str(fb, w, DETAIL_LABEL_X, row2_y, "Retention:", color::DARK_GREY, color::BLACK);
        let ret_str = format_retention(cat.retention_days);
        ui::draw_str(fb, w, DETAIL_VALUE_X, row2_y, ret_str.as_str(), color::WHITE, color::BLACK);

        // Purgeable status.
        let row3_y = row2_y + DETAIL_SPACING;
        ui::draw_str(fb, w, DETAIL_LABEL_X, row3_y, "Purgeable:", color::DARK_GREY, color::BLACK);
        let purge_text = if cat.purgeable { "Yes" } else { "No (protected)" };
        let purge_color = if cat.purgeable { color::GREEN } else { color::RED };
        ui::draw_str(fb, w, DETAIL_VALUE_X, row3_y, purge_text, purge_color, color::BLACK);

        // Action hint.
        if cat.purgeable && cat.size_bytes > 0 {
            let hint_y = row3_y + DETAIL_SPACING + 8;
            ui::draw_str_centered(
                fb, w, 0, w, hint_y,
                "LSK: PURGE data", color::YELLOW, color::BLACK,
            );
        }
    }

    /// Draw the purge confirmation dialog.
    fn draw_purge_confirm(&self, fb: &mut [u16]) {
        let w = SCREEN_WIDTH;
        let h = CONTENT_HEIGHT;

        ui::fill_rect(fb, w, h, 0, 0, w, h, color::BLACK);

        let cat_name = if let Some(state) = &self.purge_state {
            if state.category_idx < CATEGORY_COUNT {
                self.categories[state.category_idx].name
            } else {
                "Unknown"
            }
        } else {
            "Unknown"
        };

        // Warning header.
        ui::draw_str_centered(
            fb, w, 0, w, 20,
            "PURGE DATA", color::RED, color::BLACK,
        );

        // Category name.
        ui::draw_str_centered(
            fb, w, 0, w, 48,
            cat_name, color::WHITE, color::BLACK,
        );

        // Warning message.
        ui::draw_str_centered(
            fb, w, 0, w, 80,
            "This cannot be undone.", color::YELLOW, color::BLACK,
        );

        // Passphrase prompt.
        ui::draw_str_centered(
            fb, w, 0, w, 112,
            "Enter passphrase:", color::DARK_GREY, color::BLACK,
        );

        // Show dots for entered passphrase digits.
        if let Some(state) = &self.purge_state {
            let dots_width = state.passphrase_len as u16 * CHAR_WIDTH;
            let dots_x = (w.saturating_sub(dots_width)) / 2;
            for i in 0..state.passphrase_len {
                let x = dots_x + (i as u16) * CHAR_WIDTH;
                ui::draw_char(fb, w, x, 140, '*', color::WHITE, color::BLACK);
            }

            // Underline.
            let underline_x = (w.saturating_sub(MAX_PASSPHRASE_LEN as u16 * CHAR_WIDTH)) / 2;
            let underline_w = MAX_PASSPHRASE_LEN as u16 * CHAR_WIDTH;
            ui::fill_rect(
                fb, w, h,
                underline_x, 140 + CHAR_HEIGHT + 2,
                underline_w, 1,
                color::DARK_GREY,
            );
        }

        // Action hints.
        ui::draw_str_centered(
            fb, w, 0, w, 190,
            "OK: Confirm  RSK: Cancel", color::DARK_GREY, color::BLACK,
        );
    }

    /// Handle key input in the list view.
    fn handle_list_key(&mut self, key: Key) -> ScreenAction {
        match key {
            Key::Up => {
                if self.cursor > 0 {
                    self.cursor -= 1;
                    self.adjust_scroll();
                }
                ScreenAction::None
            }
            Key::Down => {
                if self.cursor < CATEGORY_COUNT - 1 {
                    self.cursor += 1;
                    self.adjust_scroll();
                }
                ScreenAction::None
            }
            Key::Ok | Key::Right => {
                // Enter detail view for selected category.
                self.view = PrivacyView::Detail;
                ScreenAction::None
            }
            Key::Lsk => {
                // REVIEW action (stub — would open category data viewer).
                ScreenAction::None
            }
            Key::Rsk | Key::End => ScreenAction::Back,
            _ => ScreenAction::None,
        }
    }

    /// Handle key input in the detail view.
    fn handle_detail_key(&mut self, key: Key) -> ScreenAction {
        match key {
            Key::Lsk => {
                // PURGE — initiate purge confirmation if category is purgeable.
                let cat = &self.categories[self.cursor];
                if cat.purgeable && cat.size_bytes > 0 {
                    self.purge_state = Some(PurgeConfirmState::new(self.cursor));
                    self.view = PrivacyView::PurgeConfirm;
                }
                ScreenAction::None
            }
            Key::Rsk | Key::End | Key::Left => {
                // Back to list.
                self.view = PrivacyView::List;
                ScreenAction::None
            }
            _ => ScreenAction::None,
        }
    }

    /// Handle key input in the purge confirmation dialog.
    fn handle_purge_key(&mut self, key: Key) -> ScreenAction {
        match key {
            // Numpad keys for passphrase entry.
            Key::Num0 => { self.purge_digit(0); ScreenAction::None }
            Key::Num1 => { self.purge_digit(1); ScreenAction::None }
            Key::Num2 => { self.purge_digit(2); ScreenAction::None }
            Key::Num3 => { self.purge_digit(3); ScreenAction::None }
            Key::Num4 => { self.purge_digit(4); ScreenAction::None }
            Key::Num5 => { self.purge_digit(5); ScreenAction::None }
            Key::Num6 => { self.purge_digit(6); ScreenAction::None }
            Key::Num7 => { self.purge_digit(7); ScreenAction::None }
            Key::Num8 => { self.purge_digit(8); ScreenAction::None }
            Key::Num9 => { self.purge_digit(9); ScreenAction::None }

            Key::Left => {
                // Backspace.
                if let Some(state) = &mut self.purge_state {
                    state.backspace();
                }
                ScreenAction::None
            }

            Key::Ok => {
                // Confirm purge (passphrase would be verified in production).
                if let Some(state) = &self.purge_state {
                    if state.passphrase_len > 0 {
                        let idx = state.category_idx;
                        self.execute_purge(idx);
                    }
                }
                ScreenAction::None
            }

            Key::Rsk | Key::End => {
                // Cancel purge.
                self.cancel_purge();
                ScreenAction::None
            }

            _ => ScreenAction::None,
        }
    }

    /// Push a digit into the purge passphrase buffer.
    fn purge_digit(&mut self, digit: u8) {
        if let Some(state) = &mut self.purge_state {
            state.push_digit(digit);
        }
    }
}

// ---------------------------------------------------------------------------
// Screen implementation
// ---------------------------------------------------------------------------

impl Screen for PrivacyScreen {
    fn draw(&self, fb: &mut [u16]) {
        match self.view {
            PrivacyView::List => self.draw_list(fb),
            PrivacyView::Detail => self.draw_detail(fb),
            PrivacyView::PurgeConfirm => self.draw_purge_confirm(fb),
        }
    }

    fn on_key(&mut self, key: Key) -> ScreenAction {
        match self.view {
            PrivacyView::List => self.handle_list_key(key),
            PrivacyView::Detail => self.handle_detail_key(key),
            PrivacyView::PurgeConfirm => self.handle_purge_key(key),
        }
    }

    fn softkey_left(&self) -> &'static str {
        match self.view {
            PrivacyView::List => "REVIEW",
            PrivacyView::Detail => {
                let cat = &self.categories[self.cursor];
                if cat.purgeable && cat.size_bytes > 0 {
                    "PURGE"
                } else {
                    ""
                }
            }
            PrivacyView::PurgeConfirm => "CONFIRM",
        }
    }

    fn softkey_right(&self) -> &'static str {
        match self.view {
            PrivacyView::List => "BACK",
            PrivacyView::Detail | PrivacyView::PurgeConfirm => "CANCEL",
        }
    }

    fn title(&self) -> &'static str {
        "Privacy"
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_categories_has_correct_count() {
        let cats = default_categories();
        assert_eq!(
            cats.len(), CATEGORY_COUNT,
            "default categories must have {CATEGORY_COUNT} entries"
        );
    }

    #[test]
    fn categories_constant_matches_defaults() {
        let cats = default_categories();
        for (i, cat) in cats.iter().enumerate() {
            assert_eq!(
                cat.name, CATEGORIES[i],
                "category {i} name must match CATEGORIES constant"
            );
        }
    }

    #[test]
    fn format_size_bytes() {
        let buf = format_size(512);
        assert_eq!(buf.as_str(), "512 B", "512 bytes");
    }

    #[test]
    fn format_size_kilobytes() {
        let buf = format_size(4096);
        assert_eq!(buf.as_str(), "4 KB", "4096 bytes = 4 KB");
    }

    #[test]
    fn format_size_megabytes() {
        let buf = format_size(1_572_864);
        assert_eq!(buf.as_str(), "1.5 MB", "1.5 MB");
    }

    #[test]
    fn format_size_gigabytes() {
        let buf = format_size(2_147_483_648);
        assert_eq!(buf.as_str(), "2 GB", "2 GB");
    }

    #[test]
    fn format_size_zero() {
        let buf = format_size(0);
        assert_eq!(buf.as_str(), "0 B", "0 bytes");
    }

    #[test]
    fn format_retention_indefinite() {
        let buf = format_retention(0);
        assert_eq!(buf.as_str(), "indef", "0 days = indefinite");
    }

    #[test]
    fn format_retention_days() {
        let buf = format_retention(30);
        assert_eq!(buf.as_str(), "30d", "30 days");
    }

    #[test]
    fn format_retention_years() {
        let buf = format_retention(365);
        assert_eq!(buf.as_str(), "1y", "365 days = 1 year");
    }

    #[test]
    fn new_screen_starts_at_list_view() {
        let screen = PrivacyScreen::new();
        assert_eq!(screen.view, PrivacyView::List);
        assert_eq!(screen.cursor, 0);
        assert_eq!(screen.scroll_offset, 0);
    }

    #[test]
    fn total_bytes_calculated() {
        let screen = PrivacyScreen::new();
        let expected: u64 = default_categories().iter().map(|c| c.size_bytes).sum();
        assert_eq!(
            screen.total_bytes(), expected,
            "total_bytes must match sum of all category sizes"
        );
    }

    #[test]
    fn update_size_recalculates_total() {
        let mut screen = PrivacyScreen::new();
        let old_total = screen.total_bytes();
        screen.update_size(1, 0); // Zero out Messages
        assert!(
            screen.total_bytes() < old_total,
            "total must decrease after zeroing a category"
        );
    }

    #[test]
    fn cursor_navigation() {
        let mut screen = PrivacyScreen::new();

        // Down moves cursor.
        let action = screen.on_key(Key::Down);
        assert_eq!(action, ScreenAction::None);
        assert_eq!(screen.cursor, 1);

        // Up moves back.
        let action = screen.on_key(Key::Up);
        assert_eq!(action, ScreenAction::None);
        assert_eq!(screen.cursor, 0);

        // Up at top stays at 0.
        let action = screen.on_key(Key::Up);
        assert_eq!(action, ScreenAction::None);
        assert_eq!(screen.cursor, 0);
    }

    #[test]
    fn cursor_stops_at_bottom() {
        let mut screen = PrivacyScreen::new();
        for _ in 0..CATEGORY_COUNT + 5 {
            screen.on_key(Key::Down);
        }
        assert_eq!(
            screen.cursor, CATEGORY_COUNT - 1,
            "cursor must not exceed last category"
        );
    }

    #[test]
    fn ok_enters_detail_view() {
        let mut screen = PrivacyScreen::new();
        screen.on_key(Key::Ok);
        assert_eq!(screen.view, PrivacyView::Detail);
    }

    #[test]
    fn rsk_exits_from_list() {
        let mut screen = PrivacyScreen::new();
        let action = screen.on_key(Key::Rsk);
        assert_eq!(action, ScreenAction::Back);
    }

    #[test]
    fn back_from_detail_returns_to_list() {
        let mut screen = PrivacyScreen::new();
        screen.on_key(Key::Ok); // Enter detail
        assert_eq!(screen.view, PrivacyView::Detail);

        screen.on_key(Key::Rsk); // Back
        assert_eq!(screen.view, PrivacyView::List);
    }

    #[test]
    fn purge_flow_for_purgeable_category() {
        let mut screen = PrivacyScreen::new();
        // Navigate to Messages (index 1, purgeable).
        screen.on_key(Key::Down);
        screen.on_key(Key::Ok); // Detail view
        assert_eq!(screen.view, PrivacyView::Detail);

        screen.on_key(Key::Lsk); // PURGE
        assert_eq!(screen.view, PrivacyView::PurgeConfirm);

        // Enter a passphrase digit and confirm.
        screen.on_key(Key::Num1);
        screen.on_key(Key::Num2);
        screen.on_key(Key::Num3);
        screen.on_key(Key::Ok); // Confirm

        // Should be back in list view with zeroed size.
        assert_eq!(screen.view, PrivacyView::List);
        assert_eq!(
            screen.categories[1].size_bytes, 0,
            "purged category must have zero size"
        );
    }

    #[test]
    fn purge_rejected_for_protected_category() {
        let mut screen = PrivacyScreen::new();
        // First category (Audit log) is not purgeable.
        screen.on_key(Key::Ok); // Detail view
        assert_eq!(screen.view, PrivacyView::Detail);

        screen.on_key(Key::Lsk); // PURGE (should be ignored)
        assert_eq!(
            screen.view, PrivacyView::Detail,
            "purge must not start for protected category"
        );
    }

    #[test]
    fn purge_cancel_returns_to_list() {
        let mut screen = PrivacyScreen::new();
        screen.on_key(Key::Down); // Messages
        screen.on_key(Key::Ok); // Detail
        screen.on_key(Key::Lsk); // PURGE
        assert_eq!(screen.view, PrivacyView::PurgeConfirm);

        screen.on_key(Key::Rsk); // Cancel
        assert_eq!(screen.view, PrivacyView::List);
        assert!(screen.purge_state.is_none(), "purge state must be cleared on cancel");
    }

    #[test]
    fn purge_requires_passphrase() {
        let mut screen = PrivacyScreen::new();
        screen.on_key(Key::Down); // Messages
        screen.on_key(Key::Ok); // Detail
        screen.on_key(Key::Lsk); // PURGE

        // Confirm without entering passphrase.
        let original_size = screen.categories[1].size_bytes;
        screen.on_key(Key::Ok);

        // Should still be in purge confirm (no passphrase entered).
        assert_eq!(
            screen.view, PrivacyView::PurgeConfirm,
            "purge must not proceed without passphrase"
        );
        assert_eq!(
            screen.categories[1].size_bytes, original_size,
            "size must not change when purge rejected"
        );
    }

    #[test]
    fn passphrase_backspace() {
        let mut screen = PrivacyScreen::new();
        screen.on_key(Key::Down); // Messages
        screen.on_key(Key::Ok); // Detail
        screen.on_key(Key::Lsk); // PURGE

        screen.on_key(Key::Num1);
        screen.on_key(Key::Num2);
        assert_eq!(screen.purge_state.as_ref().map(|s| s.passphrase_len), Some(2));

        screen.on_key(Key::Left); // Backspace
        assert_eq!(screen.purge_state.as_ref().map(|s| s.passphrase_len), Some(1));
    }

    #[test]
    fn softkey_labels_change_by_view() {
        let mut screen = PrivacyScreen::new();

        // List view.
        assert_eq!(screen.softkey_left(), "REVIEW");
        assert_eq!(screen.softkey_right(), "BACK");

        // Detail view (purgeable category with data).
        screen.on_key(Key::Down); // Messages
        screen.on_key(Key::Ok);
        assert_eq!(screen.softkey_left(), "PURGE");
        assert_eq!(screen.softkey_right(), "CANCEL");

        // Detail view (protected category).
        screen.on_key(Key::Rsk); // Back to list
        screen.cursor = 0; // Audit log
        screen.view = PrivacyView::Detail;
        assert_eq!(screen.softkey_left(), "");
    }

    #[test]
    fn draw_list_does_not_panic() {
        let screen = PrivacyScreen::new();
        let mut fb = [0u16; SCREEN_WIDTH as usize * CONTENT_HEIGHT as usize];
        screen.draw(&mut fb);
        let any_set = fb.iter().any(|&px| px != 0);
        assert!(any_set, "privacy list must render visible content");
    }

    #[test]
    fn draw_detail_does_not_panic() {
        let mut screen = PrivacyScreen::new();
        screen.view = PrivacyView::Detail;
        let mut fb = [0u16; SCREEN_WIDTH as usize * CONTENT_HEIGHT as usize];
        screen.draw(&mut fb);
    }

    #[test]
    fn draw_purge_confirm_does_not_panic() {
        let mut screen = PrivacyScreen::new();
        screen.view = PrivacyView::PurgeConfirm;
        screen.purge_state = Some(PurgeConfirmState::new(1));
        let mut fb = [0u16; SCREEN_WIDTH as usize * CONTENT_HEIGHT as usize];
        screen.draw(&mut fb);
    }

    #[test]
    fn title_is_privacy() {
        let screen = PrivacyScreen::new();
        assert_eq!(screen.title(), "Privacy");
    }

    #[test]
    fn purgeable_count_correct() {
        let screen = PrivacyScreen::new();
        let expected = default_categories().iter().filter(|c| c.purgeable).count();
        assert_eq!(screen.purgeable_count(), expected);
    }

    #[test]
    fn data_category_display() {
        let cat = DataCategory {
            name: "Test",
            size_bytes: 1024,
            retention_days: 30,
            purgeable: true,
        };
        let s = alloc::format!("{cat}");
        assert!(s.contains("Test"), "display must include category name");
        assert!(s.contains("1 KB"), "display must include human-readable size");
        assert!(s.contains("30d"), "display must include retention");
        assert!(s.contains("purgeable"), "display must include purgeable status");
    }

    #[test]
    fn update_retention() {
        let mut screen = PrivacyScreen::new();
        screen.update_retention(1, 180);
        assert_eq!(
            screen.categories[1].retention_days, 180,
            "retention must be updated"
        );
    }

    #[test]
    fn category_accessor() {
        let screen = PrivacyScreen::new();
        let cat = screen.category(0);
        assert!(cat.is_some());
        assert_eq!(cat.map(|c| c.name), Some("Audit log"));
        assert!(screen.category(CATEGORY_COUNT).is_none());
    }
}
