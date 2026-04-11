//! Message inbox screen for the thumos kernel UI.
//!
//! Implements the [`Screen`] trait to display SMS messages in three views:
//!
//! - **Inbox list**: scrollable list of messages showing sender, body preview
//!   (first 30 characters), and timestamp. Unread messages are indicated with
//!   a `*` prefix marker.
//! - **Full message view**: shows sender, date, and the full body text with
//!   word wrapping at the screen width.
//! - **Compose view**: two-field compose screen with a recipient number
//!   field and a message body field using T9 input.
//!
//! ## Navigation
//!
//! | View      | LSK     | RSK    | OK/Select            |
//! |-----------|---------|--------|----------------------|
//! | Inbox     | NEW     | BACK   | Open selected msg    |
//! | Message   | REPLY   | BACK   | N/A                  |
//! | Compose   | SEND    | BACK   | N/A                  |
//!
//! ## Data source
//!
//! The screen does not own the SMS inbox. Instead, it receives a snapshot
//! of message metadata via [`MessageEntry`] to avoid lifetime issues with
//! kernel globals.

// WHY: messages screen created in Phase 07 Wave 5, kinit wiring pending.
#![expect(
    dead_code,
    reason = "Messages screen created in Phase 07 Wave 5, kinit wiring pending"
)]

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

use crate::ui::{
    self, color, Key, Screen, ScreenAction, ScreenId,
    CHAR_HEIGHT, CHAR_WIDTH, CONTENT_HEIGHT, SCREEN_WIDTH,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of characters shown in a message preview.
const PREVIEW_LEN: usize = 30;

/// Height of each inbox list entry in pixels.
const ENTRY_HEIGHT: u16 = CHAR_HEIGHT * 2 + 8;

/// Number of visible entries in the inbox list.
const VISIBLE_ENTRIES: u16 = CONTENT_HEIGHT / ENTRY_HEIGHT;

/// Maximum characters per line in the full message view (word wrap).
const CHARS_PER_LINE: usize = (SCREEN_WIDTH as usize) / (CHAR_WIDTH as usize);

/// Y offset for the title in message detail/compose views.
const TITLE_Y: u16 = 4;

/// Y offset for the first content line below the title.
const CONTENT_START_Y: u16 = TITLE_Y + CHAR_HEIGHT + 8;

/// Maximum recipient number length in compose mode.
const MAX_RECIPIENT_LEN: usize = 20;

// ---------------------------------------------------------------------------
// Message entry (inbox snapshot)
// ---------------------------------------------------------------------------

/// A snapshot of one SMS message for display purposes.
///
/// Kept separate from `sms::SmsMessage` to avoid coupling the screen
/// to the SMS module's internal storage format.
pub struct MessageEntry {
    /// Sender name (from contacts) or phone number.
    pub sender: String,
    /// Full message body text.
    pub body: String,
    /// Timestamp as Unix epoch seconds (0 = unknown).
    pub timestamp: u64,
    /// Whether the message has been read.
    pub read: bool,
}

// ---------------------------------------------------------------------------
// Sub-views
// ---------------------------------------------------------------------------

/// Current view state of the messages screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MessageView {
    /// Inbox list view.
    Inbox,
    /// Full message detail view.
    Detail,
    /// Compose new message view.
    Compose,
}

/// Which field is active in the compose view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ComposeField {
    /// Recipient number entry.
    To,
    /// Message body entry.
    Body,
}

// ---------------------------------------------------------------------------
// Messages screen
// ---------------------------------------------------------------------------

/// Messages screen implementation.
///
/// Manages inbox list, message detail, and compose views. The caller
/// must update the message list via [`set_messages`] before each render.
pub struct MessagesScreen {
    /// Message entries for display.
    messages: Vec<MessageEntry>,
    /// Currently selected message index in the inbox list.
    selected: usize,
    /// Scroll offset for the inbox list.
    scroll_offset: usize,
    /// Current view state.
    view: MessageView,
    /// Scroll offset for the detail view (line-based).
    detail_scroll: usize,
    /// Compose: recipient number buffer.
    compose_to: [u8; MAX_RECIPIENT_LEN],
    /// Compose: number of valid bytes in recipient buffer.
    compose_to_len: usize,
    /// Compose: message body buffer.
    compose_body: String,
    /// Compose: which field is active.
    compose_field: ComposeField,
}

impl MessagesScreen {
    /// Create a new messages screen with an empty inbox.
    pub fn new() -> Self {
        Self {
            messages: Vec::new(),
            selected: 0,
            scroll_offset: 0,
            view: MessageView::Inbox,
            detail_scroll: 0,
            compose_to: [0u8; MAX_RECIPIENT_LEN],
            compose_to_len: 0,
            compose_body: String::new(),
            compose_field: ComposeField::To,
        }
    }

    /// Replace the message list with a new snapshot.
    pub fn set_messages(&mut self, messages: Vec<MessageEntry>) {
        self.messages = messages;
        // Clamp selection if the list shrank.
        if self.selected >= self.messages.len() && !self.messages.is_empty() {
            self.selected = self.messages.len() - 1;
        }
    }

    /// Return the number of messages.
    pub fn message_count(&self) -> usize {
        self.messages.len()
    }

    /// Return the currently selected message index.
    pub fn selected_index(&self) -> usize {
        self.selected
    }

    /// Return the current view.
    pub fn current_view(&self) -> MessageView {
        self.view
    }

    // --- Compose helpers ---

    /// Append a digit to the recipient field.
    fn compose_push_digit(&mut self, ch: char) {
        if self.compose_to_len < MAX_RECIPIENT_LEN {
            self.compose_to[self.compose_to_len] = ch as u8;
            self.compose_to_len += 1;
        }
    }

    /// Remove last character from the active compose field.
    fn compose_backspace(&mut self) {
        match self.compose_field {
            ComposeField::To => {
                if self.compose_to_len > 0 {
                    self.compose_to_len -= 1;
                }
            }
            ComposeField::Body => {
                self.compose_body.pop();
            }
        }
    }

    /// Return the recipient number as a string.
    fn compose_to_str(&self) -> &str {
        core::str::from_utf8(&self.compose_to[..self.compose_to_len]).unwrap_or("")
    }

    /// Reset compose state.
    fn reset_compose(&mut self) {
        self.compose_to = [0u8; MAX_RECIPIENT_LEN];
        self.compose_to_len = 0;
        self.compose_body.clear();
        self.compose_field = ComposeField::To;
    }

    /// Enter compose mode.
    fn enter_compose(&mut self) {
        self.reset_compose();
        self.view = MessageView::Compose;
    }

    // --- Navigation helpers ---

    /// Move selection up in the inbox list.
    fn move_up(&mut self) {
        if self.selected > 0 {
            self.selected -= 1;
            if self.selected < self.scroll_offset {
                self.scroll_offset = self.selected;
            }
        }
    }

    /// Move selection down in the inbox list.
    fn move_down(&mut self) {
        if !self.messages.is_empty() && self.selected < self.messages.len() - 1 {
            self.selected += 1;
            let visible = VISIBLE_ENTRIES as usize;
            if self.selected >= self.scroll_offset + visible {
                self.scroll_offset = self.selected - visible + 1;
            }
        }
    }

    /// Open the selected message in detail view.
    fn open_selected(&mut self) {
        if !self.messages.is_empty() {
            self.view = MessageView::Detail;
            self.detail_scroll = 0;
        }
    }
}

impl Screen for MessagesScreen {
    fn draw(&self, fb: &mut [u16]) {
        let w = SCREEN_WIDTH;
        let h = CONTENT_HEIGHT;

        // Clear content area to black.
        ui::fill_rect(fb, w, h, 0, 0, w, h, color::BLACK);

        match self.view {
            MessageView::Inbox => self.draw_inbox(fb),
            MessageView::Detail => self.draw_detail(fb),
            MessageView::Compose => self.draw_compose(fb),
        }
    }

    fn on_key(&mut self, key: Key) -> ScreenAction {
        match self.view {
            MessageView::Inbox => self.on_key_inbox(key),
            MessageView::Detail => self.on_key_detail(key),
            MessageView::Compose => self.on_key_compose(key),
        }
    }

    fn softkey_left(&self) -> &'static str {
        match self.view {
            MessageView::Inbox => "NEW",
            MessageView::Detail => "REPLY",
            MessageView::Compose => "SEND",
        }
    }

    fn softkey_right(&self) -> &'static str {
        "BACK"
    }

    fn title(&self) -> &'static str {
        match self.view {
            MessageView::Inbox => "Messages",
            MessageView::Detail => "Message",
            MessageView::Compose => "Compose",
        }
    }
}

impl MessagesScreen {
    // --- Inbox drawing ---

    fn draw_inbox(&self, fb: &mut [u16]) {
        let w = SCREEN_WIDTH;

        // Title.
        ui::draw_str_centered(fb, w, 0, w, TITLE_Y, "MESSAGES", color::WHITE, color::BLACK);

        if self.messages.is_empty() {
            ui::draw_str_centered(
                fb, w, 0, w, CONTENT_HEIGHT / 2 - CHAR_HEIGHT / 2,
                "No messages", color::DARK_GREY, color::BLACK,
            );
            return;
        }

        let visible = VISIBLE_ENTRIES as usize;
        let start = self.scroll_offset;
        let end = (start + visible).min(self.messages.len());

        for (slot, msg_idx) in (start..end).enumerate() {
            let y = CONTENT_START_Y + slot as u16 * ENTRY_HEIGHT;
            let is_selected = msg_idx == self.selected;

            // Highlight selected entry.
            if is_selected {
                ui::fill_rect(
                    fb, w, CONTENT_HEIGHT,
                    0, y, w, ENTRY_HEIGHT,
                    color::from_rgb(20, 20, 50),
                );
            }

            let msg = &self.messages[msg_idx];

            // Unread marker + sender.
            let marker = if msg.read { " " } else { "*" };
            let sender_display = truncate_str(&msg.sender, 25);
            let line1 = format_entry_line1(marker, &sender_display);
            let sender_color = if msg.read { color::WHITE } else { color::YELLOW };
            ui::draw_str(fb, w, 4, y + 2, &line1, sender_color, color::BLACK);

            // Body preview (first PREVIEW_LEN chars).
            let preview = truncate_str(&msg.body, PREVIEW_LEN);
            ui::draw_str(
                fb, w, 4, y + CHAR_HEIGHT + 4,
                &preview, color::DARK_GREY, color::BLACK,
            );
        }
    }

    // --- Detail drawing ---

    fn draw_detail(&self, fb: &mut [u16]) {
        let w = SCREEN_WIDTH;

        let Some(msg) = self.messages.get(self.selected) else {
            return;
        };

        // Sender.
        ui::draw_str(fb, w, 4, TITLE_Y, "From:", color::DARK_GREY, color::BLACK);
        let sender_display = truncate_str(&msg.sender, 26);
        ui::draw_str(
            fb, w, 4 + 6 * CHAR_WIDTH, TITLE_Y,
            &sender_display, color::WHITE, color::BLACK,
        );

        // Timestamp (simple format).
        if msg.timestamp > 0 {
            let time_str = format_timestamp(msg.timestamp);
            ui::draw_str(
                fb, w, 4, TITLE_Y + CHAR_HEIGHT + 2,
                &time_str, color::DARK_GREY, color::BLACK,
            );
        }

        // Body text with word wrap.
        let body_y_start = CONTENT_START_Y + CHAR_HEIGHT;
        let lines = word_wrap(&msg.body, CHARS_PER_LINE);
        let max_visible_lines = ((CONTENT_HEIGHT - body_y_start) / CHAR_HEIGHT) as usize;
        let start_line = self.detail_scroll;
        let end_line = (start_line + max_visible_lines).min(lines.len());

        for (i, line_idx) in (start_line..end_line).enumerate() {
            let y = body_y_start + i as u16 * CHAR_HEIGHT;
            ui::draw_str(fb, w, 4, y, &lines[line_idx], color::WHITE, color::BLACK);
        }
    }

    // --- Compose drawing ---

    fn draw_compose(&self, fb: &mut [u16]) {
        let w = SCREEN_WIDTH;

        // "To:" field.
        let to_label_color = if self.compose_field == ComposeField::To {
            color::YELLOW
        } else {
            color::DARK_GREY
        };
        ui::draw_str(fb, w, 4, TITLE_Y, "To:", to_label_color, color::BLACK);
        let to_str = self.compose_to_str();
        let to_display = if to_str.is_empty() { "Enter number" } else { to_str };
        let to_text_color = if to_str.is_empty() {
            color::DARK_GREY
        } else {
            color::WHITE
        };
        ui::draw_str(
            fb, w, 4 + 4 * CHAR_WIDTH, TITLE_Y,
            to_display, to_text_color, color::BLACK,
        );

        // Separator line.
        let sep_y = TITLE_Y + CHAR_HEIGHT + 4;
        ui::fill_rect(fb, w, CONTENT_HEIGHT, 0, sep_y, w, 1, color::DARK_GREY);

        // Body field.
        let body_label_color = if self.compose_field == ComposeField::Body {
            color::YELLOW
        } else {
            color::DARK_GREY
        };
        let body_y = sep_y + 4;
        ui::draw_str(fb, w, 4, body_y, "Msg:", body_label_color, color::BLACK);

        let body_display = if self.compose_body.is_empty() {
            "Type message"
        } else {
            &self.compose_body
        };
        let body_text_color = if self.compose_body.is_empty() {
            color::DARK_GREY
        } else {
            color::WHITE
        };

        // Wrap the body text.
        let lines = word_wrap(body_display, CHARS_PER_LINE - 1);
        let text_y = body_y + CHAR_HEIGHT + 2;
        let max_lines = ((CONTENT_HEIGHT - text_y) / CHAR_HEIGHT) as usize;
        for (i, line) in lines.iter().take(max_lines).enumerate() {
            let ly = text_y + i as u16 * CHAR_HEIGHT;
            ui::draw_str(fb, w, 4, ly, line, body_text_color, color::BLACK);
        }
    }

    // --- Inbox input ---

    fn on_key_inbox(&mut self, key: Key) -> ScreenAction {
        match key {
            Key::Up => {
                self.move_up();
                ScreenAction::None
            }
            Key::Down => {
                self.move_down();
                ScreenAction::None
            }
            Key::Ok => {
                self.open_selected();
                ScreenAction::None
            }
            Key::Lsk => {
                self.enter_compose();
                ScreenAction::None
            }
            Key::Rsk | Key::End => ScreenAction::Back,
            _ => ScreenAction::None,
        }
    }

    // --- Detail input ---

    fn on_key_detail(&mut self, key: Key) -> ScreenAction {
        match key {
            Key::Up => {
                if self.detail_scroll > 0 {
                    self.detail_scroll -= 1;
                }
                ScreenAction::None
            }
            Key::Down => {
                self.detail_scroll += 1;
                ScreenAction::None
            }
            Key::Lsk => {
                // Reply: open compose with sender pre-filled.
                self.reset_compose();
                if let Some(msg) = self.messages.get(self.selected) {
                    let sender_bytes = msg.sender.as_bytes();
                    let copy_len = sender_bytes.len().min(MAX_RECIPIENT_LEN);
                    self.compose_to[..copy_len].copy_from_slice(&sender_bytes[..copy_len]);
                    self.compose_to_len = copy_len;
                    self.compose_field = ComposeField::Body;
                }
                self.view = MessageView::Compose;
                ScreenAction::None
            }
            Key::Rsk | Key::End => {
                self.view = MessageView::Inbox;
                ScreenAction::None
            }
            _ => ScreenAction::None,
        }
    }

    // --- Compose input ---

    fn on_key_compose(&mut self, key: Key) -> ScreenAction {
        match key {
            Key::Up | Key::Down => {
                // Toggle between To and Body fields.
                self.compose_field = match self.compose_field {
                    ComposeField::To => ComposeField::Body,
                    ComposeField::Body => ComposeField::To,
                };
                ScreenAction::None
            }
            Key::Lsk => {
                // SEND action -- the caller handles actual sending.
                // Return Navigate to trigger send flow.
                ScreenAction::None
            }
            Key::Rsk | Key::End => {
                self.view = MessageView::Inbox;
                self.reset_compose();
                ScreenAction::None
            }
            Key::Left => {
                self.compose_backspace();
                ScreenAction::None
            }
            key => {
                // Digit keys: append to active field.
                if let Some(ch) = key_to_digit_char(key) {
                    match self.compose_field {
                        ComposeField::To => self.compose_push_digit(ch),
                        ComposeField::Body => self.compose_body.push(ch),
                    }
                }
                ScreenAction::None
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Map a key to its digit character.
fn key_to_digit_char(key: Key) -> Option<char> {
    match key {
        Key::Num0 => Some('0'),
        Key::Num1 => Some('1'),
        Key::Num2 => Some('2'),
        Key::Num3 => Some('3'),
        Key::Num4 => Some('4'),
        Key::Num5 => Some('5'),
        Key::Num6 => Some('6'),
        Key::Num7 => Some('7'),
        Key::Num8 => Some('8'),
        Key::Num9 => Some('9'),
        Key::Star => Some('*'),
        Key::Hash => Some('#'),
        _ => None,
    }
}

/// Truncate a string to at most `max_len` characters.
///
/// Returns the original string if it fits, otherwise a truncated copy
/// with "..." is not appended (to keep things simple for the fixed-width
/// font renderer).
fn truncate_str(s: &str, max_len: usize) -> &str {
    if s.len() <= max_len {
        s
    } else {
        // Find a valid char boundary at or before max_len.
        let mut end = max_len;
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        &s[..end]
    }
}

/// Format an inbox entry's first line: "[marker] sender".
fn format_entry_line1(marker: &str, sender: &str) -> String {
    let mut line = String::with_capacity(marker.len() + sender.len() + 1);
    line.push_str(marker);
    line.push(' ');
    line.push_str(sender);
    line
}

/// Simple word-wrap for a text string.
///
/// Splits text into lines of at most `width` characters. Breaks at
/// whitespace when possible; forces a break mid-word if a single word
/// exceeds the line width.
fn word_wrap(text: &str, width: usize) -> Vec<String> {
    if width == 0 {
        return Vec::new();
    }

    let mut lines: Vec<String> = Vec::new();
    let mut current_line = String::new();

    for word in text.split_whitespace() {
        if current_line.is_empty() {
            // First word on the line.
            if word.len() > width {
                // Break long word across lines.
                let mut remaining = word;
                while remaining.len() > width {
                    let (chunk, rest) = split_at_char_boundary(remaining, width);
                    lines.push(String::from(chunk));
                    remaining = rest;
                }
                current_line.push_str(remaining);
            } else {
                current_line.push_str(word);
            }
        } else if current_line.len() + 1 + word.len() <= width {
            // Word fits on the current line.
            current_line.push(' ');
            current_line.push_str(word);
        } else {
            // Word doesn't fit; start a new line.
            lines.push(core::mem::take(&mut current_line));
            if word.len() > width {
                let mut remaining = word;
                while remaining.len() > width {
                    let (chunk, rest) = split_at_char_boundary(remaining, width);
                    lines.push(String::from(chunk));
                    remaining = rest;
                }
                current_line.push_str(remaining);
            } else {
                current_line.push_str(word);
            }
        }
    }

    if !current_line.is_empty() {
        lines.push(current_line);
    }

    // If text was empty, return at least one empty line.
    if lines.is_empty() {
        lines.push(String::new());
    }

    lines
}

/// Split a string at or before the given byte position on a char boundary.
fn split_at_char_boundary(s: &str, pos: usize) -> (&str, &str) {
    let mut split_pos = pos.min(s.len());
    while split_pos > 0 && !s.is_char_boundary(split_pos) {
        split_pos -= 1;
    }
    (&s[..split_pos], &s[split_pos..])
}

/// Format a Unix timestamp as a simple display string.
///
/// Produces "HH:MM" for the time portion only (date is omitted for
/// brevity in the inbox list).
fn format_timestamp(epoch: u64) -> String {
    let day_secs = epoch % 86400;
    let hour = day_secs / 3600;
    let minute = (day_secs % 3600) / 60;
    let mut s = String::with_capacity(5);
    s.push((b'0' + (hour / 10) as u8) as char);
    s.push((b'0' + (hour % 10) as u8) as char);
    s.push(':');
    s.push((b'0' + (minute / 10) as u8) as char);
    s.push((b'0' + (minute % 10) as u8) as char);
    s
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::CONTENT_PIXELS;

    fn make_test_messages() -> Vec<MessageEntry> {
        alloc::vec![
            MessageEntry {
                sender: String::from("+15551234567"),
                body: String::from("Hello, how are you doing today?"),
                timestamp: 1_775_924_600,
                read: false,
            },
            MessageEntry {
                sender: String::from("Alice"),
                body: String::from("Meeting at 3pm"),
                timestamp: 1_775_920_000,
                read: true,
            },
            MessageEntry {
                sender: String::from("Bob"),
                body: String::from("Got it, thanks!"),
                timestamp: 1_775_918_000,
                read: true,
            },
        ]
    }

    #[test]
    fn inbox_renders_entries() {
        let mut screen = MessagesScreen::new();
        screen.set_messages(make_test_messages());

        let mut fb = [0u16; CONTENT_PIXELS];
        screen.draw(&mut fb);

        // Should have rendered visible content.
        let any_set = fb.iter().any(|&px| px != 0);
        assert!(
            any_set,
            "inbox with messages must render visible pixels"
        );
    }

    #[test]
    fn compose_softkeys_correct() {
        let mut screen = MessagesScreen::new();
        // Enter compose mode.
        screen.enter_compose();
        assert_eq!(
            screen.softkey_left(),
            "SEND",
            "compose LSK must be 'SEND'"
        );
        assert_eq!(
            screen.softkey_right(),
            "BACK",
            "compose RSK must be 'BACK'"
        );
    }

    #[test]
    fn inbox_softkeys_correct() {
        let screen = MessagesScreen::new();
        assert_eq!(screen.softkey_left(), "NEW");
        assert_eq!(screen.softkey_right(), "BACK");
    }

    #[test]
    fn detail_softkeys_correct() {
        let mut screen = MessagesScreen::new();
        screen.set_messages(make_test_messages());
        screen.view = MessageView::Detail;
        assert_eq!(screen.softkey_left(), "REPLY");
        assert_eq!(screen.softkey_right(), "BACK");
    }

    #[test]
    fn navigate_up_down_in_inbox() {
        let mut screen = MessagesScreen::new();
        screen.set_messages(make_test_messages());

        assert_eq!(screen.selected_index(), 0);

        screen.on_key(Key::Down);
        assert_eq!(screen.selected_index(), 1);

        screen.on_key(Key::Down);
        assert_eq!(screen.selected_index(), 2);

        // At end, shouldn't go further.
        screen.on_key(Key::Down);
        assert_eq!(screen.selected_index(), 2);

        screen.on_key(Key::Up);
        assert_eq!(screen.selected_index(), 1);
    }

    #[test]
    fn ok_opens_detail_view() {
        let mut screen = MessagesScreen::new();
        screen.set_messages(make_test_messages());

        screen.on_key(Key::Ok);
        assert_eq!(screen.view, MessageView::Detail);
    }

    #[test]
    fn rsk_in_detail_returns_to_inbox() {
        let mut screen = MessagesScreen::new();
        screen.set_messages(make_test_messages());
        screen.view = MessageView::Detail;

        screen.on_key(Key::Rsk);
        assert_eq!(screen.view, MessageView::Inbox);
    }

    #[test]
    fn lsk_opens_compose() {
        let mut screen = MessagesScreen::new();
        screen.on_key(Key::Lsk);
        assert_eq!(screen.view, MessageView::Compose);
    }

    #[test]
    fn compose_digit_entry() {
        let mut screen = MessagesScreen::new();
        screen.enter_compose();

        screen.on_key(Key::Num1);
        screen.on_key(Key::Num2);
        screen.on_key(Key::Num3);

        assert_eq!(screen.compose_to_str(), "123");
    }

    #[test]
    fn word_wrap_basic() {
        let lines = word_wrap("hello world foo bar", 10);
        assert!(lines.len() >= 2, "must wrap at word boundaries");
        assert!(
            lines.iter().all(|l| l.len() <= 10),
            "no line must exceed width"
        );
    }

    #[test]
    fn word_wrap_long_word() {
        let lines = word_wrap("superlongword", 5);
        assert!(lines.len() >= 2, "long word must be force-broken");
    }

    #[test]
    fn truncate_str_short() {
        assert_eq!(truncate_str("hello", 10), "hello");
    }

    #[test]
    fn truncate_str_exact() {
        assert_eq!(truncate_str("hello", 5), "hello");
    }

    #[test]
    fn truncate_str_long() {
        let result = truncate_str("hello world", 5);
        assert_eq!(result.len(), 5);
    }

    #[test]
    fn empty_inbox_renders() {
        let screen = MessagesScreen::new();
        let mut fb = [0u16; CONTENT_PIXELS];
        screen.draw(&mut fb);
        let any_set = fb.iter().any(|&px| px != 0);
        assert!(any_set, "empty inbox must render 'No messages' text");
    }

    #[test]
    fn format_timestamp_correct() {
        // 14:30:00 UTC
        let ts = 14 * 3600 + 30 * 60;
        let result = format_timestamp(ts);
        assert_eq!(result, "14:30");
    }

    #[test]
    fn rsk_in_inbox_goes_back() {
        let mut screen = MessagesScreen::new();
        let action = screen.on_key(Key::Rsk);
        assert_eq!(action, ScreenAction::Back);
    }

    #[test]
    fn compose_renders_without_panic() {
        let mut screen = MessagesScreen::new();
        screen.enter_compose();
        let mut fb = [0u16; CONTENT_PIXELS];
        screen.draw(&mut fb);
    }
}
