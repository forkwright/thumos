//! Nous chat screen for the thumos kernel UI.
//!
//! Implements the [`Screen`] trait to display a conversation with the
//! currently active nous entity via its Matrix room. Uses the same
//! message rendering approach as [`crate::screen_messages`] but adds
//! action proposal cards when a message contains a `thumos_action`
//! JSON block (parsed by [`crate::ekphrasis::parse_action_proposal`]).
//!
//! ## Layout
//!
//! ```text
//! ┌─────────────────────────────┐
//! │ NOUS: Syn [ADVISOR]         │  ← title bar
//! ├─────────────────────────────┤
//! │ Syn: Sure, I'll call Maria  │  ← message bubble
//! │                             │
//! │ ┌─────────────────────────┐ │
//! │ │ Syn suggests:           │ │  ← action proposal card
//! │ │ CALL MARIA              │ │
//! │ │ +1 555 0100             │ │
//! │ │ [CANCEL]       [CONFIRM]│ │
//! │ └─────────────────────────┘ │
//! │                             │
//! │ You: Call Maria please      │  ← user message
//! ├─────────────────────────────┤
//! │ SWITCH              BACK    │  ← softkeys
//! └─────────────────────────────┘
//! ```
//!
//! ## Navigation
//!
//! | Key    | Action                                    |
//! |--------|-------------------------------------------|
//! | LSK    | SWITCH (cycle active nous entity)          |
//! | RSK    | BACK (return to previous screen)           |
//! | OK     | Send typed message / confirm proposal      |
//! | Up     | Scroll up in conversation                  |
//! | Down   | Scroll down in conversation                |
//! | Left   | Cancel action proposal (if visible)        |
//! | Right  | Confirm action proposal (if visible)       |
//! | 0-9    | Input text (for message compose)           |
//!
//! ## Action proposal cards
//!
//! When a message body contains a fenced `thumos-action` JSON block
//! (detected by [`crate::ekphrasis::parse_action_proposal`]), the
//! screen renders a bordered card showing the action description and
//! CANCEL/CONFIRM buttons. The user navigates with Left (cancel) or
//! Right (confirm).

// WHY: nous chat screen created in Phase 09 Wave 8, full integration pending.
#![expect(
    dead_code,
    reason = "Nous chat screen created in Phase 09 Wave 8, integration pending"
)]

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

use crate::ekphrasis::{self, ActionProposal};
use crate::nous::{CapabilityPreset, NousManager};
use crate::ui::{
    self, color, Key, Screen, ScreenAction,
    CHAR_HEIGHT, CHAR_WIDTH, CONTENT_HEIGHT, SCREEN_WIDTH,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Left/right padding for message text.
const PADDING_X: u16 = 4;

/// Top padding for the first message row.
const PADDING_Y: u16 = 4;

/// Height of each message row (text height + vertical spacing).
const MSG_ROW_HEIGHT: u16 = CHAR_HEIGHT + 6;

/// Maximum characters per line (word-wrap boundary).
const CHARS_PER_LINE: usize = (SCREEN_WIDTH as usize - PADDING_X as usize * 2)
    / (CHAR_WIDTH as usize);

/// Maximum messages held in the conversation buffer.
const MAX_MESSAGES: usize = 64;

/// Maximum length of a single message body.
const MAX_MSG_LEN: usize = 1024;

/// Action proposal card border padding.
const CARD_PADDING: u16 = 4;

/// Action proposal card border color.
const CARD_BORDER_COLOR: u16 = color::from_rgb(80, 80, 120);

/// Action proposal card background color.
const CARD_BG_COLOR: u16 = color::from_rgb(20, 20, 40);

/// Action proposal confirm button color.
const CONFIRM_COLOR: u16 = color::GREEN;

/// Action proposal cancel button color.
const CANCEL_COLOR: u16 = color::RED;

/// Color for nous entity name in messages.
const NOUS_NAME_COLOR: u16 = color::from_rgb(100, 180, 255);

/// Color for user messages.
const USER_MSG_COLOR: u16 = color::from_rgb(200, 200, 200);

/// Maximum visible lines in the content area.
const MAX_VISIBLE_LINES: usize =
    (CONTENT_HEIGHT as usize) / (MSG_ROW_HEIGHT as usize);

// ---------------------------------------------------------------------------
// Chat message
// ---------------------------------------------------------------------------

/// Origin of a chat message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageOrigin {
    /// Sent by the user.
    User,
    /// Sent by a nous entity.
    Nous,
}

impl core::fmt::Display for MessageOrigin {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::User => f.write_str("You"),
            Self::Nous => f.write_str("Nous"),
        }
    }
}

/// A single chat message in the conversation history.
#[derive(Debug, Clone)]
pub struct ChatMessage {
    /// Who sent this message.
    pub origin: MessageOrigin,
    /// The sender label (entity name for nous, "You" for user).
    pub sender: String,
    /// The message body text.
    pub body: String,
    /// Parsed action proposal, if the message body contained one.
    pub proposal: Option<ActionProposal>,
    /// Unix timestamp (seconds).
    pub timestamp: u64,
}

impl ChatMessage {
    /// Create a new user message.
    #[must_use]
    pub(crate) fn from_user(body: String, timestamp: u64) -> Self {
        Self {
            origin: MessageOrigin::User,
            sender: String::from("You"),
            body,
            proposal: None,
            timestamp,
        }
    }

    /// Create a new nous entity message, parsing any action proposal.
    #[must_use]
    pub(crate) fn from_nous(sender: &str, body: String, timestamp: u64) -> Self {
        let proposal = ekphrasis::parse_action_proposal(&body)
            .and_then(Result::ok);
        Self {
            origin: MessageOrigin::Nous,
            sender: String::from(sender),
            body,
            proposal,
            timestamp,
        }
    }

    /// Number of wrapped lines this message occupies.
    fn line_count(&self) -> usize {
        // Header line ("Sender:").
        let mut lines = 1;
        // Body lines (word-wrapped).
        let body_len = self.body.len();
        if body_len > 0 {
            lines += body_len.div_ceil(CHARS_PER_LINE);
        }
        // Action proposal card takes 5 lines.
        if self.proposal.is_some() {
            lines += 5;
        }
        lines
    }
}

impl core::fmt::Display for ChatMessage {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}: {}", self.sender, self.body)
    }
}

// ---------------------------------------------------------------------------
// Proposal confirmation state
// ---------------------------------------------------------------------------

/// State of an action proposal confirmation flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProposalState {
    /// Proposal is being displayed, awaiting user input.
    Pending,
    /// User confirmed the proposal.
    Confirmed,
    /// User cancelled the proposal.
    Cancelled,
}

impl core::fmt::Display for ProposalState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Pending => f.write_str("pending"),
            Self::Confirmed => f.write_str("confirmed"),
            Self::Cancelled => f.write_str("cancelled"),
        }
    }
}

// ---------------------------------------------------------------------------
// Nous chat screen
// ---------------------------------------------------------------------------

/// Nous chat screen — conversation with the active nous entity.
///
/// Renders messages in chronological order (newest at bottom) with
/// action proposal cards inline. The user can type messages via
/// numeric keys (T9-style input delegated to the caller) and send
/// with the OK key.
pub(crate) struct NousChatScreen {
    /// Conversation messages.
    messages: Vec<ChatMessage>,
    /// Scroll offset (number of lines scrolled from bottom).
    scroll_offset: usize,
    /// Input buffer for composing a message.
    input_buffer: String,
    /// Active proposal state (if any pending proposal exists).
    pending_proposal: Option<ProposalState>,
    /// Index of the message with the pending proposal.
    pending_proposal_msg_idx: Option<usize>,
    /// Cached name of the active entity (for title rendering).
    active_entity_name: String,
    /// Cached capability preset label of the active entity.
    active_preset_label: &'static str,
}

impl NousChatScreen {
    /// Create a new nous chat screen.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            messages: Vec::new(),
            scroll_offset: 0,
            input_buffer: String::new(),
            pending_proposal: None,
            pending_proposal_msg_idx: None,
            active_entity_name: String::from("Syn"),
            active_preset_label: CapabilityPreset::Advisor.label(),
        }
    }

    /// Update the cached entity info from a nous manager.
    pub(crate) fn sync_from_manager(&mut self, manager: &NousManager) {
        if let Some(entity) = manager.active() {
            self.active_entity_name = String::from(entity.name_str());
            self.active_preset_label = entity.capability_label();
        }
    }

    /// Add a message to the conversation.
    ///
    /// If the message is from a nous entity and contains an action
    /// proposal, it becomes the pending proposal.
    pub(crate) fn push_message(&mut self, msg: ChatMessage) {
        let has_proposal = msg.proposal.is_some();
        let _msg_idx = self.messages.len();

        // Enforce max messages — remove oldest if full.
        if self.messages.len() >= MAX_MESSAGES {
            self.messages.remove(0);
            // Adjust pending proposal index.
            if let Some(idx) = self.pending_proposal_msg_idx {
                if idx == 0 {
                    self.pending_proposal = None;
                    self.pending_proposal_msg_idx = None;
                } else {
                    self.pending_proposal_msg_idx = Some(idx - 1);
                }
            }
        }

        self.messages.push(msg);

        if has_proposal {
            self.pending_proposal = Some(ProposalState::Pending);
            self.pending_proposal_msg_idx = Some(
                self.messages.len().saturating_sub(1),
            );
        }

        // Auto-scroll to bottom.
        self.scroll_offset = 0;
    }

    /// Return the number of messages in the conversation.
    #[must_use]
    pub(crate) fn message_count(&self) -> usize {
        self.messages.len()
    }

    /// Return the current pending proposal state, if any.
    #[must_use]
    pub(crate) fn pending_proposal(&self) -> Option<ProposalState> {
        self.pending_proposal
    }

    /// Return the pending proposal action, if one exists.
    #[must_use]
    pub(crate) fn pending_action(&self) -> Option<&ActionProposal> {
        self.pending_proposal_msg_idx
            .and_then(|idx| self.messages.get(idx))
            .and_then(|msg| msg.proposal.as_ref())
    }

    /// Confirm the pending action proposal.
    pub(crate) fn confirm_proposal(&mut self) {
        if self.pending_proposal == Some(ProposalState::Pending) {
            self.pending_proposal = Some(ProposalState::Confirmed);
        }
    }

    /// Cancel the pending action proposal.
    pub(crate) fn cancel_proposal(&mut self) {
        if self.pending_proposal == Some(ProposalState::Pending) {
            self.pending_proposal = Some(ProposalState::Cancelled);
        }
    }

    /// Clear the pending proposal after it has been handled.
    pub(crate) fn clear_proposal(&mut self) {
        self.pending_proposal = None;
        self.pending_proposal_msg_idx = None;
    }

    /// Return a reference to the input buffer.
    #[must_use]
    pub(crate) fn input_buffer(&self) -> &str {
        &self.input_buffer
    }

    /// Append a character to the input buffer.
    pub(crate) fn input_push(&mut self, ch: char) {
        if self.input_buffer.len() < MAX_MSG_LEN {
            self.input_buffer.push(ch);
        }
    }

    /// Remove the last character from the input buffer.
    pub(crate) fn input_backspace(&mut self) {
        self.input_buffer.pop();
    }

    /// Take the current input buffer contents, clearing it.
    pub(crate) fn take_input(&mut self) -> String {
        core::mem::take(&mut self.input_buffer)
    }

    /// Scroll up by one page.
    fn scroll_up(&mut self) {
        let total_lines: usize = self.messages.iter().map(ChatMessage::line_count).sum();
        let max_scroll = total_lines.saturating_sub(MAX_VISIBLE_LINES);
        if self.scroll_offset < max_scroll {
            self.scroll_offset = (self.scroll_offset + MAX_VISIBLE_LINES / 2)
                .min(max_scroll);
        }
    }

    /// Scroll down by half a page.
    fn scroll_down(&mut self) {
        if self.scroll_offset > 0 {
            self.scroll_offset = self.scroll_offset
                .saturating_sub(MAX_VISIBLE_LINES / 2);
        }
    }

    /// Total number of rendered lines across all messages.
    fn total_lines(&self) -> usize {
        self.messages.iter().map(ChatMessage::line_count).sum()
    }
}

// ---------------------------------------------------------------------------
// Drawing helpers
// ---------------------------------------------------------------------------

/// Draw a horizontal line (1px tall).
fn draw_hline(fb: &mut [u16], x: u16, y: u16, width: u16, color: u16) {
    ui::fill_rect(fb, SCREEN_WIDTH, CONTENT_HEIGHT, x, y, width, 1, color);
}

/// Draw a vertical line (1px wide).
fn draw_vline(fb: &mut [u16], x: u16, y: u16, height: u16, color: u16) {
    ui::fill_rect(fb, SCREEN_WIDTH, CONTENT_HEIGHT, x, y, 1, height, color);
}

/// Draw a bordered rectangle (1px border).
fn draw_border(fb: &mut [u16], x: u16, y: u16, w: u16, h: u16, border_color: u16) {
    draw_hline(fb, x, y, w, border_color);                     // top
    draw_hline(fb, x, y.saturating_add(h - 1), w, border_color); // bottom
    draw_vline(fb, x, y, h, border_color);                     // left
    draw_vline(fb, x.saturating_add(w - 1), y, h, border_color); // right
}

/// Draw an action proposal card.
///
/// Returns the number of pixel rows consumed.
fn draw_proposal_card(
    fb: &mut [u16],
    proposal: &ActionProposal,
    entity_name: &str,
    y_start: u16,
    state: ProposalState,
) -> u16 {
    let card_x = PADDING_X;
    let card_w = SCREEN_WIDTH - PADDING_X * 2;
    let card_h = MSG_ROW_HEIGHT * 4 + CARD_PADDING * 2;

    // Background fill.
    ui::fill_rect(
        fb, SCREEN_WIDTH, CONTENT_HEIGHT,
        card_x, y_start, card_w, card_h, CARD_BG_COLOR,
    );

    // Border.
    draw_border(fb, card_x, y_start, card_w, card_h, CARD_BORDER_COLOR);

    let text_x = card_x + CARD_PADDING + 2;
    let mut text_y = y_start + CARD_PADDING;

    // Line 1: "Entity suggests:"
    let header = format_card_header(entity_name);
    ui::draw_str(
        fb, SCREEN_WIDTH, text_x, text_y,
        &header, NOUS_NAME_COLOR, CARD_BG_COLOR,
    );
    text_y += MSG_ROW_HEIGHT;

    // Line 2: Action description (uppercase).
    let desc_upper = to_uppercase_truncated(&proposal.description, CHARS_PER_LINE - 2);
    ui::draw_str(
        fb, SCREEN_WIDTH, text_x, text_y,
        &desc_upper, color::WHITE, CARD_BG_COLOR,
    );
    text_y += MSG_ROW_HEIGHT;

    // Line 3: First param value (e.g., phone number).
    if let Some((_, value)) = proposal.params.first() {
        let param_display = truncate_str(value, CHARS_PER_LINE - 2);
        ui::draw_str(
            fb, SCREEN_WIDTH, text_x, text_y,
            &param_display, color::DARK_GREY, CARD_BG_COLOR,
        );
    }
    text_y += MSG_ROW_HEIGHT;

    // Line 4: CANCEL / CONFIRM buttons.
    let (cancel_color, confirm_color) = match state {
        ProposalState::Pending => (CANCEL_COLOR, CONFIRM_COLOR),
        ProposalState::Confirmed => (color::DARK_GREY, CONFIRM_COLOR),
        ProposalState::Cancelled => (CANCEL_COLOR, color::DARK_GREY),
    };

    ui::draw_str(
        fb, SCREEN_WIDTH, text_x, text_y,
        "[CANCEL]", cancel_color, CARD_BG_COLOR,
    );

    let confirm_x = card_x + card_w - CARD_PADDING - 2
        - "[CONFIRM]".len() as u16 * CHAR_WIDTH;
    ui::draw_str(
        fb, SCREEN_WIDTH, confirm_x, text_y,
        "[CONFIRM]", confirm_color, CARD_BG_COLOR,
    );

    card_h
}

/// Format the card header line.
fn format_card_header(entity_name: &str) -> String {
    let mut s = String::with_capacity(entity_name.len() + 12);
    s.push_str(entity_name);
    s.push_str(" suggests:");
    s
}

/// Truncate a string to at most `max_len` characters.
fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        String::from(s)
    } else {
        let mut result = String::with_capacity(max_len);
        for (i, ch) in s.chars().enumerate() {
            if i >= max_len - 1 {
                result.push('~');
                break;
            }
            result.push(ch);
        }
        result
    }
}

/// Convert a string to uppercase, truncated to `max_len`.
fn to_uppercase_truncated(s: &str, max_len: usize) -> String {
    let mut result = String::with_capacity(max_len.min(s.len()));
    for (i, ch) in s.chars().enumerate() {
        if i >= max_len {
            break;
        }
        // ASCII uppercase only (no_std constraint).
        if ch.is_ascii_lowercase() {
            result.push((ch as u8 - b'a' + b'A') as char);
        } else {
            result.push(ch);
        }
    }
    result
}

// ---------------------------------------------------------------------------
// Screen trait implementation
// ---------------------------------------------------------------------------

impl Screen for NousChatScreen {
    fn draw(&self, fb: &mut [u16]) {
        let w = SCREEN_WIDTH;
        let h = CONTENT_HEIGHT;

        // Clear content area.
        ui::fill_rect(fb, w, h, 0, 0, w, h, color::BLACK);

        // Draw title: "NOUS: EntityName [PRESET]"
        let title_str = format_title(&self.active_entity_name, self.active_preset_label);
        ui::draw_str(
            fb, w, PADDING_X, PADDING_Y,
            &title_str, NOUS_NAME_COLOR, color::BLACK,
        );

        // Separator below title.
        let sep_y = PADDING_Y + CHAR_HEIGHT + 2;
        draw_hline(fb, PADDING_X, sep_y, w - PADDING_X * 2, color::DARK_GREY);

        // Message area starts after title + separator.
        let msg_area_start = sep_y + 4;
        let msg_area_height = h - msg_area_start - CHAR_HEIGHT - 4; // leave room for input

        if self.messages.is_empty() {
            // Empty state.
            ui::draw_str_centered(
                fb, w, 0, w,
                msg_area_start + msg_area_height / 2 - CHAR_HEIGHT / 2,
                "No messages", color::DARK_GREY, color::BLACK,
            );
        } else {
            // Calculate which lines to display (scrolled from bottom).
            let total = self.total_lines();
            let visible_lines = (msg_area_height / MSG_ROW_HEIGHT) as usize;

            // Start line index (from bottom, accounting for scroll).
            let end_line = total.saturating_sub(self.scroll_offset);
            let start_line = end_line.saturating_sub(visible_lines);

            // Render messages that fall within the visible window.
            let mut current_line: usize = 0;
            let mut render_y = msg_area_start;

            for (msg_idx, msg) in self.messages.iter().enumerate() {
                let msg_lines = msg.line_count();
                let msg_end_line = current_line + msg_lines;

                // Skip messages entirely before the visible window.
                if msg_end_line <= start_line {
                    current_line = msg_end_line;
                    continue;
                }

                // Stop if we've passed the visible window.
                if current_line >= end_line {
                    break;
                }

                // Draw sender header.
                if current_line >= start_line && render_y < msg_area_start + msg_area_height {
                    let name_color = match msg.origin {
                        MessageOrigin::Nous => NOUS_NAME_COLOR,
                        MessageOrigin::User => color::YELLOW,
                    };
                    let header = format_msg_header(&msg.sender);
                    ui::draw_str(
                        fb, w, PADDING_X, render_y,
                        &header, name_color, color::BLACK,
                    );
                    render_y += MSG_ROW_HEIGHT;
                }

                // Draw body lines (word-wrapped).
                let body_color = match msg.origin {
                    MessageOrigin::Nous => color::WHITE,
                    MessageOrigin::User => USER_MSG_COLOR,
                };

                let body_bytes = msg.body.as_bytes();
                let mut offset = 0;
                while offset < body_bytes.len() {
                    let line_end = (offset + CHARS_PER_LINE).min(body_bytes.len());
                    if render_y < msg_area_start + msg_area_height {
                        let line_str = core::str::from_utf8(&body_bytes[offset..line_end])
                            .unwrap_or("");
                        ui::draw_str(
                            fb, w, PADDING_X + CHAR_WIDTH, render_y,
                            line_str, body_color, color::BLACK,
                        );
                        render_y += MSG_ROW_HEIGHT;
                    }
                    offset = line_end;
                }

                // Draw action proposal card if present.
                if let Some(ref proposal) = msg.proposal {
                    let state = if Some(msg_idx) == self.pending_proposal_msg_idx {
                        self.pending_proposal.unwrap_or(ProposalState::Pending)
                    } else {
                        ProposalState::Cancelled // Already handled.
                    };

                    if render_y < msg_area_start + msg_area_height {
                        let card_h = draw_proposal_card(
                            fb, proposal, &msg.sender, render_y, state,
                        );
                        render_y += card_h;
                    }
                }

                current_line = msg_end_line;
            }
        }

        // Input area at bottom of content.
        let input_y = h - CHAR_HEIGHT - 2;
        draw_hline(fb, PADDING_X, input_y - 2, w - PADDING_X * 2, color::DARK_GREY);

        // Show input buffer or prompt.
        if self.input_buffer.is_empty() {
            ui::draw_str(
                fb, w, PADDING_X, input_y,
                "Type a message...", color::DARK_GREY, color::BLACK,
            );
        } else {
            // Show last CHARS_PER_LINE characters of input.
            let display_start = if self.input_buffer.len() > CHARS_PER_LINE {
                self.input_buffer.len() - CHARS_PER_LINE
            } else {
                0
            };
            let display_text = &self.input_buffer[display_start..];
            ui::draw_str(
                fb, w, PADDING_X, input_y,
                display_text, color::WHITE, color::BLACK,
            );
        }
    }

    #[allow(clippy::match_same_arms)] // WHY: LSK semantically distinct — caller dispatches entity switch.
    fn on_key(&mut self, key: Key) -> ScreenAction {
        match key {
            // LSK: switch nous entity — returns None because the caller
            // handles entity cycling via NousManager::cycle_next().
            Key::Lsk => ScreenAction::None,

            // RSK / End: go back.
            Key::Rsk | Key::End => ScreenAction::Back,

            // OK: send message.
            Key::Ok => {
                // If there's a pending proposal, confirm it.
                if self.pending_proposal == Some(ProposalState::Pending) {
                    self.confirm_proposal();
                }
                // Otherwise, the caller takes the input buffer.
                ScreenAction::None
            }

            // Up: scroll up.
            Key::Up => {
                self.scroll_up();
                ScreenAction::None
            }

            // Down: scroll down.
            Key::Down => {
                self.scroll_down();
                ScreenAction::None
            }

            // Left: cancel proposal.
            Key::Left => {
                if self.pending_proposal == Some(ProposalState::Pending) {
                    self.cancel_proposal();
                }
                ScreenAction::None
            }

            // Right: confirm proposal.
            Key::Right => {
                if self.pending_proposal == Some(ProposalState::Pending) {
                    self.confirm_proposal();
                }
                ScreenAction::None
            }

            // Star: backspace.
            Key::Star => {
                self.input_backspace();
                ScreenAction::None
            }

            // Digit keys: append to input (T9 mapping done by caller).
            Key::Num0 => { self.input_push(' '); ScreenAction::None }
            Key::Num1 => { self.input_push('1'); ScreenAction::None }
            Key::Num2 => { self.input_push('a'); ScreenAction::None }
            Key::Num3 => { self.input_push('d'); ScreenAction::None }
            Key::Num4 => { self.input_push('g'); ScreenAction::None }
            Key::Num5 => { self.input_push('j'); ScreenAction::None }
            Key::Num6 => { self.input_push('m'); ScreenAction::None }
            Key::Num7 => { self.input_push('p'); ScreenAction::None }
            Key::Num8 => { self.input_push('t'); ScreenAction::None }
            Key::Num9 => { self.input_push('w'); ScreenAction::None }

            _ => ScreenAction::None,
        }
    }

    fn softkey_left(&self) -> &'static str {
        "SWITCH"
    }

    fn softkey_right(&self) -> &'static str {
        "BACK"
    }

    fn title(&self) -> &'static str {
        "Nous"
    }
}

/// Format the screen title.
fn format_title(entity_name: &str, preset_label: &str) -> String {
    let mut s = String::with_capacity(entity_name.len() + preset_label.len() + 10);
    s.push_str("NOUS: ");
    s.push_str(entity_name);
    s.push_str(" [");
    s.push_str(preset_label);
    s.push(']');
    s
}

/// Format a message header line.
fn format_msg_header(sender: &str) -> String {
    let mut s = String::with_capacity(sender.len() + 2);
    s.push_str(sender);
    s.push(':');
    s
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;
    use crate::ui::CONTENT_PIXELS;

    #[test]
    fn screen_new_defaults() {
        let screen = NousChatScreen::new();
        assert_eq!(screen.message_count(), 0);
        assert!(screen.pending_proposal().is_none());
        assert!(screen.input_buffer().is_empty());
        assert_eq!(screen.softkey_left(), "SWITCH");
        assert_eq!(screen.softkey_right(), "BACK");
    }

    #[test]
    fn push_user_message() {
        let mut screen = NousChatScreen::new();
        let msg = ChatMessage::from_user(String::from("Hello Syn"), 1000);
        screen.push_message(msg);
        assert_eq!(screen.message_count(), 1);
        assert!(screen.pending_proposal().is_none());
    }

    #[test]
    fn push_nous_message_without_proposal() {
        let mut screen = NousChatScreen::new();
        let msg = ChatMessage::from_nous(
            "Syn",
            String::from("Hello Cody, how can I help?"),
            1000,
        );
        screen.push_message(msg);
        assert_eq!(screen.message_count(), 1);
        assert!(screen.pending_proposal().is_none());
    }

    #[test]
    fn push_nous_message_with_proposal() {
        let mut screen = NousChatScreen::new();
        let body = String::from(
            "Sure, I'll call Maria.\n\n```thumos-action\n{\"thumos_action\": \"open_dialer\", \"params\": {\"number\": \"+15550100\"}, \"description\": \"Call Maria\"}\n```"
        );
        let msg = ChatMessage::from_nous("Syn", body, 1000);
        screen.push_message(msg);
        assert_eq!(screen.message_count(), 1);
        assert_eq!(screen.pending_proposal(), Some(ProposalState::Pending));

        let action = screen.pending_action();
        assert!(action.is_some());
        assert_eq!(
            action.map(|a| a.action.as_str()),
            Some("open_dialer"),
        );
    }

    #[test]
    fn confirm_proposal() {
        let mut screen = NousChatScreen::new();
        let body = String::from(
            "```thumos-action\n{\"thumos_action\": \"start_timer\", \"params\": {\"duration\": \"300\"}, \"description\": \"5 minute timer\"}\n```"
        );
        let msg = ChatMessage::from_nous("Syn", body, 1000);
        screen.push_message(msg);

        assert_eq!(screen.pending_proposal(), Some(ProposalState::Pending));
        screen.confirm_proposal();
        assert_eq!(screen.pending_proposal(), Some(ProposalState::Confirmed));
    }

    #[test]
    fn cancel_proposal() {
        let mut screen = NousChatScreen::new();
        let body = String::from(
            "```thumos-action\n{\"thumos_action\": \"open_dialer\", \"params\": {}, \"description\": \"Call someone\"}\n```"
        );
        let msg = ChatMessage::from_nous("Syn", body, 1000);
        screen.push_message(msg);

        screen.cancel_proposal();
        assert_eq!(screen.pending_proposal(), Some(ProposalState::Cancelled));
    }

    #[test]
    fn clear_proposal() {
        let mut screen = NousChatScreen::new();
        let body = String::from(
            "```thumos-action\n{\"thumos_action\": \"open_dialer\", \"params\": {}, \"description\": \"Test\"}\n```"
        );
        let msg = ChatMessage::from_nous("Syn", body, 1000);
        screen.push_message(msg);

        screen.confirm_proposal();
        screen.clear_proposal();
        assert!(screen.pending_proposal().is_none());
        assert!(screen.pending_action().is_none());
    }

    #[test]
    fn input_buffer_operations() {
        let mut screen = NousChatScreen::new();
        screen.input_push('H');
        screen.input_push('i');
        assert_eq!(screen.input_buffer(), "Hi");

        screen.input_backspace();
        assert_eq!(screen.input_buffer(), "H");

        let taken = screen.take_input();
        assert_eq!(taken, "H");
        assert!(screen.input_buffer().is_empty());
    }

    #[test]
    fn input_buffer_max_length() {
        let mut screen = NousChatScreen::new();
        for _ in 0..MAX_MSG_LEN + 10 {
            screen.input_push('x');
        }
        assert_eq!(
            screen.input_buffer().len(),
            MAX_MSG_LEN,
            "input must be clamped to MAX_MSG_LEN"
        );
    }

    #[test]
    fn scroll_operations() {
        let mut screen = NousChatScreen::new();
        // Add enough messages to overflow the screen.
        for i in 0..30 {
            let msg = ChatMessage::from_user(
                alloc::format!("Message number {i} with some extra text"),
                i as u64 * 100,
            );
            screen.push_message(msg);
        }

        assert_eq!(screen.scroll_offset, 0, "starts at bottom");
        screen.scroll_up();
        assert!(screen.scroll_offset > 0, "scroll_up must increase offset");
        let up_offset = screen.scroll_offset;
        screen.scroll_down();
        assert!(
            screen.scroll_offset < up_offset,
            "scroll_down must decrease offset"
        );
    }

    #[test]
    fn max_messages_eviction() {
        let mut screen = NousChatScreen::new();
        for i in 0..MAX_MESSAGES + 5 {
            let msg = ChatMessage::from_user(
                alloc::format!("msg {i}"),
                i as u64,
            );
            screen.push_message(msg);
        }
        assert_eq!(
            screen.message_count(),
            MAX_MESSAGES,
            "must evict oldest messages"
        );
    }

    #[test]
    fn on_key_rsk_returns_back() {
        let mut screen = NousChatScreen::new();
        assert_eq!(screen.on_key(Key::Rsk), ScreenAction::Back);
    }

    #[test]
    fn on_key_end_returns_back() {
        let mut screen = NousChatScreen::new();
        assert_eq!(screen.on_key(Key::End), ScreenAction::Back);
    }

    #[test]
    fn on_key_lsk_returns_none() {
        let mut screen = NousChatScreen::new();
        // LSK (SWITCH) returns None — caller handles entity cycling.
        assert_eq!(screen.on_key(Key::Lsk), ScreenAction::None);
    }

    #[test]
    fn on_key_digit_appends_input() {
        let mut screen = NousChatScreen::new();
        screen.on_key(Key::Num0); // space
        screen.on_key(Key::Num2); // 'a'
        assert_eq!(screen.input_buffer(), " a");
    }

    #[test]
    fn on_key_star_backspaces() {
        let mut screen = NousChatScreen::new();
        screen.input_push('x');
        screen.input_push('y');
        screen.on_key(Key::Star);
        assert_eq!(screen.input_buffer(), "x");
    }

    #[test]
    fn on_key_left_cancels_proposal() {
        let mut screen = NousChatScreen::new();
        let body = String::from(
            "```thumos-action\n{\"thumos_action\": \"test\", \"params\": {}, \"description\": \"Test\"}\n```"
        );
        screen.push_message(ChatMessage::from_nous("Syn", body, 1000));
        assert_eq!(screen.pending_proposal(), Some(ProposalState::Pending));

        screen.on_key(Key::Left);
        assert_eq!(screen.pending_proposal(), Some(ProposalState::Cancelled));
    }

    #[test]
    fn on_key_right_confirms_proposal() {
        let mut screen = NousChatScreen::new();
        let body = String::from(
            "```thumos-action\n{\"thumos_action\": \"test\", \"params\": {}, \"description\": \"Test\"}\n```"
        );
        screen.push_message(ChatMessage::from_nous("Syn", body, 1000));

        screen.on_key(Key::Right);
        assert_eq!(screen.pending_proposal(), Some(ProposalState::Confirmed));
    }

    #[test]
    fn on_key_ok_confirms_pending_proposal() {
        let mut screen = NousChatScreen::new();
        let body = String::from(
            "```thumos-action\n{\"thumos_action\": \"test\", \"params\": {}, \"description\": \"Test\"}\n```"
        );
        screen.push_message(ChatMessage::from_nous("Syn", body, 1000));

        screen.on_key(Key::Ok);
        assert_eq!(screen.pending_proposal(), Some(ProposalState::Confirmed));
    }

    #[test]
    fn draw_does_not_panic_empty() {
        let screen = NousChatScreen::new();
        let mut fb = [0u16; CONTENT_PIXELS];
        screen.draw(&mut fb);
        // No panic = success.
    }

    #[test]
    fn draw_does_not_panic_with_messages() {
        let mut screen = NousChatScreen::new();
        screen.push_message(ChatMessage::from_user(
            String::from("Hello"),
            1000,
        ));
        screen.push_message(ChatMessage::from_nous(
            "Syn",
            String::from("Hi there!"),
            1001,
        ));

        let mut fb = [0u16; CONTENT_PIXELS];
        screen.draw(&mut fb);
    }

    #[test]
    fn draw_does_not_panic_with_proposal() {
        let mut screen = NousChatScreen::new();
        let body = String::from(
            "```thumos-action\n{\"thumos_action\": \"open_dialer\", \"params\": {\"number\": \"+15550100\"}, \"description\": \"Call Maria\"}\n```"
        );
        screen.push_message(ChatMessage::from_nous("Syn", body, 1000));

        let mut fb = [0u16; CONTENT_PIXELS];
        screen.draw(&mut fb);
    }

    #[test]
    fn sync_from_manager() {
        let mut screen = NousChatScreen::new();
        let mgr = NousManager::new();
        screen.sync_from_manager(&mgr);
        assert_eq!(screen.active_entity_name, "Syn");
        assert_eq!(screen.active_preset_label, "ADVISOR");
    }

    #[test]
    fn chat_message_line_count() {
        // Simple short message: 1 header + 1 body = 2 lines.
        let msg = ChatMessage::from_user(String::from("Hi"), 0);
        assert_eq!(msg.line_count(), 2);

        // Empty body: 1 header line.
        let msg = ChatMessage::from_user(String::from(""), 0);
        assert_eq!(msg.line_count(), 1);
    }

    #[test]
    fn chat_message_display() {
        let msg = ChatMessage::from_user(String::from("Hello world"), 0);
        let display = alloc::format!("{msg}");
        assert_eq!(display, "You: Hello world");
    }

    #[test]
    fn message_origin_display() {
        assert_eq!(alloc::format!("{}", MessageOrigin::User), "You");
        assert_eq!(alloc::format!("{}", MessageOrigin::Nous), "Nous");
    }

    #[test]
    fn proposal_state_display() {
        assert_eq!(alloc::format!("{}", ProposalState::Pending), "pending");
        assert_eq!(alloc::format!("{}", ProposalState::Confirmed), "confirmed");
        assert_eq!(alloc::format!("{}", ProposalState::Cancelled), "cancelled");
    }

    #[test]
    fn truncate_str_short() {
        let result = truncate_str("Hello", 10);
        assert_eq!(result, "Hello");
    }

    #[test]
    fn truncate_str_exact() {
        let result = truncate_str("Hello", 5);
        assert_eq!(result, "Hello");
    }

    #[test]
    fn truncate_str_long() {
        let result = truncate_str("Hello World", 6);
        assert!(result.len() <= 6);
        assert!(result.ends_with('~'));
    }

    #[test]
    fn to_uppercase_truncated_basic() {
        let result = to_uppercase_truncated("call maria", 20);
        assert_eq!(result, "CALL MARIA");
    }

    #[test]
    fn to_uppercase_truncated_limit() {
        let result = to_uppercase_truncated("call maria please", 10);
        assert_eq!(result.len(), 10);
        assert_eq!(result, "CALL MARIA");
    }

    #[test]
    fn format_title_output() {
        let title = format_title("Syn", "ADVISOR");
        assert_eq!(title, "NOUS: Syn [ADVISOR]");
    }

    #[test]
    fn format_msg_header_output() {
        let header = format_msg_header("Syn");
        assert_eq!(header, "Syn:");
    }
}
