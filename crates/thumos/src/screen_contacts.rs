//! Contact list screen for the thumos kernel UI.
//!
//! Implements the [`Screen`] trait to display and manage contacts:
//!
//! - **List view**: alphabetically sorted scrollable list of all contacts.
//!   Each entry shows the contact name. Selecting an entry opens the
//!   detail view.
//! - **Detail view**: shows name, phone number, and action options:
//!   Call, Message, Edit, Delete.
//! - **Add view**: two-field form for entering a new contact name and number.
//!
//! ## Navigation
//!
//! | View    | LSK    | RSK    | OK/Select          |
//! |---------|--------|--------|--------------------|
//! | List    | ADD    | BACK   | Open contact detail|
//! | Detail  | CALL   | BACK   | Select action      |
//! | Add     | SAVE   | BACK   | N/A                |

// WHY: contacts screen created in Phase 07 Wave 5, kinit wiring pending.
#![expect(
    dead_code,
    reason = "Contacts screen created in Phase 07 Wave 5, kinit wiring pending"
)]

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

use crate::contacts::ContactManager;
use crate::ui::{
    self, color, Key, Screen, ScreenAction, ScreenId,
    CHAR_HEIGHT, CHAR_WIDTH, CONTENT_HEIGHT, SCREEN_WIDTH,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Height of each contact list entry in pixels.
const ENTRY_HEIGHT: u16 = CHAR_HEIGHT + 8;

/// Number of visible entries on screen.
const VISIBLE_ENTRIES: u16 = (CONTENT_HEIGHT - TITLE_HEIGHT) / ENTRY_HEIGHT;

/// Height reserved for the title area.
const TITLE_HEIGHT: u16 = CHAR_HEIGHT + 8;

/// Y offset for the title.
const TITLE_Y: u16 = 4;

/// Y offset where list entries start.
const LIST_START_Y: u16 = TITLE_HEIGHT;

/// Maximum name length for add mode input.
const MAX_ADD_NAME_LEN: usize = 32;

/// Maximum number length for add mode input.
const MAX_ADD_NUMBER_LEN: usize = 20;

// ---------------------------------------------------------------------------
// Sub-views
// ---------------------------------------------------------------------------

/// Current view state of the contacts screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ContactView {
    /// Scrollable list of all contacts.
    List,
    /// Detail view for a selected contact.
    Detail,
    /// Add new contact form.
    Add,
}

/// Detail view action options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DetailOption {
    /// Initiate a voice call to this contact.
    Call,
    /// Open compose screen with this contact's number.
    Message,
    /// Edit the contact (future work).
    Edit,
    /// Delete the contact.
    Delete,
}

impl DetailOption {
    /// Display label.
    const fn label(self) -> &'static str {
        match self {
            Self::Call => "Call",
            Self::Message => "Message",
            Self::Edit => "Edit",
            Self::Delete => "Delete",
        }
    }

    /// Cycle to the next option (wrapping).
    const fn next(self) -> Self {
        match self {
            Self::Call => Self::Message,
            Self::Message => Self::Edit,
            Self::Edit => Self::Delete,
            Self::Delete => Self::Call,
        }
    }

    /// Cycle to the previous option (wrapping).
    const fn prev(self) -> Self {
        match self {
            Self::Call => Self::Delete,
            Self::Message => Self::Call,
            Self::Edit => Self::Message,
            Self::Delete => Self::Edit,
        }
    }
}

/// Which field is active in the add view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AddField {
    /// Name entry.
    Name,
    /// Number entry.
    Number,
}

// ---------------------------------------------------------------------------
// Contacts screen
// ---------------------------------------------------------------------------

/// Contacts screen implementation.
///
/// Holds a reference to the contact manager via a snapshot of sorted
/// indices and contact data. The caller must call [`update_contacts`]
/// before each render to refresh the display.
pub(crate) struct ContactsScreen {
    /// Sorted indices into the contact manager.
    sorted_indices: Vec<usize>,
    /// Contact names for display (parallel to sorted_indices).
    display_names: Vec<String>,
    /// Contact numbers for display (parallel to sorted_indices).
    display_numbers: Vec<String>,
    /// Currently selected index in the sorted list.
    selected: usize,
    /// Scroll offset for the list.
    scroll_offset: usize,
    /// Current view.
    view: ContactView,
    /// Selected option in detail view.
    detail_option: DetailOption,
    /// Add mode: name buffer.
    add_name: [u8; MAX_ADD_NAME_LEN],
    /// Add mode: name length.
    add_name_len: usize,
    /// Add mode: number buffer.
    add_number: [u8; MAX_ADD_NUMBER_LEN],
    /// Add mode: number length.
    add_number_len: usize,
    /// Add mode: active field.
    add_field: AddField,
}

impl ContactsScreen {
    /// Create a new contacts screen.
    pub(crate) fn new() -> Self {
        Self {
            sorted_indices: Vec::new(),
            display_names: Vec::new(),
            display_numbers: Vec::new(),
            selected: 0,
            scroll_offset: 0,
            view: ContactView::List,
            detail_option: DetailOption::Call,
            add_name: [0u8; MAX_ADD_NAME_LEN],
            add_name_len: 0,
            add_number: [0u8; MAX_ADD_NUMBER_LEN],
            add_number_len: 0,
            add_field: AddField::Name,
        }
    }

    /// Update the displayed contacts from the contact manager.
    ///
    /// Must be called before each render to reflect add/delete changes.
    pub(crate) fn update_contacts(&mut self, manager: &ContactManager) {
        self.sorted_indices = manager.sorted_indices();
        self.display_names.clear();
        self.display_numbers.clear();

        for &idx in &self.sorted_indices {
            if let Some(contact) = manager.get(idx) {
                self.display_names.push(String::from(contact.name_str()));
                self.display_numbers.push(String::from(contact.number_str()));
            }
        }

        // Clamp selection.
        if self.selected >= self.sorted_indices.len() && !self.sorted_indices.is_empty() {
            self.selected = self.sorted_indices.len() - 1;
        }
    }

    /// Return the number of contacts displayed.
    pub(crate) fn contact_count(&self) -> usize {
        self.sorted_indices.len()
    }

    /// Return the currently selected list index.
    pub(crate) fn selected_index(&self) -> usize {
        self.selected
    }

    /// Return the original contact manager index for the selected entry.
    pub(crate) fn selected_manager_index(&self) -> Option<usize> {
        self.sorted_indices.get(self.selected).copied()
    }

    // --- Navigation helpers ---

    fn move_up(&mut self) {
        if self.selected > 0 {
            self.selected -= 1;
            if self.selected < self.scroll_offset {
                self.scroll_offset = self.selected;
            }
        }
    }

    fn move_down(&mut self) {
        if !self.sorted_indices.is_empty() && self.selected < self.sorted_indices.len() - 1 {
            self.selected += 1;
            let visible = VISIBLE_ENTRIES as usize;
            if self.selected >= self.scroll_offset + visible {
                self.scroll_offset = self.selected - visible + 1;
            }
        }
    }

    // --- Add mode helpers ---

    fn reset_add(&mut self) {
        self.add_name = [0u8; MAX_ADD_NAME_LEN];
        self.add_name_len = 0;
        self.add_number = [0u8; MAX_ADD_NUMBER_LEN];
        self.add_number_len = 0;
        self.add_field = AddField::Name;
    }

    fn add_name_str(&self) -> &str {
        core::str::from_utf8(&self.add_name[..self.add_name_len]).unwrap_or("")
    }

    fn add_number_str(&self) -> &str {
        core::str::from_utf8(&self.add_number[..self.add_number_len]).unwrap_or("")
    }

    fn add_push_char(&mut self, ch: char) {
        match self.add_field {
            AddField::Name => {
                if self.add_name_len < MAX_ADD_NAME_LEN {
                    self.add_name[self.add_name_len] = ch as u8;
                    self.add_name_len += 1;
                }
            }
            AddField::Number => {
                if self.add_number_len < MAX_ADD_NUMBER_LEN {
                    self.add_number[self.add_number_len] = ch as u8;
                    self.add_number_len += 1;
                }
            }
        }
    }

    fn add_backspace(&mut self) {
        match self.add_field {
            AddField::Name => {
                if self.add_name_len > 0 {
                    self.add_name_len -= 1;
                }
            }
            AddField::Number => {
                if self.add_number_len > 0 {
                    self.add_number_len -= 1;
                }
            }
        }
    }
}

impl Screen for ContactsScreen {
    fn draw(&self, fb: &mut [u16]) {
        let w = SCREEN_WIDTH;
        let h = CONTENT_HEIGHT;

        // Clear.
        ui::fill_rect(fb, w, h, 0, 0, w, h, color::BLACK);

        match self.view {
            ContactView::List => self.draw_list(fb),
            ContactView::Detail => self.draw_detail(fb),
            ContactView::Add => self.draw_add(fb),
        }
    }

    fn on_key(&mut self, key: Key) -> ScreenAction {
        match self.view {
            ContactView::List => self.on_key_list(key),
            ContactView::Detail => self.on_key_detail(key),
            ContactView::Add => self.on_key_add(key),
        }
    }

    fn softkey_left(&self) -> &'static str {
        match self.view {
            ContactView::List => "ADD",
            ContactView::Detail => "CALL",
            ContactView::Add => "SAVE",
        }
    }

    fn softkey_right(&self) -> &'static str {
        "BACK"
    }

    fn title(&self) -> &'static str {
        match self.view {
            ContactView::List => "Contacts",
            ContactView::Detail => "Contact",
            ContactView::Add => "New Contact",
        }
    }
}

impl ContactsScreen {
    // --- List drawing ---

    fn draw_list(&self, fb: &mut [u16]) {
        let w = SCREEN_WIDTH;

        // Title.
        ui::draw_str_centered(fb, w, 0, w, TITLE_Y, "CONTACTS", color::WHITE, color::BLACK);

        if self.sorted_indices.is_empty() {
            ui::draw_str_centered(
                fb, w, 0, w, CONTENT_HEIGHT / 2 - CHAR_HEIGHT / 2,
                "No contacts", color::DARK_GREY, color::BLACK,
            );
            return;
        }

        let visible = VISIBLE_ENTRIES as usize;
        let start = self.scroll_offset;
        let end = (start + visible).min(self.sorted_indices.len());

        for (slot, list_idx) in (start..end).enumerate() {
            let y = LIST_START_Y + slot as u16 * ENTRY_HEIGHT;
            let is_selected = list_idx == self.selected;

            // Highlight selected entry.
            if is_selected {
                ui::fill_rect(
                    fb, w, CONTENT_HEIGHT,
                    0, y, w, ENTRY_HEIGHT,
                    color::from_rgb(20, 20, 50),
                );
            }

            // Contact name.
            if let Some(name) = self.display_names.get(list_idx) {
                let display = truncate_display_str(name, 28);
                ui::draw_str(
                    fb, w, 4, y + 4,
                    display, color::WHITE, color::BLACK,
                );
            }
        }
    }

    // --- Detail drawing ---

    fn draw_detail(&self, fb: &mut [u16]) {
        let w = SCREEN_WIDTH;

        let name = self.display_names.get(self.selected).map_or("", String::as_str);
        let number = self.display_numbers.get(self.selected).map_or("", String::as_str);

        // Name (large, centered).
        ui::draw_str_centered(fb, w, 0, w, TITLE_Y + 8, name, color::WHITE, color::BLACK);

        // Number.
        let num_y = TITLE_Y + CHAR_HEIGHT * 2 + 12;
        ui::draw_str_centered(fb, w, 0, w, num_y, number, color::DARK_GREY, color::BLACK);

        // Action options.
        let options = [
            DetailOption::Call,
            DetailOption::Message,
            DetailOption::Edit,
            DetailOption::Delete,
        ];
        let options_y = num_y + CHAR_HEIGHT + 20;

        for (i, option) in options.iter().enumerate() {
            let y = options_y + i as u16 * (CHAR_HEIGHT + 8);
            let is_selected = *option == self.detail_option;
            let text_color = if is_selected { color::YELLOW } else { color::WHITE };

            if is_selected {
                ui::fill_rect(
                    fb, w, CONTENT_HEIGHT,
                    0, y, w, CHAR_HEIGHT + 4,
                    color::from_rgb(20, 20, 50),
                );
            }

            let label = option.label();
            ui::draw_str_centered(fb, w, 0, w, y + 2, label, text_color, color::BLACK);
        }
    }

    // --- Add drawing ---

    fn draw_add(&self, fb: &mut [u16]) {
        let w = SCREEN_WIDTH;

        // Name field.
        let name_label_color = if self.add_field == AddField::Name {
            color::YELLOW
        } else {
            color::DARK_GREY
        };
        ui::draw_str(fb, w, 4, TITLE_Y + 8, "Name:", name_label_color, color::BLACK);
        let name_str = self.add_name_str();
        let name_display = if name_str.is_empty() { "Enter name" } else { name_str };
        let name_color = if name_str.is_empty() {
            color::DARK_GREY
        } else {
            color::WHITE
        };
        ui::draw_str(
            fb, w, 4 + 6 * CHAR_WIDTH, TITLE_Y + 8,
            name_display, name_color, color::BLACK,
        );

        // Separator.
        let sep_y = TITLE_Y + 8 + CHAR_HEIGHT + 4;
        ui::fill_rect(fb, w, CONTENT_HEIGHT, 0, sep_y, w, 1, color::DARK_GREY);

        // Number field.
        let num_label_color = if self.add_field == AddField::Number {
            color::YELLOW
        } else {
            color::DARK_GREY
        };
        let num_y = sep_y + 4;
        ui::draw_str(fb, w, 4, num_y, "Num:", num_label_color, color::BLACK);
        let num_str = self.add_number_str();
        let num_display = if num_str.is_empty() { "Enter number" } else { num_str };
        let num_color = if num_str.is_empty() {
            color::DARK_GREY
        } else {
            color::WHITE
        };
        ui::draw_str(
            fb, w, 4 + 5 * CHAR_WIDTH, num_y,
            num_display, num_color, color::BLACK,
        );
    }

    // --- List input ---

    fn on_key_list(&mut self, key: Key) -> ScreenAction {
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
                if !self.sorted_indices.is_empty() {
                    self.view = ContactView::Detail;
                    self.detail_option = DetailOption::Call;
                }
                ScreenAction::None
            }
            Key::Lsk => {
                self.reset_add();
                self.view = ContactView::Add;
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
                self.detail_option = self.detail_option.prev();
                ScreenAction::None
            }
            Key::Down => {
                self.detail_option = self.detail_option.next();
                ScreenAction::None
            }
            Key::Ok => {
                match self.detail_option {
                    DetailOption::Call => ScreenAction::Navigate(ScreenId::InCall),
                    DetailOption::Message => ScreenAction::Navigate(ScreenId::Messages),
                    DetailOption::Edit | DetailOption::Delete => {
                        // Edit/Delete require contact manager access;
                        // return to list for now. The caller handles
                        // the actual mutation.
                        self.view = ContactView::List;
                        ScreenAction::None
                    }
                }
            }
            Key::Lsk => {
                // CALL shortcut.
                ScreenAction::Navigate(ScreenId::InCall)
            }
            Key::Rsk | Key::End => {
                self.view = ContactView::List;
                ScreenAction::None
            }
            _ => ScreenAction::None,
        }
    }

    // --- Add input ---

    fn on_key_add(&mut self, key: Key) -> ScreenAction {
        match key {
            Key::Up | Key::Down => {
                self.add_field = match self.add_field {
                    AddField::Name => AddField::Number,
                    AddField::Number => AddField::Name,
                };
                ScreenAction::None
            }
            Key::Lsk => {
                // SAVE — the caller reads add_name/add_number and calls
                // ContactManager::add(). We return to list view.
                self.view = ContactView::List;
                ScreenAction::None
            }
            Key::Rsk | Key::End => {
                self.view = ContactView::List;
                self.reset_add();
                ScreenAction::None
            }
            Key::Left => {
                self.add_backspace();
                ScreenAction::None
            }
            key => {
                if let Some(ch) = key_to_digit_char(key) {
                    self.add_push_char(ch);
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

/// Truncate a display string to a maximum character count.
///
/// Returns the input string if it fits; otherwise returns a prefix
/// up to a valid char boundary.
fn truncate_display_str(s: &str, max_len: usize) -> &str {
    if s.len() <= max_len {
        return s;
    }
    let mut end = max_len;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::CONTENT_PIXELS;

    fn make_manager() -> ContactManager {
        let mut mgr = ContactManager::new();
        mgr.add("Charlie", "+15553333333")
            .unwrap_or_else(|_| unreachable!());
        mgr.add("Alice", "+15551111111")
            .unwrap_or_else(|_| unreachable!());
        mgr.add("Bob", "+15552222222")
            .unwrap_or_else(|_| unreachable!());
        mgr
    }

    #[test]
    fn list_renders_contacts() {
        let mgr = make_manager();
        let mut screen = ContactsScreen::new();
        screen.update_contacts(&mgr);

        let mut fb = [0u16; CONTENT_PIXELS];
        screen.draw(&mut fb);

        let any_set = fb.iter().any(|&px| px != 0);
        assert!(
            any_set,
            "contact list must render visible pixels"
        );
    }

    #[test]
    fn softkeys_correct() {
        let screen = ContactsScreen::new();
        assert_eq!(
            screen.softkey_left(),
            "ADD",
            "list LSK must be 'ADD'"
        );
        assert_eq!(
            screen.softkey_right(),
            "BACK",
            "list RSK must be 'BACK'"
        );
    }

    #[test]
    fn contacts_sorted_alphabetically() {
        let mgr = make_manager();
        let mut screen = ContactsScreen::new();
        screen.update_contacts(&mgr);

        // Sorted order should be Alice, Bob, Charlie.
        assert_eq!(screen.display_names.len(), 3);
        assert_eq!(screen.display_names[0], "Alice");
        assert_eq!(screen.display_names[1], "Bob");
        assert_eq!(screen.display_names[2], "Charlie");
    }

    #[test]
    fn navigate_up_down() {
        let mgr = make_manager();
        let mut screen = ContactsScreen::new();
        screen.update_contacts(&mgr);

        assert_eq!(screen.selected_index(), 0);

        screen.on_key(Key::Down);
        assert_eq!(screen.selected_index(), 1);

        screen.on_key(Key::Up);
        assert_eq!(screen.selected_index(), 0);

        // Up at top stays at top.
        screen.on_key(Key::Up);
        assert_eq!(screen.selected_index(), 0);
    }

    #[test]
    fn ok_opens_detail() {
        let mgr = make_manager();
        let mut screen = ContactsScreen::new();
        screen.update_contacts(&mgr);

        screen.on_key(Key::Ok);
        assert_eq!(screen.view, ContactView::Detail);
    }

    #[test]
    fn detail_call_navigates_to_in_call() {
        let mgr = make_manager();
        let mut screen = ContactsScreen::new();
        screen.update_contacts(&mgr);
        screen.view = ContactView::Detail;
        screen.detail_option = DetailOption::Call;

        let action = screen.on_key(Key::Ok);
        assert_eq!(
            action,
            ScreenAction::Navigate(ScreenId::InCall),
            "selecting Call must navigate to InCall"
        );
    }

    #[test]
    fn detail_message_navigates_to_messages() {
        let mgr = make_manager();
        let mut screen = ContactsScreen::new();
        screen.update_contacts(&mgr);
        screen.view = ContactView::Detail;
        screen.detail_option = DetailOption::Message;

        let action = screen.on_key(Key::Ok);
        assert_eq!(
            action,
            ScreenAction::Navigate(ScreenId::Messages),
            "selecting Message must navigate to Messages"
        );
    }

    #[test]
    fn lsk_opens_add_view() {
        let mut screen = ContactsScreen::new();
        screen.on_key(Key::Lsk);
        assert_eq!(screen.view, ContactView::Add);
    }

    #[test]
    fn rsk_in_list_goes_back() {
        let mut screen = ContactsScreen::new();
        let action = screen.on_key(Key::Rsk);
        assert_eq!(action, ScreenAction::Back);
    }

    #[test]
    fn empty_contacts_renders() {
        let screen = ContactsScreen::new();
        let mut fb = [0u16; CONTENT_PIXELS];
        screen.draw(&mut fb);
        let any_set = fb.iter().any(|&px| px != 0);
        assert!(any_set, "empty contact list must render 'No contacts'");
    }

    #[test]
    fn add_view_digit_entry() {
        let mut screen = ContactsScreen::new();
        screen.view = ContactView::Add;
        screen.add_field = AddField::Number;

        screen.on_key(Key::Num1);
        screen.on_key(Key::Num2);
        screen.on_key(Key::Num3);

        assert_eq!(screen.add_number_str(), "123");
    }

    #[test]
    fn detail_option_cycles() {
        assert_eq!(DetailOption::Call.next(), DetailOption::Message);
        assert_eq!(DetailOption::Message.next(), DetailOption::Edit);
        assert_eq!(DetailOption::Edit.next(), DetailOption::Delete);
        assert_eq!(DetailOption::Delete.next(), DetailOption::Call);

        assert_eq!(DetailOption::Call.prev(), DetailOption::Delete);
        assert_eq!(DetailOption::Message.prev(), DetailOption::Call);
    }

    #[test]
    fn detail_renders_without_panic() {
        let mgr = make_manager();
        let mut screen = ContactsScreen::new();
        screen.update_contacts(&mgr);
        screen.view = ContactView::Detail;

        let mut fb = [0u16; CONTENT_PIXELS];
        screen.draw(&mut fb);
        let any_set = fb.iter().any(|&px| px != 0);
        assert!(any_set, "detail view must render content");
    }

    #[test]
    fn add_view_renders_without_panic() {
        let mut screen = ContactsScreen::new();
        screen.view = ContactView::Add;
        let mut fb = [0u16; CONTENT_PIXELS];
        screen.draw(&mut fb);
        let any_set = fb.iter().any(|&px| px != 0);
        assert!(any_set, "add contact view must render visible content");
    }
}
