//! In-memory contact storage.
//!
//! Provides a simple flat-file contact list held in memory. No filesystem
//! persistence in this wave -- that is future work. Contacts are used by
//! the dialer (caller ID lookup) and the messaging screen (recipient
//! selection).
//!
//! ## Storage format
//!
//! Each [`Contact`] uses fixed-size byte arrays for name and number to avoid
//! heap fragmentation from many small allocations. Names and numbers are
//! stored as UTF-8 bytes with a length field.
//!
//! ## Search
//!
//! Prefix search is case-insensitive and returns indices into the contact
//! list. This supports T9 contact lookup in the dialer screen.

// WHY: contacts module created in Phase 07 Wave 5, kinit wiring pending.
#![expect(
    dead_code,
    reason = "Contacts module exists; kinit wiring pending (tier in docs/capability-inventory.toml)"
)]

extern crate alloc;
use alloc::vec::Vec;

use crate::screen_messages::MessageTransport;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum name length in bytes.
const MAX_NAME_LEN: usize = 64;

/// Maximum phone number length in bytes.
const MAX_NUMBER_LEN: usize = 32;

/// Maximum Matrix user ID length in bytes (e.g., `@user:server.example`).
const MAX_MATRIX_ID_LEN: usize = 64;

// ---------------------------------------------------------------------------
// Contact
// ---------------------------------------------------------------------------

/// Errors from contact construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub(crate) enum ContactError {
    /// Phone number contains a byte outside the GSM dial-string charset.
    InvalidNumber,
}

impl core::fmt::Display for ContactError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidNumber => write!(f, "invalid phone number"),
        }
    }
}

/// A single contact entry.
///
/// Uses fixed-size byte arrays to avoid heap allocation per contact.
/// The name and number fields are UTF-8 encoded with a separate length
/// byte.
#[derive(Clone)]
pub struct Contact {
    /// Contact name as UTF-8 bytes.
    pub name: [u8; MAX_NAME_LEN],
    /// Number of valid bytes in `name`.
    pub name_len: u8,
    /// Phone number as ASCII bytes.
    pub number: [u8; MAX_NUMBER_LEN],
    /// Number of valid bytes in `number`.
    pub number_len: u8,
    /// Matrix user ID as UTF-8 bytes (e.g., `@user:server.example`).
    pub matrix_id: [u8; MAX_MATRIX_ID_LEN],
    /// Number of valid bytes in `matrix_id`.
    pub matrix_id_len: u8,
    /// Preferred transport for this contact.
    ///
    /// When composing a message to this contact, the compose view starts
    /// with this transport selected. Defaults to [`MessageTransport::Sms`]
    /// unless the contact has a Matrix ID set.
    pub default_transport: MessageTransport,
}

impl Contact {
    /// Create a new contact from name and number strings.
    ///
    /// Truncates `name` if it exceeds the maximum length. The Matrix ID
    /// is left empty and default transport is SMS.
    ///
    /// # Errors
    ///
    /// Returns [`ContactError::InvalidNumber`] if `number` contains any
    /// byte outside the GSM dial-string charset (an empty `number` is
    /// valid -- Matrix-only contacts have no phone number). A rejected
    /// number is never truncated-and-stored: reject, don't sanitize.
    pub(crate) fn new(name: &str, number: &str) -> Result<Self, ContactError> {
        if !number
            .bytes()
            .all(crate::telephony_parser::is_valid_dial_byte)
        {
            return Err(ContactError::InvalidNumber);
        }

        let mut c = Self {
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            number: [0u8; MAX_NUMBER_LEN],
            number_len: 0,
            matrix_id: [0u8; MAX_MATRIX_ID_LEN],
            matrix_id_len: 0,
            default_transport: MessageTransport::Sms,
        };
        let name_bytes = name.as_bytes();
        // WHY: byte-length truncation can split a multi-byte UTF-8 char,
        // producing invalid UTF-8 that name_str() then silently maps to ""
        // for the ENTIRE name. utf8_truncate_len backs off to the last full
        // codepoint boundary -- the same fix already applied to calendar
        // event titles and alarm labels for the identical class of bug (#359).
        let name_copy_len = crate::heorte::utf8_truncate_len(name_bytes, MAX_NAME_LEN);
        c.name[..name_copy_len].copy_from_slice(&name_bytes[..name_copy_len]);
        c.name_len = name_copy_len as u8;

        let number_bytes = number.as_bytes();
        let number_copy_len = number_bytes.len().min(MAX_NUMBER_LEN);
        c.number[..number_copy_len].copy_from_slice(&number_bytes[..number_copy_len]);
        c.number_len = number_copy_len as u8;
        Ok(c)
    }

    /// Create a new contact with a Matrix ID and optional phone number.
    ///
    /// Sets the default transport to Matrix when a Matrix ID is provided.
    ///
    /// # Errors
    ///
    /// Returns [`ContactError::InvalidNumber`] under the same condition as
    /// [`Contact::new`].
    pub(crate) fn with_matrix_id(
        name: &str,
        number: &str,
        matrix_id: &str,
    ) -> Result<Self, ContactError> {
        let mut c = Self::new(name, number)?;
        let mid_bytes = matrix_id.as_bytes();
        let mid_copy_len = mid_bytes.len().min(MAX_MATRIX_ID_LEN);
        c.matrix_id[..mid_copy_len].copy_from_slice(&mid_bytes[..mid_copy_len]);
        c.matrix_id_len = mid_copy_len as u8;
        if mid_copy_len > 0 {
            c.default_transport = MessageTransport::Matrix;
        }
        Ok(c)
    }

    /// Return the name as a string slice.
    #[must_use]
    pub(crate) fn name_str(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len as usize]).unwrap_or("")
    }

    /// Return the number as a string slice.
    #[must_use]
    pub(crate) fn number_str(&self) -> &str {
        core::str::from_utf8(&self.number[..self.number_len as usize]).unwrap_or("")
    }

    /// Return the Matrix user ID as a string slice, or empty if not set.
    #[must_use]
    pub(crate) fn matrix_id_str(&self) -> &str {
        core::str::from_utf8(&self.matrix_id[..self.matrix_id_len as usize]).unwrap_or("")
    }

    /// Return whether this contact has a Matrix ID.
    #[must_use]
    pub(crate) fn has_matrix_id(&self) -> bool {
        self.matrix_id_len > 0
    }
}

impl core::fmt::Display for Contact {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.has_matrix_id() {
            write!(
                f,
                "{} ({}, {})",
                self.name_str(),
                self.number_str(),
                self.matrix_id_str(),
            )
        } else {
            write!(f, "{} ({})", self.name_str(), self.number_str())
        }
    }
}

// WHY: name/number/matrix_id/*_len are the fixed-size byte-array + length
// halves of what name_str()/number_str()/matrix_id_str() already decode --
// dumping the raw arrays alongside the decoded strings would duplicate
// the same content in a less readable form, not add information.
#[expect(
    clippy::missing_fields_in_debug,
    reason = "raw name/number/matrix_id arrays are redundant with the already-decoded name_str()/number_str()/matrix_id_str() fields shown; dumping both would duplicate content, not add it"
)]
impl core::fmt::Debug for Contact {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut s = f.debug_struct("Contact");
        s.field("name", &self.name_str())
            .field("number", &self.number_str());
        if self.has_matrix_id() {
            s.field("matrix_id", &self.matrix_id_str());
        }
        s.field("default_transport", &self.default_transport)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Contact manager
// ---------------------------------------------------------------------------

/// In-memory contact list manager.
///
/// Stores contacts in a `Vec` and provides add/delete/search operations.
/// No persistence -- contacts are lost on reboot until filesystem
/// integration is added.
pub(crate) struct ContactManager {
    /// All stored contacts.
    contacts: Vec<Contact>,
}

impl ContactManager {
    /// Create a new empty contact manager.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            contacts: Vec::new(),
        }
    }

    /// Add a contact with the given name and number.
    ///
    /// The contact is appended to the end of the list.
    ///
    /// # Errors
    ///
    /// Returns [`ContactError::InvalidNumber`] and adds nothing if `number`
    /// fails dial-string validation (see [`Contact::new`]).
    pub(crate) fn add(&mut self, name: &str, number: &str) -> Result<(), ContactError> {
        self.contacts.push(Contact::new(name, number)?);
        Ok(())
    }

    /// Delete a contact by index.
    ///
    /// Out-of-bounds indices are silently ignored.
    pub(crate) fn delete(&mut self, index: usize) {
        if index < self.contacts.len() {
            self.contacts.remove(index);
        }
    }

    /// Search contacts by name prefix (case-insensitive).
    ///
    /// Returns indices of all contacts whose name starts with the given
    /// prefix. An empty prefix returns all contact indices.
    pub(crate) fn search(&self, prefix: &str) -> Vec<usize> {
        if prefix.is_empty() {
            return (0..self.contacts.len()).collect();
        }

        let prefix_lower: Vec<u8> = prefix.bytes().map(|b| b.to_ascii_lowercase()).collect();

        self.contacts
            .iter()
            .enumerate()
            .filter(|(_, contact)| {
                let name = &contact.name[..contact.name_len as usize];
                if name.len() < prefix_lower.len() {
                    return false;
                }
                name[..prefix_lower.len()]
                    .iter()
                    .zip(prefix_lower.iter())
                    .all(|(a, b)| a.to_ascii_lowercase() == *b)
            })
            .map(|(i, _)| i)
            .collect()
    }

    /// Get a contact by index.
    pub(crate) fn get(&self, index: usize) -> Option<&Contact> {
        self.contacts.get(index)
    }

    /// Return a slice of all contacts.
    pub(crate) fn all(&self) -> &[Contact] {
        &self.contacts
    }

    /// Return the number of stored contacts.
    pub(crate) fn count(&self) -> usize {
        self.contacts.len()
    }

    /// Return contacts sorted alphabetically by name (case-insensitive).
    ///
    /// Returns a vector of indices into the contact list, sorted by name.
    pub(crate) fn sorted_indices(&self) -> Vec<usize> {
        // WHY precompute keys once: the previous implementation called
        // to_ascii_lowercase() (a heap allocation) inside the sort
        // comparator, which runs O(N log N) times for N contacts -- O(N
        // log N) heap Strings for a single sort. Lowercasing each name
        // exactly once up front (O(N) allocations) and sorting the
        // precomputed keys avoids the per-compare allocation entirely.
        let keys: Vec<alloc::string::String> = self
            .contacts
            .iter()
            .map(|c| c.name_str().to_ascii_lowercase())
            .collect();
        let mut indices: Vec<usize> = (0..self.contacts.len()).collect();
        indices.sort_by(|&a, &b| keys[a].cmp(&keys[b]));
        indices
    }

    /// Look up a contact by phone number.
    ///
    /// Returns the index of the first contact with a matching number,
    /// or `None` if no match is found.
    pub(crate) fn find_by_number(&self, number: &str) -> Option<usize> {
        self.contacts.iter().position(|c| c.number_str() == number)
    }

    /// Look up a contact by Matrix user ID.
    ///
    /// Returns the index of the first contact with a matching Matrix ID,
    /// or `None` if no match is found.
    pub(crate) fn find_by_matrix_id(&self, matrix_id: &str) -> Option<usize> {
        self.contacts
            .iter()
            .position(|c| c.has_matrix_id() && c.matrix_id_str() == matrix_id)
    }

    /// Add a contact with name, phone number, and Matrix ID.
    ///
    /// The contact is appended to the end of the list.
    ///
    /// # Errors
    ///
    /// Returns [`ContactError::InvalidNumber`] and adds nothing if `number`
    /// fails dial-string validation (see [`Contact::new`]).
    pub(crate) fn add_with_matrix_id(
        &mut self,
        name: &str,
        number: &str,
        matrix_id: &str,
    ) -> Result<(), ContactError> {
        self.contacts
            .push(Contact::with_matrix_id(name, number, matrix_id)?);
        Ok(())
    }
}

// We need the to_ascii_lowercase method on str for sorted_indices.
// In no_std with alloc, we provide a simple helper via byte-level conversion.
trait AsciiLowercase {
    fn to_ascii_lowercase(&self) -> alloc::string::String;
}

impl AsciiLowercase for str {
    fn to_ascii_lowercase(&self) -> alloc::string::String {
        let mut s = alloc::string::String::with_capacity(self.len());
        for b in self.bytes() {
            s.push(b.to_ascii_lowercase() as char);
        }
        s
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    #[test]
    fn add_and_retrieve() {
        let mut mgr = ContactManager::new();
        mgr.add("Alice", "+15551234567")
            .unwrap_or_else(|_| unreachable!());
        mgr.add("Bob", "+15559876543")
            .unwrap_or_else(|_| unreachable!());

        assert_eq!(mgr.count(), 2);

        let alice = mgr.get(0);
        assert!(alice.is_some());
        let alice = alice.unwrap();
        assert_eq!(alice.name_str(), "Alice");
        assert_eq!(alice.number_str(), "+15551234567");

        let bob = mgr.get(1);
        assert!(bob.is_some());
        let bob = bob.unwrap();
        assert_eq!(bob.name_str(), "Bob");
        assert_eq!(bob.number_str(), "+15559876543");
    }

    #[test]
    fn search_by_prefix() {
        let mut mgr = ContactManager::new();
        mgr.add("Alice", "111").unwrap_or_else(|_| unreachable!());
        mgr.add("Aaron", "222").unwrap_or_else(|_| unreachable!());
        mgr.add("Bob", "333").unwrap_or_else(|_| unreachable!());
        mgr.add("charlie", "444").unwrap_or_else(|_| unreachable!());

        // Search "A" should find Alice and Aaron.
        let results = mgr.search("A");
        assert_eq!(results.len(), 2, "prefix 'A' must match Alice and Aaron");
        assert!(results.contains(&0));
        assert!(results.contains(&1));

        // Case-insensitive: "a" should also match.
        let results = mgr.search("a");
        assert_eq!(results.len(), 2, "prefix 'a' must match case-insensitively");

        // Search "Bo" should find only Bob.
        let results = mgr.search("Bo");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], 2);

        // Search "Ch" should find charlie (case-insensitive).
        let results = mgr.search("Ch");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], 3);

        // Search "Z" should find nothing.
        let results = mgr.search("Z");
        assert!(results.is_empty());
    }

    #[test]
    fn delete_removes_entry() {
        let mut mgr = ContactManager::new();
        mgr.add("Alice", "111").unwrap_or_else(|_| unreachable!());
        mgr.add("Bob", "222").unwrap_or_else(|_| unreachable!());
        mgr.add("Charlie", "333").unwrap_or_else(|_| unreachable!());

        mgr.delete(1); // Remove Bob.

        assert_eq!(mgr.count(), 2);
        assert_eq!(mgr.get(0).map(super::Contact::name_str), Some("Alice"));
        assert_eq!(mgr.get(1).map(super::Contact::name_str), Some("Charlie"));
    }

    #[test]
    fn search_empty_returns_all() {
        let mut mgr = ContactManager::new();
        mgr.add("Alice", "111").unwrap_or_else(|_| unreachable!());
        mgr.add("Bob", "222").unwrap_or_else(|_| unreachable!());

        let results = mgr.search("");
        assert_eq!(results.len(), 2, "empty prefix must return all contacts");
    }

    #[test]
    fn delete_out_of_bounds_is_safe() {
        let mut mgr = ContactManager::new();
        mgr.add("Alice", "111").unwrap_or_else(|_| unreachable!());
        mgr.delete(5); // Out of bounds.
        assert_eq!(mgr.count(), 1, "out-of-bounds delete must not crash");
    }

    #[test]
    fn get_out_of_bounds_returns_none() {
        let mgr = ContactManager::new();
        assert!(mgr.get(0).is_none());
        assert!(mgr.get(100).is_none());
    }

    #[test]
    fn sorted_indices_alphabetical() {
        let mut mgr = ContactManager::new();
        mgr.add("Charlie", "333").unwrap_or_else(|_| unreachable!());
        mgr.add("Alice", "111").unwrap_or_else(|_| unreachable!());
        mgr.add("Bob", "222").unwrap_or_else(|_| unreachable!());

        let sorted = mgr.sorted_indices();
        assert_eq!(sorted, vec![1, 2, 0], "must be sorted: Alice, Bob, Charlie");
    }

    #[test]
    fn sorted_indices_case_insensitive_with_many_contacts() {
        let mut mgr = ContactManager::new();
        mgr.add("charlie", "1").unwrap_or_else(|_| unreachable!());
        mgr.add("Alice", "2").unwrap_or_else(|_| unreachable!());
        mgr.add("BOB", "3").unwrap_or_else(|_| unreachable!());
        mgr.add("dave", "4").unwrap_or_else(|_| unreachable!());
        mgr.add("aaron", "5").unwrap_or_else(|_| unreachable!());

        let sorted = mgr.sorted_indices();
        let names: Vec<&str> = sorted
            .iter()
            .map(|&i| mgr.get(i).map_or("", super::Contact::name_str))
            .collect();
        assert_eq!(
            names,
            vec!["aaron", "Alice", "BOB", "charlie", "dave"],
            "precomputed-key sort must still be case-insensitive across many contacts"
        );
    }

    #[test]
    fn find_by_number_works() {
        let mut mgr = ContactManager::new();
        mgr.add("Alice", "+15551234567")
            .unwrap_or_else(|_| unreachable!());
        mgr.add("Bob", "+15559876543")
            .unwrap_or_else(|_| unreachable!());

        assert_eq!(mgr.find_by_number("+15551234567"), Some(0));
        assert_eq!(mgr.find_by_number("+15559876543"), Some(1));
        assert_eq!(mgr.find_by_number("+10000000000"), None);
    }

    #[test]
    fn contact_new_truncates_long_name() {
        let long_name = "A".repeat(100);
        let contact = Contact::new(&long_name, "123").unwrap_or_else(|_| unreachable!());
        assert_eq!(
            contact.name_len as usize, MAX_NAME_LEN,
            "name must be truncated to MAX_NAME_LEN"
        );
    }

    #[test]
    fn contact_new_truncates_on_char_boundary() {
        let mut name = "A".repeat(63);
        name.push('\u{e9}'); // 2-byte UTF-8 char straddles the 64-byte truncation point
        let contact = Contact::new(&name, "123").unwrap_or_else(|_| unreachable!());
        assert!(
            core::str::from_utf8(&contact.name[..contact.name_len as usize]).is_ok(),
            "truncated name bytes must remain valid UTF-8"
        );
        assert_eq!(
            contact.name_str(),
            "A".repeat(63),
            "truncation must back off to the char boundary, not split the multi-byte char"
        );
    }

    #[test]
    fn all_returns_slice() {
        let mut mgr = ContactManager::new();
        mgr.add("Alice", "111").unwrap_or_else(|_| unreachable!());
        mgr.add("Bob", "222").unwrap_or_else(|_| unreachable!());

        let all = mgr.all();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].name_str(), "Alice");
        assert_eq!(all[1].name_str(), "Bob");
    }

    // --- Wave 5: Matrix ID and transport tests ---

    #[test]
    fn contact_with_matrix_id() {
        let c = Contact::with_matrix_id("Alice", "+15551234567", "@alice:matrix.org")
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(c.name_str(), "Alice");
        assert_eq!(c.number_str(), "+15551234567");
        assert_eq!(c.matrix_id_str(), "@alice:matrix.org");
        assert!(c.has_matrix_id());
        assert_eq!(
            c.default_transport,
            MessageTransport::Matrix,
            "contact with matrix_id must default to Matrix transport"
        );
    }

    #[test]
    fn contact_without_matrix_id_defaults_sms() {
        let c = Contact::new("Bob", "+15559876543").unwrap_or_else(|_| unreachable!());
        assert_eq!(c.matrix_id_str(), "");
        assert!(!c.has_matrix_id());
        assert_eq!(
            c.default_transport,
            MessageTransport::Sms,
            "contact without matrix_id must default to Sms transport"
        );
    }

    #[test]
    fn contact_with_empty_matrix_id_stays_sms() {
        let c =
            Contact::with_matrix_id("Carol", "+15550001111", "").unwrap_or_else(|_| unreachable!());
        assert!(!c.has_matrix_id());
        assert_eq!(c.default_transport, MessageTransport::Sms);
    }

    #[test]
    fn find_by_matrix_id_works() {
        let mut mgr = ContactManager::new();
        mgr.add("Alice", "+15551234567")
            .unwrap_or_else(|_| unreachable!());
        mgr.add_with_matrix_id("Bob", "+15559876543", "@bob:matrix.org")
            .unwrap_or_else(|_| unreachable!());
        mgr.add_with_matrix_id("Carol", "", "@carol:example.com")
            .unwrap_or_else(|_| unreachable!());

        assert_eq!(mgr.find_by_matrix_id("@bob:matrix.org"), Some(1));
        assert_eq!(mgr.find_by_matrix_id("@carol:example.com"), Some(2));
        assert_eq!(
            mgr.find_by_matrix_id("@alice:matrix.org"),
            None,
            "Alice has no matrix_id"
        );
        assert_eq!(mgr.find_by_matrix_id("@nobody:nowhere.net"), None,);
    }

    #[test]
    fn contact_matrix_id_truncates_long_id() {
        let mut long_id = alloc::string::String::from("@");
        for _ in 0..200 {
            long_id.push('a');
        }
        long_id.push_str(":server.example");
        let c = Contact::with_matrix_id("Dave", "111", &long_id).unwrap_or_else(|_| unreachable!());
        assert_eq!(
            c.matrix_id_len as usize, MAX_MATRIX_ID_LEN,
            "matrix_id must be truncated to MAX_MATRIX_ID_LEN"
        );
    }

    #[test]
    fn contact_display_with_matrix_id() {
        let c = Contact::with_matrix_id("Alice", "+1555", "@alice:matrix.org")
            .unwrap_or_else(|_| unreachable!());
        let s = alloc::format!("{c}");
        assert!(
            s.contains("@alice:matrix.org"),
            "Display must include matrix_id when present"
        );
    }

    #[test]
    fn contact_display_without_matrix_id() {
        let c = Contact::new("Bob", "+1555").unwrap_or_else(|_| unreachable!());
        let s = alloc::format!("{c}");
        assert!(
            !s.contains("matrix"),
            "Display must not mention matrix when no matrix_id"
        );
    }

    #[test]
    fn contact_debug_includes_transport() {
        let c = Contact::with_matrix_id("Alice", "+1555", "@alice:m.org")
            .unwrap_or_else(|_| unreachable!());
        let s = alloc::format!("{c:?}");
        assert!(s.contains("Matrix"), "Debug must include default_transport");
    }

    #[test]
    fn add_with_matrix_id_method() {
        let mut mgr = ContactManager::new();
        mgr.add_with_matrix_id("Eve", "+15550002222", "@eve:matrix.org")
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(mgr.count(), 1);
        let eve = mgr.get(0);
        assert!(eve.is_some());
        let eve = eve.unwrap();
        assert_eq!(eve.name_str(), "Eve");
        assert_eq!(eve.matrix_id_str(), "@eve:matrix.org");
        assert_eq!(eve.default_transport, MessageTransport::Matrix);
    }

    // --- AT-injection rejection tests (#368) ---

    #[test]
    fn contact_new_rejects_at_injection() {
        let result = Contact::new("Alice", "+1234\r\nATDT+evil;");
        assert!(
            matches!(result, Err(ContactError::InvalidNumber)),
            "CR/LF + semicolon in number must be rejected, not stored"
        );
    }

    #[test]
    fn add_rejects_invalid_number_and_stores_nothing() {
        let mut mgr = ContactManager::new();
        let result = mgr.add("Eve", "+1234\r\nATDT+evil;");
        assert!(
            matches!(result, Err(ContactError::InvalidNumber)),
            "invalid number must be rejected"
        );
        assert_eq!(
            mgr.count(),
            0,
            "no contact may be created for a rejected number"
        );
    }

    #[test]
    fn contact_new_accepts_empty_number() {
        // Matrix-only contacts have no phone number; empty must stay valid.
        let result = Contact::new("Matrix Only", "");
        assert!(
            result.is_ok(),
            "empty number must remain valid (Matrix-only contact)"
        );
    }

    #[test]
    fn contact_new_accepts_full_dial_charset() {
        let result = Contact::new("Full Charset", "+0123456789*#ABCD");
        assert!(result.is_ok(), "full GSM dial charset must be accepted");
    }
}
