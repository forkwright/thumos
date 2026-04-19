//! T9 predictive text input for keypad-based text entry.
//!
//! Implements three input modes:
//! - **Predictive (T9)**: maps key sequences to dictionary words. A built-in
//!   dictionary of ~200 common English words is searched by prefix for each
//!   key sequence. Users cycle through candidates with `next_candidate()`.
//! - **Multi-tap**: classic multi-tap input where pressing a key repeatedly
//!   cycles through the letters assigned to that key (e.g., pressing 2 three
//!   times produces 'c').
//! - **Numeric**: digits only, for entering phone numbers in text fields.
//!
//! ## Key mapping (ITU E.161)
//!
//! | Key | Letters      |
//! |-----|-------------|
//! | 2   | a b c       |
//! | 3   | d e f       |
//! | 4   | g h i       |
//! | 5   | j k l       |
//! | 6   | m n o       |
//! | 7   | p q r s     |
//! | 8   | t u v       |
//! | 9   | w x y z     |
//!
//! ## Dictionary
//!
//! The dictionary is a sorted `&[&str]` of common English words. For each
//! key sequence, all words whose letter-to-key mapping matches the pressed
//! keys as a prefix are returned as candidates.

// WHY: T9 input created in Phase 07 Wave 5, kinit wiring pending.
#![expect(
    dead_code,
    reason = "T9 input created in Phase 07 Wave 5, kinit wiring pending"
)]

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

// ---------------------------------------------------------------------------
// Key-to-letter mapping
// ---------------------------------------------------------------------------

/// Letters assigned to each key (2-9).
///
/// Index 0 = key 2, index 7 = key 9. Keys 0 and 1 have no letter
/// assignments in T9.
const KEY_LETTERS: &[&[u8]] = &[
    b"abc",  // 2
    b"def",  // 3
    b"ghi",  // 4
    b"jkl",  // 5
    b"mno",  // 6
    b"pqrs", // 7
    b"tuv",  // 8
    b"wxyz", // 9
];

/// Map a digit (2-9) to its letter group index (0-7).
///
/// Returns `None` for digits outside 2-9.
const fn digit_to_group(digit: u8) -> Option<usize> {
    match digit {
        2..=9 => Some((digit - 2) as usize),
        _ => None,
    }
}

/// Map a lowercase letter to its T9 digit key.
///
/// Returns `None` for non-alphabetic characters.
fn letter_to_digit(ch: u8) -> Option<u8> {
    let lower = ch.to_ascii_lowercase();
    for (i, &group) in KEY_LETTERS.iter().enumerate() {
        for &letter in group {
            if letter == lower {
                return Some(i as u8 + 2);
            }
        }
    }
    None
}

/// Check whether a word matches a T9 key sequence as a prefix.
///
/// Each byte of `key_sequence` must match the digit that the corresponding
/// letter of `word` maps to.
fn word_matches_prefix(word: &str, key_sequence: &[u8]) -> bool {
    if key_sequence.is_empty() || word.len() < key_sequence.len() {
        return false;
    }
    for (i, &digit) in key_sequence.iter().enumerate() {
        let Some(word_byte) = word.as_bytes().get(i) else {
            return false;
        };
        let Some(word_digit) = letter_to_digit(*word_byte) else {
            return false;
        };
        if word_digit != digit {
            return false;
        }
    }
    true
}

// ---------------------------------------------------------------------------
// Input modes
// ---------------------------------------------------------------------------

/// Text input mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum T9Mode {
    /// T9 word prediction from dictionary.
    Predictive,
    /// Classic multi-tap letter cycling.
    MultiTap,
    /// Numeric digits only.
    Numeric,
}

impl T9Mode {
    /// Cycle to the next mode.
    pub(crate) const fn next(self) -> Self {
        match self {
            Self::Predictive => Self::MultiTap,
            Self::MultiTap => Self::Numeric,
            Self::Numeric => Self::Predictive,
        }
    }

    /// Display label for the current mode.
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Predictive => "T9",
            Self::MultiTap => "ABC",
            Self::Numeric => "123",
        }
    }
}

// ---------------------------------------------------------------------------
// Multi-tap state
// ---------------------------------------------------------------------------

/// Tracks multi-tap cycling state for a single key press sequence.
struct MultiTapState {
    /// The digit key being pressed (2-9).
    digit: u8,
    /// How many times this key has been pressed consecutively.
    tap_count: u8,
}

// ---------------------------------------------------------------------------
// T9 input engine
// ---------------------------------------------------------------------------

/// T9 predictive text input engine.
///
/// Accumulates key presses, searches the dictionary for matching words,
/// and allows cycling through candidates. The committed text is built
/// up as words are accepted.
pub(crate) struct T9Input {
    /// Pressed key digits (2-9) for the current word.
    key_sequence: Vec<u8>,
    /// Current candidate list for the key sequence.
    candidates: Vec<&'static str>,
    /// Index into `candidates` of the currently displayed word.
    selected_index: usize,
    /// Currently active input mode.
    mode: T9Mode,
    /// Text committed so far (accepted words).
    committed: String,
    /// Multi-tap state for the current key press.
    multi_tap: Option<MultiTapState>,
}

impl T9Input {
    /// Create a new T9 input engine in Predictive mode.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            key_sequence: Vec::new(),
            candidates: Vec::new(),
            selected_index: 0,
            mode: T9Mode::Predictive,
            committed: String::new(),
            multi_tap: None,
        }
    }

    /// Return the current input mode.
    pub(crate) fn mode(&self) -> T9Mode {
        self.mode
    }

    /// Press a digit key (2-9). Updates the key sequence and candidates.
    ///
    /// In Predictive mode, refreshes the candidate list.
    /// In Multi-tap mode, cycles through letters for the pressed key.
    /// In Numeric mode, appends the digit character.
    pub(crate) fn press_key(&mut self, digit: u8) {
        match self.mode {
            T9Mode::Predictive => {
                if digit_to_group(digit).is_some() {
                    self.key_sequence.push(digit);
                    self.refresh_candidates();
                    self.selected_index = 0;
                }
            }
            T9Mode::MultiTap => {
                self.press_multi_tap(digit);
            }
            T9Mode::Numeric => {
                if digit <= 9 {
                    self.key_sequence.push(digit);
                }
            }
        }
    }

    /// Handle a multi-tap key press.
    ///
    /// If the same key is pressed again, cycle to the next letter.
    /// If a different key is pressed, commit the current letter and
    /// start a new sequence.
    fn press_multi_tap(&mut self, digit: u8) {
        let Some(group_idx) = digit_to_group(digit) else {
            return;
        };
        let group = KEY_LETTERS[group_idx];

        if let Some(ref mut state) = self.multi_tap {
            if state.digit == digit {
                // Same key: cycle to next letter.
                state.tap_count = (state.tap_count + 1) % group.len() as u8;
            } else {
                // Different key: commit current letter, start new.
                self.commit_multi_tap_letter();
                self.multi_tap = Some(MultiTapState {
                    digit,
                    tap_count: 0,
                });
            }
        } else {
            // No active multi-tap: start new.
            self.multi_tap = Some(MultiTapState {
                digit,
                tap_count: 0,
            });
        }
    }

    /// Commit the current multi-tap letter to the key sequence.
    fn commit_multi_tap_letter(&mut self) {
        if let Some(ref state) = self.multi_tap {
            if let Some(group_idx) = digit_to_group(state.digit) {
                let group = KEY_LETTERS[group_idx];
                let letter_idx = state.tap_count as usize % group.len();
                self.key_sequence.push(group[letter_idx]);
            }
        }
        self.multi_tap = None;
    }

    /// Cycle to the next candidate word.
    ///
    /// Wraps around to the first candidate after the last.
    pub(crate) fn next_candidate(&mut self) {
        if !self.candidates.is_empty() {
            self.selected_index = (self.selected_index + 1) % self.candidates.len();
        }
    }

    /// Accept the current word and append it to the committed text.
    ///
    /// Returns the accepted text segment. Resets the key sequence for
    /// the next word.
    pub(crate) fn accept(&mut self) -> String {
        let word = match self.mode {
            T9Mode::Predictive => {
                if let Some(&candidate) = self.candidates.get(self.selected_index) {
                    String::from(candidate)
                } else {
                    // No candidates: return the raw key sequence as digits.
                    self.key_sequence_as_digits()
                }
            }
            T9Mode::MultiTap => {
                // Commit any pending multi-tap letter first.
                self.commit_multi_tap_letter();
                self.key_sequence_as_letters()
            }
            T9Mode::Numeric => self.key_sequence_as_digits(),
        };

        if !self.committed.is_empty() && !word.is_empty() {
            self.committed.push(' ');
        }
        self.committed.push_str(&word);

        let result = word;
        self.key_sequence.clear();
        self.candidates.clear();
        self.selected_index = 0;
        result
    }

    /// Remove the last key from the sequence (backspace).
    pub(crate) fn backspace(&mut self) {
        match self.mode {
            T9Mode::Predictive => {
                self.key_sequence.pop();
                self.refresh_candidates();
                self.selected_index = 0;
            }
            T9Mode::MultiTap => {
                if self.multi_tap.is_some() {
                    // Cancel the current multi-tap without committing.
                    self.multi_tap = None;
                } else {
                    self.key_sequence.pop();
                }
            }
            T9Mode::Numeric => {
                self.key_sequence.pop();
            }
        }
    }

    /// Toggle to the next input mode.
    pub(crate) fn toggle_mode(&mut self) {
        // Commit any pending multi-tap letter before switching modes.
        if self.mode == T9Mode::MultiTap {
            self.commit_multi_tap_letter();
        }
        self.mode = self.mode.next();
        self.key_sequence.clear();
        self.candidates.clear();
        self.selected_index = 0;
        self.multi_tap = None;
    }

    /// Return the currently composed text.
    ///
    /// In Predictive mode, returns the selected candidate word.
    /// In Multi-tap mode, returns the letters entered so far plus the
    /// current cycling letter.
    /// In Numeric mode, returns the digit string.
    pub(crate) fn current_text(&self) -> String {
        match self.mode {
            T9Mode::Predictive => {
                if let Some(&candidate) = self.candidates.get(self.selected_index) {
                    String::from(candidate)
                } else if self.key_sequence.is_empty() {
                    String::new()
                } else {
                    self.key_sequence_as_digits()
                }
            }
            T9Mode::MultiTap => {
                let mut text = self.key_sequence_as_letters();
                // Append the current multi-tap cycling letter.
                if let Some(ref state) = self.multi_tap {
                    if let Some(group_idx) = digit_to_group(state.digit) {
                        let group = KEY_LETTERS[group_idx];
                        let letter_idx = state.tap_count as usize % group.len();
                        text.push(group[letter_idx] as char);
                    }
                }
                text
            }
            T9Mode::Numeric => self.key_sequence_as_digits(),
        }
    }

    /// Return the full committed text.
    pub(crate) fn committed_text(&self) -> &str {
        &self.committed
    }

    /// Return the number of keys in the current sequence.
    pub(crate) fn key_count(&self) -> usize {
        self.key_sequence.len()
    }

    /// Return the number of candidates.
    pub(crate) fn candidate_count(&self) -> usize {
        self.candidates.len()
    }

    /// Clear all state (committed text, key sequence, candidates).
    pub(crate) fn clear(&mut self) {
        self.committed.clear();
        self.key_sequence.clear();
        self.candidates.clear();
        self.selected_index = 0;
        self.multi_tap = None;
    }

    // --- internal helpers ---

    /// Refresh the candidate list based on the current key sequence.
    fn refresh_candidates(&mut self) {
        self.candidates.clear();
        if self.key_sequence.is_empty() {
            return;
        }
        for &word in DICTIONARY {
            if word_matches_prefix(word, &self.key_sequence) {
                // Prefer exact-length matches first.
                if word.len() == self.key_sequence.len() {
                    self.candidates.insert(0, word);
                } else {
                    self.candidates.push(word);
                }
            }
        }
    }

    /// Convert the key sequence to a digit string.
    fn key_sequence_as_digits(&self) -> String {
        let mut s = String::with_capacity(self.key_sequence.len());
        for &d in &self.key_sequence {
            s.push((b'0' + d) as char);
        }
        s
    }

    /// Convert the key sequence to letters (multi-tap committed bytes).
    ///
    /// In multi-tap mode, the key_sequence stores raw letter bytes
    /// after they are committed.
    fn key_sequence_as_letters(&self) -> String {
        let mut s = String::with_capacity(self.key_sequence.len());
        for &b in &self.key_sequence {
            s.push(b as char);
        }
        s
    }
}

// ---------------------------------------------------------------------------
// Built-in dictionary (~200 common English words)
// ---------------------------------------------------------------------------

/// Sorted array of common English words for T9 prediction.
///
/// Words are lowercase, sorted alphabetically for binary search
/// compatibility (though we currently use linear scan for prefix matching).
const DICTIONARY: &[&str] = &[
    "a", "about", "after", "again", "all", "also", "am", "an", "and",
    "another", "any", "are", "around", "as", "at", "away",
    "back", "bad", "be", "because", "been", "before", "being", "best",
    "better", "between", "big", "both", "bring", "but", "buy", "by",
    "call", "came", "can", "change", "close", "come", "could",
    "day", "did", "do", "does", "done", "down", "during",
    "each", "end", "even", "every",
    "feel", "few", "find", "first", "for", "from", "full",
    "get", "give", "go", "going", "good", "got", "great",
    "had", "has", "have", "he", "help", "her", "here", "hi", "him",
    "his", "home", "how",
    "i", "if", "in", "into", "is", "it", "its",
    "just",
    "keep", "kind", "know",
    "last", "left", "let", "life", "like", "little", "live", "long",
    "look", "lot", "love",
    "made", "make", "man", "many", "may", "me", "might", "more",
    "most", "much", "must", "my",
    "need", "new", "next", "nice", "night", "no", "not", "now",
    "of", "off", "oh", "ok", "old", "on", "one", "only", "or",
    "other", "our", "out", "over", "own",
    "part", "people", "place", "put",
    "real", "right", "run",
    "said", "same", "say", "see", "she", "should", "show", "side",
    "since", "so", "some", "something", "still", "sure",
    "take", "tell", "than", "thank", "that", "the", "their", "them",
    "then", "there", "these", "they", "thing", "think", "this", "those",
    "through", "time", "to", "today", "too", "try", "turn", "two",
    "up", "us", "use",
    "very",
    "want", "was", "way", "we", "well", "went", "were", "what",
    "when", "where", "which", "while", "who", "why", "will", "with",
    "work", "world", "would",
    "year", "yes", "yet", "you", "your",
];

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn press_2_shows_abc_words() {
        let mut input = T9Input::new();
        // Key 2 maps to a, b, c.
        input.press_key(2);
        let text = input.current_text();
        // Should show a word starting with a, b, or c.
        assert!(
            !text.is_empty(),
            "pressing 2 must produce at least one candidate"
        );
        // "a" is in the dictionary and matches key 2 exactly.
        assert!(
            input.candidates.iter().any(|&w| w == "a"),
            "'a' must be among candidates for key 2"
        );
    }

    #[test]
    fn backspace_removes_last() {
        let mut input = T9Input::new();
        input.press_key(4);
        input.press_key(3);
        assert_eq!(input.key_count(), 2);

        input.backspace();
        assert_eq!(
            input.key_count(),
            1,
            "backspace must remove the last key"
        );
    }

    #[test]
    fn multi_tap_cycles_letters() {
        let mut input = T9Input::new();
        input.toggle_mode(); // Predictive -> MultiTap
        assert_eq!(input.mode(), T9Mode::MultiTap);

        // Press key 2 once -> 'a'.
        input.press_key(2);
        let text = input.current_text();
        assert_eq!(text, "a", "first press of 2 must show 'a'");

        // Press key 2 again -> 'b'.
        input.press_key(2);
        let text = input.current_text();
        assert_eq!(text, "b", "second press of 2 must show 'b'");

        // Press key 2 again -> 'c'.
        input.press_key(2);
        let text = input.current_text();
        assert_eq!(text, "c", "third press of 2 must show 'c'");

        // Press key 2 again -> wraps back to 'a'.
        input.press_key(2);
        let text = input.current_text();
        assert_eq!(text, "a", "fourth press of 2 must wrap to 'a'");
    }

    #[test]
    fn numeric_mode_returns_digits() {
        let mut input = T9Input::new();
        // Predictive -> MultiTap -> Numeric
        input.toggle_mode();
        input.toggle_mode();
        assert_eq!(input.mode(), T9Mode::Numeric);

        input.press_key(2);
        input.press_key(3);
        input.press_key(4);
        let text = input.current_text();
        assert_eq!(text, "234", "numeric mode must return digit characters");
    }

    #[test]
    fn next_candidate_cycles() {
        let mut input = T9Input::new();
        // Press 8, 4, 3 -> "the"
        input.press_key(8);
        input.press_key(4);
        input.press_key(3);

        let count = input.candidate_count();
        assert!(count > 0, "843 must have at least one candidate");

        let first = input.current_text();
        if count > 1 {
            input.next_candidate();
            let second = input.current_text();
            assert_ne!(
                first, second,
                "next_candidate must cycle to a different word"
            );

            // Cycle back around.
            for _ in 0..count - 1 {
                input.next_candidate();
            }
            let cycled = input.current_text();
            assert_eq!(
                first, cycled,
                "cycling through all candidates must return to start"
            );
        }
    }

    #[test]
    fn accept_commits_word() {
        let mut input = T9Input::new();
        input.press_key(8);
        input.press_key(4);
        input.press_key(3);
        let word = input.accept();
        assert!(!word.is_empty(), "accepted word must not be empty");
        assert!(
            input.key_count() == 0,
            "key sequence must be cleared after accept"
        );
        assert_eq!(
            input.committed_text(),
            &word,
            "committed text must match accepted word"
        );
    }

    #[test]
    fn toggle_mode_cycles() {
        let mut input = T9Input::new();
        assert_eq!(input.mode(), T9Mode::Predictive);

        input.toggle_mode();
        assert_eq!(input.mode(), T9Mode::MultiTap);

        input.toggle_mode();
        assert_eq!(input.mode(), T9Mode::Numeric);

        input.toggle_mode();
        assert_eq!(input.mode(), T9Mode::Predictive);
    }

    #[test]
    fn clear_resets_all_state() {
        let mut input = T9Input::new();
        input.press_key(4);
        input.press_key(3);
        let _ = input.accept();
        input.press_key(2);

        input.clear();
        assert_eq!(input.key_count(), 0);
        assert!(input.committed_text().is_empty());
        assert!(input.current_text().is_empty());
    }

    #[test]
    fn multi_tap_different_key_commits_previous() {
        let mut input = T9Input::new();
        input.toggle_mode(); // -> MultiTap

        // Press 2 once -> 'a', then press 3 -> commits 'a', starts 'd'.
        input.press_key(2);
        input.press_key(3);
        let text = input.current_text();
        assert_eq!(
            text, "ad",
            "pressing different key must commit previous letter"
        );
    }

    #[test]
    fn letter_to_digit_covers_alphabet() {
        // Every lowercase letter must map to a digit 2-9.
        for ch in b'a'..=b'z' {
            assert!(
                letter_to_digit(ch).is_some(),
                "letter '{}' must map to a digit",
                ch as char
            );
        }
    }

    #[test]
    fn word_matches_prefix_basic() {
        assert!(word_matches_prefix("the", &[8, 4, 3]));
        assert!(word_matches_prefix("them", &[8, 4, 3]));
        assert!(!word_matches_prefix("hi", &[8, 4, 3]));
        assert!(!word_matches_prefix("th", &[8, 4, 3]));
    }

    #[test]
    fn dictionary_is_sorted() {
        for pair in DICTIONARY.windows(2) {
            assert!(
                pair[0] <= pair[1],
                "dictionary must be sorted: '{}' > '{}'",
                pair[0],
                pair[1]
            );
        }
    }

    #[test]
    fn empty_sequence_has_no_candidates() {
        let input = T9Input::new();
        assert_eq!(input.candidate_count(), 0);
        assert!(input.current_text().is_empty());
    }
}
