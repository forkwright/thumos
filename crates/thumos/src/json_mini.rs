//! Minimal JSON emitter and parser for Matrix CS API.
//!
//! Provides [`JsonWriter`] for building JSON strings and [`JsonParser`]
//! for parsing JSON bytes into [`JsonValue`]. This is intentionally NOT
//! serde — the kernel crate avoids serde for wire protocols to keep the
//! binary size small and avoid the serde trait machinery in `no_std`.
//!
//! # Architecture
//!
//! Optimized for the Matrix event shapes we need:
//! - Sync response envelopes (nested objects with room timelines)
//! - `m.room.message` events (object with `msgtype`, `body` strings)
//! - `m.room.encrypted` events (object with `algorithm`, `ciphertext`)
//! - Login request/response (object with `user_id`, `access_token`)
//!
//! # Limitations
//!
//! - Numbers are parsed as `i64` (no floating point — Matrix event
//!   fields that are numeric are integers: `origin_server_ts`, etc.)
//! - No streaming/incremental parser — the full JSON must be in memory
//! - String escapes: supports `\"`, `\\`, `\/`, `\b`, `\f`, `\n`, `\r`,
//!   `\t`, `\uXXXX` (BMP only, no surrogate pair handling)
//! - Maximum nesting depth of 32 to prevent stack overflow

// WHY: JSON primitives created in Phase 09 Wave 1, harmostes integration pending.
#![expect(
    dead_code,
    reason = "JSON primitives created in Phase 09 Wave 1, harmostes integration pending"
)]

extern crate alloc;

use core::fmt;

use alloc::string::String;
use alloc::vec::Vec;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum nesting depth for the parser (objects/arrays).
/// Prevents stack overflow on deeply nested (possibly malicious) input.
const MAX_DEPTH: usize = 32;

/// Initial capacity for the writer's output buffer.
const WRITER_INITIAL_CAPACITY: usize = 256;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors from JSON parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum JsonError {
    /// The input is empty or contains only whitespace.
    Empty,
    /// Unexpected character encountered during parsing.
    UnexpectedChar,
    /// Unterminated string literal (missing closing `"`).
    UnterminatedString,
    /// Invalid escape sequence in a string.
    InvalidEscape,
    /// Invalid Unicode escape (`\uXXXX` with non-hex digits).
    InvalidUnicodeEscape,
    /// Invalid number format.
    InvalidNumber,
    /// Invalid literal (expected `true`, `false`, or `null`).
    InvalidLiteral,
    /// Nesting depth exceeds [`MAX_DEPTH`].
    TooDeep,
    /// Expected a colon `:` after an object key.
    ExpectedColon,
    /// Expected a comma or closing bracket/brace.
    ExpectedCommaOrEnd,
    /// Trailing data after the root value.
    TrailingData,
    /// Object key is not a string.
    KeyNotString,
}

impl fmt::Display for JsonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "empty JSON input"),
            Self::UnexpectedChar => write!(f, "unexpected character"),
            Self::UnterminatedString => write!(f, "unterminated string"),
            Self::InvalidEscape => write!(f, "invalid escape sequence"),
            Self::InvalidUnicodeEscape => write!(f, "invalid unicode escape"),
            Self::InvalidNumber => write!(f, "invalid number"),
            Self::InvalidLiteral => write!(f, "invalid literal"),
            Self::TooDeep => write!(f, "nesting too deep"),
            Self::ExpectedColon => write!(f, "expected colon after key"),
            Self::ExpectedCommaOrEnd => write!(f, "expected comma or closing bracket"),
            Self::TrailingData => write!(f, "trailing data after JSON value"),
            Self::KeyNotString => write!(f, "object key must be a string"),
        }
    }
}

// ---------------------------------------------------------------------------
// JSON value (parser output)
// ---------------------------------------------------------------------------

/// A parsed JSON value.
///
/// Object entries preserve insertion order (important for Matrix event
/// field ordering in some signature contexts).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum JsonValue {
    /// A JSON null.
    Null,
    /// A JSON boolean.
    Bool(bool),
    /// A JSON number (integer only — sufficient for Matrix).
    Number(i64),
    /// A JSON string (unescaped).
    String(String),
    /// A JSON array.
    Array(Vec<JsonValue>),
    /// A JSON object, preserving key order.
    Object(Vec<(String, JsonValue)>),
}

impl JsonValue {
    /// Return this value as a string reference, if it is a `String`.
    #[must_use]
    pub(crate) fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(s.as_str()),
            _ => None,
        }
    }

    /// Return this value as an i64, if it is a `Number`.
    #[must_use]
    pub(crate) fn as_i64(&self) -> Option<i64> {
        match self {
            Self::Number(n) => Some(*n),
            _ => None,
        }
    }

    /// Return this value as a bool, if it is a `Bool`.
    #[must_use]
    pub(crate) fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// Return this value as an array reference, if it is an `Array`.
    #[must_use]
    pub(crate) fn as_array(&self) -> Option<&[JsonValue]> {
        match self {
            Self::Array(a) => Some(a.as_slice()),
            _ => None,
        }
    }

    /// Return this value as an object reference, if it is an `Object`.
    #[must_use]
    pub(crate) fn as_object(&self) -> Option<&[(String, JsonValue)]> {
        match self {
            Self::Object(o) => Some(o.as_slice()),
            _ => None,
        }
    }

    /// Look up a field by key in an `Object`. Returns `None` if this
    /// is not an object or the key is not found.
    #[must_use]
    pub(crate) fn get(&self, key: &str) -> Option<&JsonValue> {
        match self {
            Self::Object(entries) => entries.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// Return true if this value is `Null`.
    #[must_use]
    pub(crate) fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }
}

impl fmt::Display for JsonValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Null => write!(f, "null"),
            Self::Bool(b) => write!(f, "{b}"),
            Self::Number(n) => write!(f, "{n}"),
            Self::String(s) => write!(f, "\"{s}\""),
            Self::Array(a) => {
                write!(f, "[")?;
                for (i, v) in a.iter().enumerate() {
                    if i > 0 {
                        write!(f, ",")?;
                    }
                    write!(f, "{v}")?;
                }
                write!(f, "]")
            }
            Self::Object(o) => {
                write!(f, "{{")?;
                for (i, (k, v)) in o.iter().enumerate() {
                    if i > 0 {
                        write!(f, ",")?;
                    }
                    write!(f, "\"{k}\":{v}")?;
                }
                write!(f, "}}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// JSON writer (emitter)
// ---------------------------------------------------------------------------

/// State of the writer at each nesting level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WriterContext {
    /// Inside a JSON object.
    Object,
    /// Inside a JSON array.
    Array,
}

/// A streaming JSON emitter that builds a JSON string incrementally.
///
/// Call methods in order to produce valid JSON:
///
/// ```text
/// let mut w = JsonWriter::new();
/// w.object_start();
///   w.key("msgtype");
///   w.string_value("m.text");
///   w.key("body");
///   w.string_value("hello");
/// w.end();
/// // w.finish() => {"msgtype":"m.text","body":"hello"}
/// ```
///
/// The writer tracks nesting state and inserts commas automatically.
#[derive(Debug)]
pub struct JsonWriter {
    /// The output buffer being built.
    buf: String,
    /// Stack of nesting contexts (Object or Array).
    stack: Vec<WriterContext>,
    /// Number of values written at the current nesting level.
    /// Used to determine when to insert commas.
    counts: Vec<usize>,
}

impl JsonWriter {
    /// Create a new writer with an empty output buffer.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            buf: String::with_capacity(WRITER_INITIAL_CAPACITY),
            stack: Vec::new(),
            counts: Vec::new(),
        }
    }

    /// Start a JSON object (`{`).
    ///
    /// When used as a value inside an array, a comma is inserted before
    /// the opening brace if this is not the first element. When used as
    /// a value after a key in an object, the preceding `key()` call
    /// already handled the comma.
    pub(crate) fn object_start(&mut self) {
        self.pre_value();
        self.buf.push('{');
        self.stack.push(WriterContext::Object);
        self.counts.push(0);
    }

    /// Start a JSON array (`[`).
    ///
    /// Same comma logic as `object_start`: commas are inserted
    /// automatically in array context.
    pub(crate) fn array_start(&mut self) {
        self.pre_value();
        self.buf.push('[');
        self.stack.push(WriterContext::Array);
        self.counts.push(0);
    }

    /// Write an object key. Must be called inside an object context,
    /// before a value method.
    pub(crate) fn key(&mut self, name: &str) {
        self.maybe_comma();
        self.buf.push('"');
        escape_string_into(&mut self.buf, name);
        self.buf.push_str("\":");
    }

    /// Write a string value.
    pub(crate) fn string_value(&mut self, value: &str) {
        self.pre_value();
        self.buf.push('"');
        escape_string_into(&mut self.buf, value);
        self.buf.push('"');
        self.post_value();
    }

    /// Write a number value (i64).
    pub(crate) fn number_value(&mut self, value: i64) {
        self.pre_value();
        // WHY: use Display trait to convert i64 to string in no_std.
        use core::fmt::Write;
        write!(&mut self.buf, "{value}").ok();
        self.post_value();
    }

    /// Write a boolean value.
    pub(crate) fn bool_value(&mut self, value: bool) {
        self.pre_value();
        self.buf.push_str(if value { "true" } else { "false" });
        self.post_value();
    }

    /// Write a null value.
    pub(crate) fn null_value(&mut self) {
        self.pre_value();
        self.buf.push_str("null");
        self.post_value();
    }

    /// Write a raw JSON string directly into the output.
    ///
    /// The caller is responsible for ensuring `raw` is valid JSON.
    /// Used for embedding pre-serialized fragments.
    pub(crate) fn raw_value(&mut self, raw: &str) {
        self.pre_value();
        self.buf.push_str(raw);
        self.post_value();
    }

    /// End the current object or array.
    pub(crate) fn end(&mut self) {
        if let Some(ctx) = self.stack.pop() {
            self.counts.pop();
            match ctx {
                WriterContext::Object => self.buf.push('}'),
                WriterContext::Array => self.buf.push(']'),
            }
            // Count this completed container as a value in the parent.
            if let Some(count) = self.counts.last_mut() {
                *count += 1;
            }
        }
    }

    /// Consume the writer and return the built JSON string.
    #[must_use]
    pub(crate) fn finish(self) -> String {
        self.buf
    }

    /// Return the current output as a byte slice (for inspection/testing).
    #[must_use]
    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.buf.as_bytes()
    }

    /// Return the current length of the output buffer.
    #[must_use]
    pub(crate) fn len(&self) -> usize {
        self.buf.len()
    }

    /// Return true if the output buffer is empty.
    #[must_use]
    pub(crate) fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Insert a comma before the next value if needed.
    ///
    /// In an array context, commas go before every value after the first.
    /// In an object context, commas go before every key after the first.
    /// The `key()` method calls this, so values within objects don't
    /// need to call it themselves (they are preceded by a key).
    fn maybe_comma(&mut self) {
        if let Some(count) = self.counts.last() {
            if *count > 0 {
                self.buf.push(',');
            }
        }
    }

    /// Pre-value hook: in array context, insert comma if needed.
    fn pre_value(&mut self) {
        if let Some(ctx) = self.stack.last() {
            if *ctx == WriterContext::Array {
                self.maybe_comma();
            }
        }
    }

    /// Post-value hook: increment the count at the current level.
    fn post_value(&mut self) {
        if let Some(count) = self.counts.last_mut() {
            *count += 1;
        }
    }
}

impl fmt::Display for JsonWriter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.buf)
    }
}

// ---------------------------------------------------------------------------
// JSON parser
// ---------------------------------------------------------------------------

/// Recursive-descent JSON parser.
///
/// Parses a complete JSON value from a byte slice. Not streaming —
/// the full input must be available. Designed for Matrix CS API
/// response bodies which are fully buffered by the HTTP layer.
pub(crate) struct JsonParser<'a> {
    /// The input bytes.
    data: &'a [u8],
    /// Current read position.
    pos: usize,
    /// Current nesting depth (incremented on `{` and `[`).
    depth: usize,
}

impl<'a> JsonParser<'a> {
    /// Parse a JSON value from the given bytes.
    ///
    /// # Errors
    ///
    /// Returns [`JsonError`] if the input is not valid JSON (within
    /// the subset we support).
    #[must_use]
    pub(crate) fn parse(data: &'a [u8]) -> Result<JsonValue, JsonError> {
        let mut parser = Self {
            data,
            pos: 0,
            depth: 0,
        };
        parser.skip_whitespace();
        if parser.pos >= parser.data.len() {
            return Err(JsonError::Empty);
        }
        let value = parser.parse_value()?;
        parser.skip_whitespace();
        if parser.pos < parser.data.len() {
            return Err(JsonError::TrailingData);
        }
        Ok(value)
    }

    /// Parse a single JSON value at the current position.
    fn parse_value(&mut self) -> Result<JsonValue, JsonError> {
        self.skip_whitespace();
        let byte = self.peek().ok_or(JsonError::UnexpectedChar)?;
        match byte {
            b'"' => self.parse_string().map(JsonValue::String),
            b'{' => self.parse_object(),
            b'[' => self.parse_array(),
            b't' | b'f' => self.parse_bool(),
            b'n' => self.parse_null(),
            b'-' | b'0'..=b'9' => self.parse_number(),
            _ => Err(JsonError::UnexpectedChar),
        }
    }

    /// Parse a JSON string (the opening `"` must be at the current position).
    fn parse_string(&mut self) -> Result<String, JsonError> {
        self.advance(); // Skip opening quote.
        let mut s = String::new();

        loop {
            let byte = self.next_byte().ok_or(JsonError::UnterminatedString)?;
            match byte {
                b'"' => return Ok(s),
                b'\\' => {
                    let esc = self.next_byte().ok_or(JsonError::InvalidEscape)?;
                    match esc {
                        b'"' => s.push('"'),
                        b'\\' => s.push('\\'),
                        b'/' => s.push('/'),
                        b'b' => s.push('\u{08}'),
                        b'f' => s.push('\u{0C}'),
                        b'n' => s.push('\n'),
                        b'r' => s.push('\r'),
                        b't' => s.push('\t'),
                        b'u' => {
                            let cp = self.parse_unicode_escape()?;
                            if let Some(c) = char::from_u32(cp) {
                                s.push(c);
                            } else {
                                // Invalid code point — replace with U+FFFD.
                                s.push('\u{FFFD}');
                            }
                        }
                        _ => return Err(JsonError::InvalidEscape),
                    }
                }
                _ => {
                    // Direct UTF-8 bytes. For ASCII, push directly.
                    // For multi-byte UTF-8, we need to collect the full
                    // sequence.
                    if byte < 0x80 {
                        s.push(byte as char);
                    } else {
                        // Multi-byte UTF-8: determine the byte count
                        // from the leading byte and collect the rest.
                        let (cp, extra) = decode_utf8_leading(byte)?;
                        let mut code = cp;
                        for _ in 0..extra {
                            let cont = self.next_byte().ok_or(JsonError::UnterminatedString)?;
                            if cont & 0xC0 != 0x80 {
                                return Err(JsonError::UnexpectedChar);
                            }
                            code = (code << 6) | u32::from(cont & 0x3F);
                        }
                        if let Some(c) = char::from_u32(code) {
                            s.push(c);
                        } else {
                            s.push('\u{FFFD}');
                        }
                    }
                }
            }
        }
    }

    /// Parse a `\uXXXX` Unicode escape (the `\u` has already been consumed).
    fn parse_unicode_escape(&mut self) -> Result<u32, JsonError> {
        let mut cp: u32 = 0;
        for _ in 0..4 {
            let b = self.next_byte().ok_or(JsonError::InvalidUnicodeEscape)?;
            let digit = hex_digit(b).ok_or(JsonError::InvalidUnicodeEscape)?;
            cp = (cp << 4) | u32::from(digit);
        }
        Ok(cp)
    }

    /// Parse a JSON object.
    fn parse_object(&mut self) -> Result<JsonValue, JsonError> {
        self.advance(); // Skip `{`.
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err(JsonError::TooDeep);
        }

        let mut entries = Vec::new();
        self.skip_whitespace();

        // Empty object.
        if self.peek() == Some(b'}') {
            self.advance();
            self.depth -= 1;
            return Ok(JsonValue::Object(entries));
        }

        loop {
            self.skip_whitespace();

            // Key must be a string.
            if self.peek() != Some(b'"') {
                return Err(JsonError::KeyNotString);
            }
            let key = self.parse_string()?;

            // Expect colon.
            self.skip_whitespace();
            if self.next_byte() != Some(b':') {
                return Err(JsonError::ExpectedColon);
            }

            // Value.
            self.skip_whitespace();
            let value = self.parse_value()?;
            entries.push((key, value));

            // Expect comma or closing brace.
            self.skip_whitespace();
            match self.peek() {
                Some(b',') => {
                    self.advance();
                }
                Some(b'}') => {
                    self.advance();
                    self.depth -= 1;
                    return Ok(JsonValue::Object(entries));
                }
                _ => return Err(JsonError::ExpectedCommaOrEnd),
            }
        }
    }

    /// Parse a JSON array.
    fn parse_array(&mut self) -> Result<JsonValue, JsonError> {
        self.advance(); // Skip `[`.
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err(JsonError::TooDeep);
        }

        let mut items = Vec::new();
        self.skip_whitespace();

        // Empty array.
        if self.peek() == Some(b']') {
            self.advance();
            self.depth -= 1;
            return Ok(JsonValue::Array(items));
        }

        loop {
            self.skip_whitespace();
            let value = self.parse_value()?;
            items.push(value);

            self.skip_whitespace();
            match self.peek() {
                Some(b',') => {
                    self.advance();
                }
                Some(b']') => {
                    self.advance();
                    self.depth -= 1;
                    return Ok(JsonValue::Array(items));
                }
                _ => return Err(JsonError::ExpectedCommaOrEnd),
            }
        }
    }

    /// Parse a JSON boolean (`true` or `false`).
    fn parse_bool(&mut self) -> Result<JsonValue, JsonError> {
        if self.remaining().starts_with(b"true") {
            self.pos += 4;
            Ok(JsonValue::Bool(true))
        } else if self.remaining().starts_with(b"false") {
            self.pos += 5;
            Ok(JsonValue::Bool(false))
        } else {
            Err(JsonError::InvalidLiteral)
        }
    }

    /// Parse a JSON null.
    fn parse_null(&mut self) -> Result<JsonValue, JsonError> {
        if self.remaining().starts_with(b"null") {
            self.pos += 4;
            Ok(JsonValue::Null)
        } else {
            Err(JsonError::InvalidLiteral)
        }
    }

    /// Parse a JSON number (integer only).
    ///
    /// Handles optional leading `-`, digits, and rejects leading zeros
    /// (except `0` itself). Does not handle floating point — Matrix
    /// numeric fields are integers.
    fn parse_number(&mut self) -> Result<JsonValue, JsonError> {
        let start = self.pos;
        let negative = self.peek() == Some(b'-');
        if negative {
            self.advance();
        }

        // Must have at least one digit.
        let first = self.peek().ok_or(JsonError::InvalidNumber)?;
        if !first.is_ascii_digit() {
            return Err(JsonError::InvalidNumber);
        }

        // Check for leading zero: if first digit is '0', the next
        // must not be a digit (JSON spec).
        if first == b'0' {
            self.advance();
            if let Some(next) = self.peek() {
                if next.is_ascii_digit() {
                    return Err(JsonError::InvalidNumber);
                }
            }
        } else {
            // Consume remaining digits.
            while let Some(b) = self.peek() {
                if b.is_ascii_digit() {
                    self.advance();
                } else {
                    break;
                }
            }
        }

        // Parse the accumulated digit string.
        let num_str =
            core::str::from_utf8(&self.data[start..self.pos]).map_err(|_| JsonError::InvalidNumber)?;
        let value: i64 = num_str.parse().map_err(|_| JsonError::InvalidNumber)?;
        Ok(JsonValue::Number(value))
    }

    /// Skip whitespace characters (space, tab, newline, carriage return).
    fn skip_whitespace(&mut self) {
        while let Some(b) = self.peek() {
            if b == b' ' || b == b'\t' || b == b'\n' || b == b'\r' {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    /// Peek at the byte at the current position without advancing.
    fn peek(&self) -> Option<u8> {
        self.data.get(self.pos).copied()
    }

    /// Read the byte at the current position and advance.
    fn next_byte(&mut self) -> Option<u8> {
        let b = self.data.get(self.pos).copied();
        if b.is_some() {
            self.pos += 1;
        }
        b
    }

    /// Advance the position by one byte.
    fn advance(&mut self) {
        self.pos += 1;
    }

    /// Return the remaining unparsed bytes.
    fn remaining(&self) -> &[u8] {
        &self.data[self.pos..]
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Escape a string for JSON output, appending escaped characters to `out`.
fn escape_string_into(out: &mut String, s: &str) {
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0C}' => out.push_str("\\f"),
            c if c < '\u{20}' => {
                // Other control characters: \u00XX.
                out.push_str("\\u00");
                let byte = c as u8;
                out.push(hex_char(byte >> 4));
                out.push(hex_char(byte & 0x0F));
            }
            c => out.push(c),
        }
    }
}

/// Convert a nibble (0-15) to its hex character.
fn hex_char(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        10..=15 => (b'a' + n - 10) as char,
        _ => '0', // Should not happen.
    }
}

/// Convert a hex ASCII character to its numeric value (0-15).
fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Decode the leading byte of a multi-byte UTF-8 sequence.
///
/// Returns `(initial_code_point_bits, additional_bytes_count)`.
fn decode_utf8_leading(byte: u8) -> Result<(u32, usize), JsonError> {
    if byte & 0xE0 == 0xC0 {
        // 2-byte sequence: 110xxxxx.
        Ok((u32::from(byte & 0x1F), 1))
    } else if byte & 0xF0 == 0xE0 {
        // 3-byte sequence: 1110xxxx.
        Ok((u32::from(byte & 0x0F), 2))
    } else if byte & 0xF8 == 0xF0 {
        // 4-byte sequence: 11110xxx.
        Ok((u32::from(byte & 0x07), 3))
    } else {
        Err(JsonError::UnexpectedChar)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use alloc::string::ToString;
    
    use super::*;

    // ===== JsonWriter tests =====

    #[test]
    fn write_empty_object() {
        let mut w = JsonWriter::new();
        w.object_start();
        w.end();
        assert_eq!(w.finish(), "{}");
    }

    #[test]
    fn write_empty_array() {
        let mut w = JsonWriter::new();
        w.array_start();
        w.end();
        assert_eq!(w.finish(), "[]");
    }

    #[test]
    fn write_simple_object() {
        let mut w = JsonWriter::new();
        w.object_start();
        w.key("name");
        w.string_value("Alice");
        w.key("age");
        w.number_value(30);
        w.end();
        assert_eq!(w.finish(), r#"{"name":"Alice","age":30}"#);
    }

    #[test]
    fn write_matrix_message_event() {
        let mut w = JsonWriter::new();
        w.object_start();
        w.key("msgtype");
        w.string_value("m.text");
        w.key("body");
        w.string_value("Hello from Thumos");
        w.end();
        let json = w.finish();
        assert_eq!(json, r#"{"msgtype":"m.text","body":"Hello from Thumos"}"#);
    }

    #[test]
    fn write_nested_object() {
        let mut w = JsonWriter::new();
        w.object_start();
        w.key("outer");
        w.object_start();
        w.key("inner");
        w.string_value("value");
        w.end();
        w.end();
        assert_eq!(w.finish(), r#"{"outer":{"inner":"value"}}"#);
    }

    #[test]
    fn write_array_of_strings() {
        let mut w = JsonWriter::new();
        w.array_start();
        w.string_value("one");
        w.string_value("two");
        w.string_value("three");
        w.end();
        assert_eq!(w.finish(), r#"["one","two","three"]"#);
    }

    #[test]
    fn write_array_of_numbers() {
        let mut w = JsonWriter::new();
        w.array_start();
        w.number_value(1);
        w.number_value(2);
        w.number_value(3);
        w.end();
        assert_eq!(w.finish(), "[1,2,3]");
    }

    #[test]
    fn write_mixed_array() {
        let mut w = JsonWriter::new();
        w.array_start();
        w.string_value("text");
        w.number_value(42);
        w.bool_value(true);
        w.null_value();
        w.end();
        assert_eq!(w.finish(), r#"["text",42,true,null]"#);
    }

    #[test]
    fn write_bool_values() {
        let mut w = JsonWriter::new();
        w.object_start();
        w.key("yes");
        w.bool_value(true);
        w.key("no");
        w.bool_value(false);
        w.end();
        assert_eq!(w.finish(), r#"{"yes":true,"no":false}"#);
    }

    #[test]
    fn write_null() {
        let mut w = JsonWriter::new();
        w.object_start();
        w.key("value");
        w.null_value();
        w.end();
        assert_eq!(w.finish(), r#"{"value":null}"#);
    }

    #[test]
    fn write_negative_number() {
        let mut w = JsonWriter::new();
        w.object_start();
        w.key("n");
        w.number_value(-42);
        w.end();
        assert_eq!(w.finish(), r#"{"n":-42}"#);
    }

    #[test]
    fn write_string_escapes() {
        let mut w = JsonWriter::new();
        w.object_start();
        w.key("msg");
        w.string_value("line1\nline2\ttab\"quote\\backslash");
        w.end();
        assert_eq!(
            w.finish(),
            r#"{"msg":"line1\nline2\ttab\"quote\\backslash"}"#
        );
    }

    #[test]
    fn write_object_in_array() {
        let mut w = JsonWriter::new();
        w.array_start();
        w.object_start();
        w.key("id");
        w.number_value(1);
        w.end();
        w.object_start();
        w.key("id");
        w.number_value(2);
        w.end();
        w.end();
        assert_eq!(w.finish(), r#"[{"id":1},{"id":2}]"#);
    }

    #[test]
    fn write_raw_value() {
        let mut w = JsonWriter::new();
        w.object_start();
        w.key("data");
        w.raw_value("[1,2,3]");
        w.end();
        assert_eq!(w.finish(), r#"{"data":[1,2,3]}"#);
    }

    #[test]
    fn writer_len_and_empty() {
        let w = JsonWriter::new();
        assert!(w.is_empty());
        assert_eq!(w.len(), 0);
    }

    #[test]
    fn writer_display() {
        let mut w = JsonWriter::new();
        w.object_start();
        w.key("k");
        w.string_value("v");
        w.end();
        assert_eq!(w.to_string(), r#"{"k":"v"}"#);
    }

    // ===== Matrix-specific emitter tests =====

    #[test]
    fn write_matrix_login_request() {
        let mut w = JsonWriter::new();
        w.object_start();
        w.key("type");
        w.string_value("m.login.password");
        w.key("identifier");
        w.object_start();
        w.key("type");
        w.string_value("m.id.user");
        w.key("user");
        w.string_value("@thumos:matrix.local.lan");
        w.end();
        w.key("password");
        w.string_value("secret123");
        w.key("initial_device_display_name");
        w.string_value("Thumos Phone");
        w.end();
        let json = w.finish();

        // Parse it back to verify validity.
        let parsed = JsonParser::parse(json.as_bytes());
        assert!(parsed.is_ok(), "Failed to parse: {json}");
        let val = parsed.ok().unwrap(); // ok: test
        assert_eq!(
            val.get("type").and_then(JsonValue::as_str),
            Some("m.login.password")
        );
        assert_eq!(
            val.get("initial_device_display_name")
                .and_then(JsonValue::as_str),
            Some("Thumos Phone")
        );
    }

    #[test]
    fn write_matrix_encrypted_event() {
        let mut w = JsonWriter::new();
        w.object_start();
        w.key("algorithm");
        w.string_value("m.megolm.v1.aes-sha2");
        w.key("ciphertext");
        w.string_value("AwgBEoABzQ...");
        w.key("device_id");
        w.string_value("THUMOS001");
        w.key("sender_key");
        w.string_value("Curve25519Key...");
        w.key("session_id");
        w.string_value("session123");
        w.end();
        let json = w.finish();
        let parsed = JsonParser::parse(json.as_bytes());
        assert!(parsed.is_ok());
    }

    // ===== JsonParser tests =====

    #[test]
    fn parse_null() {
        let val = JsonParser::parse(b"null");
        assert_eq!(val, Ok(JsonValue::Null));
    }

    #[test]
    fn parse_true() {
        let val = JsonParser::parse(b"true");
        assert_eq!(val, Ok(JsonValue::Bool(true)));
    }

    #[test]
    fn parse_false() {
        let val = JsonParser::parse(b"false");
        assert_eq!(val, Ok(JsonValue::Bool(false)));
    }

    #[test]
    fn parse_positive_number() {
        let val = JsonParser::parse(b"42");
        assert_eq!(val, Ok(JsonValue::Number(42)));
    }

    #[test]
    fn parse_negative_number() {
        let val = JsonParser::parse(b"-7");
        assert_eq!(val, Ok(JsonValue::Number(-7)));
    }

    #[test]
    fn parse_zero() {
        let val = JsonParser::parse(b"0");
        assert_eq!(val, Ok(JsonValue::Number(0)));
    }

    #[test]
    fn parse_leading_zero_rejected() {
        let val = JsonParser::parse(b"007");
        assert_eq!(val, Err(JsonError::InvalidNumber));
    }

    #[test]
    fn parse_simple_string() {
        let val = JsonParser::parse(b"\"hello\"");
        assert_eq!(val, Ok(JsonValue::String(String::from("hello"))));
    }

    #[test]
    fn parse_string_with_escapes() {
        let val = JsonParser::parse(b"\"line1\\nline2\\ttab\\\"quote\"");
        assert!(val.is_ok());
        let s = val.ok().unwrap(); // ok: test
        assert_eq!(s.as_str(), Some("line1\nline2\ttab\"quote"));
    }

    #[test]
    fn parse_string_unicode_escape() {
        // \u0041 = 'A'
        let val = JsonParser::parse(b"\"\\u0041\"");
        assert_eq!(val, Ok(JsonValue::String(String::from("A"))));
    }

    #[test]
    fn parse_empty_string() {
        let val = JsonParser::parse(b"\"\"");
        assert_eq!(val, Ok(JsonValue::String(String::new())));
    }

    #[test]
    fn parse_empty_object() {
        let val = JsonParser::parse(b"{}");
        assert_eq!(val, Ok(JsonValue::Object(Vec::new())));
    }

    #[test]
    fn parse_empty_array() {
        let val = JsonParser::parse(b"[]");
        assert_eq!(val, Ok(JsonValue::Array(Vec::new())));
    }

    #[test]
    fn parse_simple_object() {
        let json = br#"{"name":"Alice","age":30}"#;
        let val = JsonParser::parse(json);
        assert!(val.is_ok());
        let val = val.ok().unwrap(); // ok: test
        assert_eq!(val.get("name").and_then(JsonValue::as_str), Some("Alice"));
        assert_eq!(val.get("age").and_then(JsonValue::as_i64), Some(30));
    }

    #[test]
    fn parse_nested_object() {
        let json = br#"{"outer":{"inner":"value"}}"#;
        let val = JsonParser::parse(json);
        assert!(val.is_ok());
        let val = val.ok().unwrap(); // ok: test
        let outer = val.get("outer");
        assert!(outer.is_some());
        assert_eq!(
            outer.and_then(|o| o.get("inner")).and_then(JsonValue::as_str),
            Some("value")
        );
    }

    #[test]
    fn parse_array_of_numbers() {
        let json = b"[1,2,3]";
        let val = JsonParser::parse(json);
        assert!(val.is_ok());
        let val = val.ok().unwrap(); // ok: test
        let arr = val.as_array();
        assert!(arr.is_some());
        let arr = arr.unwrap(); // ok: test
        assert_eq!(arr.len(), 3);
        assert_eq!(arr[0].as_i64(), Some(1));
        assert_eq!(arr[1].as_i64(), Some(2));
        assert_eq!(arr[2].as_i64(), Some(3));
    }

    #[test]
    fn parse_whitespace_tolerant() {
        let json = b"  {  \"key\"  :  \"value\"  }  ";
        let val = JsonParser::parse(json);
        assert!(val.is_ok());
        let val = val.ok().unwrap(); // ok: test
        assert_eq!(val.get("key").and_then(JsonValue::as_str), Some("value"));
    }

    #[test]
    fn parse_matrix_message_event() {
        let json = br#"{"msgtype":"m.text","body":"Hello from Thumos"}"#;
        let val = JsonParser::parse(json);
        assert!(val.is_ok());
        let val = val.ok().unwrap(); // ok: test
        assert_eq!(
            val.get("msgtype").and_then(JsonValue::as_str),
            Some("m.text")
        );
        assert_eq!(
            val.get("body").and_then(JsonValue::as_str),
            Some("Hello from Thumos")
        );
    }

    #[test]
    fn parse_matrix_sync_envelope() {
        let json = br#"{
            "next_batch": "s72595_4483_1934",
            "rooms": {
                "join": {
                    "!room:example.com": {
                        "timeline": {
                            "events": [
                                {
                                    "type": "m.room.message",
                                    "sender": "@alice:example.com",
                                    "content": {
                                        "msgtype": "m.text",
                                        "body": "hello"
                                    },
                                    "origin_server_ts": 1234567890,
                                    "event_id": "$event1"
                                }
                            ]
                        }
                    }
                }
            }
        }"#;
        let val = JsonParser::parse(json);
        assert!(val.is_ok());
        let val = val.ok().unwrap(); // ok: test

        // Navigate the sync envelope.
        assert_eq!(
            val.get("next_batch").and_then(JsonValue::as_str),
            Some("s72595_4483_1934")
        );

        let rooms = val.get("rooms");
        assert!(rooms.is_some());
        let join = rooms.and_then(|r| r.get("join"));
        assert!(join.is_some());
        let room = join.and_then(|j| j.get("!room:example.com"));
        assert!(room.is_some());
        let timeline = room.and_then(|r| r.get("timeline"));
        assert!(timeline.is_some());
        let events = timeline.and_then(|t| t.get("events"));
        assert!(events.is_some());
        let events_arr = events.and_then(JsonValue::as_array);
        assert!(events_arr.is_some());
        let events_arr = events_arr.unwrap(); // ok: test
        assert_eq!(events_arr.len(), 1);

        let event = &events_arr[0];
        assert_eq!(
            event.get("type").and_then(JsonValue::as_str),
            Some("m.room.message")
        );
        assert_eq!(
            event.get("origin_server_ts").and_then(JsonValue::as_i64),
            Some(1_234_567_890)
        );
        let content = event.get("content");
        assert_eq!(
            content.and_then(|c| c.get("body")).and_then(JsonValue::as_str),
            Some("hello")
        );
    }

    // ===== Round-trip tests =====

    #[test]
    fn roundtrip_simple_object() {
        let mut w = JsonWriter::new();
        w.object_start();
        w.key("key");
        w.string_value("value");
        w.key("num");
        w.number_value(42);
        w.key("flag");
        w.bool_value(true);
        w.key("nil");
        w.null_value();
        w.end();
        let json = w.finish();

        let parsed = JsonParser::parse(json.as_bytes());
        assert!(parsed.is_ok());
        let val = parsed.ok().unwrap(); // ok: test
        assert_eq!(val.get("key").and_then(JsonValue::as_str), Some("value"));
        assert_eq!(val.get("num").and_then(JsonValue::as_i64), Some(42));
        assert_eq!(val.get("flag").and_then(JsonValue::as_bool), Some(true));
        assert!(val.get("nil").map_or(false, JsonValue::is_null));
    }

    #[test]
    fn roundtrip_nested_structure() {
        let mut w = JsonWriter::new();
        w.object_start();
        w.key("rooms");
        w.object_start();
        w.key("join");
        w.object_start();
        w.key("!room:ex.com");
        w.object_start();
        w.key("events");
        w.array_start();
        w.object_start();
        w.key("type");
        w.string_value("m.room.message");
        w.key("ts");
        w.number_value(1_700_000_000);
        w.end(); // event object
        w.end(); // events array
        w.end(); // room object
        w.end(); // join object
        w.end(); // rooms object
        w.end(); // root object
        let json = w.finish();

        let parsed = JsonParser::parse(json.as_bytes());
        assert!(parsed.is_ok());
        let val = parsed.ok().unwrap(); // ok: test
        let ts = val
            .get("rooms")
            .and_then(|r| r.get("join"))
            .and_then(|j| j.get("!room:ex.com"))
            .and_then(|room| room.get("events"))
            .and_then(JsonValue::as_array)
            .and_then(|events| events.first())
            .and_then(|e| e.get("ts"))
            .and_then(JsonValue::as_i64);
        assert_eq!(ts, Some(1_700_000_000));
    }

    #[test]
    fn roundtrip_array_of_mixed() {
        let mut w = JsonWriter::new();
        w.array_start();
        w.string_value("text");
        w.number_value(-1);
        w.bool_value(false);
        w.null_value();
        w.array_start();
        w.number_value(1);
        w.number_value(2);
        w.end();
        w.end();
        let json = w.finish();

        let parsed = JsonParser::parse(json.as_bytes());
        assert!(parsed.is_ok());
        let val = parsed.ok().unwrap(); // ok: test
        let arr = val.as_array();
        assert!(arr.is_some());
        let arr = arr.unwrap(); // ok: test
        assert_eq!(arr.len(), 5);
        assert_eq!(arr[0].as_str(), Some("text"));
        assert_eq!(arr[1].as_i64(), Some(-1));
        assert_eq!(arr[2].as_bool(), Some(false));
        assert!(arr[3].is_null());
        assert!(arr[4].as_array().is_some());
    }

    // ===== Error cases =====

    #[test]
    fn parse_empty_input() {
        assert_eq!(JsonParser::parse(b""), Err(JsonError::Empty));
    }

    #[test]
    fn parse_whitespace_only() {
        assert_eq!(JsonParser::parse(b"   "), Err(JsonError::Empty));
    }

    #[test]
    fn parse_trailing_data() {
        assert_eq!(JsonParser::parse(b"42 extra"), Err(JsonError::TrailingData));
    }

    #[test]
    fn parse_unterminated_string() {
        assert_eq!(
            JsonParser::parse(b"\"no end"),
            Err(JsonError::UnterminatedString)
        );
    }

    #[test]
    fn parse_invalid_escape() {
        assert_eq!(
            JsonParser::parse(b"\"bad \\x escape\""),
            Err(JsonError::InvalidEscape)
        );
    }

    #[test]
    fn parse_invalid_unicode_escape() {
        assert_eq!(
            JsonParser::parse(b"\"\\uGGGG\""),
            Err(JsonError::InvalidUnicodeEscape)
        );
    }

    #[test]
    fn parse_missing_colon() {
        assert_eq!(
            JsonParser::parse(b"{\"key\" \"value\"}"),
            Err(JsonError::ExpectedColon)
        );
    }

    #[test]
    fn parse_missing_comma_in_object() {
        assert_eq!(
            JsonParser::parse(br#"{"a":1 "b":2}"#),
            Err(JsonError::ExpectedCommaOrEnd)
        );
    }

    #[test]
    fn parse_missing_comma_in_array() {
        assert_eq!(
            JsonParser::parse(b"[1 2]"),
            Err(JsonError::ExpectedCommaOrEnd)
        );
    }

    #[test]
    fn parse_invalid_literal() {
        // "nope" starts with 'n', so the parser tries parse_null(),
        // sees it doesn't match "null", and returns InvalidLiteral.
        assert_eq!(
            JsonParser::parse(b"nope"),
            Err(JsonError::InvalidLiteral)
        );
    }

    #[test]
    fn parse_key_not_string() {
        assert_eq!(
            JsonParser::parse(b"{42:\"value\"}"),
            Err(JsonError::KeyNotString)
        );
    }

    // ===== Display impls =====

    #[test]
    fn json_error_display() {
        assert_eq!(JsonError::Empty.to_string(), "empty JSON input");
        assert_eq!(
            JsonError::UnterminatedString.to_string(),
            "unterminated string"
        );
    }

    #[test]
    fn json_value_display_null() {
        assert_eq!(JsonValue::Null.to_string(), "null");
    }

    #[test]
    fn json_value_display_bool() {
        assert_eq!(JsonValue::Bool(true).to_string(), "true");
        assert_eq!(JsonValue::Bool(false).to_string(), "false");
    }

    #[test]
    fn json_value_display_number() {
        assert_eq!(JsonValue::Number(42).to_string(), "42");
        assert_eq!(JsonValue::Number(-7).to_string(), "-7");
    }

    #[test]
    fn json_value_display_string() {
        assert_eq!(
            JsonValue::String(String::from("hello")).to_string(),
            "\"hello\""
        );
    }

    #[test]
    fn json_value_accessor_none_on_wrong_type() {
        let n = JsonValue::Number(42);
        assert_eq!(n.as_str(), None);
        assert_eq!(n.as_bool(), None);
        assert_eq!(n.as_array(), None);
        assert_eq!(n.as_object(), None);
        assert_eq!(n.get("key"), None);
        assert!(!n.is_null());
    }

    #[test]
    fn large_timestamp_roundtrip() {
        // Matrix origin_server_ts values are large i64s (milliseconds since epoch).
        let ts: i64 = 1_700_000_000_000;
        let mut w = JsonWriter::new();
        w.object_start();
        w.key("ts");
        w.number_value(ts);
        w.end();
        let json = w.finish();
        let parsed = JsonParser::parse(json.as_bytes()).ok().unwrap(); // ok: test
        assert_eq!(parsed.get("ts").and_then(JsonValue::as_i64), Some(ts));
    }
}
