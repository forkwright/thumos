//! GSM-7 character encoding codec (3GPP TS 23.038).
//!
//! The GSM 7-bit default alphabet maps 128 septets to Unicode code points.
//! Extension-table characters (accessed via ESC prefix 0x1B) consume two
//! septets. This module handles the full base table plus 10 extension
//! characters including euro (ESC + 0x65).
//!
//! Note: `@` is in the base table at septet 0x00 (common bug site), not
//! the extension table.

// Items in this module are re-exported from sms.rs.

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

use crate::sms::SmsError;

// ---------------------------------------------------------------------------
// GSM-7 character tables (ported from klesis/src/gsm7.rs)
// ---------------------------------------------------------------------------

/// GSM default alphabet: 128 septet-to-Unicode mapping.
///
/// Index is the GSM septet value; value is the Unicode character.
/// Septet 0x1B is the extension table escape (represented as `'\x1b'`).
#[rustfmt::skip]
pub(crate) const GSM_TO_UNICODE: [char; 128] = [
    // 0x00-0x0F
    '@',  '\u{00A3}', '$',  '\u{00A5}', '\u{00E8}', '\u{00E9}', '\u{00F9}', '\u{00EC}',
    '\u{00F2}', '\u{00C7}', '\n', '\u{00D8}', '\u{00F8}', '\r', '\u{00C5}', '\u{00E5}',
    // 0x10-0x1F
    '\u{0394}', '_',  '\u{03A6}', '\u{0393}', '\u{039B}', '\u{03A9}', '\u{03A0}', '\u{03A8}',
    '\u{03A3}', '\u{0398}', '\u{039E}', '\x1b', '\u{00C6}', '\u{00E6}', '\u{00DF}', '\u{00C9}',
    // 0x20-0x2F
    ' ',  '!',  '"',  '#',  '\u{00A4}', '%',  '&',  '\'',
    '(',  ')',  '*',  '+',  ',',  '-',  '.',  '/',
    // 0x30-0x3F
    '0',  '1',  '2',  '3',  '4',  '5',  '6',  '7',
    '8',  '9',  ':',  ';',  '<',  '=',  '>',  '?',
    // 0x40-0x4F
    '\u{00A1}', 'A',  'B',  'C',  'D',  'E',  'F',  'G',
    'H',  'I',  'J',  'K',  'L',  'M',  'N',  'O',
    // 0x50-0x5F
    'P',  'Q',  'R',  'S',  'T',  'U',  'V',  'W',
    'X',  'Y',  'Z',  '\u{00C4}', '\u{00D6}', '\u{00D1}', '\u{00DC}', '\u{00A7}',
    // 0x60-0x6F
    '\u{00BF}', 'a',  'b',  'c',  'd',  'e',  'f',  'g',
    'h',  'i',  'j',  'k',  'l',  'm',  'n',  'o',
    // 0x70-0x7F
    'p',  'q',  'r',  's',  't',  'u',  'v',  'w',
    'x',  'y',  'z',  '\u{00E4}', '\u{00F6}', '\u{00F1}', '\u{00FC}', '\u{00E0}',
];

/// Extension table entries accessed via ESC (0x1B) prefix.
///
/// Tuple: `(extension_septet_code, unicode_char)`.
pub(crate) const EXT_TABLE: &[(u8, char)] = &[
    (0x0A, '\x0C'), // form feed
    (0x14, '^'),
    (0x28, '{'),
    (0x29, '}'),
    (0x2F, '\\'),
    (0x3C, '['),
    (0x3D, '~'),
    (0x3E, ']'),
    (0x40, '|'),
    (0x65, '\u{20AC}'), // euro sign
];

// ---------------------------------------------------------------------------
// GSM-7 codec
// ---------------------------------------------------------------------------

/// Convert a Unicode character to its GSM-7 septet representation.
///
/// Returns `(is_extension, septet_code)` or `None` if the character
/// has no GSM-7 representation.
fn char_to_septet(c: char) -> Option<(bool, u8)> {
    // Check extension table first (contains chars not in base table).
    for &(code, ext_char) in EXT_TABLE {
        if ext_char == c {
            return Some((true, code));
        }
    }
    // Linear scan of the base table.
    // NOTE: 0x1B (ESC) is never returned for user characters.
    for (septet, &table_char) in GSM_TO_UNICODE.iter().enumerate() {
        if table_char == c && septet != 0x1B {
            // INVARIANT: septet bounded by GSM_TO_UNICODE.len() (128), fits in u8.
            if let Ok(code) = u8::try_from(septet) {
                return Some((false, code));
            }
        }
    }
    None
}

/// Encode a UTF-8 string into packed GSM 7-bit bytes.
///
/// Returns the packed byte buffer. Extension characters consume two septets
/// each (ESC prefix + code).
///
/// # Errors
///
/// - [`SmsError::Gsm7Encode`] -- a character has no GSM-7 representation.
#[must_use]
pub(crate) fn encode_gsm7(text: &str) -> Result<Vec<u8>, SmsError> {
    // First pass: collect the septet sequence.
    let mut septets: Vec<u8> = Vec::with_capacity(text.len());
    for c in text.chars() {
        let (is_ext, code) =
            char_to_septet(c).ok_or(SmsError::Gsm7Encode(u32::from(c)))?;
        if is_ext {
            septets.push(0x1B); // ESC prefix
        }
        septets.push(code);
    }

    // Second pass: bit-pack septets into bytes.
    let n = septets.len();
    if n == 0 {
        return Ok(Vec::new());
    }
    let byte_len = n.saturating_mul(7).div_ceil(8);
    let mut result = alloc::vec![0u8; byte_len];
    for (i, &septet) in septets.iter().enumerate() {
        let bit_offset = i * 7;
        let byte_index = bit_offset / 8;
        let bit_shift = bit_offset % 8;
        let val = u16::from(septet) << bit_shift;
        let [lo, hi] = val.to_le_bytes();
        result[byte_index] |= lo;
        if hi != 0 {
            if let Some(slot) = result.get_mut(byte_index + 1) {
                *slot |= hi;
            }
        }
    }
    Ok(result)
}

/// Decode `num_septets` GSM 7-bit characters from a packed byte buffer.
///
/// Extension characters (ESC + code) consume two septets but produce
/// one output character.
///
/// # Errors
///
/// - [`SmsError::PduDecode`] -- packed data is truncated or contains invalid septets.
#[must_use]
pub(crate) fn decode_gsm7(data: &[u8], num_septets: usize) -> Result<String, SmsError> {
    if num_septets == 0 {
        return Ok(String::new());
    }
    let mut out = String::with_capacity(num_septets);
    let mut i = 0usize; // septet index
    let mut chars_produced = 0usize;
    let mut pending_ext = false;

    while chars_produced < num_septets {
        let bit_offset = i * 7;
        let byte_index = bit_offset / 8;
        let bit_shift = bit_offset % 8;

        let b0 = u16::from(
            *data.get(byte_index).ok_or(SmsError::PduDecode)?,
        );
        // NOTE: missing high byte contributes 0 bits, which is correct.
        let b1 = u16::from(data.get(byte_index + 1).copied().unwrap_or(0));

        let septet = (((b0 >> bit_shift) | (b1 << (8 - bit_shift))) & 0x7F) as u8;
        i += 1;

        if pending_ext {
            pending_ext = false;
            // Look up in extension table; fall back to space for unknown codes.
            let ch = EXT_TABLE
                .iter()
                .find(|&&(code, _)| code == septet)
                .map_or(' ', |&(_, c)| c);
            out.push(ch);
        } else if septet == 0x1B {
            // ESC does not produce a character; next septet is the extension code.
            pending_ext = true;
        } else {
            let ch = GSM_TO_UNICODE
                .get(usize::from(septet))
                .copied()
                .ok_or(SmsError::PduDecode)?;
            out.push(ch);
        }
        chars_produced += 1;
    }
    Ok(out)
}

/// Count the number of GSM-7 septets required to encode a string.
///
/// Extension-table characters consume 2 septets each.
pub(crate) fn count_gsm7_septets(text: &str) -> Result<usize, SmsError> {
    let mut count = 0usize;
    for c in text.chars() {
        let is_ext = EXT_TABLE.iter().any(|&(_, ec)| ec == c);
        if is_ext {
            count += 2; // ESC + code
        } else {
            let found = GSM_TO_UNICODE
                .iter()
                .enumerate()
                .any(|(i, &tc)| tc == c && i != 0x1B);
            if !found {
                return Err(SmsError::Gsm7Encode(u32::from(c)));
            }
            count += 1;
        }
    }
    Ok(count)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_gsm7_ascii_text() {
        let encoded = encode_gsm7("Hello").unwrap_or_default();
        assert_eq!(
            encoded,
            &[0xC8, 0x32, 0x9B, 0xFD, 0x06],
            "'Hello' must pack to the canonical GSM-7 byte sequence"
        );
    }

    #[test]
    fn decode_gsm7_round_trips() {
        let text = "Testing 123";
        let encoded = encode_gsm7(text).unwrap_or_default();
        let decoded = decode_gsm7(&encoded, text.len()).unwrap_or_default();
        assert_eq!(decoded, text, "GSM-7 round-trip must be lossless for ASCII text");
    }

    #[test]
    fn encode_gsm7_handles_at_sign() {
        // '@' maps to GSM septet 0x00, common off-by-one bug site.
        let encoded = encode_gsm7("@").unwrap_or_default();
        assert_eq!(
            encoded,
            &[0x00],
            "'@' must encode to septet 0x00 (single zero byte)"
        );
        let decoded = decode_gsm7(&encoded, 1).unwrap_or_default();
        assert_eq!(decoded, "@", "round-trip for '@' (septet 0x00) must succeed");
    }

    #[test]
    fn gsm7_extension_euro_round_trips() {
        let encoded = encode_gsm7("\u{20AC}").unwrap_or_default();
        // ESC (0x1B) + 0x65, packed: 2 septets.
        assert_eq!(encoded.len(), 2, "euro must encode to 2 bytes");
        let decoded = decode_gsm7(&encoded, 2).unwrap_or_default();
        assert_eq!(decoded, "\u{20AC}", "euro must survive round-trip");
    }

    #[test]
    fn count_septets_includes_extensions() {
        let count = count_gsm7_septets("{").unwrap_or(0);
        assert_eq!(count, 2, "extension char '{{' must count as 2 septets");

        let count = count_gsm7_septets("Hi").unwrap_or(0);
        assert_eq!(count, 2, "'Hi' must count as 2 septets");
    }
}
