//! GSM 7-bit default alphabet codec (3GPP TS 23.038 § 6.2.1).
//!
//! The character tables, the char<->septet mapping, and packed-septet
//! encode/decode. Septet-stream offset arithmetic that relates this codec
//! to a preceding User Data Header lives in [`crate::udh`]
//! ([`crate::gsm7_udh_septets`]), not here — that boundary is
//! UDH-specific, not GSM-7-specific.

use alloc::string::String;
use alloc::vec::Vec;

use crate::{CoreError, Result};

/// GSM default alphabet: 128 septet-to-Unicode mapping.
///
/// Index is the GSM septet value; the value is the Unicode character.
/// Septet `0x1B` is the extension-table escape, represented as `'\x1b'`.
///
/// NOTE: `@` is at septet `0x00`, not in the extension table — a common
/// bug site, since `0x00` also reads as a natural "empty" value.
#[rustfmt::skip]
pub const GSM_TO_UNICODE: [char; 128] = [
    // 0x00-0x0F
    '@',  '£',  '$',  '¥',  'è',  'é',  'ù',  'ì',
    'ò',  'Ç',  '\n', 'Ø',  'ø',  '\r', 'Å',  'å',
    // 0x10-0x1F
    'Δ',  '_',  'Φ',  'Γ',  'Λ',  'Ω',  'Π',  'Ψ',
    'Σ',  'Θ',  'Ξ',  '\x1b', 'Æ', 'æ', 'ß',  'É',
    // 0x20-0x2F
    ' ',  '!',  '"',  '#',  '¤',  '%',  '&',  '\'',
    '(',  ')',  '*',  '+',  ',',  '-',  '.',  '/',
    // 0x30-0x3F
    '0',  '1',  '2',  '3',  '4',  '5',  '6',  '7',
    '8',  '9',  ':',  ';',  '<',  '=',  '>',  '?',
    // 0x40-0x4F
    '¡',  'A',  'B',  'C',  'D',  'E',  'F',  'G',
    'H',  'I',  'J',  'K',  'L',  'M',  'N',  'O',
    // 0x50-0x5F
    'P',  'Q',  'R',  'S',  'T',  'U',  'V',  'W',
    'X',  'Y',  'Z',  'Ä',  'Ö',  'Ñ',  'Ü',  '§',
    // 0x60-0x6F
    '¿',  'a',  'b',  'c',  'd',  'e',  'f',  'g',
    'h',  'i',  'j',  'k',  'l',  'm',  'n',  'o',
    // 0x70-0x7F
    'p',  'q',  'r',  's',  't',  'u',  'v',  'w',
    'x',  'y',  'z',  'ä',  'ö',  'ñ',  'ü',  'à',
];

/// Extension-table entries, reached via the ESC (`0x1B`) prefix.
///
/// Tuple: `(extension_septet_code, unicode_char)`.
pub const EXT_TABLE: &[(u8, char)] = &[
    (0x0A, '\x0C'), // form feed
    (0x14, '^'),
    (0x28, '{'),
    (0x29, '}'),
    (0x2F, '\\'),
    (0x3C, '['),
    (0x3D, '~'),
    (0x3E, ']'),
    (0x40, '|'),
    (0x65, '€'),
];

/// The GSM-7 escape septet introducing an extension-table character.
pub const ESC_SEPTET: u8 = 0x1B;

/// Convert a Unicode character to its GSM-7 representation.
///
/// Returns `(is_extension, septet_code)`, or `None` when the character has
/// no GSM-7 representation.
///
/// Time: O(1) -- the two loops are bounded by the compile-time-fixed
/// lengths of [`EXT_TABLE`] (10 entries) and [`GSM_TO_UNICODE`] (128
/// entries); neither bound depends on `c`, so every call touches at most
/// 138 table entries regardless of input.
/// Space: O(1) -- no allocation.
#[must_use]
pub fn char_to_septet(c: char) -> Option<(bool, u8)> {
    // Extension table first: it holds characters absent from the base table.
    for &(code, ext_char) in EXT_TABLE {
        if ext_char == c {
            return Some((true, code));
        }
    }
    for (septet, &table_char) in GSM_TO_UNICODE.iter().enumerate() {
        // WHY the `!= ESC_SEPTET` guard: septet 0x1B holds '\x1b' as a
        // placeholder, so a literal ESC in user text would otherwise encode
        // as a bare escape and silently reinterpret the following character
        // as an extension code.
        if table_char == c && septet != usize::from(ESC_SEPTET) {
            // INVARIANT: septet is bounded by GSM_TO_UNICODE.len() (128).
            if let Ok(code) = u8::try_from(septet) {
                return Some((false, code));
            }
        }
    }
    None
}

/// Count the septets required to encode `text` in GSM-7.
///
/// Extension-table characters consume two septets each (ESC + code).
///
/// # Errors
///
/// [`CoreError::Gsm7Encode`] when a character has no GSM-7 representation.
///
/// Time: O(n) where n is the number of `char`s in `text` -- one
/// [`char_to_septet`] call per character, each O(1).
/// Space: O(1) -- only a running counter, no allocation.
pub fn count_septets(text: &str) -> Result<usize> {
    let mut count = 0usize;
    for c in text.chars() {
        let (is_ext, _) = char_to_septet(c).ok_or_else(|| CoreError::Gsm7Encode {
            codepoint: u32::from(c),
        })?;
        count = count.saturating_add(if is_ext { 2 } else { 1 });
    }
    Ok(count)
}

/// Encode a UTF-8 string into packed GSM-7 bytes.
///
/// # Errors
///
/// [`CoreError::Gsm7Encode`] when a character has no GSM-7 representation.
///
/// Time: O(n) where n is the number of `char`s in `text` -- one
/// [`char_to_septet`] call per character (O(1) each) to build up to 2n
/// septets, then one O(1) bit-pack step per septet.
/// Space: O(n) -- an intermediate `septets` `Vec` of up to 2n bytes, then a
/// packed `result` buffer of roughly 7n/8 bytes.
pub fn encode(text: &str) -> Result<Vec<u8>> {
    let mut septets: Vec<u8> = Vec::with_capacity(text.len());
    for c in text.chars() {
        let (is_ext, code) = char_to_septet(c).ok_or_else(|| CoreError::Gsm7Encode {
            codepoint: u32::from(c),
        })?;
        if is_ext {
            septets.push(ESC_SEPTET);
        }
        septets.push(code);
    }

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
        if let Some(slot) = result.get_mut(byte_index) {
            *slot |= lo;
        }
        if hi != 0
            && let Some(slot) = result.get_mut(byte_index + 1)
        {
            *slot |= hi;
        }
    }
    Ok(result)
}

/// Decode `num_septets` septets of packed GSM-7 data.
///
/// Extension characters (ESC + code) consume two septets and produce one
/// output character.
///
/// # Errors
///
/// - [`CoreError::Gsm7Truncated`] when the buffer ends early.
/// - [`CoreError::Gsm7DanglingEscape`] when the data ends on an ESC with no
///   following extension code. WHY this is an error rather than a silently
///   dropped trailing character: the septet stream is modem-controlled, and
///   accepting a truncated extension sequence means rendering a message
///   whose final character the sender did not write.
pub fn decode(data: &[u8], num_septets: usize) -> Result<String> {
    decode_from(data, 0, num_septets)
}

#[expect(
    clippy::as_conversions,
    reason = "septet is masked to 7 bits (0x7F), so the value is always 0-127 and fits u8"
)]
/// Decode `num_septets` septets beginning at septet index `start_septet`.
///
/// WHY this exists (#662): a User Data Header occupies whole octets at the
/// head of the user data, and 3GPP TS 23.040 § 9.2.3.24 then inserts fill
/// bits so the first text septet begins on a *septet* boundary. Those two
/// boundaries do not coincide. Six UDH octets are 48 bits, which is seven
/// septets — 49 bits — so the text starts one bit past the octet the header
/// ends on.
///
/// Skipping the header by slicing at `udh_octets` and decoding from bit zero
/// therefore shifts the whole message by that fill bit and renders garbage.
/// Both the kernel and `klesis` did exactly that. Indexing the septet stream
/// directly is what makes the two boundaries impossible to confuse; the
/// misalignment only vanishes when `udh_octets` is a multiple of 7, which is
/// why the WAP-Push case (7 octets) looked correct while the concatenation
/// case (6 octets) did not.
///
/// # Errors
///
/// As [`decode`].
///
/// Time: O(m) where m is `num_septets` -- the loop consumes exactly
/// `num_septets` septets FROM `data` (regardless of how many collapse into
/// extension characters), each iteration doing O(1) fixed-table lookups
/// and bit-unpacking of at most 2 bytes.
/// Space: O(m) -- `out` is allocated with capacity `num_septets`, an upper
/// bound on the number of characters actually produced.
pub fn decode_from(data: &[u8], start_septet: usize, num_septets: usize) -> Result<String> {
    if num_septets == 0 {
        return Ok(String::new());
    }
    let mut out = String::with_capacity(num_septets);
    let mut i = start_septet;
    let mut septets_consumed = 0usize;
    let mut pending_ext = false;

    while septets_consumed < num_septets {
        let bit_offset = i * 7;
        let byte_index = bit_offset / 8;
        let bit_shift = bit_offset % 8;

        let b0 = u16::from(
            *data
                .get(byte_index)
                .ok_or(CoreError::Gsm7Truncated { septet: i })?,
        );
        // NOTE: a missing high byte contributes 0 bits, which is correct.
        let b1 = u16::from(data.get(byte_index + 1).copied().unwrap_or(0));

        let septet = (((b0 >> bit_shift) | (b1 << (8 - bit_shift))) & 0x7F) as u8;
        i += 1;

        if pending_ext {
            pending_ext = false;
            // An unknown extension code renders as a space rather than
            // failing: 3GPP reserves codes for future characters, and a
            // reserved code is a display gap, not a malformed message.
            let ch = EXT_TABLE
                .iter()
                .find(|&&(code, _)| code == septet)
                .map_or(' ', |&(_, c)| c);
            out.push(ch);
        } else if septet == ESC_SEPTET {
            pending_ext = true;
        } else {
            let ch = GSM_TO_UNICODE
                .get(usize::from(septet))
                .copied()
                .ok_or(CoreError::Gsm7Truncated { septet: i })?;
            out.push(ch);
        }
        septets_consumed += 1;
    }
    if pending_ext {
        return Err(CoreError::Gsm7DanglingEscape);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;
    use crate::ok;

    #[test]
    fn gsm7_round_trips_ascii() {
        let packed = ok(encode("Hello"));
        assert_eq!(
            ok(decode(&packed, 5)),
            "Hello",
            "a GSM-7 round trip must return the original text"
        );
    }

    #[test]
    fn gsm7_round_trips_extension_characters() {
        // Each extension char costs two septets (ESC + code).
        let packed = ok(encode("a{b}"));
        assert_eq!(
            ok(decode(&packed, 6)),
            "a{b}",
            "extension-table characters must survive a round trip"
        );
    }

    #[test]
    fn gsm7_at_sign_is_septet_zero_not_extension() {
        // WHY: '@' at septet 0x00 is a classic bug site — a decoder that
        // treats 0x00 as "no character" silently drops it.
        let packed = ok(encode("@"));
        assert_eq!(ok(decode(&packed, 1)), "@", "'@' must decode from septet 0");
    }

    #[test]
    fn gsm7_rejects_dangling_escape() {
        // A lone ESC septet with nothing after it. WHY this must be an
        // error: the kernel previously accepted it and rendered a message
        // missing its final character, while klesis rejected the same
        // bytes — the divergence #662 records.
        let packed = vec![ESC_SEPTET];
        assert_eq!(
            decode(&packed, 1),
            Err(CoreError::Gsm7DanglingEscape),
            "GSM-7 data ending on a bare ESC must be rejected, not truncated"
        );
    }

    #[test]
    fn gsm7_rejects_unencodable_character() {
        match encode("日") {
            Err(CoreError::Gsm7Encode { codepoint }) => {
                assert_eq!(codepoint, u32::from('日'), "the codepoint must be reported");
            }
            other => unreachable!("expected Gsm7Encode, got {other:?}"),
        }
    }
}
