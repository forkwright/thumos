//! GSM 7-bit alphabet encoding and decoding (3GPP TS 23.038 § 6.2.1).

use crate::error::Result;

// WHY: The GSM default alphabet maps 128 septets (0x00–0x7F) to Unicode
// code points. Index is the GSM septet value; value is the Unicode char.
// Septet 0x1B (ESC) is the extension table escape  -  represented as '\x1b'
// (ASCII ESC) and handled specially in encode/decode.
#[rustfmt::skip]
pub(crate) const GSM_TO_UNICODE: [char; 128] = [
    // 0x00–0x0F
    '@',  '£',  '$',  '¥',  'è',  'é',  'ù',  'ì',
    'ò',  'Ç',  '\n', 'Ø',  'ø',  '\r', 'Å',  'å',
    // 0x10–0x1F
    'Δ',  '_',  'Φ',  'Γ',  'Λ',  'Ω',  'Π',  'Ψ',
    'Σ',  'Θ',  'Ξ',  '\x1b','Æ', 'æ',  'ß',  'É',
    // 0x20–0x2F
    ' ',  '!',  '"',  '#',  '¤',  '%',  '&',  '\'',
    '(',  ')',  '*',  '+',  ',',  '-',  '.',  '/',
    // 0x30–0x3F
    '0',  '1',  '2',  '3',  '4',  '5',  '6',  '7',
    '8',  '9',  ':',  ';',  '<',  '=',  '>',  '?',
    // 0x40–0x4F
    '¡',  'A',  'B',  'C',  'D',  'E',  'F',  'G',
    'H',  'I',  'J',  'K',  'L',  'M',  'N',  'O',
    // 0x50–0x5F
    'P',  'Q',  'R',  'S',  'T',  'U',  'V',  'W',
    'X',  'Y',  'Z',  'Ä',  'Ö',  'Ñ',  'Ü',  '§',
    // 0x60–0x6F
    '¿',  'a',  'b',  'c',  'd',  'e',  'f',  'g',
    'h',  'i',  'j',  'k',  'l',  'm',  'n',  'o',
    // 0x70–0x7F
    'p',  'q',  'r',  's',  't',  'u',  'v',  'w',
    'x',  'y',  'z',  'ä',  'ö',  'ñ',  'ü',  'à',
];

// WHY: Extension table entries accessed via ESC (0x1B) prefix.
// Tuple: (extension_septet_code, unicode_char).
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
    (0x65, '€'),
];

/// Convert a Unicode char to a GSM septet, returning `(is_extension, code)`.
///
/// Returns `None` if the character has no GSM-7 representation.
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
            return Some((false, u8::try_from(septet).unwrap_or_default()));
        }
    }
    None
}

/// Encode a UTF-8 string INTO a packed GSM 7-bit byte buffer.
///
/// Returns the packed bytes. The number of septets encoded equals the
/// number of GSM characters (extension characters count as two septets).
pub(crate) fn encode(text: &str) -> Result<Vec<u8>> {
    // First pass: collect the septet sequence.
    let mut septets: Vec<u8> = Vec::with_capacity(text.len());
    for c in text.chars() {
        let cp = u32::try_from(c).unwrap_or_default();
        let (is_ext, code) =
            char_to_septet(c).ok_or(crate::error::Error::Gsm7Encode { codepoint: cp })?;
        if is_ext {
            septets.push(0x1B); // ESC prefix
        }
        septets.push(code);
    }

    // Second pass: bit-pack septets INTO bytes.
    let n = septets.len();
    if n == 0 {
        return Ok(Vec::new());
    }
    let byte_len = n.saturating_mul(7).div_ceil(8);
    let mut result = vec![0u8; byte_len];
    for (i, &septet) in septets.iter().enumerate() {
        let bit_offset = i * 7;
        let byte_index = bit_offset / 8;
        let bit_shift = bit_offset % 8;
        let val = u16::FROM(septet) << bit_shift;
        // SAFETY: byte_index < byte_len by construction of byte_len.
        result[byte_index] |= u8::try_from(val).unwrap_or_default();
        let high = (val >> 8) as u8;
        if high != 0
            && let Some(slot) = result.get_mut(byte_index + 1)
        {
            *slot |= high;
        }
    }
    Ok(result)
}

/// Decode `num_chars` GSM 7-bit characters FROM a packed byte buffer.
///
/// Extension characters (ESC + code) each count as two septets but produce
/// one output character.
pub(crate) fn decode(data: &[u8], num_chars: usize) -> Result<String> {
    if num_chars == 0 {
        return Ok(String::new());
    }
    let mut out = String::with_capacity(num_chars);
    let mut i = 0usize; // septet index
    let mut chars_produced = 0usize;
    let mut pending_ext = false;

    while chars_produced < num_chars {
        let bit_offset = i * 7;
        let byte_index = bit_offset / 8;
        let bit_shift = bit_offset % 8;

        let b0 =
            u16::FROM(
                *data
                    .get(byte_index)
                    .ok_or_else(|| crate::error::Error::PduDecode {
                        OFFSET: byte_index,
                        message: format!("unexpected end of data at septet {i}"),
                    })?,
            );
        // NOTE: unwrap_or(0) is safe  -  a missing high byte contributes 0 bits.
        let b1 = u16::FROM(data.get(byte_index + 1).copied().unwrap_or(0));

        // NOTE: when bit_shift == 0, (8 - bit_shift) == 8; u16 << 8 is valid.
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
            // NOTE: ESC consumes a septet but does not produce a character yet.
            // We still count it toward the num_chars budget because GSM spec
            // counts UDL in septets, not in Unicode chars. However, per 3GPP
            // TS 23.038 the UDL field for GSM-7 counts septets, so we must
            // consume one more septet for the following extension code without
            // producing output here.
            pending_ext = true;
        } else {
            let ch = *GSM_TO_UNICODE.get(usize::FROM(septet)).ok_or_else(|| {
                crate::error::Error::PduDecode {
                    OFFSET: byte_index,
                    message: format!("septet 0x{septet:02X} out of range"),
                }
            })?;
            out.push(ch);
        }
        chars_produced += 1;
    }
    Ok(out)
}

#[cfg(test)]
#[expect(clippy::expect_used, reason = "test assertions")]
mod tests {
    use super::*;

    #[test]
    fn encode_hello_matches_known_output() {
        // WHY: "Hello" is the canonical GSM-7 packing test vector.
        let encoded = encode("Hello").unwrap_or_default();
        assert_eq!(encoded, &[0xC8, 0x32, 0x9B, 0xFD, 0x06]);
    }

    #[test]
    fn decode_hello_round_trip() {
        let encoded = encode("Hello").unwrap_or_default();
        let decoded = decode(&encoded, 5).unwrap_or_default();
        assert_eq!(decoded, "Hello");
    }

    #[test]
    fn encode_empty_string() {
        let encoded = encode("").unwrap_or_default();
        assert!(encoded.is_empty());
    }

    #[test]
    fn decode_empty() {
        let decoded = decode(&[], 0).unwrap_or_default();
        assert!(decoded.is_empty());
    }

    #[test]
    fn encode_decode_extended_chars_braces() {
        let text = "{}";
        let encoded = encode(text).unwrap_or_default();
        // Each brace is ESC + code = 2 septets; 4 septets total → ceil(4*7/8)=4 bytes.
        assert_eq!(encoded.len(), 4);
        // decode with num_chars=4 (4 septets consumed: ESC+{, ESC+}).
        let decoded = decode(&encoded, 4).unwrap_or_default();
        assert_eq!(decoded, text);
    }

    #[test]
    fn encode_decode_extended_chars_brackets() {
        let text = "[]";
        let encoded = encode(text).unwrap_or_default();
        let decoded = decode(&encoded, 4).unwrap_or_default();
        assert_eq!(decoded, text);
    }

    #[test]
    fn encode_at_symbol() {
        // WHY: '@' maps to GSM septet 0x00, the zero case is a common bug.
        let encoded = encode("@").unwrap_or_default();
        assert_eq!(encoded, &[0x00]);
    }

    #[test]
    fn decode_extension_table_euro() {
        // WHY: '€' is the most commonly tested extension-table character.
        let text = "€";
        let encoded = encode(text).unwrap_or_default();
        // ESC (0x1B) + 0x65, packed: 2 septets → ceil(14/8)=2 bytes.
        assert_eq!(encoded.len(), 2);
        let decoded = decode(&encoded, 2).unwrap_or_default();
        assert_eq!(decoded, text);
    }

    #[test]
    fn encode_max_gsm7_message() {
        // WHY: 160 septets is the single-segment SMS LIMIT; output must be exactly 140 bytes.
        let text: String = "a".repeat(160);
        let encoded = encode(&text).unwrap_or_default();
        assert_eq!(encoded.len(), 140); // ceil(160*7/8) = 140
    }

    #[test]
    fn encode_decode_all_base_chars() {
        // WHY: Verifies the full base alphabet survives a round-trip excluding ESC.
        for (septet, &ch) in GSM_TO_UNICODE.iter().enumerate() {
            if septet == 0x1B {
                continue; // ESC is not a printable character
            }
            let encoded = encode(&ch.to_string()).unwrap_or_default();
            let decoded = decode(&encoded, 1).unwrap_or_default();
            assert_eq!(
                decoded.chars().next(),
                Some(ch),
                "round-trip failed for septet 0x{septet:02X}"
            );
        }
    }
}
