//! GSM 7-bit alphabet encoding and decoding (3GPP TS 23.038 § 6.2.1).
//!
//! The codec itself lives in [`klesis_core`], shared with the thumos kernel
//! so the two cannot drift (#545, #662). This module adapts it to the
//! crate's error type; it holds no tables and no bit-packing of its own.

use alloc::string::String;
use alloc::vec::Vec;

use crate::error::Result;

extern crate alloc;

pub(crate) use klesis_core::{EXT_TABLE, GSM_TO_UNICODE};

/// Encode a UTF-8 string INTO a packed GSM 7-bit byte buffer.
///
/// Returns the packed bytes. The number of septets encoded equals the
/// number of GSM characters (extension characters count as two septets).
///
/// # Errors
///
/// [`crate::error::Error::Gsm7Encode`] when a character has no GSM-7
/// representation.
///
/// Time: O(n) where n is the number of `char`s in `text` — one constant-time
/// table lookup per character to produce its septet(s), then one
/// constant-time bit-pack step per septet produced (at most 2n).
/// Space: O(n) — an intermediate septet buffer of up to 2n bytes, then a
/// packed output buffer of roughly 7n/8 bytes.
pub(crate) fn encode(text: &str) -> Result<Vec<u8>> {
    Ok(klesis_core::encode(text)?)
}

/// Decode `num_chars` GSM 7-bit characters FROM a packed byte buffer.
///
/// Extension characters (ESC + code) each count as two septets but produce
/// one output character.
///
/// # Errors
///
/// [`crate::error::Error::PduDecode`] when the data is truncated or ends on
/// a dangling ESC septet.
///
/// Time: O(m) where m is `num_chars` — despite the name, this value is
/// passed straight through as the SEPTET count `klesis_core::decode`
/// consumes FROM `data` (extension characters consume two septets per
/// output char, so the septet count is not the output character count);
/// each of the m septets costs one constant-time table lookup.
/// Space: O(m) — the output `String`'s capacity is sized to `num_chars`,
/// an upper bound on the character count actually produced.
// NOTE(#718): kept `pub` deliberately. Narrowing this to pub(crate)
// showed its only callers are this module's own tests -- after #662 moved
// GSM-7 into klesis-core, the wrapper lost its production consumers. That
// makes it a deletion candidate, not a visibility fix, and deleting a
// public API belongs in its own change rather than inside a lint pass.
pub fn decode(data: &[u8], num_chars: usize) -> Result<String> {
    Ok(klesis_core::decode(data, num_chars)?)
}

/// Decode `num_chars` characters starting at septet index `start_septet`.
///
/// Used to skip a User Data Header, which ends on an octet boundary while
/// the text resumes on a septet boundary — see
/// [`klesis_core::decode_from`].
///
/// # Errors
///
/// As [`decode`].
///
/// Time: O(m) where m is `num_chars` — as [`decode`], this is the septet
/// count consumed starting at `start_septet`, not the output character
/// count.
/// Space: O(m) — the output `String`'s capacity is sized to `num_chars`.
pub(crate) fn decode_from(data: &[u8], start_septet: usize, num_chars: usize) -> Result<String> {
    Ok(klesis_core::decode_from(data, start_septet, num_chars)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_hello_matches_known_output() {
        // WHY: "Hello" is the canonical GSM-7 packing test vector.
        let encoded = encode("Hello").unwrap_or_default();
        assert_eq!(
            encoded,
            [0xC8, 0x32, 0x9B, 0xFD, 0x06],
            "the canonical GSM-7 vector must pack to its published bytes"
        );
    }

    #[test]
    fn round_trip_through_the_shared_codec() {
        let encoded = encode("Hello").unwrap_or_default();
        assert_eq!(decode(&encoded, 5).unwrap_or_default(), "Hello");
    }

    #[test]
    fn errors_map_into_the_crate_error_type() {
        // The adapter must not swallow a core failure into a success.
        assert!(
            encode("日").is_err(),
            "an unencodable character must surface as a crate error"
        );
        assert!(
            decode(&[0x1B], 1).is_err(),
            "a dangling ESC must surface as a crate error"
        );
    }
}
