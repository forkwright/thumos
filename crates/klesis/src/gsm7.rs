//! GSM 7-bit alphabet encoding and decoding (3GPP TS 23.038 § 6.2.1).
//!
//! The codec itself lives in [`klesis_core`], shared with the thumos kernel
//! so the two cannot drift (#545, #662). This module adapts it to the
//! crate's error type; it holds no tables and no bit-packing of its own.

use crate::error::Result;
use alloc::string::String;
use alloc::vec::Vec;

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
pub fn encode(text: &str) -> Result<Vec<u8>> {
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
pub fn decode_from(data: &[u8], start_septet: usize, num_chars: usize) -> Result<String> {
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
