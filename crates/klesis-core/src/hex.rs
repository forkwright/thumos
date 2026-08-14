//! ASCII hex encode/decode for PDU byte data.

use alloc::string::String;
use alloc::vec::Vec;

use crate::{CoreError, Result};

const HEX_CHARS: &[u8; 16] = b"0123456789ABCDEF";

/// Value of a single ASCII hex digit, or `None` if not a hex digit.
#[must_use]
pub const fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Encode bytes as an uppercase hex string.
///
/// Time: O(n) where n is `data.len()` -- one O(1) pair of [`HEX_CHARS`]
/// lookups per input byte.
/// Space: O(n) -- `out` is allocated with capacity `data.len() * 2`.
#[must_use]
pub fn hex_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 2);
    for &b in data {
        // INVARIANT: both indices are masked to 0-15, within HEX_CHARS.
        if let (Some(&hi), Some(&lo)) = (
            HEX_CHARS.get(usize::from(b >> 4)),
            HEX_CHARS.get(usize::from(b & 0x0F)),
        ) {
            out.push(char::from(hi));
            out.push(char::from(lo));
        }
    }
    out
}

/// Decode an ASCII hex string into bytes.
///
/// # Errors
///
/// [`CoreError::HexInvalid`] on odd length or a non-hex character.
///
/// Time: O(n) where n is `s.len()` -- one `chunks_exact(2)` pass, each pair
/// costing two O(1) [`hex_nibble`] lookups.
/// Space: O(n) -- `out` is allocated with capacity `s.len() / 2`.
pub fn hex_decode(s: &[u8]) -> Result<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return Err(CoreError::HexInvalid { offset: s.len() });
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for (pair_index, pair) in s.chunks_exact(2).enumerate() {
        let offset = pair_index * 2;
        let hi = pair
            .first()
            .copied()
            .and_then(hex_nibble)
            .ok_or(CoreError::HexInvalid { offset })?;
        let lo = pair
            .get(1)
            .copied()
            .and_then(hex_nibble)
            .ok_or(CoreError::HexInvalid { offset: offset + 1 })?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ok;

    #[test]
    fn hex_round_trips() {
        let bytes = [0x00u8, 0x1B, 0xFF, 0xA5];
        let s = hex_encode(&bytes);
        assert_eq!(s, "001BFFA5", "hex encoding must be uppercase and padded");
        assert_eq!(ok(hex_decode(s.as_bytes())), bytes);
    }

    #[test]
    fn hex_decode_rejects_odd_length_and_non_hex() {
        assert!(
            hex_decode(b"ABC").is_err(),
            "an odd-length hex string must be rejected"
        );
        assert!(
            hex_decode(b"AZ").is_err(),
            "a non-hex character must be rejected"
        );
    }
}
