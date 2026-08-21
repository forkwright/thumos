//! BCD-packed SMS address encode/decode (3GPP TS 23.040 § 9.1.2.5).

use alloc::string::String;
use alloc::vec::Vec;

use crate::{CoreError, Result};

/// Maximum significant digits in an SMS address.
pub const MAX_ADDRESS_DIGITS: usize = 20;

/// Type-of-address octet marking an international number.
pub const TOA_INTERNATIONAL: u8 = 0x91;

/// The BCD filler nibble padding an odd-length address.
const BCD_FILLER: u8 = 0x0F;

/// Decode a BCD-packed address field into its digit string.
///
/// `len_digits` is the significant digit count from the TP-OA/TP-DA length
/// octet, `type_byte` the type-of-address octet, and `bcd` the packed bytes.
/// An international `type_byte` yields a leading `+`.
///
/// # Errors
///
/// - [`CoreError::AddressTooLong`] when `len_digits` exceeds
///   [`MAX_ADDRESS_DIGITS`].
/// - [`CoreError::BcdInvalidDigit`] when a nibble is not a decimal digit.
///
/// Time: O(d) where d is `len_digits` -- each of the d nibbles costs O(1).
/// `d` is checked against the compile-time constant [`MAX_ADDRESS_DIGITS`]
/// (20) and rejected BEFORE the loop runs, so in practice d never exceeds
/// 20.
/// Space: O(d) -- `out` is allocated with capacity `digits + 1`, bounded by
/// the same check.
pub fn decode_bcd_address(len_digits: u8, type_byte: u8, bcd: &[u8]) -> Result<String> {
    let digits = usize::from(len_digits);
    if digits > MAX_ADDRESS_DIGITS {
        return Err(CoreError::AddressTooLong { digits });
    }
    let mut out = String::with_capacity(digits + 1);
    if type_byte == TOA_INTERNATIONAL {
        out.push('+');
    }
    for i in 0..digits {
        let byte = *bcd
            .get(i / 2)
            .ok_or(CoreError::Truncated { offset: i / 2 })?;
        let nibble = if i % 2 == 0 { byte & 0x0F } else { byte >> 4 };
        // WHY reject rather than skip: a non-decimal nibble in a sender
        // address is a malformed or hostile PDU, and silently dropping it
        // yields a number that looks legitimate but is not the sender's.
        if nibble > 9 {
            return Err(CoreError::BcdInvalidDigit { nibble });
        }
        out.push(char::from(b'0' + nibble));
    }
    Ok(out)
}

/// Pack ASCII decimal digits into TS 23.040 BCD byte pairs.
///
/// Each output byte holds two digits, low-nibble-first; an odd digit count
/// pads the final high nibble with [`BCD_FILLER`]. This is the byte-level
/// packing shared by every address-encoding caller — [`encode_bcd_address`]
/// below and the `klesis` workspace crate's own type-of-address-aware
/// encoder, which need the same packing but derive the type-of-address
/// octet differently (a leading `+` here vs. an explicit caller-supplied
/// address type there).
///
/// # Errors
///
/// - [`CoreError::BcdInvalidDigit`] when a byte is not an ASCII decimal
///   digit.
/// - [`CoreError::AddressTooLong`] when `digits.len()` exceeds
///   [`MAX_ADDRESS_DIGITS`].
///
/// Time: O(m) where m is `digits.len()` -- UNLIKE [`decode_bcd_address`],
/// the [`MAX_ADDRESS_DIGITS`] length check runs AFTER the first loop has
/// already scanned the whole input into `nibbles`, so this is not bounded
/// to a small constant: an oversized `digits` slice is still fully scanned
/// (and allocated into) before being rejected. The second loop packs the
/// (now length-checked) nibbles two at a time, O(m).
/// Space: O(m) -- `nibbles` is allocated with capacity `digits.len()`
/// (built to full input length before the bound check), plus `packed` at
/// roughly half that.
pub fn pack_bcd_digits(digits: &[u8]) -> Result<Vec<u8>> {
    let mut nibbles: Vec<u8> = Vec::with_capacity(digits.len());
    for &b in digits {
        if !b.is_ascii_digit() {
            return Err(CoreError::BcdInvalidDigit { nibble: b });
        }
        nibbles.push(b - b'0');
    }
    if nibbles.len() > MAX_ADDRESS_DIGITS {
        return Err(CoreError::AddressTooLong {
            digits: nibbles.len(),
        });
    }

    let mut packed = Vec::with_capacity(nibbles.len().div_ceil(2));
    for pair in nibbles.chunks(2) {
        let lo = pair.first().copied().unwrap_or(BCD_FILLER);
        let hi = pair.get(1).copied().unwrap_or(BCD_FILLER);
        packed.push((hi << 4) | lo);
    }
    Ok(packed)
}

/// Encode a digit string as a BCD address field.
///
/// Returns `(type_of_address, packed_bcd)`. A leading `+` selects the
/// international type-of-address; the `+` is not itself encoded.
///
/// # Errors
///
/// - [`CoreError::AddressTooLong`] when the digit count exceeds
///   [`MAX_ADDRESS_DIGITS`].
/// - [`CoreError::BcdInvalidDigit`] when a character is not a decimal digit.
pub fn encode_bcd_address(number: &str) -> Result<(u8, Vec<u8>)> {
    let (toa, digits_str) = number
        .strip_prefix('+')
        .map_or((0x81, number), |rest| (TOA_INTERNATIONAL, rest));
    let packed = pack_bcd_digits(digits_str.as_bytes())?;
    Ok((toa, packed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ok;

    #[test]
    fn bcd_address_round_trips_international() {
        let (toa, packed) = ok(encode_bcd_address("+15551234"));
        assert_eq!(toa, TOA_INTERNATIONAL, "a leading + selects international");
        let decoded = ok(decode_bcd_address(8, toa, &packed));
        assert_eq!(decoded, "+15551234");
    }

    #[test]
    fn bcd_address_round_trips_odd_length() {
        let (toa, packed) = ok(encode_bcd_address("+1555123"));
        let decoded = ok(decode_bcd_address(7, toa, &packed));
        assert_eq!(
            decoded, "+1555123",
            "an odd digit count must survive the filler nibble"
        );
    }

    #[test]
    fn bcd_address_rejects_non_decimal_nibble() {
        // 0x0A is neither a digit nor the 0xF filler.
        assert_eq!(
            decode_bcd_address(2, 0x81, &[0xAA]),
            Err(CoreError::BcdInvalidDigit { nibble: 0x0A }),
            "a non-decimal nibble must be rejected, not silently rendered"
        );
    }

    #[test]
    fn decode_rejects_a_length_beyond_the_address_bound() {
        // #833: the guard runs before the loop and before the allocation, so
        // a claimed length cannot drive either. Without it a hostile length
        // byte sizes a String and a decode loop from attacker input.
        let err = decode_bcd_address(
            u8::try_from(MAX_ADDRESS_DIGITS + 1).unwrap_or(u8::MAX),
            TOA_INTERNATIONAL,
            &[0x21; 16],
        );
        assert!(
            matches!(err, Err(CoreError::AddressTooLong { .. })),
            "a length above MAX_ADDRESS_DIGITS must be rejected as AddressTooLong"
        );
    }

    #[test]
    fn decode_accepts_the_address_bound_exactly() {
        // The bound is inclusive; rejecting it would drop legitimate
        // maximum-length numbers as malformed.
        let bcd = [0x21u8; MAX_ADDRESS_DIGITS / 2];
        let ok = decode_bcd_address(
            u8::try_from(MAX_ADDRESS_DIGITS).unwrap_or(u8::MAX),
            TOA_INTERNATIONAL,
            &bcd,
        );
        assert!(ok.is_ok(), "exactly MAX_ADDRESS_DIGITS must decode");
    }
}
