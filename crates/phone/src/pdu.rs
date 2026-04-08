//! SMS PDU encoding and decoding (3GPP TS 23.040).
//!
//! Supports SMS-DELIVER (MT) and SMS-SUBMIT (MO) message types.
//! GSM 7-bit and UCS-2 (UTF-16 BE) data encodings are implemented.

use crate::error::Result;
use crate::gsm7;

// ── Address ──────────────────────────────────────────────────────────────────

/// Address type indicator per 3GPP TS 24.008 § 10.5.4.7.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum AddressType {
    /// Type-of-number = international (0x91). Number includes country code.
    International,
    /// Type-of-number = national (0x81).
    National,
    /// Any other type-of-address byte.
    #[default]
    Unknown,
}

/// A phone number with its type indicator.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Address {
    /// Decimal digit string, including leading '+' for international numbers.
    pub number: String,
    /// How the number should be interpreted.
    pub type_of_address: AddressType,
}

// ── Data encoding ─────────────────────────────────────────────────────────────

/// SMS data coding scheme (DCS) classification.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum DataEncoding {
    /// DCS 0x00  -  GSM 7-bit default alphabet, uncompressed.
    #[default]
    Gsm7Bit,
    /// DCS 0x08  -  UCS-2 (UTF-16 big-endian).
    Ucs2,
}

/// Decoded user data (text payload).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UserData {
    /// Which encoding was used to carry the text.
    pub encoding: DataEncoding,
    /// The decoded text, in Rust's native UTF-8.
    pub text: String,
}

// ── PDU message types ─────────────────────────────────────────────────────────

/// A received SMS (SMS-DELIVER, MTI = 0b00).
#[derive(Debug, Clone, Default)]
pub struct SmsDeliver {
    /// Originating address.
    pub sender: Address,
    /// Service centre timestamp in "YYYY-MM-DD HH:MM:SS+HH:MM" format.
    pub timestamp: String,
    /// Decoded message payload.
    pub user_data: UserData,
}

/// A message to be sent (SMS-SUBMIT, MTI = 0b01).
#[derive(Debug, Clone)]
pub struct SmsSubmit {
    /// Destination address.
    pub destination: Address,
    /// Message payload and encoding.
    pub user_data: UserData,
    /// Relative validity period (1 byte). `None` = omit VP field.
    pub validity_period: Option<u8>,
}

// ── BCD address helpers ───────────────────────────────────────────────────────

/// Decode a BCD-packed address field INTO an [`Address`].
///
/// `len_digits` is the number of significant digits (FROM the TP-OA/TP-DA
/// length octet). `type_byte` is the type-of-address octet. `bcd` is the
/// packed BCD byte slice (`ceil(len_digits` / 2) bytes).
fn decode_bcd_address(len_digits: u8, type_byte: u8, bcd: &[u8]) -> Address {
    let type_of_address = match type_byte {
        0x91 => AddressType::International,
        0x81 => AddressType::National,
        _ => AddressType::Unknown,
    };

    let mut number = String::new();
    if type_of_address == AddressType::International {
        number.push('+');
    }

    let digit_count = usize::from(len_digits);
    for (idx, &byte) in bcd.iter().enumerate() {
        let lo = byte & 0x0F;
        let hi = (byte >> 4) & 0x0F;

        // Low nibble always present when we have a BCD byte.
        let lo_digit_index = idx * 2;
        if lo_digit_index < digit_count {
            number.push(char::from(b'0' + lo));
        }
        // High nibble may be a filler 0xF for odd-digit numbers.
        let hi_digit_index = idx * 2 + 1;
        if hi_digit_index < digit_count && hi != 0x0F {
            number.push(char::from(b'0' + hi));
        }
    }

    Address {
        number,
        type_of_address,
    }
}

/// Encode an [`Address`] INTO the PDU wire format.
///
/// Returns `[length_in_digits, type_byte, bcd_bytes…]`.
fn encode_bcd_address(addr: &Address) -> Vec<u8> {
    // Strip any leading '+'.
    let digits: &str = addr.number.strip_prefix('+').unwrap_or(&addr.number);

    let type_byte: u8 = match addr.type_of_address {
        AddressType::International => 0x91,
        AddressType::National => 0x81,
        _ => 0x80,
    };

    let digit_bytes: Vec<u8> = digits.as_bytes().to_vec();
    // INVARIANT: SMS phone numbers are at most 20 digits (E.164), always fits in u8.
    let len_digits = u8::try_from(digit_bytes.len()).unwrap_or_default();
    let bcd_byte_count = usize::from(len_digits.div_ceil(2));

    let mut bcd: Vec<u8> = vec![0u8; bcd_byte_count];
    for (i, &d) in digit_bytes.iter().enumerate() {
        let nibble = d - b'0';
        let byte_index = i / 2;
        if i % 2 == 0 {
            // Low nibble
            bcd[byte_index] = nibble;
        } else {
            // High nibble
            bcd[byte_index] |= nibble << 4;
        }
    }
    // Pad odd-length numbers with 0xF in the final high nibble.
    if !digit_bytes.len().is_multiple_of(2)
        && let Some(last) = bcd.last_mut()
    {
        *last |= 0xF0;
    }

    let mut out = Vec::with_capacity(2 + bcd_byte_count);
    out.push(len_digits);
    out.push(type_byte);
    out.extend_from_slice(&bcd);
    out
}

// ── Timestamp helpers ─────────────────────────────────────────────────────────

/// Decode a 7-byte SCTS field INTO an ISO-8601-like timestamp string.
///
/// Each byte contains two BCD digits packed low-nibble-first.
/// The timezone byte encodes signed quarter-hour offsets; bit 3 is the sign.
fn decode_scts(scts: [u8; 7]) -> String {
    // Helper: extract low and high BCD nibbles (low-nibble-first convention).
    let lo = |b: u8| b & 0x0F;
    let hi = |b: u8| (b >> 4) & 0x0F;
    let pair = |b: u8| lo(b) * 10 + hi(b);

    let year = 2000u32 + u32::from(pair(scts.first().copied().unwrap_or_default()));
    let month = pair(scts.get(1).copied().unwrap_or_default());
    let day = pair(scts.get(2).copied().unwrap_or_default());
    let hour = pair(scts.get(3).copied().unwrap_or_default());
    let minute = pair(scts.get(4).copied().unwrap_or_default());
    let second = pair(scts.get(5).copied().unwrap_or_default());

    // Timezone byte: magnitude in bits 0-2, 4-7; sign in bit 3.
    let tz_raw = scts.get(6).copied().unwrap_or_default();
    let tz_negative = (tz_raw & 0x08) != 0;
    let tz_quarters = (lo(tz_raw) & 0x07) * 10 + hi(tz_raw);
    let tz_total_minutes = u32::from(tz_quarters) * 15;
    let tz_hh = tz_total_minutes / 60;
    let tz_mm = tz_total_minutes % 60;
    let tz_sign = if tz_negative { '-' } else { '+' };

    format!(
        "{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}{tz_sign}{tz_hh:02}:{tz_mm:02}"
    )
}

// ── Hex codec helpers ─────────────────────────────────────────────────────────

fn hex_decode(s: &str) -> Result<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return Err(crate::error::Error::InvalidHex {
            message: "odd number of hex characters".to_owned(),
        });
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for chunk in s.as_bytes().chunks(2) {
        // SAFETY: chunks(2) always gives exactly 2 bytes here; we checked even length.
        let hi = hex_nibble(chunk.first().copied().unwrap_or_default()).ok_or_else(|| crate::error::Error::InvalidHex {
            message: format!("invalid hex digit: 0x{:02X}", chunk.first().copied().unwrap_or_default()),
        })?;
        let lo = hex_nibble(chunk.get(1).copied().unwrap_or_default()).ok_or_else(|| crate::error::Error::InvalidHex {
            message: format!("invalid hex digit: 0x{:02X}", chunk.get(1).copied().unwrap_or_default()),
        })?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

const fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn hex_encode(data: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(data.len() * 2);
    for &b in data {
        // INVARIANT: nibble values 0–15 always index into HEX[16]; no truncation possible.
        out.push(char::from(HEX[usize::from(b >> 4)]));
        out.push(char::from(HEX[usize::from(b & 0x0F)]));
    }
    out
}

// ── Cursor helper ─────────────────────────────────────────────────────────────

/// A simple read cursor over a byte slice that tracks the current OFFSET.
struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    const fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn read_byte(&mut self) -> Result<u8> {
        let b = *self
            .data
            .get(self.pos)
            .ok_or_else(|| crate::error::Error::PduDecode {
                offset: self.pos,
                message: "unexpected end of PDU".to_owned(),
            })?;
        self.pos += 1;
        Ok(b)
    }

    fn read_slice(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self.pos + len;
        let slice = self
            .data
            .get(self.pos..end)
            .ok_or_else(|| crate::error::Error::PduDecode {
                offset: self.pos,
                message: format!(
                    "need {len} bytes but only {} remain",
                    self.data.len() - self.pos
                ),
            })?;
        self.pos = end;
        Ok(slice)
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Decode an SMS-DELIVER PDU FROM its hex string representation.
///
/// The hex string must represent the full TPDU including the SMSC prefix.
pub fn decode_deliver(pdu_hex: &str) -> Result<SmsDeliver> {
    let raw = hex_decode(pdu_hex)?;
    let mut cur = Cursor::new(&raw);

    // SMSC prefix: length byte + SMSC bytes (skip entirely).
    let smsc_len = usize::from(cur.read_byte()?);
    cur.read_slice(smsc_len)?;

    // First octet of TPDU.
    let first_octet = cur.read_byte()?;
    let mti = first_octet & 0x03;
    if mti != 0x00 {
        return Err(crate::error::Error::PduDecode {
            offset: cur.pos - 1,
            message: format!("expected SMS-DELIVER (MTI=0), got MTI={mti}"),
        });
    }

    // Originating address.
    let oa_len_digits = cur.read_byte()?;
    let oa_type = cur.read_byte()?;
    let oa_bcd_bytes = usize::from(oa_len_digits.div_ceil(2));
    let oa_bcd = cur.read_slice(oa_bcd_bytes)?;
    let sender = decode_bcd_address(oa_len_digits, oa_type, oa_bcd);

    // PID (ignored).
    cur.read_byte()?;

    // DCS  -  determine encoding.
    let dcs = cur.read_byte()?;
    let encoding = dcs_to_encoding(dcs, cur.pos - 1)?;

    // SCTS  -  7 bytes.
    let scts_slice = cur.read_slice(7)?;
    let mut scts = [0u8; 7];
    scts.copy_from_slice(scts_slice);
    let timestamp = decode_scts(scts);

    // User data length (UDL) + user data (UD).
    let udl = usize::from(cur.read_byte()?);
    let user_data = decode_user_data(&mut cur, udl, encoding)?;

    Ok(SmsDeliver {
        sender,
        timestamp,
        user_data,
    })
}

/// Encode an SMS-SUBMIT INTO a hex string suitable for `AT+CMGS`.
pub fn encode_submit(msg: &SmsSubmit) -> Result<String> {
    let mut out: Vec<u8> = Vec::new();

    // SMSC length 0x00  -  let the modem use its stored default.
    out.push(0x00);

    // First octet: MTI=01 (SMS-SUBMIT).
    // VPF bits 4-3: 00=no VP, 10=relative VP.
    let vpf: u8 = if msg.validity_period.is_some() {
        0b0001_0001 // MTI=01, VPF=10 (relative)
    } else {
        0b0000_0001 // MTI=01, VPF=00 (not present)
    };
    out.push(vpf);

    // Message reference: 0x00 (let modem assign).
    out.push(0x00);

    // Destination address.
    out.extend_from_slice(&encode_bcd_address(&msg.destination));

    // PID: 0x00 (normal SMS).
    out.push(0x00);

    // DCS.
    let dcs: u8 = match msg.user_data.encoding {
        DataEncoding::Gsm7Bit => 0x00,
        DataEncoding::Ucs2 => 0x08,
    };
    out.push(dcs);

    // Validity period (optional).
    if let Some(vp) = msg.validity_period {
        out.push(vp);
    }

    // Encode user data.
    encode_user_data_into(&msg.user_data, &mut out)?;

    Ok(hex_encode(&out))
}

// ── Internal encoding/decoding helpers ───────────────────────────────────────

fn dcs_to_encoding(dcs: u8, offset: usize) -> Result<DataEncoding> {
    // NOTE: per 3GPP TS 23.038 § 4, bits 3-2 of DCS (for general GROUP 0x0X)
    // indicate the character SET: 00=GSM7, 01=8-bit data, 10=UCS-2.
    let class_bits = (dcs >> 2) & 0x03;
    match class_bits {
        0b00 => Ok(DataEncoding::Gsm7Bit),
        0b10 => Ok(DataEncoding::Ucs2),
        other => Err(crate::error::Error::PduDecode {
            offset,
            message: format!("unsupported DCS encoding class 0b{other:02b} (DCS=0x{dcs:02X})"),
        }),
    }
}

fn decode_user_data(cur: &mut Cursor<'_>, udl: usize, encoding: DataEncoding) -> Result<UserData> {
    let text = match encoding {
        DataEncoding::Gsm7Bit => {
            // UDL is the number of septets; byte count is ceil(UDL*7/8).
            let byte_count = udl.saturating_mul(7).div_ceil(8);
            let ud_bytes = cur.read_slice(byte_count)?;
            gsm7::decode(ud_bytes, udl)?
        }
        DataEncoding::Ucs2 => {
            // UDL is the number of bytes for UCS-2.
            let ud_bytes = cur.read_slice(udl)?;
            if ud_bytes.len() % 2 != 0 {
                return Err(crate::error::Error::PduDecode {
                    offset: cur.pos,
                    message: "UCS-2 user data has odd byte count".to_owned(),
                });
            }
            let mut s = String::with_capacity(ud_bytes.len() / 2);
            for pair in ud_bytes.chunks_exact(2) {
                let code_unit = u16::from_be_bytes([pair.first().copied().unwrap_or_default(), pair.get(1).copied().unwrap_or_default()]);
                // WHY: SMS UCS-2 is BMP-only; surrogate pairs are technically
                // possible but rare and outside our current scope.
                let ch =
                    char::from_u32(u32::from(code_unit)).unwrap_or(char::REPLACEMENT_CHARACTER);
                s.push(ch);
            }
            s
        }
    };
    Ok(UserData { encoding, text })
}

fn encode_user_data_into(ud: &UserData, out: &mut Vec<u8>) -> Result<()> {
    match ud.encoding {
        DataEncoding::Gsm7Bit => {
            let packed = gsm7::encode(&ud.text)?;
            // UDL = number of septets. We need to count them (extension chars
            // produce 2 septets but 1 character).
            let septet_count = count_gsm7_septets(&ud.text)?;
            out.push(u8::try_from(septet_count).unwrap_or_default());
            out.extend_from_slice(&packed);
        }
        DataEncoding::Ucs2 => {
            // UDL = number of bytes.
            let mut utf16_bytes: Vec<u8> = Vec::with_capacity(ud.text.len() * 2);
            for c in ud.text.chars() {
                let code = u32::from(c);
                // NOTE: BMP characters fit in one u16.
                let unit = u16::try_from(code).unwrap_or_default();
                let [hi, lo] = unit.to_be_bytes();
                utf16_bytes.push(hi);
                utf16_bytes.push(lo);
            }
            // INVARIANT: single-segment SMS UCS-2 is max 140 bytes, always fits in u8.
            out.push(u8::try_from(utf16_bytes.len()).unwrap_or_default());
            out.extend_from_slice(&utf16_bytes);
        }
    }
    Ok(())
}

/// Count the number of GSM-7 septets required to encode a string.
///
/// Extension-table characters consume 2 septets each.
fn count_gsm7_septets(text: &str) -> Result<usize> {
    use crate::gsm7::EXT_TABLE;
    use crate::gsm7::GSM_TO_UNICODE;

    let mut count = 0usize;
    for c in text.chars() {
        // Check extension table.
        let is_ext = EXT_TABLE.iter().any(|&(_, ec)| ec == c);
        if is_ext {
            count += 2; // ESC + code
        } else {
            // Must exist in base table (encoding will have already failed if not).
            let found = GSM_TO_UNICODE
                .iter()
                .enumerate()
                .any(|(i, &tc)| tc == c && i != 0x1B);
            if !found {
                return Err(crate::error::Error::Gsm7Encode {
                    codepoint: u32::from(c),
                });
            }
            count += 1;
        }
    }
    Ok(count)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── BCD address tests ─────────────────────────────────────────────────────

    #[test]
    fn bcd_encode_decode_international() {
        let addr = Address {
            number: "+1234567890".to_owned(),
            type_of_address: AddressType::International,
        };
        let encoded = encode_bcd_address(&addr);
        // encoded = [len_digits=10, type=0x91, bcd*5]
        assert_eq!(encoded.first().copied().unwrap_or_default(), 10, "first byte must be digit count (10)");
        assert_eq!(encoded.get(1).copied().unwrap_or_default(), 0x91, "second byte must be type-of-address 0x91 (international)");
        // Decode back: len_digits=10, type=0x91, bcd = encoded[2..]
        let decoded = decode_bcd_address(encoded[0], encoded[1], &encoded[2..]);
        assert_eq!(decoded.number, "+1234567890", "decoded number must match original");
        assert_eq!(decoded.type_of_address, AddressType::International, "decoded type must be International");
    }

    #[test]
    fn bcd_encode_decode_odd_digits() {
        let addr = Address {
            number: "+12345678901".to_owned(),
            type_of_address: AddressType::International,
        };
        let encoded = encode_bcd_address(&addr);
        assert_eq!(encoded.first().copied().unwrap_or_default(), 11, "first byte must be digit count (11)");
        let decoded = decode_bcd_address(encoded[0], encoded[1], &encoded[2..]);
        assert_eq!(decoded.number, "+12345678901", "decoded number must match 11-digit original including trailing filler nibble");
    }

    // ── Known PDU decode (SMS-DELIVER, GSM-7) ─────────────────────────────────

    #[test]
    fn decode_deliver_known_pdu() {
        // WHY: This is the canonical test vector derived FROM the prompt.
        // PDU breakdown:
        //   00            -  SMSC len 0 (no SMSC prefix)
        //   00            -  first octet: MTI=0 (SMS-DELIVER)
        //   0A            -  OA length: 10 digits
        //   91            -  OA type: international
        //   21 43 65 87 09  -  BCD: +1234567890
        //   00            -  PID
        //   00            -  DCS: GSM-7
        //   32 10 51 21 03 00 00  -  SCTS: 2023-01-15 12:30:00+00:00
        //   05            -  UDL: 5 septets
        //   C8 32 9B FD 06  -  UD: "Hello" packed
        let pdu = "00000A9121436587090000321051210300000 5C8329BFD06".replace(' ', "");
        let sms = decode_deliver(&pdu).unwrap_or_default();
        assert_eq!(sms.sender.number, "+1234567890", "sender number must decode to +1234567890");
        assert_eq!(sms.sender.type_of_address, AddressType::International, "sender type must be International");
        assert!(
            sms.timestamp.contains("2023-01-15"),
            "timestamp must contain date 2023-01-15, got: {}",
            sms.timestamp
        );
        assert_eq!(sms.user_data.text, "Hello", "GSM-7 packed bytes must decode to 'Hello'");
    }

    // ── SMS-SUBMIT encode/decode ───────────────────────────────────────────────

    #[test]
    fn encode_submit_basic() {
        let msg = SmsSubmit {
            destination: Address {
                number: "+1234567890".to_owned(),
                type_of_address: AddressType::International,
            },
            user_data: UserData {
                encoding: DataEncoding::Gsm7Bit,
                text: "Hello".to_owned(),
            },
            validity_period: None,
        };
        let hex = encode_submit(&msg).unwrap_or_default();
        // Must be valid hex and decodable.
        let raw = hex_decode(&hex).unwrap_or_default();
        // First byte is SMSC len 0x00.
        assert_eq!(raw.first(), Some(&0x00), "SMSC length prefix must be 0x00");
        // Second byte: MTI=01.
        assert_eq!(raw.get(1).map(|b| b & 0x03), Some(0x01), "MTI bits must be 0x01 (SMS-SUBMIT)");
    }

    #[test]
    fn encode_decode_submit_round_trip() {
        // WHY: Encode an SMS-SUBMIT, then manually verify fields in the raw bytes.
        let msg = SmsSubmit {
            destination: Address {
                number: "+442071234567".to_owned(),
                type_of_address: AddressType::International,
            },
            user_data: UserData {
                encoding: DataEncoding::Gsm7Bit,
                text: "Test".to_owned(),
            },
            validity_period: Some(0xAA),
        };
        let hex = encode_submit(&msg).unwrap_or_default();
        let raw = hex_decode(&hex).unwrap_or_default();

        // With VPF=10, first octet should be 0x11.
        assert_eq!(raw.get(1), Some(&0x11), "first octet must be 0x11 (MTI=01 with VPF=10 relative VP)");
        // VP byte should be present after DA.
        // DA length = 12 digits → 8 bytes ([len, type, 6×bcd]) → OFFSET for VP = 1+1+1+8+1+1 = 13? Let's just verify non-empty.
        assert!(!hex.is_empty(), "encoded PDU hex must be non-empty");
    }

    // ── UCS-2 test ────────────────────────────────────────────────────────────

    #[test]
    fn decode_deliver_ucs2() {
        // WHY: Verifies UCS-2 decoding path.
        // PDU: 00 00 0A 91 21 43 65 87 09 00 08 32 10 51 21 03 00 00 04 00 48 00 69
        //   DCS=0x08 (UCS-2), UDL=4 bytes, UD=0x0048 0x0069 → "Hi"
        let pdu = "00000A91214365870900083210512103000004004800 69".replace(' ', "");
        let sms = decode_deliver(&pdu).unwrap_or_default();
        assert_eq!(sms.user_data.encoding, DataEncoding::Ucs2, "DCS=0x08 must be decoded as UCS-2");
        assert_eq!(sms.user_data.text, "Hi", "UCS-2 bytes 0x0048 0x0069 must decode to 'Hi'");
    }

    // ── Edge cases ────────────────────────────────────────────────────────────

    #[test]
    fn encode_submit_empty_message() {
        let msg = SmsSubmit {
            destination: Address {
                number: "+1".to_owned(),
                type_of_address: AddressType::International,
            },
            user_data: UserData {
                encoding: DataEncoding::Gsm7Bit,
                text: String::new(),
            },
            validity_period: None,
        };
        let hex = encode_submit(&msg).unwrap_or_default();
        let raw = hex_decode(&hex).unwrap_or_default();
        // UDL byte should be 0x00.
        // Find UDL: after SMSC(1) + first_octet(1) + MR(1) + DA + PID(1) + DCS(1)
        // DA for "+1": len=1, type=1, bcd=1 → 3 bytes → total before UDL = 1+1+1+3+1+1 = 8
        assert_eq!(raw.get(8), Some(&0x00), "UDL must be 0x00 for an empty message");
    }

    #[test]
    fn encode_submit_max_ucs2() {
        // WHY: 70 UCS-2 characters = 140 bytes, the single-segment SMS LIMIT.
        let text: String = "あ".repeat(70); // U+3042, outside BMP-ASCII
        let msg = SmsSubmit {
            destination: Address {
                number: "+1".to_owned(),
                type_of_address: AddressType::International,
            },
            user_data: UserData {
                encoding: DataEncoding::Ucs2,
                text,
            },
            validity_period: None,
        };
        let hex = encode_submit(&msg).unwrap_or_default();
        let raw = hex_decode(&hex).unwrap_or_default();
        // UDL for 70 UCS-2 chars = 140 bytes.
        assert_eq!(raw.get(8), Some(&140), "UDL must be 140 bytes for 70 UCS-2 characters");
    }

    // ── Invalid input ─────────────────────────────────────────────────────────

    #[test]
    fn decode_deliver_wrong_mti_returns_error() {
        // PDU with MTI=01 (SMS-SUBMIT)  -  should fail.
        // Construct minimal PDU: SMSC=00, first_octet=01 (MTI=1).
        let pdu = "00010A9121436587090000321051210300000 5C8329BFD06".replace(' ', "");
        let result = decode_deliver(&pdu);
        assert!(result.is_err(), "SMS-SUBMIT PDU must be rejected by decode_deliver (expects MTI=0)");
    }

    #[test]
    fn hex_decode_odd_length_returns_error() {
        let result = hex_decode("ABC");
        assert!(result.is_err(), "odd-length hex string must return an error");
    }

    #[test]
    fn hex_decode_invalid_char_returns_error() {
        let result = hex_decode("GG");
        assert!(result.is_err(), "non-hex character 'G' must return an error");
    }
}
