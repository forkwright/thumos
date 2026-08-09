#![no_std]
//! klesis-core: the canonical GSM-7 and SMS-PDU semantics (#545, #662).
//!
//! This crate is the single home of the GSM 7-bit alphabet codec, the PDU
//! byte primitives (hex, BCD address, cursor), and the surveillance
//! classification of an incoming message — silent SMS by PID, and WAP
//! Push by UDH application port. It is shared by the `klesis` workspace
//! crate (telephony daemon) and the thumos kernel (`sms.rs`, the SMS path
//! actually reached from a `+CMT` URC on the device).
//!
//! It exists because the two sides were independent hand-ports and had
//! already diverged in both directions (#662):
//!
//! - the kernel read the PID and discarded it (`// PID (ignored).`), so a
//!   silent SMS — the standard covert location-ping, specified as neither
//!   displayed nor stored — was filed to the inbox as an ordinary message,
//!   while `klesis` rejected it. The detection existed only in the layer
//!   that never runs on the phone.
//! - the kernel accepted GSM-7 data ending in a dangling ESC septet and
//!   returned the truncated text; `klesis` rejected it. The same modem
//!   bytes produced a message on one side and an error on the other.
//!
//! Neither drift could be caught, because nothing tested the two against
//! each other. One codec, one classification.
//!
//! `no_std` + alloc so the bare-metal kernel can link it via a path
//! dependency; nothing here performs I/O, and nothing here decides policy
//! — a caller is told *what a message is* and chooses what to do about it.
//! That split is deliberate: `klesis` drops a silent SMS, while the kernel
//! must keep and surface it, because an alert the user never sees is
//! indistinguishable from no detection at all.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// A failure decoding or encoding SMS wire data.
///
/// Deliberately `Copy` and allocation-free: every variant carries only the
/// position or value needed to locate the fault, so the kernel can surface
/// one without a heap allocation on an error path fed by a hostile modem.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CoreError {
    /// A character has no GSM-7 representation.
    Gsm7Encode {
        /// Unicode scalar value that could not be encoded.
        codepoint: u32,
    },
    /// Packed GSM-7 data ran out before the declared septet count.
    Gsm7Truncated {
        /// Septet index at which the data ended.
        septet: usize,
    },
    /// GSM-7 data ends with an ESC that has no following extension code.
    Gsm7DanglingEscape,
    /// A BCD nibble was not a decimal digit (and not the 0xF filler).
    BcdInvalidDigit {
        /// The offending nibble.
        nibble: u8,
    },
    /// An address exceeded the maximum digit count.
    AddressTooLong {
        /// Digit count supplied.
        digits: usize,
    },
    /// A hex string had odd length or a non-hex character.
    HexInvalid {
        /// Byte offset of the fault.
        offset: usize,
    },
    /// A read ran past the end of the buffer.
    Truncated {
        /// Byte offset at which the read was attempted.
        offset: usize,
    },
}

/// Result alias for this crate.
pub type Result<T> = core::result::Result<T, CoreError>;

// ---------------------------------------------------------------------------
// GSM-7 character tables (3GPP TS 23.038 § 6.2.1)
// ---------------------------------------------------------------------------

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
#[expect(
    clippy::as_conversions,
    reason = "septet is masked to 7 bits (0x7F), so the value is always 0-127 and fits u8"
)]
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

// ---------------------------------------------------------------------------
// Hex primitives
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// BCD address primitives (3GPP TS 23.040 § 9.1.2.5)
// ---------------------------------------------------------------------------

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

    let mut digits: Vec<u8> = Vec::with_capacity(digits_str.len());
    for b in digits_str.bytes() {
        if !b.is_ascii_digit() {
            return Err(CoreError::BcdInvalidDigit { nibble: b });
        }
        digits.push(b - b'0');
    }
    if digits.len() > MAX_ADDRESS_DIGITS {
        return Err(CoreError::AddressTooLong {
            digits: digits.len(),
        });
    }

    let mut packed = Vec::with_capacity(digits.len().div_ceil(2));
    for pair in digits.chunks(2) {
        let lo = pair.first().copied().unwrap_or(BCD_FILLER);
        let hi = pair.get(1).copied().unwrap_or(BCD_FILLER);
        packed.push((hi << 4) | lo);
    }
    Ok((toa, packed))
}

// ---------------------------------------------------------------------------
// PDU cursor
// ---------------------------------------------------------------------------

/// A bounds-checked forward reader over PDU bytes.
///
/// Every read is fallible: the underlying bytes come from the modem, so a
/// truncated PDU must surface as an error rather than an index panic.
#[derive(Debug)]
pub struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    /// Start a cursor at the beginning of `data`.
    #[must_use]
    pub const fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// Current byte offset.
    #[must_use]
    pub const fn pos(&self) -> usize {
        self.pos
    }

    /// The bytes not yet consumed.
    #[must_use]
    pub fn remaining(&self) -> &'a [u8] {
        self.data.get(self.pos..).unwrap_or(&[])
    }

    /// Read one byte and advance.
    ///
    /// # Errors
    ///
    /// [`CoreError::Truncated`] at end of input.
    pub fn read_byte(&mut self) -> Result<u8> {
        let b = self
            .data
            .get(self.pos)
            .copied()
            .ok_or(CoreError::Truncated { offset: self.pos })?;
        self.pos += 1;
        Ok(b)
    }

    /// Read `n` bytes and advance.
    ///
    /// # Errors
    ///
    /// [`CoreError::Truncated`] when fewer than `n` bytes remain.
    pub fn read_slice(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(CoreError::Truncated { offset: self.pos })?;
        let s = self
            .data
            .get(self.pos..end)
            .ok_or(CoreError::Truncated { offset: self.pos })?;
        self.pos = end;
        Ok(s)
    }
}

// ---------------------------------------------------------------------------
// Surveillance classification
// ---------------------------------------------------------------------------

/// PID for Type 0 SMS: no display, no storage (3GPP TS 23.040 § 9.2.3.9).
pub const PID_TYPE_0_SMS: u8 = 0x40;

/// Exclusive upper bound of the SIM-toolkit replace-short-message PID range
/// (`0x41`-`0x47`).
pub const PID_SIM_TOOLKIT_UPPER: u8 = 0x48;

/// OMA-CP WAP Push destination port (3GPP TS 23.040 / OMA WAP-259).
pub const WAP_PUSH_PORT_OMA_CP: u16 = 2948;

/// Alternative WAP Push destination port used by some implementations.
pub const WAP_PUSH_PORT_ALT: u16 = 49999;

/// UDH Information Element Identifier for 16-bit application port
/// addressing (3GPP TS 23.040 § 9.2.3.24.4).
pub const UDH_IEI_APP_PORT_16BIT: u8 = 0x05;

/// Bit 6 of the first TPDU octet: User Data Header Indicator.
pub const UDHI_BIT: u8 = 0x40;

/// Maximum accepted hex length for a single SMS-DELIVER PDU.
///
/// SECURITY: the hex string originates from modem-controlled storage and is
/// otherwise unbounded. A single SMS-DELIVER TPDU stays well under 200
/// octets; this cap is generous headroom against a malfunctioning or
/// hostile modem flooding the decoder.
pub const MAX_PDU_HEX_LEN: usize = 1024;

/// A parsed UDH application-port addressing element.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdhPorts {
    /// Destination port from the UDH IE.
    pub destination: u16,
    /// Source port from the UDH IE.
    pub source: u16,
}

/// What an incoming message is, beyond its text.
///
/// Returned rather than acted upon: `klesis` rejects a flagged message,
/// while the kernel keeps and marks it. Encoding that choice here would
/// force one of those two to be wrong.
/// WHY deliberately NOT `#[non_exhaustive]`: a downstream `_` arm would map
/// any future covert class to "ordinary message", which is fail-open on the
/// exact axis this type exists to guard. Adding a variant must break every
/// consumer that classifies, so each one decides what the new class means.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MessageClass {
    /// An ordinary user-visible message.
    #[default]
    Normal,
    /// A silent / Type 0 message: specified as neither displayed nor
    /// stored, and the standard covert location-ping.
    Silent {
        /// The PID that triggered the classification.
        pid: u8,
    },
    /// A WAP Push / OMA-CP message, the usual carrier for silent
    /// provisioning changes.
    WapPush {
        /// UDH destination port.
        destination_port: u16,
        /// UDH source port.
        source_port: u16,
    },
}

impl MessageClass {
    /// Whether this classification describes a surveillance-relevant
    /// message that the user would otherwise never see.
    #[must_use]
    pub const fn is_covert(self) -> bool {
        !matches!(self, Self::Normal)
    }
}

/// Whether a PID marks a silent / surveillance message.
///
/// Covers `0x40` (Type 0) through `0x47` (SIM-toolkit replace types).
#[must_use]
pub const fn is_silent_sms_pid(pid: u8) -> bool {
    pid >= PID_TYPE_0_SMS && pid < PID_SIM_TOOLKIT_UPPER
}

/// Whether a UDH destination port marks a WAP Push / OMA-CP message.
#[must_use]
pub const fn is_wap_push_port(port: u16) -> bool {
    port == WAP_PUSH_PORT_OMA_CP || port == WAP_PUSH_PORT_ALT
}

/// Whether the first TPDU octet has the User Data Header Indicator set.
#[must_use]
pub const fn has_udh(first_octet: u8) -> bool {
    first_octet & UDHI_BIT != 0
}

/// Parse a User Data Header from the start of the user-data bytes.
///
/// Scans information elements for 16-bit application port addressing
/// (IEI `0x05`), returning the port pair when present.
#[must_use]
pub fn parse_udh_ports(ud_bytes: &[u8]) -> Option<UdhPorts> {
    let udhl = usize::from(*ud_bytes.first()?);
    // UDH content starts at byte 1 and runs for `udhl` bytes.
    if ud_bytes.len() < udhl + 1 {
        return None;
    }
    let udh = ud_bytes.get(1..=udhl)?;

    let mut pos = 0;
    while pos < udh.len() {
        let iei = *udh.get(pos)?;
        let ie_len = usize::from(*udh.get(pos + 1)?);
        let ie_data_start = pos + 2;
        let ie_data_end = ie_data_start + ie_len;
        if ie_data_end > udh.len() {
            break;
        }
        if iei == UDH_IEI_APP_PORT_16BIT && ie_len == 4 {
            let dest_hi = *udh.get(ie_data_start)?;
            let dest_lo = *udh.get(ie_data_start + 1)?;
            let src_hi = *udh.get(ie_data_start + 2)?;
            let src_lo = *udh.get(ie_data_start + 3)?;
            return Some(UdhPorts {
                destination: u16::from_be_bytes([dest_hi, dest_lo]),
                source: u16::from_be_bytes([src_hi, src_lo]),
            });
        }
        pos = ie_data_end;
    }
    None
}

/// Total octets the UDH occupies, including its own length byte.
///
/// Returns 0 when `ud_bytes` is empty. The result is clamped to the buffer
/// so a hostile UDHL cannot push a later slice past the end.
#[must_use]
pub fn udh_octet_len(ud_bytes: &[u8]) -> usize {
    let udhl = usize::from(ud_bytes.first().copied().unwrap_or(0));
    (udhl + 1).min(ud_bytes.len())
}

/// Septets consumed by `udh_octets` raw UDH bytes once folded into the
/// septet stream.
///
/// 3GPP TS 23.040 § 9.2.3.24: the UDH is stored as whole octets, and fill
/// bits pad it to the next septet boundary before the text begins.
#[must_use]
pub const fn gsm7_udh_septets(udh_octets: usize) -> usize {
    (udh_octets * 8).div_ceil(7)
}

/// Classify an incoming SMS-DELIVER from its PID and user-data bytes.
///
/// `first_octet` is the first TPDU octet (for the UDHI bit), `pid` the
/// protocol identifier, and `ud_bytes` the raw user data — the UDH, when
/// present, is at its head.
///
/// A silent PID takes precedence over a WAP Push port: both describe a
/// message the user never sees, and the PID is the stronger signal because
/// it is what makes the message invisible in the first place.
#[must_use]
pub fn classify(first_octet: u8, pid: u8, ud_bytes: &[u8]) -> MessageClass {
    if is_silent_sms_pid(pid) {
        return MessageClass::Silent { pid };
    }
    if has_udh(first_octet)
        && let Some(ports) = parse_udh_ports(ud_bytes)
        && is_wap_push_port(ports.destination)
    {
        return MessageClass::WapPush {
            destination_port: ports.destination,
            source_port: ports.source,
        };
    }
    MessageClass::Normal
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn ok<T>(r: Result<T>) -> T {
        match r {
            Ok(v) => v,
            Err(e) => unreachable!("expected Ok, got {e:?}"),
        }
    }

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

    #[test]
    fn decode_from_reads_text_at_a_septet_offset_not_an_octet_one() {
        // A real UDH-bearing user-data field: 6 header octets, then "Hello".
        // 6 octets = 48 bits; ceil(48/7) = 7 septets = 49 bits, so one fill
        // bit separates them and the text starts at BIT 49.
        let ud = [
            0x05, 0x00, 0x03, 0xAB, 0x02, 0x01, // UDH
            0x90, 0x65, 0x36, 0xFB, 0x0D, // "Hello" from bit 49
        ];
        let udh_septets = gsm7_udh_septets(udh_octet_len(&ud));
        assert_eq!(udh_septets, 7, "6 header octets fold into 7 septets");

        assert_eq!(
            ok(decode_from(&ud, udh_septets, 5)),
            "Hello",
            "text must be read from the septet boundary after the header"
        );

        // The bug this replaced: skipping the header by OCTET and decoding
        // from bit 0 of the remainder. It is off by the single fill bit and
        // produces confident garbage rather than an error, which is why it
        // survived in both the kernel and klesis.
        assert_eq!(
            ok(decode(&ud[6..], 5)),
            "\u{394}KYY\u{a7}",
            "slicing at the octet boundary must be demonstrably wrong -- if \
             this ever equals \"Hello\", the fixture stopped exercising the \
             misalignment and the test above proves nothing"
        );
    }

    #[test]
    fn gsm7_udh_septets_matches_the_spec_rounding() {
        // ceil(octets * 8 / 7). The two boundaries coincide only when the
        // octet count is a multiple of 7 -- which is why the 7-octet WAP
        // Push header looked correct while the 6-octet concatenation
        // header did not.
        assert_eq!(gsm7_udh_septets(6), 7, "6 octets (48 bits) -> 7 septets");
        assert_eq!(
            gsm7_udh_septets(7),
            8,
            "7 octets (56 bits) -> 8 septets exactly, no fill bits"
        );
        assert_eq!(gsm7_udh_septets(0), 0);
    }

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
    fn cursor_reads_are_bounds_checked() {
        let mut cur = Cursor::new(&[0x01, 0x02]);
        assert_eq!(ok(cur.read_byte()), 0x01);
        assert_eq!(ok(cur.read_slice(1)), &[0x02]);
        assert!(
            cur.read_byte().is_err(),
            "reading past the end must error, not panic"
        );
    }

    #[test]
    fn silent_pid_range_matches_spec() {
        assert!(is_silent_sms_pid(0x40), "PID 0x40 is Type 0 SMS");
        assert!(is_silent_sms_pid(0x41), "PID 0x41 is a replace type");
        assert!(is_silent_sms_pid(0x47), "PID 0x47 is a replace type");
        assert!(!is_silent_sms_pid(0x48), "PID 0x48 is outside the range");
        assert!(!is_silent_sms_pid(0x00), "PID 0x00 is an ordinary message");
        assert!(!is_silent_sms_pid(0x3F), "PID 0x3F is below the range");
    }

    #[test]
    fn wap_push_ports_match_spec() {
        assert!(is_wap_push_port(WAP_PUSH_PORT_OMA_CP));
        assert!(is_wap_push_port(WAP_PUSH_PORT_ALT));
        assert!(!is_wap_push_port(80), "port 80 is not WAP Push");
    }

    #[test]
    fn udh_ports_parse_from_port_ie() {
        // UDHL=6, IEI=0x05, len=4, dest=2948 (0x0B84), src=0 (0x0000).
        let ud = [0x06, 0x05, 0x04, 0x0B, 0x84, 0x00, 0x00];
        let ports = parse_udh_ports(&ud);
        assert_eq!(
            ports,
            Some(UdhPorts {
                destination: 2948,
                source: 0
            })
        );
    }

    #[test]
    fn udh_ports_absent_when_no_port_ie() {
        // UDHL=5, IEI=0x00 (concatenation), len=3.
        let ud = [0x05, 0x00, 0x03, 0x01, 0x02, 0x03];
        assert_eq!(
            parse_udh_ports(&ud),
            None,
            "a concatenation IE carries no ports"
        );
        assert_eq!(parse_udh_ports(&[]), None, "empty user data has no UDH");
    }

    #[test]
    fn udh_length_is_clamped_to_the_buffer() {
        // A hostile UDHL claiming 200 octets in a 3-byte buffer.
        assert_eq!(
            udh_octet_len(&[200, 0x01, 0x02]),
            3,
            "an over-long UDHL must clamp, so no later slice runs past the end"
        );
    }

    #[test]
    fn classify_flags_silent_sms() {
        assert_eq!(
            classify(0x00, PID_TYPE_0_SMS, &[]),
            MessageClass::Silent {
                pid: PID_TYPE_0_SMS
            },
            "a Type 0 PID must classify as silent"
        );
    }

    #[test]
    fn classify_flags_wap_push_only_when_udhi_set() {
        let ud = [0x06, 0x05, 0x04, 0x0B, 0x84, 0x00, 0x00];
        assert_eq!(
            classify(UDHI_BIT, 0x00, &ud),
            MessageClass::WapPush {
                destination_port: 2948,
                source_port: 0
            },
            "UDHI set plus an OMA-CP port must classify as WAP Push"
        );
        // WHY: without the UDHI bit those same bytes are ordinary message
        // text that merely happens to look like a header. Classifying on
        // content alone would let any sender forge the flag by typing it.
        assert_eq!(
            classify(0x00, 0x00, &ud),
            MessageClass::Normal,
            "identical bytes without UDHI are message text, not a header"
        );
    }

    #[test]
    fn classify_prefers_silent_over_wap_push() {
        let ud = [0x06, 0x05, 0x04, 0x0B, 0x84, 0x00, 0x00];
        assert_eq!(
            classify(UDHI_BIT, PID_TYPE_0_SMS, &ud),
            MessageClass::Silent {
                pid: PID_TYPE_0_SMS
            },
            "the silent PID is the stronger signal and must win"
        );
    }

    #[test]
    fn normal_message_is_not_covert() {
        assert!(!MessageClass::Normal.is_covert());
        assert!(MessageClass::Silent { pid: 0x40 }.is_covert());
        assert!(
            MessageClass::WapPush {
                destination_port: 2948,
                source_port: 0
            }
            .is_covert()
        );
    }
}
