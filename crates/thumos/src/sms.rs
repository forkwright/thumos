//! SMS send/receive with PDU encoding (3GPP TS 23.040).
//!
//! Ports GSM-7 character encoding and PDU framing from `klesis/src/gsm7.rs`
//! and `klesis/src/pdu.rs` into the `#![no_std]` kernel context. Provides
//! the [`SmsManager`] for inbox management and AT command-based SMS operations
//! via the telephony subsystem's [`ModemTransport`] trait.
//!
//! ## GSM-7 encoding
//!
//! The GSM 7-bit default alphabet (3GPP TS 23.038 section 6.2.1) maps 128 septets
//! to Unicode code points. Extension-table characters (accessed via ESC prefix
//! 0x1B) consume two septets. The codec handles the full base table plus
//! 10 extension characters including `@` (septet 0x00, common bug site)
//! and `euro` (ESC + 0x65).
//!
//! ## PDU format
//!
//! SMS-SUBMIT PDU (mobile-originated) is built as:
//! - SCA length 0x00 (use modem default)
//! - First octet: MTI=01 (SMS-SUBMIT), VPF=00 (no validity period)
//! - Message reference: 0x00 (modem-assigned)
//! - Destination address: BCD-encoded phone number
//! - PID: 0x00 (normal SMS)
//! - DCS: 0x00 (GSM-7)
//! - UDL + packed GSM-7 user data
//!
//! ## Integration
//!
//! Used by the UI screens (messages, notifications) and the telephony poll loop
//! for handling incoming `+CMT` URCs.

// WHY: SMS API not yet wired to kinit event loop (Wave 4 integration).
#![expect(
    dead_code,
    reason = "SMS API created in Phase 07 Wave 3, kinit wiring pending"
)]

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

use crate::telephony::{AtResponse, ModemTransport, TelephonyError, MAX_LINE_LEN};

// ---------------------------------------------------------------------------
// GSM-7 character tables (ported from klesis/src/gsm7.rs)
// ---------------------------------------------------------------------------

/// GSM default alphabet: 128 septet-to-Unicode mapping.
///
/// Index is the GSM septet value; value is the Unicode character.
/// Septet 0x1B is the extension table escape (represented as `'\x1b'`).
#[rustfmt::skip]
const GSM_TO_UNICODE: [char; 128] = [
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
const EXT_TABLE: &[(u8, char)] = &[
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

/// SMS error types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SmsError {
    /// Character cannot be encoded in GSM-7.
    Gsm7Encode(u32),
    /// PDU data is truncated or malformed.
    PduDecode,
    /// Modem returned an error during send.
    ModemError,
    /// Modem returned a CME error.
    CmeError(u32),
    /// Transport failure.
    TransportError,
    /// Phone number too long.
    NumberTooLong,
    /// Message text too long for single-segment SMS.
    MessageTooLong,
}

impl core::fmt::Display for SmsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Gsm7Encode(cp) => write!(f, "cannot encode U+{cp:04X} in GSM-7"),
            Self::PduDecode => write!(f, "PDU decode error"),
            Self::ModemError => write!(f, "modem error"),
            Self::CmeError(code) => write!(f, "CME error {code}"),
            Self::TransportError => write!(f, "transport error"),
            Self::NumberTooLong => write!(f, "phone number too long"),
            Self::MessageTooLong => write!(f, "message too long"),
        }
    }
}

/// Maximum phone number length (digits) per E.164.
const MAX_NUMBER_DIGITS: usize = 20;

/// Maximum single-segment GSM-7 SMS length in septets.
const MAX_GSM7_SEPTETS: usize = 160;

/// Maximum phone number length stored in `SmsMessage.sender`.
const MAX_SENDER_LEN: usize = 32;

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
pub fn encode_gsm7(text: &str) -> Result<Vec<u8>, SmsError> {
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
pub fn decode_gsm7(data: &[u8], num_septets: usize) -> Result<String, SmsError> {
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
fn count_gsm7_septets(text: &str) -> Result<usize, SmsError> {
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
// BCD address encoding (ported from klesis/src/pdu.rs)
// ---------------------------------------------------------------------------

/// Encode a phone number string into BCD address format for PDU.
///
/// Returns `[length_in_digits, type_byte, bcd_bytes...]`.
/// International numbers (starting with '+') use type 0x91.
fn encode_bcd_address(number: &str) -> Result<Vec<u8>, SmsError> {
    let digits = number.strip_prefix('+').unwrap_or(number);
    let type_byte: u8 = if number.starts_with('+') { 0x91 } else { 0x81 };

    if digits.len() > MAX_NUMBER_DIGITS {
        return Err(SmsError::NumberTooLong);
    }

    let digit_bytes = digits.as_bytes();
    let len_digits = digit_bytes.len();
    let bcd_byte_count = len_digits.div_ceil(2);

    let mut bcd = alloc::vec![0u8; bcd_byte_count];
    for (i, &d) in digit_bytes.iter().enumerate() {
        if !d.is_ascii_digit() {
            return Err(SmsError::PduDecode);
        }
        let nibble = d - b'0';
        let byte_index = i / 2;
        if i % 2 == 0 {
            bcd[byte_index] = nibble; // low nibble
        } else {
            bcd[byte_index] |= nibble << 4; // high nibble
        }
    }
    // Pad odd-length numbers with 0xF in the final high nibble.
    if len_digits % 2 != 0 {
        if let Some(last) = bcd.last_mut() {
            *last |= 0xF0;
        }
    }

    let mut out = Vec::with_capacity(2 + bcd_byte_count);
    // INVARIANT: SMS phone numbers are at most 20 digits (E.164), fits in u8.
    out.push(len_digits as u8);
    out.push(type_byte);
    out.extend_from_slice(&bcd);
    Ok(out)
}

/// Decode a BCD-packed address from raw PDU bytes.
///
/// `len_digits` is the number of significant digits. `type_byte` is the
/// type-of-address octet. `bcd` contains the packed BCD bytes.
fn decode_bcd_address(len_digits: u8, type_byte: u8, bcd: &[u8]) -> String {
    let mut number = String::new();
    if type_byte == 0x91 {
        number.push('+');
    }

    let digit_count = usize::from(len_digits);
    for (idx, &byte) in bcd.iter().enumerate() {
        let lo = byte & 0x0F;
        let hi = (byte >> 4) & 0x0F;

        let lo_digit_index = idx * 2;
        if lo_digit_index < digit_count {
            number.push(char::from(b'0' + lo));
        }
        let hi_digit_index = idx * 2 + 1;
        if hi_digit_index < digit_count && hi != 0x0F {
            number.push(char::from(b'0' + hi));
        }
    }
    number
}

// ---------------------------------------------------------------------------
// Hex codec helpers
// ---------------------------------------------------------------------------

const HEX_CHARS: &[u8; 16] = b"0123456789ABCDEF";

fn hex_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 2);
    for &b in data {
        out.push(char::from(HEX_CHARS[usize::from(b >> 4)]));
        out.push(char::from(HEX_CHARS[usize::from(b & 0x0F)]));
    }
    out
}

const fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn hex_decode(s: &[u8]) -> Result<Vec<u8>, SmsError> {
    if s.len() % 2 != 0 {
        return Err(SmsError::PduDecode);
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for chunk in s.chunks(2) {
        let hi = hex_nibble(chunk[0]).ok_or(SmsError::PduDecode)?;
        let lo = hex_nibble(chunk[1]).ok_or(SmsError::PduDecode)?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// PDU encoding (SMS-SUBMIT)
// ---------------------------------------------------------------------------

/// Build an SMS-SUBMIT PDU for sending via AT+CMGS.
///
/// Returns the hex-encoded PDU string and the TPDU length (bytes after SCA).
fn encode_submit_pdu(number: &str, text: &str) -> Result<(String, usize), SmsError> {
    let septet_count = count_gsm7_septets(text)?;
    if septet_count > MAX_GSM7_SEPTETS {
        return Err(SmsError::MessageTooLong);
    }

    let mut pdu: Vec<u8> = Vec::new();

    // SCA length 0x00: use modem's stored SMSC.
    pdu.push(0x00);

    // First octet: MTI=01 (SMS-SUBMIT), VPF=00 (no validity period).
    pdu.push(0x01);

    // Message reference: 0x00 (modem-assigned).
    pdu.push(0x00);

    // Destination address (BCD-encoded).
    pdu.extend_from_slice(&encode_bcd_address(number)?);

    // PID: 0x00 (normal SMS).
    pdu.push(0x00);

    // DCS: 0x00 (GSM-7 default alphabet).
    pdu.push(0x00);

    // UDL: number of septets.
    // INVARIANT: septet_count <= 160, always fits in u8.
    pdu.push(septet_count as u8);

    // User data: packed GSM-7 bytes.
    let packed = encode_gsm7(text)?;
    pdu.extend_from_slice(&packed);

    // TPDU length = total PDU bytes minus the SCA byte.
    let tpdu_len = pdu.len() - 1;

    Ok((hex_encode(&pdu), tpdu_len))
}

// ---------------------------------------------------------------------------
// PDU decoding (SMS-DELIVER, for incoming +CMT)
// ---------------------------------------------------------------------------

/// Simple cursor for reading PDU bytes.
struct PduCursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> PduCursor<'a> {
    const fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn read_byte(&mut self) -> Result<u8, SmsError> {
        let b = *self.data.get(self.pos).ok_or(SmsError::PduDecode)?;
        self.pos += 1;
        Ok(b)
    }

    fn read_slice(&mut self, len: usize) -> Result<&'a [u8], SmsError> {
        let end = self.pos + len;
        let slice = self.data.get(self.pos..end).ok_or(SmsError::PduDecode)?;
        self.pos = end;
        Ok(slice)
    }
}

// ---------------------------------------------------------------------------
// SMS message types
// ---------------------------------------------------------------------------

/// An SMS message stored in the inbox.
pub struct SmsMessage {
    /// Sender phone number as ASCII bytes.
    pub sender: [u8; MAX_SENDER_LEN],
    /// Number of valid bytes in `sender`.
    pub sender_len: u8,
    /// Decoded message body (UTF-8).
    pub body: String,
    /// Timestamp in Unix epoch seconds (0 = unknown).
    pub timestamp: u64,
    /// Whether this message has been read.
    pub read: bool,
}

// ---------------------------------------------------------------------------
// SMS manager
// ---------------------------------------------------------------------------

/// SMS manager: inbox storage and send/receive operations.
pub struct SmsManager {
    /// Inbox of received messages, newest last.
    inbox: Vec<SmsMessage>,
}

impl SmsManager {
    /// Create a new SMS manager with an empty inbox.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inbox: Vec::new(),
        }
    }

    /// Send an SMS message via the modem.
    ///
    /// Encodes the text as GSM-7 PDU and sends via `AT+CMGS`. The modem
    /// must be in PDU mode (`AT+CMGF=0`) before calling this.
    pub fn send<T: ModemTransport>(
        transport: &mut T,
        number: &str,
        text: &str,
    ) -> Result<(), SmsError> {
        let (pdu_hex, tpdu_len) = encode_submit_pdu(number, text)?;

        // Set PDU mode.
        transport.send_at("AT+CMGF=0").map_err(|_| SmsError::TransportError)?;
        let mut line_buf = [0u8; MAX_LINE_LEN];
        // Drain response lines until OK/ERROR.
        for _ in 0..16 {
            let n = transport
                .recv_line(&mut line_buf, 2000)
                .map_err(|_| SmsError::TransportError)?;
            let line = &line_buf[..n];
            if let Some(result) = crate::telephony::parse_final_result(line) {
                match result {
                    AtResponse::Ok => break,
                    AtResponse::Error => return Err(SmsError::ModemError),
                    AtResponse::CmeError(code) => return Err(SmsError::CmeError(code)),
                }
            }
        }

        // Send AT+CMGS=<tpdu_len> followed by the PDU.
        let mut cmd_buf = [0u8; 32];
        let cmd_len = write_cmgs_command(&mut cmd_buf, tpdu_len);
        let cmd_str = core::str::from_utf8(&cmd_buf[..cmd_len])
            .map_err(|_| SmsError::TransportError)?;

        transport.send_at(cmd_str).map_err(|_| SmsError::TransportError)?;

        // Wait for the '>' prompt, then send PDU + Ctrl-Z.
        for _ in 0..16 {
            let n = transport
                .recv_line(&mut line_buf, 5000)
                .map_err(|_| SmsError::TransportError)?;
            let line = &line_buf[..n];
            if !line.is_empty() && line[0] == b'>' {
                break;
            }
        }

        // Send the PDU hex followed by Ctrl-Z (0x1A).
        let mut pdu_with_ctrl_z = pdu_hex;
        pdu_with_ctrl_z.push('\x1A');
        transport
            .send_at(&pdu_with_ctrl_z)
            .map_err(|_| SmsError::TransportError)?;

        // Wait for final result.
        for _ in 0..32 {
            let n = transport
                .recv_line(&mut line_buf, 10_000)
                .map_err(|_| SmsError::TransportError)?;
            let line = &line_buf[..n];
            if let Some(result) = crate::telephony::parse_final_result(line) {
                return match result {
                    AtResponse::Ok => Ok(()),
                    AtResponse::Error => Err(SmsError::ModemError),
                    AtResponse::CmeError(code) => Err(SmsError::CmeError(code)),
                };
            }
        }

        Err(SmsError::TransportError)
    }

    /// Handle an incoming SMS PDU from a +CMT URC.
    ///
    /// `pdu_data` is the raw hex bytes of the PDU (not hex-encoded string,
    /// but the actual PDU bytes after hex decoding by the caller).
    pub fn handle_incoming(pdu_data: &[u8]) -> Result<SmsMessage, SmsError> {
        let mut cur = PduCursor::new(pdu_data);

        // SMSC prefix: length byte + SMSC bytes (skip).
        let smsc_len = usize::from(cur.read_byte()?);
        cur.read_slice(smsc_len)?;

        // First octet of TPDU.
        let first_octet = cur.read_byte()?;
        let mti = first_octet & 0x03;
        if mti != 0x00 {
            return Err(SmsError::PduDecode);
        }

        // Originating address.
        let oa_len_digits = cur.read_byte()?;
        let oa_type = cur.read_byte()?;
        let oa_bcd_bytes = usize::from(oa_len_digits.div_ceil(2));
        let oa_bcd = cur.read_slice(oa_bcd_bytes)?;
        let sender_str = decode_bcd_address(oa_len_digits, oa_type, oa_bcd);

        // Build sender field.
        let mut sender = [0u8; MAX_SENDER_LEN];
        let sender_bytes = sender_str.as_bytes();
        let sender_len = sender_bytes.len().min(MAX_SENDER_LEN);
        sender[..sender_len].copy_from_slice(&sender_bytes[..sender_len]);

        // PID (ignored).
        cur.read_byte()?;

        // DCS: only GSM-7 (0x00) supported in this kernel build.
        let dcs = cur.read_byte()?;
        let class_bits = (dcs >> 2) & 0x03;
        if class_bits != 0x00 {
            return Err(SmsError::PduDecode);
        }

        // SCTS: 7 bytes (timestamp, partially decoded).
        let scts = cur.read_slice(7)?;
        let timestamp = decode_scts_epoch(scts);

        // User data length (septets) and packed user data.
        let udl = usize::from(cur.read_byte()?);
        let ud_byte_count = udl.saturating_mul(7).div_ceil(8);
        let ud_bytes = cur.read_slice(ud_byte_count)?;
        let body = decode_gsm7(ud_bytes, udl)?;

        Ok(SmsMessage {
            sender,
            sender_len: sender_len as u8,
            body,
            timestamp,
            read: false,
        })
    }

    /// Return the inbox as a slice.
    #[must_use]
    pub fn inbox(&self) -> &[SmsMessage] {
        &self.inbox
    }

    /// Mark a message as read by index.
    ///
    /// No-op if the index is out of bounds.
    pub fn mark_read(&mut self, index: usize) {
        if let Some(msg) = self.inbox.get_mut(index) {
            msg.read = true;
        }
    }

    /// Delete a message by index.
    ///
    /// No-op if the index is out of bounds.
    pub fn delete(&mut self, index: usize) {
        if index < self.inbox.len() {
            self.inbox.remove(index);
        }
    }

    /// Add a message to the inbox (used by `handle_incoming`).
    pub fn receive(&mut self, msg: SmsMessage) {
        self.inbox.push(msg);
    }
}

// ---------------------------------------------------------------------------
// AT+CMGS command builder
// ---------------------------------------------------------------------------

/// Write `AT+CMGS=<len>` into the buffer, returning the number of bytes written.
fn write_cmgs_command(buf: &mut [u8; 32], tpdu_len: usize) -> usize {
    // Format: "AT+CMGS=NNN"
    let prefix = b"AT+CMGS=";
    buf[..prefix.len()].copy_from_slice(prefix);
    let mut pos = prefix.len();

    // Write decimal digits of tpdu_len.
    let mut digits = [0u8; 5];
    let mut n = tpdu_len;
    let mut digit_count = 0;

    if n == 0 {
        digits[0] = b'0';
        digit_count = 1;
    } else {
        while n > 0 {
            digits[digit_count] = b'0' + (n % 10) as u8;
            digit_count += 1;
            n /= 10;
        }
    }

    // Reverse digits into buffer.
    for i in 0..digit_count {
        buf[pos] = digits[digit_count - 1 - i];
        pos += 1;
    }

    pos
}

// ---------------------------------------------------------------------------
// SCTS timestamp helper
// ---------------------------------------------------------------------------

/// Decode a 7-byte SCTS field into a rough Unix epoch timestamp.
///
/// Each byte contains two BCD digits packed low-nibble-first.
/// Returns 0 if the timestamp cannot be decoded.
fn decode_scts_epoch(scts: &[u8]) -> u64 {
    if scts.len() < 7 {
        return 0;
    }

    let lo = |b: u8| b & 0x0F;
    let hi = |b: u8| (b >> 4) & 0x0F;
    let pair = |b: u8| u64::from(lo(b) * 10 + hi(b));

    let year = 2000 + pair(scts[0]);
    let month = pair(scts[1]);
    let day = pair(scts[2]);
    let hour = pair(scts[3]);
    let minute = pair(scts[4]);
    let second = pair(scts[5]);

    // Simplified epoch calculation (no leap second precision needed).
    // Days from 1970-01-01 to the given date, approximate.
    let days = days_from_epoch(year, month, day);
    days * 86400 + hour * 3600 + minute * 60 + second
}

/// Approximate days from Unix epoch (1970-01-01) to a given date.
///
/// Not astronomically precise but sufficient for SMS timestamp display.
fn days_from_epoch(year: u64, month: u64, day: u64) -> u64 {
    // Use a simplified Gregorian day count.
    let y = if month <= 2 { year - 1 } else { year };
    let m = if month <= 2 { month + 9 } else { month - 3 };
    let c = y / 100;
    let ya = y - c * 100;

    // Days from year 0 to the date (shifted March-based calendar).
    let total = (146_097 * c) / 4 + (1461 * ya) / 4 + (153 * m + 2) / 5 + day;
    // Subtract days from epoch 0 to 1970-01-01.
    total.saturating_sub(719_469)
}

// ---------------------------------------------------------------------------
// Byte-level parsing helpers
// ---------------------------------------------------------------------------

/// Strip a prefix from a byte slice.
fn strip_prefix<'a>(input: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    if input.len() >= prefix.len() && &input[..prefix.len()] == prefix {
        Some(&input[prefix.len()..])
    } else {
        None
    }
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
    fn pdu_encode_produces_valid_bytes() {
        let (pdu_hex, tpdu_len) = encode_submit_pdu("+1234567890", "Hi").unwrap_or_default();
        // Must be non-empty hex string.
        assert!(!pdu_hex.is_empty(), "PDU hex must be non-empty");
        // TPDU length must be > 0 (SCA excluded).
        assert!(tpdu_len > 0, "TPDU length must be positive");
        // First two hex chars represent SCA length (0x00).
        assert!(
            pdu_hex.starts_with("00"),
            "PDU must start with SCA length 0x00"
        );
        // Verify it's valid hex by decoding.
        let raw = hex_decode(pdu_hex.as_bytes());
        assert!(raw.is_ok(), "PDU hex must be valid hex");
    }

    #[test]
    fn handle_incoming_parses_pdu() {
        // Build a minimal SMS-DELIVER PDU:
        //   00            - SMSC len 0
        //   00            - first octet: MTI=0 (SMS-DELIVER)
        //   0A            - OA length: 10 digits
        //   91            - OA type: international
        //   21 43 65 87 09 - BCD: +1234567890
        //   00            - PID
        //   00            - DCS: GSM-7
        //   32 10 51 21 03 00 00 - SCTS
        //   05            - UDL: 5 septets
        //   C8 32 9B FD 06 - "Hello" packed
        let pdu_bytes: &[u8] = &[
            0x00, // SCA len
            0x00, // first octet (MTI=0)
            0x0A, // OA len (10 digits)
            0x91, // OA type (international)
            0x21, 0x43, 0x65, 0x87, 0x09, // BCD +1234567890
            0x00, // PID
            0x00, // DCS (GSM-7)
            0x32, 0x10, 0x51, 0x21, 0x03, 0x00, 0x00, // SCTS
            0x05, // UDL (5 septets)
            0xC8, 0x32, 0x9B, 0xFD, 0x06, // "Hello" packed
        ];

        let msg = SmsManager::handle_incoming(pdu_bytes);
        assert!(msg.is_ok(), "must parse valid SMS-DELIVER PDU");
        let msg = msg.unwrap_or_else(|_| SmsMessage {
            sender: [0u8; MAX_SENDER_LEN],
            sender_len: 0,
            body: String::new(),
            timestamp: 0,
            read: false,
        });
        let sender = core::str::from_utf8(&msg.sender[..msg.sender_len as usize])
            .unwrap_or("");
        assert_eq!(sender, "+1234567890", "sender must decode to +1234567890");
        assert_eq!(msg.body, "Hello", "body must decode to 'Hello'");
        assert!(!msg.read, "incoming message must be unread");
    }

    #[test]
    fn inbox_starts_empty() {
        let manager = SmsManager::new();
        assert!(
            manager.inbox().is_empty(),
            "new SMS manager must have empty inbox"
        );
    }

    #[test]
    fn mark_read_updates_flag() {
        let mut manager = SmsManager::new();
        manager.receive(SmsMessage {
            sender: [0u8; MAX_SENDER_LEN],
            sender_len: 0,
            body: String::from("test"),
            timestamp: 0,
            read: false,
        });
        assert!(!manager.inbox()[0].read, "message must start unread");
        manager.mark_read(0);
        assert!(manager.inbox()[0].read, "message must be read after mark_read");
    }

    #[test]
    fn delete_removes_message() {
        let mut manager = SmsManager::new();
        manager.receive(SmsMessage {
            sender: [0u8; MAX_SENDER_LEN],
            sender_len: 0,
            body: String::from("msg1"),
            timestamp: 0,
            read: false,
        });
        manager.receive(SmsMessage {
            sender: [0u8; MAX_SENDER_LEN],
            sender_len: 0,
            body: String::from("msg2"),
            timestamp: 0,
            read: false,
        });
        assert_eq!(manager.inbox().len(), 2);
        manager.delete(0);
        assert_eq!(manager.inbox().len(), 1);
        assert_eq!(manager.inbox()[0].body, "msg2", "remaining message must be msg2");
    }

    #[test]
    fn encode_bcd_address_international() {
        let bcd = encode_bcd_address("+1234567890");
        assert!(bcd.is_ok(), "must encode international number");
        let bcd = bcd.unwrap_or_default();
        assert_eq!(bcd[0], 10, "digit count must be 10");
        assert_eq!(bcd[1], 0x91, "type must be international (0x91)");
    }

    #[test]
    fn decode_bcd_address_round_trips() {
        let bcd = encode_bcd_address("+15551234567");
        assert!(bcd.is_ok());
        let bcd = bcd.unwrap_or_default();
        let decoded = decode_bcd_address(bcd[0], bcd[1], &bcd[2..]);
        assert_eq!(decoded, "+15551234567", "BCD round-trip must preserve number");
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

    #[test]
    fn mark_read_out_of_bounds_is_noop() {
        let mut manager = SmsManager::new();
        // Must not panic.
        manager.mark_read(999);
        assert!(manager.inbox().is_empty());
    }

    #[test]
    fn delete_out_of_bounds_is_noop() {
        let mut manager = SmsManager::new();
        // Must not panic.
        manager.delete(999);
        assert!(manager.inbox().is_empty());
    }
}
