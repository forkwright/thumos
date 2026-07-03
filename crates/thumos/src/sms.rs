//! SMS send/receive with PDU encoding (3GPP TS 23.040).
//!
//! Ports GSM-7 character encoding and PDU framing from `klesis/src/gsm7.rs`
//! and `klesis/src/pdu.rs` into the `#![no_std]` kernel context. Provides
//! the [`SmsManager`] for inbox management and AT command-based SMS operations
//! via the telephony subsystem's [`ModemTransport`] trait.
//!
//! ## Module structure
//!
//! GSM-7 codec (encode/decode, character tables) is in [`crate::gsm7`].
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

use crate::telephony::{AtResponse, MAX_LINE_LEN, ModemTransport, TelephonyError};

// Re-export GSM-7 codec so callers can still use crate::sms::*.
pub(crate) use crate::gsm7::*;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// SMS error types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SmsError {
    /// Character cannot be encoded in GSM-7.
    Gsm7Encode(u32),
    /// PDU data is truncated or malformed.
    PduDecode,
    /// The PDU is well-formed but uses an unsupported data coding scheme
    /// (DCS); only GSM-7 (0x00) is supported. Carries the offending DCS
    /// byte. Distinct from [`Self::PduDecode`] -- the bytes decoded fine,
    /// the encoding is simply not implemented.
    UnsupportedDcs(u8),
    /// Modem returned an error during send.
    ModemError,
    /// Modem returned a CME error.
    CmeError(u32),
    /// Modem returned a CMS error (SMS-specific, 3GPP TS 27.005).
    CmsError(u32),
    /// Transport failure.
    TransportError,
    /// Phone number too long.
    NumberTooLong,
    /// Message text too long for single-segment SMS.
    MessageTooLong,
    /// The inbox was already at capacity ([`MAX_INBOX_MESSAGES`]); the
    /// oldest buffered message was dropped to make room for the new
    /// one, which is still enqueued.
    InboxOverflow,
}

impl core::fmt::Display for SmsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Gsm7Encode(cp) => write!(f, "cannot encode U+{cp:04X} in GSM-7"),
            Self::PduDecode => write!(f, "PDU decode error"),
            Self::UnsupportedDcs(dcs) => write!(f, "unsupported DCS {dcs:#04x}"),
            Self::ModemError => write!(f, "modem error"),
            Self::CmeError(code) => write!(f, "CME error {code}"),
            Self::CmsError(code) => write!(f, "CMS error {code}"),
            Self::TransportError => write!(f, "transport error"),
            Self::NumberTooLong => write!(f, "phone number too long"),
            Self::MessageTooLong => write!(f, "message too long"),
            Self::InboxOverflow => write!(f, "inbox overflow, oldest message dropped"),
        }
    }
}

/// Maximum phone number length (digits) per E.164.
const MAX_NUMBER_DIGITS: usize = 20;

/// Maximum single-segment GSM-7 SMS length in septets.
const MAX_GSM7_SEPTETS: usize = 160;

/// Maximum phone number length stored in `SmsMessage.sender`.
const MAX_SENDER_LEN: usize = 32;

/// Maximum number of messages retained in the inbox before the oldest
/// is dropped to make room (unbounded SMS flood protection).
const MAX_INBOX_MESSAGES: usize = 256;

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
///
/// # Errors
///
/// Returns [`SmsError::PduDecode`] if any significant nibble is outside
/// `0..=9` -- a network-supplied PDU that claims a BCD digit of 0xA-0xE
/// has no valid decimal-digit meaning and must not be rendered as a
/// non-digit character in the sender field (same class as the klesis
/// BCD fix).
fn decode_bcd_address(len_digits: u8, type_byte: u8, bcd: &[u8]) -> Result<String, SmsError> {
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
            if lo > 9 {
                return Err(SmsError::PduDecode);
            }
            number.push(char::from(b'0' + lo));
        }
        let hi_digit_index = idx * 2 + 1;
        if hi_digit_index < digit_count && hi != 0x0F {
            if hi > 9 {
                return Err(SmsError::PduDecode);
            }
            number.push(char::from(b'0' + hi));
        }
    }
    Ok(number)
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
pub(crate) struct SmsMessage {
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
pub(crate) struct SmsManager {
    /// Inbox of received messages, newest last.
    inbox: Vec<SmsMessage>,
}

impl SmsManager {
    /// Create a new SMS manager with an empty inbox.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self { inbox: Vec::new() }
    }

    /// Send an SMS message via the modem.
    ///
    /// Encodes the text as GSM-7 PDU and sends via `AT+CMGS`. The modem
    /// must be in PDU mode (`AT+CMGF=0`) before calling this.
    ///
    /// # Errors
    ///
    /// - [`SmsError::Gsm7Encode`] -- message contains a non-GSM-7 character.
    /// - [`SmsError::MessageTooLong`] -- text exceeds 160 GSM-7 septets.
    /// - [`SmsError::NumberTooLong`] -- phone number exceeds E.164 limit.
    /// - [`SmsError::ModemError`] -- modem returned ERROR.
    /// - [`SmsError::CmeError`] -- modem returned CME error.
    /// - [`SmsError::TransportError`] -- transport layer send/receive failed.
    pub(crate) fn send<T: ModemTransport>(
        transport: &mut T,
        number: &str,
        text: &str,
    ) -> Result<(), SmsError> {
        let (pdu_hex, tpdu_len) = encode_submit_pdu(number, text)?;

        // Set PDU mode.
        transport
            .send_at("AT+CMGF=0")
            .map_err(|_| SmsError::TransportError)?;
        let mut line_buf = [0u8; MAX_LINE_LEN];
        // Drain response lines until OK/ERROR.
        let mut cmgf_confirmed = false;
        for _ in 0..16 {
            let n = transport
                .recv_line(&mut line_buf, 2000)
                .map_err(|_| SmsError::TransportError)?;
            let line = &line_buf[..n];
            if let Some(result) = crate::telephony::parse_final_result(line) {
                match result {
                    AtResponse::Ok => {
                        cmgf_confirmed = true;
                        break;
                    }
                    AtResponse::Error => return Err(SmsError::ModemError),
                    AtResponse::CmeError(code) => return Err(SmsError::CmeError(code)),
                    AtResponse::CmsError(code) => return Err(SmsError::CmsError(code)),
                }
            }
        }
        // WHY: mirror the '>' prompt and final-result loops below -- a mode-set
        // that never returns OK/ERROR within the drain window is a transport
        // failure, not a green light to transmit the PDU.
        if !cmgf_confirmed {
            return Err(SmsError::TransportError);
        }

        // Send AT+CMGS=<tpdu_len> followed by the PDU.
        let mut cmd_buf = [0u8; 32];
        let cmd_len = write_cmgs_command(&mut cmd_buf, tpdu_len);
        let cmd_str =
            core::str::from_utf8(&cmd_buf[..cmd_len]).map_err(|_| SmsError::TransportError)?;

        transport
            .send_at(cmd_str)
            .map_err(|_| SmsError::TransportError)?;

        // Wait for the '>' prompt, then send PDU + Ctrl-Z.
        let mut prompt_received = false;
        for _ in 0..16 {
            let n = transport
                .recv_line(&mut line_buf, 5000)
                .map_err(|_| SmsError::TransportError)?;
            let line = &line_buf[..n];
            if !line.is_empty() && line[0] == b'>' {
                prompt_received = true;
                break;
            }
        }

        if !prompt_received {
            return Err(SmsError::TransportError);
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
                    AtResponse::CmsError(code) => Err(SmsError::CmsError(code)),
                };
            }
        }

        Err(SmsError::TransportError)
    }

    /// Handle an incoming SMS PDU from a +CMT URC.
    ///
    /// `pdu_data` is the raw hex bytes of the PDU (not hex-encoded string,
    /// but the actual PDU bytes after hex decoding by the caller).
    ///
    /// # Errors
    ///
    /// - [`SmsError::PduDecode`] -- PDU is truncated or malformed.
    /// - [`SmsError::UnsupportedDcs`] -- PDU is well-formed but uses a data
    ///   coding scheme other than GSM-7 (0x00).
    #[must_use]
    pub(crate) fn handle_incoming(pdu_data: &[u8]) -> Result<SmsMessage, SmsError> {
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
        let sender_str = decode_bcd_address(oa_len_digits, oa_type, oa_bcd)?;

        // Build sender field.
        let mut sender = [0u8; MAX_SENDER_LEN];
        let sender_bytes = sender_str.as_bytes();
        let sender_len = sender_bytes.len().min(MAX_SENDER_LEN);
        sender[..sender_len].copy_from_slice(&sender_bytes[..sender_len]);

        // PID (ignored).
        cur.read_byte()?;

        // DCS: only GSM-7 (0x00) supported in this kernel build.
        let dcs = cur.read_byte()?;
        if dcs != 0x00 {
            // WHY: the PDU decoded cleanly; the coding scheme is simply
            // unsupported. Conflating this with PduDecode (malformed PDU)
            // hides that the message was well-formed but used, e.g., UCS-2.
            return Err(SmsError::UnsupportedDcs(dcs));
        }

        // SCTS: 7 bytes (timestamp, partially decoded).
        let scts = cur.read_slice(7)?;
        let timestamp = decode_scts_epoch(scts);

        // User data length (septets) and packed user data.
        let udl = usize::from(cur.read_byte()?);
        // GSM 03.40: TP-UD is at most 140 octets, i.e. 160 GSM-7 septets,
        // for a single (non-concatenated) segment. This kernel does not
        // parse the concatenation UDH, so no legitimately encodable
        // single-segment message can claim a larger UDL; treat it as a
        // malformed PDU rather than decoding whatever bytes follow.
        const MAX_SINGLE_SEGMENT_SEPTETS: usize = 160;
        if udl > MAX_SINGLE_SEGMENT_SEPTETS {
            return Err(SmsError::PduDecode);
        }
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
    pub(crate) fn inbox(&self) -> &[SmsMessage] {
        &self.inbox
    }

    /// Mark a message as read by index.
    ///
    /// No-op if the index is out of bounds.
    pub(crate) fn mark_read(&mut self, index: usize) {
        if let Some(msg) = self.inbox.get_mut(index) {
            msg.read = true;
        }
    }

    /// Delete a message by index.
    ///
    /// No-op if the index is out of bounds.
    pub(crate) fn delete(&mut self, index: usize) {
        if index < self.inbox.len() {
            self.inbox.remove(index);
        }
    }

    /// Add a message to the inbox (used by `handle_incoming`).
    ///
    /// Drops the oldest message if the buffer is already at
    /// [`MAX_INBOX_MESSAGES`] capacity, bounding heap growth under an
    /// SMS flood.
    ///
    /// # Errors
    ///
    /// - [`SmsError::InboxOverflow`] if the inbox was already at capacity
    ///   (the oldest buffered message was dropped to make room for `msg`,
    ///   which is still enqueued)
    pub(crate) fn receive(&mut self, msg: SmsMessage) -> Result<(), SmsError> {
        let overflowed = self.inbox.len() >= MAX_INBOX_MESSAGES;
        if overflowed {
            // Drop oldest message to make room.
            self.inbox.remove(0);
        }
        self.inbox.push(msg);
        if overflowed {
            return Err(SmsError::InboxOverflow);
        }
        Ok(())
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
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

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
        let sender = core::str::from_utf8(&msg.sender[..msg.sender_len as usize]).unwrap_or("");
        assert_eq!(sender, "+1234567890", "sender must decode to +1234567890");
        assert_eq!(msg.body, "Hello", "body must decode to 'Hello'");
        assert!(!msg.read, "incoming message must be unread");
    }

    #[test]
    fn handle_incoming_rejects_non_gsm7_dcs() {
        // WHY: regression test for #306 — bits-3:2-only validation admitted
        // any DCS whose bits 3:2 were 0b00, letting compressed-GSM-7 (0x20,
        // 0x30), message-waiting-indication (0xC0), and other non-GSM-7
        // schemes reach the septet decoder. Only DCS 0x00 is supported.
        // These bytes are well-formed PDUs with an unsupported coding
        // scheme, so they must surface as UnsupportedDcs (carrying the
        // offending byte), NOT PduDecode (which means malformed PDU).
        let base: [u8; 24] = [
            0x00, // SCA len
            0x00, // first octet (MTI=0)
            0x0A, // OA len (10 digits)
            0x91, // OA type (international)
            0x21, 0x43, 0x65, 0x87, 0x09, // BCD +1234567890
            0x00, // PID
            0x00, // DCS (overwritten per case below)
            0x32, 0x10, 0x51, 0x21, 0x03, 0x00, 0x00, // SCTS
            0x05, // UDL (5 septets)
            0xC8, 0x32, 0x9B, 0xFD, 0x06, // "Hello" packed
        ];

        for &adversarial_dcs in &[0x10u8, 0xF0, 0xC0, 0x20, 0x30] {
            let mut pdu = base.to_vec();
            pdu[10] = adversarial_dcs;
            let result = SmsManager::handle_incoming(&pdu);
            assert!(
                matches!(result, Err(SmsError::UnsupportedDcs(d)) if d == adversarial_dcs),
                "DCS {adversarial_dcs:#04x} must surface as UnsupportedDcs carrying the offending byte, not conflated with a malformed PDU"
            );
        }
    }

    #[test]
    fn handle_incoming_rejects_udl_over_160() {
        // Same fixed PDU prefix as handle_incoming_parses_pdu, but with a
        // UDL claiming 161 septets -- one past GSM 03.40's 160-septet
        // ceiling for a single (non-concatenated) TP-UD. This kernel does
        // not parse a concatenation UDH, so no larger UDL can legitimately
        // describe one segment; it must be rejected as malformed rather
        // than decoded from whatever bytes happen to follow.
        let mut pdu = alloc::vec![
            0x00, // SCA len
            0x00, // first octet (MTI=0)
            0x0A, // OA len (10 digits)
            0x91, // OA type (international)
            0x21, 0x43, 0x65, 0x87, 0x09, // BCD +1234567890
            0x00, // PID
            0x00, // DCS (GSM-7)
            0x32, 0x10, 0x51, 0x21, 0x03, 0x00, 0x00, // SCTS
            0xA1, // UDL: 161 septets
        ];
        // 161 septets needs ceil(161*7/8) = 141 packed bytes; pad enough
        // that a plain truncation error could never mask the UDL bound.
        pdu.extend(core::iter::repeat(0u8).take(141));

        let result = SmsManager::handle_incoming(&pdu);
        assert!(
            matches!(result, Err(SmsError::PduDecode)),
            "UDL=161 (over the 160-septet single-segment ceiling) must be rejected"
        );
    }

    #[test]
    fn handle_incoming_truncated_pdu_is_pdudecode_not_unsupported_dcs() {
        // Distinctness: a genuinely malformed (truncated) PDU must still be
        // PduDecode, proving the unsupported-DCS variant did not swallow
        // the malformed-PDU case.
        let truncated: [u8; 2] = [0x00, 0x00]; // SCA len 0 + first octet, then nothing
        let result = SmsManager::handle_incoming(&truncated);
        assert!(
            matches!(result, Err(SmsError::PduDecode)),
            "a truncated PDU must remain PduDecode, distinct from UnsupportedDcs"
        );
    }

    #[test]
    fn send_returns_cms_error_immediately() {
        use crate::telephony_mock::MockModemTransport;

        let mut mock = MockModemTransport::new();
        mock.queue_ok(); // AT+CMGF=0 -> OK
        mock.queue_response(b">"); // CMGS prompt
        mock.queue_response(b"+CMS ERROR: 330"); // final result: no network service

        let result = SmsManager::send(&mut mock, "+15551234567", "Hi");
        assert_eq!(
            result,
            Err(SmsError::CmsError(330)),
            "a +CMS ERROR final result on SMS submit must surface the code immediately, not TransportError after exhausting the wait loop"
        );
    }

    #[test]
    fn send_returns_error_when_cmgf_never_confirmed() {
        use crate::telephony_mock::MockModemTransport;

        let mut mock = MockModemTransport::new();
        // AT+CMGF=0 never returns OK/ERROR: 16 non-final lines exhaust the
        // drain loop, which must fail closed instead of proceeding to CMGS.
        for _ in 0..16 {
            mock.queue_response(b"");
        }

        let result = SmsManager::send(&mut mock, "+15551234567", "Hi");

        assert_eq!(
            result,
            Err(SmsError::TransportError),
            "an AT+CMGF=0 that never returns OK/ERROR must fail closed, not fall through to PDU transmission"
        );
        assert_eq!(
            mock.sent_commands.len(),
            1,
            "only AT+CMGF=0 must have been sent; CMGS must not be reached"
        );
    }

    #[test]
    fn send_returns_transport_error_when_prompt_never_received() {
        use crate::telephony_mock::MockModemTransport;

        let mut mock = MockModemTransport::new();
        mock.queue_ok(); // AT+CMGF=0 -> OK
        // Never queue a '>' prompt line: 16 non-prompt lines exhaust the
        // wait loop without ever seeing the modem's data-entry prompt.
        for _ in 0..16 {
            mock.queue_response(b"");
        }

        let result = SmsManager::send(&mut mock, "+15551234567", "Hi");

        assert_eq!(
            result,
            Err(SmsError::TransportError),
            "exhausting the '>' prompt wait loop must return TransportError, not fall through to PDU transmission"
        );
        assert_eq!(
            mock.sent_commands.len(),
            2,
            "the PDU must never be transmitted when the '>' prompt was not received; only AT+CMGF=0 and AT+CMGS=<len> may have been sent"
        );
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
    fn receive_caps_inbox_and_drops_oldest_under_flood() {
        let mut manager = SmsManager::new();
        for i in 0..MAX_INBOX_MESSAGES {
            let result = manager.receive(SmsMessage {
                sender: [0u8; MAX_SENDER_LEN],
                sender_len: 0,
                body: String::from("m"),
                timestamp: i as u64,
                read: false,
            });
            assert!(result.is_ok(), "inbox has room until MAX_INBOX_MESSAGES");
        }
        assert_eq!(manager.inbox().len(), MAX_INBOX_MESSAGES);

        // One more message over capacity must drop the oldest, not grow
        // the inbox unbounded (the pre-fix behavior under an SMS flood).
        let result = manager.receive(SmsMessage {
            sender: [0u8; MAX_SENDER_LEN],
            sender_len: 0,
            body: String::from("overflow"),
            timestamp: MAX_INBOX_MESSAGES as u64,
            read: false,
        });
        assert_eq!(
            result,
            Err(SmsError::InboxOverflow),
            "push into a full inbox must surface InboxOverflow"
        );
        assert_eq!(
            manager.inbox().len(),
            MAX_INBOX_MESSAGES,
            "inbox must stay capped at MAX_INBOX_MESSAGES, not grow unbounded under flood"
        );
        assert_eq!(
            manager.inbox()[0].timestamp,
            1,
            "the oldest message must have been dropped to make room"
        );
        assert_eq!(
            manager.inbox().last().map(|m| m.timestamp),
            Some(MAX_INBOX_MESSAGES as u64),
            "the newly received message must be enqueued"
        );
    }

    #[test]
    fn mark_read_updates_flag() {
        let mut manager = SmsManager::new();
        manager
            .receive(SmsMessage {
                sender: [0u8; MAX_SENDER_LEN],
                sender_len: 0,
                body: String::from("test"),
                timestamp: 0,
                read: false,
            })
            .ok();
        assert!(!manager.inbox()[0].read, "message must start unread");
        manager.mark_read(0);
        assert!(
            manager.inbox()[0].read,
            "message must be read after mark_read"
        );
    }

    #[test]
    fn delete_removes_message() {
        let mut manager = SmsManager::new();
        manager
            .receive(SmsMessage {
                sender: [0u8; MAX_SENDER_LEN],
                sender_len: 0,
                body: String::from("msg1"),
                timestamp: 0,
                read: false,
            })
            .ok();
        manager
            .receive(SmsMessage {
                sender: [0u8; MAX_SENDER_LEN],
                sender_len: 0,
                body: String::from("msg2"),
                timestamp: 0,
                read: false,
            })
            .ok();
        assert_eq!(manager.inbox().len(), 2);
        manager.delete(0);
        assert_eq!(manager.inbox().len(), 1);
        assert_eq!(
            manager.inbox()[0].body,
            "msg2",
            "remaining message must be msg2"
        );
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
        assert_eq!(
            decoded,
            Ok(String::from("+15551234567")),
            "BCD round-trip must preserve number"
        );
    }

    #[test]
    fn decode_bcd_address_rejects_non_decimal_nibble() {
        // Low nibble 0xA (10) has no decimal-digit meaning; before the
        // fix this silently emitted ':' (b'0' + 10) into the sender
        // field instead of being rejected.
        let bcd = [0x1Au8];
        let decoded = decode_bcd_address(2, 0x81, &bcd);
        assert_eq!(
            decoded,
            Err(SmsError::PduDecode),
            "a BCD nibble outside 0-9 must be rejected, not rendered as a non-digit character"
        );
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

    #[test]
    fn number_too_long_in_bcd_encode() {
        // E.164 limit is 20 digits; a 21-digit number must fail.
        let long_number = "+123456789012345678901"; // 21 digits
        let result = encode_bcd_address(long_number);
        assert_eq!(
            result,
            Err(SmsError::NumberTooLong),
            "encoding >20-digit number must return NumberTooLong"
        );
    }
}
