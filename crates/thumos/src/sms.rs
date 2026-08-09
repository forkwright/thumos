//! SMS send/receive with PDU encoding (3GPP TS 23.040).
//!
//! Provides the [`SmsManager`] for inbox management and AT command-based SMS
//! operations via the telephony subsystem's [`ModemTransport`] trait.
//!
//! ## Module structure
//!
//! The GSM-7 codec, the PDU byte primitives (hex, BCD, cursor), and the
//! surveillance classification of an incoming message live in
//! [`klesis_core`], shared with the workspace `klesis` crate. This module
//! holds only what is kernel-shaped: PDU framing, the AT command exchange,
//! and inbox storage.
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
    reason = "SMS API created in Phase 07 Wave 3, kinit wiring pending (#145)"
)]

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

use crate::telephony::{AtResponse, MAX_LINE_LEN, ModemTransport};

pub(crate) use klesis_core::MessageClass;
use klesis_core::{CoreError, Cursor};

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

impl From<CoreError> for SmsError {
    fn from(e: CoreError) -> Self {
        match e {
            CoreError::Gsm7Encode { codepoint } => Self::Gsm7Encode(codepoint),
            CoreError::AddressTooLong { .. } => Self::NumberTooLong,
            // WHY the rest collapse to PduDecode: they all describe a PDU
            // the modem should not have produced (truncation, a dangling
            // ESC, a non-decimal BCD nibble, bad hex). The kernel's caller
            // acts identically on each -- drop the PDU -- so distinguishing
            // them here would add variants nothing branches on.
            //
            // The `_` arm is required because CoreError is
            // `#[non_exhaustive]`, and it is safe here in a way it would
            // NOT be on MessageClass: an unrecognised decode failure
            // becoming PduDecode drops the PDU, which is fail-closed. An
            // unrecognised *classification* becoming Normal would deliver
            // it, which is why that type is exhaustive.
            CoreError::Gsm7Truncated { .. }
            | CoreError::Gsm7DanglingEscape
            | CoreError::BcdInvalidDigit { .. }
            | CoreError::HexInvalid { .. }
            | CoreError::Truncated { .. }
            | _ => Self::PduDecode,
        }
    }
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

/// Encode a phone number string into the PDU address field.
///
/// Returns `[length_in_digits, type_byte, bcd_bytes...]`. The BCD packing
/// itself is [`klesis_core::encode_bcd_address`]; only the length/type
/// framing is PDU-shaped and lives here.
fn encode_bcd_address(number: &str) -> Result<Vec<u8>, SmsError> {
    let digits = number.strip_prefix('+').unwrap_or(number);
    if digits.len() > MAX_NUMBER_DIGITS {
        return Err(SmsError::NumberTooLong);
    }
    let (type_byte, bcd) = klesis_core::encode_bcd_address(number)?;

    let mut out = Vec::with_capacity(2 + bcd.len());
    // INVARIANT: SMS phone numbers are at most 20 digits (E.164), fits in u8.
    out.push(digits.len() as u8);
    out.push(type_byte);
    out.extend_from_slice(&bcd);
    Ok(out)
}

// ---------------------------------------------------------------------------
// PDU encoding (SMS-SUBMIT)
// ---------------------------------------------------------------------------

/// Build an SMS-SUBMIT PDU for sending via AT+CMGS.
///
/// Returns the hex-encoded PDU string and the TPDU length (bytes after SCA).
fn encode_submit_pdu(number: &str, text: &str) -> Result<(String, usize), SmsError> {
    let septet_count = klesis_core::count_septets(text)?;
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
    let packed = klesis_core::encode(text)?;
    pdu.extend_from_slice(&packed);

    // TPDU length = total PDU bytes minus the SCA byte.
    let tpdu_len = pdu.len() - 1;

    Ok((klesis_core::hex_encode(&pdu), tpdu_len))
}

// ---------------------------------------------------------------------------
// PDU decoding (SMS-DELIVER, for incoming +CMT)
// ---------------------------------------------------------------------------

// The PDU cursor is [`klesis_core::Cursor`] -- bounds-checked reads over
// modem-supplied bytes, shared with the workspace `klesis` crate.

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
    /// What this message is beyond its text (#662).
    ///
    /// WHY the message is kept rather than dropped: `klesis` rejects a
    /// silent SMS outright, which is right for a daemon and wrong here. On
    /// a counter-surveillance phone the ping itself is the intelligence --
    /// an alert the user never sees is indistinguishable from no detection
    /// at all -- so the kernel records it and marks what it is.
    pub class: MessageClass,
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
        let mut cur = Cursor::new(pdu_data);

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
        let sender_str = klesis_core::decode_bcd_address(oa_len_digits, oa_type, oa_bcd)?;

        // Build sender field.
        let mut sender = [0u8; MAX_SENDER_LEN];
        let sender_bytes = sender_str.as_bytes();
        let sender_len = sender_bytes.len().min(MAX_SENDER_LEN);
        sender[..sender_len].copy_from_slice(&sender_bytes[..sender_len]);

        // WHY (#662): the PID is the silent-SMS signal. This byte was
        // previously read and discarded, so a Type 0 message -- specified
        // as neither displayed nor stored, and the standard covert
        // location-ping -- was filed to the inbox as ordinary mail.
        let pid = cur.read_byte()?;

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
        // for a single (non-concatenated) segment. No legitimately
        // encodable single-segment message can claim a larger UDL; treat it
        // as a malformed PDU rather than decoding whatever bytes follow.
        const MAX_SINGLE_SEGMENT_SEPTETS: usize = 160;
        if udl > MAX_SINGLE_SEGMENT_SEPTETS {
            return Err(SmsError::PduDecode);
        }
        let ud_byte_count = udl.saturating_mul(7).div_ceil(8);
        let ud_bytes = cur.read_slice(ud_byte_count)?;

        let class = klesis_core::classify(first_octet, pid, ud_bytes);

        // SECURITY (#662): strip the User Data Header before decoding text.
        // Without this the header octets -- attacker-controlled on e.g. a
        // concatenation IE -- decode as characters and are prepended to the
        // visible body, which is a forged-sender-prefix phishing surface
        // inside a message that displays as coming from a real number.
        let body = if klesis_core::has_udh(first_octet) {
            let udh_septets = klesis_core::gsm7_udh_septets(klesis_core::udh_octet_len(ud_bytes));
            // WHY decode_from over slicing at the UDH's last octet: the
            // header is octet-aligned but the text resumes on a SEPTET
            // boundary, and those differ by up to 6 fill bits. Slicing
            // shifts the whole message.
            klesis_core::decode_from(ud_bytes, udh_septets, udl.saturating_sub(udh_septets))?
        } else {
            klesis_core::decode(ud_bytes, udl)?
        };

        Ok(SmsMessage {
            sender,
            sender_len: sender_len as u8,
            body,
            timestamp,
            read: false,
            class,
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
        let raw = klesis_core::hex_decode(pdu_hex.as_bytes());
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
            class: MessageClass::Normal,
        });
        let sender = core::str::from_utf8(&msg.sender[..msg.sender_len as usize]).unwrap_or("");
        assert_eq!(sender, "+1234567890", "sender must decode to +1234567890");
        assert_eq!(msg.body, "Hello", "body must decode to 'Hello'");
        assert!(!msg.read, "incoming message must be unread");
        assert_eq!(
            msg.class,
            MessageClass::Normal,
            "an ordinary PDU must not be classified as covert"
        );
    }

    /// Build an SMS-DELIVER PDU with a caller-chosen first octet, PID, and
    /// user-data section. Everything else matches the canonical fixture
    /// above, so a test difference is attributable to what it varied.
    fn deliver_pdu(first_octet: u8, pid: u8, udl: u8, ud: &[u8]) -> Vec<u8> {
        let mut pdu = alloc::vec![
            0x00, // SCA len
            first_octet,
            0x0A, // OA len (10 digits)
            0x91, // OA type (international)
            0x21,
            0x43,
            0x65,
            0x87,
            0x09, // BCD +1234567890
            pid,
            0x00, // DCS (GSM-7)
            0x32,
            0x10,
            0x51,
            0x21,
            0x03,
            0x00,
            0x00, // SCTS
            udl,
        ];
        pdu.extend_from_slice(ud);
        pdu
    }

    #[test]
    fn handle_incoming_classifies_silent_sms_and_keeps_the_message() {
        // WHY (#662): PID 0x40 marks a Type 0 message -- specified as
        // neither displayed nor stored, and the standard covert
        // location-ping. Before this, the PID byte was read and discarded,
        // so the ping was filed to the inbox as ordinary mail.
        for pid in [0x40u8, 0x41, 0x47] {
            let pdu = deliver_pdu(0x00, pid, 0x05, &[0xC8, 0x32, 0x9B, 0xFD, 0x06]);
            let msg = SmsManager::handle_incoming(&pdu);
            let Ok(msg) = msg else {
                unreachable!("silent SMS must still decode, not error: PID {pid:#04X}")
            };
            assert_eq!(
                msg.class,
                MessageClass::Silent { pid },
                "PID {pid:#04X} must classify as a silent SMS"
            );
            // The message is RETAINED, not dropped: on a counter-surveillance
            // phone the ping itself is the intelligence, and an alert nobody
            // sees is indistinguishable from no detection.
            assert_eq!(msg.body, "Hello", "a silent SMS must keep its decoded body");
        }
    }

    #[test]
    fn handle_incoming_leaves_ordinary_pid_unclassified() {
        // 0x3F sits just below the silent range and 0x48 just above it --
        // an off-by-one in either bound would show here.
        for pid in [0x00u8, 0x3F, 0x48] {
            let pdu = deliver_pdu(0x00, pid, 0x05, &[0xC8, 0x32, 0x9B, 0xFD, 0x06]);
            let Ok(msg) = SmsManager::handle_incoming(&pdu) else {
                unreachable!("PID {pid:#04X} must decode")
            };
            assert_eq!(
                msg.class,
                MessageClass::Normal,
                "PID {pid:#04X} is outside the silent range"
            );
        }
    }

    #[test]
    fn handle_incoming_strips_udh_from_the_visible_body() {
        // SECURITY (#662): with UDHI set, the UD begins with a header whose
        // bytes are attacker-controlled. Decoded as text they are prepended
        // to what the user reads -- a forged-sender-prefix inside a message
        // that displays as coming from a real number.
        //
        // UDH: UDHL=05, IEI=00 (concatenation), IEL=03, ref=0xAB, total=02,
        // seq=01 -- 6 octets. 6 octets = 48 bits; ceil(48/7) = 7 septets =
        // 49 bits, so ONE fill bit sits between the header and the text.
        // "Hello" is then packed starting at BIT 49, not byte 6.
        //
        // This fixture is the point of the test. Decoding by slicing at the
        // header's last octet and reading from bit 0 -- which both this
        // kernel and klesis did -- yields "ΔKYY§" from these exact bytes.
        // An assertion that merely checked for absent NULs or a short body
        // passes on that garbage, which is why it must assert the text.
        let ud = alloc::vec![
            0x05, 0x00, 0x03, 0xAB, 0x02, 0x01, // UDH (6 octets)
            0x90, 0x65, 0x36, 0xFB, 0x0D, // "Hello" packed from bit 49
        ];
        let pdu = deliver_pdu(klesis_core::UDHI_BIT, 0x00, 12, &ud);

        let Ok(msg) = SmsManager::handle_incoming(&pdu) else {
            unreachable!("a UDH-bearing PDU must decode")
        };
        assert_eq!(
            msg.body, "Hello",
            "the body must be the text septets only, decoded from the septet \
             boundary after the UDH -- not the octet boundary"
        );
    }

    #[test]
    fn handle_incoming_flags_wap_push_destination_port() {
        // UDHL=06, IEI=05 (16-bit app ports), len=04, dest=2948, src=0.
        let mut ud = alloc::vec![0x06, 0x05, 0x04, 0x0B, 0x84, 0x00, 0x00];
        ud.extend_from_slice(&[0xC8, 0x32, 0x9B, 0xFD, 0x06]);
        let pdu = deliver_pdu(klesis_core::UDHI_BIT, 0x00, 13, &ud);

        let Ok(msg) = SmsManager::handle_incoming(&pdu) else {
            unreachable!("a WAP Push PDU must decode")
        };
        assert_eq!(
            msg.class,
            MessageClass::WapPush {
                destination_port: 2948,
                source_port: 0
            },
            "an OMA-CP destination port must classify as WAP Push"
        );
    }

    #[test]
    fn silent_sms_maps_to_a_threat_alert() {
        // WHY (#662): ThreatAlertType::SilentSms existed with an icon, a
        // Display impl, and tests -- and no producer anywhere in the
        // kernel. This is the seam that gives a decode result somewhere to
        // go. Wiring it into the live event loop is #145.
        use crate::screen_threat::ThreatAlertType;
        assert_eq!(
            ThreatAlertType::from_message_class(MessageClass::Silent { pid: 0x40 }),
            Some(ThreatAlertType::SilentSms),
            "a silent SMS must raise the alert type that already exists for it"
        );
        assert_eq!(
            ThreatAlertType::from_message_class(MessageClass::WapPush {
                destination_port: 2948,
                source_port: 0
            }),
            Some(ThreatAlertType::WapPushRejected),
        );
        assert_eq!(
            ThreatAlertType::from_message_class(MessageClass::Normal),
            None,
            "an ordinary message must raise no alert"
        );
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
    fn handle_incoming_rejects_non_zero_mti() {
        // MTI bits (first_octet & 0x03) must be 0b00 (SMS-DELIVER) for an
        // incoming message. first_octet=0x01 has MTI=01 (SMS-SUBMIT), a
        // PDU type this receive path must never accept.
        let pdu: [u8; 2] = [0x00, 0x01]; // SCA len 0, first octet MTI=01
        let result = SmsManager::handle_incoming(&pdu);
        assert!(
            matches!(result, Err(SmsError::PduDecode)),
            "a non-zero MTI (not SMS-DELIVER) must be rejected as PduDecode"
        );
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
    fn handle_incoming_rejects_pdu_truncated_before_full_user_data() {
        // Distinct from handle_incoming_truncated_pdu_is_pdudecode_not_unsupported_dcs
        // (which truncates immediately after the first octet): this PDU
        // is well-formed through the UDL byte, claims 5 septets of user
        // data (5 packed bytes needed), but only provides 2 -- exercising
        // the read_slice() length check at the very end of the parse, a
        // different cursor site than the early read_byte() truncation.
        let pdu: [u8; 21] = [
            0x00, // SCA len
            0x00, // first octet (MTI=0)
            0x0A, // OA len (10 digits)
            0x91, // OA type (international)
            0x21, 0x43, 0x65, 0x87, 0x09, // BCD +1234567890
            0x00, // PID
            0x00, // DCS (GSM-7)
            0x32, 0x10, 0x51, 0x21, 0x03, 0x00, 0x00, // SCTS
            0x05, // UDL (5 septets -> needs 5 packed bytes)
            0xC8, 0x32, // only 2 of the 5 needed packed bytes present
        ];
        let result = SmsManager::handle_incoming(&pdu);
        assert!(
            matches!(result, Err(SmsError::PduDecode)),
            "user data truncated short of UDL's claimed length must be PduDecode"
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
                class: MessageClass::Normal,
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
            class: MessageClass::Normal,
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
                class: MessageClass::Normal,
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
                class: MessageClass::Normal,
            })
            .ok();
        manager
            .receive(SmsMessage {
                sender: [0u8; MAX_SENDER_LEN],
                sender_len: 0,
                body: String::from("msg2"),
                timestamp: 0,
                read: false,
                class: MessageClass::Normal,
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
        let decoded = klesis_core::decode_bcd_address(bcd[0], bcd[1], &bcd[2..]);
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
        let decoded = klesis_core::decode_bcd_address(2, 0x81, &bcd);
        assert_eq!(
            decoded,
            Err(klesis_core::CoreError::BcdInvalidDigit { nibble: 0x0A }),
            "a BCD nibble outside 0-9 must be rejected, not rendered as a non-digit character"
        );
        // ...and the kernel's own error mapping must keep it a decode
        // failure rather than losing it to a broader variant.
        assert_eq!(
            decoded.map_err(SmsError::from),
            Err(SmsError::PduDecode),
            "a rejected BCD nibble must surface to the kernel as PduDecode"
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
