//! Error types for the telephony daemon.

use snafu::Snafu;

/// Telephony subsystem errors.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
#[non_exhaustive]
pub(crate) enum Error {
    /// AT command timed out.
    #[snafu(display("AT command timed out after {timeout_ms}ms"))]
    Timeout {
        /// Timeout duration in milliseconds.
        timeout_ms: u64,
    },

    /// Modem returned an error code.
    #[snafu(display("modem returned error: {code}"))]
    ModemError {
        /// CME/CMS error code.
        code: u32,
    },

    /// Modem returned an unexpected response.
    #[snafu(display("unexpected response: {response}"))]
    UnexpectedResponse {
        /// The unexpected response text.
        response: String,
    },

    /// Failed to parse modem output.
    #[snafu(display("parse error: {message}"))]
    Parse {
        /// Description of the parse failure.
        message: String,
    },

    /// CCCI channel I/O error.
    #[snafu(display("CCCI channel error: {source}"))]
    Ccci {
        /// Underlying I/O error.
        source: std::io::Error,
    },

    /// Modem is not ready for commands.
    #[snafu(display("modem not ready"))]
    NotReady,

    /// PDU decoding error.
    #[snafu(display("PDU decode error at byte {offset}: {message}"))]
    PduDecode {
        /// Byte offset where decoding failed.
        offset: usize,
        /// Description of the decode failure.
        message: String,
    },

    /// Invalid hex encoding in PDU data.
    #[snafu(display("invalid PDU hex: {message}"))]
    InvalidHex {
        /// Description of the hex error.
        message: String,
    },

    /// Character cannot be encoded in GSM-7.
    #[snafu(display("GSM-7 encode: unmappable character U+{codepoint:04X}"))]
    Gsm7Encode {
        /// Unicode codepoint that cannot be encoded.
        codepoint: u32,
    },

    /// Silent SMS (Type 0) detected: PID indicates the message should not be
    /// displayed or stored. This is a surveillance technique used by IMSI
    /// catchers and law enforcement to silently ping a device.
    #[snafu(display("silent SMS detected (PID=0x{pid:02X})"))]
    SilentSmsAlert {
        /// The Protocol Identifier byte that triggered the alert.
        pid: u8,
    },

    /// WAP Push / OMA-CP message rejected. UDH destination port indicates
    /// an over-the-air provisioning or WAP Push message, which can be used
    /// for remote SIM toolkit attacks.
    #[snafu(display(
        "WAP Push rejected: UDH destination port {destination_port} (source port {source_port})"
    ))]
    WapPushRejected {
        /// UDH destination port number.
        destination_port: u16,
        /// UDH source port number.
        source_port: u16,
    },
}

/// Result type for telephony operations.
pub(crate) type Result<T> = std::result::Result<T, Error>;
