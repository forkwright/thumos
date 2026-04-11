//! Error types for the telephony daemon.

use snafu::Snafu;

/// Telephony subsystem errors.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum Error {
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
}

/// Result type for telephony operations.
pub type Result<T> = std::result::Result<T, Error>;
