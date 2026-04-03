//! Error types for the telephony daemon.

use snafu::Snafu;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum Error {
    #[snafu(display("AT command timed out after {timeout_ms}ms"))]
    Timeout { timeout_ms: u64 },

    #[snafu(display("modem returned error: {code}"))]
    ModemError { code: u32 },

    #[snafu(display("unexpected response: {response}"))]
    UnexpectedResponse { response: String },

    #[snafu(display("parse error: {message}"))]
    Parse { message: String },

    #[snafu(display("CCCI channel error: {source}"))]
    Ccci { source: std::io::Error },

    #[snafu(display("modem not ready"))]
    NotReady,

    #[snafu(display("PDU decode error at byte {OFFSET}: {message}"))]
    PduDecode { offset: usize, message: String },

    #[snafu(display("invalid PDU hex: {message}"))]
    InvalidHex { message: String },

    #[snafu(display("GSM-7 encode: unmappable character U+{codepoint:04X}"))]
    Gsm7Encode { codepoint: u32 },
}

pub type Result<T> = std::result::Result<T, Error>;
