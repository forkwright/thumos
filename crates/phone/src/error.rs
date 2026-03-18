//! Error types for the telephony daemon.

use snafu::Snafu;

#[derive(Debug, Snafu)]
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
}

pub type Result<T> = std::result::Result<T, Error>;
