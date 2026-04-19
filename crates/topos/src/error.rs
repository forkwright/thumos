//! Error types for the GPS subsystem.

use snafu::Snafu;

/// Errors from GPS operations.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum Error {
    /// NMEA sentence failed checksum validation.
    #[snafu(display("NMEA checksum mismatch: expected {expected:02X}, got {actual:02X}"))]
    ChecksumMismatch {
        /// Expected checksum value.
        expected: u8,
        /// Actual computed checksum.
        actual: u8,
    },

    /// NMEA sentence has invalid format.
    #[snafu(display("NMEA parse error: {message}"))]
    ParseError {
        /// Description of what went wrong.
        message: String,
    },

    /// GPS device not responding.
    #[snafu(display("GPS device timeout"))]
    Timeout,

    /// No fix available.
    #[snafu(display("no GPS fix"))]
    NoFix,
}

/// Result type for GPS operations.
pub type Result<T> = std::result::Result<T, Error>;
