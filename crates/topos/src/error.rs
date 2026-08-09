//! Error types for the GPS subsystem.

use snafu::Snafu;

/// Errors from GPS operations.
#[derive(Debug, PartialEq, Snafu)]
#[non_exhaustive]
pub(crate) enum Error {
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
    Parse {
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

impl From<topos_core::CoreError> for Error {
    fn from(e: topos_core::CoreError) -> Self {
        use topos_core::CoreError as C;
        match e {
            C::NoFix => Self::NoFix,
            C::ChecksumMismatch { expected, actual } => Self::ChecksumMismatch { expected, actual },
            C::MissingDelimiters => Self::Parse {
                message: "missing $ prefix or * checksum delimiter".to_owned(),
            },
            C::ChecksumNotHex => Self::Parse {
                message: "checksum is not two hex digits".to_owned(),
            },
            C::TooFewFields { needed, got } => Self::Parse {
                message: format!("sentence needs {needed}+ fields, got {got}"),
            },
            C::CoordinateTooShort => Self::Parse {
                message: "coordinate field is shorter than the format requires".to_owned(),
            },
            C::FieldNotDigits => Self::Parse {
                message: "field contains a non-digit character where a digit was required"
                    .to_owned(),
            },
            C::MinutesOutOfRange => Self::Parse {
                message: "NMEA minutes must be less than 60".to_owned(),
            },
            C::FractionalDigitsExceeded => Self::Parse {
                message: "fractional digit count exceeds the supported range".to_owned(),
            },
            C::MagnitudeOverflow => Self::Parse {
                message: "parsed magnitude overflowed the fixed-point range".to_owned(),
            },
            C::LatitudeOutOfBounds => Self::Parse {
                message: "latitude outside +/-90 degrees".to_owned(),
            },
            C::LongitudeOutOfBounds => Self::Parse {
                message: "longitude outside +/-180 degrees".to_owned(),
            },
            C::InvalidTimeDate => Self::Parse {
                message: "time or date field is malformed or out of range".to_owned(),
            },
            // WHY a catch-all: CoreError is `#[non_exhaustive]`; an
            // unrecognised parse failure becoming Error::Parse rejects the
            // sentence, which is the fail-closed direction.
            _ => Self::Parse {
                message: "unrecognised NMEA parse failure".to_owned(),
            },
        }
    }
}

/// Result type for GPS operations.
pub(crate) type Result<T> = std::result::Result<T, Error>;
