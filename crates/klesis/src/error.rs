//! Error types for the telephony daemon.

use snafu::Snafu;

/// Telephony subsystem errors.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
#[non_exhaustive]
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

    /// PDU encoding error.
    #[snafu(display("PDU encode error: {message}"))]
    PduEncode {
        /// Description of the encode failure.
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

impl From<klesis_core::CoreError> for Error {
    fn from(e: klesis_core::CoreError) -> Self {
        use klesis_core::CoreError as C;
        match e {
            C::Gsm7Encode { codepoint } => Self::Gsm7Encode { codepoint },
            C::HexInvalid { offset } => Self::InvalidHex {
                message: format!("invalid hex at offset {offset}"),
            },
            C::AddressTooLong { digits } => Self::PduDecode {
                offset: 0,
                message: format!("address of {digits} digits exceeds the maximum"),
            },
            C::BcdInvalidDigit { nibble } => Self::PduDecode {
                offset: 0,
                message: format!("BCD nibble 0x{nibble:X} is not a decimal digit"),
            },
            C::Gsm7Truncated { septet } => Self::PduDecode {
                offset: septet,
                message: "GSM-7 data ended before the declared septet count".to_owned(),
            },
            C::Gsm7DanglingEscape => Self::PduDecode {
                offset: 0,
                message: "GSM-7 data ends with a dangling ESC septet (truncated extension char)"
                    .to_owned(),
            },
            C::Truncated { offset } => Self::PduDecode {
                offset,
                message: "read past the end of the PDU".to_owned(),
            },
            // WHY a catch-all: CoreError is `#[non_exhaustive]`, and an
            // unrecognised decode failure becoming PduDecode rejects the
            // message, which is the fail-closed direction.
            _ => Self::PduDecode {
                offset: 0,
                message: "unrecognised PDU decode failure".to_owned(),
            },
        }
    }
}

/// Result type for telephony operations.
pub(crate) type Result<T> = std::result::Result<T, Error>;
