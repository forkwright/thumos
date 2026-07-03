//! Typed Matrix identifiers.

extern crate alloc;

use core::{fmt, ops::Deref};

use alloc::string::String;

use serde::{Deserialize, Deserializer, Serialize};

/// Maximum length (bytes) accepted for any typed Matrix identifier.
///
/// WHY: bounds worst-case memory for an identifier parsed from an
/// adversarial homeserver response or USB provisioning stream; the Matrix
/// spec sets no hard ceiling but no legitimate user/room/event/device ID
/// approaches this size (#373).
const MAX_ID_LEN: usize = 255;

/// Errors returned when constructing a typed Matrix identifier from an
/// untrusted string (#373).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MatrixIdError {
    /// The value is missing the sigil this identifier type requires.
    MissingSigil {
        /// The sigil character this identifier type requires.
        expected: char,
    },
    /// The value contains a CR, LF, or NUL byte (header/path injection risk).
    ForbiddenByte,
    /// The value exceeds `MAX_ID_LEN` bytes.
    TooLong,
    /// The value is empty.
    Empty,
}

impl fmt::Display for MatrixIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingSigil { expected } => write!(f, "missing required sigil '{expected}'"),
            Self::ForbiddenByte => write!(f, "contains a forbidden CR/LF/NUL byte"),
            Self::TooLong => write!(f, "exceeds maximum identifier length"),
            Self::Empty => write!(f, "identifier is empty"),
        }
    }
}

/// Validate a candidate Matrix identifier string.
///
/// `sigil` is `Some(c)` when the identifier type requires a leading sigil
/// (`@` user, `!` room, `$` event); `None` for device IDs, which the Matrix
/// spec does not sigil-prefix (#373).
fn validate_matrix_id(value: &str, sigil: Option<char>) -> Result<(), MatrixIdError> {
    if value.is_empty() {
        return Err(MatrixIdError::Empty);
    }
    if value.len() > MAX_ID_LEN {
        return Err(MatrixIdError::TooLong);
    }
    if value.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0) {
        return Err(MatrixIdError::ForbiddenByte);
    }
    if let Some(expected) = sigil
        && !value.starts_with(expected)
    {
        return Err(MatrixIdError::MissingSigil { expected });
    }
    Ok(())
}

macro_rules! matrix_id {
    ($name:ident, $sigil:expr) => {
        #[derive(Debug, Clone, PartialEq, Eq, Serialize)]
        #[must_use]
        pub struct $name(String);

        impl $name {
            /// Construct a validated `$name` from an untrusted string.
            ///
            /// # Errors
            ///
            /// Returns [`MatrixIdError`] if `value` is empty, exceeds the
            /// maximum identifier length, contains a CR/LF/NUL byte, or is
            /// missing the required sigil (#373).
            pub(crate) fn new(value: &str) -> Result<Self, MatrixIdError> {
                validate_matrix_id(value, $sigil)?;
                Ok(Self(String::from(value)))
            }

            pub(crate) fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = MatrixIdError;

            fn try_from(value: String) -> Result<Self, MatrixIdError> {
                validate_matrix_id(&value, $sigil)?;
                Ok(Self(value))
            }
        }

        impl TryFrom<&str> for $name {
            type Error = MatrixIdError;

            fn try_from(value: &str) -> Result<Self, MatrixIdError> {
                Self::new(value)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let s = String::deserialize(deserializer)?;
                Self::new(&s).map_err(serde::de::Error::custom)
            }
        }

        impl Deref for $name {
            type Target = str;

            fn deref(&self) -> &Self::Target {
                self.as_str()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.as_str())
            }
        }

        impl PartialEq<&str> for $name {
            fn eq(&self, other: &&str) -> bool {
                self.as_str() == *other
            }
        }
    };
}

matrix_id!(MatrixDeviceId, None);
matrix_id!(MatrixEventId, Some('$'));
matrix_id!(MatrixRoomId, Some('!'));
matrix_id!(MatrixUserId, Some('@'));

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_id_requires_at_sigil() {
        assert!(MatrixUserId::new("@foo:bar").is_ok());
        assert!(matches!(
            MatrixUserId::new("foo:bar"),
            Err(MatrixIdError::MissingSigil { expected: '@' })
        ));
    }

    #[test]
    fn room_id_requires_bang_sigil() {
        assert!(MatrixRoomId::new("!room:bar").is_ok());
        assert!(matches!(
            MatrixRoomId::new("room:bar"),
            Err(MatrixIdError::MissingSigil { expected: '!' })
        ));
    }

    #[test]
    fn event_id_requires_dollar_sigil() {
        assert!(MatrixEventId::new("$event123").is_ok());
        assert!(matches!(
            MatrixEventId::new("event123"),
            Err(MatrixIdError::MissingSigil { expected: '$' })
        ));
    }

    #[test]
    fn device_id_has_no_sigil_requirement() {
        assert!(MatrixDeviceId::new("THUMOSDEV01").is_ok());
        assert!(MatrixDeviceId::new("@notasigil").is_ok());
    }

    #[test]
    fn crlf_injection_is_rejected() {
        // #373: a malicious homeserver embedding CRLF in a user ID must not
        // produce a valid typed identifier -- downstream HTTP path/header
        // construction would otherwise be injectable.
        let malicious = "@foo:bar\r\nX-Injected: evil";
        assert!(matches!(
            MatrixUserId::new(malicious),
            Err(MatrixIdError::ForbiddenByte)
        ));
    }

    #[test]
    fn embedded_nul_is_rejected() {
        let malicious = "@foo:bar\u{0}evil";
        assert!(matches!(
            MatrixUserId::new(malicious),
            Err(MatrixIdError::ForbiddenByte)
        ));
    }

    #[test]
    fn empty_id_is_rejected() {
        assert!(matches!(MatrixUserId::new(""), Err(MatrixIdError::Empty)));
    }

    #[test]
    fn oversized_id_is_rejected() {
        let mut long = String::from("@");
        for _ in 0..MAX_ID_LEN {
            long.push('a');
        }
        assert!(matches!(
            MatrixUserId::new(&long),
            Err(MatrixIdError::TooLong)
        ));
    }

    #[test]
    fn try_from_str_matches_new() {
        assert_eq!(
            MatrixUserId::try_from("@foo:bar"),
            MatrixUserId::new("@foo:bar")
        );
        assert!(MatrixUserId::try_from("bad").is_err());
    }

    #[test]
    fn postcard_deserialize_rejects_injected_crlf() {
        // #373: ProvisionBundle.user_id: MatrixUserId is deserialized
        // straight off the USB provisioning wire format (postcard) -- an
        // adversarial provisioner must not be able to smuggle a
        // CRLF-bearing value into a typed identifier this way.
        let malicious = "@foo:bar\r\nX-Injected: evil";
        let encoded = postcard::to_allocvec(&malicious).unwrap_or_default();
        let result: Result<MatrixUserId, _> = postcard::from_bytes(&encoded);
        assert!(
            result.is_err(),
            "postcard deserialization of a CRLF-injected user ID must fail"
        );
    }

    #[test]
    fn postcard_deserialize_accepts_well_formed_id() {
        let valid = "@foo:bar";
        let encoded = postcard::to_allocvec(&valid).unwrap_or_default();
        let result: Result<MatrixUserId, _> = postcard::from_bytes(&encoded);
        assert_eq!(
            result.ok().map(|id| String::from(id.as_str())),
            Some(String::from(valid))
        );
    }
}
