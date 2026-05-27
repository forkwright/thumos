//! Typed Matrix identifiers.

extern crate alloc;

use core::{fmt, ops::Deref};

use alloc::string::String;

use serde::{Deserialize, Serialize};

macro_rules! matrix_id {
    ($name:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        #[must_use]
        pub struct $name(String);

        impl $name {
            pub(crate) fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl From<String> for $name {
            fn from(value: String) -> Self {
                Self(value)
            }
        }

        impl From<&str> for $name {
            fn from(value: &str) -> Self {
                Self(String::from(value))
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

matrix_id!(MatrixDeviceId);
matrix_id!(MatrixEventId);
matrix_id!(MatrixRoomId);
matrix_id!(MatrixUserId);
