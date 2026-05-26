//! Error types for the Aletheia bridge.

use compact_str::CompactString;
use snafu::{GenerateImplicitData as _, Location, Snafu};
use ulid::Ulid;

use crate::protocol::Capability;

/// Result type for bridge operations.
pub type Result<T> = std::result::Result<T, Error>; // kanon:ignore RUST/pub-visibility -- public API

/// Aletheia bridge errors.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
#[non_exhaustive]
pub enum Error {
    /// Failed to serialize a bridge message.
    #[snafu(display("failed to encode bridge message at {location}: {source}"))]
    Encode {
        /// Underlying serialization error.
        source: postcard::Error,
        /// Source location where the error was attached.
        #[snafu(implicit)]
        location: Location,
    },

    /// Failed to deserialize a bridge message.
    #[snafu(display("failed to decode bridge message at {location}: {source}"))]
    Decode {
        /// Underlying deserialization error.
        source: postcard::Error,
        /// Source location where the error was attached.
        #[snafu(implicit)]
        location: Location,
    },

    /// A request was missing the capability grant required by its task.
    #[snafu(display(
        "request {request_id} is missing required capability grant {capability:?} at {location}"
    ))]
    MissingCapability {
        /// Request identifier.
        request_id: Ulid,
        /// Capability required by the task.
        capability: Capability,
        /// Source location where the error was attached.
        #[snafu(implicit)]
        location: Location,
    },

    /// The runtime response did not correspond to the submitted request.
    #[snafu(display(
        "response request id {response_id} did not match submitted request {request_id} at {location}"
    ))]
    ResponseRequestMismatch {
        /// Submitted request identifier.
        request_id: Ulid,
        /// Response request identifier.
        response_id: Ulid,
        /// Source location where the error was attached.
        #[snafu(implicit)]
        location: Location,
    },

    /// Transport-level failure.
    #[snafu(display("bridge transport error at {location}: {message}"))]
    Transport {
        /// Transport-specific failure message.
        message: CompactString,
        /// Source location where the error was attached.
        #[snafu(implicit)]
        location: Location,
    },
}

impl Error {
    /// Build a transport error from an implementation-specific message.
    #[must_use]
    pub fn transport(message: impl Into<CompactString>) -> Self {
        Self::Transport {
            message: message.into(),
            location: Location::generate(),
        }
    }
}
