//! Error types for the Aletheia bridge.

use snafu::{GenerateImplicitData as _, Location, Snafu};
use ulid::Ulid;

use crate::protocol::Capability;

/// Result type for bridge operations.
///
/// `E` is the transport-specific failure type carried by [`Error::Transport`];
/// call sites that can never produce a transport error (encode/decode paths)
/// use the `Infallible` default so the source chain is preserved without
/// forcing every caller to name a transport error type.
pub type Result<T, E = core::convert::Infallible> = std::result::Result<T, Error<E>>; // kanon:ignore RUST/pub-visibility -- public API

/// Aletheia bridge errors.
///
/// Generic over `E`, the transport-specific failure type carried by
/// [`Error::Transport`]. `E` defaults to [`core::convert::Infallible`] for
/// call sites that can never produce a transport error.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
#[non_exhaustive]
pub enum Error<E = core::convert::Infallible>
where
    E: std::error::Error + 'static,
{
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

    /// The wire envelope rejected a frame (bad magic, version, kind,
    /// size, or shape) before any payload decode (#553).
    #[snafu(display("envelope rejected frame at {location}: {source}"))]
    Envelope {
        /// The envelope-level rejection.
        source: crate::envelope::EnvelopeError,
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

    /// An authenticated response's MAC did not verify under the session's
    /// grant response key -- the response cannot be trusted: it may be
    /// tampered, forged by a party that never held the grant's nonce, or
    /// corrupted in transit. The response is discarded unread.
    #[snafu(display(
        "authenticated response for request {request_id} failed MAC verification at {location}"
    ))]
    ResponseAuthenticationFailed {
        /// Submitted request identifier.
        request_id: Ulid,
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
    ///
    /// `source` preserves the concrete failure produced by the
    /// [`crate::BridgeTransport`] implementation in use, so the cause is
    /// walkable and downcastable instead of collapsed into a message string.
    #[snafu(display("bridge transport error at {location}: {source}"))]
    Transport {
        /// Underlying transport failure.
        source: E,
        /// Source location where the error was attached.
        #[snafu(implicit)]
        location: Location,
    },
}

impl<E> Error<E>
where
    E: std::error::Error + 'static,
{
    /// Build a transport error from an implementation-specific cause.
    #[must_use]
    pub fn transport(source: E) -> Self {
        Self::Transport {
            source,
            location: Location::generate(),
        }
    }
}

impl Error<core::convert::Infallible> {
    /// Convert a `metaxu-core` encode/decode failure into this crate's own
    /// error shape (#545): `metaxu-core` is `no_std` and has no
    /// `snafu::Location`/transport concept of its own, so every
    /// `metaxu_core::error::CoreError` produced by a core wire function is
    /// mapped here, preserving `Error::{Encode,Decode,Envelope}`'s existing
    /// public shape for every caller in this crate.
    pub(crate) fn from_core(err: metaxu_core::error::CoreError) -> Self {
        match err {
            metaxu_core::error::CoreError::Encode(source) => Self::Encode {
                source,
                location: Location::generate(),
            },
            metaxu_core::error::CoreError::Decode(source) => Self::Decode {
                source,
                location: Location::generate(),
            },
            metaxu_core::error::CoreError::Envelope(source) => Self::Envelope {
                source,
                location: Location::generate(),
            },
        }
    }

    // WHY: encode/decode/capability call sites are fixed at the
    // `Infallible` placeholder so they never name a transport error type;
    // widen() composes their result with a caller's transport-typed
    // `Error<E>` via `.map_err(|err| err.widen())` at the `?` site. A plain
    // blanket `From<Error<Infallible>> for Error<E>` impl would conflict
    // with core's reflexive `impl<T> From<T> for T` at `E = Infallible`
    // (E0119), so this is an inherent method instead of a trait impl.
    pub(crate) const fn widen<E>(self) -> Error<E>
    where
        E: std::error::Error + 'static,
    {
        match self {
            Self::Encode { source, location } => Error::Encode { source, location },
            Self::Decode { source, location } => Error::Decode { source, location },
            Self::MissingCapability {
                request_id,
                capability,
                location,
            } => Error::MissingCapability {
                request_id,
                capability,
                location,
            },
            Self::Envelope { source, location } => Error::Envelope { source, location },
            Self::ResponseAuthenticationFailed {
                request_id,
                location,
            } => Error::ResponseAuthenticationFailed {
                request_id,
                location,
            },
            Self::ResponseRequestMismatch {
                request_id,
                response_id,
                location,
            } => Error::ResponseRequestMismatch {
                request_id,
                response_id,
                location,
            },
            Self::Transport { source, .. } => match source {},
        }
    }
}

#[cfg(test)]
mod tests {
    use snafu::GenerateImplicitData as _;

    use super::*;

    #[test]
    fn transport_error_preserves_concrete_source() {
        let cause = std::io::Error::other("socket reset by peer");
        let cause_message = cause.to_string();
        let error = Error::transport(cause);

        let source = std::error::Error::source(&error);
        let downcast = source.and_then(|inner| inner.downcast_ref::<std::io::Error>());

        assert!(
            downcast.is_some(),
            "concrete io::Error must survive through Error::Transport unstringified"
        );
        assert_eq!(
            downcast.map(std::string::ToString::to_string),
            Some(cause_message)
        );
    }

    #[test]
    fn transport_variant_matches_on_typed_source() {
        let error = Error::transport(std::io::Error::other("connection reset"));

        assert!(matches!(
            error,
            Error::Transport { source, .. } if source.kind() == std::io::ErrorKind::Other
        ));
    }

    #[test]
    fn widen_preserves_non_transport_variant_shape() {
        let request_id = Ulid::from_bytes([1; 16]);
        let narrow: Error = Error::MissingCapability {
            request_id,
            capability: Capability::ContactsRead,
            location: Location::generate(),
        };

        let widened: Error<std::io::Error> = narrow.widen();

        assert!(matches!(
            widened,
            Error::MissingCapability { request_id: seen, .. } if seen == request_id
        ));
    }
}
