//! metaxu's std-side wrapper over `metaxu_core::session` (#544/#545): the
//! authenticated session TYPES are the canonical `metaxu-core` ones
//! (re-exported below so `crate::session::X` keeps resolving for every
//! existing caller in this crate); only the two encode/decode FUNCTIONS
//! need a wrapper here, to convert [`metaxu_core::error::CoreError`] into
//! this crate's own [`crate::error::Error`] at the boundary, preserving
//! `BridgeClient::submit_authenticated`'s existing error shape.

pub use metaxu_core::session::{AuthenticatedRequest, AuthenticatedResponse, AuthenticatedSession};

use metaxu_core::protocol::TaskRequest;

/// Encode an authenticated task request for transport (#544). See
/// `metaxu_core::session::encode_authenticated_request` for the wire
/// contract; this wrapper only maps the error type.
///
/// Time: O(n) where n is the combined encoded size of `request` and the
/// session's signed grant -- dominated by the wrapped call's clone of
/// `request`, its postcard encoding, and the envelope build/encode, each
/// linear in that size.
/// Space: O(n) -- the cloned request, the postcard-encoded payload, and
/// the final encoded frame are each proportional to that size.
pub(crate) fn encode_authenticated_request(
    session: &AuthenticatedSession,
    request: &TaskRequest,
) -> crate::error::Result<Vec<u8>> {
    metaxu_core::session::encode_authenticated_request(session, request)
        .map_err(crate::error::Error::from_core)
}

/// Decode an authenticated task response from transport bytes (#544). See
/// `metaxu_core::session::decode_authenticated_response` for the wire
/// contract; this wrapper only maps the error type.
///
/// Time: O(n) where n is `bytes.len()` -- the wrapped call's envelope
/// decode copies the payload once and the postcard deserialize of the
/// `AuthenticatedResponse` is linear in that same payload.
/// Space: O(n) -- the decoded envelope payload and the deserialized
/// response are each proportional to `bytes.len()`.
pub(crate) fn decode_authenticated_response(
    bytes: &[u8],
) -> crate::error::Result<AuthenticatedResponse> {
    metaxu_core::session::decode_authenticated_response(bytes)
        .map_err(crate::error::Error::from_core)
}
