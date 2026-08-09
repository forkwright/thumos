#![deny(missing_docs)]
//! Thin capability bridge between Thumos device services and an
//! Aletheia/Menos-resident runtime.
//!
//! `metaxu` defines the typed wire boundary: task requests, capability grant
//! claims, device-identity references, responses, and a synchronous
//! transport abstraction. It intentionally does not embed runtime logic or
//! require live Menos connectivity.
//!
//! Two request paths exist. [`BridgeClient::submit`] sends a bare
//! [`TaskRequest`] and only checks that the task carries a self-claimed
//! [`CapabilityGrant`] locally -- suitable for an in-process transport where
//! the runtime boundary is trusted by construction (tests, a same-address-
//! space stub). [`BridgeClient::submit_authenticated`] (#544) is the path
//! for an actual network peer: it presents a cryptographically verified,
//! expiring [`SignedGrant`] on every request and refuses any response whose
//! MAC does not prove the responder held the grant's signed nonce.

mod client;
mod error;
mod session;
mod transport;
#[cfg(test)]
mod vectors;
#[cfg(test)]
mod witness;
// WHY (#544 on-device leg): un-gated from `#[cfg(test)]` to `pylon-bin` so a
// standalone host binary (src/bin/pylon_bridge.rs) can launch the SAME
// reference endpoint double the adversarial witness runs against, as a real
// process a QEMU-booted kernel talks to over a second UART -- reusing
// verification logic instead of a second, driftable reimplementation.
#[cfg(any(test, feature = "pylon-bin"))]
pub mod pylon;

// WHY (#545): the envelope framing, signed-grant verification, and typed
// task/response payloads are canonically defined in metaxu-core (no_std +
// alloc, shared with the kernel) -- re-exported here as modules so every
// existing `crate::envelope::X` / `crate::grants::X` / `crate::protocol::X`
// reference in this crate keeps resolving unchanged. `grants` is used only
// by test-gated code (witness.rs, pylon.rs) -- cfg-gated the same way, or
// it is an unused-import error on a plain (non-test, non-pylon-bin) build.
#[cfg(any(test, feature = "pylon-bin"))]
pub(crate) use metaxu_core::grants;
pub(crate) use metaxu_core::{envelope, protocol};

use snafu::{OptionExt as _, ResultExt as _};

pub use client::BridgeClient; // kanon:ignore RUST/pub-visibility -- public API
pub use error::{Error, Result};
pub use metaxu_core::envelope::{EnvelopeError, MessageKind, SttErrorCode, SttEvent}; // kanon:ignore RUST/pub-visibility -- public API
pub use metaxu_core::grants::{Grant, GrantError, SignedGrant}; // kanon:ignore RUST/pub-visibility -- public API
pub use metaxu_core::protocol::{
    AudioMode, Capability, CapabilityGrant, ContactSummary, DeviceAction, DeviceIdentityRef,
    IdentityKind, TaskRequest, TaskResponse, TaskStatus,
};
pub use session::{AuthenticatedRequest, AuthenticatedResponse, AuthenticatedSession}; // kanon:ignore RUST/pub-visibility -- public API
pub use transport::BridgeTransport; // kanon:ignore RUST/pub-visibility -- public API

impl<T> BridgeClient<T>
where
    T: BridgeTransport,
{
    /// Construct a bridge client around a transport implementation.
    #[must_use]
    pub const fn new(transport: T) -> Self {
        Self { transport }
    }

    /// Return the underlying transport.
    #[must_use]
    pub fn into_transport(self) -> T {
        self.transport
    }

    /// Serialize a request, exchange it with the runtime boundary, and parse
    /// the response.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MissingCapability`] when local preflight does not find
    /// a grant claim for the required capability, [`Error::Transport`] for
    /// transport failures (wrapping `T::Error` so the concrete transport
    /// cause is preserved rather than stringified),
    /// [`Error::Decode`] for malformed responses, and
    /// [`Error::ResponseRequestMismatch`] when the runtime answers another
    /// request id.
    pub fn submit(&mut self, request: &TaskRequest) -> Result<TaskResponse, T::Error> {
        request
            .has_required_capability()
            .then_some(())
            .context(error::MissingCapabilitySnafu {
                request_id: request.request_id(),
                capability: request.required_capability(),
            })?;

        let request_id = request.request_id();
        let request_frame = encode_request(request).map_err(error::Error::widen)?;
        let response_frame = self
            .transport
            .exchange(&request_frame)
            .context(error::TransportSnafu)?;
        let response = decode_response(&response_frame).map_err(error::Error::widen)?;

        (response.request_id == request_id).then_some(()).context(
            error::ResponseRequestMismatchSnafu {
                request_id,
                response_id: response.request_id,
            },
        )?;

        Ok(response)
    }

    /// Submit a task through a mutually authenticated session (#544): the
    /// device presents a cryptographically verified, expiring grant on
    /// every request and refuses any response whose MAC does not prove the
    /// responder held the grant's signed nonce. This is the path a real
    /// network-connected caller uses; [`Self::submit`] is for a trusted
    /// in-process transport only.
    ///
    /// Capability enforcement here checks the session's VERIFIED grant
    /// (`session.grant().grant.capabilities`) -- never the task's
    /// self-claimed wire [`CapabilityGrant`] list [`Self::submit`] checks.
    /// A caller cannot talk itself into a capability the runtime never
    /// actually granted; this is the local confirmation gate the runtime
    /// endpoint's own check backs up, not a substitute for it.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MissingCapability`] when the session's verified
    /// grant does not cover the task's required capability -- checked
    /// locally, before anything is sent. [`Error::Envelope`] /
    /// [`Error::Encode`] if the request cannot be framed.
    /// [`Error::Transport`] for transport failures (wrapping `T::Error` so
    /// the concrete transport cause is preserved). [`Error::Envelope`] /
    /// [`Error::Decode`] for a malformed response frame.
    /// [`Error::ResponseAuthenticationFailed`] when the response MAC does
    /// not verify under the session's grant -- the response is discarded,
    /// never trusted. [`Error::ResponseRequestMismatch`] when the runtime
    /// answers another request id.
    pub fn submit_authenticated(
        &mut self,
        session: &AuthenticatedSession,
        request: &TaskRequest,
    ) -> Result<TaskResponse, T::Error> {
        let required = request.required_capability();
        session
            .grant()
            .grant
            .capabilities
            .contains(&required)
            .then_some(())
            .context(error::MissingCapabilitySnafu {
                request_id: request.request_id(),
                capability: required,
            })?;

        let request_id = request.request_id();
        let request_frame =
            session::encode_authenticated_request(session, request).map_err(error::Error::widen)?;
        let response_frame = self
            .transport
            .exchange(&request_frame)
            .context(error::TransportSnafu)?;
        let authenticated =
            session::decode_authenticated_response(&response_frame).map_err(error::Error::widen)?;

        session
            .verify_response(&authenticated)
            .then_some(())
            .context(error::ResponseAuthenticationFailedSnafu { request_id })?;

        (authenticated.response.request_id == request_id)
            .then_some(())
            .context(error::ResponseRequestMismatchSnafu {
                request_id,
                response_id: authenticated.response.request_id,
            })?;

        Ok(authenticated.response)
    }
}

/// Serialize a task request for transport.
///
/// # Errors
///
/// Returns [`Error::Encode`] if the request cannot be serialized.
pub fn encode_request(request: &TaskRequest) -> Result<Vec<u8>> {
    protocol::encode_request(request).map_err(error::Error::from_core)
}

/// Deserialize a task request from transport bytes.
///
/// # Errors
///
/// Returns [`Error::Decode`] if the frame is malformed.
pub fn decode_request(bytes: &[u8]) -> Result<TaskRequest> {
    protocol::decode_request(bytes).map_err(error::Error::from_core)
}

/// Serialize a task response for transport.
///
/// # Errors
///
/// Returns [`Error::Encode`] if the response cannot be serialized.
pub fn encode_response(response: &TaskResponse) -> Result<Vec<u8>> {
    protocol::encode_response(response).map_err(error::Error::from_core)
}

/// Deserialize a task response from transport bytes.
///
/// # Errors
///
/// Returns [`Error::Decode`] if the frame is malformed.
pub fn decode_response(bytes: &[u8]) -> Result<TaskResponse> {
    protocol::decode_response(bytes).map_err(error::Error::from_core)
}

#[cfg(test)]
mod tests {
    use compact_str::CompactString;
    use ulid::Ulid;

    use super::{
        Capability, CapabilityGrant, DeviceIdentityRef, Error, IdentityKind, TaskRequest,
        decode_request, decode_response, encode_request,
    };

    #[test]
    fn crate_exports_encode_decode_round_trip() -> Result<(), Error> {
        let request = TaskRequest::LookupContact {
            request_id: Ulid::from_bytes([3; 16]),
            identity: DeviceIdentityRef::new(IdentityKind::Device, "device-ref", [9; 32]),
            grants: vec![CapabilityGrant::new(
                Capability::ContactsRead,
                "policy",
                "grant-contact",
            )],
            query: CompactString::from("Ada"),
        };

        let encoded = encode_request(&request)?;
        let decoded = decode_request(&encoded)?;

        assert_eq!(decoded, request);
        Ok(())
    }

    #[test]
    fn decode_request_rejects_malformed_bytes() {
        let result = decode_request(&[]);

        // #553: the envelope layer rejects first (truncated header), so a
        // malformed frame can never reach the postcard decoder.
        assert!(matches!(result, Err(Error::Envelope { .. })));
    }

    #[test]
    fn decode_request_rejects_malformed_payload()
    -> core::result::Result<(), crate::envelope::EnvelopeError> {
        // A well-formed envelope whose payload is not a valid TaskRequest:
        // the envelope passes, the postcard layer rejects.
        let frame = crate::envelope::Envelope::build(
            crate::envelope::MessageKind::TaskRequest,
            1,
            vec![0xFF, 0xFF, 0xFF],
        )?;
        let result = decode_request(&frame.encode());
        assert!(matches!(result, Err(Error::Decode { .. })));
        Ok(())
    }

    #[test]
    fn decode_response_rejects_malformed_bytes() {
        let result = decode_response(&[]);

        assert!(matches!(result, Err(Error::Envelope { .. })));
    }
}
