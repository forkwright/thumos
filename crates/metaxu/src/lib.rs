#![deny(missing_docs)]
//! Thin capability bridge between Thumos device services and an
//! Aletheia/Menos-resident runtime.
//!
//! `metaxu` defines the typed wire boundary only: task requests, capability
//! grant claims, device-identity references, responses, and a synchronous
//! transport abstraction. It intentionally does not embed runtime logic,
//! authenticate grants, or require live Menos connectivity.

mod client;
mod error;
mod protocol;
mod transport;

use snafu::OptionExt as _;

pub use client::BridgeClient; // kanon:ignore RUST/pub-visibility -- public API
pub use error::{Error, Result};
pub use protocol::{
    AudioMode, Capability, CapabilityGrant, ContactSummary, DeviceAction, DeviceIdentityRef,
    IdentityKind, TaskRequest, TaskResponse, TaskStatus,
};
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
    /// transport failures,
    /// [`Error::Decode`] for malformed responses, and
    /// [`Error::ResponseRequestMismatch`] when the runtime answers another
    /// request id.
    pub fn submit(&mut self, request: &TaskRequest) -> Result<TaskResponse> {
        request
            .has_required_capability()
            .then_some(())
            .context(error::MissingCapabilitySnafu {
                request_id: request.request_id(),
                capability: request.required_capability(),
            })?;

        let request_id = request.request_id();
        let request_frame = encode_request(request)?;
        let response_frame = self.transport.exchange(&request_frame)?;
        let response = decode_response(&response_frame)?;

        (response.request_id == request_id).then_some(()).context(
            error::ResponseRequestMismatchSnafu {
                request_id,
                response_id: response.request_id,
            },
        )?;

        Ok(response)
    }
}

/// Serialize a task request for transport.
///
/// # Errors
///
/// Returns [`Error::Encode`] if the request cannot be serialized.
pub fn encode_request(request: &TaskRequest) -> Result<Vec<u8>> {
    protocol::encode_request(request)
}

/// Deserialize a task request from transport bytes.
///
/// # Errors
///
/// Returns [`Error::Decode`] if the frame is malformed.
pub fn decode_request(bytes: &[u8]) -> Result<TaskRequest> {
    protocol::decode_request(bytes)
}

/// Serialize a task response for transport.
///
/// # Errors
///
/// Returns [`Error::Encode`] if the response cannot be serialized.
pub fn encode_response(response: &TaskResponse) -> Result<Vec<u8>> {
    protocol::encode_response(response)
}

/// Deserialize a task response from transport bytes.
///
/// # Errors
///
/// Returns [`Error::Decode`] if the frame is malformed.
pub fn decode_response(bytes: &[u8]) -> Result<TaskResponse> {
    protocol::decode_response(bytes)
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

        assert!(matches!(result, Err(Error::Decode { .. })));
    }

    #[test]
    fn decode_response_rejects_malformed_bytes() {
        let result = decode_response(&[]);

        assert!(matches!(result, Err(Error::Decode { .. })));
    }
}
