//! The authenticated session layer (#544): one mutually authenticated
//! Thumos↔Aletheia round trip over the versioned envelope.
//!
//! Two payload kinds extend the contract additively (envelope MINOR 1,
//! exercising the #553 compat rule — known kinds decode identically on both
//! sides, unknown ones reject loudly):
//!
//! - `AuthenticatedRequest` (kind 4): `SignedGrant` + `TaskRequest`. The
//!   device presents a cryptographically verified, expiring grant bound to
//!   both identities on EVERY request — there is no session state to
//!   confuse, and a stateless endpoint can verify each request alone.
//! - `AuthenticatedResponse` (kind 5): `TaskResponse` + an HMAC-SHA256 over
//!   the response payload, keyed by HKDF from the grant's nonce (see
//!   grants.rs). A verified response proves the responder knows the signed
//!   nonce — the mutual half of the authentication.
//!
//! The pylon (`crate::pylon`) is the reference endpoint double the
//! adversarial witness runs against.

use serde::{Deserialize, Serialize};
use snafu::{IntoError as _, ResultExt as _};

use crate::envelope::{Envelope, MessageKind};
use crate::error::{DecodeSnafu, EncodeSnafu, EnvelopeSnafu};
use crate::grants::SignedGrant;
use crate::protocol::{TaskRequest, TaskResponse, correlation_of};

/// An authenticated task request: the verified grant plus the typed task
/// (#544). Envelope kind 4 (MINOR 1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticatedRequest {
    /// The device's grant for this task's capabilities.
    pub signed_grant: SignedGrant,
    /// The task being requested.
    pub request: TaskRequest,
}

/// An authenticated task response: the typed response plus its
/// grant-nonce-keyed HMAC (#544). Envelope kind 5 (MINOR 1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticatedResponse {
    /// The task response.
    pub response: TaskResponse,
    /// HMAC-SHA256 over `postcard::to_allocvec(response)` under the grant's
    /// response key.
    pub mac: [u8; 32],
}

impl AuthenticatedResponse {
    /// Build an authenticated response for `response` under `grant`'s
    /// response key.
    pub fn build(signed_grant: &SignedGrant, response: TaskResponse) -> Self {
        let payload = postcard::to_allocvec(&response).unwrap_or_default();
        let mac = crate::grants::response_mac(&signed_grant.response_key(), &[&payload]);
        Self { response, mac }
    }

    /// Verify the response MAC under `signed_grant`'s response key.
    pub fn verify(&self, signed_grant: &SignedGrant) -> bool {
        let payload = postcard::to_allocvec(&self.response).unwrap_or_default();
        let expected = crate::grants::response_mac(&signed_grant.response_key(), &[&payload]);
        // Constant-time comparison for a 32-byte MAC.
        expected
            .iter()
            .zip(self.mac.iter())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0
    }
}

/// The device's side of an authenticated exchange: present a grant, send a
/// task, verify the response MAC (#544).
#[derive(Debug, Clone)]
pub struct AuthenticatedSession {
    signed_grant: SignedGrant,
}

impl AuthenticatedSession {
    /// Open a session for `signed_grant`, after checking the grant is for
    /// this device and unexpired at `now_ms` — a client never presents a
    /// grant it cannot verify (fail-closed pre-flight).
    pub fn open(
        signed_grant: SignedGrant,
        device: &[u8; 32],
        now_ms: u64,
    ) -> core::result::Result<Self, crate::grants::GrantError> {
        signed_grant.verify(device, now_ms)?;
        Ok(Self { signed_grant })
    }

    /// The session's grant.
    pub const fn grant(&self) -> &SignedGrant {
        &self.signed_grant
    }

    /// Wrap a task request for the wire.
    pub fn wrap(&self, request: TaskRequest) -> AuthenticatedRequest {
        AuthenticatedRequest {
            signed_grant: self.signed_grant.clone(),
            request,
        }
    }

    /// Verify a received authenticated response: MAC valid under the
    /// grant's response key AND the response answers this session's
    /// outstanding request (the caller checks the id match against its
    /// request, as `BridgeClient` already enforces).
    pub fn verify_response(&self, response: &AuthenticatedResponse) -> bool {
        response.verify(&self.signed_grant)
    }
}

/// Encode an authenticated task request for transport, wrapped in the
/// versioned envelope (kind 4, MINOR 1) (#544). This is the ONLY place a
/// wire frame for the authenticated exchange is built -- `BridgeClient`
/// and the adversarial witness both go through it, so there is one
/// encoding, not a client copy and a test copy that can drift apart.
pub(crate) fn encode_authenticated_request(
    session: &AuthenticatedSession,
    request: &TaskRequest,
) -> crate::error::Result<Vec<u8>> {
    let wrapped = session.wrap(request.clone());
    let payload = postcard::to_allocvec(&wrapped).context(EncodeSnafu)?;
    let frame = Envelope::build(
        MessageKind::AuthenticatedRequest,
        correlation_of(request.request_id()),
        payload,
    )
    .context(EnvelopeSnafu)?;
    Ok(frame.encode())
}

/// Decode an authenticated task response from transport bytes (kind 5,
/// MINOR 1) (#544).
///
/// Does NOT verify the MAC -- the returned value is untrusted wire data
/// until the caller checks it against the session, via
/// [`AuthenticatedSession::verify_response`]. Splitting decode from verify
/// keeps "parsed" and "trusted" distinct states, so a caller cannot act on
/// a well-formed-but-unverified response by forgetting a step.
pub(crate) fn decode_authenticated_response(
    bytes: &[u8],
) -> crate::error::Result<AuthenticatedResponse> {
    let frame = Envelope::decode(bytes).context(EnvelopeSnafu)?;
    if frame.header.kind != MessageKind::AuthenticatedResponse {
        return Err(
            EnvelopeSnafu.into_error(crate::envelope::EnvelopeError::UnexpectedKind {
                expected: MessageKind::AuthenticatedResponse,
                got: frame.header.kind,
            }),
        );
    }
    postcard::from_bytes(&frame.payload).context(DecodeSnafu)
}
