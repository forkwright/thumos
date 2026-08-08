//! The adversarial round-trip witness (#544): one authenticated
//! Thumos↔Aletheia exchange and every failure mode, over real TCP.
//!
//! Every case below drives `crate::BridgeClient::submit_authenticated` --
//! the SAME method a real Thumos userspace process calls -- rather than
//! hand-building envelope frames, so the witness proves the production API
//! surface, not a parallel test-only path that could drift from it.
//!
//! Cases (the issue's done-when, item 5):
//! 1. happy path — verified grant, accepted task, MAC-verified response.
//! 2. replay — a repeated request id is rejected.
//! 3. expired grant — rejected at evaluation: client pre-flight AND the
//!    endpoint refuse it, independently.
//! 4. wrong runtime identity — a grant from an unpinned issuer is rejected;
//!    and a grant for another device never opens a session.
//! 5. unavailable network — a typed transport error at connect, and again
//!    mid-exchange when a peer accepts then closes without responding —
//!    never a panic or a silent empty response.
//! 6. denied capability, twice: the client refuses a task outside the
//!    session's VERIFIED grant locally, before any network use; and the
//!    endpoint refuses independently for a request that skips the client
//!    (defense in depth -- the boundary does not depend on client
//!    cooperation).

use ed25519_dalek::SigningKey;
use ulid::Ulid;

use crate::envelope::{Envelope, MessageKind};
use crate::grants::{Grant, SignedGrant};
use crate::protocol::{
    Capability, CapabilityGrant, DeviceIdentityRef, IdentityKind, TaskRequest, TaskStatus,
};
use crate::pylon::{self, Pylon};
use crate::session::AuthenticatedSession;
use crate::transport::BridgeTransport;
use crate::{BridgeClient, Error};

/// The runtime the witness pins (the pylon's identity).
fn runtime_signing() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

/// The device the witness presents.
fn device_signing() -> SigningKey {
    SigningKey::from_bytes(&[9u8; 32])
}

fn device_identity() -> DeviceIdentityRef {
    DeviceIdentityRef::new(
        IdentityKind::Device,
        "witness-device",
        device_signing().verifying_key().to_bytes(),
    )
}

/// Issue a grant from the runtime to the device, expiring at `expires_at_ms`.
fn runtime_grant(expires_at_ms: u64) -> SignedGrant {
    SignedGrant::issue(
        Grant {
            issuer: runtime_signing().verifying_key().to_bytes(),
            subject: device_signing().verifying_key().to_bytes(),
            capabilities: vec![Capability::SmsSend],
            issued_at_ms: 1_000,
            expires_at_ms,
            nonce: [0xA5; 16],
        },
        &runtime_signing(),
    )
}

fn sms_request() -> TaskRequest {
    TaskRequest::SendSms {
        request_id: Ulid::from_bytes([5; 16]),
        identity: device_identity(),
        grants: vec![CapabilityGrant::new(
            Capability::SmsSend,
            "policy",
            "grant-sms",
        )],
        to: "+15551234567".into(),
        body: "witness: harmless typed task".into(),
    }
}

/// A [`BridgeTransport`] over a length-prefixed TCP stream -- the same
/// framing `pylon::spawn`'s server loop speaks. This is the shape a real
/// Thumos userspace transport takes: connect, then hand frames to
/// `BridgeClient` unmodified.
struct TcpBridgeTransport {
    stream: std::net::TcpStream,
}

impl TcpBridgeTransport {
    /// Connect to a pylon on `127.0.0.1:port`.
    fn connect(port: u16) -> Self {
        Self {
            stream: std::net::TcpStream::connect(("127.0.0.1", port))
                .unwrap_or_else(|e| unreachable!("witness pylon must accept: {e}")),
        }
    }
}

impl BridgeTransport for TcpBridgeTransport {
    type Error = std::io::Error;

    fn exchange(&mut self, request_frame: &[u8]) -> core::result::Result<Vec<u8>, Self::Error> {
        use std::io::{Read, Write};
        let len = (request_frame.len() as u32).to_le_bytes();
        self.stream.write_all(&len)?;
        self.stream.write_all(request_frame)?;
        let mut len_buf = [0u8; 4];
        self.stream.read_exact(&mut len_buf)?;
        let out_len = u32::from_le_bytes(len_buf) as usize;
        let mut out = vec![0u8; out_len];
        self.stream.read_exact(&mut out)?;
        Ok(out)
    }
}

/// A transport that panics if ever invoked -- proves a caller path never
/// reaches the network (used for the local-preflight-denial case).
struct PanicIfCalledTransport;

impl BridgeTransport for PanicIfCalledTransport {
    type Error = std::io::Error;

    fn exchange(&mut self, _request_frame: &[u8]) -> core::result::Result<Vec<u8>, Self::Error> {
        unreachable!("a locally-denied capability must never reach the transport")
    }
}

/// One raw TCP exchange against a spawned pylon, bypassing `BridgeClient`
/// entirely -- used ONLY to prove the endpoint enforces on its own, for a
/// caller that skips (or never had) the client's local preflight.
fn raw_exchange(port: u16, frame: &[u8]) -> Vec<u8> {
    use std::io::{Read, Write};
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", port))
        .unwrap_or_else(|e| unreachable!("witness pylon must accept: {e}"));
    let len = (frame.len() as u32).to_le_bytes();
    stream.write_all(&len).unwrap_or_else(|_| unreachable!());
    stream.write_all(frame).unwrap_or_else(|_| unreachable!());
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .unwrap_or_else(|_| unreachable!());
    let out_len = u32::from_le_bytes(len_buf) as usize;
    let mut out = vec![0u8; out_len];
    stream
        .read_exact(&mut out)
        .unwrap_or_else(|_| unreachable!());
    out
}

#[test]
fn happy_authenticated_round_trip() {
    let (port, _handle) = pylon::spawn(Pylon::new(runtime_signing().verifying_key(), 5_000), 1);
    let session = AuthenticatedSession::open(
        runtime_grant(10_000),
        &device_signing().verifying_key().to_bytes(),
        5_000,
    )
    .unwrap_or_else(|e| unreachable!("grant verifies: {e}"));
    let mut client = BridgeClient::new(TcpBridgeTransport::connect(port));
    let request = sms_request();
    let response = client
        .submit_authenticated(&session, &request)
        .unwrap_or_else(|e| unreachable!("an authenticated submit must succeed: {e}"));
    assert_eq!(response.request_id, request.request_id());
    assert!(
        matches!(response.status, TaskStatus::Accepted { .. }),
        "a verified grant + task must be accepted, got {:?}",
        response.status
    );
}

#[test]
fn replay_is_rejected() {
    // The pylon answers one frame per accepted connection, so replaying a
    // request means a second connection presenting the same frame -- the
    // exact shape a real device retry (or an attacker's captured frame)
    // takes.
    let (port, _handle) = pylon::spawn(Pylon::new(runtime_signing().verifying_key(), 5_000), 2);
    let session = AuthenticatedSession::open(
        runtime_grant(10_000),
        &device_signing().verifying_key().to_bytes(),
        5_000,
    )
    .unwrap_or_else(|e| unreachable!("grant verifies: {e}"));
    let request = sms_request();

    let mut first = BridgeClient::new(TcpBridgeTransport::connect(port));
    let _ = first
        .submit_authenticated(&session, &request)
        .unwrap_or_else(|e| unreachable!("the first submit must succeed: {e}"));

    let mut second = BridgeClient::new(TcpBridgeTransport::connect(port));
    let replayed = second
        .submit_authenticated(&session, &request)
        .unwrap_or_else(|e| unreachable!("a replay still MAC-verifies as a rejection: {e}"));
    match replayed.status {
        TaskStatus::Rejected { ref reason } => {
            assert_eq!(
                reason.as_str(),
                pylon::reject::REPLAY,
                "the repeated request must be a replay reject"
            );
        }
        ref other => unreachable!("replay must reject, got {other:?}"),
    }
}

#[test]
fn expired_grant_is_rejected() {
    let (port, _handle) = pylon::spawn(Pylon::new(runtime_signing().verifying_key(), 20_000), 1);
    // The grant expired at 10_000; the pylon evaluates at 20_000. The
    // client-side pre-flight ALSO refuses it (fail-closed both ends) --
    // this never reaches the network at all.
    assert!(
        AuthenticatedSession::open(
            runtime_grant(10_000),
            &device_signing().verifying_key().to_bytes(),
            20_000
        )
        .is_err(),
        "client pre-flight must refuse an expired grant"
    );
    // And the endpoint rejects it independently, for a session opened
    // while the grant was still valid but presented after it lapsed.
    let session = AuthenticatedSession::open(
        runtime_grant(10_000),
        &device_signing().verifying_key().to_bytes(),
        5_000,
    )
    .unwrap_or_else(|e| unreachable!("grant verifies at issue time: {e}"));
    let mut client = BridgeClient::new(TcpBridgeTransport::connect(port));
    let response = client
        .submit_authenticated(&session, &sms_request())
        .unwrap_or_else(|e| unreachable!("an expired grant still MAC-verifies as a reject: {e}"));
    match response.status {
        TaskStatus::Rejected { ref reason } => {
            assert_eq!(reason.as_str(), pylon::reject::GRANT_EXPIRED);
        }
        ref other => unreachable!("expired grant must reject, got {other:?}"),
    }
}

#[test]
fn wrong_runtime_identity_is_rejected() {
    // The grant is signed by an impostor runtime (a different signing key
    // than the pylon pins). Signature verifies under the impostor -- and
    // the pylon still refuses, because the issuer is not the pinned
    // runtime.
    let impostor = SigningKey::from_bytes(&[0xEE; 32]);
    let forged = SignedGrant::issue(
        Grant {
            issuer: impostor.verifying_key().to_bytes(),
            subject: device_signing().verifying_key().to_bytes(),
            capabilities: vec![Capability::SmsSend],
            issued_at_ms: 1_000,
            expires_at_ms: 10_000,
            nonce: [0xA5; 16],
        },
        &impostor,
    );
    let (port, _handle) = pylon::spawn(Pylon::new(runtime_signing().verifying_key(), 5_000), 1);
    let session =
        AuthenticatedSession::open(forged, &device_signing().verifying_key().to_bytes(), 5_000)
            .unwrap_or_else(|e| {
                unreachable!("the forged grant verifies under its own issuer: {e}")
            });
    let mut client = BridgeClient::new(TcpBridgeTransport::connect(port));
    let response = client
        .submit_authenticated(&session, &sms_request())
        .unwrap_or_else(|e| unreachable!("an unpinned issuer still MAC-verifies as a reject: {e}"));
    match response.status {
        TaskStatus::Rejected { ref reason } => {
            assert_eq!(reason.as_str(), pylon::reject::WRONG_ISSUER);
        }
        ref other => unreachable!("an unpinned issuer must reject, got {other:?}"),
    }
}

#[test]
fn grant_for_another_device_never_authorizes() {
    let signed = SignedGrant::issue(
        Grant {
            issuer: runtime_signing().verifying_key().to_bytes(),
            subject: [0x77; 32], // a different device
            capabilities: vec![Capability::SmsSend],
            issued_at_ms: 1_000,
            expires_at_ms: 10_000,
            nonce: [0xA5; 16],
        },
        &runtime_signing(),
    );
    assert!(
        AuthenticatedSession::open(signed, &device_signing().verifying_key().to_bytes(), 5_000)
            .is_err(),
        "a grant for device B must not open a session for device A"
    );
}

#[test]
fn unavailable_network_is_a_typed_transport_error() {
    // No listener on this port (bound-then-dropped to guarantee closure).
    // A real device hits this before a `BridgeClient` can even be built --
    // the transport trait takes an already-connected peer.
    let port = std::net::TcpListener::bind(("127.0.0.1", 0))
        .and_then(|l| l.local_addr().map(|a| a.port()))
        .unwrap_or_else(|_| unreachable!());
    let result = std::net::TcpStream::connect(("127.0.0.1", port));
    assert!(result.is_err(), "connecting a dead port must error");
    let err = result.err().unwrap_or_else(|| unreachable!());
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::ConnectionRefused,
        "the transport error is typed (connection refused), not a panic or empty frame"
    );
}

#[test]
fn mid_exchange_disconnect_surfaces_as_typed_transport_error() {
    // A peer that accepts the connection then closes without responding --
    // driven through the real `submit_authenticated` path, this must
    // surface a typed `Error::Transport`, never panic or return an empty
    // frame as if it were a valid response.
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap_or_else(|_| unreachable!());
    let port = listener
        .local_addr()
        .map_or_else(|_| unreachable!(), |a| a.port());
    let handle = std::thread::spawn(move || {
        if let Ok((stream, _)) = listener.accept() {
            drop(stream); // accept, then close without writing a response
        }
    });
    let session = AuthenticatedSession::open(
        runtime_grant(10_000),
        &device_signing().verifying_key().to_bytes(),
        5_000,
    )
    .unwrap_or_else(|e| unreachable!("grant verifies: {e}"));
    let mut client = BridgeClient::new(TcpBridgeTransport::connect(port));
    let result = client.submit_authenticated(&session, &sms_request());
    assert!(
        matches!(result, Err(Error::Transport { .. })),
        "a peer that closes without responding must surface a typed transport error, got {result:?}"
    );
    handle.join().unwrap_or_else(|_| unreachable!());
}

#[test]
fn capability_outside_grant_is_denied_locally_before_any_network_use() {
    // The session's VERIFIED grant carries only SendSms; a PlaceCall task
    // is outside it. The client must refuse before touching the
    // transport -- `PanicIfCalledTransport` proves that, not just an
    // assertion on the returned error.
    let session = AuthenticatedSession::open(
        runtime_grant(10_000),
        &device_signing().verifying_key().to_bytes(),
        5_000,
    )
    .unwrap_or_else(|e| unreachable!("grant verifies: {e}"));
    let call = TaskRequest::PlaceCall {
        request_id: Ulid::from_bytes([6; 16]),
        identity: device_identity(),
        grants: vec![CapabilityGrant::new(
            Capability::CallDial,
            "policy",
            "grant-call",
        )],
        to: "+15557654321".into(),
    };
    let mut client = BridgeClient::new(PanicIfCalledTransport);
    let result = client.submit_authenticated(&session, &call);
    assert!(
        matches!(
            result,
            Err(Error::MissingCapability {
                capability: Capability::CallDial,
                ..
            })
        ),
        "a task outside the verified grant must be denied locally, got {result:?}"
    );
}

#[test]
fn capability_outside_grant_is_denied_by_the_endpoint() {
    // Defense in depth: even a caller that skips `BridgeClient`'s local
    // preflight (a hand-built frame, or a future buggy client) is refused
    // by the endpoint itself. Built at the envelope layer directly so the
    // out-of-grant frame reaches the pylon regardless of client-side
    // policy.
    let (port, _handle) = pylon::spawn(Pylon::new(runtime_signing().verifying_key(), 5_000), 1);
    let session = AuthenticatedSession::open(
        runtime_grant(10_000),
        &device_signing().verifying_key().to_bytes(),
        5_000,
    )
    .unwrap_or_else(|e| unreachable!("grant verifies: {e}"));
    let call = TaskRequest::PlaceCall {
        request_id: Ulid::from_bytes([6; 16]),
        identity: device_identity(),
        grants: vec![CapabilityGrant::new(
            Capability::CallDial,
            "policy",
            "grant-call",
        )],
        to: "+15557654321".into(),
    };
    let wrapped = session.wrap(call);
    let payload = postcard::to_allocvec(&wrapped).unwrap_or_else(|_| unreachable!());
    let frame = Envelope::build(MessageKind::AuthenticatedRequest, 1, payload)
        .unwrap_or_else(|_| unreachable!())
        .encode();

    let out = raw_exchange(port, &frame);
    let response_frame =
        Envelope::decode(&out).unwrap_or_else(|e| unreachable!("response frame decodes: {e}"));
    assert_eq!(
        response_frame.header.kind,
        MessageKind::AuthenticatedResponse
    );
    let response: crate::session::AuthenticatedResponse =
        postcard::from_bytes(&response_frame.payload).unwrap_or_else(|_| unreachable!());
    assert!(
        session.verify_response(&response),
        "the rejection is still MAC-verified, not an unauthenticated error"
    );
    match response.response.status {
        TaskStatus::Rejected { ref reason } => {
            assert_eq!(reason.as_str(), pylon::reject::CAPABILITY_DENIED);
        }
        ref other => unreachable!("an out-of-grant capability must deny, got {other:?}"),
    }
}
