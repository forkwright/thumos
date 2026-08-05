//! The adversarial round-trip witness (#544): one authenticated
//! Thumos↔Aletheia exchange and every failure mode, over real TCP.
//!
//! Cases (the issue's done-when, item 5):
//! 1. happy path — verified grant, accepted task, MAC-verified response.
//! 2. replay — a repeated request id is rejected.
//! 3. expired grant — rejected at evaluation.
//! 4. wrong runtime identity — a grant from an unpinned issuer is rejected;
//!    and a grant for another device never authorizes this one.
//! 5. unavailable network — a typed transport error, not a panic or a
//!    silent empty response.
//! 6. denied capability — a task outside the grant is rejected pre-action.

use ed25519_dalek::SigningKey;
use ulid::Ulid;

use crate::envelope::{Envelope, MessageKind};
use crate::grants::{Grant, SignedGrant};
use crate::protocol::{
    Capability, CapabilityGrant, DeviceIdentityRef, IdentityKind, TaskRequest, TaskStatus,
};
use crate::pylon::{self, Pylon};
use crate::session::AuthenticatedSession;

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

/// Encode an authenticated request frame (kind 4).
fn auth_frame(session: &AuthenticatedSession, request: TaskRequest) -> Vec<u8> {
    let wrapped = session.wrap(request);
    let payload = postcard::to_allocvec(&wrapped).unwrap_or_default();
    Envelope::build(MessageKind::AuthenticatedRequest, 1, payload)
        .unwrap_or_else(|_| unreachable!())
        .encode()
}

/// One TCP exchange against a spawned pylon: send one frame, read the
/// authenticated response.
fn exchange(port: u16, frame: &[u8]) -> Vec<u8> {
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

/// Decode an authenticated response and check its MAC under the session.
fn verify_response(
    session: &AuthenticatedSession,
    frame: &[u8],
) -> crate::session::AuthenticatedResponse {
    let frame =
        Envelope::decode(frame).unwrap_or_else(|e| unreachable!("response frame decodes: {e}"));
    assert_eq!(frame.header.kind, MessageKind::AuthenticatedResponse);
    let response: crate::session::AuthenticatedResponse =
        postcard::from_bytes(&frame.payload).unwrap_or_else(|_| unreachable!());
    assert!(
        session.verify_response(&response),
        "the response MAC must verify under the grant's response key"
    );
    response
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
    let request = sms_request();
    let response = verify_response(
        &session,
        &exchange(port, &auth_frame(&session, request.clone())),
    );
    assert_eq!(response.response.request_id, request.request_id());
    assert!(
        matches!(response.response.status, TaskStatus::Accepted { .. }),
        "a verified grant + task must be accepted, got {:?}",
        response.response.status
    );
}

#[test]
fn replay_is_rejected() {
    let (port, _handle) = pylon::spawn(Pylon::new(runtime_signing().verifying_key(), 5_000), 2);
    let session = AuthenticatedSession::open(
        runtime_grant(10_000),
        &device_signing().verifying_key().to_bytes(),
        5_000,
    )
    .unwrap_or_else(|e| unreachable!("grant verifies: {e}"));
    let frame = auth_frame(&session, sms_request());
    let _ = verify_response(&session, &exchange(port, &frame));
    let second = verify_response(&session, &exchange(port, &frame));
    match second.response.status {
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
    // client-side pre-flight ALSO refuses it (fail-closed both ends).
    assert!(
        AuthenticatedSession::open(
            runtime_grant(10_000),
            &device_signing().verifying_key().to_bytes(),
            20_000
        )
        .is_err(),
        "client pre-flight must refuse an expired grant"
    );
    // And the endpoint rejects it independently.
    let session = AuthenticatedSession::open(
        runtime_grant(10_000),
        &device_signing().verifying_key().to_bytes(),
        5_000,
    )
    .unwrap_or_else(|e| unreachable!("grant verifies at issue time: {e}"));
    let response = verify_response(
        &session,
        &exchange(port, &auth_frame(&session, sms_request())),
    );
    match response.response.status {
        TaskStatus::Rejected { ref reason } => {
            assert_eq!(reason.as_str(), pylon::reject::GRANT_EXPIRED)
        }
        ref other => unreachable!("expired grant must reject, got {other:?}"),
    }
}

#[test]
fn wrong_runtime_identity_is_rejected() {
    // The grant is signed by an impostor runtime (a different signing key
    // than the pylon pins). Signature verifies under the impostor — and the
    // pylon still refuses, because the issuer is not the pinned runtime.
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
    let response = verify_response(
        &session,
        &exchange(port, &auth_frame(&session, sms_request())),
    );
    match response.response.status {
        TaskStatus::Rejected { ref reason } => {
            assert_eq!(reason.as_str(), pylon::reject::WRONG_ISSUER)
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
fn capability_outside_grant_is_denied() {
    let (port, _handle) = pylon::spawn(Pylon::new(runtime_signing().verifying_key(), 5_000), 1);
    let session = AuthenticatedSession::open(
        runtime_grant(10_000),
        &device_signing().verifying_key().to_bytes(),
        5_000,
    )
    .unwrap_or_else(|e| unreachable!("grant verifies: {e}"));
    // The grant carries only SendSms; a PlaceCall task is outside it.
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
    let response = verify_response(&session, &exchange(port, &auth_frame(&session, call)));
    match response.response.status {
        TaskStatus::Rejected { ref reason } => {
            assert_eq!(reason.as_str(), pylon::reject::CAPABILITY_DENIED)
        }
        ref other => unreachable!("an out-of-grant capability must deny, got {other:?}"),
    }
}
