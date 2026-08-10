//! The reference Aletheia-endpoint double ("pylon") for the authenticated
//! round-trip witness (#544).
//!
//! A pylon is a stateless-per-request verification endpoint: every
//! `AuthenticatedRequest` is verified alone — grant signature under the
//! pinned runtime key, expiry against the injected clock, subject against
//! the presenting device, task capability against the grant, request-id
//! replay against the per-endpoint seen set. It answers one harmless typed
//! task (echo-accept) and signs every response with the grant-nonce MAC.
//!
//! Security-failure rejections are typed `TaskStatus::Rejected` reasons so
//! the witness can assert each adversarial case explicitly.
//!
//! Public (not `pub(crate)`) under the `pylon-bin` feature (#544 on-device
//! leg): `src/bin/pylon_bridge.rs` links this module as an external binary
//! target and launches [`spawn`] as a real host process a QEMU-booted
//! kernel talks to over a second UART, reusing this SAME verification logic
//! rather than a second, driftable implementation.

use std::collections::HashSet;
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{Receiver, channel};
use std::thread::JoinHandle;

use crate::envelope::{Envelope, MessageKind};
use crate::grants::GrantError;
use crate::protocol::{DeviceAction, TaskResponse};
use crate::session::{AuthenticatedRequest, AuthenticatedResponse};

/// Rejection reasons the pylon returns for security failures (#544).
pub(crate) mod reject {
    /// The grant's signature did not verify under the pinned runtime key.
    pub(crate) const GRANT_SIGNATURE: &str = "grant_signature";
    /// The grant was expired at evaluation.
    pub(crate) const GRANT_EXPIRED: &str = "grant_expired";
    /// The grant's subject was not the presenting device.
    pub(crate) const WRONG_DEVICE: &str = "wrong_device";
    /// The grant's issuer is not the pinned runtime.
    pub(crate) const WRONG_ISSUER: &str = "wrong_issuer";
    /// The request id was already seen (replay).
    pub(crate) const REPLAY: &str = "replay";
    /// The task's capability is not in the grant.
    pub(crate) const CAPABILITY_DENIED: &str = "capability_denied";
    /// The frame could not be decoded at all.
    pub(crate) const BAD_FRAME: &str = "bad_frame";
}

/// One pylon endpoint: a pinned runtime identity + the clock it trusts.
pub struct Pylon {
    runtime_key: ed25519_dalek::VerifyingKey,
    now_ms: u64,
    seen_request_ids: HashSet<[u8; 16]>,
}

impl Pylon {
    /// Create a pylon for the runtime identity `runtime_key`, evaluating
    /// expiry at `now_ms`.
    pub fn new(runtime_key: ed25519_dalek::VerifyingKey, now_ms: u64) -> Self {
        Self {
            runtime_key,
            now_ms,
            seen_request_ids: HashSet::new(),
        }
    }

    /// Verify + answer one authenticated request frame (#544).
    pub fn handle(&mut self, frame_bytes: &[u8]) -> Vec<u8> {
        let response = self.answer(frame_bytes);
        // Wrap the authenticated response in the envelope (kind 5).
        let payload = postcard::to_allocvec(&response).unwrap_or_default();
        let correlation = frame_bytes
            .get(10..18)
            .and_then(|b| b.try_into().ok().map(u64::from_le_bytes))
            .unwrap_or(0);
        Envelope::build(MessageKind::AuthenticatedResponse, correlation, payload)
            .map(|e| e.encode())
            .unwrap_or_default()
    }

    /// The verification + answer logic (typed for the witness's assertions).
    fn answer(&mut self, frame_bytes: &[u8]) -> AuthenticatedResponse {
        let Ok(frame) = Envelope::decode(frame_bytes) else {
            return self.reject_undecodable(reject::BAD_FRAME);
        };
        if frame.header.kind != MessageKind::AuthenticatedRequest {
            return self.reject_undecodable(reject::BAD_FRAME);
        }
        let auth: AuthenticatedRequest = match postcard::from_bytes(&frame.payload) {
            Ok(a) => a,
            Err(_) => return self.reject_undecodable(reject::BAD_FRAME),
        };
        let request_id = auth.request.request_id();

        // The issuer must be the pinned runtime (cryptographic identity,
        // not a claimed string).
        if auth.signed_grant.grant.issuer != self.runtime_key.to_bytes() {
            return Self::reject(&auth, reject::WRONG_ISSUER);
        }
        // Grant signature + expiry. Device binding is proven by the subject
        // matching the grant itself (the presenting device proves possession
        // of the grant by using its nonce-keyed response MAC channel; a
        // stolen grant verifies but the device's own identity claim rides in
        // the request's identity ref, checked next).
        let device = auth.request.identity().attestation_digest;
        match auth.signed_grant.verify(&device, self.now_ms) {
            Err(GrantError::Expired { .. }) => return Self::reject(&auth, reject::GRANT_EXPIRED),
            Err(GrantError::WrongDevice) => return Self::reject(&auth, reject::WRONG_DEVICE),
            Ok(_) => {}
            // WHY a wildcard rather than a named `BadSignature` arm:
            // GrantError is `#[non_exhaustive]` (metaxu-core, cross-repo
            // API, #545) -- pylon.rs is now an external-crate consumer of
            // it, so a match must tolerate a future additive variant. This
            // catches BOTH `BadSignature` and any such future variant,
            // identically (both reject with GRANT_SIGNATURE).
            Err(_) => return Self::reject(&auth, reject::GRANT_SIGNATURE),
        }
        // The request's identity ref must match the grant's subject.
        if device != auth.signed_grant.grant.subject {
            return Self::reject(&auth, reject::WRONG_DEVICE);
        }
        // Capability: the task's requirement must be inside the grant.
        if !auth
            .signed_grant
            .grant
            .capabilities
            .contains(&auth.request.required_capability())
        {
            return Self::reject(&auth, reject::CAPABILITY_DENIED);
        }
        // Replay.
        if !self.seen_request_ids.insert(request_id.to_bytes()) {
            return Self::reject(&auth, reject::REPLAY);
        }
        // The harmless typed task: accept the echo/no-op action.
        let action = DeviceAction::None;
        AuthenticatedResponse::build(
            &auth.signed_grant,
            TaskResponse::accepted(request_id, action),
        )
    }

    /// A typed rejection, MAC'd with the request's own grant so the client
    /// verifies it through the same channel (#544).
    fn reject(auth: &AuthenticatedRequest, reason: &'static str) -> AuthenticatedResponse {
        AuthenticatedResponse::build(
            &auth.signed_grant,
            TaskResponse::rejected(auth.request.request_id(), reason),
        )
    }

    /// A rejection for an undecodable frame (no grant to MAC under; the
    /// client-side decode/verify fails on its own for these).
    fn reject_undecodable(&self, reason: &'static str) -> AuthenticatedResponse {
        AuthenticatedResponse::build(
            &self.fallback_grant(),
            TaskResponse::rejected(ulid::Ulid::from_bytes([0; 16]), reason),
        )
    }

    /// A grant-shaped placeholder for building rejection responses (the MAC
    /// key differs per grant, so rejections use the REQUEST's grant when
    /// decodable; this is only for undecodable frames).
    fn fallback_grant(&self) -> crate::grants::SignedGrant {
        crate::grants::SignedGrant {
            grant: crate::grants::Grant {
                issuer: self.runtime_key.to_bytes(),
                subject: [0; 32],
                capabilities: Vec::new(),
                issued_at_ms: 0,
                expires_at_ms: u64::MAX,
                nonce: [0; 16],
            },
            signature: ed25519_dalek::Signature::from_bytes(&[0; 64]),
        }
    }
}

/// Run a pylon on `127.0.0.1:0` in a background thread, answering exactly
/// `n_requests` frames then stopping. Returns the bound port and the join
/// handle.
///
/// Used by the adversarial witness (#544) and, under `pylon-bin`, by
/// `src/bin/pylon_bridge.rs` for the on-device QEMU round trip.
pub fn spawn(pylon: Pylon, n_requests: usize) -> (u16, JoinHandle<()>) {
    spawn_with_response_transform(pylon, n_requests, |response| response)
}

/// Like [`spawn`], but every outgoing response frame passes through
/// `transform` before it reaches the wire.
///
/// #544 negative-case witness: a tampered-MAC response must surface to the
/// client as a typed MAC failure, not a silent accept or a transport
/// error. [`spawn`] delegates here with an identity transform -- one
/// implementation, not two that could drift.
pub fn spawn_with_response_transform(
    mut pylon: Pylon,
    n_requests: usize,
    transform: impl Fn(Vec<u8>) -> Vec<u8> + Send + 'static,
) -> (u16, JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap_or_else(|_| unreachable!());
    let port = listener.local_addr().map(|a| a.port()).unwrap_or_default();
    let handle = std::thread::spawn(move || {
        for _ in 0..n_requests {
            let Ok((mut stream, _)) = listener.accept() else {
                continue;
            };
            serve_one(&mut pylon, &mut stream, &transform);
        }
    });
    (port, handle)
}

/// Read one length-prefixed frame, answer it, write the (possibly
/// transformed) response frame.
fn serve_one(pylon: &mut Pylon, stream: &mut TcpStream, transform: &dyn Fn(Vec<u8>) -> Vec<u8>) {
    use std::io::{Read, Write};
    let mut len_buf = [0u8; 4];
    if stream.read_exact(&mut len_buf).is_err() {
        return;
    }
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > 64 * 1024 {
        return;
    }
    let mut frame = vec![0u8; len];
    if stream.read_exact(&mut frame).is_err() {
        return;
    }
    let response = transform(pylon.handle(&frame));
    let out_len = (response.len() as u32).to_le_bytes();
    let _ = stream.write_all(&out_len);
    let _ = stream.write_all(&response);
}

/// The control channel for scripted endpoints (unused by the witness today;
/// kept for the on-device leg's orchestration).
pub(crate) fn _control_channel() -> (Receiver<u8>, ()) {
    let (_tx, rx) = channel::<u8>();
    (rx, ())
}
