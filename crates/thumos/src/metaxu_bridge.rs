//! The `metaxu-probe` on-device bridge (#544): the kernel-side half of the
//! second-UART round trip criterion 3 exercises.
//!
//! Builds a harmless `SendSms` task under a self-issued dev grant, sends it
//! through `metaxu-core`'s authenticated session/envelope framing over the
//! second PL011 (`board::UART1_BASE`, the on-device transport), and
//! verifies the `pylon-bridge` host process's signed response.
//!
//! Dev-only, single-shot, wire-compatible: this module signs with the SAME
//! well-known dev seeds `metaxu`'s own witness and `pylon-bridge` use for
//! the SAME roles (`[7u8; 32]` = runtime, `[9u8; 32]` = device) --
//! deliberately public, non-secret, matching `keys/dev/boot-dev.*`'s
//! convention. It never ships in a `production` build (main.rs
//! compile_error!, mirrors `kfault-probe`/`crashloop-probe`) and never
//! substitutes for a live Aletheia runtime's grant issuance -- see the PR
//! body for exactly what remains before this leg is production-real.
//!
//! Split into two syscalls (`MetaxuSubmit`, `MetaxuPoll`) rather than one
//! blocking call: an SVC handler runs with IRQs masked (`ticks()` frozen --
//! see `syscall.rs`'s `Sleep` WHY-comment), so a busy-spin here for a real
//! host round trip would repeat the exact anti-pattern that comment already
//! flags and fixed for `Sleep`. `poll` is non-blocking (mirrors
//! `Uart::getc`) and userspace retries it with `Sleep` between attempts --
//! the SAME poll-with-sleep idiom `init.rs`'s fork/forkexec/guard harnesses
//! already use.

use alloc::vec::Vec;

use compact_str::CompactString;
use ed25519_dalek::SigningKey;
use metaxu_core::grants::{Grant, SignedGrant};
use metaxu_core::protocol::{Capability, DeviceIdentityRef, IdentityKind, TaskRequest, TaskStatus};
use metaxu_core::session::AuthenticatedSession;
use ulid::Ulid;

use crate::board::UART1_BASE;
// WHY `crate::uart`, not `crate::uart_pl011`: main.rs path-swaps the
// driver FILE under the `qemu` feature (`#[path = "uart_pl011.rs"] mod
// uart;`) -- the MODULE name every caller in this kernel uses is `uart`
// regardless of which file backs it.
use crate::uart::Uart;

/// Status: the authenticated request was accepted.
pub(crate) const METAXU_ACCEPTED: u32 = 0;
/// Status: the authenticated request was rejected (a typed policy reason).
pub(crate) const METAXU_REJECTED: u32 = 1;
/// Status: the response MAC did not verify under the session's grant.
pub(crate) const METAXU_MAC_FAILED: u32 = 2;
/// Status: the response answered a different request id than submitted.
pub(crate) const METAXU_MISMATCH: u32 = 3;
/// Status: the outgoing frame could not be encoded, or the declared
/// incoming length exceeds this probe's fixed response buffer.
pub(crate) const METAXU_TRANSPORT_ERROR: u32 = 4;

/// Capacity for the response scratch buffer: 4-byte length prefix + the
/// envelope header (22 B) + the `AuthenticatedResponse` postcard payload
/// (a `TaskResponse` + 32 B MAC, comfortably under 256 B for this harmless
/// task) -- generous headroom without approaching the envelope's own
/// `MAX_AUTH_RESPONSE_PAYLOAD` (33 KiB) ceiling.
const RESPONSE_BUF_CAP: usize = 512;

/// SAFETY (single-core, SVC-serialized, #544): touched only from `poll`/
/// `drain_into_buffer`, themselves reachable only via the serialized SVC
/// dispatch path (`syscall::dispatch`) -- no concurrent access is possible
/// on this kernel.
static mut RESPONSE_BUF: [u8; RESPONSE_BUF_CAP] = [0; RESPONSE_BUF_CAP];
/// SAFETY: see [`RESPONSE_BUF`].
static mut RESPONSE_LEN: usize = 0;

/// The dev "runtime" identity: the SAME well-known seed `metaxu`'s witness
/// and `pylon-bridge` pin for this role. Never a production credential.
fn runtime_signing() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

/// The dev "device" identity this kernel presents.
fn device_signing() -> SigningKey {
    SigningKey::from_bytes(&[9u8; 32])
}

/// Grant expiry: a year-2100 epoch-ms sentinel, far past any witness run.
/// The grant is otherwise fully self-issued and fully deterministic (#544
/// dev-only simulation of what a live Aletheia runtime would provision out
/// of band); a real epoch source for this probe is out of scope here --
/// see the PR body for what remains.
const DEV_GRANT_EXPIRES_AT_MS: u64 = 4_102_444_800_000;

/// Self-issue the SAME dev grant every call -- fully deterministic (fixed
/// seeds, fixed nonce, fixed expiry), so `submit` and `poll` need no
/// persisted session state between them: each can independently re-derive
/// the identical `SignedGrant` and its response key.
fn dev_grant() -> SignedGrant {
    SignedGrant::issue(
        Grant {
            issuer: runtime_signing().verifying_key().to_bytes(),
            subject: device_signing().verifying_key().to_bytes(),
            capabilities: alloc::vec![Capability::SmsSend],
            issued_at_ms: 0,
            expires_at_ms: DEV_GRANT_EXPIRES_AT_MS,
            nonce: [0xA5; 16],
        },
        &runtime_signing(),
    )
}

/// The harmless typed task (#544's done-when: "one harmless typed task").
/// A fixed, non-randomized request id: this is a single-shot dev probe,
/// not a general facility, so there is no replay concern to a nonce.
fn harmless_task() -> TaskRequest {
    TaskRequest::SendSms {
        request_id: Ulid::from_bytes([0x54; 16]),
        identity: DeviceIdentityRef::new(
            IdentityKind::Device,
            "thumos-metaxu-probe",
            device_signing().verifying_key().to_bytes(),
        ),
        // WHY empty: the authenticated path authorizes from the VERIFIED
        // SignedGrant only (session.grant().grant.capabilities), never
        // this wire-legacy self-claimed list (see
        // metaxu::BridgeClient::submit_authenticated's docs).
        grants: Vec::new(),
        to: CompactString::from("+15550000000"),
        body: CompactString::from("thumos metaxu-probe: harmless typed task (#544)"),
    }
}

/// `Syscall::MetaxuSubmit`: build + sign the request and write it to
/// [`UART1_BASE`]. Returns [`METAXU_ACCEPTED`] once the frame is ON THE
/// WIRE (not once it is answered -- call [`poll`] for the outcome), or
/// [`METAXU_TRANSPORT_ERROR`] if it could not be built.
pub(crate) fn submit() -> u32 {
    let now_ms = crate::exceptions::uptime_ms();
    let Ok(session) = AuthenticatedSession::open(
        dev_grant(),
        &device_signing().verifying_key().to_bytes(),
        now_ms,
    ) else {
        return METAXU_TRANSPORT_ERROR; // INVARIANT: the freshly self-issued dev grant always verifies against its own subject before DEV_GRANT_EXPIRES_AT_MS; unreachable in practice
    };
    let Ok(frame) = metaxu_core::session::encode_authenticated_request(&session, &harmless_task())
    else {
        return METAXU_TRANSPORT_ERROR; // INVARIANT: the fixed harmless_task() always encodes under the envelope's MAX_AUTH_REQUEST_PAYLOAD ceiling
    };
    write_frame(&frame);
    METAXU_ACCEPTED
}

/// `Syscall::MetaxuPoll`: non-blocking. Drains whatever bytes
/// [`UART1_BASE`] currently has ready, and returns [`crate::syscall::EAGAIN`]
/// until a complete framed response has arrived, then decodes + verifies
/// it and returns a definitive [`METAXU_ACCEPTED`] / [`METAXU_REJECTED`] /
/// [`METAXU_MAC_FAILED`] / [`METAXU_MISMATCH`].
pub(crate) fn poll() -> u32 {
    drain_into_buffer();
    // SAFETY: see [`RESPONSE_BUF`].
    let have = unsafe { RESPONSE_LEN };
    if have < 4 {
        return crate::syscall::EAGAIN;
    }
    // SAFETY: see [`RESPONSE_BUF`]; the first 4 bytes are populated
    // whenever `have >= 4`.
    let declared_len = unsafe {
        usize::try_from(u32::from_le_bytes([
            RESPONSE_BUF[0],
            RESPONSE_BUF[1],
            RESPONSE_BUF[2],
            RESPONSE_BUF[3],
        ]))
        .unwrap_or(usize::MAX)
    };
    let Some(total) = 4usize.checked_add(declared_len) else {
        return METAXU_TRANSPORT_ERROR;
    };
    if total > RESPONSE_BUF_CAP {
        return METAXU_TRANSPORT_ERROR; // a declared length this probe's fixed response can never reach
    }
    if have < total {
        return crate::syscall::EAGAIN;
    }
    // SAFETY: bytes[4..total] are fully written once RESPONSE_LEN reaches
    // `total` (drain_into_buffer only ever appends, never rewinds).
    let frame_bytes = unsafe { &RESPONSE_BUF[4..total] };
    let Ok(authenticated) = metaxu_core::session::decode_authenticated_response(frame_bytes) else {
        return METAXU_TRANSPORT_ERROR;
    };
    if !authenticated.verify(&dev_grant()) {
        return METAXU_MAC_FAILED;
    }
    if authenticated.response.request_id != harmless_task().request_id() {
        return METAXU_MISMATCH;
    }
    match authenticated.response.status {
        TaskStatus::Accepted { .. } => METAXU_ACCEPTED,
        TaskStatus::Rejected { .. } => METAXU_REJECTED,
        // WHY a wildcard despite listing every known variant: TaskStatus is
        // `#[non_exhaustive]` (metaxu-core, cross-repo API), so a match from
        // this dependent crate must tolerate a future additive variant
        // rather than fail to compile on one.
        _ => METAXU_TRANSPORT_ERROR,
    }
}

/// Write a length-prefixed frame to `UART1_BASE`: a 4-byte LE length
/// followed by `frame`'s bytes -- the SAME framing `pylon::serve_one` (the
/// `pylon-bridge` process on the other end) already reads.
fn write_frame(frame: &[u8]) {
    let uart = Uart::at(UART1_BASE);
    let Ok(len) = u32::try_from(frame.len()) else {
        return; // INVARIANT: unreachable -- the envelope ceiling bounds frame.len() well under u32::MAX
    };
    for b in len.to_le_bytes() {
        uart.putc(b);
    }
    for &b in frame {
        uart.putc(b);
    }
}

/// Drain whatever bytes are currently ready on `UART1_BASE` into the
/// response buffer (non-blocking, mirrors `Uart::getc`).
fn drain_into_buffer() {
    let uart = Uart::at(UART1_BASE);
    // SAFETY: see [`RESPONSE_BUF`].
    unsafe {
        while RESPONSE_LEN < RESPONSE_BUF_CAP {
            let Some(byte) = uart.getc() else { break };
            RESPONSE_BUF[RESPONSE_LEN] = byte;
            RESPONSE_LEN += 1;
        }
    }
}
