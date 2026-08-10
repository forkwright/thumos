//! The `metaxu-probe` on-device bridge (#544): the kernel-side half of the
//! second-UART round trip criterion 3 exercises, gated on the local
//! capability check criterion 4 requires before any frame reaches the wire.
//!
//! Builds a harmless `SendSms` task, sends it through `metaxu-core`'s
//! authenticated session/envelope framing over the second PL011
//! (`board::UART1_BASE`, the on-device transport), and verifies the
//! `pylon-bridge` host process's signed response -- but ONLY after
//! [`evaluate_submission`] confirms the request is locally authorized. A
//! local denial never reaches the transport: [`submit`] calls
//! [`write_frame`] exclusively on the `Ok` arm of [`evaluate_submission`]'s
//! result, and that function has no reference to `uart`/`board`/the
//! transport anywhere in its body -- a denied request has no code path to
//! a written byte.
//!
//! Dev-only, single-shot, wire-compatible: [`dev_identity`] signs with the
//! SAME well-known dev seeds `metaxu`'s own witness and `pylon-bridge` use
//! for the SAME roles (`[7u8; 32]` = runtime, `[9u8; 32]` = device) --
//! deliberately public, non-secret, matching `keys/dev/boot-dev.*`'s
//! convention. It never ships in a `production` build: confined to
//! `#[cfg(feature = "qemu")]`, itself already mutually exclusive with
//! `production` crate-wide (main.rs `compile_error!`); [`dev_identity`]
//! restates that exclusion locally, beside the identity material, so a
//! `production` build cannot contain this dev grant even if the crate-wide
//! gate were ever relaxed. It never substitutes for a live Aletheia
//! runtime's grant issuance -- see the PR body for exactly what remains
//! before this leg is production-real.
//!
//! [`evaluate_submission`] is the ONE place the local authorization
//! decision is made. It reuses `SignedGrant::verify` (via
//! `AuthenticatedSession::open`) for device binding + expiry rather than
//! re-deriving those checks, and is generic over its grant/device/task
//! inputs -- no qemu or dev-key dependency of its own -- so it is
//! host-testable unconditionally (see the `tests` module below, which
//! exercises it without the `qemu` feature). Every failure path (bad
//! signature, wrong device, expired, capability absent) collapses to the
//! SAME [`METAXU_DENIED_LOCALLY`] outcome: no variant is treated as
//! "probably fine" (this repo already fixed three fail-open defects
//! elsewhere; this path stays fail-closed by construction rather than by
//! enumerating cases it must remember to deny).
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
use metaxu_core::grants::SignedGrant;
#[cfg(all(not(test), feature = "metaxu-probe"))]
use metaxu_core::protocol::TaskStatus;
use metaxu_core::protocol::{DeviceIdentityRef, IdentityKind, TaskRequest};
use metaxu_core::session::AuthenticatedSession;
use ulid::Ulid;

#[cfg(all(not(test), feature = "metaxu-probe"))]
use crate::board::UART1_BASE;
// WHY `crate::uart`, not `crate::uart_pl011`: main.rs path-swaps the
// driver FILE under the `qemu` feature (`#[path = "uart_pl011.rs"] mod
// uart;`) -- the MODULE name every caller in this kernel uses is `uart`
// regardless of which file backs it.
#[cfg(all(not(test), feature = "metaxu-probe"))]
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
/// Status: this device's local capability check denied the request BEFORE
/// any frame was written. Distinct from [`METAXU_REJECTED`] (a policy
/// reason FROM the peer) on purpose (#544 step 2): a local refusal must
/// never read, in the audit trail, as if the peer had seen and rejected the
/// request -- one is a control on this device, the other a claim about the
/// peer.
pub(crate) const METAXU_DENIED_LOCALLY: u32 = 5;

// WHY (#544 step 1): the self-issued dev grant stands in for two
// independent identities (a runtime issuer and a subject device) until a
// live Aletheia runtime provisions the real ones through the SAME boot
// trust anchor `production` already requires (build.rs,
// scripts/witness/trust-anchor.sh) -- never a second mechanism. Confined to
// `#[cfg(feature = "qemu")]` so it is structurally absent from every build
// that does not opt into the QEMU bring-up harness.
#[cfg(feature = "qemu")]
mod dev_identity {
    use ed25519_dalek::SigningKey;
    use metaxu_core::grants::Grant;
    use metaxu_core::protocol::Capability;

    use super::SignedGrant;

    // WHY: restates main.rs's crate-wide `qemu`+`production`
    // compile_error! immediately beside the identity material it protects
    // -- this module is already confined to `#[cfg(feature = "qemu")]`
    // above, so `production` alone is the remaining half of the same
    // condition. An adversarial diff review sees the enforcement at the
    // point of risk rather than in a different file; the crate-wide gate
    // already makes the combination unbuildable on its own, so this is a
    // second, independent structural barrier around the SAME material, not
    // the sole one.
    #[cfg(feature = "production")]
    compile_error!(
        "qemu (and therefore the self-issued dev grant it gates here, metaxu_bridge::dev_identity) is mutually exclusive with production: a shipped image must never contain a dev grant standing in for a live Aletheia identity."
    );

    /// The dev "runtime" identity: the SAME well-known seed `metaxu`'s
    /// witness and `pylon-bridge` pin for this role. Never a production
    /// credential.
    pub(super) fn runtime_signing() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    /// The dev "device" identity this kernel presents.
    pub(super) fn device_signing() -> SigningKey {
        SigningKey::from_bytes(&[9u8; 32])
    }

    /// Grant expiry: a year-2100 epoch-ms sentinel, far past any witness run.
    /// The grant is otherwise fully self-issued and fully deterministic (#544
    /// dev-only simulation of what a live Aletheia runtime would provision out
    /// of band); a real epoch source for this probe is out of scope here --
    /// see the PR body for what remains.
    ///
    /// Absent under `metaxu-probe-expired-grant` (#544 negative-case
    /// witness): that variant's `dev_grant` uses a literal, not this
    /// constant, and an unconditionally-declared, unused item would be a
    /// dead-code finding in that build's solo clippy pass.
    #[cfg(not(feature = "metaxu-probe-expired-grant"))]
    pub(super) const DEV_GRANT_EXPIRES_AT_MS: u64 = 4_102_444_800_000;

    // WHY (#544 negative-case witness): restates the crate-wide exclusion
    // beside the TWO grant variants below, the same defense-in-depth
    // rationale as the `production` compile_error! above -- a production
    // image must never contain an already-expired or capability-stripped
    // dev grant either, not just the well-formed one. Both features already
    // imply `metaxu-probe` (Cargo.toml), so this is structurally redundant
    // with the check above; an adversarial diff review sees it anyway,
    // beside the material it protects, rather than trusting a transitive
    // Cargo feature edge in a different file.
    #[cfg(all(
        any(
            feature = "metaxu-probe-expired-grant",
            feature = "metaxu-probe-no-capability"
        ),
        feature = "production"
    ))]
    compile_error!(
        "metaxu-probe-expired-grant and metaxu-probe-no-capability are CI negative-case harnesses (an intentionally-invalid dev grant); a production image must never contain either."
    );
    // WHY: the two variants select DIFFERENT bodies for the SAME `dev_grant`
    // function name below -- enabling both at once would attempt to define
    // it twice. A named compile_error! reads clearer than the resulting
    // rustc "duplicate definition" diagnostic.
    #[cfg(all(
        feature = "metaxu-probe-expired-grant",
        feature = "metaxu-probe-no-capability"
    ))]
    compile_error!(
        "metaxu-probe-expired-grant and metaxu-probe-no-capability select mutually exclusive dev-grant negative cases; enable at most one."
    );

    /// Self-issue the SAME dev grant every call -- fully deterministic (fixed
    /// seeds, fixed nonce, fixed expiry), so `submit` and `poll` need no
    /// persisted session state between them: each can independently re-derive
    /// the identical `SignedGrant` and its response key.
    #[cfg(not(any(
        feature = "metaxu-probe-expired-grant",
        feature = "metaxu-probe-no-capability"
    )))]
    pub(super) fn dev_grant() -> SignedGrant {
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

    /// #544 negative-case witness: a grant already expired at ANY `now_ms`
    /// this probe could observe. `expires_at_ms: 0` rather than a
    /// near-boot-time constant -- `now_ms >= expires_at_ms` is then a
    /// tautology for the unsigned `now_ms` `evaluate_submission` receives,
    /// so the case is deterministic regardless of how far uptime has
    /// advanced by the time `submit` runs, never a timing race.
    #[cfg(feature = "metaxu-probe-expired-grant")]
    pub(super) fn dev_grant() -> SignedGrant {
        SignedGrant::issue(
            Grant {
                issuer: runtime_signing().verifying_key().to_bytes(),
                subject: device_signing().verifying_key().to_bytes(),
                capabilities: alloc::vec![Capability::SmsSend],
                issued_at_ms: 0,
                expires_at_ms: 0,
                nonce: [0xA5; 16],
            },
            &runtime_signing(),
        )
    }

    /// #544 negative-case witness: a grant that verifies (unexpired,
    /// correctly bound) but never carries `SmsSend` -- `harmless_task`
    /// always builds a `SendSms` request, so this exercises
    /// `evaluate_submission`'s capability check specifically, distinct from
    /// the grant-verification failure the expired variant exercises.
    #[cfg(feature = "metaxu-probe-no-capability")]
    pub(super) fn dev_grant() -> SignedGrant {
        SignedGrant::issue(
            Grant {
                issuer: runtime_signing().verifying_key().to_bytes(),
                subject: device_signing().verifying_key().to_bytes(),
                capabilities: alloc::vec![Capability::CallDial], // never SmsSend
                issued_at_ms: 0,
                expires_at_ms: DEV_GRANT_EXPIRES_AT_MS,
                nonce: [0xA5; 16],
            },
            &runtime_signing(),
        )
    }
}

/// Capacity for the response scratch buffer: 4-byte length prefix + the
/// envelope header (22 B) + the `AuthenticatedResponse` postcard payload
/// (a `TaskResponse` + 32 B MAC, comfortably under 256 B for this harmless
/// task) -- generous headroom without approaching the envelope's own
/// `MAX_AUTH_RESPONSE_PAYLOAD` (33 KiB) ceiling.
#[cfg(all(not(test), feature = "metaxu-probe"))]
const RESPONSE_BUF_CAP: usize = 512;

/// SAFETY (single-core, SVC-serialized, #544): touched only from `poll`/
/// `drain_into_buffer`, themselves reachable only via the serialized SVC
/// dispatch path (`syscall::dispatch`) -- no concurrent access is possible
/// on this kernel.
#[cfg(all(not(test), feature = "metaxu-probe"))]
static mut RESPONSE_BUF: [u8; RESPONSE_BUF_CAP] = [0; RESPONSE_BUF_CAP];
/// SAFETY: see [`RESPONSE_BUF`].
#[cfg(all(not(test), feature = "metaxu-probe"))]
static mut RESPONSE_LEN: usize = 0;

/// The harmless typed task (#544's done-when: "one harmless typed task").
/// Takes the presenting device's identity bytes as a parameter rather than
/// deriving them internally: this constructor carries no qemu/dev-key
/// dependency of its own, so it compiles and runs in every build.
/// [`submit`]/[`poll`] pass `dev_identity::device_signing()`'s key -- the
/// probe's own identity; tests pass an arbitrary fixture device.
///
/// A fixed, non-randomized request id: this is a single-shot dev probe, not
/// a general facility, so there is no replay concern to a nonce.
fn harmless_task(device: [u8; 32]) -> TaskRequest {
    TaskRequest::SendSms {
        request_id: Ulid::from_bytes([0x54; 16]),
        identity: DeviceIdentityRef::new(IdentityKind::Device, "thumos-metaxu-probe", device),
        // WHY empty: the authenticated path authorizes from the VERIFIED
        // SignedGrant only (session.grant().grant.capabilities), never
        // this wire-legacy self-claimed list (see
        // metaxu::BridgeClient::submit_authenticated's docs).
        grants: Vec::new(),
        to: CompactString::from("+15550000000"),
        body: CompactString::from("thumos metaxu-probe: harmless typed task (#544)"),
    }
}

/// Local authorization for a submission (#544 step 2): the requested
/// capability must be present in a grant that verifies -- device-bound,
/// unexpired -- BEFORE any bytes are prepared for the wire.
///
/// Reuses [`SignedGrant::verify`] (via [`AuthenticatedSession::open`]) for
/// the device+expiry check -- no parallel check that could drift from it.
/// Capability presence is checked against the grant's OWN verified
/// capability list (never a self-claimed one) and only once the grant has
/// already verified. Fail closed: every rejection path -- bad signature,
/// wrong device, expired, capability absent -- returns the SAME
/// [`METAXU_DENIED_LOCALLY`], so there is no case this function can forget
/// to deny.
///
/// This function has no reference to `uart`/`board`/the transport
/// anywhere in its body. [`submit`] writes a frame ONLY on this function's
/// `Ok` arm, so a local denial has no code path to the wire -- provable by
/// reading this function, not merely by observing that a byte counter
/// stayed at zero.
fn evaluate_submission(
    signed_grant: SignedGrant,
    device: &[u8; 32],
    now_ms: u64,
    task: &TaskRequest,
) -> Result<Vec<u8>, u32> {
    let Ok(session) = AuthenticatedSession::open(signed_grant, device, now_ms) else {
        return Err(METAXU_DENIED_LOCALLY); // bad signature, wrong device, or expired
    };
    if !session
        .grant()
        .grant
        .capabilities
        .contains(&task.required_capability())
    {
        return Err(METAXU_DENIED_LOCALLY);
    }
    metaxu_core::session::encode_authenticated_request(&session, task)
        .map_err(|_| METAXU_TRANSPORT_ERROR)
}

/// `Syscall::MetaxuSubmit`: enforce the local capability check FIRST (#544
/// step 2 -- see [`evaluate_submission`]), then write the resulting frame to
/// [`UART1_BASE`]. Returns [`METAXU_ACCEPTED`] once the frame is ON THE
/// WIRE (not once it is answered -- call [`poll`] for the outcome),
/// [`METAXU_DENIED_LOCALLY`] if the local grant does not verify or lacks
/// the capability (nothing is written), or [`METAXU_TRANSPORT_ERROR`] if
/// the frame could not be encoded.
#[cfg(all(not(test), feature = "metaxu-probe"))]
pub(crate) fn submit() -> u32 {
    let now_ms = crate::exceptions::uptime_ms();
    let device = dev_identity::device_signing().verifying_key().to_bytes();
    let task = harmless_task(device);
    match evaluate_submission(dev_identity::dev_grant(), &device, now_ms, &task) {
        Ok(frame) => {
            write_frame(&frame);
            METAXU_ACCEPTED
        }
        Err(denied_or_error) => denied_or_error,
    }
}

/// `Syscall::MetaxuPoll`: non-blocking. Drains whatever bytes
/// [`UART1_BASE`] currently has ready, and returns [`crate::syscall::EAGAIN`]
/// until a complete framed response has arrived, then decodes + verifies
/// it and returns a definitive [`METAXU_ACCEPTED`] / [`METAXU_REJECTED`] /
/// [`METAXU_MAC_FAILED`] / [`METAXU_MISMATCH`].
#[cfg(all(not(test), feature = "metaxu-probe"))]
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
    if !authenticated.verify(&dev_identity::dev_grant()) {
        return METAXU_MAC_FAILED;
    }
    let device = dev_identity::device_signing().verifying_key().to_bytes();
    if authenticated.response.request_id != harmless_task(device).request_id() {
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
#[cfg(all(not(test), feature = "metaxu-probe"))]
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
#[cfg(all(not(test), feature = "metaxu-probe"))]
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

// ---------------------------------------------------------------------------
// Tests (#544 step 2): offline, no live bridge -- evaluate_submission has no
// qemu/UART dependency, so these run in the default host test pass.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use metaxu_core::grants::Grant;
    use metaxu_core::protocol::Capability;

    use super::{METAXU_DENIED_LOCALLY, SignedGrant, evaluate_submission, harmless_task};

    // WHY inline key material, not `dev_identity::{runtime_signing,
    // device_signing}`: these tests must run without the `qemu` feature (they
    // exercise `evaluate_submission`, which has no qemu dependency of its
    // own), so they cannot reference anything gated behind it. Arbitrary,
    // non-secret bytes -- test fixtures only, never linked into a build that
    // ships.
    fn issuer_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn device_key() -> [u8; 32] {
        SigningKey::from_bytes(&[9u8; 32])
            .verifying_key()
            .to_bytes()
    }

    fn other_device_key() -> [u8; 32] {
        SigningKey::from_bytes(&[0xEEu8; 32])
            .verifying_key()
            .to_bytes()
    }

    fn grant(
        capabilities: alloc::vec::Vec<Capability>,
        expires_at_ms: u64,
        subject: [u8; 32],
    ) -> SignedGrant {
        SignedGrant::issue(
            Grant {
                issuer: issuer_key().verifying_key().to_bytes(),
                subject,
                capabilities,
                issued_at_ms: 0,
                expires_at_ms,
                nonce: [0xA5; 16],
            },
            &issuer_key(),
        )
    }

    #[test]
    fn capability_present_and_valid_proceeds() {
        let signed = grant(alloc::vec![Capability::SmsSend], 10_000, device_key());
        let result =
            evaluate_submission(signed, &device_key(), 5_000, &harmless_task(device_key()));
        assert!(
            result.is_ok(),
            "a grant that verifies and carries the required capability must proceed to encoding, not deny"
        );
    }

    #[test]
    fn capability_absent_denies_locally_without_transmitting() {
        let signed = grant(alloc::vec![Capability::CallDial], 10_000, device_key());
        assert_eq!(
            evaluate_submission(signed, &device_key(), 5_000, &harmless_task(device_key())),
            Err(METAXU_DENIED_LOCALLY),
            "a grant that verifies but never carries SmsSend must deny locally -- \
             evaluate_submission's Err arm never calls write_frame, so this outcome \
             has no code path to the transport"
        );
    }

    #[test]
    fn expired_grant_denies_locally_without_transmitting() {
        let signed = grant(alloc::vec![Capability::SmsSend], 10_000, device_key());
        assert_eq!(
            evaluate_submission(signed, &device_key(), 10_000, &harmless_task(device_key())),
            Err(METAXU_DENIED_LOCALLY),
            "a grant past its expiry must deny locally even though it once carried the capability"
        );
    }

    #[test]
    fn wrong_device_denies_locally_without_transmitting() {
        let signed = grant(alloc::vec![Capability::SmsSend], 10_000, other_device_key());
        assert_eq!(
            evaluate_submission(signed, &device_key(), 5_000, &harmless_task(device_key())),
            Err(METAXU_DENIED_LOCALLY),
            "a grant bound to a different device must deny locally"
        );
    }
}
