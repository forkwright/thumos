# Aletheia Bridge Decision

Status: accepted

Date: 2026-05-26

Issue: [#141](https://github.com/forkwright/thumos/issues/141)

## Decision

Thumos uses a thin-client bridge to a menos-resident Aletheia runtime. The
runtime does not run in-process on the device in phase 1.

The device-side integration surface is the `metaxu` workspace crate. `metaxu`
defines typed task requests, task responses, opaque device identity references,
capability grant claims, and a synchronous byte transport trait. It is a wire
boundary for constrained Thumos clients, not an embedded cognition runtime.

## Rationale

Thumos targets constrained mobile hardware and already has separate local
surfaces for voice transcription (`ekphrasis`) and nous action proposals. The
Aletheia runtime likely outweighs what the device boundary should own:
it may need model orchestration, tool scheduling, long-lived memory, and
fleet-level context. Keeping that runtime off-device preserves the Thumos
resource budget and keeps the device boundary focused on typed, auditable
actions.

The thin-client design also keeps capability enforcement local to Thumos. A
runtime request can carry grant claims, but the device side remains responsible
for verifying policy before sending SMS, placing calls, reading contacts, or
opening audio sessions. Opaque handles and attestation digests represent
device identity. Raw IMEI, IMSI, WiFi MAC, Bluetooth address, and similar
hardware identifiers must not cross this bridge.

## Current Surface

- The root `Cargo.toml` registers `crates/metaxu` as a workspace member.
- Requests and responses serialize with `postcard`, framed in a versioned
  envelope (magic + schema + major/minor + kind + correlation ID + declared
  length, checked before any payload decode) so thumos and aletheia never
  drift on wire assumptions (#553).
- Two request paths exist on `BridgeClient` (#544):
  - `submit` exchanges a bare task request/response pair through a
    caller-provided transport, checking only that the task carries a
    self-claimed grant locally -- suitable for a trusted in-process
    transport, not a network peer.
  - `submit_authenticated` presents a cryptographically verified, expiring
    `SignedGrant` (Ed25519-signed by the runtime, bound to both the
    issuer's and the device's identity) on every request, and refuses any
    response whose HMAC does not prove the responder held the grant's
    signed nonce. Capability enforcement checks the session's verified
    grant, not the wire-claimed one. An adversarial witness exercises this
    path over real TCP: replay, expired grant, wrong runtime identity, a
    grant for the wrong device, unavailable network (at connect and
    mid-exchange), and a denied capability (both the client's local
    preflight and the endpoint's independent check).
- Golden vectors (`crates/metaxu/src/vectors.rs`) pin the envelope's byte
  shape so both repositories decode it identically.

## What Remains

A witness test inside the `metaxu` crate itself proves the verified protocol
path above against a reference endpoint double (`pylon`) -- a stand-in for
the real Aletheia runtime, not a live one. Outstanding for a genuinely live
round trip:

- **Done in QEMU (#544):** `board::UART1_BASE` (the qemu-virt second PL011,
  present under `-machine virt,secure=on`) carries an authenticated request
  end to end, driven by a real Thumos userspace process
  (`/metaxu_probe`, via two syscalls) against a real host process
  (`pylon-bridge`, the SAME `pylon` reference endpoint this doc's witness
  already used, not a live runtime). The kernel side calls
  `metaxu-core`'s session primitives directly (`AuthenticatedSession`,
  `encode_authenticated_request`) instead of `BridgeClient::
  submit_authenticated` -- the `no_std` kernel cannot depend on `metaxu`'s
  std-only client/transport layer, so it links `metaxu-core` (the shared
  no_std+alloc extraction, #545) instead. WiFi on hardware, and routing
  the transport through firewall policy (meaningful for an IP-based
  transport -- the UART leg is not one) remain unaddressed.
- Stand up (or point at) an actual Aletheia-side endpoint implementing the
  pylon's verification contract, so the pinned runtime key is a real
  runtime's key, not a witness fixture.
- Provision the device's grant from a real Aletheia-side issuer instead of
  having the kernel self-issue a dev-seed grant to itself (#544's on-device
  leg does the latter, clearly labeled dev-only).
- Connect nous capability presets to concrete `metaxu` grant issuance.
- Route accepted device actions through the existing confirmation UI and
  local service APIs (criterion 4 of #544, untouched).
- Cross-link the corresponding Aletheia-side runtime endpoint when it
  exists.

## Non-Goals

- This decision embeds no Aletheia runtime in Thumos.
- This decision wires no live LTE, mesh, SMS, Matrix, or socket transport.
- This decision makes no network or firewall boot path changes.
- This decision makes no userspace spawn or init path changes.
- This decision introduces no dependency on a C toolchain or heavyweight runtime library.
