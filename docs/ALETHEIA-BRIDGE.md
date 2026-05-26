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
Aletheia runtime is expected to be heavier than the device boundary should own:
it may need model orchestration, tool scheduling, long-lived memory, and
fleet-level context. Keeping that runtime off-device preserves the Thumos
resource budget and keeps the device boundary focused on typed, auditable
actions.

The thin-client design also keeps capability enforcement local to Thumos. A
runtime request can carry grant claims, but the device side remains responsible
for verifying policy before sending SMS, placing calls, reading contacts, or
opening audio sessions. Device identity is represented by opaque handles and
attestation digests; raw IMEI, IMSI, WiFi MAC, Bluetooth address, and similar
hardware identifiers must not cross this bridge.

## Current Surface

- `crates/metaxu` is registered as a workspace crate.
- Requests and responses serialize with `postcard`.
- `BridgeClient` exchanges one request frame for one response frame through a
  caller-provided transport.
- The crate has an in-memory round-trip test for device -> runtime -> device.
- The local preflight only checks that a request carries a grant for the needed
  capability. It does not authenticate grants, check expiration, or prove remote
  runtime identity.

## Non-Goals

- No Aletheia runtime is embedded in Thumos.
- No live LTE, mesh, SMS, Matrix, or socket transport is wired by this decision.
- No network or firewall boot path changes are part of this bridge decision.
- No userspace spawn or init path changes are part of this bridge decision.
- No dependency on a C toolchain or heavyweight runtime library is introduced.

## Follow-Up Work

- Bind `metaxu` to the selected live transport without bypassing firewall policy.
- Connect nous capability presets to concrete `metaxu` grant verification.
- Add runtime peer authentication and grant expiration checks.
- Route accepted device actions through the existing confirmation UI and local
  service APIs.
- Cross-link the corresponding Aletheia-side runtime endpoint when it exists.
