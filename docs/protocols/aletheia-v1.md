# Aletheia-facing protocol, v1 (issue #553)

The ONE versioned contract between thumos and aletheia. Two transports carry
the same semantic contract; neither repository declares device-local
conventions.

- **Envelope** (binary, postcard payloads): every Aletheia-facing frame —
  task request, task response — travels in the envelope below.
  Implementation: `crates/metaxu/src/envelope.rs`, golden vectors in
  `crates/metaxu/src/vectors.rs`.
- **STT events** (JSON over WebSocket): transcription events for the
  aletheia STT service, thumos-side rendering of the same typed-event
  semantics. Implementation: `crates/thumos/src/ekphrasis.rs`.

## 1. Envelope (binary)

Every frame is a 22-byte fixed header (little-endian) followed by exactly
`payload_len` payload bytes (postcard for the kind's payload type):

```
[0..4)   magic: u32      = "MTX1" (0x4D 0x54 0x58 0x31)
[4..6)   schema: u16     = 1
[6]      major: u8       = 1
[7]      minor: u8       = 1
[8..10)  kind: u16       = 1 TaskRequest | 2 TaskResponse | 3 SttEvent
                      4 AuthenticatedRequest | 5 AuthenticatedResponse (MINOR 1)
[10..18) correlation_id: u64 (request ULID's first 8 bytes)
[18..22) payload_len: u32
```

### Compatibility rules

- Wrong magic or schema: reject (`BadMagic` / `UnsupportedSchema`) — never
  a silent misdecode.
- `major` mismatch: reject (`IncompatibleVersion`). A major bump is never
  negotiated silently; a downgrade attempt is an explicit error.
- `minor` newer than the decoder's: accepted ONLY when `kind` is known and
  the payload decodes exactly. Minor bumps may ADD kinds or optional
  fields; they never change an existing kind's payload shape. An unknown
  kind always rejects (`UnknownKind`).
- `minor` older: accepted (symmetric rule).
- `payload_len` above the kind's ceiling: reject (`FrameTooLarge`) BEFORE
  allocating. Ceilings (v1): TaskRequest 32 KiB, TaskResponse 32 KiB,
  SttEvent 4 KiB.
- Frame bytes != 22 + payload_len: reject (`TruncatedFrame` /
  `TrailingBytes`) — decoding is exact, always.

## 2. Authenticated exchange (envelope MINOR 1, #544)

Two additive kinds carry one mutually authenticated round trip:

- **AuthenticatedRequest** (kind 4): `SignedGrant` + `TaskRequest`. The
  device presents a cryptographically verified, expiring grant on EVERY
  request — no session state to confuse.
- **AuthenticatedResponse** (kind 5): `TaskResponse` + HMAC-SHA256 over the
  response payload, keyed by `HKDF-SHA256(ikm = grant.nonce, info =
  "metaxu-response-v1")`. A verified response proves the responder knows
  the signed nonce — the mutual half of the authentication.

Grant semantics (`crates/metaxu/src/grants.rs`):

- A `Grant` is issuer(runtime Ed25519 pubkey) → subject(device pubkey),
  capability set, issue/expiry times (ms), and a 16-byte session nonce.
  A `SignedGrant` is the grant's postcard bytes plus the issuer's Ed25519
  signature. Verification proves: signature valid under the pinned runtime
  key, subject == the presenting device, not expired (expiry exclusive).
- The endpoint verifies each request statelessly: issuer pinned →
  signature → expiry → device match → capability inside the grant →
  request-id replay (per-endpoint seen set). Failures reject with typed
  reasons (`grant_signature`, `grant_expired`, `wrong_device`,
  `wrong_issuer`, `replay`, `capability_denied`, `bad_frame`).
- The client pre-flights identically (fail-closed both ends).

Payload ceilings: AuthenticatedRequest 34 KiB, AuthenticatedResponse
33 KiB.

## 3. STT events (JSON over WebSocket)

Every event is versioned, session-correlated, sequenced, and typed:

```json
{"v":1, "session":42, "seq":3, "kind":"partial", "text":"hel", "confidence_milli":800}
{"v":1, "session":42, "seq":7, "kind":"final", "text":"hello", "language":"en", "model":"whisper-small", "duration_ms":1200}
{"v":1, "session":42, "seq":8, "kind":"error", "code":"model_overloaded"}
```

Rules (thumos-side, `ekphrasis::process_transcription`):

- `v` must be 1 — anything else is `UnsupportedVersion` (no downgrade
  ambiguity).
- `session` must equal the recording session's id — a foreign session is
  `SessionMismatch`, never a silent mix.
- `seq` is monotonic per session — a regression is `SequenceRegression`.
- `kind`: `partial` (text required, bounded; `confidence_milli` optional),
  `final` (text required, bounded; `language`/`model`/`duration_ms`
  recorded as provenance), `error` (`code` required; surfaces as
  `ServiceError` and ends the session).
- Error codes (v1): `model_overloaded`, `bad_audio`, `cancelled`.

## 3. Golden vectors

`crates/metaxu/src/vectors.rs` holds byte-exact frames both repositories
MUST decode identically. Changing them is a contract change (major/minor/
schema), never an implementation side effect. #544 proves both endpoints
against the same immutable vectors before live action support expands.

## 4. Non-goals (v1)

- No feature negotiation beyond the minor-version additive rule.
- No authentication/encryption at this layer (the transport and the #544
  grant-verification path own those).
- No streaming reassembly across frames; each frame is self-contained and
  exactly sized.
