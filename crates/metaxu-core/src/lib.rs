#![no_std]
#![deny(missing_docs)]
//! `no_std` + alloc core for the Aletheia/Thumos wire protocol (#544/#545).
//!
//! Extracted from `metaxu` so the bare-metal kernel and the `metaxu`
//! workspace crate link the identical envelope framing, signed-grant
//! verification, typed task/response payloads, and authenticated-session
//! logic — one implementation on both sides of the wire, not two hand-ports
//! that can drift (the #545 convergence topology; see
//! `docs/convergence.toml` in the kernel repo). Mirrors the established
//! pattern: `sema-core`, `asphaleia-core`, `klesis-core`.
//!
//! This crate performs no I/O and knows nothing about a transport --
//! `metaxu`'s `BridgeClient`/`BridgeTransport` (std-only) and the kernel's
//! own bridge module each supply their own byte-level exchange and convert
//! [`error::CoreError`] into their own richer error type at the boundary.

extern crate alloc;

/// The versioned wire envelope (magic, schema, major/minor, kind,
/// correlation ID, declared length) that every Aletheia-facing frame
/// travels inside — validated before any payload allocation or decode.
pub mod envelope;

/// The encode/decode error type for this crate's wire functions --
/// deliberately narrower than `metaxu`'s own `Error<E>`, which wraps this
/// type at the crate boundary rather than re-deriving it.
pub mod error;

/// Cryptographically verified, expiring capability grants: an Aletheia
/// runtime's signed, time-bounded authorization for one device to request
/// specific capabilities, plus the response-authentication key they derive.
pub mod grants;

/// Wire protocol types for the Aletheia/Thumos bridge: typed task
/// requests, capability grants, and responses, encoded inside the
/// versioned [`envelope`].
pub mod protocol;

/// The authenticated session layer: one mutually authenticated
/// Thumos-to-Aletheia round trip, built on a verified
/// [`grants::SignedGrant`] over the versioned [`envelope`].
pub mod session;
