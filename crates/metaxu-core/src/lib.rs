#![no_std]
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

pub mod envelope;
pub mod error;
pub mod grants;
pub mod protocol;
pub mod session;
