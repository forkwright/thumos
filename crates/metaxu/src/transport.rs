//! Transport abstraction for bridge frames.

use crate::Result;

/// Synchronous request/response transport for serialized bridge frames.
///
/// Implementations may be in-memory, IPC-backed, socket-backed, or any other
/// Menos-facing mechanism. This trait is byte-oriented so tests can exercise
/// serialization without requiring a live runtime connection.
pub trait BridgeTransport /* kanon:ignore RUST/pub-visibility -- public API */ {
    /// Exchange one serialized task request for one serialized task response.
    fn exchange(&mut self, request_frame: &[u8]) -> Result<Vec<u8>>;
}
