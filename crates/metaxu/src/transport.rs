//! Transport abstraction for bridge frames.

/// Synchronous request/response transport for serialized bridge frames.
///
/// Implementations may be in-memory, IPC-backed, socket-backed, or any other
/// Menos-facing mechanism. This trait is byte-oriented so tests can exercise
/// serialization without requiring a live runtime connection.
pub trait BridgeTransport /* kanon:ignore RUST/pub-visibility -- public API */ {
    /// Transport-specific failure type.
    ///
    /// Preserved as the [`crate::Error::Transport`] source when
    /// [`crate::BridgeClient::submit`] wraps it, so the concrete cause
    /// survives instead of collapsing into a message string.
    type Error: std::error::Error + 'static;

    /// Exchange one serialized task request for one serialized task response.
    fn exchange(&mut self, request_frame: &[u8]) -> core::result::Result<Vec<u8>, Self::Error>;
}
