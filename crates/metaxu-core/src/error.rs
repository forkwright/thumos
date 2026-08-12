//! Encode/decode error type for metaxu-core's wire functions.
//!
//! Deliberately NOT the richer `metaxu::Error<E>` (which carries transport
//! errors, capability-mismatch errors, and `snafu::Location` source
//! tracking): this crate is `no_std`, has no transport concept of its own,
//! and stays dependency-minimal per the established `*-core` convention.
//! `metaxu` converts this into its own `Error::{Encode,Decode,Envelope}`
//! variants at the crate boundary, so its public error shape is unchanged.

use core::fmt;

use crate::envelope::EnvelopeError;

/// A failure encoding or decoding a metaxu-core wire type.
#[derive(Debug)]
#[non_exhaustive]
pub enum CoreError {
    /// Failed to serialize a payload.
    Encode(postcard::Error),
    /// Failed to deserialize a payload.
    Decode(postcard::Error),
    /// The wire envelope rejected a frame before any payload decode.
    Envelope(EnvelopeError),
}

impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Encode(source) => write!(f, "failed to encode: {source}"),
            Self::Decode(source) => write!(f, "failed to decode: {source}"),
            Self::Envelope(source) => write!(f, "envelope rejected frame: {source}"),
        }
    }
}

impl core::error::Error for CoreError {}

/// Result type for metaxu-core's encode/decode functions.
pub(crate) type Result<T> = core::result::Result<T, CoreError>;
