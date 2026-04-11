//! Error types for `krypta`.

use snafu::Snafu;

/// Result type for crypto operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Crypto subsystem errors.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum Error {
    /// Key generation failed.
    #[snafu(display("key generation failed"))]
    KeyGeneration {
        /// Source location.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// Invalid key material or format.
    #[snafu(display("invalid key material or key format"))]
    InvalidKey {
        /// Source location.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// Key agreement (DH) failed.
    #[snafu(display("key agreement failed"))]
    KeyAgreement {
        /// Source location.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// Message encryption failed.
    #[snafu(display("message encryption failed"))]
    Encryption {
        /// Source location.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// Message decryption failed (corrupt or tampered ciphertext).
    #[snafu(display(
        "message decryption failed — ciphertext is corrupt or has been tampered with"
    ))]
    Decryption {
        /// Source location.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// Signature verification failed.
    #[snafu(display("signature verification failed"))]
    InvalidSignature {
        /// Source location.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// Key derivation (KDF) failed.
    #[snafu(display("key derivation failed"))]
    KeyDerivation {
        /// Source location.
        #[snafu(implicit)]
        location: snafu::Location,
    },
}
