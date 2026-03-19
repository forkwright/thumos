//! Error types for `thumos-krypta`.

use snafu::Snafu;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum Error {
    #[snafu(display("key generation failed"))]
    KeyGeneration {
        #[snafu(implicit)]
        location: snafu::Location,
    },

    #[snafu(display("invalid key material or key format"))]
    InvalidKey {
        #[snafu(implicit)]
        location: snafu::Location,
    },

    #[snafu(display("key agreement failed"))]
    KeyAgreement {
        #[snafu(implicit)]
        location: snafu::Location,
    },

    #[snafu(display("message encryption failed"))]
    Encryption {
        #[snafu(implicit)]
        location: snafu::Location,
    },

    #[snafu(display(
        "message decryption failed — ciphertext is corrupt or has been tampered with"
    ))]
    Decryption {
        #[snafu(implicit)]
        location: snafu::Location,
    },

    #[snafu(display("signature verification failed"))]
    InvalidSignature {
        #[snafu(implicit)]
        location: snafu::Location,
    },

    #[snafu(display("key derivation failed"))]
    KeyDerivation {
        #[snafu(implicit)]
        location: snafu::Location,
    },
}
