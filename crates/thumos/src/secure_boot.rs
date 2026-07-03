//! Measured boot with Ed25519 signature verification.
//!
//! Verifies the integrity of the kernel image at boot by checking an
//! Ed25519 signature against an embedded public key. The signature is
//! appended as the last 64 bytes of the kernel image; the signed payload
//! is everything preceding it.
//!
//! ## Signature format
//!
//! ```text
//! [ kernel image payload (N bytes) ][ Ed25519 signature (64 bytes) ]
//! ```
//!
//! The Ed25519 signature covers the kernel image payload (all bytes
//! except the trailing 64-byte signature itself).
//!
//! ## Boot integration
//!
//! Runs in `kinit.rs` after display initialization (so errors can be
//! rendered) but before filesystem mount (so a tampered kernel cannot
//! access encrypted data). On failure, the boot process halts with a
//! visible error.
//!
//! ## Key management
//!
//! The public key is embedded as a compile-time constant. The
//! corresponding private key lives offline (Titan security key or
//! air-gapped machine) and is used by a build-side signing tool.
//!
//! ## Ed25519 implementation
//!
//! Verification is delegated to the audited [`ed25519_dalek`] crate
//! (`verify_strict`, RFC 8032 section 5.1.7) with SHA-512 provided by
//! [`sha2`]. Both are audited pure-Rust crates from the same family as the
//! kernel's `aes` / `xts-mode` dependencies, consistent with the "no C we
//! author" doctrine.

use core::fmt;

use ed25519_dalek::{Signature, VerifyingKey};

// ---------------------------------------------------------------------------
// Public key — placeholder (replaced at build time with real key)
// ---------------------------------------------------------------------------

/// Ed25519 public key size in bytes.
pub(crate) const PUBLIC_KEY_LEN: usize = 32;

/// Ed25519 signature size in bytes.
pub(crate) const SIGNATURE_LEN: usize = 64;

/// Minimum image size: at least 1 byte of payload + 64-byte signature.
const MIN_IMAGE_SIZE: usize = SIGNATURE_LEN + 1;

/// Embedded Ed25519 public key for kernel signature verification.
///
/// TODO(#233)[deliberate-prudent]: this is the RFC 8032 section 7.1 Test 1 public key, NOT a
/// real trust anchor. It must be replaced with the production boot key
/// injected by the offline signing infrastructure before any release
/// build. The corresponding private key is stored on a Titan security key
/// or air-gapped machine and never touches the device.
///
/// WARNING: the previous value here was a corrupted copy of this vector
/// (11 trailing bytes wrong) — an off-curve point that no Ed25519 verifier
/// can decompress. Restored to the genuine RFC 8032 Test 1 public key.
const BOOT_PUBLIC_KEY: [u8; PUBLIC_KEY_LEN] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from secure boot verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
#[non_exhaustive]
pub enum SecureBootError {
    /// Image is too short to contain a payload and signature.
    ImageTooShort,
    /// The Ed25519 signature does not verify against the payload.
    InvalidSignature,
    /// The public key embedded in the image does not match the expected key.
    WrongPublicKey,
}

impl fmt::Display for SecureBootError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ImageTooShort => write!(f, "kernel image too short for signature verification"),
            Self::InvalidSignature => write!(f, "Ed25519 signature verification failed"),
            Self::WrongPublicKey => write!(f, "public key does not match expected boot key"),
        }
    }
}

// ===========================================================================
// Ed25519 signature verification — RFC 8032 section 5.1.7
// ===========================================================================

/// Verify an Ed25519 signature over `message` with the given `public_key`.
///
/// Uses [`VerifyingKey::verify_strict`], which enforces the RFC 8032
/// canonical-encoding and small-order-rejection checks (the stricter,
/// non-malleable verification appropriate for secure boot).
///
/// Returns `false` for a malformed public key, a malformed signature, or a
/// signature that does not verify.
fn ed25519_verify(
    public_key: &[u8; PUBLIC_KEY_LEN],
    message: &[u8],
    signature: &[u8; SIGNATURE_LEN],
) -> bool {
    let Ok(verifying_key) = VerifyingKey::from_bytes(public_key) else {
        return false;
    };
    let sig = Signature::from_bytes(signature);
    verifying_key.verify_strict(message, &sig).is_ok()
}

// ===========================================================================
// Public API
// ===========================================================================

/// Verify the Ed25519 signature of a kernel image.
///
/// The image format is: `[payload || signature(64 bytes)]`.
/// The signature covers only the payload bytes.
///
/// Verification uses the embedded [`BOOT_PUBLIC_KEY`].
///
/// # Errors
///
/// - [`SecureBootError::ImageTooShort`] if the image is empty (no payload
///   to verify).
/// - [`SecureBootError::InvalidSignature`] if the Ed25519 signature
///   does not verify against the payload.
#[must_use = "verification result must be checked"]
pub(crate) fn verify_kernel_signature(
    image: &[u8],
    signature: &[u8; SIGNATURE_LEN],
) -> Result<(), SecureBootError> {
    if image.is_empty() {
        return Err(SecureBootError::ImageTooShort);
    }

    if ed25519_verify(&BOOT_PUBLIC_KEY, image, signature) {
        Ok(())
    } else {
        Err(SecureBootError::InvalidSignature)
    }
}

/// Verify the Ed25519 signature of a kernel image using a caller-supplied
/// public key. This allows testing with test keypairs while keeping the
/// same verification logic.
///
/// Unlike [`verify_kernel_signature`], this does not reject an empty
/// `image`: Ed25519 signs messages of any length (including zero), and this
/// helper exercises the raw verification path directly.
///
/// # Errors
///
/// - [`SecureBootError::WrongPublicKey`] if the supplied key does not
///   match the embedded boot key (when `require_boot_key` is true).
/// - [`SecureBootError::InvalidSignature`] if verification fails.
#[must_use = "verification result must be checked"]
pub(crate) fn verify_kernel_signature_with_key(
    image: &[u8],
    signature: &[u8; SIGNATURE_LEN],
    public_key: &[u8; PUBLIC_KEY_LEN],
    require_boot_key: bool,
) -> Result<(), SecureBootError> {
    if require_boot_key && *public_key != BOOT_PUBLIC_KEY {
        return Err(SecureBootError::WrongPublicKey);
    }

    if ed25519_verify(public_key, image, signature) {
        Ok(())
    } else {
        Err(SecureBootError::InvalidSignature)
    }
}

/// Verify an Ed25519 signature over an arbitrary message with a
/// caller-supplied public key.
///
/// Generic entry point for non-kernel-image signature verification (e.g.
/// USB provisioning bundles, see `crate::provision`) that still wants the
/// audited `ed25519_dalek` `verify_strict` path used by
/// [`verify_kernel_signature`].
///
/// # Errors
///
/// Returns [`SecureBootError::InvalidSignature`] if the signature does not
/// verify against `message` under `public_key`.
#[must_use = "verification result must be checked"]
pub(crate) fn verify_message_signature(
    message: &[u8],
    signature: &[u8; SIGNATURE_LEN],
    public_key: &[u8; PUBLIC_KEY_LEN],
) -> Result<(), SecureBootError> {
    if ed25519_verify(public_key, message, signature) {
        Ok(())
    } else {
        Err(SecureBootError::InvalidSignature)
    }
}

/// Extract the signature and payload from a combined kernel image.
///
/// The expected format is `[payload (N bytes) || signature (64 bytes)]`.
/// Returns `(payload, signature)` on success.
///
/// # Errors
///
/// Returns [`SecureBootError::ImageTooShort`] if the image is shorter
/// than [`MIN_IMAGE_SIZE`] (65 bytes).
pub(crate) fn split_image(image: &[u8]) -> Result<(&[u8], [u8; SIGNATURE_LEN]), SecureBootError> {
    if image.len() < MIN_IMAGE_SIZE {
        return Err(SecureBootError::ImageTooShort);
    }

    let split_at = image.len() - SIGNATURE_LEN;
    let payload = &image[..split_at];
    let mut sig = [0u8; SIGNATURE_LEN];
    sig.copy_from_slice(&image[split_at..]);
    Ok((payload, sig))
}

/// Verify a combined kernel image (payload + appended signature).
///
/// Convenience wrapper that splits the image and verifies in one call.
///
/// # Errors
///
/// - [`SecureBootError::ImageTooShort`] if the image is too short.
/// - [`SecureBootError::InvalidSignature`] if verification fails.
#[must_use = "verification result must be checked"]
pub(crate) fn verify_combined_image(image: &[u8]) -> Result<(), SecureBootError> {
    let (payload, sig) = split_image(image)?;
    verify_kernel_signature(payload, &sig)
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
/// One-shot SHA-512 over `data` via the audited [`sha2`] crate.
///
/// WHY: retained solely for the SHA-512 known-answer tests below; the
/// Ed25519 verification path hashes internally inside `ed25519-dalek`.
fn sha512(data: &[u8]) -> [u8; 64] {
    use sha2::Digest;
    let digest = sha2::Sha512::digest(data);
    let mut out = [0u8; 64];
    out.copy_from_slice(&digest);
    out
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::*;

    // -- SHA-512 test vectors (NIST) --

    #[test]
    fn sha512_empty() {
        // NIST: SHA-512("") = cf83e1357eefb8bd...
        let digest = sha512(b"");
        let expected: [u8; 64] = [
            0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd, 0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d,
            0x80, 0x07, 0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc, 0x83, 0xf4, 0xa9, 0x21,
            0xd3, 0x6c, 0xe9, 0xce, 0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0, 0xff, 0x83,
            0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f, 0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81,
            0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e,
        ];
        assert_eq!(
            digest, expected,
            "SHA-512 of empty string must match NIST vector"
        );
    }

    #[test]
    fn sha512_abc() {
        // NIST: SHA-512("abc") = ddaf35a193617aba...
        let digest = sha512(b"abc");
        let expected: [u8; 64] = [
            0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49, 0xae, 0x20,
            0x41, 0x31, 0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2, 0x0a, 0x9e, 0xee, 0xe6,
            0x4b, 0x55, 0xd3, 0x9a, 0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba,
            0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd, 0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e,
            0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f,
        ];
        assert_eq!(digest, expected, "SHA-512 of 'abc' must match NIST vector");
    }

    // -- Ed25519 verification with RFC 8032 test vectors --

    /// RFC 8032 section 7.1 Test Vector 1: empty message.
    #[test]
    fn ed25519_rfc8032_test1_empty_message() {
        let public_key: [u8; 32] = [
            0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64,
            0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68,
            0xf7, 0x07, 0x51, 0x1a,
        ];
        let signature: [u8; 64] = [
            0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e,
            0x82, 0x8a, 0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74, 0xd8, 0x73, 0xe0, 0x65,
            0x22, 0x49, 0x01, 0x55, 0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac, 0xc6, 0x1e,
            0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b, 0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24,
            0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b,
        ];

        assert!(
            ed25519_verify(&public_key, b"", &signature),
            "RFC 8032 test vector 1 (empty message) must verify"
        );
    }

    /// RFC 8032 section 7.1 Test Vector 2: single byte 0x72.
    #[test]
    fn ed25519_rfc8032_test2_one_byte() {
        let public_key: [u8; 32] = [
            0x3d, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89, 0x5a, 0x92, 0xb7, 0x0a, 0xa7, 0x4d, 0x1b,
            0x7e, 0xbc, 0x9c, 0x98, 0x2c, 0xcf, 0x2e, 0xc4, 0x96, 0x8c, 0xc0, 0xcd, 0x55, 0xf1,
            0x2a, 0xf4, 0x66, 0x0c,
        ];
        let signature: [u8; 64] = [
            0x92, 0xa0, 0x09, 0xa9, 0xf0, 0xd4, 0xca, 0xb8, 0x72, 0x0e, 0x82, 0x0b, 0x5f, 0x64,
            0x25, 0x40, 0xa2, 0xb2, 0x7b, 0x54, 0x16, 0x50, 0x3f, 0x8f, 0xb3, 0x76, 0x22, 0x23,
            0xeb, 0xdb, 0x69, 0xda, 0x08, 0x5a, 0xc1, 0xe4, 0x3e, 0x15, 0x99, 0x6e, 0x45, 0x8f,
            0x36, 0x13, 0xd0, 0xf1, 0x1d, 0x8c, 0x38, 0x7b, 0x2e, 0xae, 0xb4, 0x30, 0x2a, 0xee,
            0xb0, 0x0d, 0x29, 0x16, 0x12, 0xbb, 0x0c, 0x00,
        ];

        assert!(
            ed25519_verify(&public_key, &[0x72], &signature),
            "RFC 8032 test vector 2 (0x72) must verify"
        );
    }

    /// RFC 8032 section 7.1 Test Vector 3: two bytes.
    #[test]
    fn ed25519_rfc8032_test3_two_bytes() {
        let public_key: [u8; 32] = [
            0xfc, 0x51, 0xcd, 0x8e, 0x62, 0x18, 0xa1, 0xa3, 0x8d, 0xa4, 0x7e, 0xd0, 0x02, 0x30,
            0xf0, 0x58, 0x08, 0x16, 0xed, 0x13, 0xba, 0x33, 0x03, 0xac, 0x5d, 0xeb, 0x91, 0x15,
            0x48, 0x90, 0x80, 0x25,
        ];
        let signature: [u8; 64] = [
            0x62, 0x91, 0xd6, 0x57, 0xde, 0xec, 0x24, 0x02, 0x48, 0x27, 0xe6, 0x9c, 0x3a, 0xbe,
            0x01, 0xa3, 0x0c, 0xe5, 0x48, 0xa2, 0x84, 0x74, 0x3a, 0x44, 0x5e, 0x36, 0x80, 0xd7,
            0xdb, 0x5a, 0xc3, 0xac, 0x18, 0xff, 0x9b, 0x53, 0x8d, 0x16, 0xf2, 0x90, 0xae, 0x67,
            0xf7, 0x60, 0x98, 0x4d, 0xc6, 0x59, 0x4a, 0x7c, 0x15, 0xe9, 0x71, 0x6e, 0xd2, 0x8d,
            0xc0, 0x27, 0xbe, 0xce, 0xea, 0x1e, 0xc4, 0x0a,
        ];

        assert!(
            ed25519_verify(&public_key, &[0xaf, 0x82], &signature),
            "RFC 8032 test vector 3 (0xaf82) must verify"
        );
    }

    // -- Secure boot API tests --

    /// Test that a valid signature on a known message verifies.
    #[test]
    fn valid_signature_passes() {
        // Use RFC 8032 test vector 1 keypair.
        let public_key: [u8; 32] = [
            0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64,
            0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68,
            0xf7, 0x07, 0x51, 0x1a,
        ];
        let signature: [u8; 64] = [
            0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e,
            0x82, 0x8a, 0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74, 0xd8, 0x73, 0xe0, 0x65,
            0x22, 0x49, 0x01, 0x55, 0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac, 0xc6, 0x1e,
            0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b, 0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24,
            0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b,
        ];

        let result = verify_kernel_signature_with_key(
            b"", // empty message (RFC 8032 test 1)
            &signature,
            &public_key,
            false, // don't require boot key match
        );
        assert_eq!(result, Ok(()), "valid signature must verify");
    }

    /// Test that an invalid (corrupted) signature fails.
    #[test]
    fn invalid_signature_fails() {
        let public_key: [u8; 32] = [
            0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64,
            0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68,
            0xf7, 0x07, 0x51, 0x1a,
        ];
        // Valid signature with one byte corrupted (byte 0 changed).
        let mut signature: [u8; 64] = [
            0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e,
            0x82, 0x8a, 0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74, 0xd8, 0x73, 0xe0, 0x65,
            0x22, 0x49, 0x01, 0x55, 0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac, 0xc6, 0x1e,
            0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b, 0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24,
            0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b,
        ];
        signature[0] ^= 0x01; // corrupt one bit

        let result = verify_kernel_signature_with_key(b"", &signature, &public_key, false);
        assert_eq!(
            result,
            Err(SecureBootError::InvalidSignature),
            "corrupted signature must fail"
        );
    }

    /// Test that an empty image (too short) fails.
    #[test]
    fn truncated_image_fails() {
        let sig = [0u8; 64];
        let result = verify_kernel_signature(&[], &sig);
        assert_eq!(
            result,
            Err(SecureBootError::ImageTooShort),
            "empty image must fail with ImageTooShort"
        );
    }

    /// Test that split_image rejects images shorter than MIN_IMAGE_SIZE.
    #[test]
    fn split_image_too_short() {
        let short = [0u8; 64]; // exactly 64 bytes, need 65+
        assert_eq!(
            split_image(&short),
            Err(SecureBootError::ImageTooShort),
            "image of exactly 64 bytes must fail (need at least 65)"
        );
    }

    /// Test that a wrong public key is rejected.
    #[test]
    fn wrong_public_key_fails() {
        let signature: [u8; 64] = [
            0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e,
            0x82, 0x8a, 0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74, 0xd8, 0x73, 0xe0, 0x65,
            0x22, 0x49, 0x01, 0x55, 0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac, 0xc6, 0x1e,
            0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b, 0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24,
            0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b,
        ];
        // Different public key (all zeros — definitely not the boot key).
        let wrong_key = [0u8; 32];

        let result = verify_kernel_signature_with_key(
            b"", &signature, &wrong_key, true, // require boot key match
        );
        assert_eq!(
            result,
            Err(SecureBootError::WrongPublicKey),
            "wrong public key must be rejected when require_boot_key is true"
        );
    }

    /// Test that wrong message fails (right key, right signature format,
    /// but signature was for a different message).
    #[test]
    fn wrong_message_fails() {
        let public_key: [u8; 32] = [
            0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64,
            0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68,
            0xf7, 0x07, 0x51, 0x1a,
        ];
        // This signature is valid for empty message, not for "tampered".
        let signature: [u8; 64] = [
            0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e,
            0x82, 0x8a, 0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74, 0xd8, 0x73, 0xe0, 0x65,
            0x22, 0x49, 0x01, 0x55, 0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac, 0xc6, 0x1e,
            0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b, 0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24,
            0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b,
        ];

        let result = verify_kernel_signature_with_key(
            b"tampered kernel image",
            &signature,
            &public_key,
            false,
        );
        assert_eq!(
            result,
            Err(SecureBootError::InvalidSignature),
            "signature for wrong message must fail"
        );
    }

    /// Test split_image correctly separates payload and signature.
    #[test]
    fn split_image_correct() {
        let mut image = [0u8; 128];
        // Fill payload with 0xAA, signature with 0xBB.
        for byte in &mut image[..64] {
            *byte = 0xAA;
        }
        for byte in &mut image[64..128] {
            *byte = 0xBB;
        }

        let (payload, sig) =
            split_image(&image).expect("split_image must succeed for 128-byte image");
        assert_eq!(payload.len(), 64, "payload must be 64 bytes");
        assert!(
            payload.iter().all(|&b| b == 0xAA),
            "payload must be all 0xAA"
        );
        assert!(sig.iter().all(|&b| b == 0xBB), "signature must be all 0xBB");
    }

    /// Test Display impl for SecureBootError.
    #[test]
    fn error_display() {
        let msg = SecureBootError::ImageTooShort.to_string();
        assert!(
            msg.contains("too short"),
            "ImageTooShort display must mention 'too short'"
        );

        let msg = SecureBootError::InvalidSignature.to_string();
        assert!(
            msg.contains("verification failed"),
            "InvalidSignature display"
        );

        let msg = SecureBootError::WrongPublicKey.to_string();
        assert!(msg.contains("does not match"), "WrongPublicKey display");
    }
}
