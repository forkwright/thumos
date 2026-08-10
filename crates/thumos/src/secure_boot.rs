//! Measured boot with Ed25519ph signature verification.
//!
//! Verifies the integrity of the boot image at boot by checking an
//! Ed25519ph (prehashed, RFC 8032) signature against an embedded public
//! key. The signature is the last 64 bytes of the on-disk region; the
//! signed payload is everything preceding it (zero-padded so the signature
//! lands on the sector boundary, matching the sphragis signing tool).
//!
//! ## Signature format
//!
//! ```text
//! [ image payload (N bytes) ][ zero pad ][ Ed25519ph signature (64 bytes) ]
//! ```
//!
//! Ed25519ph (sign/verify over the SHA-512 prehash) is chosen over plain
//! Ed25519 so verification streams over bounded sector reads — a multi-MB
//! boot image never needs a contiguous buffer (#467).
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
//!
//! ## Trust root (per #467's review item)
//!
//! This gate is a LINK in the boot chain, not the sole root: the chain is
//! BROM (mask ROM, reads the preloader) -> preloader/LK (loads the boot
//! image) -> this kernel's gate (verifies the boot image's Ed25519ph
//! signature against the embedded anchor before any decrypt/mount/
//! userspace step). What verifies THE KERNEL IMAGE is therefore the
//! preloader's verified-boot configuration on the device — on the AGM M7
//! as currently operated, that upstream link is NOT established by this
//! repository (the stock device's verified-boot state is an
//! operator/hardware fact, hardware-ledger work). Until it is, this gate
//! honestly bounds its own claim: it proves the boot image is the one the
//! signing key holder built, given a kernel that already started — it
//! cannot by itself defeat a compromised preloader. That boundary is why
//! `secure_boot_ok` reads as "verified against the production anchor" and
//! no more, and why the fail-closed invariant (present-but-unreadable ->
//! Halt) matters: the gate's value is that it never WIDENS what booted.

use core::fmt;

use ed25519_dalek::{Signature, VerifyingKey};

// ---------------------------------------------------------------------------
// Public key — provisioned at build time by build.rs (#233)
// ---------------------------------------------------------------------------

/// Ed25519 public key size in bytes.
pub(crate) const PUBLIC_KEY_LEN: usize = 32;

/// Ed25519 signature size in bytes.
pub(crate) const SIGNATURE_LEN: usize = 64;

/// Minimum image size: at least 1 byte of payload + 64-byte signature.
const MIN_IMAGE_SIZE: usize = SIGNATURE_LEN + 1;

// WHY (#233): the trust anchor is never a source-committed production key.
// build.rs sources it (THUMOS_BOOT_KEY_PUB under `--features production`;
// the committed, deliberately-public dev key otherwise), refuses the
// forgeable RFC 8032 placeholder and off-curve bytes, and generates
// BOOT_PUBLIC_KEY / BOOT_KEY_IS_PRODUCTION / BOOT_TRUST_STAMP (plus, for
// dev-key builds, the test-only signing seed).
include!(concat!(env!("OUT_DIR"), "/boot_key.rs"));

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

/// Verify that an image-resident userspace payload (the boot initramfs) was
/// signed by the embedded boot anchor (#480).
///
/// WHY: establishes `userspace_image_verified` so a cryptographically-verified
/// image-resident userspace may spawn even when no boot MEDIUM was verified
/// (`secure_boot_ok == false`, e.g. the eMMC-less QEMU boot). This FULFILLS the
/// #217 requirement that userspace runs only when trust is cryptographically
/// established -- for the image-resident case -- rather than weakening it: the
/// blanket refusal existed only because no verification mechanism did. build.rs
/// signs the initramfs with the dev seed, so this verifies under the dev/qemu
/// anchor; under a production anchor the dev signature does NOT verify, so a
/// production image correctly falls back to the eMMC secure-boot gate.
#[must_use]
pub(crate) fn verify_userspace_image(image: &[u8], signature: &[u8; SIGNATURE_LEN]) -> bool {
    verify_kernel_signature(image, signature).is_ok()
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

/// Verify a combined image in memory using Ed25519ph (#467) — the same
/// signature scheme as the streamed path, for images that already fit in
/// memory (tests, small regions). The boot-partition path is
/// [`verify_image_streamed`]; both verify under [`BOOT_PUBLIC_KEY`].
///
/// # Errors
///
/// As [`verify_combined_image`].
pub(crate) fn verify_combined_image_ph(image: &[u8]) -> Result<(), SecureBootError> {
    use sha2::Digest as _;
    let (payload, sig_bytes) = split_image(image)?;
    let Ok(key) = VerifyingKey::from_bytes(&BOOT_PUBLIC_KEY) else {
        return Err(SecureBootError::InvalidSignature);
    };
    let mut prehash = sha2::Sha512::new();
    prehash.update(payload);
    let sig = Signature::from_bytes(&sig_bytes);
    key.verify_prehashed_strict(prehash, None, &sig)
        .map_err(|_| SecureBootError::InvalidSignature)
}

/// Verify a combined boot image (payload || signature) STREAMED from a
/// block device, using Ed25519ph (#467).
///
/// WHY Ed25519ph: plain Ed25519 verifies a contiguous in-memory message,
/// but a multi-MB boot image cannot fit the 1 MB kernel heap — and must
/// never require one. Ed25519ph prehashes with SHA-512, streamed here over
/// bounded 4 KiB sector reads; memory stays O(chunk), never O(image).
/// `verify_prehashed_strict` keeps the non-malleable posture of the
/// `verify_strict` path used everywhere else in this module.
///
/// The image layout is the same `payload || signature(64)` as
/// [`split_image`]; the signature covers the payload's SHA-512 prehash.
/// Reading a partition view (#603) is the intended caller-side shape.
///
/// # Errors
///
/// - [`SecureBootError::ImageTooShort`] if the region is smaller than a
///   signature plus one payload byte.
/// - [`SecureBootError::InvalidSignature`] on any verification failure or
///   unreadable sector (the caller maps failures to Halt per #467's
///   fail-closed invariant — there is no degraded read).
#[cfg(not(feature = "qemu"))]
pub(crate) fn verify_image_streamed<D: crate::block::BlockDevice>(
    dev: &D,
    total_sectors: u64,
    public_key: &[u8; PUBLIC_KEY_LEN],
) -> Result<(), SecureBootError> {
    use sha2::Digest as _;

    const CHUNK_SECTORS: u64 = (4 * 1024 / crate::block::SECTOR_SIZE) as u64; // 8

    let total_bytes = total_sectors.saturating_mul(crate::block::SECTOR_SIZE as u64);
    if total_bytes < MIN_IMAGE_SIZE as u64 {
        return Err(SecureBootError::ImageTooShort);
    }
    let Ok(key) = VerifyingKey::from_bytes(public_key) else {
        return Err(SecureBootError::InvalidSignature);
    };

    let payload_bytes = total_bytes - SIGNATURE_LEN as u64;
    let mut prehash = sha2::Sha512::new();
    let mut signature = [0u8; SIGNATURE_LEN];
    let mut lba = 0u64;
    let mut chunk = [0u8; 4 * 1024];

    while lba < total_sectors {
        let remaining_sectors = total_sectors - lba;
        let take = if remaining_sectors < CHUNK_SECTORS {
            remaining_sectors
        } else {
            CHUNK_SECTORS
        };
        let take_bytes = (take as usize) * crate::block::SECTOR_SIZE;
        dev.read_sectors(lba, take as u32, &mut chunk[..take_bytes])
            .map_err(|_| SecureBootError::InvalidSignature)?;
        let chunk_start = lba * crate::block::SECTOR_SIZE as u64;
        let chunk_end = chunk_start + take_bytes as u64;
        if chunk_end <= payload_bytes {
            // Whole chunk is payload.
            prehash.update(&chunk[..take_bytes]);
        } else if chunk_start >= payload_bytes {
            // Whole chunk is signature (only the final 64 bytes can be).
            let off = (chunk_start - payload_bytes) as usize;
            signature[off..off + take_bytes].copy_from_slice(&chunk[..take_bytes]);
        } else {
            // The boundary chunk: payload prefix into the prehash, the
            // 64-byte signature suffix out.
            let cut = (payload_bytes - chunk_start) as usize;
            prehash.update(&chunk[..cut]);
            signature[..take_bytes - cut].copy_from_slice(&chunk[cut..take_bytes]);
        }
        lba += take;
    }

    let sig = Signature::from_bytes(&signature);
    key.verify_prehashed_strict(prehash, None, &sig)
        .map_err(|_| SecureBootError::InvalidSignature)
}

// ===========================================================================
// Boot gate (#217) — fail-closed decision over the boot-image source
// ===========================================================================

/// Where the boot image came from, as established by kinit's secure-boot
/// step.
///
/// INVARIANT (#217): `Absent` means no boot medium exists — nothing to
/// verify AND nothing persistent to mount — so the boot may continue
/// DEGRADED with every trust-gated step locked. It must never stand in for
/// "a boot partition exists but could not be read or verified": that is the
/// fail-closed HALT class, expressed as `Present` with a failing
/// verification.
pub(crate) enum BootImageSource<'a> {
    /// The combined image (payload || Ed25519ph signature) read from the boot
    /// partition, in memory (tests and small images).
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "constructed by the eMMC boot-partition read wiring (#217 follow-on); the gate consumes it today"
        )
    )]
    Present(&'a [u8]),
    /// The boot partition as a block-device region, verified by STREAMED
    /// Ed25519ph (#467): a multi-MB image never needs a contiguous buffer.
    /// M7-only: virt models no eMMC, so no streamed region exists there.
    #[cfg(not(feature = "qemu"))]
    PresentStreamed {
        /// The boot partition view (already base-translated, #603).
        dev: crate::block::PartitionBlockDevice<&'a mut dyn crate::block::BlockDevice>,
        /// Region length in sectors.
        sectors: u64,
    },
    /// A boot medium exists but the boot partition could not be read or
    /// parsed: I/O error, missing GPT entry, blanked partition. INVARIANT
    /// (#467): this maps to Halt, never to the Absent/degraded path —
    /// "attacker deleted the boot partition" is a halt class, not a degrade.
    Unreadable,
    /// No boot medium: qemu (no MSDC model) or an eMMC that failed init, so
    /// no partition is readable and no persistent data is mountable.
    Absent,
}

/// Outcome of the secure-boot gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub(crate) enum SecureBootDecision {
    /// Continue booting. `verified` is the sole input to
    /// `BootState::secure_boot_ok` and is true only on cryptographic
    /// success.
    Proceed {
        /// True only when the boot image verified against the embedded key.
        verified: bool,
    },
    /// A boot partition exists and its image failed verification (or could
    /// not be parsed): the kernel must HALT before any decrypt / mount /
    /// userspace step.
    Halt(SecureBootError),
}

/// Evaluate the fail-closed secure-boot gate (#217).
///
/// - `Present` + valid signature: proceed, trusted.
/// - `Present` + anything else: halt (fail closed).
/// - `Absent` (no boot medium): proceed UNTRUSTED — `secure_boot_ok` stays
///   false and every downstream trust gate (LFS mount, passphrase,
///   encrypted mount, audit key, persistent userspace) stays locked.
pub(crate) fn evaluate_boot_image(source: &BootImageSource<'_>) -> SecureBootDecision {
    match source {
        BootImageSource::Present(image) => match verify_combined_image_ph(image) {
            Ok(()) => SecureBootDecision::Proceed { verified: true },
            Err(e) => SecureBootDecision::Halt(e),
        },
        #[cfg(not(feature = "qemu"))]
        BootImageSource::PresentStreamed { dev, sectors } => {
            match verify_image_streamed(dev, *sectors, &BOOT_PUBLIC_KEY) {
                Ok(()) => SecureBootDecision::Proceed { verified: true },
                Err(e) => SecureBootDecision::Halt(e),
            }
        }
        // #467: a present-but-unreadable boot partition is a halt class —
        // never the Absent degrade.
        BootImageSource::Unreadable => SecureBootDecision::Halt(SecureBootError::ImageTooShort),
        BootImageSource::Absent => SecureBootDecision::Proceed { verified: false },
    }
}

/// Construct the boot-image source from the eMMC (#467): GPT-locate the
/// `boot` partition by name and return its streamed view. ANY failure —
/// I/O error, missing GPT entry, blanked table — maps to
/// [`BootImageSource::Unreadable`], which the gate halts on. This is the
/// fail-closed construction site the issue's invariant names.
#[cfg(not(feature = "qemu"))]
pub(crate) fn boot_image_source(dev: &mut dyn crate::block::BlockDevice) -> BootImageSource<'_> {
    match crate::gpt::find_partition(dev, "boot") {
        Ok(boot) => BootImageSource::PresentStreamed {
            dev: crate::block::PartitionBlockDevice::new(dev, boot.first_lba, boot.sectors()),
            sectors: boot.sectors(),
        },
        Err(_) => BootImageSource::Unreadable,
    }
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

    // -- Streamed Ed25519ph verify (#467) --
    //
    // WHY the gate on this section: boot_image_source/verify_image_streamed
    // are themselves #[cfg(not(feature = "qemu"))] -- GPT-located eMMC boot
    // partition verification is M7-hardware-only, matching board::virt's own
    // "no eMMC" (see board/virt.rs). These tests exercise functions that do
    // not exist in a qemu build; they are not weakened test coverage of
    // anything a qemu boot actually exercises, only aligned with the
    // production gate already in place on the functions under test.
    #[cfg(not(feature = "qemu"))]
    #[test]
    fn unreadable_boot_partition_halts_never_degrades() {
        // #467's fail-closed invariant at the construction site: a present
        // but unreadable boot region (here: an uninitialized/failing eMMC
        // read) maps to Unreadable -> Halt, never to Absent/degraded.
        let mut dev = crate::block::tests::FailingBlockDevice::new(2048, 0);
        let source = boot_image_source(&mut dev);
        assert!(
            matches!(source, BootImageSource::Unreadable),
            "an unreadable GPT must construct Unreadable, not Absent"
        );
        assert!(
            matches!(evaluate_boot_image(&source), SecureBootDecision::Halt(_)),
            "read failure must HALT — a deleted/corrupt boot partition is not a degrade"
        );
    }

    #[cfg(not(feature = "qemu"))]
    #[test]
    fn gpt_located_signed_boot_partition_verifies() {
        use crate::block::BlockDevice as _;
        // The full happy path through the construction site: a synthetic
        // GPT naming "boot", holding an Ed25519ph-signed image under the
        // embedded anchor, verifies via the streamed path.
        let seed = BOOT_KEY_DEV_SEED.expect("dev anchor required for the streamed-verify test");
        let (image, _pubkey) = signed_image(4096, &seed);
        let mut dev = crate::block::MemBlockDevice::new(4096).expect("dev");
        // GPT: "boot" at [2048, 2048 + image_sectors).
        let image_sectors = (image.len() / 512) as u64;
        // Write the image at the partition base.
        dev.write_sectors(2048, image_sectors as u32, &image)
            .expect("write image");
        // Build the GPT over it.
        let entry_size = 128usize;
        let entry_count = 128u32;
        let entries_bytes = entry_count as usize * entry_size;
        let mut table = alloc::vec![0u8; entries_bytes];
        table[0] = 0xAF;
        table[32..40].copy_from_slice(&2048u64.to_le_bytes());
        table[40..48].copy_from_slice(&(2048 + image_sectors - 1).to_le_bytes());
        for (j, b) in b"boot".iter().enumerate() {
            table[56 + j * 2] = *b;
        }
        let entries_crc = crate::gpt::crc32(&table);
        dev.write_sectors(2, (entries_bytes / 512) as u32, &table)
            .expect("entries");
        let mut header = [0u8; 512];
        header[..8].copy_from_slice(b"EFI PART");
        header[12..16].copy_from_slice(&92u32.to_le_bytes());
        header[72..80].copy_from_slice(&2u64.to_le_bytes());
        header[80..84].copy_from_slice(&entry_count.to_le_bytes());
        header[84..88].copy_from_slice(&(entry_size as u32).to_le_bytes());
        header[88..92].copy_from_slice(&entries_crc.to_le_bytes());
        let header_crc = crate::gpt::crc32(&header[..92]);
        header[16..20].copy_from_slice(&header_crc.to_le_bytes());
        dev.write_sectors(1, 1, &header).expect("header");

        let source = boot_image_source(&mut dev);
        match source {
            BootImageSource::PresentStreamed { .. } => {}
            _ => panic!("a valid GPT must yield PresentStreamed"),
        }
        match evaluate_boot_image(&source) {
            SecureBootDecision::Proceed { verified: true } => {}
            other => panic!("a valid signed boot partition must verify, got {other:?}"),
        }
    }

    /// Build a signed combined image: payload zero-padded so that
    /// payload+pad+signature is sector-aligned (the on-disk layout the
    /// streamed verifier expects — the signature is the region's final 64
    /// bytes).
    #[cfg(not(feature = "qemu"))]
    fn signed_image(payload_len: usize, seed: &[u8; 32]) -> (alloc::vec::Vec<u8>, [u8; 32]) {
        use ed25519_dalek::SigningKey;
        use sha2::Digest as _;
        let key = SigningKey::from_bytes(seed);
        // Pad so payload+pad ends exactly 64 bytes before a sector boundary.
        let padded_len = (payload_len + SIGNATURE_LEN).div_ceil(512) * 512 - SIGNATURE_LEN;
        let mut payload = alloc::vec![0u8; padded_len];
        for (i, b) in payload.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(31).wrapping_add(7);
        }
        let mut prehash = sha2::Sha512::new();
        prehash.update(&payload);
        let sig = key.sign_prehashed(prehash, None).expect("sign_prehashed");
        let mut image = payload;
        image.extend_from_slice(&sig.to_bytes());
        (image, key.verifying_key().to_bytes())
    }

    #[cfg(not(feature = "qemu"))]
    #[test]
    fn streamed_verify_accepts_valid_image() {
        use crate::block::BlockDevice as _;
        let (image, pubkey) = signed_image(3 * 4096, &[11u8; 32]); // multi-chunk, 12 KiB payload
        let mut dev =
            crate::block::MemBlockDevice::new((image.len() as u64).div_ceil(512)).expect("dev");
        dev.write_sectors(0, (image.len() / 512) as u32, &image)
            .expect("write image");
        assert_eq!(
            verify_image_streamed(&dev, (image.len() / 512) as u64, &pubkey),
            Ok(()),
            "a valid Ed25519ph-signed image must verify when streamed"
        );
    }

    #[cfg(not(feature = "qemu"))]
    #[test]
    fn streamed_verify_rejects_tampered_payload() {
        use crate::block::BlockDevice as _;
        let (mut image, pubkey) = signed_image(3 * 4096, &[11u8; 32]);
        image[1234] ^= 0x01;
        let mut dev =
            crate::block::MemBlockDevice::new((image.len() as u64).div_ceil(512)).expect("dev");
        dev.write_sectors(0, (image.len() / 512) as u32, &image)
            .expect("write image");
        assert_eq!(
            verify_image_streamed(&dev, (image.len() / 512) as u64, &pubkey),
            Err(SecureBootError::InvalidSignature),
            "a one-bit payload change must fail verification"
        );
    }

    #[cfg(not(feature = "qemu"))]
    #[test]
    fn streamed_verify_rejects_wrong_key() {
        use crate::block::BlockDevice as _;
        let (image, _pubkey) = signed_image(4096, &[11u8; 32]);
        let other = ed25519_dalek::SigningKey::from_bytes(&[22u8; 32]).verifying_key();
        let mut dev =
            crate::block::MemBlockDevice::new((image.len() as u64).div_ceil(512)).expect("dev");
        dev.write_sectors(0, (image.len() / 512) as u32, &image)
            .expect("write image");
        assert_eq!(
            verify_image_streamed(&dev, (image.len() / 512) as u64, &other.to_bytes()),
            Err(SecureBootError::InvalidSignature),
            "a different anchor key must fail"
        );
    }

    #[cfg(not(feature = "qemu"))]
    #[test]
    fn streamed_verify_rejects_too_short_region() {
        let dev = crate::block::MemBlockDevice::new(1).expect("dev");
        assert_eq!(
            verify_image_streamed(&dev, 0, &[0u8; 32]),
            Err(SecureBootError::ImageTooShort)
        );
    }

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

    /// Test `split_image` correctly separates payload and signature.
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

    /// Test that a genuinely valid combined image (payload + Ed25519
    /// signature under the embedded boot key) verifies via
    /// [`verify_combined_image`].
    #[test]
    fn verify_userspace_image_accepts_boot_anchor_signature_and_rejects_tampering() {
        use ed25519_dalek::{Signer, SigningKey};

        // #480: an initramfs signed by the boot anchor verifies; any tamper to
        // the image OR the signature is rejected (so a swapped userspace image
        // cannot establish userspace_image_verified).
        let seed = BOOT_KEY_DEV_SEED.expect("dev anchor required for #480 test");
        let signing_key = SigningKey::from_bytes(&seed);
        let image = *b"thumos initramfs bytes (stand-in)";
        let sig = signing_key.sign(&image).to_bytes();

        assert!(
            verify_userspace_image(&image, &sig),
            "boot-anchor-signed image must verify"
        );

        let mut tampered_image = image;
        tampered_image[0] ^= 0xFF;
        assert!(
            !verify_userspace_image(&tampered_image, &sig),
            "a tampered image must not verify under the original signature"
        );

        let mut tampered_sig = sig;
        tampered_sig[0] ^= 0xFF;
        assert!(
            !verify_userspace_image(&image, &tampered_sig),
            "a tampered signature must not verify"
        );
    }

    #[test]
    fn combined_image_valid_signature_passes() {
        use ed25519_dalek::SigningKey;

        // NOTE (#233): the committed dev seed (keys/dev/boot-dev.seed),
        // emitted by build.rs only when the build's trust anchor is the dev
        // key. Host tests always build without THUMOS_BOOT_KEY_PUB, so the
        // seed is present; a key-overridden test build fails here loudly
        // rather than silently skipping the boot-key round-trip.
        let seed = BOOT_KEY_DEV_SEED.expect("boot-key tests require the dev trust anchor");
        let signing_key = SigningKey::from_bytes(&seed);
        assert_eq!(
            signing_key.verifying_key().to_bytes(),
            BOOT_PUBLIC_KEY,
            "seed must derive the embedded boot public key"
        );

        let payload = [0x5Au8; 16];
        let image = signed_dev_image(&payload);

        assert_eq!(
            verify_combined_image_ph(&image),
            Ok(()),
            "combined image with a valid boot-key signature must verify"
        );
    }

    /// Test that tampering a single payload byte after signing breaks
    /// [`verify_combined_image`] (the signature no longer covers the
    /// modified bytes).
    #[test]
    fn combined_image_tampered_payload_fails() {
        let payload = [0x5Au8; 16];
        let mut image = signed_dev_image(&payload);
        image[0] ^= 0x01; // tamper one payload byte after signing

        assert_eq!(
            verify_combined_image_ph(&image),
            Err(SecureBootError::InvalidSignature),
            "tampered payload byte must fail signature verification"
        );
    }

    /// Test that an image shorter than `MIN_IMAGE_SIZE` is rejected by
    /// [`verify_combined_image`] before any signature verification.
    #[test]
    fn combined_image_too_short_fails() {
        let short = [0u8; 64]; // exactly 64 bytes, need 65+
        assert_eq!(
            verify_combined_image_ph(&short),
            Err(SecureBootError::ImageTooShort),
            "combined image of exactly 64 bytes must fail (need at least 65)"
        );
    }

    /// Test Display impl for `SecureBootError`.
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

    // -- #217 fail-closed boot gate --

    fn signed_dev_image(payload: &[u8]) -> alloc::vec::Vec<u8> {
        // #467: the boot gate verifies Ed25519ph (prehashed SHA-512), so the
        // fixture signs with sign_prehashed — the same scheme the sphragis
        // tool produces for real boot partitions.
        use ed25519_dalek::SigningKey;
        use sha2::Digest as _;
        let seed = BOOT_KEY_DEV_SEED.expect("boot-key tests require the dev trust anchor");
        let signing_key = SigningKey::from_bytes(&seed);
        let mut prehash = sha2::Sha512::new();
        prehash.update(payload);
        let sig = signing_key
            .sign_prehashed(prehash, None)
            .expect("sign_prehashed");
        let mut image = alloc::vec::Vec::from(payload);
        image.extend_from_slice(&sig.to_bytes());
        image
    }

    #[test]
    fn gate_verified_image_proceeds_trusted() {
        let image = signed_dev_image(&[0xA5u8; 32]);
        assert_eq!(
            evaluate_boot_image(&BootImageSource::Present(&image)),
            SecureBootDecision::Proceed { verified: true },
            "a validly signed present image must proceed trusted"
        );
    }

    #[test]
    fn gate_tampered_image_halts() {
        let mut image = signed_dev_image(&[0xA5u8; 32]);
        image[0] ^= 0x01;
        assert_eq!(
            evaluate_boot_image(&BootImageSource::Present(&image)),
            SecureBootDecision::Halt(SecureBootError::InvalidSignature),
            "a tampered present image must halt, never degrade"
        );
    }

    #[test]
    fn gate_unparseable_image_halts() {
        // WHY: present-but-unparseable is the fail-closed HALT class -- it
        // must never be conflated with the no-boot-medium degrade.
        let short = [0u8; 64];
        assert_eq!(
            evaluate_boot_image(&BootImageSource::Present(&short)),
            SecureBootDecision::Halt(SecureBootError::ImageTooShort),
            "an unparseable present image must halt, never degrade"
        );
    }

    #[test]
    fn gate_absent_medium_degrades_untrusted() {
        assert_eq!(
            evaluate_boot_image(&BootImageSource::Absent),
            SecureBootDecision::Proceed { verified: false },
            "no boot medium must proceed degraded-locked, not halt"
        );
    }

    #[test]
    // WHY: BOOT_KEY_IS_PRODUCTION is a per-build const generated by build.rs
    // (production feature vs. dev key), so clippy sees a fixed value for
    // THIS compilation and flags the assert as constant. The test's job is
    // exactly to pin that per-build value here in host-test builds; kept as
    // a runtime #[test] (not a const-eval assert) so it stays a counted,
    // individually reportable entry in the host test suite.
    #[allow(clippy::assertions_on_constants)]
    fn trust_stamp_marks_dev_anchor() {
        // WHY (#233): host tests always build with the dev anchor; the
        // stamp and the production flag must say so.
        assert!(
            !BOOT_KEY_IS_PRODUCTION,
            "host tests must never be production-stamped"
        );
        assert!(
            BOOT_TRUST_STAMP.starts_with("THUMOS-BOOT-TRUST:DEV:"),
            "dev builds must carry the DEV trust stamp"
        );
    }
}
