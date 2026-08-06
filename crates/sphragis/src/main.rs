//! sphragis — boot-image signing tool (#467).
//!
//! σφραγίς = "signet, seal". Signs a boot image with Ed25519ph, producing
//! the `payload || zero-pad || signature(64)` layout the kernel's streamed
//! boot gate verifies: the payload is zero-padded so the 64-byte signature
//! ends EXACTLY on a 512-byte sector boundary (the on-disk region's final
//! bytes), and the SHA-512 prehash covers payload+pad. The prehash is fed
//! in bounded chunks — the same shape as the kernel's `verify_image_streamed`
//! (the tool itself holds the image in memory; it is a build-host tool
//! without the kernel's heap constraint).
//!
//! Usage: sphragis <image-in> <seed-hex-file> <image-out>
//!   The seed file holds the 32-byte Ed25519 seed as 64 lowercase hex chars
//!   (e.g. crates/thumos/keys/dev/boot-dev.seed for dev builds; production
//!   keys live outside the repo).

use ed25519_dalek::SigningKey;
use sha2::Digest as _;

/// Sector size the on-disk layout aligns to.
const SECTOR: usize = 512;
/// Ed25519 signature length.
const SIG_LEN: usize = 64;
/// Hash streaming chunk.
const CHUNK: usize = 64 * 1024;

/// Sign `payload` with `seed`, returning the padded combined image.
fn sign_image(payload: &[u8], seed: &[u8; 32]) -> Vec<u8> {
    // Pad so payload+pad ends exactly SIG_LEN before a sector boundary.
    let padded_len = (payload.len() + SIG_LEN).div_ceil(SECTOR) * SECTOR - SIG_LEN;
    let mut padded = payload.to_vec();
    padded.resize(padded_len, 0);

    // Stream the prehash in bounded chunks (the shape the kernel mirrors).
    let mut prehash = sha2::Sha512::new();
    for chunk in padded.chunks(CHUNK) {
        prehash.update(chunk);
    }
    let key = SigningKey::from_bytes(seed);
    let sig = key
        .sign_prehashed(prehash, None)
        .unwrap_or_else(|e| unreachable!("sign_prehashed with a valid key cannot fail: {e}"));

    let mut image = padded;
    image.extend_from_slice(&sig.to_bytes());
    image
}

/// Parse a 64-hex-char seed file.
fn parse_seed(text: &str) -> Option<[u8; 32]> {
    let text = text.trim();
    if text.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(text.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        eprintln!("usage: sphragis <image-in> <seed-hex-file> <image-out>");
        return std::process::ExitCode::from(2);
    }
    let payload = match std::fs::read(&args[1]) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("sphragis: cannot read {}: {e}", args[1]);
            return std::process::ExitCode::from(1);
        }
    };
    let seed_text = match std::fs::read_to_string(&args[2]) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("sphragis: cannot read seed {}: {e}", args[2]);
            return std::process::ExitCode::from(1);
        }
    };
    let Some(seed) = parse_seed(&seed_text) else {
        eprintln!("sphragis: seed file must hold 32 bytes as 64 lowercase hex chars");
        return std::process::ExitCode::from(1);
    };
    let image = sign_image(&payload, &seed);
    if let Err(e) = std::fs::write(&args[3], &image) {
        eprintln!("sphragis: cannot write {}: {e}", args[3]);
        return std::process::ExitCode::from(1);
    }
    println!(
        "sphragis: signed {} -> {} ({} payload bytes, {} image bytes)",
        args[1],
        args[3],
        payload.len(),
        image.len()
    );
    std::process::ExitCode::SUCCESS
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_image_is_sector_aligned_with_signature_at_end() {
        let payload = b"fake kernel image bytes".to_vec();
        let image = sign_image(&payload, &[7u8; 32]);
        assert_eq!(
            image.len() % SECTOR,
            0,
            "the combined image is sector-aligned"
        );
        assert!(image.starts_with(&payload), "payload leads");
        assert_eq!(
            image.len(),
            SIG_LEN + ((payload.len() + SIG_LEN).div_ceil(SECTOR) * SECTOR - SIG_LEN)
        );
    }

    #[test]
    fn tool_output_verifies_under_the_kernel_prehashed_strict_path() {
        // The differential proof (#467): what sphragis signs, the kernel
        // accepts — same Ed25519ph + SHA-512 + verify_prehashed_strict the
        // kernel's secure_boot uses.
        let payload: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
        let seed = [11u8; 32];
        let image = sign_image(&payload, &seed);

        let key = ed25519_dalek::VerifyingKey::from_bytes(
            &SigningKey::from_bytes(&seed).verifying_key().to_bytes(),
        )
        .unwrap_or_else(|_| unreachable!("valid key"));
        let (payload_region, sig_region) = image.split_at(image.len() - SIG_LEN);
        let mut prehash = sha2::Sha512::new();
        prehash.update(payload_region);
        let sig = ed25519_dalek::Signature::from_bytes(sig_region.try_into().unwrap_or(&[0u8; 64]));
        assert!(
            key.verify_prehashed_strict(prehash, None, &sig).is_ok(),
            "the kernel's verification path must accept the tool's output"
        );
    }

    #[test]
    fn parse_seed_accepts_and_rejects() {
        let good = "00".repeat(32);
        assert_eq!(parse_seed(&good), Some([0u8; 32]));
        assert_eq!(parse_seed("abcd"), None);
        assert_eq!(parse_seed(&"zz".repeat(32)), None);
    }
}
