//! AES-256-XTS block encryption and decryption (sector-level, like dm-crypt).

use aes::{Aes256, cipher::KeyInit};
use snafu::Snafu;
use xts_mode::Xts128;

// WHY an assertion rather than a comment (#835/#836): an AES round-key
// schedule is reversible to the key that produced it, and `aes/zeroize` is
// what supplies the `Drop` that scrubs it. A build without that feature
// compiles everything here unchanged and silently leaves the schedule
// resident, so nothing but a type-level demand would notice the regression.
// This one fails the build instead.
const _: fn() = || {
    const fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    assert_zeroize_on_drop::<Aes256>();
};

/// Block size in bytes  -  matches the OS page size and dm-crypt sector size.
pub(crate) const BLOCK_SIZE: usize = 4096;

/// XTS key length: two AES-256 keys (32 bytes each = 64 bytes total).
const XTS_KEY_LEN: usize = 64;

/// Length of each AES-256 sub-key within the XTS key.
const KEY_HALF_LEN: usize = XTS_KEY_LEN / 2;

/// Errors FROM block cipher operations.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub(crate) enum Error {
    /// The provided key is not `XTS_KEY_LEN` (64) bytes.
    #[snafu(display("invalid XTS key length: expected {XTS_KEY_LEN} bytes, got {actual}"))]
    InvalidKeyLength {
        /// Actual key length provided.
        actual: usize,
        /// Source location.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// The plaintext or ciphertext buffer is not exactly `BLOCK_SIZE` (4096) bytes.
    #[snafu(display("invalid block size: expected {BLOCK_SIZE} bytes, got {actual}"))]
    InvalidBlockSize {
        /// Actual buffer size provided.
        actual: usize,
        /// Source location.
        #[snafu(implicit)]
        location: snafu::Location,
    },
}

/// Convenience alias.
pub(crate) type Result<T> = std::result::Result<T, Error>;

/// Encrypt `plaintext` in-place INTO `ciphertext` using AES-256-XTS.
///
/// `block_number` is used as the XTS tweak (sector index), matching dm-crypt behaviour.
/// Both `plaintext` and `ciphertext` must be exactly [`BLOCK_SIZE`] bytes.
///
/// # Errors
///
/// Returns [`Error::InvalidKeyLength`] if `key` is not 64 bytes.
/// Returns [`Error::InvalidBlockSize`] if either buffer is not 4096 bytes.
pub(crate) fn encrypt_block(
    key: &[u8; XTS_KEY_LEN],
    block_number: u64,
    plaintext: &[u8],
    ciphertext: &mut [u8],
) -> Result<()> {
    if plaintext.len() != BLOCK_SIZE {
        return Err(InvalidBlockSizeSnafu {
            actual: plaintext.len(),
        }
        .build());
    }
    if ciphertext.len() != BLOCK_SIZE {
        return Err(InvalidBlockSizeSnafu {
            actual: ciphertext.len(),
        }
        .build());
    }

    ciphertext.copy_from_slice(plaintext);
    make_xts(key)?.encrypt_sector(ciphertext, block_number_to_tweak(block_number).into());
    Ok(())
}

/// Decrypt `ciphertext` in-place INTO `plaintext` using AES-256-XTS.
///
/// `block_number` must match the value used during encryption.
/// Both `ciphertext` and `plaintext` must be exactly [`BLOCK_SIZE`] bytes.
///
/// # Errors
///
/// Returns [`Error::InvalidKeyLength`] if `key` is not 64 bytes.
/// Returns [`Error::InvalidBlockSize`] if either buffer is not 4096 bytes.
///
/// # Note
///
/// XTS provides confidentiality only, not authentication. A mismatched
/// `block_number` does not produce an error — it silently yields incorrect
/// plaintext. Callers needing integrity must authenticate at a higher layer.
pub(crate) fn decrypt_block(
    key: &[u8; XTS_KEY_LEN],
    block_number: u64,
    ciphertext: &[u8],
    plaintext: &mut [u8],
) -> Result<()> {
    if ciphertext.len() != BLOCK_SIZE {
        return Err(InvalidBlockSizeSnafu {
            actual: ciphertext.len(),
        }
        .build());
    }
    if plaintext.len() != BLOCK_SIZE {
        return Err(InvalidBlockSizeSnafu {
            actual: plaintext.len(),
        }
        .build());
    }

    plaintext.copy_from_slice(ciphertext);
    make_xts(key)?.decrypt_sector(plaintext, block_number_to_tweak(block_number).into());
    Ok(())
}

/// Encode `block_number` as a 16-byte little-endian XTS tweak (sector index).
///
/// XTS places the sector index in a 128-bit little-endian integer. The upper 8
/// bytes are always zero for 64-bit block numbers.
fn block_number_to_tweak(block_number: u64) -> [u8; 16] {
    let mut tweak = [0u8; 16];
    let le_bytes = block_number.to_le_bytes();
    // Copy 8 bytes INTO the low half; upper 8 bytes remain zero.
    tweak[..8].copy_from_slice(&le_bytes);
    tweak
}

/// Build an `Xts128<Aes256>` cipher FROM a 64-byte XTS key.
fn make_xts(key: &[u8; XTS_KEY_LEN]) -> Result<Xts128<Aes256>> {
    let (k1, k2) = key.split_at(KEY_HALF_LEN);

    // split_at(32) on a [u8; 64] always produces two 32-byte slices, so
    // new_from_slice cannot fail here. The map_err is for completeness.
    let c1 = Aes256::new_from_slice(k1)
        .map_err(|_| InvalidKeyLengthSnafu { actual: k1.len() }.build())?;
    let c2 = Aes256::new_from_slice(k2)
        .map_err(|_| InvalidKeyLengthSnafu { actual: k2.len() }.build())?;

    Ok(Xts128::new(c1, c2))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_xts_key() -> [u8; XTS_KEY_LEN] {
        let mut key = [0u8; XTS_KEY_LEN];
        for (i, b) in key.iter_mut().enumerate() {
            *b = u8::try_from(i % 256).unwrap_or(0);
        }
        key
    }

    fn sample_plaintext() -> [u8; BLOCK_SIZE] {
        let mut buf = [0u8; BLOCK_SIZE];
        for (i, b) in buf.iter_mut().enumerate() {
            *b = u8::try_from(i % 256).unwrap_or(0);
        }
        buf
    }

    #[test]
    fn encrypt_decrypt_round_trip() -> super::Result<()> {
        let key = sample_xts_key();
        let plaintext = sample_plaintext();
        let mut ciphertext = [0u8; BLOCK_SIZE];
        let mut recovered = [0u8; BLOCK_SIZE];

        encrypt_block(&key, 0, &plaintext, &mut ciphertext)?;
        decrypt_block(&key, 0, &ciphertext, &mut recovered)?;

        assert_eq!(
            plaintext, recovered,
            "decrypted block must match the original plaintext"
        );
        Ok(())
    }

    #[test]
    fn different_block_numbers_produce_different_ciphertext() -> super::Result<()> {
        let key = sample_xts_key();
        let plaintext = sample_plaintext();
        let mut ct0 = [0u8; BLOCK_SIZE];
        let mut ct1 = [0u8; BLOCK_SIZE];

        encrypt_block(&key, 0, &plaintext, &mut ct0)?;
        encrypt_block(&key, 1, &plaintext, &mut ct1)?;

        assert_ne!(
            ct0, ct1,
            "XTS tweak must produce distinct ciphertext for different block numbers"
        );
        Ok(())
    }

    #[test]
    fn ciphertext_differs_from_plaintext() -> super::Result<()> {
        let key = sample_xts_key();
        let plaintext = [0x42u8; BLOCK_SIZE];
        let mut ciphertext = [0u8; BLOCK_SIZE];

        encrypt_block(&key, 42, &plaintext, &mut ciphertext)?;

        assert_ne!(
            plaintext, ciphertext,
            "encrypted block must differ FROM the plaintext"
        );
        Ok(())
    }

    #[test]
    fn decrypt_with_wrong_block_number_does_not_error() -> super::Result<()> {
        let key = sample_xts_key();
        let plaintext = sample_plaintext();
        let mut ciphertext = [0u8; BLOCK_SIZE];
        let mut recovered = [0u8; BLOCK_SIZE];

        encrypt_block(&key, 5, &plaintext, &mut ciphertext)?;
        // WHY: XTS provides no authentication — decrypting with the wrong
        // tweak succeeds and silently yields incorrect plaintext, it does
        // not surface as an Err.
        decrypt_block(&key, 6, &ciphertext, &mut recovered)?;

        assert_ne!(
            plaintext, recovered,
            "decrypting with the wrong block_number must not recover the original plaintext"
        );
        Ok(())
    }
}
