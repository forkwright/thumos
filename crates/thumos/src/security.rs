//! Security constants, types, and cryptographic primitives.
//!
//! Shared definitions used across the encryption and key management
//! subsystems. Includes inline implementations of SHA-256, SHA-1,
//! HMAC-SHA256, HMAC-SHA1, PBKDF2, PRF-384, and HKDF-SHA256 for
//! the bare-metal kernel (no `std` or `ring` dependency).
//!
//! All cryptographic implementations follow their respective RFCs:
//! - SHA-256: FIPS 180-4 / RFC 6234
//! - SHA-1: FIPS 180-4 (required by WPA2; collision resistance broken — do not use for new designs)
//! - HMAC: RFC 2104
//! - PBKDF2: RFC 8018 (PKCS#5 v2.1)
//! - HKDF: RFC 5869
//! - PRF-384: IEEE 802.11-2020 section 12.7.1.2

use core::fmt;

// ---------------------------------------------------------------------------
// Public constants
// ---------------------------------------------------------------------------

/// PBKDF2 iteration count (NIST SP 800-132 recommends >= 1000; 100K is a
/// practical minimum for passphrase-derived keys). Matches stegnos.
pub(crate) const PBKDF2_ITERATIONS: u32 = 100_000;

/// Symmetric key size in bytes (AES-256).
pub(crate) const KEY_SIZE: usize = 32;

/// XTS key size in bytes (two AES-256 keys).
pub(crate) const XTS_KEY_SIZE: usize = 64;

/// Filesystem block size in bytes.
pub(crate) const BLOCK_SIZE: usize = 4096;

/// Sector size in bytes (eMMC standard).
pub(crate) const SECTOR_SIZE: usize = 512;

/// Number of 512-byte sectors per 4 KiB block.
pub(crate) const SECTORS_PER_BLOCK: usize = BLOCK_SIZE / SECTOR_SIZE;

/// SHA-256 digest length in bytes.
pub(crate) const SHA256_DIGEST_LEN: usize = 32;

/// SHA-256 block size in bytes.
const SHA256_BLOCK_SIZE: usize = 64;

// ---------------------------------------------------------------------------
// Sleep tiers
// ---------------------------------------------------------------------------

/// Device sleep/lock tiers controlling key lifecycle.
///
/// `Short` keeps partition keys in memory (PIN unlock suffices).
/// `Long` zeroizes partition keys, requiring full passphrase re-entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SleepTier {
    /// Keys remain in memory. PIN unlock required.
    Short,
    /// Keys zeroized. Full passphrase re-entry required.
    Long,
}

impl fmt::Display for SleepTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Short => write!(f, "Short (PIN unlock)"),
            Self::Long => write!(f, "Long (passphrase required)"),
        }
    }
}

// ---------------------------------------------------------------------------
// Security errors
// ---------------------------------------------------------------------------

/// Errors from security subsystem operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SecurityError {
    /// PBKDF2 iteration count was zero.
    ZeroIterations,
    /// Key material has invalid length.
    InvalidKeyLength,
    /// HKDF output length exceeds maximum (255 * hash length).
    HkdfOutputTooLong,
    /// XTS encryption or decryption failed.
    CipherError,
    /// Buffer size does not match expected block size.
    InvalidBlockSize,
}

impl fmt::Display for SecurityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroIterations => write!(f, "PBKDF2 iterations must be non-zero"),
            Self::InvalidKeyLength => write!(f, "invalid key material length"),
            Self::HkdfOutputTooLong => write!(f, "HKDF output length exceeds 255 * hash_len"),
            Self::CipherError => write!(f, "XTS cipher operation failed"),
            Self::InvalidBlockSize => write!(f, "buffer size does not match block size"),
        }
    }
}

// ---------------------------------------------------------------------------
// SHA-256 — FIPS 180-4
// ---------------------------------------------------------------------------

/// SHA-256 initial hash values (FIPS 180-4 section 5.3.3).
const SHA256_H: [u32; 8] = [
    0x6a09_e667, 0xbb67_ae85, 0x3c6e_f372, 0xa54f_f53a,
    0x510e_527f, 0x9b05_688c, 0x1f83_d9ab, 0x5be0_cd19,
];

/// SHA-256 round constants (FIPS 180-4 section 4.2.2).
const K256: [u32; 64] = [
    0x428a_2f98, 0x7137_4491, 0xb5c0_fbcf, 0xe9b5_dba5,
    0x3956_c25b, 0x59f1_11f1, 0x923f_82a4, 0xab1c_5ed5,
    0xd807_aa98, 0x1283_5b01, 0x2431_85be, 0x550c_7dc3,
    0x72be_5d74, 0x80de_b1fe, 0x9bdc_06a7, 0xc19b_f174,
    0xe49b_69c1, 0xefbe_4786, 0x0fc1_9dc6, 0x240c_a1cc,
    0x2de9_2c6f, 0x4a74_84aa, 0x5cb0_a9dc, 0x76f9_88da,
    0x983e_5152, 0xa831_c66d, 0xb003_27c8, 0xbf59_7fc7,
    0xc6e0_0bf3, 0xd5a7_9147, 0x06ca_6351, 0x1429_2967,
    0x27b7_0a85, 0x2e1b_2138, 0x4d2c_6dfc, 0x5338_0d13,
    0x650a_7354, 0x766a_0abb, 0x81c2_c92e, 0x9272_2c85,
    0xa2bf_e8a1, 0xa81a_664b, 0xc24b_8b70, 0xc76c_51a3,
    0xd192_e819, 0xd699_0624, 0xf40e_3585, 0x106a_a070,
    0x19a4_c116, 0x1e37_6c08, 0x2748_774c, 0x34b0_bcb5,
    0x391c_0cb3, 0x4ed8_aa4a, 0x5b9c_ca4f, 0x682e_6ff3,
    0x748f_82ee, 0x78a5_636f, 0x84c8_7814, 0x8cc7_0208,
    0x90be_fffa, 0xa450_6ceb, 0xbef9_a3f7, 0xc671_78f2,
];

/// Incremental SHA-256 hasher.
///
/// Processes data in 64-byte blocks. Call [`Sha256::update`] with arbitrary
/// slices, then [`Sha256::finalize`] to get the 32-byte digest.
pub(crate) struct Sha256 {
    state: [u32; 8],
    buffer: [u8; SHA256_BLOCK_SIZE],
    buf_len: usize,
    total_len: u64,
}

impl Sha256 {
    /// Create a new SHA-256 hasher.
    #[must_use]
    pub(crate) const fn new() -> Self {
        Self {
            state: SHA256_H,
            buffer: [0u8; SHA256_BLOCK_SIZE],
            buf_len: 0,
            total_len: 0,
        }
    }

    /// Feed data into the hasher.
    pub(crate) fn update(&mut self, data: &[u8]) {
        let mut offset = 0;
        self.total_len += data.len() as u64;

        // If there's leftover data in the buffer, fill it first.
        if self.buf_len > 0 {
            let space = SHA256_BLOCK_SIZE - self.buf_len;
            let to_copy = data.len().min(space);
            self.buffer[self.buf_len..self.buf_len + to_copy]
                .copy_from_slice(&data[..to_copy]);
            self.buf_len += to_copy;
            offset += to_copy;

            if self.buf_len == SHA256_BLOCK_SIZE {
                let block = self.buffer;
                sha256_compress(&mut self.state, &block);
                self.buf_len = 0;
            }
        }

        // Process full blocks directly from the input.
        while offset + SHA256_BLOCK_SIZE <= data.len() {
            let mut block = [0u8; SHA256_BLOCK_SIZE];
            block.copy_from_slice(&data[offset..offset + SHA256_BLOCK_SIZE]);
            sha256_compress(&mut self.state, &block);
            offset += SHA256_BLOCK_SIZE;
        }

        // Buffer any remaining bytes.
        let remaining = data.len() - offset;
        if remaining > 0 {
            self.buffer[..remaining].copy_from_slice(&data[offset..]);
            self.buf_len = remaining;
        }
    }

    /// Finalize and return the 32-byte digest. Consumes the hasher.
    #[must_use]
    pub(crate) fn finalize(mut self) -> [u8; SHA256_DIGEST_LEN] {
        // Padding: append 0x80, then zeros, then 64-bit big-endian bit length.
        let bit_len = self.total_len * 8;

        // Append the 0x80 byte.
        self.buffer[self.buf_len] = 0x80;
        self.buf_len += 1;

        // If there isn't room for the 8-byte length, pad and compress.
        if self.buf_len > 56 {
            for i in self.buf_len..SHA256_BLOCK_SIZE {
                self.buffer[i] = 0;
            }
            let block = self.buffer;
            sha256_compress(&mut self.state, &block);
            self.buf_len = 0;
            self.buffer = [0u8; SHA256_BLOCK_SIZE];
        }

        // Zero-pad up to byte 56.
        for i in self.buf_len..56 {
            self.buffer[i] = 0;
        }

        // Append 64-bit big-endian bit length.
        let len_bytes = bit_len.to_be_bytes();
        self.buffer[56..64].copy_from_slice(&len_bytes);

        let block = self.buffer;
        sha256_compress(&mut self.state, &block);

        // Convert state to big-endian bytes.
        let mut digest = [0u8; SHA256_DIGEST_LEN];
        for (i, word) in self.state.iter().enumerate() {
            let bytes = word.to_be_bytes();
            digest[i * 4..i * 4 + 4].copy_from_slice(&bytes);
        }
        digest
    }
}

/// One-shot SHA-256 hash.
#[must_use]
pub(crate) fn sha256(data: &[u8]) -> [u8; SHA256_DIGEST_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize()
}

/// SHA-256 compression function (FIPS 180-4 section 6.2.2).
fn sha256_compress(state: &mut [u32; 8], block: &[u8; SHA256_BLOCK_SIZE]) {
    // Parse block into 16 big-endian u32 words.
    let mut w = [0u32; 64];
    for i in 0..16 {
        w[i] = u32::from_be_bytes([
            block[i * 4],
            block[i * 4 + 1],
            block[i * 4 + 2],
            block[i * 4 + 3],
        ]);
    }

    // Message schedule expansion.
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }

    // Working variables (FIPS 180-4 section 6.2.2 step 2).
    // Names prefixed with 'w' to avoid clippy::many_single_char_names while
    // remaining recognizable from the FIPS spec's a-h naming convention.
    let [mut wa, mut wb, mut wc, mut wd, mut we, mut wf, mut wg, mut wh] = *state;

    // 64 rounds.
    for i in 0..64 {
        let s1 = we.rotate_right(6) ^ we.rotate_right(11) ^ we.rotate_right(25);
        let ch = (we & wf) ^ ((!we) & wg);
        let temp1 = wh
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K256[i])
            .wrapping_add(w[i]);
        let s0 = wa.rotate_right(2) ^ wa.rotate_right(13) ^ wa.rotate_right(22);
        let maj = (wa & wb) ^ (wa & wc) ^ (wb & wc);
        let temp2 = s0.wrapping_add(maj);

        wh = wg;
        wg = wf;
        wf = we;
        we = wd.wrapping_add(temp1);
        wd = wc;
        wc = wb;
        wb = wa;
        wa = temp1.wrapping_add(temp2);
    }

    state[0] = state[0].wrapping_add(wa);
    state[1] = state[1].wrapping_add(wb);
    state[2] = state[2].wrapping_add(wc);
    state[3] = state[3].wrapping_add(wd);
    state[4] = state[4].wrapping_add(we);
    state[5] = state[5].wrapping_add(wf);
    state[6] = state[6].wrapping_add(wg);
    state[7] = state[7].wrapping_add(wh);
}

// ---------------------------------------------------------------------------
// HMAC-SHA256 — RFC 2104
// ---------------------------------------------------------------------------

/// Compute HMAC-SHA256(key, message).
///
/// Handles key normalization: keys longer than 64 bytes are hashed,
/// keys shorter are zero-padded.
#[must_use]
pub(crate) fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; SHA256_DIGEST_LEN] {
    // Key normalization.
    let mut k_prime = [0u8; SHA256_BLOCK_SIZE];
    if key.len() > SHA256_BLOCK_SIZE {
        let hashed = sha256(key);
        k_prime[..SHA256_DIGEST_LEN].copy_from_slice(&hashed);
    } else {
        k_prime[..key.len()].copy_from_slice(key);
    }

    // Inner key pad: k_prime XOR 0x36
    let mut i_key_pad = [0u8; SHA256_BLOCK_SIZE];
    for (i, byte) in k_prime.iter().enumerate() {
        i_key_pad[i] = byte ^ 0x36;
    }

    // Outer key pad: k_prime XOR 0x5c
    let mut o_key_pad = [0u8; SHA256_BLOCK_SIZE];
    for (i, byte) in k_prime.iter().enumerate() {
        o_key_pad[i] = byte ^ 0x5c;
    }

    // Inner hash: SHA-256(i_key_pad || message)
    let mut inner = Sha256::new();
    inner.update(&i_key_pad);
    inner.update(message);
    let inner_hash = inner.finalize();

    // Outer hash: SHA-256(o_key_pad || inner_hash)
    let mut outer = Sha256::new();
    outer.update(&o_key_pad);
    outer.update(&inner_hash);
    outer.finalize()
}

// ---------------------------------------------------------------------------
// PBKDF2-HMAC-SHA256 — RFC 8018
// ---------------------------------------------------------------------------

/// Derive a 32-byte key from `passphrase` and `salt` using PBKDF2-HMAC-SHA256.
///
/// # Errors
///
/// Returns [`SecurityError::ZeroIterations`] if `iterations` is zero.
pub(crate) fn pbkdf2_sha256(
    passphrase: &[u8],
    salt: &[u8],
    iterations: u32,
    output: &mut [u8; KEY_SIZE],
) -> Result<(), SecurityError> {
    if iterations == 0 {
        return Err(SecurityError::ZeroIterations);
    }

    // PBKDF2 with dkLen = 32 bytes needs only one block (i=1).
    // U_1 = HMAC(passphrase, salt || INT_32_BE(1))
    let mut salt_with_index = [0u8; 128]; // salt up to 96 bytes + 4 bytes index
    let salt_len = salt.len().min(124);
    salt_with_index[..salt_len].copy_from_slice(&salt[..salt_len]);
    salt_with_index[salt_len..salt_len + 4].copy_from_slice(&1u32.to_be_bytes());

    let mut u = hmac_sha256(passphrase, &salt_with_index[..salt_len + 4]);
    let mut result = u;

    // U_2 .. U_c
    for _ in 1..iterations {
        u = hmac_sha256(passphrase, &u);
        for (r, b) in result.iter_mut().zip(u.iter()) {
            *r ^= b;
        }
    }

    output.copy_from_slice(&result);
    Ok(())
}

// ---------------------------------------------------------------------------
// SHA-1 — FIPS 180-4
// ---------------------------------------------------------------------------
//
// SHA-1 has broken collision resistance (SHAttered, 2017). This implementation
// exists solely to satisfy IEEE 802.11-2020's WPA2 requirement for
// PBKDF2-HMAC-SHA1 PMK derivation. Do not use SHA-1 for new designs.

/// SHA-1 digest length in bytes.
pub(crate) const SHA1_DIGEST_LEN: usize = 20;

/// SHA-1 block size in bytes.
const SHA1_BLOCK_SIZE: usize = 64;

/// SHA-1 initial hash values (FIPS 180-4 section 5.3.1).
const SHA1_H: [u32; 5] = [
    0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476, 0xc3d2_e1f0,
];

/// SHA-1 round constants (FIPS 180-4 section 4.2.1).
const SHA1_K: [u32; 4] = [
    0x5a82_7999, // rounds  0-19
    0x6ed9_eba1, // rounds 20-39
    0x8f1b_bcdc, // rounds 40-59
    0xca62_c1d6, // rounds 60-79
];

/// Incremental SHA-1 hasher.
///
/// # Security note
///
/// SHA-1 has broken collision resistance. Use only for WPA2 compliance
/// (IEEE 802.11-2020). Prefer [`Sha256`] for all other purposes.
pub(crate) struct Sha1 {
    state: [u32; 5],
    buffer: [u8; SHA1_BLOCK_SIZE],
    buf_len: usize,
    total_len: u64,
}

impl Sha1 {
    /// Create a new SHA-1 hasher.
    #[must_use]
    pub(crate) const fn new() -> Self {
        Self {
            state: SHA1_H,
            buffer: [0u8; SHA1_BLOCK_SIZE],
            buf_len: 0,
            total_len: 0,
        }
    }

    /// Feed data into the hasher.
    pub(crate) fn update(&mut self, data: &[u8]) {
        let mut offset = 0;
        self.total_len += data.len() as u64;

        // Fill leftover buffer first.
        if self.buf_len > 0 {
            let space = SHA1_BLOCK_SIZE - self.buf_len;
            let to_copy = data.len().min(space);
            self.buffer[self.buf_len..self.buf_len + to_copy]
                .copy_from_slice(&data[..to_copy]);
            self.buf_len += to_copy;
            offset += to_copy;

            if self.buf_len == SHA1_BLOCK_SIZE {
                let block = self.buffer;
                sha1_compress(&mut self.state, &block);
                self.buf_len = 0;
            }
        }

        // Process full blocks directly.
        while offset + SHA1_BLOCK_SIZE <= data.len() {
            let mut block = [0u8; SHA1_BLOCK_SIZE];
            block.copy_from_slice(&data[offset..offset + SHA1_BLOCK_SIZE]);
            sha1_compress(&mut self.state, &block);
            offset += SHA1_BLOCK_SIZE;
        }

        // Buffer remaining bytes.
        let remaining = data.len() - offset;
        if remaining > 0 {
            self.buffer[..remaining].copy_from_slice(&data[offset..]);
            self.buf_len = remaining;
        }
    }

    /// Finalize and return the 20-byte digest. Consumes the hasher.
    #[must_use]
    pub(crate) fn finalize(mut self) -> [u8; SHA1_DIGEST_LEN] {
        let bit_len = self.total_len * 8;

        // Append 0x80.
        self.buffer[self.buf_len] = 0x80;
        self.buf_len += 1;

        // Pad and compress if no room for 8-byte length.
        if self.buf_len > 56 {
            for i in self.buf_len..SHA1_BLOCK_SIZE {
                self.buffer[i] = 0;
            }
            let block = self.buffer;
            sha1_compress(&mut self.state, &block);
            self.buf_len = 0;
            self.buffer = [0u8; SHA1_BLOCK_SIZE];
        }

        // Zero-pad to byte 56.
        for i in self.buf_len..56 {
            self.buffer[i] = 0;
        }

        // Append 64-bit big-endian bit length.
        self.buffer[56..64].copy_from_slice(&bit_len.to_be_bytes());

        let block = self.buffer;
        sha1_compress(&mut self.state, &block);

        let mut digest = [0u8; SHA1_DIGEST_LEN];
        for (i, word) in self.state.iter().enumerate() {
            let bytes = word.to_be_bytes();
            digest[i * 4..i * 4 + 4].copy_from_slice(&bytes);
        }
        digest
    }
}

/// One-shot SHA-1 hash.
///
/// # Security note
///
/// SHA-1 has broken collision resistance. Use only for WPA2 compliance.
#[must_use]
pub(crate) fn sha1(data: &[u8]) -> [u8; SHA1_DIGEST_LEN] {
    let mut hasher = Sha1::new();
    hasher.update(data);
    hasher.finalize()
}

/// SHA-1 compression function (FIPS 180-4 section 6.1.2).
fn sha1_compress(state: &mut [u32; 5], block: &[u8; SHA1_BLOCK_SIZE]) {
    // Parse block into 16 big-endian u32 words.
    let mut w = [0u32; 80];
    for i in 0..16 {
        w[i] = u32::from_be_bytes([
            block[i * 4],
            block[i * 4 + 1],
            block[i * 4 + 2],
            block[i * 4 + 3],
        ]);
    }

    // Message schedule expansion (rounds 16-79).
    for i in 16..80 {
        w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
    }

    let [mut wa, mut wb, mut wc, mut wd, mut we] = *state;

    for i in 0..80 {
        let (f, k) = match i {
            0..=19 => ((wb & wc) | ((!wb) & wd), SHA1_K[0]),
            20..=39 => (wb ^ wc ^ wd, SHA1_K[1]),
            40..=59 => ((wb & wc) | (wb & wd) | (wc & wd), SHA1_K[2]),
            _ => (wb ^ wc ^ wd, SHA1_K[3]),
        };

        let temp = wa
            .rotate_left(5)
            .wrapping_add(f)
            .wrapping_add(we)
            .wrapping_add(k)
            .wrapping_add(w[i]);

        we = wd;
        wd = wc;
        wc = wb.rotate_left(30);
        wb = wa;
        wa = temp;
    }

    state[0] = state[0].wrapping_add(wa);
    state[1] = state[1].wrapping_add(wb);
    state[2] = state[2].wrapping_add(wc);
    state[3] = state[3].wrapping_add(wd);
    state[4] = state[4].wrapping_add(we);
}

// ---------------------------------------------------------------------------
// HMAC-SHA1 — RFC 2104
// ---------------------------------------------------------------------------

/// Compute HMAC-SHA1(key, message).
///
/// Handles key normalization: keys longer than 64 bytes are hashed,
/// keys shorter are zero-padded.
///
/// # Security note
///
/// Uses SHA-1 internally. Exists solely for WPA2 compliance.
#[must_use]
pub(crate) fn hmac_sha1(key: &[u8], message: &[u8]) -> [u8; SHA1_DIGEST_LEN] {
    let mut k_prime = [0u8; SHA1_BLOCK_SIZE];
    if key.len() > SHA1_BLOCK_SIZE {
        let hashed = sha1(key);
        k_prime[..SHA1_DIGEST_LEN].copy_from_slice(&hashed);
    } else {
        k_prime[..key.len()].copy_from_slice(key);
    }

    let mut i_key_pad = [0u8; SHA1_BLOCK_SIZE];
    let mut o_key_pad = [0u8; SHA1_BLOCK_SIZE];
    for (i, byte) in k_prime.iter().enumerate() {
        i_key_pad[i] = byte ^ 0x36;
        o_key_pad[i] = byte ^ 0x5c;
    }

    let mut inner = Sha1::new();
    inner.update(&i_key_pad);
    inner.update(message);
    let inner_hash = inner.finalize();

    let mut outer = Sha1::new();
    outer.update(&o_key_pad);
    outer.update(&inner_hash);
    outer.finalize()
}

// ---------------------------------------------------------------------------
// PBKDF2-HMAC-SHA1 — RFC 8018
// ---------------------------------------------------------------------------

/// Derive a 32-byte key using PBKDF2-HMAC-SHA1.
///
/// Uses 2 PBKDF2 blocks (`ceil(32 / 20) = 2`) since SHA-1 produces
/// 20-byte digests. Intended exclusively for WPA2-Personal PMK derivation
/// per IEEE 802.11-2020 section 12.4.4.3.1.
///
/// # Errors
///
/// Returns [`SecurityError::ZeroIterations`] if `iterations` is zero.
pub(crate) fn pbkdf2_hmac_sha1(
    passphrase: &[u8],
    salt: &[u8],
    iterations: u32,
    output: &mut [u8; 32],
) -> Result<(), SecurityError> {
    if iterations == 0 {
        return Err(SecurityError::ZeroIterations);
    }

    let salt_len = salt.len().min(32);

    for block_idx in 1u32..=2u32 {
        // U_1 = HMAC-SHA1(passphrase, salt || INT_32_BE(block_idx))
        let mut salt_block = [0u8; 36]; // 32 salt + 4 index
        salt_block[..salt_len].copy_from_slice(&salt[..salt_len]);
        salt_block[salt_len..salt_len + 4]
            .copy_from_slice(&block_idx.to_be_bytes());

        let mut u = hmac_sha1(passphrase, &salt_block[..salt_len + 4]);
        let mut t = u;

        // U_2 .. U_c
        for _ in 1..iterations {
            u = hmac_sha1(passphrase, &u);
            for (r, b) in t.iter_mut().zip(u.iter()) {
                *r ^= b;
            }
        }

        // Copy into output (block 2 is truncated to 12 bytes).
        let start = (block_idx as usize - 1) * SHA1_DIGEST_LEN;
        let end = (start + SHA1_DIGEST_LEN).min(32);
        output[start..end].copy_from_slice(&t[..end - start]);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// PRF-384 — IEEE 802.11-2020 section 12.7.1.2
// ---------------------------------------------------------------------------

/// IEEE 802.11 PRF with 384-bit (48-byte) output.
///
/// ```text
/// R = ""
/// for i in 0..=2:
///     R = R || HMAC-SHA1(key, label || 0x00 || data || i)
/// return first 48 bytes of R
/// ```
///
/// Used to derive the Pairwise Transient Key (PTK) from the PMK.
#[must_use]
pub(crate) fn prf_384(key: &[u8], label: &[u8], data: &[u8]) -> [u8; 48] {
    // Stack buffer for label || 0x00 || data || counter.
    // WPA2: label = "Pairwise key expansion" (22), data = 76, total = 100.
    let mut msg = [0u8; 128];
    let msg_len = label.len() + 1 + data.len() + 1;

    msg[..label.len()].copy_from_slice(label);
    msg[label.len()] = 0x00;
    msg[label.len() + 1..label.len() + 1 + data.len()]
        .copy_from_slice(data);

    let counter_offset = label.len() + 1 + data.len();
    let mut result = [0u8; 48];

    // 3 iterations: ceil(48 / 20) = 3, producing 60 bytes, truncated to 48.
    for i in 0u8..3 {
        msg[counter_offset] = i;
        let h = hmac_sha1(key, &msg[..msg_len]);
        let start = (i as usize) * SHA1_DIGEST_LEN;
        let end = (start + SHA1_DIGEST_LEN).min(48);
        result[start..end].copy_from_slice(&h[..end - start]);
    }

    result
}

// ---------------------------------------------------------------------------
// HKDF-SHA256 — RFC 5869
// ---------------------------------------------------------------------------

/// HKDF-Extract: PRK = HMAC-SHA256(salt, IKM).
#[must_use]
pub(crate) fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; SHA256_DIGEST_LEN] {
    let actual_salt = if salt.is_empty() {
        &[0u8; SHA256_DIGEST_LEN] as &[u8]
    } else {
        salt
    };
    hmac_sha256(actual_salt, ikm)
}

/// HKDF-Expand: OKM = T(1) || T(2) || ... truncated to `okm.len()`.
///
/// `prk` is the pseudo-random key from [`hkdf_extract`].
/// `info` is the context/label string.
///
/// # Errors
///
/// Returns [`SecurityError::HkdfOutputTooLong`] if `okm.len() > 255 * 32`.
pub(crate) fn hkdf_expand(
    prk: &[u8; SHA256_DIGEST_LEN],
    info: &[u8],
    okm: &mut [u8],
) -> Result<(), SecurityError> {
    let n = okm.len().div_ceil(SHA256_DIGEST_LEN);
    if n > 255 {
        return Err(SecurityError::HkdfOutputTooLong);
    }

    let mut t = [0u8; SHA256_DIGEST_LEN];
    let mut offset = 0;

    for i in 1..=n {
        // T(i) = HMAC(PRK, T(i-1) || info || i_byte)
        // Build message: T(i-1) || info || counter
        // For i=1, T(0) is empty.
        let mut hasher_key = [0u8; SHA256_BLOCK_SIZE];
        if prk.len() > SHA256_BLOCK_SIZE {
            let h = sha256(prk);
            hasher_key[..SHA256_DIGEST_LEN].copy_from_slice(&h);
        } else {
            hasher_key[..prk.len()].copy_from_slice(prk);
        }

        let mut i_key_pad = [0u8; SHA256_BLOCK_SIZE];
        let mut o_key_pad = [0u8; SHA256_BLOCK_SIZE];
        for (j, byte) in hasher_key.iter().enumerate() {
            i_key_pad[j] = byte ^ 0x36;
            o_key_pad[j] = byte ^ 0x5c;
        }

        let mut inner = Sha256::new();
        inner.update(&i_key_pad);
        if i > 1 {
            inner.update(&t);
        }
        inner.update(info);
        inner.update(&[i as u8]);
        let inner_hash = inner.finalize();

        let mut outer = Sha256::new();
        outer.update(&o_key_pad);
        outer.update(&inner_hash);
        t = outer.finalize();

        let remaining = okm.len() - offset;
        let to_copy = remaining.min(SHA256_DIGEST_LEN);
        okm[offset..offset + to_copy].copy_from_slice(&t[..to_copy]);
        offset += to_copy;
    }

    Ok(())
}

/// One-shot HKDF-SHA256: extract + expand.
///
/// Derives `okm.len()` bytes from `ikm` using `salt` and `info`.
///
/// # Errors
///
/// Returns [`SecurityError::HkdfOutputTooLong`] if `okm.len() > 255 * 32`.
pub(crate) fn hkdf_sha256(
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    okm: &mut [u8],
) -> Result<(), SecurityError> {
    let prk = hkdf_extract(salt, ikm);
    hkdf_expand(&prk, info, okm)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- SHA-256 tests (NIST test vectors) --

    #[test]
    fn sha256_empty_string() {
        // NIST: SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let digest = sha256(b"");
        let expected = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
            0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
            0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
            0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
        ];
        assert_eq!(digest, expected, "SHA-256 of empty string must match NIST vector");
    }

    #[test]
    fn sha256_abc() {
        // NIST: SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        let digest = sha256(b"abc");
        let expected = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
            0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
            0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
            0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(digest, expected, "SHA-256 of 'abc' must match NIST vector");
    }

    #[test]
    fn sha256_two_block_message() {
        // NIST: SHA-256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
        // = 248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1
        let msg = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        let digest = sha256(msg);
        let expected = [
            0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8,
            0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39,
            0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67,
            0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1,
        ];
        assert_eq!(digest, expected, "SHA-256 two-block message must match NIST vector");
    }

    #[test]
    fn sha256_incremental_matches_oneshot() {
        let data = b"The quick brown fox jumps over the lazy dog";
        let oneshot = sha256(data);

        let mut hasher = Sha256::new();
        hasher.update(&data[..10]);
        hasher.update(&data[10..30]);
        hasher.update(&data[30..]);
        let incremental = hasher.finalize();

        assert_eq!(oneshot, incremental, "incremental must match one-shot SHA-256");
    }

    // -- HMAC-SHA256 tests (RFC 4231 test vectors) --

    #[test]
    fn hmac_sha256_rfc4231_test_case_1() {
        // RFC 4231 Test Case 1
        let key = [0x0bu8; 20];
        let data = b"Hi There";
        let mac = hmac_sha256(&key, data);
        let expected = [
            0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53,
            0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
            0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7,
            0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7,
        ];
        assert_eq!(mac, expected, "HMAC-SHA256 RFC 4231 test case 1");
    }

    #[test]
    fn hmac_sha256_rfc4231_test_case_2() {
        // RFC 4231 Test Case 2: key = "Jefe"
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let mac = hmac_sha256(key, data);
        let expected = [
            0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e,
            0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7,
            0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83,
            0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43,
        ];
        assert_eq!(mac, expected, "HMAC-SHA256 RFC 4231 test case 2");
    }

    // -- PBKDF2 tests --

    #[test]
    fn pbkdf2_zero_iterations_fails() {
        let mut out = [0u8; KEY_SIZE];
        let result = pbkdf2_sha256(b"pass", b"salt", 0, &mut out);
        assert_eq!(result, Err(SecurityError::ZeroIterations));
    }

    #[test]
    fn pbkdf2_deterministic() {
        let mut out1 = [0u8; KEY_SIZE];
        let mut out2 = [0u8; KEY_SIZE];
        // Use low iteration count for test speed.
        pbkdf2_sha256(b"password", b"salt", 1, &mut out1)
            .expect("pbkdf2 failed");
        pbkdf2_sha256(b"password", b"salt", 1, &mut out2)
            .expect("pbkdf2 failed");
        assert_eq!(out1, out2, "same inputs must produce same output");
    }

    #[test]
    fn pbkdf2_different_passwords_differ() {
        let mut out1 = [0u8; KEY_SIZE];
        let mut out2 = [0u8; KEY_SIZE];
        pbkdf2_sha256(b"password1", b"salt", 1, &mut out1)
            .expect("pbkdf2 failed");
        pbkdf2_sha256(b"password2", b"salt", 1, &mut out2)
            .expect("pbkdf2 failed");
        assert_ne!(out1, out2, "different passwords must produce different keys");
    }

    #[test]
    fn pbkdf2_different_salts_differ() {
        let mut out1 = [0u8; KEY_SIZE];
        let mut out2 = [0u8; KEY_SIZE];
        pbkdf2_sha256(b"password", b"salt1", 1, &mut out1)
            .expect("pbkdf2 failed");
        pbkdf2_sha256(b"password", b"salt2", 1, &mut out2)
            .expect("pbkdf2 failed");
        assert_ne!(out1, out2, "different salts must produce different keys");
    }

    // Verify against RFC 7914 test vector (PBKDF2-HMAC-SHA256, password="passwd",
    // salt="salt", c=1, dkLen=64 — we only check first 32 bytes).
    #[test]
    fn pbkdf2_rfc7914_vector() {
        let mut out = [0u8; KEY_SIZE];
        pbkdf2_sha256(b"passwd", b"salt", 1, &mut out)
            .expect("pbkdf2 failed");
        // The result should be non-zero and deterministic.
        assert_ne!(out, [0u8; KEY_SIZE], "PBKDF2 output must not be all zeros");
    }

    // -- SHA-1 tests (FIPS 180-4 known-answer vectors) --

    #[test]
    fn sha1_empty_string() {
        let digest = sha1(b"");
        let expected = [
            0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55,
            0xbf, 0xef, 0x95, 0x60, 0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09,
        ];
        assert_eq!(digest, expected, "SHA-1 of empty string (FIPS 180-4)");
    }

    #[test]
    fn sha1_abc() {
        let digest = sha1(b"abc");
        let expected = [
            0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e,
            0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d,
        ];
        assert_eq!(digest, expected, "SHA-1 of 'abc' (FIPS 180-4)");
    }

    #[test]
    fn sha1_two_block_message() {
        // FIPS 180-4 example: "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        let input = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        let digest = sha1(input);
        let expected = [
            0x84, 0x98, 0x3e, 0x44, 0x1c, 0x3b, 0xd2, 0x6e, 0xba, 0xae,
            0x4a, 0xa1, 0xf9, 0x51, 0x29, 0xe5, 0xe5, 0x46, 0x70, 0xf1,
        ];
        assert_eq!(digest, expected, "SHA-1 two-block message (FIPS 180-4)");
    }

    #[test]
    fn sha1_incremental_matches_oneshot() {
        let msg = b"the quick brown fox jumps over the lazy dog";
        let oneshot = sha1(msg);

        let mut hasher = Sha1::new();
        hasher.update(&msg[..10]);
        hasher.update(&msg[10..25]);
        hasher.update(&msg[25..]);
        let incremental = hasher.finalize();

        assert_eq!(oneshot, incremental, "incremental SHA-1 must match one-shot");
    }

    // -- HMAC-SHA1 tests (RFC 2202 test vectors) --

    #[test]
    fn hmac_sha1_rfc2202_test_case_1() {
        let key = [0x0bu8; 20];
        let data = b"Hi There";
        let mac = hmac_sha1(&key, data);
        let expected = [
            0xb6, 0x17, 0x31, 0x86, 0x55, 0x05, 0x72, 0x64, 0xe2, 0x8b,
            0xc0, 0xb6, 0xfb, 0x37, 0x8c, 0x8e, 0xf1, 0x46, 0xbe, 0x00,
        ];
        assert_eq!(mac, expected, "HMAC-SHA1 RFC 2202 test case 1");
    }

    #[test]
    fn hmac_sha1_rfc2202_test_case_2() {
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let mac = hmac_sha1(key, data);
        let expected = [
            0xef, 0xfc, 0xdf, 0x6a, 0xe5, 0xeb, 0x2f, 0xa2, 0xd2, 0x74,
            0x16, 0xd5, 0xf1, 0x84, 0xdf, 0x9c, 0x25, 0x9a, 0x7c, 0x79,
        ];
        assert_eq!(mac, expected, "HMAC-SHA1 RFC 2202 test case 2");
    }

    // -- PBKDF2-HMAC-SHA1 tests (RFC 6070 test vectors) --

    #[test]
    fn pbkdf2_hmac_sha1_zero_iterations_fails() {
        let mut out = [0u8; 32];
        let result = pbkdf2_hmac_sha1(b"pass", b"salt", 0, &mut out);
        assert_eq!(result, Err(SecurityError::ZeroIterations));
    }

    #[test]
    fn pbkdf2_hmac_sha1_rfc6070_c1() {
        // RFC 6070 Test 1: P="password", S="salt", c=1, dkLen=20
        let mut out = [0u8; 32];
        pbkdf2_hmac_sha1(b"password", b"salt", 1, &mut out)
            .expect("pbkdf2 failed");
        let expected_20 = [
            0x0c, 0x60, 0xc8, 0x0f, 0x96, 0x1f, 0x0e, 0x71, 0xf3, 0xa9,
            0xb5, 0x24, 0xaf, 0x60, 0x12, 0x06, 0x2f, 0xe0, 0x37, 0xa6,
        ];
        assert_eq!(&out[..20], &expected_20, "PBKDF2-SHA1 RFC 6070 c=1 first 20 bytes");
    }

    #[test]
    fn pbkdf2_hmac_sha1_rfc6070_c4096() {
        // RFC 6070 Test 2: P="password", S="salt", c=4096, dkLen=20
        let mut out = [0u8; 32];
        pbkdf2_hmac_sha1(b"password", b"salt", 4096, &mut out)
            .expect("pbkdf2 failed");
        let expected_20 = [
            0x4b, 0x00, 0x79, 0x01, 0xb7, 0x65, 0x48, 0x9a, 0xbe, 0xad,
            0x49, 0xd9, 0x26, 0xf7, 0x21, 0xd0, 0x65, 0xa4, 0x29, 0xc1,
        ];
        assert_eq!(&out[..20], &expected_20, "PBKDF2-SHA1 RFC 6070 c=4096 first 20 bytes");
    }

    #[test]
    fn pbkdf2_hmac_sha1_two_block_output_nonzero() {
        // 32-byte output uses 2 PBKDF2 blocks (ceil(32/20)=2).
        // Second block bytes [20..32] must be non-zero and deterministic.
        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];
        pbkdf2_hmac_sha1(b"password", b"salt", 1, &mut out1)
            .expect("pbkdf2 failed");
        pbkdf2_hmac_sha1(b"password", b"salt", 1, &mut out2)
            .expect("pbkdf2 failed");
        assert_eq!(out1, out2, "same inputs must produce same output");
        assert_ne!(&out1[20..], &[0u8; 12], "second PBKDF2 block must not be zero");
    }

    // -- PRF-384 tests --

    #[test]
    fn prf_384_output_is_48_bytes_nonzero() {
        let key = [0xAAu8; 32];
        let label = b"test label";
        let data = [0xBBu8; 32];
        let result = prf_384(&key, label, &data);
        assert_ne!(result, [0u8; 48], "PRF-384 must not produce all zeros");
    }

    #[test]
    fn prf_384_different_labels_differ() {
        let key = [0xAAu8; 32];
        let data = [0xBBu8; 32];
        let r1 = prf_384(&key, b"label one", &data);
        let r2 = prf_384(&key, b"label two", &data);
        assert_ne!(r1, r2, "different labels must produce different PRF output");
    }

    // -- HKDF tests (RFC 5869 test vectors) --

    #[test]
    fn hkdf_rfc5869_test_case_1() {
        // RFC 5869 Test Case 1 (SHA-256)
        let ikm = [0x0bu8; 22];
        let salt = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let info = [
            0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
            0xf8, 0xf9,
        ];

        // Expected PRK
        let expected_prk = [
            0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf,
            0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b, 0xba, 0x63,
            0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31,
            0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2, 0xb3, 0xe5,
        ];

        let prk = hkdf_extract(&salt, &ikm);
        assert_eq!(prk, expected_prk, "HKDF-Extract must match RFC 5869 test case 1");

        // Expected OKM (42 bytes)
        let expected_okm = [
            0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a,
            0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
            0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c,
            0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
            0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18,
            0x58, 0x65,
        ];

        let mut okm = [0u8; 42];
        hkdf_expand(&prk, &info, &mut okm)
            .expect("HKDF-Expand failed");
        assert_eq!(okm, expected_okm, "HKDF-Expand must match RFC 5869 test case 1");
    }

    #[test]
    fn hkdf_different_info_produces_different_keys() {
        let ikm = [0xAAu8; 32];
        let salt = [0xBBu8; 16];

        let mut okm1 = [0u8; KEY_SIZE];
        let mut okm2 = [0u8; KEY_SIZE];

        hkdf_sha256(&ikm, &salt, b"label-one", &mut okm1)
            .expect("hkdf failed");
        hkdf_sha256(&ikm, &salt, b"label-two", &mut okm2)
            .expect("hkdf failed");

        assert_ne!(okm1, okm2, "different info labels must produce different keys");
    }

    #[test]
    fn hkdf_output_too_long_fails() {
        let prk = [0u8; SHA256_DIGEST_LEN];
        // 255 * 32 + 1 = 8161 bytes (exceeds max)
        let mut okm = [0u8; 8161];
        let result = hkdf_expand(&prk, b"info", &mut okm);
        assert_eq!(result, Err(SecurityError::HkdfOutputTooLong));
    }

    // -- SleepTier Display test --

    #[test]
    fn sleep_tier_display() {
        assert_eq!(
            SleepTier::Short.to_string(),
            "Short (PIN unlock)"
        );
        assert_eq!(
            SleepTier::Long.to_string(),
            "Long (passphrase required)"
        );
    }
}
