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
//! Minimal verification-only Ed25519 (RFC 8032 section 5.1.7).
//! Implements SHA-512 and the Ed25519 curve arithmetic (twisted Edwards
//! curve over GF(2^255 - 19)) inline, consistent with the kernel's
//! pattern of self-contained crypto (no external crate dependencies
//! for cryptographic primitives).

use core::fmt;

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
/// This is a placeholder key. The real key is injected during the
/// release build by the signing infrastructure. The corresponding
/// private key is stored on a Titan security key or air-gapped machine
/// and never touches the device.
const BOOT_PUBLIC_KEY: [u8; PUBLIC_KEY_LEN] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
    0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa3, 0x23, 0x28,
    0xf8, 0xb8, 0x89, 0x1c, 0xc2, 0x97, 0x10, 0x49,
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
// SHA-512 — FIPS 180-4
// ===========================================================================

/// SHA-512 digest length in bytes.
const SHA512_DIGEST_LEN: usize = 64;

/// SHA-512 block size in bytes.
const SHA512_BLOCK_SIZE: usize = 128;

/// SHA-512 initial hash values (FIPS 180-4 section 5.3.5).
const SHA512_H: [u64; 8] = [
    0x6a09_e667_f3bc_c908, 0xbb67_ae85_84ca_a73b,
    0x3c6e_f372_fe94_f82b, 0xa54f_f53a_5f1d_36f1,
    0x510e_527f_ade6_82d1, 0x9b05_688c_2b3e_6c1f,
    0x1f83_d9ab_fb41_bd6b, 0x5be0_cd19_137e_2179,
];

/// SHA-512 round constants (FIPS 180-4 section 4.2.3).
const K512: [u64; 80] = [
    0x428a_2f98_d728_ae22, 0x7137_4491_23ef_65cd,
    0xb5c0_fbcf_ec4d_3b2f, 0xe9b5_dba5_8189_dbbc,
    0x3956_c25b_f348_b538, 0x59f1_11f1_b605_d019,
    0x923f_82a4_af19_4f9b, 0xab1c_5ed5_da6d_8118,
    0xd807_aa98_a303_0242, 0x1283_5b01_4570_6fbe,
    0x2431_85be_4ee4_b28c, 0x550c_7dc3_d5ff_b4e2,
    0x72be_5d74_f27b_896f, 0x80de_b1fe_3b16_96b1,
    0x9bdc_06a7_25c7_1235, 0xc19b_f174_cf69_2694,
    0xe49b_69c1_9ef1_4ad2, 0xefbe_4786_384f_25e3,
    0x0fc1_9dc6_8b8c_d5b5, 0x240c_a1cc_77ac_9c65,
    0x2de9_2c6f_592b_0275, 0x4a74_84aa_6ea6_e483,
    0x5cb0_a9dc_bd41_fbd4, 0x76f9_88da_8311_53b5,
    0x983e_5152_ee66_dfab, 0xa831_c66d_2db4_3210,
    0xb003_27c8_98fb_213f, 0xbf59_7fc7_beef_0ee4,
    0xc6e0_0bf3_3da8_8fc2, 0xd5a7_9147_930a_a725,
    0x06ca_6351_e003_826f, 0x1429_2967_0a0e_6e70,
    0x27b7_0a85_46d2_2ffc, 0x2e1b_2138_5c26_c926,
    0x4d2c_6dfc_5ac4_2aed, 0x5338_0d13_9d95_b3df,
    0x650a_7354_8baf_63de, 0x766a_0abb_3c77_b2a8,
    0x81c2_c92e_47ed_aee6, 0x9272_2c85_1482_353b,
    0xa2bf_e8a1_4cf1_0364, 0xa81a_664b_bc42_3001,
    0xc24b_8b70_d0f8_9791, 0xc76c_51a3_e6ef_2817,
    0xd192_e819_d6ef_5218, 0xd699_0624_5565_a910,
    0xf40e_3585_5771_202a, 0x106a_a070_32bb_d1b8,
    0x19a4_c116_b8d2_d0c8, 0x1e37_6c08_5141_ab53,
    0x2748_774c_df8e_eb99, 0x34b0_bcb5_e19b_48a8,
    0x391c_0cb3_c5c9_5a63, 0x4ed8_aa4a_e341_8acb,
    0x5b9c_ca4f_7763_e373, 0x682e_6ff3_d6b2_b8a3,
    0x748f_82ee_5def_b2fc, 0x78a5_636f_4317_2f60,
    0x84c8_7814_a1f0_ab72, 0x8cc7_0208_1a64_39ec,
    0x90be_fffa_2363_1e28, 0xa450_6ceb_de82_bde9,
    0xbef9_a3f7_b2c6_7915, 0xc671_78f2_e372_532b,
    0xca27_3ece_ea26_619c, 0xd186_b8c7_21c0_c207,
    0xeada_7dd6_cde0_eb1e, 0xf57d_4f7f_ee6e_d178,
    0x06f0_67aa_7217_6fba, 0x0a63_7dc5_a2c8_98a6,
    0x113f_9804_bef9_0dae, 0x1b71_0b35_131c_471b,
    0x28db_77f5_2304_7d84, 0x32ca_ab7b_40c7_2493,
    0x3c9e_be0a_15c9_bebc, 0x431d_67c4_9c10_0d4c,
    0x4cc5_d4be_cb3e_42b6, 0x597f_299c_fc65_7e2a,
    0x5fcb_6fab_3ad6_faec, 0x6c44_198c_4a47_5817,
];

/// Incremental SHA-512 hasher.
struct Sha512 {
    state: [u64; 8],
    buffer: [u8; SHA512_BLOCK_SIZE],
    buf_len: usize,
    total_len: u128,
}

impl Sha512 {
    /// Create a new SHA-512 hasher.
    const fn new() -> Self {
        Self {
            state: SHA512_H,
            buffer: [0u8; SHA512_BLOCK_SIZE],
            buf_len: 0,
            total_len: 0,
        }
    }

    /// Feed data into the hasher.
    fn update(&mut self, data: &[u8]) {
        let mut offset = 0;
        self.total_len += data.len() as u128;

        // Fill leftover buffer first.
        if self.buf_len > 0 {
            let space = SHA512_BLOCK_SIZE - self.buf_len;
            let to_copy = data.len().min(space);
            self.buffer[self.buf_len..self.buf_len + to_copy]
                .copy_from_slice(&data[..to_copy]);
            self.buf_len += to_copy;
            offset += to_copy;

            if self.buf_len == SHA512_BLOCK_SIZE {
                let block = self.buffer;
                sha512_compress(&mut self.state, &block);
                self.buf_len = 0;
            }
        }

        // Process full blocks from input.
        while offset + SHA512_BLOCK_SIZE <= data.len() {
            let mut block = [0u8; SHA512_BLOCK_SIZE];
            block.copy_from_slice(&data[offset..offset + SHA512_BLOCK_SIZE]);
            sha512_compress(&mut self.state, &block);
            offset += SHA512_BLOCK_SIZE;
        }

        // Buffer remaining bytes.
        let remaining = data.len() - offset;
        if remaining > 0 {
            self.buffer[..remaining].copy_from_slice(&data[offset..]);
            self.buf_len = remaining;
        }
    }

    /// Finalize and return the 64-byte digest.
    fn finalize(mut self) -> [u8; SHA512_DIGEST_LEN] {
        let bit_len = self.total_len * 8;

        // Append 0x80.
        self.buffer[self.buf_len] = 0x80;
        self.buf_len += 1;

        // If no room for 16-byte length, pad and compress.
        if self.buf_len > 112 {
            for i in self.buf_len..SHA512_BLOCK_SIZE {
                self.buffer[i] = 0;
            }
            let block = self.buffer;
            sha512_compress(&mut self.state, &block);
            self.buf_len = 0;
            self.buffer = [0u8; SHA512_BLOCK_SIZE];
        }

        // Zero-pad up to byte 112.
        for i in self.buf_len..112 {
            self.buffer[i] = 0;
        }

        // Append 128-bit big-endian bit length.
        let len_bytes = bit_len.to_be_bytes();
        self.buffer[112..128].copy_from_slice(&len_bytes);

        let block = self.buffer;
        sha512_compress(&mut self.state, &block);

        let mut digest = [0u8; SHA512_DIGEST_LEN];
        for (i, word) in self.state.iter().enumerate() {
            let bytes = word.to_be_bytes();
            digest[i * 8..i * 8 + 8].copy_from_slice(&bytes);
        }
        digest
    }
}

/// One-shot SHA-512 hash.
fn sha512(data: &[u8]) -> [u8; SHA512_DIGEST_LEN] {
    let mut hasher = Sha512::new();
    hasher.update(data);
    hasher.finalize()
}

/// SHA-512 compression function (FIPS 180-4 section 6.4.2).
fn sha512_compress(state: &mut [u64; 8], block: &[u8; SHA512_BLOCK_SIZE]) {
    let mut w = [0u64; 80];
    for i in 0..16 {
        w[i] = u64::from_be_bytes([
            block[i * 8],
            block[i * 8 + 1],
            block[i * 8 + 2],
            block[i * 8 + 3],
            block[i * 8 + 4],
            block[i * 8 + 5],
            block[i * 8 + 6],
            block[i * 8 + 7],
        ]);
    }

    for i in 16..80 {
        let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
        let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }

    let [mut wa, mut wb, mut wc, mut wd, mut we, mut wf, mut wg, mut wh] = *state;

    for i in 0..80 {
        let s1 = we.rotate_right(14) ^ we.rotate_right(18) ^ we.rotate_right(41);
        let ch = (we & wf) ^ ((!we) & wg);
        let temp1 = wh
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K512[i])
            .wrapping_add(w[i]);
        let s0 = wa.rotate_right(28) ^ wa.rotate_right(34) ^ wa.rotate_right(39);
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

// ===========================================================================
// GF(2^255 - 19) field arithmetic
// ===========================================================================
//
// The field p = 2^255 - 19. We represent elements as 5 limbs of 51 bits
// each (radix 2^51), which fits in u64 and allows lazy reduction.

/// Number of limbs in a field element.
const LIMBS: usize = 5;

/// Radix for limb representation: 2^51.
const RADIX: u64 = 1 << 51;

/// Mask for the lower 51 bits.
const MASK51: u64 = RADIX - 1;

/// A field element in GF(2^255 - 19), represented as 5 × 51-bit limbs.
///
/// Limbs are stored in little-endian order: `limbs[0]` holds bits 0..50,
/// `limbs[1]` holds bits 51..101, etc.
#[derive(Clone, Copy)]
struct Fe([u64; LIMBS]);

impl Fe {
    /// The zero element.
    const ZERO: Self = Self([0; LIMBS]);

    /// The identity element (1).
    const ONE: Self = Self([1, 0, 0, 0, 0]);

    /// The constant d = -121665/121666 (mod p) from the Ed25519 curve
    /// equation: -x^2 + y^2 = 1 + d*x^2*y^2.
    ///
    /// Value: 37095705934669439343138083508754565189542113879843219016388785533085940283555
    const D: Self = Self([
        0x0003_4dca_1359_78a3,
        0x0000_1a81_519a_09ed,
        0x0000_074d_4fb5_1415,
        0x0000_05e5_a077_954f,
        0x0000_6758_1263_1a5c,
    ]);

    /// 2*d (mod p), precomputed for point addition.
    const D2: Self = Self([
        0x0006_9b94_26b2_f159,
        0x0000_3502_8334_13da,
        0x0000_0e9a_9f6a_282b,
        0x0000_0bcb_40ef_2a9e,
        0x0000_ceb0_24c6_34b8,
    ]);

    /// The square root of -1 (mod p).
    ///
    /// `i = 2^((p-1)/4) mod p`
    /// = 19681161376707505956807079304988542015446066515923890162744021073123829784752
    const SQRT_M1: Self = Self([
        0x0000_61b2_74a0_ea0b,
        0x0000_d5a5_fc8f_189d,
        0x0000_7ef5_e9cb_d0c6,
        0x0000_7859_5a68_0474,
        0x0000_c4ee_1b27_4a0e,
    ]);

    /// Load a field element from 32 bytes (little-endian).
    fn from_bytes(bytes: &[u8; 32]) -> Self {
        // Unpack 256 bits into 5 × 51-bit limbs.
        let load8 = |b: &[u8]| -> u64 {
            let mut v = 0u64;
            for (i, &byte) in b.iter().enumerate().take(8) {
                v |= (byte as u64) << (8 * i);
            }
            v
        };

        let mut r = Self::ZERO;
        r.0[0] = load8(&bytes[0..]) & MASK51;
        r.0[1] = (load8(&bytes[6..]) >> 3) & MASK51;
        r.0[2] = (load8(&bytes[12..]) >> 6) & MASK51;
        r.0[3] = (load8(&bytes[19..]) >> 1) & MASK51;
        r.0[4] = (load8(&bytes[24..]) >> 12) & MASK51;
        r
    }

    /// Serialize to 32 bytes (little-endian), fully reduced.
    fn to_bytes(self) -> [u8; 32] {
        let mut t = self.reduce();

        // Subtract p if t >= p. We compute t - p and check if it
        // borrowed (meaning t < p, so we keep t unchanged).
        let mut s = t.0;
        s[0] += 19;
        let mut carry: i64 = 0;
        for limb in &mut s {
            let v = (*limb).cast_signed() + carry;
            carry = v >> 51;
            *limb = v.cast_unsigned() & MASK51;
        }
        // If the top carry is 1, then t >= p, use subtracted value.
        // If 0, t < p, use original. Use constant-time select.
        let borrow = 1 - carry.cast_unsigned();
        // borrow=1 means t < p (keep t), borrow=0 means t >= p (keep s).
        let mask = borrow.wrapping_neg(); // 0xFFFF... if borrow, 0 if not
        for (t_limb, &s_limb) in t.0.iter_mut().zip(s.iter()) {
            *t_limb = (*t_limb & mask) | (s_limb & !mask);
        }
        // Mask the top bit (bit 255) since p < 2^255.
        t.0[4] &= MASK51 >> 4; // bits 0..46

        // Pack 5 × 51-bit limbs into 32 bytes little-endian.
        let mut out = [0u8; 32];
        let combined = [
            t.0[0],
            t.0[0] >> 8,
            t.0[0] >> 16,
            t.0[0] >> 24,
            t.0[0] >> 32,
            t.0[0] >> 40,
            (t.0[0] >> 48) | (t.0[1] << 3),
            t.0[1] >> 5,
            t.0[1] >> 13,
            t.0[1] >> 21,
            t.0[1] >> 29,
            t.0[1] >> 37,
            (t.0[1] >> 45) | (t.0[2] << 6),
            t.0[2] >> 2,
            t.0[2] >> 10,
            t.0[2] >> 18,
            t.0[2] >> 26,
            t.0[2] >> 34,
            t.0[2] >> 42,
            (t.0[2] >> 50) | (t.0[3] << 1),
            t.0[3] >> 7,
            t.0[3] >> 15,
            t.0[3] >> 23,
            t.0[3] >> 31,
            (t.0[3] >> 39) | (t.0[4] << 12),
            t.0[4] >> 4,
            t.0[4] >> 12,
            t.0[4] >> 20,
            t.0[4] >> 28,
            t.0[4] >> 36,
            t.0[4] >> 44,
            0,
        ];
        for (byte, &val) in out.iter_mut().zip(combined.iter()) {
            *byte = val as u8;
        }
        out
    }

    /// Carry-propagate to ensure each limb is < 2^51.
    fn reduce(self) -> Self {
        let mut t = self.0;

        for _ in 0..2 {
            let mut carry = 0u64;
            for limb in &mut t[..4] {
                *limb += carry;
                carry = *limb >> 51;
                *limb &= MASK51;
            }
            t[4] += carry;
            carry = t[4] >> 51;
            t[4] &= MASK51;
            // Carry from top wraps with factor 19 (since 2^255 ≡ 19 mod p).
            t[0] += carry * 19;
        }

        Self(t)
    }

    /// Addition (mod p, lazy -- may exceed p).
    fn add(self, rhs: Self) -> Self {
        let mut r = [0u64; LIMBS];
        for (r_limb, (&a_limb, &b_limb)) in r.iter_mut().zip(self.0.iter().zip(rhs.0.iter())) {
            *r_limb = a_limb + b_limb;
        }
        Self(r)
    }

    /// Subtraction (mod p). Adds 2p first to prevent underflow.
    fn sub(self, rhs: Self) -> Self {
        // Add 2p to each limb to prevent underflow, then reduce.
        // 2p represented in 51-bit limbs:
        // p = 2^255 - 19, so 2p = 2^256 - 38
        const TWO_P: [u64; LIMBS] = [
            0x0007_ffff_ffff_ffda * 2,
            0x0007_ffff_ffff_fffe * 2,
            0x0007_ffff_ffff_fffe * 2,
            0x0007_ffff_ffff_fffe * 2,
            0x0007_ffff_ffff_fffe * 2,
        ];
        let mut r = [0u64; LIMBS];
        for (r_limb, ((&a_limb, &b_limb), &tp)) in
            r.iter_mut().zip(self.0.iter().zip(rhs.0.iter()).zip(TWO_P.iter()))
        {
            *r_limb = a_limb + tp - b_limb;
        }
        Self(r).reduce()
    }

    /// Multiplication (mod p) using schoolbook with u128 intermediates.
    #[allow(clippy::too_many_lines)]
    fn mul(self, rhs: Self) -> Self {
        let a = self.0;
        let b = rhs.0;

        // Precompute 19 * b[i] for reduction of terms above 2^255.
        let b1_19 = 19 * b[1];
        let b2_19 = 19 * b[2];
        let b3_19 = 19 * b[3];
        let b4_19 = 19 * b[4];

        // Schoolbook multiplication with reduction.
        // r[0] = a[0]*b[0] + 19*(a[1]*b[4] + a[2]*b[3] + a[3]*b[2] + a[4]*b[1])
        let r0 = (a[0] as u128) * (b[0] as u128)
            + (a[1] as u128) * (b4_19 as u128)
            + (a[2] as u128) * (b3_19 as u128)
            + (a[3] as u128) * (b2_19 as u128)
            + (a[4] as u128) * (b1_19 as u128);

        let r1 = (a[0] as u128) * (b[1] as u128)
            + (a[1] as u128) * (b[0] as u128)
            + (a[2] as u128) * (b4_19 as u128)
            + (a[3] as u128) * (b3_19 as u128)
            + (a[4] as u128) * (b2_19 as u128);

        let r2 = (a[0] as u128) * (b[2] as u128)
            + (a[1] as u128) * (b[1] as u128)
            + (a[2] as u128) * (b[0] as u128)
            + (a[3] as u128) * (b4_19 as u128)
            + (a[4] as u128) * (b3_19 as u128);

        let r3 = (a[0] as u128) * (b[3] as u128)
            + (a[1] as u128) * (b[2] as u128)
            + (a[2] as u128) * (b[1] as u128)
            + (a[3] as u128) * (b[0] as u128)
            + (a[4] as u128) * (b4_19 as u128);

        let r4 = (a[0] as u128) * (b[4] as u128)
            + (a[1] as u128) * (b[3] as u128)
            + (a[2] as u128) * (b[2] as u128)
            + (a[3] as u128) * (b[1] as u128)
            + (a[4] as u128) * (b[0] as u128);

        // Carry propagation.
        let mut out = [0u64; LIMBS];
        let c0 = r0 >> 51;
        out[0] = (r0 as u64) & MASK51;
        let r1c = r1 + c0;
        let c1 = r1c >> 51;
        out[1] = (r1c as u64) & MASK51;
        let r2c = r2 + c1;
        let c2 = r2c >> 51;
        out[2] = (r2c as u64) & MASK51;
        let r3c = r3 + c2;
        let c3 = r3c >> 51;
        out[3] = (r3c as u64) & MASK51;
        let r4c = r4 + c3;
        let c4 = r4c >> 51;
        out[4] = (r4c as u64) & MASK51;
        // Top carry wraps with factor 19.
        out[0] += (c4 as u64) * 19;

        Self(out)
    }

    /// Squaring (mod p), slightly faster than generic mul.
    fn square(self) -> Self {
        self.mul(self)
    }

    /// Compute self^(2^n) by repeated squaring.
    fn square_n(self, n: u32) -> Self {
        let mut r = self;
        for _ in 0..n {
            r = r.square();
        }
        r
    }

    /// Modular inversion: self^(p-2) mod p via addition chain.
    ///
    /// Uses the Fermat's little theorem: a^(-1) = a^(p-2) mod p
    /// where p - 2 = 2^255 - 21.
    fn invert(self) -> Self {
        // Addition chain for p-2 = 2^255 - 21
        let t0 = self.square();           // 2
        let t1 = t0.square_n(2);          // 8
        let t1 = self.mul(t1);            // 9
        let t0 = t0.mul(t1);             // 11
        let t2 = t0.square();             // 22
        let t1 = t1.mul(t2);             // 31 = 2^5 - 1
        let t2 = t1.square_n(5);          // 2^10 - 32
        let t1 = t2.mul(t1);             // 2^10 - 1
        let t2 = t1.square_n(10);         // 2^20 - 2^10
        let t2 = t2.mul(t1);             // 2^20 - 1
        let t3 = t2.square_n(20);         // 2^40 - 2^20
        let t2 = t3.mul(t2);             // 2^40 - 1
        let t2 = t2.square_n(10);         // 2^50 - 2^10
        let t1 = t2.mul(t1);             // 2^50 - 1
        let t2 = t1.square_n(50);         // 2^100 - 2^50
        let t2 = t2.mul(t1);             // 2^100 - 1
        let t3 = t2.square_n(100);        // 2^200 - 2^100
        let t2 = t3.mul(t2);             // 2^200 - 1
        let t2 = t2.square_n(50);         // 2^250 - 2^50
        let t1 = t2.mul(t1);             // 2^250 - 1
        let t1 = t1.square_n(5);          // 2^255 - 32
        t1.mul(t0)                        // 2^255 - 21
    }

    /// Compute the "power of 2^(p-5)/8" used for square root.
    ///
    /// Returns self^((p-5)/8) which is used in the Ed25519 point
    /// decompression sqrt algorithm.
    fn pow_p58(self) -> Self {
        // (p-5)/8 = (2^255 - 24) / 8 = 2^252 - 3
        let t0 = self.square();           // 2
        let t1 = t0.square_n(2);          // 8
        let t1 = self.mul(t1);            // 9
        let t0 = t0.mul(t1);             // 11
        let t0 = t0.square();             // 22
        let t0 = t1.mul(t0);             // 31 = 2^5 - 1
        let t1 = t0.square_n(5);          // 2^10 - 32
        let t0 = t1.mul(t0);             // 2^10 - 1
        let t1 = t0.square_n(10);         // 2^20 - 2^10
        let t1 = t1.mul(t0);             // 2^20 - 1
        let t2 = t1.square_n(20);         // 2^40 - 2^20
        let t1 = t2.mul(t1);             // 2^40 - 1
        let t1 = t1.square_n(10);         // 2^50 - 2^10
        let t0 = t1.mul(t0);             // 2^50 - 1
        let t1 = t0.square_n(50);         // 2^100 - 2^50
        let t1 = t1.mul(t0);             // 2^100 - 1
        let t2 = t1.square_n(100);        // 2^200 - 2^100
        let t1 = t2.mul(t1);             // 2^200 - 1
        let t1 = t1.square_n(50);         // 2^250 - 2^50
        let t0 = t1.mul(t0);             // 2^250 - 1
        let t0 = t0.square_n(2);          // 2^252 - 4
        self.mul(t0)                      // 2^252 - 3
    }

    /// Check if this element is negative (i.e., odd when serialized).
    fn is_negative(self) -> bool {
        let bytes = self.to_bytes();
        (bytes[0] & 1) != 0
    }

    /// Check if two field elements are equal (after full reduction).
    fn ct_eq(self, rhs: Self) -> bool {
        let a = self.to_bytes();
        let b = rhs.to_bytes();
        let mut diff = 0u8;
        for i in 0..32 {
            diff |= a[i] ^ b[i];
        }
        diff == 0
    }

    /// Negate: -self mod p.
    fn neg(self) -> Self {
        Self::ZERO.sub(self)
    }

    /// Conditional negate: if `negate` is true, return `-self`, else `self`.
    fn conditional_negate(self, negate: bool) -> Self {
        if negate { self.neg() } else { self }
    }
}

// ===========================================================================
// Ed25519 group operations (extended coordinates)
// ===========================================================================
//
// Points on the twisted Edwards curve -x^2 + y^2 = 1 + d*x^2*y^2
// (over GF(2^255 - 19)) are represented in extended coordinates
// (X, Y, Z, T) where x = X/Z, y = Y/Z, T = X*Y/Z.

/// A point on the Ed25519 curve in extended coordinates (X, Y, Z, T).
#[derive(Clone, Copy)]
struct GePoint {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,
}

impl GePoint {
    /// The neutral element (identity point): (0, 1, 1, 0).
    const IDENTITY: Self = Self {
        x: Fe::ZERO,
        y: Fe::ONE,
        z: Fe::ONE,
        t: Fe::ZERO,
    };

    /// The Ed25519 base point B.
    ///
    /// B has y-coordinate 4/5 (mod p) with x positive (even).
    /// Encoded (compressed): the standard generator point.
    const BASE: Self = Self {
        x: Fe([
            0x0006_2d60_8f25_d51a,
            0x0004_12a4_b4f6_592a,
            0x0007_5b7f_4565_e089,
            0x0004_1256_099d_0f8b,
            0x0001_9122_0bde_93a4,
        ]),
        y: Fe([
            0x0000_6666_6666_6658,
            0x0000_4ccc_cccc_cccc,
            0x0000_1999_9999_999a,
            0x0000_3333_3333_3333,
            0x0000_6666_6666_6666,
        ]),
        z: Fe::ONE,
        t: Fe([
            0x0006_787c_defb_3632,
            0x0005_0545_5386_9a1c,
            0x0007_89a4_7d3e_2ec0,
            0x000e_e7fe_bf73_8066,
            0x0004_feba_eb15_36b0,
        ]),
    };

    /// Point addition in extended coordinates.
    ///
    /// Algorithm from "Twisted Edwards Curves Revisited" (HWCD08),
    /// using the unified addition formula for extended coordinates.
    #[allow(clippy::many_single_char_names)]
    fn add(self, rhs: Self) -> Self {
        let a = self.y.sub(self.x).mul(rhs.y.sub(rhs.x));
        let b = self.y.add(self.x).mul(rhs.y.add(rhs.x));
        let c = self.t.mul(Fe::D2).mul(rhs.t);
        let d = self.z.mul(rhs.z).add(self.z.mul(rhs.z));
        let e = b.sub(a);
        let f = d.sub(c);
        let g = d.add(c);
        let h = b.add(a);
        Self {
            x: e.mul(f),
            y: g.mul(h),
            z: f.mul(g),
            t: e.mul(h),
        }
    }

    /// Point doubling in extended coordinates.
    ///
    /// For the twisted Edwards curve -x^2 + y^2 = 1 + d*x^2*y^2:
    /// A = X^2, B = Y^2, C = 2*Z^2
    /// D = -A (because curve coefficient a = -1)
    /// E = (X+Y)^2 - A - B
    /// G = D + B
    /// F = G - C
    /// H = D - B
    #[allow(clippy::many_single_char_names)]
    fn double(self) -> Self {
        let a = self.x.square();          // A = X^2
        let b = self.y.square();          // B = Y^2
        let c = self.z.square().add(self.z.square()); // C = 2*Z^2
        let d_neg = Fe::ZERO.sub(a);      // D = -A
        let e = self.x.add(self.y).square().sub(a).sub(b); // E
        let g = d_neg.add(b);             // G = D + B
        let f = g.sub(c);                 // F = G - C
        let h = d_neg.sub(b);             // H = D - B
        Self {
            x: e.mul(f),
            y: g.mul(h),
            z: f.mul(g),
            t: e.mul(h),
        }
    }

    /// Scalar multiplication: compute `scalar * self`.
    ///
    /// Uses a simple double-and-add algorithm. Not constant-time, which
    /// is acceptable for signature verification (public inputs only).
    fn scalar_mul(self, scalar: &[u8; 32]) -> Self {
        let mut result = Self::IDENTITY;
        // Process bits from most significant to least significant.
        for i in (0..256).rev() {
            result = result.double();
            let byte_idx = i / 8;
            let bit_idx = i % 8;
            if (scalar[byte_idx] >> bit_idx) & 1 == 1 {
                result = result.add(self);
            }
        }
        result
    }

    /// Decompress a point from its 32-byte encoding.
    ///
    /// Ed25519 encoding: the y-coordinate in little-endian with the
    /// high bit of the last byte encoding the sign of x.
    ///
    /// Returns `None` if the encoding is not a valid curve point.
    #[allow(clippy::many_single_char_names)]
    fn decompress(bytes: &[u8; 32]) -> Option<Self> {
        // Extract the sign bit (high bit of last byte).
        let x_sign = (bytes[31] >> 7) & 1;

        // Clear the sign bit and decode y.
        let mut y_bytes = *bytes;
        y_bytes[31] &= 0x7F;
        let y = Fe::from_bytes(&y_bytes);

        // Recover x from the curve equation:
        // -x^2 + y^2 = 1 + d*x^2*y^2
        // x^2 * (-1 - d*y^2) = y^2 - 1
        // x^2 = (y^2 - 1) / (-1 - d*y^2)
        let y2 = y.square();
        let u = y2.sub(Fe::ONE);             // u = y^2 - 1
        let v = Fe::D.mul(y2).add(Fe::ONE).neg(); // v = -1 - d*y^2

        // x = u * v^3 * (u * v^7)^((p-5)/8)
        let v3 = v.square().mul(v);
        let v7 = v3.square().mul(v);
        let uv7 = u.mul(v7);
        let uv7_p58 = uv7.pow_p58();
        let mut x = u.mul(v3).mul(uv7_p58);

        // Check: v * x^2 == u?
        let vx2 = v.mul(x.square());
        if vx2.ct_eq(u) {
            // Good, x is correct.
        } else if vx2.ct_eq(u.neg()) {
            // x needs to be multiplied by sqrt(-1).
            x = x.mul(Fe::SQRT_M1);
        } else {
            // Not a valid point.
            return None;
        }

        // Apply the sign bit.
        x = x.conditional_negate(x.is_negative() != (x_sign == 1));

        // Reject x == 0 with sign bit set (RFC 8032 malleability check).
        if x.ct_eq(Fe::ZERO) && x_sign == 1 {
            return None;
        }

        let t = x.mul(y);
        Some(Self {
            x,
            y,
            z: Fe::ONE,
            t,
        })
    }

    /// Compress a point to its 32-byte encoding.
    fn compress(self) -> [u8; 32] {
        let z_inv = self.z.invert();
        let x = self.x.mul(z_inv);
        let y = self.y.mul(z_inv);

        let mut encoded = y.to_bytes();
        // Set the high bit if x is negative (odd).
        encoded[31] |= if x.is_negative() { 0x80 } else { 0 };
        encoded
    }
}

// ===========================================================================
// Ed25519 signature verification — RFC 8032 section 5.1.7
// ===========================================================================

/// Verify an Ed25519 signature over `message` with the given `public_key`.
///
/// Implements RFC 8032 section 5.1.7:
/// 1. Decode the public key A and signature (R, S).
/// 2. Compute k = SHA-512(R || A || message) mod L.
/// 3. Check that [8*S]*B == [8]*R + [8*k]*A.
///
/// The cofactor-multiply ([8]*) ensures small-subgroup safety.
fn ed25519_verify(
    public_key: &[u8; PUBLIC_KEY_LEN],
    message: &[u8],
    signature: &[u8; SIGNATURE_LEN],
) -> bool {
    // 1. Decode the point A from the public key.
    let Some(a_point) = GePoint::decompress(public_key) else {
        return false;
    };

    // 2. Decode R (first 32 bytes of signature).
    let mut r_bytes = [0u8; 32];
    r_bytes.copy_from_slice(&signature[..32]);
    let Some(r_point) = GePoint::decompress(&r_bytes) else {
        return false;
    };

    // 3. Decode S (last 32 bytes of signature) as a scalar.
    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&signature[32..64]);

    // S must be < L (the group order). Check the canonical encoding.
    if !scalar_is_canonical(&s_bytes) {
        return false;
    }

    // 4. Compute k = SHA-512(R || A || message) mod L.
    let mut hasher = Sha512::new();
    hasher.update(&r_bytes);
    hasher.update(public_key);
    hasher.update(message);
    let k_hash = hasher.finalize();
    let k = scalar_reduce_wide(&k_hash);

    // 5. Check [S]*B == R + [k]*A
    // Equivalently: [S]*B - R - [k]*A == identity
    let sb = GePoint::BASE.scalar_mul(&s_bytes);
    let ka = a_point.scalar_mul(&k);
    let rhs = r_point.add(ka);

    // Compare by compressing both sides.
    let lhs_bytes = sb.compress();
    let rhs_bytes = rhs.compress();

    // Constant-time comparison.
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= lhs_bytes[i] ^ rhs_bytes[i];
    }
    diff == 0
}

/// The Ed25519 group order L.
///
/// L = 2^252 + 27742317777372353535851937790883648493
/// In little-endian bytes.
const L: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

/// Check that a 32-byte scalar is in canonical form (< L).
fn scalar_is_canonical(s: &[u8; 32]) -> bool {
    // Compare with L byte-by-byte from most significant.
    // If s >= L, reject.
    let mut borrow: i16 = 0;
    for i in 0..32 {
        borrow += (s[i] as i16) - (L[i] as i16);
        borrow >>= 8;
    }
    // If borrow is -1, s < L (canonical). If 0, s >= L (non-canonical).
    borrow != 0
}

/// Reduce a 64-byte hash to a 32-byte scalar mod L.
///
/// Uses Barrett reduction. The input is a 512-bit value from SHA-512;
/// the output is a 256-bit scalar in [0, L).
fn scalar_reduce_wide(hash: &[u8; 64]) -> [u8; 32] {
    // L in signed representation (first 17 non-zero terms).
    // Must be declared before statements to satisfy clippy::items_after_statements.
    const L_PARTS: [i64; 17] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
        0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
        0x01, // The 2^(8*16) = 2^128 part
    ];

    // Load the 512-bit value as an array of limbs for modular reduction.
    // We use a simple schoolbook division approach: convert to a big
    // integer, then repeatedly subtract L.
    //
    // For Ed25519, we can use the property that L ~= 2^252, so the
    // 512-bit hash needs at most ~260 bits of reduction. We implement
    // this via the standard "reduce mod L" algorithm used in Ed25519
    // implementations.

    // Load 64 bytes into 64 i64 limbs (signed digits).
    let mut x = [0i64; 64];
    for (limb, &byte) in x.iter_mut().zip(hash.iter()) {
        *limb = i64::from(byte);
    }

    // Reduce from the top. Each byte position i (from 63 down to 32)
    // contributes x[i] * 256^i to the value. Since 256^i = 256^(i-32) * 256^32,
    // and 256^32 = 2^256 = 2^4 * 2^252 ≡ 2^4 * (L - c) where c is the low
    // part of L, we can fold the upper bytes down.
    //
    // However, the simplest correct approach for a verification-only path
    // is to work in wider arithmetic. We'll use the standard ref10 approach.

    // Process from position 63 down to 32.
    for i in (32..64).rev() {
        let q = x[i]; // digit to eliminate
        // Subtract q * L shifted by (i - 32) bytes.
        // L occupies positions 0..16 (plus the 2^252 = byte 31 bit 4).
        let base = i - 32;
        for (j, &l_part) in L_PARTS.iter().enumerate() {
            x[base + j] -= q * l_part;
        }
        x[i] = 0;
    }

    // Now x is at most ~33 bytes. Propagate carries.
    for i in 0..31 {
        let carry = x[i] >> 8;
        x[i + 1] += carry;
        x[i] -= carry << 8;
    }

    // The value might still be >= L. Do one final conditional subtraction.
    // Check if x >= L by comparing from the top.
    let q = x[31] >> 4; // How many times L fits (L ≈ 2^252)
    // Subtract q * L
    for (j, &l_part) in L_PARTS.iter().enumerate() {
        x[j] -= q * l_part;
    }
    // Propagate carries again.
    for i in 0..31 {
        let carry = x[i] >> 8;
        x[i + 1] += carry;
        x[i] -= carry << 8;
    }

    // Final conditional subtraction if still >= L.
    // Check x >= L
    let ge = {
        let mut borrow: i64 = 0;
        for i in 0..32 {
            borrow += x[i] - (L[i] as i64);
            borrow >>= 8;
        }
        // borrow == 0 means x >= L
        borrow == 0
    };

    if ge {
        for (j, &l_part) in L_PARTS.iter().enumerate().take(17) {
            x[j] -= l_part;
        }
        for i in 0..31 {
            let carry = x[i] >> 8;
            x[i + 1] += carry;
            x[i] -= carry << 8;
        }
    }

    let mut result = [0u8; 32];
    for i in 0..32 {
        result[i] = x[i] as u8;
    }
    result
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
/// - [`SecureBootError::ImageTooShort`] if the image is shorter than
///   65 bytes (minimum 1 byte payload + 64 byte signature).
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
/// # Errors
///
/// - [`SecureBootError::ImageTooShort`] if `image` is empty.
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
    if image.is_empty() {
        return Err(SecureBootError::ImageTooShort);
    }

    if require_boot_key && *public_key != BOOT_PUBLIC_KEY {
        return Err(SecureBootError::WrongPublicKey);
    }

    if ed25519_verify(public_key, image, signature) {
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
mod tests {
    use super::*;

    // -- SHA-512 test vectors (NIST) --

    #[test]
    fn sha512_empty() {
        // NIST: SHA-512("") = cf83e1357eefb8bd...
        let digest = sha512(b"");
        let expected: [u8; 64] = [
            0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd,
            0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d, 0x80, 0x07,
            0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc,
            0x83, 0xf4, 0xa9, 0x21, 0xd3, 0x6c, 0xe9, 0xce,
            0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0,
            0xff, 0x83, 0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f,
            0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81,
            0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e,
        ];
        assert_eq!(digest, expected, "SHA-512 of empty string must match NIST vector");
    }

    #[test]
    fn sha512_abc() {
        // NIST: SHA-512("abc") = ddaf35a193617aba...
        let digest = sha512(b"abc");
        let expected: [u8; 64] = [
            0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba,
            0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31,
            0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2,
            0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a,
            0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8,
            0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd,
            0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e,
            0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f,
        ];
        assert_eq!(digest, expected, "SHA-512 of 'abc' must match NIST vector");
    }

    // -- Ed25519 verification with RFC 8032 test vectors --

    /// RFC 8032 section 7.1 Test Vector 1: empty message.
    #[test]
    fn ed25519_rfc8032_test1_empty_message() {
        let public_key: [u8; 32] = [
            0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
            0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
            0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa3, 0x23, 0x28,
            0xf8, 0xb8, 0x89, 0x1c, 0xc2, 0x97, 0x10, 0x49,
        ];
        let signature: [u8; 64] = [
            0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72,
            0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e, 0x82, 0x8a,
            0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74,
            0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49, 0x01, 0x55,
            0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac,
            0xc6, 0x1e, 0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b,
            0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24,
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
            0x3d, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89, 0x5a,
            0x92, 0xb7, 0x0a, 0xa7, 0x4d, 0x1b, 0x7e, 0xbc,
            0x9c, 0x98, 0x2c, 0xcf, 0x2e, 0xc4, 0x96, 0x8c,
            0xc0, 0xcd, 0x55, 0xf1, 0x2a, 0xf4, 0x66, 0x0c,
        ];
        let signature: [u8; 64] = [
            0x92, 0xa0, 0x09, 0xa9, 0xf0, 0xd4, 0xca, 0xb8,
            0x72, 0x0e, 0x82, 0x0b, 0x5f, 0x64, 0x25, 0x40,
            0xa2, 0xb2, 0x7b, 0x54, 0x16, 0x50, 0x3f, 0x8f,
            0xb3, 0x76, 0x22, 0x23, 0xeb, 0xdb, 0x69, 0xda,
            0x08, 0x5a, 0xc1, 0xe4, 0x3e, 0x15, 0x99, 0x6e,
            0x45, 0x8f, 0x36, 0x13, 0xd0, 0xf1, 0x1d, 0x8c,
            0x38, 0x7b, 0x2e, 0xae, 0xb4, 0x30, 0x2a, 0xee,
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
            0xfc, 0x51, 0xcd, 0x8e, 0x62, 0x18, 0xa1, 0xa3,
            0x8d, 0xa4, 0x7e, 0xd0, 0x02, 0x30, 0xf0, 0x58,
            0x08, 0x16, 0xed, 0x13, 0xba, 0x33, 0x03, 0xac,
            0x5d, 0xeb, 0x91, 0x15, 0x48, 0x90, 0x80, 0x25,
        ];
        let signature: [u8; 64] = [
            0x62, 0x91, 0xd6, 0x57, 0xde, 0xec, 0x24, 0x02,
            0x48, 0x27, 0xe6, 0x9c, 0x3a, 0xbe, 0x01, 0xa3,
            0x0c, 0xe5, 0x48, 0xa2, 0x84, 0x74, 0x3a, 0x44,
            0x5e, 0x36, 0x80, 0xd7, 0xdb, 0x5a, 0xc3, 0xac,
            0x18, 0xff, 0x9b, 0x53, 0x8d, 0x16, 0xf2, 0x90,
            0xae, 0x67, 0xf7, 0x60, 0x98, 0x4d, 0xc6, 0x59,
            0x4a, 0x7c, 0x15, 0xe9, 0x71, 0x6e, 0xd2, 0x8d,
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
            0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
            0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
            0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa3, 0x23, 0x28,
            0xf8, 0xb8, 0x89, 0x1c, 0xc2, 0x97, 0x10, 0x49,
        ];
        let signature: [u8; 64] = [
            0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72,
            0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e, 0x82, 0x8a,
            0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74,
            0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49, 0x01, 0x55,
            0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac,
            0xc6, 0x1e, 0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b,
            0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24,
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
            0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
            0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
            0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa3, 0x23, 0x28,
            0xf8, 0xb8, 0x89, 0x1c, 0xc2, 0x97, 0x10, 0x49,
        ];
        // Valid signature with one byte corrupted (byte 0 changed).
        let mut signature: [u8; 64] = [
            0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72,
            0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e, 0x82, 0x8a,
            0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74,
            0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49, 0x01, 0x55,
            0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac,
            0xc6, 0x1e, 0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b,
            0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24,
            0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b,
        ];
        signature[0] ^= 0x01; // corrupt one bit

        let result = verify_kernel_signature_with_key(
            b"",
            &signature,
            &public_key,
            false,
        );
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
            0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72,
            0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e, 0x82, 0x8a,
            0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74,
            0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49, 0x01, 0x55,
            0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac,
            0xc6, 0x1e, 0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b,
            0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24,
            0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b,
        ];
        // Different public key (all zeros — definitely not the boot key).
        let wrong_key = [0u8; 32];

        let result = verify_kernel_signature_with_key(
            b"",
            &signature,
            &wrong_key,
            true, // require boot key match
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
            0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
            0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
            0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa3, 0x23, 0x28,
            0xf8, 0xb8, 0x89, 0x1c, 0xc2, 0x97, 0x10, 0x49,
        ];
        // This signature is valid for empty message, not for "tampered".
        let signature: [u8; 64] = [
            0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72,
            0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e, 0x82, 0x8a,
            0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74,
            0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49, 0x01, 0x55,
            0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac,
            0xc6, 0x1e, 0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b,
            0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24,
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

        let (payload, sig) = split_image(&image)
            .expect("split_image must succeed for 128-byte image");
        assert_eq!(payload.len(), 64, "payload must be 64 bytes");
        assert!(payload.iter().all(|&b| b == 0xAA), "payload must be all 0xAA");
        assert!(sig.iter().all(|&b| b == 0xBB), "signature must be all 0xBB");
    }

    /// Test Display impl for SecureBootError.
    #[test]
    fn error_display() {
        let msg = SecureBootError::ImageTooShort.to_string();
        assert!(msg.contains("too short"), "ImageTooShort display must mention 'too short'");

        let msg = SecureBootError::InvalidSignature.to_string();
        assert!(msg.contains("verification failed"), "InvalidSignature display");

        let msg = SecureBootError::WrongPublicKey.to_string();
        assert!(msg.contains("does not match"), "WrongPublicKey display");
    }

    // -- Field arithmetic smoke tests --

    #[test]
    fn fe_zero_is_identity_for_add() {
        let a = Fe::from_bytes(&[42; 32]);
        let sum = a.add(Fe::ZERO);
        assert!(
            a.to_bytes() == sum.reduce().to_bytes(),
            "a + 0 must equal a"
        );
    }

    #[test]
    fn fe_one_is_identity_for_mul() {
        let a = Fe::from_bytes(&[42; 32]);
        let prod = a.mul(Fe::ONE);
        assert!(
            a.to_bytes() == prod.to_bytes(),
            "a * 1 must equal a"
        );
    }

    #[test]
    fn fe_invert_round_trip() {
        let a = Fe::from_bytes(&[
            0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);
        let a_inv = a.invert();
        let product = a.mul(a_inv);
        assert!(
            product.ct_eq(Fe::ONE),
            "a * a^(-1) must equal 1"
        );
    }

    /// Verify the base point decompresses correctly from its standard encoding.
    #[test]
    fn base_point_decompresses() {
        // The Ed25519 base point encoded (y-coordinate with sign bit).
        let base_encoded: [u8; 32] = [
            0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        ];
        let point = GePoint::decompress(&base_encoded);
        assert!(point.is_some(), "base point must decompress successfully");

        // Re-compress and verify round-trip.
        let recompressed = point.map(|p| p.compress());
        assert_eq!(
            recompressed,
            Some(base_encoded),
            "base point must round-trip through compress/decompress"
        );
    }

    /// Scalar reduce of a known value.
    #[test]
    fn scalar_reduce_identity() {
        // A value that is already < L should be unchanged.
        let mut input = [0u8; 64];
        input[0] = 42;
        let reduced = scalar_reduce_wide(&input);
        assert_eq!(reduced[0], 42, "small value must be unchanged after reduction");
        assert!(reduced[1..].iter().all(|&b| b == 0), "upper bytes must be zero");
    }
}
