//! Security Manager Protocol (SMP): the crypto toolbox, PDU codec, and the
//! LE Secure Connections pairing state machine (#455, #636).
//!
//! This module (`ah()`, [`Irk`]) covers #455 stages 1-2: the
//! random-address hash function and the key type. [`toolbox`] adds the LE
//! Secure Connections toolbox (`f4`/`f5`/`f6`/`g2`, ECDH P-256). [`pdu`]
//! covers the wire codec. [`pairing`] drives the state machine that
//! exchanges keys — #455 stage 3 / #636.
//!
//! # LE Secure Connections only
//!
//! [`pairing`] implements LE Secure Connections (ECDH P-256 key agreement)
//! exclusively and refuses a peer that will not negotiate it. LE Legacy
//! Pairing (`c1`/`s1`, no `ah()`-family relation) is deliberately NOT
//! implemented: Legacy's confirm/random exchange is derived from the TK
//! alone and is broken by passive eavesdropping for Just Works and
//! Passkey Entry — the exact class of weakness #636 exists to avoid
//! landing. See [`pairing`] docs for the IO capability / association
//! model this module supports (Just Works only, for now).
//!
//! # Byte-order convention
//!
//! Everything in this module is **big-endian display order**, the same
//! convention `transport.rs` uses for `BdAddr` (index 0 = display MSB) and
//! the convention the spec's Appendix D test vectors are written in. That
//! makes `ah()` byte-for-byte the spec's definition — `r' = padding || r`
//! and `ah(k, r) = e(k, r') mod 2^24` — with NO byte reversal anywhere.
//! (The LE-over-air swap dance Linux's `smp_ah` performs exists only
//! because Linux stores keys/addresses little-endian; this crate's HCI
//! layer already converts at the packet boundary, `build_le_*_cmd`.)
//! [`toolbox`] and [`pdu`] document where this convention's boundary with
//! the little-endian wire format sits for the newer functions.
//!
//! Verified against Core Spec Vol 3, Part H, Appendix D.7 (v5.4 p1644):
//! IRK `ec0234a357c8ad05341010a60a397d9b`, prand `708194`,
//! AES `159d5fb7 2ebe2311 a48c1bdc c40dfbaa`, ah `0dfbaa` — see the tests.

pub(crate) mod pairing;
pub(crate) mod pdu;
pub(crate) mod toolbox;

use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
use zeroize::Zeroize;

/// The `ah()` random-address hash function (Vol 3, Part H §2.2.2):
/// `ah(k, r) = e(k, r') mod 2^24`, AES-128-ECB single block.
///
/// - `irk` — the Identity Resolving Key, 16 bytes big-endian display order.
/// - `prand` — the 22-bit random, 3 bytes big-endian display order (its top
///   two bits carry the RPA type field; they are input bits, not masked here).
///
/// Returns the 24-bit hash, 3 bytes big-endian display order.
pub(crate) fn ah(irk: &[u8; 16], prand: &[u8; 3]) -> [u8; 3] {
    // r' = padding(104 bits) || r(24 bits): thirteen zero bytes, then prand.
    let mut m = [0u8; 16];
    m[13..].copy_from_slice(prand);
    // Aes128::new takes the 16-byte key by reference — no fallible slice
    // conversion, so no unwrap/expect anywhere in the primitive.
    let cipher = Aes128::new(GenericArray::from_slice(irk));
    let mut block = *GenericArray::from_slice(&m);
    cipher.encrypt_block(&mut block);
    // mod 2^24: the least significant 24 bits of the big-endian output —
    // the last three octets of the ciphertext block.
    [block[13], block[14], block[15]]
}

/// An Identity Resolving Key (#455 stage 2): 16 bytes, zeroized on drop,
/// redacted in Debug.
///
/// # Persistence seam (deliberate boundary)
///
/// An IRK must survive our own address rotations and reboots to be useful,
/// but it is a SECRET: in cleartext on disk it defeats the unlinkability it
/// exists to provide (a device in hand would resolve every past RPA). The
/// designed home is slot kind 2 of the kernel's on-disk secrets preamble
/// (#449) — a slot SEALED under the passphrase-derived primary key once the
/// boot input loop (kinit Step 8d) exists to derive it. An unsealed
/// on-disk write is rejected for the same reason a device-id-derived
/// sealing key is rejected (attacker-readable from a device in hand). So
/// today the IRK lives in RAM only: generated at boot/pairing, zeroized on
/// drop. The sealed persistence lands with 8d, not before.
pub(crate) struct Irk([u8; 16]);

impl Irk {
    /// Generate a fresh random IRK (`getrandom` in production, an injected
    /// stream in tests).
    pub(crate) fn generate(random: impl FnOnce(&mut [u8; 16])) -> Self {
        let mut bytes = [0u8; 16];
        random(&mut bytes);
        Self(bytes)
    }

    /// Wrap existing bytes (restore from the sealed store, test vectors).
    pub(crate) const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Borrow the key bytes (big-endian display order).
    pub(crate) const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl Drop for Irk {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl core::fmt::Debug for Irk {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Irk([REDACTED])")
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Core Spec v5.4 Vol 3 Part H Appendix `D.7` (p1644): the canonical `ah()`
    /// vector, big-endian display order throughout.
    const APPENDIX_D_IRK: [u8; 16] = [
        0xec, 0x02, 0x34, 0xa3, 0x57, 0xc8, 0xad, 0x05, 0x34, 0x10, 0x10, 0xa6, 0x0a, 0x39, 0x7d,
        0x9b,
    ];

    #[test]
    fn ah_matches_appendix_d_7() {
        let prand = [0x70, 0x81, 0x94];
        let hash = ah(&APPENDIX_D_IRK, &prand);
        assert_eq!(
            hash,
            [0x0d, 0xfb, 0xaa],
            "ah(IRK, 708194) must equal the spec's 0dfbaa (AES 159d5fb7..0dfbaa)"
        );
    }

    #[test]
    fn ah_is_deterministic_and_prand_sensitive() {
        let prand = [0x70, 0x81, 0x94];
        assert_eq!(ah(&APPENDIX_D_IRK, &prand), ah(&APPENDIX_D_IRK, &prand));
        let other = [0x70, 0x81, 0x95];
        assert_ne!(
            ah(&APPENDIX_D_IRK, &prand),
            ah(&APPENDIX_D_IRK, &other),
            "a one-bit prand change must change the hash (it is an AES block)"
        );
    }

    #[test]
    fn irk_debug_is_redacted() {
        let irk = Irk::from_bytes([0xAA; 16]);
        let dbg = format!("{irk:?}");
        assert_eq!(dbg, "Irk([REDACTED])");
        assert!(!dbg.contains("aa"), "IRK bytes must never appear in Debug");
    }

    #[test]
    fn irk_generate_uses_the_injected_stream() {
        let irk = Irk::generate(|buf: &mut [u8; 16]| {
            for (i, b) in buf.iter_mut().enumerate() {
                *b = i as u8;
            }
        });
        assert_eq!(irk.as_bytes()[0], 0);
        assert_eq!(irk.as_bytes()[15], 15);
    }
}
