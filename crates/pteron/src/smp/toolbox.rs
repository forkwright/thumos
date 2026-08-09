//! LE Secure Connections crypto toolbox (BT Core Spec Vol 3, Part H §2.2):
//! the `f4`/`f5`/`f6`/`g2` functions built on AES-CMAC-128, and the ECDH
//! P-256 key-agreement wrapper around the `p256` crate (#636).
//!
//! # Byte-order convention
//!
//! Same convention as [`super::ah`]: everything here is **big-endian
//! display order**. `p256`'s SEC1 coordinate encoding is already
//! big-endian (SEC1 §2.3.3), so ECDH outputs need no reversal to become
//! `f4`/`f5`/`g2`'s `U`/`V` inputs — only the wire PDU (little-endian,
//! [`super::pdu`]) needs a swap.
//!
//! # Verification
//!
//! `f4`/`f5`/`f6`/`g2` are verified against the Linux kernel's
//! `net/bluetooth/smp.c` self-test vectors (`test_f4`/`test_f5`/`test_f6`/
//! `test_g2`), which are themselves the Core Spec Appendix D sample data.
//! Linux stores every value byte-reversed relative to this module's
//! display-order convention (its own `smp_aes_cmac` swaps LSB-to-MSB
//! before calling a standard CMAC — see `swap_buf` in `smp.c`), so each
//! test reverses the published Linux arrays with a mechanical helper
//! rather than a hand-transcribed constant.

use aes::Aes128;
use cmac::{Cmac, Mac};
use p256::elliptic_curve::Generate;
use p256::elliptic_curve::point::AffineCoordinates;
use rand_core::{Infallible, TryCryptoRng, TryRng};

// ── AES-CMAC-128 primitive ─────────────────────────────────────────────────────

/// AES-CMAC-128 (RFC 4493) over an arbitrary-length message, big-endian
/// display order throughout (key, message, and the 16-byte output).
fn aes_cmac(key: &[u8; 16], message: &[u8]) -> [u8; 16] {
    // INVARIANT: a 16-byte key is always valid for CMAC-AES128 — `new_from_slice`
    // only fails on a wrong-length key, which `&[u8; 16]` makes unreachable.
    let Ok(mut mac) = Cmac::<Aes128>::new_from_slice(key) else {
        unreachable!("a 16-byte key is always accepted by Cmac::<Aes128>::new_from_slice");
    };
    mac.update(message);
    mac.finalize().into_bytes().into()
}

// ── f4 / f5 / f6 / g2 ──────────────────────────────────────────────────────────

/// `f4(U, V, X, Z) = AES-CMAC_X(U || V || Z)` (Vol 3, Part H §2.2.6) — the
/// LE Secure Connections confirm-value function.
///
/// - `u`, `v` — the x-coordinates of the two devices' ECDH public keys.
/// - `x` — the committing device's own nonce.
/// - `z` — `0x00` for Just Works / Numeric Comparison; the passkey-derived
///   bit for Passkey Entry (not implemented — see module docs).
// WHY: parameter names deliberately match the spec's own U/V/X/Z notation
// (Vol 3, Part H §2.2.6) — matching the formula verbatim is more
// auditable than inventing longer names for four single-letter terms.
#[allow(clippy::many_single_char_names)]
pub(crate) fn f4(u: &[u8; 32], v: &[u8; 32], x: &[u8; 16], z: u8) -> [u8; 16] {
    let mut m = [0u8; 65];
    m[..32].copy_from_slice(u);
    m[32..64].copy_from_slice(v);
    m[64] = z;
    aes_cmac(x, &m)
}

/// Fixed SALT input to `f5`'s key-derivation step (Vol 3, Part H §2.2.7).
const F5_SALT: [u8; 16] = [
    0x6c, 0x88, 0x83, 0x91, 0xaa, 0xf5, 0xa5, 0x38, 0x60, 0x37, 0x0b, 0xdb, 0x5a, 0x60, 0x83, 0xbe,
];

/// Fixed `keyID` input to `f5` — the ASCII string `"btle"` as a 32-bit
/// big-endian value, `0x62746c65` (Vol 3, Part H §2.2.7).
const F5_KEY_ID: [u8; 4] = [0x62, 0x74, 0x6c, 0x65];

/// Fixed `Length` input to `f5`: 256 (bits), 2 octets big-endian.
const F5_LENGTH: [u8; 2] = [0x01, 0x00];

/// `f5(W, N1, N2, A1, A2)` (Vol 3, Part H §2.2.7) — derives `MacKey` and
/// `LTK` from the ECDH shared secret. Returns `(MacKey, LTK)`.
///
/// - `w` — the raw Diffie-Hellman key (ECDH shared secret x-coordinate).
/// - `n1`, `n2` — the initiator's and responder's nonces (`Na`, `Nb`).
/// - `a1`, `a2` — the initiator's and responder's identity addresses,
///   encoded as `[address_type] || [6-byte address, MSB first]`.
pub(crate) fn f5(
    w: &[u8; 32],
    n1: &[u8; 16],
    n2: &[u8; 16],
    a1: &[u8; 7],
    a2: &[u8; 7],
) -> ([u8; 16], [u8; 16]) {
    let t = aes_cmac(&F5_SALT, w);

    let mut m = [0u8; 53];
    // m[0] is the Counter octet, set per-call below.
    m[1..5].copy_from_slice(&F5_KEY_ID);
    m[5..21].copy_from_slice(n1);
    m[21..37].copy_from_slice(n2);
    m[37..44].copy_from_slice(a1);
    m[44..51].copy_from_slice(a2);
    m[51..53].copy_from_slice(&F5_LENGTH);

    m[0] = 0; // Counter = 0 -> MacKey
    let mackey = aes_cmac(&t, &m);
    m[0] = 1; // Counter = 1 -> LTK
    let ltk = aes_cmac(&t, &m);
    (mackey, ltk)
}

/// `f6(W, N1, N2, R, IOcap, A1, A2)` (Vol 3, Part H §2.2.8) — the `DHKey`
/// Check function.
///
/// - `w` — `MacKey` (the [`f5`] output, not the raw `DHKey`).
/// - `n1`, `n2` — the committing device's own nonce, then the peer's.
/// - `r` — all-zero for Just Works / Numeric Comparison (the Passkey Entry
///   value is not implemented — see module docs).
/// - `io_cap` — `[AuthReq, OOB_data_flag, IO_Capability]` of the device
///   that owns `n1`, in that field order (Vol 3, Part H §2.2.8 — NOT wire
///   order; see [`super::pdu::io_cap_for_check`]).
/// - `a1`, `a2` — identity address of the device that owns `n1`, then the
///   other device's, each `[address_type] || [6-byte address, MSB first]`.
pub(crate) fn f6(
    w: &[u8; 16],
    n1: &[u8; 16],
    n2: &[u8; 16],
    r: &[u8; 16],
    io_cap: &[u8; 3],
    a1: &[u8; 7],
    a2: &[u8; 7],
) -> [u8; 16] {
    let mut m = [0u8; 65];
    m[0..16].copy_from_slice(n1);
    m[16..32].copy_from_slice(n2);
    m[32..48].copy_from_slice(r);
    m[48..51].copy_from_slice(io_cap);
    m[51..58].copy_from_slice(a1);
    m[58..65].copy_from_slice(a2);
    aes_cmac(w, &m)
}

/// `g2(U, V, X, Y) = AES-CMAC_X(U || V || Y) mod 2^32` (Vol 3, Part H
/// §2.2.9), further reduced `mod 1000000` for display — the Numeric
/// Comparison value function.
///
/// Not called by the Just Works flow this module implements ([`super`]
/// docs); included and verified because it shares `f4`'s message-layout
/// convention closely enough that a future Numeric Comparison IO
/// capability can reuse it directly.
// WHY: same rationale as `f4` — U/V/X/Y match the spec's own notation.
#[allow(clippy::many_single_char_names)]
pub(crate) fn g2(u: &[u8; 32], v: &[u8; 32], x: &[u8; 16], y: &[u8; 16]) -> u32 {
    let mut m = [0u8; 80];
    m[0..32].copy_from_slice(u);
    m[32..64].copy_from_slice(v);
    m[64..80].copy_from_slice(y);
    let mac = aes_cmac(x, &m);
    // WHY: "the least significant 32 bits of the AES-CMAC output" — in
    // this module's big-endian-display convention that's the trailing 4
    // bytes, read as a standard big-endian u32 (verified against Linux's
    // `test_g2` vector, which frames the same fact the other way around:
    // its LE-native output's *first* 4 bytes read as a little-endian u32).
    u32::from_be_bytes([mac[12], mac[13], mac[14], mac[15]]) % 1_000_000
}

// ── ECDH P-256 key agreement ────────────────────────────────────────────────────

/// Bridges a caller-injected entropy closure to the `rand_core` traits
/// `p256`'s key generation needs.
///
/// Mirrors [`super::Irk::generate`]'s pattern — pteron has no CSPRNG of
/// its own, so every draw is delegated to the caller (the kernel's
/// `ChaCha20` CSPRNG in production, a deterministic injected stream in
/// tests) — generalised from `Irk::generate`'s single fixed-size `FnOnce`
/// call to a repeatable `FnMut` because ECDH key generation and nonce
/// generation each draw independently over one [`super::pairing`] session.
struct InjectedRng<'a>(&'a mut dyn FnMut(&mut [u8]));

impl TryRng for InjectedRng<'_> {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut buf = [0u8; 4];
        (self.0)(&mut buf);
        Ok(u32::from_le_bytes(buf))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut buf = [0u8; 8];
        (self.0)(&mut buf);
        Ok(u64::from_le_bytes(buf))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        (self.0)(dst);
        Ok(())
    }
}

impl TryCryptoRng for InjectedRng<'_> {}

/// An ECDH P-256 ephemeral key pair for one pairing session's Phase 2
/// public-key exchange (Vol 3, Part H §2.3.5.6).
pub(crate) struct EcdhKeyPair {
    secret: p256::ecdh::EphemeralSecret,
    x: [u8; 32],
    y: [u8; 32],
}

/// A validated peer public key plus the `DHKey` computed against it.
pub(crate) struct DhKey {
    /// The peer's public key x-coordinate — `U`/`V` input to [`f4`]/[`f5`].
    pub(crate) peer_x: [u8; 32],
    /// The raw Diffie-Hellman shared secret x-coordinate — `W` input to
    /// [`f5`].
    pub(crate) shared: [u8; 32],
}

impl EcdhKeyPair {
    /// Generate a fresh ephemeral key pair using caller-supplied entropy.
    pub(crate) fn generate(random: &mut dyn FnMut(&mut [u8])) -> Self {
        let mut rng = InjectedRng(random);
        let secret = p256::ecdh::EphemeralSecret::generate_from_rng(&mut rng);
        let public = secret.public_key();
        let x = field_bytes(public.as_affine().x());
        let y = field_bytes(public.as_affine().y());
        Self { secret, x, y }
    }

    /// This key pair's public x-coordinate — big-endian display order,
    /// the `U`/`V` input to [`f4`]/[`f5`]/[`g2`] and (byte-reversed) the
    /// wire `x` field of the Pairing Public Key PDU.
    pub(crate) const fn public_x(&self) -> &[u8; 32] {
        &self.x
    }

    /// This key pair's public y-coordinate — big-endian display order,
    /// the (byte-reversed) wire `y` field of the Pairing Public Key PDU.
    pub(crate) const fn public_y(&self) -> &[u8; 32] {
        &self.y
    }

    /// Validate a peer's public key (`x`, `y`, both big-endian display
    /// order) and compute the `DHKey` against it.
    ///
    /// Rejects a point that is not on the P-256 curve, the point at
    /// infinity, or (Vol 3, Part H §2.3.5.6.1: "the device shall check
    /// that the received public key is not the same as the local public
    /// key") a peer echoing this device's own public key back — accepting
    /// either would let an attacker force a predictable or otherwise
    /// invalid shared secret before any trust exists.
    pub(crate) fn agree(&self, peer_x: &[u8; 32], peer_y: &[u8; 32]) -> Option<DhKey> {
        if peer_x == &self.x && peer_y == &self.y {
            return None;
        }
        let mut sec1 = [0u8; 65];
        sec1[0] = 0x04; // SEC1 uncompressed-point tag.
        sec1[1..33].copy_from_slice(peer_x);
        sec1[33..65].copy_from_slice(peer_y);
        let peer_public = p256::PublicKey::from_sec1_bytes(&sec1).ok()?;
        let shared = self.secret.diffie_hellman(&peer_public);
        Some(DhKey {
            peer_x: *peer_x,
            shared: field_bytes(shared.raw_secret_bytes()),
        })
    }
}

/// Copy a `p256` field-element byte slice (always exactly 32 bytes for
/// P-256) into an owned array.
fn field_bytes(repr: impl AsRef<[u8]>) -> [u8; 32] {
    let mut out = [0u8; 32];
    let src = repr.as_ref();
    // INVARIANT: every P-256 field element (coordinates, shared secret) is
    // exactly 32 bytes — a mismatch here would mean `p256` changed its
    // field size, not an attacker-controlled condition.
    debug_assert_eq!(src.len(), 32, "P-256 field element must be 32 bytes");
    let n = src.len().min(32);
    out[..n].copy_from_slice(&src[..n]);
    out
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Reverse a fixed-size byte array — the mechanical transform this
    /// module's tests use to translate Linux's LSB-first self-test
    /// vectors into this module's MSB-first (spec-display) convention.
    /// See module docs: Linux's `smp_aes_cmac` does exactly this swap
    /// (`swap_buf`) before calling a standard CMAC.
    fn rev<const N: usize>(mut a: [u8; N]) -> [u8; N] {
        a.reverse();
        a
    }

    // ── f4 (Linux net/bluetooth/smp.c test_f4) ──

    #[test]
    fn f4_matches_linux_self_test_vector() {
        let u = rev([
            0xe6, 0x9d, 0x35, 0x0e, 0x48, 0x01, 0x03, 0xcc, 0xdb, 0xfd, 0xf4, 0xac, 0x11, 0x91,
            0xf4, 0xef, 0xb9, 0xa5, 0xf9, 0xe9, 0xa7, 0x83, 0x2c, 0x5e, 0x2c, 0xbe, 0x97, 0xf2,
            0xd2, 0x03, 0xb0, 0x20,
        ]);
        let v = rev([
            0xfd, 0xc5, 0x7f, 0xf4, 0x49, 0xdd, 0x4f, 0x6b, 0xfb, 0x7c, 0x9d, 0xf1, 0xc2, 0x9a,
            0xcb, 0x59, 0x2a, 0xe7, 0xd4, 0xee, 0xfb, 0xfc, 0x0a, 0x90, 0x9a, 0xbb, 0xf6, 0x32,
            0x3d, 0x8b, 0x18, 0x55,
        ]);
        let x = rev([
            0xab, 0xae, 0x2b, 0x71, 0xec, 0xb2, 0xff, 0xff, 0x3e, 0x73, 0x77, 0xd1, 0x54, 0x84,
            0xcb, 0xd5,
        ]);
        let z = 0x00;
        let expected = rev([
            0x2d, 0x87, 0x74, 0xa9, 0xbe, 0xa1, 0xed, 0xf1, 0x1c, 0xbd, 0xa9, 0x07, 0xf1, 0x16,
            0xc9, 0xf2,
        ]);
        assert_eq!(f4(&u, &v, &x, z), expected);
    }

    // ── f5 (Linux net/bluetooth/smp.c test_f5) ──

    #[test]
    fn f5_matches_linux_self_test_vector() {
        let w = rev([
            0x98, 0xa6, 0xbf, 0x73, 0xf3, 0x34, 0x8d, 0x86, 0xf1, 0x66, 0xf8, 0xb4, 0x13, 0x6b,
            0x79, 0x99, 0x9b, 0x7d, 0x39, 0x0a, 0xa6, 0x10, 0x10, 0x34, 0x05, 0xad, 0xc8, 0x57,
            0xa3, 0x34, 0x02, 0xec,
        ]);
        let n1 = rev([
            0xab, 0xae, 0x2b, 0x71, 0xec, 0xb2, 0xff, 0xff, 0x3e, 0x73, 0x77, 0xd1, 0x54, 0x84,
            0xcb, 0xd5,
        ]);
        let n2 = rev([
            0xcf, 0xc4, 0x3d, 0xff, 0xf7, 0x83, 0x65, 0x21, 0x6e, 0x5f, 0xa7, 0x25, 0xcc, 0xe7,
            0xe8, 0xa6,
        ]);
        let a1 = rev([0xce, 0xbf, 0x37, 0x37, 0x12, 0x56, 0x00]);
        let a2 = rev([0xc1, 0xcf, 0x2d, 0x70, 0x13, 0xa7, 0x00]);
        let expected_ltk = rev([
            0x38, 0x0a, 0x75, 0x94, 0xb5, 0x22, 0x05, 0x98, 0x23, 0xcd, 0xd7, 0x69, 0x11, 0x79,
            0x86, 0x69,
        ]);
        let expected_mackey = rev([
            0x20, 0x6e, 0x63, 0xce, 0x20, 0x6a, 0x3f, 0xfd, 0x02, 0x4a, 0x08, 0xa1, 0x76, 0xf1,
            0x65, 0x29,
        ]);

        let (mackey, ltk) = f5(&w, &n1, &n2, &a1, &a2);
        assert_eq!(mackey, expected_mackey, "MacKey (Counter=0) mismatch");
        assert_eq!(ltk, expected_ltk, "LTK (Counter=1) mismatch");
    }

    // ── f6 (Linux net/bluetooth/smp.c test_f6) ──

    #[test]
    fn f6_matches_linux_self_test_vector() {
        let w = rev([
            0x20, 0x6e, 0x63, 0xce, 0x20, 0x6a, 0x3f, 0xfd, 0x02, 0x4a, 0x08, 0xa1, 0x76, 0xf1,
            0x65, 0x29,
        ]);
        let n1 = rev([
            0xab, 0xae, 0x2b, 0x71, 0xec, 0xb2, 0xff, 0xff, 0x3e, 0x73, 0x77, 0xd1, 0x54, 0x84,
            0xcb, 0xd5,
        ]);
        let n2 = rev([
            0xcf, 0xc4, 0x3d, 0xff, 0xf7, 0x83, 0x65, 0x21, 0x6e, 0x5f, 0xa7, 0x25, 0xcc, 0xe7,
            0xe8, 0xa6,
        ]);
        let r = rev([
            0xc8, 0x0f, 0x2d, 0x0c, 0xd2, 0x42, 0xda, 0x08, 0x54, 0xbb, 0x53, 0xb4, 0x3b, 0x34,
            0xa3, 0x12,
        ]);
        let io_cap = rev([0x02, 0x01, 0x01]);
        let a1 = rev([0xce, 0xbf, 0x37, 0x37, 0x12, 0x56, 0x00]);
        let a2 = rev([0xc1, 0xcf, 0x2d, 0x70, 0x13, 0xa7, 0x00]);
        let expected = rev([
            0x61, 0x8f, 0x95, 0xda, 0x09, 0x0b, 0x6c, 0xd2, 0xc5, 0xe8, 0xd0, 0x9c, 0x98, 0x73,
            0xc4, 0xe3,
        ]);

        assert_eq!(f6(&w, &n1, &n2, &r, &io_cap, &a1, &a2), expected);
    }

    // ── g2 (Linux net/bluetooth/smp.c test_g2) ──

    #[test]
    fn g2_matches_linux_self_test_vector() {
        let u = rev([
            0xe6, 0x9d, 0x35, 0x0e, 0x48, 0x01, 0x03, 0xcc, 0xdb, 0xfd, 0xf4, 0xac, 0x11, 0x91,
            0xf4, 0xef, 0xb9, 0xa5, 0xf9, 0xe9, 0xa7, 0x83, 0x2c, 0x5e, 0x2c, 0xbe, 0x97, 0xf2,
            0xd2, 0x03, 0xb0, 0x20,
        ]);
        let v = rev([
            0xfd, 0xc5, 0x7f, 0xf4, 0x49, 0xdd, 0x4f, 0x6b, 0xfb, 0x7c, 0x9d, 0xf1, 0xc2, 0x9a,
            0xcb, 0x59, 0x2a, 0xe7, 0xd4, 0xee, 0xfb, 0xfc, 0x0a, 0x90, 0x9a, 0xbb, 0xf6, 0x32,
            0x3d, 0x8b, 0x18, 0x55,
        ]);
        let x = rev([
            0xab, 0xae, 0x2b, 0x71, 0xec, 0xb2, 0xff, 0xff, 0x3e, 0x73, 0x77, 0xd1, 0x54, 0x84,
            0xcb, 0xd5,
        ]);
        let y = rev([
            0xcf, 0xc4, 0x3d, 0xff, 0xf7, 0x83, 0x65, 0x21, 0x6e, 0x5f, 0xa7, 0x25, 0xcc, 0xe7,
            0xe8, 0xa6,
        ]);
        // Linux: `*val = get_unaligned_le32(tmp); *val %= 1000000;` on the
        // raw 0x2f9ed5ba CMAC-derived value — no byte-order translation
        // needed for this comparison since it's already the final decimal
        // result, independent of display convention.
        assert_eq!(g2(&u, &v, &x, &y), 0x2f9e_d5ba_u32 % 1_000_000);
    }

    // ── f4 -> f5 -> f6 chain (the same Linux vectors chain: f5's mackey
    //    output is f6's test `w` input, cross-checking that both
    //    functions agree on ONE coherent simulated pairing session) ──

    #[test]
    fn f5_mackey_output_feeds_f6_test_vector_directly() {
        let w = rev([
            0x98, 0xa6, 0xbf, 0x73, 0xf3, 0x34, 0x8d, 0x86, 0xf1, 0x66, 0xf8, 0xb4, 0x13, 0x6b,
            0x79, 0x99, 0x9b, 0x7d, 0x39, 0x0a, 0xa6, 0x10, 0x10, 0x34, 0x05, 0xad, 0xc8, 0x57,
            0xa3, 0x34, 0x02, 0xec,
        ]);
        let n1 = rev([
            0xab, 0xae, 0x2b, 0x71, 0xec, 0xb2, 0xff, 0xff, 0x3e, 0x73, 0x77, 0xd1, 0x54, 0x84,
            0xcb, 0xd5,
        ]);
        let n2 = rev([
            0xcf, 0xc4, 0x3d, 0xff, 0xf7, 0x83, 0x65, 0x21, 0x6e, 0x5f, 0xa7, 0x25, 0xcc, 0xe7,
            0xe8, 0xa6,
        ]);
        let a1 = rev([0xce, 0xbf, 0x37, 0x37, 0x12, 0x56, 0x00]);
        let a2 = rev([0xc1, 0xcf, 0x2d, 0x70, 0x13, 0xa7, 0x00]);

        let (mackey, _ltk) = f5(&w, &n1, &n2, &a1, &a2);

        let r = rev([
            0xc8, 0x0f, 0x2d, 0x0c, 0xd2, 0x42, 0xda, 0x08, 0x54, 0xbb, 0x53, 0xb4, 0x3b, 0x34,
            0xa3, 0x12,
        ]);
        let io_cap = rev([0x02, 0x01, 0x01]);
        let expected_f6 = rev([
            0x61, 0x8f, 0x95, 0xda, 0x09, 0x0b, 0x6c, 0xd2, 0xc5, 0xe8, 0xd0, 0x9c, 0x98, 0x73,
            0xc4, 0xe3,
        ]);
        assert_eq!(
            f6(&mackey, &n1, &n2, &r, &io_cap, &a1, &a2),
            expected_f6,
            "f5's MacKey output must chain directly into f6's independently-verified vector"
        );
    }

    // ── ECDH sanity (no published fixed vector — p256 itself is the
    //    trusted, independently-audited primitive here; this checks OUR
    //    wiring, not the curve arithmetic) ──

    fn fixed_stream(seed: u8) -> impl FnMut(&mut [u8]) {
        let mut counter = seed;
        move |buf: &mut [u8]| {
            for b in buf.iter_mut() {
                *b = counter;
                counter = counter.wrapping_add(1);
            }
        }
    }

    #[test]
    fn ecdh_two_parties_agree_on_the_same_dhkey() {
        let mut a_stream = fixed_stream(0x01);
        let a = EcdhKeyPair::generate(&mut a_stream);
        let mut b_stream = fixed_stream(0x81);
        let b = EcdhKeyPair::generate(&mut b_stream);

        let Some(a_side) = a.agree(b.public_x(), b.public_y()) else {
            unreachable!("two distinct freshly-generated key pairs must agree");
        };
        let Some(b_side) = b.agree(a.public_x(), a.public_y()) else {
            unreachable!("two distinct freshly-generated key pairs must agree");
        };
        assert_eq!(
            a_side.shared, b_side.shared,
            "both parties must derive the identical DHKey"
        );
    }

    #[test]
    fn ecdh_rejects_peer_echoing_our_own_public_key() {
        let mut stream = fixed_stream(0x01);
        let a = EcdhKeyPair::generate(&mut stream);
        assert!(
            a.agree(a.public_x(), a.public_y()).is_none(),
            "a peer key equal to our own must be rejected (Vol 3 Part H §2.3.5.6.1)"
        );
    }

    #[test]
    fn ecdh_rejects_a_point_not_on_the_curve() {
        let mut stream = fixed_stream(0x01);
        let a = EcdhKeyPair::generate(&mut stream);
        // All-zero is not a valid P-256 affine point (fails the curve
        // equation) and is not equal to `a`'s own key, so this exercises
        // curve-membership rejection specifically.
        let bogus_x = [0u8; 32];
        let bogus_y = [0u8; 32];
        assert!(
            a.agree(&bogus_x, &bogus_y).is_none(),
            "a point not on the P-256 curve must be rejected, not silently accepted"
        );
    }
}
