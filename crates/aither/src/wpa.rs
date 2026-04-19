//! WPA2/WPA3 key derivation and MIC computation.
//!
//! Implements:
//! - PMK derivation via PBKDF2-HMAC-SHA1 (IEEE 802.11-2020, section 12.4.4.3.1)
//! - PTK derivation via PRF-384 (IEEE 802.11-2020, section 12.7.1.2)
//! - MIC computation via HMAC-SHA1 truncated to 128 bits

use std::num::NonZeroU32;

use ring::{hmac, pbkdf2};

/// PBKDF2 iteration count for PSK derivation (IEEE 802.11-2020 fixed value).
///
/// Computed as `NonZeroU32::MIN(1).saturating_add(4095)` to avoid unsafe or unwrap.
const PBKDF2_ITERS: NonZeroU32 = NonZeroU32::MIN.saturating_add(4095);

/// PMK/PSK output length in bytes.
pub const PMK_LEN: usize = 32;

/// Key Confirmation Key length in bytes.
pub const KCK_LEN: usize = 16;

/// Key Encryption Key length in bytes.
pub const KEK_LEN: usize = 16;

/// Temporal Key length in bytes (WPA2-CCMP).
pub const TK_LEN: usize = 16;

/// Total PTK length: KCK + KEK + TK (WPA2-CCMP, 384 bits).
pub const PTK_LEN: usize = KCK_LEN + KEK_LEN + TK_LEN;

/// MIC length in bytes.
pub const MIC_LEN: usize = 16;

/// Pairwise Transient Key components.
///
/// Derived FROM the PMK by PTK = PRF-384(PMK, "Pairwise key expansion", …).
///
/// Implements [`Drop`] to zero key material, preventing it from persisting
/// in memory after use. Uses `write_volatile` to prevent the compiler from
/// optimizing away the zeroing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ptk {
    /// Key Confirmation Key: used to compute and verify MIC.
    pub kck: [u8; KCK_LEN],
    /// Key Encryption Key: used to wrap the GTK with AES-KEYWRAP.
    pub kek: [u8; KEK_LEN],
    /// Temporal Key: used for data frame encryption (AES-CCMP).
    pub tk: [u8; TK_LEN],
}

impl Drop for Ptk {
    // WHY: write_volatile is the only way to prevent the compiler from
    // eliding zeroing as a dead store. This is a security requirement for
    // key material cleanup. The unsafe blocks access only valid mutable
    // references to initialized memory within the struct.
    #[expect(
        unsafe_code,
        reason = "volatile writes prevent the compiler from eliding zeroing as dead store"
    )]
    fn drop(&mut self) {
        for byte in &mut self.kck {
            // SAFETY: byte is a valid mutable reference to initialized memory.
            unsafe {
                std::ptr::write_volatile(byte, 0);
            }
        }
        for byte in &mut self.kek {
            // SAFETY: byte is a valid mutable reference to initialized memory.
            unsafe {
                std::ptr::write_volatile(byte, 0);
            }
        }
        for byte in &mut self.tk {
            // SAFETY: byte is a valid mutable reference to initialized memory.
            unsafe {
                std::ptr::write_volatile(byte, 0);
            }
        }
    }
}

/// Derive the Pairwise Master Key FROM a passphrase and SSID.
///
/// Uses PBKDF2-HMAC-SHA1 with 4096 iterations and a 32-byte output as
/// specified in IEEE 802.11-2020, section 12.4.4.3.1.
///
/// # Arguments
/// * `passphrase` – UTF-8 encoded network password.
/// * `ssid` – network SSID used as the PBKDF2 salt.
#[must_use]
pub fn derive_pmk(passphrase: &[u8], ssid: &[u8]) -> [u8; PMK_LEN] {
    let mut pmk = [0u8; PMK_LEN];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA1,
        PBKDF2_ITERS,
        ssid,       // salt
        passphrase, // secret
        &mut pmk,
    );
    pmk
}

/// Derive the Pairwise Transient Key using PRF-384.
///
/// Implements IEEE 802.11-2020 section 12.7.1.2:
/// ```text
/// PTK = PRF-384(PMK, "Pairwise key expansion",
///               min(AA,SPA) || max(AA,SPA) || min(ANonce,SNonce) || max(ANonce,SNonce))
/// ```
///
/// # Arguments
/// * `pmk` – 32-byte Pairwise Master Key.
/// * `anonce` – Authenticator nonce (FROM message 1 of 4-way handshake).
/// * `snonce` – Supplicant nonce (FROM message 2 of 4-way handshake).
/// * `aa` – Authenticator MAC address.
/// * `spa` – Supplicant MAC address.
#[must_use]
pub fn derive_ptk(
    pmk: &[u8; PMK_LEN],
    anonce: &[u8; 32],
    snonce: &[u8; 32],
    aa: &[u8; 6],
    spa: &[u8; 6],
) -> Ptk {
    const LABEL: &[u8] = b"Pairwise key expansion";

    // Sort MAC addresses and nonces for canonical ordering.
    let (mac_lo, mac_hi) = if aa <= spa { (aa, spa) } else { (spa, aa) };
    let (nonce_lo, nonce_hi) = if anonce <= snonce {
        (anonce, snonce)
    } else {
        (snonce, anonce)
    };

    // Build B = min(MAC)||max(MAC)||min(Nonce)||max(Nonce); prepend label.
    let mut input = Vec::with_capacity(LABEL.len() + 1 + 6 + 6 + 32 + 32);
    input.extend_from_slice(LABEL);
    input.push(0x00); // NUL separator between A and B in PRF
    input.extend_from_slice(mac_lo);
    input.extend_from_slice(mac_hi);
    input.extend_from_slice(nonce_lo);
    input.extend_from_slice(nonce_hi);

    let mut raw = [0u8; PTK_LEN];
    prf(pmk, &input, &mut raw);

    let mut kck = [0u8; KCK_LEN];
    let mut kek = [0u8; KEK_LEN];
    let mut tk = [0u8; TK_LEN];

    kck.copy_from_slice(&raw[..KCK_LEN]);
    kek.copy_from_slice(&raw[KCK_LEN..KCK_LEN + KEK_LEN]);
    tk.copy_from_slice(&raw[KCK_LEN + KEK_LEN..]);

    Ptk { kck, kek, tk }
}

/// Compute a 16-byte MIC using HMAC-SHA1 truncated to 128 bits.
///
/// Used to authenticate EAPOL-Key frames during the 4-way handshake (messages
/// 2, 3, and 4).  The MIC field in the EAPOL frame must be zeroed before
/// passing `data` to this function.
#[must_use]
pub fn compute_mic(kck: &[u8; KCK_LEN], data: &[u8]) -> [u8; MIC_LEN] {
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, kck);
    let tag = hmac::sign(&key, data);
    let bytes = tag.as_ref();
    let mut mic = [0u8; MIC_LEN];
    // HMAC-SHA1 produces 20 bytes; we take the first 16 (128 bits).
    mic.copy_from_slice(&bytes[..MIC_LEN]);
    mic
}

/// Verify that `expected_mic` matches the MIC computed over `data` with `kck`.
///
/// Uses constant-time comparison to prevent timing side-channel attacks.
/// Returns `true` only when the MIC is correct.
#[must_use]
pub fn verify_mic(kck: &[u8; KCK_LEN], data: &[u8], expected_mic: &[u8; MIC_LEN]) -> bool {
    let computed = compute_mic(kck, data);
    constant_time_eq(&computed, expected_mic)
}

/// Constant-time byte slice comparison.
///
/// Compares all bytes regardless of early differences, preventing timing
/// side-channel attacks that could leak information about secret key material.
/// Returns `true` only when both slices have equal length and identical content.
#[must_use]
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// WPA2 PRF function  -  HMAC-SHA1 counter construction.
///
/// Implements: `PRF(K, A||0x00||B, Len) = HMAC-SHA1(K, A||0x00||B||i)` for i = 0,1,…
/// until `output.len()` bytes have been produced.
///
/// `input` must already be the concatenation `A || 0x00 || B`; the counter
/// byte `i` is appended per iteration.
fn prf(key: &[u8], input: &[u8], output: &mut [u8]) {
    let hmac_key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, key);
    let out_len = output.len();
    let mut pos = 0usize;
    let mut counter = 0u8;

    while pos < out_len {
        let mut msg = Vec::with_capacity(input.len() + 1);
        msg.extend_from_slice(input);
        msg.push(counter);

        let tag = hmac::sign(&hmac_key, &msg);
        let tag_bytes = tag.as_ref();
        let copy_len = (out_len - pos).min(tag_bytes.len());
        output[pos..pos + copy_len].copy_from_slice(&tag_bytes[..copy_len]);
        pos += copy_len;
        counter = counter.wrapping_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// IEEE 802.11i Annex J test vector  -  PBKDF2(HMAC-SHA1, "password", "IEEE", 4096, 32).
    const IEEE_PMK: [u8; 32] = [
        0xf4, 0x2c, 0x6f, 0xc5, 0x2d, 0xf0, 0xeb, 0xef, 0x9e, 0xbb, 0x4b, 0x90, 0xb3, 0x8a, 0x5f,
        0x90, 0x2e, 0x83, 0xfe, 0x1b, 0x13, 0x5a, 0x70, 0xe2, 0x3a, 0xed, 0x76, 0x2e, 0x97, 0x10,
        0xa1, 0x2e,
    ];

    #[test]
    fn pmk_matches_ieee_test_vector() {
        let pmk = derive_pmk(b"password", b"IEEE");
        assert_eq!(pmk, IEEE_PMK, "PMK must match IEEE 802.11i Annex J vector");
    }

    #[test]
    fn pmk_derivation_is_deterministic() {
        let a = derive_pmk(b"secret", b"mynet");
        let b = derive_pmk(b"secret", b"mynet");
        assert_eq!(
            a, b,
            "PMK must be identical for identical passphrase and SSID"
        );
    }

    #[test]
    fn pmk_differs_when_passphrase_differs() {
        let a = derive_pmk(b"passA", b"ssid");
        let b = derive_pmk(b"passB", b"ssid");
        assert_ne!(a, b, "PMK must differ when passphrases differ");
    }

    #[test]
    fn ptk_fields_have_correct_lengths() {
        let pmk = [0u8; PMK_LEN];
        let anonce = [0xaau8; 32];
        let snonce = [0xbbu8; 32];
        let aa = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let spa = [0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb];
        let ptk = derive_ptk(&pmk, &anonce, &snonce, &aa, &spa);
        // Verify lengths via compile-time array sizes  -  just check fields exist.
        assert_eq!(ptk.kck.len(), KCK_LEN, "KCK must be KCK_LEN bytes");
        assert_eq!(ptk.kek.len(), KEK_LEN, "KEK must be KEK_LEN bytes");
        assert_eq!(ptk.tk.len(), TK_LEN, "TK must be TK_LEN bytes");
    }

    #[test]
    fn ptk_derivation_is_deterministic() {
        let pmk = IEEE_PMK;
        let anonce = [0x01u8; 32];
        let snonce = [0x02u8; 32];
        let aa = [0xa0, 0xc0, 0x89, 0x7f, 0x0c, 0xf0];
        let spa = [0x00, 0x0e, 0x35, 0x58, 0x10, 0xd2];
        let ptk1 = derive_ptk(&pmk, &anonce, &snonce, &aa, &spa);
        let ptk2 = derive_ptk(&pmk, &anonce, &snonce, &aa, &spa);
        assert_eq!(ptk1, ptk2, "PTK must be identical for identical inputs");
    }

    #[test]
    fn ptk_is_identical_when_aa_and_spa_are_swapped() {
        // PRF input is ORDER-independent: swapping AA/SPA gives the same PTK.
        let pmk = IEEE_PMK;
        let anonce = [0x10u8; 32];
        let snonce = [0x20u8; 32];
        let aa = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let spa = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let ptk_ab = derive_ptk(&pmk, &anonce, &snonce, &aa, &spa);
        let ptk_ba = derive_ptk(&pmk, &anonce, &snonce, &spa, &aa);
        assert_eq!(
            ptk_ab, ptk_ba,
            "PTK must be identical regardless of AA/SPA order"
        );
    }

    #[test]
    fn mic_computation_is_deterministic() {
        let kck = [0x37u8; KCK_LEN];
        let data = b"test EAPOL frame with MIC field zeroed";
        let mic1 = compute_mic(&kck, data);
        let mic2 = compute_mic(&kck, data);
        assert_eq!(mic1, mic2, "MIC must be identical for identical inputs");
    }

    #[test]
    fn verify_mic_accepts_correct_mic() {
        let kck = [0x42u8; KCK_LEN];
        let data = b"EAPOL message 2 of 4-way handshake";
        let mic = compute_mic(&kck, data);
        assert!(
            verify_mic(&kck, data, &mic),
            "verify_mic must return true for a freshly computed MIC"
        );
    }

    #[test]
    fn verify_mic_rejects_tampered_data() {
        let kck = [0x42u8; KCK_LEN];
        let data = b"correct data";
        let mic = compute_mic(&kck, data);
        let tampered = b"tampered data";
        assert!(
            !verify_mic(&kck, tampered, &mic),
            "verify_mic must return false when data does not match MIC"
        );
    }

    #[test]
    fn verify_mic_rejects_corrupted_mic() {
        let kck = [0x42u8; KCK_LEN];
        let data = b"some EAPOL payload";
        let mut wrong_mic = compute_mic(&kck, data);
        wrong_mic[0] ^= 0xff; // flip a byte
        assert!(
            !verify_mic(&kck, data, &wrong_mic),
            "verify_mic must return false when MIC byte is flipped"
        );
    }

    #[test]
    fn mic_differs_when_kck_differs() {
        let kck_a = [0xaau8; KCK_LEN];
        let kck_b = [0xbbu8; KCK_LEN];
        let data = b"shared data";
        assert_ne!(
            compute_mic(&kck_a, data),
            compute_mic(&kck_b, data),
            "different KCKs must produce different MICs"
        );
    }
}
