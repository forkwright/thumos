//! WPA2/WPA3 key derivation and MIC computation.
//!
//! Implements:
//! - PMK derivation via PBKDF2-HMAC-SHA1 (IEEE 802.11-2020, section 12.4.4.3.1)
//! - PTK derivation via PRF-384 (IEEE 802.11-2020, section 12.7.1.2)
//! - MIC computation via HMAC-SHA1 truncated to 128 bits

use std::num::NonZeroU32;

// WHY: digest 0.11 removed `new_from_slice` from the `Mac` trait itself
// (it now lives solely on `KeyInit`, which `hmac` re-exports) -- `Mac`
// alone no longer brings the constructor into scope.
use hmac::{Hmac, KeyInit, Mac};
use pbkdf2::pbkdf2_hmac;
use sha1::Sha1;

use crate::eapol::EapolKeyFrame;

type HmacSha1 = Hmac<Sha1>;

/// PBKDF2 iteration count for PSK derivation (IEEE 802.11-2020 fixed value).
///
/// Computed as `NonZeroU32::MIN(1).saturating_add(4095)` to avoid unsafe or unwrap.
const PBKDF2_ITERS: NonZeroU32 = NonZeroU32::MIN.saturating_add(4095);

/// PMK/PSK output length in bytes.
pub(crate) const PMK_LEN: usize = 32;

/// Key Confirmation Key length in bytes.
pub(crate) const KCK_LEN: usize = 16;

/// Key Encryption Key length in bytes.
pub(crate) const KEK_LEN: usize = 16;

/// Temporal Key length in bytes (WPA2-CCMP).
pub(crate) const TK_LEN: usize = 16;

/// Total PTK length: KCK + KEK + TK (WPA2-CCMP, 384 bits).
pub(crate) const PTK_LEN: usize = KCK_LEN + KEK_LEN + TK_LEN;

/// MIC length in bytes.
pub(crate) const MIC_LEN: usize = 16;

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
    pbkdf2_hmac::<Sha1>(passphrase, ssid, PBKDF2_ITERS.get(), &mut pmk);
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
    aa: [u8; 6],
    spa: [u8; 6],
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
    input.extend_from_slice(&mac_lo);
    input.extend_from_slice(&mac_hi);
    input.extend_from_slice(nonce_lo);
    input.extend_from_slice(nonce_hi);

    let mut raw = [0u8; PTK_LEN];
    prf(pmk, &input, &mut raw);

    let kck = std::array::from_fn(|i| raw.get(i).copied().unwrap_or(0));
    let kek = std::array::from_fn(|i| raw.get(KCK_LEN + i).copied().unwrap_or(0));
    let tk = std::array::from_fn(|i| raw.get(KCK_LEN + KEK_LEN + i).copied().unwrap_or(0));

    Ptk { kck, kek, tk }
}

/// Compute a 16-byte MIC using HMAC-SHA1 truncated to 128 bits.
///
/// Used to authenticate EAPOL-Key frames during the 4-way handshake (messages
/// 2, 3, and 4).  The MIC field in the EAPOL frame must be zeroed before
/// passing `data` to this function.
#[must_use]
pub fn compute_mic(kck: &[u8; KCK_LEN], data: &[u8]) -> [u8; MIC_LEN] {
    let Ok(mut mac) = HmacSha1::new_from_slice(kck) else {
        return [0u8; MIC_LEN];
    };
    mac.update(data);
    let bytes = mac.finalize().into_bytes();
    // HMAC-SHA1 produces 20 bytes; we take the first 16 (128 bits).
    std::array::from_fn(|i| bytes.get(i).copied().unwrap_or(0))
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
    let out_len = output.len();
    let mut pos = 0usize;
    let mut counter = 0u8;

    while pos < out_len {
        let mut msg = Vec::with_capacity(input.len() + 1);
        msg.extend_from_slice(input);
        msg.push(counter);

        let Ok(mut mac) = HmacSha1::new_from_slice(key) else {
            return;
        };
        mac.update(&msg);
        let tag_bytes = mac.finalize().into_bytes();
        let copy_len = (out_len - pos).min(tag_bytes.len());
        for j in 0..copy_len {
            if let Some(out) = output.get_mut(pos + j) {
                *out = tag_bytes.get(j).copied().unwrap_or(0);
            }
        }
        pos += copy_len;
        counter = counter.wrapping_add(1);
    }
}

/// Tracks the EAPOL-Key replay counter across a WPA 4-way handshake
/// supplicant session.
///
/// IEEE 802.11-2020 §12.7.6.2 requires the supplicant reject any EAPOL-Key
/// frame whose replay counter does not strictly exceed the last accepted
/// value, closing the replay window a KRACK-class attack depends on.
/// `EapolKeyFrame::replay_counter` (see `crate::eapol`) is parsed from the
/// wire but was previously never checked against prior state anywhere in
/// this crate (audit #347); this session type is the enforcement point.
#[derive(Debug, Default)]
pub struct Supplicant4WaySession {
    last_replay_counter: Option<u64>,
}

impl Supplicant4WaySession {
    /// Create a session with no replay counter observed yet.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            last_replay_counter: None,
        }
    }

    /// Validate `frame`'s replay counter against the last accepted value.
    ///
    /// Returns `true` and records the counter when it is the first frame of
    /// the session or strictly exceeds the last accepted value. Returns
    /// `false` — without updating internal state — for a replayed or
    /// out-of-order counter; callers must drop the frame before processing
    /// any key material it carries.
    #[must_use]
    pub const fn accept(&mut self, frame: &EapolKeyFrame) -> bool {
        if let Some(last) = self.last_replay_counter
            && frame.replay_counter <= last
        {
            return false;
        }
        self.last_replay_counter = Some(frame.replay_counter);
        true
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
        let ptk = derive_ptk(&pmk, &anonce, &snonce, aa, spa);
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
        let ptk1 = derive_ptk(&pmk, &anonce, &snonce, aa, spa);
        let ptk2 = derive_ptk(&pmk, &anonce, &snonce, aa, spa);
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
        let ptk_ab = derive_ptk(&pmk, &anonce, &snonce, aa, spa);
        let ptk_ba = derive_ptk(&pmk, &anonce, &snonce, spa, aa);
        assert_eq!(
            ptk_ab, ptk_ba,
            "PTK must be identical regardless of AA/SPA order"
        );
    }

    /// IEEE Std 802.11i-2004, Table H.13 / Table H.15 (Annex H.7.1,
    /// "Pairwise key derivation") — the standard's own published PTK
    /// worked example. Note the published SNonce/ANonce are 20 bytes each
    /// (not the 32-byte EAPOL Key Nonce field), as printed in Table H.13;
    /// this test exercises the shared `prf` primitive directly with the
    /// literal published B-string rather than `derive_ptk`'s 32-byte-nonce
    /// typed wrapper, since 20-byte values cannot be passed through that
    /// signature without altering the vector.
    #[test]
    // WHY: expected_kck/expected_kek/expected_tk mirror the IEEE standard's
    // own KCK/KEK/TK terminology (Table H.15) — renaming would obscure the
    // cross-reference to the source table.
    #[allow(clippy::similar_names)]
    fn prf384_matches_ieee_802_11i_h7_1_vector() {
        let pmk: [u8; PMK_LEN] = [
            0x0d, 0xc0, 0xd6, 0xeb, 0x90, 0x55, 0x5e, 0xd6, 0x41, 0x97, 0x56, 0xb9, 0xa1, 0x5e,
            0xc3, 0xe3, 0x20, 0x9b, 0x63, 0xdf, 0x70, 0x7d, 0xd5, 0x08, 0xd1, 0x45, 0x81, 0xf8,
            0x98, 0x27, 0x21, 0xaf,
        ];
        let aa: [u8; 6] = [0xa0, 0xa1, 0xa1, 0xa3, 0xa4, 0xa5];
        let spa: [u8; 6] = [0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5];
        let snonce: [u8; 20] = [
            0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xd0, 0xd1, 0xd2, 0xd3,
            0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9,
        ];
        let anonce: [u8; 20] = [
            0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xf0, 0xf1, 0xf2, 0xf3,
            0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9,
        ];

        // B = Min(AA,SPA) || Max(AA,SPA) || Min(ANonce,SNonce) || Max(ANonce,SNonce)
        let (mac_lo, mac_hi) = if aa <= spa { (aa, spa) } else { (spa, aa) };
        let (nonce_lo, nonce_hi) = if anonce <= snonce {
            (anonce, snonce)
        } else {
            (snonce, anonce)
        };
        let mut input = Vec::with_capacity(23 + 1 + 6 + 6 + 20 + 20);
        input.extend_from_slice(b"Pairwise key expansion");
        input.push(0x00);
        input.extend_from_slice(&mac_lo);
        input.extend_from_slice(&mac_hi);
        input.extend_from_slice(&nonce_lo);
        input.extend_from_slice(&nonce_hi);

        let mut ptk = [0u8; PTK_LEN];
        prf(&pmk, &input, &mut ptk);

        let expected_kck: [u8; KCK_LEN] = [
            0xaa, 0x7c, 0xfc, 0x85, 0x60, 0x25, 0x1e, 0x4b, 0xc6, 0x87, 0xe0, 0xcb, 0x8d, 0x29,
            0x83, 0x63,
        ];
        let expected_kek: [u8; KEK_LEN] = [
            0xba, 0x53, 0x16, 0x3d, 0xf3, 0x2a, 0x86, 0x38, 0xf4, 0x79, 0xab, 0xe3, 0x4b, 0xfd,
            0x2b, 0xc8,
        ];
        let expected_tk: [u8; TK_LEN] = [
            0x8c, 0xb7, 0x78, 0x33, 0x2e, 0x94, 0xac, 0xa6, 0xd3, 0x0b, 0x89, 0xcb, 0xe8, 0x2a,
            0x9c, 0xa9,
        ];

        assert_eq!(
            &ptk[0..16],
            &expected_kck,
            "KCK must match IEEE 802.11i-2004 Table H.15"
        );
        assert_eq!(
            &ptk[16..32],
            &expected_kek,
            "KEK must match IEEE 802.11i-2004 Table H.15"
        );
        assert_eq!(
            &ptk[32..48],
            &expected_tk,
            "TK must match IEEE 802.11i-2004 Table H.15 / Table H.14"
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

    // --- Supplicant4WaySession replay-counter enforcement (audit #347) ---

    fn make_key_frame(replay_counter: u64) -> EapolKeyFrame {
        EapolKeyFrame {
            descriptor_type: crate::eapol::DESCRIPTOR_TYPE_RSN,
            key_info: crate::eapol::KeyInfo(0x008a),
            key_length: 16,
            replay_counter,
            nonce: [0u8; crate::eapol::NONCE_LEN],
            iv: [0u8; crate::eapol::IV_LEN],
            rsc: 0,
            mic: [0u8; crate::eapol::MIC_LEN],
            key_data: Vec::new(),
        }
    }

    #[test]
    fn supplicant_session_accepts_first_replay_counter() {
        let mut session = Supplicant4WaySession::new();
        assert!(
            session.accept(&make_key_frame(1)),
            "the first frame of a session must be accepted regardless of counter value"
        );
    }

    #[test]
    fn supplicant_session_accepts_strictly_increasing_counters() {
        let mut session = Supplicant4WaySession::new();
        assert!(
            session.accept(&make_key_frame(1)),
            "counter 1 must be accepted"
        );
        assert!(
            session.accept(&make_key_frame(2)),
            "counter 2 must be accepted"
        );
        assert!(
            session.accept(&make_key_frame(100)),
            "counter 100 must be accepted"
        );
    }

    #[test]
    fn supplicant_session_rejects_replayed_equal_counter() {
        let mut session = Supplicant4WaySession::new();
        assert!(
            session.accept(&make_key_frame(5)),
            "counter 5 must be accepted"
        );
        assert!(
            !session.accept(&make_key_frame(5)),
            "a replayed frame with an equal counter must be rejected"
        );
    }

    #[test]
    fn supplicant_session_rejects_lower_counter() {
        let mut session = Supplicant4WaySession::new();
        assert!(
            session.accept(&make_key_frame(10)),
            "counter 10 must be accepted"
        );
        assert!(
            !session.accept(&make_key_frame(3)),
            "a frame with a lower counter than previously seen must be rejected"
        );
    }

    #[test]
    fn supplicant_session_state_reflects_last_accepted_not_last_seen() {
        let mut session = Supplicant4WaySession::new();
        assert!(
            session.accept(&make_key_frame(10)),
            "counter 10 must be accepted"
        );
        assert!(
            !session.accept(&make_key_frame(10)),
            "replayed counter 10 must be rejected"
        );
        assert!(
            session.accept(&make_key_frame(11)),
            "state must reflect the last ACCEPTED counter, not the rejected one"
        );
    }
}
