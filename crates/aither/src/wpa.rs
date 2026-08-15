//! WPA2/WPA3 key derivation and MIC computation.
//!
//! Implements:
//! - PMK derivation via PBKDF2-HMAC-SHA1 (IEEE 802.11-2020, section 12.4.4.3.1)
//! - PTK derivation via PRF-384 (IEEE 802.11-2020, section 12.7.1.2)
//! - MIC computation via HMAC-SHA1 truncated to 128 bits
//! - the 4-way handshake state machine
//!
//! The derivation, MIC, replay-counter enforcement, and handshake logic
//! live in [`aither_core::wpa`], shared with the thumos kernel (#545, #819)
//! so the two cannot drift; this module re-exports them directly. The one
//! exception is [`derive_ptk`] below, which adapts `aither_core`'s
//! by-reference `aa`/`spa` to this crate's established by-value public
//! signature (`fuzz_wpa` and `mac.rs` both call it this way).

pub use aither_core::wpa::{
    HandshakeState, KCK_LEN, KEK_LEN, PMK_LEN, PTK_LEN, Ptk, Supplicant4WaySession, TK_LEN,
    WpaHandshake, compute_mic, derive_pmk, prf_384, verify_mic,
};

/// Derive the Pairwise Transient Key using PRF-384.
///
/// Implements IEEE 802.11-2020 section 12.7.1.2:
/// ```text
/// PTK = PRF-384(PMK, "Pairwise key expansion",
///               min(AA,SPA) || max(AA,SPA) || min(ANonce,SNonce) || max(ANonce,SNonce))
/// ```
///
/// # Arguments
/// * `pmk` -- 32-byte Pairwise Master Key.
/// * `anonce` -- Authenticator nonce (from message 1 of the 4-way handshake).
/// * `snonce` -- Supplicant nonce (from message 2 of the 4-way handshake).
/// * `aa` -- Authenticator MAC address.
/// * `spa` -- Supplicant MAC address.
#[must_use]
pub fn derive_ptk(
    pmk: &[u8; PMK_LEN],
    anonce: &[u8; 32],
    snonce: &[u8; 32],
    aa: [u8; 6],
    spa: [u8; 6],
) -> Ptk {
    aither_core::wpa::derive_ptk(pmk, anonce, snonce, &aa, &spa)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eapol::{DESCRIPTOR_TYPE_RSN, EapolKeyFrame, IV_LEN, KeyInfo, MIC_LEN, NONCE_LEN};

    /// IEEE 802.11i Annex J test vector -- PBKDF2(HMAC-SHA1, "password", "IEEE", 4096, 32).
    const IEEE_PMK: [u8; 32] = [
        0xf4, 0x2c, 0x6f, 0xc5, 0x2d, 0xf0, 0xeb, 0xef, 0x9e, 0xbb, 0x4b, 0x90, 0xb3, 0x8a, 0x5f,
        0x90, 0x2e, 0x83, 0xfe, 0x1b, 0x13, 0x5a, 0x70, 0xe2, 0x3a, 0xed, 0x76, 0x2e, 0x97, 0x10,
        0xa1, 0x2e,
    ];

    // WHY: adapter-boundary coverage only -- `aither_core::wpa` carries the
    // exhaustive derivation/MIC/handshake test suite, including the IEEE
    // Annex J and Annex H.7.1 vectors. This confirms the re-export resolves
    // to a working implementation and that this crate's by-value
    // `derive_ptk` wrapper matches the by-reference core function it wraps.
    #[test]
    fn pmk_matches_ieee_test_vector() {
        let pmk = derive_pmk(b"password", b"IEEE");
        assert_eq!(pmk, IEEE_PMK, "PMK must match IEEE 802.11i Annex J vector");
    }

    #[test]
    fn derive_ptk_by_value_wrapper_matches_by_reference_core_call() {
        let pmk = IEEE_PMK;
        let anonce = [0x10u8; 32];
        let snonce = [0x20u8; 32];
        let aa = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let spa = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];

        let via_wrapper = derive_ptk(&pmk, &anonce, &snonce, aa, spa);
        let via_core = aither_core::wpa::derive_ptk(&pmk, &anonce, &snonce, &aa, &spa);
        assert_eq!(
            via_wrapper, via_core,
            "this crate's by-value derive_ptk must produce the same PTK as the core's \
             by-reference function it wraps"
        );
    }

    #[test]
    fn mic_computation_is_deterministic() {
        let kck = [0x37u8; KCK_LEN];
        let data = b"test EAPOL frame with MIC field zeroed";
        assert_eq!(
            compute_mic(&kck, data),
            compute_mic(&kck, data),
            "MIC must be identical for identical inputs"
        );
    }

    #[test]
    fn verify_mic_round_trips() {
        let kck = [0x42u8; KCK_LEN];
        let data = b"EAPOL message 2 of 4-way handshake";
        let mic = compute_mic(&kck, data);
        assert!(
            verify_mic(&kck, data, &mic),
            "verify_mic must accept a freshly computed MIC"
        );
    }

    // --- Supplicant4WaySession replay-counter enforcement ---

    fn make_key_frame(replay_counter: u64) -> EapolKeyFrame {
        EapolKeyFrame {
            descriptor_type: DESCRIPTOR_TYPE_RSN,
            key_info: KeyInfo(0x008a),
            key_length: 16,
            replay_counter,
            nonce: [0u8; NONCE_LEN],
            iv: [0u8; IV_LEN],
            rsc: 0,
            mic: [0u8; MIC_LEN],
            key_data: Vec::new(),
        }
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
    fn handshake_starts_awaiting_msg1() {
        let hs = WpaHandshake::new();
        assert_eq!(
            hs.state(),
            HandshakeState::AwaitMsg1,
            "initial handshake state must be AwaitMsg1"
        );
    }
}
