//! Fuzz target: WPA2 4-way-handshake key derivation, MIC, and replay session.
//!
//! Exercises `aither::wpa` — the WiFi auth surface — with fuzz-driven PMK/PTK
//! derivations (determinism + canonical-order invariants), MIC round-trips,
//! and the replay-counter accept sequence (strictly-increasing acceptance,
//! replayed/out-of-order rejection without state corruption).
//!
//! # Running
//!
//! ```text
//! cargo fuzz run fuzz_wpa -- -max_total_time=60
//! cargo fuzz run fuzz_wpa corpus/fuzz_wpa -- -max_total_time=60
//! ```
#![no_main]
use libfuzzer_sys::fuzz_target;

use aither::eapol;
use aither::wpa::{self, Supplicant4WaySession};

fn take<'a>(data: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
    if data.len() < n {
        return None;
    }
    let (head, tail) = data.split_at(n);
    *data = tail;
    Some(head)
}

fuzz_target!(|data: &[u8]| {
    let mut cur = data;
    let Some(pass) = take(&mut cur, 16) else { return };
    let Some(ssid) = take(&mut cur, 8) else { return };
    let Some(anonce) = take(&mut cur, 32) else { return };
    let Some(snonce) = take(&mut cur, 32) else { return };
    let Some(aa_b) = take(&mut cur, 6) else { return };
    let Some(spa_b) = take(&mut cur, 6) else { return };

    // ── Phase 1: derivation determinism + canonical ordering ────────────────
    // PMK/PTK derivation must never panic and must be deterministic; PTK must
    // be invariant under swapping (aa, spa) with (anonce, snonce) — the
    // canonical ordering rule in the 4-way spec.
    let pmk = wpa::derive_pmk(pass, ssid);
    assert_eq!(pmk, wpa::derive_pmk(pass, ssid), "PMK derivation must be deterministic");
    let aa: [u8; 6] = aa_b.try_into().expect("slice length checked by take()"); // kanon:ignore RUST/expect -- length proven by take()
    let spa: [u8; 6] = spa_b.try_into().expect("slice length checked by take()"); // kanon:ignore RUST/expect -- length proven by take()
    let an: &[u8; 32] = anonce.try_into().expect("slice length checked by take()"); // kanon:ignore RUST/expect -- length proven by take()
    let sn: &[u8; 32] = snonce.try_into().expect("slice length checked by take()"); // kanon:ignore RUST/expect -- length proven by take()
    let ptk1 = wpa::derive_ptk(&pmk, an, sn, aa, spa);
    let ptk2 = wpa::derive_ptk(&pmk, sn, an, spa, aa);
    assert_eq!(ptk1.kck, ptk2.kck, "PTK must be invariant under peer/nonce swap (canonical ordering)");

    // ── Phase 2: MIC round-trip ──────────────────────────────────────────────
    // verify_mic must accept a MIC computed over the same bytes and reject a
    // MIC computed over different bytes.
    if !cur.is_empty() {
        let kck = &ptk1.kck;
        let mic = wpa::compute_mic(kck, cur);
        assert!(wpa::verify_mic(kck, cur, &mic), "MIC must verify over the same bytes");
        let mut other = cur.to_vec();
        other[0] ^= 0xff;
        assert!(!wpa::verify_mic(kck, &other, &mic), "MIC must reject modified bytes");
    }

    // ── Phase 3: replay session acceptance logic ─────────────────────────────
    // Feed a counter sequence as WIRE frames through eapol::parse (the
    // non_exhaustive frame struct is only constructible in-crate; the parser
    // is the honest integration path). Acceptance must be exactly the
    // strictly-increasing subsequence, and rejected frames must not corrupt
    // session state.
    if cur.len() >= 8 {
        let mut session = Supplicant4WaySession::new();
        let mut last_accepted: Option<u64> = None;
        for chunk in cur.chunks_exact(8) {
            let counter = u64::from_be_bytes(chunk.try_into().expect("8-byte chunk")); // kanon:ignore RUST/expect -- chunks_exact(8)
            // EAPOL-Key wire frame: version=2, type=Key(0x03), body_len=95,
            // then descriptor/key_info/key_length/replay/nonce/iv/rsc/key_id/
            // mic/key_data_len — replay_counter is big-endian at body offset 5.
            let mut frame_bytes = vec![2u8, 0x03, 0x00, 95];
            frame_bytes.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00]);
            frame_bytes.extend_from_slice(&counter.to_be_bytes());
            frame_bytes.resize(4 + 95, 0);
            let parsed = eapol::parse(&frame_bytes).expect("crafted key frame must parse"); // kanon:ignore RUST/expect -- the frame is well-formed by construction
            let frame = parsed.key_frame.expect("Key packet_type must yield a key frame"); // kanon:ignore RUST/expect -- packet_type == Key guarantees key_frame
            let accepted = session.accept(&frame);
            let want = last_accepted.is_none_or(|last| counter > last);
            assert_eq!(accepted, want, "replay acceptance must be strictly-increasing-only");
            if accepted {
                last_accepted = Some(counter);
            }
        }
    }
});
