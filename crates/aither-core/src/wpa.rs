//! WPA2-Personal key derivation, MIC computation, replay-counter
//! enforcement, and the supplicant-side 4-way handshake state machine.
//!
//! Implements:
//! - PMK derivation via PBKDF2-HMAC-SHA1 (IEEE 802.11-2020, section 12.4.4.3.1)
//! - PTK derivation via PRF-384 (IEEE 802.11-2020, section 12.7.1.2)
//! - MIC computation via HMAC-SHA1 truncated to 128 bits
//! - the 4-way handshake progression (IEEE 802.11-2020, section 12.7.6)
//!
//! All hashing is via the audited `RustCrypto` `sha1`/`hmac`/`pbkdf2` crates
//! (#819) -- no hand-rolled SHA-1, HMAC, or PBKDF2 construction. PBKDF2's
//! salt (the SSID) is passed through with no length cap: the pre-convergence
//! kernel truncated an over-32-byte SSID salt to 32 bytes before hashing
//! (#837), silently deriving a different PMK than a compliant supplicant
//! would for the same passphrase/SSID pair.

use alloc::vec::Vec;

// WHY: digest 0.11 removed `new_from_slice` from the `Mac` trait itself (it
// now lives solely on `KeyInit`, which `hmac` re-exports) -- `Mac` alone no
// longer brings the constructor into scope.
use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;

use crate::eapol::{
    DESCRIPTOR_TYPE_RSN, EapolFrame, EapolKeyFrame, EapolType, IV_LEN, KeyInfo, MIC_LEN, NONCE_LEN,
};

type HmacSha1 = Hmac<Sha1>;

/// PBKDF2 iteration count for PSK derivation (IEEE 802.11-2020 fixed value).
const PBKDF2_ITERS: u32 = 4096;

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

/// Pairwise Transient Key components.
///
/// Derived from the PMK by PTK = PRF-384(PMK, "Pairwise key expansion", ...).
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
                core::ptr::write_volatile(byte, 0);
            }
        }
        for byte in &mut self.kek {
            // SAFETY: byte is a valid mutable reference to initialized memory.
            unsafe {
                core::ptr::write_volatile(byte, 0);
            }
        }
        for byte in &mut self.tk {
            // SAFETY: byte is a valid mutable reference to initialized memory.
            unsafe {
                core::ptr::write_volatile(byte, 0);
            }
        }
    }
}

/// Derive the Pairwise Master Key from a passphrase and SSID.
///
/// Uses PBKDF2-HMAC-SHA1 with 4096 iterations and a 32-byte output as
/// specified in IEEE 802.11-2020, section 12.4.4.3.1. `ssid` is used
/// unmodified as the PBKDF2 salt -- no length cap (#837).
#[must_use]
pub fn derive_pmk(passphrase: &[u8], ssid: &[u8]) -> [u8; PMK_LEN] {
    let mut pmk = [0u8; PMK_LEN];
    // WHY: the generic `pbkdf2::pbkdf2<PRF>` form, not the `hmac`-feature-
    // gated `pbkdf2_hmac` convenience wrapper -- matches the kernel's own
    // no_std, default-features=false PBKDF2 call in security.rs
    // (pbkdf2_sha256), a pattern already proven to compile in this exact
    // configuration. HMAC accepts any key length, so the InvalidLength
    // error is unreachable here; discarded for API totality.
    let _ = pbkdf2::pbkdf2::<HmacSha1>(passphrase, ssid, PBKDF2_ITERS, &mut pmk);
    pmk
}

/// WPA2 PRF-384 (IEEE 802.11-2020, section 12.7.1.2): HMAC-SHA1 counter
/// construction, truncated to 48 bytes.
///
/// ```text
/// R = ""
/// for i in 0..=2:
///     R = R || HMAC-SHA1(key, label || 0x00 || data || i)
/// return first 48 bytes of R
/// ```
#[must_use]
pub fn prf_384(key: &[u8], label: &[u8], data: &[u8]) -> [u8; 48] {
    let mut input = Vec::with_capacity(label.len() + 1 + data.len());
    input.extend_from_slice(label);
    input.push(0x00);
    input.extend_from_slice(data);

    let mut output = [0u8; 48];
    prf(key, &input, &mut output);
    output
}

/// Generic PRF construction: `PRF(K, A, Len) = HMAC-SHA1(K, A || i)` for
/// i = 0,1,... until `output.len()` bytes have been produced.
///
/// `input` must already be the concatenation the caller wants hashed (e.g.
/// `label || 0x00 || data` for [`prf_384`]); the counter byte `i` is
/// appended per iteration.
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

/// Derive the Pairwise Transient Key using PRF-384.
///
/// Implements IEEE 802.11-2020 section 12.7.1.2:
/// ```text
/// PTK = PRF-384(PMK, "Pairwise key expansion",
///               min(AA,SPA) || max(AA,SPA) || min(ANonce,SNonce) || max(ANonce,SNonce))
/// ```
#[must_use]
pub fn derive_ptk(
    pmk: &[u8; PMK_LEN],
    anonce: &[u8; 32],
    snonce: &[u8; 32],
    aa: &[u8; 6],
    spa: &[u8; 6],
) -> Ptk {
    // Build concatenated data: min(AA,SPA) || max(AA,SPA) ||
    //                          min(ANonce,SNonce) || max(ANonce,SNonce)
    let mut data = [0u8; 76];
    if aa <= spa {
        data[0..6].copy_from_slice(aa);
        data[6..12].copy_from_slice(spa);
    } else {
        data[0..6].copy_from_slice(spa);
        data[6..12].copy_from_slice(aa);
    }
    if anonce <= snonce {
        data[12..44].copy_from_slice(anonce);
        data[44..76].copy_from_slice(snonce);
    } else {
        data[12..44].copy_from_slice(snonce);
        data[44..76].copy_from_slice(anonce);
    }

    let ptk_bytes = prf_384(pmk, b"Pairwise key expansion", &data);

    let mut kck = [0u8; KCK_LEN];
    let mut kek = [0u8; KEK_LEN];
    let mut tk = [0u8; TK_LEN];
    kck.copy_from_slice(&ptk_bytes[0..16]);
    kek.copy_from_slice(&ptk_bytes[16..32]);
    tk.copy_from_slice(&ptk_bytes[32..48]);

    Ptk { kck, kek, tk }
}

/// Compute a 16-byte MIC using HMAC-SHA1 truncated to 128 bits.
///
/// Used to authenticate EAPOL-Key frames during the 4-way handshake
/// (messages 2, 3, and 4). The MIC field in the EAPOL frame must be zeroed
/// before passing `data` to this function.
#[must_use]
pub fn compute_mic(kck: &[u8; KCK_LEN], data: &[u8]) -> [u8; MIC_LEN] {
    let Ok(mut mac) = HmacSha1::new_from_slice(kck) else {
        return [0u8; MIC_LEN];
    };
    mac.update(data);
    let bytes = mac.finalize().into_bytes();
    // HMAC-SHA1 produces 20 bytes; take the first 16 (128 bits).
    let mut mic = [0u8; MIC_LEN];
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

/// Tracks the EAPOL-Key replay counter across a WPA 4-way handshake
/// supplicant session.
///
/// IEEE 802.11-2020 §12.7.6.2 requires the supplicant reject any EAPOL-Key
/// frame whose replay counter does not strictly exceed the last accepted
/// value, closing the replay window a KRACK-class attack depends on.
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
    /// `false` -- without updating internal state -- for a replayed or
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

// ---------------------------------------------------------------------------
// WPA2 4-way handshake state machine
// ---------------------------------------------------------------------------

/// WPA2-Personal 4-way handshake progression.
///
/// State machine for the supplicant side of the IEEE 802.11-2020 4-way
/// handshake (section 12.7.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum HandshakeState {
    /// Waiting for Message 1 (`ANonce` from authenticator).
    #[default]
    AwaitMsg1,
    /// Message 1 received; supplicant generated `SNonce` and derived PTK.
    /// Waiting to send Message 2.
    SendMsg2,
    /// Message 2 sent; waiting for Message 3 (GTK + Install).
    AwaitMsg3,
    /// Message 3 received; waiting to send Message 4 (final ACK).
    SendMsg4,
    /// Handshake complete; keys installed.
    Complete,
    /// Handshake failed.
    Failed,
}

/// WPA2-Personal 4-way handshake context.
///
/// Tracks handshake progression and stores transient cryptographic material
/// (nonces, derived keys) for the duration of the handshake.
///
/// NOTE: fields are private. The only sanctioned way to advance `state` or
/// populate `ptk` is through [`Self::process_message`], [`Self::msg2_sent`],
/// and [`Self::complete`] -- direct field mutation from outside this crate
/// would bypass MIC verification and the replay-counter check, e.g. jumping
/// straight to `SendMsg4` without ever validating Message 3.
///
/// This type generates no entropy of its own: [`Self::process_message`]
/// takes a caller-supplied `SNonce` rather than drawing one from an RNG.
/// The kernel's fail-closed CSPRNG (`csprng::kernel_random_bytes`) is
/// hardware-bound and has no equivalent this `no_std` core crate could
/// link; the caller is responsible for generating a fresh `SNonce` (and for
/// failing closed if its entropy source is not ready) BEFORE calling
/// [`Self::process_message`].
#[derive(Debug, Clone)]
pub struct WpaHandshake {
    /// Current handshake state.
    state: HandshakeState,
    /// Authenticator nonce (received in Message 1).
    anonce: [u8; NONCE_LEN],
    /// Supplicant nonce (caller-supplied in Message 1 processing).
    snonce: [u8; NONCE_LEN],
    /// Derived Pairwise Transient Key (populated after Message 1 processing).
    ptk: Option<Ptk>,
    /// Replay counter from the most recent authenticator message.
    replay_counter: u64,
    /// EAPOL protocol version (IEEE 802.1X-2020 §11.3.1) of the most
    /// recently received frame. Msg3 MIC reconstruction and the Msg2/Msg4
    /// responses echo this value instead of hardcoding version 2 -- a
    /// version-1 AP (802.1X-2001, common on embedded/enterprise gear)
    /// otherwise fails every MIC check.
    eapol_version: u8,
}

impl WpaHandshake {
    /// Create a new handshake context.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: HandshakeState::AwaitMsg1,
            anonce: [0u8; NONCE_LEN],
            snonce: [0u8; NONCE_LEN],
            ptk: None,
            replay_counter: 0,
            eapol_version: 2,
        }
    }

    /// Return the current handshake state.
    #[must_use]
    pub const fn state(&self) -> HandshakeState {
        self.state
    }

    /// Return the derived PTK, if Message 1 has been processed.
    #[must_use]
    pub const fn ptk(&self) -> Option<&Ptk> {
        self.ptk.as_ref()
    }

    /// Return the supplicant nonce most recently used (zero before Message
    /// 1 is processed).
    #[must_use]
    pub const fn snonce(&self) -> [u8; NONCE_LEN] {
        self.snonce
    }

    /// Record the EAPOL protocol version of the most recently received frame.
    ///
    /// Callers should invoke this with the wire frame's `version` byte
    /// before passing its key body to [`Self::process_message`] -- Msg3 MIC
    /// reconstruction and Msg2/Msg4 responses then echo the value instead
    /// of hardcoding version 2.
    pub const fn set_eapol_version(&mut self, version: u8) {
        self.eapol_version = version;
    }

    /// Process an incoming EAPOL-Key frame (Message 1 or Message 3).
    ///
    /// Advances the handshake state machine. Returns the new state.
    ///
    /// # Arguments
    ///
    /// * `key_frame` - The received EAPOL-Key frame body.
    /// * `pmk` - Pre-computed Pairwise Master Key.
    /// * `own_mac` - Supplicant MAC address (locally-administered).
    /// * `ap_mac` - Authenticator (AP) MAC address.
    /// * `snonce` - A fresh supplicant nonce, generated by the caller's own
    ///   entropy source. Consulted only when this call transitions out of
    ///   [`HandshakeState::AwaitMsg1`]; ignored otherwise (a caller
    ///   processing Message 3 may pass a fixed placeholder).
    pub fn process_message(
        &mut self,
        key_frame: &EapolKeyFrame,
        pmk: &[u8; PMK_LEN],
        own_mac: &[u8; 6],
        ap_mac: &[u8; 6],
        snonce: [u8; NONCE_LEN],
    ) -> HandshakeState {
        match self.state {
            HandshakeState::AwaitMsg1 => {
                // Message 1: AP sends ANonce, ack=true, mic=false, pairwise=true
                if !key_frame.key_info.ack()
                    || key_frame.key_info.mic()
                    || !key_frame.key_info.pairwise()
                {
                    self.state = HandshakeState::Failed;
                    return self.state;
                }
                self.anonce = key_frame.nonce;
                self.replay_counter = key_frame.replay_counter;
                self.snonce = snonce;

                // Derive PTK
                let ptk = derive_ptk(pmk, &self.anonce, &self.snonce, ap_mac, own_mac);
                self.ptk = Some(ptk);

                self.state = HandshakeState::SendMsg2;
                self.state
            }
            HandshakeState::AwaitMsg3 => {
                // Message 3: AP sends ANonce again, ack=true, mic=true, install=true, pairwise=true
                if !key_frame.key_info.ack()
                    || !key_frame.key_info.mic()
                    || !key_frame.key_info.install()
                    || !key_frame.key_info.pairwise()
                {
                    self.state = HandshakeState::Failed;
                    return self.state;
                }

                // Verify replay counter is monotonically increasing
                if key_frame.replay_counter <= self.replay_counter {
                    self.state = HandshakeState::Failed;
                    return self.state;
                }
                self.replay_counter = key_frame.replay_counter;

                // Verify MIC using KCK from PTK (IEEE 802.11-2020 section 12.7.6.4).
                // Fail closed: a missing PTK means no MIC can be verified --
                // never fall through to SendMsg4 unchecked.
                let Some(ref ptk) = self.ptk else {
                    self.state = HandshakeState::Failed;
                    return self.state;
                };
                let mut zeroed_kf = key_frame.clone();
                zeroed_kf.mic = [0u8; MIC_LEN];
                let zeroed_frame = EapolFrame {
                    version: self.eapol_version,
                    packet_type: EapolType::Key,
                    key_frame: Some(zeroed_kf),
                    raw_body: Vec::new(),
                };
                let encoded = crate::eapol::encode(&zeroed_frame);
                if !verify_mic(&ptk.kck, &encoded, &key_frame.mic) {
                    self.state = HandshakeState::Failed;
                    return self.state;
                }

                self.state = HandshakeState::SendMsg4;
                self.state
            }
            _ => self.state,
        }
    }

    /// Mark the handshake as complete after Message 4 has been sent.
    pub fn complete(&mut self) {
        if self.state == HandshakeState::SendMsg4 {
            self.state = HandshakeState::Complete;
        }
    }

    /// Advance the handshake after Message 2 has been transmitted.
    ///
    /// Transitions `SendMsg2 -> AwaitMsg3`. Without this call the state
    /// machine has no path out of `SendMsg2`: `process_message` only has
    /// match arms for `AwaitMsg1` and `AwaitMsg3`, so the AP's Message 3
    /// would otherwise fall through the `_ => self.state` catch-all and the
    /// handshake could never reach `SendMsg4`/`Complete`. No-ops (state
    /// unchanged) unless currently in `SendMsg2`.
    pub fn msg2_sent(&mut self) {
        if self.state == HandshakeState::SendMsg2 {
            self.state = HandshakeState::AwaitMsg3;
        }
    }

    /// Build an EAPOL-Key response frame (Message 2 or Message 4).
    ///
    /// Returns `None` if the handshake is not in a state that requires sending.
    #[must_use]
    pub fn build_response(&self) -> Option<EapolFrame> {
        match self.state {
            HandshakeState::SendMsg2 => {
                // Message 2: supplicant sends SNonce, mic=true, ack=false
                // Key info: version=2 (AES), pairwise, MIC
                // Fail closed: a missing PTK means no MIC can be computed --
                // never emit a frame with a zeroed, spoofable MIC.
                let ptk = self.ptk.as_ref()?;
                let key_info = KeyInfo(0x010a); // version=2, pairwise, MIC
                let mut kf = EapolKeyFrame {
                    descriptor_type: DESCRIPTOR_TYPE_RSN,
                    key_info,
                    key_length: 0,
                    replay_counter: self.replay_counter,
                    nonce: self.snonce,
                    iv: [0u8; IV_LEN],
                    rsc: 0,
                    mic: [0u8; MIC_LEN],
                    key_data: Vec::new(),
                };
                let frame_for_mic = EapolFrame {
                    version: self.eapol_version,
                    packet_type: EapolType::Key,
                    key_frame: Some(kf.clone()),
                    raw_body: Vec::new(),
                };
                kf.mic = compute_mic(&ptk.kck, &crate::eapol::encode(&frame_for_mic));
                Some(EapolFrame {
                    version: self.eapol_version,
                    packet_type: EapolType::Key,
                    key_frame: Some(kf),
                    raw_body: Vec::new(),
                })
            }
            HandshakeState::SendMsg4 => {
                // Message 4: supplicant sends final ACK, mic=true, secure=true
                // Fail closed: a missing PTK means no MIC can be computed --
                // never emit a frame with a zeroed, spoofable MIC.
                let ptk = self.ptk.as_ref()?;
                let key_info = KeyInfo(0x030a); // version=2, pairwise, MIC, secure
                let mut kf = EapolKeyFrame {
                    descriptor_type: DESCRIPTOR_TYPE_RSN,
                    key_info,
                    key_length: 0,
                    replay_counter: self.replay_counter,
                    nonce: [0u8; NONCE_LEN],
                    iv: [0u8; IV_LEN],
                    rsc: 0,
                    mic: [0u8; MIC_LEN],
                    key_data: Vec::new(),
                };
                let frame_for_mic = EapolFrame {
                    version: self.eapol_version,
                    packet_type: EapolType::Key,
                    key_frame: Some(kf.clone()),
                    raw_body: Vec::new(),
                };
                kf.mic = compute_mic(&ptk.kck, &crate::eapol::encode(&frame_for_mic));
                Some(EapolFrame {
                    version: self.eapol_version,
                    packet_type: EapolType::Key,
                    key_frame: Some(kf),
                    raw_body: Vec::new(),
                })
            }
            _ => None,
        }
    }
}

impl Drop for WpaHandshake {
    // WHY: write_volatile prevents the compiler from eliding zeroing as a
    // dead store -- nonces contribute to key derivation and are sensitive.
    // The PTK is zeroed by its own Drop impl when this Option is dropped.
    #[expect(
        unsafe_code,
        reason = "volatile writes prevent the compiler from eliding zeroing as dead store"
    )]
    fn drop(&mut self) {
        for byte in &mut self.anonce {
            // SAFETY: byte is a valid mutable reference to initialized memory.
            unsafe {
                core::ptr::write_volatile(byte, 0);
            }
        }
        for byte in &mut self.snonce {
            // SAFETY: byte is a valid mutable reference to initialized memory.
            unsafe {
                core::ptr::write_volatile(byte, 0);
            }
        }
    }
}

impl Default for WpaHandshake {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// IEEE 802.11i Annex J test vector -- PBKDF2(HMAC-SHA1, "password", "IEEE", 4096, 32).
    const IEEE_PMK: [u8; 32] = [
        0xf4, 0x2c, 0x6f, 0xc5, 0x2d, 0xf0, 0xeb, 0xef, 0x9e, 0xbb, 0x4b, 0x90, 0xb3, 0x8a, 0x5f,
        0x90, 0x2e, 0x83, 0xfe, 0x1b, 0x13, 0x5a, 0x70, 0xe2, 0x3a, 0xed, 0x76, 0x2e, 0x97, 0x10,
        0xa1, 0x2e,
    ];

    #[test]
    fn pmk_matches_ieee_annex_j_test_vector() {
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
    fn pmk_differs_when_ssid_differs() {
        let a = derive_pmk(b"password", b"Network1");
        let b = derive_pmk(b"password", b"Network2");
        assert_ne!(a, b, "PMK must differ when SSIDs differ");
    }

    // WHY (#837): the pre-convergence kernel truncated the PBKDF2 salt (the
    // SSID) to 32 bytes before hashing -- silently deriving a different PMK
    // for any SSID longer than 32 bytes than a compliant supplicant would.
    // IEEE 802.11 SSIDs are capped at 32 bytes on the wire, so this cannot
    // fire from a real over-the-air SSID; it proves the fix is real for any
    // caller that does not itself enforce that cap before reaching here.
    #[test]
    fn pmk_derivation_does_not_truncate_an_oversized_salt() {
        let short_salt = [0x41u8; 32]; // 32 'A's
        let long_salt = [0x41u8; 40]; // 40 'A's -- shares the first 32 bytes
        let pmk_short = derive_pmk(b"password", &short_salt);
        let pmk_long = derive_pmk(b"password", &long_salt);
        assert_ne!(
            pmk_short, pmk_long,
            "a salt that only DIFFERS past byte 32 must still change the derived PMK"
        );
    }

    // --- Crypto-backend migration vectors (#819) ---------------------------
    //
    // The pre-convergence kernel's hand-rolled SHA-1/HMAC-SHA1/PBKDF2-HMAC-
    // SHA1 (crates/thumos/src/security.rs) carried its own RFC 2202
    // (HMAC-SHA1) and RFC 6070 (PBKDF2-HMAC-SHA1) known-answer tests. Before
    // that code was deleted, both vector sets were run against THIS
    // module's RustCrypto-backed implementation and confirmed to match --
    // this section is that check, kept as a permanent regression rather
    // than a throwaway migration script. `compute_mic`/`derive_pmk` cannot
    // reach these exact vectors directly (RFC 2202's keys are 20 and 80
    // bytes, wider than `compute_mic`'s fixed 16-byte KCK; RFC 6070's c=1
    // vector uses a non-WPA2 iteration count `derive_pmk` does not expose),
    // so this exercises the same `hmac`/`sha1`/`pbkdf2` primitives those
    // public functions are built from, directly.

    #[test]
    fn hmac_sha1_matches_rfc2202_test_case_1() {
        // RFC 2202 Test Case 1: key = 20 bytes of 0x0b, data = "Hi There".
        let key = [0x0bu8; 20];
        let mut mac = HmacSha1::new_from_slice(&key)
            .unwrap_or_else(|_| unreachable!("HMAC accepts any key length"));
        mac.update(b"Hi There");
        let tag = mac.finalize().into_bytes();
        let expected: [u8; 20] = [
            0xb6, 0x17, 0x31, 0x86, 0x55, 0x05, 0x72, 0x64, 0xe2, 0x8b, 0xc0, 0xb6, 0xfb, 0x37,
            0x8c, 0x8e, 0xf1, 0x46, 0xbe, 0x00,
        ];
        assert_eq!(&tag[..], &expected, "HMAC-SHA1 RFC 2202 test case 1");
    }

    #[test]
    fn hmac_sha1_matches_rfc2202_test_case_2() {
        // RFC 2202 Test Case 2: key = "Jefe".
        let mut mac = HmacSha1::new_from_slice(b"Jefe")
            .unwrap_or_else(|_| unreachable!("HMAC accepts any key length"));
        mac.update(b"what do ya want for nothing?");
        let tag = mac.finalize().into_bytes();
        let expected: [u8; 20] = [
            0xef, 0xfc, 0xdf, 0x6a, 0xe5, 0xeb, 0x2f, 0xa2, 0xd2, 0x74, 0x16, 0xd5, 0xf1, 0x84,
            0xdf, 0x9c, 0x25, 0x9a, 0x7c, 0x79,
        ];
        assert_eq!(&tag[..], &expected, "HMAC-SHA1 RFC 2202 test case 2");
    }

    #[test]
    fn hmac_sha1_matches_rfc2202_test_case_6_long_key() {
        // RFC 2202 Test Case 6: key = 80 bytes of 0xaa, longer than the
        // 64-byte SHA-1 block size -- exercises RustCrypto's own long-key
        // normalization path (the hand-rolled kernel version had a
        // dedicated branch for this; RustCrypto's `new_from_slice` handles
        // it internally).
        let key = [0xaau8; 80];
        let mut mac = HmacSha1::new_from_slice(&key)
            .unwrap_or_else(|_| unreachable!("HMAC accepts any key length"));
        mac.update(b"Test Using Larger Than Block-Size Key - Hash Key First");
        let tag = mac.finalize().into_bytes();
        let expected: [u8; 20] = [
            0xaa, 0x4a, 0xe5, 0xe1, 0x52, 0x72, 0xd0, 0x0e, 0x95, 0x70, 0x56, 0x37, 0xce, 0x8a,
            0x3b, 0x55, 0xed, 0x40, 0x21, 0x12,
        ];
        assert_eq!(
            &tag[..],
            &expected,
            "HMAC-SHA1 RFC 2202 test case 6 (long key)"
        );
    }

    #[test]
    fn pbkdf2_hmac_sha1_matches_rfc6070_c1() {
        // RFC 6070 Test 1: P="password", S="salt", c=1, dkLen=20.
        let mut out = [0u8; 20];
        let _ = pbkdf2::pbkdf2::<HmacSha1>(b"password", b"salt", 1, &mut out);
        let expected: [u8; 20] = [
            0x0c, 0x60, 0xc8, 0x0f, 0x96, 0x1f, 0x0e, 0x71, 0xf3, 0xa9, 0xb5, 0x24, 0xaf, 0x60,
            0x12, 0x06, 0x2f, 0xe0, 0x37, 0xa6,
        ];
        assert_eq!(out, expected, "PBKDF2-HMAC-SHA1 RFC 6070 test 1 (c=1)");
    }

    #[test]
    fn pbkdf2_hmac_sha1_matches_rfc6070_c4096() {
        // RFC 6070 Test 2: P="password", S="salt", c=4096, dkLen=20 -- the
        // WPA2-Personal iteration count (`derive_pmk` uses the same c=4096,
        // just with a 32-byte output; this pins the shared 20-byte prefix
        // against the published vector).
        let mut out = [0u8; 20];
        let _ = pbkdf2::pbkdf2::<HmacSha1>(b"password", b"salt", 4096, &mut out);
        let expected: [u8; 20] = [
            0x4b, 0x00, 0x79, 0x01, 0xb7, 0x65, 0x48, 0x9a, 0xbe, 0xad, 0x49, 0xd9, 0x26, 0xf7,
            0x21, 0xd0, 0x65, 0xa4, 0x29, 0xc1,
        ];
        assert_eq!(out, expected, "PBKDF2-HMAC-SHA1 RFC 6070 test 2 (c=4096)");
        // Cross-check: derive_pmk's first 20 bytes must match too, since it
        // is the same PBKDF2-HMAC-SHA1(., ., 4096, .) call through the
        // public API.
        let pmk = derive_pmk(b"password", b"salt");
        assert_eq!(
            &pmk[..20],
            &expected,
            "derive_pmk's first 20 bytes must match the RFC 6070 c=4096 vector directly"
        );
    }

    #[test]
    fn ptk_fields_have_correct_lengths() {
        let pmk = [0u8; PMK_LEN];
        let anonce = [0xaau8; 32];
        let snonce = [0xbbu8; 32];
        let aa = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let spa = [0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb];
        let ptk = derive_ptk(&pmk, &anonce, &snonce, &aa, &spa);
        assert_eq!(ptk.kck.len(), KCK_LEN, "KCK must be KCK_LEN bytes");
        assert_eq!(ptk.kek.len(), KEK_LEN, "KEK must be KEK_LEN bytes");
        assert_eq!(ptk.tk.len(), TK_LEN, "TK must be TK_LEN bytes");
    }

    #[test]
    fn derive_ptk_produces_nonzero_keys() {
        let pmk = derive_pmk(b"password", b"TestSSID");
        let anonce = [0xAAu8; 32];
        let snonce = [0xBBu8; 32];
        let aa = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let spa = [0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
        let ptk = derive_ptk(&pmk, &anonce, &snonce, &aa, &spa);
        assert_ne!(ptk.kck, [0u8; KCK_LEN], "KCK must not be zero");
        assert_ne!(ptk.kek, [0u8; KEK_LEN], "KEK must not be zero");
        assert_ne!(ptk.tk, [0u8; TK_LEN], "TK must not be zero");
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
    fn ptk_is_identical_when_aa_spa_and_nonce_order_are_reversed() {
        let pmk = derive_pmk(b"password", b"TestSSID");
        let low_mac = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let high_mac = [0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
        let low_nonce = [0xAAu8; 32];
        let high_nonce = [0xBBu8; 32];

        // NOTE: canonical order (aa <= spa, anonce <= snonce) exercises the
        // already-sorted `if` branches.
        let sorted = derive_ptk(&pmk, &low_nonce, &high_nonce, &low_mac, &high_mac);
        // NOTE: reversed order (aa > spa, anonce > snonce) forces both
        // `else` branches to swap back to the canonical min-first order.
        let swapped = derive_ptk(&pmk, &high_nonce, &low_nonce, &high_mac, &low_mac);

        assert_eq!(
            sorted, swapped,
            "PTK must be identical regardless of AA/SPA and ANonce/SNonce argument order"
        );

        // WHY: cross-check against PRF-384 computed directly over the
        // canonical min(AA,SPA) || max(AA,SPA) || min(ANonce,SNonce) ||
        // max(ANonce,SNonce) concatenation, confirming the swapped call
        // normalized to that order rather than merely being self-consistent.
        let mut data = [0u8; 76];
        data[0..6].copy_from_slice(&low_mac);
        data[6..12].copy_from_slice(&high_mac);
        data[12..44].copy_from_slice(&low_nonce);
        data[44..76].copy_from_slice(&high_nonce);
        let expected = prf_384(&pmk, b"Pairwise key expansion", &data);
        assert_eq!(
            &expected[0..16],
            &swapped.kck,
            "swapped-order KCK must match the canonical PRF-384 output"
        );
        assert_eq!(
            &expected[16..32],
            &swapped.kek,
            "swapped-order KEK must match the canonical PRF-384 output"
        );
        assert_eq!(
            &expected[32..48],
            &swapped.tk,
            "swapped-order TK must match the canonical PRF-384 output"
        );
    }

    /// IEEE Std 802.11i-2004, Table H.13 / Table H.15 (Annex H.7.1,
    /// "Pairwise key derivation") -- the standard's own published PTK
    /// worked example. Note the published SNonce/ANonce are 20 bytes each
    /// (not the 32-byte EAPOL Key Nonce field), as printed in Table H.13;
    /// this test exercises [`prf_384`] directly with the literal published
    /// B-string rather than [`derive_ptk`]'s 32-byte-nonce typed wrapper,
    /// since 20-byte values cannot be passed through that signature without
    /// altering the vector. This is the side-by-side vector both the
    /// pre-convergence kernel's hand-rolled PRF-384 and the `RustCrypto`
    /// `hmac`/`sha1` backend were checked against (#819).
    #[test]
    // WHY: expected_kck/expected_kek/expected_tk mirror the IEEE standard's
    // own KCK/KEK/TK terminology (Table H.15) -- renaming would obscure the
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
        let mut data = Vec::with_capacity(6 + 6 + 20 + 20);
        data.extend_from_slice(&mac_lo);
        data.extend_from_slice(&mac_hi);
        data.extend_from_slice(&nonce_lo);
        data.extend_from_slice(&nonce_hi);

        let ptk_bytes = prf_384(&pmk, b"Pairwise key expansion", &data);

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
            &ptk_bytes[0..16],
            &expected_kck,
            "KCK must match IEEE 802.11i-2004 Table H.15"
        );
        assert_eq!(
            &ptk_bytes[16..32],
            &expected_kek,
            "KEK must match IEEE 802.11i-2004 Table H.15"
        );
        assert_eq!(
            &ptk_bytes[32..48],
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
    fn compute_mic_is_nonzero() {
        let kck = [0xCCu8; KCK_LEN];
        let data = b"test eapol frame data";
        let mic = compute_mic(&kck, data);
        assert_ne!(mic, [0u8; MIC_LEN], "MIC must not be zero");
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

    // --- Supplicant4WaySession replay-counter enforcement ---

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

    // --- WPA handshake state machine (lifted from the kernel, #545/#819) ---

    const OWN_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    const AP_MAC: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];

    fn msg1_frame() -> EapolKeyFrame {
        EapolKeyFrame {
            descriptor_type: DESCRIPTOR_TYPE_RSN,
            key_info: KeyInfo(0x008a), // version=2, pairwise, ack
            key_length: 16,
            replay_counter: 1,
            nonce: [0xaa; NONCE_LEN],
            iv: [0u8; IV_LEN],
            rsc: 0,
            mic: [0u8; MIC_LEN],
            key_data: Vec::new(),
        }
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

    #[test]
    fn handshake_transitions_to_send_msg2_on_valid_msg1() {
        let mut hs = WpaHandshake::new();
        let pmk = [0u8; PMK_LEN];
        let snonce = [0x99u8; NONCE_LEN];

        let state = hs.process_message(&msg1_frame(), &pmk, &OWN_MAC, &AP_MAC, snonce);
        assert_eq!(
            state,
            HandshakeState::SendMsg2,
            "must transition to SendMsg2 after valid Message 1"
        );
        assert!(hs.ptk().is_some(), "PTK must be derived after Message 1");
        assert_eq!(
            hs.snonce(),
            snonce,
            "the caller-supplied SNonce must be recorded"
        );
    }

    #[test]
    fn handshake_rejects_msg1_with_mic_set() {
        let mut hs = WpaHandshake::new();
        let pmk = [0u8; PMK_LEN];

        // Invalid Message 1: has MIC set (Message 1 must not have MIC)
        let msg1 = EapolKeyFrame {
            key_info: KeyInfo(0x018a), // version=2, pairwise, ack, MIC (invalid)
            ..msg1_frame()
        };

        let state = hs.process_message(&msg1, &pmk, &OWN_MAC, &AP_MAC, [0u8; NONCE_LEN]);
        assert_eq!(
            state,
            HandshakeState::Failed,
            "must reject Message 1 that has MIC set"
        );
    }

    #[test]
    fn handshake_rejects_msg1_with_pairwise_bit_clear() {
        let mut hs = WpaHandshake::new();
        let pmk = [0u8; PMK_LEN];

        // Group-key frame: ack=true, mic=false, pairwise=false (invalid as Msg1).
        let msg1 = EapolKeyFrame {
            key_info: KeyInfo(0x0082), // version=2, ack; pairwise CLEAR
            ..msg1_frame()
        };

        let state = hs.process_message(&msg1, &pmk, &OWN_MAC, &AP_MAC, [0u8; NONCE_LEN]);
        assert_eq!(
            state,
            HandshakeState::Failed,
            "must reject a group-key (pairwise=0) frame as Message 1"
        );
    }

    #[test]
    fn handshake_rejects_msg3_with_pairwise_bit_clear() {
        let mut hs = WpaHandshake::new();
        let pmk = [0u8; PMK_LEN];
        hs.process_message(&msg1_frame(), &pmk, &OWN_MAC, &AP_MAC, [0x99u8; NONCE_LEN]);
        // NOTE: `state` is crate-private; this write is legal only because
        // `tests` is a submodule of `wpa` within aither-core. Drive to
        // AwaitMsg3 directly, independent of msg2_sent()'s transition.
        hs.state = HandshakeState::AwaitMsg3;

        // Group-key frame masquerading as Msg3: ack, mic, install set,
        // pairwise CLEAR (0x01c2 = version=2 | install | ack | mic).
        let msg3 = EapolKeyFrame {
            key_info: KeyInfo(0x01c2),
            replay_counter: 2,
            ..msg1_frame()
        };

        let state = hs.process_message(&msg3, &pmk, &OWN_MAC, &AP_MAC, [0u8; NONCE_LEN]);
        assert_eq!(
            state,
            HandshakeState::Failed,
            "must reject a group-key (pairwise=0) frame as Message 3"
        );
    }

    #[test]
    fn handshake_builds_msg2_response() {
        let mut hs = WpaHandshake::new();
        let pmk = [0u8; PMK_LEN];
        let snonce = [0x99u8; NONCE_LEN];
        hs.process_message(&msg1_frame(), &pmk, &OWN_MAC, &AP_MAC, snonce);

        let response = hs.build_response();
        assert!(response.is_some(), "must produce Message 2 response");
        let response = response.as_ref();
        assert_eq!(
            response.map(|f| f.packet_type),
            Some(EapolType::Key),
            "response must be a Key frame"
        );
        let resp_kf = response.and_then(|f| f.key_frame.as_ref());
        assert!(resp_kf.is_some(), "response must have key frame");
        assert_eq!(
            resp_kf.map(|kf| kf.nonce),
            Some(snonce),
            "response nonce must be the supplicant nonce"
        );
    }

    #[test]
    fn handshake_completes_full_round_trip_after_msg2_sent() {
        let mut hs = WpaHandshake::new();
        let pmk = [0u8; PMK_LEN];

        let state = hs.process_message(&msg1_frame(), &pmk, &OWN_MAC, &AP_MAC, [0x99u8; NONCE_LEN]);
        assert_eq!(
            state,
            HandshakeState::SendMsg2,
            "Message 1 must yield SendMsg2"
        );

        assert!(
            hs.build_response().is_some(),
            "SendMsg2 must produce a Message 2 response"
        );
        hs.msg2_sent();
        assert_eq!(
            hs.state(),
            HandshakeState::AwaitMsg3,
            "msg2_sent must transition SendMsg2 -> AwaitMsg3"
        );

        // Message 3: ack=true, mic=true, install=true, pairwise=true.
        let mut msg3 = EapolKeyFrame {
            key_info: KeyInfo(0x01ca),
            replay_counter: 2,
            ..msg1_frame()
        };
        assert!(hs.ptk().is_some(), "PTK must be derived after Message 1");
        if let Some(ptk) = hs.ptk() {
            let zeroed_frame = EapolFrame {
                version: 2,
                packet_type: EapolType::Key,
                key_frame: Some(msg3.clone()),
                raw_body: Vec::new(),
            };
            msg3.mic = compute_mic(&ptk.kck, &crate::eapol::encode(&zeroed_frame));
        }

        let state = hs.process_message(&msg3, &pmk, &OWN_MAC, &AP_MAC, [0u8; NONCE_LEN]);
        assert_eq!(
            state,
            HandshakeState::SendMsg4,
            "Message 3 after msg2_sent must be processed and yield SendMsg4"
        );
    }

    #[test]
    fn build_response_fails_closed_without_ptk() {
        let mut hs = WpaHandshake::new();

        // Driver misuse: reach SendMsg2/SendMsg4 without ever deriving a
        // PTK. `state` is crate-private but settable here because `tests`
        // is a submodule of `wpa`.
        hs.state = HandshakeState::SendMsg2;
        assert!(hs.ptk().is_none(), "PTK must be None on this path");
        assert!(
            hs.build_response().is_none(),
            "SendMsg2 with ptk == None must not emit a zero-MIC frame"
        );

        hs.state = HandshakeState::SendMsg4;
        assert!(
            hs.build_response().is_none(),
            "SendMsg4 with ptk == None must not emit a zero-MIC frame"
        );
    }

    #[test]
    fn handshake_builds_msg4_response_and_completes_after_valid_msg3() {
        let mut hs = WpaHandshake::new();
        let pmk = [0u8; PMK_LEN];

        hs.process_message(&msg1_frame(), &pmk, &OWN_MAC, &AP_MAC, [0x99u8; NONCE_LEN]);
        hs.msg2_sent();

        let mut msg3 = EapolKeyFrame {
            key_info: KeyInfo(0x01ca),
            replay_counter: 2,
            ..msg1_frame()
        };
        if let Some(ptk) = hs.ptk() {
            let zeroed_frame = EapolFrame {
                version: 2,
                packet_type: EapolType::Key,
                key_frame: Some(msg3.clone()),
                raw_body: Vec::new(),
            };
            msg3.mic = compute_mic(&ptk.kck, &crate::eapol::encode(&zeroed_frame));
        }

        let state = hs.process_message(&msg3, &pmk, &OWN_MAC, &AP_MAC, [0u8; NONCE_LEN]);
        assert_eq!(
            state,
            HandshakeState::SendMsg4,
            "Message 3 with a valid MIC must yield SendMsg4"
        );

        let response = hs.build_response();
        assert!(
            response.is_some(),
            "SendMsg4 with a derived PTK must produce a Message 4 response"
        );
        let kf = response.and_then(|f| f.key_frame);
        assert!(kf.is_some(), "Message 4 response must carry a key frame");
        if let Some(kf) = kf {
            assert!(kf.key_info.secure(), "Message 4 must set the secure bit");
            assert!(kf.key_info.mic(), "Message 4 must set the MIC bit");
            assert!(!kf.key_info.install(), "Message 4 must not set install");
            assert_ne!(
                kf.mic, [0u8; MIC_LEN],
                "Message 4 MIC must be computed, not zeroed"
            );
        }

        hs.complete();
        assert_eq!(
            hs.state(),
            HandshakeState::Complete,
            "complete() must transition SendMsg4 -> Complete"
        );
    }

    #[test]
    fn handshake_fails_closed_when_awaiting_msg3_without_ptk() {
        let mut hs = WpaHandshake::new();
        let pmk = [0u8; PMK_LEN];

        // NOTE: `state` is crate-private; this write is legal only because
        // `tests` is a submodule of `wpa`. Driver misuse: reach AwaitMsg3
        // without ever processing Message 1, so `ptk` is still None.
        hs.state = HandshakeState::AwaitMsg3;
        assert!(hs.ptk().is_none(), "PTK must be None on this path");

        let msg3 = EapolKeyFrame {
            key_info: KeyInfo(0x01ca), // version=2, pairwise, install, ack, MIC
            replay_counter: 1,
            mic: [0xffu8; MIC_LEN],
            ..msg1_frame()
        };

        let state = hs.process_message(&msg3, &pmk, &OWN_MAC, &AP_MAC, [0u8; NONCE_LEN]);
        assert_eq!(
            state,
            HandshakeState::Failed,
            "entering AwaitMsg3 with ptk == None must fail closed, never reach SendMsg4"
        );
    }

    #[test]
    fn handshake_verifies_msg3_mic_using_received_eapol_version() {
        for version in [1u8, 2u8] {
            let mut hs = WpaHandshake::new();
            hs.set_eapol_version(version);
            let pmk = [0u8; PMK_LEN];

            hs.process_message(&msg1_frame(), &pmk, &OWN_MAC, &AP_MAC, [0x99u8; NONCE_LEN]);
            hs.state = HandshakeState::AwaitMsg3;

            let mut msg3 = EapolKeyFrame {
                key_info: KeyInfo(0x01ca),
                replay_counter: 2,
                ..msg1_frame()
            };
            if let Some(ptk) = hs.ptk() {
                let frame_for_mic = EapolFrame {
                    version,
                    packet_type: EapolType::Key,
                    key_frame: Some(msg3.clone()),
                    raw_body: Vec::new(),
                };
                msg3.mic = compute_mic(&ptk.kck, &crate::eapol::encode(&frame_for_mic));
            }

            let state = hs.process_message(&msg3, &pmk, &OWN_MAC, &AP_MAC, [0u8; NONCE_LEN]);
            assert_eq!(
                state,
                HandshakeState::SendMsg4,
                "Message 3 MIC must verify using the received EAPOL version {version}"
            );
        }
    }
}
