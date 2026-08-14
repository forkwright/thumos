//! Symmetric ratchet: HMAC-SHA256 chain key advancement, AES-256-GCM message encryption.

use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{AeadInOut, KeyInit};
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::error::{DecryptionSnafu, EncryptionSnafu, InvalidKeySnafu, Result};

const NONCE_LEN: usize = 12;

type HmacSha256 = Hmac<Sha256>;

/// Byte appended to chain key for message key derivation: HMAC(CK, 0x01).
const MK_LABEL: &[u8] = &[0x01];

/// Byte appended to chain key for next chain key: HMAC(CK, 0x02).
const CK_LABEL: &[u8] = &[0x02];

/// WHY(#212): upper bound on how far a single message may jump ahead of the
/// receive chain. Rejects a forged high counter before it forces unbounded key
/// derivation (`DoS`), and bounds cache growth per message.
const MAX_SKIP_AHEAD: u32 = 1024;

/// WHY(#212): total cap on cached skipped message keys; oldest is evicted when
/// exceeded, so the cache is provably bounded regardless of traffic.
const MAX_SKIPPED_KEYS: usize = 1024;

/// A message key retained for an out-of-order/dropped message, keyed by counter.
#[derive(Clone)]
struct SkippedKey {
    counter: u32,
    message_key: [u8; 32],
}

/// Encrypted message produced by [`encrypt`].
#[derive(Debug, Clone)]
pub(crate) struct CiphertextMessage {
    /// Message counter  -  used to reconstruct the nonce on the receiving side.
    pub(crate) counter: u32,
    /// Ciphertext with appended AES-256-GCM authentication tag (16 bytes).
    pub(crate) ciphertext: Vec<u8>,
}

/// Ratchet state: current chain key, message counter, and skipped-key cache.
#[derive(Clone)]
pub(crate) struct RatchetState {
    chain_key: [u8; 32],
    pub(crate) counter: u32,
    /// Bounded cache of message keys for skipped/out-of-order messages (#212).
    /// Only the receive path populates this; the send path leaves it empty.
    skipped: Vec<SkippedKey>,
}

impl RatchetState {
    /// Initialises a ratchet FROM a 32-byte root key.
    ///
    /// Time: O(1) — builds a fixed-field struct; no loop or recursion.
    /// Space: O(1) — `skipped` starts as `Vec::new()`, which allocates
    /// nothing until the first push.
    pub(crate) const fn new(root_key: [u8; 32]) -> Self {
        Self {
            chain_key: root_key,
            counter: 0,
            skipped: Vec::new(),
        }
    }

    /// Returns the current message counter.
    pub(crate) const fn counter(&self) -> u32 {
        self.counter
    }
}

impl std::fmt::Debug for RatchetState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RatchetState")
            .field("chain_key", &"[REDACTED]")
            .field("counter", &self.counter)
            .field("skipped_keys", &self.skipped.len())
            .finish()
    }
}

/// Encrypts `plaintext`, advancing `state` by one step.
///
/// # Errors
///
/// Returns [`Error::InvalidKey`] if the derived message key is malformed.
/// Returns [`Error::Encryption`] if AES-256-GCM sealing fails.
pub(crate) fn encrypt(state: &mut RatchetState, plaintext: &[u8]) -> Result<CiphertextMessage> {
    let message_key = derive_message_key(&state.chain_key)?;
    let next_chain_key = derive_next_chain_key(&state.chain_key)?;

    let nonce = counter_nonce(state.counter);
    let cipher = make_aes_cipher(&message_key)?;

    let mut in_out = plaintext.to_vec();
    cipher
        .encrypt_in_place((&nonce).into(), b"", &mut in_out)
        .map_err(|_| EncryptionSnafu.build())?;

    let counter = state.counter;
    state.chain_key = next_chain_key;
    state.counter = state.counter.wrapping_add(1);

    Ok(CiphertextMessage {
        counter,
        ciphertext: in_out,
    })
}

/// Decrypts `msg`, tolerating dropped and out-of-order messages (#212).
///
/// - A message at the current counter decrypts in order and advances the chain.
/// - A message ahead of the chain skips the gap, caching each skipped key, then
///   decrypts at the target counter. The jump is bounded by [`MAX_SKIP_AHEAD`].
/// - A message behind the chain is served from the skipped-key cache; each
///   cached key is single-use, giving replay rejection for consumed counters.
///
/// The chain and cache are mutated ONLY after the target message authenticates,
/// so a forged message cannot desynchronise the ratchet or pollute the cache.
///
/// # Errors
///
/// Returns [`Error::InvalidKey`] if a derived message key is malformed.
/// Returns [`Error::Decryption`] if authentication fails, the counter is
/// unknown/replayed, or the forward jump exceeds [`MAX_SKIP_AHEAD`].
///
/// Time: O(g + L) where L is `msg.ciphertext.len()` (the AES-256-GCM
/// authenticate-and-decrypt cost, in [`aead_open`]) and g is either the
/// forward counter gap `msg.counter - state.counter` when the message is
/// ahead of the chain (one HMAC-SHA256 key derivation per skipped step,
/// each O(1)) or the current skipped-key cache size when the message is
/// behind it (a linear [`decrypt_from_skipped`] scan). Both are bounded by
/// the compile-time constants [`MAX_SKIP_AHEAD`] and [`MAX_SKIPPED_KEYS`]
/// (1024 each) — the forward-gap check runs BEFORE the derivation loop, so
/// g never exceeds 1024 in practice — but L is genuinely unbounded and
/// dominates for larger payloads.
/// Space: O(g + L) — a working copy of the ciphertext (L bytes, in
/// [`aead_open`]) plus up to g pending [`SkippedKey`] entries before they
/// are folded into the bounded skipped-key cache.
pub(crate) fn decrypt(state: &mut RatchetState, msg: &CiphertextMessage) -> Result<Vec<u8>> {
    // Behind the chain: only the skipped-key cache can decrypt it.
    if msg.counter < state.counter {
        return decrypt_from_skipped(state, msg);
    }

    // WHY(#212): bound the forward jump so a forged high counter cannot force
    // unbounded key derivation.
    let gap: u32 = msg.counter - state.counter;
    if gap > MAX_SKIP_AHEAD {
        return Err(DecryptionSnafu.build());
    }

    // Trial-decrypt on a working chain copy; commit only on authentication.
    let mut work_chain_key = state.chain_key;
    let mut pending: Vec<SkippedKey> = Vec::with_capacity(gap as usize);
    let mut counter = state.counter;
    while counter < msg.counter {
        let message_key = derive_message_key(&work_chain_key)?;
        pending.push(SkippedKey {
            counter,
            message_key,
        });
        work_chain_key = derive_next_chain_key(&work_chain_key)?;
        counter = counter.wrapping_add(1);
    }

    let message_key = derive_message_key(&work_chain_key)?;
    let plaintext = aead_open(&message_key, msg)?;

    // Authenticated: commit skipped keys and advance the receive chain.
    for skipped in pending {
        store_skipped(state, skipped);
    }
    state.chain_key = derive_next_chain_key(&work_chain_key)?;
    state.counter = msg.counter.wrapping_add(1);
    Ok(plaintext)
}

/// Decrypts a message whose counter is behind the chain using the skipped-key
/// cache. Consumes the cached key only on successful authentication.
fn decrypt_from_skipped(state: &mut RatchetState, msg: &CiphertextMessage) -> Result<Vec<u8>> {
    let index = state
        .skipped
        .iter()
        .position(|k| k.counter == msg.counter)
        .ok_or_else(|| DecryptionSnafu.build())?;
    let message_key = state
        .skipped
        .get(index)
        .ok_or_else(|| DecryptionSnafu.build())?
        .message_key;
    let plaintext = aead_open(&message_key, msg)?;
    state.skipped.remove(index);
    Ok(plaintext)
}

/// Inserts a skipped key, evicting the oldest entries beyond [`MAX_SKIPPED_KEYS`].
fn store_skipped(state: &mut RatchetState, key: SkippedKey) {
    state.skipped.push(key);
    while state.skipped.len() > MAX_SKIPPED_KEYS {
        state.skipped.remove(0);
    }
}

/// Opens an AES-256-GCM ciphertext with `message_key` under the counter nonce.
fn aead_open(message_key: &[u8; 32], msg: &CiphertextMessage) -> Result<Vec<u8>> {
    let nonce = counter_nonce(msg.counter);
    let cipher = make_aes_cipher(message_key)?;
    let mut in_out = msg.ciphertext.clone();
    cipher
        .decrypt_in_place((&nonce).into(), b"", &mut in_out)
        .map_err(|_| DecryptionSnafu.build())?;
    Ok(in_out)
}

fn derive_message_key(chain_key: &[u8; 32]) -> Result<[u8; 32]> {
    hmac_sha256(chain_key, MK_LABEL)
}

fn derive_next_chain_key(chain_key: &[u8; 32]) -> Result<[u8; 32]> {
    hmac_sha256(chain_key, CK_LABEL)
}

fn hmac_sha256(key: &[u8; 32], data: &[u8]) -> Result<[u8; 32]> {
    let mut mac =
        <HmacSha256 as KeyInit>::new_from_slice(key).map_err(|_| InvalidKeySnafu.build())?;
    mac.update(data);
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&tag);
    Ok(out)
}

const fn counter_nonce(counter: u32) -> [u8; NONCE_LEN] {
    let [b0, b1, b2, b3] = counter.to_le_bytes();
    [b0, b1, b2, b3, 0, 0, 0, 0, 0, 0, 0, 0]
}

fn make_aes_cipher(key_bytes: &[u8; 32]) -> Result<Aes256Gcm> {
    Aes256Gcm::new_from_slice(key_bytes).map_err(|_| InvalidKeySnafu.build())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root_key(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[test]
    fn aes_gcm_encrypt_decrypt_round_trip() -> Result<()> {
        let mut state = RatchetState::new(root_key(0xAB));
        let plaintext = b"signal ratchet test message";
        let ciphertext = encrypt(&mut state, plaintext)?;
        let mut recv_state = RatchetState::new(root_key(0xAB));
        let decrypted = decrypt(&mut recv_state, &ciphertext)?;
        assert_eq!(
            decrypted.as_slice(),
            plaintext,
            "decrypted bytes must match original plaintext"
        );
        Ok(())
    }

    #[test]
    fn decryption_fails_with_wrong_chain_key() -> Result<()> {
        let mut send_state = RatchetState::new(root_key(0x11));
        let ciphertext = encrypt(&mut send_state, b"secret")?;
        let mut recv_state = RatchetState::new(root_key(0xFF)); // wrong key
        assert!(
            decrypt(&mut recv_state, &ciphertext).is_err(),
            "decryption with wrong chain key must fail authentication"
        );
        Ok(())
    }

    #[test]
    fn decryption_fails_on_tampered_ciphertext() -> Result<()> {
        let mut send_state = RatchetState::new(root_key(0x22));
        let mut msg = encrypt(&mut send_state, b"secret message")?;
        // Flip a byte in the ciphertext body.
        if let Some(b) = msg.ciphertext.first_mut() {
            *b ^= 0xFF;
        }
        let mut recv_state = RatchetState::new(root_key(0x22));
        assert!(
            decrypt(&mut recv_state, &msg).is_err(),
            "tampered ciphertext must fail GCM authentication"
        );
        Ok(())
    }

    #[test]
    fn decrypt_does_not_mutate_state_on_auth_failure() -> Result<()> {
        // An in-order message (gap == 0) that fails authentication must leave
        // the receive chain key, counter, and skipped-key cache untouched —
        // only a successfully authenticated message may advance state.
        let root = root_key(0xDD);
        let mut send = RatchetState::new(root);
        let mut recv = RatchetState::new(root);
        let mut msg = encrypt(&mut send, b"in-order message")?;
        if let Some(byte) = msg.ciphertext.first_mut() {
            *byte ^= 0xFF;
        }
        let counter_before = recv.counter;
        let chain_key_before = recv.chain_key;
        assert!(
            decrypt(&mut recv, &msg).is_err(),
            "tampered in-order message must fail authentication"
        );
        assert_eq!(
            recv.counter, counter_before,
            "a failed in-order decrypt must not advance the receive counter"
        );
        assert_eq!(
            recv.chain_key, chain_key_before,
            "a failed in-order decrypt must not roll the receive chain key"
        );
        assert!(
            recv.skipped.is_empty(),
            "a failed in-order decrypt must not populate the skipped-key cache"
        );
        Ok(())
    }

    #[test]
    fn ratchet_advances_for_multiple_messages() -> Result<()> {
        let root = root_key(0x33);
        let mut send_state = RatchetState::new(root);
        let mut recv_state = RatchetState::new(root);

        let messages: &[&[u8]] = &[b"first", b"second", b"third", b"fourth"];

        let ciphertexts: Vec<_> = messages
            .iter()
            .map(|m| encrypt(&mut send_state, m))
            .collect::<Result<Vec<_>>>()?;

        for (ct, expected) in ciphertexts.iter().zip(messages.iter()) {
            let plain = decrypt(&mut recv_state, ct)?;
            assert_eq!(
                plain.as_slice(),
                *expected,
                "message must decrypt to original plaintext in ORDER"
            );
        }
        Ok(())
    }

    #[test]
    fn ratchet_counter_increments_per_message() -> Result<()> {
        let mut state = RatchetState::new(root_key(0x44));
        assert_eq!(state.counter(), 0, "initial counter must be 0");
        let _ = encrypt(&mut state, b"msg1")?;
        assert_eq!(state.counter(), 1, "counter must be 1 after first message");
        let _ = encrypt(&mut state, b"msg2")?;
        assert_eq!(state.counter(), 2, "counter must be 2 after second message");
        Ok(())
    }

    #[test]
    fn out_of_order_delivery_recovers_via_skipped_cache() -> Result<()> {
        // #212 Done-when: a later message that overtakes an earlier one still
        // decrypts, and the overtaken message decrypts afterwards from cache.
        let root = root_key(0x66);
        let mut send = RatchetState::new(root);
        let mut recv = RatchetState::new(root);
        let m0 = encrypt(&mut send, b"zero")?;
        let m1 = encrypt(&mut send, b"one")?;
        let m2 = encrypt(&mut send, b"two")?;

        assert_eq!(decrypt(&mut recv, &m0)?.as_slice(), b"zero");
        assert_eq!(decrypt(&mut recv, &m2)?.as_slice(), b"two");
        assert_eq!(
            decrypt(&mut recv, &m1)?.as_slice(),
            b"one",
            "the overtaken message must decrypt from the skipped-key cache"
        );
        Ok(())
    }

    #[test]
    fn dropped_message_does_not_desync_ratchet() -> Result<()> {
        // #212 Done-when: a permanently dropped message must not freeze the
        // receive chain — later messages still decrypt.
        let root = root_key(0x77);
        let mut send = RatchetState::new(root);
        let mut recv = RatchetState::new(root);
        let _dropped = encrypt(&mut send, b"lost")?;
        let m1 = encrypt(&mut send, b"survivor")?;
        let m2 = encrypt(&mut send, b"after")?;

        assert_eq!(decrypt(&mut recv, &m1)?.as_slice(), b"survivor");
        assert_eq!(decrypt(&mut recv, &m2)?.as_slice(), b"after");
        Ok(())
    }

    #[test]
    fn consumed_in_order_message_cannot_replay() -> Result<()> {
        let root = root_key(0x88);
        let mut send = RatchetState::new(root);
        let mut recv = RatchetState::new(root);
        let m0 = encrypt(&mut send, b"once")?;
        assert_eq!(decrypt(&mut recv, &m0)?.as_slice(), b"once");
        assert!(
            decrypt(&mut recv, &m0).is_err(),
            "a consumed in-order counter must not decrypt again (replay)"
        );
        Ok(())
    }

    #[test]
    fn cached_skipped_key_is_single_use() -> Result<()> {
        let root = root_key(0x99);
        let mut send = RatchetState::new(root);
        let mut recv = RatchetState::new(root);
        let m0 = encrypt(&mut send, b"a")?;
        let m1 = encrypt(&mut send, b"b")?;

        assert_eq!(decrypt(&mut recv, &m1)?.as_slice(), b"b");
        assert_eq!(decrypt(&mut recv, &m0)?.as_slice(), b"a");
        assert!(
            decrypt(&mut recv, &m0).is_err(),
            "a cached skipped key must be consumed exactly once"
        );
        Ok(())
    }

    #[test]
    fn skip_ahead_beyond_bound_is_rejected() -> Result<()> {
        // #212: a counter jump past MAX_SKIP_AHEAD must be rejected rather than
        // forcing unbounded key derivation.
        let root = root_key(0xAA);
        let mut send = RatchetState::new(root);
        let mut recv = RatchetState::new(root);
        let mut forged = encrypt(&mut send, b"first")?;
        forged.counter = MAX_SKIP_AHEAD + 5;
        assert!(
            decrypt(&mut recv, &forged).is_err(),
            "a jump beyond MAX_SKIP_AHEAD must be rejected"
        );
        assert_eq!(
            recv.counter, 0,
            "a rejected over-long jump must not advance the receive chain"
        );
        Ok(())
    }

    #[test]
    fn skipped_cache_is_bounded() -> Result<()> {
        // #212: the cache never exceeds MAX_SKIPPED_KEYS even under a large gap.
        let root = root_key(0xBB);
        let mut send = RatchetState::new(root);
        let mut recv = RatchetState::new(root);

        let gap = MAX_SKIP_AHEAD; // skips `gap` keys, then decrypts at `gap`.
        let mut last = encrypt(&mut send, b"m0")?;
        for _ in 0..gap {
            last = encrypt(&mut send, b"mN")?;
        }
        // `last` is at counter == gap; decrypting it caches `gap` keys, capped.
        let _ = decrypt(&mut recv, &last)?;
        assert!(
            recv.skipped.len() <= MAX_SKIPPED_KEYS,
            "skipped-key cache must be bounded by MAX_SKIPPED_KEYS"
        );
        Ok(())
    }

    #[test]
    fn forged_skip_ahead_does_not_advance_or_cache() -> Result<()> {
        // A forged message within the skip bound but with wrong content must
        // leave the receive chain and cache untouched.
        let root = root_key(0xCC);
        let mut send = RatchetState::new(root);
        let mut recv = RatchetState::new(root);
        let mut forged = encrypt(&mut send, b"real")?;
        forged.counter = 5;
        if let Some(byte) = forged.ciphertext.first_mut() {
            *byte ^= 0xFF;
        }
        assert!(
            decrypt(&mut recv, &forged).is_err(),
            "forged message must fail"
        );
        assert_eq!(
            recv.counter, 0,
            "chain must not advance on a forged message"
        );
        assert_eq!(
            recv.skipped.len(),
            0,
            "cache must not be polluted by a forged message"
        );
        Ok(())
    }

    #[test]
    fn same_root_and_counter_produce_same_ciphertext() -> Result<()> {
        let root = root_key(0x55);
        let mut state_a = RatchetState::new(root);
        let mut state_b = RatchetState::new(root);
        let ct_a = encrypt(&mut state_a, b"same plaintext")?;
        let ct_b = encrypt(&mut state_b, b"same plaintext")?;
        assert_eq!(
            ct_a.ciphertext, ct_b.ciphertext,
            "same root and counter must produce same ciphertext (deterministic ratchet)"
        );
        Ok(())
    }
}
