//! Symmetric ratchet: HMAC-SHA256 chain key advancement, AES-256-GCM message encryption.

use ring::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use ring::hmac::{self, HMAC_SHA256};

use crate::error::{DecryptionSnafu, EncryptionSnafu, InvalidKeySnafu, Result};

/// Byte appended to chain key for message key derivation: HMAC(CK, 0x01).
const MK_LABEL: &[u8] = &[0x01];

/// Byte appended to chain key for next chain key: HMAC(CK, 0x02).
const CK_LABEL: &[u8] = &[0x02];

/// Encrypted message produced by [`encrypt`].
#[derive(Debug, Clone)]
pub struct CiphertextMessage {
    /// Message counter  -  used to reconstruct the nonce on the receiving side.
    pub counter: u32,
    /// Ciphertext with appended AES-256-GCM authentication tag (16 bytes).
    pub ciphertext: Vec<u8>,
}

/// Ratchet state: current chain key and message counter.
#[derive(Clone)]
pub struct RatchetState {
    chain_key: [u8; 32],
    pub(crate) counter: u32,
}

impl RatchetState {
    /// Initialises a ratchet FROM a 32-byte root key.
    pub const fn new(root_key: [u8; 32]) -> Self {
        Self {
            chain_key: root_key,
            counter: 0,
        }
    }

    /// Returns the current message counter.
    pub const fn counter(&self) -> u32 {
        self.counter
    }
}

impl std::fmt::Debug for RatchetState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RatchetState")
            .field("chain_key", &"[REDACTED]")
            .field("counter", &self.counter)
            .finish()
    }
}

/// Encrypts `plaintext`, advancing `state` by one step.
///
/// # Errors
///
/// Returns [`Error::InvalidKey`] if the derived message key is malformed.
/// Returns [`Error::Encryption`] if AES-256-GCM sealing fails.
pub fn encrypt(state: &mut RatchetState, plaintext: &[u8]) -> Result<CiphertextMessage> {
    let message_key = derive_message_key(&state.chain_key);
    let next_chain_key = derive_next_chain_key(&state.chain_key);

    let nonce = counter_nonce(state.counter);
    let key = make_aes_key(&message_key)?;

    let mut in_out = plaintext.to_vec();
    key.seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
        .map_err(|_| EncryptionSnafu.build())?;

    let counter = state.counter;
    state.chain_key = next_chain_key;
    state.counter = state.counter.wrapping_add(1);

    Ok(CiphertextMessage {
        counter,
        ciphertext: in_out,
    })
}

/// Decrypts `msg`, advancing `state` by one step.
///
/// # Errors
///
/// Returns [`Error::InvalidKey`] if the derived message key is malformed.
/// Returns [`Error::Decryption`] if AES-256-GCM authentication or decryption fails.
pub fn decrypt(state: &mut RatchetState, msg: &CiphertextMessage) -> Result<Vec<u8>> {
    let message_key = derive_message_key(&state.chain_key);
    let next_chain_key = derive_next_chain_key(&state.chain_key);

    let nonce = counter_nonce(msg.counter);
    let key = make_aes_key(&message_key)?;

    let mut in_out = msg.ciphertext.clone();
    let plaintext_slice = key
        .open_in_place(nonce, Aad::empty(), &mut in_out)
        .map_err(|_| DecryptionSnafu.build())?;
    let plaintext = plaintext_slice.to_vec();

    state.chain_key = next_chain_key;
    state.counter = state.counter.wrapping_add(1);

    Ok(plaintext)
}

fn derive_message_key(chain_key: &[u8; 32]) -> [u8; 32] {
    let key = hmac::Key::new(HMAC_SHA256, chain_key);
    let tag = hmac::sign(&key, MK_LABEL);
    let mut out = [0u8; 32];
    out.copy_from_slice(tag.as_ref());
    out
}

fn derive_next_chain_key(chain_key: &[u8; 32]) -> [u8; 32] {
    let key = hmac::Key::new(HMAC_SHA256, chain_key);
    let tag = hmac::sign(&key, CK_LABEL);
    let mut out = [0u8; 32];
    out.copy_from_slice(tag.as_ref());
    out
}

fn counter_nonce(counter: u32) -> Nonce {
    let mut nonce_bytes = [0u8; NONCE_LEN];
    nonce_bytes[..4].copy_from_slice(&counter.to_le_bytes());
    Nonce::assume_unique_for_key(nonce_bytes)
}

fn make_aes_key(key_bytes: &[u8; 32]) -> Result<LessSafeKey> {
    let unbound = UnboundKey::new(&AES_256_GCM, key_bytes).map_err(|_| InvalidKeySnafu.build())?;
    Ok(LessSafeKey::new(unbound))
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
