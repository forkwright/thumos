//! Symmetric ratchet: HMAC-SHA256 chain key advancement, AES-256-GCM message encryption.

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::error::{DecryptionSnafu, EncryptionSnafu, InvalidKeySnafu, Result};

const NONCE_LEN: usize = 12;

type HmacSha256 = Hmac<Sha256>;

/// Byte appended to chain key for message key derivation: HMAC(CK, 0x01).
const MK_LABEL: &[u8] = &[0x01];

/// Byte appended to chain key for next chain key: HMAC(CK, 0x02).
const CK_LABEL: &[u8] = &[0x02];

/// Encrypted message produced by [`encrypt`].
#[derive(Debug, Clone)]
pub(crate) struct CiphertextMessage {
    /// Message counter  -  used to reconstruct the nonce on the receiving side.
    pub(crate) counter: u32,
    /// Ciphertext with appended AES-256-GCM authentication tag (16 bytes).
    pub(crate) ciphertext: Vec<u8>,
}

/// Ratchet state: current chain key and message counter.
#[derive(Clone)]
pub(crate) struct RatchetState {
    chain_key: [u8; 32],
    pub(crate) counter: u32,
}

impl RatchetState {
    /// Initialises a ratchet FROM a 32-byte root key.
    pub(crate) const fn new(root_key: [u8; 32]) -> Self {
        Self {
            chain_key: root_key,
            counter: 0,
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
        .encrypt_in_place(Nonce::from_slice(&nonce), b"", &mut in_out)
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
pub(crate) fn decrypt(state: &mut RatchetState, msg: &CiphertextMessage) -> Result<Vec<u8>> {
    let message_key = derive_message_key(&state.chain_key)?;
    let next_chain_key = derive_next_chain_key(&state.chain_key)?;

    let nonce = counter_nonce(msg.counter);
    let cipher = make_aes_cipher(&message_key)?;

    let mut in_out = msg.ciphertext.clone();
    cipher
        .decrypt_in_place(Nonce::from_slice(&nonce), b"", &mut in_out)
        .map_err(|_| DecryptionSnafu.build())?;

    state.chain_key = next_chain_key;
    state.counter = state.counter.wrapping_add(1);

    Ok(in_out)
}

fn derive_message_key(chain_key: &[u8; 32]) -> Result<[u8; 32]> {
    hmac_sha256(chain_key, MK_LABEL)
}

fn derive_next_chain_key(chain_key: &[u8; 32]) -> Result<[u8; 32]> {
    hmac_sha256(chain_key, CK_LABEL)
}

fn hmac_sha256(key: &[u8; 32], data: &[u8]) -> Result<[u8; 32]> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).map_err(|_| InvalidKeySnafu.build())?;
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
