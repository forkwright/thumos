//! Cryptographically verified, expiring capability grants (#544).
//!
//! Extracted `no_std` + alloc (#545) so the kernel signs/verifies against
//! the same implementation `metaxu`'s pylon and witness already prove.
//!
//! A grant is the Aletheia runtime's signed authorization for ONE device to
//! request specific capabilities until an expiry. It is bound to both
//! identities: the issuer's Ed25519 public key (which the device pins out of
//! band) and the subject device's public key (which the issuer binds at
//! issue). Verification therefore proves: the signature is valid under the
//! pinned runtime key, the grant is for THIS device, and it has not
//! expired. Nothing else — no unsigned claims, no grantless authority.
//!
//! The session-nonce is the response-authentication root: response MACs
//! are keyed by `HKDF-SHA256(ikm = nonce, info = "metaxu-response-v1")`,
//! so a verified response proves the responder knows the nonce inside the
//! signed grant — i.e. it is the issuer (or holds the grant, which the
//! device handed only over the authenticated hello).

extern crate alloc;

use core::fmt;

use alloc::vec::Vec;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::protocol::Capability;

/// Grant error: every verification failure is explicit (#544).
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
#[non_exhaustive]
pub enum GrantError {
    /// The Ed25519 signature does not verify under the issuer key.
    BadSignature,
    /// The grant is expired at the evaluation time.
    Expired {
        /// When the grant expired.
        expired_at_ms: u64,
        /// When verification was evaluated.
        now_ms: u64,
    },
    /// The grant's subject is not the device presenting it.
    WrongDevice,
}

impl fmt::Display for GrantError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadSignature => write!(f, "grant signature invalid"),
            Self::Expired {
                expired_at_ms,
                now_ms,
            } => write!(
                f,
                "grant expired at {expired_at_ms} (evaluated at {now_ms})"
            ),
            Self::WrongDevice => write!(f, "grant issued for a different device"),
        }
    }
}

impl core::error::Error for GrantError {}

/// A capability grant: issuer → subject, bounded in time (#544).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grant {
    /// Issuer's Ed25519 public key (the Aletheia runtime; the device pins
    /// this out of band).
    pub issuer: [u8; 32],
    /// Subject device's Ed25519 public key.
    pub subject: [u8; 32],
    /// The capabilities this grant authorizes.
    pub capabilities: Vec<Capability>,
    /// Issue time, ms since the Unix epoch.
    pub issued_at_ms: u64,
    /// Expiry time, ms since the Unix epoch. Verification at or after this
    /// time fails.
    pub expires_at_ms: u64,
    /// Session nonce: the response-authentication root (see module docs).
    pub nonce: [u8; 16],
}

/// A [`Grant`] plus the issuer's Ed25519 signature over its postcard bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedGrant {
    /// The grant payload.
    pub grant: Grant,
    /// Ed25519 signature over `postcard::to_allocvec(grant)`.
    pub signature: Signature,
}

impl SignedGrant {
    /// Issue a grant: sign the postcard encoding with the issuer key.
    pub fn issue(grant: Grant, issuer_key: &SigningKey) -> Self {
        let bytes = postcard::to_allocvec(&grant).unwrap_or_default(); // WHY: infallible -- Grant is fixed-size byte arrays, a bounded Vec<Capability>, and u64 fields; postcard cannot fail encoding it
        let signature: Signature = issuer_key.sign(&bytes);
        Self { grant, signature }
    }

    /// The signed payload bytes (what the signature covers).
    fn signed_bytes(&self) -> Vec<u8> {
        postcard::to_allocvec(&self.grant).unwrap_or_default() // WHY: infallible -- see SignedGrant::issue
    }

    /// Verify the grant against the expected device at `now_ms`.
    ///
    /// # Errors
    ///
    /// [`GrantError::BadSignature`] if the signature does not verify under
    /// the grant's issuer key, [`GrantError::Expired`] if `now_ms` is at or
    /// past the expiry, [`GrantError::WrongDevice`] if the subject is not
    /// `expected_device`.
    pub fn verify(&self, expected_device: &[u8; 32], now_ms: u64) -> Result<&Grant, GrantError> {
        let Ok(issuer_key) = VerifyingKey::from_bytes(&self.grant.issuer) else {
            return Err(GrantError::BadSignature);
        };
        if issuer_key
            .verify_strict(&self.signed_bytes(), &self.signature)
            .is_err()
        {
            return Err(GrantError::BadSignature);
        }
        if self.grant.subject != *expected_device {
            return Err(GrantError::WrongDevice);
        }
        if now_ms >= self.grant.expires_at_ms {
            return Err(GrantError::Expired {
                expired_at_ms: self.grant.expires_at_ms,
                now_ms,
            });
        }
        Ok(&self.grant)
    }

    /// The response-authentication key derived from the grant nonce (see
    /// module docs). Both endpoints derive it identically.
    pub fn response_key(&self) -> [u8; 32] {
        hkdf_sha256(&self.grant.nonce, b"metaxu-response-v1")
    }
}

/// HKDF-SHA256 extract+expand to a 32-byte key (single block).
pub fn hkdf_sha256(ikm: &[u8; 16], info: &[u8]) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    // extract: PRK = HMAC(salt=zero, IKM); expand: OKM = HMAC(PRK, info||0x01).
    let mut h =
        <Hmac<Sha256> as Mac>::new_from_slice(&[0u8; 32]).unwrap_or_else(|_| unreachable!()); // INVARIANT: RustCrypto hmac's new_from_slice never errs on any key
    h.update(ikm);
    let prk = h.finalize().into_bytes();
    let mut e = <Hmac<Sha256> as Mac>::new_from_slice(&prk).unwrap_or_else(|_| unreachable!()); // INVARIANT: RustCrypto hmac's new_from_slice never errs on any key
    e.update(info);
    e.update(&[0x01]);
    e.finalize().into_bytes().into()
}

/// HMAC-SHA256 over `parts` under `key` (response authentication).
pub fn response_mac(key: &[u8; 32], parts: &[&[u8]]) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut h = <Hmac<Sha256> as Mac>::new_from_slice(key).unwrap_or_else(|_| unreachable!()); // INVARIANT: RustCrypto hmac's new_from_slice never errs on any key
    for part in parts {
        h.update(part);
    }
    h.finalize().into_bytes().into()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::Capability;

    fn issuer_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn device_key() -> VerifyingKey {
        SigningKey::from_bytes(&[9u8; 32]).verifying_key()
    }

    fn grant(expires_at_ms: u64) -> Grant {
        Grant {
            issuer: issuer_key().verifying_key().to_bytes(),
            subject: device_key().to_bytes(),
            capabilities: alloc::vec![Capability::SmsSend],
            issued_at_ms: 1_000,
            expires_at_ms,
            nonce: [0xA5; 16],
        }
    }

    #[test]
    fn issue_and_verify_happy_path() {
        let signed = SignedGrant::issue(grant(10_000), &issuer_key());
        let verified = signed.verify(&device_key().to_bytes(), 5_000);
        assert!(verified.is_ok(), "a valid unexpired grant must verify");
        assert_eq!(
            verified.map(|g| &g.capabilities),
            Ok(&alloc::vec![Capability::SmsSend])
        );
    }

    #[test]
    fn wrong_device_rejects() {
        let signed = SignedGrant::issue(grant(10_000), &issuer_key());
        let other = [0xEE; 32];
        assert_eq!(
            signed.verify(&other, 5_000),
            Err(GrantError::WrongDevice),
            "a grant for device A must not authorize device B"
        );
    }

    #[test]
    fn expired_rejects_at_and_after_expiry() {
        let signed = SignedGrant::issue(grant(10_000), &issuer_key());
        assert_eq!(
            signed.verify(&device_key().to_bytes(), 10_000),
            Err(GrantError::Expired {
                expired_at_ms: 10_000,
                now_ms: 10_000,
            }),
            "at-expiry rejects (expiry is exclusive)"
        );
        assert!(matches!(
            signed.verify(&device_key().to_bytes(), 10_001),
            Err(GrantError::Expired { .. })
        ));
        assert!(signed.verify(&device_key().to_bytes(), 9_999).is_ok());
    }

    #[test]
    fn tampered_capability_rejects() {
        let mut signed = SignedGrant::issue(grant(10_000), &issuer_key());
        signed.grant.capabilities = alloc::vec![Capability::CallDial];
        assert_eq!(
            signed.verify(&device_key().to_bytes(), 5_000),
            Err(GrantError::BadSignature),
            "editing the signed capabilities must invalidate the signature"
        );
    }

    #[test]
    fn tampered_nonce_rejects_and_rekeys() {
        let a = SignedGrant::issue(grant(10_000), &issuer_key());
        let mut b = a.clone();
        b.grant.nonce = [0x5A; 16];
        assert_eq!(
            b.verify(&device_key().to_bytes(), 5_000),
            Err(GrantError::BadSignature)
        );
        assert_ne!(a.response_key(), b.response_key());
    }

    #[test]
    fn response_mac_is_keyed_and_deterministic() {
        let signed = SignedGrant::issue(grant(10_000), &issuer_key());
        let key = signed.response_key();
        let mac = response_mac(&key, &[b"response"]);
        assert_eq!(mac, response_mac(&key, &[b"response"]));
        let other = response_mac(&[0u8; 32], &[b"response"]);
        assert_ne!(mac, other, "a different key must produce a different MAC");
    }
}
