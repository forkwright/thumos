//! Boot-secret entropy policy: what a boot passphrase may be, and why.
//!
//! ## The decision this encodes
//!
//! `planning/design/principles.md` commits this device to resisting forensic
//! and state-level adversaries. That claim constrains the secret, not just the
//! KDF, because a work factor multiplies the cost of one guess while the input
//! space decides how many guesses there are. Against Argon2id at 64 MiB where
//! a high-end GPU sustains a few thousand guesses per second:
//!
//! | Secret | Space | One GPU | A state's cluster |
//! |--------|-------|---------|-------------------|
//! | 6 digits | 2^20 | minutes | seconds |
//! | 10 digits | 2^33 | weeks | under an hour |
//! | 12 digits | 2^40 | years | days |
//! | 6 words of 7776 | 2^77 | infeasible | infeasible |
//!
//! Ten digits is what the planning prose used to promise. It does not deliver
//! what the prose claims, and raising the numeric floor buys a different
//! adversary rather than a stronger position against the stated one. So the
//! policy is [`REQUIRED_WORDS`] words drawn from a [`WORDLIST_SIZE`]-word list
//! (#872).
//!
//! ## Why the secret is indices and the pad stays numeric
//!
//! The boot keypad's alphabet is digits (`kinit::boot_digit`); Star and Hash
//! are backspace and confirm. Text entry would need T9 disambiguation on the
//! one screen that must work before anything else does.
//!
//! It is not needed. Each word is identified by a fixed-width decimal index,
//! so the secret is entered as digits on the pad that already exists, and the
//! wordlist is what renders those indices *human-transcribable* for backup.
//! The entropy is identical either way — it is in the indices — so this buys
//! the full 2^77 with no change to the input path.
//!
//! ## Why the device generates it
//!
//! A user-chosen secret carries selection bias that no length requirement
//! removes; the entropy figures above assume uniform draws and are simply
//! wrong for a chosen one. [`generate`] draws every index from the kernel
//! CSPRNG and fails closed when entropy is unavailable, so the stated bit
//! count is a property of the mechanism rather than a hope about the user.

/// Words in the backing list. 7776 is 6^5 — the standard Diceware size, and
/// the size every established list (EFF's large list, BIP-39's 2048 aside)
/// is built to.
///
/// WARNING: this is the number the entropy claim is computed from. Changing
/// it without changing the list, or the list without this, silently restates
/// the security level.
pub(crate) const WORDLIST_SIZE: u32 = 7776;

/// Words in a boot secret.
pub(crate) const REQUIRED_WORDS: usize = 6;

/// Decimal digits per word index. `7775` is four digits, and the width is
/// fixed rather than minimal so an index is unambiguous without a separator
/// the numeric pad cannot type.
pub(crate) const DIGITS_PER_WORD: usize = 4;

/// Digits in a complete boot secret.
pub(crate) const SECRET_DIGITS: usize = REQUIRED_WORDS * DIGITS_PER_WORD;

/// The floor the policy enforces, in bits.
///
/// WHY stated as a constant rather than derived at the call site: this is the
/// number `principles.md` promises, and a promise that lives in two places
/// drifts. [`policy_meets_floor`] proves the configuration above actually
/// reaches it, so the constant cannot quietly diverge from what the mechanism
/// delivers.
pub(crate) const MIN_ENTROPY_BITS: u32 = 77;

/// Why a candidate boot secret was refused.
///
/// WHY refusal is typed rather than a bare `false` (#872): the acceptance
/// requires the failure be surfaced, and "too short" and "not a valid word
/// index" are different mistakes with different corrections. A caller that
/// cannot tell them apart can only say "wrong", which is what makes a floor
/// feel arbitrary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub(crate) enum SecretRejected {
    /// Fewer digits than a complete secret needs.
    TooShort {
        /// Digits entered.
        entered: usize,
    },
    /// More digits than a complete secret needs.
    TooLong {
        /// Digits entered.
        entered: usize,
    },
    /// A byte that is not an ASCII digit.
    NotNumeric,
    /// A four-digit group that is not a valid index into the wordlist.
    ///
    /// WHY this is refused rather than reduced modulo the list size: a
    /// reduction would map several typed values onto one word, so two
    /// different transcriptions would unlock the same device and the space
    /// would no longer be the size the entropy claim assumes.
    IndexOutOfRange {
        /// The offending word position, zero-based.
        word: usize,
        /// The value that is not an index.
        value: u32,
    },
}

/// Whether the configured policy actually reaches [`MIN_ENTROPY_BITS`].
///
/// Uses integer arithmetic over a floating log so this stays `const` and
/// exact: `WORDLIST_SIZE^REQUIRED_WORDS >= 2^MIN_ENTROPY_BITS` is checked by
/// comparing against the threshold rather than by computing a logarithm.
pub(crate) const fn policy_meets_floor() -> bool {
    // 2^77 does not fit in u64, so compare in u128.
    let mut space: u128 = 1;
    let mut i = 0;
    while i < REQUIRED_WORDS {
        space *= WORDLIST_SIZE as u128;
        i += 1;
    }
    space >= 1u128 << MIN_ENTROPY_BITS
}

/// Parse a typed boot secret into its word indices, enforcing the policy.
///
/// # Errors
///
/// Returns [`SecretRejected`] describing which rule the input broke. No
/// partial result is produced: a secret is a complete valid secret or it is
/// refused.
pub(crate) fn parse_secret(digits: &[u8]) -> Result<[u32; REQUIRED_WORDS], SecretRejected> {
    if digits.len() < SECRET_DIGITS {
        return Err(SecretRejected::TooShort {
            entered: digits.len(),
        });
    }
    if digits.len() > SECRET_DIGITS {
        return Err(SecretRejected::TooLong {
            entered: digits.len(),
        });
    }

    let mut words = [0u32; REQUIRED_WORDS];
    for (word, slot) in words.iter_mut().enumerate() {
        let mut value: u32 = 0;
        for offset in 0..DIGITS_PER_WORD {
            let byte = digits.get(word * DIGITS_PER_WORD + offset).copied().ok_or(
                SecretRejected::TooShort {
                    entered: digits.len(),
                },
            )?;
            if !byte.is_ascii_digit() {
                return Err(SecretRejected::NotNumeric);
            }
            value = value * 10 + u32::from(byte - b'0');
        }
        if value >= WORDLIST_SIZE {
            return Err(SecretRejected::IndexOutOfRange { word, value });
        }
        *slot = value;
    }
    Ok(words)
}

/// Draw a fresh boot secret from the kernel CSPRNG, written as its digit
/// form into `out`.
///
/// # Errors
///
/// Returns `()` when the CSPRNG is unseeded. The buffer is left untouched, so
/// a caller cannot mistake a refusal for a weak secret.
pub(crate) fn generate(out: &mut [u8; SECRET_DIGITS]) -> Result<(), ()> {
    let mut words = [0u32; REQUIRED_WORDS];
    for slot in &mut words {
        *slot = uniform_index()?;
    }
    for (word, index) in words.iter().enumerate() {
        let mut value = *index;
        for offset in (0..DIGITS_PER_WORD).rev() {
            if let Some(byte) = out.get_mut(word * DIGITS_PER_WORD + offset) {
                *byte = b'0' + u8::try_from(value % 10).unwrap_or(0);
            }
            value /= 10;
        }
    }
    Ok(())
}

/// One uniform index in `0..WORDLIST_SIZE`, by rejection sampling.
///
/// WHY rejection rather than `% WORDLIST_SIZE` (#872): 2^32 is not a multiple
/// of 7776, so the modulo maps slightly more raw values onto the low indices.
/// The bias is tiny per draw and it is exactly the kind that compounds over
/// six draws and invalidates the bit count this module promises. Rejecting
/// the unusable tail costs an occasional extra draw and keeps the
/// distribution flat.
fn uniform_index() -> Result<u32, ()> {
    // Largest multiple of WORDLIST_SIZE that fits in u32; raw values at or
    // above it are the biased tail.
    let limit = (u32::MAX / WORDLIST_SIZE) * WORDLIST_SIZE;
    loop {
        let mut raw = [0u8; 4];
        crate::csprng::kernel_random_bytes(&mut raw).map_err(|_| ())?;
        let value = u32::from_le_bytes(raw);
        if value < limit {
            return Ok(value % WORDLIST_SIZE);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A valid secret: six in-range indices, fixed width.
    fn valid_digits() -> [u8; SECRET_DIGITS] {
        *b"000107750001000200030004"
    }

    #[test]
    fn the_configured_policy_reaches_the_stated_floor() {
        // #872: MIN_ENTROPY_BITS is what principles.md promises. This proves
        // the word count and list size actually deliver it, so the constant
        // cannot drift into being a claim about a configuration that does not
        // reach it.
        assert!(
            policy_meets_floor(),
            "{REQUIRED_WORDS} words of {WORDLIST_SIZE} must reach {MIN_ENTROPY_BITS} bits"
        );
    }

    #[test]
    fn a_numeric_secret_of_the_old_floor_is_refused() {
        // The superseded policy accepted six digits. Under this one that is
        // not a short secret, it is not a secret at all.
        assert_eq!(
            parse_secret(b"123456"),
            Err(SecretRejected::TooShort { entered: 6 })
        );
    }

    #[test]
    fn a_ten_digit_secret_is_refused() {
        // Ten digits is what the planning prose used to call a locked defence
        // against state-level forensics. It is ~2^33 and is refused.
        assert_eq!(
            parse_secret(b"0123456789"),
            Err(SecretRejected::TooShort { entered: 10 })
        );
    }

    #[test]
    fn a_complete_secret_parses_to_its_indices() {
        let words = parse_secret(&valid_digits()).unwrap_or([0; REQUIRED_WORDS]);
        assert_eq!(words, [1, 7750, 1, 2, 3, 4]);
    }

    #[test]
    fn an_index_past_the_wordlist_is_refused_not_reduced() {
        // WHY this matters more than it looks: reducing modulo the list size
        // would map several typed values onto one word, so two different
        // transcriptions would unlock the same device and the real space
        // would be smaller than the entropy claim assumes.
        let mut digits = valid_digits();
        digits[0..4].copy_from_slice(b"7776");
        assert_eq!(
            parse_secret(&digits),
            Err(SecretRejected::IndexOutOfRange {
                word: 0,
                value: 7776
            })
        );
    }

    #[test]
    fn the_highest_valid_index_is_accepted() {
        // The bound is exclusive at 7776, so 7775 must still parse -- a
        // tightening that lost the top word would shrink the space silently.
        let mut digits = valid_digits();
        digits[0..4].copy_from_slice(b"7775");
        let words = parse_secret(&digits).unwrap_or([0; REQUIRED_WORDS]);
        assert_eq!(words[0], 7775);
    }

    #[test]
    fn a_non_digit_byte_is_refused() {
        let mut digits = valid_digits();
        digits[5] = b'x';
        assert_eq!(parse_secret(&digits), Err(SecretRejected::NotNumeric));
    }

    #[test]
    fn an_overlong_secret_is_refused_rather_than_truncated() {
        // Truncating would accept a typo as a different valid secret, which
        // provisions a device with something the operator did not intend.
        let mut too_many = [b'0'; SECRET_DIGITS + 1];
        too_many[SECRET_DIGITS] = b'1';
        assert_eq!(
            parse_secret(&too_many),
            Err(SecretRejected::TooLong {
                entered: SECRET_DIGITS + 1
            })
        );
    }

    #[test]
    fn generation_fails_closed_when_entropy_is_unavailable() {
        // No seed_for_test call: the CSPRNG is unseeded in this process, and
        // a refusal must not leave a weak secret behind for a caller to use.
        let mut out = [0u8; SECRET_DIGITS];
        assert_eq!(generate(&mut out), Err(()));
        assert_eq!(out, [0u8; SECRET_DIGITS], "a refusal must not write");
    }

    #[test]
    fn a_generated_secret_satisfies_the_policy_that_parses_it() {
        // The two halves must agree: anything `generate` produces must be
        // something `parse_secret` accepts, or provisioning could create a
        // device its own boot path refuses to unlock.
        crate::csprng::seed_for_test(&[0x42u8; 32], &[0u8; 8], 0);
        let mut out = [0u8; SECRET_DIGITS];
        assert_eq!(generate(&mut out), Ok(()));
        assert!(
            parse_secret(&out).is_ok(),
            "a generated secret must parse: {out:?}"
        );
    }

    #[test]
    fn generation_does_not_repeat_itself() {
        crate::csprng::seed_for_test(&[0x42u8; 32], &[0u8; 8], 0);
        let mut first = [0u8; SECRET_DIGITS];
        let mut second = [0u8; SECRET_DIGITS];
        assert_eq!(generate(&mut first), Ok(()));
        assert_eq!(generate(&mut second), Ok(()));
        assert_ne!(
            first, second,
            "two draws must differ, or the CSPRNG is not being consumed"
        );
    }
}
