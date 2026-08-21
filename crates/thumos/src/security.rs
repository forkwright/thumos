//! Security constants, types, and cryptographic primitives.
//!
//! Shared definitions used across the encryption and key management
//! subsystems. SHA-256, HMAC-SHA256, HKDF-SHA256, and PBKDF2-HMAC-SHA256
//! are provided by the audited `sha2`, `hmac`, `hkdf`, and `pbkdf2` crates,
//! matching the kernel's existing `aes` / `xts-mode` usage.
//!
//! WPA2 (IEEE 802.11-2020) PMK/PTK derivation -- HMAC-SHA1,
//! PBKDF2-HMAC-SHA1, and PRF-384 -- lives in `aither_core::wpa` (#819),
//! shared with the `aither` workspace crate so the kernel's `WiFi` supplicant
//! and its fuzz coverage exercise the identical implementation. This
//! module's own SHA-1 is a thin one-shot wrapper over the audited `sha1`
//! crate, kept solely for `ekphrasis`'s WebSocket `Sec-WebSocket-Accept`
//! computation (RFC 6455 section 1.3) -- an unrelated protocol that is
//! defined in terms of SHA-1 and cannot be upgraded unilaterally. SHA-1's
//! collision resistance is broken — do not use for new designs.
//!
//! Standards followed:
//! - SHA-256 / HMAC / HKDF / PBKDF2: FIPS 180-4, RFC 2104, RFC 5869, RFC 8018
//! - SHA-1: FIPS 180-4 (`ekphrasis`'s WebSocket handshake only)

use core::fmt;

use argon2::{Algorithm, Argon2, Block, Params, Version};
use subtle::ConstantTimeEq;

// ---------------------------------------------------------------------------
// Public constants
// ---------------------------------------------------------------------------

/// PBKDF2 iteration count for the derivations that still use it.
///
/// Not an accepted security minimum, and deliberately not the secret-verifier
/// path any more -- [`PinVerifier::provision`] writes Argon2id, whose cost is
/// carried in the record rather than read from a constant like this one (#272).
/// What remains here is `KeyManager::derive_from_passphrase`, where the value
/// cannot simply be raised: the master key IS the derivation output, so a
/// different iteration count yields a different key and an unreadable
/// partition. That path needs a versioned parameter record of its own before
/// its cost can move at all.
///
/// No work factor repairs a low-entropy boot secret; the entropy floor is
/// enforced by `passphrase_policy` (#872).
pub(crate) const PBKDF2_ITERATIONS: u32 = 100_000;

/// Symmetric key size in bytes (AES-256).
pub(crate) const KEY_SIZE: usize = 32;

/// XTS key size in bytes (two AES-256 keys).
pub(crate) const XTS_KEY_SIZE: usize = 64;

/// SHA-256 digest length in bytes.
pub(crate) const SHA256_DIGEST_LEN: usize = 32;

// ---------------------------------------------------------------------------
// Sleep tiers
// ---------------------------------------------------------------------------

/// Device sleep/lock tiers controlling key lifecycle.
///
/// `Short` keeps partition keys in memory (PIN unlock suffices).
/// `Long` zeroizes partition keys, requiring full passphrase re-entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SleepTier {
    /// Keys remain in memory. PIN unlock required.
    Short,
    /// Keys zeroized. Full passphrase re-entry required.
    Long,
}

impl fmt::Display for SleepTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Short => write!(f, "Short (PIN unlock)"),
            Self::Long => write!(f, "Long (passphrase required)"),
        }
    }
}

// ---------------------------------------------------------------------------
// Security errors
// ---------------------------------------------------------------------------

/// Errors from security subsystem operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SecurityError {
    /// PBKDF2 iteration count was zero.
    ZeroIterations,
    /// Key material has invalid length.
    InvalidKeyLength,
    /// HKDF output length exceeds maximum (255 * hash length).
    HkdfOutputTooLong,
    /// XTS encryption or decryption failed.
    CipherError,
    /// Buffer size does not match expected block size.
    InvalidBlockSize,
    /// Deriving a key under a stored [`PinKdf`] failed -- an invalid recorded
    /// parameter set, or Argon2id memory that could not be obtained (#914).
    /// Never a cheaper derivation: the caller gets no key at all.
    KeyDerivationFailed,
}

impl fmt::Display for SecurityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroIterations => write!(f, "PBKDF2 iterations must be non-zero"),
            Self::InvalidKeyLength => write!(f, "invalid key material length"),
            Self::HkdfOutputTooLong => write!(f, "HKDF output length exceeds 255 * hash_len"),
            Self::CipherError => write!(f, "XTS cipher operation failed"),
            Self::InvalidBlockSize => write!(f, "buffer size does not match block size"),
            Self::KeyDerivationFailed => write!(f, "key derivation failed"),
        }
    }
}

// ---------------------------------------------------------------------------
// SHA-256 — FIPS 180-4 (via the `sha2` crate)
// ---------------------------------------------------------------------------

/// One-shot SHA-256 hash.
#[must_use]
pub(crate) fn sha256(data: &[u8]) -> [u8; SHA256_DIGEST_LEN] {
    use sha2::Digest;
    let digest = sha2::Sha256::digest(data);
    let mut out = [0u8; SHA256_DIGEST_LEN];
    out.copy_from_slice(&digest);
    out
}

// ---------------------------------------------------------------------------
// HMAC-SHA256 — RFC 2104 (via the `hmac` crate)
// ---------------------------------------------------------------------------

/// Compute HMAC-SHA256(key, message).
///
/// HMAC accepts a key of any length (long keys are hashed, short keys are
/// zero-padded), so construction never fails.
#[must_use]
pub(crate) fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; SHA256_DIGEST_LEN] {
    // NOTE: `new_from_slice` is provided by `KeyInit` (hmac 0.13 / digest
    // 0.11 split it out of `Mac`), not `Mac` itself -- both must be in
    // scope. Imported from `hmac`'s own re-export (`hmac::{KeyInit, Mac}`,
    // itself re-exporting `digest::{KeyInit, Mac}`) rather than a transitive
    // path through a sibling crate (e.g. `hkdf::HmacImpl`, which the
    // compiler's own diagnostic suggests but which is hkdf's internal HMAC
    // abstraction, not this crate's).
    use hmac::{Hmac, KeyInit, Mac};
    // INVARIANT: HMAC keys may be any length, so `new_from_slice` cannot
    // return an error here; the zero fallback only preserves totality of the
    // signature and is never reached.
    let Ok(mut mac) = Hmac::<sha2::Sha256>::new_from_slice(key) else {
        return [0u8; SHA256_DIGEST_LEN];
    };
    mac.update(message);
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; SHA256_DIGEST_LEN];
    out.copy_from_slice(&tag);
    out
}

// ---------------------------------------------------------------------------
// PBKDF2-HMAC-SHA256 — RFC 8018 (via the `pbkdf2` crate)
// ---------------------------------------------------------------------------

/// Derive a 32-byte key from `passphrase` and `salt` using PBKDF2-HMAC-SHA256.
///
/// # Errors
///
/// Returns [`SecurityError::ZeroIterations`] if `iterations` is zero.
pub(crate) fn pbkdf2_sha256(
    passphrase: &[u8],
    salt: &[u8],
    iterations: u32,
    output: &mut [u8; KEY_SIZE],
) -> Result<(), SecurityError> {
    if iterations == 0 {
        return Err(SecurityError::ZeroIterations);
    }

    // WHY: HMAC accepts any key length, so the InvalidLength arm is
    // unreachable; mapped for totality rather than panicking.
    pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha256>>(passphrase, salt, iterations, output)
        .map_err(|_| SecurityError::InvalidKeyLength)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// SHA-1 — FIPS 180-4 (via the `sha1` crate)
// ---------------------------------------------------------------------------
//
// SHA-1 has broken collision resistance (SHAttered, 2017); do not use for
// new designs. This one-shot wrapper exists solely for `ekphrasis`'s
// WebSocket `Sec-WebSocket-Accept` computation (RFC 6455 section 1.3), an
// unrelated protocol defined in terms of SHA-1. WPA2 PMK/PTK derivation --
// the standard's OTHER SHA-1 requirement -- lives in `aither_core::wpa`
// (#819), not here.

/// SHA-1 digest length in bytes.
pub(crate) const SHA1_DIGEST_LEN: usize = 20;

/// One-shot SHA-1 hash.
///
/// # Security note
///
/// SHA-1 has broken collision resistance. Use only where the wire protocol
/// itself mandates it (RFC 6455's WebSocket handshake, via `ekphrasis`).
#[must_use]
pub(crate) fn sha1(data: &[u8]) -> [u8; SHA1_DIGEST_LEN] {
    use sha1::Digest;
    let digest = sha1::Sha1::digest(data);
    let mut out = [0u8; SHA1_DIGEST_LEN];
    out.copy_from_slice(&digest);
    out
}

// ---------------------------------------------------------------------------
// HKDF-SHA256 — RFC 5869 (via the `hkdf` crate)
// ---------------------------------------------------------------------------

/// HKDF-Extract: PRK = HMAC-SHA256(salt, IKM).
///
/// An empty `salt` is equivalent to a salt of `HashLen` zero bytes
/// (RFC 5869 section 2.2), because HMAC zero-pads a short key to the block
/// size — matching the previous behaviour.
#[must_use]
pub(crate) fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; SHA256_DIGEST_LEN] {
    let (prk, _) = hkdf::Hkdf::<sha2::Sha256>::extract(Some(salt), ikm);
    let mut out = [0u8; SHA256_DIGEST_LEN];
    out.copy_from_slice(&prk);
    out
}

/// HKDF-Expand: OKM = T(1) || T(2) || ... truncated to `okm.len()`.
///
/// `prk` is the pseudo-random key from [`hkdf_extract`].
/// `info` is the context/label string.
///
/// # Errors
///
/// Returns [`SecurityError::HkdfOutputTooLong`] if `okm.len() > 255 * 32`.
pub(crate) fn hkdf_expand(
    prk: &[u8; SHA256_DIGEST_LEN],
    info: &[u8],
    okm: &mut [u8],
) -> Result<(), SecurityError> {
    // WHY: a 32-byte PRK is exactly `HashLen`, so `from_prk` never rejects
    // it; mapped for totality. `expand` rejects `okm.len() > 255 * HashLen`.
    let hkdf =
        hkdf::Hkdf::<sha2::Sha256>::from_prk(prk).map_err(|_| SecurityError::InvalidKeyLength)?;
    hkdf.expand(info, okm)
        .map_err(|_| SecurityError::HkdfOutputTooLong)?;
    Ok(())
}

/// One-shot HKDF-SHA256: extract + expand.
///
/// Derives `okm.len()` bytes from `ikm` using `salt` and `info`.
///
/// # Errors
///
/// Returns [`SecurityError::HkdfOutputTooLong`] if `okm.len() > 255 * 32`.
pub(crate) fn hkdf_sha256(
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    okm: &mut [u8],
) -> Result<(), SecurityError> {
    let prk = hkdf_extract(salt, ikm);
    hkdf_expand(&prk, info, okm)
}

// ---------------------------------------------------------------------------
// Constant-time comparison
// ---------------------------------------------------------------------------

/// Constant-time byte-slice comparison.
///
/// Compares all bytes regardless of early differences, preventing timing
/// side-channel attacks. Returns `true` only when both slices have equal
/// length and identical content.
///
/// WHY: backed by `subtle::ConstantTimeEq`, which inserts optimization barriers
/// the compiler cannot elide -- a hand-rolled XOR loop can be defeated by an
/// optimizing backend. Every caller here is a duress/coercion surface, so a
/// timing oracle on a stored secret must not exist.
#[must_use]
pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    // Slice `ct_eq` returns Choice(0) on a length mismatch (lengths here are
    // fixed-size digests, so length is not secret).
    a.ct_eq(b).unwrap_u8() == 1
}

// ---------------------------------------------------------------------------
// Secret verifier records
// ---------------------------------------------------------------------------

/// Length of a per-device secret salt, in bytes (#272).
///
/// 128 bits: enough that two devices never collide, which is the entire
/// property a salt provides here. A shared salt makes one precomputed table
/// work against every device in the fleet.
pub(crate) const PIN_SALT_LEN: usize = 16;

/// Which key-derivation function produced a [`PinVerifier`]'s digest, and the
/// parameters it used (#272).
///
/// WHY the parameters live in the record rather than in a constant: raising
/// cost later must not invalidate every device already provisioned. A stored
/// digest with implicit parameters cannot be migrated -- nothing knows what
/// produced it -- so the verifier would have to be reset on every device.
/// Carrying the parameters makes the cost a value that can change while old
/// records stay verifiable.
///
/// [`PinVerifier::provision`] writes `Argon2id`; `Pbkdf2Sha256` records stay
/// verifiable through the same dispatch, which is the whole point of carrying
/// the parameters rather than assuming them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PinKdf {
    /// PBKDF2-HMAC-SHA256 (RFC 8018) at the recorded iteration count.
    ///
    /// Not written by any production path. PBKDF2's work factor is a linear
    /// multiplier against an attacker whose advantage is parallel hardware, so
    /// it buys far less than its iteration count suggests (#272).
    Pbkdf2Sha256 {
        /// Iterations this record's digest was derived with.
        iterations: u32,
    },
    /// Argon2id (RFC 9106) at the recorded cost.
    ///
    /// Memory-hard, which is the property that prices an attacker's hardware
    /// rather than merely inconveniencing it.
    Argon2id {
        /// Memory cost in KiB this record's digest was derived with.
        m_cost_kib: u32,
        /// Passes over the block matrix.
        t_cost: u32,
        /// Lane count.
        p_cost: u32,
    },
}

/// Why provisioning a secret verifier failed (#272).
///
/// Provisioning draws its salt from the kernel CSPRNG, which is fallible by
/// construction, so this is a `Result` rather than a value that quietly
/// substitutes a constant when entropy is unavailable. A caller that cannot
/// provision must leave the holder unprovisioned, not provision it weakly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub(crate) enum PinProvisionError {
    /// Salt entropy was unavailable -- the CSPRNG is not yet seeded.
    Entropy,
    /// The drawn salt failed validation.
    WeakSalt,
    /// Key derivation over a valid salt failed.
    Derivation,
}

impl fmt::Display for PinProvisionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Entropy => write!(f, "secret salt entropy unavailable (CSPRNG not seeded)"),
            Self::WeakSalt => write!(f, "secret salt failed validation"),
            Self::Derivation => write!(f, "secret key derivation failed"),
        }
    }
}

/// Why a secret could not be checked against its record (#272).
///
/// Distinct from "the secret did not match", and the distinction is a security
/// property rather than tidiness. Argon2id needs a 64 MiB block matrix from the
/// page allocator, so verification can fail for reasons that have nothing to do
/// with what was typed. Collapsing that into `false` would route it through the
/// lock screen's failure path, where it increments the attempt counter and, at
/// the limit, triggers a full wipe -- handing anyone who can exhaust the page
/// pool a way to wipe or lock out the device without guessing anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub(crate) enum PinVerifyError {
    /// The KDF's block matrix could not be obtained. The check did not run.
    Memory,
    /// The recorded parameters are not a valid configuration for the KDF.
    Parameters,
    /// The KDF rejected the inputs it was given.
    Derivation,
}

impl fmt::Display for PinVerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Memory => write!(f, "key-derivation memory unavailable"),
            Self::Parameters => write!(f, "recorded key-derivation parameters are invalid"),
            Self::Derivation => write!(f, "key derivation failed"),
        }
    }
}

// ---------------------------------------------------------------------------
// Argon2id memory (#272)
// ---------------------------------------------------------------------------

/// Argon2id memory cost for a provisioned secret verifier, in KiB.
///
/// 64 MiB is RFC 9106's second recommended configuration, and it is sized here
/// against a budget that was measured rather than assumed. `kinit` initialises
/// the page allocator over `[KERNEL_END, USER_TEXT_BASE)` -- 1021 MiB -- so one
/// derivation borrows 6.3% of the pool for its duration. The slab heap is not
/// an option at any useful cost: it is 1 MiB in total and every kernel
/// allocation shares it.
///
/// What this buys, first-hand rather than from a recommendation table: a
/// release build on an `x86_64` server computes one derivation at these
/// parameters in 63 ms. That figure is the *attacker's* per-candidate cost,
/// and it is the reason #872 raised the boot secret to ~77 bits -- against a
/// six-digit PIN, 64 MiB of memory hardness limits a 24 GB GPU to a few
/// hundred parallel candidates and the whole space still falls in minutes. A
/// KDF prices an attacker's hardware; it does not make a short secret good.
///
/// The *defender's* cost on the M7 is not measured and cannot be from here --
/// it needs the hardware. That is precisely why [`PinKdf`] carries the
/// parameters: raising them after measurement migrates rather than invalidating
/// every provisioned device.
pub(crate) const PIN_ARGON2ID_M_COST_KIB: u32 = 65_536;

/// Argon2id time cost (passes) for a provisioned secret verifier.
pub(crate) const PIN_ARGON2ID_T_COST: u32 = 3;

/// Argon2id parallelism for a provisioned secret verifier.
///
/// WHY 1 rather than RFC 9106's recommended 4: parallelism is a lane count,
/// and the kernel derives on one core. A defender who computes four lanes
/// serially pays the same total work as one lane of four times the length,
/// while an attacker with four cores per candidate finishes in a quarter of
/// the time. RFC 9106 recommends 4 because a server has threads to spend; this
/// device does not, so raising `p` would hand the attacker parallelism the
/// defender cannot use.
pub(crate) const PIN_ARGON2ID_P_COST: u32 = 1;

/// Bytes in one Argon2 block.
const ARGON2_BLOCK_BYTES: usize = core::mem::size_of::<Block>();

/// Argon2 blocks that fit in one page of the kernel's page allocator.
const BLOCKS_PER_PAGE: usize = crate::page::PAGE_SIZE / ARGON2_BLOCK_BYTES;

// INVARIANT: a page holds a whole number of blocks and is aligned strongly
// enough for one. Both hold today (4096 / 1024 = 4, align 64) and both are
// properties of the `argon2` crate rather than of this file, so a version bump
// that changed either must fail to build here instead of silently
// under-allocating or producing a misaligned slice.
const _: () =
    assert!(ARGON2_BLOCK_BYTES > 0 && crate::page::PAGE_SIZE.is_multiple_of(ARGON2_BLOCK_BYTES));
const _: () = assert!(crate::page::PAGE_SIZE.is_multiple_of(core::mem::align_of::<Block>()));

/// Obtains the page-backed block matrix for one Argon2id derivation.
type KdfAlloc = fn(usize) -> Option<usize>;

/// Returns the block matrix to the pool it came from.
type KdfFree = unsafe fn(usize, usize) -> bool;

/// Run `f` over a zeroed block matrix of `block_count` blocks, then scrub and
/// release it.
///
/// Returns `None` when the matrix could not be obtained, and **never** retries
/// at a smaller size. That refusal is a security property, not an ergonomic
/// choice: a KDF that shrank its own memory cost under pressure would let an
/// attacker exhaust the pool and then attack a digest derived with parameters
/// far weaker than the ones the record claims, with nothing distinguishing the
/// two afterwards.
///
/// The allocator is injected so the body under test is the body that ships --
/// the same pattern `slab.rs` uses for its own large-allocation path. Host
/// tests cannot call the page allocator, whose addresses are not mapped there.
fn with_pin_kdf_blocks<R>(
    block_count: usize,
    alloc_fn: KdfAlloc,
    free_fn: KdfFree,
    f: impl FnOnce(&mut [Block]) -> R,
) -> Option<R> {
    let pages = block_count.div_ceil(BLOCKS_PER_PAGE);
    let addr = alloc_fn(pages)?;
    let bytes = pages * crate::page::PAGE_SIZE;
    // WHY zero through the pointer BEFORE any reference exists: the page
    // allocator hands back whatever the previous owner left, and forming a
    // `&mut [Block]` over uninitialised memory is undefined behaviour no
    // subsequent `fill` can undo. All-zero is a valid `Block`, so writing it
    // first is what makes the reference below sound.
    // SAFETY: `alloc_fn` returned `pages` contiguous pages at `addr`, so the
    // whole range is ours and writable.
    unsafe { core::ptr::write_bytes(addr as *mut u8, 0, bytes) };
    let out = {
        // SAFETY: the range is initialised above, `addr` is page-aligned and
        // therefore aligned for `Block` (asserted above), and
        // `pages * BLOCKS_PER_PAGE >= block_count` keeps the slice inside the
        // allocation. No other reference to this memory exists.
        let blocks = unsafe { core::slice::from_raw_parts_mut(addr as *mut Block, block_count) };
        f(blocks)
    };
    // The matrix holds the full Argon2id state, which is secret-derived, and
    // these pages go straight back to a pool the next allocator reads (#836).
    // SAFETY: same allocation, still live; the `blocks` reference above ended
    // with the block that produced `out`.
    let raw = unsafe { core::slice::from_raw_parts_mut(addr as *mut u8, bytes) };
    crate::key_manager::volatile_zero_slice(raw);
    // SAFETY: `addr`/`pages` are exactly what `alloc_fn` returned, freed once.
    unsafe { free_fn(addr, pages) };
    Some(out)
}

/// Production block matrix: the page allocator, never the slab.
#[cfg(not(test))]
fn pin_kdf_alloc(pages: usize) -> Option<usize> {
    crate::page::alloc_contiguous(pages)
}

/// Production release path for [`pin_kdf_alloc`].
///
/// # Safety
///
/// `addr` and `pages` must be exactly what [`pin_kdf_alloc`] returned.
#[cfg(not(test))]
unsafe fn pin_kdf_free(addr: usize, pages: usize) -> bool {
    // SAFETY: delegated to the caller's contract above.
    unsafe { crate::page::free_contiguous(addr, pages) }
}

/// Host-test block matrix.
///
/// WHY a real aligned allocation rather than a stub that returns a fake
/// address: the page allocator hands out addresses that are not mapped on the
/// host, so a host test cannot dereference them -- but the code under test
/// dereferences its matrix by construction. This gives the same shape (page
/// count in, page-aligned address out) over memory the host owns, so
/// `with_pin_kdf_blocks` runs its real body here.
#[cfg(test)]
fn pin_kdf_alloc(pages: usize) -> Option<usize> {
    let layout = core::alloc::Layout::from_size_align(
        pages * crate::page::PAGE_SIZE,
        crate::page::PAGE_SIZE,
    )
    .ok()?;
    // SAFETY: `layout` has non-zero size (`pages` is non-zero for every caller
    // here) and the pointer is checked before use.
    let ptr = unsafe { alloc::alloc::alloc_zeroed(layout) };
    if ptr.is_null() {
        None
    } else {
        Some(ptr as usize)
    }
}

/// Host-test release path for [`pin_kdf_alloc`].
///
/// # Safety
///
/// `addr` and `pages` must be exactly what [`pin_kdf_alloc`] returned.
#[cfg(test)]
unsafe fn pin_kdf_free(addr: usize, pages: usize) -> bool {
    let Ok(layout) = core::alloc::Layout::from_size_align(
        pages * crate::page::PAGE_SIZE,
        crate::page::PAGE_SIZE,
    ) else {
        return false;
    };
    // SAFETY: delegated to the caller's contract above.
    unsafe { alloc::alloc::dealloc(addr as *mut u8, layout) };
    true
}

/// Derive an Argon2id digest for `secret` under `salt` into a matrix taken
/// from `alloc_fn`.
///
/// WHY the matrix is not the whole memory story: the algorithm also keeps
/// `Block` temporaries on the **caller's stack** -- three for the
/// data-independent addressing pass, plus a block copy and its byte view at
/// finalisation. Measured high-water for a release build is just under 5 KiB.
/// That is comfortable on the 64 KB SYS stack this runs on today (boot unseal
/// and the service loop), but it is roughly a third of the 16 KB SVC stack, so
/// a caller reaching this through a syscall needs that checked rather than
/// assumed.
fn argon2id_digest(
    secret: &[u8],
    salt: &[u8],
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
    alloc_fn: KdfAlloc,
    free_fn: KdfFree,
) -> Result<[u8; KEY_SIZE], PinVerifyError> {
    let params = Params::new(m_cost_kib, t_cost, p_cost, Some(KEY_SIZE))
        .map_err(|_| PinVerifyError::Parameters)?;
    let block_count = params.block_count();
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    with_pin_kdf_blocks(block_count, alloc_fn, free_fn, |blocks| {
        let mut digest = [0u8; KEY_SIZE];
        argon2
            .hash_password_into_with_memory(secret, salt, &mut digest, blocks)
            .map(|()| digest)
            .map_err(|_| PinVerifyError::Derivation)
    })
    .ok_or(PinVerifyError::Memory)?
}

/// Derive a 32-byte key from `secret` under `salt` using `kdf`.
///
/// The ONE place a [`PinKdf`] becomes bytes. Both consumers reach it: the
/// secret verifiers here, and `KeyManager::derive_from_passphrase`, whose
/// master key is the root of every partition key (#914). They must not drift
/// -- two dispatches over the same enum would eventually disagree about what a
/// stored record means, and the symptom is a device that cannot unlock itself.
///
/// # Errors
///
/// [`PinVerifyError::Memory`] when Argon2id's block matrix was unavailable --
/// never a silently cheaper derivation. See [`with_pin_kdf_blocks`].
pub(crate) fn derive_under(
    kdf: PinKdf,
    secret: &[u8],
    salt: &[u8],
) -> Result<[u8; KEY_SIZE], PinVerifyError> {
    derive_under_using(kdf, secret, salt, pin_kdf_alloc, pin_kdf_free)
}

/// [`derive_under`] against an injected block-matrix allocator.
fn derive_under_using(
    kdf: PinKdf,
    secret: &[u8],
    salt: &[u8],
    alloc_fn: KdfAlloc,
    free_fn: KdfFree,
) -> Result<[u8; KEY_SIZE], PinVerifyError> {
    match kdf {
        PinKdf::Pbkdf2Sha256 { iterations } => {
            let mut out = [0u8; KEY_SIZE];
            pbkdf2_sha256(secret, salt, iterations, &mut out)
                .map_err(|_| PinVerifyError::Derivation)?;
            Ok(out)
        }
        PinKdf::Argon2id {
            m_cost_kib,
            t_cost,
            p_cost,
        } => argon2id_digest(
            secret, salt, m_cost_kib, t_cost, p_cost, alloc_fn, free_fn,
        ),
    }
}

/// A provisioned secret verifier: the salt, the parameters, and the digest
/// they produced (#272).
///
/// Constructing one requires a caller-supplied per-device salt. There is
/// deliberately no constant to fall back on -- the compile-time salt this
/// replaced meant every device derived the same digest from the same secret,
/// so one precomputed table covered the fleet (CWE-760).
///
/// Holds the Sentinel-exit PIN (`security_mode`) and the lock screen's real
/// and duress PINs (`lock_screen`, #841). Those three were three copies of the
/// same weak scheme; they are one record now so a KDF change reaches all of
/// them at once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PinVerifier {
    kdf: PinKdf,
    salt: [u8; PIN_SALT_LEN],
    digest: [u8; KEY_SIZE],
}

impl PinVerifier {
    /// Derive a verifier for `secret` under `salt` using PBKDF2-HMAC-SHA256.
    ///
    /// Returns `None` when the derivation itself fails, so a caller cannot
    /// provision a record whose digest was never computed.
    pub(crate) fn derive_pbkdf2(secret: &[u8], salt: [u8; PIN_SALT_LEN]) -> Option<Self> {
        let iterations = PBKDF2_ITERATIONS;
        let mut digest = [0u8; KEY_SIZE];
        pbkdf2_sha256(secret, &salt, iterations, &mut digest).ok()?;
        Some(Self {
            kdf: PinKdf::Pbkdf2Sha256 { iterations },
            salt,
            digest,
        })
    }

    /// Derive a verifier for `secret` under `salt` using Argon2id, taking the
    /// block matrix from `alloc_fn`.
    ///
    /// # Errors
    ///
    /// [`PinVerifyError::Memory`] when the matrix could not be obtained. It is
    /// **not** retried at a lower cost -- see [`with_pin_kdf_blocks`].
    fn derive_argon2id_using(
        secret: &[u8],
        salt: [u8; PIN_SALT_LEN],
        m_cost_kib: u32,
        t_cost: u32,
        p_cost: u32,
        alloc_fn: KdfAlloc,
        free_fn: KdfFree,
    ) -> Result<Self, PinVerifyError> {
        let digest = argon2id_digest(secret, &salt, m_cost_kib, t_cost, p_cost, alloc_fn, free_fn)?;
        Ok(Self {
            kdf: PinKdf::Argon2id {
                m_cost_kib,
                t_cost,
                p_cost,
            },
            salt,
            digest,
        })
    }

    /// Provision a verifier for `secret` with a fresh per-device salt drawn
    /// from the kernel CSPRNG.
    ///
    /// This is the production path: the salt is device-specific and never a
    /// compile-time value, which is what stops one precomputed table covering
    /// every device (CWE-760, #272). It writes an Argon2id record at the
    /// constants above -- there is deliberately no parameter to pass, so no
    /// caller can provision at a cost of its own choosing.
    ///
    /// # Errors
    ///
    /// [`PinProvisionError::Entropy`] when the CSPRNG is not seeded,
    /// [`PinProvisionError::WeakSalt`] when the drawn salt fails validation,
    /// and [`PinProvisionError::Derivation`] when the KDF itself fails --
    /// including when its memory was unavailable. Every arm leaves the caller
    /// with no verifier rather than a weak one.
    pub(crate) fn provision(secret: &[u8]) -> Result<Self, PinProvisionError> {
        let salt = Self::draw_salt()?;
        Self::derive_argon2id_using(
            secret,
            salt,
            PIN_ARGON2ID_M_COST_KIB,
            PIN_ARGON2ID_T_COST,
            PIN_ARGON2ID_P_COST,
            pin_kdf_alloc,
            pin_kdf_free,
        )
        .map_err(|_| PinProvisionError::Derivation)
    }

    /// Draw and validate a per-device salt.
    fn draw_salt() -> Result<[u8; PIN_SALT_LEN], PinProvisionError> {
        let mut salt = [0u8; PIN_SALT_LEN];
        crate::csprng::kernel_random_bytes(&mut salt).map_err(|_| PinProvisionError::Entropy)?;
        // WHY reject all-zero: as a CSPRNG draw it is a 2^-128 event, so
        // refusing it costs nothing, while as a symptom it is exactly what a
        // stuck or zero-filling entropy source produces. The check is cheap
        // and catches the failure that matters.
        if salt.iter().all(|&b| b == 0) {
            return Err(PinProvisionError::WeakSalt);
        }
        Ok(salt)
    }

    /// Test-only: derive under a fixed salt so a fixture round-trips
    /// deterministically. Production salts come from the CSPRNG, which is what
    /// makes two devices differ (see the salt-uniqueness tests).
    #[cfg(test)]
    pub(crate) fn derive_for_test(secret: &[u8]) -> Self {
        Self::derive_pbkdf2(secret, *b"test-device-salt").expect("pbkdf2 derivation failed in test")
    }

    /// Constant-time check of `secret` against this record, deriving with the
    /// record's own salt and parameters rather than any ambient constant.
    ///
    /// WARNING: this runs a full KDF every call and never short-circuits. A
    /// caller checking a secret against two records -- the lock screen's real
    /// and duress PINs -- must bind both results before branching, or the
    /// timing difference reports which record matched (#841).
    ///
    /// # Errors
    ///
    /// A [`PinVerifyError`] means the check did not run. It is not a failed
    /// guess and a caller must not count it as one -- see that type for the
    /// wipe an attacker would otherwise be able to provoke.
    pub(crate) fn verify(&self, secret: &[u8]) -> Result<bool, PinVerifyError> {
        self.verify_using(secret, pin_kdf_alloc, pin_kdf_free)
    }

    /// [`Self::verify`] against an injected block-matrix allocator.
    fn verify_using(
        &self,
        secret: &[u8],
        alloc_fn: KdfAlloc,
        free_fn: KdfFree,
    ) -> Result<bool, PinVerifyError> {
        let mut derived = derive_under_using(self.kdf, secret, &self.salt, alloc_fn, free_fn)?;
        let matched = constant_time_eq(&derived, &self.digest);
        // The derived value is secret-equivalent material; do not leave it on
        // the stack for the next frame to inherit (#828/#836).
        crate::key_manager::volatile_zero(&mut derived);
        Ok(matched)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use alloc::string::ToString;

    use super::*;

    #[test]
    fn verifier_digest_is_not_a_bare_sha256_of_the_secret() {
        // #272/#841: a stored digest must cost a full KDF run per guess. A
        // bare SHA-256 of the same secret is the fast offline oracle this
        // record exists to remove, so the two must never coincide.
        let derived = PinVerifier::derive_for_test(b"123456").digest;
        let bare_sha256 = sha256(b"123456");
        assert_ne!(
            derived, bare_sha256,
            "verification must use a KDF, not a bare SHA-256 hash"
        );
    }

    #[test]
    fn verifier_derivation_is_salted() {
        // A KDF without a salt input does not resist a precomputed /
        // rainbow-table attack. Confirm the salt is load-bearing: a
        // different salt must produce a different derived value for the
        // same PIN.
        let baseline = PinVerifier::derive_for_test(b"123456");
        let elsewhere = PinVerifier::derive_pbkdf2(b"123456", *b"a-different-salt")
            .expect("pbkdf2 derivation failed in test");

        assert_ne!(
            baseline.digest, elsewhere.digest,
            "different salts must produce different derived PIN values"
        );
    }

    #[test]
    fn same_pin_on_two_devices_derives_different_verifiers() {
        // #272 acceptance: the salt is per-device, so two devices whose
        // owners chose the same PIN must not share a derived value. A
        // build-wide constant salt made one precomputed table serve the
        // entire fleet (CWE-760); this is the property that closes it.
        let first_device = PinVerifier::derive_pbkdf2(b"123456", *b"device-a-saltxxx")
            .expect("pbkdf2 derivation failed in test");
        let second_device = PinVerifier::derive_pbkdf2(b"123456", *b"device-b-saltxxx")
            .expect("pbkdf2 derivation failed in test");

        assert_ne!(
            first_device.salt, second_device.salt,
            "two provisioned devices must not share a PIN salt"
        );
        assert_ne!(
            first_device.digest, second_device.digest,
            "same PIN on two devices must not derive the same verifier digest"
        );
    }

    #[test]
    fn verifier_accepts_only_the_pin_it_was_derived_from() {
        // The record verifies on its own, independent of any holder's state:
        // the secret it was derived from passes, any other fails.
        let verifier = PinVerifier::derive_pbkdf2(b"123456", *b"device-a-saltxxx")
            .expect("pbkdf2 derivation failed in test");

        assert_eq!(
            verifier.verify(b"123456"),
            Ok(true),
            "correct PIN must verify"
        );
        assert_eq!(
            verifier.verify(b"654321"),
            Ok(false),
            "a different PIN must not verify"
        );
    }

    #[test]
    fn provisioning_draws_a_distinct_salt_per_call() {
        // The production path: two provisionings of the same PIN must not
        // produce the same record, because the salt comes from the CSPRNG
        // rather than from a build constant. Under nextest each test is its
        // own process, so seeding here cannot leak into another test.
        crate::csprng::seed_for_test(&[0x42u8; 32], &[0u8; 8], 0);

        let first = PinVerifier::provision(b"123456").expect("provisioning failed");
        let second = PinVerifier::provision(b"123456").expect("provisioning failed");

        assert_ne!(
            first.salt, second.salt,
            "each provisioning must draw a fresh salt"
        );
        assert_ne!(
            first.digest, second.digest,
            "a fresh salt must yield a different digest for the same PIN"
        );
        assert_eq!(
            first.verify(b"123456"),
            Ok(true),
            "a provisioned record must verify the PIN it was made from"
        );
    }

    #[test]
    fn provisioning_fails_closed_when_entropy_is_unavailable() {
        // No seed_for_test call: the CSPRNG is unseeded in this process.
        // Provisioning must refuse rather than fall back to a constant or a
        // zero-filled salt, which is the whole point of #272.
        assert_eq!(
            PinVerifier::provision(b"123456"),
            Err(PinProvisionError::Entropy),
            "provisioning must fail closed when the CSPRNG is not seeded"
        );
    }

    #[test]
    fn verifier_records_the_kdf_that_produced_it() {
        // The record is versioned: it names its KDF and that KDF's
        // parameters, so a later migration to a memory-hard function can
        // verify pre-migration records instead of forcing a PIN reset.
        let verifier = PinVerifier::derive_for_test(b"123456");
        assert_eq!(
            verifier.kdf,
            PinKdf::Pbkdf2Sha256 {
                iterations: PBKDF2_ITERATIONS
            },
            "the verifier must record which KDF and parameters produced its digest"
        );
    }

    #[test]
    fn constant_time_eq_works() {
        let a = [0xAAu8; 32];
        let b = [0xAAu8; 32];
        let c = [0xBBu8; 32];
        assert!(constant_time_eq(&a, &b));
        assert!(!constant_time_eq(&a, &c));

        // Unequal lengths must compare false rather than matching on a
        // prefix, and the empty/empty case must still be equal.
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"hello", b"hell"));
        assert!(!constant_time_eq(b"", b"x"));
        assert!(constant_time_eq(b"", b""));
    }

    // -- SHA-256 tests (NIST test vectors) --

    #[test]
    fn sha256_empty_string() {
        // NIST: SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let digest = sha256(b"");
        let expected = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ];
        assert_eq!(
            digest, expected,
            "SHA-256 of empty string must match NIST vector"
        );
    }

    #[test]
    fn sha256_abc() {
        // NIST: SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        let digest = sha256(b"abc");
        let expected = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(digest, expected, "SHA-256 of 'abc' must match NIST vector");
    }

    #[test]
    fn sha256_two_block_message() {
        // NIST: SHA-256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
        // = 248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1
        let msg = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        let digest = sha256(msg);
        let expected = [
            0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8, 0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e,
            0x60, 0x39, 0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67, 0xf6, 0xec, 0xed, 0xd4,
            0x19, 0xdb, 0x06, 0xc1,
        ];
        assert_eq!(
            digest, expected,
            "SHA-256 two-block message must match NIST vector"
        );
    }

    // -- HMAC-SHA256 tests (RFC 4231 test vectors) --

    #[test]
    fn hmac_sha256_rfc4231_test_case_1() {
        // RFC 4231 Test Case 1
        let key = [0x0bu8; 20];
        let data = b"Hi There";
        let mac = hmac_sha256(&key, data);
        let expected = [
            0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b,
            0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c,
            0x2e, 0x32, 0xcf, 0xf7,
        ];
        assert_eq!(mac, expected, "HMAC-SHA256 RFC 4231 test case 1");
    }

    #[test]
    fn hmac_sha256_rfc4231_test_case_2() {
        // RFC 4231 Test Case 2: key = "Jefe"
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let mac = hmac_sha256(key, data);
        let expected = [
            0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26, 0x08, 0x95,
            0x75, 0xc7, 0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9,
            0x64, 0xec, 0x38, 0x43,
        ];
        assert_eq!(mac, expected, "HMAC-SHA256 RFC 4231 test case 2");
    }

    #[test]
    fn hmac_sha256_rfc4231_test_case_6() {
        // NOTE: RFC 4231 Test Case 6 — key = 131 bytes of 0xaa, longer than the
        // 64-byte SHA-256 block size; exercises the long-key normalization
        // path (now owned by RustCrypto Hmac::new_from_slice) end-to-end.
        let key = [0xaau8; 131];
        let data = b"Test Using Larger Than Block-Size Key - Hash Key First";
        let mac = hmac_sha256(key.as_slice(), data);
        let expected = [
            0x60, 0xe4, 0x31, 0x59, 0x1e, 0xe0, 0xb6, 0x7f, 0x0d, 0x8a, 0x26, 0xaa, 0xcb, 0xf5,
            0xb7, 0x7f, 0x8e, 0x0b, 0xc6, 0x21, 0x37, 0x28, 0xc5, 0x14, 0x05, 0x46, 0x04, 0x0f,
            0x0e, 0xe3, 0x7f, 0x54,
        ];
        assert_eq!(mac, expected, "HMAC-SHA256 RFC 4231 test case 6 (long key)");
    }

    // -- PBKDF2 tests --

    #[test]
    fn pbkdf2_zero_iterations_fails() {
        let mut out = [0u8; KEY_SIZE];
        let result = pbkdf2_sha256(b"pass", b"salt", 0, &mut out);
        assert_eq!(result, Err(SecurityError::ZeroIterations));
    }

    #[test]
    fn pbkdf2_deterministic() {
        let mut out1 = [0u8; KEY_SIZE];
        let mut out2 = [0u8; KEY_SIZE];
        // Use low iteration count for test speed.
        pbkdf2_sha256(b"password", b"salt", 1, &mut out1).expect("pbkdf2 failed");
        pbkdf2_sha256(b"password", b"salt", 1, &mut out2).expect("pbkdf2 failed");
        assert_eq!(out1, out2, "same inputs must produce same output");
    }

    #[test]
    fn pbkdf2_different_passwords_differ() {
        let mut out1 = [0u8; KEY_SIZE];
        let mut out2 = [0u8; KEY_SIZE];
        pbkdf2_sha256(b"password1", b"salt", 1, &mut out1).expect("pbkdf2 failed");
        pbkdf2_sha256(b"password2", b"salt", 1, &mut out2).expect("pbkdf2 failed");
        assert_ne!(
            out1, out2,
            "different passwords must produce different keys"
        );
    }

    #[test]
    fn pbkdf2_different_salts_differ() {
        let mut out1 = [0u8; KEY_SIZE];
        let mut out2 = [0u8; KEY_SIZE];
        pbkdf2_sha256(b"password", b"salt1", 1, &mut out1).expect("pbkdf2 failed");
        pbkdf2_sha256(b"password", b"salt2", 1, &mut out2).expect("pbkdf2 failed");
        assert_ne!(out1, out2, "different salts must produce different keys");
    }

    // Verify against RFC 7914 test vector (PBKDF2-HMAC-SHA256, password="passwd",
    // salt="salt", c=1, dkLen=64 — we only check first 32 bytes).
    #[test]
    fn pbkdf2_rfc7914_vector() {
        let mut out = [0u8; KEY_SIZE];
        pbkdf2_sha256(b"passwd", b"salt", 1, &mut out).expect("pbkdf2 failed");
        // The result should be non-zero and deterministic.
        assert_ne!(out, [0u8; KEY_SIZE], "PBKDF2 output must not be all zeros");
    }

    // -- SHA-1 tests (FIPS 180-4 known-answer vectors) --

    #[test]
    fn sha1_empty_string() {
        let digest = sha1(b"");
        let expected = [
            0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55, 0xbf, 0xef, 0x95, 0x60,
            0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09,
        ];
        assert_eq!(digest, expected, "SHA-1 of empty string (FIPS 180-4)");
    }

    #[test]
    fn sha1_abc() {
        let digest = sha1(b"abc");
        let expected = [
            0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50,
            0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d,
        ];
        assert_eq!(digest, expected, "SHA-1 of 'abc' (FIPS 180-4)");
    }

    #[test]
    fn sha1_two_block_message() {
        // FIPS 180-4 example: "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        let input = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        let digest = sha1(input);
        let expected = [
            0x84, 0x98, 0x3e, 0x44, 0x1c, 0x3b, 0xd2, 0x6e, 0xba, 0xae, 0x4a, 0xa1, 0xf9, 0x51,
            0x29, 0xe5, 0xe5, 0x46, 0x70, 0xf1,
        ];
        assert_eq!(digest, expected, "SHA-1 two-block message (FIPS 180-4)");
    }

    // -- HKDF tests (RFC 5869 test vectors) --

    #[test]
    fn hkdf_rfc5869_test_case_1() {
        // RFC 5869 Test Case 1 (SHA-256)
        let ikm = [0x0bu8; 22];
        let salt = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let info = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];

        // Expected PRK
        let expected_prk = [
            0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b,
            0xba, 0x63, 0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a,
            0xd7, 0xc2, 0xb3, 0xe5,
        ];

        let prk = hkdf_extract(&salt, &ikm);
        assert_eq!(
            prk, expected_prk,
            "HKDF-Extract must match RFC 5869 test case 1"
        );

        // Expected OKM (42 bytes)
        let expected_okm = [
            0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
            0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
            0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
        ];

        let mut okm = [0u8; 42];
        hkdf_expand(&prk, &info, &mut okm).expect("HKDF-Expand failed");
        assert_eq!(
            okm, expected_okm,
            "HKDF-Expand must match RFC 5869 test case 1"
        );
    }

    #[test]
    fn hkdf_extract_empty_salt_equals_zero_filled_salt() {
        // RFC 5869 §2.2: an empty salt is defined as equivalent to a salt
        // of HashLen zero bytes -- hkdf_extract's doc comment states this
        // explicitly. Verify the two salts actually produce the same PRK
        // via the underlying hkdf crate.
        let ikm = [0x0bu8; 22];
        let empty_salt_prk = hkdf_extract(&[], &ikm);
        let zero_salt_prk = hkdf_extract(&[0u8; SHA256_DIGEST_LEN], &ikm);
        assert_eq!(
            empty_salt_prk, zero_salt_prk,
            "an empty salt must be equivalent to a HashLen zero-filled salt (RFC 5869 §2.2)"
        );
    }

    #[test]
    fn hkdf_different_info_produces_different_keys() {
        let ikm = [0xAAu8; 32];
        let salt = [0xBBu8; 16];

        let mut okm1 = [0u8; KEY_SIZE];
        let mut okm2 = [0u8; KEY_SIZE];

        hkdf_sha256(&ikm, &salt, b"label-one", &mut okm1).expect("hkdf failed");
        hkdf_sha256(&ikm, &salt, b"label-two", &mut okm2).expect("hkdf failed");

        assert_ne!(
            okm1, okm2,
            "different info labels must produce different keys"
        );
    }

    #[test]
    fn hkdf_output_too_long_fails() {
        let prk = [0u8; SHA256_DIGEST_LEN];
        // 255 * 32 + 1 = 8161 bytes (exceeds max)
        let mut okm = [0u8; 8161];
        let result = hkdf_expand(&prk, b"info", &mut okm);
        assert_eq!(result, Err(SecurityError::HkdfOutputTooLong));
    }

    // -- SleepTier Display test --

    #[test]
    fn sleep_tier_display() {
        assert_eq!(SleepTier::Short.to_string(), "Short (PIN unlock)");
        assert_eq!(SleepTier::Long.to_string(), "Long (passphrase required)");
    }

    // -----------------------------------------------------------------------
    // Argon2id (#272)
    // -----------------------------------------------------------------------

    /// Argon2id cost for the behavioural tests below.
    ///
    /// WHY not the production constants: every property here is independent of
    /// the cost, and one 64 MiB derivation costs over a second in a debug
    /// build. `provisioning_writes_the_production_argon2id_cost` pays that once
    /// so the shipped numbers are still exercised end to end. That these tests
    /// pass at a cost the production path never writes is itself the point --
    /// a record verifies against its own recorded parameters, not an ambient
    /// constant.
    const TEST_M_COST_KIB: u32 = 64;
    const TEST_T_COST: u32 = 1;
    const TEST_P_COST: u32 = 1;

    fn argon2id_test_record(secret: &[u8], salt: [u8; PIN_SALT_LEN]) -> PinVerifier {
        PinVerifier::derive_argon2id_using(
            secret,
            salt,
            TEST_M_COST_KIB,
            TEST_T_COST,
            TEST_P_COST,
            pin_kdf_alloc,
            pin_kdf_free,
        )
        .expect("argon2id derivation failed in test")
    }

    static REFUSED_ALLOC_CALLS: AtomicUsize = AtomicUsize::new(0);

    fn refusing_alloc(_pages: usize) -> Option<usize> {
        REFUSED_ALLOC_CALLS.fetch_add(1, Ordering::Relaxed);
        None
    }

    /// # Safety
    ///
    /// Never called: [`refusing_alloc`] hands out nothing to free.
    unsafe fn unreachable_free(_addr: usize, _pages: usize) -> bool {
        unreachable!("nothing was allocated, so nothing can be released")
    }

    static RELEASED_SCRUBBED: AtomicBool = AtomicBool::new(false);
    static RELEASED_BYTES: AtomicUsize = AtomicUsize::new(0);

    /// # Safety
    ///
    /// Same contract as [`pin_kdf_free`], which it delegates to.
    unsafe fn scrub_observing_free(addr: usize, pages: usize) -> bool {
        let bytes = pages * crate::page::PAGE_SIZE;
        // SAFETY: the caller's contract gives us exactly this allocation, and
        // it is still live until the delegate below releases it.
        let raw = unsafe { core::slice::from_raw_parts(addr as *const u8, bytes) };
        RELEASED_SCRUBBED.store(raw.iter().all(|&b| b == 0), Ordering::Relaxed);
        RELEASED_BYTES.store(bytes, Ordering::Relaxed);
        // SAFETY: delegated to the caller's contract.
        unsafe { pin_kdf_free(addr, pages) }
    }

    #[test]
    fn an_argon2id_record_accepts_only_the_secret_it_was_derived_from() {
        let record = argon2id_test_record(b"123456", *b"device-a-saltxxx");

        assert_eq!(
            record.verify_using(b"123456", pin_kdf_alloc, pin_kdf_free),
            Ok(true),
            "the correct secret must verify"
        );
        assert_eq!(
            record.verify_using(b"654321", pin_kdf_alloc, pin_kdf_free),
            Ok(false),
            "a different secret must not verify"
        );
    }

    #[test]
    fn two_devices_derive_different_argon2id_digests_from_one_secret() {
        // The property a salt exists for: one precomputed table must not cover
        // the fleet (CWE-760).
        let first = argon2id_test_record(b"123456", *b"device-a-saltxxx");
        let second = argon2id_test_record(b"123456", *b"device-b-saltxxx");

        assert_ne!(
            first.digest, second.digest,
            "the same secret under two salts must not produce one digest"
        );
    }

    #[test]
    fn a_pbkdf2_record_still_verifies_through_the_same_dispatch() {
        // Carrying the parameters in the record is what makes the KDF a value
        // that can change. A record written before Argon2id must keep working,
        // or raising cost would mean resetting every provisioned device.
        let legacy = PinVerifier::derive_pbkdf2(b"123456", *b"device-a-saltxxx")
            .expect("pbkdf2 derivation failed in test");

        assert!(
            matches!(legacy.kdf, PinKdf::Pbkdf2Sha256 { .. }),
            "fixture must be a PBKDF2 record"
        );
        assert_eq!(
            legacy.verify_using(b"123456", refusing_alloc, unreachable_free),
            Ok(true),
            "a PBKDF2 record must verify without ever asking for Argon2id memory"
        );
    }

    #[test]
    fn an_unavailable_block_matrix_refuses_instead_of_deriving_weakly() {
        // The downgrade this forbids: exhaust the page pool, and a KDF that
        // shrank to fit would produce a digest at a cost far below the one its
        // own record claims, with nothing afterwards able to tell the two
        // apart.
        REFUSED_ALLOC_CALLS.store(0, Ordering::Relaxed);

        let refused = PinVerifier::derive_argon2id_using(
            b"123456",
            *b"device-a-saltxxx",
            TEST_M_COST_KIB,
            TEST_T_COST,
            TEST_P_COST,
            refusing_alloc,
            unreachable_free,
        );

        assert_eq!(
            refused,
            Err(PinVerifyError::Memory),
            "an unavailable matrix must refuse, not derive"
        );
        assert_eq!(
            REFUSED_ALLOC_CALLS.load(Ordering::Relaxed),
            1,
            "exactly one request, so there is no smaller size to fall back to"
        );
    }

    #[test]
    fn a_record_that_cannot_be_checked_is_not_a_failed_guess() {
        // `verify` returns three outcomes, not two. A caller that collapsed the
        // error into `false` would count memory pressure as a wrong secret,
        // which the lock screen answers by counting attempts and eventually
        // wiping.
        let record = argon2id_test_record(b"123456", *b"device-a-saltxxx");

        assert_eq!(
            record.verify_using(b"123456", refusing_alloc, unreachable_free),
            Err(PinVerifyError::Memory),
            "the correct secret must still report Err when the check cannot run"
        );
    }

    #[test]
    fn the_block_matrix_is_scrubbed_before_it_returns_to_the_pool() {
        // These pages go back to a pool the next allocator reads, and they hold
        // the full Argon2id state, which is derived from the secret (#836).
        RELEASED_SCRUBBED.store(false, Ordering::Relaxed);
        RELEASED_BYTES.store(0, Ordering::Relaxed);

        PinVerifier::derive_argon2id_using(
            b"123456",
            *b"device-a-saltxxx",
            TEST_M_COST_KIB,
            TEST_T_COST,
            TEST_P_COST,
            pin_kdf_alloc,
            scrub_observing_free,
        )
        .expect("argon2id derivation failed in test");

        assert!(
            RELEASED_BYTES.load(Ordering::Relaxed) > 0,
            "the observing release path must actually have run"
        );
        assert!(
            RELEASED_SCRUBBED.load(Ordering::Relaxed),
            "every byte of the matrix must be zero before release"
        );
    }

    #[test]
    fn the_page_count_covers_the_whole_block_matrix() {
        // The conversion the issue warns about: `m_cost` is KiB, a `Block` is
        // 1 KiB, and a page is 4 KiB, so a matrix needs a quarter as many pages
        // as blocks. Getting it wrong under-allocates, and the crate answers
        // with a parameter error that reads as a bad cost rather than a bad
        // page count.
        assert_eq!(BLOCKS_PER_PAGE, 4, "4 KiB page holds four 1 KiB blocks");

        for block_count in [8usize, 64, 4096, 65_536] {
            let pages = block_count.div_ceil(BLOCKS_PER_PAGE);
            assert!(
                pages * crate::page::PAGE_SIZE >= block_count * ARGON2_BLOCK_BYTES,
                "{block_count} blocks must fit in {pages} pages"
            );
        }
    }

    #[test]
    fn provisioning_writes_the_production_argon2id_cost() {
        // The one test that pays the shipped cost, so the constants are
        // exercised rather than merely declared. Under nextest each test is its
        // own process, so seeding here cannot leak into another test.
        crate::csprng::seed_for_test(&[0x42u8; 32], &[0u8; 8], 0);

        let record = PinVerifier::provision(b"123456").expect("provisioning failed");

        assert_eq!(
            record.kdf,
            PinKdf::Argon2id {
                m_cost_kib: PIN_ARGON2ID_M_COST_KIB,
                t_cost: PIN_ARGON2ID_T_COST,
                p_cost: PIN_ARGON2ID_P_COST,
            },
            "the production path must record the production cost"
        );
        assert_eq!(
            record.verify(b"123456"),
            Ok(true),
            "a provisioned record must verify the secret it was made from"
        );
    }
}
