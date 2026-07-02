//! Kernel CSPRNG — RustCrypto `ChaCha20Rng`, seeded from ARM generic timer jitter.
//!
//! Architecture mirrors Linux kernel random.c:
//!   entropy pool (256 bits) → ChaCha20 key → keystream output
//!
//! The DRBG core is `rand_chacha::ChaCha20Rng` (RustCrypto). This module owns
//! only the kernel-specific parts: entropy sourcing, the seededness gate, the
//! reseed-after-N-bytes policy, and the fail-closed `kernel_random_bytes`
//! interface. It does NOT hand-roll ChaCha20.
//!
//! Entropy sources:
//!   (a) ARM generic timer (CNTPCT_EL0 / mrrc p15,0,…,c14) low word sampled
//!       at every timer interrupt entry.
//!   (b) Interrupt arrival timing jitter from source (a) — the *variation*
//!       between successive samples, which is what earns entropy credit.
//!
//! Initialization must complete (via `init()`) before any driver calls
//! `kernel_random_bytes()`. The CSPRNG auto-reseeds after every
//! `RESEED_THRESHOLD` bytes.
//!
//! # Fail-closed (audit #284)
//!
//! `kernel_random_bytes` returns `Result<(), CsprngError>` and NEVER writes
//! keystream before the pool is seeded — it returns `Err(CsprngError::NotSeeded)`
//! and leaves the caller buffer untouched. Callers must handle the error rather
//! than consuming silent all-zero key material.
//!
//! # Seededness (audit #304)
//!
//! The pool is "seeded" only once it has accumulated a conservative
//! `SEED_ENTROPY_BITS` estimate of *actual* entropy. Timer samples earn credit
//! solely from the bit-flips in their low (jitter) band relative to the previous
//! sample, so a constant / stuck timer credits zero and can never satisfy the
//! gate.
//!
//! # Safety model
//!
//! All mutable globals are `static mut`. Access is restricted to:
//!   - `collect_timer_entropy` / `add_entropy`: called only from the IRQ handler
//!     (non-reentrant on single-core ARMv7, IRQ disabled during execution).
//!   - `init`: called once from kinit, before any code reads the CSPRNG.
//!   - `kernel_random_bytes`: callable from kernel context after `init()`; not
//!     called concurrently on this single-core kernel.

use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

// ---------------------------------------------------------------------------
// Policy constants
// ---------------------------------------------------------------------------

/// Reseed threshold: reseed after this many bytes generated.
const RESEED_THRESHOLD: u64 = 1 << 20; // 1 MiB

/// Estimated accumulated entropy (bits) required before the pool is seeded.
/// 256 bits = full pool width; fail-closed gate for #284/#304.
const SEED_ENTROPY_BITS: u32 = 256;

/// Low-bit mask isolating the ARM generic timer's interrupt-latency jitter
/// band. Higher bits track the deterministic tick period and carry no fresh
/// entropy, so only bit-flips within this mask are credited.
const TIMER_JITTER_MASK: u32 = 0x0000_0FFF;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Failure returned by [`kernel_random_bytes`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CsprngError {
    /// The entropy pool has not yet accumulated sufficient entropy, so no
    /// keystream can be produced. Callers must NOT proceed with zeroed output.
    NotSeeded,
}

// ---------------------------------------------------------------------------
// DRBG wrapper
// ---------------------------------------------------------------------------

/// Kernel DRBG: a RustCrypto `ChaCha20Rng` plus the reseed accounting the
/// kernel policy needs.
struct Csprng {
    rng: ChaCha20Rng,
    /// Bytes generated since the last reseed (drives auto-reseed).
    bytes_generated: u64,
}

// ---------------------------------------------------------------------------
// Entropy pool
// ---------------------------------------------------------------------------

/// 256-bit entropy accumulator with a conservative entropy estimate.
///
/// Entropy is mixed in via XOR at a rotating cursor. `entropy_bits` tracks a
/// conservative bit estimate; the pool is seeded once it reaches
/// `SEED_ENTROPY_BITS`. Only timer-jitter variation earns credit.
struct EntropyPool {
    pool: [u8; 32],
    /// Conservative running estimate of accumulated entropy, in bits.
    entropy_bits: u32,
    /// Previous timer sample, for delta-based (jitter) crediting.
    last_sample: u32,
    /// Whether `last_sample` holds a valid prior reading.
    have_sample: bool,
    /// Write cursor (rotates through pool bytes).
    cursor: usize,
}

impl EntropyPool {
    const fn new() -> Self {
        Self {
            pool: [0u8; 32],
            entropy_bits: 0,
            last_sample: 0,
            have_sample: false,
            cursor: 0,
        }
    }

    /// XOR `data` bytes into the pool, advancing the cursor. Mixing alone earns
    /// NO entropy credit — only `add_timer_sample` credits the seededness gate.
    fn mix_bytes(&mut self, data: &[u8]) {
        for &byte in data {
            self.pool[self.cursor] ^= byte;
            self.cursor = (self.cursor + 1) % 32;
        }
    }

    /// Mix a timer sample and credit entropy from its jitter-band variation.
    ///
    /// A repeated sample (`sample == last_sample`) flips no bits in the jitter
    /// band and credits zero — closing #304 (a stuck/constant timer can never
    /// seed the pool).
    fn add_timer_sample(&mut self, sample: u32) {
        self.mix_bytes(&sample.to_le_bytes());
        if self.have_sample {
            // Credit only the bits that actually flipped inside the jitter band.
            let flips = ((sample ^ self.last_sample) & TIMER_JITTER_MASK).count_ones();
            self.entropy_bits = self.entropy_bits.saturating_add(flips);
        }
        self.last_sample = sample;
        self.have_sample = true;
    }

    /// True once a conservative `SEED_ENTROPY_BITS` estimate has accumulated.
    fn is_seeded(&self) -> bool {
        self.entropy_bits >= SEED_ENTROPY_BITS
    }
}

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------

/// Global CSPRNG instance. None until `init()` is called.
///
/// SAFETY: written once (in `init()`) before any reader; thereafter mutated
/// only through `kernel_random_bytes()`, which is not called concurrently on
/// this single-core kernel.
static mut CSPRNG: Option<Csprng> = None;

/// Global entropy accumulator. Written only from the IRQ handler.
///
/// SAFETY: all writes are from `irq_handler_rust` (non-reentrant on single-core
/// ARMv7 with IRQs disabled during handler execution). `init()` reads it once
/// after sufficient mixing; no concurrent read/write is possible.
static mut ENTROPY: EntropyPool = EntropyPool::new();

/// True after `init()` completes successfully.
///
/// SAFETY: written once in `init()`, read from `kernel_random_bytes()`. Single-
/// core, no races.
static mut INITIALIZED: bool = false;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Collect entropy from the ARM generic timer (CNTPCT via mrrc p15,0,…,c14).
///
/// Called from the timer IRQ handler. Reads the physical counter's low word and
/// mixes it; the timing jitter between successive interrupts is the actual
/// entropy source.
///
/// # Safety
///
/// Must be called only from the IRQ handler context (single-core, non-reentrant,
/// IRQ disabled during execution). Accessing `ENTROPY` without a lock is safe
/// here because the IRQ handler is the sole writer and is not re-entrant.
pub unsafe fn collect_timer_entropy() {
    // On the ARM target: read the physical counter (CNTPCT) via mrrc p15,0,…,c14.
    // In test builds (host): no hardware available, this function is a no-op —
    // tests inject entropy directly via seed_for_test().
    #[cfg(not(test))]
    {
        let lo: u32;
        let hi: u32;
        // SAFETY: mrrc p15,0 with c14 reads CNTPCT, the physical counter. This is a
        // read-only CP15 system register accessible at EL1 (PL1 in ARMv7 terms).
        // No memory is modified; the register access cannot fault.
        unsafe {
            core::arch::asm!(
                "mrrc p15, 0, {lo}, {hi}, c14",
                lo = out(reg) lo,
                hi = out(reg) hi,
            );
        }
        // NOTE: `hi` changes far too slowly to carry per-tick jitter; the low
        // word `lo` is the jitter signal used for both mixing and crediting.
        let _ = hi;

        // SAFETY: ENTROPY is only accessed from IRQ context (this function).
        // Single-core ARMv7: IRQs are masked for the duration of the handler,
        // so there is no concurrent access. addr_of_mut! avoids creating an
        // intermediate reference to the static mut (Rust 2024 static_mut_refs).
        unsafe {
            (*core::ptr::addr_of_mut!(ENTROPY)).add_timer_sample(lo);
        }
    }
}

/// Add arbitrary entropy bytes to the pool.
///
/// Called from drivers with access to additional entropy sources (e.g. eMMC
/// CID registers). The bytes are mixed but earn NO seededness credit: only the
/// hardware timer jitter is trusted to satisfy the fail-closed gate, so
/// caller-supplied data can never (falsely) seed the pool.
///
/// # Safety
///
/// Must be called only from IRQ context or before interrupts are enabled.
/// See module-level safety note.
pub unsafe fn add_entropy(data: &[u8]) {
    // SAFETY: See ENTROPY static's safety comment above. addr_of_mut! avoids
    // creating an intermediate reference to the static mut.
    unsafe {
        (*core::ptr::addr_of_mut!(ENTROPY)).mix_bytes(data);
    }
}

/// Initialize the CSPRNG from the accumulated entropy pool.
///
/// Call this from kinit after the timer has been running long enough to
/// accumulate `SEED_ENTROPY_BITS` of jitter entropy. If the pool is not yet
/// seeded, spins (busy-polls) until it is — the timer ISR is running at this
/// point and will call `collect_timer_entropy()` each tick.
///
/// # Safety
///
/// Must be called exactly once from kinit, after `exceptions::init()` (timer
/// running), before any driver calls `kernel_random_bytes()`. IRQs must be
/// enabled at call time so the timer ISR can supply entropy.
pub unsafe fn init() {
    // Spin until the entropy pool has accumulated a full seed estimate.
    loop {
        // SAFETY: ENTROPY is accessed read-only here; writes only come from the
        // IRQ handler which cannot execute concurrently on single-core ARMv7.
        // addr_of! avoids creating a shared reference to the static mut.
        let seeded = unsafe { (*core::ptr::addr_of!(ENTROPY)).is_seeded() };
        if seeded {
            break;
        }
        // Yield to allow the timer IRQ to fire.
        #[cfg(not(test))]
        // SAFETY: WFI is a hint instruction available at all ARM privilege levels.
        unsafe {
            core::arch::asm!("wfi");
        }
        // On test host: init() is not exercised (seed_for_test bypasses it);
        // break to prevent an infinite loop should it ever be reached.
        #[cfg(test)]
        {
            break;
        }
    }

    // Seed the DRBG from the entropy pool.
    // SAFETY: ENTROPY is read once here; no concurrent writer is possible because
    // we only reach this point after `is_seeded()` returns true, and init() is
    // called exactly once.
    let pool_snapshot = unsafe { (*core::ptr::addr_of!(ENTROPY)).pool };
    let csprng = Csprng {
        rng: ChaCha20Rng::from_seed(pool_snapshot),
        bytes_generated: 0,
    };

    // SAFETY: CSPRNG/INITIALIZED are written exactly once here; no reader exists
    // yet (init() runs before any driver uses kernel_random_bytes()).
    unsafe {
        CSPRNG = Some(csprng);
        INITIALIZED = true;
    }
}

/// Generate `buf.len()` cryptographically random bytes.
///
/// Fail-closed (audit #284): if the CSPRNG is not yet seeded this returns
/// `Err(CsprngError::NotSeeded)` and leaves `buf` untouched — it never emits
/// zeroed (or any) output before seeding. Callers MUST handle the error and
/// not treat the buffer as key material on failure.
///
/// Auto-reseeds after every `RESEED_THRESHOLD` bytes generated.
///
/// # Errors
///
/// [`CsprngError::NotSeeded`] if `init()` has not completed.
pub fn kernel_random_bytes(buf: &mut [u8]) -> Result<(), CsprngError> {
    // SAFETY: INITIALIZED is written once in `init()`. Reading it here without a
    // lock is safe on single-core ARMv7.
    if !unsafe { INITIALIZED } {
        return Err(CsprngError::NotSeeded);
    }

    // SAFETY: CSPRNG is Some after INITIALIZED is true (set together in init()).
    // kernel_random_bytes() is not called concurrently on this single-core
    // kernel; the IRQ handler only touches ENTROPY, not CSPRNG. addr_of_mut!
    // avoids creating an implicit reference to the static mut.
    let csprng = unsafe {
        match (*core::ptr::addr_of_mut!(CSPRNG)).as_mut() {
            Some(c) => c,
            None => return Err(CsprngError::NotSeeded),
        }
    };

    csprng.rng.fill_bytes(buf);
    csprng.bytes_generated = csprng.bytes_generated.saturating_add(buf.len() as u64);

    // Auto-reseed once the threshold is crossed.
    if csprng.bytes_generated >= RESEED_THRESHOLD {
        // Combine the accumulated pool entropy with fresh keystream so the new
        // key never repeats a prior stream even if the pool is momentarily
        // static between reseeds.
        // SAFETY: ENTROPY is only written from IRQ context; on single-core
        // ARMv7 this read cannot interleave mid-instruction with the handler.
        // A missed tick or two of entropy is acceptable for the snapshot.
        let mut new_seed = unsafe { (*core::ptr::addr_of!(ENTROPY)).pool };
        let mut mixer = [0u8; 32];
        csprng.rng.fill_bytes(&mut mixer);
        for (s, m) in new_seed.iter_mut().zip(mixer.iter()) {
            *s ^= *m;
        }
        csprng.rng = ChaCha20Rng::from_seed(new_seed);
        csprng.bytes_generated = 0;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Test-mode seed injection
// ---------------------------------------------------------------------------

/// Inject a known seed for deterministic testing.
///
/// Only available in `#[cfg(test)]` builds. Seeds the DRBG deterministically so
/// test vectors are reproducible without platform hardware. `nonce` sets the
/// ChaCha20 stream and `counter` the block position (both zero for most callers).
#[cfg(test)]
pub fn seed_for_test(key: &[u8; 32], nonce: &[u8; 8], counter: u64) {
    let mut rng = ChaCha20Rng::from_seed(*key);
    rng.set_stream(u64::from_le_bytes(*nonce));
    // set_word_pos is measured in 32-bit words; one 64-byte block = 16 words.
    rng.set_word_pos(u128::from(counter) * 16);
    // SAFETY: cargo-nextest (the canonical runner for this crate/target — see
    // ci.yml) spawns a fresh OS process per #[test] fn, so CSPRNG/INITIALIZED
    // here are process-local: no other test's mutation of these statics is ever
    // visible to this one, regardless of --test-threads. This is process
    // isolation, not single-threaded execution (nextest parallelizes freely) —
    // a different mechanism giving the same absence-of-data-race guarantee.
    // WARNING: this does NOT hold under a bare `cargo test` inside crates/thumos/
    // (threads in one process); nextest is enforced by CI, not by this code.
    unsafe {
        CSPRNG = Some(Csprng {
            rng,
            bytes_generated: 0,
        });
        INITIALIZED = true;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- Entropy pool tests ---

    #[test]
    fn entropy_pool_mixes_data() {
        let mut pool = EntropyPool::new();
        let initial = pool.pool;
        pool.mix_bytes(&[0xDE, 0xAD, 0xBE, 0xEF]);
        assert_ne!(pool.pool, initial, "pool must change after mix");
    }

    #[test]
    fn entropy_pool_not_seeded_initially() {
        let pool = EntropyPool::new();
        assert!(!pool.is_seeded(), "fresh pool must not be seeded");
    }

    #[test]
    fn entropy_pool_constant_samples_do_not_seed() {
        // #304 regression: a stuck/constant timer flips no jitter bits and must
        // NEVER satisfy the seededness gate, no matter how many samples arrive.
        let mut pool = EntropyPool::new();
        for _ in 0..10_000 {
            pool.add_timer_sample(0x1234_5678);
        }
        assert!(
            !pool.is_seeded(),
            "constant timer samples must not seed the pool (#304)"
        );
        assert_eq!(pool.entropy_bits, 0, "constant samples credit zero entropy");
    }

    #[test]
    fn entropy_pool_varying_samples_seed() {
        // Distinct samples that flip jitter-band bits accumulate real credit.
        let mut pool = EntropyPool::new();
        let mut sample: u32 = 0;
        let mut ticks = 0;
        while !pool.is_seeded() && ticks < 100_000 {
            // Vary the low (jitter) bits each tick.
            sample = sample.wrapping_add(0x0000_0ABF);
            pool.add_timer_sample(sample);
            ticks += 1;
        }
        assert!(pool.is_seeded(), "varying timer jitter must seed the pool");
        assert!(pool.entropy_bits >= SEED_ENTROPY_BITS);
    }

    #[test]
    fn entropy_pool_cursor_wraps() {
        let mut pool = EntropyPool::new();
        pool.mix_bytes(&[0xFFu8; 32]);
        assert_eq!(pool.cursor, 0, "cursor must wrap around to 0 after 32 bytes");
    }

    // --- kernel_random_bytes tests (use test seed injection) ---

    fn setup_test_rng() {
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let nonce = [0u8; 8];
        seed_for_test(&key, &nonce, 0);
    }

    #[test]
    fn random_bytes_not_zero() {
        setup_test_rng();
        let mut buf = [0u8; 32];
        kernel_random_bytes(&mut buf).expect("seeded test rng");
        assert_ne!(buf, [0u8; 32], "random bytes must not be all zero");
    }

    #[test]
    fn sequential_outputs_differ() {
        setup_test_rng();
        let mut buf1 = [0u8; 32];
        let mut buf2 = [0u8; 32];
        kernel_random_bytes(&mut buf1).expect("seeded test rng");
        kernel_random_bytes(&mut buf2).expect("seeded test rng");
        assert_ne!(buf1, buf2, "sequential calls must produce different output");
    }

    #[test]
    fn random_bytes_spans_block_boundary() {
        // Request more than 64 bytes to exercise the multi-block path.
        setup_test_rng();
        let mut buf = [0u8; 128];
        kernel_random_bytes(&mut buf).expect("seeded test rng");
        assert_ne!(&buf[..64], &buf[64..], "consecutive blocks must be distinct");
    }

    #[test]
    fn reseed_changes_output() {
        let key1 = [0x11u8; 32];
        let key2 = [0x22u8; 32];
        let nonce = [0u8; 8];

        seed_for_test(&key1, &nonce, 0);
        let mut out1 = [0u8; 32];
        kernel_random_bytes(&mut out1).expect("seeded test rng");

        seed_for_test(&key2, &nonce, 0);
        let mut out2 = [0u8; 32];
        kernel_random_bytes(&mut out2).expect("seeded test rng");

        assert_ne!(
            out1, out2,
            "different keys must produce different output streams"
        );
    }

    #[test]
    fn output_is_deterministic_for_same_seed() {
        let key = [0xAAu8; 32];
        let nonce = [0u8; 8];

        seed_for_test(&key, &nonce, 0);
        let mut out1 = [0u8; 64];
        kernel_random_bytes(&mut out1).expect("seeded test rng");

        seed_for_test(&key, &nonce, 0);
        let mut out2 = [0u8; 64];
        kernel_random_bytes(&mut out2).expect("seeded test rng");

        assert_eq!(
            out1, out2,
            "same seed must produce identical output (deterministic)"
        );
    }

    #[test]
    fn uninitialized_fails_closed() {
        // #284: an unseeded CSPRNG must fail closed — return an error and leave
        // the caller buffer untouched, never emitting (zeroed) key material.
        // SAFETY: test-only manipulation of global state.
        unsafe {
            CSPRNG = None;
            INITIALIZED = false;
        }
        let mut buf = [0xFFu8; 16];
        let result = kernel_random_bytes(&mut buf);
        assert_eq!(result, Err(CsprngError::NotSeeded), "must signal failure");
        assert_eq!(
            buf, [0xFFu8; 16],
            "buffer must be left untouched on fail-closed"
        );
    }

    #[test]
    fn chacha20_rfc8439_test_vector_1() {
        // NOTE: RFC 8439 §2.3.2 / Appendix A.1 Test Vector #1 — all-zero key,
        // all-zero nonce, block counter 0. WHY it applies to rand_chacha 0.3.1's
        // 64-bit-counter/64-bit-stream layout despite RFC 8439 using a
        // 32-bit-counter/96-bit-nonce split: state words 12-15 are all zero in
        // BOTH layouts here, so the initial state (hence the keystream) is
        // identical — the published block applies directly, no derived vector.
        let key = [0u8; 32];
        let nonce = [0u8; 8];
        seed_for_test(&key, &nonce, 0);

        let mut buf = [0u8; 64];
        kernel_random_bytes(&mut buf).expect("seeded test rng");

        let expected: [u8; 64] = [
            0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90,
            0x40, 0x5d, 0x6a, 0xe5, 0x53, 0x86, 0xbd, 0x28,
            0xbd, 0xd2, 0x19, 0xb8, 0xa0, 0x8d, 0xed, 0x1a,
            0xa8, 0x36, 0xef, 0xcc, 0x8b, 0x77, 0x0d, 0xc7,
            0xda, 0x41, 0x59, 0x7c, 0x51, 0x57, 0x48, 0x8d,
            0x77, 0x24, 0xe0, 0x3f, 0xb8, 0xd8, 0x4a, 0x37,
            0x6a, 0x43, 0xb8, 0xf4, 0x15, 0x18, 0xa1, 0x1c,
            0xc3, 0x87, 0xb6, 0x69, 0xb2, 0xee, 0x65, 0x86,
        ];
        assert_eq!(buf, expected, "ChaCha20 block 0 must match RFC 8439 Test Vector #1");
    }
}
