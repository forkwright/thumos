//! Kernel CSPRNG — `RustCrypto` `ChaCha20Rng` with a provisional timer-derived seed gate.
//!
//! Architecture mirrors Linux kernel random.c:
//!   entropy pool (256 bits) → `ChaCha20` key → keystream output
//!
//! The DRBG core is `rand_chacha::ChaCha20Rng` (`RustCrypto`). This module owns
//! only the kernel-specific parts: entropy sourcing, the seededness gate, the
//! reseed-after-N-bytes policy, and the fail-closed `kernel_random_bytes`
//! interface. It does NOT hand-roll `ChaCha20`.
//!
//! Entropy sources:
//!   (a) ARM generic timer (`CNTPCT_EL0` / mrrc p15,0,…,c14) low word sampled
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
//! # Seededness (audits #304 and #840)
//!
//! Credit is scored against the SECOND difference between timer samples --
//! how far each interval departs from the interval before it -- not against
//! the raw sample-to-sample XOR. The timer is re-armed every tick with a fixed
//! reload against a fixed CNTFRQ, so its deterministic component is a constant
//! first difference and contributes nothing by construction. A repetition
//! guard drops credit when a departure repeats its predecessor in magnitude,
//! which covers a cadence that is periodic rather than constant.
//!
//! That bounds what a cadence-aware attacker cannot predict. It is not a
//! min-entropy measurement, and it does not attempt one: the per-sample credit
//! is capped well below the mask width so no single excursion can stand in for
//! sustained jitter.
//!
//! # Safety model
//!
//! All mutable globals are `static mut`. Access is restricted to:
//!   - `collect_timer_entropy` / `add_entropy`: called only from the IRQ handler
//!     (non-reentrant on single-core `ARMv7`, IRQ disabled during execution).
//!   - `init`: called once from kinit, before any code reads the CSPRNG.
//!   - `kernel_random_bytes`: callable from kernel context after `init()`; not
//!     called concurrently on this single-core kernel.

use rand_chacha::ChaCha20Rng;
// WHY: rand_core 0.10 renamed the infallible-fill trait `RngCore` -> `Rng`
// (old `Rng` became `RngExt`, in the `rand` crate, unused here). `fill_bytes`
// stays the same infallible `fn fill_bytes(&mut self, dst: &mut [u8])` --
// no Result, no new panic path -- just re-homed onto the renamed trait.
use rand_core::{Rng, SeedableRng};

// ---------------------------------------------------------------------------
// Policy constants
// ---------------------------------------------------------------------------

/// Reseed threshold: reseed after this many bytes generated.
const RESEED_THRESHOLD: u64 = 1 << 20; // 1 MiB

/// Accumulated credit required before the pool reports seeded.
const SEED_ENTROPY_BITS: u32 = 256;

/// Low-bit mask applied to the inter-sample interval's departure from the
/// preceding interval.
///
/// WHY masking is sound HERE and was not on the raw sample: the deterministic
/// per-tick advance is a constant first difference, so it cancels in the
/// second difference regardless of which bits it occupies. What remains inside
/// the mask is cadence departure, and anything above it is a gross excursion
/// -- a missed tick or a frequency change -- which is one event rather than
/// many independent bits and is deliberately not credited in proportion to its
/// size (#840).
const TIMER_JITTER_MASK: u32 = 0x0000_0FFF;

/// Ceiling on the credit any one timer sample may earn.
///
/// WHY a ceiling: the score below bounds unpredictability against a known
/// cadence; it does not measure min-entropy. A single large departure produces
/// a large popcount that represents one event, and a negative departure sets
/// most of the masked bits purely through two's-complement wrapping. Without
/// this, either could satisfy the whole gate in a handful of samples. At this
/// value the gate needs at least 64 credited samples -- 0.64 s at the 10 ms
/// tick -- against the 30 s bound below.
const MAX_CREDIT_BITS_PER_SAMPLE: u32 = 4;

/// Maximum wall-clock time `init()` will spin waiting for
/// `SEED_ENTROPY_BITS` before giving up and reporting failure.
///
/// WHY 30s: at the 10 ms scheduler tick period, one credited bit per tick
/// reaches 256 in ~2.6 s, and the per-sample ceiling puts the floor at 0.64 s.
/// The 30 s bound prevents a dead or fully deterministic credit source from
/// hanging boot; reaching the gate is a necessary condition for seeding, not a
/// measurement of the entropy behind it.
const CSPRNG_INIT_TIMEOUT_MS: u64 = 30_000;

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

/// Kernel DRBG: a `RustCrypto` `ChaCha20Rng` plus the reseed accounting the
/// kernel policy needs.
struct Csprng {
    rng: ChaCha20Rng,
    /// Bytes generated since the last reseed (drives auto-reseed).
    bytes_generated: u64,
}

// ---------------------------------------------------------------------------
// Entropy pool
// ---------------------------------------------------------------------------

/// 256-bit accumulator plus the cadence-departure credit that gates seeding.
///
/// Samples are mixed via XOR at a rotating cursor. `entropy_bits` counts
/// credited cadence departure; it bounds unpredictability against a known
/// cadence rather than measuring min-entropy (see the module docs).
struct EntropyPool {
    pool: [u8; 32],
    /// Accumulated cadence-departure credit.
    entropy_bits: u32,
    /// Previous timer sample, for the first difference.
    last_sample: u32,
    /// Previous first difference, for the second difference.
    last_delta: u32,
    /// Previous second difference, for the repetition guard.
    last_jitter: u32,
    /// Whether `last_sample` holds a valid prior reading.
    have_sample: bool,
    /// Whether `last_delta` holds a valid prior interval.
    have_delta: bool,
    /// Whether `last_jitter` holds a valid prior departure.
    have_jitter: bool,
    /// Write cursor (rotates through pool bytes).
    cursor: usize,
}

impl EntropyPool {
    const fn new() -> Self {
        Self {
            pool: [0u8; 32],
            entropy_bits: 0,
            last_sample: 0,
            last_delta: 0,
            last_jitter: 0,
            have_sample: false,
            have_delta: false,
            have_jitter: false,
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

    /// Mix a timer sample and credit however far its interval departed from
    /// the interval before it.
    ///
    /// Two shapes credit nothing by construction, and both are shapes a
    /// deterministic source actually produces (#304, #840):
    ///
    /// - a stuck timer, whose interval is zero every tick;
    /// - a timer re-armed with a fixed reload against a fixed CNTFRQ -- this
    ///   platform's own arrangement -- whose interval is a nonzero constant,
    ///   so the second difference is zero however many bits the raw sample
    ///   XOR would have flipped.
    ///
    /// The repetition guard extends that to a cadence that is periodic rather
    /// than constant: an interval alternating between two values produces a
    /// departure that alternates in sign and repeats in magnitude, which is
    /// fully predictable and must not earn credit either.
    fn add_timer_sample(&mut self, sample: u32) {
        self.mix_bytes(&sample.to_le_bytes());

        // WHY wrapping arithmetic throughout: CNTPCT's low word wraps, and a
        // difference taken modulo 2^32 stays correct across the wrap. Signs
        // are irrelevant to the popcount that follows.
        let delta = sample.wrapping_sub(self.last_sample);
        let jitter = delta.wrapping_sub(self.last_delta);

        // INVARIANT: have_delta implies have_sample -- the former is only set
        // in the branch guarded by the latter -- so this one condition means
        // "two prior samples exist". Crediting before then would score the
        // arbitrary distance from a zero-initialised field rather than a
        // cadence, which needs two intervals to exist at all.
        if self.have_delta {
            // Repetition guard: a departure that repeats its predecessor's
            // magnitude, in either direction, is cadence rather than jitter.
            let repeated = self.have_jitter
                && (jitter == self.last_jitter || jitter == self.last_jitter.wrapping_neg());
            if !repeated {
                let credit = (jitter & TIMER_JITTER_MASK)
                    .count_ones()
                    .min(MAX_CREDIT_BITS_PER_SAMPLE);
                self.entropy_bits = self.entropy_bits.saturating_add(credit);
            }
            self.last_jitter = jitter;
            self.have_jitter = true;
        }

        if self.have_sample {
            self.last_delta = delta;
            self.have_delta = true;
        }
        self.last_sample = sample;
        self.have_sample = true;
    }

    /// True once accumulated cadence-departure credit reaches its threshold.
    fn is_seeded(&self) -> bool {
        self.entropy_bits >= SEED_ENTROPY_BITS
    }

    /// Deterministically seed the pool for QEMU bring-up (feature `qemu`).
    ///
    /// WHY(qemu): a deterministic emulator has no hardware entropy source.
    /// Its CP15 counter advances predictably, which is exactly the shape the
    /// estimator refuses to credit, so `init`'s seed loop cannot make
    /// progress and would spin out its timeout every boot. This
    /// fills the pool from a fixed vector and marks it seeded so the boot
    /// proceeds. NOT cryptographically secure; compiled ONLY under
    /// `--features qemu`, which is mutually exclusive with `production`
    /// (`main.rs` `compile_error!`) and so can never reach a shippable image.
    #[cfg(feature = "qemu")]
    fn seed_deterministic_qemu(&mut self) {
        self.pool = *b"thumos-qemu-deterministic-seed!!";
        self.entropy_bits = SEED_ENTROPY_BITS;
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
/// `ARMv7` with IRQs disabled during handler execution). `init()` reads it once
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

/// Collect a timer sample from CNTPCT and mix it into the entropy pool.
///
/// Called from the timer IRQ handler. Deterministic counter advance credits
/// nothing (see [`EntropyPool::add_timer_sample`]); what the gate cannot do is
/// measure how much real jitter the remainder carries, which is why reaching
/// it is a precondition for seeding rather than an entropy receipt (#873).
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
        // NOTE: `hi` changes far too slowly to carry per-tick jitter, so the
        // low word `lo` is the input for both mixing and crediting. Wrapping
        // of that word is handled by the modular arithmetic in the estimator.
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
/// CID registers). The bytes are mixed but earn NO seededness credit: only
/// timer cadence departure drives the gate. A CID register is a fixed
/// per-device value, so crediting it would let a constant satisfy the gate --
/// the same defect the timer estimator refuses (#304, #840).
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
/// Call this from kinit after the timer has begun feeding credits. If the
/// counter has not reached `SEED_ENTROPY_BITS`, this busy-polls while the
/// timer ISR calls `collect_timer_entropy()` each tick. A deterministic timer
/// credits nothing and times out here rather than seeding.
///
/// Bounded by `CSPRNG_INIT_TIMEOUT_MS`, measured against the free-running
/// CNTPCT counter (`crate::timer::elapsed_ms()`) rather than the IRQ-
/// driven tick count: if the timer ISR never fires at all, the tick
/// count never advances either (the same handler drives both), so it
/// cannot detect that failure mode -- CNTPCT keeps counting in hardware
/// regardless of whether interrupts are ever delivered. Returns `false`
/// on timeout and leaves the CSPRNG unseeded; `kernel_random_bytes()`
/// then fails closed with `CsprngError::NotSeeded` forever, exactly as
/// it already does before `init()` runs. The only behavior change is
/// that a starved provisional credit source degrades the boot (per the kinit
/// Hubris fault-isolation model) instead of hanging it.
///
/// # Safety
///
/// Must be called exactly once from kinit, after `exceptions::init()` (timer
/// running), before any driver calls `kernel_random_bytes()`. IRQs must be
/// enabled at call time so the timer ISR can supply samples.
#[must_use = "a `false` return means the CSPRNG is unseeded; the caller must record and report the degraded boot state"]
pub unsafe fn init() -> bool {
    // SAFETY: elapsed_ms() only reads the free-running CP15 CNTPCT/CNTFRQ
    // registers; no state is mutated.
    #[cfg(not(test))]
    let deadline_start = crate::timer::elapsed_ms();

    // WHY(qemu): deterministic emulator has no hardware entropy; inject a
    // fixed seed so is_seeded() passes on the first check below and boot
    // proceeds instead of spinning out the timeout.
    // SAFETY: ENTROPY is written only from the timer IRQ handler; this runs
    // before IRQs deliver entropy and is non-reentrant on single-core ARMv7.
    #[cfg(feature = "qemu")]
    unsafe {
        (*core::ptr::addr_of_mut!(ENTROPY)).seed_deterministic_qemu();
    }

    // Spin until the credit counter reaches its threshold, or until
    // CSPRNG_INIT_TIMEOUT_MS elapses.
    // WHY: in host test builds the #[cfg(test)] arm below always breaks on
    // the first pass (test host bypasses real entropy collection), so this
    // loop genuinely never loops more than once THERE -- but the production
    // (#[cfg(not(test))]) arm is the real spin/timeout wait and must stay a
    // loop. cfg_attr scopes the allow to the build where the single-pass
    // shape is deliberate, not the one doing the actual waiting.
    #[cfg_attr(test, allow(clippy::never_loop))]
    let seeded = loop {
        // SAFETY: ENTROPY is accessed read-only here; writes only come from the
        // IRQ handler which cannot execute concurrently on single-core ARMv7.
        // addr_of! avoids creating a shared reference to the static mut.
        let seeded = unsafe { (*core::ptr::addr_of!(ENTROPY)).is_seeded() };
        if seeded {
            break true;
        }

        #[cfg(not(test))]
        {
            let elapsed = crate::timer::elapsed_ms().saturating_sub(deadline_start);
            if elapsed >= CSPRNG_INIT_TIMEOUT_MS {
                break false;
            }
            // Yield to allow the timer IRQ to fire.
            // SAFETY: WFI is a hint instruction available at all ARM privilege levels.
            unsafe {
                core::arch::asm!("wfi");
            }
        }

        // On test host: init() is not exercised for real entropy
        // collection (seed_for_test bypasses it); break unseeded so the
        // fail-closed path below runs instead of spinning forever should
        // this ever execute.
        #[cfg(test)]
        {
            break false;
        }
    };

    if !seeded {
        return false;
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
    true
}

/// Generate `buf.len()` bytes from the `ChaCha20` DRBG once the gate is met.
///
/// The gate refuses a deterministic timer, but it measures no min-entropy and
/// #873 still blocks treating reset/reseed state as non-repeating. Callers
/// fail closed when the gate is not reached; success is a precondition for
/// cryptographic readiness rather than evidence of it.
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
/// `ChaCha20` stream and `counter` the block position (both zero for most callers).
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

    // --- init() fail-closed timeout path ---

    #[test]
    fn init_without_sufficient_entropy_returns_false_and_stays_unseeded() {
        // Under #[cfg(test)], init()'s spin loop breaks unseeded on the
        // first iteration (no real timer ISR to feed it) rather than
        // looping forever -- this exercises the fail-closed return path
        // that used to unconditionally seed FROM a zero-entropy pool.
        // SAFETY: test-only; nextest process isolation means ENTROPY/
        // CSPRNG/INITIALIZED here are fresh for this test (see
        // seed_for_test's SAFETY comment for the same guarantee).
        let seeded = unsafe { init() };
        assert!(
            !seeded,
            "init() must not report seeded with zero accumulated entropy"
        );

        let mut buf = [0u8; 4];
        assert_eq!(
            kernel_random_bytes(&mut buf),
            Err(CsprngError::NotSeeded),
            "an init() that gave up before reaching SEED_ENTROPY_BITS must leave \
             the CSPRNG unseeded (fail-closed), not silently seed FROM an empty pool"
        );
    }

    #[test]
    // WHY: CSPRNG_INIT_TIMEOUT_MS is a fixed crate const, so both bounds
    // below are compile-time-constant to clippy. This test exists precisely
    // to pin that literal within a sane range as a discoverable, individually
    // reportable host test (not a const-eval assert) so a future edit to the
    // constant fails a named test rather than a silent build-time check.
    #[expect(
        clippy::assertions_on_constants,
        reason = "pins a compile-time constant to a sane range as a named, individually-reportable host test rather than a silent const-eval assert"
    )]
    fn csprng_init_timeout_is_sane() {
        assert!(
            CSPRNG_INIT_TIMEOUT_MS >= 5_000,
            "timeout must be generous enough for a slow/noisy real timer"
        );
        assert!(
            CSPRNG_INIT_TIMEOUT_MS <= 60_000,
            "timeout must not stall boot for an unreasonable amount of time"
        );
    }

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

    /// The per-tick CNTPCT advance this platform actually produces: a 10 ms
    /// tick against the MT6739's 13 MHz CNTFRQ. Its residue inside
    /// `TIMER_JITTER_MASK` is `130_000 % 4096 = 3024` (seven bits set), which
    /// is what the superseded raw-XOR estimator credited every tick.
    const REGULAR_TICK_DELTA: u32 = 130_000;

    #[test]
    fn perfectly_regular_delta_never_seeds() {
        // #840 regression, and the shape this platform's own timer produces:
        // a fixed reload against a fixed CNTFRQ. There is no unpredictability
        // in an arithmetic progression, so it must never satisfy the gate --
        // however many ticks arrive, and regardless of how many bits the raw
        // sample-to-sample XOR would have flipped.
        let mut pool = EntropyPool::new();
        let mut sample: u32 = 0;
        for _ in 0..100_000 {
            sample = sample.wrapping_add(REGULAR_TICK_DELTA);
            pool.add_timer_sample(sample);
        }
        assert_eq!(
            pool.entropy_bits, 0,
            "a constant interval must credit zero (#840)"
        );
        assert!(
            !pool.is_seeded(),
            "a perfectly regular timer must never seed the pool (#840)"
        );
    }

    #[test]
    fn the_superseded_estimator_would_have_credited_that_delta() {
        // Pins WHY the test above is not vacuous. The old estimator scored
        // `count_ones(sample ^ last_sample & MASK)`; on this exact progression
        // that is seven bits per tick, so it reached the 256-bit gate in 37
        // ticks of a fully deterministic source. If a future change makes this
        // arithmetic stop holding, the regression above is no longer covering
        // the case it names.
        let a: u32 = 0;
        let b: u32 = a.wrapping_add(REGULAR_TICK_DELTA);
        let old_credit = ((a ^ b) & TIMER_JITTER_MASK).count_ones();
        assert!(
            old_credit > 0,
            "the superseded estimator must be shown to credit this progression"
        );
        assert!(
            (SEED_ENTROPY_BITS / old_credit) < 100_000,
            "the superseded estimator must be shown to REACH the gate on it"
        );
    }

    #[test]
    fn alternating_cadence_never_seeds() {
        // A periodic rather than constant cadence: the interval alternates
        // between two fixed values, so the departure alternates in sign and
        // repeats in magnitude. Fully predictable to anyone who has watched
        // two ticks, so the repetition guard must refuse it.
        let mut pool = EntropyPool::new();
        let mut sample: u32 = 0;
        for i in 0..100_000u32 {
            let step = if i % 2 == 0 {
                REGULAR_TICK_DELTA
            } else {
                REGULAR_TICK_DELTA + 37
            };
            sample = sample.wrapping_add(step);
            pool.add_timer_sample(sample);
        }
        assert!(
            !pool.is_seeded(),
            "an alternating cadence carries no unpredictability and must not seed"
        );
    }

    #[test]
    fn irregular_cadence_still_seeds() {
        // The gate must remain reachable: an estimator that refuses everything
        // is fail-closed into a kernel that never boots. Jitter here is small
        // relative to the tick -- the scale real ISR latency produces -- and
        // never repeats its predecessor.
        let mut pool = EntropyPool::new();
        let mut sample: u32 = 0;
        let mut ticks = 0u32;
        // A cheap non-repeating wander; the exact values do not matter, only
        // that consecutive departures differ.
        let mut lcg: u32 = 0x1234_5678;
        while !pool.is_seeded() && ticks < 100_000 {
            lcg = lcg.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let jitter = lcg >> 27; // 0..=31 counts of latency wander
            sample = sample.wrapping_add(REGULAR_TICK_DELTA + jitter);
            pool.add_timer_sample(sample);
            ticks += 1;
        }
        assert!(
            pool.is_seeded(),
            "realistic latency jitter must still be able to seed the pool"
        );
        assert!(
            ticks >= SEED_ENTROPY_BITS / MAX_CREDIT_BITS_PER_SAMPLE,
            "the per-sample ceiling must hold: {ticks} ticks is fewer than the \
             floor the cap imposes"
        );
    }

    #[test]
    fn one_huge_excursion_cannot_seed_the_pool() {
        // A single gross departure -- a missed tick, a frequency change -- is
        // one event. Without the ceiling its masked popcount alone could carry
        // a large share of the gate.
        let mut pool = EntropyPool::new();
        pool.add_timer_sample(0);
        pool.add_timer_sample(REGULAR_TICK_DELTA);
        pool.add_timer_sample(REGULAR_TICK_DELTA.wrapping_mul(2).wrapping_add(0x0FFF));
        assert!(
            pool.entropy_bits <= MAX_CREDIT_BITS_PER_SAMPLE,
            "a single sample must not credit more than the ceiling, got {}",
            pool.entropy_bits
        );
    }

    #[test]
    fn entropy_pool_cursor_wraps() {
        let mut pool = EntropyPool::new();
        pool.mix_bytes(&[0xFFu8; 32]);
        assert_eq!(
            pool.cursor, 0,
            "cursor must wrap around to 0 after 32 bytes"
        );
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
        assert_ne!(
            &buf[..64],
            &buf[64..],
            "consecutive blocks must be distinct"
        );
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
    fn kernel_random_bytes_auto_reseeds_after_threshold() {
        let key = [0x33u8; 32];
        let nonce = [0u8; 8];
        seed_for_test(&key, &nonce, 0);

        // Force bytes_generated right up to the threshold so the next
        // call crosses RESEED_THRESHOLD and exercises the auto-reseed
        // branch inside kernel_random_bytes.
        // SAFETY: test-only manipulation of global state.
        unsafe {
            if let Some(c) = (*core::ptr::addr_of_mut!(CSPRNG)).as_mut() {
                c.bytes_generated = RESEED_THRESHOLD - 4;
            }
        }

        let mut buf = [0u8; 4];
        kernel_random_bytes(&mut buf).expect("seeded test rng");

        // SAFETY: test-only read of global state.
        let bytes_generated_after = unsafe {
            (*core::ptr::addr_of_mut!(CSPRNG))
                .as_ref()
                .map(|c| c.bytes_generated)
        };
        assert_eq!(
            bytes_generated_after,
            Some(0),
            "crossing RESEED_THRESHOLD must reset the reseed counter"
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
            0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90, 0x40, 0x5d, 0x6a, 0xe5, 0x53, 0x86,
            0xbd, 0x28, 0xbd, 0xd2, 0x19, 0xb8, 0xa0, 0x8d, 0xed, 0x1a, 0xa8, 0x36, 0xef, 0xcc,
            0x8b, 0x77, 0x0d, 0xc7, 0xda, 0x41, 0x59, 0x7c, 0x51, 0x57, 0x48, 0x8d, 0x77, 0x24,
            0xe0, 0x3f, 0xb8, 0xd8, 0x4a, 0x37, 0x6a, 0x43, 0xb8, 0xf4, 0x15, 0x18, 0xa1, 0x1c,
            0xc3, 0x87, 0xb6, 0x69, 0xb2, 0xee, 0x65, 0x86,
        ];
        assert_eq!(
            buf, expected,
            "ChaCha20 block 0 must match RFC 8439 Test Vector #1"
        );
    }
}
