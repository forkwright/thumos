//! Physical page allocator.
//!
//! Simple bitmap allocator for 4 KB pages. The MT6739 has ~914 MB RAM.
//! The kernel, device memory, and reserved regions are marked as allocated at init.
//!
//! # Thread safety
//!
//! `PAGE_BITMAP`/`FREE_PAGES` mutations are serialized by `PAGE_LOCK`, an
//! IRQ-safe spinlock (`irq::IrqSpinlock`) shared by every accessor --
//! `alloc_page`, `try_free_page`, and `free_count` alike. Without it, an
//! IRQ-context allocation (the slab allocator's refill path) can interleave
//! its non-atomic `*word |= 1 << bit` with a direct, non-slab caller
//! (process creation, mmap/brk, panic-wipe) and hand out the same physical
//! frame twice (#331). `init()` also takes the lock for the same
//! `PAGE_BITMAP`/`FREE_PAGES` writes, even though it runs once during early
//! boot before interrupts are enabled -- no accessor is exempt.

use core::ptr::addr_of_mut;

use crate::irq;

/// Page size: 4 KB (ARM standard).
pub(crate) const PAGE_SIZE: usize = 4096;

/// Maximum physical pages for 1 GB RAM.
const MAX_PAGES: usize = 1024 * 1024 * 1024 / PAGE_SIZE;

/// Bitmap: 1 bit per page. 0 = free, 1 = allocated.
static mut PAGE_BITMAP: [u32; MAX_PAGES / 32] = [0; MAX_PAGES / 32];
static mut FREE_PAGES: usize = 0;
static mut FIRST_PAGE: usize = 0;
/// Start/end page-number bounds of the usable (dynamically-managed) range,
/// set once by `init()`. Lets `zero_usable_range` walk the full range
/// directly by address, independent of the free/allocated bitmap (#321).
static mut USABLE_START_PAGE: usize = 0;
static mut USABLE_END_PAGE: usize = 0;

/// WHY (#331): guards every `PAGE_BITMAP`/`FREE_PAGES` accessor.
static PAGE_LOCK: irq::IrqSpinlock = irq::IrqSpinlock::new();

/// Initialize the page allocator.
///
/// # Safety
///
/// Must be called exactly once during kernel init, before any allocations.
pub unsafe fn init(ram_start: usize, ram_end: usize, kernel_end: usize) {
    let _g = PAGE_LOCK.lock();
    // SAFETY: page frame index is within physical memory bounds (checked by caller).
    unsafe {
        let usable_start = (kernel_end + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        let usable_end = ram_end & !(PAGE_SIZE - 1);

        FIRST_PAGE = ram_start;
        let total = (usable_end - usable_start) / PAGE_SIZE;
        FREE_PAGES = total;

        let bitmap = &mut *addr_of_mut!(PAGE_BITMAP);
        for word in bitmap.iter_mut() {
            *word = 0xFFFF_FFFF;
        }

        let start_page = (usable_start - ram_start) / PAGE_SIZE;
        let end_page = (usable_end - ram_start) / PAGE_SIZE;
        USABLE_START_PAGE = start_page;
        USABLE_END_PAGE = end_page;
        for page in start_page..end_page {
            let word = page / 32;
            let bit = page % 32;
            bitmap[word] &= !(1 << bit);
        }
    }
}

/// Overwrite a page's contents with zeros via volatile writes.
///
/// WHY volatile: from the compiler's point of view a page about to be
/// freed or scrubbed looks dead; a future allocation reading the same
/// physical memory is invisible to the optimizer. `write_volatile`
/// forbids eliding the store.
///
/// # Safety
///
/// `addr` must be a valid, page-aligned physical address of a mapped
/// `PAGE_SIZE`-byte region.
unsafe fn zero_page(addr: usize) {
    for offset in (0..PAGE_SIZE).step_by(core::mem::size_of::<usize>()) {
        let ptr = (addr + offset) as *mut usize;
        // SAFETY: addr is page-aligned (caller contract) and PAGE_SIZE is a
        // multiple of size_of::<usize>(), so offset stays in bounds and ptr
        // stays usize-aligned throughout the loop.
        #[expect(
            unsafe_code,
            reason = "volatile write required to defeat dead-store elimination when zeroing a page"
        )]
        unsafe {
            core::ptr::write_volatile(ptr, 0);
        }
    }
}

/// Zero every page in `[start_page, end_page)`, addressed relative to
/// `first_page`. Pure address-range zeroing: no bitmap access, no
/// allocation, no global state — callable and testable in isolation.
///
/// Returns the number of pages zeroed.
///
/// # Safety
///
/// `first_page + start_page * PAGE_SIZE` through
/// `first_page + end_page * PAGE_SIZE` must describe a valid, mapped,
/// page-aligned address range. The caller must not read or write any page
/// in that range while or after this runs.
unsafe fn zero_page_range(first_page: usize, start_page: usize, end_page: usize) -> usize {
    let mut zeroed = 0usize;
    for page_num in start_page..end_page {
        let addr = first_page + page_num * PAGE_SIZE;
        // SAFETY: addr falls within the caller-validated range.
        #[expect(
            unsafe_code,
            reason = "delegating to zero_page under the caller's range contract"
        )]
        unsafe {
            zero_page(addr);
        }
        zeroed += 1;
    }
    zeroed
}

/// Zero every page frame in the managed usable range, in place — both
/// currently-free and currently-allocated frames alike.
///
/// Walks the usable physical range directly by address; it does NOT go
/// through `alloc_page`/`free_page` and performs no heap allocation, so it
/// cannot trigger `handle_alloc_error` regardless of free-page count
/// (#321). It does not consult or mutate `PAGE_BITMAP` — allocator
/// bookkeeping is left exactly as it was; this is a pure memory scrub, not
/// a free operation.
///
/// Returns the number of pages zeroed (0 if `init` was never called).
///
/// # Safety
///
/// The caller must not read or write ANY page in the managed usable range
/// — free or allocated — while or after calling this, until the next
/// reboot: every live heap object, process page, and kernel data
/// structure backed by this range is destroyed. This must be the LAST
/// action taken before an immediate halt/reboot; it must never be called
/// from a path that returns to normal execution. (Not yet wired into a
/// live boot/panic path — see `panic_wipe::scrub_user_pages`.)
pub unsafe fn zero_usable_range() -> usize {
    // SAFETY: FIRST_PAGE/USABLE_START_PAGE/USABLE_END_PAGE are set once by
    // init() before boot proceeds past page-allocator init (single-core,
    // pre-concurrency); this function's own contract above governs the
    // destructive read/write that follows.
    unsafe { zero_page_range(FIRST_PAGE, USABLE_START_PAGE, USABLE_END_PAGE) }
}

/// Allocate a single physical page. Returns the physical address, or None.
pub(crate) fn alloc_page() -> Option<usize> {
    // WHY (#331): serializes with every other PAGE_BITMAP/FREE_PAGES
    // accessor, including an IRQ-context caller, so a duplicate-frame race
    // cannot occur (see the module doc).
    let _g = PAGE_LOCK.lock();
    // SAFETY: page frame index is within physical memory bounds (checked by caller).
    unsafe {
        if FREE_PAGES == 0 {
            return None;
        }

        let bitmap = &mut *addr_of_mut!(PAGE_BITMAP);
        for (word_idx, word) in bitmap.iter_mut().enumerate() {
            if *word != 0xFFFF_FFFF {
                let bit = (*word).trailing_ones() as usize;
                *word |= 1 << bit;
                FREE_PAGES -= 1;
                let page_num = word_idx * 32 + bit;
                return Some(FIRST_PAGE + page_num * PAGE_SIZE);
            }
        }
        None
    }
}

/// Free a physical page back to the allocator, reporting whether it happened.
///
/// Returns `true` if a page was freed, `false` if `addr` is rejected: below the
/// managed base (a raw subtraction would unsigned-wrap into a huge index),
/// misaligned, past the bitmap, or not currently allocated (double-free). A
/// rejected address leaves allocator state completely unchanged.
///
/// # Safety
///
/// `addr` should be an address previously returned by `alloc_page`. The range
/// and allocation-state guards make an invalid `addr` a no-op rather than a
/// bitmap-corruption / double-free primitive, but callers must still not use a
/// page after freeing it.
pub unsafe fn try_free_page(addr: usize) -> bool {
    // WHY (#331): serializes with every other PAGE_BITMAP/FREE_PAGES
    // accessor (see the module doc) so a concurrent alloc/free pair can
    // never observe or corrupt a torn bitmap update.
    let _g = PAGE_LOCK.lock();
    // SAFETY: every bitmap access below is bounds-checked against the array
    // length, and FREE_PAGES is incremented only when a set bit is actually
    // cleared, so an out-of-range or already-free address cannot corrupt
    // memory or inflate the free count.
    unsafe {
        // Reject addresses below the managed base — the frame-index subtraction
        // would underflow (unsigned wrap on ARM32) into a huge out-of-range
        // index, corrupting kernel .bss/.data.
        if addr < FIRST_PAGE {
            return false;
        }
        let offset = addr - FIRST_PAGE;
        // Reject misaligned addresses — they never name a real frame.
        if offset % PAGE_SIZE != 0 {
            return false;
        }
        let page_num = offset / PAGE_SIZE;
        let word = page_num / 32;
        let bit = page_num % 32;
        let bitmap = &mut *addr_of_mut!(PAGE_BITMAP);
        // Reject indices past the bitmap — prevents out-of-bounds writes.
        if word >= bitmap.len() {
            return false;
        }
        // Reject double-free — only a currently-allocated (set) bit may be
        // cleared, so freeing a free page cannot alias it back into service.
        if bitmap[word] & (1 << bit) == 0 {
            return false;
        }
        // SAFETY: addr passed every guard above — within the managed range,
        // page-aligned, within the bitmap, and currently allocated. Zero it
        // before it is returned to the free pool so a page that held
        // decrypted data or key material is not handed to the next
        // allocation owner unscrubbed (#334).
        //
        // WHY cfg(not(test)): this dereferences `addr` as real physical
        // memory. On the armv7a device every managed frame is real,
        // identity-mapped DRAM, so the scrub runs and is correct. Host unit
        // tests initialise this allocator over a FABRICATED physical range
        // (see `process::tests` / the `page::init(0x4000_0000, …)` calls)
        // whose addresses are not backed by mapped host memory, so
        // dereferencing them faults (SIGSEGV) — the same reason `mmio`
        // hardware access is never exercised on host. The zeroing PRIMITIVE
        // (`zero_page`) is unit-tested directly against a real buffer below;
        // only this on-free integration deref is device-only. Skipping it
        // under test changes nothing the bitmap-level free tests observe.
        #[cfg(not(test))]
        {
            zero_page(addr);
        }
        bitmap[word] &= !(1 << bit);
        FREE_PAGES += 1;
        true
    }
}

/// Allocate `n` physically-contiguous free pages, returning the base address
/// or `None` if no run of `n` free pages exists.
///
/// WHY (#475): the slab's large-allocation path and per-process page-table
/// mappings need runs larger than one page, but `alloc_page` gives no
/// contiguity guarantee (it returns the lowest free frame). A first-fit scan of
/// the free bitmap returns the lowest run of `n`, skipping fully-allocated
/// words. `n == 1` delegates to `alloc_page`.
pub(crate) fn alloc_contiguous(n: usize) -> Option<usize> {
    if n == 0 {
        return None;
    }
    if n == 1 {
        return alloc_page();
    }
    // WHY (#331): serializes with every other PAGE_BITMAP/FREE_PAGES accessor.
    let _g = PAGE_LOCK.lock();
    // SAFETY: every bitmap index below is bounds-checked by the enclosing
    // iteration over `bitmap`; FREE_PAGES is decremented by exactly the `n`
    // bits set.
    unsafe {
        if FREE_PAGES < n {
            return None;
        }
        let bitmap = &mut *addr_of_mut!(PAGE_BITMAP);
        let mut run = 0usize;
        let mut run_start = 0usize;
        for word_idx in 0..bitmap.len() {
            // A fully-allocated word breaks any in-progress run; skip its bits.
            if bitmap[word_idx] == 0xFFFF_FFFF {
                run = 0;
                continue;
            }
            for bit in 0..32 {
                if (bitmap[word_idx] >> bit) & 1 == 1 {
                    run = 0;
                    continue;
                }
                if run == 0 {
                    run_start = word_idx * 32 + bit;
                }
                run += 1;
                if run == n {
                    for p in run_start..run_start + n {
                        bitmap[p / 32] |= 1 << (p % 32);
                    }
                    FREE_PAGES -= n;
                    return Some(FIRST_PAGE + run_start * PAGE_SIZE);
                }
            }
        }
        None
    }
}

/// Free `n` physically-contiguous pages previously returned by
/// `alloc_contiguous`. Returns `false` (no state change) if the range is
/// misaligned, out of range, or not fully allocated (double-free guard). `n ==
/// 1` delegates to `try_free_page`.
///
/// # Safety
///
/// `addr`/`n` must name a run previously returned by `alloc_contiguous` and not
/// since freed.
pub unsafe fn free_contiguous(addr: usize, n: usize) -> bool {
    if n == 0 {
        return false;
    }
    if n == 1 {
        // SAFETY: delegated to the validated single-page path.
        return unsafe { try_free_page(addr) };
    }
    let _g = PAGE_LOCK.lock();
    // SAFETY: the run is fully validated (range + currently-allocated) before
    // any bit is cleared, so an invalid free is an all-or-nothing no-op.
    unsafe {
        if addr < FIRST_PAGE {
            return false;
        }
        let offset = addr - FIRST_PAGE;
        if offset % PAGE_SIZE != 0 {
            return false;
        }
        let start = offset / PAGE_SIZE;
        let bitmap = &mut *addr_of_mut!(PAGE_BITMAP);
        for p in start..start + n {
            let word = p / 32;
            if word >= bitmap.len() || bitmap[word] & (1 << (p % 32)) == 0 {
                return false;
            }
        }
        for p in start..start + n {
            // Scrub before return to the pool (#334); device-only (see
            // try_free_page's cfg(not(test)) rationale).
            #[cfg(not(test))]
            {
                zero_page(FIRST_PAGE + p * PAGE_SIZE);
            }
            bitmap[p / 32] &= !(1 << (p % 32));
        }
        FREE_PAGES += n;
        true
    }
}

/// Free a physical page back to the allocator, ignoring the outcome.
///
/// Fire-and-forget wrapper over [`try_free_page`] for callers that free pages
/// they are certain they own, and for use as a bare `unsafe fn(usize)` pointer
/// (e.g. the slab allocator's large-object free hook). An invalid address is a
/// safe no-op via the same guards.
///
/// # Safety
///
/// Same contract as [`try_free_page`].
pub unsafe fn free_page(addr: usize) {
    // SAFETY: try_free_page validates the address range and allocation state;
    // an invalid address is a no-op rather than corruption.
    unsafe {
        let _ = try_free_page(addr); // kanon:ignore RUST/no-silent-result-swallow -- try_free_page returns bool (not Result); deliberate fire-and-forget per doc comment above, an invalid address is a defined safe no-op, not an error to propagate
    }
}

/// Return the number of free pages.
pub(crate) fn free_count() -> usize {
    // WHY (#331): reads FREE_PAGES under the same lock every writer uses,
    // so this can't observe a torn/partial update mid-mutation.
    let _g = PAGE_LOCK.lock();
    // SAFETY: page frame index is within physical memory bounds (checked by caller).
    unsafe { FREE_PAGES }
}

/// Return free memory in bytes.
pub(crate) fn free_bytes() -> usize {
    free_count() * PAGE_SIZE
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
//
// WHY these tests avoid page::init(): PAGE_BITMAP/FREE_PAGES/FIRST_PAGE/
// USABLE_START_PAGE/USABLE_END_PAGE are process-global statics, and Rust's
// default test harness runs tests on separate threads, so two tests both
// calling init() would race. zero_page and zero_page_range take their
// range as explicit parameters and never touch the bitmap or FREE_PAGES,
// so they can be exercised directly against private, test-owned static
// buffers instead (each test below uses its own buffer, never shared).

#[cfg(test)]
mod tests {
    use super::*;

    /// Page-aligned static backing buffer for the zeroing tests.
    ///
    /// WHY repr(align): `zero_page` writes through `*mut usize`, so the
    /// backing store must be at least usize-aligned. A bare `static [u8; N]`
    /// has alignment 1 — the compiler may place it at any byte address, and a
    /// CI runner did, tripping the debug misaligned-pointer-dereference check
    /// (SIGABRT) that a locally-lucky address had hidden. Page alignment also
    /// matches production, where these buffers stand in for real page frames.
    #[repr(align(4096))]
    struct AlignedBuf<const N: usize>([u8; N]);

    static mut TEST_BUF_SINGLE: AlignedBuf<PAGE_SIZE> = AlignedBuf([0u8; PAGE_SIZE]);

    #[test]
    fn zero_page_clears_every_byte() {
        // SAFETY: TEST_BUF_SINGLE is a private static touched only by this
        // test.
        unsafe {
            let base = core::ptr::addr_of_mut!(TEST_BUF_SINGLE) as *mut u8 as usize;
            let ptr = base as *mut u8;
            for i in 0..PAGE_SIZE {
                core::ptr::write_volatile(ptr.add(i), 0xAA);
            }

            zero_page(base);

            for i in 0..PAGE_SIZE {
                assert_eq!(
                    core::ptr::read_volatile(ptr.add(i)),
                    0,
                    "byte {i} must be zeroed, not left as the 0xAA sentinel"
                );
            }
        }
    }

    const TEST_RANGE_PAGES: usize = 3;
    static mut TEST_BUF_RANGE: AlignedBuf<{ TEST_RANGE_PAGES * PAGE_SIZE }> =
        AlignedBuf([0u8; TEST_RANGE_PAGES * PAGE_SIZE]);

    #[test]
    fn zero_page_range_zeroes_every_page_in_range() {
        // Regression test for #321: the old scrub only reached free frames
        // (via alloc_page) and could abort via handle_alloc_error. This
        // proves zero_page_range reaches every page in an address range
        // with no allocator/bitmap interaction at all.
        // SAFETY: TEST_BUF_RANGE is a private static touched only by this
        // test.
        // WHY the const, not TEST_BUF_RANGE.len(): reading `.len()` off a
        // `static mut` creates a shared reference to it, which is a hard
        // error under this crate's `deny(static_mut_refs)`. The length is a
        // compile-time constant, so use it directly.
        const RANGE_LEN: usize = TEST_RANGE_PAGES * PAGE_SIZE;
        unsafe {
            let base = core::ptr::addr_of_mut!(TEST_BUF_RANGE) as *mut u8 as usize;
            let ptr = base as *mut u8;
            for i in 0..RANGE_LEN {
                core::ptr::write_volatile(ptr.add(i), 0xBB);
            }

            let zeroed = zero_page_range(base, 0, TEST_RANGE_PAGES);
            assert_eq!(
                zeroed, TEST_RANGE_PAGES,
                "must report every page in range as zeroed"
            );

            for i in 0..RANGE_LEN {
                assert_eq!(
                    core::ptr::read_volatile(ptr.add(i)),
                    0,
                    "byte {i} across the whole range must be zeroed"
                );
            }
        }
    }

    #[test]
    fn zero_page_range_empty_range_is_a_no_op() {
        // SAFETY: an empty range performs zero memory accesses, so an
        // arbitrary base address is safe here.
        let zeroed = unsafe { zero_page_range(0, 5, 5) };
        assert_eq!(zeroed, 0, "an empty range must zero nothing");
    }

    // -----------------------------------------------------------------------
    // #331: IRQ-safe locking
    // -----------------------------------------------------------------------
    //
    // WHY these tests exercise PAGE_LOCK directly rather than going through
    // alloc_page()/try_free_page(): those need page::init() first, and this
    // file's tests deliberately avoid init() (see the file-level WHY comment
    // above) because PAGE_BITMAP/FREE_PAGES/FIRST_PAGE are shared statics
    // that a threaded harness could race across tests. PAGE_LOCK's
    // masking/nesting contract is independent of whether init() ran, so it
    // is fully testable in isolation the same way.

    #[test]
    fn page_lock_masks_irqs_for_the_critical_section() {
        // Regression test for #331: PAGE_BITMAP/FREE_PAGES mutations must
        // run inside an IRQ-masked critical section shared by every caller
        // -- the slab-internal refill path AND the direct callers in
        // process.rs/syscall.rs -- or an IRQ-context alloc_page() can
        // interleave with a non-locked in-progress caller and hand out the
        // same physical frame twice. Host-testable via the mock IRQ-state
        // seam in `irq` (the real CPSR I-bit is ARM-only).
        crate::irq::reset_mock();
        assert!(crate::irq::mock_enabled(), "starts unmasked");
        let guard = PAGE_LOCK.lock();
        assert!(
            !crate::irq::mock_enabled(),
            "PAGE_LOCK.lock() must mask IRQ delivery while held"
        );
        drop(guard);
        assert!(
            crate::irq::mock_enabled(),
            "dropping the guard must restore IRQ delivery"
        );
    }

    #[test]
    fn nested_irq_guard_does_not_unmask_while_page_lock_held() {
        // The property that prevents the #331 double-allocation race: a
        // nested critical section must not unmask IRQ delivery early and
        // let an interrupt-context allocator run before the OUTER critical
        // section -- the page lock -- has released.
        crate::irq::reset_mock();
        let outer = PAGE_LOCK.lock();
        assert!(!crate::irq::mock_enabled());
        let inner = crate::irq::IrqGuard::new();
        assert!(!crate::irq::mock_enabled());
        drop(inner);
        assert!(
            !crate::irq::mock_enabled(),
            "inner drop must not unmask while the page lock is still held"
        );
        drop(outer);
        assert!(
            crate::irq::mock_enabled(),
            "outer drop restores IRQ delivery"
        );
    }

    #[test]
    fn init_computes_bitmap_boundaries_from_unaligned_inputs() {
        // Done-when (finding 38): kernel_end must round UP to the next
        // page boundary (so a kernel ending mid-page never bleeds into
        // the free pool) and ram_end must round DOWN to a page boundary;
        // init must then mark exactly [start_page, end_page) free and
        // every other page allocated.
        //
        // WHY calling page::init() here (unlike this file's other tests,
        // which deliberately avoid it to prevent intra-file races): this
        // is the ONLY test in this module touching PAGE_BITMAP/
        // FREE_PAGES, so there is no race within this file -- the same
        // accepted pattern process.rs's tests already use for
        // page::init() with fabricated (never-dereferenced) addresses.
        const RAM_START: usize = 0x1000_0000;
        // kernel_end lands inside page index 1 (not aligned) -> must
        // round UP to page index 2.
        const KERNEL_END: usize = RAM_START + 4660;
        // ram_end lands just past page index 10's start (not aligned) ->
        // must round DOWN to page index 10.
        const RAM_END: usize = RAM_START + 10 * PAGE_SIZE + 5;

        // SAFETY: test-only; RAM_START/RAM_END/KERNEL_END are never
        // dereferenced by init() -- it only computes page-index
        // bookkeeping.
        unsafe {
            init(RAM_START, RAM_END, KERNEL_END);

            // addr_of!().read() avoids a shared reference to the static mut.
            let first = core::ptr::addr_of!(FIRST_PAGE).read();
            let usable_start = core::ptr::addr_of!(USABLE_START_PAGE).read();
            let usable_end = core::ptr::addr_of!(USABLE_END_PAGE).read();
            let free = core::ptr::addr_of!(FREE_PAGES).read();
            assert_eq!(first, RAM_START);
            assert_eq!(usable_start, 2, "kernel_end must round UP to page index 2");
            assert_eq!(usable_end, 10, "ram_end must round DOWN to page index 10");
            assert_eq!(free, 8, "8 usable pages (index 2..10) must be free");

            let bitmap = &*core::ptr::addr_of!(PAGE_BITMAP);
            let is_allocated = |page: usize| bitmap[page / 32] & (1 << (page % 32)) != 0;

            assert!(
                is_allocated(0),
                "page 0 (below usable start) must be allocated"
            );
            assert!(
                is_allocated(1),
                "page 1 (below usable start) must be allocated"
            );
            for page in 2..10 {
                assert!(
                    !is_allocated(page),
                    "page {page} (within the usable range) must be free"
                );
            }
            assert!(
                is_allocated(10),
                "page 10 (at usable end, exclusive) must be allocated"
            );
            assert!(
                is_allocated(11),
                "page 11 (past usable end) must be allocated"
            );
        }
    }

    #[test]
    fn alloc_and_free_round_trip_yields_distinct_pages_and_rejects_double_free() {
        // Done-when (finding 39): alloc_page/try_free_page/free_count
        // have zero coverage in this module (the file's other tests only
        // exercise zero_page/zero_page_range/PAGE_LOCK to avoid
        // page::init() races). This is the second (and only other) test
        // here to call page::init(); like
        // init_computes_bitmap_boundaries_from_unaligned_inputs it is the
        // only test touching PAGE_BITMAP/FREE_PAGES via this specific
        // call, and process.rs's tests already independently call
        // page::init() with fabricated addresses, so this does not
        // introduce a new class of risk.
        const RAM_START: usize = 0x2000_0000;
        const RAM_END: usize = RAM_START + 4 * PAGE_SIZE;
        const KERNEL_END: usize = RAM_START; // entire range usable

        // SAFETY: test-only; fabricated addresses are never dereferenced
        // by the allocator's bookkeeping in a `#[cfg(test)]` build (the
        // zero-on-free memory scrub is `#[cfg(not(test))]`-gated; see
        // try_free_page's own WHY comment).
        unsafe {
            init(RAM_START, RAM_END, KERNEL_END);
            assert_eq!(free_count(), 4, "4 whole pages must be free after init");

            let a = alloc_page().expect("first allocation must succeed");
            let b = alloc_page().expect("second allocation must succeed");
            assert_ne!(a, b, "two allocations must never return the same page");
            assert_eq!(
                free_count(),
                2,
                "free_count must drop by 2 after 2 allocations"
            );

            assert!(try_free_page(a), "freeing an allocated page must succeed");
            assert_eq!(free_count(), 3, "free_count must rise by 1 after freeing");

            // Double-free of the same address must be rejected, not
            // double-increment free_count.
            assert!(
                !try_free_page(a),
                "double-freeing the same page must be rejected"
            );
            assert_eq!(
                free_count(),
                3,
                "a rejected double-free must not change free_count"
            );

            // The freed page must be handed out again on the next
            // allocation (bitmap correctly reflects the free bit).
            let c = alloc_page().expect("third allocation must succeed");
            assert_eq!(c, a, "the freed page must be reusable");

            try_free_page(b);
            try_free_page(c);
        }
    }

    #[test]
    fn contiguous_alloc_free_round_trip() {
        // #475: alloc_contiguous(3) must return a page-aligned base whose 3
        // pages are contiguous + marked allocated, and free_contiguous must
        // restore them (with a double-free guard).
        const RAM_START: usize = 0x2000_0000;
        const RAM_END: usize = RAM_START + 16 * PAGE_SIZE;
        // SAFETY: test-only fabricated addresses; init() only bookkeeps and the
        // cfg(test) build skips the scrub deref, so they are never dereferenced.
        unsafe {
            init(RAM_START, RAM_END, RAM_START);
            assert_eq!(core::ptr::addr_of!(FREE_PAGES).read(), 16);

            let base = alloc_contiguous(3).expect("3-run in a fresh 16-page pool");
            assert_eq!(base % PAGE_SIZE, 0, "base must be page-aligned");
            assert!(base >= RAM_START && base + 3 * PAGE_SIZE <= RAM_END);
            assert_eq!(
                core::ptr::addr_of!(FREE_PAGES).read(),
                13,
                "3 pages consumed"
            );

            let bitmap = &*core::ptr::addr_of!(PAGE_BITMAP);
            let start = (base - RAM_START) / PAGE_SIZE;
            for p in start..start + 3 {
                assert!(
                    bitmap[p / 32] & (1 << (p % 32)) != 0,
                    "page {p} of the run must be allocated"
                );
            }

            assert!(free_contiguous(base, 3), "freeing the run must succeed");
            assert_eq!(
                core::ptr::addr_of!(FREE_PAGES).read(),
                16,
                "all pages returned"
            );
            assert!(
                !free_contiguous(base, 3),
                "double-free of the run must be rejected"
            );
            assert_eq!(core::ptr::addr_of!(FREE_PAGES).read(), 16);
        }
    }

    #[test]
    fn contiguous_alloc_respects_fragmentation_and_exhaustion() {
        // #475: a run larger than the pool fails; and a pool with enough FREE
        // pages but no contiguous run of the requested size also fails.
        const RAM_START: usize = 0x3000_0000;
        const RAM_END: usize = RAM_START + 8 * PAGE_SIZE;
        // SAFETY: test-only fabricated addresses, never dereferenced.
        unsafe {
            init(RAM_START, RAM_END, RAM_START);
            assert!(alloc_contiguous(9).is_none(), "no 9-run in an 8-page pool");
            // Allocate all 8, then free only the even pages: 4 free, none
            // adjacent.
            for _ in 0..8 {
                alloc_page().expect("pool has 8 pages");
            }
            for p in [0usize, 2, 4, 6] {
                assert!(try_free_page(RAM_START + p * PAGE_SIZE));
            }
            assert_eq!(core::ptr::addr_of!(FREE_PAGES).read(), 4);
            assert!(
                alloc_contiguous(2).is_none(),
                "4 free pages but no 2-run (fragmentation)"
            );
            assert!(
                alloc_contiguous(1).is_some(),
                "a single page still allocates (delegates to alloc_page)"
            );
        }
    }
}
