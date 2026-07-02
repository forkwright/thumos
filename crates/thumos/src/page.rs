//! Physical page allocator.
//!
//! Simple bitmap allocator for 4 KB pages. The MT6739 has ~914 MB RAM.
//! The kernel, device memory, and reserved regions are marked as allocated at init.

use core::ptr::addr_of_mut;

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

/// Initialize the page allocator.
///
/// # Safety
///
/// Must be called exactly once during kernel init, before any allocations.
pub unsafe fn init(ram_start: usize, ram_end: usize, kernel_end: usize) {
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
        #[expect(unsafe_code, reason = "volatile write required to defeat dead-store elimination when zeroing a page")]
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
        #[expect(unsafe_code, reason = "delegating to zero_page under the caller's range contract")]
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
            #[expect(unsafe_code, reason = "zeroing a page immediately before freeing it, per this function's own SAFETY analysis above")]
            unsafe {
                zero_page(addr);
            }
        }
        bitmap[word] &= !(1 << bit);
        FREE_PAGES += 1;
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

    static mut TEST_BUF_SINGLE: [u8; PAGE_SIZE] = [0u8; PAGE_SIZE];

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
    static mut TEST_BUF_RANGE: [u8; TEST_RANGE_PAGES * PAGE_SIZE] =
        [0u8; TEST_RANGE_PAGES * PAGE_SIZE];

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
            assert_eq!(zeroed, TEST_RANGE_PAGES, "must report every page in range as zeroed");

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
}
