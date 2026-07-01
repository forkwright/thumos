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
        for page in start_page..end_page {
            let word = page / 32;
            let bit = page % 32;
            bitmap[word] &= !(1 << bit);
        }
    }
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
        let _ = try_free_page(addr);
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
