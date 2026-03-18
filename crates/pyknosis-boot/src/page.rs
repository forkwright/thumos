//! Physical page allocator.
//!
//! Simple bitmap allocator for 4 KB pages. The MT6739 has ~914 MB RAM.
//! The kernel, device memory, and reserved regions are marked as allocated at init.

use core::ptr::addr_of_mut;

/// Page size: 4 KB (ARM standard).
pub const PAGE_SIZE: usize = 4096;

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
pub fn alloc_page() -> Option<usize> {
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

/// Free a physical page back to the allocator.
///
/// # Safety
///
/// The caller must ensure `addr` was previously returned by `alloc_page`.
pub unsafe fn free_page(addr: usize) {
    unsafe {
        let page_num = (addr - FIRST_PAGE) / PAGE_SIZE;
        let word = page_num / 32;
        let bit = page_num % 32;
        let bitmap = &mut *addr_of_mut!(PAGE_BITMAP);
        bitmap[word] &= !(1 << bit);
        FREE_PAGES += 1;
    }
}

/// Return the number of free pages.
pub fn free_count() -> usize {
    unsafe { FREE_PAGES }
}

/// Return free memory in bytes.
pub fn free_bytes() -> usize {
    free_count() * PAGE_SIZE
}
