//! Kernel heap allocator.
//!
//! A simple bump allocator backed by physical pages FROM the page allocator.
//! Supports the Rust `GlobalAlloc` trait so kernel code can use `alloc::vec::Vec`,
//! `alloc::string::String`, etc.
//!
//! This is intentionally simple. A production kernel would use a slab allocator
//! (like Linux's SLUB) for better fragmentation behavior. The bump allocator
//! is sufficient for early boot and can be replaced later.

use crate::page;
use core::alloc::{GlobalAlloc, Layout};
use core::ptr;

/// Heap size: 1 MB (256 pages).
const HEAP_PAGES: usize = 256;

/// Heap state.
struct BumpAllocator {
    start: usize,
    end: usize,
    next: usize,
    initialized: bool,
}

static mut HEAP: BumpAllocator = BumpAllocator {
    start: 0,
    end: 0,
    next: 0,
    initialized: false,
};

/// Initialize the kernel heap.
///
/// Allocates `HEAP_PAGES` physical pages and sets up the bump allocator.
///
/// # Safety
///
/// Must be called once after the page allocator is initialized.
pub unsafe fn init() {
    unsafe {
        let heap = &mut *ptr::addr_of_mut!(HEAP);

        // Allocate contiguous pages for the heap
        // NOTE: this assumes alloc_page returns increasing addresses.
        // A real implementation would use a contiguous allocator.
        let first_page = page::alloc_page().unwrap_or_default();
        heap.start = first_page;

        for _ in 1..HEAP_PAGES {
            page::alloc_page().unwrap_or_default();
        }

        heap.end = heap.start + HEAP_PAGES * page::PAGE_SIZE;
        heap.next = heap.start;
        heap.initialized = true;
    }
}

/// Global allocator instance for `#[global_allocator]`.
pub struct KernelAllocator;

unsafe impl GlobalAlloc for KernelAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe {
            let heap = &mut *ptr::addr_of_mut!(HEAP);

            if !heap.initialized {
                return ptr::null_mut();
            }

            // Align up
            let align = layout.align();
            let aligned = (heap.next + align - 1) & !(align - 1);
            let new_next = aligned + layout.size();

            if new_next > heap.end {
                // Out of heap space
                return ptr::null_mut();
            }

            heap.next = new_next;
            aligned as *mut u8
        }
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {
        // NOTE: bump allocator doesn't free individual allocations.
        // Memory is reclaimed only when the entire heap is reset.
        // This is acceptable for early boot. Replace with slab allocator
        // when fragmentation becomes a concern.
    }
}

/// Return heap usage statistics.
pub fn stats() -> (usize, usize) {
    unsafe {
        let heap = &*ptr::addr_of!(HEAP);
        let used = heap.next - heap.start;
        let total = heap.end - heap.start;
        (used, total)
    }
}
