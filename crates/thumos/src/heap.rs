//! Kernel heap — thin shim over the slab allocator.
//!
//! The slab allocator (`src/slab.rs`) is the kernel's `GlobalAlloc` backend.
//! This module keeps the original `init()` / `stats()` / `KernelAllocator`
//! surface so call sites in `kinit.rs` and `main.rs` need no changes.
//!
//! The old bump allocator has been removed. See `slab.rs` for implementation
//! details (REQ-06).

use crate::slab;

/// Initialize the kernel heap (slab allocator).
///
/// The page allocator must be initialized before calling this.
///
/// # Safety
///
/// Must be called exactly once during kernel init, before any heap allocation.
pub unsafe fn init() {
    // SAFETY: delegated — page allocator is up, called once from kinit.
    unsafe { slab::init() }
}

/// Re-export the slab allocator as `KernelAllocator` for `#[global_allocator]`.
pub use slab::KernelAllocator;

/// Return `(total_allocs, total_frees)` for leak detection.
///
/// Replaces the old `(used_bytes, total_bytes)` tuple; callers that only check
/// for leaks can compare the two values for equality.
pub fn stats() -> (u64, u64) {
    slab::stats()
}
