//! Slab allocator.
//!
//! Replaces the bump allocator with a proper alloc/free slab system.
//! Objects are carved from physical pages grouped by size class. Freed objects
//! return to their class free list and are immediately reusable, eliminating
//! fragmentation caused by the bump allocator.
//!
//! # Size classes
//!
//! 32, 64, 128, 256, 512, 1024, 2048 bytes. Requests larger than 2048 bytes
//! fall back to the page allocator directly (whole pages).
//!
//! # Thread safety
//!
//! A single spinlock guards the allocator, with IRQ delivery masked for the
//! duration of each critical section (mask, then acquire; release, then
//! unmask -- see `irq::IrqSpinlock`). On the single-core MT6739 boot CPU the
//! only concurrent caller is an IRQ handler; the atomic flag alone does not
//! stop that reentrancy -- without masking, an IRQ firing while interrupted
//! code holds the lock and then allocating would self-deadlock (#322). IRQ
//! masking is what actually makes the section safe against that case.
//!
//! # Invariants
//!
//! - The page allocator must be initialized before `SlabAllocator::init()`.
//! - `init()` must be called exactly once before any `alloc`/`dealloc`.

use core::alloc::{GlobalAlloc, Layout};
use core::ptr;

use crate::irq;
use crate::page;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Size classes, in bytes. Must be powers-of-two and strictly increasing.
const SLAB_SIZES: [usize; 7] = [32, 64, 128, 256, 512, 1024, 2048];

/// Maximum slab pages per size class. 32 pages × 7 classes = 224 pages total
/// worst case, within `kconfig::HEAP_PAGES` (256 pages / 1 MB) even if every
/// class maxes out simultaneously (pages are claimed lazily, not
/// pre-allocated, so this is a ceiling, not a reservation).
///
/// WHY 32: the smallest classes need concurrent-object headroom well past
/// "early boot" — e.g. the 128-byte class holds `32 * (PAGE_SIZE / 128) =
/// 1024` objects. A cap of 8 (256 objects for the 128-byte class) is
/// exhausted by realistic workloads (many live pipe buffers / small
/// structs) well before physical RAM is under any pressure, which
/// surfaces as spurious allocation failure.
const MAX_SLABS: usize = 32;

// ---------------------------------------------------------------------------
// Intrusive free list node
// ---------------------------------------------------------------------------

/// Every free object is reinterpreted as a `FreeNode`. The object must be at
/// least `size_of::<*mut FreeNode>()` bytes; all our size classes satisfy this
/// on a 32-bit ARM target (minimum 4 bytes, smallest class is 32 bytes).
struct FreeNode {
    next: *mut FreeNode,
}

// ---------------------------------------------------------------------------
// Per-class slab metadata
// ---------------------------------------------------------------------------

struct SlabClass {
    /// Head of the intrusive free list for this class.
    free_list: *mut FreeNode,
    /// Physical addresses of pages currently serving this class.
    slab_pages: [*mut u8; MAX_SLABS],
    /// Number of slab pages allocated for this class.
    slab_count: usize,
    /// Object size for this class.
    obj_size: usize,
    /// Lifetime allocation count (for leak detection).
    alloc_count: u64,
    /// Lifetime free count (for leak detection).
    free_count: u64,
}

impl SlabClass {
    const fn zeroed() -> Self {
        SlabClass {
            free_list: ptr::null_mut(),
            slab_pages: [ptr::null_mut(); MAX_SLABS],
            slab_count: 0,
            obj_size: 0,
            alloc_count: 0,
            free_count: 0,
        }
    }

    /// Refill the free list by claiming one page from the page allocator and
    /// carving it into `obj_size`-sized objects.
    ///
    /// Returns `false` if the page allocator is exhausted or the slab table is
    /// full.
    ///
    /// # Safety
    ///
    /// Caller must hold the allocator spinlock. `self.obj_size` must be
    /// non-zero and a power of two no larger than `page::PAGE_SIZE`.
    unsafe fn refill(&mut self, page_fn: unsafe fn() -> Option<usize>) -> bool {
        if self.slab_count >= MAX_SLABS {
            return false;
        }

        // SAFETY: page allocator is initialized before the slab allocator.
        let phys = unsafe { page_fn() };
        let Some(page_addr) = phys else {
            return false;
        };

        let page_ptr = page_addr as *mut u8;

        // Record so we can return the page on shutdown / leak check.
        self.slab_pages[self.slab_count] = page_ptr;
        self.slab_count += 1;

        // Carve the page into obj_size chunks and link into the free list.
        let n = page::PAGE_SIZE / self.obj_size;
        for i in (0..n).rev() {
            // SAFETY: i * obj_size < PAGE_SIZE, so offset is within the page.
            //
            // INVARIANT: `page_ptr` is the physical page address the page
            // allocator returned, which is always `PAGE_SIZE` (4096-byte)
            // aligned (`page::alloc_page`'s `FIRST_PAGE + page_num *
            // PAGE_SIZE`, with `FIRST_PAGE` the SoC's fixed, page-aligned
            // DRAM base). `self.obj_size` is one of `SLAB_SIZES` (32..=2048),
            // always a multiple of 4, so `page_ptr + i * self.obj_size` is
            // always a multiple of 4 -- `FreeNode`'s alignment requirement.
            // `.cast()` keeps that a type-checked reinterpretation rather
            // than a raw `as`.
            //
            // WHY the allow: `cast_ptr_alignment` fires on `.cast()` the same
            // as on `as` -- it cannot see the page-alignment + size-class
            // multiple-of-4 proof in the INVARIANT above, which is exactly
            // what discharges the alignment obligation the lint exists to
            // demand.
            #[expect(
                clippy::cast_ptr_alignment,
                reason = "cast_ptr_alignment fires on .cast() the same as on as -- it cannot see the page-alignment + size-class multiple-of-4 proof in the INVARIANT above, which is exactly what discharges the alignment obligation the lint exists to demand"
            )]
            let node_ptr = unsafe { page_ptr.add(i * self.obj_size).cast::<FreeNode>() };
            unsafe {
                (*node_ptr).next = self.free_list;
            }
            self.free_list = node_ptr;
        }

        true
    }

    /// Pop one object from the free list, refilling from the page allocator if
    /// empty.
    ///
    /// Returns null on OOM. Never panics.
    ///
    /// # Safety
    ///
    /// Caller must hold the allocator spinlock. `page_fn` must return pages
    /// from an initialized page allocator.
    unsafe fn alloc_obj(&mut self, page_fn: unsafe fn() -> Option<usize>) -> *mut u8 {
        if self.free_list.is_null() {
            // SAFETY: delegated to refill's contract.
            if !unsafe { self.refill(page_fn) } {
                return ptr::null_mut();
            }
        }

        // SAFETY: free_list is non-null (just refilled if needed); node was
        // placed there by refill() or dealloc_obj(), which both wrote a valid
        // FreeNode header into a page-backed object.
        let node = self.free_list;
        self.free_list = unsafe { (*node).next };
        self.alloc_count += 1;
        node.cast::<u8>()
    }

    /// Push `ptr` onto the free list.
    ///
    /// # Safety
    ///
    /// `ptr` must have been returned by `alloc_obj` on this class, must not
    /// already be on the free list (no double-free), and must be valid for a
    /// write of `size_of::<FreeNode>()` bytes.
    unsafe fn dealloc_obj(&mut self, ptr: *mut u8) {
        // SAFETY: ptr is object-sized (>= 32 bytes) and properly aligned
        // from alloc_obj. Zero the full object before it re-enters the free
        // list so a secret that lived in this slot does not leak to
        // whichever caller alloc_obj hands it to next (#334); the free-list
        // link is written into the now-zeroed buffer immediately after.
        let obj_size = self.obj_size;
        for i in 0..obj_size {
            // SAFETY: ptr is valid for obj_size bytes per this function's
            // own contract; write_volatile defeats dead-store elimination.
            unsafe {
                core::ptr::write_volatile(ptr.add(i), 0);
            }
        }
        // INVARIANT: `ptr` was returned by `alloc_obj` on this class per this
        // function's own contract, so it traces back to the page-aligned,
        // obj_size-multiple offset `refill` establishes (see that
        // function's comment) -- `.cast()` keeps the reinterpretation
        // type-checked instead of re-deriving alignment by hand.
        //
        // WHY the allow: see `refill`'s identical `cast_ptr_alignment` note
        // -- the lint fires on `.cast()` too and cannot see the INVARIANT
        // above that discharges it.
        #[expect(
            clippy::cast_ptr_alignment,
            reason = "see refill's identical cast_ptr_alignment note -- the lint fires on .cast() too and cannot see the INVARIANT above that discharges it"
        )]
        let node = ptr.cast::<FreeNode>();
        unsafe {
            (*node).next = self.free_list;
        }
        self.free_list = node;
        self.free_count += 1;
    }
}

// ---------------------------------------------------------------------------
// Allocator
// ---------------------------------------------------------------------------

pub(crate) struct SlabAllocator {
    classes: [SlabClass; 7],
    /// Counts of large (>2048 byte) allocations backed by whole pages.
    large_alloc_count: u64,
    large_free_count: u64,
    /// Set to true after `init()` is called.
    initialized: bool,
}

impl SlabAllocator {
    pub(crate) const fn new() -> Self {
        SlabAllocator {
            classes: [
                SlabClass::zeroed(),
                SlabClass::zeroed(),
                SlabClass::zeroed(),
                SlabClass::zeroed(),
                SlabClass::zeroed(),
                SlabClass::zeroed(),
                SlabClass::zeroed(),
            ],
            large_alloc_count: 0,
            large_free_count: 0,
            initialized: false,
        }
    }

    /// Wire up size classes. Must be called once before any allocation.
    pub(crate) fn init(&mut self) {
        for (cls, &sz) in self.classes.iter_mut().zip(SLAB_SIZES.iter()) {
            cls.obj_size = sz;
        }
        self.initialized = true;
    }

    /// Return the index of the smallest size class that fits `size`, or `None`
    /// if `size > 2048`.
    fn class_for(size: usize) -> Option<usize> {
        SLAB_SIZES.iter().position(|&s| size <= s)
    }

    /// Allocate `layout.size()` bytes, returning null on failure.
    ///
    /// # Safety
    ///
    /// Caller must hold the spinlock.
    pub(crate) unsafe fn alloc_inner(
        &mut self,
        layout: Layout,
        page_fn: unsafe fn() -> Option<usize>,
        large_alloc_fn: unsafe fn() -> Option<usize>,
    ) -> *mut u8 {
        if !self.initialized {
            return ptr::null_mut();
        }

        let size = layout.size().max(layout.align());

        if let Some(idx) = Self::class_for(size) {
            // SAFETY: delegated to alloc_obj's contract; page_fn is valid.
            unsafe { self.classes[idx].alloc_obj(page_fn) }
        } else {
            // Large allocation: back it with whole pages from the page
            // allocator.
            let pages = size.div_ceil(page::PAGE_SIZE);
            let addr = if pages == 1 {
                // SAFETY: large_alloc_fn returns a page from an initialized
                // page allocator (injected so the single-page path stays
                // host-fakeable).
                unsafe { large_alloc_fn() }
            } else {
                // WHY (#475): multi-page requests need a contiguous run;
                // the injected single-page fn cannot express that, so go
                // direct to the page allocator's contiguous path.
                page::alloc_contiguous(pages)
            };
            match addr {
                Some(a) => {
                    self.large_alloc_count += 1;
                    a as *mut u8
                }
                None => ptr::null_mut(),
            }
        }
    }

    /// Deallocate the object at `ptr` with the given layout.
    ///
    /// # Safety
    ///
    /// Caller must hold the spinlock. `ptr` must have been returned by
    /// `alloc_inner` and must not have been freed since.
    pub(crate) unsafe fn dealloc_inner(
        &mut self,
        ptr: *mut u8,
        layout: Layout,
        large_free_fn: unsafe fn(usize),
    ) {
        if !self.initialized || ptr.is_null() {
            return;
        }

        let size = layout.size().max(layout.align());

        if let Some(idx) = Self::class_for(size) {
            // SAFETY: delegated to dealloc_obj's contract.
            unsafe { self.classes[idx].dealloc_obj(ptr) };
        } else {
            // ptr was returned by alloc_inner's large path, so it is a
            // page-aligned base of `pages` whole pages.
            let pages = size.div_ceil(page::PAGE_SIZE);
            if pages == 1 {
                // SAFETY: single-page large alloc came from large_alloc_fn.
                unsafe { large_free_fn(ptr as usize) };
            } else {
                // WHY (#475): free the contiguous run alloc_contiguous
                // handed out. The bool return is a validated no-op on a bad
                // address (not an error to propagate).
                // SAFETY: ptr/pages name the run from alloc_contiguous.
                unsafe { page::free_contiguous(ptr as usize, pages) };
            }
            self.large_free_count += 1;
        }
    }

    /// Return `(total_allocs, total_frees)` across all size classes and large
    /// allocations. Equal counts indicate no leaks.
    pub(crate) fn stats(&self) -> (u64, u64) {
        let mut allocs = self.large_alloc_count;
        let mut frees = self.large_free_count;
        for cls in &self.classes {
            allocs += cls.alloc_count;
            frees += cls.free_count;
        }
        (allocs, frees)
    }
}

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------

/// WHY (#322): an `irq::IrqSpinlock`, not a plain atomic flag -- IRQ
/// delivery is masked for the whole critical section, which is what
/// actually prevents an allocating IRQ handler from self-deadlocking
/// against interrupted code that holds this lock.
static LOCK: irq::IrqSpinlock = irq::IrqSpinlock::new();

// SAFETY: SlabAllocator is only accessed under LOCK.
static mut SLAB: SlabAllocator = SlabAllocator::new();

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Initialize the slab allocator.
///
/// Wires up size-class metadata. No pages are pre-allocated; slabs are claimed
/// lazily on first alloc.
///
/// # Safety
///
/// Must be called exactly once, after the page allocator is initialized, and
/// before any heap allocation. Calling from multiple cores simultaneously is
/// undefined behavior.
pub unsafe fn init() {
    // SAFETY: called once from kinit, before any concurrent access.
    unsafe {
        let _g = LOCK.lock();
        (*ptr::addr_of_mut!(SLAB)).init();
    }
}

/// Return `(total_allocs, total_frees)` for all size classes and large allocs.
///
/// Equal values indicate no outstanding allocations (no leaks).
pub(crate) fn stats() -> (u64, u64) {
    // SAFETY: reading through the lock is safe; stats() only reads counters.
    let _g = LOCK.lock();
    // SAFETY: SLAB is only mutated under LOCK.
    unsafe { (*ptr::addr_of!(SLAB)).stats() }
}

// ---------------------------------------------------------------------------
// GlobalAlloc impl
// ---------------------------------------------------------------------------

/// The kernel's global slab allocator, exposed as `#[global_allocator]`.
pub(crate) struct KernelAllocator;

unsafe impl GlobalAlloc for KernelAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: SLAB is protected by LOCK; page::alloc_page is safe to call
        // after page allocator init.
        unsafe {
            let _g = LOCK.lock();
            (*ptr::addr_of_mut!(SLAB)).alloc_inner(
                layout,
                // SAFETY: wrapping the free function: alloc_page returns None on
                // exhaustion, never panics.
                page::alloc_page,
                page::alloc_page,
            )
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: SLAB is protected by LOCK; free_page is safe when ptr was
        // returned by alloc_page.
        unsafe {
            let _g = LOCK.lock();
            (*ptr::addr_of_mut!(SLAB)).dealloc_inner(ptr, layout, page::free_page);
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
//
// Tests run on the host (x86_64) via `cargo test --target x86_64-unknown-linux-gnu`.
// They cannot use the real page allocator (which requires physical memory) so
// they inject a bump-backed fake page allocator through the alloc_inner /
// dealloc_inner indirection.

#[cfg(test)]
mod tests {
    use core::alloc::Layout;

    use super::*;

    // -----------------------------------------------------------------------
    // Fake page allocator for tests
    // -----------------------------------------------------------------------

    // 64 pages of static backing storage, forced to page alignment.
    // WHY repr(align): a bare `static [u8; N]` has alignment 1, so the
    // compiler may place it at any byte address (it landed on 0x5a953669 on a
    // CI runner). The slab casts these bytes to `*mut FreeNode` and
    // dereferences them, so the pool must be page-aligned to match
    // production's page-aligned `alloc_page` — otherwise the debug
    // misaligned-pointer-dereference check aborts nondeterministically
    // (passed locally, SIGABRT on CI).
    const TEST_PAGES: usize = 64;
    #[repr(align(4096))]
    struct AlignedPool([u8; TEST_PAGES * page::PAGE_SIZE]);
    static mut TEST_POOL: AlignedPool = AlignedPool([0u8; TEST_PAGES * page::PAGE_SIZE]);
    static mut TEST_NEXT_PAGE: usize = 0;
    static mut TEST_FREED_PAGES: [usize; TEST_PAGES] = [0; TEST_PAGES];
    static mut TEST_FREED_COUNT: usize = 0;

    /// Fake `alloc_page`: returns the next page from `TEST_POOL`.
    unsafe fn fake_alloc_page() -> Option<usize> {
        // SAFETY: single-threaded test execution; TEST_NEXT_PAGE is private.
        unsafe {
            if TEST_NEXT_PAGE >= TEST_PAGES {
                return None;
            }
            let base = core::ptr::addr_of_mut!(TEST_POOL).cast::<u8>() as usize;
            let addr = base + TEST_NEXT_PAGE * page::PAGE_SIZE;
            TEST_NEXT_PAGE += 1;
            Some(addr)
        }
    }

    /// Fake `free_page`: records the freed address.
    unsafe fn fake_free_page(addr: usize) {
        // SAFETY: single-threaded test execution.
        unsafe {
            if TEST_FREED_COUNT < TEST_PAGES {
                TEST_FREED_PAGES[TEST_FREED_COUNT] = addr;
                TEST_FREED_COUNT += 1;
            }
        }
    }

    /// Create a fresh, initialized `SlabAllocator` for each test.
    fn make_allocator() -> SlabAllocator {
        let mut sa = SlabAllocator::new();
        sa.init();
        sa
    }

    // -----------------------------------------------------------------------
    // Tests
    // -----------------------------------------------------------------------

    #[test]
    fn allocates_and_frees_small_object() {
        // SAFETY: test is single-threaded; sa is local.
        unsafe {
            let mut sa = make_allocator();
            let layout = Layout::from_size_align(32, 4).unwrap();
            let ptr = sa.alloc_inner(layout, fake_alloc_page, fake_alloc_page);
            assert!(!ptr.is_null(), "allocation must succeed");
            // Write to the full object to catch any out-of-bounds issues.
            ptr.write_bytes(0xAB, 32);
            sa.dealloc_inner(ptr, layout, fake_free_page);
            let (allocs, frees) = sa.stats();
            assert_eq!(allocs, 1, "one allocation recorded");
            assert_eq!(frees, 1, "one free recorded");
        }
    }

    #[test]
    fn dealloc_zeroizes_object_before_relinking() {
        // Regression test for #334: dealloc_obj previously only wrote the
        // free-list pointer into the freed object, leaving the rest of a
        // former secret's bytes intact. The fix zeroes the full object
        // before relinking.
        //
        // WHY the assertion excludes the head: the free list is intrusive
        // (see `FreeNode`), so dealloc_obj writes the free-list link back
        // into the first `size_of::<FreeNode>()` bytes AFTER zeroing —
        // those bytes legitimately hold an allocator pointer whose byte
        // values are unconstrained (checking them for 0/non-0xAB would flake
        // on the pointer's own bytes). The bytes the fix is responsible for
        // scrubbing are the object body past that link, which formerly kept
        // the 0xAB secret and must now be entirely zero.
        // SAFETY: test is single-threaded; sa is local; ptr stays valid
        // (belongs to the fake test pool) for this immediate read-back,
        // before any subsequent allocation could reuse it.
        unsafe {
            let mut sa = make_allocator();
            let layout = Layout::from_size_align(32, 4).unwrap();
            let ptr = sa.alloc_inner(layout, fake_alloc_page, fake_alloc_page);
            assert!(!ptr.is_null());

            ptr.write_bytes(0xAB, 32);
            sa.dealloc_inner(ptr, layout, fake_free_page);

            let link_len = core::mem::size_of::<FreeNode>();
            let body = core::slice::from_raw_parts(ptr.add(link_len), 32 - link_len);
            assert!(
                body.iter().all(|&b| b == 0),
                "object body past the free-list link must be zeroed, not left holding 0xAB"
            );
        }
    }

    #[test]
    fn allocates_correct_size_class() {
        // A 33-byte request must be satisfied from the 64-byte class.
        unsafe {
            let mut sa = make_allocator();
            let layout = Layout::from_size_align(33, 1).unwrap();
            let ptr = sa.alloc_inner(layout, fake_alloc_page, fake_alloc_page);
            assert!(!ptr.is_null());
            // The allocation comes from class index 1 (64 bytes).
            assert_eq!(sa.classes[1].alloc_count, 1, "64-byte class used");
            assert_eq!(sa.classes[0].alloc_count, 0, "32-byte class not used");
            sa.dealloc_inner(ptr, layout, fake_free_page);
        }
    }

    #[test]
    fn reuses_freed_objects() {
        // Alloc, free, alloc again — must return the same pointer.
        unsafe {
            let mut sa = make_allocator();
            let layout = Layout::from_size_align(64, 8).unwrap();
            let first = sa.alloc_inner(layout, fake_alloc_page, fake_alloc_page);
            assert!(!first.is_null());
            sa.dealloc_inner(first, layout, fake_free_page);
            let second = sa.alloc_inner(layout, fake_alloc_page, fake_alloc_page);
            assert_eq!(
                first, second,
                "second alloc must reuse the just-freed object"
            );
            sa.dealloc_inner(second, layout, fake_free_page);
        }
    }

    #[test]
    fn stress_test_no_leaks() {
        // Alloc + free 1000 objects; alloc_count must equal free_count.
        unsafe {
            const N: usize = 1000;
            let mut sa = make_allocator();
            let layout = Layout::from_size_align(128, 8).unwrap();
            let mut ptrs = [ptr::null_mut::<u8>(); N];
            for p in &mut ptrs {
                *p = sa.alloc_inner(layout, fake_alloc_page, fake_alloc_page);
                assert!(!p.is_null());
            }
            for &p in &ptrs {
                sa.dealloc_inner(p, layout, fake_free_page);
            }
            let (allocs, frees) = sa.stats();
            assert_eq!(allocs, N as u64, "all allocations recorded");
            assert_eq!(frees, N as u64, "all frees recorded");
        }
    }

    #[test]
    fn large_allocation_uses_page_allocator() {
        // A 4096-byte request (>2048) must fall back to the page allocator.
        unsafe {
            let mut sa = make_allocator();
            let layout = Layout::from_size_align(4096, 4096).unwrap();
            let ptr = sa.alloc_inner(layout, fake_alloc_page, fake_alloc_page);
            assert!(!ptr.is_null(), "large alloc must succeed");
            assert_eq!(sa.large_alloc_count, 1, "large_alloc_count incremented");
            // Verify no slab class was used.
            for cls in &sa.classes {
                assert_eq!(cls.alloc_count, 0);
            }
            sa.dealloc_inner(ptr, layout, fake_free_page);
            assert_eq!(sa.large_free_count, 1, "large_free_count incremented");
        }
    }

    // WHY a second, scarce fake page_fn: the shared fake_alloc_page pool holds
    // TEST_PAGES(64) pages, well above MAX_SLABS(32), so a single size class
    // always trips MAX_SLABS before the page pool empties — a distinct 3-page
    // source is needed to isolate refill's page_fn()==None branch.
    static mut TEST_SCARCE_NEXT_PAGE: usize = 0;
    const TEST_SCARCE_PAGES: usize = 3;

    unsafe fn fake_alloc_page_scarce() -> Option<usize> {
        // SAFETY: single-threaded test execution; TEST_SCARCE_NEXT_PAGE is private.
        unsafe {
            if TEST_SCARCE_NEXT_PAGE >= TEST_SCARCE_PAGES {
                return None;
            }
            let base = core::ptr::addr_of_mut!(TEST_POOL).cast::<u8>() as usize;
            let addr = base + TEST_SCARCE_NEXT_PAGE * page::PAGE_SIZE;
            TEST_SCARCE_NEXT_PAGE += 1;
            Some(addr)
        }
    }

    #[test]
    fn slab_exhaustion_returns_null_after_max_slabs() {
        // SAFETY: test is single-threaded; sa is local.
        unsafe {
            let mut sa = make_allocator();
            let layout = Layout::from_size_align(32, 4).unwrap();
            // WHY the 32B class: PAGE_SIZE/32 objects per slab page, so
            // MAX_SLABS pages of capacity stay under TEST_PAGES — the null
            // below is the MAX_SLABS guard in refill(), not page exhaustion.
            let objs_per_slab = page::PAGE_SIZE / 32;
            let total_capacity = objs_per_slab * MAX_SLABS;
            for _ in 0..total_capacity {
                let ptr = sa.alloc_inner(layout, fake_alloc_page, fake_alloc_page);
                assert!(
                    !ptr.is_null(),
                    "allocation within MAX_SLABS capacity must succeed"
                );
            }
            let ptr = sa.alloc_inner(layout, fake_alloc_page, fake_alloc_page);
            assert!(
                ptr.is_null(),
                "allocation beyond MAX_SLABS must return null, not panic"
            );
        }
    }

    #[test]
    fn page_allocator_exhaustion_returns_null() {
        // SAFETY: single-threaded; sa is local; the scarce page_fn holds only
        // TEST_SCARCE_PAGES(3) pages, far below MAX_SLABS, isolating the
        // page_fn()==None branch from the MAX_SLABS cap.
        unsafe {
            let mut sa = make_allocator();
            let layout = Layout::from_size_align(32, 4).unwrap();
            let objs_per_slab = page::PAGE_SIZE / 32;
            for _ in 0..(objs_per_slab * TEST_SCARCE_PAGES) {
                let ptr = sa.alloc_inner(layout, fake_alloc_page_scarce, fake_alloc_page_scarce);
                assert!(
                    !ptr.is_null(),
                    "allocation within the scarce page budget must succeed"
                );
            }
            let ptr = sa.alloc_inner(layout, fake_alloc_page_scarce, fake_alloc_page_scarce);
            assert!(
                ptr.is_null(),
                "allocation once the page allocator is exhausted must return null, not panic"
            );
        }
    }

    #[test]
    fn oversized_allocation_rejected() {
        // SAFETY: test is single-threaded; sa is local.
        unsafe {
            let mut sa = make_allocator();
            // WHY 4097: needs 2 pages; multi-page large allocs are unsupported
            // and must be rejected before the page allocator is touched.
            let layout = Layout::from_size_align(4097, 1).unwrap();
            let ptr = sa.alloc_inner(layout, fake_alloc_page, fake_alloc_page);
            assert!(
                ptr.is_null(),
                "a >4096-byte request must be rejected, not silently truncated"
            );
            assert_eq!(
                sa.large_alloc_count, 0,
                "a rejected multi-page request must not be counted as a successful large alloc"
            );
        }
    }

    #[test]
    fn uninitialized_allocator_returns_null() {
        // SAFETY: single-threaded; sa is local; init() deliberately not called.
        unsafe {
            let mut sa = SlabAllocator::new();
            let layout = Layout::from_size_align(32, 4).unwrap();
            let ptr = sa.alloc_inner(layout, fake_alloc_page, fake_alloc_page);
            assert!(
                ptr.is_null(),
                "alloc on an uninitialized allocator must return null, not panic"
            );
        }
    }

    #[test]
    fn uninitialized_dealloc_is_noop() {
        // SAFETY: single-threaded; sa is local; init() deliberately not called.
        // WHY the bogus non-null ptr: if the !initialized guard were removed,
        // dealloc_obj would dereference it — the guard must bail out first.
        unsafe {
            let mut sa = SlabAllocator::new();
            let layout = Layout::from_size_align(32, 4).unwrap();
            let fake_ptr = 0x1000 as *mut u8;
            sa.dealloc_inner(fake_ptr, layout, fake_free_page);
            assert_eq!(
                sa.stats(),
                (0, 0),
                "dealloc on an uninitialized allocator must be a pure no-op"
            );
        }
    }

    #[test]
    fn null_ptr_dealloc_is_noop() {
        // SAFETY: test is single-threaded; sa is local.
        unsafe {
            let mut sa = make_allocator();
            let layout = Layout::from_size_align(32, 4).unwrap();
            sa.dealloc_inner(ptr::null_mut(), layout, fake_free_page);
            let (_, frees) = sa.stats();
            assert_eq!(
                frees, 0,
                "dealloc(null) on an initialized allocator must be a no-op, not decrement/crash"
            );
        }
    }

    // -----------------------------------------------------------------------
    // #322: IRQ-safe locking
    // -----------------------------------------------------------------------

    #[test]
    fn global_lock_masks_irqs_for_the_critical_section() {
        // Regression test for #322: the spinlock alone does not stop
        // IRQ-context reentrancy -- an allocating IRQ handler that fires
        // while this lock is held self-deadlocks unless IRQ delivery is
        // masked for the critical section. Host-testable via the mock
        // IRQ-state seam in `irq` (the real CPSR I-bit is ARM-only).
        crate::irq::reset_mock();
        assert!(crate::irq::mock_enabled(), "starts unmasked");
        let guard = LOCK.lock();
        assert!(
            !crate::irq::mock_enabled(),
            "LOCK.lock() must mask IRQ delivery while held"
        );
        drop(guard);
        assert!(
            crate::irq::mock_enabled(),
            "dropping the guard must restore IRQ delivery"
        );
    }

    #[test]
    fn nested_irq_guard_does_not_unmask_while_global_lock_held() {
        // The property that prevents the #322 self-deadlock: a nested
        // critical section (e.g. an IRQ handler's own masking, or a second
        // lock taken while this one is held) must not unmask IRQ delivery
        // early and let a handler run before the OUTER critical section --
        // the slab lock -- has released.
        crate::irq::reset_mock();
        let outer = LOCK.lock();
        assert!(!crate::irq::mock_enabled());
        let inner = crate::irq::IrqGuard::new();
        assert!(!crate::irq::mock_enabled());
        drop(inner);
        assert!(
            !crate::irq::mock_enabled(),
            "inner drop must not unmask while the slab lock is still held"
        );
        drop(outer);
        assert!(
            crate::irq::mock_enabled(),
            "outer drop restores IRQ delivery"
        );
    }

    #[test]
    fn large_multi_page_alloc_writes_reads_and_round_trips() {
        // #475: a >4 KB (2-page) allocation must succeed via the contiguous
        // page path, be writable/readable across its whole span, and
        // round-trip. Back the page allocator with a REAL host-aligned buffer
        // so the returned addresses are dereferenceable (fabricated addresses
        // would SIGSEGV). The multi-page path goes direct to
        // page::alloc_contiguous, so the injected fakes are unused here.
        #[repr(align(4096))]
        struct Pool([u8; 64 * 4096]);
        static mut POOL: Pool = Pool([0; 64 * 4096]);
        // SAFETY: single-threaded test (nextest runs it in its own process);
        // POOL is a real, page-aligned, host-backed buffer.
        unsafe {
            let base = core::ptr::addr_of_mut!(POOL) as usize;
            page::init(base, base + 64 * page::PAGE_SIZE, base);
            let mut sa = make_allocator();

            let layout = Layout::from_size_align(6000, 8).unwrap(); // 2 pages
            let ptr = sa.alloc_inner(layout, fake_alloc_page, fake_alloc_page);
            assert!(!ptr.is_null(), "multi-page large alloc must succeed");
            assert_eq!(ptr as usize % page::PAGE_SIZE, 0, "must be page-aligned");

            // Writable + readable across the full 2-page span (proves the run
            // is real contiguous backing, not a single page).
            core::ptr::write_bytes(ptr, 0xAB, 6000);
            assert_eq!(*ptr, 0xAB, "first byte");
            assert_eq!(*ptr.add(5999), 0xAB, "last byte of the 2-page span");

            sa.dealloc_inner(ptr, layout, fake_free_page);
            // The run is returned to the pool: a second identical alloc works.
            let ptr2 = sa.alloc_inner(layout, fake_alloc_page, fake_alloc_page);
            assert!(!ptr2.is_null(), "pages must be reusable after free");
            sa.dealloc_inner(ptr2, layout, fake_free_page);
        }
    }
}
