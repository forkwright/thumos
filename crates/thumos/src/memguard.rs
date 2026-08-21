//! User-pointer memory guards shared across syscall entry points.
//!
//! Two guards live here, and the difference between them is the whole point of
//! the module. [`validate_user_buffer`] answers a numeric question: does this
//! range lie inside allocatable DRAM. [`validate_user_range`] answers the
//! security question: may *this caller* touch these pages in *this direction*,
//! according to its own page tables. Syscall entry points want the second one;
//! the first survives as its cheap first gate and for the one caller that has
//! no caller VAS to check against (ELF segment placement, where the target is
//! identity-mapped before any per-process table exists).
//!
//! This logic lives here, in an always-compiled module (not the
//! hardware-coupled `syscall` module, which is excluded from host test builds),
//! so that pointer-taking subsystems (`pipe`, `fd`, `socket`, `time`, ...) can
//! call it and — crucially — so the guards have runnable host unit tests.

use crate::board;

/// Validate that a user-supplied numeric buffer range `[ptr, ptr+len)` lies
/// inside the broad DRAM window and avoids statically reserved kernel memory.
///
/// This is a bounds check, not a security boundary: at PL1 the kernel
/// identity-maps DRAM, so another process's pages, an allocator arena, and a
/// `PROT_NONE` page are all numerically ordinary and all pass. Syscall paths
/// must use [`validate_user_range`], which adds the caller-VAS and permission
/// gate on top of this one.
///
/// # Memory layout (MT6739)
///
/// - `0x0000_0000 - 0x3FFF_FFFF`: device MMIO (boot ROM, peripherals, modem)
/// - `0x4000_0000 - 0x4000_7FFF`: DRAM below kernel load (reserved)
/// - `0x4000_8000 - 0x400F_FFFF`: kernel image + reserved (`KERNEL_LOAD..KERNEL_END`)
/// - `0x4010_0000 - 0x7FFF_FFFF`: broad allocatable DRAM window
/// - `0x8000_0000 - 0xFFFF_FFFF`: unmapped
///
/// Returns `true` if the entire numeric buffer falls within that broad window.
/// It does not prove caller mapping or permissions. Returns `false` for null,
/// overflow, kernel-reserved, device, or out-of-DRAM addresses.
pub(crate) fn validate_user_buffer(ptr: usize, len: usize) -> bool {
    // Null pointer
    if ptr == 0 {
        return false;
    }
    // Zero-length buffer is vacuously valid (no memory accessed)
    if len == 0 {
        return true;
    }
    // Overflow check: ptr + len must not wrap
    let Some(end) = ptr.checked_add(len) else {
        return false;
    };
    // Entire range must be within broad allocatable DRAM: [KERNEL_END, RAM_END).
    // This is not caller-VAS/permission validation (#871).
    // WHY: KERNEL_END is the first byte after kernel-reserved memory;
    // RAM_END is one past the last byte of physical DRAM.
    ptr >= board::KERNEL_END && end <= board::RAM_END
}

/// True if `addr` is a page-aligned address inside the user-allocatable DRAM
/// window `[KERNEL_END, RAM_END)` — the exact range `page::alloc_page` hands
/// out. Used to reject a forged `FreePage` argument (null, a kernel/image
/// address, device MMIO, or a misaligned value) before it reaches the physical
/// page allocator, where an out-of-range address would corrupt the bitmap.
pub(crate) fn is_freeable_user_page(addr: usize) -> bool {
    addr.is_multiple_of(crate::page::PAGE_SIZE)
        && (board::KERNEL_END..board::RAM_END).contains(&addr)
}

/// Direction of a user-buffer access, from the kernel's point of view.
///
/// `Read` means the kernel reads FROM the buffer; `Write` means it writes INTO
/// it. The distinction is load-bearing rather than descriptive: a read-only
/// user mapping is a legitimate source and an illegitimate destination, and a
/// guard that ignores direction accepts both.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Access {
    /// Kernel reads from the user buffer.
    Read,
    /// Kernel writes into the user buffer.
    Write,
}

/// ARMv7-A short-descriptor access-permission field of a small-page L2
/// descriptor: `AP[1:0]` occupies bits 5:4.
const AP_MASK: u32 = 0b11 << 4;

/// `APX` (bit 9) downgrades the whole descriptor to read-only regardless of AP.
const APX_BIT: u32 = 1 << 9;

/// True when a small-page L2 descriptor grants the calling PL0 process the
/// requested access.
///
/// WHY ownership and permission are both required: `mmu::l2_entry_is_user`
/// answers *ownership* via the software `NG` tag, not reachability. A
/// `PROT_NONE` user page is user-owned and carries `AP_KERNEL_ONLY`, so it is
/// indistinguishable from a kernel fill by AP alone and indistinguishable from
/// a readable user page by ownership alone. Asking only one question admits the
/// other's failures.
///
/// PL0 column of the ARMv7-A permission table:
///
/// | APX | AP     | PL0 access        |
/// |-----|--------|-------------------|
/// | 0   | `0b00` | none              |
/// | 0   | `0b01` | none              |
/// | 0   | `0b10` | read-only         |
/// | 0   | `0b11` | read/write        |
/// | 1   | any    | read-only at most |
pub(crate) fn pl0_grants(entry: u32, access: Access) -> bool {
    if !crate::mmu::l2_entry_is_user(entry) {
        return false;
    }
    let ap = entry & AP_MASK;
    match access {
        Access::Read => {
            ap == crate::mmu::page_flags::AP_READ_ONLY || ap == crate::mmu::page_flags::AP_FULL
        }
        // WHY APX is consulted only here: APX=1 forces read-only whatever AP
        // says, so `AP_FULL` on its own does not establish writability.
        Access::Write => ap == crate::mmu::page_flags::AP_FULL && entry & APX_BIT == 0,
    }
}

/// Walk `[ptr, ptr+len)` page by page, requiring every page to grant `access`.
///
/// `read_desc` returns the small-page L2 descriptor for a page-aligned virtual
/// address, or `None` when the address is not backed by a page table at all.
///
/// WHY a closure instead of reading the page table directly: it leaves the
/// traversal — the boundary arithmetic and the hole detection, which is where
/// the interesting mistakes live — a pure function with host tests, and reduces
/// the unsafe part to a one-line adapter.
fn range_grants(
    ptr: usize,
    len: usize,
    access: Access,
    mut read_desc: impl FnMut(usize) -> Option<u32>,
) -> bool {
    // A zero-length buffer touches no page, so no mapping is required.
    if len == 0 {
        return true;
    }
    let Some(end) = ptr.checked_add(len) else {
        return false;
    };
    // WHY the walk starts at the containing page rather than at `ptr`: a range
    // beginning mid-page still dereferences that whole page's mapping, and one
    // ending mid-page still dereferences its final page. Rounding either end
    // inward would skip a page the kernel is about to touch.
    let mut page = ptr - (ptr % crate::page::PAGE_SIZE);
    while page < end {
        let Some(entry) = read_desc(page) else {
            return false;
        };
        if !pl0_grants(entry, access) {
            return false;
        }
        let Some(next) = page.checked_add(crate::page::PAGE_SIZE) else {
            return false;
        };
        page = next;
    }
    true
}

/// Validate that `[ptr, ptr+len)` is a legitimate user buffer for `access`.
///
/// Two independent gates, both required:
///
/// 1. The numeric gate (`validate_user_buffer`): the range is non-null, does
///    not wrap, and lies inside the allocatable DRAM window.
/// 2. The mapping gate: every page in the range is mapped by the *calling*
///    process with PL0 permission in this direction.
///
/// The second gate is what makes this a security boundary rather than a bounds
/// check. It rejects holes, `PROT_NONE`, read-only destinations, kernel and
/// allocator identity mappings, and pages belonging to another process — none
/// of which the numeric gate can see, because at PL1 the kernel identity-maps
/// DRAM and every one of those addresses is numerically ordinary.
///
/// WHY the mapping gate is conditional on a user address space: it asks what
/// the caller's page tables say, and that question only has an answer while a
/// user process is current. `process::current_user_page_table` decides that
/// positively — a non-zero PID holding a table of its own, not PID 0's kernel
/// global L1 — so a PL0 caller, which by construction has such a table, cannot
/// reach the numeric-only path. A host test build has no MMU and no user
/// address space, so there the numeric gate is the whole check; the mapping
/// gate's behaviour is covered by tests that drive `range_grants` over a
/// descriptor reader directly.
pub(crate) fn validate_user_range(ptr: usize, len: usize, access: Access) -> bool {
    if !validate_user_buffer(ptr, len) {
        return false;
    }
    let Some(l1) = crate::process::current_user_page_table() else {
        return true;
    };
    range_grants(ptr, len, access, |va| {
        // SAFETY: `l1` is a live user L1 taken from the process table, and
        // `range_grants` only ever passes page-aligned addresses.
        unsafe { crate::mmu::read_l2_entry(l1, va) }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_user_pointer_passes() {
        assert!(validate_user_buffer(0x5000_0000, 4096));
    }

    #[test]
    fn entire_user_range_passes() {
        let start = board::KERNEL_END;
        let len = board::RAM_END - board::KERNEL_END;
        assert!(validate_user_buffer(start, len));
    }

    #[test]
    fn zero_length_is_vacuously_valid() {
        assert!(validate_user_buffer(0x5000_0000, 0));
    }

    #[test]
    fn null_pointer_fails() {
        assert!(!validate_user_buffer(0, 100));
        assert!(!validate_user_buffer(0, 0));
    }

    #[test]
    fn kernel_space_fails() {
        assert!(!validate_user_buffer(board::KERNEL_LOAD, 4096));
        assert!(!validate_user_buffer(board::KERNEL_LOAD + 0x1000, 256));
    }

    #[test]
    fn device_mmio_fails() {
        assert!(!validate_user_buffer(0x1100_2000, 16));
        assert!(!validate_user_buffer(0x0C00_0000, 4));
    }

    #[test]
    fn above_ram_fails() {
        assert!(!validate_user_buffer(board::RAM_END, 1));
        assert!(!validate_user_buffer(0xC000_0000, 4096));
    }

    #[test]
    fn overflow_fails() {
        assert!(!validate_user_buffer(usize::MAX, 1));
        assert!(!validate_user_buffer(usize::MAX - 10, 100));
    }

    #[test]
    fn buffer_spanning_into_kernel_fails() {
        // Starts one byte below KERNEL_END, so the range dips into kernel space.
        assert!(!validate_user_buffer(board::KERNEL_END - 1, 2));
    }

    #[test]
    fn buffer_spanning_past_ram_end_fails() {
        assert!(!validate_user_buffer(board::RAM_END - 10, 20));
    }

    #[test]
    fn boundary_exact_edges() {
        // Exactly at KERNEL_END is valid; one byte below is not.
        assert!(validate_user_buffer(board::KERNEL_END, 1));
        assert!(!validate_user_buffer(board::KERNEL_END - 1, 1));
        // Last valid byte of DRAM.
        assert!(validate_user_buffer(board::RAM_END - 1, 1));
    }

    #[test]
    fn freeable_page_accepts_aligned_user_pages() {
        assert!(is_freeable_user_page(board::KERNEL_END));
        assert!(is_freeable_user_page(
            board::RAM_END - crate::page::PAGE_SIZE
        ));
    }

    #[test]
    fn freeable_page_rejects_forged_addresses() {
        assert!(!is_freeable_user_page(0)); // null
        assert!(!is_freeable_user_page(board::KERNEL_LOAD)); // kernel image
        assert!(!is_freeable_user_page(0x1100_2000)); // UART MMIO
        assert!(!is_freeable_user_page(board::RAM_END)); // above RAM
        assert!(!is_freeable_user_page(board::KERNEL_END + 1)); // misaligned
    }

    // --- Caller-VAS permission gate (#871) ---
    //
    // Descriptors are minted by `prot_to_l2_flags`, the sole producer of user
    // L2 entries, so these fixtures exercise the real encoding rather than a
    // hand-assembled approximation of it.

    use crate::mmu::{page_flags, prot, prot_to_l2_flags};

    const PAGE: usize = crate::page::PAGE_SIZE;
    const USER_BASE: usize = 0x5000_0000;

    fn rw_page() -> u32 {
        prot_to_l2_flags(prot::PROT_READ | prot::PROT_WRITE)
    }

    fn ro_page() -> u32 {
        prot_to_l2_flags(prot::PROT_READ)
    }

    fn none_page() -> u32 {
        prot_to_l2_flags(0)
    }

    #[test]
    fn pl0_grants_read_write_user_page_both_directions() {
        let e = rw_page();
        assert!(pl0_grants(e, Access::Read));
        assert!(pl0_grants(e, Access::Write));
    }

    #[test]
    fn pl0_grants_read_only_page_reads_but_never_writes() {
        // The direction split exists for exactly this descriptor: a legitimate
        // copyin source that must never be a copyout destination.
        let e = ro_page();
        assert!(pl0_grants(e, Access::Read));
        assert!(!pl0_grants(e, Access::Write));
    }

    #[test]
    fn pl0_denies_prot_none_user_page_in_both_directions() {
        // NEGATIVE FIXTURE: a PROT_NONE page is user-OWNED, so an
        // ownership-only test admits it. Its AP is byte-identical to a kernel
        // fill, so an AP-only test would have to reject every kernel page to
        // catch it. Only asking both questions rejects this one.
        let e = none_page();
        assert!(
            crate::mmu::l2_entry_is_user(e),
            "fixture must be user-owned"
        );
        assert!(!pl0_grants(e, Access::Read));
        assert!(!pl0_grants(e, Access::Write));
    }

    #[test]
    fn pl0_denies_kernel_fill_page() {
        let e = page_flags::SMALL_PAGE
            | page_flags::SHAREABLE
            | page_flags::NORMAL_WB_WA
            | page_flags::AP_KERNEL_ONLY;
        assert!(!pl0_grants(e, Access::Read));
        assert!(!pl0_grants(e, Access::Write));
    }

    #[test]
    fn pl0_denies_kernel_page_even_when_ap_is_permissive() {
        // NEGATIVE FIXTURE for the ownership half: a descriptor carrying
        // AP_FULL but no user tag is a kernel mapping, and permissive AP must
        // not be enough to reach it.
        let e = page_flags::SMALL_PAGE | page_flags::AP_FULL;
        assert!(!crate::mmu::l2_entry_is_user(e));
        assert!(!pl0_grants(e, Access::Read));
        assert!(!pl0_grants(e, Access::Write));
    }

    #[test]
    fn pl0_denies_write_when_apx_forces_read_only() {
        // NEGATIVE FIXTURE for the APX half: AP_FULL alone reads as writable,
        // but APX=1 downgrades the page to read-only in hardware. A check that
        // matched AP and ignored APX would hand back a writable verdict for a
        // page the MMU will fault on.
        let e = rw_page() | APX_BIT;
        assert!(pl0_grants(e, Access::Read));
        assert!(!pl0_grants(e, Access::Write));
    }

    #[test]
    fn pl0_denies_fault_and_large_page_descriptors() {
        assert!(!pl0_grants(0, Access::Read)); // fault entry (0b00)
        // Large-page descriptor (0b01) with an otherwise permissive body.
        assert!(!pl0_grants(
            0b01 | page_flags::NG | page_flags::AP_FULL,
            Access::Read
        ));
    }

    #[test]
    fn range_grants_accepts_a_fully_mapped_span() {
        assert!(range_grants(USER_BASE, PAGE * 2, Access::Write, |_| Some(
            rw_page()
        )));
    }

    #[test]
    fn range_grants_rejects_a_hole_in_the_middle() {
        // NEGATIVE FIXTURE: the first page is mapped, so a check that examined
        // only the starting address would accept the whole range.
        let hole = USER_BASE + PAGE;
        assert!(!range_grants(USER_BASE, PAGE * 3, Access::Write, |va| {
            if va == hole { None } else { Some(rw_page()) }
        }));
    }

    #[test]
    fn range_grants_rejects_a_read_only_page_late_in_a_write_span() {
        let ro = USER_BASE + PAGE * 2;
        let desc = |va: usize| Some(if va == ro { ro_page() } else { rw_page() });
        assert!(range_grants(USER_BASE, PAGE * 3, Access::Read, desc));
        assert!(!range_grants(USER_BASE, PAGE * 3, Access::Write, desc));
    }

    #[test]
    fn range_grants_consults_the_page_containing_an_unaligned_start() {
        // A one-byte read at page+1 still dereferences that page, so its
        // mapping must be consulted. Walking from `ptr` rounded UP would skip
        // it entirely and accept an unmapped page.
        let mut visited = [0usize; 4];
        let mut n = 0;
        let ok = range_grants(USER_BASE + 1, 1, Access::Read, |va| {
            visited[n] = va;
            n += 1;
            Some(rw_page())
        });
        assert!(ok);
        assert_eq!(n, 1);
        assert_eq!(visited[0], USER_BASE);
    }

    #[test]
    fn range_grants_consults_the_final_page_of_a_span_ending_mid_page() {
        // One byte past a page boundary must pull in the next page. An
        // exclusive-end walk that stopped at the boundary would miss it.
        let mut visited = [0usize; 4];
        let mut n = 0;
        let ok = range_grants(USER_BASE + PAGE - 1, 2, Access::Read, |va| {
            visited[n] = va;
            n += 1;
            Some(rw_page())
        });
        assert!(ok);
        assert_eq!(n, 2, "a two-byte span across a boundary spans two pages");
        assert_eq!(visited[0], USER_BASE);
        assert_eq!(visited[1], USER_BASE + PAGE);
    }

    #[test]
    fn range_grants_zero_length_consults_nothing() {
        let mut consulted = false;
        let ok = range_grants(USER_BASE, 0, Access::Write, |_| {
            consulted = true;
            None
        });
        assert!(ok);
        assert!(!consulted, "a zero-length buffer touches no page");
    }

    #[test]
    fn range_grants_rejects_a_wrapping_range() {
        assert!(!range_grants(usize::MAX, 2, Access::Read, |_| Some(
            rw_page()
        )));
    }

    #[test]
    fn validate_user_range_keeps_the_numeric_gate() {
        // The mapping gate is additive: everything the numeric gate rejected
        // must still be rejected, whether or not an address space is active.
        assert!(!validate_user_range(0, 4, Access::Read));
        assert!(!validate_user_range(board::KERNEL_LOAD, 4, Access::Read));
        assert!(!validate_user_range(0x1100_2000, 4, Access::Write));
        assert!(!validate_user_range(usize::MAX, 1, Access::Read));
        assert!(!validate_user_range(board::RAM_END - 10, 20, Access::Write));
    }
}
