//! ARMv7 MMU (Memory Management Unit) setup.
//!
//! Configures the ARM two-level page table for the MT6739:
//! - Level 1 (L1): 4096 entries, each covers 1 MB (section mapping)
//! - Level 2 (L2): 256 entries per table, each covers 4 KB (page mapping)
//!
//! For the initial kernel boot, we use section mapping (1 MB granularity)
//! which only needs the L1 table. This identity-maps RAM and device MMIO
//! so physical addresses equal virtual addresses.
//!
//! Register reference (ARM Architecture Reference Manual, B3.5):
//! - TTBR0 (CP15 c2): translation table base register
//! - TTBCR (CP15 c2,2): translation table base control
//! - DACR  (CP15 c3): domain access control
//! - SCTLR (CP15 c1): system control (bit 0 = MMU enable)

use crate::irq;

/// L1 page table: 4096 entries x 4 bytes = 16 KB.
/// Must be 16 KB aligned.
#[repr(C, align(16384))]
pub(crate) struct L1Table {
    entries: [u32; 4096],
}

/// Global L1 page table.
static mut L1: L1Table = L1Table { entries: [0; 4096] };

/// Section descriptor flags (1 MB mapping).
mod flags {
    /// This is a section descriptor (bits [1:0] = 0b10).
    pub(crate) const SECTION: u32 = 0b10;
    /// Access permission: PL1 (kernel) read/write, PL0 (user) NO access
    /// (AP[2:0] = 0b001: APX = 0 at bit 15 (unset), AP[1:0] = 0b01 at bits
    /// [11:10]). WHY (#323): kernel RAM and device MMIO sections must never
    /// grant PL0 access -- the prior AP_FULL (AP[2:0] = 0b011) let any user
    /// process read and write kernel memory and MMIO directly.
    pub(crate) const AP_PL1_ONLY: u32 = 0b01 << 10;
    /// Shareable (bit 16).
    pub(crate) const SHAREABLE: u32 = 1 << 16;
    /// Normal memory, OUTER/INNER write-back write-allocate.
    /// TEX[2:0] = 0b001, C = 1, B = 1 (bits [14:12], [3], [2]).
    pub(crate) const NORMAL_WB_WA: u32 = (0b001 << 12) | (1 << 3) | (1 << 2);
    /// Device memory, strongly ordered.
    /// TEX[2:0] = 0b000, C = 0, B = 1 (for device/shared).
    pub(crate) const DEVICE: u32 = 1 << 2;
    /// Execute never (XN, bit 4).
    pub(crate) const XN: u32 = 1 << 4;
}

/// L2 (small page) descriptor flags (4 KB mapping).
///
/// WHY: L1 section mapping (1 MB) is too coarse for userspace memory management.
/// mmap/brk need page-level (4 KB) granularity. ARMv7 short-descriptor format
/// uses L2 page tables (256 entries x 4 bytes = 1 KB) pointed to by L1 "page
/// table" descriptors.
pub(crate) mod page_flags {
    /// L1 descriptor type: coarse page table pointer (bits [1:0] = 0b01).
    pub(crate) const L1_PAGE_TABLE: u32 = 0b01;
    /// L2 small page descriptor (bits [1:0] = 0b10, XN in bit 0 = 0).
    pub(crate) const SMALL_PAGE: u32 = 0b10;
    /// AP[1:0] = 0b11 (bits [5:4]): full access (PL1 + PL0 read/write).
    pub(crate) const AP_FULL: u32 = 0b11 << 4;
    /// AP[1:0] = 0b10 (bits [5:4]): read-only (PL0 read, PL1 read/write).
    pub(crate) const AP_READ_ONLY: u32 = 0b10 << 4;
    /// AP[1:0] = 0b01 (bits [5:4]): PL1-only (no PL0 access).
    pub(crate) const AP_KERNEL_ONLY: u32 = 0b01 << 4;
    /// AP[2:0] = 0b101 (APX bit 9 set, AP[1:0]=0b01): PL1 READ-ONLY, no PL0.
    /// WHY (#417): kernel `.text` is mapped read-only + executable for W^X.
    pub(crate) const AP_KERNEL_RO: u32 = (0b01 << 4) | (1 << 9);
    /// Execute-never for small pages (XN, bit 0).
    pub(crate) const XN: u32 = 1;
    /// Shareable (bit 10).
    pub(crate) const SHAREABLE: u32 = 1 << 10;
    /// Normal memory for small pages: TEX[2:0]=0b001 (bits [8:6]), C=1 (bit 3), B=1 (bit 2).
    pub(crate) const NORMAL_WB_WA: u32 = (0b001 << 6) | (1 << 3) | (1 << 2);
    /// Not-global (nG, bit 11), repurposed as a software USER_OWNED tag (#496).
    /// Every user page (minted through `prot_to_l2_flags`) carries it; the kernel
    /// fills (`KERNEL_DEFAULT_PAGE`, `wx_page_attrs`) never do. This lets
    /// `l2_entry_is_user` recognise a PROT_NONE user page -- whose AP (0b01) is
    /// byte-identical to a kernel fill -- so fork/exit/exec enumeration copies +
    /// frees it. HW effect: nG makes the TLB entry ASID-tagged; harmless here
    /// because CONTEXTIDR is pinned 0 (see `program_translation`) and every
    /// address-space switch does TLBIALL, so `TLBIMVA(VA, ASID=0)` still hits
    /// user entries.
    pub(crate) const NG: u32 = 1 << 11;
}

/// L2 page table: 256 entries x 4 bytes = 1 KB, must be 1 KB aligned.
#[repr(C, align(1024))]
pub(crate) struct L2Table {
    pub entries: [u32; 256],
}

/// Dedicated L2 table for the kernel's 1 MB region at 0x4000_0000, mapped with
/// W^X page permissions (#417). Permanent (not drawn from the userspace pool).
static mut KERNEL_L2: L2Table = L2Table { entries: [0; 256] };

/// Pool of L2 page tables for userspace mappings.
/// WHY: 64 tables supports up to ~64 MB of page-mapped address space
/// across all processes (each L2 covers 1 MB of VA space at 4 KB granularity).
const L2_POOL_SIZE: usize = 64;
static mut L2_TABLES: [L2Table; L2_POOL_SIZE] = {
    const EMPTY: L2Table = L2Table { entries: [0; 256] };
    [EMPTY; L2_POOL_SIZE]
};

/// Allocation bitmask for L2_TABLES. Bit N = 1 means slot N is in use.
static mut L2_ALLOC: u64 = 0;

/// WHY (#416): guards every `L2_ALLOC` accessor (`alloc_l2_table`,
/// `free_l2_table`) -- same defect class as #331/PAGE_LOCK.
static L2_POOL_LOCK: irq::IrqSpinlock = irq::IrqSpinlock::new();

/// Allocate an L2 page table from the pool. Returns its physical address.
pub(crate) fn alloc_l2_table() -> Option<usize> {
    // WHY (#416): serializes with every other L2_ALLOC accessor, including
    // an IRQ-context caller, so a concurrent or IRQ-interleaved RMW cannot
    // double-allocate the same pool slot (same defect class as #331).
    let _g = L2_POOL_LOCK.lock();
    unsafe {
        let alloc = core::ptr::addr_of_mut!(L2_ALLOC);
        let mask = core::ptr::read_volatile(alloc);
        let slot = (0u64..L2_POOL_SIZE as u64).find(|&i| mask & (1 << i) == 0)?;
        core::ptr::write_volatile(alloc, mask | (1 << slot));
        let table = &mut (*core::ptr::addr_of_mut!(L2_TABLES))[slot as usize];
        for entry in table.entries.iter_mut() {
            *entry = 0;
        }
        Some(core::ptr::addr_of!(*table) as usize)
    }
}

/// Free an L2 page table back to the pool.
///
/// Returns `true` if `phys_addr` matched an allocated pool slot and was
/// freed, `false` if it matched no slot -- WHY (finding 8): the caller can
/// now detect a free of an unrecognized address instead of the prior
/// silent no-op.
///
/// # Safety
///
/// `phys_addr` must have been returned by `alloc_l2_table` and not yet freed.
pub unsafe fn free_l2_table(phys_addr: usize) -> bool {
    // WHY (#416): serializes with every other L2_ALLOC accessor (see
    // alloc_l2_table) so a concurrent alloc/free pair cannot corrupt a torn
    // bitmask update.
    let _g = L2_POOL_LOCK.lock();
    unsafe {
        let tables = &*core::ptr::addr_of!(L2_TABLES);
        for (i, table) in tables.iter().enumerate() {
            if core::ptr::addr_of!(*table) as usize == phys_addr {
                let alloc = core::ptr::addr_of_mut!(L2_ALLOC);
                let mask = core::ptr::read_volatile(alloc);
                core::ptr::write_volatile(alloc, mask & !(1u64 << i));
                return true;
            }
        }
    }
    false
}

/// POSIX protection flag constants (from mman.h).
pub(crate) mod prot {
    /// Page can be read.
    pub(crate) const PROT_READ: u32 = 0x1;
    /// Page can be written.
    pub(crate) const PROT_WRITE: u32 = 0x2;
    /// Page can be executed.
    pub(crate) const PROT_EXEC: u32 = 0x4;
}

/// Translate POSIX prot flags to ARMv7 L2 small page descriptor attributes.
///
/// WHY: userspace passes POSIX prot flags (PROT_READ|PROT_WRITE|PROT_EXEC),
/// but the ARM MMU uses AP bits and XN to control access and execution.
pub(crate) fn prot_to_l2_flags(prot_flags: u32) -> u32 {
    // #496: this function is the SOLE funnel for user L2 descriptors (image,
    // stack, heap/brk, mmap, mprotect all route through it), so tagging nG
    // (USER_OWNED) here -- unconditionally, every page it mints is a user page --
    // marks exactly the user pages and nothing else. Enumeration keys on this tag,
    // not AP, so a PROT_NONE page (AP 0b01) is no longer confused with a kernel
    // fill.
    let mut attrs =
        page_flags::SMALL_PAGE | page_flags::SHAREABLE | page_flags::NORMAL_WB_WA | page_flags::NG;

    // Access permissions
    if prot_flags & prot::PROT_WRITE != 0 {
        attrs |= page_flags::AP_FULL; // read/write
    } else if prot_flags & prot::PROT_READ != 0 {
        attrs |= page_flags::AP_READ_ONLY; // read-only
    } else {
        attrs |= page_flags::AP_KERNEL_ONLY; // no user access
    }

    // WHY (SECURITY, finding 19, W^X / #417): a page must never be both
    // writable and executable -- that combination is a direct
    // code-injection primitive (write shellcode, then execute it from the
    // same mapping). PROT_WRITE always forces XN regardless of whether
    // PROT_EXEC was also requested, so sys_mmap/sys_mprotect (the only two
    // callers, in syscall.rs) can never install a WX page even though
    // neither performs its own WX check before calling this function.
    // Execute-never unless exec was requested AND write was not.
    if prot_flags & prot::PROT_WRITE != 0 || prot_flags & prot::PROT_EXEC == 0 {
        attrs |= page_flags::XN;
    }

    attrs
}

/// Map a single 4 KB page in a process's address space.
///
/// Installs an L2 page table at the appropriate L1 index if one is not
/// already present, then writes the L2 entry for the 4 KB page.
///
/// # Safety
///
/// `l1_phys` must be a valid L1 page table address. `virt_addr` must be
/// page-aligned. `phys_addr` must be a valid allocated physical page.
pub unsafe fn map_page(l1_phys: usize, virt_addr: usize, phys_addr: usize, l2_attrs: u32) -> bool {
    let l1_index = virt_addr >> 20; // which 1 MB section
    let l2_index = (virt_addr >> 12) & 0xFF; // which 4 KB page within the section

    unsafe {
        let l1_entry_ptr = (l1_phys as *mut u32).add(l1_index);
        let l1_val = l1_entry_ptr.read_volatile();

        // Check if an L2 table already exists at this L1 index
        let l2_phys = if l1_val & 0b11 == page_flags::L1_PAGE_TABLE {
            // L1 already points to an L2 table
            (l1_val & 0xFFFF_FC00) as usize
        } else if l1_val & 0b11 == 0 {
            // No mapping exists -- allocate a new L2 table
            let Some(new_l2) = alloc_l2_table() else {
                return false;
            };
            // Write L1 entry pointing to the new L2 table
            let l1_desc = (new_l2 as u32) | page_flags::L1_PAGE_TABLE;
            l1_entry_ptr.write_volatile(l1_desc);
            new_l2
        } else {
            // Section mapping exists -- cannot overlay with page mapping
            return false;
        };

        // Write the L2 entry
        let l2_entry_ptr = (l2_phys as *mut u32).add(l2_index);
        let l2_desc = (phys_addr as u32 & 0xFFFFF000) | l2_attrs;
        l2_entry_ptr.write_volatile(l2_desc);

        true
    }
}

/// Kernel-default L2 small-page descriptor (value 0x45F): PL1 read/write, PL0
/// NO access, execute-never (#482). Fills a shattered identity MB so a PL0
/// process gets nothing in that MB by default; specific pages are then granted
/// via `map_page`.
pub(crate) const KERNEL_DEFAULT_PAGE: u32 = page_flags::SMALL_PAGE
    | page_flags::SHAREABLE
    | page_flags::NORMAL_WB_WA
    | page_flags::AP_KERNEL_ONLY
    | page_flags::XN;

/// Convert the 1 MB SECTION covering `virt_addr` in `l1_phys` into a FULLY
/// POPULATED identity L2 table (256 entries, each `KERNEL_DEFAULT_PAGE`), so
/// individual pages can then be granted PL0 access via `map_page` (#482).
///
/// INVARIANT (load-bearing): ALL 256 entries are written. A sparse shatter
/// would leave neighbor pages unmapped for the KERNEL too -- it would
/// data-abort mid-syscall on the first access to any other page in this MB
/// through the process TTBR0 (kernel heap and other processes' stacks share
/// allocator MBs), an intermittent layout-dependent lockup.
///
/// Idempotent: returns true unchanged if the L1 slot is already a page table.
/// Fails closed (false) on an empty/unexpected descriptor or L2-pool
/// exhaustion. Callers pass DRAM addresses only (never device MBs).
///
/// # Safety
///
/// `l1_phys` must be a valid process L1 table. If it is LIVE in TTBR0 (exec),
/// the caller must flush the TLB afterward; at spawn the table is not yet live.
pub(crate) unsafe fn shatter_section(l1_phys: usize, virt_addr: usize) -> bool {
    let l1_index = virt_addr >> 20;
    unsafe {
        let l1_entry_ptr = (l1_phys as *mut u32).add(l1_index);
        let l1_val = l1_entry_ptr.read_volatile();
        if l1_val & 0b11 == page_flags::L1_PAGE_TABLE {
            return true;
        }
        if l1_val & 0b11 != flags::SECTION {
            return false;
        }
        let Some(l2_phys) = alloc_l2_table() else {
            return false;
        };
        let base = l1_val & 0xFFF0_0000;
        let l2 = l2_phys as *mut u32;
        for i in 0..256u32 {
            l2.add(i as usize)
                .write_volatile((base + (i << 12)) | KERNEL_DEFAULT_PAGE);
        }
        l1_entry_ptr.write_volatile((l2_phys as u32) | page_flags::L1_PAGE_TABLE);
        true
    }
}

/// Ensure the MB covering `virt_addr` in `l1_phys` can accept a `map_page` (#496).
///
/// `map_page` REFUSES to overlay a 1 MB SECTION descriptor, and the identity map
/// covers the user windows (the mmap region, the heap) with sections -- so a
/// syscall that maps a page there must shatter the section first, exactly as
/// `map_user_image` / `map_user_stack` do at spawn.
///
/// Unlike `shatter_section`, an ABSENT L1 entry is not an error here: `map_page`
/// allocates the L2 itself in that case. So this returns true for absent and for
/// already-shattered entries, and only shatters an actual section.
///
/// # Safety
///
/// Same as `shatter_section`; on a LIVE table the caller must flush the TLB for
/// the affected VA (the stale section entry would otherwise still resolve).
pub(crate) unsafe fn ensure_page_mappable(l1_phys: usize, virt_addr: usize) -> bool {
    let l1_index = virt_addr >> 20;
    // SAFETY: the caller guarantees `l1_phys` is a valid L1 table.
    let l1_val = unsafe { (l1_phys as *const u32).add(l1_index).read_volatile() };
    if l1_val & 0b11 != flags::SECTION {
        return true; // absent (map_page allocates) or already a page table
    }
    // SAFETY: the entry is a section; shatter it into a KERNEL_DEFAULT L2.
    unsafe { shatter_section(l1_phys, virt_addr) }
}

/// Rewrite every entry of an already-shattered identity MB back to
/// `KERNEL_DEFAULT_PAGE`, dropping all PL0 grants in that MB (#482, used by exec
/// to revoke the old image's user windows). Returns false if not shattered.
///
/// # Safety
///
/// Same as `shatter_section`; on a LIVE table the caller must flush the TLB.
pub(crate) unsafe fn reset_shattered_section(l1_phys: usize, virt_addr: usize) -> bool {
    let l1_index = virt_addr >> 20;
    unsafe {
        let l1_val = (l1_phys as *const u32).add(l1_index).read_volatile();
        if l1_val & 0b11 != page_flags::L1_PAGE_TABLE {
            return false;
        }
        let l2_phys = (l1_val & 0xFFFF_FC00) as usize;
        let base = (virt_addr & 0xFFF0_0000) as u32;
        let l2 = l2_phys as *mut u32;
        for i in 0..256u32 {
            l2.add(i as usize)
                .write_volatile((base + (i << 12)) | KERNEL_DEFAULT_PAGE);
        }
        true
    }
}

/// Read the raw L2 small-page descriptor for `virt_addr`, or None if the L1
/// slot is not a page table. Test/diagnostic seam for asserting AP/XN bits.
///
/// # Safety
///
/// `l1_phys` must be a valid L1 table; `virt_addr` page-aligned.
pub(crate) unsafe fn read_l2_entry(l1_phys: usize, virt_addr: usize) -> Option<u32> {
    let l1_index = virt_addr >> 20;
    let l2_index = (virt_addr >> 12) & 0xFF;
    unsafe {
        let l1_val = (l1_phys as *const u32).add(l1_index).read_volatile();
        if l1_val & 0b11 != page_flags::L1_PAGE_TABLE {
            return None;
        }
        let l2_phys = (l1_val & 0xFFFF_FC00) as usize;
        Some((l2_phys as *const u32).add(l2_index).read_volatile())
    }
}

/// True if a small-page L2 descriptor is a USER-OWNED page (#478, #496).
///
/// A small-page descriptor is bits[1:0] = 0b1X (bit 1 marks the small page, bit
/// 0 is XN), so `bit 1 set` catches an executable (0b10) or execute-never (0b11)
/// page and rejects a large-page (0b01) or fault (0b00) entry. Ownership is then
/// decided by the software `NG` (USER_OWNED) tag, NOT by AP: `prot_to_l2_flags`
/// sets NG on every user page (image, stack, heap/mmap), while the kernel fills
/// (`KERNEL_DEFAULT_PAGE`, `wx_page_attrs`, the shared `KERNEL_L2`) never do.
///
/// WHY NG and not AP (#496): a PROT_NONE user page maps to AP=0b01
/// (`AP_KERNEL_ONLY`) -- byte-identical to a kernel fill -- so the old AP >= 0b10
/// test dropped it from fork's deep-copy and from exit/exec teardown. Keying on
/// the ownership tag enumerates PROT_NONE user pages while still rejecting every
/// kernel entry.
pub(crate) fn l2_entry_is_user(entry: u32) -> bool {
    entry & page_flags::SMALL_PAGE != 0 && entry & page_flags::NG != 0
}

/// Visit every PL0-accessible small page in `l1_phys`, calling `f(va, phys,
/// attrs)` per page where `attrs` is the full low-12 descriptor bits
/// (type+XN, C/B, AP, TEX, APX, S). Early-aborts (returns false) when `f`
/// returns false; returns true after a full walk (#478).
///
/// A PL0 process's ENTIRE user-visible memory is, by construction, exactly the
/// set of user-AP L2 entries in its own L1 -- so enumerating the page table is
/// complete (fork needs no ELF), and passing `attrs` straight to `map_page`
/// reconstructs each descriptor bit-for-bit (same W^X, XN, AP, memory type).
///
/// # Safety
/// `l1_phys` must be a valid L1 table; its L2 tables live in kernel statics
/// mapped in every address space.
pub(crate) unsafe fn for_each_user_page(
    l1_phys: usize,
    mut f: impl FnMut(usize, usize, u32) -> bool,
) -> bool {
    // SAFETY: caller guarantees l1_phys is a valid L1; every read below is
    // bounds-checked by the fixed 4096/256 loop extents.
    unsafe {
        let l1 = l1_phys as *const u32;
        for l1_idx in 0..4096usize {
            let l1_val = l1.add(l1_idx).read_volatile();
            if l1_val & 0b11 != page_flags::L1_PAGE_TABLE {
                continue;
            }
            let l2 = (l1_val & 0xFFFF_FC00) as *const u32;
            for l2_idx in 0..256usize {
                let entry = l2.add(l2_idx).read_volatile();
                if !l2_entry_is_user(entry) {
                    continue;
                }
                let va = (l1_idx << 20) | (l2_idx << 12);
                if !f(va, (entry & 0xFFFF_F000) as usize, entry & 0xFFF) {
                    return false;
                }
            }
        }
        true
    }
}

/// Unmap a single 4 KB page from a process's address space.
///
/// Zeroes the L2 entry for the given virtual address. If clearing that
/// entry leaves every entry in the L2 table empty, the table is returned to
/// the global pool (`free_l2_table`) and the owning L1 descriptor is
/// cleared, so a sparse map/unmap workload cannot permanently strand pool
/// slots (#330) -- the caller's existing post-unmap `flush_tlb_page(virt_addr)`
/// call already invalidates the one translation this can affect; no other
/// entry in a now-empty table was ever live in the TLB.
///
/// # Safety
///
/// `l1_phys` must be a valid L1 page table address. `virt_addr` must be
/// page-aligned.
pub unsafe fn unmap_page(l1_phys: usize, virt_addr: usize) {
    let l1_index = virt_addr >> 20;
    let l2_index = (virt_addr >> 12) & 0xFF;

    unsafe {
        let l1_entry_ptr = (l1_phys as *mut u32).add(l1_index);
        let l1_val = l1_entry_ptr.read_volatile();

        if l1_val & 0b11 == page_flags::L1_PAGE_TABLE {
            let l2_phys = (l1_val & 0xFFFF_FC00) as usize;
            let l2_entry_ptr = (l2_phys as *mut u32).add(l2_index);
            l2_entry_ptr.write_volatile(0);

            // WHY (#330): reclaim the table once every entry is empty,
            // rather than leaking a global pool slot per touched 1 MB
            // region forever.
            let table_ptr = l2_phys as *const u32;
            let mut all_empty = true;
            for i in 0..256isize {
                if table_ptr.offset(i).read_volatile() != 0 {
                    all_empty = false;
                    break;
                }
            }
            if all_empty {
                l1_entry_ptr.write_volatile(0);
                free_l2_table(l2_phys);
            }
        }
    }
}

/// Read the physical small-page base address mapped at `virt_addr` in
/// `l1_phys`'s address space, without clearing the L2 entry.
///
/// WHY (#225, #226): `unmap_page` zeroes the L2 entry, permanently losing the
/// physical frame it pointed to unless the caller reads it out first. Callers
/// that need to return the frame to `page::free_page` must call this before
/// `unmap_page`, not after.
///
/// Returns `None` if no L2 table is installed at this L1 index, or if the
/// L2 entry is not currently mapped.
///
/// # Safety
///
/// `l1_phys` must be a valid L1 page table address. `virt_addr` must be
/// page-aligned.
pub unsafe fn read_l2_phys(l1_phys: usize, virt_addr: usize) -> Option<usize> {
    let l1_index = virt_addr >> 20;
    let l2_index = (virt_addr >> 12) & 0xFF;

    unsafe {
        let l1_entry_ptr = (l1_phys as *const u32).add(l1_index);
        let l1_val = l1_entry_ptr.read_volatile();

        if l1_val & 0b11 != page_flags::L1_PAGE_TABLE {
            return None;
        }

        let l2_phys = (l1_val & 0xFFFF_FC00) as usize;
        let l2_entry_ptr = (l2_phys as *const u32).add(l2_index);
        let l2_val = l2_entry_ptr.read_volatile();

        if l2_val & 0b11 == 0 {
            return None;
        }

        Some((l2_val & 0xFFFFF000) as usize)
    }
}

/// Update the protection flags on a single 4 KB page.
///
/// Returns true if the page was found and updated, false if not mapped.
///
/// # Safety
///
/// `l1_phys` must be a valid L1 page table address. `virt_addr` must be
/// page-aligned.
pub unsafe fn update_page_prot(l1_phys: usize, virt_addr: usize, l2_attrs: u32) -> bool {
    let l1_index = virt_addr >> 20;
    let l2_index = (virt_addr >> 12) & 0xFF;

    unsafe {
        let l1_entry_ptr = (l1_phys as *const u32).add(l1_index);
        let l1_val = l1_entry_ptr.read_volatile();

        if l1_val & 0b11 != page_flags::L1_PAGE_TABLE {
            return false;
        }

        let l2_phys = (l1_val & 0xFFFF_FC00) as usize;
        let l2_entry_ptr = (l2_phys as *mut u32).add(l2_index);
        let old = l2_entry_ptr.read_volatile();

        if old & 0b11 == 0 {
            return false; // page not mapped
        }

        // Preserve the physical address, replace the attribute bits
        let new_desc = (old & 0xFFFFF000) | l2_attrs;
        l2_entry_ptr.write_volatile(new_desc);

        true
    }
}

/// Flush TLB for a single virtual address.
///
/// # Safety
///
/// Must be called after modifying page table entries to ensure the TLB
/// reflects the new mapping.
#[cfg(target_arch = "arm")]
pub unsafe fn flush_tlb_page(virt_addr: usize) {
    // SAFETY: CP15 system register access is a privileged operation. The register
    // being modified is TLBIMVA (c8, c7, 1) which invalidates the TLB entry for
    // the given virtual address. DSB/ISB barriers ensure visibility before the
    // next memory access or instruction fetch.
    unsafe {
        core::arch::asm!(
            "mcr p15, 0, {addr}, c8, c7, 1", // TLBIMVA
            "dsb sy",
            "isb sy",
            addr = in(reg) virt_addr as u32,
        );
    }
}

/// No-op TLB flush for non-ARM builds.
#[cfg(not(target_arch = "arm"))]
pub unsafe fn flush_tlb_page(_virt_addr: usize) {}

/// Invalidate the ENTIRE unified TLB + branch predictor (#489).
///
/// Used by exec, which rewrites whole MBs of the LIVE table
/// (reset_shattered_section + map_user_image + map_user_stack) -- a per-page
/// TLBIMVA loop over 256+ changed entries is the wrong tool. BPIALL is needed
/// because the executable image at USER_TEXT changed identity.
///
/// # Safety
/// Call with IRQs masked, after all table writes, before returning to PL0.
#[cfg(target_arch = "arm")]
pub unsafe fn flush_tlb_all() {
    // SAFETY: privileged CP15 maintenance; barriers order it before the return.
    unsafe {
        core::arch::asm!(
            "mcr p15, 0, {z}, c8, c7, 0", // TLBIALL
            "mcr p15, 0, {z}, c7, c5, 6", // BPIALL
            "dsb sy",
            "isb sy",
            z = in(reg) 0u32,
        );
    }
}

/// No-op full-TLB flush for non-ARM builds.
#[cfg(not(target_arch = "arm"))]
pub unsafe fn flush_tlb_all() {}

/// D-cache line size in bytes, decoded from CTR (CP15 c0, c0, 1) DminLine
/// (bits [19:16], ARM ARM B4.1.61): the smallest data/unified cache line is
/// `2^DminLine` words, so its byte size is `4 << DminLine`. Pure so the
/// encoding is host-testable without CP15 access.
fn dcache_line_bytes_from_ctr(dminline: u32) -> usize {
    4usize << (dminline & 0xF)
}

/// Read CTR and decode this core's D-cache line size in bytes.
#[cfg(target_arch = "arm")]
fn dcache_line_size() -> usize {
    let ctr: u32;
    // SAFETY: CTR (c0, c0, 1) is a read-only CP15 identification register,
    // legal to read from PL1 unconditionally.
    unsafe {
        core::arch::asm!("mrc p15, 0, {0}, c0, c0, 1", out(reg) ctr);
    }
    dcache_line_bytes_from_ctr((ctr >> 16) & 0xF)
}

/// The cache-line-aligned `(first_line_addr, line_count)` covering
/// `[va, va + len)` at `line_size` granularity: the start rounds DOWN and the
/// end rounds UP to line boundaries, so every byte in the range is covered
/// even when `va` starts mid-line or `len` doesn't end on a line boundary --
/// missing the trailing line is exactly how the last dirty bytes of a
/// freshly-written page would keep a stale I-cache line (#498). Pure so the
/// walk is host-testable without CP15 access. `len == 0` visits no lines.
fn icache_line_range(va: usize, len: usize, line_size: usize) -> (usize, usize) {
    if len == 0 {
        return (va, 0);
    }
    let start = va & !(line_size - 1);
    let end = va + len;
    let end_aligned = (end + line_size - 1) & !(line_size - 1);
    (start, (end_aligned - start) / line_size)
}

/// Synchronize the I-cache with freshly D-side-written code before it is
/// executed (ARM ARM B2.2.6 self-modifying-code sequence, #498): clean the
/// D-cache to the Point of Unification over `[va, va+len)`, then invalidate
/// the whole I-cache and branch predictor, with DSB/ISB ordering so a
/// subsequent instruction fetch cannot observe a stale line.
///
/// QEMU TCG's caches are architecturally coherent, so this call has no
/// observable effect under QEMU/CI -- it matters on real Cortex-A7 hardware
/// (I-cache enabled at `init_and_enable`), where a D-side write (fork's page
/// copy, an ELF load, an exec remap) is otherwise invisible to a stale
/// I-cache line at the same address.
///
/// # Safety
/// `va` must currently translate, under the active TTBR0, to the physical
/// page(s) that were just written; `len` must not exceed the mapped region.
#[cfg(target_arch = "arm")]
pub unsafe fn sync_icache_range(va: usize, len: usize) {
    let line_size = dcache_line_size();
    let (start, line_count) = icache_line_range(va, len, line_size);
    for i in 0..line_count {
        let addr = start + i * line_size;
        // SAFETY: DCCMVAU (Data Cache line Clean by MVA to PoU, c7 c11 1)
        // writes this line back so the I-side/memory view agrees with it;
        // `addr` was proven mapped by the caller's contract.
        unsafe {
            core::arch::asm!(
                "mcr p15, 0, {addr}, c7, c11, 1", // DCCMVAU
                addr = in(reg) addr as u32,
            );
        }
    }
    // SAFETY: privileged CP15 cache/branch-predictor maintenance. DSB orders
    // the D-cache cleans above before the invalidate; ICIALLU (c7 c5 0) +
    // BPIALL (c7 c5 6) invalidate the whole I-cache and branch predictor; the
    // closing DSB/ISB make both effective before the next fetched
    // instruction.
    unsafe {
        core::arch::asm!(
            "dsb sy",
            "mcr p15, 0, {z}, c7, c5, 0", // ICIALLU
            "mcr p15, 0, {z}, c7, c5, 6", // BPIALL
            "dsb sy",
            "isb sy",
            z = in(reg) 0u32,
        );
    }
}

/// No-op I-cache sync for non-ARM (host test) builds: host tests run with
/// architecturally coherent caches, so there is nothing to synchronize.
#[cfg(not(target_arch = "arm"))]
pub unsafe fn sync_icache_range(_va: usize, _len: usize) {}

/// Reset the L2 table pool (test helper only).
#[cfg(test)]
pub(crate) fn reset_l2_pool() {
    unsafe {
        core::ptr::write_volatile(core::ptr::addr_of_mut!(L2_ALLOC), 0);
    }
}

/// Memory region type for the initial mapping.
#[derive(Clone, Copy)]
pub enum MemoryType {
    /// Normal cacheable RAM.
    Ram,
    /// Device/MMIO registers (non-cacheable, strongly ordered).
    Device,
}

/// The W^X access-permission + execute bits for a kernel page at virtual
/// address `va`, given the page-aligned image boundaries (#417). Pure, so the
/// W^X policy is host-testable without the MMU:
/// - `.text` (`[text_start, etext)`): read-only + executable.
/// - `.rodata` (`[etext, erodata)`): read-only + execute-never.
/// - everything else (pre-image gap, data, bss, stacks): writable +
///   execute-never.
///
/// INVARIANT: an executable page (XN unset) is always read-only, so no page is
/// ever both writable and executable.
fn wx_page_attrs(va: usize, text_start: usize, etext: usize, erodata: usize) -> u32 {
    if va >= text_start && va < etext {
        page_flags::AP_KERNEL_RO
    } else if va >= etext && va < erodata {
        page_flags::AP_KERNEL_RO | page_flags::XN
    } else {
        page_flags::AP_KERNEL_ONLY | page_flags::XN
    }
}

/// Fill the kernel L2 table with W^X page permissions (#417).
///
/// link.ld page-aligns the image boundaries so each 4 KB page of the kernel's
/// 1 MB region falls entirely in one region (see [`wx_page_attrs`]). Gated to
/// the real target: the linker symbols do not exist in the i686 host-test link
/// (the wx policy itself is unit-tested via `wx_page_attrs`).
///
/// # Safety
/// Called once during early boot on `KERNEL_L2`, interrupts disabled, before
/// the MMU is enabled.
#[cfg(not(test))]
unsafe fn map_kernel_wx() {
    unsafe extern "C" {
        static __text_start: u8;
        static __etext: u8;
        static __erodata: u8;
    }
    let text_start = core::ptr::addr_of!(__text_start) as usize;
    let etext = core::ptr::addr_of!(__etext) as usize;
    let erodata = core::ptr::addr_of!(__erodata) as usize;
    const KERNEL_BASE: usize = 0x4000_0000;
    const PAGE: usize = 4096;
    // SAFETY: KERNEL_L2 is a static mut written once here during early boot
    // with interrupts disabled and no concurrent access.
    let l2 = unsafe { &mut *core::ptr::addr_of_mut!(KERNEL_L2) };
    for (i, entry) in l2.entries.iter_mut().enumerate() {
        let va = KERNEL_BASE + i * PAGE;
        *entry = u32::try_from(va).unwrap_or_default()
            | page_flags::SMALL_PAGE
            | page_flags::SHAREABLE
            | page_flags::NORMAL_WB_WA
            | wx_page_attrs(va, text_start, etext, erodata);
    }
}

/// Map a 1 MB section in the L1 page table.
///
/// `virt_mb` and `phys_mb` are megabyte-aligned addresses divided by 1 MB.
/// For identity mapping, `virt_mb == phys_mb`.
fn map_section(virt_mb: usize, phys_mb: usize, mem_type: MemoryType) {
    let base = (u32::try_from(phys_mb).unwrap_or_default()) << 20;
    let attrs = match mem_type {
        // WHY (#417): RAM sections are execute-never. The one executable RAM
        // region -- the kernel `.text` -- is mapped separately via the kernel
        // L2 table (map_kernel_wx); all flat DRAM here is data/heap and must
        // not be executable (W^X defense-in-depth).
        MemoryType::Ram => {
            flags::SECTION | flags::AP_PL1_ONLY | flags::SHAREABLE | flags::NORMAL_WB_WA | flags::XN
        }
        MemoryType::Device => flags::SECTION | flags::AP_PL1_ONLY | flags::DEVICE | flags::XN,
    };
    unsafe {
        let table = &mut *core::ptr::addr_of_mut!(L1);
        table.entries[virt_mb] = base | attrs;
    }
}

/// Set up the initial page table and enable the MMU.
///
/// Identity maps:
/// - 0x0000_0000 - 0x0FFF_FFFF: boot ROM / SRAM (device)
/// - 0x1000_0000 - 0x1FFF_FFFF: peripheral MMIO (device)
/// - 0x2000_0000 - 0x2FFF_FFFF: modem / CCCI (device)
/// - 0x4000_0000 - 0x7FFF_FFFF: DRAM 1 GB (normal RAM)
///
/// # Safety
///
/// Must be called once during early boot, with interrupts disabled,
/// before any code that depends on virtual memory.
pub unsafe fn init_and_enable() {
    // SAFETY: L1 is a static mut only accessed during early boot with interrupts
    // disabled and no concurrent readers. addr_of_mut! avoids creating a reference
    // to a static mut, which is UB.
    let table = unsafe { &mut *core::ptr::addr_of_mut!(L1) };
    for entry in table.entries.iter_mut() {
        *entry = 0;
    }

    // Boot ROM / SRAM: 0x0000_0000 - 0x0FFF_FFFF (256 MB)
    for mb in 0x000..0x100 {
        map_section(mb, mb, MemoryType::Device);
    }

    // Peripheral MMIO: 0x1000_0000 - 0x1FFF_FFFF (256 MB)
    // NOTE: UART0 at 0x1100_2000, GPIO, SPI, I2C, etc.
    for mb in 0x100..0x200 {
        map_section(mb, mb, MemoryType::Device);
    }

    // Modem / CCCI: 0x2000_0000 - 0x2FFF_FFFF (256 MB)
    for mb in 0x200..0x300 {
        map_section(mb, mb, MemoryType::Device);
    }

    // Kernel image region (0x4000_0000 - 0x4010_0000): W^X via the kernel L2
    // table (#417) -- .text read-only+executable, .rodata read-only+XN,
    // data/bss/stacks writable+XN. The rest of DRAM below is flat RAM sections,
    // now execute-never.
    // On the real target the kernel image is W^X-mapped via its L2 table;
    // under host test the linker symbols do not exist, so map mb 0x400 as a
    // flat RAM section (the wx policy is unit-tested via wx_page_attrs).
    #[cfg(not(test))]
    {
        // SAFETY: KERNEL_L2 is filled once here during early boot with
        // interrupts disabled, before the MMU is enabled; L1[0x400] then
        // points at it as a coarse page table (domain 0, checked by DACR per
        // #323).
        unsafe {
            map_kernel_wx();
        }
        table.entries[0x400] = u32::try_from(core::ptr::addr_of!(KERNEL_L2) as usize)
            .unwrap_or_default()
            | page_flags::L1_PAGE_TABLE;
    }
    #[cfg(test)]
    map_section(0x400, 0x400, MemoryType::Ram);

    // DRAM beyond the kernel image: 0x4010_0000 - 0x7FFF_FFFF, RAM + XN.
    // WHY (#482): this INCLUDES the userspace text region (0x7FF0_0000, still
    // excluded from the page allocator as the fixed /init load address). The
    // kernel never executes user code from its own address space anymore --
    // spawned processes run from their OWN page tables, where `map_user_image`
    // maps the image user-RX. So the kernel view has NO executable RAM outside
    // kernel .text, completing #417's W^X: a kernel control-flow hijack into
    // the attacker-influenced /init image region now prefetch-aborts (XN)
    // instead of executing. (Retires MemoryType::UserText.)
    for mb in 0x401..0x800 {
        map_section(mb, mb, MemoryType::Ram);
    }

    // Program CP15 and enable address translation.
    // WHY(host-test): the L1 table is populated above on every target, but the
    // CP15 register programming and MMU-enable barriers are ARM-only. On the
    // host test target `program_translation` is a no-op, so this function
    // populates the static table and returns without enabling translation.
    // SAFETY: the L1 table has just been fully populated; called once during
    // early boot with interrupts disabled before any VA-dependent code runs.
    unsafe {
        program_translation();
    }
}

/// Program TTBR0/TTBCR/DACR, invalidate the TLB, and enable the MMU + caches.
///
/// # Safety
///
/// Must be called from `init_and_enable` after the L1 table is fully populated,
/// once during early boot with interrupts disabled.
#[cfg(target_arch = "arm")]
#[inline(always)]
unsafe fn program_translation() {
    // Set TTBR0 to our page table
    let ttbr0 = core::ptr::addr_of!(L1) as u32;
    // SAFETY: CP15 system register access is a privileged operation. The register
    // being modified is TTBR0 (c2, c0, 0) which controls the translation table base.
    unsafe {
        core::arch::asm!(
            "mcr p15, 0, {ttbr}, c2, c0, 0",  // TTBR0
            ttbr = in(reg) ttbr0 | 0x6B,       // NOTE: INNER/OUTER WB-WA cacheable, shareable
        );
    }

    // TTBCR: use TTBR0 for all addresses (N = 0)
    // SAFETY: CP15 system register access is a privileged operation. The register
    // being modified is TTBCR (c2, c0, 2) which controls translation table base selection.
    unsafe {
        core::arch::asm!(
            "mcr p15, 0, {val}, c2, c0, 2",
            val = in(reg) 0u32,
        );
    }

    // DACR: domain 0 = client (check permissions)
    // SAFETY: CP15 system register access is a privileged operation. The register
    // being modified is DACR (c3, c0, 0) which controls domain access permissions.
    unsafe {
        core::arch::asm!(
            "mcr p15, 0, {val}, c3, c0, 0",
            val = in(reg) 1u32,  // NOTE: domain 0 = client access
        );
    }

    // CONTEXTIDR = 0 (ASID 0). #496: user L2 descriptors carry the nG bit as a
    // software USER_OWNED tag (page_flags::NG); nG makes the TLB entry ASID-tagged,
    // so flush_tlb_page/TLBIMVA -- which passes a page-aligned VA whose ASID field
    // is 0 -- only invalidates a user entry when that entry's ASID is also 0. With
    // no ASID scheme (constant CONTEXTIDR + TLBIALL on every address-space switch)
    // that just requires CONTEXTIDR to be 0. QEMU resets it to 0; this makes the
    // invariant explicit and hardens hardware whose reset value is UNKNOWN per ARMv7.
    // SAFETY: CP15 CONTEXTIDR (c13, c0, 1); privileged, once at boot before enable.
    unsafe {
        core::arch::asm!(
            "mcr p15, 0, {zero}, c13, c0, 1",  // CONTEXTIDR = 0
            "isb",
            zero = in(reg) 0u32,
        );
    }

    // Invalidate TLB
    // SAFETY: CP15 system register access is a privileged operation. The register
    // being modified is TLBIALL (c8, c7, 0) which invalidates all TLB entries.
    unsafe {
        core::arch::asm!(
            "mcr p15, 0, {zero}, c8, c7, 0",  // TLBIALL
            zero = in(reg) 0u32,
        );
    }

    // Data synchronization barrier
    // SAFETY: DSB is a privileged barrier instruction required to ensure all
    // prior memory accesses and CP15 writes complete before the MMU is enabled.
    unsafe {
        core::arch::asm!("dsb sy");
    }

    // Enable MMU (SCTLR bit 0) + caches (bit 2 = D-cache, bit 12 = I-cache)
    let mut sctlr: u32;
    // SAFETY: CP15 system register access is a privileged operation. The register
    // being read is SCTLR (c1, c0, 0) which controls system features including the MMU.
    unsafe {
        core::arch::asm!(
            "mrc p15, 0, {val}, c1, c0, 0",
            val = out(reg) sctlr,
        );
    }
    sctlr |= 1 << 0; // M: MMU enable
    sctlr |= 1 << 2; // C: data cache enable
    sctlr |= 1 << 12; // I: instruction cache enable
    // SAFETY: CP15 system register access is a privileged operation. The register
    // being modified is SCTLR (c1, c0, 0) which enables the MMU and caches.
    // The page table has been populated and barriers issued before this write.
    unsafe {
        core::arch::asm!(
            "mcr p15, 0, {val}, c1, c0, 0",
            val = in(reg) sctlr,
        );
    }

    // Instruction synchronization barrier
    // SAFETY: ISB is a privileged barrier instruction required after enabling the MMU
    // to flush the instruction pipeline and ensure subsequent fetches use virtual addresses.
    unsafe {
        core::arch::asm!("isb sy");
    }
}

/// Host-test no-op: address translation is never enabled off-ARM.
///
/// # Safety
///
/// No preconditions; performs no operation.
#[cfg(not(target_arch = "arm"))]
#[inline(always)]
unsafe fn program_translation() {}

/// Return the physical address of the L1 page table.
pub fn table_base() -> usize {
    core::ptr::addr_of!(L1) as usize
}

// --- Per-process address space pool ---

/// Per-process L1 page table: 4096 entries × 4 bytes = 16 KB.
/// Must be 16 KB aligned to satisfy TTBR0 requirements.
#[repr(C, align(16384))]
pub struct UserL1Table {
    entries: [u32; 4096],
}

/// Pool of 16 user-process L1 page tables (256 KB total in BSS).
// INVARIANT: only one owner per slot; ownership tracked by ADDR_SPACE_ALLOC bitmask.
static mut USER_TABLES: [UserL1Table; 16] = {
    const EMPTY: UserL1Table = UserL1Table { entries: [0; 4096] };
    [EMPTY; 16]
};

/// Allocation bitmask for USER_TABLES. Bit N = 1 means slot N is in use.
// NOTE: cfg(test) makes it pub(crate) so process.rs tests can call reset helpers.
#[cfg(test)]
pub(crate) static mut ADDR_SPACE_ALLOC: u16 = 0;
#[cfg(not(test))]
static mut ADDR_SPACE_ALLOC: u16 = 0;

/// WHY (#416): guards every `ADDR_SPACE_ALLOC` accessor (`alloc_addr_space`,
/// `free_addr_space`) -- same defect class as #331/PAGE_LOCK.
static ADDR_SPACE_LOCK: irq::IrqSpinlock = irq::IrqSpinlock::new();

/// Allocate a free user L1 page table FROM the pool.
/// Zeroes the slot before returning its physical address.
/// Returns None if all 16 slots are occupied.
pub fn alloc_addr_space() -> Option<usize> {
    // WHY (#416): serializes with every other ADDR_SPACE_ALLOC accessor,
    // including an IRQ-context caller, so a concurrent or IRQ-interleaved
    // RMW cannot double-allocate the same address-space slot (same defect
    // class as #331).
    let _g = ADDR_SPACE_LOCK.lock();
    unsafe {
        let alloc = core::ptr::addr_of_mut!(ADDR_SPACE_ALLOC);
        let mask = core::ptr::read_volatile(alloc);
        // WHY: find first zero bit (free slot)
        let slot = (0u16..16).find(|&i| mask & (1 << i) == 0)?;
        core::ptr::write_volatile(alloc, mask | (1 << slot));
        let table =
            &mut (*core::ptr::addr_of_mut!(USER_TABLES))[usize::try_from(slot).unwrap_or_default()];
        for entry in table.entries.iter_mut() {
            *entry = 0;
        }
        Some(core::ptr::addr_of!(*table) as usize)
    }
}

/// Return a user L1 page table slot to the pool.
///
/// Also reclaims every L2 page table still referenced by this address
/// space's L1 entries -- page-mapped mmap/heap/stack regions the process
/// never individually unmapped before exit -- so a process that exits
/// without tearing down its own mappings cannot permanently strand pool
/// slots (#330). Cloned kernel identity-map entries are section descriptors,
/// so the walk skips them. The ONE cloned kernel entry that IS an
/// `L1_PAGE_TABLE` -- the shared `KERNEL_L2` at L1[0x400] (#417 W^X) -- is
/// visited by this walk, but `free_l2_table` rejects it: it only frees an
/// address that matches an `L2_TABLES` pool slot, and `KERNEL_L2` is a separate
/// static, never a pool member. So the kernel's own mappings are never freed --
/// safety here rests on that pool-membership check, not on the descriptor type
/// alone.
///
/// Returns `true` if `phys_addr` matched an allocated pool slot and was
/// freed, `false` if it matched no slot -- WHY (finding 8): the caller can
/// now detect a free of an unrecognized address instead of the prior
/// silent no-op.
///
/// # Safety
///
/// `phys_addr` must have been returned by `alloc_addr_space` and not yet freed.
pub unsafe fn free_addr_space(phys_addr: usize) -> bool {
    // WHY (#416): serializes with every other ADDR_SPACE_ALLOC accessor (see
    // alloc_addr_space) so a concurrent alloc/free pair cannot corrupt a
    // torn bitmask update.
    let _g = ADDR_SPACE_LOCK.lock();
    unsafe {
        let tables = &*core::ptr::addr_of!(USER_TABLES);
        for (i, table) in tables.iter().enumerate() {
            if core::ptr::addr_of!(*table) as usize == phys_addr {
                let l1 = phys_addr as *const u32;
                for idx in 0..4096isize {
                    let entry = l1.offset(idx).read_volatile();
                    if entry & 0b11 == page_flags::L1_PAGE_TABLE {
                        let l2_phys = (entry & 0xFFFF_FC00) as usize;
                        free_l2_table(l2_phys);
                    }
                }

                let alloc = core::ptr::addr_of_mut!(ADDR_SPACE_ALLOC);
                let mask = core::ptr::read_volatile(alloc);
                core::ptr::write_volatile(alloc, mask & !(1 << i));
                return true;
            }
        }
    }
    false
}

/// Copy all 4096 L1 entries FROM the source address space INTO the destination.
/// Used by fork() to clone the kernel's mappings INTO a new process table.
///
/// # Safety
///
/// Both `src_phys` and `dst_phys` must be valid physical addresses of
/// 16 KB-aligned L1 tables (either the kernel L1 or a USER_TABLES slot).
pub unsafe fn clone_addr_space(src_phys: usize, dst_phys: usize) {
    // SAFETY: caller guarantees both pointers are valid 16 KB-aligned L1 tables.
    unsafe {
        let src = src_phys as *const u32;
        let dst = dst_phys as *mut u32;
        for i in 0..4096isize {
            dst.offset(i).write_volatile(src.offset(i).read_volatile());
        }
    }
}

/// Switch the active user address space by writing TTBR0 and flushing the TLB.
///
/// # Safety
///
/// `table_phys` must be the physical address of a valid, correctly populated
/// 16 KB-aligned L1 page table. Must be called with interrupts disabled.
#[cfg(target_arch = "arm")]
pub unsafe fn switch_addr_space(table_phys: usize) {
    // SAFETY: TTBR0 write followed by full TLB invalidation and barriers.
    unsafe {
        core::arch::asm!(
            "mcr p15, 0, {ttbr}, c2, c0, 0",
            "mcr p15, 0, {zero}, c8, c7, 0",  // TLBIALL
            "dsb sy",
            "isb sy",
            ttbr = in(reg) (u32::try_from(table_phys).unwrap_or_default()) | 0x6B,
            zero = in(reg) 0u32,
        );
    }
}

/// No-op stub for non-ARM builds so process.rs compiles on the host.
#[cfg(not(target_arch = "arm"))]
pub unsafe fn switch_addr_space(_table_phys: usize) {}

/// Reset the address space pool (test helper only).
#[cfg(test)]
pub(crate) fn reset_addr_space_pool() {
    unsafe {
        core::ptr::write_volatile(core::ptr::addr_of_mut!(ADDR_SPACE_ALLOC), 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reset() {
        reset_addr_space_pool();
    }

    #[test]
    fn dcache_line_bytes_from_ctr_decodes_word_count_to_bytes() {
        // Cortex-A7: DminLine = 4 -> 16 words -> 64 bytes.
        assert_eq!(dcache_line_bytes_from_ctr(4), 64);
        // DminLine = 3 -> 8 words -> 32 bytes (another common ARMv7 line size).
        assert_eq!(dcache_line_bytes_from_ctr(3), 32);
    }

    #[test]
    fn icache_line_range_covers_a_line_aligned_exact_span() {
        assert_eq!(icache_line_range(0x1000, 64, 32), (0x1000, 2));
    }

    #[test]
    fn icache_line_range_rounds_up_for_a_trailing_partial_line() {
        // #498: 33 bytes starting at a line boundary spills one byte into a
        // second cache line -- a floor-only end computation would report
        // just one line and leave that trailing byte's line un-cleaned,
        // reproducing the exact staleness this function exists to prevent.
        assert_eq!(icache_line_range(0x1000, 33, 32), (0x1000, 2));
    }

    #[test]
    fn icache_line_range_rounds_down_for_a_mid_line_start() {
        // A mid-line va must still walk from the START of that line, not
        // from va itself, or the leading bytes of the line never get
        // cleaned.
        assert_eq!(icache_line_range(0x1004, 28, 32), (0x1000, 1));
    }

    #[test]
    fn icache_line_range_empty_range_visits_no_lines() {
        assert_eq!(icache_line_range(0x2000, 0, 32), (0x2000, 0));
    }

    #[test]
    fn prot_to_l2_flags_denies_write_plus_exec_wx_combo() {
        // SECURITY (finding 19, W^X / #417): PROT_WRITE | PROT_EXEC must
        // never yield a page that is both writable and executable -- the
        // direct code-injection primitive (write shellcode, then execute
        // it from the same mapping). Neither sys_mmap nor sys_mprotect
        // perform their own WX check before calling prot_to_l2_flags, so
        // this function is the sole enforcement point.
        let attrs = prot_to_l2_flags(prot::PROT_READ | prot::PROT_WRITE | prot::PROT_EXEC);
        assert_eq!(
            attrs & page_flags::AP_FULL,
            page_flags::AP_FULL,
            "write access must still be granted"
        );
        assert_eq!(
            attrs & page_flags::XN,
            page_flags::XN,
            "exec must be stripped (XN set) when write is also requested"
        );
    }

    #[test]
    fn prot_to_l2_flags_allows_exec_without_write() {
        // A read+exec-only mapping (no write) is not a WX page and must
        // remain executable.
        let attrs = prot_to_l2_flags(prot::PROT_READ | prot::PROT_EXEC);
        assert_eq!(
            attrs & page_flags::XN,
            0,
            "read+exec without write must remain executable"
        );
    }

    #[test]
    fn alloc_addr_space_gives_different_addresses() {
        reset();
        let a = alloc_addr_space().unwrap_or_default();
        let b = alloc_addr_space().unwrap_or_default();
        assert_ne!(a, b, "two allocations must return distinct table addresses");
        // cleanup
        unsafe {
            free_addr_space(a);
            free_addr_space(b);
        }
    }

    #[test]
    fn alloc_addr_space_pool_exhaustion() {
        reset();
        let mut addrs = [0usize; 16];
        for slot in &mut addrs {
            *slot = alloc_addr_space().unwrap_or_default();
        }
        let overflow = alloc_addr_space();
        assert!(overflow.is_none(), "17th allocation must return None");
        for addr in &addrs {
            unsafe {
                free_addr_space(*addr);
            }
        }
    }

    #[test]
    fn free_addr_space_allows_reuse() {
        reset();
        let a = alloc_addr_space().unwrap_or_default();
        unsafe {
            free_addr_space(a);
        }
        let b = alloc_addr_space().unwrap_or_default();
        // WHY: slot 0 freed then reallocated  -  must come back at the same address.
        assert_eq!(a, b, "freed slot must be reused");
        unsafe {
            free_addr_space(b);
        }
    }

    #[test]
    fn clone_addr_space_is_independent() {
        reset();
        let src = alloc_addr_space().unwrap_or_default();
        let dst = alloc_addr_space().unwrap_or_default();
        // Write a sentinel value INTO src entry 42
        unsafe {
            (src as *mut u32).add(42).write(0xDEAD_BEEF);
            clone_addr_space(src, dst);
            // Verify dst received the sentinel
            assert_eq!((dst as *const u32).add(42).read(), 0xDEAD_BEEF);
            // Modify src after clone  -  dst must be unaffected
            (src as *mut u32).add(42).write(0x1234_5678);
            assert_eq!(
                (dst as *const u32).add(42).read(),
                0xDEAD_BEEF,
                "dst must be independent after clone"
            );
            free_addr_space(src);
            free_addr_space(dst);
        }
    }

    /// #225/#226: read_l2_phys must return the mapped frame while the page is
    /// mapped, and None once unmap_page has cleared the entry.
    #[test]
    fn read_l2_phys_returns_mapped_frame_and_none_after_unmap() {
        reset();
        let l1 = alloc_addr_space().unwrap_or_default();
        let virt = 0x2000_0000usize;
        let phys = 0x5000_0000usize;
        let attrs = page_flags::SMALL_PAGE | page_flags::AP_FULL;
        unsafe {
            assert!(map_page(l1, virt, phys, attrs), "map_page must succeed");
            assert_eq!(
                read_l2_phys(l1, virt),
                Some(phys),
                "read_l2_phys must return the mapped physical frame"
            );
            unmap_page(l1, virt);
            assert_eq!(
                read_l2_phys(l1, virt),
                None,
                "read_l2_phys must return None after unmap_page clears the entry"
            );
            free_addr_space(l1);
        }
    }

    // -----------------------------------------------------------------------
    // #323: kernel/device sections must be PL1-only
    // -----------------------------------------------------------------------

    #[test]
    fn kernel_sections_are_pl1_only_not_ap_full() {
        // Regression test for #323: AP[2:0] for every identity-mapped kernel
        // RAM / device / modem section must be 0b001 (PL1 R/W, PL0 no
        // access), never 0b011 (AP_FULL, PL0 R/W). The L1 table is plain
        // memory -- populating it involves no ARM CPU instructions -- so
        // this is host-testable even though the actual privilege-fault
        // enforcement is ARM-only.
        unsafe {
            init_and_enable();
            let table = &*core::ptr::addr_of!(L1);
            // One section from each identity-mapped region: boot ROM/SRAM,
            // peripheral MMIO, modem/CCCI, and DRAM (first and last MB).
            for &mb in &[0x000usize, 0x100, 0x200, 0x400, 0x7FF] {
                let entry = table.entries[mb];
                assert_eq!(
                    entry & 0b11,
                    flags::SECTION,
                    "section {mb:#x} must be a section descriptor"
                );
                let ap = (entry >> 10) & 0b11;
                let apx = (entry >> 15) & 0b1;
                assert_eq!(
                    (apx, ap),
                    (0, 0b01),
                    "section {mb:#x} must be AP[2:0]=001 (PL1-only R/W); PL0 must have zero access"
                );
            }
        }
    }

    #[test]
    fn cloned_user_table_still_denies_pl0_access_to_kernel_sections() {
        // #323's clone_addr_space interaction: fork() copies the kernel L1
        // verbatim into each per-process table, so the PL1-only fix must
        // hold in the CLONED copy too, not just the primary kernel table.
        reset();
        unsafe {
            init_and_enable();
            let dst = alloc_addr_space().unwrap_or_default();
            clone_addr_space(table_base(), dst);
            let dst_l1 = dst as *const u32;
            for &mb in &[0x100usize, 0x400] {
                let entry = dst_l1.add(mb).read_volatile();
                let ap = (entry >> 10) & 0b11;
                let apx = (entry >> 15) & 0b1;
                assert_eq!(
                    (apx, ap),
                    (0, 0b01),
                    "cloned user table section {mb:#x} must still deny PL0 access"
                );
            }
            free_addr_space(dst);
        }
    }

    // -----------------------------------------------------------------------
    // #330: L2 page table reclaim
    // -----------------------------------------------------------------------

    #[test]
    fn unmap_reclaims_l2_table_once_fully_empty() {
        reset();
        reset_l2_pool();
        let l1 = alloc_addr_space().unwrap_or_default();
        let virt = 0x1000_0000usize;
        let phys = 0x5000_0000usize;
        let attrs = page_flags::SMALL_PAGE | page_flags::AP_FULL;
        unsafe {
            assert!(map_page(l1, virt, phys, attrs), "map_page must succeed");
            let l1_index = virt >> 20;
            let l1_val = (l1 as *const u32).add(l1_index).read_volatile();
            assert_eq!(
                l1_val & 0b11,
                page_flags::L1_PAGE_TABLE,
                "L1 entry must point at an L2 table after map_page"
            );

            unmap_page(l1, virt);

            let l1_val_after = (l1 as *const u32).add(l1_index).read_volatile();
            assert_eq!(
                l1_val_after, 0,
                "L1 descriptor must be cleared once its only L2 entry is unmapped (#330)"
            );

            free_addr_space(l1);
        }
    }

    #[test]
    fn sparse_map_unmap_over_more_than_pool_size_regions_does_not_exhaust_l2_pool() {
        // Regression test for #330: before the fix, unmap_page never called
        // free_l2_table, so touching more than L2_POOL_SIZE distinct 1 MB
        // regions permanently exhausted the global pool even though every
        // region was unmapped before moving to the next.
        reset();
        reset_l2_pool();
        let l1 = alloc_addr_space().unwrap_or_default();
        let attrs = page_flags::SMALL_PAGE | page_flags::AP_FULL;
        let phys = 0x5000_0000usize;
        unsafe {
            for region in 0..(L2_POOL_SIZE * 2) {
                let virt = region << 20; // one distinct 1 MB region per iteration
                assert!(
                    map_page(l1, virt, phys, attrs),
                    "map must succeed in region {region} -- pool must not be exhausted by prior, already-unmapped regions"
                );
                unmap_page(l1, virt);
            }

            // The pool must be back to fully available: every slot can be
            // claimed fresh.
            let mut reclaimed = [0usize; L2_POOL_SIZE];
            for slot in reclaimed.iter_mut() {
                *slot = alloc_l2_table()
                    .expect("L2 pool must be fully reclaimed after every region was unmapped");
            }
            for &addr in &reclaimed {
                free_l2_table(addr);
            }

            free_addr_space(l1);
        }
    }

    #[test]
    fn free_addr_space_reclaims_l2_tables_left_mapped_at_exit() {
        // #330's other reclaim path: a process that exits WITHOUT calling
        // munmap on its own mappings must not strand their L2 tables
        // forever -- free_addr_space must walk the L1 and reclaim them.
        reset();
        reset_l2_pool();
        let l1 = alloc_addr_space().unwrap_or_default();
        let attrs = page_flags::SMALL_PAGE | page_flags::AP_FULL;
        let phys = 0x5000_0000usize;
        unsafe {
            for region in 0..L2_POOL_SIZE {
                let virt = region << 20;
                assert!(
                    map_page(l1, virt, phys, attrs),
                    "map must succeed in region {region}"
                );
            }
            // Every pool slot is now live and still mapped (no unmap_page
            // calls) -- exactly the "process exits with mappings still up"
            // case.
            assert!(
                alloc_l2_table().is_none(),
                "pool must be fully consumed by the L2_POOL_SIZE live regions"
            );

            free_addr_space(l1);

            // free_addr_space must have walked the L1 and reclaimed every
            // still-referenced L2 table.
            let mut reclaimed = [0usize; L2_POOL_SIZE];
            for slot in reclaimed.iter_mut() {
                *slot = alloc_l2_table()
                    .expect("free_addr_space must reclaim L2 tables left mapped at process exit");
            }
            for &addr in &reclaimed {
                free_l2_table(addr);
            }
        }
    }

    // -----------------------------------------------------------------------
    // #416: IRQ-safe locking for L2_ALLOC / ADDR_SPACE_ALLOC pools
    // -----------------------------------------------------------------------
    //
    // WHY these tests exercise L2_POOL_LOCK/ADDR_SPACE_LOCK directly rather
    // than going through alloc_l2_table()/alloc_addr_space(): the masking
    // contract is independent of pool state, so it is testable in isolation
    // the same way page.rs's #331 PAGE_LOCK tests are (see that file).

    #[test]
    fn l2_pool_lock_masks_irqs_for_the_critical_section() {
        // Regression test for #416: L2_ALLOC mutations must run inside an
        // IRQ-masked critical section shared by every caller -- alloc_l2_table
        // AND free_l2_table -- or an IRQ-context caller can interleave with a
        // non-locked in-progress caller and double-allocate the same L2 pool
        // slot (same defect class as #331). Host-testable via the mock
        // IRQ-state seam in `irq`.
        crate::irq::reset_mock();
        assert!(crate::irq::mock_enabled(), "starts unmasked");
        let guard = L2_POOL_LOCK.lock();
        assert!(
            !crate::irq::mock_enabled(),
            "L2_POOL_LOCK.lock() must mask IRQ delivery while held"
        );
        drop(guard);
        assert!(
            crate::irq::mock_enabled(),
            "dropping the guard must restore IRQ delivery"
        );
    }

    #[test]
    fn nested_irq_guard_does_not_unmask_while_l2_pool_lock_held() {
        crate::irq::reset_mock();
        let outer = L2_POOL_LOCK.lock();
        assert!(!crate::irq::mock_enabled());
        let inner = crate::irq::IrqGuard::new();
        assert!(!crate::irq::mock_enabled());
        drop(inner);
        assert!(
            !crate::irq::mock_enabled(),
            "inner drop must not unmask while L2_POOL_LOCK is still held"
        );
        drop(outer);
        assert!(
            crate::irq::mock_enabled(),
            "outer drop restores IRQ delivery"
        );
    }

    #[test]
    fn addr_space_lock_masks_irqs_for_the_critical_section() {
        // Regression test for #416: ADDR_SPACE_ALLOC mutations must run
        // inside an IRQ-masked critical section shared by every caller --
        // alloc_addr_space AND free_addr_space -- or an IRQ-context caller
        // can interleave with a non-locked in-progress caller and
        // double-allocate the same address-space slot.
        crate::irq::reset_mock();
        assert!(crate::irq::mock_enabled(), "starts unmasked");
        let guard = ADDR_SPACE_LOCK.lock();
        assert!(
            !crate::irq::mock_enabled(),
            "ADDR_SPACE_LOCK.lock() must mask IRQ delivery while held"
        );
        drop(guard);
        assert!(
            crate::irq::mock_enabled(),
            "dropping the guard must restore IRQ delivery"
        );
    }

    #[test]
    fn nested_irq_guard_does_not_unmask_while_addr_space_lock_held() {
        crate::irq::reset_mock();
        let outer = ADDR_SPACE_LOCK.lock();
        assert!(!crate::irq::mock_enabled());
        let inner = crate::irq::IrqGuard::new();
        assert!(!crate::irq::mock_enabled());
        drop(inner);
        assert!(
            !crate::irq::mock_enabled(),
            "inner drop must not unmask while ADDR_SPACE_LOCK is still held"
        );
        drop(outer);
        assert!(
            crate::irq::mock_enabled(),
            "outer drop restores IRQ delivery"
        );
    }

    #[test]
    fn prot_to_l2_flags_translates_the_non_wx_permission_combinations() {
        // Done-when (finding 35): batch-1 added the W^X-specific cases
        // (write+exec denial, exec-without-write). This covers every
        // remaining POSIX-to-ARM AP/XN translation those didn't:
        // read-only, read+write (no exec), no permissions at all, and
        // exec-only (no read/write).
        let ap_mask = page_flags::AP_FULL | page_flags::AP_READ_ONLY | page_flags::AP_KERNEL_ONLY;

        // Read-only: AP_READ_ONLY, not executable (no PROT_EXEC requested).
        let ro = prot_to_l2_flags(prot::PROT_READ);
        assert_eq!(
            ro & ap_mask,
            page_flags::AP_READ_ONLY,
            "read-only must set AP_READ_ONLY"
        );
        assert_eq!(
            ro & page_flags::XN,
            page_flags::XN,
            "read-only (no exec) must set XN"
        );

        // Read+write, no exec: AP_FULL, XN set (write forces XN regardless).
        let rw = prot_to_l2_flags(prot::PROT_READ | prot::PROT_WRITE);
        assert_eq!(
            rw & page_flags::AP_FULL,
            page_flags::AP_FULL,
            "read+write must set AP_FULL"
        );
        assert_eq!(
            rw & page_flags::XN,
            page_flags::XN,
            "write without exec must still set XN"
        );

        // No permissions requested at all: AP_KERNEL_ONLY (no PL0 access), XN set.
        let none = prot_to_l2_flags(0);
        assert_eq!(
            none & ap_mask,
            page_flags::AP_KERNEL_ONLY,
            "no permissions must set AP_KERNEL_ONLY"
        );
        assert_eq!(
            none & page_flags::XN,
            page_flags::XN,
            "no permissions must set XN"
        );

        // Exec-only (no read, no write requested): AP_KERNEL_ONLY (neither
        // write nor read branch taken), but XN must NOT be set since exec
        // was requested and write was not.
        let exec_only = prot_to_l2_flags(prot::PROT_EXEC);
        assert_eq!(
            exec_only & ap_mask,
            page_flags::AP_KERNEL_ONLY,
            "exec-only (no read/write) must set AP_KERNEL_ONLY"
        );
        assert_eq!(
            exec_only & page_flags::XN,
            0,
            "exec-only must remain executable (XN unset)"
        );
    }

    #[test]
    fn map_page_fails_closed_when_l2_pool_is_exhausted() {
        // Done-when (finding 36): if alloc_l2_table() cannot supply a new
        // L2 table (pool exhausted), map_page must fail closed (return
        // false), not silently install a partial/garbage mapping.
        reset();
        reset_l2_pool();
        let l1 = alloc_addr_space().unwrap_or_default();
        let attrs = page_flags::SMALL_PAGE | page_flags::AP_FULL;
        unsafe {
            // Exhaust the L2 pool by mapping L2_POOL_SIZE distinct 1 MB
            // regions (each consumes one pool slot) without ever
            // unmapping. Region 0 is deliberately skipped so it can be
            // used below as the "one more" attempt after exhaustion.
            for region in 0..L2_POOL_SIZE {
                let virt = (region + 1) << 20;
                assert!(
                    map_page(l1, virt, 0x5000_0000, attrs),
                    "map must succeed while the pool still has capacity"
                );
            }
            assert!(alloc_l2_table().is_none(), "pool must be fully exhausted");

            let virt_new = 0usize; // region 0, not yet touched above
            assert!(
                !map_page(l1, virt_new, 0x5000_0000, attrs),
                "map_page must fail closed (false) when the L2 pool is exhausted"
            );

            free_addr_space(l1);
        }
    }

    #[test]
    fn map_page_fails_closed_over_an_existing_section_mapping() {
        // A virtual address already covered by an L1 SECTION descriptor
        // (1 MB granularity, e.g. the kernel identity map) must never be
        // overlaid with a page-granularity mapping -- map_page must
        // refuse, not corrupt the L1 entry.
        reset();
        unsafe {
            init_and_enable(); // populates the kernel L1 with SECTION descriptors
            let table_phys = table_base();
            // 0x400 MB is the start of the DRAM identity-mapped region:
            // a SECTION descriptor, not a page table.
            let virt = 0x400usize << 20;
            let attrs = page_flags::SMALL_PAGE | page_flags::AP_FULL;
            assert!(
                !map_page(table_phys, virt, 0x5000_0000, attrs),
                "map_page must fail closed over an existing section mapping"
            );
        }
    }

    #[test]
    fn shatter_populates_all_256_kernel_default_entries() {
        // #482 INVARIANT (the load-bearing regression): shatter converts a
        // SECTION to a FULLY POPULATED identity L2 -- ALL 256 entries =
        // KERNEL_DEFAULT_PAGE (PL1-RW, PL0-none, XN). A sparse shatter would
        // lock up the kernel mid-syscall on a neighbor-page access.
        reset();
        unsafe {
            init_and_enable();
            let dst = alloc_addr_space().unwrap();
            clone_addr_space(table_base(), dst);
            let mb = 0x503usize << 20; // a DRAM section MB in the clone
            assert!(
                shatter_section(dst, mb),
                "shatter of a DRAM section must succeed"
            );
            for i in 0..256usize {
                let va = mb + i * 0x1000;
                let entry = read_l2_entry(dst, va).expect("every entry must exist");
                assert_eq!(
                    entry,
                    (va as u32) | KERNEL_DEFAULT_PAGE,
                    "entry {i} must be identity KERNEL_DEFAULT_PAGE"
                );
                assert_eq!(
                    entry & (0b11 << 4),
                    page_flags::AP_KERNEL_ONLY,
                    "AP must be PL1-only"
                );
                assert_eq!(entry & (1 << 9), 0, "APX must be 0");
                assert_ne!(entry & page_flags::XN, 0, "XN must be set");
            }
            free_addr_space(dst);
        }
    }

    #[test]
    fn shatter_is_idempotent_and_map_page_grants_pl0_over_shattered_mb() {
        reset();
        unsafe {
            init_and_enable();
            let dst = alloc_addr_space().unwrap();
            clone_addr_space(table_base(), dst);
            let mb = 0x503usize << 20;
            assert!(shatter_section(dst, mb));
            // A shattered MB is a page table, so map_page can now overlay a
            // user grant (it refused when the MB was a section).
            let user_page = mb + 5 * 0x1000;
            let user_attrs = prot_to_l2_flags(prot::PROT_READ | prot::PROT_WRITE);
            assert!(
                map_page(dst, user_page, user_page, user_attrs),
                "map_page must overlay a shattered MB"
            );
            // Re-shatter is idempotent and must NOT wipe the user grant.
            assert!(shatter_section(dst, mb), "re-shatter is idempotent");
            assert_eq!(
                read_l2_entry(dst, user_page).unwrap(),
                (user_page as u32) | user_attrs,
                "the user grant must survive a re-shatter"
            );
            free_addr_space(dst);
        }
    }

    #[test]
    fn ensure_page_mappable_shatters_a_section_and_tolerates_an_absent_entry() {
        // #496: sys_mmap maps into a window the identity map covers with a 1 MB
        // SECTION, and map_page refuses to overlay a section -- so mmap failed on
        // every REAL table (it only ever worked against synthetic host tables
        // whose L1 entries are absent). ensure_page_mappable is that missing step.
        // Unlike shatter_section it treats an ABSENT entry as success, because
        // map_page allocates the L2 itself in that case.
        reset();
        unsafe {
            init_and_enable();
            let dst = alloc_addr_space().unwrap();
            clone_addr_space(table_base(), dst);
            let attrs = prot_to_l2_flags(prot::PROT_READ);

            // A cloned identity MB is a SECTION -> shattered, then mappable.
            let section_mb = 0x505usize << 20;
            assert!(
                ensure_page_mappable(dst, section_mb),
                "a section must be shattered"
            );
            let page = section_mb + 3 * 0x1000;
            assert!(
                map_page(dst, page, page, attrs),
                "map_page must overlay the now-shattered MB"
            );
            // Idempotent: the MB is a page table now, and the grant survives.
            assert!(
                ensure_page_mappable(dst, section_mb),
                "an already-shattered MB is a no-op"
            );
            assert_eq!(
                read_l2_entry(dst, page).unwrap(),
                (page as u32) | attrs,
                "the user grant must survive"
            );

            // An ABSENT L1 entry is not an error -- map_page allocates the L2.
            let absent_mb = 0x900usize << 20;
            (dst as *mut u32).add(absent_mb >> 20).write_volatile(0);
            assert!(
                ensure_page_mappable(dst, absent_mb),
                "an absent entry is not an error"
            );
            assert!(
                map_page(dst, absent_mb, absent_mb, attrs),
                "map_page allocates the L2 for an absent entry"
            );
            free_addr_space(dst);
        }
    }

    #[test]
    fn user_page_attrs_grant_pl0_and_are_write_xor_execute() {
        // #482: user segment permissions via prot_to_l2_flags -- text RX,
        // rodata RO+XN, data/stack RW+XN; W|X degrades to RW+XN (W^X); and each
        // user attr grants PL0 (AP[1:0] in {0b10, 0b11}) while KERNEL_DEFAULT
        // denies it (AP[1:0]=0b01).
        let text = prot_to_l2_flags(prot::PROT_READ | prot::PROT_EXEC);
        let rodata = prot_to_l2_flags(prot::PROT_READ);
        let data = prot_to_l2_flags(prot::PROT_READ | prot::PROT_WRITE);
        let wx = prot_to_l2_flags(prot::PROT_READ | prot::PROT_WRITE | prot::PROT_EXEC);
        assert_eq!(text & page_flags::XN, 0, "text must be executable");
        assert_ne!(rodata & page_flags::XN, 0, "rodata must be execute-never");
        assert_ne!(data & page_flags::XN, 0, "data must be execute-never");
        assert_eq!(wx, data, "W|X must degrade to RW+XN (W^X)");
        assert_eq!(
            KERNEL_DEFAULT_PAGE & (0b11 << 4),
            page_flags::AP_KERNEL_ONLY
        );
        for a in [text, rodata, data] {
            let ap = (a >> 4) & 0b11;
            assert!(
                ap == 0b10 || ap == 0b11,
                "user page must grant PL0 (ap={ap:#b})"
            );
        }
    }

    #[test]
    fn update_page_prot_fails_closed_when_no_l2_table_is_installed() {
        // Done-when (finding 36): update_page_prot on a virtual address
        // whose L1 index has never had an L2 table installed must fail
        // closed. No existing test calls update_page_prot at all.
        reset();
        let l1 = alloc_addr_space().unwrap_or_default();
        unsafe {
            let virt = 0x3000_0000usize;
            assert!(
                !update_page_prot(l1, virt, page_flags::SMALL_PAGE | page_flags::AP_READ_ONLY),
                "update_page_prot must fail closed when no L2 table is installed"
            );
            free_addr_space(l1);
        }
    }

    #[test]
    fn update_page_prot_fails_closed_on_an_unmapped_page_within_an_installed_l2_table() {
        // An L2 table can be installed (via a sibling mapping in the same
        // 1 MB region) while the SPECIFIC page being updated is still
        // unmapped -- update_page_prot must fail closed for that page too.
        reset();
        reset_l2_pool();
        let l1 = alloc_addr_space().unwrap_or_default();
        let attrs = page_flags::SMALL_PAGE | page_flags::AP_FULL;
        unsafe {
            let mapped_virt = 0x2000_0000usize;
            let unmapped_virt = mapped_virt + 0x1000; // same 1 MB region, next page
            assert!(map_page(l1, mapped_virt, 0x5000_0000, attrs));

            assert!(
                !update_page_prot(
                    l1,
                    unmapped_virt,
                    page_flags::SMALL_PAGE | page_flags::AP_READ_ONLY
                ),
                "update_page_prot must fail closed on an unmapped page even though the L2 table exists"
            );

            free_addr_space(l1);
        }
    }

    #[test]
    fn update_page_prot_succeeds_and_preserves_the_physical_frame() {
        // Success path: update_page_prot must change only the attribute
        // bits, never the physical frame address.
        reset();
        reset_l2_pool();
        let l1 = alloc_addr_space().unwrap_or_default();
        let virt = 0x2100_0000usize;
        let phys = 0x5000_0000usize;
        unsafe {
            assert!(map_page(
                l1,
                virt,
                phys,
                page_flags::SMALL_PAGE | page_flags::AP_FULL
            ));
            assert!(update_page_prot(
                l1,
                virt,
                page_flags::SMALL_PAGE | page_flags::AP_READ_ONLY
            ));
            assert_eq!(
                read_l2_phys(l1, virt),
                Some(phys),
                "update_page_prot must preserve the mapped physical frame"
            );
            free_addr_space(l1);
        }
    }

    #[test]
    fn alloc_l2_table_pool_exhaustion_and_reuse() {
        // Done-when (finding 37): the L2 table pool's OWN
        // allocate/exhaust/free/reuse cycle, exercised directly via
        // alloc_l2_table/free_l2_table -- mirroring the dedicated
        // alloc_addr_space_pool_exhaustion / free_addr_space_allows_reuse
        // coverage that already exists for the address-space pool; the L2
        // pool itself only ever received this exercise INDIRECTLY (via
        // map_page/unmap_page) until now.
        reset_l2_pool();
        let mut addrs = [0usize; L2_POOL_SIZE];
        for slot in &mut addrs {
            *slot = alloc_l2_table().expect("pool must have capacity for L2_POOL_SIZE allocations");
        }

        let overflow = alloc_l2_table();
        assert!(
            overflow.is_none(),
            "the (L2_POOL_SIZE + 1)th allocation must return None"
        );

        // Free one slot and confirm it becomes available for reuse at the
        // SAME address.
        let freed = addrs[0];
        assert!(
            unsafe { free_l2_table(freed) },
            "freeing a previously allocated slot must report true"
        );
        let reused = alloc_l2_table().expect("freed slot must be available for reuse");
        assert_eq!(
            reused, freed,
            "reused allocation must return the just-freed address"
        );

        // Clean up the rest.
        for &addr in addrs.iter().skip(1) {
            unsafe {
                free_l2_table(addr);
            }
        }
        unsafe {
            free_l2_table(reused);
        }
    }

    #[test]
    fn wx_page_attrs_is_write_xor_execute() {
        // Synthetic page-aligned image bounds within the kernel 1 MB region.
        let (text_start, etext, erodata) = (0x4000_8000usize, 0x4004_0000, 0x4005_0000);
        let is_xn = |a: u32| a & page_flags::XN != 0;

        // .text: executable (not XN) and read-only (AP_KERNEL_RO exactly).
        let text = wx_page_attrs(0x4000_8000, text_start, etext, erodata);
        assert!(!is_xn(text), ".text must be executable");
        assert_eq!(text, page_flags::AP_KERNEL_RO, ".text must be read-only");

        // .rodata: read-only + execute-never.
        let ro = wx_page_attrs(0x4004_2000, text_start, etext, erodata);
        assert_eq!(ro, page_flags::AP_KERNEL_RO | page_flags::XN);

        // pre-image gap, and everything at/after erodata: writable + XN.
        for va in [0x4000_0000usize, 0x4005_0000, 0x400F_F000] {
            let data = wx_page_attrs(va, text_start, etext, erodata);
            assert_eq!(data, page_flags::AP_KERNEL_ONLY | page_flags::XN);
        }

        // INVARIANT across the whole 1 MB region: an executable page is never
        // writable (W^X). Only .text is executable, and it is read-only.
        for i in 0..256usize {
            let va = 0x4000_0000 + i * 4096;
            let a = wx_page_attrs(va, text_start, etext, erodata);
            if !is_xn(a) {
                assert_eq!(
                    a,
                    page_flags::AP_KERNEL_RO,
                    "executable page must be read-only"
                );
            }
        }
    }

    #[test]
    fn l2_entry_is_user_covers_xn_data_and_rejects_kernel_only() {
        // #478 regression: a small-page descriptor is bits[1:0]=0b1X (bit 0 =
        // XN), so an execute-never DATA/stack page is 0b11 -- NOT 0b10. The
        // enumerator must catch it, or a fork would silently skip every user
        // data/stack page (the bug this test pins).
        // User RX (.text): SMALL_PAGE | AP_READ_ONLY | NG, XN clear -> bits 0b10.
        assert!(l2_entry_is_user(
            page_flags::SMALL_PAGE | page_flags::AP_READ_ONLY | page_flags::NG
        ));
        // User RW+XN (.data/stack): SMALL_PAGE | XN | AP_FULL | NG -> bits 0b11.
        assert!(l2_entry_is_user(
            page_flags::SMALL_PAGE | page_flags::XN | page_flags::AP_FULL | page_flags::NG
        ));
        // #496: ownership is the NG tag, NOT the AP bits -- a PROT_NONE user page
        // (AP 0b01, byte-identical in AP to a kernel fill) IS user, and an
        // untagged PL0-accessible descriptor is NOT (nothing mints one).
        assert!(
            l2_entry_is_user(prot_to_l2_flags(0)),
            "PROT_NONE user page must enumerate (#496)"
        );
        assert!(
            !l2_entry_is_user(page_flags::SMALL_PAGE | page_flags::AP_FULL),
            "untagged descriptor is not user-owned"
        );
        // Real attrs from prot_to_l2_flags must all count as user.
        for prot in [
            prot::PROT_READ | prot::PROT_EXEC,
            prot::PROT_READ,
            prot::PROT_READ | prot::PROT_WRITE,
            prot::PROT_EXEC,
            0,
        ] {
            assert!(l2_entry_is_user(prot_to_l2_flags(prot)), "prot {prot:#x}");
        }
        // Kernel-only (PL1 RW, PL0 none) and the shatter default: NOT user.
        assert!(!l2_entry_is_user(
            page_flags::SMALL_PAGE | page_flags::XN | page_flags::AP_KERNEL_ONLY
        ));
        assert!(!l2_entry_is_user(KERNEL_DEFAULT_PAGE));
        // Large page (0b01) and fault (0b00): not small pages -> NOT user.
        assert!(!l2_entry_is_user(0b01 | page_flags::AP_FULL));
        assert!(!l2_entry_is_user(0));
    }

    #[test]
    fn for_each_user_page_visits_user_pages_and_skips_kernel_only() {
        // #478: enumerate exactly the PL0-accessible pages of a table.
        reset();
        unsafe {
            init_and_enable();
            let pt = alloc_addr_space().unwrap();
            clone_addr_space(table_base(), pt);
            let mb = 0x503usize << 20;
            assert!(shatter_section(pt, mb)); // fills 256 KERNEL_DEFAULT (PL1-only)
            let user_va = mb + 7 * 0x1000;
            assert!(map_page(
                pt,
                user_va,
                user_va,
                prot_to_l2_flags(prot::PROT_READ | prot::PROT_WRITE)
            ));

            let mut visited = alloc::vec::Vec::new();
            for_each_user_page(pt, |va, phys, _attrs| {
                visited.push((va, phys));
                true
            });
            assert_eq!(
                visited,
                alloc::vec![(user_va, user_va)],
                "only the one granted user page is visited; the 255 KERNEL_DEFAULT entries are skipped"
            );
            free_addr_space(pt);
        }
    }
}
