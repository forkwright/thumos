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
    pub(crate) const DEVICE: u32 = (1 << 2);
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
    /// Execute-never for small pages (XN, bit 0).
    pub(crate) const XN: u32 = 1;
    /// Shareable (bit 10).
    pub(crate) const SHAREABLE: u32 = 1 << 10;
    /// Normal memory for small pages: TEX[2:0]=0b001 (bits [8:6]), C=1 (bit 3), B=1 (bit 2).
    pub(crate) const NORMAL_WB_WA: u32 = (0b001 << 6) | (1 << 3) | (1 << 2);
}

/// L2 page table: 256 entries x 4 bytes = 1 KB, must be 1 KB aligned.
#[repr(C, align(1024))]
pub(crate) struct L2Table {
    pub entries: [u32; 256],
}

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
    let mut attrs = page_flags::SMALL_PAGE | page_flags::SHAREABLE | page_flags::NORMAL_WB_WA;

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

/// Map a 1 MB section in the L1 page table.
///
/// `virt_mb` and `phys_mb` are megabyte-aligned addresses divided by 1 MB.
/// For identity mapping, `virt_mb == phys_mb`.
fn map_section(virt_mb: usize, phys_mb: usize, mem_type: MemoryType) {
    let base = (u32::try_from(phys_mb).unwrap_or_default()) << 20;
    let attrs = match mem_type {
        MemoryType::Ram => {
            flags::SECTION | flags::AP_PL1_ONLY | flags::SHAREABLE | flags::NORMAL_WB_WA
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

    // DRAM: 0x4000_0000 - 0x7FFF_FFFF (1 GB)
    for mb in 0x400..0x800 {
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
    unsafe { core::ptr::addr_of!(L1) as usize }
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
/// slots (#330). Cloned kernel identity-map entries are section descriptors
/// (`flags::SECTION`, bits [1:0] = 0b10), never `page_flags::L1_PAGE_TABLE`
/// (0b01), so this walk never touches or frees the kernel's own mappings.
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
}
