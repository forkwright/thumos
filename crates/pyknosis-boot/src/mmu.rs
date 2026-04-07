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

/// L1 page table: 4096 entries x 4 bytes = 16 KB.
/// Must be 16 KB aligned.
#[repr(C, align(16384))]
pub struct L1Table {
    entries: [u32; 4096],
}

/// Global L1 page table.
static mut L1: L1Table = L1Table { entries: [0; 4096] };

/// Section descriptor flags (1 MB mapping).
mod flags {
    /// This is a section descriptor (bits [1:0] = 0b10).
    pub const SECTION: u32 = 0b10;
    /// Access permission: full access (AP = 0b11, bits [11:10]).
    pub const AP_FULL: u32 = 0b11 << 10;
    /// Shareable (bit 16).
    pub const SHAREABLE: u32 = 1 << 16;
    /// Normal memory, OUTER/INNER write-back write-allocate.
    /// TEX[2:0] = 0b001, C = 1, B = 1 (bits [14:12], [3], [2]).
    pub const NORMAL_WB_WA: u32 = (0b001 << 12) | (1 << 3) | (1 << 2);
    /// Device memory, strongly ordered.
    /// TEX[2:0] = 0b000, C = 0, B = 1 (for device/shared).
    pub const DEVICE: u32 = (1 << 2);
    /// Execute never (XN, bit 4).
    pub const XN: u32 = 1 << 4;
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
        MemoryType::Ram => flags::SECTION | flags::AP_FULL | flags::SHAREABLE | flags::NORMAL_WB_WA,
        MemoryType::Device => flags::SECTION | flags::AP_FULL | flags::DEVICE | flags::XN,
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
    // Clear the table
    let table = &mut *core::ptr::addr_of_mut!(L1);
    for entry in table.entries.iter_mut() {
        *entry = 0; // SAFETY: fault on access to unmapped regions
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

    // Set TTBR0 to our page table
    let ttbr0 = core::ptr::addr_of!(L1) as u32;
    // SAFETY: writing CP15 registers during MMU init
    core::arch::asm!(
        "mcr p15, 0, {ttbr}, c2, c0, 0",  // TTBR0
        ttbr = in(reg) ttbr0 | 0x6B,       // NOTE: INNER/OUTER WB-WA cacheable, shareable
    );

    // TTBCR: use TTBR0 for all addresses (N = 0)
    core::arch::asm!(
        "mcr p15, 0, {val}, c2, c0, 2",
        val = in(reg) 0u32,
    );

    // DACR: domain 0 = client (check permissions)
    core::arch::asm!(
        "mcr p15, 0, {val}, c3, c0, 0",
        val = in(reg) 1u32,  // NOTE: domain 0 = client access
    );

    // Invalidate TLB
    core::arch::asm!(
        "mcr p15, 0, {zero}, c8, c7, 0",  // TLBIALL
        zero = in(reg) 0u32,
    );

    // Data synchronization barrier
    core::arch::asm!("dsb sy");

    // Enable MMU (SCTLR bit 0) + caches (bit 2 = D-cache, bit 12 = I-cache)
    let mut sctlr: u32;
    core::arch::asm!(
        "mrc p15, 0, {val}, c1, c0, 0",
        val = out(reg) sctlr,
    );
    sctlr |= 1 << 0; // M: MMU enable
    sctlr |= 1 << 2; // C: data cache enable
    sctlr |= 1 << 12; // I: instruction cache enable
    core::arch::asm!(
        "mcr p15, 0, {val}, c1, c0, 0",
        val = in(reg) sctlr,
    );

    // Instruction synchronization barrier
    core::arch::asm!("isb sy");
}

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

/// Allocate a free user L1 page table FROM the pool.
/// Zeroes the slot before returning its physical address.
/// Returns None if all 16 slots are occupied.
pub fn alloc_addr_space() -> Option<usize> {
    unsafe {
        let alloc = core::ptr::addr_of_mut!(ADDR_SPACE_ALLOC);
        let mask = core::ptr::read_volatile(alloc);
        // WHY: find first zero bit (free slot)
        let slot = (0u16..16).find(|&i| mask & (1 << i) == 0)?;
        core::ptr::write_volatile(alloc, mask | (1 << slot));
        let table = &mut (*core::ptr::addr_of_mut!(USER_TABLES))[usize::try_from(slot).unwrap_or_default()];
        for entry in table.entries.iter_mut() {
            *entry = 0;
        }
        Some(core::ptr::addr_of!(*table) as usize)
    }
}

/// Return a user L1 page table slot to the pool.
///
/// # Safety
///
/// `phys_addr` must have been returned by `alloc_addr_space` and not yet freed.
pub unsafe fn free_addr_space(phys_addr: usize) {
    unsafe {
        let tables = &*core::ptr::addr_of!(USER_TABLES);
        for (i, table) in tables.iter().enumerate() {
            if core::ptr::addr_of!(*table) as usize == phys_addr {
                let alloc = core::ptr::addr_of_mut!(ADDR_SPACE_ALLOC);
                let mask = core::ptr::read_volatile(alloc);
                core::ptr::write_volatile(alloc, mask & !(1 << i));
                return;
            }
        }
    }
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
    fn alloc_addr_space_gives_different_addresses() {
        reset();
        let a = alloc_addr_space().unwrap_or_default();
        let b = alloc_addr_space().unwrap_or_default();
        assert_ne!(a, b, "two allocations must return distinct table addresses");
        // cleanup
        unsafe { free_addr_space(a); free_addr_space(b); }
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
            unsafe { free_addr_space(*addr); }
        }
    }

    #[test]
    fn free_addr_space_allows_reuse() {
        reset();
        let a = alloc_addr_space().unwrap_or_default();
        unsafe { free_addr_space(a); }
        let b = alloc_addr_space().unwrap_or_default();
        // WHY: slot 0 freed then reallocated  -  must come back at the same address.
        assert_eq!(a, b, "freed slot must be reused");
        unsafe { free_addr_space(b); }
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
            assert_eq!((dst as *const u32).add(42).read(), 0xDEAD_BEEF,
                "dst must be independent after clone");
            free_addr_space(src);
            free_addr_space(dst);
        }
    }
}
