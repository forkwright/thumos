//! Fault-contained user-memory access shared across syscall entry points.
//!
//! Two guards live here, and the difference between them is the whole point of
//! the module. [`validate_user_buffer`] answers a bootstrap/identity-map
//! question: does this physical range lie inside allocatable DRAM.
//! [`validate_user_range`] answers the syscall security question: may *this
//! caller* touch these virtual pages in *this direction*, according to its own
//! page tables. Syscall entry points want the second one; the first survives
//! for callers with no VAS to consult (ELF segment placement, where the target
//! is identity-mapped before any per-process table exists).
//!
//! Validation alone is insufficient: a mapping can change after the walk and
//! a PL1 load/store ignores PL0 permissions. [`copy_from_user`] and
//! [`copy_to_user`] therefore perform the actual transfer with ARM's
//! unprivileged access instructions. A data abort at either exact instruction
//! is redirected to its assembly fixup by [`fault_fixup_pc`], producing
//! [`UserAccessError`] instead of halting the kernel. Every other PL1 fault
//! retains the kernel-halt disposition.
//!
//! This logic lives here, in an always-compiled module (not the
//! hardware-coupled `syscall` module, which is excluded from host test builds),
//! so that pointer-taking subsystems (`pipe`, `fd`, `socket`, `time`, ...) can
//! call it and — crucially — so the guards have runnable host unit tests.

#[cfg(test)]
use core::sync::atomic::{AtomicBool, Ordering};

use crate::board;

/// Host-only execution-fault injection. This sits after the permission walk,
/// so rollback tests can distinguish a transfer-time failure from ordinary
/// prevalidation without pretending x86 has ARM unprivileged instructions.
#[cfg(test)]
static FAIL_NEXT_COPY_TO_USER: AtomicBool = AtomicBool::new(false);

#[cfg(test)]
pub(crate) fn fail_next_copy_to_user_for_test() {
    FAIL_NEXT_COPY_TO_USER.store(true, Ordering::Release);
}

/// A user-memory transfer could not access the complete requested range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct UserAccessError;

#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    ".section .text",
    ".arm",
    ".balign 4",
    ".global __thumos_copy_from_user",
    ".type __thumos_copy_from_user, %function",
    "__thumos_copy_from_user:",
    "    cmp     r2, #0",
    "    beq     2f",
    "1:",
    ".global __thumos_copy_from_user_fault",
    "__thumos_copy_from_user_fault:",
    // LDRBT applies PL0 permissions even though the copy runs in a privileged
    // exception mode. The exact instruction address is the recovery key.
    "    ldrbt   r3, [r1], #1",
    "    strb    r3, [r0], #1",
    "    subs    r2, r2, #1",
    "    bne     1b",
    "2:",
    "    mov     r0, #0",
    "    bx      lr",
    ".global __thumos_copy_from_user_fixup",
    "__thumos_copy_from_user_fixup:",
    "    mov     r0, #1",
    "    bx      lr",
    ".size __thumos_copy_from_user, .-__thumos_copy_from_user",
    ".balign 4",
    ".global __thumos_copy_to_user",
    ".type __thumos_copy_to_user, %function",
    "__thumos_copy_to_user:",
    "    cmp     r2, #0",
    "    beq     4f",
    "3:",
    "    ldrb    r3, [r1], #1",
    ".global __thumos_copy_to_user_fault",
    "__thumos_copy_to_user_fault:",
    // STRBT is the write-direction counterpart: PL0 write permission is
    // checked at the store itself, closing validation/dereference races.
    "    strbt   r3, [r0], #1",
    "    subs    r2, r2, #1",
    "    bne     3b",
    "4:",
    "    mov     r0, #0",
    "    bx      lr",
    ".global __thumos_copy_to_user_fixup",
    "__thumos_copy_to_user_fixup:",
    "    mov     r0, #1",
    "    bx      lr",
    ".size __thumos_copy_to_user, .-__thumos_copy_to_user",
);

#[cfg(target_arch = "arm")]
unsafe extern "C" {
    fn __thumos_copy_from_user(dst: *mut u8, src: *const u8, len: usize) -> u32;
    fn __thumos_copy_to_user(dst: *mut u8, src: *const u8, len: usize) -> u32;
    static __thumos_copy_from_user_fault: u8;
    static __thumos_copy_from_user_fixup: u8;
    static __thumos_copy_to_user_fault: u8;
    static __thumos_copy_to_user_fixup: u8;
}

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
/// - `0x4000_8000 - 0x401F_FFFF`: kernel image + reserved (`KERNEL_LOAD..KERNEL_END`)
/// - `0x4020_0000 - 0x7FFF_FFFF`: broad allocatable DRAM window
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

/// Check the address arithmetic shared by identity and virtual ranges.
fn range_is_well_formed(ptr: usize, len: usize) -> bool {
    ptr != 0 && ptr.checked_add(len).is_some()
}

/// Pure policy seam for the live-VAS/no-VAS split.
///
/// With a descriptor reader, virtual mappings are authoritative after the
/// null/overflow check. Without one, bootstrap identity-map DRAM bounds are
/// the only available authority. Keeping this seam pure pins the #890
/// modelling correction on hosts without manufacturing a live MMU.
fn validate_user_range_with(
    ptr: usize,
    len: usize,
    access: Access,
    read_desc: Option<&mut dyn FnMut(usize) -> Option<u32>>,
) -> bool {
    if !range_is_well_formed(ptr, len) {
        return false;
    }
    match read_desc {
        Some(read_desc) => range_grants(ptr, len, access, read_desc),
        None => validate_user_buffer(ptr, len),
    }
}

/// Validate that `[ptr, ptr+len)` is a legitimate user buffer for `access`.
///
/// With a live caller VAS, two independent questions are required:
///
/// 1. The address range is non-null and does not wrap.
/// 2. Every page in the range is mapped by the *calling*
///    process with PL0 permission in this direction.
///
/// The second gate is what makes this a security boundary rather than a bounds
/// check. It rejects holes, `PROT_NONE`, read-only destinations, kernel and
/// allocator identity mappings, and pages belonging to another process — none
/// of which address arithmetic can see. The VAS is authoritative even below
/// `KERNEL_END`: anonymous mappings begin at `process::MMAP_BASE`
/// (`0x2000_0000`), and #890's unconditional identity-DRAM gate incorrectly
/// made those legitimate mappings unusable as syscall buffers.
///
/// WHY the mapping gate is conditional on a user address space: it asks what
/// the caller's page tables say, and that question only has an answer while a
/// user process is current. `process::current_user_page_table` decides that
/// positively — a non-zero PID holding a table of its own, not PID 0's kernel
/// global L1 — so a PL0 caller, which by construction has such a table, cannot
/// reach the identity-DRAM fallback. PID 0/bootstrap and host fixtures without
/// a user VAS retain [`validate_user_buffer`]'s physical-range policy.
pub(crate) fn validate_user_range(ptr: usize, len: usize, access: Access) -> bool {
    let Some(l1) = crate::process::current_user_page_table() else {
        return validate_user_range_with(ptr, len, access, None);
    };
    let mut read_desc = |va| {
        // SAFETY: `l1` is a live user L1 taken from the process table, and
        // `range_grants` only ever passes page-aligned addresses.
        unsafe { crate::mmu::read_l2_entry(l1, va) }
    };
    validate_user_range_with(ptr, len, access, Some(&mut read_desc))
}

/// Copy a complete byte slice out of the calling process.
///
/// The whole range is permission-walked before the first byte is read, then
/// each ARM load is performed with PL0 permissions. The second check is what
/// closes an unmap/mprotect race between validation and dereference.
pub(crate) fn copy_from_user(src: usize, dst: &mut [u8]) -> Result<(), UserAccessError> {
    if !validate_user_range(src, dst.len(), Access::Read) {
        return Err(UserAccessError);
    }
    copy_from_user_after_validation(src, dst)
}

/// Copy a complete byte slice into the calling process.
///
/// The destination is permission-walked for PL0 write access before any byte
/// is stored. ARM then uses unprivileged stores so a stale or concurrently
/// changed descriptor becomes a contained [`UserAccessError`].
pub(crate) fn copy_to_user(dst: usize, src: &[u8]) -> Result<(), UserAccessError> {
    if !validate_user_range(dst, src.len(), Access::Write) {
        return Err(UserAccessError);
    }
    copy_to_user_after_validation(dst, src)
}

#[cfg(target_arch = "arm")]
fn copy_from_user_after_validation(src: usize, dst: &mut [u8]) -> Result<(), UserAccessError> {
    // SAFETY: the numeric and caller-VAS gates accepted the full source range;
    // the assembly routine bounds itself by dst.len() and uses LDRBT for the
    // only user-memory access. A data abort at that instruction resumes at its
    // error fixup rather than escaping this call.
    let failed =
        unsafe { __thumos_copy_from_user(dst.as_mut_ptr(), src as *const u8, dst.len()) != 0 };
    if failed { Err(UserAccessError) } else { Ok(()) }
}

#[cfg(not(target_arch = "arm"))]
fn copy_from_user_after_validation(src: usize, dst: &mut [u8]) -> Result<(), UserAccessError> {
    let Some(src_ptr) = core::ptr::NonNull::new(src as *mut u8) else {
        return Err(UserAccessError);
    };
    // SAFETY: host syscall fixtures map their backing statics with
    // process::map_user_buffer_for_test before entering this function. Host
    // CPUs have no ARM unprivileged-transfer instruction; the permission walk
    // above is the executable half of this path and QEMU covers the fixup.
    unsafe {
        core::ptr::copy_nonoverlapping(src_ptr.as_ptr().cast_const(), dst.as_mut_ptr(), dst.len());
    }
    Ok(())
}

#[cfg(target_arch = "arm")]
fn copy_to_user_after_validation(dst: usize, src: &[u8]) -> Result<(), UserAccessError> {
    // SAFETY: the numeric and caller-VAS gates accepted the full destination;
    // STRBT is the only user-memory store and its abort site has an exact
    // fixup. The ordinary source load remains privileged so a kernel-source
    // fault still takes the kernel-halt path.
    let failed = unsafe { __thumos_copy_to_user(dst as *mut u8, src.as_ptr(), src.len()) != 0 };
    if failed { Err(UserAccessError) } else { Ok(()) }
}

#[cfg(not(target_arch = "arm"))]
fn copy_to_user_after_validation(dst: usize, src: &[u8]) -> Result<(), UserAccessError> {
    let Some(dst_ptr) = core::ptr::NonNull::new(dst as *mut u8) else {
        return Err(UserAccessError);
    };
    #[cfg(test)]
    if FAIL_NEXT_COPY_TO_USER.swap(false, Ordering::AcqRel) {
        return Err(UserAccessError);
    }
    // SAFETY: same host-fixture contract as copy_from_user_after_validation;
    // ranges have already passed the caller-VAS permission walk.
    unsafe {
        core::ptr::copy_nonoverlapping(src.as_ptr(), dst_ptr.as_ptr(), src.len());
    }
    Ok(())
}

/// Return the sole legal recovery PC for a data abort at `fault_pc`.
///
/// The exception handler consults this before applying the ordinary PL1-halt
/// policy. Exact instruction equality is load-bearing: an abort in validation,
/// a kernel-side source/destination, or any unrelated code is never recovered.
#[cfg(target_arch = "arm")]
pub(crate) fn fault_fixup_pc(fault_pc: u32) -> Option<u32> {
    // These linker symbols name instructions in this image. Taking their
    // addresses reads no memory and the armv7a image is 32-bit.
    let from_fault = core::ptr::addr_of!(__thumos_copy_from_user_fault) as usize;
    let from_fixup = core::ptr::addr_of!(__thumos_copy_from_user_fixup) as usize;
    let to_fault = core::ptr::addr_of!(__thumos_copy_to_user_fault) as usize;
    let to_fixup = core::ptr::addr_of!(__thumos_copy_to_user_fixup) as usize;

    if usize::try_from(fault_pc).ok() == Some(from_fault) {
        u32::try_from(from_fixup).ok()
    } else if usize::try_from(fault_pc).ok() == Some(to_fault) {
        u32::try_from(to_fixup).ok()
    } else {
        None
    }
}

/// Non-ARM builds have no unprivileged-transfer instructions and therefore no
/// legal kernel-fault recovery site. Keeping the seam present makes host
/// clippy compile the real exception handler while preserving fail-closed
/// behavior.
#[cfg(not(target_arch = "arm"))]
pub(crate) const fn fault_fixup_pc(_fault_pc: u32) -> Option<u32> {
    None
}

/// Exercise both real data-abort fixups for the QEMU target witness.
///
/// This deliberately bypasses the preflight gate so the transfer instruction,
/// not validation, receives a PL1-only address. It is compiled only into the
/// dedicated non-production witness feature.
#[cfg(all(target_arch = "arm", feature = "uaccess-probe"))]
pub(crate) fn qemu_fault_fixup_probe() -> bool {
    let mut byte = [0u8; 1];
    let source_fault = copy_from_user_after_validation(board::KERNEL_LOAD, &mut byte).is_err();
    // Preserve the target byte if STRBT unexpectedly succeeds: the negative
    // probe must fail loudly, not corrupt the image it is using as evidence.
    // SAFETY: KERNEL_LOAD is a live privileged mapping in this kernel image.
    let original = unsafe { (board::KERNEL_LOAD as *const u8).read_volatile() };
    let destination_fault = copy_to_user_after_validation(board::KERNEL_LOAD, &[original]).is_err();
    source_fault && destination_fault
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
    fn pl0_denies_execute_only_user_page_in_both_data_directions() {
        // ARM execute permission is controlled separately from AP. The MMU's
        // sole user-descriptor funnel represents POSIX PROT_EXEC without READ
        // or WRITE as user-owned but AP_KERNEL_ONLY: executable at PL0, never
        // a legal syscall data source or destination.
        let e = prot_to_l2_flags(prot::PROT_EXEC);
        assert!(crate::mmu::l2_entry_is_user(e));
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
    fn live_vas_accepts_a_low_anonymous_mapping() {
        // #890's unconditional identity-DRAM gate rejected this address before
        // consulting the descriptor, even though mmap deliberately allocates
        // from 0x2000_0000. With a caller VAS, the user-RW L2 is authoritative.
        let mmap_base = crate::process::MMAP_BASE;
        assert!(
            mmap_base < board::KERNEL_END,
            "fixture must expose the old gate"
        );
        let mut read_desc = |_va| Some(rw_page());
        assert!(validate_user_range_with(
            mmap_base,
            PAGE,
            Access::Write,
            Some(&mut read_desc)
        ));
    }

    #[test]
    fn no_vas_retains_the_identity_dram_boundary() {
        let mmap_base = crate::process::MMAP_BASE;
        assert!(!validate_user_range_with(
            mmap_base,
            PAGE,
            Access::Read,
            None
        ));
        assert!(validate_user_range_with(
            board::KERNEL_END,
            PAGE,
            Access::Read,
            None
        ));
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
    fn validate_user_range_without_a_vas_keeps_the_identity_gate() {
        // Test binaries begin as PID 0 with no caller VAS, so the bootstrap
        // identity-DRAM policy remains authoritative on this path.
        assert!(!validate_user_range(0, 4, Access::Read));
        assert!(!validate_user_range(board::KERNEL_LOAD, 4, Access::Read));
        assert!(!validate_user_range(0x1100_2000, 4, Access::Write));
        assert!(!validate_user_range(usize::MAX, 1, Access::Read));
        assert!(!validate_user_range(board::RAM_END - 10, 20, Access::Write));
    }
}
