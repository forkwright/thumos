//! User-pointer memory guards shared across syscall entry points.
//!
//! Every syscall that dereferences a userspace-supplied pointer must first
//! confirm the whole buffer lies inside user-accessible DRAM. This logic lives
//! here, in an always-compiled module (not the hardware-coupled `syscall`
//! module, which is excluded from host test builds), so that pointer-taking
//! subsystems (`pipe`, `fd`, `socket`, `time`, ...) can call it and — crucially
//! — so the guard has runnable host unit tests.

use crate::board;

/// Validate that a user-supplied buffer `[ptr, ptr+len)` lies entirely
/// within user-accessible DRAM and does not overlap kernel-reserved memory.
///
/// # Memory layout (MT6739)
///
/// - `0x0000_0000 - 0x3FFF_FFFF`: device MMIO (boot ROM, peripherals, modem)
/// - `0x4000_0000 - 0x4000_7FFF`: DRAM below kernel load (reserved)
/// - `0x4000_8000 - 0x400F_FFFF`: kernel image + reserved (`KERNEL_LOAD..KERNEL_END`)
/// - `0x4010_0000 - 0x7FFF_FFFF`: user-accessible DRAM
/// - `0x8000_0000 - 0xFFFF_FFFF`: unmapped
///
/// Returns `true` if the entire buffer falls within user-accessible DRAM.
/// Returns `false` for null, overflow, kernel-space, device, or unmapped addresses.
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
    // Entire range must be within user DRAM: [KERNEL_END, RAM_END)
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
}
