//! Memory-mapped I/O primitives.
//!
//! Volatile register access for hardware drivers. These enforce that the
//! compiler does not optimize away or reorder hardware register reads/writes.

use core::ptr;

/// Read a 32-bit value from a memory-mapped register.
///
/// # Safety
///
/// The caller must ensure `addr` points to a valid MMIO register
/// that is safe to read without side effects beyond the read itself.
#[inline(always)]
pub unsafe fn read32(addr: usize) -> u32 {
    unsafe { ptr::read_volatile(addr as *const u32) }
}

/// Write a 32-bit value to a memory-mapped register.
///
/// # Safety
///
/// The caller must ensure `addr` points to a valid MMIO register.
#[inline(always)]
pub unsafe fn write32(addr: usize, val: u32) {
    unsafe {
        ptr::write_volatile(addr as *mut u32, val);
    }
}

/// Set specific bits in a register (read-modify-write).
///
/// # Safety
///
/// Same requirements as `read32` and `write32`. The read-modify-write
/// is NOT atomic — do not use on registers where concurrent access
/// from other cores or DMA is possible without synchronization.
#[inline(always)]
pub unsafe fn set_bits(addr: usize, bits: u32) {
    unsafe {
        let val = read32(addr);
        write32(addr, val | bits);
    }
}

/// Clear specific bits in a register (read-modify-write).
///
/// # Safety
///
/// Same as `set_bits`.
#[inline(always)]
pub unsafe fn clear_bits(addr: usize, bits: u32) {
    unsafe {
        let val = read32(addr);
        write32(addr, val & !bits);
    }
}

/// Wait until specific bits in a register are set, with a timeout.
///
/// Returns `true` if the bits became set, `false` on timeout.
///
/// # Safety
///
/// Same requirements as `read32`.
#[inline]
pub unsafe fn wait_bits_set(addr: usize, bits: u32, max_iterations: u32) -> bool {
    for _ in 0..max_iterations {
        if unsafe { read32(addr) } & bits == bits {
            return true;
        }
    }
    false
}

/// Wait until specific bits in a register are clear, with a timeout.
///
/// Returns `true` if the bits became clear, `false` on timeout.
///
/// # Safety
///
/// Same requirements as `read32`.
#[inline]
pub unsafe fn wait_bits_clear(addr: usize, bits: u32, max_iterations: u32) -> bool {
    for _ in 0..max_iterations {
        if unsafe { read32(addr) } & bits == 0 {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    // NOTE: MMIO tests require actual hardware or a mock.
    // These functions are verified by integration testing on the device.
}
