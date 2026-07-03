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

/// Poll a register-read closure up to `max_iterations` times, returning
/// `true` as soon as the read matches the wait condition.
///
/// Host-testable core of `wait_bits_set`/`wait_bits_clear` -- the two public
/// unsafe wrappers below just supply a real MMIO `read32` closure, so this
/// loop/timeout logic (including the zero-iteration case) has host-test
/// coverage without needing a live MMIO register.
#[inline]
fn poll_until<F: FnMut() -> u32>(
    mut read: F,
    bits: u32,
    max_iterations: u32,
    want_set: bool,
) -> bool {
    for _ in 0..max_iterations {
        let val = read();
        let matched = if want_set {
            val & bits == bits
        } else {
            val & bits == 0
        };
        if matched {
            return true;
        }
    }
    false
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
    poll_until(|| unsafe { read32(addr) }, bits, max_iterations, true)
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
    poll_until(|| unsafe { read32(addr) }, bits, max_iterations, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    // NOTE: wait_bits_set/wait_bits_clear still require actual hardware or
    // integration testing (read32 dereferences a live MMIO address).
    // poll_until is the extracted, host-testable timeout/loop core.

    #[test]
    fn poll_until_returns_true_when_condition_met_before_timeout() {
        let values = [0u32, 0u32, 0xFF];
        let mut calls = 0usize;
        let result = poll_until(
            || {
                let v = values[calls];
                calls += 1;
                v
            },
            0xFF,
            10,
            true,
        );
        assert!(result, "must return true once the read matches");
        assert_eq!(
            calls, 3,
            "must stop polling as soon as the condition is met"
        );
    }

    #[test]
    fn poll_until_returns_false_on_timeout() {
        let result = poll_until(|| 0u32, 0xFF, 5, true);
        assert!(
            !result,
            "must return false when the condition never matches"
        );
    }

    #[test]
    fn poll_until_zero_iterations_never_reads_and_returns_false() {
        let mut calls = 0u32;
        let result = poll_until(
            || {
                calls += 1;
                0xFF
            },
            0xFF,
            0,
            true,
        );
        assert!(!result, "zero max_iterations must return false immediately");
        assert_eq!(calls, 0, "zero max_iterations must not call read at all");
    }

    #[test]
    fn poll_until_matches_clear_condition() {
        let result = poll_until(|| 0u32, 0xFF, 3, false);
        assert!(result, "bits already clear must match immediately");
    }
}
