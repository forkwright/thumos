//! Board support: the ONE seam between the kernel core and the two machines
//! thumos boots on (#534).
//!
//! thumos is a two-board OS:
//! - **m7** — the AGM M7 feature phone (MT6739 `SoC`), the field board;
//! - **virt** — QEMU `-machine virt` (armv7a), the dev board every CI
//!   witness boots on (selected by `--features qemu`).
//!
//! This module is the single selection point: the board-specific constants
//! the kernel core needs are re-exported from the selected board's module,
//! so no per-board `#[cfg]` arm and no `MT6739_*` identifier exists anywhere
//! else in the kernel core (the standing invariant, enforced by
//! `scripts/check-board-seam.sh`). Constants that are IDENTICAL on both
//! boards — the DRAM window, the kernel image layout, the userspace image
//! base, the display geometry — live directly here, once: they are kernel
//! design choices (the virt machine is deliberately run with the M7's DRAM
//! base so the memory map is one truth), not per-board facts.
//!
//! OUT OF SCOPE by design (recognition-not-induction, #534): no device-tree
//! parsing, no runtime board detection, no second `SoC` port, no mega-HAL —
//! the per-subsystem `HwOps` traits stay the driver seam; this module is
//! only the *board* seam.

#[cfg(not(feature = "qemu"))]
mod m7;
#[cfg(not(feature = "qemu"))]
pub(crate) use m7::*;

#[cfg(feature = "qemu")]
mod virt;
// WHY: under `--features qemu --tests`, nothing in the test build's own
// code paths references virt's re-exports (register_devices and the MMIO
// base consts are only called from the non-test boot path) -- the glob
// import is real production surface, just unused specifically in test
// compilations, the same shape as m7's non-qemu re-export would show if
// virt's board had comparably test-referenced content.
#[cfg(feature = "qemu")]
#[cfg_attr(test, allow(unused_imports))]
pub(crate) use virt::*;

// ---------------------------------------------------------------------------
// Shared memory map (identical on both boards, by design)
// ---------------------------------------------------------------------------

/// RAM start address.
pub(crate) const RAM_START: usize = 0x4000_0000;

/// RAM end address (1 GB).
pub(crate) const RAM_END: usize = 0x8000_0000;

/// Kernel load address.
pub(crate) const KERNEL_LOAD: usize = 0x4000_8000;

/// Kernel reserved size (2016 KB).
///
/// WHY the window is measured to `KERNEL_LOAD` but sized in whole megabytes
/// from `RAM_START`: the region is mapped by coarse L2 tables, one per 1 MB
/// L1 section, so `KERNEL_END` must land on a megabyte boundary. The image
/// loads 32 KB in, at `KERNEL_LOAD`, which is why this constant is 32 KB short
/// of a round figure.
///
/// WHY two sections rather than one (#917): the image, its statics and all
/// five stacks share this window, and at one section they occupied 96.4% of
/// it -- 36,958 bytes of headroom, against features that cost tens of
/// kilobytes each. `mmu::KERNEL_SECTIONS` derives the table count from this
/// value, so raising it further needs no second edit there; what it does need
/// is `link.ld`'s bound, which `scripts/check-kernel-window.sh` holds to this
/// definition because a linker script cannot read a Rust constant.
pub(crate) const KERNEL_RESERVED: usize = 0x1F_8000;

/// Kernel end address (load + reserved).
pub(crate) const KERNEL_END: usize = KERNEL_LOAD + KERNEL_RESERVED;

/// Userspace text region base (#474/#482): the top 1 MB of DRAM
/// (`0x7FF0_0000..0x8000_0000`), the fixed identity load address for the
/// image-resident /init. EXCLUDED from the page allocator (kinit passes this
/// as the allocator's upper bound) so an allocation never collides with the
/// loaded image. In the KERNEL address space it is plain RAM + execute-never
/// (W^X #417 — the kernel never executes user code from its own space); a
/// spawned process runs it user-RX from its OWN page table via `mmu`
/// per-process mappings (PL0 isolation, #482).
pub(crate) const USER_TEXT_BASE: usize = 0x7FF0_0000;

/// Display width (the M7's 240x320 panel; the virt synthetic framebuffer
/// mirrors the same geometry so the UI is pixel-identical across boards).
pub(crate) const DISPLAY_WIDTH: u32 = 240;

/// Display height.
pub(crate) const DISPLAY_HEIGHT: u32 = 320;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    // WHY: every bound here is a fixed board-layout const, so clippy sees
    // compile-time-constant assertions. This test exists precisely to pin
    // those relationships (map size, KERNEL_END derivation, ordering) as a
    // discoverable, individually reportable regression guard rather than a
    // silent const-eval check.
    #[allow(clippy::assertions_on_constants)]
    fn shared_memory_map_is_self_consistent() {
        assert_eq!(RAM_END - RAM_START, 1024 * 1024 * 1024);
        assert_eq!(KERNEL_END, 0x4020_0000);
        // The window must be a whole number of 1 MB sections measured from
        // RAM_START, because coarse L2 tables cannot map a partial one.
        assert_eq!((KERNEL_END - RAM_START) % (1 << 20), 0);
        assert_eq!(KERNEL_END, KERNEL_LOAD + KERNEL_RESERVED);
        assert_eq!(DISPLAY_WIDTH * DISPLAY_HEIGHT * 2, 153_600); // RGB565 framebuffer size
        assert!(USER_TEXT_BASE < RAM_END);
    }
}
