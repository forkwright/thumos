//! Watchdog no-op stub for QEMU `-machine virt` (bring-up feature `qemu`).
//!
//! virt models no MT6739 WDT block at 0x1000_7000 -- any register write
//! would data-abort (and `pet()` runs on EVERY timer IRQ). Same module
//! surface as `watchdog.rs`; QEMU runs are bounded by the runner timeout
//! instead of a hardware watchdog.

/// No-op init: no WDT hardware exists under QEMU virt.
///
/// # Safety
///
/// No preconditions; performs no operation.
pub unsafe fn init() {}

/// No-op pet: keeps the timer-IRQ call site identical.
///
/// # Safety
///
/// No preconditions; performs no operation.
pub unsafe fn pet() {}

/// No-op disable.
///
/// # Safety
///
/// No preconditions; performs no operation.
pub unsafe fn disable() {}
