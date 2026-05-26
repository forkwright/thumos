//! ARM Generic Timer driver.
//!
//! The Cortex-A53 has an integrated generic timer (CNTPCT, CNTP_TVAL, CNTP_CTL).
//! We use the physical timer (not virtual) since we're the kernel.
//!
//! The timer fires an IRQ (typically IRQ 30 on GICv2 for the physical timer PPI)
//! which we use as the scheduler tick.

/// Timer IRQ number (PPI 14 = SPI-less, mapped to GIC IRQ 30 on A53).
pub(crate) const TIMER_IRQ: u32 = 30;

/// Read the counter frequency (CNTFRQ).
pub(crate) fn frequency() -> u32 {
    let freq: u32;
    // SAFETY: CNTP_TVAL/CNTP_CTL are system timer registers accessible at EL1.
    unsafe {
        core::arch::asm!(
            "mrc p15, 0, {}, c14, c0, 0", // CNTFRQ
            out(reg) freq,
        );
    }
    freq
}

/// Read the current counter value (CNTPCT, 64-bit).
pub(crate) fn counter() -> u64 {
    let lo: u32;
    let hi: u32;
    // SAFETY: CNTP_TVAL/CNTP_CTL are system timer registers accessible at EL1.
    unsafe {
        core::arch::asm!(
            "mrrc p15, 0, {lo}, {hi}, c14", // CNTPCT
            lo = out(reg) lo,
            hi = out(reg) hi,
        );
    }
    ((u64::from(hi)) << 32) | (u64::from(lo))
}

/// Set the timer to fire after `ticks` counter increments.
pub(crate) fn set_timer(ticks: u32) {
    // SAFETY: CNTP_TVAL/CNTP_CTL are system timer registers accessible at EL1.
    unsafe {
        // Set countdown value
        core::arch::asm!(
            "mcr p15, 0, {}, c14, c2, 0", // CNTP_TVAL
            in(reg) ticks,
        );
        // Enable timer, unmask interrupt
        core::arch::asm!(
            "mcr p15, 0, {}, c14, c2, 1", // CNTP_CTL = 1 (enable, not masked)
            in(reg) 1u32,
        );
    }
}

/// Disable the timer.
pub(crate) fn disable() {
    // SAFETY: CNTP_TVAL/CNTP_CTL are system timer registers accessible at EL1.
    unsafe {
        core::arch::asm!(
            "mcr p15, 0, {}, c14, c2, 1", // CNTP_CTL = 0
            in(reg) 0u32,
        );
    }
}

/// Set timer to fire after `ms` milliseconds.
pub(crate) fn set_ms(ms: u32) {
    let freq = frequency();
    let ticks = (freq / 1000) * ms;
    set_timer(ticks);
}

/// Get elapsed time since boot in milliseconds.
pub(crate) fn elapsed_ms() -> u64 {
    let freq = frequency() as u64;
    if freq == 0 {
        return 0;
    }
    (counter() * 1000) / freq
}
