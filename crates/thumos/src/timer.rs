//! ARM Generic Timer driver.
//!
//! The Cortex-A53 has an integrated generic timer (CNTPCT, `CNTP_TVAL`, `CNTP_CTL`).
//! We use the physical timer (not virtual) since we're the kernel.
//!
//! The timer fires an IRQ (typically IRQ 30 on `GICv2` for the physical timer PPI)
//! which we use as the scheduler tick.
//!
//! WHY `TIMER_IRQ` is feature-conditional (#544): the `CNTP_*` registers
//! programmed below (`p15, 0, ..., c14, c2, *`) are BANKED between Secure
//! and Non-secure PL1 on a core with ARM Security Extensions -- every
//! normal boot (`secure=off`, the M7 board and every other QEMU witness)
//! runs Non-secure (or on a core with no Security Extensions active at
//! all), so the physical timer's interrupt is the Non-secure PPI (GIC
//! INTID 30). `metaxu-probe`'s `-machine virt,secure=on` (for the second
//! PL011, `board::UART1_BASE`) boots this kernel in SECURE state instead
//! (there is no Secure->Non-secure monitor-mode transition in this boot
//! stub) -- the SAME register writes there bank to the SECURE physical
//! timer, whose interrupt is a DIFFERENT PPI (GIC INTID 29). Programming
//! IRQ 30 there leaves the kernel waiting on an interrupt line that never
//! fires: `exceptions::ticks()` never advances past 0, silently hanging
//! the #461 timer witness's own busy-wait in `kinit.rs` forever (found
//! via the metaxu-probe QEMU boot hanging at "Timer frequency: ... Hz").

/// Timer IRQ number (PPI 14 = SPI-less, mapped to GIC IRQ 30 on A53).
///
/// Under `metaxu-probe` (secure=on), the physical timer registers bank to
/// the SECURE instance (PPI 13, GIC INTID 29) instead -- see the module
/// doc's WHY.
#[cfg(not(feature = "metaxu-probe"))]
pub(crate) const TIMER_IRQ: u32 = 30;
/// See [`TIMER_IRQ`]'s doc (the non-`metaxu-probe` one) and the module doc.
#[cfg(feature = "metaxu-probe")]
pub(crate) const TIMER_IRQ: u32 = 29;

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
///
/// WHY saturating: `(freq / 1000) * ms` overflows u32 once `ms` exceeds
/// roughly 330 s at the MT6739's 13 MHz CNTFRQ. A saturated ticks value
/// caps the countdown at the longest representable delay instead of
/// silently wrapping to a near-zero tick count, which would fire the
/// timer IRQ (the scheduler tick and watchdog pet source) almost
/// immediately instead of after the requested delay. See
/// `timer_stub::ms_to_ticks` for the host-tested mirror of this
/// arithmetic.
pub(crate) fn set_ms(ms: u32) {
    let freq = frequency();
    // WHY the zero guard (#842): `elapsed_ms` a few lines below already
    // refuses a zero CNTFRQ. Without the same refusal here, `freq / 1000` is
    // 0, so `ticks` is 0 and `set_timer(0)` fires the IRQ immediately -- on
    // the scheduler tick and watchdog-pet source, which turns an unreadable
    // CNTFRQ into a boot-time interrupt storm rather than a slow clock.
    // Leaving the timer unarmed is the safer failure: the watchdog then
    // expires and resets, which is visible, instead of the CPU never leaving
    // the handler.
    if freq == 0 {
        return;
    }
    let ticks = (freq / 1000).saturating_mul(ms);
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
