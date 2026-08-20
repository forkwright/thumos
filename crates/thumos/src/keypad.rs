//! Boot-time keypad matrix reader (#446, source-grounding blocker #880).
//!
//! Poll-based GPIO matrix scan for the boot passphrase gate. `haphe` is
//! `no_std` and linked only as a dev-dependency for host-test vocabulary
//! cross-checks, but its private,
//! queued pressed/released event shape does not fit this synchronous boot
//! gate's first-confirmed-press interface. This module mirrors haphe's proven scan/debounce algorithm
//! (`crates/haphe/src/gpio.rs`) against the kernel's [`crate::ui::Key`]
//! vocabulary. The KPD hardware block at
//! `board::KPD_BASE` is only *enabled* by kinit (Step 8a) — no verified
//! read-out register map exists for it — so the boot path scans the raw
//! GPIO matrix directly, exactly as the userspace driver does.
//!
//! Pin assignments and the generic GPIO transaction model are placeholders.
//! The current non-QEMU boot path can execute them; #880 requires fail-closed
//! disablement plus accepted AGM M7/MT6739 evidence before any device run.
//!
//! Simplifications versus haphe, deliberate for the boot path: no input
//! queue and no release/held events — the boot loop polls on a ~10 ms
//! cadence and acts on confirmed *presses* (taps) only. Debounce state is
//! still tracked per key so a press is reported once and re-arming
//! requires a physical release.

// WHY: the whole module is M7-only hardware access. It is compiled on the
// host for tests (the scan/debounce logic is injected-matrix host-tested)
// and in m7 kernel builds; the qemu build has no GPIO matrix and never
// constructs the reader.

use crate::board;
use crate::ui::Key;

/// Number of row lines in the key matrix.
pub(crate) const ROW_COUNT: usize = board::KEYPAD_ROW_PINS.len();
/// Number of column lines in the key matrix.
pub(crate) const COL_COUNT: usize = board::KEYPAD_COL_PINS.len();
/// Total keys in the matrix.
pub(crate) const KEY_COUNT: usize = ROW_COUNT * COL_COUNT;

/// Consecutive identical scans required before a press transition is
/// accepted. At the boot loop's ~10 ms poll cadence this is ~30 ms of
/// debounce, mirroring haphe's `DEBOUNCE_THRESHOLD`.
pub(crate) const DEBOUNCE_THRESHOLD: u8 = 3;

/// Key lookup table indexed by `[row][col]` — the standard 4x3 phone
/// layout. Mirrors haphe's `KEY_MAP`, mapped to the kernel's `ui::Key`.
///
/// NOTE: the matrix yields only digits, Star, and Hash. The boot passphrase
/// UX binds Star = backspace and Hash = submit (see kinit Step 8c), so a
/// boot passphrase is effectively digits-only; the first-boot setup path
/// constrains the alphabet the same way, keeping set/enter consistent.
pub(crate) const KEY_MAP: [[Key; COL_COUNT]; ROW_COUNT] = [
    [Key::Num1, Key::Num2, Key::Num3],
    [Key::Num4, Key::Num5, Key::Num6],
    [Key::Num7, Key::Num8, Key::Num9],
    [Key::Star, Key::Num0, Key::Hash],
];

/// Register address and bit mask for `pin` within the register bank at
/// `bank_base` (an offset from `board::GPIO_BASE`).
///
/// `MT67xx` layout: each bank controls 32 pins; the address stride within a
/// bank is 8 (value at +0x00, set/clear aliases at +0x04). Mirrors haphe's
/// `gpio_reg`.
#[inline]
pub(crate) fn gpio_reg(bank_base: usize, pin: u8) -> (usize, u32) {
    let bank = usize::from(pin / 32);
    let bit = u32::from(pin % 32);
    (board::GPIO_BASE + bank_base + bank * 8, 1u32 << bit)
}

/// Snapshot of every matrix key's pressed state: bit `row * COL_COUNT +
/// col` is set when that key is currently pressed. Mirrors haphe's
/// `KeyMatrix`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct KeyMatrix(u16);

impl KeyMatrix {
    /// All keys released.
    pub(crate) const fn none() -> Self {
        Self(0)
    }

    /// Whether the key at (`row`, `col`) is pressed in this snapshot.
    #[inline]
    pub(crate) const fn is_pressed(self, row: usize, col: usize) -> bool {
        // usize->u16: at most 12 keys; the bit index always fits.
        let bit = (row * COL_COUNT + col) as u16;
        (self.0 >> bit) & 1 == 1
    }

    /// Set or clear the bit for (`row`, `col`).
    #[inline]
    pub(crate) const fn set(&mut self, row: usize, col: usize, pressed: bool) {
        // usize->u16: at most 12 keys; the bit index always fits.
        let bit = (row * COL_COUNT + col) as u16;
        if pressed {
            self.0 |= 1 << bit;
        } else {
            self.0 &= !(1 << bit);
        }
    }
}

/// Per-key debounce state: the accepted stable level plus the candidate
/// level accumulating confirmations. Mirrors haphe's `Debounce`.
#[derive(Clone, Copy, Debug)]
struct Debounce {
    /// The stable (accepted) pressed state.
    stable: bool,
    /// Candidate state currently accumulating confirmations.
    candidate: bool,
    /// Consecutive scans agreeing on `candidate`.
    count: u8,
}

impl Debounce {
    const fn new() -> Self {
        Self {
            stable: false,
            candidate: false,
            count: 0,
        }
    }

    /// Feed one raw reading. Returns `Some(true)` exactly on the scan that
    /// confirms a release->press transition; releases and sub-threshold
    /// wiggle only update internal state (the boot path acts on presses).
    const fn update(&mut self, pressed: bool) -> Option<bool> {
        if pressed == self.candidate {
            if self.count < DEBOUNCE_THRESHOLD {
                self.count += 1;
            }
            if self.count >= DEBOUNCE_THRESHOLD && pressed != self.stable {
                self.stable = pressed;
                return Some(pressed);
            }
        } else {
            self.candidate = pressed;
            self.count = 1;
        }
        None
    }
}

/// Boot keypad scanner: one scan cycle per poll, debounce per key, emits
/// the first confirmed press of the cycle.
pub(crate) struct BootKeypad {
    /// Per-key debounce state, laid out as `row * COL_COUNT + col`.
    debounce: [Debounce; KEY_COUNT],
}

impl BootKeypad {
    /// A fresh scanner (all keys released, no history).
    pub(crate) const fn new() -> Self {
        const DB: Debounce = Debounce::new();
        Self {
            debounce: [DB; KEY_COUNT],
        }
    }

    /// Debounce-and-decode core: feed one raw matrix snapshot, get back
    /// `Some(key)` on the first newly-confirmed press this cycle.
    ///
    /// This is the host-testable half; hardware reads reach it through
    /// [`BootKeypad::poll`].
    pub(crate) fn poll_with_matrix(&mut self, matrix: KeyMatrix) -> Option<Key> {
        for (row, row_keys) in KEY_MAP.iter().enumerate() {
            for (col, &key) in row_keys.iter().enumerate() {
                let pressed = matrix.is_pressed(row, col);
                // WHY get_mut: KEY_COUNT == ROW_COUNT * COL_COUNT by
                // construction, but an indexing panic in the boot path is a
                // bricked phone — stay total.
                if let Some(slot) = self.debounce.get_mut(row * COL_COUNT + col)
                    && let Some(true) = slot.update(pressed)
                {
                    return Some(key);
                }
            }
        }
        None
    }

    /// Configure the matrix GPIOs: rows as outputs driven high (inactive),
    /// columns as inputs with pull-up.
    #[cfg(not(test))]
    // WHY: the body only touches board:: constants and MMIO registers, not
    // self, but kinit.rs (out of this change's scope) calls this as
    // `keypad.init()` alongside the rest of BootKeypad's per-instance API --
    // dropping &self would require a matching kinit.rs call-site edit.
    // NOTE: cfg_attr split, not a bare expect (#718 trap) -- clippy's
    // unused_self does not fire on this body under the qemu feature
    // (verified: CI run 31499203998), so an unconditional #[expect] is
    // unfulfilled there while fulfilled under every non-qemu, non-test
    // kernel configuration.
    #[cfg_attr(
        not(feature = "qemu"),
        expect(
            clippy::unused_self,
            reason = "the body only touches board:: constants and MMIO registers, not self, but kinit.rs calls this as keypad.init() alongside the rest of BootKeypad's per-instance API -- dropping &self would require a matching kinit.rs call-site edit"
        )
    )]
    #[cfg_attr(
        feature = "qemu",
        allow(
            clippy::unused_self,
            reason = "same instance-method-parity rationale as the non-qemu expect above; clippy's unused_self does not fire on this body under qemu"
        )
    )]
    pub(crate) fn init(&self) {
        for &pin in &board::KEYPAD_ROW_PINS {
            let (dir_addr, dir_mask) = gpio_reg(board::GPIO_DIR_BASE, pin);
            let (dout_addr, dout_mask) = gpio_reg(board::GPIO_DOUT_BASE, pin);
            // SAFETY: GPIO MMIO registers at board::GPIO_BASE-derived
            // addresses, identity-mapped as device memory; written once at
            // boot before the passphrase loop polls.
            unsafe {
                crate::mmio::write32(dir_addr, crate::mmio::read32(dir_addr) | dir_mask);
                crate::mmio::write32(dout_addr, crate::mmio::read32(dout_addr) | dout_mask);
            }
        }
        for &pin in &board::KEYPAD_COL_PINS {
            let (dir_addr, dir_mask) = gpio_reg(board::GPIO_DIR_BASE, pin);
            let (pullen_addr, pullen_mask) = gpio_reg(board::GPIO_PULLEN_BASE, pin);
            let (pullsel_addr, pullsel_mask) = gpio_reg(board::GPIO_PULLSEL_BASE, pin);
            // SAFETY: as above. DIR bit cleared = input; pull enabled and
            // selected up so an idle column reads high.
            unsafe {
                crate::mmio::write32(dir_addr, crate::mmio::read32(dir_addr) & !dir_mask);
                crate::mmio::write32(pullen_addr, crate::mmio::read32(pullen_addr) | pullen_mask);
                crate::mmio::write32(
                    pullsel_addr,
                    crate::mmio::read32(pullsel_addr) | pullsel_mask,
                );
            }
        }
    }

    /// One scan cycle against the hardware matrix.
    #[cfg(not(test))]
    pub(crate) fn poll(&mut self) -> Option<Key> {
        self.poll_with_matrix(read_matrix())
    }
}

/// Read the raw (un-debounced) matrix from hardware: drive each row low in
/// turn, read the column bank, active-low. Mirrors haphe's `read_matrix`.
#[cfg(not(test))]
fn read_matrix() -> KeyMatrix {
    let mut matrix = KeyMatrix::none();
    for (row_idx, &row_pin) in board::KEYPAD_ROW_PINS.iter().enumerate() {
        let (dout_addr, dout_mask) = gpio_reg(board::GPIO_DOUT_BASE, row_pin);
        let first_col = board::KEYPAD_COL_PINS.first().copied().unwrap_or(0);
        let (din_addr, _) = gpio_reg(board::GPIO_DIN_BASE, first_col);
        // SAFETY: GPIO MMIO as in init(); rows/cols were configured by
        // BootKeypad::init before the poll loop runs.
        unsafe {
            // Drive this row low.
            crate::mmio::write32(dout_addr, crate::mmio::read32(dout_addr) & !dout_mask);
        }
        // WHY: GPIO propagation is sub-microsecond on MT67xx; a short spin
        // lets the level settle before the column read.
        for _ in 0..16u32 {
            core::hint::spin_loop();
        }
        // SAFETY: read of the data-in bank as mapped above. All column pins
        // live in the same 32-pin bank (44-46).
        let din_word = unsafe { crate::mmio::read32(din_addr) };
        for (col_idx, &col_pin) in board::KEYPAD_COL_PINS.iter().enumerate() {
            let col_bit = u32::from(col_pin % 32);
            // Pull-up keeps an idle column high; a pressed key shorts the
            // driven-low row to the column and reads low.
            let high = (din_word >> col_bit) & 1 == 1;
            matrix.set(row_idx, col_idx, !high);
        }
        // SAFETY: restoring the row high (inactive) as mapped above.
        unsafe {
            crate::mmio::write32(dout_addr, crate::mmio::read32(dout_addr) | dout_mask);
        }
    }
    matrix
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Feed `matrix` into `kp` exactly `n` times, returning the last poll.
    fn scan_n(kp: &mut BootKeypad, matrix: KeyMatrix, n: usize) -> Option<Key> {
        let mut out = None;
        for _ in 0..n {
            out = kp.poll_with_matrix(matrix);
        }
        out
    }

    #[test]
    fn press_confirms_after_threshold_and_reports_once() {
        let mut kp = BootKeypad::new();
        let mut m = KeyMatrix::none();
        m.set(0, 0, true); // Num1

        // Below threshold: no event.
        for _ in 0..(DEBOUNCE_THRESHOLD - 1) {
            assert_eq!(kp.poll_with_matrix(m), None, "sub-threshold must not emit");
        }
        // At threshold: exactly one press event.
        assert_eq!(kp.poll_with_matrix(m), Some(Key::Num1));
        // Held steady: no repeat emission.
        assert_eq!(scan_n(&mut kp, m, 10), None, "a held key must not re-emit");
    }

    #[test]
    fn release_rearms_the_key() {
        let mut kp = BootKeypad::new();
        let mut m = KeyMatrix::none();
        m.set(1, 1, true); // Num5

        scan_n(&mut kp, m, DEBOUNCE_THRESHOLD as usize);
        // Release past the threshold.
        assert_eq!(
            scan_n(&mut kp, KeyMatrix::none(), DEBOUNCE_THRESHOLD as usize + 2),
            None,
            "release emits nothing on the boot path"
        );
        // A second press confirms again.
        assert_eq!(
            scan_n(&mut kp, m, DEBOUNCE_THRESHOLD as usize),
            Some(Key::Num5),
            "key must re-arm after release"
        );
    }

    #[test]
    fn bounce_never_confirms() {
        let mut kp = BootKeypad::new();
        let mut m = KeyMatrix::none();
        m.set(2, 2, true); // Num9
        // Alternate pressed/released under the threshold: no stable press.
        for _ in 0..20 {
            assert_eq!(kp.poll_with_matrix(m), None);
            assert_eq!(kp.poll_with_matrix(KeyMatrix::none()), None);
        }
    }

    #[test]
    fn key_map_layout_is_the_phone_pad() {
        assert_eq!(KEY_MAP[0], [Key::Num1, Key::Num2, Key::Num3]);
        assert_eq!(KEY_MAP[1], [Key::Num4, Key::Num5, Key::Num6]);
        assert_eq!(KEY_MAP[2], [Key::Num7, Key::Num8, Key::Num9]);
        assert_eq!(KEY_MAP[3], [Key::Star, Key::Num0, Key::Hash]);
    }

    #[test]
    fn gpio_reg_addressing_matches_the_mt67xx_bank_formula() {
        // Pin 8 in bank 0: base + bank offset, bit 8.
        let (addr, mask) = gpio_reg(board::GPIO_DOUT_BASE, 8);
        assert_eq!(addr, board::GPIO_BASE + board::GPIO_DOUT_BASE);
        assert_eq!(mask, 1 << 8);
        // Pin 40 (first row pin): bank 1, stride 8, bit 8.
        let (addr, mask) = gpio_reg(board::GPIO_DIN_BASE, 40);
        assert_eq!(addr, board::GPIO_BASE + board::GPIO_DIN_BASE + 8);
        assert_eq!(mask, 1 << 8);
    }

    #[test]
    fn first_confirmed_press_wins_the_cycle() {
        let mut kp = BootKeypad::new();
        let mut m = KeyMatrix::none();
        m.set(0, 0, true); // Num1
        m.set(3, 2, true); // Hash
        assert_eq!(
            scan_n(&mut kp, m, DEBOUNCE_THRESHOLD as usize),
            Some(Key::Num1),
            "scan order is row-major; Num1 precedes Hash"
        );
    }
}
