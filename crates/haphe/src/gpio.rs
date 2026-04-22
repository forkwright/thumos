//! GPIO keypad matrix scan driver for the MT6739.
//!
//! Drives a row-column matrix keypad over MT6739 GPIO MMIO registers.
//! For each scan cycle, each row is pulled low in turn and the column
//! pins are read. Debounce requires N consecutive identical readings
//! before a state change is emitted.
//!
//! Pin assignments are placeholders  -  exact numbers must be verified
//! against the AGM M7 schematic.

// NOTE: no_std  -  all core:: primitives only.

use crate::input::{InputEvent, InputQueue, Key, KeyState};

// ── MT6739 GPIO register map ───────────────────────────────────────────────────

/// MT6739 GPIO controller base address.
///
/// NOTE: Standard `MT67xx` base. Verify against MT6739 TRM §GPIO.
const GPIO_BASE: usize = 0x1000_5000;

// Each register bank controls 32 GPIO pins.
// Offset formula: (pin / 32) * 8 + bank_base.
// The MT67xx "SET/clear" pattern writes to +0x04 to SET bits and
// reads back the value at +0x00.

/// GPIO direction register base OFFSET (0 = input, 1 = output).
const GPIO_DIR_BASE: usize = 0x000;

/// GPIO data-out register base OFFSET.
#[cfg_attr(
    test,
    expect(dead_code, reason = "used only in hardware (non-test) build")
)]
const GPIO_DOUT_BASE: usize = 0x100;

/// GPIO data-in register base OFFSET (always reads current pin level).
#[cfg_attr(
    test,
    expect(dead_code, reason = "used only in hardware (non-test) build")
)]
const GPIO_DIN_BASE: usize = 0x200;

/// GPIO pull-enable register base OFFSET.
#[cfg_attr(
    test,
    expect(dead_code, reason = "used only in hardware (non-test) build")
)]
const GPIO_PULLEN_BASE: usize = 0x300;

/// GPIO pull-SELECT register base OFFSET (0 = pull-down, 1 = pull-up).
#[cfg_attr(
    test,
    expect(dead_code, reason = "used only in hardware (non-test) build")
)]
const GPIO_PULLSEL_BASE: usize = 0x400;

// ── Key matrix geometry ────────────────────────────────────────────────────────

/// Number of row GPIO pins in the key matrix.
pub(crate) const ROW_COUNT: usize = 4;

/// Number of column GPIO pins in the key matrix.
pub(crate) const COL_COUNT: usize = 3;

/// Total number of keys in the matrix.
pub(crate) const KEY_COUNT: usize = ROW_COUNT * COL_COUNT;

/// Row GPIO pin numbers (`MT6739` pin index).
///
/// NOTE: These are placeholder VALUES. Exact assignments require
/// hardware probing against the AGM M7 schematic. Rows are driven
/// low during scanning.
#[cfg_attr(
    test,
    expect(dead_code, reason = "used only in hardware (non-test) build")
)]
pub(crate) const ROW_PINS: [u8; ROW_COUNT] = [40, 41, 42, 43];

/// Column GPIO pin numbers.
///
/// NOTE: Placeholder VALUES  -  verify against AGM M7 schematic.
/// Columns are inputs with pull-up; a driven row pulls a pressed
/// key's column low.
#[cfg_attr(
    test,
    expect(dead_code, reason = "used only in hardware (non-test) build")
)]
pub(crate) const COL_PINS: [u8; COL_COUNT] = [44, 45, 46];

/// Key lookup table indexed by `[row][col]`.
///
/// Standard 4-row × 3-col phone keypad layout:
/// ```text
/// row 0: 1  2  3
/// row 1: 4  5  6
/// row 2: 7  8  9
/// row 3: *  0  #
/// ```
pub(crate) const KEY_MAP: [[Key; COL_COUNT]; ROW_COUNT] = [
    [Key::Num1, Key::Num2, Key::Num3],
    [Key::Num4, Key::Num5, Key::Num6],
    [Key::Num7, Key::Num8, Key::Num9],
    [Key::Star, Key::Num0, Key::Hash],
];

/// Number of consecutive identical scans required before a state
/// transition is accepted.
///
/// At ~10 ms per scan this gives 30 ms of debounce time.
pub(crate) const DEBOUNCE_THRESHOLD: u8 = 3;

// ── GPIO register addressing ──────────────────────────────────────────────────

/// Return the register address and bit mask for the given GPIO pin
/// within the bank identified by `bank_base`.
#[inline]
pub(crate) fn gpio_reg(bank_base: usize, pin: u8) -> (usize, u32) {
    let bank = usize::from(pin / 32);
    let bit = u32::from(pin % 32);
    let addr = GPIO_BASE + bank_base + bank * 8;
    (addr, 1u32 << bit)
}

// ── MMIO abstractions (hardware build only) ───────────────────────────────────

#[cfg(not(test))]
mod hw {
    //! Raw MMIO helpers. All `unsafe` is confined to this module.
    #![expect(unsafe_code, reason = "bare-metal MMIO: volatile r/w is unavoidable")]

    use super::{GPIO_DIR_BASE, GPIO_DOUT_BASE, GPIO_PULLEN_BASE, GPIO_PULLSEL_BASE, gpio_reg};

    #[inline]
    pub(super) fn mmio_read(addr: usize) -> u32 {
        // SAFETY: Callers (gpio_init_row, gpio_init_col, read_matrix) guarantee
        // addr is a valid, aligned MT6739 MMIO register address.
        unsafe { core::ptr::read_volatile(addr as *const u32) }
    }

    #[inline]
    pub(super) fn mmio_write(addr: usize, val: u32) {
        // SAFETY: Same as mmio_read.
        unsafe { core::ptr::write_volatile(addr as *mut u32, val) }
    }

    /// Set bits in an MMIO register (read-modify-write).
    #[inline]
    pub(super) fn reg_set(addr: usize, mask: u32) {
        mmio_write(addr, mmio_read(addr) | mask);
    }

    /// Clear bits in an MMIO register (read-modify-write).
    #[inline]
    pub(super) fn reg_clr(addr: usize, mask: u32) {
        mmio_write(addr, mmio_read(addr) & !mask);
    }

    /// Configure a GPIO as output and drive it high.
    pub(super) fn gpio_init_row(pin: u8) {
        let (dir_addr, dir_mask) = gpio_reg(GPIO_DIR_BASE, pin);
        let (dout_addr, dout_mask) = gpio_reg(GPIO_DOUT_BASE, pin);
        // WHY: Set DIR bit = output. Drive high so inactive rows do not float.
        reg_set(dir_addr, dir_mask);
        reg_set(dout_addr, dout_mask);
    }

    /// Configure a GPIO as input with pull-up.
    pub(super) fn gpio_init_col(pin: u8) {
        let (dir_addr, dir_mask) = gpio_reg(GPIO_DIR_BASE, pin);
        let (pullen_addr, pullen_mask) = gpio_reg(GPIO_PULLEN_BASE, pin);
        let (pullsel_addr, pullsel_mask) = gpio_reg(GPIO_PULLSEL_BASE, pin);
        reg_clr(dir_addr, dir_mask); // input
        reg_set(pullen_addr, pullen_mask); // pull enable
        reg_set(pullsel_addr, pullsel_mask); // pull-up (1 = pull-up in MT67xx)
    }
}

// ── GpioKeypad ────────────────────────────────────────────────────────────────

/// Snapshot of every key's pressed/released state.
///
/// Bit i is SET when key i (`row * COL_COUNT + col`) is currently pressed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct KeyMatrix(pub(crate) u16);

impl KeyMatrix {
    /// All keys released.
    pub(crate) const fn none() -> Self {
        Self(0)
    }

    /// Test whether key at (row, col) is pressed in this snapshot.
    #[inline]
    pub(crate) const fn is_pressed(self, row: usize, col: usize) -> bool {
        // usize→u16: matrix has 12 keys max; value always fits
        let bit = (row * COL_COUNT + col) as u16;
        (self.0 >> bit) & 1 == 1
    }

    /// Set or clear the bit for (row, col).
    #[inline]
    pub(crate) const fn set(&mut self, row: usize, col: usize, pressed: bool) {
        // usize→u16: matrix has 12 keys max; value always fits
        let bit = (row * COL_COUNT + col) as u16;
        if pressed {
            self.0 |= 1 << bit;
        } else {
            self.0 &= !(1 << bit);
        }
    }
}

/// Per-key debounce state.
///
/// Tracks how many consecutive scans have returned the same level
/// and what that level is.
#[derive(Clone, Copy, Debug)]
struct Debounce {
    /// The stable (accepted) state.
    stable: bool,
    /// Candidate state currently accumulating confirmations.
    candidate: bool,
    /// Number of consecutive scans that agree on `candidate`.
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

    /// Feed a new raw reading. Returns the new stable state if a
    /// transition was just confirmed, otherwise `None`.
    const fn update(&mut self, pressed: bool) -> Option<KeyState> {
        if pressed == self.candidate {
            if self.count < DEBOUNCE_THRESHOLD {
                self.count += 1;
            }
            if self.count >= DEBOUNCE_THRESHOLD && pressed != self.stable {
                self.stable = pressed;
                return Some(if pressed {
                    KeyState::Pressed
                } else {
                    KeyState::Released
                });
            }
        } else {
            self.candidate = pressed;
            self.count = 1;
        }
        None
    }
}

/// GPIO keypad matrix scanner.
///
/// Call [`GpioKeypad::init`] once on boot, then call [`GpioKeypad::scan`]
/// in the main input loop to push [`InputEvent`] VALUES INTO the queue.
pub(crate) struct GpioKeypad {
    /// Per-key debounce state; laid out as `[row * COL_COUNT + col]`.
    debounce: [Debounce; KEY_COUNT],
}

impl GpioKeypad {
    /// Create a new, uninitialised keypad driver.
    pub(crate) const fn new() -> Self {
        const DB: Debounce = Debounce::new();
        Self {
            debounce: [DB; KEY_COUNT],
        }
    }

    /// Initialise GPIO pins: rows as outputs (initially high), columns
    /// as inputs with pull-up.
    ///
    /// NOTE: No-op in test builds  -  MMIO is unavailable on the host.
    #[cfg(not(test))]
    pub(crate) fn init(&self) {
        let _ = self;
        for &row in &ROW_PINS {
            hw::gpio_init_row(row);
        }
        for &col in &COL_PINS {
            hw::gpio_init_col(col);
        }
    }

    /// Scan the key matrix and push any state-change events INTO `queue`.
    ///
    /// NOTE: This is not ISR-safe. Call FROM a single task/thread only.
    pub(crate) fn scan(&mut self, queue: &mut InputQueue) {
        let raw = Self::read_matrix();
        self.process_matrix(raw, queue);
    }

    /// Shared debounce-and-emit logic used by both `scan` and the test helper.
    fn process_matrix(&mut self, matrix: KeyMatrix, queue: &mut InputQueue) {
        for (row, row_keys) in KEY_MAP.iter().enumerate() {
            for (col, &key) in row_keys.iter().enumerate() {
                let idx = row * COL_COUNT + col;
                let pressed = matrix.is_pressed(row, col);
                if let Some(debounce) = self.debounce.get_mut(idx)
                    && let Some(state) = debounce.update(pressed)
                {
                    queue.push(InputEvent::Key { key, state });
                }
            }
        }
    }

    /// Read the raw (un-debounced) key matrix FROM hardware.
    #[cfg(not(test))]
    fn read_matrix() -> KeyMatrix {
        let mut matrix = KeyMatrix::none();
        for (row_idx, &row_pin) in ROW_PINS.iter().enumerate() {
            let (dout_addr, dout_mask) = gpio_reg(GPIO_DOUT_BASE, row_pin);
            // Drive this row low.
            hw::reg_clr(dout_addr, dout_mask);

            // WHY: GPIO propagation delay on MT67xx is typically <1 µs;
            // a short spin lets the level settle before reading columns.
            for _ in 0..16u32 {
                core::hint::spin_loop();
            }

            // All column pins are in the same 32-pin bank (pins 44-46).
            let (din_addr, _) =
                gpio_reg(GPIO_DIN_BASE, COL_PINS.first().copied().unwrap_or_default());
            let din_word = hw::mmio_read(din_addr);
            for (col_idx, &col_pin) in COL_PINS.iter().enumerate() {
                let col_bit = u32::from(col_pin % 32);
                // Pull-up keeps column high; a pressed key shorts the
                // driven-low row to the column → reads low.
                let high = (din_word >> col_bit) & 1 == 1;
                matrix.set(row_idx, col_idx, !high);
            }

            // Release row back to high.
            hw::reg_set(dout_addr, dout_mask);
        }
        matrix
    }

    /// Test-only matrix reader.
    ///
    /// Tests use [`GpioKeypad::scan_with_matrix`] directly rather than
    /// calling `scan`, so this is never reached in test builds.
    #[cfg(test)]
    const fn read_matrix() -> KeyMatrix {
        KeyMatrix::none()
    }

    /// Inject an arbitrary raw matrix state and run the scan/debounce
    /// logic. Test-only entry point.
    #[cfg(test)]
    pub(crate) fn scan_with_matrix(&mut self, matrix: KeyMatrix, queue: &mut InputQueue) {
        self.process_matrix(matrix, queue);
    }
}

impl Default for GpioKeypad {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::input::{InputQueue, Key, KeyState};

    // ── KeyMatrix ──────────────────────────────────────────────────────────────

    #[test]
    fn key_matrix_none_has_no_pressed_keys() {
        let m = KeyMatrix::none();
        for row in 0..ROW_COUNT {
            for col in 0..COL_COUNT {
                assert!(
                    !m.is_pressed(row, col),
                    "KeyMatrix::none() must have no pressed keys (row={row}, col={col})"
                );
            }
        }
    }

    #[test]
    fn key_matrix_set_and_read_roundtrip() {
        let mut m = KeyMatrix::none();
        m.set(1, 2, true);
        assert!(
            m.is_pressed(1, 2),
            "SET(1,2,true) must make is_pressed(1,2) return true"
        );
        m.set(1, 2, false);
        assert!(
            !m.is_pressed(1, 2),
            "SET(1,2,false) must make is_pressed(1,2) return false"
        );
    }

    #[test]
    fn key_matrix_independent_bits() {
        let mut m = KeyMatrix::none();
        m.set(0, 0, true);
        m.set(3, 2, true);
        assert!(
            m.is_pressed(0, 0),
            "bit for (0,0) must remain SET after setting (3,2)"
        );
        assert!(
            m.is_pressed(3, 2),
            "bit for (3,2) must remain SET after setting (0,0)"
        );
        assert!(
            !m.is_pressed(1, 1),
            "bit for (1,1) must remain clear when not explicitly SET"
        );
    }

    // ── gpio_reg ───────────────────────────────────────────────────────────────

    #[test]
    fn gpio_reg_pin0_is_bank0_bit0() {
        let (addr, mask) = gpio_reg(GPIO_DIR_BASE, 0);
        assert_eq!(
            addr,
            GPIO_BASE + GPIO_DIR_BASE,
            "pin 0 must map to bank 0 (OFFSET 0)"
        );
        assert_eq!(mask, 1u32, "pin 0 must be bit 0");
    }

    #[test]
    fn gpio_reg_pin32_is_bank1() {
        let (addr, mask) = gpio_reg(GPIO_DIR_BASE, 32);
        assert_eq!(
            addr,
            GPIO_BASE + GPIO_DIR_BASE + 8,
            "pin 32 must map to bank 1 (OFFSET +8)"
        );
        assert_eq!(mask, 1u32, "pin 32 must be bit 0 within bank 1");
    }

    #[test]
    fn gpio_reg_pin_bit_position() {
        let (_, mask) = gpio_reg(GPIO_DIR_BASE, 5);
        assert_eq!(mask, 1u32 << 5, "pin 5 must SET bit 5 in the mask");
    }

    // ── Debounce ──────────────────────────────────────────────────────────────

    #[test]
    fn debounce_does_not_fire_below_threshold() {
        let mut db = Debounce::new();
        for i in 0..(DEBOUNCE_THRESHOLD - 1) {
            let result = db.update(true);
            assert!(
                result.is_none(),
                "debounce must not fire before threshold (count={i})"
            );
        }
    }

    #[test]
    fn debounce_fires_at_threshold() {
        let mut db = Debounce::new();
        for _ in 0..(DEBOUNCE_THRESHOLD - 1) {
            db.update(true);
        }
        let result = db.update(true);
        assert!(
            matches!(result, Some(KeyState::Pressed)),
            "debounce must emit Pressed after {DEBOUNCE_THRESHOLD} consecutive pressed readings"
        );
    }

    #[test]
    fn debounce_resets_on_noise() {
        let mut db = Debounce::new();
        // Feed threshold - 1 "pressed" readings.
        for _ in 0..(DEBOUNCE_THRESHOLD - 1) {
            db.update(true);
        }
        // One "released" reading should reset the count.
        db.update(false);
        // Next pressed reading restarts FROM count 1  -  should not fire.
        let result = db.update(true);
        assert!(
            result.is_none(),
            "after a noise pulse the debounce count must reset and not fire immediately"
        );
    }

    #[test]
    fn debounce_fires_released_after_press() {
        let mut db = Debounce::new();
        // Stabilise to pressed.
        for _ in 0..DEBOUNCE_THRESHOLD {
            db.update(true);
        }
        // Stabilise to released.
        for _ in 0..(DEBOUNCE_THRESHOLD - 1) {
            db.update(false);
        }
        let result = db.update(false);
        assert!(
            matches!(result, Some(KeyState::Released)),
            "debounce must emit Released after {DEBOUNCE_THRESHOLD} consecutive released readings"
        );
    }

    #[test]
    fn debounce_does_not_fire_twice_for_same_stable_state() {
        let mut db = Debounce::new();
        // Reach stable pressed.
        for _ in 0..DEBOUNCE_THRESHOLD {
            db.update(true);
        }
        // Continue feeding "pressed"  -  should not emit again.
        let result = db.update(true);
        assert!(
            result.is_none(),
            "debounce must not re-emit for a state that is already stable"
        );
    }

    // ── Key map ────────────────────────────────────────────────────────────────

    #[test]
    fn key_map_row0_is_1_2_3() {
        assert_eq!(
            KEY_MAP[0],
            [Key::Num1, Key::Num2, Key::Num3],
            "row 0 must map to keys 1 2 3"
        );
    }

    #[test]
    fn key_map_row3_is_star_0_hash() {
        assert_eq!(
            KEY_MAP[3],
            [Key::Star, Key::Num0, Key::Hash],
            "row 3 must map to * 0 #"
        );
    }

    // ── GpioKeypad matrix scan integration ────────────────────────────────────

    #[test]
    fn scan_no_keys_produces_no_events() {
        let mut kp = GpioKeypad::new();
        let mut q = InputQueue::new();
        for _ in 0..DEBOUNCE_THRESHOLD {
            kp.scan_with_matrix(KeyMatrix::none(), &mut q);
        }
        assert!(
            q.is_empty(),
            "no keys pressed must produce no events in the queue"
        );
    }

    #[test]
    fn scan_key_press_emits_after_debounce() {
        let mut kp = GpioKeypad::new();
        let mut q = InputQueue::new();
        let mut m = KeyMatrix::none();
        m.set(0, 0, true); // Num1

        // Below threshold: no events.
        for _ in 0..(DEBOUNCE_THRESHOLD - 1) {
            kp.scan_with_matrix(m, &mut q);
            assert!(
                q.is_empty(),
                "must not emit before debounce threshold is reached"
            );
        }

        // Exactly at threshold: Pressed event.
        kp.scan_with_matrix(m, &mut q);
        assert!(
            matches!(
                q.pop(),
                Some(InputEvent::Key {
                    key: Key::Num1,
                    state: KeyState::Pressed
                })
            ),
            "must emit Pressed for Num1 once debounce threshold is reached"
        );
    }

    #[test]
    fn scan_key_release_emits_after_debounce() {
        let mut kp = GpioKeypad::new();
        let mut q = InputQueue::new();
        let mut pressed = KeyMatrix::none();
        pressed.set(1, 1, true); // Num5

        // Stabilise to pressed.
        for _ in 0..DEBOUNCE_THRESHOLD {
            kp.scan_with_matrix(pressed, &mut q);
        }
        q.pop(); // consume Pressed

        // Now release.
        let released = KeyMatrix::none();
        for _ in 0..(DEBOUNCE_THRESHOLD - 1) {
            kp.scan_with_matrix(released, &mut q);
            assert!(
                q.is_empty(),
                "must not emit Released before threshold is reached"
            );
        }
        kp.scan_with_matrix(released, &mut q);
        assert!(
            matches!(
                q.pop(),
                Some(InputEvent::Key {
                    key: Key::Num5,
                    state: KeyState::Released
                })
            ),
            "must emit Released for Num5 once debounce threshold is reached"
        );
    }

    #[test]
    fn scan_multiple_simultaneous_keys() {
        let mut kp = GpioKeypad::new();
        let mut q = InputQueue::new();
        let mut m = KeyMatrix::none();
        m.set(0, 0, true); // Num1
        m.set(2, 2, true); // Num9

        for _ in 0..DEBOUNCE_THRESHOLD {
            kp.scan_with_matrix(m, &mut q);
        }

        let mut got_num1 = false;
        let mut got_num9 = false;
        while let Some(event) = q.pop() {
            match event {
                InputEvent::Key {
                    key: Key::Num1,
                    state: KeyState::Pressed,
                } => got_num1 = true,
                InputEvent::Key {
                    key: Key::Num9,
                    state: KeyState::Pressed,
                } => got_num9 = true,
                _ => {}
            }
        }
        assert!(got_num1, "simultaneous press must emit Pressed for Num1");
        assert!(got_num9, "simultaneous press must emit Pressed for Num9");
    }
}
