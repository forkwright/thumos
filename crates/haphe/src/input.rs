//! Input event subsystem.
//!
//! Unified input abstraction for keypad and touchscreen. Produces
//! `InputEvent` VALUES that the UI (eidolon) consumes. The actual
//! hardware drivers (`GPIO` keypad scan, touch I2C) feed INTO this.
//!
//! Event types mirror Linux's input event model (`EV_KEY`, `EV_ABS`)
//! but simplified for our needs.

/// Physical key codes for the AGM M7 21-key keypad.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
#[non_exhaustive]
pub enum Key {
    /// Digit 0 key.
    Num0 = 0,
    /// Digit 1 key.
    Num1 = 1,
    /// Digit 2 key.
    Num2 = 2,
    /// Digit 3 key.
    Num3 = 3,
    /// Digit 4 key.
    Num4 = 4,
    /// Digit 5 key.
    Num5 = 5,
    /// Digit 6 key.
    Num6 = 6,
    /// Digit 7 key.
    Num7 = 7,
    /// Digit 8 key.
    Num8 = 8,
    /// Digit 9 key.
    Num9 = 9,
    /// Star (*)
    Star = 10,
    /// Hash (#)
    Hash = 11,
    /// D-pad up.
    Up = 12,
    /// D-pad down.
    Down = 13,
    /// D-pad left.
    Left = 14,
    /// D-pad right.
    Right = 15,
    /// Center/OK/Select
    Select = 16,
    /// Call (green phone)
    Call = 17,
    /// End/Power (red phone)
    End = 18,
    /// Side button (programmable)
    Side = 19,
    /// Volume up
    VolUp = 20,
    /// Volume down
    VolDown = 21,
}

/// Key state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub(crate) enum KeyState {
    /// Key pressed down.
    Pressed,
    /// Key released.
    Released,
    /// Key held (repeat).
    Held,
}

/// Touch event type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub(crate) enum TouchAction {
    /// Finger touched the screen.
    Down,
    /// Finger moved on the screen.
    Move,
    /// Finger lifted FROM the screen.
    Up,
}

/// Touch point with coordinates and pressure.
#[derive(Debug, Clone, Copy)]
pub struct TouchPoint {
    /// X coordinate (0-240).
    pub x: u16,
    /// Y coordinate (0-320).
    pub y: u16,
    /// Pressure (0-255, 0 = no contact).
    pub pressure: u8,
    /// Tracking ID for multi-touch (0-9).
    pub tracking_id: u8,
}

/// Unified input event.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub(crate) enum InputEvent {
    /// Keypad key event.
    Key {
        /// Which key was pressed.
        key: Key,
        /// Press, release, or held.
        state: KeyState,
    },
    /// Touchscreen event.
    Touch {
        /// Touch action type.
        action: TouchAction,
        /// Touch coordinates and pressure.
        point: TouchPoint,
    },
}

/// Input event queue (ring buffer).
pub(crate) struct InputQueue {
    events: [Option<InputEvent>; 64],
    head: usize,
    tail: usize,
    count: usize,
}

impl Default for InputQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl InputQueue {
    /// Create an empty input queue.
    pub(crate) const fn new() -> Self {
        const NONE: Option<InputEvent> = None;
        Self {
            events: [NONE; 64],
            head: 0,
            tail: 0,
            count: 0,
        }
    }

    /// Push an event. Drops oldest if full.
    pub(crate) const fn push(&mut self, event: InputEvent) {
        if self.count >= 64 {
            // Drop oldest
            self.head = (self.head + 1) % 64;
            self.count -= 1;
        }
        self.events[self.tail] = Some(event);
        self.tail = (self.tail + 1) % 64;
        self.count += 1;
    }

    /// Pop the next event.
    pub(crate) const fn pop(&mut self) -> Option<InputEvent> {
        if self.count == 0 {
            return None;
        }
        let event = self.events[self.head].take();
        self.head = (self.head + 1) % 64;
        self.count -= 1;
        event
    }

    /// Check if empty.
    pub(crate) const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Number of pending events.
    pub(crate) const fn len(&self) -> usize {
        self.count
    }
}

/// T9 predictive text input state.
pub(crate) struct T9Input {
    /// Current key sequence (e.g., [2, 2, 3] for "ad" or "be" etc.).
    keys: [u8; 32],
    /// Number of keys in the sequence.
    len: usize,
    /// Current candidate index (cycle through options per key press).
    candidate: usize,
}

impl Default for T9Input {
    fn default() -> Self {
        Self::new()
    }
}

impl T9Input {
    /// Create a new T9 input state.
    pub(crate) const fn new() -> Self {
        Self {
            keys: [0; 32],
            len: 0,
            candidate: 0,
        }
    }

    /// Get the characters mapped to a key (standard phone keypad).
    pub(crate) const fn key_chars(key: Key) -> &'static [char] {
        match key {
            Key::Num0 => &[' ', '0'],
            Key::Num1 => &['.', ',', '!', '?', '1'],
            Key::Num2 => &['a', 'b', 'c', '2'],
            Key::Num3 => &['d', 'e', 'f', '3'],
            Key::Num4 => &['g', 'h', 'i', '4'],
            Key::Num5 => &['j', 'k', 'l', '5'],
            Key::Num6 => &['m', 'n', 'o', '6'],
            Key::Num7 => &['p', 'q', 'r', 's', '7'],
            Key::Num8 => &['t', 'u', 'v', '8'],
            Key::Num9 => &['w', 'x', 'y', 'z', '9'],
            Key::Star => &['*', '+'],
            Key::Hash => &['#'],
            _ => &[],
        }
    }

    /// Press a key. Returns the current character selection.
    pub(crate) fn press(&mut self, key: Key) -> Option<char> {
        let chars = Self::key_chars(key);
        if chars.is_empty() {
            return None;
        }

        // SAFETY: Key is #[repr(u8)], so the discriminant always fits in u8.
        let key_discriminant = key as u8;
        if self.len > 0 && self.keys[self.len - 1] == key_discriminant {
            // Same key pressed again  -  cycle through characters
            self.candidate = (self.candidate + 1) % chars.len();
        } else {
            // New key  -  commit previous and start new character
            if self.len < 32 {
                self.keys[self.len] = key_discriminant;
                self.len += 1;
            }
            self.candidate = 0;
        }

        Some(chars[self.candidate])
    }

    /// Clear the input buffer.
    pub(crate) const fn clear(&mut self) {
        self.len = 0;
        self.candidate = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- InputQueue ---

    #[test]
    fn input_queue_push_and_pop_returns_event() {
        let mut q = InputQueue::new();
        q.push(InputEvent::Key {
            key: Key::Num1,
            state: KeyState::Pressed,
        });
        let result = q.pop();
        assert!(result.is_some(), "pop must return Some after a push");
        assert!(
            matches!(
                result,
                Some(InputEvent::Key {
                    key: Key::Num1,
                    state: KeyState::Pressed
                })
            ),
            "popped event must match the pushed key and state"
        );
    }

    #[test]
    fn input_queue_empty_pop_returns_none() {
        let mut q = InputQueue::new();
        assert!(q.pop().is_none(), "empty queue must return None on pop");
    }

    #[test]
    fn input_queue_fifo_ordering() {
        let mut q = InputQueue::new();
        q.push(InputEvent::Key {
            key: Key::Num1,
            state: KeyState::Pressed,
        });
        q.push(InputEvent::Key {
            key: Key::Num2,
            state: KeyState::Pressed,
        });
        q.push(InputEvent::Key {
            key: Key::Num3,
            state: KeyState::Pressed,
        });

        assert!(
            matches!(q.pop(), Some(InputEvent::Key { key: Key::Num1, .. })),
            "first pop must return the first pushed event (Num1)"
        );
        assert!(
            matches!(q.pop(), Some(InputEvent::Key { key: Key::Num2, .. })),
            "second pop must return the second pushed event (Num2)"
        );
        assert!(
            matches!(q.pop(), Some(InputEvent::Key { key: Key::Num3, .. })),
            "third pop must return the third pushed event (Num3)"
        );
    }

    #[test]
    fn input_queue_full_drops_oldest() {
        let mut q = InputQueue::new();
        // Fill to capacity: first event is VolDown (sentinel), rest are Num0.
        q.push(InputEvent::Key {
            key: Key::VolDown,
            state: KeyState::Pressed,
        });
        for _ in 1..64 {
            q.push(InputEvent::Key {
                key: Key::Num0,
                state: KeyState::Pressed,
            });
        }
        // 65th push must DROP VolDown (the oldest).
        q.push(InputEvent::Key {
            key: Key::VolUp,
            state: KeyState::Pressed,
        });

        assert_eq!(
            q.len(),
            64,
            "queue length must remain 64 after overflow push"
        );
        assert!(
            matches!(q.pop(), Some(InputEvent::Key { key: Key::Num0, .. })),
            "oldest event (VolDown) must be dropped; next in line is Num0"
        );
        // Drain the 62 remaining Num0 events.
        for _ in 0..62 {
            q.pop();
        }
        assert!(
            matches!(
                q.pop(),
                Some(InputEvent::Key {
                    key: Key::VolUp,
                    ..
                })
            ),
            "last event must be VolUp (the 65th push)"
        );
    }

    #[test]
    fn input_queue_len_and_is_empty() {
        let mut q = InputQueue::new();
        assert!(
            q.is_empty(),
            "newly created queue must report is_empty true"
        );
        assert_eq!(q.len(), 0, "newly created queue must have length 0");

        q.push(InputEvent::Key {
            key: Key::Select,
            state: KeyState::Pressed,
        });
        assert!(!q.is_empty(), "queue must not be empty after a push");
        assert_eq!(q.len(), 1, "queue length must be 1 after a single push");

        q.pop();
        assert!(
            q.is_empty(),
            "queue must be empty after the only event is popped"
        );
        assert_eq!(
            q.len(),
            0,
            "queue length must return to 0 after popping all events"
        );
    }

    // --- T9Input ---

    #[test]
    fn t9_key_chars_num0_maps_space_and_digit() {
        let chars = T9Input::key_chars(Key::Num0);
        assert_eq!(chars, &[' ', '0'], "Num0 must map to space then '0'");
    }

    #[test]
    fn t9_key_chars_all_number_keys_and_symbols() {
        assert_eq!(
            T9Input::key_chars(Key::Num1),
            &['.', ',', '!', '?', '1'],
            "Num1 chars mismatch"
        );
        assert_eq!(
            T9Input::key_chars(Key::Num2),
            &['a', 'b', 'c', '2'],
            "Num2 chars mismatch"
        );
        assert_eq!(
            T9Input::key_chars(Key::Num3),
            &['d', 'e', 'f', '3'],
            "Num3 chars mismatch"
        );
        assert_eq!(
            T9Input::key_chars(Key::Num4),
            &['g', 'h', 'i', '4'],
            "Num4 chars mismatch"
        );
        assert_eq!(
            T9Input::key_chars(Key::Num5),
            &['j', 'k', 'l', '5'],
            "Num5 chars mismatch"
        );
        assert_eq!(
            T9Input::key_chars(Key::Num6),
            &['m', 'n', 'o', '6'],
            "Num6 chars mismatch"
        );
        assert_eq!(
            T9Input::key_chars(Key::Num7),
            &['p', 'q', 'r', 's', '7'],
            "Num7 chars mismatch"
        );
        assert_eq!(
            T9Input::key_chars(Key::Num8),
            &['t', 'u', 'v', '8'],
            "Num8 chars mismatch"
        );
        assert_eq!(
            T9Input::key_chars(Key::Num9),
            &['w', 'x', 'y', 'z', '9'],
            "Num9 chars mismatch"
        );
        assert_eq!(
            T9Input::key_chars(Key::Star),
            &['*', '+'],
            "Star chars mismatch"
        );
        assert_eq!(T9Input::key_chars(Key::Hash), &['#'], "Hash chars mismatch");
    }

    #[test]
    fn t9_single_press_returns_first_char() {
        let mut t9 = T9Input::new();
        assert_eq!(
            t9.press(Key::Num2),
            Some('a'),
            "first press of Num2 must return 'a'"
        );
    }

    #[test]
    fn t9_same_key_cycles_through_chars_and_wraps() {
        let mut t9 = T9Input::new();
        // Num2 maps to: a b c 2
        assert_eq!(t9.press(Key::Num2), Some('a'), "1st press must return 'a'");
        assert_eq!(t9.press(Key::Num2), Some('b'), "2nd press must return 'b'");
        assert_eq!(t9.press(Key::Num2), Some('c'), "3rd press must return 'c'");
        assert_eq!(t9.press(Key::Num2), Some('2'), "4th press must return '2'");
        assert_eq!(
            t9.press(Key::Num2),
            Some('a'),
            "5th press must wrap around to 'a'"
        );
    }

    #[test]
    fn t9_different_key_starts_at_first_char() {
        let mut t9 = T9Input::new();
        assert_eq!(
            t9.press(Key::Num2),
            Some('a'),
            "first key must start at 'a'"
        );
        // A different key must reset the candidate index.
        assert_eq!(
            t9.press(Key::Num3),
            Some('d'),
            "different key must start at first char of its mapping"
        );
    }

    #[test]
    fn t9_clear_resets_cycling_state() {
        let mut t9 = T9Input::new();
        t9.press(Key::Num2); // 'a'
        t9.press(Key::Num2); // 'b'
        t9.clear();
        assert_eq!(
            t9.press(Key::Num2),
            Some('a'),
            "after clear, press must restart at first char"
        );
    }

    #[test]
    fn t9_non_mappable_keys_return_none() {
        let mut t9 = T9Input::new();
        assert!(
            t9.press(Key::Up).is_none(),
            "Up must return None (no T9 mapping)"
        );
        assert!(
            t9.press(Key::Down).is_none(),
            "Down must return None (no T9 mapping)"
        );
        assert!(
            t9.press(Key::Select).is_none(),
            "Select must return None (no T9 mapping)"
        );
        assert!(
            t9.press(Key::Call).is_none(),
            "Call must return None (no T9 mapping)"
        );
        assert!(
            t9.press(Key::End).is_none(),
            "End must return None (no T9 mapping)"
        );
    }

    // --- TouchPoint ---

    #[test]
    fn touch_point_coordinate_bounds() {
        let min = TouchPoint {
            x: 0,
            y: 0,
            pressure: 0,
            tracking_id: 0,
        };
        assert_eq!(min.x, 0, "x must support minimum value 0");
        assert_eq!(min.y, 0, "y must support minimum value 0");

        let max = TouchPoint {
            x: 240,
            y: 320,
            pressure: 255,
            tracking_id: 0,
        };
        assert_eq!(max.x, 240, "x must support maximum value 240");
        assert_eq!(max.y, 320, "y must support maximum value 320");
    }

    #[test]
    fn touch_point_pressure_range() {
        let no_contact = TouchPoint {
            x: 0,
            y: 0,
            pressure: 0,
            tracking_id: 0,
        };
        assert_eq!(
            no_contact.pressure, 0,
            "pressure 0 must indicate no contact"
        );

        let full_press = TouchPoint {
            x: 0,
            y: 0,
            pressure: 255,
            tracking_id: 0,
        };
        assert_eq!(full_press.pressure, 255, "pressure 255 must be maximum");
    }

    #[test]
    fn touch_point_tracking_id_range() {
        let first = TouchPoint {
            x: 0,
            y: 0,
            pressure: 100,
            tracking_id: 0,
        };
        assert_eq!(
            first.tracking_id, 0,
            "tracking_id must support minimum value 0"
        );

        let last = TouchPoint {
            x: 0,
            y: 0,
            pressure: 100,
            tracking_id: 9,
        };
        assert_eq!(
            last.tracking_id, 9,
            "tracking_id must support maximum value 9"
        );
    }

    // --- InputEvent ---

    #[test]
    fn input_event_key_construction_and_matching() {
        let event = InputEvent::Key {
            key: Key::Select,
            state: KeyState::Held,
        };
        assert!(
            matches!(
                event,
                InputEvent::Key {
                    key: Key::Select,
                    state: KeyState::Held
                }
            ),
            "Key event must preserve the key variant and state"
        );
    }

    #[test]
    fn input_event_touch_construction_and_matching() {
        let point = TouchPoint {
            x: 120,
            y: 160,
            pressure: 100,
            tracking_id: 2,
        };
        let event = InputEvent::Touch {
            action: TouchAction::Move,
            point,
        };
        assert!(
            matches!(
                event,
                InputEvent::Touch {
                    action: TouchAction::Move,
                    ..
                }
            ),
            "Touch event must preserve the action variant"
        );
        if let InputEvent::Touch { point, .. } = event {
            assert_eq!(point.x, 120, "Touch event must preserve x coordinate");
            assert_eq!(point.y, 160, "Touch event must preserve y coordinate");
            assert_eq!(point.pressure, 100, "Touch event must preserve pressure");
            assert_eq!(
                point.tracking_id, 2,
                "Touch event must preserve tracking id"
            );
        }
    }
}
