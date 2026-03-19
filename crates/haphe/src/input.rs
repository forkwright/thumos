//! Input event subsystem.
//!
//! Unified input abstraction for keypad and touchscreen. Produces
//! `InputEvent` values that the UI (eidolon) consumes. The actual
//! hardware drivers (`GPIO` keypad scan, touch I2C) feed into this.
//!
//! Event types mirror Linux's input event model (`EV_KEY`, `EV_ABS`)
//! but simplified for our needs.

/// Physical key codes for the AGM M7 21-key keypad.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Key {
    /// Number keys
    Num0 = 0,
    Num1 = 1,
    Num2 = 2,
    Num3 = 3,
    Num4 = 4,
    Num5 = 5,
    Num6 = 6,
    Num7 = 7,
    Num8 = 8,
    Num9 = 9,
    /// Star (*)
    Star = 10,
    /// Hash (#)
    Hash = 11,
    /// Navigation
    Up = 12,
    Down = 13,
    Left = 14,
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
pub enum KeyState {
    /// Key pressed down.
    Pressed,
    /// Key released.
    Released,
    /// Key held (repeat).
    Held,
}

/// Touch event type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TouchAction {
    /// Finger touched the screen.
    Down,
    /// Finger moved on the screen.
    Move,
    /// Finger lifted from the screen.
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
pub enum InputEvent {
    /// Keypad key event.
    Key { key: Key, state: KeyState },
    /// Touchscreen event.
    Touch {
        action: TouchAction,
        point: TouchPoint,
    },
}

/// Input event queue (ring buffer).
pub struct InputQueue {
    events: [Option<InputEvent>; 64],
    head: usize,
    tail: usize,
    count: usize,
}

impl Default for InputQueue {
    fn default() -> Self { Self::new() }
}

impl InputQueue {
    /// Create an empty input queue.
    pub const fn new() -> Self {
        const NONE: Option<InputEvent> = None;
        Self {
            events: [NONE; 64],
            head: 0,
            tail: 0,
            count: 0,
        }
    }

    /// Push an event. Drops oldest if full.
    pub fn push(&mut self, event: InputEvent) {
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
    pub fn pop(&mut self) -> Option<InputEvent> {
        if self.count == 0 {
            return None;
        }
        let event = self.events[self.head].take();
        self.head = (self.head + 1) % 64;
        self.count -= 1;
        event
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Number of pending events.
    pub fn len(&self) -> usize {
        self.count
    }
}

/// T9 predictive text input state.
pub struct T9Input {
    /// Current key sequence (e.g., [2, 2, 3] for "ad" or "be" etc.).
    keys: [u8; 32],
    /// Number of keys in the sequence.
    len: usize,
    /// Current candidate index (cycle through options per key press).
    candidate: usize,
}

impl Default for T9Input {
    fn default() -> Self { Self::new() }
}

impl T9Input {
    /// Create a new T9 input state.
    pub const fn new() -> Self {
        Self {
            keys: [0; 32],
            len: 0,
            candidate: 0,
        }
    }

    /// Get the characters mapped to a key (standard phone keypad).
    pub fn key_chars(key: Key) -> &'static [char] {
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
    pub fn press(&mut self, key: Key) -> Option<char> {
        let chars = Self::key_chars(key);
        if chars.is_empty() {
            return None;
        }

        if self.len > 0 && self.keys[self.len - 1] == key as u8 {
            // Same key pressed again — cycle through characters
            self.candidate = (self.candidate + 1) % chars.len();
        } else {
            // New key — commit previous and start new character
            if self.len < 32 {
                self.keys[self.len] = key as u8;
                self.len += 1;
            }
            self.candidate = 0;
        }

        Some(chars[self.candidate])
    }

    /// Clear the input buffer.
    pub fn clear(&mut self) {
        self.len = 0;
        self.candidate = 0;
    }
}
