//! mtk-tpd touchscreen driver for the MT6739 / AGM M7.
//!
//! Communicates with the touch controller over I2C. Each poll reads
//! the touch-count register, then reads up to 10 touch-point records.
//! Coordinate ranges are validated against the physical display bounds
//! before events are emitted.
//!
//! A trait-based I2C abstraction is used so that both hardware and
//! test implementations can be substituted without `unsafe` in the
//! driver logic.

// NOTE: no_std  -  all core:: primitives only.

use crate::input::{InputEvent, InputQueue, TouchAction, TouchPoint};

// ── Hardware constants ────────────────────────────────────────────────────────

/// I2C address for the mtk-tpd touch controller.
///
/// NOTE: 0x38 is the mtk-tpd default. Unconfirmed for the AGM M7  - 
/// verify with `i2cdetect` on the stock Android kernel.
pub const TPD_I2C_ADDR: u8 = 0x38;

/// GPIO used for the touch interrupt (EINT).
///
/// NOTE: Placeholder  -  needs hardware probing on the AGM M7.
pub const TPD_EINT_GPIO: u8 = 1;

/// Register: current touch-point count (0–10).
const REG_TOUCH_COUNT: u8 = 0x00;

/// Register: base of touch-point data array.
///
/// Each record is 6 bytes: `X_hi`, `X_lo`, `Y_hi`, `Y_lo`, pressure, id.
/// The 12-bit X/Y coordinates are packed big-endian across two bytes.
const REG_TOUCH_DATA: u8 = 0x02;

/// Bytes per touch-point record in the register map.
const BYTES_PER_TOUCH: usize = 6;

/// Maximum number of simultaneous touch points.
const MAX_TOUCH_POINTS: usize = 10;

// ── Display boundary constants ────────────────────────────────────────────────

/// Maximum valid X coordinate (display width − 1).
pub(crate) const X_MAX: u16 = 240;

/// Maximum valid Y coordinate (display height − 1).
pub(crate) const Y_MAX: u16 = 320;

/// Maximum valid tracking ID.
pub(crate) const TRACKING_ID_MAX: u8 = 9;

// ── I2C abstraction ───────────────────────────────────────────────────────────

/// Minimal I2C bus trait required by the touchscreen driver.
///
/// Implementations exist for the real MT6739 I2C controller (bare-metal)
/// and for test doubles.
pub trait I2cBus {
    /// The error type for I2C operations on this bus.
    type Error: core::fmt::Debug;

    /// Write `reg` then read `buf.len()` bytes INTO `buf` FROM `addr`.
    ///
    /// This corresponds to a standard I2C write-then-read
    /// (repeated-start) transaction.
    fn write_read(&mut self, addr: u8, reg: u8, buf: &mut [u8]) -> Result<(), Self::Error>;
}

// ── Error type ────────────────────────────────────────────────────────────────

/// Errors produced by the touchscreen driver.
#[derive(Debug)]
#[non_exhaustive]
pub enum TouchError<E: core::fmt::Debug> {
    /// I2C bus transaction failed.
    I2c(E),

    /// The hardware reported more touch points than the maximum.
    TooManyTouches {
        /// Reported count.
        count: u8,
    },
}

// ── Raw touch record ──────────────────────────────────────────────────────────

/// A single parsed touch record read FROM the hardware registers.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct RawTouch {
    pub(crate) x: u16,
    pub(crate) y: u16,
    pub(crate) pressure: u8,
    pub(crate) tracking_id: u8,
}

// ── Coordinate validation ─────────────────────────────────────────────────────

/// Validate raw touch coordinates against hardware bounds.
///
/// Returns `None` when any field is out of range so the driver can
/// skip malformed hardware readings.
pub(crate) const fn validate_touch(raw: RawTouch) -> Option<TouchPoint> {
    if raw.x > X_MAX || raw.y > Y_MAX || raw.tracking_id > TRACKING_ID_MAX {
        return None;
    }
    Some(TouchPoint {
        x: raw.x,
        y: raw.y,
        pressure: raw.pressure,
        tracking_id: raw.tracking_id,
    })
}

// ── Packet parsing ────────────────────────────────────────────────────────────

/// Parse a single 6-byte touch record.
///
/// Register layout (mtk-tpd):
/// ```text
/// byte 0: X[11:8] (high nibble of X)
/// byte 1: X[7:0]  (low byte of X)
/// byte 2: Y[11:8] (high nibble of Y)
/// byte 3: Y[7:0]  (low byte of Y)
/// byte 4: pressure (0–255)
/// byte 5: tracking_id (0–9)
/// ```
///
/// Returns `None` when `data` is shorter than `BYTES_PER_TOUCH`.
pub(crate) fn parse_touch_record(data: &[u8]) -> Option<RawTouch> {
    if data.len() < BYTES_PER_TOUCH {
        return None;
    }
    // SAFETY: length checked above; indexing by known offsets is safe.
    let x_hi = u16::from(*data.first()?);
    let x_lo = u16::from(*data.get(1)?);
    let y_hi = u16::from(*data.get(2)?);
    let y_lo = u16::from(*data.get(3)?);
    let pressure = *data.get(4)?;
    let tracking_id = *data.get(5)?;

    // NOTE: mtk-tpd packs a 12-bit coordinate across two bytes.
    // The high nibble (bits 11:8) sits in the low nibble of byte 0;
    // byte 1 carries bits 7:0.
    let x = (x_hi & 0x0F) << 8 | x_lo;
    let y = (y_hi & 0x0F) << 8 | y_lo;

    Some(RawTouch {
        x,
        y,
        pressure,
        tracking_id,
    })
}

// ── TouchscreenDriver ─────────────────────────────────────────────────────────

/// State retained across polls to distinguish Down / Move / Up events.
///
/// Bit i is SET when `tracking_id` i was active on the previous poll.
#[derive(Clone, Copy, Debug, Default)]
struct ActiveMask(u16);

impl ActiveMask {
    fn is_active(self, id: u8) -> bool {
        (self.0 >> u16::from(id)) & 1 == 1
    }

    fn set(&mut self, id: u8, active: bool) {
        if active {
            self.0 |= 1 << u16::from(id);
        } else {
            self.0 &= !(1 << u16::from(id));
        }
    }
}

/// mtk-tpd multi-touch driver.
///
/// Call [`TouchscreenDriver::new`] once, then call [`TouchscreenDriver::poll`]
/// in the main input loop to push [`InputEvent`] VALUES.
pub struct TouchscreenDriver {
    /// I2C device address.
    addr: u8,
    /// Which tracking IDs were active on the previous poll.
    prev_active: ActiveMask,
}

impl TouchscreenDriver {
    /// Create a driver targeting `addr` on the I2C bus.
    ///
    /// Use [`TPD_I2C_ADDR`] for the default hardware address.
    pub const fn new(addr: u8) -> Self {
        Self {
            addr,
            prev_active: ActiveMask(0),
        }
    }

    /// Poll the touch controller and push any new events INTO `queue`.
    ///
    /// Reads the touch-count register, then reads all active touch-point
    /// records. For each point, emits [`TouchAction::Down`] on first
    /// contact, [`TouchAction::Move`] on subsequent polls while the
    /// finger remains, and [`TouchAction::Up`] for tracking IDs that
    /// disappeared since the last poll.
    ///
    /// Returns an error if the I2C bus transaction fails or the
    /// hardware reports an impossible touch count.
    pub fn poll<B: I2cBus>(
        &mut self,
        bus: &mut B,
        queue: &mut InputQueue,
    ) -> Result<(), TouchError<B::Error>> {
        // Read touch count.
        let mut count_buf = [0u8; 1];
        bus.write_read(self.addr, REG_TOUCH_COUNT, &mut count_buf)
            .map_err(TouchError::I2c)?;
        let count = count_buf.first().copied().unwrap_or_default();

        if usize::from(count) > MAX_TOUCH_POINTS {
            return Err(TouchError::TooManyTouches { count });
        }

        // Read all touch-point data in one transaction.
        let total_bytes = usize::from(count) * BYTES_PER_TOUCH;
        let mut raw_buf = [0u8; MAX_TOUCH_POINTS * BYTES_PER_TOUCH];
        if count > 0 {
            bus.write_read(self.addr, REG_TOUCH_DATA, &mut raw_buf[..total_bytes])
                .map_err(TouchError::I2c)?;
        }

        // Track which IDs are active this poll.
        let mut current_active = ActiveMask(0);

        for i in 0..usize::from(count) {
            let offset = i * BYTES_PER_TOUCH;
            let slice = raw_buf.get(offset..offset + BYTES_PER_TOUCH);
            let Some(record_bytes) = slice else {
                continue;
            };

            let Some(raw) = parse_touch_record(record_bytes) else {
                continue;
            };
            let Some(point) = validate_touch(raw) else {
                continue;
            };

            current_active.set(point.tracking_id, true);

            let action = if self.prev_active.is_active(point.tracking_id) {
                TouchAction::Move
            } else {
                TouchAction::Down
            };

            queue.push(InputEvent::Touch { action, point });
        }

        // Emit Up events for tracking IDs that were active last poll
        // but are absent this poll.
        for id in 0..=TRACKING_ID_MAX {
            if self.prev_active.is_active(id) && !current_active.is_active(id) {
                // WHY: The final position is unknown on Up; emit a zero-pressure
                // sentinel so the UI can dismiss the touch target cleanly.
                let point = TouchPoint {
                    x: 0,
                    y: 0,
                    pressure: 0,
                    tracking_id: id,
                };
                queue.push(InputEvent::Touch {
                    action: TouchAction::Up,
                    point,
                });
            }
        }

        self.prev_active = current_active;
        Ok(())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::collections::VecDeque;
    use std::vec;
    use std::vec::Vec;

    use super::*;
    use crate::input::{InputQueue, TouchAction};

    // ── Test I2C bus ───────────────────────────────────────────────────────────

    /// A scriptable I2C double.
    ///
    /// `reads` is consumed in FIFO ORDER for each `write_read` call.
    struct FakeBus {
        reads: VecDeque<Vec<u8>>,
    }

    impl FakeBus {
        fn new() -> Self {
            Self {
                reads: VecDeque::new(),
            }
        }

        fn push_read(&mut self, data: Vec<u8>) {
            self.reads.push_back(data);
        }
    }

    #[derive(Debug)]
    struct BusError;

    impl I2cBus for FakeBus {
        type Error = BusError;

        fn write_read(&mut self, _addr: u8, _reg: u8, buf: &mut [u8]) -> Result<(), BusError> {
            let data = self.reads.pop_front().unwrap_or_default();
            let len = buf.len().min(data.len());
            buf[..len].copy_from_slice(&data[..len]);
            Ok(())
        }
    }

    /// Build 6 raw bytes for a single touch point using the mtk-tpd layout.
    fn make_touch_bytes(x: u16, y: u16, pressure: u8, id: u8) -> Vec<u8> {
        vec![
            ((x >> 8) & 0x0F) as u8,
            (x & 0xFF) as u8,
            ((y >> 8) & 0x0F) as u8,
            (y & 0xFF) as u8,
            pressure,
            id,
        ]
    }

    // ── parse_touch_record ────────────────────────────────────────────────────

    #[test]
    fn parse_touch_record_extracts_coordinates() {
        let bytes = make_touch_bytes(120, 160, 100, 3);
        let raw = parse_touch_record(&bytes);
        assert!(raw.is_some(), "valid 6-byte record must parse successfully");
        let raw = raw.unwrap();
        assert_eq!(raw.x, 120, "parsed X must match encoded value");
        assert_eq!(raw.y, 160, "parsed Y must match encoded value");
        assert_eq!(
            raw.pressure, 100,
            "parsed pressure must match encoded value"
        );
        assert_eq!(
            raw.tracking_id, 3,
            "parsed tracking_id must match encoded value"
        );
    }

    #[test]
    fn parse_touch_record_max_coordinates() {
        let bytes = make_touch_bytes(X_MAX, Y_MAX, 255, TRACKING_ID_MAX);
        let raw = parse_touch_record(&bytes).unwrap_or_default();
        assert_eq!(raw.x, X_MAX, "max X must round-trip through parse");
        assert_eq!(raw.y, Y_MAX, "max Y must round-trip through parse");
        assert_eq!(
            raw.pressure, 255,
            "max pressure must round-trip through parse"
        );
        assert_eq!(
            raw.tracking_id, TRACKING_ID_MAX,
            "max tracking_id must round-trip through parse"
        );
    }

    #[test]
    fn parse_touch_record_zero_coordinates() {
        let bytes = make_touch_bytes(0, 0, 0, 0);
        let raw = parse_touch_record(&bytes).unwrap_or_default();
        assert_eq!(raw.x, 0, "zero X must round-trip");
        assert_eq!(raw.y, 0, "zero Y must round-trip");
    }

    #[test]
    fn parse_touch_record_short_buffer_returns_none() {
        let bytes = vec![0x00, 0x78, 0x00]; // only 3 bytes
        let raw = parse_touch_record(&bytes);
        assert!(
            raw.is_none(),
            "buffer shorter than BYTES_PER_TOUCH must return None"
        );
    }

    // ── validate_touch ────────────────────────────────────────────────────────

    #[test]
    fn validate_touch_accepts_boundary_values() {
        let raw = RawTouch {
            x: 0,
            y: 0,
            pressure: 0,
            tracking_id: 0,
        };
        assert!(
            validate_touch(raw).is_some(),
            "minimum-value touch must be valid"
        );

        let raw_max = RawTouch {
            x: X_MAX,
            y: Y_MAX,
            pressure: 255,
            tracking_id: TRACKING_ID_MAX,
        };
        assert!(
            validate_touch(raw_max).is_some(),
            "maximum-value touch must be valid"
        );
    }

    #[test]
    fn validate_touch_rejects_x_out_of_range() {
        let raw = RawTouch {
            x: X_MAX + 1,
            y: 100,
            pressure: 128,
            tracking_id: 0,
        };
        assert!(
            validate_touch(raw).is_none(),
            "X coordinate above X_MAX must be rejected"
        );
    }

    #[test]
    fn validate_touch_rejects_y_out_of_range() {
        let raw = RawTouch {
            x: 100,
            y: Y_MAX + 1,
            pressure: 128,
            tracking_id: 0,
        };
        assert!(
            validate_touch(raw).is_none(),
            "Y coordinate above Y_MAX must be rejected"
        );
    }

    #[test]
    fn validate_touch_rejects_tracking_id_out_of_range() {
        let raw = RawTouch {
            x: 100,
            y: 100,
            pressure: 128,
            tracking_id: TRACKING_ID_MAX + 1,
        };
        assert!(
            validate_touch(raw).is_none(),
            "tracking_id above TRACKING_ID_MAX must be rejected"
        );
    }

    // ── TouchscreenDriver integration ─────────────────────────────────────────

    #[test]
    fn poll_single_touch_down_emits_down_event() {
        let mut driver = TouchscreenDriver::new(TPD_I2C_ADDR);
        let mut bus = FakeBus::new();
        let mut q = InputQueue::new();

        // Count = 1, then 6 bytes for one touch point.
        bus.push_read(vec![1]);
        bus.push_read(make_touch_bytes(120, 160, 100, 0));

        driver.poll(&mut bus, &mut q).unwrap_or_default();

        assert_eq!(q.len(), 1, "one touch down must emit exactly one event");
        let event = q.pop().expect("queue must have one event after poll");
        assert!(
            matches!(
                event,
                InputEvent::Touch {
                    action: TouchAction::Down,
                    ..
                }
            ),
            "first contact must emit a Down event"
        );
        if let InputEvent::Touch { point, .. } = event {
            assert_eq!(point.x, 120, "Down event must carry correct X");
            assert_eq!(point.y, 160, "Down event must carry correct Y");
            assert_eq!(
                point.pressure, 100,
                "Down event must carry correct pressure"
            );
            assert_eq!(
                point.tracking_id, 0,
                "Down event must carry correct tracking_id"
            );
        }
    }

    #[test]
    fn poll_second_contact_at_same_id_emits_move() {
        let mut driver = TouchscreenDriver::new(TPD_I2C_ADDR);
        let mut bus = FakeBus::new();
        let mut q = InputQueue::new();

        // First poll: Down.
        bus.push_read(vec![1]);
        bus.push_read(make_touch_bytes(50, 50, 128, 0));
        driver
            .poll(&mut bus, &mut q)
            .unwrap_or_default();
        q.pop(); // consume Down

        // Second poll with same tracking_id: Move.
        bus.push_read(vec![1]);
        bus.push_read(make_touch_bytes(60, 70, 128, 0));
        driver
            .poll(&mut bus, &mut q)
            .unwrap_or_default();

        let event = q.pop().expect("queue must have one event after second poll");
        assert!(
            matches!(
                event,
                InputEvent::Touch {
                    action: TouchAction::Move,
                    ..
                }
            ),
            "second contact at same tracking_id must emit Move"
        );
    }

    #[test]
    fn poll_finger_lifted_emits_up() {
        let mut driver = TouchscreenDriver::new(TPD_I2C_ADDR);
        let mut bus = FakeBus::new();
        let mut q = InputQueue::new();

        // First poll: Down.
        bus.push_read(vec![1]);
        bus.push_read(make_touch_bytes(100, 200, 150, 1));
        driver
            .poll(&mut bus, &mut q)
            .unwrap_or_default();
        q.pop(); // consume Down

        // Second poll: finger lifted (count = 0).
        bus.push_read(vec![0]);
        driver.poll(&mut bus, &mut q).unwrap_or_default();

        let event = q.pop().expect("queue must have one Up event after finger lifted");
        assert!(
            matches!(
                event,
                InputEvent::Touch {
                    action: TouchAction::Up,
                    ..
                }
            ),
            "tracking_id disappearing between polls must emit Up"
        );
        if let InputEvent::Touch { point, .. } = event {
            assert_eq!(
                point.tracking_id, 1,
                "Up event must carry the correct tracking_id"
            );
        }
    }

    #[test]
    fn poll_multi_touch_two_fingers() {
        let mut driver = TouchscreenDriver::new(TPD_I2C_ADDR);
        let mut bus = FakeBus::new();
        let mut q = InputQueue::new();

        // Count = 2, then 12 bytes for two touch points.
        bus.push_read(vec![2]);
        let mut data = make_touch_bytes(10, 20, 100, 0);
        data.extend(make_touch_bytes(200, 300, 80, 1));
        bus.push_read(data);

        driver
            .poll(&mut bus, &mut q)
            .unwrap_or_default();

        assert_eq!(q.len(), 2, "two simultaneous touches must emit two events");

        let e1 = q.pop().expect("queue must have first of two Down events");
        let e2 = q.pop().expect("queue must have second of two Down events");
        assert!(
            matches!(
                &e1,
                InputEvent::Touch {
                    action: TouchAction::Down,
                    ..
                }
            ),
            "first multi-touch event must be Down"
        );
        assert!(
            matches!(
                &e2,
                InputEvent::Touch {
                    action: TouchAction::Down,
                    ..
                }
            ),
            "second multi-touch event must be Down"
        );
    }

    #[test]
    fn poll_zero_touches_no_events_and_no_up_when_no_prior_state() {
        let mut driver = TouchscreenDriver::new(TPD_I2C_ADDR);
        let mut bus = FakeBus::new();
        let mut q = InputQueue::new();

        bus.push_read(vec![0]);
        driver
            .poll(&mut bus, &mut q)
            .unwrap_or_default();

        assert!(
            q.is_empty(),
            "zero touches with no prior state must not emit any events"
        );
    }

    #[test]
    fn poll_out_of_range_coordinate_is_dropped() {
        let mut driver = TouchscreenDriver::new(TPD_I2C_ADDR);
        let mut bus = FakeBus::new();
        let mut q = InputQueue::new();

        // X = 0xFFF (4095), way out of range.
        let bad = vec![0x0F, 0xFF, 0x00, 0xA0, 100, 0];
        bus.push_read(vec![1]);
        bus.push_read(bad);

        driver
            .poll(&mut bus, &mut q)
            .unwrap_or_default();
        assert!(
            q.is_empty(),
            "out-of-range coordinates must be silently dropped"
        );
    }

    #[test]
    fn poll_multi_touch_event_ordering_matches_register_order() {
        let mut driver = TouchscreenDriver::new(TPD_I2C_ADDR);
        let mut bus = FakeBus::new();
        let mut q = InputQueue::new();

        bus.push_read(vec![3]);
        let mut data = make_touch_bytes(10, 10, 50, 0);
        data.extend(make_touch_bytes(100, 100, 60, 1));
        data.extend(make_touch_bytes(200, 200, 70, 2));
        bus.push_read(data);

        driver
            .poll(&mut bus, &mut q)
            .unwrap_or_default();
        assert_eq!(
            q.len(),
            3,
            "three simultaneous touches must produce three events"
        );

        // Events must arrive in register-read ORDER (id 0, 1, 2).
        for expected_id in 0u8..3 {
            let event = q.pop().expect("queue must have event for each touch id");
            if let InputEvent::Touch { point, .. } = event {
                assert_eq!(
                    point.tracking_id, expected_id,
                    "event ORDER must match register read ORDER (expected id {expected_id})"
                );
            } else {
                panic!("expected Touch event, got Key event");
            }
        }
    }
}
