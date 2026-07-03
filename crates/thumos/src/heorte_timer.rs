//! Timer and stopwatch for the Heorte engine.
//!
//! Provides [`Timer`] (countdown) and [`Stopwatch`] (count-up with lap
//! recording). Both use tick-based timing: callers pass the current kernel
//! tick count and the engine computes elapsed time from deltas.

// WHY: timers are compiled and tested through heorte but are not owned by a
// boot-time runtime manager yet.
#![expect(dead_code, reason = "Heorte timer runtime is not wired into kinit")]

extern crate alloc;
use alloc::vec::Vec;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of stopwatch laps stored. Oldest evicted beyond this.
const MAX_LAPS: usize = 50;

// ---------------------------------------------------------------------------
// Timer
// ---------------------------------------------------------------------------

/// Countdown timer.
///
/// Tracks a set duration and computes remaining time based on the kernel
/// tick count (milliseconds). The timer can be started, paused, and reset.
#[derive(Debug, Clone)]
pub struct Timer {
    /// Total duration in seconds.
    pub duration_secs: u32,
    /// Remaining seconds (computed on query, cached for display).
    pub remaining_secs: u32,
    /// Whether the timer is actively counting down.
    pub running: bool,
    /// Kernel tick (ms) when the timer was last started or resumed.
    pub started_tick: u64,
}

impl Timer {
    /// Create a new timer with zero duration.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            duration_secs: 0,
            remaining_secs: 0,
            running: false,
            started_tick: 0,
        }
    }

    /// Set the timer duration and reset state.
    pub(crate) fn set_duration(&mut self, secs: u32) {
        self.duration_secs = secs;
        self.remaining_secs = secs;
        self.running = false;
        self.started_tick = 0;
    }

    /// Start or resume the countdown from the current tick.
    pub(crate) fn start(&mut self, current_tick: u64) {
        if !self.running && self.remaining_secs > 0 {
            self.running = true;
            self.started_tick = current_tick;
        }
    }

    /// Pause the countdown, preserving remaining time.
    pub(crate) fn pause(&mut self, current_tick: u64) {
        if self.running {
            self.update(current_tick);
            self.running = false;
        }
    }

    /// Reset the timer to its original duration.
    pub(crate) fn reset(&mut self) {
        self.remaining_secs = self.duration_secs;
        self.running = false;
        self.started_tick = 0;
    }

    /// Update remaining seconds from the current tick.
    ///
    /// Called each render cycle (or on query) to recompute remaining time.
    /// Returns `true` if the timer has expired (reached zero).
    pub(crate) fn update(&mut self, current_tick: u64) -> bool {
        if !self.running {
            return self.remaining_secs == 0 && self.duration_secs > 0;
        }

        let elapsed_ms = current_tick.saturating_sub(self.started_tick);
        let elapsed_secs = (elapsed_ms / 1000) as u32;

        if elapsed_secs >= self.remaining_secs {
            self.remaining_secs = 0;
            self.running = false;
            return true;
        }

        self.remaining_secs = self.remaining_secs.saturating_sub(elapsed_secs);
        // WHY: advance the epoch by only the consumed whole seconds, not to
        // current_tick, so the sub-second remainder (elapsed_ms % 1000)
        // carries forward into the next update() instead of being
        // discarded — a timer polled faster than 1 Hz must still advance
        // wall-clock seconds (#342).
        self.started_tick = self
            .started_tick
            .saturating_add(u64::from(elapsed_secs) * 1000);
        false
    }

    /// Whether the timer has expired.
    pub(crate) fn expired(&self) -> bool {
        self.duration_secs > 0 && self.remaining_secs == 0 && !self.running
    }

    /// Format remaining time as `MM:SS`.
    pub(crate) fn format_remaining(&self) -> [u8; 5] {
        let m = (self.remaining_secs / 60).min(99);
        let s = self.remaining_secs % 60;
        [
            b'0' + (m / 10) as u8,
            b'0' + (m % 10) as u8,
            b':',
            b'0' + (s / 10) as u8,
            b'0' + (s % 10) as u8,
        ]
    }
}

impl core::fmt::Display for Timer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let buf = self.format_remaining();
        let s = core::str::from_utf8(&buf).unwrap_or("??:??");
        write!(f, "{s}")
    }
}

// ---------------------------------------------------------------------------
// Stopwatch
// ---------------------------------------------------------------------------

/// Count-up stopwatch with lap recording.
///
/// Elapsed time is tracked in milliseconds. Laps record cumulative split
/// times; the display shows per-lap deltas. Maximum [`MAX_LAPS`] laps;
/// oldest is evicted when full.
#[derive(Debug, Clone)]
pub struct Stopwatch {
    /// Total elapsed milliseconds (accumulated across start/stop cycles).
    pub elapsed_ms: u64,
    /// Whether the stopwatch is currently running.
    pub running: bool,
    /// Kernel tick (ms) when the stopwatch was last started or resumed.
    pub started_tick: u64,
    /// Cumulative lap split times in milliseconds.
    pub laps: Vec<u64>,
}

impl Stopwatch {
    /// Create a new stopwatch in the stopped state.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            elapsed_ms: 0,
            running: false,
            started_tick: 0,
            laps: Vec::new(),
        }
    }

    /// Start or resume the stopwatch.
    pub(crate) fn start(&mut self, current_tick: u64) {
        if !self.running {
            self.running = true;
            self.started_tick = current_tick;
        }
    }

    /// Stop the stopwatch, preserving elapsed time.
    pub(crate) fn stop(&mut self, current_tick: u64) {
        if self.running {
            self.elapsed_ms += current_tick.saturating_sub(self.started_tick);
            self.running = false;
        }
    }

    /// Reset the stopwatch to zero.
    pub(crate) fn reset(&mut self) {
        self.elapsed_ms = 0;
        self.running = false;
        self.started_tick = 0;
        self.laps.clear();
    }

    /// Record a lap at the current tick.
    ///
    /// Stores the cumulative elapsed time as a lap marker. If the lap
    /// list exceeds [`MAX_LAPS`], the oldest lap is removed.
    pub(crate) fn lap(&mut self, current_tick: u64) {
        if !self.running {
            return;
        }

        let current_elapsed = self.elapsed_ms + current_tick.saturating_sub(self.started_tick);
        if self.laps.len() >= MAX_LAPS {
            self.laps.remove(0);
        }
        self.laps.push(current_elapsed);
    }

    /// Get the current total elapsed time in milliseconds.
    pub(crate) fn current_elapsed(&self, current_tick: u64) -> u64 {
        if self.running {
            self.elapsed_ms + current_tick.saturating_sub(self.started_tick)
        } else {
            self.elapsed_ms
        }
    }

    /// Get per-lap duration (delta between consecutive laps) in milliseconds.
    ///
    /// Returns an iterator of `(lap_number, duration_ms)` pairs, 1-indexed.
    pub(crate) fn lap_durations(&self) -> Vec<(usize, u64)> {
        let mut result = Vec::with_capacity(self.laps.len());
        let mut prev = 0u64;
        for (i, &cumulative) in self.laps.iter().enumerate() {
            result.push((i + 1, cumulative.saturating_sub(prev)));
            prev = cumulative;
        }
        result
    }

    /// Format elapsed time as `HH:MM:SS.mmm`.
    ///
    /// Returns a 12-byte buffer. Caller should convert to `&str` via
    /// `core::str::from_utf8`.
    pub(crate) fn format_elapsed(&self, current_tick: u64) -> [u8; 12] {
        format_elapsed_ms(self.current_elapsed(current_tick))
    }
}

impl core::fmt::Display for Stopwatch {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let ms = self.elapsed_ms;
        let secs = ms / 1000;
        write!(f, "{:02}:{:02}", secs / 60, secs % 60)
    }
}

/// Format milliseconds as `HH:MM:SS.mmm`.
pub(crate) fn format_elapsed_ms(ms: u64) -> [u8; 12] {
    let total_secs = ms / 1000;
    let millis = (ms % 1000) as u16;
    let hours = (total_secs / 3600).min(99);
    let minutes = (total_secs % 3600) / 60;
    let seconds = total_secs % 60;

    [
        b'0' + (hours / 10) as u8,
        b'0' + (hours % 10) as u8,
        b':',
        b'0' + (minutes / 10) as u8,
        b'0' + (minutes % 10) as u8,
        b':',
        b'0' + (seconds / 10) as u8,
        b'0' + (seconds % 10) as u8,
        b'.',
        b'0' + (millis / 100) as u8,
        b'0' + ((millis / 10) % 10) as u8,
        b'0' + (millis % 10) as u8,
    ]
}

/// Format milliseconds as `MM:SS.mmm` (compact, for lap display).
pub(crate) fn format_lap_ms(ms: u64) -> [u8; 9] {
    let total_secs = ms / 1000;
    let millis = (ms % 1000) as u16;
    let minutes = (total_secs / 60).min(99);
    let seconds = total_secs % 60;

    [
        b'0' + (minutes / 10) as u8,
        b'0' + (minutes % 10) as u8,
        b':',
        b'0' + (seconds / 10) as u8,
        b'0' + (seconds % 10) as u8,
        b'.',
        b'0' + (millis / 100) as u8,
        b'0' + ((millis / 10) % 10) as u8,
        b'0' + (millis % 10) as u8,
    ]
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timer_countdown_updates() {
        let mut timer = Timer::new();
        timer.set_duration(300); // 5 minutes
        assert_eq!(timer.remaining_secs, 300);

        timer.start(1000); // start at tick 1000ms
        assert!(timer.running);

        // Advance 60 seconds (60000ms).
        let expired = timer.update(61_000);
        assert!(!expired, "timer must not be expired yet");
        assert_eq!(
            timer.remaining_secs, 240,
            "must have 240s remaining after 60s"
        );
    }

    #[test]
    fn timer_expires() {
        let mut timer = Timer::new();
        timer.set_duration(10);
        timer.start(0);

        let expired = timer.update(10_000); // 10 seconds
        assert!(expired, "timer must expire after full duration");
        assert_eq!(timer.remaining_secs, 0);
        assert!(!timer.running, "timer must stop when expired");
    }

    #[test]
    fn timer_pause_resume() {
        let mut timer = Timer::new();
        timer.set_duration(60);
        timer.start(0);
        timer.pause(5_000); // pause after 5 seconds
        assert!(!timer.running);
        assert_eq!(timer.remaining_secs, 55);

        timer.start(10_000); // resume at tick 10000
        let expired = timer.update(20_000); // 10 more seconds
        assert!(!expired);
        assert_eq!(timer.remaining_secs, 45);
    }

    #[test]
    fn timer_reset_clears() {
        let mut timer = Timer::new();
        timer.set_duration(120);
        timer.start(0);
        timer.update(30_000); // advance 30 seconds
        timer.reset();
        assert_eq!(
            timer.remaining_secs, 120,
            "reset must restore full duration"
        );
        assert!(!timer.running, "reset must stop timer");
    }

    #[test]
    fn timer_format_remaining() {
        let mut timer = Timer::new();
        timer.set_duration(332); // 5:32
        let buf = timer.format_remaining();
        assert_eq!(&buf, b"05:32", "must format as MM:SS");

        timer.set_duration(0);
        let buf = timer.format_remaining();
        assert_eq!(&buf, b"00:00");
    }

    #[test]
    fn timer_sub_second_polls_accumulate_at_500ms() {
        // WHY: regression test for #342 — update() must not discard the
        // sub-second remainder every call; a 2s timer polled at 500ms
        // intervals must expire after exactly 4 calls (2000ms).
        let mut timer = Timer::new();
        timer.set_duration(2);
        timer.start(0);

        assert!(!timer.update(500), "must not expire after 500ms");
        assert!(!timer.update(1_000), "must not expire after 1000ms");
        assert!(!timer.update(1_500), "must not expire after 1500ms");
        assert!(
            timer.update(2_000),
            "must expire after exactly 2000ms (4th call)"
        );
    }

    #[test]
    fn timer_sub_second_polls_accumulate_at_100ms() {
        // WHY: regression test for #342 — the same 2s timer polled at
        // 100ms intervals must expire after exactly 20 calls (2000ms); a
        // truncating update() never accumulates past 0 elapsed_secs per
        // call and never expires.
        let mut timer = Timer::new();
        timer.set_duration(2);
        timer.start(0);

        let mut expired = false;
        for i in 1..=20 {
            expired = timer.update(i * 100);
        }
        assert!(
            expired,
            "timer polled at 100ms intervals must expire after 20 calls (2000ms)"
        );
    }

    #[test]
    fn stopwatch_lap_records() {
        let mut sw = Stopwatch::new();
        sw.start(0);
        sw.lap(3_000); // lap 1 at 3s
        sw.lap(7_000); // lap 2 at 7s
        sw.lap(10_000); // lap 3 at 10s

        assert_eq!(sw.laps.len(), 3, "must have 3 laps");
        let durations = sw.lap_durations();
        assert_eq!(durations.len(), 3);
        assert_eq!(durations[0], (1, 3_000), "lap 1 must be 3s");
        assert_eq!(durations[1], (2, 4_000), "lap 2 must be 4s");
        assert_eq!(durations[2], (3, 3_000), "lap 3 must be 3s");
    }

    #[test]
    fn stopwatch_elapsed_accumulates() {
        let mut sw = Stopwatch::new();
        sw.start(0);
        sw.stop(5_000); // 5 seconds
        assert_eq!(sw.elapsed_ms, 5_000);

        sw.start(10_000);
        sw.stop(13_000); // 3 more seconds
        assert_eq!(
            sw.elapsed_ms, 8_000,
            "elapsed must accumulate across stop/start"
        );
    }

    #[test]
    fn stopwatch_reset() {
        let mut sw = Stopwatch::new();
        sw.start(0);
        sw.lap(1_000);
        sw.stop(2_000);
        sw.reset();
        assert_eq!(sw.elapsed_ms, 0, "reset must clear elapsed");
        assert!(sw.laps.is_empty(), "reset must clear laps");
        assert!(!sw.running, "reset must stop stopwatch");
    }

    #[test]
    fn stopwatch_max_laps() {
        let mut sw = Stopwatch::new();
        sw.start(0);
        for i in 1..=55 {
            sw.lap(i * 1000);
        }
        assert_eq!(sw.laps.len(), MAX_LAPS, "must cap at MAX_LAPS");
    }

    #[test]
    fn stopwatch_lap_while_stopped() {
        let mut sw = Stopwatch::new();
        sw.lap(1_000); // should be a no-op
        assert!(sw.laps.is_empty(), "lap while stopped must be ignored");
    }

    #[test]
    fn format_elapsed_ms_works() {
        // 12 min 34 sec 567 ms
        let ms = 12 * 60 * 1000 + 34 * 1000 + 567;
        let buf = format_elapsed_ms(ms);
        let s = core::str::from_utf8(&buf).unwrap_or("");
        assert_eq!(s, "00:12:34.567");
    }

    #[test]
    fn format_lap_ms_works() {
        let ms = 3 * 60 * 1000 + 21 * 1000 + 443;
        let buf = format_lap_ms(ms);
        let s = core::str::from_utf8(&buf).unwrap_or("");
        assert_eq!(s, "03:21.443");
    }
}
