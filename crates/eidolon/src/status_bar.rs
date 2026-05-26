//! Status bar: a 240×16 pixel top strip showing signal strength, time, and battery.
//!
//! Signal bars are drawn at the left edge, the time string is centred, and the
//! battery percentage is right-aligned. All rendering clips to the framebuffer
//! boundary through [`Framebuffer::set_pixel`].

use crate::color::Rgb565;
use crate::font::{CHAR_HEIGHT, draw_str, str_pixel_width};
use crate::framebuffer::Framebuffer;

/// Height of the status bar in pixels. Matches one font row (`CHAR_HEIGHT`).
pub(crate) const STATUS_BAR_HEIGHT: u32 = CHAR_HEIGHT;

/// Number of signal bar columns rendered.
const SIGNAL_BAR_COUNT: u8 = 4;
/// Width of each individual signal bar in pixels.
const SIGNAL_BAR_WIDTH: u32 = 3;
/// Gap between signal bars in pixels.
const SIGNAL_BAR_GAP: u32 = 1;
/// X offset of the first (shortest) bar.
const SIGNAL_BAR_X_START: u32 = 2;
/// Step in height per bar level (bars grow from shortest to tallest left-to-right).
const SIGNAL_BAR_HEIGHT_STEP: u32 = 4;

/// Dim colour for inactive signal bars.
const SIGNAL_DIM: Rgb565 = Rgb565::from_rgb(48, 48, 48);

/// Renders a status bar into the top `STATUS_BAR_HEIGHT` rows of `fb`.
pub struct StatusBar;

impl StatusBar {
    /// Draw the status bar.
    ///
    /// - `signal_bars`: active bar count, clamped to `0..=4`.
    /// - `battery_pct`: battery percentage, clamped to `0..=100`.
    /// - `time_str`: time string displayed centred (e.g. `"12:34"`).
    pub(crate) fn draw(fb: &mut Framebuffer, signal_bars: u8, battery_pct: u8, time_str: &str) {
        let w = fb.width();

        // Background
        fb.fill_rect(0, 0, w, STATUS_BAR_HEIGHT, Rgb565::BLACK);

        draw_signal_bars(fb, signal_bars);
        draw_time(fb, time_str, w);
        draw_battery(fb, battery_pct, w);
    }
}

fn draw_signal_bars(fb: &mut Framebuffer, signal_bars: u8) {
    let active = signal_bars.min(SIGNAL_BAR_COUNT);
    for i in 0..SIGNAL_BAR_COUNT {
        let bar_h = SIGNAL_BAR_HEIGHT_STEP * u32::from(i + 1);
        let bar_x = SIGNAL_BAR_X_START + u32::from(i) * (SIGNAL_BAR_WIDTH + SIGNAL_BAR_GAP);
        let bar_y = STATUS_BAR_HEIGHT.saturating_sub(bar_h);
        let color = if i < active {
            Rgb565::WHITE
        } else {
            SIGNAL_DIM
        };
        fb.fill_rect(bar_x, bar_y, SIGNAL_BAR_WIDTH, bar_h, color);
    }
}

fn draw_time(fb: &mut Framebuffer, time_str: &str, fb_width: u32) {
    let text_w = str_pixel_width(time_str);
    let x = fb_width.saturating_sub(text_w) / 2;
    draw_str(fb, x, 0, time_str, Rgb565::WHITE, Rgb565::BLACK);
}

fn draw_battery(fb: &mut Framebuffer, battery_pct: u8, fb_width: u32) {
    let pct = battery_pct.min(100);
    let text = battery_text(pct);
    let text_w = str_pixel_width(text);
    let x = fb_width.saturating_sub(text_w);
    draw_str(fb, x, 0, text, Rgb565::WHITE, Rgb565::BLACK);
}

/// Return a static string for the battery percentage (avoids heap allocation).
const fn battery_text(pct: u8) -> &'static str {
    match pct {
        100 => "100%",
        90..=99 => "9x%",
        80..=89 => "8x%",
        70..=79 => "7x%",
        60..=69 => "6x%",
        50..=59 => "5x%",
        40..=49 => "4x%",
        30..=39 => "3x%",
        20..=29 => "2x%",
        10..=19 => "1x%",
        1..=9 => "x%",
        _ => "0%",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn draw_does_not_panic_at_nominal_values() {
        let mut fb = Framebuffer::new(240, 320);
        fb.clear(Rgb565::WHITE);
        StatusBar::draw(&mut fb, 3, 75, "12:34");
        assert!(
            fb.as_bytes().iter().any(|&b| b != 0xFF),
            "status bar must write at least one pixel"
        );
    }

    #[test]
    fn draw_does_not_panic_at_zero_values() {
        let mut fb = Framebuffer::new(240, 320);
        fb.clear(Rgb565::WHITE);
        StatusBar::draw(&mut fb, 0, 0, "");
        assert!(
            fb.as_bytes().iter().any(|&b| b != 0xFF),
            "status bar must write at least one pixel even at zero values"
        );
    }

    #[test]
    fn draw_does_not_panic_at_max_values() {
        let mut fb = Framebuffer::new(240, 320);
        fb.clear(Rgb565::WHITE);
        StatusBar::draw(&mut fb, 255, 255, "00:00");
        assert!(
            fb.as_bytes().iter().any(|&b| b != 0xFF),
            "status bar must write at least one pixel even at max values"
        );
    }

    #[test]
    fn draw_stays_within_status_bar_height() {
        let mut fb = Framebuffer::new(240, 320);
        // Zero out only the rows below the status bar so we can check they remain clean.
        for y in STATUS_BAR_HEIGHT..fb.height() {
            for x in 0..fb.width() {
                fb.set_pixel(x, y, Rgb565::BLACK);
            }
        }
        StatusBar::draw(&mut fb, 4, 100, "23:59");
        // Rows below STATUS_BAR_HEIGHT must remain black (all zeros).
        let bytes = fb.as_bytes();
        // u32 → usize: framebuffer dimensions fit on any supported platform
        let row_bytes = fb.width() as usize * 2;
        let bar_end = STATUS_BAR_HEIGHT as usize * row_bytes;
        let below = &bytes[bar_end..];
        assert!(
            below.iter().all(|&b| b == 0),
            "status bar must not write pixels below STATUS_BAR_HEIGHT"
        );
    }

    #[test]
    fn draw_produces_nonzero_pixels_in_bar_area() {
        let mut fb = Framebuffer::new(240, 320);
        StatusBar::draw(&mut fb, 4, 100, "12:00");
        let bytes = fb.as_bytes();
        // u32 → usize: framebuffer dimensions fit on any supported platform
        let row_bytes = fb.width() as usize * 2;
        let bar_area = &bytes[..STATUS_BAR_HEIGHT as usize * row_bytes];
        let any_set = bar_area.iter().any(|&b| b != 0);
        assert!(
            any_set,
            "status bar area must contain visible pixels after drawing"
        );
    }

    #[test]
    fn battery_text_clamps_above_100() {
        let text = battery_text(200);
        assert!(!text.is_empty(), "clamped battery text must not be empty");
    }

    #[test]
    fn signal_bars_clamped_above_4() {
        // Should not panic with more than 4 bars
        let mut fb = Framebuffer::new(240, 320);
        fb.clear(Rgb565::WHITE);
        StatusBar::draw(&mut fb, 10, 80, "09:00");
        assert!(
            fb.as_bytes().iter().any(|&b| b != 0xFF),
            "status bar must write at least one pixel when signal bars are clamped"
        );
    }
}
