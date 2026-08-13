//! 8×16 bitmap font for the 240×320 framebuffer display.
//!
//! Covers ASCII printable range `0x20` (space) through `0x7E` (`~`), giving
//! 95 glyphs. At 8×16 pixels per character, the display fits 30 columns × 20 rows.
//!
//! Each glyph is 16 bytes. Bit 7 of each byte is the leftmost pixel of that row.

use crate::color::Rgb565;
use crate::framebuffer::Framebuffer;

/// Width of each character cell in pixels.
pub const CHAR_WIDTH: u32 = eidolon_core::CHAR_WIDTH as u32;

/// Height of each character cell in pixels.
pub const CHAR_HEIGHT: u32 = eidolon_core::CHAR_HEIGHT as u32;

const FONT_FIRST: u32 = eidolon_core::FONT_FIRST;
const FONT_LAST: u32 = eidolon_core::FONT_LAST;
const FONT_CHAR_COUNT: usize = eidolon_core::FONT_CHAR_COUNT;

/// Bitmap font data: 95 glyphs, 16 rows each, 8 pixels wide.
///
/// Canonical table lives in [`eidolon_core::FONT_DATA`] (#545); indexed as
/// `FONT_DATA[char_code - FONT_FIRST]`. Each byte is one row; bit 7 is the
/// leftmost pixel.
static FONT_DATA: [[u8; 16]; FONT_CHAR_COUNT] = eidolon_core::FONT_DATA;

/// Render one character at pixel position `(x, y)`.
///
/// Characters outside the printable ASCII range are silently skipped.
/// Out-of-bounds pixels are clipped by [`Framebuffer::set_pixel`].
///
/// Time: O(1) — the nested loop is bounded by the compile-time constants
/// `CHAR_HEIGHT` = 16 and the literal 8-wide bit scan (`0u8..8`), so every
/// call touches exactly 128 pixels regardless of any runtime input; each
/// `set_pixel` call is itself O(1).
/// Space: O(1) — no allocation.
pub fn draw_char(fb: &mut Framebuffer, x: u32, y: u32, ch: char, fg: Rgb565, bg: Rgb565) {
    let code = u32::from(ch);
    if !(FONT_FIRST..=FONT_LAST).contains(&code) {
        return;
    }
    // code - FONT_FIRST is 0..=94, always fits in usize
    let glyph = &FONT_DATA[(code - FONT_FIRST) as usize];
    for (row, &byte) in glyph.iter().enumerate() {
        for col in 0u8..8 {
            let bit = (byte >> (7 - col)) & 1;
            let color = if bit != 0 { fg } else { bg };
            // SAFETY: glyph has exactly 16 rows, so row is 0..16, always fits in u32.
            fb.set_pixel(x + u32::from(col), y + row as u32, color);
        }
    }
}

/// Render a string starting at pixel position `(x, y)`.
///
/// Characters are placed LEFT-to-RIGHT with no wrapping. Pixels that fall
/// outside the framebuffer boundary are clipped.
///
/// Time: O(n) where n is the number of `char`s in `s` — one `draw_char`
/// call per character, each of which is O(1) (see [`draw_char`]).
/// Space: O(1) — iterates `s.chars()` in place, no allocation.
pub fn draw_str(fb: &mut Framebuffer, x: u32, y: u32, s: &str, fg: Rgb565, bg: Rgb565) {
    for (i, ch) in s.chars().enumerate() {
        // WHY: i exceeds u32 only for >4 GiB strings, impossible on this device;
        // saturating_add handles u32::MAX gracefully.
        let cx = x.saturating_add(u32::try_from(i).unwrap_or(u32::MAX) * CHAR_WIDTH);
        draw_char(fb, cx, y, ch, fg, bg);
    }
}

/// Return the pixel width of a string rendered with this font.
pub(crate) fn str_pixel_width(s: &str) -> u32 {
    u32::try_from(s.chars().count()).unwrap_or(u32::MAX) * CHAR_WIDTH
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framebuffer::Framebuffer;

    #[test]
    fn font_table_has_correct_character_count() {
        assert_eq!(
            FONT_DATA.len(),
            95,
            "font table must contain exactly 95 printable ASCII glyphs"
        );
    }

    #[test]
    fn draw_char_non_space_produces_nonzero_pixels() {
        let mut fb = Framebuffer::new(16, 16);
        draw_char(&mut fb, 0, 0, 'A', Rgb565::WHITE, Rgb565::BLACK);
        let any_set = fb.as_bytes().iter().any(|&b| b != 0);
        assert!(
            any_set,
            "drawing 'A' must produce at least one non-zero pixel"
        );
    }

    #[test]
    fn draw_char_space_produces_all_background() {
        let mut fb = Framebuffer::new(8, 16);
        fb.clear(Rgb565::WHITE);
        draw_char(&mut fb, 0, 0, ' ', Rgb565::WHITE, Rgb565::BLACK);
        let all_zero = fb.as_bytes().iter().all(|&b| b == 0);
        assert!(
            all_zero,
            "space character drawn with black background must clear all pixels"
        );
    }

    #[test]
    fn draw_char_out_of_range_is_noop() {
        let mut fb = Framebuffer::new(8, 16);
        draw_char(&mut fb, 0, 0, '\x01', Rgb565::WHITE, Rgb565::BLACK);
        let any_set = fb.as_bytes().iter().any(|&b| b != 0);
        assert!(
            !any_set,
            "non-printable character must not modify the framebuffer"
        );
    }

    #[test]
    fn draw_str_renders_multiple_characters() {
        let mut fb = Framebuffer::new(240, 16);
        draw_str(&mut fb, 0, 0, "Hi", Rgb565::WHITE, Rgb565::BLACK);
        let bytes = fb.as_bytes();
        // u32 → usize: framebuffer width fits on any supported platform
        let row_stride = fb.width() as usize * 2; // bytes per row

        // Scan columns 0-7 across all rows for 'H' pixels
        let any_h =
            (0..16_usize).any(|row| (0..8_usize).any(|col| bytes[row * row_stride + col * 2] != 0));
        // Scan columns 8-15 across all rows for 'i' pixels
        let any_i = (0..16_usize)
            .any(|row| (8..16_usize).any(|col| bytes[row * row_stride + col * 2] != 0));

        assert!(any_h, "'H' region must have SET pixels");
        assert!(any_i, "'i' region must have SET pixels");
    }

    #[test]
    fn str_pixel_width_matches_char_count() {
        assert_eq!(str_pixel_width("Hello"), 40, "5 characters × 8 pixels = 40");
        assert_eq!(str_pixel_width(""), 0, "empty string has zero pixel width");
        assert_eq!(
            str_pixel_width("12:34"),
            40,
            "time string '12:34' is 5 chars × 8 pixels"
        );
    }
}
