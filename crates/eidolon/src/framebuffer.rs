//! In-memory `RGB565` framebuffer.
//!
//! Pixels are stored as packed little-endian `u16` VALUES in a flat `Vec<u8>`.
//! All write operations are bounds-checked and silently ignore out-of-range coordinates,
//! which is safe for clipped rendering on the 240×320 display.

use alloc::vec;
use alloc::vec::Vec;

use crate::color::Rgb565;

const BYTES_PER_PIXEL: usize = 2;

/// An in-memory framebuffer for the `RGB565` display.
///
/// The internal buffer stores pixels row-major, two bytes each in little-endian ORDER.
/// Index for pixel `(x, y)` is `(y * width + x) * 2`.
pub struct Framebuffer {
    buf: Vec<u8>,
    width: u32,
    height: u32,
}

impl Framebuffer {
    /// Allocate a new framebuffer filled with black.
    pub(crate) fn new(width: u32, height: u32) -> Self {
        // SAFETY: u32 always fits in usize.
        let size = width as usize * height as usize * BYTES_PER_PIXEL;
        Self {
            buf: vec![0u8; size],
            width,
            height,
        }
    }

    /// Set a single pixel. Out-of-bounds coordinates are silently ignored.
    pub(crate) fn set_pixel(&mut self, x: u32, y: u32, color: Rgb565) {
        if x >= self.width || y >= self.height {
            return;
        }
        // SAFETY: coordinates are bounds-checked and buffer dimensions fit in usize.
        let idx = (y as usize * self.width as usize + x as usize) * BYTES_PER_PIXEL;
        let bytes = color.0.to_le_bytes();
        if let Some(slot) = self
            .buf
            .get_mut(idx..idx + BYTES_PER_PIXEL)
            .and_then(|s| <&mut [u8; BYTES_PER_PIXEL]>::try_from(s).ok())
        {
            *slot = bytes;
        }
    }

    /// Fill a rectangular region with `color`. Clips to the framebuffer boundary.
    ///
    /// Time: O(w * h) where w and h are the clipped rectangle's pixel width
    /// and height (`x_end - x` and `y_end - y`) — one write per pixel in
    /// the region.
    /// Space: O(1) — writes into the pre-allocated `buf`, no new allocation.
    pub(crate) fn fill_rect(&mut self, x: u32, y: u32, w: u32, h: u32, color: Rgb565) {
        let bytes = color.0.to_le_bytes();
        let y_end = y.saturating_add(h).min(self.height);
        let x_end = x.saturating_add(w).min(self.width);
        for row in y..y_end {
            for col in x..x_end {
                let idx = (row as usize * self.width as usize + col as usize) * BYTES_PER_PIXEL; // SAFETY: u32->usize widening, always valid
                if let Some(slot) = self
                    .buf
                    .get_mut(idx..idx + BYTES_PER_PIXEL)
                    .and_then(|s| <&mut [u8; BYTES_PER_PIXEL]>::try_from(s).ok())
                {
                    *slot = bytes;
                }
            }
        }
    }

    /// Fill the entire framebuffer with `color`.
    ///
    /// Time: O(p) where p is the number of pixels in the framebuffer
    /// (`self.buf.len() / BYTES_PER_PIXEL`, fixed at construction by
    /// `width * height`) — one write per pixel.
    /// Space: O(1) — writes into the pre-allocated `buf`, no new allocation.
    pub(crate) fn clear(&mut self, color: Rgb565) {
        let bytes = color.0.to_le_bytes();
        for chunk in self.buf.chunks_exact_mut(BYTES_PER_PIXEL) {
            if let Ok(slot) = <&mut [u8; BYTES_PER_PIXEL]>::try_from(chunk) {
                *slot = bytes;
            }
        }
    }

    /// Display width in pixels.
    pub(crate) const fn width(&self) -> u32 {
        self.width
    }

    /// Display height in pixels.
    pub(crate) const fn height(&self) -> u32 {
        self.height
    }

    /// Raw byte slice for direct hardware write. Two bytes per pixel, little-endian.
    pub(crate) const fn as_bytes(&self) -> &[u8] {
        self.buf.as_slice()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_creates_correct_byte_size() {
        let fb = Framebuffer::new(240, 320);
        assert_eq!(
            fb.as_bytes().len(),
            240 * 320 * 2,
            "240×320 RGB565 framebuffer must be exactly 153,600 bytes"
        );
    }

    #[test]
    fn new_is_zeroed() {
        let fb = Framebuffer::new(4, 4);
        assert!(
            fb.as_bytes().iter().all(|&b| b == 0),
            "new framebuffer must be filled with black (all zeros)"
        );
    }

    #[test]
    fn set_pixel_within_bounds_modifies_buffer() {
        let mut fb = Framebuffer::new(10, 10);
        fb.set_pixel(0, 0, Rgb565::WHITE);
        let bytes = fb.as_bytes();
        assert_eq!(
            bytes.first().copied().unwrap_or_default(),
            0xFF,
            "first byte of pixel (0,0) must be 0xFF for white"
        );
        assert_eq!(
            bytes.get(1).copied().unwrap_or_default(),
            0xFF,
            "second byte of pixel (0,0) must be 0xFF for white"
        );
    }

    #[test]
    fn set_pixel_out_of_bounds_is_noop() {
        let mut fb = Framebuffer::new(10, 10);
        fb.set_pixel(10, 0, Rgb565::WHITE); // x == width, out of bounds
        fb.set_pixel(0, 10, Rgb565::WHITE); // y == height, out of bounds
        fb.set_pixel(100, 100, Rgb565::WHITE);
        assert!(
            fb.as_bytes().iter().all(|&b| b == 0),
            "out-of-bounds set_pixel must not modify the buffer"
        );
    }

    #[test]
    fn set_pixel_writes_correct_row_offset() {
        let mut fb = Framebuffer::new(8, 8);
        fb.set_pixel(0, 1, Rgb565::RED); // second row, first column
        let bytes = fb.as_bytes();
        let [lo, hi] = Rgb565::RED.0.to_le_bytes();
        let offset = 8 * 2; // row 1, col 0
        assert_eq!(bytes[offset], lo, "red pixel row byte 0 must match");
        assert_eq!(bytes[offset + 1], hi, "red pixel row byte 1 must match");
    }

    #[test]
    fn fill_rect_colors_correct_region() {
        let mut fb = Framebuffer::new(10, 10);
        fb.fill_rect(0, 0, 5, 5, Rgb565::WHITE);
        let bytes = fb.as_bytes();
        // Pixel (4, 4) is inside the rect
        let idx_in = (4 * 10 + 4) * 2;
        assert_eq!(bytes[idx_in], 0xFF, "pixel inside fill_rect must be white");
        // Pixel (5, 0) is outside the rect
        let idx_out = 5 * 2;
        assert_eq!(
            bytes[idx_out], 0x00,
            "pixel outside fill_rect must be black"
        );
    }

    #[test]
    fn fill_rect_clips_to_bounds() {
        let mut fb = Framebuffer::new(4, 4);
        // Rect that starts in-bounds but extends past the edge
        fb.fill_rect(2, 2, 100, 100, Rgb565::BLUE);
        // Should not panic and buffer should still be valid size
        assert_eq!(
            fb.as_bytes().len(),
            4 * 4 * 2,
            "buffer size must not change after clipped fill_rect"
        );
    }

    #[test]
    fn clear_fills_entire_buffer() {
        let mut fb = Framebuffer::new(8, 8);
        fb.clear(Rgb565::RED);
        let [lo, hi] = Rgb565::RED.0.to_le_bytes();
        let bytes = fb.as_bytes();
        for chunk in bytes.chunks_exact(2) {
            assert_eq!(
                chunk.first().copied().unwrap_or_default(),
                lo,
                "every pixel low byte must be red"
            );
            assert_eq!(
                chunk.get(1).copied().unwrap_or_default(),
                hi,
                "every pixel high byte must be red"
            );
        }
    }

    #[test]
    fn dimensions_are_reported_correctly() {
        let fb = Framebuffer::new(240, 320);
        assert_eq!(fb.width(), 240, "width must match constructor argument");
        assert_eq!(fb.height(), 320, "height must match constructor argument");
    }
}
