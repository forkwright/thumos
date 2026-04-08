//! `RGB565` color type for 16-bit framebuffer output.
//!
//! The `GC9306` DBI controller uses `RGB565` format: 5 red bits, 6 green bits, 5 blue bits
//! packed INTO a 16-bit little-endian word.

use std::fmt;

const RED_BITS: u8 = 5;
const GREEN_BITS: u8 = 6;
const BLUE_BITS: u8 = 5;

const RED_SHIFT_RIGHT: u8 = 8 - RED_BITS; // 3: discard 3 LSBs of 8-bit red
const GREEN_SHIFT_RIGHT: u8 = 8 - GREEN_BITS; // 2: discard 2 LSBs of 8-bit green
const BLUE_SHIFT_RIGHT: u8 = 8 - BLUE_BITS; // 3: discard 3 LSBs of 8-bit blue

const RED_SHIFT_LEFT: u16 = 11; // bits 15:11 in RGB565 word
const GREEN_SHIFT_LEFT: u16 = 5; // bits 10:5 in RGB565 word
// blue occupies bits 4:0, no LEFT shift

/// A 16-bit `RGB565` color value.
///
/// Bit layout: `RRRRRGGGGGGBBBBB` (MSB to LSB).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Rgb565(pub u16);

impl Rgb565 {
    pub const BLACK: Self = Self(0x0000);
    pub const WHITE: Self = Self(0xFFFF);
    pub const RED: Self = Self(0xF800);
    pub const GREEN: Self = Self(0x07E0);
    pub const BLUE: Self = Self(0x001F);
    pub const YELLOW: Self = Self(0xFFE0);
    pub const CYAN: Self = Self(0x07FF);
    pub const MAGENTA: Self = Self(0xF81F);

    /// Convert 24-bit `RGB888` to `RGB565` by truncating the least significant bits.
    pub const fn from_rgb(r: u8, g: u8, b: u8) -> Self {
        // u8 → u16: always a widening, never truncates. `From` is not yet const-stable.
        let r5 = (r >> RED_SHIFT_RIGHT) as u16;
        let g6 = (g >> GREEN_SHIFT_RIGHT) as u16;
        let b5 = (b >> BLUE_SHIFT_RIGHT) as u16;
        Self((r5 << RED_SHIFT_LEFT) | (g6 << GREEN_SHIFT_LEFT) | b5)
    }
}

impl fmt::Display for Rgb565 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "#{:04X}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn black_is_zero() {
        assert_eq!(Rgb565::BLACK.0, 0x0000, "black must be all-zero bits");
    }

    #[test]
    fn white_is_all_ones() {
        assert_eq!(Rgb565::WHITE.0, 0xFFFF, "white must be all-one bits");
    }

    #[test]
    fn named_constants_match_expected_values() {
        assert_eq!(Rgb565::RED.0, 0xF800, "red occupies top 5 bits");
        assert_eq!(Rgb565::GREEN.0, 0x07E0, "green occupies middle 6 bits");
        assert_eq!(Rgb565::BLUE.0, 0x001F, "blue occupies bottom 5 bits");
        assert_eq!(Rgb565::YELLOW.0, 0xFFE0, "yellow = red + green");
        assert_eq!(Rgb565::CYAN.0, 0x07FF, "cyan = green + blue");
        assert_eq!(Rgb565::MAGENTA.0, 0xF81F, "magenta = red + blue");
    }

    #[test]
    fn from_rgb_black_produces_zero() {
        assert_eq!(
            Rgb565::from_rgb(0, 0, 0).0,
            0,
            "from_rgb(0,0,0) must produce black"
        );
    }

    #[test]
    fn from_rgb_white_produces_all_ones() {
        assert_eq!(
            Rgb565::from_rgb(255, 255, 255).0,
            0xFFFF,
            "from_rgb(255,255,255) must produce white"
        );
    }

    #[test]
    fn from_rgb_red_channel_isolated() {
        let c = Rgb565::from_rgb(255, 0, 0);
        assert_eq!(c.0 & 0xF800, 0xF800, "red bits must be SET");
        assert_eq!(c.0 & 0x07FF, 0x0000, "green and blue bits must be clear");
    }

    #[test]
    fn display_formats_as_hex() {
        let c = Rgb565::BLACK;
        assert_eq!(
            format!("{c}"),
            "#0000",
            "display must use 4-digit uppercase hex"
        );

        let w = Rgb565::WHITE;
        assert_eq!(format!("{w}"), "#FFFF", "white display must show all Fs");
    }
}
